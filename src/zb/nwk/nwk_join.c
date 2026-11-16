#include "nwk_join.h"

#include "mac.h"
#include "nwk_addr.h"
#include "nwk_parents.h"
#include "aps_frag.h"
#include "nwk_commissioning.h"
#include "nwk_timeout.h"
#include "nwk_neighbor.h"
#include "nwk_status.h"
#include "zb_bstream.h"
#include "zb_time.h"
#include "zb_utils.h"

/* R23.1: 3.3.1.2, 3.4, 3.4.6, 3.4.6.1, 3.4.6.2, 3.4.6.3.1, 3.4.7, 3.4.7.1, 3.4.7.2, 3.4.7.3.1, 3.4.11, 3.4.12, 3.4.14, 3.4.15,
   3.4.15.2, 3.6.1.6.1, 3.6.1.6.1.1, 3.6.1.6.1.2, 3.6.1.6.1.3, 3.6.1.10.3, 3.6.1.10.5, 3.6.1.10.6, 3.6.4.8.1, 3.6.9, 3.6.10.2,
   3.6.10.3, 3.6.10.8, 3.6.13, 3.2.2.13, 3.2.2.14, 3.2.2.15 ok; 3.6.1.8 deferred (NIST); 2.4, 3.4.1.1, 4.3.1.2 elsewhere. */

enum
{
    NWK_JOIN_CHANNEL_FIRST = 11,
    NWK_JOIN_CHANNEL_LAST = 26,

    NWK_JOIN_ADDRESS_FIRST = 1,     

    NWK_JOIN_ADDRESS_NONE = 0xffff, 
    NWK_JOIN_PAN_NONE = 0xffff,

    NWK_JOIN_RADIUS = 1,

    NWK_JOIN_STATUS_NO_DATA = 0xeb
};

/* 3.6.1.8's generator, the xorshift32 draw `Nwk_RelayJitterMs` also uses: its only fixed point is 0, so a state
   that reached 0 would stay there and the seed never lets it. */
static uint32_t nwkJoinDraw(Nwk_Nwk *self)
{
    uint32_t x;

    x = self->joinSeedState;

    if (x == 0)
        x = 1;

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;

    self->joinSeedState = x;

    return x;
}

/* 3.6.1.6.1.2's search, by the only identity a neighbour's entry can be matched on */
static Nwk_NeighborTableEntry *nwkJoinNeighborOfIeee(Nwk_NeighborTableEntry *pool, uint64_t extendedAddress)
{
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!pool[i].inUse || !pool[i].ieeeKnown)
            continue;

        if (pool[i].extendedAddress == extendedAddress)
            return &pool[i];
    }

    return 0;
}

/* Whether a join answer comes from the parent asked: by its IEEE address once known, else by the short address the
   beacon named, a coordinator's beacon carrying no IEEE address, which the answer's own source field then supplies. */
static int nwkJoinFromTheParent(const Nwk_Nwk *self, const Nwk_Frame *frame)
{
    if (self->joinParentExtended != 0)
        return frame->srcIeee == self->joinParentExtended;

    return self->joinParentShortKnown && frame->srcAddr == (uint16_t)self->joinParentShort;
}

/* Table 3-74's entry for that network, which is where the parent's role and receiver duty come from */
static const Nwk_JoinParent *nwkJoinParentOf(const Nwk_Nwk *self, const uint8_t *extendedPanId)
{
    uint32_t i;

    for (i = 0; i < NWK_JOIN_PARENT_MAX; i++)
    {
        if (!self->joinParents[i].inUse)
            continue;

        if (Zb_memcmp(self->joinParents[i].extendedPanId, extendedPanId, RADIO_ADDR_LEN) != 0)
            continue;

        return &self->joinParents[i];
    }

    return 0;
}

/* The PIB's extended address read the way `nwk.c`'s own static reads it: the octets 3.4.6.2 puts in the source
   IEEE field, little endian, as one number */
static uint64_t nwkJoinOwnIeee(const Nwk_Nwk *self)
{
    const Radio_Pib *pib;
    uint64_t value;
    uint32_t i;

    pib = Mac_Pib(self->mac);
    value = 0;

    if (pib == 0)
        return 0;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        value = value | ((uint64_t)pib->extendedAddress[i] << (i * 8));

    return value;
}

/* 3.6.1.6.1.2's "most recent potential parent": the neighbour entry that says this device joined through it, or for a
   router, whose entry 7935-7936 turn into a sibling, the one at the address it joined through. */
static Nwk_NeighborTableEntry *nwkJoinParentNeighbor(Nwk_Nwk *self)
{
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!self->neighbors[i].inUse || self->neighbors[i].relationship != NWK_REL_PARENT)
            continue;

        return &self->neighbors[i];
    }

    if (!self->joinParentShortKnown)
        return 0;

    return Nwk_NeighborOf(self->neighbors, (uint16_t)self->joinParentShort);
}

/* Whether nwkCapabilityInformation holds anything: 3.6.1.6.1.1 stores the capability octet of the first join, and
   a zeroed struct is a device that never made one. */
static int nwkJoinCapabilitySet(const MacFrame_Capability *capability)
{
    return capability->deviceType || capability->powerSource || capability->rxOnWhenIdle
           || capability->associationType || capability->suspendableCsmaCa
           || capability->securityCapability || capability->allocateAddress;
}

/* 1 when all eight octets are zero, which names no network (Table 3-74's ExtendedPANId) */
static int nwkJoinPanIdUnset(const uint8_t *extendedPanId)
{
    uint32_t i;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
    {
        if (extendedPanId[i] != 0)
            return 0;
    }

    return 1;
}

/* 3.6.1.8: an address is free when no entry of the NIB carries it, this device's own included */
/* 3.6.1.10.3: the parent assigns an address "by randomly generating an address and ensuring it does not conflict with
   its local address map, nwkAddressMap", which holds devices the neighbour table no longer does. */
static int nwkJoinAddressTaken(const Nwk_Nwk *self, uint16_t address)
{
    uint16_t own;
    uint32_t i;

    own = 0;

    if (Nwk_AddrOwn(Mac_Pib(self->mac), &own) && own == address)
        return 1;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!self->neighbors[i].inUse)
            continue;

        if (self->neighbors[i].networkAddress == address)
            return 1;
    }

    for (i = 0; i < NWK_ADDR_MAP_MAX; i++)
    {
        const Nwk_AddressMapEntry *entry = &self->addressMap[i];

        if (entry->inUse && entry->networkAddress == address)
            return 1;
    }

    return 0;
}

/* 3.6.1.8's draw: 1..0xfff7 and nothing a NIB entry already carries; no address after the tries is the
   capacity answer 3.6.1.6.1.3 gives. */
static int nwkJoinAddressTake(Nwk_Nwk *self, uint16_t *out)
{
    uint16_t candidate;
    uint32_t i;

    for (i = 0; i < NWK_JOIN_ADDRESS_TRIES; i++)
    {
        candidate = (uint16_t)((nwkJoinDraw(self) % NWK_JOIN_ADDRESS_MAX) + NWK_JOIN_ADDRESS_FIRST);

        if (nwkJoinAddressTaken(self, candidate))
            continue;

        *out = candidate;

        return 1;
    }

    return 0;
}

/* The security level as this layer knows it: a network at level 0x00 has no secured frame to wait for. */
static int nwkJoinSecured(const Nwk_Nwk *self)
{
    return self->security != 0 && Security_Level(self->security) != SECURITY_LEVEL_NONE;
}

/* Every frame this layer sends itself: one the transmit door has no room for is copied and offered again each step,
   as the MAC holds its association request, and a request's countdown starts when it goes out. */
static ZbStatus nwkJoinSend(Nwk_Nwk *self, const uint8_t *octets, uint32_t octetLen, uint16_t nextHop, int indirect,
                            int countdown, uint32_t nowMs)
{
    ZbStatus status;

    status = Nwk_TxOfferRaw(self->mac, octets, octetLen, nextHop, indirect, NWK_TX_HELD_UNTRACKED, nowMs, 0);

    if ((status != ZB_ERR_BUSY && status != ZB_ERR_NO_SPACE) || self->joinOwedInUse
        || octetLen > (uint32_t)sizeof self->joinOwedNpdu)
        return status;

    Zb_memcpy(self->joinOwedNpdu, octets, octetLen);

    self->joinOwedLen = octetLen;
    self->joinOwedNextHop = nextHop;
    self->joinOwedIndirect = indirect;
    self->joinOwedCountdown = countdown;
    self->joinOwedSinceMs = nowMs;
    self->joinOwedInUse = 1;

    return ZB_OK;
}

/* The held frame offered again: gone once the door takes it, dropped and counted once the wait has passed */
static void nwkJoinStepOwed(Nwk_Nwk *self, uint32_t nowMs)
{
    ZbStatus status;

    if (!self->joinOwedInUse)
        return;

    status = Nwk_TxOfferRaw(self->mac, self->joinOwedNpdu, self->joinOwedLen, self->joinOwedNextHop,
                            self->joinOwedIndirect, NWK_TX_HELD_UNTRACKED, nowMs, 0);

    if (status == ZB_OK)
    {
        self->joinOwedInUse = 0;

        if (self->joinOwedCountdown
            && (self->joinState == NWK_JOIN_COMMISSIONING || self->joinState == NWK_JOIN_REJOINING))
        {
            self->joinAttemptMs = nowMs;
            self->joinPollMs = nowMs;
        }

        return;
    }

    if ((status == ZB_ERR_BUSY || status == ZB_ERR_NO_SPACE)
        && Zb_timeWithin(nowMs, self->joinOwedSinceMs, MAC_ASSOC_SEND_WAIT_MS))
        return;

    self->joinOwedInUse = 0;
    self->joinSendsDropped++;
}

/* One command this layer composes onto the air: protected when `secured` and this device holds the key, since the
   receive gate discards an unsecured command from a joined sender; held for the receiver's poll when `indirect`. */
static ZbStatus nwkJoinIssue(Nwk_Nwk *self, Nwk_Frame *header, const uint8_t *payload, uint32_t payloadLen,
                             uint16_t nextHop, int secured, int indirect, uint32_t nowMs)
{
    const uint8_t *octets;
    uint32_t octetLen;
    uint32_t npduLen = 0;
    uint32_t securedLen = 0;
    ZbStatus status;

    header->securityEnabled = secured && Nwk_TxSecurityRuns(self->security) ? 1 : 0;

    status = NwkFrame_Compose(header, payload, payloadLen, self->relayNpdu, (uint32_t)sizeof self->relayNpdu,
                              &npduLen);

    if (status != ZB_OK)
        return status;

    octets = self->relayNpdu;
    octetLen = npduLen;

    if (header->securityEnabled)
    {
        status = Nwk_TxProtect(self->security, self->relayNpdu, npduLen, NwkFrame_HeaderLen(header),
                               self->secureScratch, (uint32_t)sizeof self->secureScratch, &securedLen);

        if (status != ZB_OK)
            return status;

        octets = self->secureScratch;
        octetLen = securedLen;
    }

    return nwkJoinSend(self, octets, octetLen, nextHop, indirect, 0, nowMs);
}

/* An end device that has just joined or rejoined sends its timeout request to the parent, every time and even to
   the same parent; a router or coordinator sends none. It goes on the turn after the confirm, so the exchange the
   join itself ran is closed before another frame takes the session. */
static void nwkJoinSendTimeoutRequest(Nwk_Nwk *self, uint32_t nowMs)
{
    Nwk_NeighborTableEntry *parent;
    Nwk_Frame header;
    uint8_t payload[1 + NWK_TIMEOUT_REQUEST_OCTETS];
    uint32_t payloadLen = 0;
    uint16_t own;
    ZbStatus status;

    if (!self->timeoutRequestPending || self->joinConfirmReady)
        return;

    if (self->joinState != NWK_JOIN_JOINED)
        return;

    if (nwkJoinSecured(self) && !Nwk_TxSecurityRuns(self->security))
        return;

    if (self->cfg.deviceType != NWK_DEVICE_END_DEVICE)
    {
        self->timeoutRequestPending = 0;
        return;
    }

    parent = nwkJoinParentNeighbor(self);

    if (parent == 0 || !parent->ieeeKnown)
        return;

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        return;

    if (Nwk_TimeoutRequestCompose(self->cfg.endDeviceTimeout, 0, payload + 1, (uint32_t)sizeof payload - 1,
                                  &payloadLen) != ZB_OK)
    {
        self->timeoutRequestPending = 0;
        return;
    }

    payload[0] = NWK_CMD_END_DEVICE_TIMEOUT_REQUEST;
    payloadLen++;

    Zb_memset(&header, 0, (uint32_t)sizeof header);

    header.frameType = NWK_FRAME_TYPE_COMMAND;
    header.protocolVersion = NWK_PROTOCOL_VERSION;
    header.discoverRoute = NWK_DISCOVER_SUPPRESS;
    header.destAddr = parent->networkAddress;
    header.srcAddr = own;
    header.radius = NWK_JOIN_RADIUS;
    header.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    header.srcIeeePresent = 1;
    header.srcIeee = nwkJoinOwnIeee(self);
    header.destIeeePresent = 1;
    header.destIeee = parent->extendedAddress;
    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    status = nwkJoinIssue(self, &header, payload, payloadLen, parent->networkAddress, 1, 0, nowMs);

    if (status == ZB_OK)
        self->timeoutRequestsSent++;

    if (status == ZB_OK || !Nwk_TxRetryOwed(status))
        self->timeoutRequestPending = 0;
}

/* A command this layer composes itself, wrapped in the NPDU a receiver parses: the identifier, the payload, and
   the header a payload without it does not have. */
static ZbStatus nwkJoinSendCommand(Nwk_Nwk *self, uint16_t destination, uint64_t destinationIeee,
                                   uint8_t identifier, const uint8_t *payload, uint32_t payloadLen, int secured,
                                   int indirect, uint32_t nowMs)
{
    Nwk_Frame header;
    uint8_t body[NWK_COMMISSIONING_RESPONSE_OCTETS + 1];
    uint16_t own;

    if (payloadLen + 1 > (uint32_t)sizeof body)
        return ZB_ERR_BAD_ARGUMENT;

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        return ZB_ERR_NOT_READY;

    body[0] = identifier;

    if (payloadLen != 0)
        Zb_memcpy(body + 1, payload, payloadLen);

    payload = body;
    payloadLen++;

    Zb_memset(&header, 0, (uint32_t)sizeof header);

    header.frameType = NWK_FRAME_TYPE_COMMAND;
    header.protocolVersion = NWK_PROTOCOL_VERSION;
    header.discoverRoute = NWK_DISCOVER_SUPPRESS;
    header.destAddr = destination;
    header.srcAddr = own;
    header.radius = NWK_JOIN_RADIUS;
    header.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    header.srcIeeePresent = 1;
    header.srcIeee = nwkJoinOwnIeee(self);

    if (destinationIeee != 0)
    {
        header.destIeeePresent = 1;
        header.destIeee = destinationIeee;
    }

    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    return nwkJoinIssue(self, &header, payload, payloadLen, destination, secured, indirect, nowMs);
}

/* 3.2.2.14's indication, pushed after the answer it follows: full is drop-newest and count (docs/internals/coding-rules.md §4.3) */
static void nwkJoinIndicationPush(Nwk_Nwk *self, uint16_t networkAddress, uint64_t extendedAddress,
                                  MacFrame_Capability capability, uint32_t joinerMethod)
{
    Nwk_JoinIndicationParameters *indication;

    if (self->joinIndicationCount >= NWK_JOIN_INDICATION_MAX)
    {
        self->joinIndicationsDropped++;

        return;
    }

    indication = &self->joinIndications[(self->joinIndicationHead + self->joinIndicationCount)
                                        % NWK_JOIN_INDICATION_MAX];

    Zb_memset(indication, 0, (uint32_t)sizeof *indication);

    indication->interfaceIndex = 0;
    indication->networkAddress = networkAddress;
    indication->extendedAddress = extendedAddress;
    indication->capability = capability;
    indication->joinerMethod = joinerMethod;

    self->joinIndicationCount++;
}

/* 3.6.1.6.1.3's PAN AT CAPACITY: Table 10-102's 0x01 with no address is an answer, so nothing is dropped here */
static void nwkJoinAnswerCapacity(Nwk_Nwk *self, const Mac_AssociationIndication *request, uint32_t nowMs)
{
    Mac_AssociationResponse response;

    Zb_memset(&response, 0, (uint32_t)sizeof response);

    response.request = *request;
    response.shortAddress = NWK_JOIN_ADDRESS_NONE;
    response.status = MAC_ASSOC_STATUS_PAN_AT_CAPACITY;

    Mac_AssociateResponse(self->mac, &response, nowMs);
}

/* 3.6.1.6.1.1's parent entry, exactly as the association half of this file writes it: the rejoin's success names the
   parent it addressed, so an entry that already carries it is refreshed in place and a new one comes from the pool. */
/* The countdown's length: a config that names 0 takes Table 4-35's 10 seconds, and Table 3-75's range caps it. */
static uint32_t nwkJoinSecurityTimeout(const Nwk_Nwk *self)
{
    uint32_t seconds = self->cfg.apsSecurityTimeOutPeriod;

    if (seconds == 0)
        seconds = NWK_SECURITY_TIMEOUT_DEFAULT;

    if (seconds > NWK_SECURITY_TIMEOUT_MAX)
        seconds = NWK_SECURITY_TIMEOUT_MAX;

    return seconds;
}

/* An NLME-NWK-STATUS.indication queued for the layer above; a full ring drops the newest and counts it. */
static void nwkJoinIndicate(Nwk_Nwk *self, uint32_t status, uint16_t address)
{
    Nwk_NwkStatusIndication *slot;

    if (self->statusIndicationCount >= NWK_STATUS_INDICATION_MAX)
    {
        self->droppedIndications++;

        return;
    }

    slot = &self->statusIndications[(self->statusIndicationHead + self->statusIndicationCount)
                                    % NWK_STATUS_INDICATION_MAX];

    Zb_memset(slot, 0, (uint32_t)sizeof *slot);

    slot->status = status;
    slot->shortAddr = address;

    self->statusIndicationCount++;
}

void Nwk_JoinParentLinkFailed(Nwk_Nwk *self, uint16_t hop)
{
    if (self == 0 || self->cfg.deviceType != NWK_DEVICE_END_DEVICE || self->joinState != NWK_JOIN_JOINED
        || !self->joinParentShortKnown || hop != (uint16_t)self->joinParentShort)
        return;

    self->parentLinkFailures++;

    nwkJoinIndicate(self, NWK_STATUS_CODE_PARENT_LINK_FAILURE, hop);
}

void Nwk_JoinParentLinkHeld(Nwk_Nwk *self, uint16_t hop)
{
    if (self == 0 || self->cfg.deviceType != NWK_DEVICE_END_DEVICE || self->joinState != NWK_JOIN_JOINED
        || !self->joinParentShortKnown || hop != (uint16_t)self->joinParentShort)
        return;

    self->parentLinkHeld++;
}

static void nwkJoinRecordParent(Nwk_Nwk *self, uint32_t nowMs)
{
    const Nwk_JoinParent *discovery;
    Nwk_NeighborTableEntry *parent;

    if (self->joinParentExtended == 0)
        return;

    parent = nwkJoinNeighborOfIeee(self->neighbors, self->joinParentExtended);

    if (parent == 0)
        parent = Nwk_NeighborFree(self->neighbors);

    if (parent == 0)
        return;                 

    discovery = nwkJoinParentOf(self, self->joinExtendedPanId);

    Zb_memset(parent, 0, (uint32_t)sizeof *parent);

    parent->inUse = 1;
    parent->networkAddress = (uint16_t)self->joinParentShort;
    parent->extendedAddress = self->joinParentExtended;
    parent->ieeeKnown = 1;
    parent->deviceType = discovery != 0 ? discovery->deviceType : NWK_NEIGHBOR_TYPE_UNKNOWN;
    parent->rxOnWhenIdle = discovery != 0 ? discovery->rxOnWhenIdle : 0;
    parent->relationship = NWK_REL_PARENT;
    parent->ageFromMs = nowMs;
    parent->routerOutboundActivity = NWK_ROUTER_AGE_LIMIT;
    parent->routerInboundActivity = NWK_ROUTER_AGE_LIMIT;

    Nwk_NeighborSecurityTimerArm(parent, nwkJoinSecurityTimeout(self), nowMs);
}

void Nwk_JoinResume(Nwk_Nwk *self, uint16_t parentShort, uint64_t parentIeee)
{
    Nwk_NeighborTableEntry *parent;
    uint16_t own;

    if (self == 0 || self->mac == 0 || !Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        return;

    self->joinState = NWK_JOIN_JOINED;

    if (self->cfg.deviceType != NWK_DEVICE_END_DEVICE || parentIeee == 0)
        return;

    self->joinParentShort = parentShort;
    self->joinParentShortKnown = 1;
    self->joinParentExtended = parentIeee;

    parent = nwkJoinNeighborOfIeee(self->neighbors, parentIeee);

    if (parent == 0)
        parent = Nwk_NeighborFree(self->neighbors);

    if (parent == 0)
        return;

    Zb_memset(parent, 0, (uint32_t)sizeof *parent);

    parent->inUse = 1;
    parent->networkAddress = parentShort;
    parent->extendedAddress = parentIeee;
    parent->ieeeKnown = 1;
    parent->deviceType = parentShort == NWK_ADDR_COORDINATOR ? NWK_DEVICE_COORDINATOR : NWK_DEVICE_ROUTER;
    parent->rxOnWhenIdle = 1;
    parent->relationship = NWK_REL_PARENT;
    parent->routerOutboundActivity = NWK_ROUTER_AGE_LIMIT;
    parent->routerInboundActivity = NWK_ROUTER_AGE_LIMIT;

    self->keepalive = NWK_KEEPALIVE_OWED;
}

/* The PIB a commissioning join borrowed, given back when the join fails: the unassociated PAN and address */
static void nwkJoinCommissionRestore(Nwk_Nwk *self)
{
    const Radio_Pib *current;
    Radio_Pib pib;

    current = Mac_Pib(self->mac);

    if (current->panId == NWK_JOIN_PAN_NONE && current->shortAddress == NWK_JOIN_ADDRESS_NONE)
        return;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);

    pib.present = RADIO_PIB_PAN_ID | RADIO_PIB_SHORT_ADDRESS;
    pib.panId = NWK_JOIN_PAN_NONE;
    pib.shortAddress = NWK_JOIN_ADDRESS_NONE;

    (void)Mac_SetPib(self->mac, &pib);
}

/* A commissioning join that ends without an address: the confirm names the parent it last asked */
static void nwkJoinCommissionFail(Nwk_Nwk *self, uint32_t status)
{
    Zb_memset(&self->joinConfirm, 0, (uint32_t)sizeof self->joinConfirm);

    Zb_memcpy(self->joinConfirm.extendedPanId, self->joinExtendedPanId, RADIO_ADDR_LEN);

    self->joinConfirm.status = status;
    self->joinConfirm.networkAddress = NWK_JOIN_ADDRESS_NONE;
    self->joinConfirm.channel = self->joinChannel;
    self->joinConfirm.parentShortKnown = self->joinParentShortKnown;
    self->joinConfirm.parentShort = (uint16_t)self->joinParentShort;
    self->joinConfirm.parentExtended = self->joinParentExtended;

    self->joinState = NWK_JOIN_FAILED;
    self->joinConfirmReady = 1;

    nwkJoinCommissionRestore(self);
}

/* The request to one discovery entry, from the address the join claims. The PIB takes the entry's channel and PAN
   and that address first: the request's source and the answer's destination are both that address. */
static ZbStatus nwkJoinCommission(Nwk_Nwk *self, uint32_t index, uint32_t nowMs)
{
    const Nwk_JoinParent *parent;
    const Radio_Pib *current;
    Nwk_CommissioningRequest commissioning;
    Nwk_Frame header;
    Radio_Pib pib;
    uint8_t payload[1 + NWK_COMMISSIONING_OCTETS + 2 + 2 + NWK_TLV_FRAGMENTATION_OCTETS + 2 + NWK_TLV_KEY_NEGOTIATION_OCTETS];
    uint16_t own;
    uint32_t payloadLen = 0;
    uint32_t npduLen = 0;
    uint32_t capabilityLen = 0;
    ZbStatus status;

    parent = &self->joinParents[index];
    current = Mac_Pib(self->mac);

    if (!parent->shortKnown)
        return ZB_ERR_BAD_ARGUMENT;

    if (!Nwk_AddrOwn(current, &own) && !nwkJoinAddressTake(self, &own))
        return ZB_ERR_BAD_STATE;

    Zb_memset(&commissioning, 0, (uint32_t)sizeof commissioning);

    commissioning.type = NWK_COMMISSIONING_INITIAL_JOIN;
    commissioning.nodeId = own;
    commissioning.fragmentationOptions = NWK_TLV_FRAGMENTATION_APS_BIT;
    commissioning.maxIncomingTransferUnit = APS_FRAG_MAX_ASDU;
    commissioning.sourceEui64 = nwkJoinOwnIeee(self);

    status = MacFrame_ComposeAssociationRequest(&self->joinCapability, &commissioning.capability, 1, &capabilityLen);

    if (status != ZB_OK)
        return status;

    payload[0] = NWK_CMD_NETWORK_COMMISSIONING_REQUEST;

    status = Nwk_CommissioningRequestCompose(&commissioning, payload + 1, (uint32_t)sizeof payload - 1, &payloadLen);

    if (status != ZB_OK)
        return status;

    payloadLen++;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);

    if (current->channel != parent->channel)
    {
        pib.present |= RADIO_PIB_CHANNEL;
        pib.channel = parent->channel;
    }

    if (current->panId != parent->panId)
    {
        pib.present |= RADIO_PIB_PAN_ID;
        pib.panId = parent->panId;
    }

    if ((current->present & RADIO_PIB_SHORT_ADDRESS) == 0 || current->shortAddress != own)
    {
        pib.present |= RADIO_PIB_SHORT_ADDRESS;
        pib.shortAddress = own;
    }

    if (pib.present != 0)
    {
        status = Mac_SetPib(self->mac, &pib);

        if (status != ZB_OK)
            return status;
    }

    Zb_memset(&header, 0, (uint32_t)sizeof header);

    header.frameType = NWK_FRAME_TYPE_COMMAND;
    header.protocolVersion = NWK_PROTOCOL_VERSION;
    header.discoverRoute = NWK_DISCOVER_SUPPRESS;
    header.destAddr = parent->shortAddress;
    header.srcAddr = own;
    header.radius = NWK_JOIN_RADIUS;
    header.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    header.srcIeeePresent = 1;
    header.srcIeee = nwkJoinOwnIeee(self);
    header.destIeeePresent = parent->extendedAddress != 0 ? 1 : 0;
    header.destIeee = parent->extendedAddress;
    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    status = NwkFrame_Compose(&header, payload, payloadLen, self->relayNpdu, (uint32_t)sizeof self->relayNpdu,
                              &npduLen);

    if (status == ZB_OK)
        status = nwkJoinSend(self, self->relayNpdu, npduLen, header.destAddr, 0, 1, nowMs);

    if (status != ZB_OK)
    {
        nwkJoinCommissionRestore(self);

        return status;
    }

    self->joinState = NWK_JOIN_COMMISSIONING;
    self->joinParentShort = parent->shortAddress;
    self->joinParentShortKnown = 1;
    self->joinParentExtended = parent->extendedAddress;
    self->joinChannel = parent->channel;
    self->joinAttemptMs = nowMs;
    self->joinPollMs = nowMs;
    self->joinConfirmReady = 0;

    Zb_memset(&self->joinConfirm, 0, (uint32_t)sizeof self->joinConfirm);
    Zb_memcpy(self->joinExtendedPanId, parent->extendedPanId, RADIO_ADDR_LEN);

    return ZB_OK;
}

/* The next potential parent: the best-ranked permitting entry of the network asked for, on a channel this layer joins
   and the request allows, that this join has not tried (docs/internals/decisions.md). */
static uint32_t nwkJoinNextParent(const Nwk_Nwk *self, const uint8_t *extendedPanId, uint32_t scanChannels)
{
    const Nwk_JoinParent *entry;
    uint32_t eligible = 0;
    uint32_t i;

    for (i = 0; i < NWK_JOIN_PARENT_MAX; i++)
    {
        entry = &self->joinParents[i];

        if (!entry->inUse || !entry->associationPermit || (self->joinParentsTried & ((uint32_t)1 << i)) != 0)
            continue;

        if (Zb_memcmp(entry->extendedPanId, extendedPanId, RADIO_ADDR_LEN) != 0)
            continue;

        if (entry->channel < NWK_JOIN_CHANNEL_FIRST || entry->channel > NWK_JOIN_CHANNEL_LAST)
            continue;

        if (scanChannels != 0 && (scanChannels & ((uint32_t)1 << entry->channel)) == 0)
            continue;

        eligible |= (uint32_t)1 << i;
    }

    return Nwk_ParentBest(self->joinParents, eligible, Nwk_ParentsGoodLqa(self));
}

/* Table 3-50's bound on the parents one join tries: a config that names 0 takes the printed default */
static uint32_t nwkJoinAttemptsMax(const Nwk_Nwk *self)
{
    if (self->cfg.maxInitialJoinParentAttempts == 0)
        return NWK_JOIN_INITIAL_ATTEMPTS_DEFAULT;

    return self->cfg.maxInitialJoinParentAttempts;
}

/* The association with one discovery entry, on the entry's channel: the first attempt and every later one */
static ZbStatus nwkJoinAssociate(Nwk_Nwk *self, uint32_t index, uint32_t nowMs)
{
    const Nwk_JoinParent *parent;
    Mac_AssociateRequestParameters request;
    ZbStatus status;

    parent = &self->joinParents[index];

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.destPan = parent->panId;
    request.parentShortKnown = parent->shortKnown;
    request.parentShort = parent->shortKnown ? parent->shortAddress : 0;
    request.parentExtended = parent->extendedAddress;
    request.channel = parent->channel;
    request.capability = self->joinCapability;

    status = Mac_AssociateRequest(self->mac, &request, nowMs);

    if (status != ZB_OK)
        return status;

    self->joinState = NWK_JOIN_ASSOCIATING;
    self->joinParentShort = parent->shortAddress;
    self->joinParentShortKnown = parent->shortKnown;
    self->joinParentExtended = parent->extendedAddress;
    self->joinChannel = parent->channel;
    self->joinConfirmReady = 0;

    Zb_memset(&self->joinConfirm, 0, (uint32_t)sizeof self->joinConfirm);
    Zb_memcpy(self->joinExtendedPanId, parent->extendedPanId, RADIO_ADDR_LEN);

    return ZB_OK;
}

/* Rule 1 for an Initial Join: Network Commissioning to a parent whose beacon carried the R23 appendix, MAC
   association to any other, unless the configuration forces one of the two. */
static int nwkJoinByCommissioning(const Nwk_Nwk *self, const Nwk_JoinParent *parent)
{
    if (self->cfg.attachMechanism == (uint32_t)NWK_ATTACH_COMMISSIONING)
        return 1;

    if (self->cfg.attachMechanism == (uint32_t)NWK_ATTACH_ASSOCIATION)
        return 0;

    return parent->r23Appendix != 0;
}

/* One attempt at one discovery entry by the attach mechanism chosen for it, counted against the bound and marked
   tried only when it went out. */
static ZbStatus nwkJoinAttach(Nwk_Nwk *self, uint32_t index, uint32_t nowMs)
{
    ZbStatus status;

    status = nwkJoinByCommissioning(self, &self->joinParents[index]) ? nwkJoinCommission(self, index, nowMs)
                                                                       : nwkJoinAssociate(self, index, nowMs);

    if (status != ZB_OK)
        return status;

    self->joinParentsTried |= (uint32_t)1 << index;
    self->joinParentIndex = index;
    self->joinConflictRetried = 0;
    self->joinAttempts++;

    return ZB_OK;
}

/* An unsuccessful attempt moves to the next parent until the bound or the list runs out; a parent the MAC will not
   take ends the join there, with the failure that came before it. */
static int nwkJoinTryNextParent(Nwk_Nwk *self, uint32_t nowMs)
{
    uint32_t index;

    if (self->joinAttempts >= nwkJoinAttemptsMax(self))
        return 0;

    index = nwkJoinNextParent(self, self->joinExtendedPanId, self->joinScanChannels);

    if (index == NWK_JOIN_PARENT_MAX)
        return 0;

    return nwkJoinAttach(self, index, nowMs) == ZB_OK;
}

/* 3.6.1.6.1.1: the join 3.2.2.13 asked for, whose outcome 10.21.6.1.5 answers as the MLME-ASSOCIATE.confirm */
static void nwkJoinStepChild(Nwk_Nwk *self, uint32_t nowMs)
{
    nwkJoinSendTimeoutRequest(self, nowMs);

    Mac_AssociateConfirmParameters confirm;

    if (self->joinState != NWK_JOIN_ASSOCIATING)
        return;

    Zb_memset(&confirm, 0, (uint32_t)sizeof confirm);

    if (!Mac_PollAssociateConfirm(self->mac, &confirm))
        return;

    Zb_memset(&self->joinConfirm, 0, (uint32_t)sizeof self->joinConfirm);

    Zb_memcpy(self->joinConfirm.extendedPanId, self->joinExtendedPanId, RADIO_ADDR_LEN);

    self->joinConfirm.status = confirm.status;     
    self->joinConfirm.channel = self->joinChannel;
    self->joinConfirm.parentShortKnown = confirm.parentShortKnown ? 1 : self->joinParentShortKnown;
    self->joinConfirm.parentShort = confirm.parentShortKnown ? confirm.parentShort : (uint16_t)self->joinParentShort;
    self->joinConfirm.parentExtended = confirm.parentExtended != 0 ? confirm.parentExtended : self->joinParentExtended;

    if (confirm.status != NWK_JOIN_STATUS_SUCCESS || confirm.shortAddress >= NWK_ADDR_RESERVED_LOW)
    {
        if (nwkJoinTryNextParent(self, nowMs))
            return;

        self->joinConfirm.networkAddress = NWK_JOIN_ADDRESS_NONE;
        self->joinConfirm.status = confirm.status != NWK_JOIN_STATUS_SUCCESS
                                   ? confirm.status
                                   : NWK_JOIN_STATUS_NO_DATA;
        self->joinState = NWK_JOIN_FAILED;
        self->joinConfirmReady = 1;

        return;
    }

    self->joinConfirm.networkAddress = confirm.shortAddress;
    self->joinState = NWK_JOIN_JOINED;
    self->cfg.parentInformation = 0;
    self->joinConfirmReady = 1;

    if (!self->joinConfirm.parentShortKnown)
        return;

    self->joinParentShort = self->joinConfirm.parentShort;
    self->joinParentExtended = self->joinConfirm.parentExtended;

    nwkJoinRecordParent(self, nowMs);
    self->timeoutRequestPending = 1;
}

/* 3.6.1.6.1.3's PAN ACCESS DENIED for a request this device's own policy refuses: an answer, no address, and the
   parent's word that it takes nobody. The MAC's ring is drained either way, because mac's association event is the
   MAC's and not the NWK's; 3.6.1.6.1.3 has the permit read here and nowhere below. */
static void nwkJoinAnswerDenied(Nwk_Nwk *self, const Mac_AssociationIndication *request, uint32_t nowMs)
{
    Mac_AssociationResponse response;

    Zb_memset(&response, 0, (uint32_t)sizeof response);

    response.request = *request;
    response.shortAddress = NWK_JOIN_ADDRESS_NONE;
    response.status = MAC_ASSOC_STATUS_PAN_ACCESS_DENIED;

    if (Mac_AssociateResponse(self->mac, &response, nowMs) != ZB_OK)
        self->joinResponsesDropped++;
}

/* An association answered and handed to the MAC: its indication waits for the delivery, and a pool with no room left
   indicates at once, as this stack did before it waited. */
static void nwkJoinPendingAdd(Nwk_Nwk *self, uint16_t networkAddress, uint64_t extendedAddress,
                              MacFrame_Capability capability)
{
    uint32_t i;

    for (i = 0; i < NWK_JOIN_INDICATION_MAX; i++)
    {
        if (self->joinPendingInUse[i] && self->joinPending[i].extendedAddress == extendedAddress)
            self->joinPendingInUse[i] = 0;
    }

    for (i = 0; i < NWK_JOIN_INDICATION_MAX; i++)
    {
        if (self->joinPendingInUse[i])
            continue;

        Zb_memset(&self->joinPending[i], 0, (uint32_t)sizeof self->joinPending[i]);
        self->joinPending[i].networkAddress = networkAddress;
        self->joinPending[i].extendedAddress = extendedAddress;
        self->joinPending[i].capability = capability;
        self->joinPending[i].joinerMethod = NWK_JOIN_METHOD_ASSOCIATION;
        self->joinPendingInUse[i] = 1;

        return;
    }

    nwkJoinIndicationPush(self, networkAddress, extendedAddress, capability, NWK_JOIN_METHOD_ASSOCIATION);
}

/* 3.6.1.6.1.3's last two sentences: a delivered answer is a join the next higher layer is told of, the device's old
   NWK counter forgotten with it, and one that was not delivered ends the procedure, the child
   it created removed with it. */
void Nwk_JoinCommStatus(Nwk_Nwk *self, const Mac_CommStatusParameters *status)
{
    Nwk_NeighborTableEntry *entry;
    Nwk_JoinIndicationParameters *pending;
    uint32_t i;

    if (self == 0 || status == 0 || status->destAddrMode != MAC_ADDR_EXTENDED)
        return;

    for (i = 0; i < NWK_JOIN_INDICATION_MAX; i++)
    {
        if (!self->joinPendingInUse[i] || self->joinPending[i].extendedAddress != status->destExtended)
            continue;

        pending = &self->joinPending[i];
        self->joinPendingInUse[i] = 0;

        if (status->status == ZB_OK)
        {
            self->joinResponsesDelivered++;
            Security_ForgetSender(self->security, pending->extendedAddress);
            nwkJoinIndicationPush(self, pending->networkAddress, pending->extendedAddress, pending->capability,
                                  pending->joinerMethod);
            return;
        }

        self->joinResponsesUndelivered++;
        entry = nwkJoinNeighborOfIeee(self->neighbors, pending->extendedAddress);

        if (entry != 0 && entry->relationship == NWK_REL_UNAUTHENTICATED_CHILD
            && entry->networkAddress == pending->networkAddress)
            Zb_memset(entry, 0, (uint32_t)sizeof *entry);

        return;
    }
}

/* 3.6.1.6.1.3: the parent's answer to each child 10.21.5.1 brought this device */
static void nwkJoinStepParent(Nwk_Nwk *self, uint32_t nowMs)
{
    Mac_AssociationIndication requests[MAC_ASSOCIATION_MAX];
    Mac_AssociationResponse response;
    Nwk_NeighborTableEntry *entry;
    uint32_t got;
    uint32_t i;
    uint16_t address;
    int addressKnown;

    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        return;

    got = Mac_PollAssociations(self->mac, requests, MAC_ASSOCIATION_MAX);

    for (i = 0; i < got; i++)
    {
        if (requests[i].extendedAddress == 0)
            continue;           

        if (!self->associationPermit)
        {
            nwkJoinAnswerDenied(self, &requests[i], nowMs);

            continue;           
        }

        entry = nwkJoinNeighborOfIeee(self->neighbors, requests[i].extendedAddress);
        address = 0;
        addressKnown = 0;

        if (entry != 0 && entry->networkAddress < NWK_ADDR_RESERVED_LOW)
        {
            address = entry->networkAddress;
            addressKnown = 1;
        }

        if (entry == 0)
            entry = Nwk_NeighborFree(self->neighbors);

        if (entry == 0)
        {
            nwkJoinAnswerCapacity(self, &requests[i], nowMs);

            continue;
        }

        if (!addressKnown && !nwkJoinAddressTake(self, &address))
        {
            nwkJoinAnswerCapacity(self, &requests[i], nowMs);

            continue;
        }

        Zb_memset(entry, 0, (uint32_t)sizeof *entry);

        entry->inUse = 1;
        entry->networkAddress = address;
        entry->extendedAddress = requests[i].extendedAddress;
        entry->ieeeKnown = 1;
        entry->deviceType = requests[i].capability.deviceType ? NWK_DEVICE_ROUTER : NWK_DEVICE_END_DEVICE;
        entry->rxOnWhenIdle = requests[i].capability.rxOnWhenIdle;
        entry->relationship = NWK_REL_UNAUTHENTICATED_CHILD;
        entry->ageFromMs = nowMs;
        entry->routerOutboundActivity = NWK_ROUTER_AGE_LIMIT;
        entry->routerInboundActivity = NWK_ROUTER_AGE_LIMIT;

        if (entry->deviceType == NWK_DEVICE_END_DEVICE)
            Nwk_TimeoutDefault(entry, nowMs);

        if (nwkJoinSecured(self))
            Nwk_NeighborSecurityTimerArm(entry, nwkJoinSecurityTimeout(self), nowMs);

        Zb_memset(&response, 0, (uint32_t)sizeof response);

        response.request = requests[i];
        response.shortAddress = address;
        response.status = MAC_ASSOC_STATUS_SUCCESS;

        if (Mac_AssociateResponse(self->mac, &response, nowMs) != ZB_OK)
        {
            Zb_memset(entry, 0, (uint32_t)sizeof *entry);

            self->joinResponsesDropped++;

            continue;
        }

        self->joinAddressesAssigned++;

        nwkJoinPendingAdd(self, address, requests[i].extendedAddress, requests[i].capability);
    }
}

/* A refusal the requester is told of: no address, and the status the clause names. */
static void nwkJoinCommissioningRefuse(Nwk_Nwk *self, const Nwk_Frame *frame, uint8_t status, int indirect,
                                       uint32_t nowMs)
{
    uint8_t response[NWK_COMMISSIONING_RESPONSE_OCTETS];
    uint32_t responseLen = 0;

    Zb_memset(response, 0, (uint32_t)sizeof response);
    (void)Nwk_CommissioningResponseCompose(NWK_JOIN_ADDRESS_NONE, status, response, (uint32_t)sizeof response,
                                           &responseLen);
    (void)nwkJoinSendCommand(self, frame->srcAddr, frame->srcIeee, NWK_CMD_NETWORK_COMMISSIONING_RESPONSE,
                             response, responseLen, frame->securityEnabled, indirect, nowMs);
}

/* An entry the request names by its IEEE address disagrees with it where the entry knows better: the address, the
   device type or the receiver duty. */
static int nwkJoinCommissioningDiffers(const Nwk_NeighborTableEntry *entry, uint16_t address, uint32_t deviceType,
                                       int rxOnWhenIdle)
{
    int known = entry->deviceType != NWK_NEIGHBOR_TYPE_UNKNOWN;

    return address != entry->networkAddress
           || (known && deviceType != entry->deviceType)
           || (known && (rxOnWhenIdle ? 1 : 0) != (entry->rxOnWhenIdle ? 1 : 0));
}

/* The parent's half of a commissioning join in the parent procedure's order: the permit and security gates, a known
   device matched by IEEE address, an unsecured rejoin that disagrees refused (8106-8110), a known device's Initial Join
   a join again at its entry's address as an association is, and a new device an entry, 0xF0 if its address is held. */
static int nwkJoinCommissioningRequest(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload,
                                       uint32_t payloadLen, uint32_t nowMs)
{
    Nwk_CommissioningRequest request;
    Nwk_NeighborTableEntry *entry;
    Nwk_NeighborTableEntry *existing;
    Nwk_NeighborTableEntry *holder;
    MacFrame_Capability capability;
    uint8_t response[NWK_COMMISSIONING_RESPONSE_OCTETS];
    uint32_t responseLen = 0;
    uint32_t joinerMethod;
    uint32_t deviceType;
    uint16_t address;
    uint32_t status = 0;
    int initialJoin;
    int indirect;
    int taken;

    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        return 0;

    if (!frame->srcIeeePresent)
        return 0;

    if (Nwk_CommissioningRequestParse(payload + 1, payloadLen - 1, &request) != ZB_OK)
    {
        self->droppedMalformed++;

        return 1;
    }

    if (MacFrame_ParseAssociationRequest(&request.capability, 1, &capability) != ZB_OK)
    {
        self->droppedMalformed++;

        return 1;
    }

    indirect = !capability.rxOnWhenIdle;
    initialJoin = request.type == NWK_COMMISSIONING_INITIAL_JOIN;

    if (initialJoin && !self->associationPermit)
    {
        nwkJoinCommissioningRefuse(self, frame, MAC_ASSOC_STATUS_PAN_ACCESS_DENIED, indirect, nowMs);

        return 1;
    }

    if (initialJoin && frame->securityEnabled)
    {
        self->joinCommandsDropped++;

        return 1;
    }

    if (request.type == NWK_COMMISSIONING_REJOIN && !frame->securityEnabled
        && self->trustCenterIeee == NWK_TRUST_CENTER_NONE)
    {
        nwkJoinCommissioningRefuse(self, frame, MAC_ASSOC_STATUS_PAN_ACCESS_DENIED, indirect, nowMs);

        return 1;
    }

    deviceType = capability.deviceType ? NWK_DEVICE_ROUTER : NWK_DEVICE_END_DEVICE;

    address = frame->srcAddr;

    existing = nwkJoinNeighborOfIeee(self->neighbors, frame->srcIeee);
    holder = Nwk_NeighborOf(self->neighbors, address);

    if (existing != 0 && existing->deviceType == NWK_NEIGHBOR_TYPE_UNKNOWN && existing->relationship == NWK_REL_NONE)
        existing = 0;

    if (existing != 0 && !frame->securityEnabled && !initialJoin
        && nwkJoinCommissioningDiffers(existing, address, deviceType, capability.rxOnWhenIdle))
    {
        nwkJoinCommissioningRefuse(self, frame, MAC_ASSOC_STATUS_PAN_ACCESS_DENIED, indirect, nowMs);

        return 1;
    }

    if (initialJoin && existing != 0)
    {
        if (holder != 0 && holder != existing && holder->ieeeKnown && holder->extendedAddress == frame->srcIeee)
            Zb_memset(holder, 0, (uint32_t)sizeof *holder);

        if (existing->networkAddress <= NWK_ADDR_LAST_UNICAST)
            address = existing->networkAddress;

        holder = existing;
    }

    taken = holder != 0 && holder != existing && holder->ieeeKnown && holder->extendedAddress != frame->srcIeee;

    if (taken)
    {
        if (!nwkJoinAddressTake(self, &address))
        {
            nwkJoinCommissioningRefuse(self, frame, MAC_ASSOC_STATUS_PAN_AT_CAPACITY, indirect, nowMs);

            return 1;
        }

        status = NWK_COMMISSIONING_STATUS_ADDRESS_CONFLICT;
    }

    entry = existing;

    if (entry == 0 && holder != 0 && !taken)
        entry = holder;

    if (entry == 0)
        entry = Nwk_NeighborFree(self->neighbors);

    if (entry == 0)
    {
        self->joinResponsesDropped++;

        return 1;
    }

    if (existing != 0 && !initialJoin)
    {
        if (frame->securityEnabled)
        {
            entry->networkAddress = address;
            entry->deviceType = deviceType;
            entry->rxOnWhenIdle = capability.rxOnWhenIdle;
        }

        entry->ageFromMs = nowMs;
    }
    else
    {
        Zb_memset(entry, 0, (uint32_t)sizeof *entry);

        entry->inUse = 1;
        entry->networkAddress = address;
        entry->extendedAddress = frame->srcIeee;
        entry->ieeeKnown = 1;
        entry->deviceType = deviceType;
        entry->rxOnWhenIdle = capability.rxOnWhenIdle;
        entry->relationship = NWK_REL_UNAUTHENTICATED_CHILD;
        entry->ageFromMs = nowMs;
        entry->routerOutboundActivity = NWK_ROUTER_AGE_LIMIT;
        entry->routerInboundActivity = NWK_ROUTER_AGE_LIMIT;

        if (entry->deviceType == NWK_DEVICE_END_DEVICE)
            Nwk_TimeoutDefault(entry, nowMs);

        if (nwkJoinSecured(self))
            Nwk_NeighborSecurityTimerArm(entry, nwkJoinSecurityTimeout(self), nowMs);
    }

    Zb_memset(response, 0, (uint32_t)sizeof response);
    (void)Nwk_CommissioningResponseCompose(address, (uint8_t)status, response, (uint32_t)sizeof response,
                                           &responseLen);

    if (nwkJoinSendCommand(self, frame->srcAddr, frame->srcIeee, NWK_CMD_NETWORK_COMMISSIONING_RESPONSE, response,
                           responseLen, frame->securityEnabled, indirect, nowMs) != ZB_OK)
    {
        self->joinResponsesDropped++;

        return 1;
    }

    joinerMethod = initialJoin
                   ? NWK_JOIN_METHOD_COMMISSIONING_JOIN
                   : (frame->securityEnabled ? NWK_JOIN_METHOD_COMMISSIONING_REJOIN_SECURED
                                             : NWK_JOIN_METHOD_COMMISSIONING_REJOIN);

    self->joinAddressesAssigned++;
    self->commissioningJoins++;

    if (initialJoin)
        Security_ForgetSender(self->security, frame->srcIeee);

    nwkJoinIndicationPush(self, address, frame->srcIeee, capability, joinerMethod);

    return 1;
}


/* The parent's six steps over a child's timeout request: the range, the entry, the configuration bits, the seconds
   the enumeration stands for, the entry's two fields, and the answer that names the keepalive it wants. */
static int nwkJoinTimeoutRequest(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                                 uint32_t nowMs)
{
    Nwk_NeighborTableEntry *entry;
    uint8_t response[NWK_TIMEOUT_RESPONSE_OCTETS];
    uint32_t responseLen = 0;
    uint32_t enumeration = 0;
    uint8_t configuration = 0;
    uint32_t status;
    uint32_t seconds;

    (void)frame;

    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        return 0;

    if (Nwk_TimeoutRequestParse(payload + 1, payloadLen - 1, &enumeration, &configuration) != ZB_OK)
    {
        self->droppedMalformed++;

        return 1;
    }

    if (enumeration > NWK_TIMEOUT_MAX)
        status = NWK_TIMEOUT_STATUS_INCORRECT_VALUE;
    else if (configuration != 0)
        status = NWK_TIMEOUT_STATUS_UNSUPPORTED_FEATURE;
    else
        status = NWK_TIMEOUT_STATUS_SUCCESS;

    entry = Nwk_NeighborOf(self->neighbors, frame->srcAddr);

    if (entry == 0 || entry->deviceType != NWK_DEVICE_END_DEVICE)
        return 1;

    if (status == NWK_TIMEOUT_STATUS_SUCCESS)
    {
        seconds = Nwk_TimeoutSeconds(enumeration);

        entry->deviceTimeout = seconds;
        entry->endDeviceConfiguration = configuration;

        Nwk_TimeoutRestart(entry, nowMs);
    }

    (void)Nwk_TimeoutResponseCompose((uint8_t)status, NWK_PARENT_INFORMATION_MAC_DATA_POLL, response,
                                     (uint32_t)sizeof response, &responseLen);

    if (nwkJoinSendCommand(self, frame->srcAddr, frame->srcIeee, NWK_CMD_END_DEVICE_TIMEOUT_RESPONSE, response,
                           responseLen, 1, !entry->rxOnWhenIdle, nowMs) == ZB_OK)
        self->timeoutResponsesSent++;

    return 1;
}

/* The child's last two steps: it takes the bitmask into its own NIB, where the End Device Initiator bit reads it. */
static int nwkJoinTimeoutResponse(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload,
                                  uint32_t payloadLen, uint32_t nowMs)
{
    uint8_t status = 0;
    uint8_t parentInformation = 0;

    (void)frame;
    (void)nowMs;

    if (Nwk_TimeoutResponseParse(payload + 1, payloadLen - 1, &status, &parentInformation) != ZB_OK)
        return 0;

    if (self->keepalive == NWK_KEEPALIVE_AWAITING_RESPONSE)
    {
        self->keepalive = NWK_KEEPALIVE_NONE;

        if (status != NWK_TIMEOUT_STATUS_SUCCESS)
            Nwk_JoinParentLinkFailed(self, (uint16_t)self->joinParentShort);
        else
            Nwk_JoinParentLinkHeld(self, (uint16_t)self->joinParentShort);
    }

    if (status != NWK_TIMEOUT_STATUS_SUCCESS)
        return 1;

    self->cfg.parentInformation = parentInformation;

    return 1;
}

/* An address conflict's 0xF0: the request once more to the same parent from the address its answer gave, which is not
   a new parent and so not counted; a parent that conflicts twice has failed. */
static int nwkJoinCommissionAgainAt(Nwk_Nwk *self, uint16_t address, uint32_t nowMs)
{
    Radio_Pib pib;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_SHORT_ADDRESS;
    pib.shortAddress = address;

    if (Mac_SetPib(self->mac, &pib) != ZB_OK)
        return 0;

    if (nwkJoinCommission(self, self->joinParentIndex, nowMs) != ZB_OK)
        return 0;

    self->joinConflictRetried = 1;

    return 1;
}

/* The answer to this device's own commissioning request, from the parent it asked and to this device: the address
   it was given, which the PIB takes, the parent it joined, and the confirm behind it. */
static int nwkJoinCommissioningResponse(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload,
                                        uint32_t payloadLen, uint32_t nowMs)
{
    Radio_Pib pib;
    uint16_t address = 0;
    uint16_t own = 0;
    uint8_t status = 0;

    if (Nwk_CommissioningResponseParse(payload + 1, payloadLen - 1, &address, &status) != ZB_OK)
        return 0;

    if (self->joinState != NWK_JOIN_COMMISSIONING)
    {
        self->joinCommandsDropped++;

        return 1;
    }

    if (!frame->srcIeeePresent || !frame->destIeeePresent || !nwkJoinFromTheParent(self, frame)
        || frame->destIeee != nwkJoinOwnIeee(self))
    {
        self->joinCommandsDropped++;

        return 1;
    }

    self->joinParentExtended = frame->srcIeee;

    if (status == NWK_COMMISSIONING_STATUS_ADDRESS_CONFLICT && address < NWK_ADDR_RESERVED_LOW
        && !self->joinConflictRetried && nwkJoinCommissionAgainAt(self, address, nowMs))
        return 1;

    if (status != 0 || address >= NWK_ADDR_RESERVED_LOW)
    {
        if (nwkJoinTryNextParent(self, nowMs))
            return 1;

        nwkJoinCommissionFail(self, status != 0 ? status : NWK_JOIN_STATUS_NO_DATA);

        return 1;
    }

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own) || own != address)
    {
        Zb_memset(&pib, 0, (uint32_t)sizeof pib);
        pib.present = RADIO_PIB_SHORT_ADDRESS;
        pib.shortAddress = address;

        if (Mac_SetPib(self->mac, &pib) != ZB_OK)
        {
            nwkJoinCommissionFail(self, NWK_JOIN_STATUS_NO_DATA);

            return 1;
        }
    }

    Zb_memset(&self->joinConfirm, 0, (uint32_t)sizeof self->joinConfirm);

    Zb_memcpy(self->joinConfirm.extendedPanId, self->joinExtendedPanId, RADIO_ADDR_LEN);

    self->joinConfirm.status = NWK_JOIN_STATUS_SUCCESS;
    self->joinConfirm.networkAddress = address;
    self->joinConfirm.channel = self->joinChannel;
    self->joinConfirm.parentShortKnown = self->joinParentShortKnown;
    self->joinConfirm.parentShort = (uint16_t)self->joinParentShort;
    self->joinConfirm.parentExtended = self->joinParentExtended;

    self->joinState = NWK_JOIN_JOINED;
    self->cfg.parentInformation = 0;
    self->commissioningJoins++;

    nwkJoinRecordParent(self, nowMs);
    self->timeoutRequestPending = 1;
    self->joinConfirmReady = 1;

    return 1;
}

/* 3.6.1.6.1.2's MLME-POLL.request: a Data Request command frame to the parent the rejoin request went to, which
   is 10.22.4.1's shape and the one extraction this layer has to make for itself rather than wait for. */
static ZbStatus nwkJoinPollParent(Nwk_Nwk *self, uint32_t nowMs, Radio_Handle *handle)
{
    const Radio_Pib *pib;
    Mac_DataRequestParameters poll;
    uint8_t content[1];

    content[0] = MAC_CMD_POLL;

    pib = Mac_Pib(self->mac);

    Zb_memset(&poll, 0, (uint32_t)sizeof poll);

    poll.frameType = MAC_FRAME_TYPE_COMMAND;
    poll.destAddrMode = MAC_ADDR_SHORT;

    poll.srcAddrMode = pib->shortAddress < MAC_SHORT_ADDRESS_LAST_USABLE ? MAC_ADDR_SHORT : MAC_ADDR_EXTENDED;
    poll.destPan = pib->panId;
    poll.destShort = (uint16_t)self->joinParentShort;
    poll.ackRequest = 1;
    poll.payload = content;
    poll.payloadLen = 1;

    return Mac_DataRequest(self->mac, &poll, nowMs, handle);
}

static void nwkJoinPoll(Nwk_Nwk *self, uint32_t nowMs)
{
    Radio_Handle handle = RADIO_HANDLE_NONE;

    self->joinPollMs = nowMs;

    if (nwkJoinPollParent(self, nowMs, &handle) != ZB_OK)
        self->joinResponsesDropped++;
}

/* A rejoin's next potential parent: the best-ranked entry of the network asked for, on a channel this layer joins,
   whose short address the request can be sent to and that this rejoin has not tried. */
static uint32_t nwkJoinNextRejoinParent(const Nwk_Nwk *self, const uint8_t *extendedPanId)
{
    uint32_t eligible = 0;
    uint32_t i;

    for (i = 0; i < NWK_JOIN_PARENT_MAX; i++)
    {
        if (!self->joinParents[i].inUse || !self->joinParents[i].shortKnown
            || (self->joinParentsTried & ((uint32_t)1 << i)) != 0)
            continue;

        if (Zb_memcmp(self->joinParents[i].extendedPanId, extendedPanId, RADIO_ADDR_LEN) != 0)
            continue;

        if (self->joinParents[i].channel < NWK_JOIN_CHANNEL_FIRST || self->joinParents[i].channel > NWK_JOIN_CHANNEL_LAST)
            continue;

        eligible |= (uint32_t)1 << i;
    }

    return Nwk_ParentBest(self->joinParents, eligible, Nwk_ParentsGoodLqa(self));
}

/* Table 3-50's bound on the parents one rejoin tries: a config that names 0 takes the printed default */
static uint32_t nwkJoinRejoinAttemptsMax(const Nwk_Nwk *self)
{
    if (self->cfg.maxRejoinParentAttempts == 0)
        return NWK_JOIN_REJOIN_ATTEMPTS_DEFAULT;

    return self->cfg.maxRejoinParentAttempts;
}

/* Rule 1 and rule 2 for a rejoin: Commission Type 0x01 to a parent whose beacon carried the R23 appendix, 0x06 to
   any other or to a parent no discovery entry describes, unless the configuration forces one of the two. */
static int nwkJoinRejoinByCommissioning(const Nwk_Nwk *self, const Nwk_JoinParent *parent)
{
    if (parent == 0)
        return self->cfg.attachMechanism == (uint32_t)NWK_ATTACH_COMMISSIONING;

    return nwkJoinByCommissioning(self, parent);
}

/* 7974-7977 with 7689-7694: Commission Type 0x01 from the rejoin's own address, its Joiner Encapsulation carrying the
   fragmentation parameters and no key negotiation methods. */
static ZbStatus nwkJoinRejoinCommissioning(const Nwk_Nwk *self, uint8_t *out, uint32_t outCap, uint32_t *outLen)
{
    Nwk_CommissioningRequest commissioning;
    uint32_t capabilityLen = 0;
    ZbStatus status;

    Zb_memset(&commissioning, 0, (uint32_t)sizeof commissioning);

    commissioning.type = NWK_COMMISSIONING_REJOIN;
    commissioning.nodeId = self->joinRejoinSource;
    commissioning.fragmentationOptions = NWK_TLV_FRAGMENTATION_APS_BIT;
    commissioning.maxIncomingTransferUnit = APS_FRAG_MAX_ASDU;
    commissioning.sourceEui64 = nwkJoinOwnIeee(self);

    status = MacFrame_ComposeAssociationRequest(&self->joinCapability, &commissioning.capability, 1, &capabilityLen);

    if (status != ZB_OK)
        return status;

    out[0] = NWK_CMD_NETWORK_COMMISSIONING_REQUEST;

    status = Nwk_CommissioningRequestCompose(&commissioning, out + 1, outCap - 1, outLen);

    if (status == ZB_OK)
        (*outLen)++;

    return status;
}

/* The request to one parent on its channel (0 keeps the radio's), from the address and with the capability and
   security the rejoin holds: every attempt goes out here, and the parent it names is the one an answer must come from. */
static ZbStatus nwkJoinRejoinSend(Nwk_Nwk *self, uint16_t parentShort, uint64_t parentExtended, uint32_t channel,
                                  int commissioning, uint32_t nowMs)
{
    Radio_Pib pib;
    Nwk_Frame header;
    const uint8_t *octets;
    uint8_t payload[1 + NWK_COMMISSIONING_OCTETS + 2 + 2 + NWK_TLV_FRAGMENTATION_OCTETS + 2 + NWK_TLV_KEY_NEGOTIATION_OCTETS];
    uint32_t payloadLen = 0;
    uint32_t npduLen;
    uint32_t securedLen;
    uint32_t octetLen;
    ZbStatus status;

    if (channel != 0 && channel != Mac_Pib(self->mac)->channel)
    {
        Zb_memset(&pib, 0, (uint32_t)sizeof pib);
        pib.present = RADIO_PIB_CHANNEL;
        pib.channel = channel;

        status = Mac_SetPib(self->mac, &pib);

        if (status != ZB_OK)
            return status;
    }

    if (commissioning)
        status = nwkJoinRejoinCommissioning(self, payload, (uint32_t)sizeof payload, &payloadLen);
    else
    {
        payload[0] = NWK_CMD_REJOIN_REQUEST;

        status = MacFrame_ComposeAssociationRequest(&self->joinCapability, payload + 1, (uint32_t)sizeof payload - 1,
                                                    &payloadLen);
        payloadLen++;
    }

    if (status != ZB_OK)
        return status;

    Zb_memset(&header, 0, (uint32_t)sizeof header);

    header.frameType = NWK_FRAME_TYPE_COMMAND;
    header.protocolVersion = NWK_PROTOCOL_VERSION;
    header.discoverRoute = NWK_DISCOVER_SUPPRESS;    
    header.destAddr = parentShort;
    header.srcAddr = self->joinRejoinSource;
    header.radius = NWK_JOIN_RADIUS;
    header.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    header.srcIeeePresent = 1;
    header.srcIeee = nwkJoinOwnIeee(self);
    header.destIeeePresent = parentExtended != 0 ? 1 : 0;
    header.destIeee = parentExtended;
    header.securityEnabled = self->joinRejoinSecured ? 1 : 0;
    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    status = NwkFrame_Compose(&header, payload, payloadLen, self->relayNpdu, (uint32_t)sizeof self->relayNpdu,
                              &npduLen);

    if (status != ZB_OK)
        return status;

    octets = self->relayNpdu;
    octetLen = npduLen;

    if (header.securityEnabled)
    {
        status = Nwk_TxProtect(self->security, self->relayNpdu, npduLen, NwkFrame_HeaderLen(&header),
                               self->secureScratch, (uint32_t)sizeof self->secureScratch, &securedLen);

        if (status != ZB_OK)
            return status;

        octets = self->secureScratch;
        octetLen = securedLen;
    }

    status = nwkJoinSend(self, octets, octetLen, parentShort, 0, 1, nowMs);

    if (status != ZB_OK)
        return status;

    self->joinAttempts++;
    self->joinState = NWK_JOIN_REJOINING;
    self->joinAttemptMs = nowMs;
    self->joinPollMs = nowMs;
    self->joinRejoinByCommissioning = commissioning ? 1 : 0;

    if (commissioning)
    {
        self->joinMethod = self->joinRejoinSecured ? NWK_JOIN_METHOD_COMMISSIONING_REJOIN_SECURED
                                                   : NWK_JOIN_METHOD_COMMISSIONING_REJOIN;
    }
    else
        self->joinMethod = self->joinRejoinSecured ? NWK_JOIN_METHOD_REJOIN_SECURED : NWK_JOIN_METHOD_REJOIN_UNSECURED;

    self->joinParentShort = parentShort;
    self->joinParentShortKnown = 1;
    self->joinParentExtended = parentExtended;

    self->joinChannel = Mac_Pib(self->mac)->channel;
    self->joinConfirmReady = 0;

    Zb_memset(&self->joinConfirm, 0, (uint32_t)sizeof self->joinConfirm);

    return ZB_OK;
}

/* An unsuccessful rejoin moves to the next parent of the network asked for until the bound or the list runs out; a
   request the next parent cannot be sent ends the rejoin there, with the failure before it. */
static int nwkJoinTryNextRejoinParent(Nwk_Nwk *self, uint32_t nowMs)
{
    const Nwk_JoinParent *parent;
    uint32_t index;

    if (self->joinAttempts >= nwkJoinRejoinAttemptsMax(self))
        return 0;

    index = nwkJoinNextRejoinParent(self, self->joinExtendedPanId);

    if (index == NWK_JOIN_PARENT_MAX)
        return 0;

    parent = &self->joinParents[index];
    self->joinParentsTried |= (uint32_t)1 << index;
    self->joinConflictRetried = 0;

    return nwkJoinRejoinSend(self, parent->shortAddress, parent->extendedAddress, parent->channel,
                             nwkJoinRejoinByCommissioning(self, parent), nowMs) == ZB_OK;
}

/* 3.6.1.6.1.2's countdown: "the network layer SHALL load a countdown timer with a value of macResponseWaitTime
   ([B1]). If this timer elapses before the appropriate response command frame is received, then the attachment
   mechanism was unsuccessful." 802.15.4 Table 8-36 prints that wait as 32 units of aBaseSuperframeDuration, and the PIB is left untouched. */
static void nwkJoinStepRejoin(Nwk_Nwk *self, uint32_t nowMs)
{
    if (self->joinState != NWK_JOIN_REJOINING)
        return;

    if (!Zb_timeWithin(nowMs, self->joinAttemptMs, MAC_RESPONSE_WAIT_MS))
    {
        if (nwkJoinTryNextRejoinParent(self, nowMs))
            return;

        Zb_memset(&self->joinConfirm, 0, (uint32_t)sizeof self->joinConfirm);

        Zb_memcpy(self->joinConfirm.extendedPanId, self->joinExtendedPanId, RADIO_ADDR_LEN);

        self->joinConfirm.status = NWK_JOIN_STATUS_NO_DATA;
        self->joinConfirm.networkAddress = NWK_JOIN_ADDRESS_NONE;
        self->joinConfirm.channel = self->joinChannel;
        self->joinConfirm.parentShortKnown = self->joinParentShortKnown;
        self->joinConfirm.parentShort = (uint16_t)self->joinParentShort;
        self->joinConfirm.parentExtended = self->joinParentExtended;

        self->joinState = NWK_JOIN_FAILED;
        self->joinConfirmReady = 1;

        return;
    }

    if (self->joinCapability.rxOnWhenIdle)
        return;

    if (Zb_timeWithin(nowMs, self->joinPollMs, MAC_ASSOC_POLL_DELAY_MS))
        return;

    nwkJoinPoll(self, nowMs);      
}

/* The commissioning answer's countdown and its polls, as the rejoin's: a timer of macResponseWaitTime from the
   request, and a Data Request to the parent while it runs when the receiver rests. */
static void nwkJoinStepCommissioning(Nwk_Nwk *self, uint32_t nowMs)
{
    if (self->joinState != NWK_JOIN_COMMISSIONING)
        return;

    if (!Zb_timeWithin(nowMs, self->joinAttemptMs, MAC_RESPONSE_WAIT_MS))
    {
        if (nwkJoinTryNextParent(self, nowMs))
            return;

        nwkJoinCommissionFail(self, NWK_JOIN_STATUS_NO_DATA);

        return;
    }

    if (self->joinCapability.rxOnWhenIdle)
        return;

    if (Zb_timeWithin(nowMs, self->joinPollMs, MAC_ASSOC_POLL_DELAY_MS))
        return;

    nwkJoinPoll(self, nowMs);
}

/* The child's wait for security data, which ends either with the NIB holding the network key or with the countdown
   reaching zero and NO_KEY on a second NLME-JOIN.confirm. */
static void nwkJoinStepKeyWait(Nwk_Nwk *self, uint32_t nowMs)
{
    Nwk_NeighborTableEntry *parent;
    uint16_t own;

    if (self->joinState != NWK_JOIN_JOINED)
        return;

    if (self->security != 0 && Security_IsEnabled(self->security))
        return;

    parent = nwkJoinParentNeighbor(self);

    if (parent == 0 || !Nwk_NeighborSecurityTimerTick(parent, nowMs))
        return;

    self->joinKeyTimeouts++;

    if (self->joinConfirmReady)
    {
        self->joinKeyConfirmsDropped++;
        return;
    }

    Zb_memset(&self->joinConfirm, 0, (uint32_t)sizeof self->joinConfirm);

    Zb_memcpy(self->joinConfirm.extendedPanId, self->joinExtendedPanId, RADIO_ADDR_LEN);

    own = NWK_JOIN_ADDRESS_NONE;

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        own = NWK_JOIN_ADDRESS_NONE;

    self->joinConfirm.status = NWK_STATUS_NO_KEY;
    self->joinConfirm.networkAddress = own;
    self->joinConfirm.channel = self->joinChannel;
    self->joinConfirm.parentShortKnown = self->joinParentShortKnown;
    self->joinConfirm.parentShort = (uint16_t)self->joinParentShort;
    self->joinConfirm.parentExtended = self->joinParentExtended;
    self->joinConfirmReady = 1;
}

/* The parent's countdown for a child that has not shown a network-secured frame since it joined, and its deletion. */
static void nwkJoinStepChildTimer(Nwk_Nwk *self, uint32_t nowMs)
{
    Nwk_NeighborTableEntry *entry;
    uint32_t i;

    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        return;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        entry = &self->neighbors[i];

        if (!entry->inUse || entry->relationship != NWK_REL_UNAUTHENTICATED_CHILD)
            continue;

        if (!Nwk_NeighborSecurityTimerTick(entry, nowMs))
            continue;

        Zb_memset(entry, 0, (uint32_t)sizeof *entry);

        self->joinChildrenExpired++;
    }
}

/* 3.6.1.6.1.1 and 3.6.1.6.1.3 are the two countdowns this turn carries: the child's wait for the network key and the
   parent's for a child that has not yet shown itself authorized. */
/* The orphan scan's outcome: a realignment joins the device at the address it names, under the coordinator that sent
   it, as any join's parent; no realignment is the scan's status on the confirm (6163-6165). */
static void nwkJoinStepOrphan(Nwk_Nwk *self, uint32_t nowMs)
{
    Mac_ScanConfirmParameters scan;

    if (self->joinState != NWK_JOIN_ORPHANING || Mac_PollScanConfirm(self->mac, &scan) != 1)
        return;

    Zb_memset(&self->joinConfirm, 0, (uint32_t)sizeof self->joinConfirm);

    Zb_memcpy(self->joinConfirm.extendedPanId, self->joinExtendedPanId, RADIO_ADDR_LEN);

    if (scan.status != 0 || !scan.realigned || scan.shortAddress >= NWK_ADDR_RESERVED_LOW)
    {
        self->joinState = NWK_JOIN_FAILED;
        self->joinConfirm.status = scan.status != 0 ? scan.status : NWK_JOIN_STATUS_NO_DATA;
        self->joinConfirm.networkAddress = NWK_JOIN_ADDRESS_NONE;
        self->joinConfirmReady = 1;

        return;
    }

    self->joinParentShort = scan.coordShort;
    self->joinParentShortKnown = 1;
    self->joinParentExtended = scan.coordExtended;
    self->joinChannel = scan.channel;

    self->joinState = NWK_JOIN_JOINED;
    self->cfg.parentInformation = 0;

    self->joinConfirm.status = NWK_JOIN_STATUS_SUCCESS;
    self->joinConfirm.networkAddress = scan.shortAddress;
    self->joinConfirm.channel = scan.channel;
    self->joinConfirm.parentShortKnown = 1;
    self->joinConfirm.parentShort = scan.coordShort;
    self->joinConfirm.parentExtended = scan.coordExtended;

    nwkJoinRecordParent(self, nowMs);
    self->timeoutRequestPending = 1;

    self->joinConfirmReady = 1;
}

/* 5199-5205 and 5283 at a parent: an orphan this device holds as a child is realigned to the address it has, and one
   it holds no child entry for is answered as no member, which sends nothing. */
static void nwkJoinStepOrphans(Nwk_Nwk *self, uint32_t nowMs)
{
    Mac_OrphanIndication orphan;
    Mac_OrphanResponseParameters response;
    Nwk_NeighborTableEntry *entry;

    while (Mac_PollOrphans(self->mac, &orphan, 1) == 1)
    {
        entry = nwkJoinNeighborOfIeee(self->neighbors, orphan.orphanAddress);

        Zb_memset(&response, 0, (uint32_t)sizeof response);
        response.orphanAddress = orphan.orphanAddress;
        response.shortAddress = NWK_JOIN_ADDRESS_NONE;

        if (Nwk_AddrHasRoutingDuty(self->cfg.deviceType) && entry != 0
            && (entry->relationship == NWK_REL_CHILD || entry->relationship == NWK_REL_UNAUTHENTICATED_CHILD))
        {
            response.shortAddress = entry->networkAddress;
            response.associatedMember = 1;
        }

        if (Mac_OrphanResponse(self->mac, &response, nowMs) == ZB_OK && response.associatedMember)
            self->orphansRealigned++;
        else
            self->orphansUnknown++;
    }
}

/* The keepalive by the method the parent named: a MAC data poll where it named that one, a timeout request where it
   named only that, and a poll where it named neither, which any parent answers. */
static void nwkJoinStepKeepalive(Nwk_Nwk *self, uint32_t nowMs)
{
    Radio_Handle handle = RADIO_HANDLE_NONE;
    ZbStatus status;

    if (self->keepalive == NWK_KEEPALIVE_REQUESTING && !self->timeoutRequestPending)
    {
        self->keepalive = NWK_KEEPALIVE_AWAITING_RESPONSE;
        self->keepaliveSinceMs = nowMs;
        self->keepalivesSent++;

        return;
    }

    if (self->keepalive == NWK_KEEPALIVE_AWAITING_RESPONSE
        && !Zb_timeWithin(nowMs, self->keepaliveSinceMs, NWK_KEEPALIVE_RESPONSE_WAIT_MS))
    {
        self->keepalive = NWK_KEEPALIVE_NONE;
        Nwk_JoinParentLinkFailed(self, (uint16_t)self->joinParentShort);

        return;
    }

    if (self->keepalive != NWK_KEEPALIVE_OWED || self->joinState != NWK_JOIN_JOINED)
        return;

    if (nwkJoinSecured(self) && !Nwk_TxSecurityRuns(self->security))
        return;

    if ((self->cfg.parentInformation & NWK_PARENT_INFORMATION_TIMEOUT_REQUEST) != 0
        && (self->cfg.parentInformation & NWK_PARENT_INFORMATION_MAC_DATA_POLL) == 0)
    {
        self->keepalive = NWK_KEEPALIVE_REQUESTING;
        self->timeoutRequestPending = 1;

        return;
    }

    status = nwkJoinPollParent(self, nowMs, &handle);

    if (status == ZB_ERR_BUSY)
        return;

    self->keepalive = status == ZB_OK ? NWK_KEEPALIVE_POLLING : NWK_KEEPALIVE_NONE;
    self->keepaliveHandle = handle;

    if (status == ZB_OK)
        self->keepalivesSent++;
}

void Nwk_JoinKeepaliveOwe(Nwk_Nwk *self)
{
    if (self == 0 || self->cfg.deviceType != NWK_DEVICE_END_DEVICE || self->joinState != NWK_JOIN_JOINED
        || self->keepalive != NWK_KEEPALIVE_NONE)
        return;

    self->keepalive = NWK_KEEPALIVE_OWED;
}

int Nwk_JoinKeepaliveAnswered(Nwk_Nwk *self, const Mac_DataConfirmParameters *confirm)
{
    if (self == 0 || confirm == 0 || self->keepalive != NWK_KEEPALIVE_POLLING || confirm->handle != self->keepaliveHandle)
        return 0;

    self->keepalive = NWK_KEEPALIVE_NONE;

    if (confirm->status == ZB_ERR_NO_ACK || confirm->status == ZB_ERR_DEVICE)
        Nwk_JoinParentLinkFailed(self, (uint16_t)self->joinParentShort);
    else if (confirm->status == ZB_OK)
        Nwk_JoinParentLinkHeld(self, (uint16_t)self->joinParentShort);

    return 1;
}

void Nwk_JoinStep(Nwk_Nwk *self, uint32_t nowMs)
{
    if (self == 0 || self->mac == 0)
        return;

    nwkJoinStepOwed(self, nowMs);

    nwkJoinStepChild(self, nowMs);

    nwkJoinStepRejoin(self, nowMs);

    nwkJoinStepCommissioning(self, nowMs);

    nwkJoinStepOrphan(self, nowMs);

    nwkJoinStepParent(self, nowMs);

    nwkJoinStepOrphans(self, nowMs);

    nwkJoinStepKeyWait(self, nowMs);

    nwkJoinStepChildTimer(self, nowMs);

    nwkJoinStepKeepalive(self, nowMs);
}

/* 3.4.7.2's header, secured to the level the request carried (3.4.7.2's last paragraph); `indirect` is 3.4.7.1's
   TXOptions: a device whose rejoin said its receiver rests has the frame held for it, one that listens gets it
   sent. */
/* 3.6.1.10.3: the parent checks a rejoining device's short address against its own map, and an address the map holds
   for another device is not allowed: a new one is drawn and the answer names it while the frame stays addressed to
   the old one at the MAC layer, the rejoin still succeeding. */

static uint16_t nwkJoinResolveRejoinAddress(Nwk_Nwk *self, Nwk_NeighborTableEntry *entry, const Nwk_Frame *frame)
{
    uint64_t mapped = 0;
    uint16_t replacement = 0;

    if (!Nwk_AddrMapExtendedOf(self->addressMap, entry->networkAddress, &mapped))
        return entry->networkAddress;

    if (mapped == frame->srcIeee)
        return entry->networkAddress;

    if (!nwkJoinAddressTake(self, &replacement))
        return entry->networkAddress;

    entry->networkAddress = replacement;

    self->addressConflictsOther++;

    return replacement;
}

/* A rejoin response's payload: the command identifier, the address least significant octet first, and the rejoin
   status. */
static void nwkJoinRejoinResponseWrite(uint8_t *payload, uint16_t address, uint8_t status)
{
    U_BStream stream;

    U_bstream_init(&stream, payload, NWK_COMMAND_REJOIN_RESPONSE_OCTETS);
    U_bstream_put_u8(&stream, NWK_CMD_REJOIN_RESPONSE);
    U_bstream_put_u16_le(&stream, address);
    U_bstream_put_u8(&stream, status);
}

static void nwkJoinRejoinResponseRead(const uint8_t *payload, uint16_t *address, uint8_t *status)
{
    U_BStream stream;

    Zb_bstream_init_const(&stream, payload, NWK_COMMAND_REJOIN_RESPONSE_OCTETS);
    U_bstream_advance(&stream, 1);
    *address = U_bstream_get_u16_le(&stream);
    *status = U_bstream_get_u8(&stream);
}

/* 3.6.1.10.5's unsolicited answer: the parent tells an end-device child its new address, network-encrypted as
   3.6.1.10.6 requires of any unsolicited rejoin response. */
uint16_t Nwk_JoinReaddressChild(Nwk_Nwk *self, Nwk_NeighborTableEntry *child, uint32_t nowMs)
{
    uint16_t newAddress = 0;
    Mac_DataRequestParameters held;
    Nwk_Frame reply;
    uint8_t payload[NWK_COMMAND_REJOIN_RESPONSE_OCTETS];
    const uint8_t *octets;
    uint16_t own;
    uint32_t npduLen;
    uint32_t securedLen;
    uint32_t octetLen;
    uint64_t ownIeee;

    if (self == 0 || child == 0 || !child->inUse)
        return 0;

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        return 0;

    if (!nwkJoinAddressTake(self, &newAddress))
        return 0;

    ownIeee = nwkJoinOwnIeee(self);

    nwkJoinRejoinResponseWrite(payload, newAddress, MAC_ASSOC_STATUS_SUCCESS);

    Zb_memset(&reply, 0, (uint32_t)sizeof reply);

    reply.frameType = NWK_FRAME_TYPE_COMMAND;
    reply.protocolVersion = NWK_PROTOCOL_VERSION;
    reply.discoverRoute = NWK_DISCOVER_SUPPRESS;
    reply.destAddr = child->networkAddress;
    reply.srcAddr = own;
    reply.radius = NWK_JOIN_RADIUS;
    reply.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    reply.srcIeeePresent = 1;
    reply.srcIeee = ownIeee;
    reply.destIeeePresent = 1;
    reply.destIeee = child->extendedAddress;
    reply.securityEnabled = Nwk_TxSecurityRuns(self->security) ? 1 : 0;
    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    if (NwkFrame_Compose(&reply, payload, (uint32_t)sizeof payload, self->relayNpdu,
                         (uint32_t)sizeof self->relayNpdu, &npduLen) != ZB_OK)
    {
        self->joinResponsesDropped++;
        return 0;
    }

    octets = self->relayNpdu;
    octetLen = npduLen;

    if (reply.securityEnabled)
    {
        if (Nwk_TxProtect(self->security, self->relayNpdu, npduLen, NwkFrame_HeaderLen(&reply),
                          self->secureScratch, (uint32_t)sizeof self->secureScratch, &securedLen) != ZB_OK)
        {
            self->joinResponsesDropped++;
            return 0;
        }

        octets = self->secureScratch;
        octetLen = securedLen;
    }

    Zb_memset(&held, 0, (uint32_t)sizeof held);

    held.frameType = MAC_FRAME_TYPE_DATA;
    held.destAddrMode = MAC_ADDR_SHORT;
    held.srcAddrMode = MAC_ADDR_SHORT;
    held.destPan = Mac_Pib(self->mac)->panId;
    held.destShort = child->networkAddress;
    held.ackRequest = 1;
    held.payload = octets;
    held.payloadLen = octetLen;

    if (child->rxOnWhenIdle)
    {
        if (nwkJoinSend(self, octets, octetLen, child->networkAddress, 0, 0, nowMs) != ZB_OK)
        {
            self->joinResponsesDropped++;

            return 0;
        }
    }
    else if (Mac_IndirectRequest(self->mac, &held, nowMs) != ZB_OK)
    {
        self->joinResponsesDropped++;

        return 0;
    }

    self->addressUpdatesSent++;
    child->networkAddress = newAddress;

    return newAddress;
}

static void nwkJoinRejoinAnswer(Nwk_Nwk *self, const Nwk_Frame *request, uint16_t networkAddress, uint8_t status,
                                int indirect, uint32_t nowMs)
{
    Mac_DataRequestParameters held;
    Nwk_Frame reply;
    uint8_t payload[NWK_COMMAND_REJOIN_RESPONSE_OCTETS];
    const uint8_t *octets;
    uint16_t own;
    uint32_t npduLen;
    uint32_t securedLen;
    uint32_t octetLen;

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        return;                 

    nwkJoinRejoinResponseWrite(payload, networkAddress, status);

    Zb_memset(&reply, 0, (uint32_t)sizeof reply);

    reply.frameType = NWK_FRAME_TYPE_COMMAND;
    reply.protocolVersion = NWK_PROTOCOL_VERSION;
    reply.discoverRoute = NWK_DISCOVER_SUPPRESS;    
    reply.destAddr = request->srcAddr;              
    reply.srcAddr = own;
    reply.radius = NWK_JOIN_RADIUS;
    reply.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    reply.srcIeeePresent = 1;                       
    reply.srcIeee = nwkJoinOwnIeee(self);
    reply.destIeeePresent = 1;                      
    reply.destIeee = request->srcIeee;
    reply.securityEnabled = request->securityEnabled ? 1 : 0;
    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    if (NwkFrame_Compose(&reply, payload, (uint32_t)sizeof payload, self->relayNpdu,
                         (uint32_t)sizeof self->relayNpdu, &npduLen) != ZB_OK)
    {
        self->joinResponsesDropped++;
        return;
    }

    octets = self->relayNpdu;
    octetLen = npduLen;

    if (reply.securityEnabled)
    {
        if (Nwk_TxProtect(self->security, self->relayNpdu, npduLen, NwkFrame_HeaderLen(&reply),
                          self->secureScratch, (uint32_t)sizeof self->secureScratch, &securedLen) != ZB_OK)
        {
            self->joinResponsesDropped++;
            return;
        }

        octets = self->secureScratch;
        octetLen = securedLen;
    }

    if (indirect)
    {
        Zb_memset(&held, 0, (uint32_t)sizeof held);

        held.frameType = MAC_FRAME_TYPE_DATA;      
        held.destAddrMode = MAC_ADDR_SHORT;        
        held.srcAddrMode = MAC_ADDR_SHORT;
        held.destPan = Mac_Pib(self->mac)->panId;
        held.destShort = request->srcAddr;
        held.ackRequest = 1;
        held.payload = octets;
        held.payloadLen = octetLen;

        if (Mac_IndirectRequest(self->mac, &held, nowMs) != ZB_OK)
            self->joinResponsesDropped++;

        return;
    }

    if (nwkJoinSend(self, octets, octetLen, request->srcAddr, 0, 0, nowMs) != ZB_OK)
        self->joinResponsesDropped++;
}

/* 3.6.1.6.1.3: this device as the parent a 3.4.6 request asked. 1 when the frame was that request and this device
   answered or silently refused it, 0 when it is not a request this device is a parent for (3.6.13's 0x13). */
static int nwkJoinRejoinRequest(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                               uint32_t nowMs)
{
    MacFrame_Capability capability;
    Nwk_NeighborTableEntry *entry;
    Nwk_NeighborTableEntry *holder;
    uint32_t deviceType;
    uint16_t own;
    uint16_t address;
    int capabilityKnown;
    int indirect;

    if (payloadLen != 2)
        return 0;

    if (frame->frameType != NWK_FRAME_TYPE_COMMAND)
        return 0;

    if (!frame->srcIeeePresent || frame->srcIeee == 0)
        return 0;

    if (Nwk_AddrIsBroadcast(frame->srcAddr) || Nwk_AddrIsReserved(frame->srcAddr))
        return 0;

    if (self->cfg.deviceType != NWK_DEVICE_COORDINATOR && self->cfg.deviceType != NWK_DEVICE_ROUTER)
        return 0;

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        return 0;

    if (MacFrame_ParseAssociationRequest(payload + 1, 1, &capability) != ZB_OK)
        return 0;

    if (!frame->securityEnabled && self->trustCenterIeee == NWK_TRUST_CENTER_NONE)
    {
        self->joinMethod = NWK_JOIN_METHOD_REJOIN_UNSECURED;

        nwkJoinRejoinAnswer(self, frame, NWK_JOIN_ADDRESS_NONE, MAC_ASSOC_STATUS_PAN_ACCESS_DENIED,
                            capability.rxOnWhenIdle ? 0 : 1, nowMs);

        return 1;
    }

    indirect = capability.rxOnWhenIdle ? 0 : 1;
    deviceType = capability.deviceType ? NWK_DEVICE_ROUTER : NWK_DEVICE_END_DEVICE;

    entry = nwkJoinNeighborOfIeee(self->neighbors, frame->srcIeee);

    holder = Nwk_NeighborOf(self->neighbors, frame->srcAddr);

    if (entry == 0 && holder != 0 && holder->ieeeKnown && holder->extendedAddress != frame->srcIeee)
    {
        nwkJoinRejoinAnswer(self, frame, NWK_JOIN_ADDRESS_NONE, MAC_ASSOC_STATUS_PAN_ACCESS_DENIED, indirect, nowMs);

        return 1;
    }

    if (entry == 0)
    {
        entry = holder != 0 ? holder : Nwk_NeighborFree(self->neighbors);

        if (entry == 0)
        {
            nwkJoinRejoinAnswer(self, frame, NWK_JOIN_ADDRESS_NONE, MAC_ASSOC_STATUS_PAN_AT_CAPACITY, indirect, nowMs);

            return 1;
        }

        Zb_memset(entry, 0, (uint32_t)sizeof *entry);

        entry->inUse = 1;
        entry->networkAddress = frame->srcAddr;
        entry->extendedAddress = frame->srcIeee;
        entry->ieeeKnown = 1;
        entry->deviceType = deviceType;
        entry->rxOnWhenIdle = capability.rxOnWhenIdle;

        entry->relationship = frame->securityEnabled ? NWK_REL_CHILD : NWK_REL_UNAUTHENTICATED_CHILD;
        entry->ageFromMs = nowMs;
        entry->routerOutboundActivity = NWK_ROUTER_AGE_LIMIT;
        entry->routerInboundActivity = NWK_ROUTER_AGE_LIMIT;

        self->joinAddressesAssigned++;
    }
    else
    {
        capabilityKnown = entry->deviceType != NWK_NEIGHBOR_TYPE_UNKNOWN;

        if (!frame->securityEnabled
            && (frame->srcAddr != entry->networkAddress
                || (capabilityKnown && deviceType != entry->deviceType)
                || (capabilityKnown && (capability.rxOnWhenIdle ? 1 : 0) != (entry->rxOnWhenIdle ? 1 : 0))))
        {
            nwkJoinRejoinAnswer(self, frame, NWK_JOIN_ADDRESS_NONE, MAC_ASSOC_STATUS_PAN_ACCESS_DENIED, indirect,
                                nowMs);

            return 1;
        }

        if (!capabilityKnown && entry->relationship == NWK_REL_NONE)
            entry->relationship = NWK_REL_UNAUTHENTICATED_CHILD;

        entry->networkAddress = frame->srcAddr;
        entry->extendedAddress = frame->srcIeee;
        entry->ieeeKnown = 1;
        entry->deviceType = deviceType;
        entry->rxOnWhenIdle = capability.rxOnWhenIdle;
        entry->ageFromMs = nowMs;
    }

    if (entry->deviceType == NWK_DEVICE_END_DEVICE)
        Nwk_TimeoutDefault(entry, nowMs);

    if (entry->relationship == NWK_REL_UNAUTHENTICATED_CHILD && nwkJoinSecured(self))
        Nwk_NeighborSecurityTimerArm(entry, nwkJoinSecurityTimeout(self), nowMs);

    address = nwkJoinResolveRejoinAddress(self, entry, frame);

    nwkJoinRejoinAnswer(self, frame, address, MAC_ASSOC_STATUS_SUCCESS, indirect, nowMs);

    self->joinRoutesDeleted += Nwk_RouteDelete(self, address);

    nwkJoinIndicationPush(self, address, frame->srcIeee, capability,
                          frame->securityEnabled ? NWK_JOIN_METHOD_REJOIN_SECURED
                                                 : NWK_JOIN_METHOD_REJOIN_UNSECURED);

    return 1;
}

/* 3.6.1.6.1.2: the child's half of the response, whose checks are the clause's two IEEE comparisons */
/* 3.6.1.10.5's unsolicited response: an end device that is already joined is told a new address by its parent, changes
   to it, and reports the change upward as Table 3-25's NLME-NWK-STATUS.indication. 3.6.1.10.6 requires the frame to
   be network encrypted, and one that is not is dropped. */
static int nwkJoinUnsolicitedResponse(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload,
                                      uint32_t payloadLen)
{
    Radio_Pib pib;
    uint16_t address;
    uint8_t status;

    if (payloadLen != NWK_COMMAND_REJOIN_RESPONSE_OCTETS)
    {
        self->joinCommandsDropped++;

        return 1;
    }

    nwkJoinRejoinResponseRead(payload, &address, &status);

    if (status != MAC_ASSOC_STATUS_SUCCESS)
    {
        self->joinCommandsDropped++;

        return 1;
    }

    if (!frame->securityEnabled)
    {
        self->joinCommandsDropped++;

        return 1;
    }

    if (!frame->srcIeeePresent || frame->srcIeee != self->joinParentExtended)
    {
        self->joinCommandsDropped++;

        return 1;
    }

    if (address >= NWK_ADDR_RESERVED_LOW)
    {
        self->joinCommandsDropped++;

        return 1;
    }

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);

    pib.present = RADIO_PIB_SHORT_ADDRESS;
    pib.shortAddress = address;

    if (Mac_SetPib(self->mac, &pib) != ZB_OK)
    {
        self->joinCommandsDropped++;

        return 1;
    }

    self->addressUpdatesTaken++;

    nwkJoinIndicate(self, NWK_STATUS_CODE_NETWORK_ADDRESS_UPDATE, address);

    return 1;
}

/* A rejoin's answer, by 0x07 or by commissioning: a refusal moves to the next parent, the last one ends the rejoin,
   and success takes the address and the parent. */
static void nwkJoinRejoinAnswered(Nwk_Nwk *self, uint16_t address, uint8_t status, uint32_t nowMs)
{
    Radio_Pib pib;

    if ((status != NWK_JOIN_STATUS_SUCCESS || address >= NWK_ADDR_RESERVED_LOW) && nwkJoinTryNextRejoinParent(self, nowMs))
        return;

    Zb_memset(&self->joinConfirm, 0, (uint32_t)sizeof self->joinConfirm);

    Zb_memcpy(self->joinConfirm.extendedPanId, self->joinExtendedPanId, RADIO_ADDR_LEN);

    if (status != NWK_JOIN_STATUS_SUCCESS || address >= NWK_ADDR_RESERVED_LOW)
    {
        self->joinState = NWK_JOIN_FAILED;
        self->joinConfirm.status = status != NWK_JOIN_STATUS_SUCCESS ? status : NWK_JOIN_STATUS_NO_DATA;
        self->joinConfirm.networkAddress = NWK_JOIN_ADDRESS_NONE;
        self->joinConfirmReady = 1;

        return;
    }

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);

    pib.present = RADIO_PIB_SHORT_ADDRESS;
    pib.shortAddress = address;

    if (Mac_SetPib(self->mac, &pib) != ZB_OK)
    {
        self->joinState = NWK_JOIN_FAILED;
        self->joinConfirm.status = NWK_JOIN_STATUS_NO_DATA;
        self->joinConfirm.networkAddress = NWK_JOIN_ADDRESS_NONE;
        self->joinConfirmReady = 1;

        return;
    }

    self->joinState = NWK_JOIN_JOINED;

    self->cfg.parentInformation = 0;
    self->joinConfirm.status = NWK_JOIN_STATUS_SUCCESS;
    self->joinConfirm.networkAddress = address;
    self->joinConfirm.channel = self->joinChannel;
    self->joinConfirm.parentShortKnown = self->joinParentShortKnown;
    self->joinConfirm.parentShort = (uint16_t)self->joinParentShort;
    self->joinConfirm.parentExtended = self->joinParentExtended;

    nwkJoinRecordParent(self, nowMs);
    self->timeoutRequestPending = 1;

    self->joinConfirmReady = 1;
}

/* The answer to a Commissioning Rejoin, judged as 8056-8061 judge any rejoin's: from the parent asked and to this
   device. 0xF0 asks the same parent again once, from the address it names (7737-7738). */
static int nwkJoinRejoinCommissioned(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload,
                                     uint32_t payloadLen, uint32_t nowMs)
{
    Radio_Pib pib;
    uint16_t address = 0;
    uint8_t status = 0;

    if (Nwk_CommissioningResponseParse(payload + 1, payloadLen - 1, &address, &status) != ZB_OK)
        return 0;

    if (!frame->srcIeeePresent || !frame->destIeeePresent || !nwkJoinFromTheParent(self, frame)
        || frame->destIeee != nwkJoinOwnIeee(self))
    {
        self->joinCommandsDropped++;

        return 1;
    }

    self->joinParentExtended = frame->srcIeee;

    if (status == NWK_COMMISSIONING_STATUS_ADDRESS_CONFLICT && address < NWK_ADDR_RESERVED_LOW
        && !self->joinConflictRetried)
    {
        Zb_memset(&pib, 0, (uint32_t)sizeof pib);
        pib.present = RADIO_PIB_SHORT_ADDRESS;
        pib.shortAddress = address;

        self->joinConflictRetried = 1;
        self->joinRejoinSource = address;

        if (Mac_SetPib(self->mac, &pib) == ZB_OK
            && nwkJoinRejoinSend(self, (uint16_t)self->joinParentShort, self->joinParentExtended, 0, 1, nowMs) == ZB_OK)
            return 1;
    }

    nwkJoinRejoinAnswered(self, address, status, nowMs);

    return 1;
}

static int nwkJoinRejoinResponse(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload,
                                 uint32_t payloadLen, uint32_t nowMs)
{
    uint64_t ownIeee;
    uint16_t address;
    uint8_t status;

    if (self->joinState == NWK_JOIN_JOINED)
        return nwkJoinUnsolicitedResponse(self, frame, payload, payloadLen);

    if (self->joinState != NWK_JOIN_REJOINING)
    {
        self->joinCommandsDropped++;

        return 1;
    }

    if (payloadLen != NWK_COMMAND_REJOIN_RESPONSE_OCTETS)
    {
        self->joinCommandsDropped++;

        return 1;
    }

    ownIeee = nwkJoinOwnIeee(self);

    if (!frame->srcIeeePresent || !frame->destIeeePresent || !nwkJoinFromTheParent(self, frame)
        || frame->destIeee != ownIeee)
    {
        self->joinCommandsDropped++;

        return 1;
    }

    self->joinParentExtended = frame->srcIeee;

    nwkJoinRejoinResponseRead(payload, &address, &status);

    nwkJoinRejoinAnswered(self, address, status, nowMs);

    return 1;
}



int Nwk_JoinHandleCommand(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                          uint32_t nowMs)
{
    if (self == 0 || frame == 0 || payload == 0 || payloadLen < 1)
        return 0;

    if (payload[0] == NWK_CMD_REJOIN_REQUEST)
        return nwkJoinRejoinRequest(self, frame, payload, payloadLen, nowMs);

    if (payload[0] == NWK_CMD_REJOIN_RESPONSE)
        return nwkJoinRejoinResponse(self, frame, payload, payloadLen, nowMs);

    if (payload[0] == NWK_CMD_NETWORK_COMMISSIONING_REQUEST)
        return nwkJoinCommissioningRequest(self, frame, payload, payloadLen, nowMs);

    if (payload[0] == NWK_CMD_NETWORK_COMMISSIONING_RESPONSE && self->joinState == NWK_JOIN_REJOINING
        && self->joinRejoinByCommissioning)
        return nwkJoinRejoinCommissioned(self, frame, payload, payloadLen, nowMs);

    if (payload[0] == NWK_CMD_NETWORK_COMMISSIONING_RESPONSE)
        return nwkJoinCommissioningResponse(self, frame, payload, payloadLen, nowMs);

    if (payload[0] == NWK_CMD_END_DEVICE_TIMEOUT_REQUEST)
        return nwkJoinTimeoutRequest(self, frame, payload, payloadLen, nowMs);

    if (payload[0] == NWK_CMD_END_DEVICE_TIMEOUT_RESPONSE)
        return nwkJoinTimeoutResponse(self, frame, payload, payloadLen, nowMs);

    return 0;
}

/* 3.2.2.15 and Table 3-23: INV_REQUESTTYPE and NOT_PERMITTED are statuses of the NLME-JOIN.confirm, so a request
   this device refuses at the door answers with a confirm beside the door's own ZbStatus. A request no exchange
   started for is a failed join whose network address is 3.4.7.3.1's 0xffff and whose channel is the radio's own. */
static void nwkJoinAnswer(Nwk_Nwk *self, const Nwk_JoinRequestParameters *req, uint32_t status)
{
    Zb_memset(&self->joinConfirm, 0, (uint32_t)sizeof self->joinConfirm);

    self->joinConfirm.status = status;
    self->joinConfirm.networkAddress = NWK_JOIN_ADDRESS_NONE;
    Zb_memcpy(self->joinConfirm.extendedPanId, req->extendedPanId, RADIO_ADDR_LEN);
    self->joinConfirm.channel = Mac_Pib(self->mac)->channel;

    self->joinConfirmReady = 1;
}

/* 3.2.2.13's RejoinNetwork 0x02, 3.6.1.6.1.2's request: 3.4.6's command frame to the parent this device has, whose
   answer 3.4.7 carries and whose arrival is `Nwk_JoinHandleCommand`'s business. */
static ZbStatus nwkJoinRequestRejoin(Nwk_Nwk *self, const Nwk_JoinRequestParameters *req, uint32_t nowMs)
{
    Nwk_NeighborTableEntry *neighbor;
    uint16_t own;
    uint16_t parentShort;
    uint64_t parentExtended;
    uint32_t index;
    ZbStatus status;

    if (self->joinState == NWK_JOIN_ASSOCIATING || self->joinState == NWK_JOIN_REJOINING
        || self->joinState == NWK_JOIN_COMMISSIONING || self->joinState == NWK_JOIN_ORPHANING)
        return ZB_ERR_BUSY;

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own) && !nwkJoinAddressTake(self, &own))
        return ZB_ERR_BAD_STATE;

    neighbor = 0;
    index = NWK_JOIN_PARENT_MAX;
    self->joinParentsTried = 0;
    self->joinAttempts = 0;

    if (nwkJoinPanIdUnset(req->extendedPanId))
    {
        neighbor = nwkJoinParentNeighbor(self);

        if (neighbor != 0 && neighbor->ieeeKnown && neighbor->networkAddress < NWK_ADDR_RESERVED_LOW)
        {
            parentShort = neighbor->networkAddress;
            parentExtended = neighbor->extendedAddress;
        }
        else
            neighbor = 0;
    }

    if (neighbor == 0)
    {
        index = nwkJoinNextRejoinParent(self, req->extendedPanId);

        if (index == NWK_JOIN_PARENT_MAX)
            return ZB_ERR_NOT_FOUND;

        parentShort = self->joinParents[index].shortAddress;
        parentExtended = self->joinParents[index].extendedAddress;
    }

    if (req->securityEnable
        && !(self->security != 0 && Security_Level(self->security) != SECURITY_LEVEL_NONE))
        return ZB_ERR_UNSUPPORTED;    /* 3.6.1.6.1.1's secured join needs the network key, not built, docs/internals/conformance.md §2 */

    if (!nwkJoinCapabilitySet(&self->joinCapability))
        self->joinCapability = req->capability;

    self->joinRejoinSource = own;
    self->joinRejoinSecured = req->securityEnable ? 1 : 0;
    self->joinConflictRetried = 0;

    status = nwkJoinRejoinSend(self, parentShort, parentExtended,
                               neighbor != 0 ? 0 : self->joinParents[index].channel,
                               nwkJoinRejoinByCommissioning(self, neighbor != 0 ? 0 : &self->joinParents[index]),
                               nowMs);

    if (status != ZB_OK)
        return status;

    if (neighbor != 0)
        self->joinParentsTried = ~(uint32_t)0;
    else
        self->joinParentsTried = (uint32_t)1 << index;

    if (neighbor == 0)
        Zb_memcpy(self->joinExtendedPanId, self->joinParents[index].extendedPanId, RADIO_ADDR_LEN);
    else if (!nwkJoinPanIdUnset(req->extendedPanId))
        Zb_memcpy(self->joinExtendedPanId, req->extendedPanId, RADIO_ADDR_LEN);

    return ZB_OK;
}

/* RejoinNetwork 0x01, the orphaning procedure 6168 names as the MAC's: an orphan scan of the channels the request
   names, the radio's own when it names none, whose realignment the step reads. */
static ZbStatus nwkJoinRequestOrphan(Nwk_Nwk *self, const Nwk_JoinRequestParameters *req, uint32_t nowMs)
{
    Mac_ScanRequestParameters scan;
    ZbStatus status;

    if (self->joinState == NWK_JOIN_ASSOCIATING || self->joinState == NWK_JOIN_REJOINING
        || self->joinState == NWK_JOIN_COMMISSIONING || self->joinState == NWK_JOIN_ORPHANING
        || self->discoveryRunning)
        return ZB_ERR_BUSY;

    Zb_memset(&scan, 0, (uint32_t)sizeof scan);
    scan.scanType = MAC_SCAN_ORPHAN;
    scan.scanChannels = req->scanChannels != 0 ? req->scanChannels : (uint32_t)1 << Mac_Pib(self->mac)->channel;

    status = Mac_ScanRequest(self->mac, &scan, nowMs);

    if (status != ZB_OK)
        return status;

    if (!nwkJoinCapabilitySet(&self->joinCapability))
        self->joinCapability = req->capability;

    if (!nwkJoinPanIdUnset(req->extendedPanId))
        Zb_memcpy(self->joinExtendedPanId, req->extendedPanId, RADIO_ADDR_LEN);

    self->joinState = NWK_JOIN_ORPHANING;
    self->joinConfirmReady = 0;

    return ZB_OK;
}

ZbStatus Nwk_JoinParentAdd(Nwk_Nwk *self, const Nwk_JoinParent *entry)
{
    uint32_t i;

    if (self == 0 || entry == 0)
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
    {
        if (entry->extendedPanId[i] != 0)
            break;
    }

    if (i == RADIO_ADDR_LEN)
        return ZB_ERR_BAD_ARGUMENT;

    if ((entry->extendedAddress == 0 && !entry->shortKnown) || entry->extendedAddress == 0xffffffffffffffff)
        return ZB_ERR_BAD_ARGUMENT;

    if (entry->shortKnown && entry->shortAddress >= MAC_SHORT_ADDRESS_LAST_USABLE)
        return ZB_ERR_BAD_ARGUMENT;

    return Nwk_ParentAdmit(self->joinParents, entry, Nwk_ParentsGoodLqa(self));
}

uint32_t Nwk_JoinParentCount(const Nwk_Nwk *self)
{
    uint32_t count;
    uint32_t i;

    if (self == 0)
        return 0;

    count = 0;

    for (i = 0; i < NWK_JOIN_PARENT_MAX; i++)
    {
        if (self->joinParents[i].inUse)
            count++;
    }

    return count;
}


/* A channel change names one channel and sets it on the radio, and the confirm reports it; more than one is
   INV_REQUESTTYPE, and a radio that cannot be set is UNSUPPORTED_ATTRIBUTE, docs/internals/conformance.md §2. */
static ZbStatus nwkJoinRequestChannelChange(Nwk_Nwk *self, const Nwk_JoinRequestParameters *req)
{
    Radio_Pib pib;
    uint32_t bits = 0;
    uint32_t named = 0;
    uint32_t i;
    ZbStatus status;

    for (i = 0; i < 32; i++)
    {
        if ((req->scanChannels & ((uint32_t)1 << i)) == 0)
            continue;

        bits++;
        named = i;
    }

    if (bits != 1)
    {
        nwkJoinAnswer(self, req, NWK_STATUS_INV_REQUESTTYPE);

        return ZB_ERR_BAD_ARGUMENT;
    }

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_CHANNEL;
    pib.channel = named;

    status = Mac_SetPib(self->mac, &pib);

    /* a radio that cannot be told to change channel: docs/internals/conformance.md §2 */
    if (status == ZB_ERR_UNSUPPORTED)
    {
        nwkJoinAnswer(self, req, NWK_STATUS_UNSUPPORTED_ATTRIBUTE);

        return status;
    }

    if (status != ZB_OK)
    {
        nwkJoinAnswer(self, req, NWK_STATUS_LAST_MAC_STATUS);

        return status;
    }

    nwkJoinAnswer(self, req, NWK_STATUS_SUCCESS);

    return ZB_OK;
}

ZbStatus Nwk_JoinRequest(Nwk_Nwk *self, const Nwk_JoinRequestParameters *req, uint32_t nowMs)
{
    uint16_t own;
    uint32_t bits;
    uint32_t index;
    uint32_t i;

    if (self == 0 || req == 0 || self->mac == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (req->rejoinNetwork == NWK_JOIN_REJOIN_NETWORK)
        return nwkJoinRequestRejoin(self, req, nowMs);

    if (req->rejoinNetwork == NWK_JOIN_ORPHAN)
        return nwkJoinRequestOrphan(self, req, nowMs);

    if (req->rejoinNetwork == NWK_JOIN_CHANNEL_CHANGE)
        return nwkJoinRequestChannelChange(self, req);

    if (req->rejoinNetwork != 0)
        return ZB_ERR_UNSUPPORTED;    /* 3.2.2.13's forms above 0x03: not built, docs/internals/conformance.md §2 */

    if (req->securityEnable != 0)
        return ZB_ERR_UNSUPPORTED;    /* Table 3-21 sets it FALSE for an association: refused, docs/internals/conformance.md §2 */

    if (self->joinState == NWK_JOIN_ASSOCIATING || self->joinState == NWK_JOIN_REJOINING
        || self->joinState == NWK_JOIN_COMMISSIONING || self->joinState == NWK_JOIN_ORPHANING
        || self->discoveryRunning)
        return ZB_ERR_BUSY;

    if (self->joinState == NWK_JOIN_JOINED || Nwk_AddrOwn(Mac_Pib(self->mac), &own)
        || self->cfg.deviceType == NWK_DEVICE_COORDINATOR)
    {
        nwkJoinAnswer(self, req, NWK_STATUS_INV_REQUESTTYPE);

        return ZB_ERR_BAD_STATE;
    }

    if (req->scanChannels != 0)
    {
        bits = 0;

        for (i = 0; i < 32; i++)
        {
            if ((req->scanChannels & ((uint32_t)1 << i)) != 0)
                bits++;
        }

        if (bits != 1)
            return ZB_ERR_BAD_ARGUMENT;
    }

    self->joinParentsTried = 0;
    self->joinAttempts = 0;

    index = nwkJoinNextParent(self, req->extendedPanId, req->scanChannels);

    if (index == NWK_JOIN_PARENT_MAX)
    {
        nwkJoinAnswer(self, req, NWK_STATUS_NOT_PERMITTED);

        return ZB_ERR_NOT_FOUND;
    }

    if (!req->capability.allocateAddress || req->capability.securityCapability
        || req->capability.associationType || req->capability.suspendableCsmaCa)
        return ZB_ERR_UNSUPPORTED;    /* the capability's three unbuilt bits and the address this door allocates, docs/internals/conformance.md §2 */

    self->joinCapability = req->capability;
    self->joinScanChannels = req->scanChannels;

    return nwkJoinAttach(self, index, nowMs);
}

uint32_t Nwk_PollJoinConfirm(Nwk_Nwk *self, Nwk_JoinConfirmParameters *out)
{
    if (self == 0 || out == 0)
        return 0;

    if (!self->joinConfirmReady)
        return 0;

    *out = self->joinConfirm;

    Zb_memset(&self->joinConfirm, 0, (uint32_t)sizeof self->joinConfirm);
    self->joinConfirmReady = 0;

    return 1;
}

Nwk_JoinState Nwk_JoinStateOf(const Nwk_Nwk *self)
{
    if (self == 0)
        return NWK_JOIN_IDLE;

    return self->joinState;
}

uint32_t Nwk_PollJoinIndications(Nwk_Nwk *self, Nwk_JoinIndicationParameters *out, uint32_t max)
{
    uint32_t taken;

    if (self == 0 || out == 0 || max == 0)
        return 0;

    taken = 0;

    while (taken < max && self->joinIndicationCount > 0)
    {
        out[taken] = self->joinIndications[self->joinIndicationHead];
        self->joinIndicationHead = (self->joinIndicationHead + 1) % NWK_JOIN_INDICATION_MAX;
        self->joinIndicationCount--;
        taken++;
    }

    return taken;
}

uint32_t Nwk_JoinIndicationQueue(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->joinIndicationCount;
}

uint32_t Nwk_JoinIndicationsDropped(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->joinIndicationsDropped;
}

uint32_t Nwk_JoinAddressesAssigned(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->joinAddressesAssigned;
}

uint32_t Nwk_JoinResponsesDropped(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->joinResponsesDropped;
}

uint32_t Nwk_JoinCommandsDropped(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->joinCommandsDropped;
}

uint32_t Nwk_JoinRoutesDeleted(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->joinRoutesDeleted;
}

uint32_t Nwk_JoinKeyTimeouts(const Nwk_Nwk *self)
{
    return self->joinKeyTimeouts;
}

uint32_t Nwk_JoinKeyConfirmsDropped(const Nwk_Nwk *self)
{
    return self->joinKeyConfirmsDropped;
}

uint32_t Nwk_JoinChildrenExpired(const Nwk_Nwk *self)
{
    return self->joinChildrenExpired;
}

uint32_t Nwk_JoinSendsDropped(const Nwk_Nwk *self)
{
    return self != 0 ? self->joinSendsDropped : 0;
}
