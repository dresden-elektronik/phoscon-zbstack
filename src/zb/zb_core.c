#include "zb_core.h"

#include "nwk.h"
#include "nwk_beacon.h"
#include "nwk_join.h"
#include "nwk_leave.h"
#include "nwk_permit.h"
#include "nwk_status.h"
#include "zb_time.h"
#include "zb_utils.h"

/* R23.1: 2.3.2.5, 2.2.4.1.1, 2.2.5.1.1, 2.2.5.1.1.2, 2.2.8.4.2, 2.4.3.1.11, 2.4.3.1.11.1, 2.5.4.5.5, Table 2-135, 3.2.2.3, 3.2.2.7, 3.6.1.6.1, 3.6.1.11, D.9 ok;
   4.6.3.2.1 4.4.3.2.3 4.6.3.6.1 4.6.3.6.2 4.4.4.1.2 4.7.3.2 ok, a join reported and the key it owes, a removal sent
   through the joiner's parent or taken from the trust centre, and a child's departure reported; 4.7.3.8 ok (a joiner's
   update asked once joined, its wait and attempts this stack's own); the ZDP is `zdo`'s. */

#define ZB_CORE_KEY_SETTLE_MS 400     /* the turn a Transport Key waits, so the association's session is over */
#define ZB_CORE_KEY_HOLD_MS 1000      /* how long a key the APS door has no room for stays owed after the settle */

static uint64_t zbDeviceExtended(const uint8_t *octets)
{
    uint64_t value = 0;
    uint32_t i;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        value |= (uint64_t)octets[i] << (8 * i);

    return value;
}

/* Which frames are the device object's: endpoint 0 except a ZDP response (bit 15 set, the application's), and a ZDP
   request broadcast to 0xff, as this stack sent them before D-217. The profile is half the test: 0x0006 is On/Off to
   an application and Simple_Desc_req to the object. */
static int zbDeviceIsTheObjects(const Aps_Indication *indication)
{
    int deviceProfile = indication->profileId == ZDO_PROFILE_ID;

    if (indication->dstEndpoint == AF_ENDPOINT_ZDO)
        return !(deviceProfile && indication->clusterId >= ZDO_RESPONSE_BIT);

    if (indication->dstEndpoint == AF_ENDPOINT_ALL)
        return deviceProfile && indication->clusterId <= ZDO_CLUSTER_LAST;

    return 0;
}

/* One APS indication as the framework reads it: the endpoint that answers is named by the caller, since a broadcast
   carries 0xff and the device object answers as endpoint 0. */
static void zbDeviceToAf(const Aps_Indication *aps, uint8_t dstEndpoint, Af_Indication *out)
{
    Zb_memset(out, 0, (uint32_t)sizeof *out);

    out->dstEndpoint = dstEndpoint;
    out->srcEndpoint = aps->srcEndpoint;
    out->srcAddress = aps->srcAddress;
    out->dstAddrMode = aps->dstAddrMode;
    out->dstAddress = aps->dstAddress;
    out->profileId = aps->profileId;
    out->clusterId = aps->clusterId;
    out->status = aps->status;
    out->linkQuality = aps->linkQuality;
    out->asduLength = aps->asduLength > AF_ASDU_MAX ? AF_ASDU_MAX : aps->asduLength;

    if (out->asduLength != 0)
        Zb_memcpy(out->asdu, aps->asdu, out->asduLength);
}

/* Table 3-83's info field for the network `extendedPanId` names, with the depth the config gave, the network's
   update id and the permit the network layer holds, so the permit door has a beacon to open. */
static ZbStatus zbDeviceBeaconFor(Zb_Core *self, uint64_t extendedPanId, uint32_t depth, uint32_t updateId)
{
    Nwk_BeaconInfo info;

    Zb_memset(&info, 0, (uint32_t)sizeof info);

    info.stackProfile = NWK_STACK_PROFILE_PRO;
    info.protocolVersion = NWK_PROTOCOL_VERSION;
    info.routerCapacity = 1;
    info.deviceDepth = depth;
    info.endDeviceCapacity = 1;
    info.extendedPanId = extendedPanId;
    info.txOffset = NWK_BEACON_TX_OFFSET_NONE;
    info.updateId = updateId;

    return Nwk_SetBeaconInfo(&self->layers.nwk, &info, self->layers.nwk.associationPermit);
}

/* This device's beacon at init, so a joiner reads its identity before it asks. An end device answers none, its parent's
   being the one a joiner reads, and neither does a router the config puts on no network yet: it beacons once joined. */
static ZbStatus zbDeviceStateBeacon(Zb_Core *self, const Zb_CoreConfig *cfg)
{
    if (self->layers.nwk.cfg.deviceType == NWK_DEVICE_END_DEVICE)
        return ZB_OK;

    if (self->layers.nwk.cfg.deviceType == NWK_DEVICE_ROUTER
        && ((cfg->layers.present & RADIO_PIB_SHORT_ADDRESS) == 0 || cfg->layers.shortAddress > NWK_ADDR_LAST_UNICAST))
        return ZB_OK;

    return zbDeviceBeaconFor(self, zbDeviceExtended(cfg->layers.extendedPanId), cfg->depth, 0);
}

/* The security material the config names, built into this device's own storage so an application states a key and not
   a table. A device holding only the trust centre link key is a joiner of a secured network, at its level, and waits
   on the network key; one with neither key runs at level 0, which is what a scaffold without security wants. */
static void zbDeviceSecurity(Zb_Core *self, const Zb_CoreConfig *cfg, Zb_LayersConfig *stack)
{
    uint32_t i;
    int haveKey = 0;
    int haveLinkKey = 0;

    for (i = 0; i < SECURITY_KEY_OCTETS; i++)
    {
        if (cfg->networkKey[i] != 0)
            haveKey = 1;

        if (cfg->trustCentreLinkKey[i] != 0)
            haveLinkKey = 1;
    }

    if (!haveKey && !haveLinkKey)
        return;

    self->security.ownIeee = zbDeviceExtended(cfg->layers.extendedAddress);
    self->security.log = cfg->layers.log;
    self->security.trustCenterIeee = cfg->transportNetworkKey ? self->security.ownIeee : APS_KEY_IEEE_UNSET;

    if (haveKey)
    {
        self->keys[0].keySeqNumber = cfg->networkKeySeq;
        self->keys[0].inUse = 1;
        Zb_memcpy(self->keys[0].key, cfg->networkKey, SECURITY_KEY_OCTETS);

        self->security.keys = self->keys;
        self->security.keyCount = 1;
        self->security.nwkActiveKeySeqNumber = cfg->networkKeySeq;
        self->security.authenticated = 1;
        self->security.nwkAllFresh = cfg->layers.deviceType == NWK_DEVICE_COORDINATOR ? 1 : 0;
    }

    if (haveLinkKey)
    {
        self->pairs[0].deviceIeee = 0;
        self->pairs[0].keyAttributes = SECURITY_KEYPAIR_ATTR_VERIFIED;
        self->pairs[0].linkKeyType = SECURITY_LINK_KEY_GLOBAL;
        self->pairs[0].verifiedFrameCounter = 1;
        self->pairs[0].outgoingFrameCounter = 1;
        Zb_memcpy(self->pairs[0].key, cfg->trustCentreLinkKey, SECURITY_KEY_OCTETS);

        self->security.keyPairs = self->pairs;
        self->security.keyPairCount = 1;

        for (i = 0; i < SECURITY_KEY_OCTETS; i++)
        {
            if (cfg->linkKeySeed[i] != 0)
                self->security.linkKeySeed = cfg->linkKeySeed;
        }
    }

    self->security.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;

    stack->nwkSecurityLevel = self->security.nwkSecurityLevel;
    stack->security = &self->security;
    stack->trustCenterIeee = self->security.trustCenterIeee;
}

static void zbDevicePush(Zb_Core *self, const Aps_Indication *indication)
{
    if (self->indicationCount >= ZB_CORE_INDICATION_MAX)
    {
        self->indicationsDropped++;

        return;
    }

    self->indications[self->indicationCount++] = *indication;
}

/* A frame for the application. Under APS_GROUP_DELIVERY_ENDPOINTS a group frame no member took, which APS hands over
   at the broadcast endpoint, is delivered once to each registered endpoint whose profile is the frame's, either side's
   0xffff matching any; one that matches none is counted and dropped. */
static void zbDeviceDeliver(Zb_Core *self, const Aps_Indication *indication)
{
    Aps_Indication copy;
    uint32_t matched = 0;
    uint32_t i;

    if (Aps_GroupDelivery(&self->layers.aps) != APS_GROUP_DELIVERY_ENDPOINTS || indication->dstAddrMode != APS_ADDR_MODE_GROUP
        || indication->dstEndpoint != APS_ENDPOINT_BROADCAST)
    {
        zbDevicePush(self, indication);

        return;
    }

    for (i = 0; i < AF_ENDPOINT_MAX; i++)
    {
        const Af_Endpoint *endpoint = &self->af.endpoints[i];

        if (!endpoint->inUse || endpoint->descriptor.endpoint == AF_ENDPOINT_ZDO)
            continue;

        if (endpoint->descriptor.profileId != indication->profileId && endpoint->descriptor.profileId != 0xffff
            && indication->profileId != 0xffff)
            continue;

        copy = *indication;
        copy.dstEndpoint = endpoint->descriptor.endpoint;
        zbDevicePush(self, &copy);
        matched++;
    }

    if (matched == 0)
        self->groupFramesUnmatched++;
}

/* The radio's mode, asked for until the seam takes it: adoption queued its PIB writes first and the write queue holds
   six, so the first turns are refused. An RCP left in receive-all mode acknowledges nothing, and every exchange a
   device owes an answer to would then fail while its own side looked healthy. */
static void zbDeviceFilter(Zb_Core *self)
{
    if (self->filtered)
        return;

    if (Mac_SetPromiscuousMode(&self->layers.mac, 0) == ZB_OK)
        self->filtered = 1;
}

/* Table 3-22's JoinerMethod as Table 4-14's Status, the mapping Table 3-73 prints. */
static uint8_t zbDeviceUpdateStatusOf(uint32_t joinerMethod)
{
    if (joinerMethod == NWK_JOIN_METHOD_REJOIN_SECURED || joinerMethod == NWK_JOIN_METHOD_COMMISSIONING_REJOIN_SECURED)
        return APS_UPDATE_DEVICE_SECURED_REJOIN;

    if (joinerMethod == NWK_JOIN_METHOD_REJOIN_UNSECURED || joinerMethod == NWK_JOIN_METHOD_COMMISSIONING_REJOIN)
        return APS_UPDATE_DEVICE_TC_REJOIN;

    return APS_UPDATE_DEVICE_UNSECURED_JOIN;
}

/* A join this device indicated is reported to the trust centre, which at the trust centre itself is the indication;
   a device holding no link key is on an unsecured network and reports nothing, and the trust centre's own return
   behind a trusted link is not reported. */
static void zbDeviceReportJoins(Zb_Core *self, uint32_t nowMs)
{
    Nwk_JoinIndicationParameters joins[NWK_JOIN_INDICATION_MAX];
    Aps_UpdateDeviceReq request;
    uint32_t taken;
    uint32_t i;

    taken = Nwk_PollJoinIndications(&self->layers.nwk, joins, NWK_JOIN_INDICATION_MAX);

    for (i = 0; i < taken; i++)
    {
        self->joinsHeard++;

        if (Security_KeyPairCount(&self->layers.security) == 0 || joins[i].networkAddress == 0x0000
            || joins[i].extendedAddress == self->layers.security.trustCenterIeee)
            continue;

        Zb_memset(&request, 0, (uint32_t)sizeof request);

        request.destIeee = self->layers.security.trustCenterIeee;
        request.deviceIeee = joins[i].extendedAddress;
        request.deviceShortAddress = joins[i].networkAddress;
        request.status = zbDeviceUpdateStatusOf(joins[i].joinerMethod);

        if (Aps_UpdateDeviceRequest(&self->layers.aps, &request, nowMs) != ZB_OK)
            self->joinsUnreported++;
    }
}

/* The joiner's row, or 0 when the trust centre noted none. */
static Zb_CoreJoiner *zbDeviceJoinerOf(Zb_Core *self, uint64_t deviceIeee)
{
    uint32_t i;

    for (i = 0; i < ZB_CORE_JOINER_MAX; i++)
    {
        if (self->joiners[i].inUse && self->joiners[i].deviceIeee == deviceIeee)
            return &self->joiners[i];
    }

    return 0;
}

/* A join noted with its parent, or a departure forgotten. The table is a note and not a transaction, so a full one
   evicts the oldest join and counts it: the newest joiner is the one a trust centre most often removes. */
static void zbDeviceNoteJoiner(Zb_Core *self, const Aps_UpdateDeviceIndication *update)
{
    Zb_CoreJoiner *row;
    uint32_t i;

    row = zbDeviceJoinerOf(self, update->deviceIeee);

    if (update->status == APS_UPDATE_DEVICE_LEFT)
    {
        if (row != 0)
            Zb_memset(row, 0, (uint32_t)sizeof *row);

        return;
    }

    for (i = 0; row == 0 && i < ZB_CORE_JOINER_MAX; i++)
    {
        if (!self->joiners[i].inUse)
            row = &self->joiners[i];
    }

    if (row == 0)
    {
        row = &self->joiners[0];

        for (i = 1; i < ZB_CORE_JOINER_MAX; i++)
        {
            if (self->joiners[i].order < row->order)
                row = &self->joiners[i];
        }

        self->joinersEvicted++;
    }

    row->deviceIeee = update->deviceIeee;
    row->parentIeee = update->srcIeee;
    row->parentShort = update->srcAddress;
    row->order = self->joinerOrder++;
    row->inUse = 1;
}

/* Another device's departure, kept for the application; a full ring counts it. */
static void zbDeviceDeparted(Zb_Core *self, uint64_t ieee, uint16_t networkAddress, int rejoin, int reported)
{
    Zb_CoreDeparture *departure;

    if (self->departureCount >= ZB_CORE_DEPARTURE_MAX)
    {
        self->departuresDropped++;
        return;
    }

    departure = &self->departures[self->departureCount++];
    departure->ieee = ieee;
    departure->networkAddress = networkAddress;
    departure->rejoin = rejoin;
    departure->reported = reported;
}

/* A child's departure without rejoin is reported to the trust centre as status 0x02 (11973-11978); the trust centre
   issues none for its own child and forgets the joiner itself (11979), and an unsecured network reports nothing. */
static void zbDeviceReportLeaves(Zb_Core *self, uint32_t nowMs)
{
    Nwk_LeaveIndication leaves[NWK_LEAVE_INDICATION_MAX];
    Aps_UpdateDeviceReq request;
    Zb_CoreJoiner *row;
    uint32_t taken;
    uint32_t i;

    taken = Nwk_PollLeaveIndications(&self->layers.nwk, leaves, NWK_LEAVE_INDICATION_MAX);

    for (i = 0; i < taken; i++)
    {
        if (leaves[i].deviceAddress == NWK_LEAVE_ADDRESS_NULL && leaves[i].rejoin
            && self->layers.nwk.cfg.deviceType != NWK_DEVICE_COORDINATOR)
            self->rejoinOwed = 1;

        if (leaves[i].deviceAddress != NWK_LEAVE_ADDRESS_NULL)
            zbDeviceDeparted(self, leaves[i].deviceAddress, leaves[i].networkAddress, leaves[i].rejoin != 0, 0);

        if (!leaves[i].child || leaves[i].rejoin || Security_KeyPairCount(&self->layers.security) == 0)
            continue;

        if (self->transportNetworkKey)
        {
            row = zbDeviceJoinerOf(self, leaves[i].deviceAddress);

            if (row != 0)
                Zb_memset(row, 0, (uint32_t)sizeof *row);

            continue;
        }

        Zb_memset(&request, 0, (uint32_t)sizeof request);

        request.destIeee = self->layers.security.trustCenterIeee;
        request.deviceIeee = leaves[i].deviceAddress;
        request.deviceShortAddress = leaves[i].networkAddress;
        request.status = APS_UPDATE_DEVICE_LEFT;

        if (Aps_UpdateDeviceRequest(&self->layers.aps, &request, nowMs) != ZB_OK)
            self->leavesUnreported++;
    }
}

/* A trust centre's Remove Device, carried out by the network layer's leave request: on this device itself, or on the
   child it names; one naming neither is discarded. */
static void zbDeviceTakeRemovals(Zb_Core *self, uint32_t nowMs)
{
    Aps_RemoveDeviceIndication removals[APS_REMOVE_DEVICE_INDICATION_MAX];
    uint32_t taken;
    uint32_t i;

    taken = Aps_PollRemoveDeviceIndications(&self->layers.aps, removals, APS_REMOVE_DEVICE_INDICATION_MAX);

    for (i = 0; i < taken; i++)
    {
        if (Nwk_LeaveRequest(&self->layers.nwk, removals[i].targetIeee, 0, 0, nowMs) == NWK_LEAVE_STATUS_SUCCESS)
            self->removalsTaken++;
        else
            self->removalsDiscarded++;
    }
}

/* 12483-12487: a trust centre rejoin is admitted only for a device whose own pair is a unique link key; the global
   pair the plain lookup falls back to is not the device's. */
static int zbDeviceHoldsUniqueKey(const Zb_Core *self, uint64_t deviceIeee)
{
    const Security_KeyPairEntry *entry;

    entry = Security_KeyPairAt(&self->layers.security, Security_FindKeyPairByIeee(&self->layers.security, deviceIeee));

    return entry != 0 && entry->deviceIeee == deviceIeee && entry->linkKeyType == SECURITY_LINK_KEY_UNIQUE;
}

/* A joiner owed the key is noted once: a second update for it moves its settle, and a join while every slot is taken
   is refused and counted. */
static void zbDeviceNoteKeyOwed(Zb_Core *self, const Aps_UpdateDeviceIndication *update, uint32_t nowMs)
{
    Zb_CoreKeyOwed *slot = 0;
    uint32_t i;

    for (i = 0; i < ZB_CORE_KEY_OWED_MAX && slot == 0; i++)
    {
        if (self->keysOwed[i].inUse && self->keysOwed[i].deviceIeee == update->deviceIeee)
            slot = &self->keysOwed[i];
    }

    for (i = 0; i < ZB_CORE_KEY_OWED_MAX && slot == 0; i++)
    {
        if (!self->keysOwed[i].inUse)
            slot = &self->keysOwed[i];
    }

    if (slot == 0)
    {
        self->keysOwedRefused++;
        return;
    }

    slot->inUse = 1;
    slot->armedMs = nowMs;
    slot->deviceShort = update->deviceShortAddress;
    slot->deviceIeee = update->deviceIeee;
    slot->tunnel = update->srcIeee != self->layers.security.ownIeee ? 1 : 0;
    slot->parentShort = update->srcAddress;
    slot->parentIeee = update->srcIeee;
}

/* The owed key whose settle ended first, or 0 while none has. */
static Zb_CoreKeyOwed *zbDeviceKeyDue(Zb_Core *self, uint32_t nowMs)
{
    Zb_CoreKeyOwed *due = 0;
    uint32_t i;

    for (i = 0; i < ZB_CORE_KEY_OWED_MAX; i++)
    {
        if (!self->keysOwed[i].inUse || !Zb_timeReached(nowMs, self->keysOwed[i].armedMs + ZB_CORE_KEY_SETTLE_MS))
            continue;

        if (due == 0 || !Zb_timeReached(self->keysOwed[i].armedMs, due->armedMs))
            due = &self->keysOwed[i];
    }

    return due;
}

/* At the trust centre an unsecured join and a trust centre rejoin are owed the active network key, a secured rejoin
   and a departure nothing, and a device a router reported is owed it through that router; each join's parent is
   noted, and a departure a router reported told. A key goes a turn later, the exchange that answered the association still owning the MAC, one per turn;
   one the APS door has no room for is asked again for ZB_CORE_KEY_HOLD_MS, any other refusal counted. */
static void zbDeviceOweKey(Zb_Core *self, uint32_t nowMs)
{
    Aps_UpdateDeviceIndication updates[APS_UPDATE_DEVICE_INDICATION_MAX];
    const Security_KeyDescriptor *active;
    Zb_CoreKeyOwed *due;
    Aps_TransportKeyReq request;
    ZbStatus status;
    uint32_t taken;
    uint32_t i;

    taken = Aps_PollUpdateDeviceIndications(&self->layers.aps, updates, APS_UPDATE_DEVICE_INDICATION_MAX);

    for (i = 0; i < taken; i++)
    {
        zbDeviceNoteJoiner(self, &updates[i]);

        if (updates[i].status == APS_UPDATE_DEVICE_LEFT)
            zbDeviceDeparted(self, updates[i].deviceIeee, updates[i].deviceShortAddress, 0, 1);

        if (updates[i].status != APS_UPDATE_DEVICE_UNSECURED_JOIN && updates[i].status != APS_UPDATE_DEVICE_TC_REJOIN)
            continue;

        if (updates[i].status == APS_UPDATE_DEVICE_TC_REJOIN && !zbDeviceHoldsUniqueKey(self, updates[i].deviceIeee))
        {
            self->trustCentreRejoinsRefused++;
            continue;
        }

        zbDeviceNoteKeyOwed(self, &updates[i], nowMs);
    }

    due = zbDeviceKeyDue(self, nowMs);

    if (due == 0)
        return;

    active = Security_ActiveNetworkKey(&self->layers.security);

    if (active == 0)
    {
        due->inUse = 0;
        return;
    }

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.destIeee = due->deviceIeee;
    request.nwkDst = due->deviceShort;
    request.standardKeyType = APS_TK_TYPE_NETWORK_KEY;
    request.keySeqNumber = active->keySeqNumber;
    request.destinationIeee = due->deviceIeee;
    request.tunnel = due->tunnel;
    request.tunnelNwk = due->parentShort;
    request.tunnelIeee = due->parentIeee;
    Zb_memcpy(request.key, active->key, SECURITY_KEY_OCTETS);

    status = Aps_TransportKeyRequest(&self->layers.aps, &request, nowMs);

    if ((status == ZB_ERR_BUSY || status == ZB_ERR_NO_SPACE)
        && Zb_timeWithin(nowMs, due->armedMs + ZB_CORE_KEY_SETTLE_MS, ZB_CORE_KEY_HOLD_MS))
        return;

    due->inUse = 0;

    if (status != ZB_OK)
    {
        self->networkKeysRefused++;
        return;
    }

    self->networkKeysSent++;

    if (request.tunnel)
        self->networkKeysTunnelled++;
}

/* A device is joined once it is on a network and, where that network is secured, holds its key: the announcement
   is the device's first network-secured frame, which is also what its parent authenticates it by. */
static int zbDeviceJoined(Zb_Core *self)
{
    const Security *security = Nwk_Security(&self->layers.nwk);

    if (!Nwk_IsPartOfNetwork(&self->layers.nwk))
        return 0;

    return security == 0 || security->nwkSecurityLevel == SECURITY_LEVEL_NONE || Security_IsEnabled(security);
}

/* A joiner's trust centre link key update once it holds the network key: a Request-Key, its Confirm-Key awaited, and
   another while attempts remain; the last given up keeps the key the device joined with. */
static void zbDeviceTcLinkKeyStep(Zb_Core *self, uint32_t nowMs)
{
    Aps_Aps *aps = &self->layers.aps;
    uint32_t state;
    ZbStatus status;

    if (!aps->tcLinkKeyUpdate || self->tcLinkKeyDone || self->transportNetworkKey || !zbDeviceJoined(self))
        return;

    state = Aps_TcLinkKeyState(aps);

    if (state == APS_TCLK_VERIFIED || state == APS_TCLK_ABANDONED)
    {
        self->tcLinkKeyDone = 1;
        return;
    }

    if ((state != APS_TCLK_NONE || self->tcLinkKeyDeadlineMs != 0) && !Zb_timeReached(nowMs, self->tcLinkKeyDeadlineMs))
        return;

    if (state != APS_TCLK_NONE && self->tcLinkKeyAttempts >= ZB_CORE_TC_LINK_KEY_ATTEMPTS)
    {
        Aps_TcLinkKeyAbandon(aps);
        self->tcLinkKeyDone = 1;
        return;
    }

    status = Aps_RequestTcLinkKey(aps, nowMs);

    if (status == ZB_ERR_BAD_STATE)
    {
        self->tcLinkKeyDone = 1;
        return;
    }

    if (status == ZB_OK)
        self->tcLinkKeyAttempts++;

    self->tcLinkKeyDeadlineMs = nowMs + (uint32_t)(status == ZB_OK ? ZB_CORE_TC_LINK_KEY_WAIT_MS
                                                                  : ZB_CORE_TC_LINK_KEY_RETRY_MS);
}

/* A resting end device polls at the attach rate while its trust centre link key is being negotiated or a fragmented
   message is arriving, and at its own rate otherwise. */
static void zbDevicePollRate(Zb_Core *self)
{
    int negotiating = self->layers.aps.tcLinkKeyUpdate && !self->tcLinkKeyDone && !self->transportNetworkKey;

    Nwk_SetPollFast(&self->layers.nwk, negotiating || Aps_Reassembling(&self->layers.aps));
}

/* The capability this device's type and receiver duty make it: an FFD for a router, on mains as its power descriptor
   says, asking for an address. */
static void zbDeviceCapability(Zb_Core *self, MacFrame_Capability *out)
{
    int router = self->layers.nwk.cfg.deviceType == NWK_DEVICE_ROUTER;

    out->deviceType = router;
    out->powerSource = 1;
    out->rxOnWhenIdle = router || Nwk_AddrOwnRxOnWhenIdle(Mac_Pib(&self->layers.mac));
    out->allocateAddress = 1;
}

/* The NLME-JOIN.request for the network the discovery chose: no rejoin, the channels the door named. */
static ZbStatus zbDeviceJoinNetwork(Zb_Core *self, uint32_t nowMs)
{
    Nwk_JoinRequestParameters req;
    uint32_t i;

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        req.extendedPanId[i] = (uint8_t)(self->joinExtendedPanId >> (8 * i));

    req.rejoinNetwork = 0;
    req.scanChannels = self->joinParams.scanChannels;
    req.scanDuration = self->joinParams.scanDuration;
    zbDeviceCapability(self, &req.capability);

    return Nwk_JoinRequest(&self->layers.nwk, &req, nowMs);
}

/* 7950-7952: a rejoin's discovery of the channel the device is on, every parent there, since only a new device reads
   the permit flag (14045-14048), for the join's ScanDuration or, with none named as after a restore, D.9's. */
static ZbStatus zbDeviceRejoinDiscover(Zb_Core *self, uint32_t nowMs)
{
    Nwk_NetworkDiscoveryRequestParameters discovery;

    Zb_memset(&discovery, 0, (uint32_t)sizeof discovery);
    discovery.scanChannels = (uint32_t)1 << Mac_Pib(&self->layers.mac)->channel;
    discovery.scanDuration = self->joinParams.scanDuration != 0 ? self->joinParams.scanDuration
                                                                 : (uint32_t)ZB_CORE_SCAN_DURATION_DEFAULT;

    return Nwk_NetworkDiscoveryRequest(&self->layers.nwk, &discovery, nowMs);
}

/* 6103-6105: the secured rejoin of the network the device is on, from the parents its discovery found. */
static ZbStatus zbDeviceRejoinNetwork(Zb_Core *self, uint32_t nowMs)
{
    Nwk_JoinRequestParameters req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    req.rejoinNetwork = NWK_JOIN_REJOIN_NETWORK;
    req.scanChannels = (uint32_t)1 << Mac_Pib(&self->layers.mac)->channel;
    req.securityEnable = 1;
    Zb_memcpy(req.extendedPanId, self->layers.nwk.joinExtendedPanId, RADIO_ADDR_LEN);
    zbDeviceCapability(self, &req.capability);

    return Nwk_JoinRequest(&self->layers.nwk, &req, nowMs);
}

/* 5403-5408: an end device counts the parent link failures its network layer raises, a run that an answered
   exchange ends (5378-5380's consecutive attempts); up to the threshold it tries its parent again, past it it
   rejoins. Every other status is read and left. */
static void zbDeviceParentLink(Zb_Core *self)
{
    Nwk_NwkStatusIndication statuses[NWK_STATUS_INDICATION_MAX];
    uint32_t got = Nwk_PollStatusIndications(&self->layers.nwk, statuses, NWK_STATUS_INDICATION_MAX);
    uint32_t i;

    if (Nwk_ParentLinkHeld(&self->layers.nwk) != self->parentLinkHeld)
    {
        self->parentLinkHeld = Nwk_ParentLinkHeld(&self->layers.nwk);
        self->parentLinkFailures = 0;
    }

    for (i = 0; i < got; i++)
    {
        if (statuses[i].status != NWK_STATUS_CODE_PARENT_LINK_FAILURE)
            continue;

        self->parentLinkFailures++;

        if (self->parentLinkFailures > self->parentLinkRetryThreshold)
            self->rejoinOwed = 1;
        else
            Nwk_JoinKeepaliveOwe(&self->layers.nwk);
    }
}

/* 5421-5427: an end device whose rejoin failed starts another once the interval has passed, the first interval the
   configured one and each after it doubled up to its maximum; a router keeps the one attempt. */
static void zbDeviceRejoinFailed(Zb_Core *self)
{
    self->rejoinsFailed++;

    if (self->layers.nwk.cfg.deviceType != NWK_DEVICE_END_DEVICE)
        return;

    self->rejoinOwed = 1;
    self->rejoinFailuresInRow++;

    if (self->rejoinFailuresInRow == 1)
        return;

    self->rejoinIntervalMs = self->rejoinIntervalMs > self->rejoinIntervalMaxMs / 2 ? self->rejoinIntervalMaxMs
                                                                                   : self->rejoinIntervalMs * 2;
}

/* 7175-7176 and 5299-5301: a device told to leave and rejoin discovers its network's parents, rejoins through one of
   them, and announces itself again once it has; 5421-5423 holds a rejoin back until the interval since the last. */
static void zbDeviceRejoinStep(Zb_Core *self, uint32_t nowMs)
{
    Nwk_NetworkDiscoveryConfirmParameters discovery;
    Nwk_JoinConfirmParameters confirm;
    ZbStatus status;

    if (self->rejoinOwed && self->joinState == ZB_CORE_JOIN_IDLE)
    {
        if (self->rejoinStarted && Zb_timeWithin(nowMs, self->rejoinStartMs, self->rejoinIntervalMs))
            return;

        status = ZB_ERR_BAD_STATE;

        if (zbDeviceExtended(self->layers.nwk.joinExtendedPanId) != 0)
            status = zbDeviceRejoinDiscover(self, nowMs);

        if (status == ZB_ERR_BUSY)
            return;

        self->rejoinOwed = 0;

        if (status != ZB_OK)
        {
            self->rejoinsFailed++;
            return;
        }

        self->rejoinStarted = 1;
        self->rejoinStartMs = nowMs;
        self->joinState = ZB_CORE_JOIN_REJOIN_DISCOVERING;
    }

    if (self->joinState == ZB_CORE_JOIN_REJOIN_DISCOVERING)
    {
        if (Nwk_PollNetworkDiscoveryConfirm(&self->layers.nwk, &discovery) != 1)
            return;

        self->joinState = ZB_CORE_JOIN_REJOINING;
        self->joinOwed = 1;
    }

    if (self->joinState != ZB_CORE_JOIN_REJOINING)
        return;

    if (self->joinOwed)
    {
        status = zbDeviceRejoinNetwork(self, nowMs);

        if (status == ZB_ERR_BUSY)
            return;

        self->joinOwed = 0;

        if (status != ZB_OK)
        {
            self->joinState = ZB_CORE_JOIN_IDLE;
            zbDeviceRejoinFailed(self);
            return;
        }
    }

    if (Nwk_PollJoinConfirm(&self->layers.nwk, &confirm) != 1)
        return;

    self->joinState = ZB_CORE_JOIN_IDLE;

    if (confirm.status != NWK_JOIN_STATUS_SUCCESS)
    {
        zbDeviceRejoinFailed(self);
        return;
    }

    self->rejoins++;
    self->joinAnnounced = 0;
    self->parentLinkFailures = 0;
    self->rejoinFailuresInRow = 0;
    self->rejoinIntervalMs = self->rejoinIntervalFirstMs;
}

/* The join's end: the result handed up, and a router that joined beaconing for the network it is now on. */
static void zbDeviceJoinEnds(Zb_Core *self, uint8_t status, const Nwk_JoinConfirmParameters *confirm)
{
    self->joinResult.status = status;

    if (confirm != 0)
    {
        self->joinResult.networkAddress = confirm->networkAddress;
        self->joinResult.extendedPanId = zbDeviceExtended(confirm->extendedPanId);
        self->joinResult.channel = confirm->channel;
    }

    if (status == NWK_JOIN_STATUS_SUCCESS && self->layers.nwk.cfg.deviceType == NWK_DEVICE_ROUTER)
        (void)zbDeviceBeaconFor(self, self->joinResult.extendedPanId, 0, 0);

    self->joinState = ZB_CORE_JOIN_IDLE;
    self->joinResultReady = 1;
}

/* The network to join from the discovery's table: the one the door named if a parent of it was heard, else the
   best-ranked parent's. 0 when there is none. */
static uint64_t zbDeviceChooseNetwork(const Zb_Core *self)
{
    Nwk_JoinParent entries[NWK_JOIN_PARENT_MAX];
    uint64_t heard;
    uint32_t count;
    uint32_t i;
    uint32_t k;

    count = Nwk_DiscoveryEntries(&self->layers.nwk, entries, NWK_JOIN_PARENT_MAX);

    for (i = 0; i < count; i++)
    {
        heard = 0;

        for (k = 0; k < RADIO_ADDR_LEN; k++)
            heard |= (uint64_t)entries[i].extendedPanId[k] << (8 * k);

        if (self->joinParams.extendedPanId == 0 || heard == self->joinParams.extendedPanId)
            return heard;
    }

    return 0;
}

/* A secured network's join is over once the network key is here, or once the NO_KEY confirm says it will not be. */
static void zbDeviceKeyWaitStep(Zb_Core *self)
{
    Nwk_JoinConfirmParameters confirm;

    if (zbDeviceJoined(self))
    {
        zbDeviceJoinEnds(self, NWK_JOIN_STATUS_SUCCESS, &self->joinConfirm);
        return;
    }

    if (Nwk_PollJoinConfirm(&self->layers.nwk, &confirm) == 1 && confirm.status != NWK_JOIN_STATUS_SUCCESS)
        zbDeviceJoinEnds(self, confirm.status, &self->joinConfirm);
}

/* One scan of the discovery the door runs :Config_NWK_Scan_Attempts times, each after the first adding to the table. */
static ZbStatus zbDeviceDiscover(Zb_Core *self, int keepTable, uint32_t nowMs)
{
    Nwk_NetworkDiscoveryRequestParameters discovery;

    Zb_memset(&discovery, 0, (uint32_t)sizeof discovery);
    discovery.scanChannels = self->joinParams.scanChannels;
    discovery.scanDuration = self->joinParams.scanDuration;
    discovery.onlyPermitJoinNetworks = 1;
    discovery.onlyEndDeviceCapacity = self->layers.nwk.cfg.deviceType == NWK_DEVICE_END_DEVICE;
    discovery.keepTable = keepTable;

    return Nwk_NetworkDiscoveryRequest(&self->layers.nwk, &discovery, nowMs);
}

/* The gap between two scans, then the next one, asked again on a busy turn. */
static void zbDeviceScanGapStep(Zb_Core *self, uint32_t nowMs)
{
    ZbStatus status;

    if (!Zb_timeReached(nowMs, self->joinScanAtMs))
        return;

    status = zbDeviceDiscover(self, 1, nowMs);

    if (status == ZB_ERR_BUSY)
        return;

    if (status != ZB_OK)
    {
        zbDeviceJoinEnds(self, NWK_STATUS_INV_REQUESTTYPE, 0);
        return;
    }

    self->joinState = ZB_CORE_JOIN_DISCOVERING;
}

/* One turn of the door: the discovery's confirm and the next scan while any is left, the network chosen and its join
   asked (again on a busy turn), then the join's confirm, and on a secured network the wait for the key. */
static void zbDeviceJoinStep(Zb_Core *self, uint32_t nowMs)
{
    Nwk_NetworkDiscoveryConfirmParameters discovery;
    Nwk_JoinConfirmParameters confirm;
    ZbStatus status;

    if (self->joinState == ZB_CORE_JOIN_KEY_WAIT)
    {
        zbDeviceKeyWaitStep(self);
        return;
    }

    if (self->joinState == ZB_CORE_JOIN_SCAN_GAP)
    {
        zbDeviceScanGapStep(self, nowMs);
        return;
    }

    if (self->joinState == ZB_CORE_JOIN_DISCOVERING
        && Nwk_PollNetworkDiscoveryConfirm(&self->layers.nwk, &discovery) == 1)
    {
        self->joinResult.parentsHeard = discovery.entries;
        self->joinScansLeft--;

        if (self->joinScansLeft != 0)
        {
            self->joinScanAtMs = nowMs + self->joinParams.scanGapMs;
            self->joinState = ZB_CORE_JOIN_SCAN_GAP;
            return;
        }

        self->joinExtendedPanId = zbDeviceChooseNetwork(self);

        if (self->joinExtendedPanId == 0)
        {
            zbDeviceJoinEnds(self, discovery.status != 0 ? discovery.status : NWK_STATUS_NOT_PERMITTED, 0);
            return;
        }

        self->joinState = ZB_CORE_JOIN_JOINING;
        self->joinOwed = 1;
    }

    if (self->joinState != ZB_CORE_JOIN_JOINING)
        return;

    if (self->joinOwed)
    {
        status = zbDeviceJoinNetwork(self, nowMs);

        if (status == ZB_ERR_BUSY)
            return;

        self->joinOwed = 0;

        if (status != ZB_OK)
        {
            zbDeviceJoinEnds(self, NWK_STATUS_INV_REQUESTTYPE, 0);
            return;
        }
    }

    if (Nwk_PollJoinConfirm(&self->layers.nwk, &confirm) != 1)
        return;

    if (confirm.status != NWK_JOIN_STATUS_SUCCESS || zbDeviceJoined(self))
    {
        zbDeviceJoinEnds(self, confirm.status, &confirm);
        return;
    }

    self->joinConfirm = confirm;
    self->joinState = ZB_CORE_JOIN_KEY_WAIT;
}

/* The stack first, because the ring below it is filled by that turn; then one read of the ring, which no other door
   may make. */
ZbStatus Zb_CoreStep(Zb_Core *self, uint32_t nowMs)
{
    Aps_Indication indication;
    Af_Indication afIndication;
    ZbStatus handled;
    ZbStatus status;

    if (self == 0 || !self->running)
        return ZB_ERR_BAD_ARGUMENT;

    zbDeviceFilter(self);

    status = Zb_LayersStep(&self->layers, nowMs);

    while (Aps_PollIndications(&self->layers.aps, &indication, 1) == 1)
    {
        if (zbDeviceIsTheObjects(&indication))
        {
            zbDeviceToAf(&indication, AF_ENDPOINT_ZDO, &afIndication);

            handled = Zdo_HandleIndication(&self->zdo, &afIndication, nowMs);

            if (handled == ZB_ERR_UNSUPPORTED && self->zdo.unsupportedToApplication)
            {
                zbDevicePush(self, &indication);

                continue;
            }

            self->zdpFramesConsumed++;
            self->lastZdpCluster = indication.clusterId;
            self->lastZdpProfile = indication.profileId;
            self->lastZdpEndpoint = indication.dstEndpoint;

            if (indication.clusterId == ZDO_DEVICE_ANNCE)
            {
                zbDevicePush(self, &indication);

                self->announcementsRepublished++;
            }

            continue;
        }

        zbDeviceDeliver(self, &indication);
    }

    zbDeviceReportJoins(self, nowMs);

    zbDeviceReportLeaves(self, nowMs);

    zbDeviceTakeRemovals(self, nowMs);

    zbDeviceOweKey(self, nowMs);

    zbDeviceJoinStep(self, nowMs);

    zbDeviceParentLink(self);

    zbDeviceRejoinStep(self, nowMs);

    zbDeviceTcLinkKeyStep(self, nowMs);

    zbDevicePollRate(self);

    if (zbDeviceJoined(self))
    {
        if (!self->joinAnnounced && self->layers.nwk.cfg.deviceType != NWK_DEVICE_COORDINATOR)
        {
            (void)Zdo_DeviceAnnce(&self->zdo, nowMs);

            self->joinAnnounced = 1;
        }
    }
    else if (!Nwk_IsPartOfNetwork(&self->layers.nwk))
        self->joinAnnounced = 0;

    return status;
}

ZbStatus Zb_CoreInit(Zb_Core *self, Radio_Radio *radio, const Zb_CoreConfig *cfg)
{
    Zb_LayersConfig stack;
    ZbStatus status;

    if (self == 0 || radio == 0 || cfg == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(self, 0, (uint32_t)sizeof *self);

    stack = cfg->layers;
    zbDeviceSecurity(self, cfg, &stack);

    status = Zb_LayersInit(&self->layers, radio, &stack);

    if (status != ZB_OK)
        return status;

    status = Af_Init(&self->af, &self->layers.aps);

    if (status != ZB_OK)
        goto refuse;

    Aps_SetBindings(&self->layers.aps, self->bindings);
    Aps_SetGroupDelivery(&self->layers.aps, cfg->groupDelivery);
    Aps_SetTcLinkKeyUpdate(&self->layers.aps, cfg->tcLinkKeyUpdate);

    status = Zdo_Init(&self->zdo, &self->af, cfg->layers.shortAddress,
                      zbDeviceExtended(cfg->layers.extendedAddress), &cfg->node, &cfg->power);

    if (status != ZB_OK)
        goto refuse;

    Zdo_SetNetwork(&self->zdo, &self->layers.nwk, &self->layers.aps, zbDeviceExtended(cfg->layers.extendedPanId));
    Zdo_SetUnsupportedToApplication(&self->zdo, cfg->zdpUnsupportedToApplication);

    status = zbDeviceStateBeacon(self, cfg);

    if (status != ZB_OK)
        goto refuse;

    self->transportNetworkKey = cfg->transportNetworkKey ? 1 : 0;
    self->parentLinkRetryThreshold = cfg->parentLinkRetryThreshold != 0 ? cfg->parentLinkRetryThreshold
                                                                        : ZB_CORE_PARENT_LINK_RETRY_THRESHOLD_DEFAULT;
    self->rejoinIntervalFirstMs = cfg->rejoinIntervalMs != 0 ? cfg->rejoinIntervalMs : ZB_CORE_REJOIN_INTERVAL_DEFAULT_MS;
    self->rejoinIntervalMaxMs = cfg->maxRejoinIntervalMs != 0 ? cfg->maxRejoinIntervalMs
                                                              : ZB_CORE_MAX_REJOIN_INTERVAL_DEFAULT_MS;

    if (self->rejoinIntervalMaxMs < self->rejoinIntervalFirstMs)
        self->rejoinIntervalMaxMs = self->rejoinIntervalFirstMs;

    self->rejoinIntervalMs = self->rejoinIntervalFirstMs;
    self->running = 1;

    return ZB_OK;

refuse:
    Zb_memset(self, 0, (uint32_t)sizeof *self);

    return status;
}

ZbStatus Zb_CoreRestore(Zb_Core *self, const Zb_State *state, int announce)
{
    ZbStatus status;

    if (self == 0 || !self->running || state == 0)
        return ZB_ERR_BAD_ARGUMENT;

    status = Zb_LayersRestore(&self->layers, state);

    if (status != ZB_OK)
        return status;

    Zdo_SetNetwork(&self->zdo, &self->layers.nwk, &self->layers.aps, state->extendedPanId);

    if (self->layers.nwk.cfg.deviceType != NWK_DEVICE_END_DEVICE)
    {
        status = zbDeviceBeaconFor(self, state->extendedPanId, 0, state->nwkUpdateId);

        if (status != ZB_OK)
            return status;
    }

    self->joinAnnounced = announce ? 0 : 1;
    self->tcLinkKeyDone = 1;

    return ZB_OK;
}

ZbStatus Zb_CoreRegisterEndpoint(Zb_Core *self, const Af_SimpleDescriptor *descriptor)
{
    if (self == 0 || !self->running)
        return ZB_ERR_BAD_ARGUMENT;

    return Af_RegisterEndpoint(&self->af, descriptor, 0, 0);
}

ZbStatus Zb_CoreSendRequest(Zb_Core *self, const Aps_ApsdeReq *request, uint32_t nowMs)
{
    if (self == 0 || !self->running || request == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (request->srcEndpoint != AF_ENDPOINT_ZDO && Af_DescriptorOf(&self->af, request->srcEndpoint) == 0)
        return ZB_ERR_NOT_FOUND;

    return Aps_DataRequest(&self->layers.aps, request, nowMs);
}

ZbStatus Zb_CoreJoin(Zb_Core *self, const Zb_CoreJoinParameters *params, uint32_t nowMs)
{
    ZbStatus status;

    if (self == 0 || !self->running || params == 0 || params->scanChannels == 0
        || params->scanAttempts > ZB_CORE_SCAN_ATTEMPTS_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->joinState != ZB_CORE_JOIN_IDLE)
        return ZB_ERR_BUSY;

    if (self->layers.nwk.cfg.deviceType == NWK_DEVICE_COORDINATOR || Nwk_IsPartOfNetwork(&self->layers.nwk))
        return ZB_ERR_BAD_STATE;

    self->joinParams = *params;

    if (self->joinParams.scanAttempts == 0)
        self->joinParams.scanAttempts = ZB_CORE_SCAN_ATTEMPTS_DEFAULT;

    if (self->joinParams.scanGapMs == 0)
        self->joinParams.scanGapMs = ZB_CORE_SCAN_GAP_DEFAULT_MS;

    zbDeviceFilter(self);
    status = zbDeviceDiscover(self, 0, nowMs);

    if (status != ZB_OK)
        return status;

    Zb_memset(&self->joinResult, 0, (uint32_t)sizeof self->joinResult);
    self->joinScansLeft = self->joinParams.scanAttempts;
    self->joinResultReady = 0;
    self->joinState = ZB_CORE_JOIN_DISCOVERING;

    return ZB_OK;
}

uint32_t Zb_CorePollJoinResult(Zb_Core *self, Zb_CoreJoinResult *out)
{
    if (self == 0 || out == 0 || !self->joinResultReady)
        return 0;

    *out = self->joinResult;
    self->joinResultReady = 0;

    return 1;
}

ZbStatus Zb_CoreAnnounce(Zb_Core *self, uint32_t nowMs)
{
    if (self == 0 || !self->running)
        return ZB_ERR_BAD_ARGUMENT;

    return Zdo_DeviceAnnce(&self->zdo, nowMs);
}

/* 3.2.2.7's permit, and the radio's mode before it: a door opened before this device can acknowledge is a door a
   device walks into and fails, its association unanswered and its own report a NO_ACK this side never learns from. */
ZbStatus Zb_CorePermitJoining(Zb_Core *self, uint8_t duration, uint32_t nowMs)
{
    uint32_t verdict;

    if (self == 0 || !self->running)
        return ZB_ERR_BAD_ARGUMENT;

    zbDeviceFilter(self);

    if (!self->filtered)
        return ZB_ERR_NOT_READY;

    verdict = Nwk_PermitJoining(&self->layers.nwk, duration, nowMs);

    return verdict == NWK_PERMIT_SUCCESS ? ZB_OK : ZB_ERR_BAD_STATE;
}

ZbStatus Zb_CoreLeave(Zb_Core *self, int rejoin, uint32_t nowMs)
{
    uint32_t verdict;

    if (self == 0 || !self->running)
        return ZB_ERR_BAD_ARGUMENT;

    verdict = Nwk_LeaveRequest(&self->layers.nwk, Nwk_OwnExtendedAddress(&self->layers.nwk), 0, rejoin, nowMs);

    return verdict == NWK_LEAVE_STATUS_SUCCESS ? ZB_OK : ZB_ERR_BAD_STATE;
}

/* A parent other than this device is sent Remove Device at the address its report came from; this device's own child,
   or a device it noted no parent for, is tried by the leave request first, and one the neighbour table cannot name
   goes as the router form, to wherever the address map places it. */
ZbStatus Zb_CoreRemove(Zb_Core *self, uint64_t targetIeee, uint32_t nowMs)
{
    Aps_RemoveDeviceReq request;
    Zb_CoreJoiner *joiner;
    uint64_t own;
    uint32_t verdict;
    ZbStatus status;

    if (self == 0 || !self->running)
        return ZB_ERR_BAD_ARGUMENT;

    if (!self->transportNetworkKey)
        return ZB_ERR_BAD_STATE;

    own = self->layers.security.ownIeee;

    if (targetIeee == 0 || targetIeee == own)
        return ZB_ERR_BAD_ARGUMENT;

    joiner = zbDeviceJoinerOf(self, targetIeee);

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.targetIeee = targetIeee;

    if (joiner != 0 && joiner->parentIeee != own)
    {
        request.parentIeee = joiner->parentIeee;
        request.parentNwk = joiner->parentShort;
        (void)Nwk_AddressOfIeee(&self->layers.nwk, joiner->parentIeee, &request.parentNwk);

        status = Aps_RemoveDeviceRequest(&self->layers.aps, &request, nowMs);
    }
    else
    {
        verdict = Nwk_LeaveRequest(&self->layers.nwk, targetIeee, 0, 0, nowMs);
        request.parentIeee = targetIeee;

        if (verdict == NWK_LEAVE_STATUS_SUCCESS)
            status = ZB_OK;
        else if (verdict != NWK_LEAVE_STATUS_UNKNOWN_DEVICE)
            status = ZB_ERR_BAD_STATE;
        else if (!Nwk_AddressOfIeee(&self->layers.nwk, targetIeee, &request.parentNwk))
            status = ZB_ERR_NOT_FOUND;
        else
            status = Aps_RemoveDeviceRequest(&self->layers.aps, &request, nowMs);
    }

    if (status == ZB_OK && joiner != 0)
        Zb_memset(joiner, 0, (uint32_t)sizeof *joiner);

    return status;
}

int Zb_CoreParentOf(const Zb_Core *self, uint64_t deviceIeee, uint64_t *parentIeee)
{
    uint32_t i;

    if (self == 0 || parentIeee == 0)
        return 0;

    for (i = 0; i < ZB_CORE_JOINER_MAX; i++)
    {
        if (self->joiners[i].inUse && self->joiners[i].deviceIeee == deviceIeee)
        {
            *parentIeee = self->joiners[i].parentIeee;

            return 1;
        }
    }

    return 0;
}

uint32_t Zb_CorePollIndications(Zb_Core *self, Aps_Indication *out, uint32_t max)
{
    uint32_t taken = 0;
    uint32_t i;

    if (self == 0 || out == 0)
        return 0;

    while (taken < max && self->indicationCount > 0)
    {
        out[taken++] = self->indications[0];

        for (i = 1; i < self->indicationCount; i++)
            self->indications[i - 1] = self->indications[i];

        self->indicationCount--;
    }

    return taken;
}

uint32_t Zb_CorePollDepartures(Zb_Core *self, Zb_CoreDeparture *out, uint32_t max)
{
    uint32_t taken = 0;
    uint32_t i;

    if (self == 0 || out == 0)
        return 0;

    while (taken < max && self->departureCount > 0)
    {
        out[taken++] = self->departures[0];

        for (i = 1; i < self->departureCount; i++)
            self->departures[i - 1] = self->departures[i];

        self->departureCount--;
    }

    return taken;
}

uint32_t Zb_CorePollConfirms(Zb_Core *self, Aps_Confirm *out, uint32_t max)
{
    if (self == 0 || !self->running)
        return 0;

    return Zb_LayersPollConfirms(&self->layers, out, max);
}

Zb_Layers *Zb_CoreLayers(Zb_Core *self)
{
    return self ? &self->layers : 0;
}

Aps_Aps *Zb_CoreAps(Zb_Core *self)
{
    return self ? &self->layers.aps : 0;
}

Nwk_Nwk *Zb_CoreNwk(Zb_Core *self)
{
    return self ? &self->layers.nwk : 0;
}

Mac_Mac *Zb_CoreMac(Zb_Core *self)
{
    return self ? &self->layers.mac : 0;
}

Aps_Binding *Zb_CoreBindings(Zb_Core *self)
{
    return self ? self->bindings : 0;
}

uint32_t Zb_CoreEndpointCount(const Zb_Core *self)
{
    return self != 0 ? Af_EndpointCount(&self->af) : 0;
}

uint32_t Zb_CoreZdpFramesConsumed(const Zb_Core *self)
{
    return self != 0 ? self->zdpFramesConsumed : 0;
}

uint16_t Zb_CoreLastZdpCluster(const Zb_Core *self)
{
    return self != 0 ? self->lastZdpCluster : 0;
}

uint16_t Zb_CoreLastZdpProfile(const Zb_Core *self)
{
    return self != 0 ? self->lastZdpProfile : 0;
}

uint8_t Zb_CoreLastZdpEndpoint(const Zb_Core *self)
{
    return self != 0 ? self->lastZdpEndpoint : 0;
}

uint32_t Zb_CoreAnnouncementsRepublished(const Zb_Core *self)
{
    return self != 0 ? self->announcementsRepublished : 0;
}

uint32_t Zb_CoreGroupFramesUnmatched(const Zb_Core *self)
{
    return self != 0 ? self->groupFramesUnmatched : 0;
}

uint32_t Zb_CoreIndicationsDropped(const Zb_Core *self)
{
    return self != 0 ? self->indicationsDropped : 0;
}

uint32_t Zb_CoreDeparturesDropped(const Zb_Core *self)
{
    return self != 0 ? self->departuresDropped : 0;
}

uint32_t Zb_CoreNetworkKeysSent(const Zb_Core *self)
{
    return self != 0 ? self->networkKeysSent : 0;
}

ZbStatus Zb_CoreForgetLinkKey(Zb_Core *self, uint64_t deviceIeee)
{
    if (self == 0 || !self->running || deviceIeee == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (!self->transportNetworkKey)
        return ZB_ERR_BAD_STATE;

    return Security_ForgetLinkKey(&self->layers.security, deviceIeee) >= 0 ? ZB_OK : ZB_ERR_NOT_FOUND;
}

uint32_t Zb_CoreJoinsHeard(const Zb_Core *self)
{
    return self != 0 ? self->joinsHeard : 0;
}

uint32_t Zb_CoreJoinsUnreported(const Zb_Core *self)
{
    return self != 0 ? self->joinsUnreported : 0;
}

uint32_t Zb_CoreLeavesUnreported(const Zb_Core *self)
{
    return self != 0 ? self->leavesUnreported : 0;
}

uint32_t Zb_CoreRemovalsTaken(const Zb_Core *self)
{
    return self != 0 ? self->removalsTaken : 0;
}

uint32_t Zb_CoreRemovalsDiscarded(const Zb_Core *self)
{
    return self != 0 ? self->removalsDiscarded : 0;
}

uint32_t Zb_CoreRejoins(const Zb_Core *self)
{
    return self != 0 ? self->rejoins : 0;
}

uint32_t Zb_CoreRejoinsFailed(const Zb_Core *self)
{
    return self != 0 ? self->rejoinsFailed : 0;
}

uint32_t Zb_CoreParentLinkFailures(const Zb_Core *self)
{
    return self != 0 ? self->parentLinkFailures : 0;
}

uint32_t Zb_CoreJoinersEvicted(const Zb_Core *self)
{
    return self != 0 ? self->joinersEvicted : 0;
}

uint32_t Zb_CoreNetworkKeysTunnelled(const Zb_Core *self)
{
    return self != 0 ? self->networkKeysTunnelled : 0;
}

uint32_t Zb_CoreKeysOwedRefused(const Zb_Core *self)
{
    return self != 0 ? self->keysOwedRefused : 0;
}

uint32_t Zb_CoreTrustCentreRejoinsRefused(const Zb_Core *self)
{
    return self != 0 ? self->trustCentreRejoinsRefused : 0;
}

uint32_t Zb_CoreNetworkKeysRefused(const Zb_Core *self)
{
    return self != 0 ? self->networkKeysRefused : 0;
}

int Zb_CoreIsRunning(const Zb_Core *self)
{
    return self != 0 && self->running;
}
