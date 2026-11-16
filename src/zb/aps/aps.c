#include "aps.h"

#include "aps_ack.h"
#include "aps_dup.h"
#include "aps_frame.h"
#include "aps_group.h"
#include "aps_rx.h"
#include "nwk.h"
#include "nwk_addr.h"
#include "nwk_frame.h"
#include "security.h"
#include "zb_time.h"
#include "zb_utils.h"

/* R23.1 2.2.4 2.2.4.1.1 2.2.4.1.1.3 2.2.4.1.2 2.2.4.1.3 2.2.4.3 2.2.4.5 2.2.4.5.1 2.2.4.5.3 2.2.4.5.5 2.2.7 2.2.5.1.7 2.2.8.4.1
   2.2.8.4.2 2.2.8.4.4 4.4.1.3 4.4.2.2 4.4.2.3 4.4.11 4.4.12 4.6.3.4.2 4.6.3.7 4.6.3.8 4.9.2 ok; 4.4.3 4.6.3.2.1 ok (a
   trust centre's indication, from its own join and from a router's command judged by Table 4-6, and the router's
   command, its two copies and the Tunnel it relays); 4.4.4 4.4.4.1.3 4.4.4.2 ok (the command, APS encrypted both ways,
   and its indication at a router); 4.4.5 4.4.5.2 4.4.7.1 4.4.7.2.3 4.4.8.1 4.4.8.2.3 4.7.3.8
   4.7.3.8.1 ok (a trust centre's answer for the trust centre link key, and a joiner's own Request-Key, Verify-Key and
   Confirm-Key, D-218; an application key unbuilt); 2.2.5 2.2.5.1.1
   2.2.5.1.6 2.2.5.2.3 2.2.8 2.2.8.3.1 2.2.8.4.5 4.4.1 4.4.1.1 4.4.1.2 4.5.1.3 elsewhere (aps_frame.c's header, aps_group.c's table,
   aps_tx.c's protection, aps_ack.c's mirror). */

/*
 * The answer a transaction gets when it is finished with, and the only way a slot ends: the confirmation ring
 * is the SAP's own channel, and the door's slot-plus-ring check keeps it inside its bound (§4.3).
 */
static void apsDoConfirm(Aps_Aps *self, Aps_Tx *tx, ZbStatus status, uint32_t apsStatus)
{
    Aps_Confirm *confirm;

    if (!tx->confirmOwed)
    {
        self->commandAnswers++;

        if (status != ZB_OK || apsStatus != APS_STATUS_SUCCESS)
            self->commandFailures++;

        Zb_memset(tx, 0, (uint32_t)sizeof *tx);

        return;
    }

    confirm = &self->confirms[(self->confirmHead + self->confirmCount) % APS_CONFIRM_MAX];

    confirm->status = status;
    confirm->apsStatus = apsStatus;
    confirm->dstAddrMode = tx->dstAddrMode;
    confirm->dstAddress = tx->dstAddress;
    confirm->dstExtendedAddress = tx->dstExtendedAddress;
    confirm->dstEndpoint = tx->dstEndpoint;
    confirm->srcEndpoint = tx->srcEndpoint;
    confirm->profileId = tx->profileId;
    confirm->clusterId = tx->clusterId;
    confirm->apsCounter = tx->apsCounter;
    confirm->attempts = tx->attempts;
    confirm->tag = tx->tag;

    self->confirmCount++;

    Zb_memset(tx, 0, (uint32_t)sizeof *tx);
}

/*
 * An answer for a request that never became a transaction: 2.2.4.1.1.3 answers these through
 * APSDE-DATA.confirm and not through a return code, `attempts` being zero because nothing was issued. A
 * refusal this module cannot deliver is said so, `ZB_ERR_NO_SPACE` and a count (§4.3).
 */
static int apsDoRequestConfirm(Aps_Aps *self, const Aps_ApsdeReq *req, ZbStatus status, uint32_t apsStatus)
{
    Aps_Confirm *confirm;

    if (self->confirmCount >= APS_CONFIRM_MAX)
    {
        self->refusedRequests++;
        return 0;
    }

    confirm = &self->confirms[(self->confirmHead + self->confirmCount) % APS_CONFIRM_MAX];

    confirm->status = status;
    confirm->apsStatus = apsStatus;
    confirm->dstAddrMode = req->dstAddrMode;
    confirm->dstAddress = req->dstAddress;
    confirm->dstExtendedAddress = req->dstExtendedAddress;
    confirm->dstEndpoint = req->dstEndpoint;
    confirm->srcEndpoint = req->srcEndpoint;
    confirm->profileId = req->profileId;
    confirm->clusterId = req->clusterId;
    confirm->apsCounter = (uint8_t)self->apsCounter;
    confirm->attempts = 0;
    confirm->tag = req->tag;

    self->confirmCount++;

    return 1;
}

/* A frame for this device itself, a binding entry that names it or a request to its own address, is delivered here
   rather than put on the air: the indication carries `dstEndpoint` and this device's own source address, which is the
   address the frame came from. 0 when the indication ring is full, which is counted. */
static int apsDoLocalIndicate(Aps_Aps *self, const Aps_ApsdeReq *req, uint8_t dstEndpoint, uint64_t ownIeee)
{
    Aps_Indication *slot;
    uint16_t ownShort = Nwk_OwnAddress(self->nwk);

    if (self->indicationCount >= APS_INDICATION_MAX)
    {
        self->droppedIndications++;

        return 0;
    }

    if (req->asduLength > (uint32_t)sizeof slot->asdu)
    {
        self->droppedIndications++;

        return 0;
    }

    slot = &self->indications[(self->indicationHead + self->indicationCount) % APS_INDICATION_MAX];

    Zb_memset(slot, 0, (uint32_t)sizeof *slot);

    slot->dstAddrMode = APS_ADDR_MODE_SHORT;
    slot->dstAddress = ownShort;
    slot->dstEndpoint = dstEndpoint;
    slot->srcAddrMode = APS_ADDR_MODE_SHORT;
    slot->srcAddress = ownShort;
    slot->srcExtendedAddress = ownIeee;
    slot->srcEndpoint = req->srcEndpoint;
    slot->profileId = req->profileId;
    slot->clusterId = req->clusterId;
    slot->status = APS_STATUS_SUCCESS;
    slot->securityStatus = APS_STATUS_SUCCESS;
    slot->keyIndex = APS_KEY_INDEX_NONE;
    slot->keyStatus = APS_KEY_STATUS_NONE;

    if (req->asdu != 0 && req->asduLength != 0)
        Zb_memcpy(slot->asdu, req->asdu, req->asduLength);

    slot->asduLength = req->asduLength;

    self->indicationCount++;

    return 1;
}

/* A unicast to this device's own address goes no further than here: it is indicated as a received frame would be, and
   confirmed SUCCESS, since the ASDU reached every intended target. An ASDU the indication cannot hold is
   ASDU_TOO_LONG; a full confirm or indication ring refuses the request, ZB_ERR_NO_SPACE, and indicates nothing. */
static ZbStatus apsDoLoopback(Aps_Aps *self, const Aps_ApsdeReq *req)
{
    if (req->asduLength > (uint32_t)sizeof self->indications[0].asdu)
    {
        if (!apsDoRequestConfirm(self, req, ZB_OK, APS_STATUS_ASDU_TOO_LONG))
            return ZB_ERR_NO_SPACE;

        return ZB_OK;
    }

    if (self->confirmCount >= APS_CONFIRM_MAX || self->indicationCount >= APS_INDICATION_MAX)
    {
        self->refusedRequests++;
        return ZB_ERR_NO_SPACE;
    }

    (void)apsDoLocalIndicate(self, req, req->dstEndpoint, Nwk_OwnExtendedAddress(self->nwk));
    (void)apsDoRequestConfirm(self, req, ZB_OK, APS_STATUS_SUCCESS);
    self->loopbacks++;

    return ZB_OK;
}

/* The request itself, once the binding search has decided what address it carries. */
static ZbStatus apsDoRequest(Aps_Aps *self, const Aps_ApsdeReq *req, uint32_t nowMs);

/*
 * The binding fan-out: the table is searched by the request's source endpoint and cluster, no entry is
 * 2.2.4.1.1.3's NO_BOUND_DEVICE, and every entry found becomes a request of its own, addressed at the entry's
 * destination or indicated to this device when the entry names it.
 */
static ZbStatus apsDoBoundRequest(Aps_Aps *self, const Aps_ApsdeReq *req, uint32_t nowMs)
{
    Aps_ApsdeReq bound;
    Aps_Binding *bindings = self->bindings;
    uint32_t indices[APS_BIND_MAX];
    uint64_t ownIeee = Nwk_OwnExtendedAddress(self->nwk);
    uint32_t count;
    uint32_t i;
    uint32_t sent = 0;
    ZbStatus status;

    if (bindings == 0)
    {
        (void)apsDoRequestConfirm(self, req, ZB_ERR_UNSUPPORTED, APS_STATUS_NOT_SUPPORTED);

        return ZB_OK;
    }

    count = Aps_BindOf(bindings, ownIeee, req->srcEndpoint, req->clusterId, indices, APS_BIND_MAX);

    if (count == 0)
    {
        (void)apsDoRequestConfirm(self, req, ZB_ERR_NOT_FOUND, APS_STATUS_NO_BOUND_DEVICE);

        return ZB_OK;
    }

    for (i = 0; i < count && i < APS_BIND_MAX; i++)
    {
        const Aps_Binding *entry = &bindings[indices[i]];

        if (Aps_BindCheck(entry) != ZB_OK)
        {
            self->droppedBoundEntries++;

            continue;
        }

        if (entry->dstAddrMode == APS_ADDR_MODE_EXTENDED && entry->dstExtendedAddress == ownIeee)
        {
            if (apsDoLocalIndicate(self, req, entry->dstEndpoint, ownIeee))
                sent++;

            continue;
        }

        bound = *req;
        bound.dstAddrMode = entry->dstAddrMode;
        bound.dstAddress = entry->dstAddress;
        bound.dstExtendedAddress = entry->dstExtendedAddress;
        bound.dstEndpoint = entry->dstEndpoint;

        status = apsDoRequest(self, &bound, nowMs);

        if (status == ZB_OK)
            sent++;
    }

    return sent != 0 ? ZB_OK : ZB_ERR_NO_ROUTE;
}

/*
 * What the network layer answered, in the order it answered it. A failed NLDE confirmation ends the
 * transaction now with the code the NWK layer printed and no APS retransmission (2.2.4.1.1.3, Table 2-3).
 * Then the ask decides: AR set arms `apscAckWaitDuration` from this moment, AR clear answers SUCCESS.
 */
static void apsDoDrainConfirms(Aps_Aps *self, uint32_t nowMs)
{
    const Nwk_DataConfirmParameters *confirm = &self->nwkConfirm;
    Aps_Tx *tx;
    uint32_t waiting;
    uint32_t i;

    waiting = Nwk_ConfirmsWaiting(self->nwk);

    for (i = 0; i < waiting && Nwk_PollConfirms(self->nwk, &self->nwkConfirm, 1) == 1; i++)
    {
        tx = Aps_TxSlotForConfirm(self->tx, confirm);

        if (tx == 0)
        {
            self->confirmsIgnored++;
            continue;
        }

        if (confirm->status != ZB_OK)
        {
            apsDoConfirm(self, tx, confirm->status, confirm->nwkStatus);
            continue;
        }

        if (tx->ackRequested)
        {
            tx->state = APS_TX_AWAITING_ACK;
            tx->ackDeadlineMs = nowMs + APS_ACK_WAIT_DURATION_MS;
            continue;
        }

        apsDoConfirm(self, tx, ZB_OK, APS_STATUS_SUCCESS);
    }
}

/*
 * One delivery into the indication ring, refused and counted when there is no room
 * for it or for the ASDU it would carry: refusal and count at production, never an
 * overwrite in flight (§4.3). A Status other than SUCCESS carries the null ASDU
 * 2.2.4.1.3.2 prescribes; the security triple arrives from the gate that decided it.
 */
/* The source mapping sits beside the rest of the indication: a source the map holds is named by its 64-bit address
   and the mode says so. */
static void apsDoIndicate(Aps_Aps *self, const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame,
                          uint32_t dstAddrMode, uint16_t dstAddress, uint8_t dstEndpoint,
                          const Aps_Delivery *delivery);

#if ZB_APS_FRAGMENTATION
/* The reception of a fragmented frame: the block into the reassembly pool, the window acknowledgement, and the whole
   ASDU upward when the last block lands. A block the pool refuses is counted by the rule that refused it and is not
   acknowledged, which is the clause's own answer for a number outside the window. */
static void apsDoFragmentReceive(Aps_Aps *self, const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame,
                                 Aps_Delivery *delivery, uint32_t nowMs)
{
    Aps_FragAssembly *assembly = 0;
    Aps_FragVerdict verdict;
    Aps_AckOutcome ackOutcome;
    uint8_t windowBlock = 0;
    uint8_t windowBitfield = 0;
    uint32_t capacity;

    capacity = (uint32_t)APS_FRAME_MAX - (uint32_t)APS_MIN_HEADER_OVERHEAD;

    verdict = Aps_FragAccept(self->frag, ind->srcAddr, frame->apsCounter, frame->fragmentation,
                             frame->blockNumberPresent ? frame->blockNumber : 0, delivery->asdu,
                             delivery->asduLength, capacity, nowMs, &assembly);

    if (verdict == APS_FRAG_DROP_SHAPE || verdict == APS_FRAG_DROP_BOUNDS
        || verdict == APS_FRAG_DROP_OUT_OF_WINDOW || verdict == APS_FRAG_DROP_NO_ROOM)
    {
        self->rxFragmentDrops++;
        return;
    }

    if (Aps_FragAckWindow(self->frag, ind->srcAddr, frame->apsCounter, &windowBlock, &windowBitfield))
    {
        ackOutcome = Aps_AckRespondFragment(ind, frame, windowBlock, windowBitfield, self->nwk,
                                            self->ackApdu, (uint32_t)sizeof self->ackApdu, nowMs);

        if (ackOutcome == APS_ACK_RESPONDED)
            self->acksGenerated++;

        if (ackOutcome == APS_ACK_COMPOSE_REFUSED || ackOutcome == APS_ACK_ISSUE_REFUSED)
            self->acksRefused++;
    }

    if (verdict != APS_FRAG_COMPLETE || assembly == 0)
        return;

    delivery->asdu = assembly->asdu;
    delivery->asduLength = assembly->asduLength;
    delivery->status = APS_STATUS_SUCCESS;

    self->fragmentsReassembled++;

    apsDoIndicate(self, ind, frame, APS_ADDR_MODE_SHORT, ind->dstAddr, frame->dstEndpoint, delivery);

    Zb_memset(assembly, 0, (uint32_t)sizeof *assembly);
}
#endif
static void apsDoIndicate(Aps_Aps *self, const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame,
                          uint32_t dstAddrMode, uint16_t dstAddress, uint8_t dstEndpoint,
                          const Aps_Delivery *delivery)
{
    Aps_Indication *slot;

    if (self->indicationCount >= APS_INDICATION_MAX)
    {
        self->droppedIndications++;
        return;
    }

    if (delivery->asduLength > (uint32_t)sizeof slot->asdu)
    {
        self->droppedIndications++;
        return;
    }

    slot = &self->indications[(self->indicationHead + self->indicationCount) % APS_INDICATION_MAX];

    Zb_memset(slot, 0, (uint32_t)sizeof *slot);

    slot->dstAddrMode = dstAddrMode;
    slot->dstAddress = dstAddress;
    slot->dstEndpoint = dstEndpoint;
    slot->srcAddrMode = APS_ADDR_MODE_SHORT;
    slot->srcAddress = ind->srcAddr;

    if (self->nwk != 0 && Nwk_IeeeOfAddress(self->nwk, ind->srcAddr, &slot->srcExtendedAddress))
        slot->srcAddrMode = APS_ADDR_MODE_EXTENDED;

    slot->srcEndpoint = frame->srcEndpoint;
    slot->profileId = frame->profileId;
    slot->clusterId = frame->clusterId;
    slot->status = delivery->status;
    slot->securityStatus = delivery->securityStatus;
    slot->linkQuality = ind->lqi;
    slot->keyIndex = delivery->keyIndex;
    slot->keyStatus = delivery->keyStatus;

    if (delivery->status == APS_STATUS_SUCCESS && delivery->asduLength != 0)
        Zb_memcpy(slot->asdu, delivery->asdu, delivery->asduLength);

    slot->asduLength = delivery->status == APS_STATUS_SUCCESS ? delivery->asduLength : 0;

    self->indicationCount++;
}

/* The AIB attributes the key door reads, taken off the adopted `Security` because the key pairs and the operating
   state live there. A pair whose DeviceAddress is apsTrustCenterAddress is a preconfigured link key. */
static void apsDoKeyPolicy(const Aps_Aps *self, Aps_KeyPolicy *out)
{
    Zb_memset(out, 0, (uint32_t)sizeof *out);

    if (self->security == 0)
        return;

    out->trustCenterIeee = self->security->trustCenterIeee;
    out->requireLinkKeyEncryption = self->security->requireLinkKeyEncryption;
    out->joinedAndAuthorized = Security_IsAuthenticated(self->security) ? 1 : 0;
    out->hasPreconfiguredLinkKey =
        Security_FindKeyPairByIeee(self->security, self->security->trustCenterIeee) >= 0 ? 1 : 0;
}

#if ZB_APS_FRAGMENTATION
/* The block sequence, one window at a time: an acknowledgement for the block being sent moves to the next one, and
   the retry counter is the transaction's own, reset whenever a block lands. */
static void apsDoFragmentedAck(Aps_Aps *self, Aps_Tx *tx, const Aps_Frame *frame, uint32_t nowMs)
{
    ZbStatus status;

    if (frame->blockNumberPresent && frame->blockNumber != Aps_FragBlockNumber(tx->fragIndex, tx->fragTotal))
    {
        self->unmatchedAcks++;
        return;
    }

    tx->attempts = 0;
    tx->fragIndex = (uint8_t)(tx->fragIndex + 1);

    if (tx->fragIndex >= tx->fragTotal)
    {
        apsDoConfirm(self, tx, ZB_OK, APS_STATUS_SUCCESS);
        return;
    }

    status = Aps_TxComposeBlock(tx);

    if (status == ZB_OK && tx->apsSecurity)
        status = Aps_TxProtect(self->security, tx, self->secureScratch, (uint32_t)sizeof self->secureScratch);

    if (status != ZB_OK)
    {
        apsDoConfirm(self, tx, status, APS_STATUS_LAST_SEAM_STATUS);
        return;
    }

    status = Aps_TxIssue(tx, self->nwk, self->secureScratch, nowMs);

    if (status != ZB_OK)
    {
        apsDoConfirm(self, tx, status, APS_STATUS_LAST_SEAM_STATUS);
        return;
    }

    tx->state = APS_TX_AWAITING_ACK;
    tx->ackDeadlineMs = nowMs + APS_ACK_WAIT_DURATION_MS;
}
#endif

/*
 * 4.4.1.3 then 4.4.2.3 over one transport-key command, and the act the verdict asks for: a network key lands through
 * 4.6.3.4.2 and verifies the pair it came from (4.6.3.8), a link key waits for the pair-set install this slice does
 * not have, a forward for 4.6.3.7's tunnel, and every outcome is counted by the rule that produced it.
 */
/* 4.4.11 asks an acknowledgement for every unicast command, so the answer is composed here for the frame the door
   decided, whatever it decided: a dropped key is answered with the status that says so. */
static void apsDoCommandAnswer(Aps_Aps *self, const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame,
                               uint32_t deliveryStatus, uint32_t nowMs)
{
    Aps_AckOutcome outcome;

    outcome = Aps_AckRespond(ind, frame, deliveryStatus, self->nwk, self->ackApdu,
                             (uint32_t)sizeof self->ackApdu, nowMs);

    if (outcome == APS_ACK_RESPONDED)
        self->acksGenerated++;

    if (outcome == APS_ACK_COMPOSE_REFUSED || outcome == APS_ACK_ISSUE_REFUSED)
        self->acksRefused++;
}

/* The device a frame's link key names: the pair's own, or for the global pair, which names none, the sender the crossing
   authenticated. */
static void apsDoKeyPairOf(const Aps_Aps *self, const Aps_Delivery *delivery, Aps_KeyReceipt *receipt)
{
    const Security_KeyPairEntry *pair;

    pair = Security_KeyPairAt(self->security, (int)delivery->keyIndex);

    if (pair == 0)
        return;

    receipt->keyPairIeee = pair->deviceIeee != 0 ? pair->deviceIeee : delivery->srcIeee;
    receipt->keyPairKnown = 1;
}

/* The identifier is the payload's first octet (Figure 2-8), read once the crossing has unsecured it. A secured NWK
   lets an unsecured frame through for a Transport Key alone and cannot see an APS-secured identifier, so any other
   command that came that way is refused here. */
static ZbStatus apsDoTransportKey(Aps_Aps *self, const Aps_TransportKeyReq *req, int pairIndex, uint32_t nowMs);
static ZbStatus apsDoCommandSend(Aps_Aps *self, uint16_t nwkDst, uint64_t destIeee, const uint8_t *payload,
                                 uint32_t payloadLen, int pairIndex, uint32_t nowMs);

/* Whether this device is a centralized network's trust centre, the only device that answers these commands. */
static int apsDoIsTrustCenter(const Aps_Aps *self)
{
    return self->security != 0 && self->security->trustCenterIeee != 0xffffffffffffffff
           && self->security->trustCenterIeee == self->security->ownIeee;
}

/* The device's own unique pair for the address, never the global fallback the plain lookup ends in. */
static int apsDoUniquePairOf(const Aps_Aps *self, uint64_t ieee)
{
    const Security_KeyPairEntry *entry;
    int index;

    index = Security_FindKeyPairByIeee(self->security, ieee);
    entry = Security_KeyPairAt(self->security, index);

    if (entry == 0 || entry->deviceIeee != ieee || entry->linkKeyType != SECURITY_LINK_KEY_UNIQUE)
        return -1;

    return index;
}

/*
 * A Request-Key for the trust centre link key: APS encrypted under the pair of the device that sent it, or under the
 * global key a joiner holds (D-218); allowTrustCenterLinkKeyRequests decides; the key is derived, sent under the key
 * the device holds now, and the new entry written unverified. An application key request is not taken.
 */
static void apsDoRequestKey(Aps_Aps *self, const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame,
                            const Aps_Delivery *delivery, uint32_t nowMs)
{
    const Security_KeyPairEntry *used;
    Aps_RequestKey request;
    Aps_TransportKeyReq keyReq;
    uint8_t key[SECURITY_KEY_OCTETS];
    int sendIndex;
    int exact;
    uint32_t i;

    if (Aps_RequestKeyParse(delivery->asdu + APS_FRAME_COMMAND_ID_OCTETS,
                            delivery->asduLength - APS_FRAME_COMMAND_ID_OCTETS, &request) != ZB_OK)
    {
        self->rxMalformed++;
        return;
    }

    if (request.requestKeyType != APS_TCLINK_REQUEST_TC_LINK_KEY)
    {
        self->rxCommandDeferred++;
        return;
    }

    used = Security_KeyPairAt(self->security, (int)delivery->keyIndex);

    if (!frame->securityEnabled || used == 0 || !apsDoIsTrustCenter(self)
        || (used->linkKeyType == SECURITY_LINK_KEY_UNIQUE && used->deviceIeee != delivery->srcIeee))
    {
        self->tcLinkKeyRequestsDropped++;
        return;
    }

    exact = apsDoUniquePairOf(self, delivery->srcIeee);

    if (self->allowTcLinkKeyRequests == 0
        || (self->allowTcLinkKeyRequests == 2
            && (exact < 0 || self->security->keyPairs[exact].keyAttributes != SECURITY_KEYPAIR_ATTR_PROVISIONAL))
        || Security_DeriveLinkKey(self->security, delivery->srcIeee, key) != ZB_OK)
    {
        self->tcLinkKeyRequestsDropped++;
        return;
    }

    apsDoCommandAnswer(self, ind, frame, APS_STATUS_SUCCESS, nowMs);

    Zb_memset(&keyReq, 0, (uint32_t)sizeof keyReq);
    keyReq.destIeee = delivery->srcIeee;
    keyReq.nwkDst = ind->srcAddr;
    keyReq.standardKeyType = APS_TK_TYPE_TC_LINK_KEY;
    keyReq.destinationIeee = delivery->srcIeee;
    keyReq.sourceIeee = self->security->ownIeee;
    Zb_memcpy(keyReq.key, key, APS_TK_KEY_OCTETS);

    sendIndex = (int)delivery->keyIndex;

    if (apsDoTransportKey(self, &keyReq, sendIndex, nowMs) != ZB_OK
        || Security_SetUnverifiedPair(self->security, delivery->srcIeee, ind->srcAddr, key) < 0)
        self->tcLinkKeyRequestsDropped++;
    else
        self->tcLinkKeysSent++;

    for (i = 0; i < SECURITY_KEY_OCTETS; i++)
        key[i] = 0;
}

/* The Confirm-Key: APS encrypted under the entry when there is one and in clear when there is none, a success sent
   once the entry is verified, its incoming counter back to 0. */
static void apsDoConfirmKey(Aps_Aps *self, uint16_t nwkDst, uint64_t destIeee, uint8_t status, int pairIndex,
                            uint32_t nowMs)
{
    uint8_t payload[1 + APS_TCLINK_CONFIRM_OCTETS];
    uint32_t len;

    if (Aps_ConfirmKeyCompose(status, APS_TK_TYPE_TC_LINK_KEY, destIeee, payload, (uint32_t)sizeof payload, &len)
        != ZB_OK)
        return;

    if (status == APS_STATUS_SUCCESS)
        (void)Security_ConfirmKeyPair(self->security, pairIndex);

    (void)apsDoCommandSend(self, nwkDst, destIeee, payload, len, pairIndex, nowMs);
}

/* A joiner's new trust centre link key: held unverified for the trust centre, so it encrypts nothing yet, and the
   Verify-Key its hash goes out in, unsecured at the APS layer. */
static void apsDoTcLinkKeyTaken(Aps_Aps *self, uint16_t trustCenter, const uint8_t *key, uint32_t nowMs)
{
    Aps_VerifyKey verify;
    uint8_t payload[1 + APS_TCLINK_VERIFY_OCTETS];
    uint32_t len;
    int index;

    index = Security_SetUnverifiedPair(self->security, self->security->trustCenterIeee, trustCenter, key);

    if (index < 0)
    {
        self->keyInstallFailed++;
        return;
    }

    self->tcLinkKeysInstalled++;
    self->tcLinkKeyState = APS_TCLK_VERIFYING;

    Zb_memset(&verify, 0, (uint32_t)sizeof verify);
    verify.standardKeyType = APS_TK_TYPE_TC_LINK_KEY;
    verify.sourceIeee = self->security->ownIeee;

    if (Security_VerifyKeyHash(&self->security->keyPairs[index], verify.hash) != ZB_OK
        || Aps_VerifyKeyCompose(&verify, payload, (uint32_t)sizeof payload, &len) != ZB_OK)
        return;

    (void)apsDoCommandSend(self, trustCenter, self->security->trustCenterIeee, payload, len, -1, nowMs);
}

/* A Confirm-Key at a joiner: from its trust centre, for the trust centre link key; SUCCESS verifies the entry the
   Verify-Key named, and any other status gives the update up. */
static void apsDoConfirmKeyTaken(Aps_Aps *self, const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame,
                                 const Aps_Delivery *delivery, uint32_t nowMs)
{
    Aps_ConfirmKey confirm;
    int index;

    if (ind->wasBroadcast || apsDoIsTrustCenter(self)
        || Aps_ConfirmKeyParse(delivery->asdu + APS_FRAME_COMMAND_ID_OCTETS,
                               delivery->asduLength - APS_FRAME_COMMAND_ID_OCTETS, &confirm) != ZB_OK)
    {
        self->rxMalformed++;
        return;
    }

    apsDoCommandAnswer(self, ind, frame, APS_STATUS_SUCCESS, nowMs);

    if (confirm.standardKeyType != APS_TK_TYPE_TC_LINK_KEY || self->security == 0
        || delivery->srcIeee != self->security->trustCenterIeee || self->tcLinkKeyState != APS_TCLK_VERIFYING)
    {
        self->rxCommandDeferred++;
        return;
    }

    index = apsDoUniquePairOf(self, self->security->trustCenterIeee);

    if (confirm.status != APS_STATUS_SUCCESS || index < 0
        || Security_ConfirmKeyPair(self->security, index) != ZB_OK)
    {
        Aps_TcLinkKeyAbandon(self);
        return;
    }

    self->tcLinkKeysVerified++;
    self->tcLinkKeyState = APS_TCLK_VERIFIED;
}

/* A unicast Verify-Key for the trust centre link key: its hash checked against the device's own entry, the entry
   verified on a match, and Confirm-Key's status either way. */
static void apsDoVerifyKey(Aps_Aps *self, const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame,
                           const Aps_Delivery *delivery, uint32_t nowMs)
{
    Aps_VerifyKey verify;
    uint8_t hash[SECURITY_KEY_OCTETS];
    uint32_t attributes;
    int index;

    if (ind->wasBroadcast
        || Aps_VerifyKeyParse(delivery->asdu + APS_FRAME_COMMAND_ID_OCTETS,
                              delivery->asduLength - APS_FRAME_COMMAND_ID_OCTETS, &verify) != ZB_OK)
    {
        self->rxMalformed++;
        return;
    }

    apsDoCommandAnswer(self, ind, frame, APS_STATUS_SUCCESS, nowMs);

    if (verify.standardKeyType != APS_TK_TYPE_TC_LINK_KEY || !apsDoIsTrustCenter(self))
    {
        self->verifyKeysRefused++;
        apsDoConfirmKey(self, ind->srcAddr, verify.sourceIeee,
                        verify.standardKeyType == APS_TK_TYPE_TC_LINK_KEY ? APS_STATUS_ILLEGAL_REQUEST
                                                                          : APS_STATUS_NOT_SUPPORTED, -1, nowMs);
        return;
    }

    index = apsDoUniquePairOf(self, verify.sourceIeee);
    attributes = index >= 0 ? self->security->keyPairs[index].keyAttributes : SECURITY_KEYPAIR_ATTR_PROVISIONAL;

    if (index < 0
        || (attributes != SECURITY_KEYPAIR_ATTR_UNVERIFIED && attributes != SECURITY_KEYPAIR_ATTR_VERIFIED)
        || Security_VerifyKeyHash(&self->security->keyPairs[index], hash) != ZB_OK
        || Zb_memcmp(hash, verify.hash, SECURITY_KEY_OCTETS) != 0)
    {
        self->verifyKeysRefused++;
        apsDoConfirmKey(self, ind->srcAddr, verify.sourceIeee, APS_STATUS_SECURITY_FAIL,
                        attributes == SECURITY_KEYPAIR_ATTR_PROVISIONAL ? -1 : index, nowMs);
        return;
    }

    self->verifyKeysConfirmed++;
    apsDoConfirmKey(self, ind->srcAddr, verify.sourceIeee, APS_STATUS_SUCCESS, index, nowMs);
}

/* One indication onto the ring: a repeat of one still queued is the same report, which a router's second copy is,
   and a full ring is drop-newest and count (docs/internals/coding-rules.md §4.3). */
static ZbStatus apsDoUpdateDevicePush(Aps_Aps *self, const Aps_UpdateDeviceIndication *indication)
{
    const Aps_UpdateDeviceIndication *queued;
    uint32_t i;

    for (i = 0; i < self->updateDeviceCount; i++)
    {
        queued = &self->updateDevices[(self->updateDeviceHead + i) % APS_UPDATE_DEVICE_INDICATION_MAX];

        if (queued->srcIeee == indication->srcIeee && queued->deviceIeee == indication->deviceIeee
            && queued->deviceShortAddress == indication->deviceShortAddress && queued->status == indication->status)
        {
            self->updateDevicesRepeated++;

            return ZB_OK;
        }
    }

    if (self->updateDeviceCount >= APS_UPDATE_DEVICE_INDICATION_MAX)
    {
        self->updateDevicesDropped++;

        return ZB_ERR_NO_SPACE;
    }

    self->updateDevices[(self->updateDeviceHead + self->updateDeviceCount) % APS_UPDATE_DEVICE_INDICATION_MAX]
        = *indication;
    self->updateDeviceCount++;
    self->updateDevicesIndicated++;

    return ZB_OK;
}

/* A received Update Device: ignored away from the trust centre, and refused unencrypted from a sender whose trust
   centre link key is unique or whose 64-bit address this device cannot name, its key type then unknown. */
static void apsDoUpdateDevice(Aps_Aps *self, const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame,
                              const Aps_Delivery *delivery, uint32_t nowMs)
{
    Aps_UpdateDeviceIndication indication;
    Aps_UpdateDevice body;
    uint64_t sender = 0;

    if (Aps_UpdateDeviceParse(delivery->asdu + APS_FRAME_COMMAND_ID_OCTETS,
                              delivery->asduLength - APS_FRAME_COMMAND_ID_OCTETS, &body) != ZB_OK)
    {
        self->rxMalformed++;
        return;
    }

    apsDoCommandAnswer(self, ind, frame, APS_STATUS_SUCCESS, nowMs);

    if (!apsDoIsTrustCenter(self))
    {
        self->updateDevicesIgnored++;
        return;
    }

    if (frame->securityEnabled)
        sender = delivery->srcIeee;
    else if (!Nwk_IeeeOfAddress(self->nwk, ind->srcAddr, &sender) || apsDoUniquePairOf(self, sender) >= 0)
    {
        self->updateDevicesRefused++;
        return;
    }

    Zb_memset(&indication, 0, (uint32_t)sizeof indication);

    indication.srcIeee = sender;
    indication.srcAddress = ind->srcAddr;
    indication.deviceIeee = body.deviceIeee;
    indication.deviceShortAddress = body.deviceShortAddress;
    indication.status = body.status;

    (void)apsDoUpdateDevicePush(self, &indication);
}

/* A router's report to its trust centre: APS encrypted under the pair it holds for the trust centre, and under a
   global key a second, NWK-only copy for a trust centre that accepts no other form. A trust centre the address map
   cannot place is the one an unencrypted command's source is checked against, at 0x0000. */
static ZbStatus apsDoUpdateDeviceSend(Aps_Aps *self, const Aps_UpdateDeviceReq *req, uint32_t nowMs)
{
    const Security_KeyPairEntry *pair;
    Aps_UpdateDevice body;
    uint8_t payload[APS_FRAME_MAX];
    uint32_t payloadLen = 0;
    uint64_t trustCenter;
    uint16_t nwkDst = APS_KEY_NWK_TRUST_CENTER;
    ZbStatus status;
    int pairIndex;

    trustCenter = self->security->trustCenterIeee;

    if (trustCenter == APS_KEY_IEEE_UNSET)
        return ZB_ERR_NOT_READY;

    if (trustCenter == APS_KEY_IEEE_ALL_F)
        return ZB_ERR_BAD_STATE;

    pairIndex = Security_FindKeyPairByIeee(self->security, trustCenter);
    pair = Security_KeyPairAt(self->security, pairIndex);

    if (pair == 0)
        return ZB_ERR_NOT_FOUND;

    Zb_memset(&body, 0, (uint32_t)sizeof body);

    body.deviceIeee = req->deviceIeee;
    body.deviceShortAddress = req->deviceShortAddress;
    body.status = req->status;
    body.joinerTlvs = req->joinerTlvs;
    body.joinerTlvLen = req->joinerTlvLen;

    status = Aps_UpdateDeviceCompose(&body, payload, (uint32_t)sizeof payload, &payloadLen);

    if (status != ZB_OK)
        return status;

    (void)Nwk_AddressOfIeee(self->nwk, trustCenter, &nwkDst);

    status = apsDoCommandSend(self, nwkDst, trustCenter, payload, payloadLen, pairIndex, nowMs);

    if (status == ZB_OK && pair->linkKeyType == SECURITY_LINK_KEY_GLOBAL)
        status = apsDoCommandSend(self, nwkDst, trustCenter, payload, payloadLen, -1, nowMs);

    if (status == ZB_OK)
        self->updateDevicesSent++;

    return status;
}

/* A received Remove Device: taken from the trust centre alone and only APS encrypted, which Table 4-7 requires of it.
   The sender is the one the decryption authenticated, so an unencrypted command names nobody; a full ring is
   drop-newest and count. */
static void apsDoRemoveDevice(Aps_Aps *self, const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame,
                              const Aps_Delivery *delivery, uint32_t nowMs)
{
    Aps_RemoveDeviceIndication *slot;
    uint64_t target;

    if (Aps_RemoveDeviceParse(delivery->asdu + APS_FRAME_COMMAND_ID_OCTETS,
                              delivery->asduLength - APS_FRAME_COMMAND_ID_OCTETS, &target) != ZB_OK)
    {
        self->rxMalformed++;
        return;
    }

    apsDoCommandAnswer(self, ind, frame, APS_STATUS_SUCCESS, nowMs);

    if (apsDoIsTrustCenter(self) || self->security->trustCenterIeee == APS_KEY_IEEE_UNSET
        || delivery->srcIeee != self->security->trustCenterIeee)
    {
        self->removeDevicesRefused++;
        return;
    }

    if (self->removeDeviceCount >= APS_REMOVE_DEVICE_INDICATION_MAX)
    {
        self->removeDevicesDropped++;
        return;
    }

    slot = &self->removeDevices[(self->removeDeviceHead + self->removeDeviceCount) % APS_REMOVE_DEVICE_INDICATION_MAX];

    slot->srcIeee = delivery->srcIeee;
    slot->targetIeee = target;

    self->removeDeviceCount++;
    self->removeDevicesIndicated++;
}

/* A Tunnel at a parent: taken from the trust centre alone, the APS-secured form under its pair and the unsecured one
   from 0x0000, and only for a child still unauthenticated; the command it carries goes to that child with network
   security off, the child having no key to read it by. */
static void apsDoTunnelReceive(Aps_Aps *self, const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame,
                               const Aps_Delivery *delivery, uint32_t nowMs)
{
    const Security_KeyPairEntry *pair;
    Nwk_DataRequestParameters req;
    Aps_Tunnel tunnel;
    uint16_t child;
    int fromTrustCenter;

    if (Aps_TunnelParse(delivery->asdu + APS_FRAME_COMMAND_ID_OCTETS,
                        delivery->asduLength - APS_FRAME_COMMAND_ID_OCTETS, &tunnel) != ZB_OK)
    {
        self->rxMalformed++;
        return;
    }

    apsDoCommandAnswer(self, ind, frame, APS_STATUS_SUCCESS, nowMs);

    pair = Security_KeyPairAt(self->security, (int)delivery->keyIndex);

    if (frame->securityEnabled)
        fromTrustCenter = pair != 0 && pair->deviceIeee == self->security->trustCenterIeee;
    else
        fromTrustCenter = ind->srcAddr == APS_KEY_NWK_TRUST_CENTER;

    if (!fromTrustCenter || apsDoIsTrustCenter(self)
        || !Nwk_UnauthenticatedChildOf(self->nwk, tunnel.destinationIeee, &child))
    {
        self->tunnelsDropped++;
        return;
    }

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    req.dstAddr = child;
    req.nsdu = tunnel.secured;
    req.nsduLength = tunnel.securedLen;
    req.radius = 1;
    req.discoverRoute = NWK_DISCOVER_SUPPRESS;
    req.securityEnable = 0;

    if (Nwk_DataRequest(self->nwk, &req, nowMs) == ZB_OK)
        self->tunnelsRelayed++;
    else
        self->tunnelsDropped++;
}

static void apsDoCommandReceive(Aps_Aps *self, const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame,
                                const Aps_Delivery *delivery, uint32_t nowMs)
{
    Aps_KeyIndication *slot;
    Aps_TransportKey body;
    Aps_KeyPolicy policy;
    Aps_KeyReceipt receipt;
    Aps_KeyVerdict verdict;
    ZbStatus status;
    uint32_t commandId;

    (void)nowMs;

    if (delivery->asdu == 0 || delivery->asduLength < APS_FRAME_COMMAND_ID_OCTETS)
    {
        self->rxMalformed++;
        return;
    }

    commandId = delivery->asdu[0];

    if (!ind->securityUsed && Nwk_Security(self->nwk) != 0
        && Nwk_Security(self->nwk)->nwkSecurityLevel != SECURITY_LEVEL_NONE && commandId != APS_TK_COMMAND_ID)
    {
        self->rxShapeRefused++;
        return;
    }

    if (commandId == APS_TCLINK_REQUEST_KEY_ID)
    {
        apsDoRequestKey(self, ind, frame, delivery, nowMs);
        return;
    }

    if (commandId == APS_TCLINK_VERIFY_KEY_ID)
    {
        apsDoVerifyKey(self, ind, frame, delivery, nowMs);
        return;
    }

    if (commandId == APS_TCLINK_CONFIRM_KEY_ID)
    {
        apsDoConfirmKeyTaken(self, ind, frame, delivery, nowMs);
        return;
    }

    if (commandId == APS_CMD_UPDATE_DEVICE)
    {
        apsDoUpdateDevice(self, ind, frame, delivery, nowMs);
        return;
    }

    if (commandId == APS_CMD_REMOVE_DEVICE)
    {
        apsDoRemoveDevice(self, ind, frame, delivery, nowMs);
        return;
    }

    if (commandId == APS_CMD_TUNNEL)
    {
        apsDoTunnelReceive(self, ind, frame, delivery, nowMs);
        return;
    }

    if (commandId != APS_TK_COMMAND_ID)
    {
        self->rxCommandDeferred++;
        return;
    }

    if (Aps_TransportKeyParse(delivery->asdu + APS_FRAME_COMMAND_ID_OCTETS,
                              delivery->asduLength - APS_FRAME_COMMAND_ID_OCTETS, &body) != ZB_OK)
    {
        self->rxMalformed++;
        return;
    }

    apsDoKeyPolicy(self, &policy);

    Zb_memset(&receipt, 0, (uint32_t)sizeof receipt);

    receipt.body = &body;
    receipt.secured = frame->securityEnabled ? 1 : 0;

    if (self->security != 0 && delivery->keyIndex != APS_KEY_INDEX_NONE)
        apsDoKeyPairOf(self, delivery, &receipt);

    receipt.nwkSrc = ind->srcAddr;
    receipt.localIeee = self->security != 0 ? self->security->ownIeee : 0;
    receipt.policy = &policy;

    if (Aps_KeyVerdictFor(&receipt, &verdict) != ZB_OK)
    {
        self->rxMalformed++;
        return;
    }

    if (verdict == APS_KEY_DROP_NOT_TRUST_CENTER)
    {
        self->keyDroppedNotTrustCenter++;
        apsDoCommandAnswer(self, ind, frame, APS_STATUS_SECURITY_FAIL, nowMs);
        return;
    }

    if (verdict == APS_KEY_DROP_POLICY)
    {
        self->keyDroppedPolicy++;
        apsDoCommandAnswer(self, ind, frame, APS_STATUS_SECURITY_FAIL, nowMs);
        return;
    }

    if (verdict == APS_KEY_DROP_UNSECURED_KEY)
    {
        self->keyDroppedUnsecured++;
        apsDoCommandAnswer(self, ind, frame, APS_STATUS_SECURITY_FAIL, nowMs);
        return;
    }

    if (verdict == APS_KEY_DROP_DISTRIBUTED)
    {
        self->keyDroppedDistributed++;
        apsDoCommandAnswer(self, ind, frame, APS_STATUS_SECURITY_FAIL, nowMs);
        return;
    }

    if (verdict == APS_KEY_FORWARD)
    {
        self->keyForwardDeferred++;
        apsDoCommandAnswer(self, ind, frame, APS_STATUS_SUCCESS, nowMs);
        return;
    }

    status = ZB_OK;

    if (body.standardKeyType == APS_TK_TYPE_NETWORK_KEY)
    {
        status = Security_InstallNetworkKey(self->security, body.key, body.keySeqNumber,
                                            policy.joinedAndAuthorized, 1);

        if (status == ZB_OK)
        {
            self->keyInstalled++;

            if (self->security->trustCenterIeee == APS_KEY_IEEE_UNSET)
            {
                self->security->trustCenterIeee = body.sourceIeee;
                Nwk_SetTrustCenter(self->nwk, body.sourceIeee);
            }

            if (receipt.keyPairKnown)
                (void)Security_VerifyKeyPair(self->security, (int)delivery->keyIndex,
                                             delivery->frameCounter);
        }
        else
            self->keyInstallFailed++;
    }
    else if (body.standardKeyType == APS_TK_TYPE_TC_LINK_KEY && self->tcLinkKeyUpdate && !apsDoIsTrustCenter(self)
             && body.sourceIeee == self->security->trustCenterIeee)
    {
        apsDoTcLinkKeyTaken(self, ind->srcAddr, body.key, nowMs);
    }
    else
    {
        self->keyLinkKeyDeferred++;
    }

    if (self->keyIndicationCount >= APS_KEY_INDICATION_MAX)
    {
        self->droppedIndications++;
        return;
    }

    slot = &self->keyIndications[(self->keyIndicationHead + self->keyIndicationCount) % APS_KEY_INDICATION_MAX];

    Zb_memset(slot, 0, (uint32_t)sizeof *slot);

    slot->srcIeee = body.standardKeyType == APS_TK_TYPE_APPLICATION_LINK_KEY ? 0 : body.sourceIeee;

    if (body.standardKeyType == APS_TK_TYPE_APPLICATION_LINK_KEY)
        slot->srcIeee = receipt.keyPairIeee;

    slot->standardKeyType = body.standardKeyType;
    Zb_memcpy(slot->key, body.key, APS_TK_KEY_OCTETS);
    slot->keySeqNumber = body.keySeqNumber;
    slot->partnerIeee = body.partnerIeee;
    slot->initiator = body.initiator;
    slot->status = status == ZB_OK ? APS_STATUS_SUCCESS : APS_STATUS_INVALID_PARAMETER;

    self->keyIndicationCount++;

    apsDoCommandAnswer(self, ind, frame, APS_STATUS_SUCCESS, nowMs);
}

/*
 * One indication, decided in the order 2.2.8.4.2 and 2.2.4.1.3.2 print the questions, one counter per gate
 * (§9.6): the carrier and the codec's two families, the command deferral, the security crossing before any
 * judgement of the frame, this module's own acknowledgement match, duplicate rejection, the delivery mode, the
 * Status, the answer owed, the delivery upward. Each gate counts its own refusal and the frame stops there.
 */
static void apsDoReceive(Aps_Aps *self, const Nwk_DataIndicationParameters *ind, uint32_t nowMs)
{
    Aps_Frame frame;
    Aps_Tx *tx;
    Aps_Delivery delivery;
    uint32_t payloadOffset;
    uint32_t payloadLen;
    uint32_t member;
    uint32_t index;
    uint32_t members;
    ZbStatus parseStatus;
    ZbStatus secureStatus;
    Aps_AckOutcome ackOutcome;

    if (ind->frameType != NWK_FRAME_TYPE_DATA)
    {
        self->rxShapeRefused++;
        return;
    }

    parseStatus = ApsFrame_Parse(ind->nsdu, ind->nsduLength, &frame, &payloadOffset, &payloadLen);

    if (parseStatus == ZB_ERR_UNSUPPORTED)
    {
        self->rxShapeRefused++;
        return;
    }

    if (parseStatus != ZB_OK)
    {
        self->rxMalformed++;
        return;
    }

    Zb_memset(&delivery, 0, (uint32_t)sizeof delivery);

    delivery.asdu = ind->nsdu + payloadOffset;
    delivery.asduLength = payloadLen;
    delivery.status = APS_STATUS_SUCCESS;
    delivery.securityStatus = APS_STATUS_UNSECURED;
    delivery.keyStatus = APS_KEY_STATUS_NONE;
    delivery.keyIndex = APS_KEY_INDEX_NONE;

    if (frame.securityEnabled)
    {
        secureStatus = Aps_RxSecureReceive(self->security, self->nwk, ind, &frame, payloadOffset, ind->nsduLength,
                                           &delivery, self->plainScratch,
                                           (uint32_t)sizeof self->plainScratch);

        if (secureStatus == ZB_ERR_UNSUPPORTED)
        {
            self->rxSecuredDeferred++;
            return;
        }

        if (secureStatus == ZB_ERR_BAD_ARGUMENT)
        {
            self->rxMalformed++;
            return;
        }

        if (secureStatus != ZB_OK)
        {
            if (secureStatus == ZB_ERR_BAD_FRAME_COUNTER)
                self->rxSecuredFailuresCounters++;
            else
                self->rxSecuredFailuresAuth++;
        }
    }

    if (frame.frameType == APS_FRAME_TYPE_COMMAND)
    {
        apsDoCommandReceive(self, ind, &frame, &delivery, nowMs);
        return;
    }

    if (frame.frameType == APS_FRAME_TYPE_ACK)
    {
        if (delivery.status != APS_STATUS_SUCCESS)
            return;

        tx = Aps_AckSlotForAck(self->tx, ind, &frame);

        if (tx == 0)
        {
            self->unmatchedAcks++;
            return;
        }

#if ZB_APS_FRAGMENTATION
        if (tx->fragmented)
        {
            apsDoFragmentedAck(self, tx, &frame, nowMs);
            return;
        }

#endif

        apsDoConfirm(self, tx, ZB_OK, APS_STATUS_SUCCESS);
        return;
    }

    if (delivery.status != APS_STATUS_SECURITY_FAIL
        && Aps_DupSeen(self->dups, ind->srcAddr, frame.apsCounter,
                       frame.blockNumberPresent ? frame.blockNumber : 0, nowMs))
    {
        self->rxDuplicateDrops++;

        ackOutcome = Aps_AckRespond(ind, &frame, APS_STATUS_SUCCESS, self->nwk, self->ackApdu,
                                    (uint32_t)sizeof self->ackApdu, nowMs);

        if (ackOutcome == APS_ACK_RESPONDED)
            self->acksGenerated++;

        if (ackOutcome == APS_ACK_COMPOSE_REFUSED || ackOutcome == APS_ACK_ISSUE_REFUSED)
            self->acksRefused++;

        return;
    }

    if (delivery.status == APS_STATUS_SUCCESS
        && frame.extendedHeaderPresent
        && (frame.fragmentation == APS_FRAG_FIRST || frame.fragmentation == APS_FRAG_SUBSEQUENT))
    {
#if ZB_APS_FRAGMENTATION
        apsDoFragmentReceive(self, ind, &frame, &delivery, nowMs);
        return;
#else
        delivery.status = APS_STATUS_DEFRAG_UNSUPPORTED;
        delivery.asdu = 0;
        delivery.asduLength = 0;
#endif
    }

    ackOutcome = Aps_AckRespond(ind, &frame, delivery.status, self->nwk, self->ackApdu,
                                (uint32_t)sizeof self->ackApdu, nowMs);

    if (ackOutcome == APS_ACK_RESPONDED)
        self->acksGenerated++;

    if (ackOutcome == APS_ACK_COMPOSE_REFUSED || ackOutcome == APS_ACK_ISSUE_REFUSED)
        self->acksRefused++;

    if (frame.deliveryMode == APS_DELIVERY_GROUP)
    {
        members = 0;
        index = 0;

        while (index < APS_GROUP_MAX)
        {
            member = Aps_GroupMemberAt(self->groups, frame.groupAddress, index);

            if (member == APS_NO_GROUP_MEMBER)
                break;

            apsDoIndicate(self, ind, &frame, APS_ADDR_MODE_GROUP, frame.groupAddress,
                          self->groups[member].endpoint, &delivery);

            members++;
            index = member + 1;
        }

        if (members == 0)
        {
            if (self->groupDelivery == APS_GROUP_DELIVERY_MEMBERS)
            {
                self->droppedGroupMiss++;

                return;
            }

            apsDoIndicate(self, ind, &frame, APS_ADDR_MODE_GROUP, frame.groupAddress, APS_ENDPOINT_BROADCAST,
                          &delivery);

            self->groupDeliveredUnfiltered++;

            return;
        }

        return;
    }

    apsDoIndicate(self, ind, &frame, APS_ADDR_MODE_SHORT, ind->dstAddr, frame.dstEndpoint, &delivery);
}


/*
 * What the network layer delivered, one frame at a time and by reference: each is decided before the receive takes
 * the next, and a frame a decision puts back down the seam comes back through the radio, in the *next* turn.
 */
static void apsDoDrainIndications(Aps_Aps *self, uint32_t nowMs)
{
    const Nwk_DataIndicationParameters *ind;

    while ((ind = Nwk_Indication(self->nwk)) != 0)
    {
        apsDoReceive(self, ind, nowMs);
        Nwk_IndicationDone(self->nwk);
    }
}

/*
 * The slots whose wait has ended: one attempt is one transmission plus one wait, so 1 + apscMaxFrameRetries
 * transmissions bound a transaction, each one the stored APDU re-offered with its own APS counter and a fresh
 * protection (2.2.8.4.4, 3.3.1.5). A refusal the layer below's full pool caused keeps the wait.
 */
static void apsDoRetransmissions(Aps_Aps *self, uint32_t nowMs)
{
    Aps_Tx *tx;
    uint32_t i;
    ZbStatus status;

    for (i = 0; i < APS_TX_MAX; i++)
    {
        tx = &self->tx[i];

        if (tx->state != APS_TX_AWAITING_ACK)
            continue;

        if (!Zb_timeReached(nowMs, tx->ackDeadlineMs))
            continue;

        if (tx->attempts < APS_MAX_FRAME_RETRIES + 1)
        {
            if (tx->apsSecurity)
            {
                status = Aps_TxProtect(self->security, tx, self->secureScratch,
                                       (uint32_t)sizeof self->secureScratch);

                if (status != ZB_OK)
                {
                    self->txSecuredFailures++;
                    apsDoConfirm(self, tx, ZB_OK, APS_STATUS_SECURITY_FAIL);
                    continue;
                }
            }

            status = Aps_TxIssue(tx, self->nwk, self->secureScratch, nowMs);

            if (status == ZB_OK)
                continue;

            if (status == ZB_ERR_NO_SPACE)
            {
                self->retransmitRefusals++;
                continue;
            }

            apsDoConfirm(self, tx, status, APS_STATUS_LAST_SEAM_STATUS);

            continue;
        }

        apsDoConfirm(self, tx, ZB_ERR_TIMEOUT, APS_STATUS_NO_ACK);
    }
}

ZbStatus Aps_Init(Aps_Aps *self, Nwk_Nwk *nwk)
{
    if (self == 0 || nwk == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(self, 0, (uint32_t)sizeof *self);

    self->nwk = nwk;
    self->apsCounter = APS_COUNTER_START;
    self->allowTcLinkKeyRequests = 1;

    return ZB_OK;
}

/* Keep the pointer and nothing else: the keys, the pairs and both families of counters stay the caller's,
   read at the moment of an attempt, which is what lets an application rotate a link key under
   a running stack. A 0 is the unsecured device put back, and a 0x01 ask answered 2.2.4.1.1.3's own word. */
void Aps_AttachSecurity(Aps_Aps *self, Security *security)
{
    if (self == 0)
        return;

    self->security = security;
}

/* One APSDE-DATA.request: the parameters Table 2-2 prints are checked at this door, the transaction is taken back
   and answered through the ring. Table 2-2's 0x02 is not stored here: 4.2.2 gives the carrier's protection to the
   network, and `Aps_TxIssue` reads that network's own state, so a key-less network composes the frame unsecured. */
/* A mode-0x03 destination is mapped through Table 3-66's nwkAddressMap first, and the confirmation is
   NO_SHORT_ADDRESS when the map holds no row for it. A device that is not part of a network discards the request and
   tells the layer that asked, with Table 2-29's own ILLEGAL_REQUEST because the clause names no APS status. And an
   ASDU no single frame holds is split when the request is an acknowledged unicast asking for fragmentation, its
   blocks going one window at a time until the last is acknowledged. */
static ZbStatus apsDoRequest(Aps_Aps *self, const Aps_ApsdeReq *req, uint32_t nowMs)
{
    Aps_Tx *tx;
    uint32_t deliveryMode;
    uint16_t nwkDst;
    int keyPairIndex = -1;      
    ZbStatus status;

    if (self == 0 || req == 0 || self->nwk == 0)
        return ZB_ERR_BAD_ARGUMENT;


    if (req->asdu == 0 && req->asduLength != 0)
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;     
    }

    if (req->asduLength > APS_ASDU_LENGTH_MAX)
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;     
    }

    if (req->txOptions > APS_TX_OPTIONS_MAX)
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;     
    }

    if (req->dstAddrMode > APS_ADDR_MODE_MAX)
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;     
    }

    if (req->srcEndpoint > APS_SRC_ENDPOINT_MAX)
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;     
    }

    deliveryMode = Aps_TxDeliveryMode(req);
    nwkDst = Aps_TxNwkDestination(req);

    if (req->dstAddrMode == APS_ADDR_MODE_SHORT && Nwk_AddrIsReserved(req->dstAddress))
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;     
    }

    if (req->dstAddrMode == APS_ADDR_MODE_GROUP)
    {
        if (req->nwkBroadcastAddress != 0
            && req->nwkBroadcastAddress < APS_BROADCAST_ADDRESS_MIN)
        {
            self->refusedRequests++;
            return ZB_ERR_BAD_ARGUMENT;
        }
    }

    if ((req->txOptions & APS_TX_OPTION_ACK) != 0 && deliveryMode != APS_DELIVERY_UNICAST)
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;     
    }

    if ((req->txOptions & APS_TX_OPTION_SECURITY) != 0 && deliveryMode != APS_DELIVERY_UNICAST)
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;     
    }


    if (req->dstAddrMode == APS_ADDR_MODE_NONE)
    {
        if (!apsDoRequestConfirm(self, req, ZB_OK, APS_STATUS_NOT_SUPPORTED))
            return ZB_ERR_NO_SPACE;

        return ZB_OK;       
    }

    if (self->nwk != 0 && !Nwk_IsPartOfNetwork(self->nwk))
    {
        if (!apsDoRequestConfirm(self, req, ZB_OK, APS_STATUS_ILLEGAL_REQUEST))
            return ZB_ERR_NO_SPACE;

        return ZB_OK;
    }

    if ((req->dstAddrMode == APS_ADDR_MODE_SHORT && req->dstAddress == Nwk_OwnAddress(self->nwk))
        || (req->dstAddrMode == APS_ADDR_MODE_EXTENDED && req->dstExtendedAddress == Nwk_OwnExtendedAddress(self->nwk)))
        return apsDoLoopback(self, req);

    if (req->dstAddrMode == APS_ADDR_MODE_EXTENDED)
    {
        uint16_t resolved = 0;

        if (self->nwk != 0 && Nwk_AddressOfIeee(self->nwk, req->dstExtendedAddress, &resolved))
        {
            Aps_ApsdeReq mapped = *req;

            mapped.dstAddrMode = APS_ADDR_MODE_SHORT;
            mapped.dstAddress = resolved;

            return Aps_DataRequest(self, &mapped, nowMs);
        }

        if (!apsDoRequestConfirm(self, req, ZB_OK, APS_STATUS_NO_SHORT_ADDRESS))
            return ZB_ERR_NO_SPACE;

        return ZB_OK;
    }

    if (req->useAlias)
    {
        if (!apsDoRequestConfirm(self, req, ZB_OK, APS_STATUS_NOT_SUPPORTED))
            return ZB_ERR_NO_SPACE;

        return ZB_OK;
    }

    if ((req->txOptions & APS_TX_OPTION_SECURITY) != 0)
    {
        keyPairIndex = Aps_TxResolveKeyPair(self->security, req);

        if (self->security == 0)
        {
            if (!apsDoRequestConfirm(self, req, ZB_OK, APS_STATUS_SECURITY_FAIL))
                return ZB_ERR_NO_SPACE;

            self->txSecuredFailures++;

            return ZB_OK;       
        }

        if (keyPairIndex < 0)
        {
            if (!apsDoRequestConfirm(self, req, ZB_OK, APS_STATUS_SECURITY_FAIL))
                return ZB_ERR_NO_SPACE;

            self->txNoKeyPair++;

            return ZB_OK;       
        }
    }

    if (req->asduLength > APS_ASDU_MAX)
    {
        if (!apsDoRequestConfirm(self, req, ZB_OK, APS_STATUS_ASDU_TOO_LONG))
            return ZB_ERR_NO_SPACE;

        return ZB_OK;       
    }


    if (Aps_TxOccupied(self->tx) + self->confirmCount >= APS_CONFIRM_MAX)
    {
        self->refusedRequests++;
        return ZB_ERR_NO_SPACE;
    }

    tx = Aps_TxFree(self->tx);

    if (tx == 0)
    {
        self->refusedRequests++;
        return ZB_ERR_NO_SPACE;
    }


    Zb_memset(tx, 0, (uint32_t)sizeof *tx);

    tx->state = APS_TX_AWAITING_NLDE;
    tx->dstAddrMode = req->dstAddrMode;
    tx->dstAddress = req->dstAddress;
    tx->dstExtendedAddress = req->dstExtendedAddress;
    tx->dstEndpoint = req->dstEndpoint;
    tx->srcEndpoint = req->srcEndpoint;
    tx->profileId = req->profileId;
    tx->clusterId = req->clusterId;
    tx->deliveryMode = deliveryMode;
    tx->nwkDst = nwkDst;
    tx->apsCounter = (uint8_t)self->apsCounter;
    tx->tag = req->tag;
    tx->ackRequested = (req->txOptions & APS_TX_OPTION_ACK) != 0 && deliveryMode == APS_DELIVERY_UNICAST ? 1 : 0;
    tx->apsSecurity = (req->txOptions & APS_TX_OPTION_SECURITY) != 0 ? 1 : 0;
    tx->extendedNonce = (req->txOptions & APS_TX_OPTION_EXTENDED_NONCE) != 0 ? 1 : 0;
    tx->keyPairIndex = keyPairIndex;
    tx->keyIdentifier = SECURITY_KEY_ID_DATA;
    tx->confirmOwed = 1;
    tx->nwkSecurity = 1;
    tx->securedLen = 0;
    tx->radiusCounter = req->radiusCounter;
    tx->useAlias = req->useAlias ? 1 : 0;
    tx->aliasSrcAddr = req->aliasSrcAddr;
    tx->aliasSeqNumb = req->aliasSeqNumb;
    tx->lastHandle = RADIO_HANDLE_NONE;

    self->apsCounter = (self->apsCounter + 1) % APS_COUNTER_WRAP;

    status = Aps_TxCompose(tx, req);

#if ZB_APS_FRAGMENTATION
    if (status == ZB_ERR_NO_SPACE && (req->txOptions & APS_TX_OPTION_FRAGMENT) != 0
        && tx->ackRequested && req->asduLength <= (uint32_t)APS_FRAG_MAX_ASDU)
    {
        tx->fragCapacity = (uint8_t)Aps_TxBlockCapacity(tx);
        tx->fragTotal = (uint8_t)Aps_FragBlockCount(req->asduLength, tx->fragCapacity);

        if (tx->fragTotal >= 2)
        {
            tx->fragmented = 1;
            tx->fragIndex = 0;
            tx->fragAsduLength = req->asduLength;
            Zb_memcpy(tx->fragAsdu, req->asdu, req->asduLength);

            status = Aps_TxComposeBlock(tx);
        }
    }

#endif

    if (status != ZB_OK)
    {
        Zb_memset(tx, 0, (uint32_t)sizeof *tx);
        self->refusedRequests++;

        return status;
    }

    if (tx->apsSecurity)
    {
        status = Aps_TxProtect(self->security, tx, self->secureScratch,
                               (uint32_t)sizeof self->secureScratch);

        if (status != ZB_OK)
        {
            self->txSecuredFailures++;
            apsDoConfirm(self, tx, ZB_OK, APS_STATUS_SECURITY_FAIL);

            return ZB_OK;
        }
    }

    status = Aps_TxIssue(tx, self->nwk, self->secureScratch, nowMs);

    if (status != ZB_OK)
    {
        Zb_memset(tx, 0, (uint32_t)sizeof *tx);
        self->refusedRequests++;

        return status;
    }

    return ZB_OK;
}

void Aps_SetBindings(Aps_Aps *self, Aps_Binding *bindings)
{
    if (self == 0)
        return;

    self->bindings = bindings;
}

/* 2.2.4.3.1.3 and 2.2.4.3.3.3: a device not joined to a network, one that keeps no binding table, and a request
   whose parameters are out of range all get ILLEGAL_REQUEST; the table itself answers the rest. */
uint32_t Aps_BindRequest(Aps_Aps *self, const Aps_Binding *entry, int add)
{
    if (self == 0 || self->bindings == 0 || entry == 0)
        return APS_BIND_ILLEGAL;

    if (!Nwk_IsPartOfNetwork(self->nwk))
        return APS_BIND_ILLEGAL;

    if (Aps_BindCheck(entry) != ZB_OK)
        return APS_BIND_ILLEGAL;

    return add != 0 ? Aps_BindAdd(self->bindings, entry) : Aps_BindRemove(self->bindings, entry);
}

const Aps_Binding *Aps_BindingPool(const Aps_Aps *self)
{
    return self != 0 ? self->bindings : 0;
}

/* A destination mode of 0x00 is not an address but a search of the binding table, and every entry it finds is a
   request of its own. */
ZbStatus Aps_DataRequest(Aps_Aps *self, const Aps_ApsdeReq *req, uint32_t nowMs)
{
    if (self == 0 || req == 0 || self->nwk == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (req->dstAddrMode == APS_ADDR_MODE_NONE)
        return apsDoBoundRequest(self, req, nowMs);

    return apsDoRequest(self, req, nowMs);
}

ZbStatus Aps_Step(Aps_Aps *self, uint32_t nowMs)
{
    ZbStatus status;

    if (self == 0 || self->nwk == 0)
        return ZB_ERR_BAD_ARGUMENT;

    status = Nwk_Step(self->nwk, nowMs);

    apsDoDrainConfirms(self, nowMs);

    apsDoDrainIndications(self, nowMs);

    apsDoDrainConfirms(self, nowMs);

    apsDoRetransmissions(self, nowMs);

    return status;
}

uint32_t Aps_PollConfirms(Aps_Aps *self, Aps_Confirm *out, uint32_t max)
{
    uint32_t taken = 0;

    if (self == 0 || out == 0 || max == 0)
        return 0;

    while (taken < max && self->confirmCount > 0)
    {
        out[taken] = self->confirms[self->confirmHead];
        self->confirmHead = (self->confirmHead + 1) % APS_CONFIRM_MAX;
        self->confirmCount--;
        taken++;
    }

    return taken;
}

uint32_t Aps_PollIndications(Aps_Aps *self, Aps_Indication *out, uint32_t max)
{
    uint32_t taken = 0;

    if (self == 0 || out == 0 || max == 0)
        return 0;

    while (taken < max && self->indicationCount > 0)
    {
        out[taken] = self->indications[self->indicationHead];
        self->indicationHead = (self->indicationHead + 1) % APS_INDICATION_MAX;
        self->indicationCount--;
        taken++;
    }

    return taken;
}

/*
 * APSME-ADD-GROUP.request (2.2.4.5.1), answered in place: the Status Table 2-15 prints *is* the return value.
 * Only the printed endpoint range is judged (0x00 is the ZDO and 0xff names every endpoint rather than a
 * member) and `GroupAddress` is never refused for its value, Table 2-14 printing every uint16_t and Table
 * 3-80's Reserved band being no thing a group id has. The "not implemented on the current device" half of
 * 2.2.4.5.1.3 needs the endpoint registry of the layer above, which band A has not built.
 */
uint32_t Aps_AddGroup(Aps_Aps *self, uint16_t groupAddress, uint8_t endpoint)
{
    uint32_t status;

    if (self == 0)
        return APS_STATUS_INVALID_PARAMETER;      

    if (endpoint < APS_GROUP_ENDPOINT_FIRST || endpoint > APS_GROUP_ENDPOINT_LAST)
    {
        self->groupRefusals++;
        return APS_STATUS_INVALID_PARAMETER;      
    }

    status = Aps_GroupAdd(self->groups, groupAddress, endpoint);

    if (status == APS_STATUS_TABLE_FULL)
        self->groupRefusals++;      

    return status;
}

/*
 * APSME-REMOVE-GROUP.request (2.2.4.5.3): the same parameter judgement from Table 2-16, and 2.2.4.5.3.3
 * deciding the rest, SUCCESS for the pair removed, INVALID_GROUP for the pair the table does not hold. One
 * pair and not one group: Table 2-25's entry is a group with a *list* of endpoints, and these primitives name
 * one endpoint each.
 */
uint32_t Aps_RemoveGroup(Aps_Aps *self, uint16_t groupAddress, uint8_t endpoint)
{
    if (self == 0)
        return APS_STATUS_INVALID_PARAMETER;

    if (endpoint < APS_GROUP_ENDPOINT_FIRST || endpoint > APS_GROUP_ENDPOINT_LAST)
    {
        self->groupRefusals++;
        return APS_STATUS_INVALID_PARAMETER;      
    }

    return Aps_GroupRemove(self->groups, groupAddress, endpoint);
}

/*
 * APSME-REMOVE-ALL-GROUPS.request (2.2.4.5.5): the parameter is judged from Table 2-18's range, then every
 * pair carrying the endpoint goes. 2.2.4.5.5.3 asks for the endpoint's memberships and not for a match, so
 * SUCCESS answers an endpoint that belonged to nothing and INVALID_GROUP is not a status this primitive has.
 */
uint32_t Aps_RemoveAllGroups(Aps_Aps *self, uint8_t endpoint)
{
    if (self == 0)
        return APS_STATUS_INVALID_PARAMETER;

    if (endpoint < APS_GROUP_ENDPOINT_FIRST || endpoint > APS_GROUP_ENDPOINT_LAST)
    {
        self->groupRefusals++;
        return APS_STATUS_INVALID_PARAMETER;      
    }

    return Aps_GroupRemoveAll(self->groups, endpoint);
}

uint32_t Aps_TransmitQueue(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return Aps_TxOccupied(self->tx);
}

uint32_t Aps_ConfirmQueue(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->confirmCount;
}

uint32_t Aps_RefusedRequests(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->refusedRequests;
}

uint32_t Aps_UnmatchedAcks(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->unmatchedAcks;
}

uint32_t Aps_ConfirmationsIgnored(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->confirmsIgnored;
}

uint32_t Aps_RetransmitRefusals(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->retransmitRefusals;
}

uint32_t Aps_IndicationQueue(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->indicationCount;
}

uint32_t Aps_GroupQueue(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return Aps_GroupCount(self->groups);
}

uint32_t Aps_RxShapeRefused(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->rxShapeRefused;
}

uint32_t Aps_RxMalformed(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->rxMalformed;
}

uint32_t Aps_RxSecuredDeferred(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->rxSecuredDeferred;
}

uint32_t Aps_RxCommandDeferred(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->rxCommandDeferred;
}

uint32_t Aps_RxDuplicateDrops(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->rxDuplicateDrops;
}

uint32_t Aps_GroupDeliveredUnfiltered(const Aps_Aps *self)
{
    return self != 0 ? self->groupDeliveredUnfiltered : 0;
}

/* 2.2.8.4.2 delivers per associated endpoint; with no member this stack delivers once at the broadcast endpoint
   when the application asks for it, which is a departure the register records. */
void Aps_SetGroupDelivery(Aps_Aps *self, uint32_t mode)
{
    if (self == 0)
        return;

    self->groupDelivery = mode <= APS_GROUP_DELIVERY_ENDPOINTS ? mode : APS_GROUP_DELIVERY_MEMBERS;
}

uint32_t Aps_GroupDelivery(const Aps_Aps *self)
{
    return self != 0 ? self->groupDelivery : APS_GROUP_DELIVERY_MEMBERS;
}

uint32_t Aps_DroppedGroupMiss(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->droppedGroupMiss;
}

uint32_t Aps_AcksGenerated(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->acksGenerated;
}

uint32_t Aps_AcksRefused(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->acksRefused;
}

uint32_t Aps_DroppedIndications(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->droppedIndications;
}

uint32_t Aps_Loopbacks(const Aps_Aps *self)
{
    return self != 0 ? self->loopbacks : 0;
}

uint32_t Aps_GroupRefusals(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->groupRefusals;
}

uint32_t Aps_TxNoKeyPair(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->txNoKeyPair;
}

uint32_t Aps_TxSecuredFailures(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->txSecuredFailures;
}

uint32_t Aps_RxSecuredFailuresAuth(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->rxSecuredFailuresAuth;
}

uint32_t Aps_RxSecuredFailuresCounters(const Aps_Aps *self)
{
    if (self == 0)
        return 0;

    return self->rxSecuredFailuresCounters;
}

/* One APS command of this module's own, its identifier first in `payload`: a unicast transaction asking for an
   acknowledgement, protected with the pair's data key and the extended nonce where `pairIndex` names one, in clear
   at the APS layer where it is -1, and protected at the network layer either way. */
static ZbStatus apsDoCommandSend(Aps_Aps *self, uint16_t nwkDst, uint64_t destIeee, const uint8_t *payload,
                                 uint32_t payloadLen, int pairIndex, uint32_t nowMs)
{
    Aps_Frame frame;
    Aps_Tx *tx;
    uint32_t apduLen;
    uint32_t headerLen;
    ZbStatus status;

    tx = Aps_TxFree(self->tx);

    if (tx == 0)
    {
        self->refusedRequests++;
        return ZB_ERR_NO_SPACE;
    }

    Zb_memset(tx, 0, (uint32_t)sizeof *tx);
    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = APS_FRAME_TYPE_COMMAND;
    frame.deliveryMode = APS_DELIVERY_UNICAST;
    frame.ackRequest = 1;
    frame.securityEnabled = pairIndex >= 0 ? 1 : 0;
    frame.apsCounter = (uint8_t)self->apsCounter;

    status = ApsFrame_Compose(&frame, payload, payloadLen, tx->apdu, (uint32_t)sizeof tx->apdu, &apduLen, &headerLen);

    if (status != ZB_OK)
    {
        Zb_memset(tx, 0, (uint32_t)sizeof *tx);
        self->refusedRequests++;
        return status;
    }

    tx->state = APS_TX_AWAITING_NLDE;
    tx->dstAddrMode = APS_ADDR_MODE_EXTENDED;
    tx->dstAddress = nwkDst;
    tx->dstExtendedAddress = destIeee;
    tx->deliveryMode = APS_DELIVERY_UNICAST;
    tx->nwkDst = nwkDst;
    tx->apsCounter = frame.apsCounter;
    tx->ackRequested = 1;
    tx->apsSecurity = frame.securityEnabled;
    tx->extendedNonce = 1;
    tx->keyPairIndex = pairIndex;
    tx->keyIdentifier = SECURITY_KEY_ID_DATA;
    tx->confirmOwed = 0;
    tx->nwkSecurity = 1;
    tx->lastHandle = RADIO_HANDLE_NONE;
    tx->apduLen = apduLen;
    tx->apduHeaderLen = headerLen;

    self->apsCounter = (self->apsCounter + 1) % APS_COUNTER_WRAP;

    if (tx->apsSecurity)
        status = Aps_TxProtect(self->security, tx, self->secureScratch, (uint32_t)sizeof self->secureScratch);

    if (status != ZB_OK)
    {
        Zb_memset(tx, 0, (uint32_t)sizeof *tx);
        self->txSecuredFailures++;
        return status;
    }

    status = Aps_TxIssue(tx, self->nwk, self->secureScratch, nowMs);

    if (status != ZB_OK)
    {
        Zb_memset(tx, 0, (uint32_t)sizeof *tx);
        self->refusedRequests++;
        return status;
    }

    tx->state = APS_TX_AWAITING_NLDE;

    return ZB_OK;
}

void Aps_SetTcLinkKeyUpdate(Aps_Aps *self, int update)
{
    if (self != 0)
        self->tcLinkKeyUpdate = update ? 1 : 0;
}

ZbStatus Aps_RequestTcLinkKey(Aps_Aps *self, uint32_t nowMs)
{
    uint8_t payload[1 + APS_TCLINK_REQUEST_TC_OCTETS];
    uint64_t trustCenter;
    uint16_t address = 0x0000;
    uint32_t len;
    ZbStatus status;

    if (self == 0 || self->security == 0)
        return ZB_ERR_BAD_ARGUMENT;

    trustCenter = self->security->trustCenterIeee;

    if (trustCenter == 0 || trustCenter == 0xffffffffffffffff || apsDoIsTrustCenter(self))
        return ZB_ERR_BAD_STATE;

    (void)Nwk_AddressOfIeee(self->nwk, trustCenter, &address);

    status = Aps_RequestKeyCompose(APS_TCLINK_REQUEST_TC_LINK_KEY, payload, (uint32_t)sizeof payload, &len);

    if (status == ZB_OK)
        status = apsDoCommandSend(self, address, trustCenter, payload, len,
                                  Security_FindKeyPairByIeee(self->security, trustCenter), nowMs);

    if (status != ZB_OK)
        return status;

    self->tcLinkKeyRequestsSent++;
    self->tcLinkKeyState = APS_TCLK_REQUESTED;

    return ZB_OK;
}

void Aps_TcLinkKeyAbandon(Aps_Aps *self)
{
    int index;

    if (self == 0 || self->security == 0)
        return;

    index = apsDoUniquePairOf(self, self->security->trustCenterIeee);

    if (index >= 0 && self->security->keyPairs[index].keyAttributes == SECURITY_KEYPAIR_ATTR_UNVERIFIED)
        (void)Security_ForgetLinkKey(self->security, self->security->trustCenterIeee);

    self->tcLinkKeysAbandoned++;
    self->tcLinkKeyState = APS_TCLK_ABANDONED;
}

uint32_t Aps_TcLinkKeyState(const Aps_Aps *self)
{
    return self != 0 ? self->tcLinkKeyState : APS_TCLK_NONE;
}

uint32_t Aps_TcLinkKeyRequestsSent(const Aps_Aps *self)
{
    return self != 0 ? self->tcLinkKeyRequestsSent : 0;
}

uint32_t Aps_TcLinkKeysVerified(const Aps_Aps *self)
{
    return self != 0 ? self->tcLinkKeysVerified : 0;
}

uint32_t Aps_TcLinkKeysAbandoned(const Aps_Aps *self)
{
    return self != 0 ? self->tcLinkKeysAbandoned : 0;
}

void Aps_SetAllowTcLinkKeyRequests(Aps_Aps *self, uint32_t allow)
{
    if (self != 0 && allow <= 2)
        self->allowTcLinkKeyRequests = allow;
}

uint32_t Aps_TcLinkKeysSent(const Aps_Aps *self)
{
    return self != 0 ? self->tcLinkKeysSent : 0;
}

uint32_t Aps_TcLinkKeyRequestsDropped(const Aps_Aps *self)
{
    return self != 0 ? self->tcLinkKeyRequestsDropped : 0;
}

uint32_t Aps_VerifyKeysConfirmed(const Aps_Aps *self)
{
    return self != 0 ? self->verifyKeysConfirmed : 0;
}

uint32_t Aps_VerifyKeysRefused(const Aps_Aps *self)
{
    return self != 0 ? self->verifyKeysRefused : 0;
}

uint32_t Aps_CommandAnswers(const Aps_Aps *self)
{
    return self->commandAnswers;
}

uint32_t Aps_CommandFailures(const Aps_Aps *self)
{
    return self->commandFailures;
}

ZbStatus Aps_TransportKeyRequest(Aps_Aps *self, const Aps_TransportKeyReq *req, uint32_t nowMs)
{
    int pairIndex;

    if (self == 0 || req == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->security == 0)
    {
        self->refusedRequests++;
        return ZB_ERR_AUTH;
    }

    pairIndex = Security_FindKeyPairByIeee(self->security, req->destIeee);

    if (pairIndex < 0)
    {
        self->refusedRequests++;
        return ZB_ERR_NOT_FOUND;
    }

    return apsDoTransportKey(self, req, pairIndex, nowMs);
}

/* The slot's secured command rewritten as the Tunnel that carries it to the parent: an unsecured command of its own,
   with its own counter, acknowledged by the parent and protected by the network layer, so a retry resends the same
   Tunnel and the frame inside it is never secured twice. */
static ZbStatus apsDoTunnel(Aps_Aps *self, Aps_Tx *tx, const Aps_TransportKeyReq *req)
{
    Aps_Frame frame;
    uint8_t payload[APS_FRAME_MAX];
    uint32_t payloadLen = 0;
    uint32_t apduLen = 0;
    uint32_t headerLen = 0;
    ZbStatus status;

    status = Aps_TunnelCompose(req->destIeee, self->secureScratch, tx->securedLen, payload, (uint32_t)sizeof payload,
                               &payloadLen);

    if (status != ZB_OK)
        return status;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = APS_FRAME_TYPE_COMMAND;
    frame.deliveryMode = APS_DELIVERY_UNICAST;
    frame.ackRequest = 1;
    frame.apsCounter = (uint8_t)self->apsCounter;

    status = ApsFrame_Compose(&frame, payload, payloadLen, tx->apdu, (uint32_t)sizeof tx->apdu, &apduLen, &headerLen);

    if (status != ZB_OK)
        return status;

    self->apsCounter = (self->apsCounter + 1) % APS_COUNTER_WRAP;

    tx->apsCounter = frame.apsCounter;
    tx->apduLen = apduLen;
    tx->apduHeaderLen = headerLen;
    tx->apsSecurity = 0;
    tx->extendedNonce = 0;
    tx->nwkSecurity = 1;
    tx->nwkDst = req->tunnelNwk;
    tx->dstAddress = req->tunnelNwk;
    tx->dstExtendedAddress = req->tunnelIeee;

    return ZB_OK;
}

/* The door's transaction under a pair the caller resolved: a trust centre's new link key goes out under the key the
   device holds now, which is not the entry about to be written for it (D-218). */
static ZbStatus apsDoTransportKey(Aps_Aps *self, const Aps_TransportKeyReq *req, int pairIndex, uint32_t nowMs)
{
    Aps_Tx *tx;
    uint32_t keyIdentifier;
    uint32_t apduLen;
    uint32_t headerLen;
    ZbStatus status;

    keyIdentifier = Aps_TransportKeyIdentifier(req->standardKeyType);

    if (keyIdentifier == SECURITY_KEY_ID_DATA)
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;
    }

    tx = Aps_TxFree(self->tx);

    if (tx == 0)
    {
        self->refusedRequests++;
        return ZB_ERR_NO_SPACE;
    }

    Zb_memset(tx, 0, (uint32_t)sizeof *tx);

    tx->state = APS_TX_AWAITING_NLDE;
    tx->dstAddrMode = APS_ADDR_MODE_EXTENDED;
    tx->dstAddress = req->nwkDst;
    tx->dstExtendedAddress = req->destIeee;
    tx->deliveryMode = APS_DELIVERY_UNICAST;
    tx->nwkDst = req->nwkDst;
    tx->apsCounter = (uint8_t)self->apsCounter;
    tx->ackRequested = 1;
    tx->apsSecurity = 1;
    tx->extendedNonce = 1;
    tx->keyPairIndex = pairIndex;
    tx->keyIdentifier = keyIdentifier;
    tx->confirmOwed = 0;
    tx->nwkSecurity = req->standardKeyType == APS_TK_TYPE_NETWORK_KEY ? 0 : 1;
    tx->radiusCounter = req->radiusCounter;
    tx->lastHandle = RADIO_HANDLE_NONE;

    self->apsCounter = (self->apsCounter + 1) % APS_COUNTER_WRAP;

    status = Aps_TransportKeyComposeFrame(req, self->security->ownIeee, tx->apsCounter, 1, tx->apdu,
                                          (uint32_t)sizeof tx->apdu, &apduLen, &headerLen);

    if (status != ZB_OK)
    {
        Zb_memset(tx, 0, (uint32_t)sizeof *tx);
        self->refusedRequests++;

        return status;
    }

    tx->apduLen = apduLen;
    tx->apduHeaderLen = headerLen;

    status = Aps_TxProtect(self->security, tx, self->secureScratch, (uint32_t)sizeof self->secureScratch);

    if (status != ZB_OK)
    {
        Zb_memset(tx, 0, (uint32_t)sizeof *tx);
        self->txSecuredFailures++;

        return status;
    }

    if (req->tunnel && apsDoTunnel(self, tx, req) != ZB_OK)
    {
        Zb_memset(tx, 0, (uint32_t)sizeof *tx);
        self->refusedRequests++;

        return ZB_ERR_NO_SPACE;
    }

    status = Aps_TxIssue(tx, self->nwk, self->secureScratch, nowMs);

    if (status != ZB_OK)
    {
        Zb_memset(tx, 0, (uint32_t)sizeof *tx);
        self->refusedRequests++;

        return status;
    }

    return ZB_OK;
}

ZbStatus Aps_UpdateDeviceRequest(Aps_Aps *self, const Aps_UpdateDeviceReq *req, uint32_t nowMs)
{
    Aps_UpdateDeviceIndication indication;

    (void)nowMs;

    if (self == 0 || req == 0 || self->security == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (req->status > APS_UPDATE_DEVICE_TC_REJOIN)
        return ZB_ERR_BAD_ARGUMENT;

    if (!apsDoIsTrustCenter(self))
        return apsDoUpdateDeviceSend(self, req, nowMs);

    Zb_memset(&indication, 0, (uint32_t)sizeof indication);

    indication.srcIeee = self->security->ownIeee;
    indication.srcAddress = Nwk_OwnAddress(self->nwk);
    indication.deviceIeee = req->deviceIeee;
    indication.deviceShortAddress = req->deviceShortAddress;
    indication.status = req->status;

    return apsDoUpdateDevicePush(self, &indication);
}

uint32_t Aps_PollUpdateDeviceIndications(Aps_Aps *self, Aps_UpdateDeviceIndication *out, uint32_t max)
{
    uint32_t taken;

    if (self == 0 || out == 0)
        return 0;

    for (taken = 0; taken < max && self->updateDeviceCount != 0; taken++)
    {
        out[taken] = self->updateDevices[self->updateDeviceHead];

        self->updateDeviceHead = (self->updateDeviceHead + 1) % APS_UPDATE_DEVICE_INDICATION_MAX;
        self->updateDeviceCount--;
    }

    return taken;
}

uint32_t Aps_UpdateDevicesIndicated(const Aps_Aps *self)
{
    return self != 0 ? self->updateDevicesIndicated : 0;
}

uint32_t Aps_UpdateDevicesIgnored(const Aps_Aps *self)
{
    return self != 0 ? self->updateDevicesIgnored : 0;
}

uint32_t Aps_UpdateDevicesRefused(const Aps_Aps *self)
{
    return self != 0 ? self->updateDevicesRefused : 0;
}

uint32_t Aps_UpdateDevicesRepeated(const Aps_Aps *self)
{
    return self != 0 ? self->updateDevicesRepeated : 0;
}

uint32_t Aps_UpdateDevicesDropped(const Aps_Aps *self)
{
    return self != 0 ? self->updateDevicesDropped : 0;
}

uint32_t Aps_UpdateDevicesSent(const Aps_Aps *self)
{
    return self != 0 ? self->updateDevicesSent : 0;
}

uint32_t Aps_TunnelsRelayed(const Aps_Aps *self)
{
    return self != 0 ? self->tunnelsRelayed : 0;
}

uint32_t Aps_TunnelsDropped(const Aps_Aps *self)
{
    return self != 0 ? self->tunnelsDropped : 0;
}

ZbStatus Aps_RemoveDeviceRequest(Aps_Aps *self, const Aps_RemoveDeviceReq *req, uint32_t nowMs)
{
    uint8_t payload[APS_FRAME_COMMAND_ID_OCTETS + APS_REMOVE_DEVICE_OCTETS];
    uint32_t payloadLen = 0;
    ZbStatus status;
    int pairIndex;

    if (self == 0 || req == 0 || self->security == 0 || req->parentIeee == 0 || req->targetIeee == 0)
        return ZB_ERR_BAD_ARGUMENT;

    pairIndex = Security_FindKeyPairByIeee(self->security, req->parentIeee);

    if (Security_KeyPairAt(self->security, pairIndex) == 0)
        return ZB_ERR_NOT_FOUND;

    status = Aps_RemoveDeviceCompose(req->targetIeee, payload, (uint32_t)sizeof payload, &payloadLen);

    if (status != ZB_OK)
        return status;

    status = apsDoCommandSend(self, req->parentNwk, req->parentIeee, payload, payloadLen, pairIndex, nowMs);

    if (status == ZB_OK)
        self->removeDevicesSent++;

    return status;
}

uint32_t Aps_PollRemoveDeviceIndications(Aps_Aps *self, Aps_RemoveDeviceIndication *out, uint32_t max)
{
    uint32_t taken;

    if (self == 0 || out == 0)
        return 0;

    for (taken = 0; taken < max && self->removeDeviceCount != 0; taken++)
    {
        out[taken] = self->removeDevices[self->removeDeviceHead];

        self->removeDeviceHead = (self->removeDeviceHead + 1) % APS_REMOVE_DEVICE_INDICATION_MAX;
        self->removeDeviceCount--;
    }

    return taken;
}

uint32_t Aps_RemoveDevicesSent(const Aps_Aps *self)
{
    return self != 0 ? self->removeDevicesSent : 0;
}

uint32_t Aps_RemoveDevicesIndicated(const Aps_Aps *self)
{
    return self != 0 ? self->removeDevicesIndicated : 0;
}

uint32_t Aps_RemoveDevicesRefused(const Aps_Aps *self)
{
    return self != 0 ? self->removeDevicesRefused : 0;
}

uint32_t Aps_RemoveDevicesDropped(const Aps_Aps *self)
{
    return self != 0 ? self->removeDevicesDropped : 0;
}

uint32_t Aps_PollKeyIndications(Aps_Aps *self, Aps_KeyIndication *out, uint32_t max)
{
    uint32_t taken;

    if (self == 0 || out == 0)
        return 0;

    for (taken = 0; taken < max && self->keyIndicationCount != 0; taken++)
    {
        out[taken] = self->keyIndications[self->keyIndicationHead];

        self->keyIndicationHead = (self->keyIndicationHead + 1) % APS_KEY_INDICATION_MAX;
        self->keyIndicationCount--;
    }

    return taken;
}

uint32_t Aps_KeyIndicationQueue(const Aps_Aps *self)
{
    return self->keyIndicationCount;
}

uint32_t Aps_KeyDroppedNotTrustCenter(const Aps_Aps *self)
{
    return self->keyDroppedNotTrustCenter;
}

uint32_t Aps_KeyDroppedPolicy(const Aps_Aps *self)
{
    return self->keyDroppedPolicy;
}

uint32_t Aps_KeyDroppedUnsecured(const Aps_Aps *self)
{
    return self->keyDroppedUnsecured;
}

uint32_t Aps_KeyDroppedDistributed(const Aps_Aps *self)
{
    return self->keyDroppedDistributed;
}

uint32_t Aps_KeyForwardDeferred(const Aps_Aps *self)
{
    return self->keyForwardDeferred;
}

uint32_t Aps_KeyInstalled(const Aps_Aps *self)
{
    return self->keyInstalled;
}

uint32_t Aps_KeyInstallFailed(const Aps_Aps *self)
{
    return self->keyInstallFailed;
}

uint32_t Aps_KeyLinkKeyDeferred(const Aps_Aps *self)
{
    return self->keyLinkKeyDeferred;
}

uint32_t Aps_RxFragmentDrops(const Aps_Aps *self)
{
    return self->rxFragmentDrops;
}

uint32_t Aps_FragmentsReassembled(const Aps_Aps *self)
{
    return self->fragmentsReassembled;
}

int Aps_Reassembling(const Aps_Aps *self)
{
#if ZB_APS_FRAGMENTATION
    uint32_t i;

    for (i = 0; self != 0 && i < APS_FRAG_TRANSACTIONS; i++)
    {
        if (self->frag[i].inUse)
            return 1;
    }

#else
    (void)self;
#endif

    return 0;
}

uint32_t Aps_DroppedBoundEntries(const Aps_Aps *self)
{
    return self != 0 ? self->droppedBoundEntries : 0;
}
