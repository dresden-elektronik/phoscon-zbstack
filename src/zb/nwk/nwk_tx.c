#include "nwk.h"

#include "nwk_tx.h"

#include "mac.h"
#include "nwk_frame.h"
#include "security.h"
#include "zb_utils.h"

/* M2024: 7.2.4, 10.22.2 ok; R23.1: 3.2.1.1.1, 3.2.1.1.3, 3.3.1.5, 3.3.1.6, 3.3.1.7, 3.3.1.8, 3.6.6, 4.2.2, 4.3.1.1, 4.3.2 ok
   (the compose with its source route, the MAC destination including an end device's parent, the alias rows, one
   protection per attempt); 3.2.1.2.1, 3.3.2.2.2, 3.4.1.1, 3.6.4.3, 3.6.4.5.1, 3.6.13, 4.3.1.2 elsewhere. */

/* Whether this device runs NWK security at all: a `Security` attached and answering enabled, level 0x00 being no security call in either direction (3.2.1.1.3, 4.3.1.2) */
int Nwk_TxSecurityRuns(const Security *security)
{
    if (security == 0)
        return 0;

    return Security_IsEnabled(security);
}

/* The Table 3-84 code of a protection this stack attempted and did not get, the seam's status beside it (3.2.1.1.3); a length has no code among them, so such a refusal goes uncoded */
uint32_t Nwk_TxConfirmStatus(ZbStatus status)
{
    if (status == ZB_ERR_BAD_FRAME_COUNTER)
        return NWK_STATUS_MAX_FRM_COUNTER;      

    if (status == ZB_ERR_AUTH)
        return NWK_STATUS_NO_KEY;               

    if (status == ZB_ERR_INTERNAL || status == ZB_ERR_BAD_ARGUMENT)
        return NWK_STATUS_BAD_CCM_OUTPUT;       

    return NWK_STATUS_LAST_MAC_STATUS;
}

/* The slot that holds a frame this module still owes an answer for. */
Nwk_Tx *Nwk_TxFree(Nwk_Tx *pool)
{
    uint32_t i;

    for (i = 0; i < NWK_TX_MAX; i++)
    {
        if (pool[i].state == NWK_TX_FREE)
            return &pool[i];
    }

    return 0;
}

uint32_t Nwk_TxOccupied(const Nwk_Tx *pool)
{
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < NWK_TX_MAX; i++)
    {
        if (pool[i].state != NWK_TX_FREE)
            count++;
    }

    return count;
}

/* The codec's minimal eight-octet header, the two IEEE sub-fields left zero (3.3.1.6, 3.3.1.7) and no source route, that route being a deferred arc's, and unsecured octets whatever the answer: protection is the attempt's act */
/* 3.2.1.1.1 with Table 3-2: an aliased frame carries the alias source address and sequence number the request named,
   and neither of this device's own is written or spent. */
/* A record the table holds is written as 3.3.1.8's sub-frame, its index at the entry closest to the originator,
   which is where the first hop starts; Table 3-51 gives a source-routed frame Discover Route 00, whatever the
   request asked, since 8859 source-routes it. */
ZbStatus Nwk_TxCompose(Nwk_Tx *tx, const Nwk_DataRequestParameters *req, uint16_t srcAddr, uint32_t *seq,
                       int endDeviceInitiator, const Nwk_SourceRouteEntry *sourceRoute)
{
    Nwk_Frame frame;
    uint32_t i;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    if (sourceRoute != 0 && sourceRoute->inUse && sourceRoute->relayCount > 0
        && sourceRoute->relayCount <= NWK_MAX_SOURCE_ROUTE)
    {
        frame.sourceRoute = 1;
        frame.relayCount = (uint8_t)sourceRoute->relayCount;
        frame.relayIndex = (uint8_t)(sourceRoute->relayCount - 1);

        for (i = 0; i < sourceRoute->relayCount; i++)
            frame.relayList[i] = sourceRoute->relayList[i];
    }

    frame.frameType = NWK_FRAME_TYPE_DATA;      
    frame.protocolVersion = NWK_PROTOCOL_VERSION;

    frame.discoverRoute = frame.sourceRoute ? NWK_DISCOVER_SUPPRESS : (int)req->discoverRoute;
    frame.destAddr = req->dstAddr;

    if (req->useAlias)
    {
        frame.srcAddr = req->aliasSrcAddr;
        frame.sequenceNumber = (uint8_t)(req->aliasSeqNumb % NWK_SEQ_WRAP);
        tx->seq = frame.sequenceNumber;
    }
    else
    {
        frame.srcAddr = srcAddr;
        frame.sequenceNumber = (uint8_t)(*seq % NWK_SEQ_WRAP);
        tx->seq = frame.sequenceNumber;
        *seq = (*seq + 1) % NWK_SEQ_WRAP;
    }

    frame.endDeviceInitiator = endDeviceInitiator;
    frame.radius = req->radius == 0 ? NWK_INITIAL_RADIUS : req->radius;

    frame.securityEnabled = req->securityEnable ? 1 : 0;
    tx->secured = frame.securityEnabled;
    tx->headerLen = NwkFrame_HeaderLen(&frame);

    return NwkFrame_Compose(&frame, req->nsdu, req->nsduLength, tx->npdu,
                            NWK_FRAME_NPDU_MAX, &tx->npduLen);
}

/* 3.2.1.1.3 step 6 a.3: a NWK destination of 0xFFFF, 0xFFFD or 0xFFFC goes down with the MAC's 0xFFFF, the class
   travelling in the NWK header. 3.6.6 makes the one exception: an end device's broadcast is addressed to its parent. */
uint16_t Nwk_TxMacDestination(uint16_t nextHop, int isBroadcast, int toParent)
{
    if (isBroadcast && !toParent)
        return MAC_FRAME_ADDR_BROADCAST;

    return nextHop;
}

/* 3.2.1.1.3's retry set as the seam names it: NO_ACK and CHANNEL_ACCESS_FAILURE by name, the device's other refusals under ZB_ERR_DEVICE, and a refusal that says there was no room for the transaction, which is IEEE 7.2.4's TRANSACTION_OVERFLOW (docs/internals/protocol.md §7.3). The clause owes the retry to a unicast and confirms a broadcast on the spot; a broadcast the door refused for room was never sent, and is held. */
int Nwk_TxRetryOwed(ZbStatus status)
{
    if (status == ZB_ERR_NO_ACK || status == ZB_ERR_CHANNEL_ACCESS_FAILURE || status == ZB_ERR_DEVICE)
        return 1;

    if (status == ZB_ERR_NO_SPACE || status == ZB_ERR_BUSY || status == ZB_ERR_TRANSACTION_OVERFLOW)
        return 1;

    return 0;
}

int Nwk_TxRefusedForRoom(ZbStatus status)
{
    return status == ZB_ERR_NO_SPACE || status == ZB_ERR_BUSY;
}

int Nwk_TxBlamesNextHop(ZbStatus status)
{
    return !Nwk_TxRefusedForRoom(status) && status != ZB_ERR_TIMEOUT && status != ZB_ERR_DEVICE_LOST;
}

/* One attempt at the frame a slot holds: an unsecured slot offered verbatim, a secured one protected from its stored octets on this attempt and every later one (3.2.1.1.3), on 3.6.4.3's next hop. The attempt count moves with the request issued, a request the seam refused being one of the requests the clause counts. */
ZbStatus Nwk_TxIssueAttempt(Nwk_Tx *tx, Mac_Mac *mac, Security *security, uint8_t *scratch,
                            uint32_t scratchMax, uint32_t nowMs, int *retryable, int *protectRefused)
{
    const Radio_Pib *pib;
    Mac_DataRequestParameters req;
    Radio_Handle handle;
    const uint8_t *octets;
    uint32_t octetLen;
    uint32_t securedLen;
    ZbStatus status;

    *retryable = 0;
    *protectRefused = 0;

    octets = tx->npdu;
    octetLen = tx->npduLen;

    if (tx->secured)
    {
        status = Nwk_TxProtect(security, tx->npdu, tx->npduLen, tx->headerLen, scratch, scratchMax,
                               &securedLen);

        if (status != ZB_OK)
        {
            *protectRefused = 1;
            return status;
        }

        octets = scratch;
        octetLen = securedLen;
    }

    pib = Mac_Pib(mac);

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    req.frameType = MAC_FRAME_TYPE_DATA;
    req.destAddrMode = MAC_ADDR_SHORT;
    req.srcAddrMode = MAC_ADDR_SHORT;
    req.destPan = pib->panId;
    req.destShort = Nwk_TxMacDestination(tx->nextHop, tx->isBroadcast, tx->toParent);
    req.ackRequest = tx->isBroadcast ? 0 : 1;
    req.payload = octets;
    req.payloadLen = octetLen;

    handle = RADIO_HANDLE_NONE;

    tx->attempts = tx->attempts + 1;

    if (tx->indirect)
    {
        req.msduHandle = tx->msduHandle;
        status = Mac_IndirectRequest(mac, &req, nowMs);
    }
    else
        status = Mac_DataRequest(mac, &req, nowMs, &handle);

    if (status != ZB_OK)
    {
        *retryable = (tx->isBroadcast ? Nwk_TxRefusedForRoom(status) : Nwk_TxRetryOwed(status)) ? 1 : 0;
        return status;
    }

    tx->lastHandle = handle;
    tx->state = NWK_TX_OUTSTANDING;

    return ZB_OK;
}

ZbStatus Nwk_TxHold(Nwk_Tx *tx, const uint8_t *npdu, uint32_t npduLen, uint32_t headerLen, int secured, uint8_t seq,
                    uint16_t dstAddr)
{
    if (tx == 0 || npduLen > (uint32_t)sizeof tx->npdu)
        return ZB_ERR_NO_SPACE;

    Zb_memset(tx, 0, (uint32_t)sizeof *tx);
    Zb_memcpy(tx->npdu, npdu, npduLen);

    tx->state = NWK_TX_OUTSTANDING;
    tx->dstAddr = dstAddr;
    tx->seq = seq;
    tx->npduLen = npduLen;
    tx->headerLen = headerLen;
    tx->secured = secured;
    tx->forwarded = 1;

    return ZB_OK;
}

ZbStatus Nwk_TxForward(Nwk_Tx *tx, Mac_Mac *mac, Security *security, uint8_t *scratch, uint32_t scratchMax,
                       const uint8_t *npdu, uint32_t npduLen, uint32_t headerLen, int secured, uint8_t seq,
                       uint16_t nextHop, uint16_t dstAddr, uint32_t nowMs, int *protectRefused)
{
    ZbStatus status;
    int retryable;

    *protectRefused = 0;

    status = Nwk_TxHold(tx, npdu, npduLen, headerLen, secured, seq, dstAddr);

    if (status != ZB_OK)
        return status;

    tx->nextHop = nextHop;

    status = Nwk_TxIssueAttempt(tx, mac, security, scratch, scratchMax, nowMs, &retryable, protectRefused);

    if (status == ZB_OK)
        return ZB_OK;

    if (retryable)
    {
        tx->state = NWK_TX_AWAITING_RETRY;
        tx->nextRetryMs = nowMs + NWK_UNICAST_RETRY_DELAY_MS;

        return ZB_OK;
    }

    Zb_memset(tx, 0, (uint32_t)sizeof *tx);

    return status;
}

/* One frame onto the air with octets a caller already holds and no slot taken (a relay, the 3.6.13 answer, a sleepy neighbour's copy), so 3.2.1.2.1's confirm answers nobody and the retry loop is `mac`'s */
ZbStatus Nwk_TxIssueRaw(Mac_Mac *mac, const uint8_t *npdu, uint32_t npduLen, uint16_t nextHop,
                        int isBroadcast, uint32_t nowMs, Radio_Handle *outHandle)
{
    const Radio_Pib *pib;
    Mac_DataRequestParameters req;

    if (outHandle != 0)
        *outHandle = RADIO_HANDLE_NONE;

    pib = Mac_Pib(mac);

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    req.frameType = MAC_FRAME_TYPE_DATA;      
    req.destAddrMode = MAC_ADDR_SHORT;
    req.srcAddrMode = MAC_ADDR_SHORT;
    req.destPan = pib->panId;
    req.destShort = Nwk_TxMacDestination(nextHop, isBroadcast, 0);
    req.ackRequest = isBroadcast ? 0 : 1;
    req.payload = npdu;
    req.payloadLen = npduLen;

    return Mac_DataRequest(mac, &req, nowMs, outHandle);
}

ZbStatus Nwk_TxOfferRaw(Mac_Mac *mac, const uint8_t *npdu, uint32_t npduLen, uint16_t nextHop, int held,
                        uint8_t heldHandle, uint32_t nowMs, Radio_Handle *outHandle)
{
    Mac_DataRequestParameters req;

    if (!held)
        return Nwk_TxIssueRaw(mac, npdu, npduLen, nextHop, 0, nowMs, outHandle);

    if (outHandle != 0)
        *outHandle = RADIO_HANDLE_NONE;

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    req.frameType = MAC_FRAME_TYPE_DATA;
    req.destAddrMode = MAC_ADDR_SHORT;
    req.srcAddrMode = MAC_ADDR_SHORT;
    req.destPan = Mac_Pib(mac)->panId;
    req.destShort = nextHop;
    req.ackRequest = 1;
    req.payload = npdu;
    req.payloadLen = npduLen;
    req.msduHandle = heldHandle;

    return Mac_IndirectRequest(mac, &req, nowMs);
}

/* The secured form of octets a caller holds, into its own scratch: the one protection crossing in this directory, run by every issue that carries no slot (4.3.1.1, 4.3.2), `headerLen` splitting header from payload */
ZbStatus Nwk_TxProtect(Security *security, const uint8_t *npdu, uint32_t npduLen, uint32_t headerLen,
                       uint8_t *scratch, uint32_t scratchMax, uint32_t *outLen)
{
    return Security_Protect(security, npdu, headerLen, npdu + headerLen, npduLen - headerLen, scratch,
                            scratchMax, outLen);
}
