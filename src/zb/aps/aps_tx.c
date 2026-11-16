#include "aps.h"

#include "aps_tx.h"

#include "aps_frame.h"
#include "nwk.h"
#include "nwk_addr.h"
#include "security.h"
#include "zb_utils.h"

/* R23.1 2.2.4.1.1 2.2.5.1.1 2.2.5.1.2 2.2.5.1.7 2.2.8.4.1 2.2.8.4.5 2.2.8.4.5.3 4.4.1.1 4.4.10 4.6.3.2.1 ok; 2.2.8.4.4 4.4.1.2 elsewhere
   (aps.c's retry loop, aps_rx.c, security.c). */

/*
 * The delivery mode, derived from the request rather than handed to it: Table 2-2's addressing mode says what
 * kind of address `dstAddress` is and 2.2.5.1.1.2 says what a broadcast *is*, making Table 3-80's classes the
 * fact and not a flag. The class predicate is `nwk_addr`'s and is called, not copied.
 */
uint32_t Aps_TxDeliveryMode(const Aps_ApsdeReq *req)
{
    if (req->dstAddrMode == APS_ADDR_MODE_GROUP)
        return APS_DELIVERY_GROUP;

    if (Nwk_AddrIsBroadcast(req->dstAddress))
        return APS_DELIVERY_BROADCAST;

    return APS_DELIVERY_UNICAST;
}

/*
 * The address the NWK layer is asked to reach, which for a group send is not the address the request named:
 * 2.2.4.1.1.3 puts the group id in the APS header and passes `nwkBroadcastAddress` down, and 2.2.8.4.1 prints
 * 0xfffd for a request that states none.
 */
uint16_t Aps_TxNwkDestination(const Aps_ApsdeReq *req)
{
    if (req->dstAddrMode != APS_ADDR_MODE_GROUP)
        return req->dstAddress;

    if (req->nwkBroadcastAddress == 0)
        return APS_NWK_BROADCAST_GROUP_DEFAULT;

    return req->nwkBroadcastAddress;
}

/* The transaction slot that is free, in pool order. */
Aps_Tx *Aps_TxFree(Aps_Tx *pool)
{
    uint32_t i;

    for (i = 0; i < APS_TX_MAX; i++)
    {
        if (pool[i].state == APS_TX_FREE)
            return &pool[i];
    }

    return 0;
}

uint32_t Aps_TxOccupied(const Aps_Tx *pool)
{
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < APS_TX_MAX; i++)
    {
        if (pool[i].state != APS_TX_FREE)
            count++;
    }

    return count;
}

/*
 * The APDU the transaction will transmit, composed into the slot by the codec and nothing else.
 * The flags are what 2.2.5.1.2 … 2.2.5.1.7 and 2.2.8.4.1 fix for the delivery mode this request became; the
 * security bit is the transaction's own and is set before the protection runs because the APS header is
 * inside the authenticated string (4.4.1.1 step 5d). What the codec refuses is refused in its vocabulary,
 * and its payload offset is kept with the APDU: where `Security_ProtectAps` puts the auxiliary (4.4.10).
 */
ZbStatus Aps_TxCompose(Aps_Tx *tx, const Aps_ApsdeReq *req)
{
    Aps_Frame frame;
    uint32_t apduLen;
    uint32_t payloadOffset;
    ZbStatus status;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = APS_FRAME_TYPE_DATA;
    frame.deliveryMode = tx->deliveryMode;
    frame.ackRequest = tx->ackRequested;
    frame.securityEnabled = tx->apsSecurity;

    frame.dstEndpointPresent = tx->deliveryMode == APS_DELIVERY_GROUP ? 0 : 1;
    frame.dstEndpoint = req->dstEndpoint;

    frame.groupAddressPresent = tx->deliveryMode == APS_DELIVERY_GROUP ? 1 : 0;
    frame.groupAddress = req->dstAddress;

    frame.clusterPresent = 1;
    frame.clusterId = req->clusterId;
    frame.profilePresent = 1;
    frame.profileId = req->profileId;
    frame.srcEndpointPresent = 1;
    frame.srcEndpoint = req->srcEndpoint;
    frame.apsCounter = tx->apsCounter;

    status = ApsFrame_Compose(&frame, req->asdu, req->asduLength, tx->apdu,
                              (uint32_t)sizeof tx->apdu, &apduLen, &payloadOffset);

    if (status != ZB_OK)
        return status;

    tx->apduLen = apduLen;
    tx->apduHeaderLen = payloadOffset;

    return ZB_OK;
}

/* The key pair an outgoing secured frame is shared with: 4.4.1.1 step 1's "the entity indicated by the DstAddress
   parameter", matched by Table 4-36's DeviceAddress, an extended destination by its IEEE address; -1 is no pair,
   which the caller answers NO_SHORT_ADDRESS. */
int Aps_TxResolveKeyPair(const Security *security, const Aps_ApsdeReq *req)
{
    if (security == 0)
        return -1;

    if (req->dstAddrMode == APS_ADDR_MODE_EXTENDED)
        return Security_FindKeyPairByIeee(security, req->dstExtendedAddress);

    return Security_FindKeyPairByShort(security, req->dstAddress);
}

/*
 * 4.4.1.1 over the stored APDU: the codec's own offset splits header from payload, `extendedNonce` is the bit
 * that chose the auxiliary's length and RVFC is Table 4-41's 1 for a datagram (4.4.1.1 step 4a-ii).
 * The entry is re-read from the pool at every issue, so a key set the application replaced under an
 * outstanding transaction is answered at the attempt and not trusted from the door.
 */
ZbStatus Aps_TxProtect(Security *security, Aps_Tx *tx, uint8_t *scratch, uint32_t scratchMax)
{
    uint32_t securedLen;
    ZbStatus status;

    if (security == 0)
        return ZB_ERR_AUTH;

    status = Security_ProtectAps(security, tx->keyPairIndex, tx->keyIdentifier,
                                 tx->apdu, tx->apduHeaderLen,
                                 tx->apdu + tx->apduHeaderLen, tx->apduLen - tx->apduHeaderLen,
                                 tx->extendedNonce,
                                 scratch, scratchMax, &securedLen);

    if (status != ZB_OK)
        return status;

    tx->securedLen = securedLen;

    return ZB_OK;
}

/* The octets one issue of this transaction puts down as its NSDU: the protected frame for a secured
   transaction, which is only ever reached after `Aps_TxProtect` filled the scratch, and the stored APDU for
   every other transaction of this module, the unsecured path, unchanged. */
void Aps_TxOutgoingOctets(const Aps_Tx *tx, const uint8_t *scratch,
                          const uint8_t **octets, uint32_t *len)
{
    if (tx->apsSecurity)
    {
        *octets = scratch;
        *len = tx->securedLen;
        return;
    }

    *octets = tx->apdu;
    *len = tx->apduLen;
}

/* One transmission of this transaction, as one NLDE-DATA.request carrying the stored APDU as its NSDU (2.2.8.4.1),
   issued with the route discovery 2.2.8.4.1 obliges the APS layer to enable and the value suppressed only for the
   group and broadcast case that clause itself sends as a broadcast. RadiusCounter travels unchanged and a zero is
   `nwk`'s to derive (3.2.1.1.3); the APS-side ask has already been acted on by the time a frame reaches here. The
   carrier's protection is the network's own state (4.2.2), which this slice never prohibits. */
ZbStatus Aps_TxIssue(Aps_Tx *tx, Nwk_Nwk *nwk, const uint8_t *scratch, uint32_t nowMs)
{
    Nwk_DataRequestParameters req;
    const uint8_t *octets;
    uint32_t octetsLen;
    ZbStatus status;

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    Aps_TxOutgoingOctets(tx, scratch, &octets, &octetsLen);

    req.dstAddr = tx->nwkDst;
    req.nsdu = octets;
    req.nsduLength = octetsLen;
    req.radius = tx->radiusCounter;
    req.discoverRoute = tx->deliveryMode == APS_DELIVERY_UNICAST ? NWK_DISCOVER_ENABLE : NWK_DISCOVER_SUPPRESS;
    req.securityEnable = tx->nwkSecurity && Security_IsEnabled(Nwk_Security(nwk)) ? 1 : 0;
    req.useAlias = tx->useAlias;
    req.aliasSrcAddr = tx->aliasSrcAddr;
    req.aliasSeqNumb = tx->aliasSeqNumb;

    status = Nwk_DataRequest(nwk, &req, nowMs);

    if (status != ZB_OK)
        return status;

    tx->attempts = tx->attempts + 1;
    tx->lastHandle = Nwk_LastRequestHandle(nwk);
    tx->lastNwkSeq = Nwk_LastRequestSeq(nwk);
    tx->state = APS_TX_AWAITING_NLDE;

    return ZB_OK;
}

/*
 * Which transaction a NLDE confirmation belongs to: the handle, the same key `mac` and `nwk` use. A confirm
 * whose handle names no issue (a ROUTE_ERROR discard that ran no transmit (3.6.4.3), an attempt re-issued on a
 * later turn (3.2.1.1.3), a frame held for a sleeping child) pairs by destination and the NWK sequence number.
 */
Aps_Tx *Aps_TxSlotForConfirm(Aps_Tx *pool, const Nwk_DataConfirmParameters *confirm)
{
    uint32_t i;

    for (i = 0; i < APS_TX_MAX; i++)
    {
        if (pool[i].state != APS_TX_AWAITING_NLDE)
            continue;

        if (pool[i].lastHandle == RADIO_HANDLE_NONE)
            continue;

        if (pool[i].lastHandle != confirm->handle)
            continue;

        return &pool[i];
    }

    for (i = 0; i < APS_TX_MAX; i++)
    {
        if (pool[i].state != APS_TX_AWAITING_NLDE)
            continue;

        if (pool[i].nwkDst != confirm->dstAddr || pool[i].lastNwkSeq != confirm->seq)
            continue;

        return &pool[i];
    }

    return 0;
}

#if ZB_APS_FRAGMENTATION
uint32_t Aps_TxBlockCapacity(const Aps_Tx *tx)
{
    uint8_t probe[APS_FRAME_MAX];
    Aps_Frame frame;
    uint32_t apduLen;
    uint32_t payloadOffset;

    if (tx == 0)
        return 0;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = APS_FRAME_TYPE_DATA;
    frame.deliveryMode = tx->deliveryMode;
    frame.ackRequest = tx->ackRequested;
    frame.securityEnabled = tx->apsSecurity;
    frame.extendedHeaderPresent = 1;
    frame.blockNumberPresent = 1;

    frame.dstEndpointPresent = tx->deliveryMode == APS_DELIVERY_GROUP ? 0 : 1;
    frame.dstEndpoint = tx->dstEndpoint;
    frame.groupAddressPresent = tx->deliveryMode == APS_DELIVERY_GROUP ? 1 : 0;
    frame.groupAddress = tx->dstAddress;
    frame.clusterPresent = 1;
    frame.clusterId = tx->clusterId;
    frame.profilePresent = 1;
    frame.profileId = tx->profileId;
    frame.srcEndpointPresent = 1;
    frame.srcEndpoint = tx->srcEndpoint;

    if (ApsFrame_Compose(&frame, 0, 0, probe, (uint32_t)sizeof probe, &apduLen, &payloadOffset) != ZB_OK)
        return 0;

    if (payloadOffset >= (uint32_t)APS_FRAME_MAX)
        return 0;

    return (uint32_t)APS_FRAME_MAX - payloadOffset;
}

ZbStatus Aps_TxComposeBlock(Aps_Tx *tx)
{
    Aps_Frame frame;
    const uint8_t *block;
    uint32_t blockLen;
    uint32_t apduLen;
    uint32_t payloadOffset;
    ZbStatus status;

    if (tx == 0 || !tx->fragmented)
        return ZB_ERR_BAD_ARGUMENT;

    block = Aps_FragBlock(tx->fragAsdu, tx->fragAsduLength, tx->fragCapacity, tx->fragIndex, &blockLen);

    if (block == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = APS_FRAME_TYPE_DATA;
    frame.deliveryMode = tx->deliveryMode;
    frame.ackRequest = tx->ackRequested;
    frame.securityEnabled = tx->apsSecurity;

    frame.dstEndpointPresent = tx->deliveryMode == APS_DELIVERY_GROUP ? 0 : 1;
    frame.dstEndpoint = tx->dstEndpoint;

    frame.groupAddressPresent = tx->deliveryMode == APS_DELIVERY_GROUP ? 1 : 0;
    frame.groupAddress = tx->dstAddress;

    frame.clusterPresent = 1;
    frame.clusterId = tx->clusterId;
    frame.profilePresent = 1;
    frame.profileId = tx->profileId;
    frame.srcEndpointPresent = 1;
    frame.srcEndpoint = tx->srcEndpoint;
    frame.apsCounter = tx->apsCounter;

    frame.extendedHeaderPresent = 1;
    frame.fragmentation = Aps_FragSubField(tx->fragIndex);
    frame.extFrameControl = (uint8_t)frame.fragmentation;
    frame.blockNumberPresent = 1;
    frame.blockNumber = Aps_FragBlockNumber(tx->fragIndex, tx->fragTotal);

    status = ApsFrame_Compose(&frame, block, blockLen, tx->apdu, (uint32_t)sizeof tx->apdu, &apduLen,
                              &payloadOffset);

    if (status != ZB_OK)
        return status;

    tx->apduLen = apduLen;
    tx->apduHeaderLen = payloadOffset;

    return ZB_OK;
}
#endif
