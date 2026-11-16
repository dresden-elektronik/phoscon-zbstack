#include "nwk.h"

#include "nwk_rx.h"

#include "mac.h"
#include "nwk_addr.h"
#include "nwk_command.h"
#include "nwk_cost.h"
#include "nwk_frame.h"
#include "nwk_neighbor.h"
#include "security.h"
#include "zb_time.h"
#include "zb_utils.h"

/* R23.1: 3.3.1.7, 3.4.14, 3.6.1.6.1, 3.6.1.6.1.3, 3.6.1.7, 3.6.2.2, 3.6.2.3, 3.6.4.3.2, 4.3.1.2, 4.5.1.3 ok;
   3.3.1.1.8 elsewhere (nwk.c's gate); 3.4.7.2 3.6.4.3 3.6.4.4.3 3.6.4.4.4 3.6.6 3.6.4.5.1.2 elsewhere. */

/* What a consumed frame says about the device that sent it this hop: a NWK address, an IEEE address and Table 3-75's
   measurement, where a device type and a receiver duty are no frame's to state. The originator's header speaks for
   the hop only when they are the same device; 4.5.1.3's auxiliary source is always the hop's. */
void Nwk_RxObserve(Nwk_NeighborTableEntry *neighbors, const Nwk_Frame *frame, uint16_t hopAddr, uint32_t lqi,
                   uint64_t hopIeee, int hopIeeeKnown, uint32_t nowMs, int *addRefusedOut)
{
    Nwk_NeighborTableEntry *neighbor;

    *addRefusedOut = 0;

    neighbor = Nwk_NeighborOf(neighbors, hopAddr);

    if (neighbor == 0)
    {
        neighbor = Nwk_NeighborFree(neighbors);

        if (neighbor == 0)
        {
            *addRefusedOut = 1;
            return;
        }

        Zb_memset(neighbor, 0, (uint32_t)sizeof *neighbor);

        neighbor->inUse = 1;
        neighbor->networkAddress = hopAddr;
        neighbor->deviceType = NWK_NEIGHBOR_TYPE_UNKNOWN;
        neighbor->relationship = NWK_REL_NONE;

        neighbor->routerOutboundActivity = NWK_ROUTER_AGE_LIMIT;
        neighbor->routerInboundActivity = NWK_ROUTER_AGE_LIMIT;
        neighbor->ageFromMs = nowMs;
    }

    Nwk_NeighborLqaSample(neighbor, lqi);

    if (hopIeeeKnown)
    {
        neighbor->extendedAddress = hopIeee;
        neighbor->ieeeKnown = 1;
    }
    else if (frame->srcAddr == hopAddr && frame->srcIeeePresent && !neighbor->ieeeKnown)
    {
        neighbor->extendedAddress = frame->srcIeee;
        neighbor->ieeeKnown = 1;
    }
}

/* 4.3.1.2 step 8: every entry whose extended address is the auxiliary's SenderAddress and whose relationship is 0x05
   becomes 0x01, the hop that secured the frame, not the originator (4.5.1.3); 3.6.1.6.1.3's countdown stops there,
   the frame being the network-encrypted message that paragraph waits for. */
void Nwk_RxAuthenticateHop(Nwk_NeighborTableEntry *neighbors, const Security_Result *result)
{
    Nwk_NeighborTableEntry *neighbor;
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        neighbor = &neighbors[i];

        if (!neighbor->inUse)
            continue;

        if (!neighbor->ieeeKnown)
            continue;

        if (neighbor->extendedAddress != result->senderIeee)
            continue;

        if (neighbor->relationship != NWK_REL_UNAUTHENTICATED_CHILD)
            continue;

        neighbor->relationship = NWK_REL_CHILD;

        neighbor->securityTimer = 0;
    }
}

/* 3.6.2.3 step by step: the entry for the frame's NWK source, its type, a MAC source that differs, a broadcast already recorded skipped, and 0x07 stamped for that paragraph's own re-evaluation */
void Nwk_RxExamineParents(Nwk_NeighborTableEntry *neighbors, uint32_t deviceType, const Mac_DataIndicationParameters *ind,
                          const Nwk_Frame *frame, uint32_t nowMs)
{
    Nwk_NeighborTableEntry *neighbor;

    if (!Nwk_AddrHasRoutingDuty(deviceType))
        return;

    if (ind->header.srcAddrMode != MAC_ADDR_SHORT)
        return;

    neighbor = Nwk_NeighborOf(neighbors, frame->srcAddr);

    if (neighbor == 0)
        return;

    if (neighbor->deviceType != NWK_DEVICE_END_DEVICE)
        return;

    if (ind->header.srcShort == frame->srcAddr)
        return;

    neighbor->relationship = NWK_REL_LOST_CHILD;
    neighbor->lostChildMs = nowMs + NWK_LOST_CHILD_EVALUATION_MS;
}

/* 3.6.2.3's last paragraph: "The NLME SHALL evaluate the neighbor table after the APS layer has processed the
   message … If the field is still 0x07 then the neighbor table entry SHALL be deleted." */
uint32_t Nwk_RxReleaseLostChildren(Nwk_NeighborTableEntry *neighbors, uint32_t nowMs)
{
    Nwk_NeighborTableEntry *neighbor;
    uint32_t deleted = 0;
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        neighbor = &neighbors[i];

        if (!neighbor->inUse)
            continue;

        if (neighbor->relationship != NWK_REL_LOST_CHILD || neighbor->lostChildMs == 0)
            continue;

        if (!Zb_timeReached(nowMs, neighbor->lostChildMs))
            continue;

        Zb_memset(neighbor, 0, (uint32_t)sizeof *neighbor);
        deleted++;
    }

    return deleted;
}

/* 3.6.2.2's judgement at a joined, authenticated device above level 0: an unsecured data frame discarded, an unsecured 0x06 accepted only where the frame is destined to this device (docs/internals/conformance.md §2) */
/* 3.6.2.2's second half, for a device not joined and authenticated: an unsecured data frame passes only if "it
   contains an APS command ID of 0x05 (Transport Key)". An APS-secured command encrypts that identifier, so it passes
   on its shape and `aps` judges the identifier once unsecured. */
int Nwk_RxCarriesTransportKey(const uint8_t *payload, uint32_t payloadLen)
{
    if (payload == 0 || payloadLen < NWK_RX_APS_COMMAND_ID_OFFSET + 1)
        return 0;

    if ((payload[0] & NWK_RX_APS_FRAME_TYPE_MASK) != NWK_RX_APS_FRAME_TYPE_COMMAND)
        return 0;

    if ((payload[0] & NWK_RX_APS_FCF_SECURITY) != 0)
        return 1;

    return payload[NWK_RX_APS_COMMAND_ID_OFFSET] == NWK_RX_APS_CMD_TRANSPORT_KEY ? 1 : 0;
}

/* A joined device takes an unsecured rejoin request and an unsecured commissioning request: both come from a device
   that is not on the network yet, so no key of this network protects either. */
int Nwk_RxUnsecuredAccepted(const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                            int destinedToSelf)
{
    if (frame->frameType != NWK_FRAME_TYPE_COMMAND)
        return 0;

    if (payloadLen == 0)
        return 0;

    if (payload[0] == NWK_CMD_REJOIN_REQUEST)
        return destinedToSelf;

    if (payload[0] == NWK_CMD_NETWORK_COMMISSIONING_REQUEST)
        return destinedToSelf;

    return 0;
}

/* The octets a relay puts on the air: the frame as it was read, the decrement already in it; 3.3.1.1.8's End Device Initiator clear needs parent/child state this stack has none of (docs/internals/conformance.md §2) */
ZbStatus Nwk_RxForwardCopy(const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                           uint8_t *npdu, uint32_t npduMax, uint32_t *outLen)
{
    return NwkFrame_ComposeRelay(frame, payload, payloadLen, npdu, npduMax, outLen);
}

Nwk_SourceRouteVerdict Nwk_RxSourceRoute(const Nwk_Frame *frame, uint16_t ownAddr, uint32_t deviceType,
                                         const Nwk_NeighborTableEntry *neighbors, uint16_t *nextHopOut)
{
    const Nwk_NeighborTableEntry *target;

    if (nextHopOut != 0)
        *nextHopOut = 0;

    if (frame == 0 || !frame->sourceRoute || frame->relayCount == 0)
        return NWK_SR_DROP;

    if (frame->relayIndex == 0)
    {
        if (frame->destAddr == ownAddr)
            return NWK_SR_DELIVER;

        if (!Nwk_AddrHasRoutingDuty(deviceType))
            return NWK_SR_DROP;

        if (nextHopOut != 0)
            *nextHopOut = frame->destAddr;

        return NWK_SR_RELAY_DIRECT;
    }

    if (frame->relayIndex >= frame->relayCount)
        return NWK_SR_DROP;

    if (frame->relayList[frame->relayIndex] != ownAddr)
        return NWK_SR_DROP;

    target = Nwk_NeighborOf((Nwk_NeighborTableEntry *)neighbors, frame->destAddr);

    if (target != 0 && target->deviceType == NWK_DEVICE_END_DEVICE
        && target->relationship == NWK_REL_CHILD)
    {
        if (nextHopOut != 0)
            *nextHopOut = frame->destAddr;

        return NWK_SR_RELAY_DIRECT;
    }

    if (nextHopOut != 0)
        *nextHopOut = frame->relayList[frame->relayIndex - 1];

    return NWK_SR_RELAY_ONWARD;
}
