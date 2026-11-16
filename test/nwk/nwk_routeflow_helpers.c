/* The `nwk_routeflow` suite's shared machinery: the one composition and the four seedings.
   See `nwk_routeflow_helpers.h` for the contract. */

#include "nwk_routeflow_helpers.h"

#include "test_harness.h"
#include "zb_utils.h"

uint32_t composeRrep(const Nwk_RouteReplyPayload *reply, uint32_t *routingSeq, uint8_t *out, uint32_t outMax)
{
    uint32_t len = 0;
    ZbStatus status;

    status = Nwk_RrepCompose(reply, routingSeq, out, outMax, &len);

    if (status != ZB_OK)
        Test_Fault("the route reply this case composes was refused");

    return len;
}

Nwk_NeighborTableEntry *seedFlowNeighbor(Nwk_NeighborTableEntry *pool, uint32_t slot, uint16_t addr, uint32_t lqa,
                           uint32_t outgoingCost)
{
    Zb_memset(&pool[slot], 0, (uint32_t)sizeof pool[slot]);

    pool[slot].inUse = 1;
    pool[slot].networkAddress = addr;
    pool[slot].deviceType = NWK_NEIGHBOR_TYPE_UNKNOWN;
    pool[slot].lqi = lqa;
    pool[slot].outgoingCost = outgoingCost;

    return &pool[slot];
}

Nwk_RoutingTableEntry *seedRoute(Nwk_RoutingTableEntry *pool, uint32_t slot, uint16_t dest, uint32_t status, uint16_t nextHop)
{
    Zb_memset(&pool[slot], 0, (uint32_t)sizeof pool[slot]);

    pool[slot].inUse = 1;
    pool[slot].destinationAddress = dest;
    pool[slot].status = status;
    pool[slot].nextHopAddress = nextHop;

    return &pool[slot];
}

Nwk_RouteDiscoveryTableEntry *seedDiscovery(Nwk_RouteDiscoveryTableEntry *pool, uint32_t slot, uint16_t sourceAddr, uint8_t requestId,
                             uint8_t forwardCost, uint8_t residualCost, uint32_t expiryMs)
{
    Zb_memset(&pool[slot], 0, (uint32_t)sizeof pool[slot]);

    pool[slot].inUse = 1;
    pool[slot].sourceAddress = sourceAddr;
    pool[slot].routeRequestId = requestId;
    pool[slot].senderAddress = 0x0200;
    pool[slot].forwardCost = forwardCost;
    pool[slot].residualCost = residualCost;
    pool[slot].expiresAtMs = expiryMs;

    return &pool[slot];
}

Nwk_RouteRequestFields rreqFieldsAt(uint16_t destAddr, uint8_t pathCost)
{
    Nwk_RouteRequestFields fields;

    Zb_memset(&fields, 0, (uint32_t)sizeof fields);

    fields.destAddr = destAddr;
    fields.pathCost = pathCost;
    fields.requestId = 0x09;
    fields.manyToOne = NWK_RREQ_MANY_TO_ONE_NONE;
    fields.initialRadius = 30;

    return fields;
}

Nwk_Frame receivedRreq(uint16_t sourceAddr, uint8_t radius)
{
    Nwk_Frame frame;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = NWK_FRAME_TYPE_COMMAND;
    frame.destAddr = NWK_ADDR_ROUTERS;
    frame.srcAddr = sourceAddr;
    frame.radius = radius;

    return frame;
}

Nwk_RouteReplyFields rrepFieldsAt(uint16_t originatorAddr, uint16_t responderAddr, uint8_t pathCost)
{
    Nwk_RouteReplyFields fields;

    Zb_memset(&fields, 0, (uint32_t)sizeof fields);

    fields.originatorAddr = originatorAddr;
    fields.responderAddr = responderAddr;
    fields.pathCost = pathCost;
    fields.requestId = 0x09;
    fields.routingSequenceNumber = 0x1235;
    fields.initialRadius = 30;

    return fields;
}

Nwk_Frame receivedRrep(uint16_t previousHop)
{
    Nwk_Frame frame;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = NWK_FRAME_TYPE_COMMAND;
    frame.destAddr = NWK_ADDR_ROUTERS;
    frame.srcAddr = previousHop;
    frame.radius = 29;

    return frame;
}
