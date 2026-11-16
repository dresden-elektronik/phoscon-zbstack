#include "nwk.h"

#include "nwk_rreqrx.h"

#include "nwk_cost.h"
#include "nwk_discovery.h"
#include "nwk_neighbor.h"
#include "nwk_route.h"
#include "zb_utils.h"

/* R23.1: 3.4.1.3.2, 3.4.1.3.3, 3.6.4.5.1, 3.6.4.5.3 ok (the discovery entry now carries the request's destination,
   which the expiry keys on); 3.3.1.4 elsewhere (nwk.c decrements); 3.4.1.2 elsewhere (nwk_tx.c's header). */

/* 9122-9124 and Table 3-76: the worse of the incoming and outgoing costs of this neighbor. */
uint32_t Nwk_RreqRxLinkCost(const Nwk_NeighborTableEntry *neighbor)
{
    if (neighbor == 0)
        return 0;

    return Nwk_CostCombine(Nwk_CostFromLqa(neighbor->lqi), neighbor->outgoingCost);
}

/* 9125-9142's reverse route (the request's source as destination, the transmitting device as next hop, ACTIVE) carrying Table 3-77's four fields 9154-9162 writes */
static void nwkRreqRxReverseRoute(Nwk_RoutingTableEntry *routes, const Nwk_RouteRequestFields *fields, uint16_t sourceAddr,
                                  uint16_t senderAddr, uint32_t nowMs)
{
    Nwk_RoutingTableEntry *route = Nwk_RouteOf(routes, sourceAddr);

    if (route == 0)
    {
        route = Nwk_RouteClaim(routes);

        if (route == 0)
            return;

        Zb_memset(route, 0, (uint32_t)sizeof *route);

        route->inUse = 1;
        route->destinationAddress = sourceAddr;
    }

    route->status = NWK_ROUTE_ACTIVE;
    route->nextHopAddress = senderAddr;
    route->ageMs = nowMs;

    if (fields->manyToOne != NWK_RREQ_MANY_TO_ONE_NONE)
    {
        route->manyToOne = 1;
        route->routeRecordRequired = 1;
        route->noRouteCache = (fields->manyToOne == NWK_RREQ_MANY_TO_ONE_WITHOUT_RECORD) ? 1 : 0;
    }

    if (fields->extendedRouteInfo)
    {
        route->sequenceNumber = fields->routingSequenceNumber;
        route->sequenceNumberValid = 1;
    }
}

/* The destination test's second half: a destination that is one of this device's end device children, which a router
   answers on because a sleepy child never hears the request itself */
static int nwkRreqRxIsEndDeviceChild(const Nwk_NeighborTableEntry *neighbors, uint16_t address)
{
    const Nwk_NeighborTableEntry *child;

    child = Nwk_NeighborOf((Nwk_NeighborTableEntry *)neighbors, address);

    if (child == 0)
        return 0;

    return child->relationship == NWK_REL_CHILD && child->deviceType == NWK_DEVICE_END_DEVICE;
}

Nwk_RreqRxOutcome Nwk_RreqRx(const Nwk_RouteRequestFields *fields, const Nwk_Frame *frame, uint16_t senderAddr,
                             Nwk_NeighborTableEntry *neighbors, Nwk_RoutingTableEntry *routes, Nwk_RouteDiscoveryTableEntry *discoveries,
                             uint16_t ownAddr, uint32_t deviceType, uint32_t nowMs,
                             Nwk_RreqRxDecision *out)
{
    Nwk_RreqRxOutcome outcome;
    Nwk_NeighborTableEntry *neighbor;
    Nwk_RouteDiscoveryTableEntry *entry;
    uint32_t linkCost;
    uint8_t forwardCost;

    Zb_memset(out, 0, (uint32_t)sizeof *out);

    out->sourceAddr = frame->srcAddr;
    out->senderAddr = senderAddr;
    out->destination = fields->destAddr;
    out->requestId = fields->requestId;
    out->radius = frame->radius;

    if (deviceType == NWK_DEVICE_END_DEVICE)
    {
        outcome = NWK_RREQ_RX_END_DEVICE;

        out->outcome = outcome;

        return outcome;
    }

    neighbor = Nwk_NeighborOf(neighbors, senderAddr);

    if (!neighbor)
    {
        outcome = NWK_RREQ_RX_NO_NEIGHBOR;

        out->outcome = outcome;

        return outcome;
    }

    if (!Nwk_CostUsable(neighbor->outgoingCost))
    {
        outcome = NWK_RREQ_RX_OUTGOING_COST_ZERO;

        out->outcome = outcome;

        return outcome;
    }

    linkCost = Nwk_RreqRxLinkCost(neighbor);
    forwardCost = (uint8_t)Nwk_CostAccumulate(fields->pathCost, linkCost);
    out->forwardCost = forwardCost;

    entry = Nwk_DiscoveryOf(discoveries, frame->srcAddr, fields->requestId);

    if (entry)
    {
        if (entry->forwardCost != 0 && forwardCost > entry->forwardCost)
        {
            outcome = NWK_RREQ_RX_GREATER_FORWARD_COST;

            out->outcome = outcome;

            return outcome;
        }

        entry->forwardCost = forwardCost;
        entry->senderAddress = senderAddr;
    }
    else
    {
        entry = Nwk_DiscoveryClaim(discoveries, nowMs);

        if (!entry)
        {
            outcome = NWK_RREQ_RX_NO_DISCOVERY_SLOT;

            out->outcome = outcome;

            return outcome;
        }

        entry->inUse = 1;
        entry->routeRequestId = fields->requestId;
        entry->sourceAddress = frame->srcAddr;
        entry->destAddr = fields->destAddr;
        entry->senderAddress = senderAddr;
        entry->forwardCost = forwardCost;
        entry->residualCost = 0;
        entry->expiresAtMs = nowMs + NWK_ROUTE_DISCOVERY_TIME_MS;
    }

    out->expiryMs = entry->expiresAtMs;

    nwkRreqRxReverseRoute(routes, fields, frame->srcAddr, senderAddr, nowMs);

    if (fields->destAddr == ownAddr || nwkRreqRxIsEndDeviceChild(neighbors, fields->destAddr))
        outcome = NWK_RREQ_RX_DESTINATION_REPLY;
    else
        outcome = NWK_RREQ_RX_FORWARD_RELAY;

    out->outcome = outcome;

    return outcome;
}
