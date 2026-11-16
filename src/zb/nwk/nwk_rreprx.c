#include "nwk.h"

#include "nwk_rreprx.h"

#include "nwk_cost.h"
#include "nwk_discovery.h"
#include "nwk_neighbor.h"
#include "nwk_route.h"
#include "zb_utils.h"

/* R23.1: 3.6.4.5.2, 3.6.4.5.3 ok (the originator and relay branches, the loop-free and cost comparisons both owe, and
   the reverse route the reply's own clause prints). docs/internals/conformance.md pages. */

/* 9225-9228: the link cost from the device that sent the reply to this one, 0 where nothing measured it. */
static uint32_t nwkRrepRxLinkCost(const Nwk_NeighborTableEntry *neighbor)
{
    if (!neighbor)
        return NWK_COST_UNMEASURED;

    return Nwk_CostCombine(Nwk_CostFromLqa(neighbor->lqi), neighbor->outgoingCost);
}

/* 9279-9285: the reverse route to the reply's originator, its next hop 9266-9272's sender address in Table 3-79
   (the hop the reply is relayed to, not the one it came from) created when absent and re-pointed when present. */
static void nwkRrepRxReverseRoute(Nwk_RoutingTableEntry *routes, const Nwk_RouteDiscoveryTableEntry *entry, uint32_t nowMs)
{
    Nwk_RoutingTableEntry *reverse;

    reverse = Nwk_RouteOf(routes, entry->sourceAddress);

    if (reverse)
    {
        reverse->status = NWK_ROUTE_ACTIVE;
        reverse->nextHopAddress = entry->senderAddress;
        reverse->ageMs = nowMs;

        return;
    }

    reverse = Nwk_RouteClaim(routes);

    if (!reverse)
        return;

    Zb_memset(reverse, 0, (uint32_t)sizeof *reverse);
    reverse->inUse = 1;
    reverse->destinationAddress = entry->sourceAddress;
    reverse->status = NWK_ROUTE_ACTIVE;
    reverse->nextHopAddress = entry->senderAddress;
    reverse->ageMs = nowMs;
}

Nwk_RrepRxOutcome Nwk_RrepRx(const Nwk_RouteReplyFields *reply, const Nwk_Frame *frame, uint16_t ownAddr,
                             uint32_t deviceType, Nwk_NeighborTableEntry *neighbors, Nwk_RoutingTableEntry *routes,
                             Nwk_RouteDiscoveryTableEntry *discoveries, uint32_t nowMs, Nwk_RrepRxDecision *out)
{
    Nwk_RrepRxOutcome outcome;
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_RoutingTableEntry *route;
    uint32_t linkCost;
    uint8_t replyCost;

    if (reply == 0 || frame == 0 || out == 0)
        return NWK_RREP_RX_NO_DISCOVERY;

    Zb_memset(out, 0, (uint32_t)sizeof *out);

    out->destination = reply->originatorAddr;
    out->nextHop = frame->srcAddr;
    out->originator = (ownAddr == reply->originatorAddr) ? 1 : 0;

    if (deviceType == NWK_DEVICE_END_DEVICE)
    {
        outcome = NWK_RREP_RX_NO_ROUTING_CAPACITY;

        out->outcome = outcome;

        return outcome;
    }

    replyCost = reply->pathCost;

    entry = Nwk_DiscoveryOf(discoveries, reply->originatorAddr, reply->requestId);

    if (!entry)
    {
        outcome = NWK_RREP_RX_NO_DISCOVERY;

        out->outcome = outcome;

        return outcome;
    }

    route = Nwk_RouteOf(routes, reply->responderAddr);

    if (out->originator)
    {
        if (!route)
        {
            (void)Nwk_DiscoveryRemove(discoveries, reply->originatorAddr, reply->requestId);

            outcome = NWK_RREP_RX_NO_ROUTE_REMOVED;

            out->outcome = outcome;

            return outcome;
        }

        if (route->status == NWK_ROUTE_DISCOVERY_UNDERWAY)
        {
            if (entry->residualCost != 0 && !Nwk_CostLoopFree(replyCost, entry->residualCost))
            {
                outcome = NWK_RREP_RX_UNSUITABLE;

                out->outcome = outcome;

                return outcome;
            }

            route->status = NWK_ROUTE_ACTIVE;
            route->nextHopAddress = frame->srcAddr;
            route->ageMs = nowMs;
            entry->residualCost = replyCost;

            if (reply->extendedRouteInfo)
            {
                route->sequenceNumber = reply->routingSequenceNumber;
                route->sequenceNumberValid = 1;
            }

            outcome = NWK_RREP_RX_ORIGINATOR_ROUTE;

            out->outcome = outcome;

            return outcome;
        }

        if (entry->residualCost != 0 && replyCost >= entry->residualCost)
        {
            outcome = NWK_RREP_RX_COST_NOT_SMALLER;

            out->outcome = outcome;

            return outcome;
        }

        route->nextHopAddress = frame->srcAddr;
        route->ageMs = nowMs;
        entry->residualCost = replyCost;

        if (reply->extendedRouteInfo)
        {
            route->sequenceNumber = reply->routingSequenceNumber;
            route->sequenceNumberValid = 1;
        }

        outcome = NWK_RREP_RX_ORIGINATOR_CHEAPER;

        out->outcome = outcome;

        return outcome;
    }

    if (entry->residualCost != 0 && entry->residualCost < replyCost)
    {
        outcome = NWK_RREP_RX_COST_NOT_SMALLER;

        out->outcome = outcome;

        return outcome;
    }

    if (!route)
    {
        outcome = NWK_RREP_RX_NO_ROUTE_DISCARDED;

        out->outcome = outcome;

        return outcome;
    }

    route->status = NWK_ROUTE_ACTIVE;
    route->nextHopAddress = frame->srcAddr;
    route->ageMs = nowMs;
    entry->residualCost = replyCost;

    if (reply->extendedRouteInfo)
    {
        route->sequenceNumber = reply->routingSequenceNumber;
        route->sequenceNumberValid = 1;
    }

    linkCost = nwkRrepRxLinkCost(Nwk_NeighborOf(neighbors, entry->senderAddress));
    out->pathCost = (uint8_t)Nwk_CostAccumulate(replyCost, linkCost);

    nwkRrepRxReverseRoute(routes, entry, nowMs);

    outcome = NWK_RREP_RX_FORWARDED;

    out->outcome = outcome;

    return outcome;
}
