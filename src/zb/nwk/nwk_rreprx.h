#ifndef NWK_RREPRX_H
#define NWK_RREPRX_H

/*
 * 3.6.4.5.2's receipt of a Route Reply; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "nwk_discovery.h"
#include "nwk_frame.h"
#include "nwk_neighbor.h"
#include "nwk_rrep.h"
#include "nwk_route.h"

/* What became of one received route reply, one name per printed branch. */
typedef enum Nwk_RrepRxOutcome
{
    NWK_RREP_RX_NO_DISCOVERY = 0,      /* 9231-9249: Table 3-79 holds nothing for this (source, request id) */
    NWK_RREP_RX_NO_ROUTE_REMOVED = 1,  /* 9231-9249: no routing entry for the responder; the discovery entry goes */
    NWK_RREP_RX_ORIGINATOR_ROUTE = 2,  /* 9240-9243: DISCOVERY_UNDERWAY became ACTIVE, next hop the forwarder */
    NWK_RREP_RX_ORIGINATOR_CHEAPER = 3,/* 9244-9249: an ACTIVE entry took the smaller cost */
    NWK_RREP_RX_COST_NOT_SMALLER = 4,  /* 9247-9249 and 9251-9256: the recorded cost is the smaller one */
    NWK_RREP_RX_NO_ROUTE_DISCARDED = 5,/* 9251-9256: a forwarder's discovery entry without a routing entry */
    NWK_RREP_RX_FORWARDED = 6,         /* 9256-9263 and 9279-9285: the forward, and the reverse route */
    NWK_RREP_RX_UNSUITABLE = 7,        /* 3.6.4.5.3 step 2 with 9248 and 9256: the advertised route is not loop-free */
    NWK_RREP_RX_NO_ROUTING_CAPACITY = 8 /* 9224-9225: "If the receiving device has no routing capacity it SHALL discard" */
} Nwk_RrepRxOutcome;

/* The fields a caller acts on: the cost the replied path now stands at, and where the route from here goes. */
typedef struct Nwk_RrepRxDecision
{
    Nwk_RrepRxOutcome outcome;
    uint8_t pathCost;               /* 9225-9228: the payload's cost plus this hop's link cost, clamped (G3) */
    uint16_t nextHop;               /* 9242, 9256: the device that forwarded the reply */
    uint16_t destination;           /* 9279-9285: the reverse route's destination, the reply's originator */
    int originator;                 /* 1 for 9231-9249's half, 0 for 9251-9285's */
} Nwk_RrepRxDecision;

/* Judge a received reply: 3.6.4.5.2's two halves, with 3.6.4.5.3's loop test and 9279-9285's reverse route. A
   forwarder takes the entry 9195 marked underway to ACTIVE as the originator does: 9261-9263 prints only the next
   hop, and 8852-8856 would have it rediscover the route it just carried (docs/internals/decisions.md). */
Nwk_RrepRxOutcome Nwk_RrepRx(const Nwk_RouteReplyFields *reply, const Nwk_Frame *frame, uint16_t ownAddr,
                             uint32_t deviceType, Nwk_NeighborTableEntry *neighbors, Nwk_RoutingTableEntry *routes,
                             Nwk_RouteDiscoveryTableEntry *discoveries, uint32_t nowMs, Nwk_RrepRxDecision *out);

#endif /* NWK_RREPRX_H */
