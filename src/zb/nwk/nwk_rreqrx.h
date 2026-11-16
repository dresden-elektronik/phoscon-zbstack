#ifndef NWK_RREQRX_H
#define NWK_RREQRX_H

/*
 * 3.6.4.5.1's receipt of a Route Request; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "nwk_discovery.h"
#include "nwk_frame.h"
#include "nwk_neighbor.h"
#include "nwk_rreq.h"
#include "nwk_route.h"

/* What became of one received route request, one name per printed branch. */
typedef enum Nwk_RreqRxOutcome
{
    NWK_RREQ_RX_END_DEVICE = 0,     /* 3.6.4.5.1, 9090: an end device SHALL drop the frame */
    NWK_RREQ_RX_NO_NEIGHBOR = 1,    /* 9119-9120: no neighbor entry for the transmitting device */
    NWK_RREQ_RX_OUTGOING_COST_ZERO = 2, /* 9121-9124: the entry's outgoing cost is 0 */
    NWK_RREQ_RX_GREATER_FORWARD_COST = 3, /* 9134-9140: the frame's path cost plus this link's is greater than the recorded forward cost, which 3.6.4.5.3's LoopFree says the same way */
    NWK_RREQ_RX_NO_DISCOVERY_SLOT = 4, /* Table 3-79's pool is full: refusal-and-count (docs/internals/coding-rules.md §4.3) */
    NWK_RREQ_RX_DESTINATION_REPLY = 5, /* 3.6.4.5.1.1, 9094-9107 and 9112-9116: this device, or one of its end device children, is 3.4.1.3.3's destination */
    NWK_RREQ_RX_FORWARD_RELAY = 6,  /* 3.6.4.5.1.2 and 3.6.4.5.1.4: a forwarder, with the rewritten cost */

    NWK_RREQ_RX_FORWARDER_REPLY = 8 /* named, never produced: 9142-9147's forwarder reply (G12) */
} Nwk_RreqRxOutcome;

/* The fields a caller acts on: who the reverse route names, and the path cost a relayed copy would carry. */
typedef struct Nwk_RreqRxDecision
{
    Nwk_RreqRxOutcome outcome;
    uint16_t sourceAddr;            /* 3.4.1.2: the request's initiator, and 9125's reverse route's destination */
    uint16_t senderAddr;            /* 3.4.1.2: the transmitting device, and 9125's next hop */
    uint16_t destination;           /* 3.4.1.3.3: the request's intended destination */
    uint8_t requestId;              /* 3.4.1.3.2, the request identifier */
    uint8_t forwardCost;            /* 9125-9136: the path cost the relayed copy carries */
    uint8_t radius;                 /* 3.4.1.2: as received; 3.3.1.4's decrement is the header's */
    uint32_t expiryMs;              /* 9151: nowMs + nwkcRouteDiscoveryTime for the entry this call made */
} Nwk_RreqRxDecision;

/* 9122-9124's link cost with Table 3-76: the greater of the two directions. */
uint32_t Nwk_RreqRxLinkCost(const Nwk_NeighborTableEntry *neighbor);

/* Judge a received request: 3.6.4.5.1's gates, its forward cost, Table 3-79's dedup and 9125-9142's reverse route. */
Nwk_RreqRxOutcome Nwk_RreqRx(const Nwk_RouteRequestFields *fields, const Nwk_Frame *frame, uint16_t senderAddr,
                             Nwk_NeighborTableEntry *neighbors, Nwk_RoutingTableEntry *routes, Nwk_RouteDiscoveryTableEntry *discoveries,
                             uint16_t ownAddr, uint32_t deviceType, uint32_t nowMs,
                             Nwk_RreqRxDecision *out);

#endif /* NWK_RREQRX_H */
