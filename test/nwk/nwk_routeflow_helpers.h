/* The `nwk_routeflow` suite's shared machinery.

   What the three topic case files use, once: the one reply composition a case drives (Figure 3-11's payload
   out of `Nwk_RrepCompose`, its length handed back, a refusal reported rather than ignored), and the four
   seedings a plain pool needs, a neighbor with a measured link, a routing entry with the status and next hop
   a case names, a Table 3-79 record with both costs, and the two field sets a received command arrives as.
   Nothing here holds state between calls: every pool is a caller-owned array on the case's own stack. */

#ifndef NWK_ROUTEFLOW_HELPERS_H
#define NWK_ROUTEFLOW_HELPERS_H

#include <stdint.h>

#include "nwk_discovery.h"
#include "nwk_frame.h"
#include "nwk_neighbor.h"
#include "nwk_rrep.h"
#include "nwk_rreq.h"
#include "nwk_route.h"

/* Figure 3-11's payload of one reply, `*routingSeq` advanced as `Nwk_RrepCompose` advances it; 0 octets and a
   fault line when the module refused, because a case that cannot compose cannot assert anything about it. */
uint32_t composeRrep(const Nwk_RouteReplyPayload *reply, uint32_t *routingSeq, uint8_t *out, uint32_t outMax);

/* One Table 3-75 entry as an observation leaves it: the address, the measurement and the cost derived from it. */
Nwk_NeighborTableEntry *seedFlowNeighbor(Nwk_NeighborTableEntry *pool, uint32_t slot, uint16_t addr, uint32_t lqa,
                           uint32_t outgoingCost);

/* One Table 3-77 entry in a slot the case names, the way only a suite can seed one. */
Nwk_RoutingTableEntry *seedRoute(Nwk_RoutingTableEntry *pool, uint32_t slot, uint16_t dest, uint32_t status, uint16_t nextHop);

/* One Table 3-79 record in a slot the case names: the key, both costs and a live expiration. */
Nwk_RouteDiscoveryTableEntry *seedDiscovery(Nwk_RouteDiscoveryTableEntry *pool, uint32_t slot, uint16_t sourceAddr, uint8_t requestId,
                             uint8_t forwardCost, uint8_t residualCost, uint32_t expiryMs);

/* The fields of a route request as a parse leaves them: the destination and the path cost a case names. */
Nwk_RouteRequestFields rreqFieldsAt(uint16_t destAddr, uint8_t pathCost);

/* The header of a route request received directly from `sourceAddr`, aimed at Table 3-80's routers. */
Nwk_Frame receivedRreq(uint16_t sourceAddr, uint8_t radius);

/* The fields of a route reply as a parse leaves them: the originator, the responder and the path cost. */
Nwk_RouteReplyFields rrepFieldsAt(uint16_t originatorAddr, uint16_t responderAddr, uint8_t pathCost);

/* The header of a route reply received from `previousHop`: 3.4.2.2's newly created frame names that hop. */
Nwk_Frame receivedRrep(uint16_t previousHop);

#endif /* NWK_ROUTEFLOW_HELPERS_H */
