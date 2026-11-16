/* The `nwk_routedisc` suite's shared machinery.

   What both topic case files use, once: the one composition a case drives (Figure 3-9's payload out of
   `Nwk_RreqCompose`, its length handed back, a refusal reported rather than ignored) and the one way a
   discovery record is seeded into a plain pool. Nothing here is state two cases share: every pool is a
   caller-owned array on the case's own stack, and the two functions hold nothing between calls. */

#ifndef NWK_ROUTEDISC_HELPERS_H
#define NWK_ROUTEDISC_HELPERS_H

#include <stdint.h>

#include "nwk_discovery.h"
#include "nwk_rreq.h"

/* Figure 3-9's payload of one request, `*routingSeq` advanced as `Nwk_RreqCompose` advances it; 0 octets and a
   fault line when the module refused, because a case that cannot compose cannot assert anything about it. */
uint32_t composeRreq(const Nwk_RouteRequestPayload *req, uint32_t *routingSeq, uint8_t initialRadius,
                     uint8_t *out, uint32_t outMax);

/* One Table 3-79 record in a slot the case names, the way only a suite can seed one: the key, both costs and
   the expiration the owner of the record computes. */
Nwk_RouteDiscoveryTableEntry *seedDiscovery(Nwk_RouteDiscoveryTableEntry *pool, uint32_t slot, uint16_t sourceAddr, uint8_t requestId,
                             uint32_t expiryMs);

#endif /* NWK_ROUTEDISC_HELPERS_H */
