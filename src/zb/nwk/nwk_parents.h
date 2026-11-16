#ifndef NWK_PARENTS_H
#define NWK_PARENTS_H

/*
 * 3.6.1.5's discovery table, the beacons it takes and its ranking; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "mac.h"
#include "nwk.h"

/* A beacon notification as Table 3-74's entry, or ZB_ERR_BAD_FRAME for one 3.6.1.5.1 discards whatever the request:
   no payload (rule 1), a protocol version other than 0x02 (rule 2) or a stack profile other than 0x02 (rule 3). */
ZbStatus Nwk_ParentFromBeacon(const Mac_BeaconNotification *beacon, Nwk_JoinParent *out);

/* Whether `a` is tried before `b`: a good LQA (`goodLqa` or more) before a marginal one, then Table I-6's hub
   connectivity, preferred parent and long uptime, then the newer NWK Update ID, wrap considered (3.6.1.5.2). */
int Nwk_ParentRanksAbove(const Nwk_JoinParent *a, const Nwk_JoinParent *b, uint32_t goodLqa);

/* An entry into the table: the same parent heard again updates its row, a free row takes a new one, and a full table
   gives its lowest-ranked row to a newcomer that ranks above it (3.6.1.5.2); ZB_ERR_NO_SPACE when it does not. */
ZbStatus Nwk_ParentAdmit(Nwk_JoinParent *pool, const Nwk_JoinParent *entry, uint32_t goodLqa);

/* The best-ranked row among those `eligible` names (bit i for row i), or NWK_JOIN_PARENT_MAX when it names none. */
uint32_t Nwk_ParentBest(const Nwk_JoinParent *pool, uint32_t eligible, uint32_t goodLqa);

/* Table 3-66's nwkGoodParentLQA as the configuration states it, its default where the configuration names none. */
uint32_t Nwk_ParentsGoodLqa(const Nwk_Nwk *self);

/* A running discovery's turn, after the MAC's: every beacon the scan notified taken through 3.6.1.5.1 into the table,
   then the scan's confirm made the discovery's. Nothing while no discovery runs, the beacon ring left to others. */
void Nwk_ParentsStep(Nwk_Nwk *self, uint32_t nowMs);

#endif /* NWK_PARENTS_H */
