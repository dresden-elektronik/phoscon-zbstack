#ifndef NWK_COST_H
#define NWK_COST_H

/*
 * The path cost metric over numbers alone; docs/internals/conformance.md §2 owns its contract.
 */

/* 3.6.4.1's C(P) scales each hop by the interface's InterfaceLinkCostScalar, printed with a default of 1. This stack
   drives one interface and takes that default, so the sums here are unscaled; a second interface would scale first. */

#include <stdint.h>

enum
{
    NWK_LQA_MAX = 0xff,             /* Table 3-75's LQA (LQI), the measurement Table 3-76 is indexed by */
    NWK_COST_MAX = 0xff,            /* 3.6.4.1's C(P) = min(Σ αᵢ·C(Dᵢ,Dᵢ₊₁), 0xff), the accumulated path cost */

    NWK_COST_UNMEASURED = 0x0,      /* Table 3-76's "C(i) = 0 | No LQA": no measurement, which is not "worst" */
    NWK_COST_BEST = 0x1,            /* the level of the best link the table prints */
    NWK_COST_WORST = 0x7,           /* the level of the worst, and (see nwk_cost.c) of an LQA of 0 as well */

    /* Table 3-76's six printed thresholds, each the exclusive lower bound of the level named and the inclusive
       upper bound of the level beneath it: cost 1 is "192 < LQA ≤ 255", cost 2 "128 < LQA ≤ 192", cost 3
       "96 < LQA ≤ 128", cost 4 "64 < LQA ≤ 96", cost 5 "32 < LQA ≤ 64", cost 6 "16 < LQA ≤ 32". */
    NWK_LQA_COST1_ABOVE = 192,
    NWK_LQA_COST2_ABOVE = 128,
    NWK_LQA_COST3_ABOVE = 96,
    NWK_LQA_COST4_ABOVE = 64,
    NWK_LQA_COST5_ABOVE = 32,
    NWK_LQA_COST6_ABOVE = 16
};

/* Table 3-76 as a function: the link cost of a measured LQA, 0 included. The argument is an octet, and a caller holding a
   wider measurement clamps it first, as `nwk_rx` does when it stores one. */
uint32_t Nwk_CostFromLqa(uint32_t lqa);

/* 3.6.4.5.1.2's "maximum of the incoming and outgoing costs for the neighbor": the greater, 0 only when
   both are 0 (the no-link-status symmetry that makes the outgoing cost the measured
   incoming one). */
uint32_t Nwk_CostCombine(uint32_t incoming, uint32_t outgoing);

/* 3.6.4.1's C(P) one hop further: the sum of a path cost and a link cost, clamped at NWK_COST_MAX (gap G3). */
uint32_t Nwk_CostAccumulate(uint32_t pathCost, uint32_t linkCost);

/* 3.6.4.5.3 step 2's loop test, the advertised path against the caller's local one. A local cost of 0 is this stack's
   "nothing recorded yet" and the caller's gate: Table 3-79 prints the field's meaning but no such sentinel. */
int Nwk_CostLoopFree(uint32_t advertisedPathCost, uint32_t localPathCost);

/* 3.6.4.5.1.2's "if the outgoing cost field of the entry has a value of 0, the frame is discarded", the argument being
   that field's octet: 0 is "no measurement" and not the best cost there is. */
int Nwk_CostUsable(uint32_t cost);

#endif /* NWK_COST_H */
