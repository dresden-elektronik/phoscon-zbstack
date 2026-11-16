#include "nwk_cost.h"

/* R23.1: 3.6.4.1, 3.6.4.5.1, 3.6.4.5.3 ok (Table 3-76's mapping, the worse direction, the saturating path cost and
   LoopFree); 3.6.4.1 ok (InterfaceLinkCostScalar is the interface's, taken as 1, which Table 3-66 prints in its 1-36 range
   and is the identity a single-interface device wants). */

/* Table 3-76's levels read from the top at the printed thresholds: an octet of 0 is the worst link, cost 7, not the cost 0 "no LQA" row the table also prints (docs/internals/conformance.md §2) */
uint32_t Nwk_CostFromLqa(uint32_t lqa)
{
    if (lqa > NWK_LQA_COST1_ABOVE)
        return NWK_COST_BEST;

    if (lqa > NWK_LQA_COST2_ABOVE)
        return 2;

    if (lqa > NWK_LQA_COST3_ABOVE)
        return 3;

    if (lqa > NWK_LQA_COST4_ABOVE)
        return 4;

    if (lqa > NWK_LQA_COST5_ABOVE)
        return 5;

    if (lqa > NWK_LQA_COST6_ABOVE)
        return 6;

    return NWK_COST_WORST;
}

/* 3.6.4.5.1.2's worse direction, the greater of the incoming and outgoing costs, which is also the value the relay increments the path cost field with before retransmitting; the clause's other half, a neighbour with no entry at all, is its caller's */
uint32_t Nwk_CostCombine(uint32_t incoming, uint32_t outgoing)
{
    return (incoming > outgoing) ? incoming : outgoing;
}

/* 3.6.4.1's sum, clamped at the 0xff its own C(P) prints as the ceiling of the whole path; clamping each hop is the same arithmetic as clamping the total */
uint32_t Nwk_CostAccumulate(uint32_t pathCost, uint32_t linkCost)
{
    if (pathCost > NWK_COST_MAX)
        pathCost = NWK_COST_MAX;

    return (linkCost > NWK_COST_MAX - pathCost) ? NWK_COST_MAX : pathCost + linkCost;
}

/* 3.6.4.5.3 step 2's LoopFree at the printed boundary, an equal cost being no loop. Whether an as-good route is then taken is step 3's and the caller's: a route still under discovery takes it, one already discovered needs a strictly smaller cost */
int Nwk_CostLoopFree(uint32_t advertisedPathCost, uint32_t localPathCost)
{
    return (advertisedPathCost <= localPathCost) ? 1 : 0;
}

/* 3.6.4.5.1.2's discard on an entry's outgoing cost of 0: the field and not the measurement */
int Nwk_CostUsable(uint32_t cost)
{
    return cost != 0;
}
