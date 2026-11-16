#include "nwk.h"

#include "nwk_neighbor.h"

#include "nwk_cost.h"

#include "zb_time.h"
#include "zb_utils.h"

/* R23.1: 3.6.1.6.1.1, 3.6.1.6.1.3, 3.6.1.9, 3.6.3, 3.6.4.4.4, 3.6.4.8, 3.6.4.3, 3.6.6 ok (3.6.1.9's addressing is the
   stochastic kind, which `nwk_join.c` draws); 3.6.4.4.3 elsewhere (`nwk_linkstatus.c` holds the rank and the
   promotion); 3.6.2.2, 3.6.2.3, 3.6.4.4.1, 3.6.4.5.1 elsewhere. */

/* Table 3-75's entry for that address, if there is one: the table is fed by observation, so the transmit half reads what its owner put in it */
Nwk_NeighborTableEntry *Nwk_NeighborOf(Nwk_NeighborTableEntry *pool, uint16_t address)
{
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (pool[i].networkAddress == address)
            return &pool[i];
    }

    return 0;
}

int Nwk_NeighborRestsReceiver(Nwk_NeighborTableEntry *pool, uint16_t address)
{
    const Nwk_NeighborTableEntry *entry = Nwk_NeighborOf(pool, address);

    if (entry == 0 || entry->deviceType != NWK_DEVICE_END_DEVICE || entry->rxOnWhenIdle)
        return 0;

    return entry->relationship == NWK_REL_CHILD || entry->relationship == NWK_REL_UNAUTHENTICATED_CHILD;
}

/* The slot a new entry needs: a free one, else 3.6.4.4.4's MAY to reuse a stale router entry (end devices never stale) the claim's order being docs/internals/conformance.md §2's */
Nwk_NeighborTableEntry *Nwk_NeighborFree(Nwk_NeighborTableEntry *pool)
{
    Nwk_NeighborTableEntry *exchange;
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!pool[i].inUse)
            return &pool[i];
    }

    exchange = 0;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (pool[i].deviceType == NWK_DEVICE_END_DEVICE)
            continue;

        if (pool[i].age <= NWK_ROUTER_AGE_LIMIT)
            continue;

        if (exchange == 0 || pool[i].age > exchange->age)
            exchange = &pool[i];
    }

    if (exchange != 0)
        Zb_memset(exchange, 0, (uint32_t)sizeof *exchange);

    return exchange;
}

/* 3.6.4.4.4 in Table 3-75's unit: past nwkRouterAgeLimit the outgoing cost goes to 0, counted from the last link status, or from the entry's making when none has come */
uint32_t Nwk_NeighborAge(Nwk_NeighborTableEntry *pool, uint32_t nowMs)
{
    Nwk_NeighborTableEntry *neighbor;
    uint32_t retired = 0;
    uint32_t ticks;
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        neighbor = &pool[i];

        if (!neighbor->inUse)
            continue;

        if (neighbor->ageFromMs == 0)
            continue;

        ticks = (uint32_t)(nowMs - neighbor->ageFromMs) / NWK_LINK_STATUS_PERIOD_MS;

        if (ticks > NWK_AGE_UNBOUNDED)
            ticks = NWK_AGE_UNBOUNDED;

        neighbor->age = ticks;

        if (neighbor->deviceType == NWK_DEVICE_END_DEVICE)
            continue;

        if (ticks <= NWK_ROUTER_AGE_LIMIT)
            continue;

        if (neighbor->outgoingCost == 0)
            continue;

        neighbor->outgoingCost = 0;
        retired++;
    }

    return retired;
}

void Nwk_NeighborLqaSample(Nwk_NeighborTableEntry *entry, uint32_t raw)
{
    uint8_t newest = (uint8_t)(raw > NWK_LQA_MAX ? NWK_LQA_MAX : raw);
    uint8_t low = newest;
    uint8_t high = newest;

    if (entry->lqaRawCount == 0)
        entry->lqi = newest;
    else
    {
        low = newest < entry->lqaRaw[0] ? newest : entry->lqaRaw[0];
        high = newest < entry->lqaRaw[0] ? entry->lqaRaw[0] : newest;
        entry->lqi = low;
    }

    if (entry->lqaRawCount >= 2)
    {
        if (entry->lqaRaw[1] > high)
            entry->lqi = high;
        else if (entry->lqaRaw[1] > low)
            entry->lqi = entry->lqaRaw[1];
    }

    entry->lqaRaw[1] = entry->lqaRaw[0];
    entry->lqaRaw[0] = newest;

    if (entry->lqaRawCount < 2)
        entry->lqaRawCount++;
}

/* 3.6.4.8's failure counter for each neighbour an outgoing link exists to, one per failed transmit and saturating at Table 3-75's octet */
uint32_t Nwk_NeighborTxFailure(Nwk_NeighborTableEntry *pool, uint16_t address)
{
    Nwk_NeighborTableEntry *neighbor;

    neighbor = Nwk_NeighborOf(pool, address);

    if (neighbor == 0)
        return 0;

    if (neighbor->transmitFailures < NWK_TRANSMIT_FAILURE_MAX)
        neighbor->transmitFailures++;

    return neighbor->transmitFailures;
}

/* The same counter's other direction: a transmit that succeeded is not a failure, and the count starts again. */
void Nwk_NeighborTxSuccess(Nwk_NeighborTableEntry *pool, uint16_t address)
{
    Nwk_NeighborTableEntry *neighbor;

    neighbor = Nwk_NeighborOf(pool, address);

    if (neighbor != 0)
        neighbor->transmitFailures = 0;
}

/* 3.6.4.3's RouterOutboundActivity for the next hop a forwarding lookup settled on, saturating at Table 3-75's octet */
uint32_t Nwk_NeighborOutboundActivity(Nwk_NeighborTableEntry *pool, uint16_t address)
{
    Nwk_NeighborTableEntry *neighbor;

    neighbor = Nwk_NeighborOf(pool, address);

    if (neighbor == 0)
        return 0;

    if (neighbor->routerOutboundActivity < NWK_ROUTER_ACTIVITY_MAX)
        neighbor->routerOutboundActivity++;

    return neighbor->routerOutboundActivity;
}

/* 3.6.4.3's RouterInboundActivity for the SrcAddr's entry: the same octet and the same ceiling */
uint32_t Nwk_NeighborInboundActivity(Nwk_NeighborTableEntry *pool, uint16_t address)
{
    Nwk_NeighborTableEntry *neighbor;

    neighbor = Nwk_NeighborOf(pool, address);

    if (neighbor == 0)
        return 0;

    if (neighbor->routerInboundActivity < NWK_ROUTER_ACTIVITY_MAX)
        neighbor->routerInboundActivity++;

    return neighbor->routerInboundActivity;
}

/* Table 3-75's other half of both counters: down by one once every nwkLinkStatusPeriod, resting at 0. */
void Nwk_NeighborActivityDecay(Nwk_NeighborTableEntry *pool)
{
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (pool[i].routerOutboundActivity != 0)
            pool[i].routerOutboundActivity--;

        if (pool[i].routerInboundActivity != 0)
            pool[i].routerInboundActivity--;
    }
}

/*
 * How many slots hold a neighbor: the façade's `Nwk_NeighborQueue`.
 */
uint32_t Nwk_NeighborCount(const Nwk_NeighborTableEntry *pool)
{
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (pool[i].inUse)
            count++;
    }

    return count;
}

void Nwk_NeighborSecurityTimerArm(Nwk_NeighborTableEntry *entry, uint32_t seconds, uint32_t nowMs)
{
    if (entry == 0)
        return;

    entry->securityTimer = seconds;
    entry->securityTimerMs = nowMs;
}

int Nwk_NeighborSecurityTimerTick(Nwk_NeighborTableEntry *entry, uint32_t nowMs)
{
    if (entry == 0 || entry->securityTimer == 0)
        return 0;

    while (entry->securityTimer != 0 && nowMs - entry->securityTimerMs >= 1000)
    {
        entry->securityTimerMs = entry->securityTimerMs + 1000;
        entry->securityTimer--;
    }

    return entry->securityTimer == 0 ? 1 : 0;
}
