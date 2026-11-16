#include "nwk_route.h"

#include "zb_utils.h"

/* R23.1: 3.6.4.2, 3.6.4.3, 3.6.4.8, 3.6.4.8.1 ok (Table 3-77's fields and the usage count, the ACTIVE and neighbour
   choices, the eviction and the invalidation; a routing table is a MAY and no route cache is kept);
   3.6.4.5.1, 3.6.4.5.2, 3.6.4.5.3 elsewhere (the discovery family). */
Nwk_RoutingTableEntry *Nwk_RouteOf(Nwk_RoutingTableEntry *pool, uint16_t dest)
{
    uint32_t i;

    for (i = 0; i < NWK_ROUTE_MAX; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (pool[i].destinationAddress == dest)
            return &pool[i];
    }

    return 0;
}

Nwk_RoutingTableEntry *Nwk_RouteFree(Nwk_RoutingTableEntry *pool)
{
    uint32_t i;

    for (i = 0; i < NWK_ROUTE_MAX; i++)
    {
        if (!pool[i].inUse)
            return &pool[i];
    }

    return 0;
}

/* A free slot first, else 3.6.4.8's ranking: the entry not used recently goes before one in active use, and among
   entries used equally recently the one used less often overall goes (docs/internals/conformance.md §2) */
Nwk_RoutingTableEntry *Nwk_RouteClaim(Nwk_RoutingTableEntry *pool)
{
    Nwk_RoutingTableEntry *victim;
    uint32_t i;

    victim = Nwk_RouteFree(pool);

    if (victim != 0)
        return victim;

    victim = &pool[0];

    for (i = 1; i < NWK_ROUTE_MAX; i++)
    {
        if (pool[i].ageMs < victim->ageMs)
            victim = &pool[i];
        else if (pool[i].ageMs == victim->ageMs && pool[i].totalUsageCount < victim->totalUsageCount)
            victim = &pool[i];
    }

    Zb_memset(victim, 0, (uint32_t)sizeof *victim);

    return victim;
}

/* How many entries are held, an INACTIVE one among them: 3.6.4.8.1 invalidates the routes through a broken link rather than deleting them, so 3.6.4.5.3's repair finds the entry */
uint32_t Nwk_RouteCount(const Nwk_RoutingTableEntry *pool)
{
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < NWK_ROUTE_MAX; i++)
    {
        if (pool[i].inUse)
            count++;
    }

    return count;
}

/* 3.6.4.8.1's invalidation: every route whose next hop is the broken link becomes Table 3-78's INACTIVE, once per entry, the rest of the entry standing */
uint32_t Nwk_RouteInvalidate(Nwk_RoutingTableEntry *pool, uint16_t brokenLink)
{
    uint32_t invalidated = 0;
    uint32_t i;

    for (i = 0; i < NWK_ROUTE_MAX; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (pool[i].nextHopAddress != brokenLink)
            continue;

        if (pool[i].status == NWK_ROUTE_INACTIVE)
            continue;

        pool[i].status = NWK_ROUTE_INACTIVE;
        invalidated++;
    }

    return invalidated;
}

/* 3.6.4.3's order (an ACTIVE entry, else a neighbour entry implying a direct hop, else the case that clause answers) and Table 3-77's TotalUsageCount for the entry it settles on (3.6.4.2) */
int Nwk_RouteNextHop(Nwk_RoutingTableEntry *routes, Nwk_NeighborTableEntry *neighbors, uint16_t dest, uint32_t nowMs,
                     uint16_t *outNextHop)
{
    Nwk_RoutingTableEntry *route;
    Nwk_NeighborTableEntry *neighbor;
    uint16_t nextHop;

    route = Nwk_RouteOf(routes, dest);

    if (route != 0 && route->status == NWK_ROUTE_ACTIVE)
    {
        route->ageMs = nowMs;

        if (route->totalUsageCount < NWK_ROUTE_USAGE_MAX)
            route->totalUsageCount++;

        nextHop = route->nextHopAddress;

        (void)Nwk_NeighborOutboundActivity(neighbors, nextHop);

        *outNextHop = nextHop;

        return 1;
    }

    neighbor = Nwk_NeighborOf(neighbors, dest);

    if (neighbor == 0)
        return 0;

    if (route == 0)
        route = Nwk_RouteClaim(routes);

    if (route != 0)
    {
        Zb_memset(route, 0, (uint32_t)sizeof *route);

        route->inUse = 1;
        route->destinationAddress = dest;
        route->status = NWK_ROUTE_ACTIVE;
        route->nextHopAddress = dest;
        route->ageMs = nowMs;
        route->totalUsageCount = 1;     
    }

    (void)Nwk_NeighborOutboundActivity(neighbors, dest);

    *outNextHop = dest;

    return 1;
}
