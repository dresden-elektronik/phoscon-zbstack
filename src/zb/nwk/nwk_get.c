#include "nwk_get.h"

#include "nwk_neighbor.h"
#include "nwk_route.h"

/* R23.1: 3.2.2.27, 3.2.2.28 ok. */

/* One entry per network address, so the entries in use are the entries with unique addresses a report counts. */
uint32_t Nwk_NeighborTableEntries(const Nwk_Nwk *self)
{
    uint32_t count = 0;
    uint32_t i;

    if (self == 0)
        return 0;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (self->neighbors[i].inUse)
            count++;
    }

    return count;
}

const Nwk_NeighborTableEntry *Nwk_NeighborTableAt(const Nwk_Nwk *self, uint32_t index)
{
    uint32_t seen = 0;
    uint32_t i;

    if (self == 0)
        return 0;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!self->neighbors[i].inUse)
            continue;

        if (seen == index)
            return &self->neighbors[i];

        seen++;
    }

    return 0;
}

uint32_t Nwk_RouteTableEntries(const Nwk_Nwk *self)
{
    uint32_t count = 0;
    uint32_t i;

    if (self == 0)
        return 0;

    for (i = 0; i < NWK_ROUTE_MAX; i++)
    {
        if (self->routes[i].inUse)
            count++;
    }

    return count;
}

const Nwk_RoutingTableEntry *Nwk_RouteTableAt(const Nwk_Nwk *self, uint32_t index)
{
    uint32_t seen = 0;
    uint32_t i;

    if (self == 0)
        return 0;

    for (i = 0; i < NWK_ROUTE_MAX; i++)
    {
        if (!self->routes[i].inUse)
            continue;

        if (seen == index)
            return &self->routes[i];

        seen++;
    }

    return 0;
}
