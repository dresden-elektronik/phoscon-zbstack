#ifndef NWK_ROUTE_H
#define NWK_ROUTE_H

/*
 * The route table of Table 3-77 and Table 3-78's statuses; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "nwk_neighbor.h"
#include "zb_limits.h"

enum
{
    /* the nwkRouteTable of NIB attribute 0x8b, whose entries Table 3-77 describes */
    NWK_ROUTE_MAX = ZB_LIMIT_NWK_ROUTE,

    /* Route statuses, Table 3-78. DISCOVERY_UNDERWAY is back: 3.6.4.5.1 creates an entry
       carrying it, 3.6.4.5.2 changes it to ACTIVE, and 3.6.4.5.1.7 deletes an entry that still carries it. */
    NWK_ROUTE_ACTIVE = 0x0,
    NWK_ROUTE_DISCOVERY_UNDERWAY = 0x1,
    NWK_ROUTE_DISCOVERY_FAILED = 0x2,
    NWK_ROUTE_INACTIVE = 0x3
};

/* Table 3-77's TotalUsageCount is a "32-bit saturating counter", so its ceiling is 0xffffffff. A macro and
   not an enum member, for the reason `security.h` states for SECURITY_FRAME_COUNTER_LAST: an enumeration
   value must be representable as an int (C99 6.7.2.2). */
#define NWK_ROUTE_USAGE_MAX 0xffffffff

/* Table 3-77, the routing table entry: `inUse` is this stack's; `destinationAddress`, `nextHopAddress` and `ageMs` are its Destination
   address, Next-hop address and RecentActivity, `ageMs` a nowMs stamp of 4 octets where that row counts
   nwkLinkStatusPeriod ticks in 1. Expired is not held. */
typedef struct Nwk_RoutingTableEntry
{
    int inUse;
    uint16_t destinationAddress;
    uint32_t status;
    uint16_t sequenceNumber;
    int sequenceNumberValid;
    int manyToOne;
    int noRouteCache;
    int routeRecordRequired;
    uint32_t totalUsageCount;
    uint16_t nextHopAddress;
    uint32_t ageMs;
} Nwk_RoutingTableEntry;

/* The entry for that destination, or 0 when the table has none (3.6.4.3). */
Nwk_RoutingTableEntry *Nwk_RouteOf(Nwk_RoutingTableEntry *pool, uint16_t dest);

/* A slot for a new entry, and no eviction of an old one: 0 when the table is full. */
Nwk_RoutingTableEntry *Nwk_RouteFree(Nwk_RoutingTableEntry *pool);

/* A claim's slot: 3.6.4.8's eviction, ranked by Table 3-77's TotalUsageCount and RecentActivity. */
Nwk_RoutingTableEntry *Nwk_RouteClaim(Nwk_RoutingTableEntry *pool);

/* How many slots of the pool hold a route. */
uint32_t Nwk_RouteCount(const Nwk_RoutingTableEntry *pool);

/* 3.6.4.8.1's invalidation: every entry whose next hop is the broken link becomes Table 3-78's INACTIVE. */
uint32_t Nwk_RouteInvalidate(Nwk_RoutingTableEntry *pool, uint16_t brokenLink);

/* 3.6.4.3's order of choices, with Table 3-77's TotalUsageCount moved and its next hop's activity counter beside it. */
int Nwk_RouteNextHop(Nwk_RoutingTableEntry *routes, Nwk_NeighborTableEntry *neighbors, uint16_t dest, uint32_t nowMs,
                     uint16_t *outNextHop);

#endif /* NWK_ROUTE_H */
