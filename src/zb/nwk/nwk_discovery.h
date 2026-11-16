#ifndef NWK_DISCOVERY_H
#define NWK_DISCOVERY_H

/*
 * The route discovery table of Table 3-79; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "zb_limits.h"

enum
{
    /* the pool of Table 3-79's entries; R23.1 prints no number, so it is the house's */
    NWK_DISCOVERY_MAX = ZB_LIMIT_NWK_DISCOVERY,

    NWK_ROUTE_DISCOVERY_TIME_MS = 10000 /* nwkcRouteDiscoveryTime, Table 3-65: 0x2710 msec at 2.4 GHz */
};

/* Table 3-79, the route discovery table entry: every row is held (Route request ID `routeRequestId`, Source/Sender
   address `sourceAddress`/`senderAddress`, Forward/Residual cost `forwardCost`/`residualCost`), `inUse` and `destAddr` are
   this stack's, and `expiresAtMs` answers Expiration time as a nowMs deadline of 4 octets where the row counts down 2. */
typedef struct Nwk_RouteDiscoveryTableEntry
{
    int inUse;
    uint8_t routeRequestId;
    uint16_t sourceAddress;
    uint16_t senderAddress;
    uint8_t forwardCost;
    uint8_t residualCost;
    uint32_t expiresAtMs;
    uint16_t destAddr;
} Nwk_RouteDiscoveryTableEntry;

/* The entry for that (source address, route request ID) pair, live or expired, or 0 when the pool holds none. */
Nwk_RouteDiscoveryTableEntry *Nwk_DiscoveryOf(Nwk_RouteDiscoveryTableEntry *pool, uint16_t sourceAddr, uint8_t requestId);

/* The discovery running for that destination, 3.6.4.3's second frame waiting on it. */
Nwk_RouteDiscoveryTableEntry *Nwk_DiscoveryRunning(Nwk_RouteDiscoveryTableEntry *pool, uint16_t sourceAddr, uint16_t destAddr);

/* The slot a claim may take: free, else the expired entry that expires first, cleared as it is handed over; 0 when every slot is live. */
Nwk_RouteDiscoveryTableEntry *Nwk_DiscoveryClaim(Nwk_RouteDiscoveryTableEntry *pool, uint32_t nowMs);

/* How many slots hold a discovery: a claim that recycles an expired one does not move the number. */
uint32_t Nwk_DiscoveryCount(const Nwk_RouteDiscoveryTableEntry *pool);

/* The live entries held for a destination, and for an initiator (3.6.4.5.1.7 for the first, this module's own count for
   the second), asked after the release. */
uint32_t Nwk_DiscoveryHeldForDestination(const Nwk_RouteDiscoveryTableEntry *pool, uint16_t destAddr);
uint32_t Nwk_DiscoveryHeldForSource(const Nwk_RouteDiscoveryTableEntry *pool, uint16_t sourceAddr);

/* 3.6.4.5.1.7's timer, deleting what has expired at `nowMs`; a released slot keeps its octets until a claim recycles
   it. */
uint32_t Nwk_DiscoveryExpire(Nwk_RouteDiscoveryTableEntry *pool, uint32_t nowMs);

/* Delete the entry for that key, answering the released record with its fields intact, or 0 when none matched. */
Nwk_RouteDiscoveryTableEntry *Nwk_DiscoveryRemove(Nwk_RouteDiscoveryTableEntry *pool, uint16_t sourceAddr, uint8_t requestId);

#endif /* NWK_DISCOVERY_H */
