#include "nwk_discovery.h"

#include "zb_time.h"
#include "zb_utils.h"

/* R23.1: 3.6.4.2, 3.6.4.3, 3.6.4.5.1, 3.6.4.5.1.7 ok (the claim, the running and held lookups, the expiry and the
   removal; the routing entry's own half is nwk.c's); 2.4 elsewhere (ZDO and APS). */

/* Table 3-79's key is the pair the procedure compares: the initiator and the request id it numbered this with */
Nwk_RouteDiscoveryTableEntry *Nwk_DiscoveryOf(Nwk_RouteDiscoveryTableEntry *pool, uint16_t sourceAddr, uint8_t requestId)
{
    uint32_t i;

    for (i = 0; i < NWK_DISCOVERY_MAX; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (pool[i].sourceAddress == sourceAddr && pool[i].routeRequestId == requestId)
            return &pool[i];
    }

    return 0;
}

/* Free before expired, and the expired one that expires first: the transient table's reuse is 3.6.4.2's */
Nwk_RouteDiscoveryTableEntry *Nwk_DiscoveryClaim(Nwk_RouteDiscoveryTableEntry *pool, uint32_t nowMs)
{
    Nwk_RouteDiscoveryTableEntry *expired = 0;
    Nwk_RouteDiscoveryTableEntry *record;
    uint32_t i;

    for (i = 0; i < NWK_DISCOVERY_MAX; i++)
    {
        if (!pool[i].inUse)
            return &pool[i];
    }

    for (i = 0; i < NWK_DISCOVERY_MAX; i++)
    {
        record = &pool[i];

        if (!Zb_timeReached(nowMs, record->expiresAtMs))
            continue;

        if (expired == 0 || record->expiresAtMs < expired->expiresAtMs)
            expired = record;
    }

    if (expired == 0)
        return 0;

    Zb_memset(expired, 0, (uint32_t)sizeof *expired);

    return expired;
}

/* 3.6.4.3: the discovery this device already runs for that destination, which a second frame joins */
Nwk_RouteDiscoveryTableEntry *Nwk_DiscoveryRunning(Nwk_RouteDiscoveryTableEntry *pool, uint16_t sourceAddr, uint16_t destAddr)
{
    uint32_t i;

    for (i = 0; i < NWK_DISCOVERY_MAX; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (pool[i].sourceAddress != sourceAddr || pool[i].destAddr != destAddr)
            continue;

        return &pool[i];
    }

    return 0;
}

/* A claim that recycles an expired slot does not move the depth: the slot is in use either way */
uint32_t Nwk_DiscoveryCount(const Nwk_RouteDiscoveryTableEntry *pool)
{
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < NWK_DISCOVERY_MAX; i++)
    {
        if (pool[i].inUse)
            count++;
    }

    return count;
}

/* 3.6.4.5.1.7: the entries a second discovery for that destination would have to share the routing entry with */
uint32_t Nwk_DiscoveryHeldForDestination(const Nwk_RouteDiscoveryTableEntry *pool, uint16_t destAddr)
{
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < NWK_DISCOVERY_MAX; i++)
    {
        if (pool[i].inUse && pool[i].destAddr == destAddr)
            count++;
    }

    return count;
}

/* The entries one initiator is still running, this module's own bookkeeping: 3.6.4.5.1.7 keys the deletion on the
   destination, and the initiator's count is what the façade asks before it releases one */
uint32_t Nwk_DiscoveryHeldForSource(const Nwk_RouteDiscoveryTableEntry *pool, uint16_t sourceAddr)
{
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < NWK_DISCOVERY_MAX; i++)
    {
        if (pool[i].inUse && pool[i].sourceAddress == sourceAddr)
            count++;
    }

    return count;
}

/* 3.6.4.5.1.7: the route request timer expiry deletes the entry, the routing table's fate being the pipeline's */
uint32_t Nwk_DiscoveryExpire(Nwk_RouteDiscoveryTableEntry *pool, uint32_t nowMs)
{
    uint32_t expired = 0;
    uint32_t i;

    for (i = 0; i < NWK_DISCOVERY_MAX; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (!Zb_timeReached(nowMs, pool[i].expiresAtMs))
            continue;

        pool[i].inUse = 0;
        expired++;
    }

    return expired;
}

/* The removal 3.6.4.5.1.7's caller makes once a reply arrives: the entry goes, its fields answering for it, and no
   routing table entry is touched here */
Nwk_RouteDiscoveryTableEntry *Nwk_DiscoveryRemove(Nwk_RouteDiscoveryTableEntry *pool, uint16_t sourceAddr, uint8_t requestId)
{
    Nwk_RouteDiscoveryTableEntry *record = Nwk_DiscoveryOf(pool, sourceAddr, requestId);

    if (record == 0)
        return 0;

    record->inUse = 0;

    return record;
}
