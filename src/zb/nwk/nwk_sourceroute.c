#include "nwk.h"

#include "nwk_sourceroute.h"

#include "zb_bstream.h"
#include "zb_time.h"
#include "zb_utils.h"

/* R23.1: 3.3.1.8.3, 3.4.5, 3.6.4.5.5 ok; Table 3-67's own row is this module's record. */

ZbStatus Nwk_RouteRecordParse(const uint8_t *payload, uint32_t payloadLen, uint16_t *relays, uint32_t relaysMax,
                              uint32_t *countOut)
{
    U_BStream stream;
    uint32_t count;
    uint32_t i;

    if (payload == 0 || relays == 0 || countOut == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payloadLen < 1)
        return ZB_ERR_BAD_ARGUMENT;

    count = payload[0];

    if (payloadLen != 1 + count * NWK_FRAME_RELAY_OCTETS)
        return ZB_ERR_BAD_ARGUMENT;

    if (count > relaysMax || count > NWK_MAX_RELAYS)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_bstream_init_const(&stream, payload + 1, payloadLen - 1);

    for (i = 0; i < count; i++)
        relays[i] = U_bstream_get_u16_le(&stream);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_BAD_ARGUMENT;

    *countOut = count;

    return ZB_OK;
}

ZbStatus Nwk_RouteRecordCompose(const uint16_t *relays, uint32_t count, uint8_t *out, uint32_t outCap,
                                uint32_t *outLen)
{
    U_BStream stream;
    uint32_t len;
    uint32_t i;

    if (out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (relays == 0 && count != 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (count > NWK_MAX_RELAYS)
        return ZB_ERR_BAD_ARGUMENT;

    len = 1 + count * NWK_FRAME_RELAY_OCTETS;

    if (outCap < len)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outCap);
    U_bstream_put_u8(&stream, (uint8_t)count);

    for (i = 0; i < count; i++)
        U_bstream_put_u16_le(&stream, relays[i]);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = len;

    return ZB_OK;
}

Nwk_SourceRouteEntry *Nwk_SourceRouteOf(Nwk_SourceRouteEntry *pool, uint16_t destination, uint32_t nowMs)
{
    Nwk_SourceRouteEntry *entry;
    uint32_t i;

    if (pool == 0)
        return 0;

    for (i = 0; i < NWK_SOURCE_ROUTE_MAX; i++)
    {
        entry = &pool[i];

        if (!entry->inUse || entry->destinationAddress != destination)
            continue;

        if (entry->inUse == NWK_SR_ROW_LEARNED && Zb_timeReached(nowMs, entry->expiresAtMs))
        {
            Zb_memset(entry, 0, (uint32_t)sizeof *entry);
            return 0;
        }

        return entry;
    }

    return 0;
}

/* The record arrives in the order it was collected, from its originator outward, which is 3.3.1.8.3's order for a
   frame back to it: the relay closest to that destination first. It is stored as it came. */
uint32_t Nwk_SourceRouteLearn(Nwk_SourceRouteEntry *pool, uint16_t destination, const uint16_t *relays, uint32_t count,
                              uint32_t nowMs)
{
    Nwk_SourceRouteEntry *entry;
    uint32_t verdict = NWK_SR_FULL;
    uint32_t i;

    if (pool == 0 || relays == 0 || count == 0 || count > NWK_MAX_SOURCE_ROUTE)
        return NWK_SR_FULL;

    entry = Nwk_SourceRouteOf(pool, destination, nowMs);

    if (entry == 0)
    {
        for (i = 0; i < NWK_SOURCE_ROUTE_MAX; i++)
        {
            if (pool[i].inUse)
                continue;

            entry = &pool[i];
            verdict = NWK_SR_LEARNED;
            break;
        }
    }
    else if (entry->relayCount == count
             && Zb_memcmp(entry->relayList, relays, count * (uint32_t)sizeof relays[0]) == 0)
    {
        verdict = NWK_SR_SAME;
    }
    else
    {
        verdict = NWK_SR_UPDATED;
    }

    if (entry == 0)
        return NWK_SR_FULL;

    Zb_memset(entry, 0, (uint32_t)sizeof *entry);

    entry->inUse = NWK_SR_ROW_LEARNED;
    entry->destinationAddress = destination;
    entry->relayCount = count;
    entry->expiresAtMs = nowMs + NWK_SOURCE_ROUTE_LIFETIME_MS;

    for (i = 0; i < count; i++)
        entry->relayList[i] = relays[i];

    return verdict;
}

ZbStatus Nwk_SourceRouteSeed(Nwk_SourceRouteEntry *pool, uint16_t destination, const uint16_t *relays, uint32_t count,
                             uint32_t nowMs)
{
    Nwk_SourceRouteEntry *entry;
    uint32_t i;

    if (pool == 0 || (relays == 0 && count != 0) || count > NWK_MAX_SOURCE_ROUTE)
        return ZB_ERR_BAD_ARGUMENT;

    if (count == 0)
    {
        (void)Nwk_SourceRouteForget(pool, destination);
        return ZB_OK;
    }

    entry = Nwk_SourceRouteOf(pool, destination, nowMs);

    for (i = 0; entry == 0 && i < NWK_SOURCE_ROUTE_MAX; i++)
    {
        if (!pool[i].inUse)
            entry = &pool[i];
    }

    if (entry == 0)
        return ZB_ERR_NO_SPACE;

    Zb_memset(entry, 0, (uint32_t)sizeof *entry);

    entry->inUse = NWK_SR_ROW_SEEDED;
    entry->destinationAddress = destination;
    entry->relayCount = count;

    for (i = 0; i < count; i++)
        entry->relayList[i] = relays[i];

    return ZB_OK;
}

uint32_t Nwk_SourceRouteExpire(Nwk_SourceRouteEntry *pool, uint32_t nowMs)
{
    uint32_t released = 0;
    uint32_t i;

    if (pool == 0)
        return 0;

    for (i = 0; i < NWK_SOURCE_ROUTE_MAX; i++)
    {
        if (pool[i].inUse != NWK_SR_ROW_LEARNED || !Zb_timeReached(nowMs, pool[i].expiresAtMs))
            continue;

        Zb_memset(&pool[i], 0, (uint32_t)sizeof pool[i]);
        released++;
    }

    return released;
}

int Nwk_SourceRouteForget(Nwk_SourceRouteEntry *pool, uint16_t destination)
{
    uint32_t i;

    for (i = 0; pool != 0 && i < NWK_SOURCE_ROUTE_MAX; i++)
    {
        if (pool[i].inUse && pool[i].destinationAddress == destination)
        {
            Zb_memset(&pool[i], 0, (uint32_t)sizeof pool[i]);
            return 1;
        }
    }

    return 0;
}
