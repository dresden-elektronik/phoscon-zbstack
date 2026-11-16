#ifndef NWK_SOURCEROUTE_H
#define NWK_SOURCEROUTE_H

/* 3.4.5's route record command, 3.6.4.5.5's initiation and processing of it, and Table 3-67's source route table
   that its answer fills; docs/internals/conformance.md owns the clause marks and docs/internals/conformance.md §2 the deferrals. */

#include <stdint.h>

#include "nwk_frame.h"
#include "zb_limits.h"
#include "zb_status.h"

enum
{
    /* Table 3-66's nwkRouteRecordTable, NIB attribute 0x9c, a house size like the routing table's */
    NWK_SOURCE_ROUTE_MAX = ZB_LIMIT_NWK_SOURCE_ROUTE,
    NWK_SOURCE_ROUTE_LIFETIME_MS = 60000, /* how long a record outlives its own frame: no clause prints one */

    /* the notice ring's depth: one record's destination and the rows of its twelve relays, with room to spare */
    NWK_SOURCE_ROUTE_NOTICE_MAX = 16
};

/* A row's `inUse`: free, learned from a record and held for its lifetime, or seeded by the higher layer and held
   until a record or a 0x0b replaces it. */
enum
{
    NWK_SR_ROW_FREE = 0,
    NWK_SR_ROW_LEARNED = 1,
    NWK_SR_ROW_SEEDED = 2
};

/* One row of the source route table: the destination a record was learned for, and the relays that lead to it in
   3.3.1.8.3's order, the relay next to the destination first; Table 3-67 prints its Path the other way round. */
typedef struct Nwk_SourceRouteEntry
{
    int inUse;
    uint16_t destinationAddress;
    uint32_t relayCount;
    uint16_t relayList[NWK_MAX_SOURCE_ROUTE];
    uint32_t expiresAtMs;
} Nwk_SourceRouteEntry;

enum
{
    NWK_SR_LEARNED = 0,     /* the destination had no record and now has one */
    NWK_SR_UPDATED = 1,     /* it had one, and 3.6.4.5.5 replaces it */
    NWK_SR_FULL = 2,        /* no row free and none expired */
    NWK_SR_SAME = 3         /* it had the same relays, and only the lifetime starts again */
};

/* Why a row changed, for the higher layer: a lifetime's expiry and the higher layer's own seed are not told. */
enum
{
    NWK_SR_NOTICE_LEARNED = 1,      /* a record gave a destination with no row its relays */
    NWK_SR_NOTICE_CHANGED = 2,      /* a record replaced the relays a row held */
    NWK_SR_NOTICE_DIRECT = 3,       /* a record said the route is direct, and the row went */
    NWK_SR_NOTICE_FAILED = 4        /* a 0x0b source route failure removed the row */
};

/* One change of the table, the relays in the row's own order; none when the row went. */
typedef struct Nwk_SourceRouteNotice
{
    uint16_t destinationAddress;
    uint32_t reason;
    uint32_t relayCount;
    uint16_t relayList[NWK_MAX_SOURCE_ROUTE];
} Nwk_SourceRouteNotice;

/* 3.4.5's payload: Figure 3-16's relay count and relay list, count first. */
ZbStatus Nwk_RouteRecordParse(const uint8_t *payload, uint32_t payloadLen, uint16_t *relays, uint32_t relaysMax,
                              uint32_t *countOut);

/* The same payload as this device writes it, with its own address appended to the record it forwards. */
ZbStatus Nwk_RouteRecordCompose(const uint16_t *relays, uint32_t count, uint8_t *out, uint32_t outCap,
                                uint32_t *outLen);

/* Table 3-67's row for that destination, 0 when there is none or it has expired. */
Nwk_SourceRouteEntry *Nwk_SourceRouteOf(Nwk_SourceRouteEntry *pool, uint16_t destination, uint32_t nowMs);

/* 3.6.4.5.5's last paragraph: the record replaces what this device held for that destination. */
uint32_t Nwk_SourceRouteLearn(Nwk_SourceRouteEntry *pool, uint16_t destination, const uint16_t *relays, uint32_t count,
                              uint32_t nowMs);

/* The higher layer's row for `destination`, held until a record or a 0x0b replaces it; no relays let the row go.
   ZB_ERR_NO_SPACE when no row is free. */
ZbStatus Nwk_SourceRouteSeed(Nwk_SourceRouteEntry *pool, uint16_t destination, const uint16_t *relays, uint32_t count,
                             uint32_t nowMs);

/* Rows whose lifetime ran out, as the number released; a seeded row has none. */
uint32_t Nwk_SourceRouteExpire(Nwk_SourceRouteEntry *pool, uint32_t nowMs);

/* The row for `destination` let go, for a record that says the route to it is direct; 1 when there was one. */
int Nwk_SourceRouteForget(Nwk_SourceRouteEntry *pool, uint16_t destination);

#endif
