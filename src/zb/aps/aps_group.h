#ifndef APS_GROUP_H
#define APS_GROUP_H

/*
 * The group table of band A's APS sub-layer: the Table 2-25 entry, the constants the APSME services of
 * 2.2.4.5 judge against, and the reads the pipeline runs on it. Every operation takes the pool
 * from its caller; the parameter doors of Tables 2-14, 2-16 and 2-18, the `groupRefusals` count and the
 * fan-out that indicates one instance per member stay with the façade that answers the primitive. Table
 * 2-24 prints `apsGroupTable` as "Variable" and 2.2.8.3.1 prints no size, so the pool is the house's and
 * full is refusal and count (§4.3).
 */

#include <stdint.h>

#include "zb_limits.h"

enum
{
    /* 2.2.8.3.1's {(g - ep …)} flattened into pairs: a group id in several entries, an endpoint in several
       groups (Table 2-25) */
    APS_GROUP_MAX = ZB_LIMIT_APS_GROUP,

    /* Tables 2-14, 2-16 and 2-18 print "0x01 – 0xfe": 0x00 is the ZDO, 0xff names every endpoint */
    APS_GROUP_ENDPOINT_FIRST = 0x01,
    APS_GROUP_ENDPOINT_LAST = 0xfe,

    /* not a printed value: an index one past the pool, which no entry of it can ever be */
    APS_NO_GROUP_MEMBER = APS_GROUP_MAX
};

/*
 * One entry: one pair of Table 2-25's "Group ID" with one endpoint of its "Endpoint List". The entry states
 * membership and nothing else, because Table 2-25 prints two fields and chapter 2 defines no other. `inUse`
 * is the pool's own bookkeeping, and `Aps_Init`'s zeroing *is* Table 2-24's printed "Null set" default.
 */
typedef struct Aps_Group
{
    int inUse;                    /* 1 while this slot holds a pair */
    uint16_t groupAddress;        /* Table 2-25's Group ID, every uint16_t in range */
    uint8_t endpoint;             /* one member of Table 2-25's Endpoint List */
} Aps_Group;

/* The entry for that (group id, endpoint) pair, or 0 when the table holds no such pair
   (2.2.4.5.1.3, 2.2.4.5.3.3). */
Aps_Group *Aps_GroupFind(Aps_Group *pool, uint16_t groupAddress, uint8_t endpoint);

/* A slot a new pair may fill, and no eviction of an old one: 0 when the table is full
   (Table 2-15's TABLE_FULL). */
Aps_Group *Aps_GroupFree(Aps_Group *pool);

/* The next member of that group at or after index `from`, or APS_NO_GROUP_MEMBER (2.2.8.4.2's fan-out). */
uint32_t Aps_GroupMemberAt(const Aps_Group *pool, uint16_t groupAddress, uint32_t from);

/* How many pairs the table holds: the façade's `Aps_GroupQueue`. */
uint32_t Aps_GroupCount(const Aps_Group *pool);

/* APSME-ADD-GROUP's act on the pool (2.2.4.5.1): SUCCESS, or TABLE_FULL when no slot is free. */
uint32_t Aps_GroupAdd(Aps_Group *pool, uint16_t groupAddress, uint8_t endpoint);

/* APSME-REMOVE-GROUP's act on the pool (2.2.4.5.3): SUCCESS for the pair it cleared, INVALID_GROUP for a
   pair the table does not hold. */
uint32_t Aps_GroupRemove(Aps_Group *pool, uint16_t groupAddress, uint8_t endpoint);

/* APSME-REMOVE-ALL-GROUPS' act on the pool (2.2.4.5.5): every pair carrying that endpoint cleared,
   SUCCESS either way. */
uint32_t Aps_GroupRemoveAll(Aps_Group *pool, uint8_t endpoint);

#endif /* APS_GROUP_H */
