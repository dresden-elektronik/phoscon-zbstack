#ifndef APS_DUP_H
#define APS_DUP_H

/*
 * The duplicate rejection table of band A's APS sub-layer: the record and the one read the receive pipeline runs on
 * it, whether this frame repeats a record the table already holds, its own record being made in the same act. The
 * pool arrives from its caller; `rxDuplicateDrops` stays at the call site. The record's three printed parts and
 * Table 2-23's size floor of 1 are the clause's; the pool, its replace-oldest eviction and the record's lifetime
 * are band A's (docs/internals/coding-rules.md §4.3).
 */

#include <stdint.h>

#include "zb_limits.h"

enum
{
    /* the printed record's three parts, band A's size against Table 2-23's floor of 1 */
    APS_DUP_MAX = ZB_LIMIT_APS_DUP,
    APS_MIN_DUPLICATE_REJECTION_TABLE_SIZE = 1   /* apscMinDuplicateRejectionTableSize, Table 2-23 */
};

/*
 * One record, in the three parts 2.2.8.4.2 prints. The source address can only be the NWK source of the
 * indication (an APS header carries no device address at all) and the APS counter is 2.2.5.1.7's octet.
 * `seenMs` is the timing information: a record past APS_DUP_LIFETIME_MS (aps.h) names no frame that can arrive again,
 * and a full pool drops the oldest. The key carries the block number as its fourth part, because one counter serves every block of a
 * fragmented transaction and the three printed parts alone would read the second block as a repeat of the first.
 * A frame that is not fragmented carries 0 there.
 */
typedef struct Aps_Dup
{
    int inUse;
    uint16_t srcAddress;          /* the NWK originator (Table 3-4), not the hop that carried it */
    uint8_t apsCounter;           /* 2.2.5.1.7's octet, as the frame carried it */
    uint8_t blockNumber;          /* the block number for a fragmented frame, 0 for any other */
    uint32_t seenMs;              /* the printed "timing information": the eviction's key and nothing else */
} Aps_Dup;

/* 1 when that (source address, APS counter) pair is recorded within its lifetime, 0 when its record now exists: a
   hit returns before the pool is written and refreshes nothing (2.2.8.4.2). A pool that is not there records nothing
   and rejects nothing, which is the one answer that loses no frame. */
int Aps_DupSeen(Aps_Dup *pool, uint16_t srcAddress, uint8_t apsCounter, uint8_t blockNumber, uint32_t nowMs);

#endif /* APS_DUP_H */
