#ifndef NWK_BTT_H
#define NWK_BTT_H

/*
 * The broadcast transaction table of Table 3-81; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "nwk_frame.h"
#include "zb_limits.h"

enum
{
    /* the nwkBroadcastTransactionTable of NIB attribute 0x98; Table 3-81 names the entry */
    NWK_BTT_MAX = ZB_LIMIT_NWK_BTT
};

/* 3.6.6 and Table 3-81, the broadcast transaction record: `sourceAddress`, `sequenceNumber` and `expiresAtMs` are its
   Source Address, Sequence Number and Expiration Time; every other field is this stack's. */
typedef struct Nwk_BroadcastTransactionRecord
{
    int inUse;
    uint16_t sourceAddress;
    uint16_t dst;
    uint8_t sequenceNumber;
    uint32_t expiresAtMs;
    uint32_t relayed;
    uint32_t nextRelayMs;
    int relayedByNeighbor;
    uint32_t npduLen;
    uint32_t headerLen;
    int reprotect;
    int originates;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
} Nwk_BroadcastTransactionRecord;

/* The record of that (source, sequence) pair, live or expired (3.6.6). */
Nwk_BroadcastTransactionRecord *Nwk_BttOf(Nwk_BroadcastTransactionRecord *pool, uint16_t src, uint8_t seq);

/* A slot a new record may fill: free, else the least-expired of the expired, else 0 (3.6.6). */
Nwk_BroadcastTransactionRecord *Nwk_BttClaim(Nwk_BroadcastTransactionRecord *pool, uint32_t nowMs);

/* 3.6.6's passive-acknowledgment window for a broadcast this device originates: no stored frame, and 0 when nothing
   is free or expired, which the caller refuses as Table 3-84's BT_TABLE_FULL. */
Nwk_BroadcastTransactionRecord *Nwk_BttOpen(Nwk_BroadcastTransactionRecord *pool, uint16_t src, uint8_t seq, uint16_t dst, uint32_t nowMs,
                     uint32_t expiryMs);

/* How many records the pool holds. */
uint32_t Nwk_BttCount(const Nwk_BroadcastTransactionRecord *pool);

/* 3.6.6's passive acknowledgement, the mark a record carries: 1 the first time it lands and 0 when it was already
   there, which counts one acknowledgement rather than every copy of a flood. */
int Nwk_BttMarkRelayed(Nwk_BroadcastTransactionRecord *record);

#endif /* NWK_BTT_H */
