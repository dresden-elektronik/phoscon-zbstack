#include "nwk_btt.h"

#include "zb_time.h"
#include "zb_utils.h"

/* R23.1: 3.6.6 ok (Table 3-78's record, the duplicate key, the relayed mark); its passive-ack consumer is nwk.c's. */

/*
 * A record for that (source, sequence) pair, live or expired: 3.6.6's dedup key, Table 3-81's minimum.
 */
Nwk_BroadcastTransactionRecord *Nwk_BttOf(Nwk_BroadcastTransactionRecord *pool, uint16_t src, uint8_t seq)
{
    uint32_t i;

    for (i = 0; i < NWK_BTT_MAX; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (pool[i].sourceAddress == src && pool[i].sequenceNumber == seq)
            return &pool[i];
    }

    return 0;
}

/* 3.6.6's aging sentence: a free slot before an expired one and, of the expired, the record that
   expires first (the order docs/internals/conformance.md §2 names), and the recycled slot emptied before it
   is filled */
Nwk_BroadcastTransactionRecord *Nwk_BttClaim(Nwk_BroadcastTransactionRecord *pool, uint32_t nowMs)
{
    Nwk_BroadcastTransactionRecord *expired;
    Nwk_BroadcastTransactionRecord *record;
    uint32_t i;

    for (i = 0; i < NWK_BTT_MAX; i++)
    {
        if (!pool[i].inUse)
            return &pool[i];
    }

    expired = 0;

    for (i = 0; i < NWK_BTT_MAX; i++)
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

/* 3.6.6's record of a broadcast this device originates (Table 3-81): its own address and the sequence number the frame took, the class it was aimed at, no stored frame, 0 where the table is full, which is the send's refusal (Table 3-84's 0xd2) */
Nwk_BroadcastTransactionRecord *Nwk_BttOpen(Nwk_BroadcastTransactionRecord *pool, uint16_t src, uint8_t seq, uint16_t dst, uint32_t nowMs,
                     uint32_t expiryMs)
{
    Nwk_BroadcastTransactionRecord *record;

    record = Nwk_BttOf(pool, src, seq);

    if (record == 0)
        record = Nwk_BttClaim(pool, nowMs);

    if (record == 0)
        return 0;

    Zb_memset(record, 0, (uint32_t)sizeof *record);

    record->inUse = 1;
    record->sourceAddress = src;
    record->sequenceNumber = seq;
    record->dst = dst;
    record->expiresAtMs = expiryMs;

    return record;
}

/*
 * How many records the table holds: a claim that recycles an expired record does not move it.
 */
uint32_t Nwk_BttCount(const Nwk_BroadcastTransactionRecord *pool)
{
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < NWK_BTT_MAX; i++)
    {
        if (pool[i].inUse)
            count++;
    }

    return count;
}

/* 3.6.6's passive acknowledgement: a duplicate at this table is one device's evidence that another relayed, so the record is marked and its retransmission withdrawn (docs/internals/conformance.md §2) */
int Nwk_BttMarkRelayed(Nwk_BroadcastTransactionRecord *record)
{
    if (record == 0 || record->relayedByNeighbor)
        return 0;

    record->relayedByNeighbor = 1;

    return 1;
}
