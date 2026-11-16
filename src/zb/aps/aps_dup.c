#include "aps_dup.h"

#include "aps.h"
#include "zb_time.h"

/* R23.1 2.2.5.1.7 2.2.5.1.8 2.2.8.4.2 2.2.8.4.5 ok (the key's fourth part is the block number, which the receive
   path passes). docs/internals/conformance.md pages 88, 101, 103. */

/*
 * Read and written in one act: 1 when this frame repeats a record this module already took a delivery decision
 * for, 0 when its record now exists. The key is the printed record's first two parts (the NWK source and
 * 2.2.5.1.7's counter); a record past its lifetime is free again, and a full pool replaces the oldest rather than
 * lose a delivery. Ages are differences on the caller's clock, so its wrap orders nothing wrongly.
 */
int Aps_DupSeen(Aps_Dup *pool, uint16_t srcAddress, uint8_t apsCounter, uint8_t blockNumber, uint32_t nowMs)
{
    Aps_Dup *slot;
    uint32_t age;
    uint32_t oldestAge;
    uint32_t i;

    if (pool == 0)
        return 0;

    for (i = 0; i < APS_DUP_MAX; i++)
    {
        if (pool[i].inUse && pool[i].srcAddress == srcAddress && pool[i].apsCounter == apsCounter
            && pool[i].blockNumber == blockNumber && Zb_timeWithin(nowMs, pool[i].seenMs, APS_DUP_LIFETIME_MS))
            return 1;
    }

    slot = 0;
    oldestAge = 0;

    for (i = 0; i < APS_DUP_MAX; i++)
    {
        age = nowMs - pool[i].seenMs;

        if (!pool[i].inUse || age >= APS_DUP_LIFETIME_MS)
        {
            slot = &pool[i];
            break;
        }

        if (slot == 0 || age > oldestAge)
        {
            slot = &pool[i];
            oldestAge = age;
        }
    }

    slot->inUse = 1;
    slot->srcAddress = srcAddress;
    slot->apsCounter = apsCounter;
    slot->blockNumber = blockNumber;
    slot->seenMs = nowMs;

    return 0;
}
