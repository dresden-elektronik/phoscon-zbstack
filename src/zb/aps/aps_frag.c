#include "aps_frag.h"

#include "zb_time.h"
#include "zb_utils.h"

/* R23.1 2.2.8.4.5, 2.2.8.4.5.2, 2.2.8.4.5.3, 2.2.8.4.5.4 ok at apscWindowSize 1. docs/internals/conformance.md pages 103-105. */

uint32_t Aps_FragBlockCount(uint32_t asduLength, uint32_t blockCapacity)
{
    uint32_t count;

    if (asduLength == 0 || blockCapacity == 0)
        return 0;

    count = (asduLength + blockCapacity - 1) / blockCapacity;

    if (count > (uint32_t)APS_FRAG_MAX_BLOCKS)
        return 0;

    return count;
}

uint8_t Aps_FragBlockNumber(uint32_t index, uint32_t totalBlocks)
{
    if (index == 0)
        return (uint8_t)totalBlocks;

    if (index == 1)
        return 0x01;

    return (uint8_t)(index & 0xff);
}

uint32_t Aps_FragSubField(uint32_t index)
{
    return index == 0 ? (uint32_t)APS_FRAG_FIRST : (uint32_t)APS_FRAG_SUBSEQUENT;
}

const uint8_t *Aps_FragBlock(const uint8_t *asdu, uint32_t asduLength, uint32_t blockCapacity, uint32_t index,
                             uint32_t *outLength)
{
    uint32_t offset;

    if (outLength != 0)
        *outLength = 0;

    if (asdu == 0 || blockCapacity == 0 || outLength == 0)
        return 0;

    offset = index * blockCapacity;

    if (offset >= asduLength)
        return 0;

    *outLength = (asduLength - offset) < blockCapacity ? (asduLength - offset) : blockCapacity;

    return asdu + offset;
}

/* The block number a block's own field states, turned into the zero-based index the buffer is written at: the first
   block states the total, and every block after it states its own index. */
static int apsFragIndex(uint32_t fragmentation, uint8_t blockNumber, uint32_t totalBlocks, uint32_t *outIndex)
{
    if (fragmentation == (uint32_t)APS_FRAG_FIRST)
    {
        if (blockNumber == 0)
            return 0;

        *outIndex = 0;

        return 1;
    }

    if (fragmentation != (uint32_t)APS_FRAG_SUBSEQUENT)
        return 0;

    if (blockNumber == 0 || blockNumber >= totalBlocks)
        return 0;

    *outIndex = blockNumber;

    return 1;
}

static Aps_FragAssembly *apsFragRecord(Aps_FragAssembly *pool, uint16_t sourceAddress, uint8_t apsCounter)
{
    uint32_t i;

    for (i = 0; i < (uint32_t)APS_FRAG_TRANSACTIONS; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (pool[i].sourceAddress != sourceAddress || pool[i].apsCounter != apsCounter)
            continue;

        return &pool[i];
    }

    return 0;
}

static Aps_FragAssembly *apsFragClaim(Aps_FragAssembly *pool)
{
    uint32_t i;

    for (i = 0; i < (uint32_t)APS_FRAG_TRANSACTIONS; i++)
    {
        if (!pool[i].inUse)
            return &pool[i];
    }

    return 0;
}

static int apsFragSeen(const Aps_FragAssembly *assembly, uint32_t index)
{
    if (index >= (uint32_t)APS_FRAG_MAX_BLOCKS)
        return 0;

    return (assembly->received[index / 32] & ((uint32_t)1 << (index % 32))) != 0 ? 1 : 0;
}

static void apsFragMark(Aps_FragAssembly *assembly, uint32_t index)
{
    if (index >= (uint32_t)APS_FRAG_MAX_BLOCKS)
        return;

    assembly->received[index / 32] = assembly->received[index / 32] | ((uint32_t)1 << (index % 32));
}

Aps_FragVerdict Aps_FragAccept(Aps_FragAssembly *pool, uint16_t sourceAddress, uint8_t apsCounter,
                               uint32_t fragmentation, uint8_t blockNumber, const uint8_t *payload,
                               uint32_t payloadLen, uint32_t blockCapacity, uint32_t nowMs,
                               Aps_FragAssembly **outAssembly)
{
    Aps_FragAssembly *assembly;
    uint32_t index;
    uint32_t total;
    uint32_t offset;

    if (outAssembly != 0)
        *outAssembly = 0;

    if (pool == 0 || payload == 0 || blockCapacity == 0)
        return APS_FRAG_DROP_SHAPE;

    if (fragmentation != (uint32_t)APS_FRAG_FIRST && fragmentation != (uint32_t)APS_FRAG_SUBSEQUENT)
        return APS_FRAG_DROP_SHAPE;

    if (payloadLen > blockCapacity)
        return APS_FRAG_DROP_BOUNDS;

    assembly = apsFragRecord(pool, sourceAddress, apsCounter);

    if (assembly == 0)
    {
        if (fragmentation != (uint32_t)APS_FRAG_FIRST)
            return APS_FRAG_DROP_OUT_OF_WINDOW;

        if (blockNumber == 0)
            return APS_FRAG_DROP_BOUNDS;

        total = blockNumber;
        assembly = apsFragClaim(pool);

        if (assembly == 0)
            return APS_FRAG_DROP_NO_ROOM;

        Zb_memset(assembly, 0, (uint32_t)sizeof *assembly);

        assembly->inUse = 1;
        assembly->sourceAddress = sourceAddress;
        assembly->apsCounter = apsCounter;
        assembly->expected = (uint8_t)total;
        assembly->windowBase = 0;
        assembly->stride = payloadLen != 0 ? payloadLen : blockCapacity;
    }

    total = assembly->expected;

    if (!apsFragIndex(fragmentation, blockNumber, total, &index))
        return APS_FRAG_DROP_BOUNDS;

    if (apsFragSeen(assembly, index))
    {
        /* A block the window has already passed, arriving again: the sender did not hear the acknowledgement, so the
           acknowledgement is repeated for it rather than withheld, which 2.2.8.4.5.4's persistence paragraph asks for. */
        assembly->repeatIndex = (uint8_t)index;
        assembly->repeatPending = 1;
        assembly->lastBlockMs = nowMs;

        if (outAssembly != 0)
            *outAssembly = assembly;

        return assembly->have == assembly->expected ? APS_FRAG_COMPLETE : APS_FRAG_ACCEPTED;
    }

    if (index != assembly->windowBase)
        return APS_FRAG_DROP_OUT_OF_WINDOW;

    offset = index * assembly->stride;

    if (offset + payloadLen > (uint32_t)sizeof assembly->asdu)
        return APS_FRAG_DROP_BOUNDS;

    Zb_memcpy(assembly->asdu + offset, payload, payloadLen);

    apsFragMark(assembly, index);

    assembly->have++;
    assembly->windowBase = (uint8_t)(index + (uint32_t)APS_FRAG_WINDOW);
    assembly->lastBlockMs = nowMs;

    if (payloadLen > 0)
        assembly->asduLength = offset + payloadLen;

    if (outAssembly != 0)
        *outAssembly = assembly;

    return assembly->have >= assembly->expected ? APS_FRAG_COMPLETE : APS_FRAG_ACCEPTED;
}

int Aps_FragAckWindow(const Aps_FragAssembly *pool, uint16_t sourceAddress, uint8_t apsCounter,
                      uint8_t *outBlockNumber, uint8_t *outBitfield)
{
    const Aps_FragAssembly *assembly;
    uint8_t bitfield;
    uint32_t bit;

    if (pool == 0 || outBlockNumber == 0 || outBitfield == 0)
        return 0;

    assembly = apsFragRecord((Aps_FragAssembly *)pool, sourceAddress, apsCounter);

    if (assembly == 0)
        return 0;

    /* 2.2.8.4.5.4: the first bit is the first fragment of the window and 0 when it is missing; a window of one leaves
       the remaining bits at 1, which is what the clause asks of a window smaller than eight. */
    if (assembly->repeatPending)
    {
        *outBlockNumber = assembly->repeatIndex;
        *outBitfield = (uint8_t)APS_FRAG_ACK_BITFIELD_FULL;

        return 1;
    }

    bitfield = (uint8_t)APS_FRAG_ACK_BITFIELD_FULL;

    for (bit = 0; bit < (uint32_t)APS_FRAG_WINDOW; bit++)
    {
        if (apsFragSeen(assembly, (uint32_t)assembly->windowBase + bit))
            continue;

        bitfield = (uint8_t)(bitfield & (uint8_t)~((uint8_t)1 << bit));
    }

    *outBlockNumber = assembly->windowBase;
    *outBitfield = bitfield;

    return 1;
}

uint32_t Aps_FragReleaseIdle(Aps_FragAssembly *pool, uint32_t nowMs, uint32_t idleMs)
{
    uint32_t released = 0;
    uint32_t i;

    if (pool == 0)
        return 0;

    for (i = 0; i < (uint32_t)APS_FRAG_TRANSACTIONS; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (!Zb_timeReached(nowMs, pool[i].lastBlockMs + idleMs))
            continue;

        Zb_memset(&pool[i], 0, (uint32_t)sizeof pool[i]);
        released++;
    }

    return released;
}

uint32_t Aps_FragCount(const Aps_FragAssembly *pool)
{
    uint32_t count = 0;
    uint32_t i;

    if (pool == 0)
        return 0;

    for (i = 0; i < (uint32_t)APS_FRAG_TRANSACTIONS; i++)
    {
        if (pool[i].inUse)
            count++;
    }

    return count;
}
