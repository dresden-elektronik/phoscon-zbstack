#ifndef APS_FRAG_H
#define APS_FRAG_H

/*
 * 2.2.8.4.5's fragmented transmission, at the one window size R23.1 makes interoperable: Table 2-28 prints
 * apscWindowSize 1 and 2.2.8.4.5 says "the use of a window size of 1 is the only window size guaranteed to
 * interoperate", so a window here is one block and the acknowledgement covers one block.
 *
 * This module decides and holds; it composes nothing and sends nothing. The block octets live in the caller's ASDU,
 * the reassembly buffer is the caller's, and a verdict here is a value a caller acts on rather than an effect.
 */

#include <stdint.h>

#include "aps_frame.h"

/* 2.2.8.4.5.2's Table 2-28, and 2.2.8.4.5.3's first-block rule: the block number of the first block is the total
   number of blocks, so the count has to fit one octet and the ceiling is the byte's own. */
enum
{
    APS_FRAG_WINDOW = 1,            /* apscWindowSize (Table 2-28) */
    APS_FRAG_MAX_BLOCKS = 0xff,     /* 2.2.5.1.8.2: the block number field is one octet */
    APS_FRAG_MAX_ASDU = 128,        /* apscMaxASDU (Table 2-28), the printed minimum this stack implements */
    APS_FRAG_TRANSACTIONS = 4,      /* R23.1 prints no size for the reassembly pool: bounded, named, full is refusal */
    APS_FRAG_ACK_BITS = 8,          /* 2.2.5.1.8.3: "one octet in length", the bitfield of a window */
    APS_FRAG_ACK_BITFIELD_FULL = 0xff /* 2.2.8.4.5.4: "the remaining bits SHALL be set to 1" */
};

/* What a received block was. `APS_FRAG_ACCEPTED` and `APS_FRAG_COMPLETE` both mean the block was kept; the second
   says it was the last one, so the reassembled ASDU is ready. Every other verdict is a block this device did not keep,
   and each names the rule that refused it. */
typedef enum Aps_FragVerdict
{
    APS_FRAG_ACCEPTED = 0,
    APS_FRAG_COMPLETE = 1,
    APS_FRAG_DROP_SHAPE = 2,        /* 2.2.8.4.5.4: a field a fragmentation-enabled transmission requires is absent */
    APS_FRAG_DROP_BOUNDS = 3,       /* 2.2.8.4.5.4: a parameter outside this protocol's bounds */
    APS_FRAG_DROP_OUT_OF_WINDOW = 4, /* 2.2.8.4.5.4: a block number outside the current window, which is not acknowledged */
    APS_FRAG_DROP_NO_ROOM = 5       /* no reassembly record free */
} Aps_FragVerdict;

/* One fragmented transaction being reassembled. `received` is a bitmap over the block numbers a block carries, which
   for a window of one is the whole of the state a duplicate test needs; `expected` is the total the first block
   stated, and `have` counts the blocks kept. */

typedef struct Aps_FragAssembly
{
    int inUse;
    uint16_t sourceAddress;
    uint8_t apsCounter;
    uint8_t expected;
    uint8_t have;
    uint8_t windowBase;
    uint32_t stride;                 /* the octets one block carries, which the first block's own length states */
    uint8_t repeatIndex;             /* a block the window has passed that arrived again, which the ack repeats */
    int repeatPending;
    uint32_t lastBlockMs;
    uint32_t received[8];
    uint8_t asdu[APS_FRAG_MAX_ASDU];
    uint32_t asduLength;
} Aps_FragAssembly;

/* How many blocks an ASDU of `asduLength` octets takes at `blockCapacity` octets each, or 0 when it cannot be
   fragmented: a length of 0, a capacity of 0, or a count above one octet's range. */
uint32_t Aps_FragBlockCount(uint32_t asduLength, uint32_t blockCapacity);

/* The block number a block of a transmission carries, which 2.2.8.4.5.3 prints: the total number of blocks in the
   first, 0x01 in the second, and one more for each after it. `index` is zero-based. */
uint8_t Aps_FragBlockNumber(uint32_t index, uint32_t totalBlocks);

/* The fragmentation sub-field a block carries: 0b01 for the first and 0b10 for every subsequent one. */
uint32_t Aps_FragSubField(uint32_t index);

/* The octets one block hands down, and how many there are. */
const uint8_t *Aps_FragBlock(const uint8_t *asdu, uint32_t asduLength, uint32_t blockCapacity, uint32_t index,
                             uint32_t *outLength);

/* One received block into the pool: the record for its source and APS counter, created when absent, the block kept
   when its number is inside the window, and the whole ASDU ready when the last one lands. `blockNumber` is the field
   as received, so the first block's value is the total; `payload` is the block's octets. */
Aps_FragVerdict Aps_FragAccept(Aps_FragAssembly *pool, uint16_t sourceAddress, uint8_t apsCounter,
                               uint32_t fragmentation, uint8_t blockNumber, const uint8_t *payload,
                               uint32_t payloadLen, uint32_t blockCapacity, uint32_t nowMs,
                               Aps_FragAssembly **outAssembly);

/* The acknowledgement 2.2.8.4.5.4 asks for a window: the lowest block number in it, and one bit per block, the
   remaining bits set to 1. Returns 0 when the pool holds no transaction for that source and counter. */
int Aps_FragAckWindow(const Aps_FragAssembly *pool, uint16_t sourceAddress, uint8_t apsCounter,
                      uint8_t *outBlockNumber, uint8_t *outBitfield);

/* The record a transaction that has gone quiet gives back, so a later one can use it. */
uint32_t Aps_FragReleaseIdle(Aps_FragAssembly *pool, uint32_t nowMs, uint32_t idleMs);

/* How many transactions the pool holds, and the reassembled ASDU of one. */
uint32_t Aps_FragCount(const Aps_FragAssembly *pool);

#endif /* APS_FRAG_H */
