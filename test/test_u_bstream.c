#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "u_bstream.h"

/* Our own suite for the vendored reader/writer: upstream ships none for u_bstream,
   and the Spinel codec will be built on exactly these behaviours (docs/internals/refs.md §6). */

static int s_failures;

static void expect(int condition, const char *what)
{
    if (!condition)
    {
        printf("FAIL: %s\n", what);
        s_failures++;
    }
}

/* The pinned revision exists because of this: a C99 build must see the 64-bit
   accessors. A tag older than the pin gated them on C11 and dropped them here. */
#ifndef U_BSTREAM_HAS_LONG_LONG
typedef char BstreamNeedsLongLongUnderC99[-1];
#endif

static void caseLittleEndianWrites(void)
{
    unsigned char buf[32];
    U_BStream bs;

    memset(buf, 0, sizeof buf);
    U_bstream_init(&bs, buf, sizeof buf);
    U_bstream_put_u8(&bs, 0x7e);
    U_bstream_put_u16_le(&bs, 0x4242);
    U_bstream_put_u32_le(&bs, 0x120B);
    U_bstream_put_u32_le(&bs, 0x11223344);
    expect(bs.status == U_BSTREAM_OK, "writes fit");
    expect(memcmp(buf, "\x7e\x42\x42\x0b\x12\x00\x00\x44\x33\x22\x11", 11) == 0,
           "every writer is little-endian on the wire");
    U_bstream_init(&bs, buf, sizeof buf);
    U_bstream_seek(&bs, 1);
    expect(U_bstream_get_u16_le(&bs) == 0x4242, "the u16 octets read back at their offset");
    expect(U_bstream_get_u32_le(&bs) == 0x0000120B, "the u32 octets read back at their offset");
    expect(bs.status == U_BSTREAM_OK && bs.pos == 7, "reads advance the position");
}

static void caseBigEndianReads(void)
{
    unsigned char buf[8];
    U_BStream bs;

    memcpy(buf, "\x12\x34\x00\x21\x2e\xff", 6);
    U_bstream_init(&bs, buf, 6);
    expect(U_bstream_get_u16_be(&bs) == 0x1234, "u16 big-endian reader is MSB first");
    expect(U_bstream_get_u32_be(&bs) == 0x212eff, "u32 big-endian reader is MSB first");
    expect(bs.status == U_BSTREAM_OK && U_bstream_remaining(&bs) == 0, "both advanced the position");

    /* The same octets read little-endian, which is what the dialect table must decide. */
    U_bstream_init(&bs, buf, 6);
    expect(U_bstream_get_u16_le(&bs) == 0x3412, "the same octets little-endian");
    expect(U_bstream_get_u32_le(&bs) == 0xff2e2100, "the same four octets little-endian");
}

/* The writers v1.3.0 added, which the Spinel codec's big-endian widths are built on. */
static void caseBigEndianWrites(void)
{
    unsigned char buf[16];
    U_BStream bs;

    memset(buf, 0, sizeof buf);
    U_bstream_init(&bs, buf, sizeof buf);
    U_bstream_put_u16_be(&bs, 0x1234);
    U_bstream_put_u32_be(&bs, 0xdeadbeef);
    U_bstream_put_u64_be(&bs, 0x0102030405060708);
    expect(bs.status == U_BSTREAM_OK && U_bstream_pos(&bs) == 14, "the big-endian writes fit");
    expect(memcmp(buf, "\x12\x34\xde\xad\xbe\xef\x01\x02\x03\x04\x05\x06\x07\x08", 14) == 0,
           "every big-endian writer is MSB first on the wire");
    U_bstream_init(&bs, buf, sizeof buf);
    expect(U_bstream_get_u16_be(&bs) == 0x1234, "u16 reads back");
    expect(U_bstream_get_u32_be(&bs) == 0xdeadbeef, "u32 reads back");
    expect(U_bstream_get_u64_be(&bs) == 0x0102030405060708, "u64 reads back");

    memset(buf, 0xaa, sizeof buf);
    U_bstream_init(&bs, buf, 3);
    U_bstream_put_u32_be(&bs, 0x11223344);
    expect(bs.status == U_BSTREAM_WRITE_PAST_END, "a big-endian write that does not fit is refused");
    expect(buf[0] == 0xaa, "and writes no part of the value");
}

static void caseSignedOctet(void)
{
    unsigned char buf[2];
    U_BStream bs;

    U_bstream_init(&bs, buf, sizeof buf);
    U_bstream_put_s8(&bs, -98);
    U_bstream_put_s8(&bs, 127);
    expect(buf[0] == 0x9e && buf[1] == 0x7f, "s8 is the two's-complement octet");
    U_bstream_init(&bs, buf, sizeof buf);
    expect(U_bstream_get_s8(&bs) == -98, "s8 sign extends");
    expect(U_bstream_get_s8(&bs) == 127, "s8 round trip");
}

/* The unsigned varint a Spinel packed uint is (docs/internals/protocol.md §4): the wire forms,
   the 32-bit bound, and the faults the codec relies on being stated. */
static void caseLeb128U32(void)
{
    static const unsigned long values[] = { 0, 0x7f, 0x80, 0x3fff, 0x4000, 0x1fffff, 0x200000,
                                            0x0fffffff, 0x10000000, 0xffffffff };
    static const unsigned long sizes[] = { 1, 1, 2, 2, 3, 3, 4, 4, 5, 5 };
    unsigned char buf[8];
    unsigned char truncated[] = { 0x8b };
    unsigned char tooMany[] = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 };
    unsigned char tooWide[] = { 0xff, 0xff, 0xff, 0xff, 0x10 };
    unsigned char redundant[] = { 0x80, 0x00 };
    U_BStream bs;
    size_t i;

    for (i = 0; i < sizeof values / sizeof values[0]; i++)
    {
        U_bstream_init(&bs, buf, sizeof buf);
        U_bstream_put_leb128_u32(&bs, values[i]);
        expect(U_bstream_leb128_u32_size(values[i]) == sizes[i], "the size is the one recorded");
        expect(bs.status == U_BSTREAM_OK && U_bstream_pos(&bs) == sizes[i], "the write is that long");
        U_bstream_init(&bs, buf, sizeof buf);
        expect(U_bstream_get_leb128_u32(&bs) == values[i], "the value reads back");
        expect(bs.status == U_BSTREAM_OK && U_bstream_pos(&bs) == sizes[i], "and consumes what was written");
    }

    U_bstream_init(&bs, buf, sizeof buf);
    U_bstream_put_leb128_u32(&bs, 0x0b);
    expect(buf[0] == 0x0b, "a small value is one octet");
    U_bstream_init(&bs, buf, sizeof buf);
    U_bstream_put_leb128_u32(&bs, 0x1234);
    expect(buf[0] == 0xb4 && buf[1] == 0x24, "least significant group first, continuation set");

    memset(buf, 0xaa, sizeof buf);
    U_bstream_init(&bs, buf, 2);
    U_bstream_put_leb128_u32(&bs, 0x4000);
    expect(bs.status == U_BSTREAM_WRITE_PAST_END, "a varint that does not fit is refused");
    expect(buf[0] == 0xaa && buf[1] == 0xaa, "and writes no part of it");

    U_bstream_init(&bs, truncated, sizeof truncated);
    expect(U_bstream_get_leb128_u32(&bs) == 0 && bs.status == U_BSTREAM_DECODE_ERROR,
           "a continuation running off the end is a decode error");
    U_bstream_init(&bs, tooMany, sizeof tooMany);
    expect(U_bstream_get_leb128_u32(&bs) == 0 && bs.status == U_BSTREAM_DECODE_ERROR,
           "a sixth group is a decode error");
    U_bstream_init(&bs, tooWide, sizeof tooWide);
    expect(U_bstream_get_leb128_u32(&bs) == 0 && bs.status == U_BSTREAM_DECODE_ERROR,
           "a fifth group with bits above 31 is a decode error");
    U_bstream_init(&bs, redundant, sizeof redundant);
    expect(U_bstream_get_leb128_u32(&bs) == 0 && bs.status == U_BSTREAM_OK && U_bstream_pos(&bs) == 2,
           "a redundant continuation reads as its value");
    U_bstream_init(&bs, buf, 0);
    expect(U_bstream_get_leb128_u32(&bs) == 0 && bs.status != U_BSTREAM_OK, "an empty stream is an error");
}

/* pos is what was committed, even after a failure, where size minus remaining is not;
   fits is the room check before a write. */
static void casePosAndFits(void)
{
    unsigned char buf[4];
    U_BStream bs;

    U_bstream_init(&bs, buf, sizeof buf);
    expect(U_bstream_pos(&bs) == 0 && U_bstream_fits(&bs, 4) && !U_bstream_fits(&bs, 5),
           "a fresh stream fits its size and no more");
    U_bstream_put_u16_le(&bs, 0x1234);
    expect(U_bstream_pos(&bs) == 2 && U_bstream_fits(&bs, 2) && !U_bstream_fits(&bs, 3),
           "the position and the room move together");
    U_bstream_put_u32_le(&bs, 0);
    expect(bs.status == U_BSTREAM_WRITE_PAST_END, "an overflowing write fails the stream");
    expect(U_bstream_pos(&bs) == 2, "pos still reports what was committed");
    expect(U_bstream_remaining(&bs) == 0 && !U_bstream_fits(&bs, 1), "a failed stream has no room left");
}

static void caseSignedWidths(void)
{
    unsigned char buf[16];
    U_BStream bs;

    memset(buf, 0, sizeof buf);
    U_bstream_init(&bs, buf, sizeof buf);
    U_bstream_put_s16_le(&bs, -1);
    U_bstream_put_s16_le(&bs, -12345);
    U_bstream_put_s32_le(&bs, -1);
    U_bstream_put_s32_le(&bs, -70000);
    expect(buf[0] == 0xff && buf[1] == 0xff, "s16 of -1 is ff ff on the wire");
    expect(buf[2] == 0xc7 && buf[3] == 0xcf, "s16 of -12345 is c7 cf little-endian");

    U_bstream_init(&bs, buf, sizeof buf);
    expect(U_bstream_get_s16_le(&bs) == -1, "s16 round trip of -1");
    expect(U_bstream_get_s16_le(&bs) == -12345, "s16 round trip");
    expect(U_bstream_get_s32_le(&bs) == -1, "s32 sign extends");
    expect(U_bstream_get_s32_le(&bs) == -70000, "s32 round trip");
}

static void case64BitWidths(void)
{
    unsigned char buf[16];
    U_BStream bs;

    memset(buf, 0, sizeof buf);
    U_bstream_init(&bs, buf, sizeof buf);
    U_bstream_put_u64_le(&bs, 0x0102030405060708);
    expect(buf[0] == 0x08 && buf[7] == 0x01, "u64 is little-endian");
    U_bstream_init(&bs, buf, sizeof buf);
    expect(U_bstream_get_u64_le(&bs) == 0x0102030405060708, "u64 round trip");

    U_bstream_init(&bs, buf, sizeof buf);
    U_bstream_put_s64_le(&bs, -1);
    U_bstream_init(&bs, buf, sizeof buf);
    expect(U_bstream_get_s64_le(&bs) == -1, "s64 round trip of -1");
    expect(bs.status == U_BSTREAM_OK, "the 64-bit accessors exist under this build");
}

static void caseLeb128Zigzag(void)
{
    static const long long values[] = {
        0, 1, -1, 63, -64, 64, -65, 127, 128, -8192, 8191, 1000000, -1000000,
        4611686018427387903, -4611686018427387904
    };
    unsigned char buf[16];
    U_BStream bs;
    size_t i;

    for (i = 0; i < sizeof values / sizeof values[0]; i++)
    {
        memset(buf, 0, sizeof buf);
        U_bstream_init(&bs, buf, sizeof buf);
        U_bstream_put_leb128_s64(&bs, values[i]);
        U_bstream_init(&bs, buf, sizeof buf);
        expect(U_bstream_get_leb128_s64(&bs) == values[i], "zigzag LEB128 round trip");
        expect(bs.status == U_BSTREAM_OK, "zigzag LEB128 stays clean");
    }

    memset(buf, 0, sizeof buf);
    U_bstream_init(&bs, buf, sizeof buf);
    U_bstream_put_leb128_s64(&bs, 1);
    expect(buf[0] == 0x02, "zigzag maps 1 to 0x02");
    U_bstream_init(&bs, buf, sizeof buf);
    U_bstream_put_leb128_s64(&bs, -1);
    expect(buf[0] == 0x01, "zigzag maps -1 to 0x01");

    /* A continuation byte with nothing after it is a stated decode error, not a zero. */
    memset(buf, 0, sizeof buf);
    buf[0] = 0x80;
    U_bstream_init(&bs, buf, 1);
    expect(U_bstream_get_leb128_s64(&bs) == 0, "truncated LEB128 yields nothing useful");
    expect(bs.status == U_BSTREAM_DECODE_ERROR, "truncated LEB128 is a stated decode error");
}

/* Our bands count in uint32_t; the vendored API speaks unsigned long. The crossing is an
   explicit cast at the call, with the value already bounded by a named constant: the
   vendored signatures are not changed (docs/internals/refs.md §6). */
static void caseWidthBoundary(void)
{
    unsigned char buf[8];
    U_BStream bs;
    uint32_t value;
    uint32_t back;
    uint32_t capacity;

    capacity = (uint32_t)sizeof buf;
    value = 0x11223344;

    U_bstream_init(&bs, buf, (unsigned long)capacity);
    U_bstream_put_u32_le(&bs, (unsigned long)value);
    U_bstream_init(&bs, buf, (unsigned long)capacity);
    back = (uint32_t)U_bstream_get_u32_le(&bs);
    expect(back == value, "a uint32_t value round-trips across the vendor boundary");
    expect((uint32_t)U_bstream_remaining(&bs) == capacity - 4, "sizes cross as stated too");
    expect((uint32_t)bs.pos == 4, "the position is readable at our width");
}

static void casePastEndIsStated(void)
{
    unsigned char buf[4];
    U_BStream bs;

    memset(buf, 0xAA, sizeof buf);
    U_bstream_init(&bs, buf, sizeof buf);
    U_bstream_put_u32_le(&bs, 0x11223344);
    U_bstream_put_u8(&bs, 0x55);
    expect(bs.status == U_BSTREAM_WRITE_PAST_END, "a write that does not fit is refused");
    expect(buf[0] == 0x44 && buf[3] == 0x11, "the run that fitted was written, little-endian");
    expect(U_bstream_remaining(&bs) == 0, "remaining is zero at the end");

    U_bstream_put_u8(&bs, 0x66);
    expect(memcmp(buf, "\x44\x33\x22\x11", 4) == 0, "a refused write after an error writes nothing");

    memset(buf, 0xAA, sizeof buf);
    U_bstream_init(&bs, buf, 2);
    expect(U_bstream_get_u32_le(&bs) == 0, "a read past the end yields nothing");
    expect(bs.status == U_BSTREAM_READ_PAST_END, "a read past the end is a stated error");
    expect(buf[0] == 0xAA && buf[1] == 0xAA, "the buffer is untouched by the refused read");

    U_bstream_init(&bs, buf, 2);
    U_bstream_put_u16_le(&bs, 0x1234);
    expect(U_bstream_get_u8(&bs) == 0, "a sticky status stops further decoding");
    expect(bs.status == U_BSTREAM_READ_PAST_END, "the first error is the one reported");
}

static void casePositionControl(void)
{
    unsigned char buf[8];
    U_BStream bs;

    U_bstream_init(&bs, buf, sizeof buf);
    expect(U_bstream_remaining(&bs) == 8, "remaining starts at the size");
    U_bstream_advance(&bs, 3);
    expect(U_bstream_remaining(&bs) == 5 && bs.pos == 3, "advance moves the position");
    U_bstream_seek(&bs, 8);
    expect(bs.status == U_BSTREAM_OK && U_bstream_remaining(&bs) == 0, "seek to the end is legal");
    U_bstream_advance(&bs, 1);
    expect(bs.status == U_BSTREAM_WRITE_PAST_END, "advancing past the end is refused");

    U_bstream_init(&bs, buf, sizeof buf);
    U_bstream_seek(&bs, 9);
    expect(bs.status == U_BSTREAM_WRITE_PAST_END, "seeking past the end is refused");

    U_bstream_init(&bs, 0, 0);
    U_bstream_put_u8(&bs, 1);
    expect(bs.status == U_BSTREAM_NOT_INITIALISED, "a stream without a buffer says so");
    U_bstream_init(&bs, 0, 0);
    expect(U_bstream_get_u8(&bs) == 0, "a stream without a buffer reads nothing");
    expect(bs.status == U_BSTREAM_NOT_INITIALISED, "and states why");
}

static void caseBytesTransfer(void)
{
    unsigned char buf[16];
    unsigned char src[6] = { 1, 2, 3, 4, 5, 6 };
    unsigned char dst[6];
    U_BStream bs;

    U_bstream_init(&bs, buf, sizeof buf);
    U_bstream_put_bytes(&bs, src, sizeof src);
    expect(memcmp(buf, src, sizeof src) == 0, "put_bytes copies the whole run");
    U_bstream_seek(&bs, 0);
    U_bstream_get_bytes(&bs, dst, sizeof dst);
    expect(memcmp(dst, src, sizeof dst) == 0, "get_bytes reads it back");
    expect(U_bstream_remaining(&bs) == 10, "the read left the position after the run");

    memset(buf, 0xAA, sizeof buf);
    U_bstream_init(&bs, buf, 4);
    U_bstream_put_bytes(&bs, src, sizeof src);
    expect(bs.status == U_BSTREAM_WRITE_PAST_END, "put_bytes is all or nothing");
    expect(memcmp(buf, "\xaa\xaa\xaa\xaa", 4) == 0, "a refused put_bytes writes no part of the run");
}

int main(void)
{
    caseLittleEndianWrites();
    caseBigEndianReads();
    caseBigEndianWrites();
    caseSignedOctet();
    caseLeb128U32();
    casePosAndFits();
    caseSignedWidths();
    case64BitWidths();
    caseLeb128Zigzag();
    caseWidthBoundary();
    casePastEndIsStated();
    casePositionControl();
    caseBytesTransfer();

    if (s_failures == 0)
        printf("u_bstream: ok\n");
    else
        printf("u_bstream: %d failures\n", s_failures);

    return s_failures == 0 ? 0 : 1;
}
