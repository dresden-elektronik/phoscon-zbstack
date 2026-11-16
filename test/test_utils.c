/* Suite for the U_ primitives that keep <string.h> out of the bands (docs/internals/coding-rules.md
   §1), and for the invariant macro beside them: ZB_ASSERT always compiles, and a false
   condition calls the Zb_AssertHandler the executable links, once, with integers only.
   The contracts tested are the ones the bands rely on: exact byte movement, a scan
   that stops at the stated bound, an ordering defined on unsigned char values, and an
   invariant whose breakage reaches a handler instead of a compiled-out check. */

#include <stdio.h>

#include "log.h"
#include "zb_assert.h"
#include "zb_bstream.h"
#include "zb_time.h"
#include "zb_utils.h"

static int s_failures;

static uint32_t s_assertCalls;
static uint16_t s_assertComponent;
static uint16_t s_assertLine;
static uint32_t s_assertArgument;

static void expect(int condition, const char *what)
{
    if (!condition)
    {
        printf("FAIL: %s\n", what);
        s_failures++;
    }
}

void Zb_AssertHandler(uint16_t component, uint16_t line, uint32_t argument)
{
    s_assertCalls++;
    s_assertComponent = component;
    s_assertLine = line;
    s_assertArgument = argument;
}

static void caseMemset(void)
{
    unsigned char buf[8];
    unsigned char i;

    for (i = 0; i < 8; i++)
        buf[i] = (unsigned char)(0x30 + i);

    Zb_memset(buf, 0xAA, 4);

    expect(buf[0] == 0xAA && buf[1] == 0xAA && buf[2] == 0xAA && buf[3] == 0xAA,
           "the stated span is set");
    expect(buf[4] == 0x34 && buf[5] == 0x35 && buf[6] == 0x36 && buf[7] == 0x37,
           "nothing past the span changes");

    Zb_memset(buf, 0x55, 0);
    expect(buf[0] == 0xAA, "n == 0 writes nothing");

    Zb_memset(buf, 0, 8);
    expect(buf[0] == 0 && buf[7] == 0, "a whole object can be cleared");
}

static void caseMemcpy(void)
{
    unsigned char src[6];
    unsigned char dst[6];
    unsigned char i;

    for (i = 0; i < 6; i++)
        src[i] = (unsigned char)(0x10 + i);

    Zb_memset(dst, 0xEE, 6);

    Zb_memcpy(dst, src, 4);
    expect(dst[0] == 0x10 && dst[1] == 0x11 && dst[2] == 0x12 && dst[3] == 0x13,
           "the stated span is copied in order");
    expect(dst[4] == 0xEE && dst[5] == 0xEE, "nothing past the span is written");

    Zb_memcpy(dst, src, 0);
    expect(dst[0] == 0x10, "n == 0 copies nothing");

    Zb_memcpy(dst, src, 6);
    expect(Zb_memcmp(dst, src, 6) == 0, "a full copy matches the source byte for byte");
}

static void caseMemcmp(void)
{
    unsigned char a[5];
    unsigned char b[5];
    signed char negative;
    unsigned char positive;
    unsigned char i;

    for (i = 0; i < 5; i++)
    {
        a[i] = (unsigned char)(0x40 + i);
        b[i] = (unsigned char)(0x40 + i);
    }

    expect(Zb_memcmp(a, b, 5) == 0, "equal buffers compare zero");

    b[2] = 0x41;
    expect(Zb_memcmp(a, b, 5) > 0, "the first difference decides, and its sign is a minus b");
    expect(Zb_memcmp(b, a, 5) < 0, "the reverse comparison flips the sign");

    for (i = 0; i < 5; i++)
        b[i] = a[i];

    b[4] = 0x45;
    expect(Zb_memcmp(a, b, 4) == 0, "only the stated span is compared");
    expect(Zb_memcmp(a, b, 5) < 0, "the last byte is inside a span of five");

    Zb_memset(a, 0, 5);
    Zb_memset(b, 0, 5);
    expect(Zb_memcmp(a, b, 0) == 0, "n == 0 compares equal whatever the buffers hold");

    /* The comparison is on unsigned char values: the same bit pattern in a signed char and
       an unsigned char compares equal, which is what makes opaque buffers orderable. */
    negative = (signed char)-1;
    positive = 255;
    expect(Zb_memcmp(&negative, &positive, 1) == 0, "a byte pattern is compared, not a C type");

    negative = (signed char)-128;
    positive = 1;
    expect(Zb_memcmp(&negative, &positive, 1) > 0, "0x80 sorts above 0x01 as an unsigned char");
}

static void caseStrlen(void)
{
    char buf[8];

    buf[0] = '/'; buf[1] = 'd'; buf[2] = 'e'; buf[3] = 'v';
    buf[4] = 0;   buf[5] = 'x'; buf[6] = 'y'; buf[7] = 0;

    expect(Zb_strlen(buf, 8) == 4, "the length stops at the terminator");
    expect(Zb_strlen(buf, 4) == 4, "a scan capped before the terminator returns the cap");
    expect(Zb_strlen(buf, 0) == 0, "a cap of zero reads nothing");

    buf[0] = 0;
    expect(Zb_strlen(buf, 8) == 0, "an empty string is zero");

    Zb_memset(buf, 'a', 8);
    expect(Zb_strlen(buf, 8) == 8, "an unterminated buffer returns the cap, not a longer run");
}

static void caseAssert(void)
{
    uint32_t evaluated = 0;

    s_assertCalls = 0;
    ZB_ASSERT(evaluated++ == 0, LOG_COMP_LOOPBACK, 0);
    expect(s_assertCalls == 0, "a held invariant calls the handler not at all");
    expect(evaluated == 1, "the condition is evaluated once");

    s_assertCalls = 0;
    ZB_ASSERT(0, LOG_COMP_MAC, 42);
    expect(s_assertCalls == 1, "a broken invariant calls the handler exactly once");
    expect(s_assertComponent == LOG_COMP_MAC, "the component leaves with the failure");
    expect(s_assertArgument == 42, "the argument leaves with the failure");
    expect(s_assertLine == 155, "the line is the call's line");
}

/*
 * The deadline arithmetic of a wrapping millisecond counter (src/utils/zb_time.h): a deadline the counter has
 * passed is past even though the counter is now a small number, a deadline still ahead is ahead even though
 * the counter is a large one, and a window that contains the wrap is measured across it. The span of exactly
 * 2^31 ms is asserted as the helper answers it rather than as symmetry would suggest.
 */
static void caseTimeWrap(void)
{
    expect(Zb_timeReached(0x00000100, 0xFFFFFF00) == 1,
           "a deadline set before the wrap is reached after it: 0x100 - 0xFFFFFF00 is 512 ms and the sign says past");
    expect(Zb_timeReached(0xFFFFFF00, 0x00000100) == 0,
           "and the same pair the other way is not: that deadline is 512 ms away, not 49.7 days");
    expect(Zb_timeReached(0x12345678, 0x12345678) == 1, "now == deadline is reached");
    expect(Zb_timeReached(0x12345677, 0x12345678) == 0, "one millisecond before it is not");

    expect(Zb_timeWithin(0x00000080, 0xFFFFFF00, 512) == 1,
           "a 512 ms window opened before the wrap still contains the millisecond 384 ms into it");
    expect(Zb_timeWithin(0xFFFFFFFF, 0xFFFFFF00, 512) == 1, "its last millisecond is inside");
    expect(Zb_timeWithin(0x00000000, 0xFFFFFF00, 512) == 1, "the millisecond after the wrap is inside");
    expect(Zb_timeWithin(0x00000100, 0xFFFFFF00, 512) == 0,
           "and the millisecond that reaches its end is not: the window is half-open, as the subtraction is");
    expect(Zb_timeWithin(0x12345678, 0x12345678, 1) == 1 && Zb_timeWithin(0x12345678, 0x12345678, 0) == 0,
           "a window of one holds the millisecond it opens on, a window of none holds nothing");

    /* 2^31 ms is the span the rule allows: read as a signed distance it is INT32_MIN in both directions, so
       neither side calls it reached and neither calls it within, the header's design-error boundary, stated
       as the answer rather than assumed symmetric. */
    expect(Zb_timeReached(0x80000000, 0x00000000) == 0,
           "a span of exactly 2^31 ms forward is not reached: the signed distance is its own negation");
    expect(Zb_timeReached(0x00000000, 0x80000000) == 0, "and neither is the same span backwards");
    expect(Zb_timeWithin(0x80000000, 0x00000000, 0x80000000) == 0, "nor is it inside a window of that width");

    expect(Zb_timeReached(0x7FFFFFFF, 0x00000000) == 1,
           "one millisecond inside the span the rule allows, the distance still has its direction");
    expect(Zb_timeReached(0x00000000, 0x7FFFFFFF) == 0, "in both directions");
    expect(Zb_timeReached(0x00000000, 0x80000001) == 1,
           "and one millisecond past it the sign has flipped: a caller holding that span has a design error, which is what the header says");
}

/* The const view and its queries: what a stream holds is answered without touching it, and a failed or
   uninitialised stream has no room. */
static void caseBstreamExQueries(void)
{
    static const uint8_t bytes[4] = { 0x11, 0x22, 0x33, 0x44 };
    U_BStream bs;

    Zb_bstream_init_const(&bs, bytes, (uint32_t)sizeof bytes);
    expect(Zb_bstream_ok(&bs) && Zb_bstream_remaining(&bs) == 4 && Zb_bstream_pos(&bs) == 0,
           "a const view starts at its first octet with all of them left");
    expect(Zb_bstream_fits(&bs, 4) && !Zb_bstream_fits(&bs, 5), "it fits its size and no more");
    expect(Zb_bstream_size(&bs) == 4, "and its size is the length it was opened over");
    expect(U_bstream_get_u16_le(&bs) == 0x2211, "the vendored readers read through it");
    expect(Zb_bstream_pos(&bs) == 2 && Zb_bstream_remaining(&bs) == 2, "and the queries follow the cursor");

    U_bstream_get_u32_le(&bs);
    expect(!Zb_bstream_ok(&bs) && Zb_bstream_remaining(&bs) == 0 && !Zb_bstream_fits(&bs, 1),
           "a failed stream is not ok and has no room");
    expect(Zb_bstream_pos(&bs) == 2, "its position is what was taken before the failure");

    U_bstream_init(&bs, 0, 0);
    expect(!Zb_bstream_ok(&bs) && Zb_bstream_remaining(&bs) == 0, "a stream without a buffer is not ok");
    expect(bs.status == U_BSTREAM_OK, "and asking does not change its status");

    Zb_bstream_init_const(&bs, bytes, (uint32_t)sizeof bytes);
    Zb_bstream_fail(&bs, U_BSTREAM_DECODE_ERROR);
    expect(bs.status == U_BSTREAM_DECODE_ERROR && U_bstream_get_u8(&bs) == 0, "a fail fails the stream");
    Zb_bstream_fail(&bs, U_BSTREAM_WRITE_PAST_END);
    expect(bs.status == U_BSTREAM_DECODE_ERROR, "and the first failure is the one kept");
}

/* A span is the buffer itself at the cursor; a sub-stream is bounded at its own length, and a short parent opens
   it failed. */
static void caseBstreamExSpans(void)
{
    static const uint8_t bytes[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    const uint8_t *span;
    U_BStream bs;
    U_BStream sub;

    Zb_bstream_init_const(&bs, bytes, (uint32_t)sizeof bytes);
    U_bstream_get_u8(&bs);
    span = Zb_bstream_get_span(&bs, 2);
    expect(span == bytes + 1 && Zb_bstream_pos(&bs) == 3, "a span points into the buffer and moves past itself");
    expect(Zb_bstream_get_span(&bs, 4) == 0 && bs.status == U_BSTREAM_READ_PAST_END,
           "a span longer than what is left fails the stream");
    expect(Zb_bstream_get_span(&bs, 0) == 0, "and a failed stream gives no span at all");

    Zb_bstream_init_const(&bs, bytes, (uint32_t)sizeof bytes);
    Zb_bstream_sub(&bs, &sub, 2);
    expect(Zb_bstream_ok(&sub) && Zb_bstream_remaining(&sub) == 2 && Zb_bstream_pos(&bs) == 2,
           "a sub-stream holds its octets and the parent moves past them");
    expect(U_bstream_get_u16_le(&sub) == 0x0201, "it reads its own octets");
    expect(U_bstream_get_u8(&sub) == 0 && sub.status == U_BSTREAM_READ_PAST_END,
           "and never past its own length");
    expect(Zb_bstream_ok(&bs) && U_bstream_get_u8(&bs) == 0x03, "while the parent reads on behind it");

    Zb_bstream_sub(&bs, &sub, 4);
    expect(bs.status == U_BSTREAM_READ_PAST_END && sub.status == U_BSTREAM_READ_PAST_END,
           "a parent too short fails, and the child opens failed with its status");
    expect(U_bstream_get_u8(&sub) == 0 && Zb_bstream_remaining(&sub) == 0, "so the child reads as zeros");
}

/* The small additions: a peek that leaves the cursor, the 24-bit value whole or not at all, and an octet put back
   at an offset already passed. */
static void caseBstreamExSmall(void)
{
    uint8_t buf[6];
    U_BStream bs;

    Zb_memset(buf, 0xaa, (uint32_t)sizeof buf);
    U_bstream_init(&bs, buf, (unsigned long)sizeof buf);
    U_bstream_put_u8(&bs, 0x00);
    Zb_bstream_put_u24_le(&bs, 0x123456);
    expect(buf[1] == 0x56 && buf[2] == 0x34 && buf[3] == 0x12 && Zb_bstream_pos(&bs) == 4,
           "a 24-bit value is three octets, least significant first");
    Zb_bstream_put_u8_at(&bs, 0, 3);
    expect(buf[0] == 3 && Zb_bstream_pos(&bs) == 4, "an octet put at an offset leaves the cursor where it was");
    Zb_bstream_put_u24_le(&bs, 0xffffff);
    expect(bs.status == U_BSTREAM_WRITE_PAST_END && buf[4] == 0xaa && buf[5] == 0xaa,
           "a 24-bit value that does not fit writes none of itself");

    U_bstream_init(&bs, buf, (unsigned long)sizeof buf);
    Zb_bstream_put_u8_at(&bs, 6, 1);
    expect(bs.status == U_BSTREAM_WRITE_PAST_END, "an offset past the end fails the stream");

    Zb_bstream_init_const(&bs, buf, 4);
    expect(Zb_bstream_peek_u8(&bs) == 3 && Zb_bstream_pos(&bs) == 0, "a peek reads the octet at the cursor");
    U_bstream_get_u8(&bs);
    expect(Zb_bstream_get_u24_le(&bs) == 0x123456 && Zb_bstream_ok(&bs), "the 24-bit value reads back");
    expect(Zb_bstream_peek_u8(&bs) == 0 && Zb_bstream_ok(&bs), "a peek at the end is 0 and fails nothing");
    expect(Zb_bstream_get_u24_le(&bs) == 0 && bs.status == U_BSTREAM_READ_PAST_END,
           "a 24-bit read past the end fails the stream");
}

int main(void)
{
    caseMemset();
    caseMemcpy();
    caseMemcmp();
    caseStrlen();
    caseAssert();
    caseTimeWrap();
    caseBstreamExQueries();
    caseBstreamExSpans();
    caseBstreamExSmall();

    if (s_failures != 0)
    {
        printf("utils: %d failures\n", s_failures);
        return 1;
    }

    printf("utils: ok\n");
    return 0;
}
