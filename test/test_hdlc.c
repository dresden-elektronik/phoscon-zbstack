/* Suite for the framing layer: known answers from the wire, the escape set, the resync rules,
   and the three recorded transcripts re-decoded byte for byte (docs/internals/protocol.md §2). */

#include "hdlc.h"
#include "test_fixture.h"
#include "test_harness.h"
#include "zb_utils.h"

#ifndef ZB_SAMPLES_DIR
#define ZB_SAMPLES_DIR "."
#endif

#define FIXTURE_MAX 4096

static void runStream(Hdlc_Decoder *dec, const uint8_t *bytes, uint32_t len,
                      uint32_t *frames, uint32_t *drops, uint32_t *maxFrameLen)
{
    uint32_t i;
    uint8_t payload[HDLC_PAYLOAD_MAX];
    uint32_t outLen;
    HdlcEvent event;

    *frames = 0;
    *drops = 0;
    *maxFrameLen = 0;

    for (i = 0; i < len; i++)
    {
        outLen = 0;
        event = Hdlc_Feed(dec, bytes[i], payload, &outLen);

        if (event == HDLC_EVENT_FRAME)
        {
            (*frames)++;

            if (outLen > *maxFrameLen)
                *maxFrameLen = outLen;
        }
        else if (event != HDLC_EVENT_NONE)
        {
            (*drops)++;
        }
    }
}

static void caseKnownAnswer(void)
{
    uint8_t payload[2];
    uint8_t frame[8];
    uint8_t wire[6];
    uint32_t len;
    uint32_t i;
    Hdlc_Decoder dec;
    uint8_t out[HDLC_PAYLOAD_MAX];
    uint32_t outLen;
    HdlcEvent event;

    payload[0] = 0x80;
    payload[1] = 0x01;
    wire[0] = 0x7e; wire[1] = 0x80; wire[2] = 0x01; wire[3] = 0x02; wire[4] = 0x92; wire[5] = 0x7e;

    /* The reset exchange measured first (docs/internals/protocol.md §1). */
    frame[0] = 0;
    Test_Expect(Hdlc_Encode(payload, 2, frame, (uint32_t)sizeof frame, &len) == ZB_OK,
           "the reset payload encodes");
    Test_Expect(len == 6, "the framed form is flag, payload, FCS, flag");
    Test_Expect(Zb_memcmp(frame, wire, 6) == 0, "and it is byte-identical to what the RCP answered");

    /* The same validity test written the other way: register over payload+FCS, no split. */
    Test_Expect(Hdlc_ResidueValid(&wire[1], 4), "the residue constant holds on a real frame");
    Test_Expect(Hdlc_Fcs(payload, 2) == 0x9202, "and the FCS the wire carries is that value low byte first");

    Hdlc_Init(&dec);
    event = HDLC_EVENT_NONE;

    for (i = 0; i < 6; i++)
    {
        outLen = 0;
        event = Hdlc_Feed(&dec, wire[i], out, &outLen);
    }

    Test_Expect(event == HDLC_EVENT_FRAME, "the frame closes on its last flag");
    Test_Expect(outLen == 2 && out[0] == 0x80 && out[1] == 0x01, "with the payload and no FCS");
    Test_Expect(Hdlc_FramesOk(&dec) == 1 && Hdlc_Drops(&dec) == 0, "counted once, dropped never");
}

static void caseEscapes(void)
{
    uint8_t payload[8];
    uint8_t frame[32];
    uint32_t len;

    payload[0] = 0x11;
    payload[1] = 0x13;
    payload[2] = 0x7d;
    payload[3] = 0x7e;
    payload[4] = 0xf8;
    payload[5] = 0x00;
    payload[6] = 0x20;
    payload[7] = 0x80;

    Test_Expect(Hdlc_NeedsEscape(0x11) && Hdlc_NeedsEscape(0x13) && Hdlc_NeedsEscape(0xf8)
           && Hdlc_NeedsEscape(0x7d) && Hdlc_NeedsEscape(0x7e),
           "the escape set is the five octets the RCP escapes, not just the two framing ones");
    Test_Expect(!Hdlc_NeedsEscape(0x20) && !Hdlc_NeedsEscape(0x00) && !Hdlc_NeedsEscape(0x7c),
           "and nothing else");

    /* Five escaped octets add five pairs; the FCS 0x9202 escapes its 0xf8-free pair too,
       so its low octet 0x02 stays raw and the high octet 0x92 stays raw. */
    Test_Expect(Hdlc_Encode(payload, 8, frame, (uint32_t)sizeof frame, &len) == ZB_OK,
           "an all-escape payload encodes");
    Test_Expect(len == 1 + 13 + 2 + 1, "flag, eight payload octets of which five escape, two FCS octets, flag");
}

static void caseEscapeRoundTrip(void)
{
    Hdlc_Decoder dec;
    uint8_t payload[8];
    uint8_t frame[32];
    uint8_t out[HDLC_PAYLOAD_MAX];
    uint32_t len;
    uint32_t i;
    uint32_t outLen;
    HdlcEvent event;

    payload[0] = 0x11;
    payload[1] = 0x13;
    payload[2] = 0x7d;
    payload[3] = 0x7e;
    payload[4] = 0xf8;
    payload[5] = 0x00;
    payload[6] = 0x20;
    payload[7] = 0x80;

    Test_Expect(Hdlc_Encode(payload, 8, frame, (uint32_t)sizeof frame, &len) == ZB_OK, "encoded");

    Hdlc_Init(&dec);
    event = HDLC_EVENT_NONE;

    for (i = 0; i < len; i++)
    {
        outLen = 0;
        event = Hdlc_Feed(&dec, frame[i], out, &outLen);
    }

    Test_Expect(event == HDLC_EVENT_FRAME && outLen == 8, "the frame closes with its payload length");
    Test_Expect(Zb_memcmp(out, payload, 8) == 0, "byte for byte, escapes undone");
}

static void caseResyncAndDrops(void)
{
    static const uint8_t shortFrame[3] = { 0x7e, 0x01, 0x7e };
    static const uint8_t dangling[3] = { 0x7e, 0x7d, 0x7e };
    static const uint8_t known[6] = { 0x7e, 0x80, 0x01, 0x02, 0x92, 0x7e };
    uint8_t longFrame[300];
    uint8_t twin[4];
    uint8_t broken[6];
    uint8_t out[HDLC_PAYLOAD_MAX];
    uint32_t i;
    uint32_t outLen;
    Hdlc_Decoder dec;
    HdlcEvent event;

    Hdlc_Init(&dec);
    event = HDLC_EVENT_NONE;

    for (i = 0; i < 3; i++)
    {
        outLen = 0;
        event = Hdlc_Feed(&dec, shortFrame[i], out, &outLen);
    }

    Test_Expect(event == HDLC_EVENT_DROP_SHORT, "a frame shorter than its FCS is discarded");
    Test_Expect(Hdlc_Drops(&dec) == 1 && Hdlc_FramesOk(&dec) == 0, "and the discard is counted");

    Hdlc_Init(&dec);
    event = HDLC_EVENT_NONE;

    for (i = 0; i < 3; i++)
    {
        outLen = 0;
        event = Hdlc_Feed(&dec, dangling[i], out, &outLen);
    }

    Test_Expect(event == HDLC_EVENT_NONE && Hdlc_Drops(&dec) == 0,
           "an escape left hanging at the flag contributed nothing, so nothing was dropped");

    /* One octet flipped in the payload: full length, FCS disagrees, nothing is delivered. */
    broken[0] = 0x7e;
    broken[1] = 0x80;
    broken[2] = 0x02;
    broken[3] = 0x02;
    broken[4] = 0x92;
    broken[5] = 0x7e;
    Hdlc_Init(&dec);
    event = HDLC_EVENT_NONE;

    for (i = 0; i < 6; i++)
    {
        outLen = 0;
        event = Hdlc_Feed(&dec, broken[i], out, &outLen);
    }

    Test_Expect(event == HDLC_EVENT_DROP_FCS, "a corrupt payload is reported, not passed on as data");
    Test_Expect(outLen == 0, "and no length is claimed for it");

    /* A frame that outgrows the maximum is discarded whole rather than truncated and kept. */
    longFrame[0] = 0x7e;

    for (i = 1; i < 260; i++)
        longFrame[i] = (uint8_t)(0x80 + (i % 0x60));   /* no flag or escape hiding inside */

    longFrame[260] = 0x7e;
    Hdlc_Init(&dec);
    event = HDLC_EVENT_NONE;

    for (i = 0; i < 261; i++)
    {
        outLen = 0;
        event = Hdlc_Feed(&dec, longFrame[i], out, &outLen);
    }

    Test_Expect(event == HDLC_EVENT_DROP_LONG, "the overlong frame is dropped, not shortened");
    Test_Expect(Hdlc_FramesOk(&dec) == 0, "nothing was delivered from it");

    /* Its closing flag opened the next frame, so a good frame after a drop still decodes. */
    for (i = 1; i < 6; i++)
    {
        outLen = 0;
        event = Hdlc_Feed(&dec, known[i], out, &outLen);
    }

    Test_Expect(event == HDLC_EVENT_FRAME && outLen == 2 && out[0] == 0x80,
           "the decoder resynchronises on the frame that follows a drop");
    Test_Expect(Hdlc_FramesOk(&dec) == 1 && Hdlc_Drops(&dec) == 1, "one good frame, one counted drop");

    /* Two flags in a row: the first closed nothing and the second opens nothing. */
    twin[0] = 0x7e;
    twin[1] = 0x7e;
    twin[2] = 0x7e;
    twin[3] = 0x7e;
    Hdlc_Init(&dec);

    for (i = 0; i < 4; i++)
    {
        outLen = 0;
        event = Hdlc_Feed(&dec, twin[i], out, &outLen);
        Test_Expect(event == HDLC_EVENT_NONE, "an empty frame between two flags is not an event");
    }

    Test_Expect(Hdlc_Drops(&dec) == 0 && Hdlc_FramesOk(&dec) == 0, "and it manufactures no drop");
}

static void caseSharedFlag(void)
{
    uint8_t a[4];
    uint8_t b[4];
    uint8_t wire[24];
    uint32_t lenA;
    uint32_t lenB;
    uint32_t frames;
    uint32_t drops;
    uint32_t maxLen;
    Hdlc_Decoder dec;

    a[0] = 0x80; a[1] = 0x01;
    b[0] = 0x81; b[1] = 0x02; b[2] = 0x03;

    Test_Expect(Hdlc_Encode(a, 2, wire, (uint32_t)sizeof wire, &lenA) == ZB_OK, "first frame encodes");
    Test_Expect(Hdlc_Encode(b, 3, &wire[lenA - 1], (uint32_t)sizeof wire - lenA + 1, &lenB) == ZB_OK,
           "the second frame reuses the first one's closing flag");

    Hdlc_Init(&dec);
    runStream(&dec, wire, lenA + lenB - 1, &frames, &drops, &maxLen);
    Test_Expect(frames == 2 && drops == 0, "one shared flag is both a close and an open");
}

static void caseOneFixture(const char *name, uint32_t wantFrames)
{
    uint8_t bytes[FIXTURE_MAX];
    uint32_t len;
    uint32_t frames;
    uint32_t drops;
    uint32_t maxLen;
    Hdlc_Decoder dec;

    len = fixtureReadHex(name, bytes, FIXTURE_MAX);
    Test_Expect(len > 0, name);
    Test_Expect(len <= FIXTURE_MAX, "the fixture fits the read buffer");

    Hdlc_Init(&dec);
    runStream(&dec, bytes, len, &frames, &drops, &maxLen);
    Test_Expect(frames == wantFrames, "the C decoder reproduces the harness frame count");
    Test_Expect(drops == 0, "with nothing discarded: these transcripts are clean at the link layer");
    Test_Expect(maxLen <= HDLC_PAYLOAD_MAX, "and no frame exceeded the frame maximum");
    Test_Expect(Hdlc_FramesOk(&dec) == frames, "the decoder's own tally agrees with the events it returned");
}

static void caseFixtures(void)
{
    caseOneFixture(ZB_SAMPLES_DIR "/" "port_conb2_raw.hex", 39);
    caseOneFixture(ZB_SAMPLES_DIR "/" "port_conb2a_raw.hex", 7);
    caseOneFixture(ZB_SAMPLES_DIR "/" "port_conb2b_raw.hex", 49);
}

int main(void)
{
    Test_Begin("hdlc");

    caseKnownAnswer();
    caseEscapes();
    caseEscapeRoundTrip();
    caseResyncAndDrops();
    caseSharedFlag();
    caseFixtures();

    return Test_Report();
}
