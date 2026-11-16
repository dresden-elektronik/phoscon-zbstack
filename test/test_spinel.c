/* Suite for the Spinel codec: the packed-uint known answers, the header fields as the wire
   carries them, the typed value shapes of docs/internals/protocol.md §8 read out of captured
   notifications, and fault injection against truncated and malformed arguments. */

#include "hdlc.h"
#include "radio.h"
#include "spinel.h"
#include "test_fixture.h"
#include "test_harness.h"
#include "zb_utils.h"

#ifndef ZB_SAMPLES_DIR
#define ZB_SAMPLES_DIR "."
#endif

#define FIXTURE_MAX 4096
#define RANDOM_CASES 300
#define RANDOM_MAX_LEN 48
#define TABLE_LEN(table) (sizeof table / sizeof table[0])

/* The id a captured notification carries. The property table itself is props.c's business;
   this suite only needs the one id the bench recorded (docs/internals/protocol.md §8.1). */
#define PROP_STREAM_RAW 0x71

static void openWrite(U_BStream *stream, uint8_t *buf, uint32_t cap)
{
    U_bstream_init(stream, buf, (unsigned long)cap);
}

static void openRead(U_BStream *stream, uint8_t *buf, uint32_t len)
{
    U_bstream_init(stream, buf, (unsigned long)len);
}

static uint32_t nextRandom(uint32_t *state)
{
    /* Fixed seed, no wall clock. */
    *state = *state * 1103515245 + 12345;
    return (*state >> 16) & 0xff;
}

static void casePackedUint(void)
{
    static const uint8_t wireOne[] = { 0x00 };
    static const uint8_t wireTwo[] = { 0x7f };
    static const uint8_t wireThree[] = { 0x80, 0x01 };
    static const uint8_t wireFour[] = { 0xb0, 0x01 };
    static const uint8_t wireFive[] = { 0x88, 0x20 };
    static const uint8_t wireSix[] = { 0x8b, 0x24 };
    static const uint8_t wireSeven[] = { 0xff, 0xff, 0xff, 0x7f };
    static const uint8_t wireEight[] = { 0x80, 0x80, 0x80, 0x80, 0x01 };
    static const uint8_t wireNine[] = { 0xff, 0xff, 0xff, 0xff, 0x0f };
    static const uint32_t values[] =
    {
        0, 127, 128, 0xb0, 0x1008, 0x120b, 0x0fffffff, 0x10000000, 0xffffffff
    };
    static const uint8_t *const wire[] =
    {
        wireOne, wireTwo, wireThree, wireFour, wireFive,
        wireSix, wireSeven, wireEight, wireNine
    };
    static const uint32_t wireLen[] = { 1, 1, 2, 2, 2, 2, 4, 5, 5 };
    uint8_t buf[8];
    U_BStream stream;
    uint32_t i;

    /* docs/internals/protocol.md §4: the encodings the harness asserts before it touches a port. */
    for (i = 0; i < TABLE_LEN(values); i++)
    {
        openWrite(&stream, buf, (uint32_t)sizeof buf);
        Spinel_WritePackedUint(&stream, values[i]);
        Test_Expect(!Spinel_StreamFailed(&stream), "a 32-bit value always encodes");
        Test_Expect((uint32_t)stream.pos == wireLen[i], "the wire form is the recorded one");
        Test_Expect(Zb_memcmp(buf, wire[i], wireLen[i]) == 0, "octet for octet");
        Test_Expect(Spinel_PackedUintBytes(values[i]) == wireLen[i],
               "and the sizing helper predicts that length before anything is written");

        openRead(&stream, buf, wireLen[i]);
        Test_Expect(Spinel_ReadPackedUint(&stream) == values[i], "the value reads back");
        Test_Expect(!Spinel_StreamFailed(&stream), "from a clean field");
        Test_Expect(Spinel_Remaining(&stream) == 0, "and consumes exactly its own octets");
    }
}

static void casePackedUintFaults(void)
{
    uint8_t truncated[] = { 0x8b };
    uint8_t tooMany[] = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 };
    uint8_t tooWide[] = { 0xff, 0xff, 0xff, 0xff, 0x10 };
    uint8_t redundant[] = { 0x80, 0x00 };
    uint8_t nothing[1];
    U_BStream stream;

    openRead(&stream, truncated, (uint32_t)sizeof truncated);
    Test_Expect(Spinel_ReadPackedUint(&stream) == 0, "a continuation running off the end yields nothing");
    Test_Expect(Spinel_StreamFailed(&stream), "and says so");
    openRead(&stream, tooMany, (uint32_t)sizeof tooMany);
    Test_Expect(Spinel_ReadPackedUint(&stream) == 0, "a sixth group is not a 32-bit value");
    Test_Expect(Spinel_StreamFailed(&stream), "and is a decode error, not a large number");

    openRead(&stream, tooWide, (uint32_t)sizeof tooWide);
    Test_Expect(Spinel_ReadPackedUint(&stream) == 0,
           "a fifth group that needs bits above 31 is refused where upstream truncates it");
    Test_Expect(Spinel_StreamFailed(&stream), "with the failure stated");

    /* A redundant continuation byte decodes to an unambiguous value: rejecting it would reject
       frames the RCPs accept (docs/internals/protocol.md §4). */
    openRead(&stream, redundant, (uint32_t)sizeof redundant);
    Test_Expect(Spinel_ReadPackedUint(&stream) == 0, "non-canonical zero still reads as zero");
    Test_Expect(!Spinel_StreamFailed(&stream), "and is not an error");
    Test_Expect(Spinel_Remaining(&stream) == 0, "consumed as written");

    openRead(&stream, nothing, 0);
    Test_Expect(Spinel_ReadPackedUint(&stream) == 0, "an empty frame yields nothing");
    Test_Expect(Spinel_StreamFailed(&stream), "and is reported");
}

static void caseHeader(void)
{
    Spinel_Header header;
    uint8_t octet;

    Test_Expect(Spinel_HeaderByte(0) == 0x80, "a frame with no transaction id is 0x80");
    Test_Expect(Spinel_HeaderByte(1) == 0x81, "the first TID a session allocates");
    Test_Expect(Spinel_HeaderByte(15) == 0x8f, "the last one, before the wrap of docs/internals/protocol.md §5");
    Test_Expect(Spinel_HeaderByte(16) == 0x80, "an out-of-range TID masks to 0, which is a caller error");
    Test_Expect(!Spinel_TidValid(0), "TID 0 is never allocatable");
    Test_Expect(Spinel_TidValid(1) && Spinel_TidValid(15), "1..15 are");
    Test_Expect(!Spinel_TidValid(16), "and 16 is not");

    for (octet = 0x80; octet <= 0xbf; octet++)
        Test_Expect(Spinel_HeaderValid(octet), "every header this family puts on the wire is valid");

    Test_Expect(!Spinel_HeaderValid(0x00), "a header without the flag bits 0b10 is not a frame here");
    Test_Expect(!Spinel_HeaderValid(0x40), "nor one that reserves bit 6 for something else");
    Test_Expect(!Spinel_HeaderValid(0xc0), "nor the other value of the two flag bits");

    Spinel_ReadHeader(0x86, &header);
    Test_Expect(header.flags == 0x02 && header.iid == 0 && header.tid == 6, "flag, IID and TID split as §3 says");
    Test_Expect(!Spinel_IsNotification(&header), "a TID-bearing frame is not a notification");

    Spinel_ReadHeader(0x80, &header);
    Test_Expect(Spinel_IsNotification(&header), "TID 0 is");
    Test_Expect(Spinel_IidValid(&header), "with the only IID ever measured");

    Spinel_ReadHeader(0x90, &header);
    Test_Expect(header.iid == 1 && header.tid == 0, "a non-zero IID is reported, not folded to zero");
    Test_Expect(Spinel_IsNotification(&header), "and does not disturb the TID reading");

    Spinel_ReadHeader(0xbf, &header);
    Test_Expect(header.iid == 3 && header.tid == 15, "the extremes of both fields");
}

/* The two GET frames and the reset frame the harness asserts on import, composed here from
   the codec and the framing layer: band B producing a known answer from two modules that know
   nothing about each other beyond a payload buffer. */
static void caseKnownAnswerFrames(void)
{
    uint8_t payload[16];
    uint8_t frame[32];
    uint8_t wire[32];
    U_BStream stream;
    Spinel_Header header;
    uint32_t len;

    /* RESET, TID 0: `7e 80 01 02 92 7e` is the exchange that established this link. */
    wire[0] = 0x7e; wire[1] = 0x80; wire[2] = 0x01; wire[3] = 0x02; wire[4] = 0x92; wire[5] = 0x7e;
    openWrite(&stream, payload, (uint32_t)sizeof payload);
    Spinel_WriteHeader(&stream, SPINEL_TID_NONE);
    Spinel_WritePackedUint(&stream, SPINEL_CMD_RESET);
    Test_Expect(!Spinel_StreamFailed(&stream), "the reset payload composes");
    Test_Expect(Hdlc_Encode(payload, (uint32_t)stream.pos, frame, (uint32_t)sizeof frame, &len) == ZB_OK,
           "and frames");
    Test_Expect(len == 6 && Zb_memcmp(frame, wire, 6) == 0, "byte-identical to the measured frame");

    /* GET PROPS_SUPPORT (id 2) with TID 1: `7e 81 02 02 5e 80 7e`. */
    wire[0] = 0x7e; wire[1] = 0x81; wire[2] = 0x02; wire[3] = 0x02;
    wire[4] = 0x5e; wire[5] = 0x80; wire[6] = 0x7e;
    openWrite(&stream, payload, (uint32_t)sizeof payload);
    Spinel_WriteHeader(&stream, 1);
    Spinel_WritePackedUint(&stream, SPINEL_CMD_PROP_VALUE_GET);
    Spinel_WritePackedUint(&stream, 2);
    Test_Expect(Hdlc_Encode(payload, (uint32_t)stream.pos, frame, (uint32_t)sizeof frame, &len) == ZB_OK,
           "a GET composes");
    Test_Expect(len == 7 && Zb_memcmp(frame, wire, 7) == 0, "and matches its measured frame");

    /* GET a property above 0x7f (0xB0 here), which is where a single raw byte is a wire error. */
    wire[0] = 0x7e; wire[1] = 0x81; wire[2] = 0x02; wire[3] = 0xb0; wire[4] = 0x01;
    wire[5] = 0x54; wire[6] = 0x53; wire[7] = 0x7e;
    openWrite(&stream, payload, (uint32_t)sizeof payload);
    Spinel_WriteHeader(&stream, 1);
    Spinel_WritePackedUint(&stream, SPINEL_CMD_PROP_VALUE_GET);
    Spinel_WritePackedUint(&stream, 0xb0);
    Test_Expect(Hdlc_Encode(payload, (uint32_t)stream.pos, frame, (uint32_t)sizeof frame, &len) == ZB_OK,
           "a multi-byte property id composes");
    Test_Expect(len == 8 && Zb_memcmp(frame, wire, 8) == 0, "in the two-octet form the RCP expects");

    /* Reading that frame back recovers the header, the command and the property id. */
    openRead(&stream, payload, (uint32_t)stream.pos);
    Spinel_ReadHeader(Spinel_ReadUint8(&stream), &header);
    Test_Expect(Spinel_HeaderValid(payload[0]), "the frame this codec wrote is a valid header");
    Test_Expect(header.tid == 1, "carrying the TID it was composed with");
    Test_Expect(Spinel_ReadPackedUint(&stream) == SPINEL_CMD_PROP_VALUE_GET, "the command reads back");
    Test_Expect(Spinel_ReadPackedUint(&stream) == 0xb0, "the property id reads back");
    Test_Expect(!Spinel_StreamFailed(&stream), "and the frame was exactly long enough");
}
static void caseTypedValues(void)
{
    uint8_t buf[32];
    U_BStream stream;
    const uint8_t *span;
    uint32_t spanLen;

    /* Little-endian on the wire, asserted as bytes and not just as a round-trip. */
    openWrite(&stream, buf, (uint32_t)sizeof buf);
    Spinel_WriteUint16(&stream, 0x1234);
    Spinel_WriteInt16(&stream, -2);
    Spinel_WriteUint32(&stream, 0xdeadbeef);
    Spinel_WriteInt32(&stream, -1);
    Spinel_WriteUint64(&stream, 0x0102030405060708);
    Spinel_WriteBool(&stream, 1);
    Spinel_WriteBool(&stream, 0);
    Spinel_WriteInt8(&stream, -128);
    Test_Expect(!Spinel_StreamFailed(&stream), "every typed width writes");
    Test_Expect(buf[0] == 0x34 && buf[1] == 0x12, "u16 least significant octet first");
    Test_Expect(buf[2] == 0xfe && buf[3] == 0xff, "i16 the same, two's complement");
    Test_Expect(buf[4] == 0xef && buf[7] == 0xde, "u32 four octets");
    Test_Expect(buf[8] == 0xff && buf[11] == 0xff, "i32 -1 as ff ff ff ff");
    Test_Expect(buf[12] == 0x08 && buf[19] == 0x01, "u64 eight octets, the timestamp width of §8.1");
    Test_Expect(buf[20] == 0x01 && buf[21] == 0x00, "a bool is one octet of 0 or 1");
    Test_Expect(buf[22] == 0x80, "i8 -128 as one octet");

    openRead(&stream, buf, 23);
    Test_Expect(Spinel_ReadUint16(&stream) == 0x1234, "u16 reads back");
    Test_Expect(Spinel_ReadInt16(&stream) == -2, "i16 reads back");
    Test_Expect(Spinel_ReadUint32(&stream) == 0xdeadbeef, "u32 reads back");
    Test_Expect(Spinel_ReadInt32(&stream) == -1, "i32 reads back");
    Test_Expect(Spinel_ReadUint64(&stream) == 0x0102030405060708, "u64 reads back");
    Test_Expect(Spinel_ReadBool(&stream) == 1, "true reads back");
    Test_Expect(Spinel_ReadBool(&stream) == 0, "false reads back");
    Test_Expect(Spinel_ReadInt8(&stream) == -128, "i8 reads back");
    Test_Expect(!Spinel_StreamFailed(&stream) && Spinel_Remaining(&stream) == 0, "with the field accounted for");

    /* The one coercion this codec is allowed: any non-zero octet is true. */
    buf[0] = 0x02;
    openRead(&stream, buf, 1);
    Test_Expect(Spinel_ReadBool(&stream) == 1, "a device that writes 2 for true is read as true");

    /* A length prefix that runs past the end of the frame is a decode error, and the reader
       hands back a span rather than a copy. */
    buf[0] = 0xff;
    buf[1] = 0xff;
    openRead(&stream, buf, 2);
    span = Spinel_ReadPrefixed(&stream, &spanLen);
    Test_Expect(span == 0 && spanLen == 0, "a 65535-octet field in a 2-octet frame is not a field");
    Test_Expect(Spinel_StreamFailed(&stream), "and is reported once, not followed by a wild read");

    buf[0] = 0x00;
    buf[1] = 0x00;
    openRead(&stream, buf, 2);
    span = Spinel_ReadPrefixed(&stream, &spanLen);
    Test_Expect(spanLen == 0, "an empty prefixed field is legal: an RX error carries no PSDU");
    Test_Expect(!Spinel_StreamFailed(&stream), "and is not a failure");

    /* A string without its terminator inside the frame is a decode error. */
    buf[0] = 'A';
    buf[1] = 'B';
    buf[2] = 0x00;
    openRead(&stream, buf, 3);
    span = Spinel_ReadString(&stream, &spanLen);
    Test_Expect(span == buf && spanLen == 2, "a terminated string reads back as a span");
    Test_Expect(Spinel_Remaining(&stream) == 0, "terminator consumed");
    Test_Expect(!Spinel_StreamFailed(&stream), "clean");

    openRead(&stream, buf, 2);
    span = Spinel_ReadString(&stream, &spanLen);
    Test_Expect(span == 0 && spanLen == 0, "an unterminated string is refused");
    Test_Expect(Spinel_StreamFailed(&stream), "with the failure stated");
}

static void caseBigEndian(void)
{
    uint8_t buf[24];
    uint8_t addr[8];
    uint8_t read[8];
    const uint8_t *span;
    U_BStream stream;
    uint32_t i;

    /* docs/internals/hardware.md §5: MAC_15_4_LADDR is big-endian on the wire, and the codec names
       both byte orders (D-5), so the big-endian widths are pinned here too. */
    openWrite(&stream, buf, (uint32_t)sizeof buf);
    Spinel_WriteUint16Be(&stream, 0x1234);
    Spinel_WriteUint32Be(&stream, 0xdeadbeef);
    Spinel_WriteUint64Be(&stream, 0x0102030405060708);
    Test_Expect(!Spinel_StreamFailed(&stream), "the big-endian widths write");
    Test_Expect(buf[0] == 0x12 && buf[1] == 0x34, "u16 most significant octet first");
    Test_Expect(buf[2] == 0xde && buf[5] == 0xef, "u32 likewise");
    Test_Expect(buf[6] == 0x01 && buf[13] == 0x08, "u64 likewise");

    openRead(&stream, buf, 14);
    Test_Expect(Spinel_ReadUint16Be(&stream) == 0x1234, "u16 reads back");
    Test_Expect(Spinel_ReadUint32Be(&stream) == 0xdeadbeef, "u32 reads back");
    Test_Expect(Spinel_ReadUint64Be(&stream) == 0x0102030405060708, "u64 reads back");
    Test_Expect(!Spinel_StreamFailed(&stream) && Spinel_Remaining(&stream) == 0, "with the field accounted for");

    for (i = 0; i < 8; i++)
        addr[i] = (uint8_t)(0x10 + i);

    openWrite(&stream, buf, (uint32_t)sizeof buf);
    Spinel_WriteAddrBe(&stream, addr, 8);
    Test_Expect(!Spinel_StreamFailed(&stream) && (uint32_t)stream.pos == 8, "an EUI-64 goes out in address order");
    Test_Expect(Zb_memcmp(buf, addr, 8) == 0, "octet for octet, unconverted");

    openRead(&stream, buf, 8);
    span = Spinel_ReadAddrBe(&stream, read, 8);
    Test_Expect(span == read && Zb_memcmp(read, addr, 8) == 0, "and comes back in the same order");
    Test_Expect(!Spinel_StreamFailed(&stream), "from a frame long enough");

    openRead(&stream, buf, 7);
    span = Spinel_ReadAddrBe(&stream, read, 8);
    Test_Expect(span == 0, "a short frame is refused rather than answered with a partial address");
    Test_Expect(Spinel_StreamFailed(&stream), "and says so");
}

static void caseWriterBounds(void)
{
    uint8_t payload[128];
    uint8_t frame[HDLC_FRAME_MAX];
    uint8_t decoded[HDLC_PAYLOAD_MAX];
    uint8_t psdu[64];
    U_BStream stream;
    Hdlc_Decoder decoder;
    uint32_t needed;
    uint32_t len;
    uint32_t written;
    uint32_t outLen;
    uint32_t i;
    ZbStatus status;

    for (i = 0; i < 64; i++)
        psdu[i] = (uint8_t)i;

    /* 0x71 is below 0x80, so the property id is one octet here; a 64-octet PSDU costs its own
       two length octets. SET of a 64-octet PSDU = 1 + 1 + 1 + 2 + 64. */
    needed = SPINEL_HEADER_BYTES
           + Spinel_PackedUintBytes(SPINEL_CMD_PROP_VALUE_SET)
           + Spinel_PackedUintBytes(PROP_STREAM_RAW)
           + Spinel_PrefixedBytes(64);
    Test_Expect(needed == 69, "the helpers size the frame before it is composed");

    openWrite(&stream, payload, needed);
    Spinel_WriteHeader(&stream, 1);
    Spinel_WritePackedUint(&stream, SPINEL_CMD_PROP_VALUE_SET);
    Spinel_WritePackedUint(&stream, PROP_STREAM_RAW);
    Spinel_WritePrefixed(&stream, psdu, 64);
    Test_Expect(!Spinel_StreamFailed(&stream), "a buffer sized by the helpers holds it");
    Test_Expect((uint32_t)stream.pos == needed, "exactly full, nothing spilling");

    status = Hdlc_Encode(payload, needed, frame, (uint32_t)sizeof frame, &len);
    Test_Expect(status == ZB_OK, "and it frames, escaping the 0x11 and 0x13 inside the PSDU");
    Test_Expect(len > needed + HDLC_FCS_LEN, "the escape set costs octets on this frame");

    Hdlc_Init(&decoder);
    written = 0;

    for (i = 0; i < len; i++)
    {
        if (Hdlc_Feed(&decoder, frame[i], decoded, &outLen) == HDLC_EVENT_FRAME)
            written = outLen;
    }

    Test_Expect(written == needed && Zb_memcmp(decoded, payload, needed) == 0,
           "and the same bytes come back out of the framing layer");

    /* One octet short: the prefixed field refuses, and what was already composed stays composed. */
    openWrite(&stream, payload, needed - 1);
    Spinel_WriteHeader(&stream, 1);
    Spinel_WritePackedUint(&stream, SPINEL_CMD_PROP_VALUE_SET);
    Spinel_WritePackedUint(&stream, PROP_STREAM_RAW);
    written = (uint32_t)stream.pos;
    Spinel_WritePrefixed(&stream, psdu, 64);
    Test_Expect(Spinel_StreamFailed(&stream), "a short buffer is a stated failure");
    Test_Expect((uint32_t)stream.pos == written, "and a length-prefixed field is never half-written");
}

static void caseFaultInjection(void)
{
    uint8_t buf[RANDOM_MAX_LEN];
    U_BStream stream;
    uint32_t caseIndex;
    uint32_t i;
    uint32_t seed;
    uint32_t len;
    uint32_t overrun;

    overrun = 0;

    for (caseIndex = 0; caseIndex < RANDOM_CASES; caseIndex++)
    {
        seed = caseIndex + 1;
        len = 1 + (nextRandom(&seed) % RANDOM_MAX_LEN);

        for (i = 0; i < len; i++)
            buf[i] = (uint8_t)nextRandom(&seed);

        /* The shape of a notification read out of noise: header octet, command, property id,
           two length-prefixed fields, a fixed field, an i8, a string. Every step has to stay
           inside the buffer, and a failure has to be stated rather than inferred from a zero
           that could also have been data. */
        openRead(&stream, buf, len);
        Spinel_ReadHeader(Spinel_ReadUint8(&stream), 0);
        (void)Spinel_ReadPackedUint(&stream);
        (void)Spinel_ReadPackedUint(&stream);
        (void)Spinel_ReadPrefixed(&stream, 0);
        (void)Spinel_ReadPrefixed(&stream, 0);
        (void)Spinel_ReadUint32(&stream);
        (void)Spinel_ReadInt8(&stream);
        (void)Spinel_ReadString(&stream, 0);

        if (stream.pos > stream.size)
            overrun++;

        if (Spinel_Remaining(&stream) != (Spinel_StreamFailed(&stream) ? 0 : (uint32_t)(stream.size - stream.pos)))
            overrun++;
    }

    Test_Expect(overrun == 0, "no random stream moves the cursor outside its buffer");
}

/* What the recorded STREAM_RAW notifications contain, measured field by field out of the
   transcripts themselves (docs/internals/protocol.md §8.1, docs/internals/hardware.md §6). */
typedef struct FixtureExpect
{
    const char *path;
    uint32_t frames;
    uint8_t channel;
    uint32_t badFcs;
    uint32_t psduMin;
    uint32_t psduMax;
    int8_t rssiMin;
    int8_t rssiMax;
    uint32_t stampEqual;
} Fixture_Expect;

static void caseNotificationValue(const Fixture_Expect *want)
{
    static uint8_t bytes[FIXTURE_MAX];
    Hdlc_Decoder decoder;
    U_BStream stream;
    uint8_t frame[HDLC_PAYLOAD_MAX];
    Spinel_Header header;
    const uint8_t *psdu;
    const uint8_t *phy;
    const uint8_t *vend;
    const uint8_t *mac;
    uint32_t len;
    uint32_t fieldLen;
    uint32_t psduLen;
    uint32_t i;
    uint32_t frames;
    uint32_t complete;
    uint32_t notify;
    uint32_t rawProp;
    uint32_t badFcs;
    uint32_t wrongChannel;
    uint32_t wrongNoise;
    uint32_t wrongShape;
    uint32_t wrongError;
    uint32_t ackRecorded;
    uint32_t txFlagged;
    uint32_t stampBackwards;
    uint32_t stampEqual;
    uint32_t stampQuantum;
    uint64_t stampResidue;
    int8_t rssi;
    int8_t noise;
    int8_t rssiMin;
    int8_t rssiMax;
    uint16_t mdFlag;
    uint16_t psduMaxSeen;
    uint16_t psduMinSeen;
    uint8_t structBuf[10];
    uint64_t stamp;
    uint64_t stampPrev;
    U_BStream inner;
    int first;
    HdlcEvent event;

    len = fixtureReadHex(want->path, bytes, FIXTURE_MAX);
    Test_Expect(len > 0 && len <= FIXTURE_MAX, "the transcript is readable");

    Hdlc_Init(&decoder);
    frames = 0;
    complete = 0;
    notify = 0;
    rawProp = 0;
    badFcs = 0;
    wrongChannel = 0;
    wrongNoise = 0;
    wrongShape = 0;
    wrongError = 0;
    ackRecorded = 0;
    txFlagged = 0;
    stampBackwards = 0;
    stampEqual = 0;
    stampQuantum = 0;
    stampResidue = 0;
    psduMaxSeen = 0;
    psduMinSeen = 0xffff;
    stamp = 0;
    stampPrev = 0;
    rssiMin = 0;
    rssiMax = 0;
    first = 1;

    for (i = 0; i < len; i++)
    {
        event = Hdlc_Feed(&decoder, bytes[i], frame, &fieldLen);

        if (event != HDLC_EVENT_FRAME)
            continue;

        frames++;
        openRead(&stream, frame, fieldLen);
        Spinel_ReadHeader(Spinel_ReadUint8(&stream), &header);

        if (!Spinel_HeaderValid(frame[0]) || header.iid != 0)
        {
            wrongShape++;
            continue;
        }

        if (header.tid == SPINEL_TID_NONE)
            notify++;

        if (Spinel_ReadPackedUint(&stream) != SPINEL_CMD_PROP_VALUE_IS)
        {
            wrongShape++;
            continue;
        }

        if (Spinel_ReadPackedUint(&stream) != PROP_STREAM_RAW)
        {
            wrongShape++;
            continue;
        }

        rawProp++;
        psdu = Spinel_ReadPrefixed(&stream, &psduLen);

        if (psdu == 0 || psduLen < 1 || psduLen > RADIO_MPDU_MAX)
        {
            wrongShape++;
            continue;
        }

        if (psduLen > psduMaxSeen)
            psduMaxSeen = (uint16_t)psduLen;

        if (psduLen < psduMinSeen)
            psduMinSeen = (uint16_t)psduLen;

        rssi = Spinel_ReadInt8(&stream);
        noise = Spinel_ReadInt8(&stream);
        mdFlag = Spinel_ReadUint16(&stream);

        if (first)
        {
            rssiMin = rssi;
            rssiMax = rssi;
            first = 0;
        }

        if (rssi < rssiMin)
            rssiMin = rssi;

        if (rssi > rssiMax)
            rssiMax = rssi;

        if (noise != -128)
            wrongNoise++;

        if ((mdFlag & SPINEL_MD_TX) != 0)
            txFlagged++;

        if (mdFlag == SPINEL_MD_BAD_FCS)
            badFcs++;

        phy = Spinel_ReadPrefixed(&stream, &fieldLen);

        if (phy == 0 || fieldLen != 10)
        {
            wrongShape++;
            continue;
        }

        /* Decode the metadata with the codec, from a copy of the span the decoder handed out:
           a length-prefixed group is consumed whole, so its fields are read through a reader
           over the group itself. */
        Zb_memcpy(structBuf, phy, fieldLen);
        openRead(&inner, structBuf, fieldLen);

        if (Spinel_ReadUint8(&inner) != want->channel)
            wrongChannel++;

        if (Spinel_ReadUint8(&inner) == 0)
            wrongShape++;

        stampPrev = stamp;
        stamp = Spinel_ReadUint64(&inner);

        if (stampResidue == 0 && stamp != 0)
            stampResidue = stamp % SPINEL_STAMP_QUANTUM;

        if (stamp < stampPrev)
            stampBackwards++;

        if (stamp == stampPrev)
            stampEqual++;

        if (stamp % SPINEL_STAMP_QUANTUM != stampResidue)
            stampQuantum++;

        if (Spinel_Remaining(&inner) != 0 || Spinel_StreamFailed(&inner))
            wrongShape++;

        vend = Spinel_ReadPrefixed(&stream, &fieldLen);

        if (vend == 0 || fieldLen != 1)
        {
            wrongShape++;
            continue;
        }

        Zb_memcpy(structBuf, vend, fieldLen);
        openRead(&inner, structBuf, fieldLen);

        if (Spinel_ReadPackedUint(&inner) != 0)
            wrongError++;

        mac = Spinel_ReadPrefixed(&stream, &fieldLen);

        if (mac == 0 || fieldLen != 5)
        {
            wrongShape++;
            continue;
        }

        Zb_memcpy(structBuf, mac, fieldLen);
        openRead(&inner, structBuf, fieldLen);

        if (Spinel_ReadUint8(&inner) != 0)
            ackRecorded++;

        if (Spinel_ReadUint32(&inner) != 0)
            ackRecorded++;

        /* The value ends where the frame ends: nothing after MD_MAC on either firmware. */
        if (Spinel_Remaining(&stream) != 0)
            wrongShape++;

        if (Spinel_StreamFailed(&stream) || Spinel_StreamFailed(&inner))
            wrongShape++;

        complete++;
    }

    Test_Expect(frames == want->frames, "the transcript holds the frames the fixture gate counts");
    Test_Expect(rawProp == want->frames, "every one of them a STREAM_RAW notification");
    Test_Expect(notify == want->frames, "every one unsolicited, TID 0");
    Test_Expect(complete == want->frames, "and every one decodes field for field to its end");
    Test_Expect(wrongChannel == 0, "the channel in MD_PHY is the armed one, on every frame");
    Test_Expect(wrongNoise == 0, "the noise floor is -128 on every frame");
    Test_Expect(wrongShape == 0, "the §8.1 shape holds: 10, 1 and 5 metadata octet groups, frame ends after MD_MAC");
    Test_Expect(wrongError == 0, "MD_VEND carries no RX error in these captures");
    Test_Expect(txFlagged == 0, "and an RX notification never carries the TX flag");
    Test_Expect(ackRecorded == 0, "no ACK was recorded by the radio on receive");
    Test_Expect(stampBackwards == 0, "the MD_PHY timestamp never moves backwards through a transcript");
    Test_Expect(stampQuantum == 0, "and on this build it is quantised: every stamp shares one millisecond residue");
    Test_Expect(stampEqual == want->stampEqual, "frames inside one millisecond share a stamp, which is measured, not a bug");
    Test_Expect(badFcs == want->badFcs, "the count of BAD_FCS-flagged frames is the measured one");
    Test_Expect(psduMinSeen == want->psduMin && psduMaxSeen == want->psduMax,
           "the PSDU lengths are the measured ones");
    Test_Expect(rssiMin >= want->rssiMin && rssiMax <= want->rssiMax, "and the RSSI stays in its measured band");
}

int main(void)
{
    Test_Begin("spinel_codec");

    static const Fixture_Expect fixtures[] =
    {
        { ZB_SAMPLES_DIR "/" "port_conb2_raw.hex",  39, 15,  0,  5, 65, -94, -76, 1 },
        { ZB_SAMPLES_DIR "/" "port_conb2a_raw.hex",  7, 20,  0, 47, 47, -94, -94, 0 },
        { ZB_SAMPLES_DIR "/" "port_conb2b_raw.hex", 49, 15, 11,  5, 65, -94, -94, 0 }
    };
    uint32_t i;

    casePackedUint();
    casePackedUintFaults();
    caseHeader();
    caseKnownAnswerFrames();
    caseTypedValues();
    caseBigEndian();
    caseWriterBounds();
    caseFaultInjection();

    for (i = 0; i < TABLE_LEN(fixtures); i++)
        caseNotificationValue(&fixtures[i]);

    return Test_Report();
}
