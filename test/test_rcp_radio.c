/* Suite for band B's RCP backend: a scripted RCP that answers what the measured firmwares answer,
   the seam contract driven through it, and the captured transcripts delivered through it. Nothing
   here touches a device node; every byte the backend writes is inspected. */

#include "hdlc.h"
#include "port_null.h"
#include "props.h"
#include "rcp_radio.h"
#include "spinel.h"
#include "test_fixture.h"
#include "test_harness.h"
#include "zb_utils.h"

#ifndef ZB_SAMPLES_DIR
#define ZB_SAMPLES_DIR "."
#endif

#define SCRIPT_CAP 4096
#define VALUE_CAP 256
#define FIXTURE_CAP 4096
#define BRING_UP_STEPS 40
#define REQUEST_QUEUE_MAX 8
#define TABLE_LEN(table) (sizeof table / sizeof table[0])

#define DSPINEL_VERSION "DSPINEL/1.0; AT86RF233"
#define OPENTHREAD_VERSION "SL-OPENTHREAD/2.3.2.0 MIPS"

/* The EUI-64 the ConBee II answered for HWADDR (docs/internals/protocol.md §7.2), in address order. */
static const uint8_t measuredHwaddr[RADIO_ADDR_LEN] =
{
    0x00, 0x21, 0x2e, 0xff, 0xff, 0x04, 0x8a, 0x12
};

/* The same value 0x00212effff048a12 as the PIB carries it: least significant octet first, the order
   `macExtendedValue` reads and the reverse of the wire's. */
static const uint8_t measuredPibAddress[RADIO_ADDR_LEN] =
{
    0x12, 0x8a, 0x04, 0xff, 0xff, 0x2e, 0x21, 0x00
};

/*
 * IEEE 802.15.4-2024 §7.2.11's own worked example: a three-octet acknowledgment MHR `02 00 6a` whose
 * FCS is `e4 79` (docs/internals/protocol.md §9.3). Band A composes a frame complete with its footer
 * (radio.h), so what a test hands the seam is the five-octet MPDU, and what band B hands the radio
 * depends on what that radio says about its own frames.
 */
static const uint8_t ackMhr[3] = { 0x02, 0x00, 0x6a };
static const uint8_t ackFcs[2] = { 0xe4, 0x79 };
static const uint8_t ackMpdu[5] = { 0x02, 0x00, 0x6a, 0xe4, 0x79 };

/* One request the backend put on the wire, decoded out of the octets the port was given. */
typedef struct Request
{
    uint8_t tid;
    uint8_t command;
    uint32_t propId;
    uint32_t valueLen;
    uint8_t value[VALUE_CAP];
} Request;

/* One recorded transcript and what test/fixtures/ says its octets contain. */
typedef struct RcpTranscript
{
    const char *path;
    uint32_t frames;
    uint32_t badFcs;
    uint32_t linkDrops;
} Rcp_Transcript;

typedef struct Rig
{
    Rcp_Radio radio;
    PortNullScript script;
    Hdlc_Decoder txDecoder;
    Request pending[REQUEST_QUEUE_MAX];
    uint32_t pendingCount;
    uint8_t rx[SCRIPT_CAP];
    uint32_t rxLen;
    uint8_t tx[SCRIPT_CAP];
    uint32_t txSeen;
    uint8_t stage[VALUE_CAP + 32];   /* one composed answer, before it is framed */
    const char *version;
    int resetAnswerCarriesTid;
    int refuseSrcMatch;
    uint32_t radioCaps;
    uint32_t apiVersion;
    uint32_t nowMs;
} Rig;

/* One request the backend put on the wire. */
static void rigInit(Rig *rig, const char *version, uint32_t radioCaps, uint32_t apiVersion)
{
    PortConfig config;

    /* Zeroed before anything else: a field added to the rig without a line here would otherwise
       arrive as whatever the stack happened to hold, which is how the reset-answer shape first read
       as a TID-bearing answer in one case and an unsolicited one in another. */
    Zb_memset(rig, 0, sizeof *rig);
    rig->version = version;
    rig->radioCaps = radioCaps;
    rig->apiVersion = apiVersion;
    rig->rxLen = 0;
    rig->txSeen = 0;
    rig->pendingCount = 0;
    Hdlc_Init(&rig->txDecoder);
    rig->nowMs = 1;

    Zb_memset(&rig->script, 0, sizeof rig->script);
    rig->script.rxBytes = rig->rx;
    rig->script.rxLen = 0;
    rig->script.rxChunk = 0;
    rig->script.txCapture = rig->tx;
    rig->script.txCapacity = SCRIPT_CAP;
    rig->script.failPumpAfter = 0xffffffff;
    rig->script.failDrainAfter = 0xffffffff;

    Test_Expect(RcpRadio_Init(&rig->radio, PortNullOps(), 300) == ZB_OK, "the backend initialises");

    PortNull_Attach(&rig->radio.port, &rig->script);

    config.baud = 0;
    config.rxRingSize = 0;
    config.txRingSize = 0;
    config.exclusive = 0;

    Test_Expect(RcpRadio_Open(&rig->radio, "/dev/rcp-null", &config) == ZB_OK, "the link opens");
}

/*
 * A scripted RCP's answer, composed in a staging buffer and then framed into the byte stream the
 * port will deliver. Staging separately matters: the framed form is longer than what it carries, and
 * building one inside the other would write past the frame it came from.
 */
static void rigWriteScalar(U_BStream *payload, uint8_t kind, uint32_t value);

static void rigAnswerBegin(Rig *rig, uint8_t tid, uint32_t propId, U_BStream *payload)
{
    U_bstream_init(payload, rig->stage, (unsigned long)sizeof rig->stage);
    Spinel_WriteHeader(payload, tid);
    Spinel_WritePackedUint(payload, SPINEL_CMD_PROP_VALUE_IS);
    Spinel_WritePackedUint(payload, propId);
}

static void rigCommitFrame(Rig *rig, U_BStream *payload)
{
    uint8_t wire[PORT_TX_RING_MAX];
    uint32_t payloadLen;
    uint32_t wireLen = 0;

    payloadLen = (uint32_t)sizeof rig->stage - Spinel_Remaining(payload);

    if (Hdlc_Encode(rig->stage, payloadLen, wire, (uint32_t)sizeof wire, &wireLen) != ZB_OK)
    {
        Test_Fault("a scripted answer did not fit one frame");
        return;
    }

    if (rig->rxLen + wireLen > SCRIPT_CAP)
    {
        Test_Fault("the scripted transcript outgrew the rig");
        return;
    }

    Zb_memcpy(rig->rx + rig->rxLen, wire, wireLen);
    rig->rxLen += wireLen;
    rig->script.rxLen = rig->rxLen;
}

static void rigAnswerStatus(Rig *rig, uint8_t tid, uint32_t status)
{
    U_BStream payload;

    rigAnswerBegin(rig, tid, PROP_LAST_STATUS, &payload);
    Spinel_WritePackedUint(&payload, status);
    rigCommitFrame(rig, &payload);
}

/*
 * A completion in the shape §8.9.4.2 writes: the code, then the two bits the device says about the exchange it
 * ran. D-47 measured `0 OK` with both bits zero, so a rig that answers the code alone is answering
 * less than the RCP does, and that difference is a fact band B keeps rather than smooths over.
 */
static void rigAnswerCompletion(Rig *rig, uint8_t tid, uint32_t status, int framePending, int headerUpdated)
{
    U_BStream payload;

    rigAnswerBegin(rig, tid, PROP_LAST_STATUS, &payload);
    Spinel_WritePackedUint(&payload, status);
    Spinel_WriteBool(&payload, framePending);
    Spinel_WriteBool(&payload, headerUpdated);
    rigCommitFrame(rig, &payload);
}

/* One trailing bit instead of two: a shape this stack refuses to interpret, because choosing which of the two
   bits an lone octet was would put a claim on the record that the device never made. */
static void rigAnswerCompletionOne(Rig *rig, uint8_t tid, uint32_t status, int firstBit)
{
    U_BStream payload;

    rigAnswerBegin(rig, tid, PROP_LAST_STATUS, &payload);
    Spinel_WritePackedUint(&payload, status);
    Spinel_WriteBool(&payload, firstBit);
    rigCommitFrame(rig, &payload);
}

/*
 * What shape a property has on this family, as docs/internals/protocol.md §7.2 read it off the RCP. The rig
 * needs its own copy of that answer: an RCP knows its own shapes, and the backend does not know
 * which dialect it is talking to until the version string has been answered, a rig that asked the
 * backend what to write would be asking it what it was.
 */
static const struct
{
    uint32_t propId;
    uint8_t kind;
} rigShapes[] =
{
    { PROP_NCP_VERSION, PROP_KIND_UTF8 },
    { PROP_INTERFACE_TYPE, PROP_KIND_U8 },
    { PROP_HWADDR, PROP_KIND_ADDR_BE },
    { PROP_PHY_ENABLED, PROP_KIND_BOOL },
    { PROP_PHY_CHAN, PROP_KIND_U8 },
    { PROP_PHY_CCA_THRESHOLD, PROP_KIND_I8 },
    { PROP_PHY_TX_POWER, PROP_KIND_I8 },
    { PROP_PHY_RSSI, PROP_KIND_I8 },
    { PROP_PHY_RX_SENSITIVITY, PROP_KIND_I8 },
    { PROP_MAC_15_4_LADDR, PROP_KIND_ADDR_BE },
    { PROP_MAC_15_4_SADDR, PROP_KIND_U16_LE },
    { PROP_MAC_15_4_PANID, PROP_KIND_U16_LE },
    { PROP_MAC_RAW_STREAM_ENABLED, PROP_KIND_BOOL },
    { PROP_MAC_PROMISCUOUS_MODE, PROP_KIND_U8 },
    { PROP_MAC_RX_ON_WHEN_IDLE, PROP_KIND_BOOL },
    { PROP_RCP_API_VERSION, PROP_KIND_PACKED_U },
    { PROP_RCP_MIN_HOST_API_VERSION, PROP_KIND_PACKED_U },
    { PROP_RADIO_CAPS, PROP_KIND_PACKED_U },
    { PROP_MAC_SRC_MATCH_ENABLED, PROP_KIND_BOOL },
    { PROP_MAC_SRC_MATCH_SHORT_ADDRESSES, PROP_KIND_ARRAY_U16_LE },
    { PROP_MAC_SRC_MATCH_EXTENDED_ADDRESSES, PROP_KIND_ARRAY_ADDR_BE }
};

static uint8_t rigKindOf(uint32_t propId, int *outKnown)
{
    uint32_t i;

    for (i = 0; i < TABLE_LEN(rigShapes); i++)
    {
        if (rigShapes[i].propId == propId)
        {
            *outKnown = 1;
            return rigShapes[i].kind;
        }
    }

    *outKnown = 0;
    return PROP_KIND_BOOL;
}

static void rigAnswerProp(Rig *rig, uint8_t tid, uint32_t propId, uint32_t scalar,
                          const uint8_t *bytes, uint32_t len)
{
    uint8_t kind;
    U_BStream payload;
    uint32_t i;
    int known;

    kind = rigKindOf(propId, &known);
    rigAnswerBegin(rig, tid, propId, &payload);

    if (!known)
    {
        Test_Fault("the rig was asked to answer a property it has no shape for");
        return;
    }

    if (kind == PROP_KIND_UTF8)
    {
        for (i = 0; i < len; i++)
            Spinel_WriteUint8(&payload, bytes[i]);

        Spinel_WriteUint8(&payload, SPINEL_STRING_TERM);
    }
    else if (kind == PROP_KIND_ADDR_BE || kind == PROP_KIND_ARRAY_U16_LE || kind == PROP_KIND_ARRAY_ADDR_BE)
    {
        Spinel_WriteAddrBe(&payload, bytes, len);
    }
    else if (kind == PROP_KIND_DATA)
    {
        Spinel_WritePrefixed(&payload, bytes, len);
    }
    else
    {
        rigWriteScalar(&payload, kind, scalar);
    }

    rigCommitFrame(rig, &payload);
}

static void rigWriteScalar(U_BStream *payload, uint8_t kind, uint32_t value)
{
    if (kind == PROP_KIND_BOOL)
        Spinel_WriteBool(payload, value != 0);
    else if (kind == PROP_KIND_U8)
        Spinel_WriteUint8(payload, (uint8_t)value);
    else if (kind == PROP_KIND_I8)
        Spinel_WriteInt8(payload, (int8_t)value);
    else if (kind == PROP_KIND_U16_LE)
        Spinel_WriteUint16(payload, (uint16_t)value);
    else if (kind == PROP_KIND_PACKED_U)
        Spinel_WritePackedUint(payload, value);
}

/* The answer a request deserves: an echo of what was written, or the measured value for a read. */
static void rigAnswerRequest(Rig *rig, const Request *request)
{
    uint32_t scalar = 0;
    const uint8_t *bytes = 0;
    uint32_t len = 0;

    if (request->command == SPINEL_CMD_RESET)
    {
        /* Both builds measured here answer a RESET with an unsolicited LAST_STATUS (docs/internals/protocol.md
           §5), which is the shape this rig uses by default. Whether a RESET that carries a TID is
           answered with that TID is §10 question 12, so one case answers it that way instead: the
           backend must bring the RCP up either way, and only a rig that can do both proves it. */
        if (rig->resetAnswerCarriesTid)
            rigAnswerStatus(rig, request->tid, SPINEL_STATUS_RESET_SOFTWARE);
        else
            rigAnswerStatus(rig, SPINEL_TID_NONE, SPINEL_STATUS_RESET_SOFTWARE);

        return;
    }

    if (request->command == SPINEL_CMD_PROP_VALUE_SET)
    {
        const Prop_Entry *entry = Props_Find(RcpRadio_Dialect(&rig->radio), request->propId);

        if (entry != 0 && (entry->kind == PROP_KIND_ADDR_BE || entry->kind == PROP_KIND_ARRAY_U16_LE
                           || entry->kind == PROP_KIND_ARRAY_ADDR_BE))
        {
            bytes = request->value;
            len = request->valueLen;
        }
        else if (entry != 0 && entry->kind == PROP_KIND_U16_LE && request->valueLen == 2)
        {
            scalar = (uint32_t)(request->value[0] | (request->value[1] << 8));
        }
        else if (request->valueLen >= 1)
        {
            scalar = request->value[0];
        }

        rigAnswerProp(rig, request->tid, request->propId, scalar, bytes, len);
        return;
    }

    if (request->propId == PROP_NCP_VERSION)
    {
        bytes = (const uint8_t *)rig->version;
        len = (uint32_t)Zb_strlen(rig->version, 64);
    }
    else if (request->propId == PROP_HWADDR)
    {
        bytes = measuredHwaddr;
        len = RADIO_ADDR_LEN;
    }
    else if (request->propId == PROP_RADIO_CAPS)
    {
        scalar = rig->radioCaps;
    }
    else if (request->propId == PROP_MAC_SRC_MATCH_ENABLED && rig->refuseSrcMatch)
    {
        rigAnswerStatus(rig, request->tid, SPINEL_STATUS_PROP_NOT_FOUND);
        return;
    }
    else if (request->propId == PROP_RCP_API_VERSION || request->propId == PROP_RCP_MIN_HOST_API_VERSION)
    {
        scalar = rig->apiVersion;
    }
    else
    {
        scalar = 0;
    }

    rigAnswerProp(rig, request->tid, request->propId, scalar, bytes, len);
}

/*
 * Every octet the backend has put on the wire, decoded back into requests. Reading the composition
 * instead of eyeballing it is what makes a change to a trailer or a length prefix visible here rather
 * than on an RCP. The decoder is persistent and the requests are queued: a suite that re-decoded
 * from a byte offset would have to guess where a frame began.
 */
static void rigCollectRequests(Rig *rig)
{
    uint8_t payload[HDLC_PAYLOAD_MAX];
    U_BStream stream;
    Spinel_Header header;
    Request *request;
    uint32_t captured;
    uint32_t frameLen;
    uint32_t len = 0;
    uint32_t i;

    captured = PortNull_Captured(&rig->radio.port);

    for (i = rig->txSeen; i < captured; i++)
    {
        if (Hdlc_Feed(&rig->txDecoder, rig->tx[i], payload, &len) != HDLC_EVENT_FRAME)
            continue;

        if (rig->pendingCount >= REQUEST_QUEUE_MAX)
        {
            Test_Fault("the rig collected more requests at once than it can hold");
            return;
        }

        request = &rig->pending[rig->pendingCount];
        frameLen = len;
        U_bstream_init(&stream, payload, frameLen);
        Spinel_ReadHeader(Spinel_ReadUint8(&stream), &header);
        request->tid = header.tid;
        request->command = (uint8_t)Spinel_ReadPackedUint(&stream);
        request->propId = Spinel_ReadPackedUint(&stream);
        request->valueLen = Spinel_Remaining(&stream);

        if (request->valueLen > VALUE_CAP)
            request->valueLen = VALUE_CAP;

        /* The value is whatever the frame had left after header, command and id: the offset is
           measured from the end of this frame, not from the width of the buffer it was copied into. */
        Zb_memcpy(request->value, payload + frameLen - Spinel_Remaining(&stream), request->valueLen);
        rig->pendingCount++;
    }

    rig->txSeen = captured;
}

static uint32_t rigRequests(Rig *rig, Request *out, uint32_t max)
{
    uint32_t taken = 0;
    uint32_t i;

    rigCollectRequests(rig);

    while (taken < max && rig->pendingCount > 0)
    {
        out[taken] = rig->pending[0];
        taken++;

        for (i = 0; i + 1 < rig->pendingCount; i++)
            rig->pending[i] = rig->pending[i + 1];

        rig->pendingCount--;
    }

    return taken;
}

/* Bring the scripted RCP up: pump, answer what came out, until the backend says it is running. */
static int rigBringUp(Rig *rig)
{
    Request request;
    uint32_t i;

    for (i = 0; i < BRING_UP_STEPS; i++)
    {
        /* The pump that arms the RCP may also send the next thing the sequence owes, so "running" is not the
           same fact as "nothing outstanding": a rig that returned on the first would leave a request unanswered
           and the next seam call would meet a busy session. */
        if (RcpRadio_Mode(&rig->radio) == RCP_RADIO_MODE_RUNNING
                && !SpinelSession_Busy(&rig->radio.session))
            return 1;

        if (RcpRadio_Pump(&rig->radio, rig->nowMs) != ZB_OK)
            return 0;

        rig->nowMs++;

        while (rigRequests(rig, &request, 1) == 1)
            rigAnswerRequest(rig, &request);
    }

    return RcpRadio_Mode(&rig->radio) == RCP_RADIO_MODE_RUNNING;
}

/* The channel is band A's decision, and arming without one is refused: set it before bringing up. */
static void rigSetChannel(Rig *rig, uint32_t channel)
{
    const Radio_Radio *seam = RcpRadio_Seam(&rig->radio);
    Radio_Pib pib;

    pib.present = RADIO_PIB_CHANNEL;
    pib.channel = channel;
    pib.page = 0;
    pib.panId = 0;
    pib.shortAddress = 0;
    pib.rxOnWhenIdle = 0;
    pib.maxCsmaBackoffs = 0;
    pib.maxFrameRetries = 0;
    pib.ackWaitMs = 0;
    pib.ccaThresholdDbm = 0;
    Zb_memset(pib.extendedAddress, 0, RADIO_ADDR_LEN);

    Test_Expect(seam->ops->pibSet((Radio_Radio *)seam, &pib) == ZB_OK, "the channel is accepted");
}

static void caseBringUp(void)
{
    Rig rig;
    const Radio_Radio *seam = RcpRadio_Seam(&rig.radio);
    Radio_Caps caps;
    const uint8_t *addr;
    uint32_t requests;
    uint32_t replies;
    uint32_t notifications;
    uint32_t stale;
    uint32_t timeouts;
    uint32_t malformed;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    Test_Expect(RcpRadio_Mode(&rig.radio) == RCP_RADIO_MODE_RESET, "a link opens awaiting its reset answer");
    Test_Expect(!Props_Known(RcpRadio_Dialect(&rig.radio)), "and knows no dialect until it has read one");

    Test_Expect(seam->ops->caps((Radio_Radio *)seam, &caps) == ZB_ERR_NOT_READY,
           "capabilities are not known before the RCP has answered for them");
    Test_Expect(seam->ops->rxPoll((Radio_Radio *)seam, 0, 4) == 0, "nothing is queued before anything is armed");

    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "the bring-up completes against an RCP that answers");
    Test_Expect(RcpRadio_Mode(&rig.radio) == RCP_RADIO_MODE_RUNNING, "and the backend says it is running");
    Test_Expect(RcpRadio_Dialect(&rig.radio) == PROPS_DIALECT_DSPINEL,
           "the version string the RCP answered selected the dialect");
    Test_Expect(RcpRadio_ResetsSeen(&rig.radio) == 1, "the reset answer was seen, not assumed");
    Test_Expect(RcpRadio_WriteFailures(&rig.radio) == 0, "and nothing the table offered was refused");

    Test_Expect(seam->ops->caps((Radio_Radio *)seam, &caps) == ZB_OK, "capabilities are readable now");
    Test_Expect(caps.radioCaps == 0x10d, "the RCP's own bitmap travelled through uninterpreted");
    Test_Expect(caps.hasEnergyScan == 0 && caps.psduIncludesFcs == 1 && caps.hasAckMetadata == 0
           && caps.handlesAckTimeout == 1,
           "the flags band A branches on are derived from it, not decided here");
    Test_Expect(caps.hasTransmit == 1, "the dialect offers the raw-stream write, which is all this means");

    addr = RcpRadio_Address(&rig.radio);

    Test_Expect(addr != 0 && Zb_memcmp(addr, measuredHwaddr, RADIO_ADDR_LEN) == 0,
           "the RCP's EUI-64 is the one it answered, in address order");

    Test_Expect(rig.radio.apiVersion == 4 && rig.radio.minHostApiVersion == 4,
           "the API levels §6's probe reads are recorded");

    /* One request per read and per arm write, plus the RESET. Counting them is how a driver tells a
       device that refused from a device that never answered, and how a suite notices a request that
       went out twice. */
    RcpRadio_Transactions(&rig.radio, &requests, &replies, &notifications, &stale, &timeouts, &malformed);
    Test_Expect(requests == 13 && replies == 12 && notifications == 1,
           "thirteen requests: twelve answered by TID, and the RESET answered the way §5 measured it"
           "unsolicited, with TID 0");
    Test_Expect(stale == 0 && timeouts == 0 && malformed == 0, "and no frame this session could not account for");
}

static void caseResetAnsweredByTid(void)
{
    Rig rig;
    uint32_t requests;
    uint32_t replies;
    uint32_t notifications;
    uint32_t stale;
    uint32_t timeouts;
    uint32_t malformed;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rig.resetAnswerCarriesTid = 1;
    rigSetChannel(&rig, 15);

    Test_Expect(rigBringUp(&rig), "the same bring-up completes when the reset answer carries the TID");
    RcpRadio_Transactions(&rig.radio, &requests, &replies, &notifications, &stale, &timeouts, &malformed);
    Test_Expect(requests == 13 && replies == 13 && notifications == 0,
           "and the transaction accounting moves from a notification to a matched reply, which is all "
           "the two shapes differ by here");
    Test_Expect(stale == 0 && timeouts == 0 && malformed == 0 && RcpRadio_ResetsSeen(&rig.radio) == 1,
           "with no frame left unaccounted for and one reset honoured");
}

static void caseBringUpWithoutChannel(void)
{
    Rig rig;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);

    Test_Expect(!rigBringUp(&rig), "a bring-up with no channel to write does not complete");
    Test_Expect(RcpRadio_Mode(&rig.radio) == RCP_RADIO_MODE_FAULT,
           "and it stops rather than arming an RCP on an invented channel");
    Test_Expect(RcpRadio_LastError(&rig.radio) == ZB_ERR_BAD_ARGUMENT, "with the reason stated");
}

static void caseBringUpUnknownBuild(void)
{
    Rig rig;

    rigInit(&rig, "SOMETHING_ELSE/0.1", 0, 0);

    Test_Expect(!rigBringUp(&rig), "a build this stack does not know is not brought up");
    Test_Expect(RcpRadio_Mode(&rig.radio) == RCP_RADIO_MODE_FAULT, "and the state says so");
    Test_Expect(RcpRadio_Dialect(&rig.radio) == PROPS_DIALECT_UNKNOWN,
           "no dialect is guessed at from a version string that matches neither prefix");
    Test_Expect(RcpRadio_LastError(&rig.radio) == ZB_ERR_UNSUPPORTED, "with the reason stated");
}

/* One §8.1 notification value, in the order and shape the transcripts carry. */
/* The MD_MAC group is written last so a case can name its key id and frame counter: every measured frame
 * captured from the air carries zeros in all five octets, and a case that wants the other shape says so. */
static void rigStreamRaw(Rig *rig, const uint8_t *psdu, uint32_t psduLen, int8_t rssi, uint32_t lqi,
                         uint64_t stampUs, uint16_t mdFlag, uint32_t rxError, uint32_t ackKeyId,
                         uint32_t ackFrameCounter)
{
    U_BStream payload;
    U_BStream group;
    uint8_t scratch[16];
    uint32_t i;

    rigAnswerBegin(rig, SPINEL_TID_NONE, PROP_STREAM_RAW, &payload);
    Spinel_WritePrefixed(&payload, psdu, psduLen);
    Spinel_WriteInt8(&payload, rssi);
    Spinel_WriteInt8(&payload, -128);
    Spinel_WriteUint16(&payload, mdFlag);

    U_bstream_init(&group, scratch, (unsigned long)sizeof scratch);
    Spinel_WriteUint8(&group, 15);
    Spinel_WriteUint8(&group, (uint8_t)lqi);
    Spinel_WriteUint64(&group, stampUs);
    Spinel_WritePrefixed(&payload, scratch, (uint32_t)sizeof scratch - Spinel_Remaining(&group));

    U_bstream_init(&group, scratch, (unsigned long)sizeof scratch);
    Spinel_WritePackedUint(&group, rxError);
    Spinel_WritePrefixed(&payload, scratch, (uint32_t)sizeof scratch - Spinel_Remaining(&group));

    U_bstream_init(&group, scratch, (unsigned long)sizeof scratch);
    Spinel_WriteUint8(&group, (uint8_t)ackKeyId);
    Spinel_WriteUint32(&group, ackFrameCounter);
    Spinel_WritePrefixed(&payload, scratch, (uint32_t)sizeof scratch - Spinel_Remaining(&group));

    (void)i;
    rigCommitFrame(rig, &payload);
}

/*
 * The value of a raw-stream SET the backend composed: the length it declared, the octets it put in
 * front of the trailer, and the size of the trailer. Copying the request out first keeps the parse
 * away from the caller's struct.
 */
static int rigTxValue(const Request *request, uint8_t *psduOut, uint32_t *psduLen, uint32_t *trailerLen)
{
    U_BStream stream;
    uint8_t bytes[VALUE_CAP];
    const uint8_t *psdu;
    uint32_t declared = 0;

    if (request->propId != PROP_STREAM_RAW || request->valueLen > VALUE_CAP)
        return 0;

    Zb_memcpy(bytes, request->value, request->valueLen);
    U_bstream_init(&stream, bytes, request->valueLen);

    psdu = Spinel_ReadPrefixed(&stream, &declared);

    if (psdu == 0 || declared > VALUE_CAP)
        return 0;

    *psduLen = declared;
    Zb_memcpy(psduOut, psdu, declared);
    *trailerLen = Spinel_Remaining(&stream);
    return 1;
}

/* The trailer octet at `index` of a raw-stream SET: 0 is the channel, 1 the CSMA backoffs, 2 the frame
   retries (docs/internals/protocol.md §8.2); -1 when the request is not one or the trailer is shorter. */
static int rigTxTrailerOctet(const Request *request, uint32_t index)
{
    U_BStream stream;
    uint8_t bytes[VALUE_CAP];
    uint32_t declared = 0;

    if (request->propId != PROP_STREAM_RAW || request->valueLen > VALUE_CAP)
        return -1;

    Zb_memcpy(bytes, request->value, request->valueLen);
    U_bstream_init(&stream, bytes, request->valueLen);

    if (Spinel_ReadPrefixed(&stream, &declared) == 0 || Spinel_Remaining(&stream) <= index)
        return -1;

    return bytes[request->valueLen - Spinel_Remaining(&stream) + index];
}

static const char *samplePath(char *out, const char *name)
{
    uint32_t i = 0;
    const char *prefix = ZB_SAMPLES_DIR "/";

    while (prefix[i] != 0 && i < 200)
    {
        out[i] = prefix[i];
        i++;
    }

    while (*name != 0 && i < 255)
    {
        out[i] = *name;
        i++;
        name++;
    }

    out[i] = 0;
    return out;
}

static void caseStreamRawDelivery(void)
{
    Rig rig;
    const Radio_Radio *seam = RcpRadio_Seam(&rig.radio);
    Radio_Frame frames[RADIO_FRAME_BATCH_MAX];
    uint8_t psdu[6] = { 0x01, 0x08, 0x3e, 0x00, 0xdead & 0xff, 0x02 };
    uint32_t got;
    uint32_t taken;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    rigStreamRaw(&rig, psdu, 5, -94, 255, 12345000, 0, 0, 0, 0);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "a notification is pumped");
    Test_Expect(RcpRadio_RxQueued(&rig.radio) == 1, "and becomes exactly one inbound frame");

    got = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);
    Test_Expect(got == 1, "pulled, never pushed");
    Test_Expect(frames[0].len == 5 && Zb_memcmp(frames[0].bytes, psdu, 5) == 0, "the PSDU is what was sent");
    Test_Expect(frames[0].rssiDbm == -94, "the RSSI is signed, as the field is");
    Test_Expect(frames[0].lqi == 255, "the LQI is the MD_PHY one");
    Test_Expect(frames[0].deviceStampTicks == 12345000, "the device's timestamp travels untouched");
    Test_Expect(frames[0].error == ZB_OK, "and a clean frame carries no error");

    rigStreamRaw(&rig, psdu, 5, -76, 0, 1000, SPINEL_MD_BAD_FCS, 0, 0, 0);
    RcpRadio_Pump(&rig.radio, rig.nowMs++);
    got = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);
    Test_Expect(got == 1 && frames[0].error == ZB_ERR_BAD_FRAME,
           "a frame the radio says has a bad FCS is delivered with the reason on it, not discarded");
    Test_Expect(RcpRadio_FrameRejects(&rig.radio) == 0, "delivered-with-an-error is not a rejection");

    rigStreamRaw(&rig, psdu, 5, -80, 128, 2000, SPINEL_MD_DUPE, 0, 0, 0);
    RcpRadio_Pump(&rig.radio, rig.nowMs++);
    got = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);
    Test_Expect(got == 1 && frames[0].error == ZB_ERR_BUSY,
           "a frame the radio says it has already delivered is marked as suspect too");

    rigStreamRaw(&rig, psdu, 5, -80, 128, 2000, 0, 3, 0, 0);
    RcpRadio_Pump(&rig.radio, rig.nowMs++);
    got = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);
    Test_Expect(got == 1 && frames[0].error == ZB_ERR_DEVICE,
           "and the radio's own receive error is reported as the device's");

    rigStreamRaw(&rig, psdu, 5, -80, 0, 2000, 0, 0, 0, 0);
    RcpRadio_Pump(&rig.radio, rig.nowMs++);
    taken = seam->ops->rxPoll((Radio_Radio *)seam, frames, 1);
    Test_Expect(taken == 1, "a poll takes what it asks for");
    Test_Expect(RcpRadio_RxQueued(&rig.radio) == 0, "and leaves nothing behind");

    /* 10.22.3's answer read off the side that gave it: MD_FLAG's ACKED_FP says the acknowledgment this radio
       sent for the frame carried Frame Pending one, which is the only report a host gets of an Ack it never sees. */
    rigStreamRaw(&rig, psdu, 5, -80, 0, 3000, SPINEL_MD_ACKED_FP, 0, 0, 0);
    RcpRadio_Pump(&rig.radio, rig.nowMs++);
    taken = seam->ops->rxPoll((Radio_Radio *)seam, frames, 1);
    Test_Expect(taken == 1 && frames[0].ackedWithFramePending == 1,
                "a frame whose Ack said pending carries that fact, and a frame whose Ack said nothing does not");
    Test_ExpectCount(RcpRadio_RxAckedPending(&rig.radio), 1, "counted once, beside the frames that carry it");
}

/*
 * The captured transcripts, delivered through the backend. These are the bytes the operating system
 * handed the port on an RCP that was already armed: the counts are what test/fixtures/ records, and
 * they are asserted here as band B's own reading of the same octets.
 */
static void caseTranscriptReplay(void)
{
    /*
     * The counts test/fixtures/ records for these three transcripts. The one discarded
     * frame is not a mystery: that transcript begins mid-frame, and here it arrives
     * after a completed bring-up frame, so a flag had opened the partial run and closing
     * it is a drop. Decoded on its own (which is what the framing suite does) the
     * same leading octets are ignored and nothing is dropped (docs/internals/protocol.md §2).
     * Both readings are of the same bytes, and both are asserted where they belong.
     */
    static const Rcp_Transcript transcripts[] =
    {
        { "port_conb2_raw.hex", 39, 0, 1 },
        { "port_conb2a_raw.hex", 7, 0, 0 },
        { "port_conb2b_raw.hex", 49, 11, 0 }
    };
    char path[256];
    uint8_t fileBytes[FIXTURE_CAP];
    Rig rig;
    const Radio_Radio *seam;
    Radio_Frame frames[RADIO_FRAME_BATCH_MAX];
    uint32_t delivered;
    uint32_t marked;
    uint32_t taken;
    uint32_t len;
    uint32_t step;
    uint32_t i;

    for (i = 0; i < TABLE_LEN(transcripts); i++)
    {
        rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
        rigSetChannel(&rig, 15);

        if (!rigBringUp(&rig))
        {
            Test_Expect(0, "a transcript replay needs an armed backend");
            continue;
        }

        len = fixtureReadHex(samplePath(path, transcripts[i].path), fileBytes, FIXTURE_CAP);
        Test_Expect(len > 0, "the recorded transcript is readable");

        if (rig.rxLen + len > SCRIPT_CAP)
        {
            Test_Expect(0, "the scripted bring-up and the transcript do not fit one rig");
            continue;
        }

        Zb_memcpy(rig.rx + rig.rxLen, fileBytes, len);
        rig.rxLen += len;
        rig.script.rxLen = rig.rxLen;

        seam = RcpRadio_Seam(&rig.radio);
        delivered = 0;
        marked = 0;

        /* Pump until the scripted RCP has nothing left to hand over and the queue is drained. A
           loop that stopped at the first empty poll would stop at the first ring boundary. */
        for (step = 0; step < 400; step++)
        {
            if (RcpRadio_Pump(&rig.radio, rig.nowMs++) != ZB_OK)
            {
                Test_Expect(0, "replaying a recorded transcript is not a fault");
                break;
            }

            taken = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);

            for (len = 0; len < taken; len++)
            {
                delivered++;

                if (frames[len].error == ZB_ERR_BAD_FRAME)
                    marked++;
            }

            if (rig.script.rxPos >= rig.rxLen && Port_RxPending(&rig.radio.port) == 0
                    && RcpRadio_RxQueued(&rig.radio) == 0 && taken == 0)
                break;
        }

        Test_Expect(delivered == transcripts[i].frames,
               "the same octets yield the number of frames test/fixtures/ records");
        Test_Expect(marked == transcripts[i].badFcs,
               "and the frames the radio flagged as FCS-invalid are the ones it flagged");
        Test_Expect(RcpRadio_LinkDrops(&rig.radio) == transcripts[i].linkDrops,
               "and the framing says exactly what it discarded, per transcript");
        Test_Expect(RcpRadio_FrameRejects(&rig.radio) == 0, "and no frame arrived in a shape band B could not read");
        Test_Expect(RcpRadio_RxOverflows(&rig.radio) == 0, "with the poll keeping up with the queue");
    }
}
static void caseTxComposition(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    Radio_Handle handle = RADIO_HANDLE_NONE;
    uint8_t psdu[VALUE_CAP];
    uint32_t psduLen = 0;
    uint32_t trailerLen = 0;
    ZbStatus status;

    /* The AT86RF233 build: the PSDU carries its own FCS in both directions (§8.2, §9.3). */
    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = RcpRadio_Seam(&rig.radio);
    status = seam->ops->tx((Radio_Radio *)seam, ackMpdu, (uint32_t)sizeof ackMpdu, 1, 0, &handle);
    Test_Expect(status == ZB_OK, "a transmit is accepted once the RCP is armed");
    Test_Expect(handle != RADIO_HANDLE_NONE, "and comes back with a handle: 0 means none");

    Test_Expect(rigRequests(&rig, &request, 1) == 1, "one frame went out");
    Test_Expect(request.command == SPINEL_CMD_PROP_VALUE_SET && request.propId == PROP_STREAM_RAW,
           "written as a raw-stream SET");
    Test_Expect(rigTxValue(&request, psdu, &psduLen, &trailerLen), "and its value is readable");
    Test_Expect(psduLen == 5 && Zb_memcmp(psdu, ackMhr, 3) == 0
           && Zb_memcmp(psdu + 3, ackFcs, 2) == 0,
           "the standard's own worked example leaves the FCS exactly where band A put it: 02 00 6a then e4 79");
    Test_Expect(trailerLen == 16, "the trailer is the full sixteen octets even where fewer would do");

    /* The OpenThread build wants the frame without its FCS, and arms without rx-on-when-idle. */
    rigInit(&rig, OPENTHREAD_VERSION, 0xff, 9);
    rigSetChannel(&rig, 20);
    Test_Expect(rigBringUp(&rig), "the other dialect arms too");
    Test_Expect(RcpRadio_Dialect(&rig.radio) == PROPS_DIALECT_OPENTHREAD, "from its version string");
    Test_Expect(rig.radio.caps.psduIncludesFcs == 0 && rig.radio.caps.hasEnergyScan == 1,
           "and with the capabilities that build reported");

    seam = RcpRadio_Seam(&rig.radio);
    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, (uint32_t)sizeof ackMpdu, 0, 0, &handle) == ZB_OK,
           "same call, different dialect");
    Test_Expect(rigRequests(&rig, &request, 1) == 1 && rigTxValue(&request, psdu, &psduLen, &trailerLen),
           "the composition is what differs");
    Test_Expect(psduLen == 3 && Zb_memcmp(psdu, ackMhr, 3) == 0,
           "the footer band A computed is taken off: this radio says its PSDUs carry none, so it computes its own");
    Test_Expect(trailerLen == 16, "and the same trailer it must have");

    /* The one thing band B can be asked to do that it cannot: strip a footer from a frame that is
       nothing but a footer. Refused before the link is written to, so a refusal leaves no request
       half-issued (§8.2). */
    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMhr, 2, 0, 0, &handle) == ZB_ERR_BAD_ARGUMENT
           && rigRequests(&rig, &request, 1) == 0,
           "a frame that is only its footer is refused, and nothing went out for it");
}

static void caseTxCompletion(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_TxResult result;
    Request request;
    Radio_Handle handles[4];
    uint32_t txCode = 0;
    uint32_t i;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = RcpRadio_Seam(&rig.radio);

    Test_Expect(seam->ops->completion((Radio_Radio *)seam, RADIO_HANDLE_NONE, &result) == ZB_ERR_BAD_ARGUMENT,
           "handle 0 is not a transmit");
    Test_Expect(seam->ops->completion((Radio_Radio *)seam, 99, &result) == ZB_ERR_BAD_ARGUMENT,
           "and neither is one this backend never issued");

    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, 0, &handles[0]) == ZB_OK, "a transmit is issued");
    Test_Expect(rigRequests(&rig, &request, 1) == 1, "and its request is on the wire");
    Test_Expect(seam->ops->completion((Radio_Radio *)seam, handles[0], &result) == ZB_ERR_NOT_READY,
           "before the answer it has no result to give (§8.3)");

    /* §8.3: the completion is a LAST_STATUS carrying the requesting TID. */
    rigAnswerStatus(&rig, request.tid, SPINEL_STATUS_OK);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the answer is pumped");
    Test_Expect(RcpRadio_TxStatusCode(&rig.radio, handles[0], &txCode) == ZB_OK && txCode == SPINEL_STATUS_OK,
           "the code the device used is readable while the result is still uncollected");
    Test_Expect(seam->ops->completion((Radio_Radio *)seam, handles[0], &result) == ZB_OK,
           "and the result is available until it is collected");
    Test_Expect(RcpRadio_TxStatusCode(&rig.radio, handles[0], &txCode) == ZB_ERR_BAD_ARGUMENT,
           "and the code goes with the transmit: it is a fact about one outstanding frame");
    Test_Expect(result.status == ZB_OK, "the device said yes");
    Test_Expect(result.isAcked == 1,
           "the frame asked to be answered and the radio answered it with OK, which is the only acknowledgment evidence a radio with no ack metadata gives");
    Test_Expect(seam->ops->completion((Radio_Radio *)seam, handles[0], &result) == ZB_ERR_BAD_ARGUMENT,
           "collected once means collected");

    /* The device's own word survives the folding SpinelSession_StatusToZb does (§7.3), because two
       different refusals are one seam status for band A and two different measurements for a bench. */
    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, 0, &handles[0]) == ZB_OK, "a second transmit, answered with a bare refusal");
    Test_Expect(rigRequests(&rig, &request, 1) == 1, "on the wire");
    rigAnswerStatus(&rig, request.tid, SPINEL_STATUS_FAILURE);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "answered with a bare refusal");
    Test_Expect(RcpRadio_TxStatusCode(&rig.radio, handles[0], &txCode) == ZB_OK && txCode == SPINEL_STATUS_FAILURE,
           "its code is kept");
    Test_Expect(seam->ops->completion((Radio_Radio *)seam, handles[0], &result) == ZB_OK
           && result.status == ZB_ERR_DEVICE && result.isAcked == 0,
           "collecting it succeeds and the refusal travels inside the result, which is band A's one status to branch on; a refused acknowledgment is not reported as one that happened");

    /* Nothing asked, so nothing is claimed: the flag is about the request band A made, not about the
       silence that followed it. */
    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 0, 0, &handles[0]) == ZB_OK, "a transmit that asks for nothing");
    Test_Expect(rigRequests(&rig, &request, 1) == 1, "on the wire");
    rigAnswerStatus(&rig, request.tid, SPINEL_STATUS_OK);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "answered with OK");
    Test_Expect(seam->ops->completion((Radio_Radio *)seam, handles[0], &result) == ZB_OK
           && result.status == ZB_OK && result.isAcked == 0,
           "and the result says no acknowledgment, because no acknowledgment was requested");

    for (i = 0; i < 4; i++)
    {
        Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 0, 0, &handles[i]) == ZB_OK,
               "a transmit fills a slot");
        Test_Expect(rigRequests(&rig, &request, 1) == 1, "with its request on the wire");
        rigAnswerStatus(&rig, request.tid, SPINEL_STATUS_OK);
        Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "answered");
    }

    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 0, 0, &handles[0]) == ZB_ERR_NO_SPACE,
           "the fourth unanswered one is the last this backend tracks, and it says so");
}

/*
 * Answer a write the way a measured RCP answered one: the property id and the octets it was given, with the
 * request's own TID (§7.4.1 echoed `01 0c` for a mask, not a scalar read out of it).
 */
static void rigEchoSet(Rig *rig, const Request *request)
{
    U_BStream payload;
    uint32_t i;

    rigAnswerBegin(rig, request->tid, request->propId, &payload);

    for (i = 0; i < request->valueLen; i++)
        Spinel_WriteUint8(&payload, request->value[i]);

    rigCommitFrame(rig, &payload);
}

/*
 * The dwell dialogue band B runs against an RCP, scripted as §7.4.1 measured it: a
 * one-channel list, a period, and the state write that puts the dwell on the air (each echoed), then the level
 * as a notification carrying the channel it belongs to, then the scan state going idle. -94 is the floor this
 * bench reads on every quiet channel it scanned.
 */
static void caseScanDialogRunsAsMeasured(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    U_BStream payload;
    uint32_t channel = 0;
    int32_t dbm = 0;
    uint32_t i;
    int maskSeen = 0;
    int periodSeen = 0;
    int stateSeen = 0;

    rigInit(&rig, DSPINEL_VERSION, 0x10f, 4);
    rigSetChannel(&rig, 12);
    Test_Expect(rigBringUp(&rig), "armed on a measured RCP, on the channel a dwell was measured on");
    seam = RcpRadio_Seam(&rig.radio);

    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 12, 200) == ZB_OK,
           "a dwell is asked for and the call returns without waiting for it (D-124)");
    Test_Expect(RcpRadio_ScanState(&rig.radio) == RCP_RADIO_SCAN_MASK,
           "and what band B owes first is the channel list");

    for (i = 0; i < 8 && !stateSeen; i++)
    {
        if (RcpRadio_Pump(&rig.radio, rig.nowMs++) != ZB_OK)
            break;

        if (rigRequests(&rig, &request, 1) != 1)
            continue;

        if (request.propId == PROP_MAC_SCAN_MASK)
        {
            Test_Expect(request.valueLen == 2 && request.value[0] == 1 && request.value[1] == 12,
                   "the mask is a Spinel array: a count, then the one channel this dwell is for");
            maskSeen = 1;
        }
        else if (request.propId == PROP_MAC_SCAN_PERIOD)
        {
            Test_Expect(request.valueLen == 2 && request.value[0] == 200 && request.value[1] == 0,
                   "the period crosses as the u16 the RCP echoed as c8 00 (§7.4.1)");
            periodSeen = 1;
        }
        else if (request.propId == PROP_MAC_SCAN_STATE)
        {
            Test_Expect(request.valueLen == 1 && request.value[0] == SPINEL_SCAN_STATE_ENERGY,
                   "and the dwell is started by a property, not by a command the dialect does not have");
            stateSeen = 1;
        }
        else
        {
            continue;
        }

        rigEchoSet(&rig, &request);
    }

    Test_Expect(maskSeen && periodSeen && stateSeen, "the three writes went out in the order the dialog needs them");
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "and the answer to the state write is pumped");
    Test_Expect(RcpRadio_ScanState(&rig.radio) == RCP_RADIO_SCAN_DWELL, "which is what moves the machine to waiting on the device");
    Test_ExpectCount(RcpRadio_ScanDwells(&rig.radio), 1, "one dwell went out");

    Test_Expect(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm) == ZB_ERR_NOT_READY,
           "and there is nothing to report yet: the level is a notification a period later, not a reply");

    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 26, 200) == ZB_ERR_BUSY,
           "a second dwell is refused here rather than sent to an RCP measured refusing one while another ran");

    rigAnswerBegin(&rig, 0, PROP_MAC_ENERGY_SCAN_RESULT, &payload);
    Spinel_WriteUint8(&payload, 12);
    Spinel_WriteInt8(&payload, -94);
    rigCommitFrame(&rig, &payload);

    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the level is pumped in");
    Test_Expect(RcpRadio_ScanState(&rig.radio) == RCP_RADIO_SCAN_LEVEL, "and the machine holds it for collection");

    Test_Expect(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm) == ZB_OK, "the level is reported");
    Test_Expect(channel == 12 && dbm == -94, "for the channel the RCP named, at the floor measured on a quiet channel");
    Test_Expect(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm) == ZB_ERR_NOT_READY,
           "collected once means collected, like a transmit result");

    rigAnswerBegin(&rig, 0, PROP_MAC_SCAN_STATE, &payload);
    Spinel_WriteUint8(&payload, SPINEL_SCAN_STATE_IDLE);
    rigCommitFrame(&rig, &payload);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the end of the dwell is pumped as its own notification");
    Test_ExpectCount(RcpRadio_ScanAbandons(&rig.radio), 0, "and a dwell that reported is not counted as an abandon");
}

/*
 * The other answer an RCP can give. The revision whose table §7.2 first read answered `PROP_NOT_FOUND` for
 * the whole scan group (§7.4), and band B has to learn that from the ask and then refuse without putting another
 * frame of that dialogue on the port (docs/internals/decisions.md D-123).
 */
static void caseScanRefusedGroupIsRemembered(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    uint32_t channel = 0;
    int32_t dbm = 0;
    uint32_t i;

    rigInit(&rig, DSPINEL_VERSION, 0x10f, 4);
    rigSetChannel(&rig, 12);
    Test_Expect(rigBringUp(&rig), "armed");
    seam = RcpRadio_Seam(&rig.radio);

    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 12, 200) == ZB_OK, "a dwell is asked for");

    for (i = 0; i < 8; i++)
    {
        if (RcpRadio_Pump(&rig.radio, rig.nowMs++) != ZB_OK)
            break;

        if (rigRequests(&rig, &request, 1) == 1 && request.propId == PROP_MAC_SCAN_MASK)
            break;
    }

    Test_Expect(request.command == SPINEL_CMD_PROP_VALUE_SET && request.propId == PROP_MAC_SCAN_MASK,
           "and the RCP is asked for the channel list first");

    rigAnswerStatus(&rig, request.tid, SPINEL_STATUS_PROP_NOT_FOUND);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "and it answers that it has no such property");

    Test_Expect(RcpRadio_ScanState(&rig.radio) == RCP_RADIO_SCAN_NOTHERE, "recorded as this RCP having no dwell");
    Test_Expect(RcpRadio_SurfaceState(&rig.radio, PROP_MAC_SCAN_MASK) == PROPS_SURFACE_ABSENT,
           "and as an answer about that property, which is what a later ask consults");
    Test_Expect(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm) == ZB_ERR_UNSUPPORTED,
           "the refusal reaches the caller as a no, not as a dwell that has not finished");
    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 12, 200) == ZB_ERR_UNSUPPORTED,
           "and the next ask is refused without a frame going out");
    Test_ExpectCount(rigRequests(&rig, &request, 1), 0, "nothing on the wire to prove it");
    Test_Expect(RcpRadio_Mode(&rig.radio) == RCP_RADIO_MODE_RUNNING,
           "and an RCP that cannot dwell is not a backend in fault: what it was armed to be, it stays");
}

/*
 * A dwell that ends with nothing to report, in both measured ways that happens: the RCP says the dwell
 * is over without naming a level, or it says nothing at all and band B stops asking on the bound it states
 * (docs/internals/protocol.md §7.4.1). Either way the answer is the figure a device uses for
 * nothing measured, which is neither a level nor an error.
 */
static void caseScanDwellWithNothingToReport(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    U_BStream payload;
    uint32_t channel = 0;
    int32_t dbm = 0;
    uint32_t i;

    rigInit(&rig, DSPINEL_VERSION, 0x10f, 4);
    rigSetChannel(&rig, 12);
    Test_Expect(rigBringUp(&rig), "armed");
    seam = RcpRadio_Seam(&rig.radio);

    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 26, 200) == ZB_OK, "a dwell on the other quiet channel");

    for (i = 0; i < 8; i++)
    {
        if (RcpRadio_Pump(&rig.radio, rig.nowMs++) != ZB_OK)
            break;

        if (rigRequests(&rig, &request, 1) != 1)
            continue;

        if (request.propId == PROP_MAC_SCAN_STATE)
        {
            rigEchoSet(&rig, &request);
            break;
        }

        rigEchoSet(&rig, &request);
    }

    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "and the answer to that write is pumped");
    Test_Expect(RcpRadio_ScanState(&rig.radio) == RCP_RADIO_SCAN_DWELL, "the second dwell is running");
    Test_Expect(RcpRadio_ScanState(&rig.radio) == RCP_RADIO_SCAN_DWELL, "the dwell is running");

    rigAnswerBegin(&rig, 0, PROP_MAC_SCAN_STATE, &payload);
    Spinel_WriteUint8(&payload, SPINEL_SCAN_STATE_IDLE);
    rigCommitFrame(&rig, &payload);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "and the RCP says it is over, having named no level");

    Test_Expect(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm) == ZB_OK, "the report is still given");
    Test_Expect(channel == 26, "for the channel this host asked about");
    Test_Expect(dbm == RADIO_SCAN_NO_LEVEL, "and the figure that means nothing was measured is not dressed up as a level");
    Test_ExpectCount(RcpRadio_ScanAbandons(&rig.radio), 1, "counted as a dwell with nothing to report");

    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 26, 200) == ZB_OK, "and a dwell can be asked for again");

    for (i = 0; i < 8; i++)
    {
        if (RcpRadio_Pump(&rig.radio, rig.nowMs++) != ZB_OK)
            break;

        if (rigRequests(&rig, &request, 1) != 1)
            continue;

        if (request.propId == PROP_MAC_SCAN_STATE)
        {
            rigEchoSet(&rig, &request);
            break;
        }

        rigEchoSet(&rig, &request);
    }

    Test_Expect(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm) == ZB_ERR_NOT_READY,
           "a dwell that has not answered yet is not ready, which is the only honest answer while it runs");

    /* The measured dwell took 343 to 505 host milliseconds at a period written as 200;
       band B's bound is larger than that, so the host clock has to be moved past it deliberately. */
    for (i = 0; i < 400; i++)
        RcpRadio_Pump(&rig.radio, rig.nowMs += 10);

    Test_Expect(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm) == ZB_OK,
           "and band B stops asking on the bound it states, rather than leaving a caller pumping forever");
    Test_Expect(dbm == RADIO_SCAN_NO_LEVEL && channel == 26, "with the same nothing-measured figure, for the asked channel");
    Test_ExpectCount(RcpRadio_ScanAbandons(&rig.radio), 2, "counted as the second such dwell");
}

/* A level the caller never collected is still owed, and it holds the machine: band B keeps one dwell's answer
 * rather than a ring, so starting again without collecting is refused instead of quietly losing a reading. */
static void caseScanUncollectedReportHoldsTheMachine(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    U_BStream payload;
    uint32_t channel = 0;
    int32_t dbm = 0;
    uint32_t i;

    rigInit(&rig, DSPINEL_VERSION, 0x10f, 4);
    rigSetChannel(&rig, 12);
    Test_Expect(rigBringUp(&rig), "armed");
    seam = RcpRadio_Seam(&rig.radio);

    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 12, 200) == ZB_OK, "a dwell is asked for");

    for (i = 0; i < 8; i++)
    {
        if (RcpRadio_Pump(&rig.radio, rig.nowMs++) != ZB_OK)
            break;

        if (rigRequests(&rig, &request, 1) != 1)
            continue;

        if (request.propId == PROP_MAC_SCAN_STATE)
        {
            rigEchoSet(&rig, &request);
            break;
        }

        rigEchoSet(&rig, &request);
    }

    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the answer to the state write is pumped");

    rigAnswerBegin(&rig, 0, PROP_MAC_ENERGY_SCAN_RESULT, &payload);
    Spinel_WriteUint8(&payload, 12);
    Spinel_WriteInt8(&payload, -94);
    rigCommitFrame(&rig, &payload);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "and the level arrives");

    Test_Expect(RcpRadio_ScanState(&rig.radio) == RCP_RADIO_SCAN_LEVEL, "a report is waiting to be collected");
    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 26, 200) == ZB_ERR_BUSY,
           "and a new dwell is refused while it is owed, rather than overwriting it");
    Test_Expect(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm) == ZB_OK, "the report is collected");
    Test_Expect(dbm == -94 && channel == 12, "intact");
    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 26, 200) == ZB_OK, "and now the next dwell can be asked for");
}

/* A dwell is a request to a device, so its arguments are judged against that device: a period the RCP would
 * clamp, and a channel its PHY does not name, are refused before anything is composed (docs/internals/protocol.md §7.4.1). */
static void caseScanArgumentsRefusedBeforeTheLink(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    uint32_t channel = 0;
    int32_t dbm = 0;

    rigInit(&rig, DSPINEL_VERSION, 0x10f, 4);
    rigSetChannel(&rig, 12);
    Test_Expect(rigBringUp(&rig), "armed");
    seam = RcpRadio_Seam(&rig.radio);

    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 12, RCP_RADIO_SCAN_PERIOD_MAX + 1) == ZB_ERR_BAD_ARGUMENT,
           "a period past the bound the RCP was measured clamping at is refused rather than clamped for it");
    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 27, 200) == ZB_ERR_BAD_ARGUMENT,
           "and a channel this dialect's PHY does not name");
    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 12, 0) == ZB_ERR_BAD_ARGUMENT,
           "and a dwell of no length at all");
    Test_ExpectCount(rigRequests(&rig, &request, 1), 0, "none of them put a frame on the wire");
    Test_Expect(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm) == ZB_ERR_NOT_READY,
           "and nothing is outstanding, because nothing was asked");
}

/* A dwell asked of a phy that is switched off: §7.4.1 measured `INVALID_STATE` for exactly that, and "the radio
 * is not in a state to dwell" must not arrive at a caller as "ask again in a moment". */
static void caseScanRefusedByDeviceState(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    uint32_t channel = 0;
    int32_t dbm = 0;
    uint32_t i;

    rigInit(&rig, DSPINEL_VERSION, 0x10f, 4);
    rigSetChannel(&rig, 12);
    Test_Expect(rigBringUp(&rig), "armed");
    seam = RcpRadio_Seam(&rig.radio);

    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 12, 200) == ZB_OK, "a dwell is asked for");

    for (i = 0; i < 8; i++)
    {
        if (RcpRadio_Pump(&rig.radio, rig.nowMs++) != ZB_OK)
            break;

        if (rigRequests(&rig, &request, 1) != 1)
            continue;

        if (request.propId == PROP_MAC_SCAN_STATE)
            break;

        rigEchoSet(&rig, &request);
    }

    Test_Expect(request.propId == PROP_MAC_SCAN_STATE, "and the state write is where the RCP says no");

    rigAnswerStatus(&rig, request.tid, SPINEL_STATUS_INVALID_STATE);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the refusal is pumped");

    Test_Expect(RcpRadio_ScanState(&rig.radio) == RCP_RADIO_SCAN_REFUSED, "recorded as this dwell being refused");
    Test_Expect(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm) == ZB_ERR_DEVICE,
           "reported as the device refusing it, not as a dwell that has not arrived yet");
    Test_ExpectCount(RcpRadio_ScanRefusals(&rig.radio), 1, "counted");
    Test_Expect(RcpRadio_Mode(&rig.radio) == RCP_RADIO_MODE_RUNNING,
           "and the arming this dialogue sat on top of is untouched");
    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 12, 200) == ZB_OK,
           "and a dwell can be asked for again, because a radio in the wrong state is a radio that can be put right");
}

static void caseCompletionTailCarriesTheAcksFramePending(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_TxResult result;
    Request request;
    Radio_Handle handle = RADIO_HANDLE_NONE;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");
    seam = RcpRadio_Seam(&rig.radio);

    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, 0, &handle) == ZB_OK, "a transmit is issued");
    Test_Expect(rigRequests(&rig, &request, 1) == 1, "and its request is on the wire");

    rigAnswerCompletion(&rig, request.tid, SPINEL_STATUS_OK, 0, 0);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the completion is pumped");
    Test_Expect(RcpRadio_CompletionTail(&rig.radio) == RCP_RADIO_TAIL_REPORTED,
           "both bits present and both zero, which is what was measured (D-47)");

    Test_Expect(seam->ops->completion((Radio_Radio *)seam, handle, &result) == ZB_OK, "and the result is collected");
    Test_Expect(result.isAcked == 1 && result.framePendingReported == 1 && result.framePending == 0,
           "with the acknowledgment's Frame Pending stated as the zero the device reported");

    /* The pair measured on a ConBee II: an Ack that said pending reads one here. */
    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, 0, &handle) == ZB_OK, "a second transmit");
    Test_Expect(rigRequests(&rig, &request, 1) == 1, "issued");
    rigAnswerCompletion(&rig, request.tid, SPINEL_STATUS_OK, 1, 0);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "answered with the pending bit set");
    Test_Expect(RcpRadio_CompletionTail(&rig.radio) == (RCP_RADIO_TAIL_REPORTED | RCP_RADIO_TAIL_PENDING),
           "recorded as the device said it");
    Test_Expect(seam->ops->completion((Radio_Radio *)seam, handle, &result) == ZB_OK, "collected");
    Test_Expect(result.isAcked == 1 && result.framePendingReported == 1 && result.framePending == 1,
           "and the seam's result carries the one");

    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, 0, &handle) == ZB_OK, "a third transmit");
    Test_Expect(rigRequests(&rig, &request, 1) == 1, "issued");
    rigAnswerCompletionOne(&rig, request.tid, SPINEL_STATUS_FAILURE, 1);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "answered with one bit only");
    Test_Expect(RcpRadio_CompletionTail(&rig.radio) == 0, "and no tail is claimed for an incomplete shape");
    Test_Expect(seam->ops->completion((Radio_Radio *)seam, handle, &result) == ZB_OK, "collected");
    Test_Expect(result.framePendingReported == 0 && result.framePending == 0,
           "nor a Frame Pending bit, so nothing above reads an answer into it");
}

/* The word band B uses for a refusal it causes itself. One Spinel request is outstanding at a time (docs/internals/protocol.md
   §5), so a second transmit while the first awaits its reply is this backend having no room for the transaction,
   which is the condition 3.2.1.1.3 re-asks. ZB_ERR_BUSY is kept for what the device itself answered (§7.3): a rig
   that used one word for both could not tell its own queue from the RCP's refusal. */
static void caseTxAcknowledgementRefused(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_Handle handle = RADIO_HANDLE_NONE;
    Radio_TxResult result;
    Request request;
    uint32_t captured;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = RcpRadio_Seam(&rig.radio);
    captured = PortNull_Captured(&rig.radio.port);

    Test_Expect(seam->ops->tx((Radio_Radio *)seam, 0, 3, 0, 0, &handle) == ZB_ERR_BAD_ARGUMENT
           && seam->ops->tx((Radio_Radio *)seam, ackMpdu, 0, 0, 0, &handle) == ZB_ERR_BAD_ARGUMENT,
           "no frame and no buffer are the same refusal");
    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMhr, RADIO_MPDU_MAX + 1, 0, 0, &handle) == ZB_ERR_BAD_ARGUMENT,
           "and a PSDU longer than one 802.15.4 PSDU is refused before anything is composed");
    Test_Expect(PortNull_Captured(&rig.radio.port) == captured,
           "none of them put a frame on the wire");

    /* 8.2.2's NO_ACK: a frame that asked to be answered and was not. The radio names it in its own vocabulary
       (code 17), and the seam's result carries the name band A's confirmation reports. */
    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, 0, &handle) == ZB_OK, "a transmit that asks for an ack");
    Test_Expect(rigRequests(&rig, &request, 1) == 1, "and its request is on the wire");

    rigAnswerCompletion(&rig, request.tid, SPINEL_STATUS_NO_ACK, 0, 0);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the device answers that it was never acknowledged");
    Test_Expect(seam->ops->completion((Radio_Radio *)seam, handle, &result) == ZB_OK, "and the result is collected");
    Test_Expect(result.status == ZB_ERR_NO_ACK && result.isAcked == 0,
           "as NO_ACK, not as a device refusal this stack cannot name");

    /* The same code on a frame that asked for nothing is the device's own word: nothing was expected, so nothing
       was missed (6.6.3.2's "shall not be acknowledged"). */
    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 0, 0, &handle) == ZB_OK, "a transmit that asks for none");
    Test_Expect(rigRequests(&rig, &request, 1) == 1, "issued");
    rigAnswerCompletion(&rig, request.tid, SPINEL_STATUS_NO_ACK, 0, 0);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "answered with the same code");
    Test_Expect(seam->ops->completion((Radio_Radio *)seam, handle, &result) == ZB_OK, "collected");
    Test_Expect(result.status == ZB_ERR_DEVICE,
           "and reported as the device's own refusal: no acknowledgment was asked for, so none was missed");

    /* 8.2.2's CHANNEL_ACCESS_FAILURE: the radio's CCA found the channel busy (code 18), whether or not the frame
       asked for an acknowledgment. */
    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, 0, &handle) == ZB_OK, "a transmit that asks for an ack");
    Test_Expect(rigRequests(&rig, &request, 1) == 1, "issued before the channel is found busy");
    rigAnswerCompletion(&rig, request.tid, SPINEL_STATUS_CCA_FAILURE, 0, 0);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the device answers that the channel was busy");
    Test_Expect(seam->ops->completion((Radio_Radio *)seam, handle, &result) == ZB_OK, "and the result is collected");
    Test_Expect(result.status == ZB_ERR_CHANNEL_ACCESS_FAILURE && result.isAcked == 0,
           "as CHANNEL_ACCESS_FAILURE, not as a device fault");
}

/* An RCP that resets under us: the arm sequence runs again, and an outstanding transmit is told it
   never happened. */
static void caseUnsolicitedReset(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    Radio_TxResult result;
    Radio_Handle handle = RADIO_HANDLE_NONE;
    uint32_t resetsBefore;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = RcpRadio_Seam(&rig.radio);
    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, 0, &handle) == ZB_OK, "a transmit is outstanding");
    Test_Expect(rigRequests(&rig, &request, 1) == 1, "its request is on the wire, unanswered");

    resetsBefore = RcpRadio_ResetsSeen(&rig.radio);
    rigAnswerStatus(&rig, SPINEL_TID_NONE, SPINEL_STATUS_RESET_SOFTWARE);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the RCP announces a reset");

    Test_Expect(RcpRadio_ResetsSeen(&rig.radio) == resetsBefore + 1, "and the announcement is counted");
    Test_Expect(RcpRadio_Mode(&rig.radio) == RCP_RADIO_MODE_DISCOVER,
           "the bring-up starts again: every property this host wrote is gone from the device");
    Test_Expect(seam->ops->completion((Radio_Radio *)seam, handle, &result) == ZB_OK
           && result.status == ZB_ERR_DEVICE_LOST,
           "the transmit is not silently dropped: it comes back as lost");
    Test_Expect(rig.radio.caps.radioCaps == 0x10d && RcpRadio_Dialect(&rig.radio) == PROPS_DIALECT_DSPINEL,
           "what was read from the RCP is kept: a reset does not make the RCP something else");

    Test_Expect(rigBringUp(&rig), "and the sequence runs to completion again");
    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 0, 0, &handle) == ZB_OK,
           "with the raw stream open again");
}

/* A reset the RCP announces while it runs is a loss at the seam: every property band A wrote is gone, the identity
   included, and isLost is the one call band A asks before it re-applies them. It reads 1 while the bring-up runs
   again and once more after, so a band A whose turns straddle the re-arm still sees the episode. */
static void caseUnsolicitedResetIsALoss(void)
{
    Rig rig;
    Radio_Radio *seam;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = (Radio_Radio *)RcpRadio_Seam(&rig.radio);
    Test_Expect(seam->ops->isLost(seam) == 0, "a running RCP is not lost");

    rigAnswerStatus(&rig, SPINEL_TID_NONE, SPINEL_STATUS_RESET_SOFTWARE);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the RCP announces a reset of its own");
    Test_Expect(seam->ops->isLost(seam) == 1, "and the seam reports the configuration band A gave it as gone");

    Test_Expect(rigBringUp(&rig), "the bring-up runs to completion again");
    Test_Expect(seam->ops->isLost(seam) == 1, "the episode is still reported on the first ask after it");
    Test_Expect(seam->ops->isLost(seam) == 0, "and is over on the next, so band A re-applies what it holds once");
}

/* What a reset does to the inbound ring. A frame received in a session that has ended is not a frame of the
 * next one: the device's configuration is gone, so a poll still sitting in the ring would be handed to band A,
 * answered with a write the seam refuses (`ZB_ERR_NOT_READY` while the RCP is being re-armed), and that refusal
 * would become the verdict of a whole protocol step. An RCP's echo of its own frame, and the abort that
 * followed, are the shape this closes; the ring is drained with the session. */
static void caseResetDrainsTheInboundRing(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_Frame frames[RADIO_FRAME_BATCH_MAX];
    uint8_t psdu[5];

    rigInit(&rig, DSPINEL_VERSION, 0x10f, 4);
    rigSetChannel(&rig, 12);
    Test_Expect(rigBringUp(&rig), "armed");
    seam = RcpRadio_Seam(&rig.radio);

    psdu[0] = 0x63; psdu[1] = 0x88; psdu[2] = 0x00; psdu[3] = 0x00; psdu[4] = 0x04;
    rigStreamRaw(&rig, psdu, 5, -94, 200, 5000, 0, 0, 0, 0);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "a frame arrives");
    Test_ExpectCount(RcpRadio_RxQueued(&rig.radio), 1, "and is waiting in the ring");

    rigAnswerStatus(&rig, SPINEL_TID_NONE, SPINEL_STATUS_RESET_SOFTWARE);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the RCP announces a reset");
    Test_Expect(RcpRadio_Mode(&rig.radio) == RCP_RADIO_MODE_DISCOVER,
                "the bring-up starts again, so the device the frame described is gone");
    Test_ExpectCount(RcpRadio_RxQueued(&rig.radio), 0,
                     "and the ring was drained with the session rather than handed to band A");
    Test_ExpectCount(seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX), 0,
                     "so the next step is handed no frame of the old session");
}

/* An RCP left receiving by an earlier session has frames queued ahead of the RESET answer, more than the ring
   holds; they must not stand between the bring-up and that answer. */
static void caseStaleFramesBeforeTheResetAnswer(void)
{
    Rig rig;
    uint8_t psdu[5];
    uint32_t requests;
    uint32_t replies;
    uint32_t notifications;
    uint32_t stale;
    uint32_t timeouts;
    uint32_t malformed;
    uint32_t i;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 12);

    psdu[0] = 0x63; psdu[1] = 0x88; psdu[2] = 0x00; psdu[3] = 0x00; psdu[4] = 0x04;

    for (i = 0; i < RCP_RADIO_RX_QUEUE_MAX + 4; i++)
        rigStreamRaw(&rig, psdu, 5, -94, 200, 1000 * i, 0, 0, 0, 0);

    Test_Expect(rigBringUp(&rig), "the bring-up reads past the old session's frames to the RESET answer");
    RcpRadio_Transactions(&rig.radio, &requests, &replies, &notifications, &stale, &timeouts, &malformed);
    Test_Expect(timeouts == 0, "without waiting out the reply window");
    Test_ExpectCount(rig.radio.rxUnarmed, RCP_RADIO_RX_QUEUE_MAX + 4, "every one is counted as heard before arming");
    Test_ExpectCount(RcpRadio_RxQueued(&rig.radio), 0, "and none is handed to band A");
}

static void caseReplyTimeout(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    Radio_Handle handle = RADIO_HANDLE_NONE;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = RcpRadio_Seam(&rig.radio);
    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, 0, &handle) == ZB_OK, "a transmit goes out");
    Test_Expect(rigRequests(&rig, &request, 1) == 1, "and is not answered");

    /* The rig's session window is 300 ms; the clock is band B's parameter, never a wall clock. */
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs + 400) == ZB_ERR_TIMEOUT,
           "a reply that never arrives is a stated error, not a hang (§5)");
    Test_Expect(RcpRadio_Mode(&rig.radio) == RCP_RADIO_MODE_RESET, "and the bring-up starts again from a RESET");

    rig.nowMs += 401;
    Test_Expect(rigBringUp(&rig), "the sequence completes against the same RCP");
}

static void caseArmRefusalFaults(void)
{
    Rig rig;
    Request request;
    uint32_t i;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);

    for (i = 0; i < BRING_UP_STEPS; i++)
    {
        if (RcpRadio_Pump(&rig.radio, rig.nowMs++) != ZB_OK)
            break;

        if (rigRequests(&rig, &request, 1) != 1)
            continue;

        if (request.command == SPINEL_CMD_PROP_VALUE_SET)
            break;

        rigAnswerRequest(&rig, &request);
    }

    Test_Expect(request.command == SPINEL_CMD_PROP_VALUE_SET, "the bring-up reached its first write");

    rigAnswerStatus(&rig, request.tid, SPINEL_STATUS_INVALID_STATE);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the device refuses it");
    Test_Expect(RcpRadio_Mode(&rig.radio) == RCP_RADIO_MODE_FAULT,
           "a device that refuses a write its own table offers has contradicted the table");
    Test_Expect(RcpRadio_WriteFailures(&rig.radio) == 1 && RcpRadio_LastError(&rig.radio) == ZB_ERR_NOT_READY,
           "with the count and the reason both stated");
    Test_Expect(RcpRadio_Seam(&rig.radio)->ops->isLost((Radio_Radio *)RcpRadio_Seam(&rig.radio)) == 1,
           "and the seam is told the backend is not usable");
}

static void caseDiscoveryRefusalContinues(void)
{
    Rig rig;
    Request request;
    uint32_t i;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);

    for (i = 0; i < BRING_UP_STEPS; i++)
    {
        if (RcpRadio_Mode(&rig.radio) == RCP_RADIO_MODE_RUNNING)
            break;

        if (RcpRadio_Pump(&rig.radio, rig.nowMs++) != ZB_OK)
            break;

        if (rigRequests(&rig, &request, 1) != 1)
            continue;

        if (request.command == SPINEL_CMD_PROP_VALUE_GET && request.propId == PROP_HWADDR)
        {
            /* A device that contradicts its own table on one property is not a reason to stop
               reading the others, and not a reason to pretend this one was answered either. */
            rigAnswerStatus(&rig, request.tid, SPINEL_STATUS_PROP_NOT_FOUND);
            continue;
        }

        rigAnswerRequest(&rig, &request);
    }

    Test_Expect(RcpRadio_Mode(&rig.radio) == RCP_RADIO_MODE_RUNNING, "the bring-up finished anyway");
    Test_Expect(RcpRadio_Address(&rig.radio) == 0, "and the identity this RCP refused stays unread");
    Test_Expect(RcpRadio_WriteFailures(&rig.radio) == 0, "a refused read is not counted as a refused write");
    Test_Expect(RcpRadio_SurfaceState(&rig.radio, PROP_HWADDR) == PROPS_SURFACE_ABSENT,
           "and the refusal is recorded as what this device answered, which is the fact a later ask consults");
}

/*
 * A surface is what the device answered, so it holds three kinds of fact and a suite has to keep them apart:
 * a read this host applied, a write this host had echoed, and an id nobody asked about, the last one being
 * the reason `PROP_NOT_FOUND` is the only answer that records absence (docs/internals/decisions.md D-123).
 */
static void caseSurfaceOfWhatWasAnswered(void)
{
    Rig rig;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed on a measured RCP");

    Test_Expect(RcpRadio_SurfaceState(&rig.radio, PROP_HWADDR) == PROPS_SURFACE_KNOWN,
           "a discovery read this host applied is recorded");
    Test_Expect(RcpRadio_SurfaceState(&rig.radio, PROP_PHY_CHAN) == PROPS_SURFACE_KNOWN,
           "so is an arm write the device echoed");
    Test_Expect(RcpRadio_SurfaceState(&rig.radio, PROP_MAC_SCAN_STATE) == PROPS_SURFACE_UNKNOWN,
           "and a group this host never asked about stays unknown, which is not the same fact as refused");

    /* The table half of the same question, for contrast: on the other dialect there is no entry to ask through. */
    Test_Expect(Props_Supports(PROPS_DIALECT_OPENTHREAD, PROP_MAC_SCAN_STATE, PROPS_OP_GET) == 0,
           "the OpenThread table names no scan group");
    Test_Expect(Props_Supports(PROPS_DIALECT_DSPINEL, PROP_MAC_SCAN_STATE, PROPS_OP_GET) == 1,
           "and the measured dialect does");
}
static Radio_Pib rigPib(void)
{
    Radio_Pib pib;

    pib.present = 0;
    pib.channel = 0;
    pib.page = 0;
    pib.panId = 0;
    pib.shortAddress = 0;
    pib.rxOnWhenIdle = 0;
    pib.maxCsmaBackoffs = 0;
    pib.maxFrameRetries = 0;
    pib.ackWaitMs = 0;
    pib.ccaThresholdDbm = 0;
    Zb_memset(pib.extendedAddress, 0, RADIO_ADDR_LEN);
    return pib;
}

static void casePibRoutes(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_Pib pib;
    Request request;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "and the queued channel write went out");

    seam = RcpRadio_Seam(&rig.radio);

    pib = rigPib();
    pib.present = RADIO_PIB_PAGE;
    pib.page = 1;
    Test_Expect(seam->ops->pibSet((Radio_Radio *)seam, &pib) == ZB_ERR_UNSUPPORTED,
           "the 2.4 GHz PHY has one page, and a stack does not invent a second");

    pib = rigPib();
    pib.present = RADIO_PIB_ACK_WAIT_MS;
    pib.ackWaitMs = 40;
    Test_Expect(seam->ops->pibSet((Radio_Radio *)seam, &pib) == ZB_ERR_UNSUPPORTED,
           "no property and no trailer field carries an acknowledgment wait on either dialect");

    pib = rigPib();
    pib.present = RADIO_PIB_CCA_THRESHOLD_DBM;
    pib.ccaThresholdDbm = 1000;
    Test_Expect(seam->ops->pibSet((Radio_Radio *)seam, &pib) == ZB_ERR_BAD_ARGUMENT,
           "a dBm figure the field cannot hold is refused as an argument before it reaches the link: the RCP itself stored +127 dBm without a word (docs/internals/protocol.md §7.4.3), so this guard is band B's own");

    pib = rigPib();
    pib.present = RADIO_PIB_CCA_THRESHOLD_DBM;
    pib.ccaThresholdDbm = -71;
    Test_Expect(seam->ops->pibSet((Radio_Radio *)seam, &pib) == ZB_OK,
           "and the threshold is writable on this dialect, which is what the measured write says it is");
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the pump puts that write on the wire");
    Test_Expect(rigRequests(&rig, &request, 1) == 1, "one property write");
    Test_Expect(request.propId == PROP_PHY_CCA_THRESHOLD && request.valueLen == 1
           && request.value[0] == 0xb9,
           "the signed octet band A named: -71 as b9, the same octet the RCP answers for its own default");
    rigAnswerRequest(&rig, &request);
    Test_Expect(1, "the RCP echoes it");
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "and the answer closes the transaction");
    Test_ExpectCount(rig.radio.writeCount, 0, "with nothing left in the queue for the calls below");

    pib = rigPib();
    pib.present = RADIO_PIB_CHANNEL;
    pib.channel = 300;
    Test_Expect(seam->ops->pibSet((Radio_Radio *)seam, &pib) == ZB_ERR_BAD_ARGUMENT,
           "a number beyond what the field can hold is an argument error too");

    pib = rigPib();
    pib.present = RADIO_PIB_CHANNEL;
    pib.channel = 27;
    Test_Expect(seam->ops->pibSet((Radio_Radio *)seam, &pib) == ZB_ERR_BAD_ARGUMENT,
           "a channel outside 11..26 is refused with the dialect's own numbering (§11.1.3.3)");

    pib = rigPib();
    pib.present = RADIO_PIB_MAX_CSMA_BACKOFFS;
    pib.maxCsmaBackoffs = 256;
    Test_Expect(seam->ops->pibSet((Radio_Radio *)seam, &pib) == ZB_ERR_BAD_ARGUMENT,
           "the trailer carries the backoff count as one octet, so 256 is out of range");

    pib = rigPib();
    pib.present = RADIO_PIB_MAX_CSMA_BACKOFFS | RADIO_PIB_MAX_FRAME_RETRIES;
    pib.maxCsmaBackoffs = 3;
    pib.maxFrameRetries = 4;
    Test_Expect(seam->ops->pibSet((Radio_Radio *)seam, &pib) == ZB_OK,
           "both are carried per transmit rather than as properties, and accepted as such");
    Test_Expect(rigRequests(&rig, &request, 1) == 0, "and neither produced a property write");

    pib = rigPib();
    pib.present = RADIO_PIB_EXTENDED_ADDRESS;
    Zb_memcpy(pib.extendedAddress, measuredPibAddress, RADIO_ADDR_LEN);
    Test_Expect(seam->ops->pibSet((Radio_Radio *)seam, &pib) == ZB_OK,
           "an EUI-64 is a PIB field here too, and the PIB carries it least significant octet first: 12 8a 04 ff ff 2e 21 00 is the address 0x00212effff048a12");

    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the pump puts a queued write on the wire");
    Test_Expect(rigRequests(&rig, &request, 1) == 1, "which produced one write");

    Test_Expect(request.propId == PROP_MAC_15_4_LADDR && request.valueLen == RADIO_ADDR_LEN,
           "eight octets under MAC_15_4_LADDR with no length in front of them");
    Test_ExpectHex("and in the wire's own order, address order, which is the PIB's reversed: 00 21 2e ff ff 04 8a 12",
                   request.value, RADIO_ADDR_LEN, "00212effff048a12");

    rigAnswerRequest(&rig, &request);
    Test_Expect(1, "the RCP echoes it");
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "and the answer closes the transaction");

    pib = rigPib();
    Test_Expect(seam->ops->pibGet((Radio_Radio *)seam, &pib) == ZB_OK, "the PIB reads back");
    Test_ExpectHex("with the mirror still holding the PIB's order, so the echo is not a second convention",
                   pib.extendedAddress, RADIO_ADDR_LEN, "128a04ffff2e2100");
    Test_ExpectHex("and with the factory address the handshake read, reversed out of the wire's order",
                   pib.hwAddress, RADIO_ADDR_LEN, "128a04ffff2e2100");
    Test_Expect((pib.present & RADIO_PIB_HW_ADDRESS) != 0,
           "present, because this RCP answered HWADDR");
    Test_Expect((pib.present & RADIO_PIB_CHANNEL) != 0 && pib.channel == 15, "with the channel this RCP holds");
    Test_Expect((pib.present & RADIO_PIB_RX_ON_WHEN_IDLE) != 0,
           "and rx-on-when-idle, which this dialect carries");
    Test_Expect((pib.present & RADIO_PIB_CCA_THRESHOLD_DBM) != 0
           && pib.ccaThresholdDbm == -71,
           "and the CCA threshold named, because this host put it there: what band B reports for that field is what it wrote, never a figure it guessed");
    Test_Expect((pib.present & RADIO_PIB_ACK_WAIT_MS) == 0,
           "while the acknowledgment wait stays a field no property on this dialect carries");

    pib = rigPib();
    pib.present = RADIO_PIB_HW_ADDRESS;
    Zb_memcpy(pib.hwAddress, measuredHwaddr, RADIO_ADDR_LEN);
    Test_Expect(seam->ops->pibSet((Radio_Radio *)seam, &pib) == ZB_ERR_UNSUPPORTED,
           "the factory address is the device's own and a PIB that names it is refused");
    Test_Expect(rigRequests(&rig, &request, 1) == 0, "with nothing put on the wire");
}

/* One of the source-match table's three writes, which is band B's own statement and not a PIB write. */
static int rigIsPendingProp(uint32_t propId)
{
    return propId == PROP_MAC_SRC_MATCH_ENABLED || propId == PROP_MAC_SRC_MATCH_SHORT_ADDRESSES
           || propId == PROP_MAC_SRC_MATCH_EXTENDED_ADDRESSES;
}

/* Pump and answer until the scripted RCP has put every queued write on the link and accepted each one, the
   table's own statement included. The count is the PIB SETs this host wrote, so a case can say how many property
   writes one call produced. */
static int rigDrainWrites(Rig *rig, uint32_t *outSets)
{
    Request request;
    uint32_t sets = 0;
    uint32_t step;

    for (step = 0; step < 32; step++)
    {
        if (RcpRadio_Pump(&rig->radio, rig->nowMs++) != ZB_OK)
            return 0;

        while (rigRequests(rig, &request, 1) == 1)
        {
            if (request.command == SPINEL_CMD_PROP_VALUE_SET && !rigIsPendingProp(request.propId))
                sets++;

            rigAnswerRequest(rig, &request);
        }

        if (rig->radio.writeCount == 0 && !rig->radio.pendingDirty)
            break;
    }

    *outSets = sets;

    return rig->radio.writeCount == 0 && !rig->radio.pendingDirty;
}

/* Every PIB field a dialect's table lets a host write, with the values a case writes them as. */
static Radio_Pib rigWritablePib(void)
{
    Radio_Pib pib;

    pib = rigPib();
    pib.present = RADIO_PIB_EXTENDED_ADDRESS | RADIO_PIB_RX_ON_WHEN_IDLE | RADIO_PIB_SHORT_ADDRESS
                  | RADIO_PIB_PAN_ID | RADIO_PIB_CHANNEL | RADIO_PIB_CCA_THRESHOLD_DBM;
    pib.channel = 12;
    pib.panId = 0xdead;
    pib.shortAddress = 0x1234;
    pib.rxOnWhenIdle = 1;
    pib.ccaThresholdDbm = -71;
    Zb_memcpy(pib.extendedAddress, measuredPibAddress, RADIO_ADDR_LEN);
    return pib;
}

/* One seam call naming every PIB field a dialect table lets a host write: six on the AT86RF233 table, four on
   the OpenThread one. This is the widest call the seam can be given, so the queue has to hold a whole call
   rather than the one call a bring-up happened to need (docs/internals/decisions.md D-121). */
/* D-231: a transmit waits behind the PIB writes the seam took before it, so the frame leaves under the address and
   channel band A set for it; measured as a RaspBee II's commissioning answer sent to an address its radio lacked. */
/* The PSDU's third octet, which the line's cases use to tell one frame from another: the value opens with two octets of length. */
static uint8_t rigTxMark(const Request *request)
{
    return request->value[2 + 2];
}

static ZbStatus rigTxMarked(Rig *rig, uint8_t mark, Radio_Handle *handle)
{
    const Radio_Radio *seam = RcpRadio_Seam(&rig->radio);
    uint8_t mpdu[sizeof ackMpdu];

    Zb_memcpy(mpdu, ackMpdu, (uint32_t)sizeof mpdu);
    mpdu[2] = mark;

    return seam->ops->tx((Radio_Radio *)seam, mpdu, (uint32_t)sizeof mpdu, 1, 0, handle);
}

static void caseTxWaitsInLine(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    Radio_TxResult result;
    Radio_Handle handles[RCP_RADIO_TX_TRACK_MAX];
    Radio_Handle extra = RADIO_HANDLE_NONE;
    uint32_t i;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = RcpRadio_Seam(&rig.radio);

    for (i = 0; i < RCP_RADIO_TX_TRACK_MAX; i++)
        Test_ExpectStatus(rigTxMarked(&rig, (uint8_t)(0x10 + i), &handles[i]), ZB_OK,
                          "a frame is taken while the request ahead of it awaits its reply");

    Test_Expect(rigRequests(&rig, &request, 1) == 1 && rigTxMark(&request) == 0x10, "the first is on the wire");
    Test_Expect(rigRequests(&rig, &request, 1) == 0, "and the others wait, because the RCP takes one request at a time");
    Test_ExpectStatus(rigTxMarked(&rig, 0x20, &extra), ZB_ERR_NO_SPACE, "a full track is the one thing that refuses");

    Test_Expect(rigRequests(&rig, &request, 1) == 0, "and the refused frame left nothing on the wire");

    for (i = 0; i < RCP_RADIO_TX_TRACK_MAX; i++)
    {
        Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handles[i], &result), ZB_ERR_NOT_READY,
                          "a frame in line has no result yet");

        if (i > 0)
            Test_Expect(rigRequests(&rig, &request, 1) == 1 && rigTxMark(&request) == 0x10 + i,
                        "the frame next in line went out when the one ahead of it ended, in the order they were taken");
        else
            request.tid = SpinelSession_PendingTid(&rig.radio.session);

        rigAnswerCompletion(&rig, request.tid, i == 1 ? SPINEL_STATUS_NO_ACK : SPINEL_STATUS_OK, 0, 0);
        Test_ExpectStatus(RcpRadio_Pump(&rig.radio, rig.nowMs++), ZB_OK, "its completion is read");
        Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handles[i], &result), ZB_OK, "and collected");
        Test_ExpectStatus(result.status, i == 1 ? ZB_ERR_NO_ACK : ZB_OK, "under its own handle, with its own outcome");
    }

    Test_ExpectStatus(rigTxMarked(&rig, 0x21, &extra), ZB_OK, "the slots came back, and the door takes a frame again");
}

/* A write and a frame leave in the order the seam took them, whichever came first: a frame must not overtake the address or channel set for it, nor leave on one set after it. */
static void caseTxKeepsItsPlaceAmongWrites(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    Radio_Pib pib;
    Radio_Handle first = RADIO_HANDLE_NONE;
    Radio_Handle second = RADIO_HANDLE_NONE;
    Radio_Handle third = RADIO_HANDLE_NONE;
    Request later;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = RcpRadio_Seam(&rig.radio);

    pib = rigPib();
    pib.present = RADIO_PIB_SHORT_ADDRESS;
    pib.shortAddress = 0x1fa1;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_OK, "the claimed short address is taken");
    Test_ExpectStatus(rigTxMarked(&rig, 0x30, &first), ZB_OK, "and a frame behind it");

    Test_Expect(rigRequests(&rig, &request, 1) == 1 && request.propId == PROP_MAC_15_4_SADDR,
                "the short address goes to the RCP first");
    Test_Expect(rigRequests(&rig, &later, 1) == 0, "and the frame waits while the RCP has not answered it");
    rigAnswerRequest(&rig, &request);
    Test_ExpectStatus(RcpRadio_Pump(&rig.radio, rig.nowMs++), ZB_OK, "the RCP's echo closes the write");
    Test_Expect(rigRequests(&rig, &request, 1) == 1 && request.propId == PROP_STREAM_RAW && rigTxMark(&request) == 0x30,
                "and the frame goes out behind the address it is answered to");

    Test_ExpectStatus(rigTxMarked(&rig, 0x31, &second), ZB_OK, "a frame waits behind the one in flight");

    pib = rigPib();
    pib.present = RADIO_PIB_CHANNEL;
    pib.channel = 20;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_OK, "a parent's channel is taken behind it");
    Test_ExpectStatus(rigTxMarked(&rig, 0x32, &third), ZB_OK, "and a frame for the new channel behind that");

    rigAnswerCompletion(&rig, request.tid, SPINEL_STATUS_OK, 0, 0);
    Test_ExpectStatus(RcpRadio_Pump(&rig.radio, rig.nowMs++), ZB_OK, "the frame in flight ends");
    Test_Expect(rigRequests(&rig, &request, 1) == 1 && request.propId == PROP_STREAM_RAW && rigTxMark(&request) == 0x31,
                "the frame taken before the channel leaves on the channel it was asked on");

    rigAnswerCompletion(&rig, request.tid, SPINEL_STATUS_OK, 0, 0);
    Test_ExpectStatus(RcpRadio_Pump(&rig.radio, rig.nowMs++), ZB_OK, "and ends");
    Test_Expect(rigRequests(&rig, &request, 1) == 1 && request.propId == PROP_PHY_CHAN, "then the channel");

    rigAnswerRequest(&rig, &request);
    Test_ExpectStatus(RcpRadio_Pump(&rig.radio, rig.nowMs++), ZB_OK, "which is echoed");
    Test_Expect(rigRequests(&rig, &request, 1) == 1 && request.propId == PROP_STREAM_RAW && rigTxMark(&request) == 0x32,
                "then the frame that asked for it");
}

/* The trailer's backoff count is the one the frame was asked under, even when the PIB moves while it waits. */
static void caseTxCarriesWhatItWasAskedUnder(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    Radio_Pib pib;
    Radio_Handle first = RADIO_HANDLE_NONE;
    Radio_Handle second = RADIO_HANDLE_NONE;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = RcpRadio_Seam(&rig.radio);

    pib = rigPib();
    pib.present = RADIO_PIB_MAX_CSMA_BACKOFFS;
    pib.maxCsmaBackoffs = 3;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_OK, "three backoffs");
    Test_ExpectStatus(rigTxMarked(&rig, 0x40, &first), ZB_OK, "a frame goes out");
    Test_ExpectStatus(rigTxMarked(&rig, 0x41, &second), ZB_OK, "and another waits under three");

    pib.maxCsmaBackoffs = 5;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_OK, "the count moves while it waits");

    Test_Expect(rigRequests(&rig, &request, 1) == 1, "the first is on the wire");
    rigAnswerCompletion(&rig, request.tid, SPINEL_STATUS_OK, 0, 0);
    Test_ExpectStatus(RcpRadio_Pump(&rig.radio, rig.nowMs++), ZB_OK, "and ends");
    Test_Expect(rigRequests(&rig, &request, 1) == 1 && rigTxMark(&request) == 0x41, "the second follows");
    Test_ExpectCount(request.value[2 + 5 + 1], 3, "with the backoff count it was asked under");
}

/* An RCP that has lost what it was told takes no frame that was waiting: each one ends, and nothing of them reaches the wire. */
static void caseTxLineEndsWithTheRcp(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    Radio_TxResult result;
    Radio_Handle handles[3];
    uint32_t i;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = RcpRadio_Seam(&rig.radio);

    for (i = 0; i < 3; i++)
        Test_ExpectStatus(rigTxMarked(&rig, (uint8_t)(0x50 + i), &handles[i]), ZB_OK, "taken");

    Test_Expect(rigRequests(&rig, &request, 1) == 1, "one on the wire");

    rigAnswerStatus(&rig, SPINEL_TID_NONE, SPINEL_STATUS_RESET_SOFTWARE);
    Test_ExpectStatus(RcpRadio_Pump(&rig.radio, rig.nowMs++), ZB_OK, "the RCP announces a reset");

    for (i = 0; i < 3; i++)
    {
        Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handles[i], &result), ZB_OK, "each ends");
        Test_ExpectStatus(result.status, ZB_ERR_DEVICE_LOST, "as lost");
    }

    Test_Expect(rigBringUp(&rig), "the RCP comes back");

    while (rigRequests(&rig, &request, 1) == 1)
        Test_Expect(request.propId != PROP_STREAM_RAW, "and no frame from before the reset reaches it");

    Test_ExpectStatus(rigTxMarked(&rig, 0x53, &handles[0]), ZB_OK, "a new frame is taken");
    Test_ExpectStatus(rigTxMarked(&rig, 0x54, &handles[1]), ZB_OK, "and another behind it");
    Test_ExpectStatus(RcpRadio_Restart(&rig.radio, rig.nowMs), ZB_OK, "a restart asked for");
    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handles[1], &result), ZB_OK, "ends the line too");
    Test_ExpectStatus(result.status, ZB_ERR_DEVICE_LOST, "the same way");
}

/* A line that does not move answers its frames in time for band A to re-ask. */
static void caseTxWaitIsBounded(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_TxResult result;
    Radio_Handle first = RADIO_HANDLE_NONE;
    Radio_Handle second = RADIO_HANDLE_NONE;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");
    rig.radio.session.timeoutMs = 0;

    seam = RcpRadio_Seam(&rig.radio);

    Test_ExpectStatus(rigTxMarked(&rig, 0x60, &first), ZB_OK, "a frame goes out and its RCP never answers");
    Test_ExpectStatus(rigTxMarked(&rig, 0x61, &second), ZB_OK, "another waits behind it");

    Test_ExpectStatus(RcpRadio_Pump(&rig.radio, rig.radio.lastPumpMs + RCP_RADIO_TX_WAIT_MS - 1), ZB_OK, "within the bound");
    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, second, &result), ZB_ERR_NOT_READY, "it still waits");

    Test_ExpectStatus(RcpRadio_Pump(&rig.radio, rig.radio.lastPumpMs + 1), ZB_OK, "past the bound");
    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, second, &result), ZB_OK, "it is answered");
    Test_ExpectStatus(result.status, ZB_ERR_NO_SPACE, "with the word band A re-asks on");
    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, first, &result), ZB_ERR_NOT_READY,
                      "and the frame the RCP holds is still the RCP's");
}

/* Band A stops waiting for a completion at its own bound and never asks again, so a result it will not collect goes
   back to the track. Four of them would otherwise refuse every frame from then on. */
static void caseTxResultNobodyCollectsFreesItsSlot(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    Radio_TxResult result;
    Radio_Handle handles[RCP_RADIO_TX_TRACK_MAX];
    Radio_Handle another = RADIO_HANDLE_NONE;
    uint32_t i;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = RcpRadio_Seam(&rig.radio);

    for (i = 0; i < RCP_RADIO_TX_TRACK_MAX; i++)
        Test_ExpectStatus(rigTxMarked(&rig, (uint8_t)(0x70 + i), &handles[i]), ZB_OK, "a frame nobody will ask after");

    Test_ExpectStatus(rigTxMarked(&rig, 0x7f, &another), ZB_ERR_NO_SPACE, "and the track is full");

    /* Answered and left there: the rig's RCP answers each in turn, and no completion is asked for. */
    for (i = 0; i < RCP_RADIO_TX_TRACK_MAX; i++)
    {
        (void)RcpRadio_Pump(&rig.radio, rig.radio.lastPumpMs + 1);

        while (rigRequests(&rig, &request, 1) == 1)
            rigAnswerCompletion(&rig, request.tid, SPINEL_STATUS_OK, 0, 0);
    }

    (void)RcpRadio_Pump(&rig.radio, rig.radio.lastPumpMs + 1);
    Test_ExpectStatus(rigTxMarked(&rig, 0x7f, &another), ZB_ERR_NO_SPACE, "an answer is kept for a caller still listening");
    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handles[0], &result), ZB_OK, "and is there when asked for");

    (void)RcpRadio_Pump(&rig.radio, rig.radio.lastPumpMs + RCP_RADIO_TX_KEEP_MS);

    for (i = 0; i < RCP_RADIO_TX_TRACK_MAX; i++)
        Test_ExpectStatus(rigTxMarked(&rig, (uint8_t)(0x80 + i), &another), ZB_OK, "past the bound the whole track is free again");

    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handles[1], &result), ZB_ERR_BAD_ARGUMENT,
                      "and a caller who comes back after all finds no such frame");
}

/* A frame still in line when the RCP is declared lost never reached the air, and still ends. */
static void caseTxReplyTimeoutEndsTheWholeTrack(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_TxResult result;
    Radio_Handle sent = RADIO_HANDLE_NONE;
    Radio_Handle waiting = RADIO_HANDLE_NONE;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = RcpRadio_Seam(&rig.radio);

    Test_ExpectStatus(rigTxMarked(&rig, 0x90, &sent), ZB_OK, "a frame the RCP never answers");
    Test_ExpectStatus(rigTxMarked(&rig, 0x91, &waiting), ZB_OK, "and one behind it");
    Test_ExpectStatus(RcpRadio_Pump(&rig.radio, rig.radio.lastPumpMs + 301), ZB_ERR_TIMEOUT, "the reply is late");
    Test_Expect(seam->ops->isLost((Radio_Radio *)seam) == 1, "band A is told the RCP is lost");
    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, sent, &result), ZB_OK, "the frame the RCP held ends");
    Test_ExpectStatus(result.status, ZB_ERR_TIMEOUT, "with the reason");
    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, waiting, &result), ZB_OK, "and so does the one in line");
    Test_ExpectStatus(result.status, ZB_ERR_TIMEOUT, "alike");
}

static void caseTxCarriesItsRetries(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Request request;
    Radio_Pib pib;
    Radio_Handle handle = RADIO_HANDLE_NONE;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = RcpRadio_Seam(&rig.radio);
    pib = rigPib();
    Test_Expect(seam->ops->pibGet((Radio_Radio *)seam, &pib) == ZB_OK
           && (pib.present & RADIO_PIB_MAX_FRAME_RETRIES) == 0,
           "the PIB read reports no retry count, so band A keeps its own default rather than adopting a zero");
    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, 3, &handle) == ZB_OK,
           "a direct frame with band A's three retries");
    Test_Expect(rigRequests(&rig, &request, 1) == 1, "goes out");
    Test_Expect(rigTxTrailerOctet(&request, 2) == 3,
           "with the count in the trailer's retry octet, which the firmware programs into the radio");
    rigAnswerCompletion(&rig, request.tid, SPINEL_STATUS_OK, 0, 0);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "its completion is read");

    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, 0, &handle) == ZB_OK, "an extraction with none");
    Test_Expect(rigRequests(&rig, &request, 1) == 1 && rigTxTrailerOctet(&request, 2) == 0,
           "carries a zero there, so the radio sends it once");
    rigAnswerCompletion(&rig, request.tid, SPINEL_STATUS_OK, 0, 0);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "and that completion too");

    Test_Expect(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, RADIO_MAX_FRAME_RETRIES + 1, &handle)
           == ZB_ERR_BAD_ARGUMENT, "eight retries is past 802.15.4's bound and refused");
    Test_Expect(rigRequests(&rig, &request, 1) == 0, "with nothing on the wire");
}

static void casePibWholeWritableSetQueued(void)
{
    static const uint32_t writeOrder[6] =
    {
        PROP_PHY_CHAN, PROP_MAC_15_4_PANID, PROP_MAC_15_4_SADDR, PROP_MAC_15_4_LADDR,
        PROP_MAC_RX_ON_WHEN_IDLE, PROP_PHY_CCA_THRESHOLD
    };
    Rig rig;
    const Radio_Radio *seam;
    Radio_Pib pib;
    Radio_Pib readBack;
    Request request;
    uint32_t sets;
    uint32_t index;
    ZbStatus status;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");
    Test_Expect(rigDrainWrites(&rig, &sets), "the bring-up's own writes are on the link and answered");

    seam = RcpRadio_Seam(&rig.radio);
    Test_ExpectCount(rig.radio.writeCount, 0, "with the write queue empty before the call");

    pib = rigWritablePib();
    status = seam->ops->pibSet((Radio_Radio *)seam, &pib);
    Test_ExpectStatus(status, ZB_OK,
           "one call naming every writable PIB field is accepted whole");
    Test_ExpectCount(rig.radio.writeCount, 6, "and queues six property writes: the widest call this seam can be given");

    if (status != ZB_OK)
        return;     /* the refusal already named itself, and nothing was queued to inspect */

    Test_Expect(rigRequests(&rig, &request, 1) == 0, "none of them on the link yet: a seam call queues, it does not send");

    /* The mask names its fields in the caller's order; the queue band B builds is band B's own PIB order,
       which is not the order the dialect's table lists these properties in either. */
    for (index = 0; index < 6; index++)
    {
        Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "one pump, one queued write");
        Test_Expect(rigRequests(&rig, &request, 1) == 1, "arriving as its own transaction");
        Test_Expect(request.command == SPINEL_CMD_PROP_VALUE_SET && request.propId == writeOrder[index],
               "in PIB order: channel, PAN id, short address, extended address, rx-on-when-idle");

        if (request.propId == PROP_PHY_CHAN)
            Test_Expect(request.valueLen == 1 && request.value[0] == 12, "the channel as one octet");

        if (request.propId == PROP_MAC_15_4_PANID)
            Test_ExpectHex("the PAN id as two little-endian octets: ad de", request.value, request.valueLen, "adde");

        if (request.propId == PROP_MAC_15_4_SADDR)
            Test_ExpectHex("the short address as two little-endian octets: 34 12", request.value, request.valueLen, "3412");

        if (request.propId == PROP_MAC_15_4_LADDR)
            Test_Expect(request.valueLen == RADIO_ADDR_LEN
                   && Zb_memcmp(request.value, measuredHwaddr, RADIO_ADDR_LEN) == 0,
                   "the EUI-64 as eight octets in the wire's address order");

        if (request.propId == PROP_MAC_RX_ON_WHEN_IDLE)
            Test_Expect(request.valueLen == 1 && request.value[0] == 1, "the idle receive as a bool");

        if (request.propId == PROP_PHY_CCA_THRESHOLD)
            Test_Expect(request.valueLen == 1 && request.value[0] == 0xb9,
                   "and the CCA threshold last, as band B walks its PIB, in the octet the RCP answers for -71");

        rigAnswerRequest(&rig, &request);
        Test_ExpectCount(rig.radio.writeCount, 6 - index, "the rest of the call waits for its own answer");
    }

    Test_Expect(rigDrainWrites(&rig, &sets), "and the last answer empties the queue");
    Test_ExpectCount(RcpRadio_WriteFailures(&rig.radio), 0, "with no write refused by the RCP");

    Zb_memset(&readBack, 0, sizeof readBack);
    Test_ExpectStatus(seam->ops->pibGet((Radio_Radio *)seam, &readBack), ZB_OK, "the PIB reads back");
    Test_ExpectCount(readBack.channel, 12, "holding the channel the accepted call named");
    Test_ExpectCount(readBack.panId, 0xdead, "the PAN id");
    Test_ExpectCount(readBack.shortAddress, 0x1234, "the short address");
    Test_ExpectCount(readBack.rxOnWhenIdle, 1, "the idle receive");
    Test_ExpectCount(readBack.ccaThresholdDbm, -71,
           "and the CCA threshold, present because band B was the one that wrote it (docs/internals/protocol.md §7.4.3)");
    Test_Expect(Zb_memcmp(readBack.extendedAddress, measuredPibAddress, RADIO_ADDR_LEN) == 0,
           "and the extended address, in the PIB's own octet order");

    /* The other table: the same mask names a property that build has none of, and the four it can write
       are four writes; the bound is the larger of the two, not the one some call happens to need. */
    rigInit(&rig, OPENTHREAD_VERSION, 0xff, 9);
    rigSetChannel(&rig, 20);
    Test_Expect(rigBringUp(&rig), "armed on the OpenThread build");
    Test_Expect(rigDrainWrites(&rig, &sets), "its four arm writes answered");

    seam = RcpRadio_Seam(&rig.radio);
    pib = rigWritablePib();
    pib.channel = 26;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_ERR_UNSUPPORTED,
           "naming rx-on-when-idle or the CCA threshold here is a refusal, not a field quietly skipped");
    Test_ExpectCount(rig.radio.writeCount, 0, "with nothing queued for a call that was refused");

    pib = rigWritablePib();
    pib.channel = 26;
    pib.present = RADIO_PIB_EXTENDED_ADDRESS | RADIO_PIB_SHORT_ADDRESS | RADIO_PIB_PAN_ID | RADIO_PIB_CHANNEL;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_OK,
           "and this build's own writable set is four fields, accepted in one call too");
    Test_ExpectCount(rig.radio.writeCount, 4, "queued four writes");
    Test_Expect(rigDrainWrites(&rig, &sets), "all four put on the link and answered");
    Test_ExpectCount(sets, 4, "counted as four property writes");
    Test_ExpectCount(RcpRadio_WriteFailures(&rig.radio), 0, "none of them refused");
}

/* Both refusals a full pool has to state (docs/internals/coding-rules.md §4.3, §7): a call too large for the room left
   goes whole or not at all, and a queue with no room left refuses what arrives next instead of pushing one
   write out of it. */
static void casePibRoomLeftRefusal(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_Pib pib;
    Radio_Pib readBack;
    Radio_Filter filter;
    Request request;
    uint32_t sets;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");
    Test_Expect(rigDrainWrites(&rig, &sets), "the bring-up answered");

    seam = RcpRadio_Seam(&rig.radio);

    Zb_memset(&filter, 0, sizeof filter);
    filter.isPromiscuous = 0;
    Test_ExpectStatus(seam->ops->filter((Radio_Radio *)seam, &filter), ZB_OK, "one write is already queued");
    Test_ExpectCount(rig.radio.writeCount, 1, "so the room left is one short of a whole call");

    pib = rigWritablePib();
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_ERR_NO_SPACE,
           "a call naming six is refused whole, not shortened to what fits");
    Test_ExpectCount(rig.radio.writeCount, 1, "the queue holds exactly what it held");
    Test_Expect(rigRequests(&rig, &request, 1) == 0, "and nothing went on the link for it");

    Zb_memset(&readBack, 0, sizeof readBack);
    Test_ExpectStatus(seam->ops->pibGet((Radio_Radio *)seam, &readBack), ZB_OK, "the PIB reads back");
    Test_ExpectCount(readBack.channel, 15, "still the channel this RCP holds, not the one the refused call named");
    Test_ExpectCount(readBack.panId, 0xffff, "no PAN id taken: the unaddressed default band B opened with is still there");
    Test_ExpectCount(readBack.shortAddress, 0xffff, "and the same for the short address");
    Test_ExpectCount(readBack.rxOnWhenIdle, 0, "no idle receive taken");
    Test_Expect(readBack.extendedAddress[0] == 0 && readBack.extendedAddress[7] == 0,
           "no extended address taken: nothing half-applied while the rest was refused");
    Test_ExpectCount(RcpRadio_WriteFailures(&rig.radio), 0,
           "and a bound this stack set is not counted as a device refusing its own table");

    Test_Expect(rigDrainWrites(&rig, &sets), "the queued filter write goes out and is answered");
    Test_ExpectCount(sets, 1, "one property write: promiscuous mode off");
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_OK,
           "the same call lands whole as soon as the room comes back");
    Test_ExpectCount(rig.radio.writeCount, 6, "six queued writes");

    Test_ExpectStatus(seam->ops->filter((Radio_Radio *)seam, &filter), ZB_ERR_NO_SPACE,
           "and a full queue refuses what arrives next rather than pushing one out");
    Test_ExpectCount(rig.radio.writeCount, 6, "leaving the six it holds where they are");
    Test_Expect(rigRequests(&rig, &request, 1) == 0, "with no frame composed for the refusal");

    Zb_memset(&readBack, 0, sizeof readBack);
    seam->ops->pibGet((Radio_Radio *)seam, &readBack);
    Test_ExpectCount(readBack.channel, 12, "the accepted call's channel is held");
    Test_ExpectCount(readBack.panId, 0xdead, "its PAN id");
    Test_ExpectCount(readBack.shortAddress, 0x1234, "its short address");
    Test_ExpectCount(readBack.rxOnWhenIdle, 1, "and its idle receive, queued or not on the link");

    Test_Expect(rigDrainWrites(&rig, &sets), "and the six are put on the link and answered");
    Test_ExpectCount(sets, 6, "six property writes, no more and no fewer");
}

/* The session a lost device leaves behind, from the seam's side: the report a bring-up hands over, the device gone
   and brought back, and what the seam answers to the two masks a re-application can be made of, the report itself
   refused outright, and that report without the read-only field landed, on each of the two episodes in turn. */
static void caseLostSessionAtTheSeam(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_Pib report;
    Radio_Pib applied;
    Radio_Pib readBack;
    Request request;
    uint32_t sets;
    uint32_t resets;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "the scripted RCP is armed");
    Test_Expect(rigDrainWrites(&rig, &sets), "and its bring-up writes are on the link and answered");

    seam = RcpRadio_Seam(&rig.radio);

    Zb_memset(&report, 0, sizeof report);
    Test_ExpectStatus(seam->ops->pibGet((Radio_Radio *)seam, &report), ZB_OK,
           "the read a band A performs when it adopts this backend answers a report of what the RCP said it holds");
    Test_Expect((report.present & RADIO_PIB_HW_ADDRESS) != 0,
           "and the report names the RCP's own factory address, because the identity handshake read it (§7.2)");
    Test_Expect((report.present & RADIO_PIB_CHANNEL) != 0 && report.channel == 15,
           "beside the channel this RCP was armed on, which is the shape of a report carrying both a fact band A may read and a fact it wrote");
    Test_Expect((report.present & RADIO_PIB_EXTENDED_ADDRESS) == 0,
           "and it names no operational long address, because this host wrote none: the factory address above is a "
           "different property, and a mask that claimed one nobody wrote is the mirror D-122 names");

    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &report), ZB_ERR_UNSUPPORTED,
           "hand that report back whole, which is what a re-application built out of it is, and the seam refuses the call as a whole");
    Test_ExpectCount(rig.radio.writeCount, 0, "with nothing queued, the read-only field judged before any write was composed");
    Test_Expect(rigRequests(&rig, &request, 1) == 0, "and nothing put on the link for it");

    /* Which of the two masks band A hands down is the `mac` and `stack` suites' proof, `Mac_Step` being a layer a
       band B suite does not carry; what is measured here is what the seam answers to each shape. */

    applied = report;
    applied.present &= ~((uint32_t)RADIO_PIB_HW_ADDRESS);
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &applied), ZB_OK,
           "the same mask with the device's own field taken out is accepted whole: every field of it is one a host may write");
    Test_ExpectCount(rig.radio.writeCount, 4,
                     "and four property writes queued: page, channel, PAN and short address, the four the report names");
    Test_Expect(rigDrainWrites(&rig, &sets), "queued, written one per pump, and answered");
    Test_ExpectCount(sets, 4, "four property writes on the link, no more and no fewer");
    Test_ExpectCount(RcpRadio_WriteFailures(&rig.radio), 0, "with none of them refused by the RCP");

    /* The pair docs/internals/protocol.md §7.2 names: the factory address is the RCP's and only ever read, and the
       operational long address is the host's and must be written. A host that skips the second half transmits
       frames sourced from eight zero octets: measured. */
    Zb_memset(&applied, 0, sizeof applied);
    applied.present = RADIO_PIB_EXTENDED_ADDRESS;
    Zb_memcpy(applied.extendedAddress, report.hwAddress, RADIO_ADDR_LEN);
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &applied), ZB_OK,
                      "the factory address written back as the operational one is accepted");
    Test_ExpectCount(rig.radio.writeCount, 1, "as one property write");
    Test_Expect(rigDrainWrites(&rig, &sets), "put on the link and answered");

    Test_ExpectStatus(seam->ops->pibGet((Radio_Radio *)seam, &readBack), ZB_OK, "and read back");
    Test_Expect((readBack.present & RADIO_PIB_EXTENDED_ADDRESS) != 0,
                "the report names it now that somebody wrote it");
    Test_Expect(Zb_memcmp(readBack.extendedAddress, report.hwAddress, RADIO_ADDR_LEN) == 0,
                "with the octets it was given, which are the factory address's");

    rigAnswerStatus(&rig, SPINEL_TID_NONE, SPINEL_STATUS_RESET_SOFTWARE);
    resets = RcpRadio_ResetsSeen(&rig.radio);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the RCP announces a reset: the device that was configured is gone");
    Test_ExpectCount(RcpRadio_ResetsSeen(&rig.radio), resets + 1,
                     "counted as one more reset seen, the announcement shape the captured transcripts carry");
    Test_ExpectStatus(seam->ops->pibGet((Radio_Radio *)seam, &readBack), ZB_ERR_NOT_READY,
           "and while band B is bringing the device back there is no report to adopt from it");

    Test_Expect(rigBringUp(&rig), "the bring-up runs again against the same RCP");
    Test_Expect(rigDrainWrites(&rig, &sets), "and its writes are on the link and answered");

    Test_ExpectStatus(seam->ops->pibGet((Radio_Radio *)seam, &readBack), ZB_OK, "a second adoption reads a report again");
    Test_Expect((readBack.present & RADIO_PIB_HW_ADDRESS) != 0,
           "naming the factory address again, because a re-armed RCP has read its own identity afresh: a re-application built out of a report is refused on every episode, not on the first one only");
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &readBack), ZB_ERR_UNSUPPORTED,
           "and handing this report back whole meets the same refusal, with the queue and the PIB left as they were");
    Test_ExpectCount(rig.radio.writeCount, 0, "nothing queued for it");

    applied = readBack;
    applied.present &= ~((uint32_t)RADIO_PIB_HW_ADDRESS);
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &applied), ZB_OK,
           "and the mask made of what a host asked for lands on this second episode too: the re-application an RCP can be given");
    Test_Expect(rigDrainWrites(&rig, &sets), "put on the link and answered one by one");
    Test_ExpectCount(sets, 5,
                     "five property writes again, the second whole call of the session: the four the fresh report "
                     "names plus the long address this host wrote in between and re-arms like anything else");
    Test_ExpectCount(RcpRadio_WriteFailures(&rig.radio), 0, "and no write this RCP refused anywhere in it");
}

static void caseFilterAndScan(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_Filter filter;
    uint32_t count = 0;
    int32_t dbmLevel = 0;
    Request request;
    int found = 0;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = RcpRadio_Seam(&rig.radio);

    Zb_memset(&filter, 0, sizeof filter);
    filter.isPromiscuous = 1;
    filter.panId = 0xde20;
    Test_Expect(seam->ops->filter((Radio_Radio *)seam, &filter) == ZB_ERR_UNSUPPORTED,
           "identity belongs in the PIB, where §6 puts it: a filter that also carries it is refused");

    Zb_memset(&filter, 0, sizeof filter);
    filter.isPromiscuous = 0;
    Test_Expect(seam->ops->filter((Radio_Radio *)seam, &filter) == ZB_OK,
           "off is a real setting: it is what the teardown writes");

    for (count = 0; count < 8 && !found; count++)
    {
        Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "the pump drains the queue");

        while (rigRequests(&rig, &request, 1) == 1)
        {
            if (request.command == SPINEL_CMD_PROP_VALUE_SET && request.propId == PROP_MAC_PROMISCUOUS_MODE)
            {
                found = 1;
                break;
            }

            rigAnswerRequest(&rig, &request);
        }
    }

    Test_Expect(found && request.valueLen == 1 && request.value[0] == 0,
           "written as promiscuous mode off, which is what the teardown writes");
    rigAnswerRequest(&rig, &request);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "and answered");

    /* The dwell is not this case's subject any more: band B has built the dialog, and what it does with a dwell
       is cases of its own (caseScanDialogRunsAsMeasured and the refusals beside it). */
    Test_Expect(seam->ops->scanCollect((Radio_Radio *)seam, &count, &dbmLevel) == ZB_ERR_NOT_READY,
           "and a collect with no dwell outstanding says nothing is in flight, which is not a refusal");
}

/* The parked RCP's build advertises the scan bit in its bitmap while the table measured for it
   names no scan group at all. A bitmap is not a request format, and band B refuses on the table before the
   device is asked anything (D-123). */
static void caseScanStillUnsupportedWhereCapable(void)
{
    Rig rig;
    const Radio_Radio *seam;
    uint32_t channel = 0;
    int32_t dbm = 0;

    rigInit(&rig, OPENTHREAD_VERSION, 0xff, 9);
    rigSetChannel(&rig, 20);
    Test_Expect(rigBringUp(&rig), "armed on the other dialect");
    Test_Expect(rig.radio.caps.hasEnergyScan == 1, "which reports the capability");

    seam = RcpRadio_Seam(&rig.radio);
    Test_Expect(seam->ops->scanStart((Radio_Radio *)seam, 11, 200) == ZB_ERR_UNSUPPORTED,
           "and is still refused at the ask, because band B has not implemented the dwell dialog");
    Test_Expect(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm) == ZB_ERR_UNSUPPORTED,
           "and the collect half refuses with it, with nothing queued and nothing on the link");
    Test_ExpectCount(rig.radio.writeCount, 0, "no scan write was composed for either call");
    Test_Expect(RcpRadio_SurfaceState(&rig.radio, PROP_MAC_SCAN_STATE) == PROPS_SURFACE_UNKNOWN,
           "and the refusal says nothing about the device, because the device was never asked");
    Test_Expect(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm) == ZB_ERR_UNSUPPORTED,
           "and the collect half says the same no, so a caller pumping for a level never mistakes it for a dwell still running");
}

static void caseDeliveryAndFaults(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_Frame frames[RADIO_FRAME_BATCH_MAX];
    uint8_t psdu[5] = { 0x01, 0x08, 0x3e, 0x00, 0x11 };
    uint32_t i;
    uint32_t taken;
    uint32_t total = 0;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 15);
    Test_Expect(rigBringUp(&rig), "armed");

    seam = RcpRadio_Seam(&rig.radio);

    /* Sixteen frames is the queue; a seventeenth is counted, not buffered somewhere else. */
    for (i = 0; i < 20; i++)
    {
        rigStreamRaw(&rig, psdu, 5, -90, 200, 1000 * i, 0, 0, 0, 0);
        Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "a notification is delivered");
    }

    Test_Expect(RcpRadio_RxQueued(&rig.radio) <= RCP_RADIO_RX_QUEUE_MAX, "the queue holds at most its stated size");
    Test_Expect(RcpRadio_RxOverflows(&rig.radio) == 0,
           "and nothing is lost: the pump stops pulling when the queue has no room for a chunk");
    Test_Expect(Port_RxPending(&rig.radio.port) > 0 || rig.script.rxPos < rig.rxLen,
           "what band B did not decode is still in band C's ring or in the RCP");

    /* A driver that polls in batches, with the pump between polls doing the pulling. */
    for (i = 0; i < 20; i++)
    {
        taken = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);
        total += taken;

        if (taken == 0)
            Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "polling hands the queue back to the pump");
        else
            rig.nowMs++;
    }

    Test_Expect(total == 20, "every notification the RCP delivered arrived");
    Test_Expect(RcpRadio_RxQueued(&rig.radio) == 0, "and the queue drained");
    Test_Expect(RcpRadio_RxOverflows(&rig.radio) == 0 && RcpRadio_PortDrops(&rig.radio) == 0,
           "with nothing dropped on the way");
    Test_Expect(seam->ops->rxPoll((Radio_Radio *)seam, frames, 99) == 0, "an empty queue polls to zero");

    /* A port whose device went away. */
    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rig.script.failPumpAfter = 0;
    rigSetChannel(&rig, 15);
    Test_Expect(!rigBringUp(&rig), "a link that fails on its first read does not come up");
    Test_Expect(RcpRadio_Mode(&rig.radio) == RCP_RADIO_MODE_FAULT, "and the backend says the link is lost");
    Test_Expect(RcpRadio_Seam(&rig.radio)->ops->isLost((Radio_Radio *)RcpRadio_Seam(&rig.radio)) == 1,
           "which the seam can ask");
}

/* The five MD_MAC octets are the dialect's way of saying a frame is the acknowledgment record of a frame the
 * radio transmitted. Nothing captured from the air ever said that (every notification in the
 * transcripts carries zeros in all five), so the nonzero shape is built here and named as built. What is
 * pinned is that band B reads those octets and counts them instead of throwing them away: docs/internals/hardware.md
 * records an RCP being handed the frame it had just sent, and on this link those octets are the only
 * thing that tells that story apart from an arrival. */
static void caseAckMetadataIsCountedNotDiscarded(void)
{
    Rig rig;
    uint8_t psdu[5];
    Radio_Frame frames[RADIO_FRAME_BATCH_MAX];
    Radio_Radio *seam;
    uint32_t got;

    rigInit(&rig, DSPINEL_VERSION, 0x10f, 4);
    rigSetChannel(&rig, 12);
    Test_Expect(rigBringUp(&rig), "armed");
    seam = RcpRadio_Seam(&rig.radio);

    psdu[0] = 0x01; psdu[1] = 0x20; psdu[2] = 0xc7; psdu[3] = 0xff; psdu[4] = 0xff;
    rigStreamRaw(&rig, psdu, 5, -94, 200, 3000, 0, 0, 0, 0);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "a frame that says nothing about an acknowledgment");
    got = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);
    Test_Expect(got == 1, "is delivered as any other");
    Test_Expect(frames[0].len == 5, "whole");
    Test_Expect(RcpRadio_RxWithAckMetadata(&rig.radio) == 0, "and is not counted");

    psdu[0] = 0x01; psdu[1] = 0x20; psdu[2] = 0xc7; psdu[3] = 0xff; psdu[4] = 0xff;
    rigStreamRaw(&rig, psdu, 5, -94, 200, 4000, 0, 0, 1, 42);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "a frame that names one");
    got = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);
    Test_Expect(got == 1, "is delivered unchanged");
    Test_Expect(frames[0].len == 5, "and the reading did not touch the frame");
    Test_Expect(RcpRadio_RxWithAckMetadata(&rig.radio) == 1, "and the one that spoke is counted");
}

static void caseNothingReady(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_Caps caps;
    Radio_Pib pib;
    Radio_Handle handle = RADIO_HANDLE_NONE;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    seam = RcpRadio_Seam(&rig.radio);

    pib = rigPib();
    pib.present = RADIO_PIB_CHANNEL;
    pib.channel = 15;

    Test_Expect(seam->ops->caps((Radio_Radio *)seam, &caps) == ZB_ERR_NOT_READY
           && seam->ops->pibGet((Radio_Radio *)seam, &pib) == ZB_ERR_NOT_READY
           && seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 0, 0, &handle) == ZB_ERR_NOT_READY,
           "before the RCP has answered, nothing about it is reported");
    Test_Expect(handle == RADIO_HANDLE_NONE, "and no handle was issued for a frame that was not sent");
}


/* Pump and answer until the table's statement has been written and taken, handing back what went on the wire. */
static int rigDrainPending(Rig *rig, Request *out, uint32_t max, uint32_t *outCount)
{
    Request request;
    uint32_t count = 0;
    uint32_t step;

    for (step = 0; step < 16; step++)
    {
        if (RcpRadio_Pump(&rig->radio, rig->nowMs++) != ZB_OK)
            return 0;

        while (rigRequests(rig, &request, 1) == 1)
        {
            if (count < max)
                out[count] = request;

            count++;
            rigAnswerRequest(rig, &request);
        }

        if (!rig->radio.pendingDirty && RcpRadio_PendingState(&rig->radio) == RCP_RADIO_PENDING_NONE)
            break;
    }

    *outCount = count;
    return !rig->radio.pendingDirty;
}

static Radio_Pending rigPending(int isComplete)
{
    Radio_Pending pending;

    Zb_memset(&pending, 0, (uint32_t)sizeof pending);
    pending.isComplete = isComplete;
    return pending;
}

/*
 * 10.22.3's table, as the three properties docs/internals/protocol.md §7.4 measured: the enable bit, then the two lists,
 * each replaced whole and each written in the order a reader of the firmware's table expects.
 */
static void casePendingTableWritesTheThreeProperties(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_Pending pending;
    Radio_Pending written;
    Request sent[8];
    uint32_t count = 0;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 12);
    Test_Expect(rigBringUp(&rig), "armed");
    seam = RcpRadio_Seam(&rig.radio);

    pending = rigPending(1);
    pending.shortAddress[0] = 0x0002;
    pending.shortAddress[1] = 0x0003;
    pending.shortCount = 2;
    pending.extendedAddress[0] = 0x00124a000b2c0180;
    pending.extendedCount = 1;

    Test_Expect(seam->ops->pendingTable((Radio_Radio *)seam, &pending) == ZB_OK,
                "a radio that answered for the family is told which addresses a frame waits for");
    Test_Expect(rigDrainPending(&rig, sent, 8, &count), "and the statement is written and taken");
    Test_ExpectCount(count, 3, "three writes: the enable bit and the two lists");

    Test_Expect(sent[0].command == SPINEL_CMD_PROP_VALUE_SET && sent[0].propId == PROP_MAC_SRC_MATCH_ENABLED,
                "0x1303 first, because a list a radio ignores decides nothing");
    Test_Expect(sent[0].valueLen == 1 && sent[0].value[0] == 1,
                "with the table enabled: a device the lists do not name has nothing waiting (10.22.3)");
    Test_Expect(sent[1].propId == PROP_MAC_SRC_MATCH_SHORT_ADDRESSES && sent[1].valueLen == 4
                && sent[1].value[0] == 0x02 && sent[1].value[1] == 0x00
                && sent[1].value[2] == 0x03 && sent[1].value[3] == 0x00,
                "0x1304 as concatenated little-endian short addresses, no count prefix");
    Test_Expect(sent[2].propId == PROP_MAC_SRC_MATCH_EXTENDED_ADDRESSES && sent[2].valueLen == 8
                && sent[2].value[0] == 0x00 && sent[2].value[1] == 0x12 && sent[2].value[7] == 0x80,
                "and 0x1305 in the byte order MAC_15_4_LADDR answers in, most significant first");

    Test_ExpectCount(RcpRadio_PendingWrites(&rig.radio), 1, "one statement, not three");
    Test_Expect(RcpRadio_PendingWritten(&rig.radio, &written) == 1 && written.isComplete == 1
                && written.shortCount == 2 && written.extendedCount == 1,
                "and what the device took is what band A stated");

    Test_Expect(seam->ops->pendingTable((Radio_Radio *)seam, &pending) == ZB_OK,
                "the same table stated again is accepted");
    Test_ExpectCount(rig.radio.pendingDirty, 0, "and owes the device nothing: three writes hold up every transmit behind them");
    Test_ExpectCount(RcpRadio_PendingWrites(&rig.radio), 1, "so it is not written again");

    pending.shortCount = 1;

    Test_Expect(seam->ops->pendingTable((Radio_Radio *)seam, &pending) == ZB_OK, "a table that differs");
    Test_Expect(rigDrainPending(&rig, sent, 8, &count), "is written");
    Test_ExpectCount(RcpRadio_PendingWrites(&rig.radio), 2, "whole, because a statement is what the seam carries, not a patch");
}

/* The standard's fallback: a coordinator that cannot name every device it holds a frame for tells the radio to
   claim one for all of them, which is the bit's own answer and not a table's. */
static void casePendingTableStatesTheFallback(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_Pending pending;
    Request sent[8];
    uint32_t count = 0;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 12);
    Test_Expect(rigBringUp(&rig), "armed");
    seam = RcpRadio_Seam(&rig.radio);

    pending = rigPending(0);
    pending.shortAddress[0] = 0x0002;
    pending.shortCount = 1;

    Test_Expect(seam->ops->pendingTable((Radio_Radio *)seam, &pending) == ZB_OK, "a table band A cannot complete");
    Test_Expect(rigDrainPending(&rig, sent, 8, &count), "is written");
    Test_Expect(sent[0].propId == PROP_MAC_SRC_MATCH_ENABLED && sent[0].value[0] == 0,
                "with the enable bit clear, which is 10.22.3's 'if this is not possible, set it to one'");
}

/* A device that answers PROP_NOT_FOUND for the family is not asked again (D-123), and the capability says so. */
static void casePendingTableRefusedIsRemembered(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_Pending pending;
    Radio_Caps caps;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rig.refuseSrcMatch = 1;
    rigSetChannel(&rig, 12);
    Test_Expect(rigBringUp(&rig), "armed against an RCP with no source-match family");
    seam = RcpRadio_Seam(&rig.radio);

    Test_Expect(seam->ops->caps((Radio_Radio *)seam, &caps) == ZB_OK && caps.hasPendingTable == 0,
                "the discovery read answered PROP_NOT_FOUND, so the capability is absent and not assumed");
    Test_Expect(RcpRadio_SurfaceState(&rig.radio, PROP_MAC_SRC_MATCH_ENABLED) == PROPS_SURFACE_ABSENT,
                "recorded as an answer about that property");

    pending = rigPending(1);
    Test_Expect(seam->ops->pendingTable((Radio_Radio *)seam, &pending) == ZB_ERR_UNSUPPORTED,
                "and a table stated to it is refused at the seam, without a frame going out");
}

/* The table lives in the device, so a device that forgot everything needs it stated again. */
static void casePendingTableRestatedAfterReset(void)
{
    Rig rig;
    const Radio_Radio *seam;
    Radio_Pending pending;
    Radio_Pending written;
    Request sent[8];
    uint32_t count = 0;

    rigInit(&rig, DSPINEL_VERSION, 0x10d, 4);
    rigSetChannel(&rig, 12);
    Test_Expect(rigBringUp(&rig), "armed");
    seam = RcpRadio_Seam(&rig.radio);

    pending = rigPending(1);
    pending.shortAddress[0] = 0x0002;
    pending.shortCount = 1;

    Test_Expect(seam->ops->pendingTable((Radio_Radio *)seam, &pending) == ZB_OK, "a table is stated");
    Test_Expect(rigDrainPending(&rig, sent, 8, &count), "and taken");
    Test_ExpectCount(RcpRadio_PendingWrites(&rig.radio), 1, "as one statement");

    Test_Expect(seam->ops->pendingTable((Radio_Radio *)seam, &pending) == ZB_OK, "the queue then moves");
    rigAnswerStatus(&rig, 0, SPINEL_STATUS_RESET_SOFTWARE);
    Test_Expect(RcpRadio_Pump(&rig.radio, rig.nowMs++) == ZB_OK, "and the RCP announces a reset");

    Test_Expect(rigBringUp(&rig), "which re-arms it");
    Test_ExpectCount(RcpRadio_PendingWrites(&rig.radio), 2,
                     "and the table is stated again, the reset having put the device back to its default");
    Test_Expect(RcpRadio_PendingWritten(&rig.radio, &written) == 1 && written.isComplete == 1
                && written.shortCount == 1 && written.shortAddress[0] == 0x0002,
                "with the list band A last stated, which the reset did not change");
}

int main(void)
{
    Test_Begin("rcp_radio");

    caseBringUp();
    caseResetAnsweredByTid();
    caseBringUpWithoutChannel();
    caseBringUpUnknownBuild();
    caseStreamRawDelivery();
    caseTranscriptReplay();
    caseTxComposition();
    caseTxCompletion();
    caseTxWaitsInLine();
    caseTxKeepsItsPlaceAmongWrites();
    caseTxCarriesWhatItWasAskedUnder();
    caseTxLineEndsWithTheRcp();
    caseTxWaitIsBounded();
    caseTxResultNobodyCollectsFreesItsSlot();
    caseTxReplyTimeoutEndsTheWholeTrack();
    caseTxCarriesItsRetries();
    caseTxAcknowledgementRefused();
    caseUnsolicitedReset();
    caseUnsolicitedResetIsALoss();
    caseReplyTimeout();
    caseArmRefusalFaults();
    caseDiscoveryRefusalContinues();
    casePibRoutes();
    casePibWholeWritableSetQueued();
    casePibRoomLeftRefusal();
    caseLostSessionAtTheSeam();
    caseResetDrainsTheInboundRing();
    caseStaleFramesBeforeTheResetAnswer();
    caseFilterAndScan();
    caseSurfaceOfWhatWasAnswered();
    caseCompletionTailCarriesTheAcksFramePending();
    caseScanDialogRunsAsMeasured();
    caseScanRefusedGroupIsRemembered();
    caseScanDwellWithNothingToReport();
    caseScanArgumentsRefusedBeforeTheLink();
    caseScanUncollectedReportHoldsTheMachine();
    caseAckMetadataIsCountedNotDiscarded();
    caseScanRefusedByDeviceState();
    caseScanStillUnsupportedWhereCapable();
    casePendingTableWritesTheThreeProperties();
    casePendingTableStatesTheFallback();
    casePendingTableRefusedIsRemembered();
    casePendingTableRestatedAfterReset();
    caseDeliveryAndFaults();
    caseNothingReady();

    return Test_Report();
}
