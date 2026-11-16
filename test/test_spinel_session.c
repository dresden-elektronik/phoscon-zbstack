/* Suite for the transaction half of a Spinel link: which TID is outstanding, which arriving frame
   answers it, what a status code becomes for the layers above, and what a reply that never arrives
   costs (docs/internals/protocol.md §3, §5, §7.3). */

#include <stdio.h>

#include "hdlc.h"
#include "props.h"
#include "spinel.h"
#include "spinel_session.h"
#include "zb_utils.h"

#define FRAME_CAP 64
#define TABLE_LEN(table) (sizeof table / sizeof table[0])

static int s_failures;

static void expect(int condition, const char *what)
{
    if (!condition)
    {
        printf("FAIL: %s\n", what);
        s_failures++;
    }
}

static void frameBegin(uint8_t *buf, uint8_t tid, uint8_t command, uint32_t propId, U_BStream *stream)
{
    U_bstream_init(stream, buf, FRAME_CAP);
    Spinel_WriteHeader(stream, tid);
    Spinel_WritePackedUint(stream, command);
    Spinel_WritePackedUint(stream, propId);
}

static uint32_t frameEnd(U_BStream *stream)
{
    return FRAME_CAP - Spinel_Remaining(stream);
}

static void caseTidRotation(void)
{
    Spinel_Session session;
    U_BStream stream;
    uint8_t buf[FRAME_CAP];
    uint8_t ask[FRAME_CAP];
    uint32_t i;
    uint8_t tid;

    SpinelSession_Init(&session, 0);
    expect(!SpinelSession_Busy(&session), "a fresh session has nothing outstanding");

    for (i = 0; i < 16; i++)
    {
        U_bstream_init(&stream, ask, (unsigned long)sizeof ask);
        expect(SpinelSession_Compose(&session, SPINEL_CMD_PROP_VALUE_GET, PROP_PHY_CHAN, i, &stream) == ZB_OK,
               "a request whose predecessor was answered is accepted");

        tid = SpinelSession_PendingTid(&session);
        expect(tid >= SPINEL_TID_MIN && tid <= SPINEL_TID_MAX,
               "every TID this session issues is in 1..15: 0 means no answer is queued (§5)");
        expect(tid == (uint8_t)((i % SPINEL_TID_MAX) + 1), "TIDs are issued in increasing order and wrap");
        expect(SpinelSession_PendingProp(&session) == PROP_PHY_CHAN
               && SpinelSession_PendingTid(&session) == tid,
               "the outstanding request is readable by its id and its TID");

        frameBegin(buf, tid, SPINEL_CMD_PROP_VALUE_IS, PROP_PHY_CHAN, &stream);
        Spinel_WriteUint8(&stream, 15);
        expect(SpinelSession_Absorb(&session, buf, frameEnd(&stream), i, 0) == SPINEL_OUTCOME_REPLY,
               "and the frame carrying that TID answers it");
    }

    expect(session.requests == 16 && session.replies == 16 && session.stale == 0 && session.malformed == 0,
           "the counts reconcile with the frames that passed");
}

static void caseBusyAndNoSpace(void)
{
    Spinel_Session session;
    U_BStream stream;
    uint8_t ask[FRAME_CAP];
    uint8_t small[4];

    SpinelSession_Init(&session, 0);
    U_bstream_init(&stream, ask, (unsigned long)sizeof ask);
    expect(SpinelSession_Compose(&session, SPINEL_CMD_PROP_VALUE_GET, PROP_PHY_CHAN, 0, &stream) == ZB_OK,
           "the first request is accepted");

    expect(SpinelSession_Compose(&session, SPINEL_CMD_PROP_VALUE_GET, PROP_PHY_ENABLED, 1, &stream) == ZB_ERR_BUSY,
           "a second request while one is outstanding is refused, not queued");
    expect(session.requests == 1, "and refusing it did not issue a TID");
    expect(SpinelSession_PendingProp(&session) == PROP_PHY_CHAN, "the outstanding request is unchanged");

    U_bstream_init(&stream, small, (unsigned long)sizeof small);
    expect(SpinelSession_Compose(&session, SPINEL_CMD_PROP_VALUE_SET, PROP_UNSOL_UPDATE_FILTER, 2, &stream)
               == ZB_ERR_BUSY,
           "a busy link is reported before a buffer is examined: the reason a driver can act on");

    SpinelSession_Init(&session, 0);
    U_bstream_init(&stream, small, (unsigned long)sizeof small);
    expect(SpinelSession_Compose(&session, SPINEL_CMD_PROP_VALUE_SET, PROP_RADIO_CAPS, 3, &stream)
               == ZB_ERR_NO_SPACE,
           "a buffer that cannot hold header, command and id is refused instead of half a frame");
    expect(!SpinelSession_Busy(&session) && session.requests == 0,
           "and a refused composition leaves nothing outstanding to time out");
}

static void caseMatching(void)
{
    Spinel_Session session;
    Spinel_Reply reply;
    U_BStream stream;
    uint8_t buf[FRAME_CAP];
    uint8_t ask[FRAME_CAP];
    uint8_t tid;

    SpinelSession_Init(&session, 0);
    U_bstream_init(&stream, ask, (unsigned long)sizeof ask);
    SpinelSession_Compose(&session, SPINEL_CMD_PROP_VALUE_GET, PROP_PHY_CHAN, 0, &stream);
    tid = SpinelSession_PendingTid(&session);

    frameBegin(buf, (uint8_t)(tid == SPINEL_TID_MAX ? 1 : tid + 1), SPINEL_CMD_PROP_VALUE_IS,
               PROP_PHY_CHAN, &stream);
    Spinel_WriteUint8(&stream, 11);
    expect(SpinelSession_Absorb(&session, buf, frameEnd(&stream), 0, &reply) == SPINEL_OUTCOME_STALE,
           "a TID this session never issued is stale, not a near miss");
    expect(SpinelSession_Busy(&session), "and it does not end the outstanding request");
    expect(session.stale == 1, "counted, never forgiven");

    frameBegin(buf, SPINEL_TID_NONE, SPINEL_CMD_PROP_VALUE_IS, PROP_PHY_RSSI, &stream);
    Spinel_WriteInt8(&stream, -128);
    expect(SpinelSession_Absorb(&session, buf, frameEnd(&stream), 0, &reply) == SPINEL_OUTCOME_NOTIFY,
           "a TID 0 frame is unsolicited and is never matched to a request");
    expect(SpinelSession_Busy(&session), "the request is still outstanding");
    expect(reply.hasValues && Spinel_ReadInt8(&reply.values) == -128,
           "its value is still readable, which is how a notification reaches a driver");

    frameBegin(buf, tid, SPINEL_CMD_PROP_VALUE_IS, PROP_PHY_CHAN, &stream);
    Spinel_WriteUint8(&stream, 15);
    expect(SpinelSession_Absorb(&session, buf, frameEnd(&stream), 0, &reply) == SPINEL_OUTCOME_REPLY,
           "and the right TID answers it");
    expect(!SpinelSession_Busy(&session), "the transaction is over");
    expect(reply.propId == PROP_PHY_CHAN && reply.command == SPINEL_CMD_PROP_VALUE_IS,
           "the reply says what it is a reply to");
    expect(reply.hasValues && reply.statusCode == SPINEL_STATUS_OK
           && Spinel_ReadUint8(&reply.values) == 15,
           "the value is where the shape says it is, and a value reply carries no status");
}

/* Each row is a code measured on the wire (docs/internals/protocol.md §7.3) and the seam status band B
   turns it into. A status the frame carries as its whole value is the shape a refusal takes. */
static void caseStatuses(void)
{
    static const uint32_t codes[] =
    {
        SPINEL_STATUS_OK, SPINEL_STATUS_INVALID_ARGUMENT, SPINEL_STATUS_INVALID_STATE,
        SPINEL_STATUS_PARSE_ERROR, SPINEL_STATUS_BUSY, SPINEL_STATUS_PROP_NOT_FOUND
    };
    static const ZbStatus wanted[] =
    {
        ZB_OK, ZB_ERR_BAD_ARGUMENT, ZB_ERR_NOT_READY, ZB_ERR_BAD_FRAME, ZB_ERR_BUSY,
        ZB_ERR_UNSUPPORTED
    };
    Spinel_Session session;
    U_BStream stream;
    uint8_t buf[FRAME_CAP];
    uint8_t ask[FRAME_CAP];
    uint32_t i;

    for (i = 0; i < TABLE_LEN(codes); i++)
        expect(SpinelSession_StatusToZb(codes[i]) == wanted[i], "a measured code maps to one status");

    expect(SpinelSession_StatusToZb(SPINEL_STATUS_FAILURE) == ZB_ERR_DEVICE
           && SpinelSession_StatusToZb(SPINEL_STATUS_UNIMPLEMENTED) == ZB_ERR_UNSUPPORTED,
           "a device that said no without a reason this stack names still says no");
    expect(SpinelSession_StatusToZb(1000) == ZB_ERR_DEVICE,
           "and a code never measured is a device fault, not a guess");

    SpinelSession_Init(&session, 0);
    U_bstream_init(&stream, ask, (unsigned long)sizeof ask);
    SpinelSession_Compose(&session, SPINEL_CMD_PROP_VALUE_GET, PROP_PHY_CHAN_SUPPORTED, 0, &stream);

    frameBegin(buf, SpinelSession_PendingTid(&session), SPINEL_CMD_PROP_VALUE_IS, PROP_LAST_STATUS, &stream);
    Spinel_WritePackedUint(&stream, SPINEL_STATUS_PROP_NOT_FOUND);
    expect(SpinelSession_Absorb(&session, buf, frameEnd(&stream), 0, 0) == SPINEL_OUTCOME_REPLY,
           "a refusal is a reply: same TID, property LAST_STATUS");
    expect(session.replies == 1 && !SpinelSession_Busy(&session), "and it ends the transaction");

    U_bstream_init(&stream, ask, (unsigned long)sizeof ask);
    SpinelSession_Compose(&session, SPINEL_CMD_PROP_VALUE_GET, PROP_PHY_CHAN, 1, &stream);

    /* The same refusal bytes, now carrying a TID that is not the one outstanding. A frame that
       answers nothing is not allowed to answer whatever happens to be waiting. */
    frameBegin(buf, (uint8_t)(SpinelSession_PendingTid(&session) + 1), SPINEL_CMD_PROP_VALUE_IS,
               PROP_LAST_STATUS, &stream);
    Spinel_WritePackedUint(&stream, SPINEL_STATUS_PROP_NOT_FOUND);
    expect(SpinelSession_Absorb(&session, buf, frameEnd(&stream), 1, 0) == SPINEL_OUTCOME_STALE,
           "the refusal of one request does not answer the next");
    expect(SpinelSession_Busy(&session), "and the outstanding request survives it");
}

static void caseTimeout(void)
{
    Spinel_Session session;
    Spinel_Reply reply;
    U_BStream stream;
    uint8_t buf[FRAME_CAP];
    uint8_t ask[FRAME_CAP];
    uint8_t tid;

    SpinelSession_Init(&session, 250);
    U_bstream_init(&stream, ask, (unsigned long)sizeof ask);
    SpinelSession_Compose(&session, SPINEL_CMD_PROP_VALUE_SET, PROP_PHY_CHAN, 1000, &stream);
    tid = SpinelSession_PendingTid(&session);

    expect(SpinelSession_Expires(&session, 1100) == ZB_OK && SpinelSession_Busy(&session),
           "inside the window the request is still outstanding");
    expect(SpinelSession_Expires(&session, 1249) == ZB_OK, "one millisecond short is not a timeout");
    expect(SpinelSession_Expires(&session, 1250) == ZB_ERR_TIMEOUT,
           "the window ending is a stated error, not a silence");
    expect(!SpinelSession_Busy(&session) && session.timeouts == 1,
           "the transaction is abandoned and the abandonment is counted");
    expect(SpinelSession_Expires(&session, 9999) == ZB_OK, "nothing outstanding has nothing to expire");

    frameBegin(buf, tid, SPINEL_CMD_PROP_VALUE_IS, PROP_PHY_CHAN, &stream);
    Spinel_WriteUint8(&stream, 20);
    expect(SpinelSession_Absorb(&session, buf, frameEnd(&stream), 1260, &reply) == SPINEL_OUTCOME_STALE,
           "an answer that came after its window is stale: a driver must not act on it as the answer "
           "to whatever it is doing now");

    SpinelSession_Init(&session, 0);
    U_bstream_init(&stream, ask, (unsigned long)sizeof ask);
    SpinelSession_Compose(&session, SPINEL_CMD_PROP_VALUE_GET, PROP_PHY_CHAN, 1, &stream);
    expect(SpinelSession_Expires(&session, 0xffffffff) == ZB_OK,
           "a session with no window is not a session that times out at the wrap");
    SpinelSession_Abandon(&session);
    expect(!SpinelSession_Busy(&session) && session.timeouts == 0,
           "abandoning without a timeout is the link going away, and is counted as nothing");
}

static void caseMalformed(void)
{
    Spinel_Session session;
    uint8_t buf[FRAME_CAP];
    U_BStream stream;

    SpinelSession_Init(&session, 0);

    expect(SpinelSession_Absorb(&session, buf, 0, 0, 0) == SPINEL_OUTCOME_MALFORMED,
           "an empty payload is not a frame");
    expect(SpinelSession_Absorb(&session, 0, 8, 0, 0) == SPINEL_OUTCOME_MALFORMED,
           "neither is a payload that is nowhere");

    buf[0] = 0x40;      /* flag bits 0b01: not the header this family writes */
    buf[1] = SPINEL_CMD_PROP_VALUE_IS;
    expect(SpinelSession_Absorb(&session, buf, 2, 0, 0) == SPINEL_OUTCOME_MALFORMED,
           "a header with the wrong flag bits is rejected before anything is read from it");

    buf[0] = 0x81;     /* header with a TID, and nothing after it */
    expect(SpinelSession_Absorb(&session, buf, 1, 0, 0) == SPINEL_OUTCOME_MALFORMED,
           "a frame with no command in it is nothing");

    buf[0] = 0x81;
    buf[1] = SPINEL_CMD_PROP_VALUE_IS;
    expect(SpinelSession_Absorb(&session, buf, 2, 0, 0) == SPINEL_OUTCOME_MALFORMED,
           "a command that names no property is the shape of a request, not of an answer");

    frameBegin(buf, 1, SPINEL_CMD_PROP_VALUE_IS, PROP_LAST_STATUS, &stream);
    expect(SpinelSession_Absorb(&session, buf, frameEnd(&stream), 0, 0) == SPINEL_OUTCOME_MALFORMED,
           "a refusal with no code in it is a truncated frame, not a refusal of nothing");

    expect(SpinelSession_Absorb(&session, buf, HDLC_PAYLOAD_MAX + 1, 0, 0) == SPINEL_OUTCOME_MALFORMED,
           "and octets past what a frame can hold are not a frame either");

    expect(session.malformed == 7 && session.replies == 0 && session.notifications == 0,
           "every one of them counted, none of them believed");
}

/*
 * Two RCPs on one host: the seam is per-device (docs/internals/coding-rules.md §4.2), so neither session may
 * see the other's transaction. There is no global TID pool here, and a suite that ran one session
 * would not notice if there were.
 */
static void caseTwoSessions(void)
{
    Spinel_Session a;
    Spinel_Session b;
    Spinel_Reply reply;
    U_BStream stream;
    uint8_t buf[FRAME_CAP];
    uint8_t askA[FRAME_CAP];
    uint8_t askB[FRAME_CAP];
    U_BStream streamB;
    uint8_t tidA;
    uint8_t tidB;

    SpinelSession_Init(&a, 0);
    SpinelSession_Init(&b, 0);

    U_bstream_init(&stream, askA, (unsigned long)sizeof askA);
    U_bstream_init(&streamB, askB, (unsigned long)sizeof askB);
    SpinelSession_Compose(&a, SPINEL_CMD_PROP_VALUE_GET, PROP_PHY_CHAN, 0, &stream);
    SpinelSession_Compose(&b, SPINEL_CMD_PROP_VALUE_GET, PROP_MAC_15_4_PANID, 0, &streamB);
    tidA = SpinelSession_PendingTid(&a);
    tidB = SpinelSession_PendingTid(&b);
    expect(tidA == tidB, "TIDs are per-link, not per-process: two RCPs may both be at 1");

    frameBegin(buf, tidB, SPINEL_CMD_PROP_VALUE_IS, PROP_MAC_15_4_PANID, &stream);
    Spinel_WriteUint16(&stream, 0xde20);
    expect(SpinelSession_Absorb(&b, buf, frameEnd(&stream), 0, &reply) == SPINEL_OUTCOME_REPLY,
           "a frame from the second link answers the second session");
    expect(reply.hasValues && Spinel_ReadUint16(&reply.values) == 0xde20,
           "a two-octet little-endian id reads back as it was written");

    SpinelSession_Compose(&b, SPINEL_CMD_PROP_VALUE_GET, PROP_PHY_ENABLED, 0, &streamB);
    expect(SpinelSession_PendingTid(&b) == (uint8_t)(tidB + 1), "and it moves on to its next TID");

    /* The first link's answer, replayed at the second session after that session had already moved
       on. Nothing in a session knows which port a frame came from, so this is the shape a two-RCP
       driver must not create, and when it does happen, the frame is refused rather than acted on. */
    frameBegin(buf, tidA, SPINEL_CMD_PROP_VALUE_IS, PROP_PHY_CHAN, &stream);
    Spinel_WriteUint8(&stream, 20);
    expect(SpinelSession_Absorb(&b, buf, frameEnd(&stream), 0, &reply) == SPINEL_OUTCOME_STALE,
           "an answer from the other link is stale, not an answer");
    expect(SpinelSession_Busy(&b) && SpinelSession_PendingProp(&b) == PROP_PHY_ENABLED,
           "the second session's own transaction is untouched");

    expect(SpinelSession_Absorb(&a, buf, frameEnd(&stream), 0, &reply) == SPINEL_OUTCOME_REPLY,
           "the very same bytes are the first link's answer, and only there");
    expect(a.replies == 1 && a.stale == 0 && b.replies == 1 && b.stale == 1,
           "the counters belong to each session, not to the process");
}

static void caseResetStatuses(void)
{
    Spinel_Session session;
    Spinel_Reply reply;
    U_BStream stream;
    uint8_t buf[FRAME_CAP];
    uint8_t ask[FRAME_CAP];

    expect(SpinelSession_IsResetStatus(SPINEL_STATUS_RESET_POWER_ON)
           && SpinelSession_IsResetStatus(SPINEL_STATUS_RESET_SOFTWARE),
           "both measured codes announce a reset (docs/internals/protocol.md §5)");
    expect(!SpinelSession_IsResetStatus(SPINEL_STATUS_OK)
           && !SpinelSession_IsResetStatus(SPINEL_STATUS_BUSY)
           && !SpinelSession_IsResetStatus(SPINEL_STATUS_PROP_NOT_FOUND),
           "no other measured code does, and 113 is not invented here because nothing answered it");
    expect(SpinelSession_StatusToZb(SPINEL_STATUS_RESET_SOFTWARE) == ZB_ERR_DEVICE_LOST,
           "a reset is the link going away, which is what the seam calls it");

    SpinelSession_Init(&session, 0);
    U_bstream_init(&stream, ask, (unsigned long)sizeof ask);
    SpinelSession_Compose(&session, SPINEL_CMD_RESET, PROP_LAST_STATUS, 0, &stream);

    frameBegin(buf, SPINEL_TID_NONE, SPINEL_CMD_PROP_VALUE_IS, PROP_LAST_STATUS, &stream);
    Spinel_WritePackedUint(&stream, SPINEL_STATUS_RESET_SOFTWARE);
    expect(SpinelSession_Absorb(&session, buf, frameEnd(&stream), 0, &reply) == SPINEL_OUTCOME_NOTIFY,
           "the measured answer to a RESET is unsolicited");
    expect(reply.statusCode == SPINEL_STATUS_RESET_SOFTWARE, "and its code is readable");

    frameBegin(buf, SPINEL_TID_NONE, SPINEL_CMD_PROP_VALUE_IS, PROP_LAST_STATUS, &stream);
    Spinel_WritePackedUint(&stream, SPINEL_STATUS_RESET_POWER_ON);
    expect(SpinelSession_Absorb(&session, buf, frameEnd(&stream), 0, &reply) == SPINEL_OUTCOME_NOTIFY,
           "the other build's answer reads the same way");
    expect(session.notifications == 2, "counted as notifications, not as answers to the request");
}

int main(void)
{
    caseTidRotation();
    caseBusyAndNoSpace();
    caseMatching();
    caseStatuses();
    caseTimeout();
    caseMalformed();
    caseTwoSessions();
    caseResetStatuses();

    if (s_failures != 0)
    {
        printf("spinel_session: %d failures\n", s_failures);
        return 1;
    }

    printf("spinel_session: ok\n");
    return 0;
}
