/* The hearing shim the mesh runs stand on (src/stack/hearing.h): over a stub radio, what reaches band A and what
   reaches the air. It has to judge the hop rather than the originator, and to report a cut link as a cut link. */

#include "hearing.h"
#include "mac_frame.h"
#include "test_harness.h"
#include "zb_utils.h"

#define NEAR_IEEE 0x00212effff0000a1
#define FAR_IEEE 0x00212effff0000b2

enum
{
    NEAR_SHORT = 0x1111,
    FAR_SHORT = 0x2222,
    STUB_QUEUE = 4
};

typedef struct Stub
{
    Radio_Frame queued[STUB_QUEUE];
    uint32_t queuedCount;
    uint32_t txCalls;
} Stub;

static Stub s_stub;
static Radio_Frame s_out[STUB_QUEUE];

static ZbStatus stubCaps(Radio_Radio *radio, Radio_Caps *outCaps)
{
    (void)radio;
    Zb_memset(outCaps, 0, (uint32_t)sizeof *outCaps);
    return ZB_OK;
}

static ZbStatus stubTx(Radio_Radio *radio, const uint8_t *mpdu, uint32_t len, int ackRequest,
                       uint32_t maxFrameRetries, Radio_Handle *outHandle)
{
    (void)radio;
    (void)mpdu;
    (void)len;
    (void)ackRequest;
    (void)maxFrameRetries;
    s_stub.txCalls++;
    *outHandle = s_stub.txCalls;
    return ZB_OK;
}

static ZbStatus stubCompletion(Radio_Radio *radio, Radio_Handle handle, Radio_TxResult *outResult)
{
    (void)radio;
    (void)handle;
    Zb_memset(outResult, 0, (uint32_t)sizeof *outResult);
    outResult->isAcked = 1;
    return ZB_OK;
}

static uint32_t stubRxPoll(Radio_Radio *radio, Radio_Frame *outFrames, uint32_t maxFrames)
{
    uint32_t i;
    uint32_t count = s_stub.queuedCount < maxFrames ? s_stub.queuedCount : maxFrames;

    (void)radio;

    for (i = 0; i < count; i++)
        outFrames[i] = s_stub.queued[i];

    s_stub.queuedCount = 0;

    return count;
}

static const Radio_Ops s_stubOps = { stubCaps, 0, 0, 0, stubTx, stubCompletion, stubRxPoll, 0, 0, 0, 0 };
static Radio_Radio s_stubRadio = { &s_stubOps, 0 };

/* A NWK data frame as a relay sends it: the MAC source `hop`, the NWK source `origin`, secured by `hopIeee`. */
static void queueSecured(uint16_t hop, uint16_t origin, uint64_t hopIeee)
{
    Radio_Frame *frame = &s_stub.queued[s_stub.queuedCount++];
    uint32_t at = 0;
    uint32_t i;

    Zb_memset(frame, 0, (uint32_t)sizeof *frame);

    /* 802.15.4: data, PAN compression, short addresses both ways, version 0. */
    frame->bytes[at++] = 0x41;
    frame->bytes[at++] = 0x88;
    frame->bytes[at++] = 0x01;
    frame->bytes[at++] = 0xef;
    frame->bytes[at++] = 0xbe;
    frame->bytes[at++] = 0x00;
    frame->bytes[at++] = 0x00;
    frame->bytes[at++] = (uint8_t)hop;
    frame->bytes[at++] = (uint8_t)(hop >> 8);

    /* 3.3.1: data, protocol 2, security set; destination, source, radius, sequence. */
    frame->bytes[at++] = 0x08;
    frame->bytes[at++] = 0x02;
    frame->bytes[at++] = 0x00;
    frame->bytes[at++] = 0x00;
    frame->bytes[at++] = (uint8_t)origin;
    frame->bytes[at++] = (uint8_t)(origin >> 8);
    frame->bytes[at++] = 0x1e;
    frame->bytes[at++] = 0x42;

    /* 4.3.2: control with the extended nonce, a counter, the hop's address, a key sequence. */
    frame->bytes[at++] = 0x28;
    at += 4;

    for (i = 0; i < 8; i++)
        frame->bytes[at++] = (uint8_t)(hopIeee >> (8 * i));

    frame->bytes[at++] = 0x00;
    at += 8;
    frame->len = at;
}

static void queueBeacon(uint16_t source)
{
    Radio_Frame *frame = &s_stub.queued[s_stub.queuedCount++];
    uint32_t at = 0;

    Zb_memset(frame, 0, (uint32_t)sizeof *frame);
    frame->bytes[at++] = 0x00;
    frame->bytes[at++] = 0x80;
    frame->bytes[at++] = 0x01;
    frame->bytes[at++] = 0xef;
    frame->bytes[at++] = 0xbe;
    frame->bytes[at++] = (uint8_t)source;
    frame->bytes[at++] = (uint8_t)(source >> 8);
    frame->bytes[at++] = 0xff;
    frame->bytes[at++] = 0xcf;
    frame->bytes[at++] = 0x00;
    frame->len = at;
}

static uint32_t unicastTo(uint8_t *mpdu, uint16_t destination)
{
    uint32_t at = 0;

    mpdu[at++] = 0x61;
    mpdu[at++] = 0x88;
    mpdu[at++] = 0x01;
    mpdu[at++] = 0xef;
    mpdu[at++] = 0xbe;
    mpdu[at++] = (uint8_t)destination;
    mpdu[at++] = (uint8_t)(destination >> 8);
    mpdu[at++] = 0x33;
    mpdu[at++] = 0x33;
    mpdu[at++] = 0xaa;

    return at;
}

static void caseIgnoredHopIsNotHeard(void)
{
    Hearing hearing;
    Radio_Radio *seam;

    Test_Case("caseIgnoredHopIsNotHeard");
    Zb_memset(&s_stub, 0, (uint32_t)sizeof s_stub);
    Hearing_Init(&hearing, &s_stubRadio);
    Test_ExpectStatus(Hearing_IgnoreIeee(&hearing, FAR_IEEE), ZB_OK, "the far device is named by its extended address");
    seam = Hearing_Seam(&hearing);

    queueSecured(NEAR_SHORT, NEAR_SHORT, NEAR_IEEE);
    queueSecured(FAR_SHORT, FAR_SHORT, FAR_IEEE);
    Test_ExpectCount(seam->ops->rxPoll(seam, s_out, STUB_QUEUE), 1, "the far device's frame is dropped by its auxiliary address");
    Test_ExpectCount(hearing.framesDropped, 1, "and counted");
    Test_ExpectCount(s_out[0].bytes[7], NEAR_SHORT & 0xff, "the near device's frame is the one that came through");
    Test_ExpectCount(hearing.ignored[0].shortKnown, 1, "and the far device's short address is learned");
    Test_ExpectCount(hearing.ignored[0].shortAddress, FAR_SHORT, "as the frame's MAC source");

    queueBeacon(FAR_SHORT);
    Test_ExpectCount(seam->ops->rxPoll(seam, s_out, STUB_QUEUE), 0, "so its beacon, which names no extended address, is dropped too");
}

static void caseRelayedFrameStillArrives(void)
{
    Hearing hearing;
    Radio_Radio *seam;

    Test_Case("caseRelayedFrameStillArrives");
    Zb_memset(&s_stub, 0, (uint32_t)sizeof s_stub);
    Hearing_Init(&hearing, &s_stubRadio);
    Test_ExpectStatus(Hearing_IgnoreIeee(&hearing, FAR_IEEE), ZB_OK, "the far device is named");
    seam = Hearing_Seam(&hearing);

    queueSecured(FAR_SHORT, FAR_SHORT, FAR_IEEE);
    (void)seam->ops->rxPoll(seam, s_out, STUB_QUEUE);

    queueSecured(NEAR_SHORT, FAR_SHORT, NEAR_IEEE);
    Test_ExpectCount(seam->ops->rxPoll(seam, s_out, STUB_QUEUE), 1,
                     "what the far device originated arrives through the relay: the hop is judged, not the originator");
    Test_ExpectCount(hearing.framesDropped, 1, "and only the frame heard from it directly was dropped");
}

static void caseKnownShortIsNotHeardFromTheStart(void)
{
    Hearing hearing;
    Radio_Radio *seam;

    Test_Case("caseKnownShortIsNotHeardFromTheStart");
    Zb_memset(&s_stub, 0, (uint32_t)sizeof s_stub);
    Hearing_Init(&hearing, &s_stubRadio);
    Test_ExpectStatus(Hearing_IgnoreShort(&hearing, 0x0000), ZB_OK, "the coordinator is named by the address it always has");
    seam = Hearing_Seam(&hearing);

    queueBeacon(0x0000);
    queueBeacon(NEAR_SHORT);
    Test_ExpectCount(seam->ops->rxPoll(seam, s_out, STUB_QUEUE), 1, "so a joining router is not offered it as a parent");
}

static void caseCutUnicastIsNotAcknowledged(void)
{
    Hearing hearing;
    Radio_Radio *seam;
    Radio_TxResult result;
    Radio_Handle handle = RADIO_HANDLE_NONE;
    uint8_t mpdu[16];
    uint32_t len;
    uint32_t i;

    Test_Case("caseCutUnicastIsNotAcknowledged");
    Zb_memset(&s_stub, 0, (uint32_t)sizeof s_stub);
    Hearing_Init(&hearing, &s_stubRadio);
    Test_ExpectStatus(Hearing_IgnoreShort(&hearing, FAR_SHORT), ZB_OK, "the far device is named");
    seam = Hearing_Seam(&hearing);

    len = unicastTo(mpdu, FAR_SHORT);
    Test_ExpectStatus(seam->ops->tx(seam, mpdu, len, 1, 3, &handle), ZB_OK, "a unicast to it is taken");
    Test_ExpectCount(s_stub.txCalls, 0, "and never reaches the air, where the far RCP would acknowledge it");
    Test_ExpectCount(hearing.framesUnsent, 1, "counted");
    Test_ExpectStatus(seam->ops->completion(seam, handle, &result), ZB_OK, "its answer is there");
    Test_ExpectStatus(result.status, ZB_ERR_NO_ACK, "and is what a link that does not exist answers");
    Test_ExpectCount(result.isAcked, 0, "with no acknowledgment");
    Test_ExpectStatus(seam->ops->completion(seam, handle, &result), ZB_ERR_BAD_ARGUMENT, "and it is answered once");

    len = unicastTo(mpdu, NEAR_SHORT);
    Test_ExpectStatus(seam->ops->tx(seam, mpdu, len, 1, 3, &handle), ZB_OK, "a unicast to anyone else");
    Test_ExpectCount(s_stub.txCalls, 1, "goes on the air");
    Test_ExpectStatus(seam->ops->completion(seam, handle, &result), ZB_OK, "and its answer is the radio's");
    Test_ExpectCount(result.isAcked, 1, "acknowledged");

    len = unicastTo(mpdu, FAR_SHORT);
    Test_ExpectStatus(seam->ops->tx(seam, mpdu, len, 0, 0, &handle), ZB_OK, "a frame that asks no acknowledgment");
    Test_ExpectCount(s_stub.txCalls, 2, "has nothing to be misreported, and goes out");

    for (i = 0; i < HEARING_UNHEARD_MAX; i++)
    {
        len = unicastTo(mpdu, FAR_SHORT);
        Test_ExpectStatus(seam->ops->tx(seam, mpdu, len, 1, 3, &handle), ZB_OK, "uncollected answers are held");
    }

    Test_ExpectStatus(seam->ops->tx(seam, mpdu, len, 1, 3, &handle), ZB_ERR_NO_SPACE, "up to the table's size");
}

int main(void)
{
    Test_Begin("hearing");

    caseIgnoredHopIsNotHeard();
    caseRelayedFrameStillArrives();
    caseKnownShortIsNotHeardFromTheStart();
    caseCutUnicastIsNotAcknowledged();

    return Test_Report();
}
