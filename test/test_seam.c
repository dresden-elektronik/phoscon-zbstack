/* Suite for the seam itself: a stub backend that satisfies Radio_Ops and the calls band A
   will make through it. It proves the contract is implementable as written and that a frame
   survives the handover, which is the property band A depends on (docs/internals/architecture.md §4). */

#include <stdio.h>

#include "radio.h"

static int s_failures;

static void expect(int condition, const char *what)
{
    if (!condition)
    {
        printf("FAIL: %s\n", what);
        s_failures++;
    }
}

typedef struct StubRadio
{
    uint32_t framesQueued;
    uint32_t txRequests;
    int ackRequestSeen;
    int isLost;
    uint32_t pibPresentSeen;
    Radio_Filter filterSeen;
} StubRadio;

static ZbStatus stubCaps(Radio_Radio *radio, Radio_Caps *outCaps)
{
    StubRadio *stub = (StubRadio *)radio->provider;

    (void)stub;
    outCaps->radioCaps = 0x10d;
    outCaps->hasTransmit = 1;
    outCaps->hasEnergyScan = 0;
    outCaps->psduIncludesFcs = 1;
    outCaps->hasAckMetadata = 0;
    return ZB_OK;
}

static ZbStatus stubPibSet(Radio_Radio *radio, const Radio_Pib *pib)
{
    StubRadio *stub = (StubRadio *)radio->provider;

    stub->pibPresentSeen = pib->present;

    if (pib->channel > 26)
        return ZB_ERR_BAD_ARGUMENT;

    return ZB_OK;
}

static ZbStatus stubPibGet(Radio_Radio *radio, Radio_Pib *pib)
{
    (void)radio;
    pib->present = RADIO_PIB_CHANNEL | RADIO_PIB_PAN_ID;
    pib->channel = 26;
    pib->panId = 0xbeef;
    return ZB_OK;
}

static ZbStatus stubFilter(Radio_Radio *radio, const Radio_Filter *filter)
{
    StubRadio *stub = (StubRadio *)radio->provider;

    stub->filterSeen = *filter;

    if (!filter->isPromiscuous)
        return ZB_ERR_UNSUPPORTED;

    return ZB_OK;
}

static ZbStatus stubTx(Radio_Radio *radio, const uint8_t *mpdu, uint32_t len,
                       int ackRequest, uint32_t maxFrameRetries, Radio_Handle *outHandle)
{
    StubRadio *stub = (StubRadio *)radio->provider;

    (void)maxFrameRetries;

    if (len == 0 || len > RADIO_MPDU_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (mpdu[0] == 0)
        return ZB_ERR_BAD_ARGUMENT;

    stub->txRequests++;
    stub->ackRequestSeen = ackRequest;
    *outHandle = stub->txRequests;
    return ZB_OK;
}

static ZbStatus stubCompletion(Radio_Radio *radio, Radio_Handle handle, Radio_TxResult *outResult)
{
    StubRadio *stub = (StubRadio *)radio->provider;

    if (handle == RADIO_HANDLE_NONE || handle > stub->txRequests)
        return ZB_ERR_BAD_ARGUMENT;

    outResult->status = ZB_OK;
    outResult->isAcked = stub->ackRequestSeen;
    outResult->retries = 0;
    outResult->framePendingReported = 0;
    outResult->framePending = 0;
    return ZB_OK;
}

static uint32_t stubRxPoll(Radio_Radio *radio, Radio_Frame *outFrames, uint32_t maxFrames)
{
    StubRadio *stub = (StubRadio *)radio->provider;
    uint32_t i;
    uint32_t octet;

    if (maxFrames > RADIO_FRAME_BATCH_MAX)
        maxFrames = RADIO_FRAME_BATCH_MAX;

    for (i = 0; i < maxFrames && stub->framesQueued > 0; i++)
    {
        stub->framesQueued--;
        outFrames[i].len = RADIO_MPDU_MAX;

        for (octet = 0; octet < RADIO_MPDU_MAX; octet++)
            outFrames[i].bytes[octet] = (uint8_t)(octet + 1);

        outFrames[i].rssiDbm = -94;
        outFrames[i].lqi = 255;
        outFrames[i].deviceStampTicks = 1234 + i;
        outFrames[i].error = ZB_OK;
    }

    return i;
}

static int stubIsLost(Radio_Radio *radio)
{
    StubRadio *stub = (StubRadio *)radio->provider;

    return stub->isLost;
}

static ZbStatus stubScanStart(Radio_Radio *radio, uint32_t channel, uint32_t dwellUnits)
{
    (void)channel;
    (void)dwellUnits;
    (void)radio;
    return ZB_ERR_UNSUPPORTED;
}

static ZbStatus stubScanCollect(Radio_Radio *radio, uint32_t *outChannel, int32_t *outDbm)
{
    (void)outChannel;
    (void)outDbm;
    (void)radio;
    return ZB_ERR_UNSUPPORTED;
}

static const Radio_Ops s_stubOps =
{
    stubCaps,
    stubPibSet,
    stubPibGet,
    stubFilter,
    stubTx,
    stubCompletion,
    stubRxPoll,
    stubIsLost,
    stubScanStart,
    stubScanCollect
    , 0    /* no pending table: this backend states 10.22.3's bit itself or not at all */
};

int main(void)
{
    StubRadio stub;
    Radio_Radio radio;
    Radio_Caps caps;
    Radio_Pib pib;
    Radio_Filter filter;
    Radio_Frame frames[RADIO_FRAME_BATCH_MAX];
    Radio_TxResult result;
    Radio_Handle handle;
    uint8_t mpdu[RADIO_MPDU_MAX];
    uint32_t i;
    uint32_t got;
    int32_t level;

    stub.framesQueued = 0;
    stub.txRequests = 0;
    stub.ackRequestSeen = 0;
    stub.isLost = 0;
    stub.pibPresentSeen = 0;

    radio.ops = &s_stubOps;
    radio.provider = &stub;

    caps.radioCaps = 0;
    expect(radio.ops->caps(&radio, &caps) == ZB_OK, "caps answers through the seam");
    expect(caps.radioCaps == 0x10d, "the device's own bitmap passes through uninterpreted");
    expect(caps.psduIncludesFcs == 1, "the FCS rule reaches band A as a capability");
    expect(caps.hasEnergyScan == 0, "a capability the silicon lacks is reported as lacking");

    pib.present = RADIO_PIB_CHANNEL | RADIO_PIB_RX_ON_WHEN_IDLE;
    pib.channel = 26;
    pib.rxOnWhenIdle = 1;
    expect(radio.ops->pibSet(&radio, &pib) == ZB_OK, "a partial PIB set is accepted");
    expect(stub.pibPresentSeen == (RADIO_PIB_CHANNEL | RADIO_PIB_RX_ON_WHEN_IDLE),
           "only the fields stated as present are carried");

    pib.channel = 27;
    expect(radio.ops->pibSet(&radio, &pib) == ZB_ERR_BAD_ARGUMENT,
           "a refused value comes back as a stated status, not as silence");

    pib.present = 0;
    expect(radio.ops->pibGet(&radio, &pib) == ZB_OK, "pibGet answers");
    expect(pib.channel == 26 && pib.panId == 0xbeef, "pibGet reports what the device holds");

    filter.isPromiscuous = 1;
    filter.panId = 0xde20;
    filter.shortAddress = 0;
    expect(radio.ops->filter(&radio, &filter) == ZB_OK, "promiscuous delivery is the measured path");

    filter.isPromiscuous = 0;
    expect(radio.ops->filter(&radio, &filter) == ZB_ERR_UNSUPPORTED,
           "an unimplemented filter is refused rather than approximated");
    expect(stub.filterSeen.isPromiscuous == 0, "the refusal is about what was actually asked for");

    for (i = 0; i < RADIO_MPDU_MAX; i++)
        mpdu[i] = (uint8_t)(i + 1);

    handle = RADIO_HANDLE_NONE;
    expect(radio.ops->tx(&radio, mpdu, RADIO_MPDU_MAX + 1, 1, 0, &handle) == ZB_ERR_BAD_ARGUMENT,
           "an over-length MPDU is refused at the seam");
    expect(handle == RADIO_HANDLE_NONE, "a refused transmit issues no handle");

    expect(radio.ops->tx(&radio, mpdu, RADIO_MPDU_MAX, 1, 0, &handle) == ZB_OK, "a full PSDU is accepted");
    expect(handle != RADIO_HANDLE_NONE, "a transmit gets a handle that means something");

    expect(radio.ops->completion(&radio, handle, &result) == ZB_OK,
           "the completion for a handle is collectable");
    expect(result.isAcked == 1, "the acknowledgement the seam was asked for comes back");

    expect(radio.ops->completion(&radio, RADIO_HANDLE_NONE, &result) == ZB_ERR_BAD_ARGUMENT,
           "no handle is not a completion");

    stub.framesQueued = RADIO_FRAME_BATCH_MAX + 3;
    got = radio.ops->rxPoll(&radio, frames, RADIO_FRAME_BATCH_MAX);
    expect(got == RADIO_FRAME_BATCH_MAX, "a poll takes at most one batch");
    expect(stub.framesQueued == 3, "what a poll did not take is still queued");
    expect(frames[0].len == RADIO_MPDU_MAX && frames[0].bytes[0] == 1
           && frames[0].bytes[RADIO_MPDU_MAX - 1] == RADIO_MPDU_MAX,
           "a frame survives the handover intact");
    expect(frames[1].deviceStampTicks == 1235, "the device stamp is carried per frame");
    expect(frames[0].error == ZB_OK, "a clean frame says so");

    got = radio.ops->rxPoll(&radio, frames, 1000);
    expect(got == 3, "a request larger than the batch is capped, not failed");
    got = radio.ops->rxPoll(&radio, frames, RADIO_FRAME_BATCH_MAX);
    expect(got == 0, "an empty radio hands over zero frames");

    expect(radio.ops->isLost(&radio) == 0, "an armed radio is not lost");

    stub.isLost = 1;
    expect(radio.ops->isLost(&radio) == 1, "a device that reset under us is reported, not swallowed");

    got = 0;
    expect(radio.ops->scanStart(&radio, 11, 200) == ZB_ERR_UNSUPPORTED,
           "a capability the backend does not implement is refused at the ask, not faked");
    expect(radio.ops->scanCollect(&radio, &got, &level) == ZB_ERR_UNSUPPORTED,
           "and there is no level to collect from a refusal: the pair is two calls, and both answer");

    if (s_failures != 0)
    {
        printf("seam: %d failures\n", s_failures);
        return 1;
    }

    printf("seam: ok\n");
    return 0;
}
