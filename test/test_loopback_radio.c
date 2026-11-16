/* Suite for the hardware-free backend: the seam contract it must satisfy like any other band B module,
   and the model a band A suite scripts, outcomes, delays that never end, injection, loss, refusal. */

#include "loopback_radio.h"
#include "test_harness.h"
#include "zb_utils.h"

/* A complete MPDU as band A hands it to the seam: MHR, payload where there is one, footer.
   The acknowledgment is the standard's own worked example (docs/internals/protocol.md §9.3). */
static const uint8_t ackMpdu[5] = { 0x02, 0x00, 0x6a, 0xe4, 0x79 };
static const uint8_t dataMpdu[11] =
{
    0x41, 0x88, 0x07, 0xef, 0xbe, 0xff, 0xff, 0xad, 0xde, 0x14, 0xa4
};

static Radio_Caps modelCaps(uint32_t radioCaps, int psduIncludesFcs, int hasEnergyScan, int hasAckMetadata)
{
    Radio_Caps caps;

    Zb_memset(&caps, 0, (uint32_t)sizeof caps);
    caps.radioCaps = radioCaps;
    caps.hasTransmit = 1;
    caps.psduIncludesFcs = psduIncludesFcs;
    caps.hasEnergyScan = hasEnergyScan;
    caps.hasAckMetadata = hasAckMetadata;

    return caps;
}

static void caseCapsAndPib(void)
{
    Loopback_Radio model;
    const Radio_Radio *seam;
    Radio_Caps caps = modelCaps(0x10d, 1, 0, 0);
    Radio_Caps reported;
    Radio_Pib pib;
    Radio_Pib read;
    ZbStatus status;

    Test_ExpectStatus(LoopbackRadio_Init(&model, &caps), ZB_OK, "a model is initialised");

    seam = LoopbackRadio_Seam(&model);
    Test_Expect(seam != 0 && seam->ops != 0 && seam->provider == &model, "and hands out a seam bound to itself");

    Test_ExpectStatus(seam->ops->caps((Radio_Radio *)seam, &reported), ZB_OK, "caps answers");
    Test_Expect(reported.radioCaps == 0x10d && reported.psduIncludesFcs == 1 && reported.hasEnergyScan == 0,
           "the declared model reaches band A uninterpreted, exactly as a device's bitmap does");
    Test_ExpectStatus(seam->ops->caps((Radio_Radio *)seam, 0), ZB_ERR_BAD_ARGUMENT, "and a null answer is refused");

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_CHANNEL | RADIO_PIB_RX_ON_WHEN_IDLE;
    pib.channel = 26;
    pib.rxOnWhenIdle = 1;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_OK, "a partial PIB set is accepted");

    Zb_memset(&read, 0, (uint32_t)sizeof read);
    read.present = RADIO_PIB_CHANNEL | RADIO_PIB_RX_ON_WHEN_IDLE | RADIO_PIB_PAN_ID;
    Test_ExpectStatus(seam->ops->pibGet((Radio_Radio *)seam, &read), ZB_OK, "pibGet answers");
    Test_Expect(read.channel == 26 && read.rxOnWhenIdle == 1, "with the fields that were set");
    Test_Expect((read.present & (RADIO_PIB_CHANNEL | RADIO_PIB_RX_ON_WHEN_IDLE)) != 0,
           "and reports which fields it holds: the model holds what it was told, not what was asked for");

    pib.present = RADIO_PIB_CHANNEL;
    pib.channel = 27;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_ERR_BAD_ARGUMENT,
                 "a channel outside 11..26 is refused here too, because no 2.4 GHz PHY numbers one");

    pib.present = RADIO_PIB_MAX_FRAME_RETRIES;
    pib.maxFrameRetries = 256;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_ERR_BAD_ARGUMENT,
                 "and a retry count a §8.2 trailer octet cannot carry is refused rather than truncated");

    pib.present = RADIO_PIB_PAGE;
    pib.page = 11;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_ERR_BAD_ARGUMENT,
                 "as is a sub-GHz page this stack has no channel set for");

    /* RADIO_PIB_ACK_WAIT_MS is the one seam field rcp_radio refuses because no property of either
       dialect carries it (its header says so). A model can hold it, which is what makes band A's
       acknowledgment-timeout decisions testable at all. */
    pib.present = RADIO_PIB_ACK_WAIT_MS;
    pib.ackWaitMs = 1200;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_OK, "the ack wait is a field this model carries");
    status = seam->ops->pibGet((Radio_Radio *)seam, &read);
    Test_Expect(status == ZB_OK && read.ackWaitMs == 1200, "and reads back");

    LoopbackRadio_RefusePib(&model, RADIO_PIB_CHANNEL);
    pib.present = RADIO_PIB_CHANNEL;
    pib.channel = 12;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_ERR_DEVICE,
                 "a scripted refusal answers the way a device refuses: as a device fault, not as an argument");
    Test_Expect(model.pib.channel == 26, "and nothing was stored");
    Test_Expect(LoopbackRadio_Refusals(&model) == 1, "counted");

    pib.present = RADIO_PIB_CHANNEL;
    pib.channel = 12;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_OK,
                 "the refusal lasts one call: it models a device that said no to this write, not a broken model");
    Test_Expect(model.pib.channel == 12, "and the write lands after it");

    /* The record a band A suite reads when its question is what it *asked* the device for rather than what the
       device kept: every request the seam was handed, in issue order, the declined ones included. */
    {
        Radio_Pib writes[LOOPBACK_PIB_WRITE_MAX];
        uint32_t count = LoopbackRadio_PibWrites(&model, writes, LOOPBACK_PIB_WRITE_MAX);

        Test_ExpectCount(count, 7, "every PIB request this case made is kept, the seven of them in issue order");
        Test_Expect(count == 7 && writes[5].channel == 12,
                    "with the request the model declined in the record beside the ones it accepted");
    }
}

/* The one PIB field a backend owns rather than holds: `rcp_radio` reports the address its identity handshake read
   and refuses any call that names it (docs/internals/protocol.md §7.2 is the sweep that reads it), and a model that hid the
   field would differ from an RCP in exactly the respect band A has to plan around, so this one does both. */
static void caseFactoryAddressIsReportedNotWritten(void)
{
    Loopback_Radio model;
    const Radio_Radio *seam;
    Radio_Caps caps = modelCaps(0x10d, 1, 0, 0);
    Radio_Pib pib;
    Radio_Pib read;
    Radio_Pib writes[LOOPBACK_PIB_WRITE_MAX];
    uint8_t octets[RADIO_ADDR_LEN] = { 0x12, 0x8a, 0x04, 0xff, 0xff, 0x2e, 0x21, 0x00 };
    uint32_t count;

    LoopbackRadio_Init(&model, &caps);

    seam = LoopbackRadio_Seam(&model);

    Zb_memset(&read, 0, sizeof read);
    Test_ExpectStatus(seam->ops->pibGet((Radio_Radio *)seam, &read), ZB_OK, "a model nobody scripted answers a read of its PIB");
    Test_Expect((read.present & RADIO_PIB_HW_ADDRESS) == 0,
           "and reports no factory address at all for a part that was given none, which is the answer an unprogrammed row gives");

    LoopbackRadio_SetFactoryAddress(&model, octets);

    Test_ExpectStatus(seam->ops->pibGet((Radio_Radio *)seam, &read), ZB_OK, "the model scripted with an identity answers again");
    Test_Expect((read.present & RADIO_PIB_HW_ADDRESS) != 0,
           "and reports the factory address as a field it holds, the way an RCP's backend reports the one its handshake read");
    Test_ExpectHex("in the PIB's octet order, which is the order band A keeps an address in and the reverse of the wire's",
                   read.hwAddress, RADIO_ADDR_LEN, "128a04ffff2e2100");

    Zb_memset(&pib, 0, sizeof pib);
    pib.present = RADIO_PIB_HW_ADDRESS;
    Zb_memcpy(pib.hwAddress, octets, RADIO_ADDR_LEN);
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_ERR_UNSUPPORTED,
           "and the very field it reports is refused as a write, whatever it carries: a read is not a licence to put it back");

    pib.present = RADIO_PIB_HW_ADDRESS | RADIO_PIB_CHANNEL;
    pib.channel = 26;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_ERR_UNSUPPORTED,
           "refused whole when it arrives beside a field this model would take, because a call is one call");
    Test_ExpectCount(model.pib.channel, 0, "with the field it could have accepted left unwritten");

    Zb_memset(&pib, 0, sizeof pib);
    pib.present = RADIO_PIB_CHANNEL | RADIO_PIB_PAN_ID;
    pib.channel = 26;
    pib.panId = 0xbeef;
    Test_ExpectStatus(seam->ops->pibSet((Radio_Radio *)seam, &pib), ZB_OK, "and a call that names only fields a host may write is taken beside that identity");

    Test_ExpectStatus(seam->ops->pibGet((Radio_Radio *)seam, &read), ZB_OK, "the read after it reports the whole of what the model holds");
    Test_ExpectCount(read.present & (RADIO_PIB_HW_ADDRESS | RADIO_PIB_CHANNEL | RADIO_PIB_PAN_ID),
                     RADIO_PIB_HW_ADDRESS | RADIO_PIB_CHANNEL | RADIO_PIB_PAN_ID,
                     "the two fields it was told and the one it is: the mask is the backend's own report, not the mask of the last call");
    Test_ExpectHex("and the factory octets are untouched by everything that went past them",
                   read.hwAddress, RADIO_ADDR_LEN, "128a04ffff2e2100");

    count = LoopbackRadio_PibWrites(&model, writes, LOOPBACK_PIB_WRITE_MAX);
    Test_ExpectCount(count, 3, "three requests kept in issue order, the two that were refused beside the one that landed");
    Test_Expect((writes[0].present & RADIO_PIB_HW_ADDRESS) != 0
           && (writes[1].present & RADIO_PIB_HW_ADDRESS) != 0,
           "the refused ones named the device's own field, which is what a band A that re-applied what it had merely read would hand down");
    Test_Expect((writes[2].present & RADIO_PIB_HW_ADDRESS) == 0,
           "and the accepted one did not: this is the mask a re-application is made of");
}

static void caseFilter(void)
{
    Loopback_Radio model;
    const Radio_Radio *seam;
    Radio_Caps caps = modelCaps(0x10d, 1, 0, 0);
    Radio_Filter filter;

    LoopbackRadio_Init(&model, &caps);
    seam = LoopbackRadio_Seam(&model);

    Zb_memset(&filter, 0, (uint32_t)sizeof filter);
    filter.isPromiscuous = 1;
    Test_ExpectStatus(seam->ops->filter((Radio_Radio *)seam, &filter), ZB_OK, "promiscuous delivery is accepted");

    filter.isPromiscuous = 0;
    filter.panId = 0xbeef;
    filter.shortAddress = 0x1234;
    Test_ExpectStatus(seam->ops->filter((Radio_Radio *)seam, &filter), ZB_OK,
                 "and so is the filtered form both ConBee II builds were measured answering");
    Test_Expect(model.filter.isPromiscuous == 0 && model.filter.shortAddress == 0x1234, "held as asked for");

    LoopbackRadio_SetFilteredDelivery(&model, 0);
    Test_ExpectStatus(seam->ops->filter((Radio_Radio *)seam, &filter), ZB_ERR_UNSUPPORTED,
                 "a model that cannot filter names that rather than approximating it");
    Test_Expect(LoopbackRadio_Refusals(&model) == 1, "as a refusal");

    Test_ExpectStatus(seam->ops->filter((Radio_Radio *)seam, 0), ZB_ERR_BAD_ARGUMENT, "and a null filter is refused");
}

/* The seam's mpdu is a complete frame, and what a radio is given depends on its own rule. */
static void caseTxTakesTheSeamContract(void)
{
    Loopback_Radio model;
    const Radio_Radio *seam;
    Radio_Caps withFcs = modelCaps(0x10d, 1, 0, 0);
    Radio_Caps withoutFcs = modelCaps(0xff, 0, 1, 1);
    Loopback_Sent sent[4];
    Radio_Handle handle = RADIO_HANDLE_NONE;
    uint32_t got;

    LoopbackRadio_Init(&model, &withFcs);
    seam = LoopbackRadio_Seam(&model);

    Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, 0, 5, 0, 0, &handle), ZB_ERR_BAD_ARGUMENT, "no frame, no transmit");
    Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 0, 0, 0, &handle), ZB_ERR_BAD_ARGUMENT,
                 "and no zero-length one");
    Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, ackMpdu, RADIO_MPDU_MAX + 1, 0, 0, &handle), ZB_ERR_BAD_ARGUMENT,
                 "nor one longer than the PHY's 127 octets");
    Test_Expect(handle == RADIO_HANDLE_NONE, "and a refused transmit issues no handle");

    Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, dataMpdu, (uint32_t)sizeof dataMpdu, 1, 0, &handle), ZB_OK,
                 "a complete data frame is accepted");
    Test_Expect(handle != RADIO_HANDLE_NONE, "with a handle that means something");

    got = LoopbackRadio_Sent(&model, sent, 4);
    Test_Expect(got == 1, "one transmit to read");
    Test_Expect(sent[0].len == 11 && Zb_memcmp(sent[0].bytes, dataMpdu, 11) == 0,
           "and this dialect is handed the frame octet for octet, footer included");
    Test_Expect(sent[0].ackRequest == 1, "with the acknowledgment band A asked for recorded beside it");

    LoopbackRadio_Init(&model, &withoutFcs);
    seam = LoopbackRadio_Seam(&model);
    Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, ackMpdu, (uint32_t)sizeof ackMpdu, 0, 0, &handle), ZB_OK,
                 "the same call on the other dialect rule");
    got = LoopbackRadio_Sent(&model, sent, 4);
    Test_Expect(got == 1 && sent[0].len == 3 && Zb_memcmp(sent[0].bytes, ackMpdu, 3) == 0,
           "and the footer is taken off for a radio that computes its own");

    Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 2, 0, 0, &handle), ZB_ERR_BAD_ARGUMENT,
                 "while a frame that is only its footer is refused before anything is issued");
    Test_Expect(LoopbackRadio_Sent(&model, sent, 4) == 1, "and nothing was added to what was sent");
}

static void caseOutcomesAndCompletion(void)
{
    Loopback_Radio model;
    const Radio_Radio *seam;
    Radio_Caps caps = modelCaps(0x10d, 1, 0, 1);
    Loopback_Outcome script[2];
    Radio_TxResult result;
    Radio_Handle handles[3];
    uint32_t i;

    LoopbackRadio_Init(&model, &caps);
    seam = LoopbackRadio_Seam(&model);

    Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, 0, &handles[0]), ZB_OK, "a transmit that asks");
    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handles[0], &result), ZB_OK,
                 "is answered without waiting, because the model answers it immediately");
    Test_Expect(result.status == ZB_OK && result.isAcked == 1 && result.retries == 0,
           "and a radio with ack metadata reports the acknowledgment it was asked for");

    Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 0, 0, &handles[1]), ZB_OK, "a transmit that asks for nothing");
    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handles[1], &result), ZB_OK, "answered");
    Test_Expect(result.isAcked == 0, "and nothing is claimed about an acknowledgment nobody requested");

    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handles[0], &result), ZB_ERR_BAD_ARGUMENT,
                 "collected once means collected");
    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, RADIO_HANDLE_NONE, &result), ZB_ERR_BAD_ARGUMENT,
                 "and handle 0 is no transmit at all");

    Zb_memset(script, 0, (uint32_t)sizeof script);
    script[0].status = ZB_ERR_DEVICE;
    script[0].isAcked = 0;
    script[0].retries = 3;
    script[1].status = ZB_OK;
    script[1].isAcked = 1;
    script[1].pendingPumps = 4;
    LoopbackRadio_ScriptOutcomes(&model, script, 2);

    Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, dataMpdu, 11, 1, 0, &handles[0]), ZB_OK, "the scripted order is issue order");
    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handles[0], &result), ZB_OK, "answered at once");
    Test_Expect(result.status == ZB_ERR_DEVICE && result.isAcked == 0 && result.retries == 3,
           "with the failure a band A retry policy needs to see, including a retry count no build here reports");

    Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, dataMpdu, 11, 1, 0, &handles[1]), ZB_OK, "the second transmit");

    for (i = 0; i < 3; i++)
    {
        Test_ExpectStatus(LoopbackRadio_Pump(&model, i + 1), ZB_OK, "pumping");
        Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handles[1], &result), ZB_ERR_NOT_READY,
                     "and no result yet, which is how band A reaches its own timeout decision");
    }

    Test_ExpectStatus(LoopbackRadio_Pump(&model, 4), ZB_OK, "the pump that was scripted to be the last");
    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handles[1], &result), ZB_OK, "then the answer arrives");
    Test_Expect(result.status == ZB_OK && result.isAcked == 1, "as scripted");

    /* Beyond the script the default resumes, which is what keeps a suite's scripts short. */
    Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, 0, &handles[2]), ZB_OK, "a third transmit, unscripted");
    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handles[2], &result), ZB_OK, "answered by the default");
    Test_Expect(result.isAcked == 1, "because it asked");

    /* The pool is bounded, and the suite says so rather than leaking. */
    for (i = 0; i < LOOPBACK_TX_MAX; i++)
    {
        Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 0, 0, &handles[0]), ZB_OK, "one more outstanding transmit");
        (void)handles;
    }

    Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 0, 0, &handles[1]), ZB_ERR_NO_SPACE,
                 "the last one beyond the pool is named, not dropped");
}

static void caseDelivery(void)
{
    Loopback_Radio model;
    const Radio_Radio *seam;
    Radio_Caps caps = modelCaps(0x10d, 1, 0, 0);
    Radio_Frame frames[LOOPBACK_RX_MAX + 2];
    Loopback_FrameSpec specs[3];
    uint8_t mutable0[5];
    uint8_t mutable1[3];
    uint8_t mutable2[4];
    uint32_t got;
    uint32_t i;

    LoopbackRadio_Init(&model, &caps);
    seam = LoopbackRadio_Seam(&model);

    Zb_memcpy(mutable0, ackMpdu, 5);
    mutable1[0] = 0x63;
    mutable1[1] = 0x88;
    mutable1[2] = 0x6f;
    mutable2[0] = 0x04;
    mutable2[1] = 0xe8;
    mutable2[2] = 0x29;
    mutable2[3] = 0x00;

    specs[0].len = 5;
    specs[0].bytes = mutable0;
    specs[0].rssiDbm = -94;
    specs[0].lqi = 255;
    specs[0].stampTicks = 3639678816;
    specs[0].error = ZB_OK;
    specs[1].len = 3;
    specs[1].bytes = mutable1;
    specs[1].rssiDbm = -88;
    specs[1].lqi = 252;
    specs[1].stampTicks = 3641003816;
    specs[1].error = ZB_OK;
    specs[2].len = 4;
    specs[2].bytes = mutable2;
    specs[2].rssiDbm = -76;
    specs[2].lqi = 0;
    specs[2].stampTicks = 3642338816;
    specs[2].error = ZB_ERR_BAD_FRAME;

    Test_ExpectStatus(LoopbackRadio_Inject(&model, specs, 3), ZB_OK, "three frames injected");
    Test_Expect(LoopbackRadio_Queued(&model) == 3, "waiting");

    mutable0[4] = 0x00;     /* the suite's own buffer, changed after injection */

    got = seam->ops->rxPoll((Radio_Radio *)seam, frames, 2);
    Test_Expect(got == 2, "a poll takes what was asked for and no more");
    Test_Expect(frames[0].len == 5 && Zb_memcmp(frames[0].bytes, ackMpdu, 5) == 0,
           "delivered as injected: the frame band A holds is its own copy, not a view of a suite's buffer");
    Test_Expect(frames[0].rssiDbm == -94 && frames[0].lqi == 255 && frames[0].deviceStampTicks == 3639678816,
           "with the metadata the injection carried, in the device's own tick unit");
    Test_Expect(frames[1].len == 3 && frames[1].bytes[2] == 0x6f, "in injection order");
    Test_Expect(LoopbackRadio_Queued(&model) == 1, "and one still waiting");

    got = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);
    Test_Expect(got == 1 && frames[0].error == ZB_ERR_BAD_FRAME,
           "a suspect frame is delivered with its reason attached rather than swallowed");
    Test_Expect(seam->ops->rxPoll((Radio_Radio *)seam, frames, 4) == 0, "and an empty model hands over nothing");
    Test_Expect(seam->ops->rxPoll((Radio_Radio *)seam, 0, 4) == 0, "refusing to write where it was not given a where");

    for (i = 0; i < LOOPBACK_RX_MAX; i++)
        Test_ExpectStatus(LoopbackRadio_Inject(&model, specs, 1), ZB_OK, "filling the delivery queue");

    Test_ExpectStatus(LoopbackRadio_Inject(&model, specs, 1), ZB_ERR_NO_SPACE,
                 "a full queue refuses the whole request rather than part of it");
    Test_Expect(LoopbackRadio_Queued(&model) == LOOPBACK_RX_MAX, "and holds what it already had");

    Test_ExpectStatus(LoopbackRadio_Inject(&model, specs, 0), ZB_ERR_BAD_ARGUMENT, "an injection of nothing is an argument error");
    specs[1].len = 0;
    Test_ExpectStatus(LoopbackRadio_Inject(&model, specs, 2), ZB_ERR_BAD_ARGUMENT,
                 "and so is a frame with no octets, halfway through a list that would otherwise fit");
    Test_Expect(LoopbackRadio_Queued(&model) == LOOPBACK_RX_MAX,
           "and the frames before it in that list were not queued either: a refusal is not half a delivery");
}

static void caseLostRadio(void)
{
    Loopback_Radio model;
    const Radio_Radio *seam;
    Radio_Caps caps = modelCaps(0x10d, 1, 1, 0);
    Radio_Pib pib;
    Radio_TxResult result;
    Radio_Handle handle = RADIO_HANDLE_NONE;

    LoopbackRadio_Init(&model, &caps);
    seam = LoopbackRadio_Seam(&model);

    Test_Expect(seam->ops->isLost((Radio_Radio *)seam) == 0, "a fresh model is not lost");
    Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 1, 0, &handle), ZB_OK, "a transmit is outstanding");

    LoopbackRadio_SetLost(&model, 1);
    Test_Expect(seam->ops->isLost((Radio_Radio *)seam) == 1, "the model can be told the radio went away");
    Test_ExpectStatus(seam->ops->tx((Radio_Radio *)seam, ackMpdu, 5, 0, 0, &handle), ZB_ERR_NOT_OPEN,
                 "and every call that needs a device says so instead of pretending");
    Test_ExpectStatus(seam->ops->pibGet((Radio_Radio *)seam, &pib), ZB_ERR_NOT_OPEN, "including a read");
    Test_ExpectStatus(seam->ops->scanStart((Radio_Radio *)seam, 11, 200), ZB_ERR_NOT_OPEN,
                 "and so is a dwell asked of a device that is gone");

    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handle, &result), ZB_OK,
                 "a transmit that was waiting for an answer gets one: the device is gone");
    Test_Expect(result.status == ZB_ERR_DEVICE_LOST && result.isAcked == 0,
           "which is the outcome band A re-arms against (§5)");

    LoopbackRadio_SetLost(&model, 0);
    Test_ExpectStatus(seam->ops->completion((Radio_Radio *)seam, handle, &result), ZB_ERR_BAD_ARGUMENT,
                 "clearing the fault does not resurrect the transmits it invalidated");
}

static void caseEnergyScan(void)
{
    Loopback_Radio model;
    const Radio_Radio *seam;
    Radio_Caps noScan = modelCaps(0x10d, 1, 0, 0);
    Radio_Caps withScan = modelCaps(0x10f, 1, 1, 0);
    int32_t script[3] = { -95, -80, -70 };
    uint32_t channel = 0;
    int32_t dbm = 0;

    LoopbackRadio_Init(&model, &noScan);
    seam = LoopbackRadio_Seam(&model);
    Test_ExpectStatus(seam->ops->scanStart((Radio_Radio *)seam, 11, 200), ZB_ERR_UNSUPPORTED,
                 "a model that declares no scan capability refuses rather than inventing numbers");
    Test_ExpectStatus(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm), ZB_ERR_UNSUPPORTED,
                 "and the second half of the pair refuses with it");

    LoopbackRadio_Init(&model, &withScan);
    seam = LoopbackRadio_Seam(&model);
    LoopbackRadio_ScriptEnergy(&model, script, 3);

    Test_ExpectStatus(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm), ZB_ERR_NOT_READY,
                 "nothing is collected before anything was asked for");
    Test_ExpectStatus(seam->ops->scanStart((Radio_Radio *)seam, 11, 200), ZB_OK,
                 "a dwell is issued, and the call returns before the dwell has measured anything");
    Test_ExpectStatus(seam->ops->scanStart((Radio_Radio *)seam, 12, 200), ZB_ERR_BUSY,
                 "a second dwell asked while one runs is refused rather than queued, which is what the device answers too");
    Test_ExpectStatus(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm), ZB_ERR_NOT_READY,
                 "and the level is not the return value of the call that asked for it");

    Test_ExpectStatus(LoopbackRadio_Pump(&model, 10), ZB_OK, "the link turns");
    Test_ExpectStatus(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm), ZB_OK,
                 "and the dwell reports its level at a later call");
    Test_Expect(channel == 11, "for the channel it was asked for");
    Test_Expect(dbm == -95, "at the level scripted for it");

    Test_ExpectStatus(seam->ops->scanStart((Radio_Radio *)seam, 13, 200), ZB_OK,
                 "the next channel may be asked once the first is collected: a band is a sequence of dwells");
    Test_ExpectStatus(LoopbackRadio_Pump(&model, 11), ZB_OK, "and it runs");
    Test_ExpectStatus(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm), ZB_OK, "and reports");
    Test_Expect(channel == 13 && dbm == -70,
           "the level scripted for the channel it was asked for, counting from the first channel of the script");

    Test_ExpectStatus(seam->ops->scanStart((Radio_Radio *)seam, 14, 200), ZB_OK, "one dwell further");
    Test_ExpectStatus(LoopbackRadio_Pump(&model, 12), ZB_OK, "and runs");
    Test_ExpectStatus(seam->ops->scanCollect((Radio_Radio *)seam, &channel, &dbm), ZB_OK, "and reports");
    Test_Expect(channel == 14 && dbm == RADIO_SCAN_NO_LEVEL,
           "with the figure a device reports when it measured nothing, because a script that ran out is not a licence to guess (docs/internals/protocol.md §7.4.1)");

    Test_ExpectStatus(seam->ops->scanStart((Radio_Radio *)seam, 27, 200), ZB_ERR_BAD_ARGUMENT,
                 "a channel outside the numbered set is refused");
    Test_ExpectStatus(seam->ops->scanStart((Radio_Radio *)seam, 10, 200), ZB_ERR_BAD_ARGUMENT,
                 "at both ends of it");
    Test_ExpectStatus(seam->ops->scanStart((Radio_Radio *)seam, 11, 0), ZB_ERR_BAD_ARGUMENT,
                 "and a dwell of no length is refused at the seam rather than answered with an empty measurement");
    Test_ExpectStatus(seam->ops->scanStart((Radio_Radio *)seam, 11, RADIO_SCAN_DWELL_MAX + 1), ZB_ERR_BAD_ARGUMENT,
                 "and so is a period past the bound the device states for its own dwell (§7.4.3)");
    Test_ExpectStatus(seam->ops->scanCollect((Radio_Radio *)seam, 0, &dbm), ZB_ERR_BAD_ARGUMENT,
                 "a collect with nowhere to put the answer is an argument error, not a silent read");
    Test_ExpectStatus(seam->ops->scanCollect((Radio_Radio *)seam, &channel, 0), ZB_ERR_BAD_ARGUMENT,
                 "on either half of the pair");
}

int main(void)
{
    Test_Begin("loopback_radio");

    caseCapsAndPib();
    caseFactoryAddressIsReportedNotWritten();
    caseFilter();
    caseTxTakesTheSeamContract();
    caseOutcomesAndCompletion();
    caseDelivery();
    caseLostRadio();
    caseEnergyScan();

    return Test_Report();
}
