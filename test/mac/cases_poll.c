/* The device's half of 10.22.3: MLME-POLL.request sends a Data Request to the coordinator, its acknowledgment's Frame
   Pending bit says whether anything is held, a one keeps the receiver on for the frame that follows, and
   MLME-POLL.confirm (10.22.5.3) says SUCCESS, NO_DATA or the transmit's failure. A device with macRxOnWhenIdle FALSE
   hears nothing outside that window unless its configuration keeps what a powered radio heard.

   The rig is a sleeping device at SLEEPY_SHORT whose parent is the coordinator at 0x0000; every frame from the parent
   is one this file injects. */

#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "mac_helpers.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

#define SLEEPY_SHORT 0x4321
#define SLEEPY_PAN 0xbeef
#define PARENT_SHORT 0x0000

static void sleepyRig(Test_BandA *dev, int hearsWhileAsleep)
{
    Test_BandAConfig cfg;

    Test_BandADefaults(&cfg);
    cfg.ownAddress = SLEEPY_SHORT;
    cfg.panId = SLEEPY_PAN;
    cfg.rxOnWhenIdle = 0;
    cfg.hearsWhileAsleep = hearsWhileAsleep;

    Test_ExpectStatus(Test_BandABuild(dev, &cfg), ZB_OK, "a device whose receiver rests is built");
}

static Mac_PollRequestParameters toParent(void)
{
    Mac_PollRequestParameters req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.coordAddrMode = MAC_ADDR_SHORT;
    req.coordPanId = SLEEPY_PAN;
    req.coordShort = PARENT_SHORT;

    return req;
}

static void scriptAck(Test_BandA *dev, ZbStatus status, int reported, int framePending, uint32_t pumps)
{
    Loopback_Outcome outcome;

    Zb_memset(&outcome, 0, (uint32_t)sizeof outcome);
    outcome.status = status;
    outcome.isAcked = status == ZB_OK;
    outcome.framePendingReported = reported;
    outcome.framePending = framePending;
    outcome.pendingPumps = pumps;
    LoopbackRadio_ScriptOutcomes(&dev->model, &outcome, 1);
}

/* A data frame from `src` to `dest` with `len` octets of payload and the Frame Pending bit given. */
static void injectData(Test_BandA *dev, uint16_t src, uint16_t dest, uint32_t len, int framePending, uint8_t seq)
{
    uint8_t bytes[RADIO_MPDU_MAX];
    uint8_t content[2] = { 0x5a, 0xa5 };
    Mac_Frame frame;
    uint32_t mpduLen;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_DATA;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.destPan = SLEEPY_PAN;
    frame.destShort = dest;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.panIdCompression = 1;
    frame.srcShort = src;
    frame.framePending = framePending;
    frame.seq = seq;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, len, bytes, RADIO_MPDU_MAX, &mpduLen), ZB_OK,
                      "a data frame composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, mpduLen, RADIO_MPDU_MAX, &mpduLen), ZB_OK, "with its footer");
    injectFrame(&dev->model, bytes, mpduLen, 100 + seq);
}

static uint32_t takeIndications(Test_BandA *dev)
{
    Mac_DataIndicationParameters indications[8];

    return Mac_PollIndications(&dev->mac, indications, 8);
}

void casePollAckWithoutPendingIsNoData(void)
{
    Test_BandA dev;
    Mac_PollRequestParameters req = toParent();
    Mac_PollConfirmParameters confirm;
    Loopback_Sent *sent;

    sleepyRig(&dev, 0);
    scriptAck(&dev, ZB_OK, 1, 0, 0);

    Test_ExpectStatus(Mac_PollRequest(&dev.mac, &req, 100), ZB_OK, "MLME-POLL.request is taken");
    sent = &dev.model.sent[0];
    Test_Expect(sent->handle != RADIO_HANDLE_NONE && sent->ackRequest == 1 && sent->bytes[9] == MAC_CMD_POLL,
                "and a Data Request goes to the parent asking to be acknowledged (10.22.4.1)");
    Test_Expect(Mac_Hears(&dev.mac), "the receiver is on from the moment the poll is sent");

    Test_ExpectStatus(Mac_Step(&dev.mac, 101), ZB_OK, "stepped");
    Test_Expect(Mac_PollRequestConfirm(&dev.mac, &confirm) == 1 && confirm.status == ZB_ERR_NO_DATA,
                "an Ack with Frame Pending zero is NO_DATA at once (10.22.5.3)");
    Test_Expect(!Mac_Hears(&dev.mac), "and the receiver rests again without a window");
    Test_Expect(Mac_PollRequestConfirm(&dev.mac, &confirm) == 0, "the confirm is taken once");

    injectData(&dev, PARENT_SHORT, SLEEPY_SHORT, 2, 0, 1);
    Test_ExpectStatus(Mac_Step(&dev.mac, 150), ZB_OK, "a frame arrives between polls");
    Test_Expect(takeIndications(&dev) == 0 && Mac_CountersOf(&dev.mac).heardAsleep == 1,
                "and is discarded and counted, as a sleeping radio never heard it");
    Test_Expect(Mac_CountersOf(&dev.mac).pollsRequested == 1 && Mac_CountersOf(&dev.mac).pollsNoData == 1,
                "one poll asked, one that found nothing");
}

void casePollWithPendingDeliversTheFrame(void)
{
    Test_BandA dev;
    Mac_PollRequestParameters req = toParent();
    Mac_PollConfirmParameters confirm;

    sleepyRig(&dev, 0);
    scriptAck(&dev, ZB_OK, 1, 1, 0);

    Test_ExpectStatus(Mac_PollRequest(&dev.mac, &req, 100), ZB_OK, "a poll");
    Test_ExpectStatus(Mac_Step(&dev.mac, 101), ZB_OK, "whose Ack said pending");
    Test_Expect(Mac_PollRequestConfirm(&dev.mac, &confirm) == 0 && Mac_Hears(&dev.mac),
                "so the receiver stays on and nothing is confirmed yet");

    injectData(&dev, PARENT_SHORT, 0xffff, 2, 0, 1);
    Test_ExpectStatus(Mac_Step(&dev.mac, 110), ZB_OK, "the parent's own broadcast arrives in the window");
    Test_Expect(takeIndications(&dev) == 1 && Mac_PollRequestConfirm(&dev.mac, &confirm) == 0,
                "heard, and not the frame the poll asked for");

    injectData(&dev, PARENT_SHORT, SLEEPY_SHORT, 2, 1, 2);
    Test_ExpectStatus(Mac_Step(&dev.mac, 120), ZB_OK, "the held frame arrives");
    Test_Expect(takeIndications(&dev) == 1, "and is delivered");
    Test_Expect(Mac_PollRequestConfirm(&dev.mac, &confirm) == 1 && confirm.status == ZB_OK && confirm.framePending == 1,
                "SUCCESS, with the frame's own Frame Pending saying more is held (10.22.3)");
    Test_Expect(!Mac_Hears(&dev.mac) && Mac_CountersOf(&dev.mac).pollsWithData == 1, "and the window closed");
}

void casePollWindowEndsWithNoData(void)
{
    Test_BandA dev;
    Mac_PollRequestParameters req = toParent();
    Mac_PollConfirmParameters confirm;

    sleepyRig(&dev, 0);
    scriptAck(&dev, ZB_OK, 1, 1, 0);

    Test_ExpectStatus(Mac_PollRequest(&dev.mac, &req, 100), ZB_OK, "a poll");
    Test_ExpectStatus(Mac_Step(&dev.mac, 101), ZB_OK, "whose Ack said pending");
    Test_ExpectStatus(Mac_Step(&dev.mac, 100 + MAC_POLL_WAIT_MS), ZB_OK, "the window's last millisecond");
    Test_Expect(Mac_PollRequestConfirm(&dev.mac, &confirm) == 0, "still open");
    Test_ExpectStatus(Mac_Step(&dev.mac, 101 + MAC_POLL_WAIT_MS), ZB_OK, "MAC_POLL_WAIT_MS after the Ack");
    Test_Expect(Mac_PollRequestConfirm(&dev.mac, &confirm) == 1 && confirm.status == ZB_ERR_NO_DATA,
                "no frame at the expected time is NO_DATA (10.22.5.3)");
}

void casePollEmptyAnswerIsNoData(void)
{
    Test_BandA dev;
    Mac_PollRequestParameters req = toParent();
    Mac_PollConfirmParameters confirm;

    sleepyRig(&dev, 0);
    scriptAck(&dev, ZB_OK, 1, 1, 0);

    Test_ExpectStatus(Mac_PollRequest(&dev.mac, &req, 100), ZB_OK, "a poll");
    Test_ExpectStatus(Mac_Step(&dev.mac, 101), ZB_OK, "whose Ack said pending");
    injectData(&dev, PARENT_SHORT, SLEEPY_SHORT, 0, 0, 1);
    Test_ExpectStatus(Mac_Step(&dev.mac, 110), ZB_OK, "the parent answers with a zero-length payload");
    Test_Expect(Mac_PollRequestConfirm(&dev.mac, &confirm) == 1 && confirm.status == ZB_ERR_NO_DATA,
                "which is NO_DATA (10.22.3)");
}

void casePollWithoutAReportedBitListens(void)
{
    Test_BandA dev;
    Mac_PollRequestParameters req = toParent();
    Mac_PollConfirmParameters confirm;

    sleepyRig(&dev, 0);
    scriptAck(&dev, ZB_OK, 0, 0, 0);

    Test_ExpectStatus(Mac_PollRequest(&dev.mac, &req, 100), ZB_OK, "a poll");
    Test_ExpectStatus(Mac_Step(&dev.mac, 101), ZB_OK, "whose completion stated no Frame Pending bit");
    Test_Expect(Mac_PollRequestConfirm(&dev.mac, &confirm) == 0 && Mac_Hears(&dev.mac),
                "is read as no answer, so the window opens");
    injectData(&dev, PARENT_SHORT, SLEEPY_SHORT, 2, 0, 1);
    Test_ExpectStatus(Mac_Step(&dev.mac, 110), ZB_OK, "the held frame arrives");
    Test_Expect(Mac_PollRequestConfirm(&dev.mac, &confirm) == 1 && confirm.status == ZB_OK, "SUCCESS");
}

void casePollAnswerBeforeItsCompletion(void)
{
    Test_BandA dev;
    Mac_PollRequestParameters req = toParent();
    Mac_PollConfirmParameters confirm;

    sleepyRig(&dev, 0);
    scriptAck(&dev, ZB_OK, 1, 1, 2);

    Test_ExpectStatus(Mac_PollRequest(&dev.mac, &req, 100), ZB_OK, "a poll whose completion is slow to arrive");
    injectData(&dev, PARENT_SHORT, SLEEPY_SHORT, 2, 0, 1);
    Test_ExpectStatus(Mac_Step(&dev.mac, 105), ZB_OK, "the held frame comes first");
    Test_Expect(takeIndications(&dev) == 1, "and is heard, the window being open since the Data Request left");
    Test_Expect(Mac_PollRequestConfirm(&dev.mac, &confirm) == 1 && confirm.status == ZB_OK, "SUCCESS");

    LoopbackRadio_Pump(&dev.model, 106);
    LoopbackRadio_Pump(&dev.model, 107);
    Test_ExpectStatus(Mac_Step(&dev.mac, 108), ZB_OK, "the completion arrives late");
    Test_Expect(Mac_PollRequestConfirm(&dev.mac, &confirm) == 0 && !Mac_Hears(&dev.mac),
                "and changes nothing: the poll already ended");
}

void casePollNotAcknowledged(void)
{
    Test_BandA dev;
    Mac_PollRequestParameters req = toParent();
    Mac_PollConfirmParameters confirm;

    sleepyRig(&dev, 0);
    scriptAck(&dev, ZB_ERR_NO_ACK, 0, 0, 0);

    Test_ExpectStatus(Mac_PollRequest(&dev.mac, &req, 100), ZB_OK, "a poll");
    Test_ExpectStatus(Mac_PollRequest(&dev.mac, &req, 100), ZB_ERR_BUSY, "and a second while it is out is refused");
    Test_ExpectStatus(Mac_Step(&dev.mac, 101), ZB_OK, "never acknowledged");
    Test_Expect(Mac_PollRequestConfirm(&dev.mac, &confirm) == 1 && confirm.status == ZB_ERR_NO_ACK,
                "MLME-POLL.confirm carries NO_ACK (8.2.2)");
    Test_Expect(!Mac_Hears(&dev.mac), "and no window opens");
}

void casePollHearsWhatTheConfigurationKeeps(void)
{
    Test_BandA dev;

    sleepyRig(&dev, 1);
    Test_Expect(Mac_Hears(&dev.mac), "a sleeping device configured to keep what it hears hears between polls");
    injectData(&dev, PARENT_SHORT, SLEEPY_SHORT, 2, 0, 1);
    Test_ExpectStatus(Mac_Step(&dev.mac, 100), ZB_OK, "a frame arrives with no poll out");
    Test_Expect(takeIndications(&dev) == 1 && Mac_CountersOf(&dev.mac).heardAsleep == 0, "and is delivered");

    rig(&dev, SLEEPY_SHORT, SLEEPY_PAN);
    Test_Expect(Mac_Hears(&dev.mac), "and a device whose receiver is on when idle always hears");
}

void casePollLeavesAnotherDataRequestsWindowOpen(void)
{
    Test_BandA dev;
    Mac_PollRequestParameters req = toParent();
    Mac_PollConfirmParameters confirm;
    Mac_DataRequestParameters other;
    Loopback_Outcome outcomes[2];
    uint8_t command[1] = { MAC_CMD_POLL };

    sleepyRig(&dev, 0);
    Zb_memset(outcomes, 0, (uint32_t)sizeof outcomes);
    outcomes[0].status = ZB_OK;
    outcomes[0].isAcked = 1;
    outcomes[0].framePendingReported = 1;
    outcomes[0].framePending = 1;
    outcomes[1] = outcomes[0];
    LoopbackRadio_ScriptOutcomes(&dev.model, outcomes, 2);

    Zb_memset(&other, 0, (uint32_t)sizeof other);
    other.frameType = MAC_FRAME_TYPE_COMMAND;
    other.destAddrMode = MAC_ADDR_SHORT;
    other.srcAddrMode = MAC_ADDR_SHORT;
    other.destPan = SLEEPY_PAN;
    other.destShort = PARENT_SHORT;
    other.ackRequest = 1;
    other.payload = command;
    other.payloadLen = 1;

    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &other, 100, 0), ZB_OK, "a Data Request the layer above composed");
    Test_ExpectStatus(Mac_PollRequest(&dev.mac, &req, 100), ZB_OK, "and MLME-POLL's beside it");
    Test_ExpectStatus(Mac_Step(&dev.mac, 101), ZB_OK, "both Acks say pending");

    injectData(&dev, PARENT_SHORT, SLEEPY_SHORT, 2, 0, 1);
    Test_ExpectStatus(Mac_Step(&dev.mac, 110), ZB_OK, "one held frame");
    Test_Expect(Mac_PollRequestConfirm(&dev.mac, &confirm) == 1 && confirm.status == ZB_OK,
                "answers MLME-POLL first");
    Test_Expect(Mac_Hears(&dev.mac), "and the other request's window is still open");

    injectData(&dev, PARENT_SHORT, SLEEPY_SHORT, 2, 0, 2);
    Test_ExpectStatus(Mac_Step(&dev.mac, 120), ZB_OK, "the second");
    Test_Expect(takeIndications(&dev) == 2 && !Mac_Hears(&dev.mac), "is heard too, and closes it");
}
