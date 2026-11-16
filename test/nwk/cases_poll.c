/* A resting end device's polls: 2.5.4.5.5.2's :Config_NWK_indirectPollRate once joined, 3.6.1.15's 250 ms while it
   attaches, 10.22.3's poll again when a frame says more is held, NLME-SYNC with 3.2.2.24.3's additional retries, and
   2.5.4.5.5.1's failed request reported to the parent link. The rig is a joined end device at SLEEPY_SHORT whose
   parent is the coordinator; the MAC keeps nothing between polls, as a sleeping radio would not. */

#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "nwk.h"
#include "nwk_cases.h"
#include "nwk_status.h"
#include "nwk_helpers.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

#define SLEEPY_SHORT 0x5a5a
#define SLEEPY_PARENT 0x0000

static void sleepyChild(Test_BandA *dev, int rxOnWhenIdle)
{
    Test_BandAConfig cfg;

    Test_BandADefaults(&cfg);
    cfg.ownAddress = SLEEPY_SHORT;
    cfg.panId = PAN_ID;
    cfg.deviceType = NWK_DEVICE_END_DEVICE;
    cfg.rxOnWhenIdle = rxOnWhenIdle;
    cfg.hearsWhileAsleep = 0;

    Test_ExpectStatus(Test_BandABuild(dev, &cfg), ZB_OK, "a joined end device is built");
    dev->nwk.joinParentShort = SLEEPY_PARENT;
    dev->nwk.joinParentShortKnown = 1;
    Test_ExpectCount(Nwk_JoinStateOf(&dev->nwk), NWK_JOIN_JOINED, "on the network, its own address being known");
}

static void scriptPoll(Test_BandA *dev, ZbStatus status, int framePending)
{
    Loopback_Outcome outcome;

    Zb_memset(&outcome, 0, (uint32_t)sizeof outcome);
    outcome.status = status;
    outcome.isAcked = status == ZB_OK;
    outcome.framePendingReported = 1;
    outcome.framePending = framePending;
    LoopbackRadio_ScriptOutcomes(&dev->model, &outcome, 1);
}

/* The parent's held frame: a MAC data frame to the child whose own Frame Pending bit says whether more waits. */
static void injectHeld(Test_BandA *dev, int framePending)
{
    uint8_t npdu[RADIO_MPDU_MAX];
    uint8_t bytes[RADIO_MPDU_MAX];
    uint8_t what[1] = { 0x42 };
    Loopback_FrameSpec spec;
    Mac_Frame frame;
    uint32_t npduLen;
    uint32_t len;

    npduLen = makeNpdu(npdu, SLEEPY_SHORT, SLEEPY_PARENT, 1, 1, NWK_FRAME_TYPE_DATA, 0, what, 1);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_DATA;
    frame.panIdCompression = 1;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.destPan = PAN_ID;
    frame.destShort = SLEEPY_SHORT;
    frame.srcShort = SLEEPY_PARENT;
    frame.framePending = framePending;

    Test_ExpectStatus(MacFrame_Compose(&frame, npdu, npduLen, bytes, RADIO_MPDU_MAX, &len), ZB_OK, "composed");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK, "with its footer");

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = len;
    spec.bytes = bytes;
    spec.lqi = 200;
    Test_ExpectStatus(LoopbackRadio_Inject(&dev->model, &spec, 1), ZB_OK, "the held frame arrives");
}

/* A host steps every few milliseconds; these cases step every 10 up to `untilMs`, its last step being on it. */
static void stepUntil(Test_BandA *dev, uint32_t *nowMs, uint32_t untilMs)
{
    while (*nowMs < untilMs)
    {
        *nowMs = *nowMs + 10 <= untilMs ? *nowMs + 10 : untilMs;
        Test_ExpectStatus(Test_NwkStep(&dev->nwk, *nowMs), ZB_OK, "stepped");
    }
}

void caseSleepyChildPollsAtItsRate(void)
{
    Test_BandA dev;
    uint32_t t = 1000;

    sleepyChild(&dev, 0);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, t), ZB_OK, "the first turn");
    Test_ExpectCount(Nwk_PollsSent(&dev.nwk), 1, "polls the parent at once");
    stepUntil(&dev, &t, 1500);
    Test_ExpectCount(Mac_CountersOf(&dev.mac).pollsNoData, 1, "and its NO_DATA is taken: the parent held nothing");

    stepUntil(&dev, &t, 990 + NWK_POLL_RATE_DEFAULT_MS);
    Test_ExpectCount(Nwk_PollsSent(&dev.nwk), 1, "no poll inside the rate");
    stepUntil(&dev, &t, 1000 + NWK_POLL_RATE_DEFAULT_MS);
    Test_ExpectCount(Nwk_PollsSent(&dev.nwk), 2, "the next at :Config_NWK_indirectPollRate (2.5.4.5.5.2)");

    Nwk_SetPollRate(&dev.nwk, 1000);
    stepUntil(&dev, &t, 2000 + NWK_POLL_RATE_DEFAULT_MS);
    Test_ExpectCount(Nwk_PollsSent(&dev.nwk), 3, "and at the rate the application set");
    Test_ExpectCount(Nwk_ParentLinkHeld(&dev.nwk), 2, "each acknowledged poll holding the parent link");
}

void caseSleepyChildPollsFastWhileAttaching(void)
{
    Test_BandA dev;
    uint32_t t = 1000;

    sleepyChild(&dev, 0);
    Nwk_SetPollFast(&dev.nwk, 1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, t), ZB_OK, "a child the layer above is attaching");
    stepUntil(&dev, &t, 990 + NWK_POLL_ATTACH_MS);
    Test_ExpectCount(Nwk_PollsSent(&dev.nwk), 1, "one poll inside 250 ms");
    stepUntil(&dev, &t, 1000 + NWK_POLL_ATTACH_MS);
    Test_ExpectCount(Nwk_PollsSent(&dev.nwk), 2, "the next at 250 ms, as 3.6.1.15 asks");

    Nwk_SetPollFast(&dev.nwk, 0);
    stepUntil(&dev, &t, 1000 + 4 * NWK_POLL_ATTACH_MS);
    Test_ExpectCount(Nwk_PollsSent(&dev.nwk), 2, "and back to the normal rate once attached");
}

void caseSleepyChildPollsAgainWhenMoreIsHeld(void)
{
    Test_BandA dev;

    sleepyChild(&dev, 0);
    scriptPoll(&dev, ZB_OK, 1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1000), ZB_OK, "a poll whose Ack says pending");
    injectHeld(&dev, 1);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1010), ZB_OK, "the held frame comes, saying more is held");
    Test_ExpectCount(Mac_CountersOf(&dev.mac).pollsWithData, 1, "delivered");
    Test_ExpectCount(Nwk_PollsSent(&dev.nwk), 2, "and the child polls again at once (10.22.3)");
}

void caseSyncRetriesOnChannelAccessFailure(void)
{
    Test_BandA dev;
    Nwk_SyncConfirmParameters confirm;
    Loopback_Outcome outcomes[4];
    uint32_t i;
    uint32_t t = 1000;

    sleepyChild(&dev, 1);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, t), ZB_OK, "a child whose receiver is on");
    Test_ExpectCount(Nwk_PollsSent(&dev.nwk), 0, "has no schedule to keep");

    Zb_memset(outcomes, 0, (uint32_t)sizeof outcomes);

    for (i = 0; i < 4; i++)
        outcomes[i].status = ZB_ERR_CHANNEL_ACCESS_FAILURE;

    LoopbackRadio_ScriptOutcomes(&dev.model, outcomes, 4);

    Test_ExpectStatus(Nwk_SyncRequest(&dev.nwk), ZB_OK, "NLME-SYNC.request is taken");
    Test_ExpectStatus(Nwk_SyncRequest(&dev.nwk), ZB_ERR_BUSY, "and a second waits for the first");

    for (i = 0; i < 8; i++)
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, ++t), ZB_OK, "stepped");

    Test_ExpectCount(Nwk_PollsSent(&dev.nwk), 1 + NWK_POLL_ADDITIONAL_RETRIES,
                     "the poll and its additional retries (3.2.2.24.3)");
    Test_Expect(Nwk_PollSyncConfirm(&dev.nwk, &confirm) == 1 && confirm.status == ZB_ERR_CHANNEL_ACCESS_FAILURE,
                "then NLME-SYNC.confirm with the last MLME-POLL.confirm's status");

    Test_ExpectStatus(Nwk_SyncRequest(&dev.nwk), ZB_OK, "another, acknowledged with nothing held");
    stepUntil(&dev, &t, t + 2 * MAC_POLL_WAIT_MS);
    Test_Expect(Nwk_PollSyncConfirm(&dev.nwk, &confirm) == 1 && confirm.status == ZB_ERR_NO_DATA,
                "NO_DATA, MLME-POLL.confirm's own (Table 3-31)");
}

void caseSleepyChildReportsAnUnansweredPoll(void)
{
    Test_BandA dev;
    Nwk_NwkStatusIndication status;

    sleepyChild(&dev, 0);
    scriptPoll(&dev, ZB_ERR_NO_ACK, 0);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1000), ZB_OK, "a poll the parent never acknowledges");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1001), ZB_OK, "its NO_ACK is taken");
    Test_ExpectCount(Nwk_ParentLinkFailures(&dev.nwk), 1, "a failed indirect request (2.5.4.5.5.1)");
    Test_Expect(Nwk_PollStatusIndications(&dev.nwk, &status, 1) == 1
                    && status.status == NWK_STATUS_CODE_PARENT_LINK_FAILURE && status.shortAddr == SLEEPY_PARENT,
                "told to the layer above as a parent link failure, which counts toward the rejoin");
}

void caseSyncRefusedOffANetwork(void)
{
    Test_BandA dev;

    rig(&dev, 0x0001, PAN_ID);
    Test_ExpectStatus(Nwk_SyncRequest(&dev.nwk), ZB_ERR_BAD_STATE, "a router has no parent to poll");
}
