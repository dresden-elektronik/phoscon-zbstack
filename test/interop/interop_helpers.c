/* The `interop` suite's shared machinery: the bodies. See `interop_helpers.h` for what this file is and why
   it is here. */

#include "aps.h"
#include "fixtures_frames.h"
#include "interop_helpers.h"
#include "loopback_radio.h"
#include "mac.h"
#include "nwk.h"
#include "radio.h"
#include "rig_band_a.h"
#include "security.h"
#include "test_harness.h"
#include "zb_utils.h"

Capture s_primary;
Capture s_secondary;

/*
 * One capture, read by the shared loader (test/support/fixtures_frames.h): every annotated line of the fixture
 * is read as what it is (a PSDU where harness/check_samples.py's PSDU_LINE has one, an annotation otherwise)
 * into this suite's own fixed-width table. The three assertions are the three things this suite expects of the
 * file: it opened, nothing in it ran past the pool, and it held the number of frames the inventory pins. What
 * is left of the reading here is the table's shape: `len[]` per row, because the drive injects each frame with
 * its own length and not a stride.
 */
void loadCapture(const char *path, Capture *cap, uint32_t wanted, const char *what)
{
    ZbStatus status;

    Zb_memset(cap, 0, (uint32_t)sizeof *cap);

    status = Test_FixtureLoad(path, &cap->bytes[0][0], cap->len, CAPTURE_MAX, RADIO_MPDU_MAX, wanted,
                              &cap->count);

    Test_Expect(status != ZB_ERR_NOT_OPEN, "the fixture opens for reading");

    if (status == ZB_ERR_NOT_OPEN)
        return;

    Test_Expect(status != ZB_ERR_NO_SPACE, "no fixture line runs past the capture pool");
    Test_ExpectCount(cap->count, wanted, what);
}

ZbStatus denyCaps(Radio_Radio *radio, Radio_Caps *outCaps)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->caps(self->backend, outCaps);
}

ZbStatus denyPibSet(Radio_Radio *radio, const Radio_Pib *pib)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->pibSet(self->backend, pib);
}

ZbStatus denyPibGet(Radio_Radio *radio, Radio_Pib *pib)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->pibGet(self->backend, pib);
}

ZbStatus denyFilter(Radio_Radio *radio, const Radio_Filter *filter)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->filter(self->backend, filter);
}

ZbStatus denyCompletion(Radio_Radio *radio, Radio_Handle handle, Radio_TxResult *outResult)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->completion(self->backend, handle, outResult);
}

uint32_t denyRxPoll(Radio_Radio *radio, Radio_Frame *outFrames, uint32_t maxFrames)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->rxPoll(self->backend, outFrames, maxFrames);
}

int denyIsLost(Radio_Radio *radio)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->isLost(self->backend);
}

ZbStatus denyScanStart(Radio_Radio *radio, uint32_t channel, uint32_t dwellUnits)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->scanStart(self->backend, channel, dwellUnits);
}

ZbStatus denyScanCollect(Radio_Radio *radio, uint32_t *outChannel, int32_t *outDbm)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->scanCollect(self->backend, outChannel, outDbm);
}

/* The one seam call the shim does not forward. No handle is handed back: the shim named the refusal. */
ZbStatus denyTx(Radio_Radio *radio, const uint8_t *mpdu, uint32_t len, int ackRequest,
                uint32_t maxFrameRetries, Radio_Handle *outHandle)
{
    DenyTx *self = (DenyTx *)radio->provider;

    (void)mpdu;
    (void)len;
    (void)ackRequest;
    (void)maxFrameRetries;
    (void)outHandle;

    self->txRefusals++;

    return ZB_ERR_UNSUPPORTED;
}

static const Radio_Ops s_denyOps =
{
    denyCaps,
    denyPibSet,
    denyPibGet,
    denyFilter,
    denyTx,
    denyCompletion,
    denyRxPoll,
    denyIsLost,
    denyScanStart,
    denyScanCollect
    , 0    /* no pending table: this backend states 10.22.3's bit itself or not at all */
};

/* The device's PIB, written through the seam: this device's address, the captured PAN, channel 15 and a
   listener's receiver duty (the passive arm). */
void bringMacUp(Mac_Mac *mac, uint16_t ownShort)
{
    Radio_Pib pib;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_SHORT_ADDRESS | RADIO_PIB_PAN_ID | RADIO_PIB_CHANNEL | RADIO_PIB_RX_ON_WHEN_IDLE;
    pib.shortAddress = ownShort;
    pib.panId = PAN_ID;
    pib.channel = CHANNEL;
    pib.rxOnWhenIdle = 1;     /* the passive arm: a passive sniffer listens, and Table 3-80's 0xfffd class is stated as that attribute */

    Test_ExpectStatus(Mac_SetPib(mac, &pib), ZB_OK, "the MAC is brought up with this device's address, PAN, channel and receiver duty");
}

/*
 * The band-A device, built from scratch. `keyOctet` and `keySeq` name the security config the leg
 * needs; `wantSecurity` 0 is the scaffold (no key attached, no crossing run), and `wantDeny` 1
 * wraps the seam in the shim.
 *
 * Why this suite assembles its own device instead of taking `Test_BandABuild`, which every other band-A suite
 * builds on. Two of this rig's facts are not a rig constructor's to name: the seam band A is handed is the
 * deny-tx shim and not the model's own, and this device is the captured network's, channel 15, PAN 0xde20, a
 * sniffer's `psduIncludesFcs` dialect (docs/internals/protocol.md §9.3), where the rig arms channel 26. A suite whose
 * scaffolding *is* its subject keeps its own assembly. What it does take from the shared
 * rig is the capability report: the ConBee II's dialect facts as capabilities (a delivered PSDU still carries
 * its own FCS, and the radio reports the acknowledgment timeout it ran), which is the same 0x10d shape both
 * RCPs report (docs/internals/hardware.md §4).
 */
void rigBuild(Rig *rig, uint16_t ownShort, int wantSecurity, uint8_t keyOctet, uint8_t keySeq,
              int wantDeny)
{
    Radio_Caps caps;
    Nwk_Config nwkCfg;
    Security_Config secCfg;
    Security_KeyDescriptor descriptor;
    Radio_Radio *seam;

    Test_BandACapsAcks(&caps);
    Zb_memset(rig, 0, (uint32_t)sizeof *rig);

    Test_ExpectStatus(LoopbackRadio_Init(&rig->model, &caps), ZB_OK, "the rig's backend is the hardware-free model band A's suites run against");

    if (wantDeny)
    {
        rig->deny.backend = LoopbackRadio_Seam(&rig->model);
        rig->deny.txRefusals = 0;
        rig->deny.seam.ops = &s_denyOps;
        rig->deny.seam.provider = &rig->deny;
        rig->shimmied = 1;
        seam = &rig->deny.seam;
    }
    else
        seam = LoopbackRadio_Seam(&rig->model);

    Test_ExpectStatus(Mac_Init(&rig->mac, seam, 0), ZB_OK, "a MAC on that seam, its own DSN seeded 0 (the seed is the application's, 0 is the deterministic one)");
    bringMacUp(&rig->mac, ownShort);
    Test_ExpectStatus(Mac_SetPromiscuousMode(&rig->mac, 1), ZB_OK,
                      "10.23.1's macPromiscuousMode is TRUE: this rig replays a promiscuous capture as the listener that made it");

    if (wantSecurity)
    {
        Zb_memset(&descriptor, 0, (uint32_t)sizeof descriptor);
        descriptor.keySeqNumber = keySeq;
        descriptor.inUse = 1;
        descriptor.outgoingFrameCounter = KEY_OUTGOING_START;
        Zb_memset(descriptor.key, keyOctet, (uint32_t)sizeof descriptor.key);

        Zb_memset(&secCfg, 0, (uint32_t)sizeof secCfg);
        secCfg.ownIeee = OWN_IEEE;
        secCfg.nwkSecurityLevel = KEY_LEVEL;
        secCfg.nwkActiveKeySeqNumber = keySeq;
        secCfg.authenticated = 1;             /* this device is a member of the network it is reading */
        secCfg.nwkAllFresh = 1;                  /* nwkAllFresh's printed default (Table 4-2) */
        secCfg.keys = &descriptor;
        secCfg.keyCount = 1;

        Test_ExpectStatus(Security_Init(&rig->security, &secCfg), ZB_OK, "the network key arrives as application config and nowhere else");
    }

    Zb_memset(&nwkCfg, 0, (uint32_t)sizeof nwkCfg);
    nwkCfg.deviceType = NWK_DEVICE_COORDINATOR;
    nwkCfg.seqStart = 0;
    nwkCfg.jitterSeed = 0;                    /* a config that names no entropy draws none */

    Test_ExpectStatus(Nwk_Init(&rig->nwk, &rig->mac, &nwkCfg), ZB_OK, "the network layer on that MAC");

    if (wantSecurity)
    {
        Nwk_AttachSecurity(&rig->nwk, &rig->security);
        rig->secured = 1;
        Test_Expect(rig->nwk.security == &rig->security, "adopted by pointer, the key state staying the application's");
    }

    Test_ExpectStatus(Aps_Init(&rig->aps, &rig->nwk), ZB_OK, "and the APS data service on that, empty group table and all (Table 2-24's 'Null set')");
}

/* What the rig was told, read back before any frame is driven through it. */
void rigAssert(const Rig *rig, uint16_t ownShort)
{
    const Radio_Pib *pib = Mac_Pib(&rig->mac);

    Test_Expect((pib->present & RADIO_PIB_SHORT_ADDRESS) != 0 && pib->shortAddress == ownShort,
          "this device's short address is the one the replay pins");
    Test_Expect((pib->present & RADIO_PIB_PAN_ID) != 0 && pib->panId == PAN_ID, "on this PAN");
    Test_Expect(pib->rxOnWhenIdle == 1, "with its receiver on");
    Test_Expect(rig->nwk.cfg.deviceType == NWK_DEVICE_COORDINATOR, "as a coordinator (3.6.2.2, 3.6.6)");
    Test_Expect(rig->nwk.jitterState == 0, "and with no jitter seed");
    Test_Expect(rig->aps.groups[0].inUse == 0, "holding no group membership");

    if (rig->secured)
    {
        Test_Expect(Security_IsAuthenticated(&rig->security) == 1, "joined and authenticated, which is what 3.6.2.2's unsecured policy reads");
        Test_Expect(Security_Level(&rig->security) == KEY_LEVEL, "at the network's own security level");
        Test_Expect(Security_IsEnabled(&rig->security) == 1, "so the crossing runs");
    }
}

void driveReset(Driven *out)
{
    Zb_memset(out, 0, (uint32_t)sizeof *out);
}

/*
 * The inventory's drive, exactly: inject at most RADIO_FRAME_BATCH_MAX captured PSDUs verbatim (FCS tail included, no
 * re-framing by the suite) in capture order, one `Aps_Step` per batch with the clock advanced 1 ms per frame (a slow
 * clock: no broadcast record ever ages out and no scheduled second retransmission is ever due), and every ring drained
 * after every step, because an un-drained ring changes what fits and so changes the ledger.
 */
void driveReplay(Rig *rig, const Capture *cap, Driven *out)
{
    Loopback_FrameSpec specs[RADIO_FRAME_BATCH_MAX];
    Mac_PollArrival polls[MAC_POLL_EVENT_MAX];
    Aps_Indication indications[APS_INDICATION_MAX];
    Aps_Confirm confirms[APS_CONFIRM_MAX];
    uint32_t nowMs;
    uint32_t taken;
    uint32_t batch;
    uint32_t i;
    uint32_t j;
    ZbStatus status;

    nowMs = 0;
    i = 0;

    while (i < cap->count)
    {
        batch = cap->count - i;

        if (batch > RADIO_FRAME_BATCH_MAX)
            batch = RADIO_FRAME_BATCH_MAX;

        for (j = 0; j < batch; j++)
        {
            Zb_memset(&specs[j], 0, (uint32_t)sizeof specs[j]);
            specs[j].len = cap->len[i + j];
            specs[j].bytes = cap->bytes[i + j];
            specs[j].rssiDbm = FIXTURE_RSSI_DBM;
            specs[j].lqi = FIXTURE_LQI;
            specs[j].stampTicks = (uint64_t)(FIXTURE_STAMP_BASE + i + j);
            specs[j].error = ZB_OK;
        }

        Test_ExpectStatus(LoopbackRadio_Inject(&rig->model, specs, batch), ZB_OK,
                     "a batch of captured PSDUs is queued verbatim, FCS octets and all: the suite reframes nothing");

        nowMs = nowMs + batch * MS_PER_FRAME;
        status = Aps_Step(&rig->aps, nowMs);

        if (status == ZB_ERR_UNSUPPORTED)
            out->stepsRefusingTx++;

        Test_Expect(status == ZB_OK || status == ZB_ERR_UNSUPPORTED,
               "nothing but the shim's own refusal interrupts a replay");

        taken = Mac_PollArrivals(&rig->mac, polls, MAC_POLL_EVENT_MAX);
        out->macPollEvents = out->macPollEvents + taken;

        taken = Aps_PollConfirms(&rig->aps, confirms, APS_CONFIRM_MAX);
        out->apsConfirms = out->apsConfirms + taken;

        taken = Aps_PollIndications(&rig->aps, indications, APS_INDICATION_MAX);
        out->apsIndications = out->apsIndications + taken;

        i = i + batch;
        out->steps++;
    }
}

void measureMacRow(const Capture *cap, MacView *out)
{
    Loopback_FrameSpec specs[RADIO_FRAME_BATCH_MAX];
    Mac_DataIndicationParameters drained[MAC_INDICATION_QUEUE_MAX];
    Mac_DataConfirmParameters confirms[MAC_TX_TRACK_MAX];
    Mac_PollArrival polls[MAC_POLL_EVENT_MAX];
    Radio_Caps caps;
    Loopback_Radio model;
    Mac_Mac mac;
    Mac_Counters counters;
    uint32_t nowMs;
    uint32_t taken;
    uint32_t batch;
    uint32_t i;
    uint32_t j;

    Test_BandACapsAcks(&caps);
    Zb_memset(out, 0, (uint32_t)sizeof *out);

    Test_ExpectStatus(LoopbackRadio_Init(&model, &caps), ZB_OK, "a MAC with nothing above it");
    Test_ExpectStatus(Mac_Init(&mac, LoopbackRadio_Seam(&model), 0), ZB_OK, "on the same model backend");
    bringMacUp(&mac, OWN_SHORT);
    Test_ExpectStatus(Mac_SetPromiscuousMode(&mac, 1), ZB_OK, "as the promiscuous listener 10.23.1 describes");

    nowMs = 0;
    i = 0;

    while (i < cap->count)
    {
        batch = cap->count - i;

        if (batch > RADIO_FRAME_BATCH_MAX)
            batch = RADIO_FRAME_BATCH_MAX;

        for (j = 0; j < batch; j++)
        {
            Zb_memset(&specs[j], 0, (uint32_t)sizeof specs[j]);
            specs[j].len = cap->len[i + j];
            specs[j].bytes = cap->bytes[i + j];
            specs[j].rssiDbm = FIXTURE_RSSI_DBM;
            specs[j].lqi = FIXTURE_LQI;
            specs[j].stampTicks = (uint64_t)(FIXTURE_STAMP_BASE + i + j);
            specs[j].error = ZB_OK;
        }

        Test_ExpectStatus(LoopbackRadio_Inject(&model, specs, batch), ZB_OK, "and the same capture in the same order");

        nowMs = nowMs + batch * MS_PER_FRAME;
        Test_ExpectStatus(Mac_Step(&mac, nowMs), ZB_OK, "stepped once per batch");

        taken = Mac_PollIndications(&mac, drained, MAC_INDICATION_QUEUE_MAX);

        for (j = 0; j < taken; j++)
        {
            out->delivered++;

            if (drained[j].status != ZB_OK)
                out->verdictFailing++;

            if (!drained[j].headerValid)
                out->headerUnread++;
        }

        out->confirms = out->confirms + Mac_PollConfirms(&mac, confirms, MAC_TX_TRACK_MAX);
        out->pollEvents = out->pollEvents + Mac_PollArrivals(&mac, polls, MAC_POLL_EVENT_MAX);

        counters = Mac_CountersOf(&mac);

        out->acksHeard = counters.acksHeard;
        out->commandsHeard = counters.commandsHeard;
        out->footerRefused = counters.fcsFailures;
        out->refused = counters.reservedTypeFrames + counters.reservedVersionFrames
                       + counters.malformedFrames + counters.unbuiltForms;

        i = i + batch;
    }
}

/* ------------------------------------------------------------------ the ledger */

void readLedger(const Rig *rig, const Driven *driven, Ledger *out)
{
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Security_KeyState state;
    Mac_Counters counters;
    uint32_t i;

    Zb_memset(out, 0, (uint32_t)sizeof *out);

    counters = Mac_CountersOf(&rig->mac);

    out->macAcksHeard = counters.acksHeard;
    out->macCommandsHeard = counters.commandsHeard;
    out->macRefusedRequests = counters.refusedRequests;
    out->macPollsSkipped = counters.pollsSkipped;
    out->macPollsUnanswered = counters.pollsUnanswered;
    out->macPollArrivalsDropped = counters.pollArrivalQueue;
    out->macTransactionsExpired = counters.transactionsExpired;
    out->macOutstanding = counters.outstanding;
    out->macTransactionQueue = counters.transactionQueue;

    out->nwkCarrierOther = Nwk_CarrierOther(&rig->nwk);
    out->nwkDroppedMalformed = Nwk_DroppedMalformed(&rig->nwk);
    out->nwkDroppedUnsupported = Nwk_DroppedUnsupported(&rig->nwk);
    out->nwkDroppedDuplicate = Nwk_DroppedDuplicate(&rig->nwk);
    out->nwkDroppedNotForMe = Nwk_DroppedNotForMe(&rig->nwk);
    out->nwkDroppedNoRoute = Nwk_DroppedNoRoute(&rig->nwk);
    out->nwkDroppedEndDeviceInitiator = Nwk_DroppedEndDeviceInitiator(&rig->nwk);
    out->nwkDroppedIndications = Nwk_DroppedIndications(&rig->nwk);
    out->nwkBttFullDrops = Nwk_BttFullDrops(&rig->nwk);
    out->nwkRecognizedCommands = Nwk_RecognizedCommands(&rig->nwk);
    out->nwkRxSecurityFailures = Nwk_RxSecurityFailures(&rig->nwk);
    out->nwkRxFrameCounterRejects = Nwk_RxFrameCounterRejects(&rig->nwk);
    out->nwkDroppedUnsecured = Nwk_DroppedUnsecured(&rig->nwk);
    out->nwkNeighborAddsRefused = Nwk_NeighborAddsRefused(&rig->nwk);
    out->nwkRouteRequestsSent = Nwk_RouteRequestsSent(&rig->nwk);
    out->nwkRouteRepliesSent = Nwk_RouteRepliesSent(&rig->nwk);
    out->nwkRreqDroppedEndDevice = Nwk_RreqDroppedEndDevice(&rig->nwk);
    out->nwkRreqDroppedNoNeighbor = Nwk_RreqDroppedNoNeighbor(&rig->nwk);
    out->nwkRreqDroppedNoOutgoingCost = Nwk_RreqDroppedNoOutgoingCost(&rig->nwk);
    out->nwkRreqDroppedGreaterCost = Nwk_RreqDroppedGreaterCost(&rig->nwk);
    out->nwkRreqDroppedNoDiscoverySlot = Nwk_RreqDroppedNoDiscoverySlot(&rig->nwk);
    out->nwkRefusedRequests = Nwk_RefusedRequests(&rig->nwk);
    out->nwkConfirmsIgnored = Nwk_ConfirmsIgnored(&rig->nwk);
    out->nwkRelaysSent = Nwk_RelaysSent(&rig->nwk);
    out->nwkReplyCommands = Nwk_ReplyCommands(&rig->nwk);
    out->nwkTxSecurityFailures = Nwk_TxSecurityFailures(&rig->nwk);
    out->nwkConfirmQueue = Nwk_ConfirmQueue(&rig->nwk);
    out->nwkTransmitQueue = Nwk_TransmitQueue(&rig->nwk);
    out->nwkBttQueue = Nwk_BttQueue(&rig->nwk);
    out->nwkNeighborQueue = Nwk_NeighborQueue(&rig->nwk);
    out->nwkRouteQueue = Nwk_RouteQueue(&rig->nwk);
    out->nwkIndicationQueue = Nwk_IndicationQueue(&rig->nwk);

    out->apsRefusedRequests = Aps_RefusedRequests(&rig->aps);
    out->apsUnmatchedAcks = Aps_UnmatchedAcks(&rig->aps);
    out->apsConfirmsIgnored = Aps_ConfirmationsIgnored(&rig->aps);
    out->apsRetransmitRefusals = Aps_RetransmitRefusals(&rig->aps);
    out->apsRxShapeRefused = Aps_RxShapeRefused(&rig->aps);
    out->apsRxMalformed = Aps_RxMalformed(&rig->aps);
    out->apsRxSecuredDeferred = Aps_RxSecuredDeferred(&rig->aps);
    out->apsRxCommandDeferred = Aps_RxCommandDeferred(&rig->aps);
    out->apsRxDuplicateDrops = Aps_RxDuplicateDrops(&rig->aps);
    out->apsDroppedGroupMiss = Aps_DroppedGroupMiss(&rig->aps);
    out->apsAcksGenerated = Aps_AcksGenerated(&rig->aps);
    out->apsAcksRefused = Aps_AcksRefused(&rig->aps);
    out->apsDroppedIndications = Aps_DroppedIndications(&rig->aps);
    out->apsGroupRefusals = Aps_GroupRefusals(&rig->aps);
    out->apsTxNoKeyPair = Aps_TxNoKeyPair(&rig->aps);
    out->apsTxSecuredFailures = Aps_TxSecuredFailures(&rig->aps);
    out->apsRxSecuredFailuresAuth = Aps_RxSecuredFailuresAuth(&rig->aps);
    out->apsRxSecuredFailuresCounters = Aps_RxSecuredFailuresCounters(&rig->aps);
    out->apsConfirmQueue = Aps_ConfirmQueue(&rig->aps);
    out->apsTransmitQueue = Aps_TransmitQueue(&rig->aps);
    out->apsGroupQueue = Aps_GroupQueue(&rig->aps);
    out->apsIndicationQueue = Aps_IndicationQueue(&rig->aps);

    out->nwkIndicationsAccounted = out->apsRxShapeRefused + out->apsRxMalformed
                                   + out->apsRxSecuredDeferred + out->apsRxCommandDeferred
                                   + out->apsRxDuplicateDrops + out->apsDroppedGroupMiss
                                   + out->apsDroppedIndications + driven->apsIndications;

    out->securityWindows = 0;

    for (i = 0; i < SECURITY_INCOMING_MAX; i++)
    {
        if (rig->security.incoming[i].inUse)
            out->securityWindows++;
    }

    Security_Snapshot(&rig->security, &state);

    if (state.keyCount != 0)
        out->securityOutgoing = state.outgoingFrameCounter[0];

    out->steps = driven->steps;
    out->stepsRefusingTx = driven->stepsRefusingTx;
    out->apsIndications = driven->apsIndications;
    out->apsConfirms = driven->apsConfirms;
    out->macPollEvents = driven->macPollEvents;
    out->backendIssued = rig->model.issued;         /* the model's own count of transmits it accepted */
    out->backendSent = LoopbackRadio_Sent(&rig->model, sent, LOOPBACK_TX_MAX);
    out->shimRefusals = rig->deny.txRefusals;
}

/* ------------------------------------------------------------------ the pinned ledger */

Ledger s_plainPrimary;       /* phase A's run, compared counter by counter against phase D's */
