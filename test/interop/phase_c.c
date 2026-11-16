/* The `interop` suite's composed legs: the three failures no capture
   contains (a genuinely unsecured frame at a joined device, a frame secured under a foreign key, and a frame
   whose key sequence number the material set does not hold) built by a second stack of this tree so what is
   refused is a frame the suite made and knows the octets of. */

#include "aps.h"
#include "interop_helpers.h"
#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "nwk.h"
#include "nwk_frame.h"
#include "security.h"
#include "test_harness.h"
#include "zb_utils.h"

/* One composed frame, one step, every ring drained: what the composed legs can only be asked of a frame the harness
   builds, because neither capture carries one of that shape. */
void driveOne(Rig *rig, const uint8_t *bytes, uint32_t len, uint32_t nowMs, Driven *out)
{
    Loopback_FrameSpec spec;
    Mac_PollArrival polls[MAC_POLL_EVENT_MAX];
    Aps_Indication indications[APS_INDICATION_MAX];
    Aps_Confirm confirms[APS_CONFIRM_MAX];

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = len;
    spec.bytes = bytes;
    spec.rssiDbm = FIXTURE_RSSI_DBM;
    spec.lqi = FIXTURE_LQI;
    spec.stampTicks = FIXTURE_STAMP_BASE;
    spec.error = ZB_OK;

    Test_ExpectStatus(LoopbackRadio_Inject(&rig->model, &spec, 1), ZB_OK, "the frame is injected verbatim");

    Test_ExpectStatus(Aps_Step(&rig->aps, nowMs), ZB_OK, "one step at the same 1 ms cadence");

    out->steps = out->steps + 1;
    out->macPollEvents = out->macPollEvents + Mac_PollArrivals(&rig->mac, polls, MAC_POLL_EVENT_MAX);
    out->apsConfirms = out->apsConfirms + Aps_PollConfirms(&rig->aps, confirms, APS_CONFIRM_MAX);
    out->apsIndications = out->apsIndications + Aps_PollIndications(&rig->aps, indications, APS_INDICATION_MAX);
}

/* The fixture frame the two failure legs are run on, named before it is used: FCS-valid, a MAC data frame,
   on this PAN, with the NWK security sub-field set and the key sequence the captures carry. */
void legFrameFacts(const uint8_t *bytes, uint32_t len, const char *what)
{
    Mac_Frame mac;
    const uint8_t *npdu = 0;
    uint32_t npduLen = 0;
    uint16_t fcf;

    Test_ExpectStatus(MacFrame_Parse(bytes, len, 1, &mac, &npdu, &npduLen, 0), ZB_OK, what);
    Test_Expect(npdu != 0 && npduLen != 0, "the frame carries an NPDU");
    Test_Expect(mac.frameType == MAC_FRAME_TYPE_DATA, "it is a data frame");
    Test_Expect(mac.destPan == PAN_ID, "on this PAN");
    Test_ExpectStatus(MacFrame_CheckFcs(bytes, len), ZB_OK, "and its own footer checks out, so the security crossing is reached");

    fcf = (uint16_t)(npdu[0] | (npdu[1] << 8));

    Test_Expect(((fcf >> NWK_FRAME_FCF_SECURITY_SHIFT) & NWK_FRAME_FCF_SECURITY_MASK) == 1,
          "with the NWK security sub-field set (3.3.1.1, bit 9)");
}

void legUnsecured(void)
{
    static const uint8_t asdu[4] = { 0x01, 0x02, 0x03, 0x04 };

    Rig sender;
    Rig receiver;
    Driven driven;
    Ledger ledger;
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Aps_ApsdeReq req;
    Mac_Frame air;
    const uint8_t *npdu = 0;
    uint32_t npduLen = 0;
    uint32_t got;
    uint16_t fcf;

    rigBuild(&sender, SENDER_SHORT, 0, 0, 0, 0);     /* the scaffold: no key attached, so what it composes is unsecured */
    rigBuild(&receiver, OWN_SHORT, 1, KEY_OCTET, KEY_SEQ, 0);

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.dstAddrMode = APS_ADDR_MODE_SHORT;
    req.dstAddress = NWK_ADDR_RX_ON_WHEN_IDLE;    /* 0xfffd: Table 3-80's macRxOnWhenIdle class, which this rig is in */
    req.dstEndpoint = 0x01;
    req.srcEndpoint = 0x01;
    req.profileId = 0x0104;
    req.clusterId = 0x0006;
    req.asdu = asdu;
    req.asduLength = 4;
    req.txOptions = 0;                               /* no APS_TX_OPTION_NWK_KEY: the SAP's own prohibition of security for this frame (4.2.2) */

    Test_ExpectStatus(Aps_DataRequest(&sender.aps, &req, 1), ZB_OK, "the composed leg is an aps→nwk→mac request, so its octets are the stack's own");
    Test_ExpectStatus(Aps_Step(&sender.aps, 2), ZB_OK, "and the sender's answer is collected before its frame is read back");

    got = LoopbackRadio_Sent(&sender.model, sent, LOOPBACK_TX_MAX);
    Test_ExpectCount(got, 1, "exactly one frame went on the sender's model air");

    if (got != 1)
        return;

    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &air, &npdu, &npduLen, 0), ZB_OK,
                 "the harvested frame is a MAC data frame the codec reads");
    Test_Expect(npdu != 0 && npduLen != 0, "carrying an NPDU");

    fcf = (uint16_t)(npdu[0] | (npdu[1] << 8));

    Test_Expect(((fcf >> NWK_FRAME_FCF_SECURITY_SHIFT) & NWK_FRAME_FCF_SECURITY_MASK) == 0,
           "with the NWK security sub-field clear: the leg is genuinely unsecured, not merely unread");

    driveReset(&driven);
    driveOne(&receiver, sent[0].bytes, sent[0].len, 1, &driven);
    readLedger(&receiver, &driven, &ledger);

    Test_ExpectCount(ledger.nwkDroppedUnsecured, 1,
                 "phase C1 Nwk_DroppedUnsecured: 1, 3.6.2.2's discard at a joined, authenticated device with a non-zero nwkSecurityLevel, reached only with a frame the harness composes");
    Test_ExpectCount(ledger.nwkIndicationsAccounted, 0, "phase C1: nothing was handed up");
    Test_ExpectCount(ledger.nwkRelaysSent, 0, "phase C1: no record, so no relay");
    Test_ExpectCount(ledger.nwkRecognizedCommands, 0, "phase C1 Nwk_RecognizedCommands");
    Test_ExpectCount(ledger.nwkRxSecurityFailures, 0, "phase C1 Nwk_RxSecurityFailures");
    Test_ExpectCount(ledger.nwkRxFrameCounterRejects, 0, "phase C1 Nwk_RxFrameCounterRejects");
    Test_ExpectCount(ledger.nwkDroppedMalformed, 0, "phase C1 Nwk_DroppedMalformed: the frame is not damage, it is unsecured");
    Test_ExpectCount(ledger.nwkDroppedNotForMe, 0, "phase C1 Nwk_DroppedNotForMe: this rig is in the destination class");
    Test_ExpectCount(ledger.nwkDroppedDuplicate, 0, "phase C1 Nwk_DroppedDuplicate");
    Test_ExpectCount(ledger.securityWindows, 0, "phase C1: an unsecured frame commits no counter window");
    Test_ExpectCount(ledger.apsIndications, 0, "phase C1: no APSDE indication");
    Test_ExpectCount(ledger.macPollEvents, 0, "phase C1: no poll");
}

void legWrongKey(void)
{
    Rig rig;
    Driven driven;
    Ledger ledger;

    legFrameFacts(s_primary.bytes[0], s_primary.len[0], "the primary fixture's first PSDU is readable as this stack reads it");

    rigBuild(&rig, OWN_SHORT, 1, FOREIGN_KEY_OCTET, KEY_SEQ, 0);
    rigAssert(&rig, OWN_SHORT);

    driveReset(&driven);
    driveOne(&rig, s_primary.bytes[0], s_primary.len[0], 1, &driven);
    readLedger(&rig, &driven, &ledger);

    Test_ExpectCount(ledger.nwkRxSecurityFailures, 1,
                 "phase C2 Nwk_RxSecurityFailures: 1, a foreign key fails at 4.3.1.2 step 5a, at the MIC, and at nothing else");
    Test_ExpectCount(ledger.nwkRxFrameCounterRejects, 0, "phase C2 Nwk_RxFrameCounterRejects: the counter was never judged, because the key was");
    Test_ExpectCount(ledger.securityWindows, 0, "phase C2: the incoming store stays empty, step 6 stores a counter only for a frame that authenticated");
    Test_ExpectCount(ledger.nwkDroppedMalformed, 0, "phase C2 Nwk_DroppedMalformed: an authenticated-config read of a real frame, not damage");
    Test_ExpectCount(ledger.nwkDroppedUnsupported, 0, "phase C2 Nwk_DroppedUnsupported: the frame form is one band A reads");
    Test_ExpectCount(ledger.nwkNeighborAddsRefused, 0, "phase C2: no neighbour observation either, 4.3.1.2 step 8 runs for a frame that passed step 5");
    Test_ExpectCount(ledger.nwkNeighborQueue, 0, "phase C2 Nwk_NeighborQueue");
    Test_ExpectCount(ledger.nwkIndicationsAccounted, 0, "phase C2: nothing reached the ring");
    Test_ExpectCount(ledger.nwkBttQueue, 0, "phase C2 Nwk_BttQueue: no record for a frame this device could not authenticate");
    Test_ExpectCount(ledger.macAcksHeard, 0, "phase C2 Mac_Counters.acksHeard");
    Test_ExpectCount(ledger.nwkCarrierOther, 0, "phase C2 Nwk_CarrierOther");
}

void legKeySequence(void)
{
    Rig rig;
    Driven driven;
    Ledger ledger;

    rigBuild(&rig, OWN_SHORT, 1, KEY_OCTET, OTHER_KEY_SEQ, 0);
    rigAssert(&rig, OWN_SHORT);

    driveReset(&driven);
    driveOne(&rig, s_primary.bytes[0], s_primary.len[0], 1, &driven);
    readLedger(&rig, &driven, &ledger);

    Test_ExpectCount(ledger.nwkRxSecurityFailures, 1,
                 "phase C3 Nwk_RxSecurityFailures: 1, 4.3.1.2 step 2's 'frame security failed' for a sequence number the material set does not hold, before the counter and before the MIC");
    Test_ExpectCount(ledger.nwkRxFrameCounterRejects, 0, "phase C3 Nwk_RxFrameCounterRejects");
    Test_ExpectCount(ledger.securityWindows, 0, "phase C3: the store stays empty for the same reason as phase C2's");
    Test_ExpectCount(ledger.nwkIndicationsAccounted, 0, "phase C3: nothing reached the ring");
    Test_ExpectCount(ledger.nwkDroppedUnsecured, 0, "phase C3 Nwk_DroppedUnsecured: the frame asked for security, so 3.6.2.2's unsecured discard is not its disposition");
}

void phaseC(void)
{
    legUnsecured();
    legWrongKey();
    legKeySequence();
}
