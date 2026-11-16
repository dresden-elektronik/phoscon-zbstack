/* The `interop` suite's passivity phase: the primary replay again, this time
   through the deny-tx shim, with every transmit the receive logic attempted refused by name
   at the seam and every counter a passive read cannot change compared one by one against phase A's. */

#include "aps.h"
#include "interop_helpers.h"
#include "loopback_radio.h"
#include "mac.h"
#include "nwk.h"
#include "test_harness.h"

/* The counters a passive read cannot change, compared one by one between the plain and the shimmed replay. */
void expectSameLedger(const Ledger *plain, const Ledger *shim)
{
    Test_ExpectPassive(shim->macAcksHeard, plain->macAcksHeard, "Mac_Counters.acksHeard");
    Test_ExpectPassive(shim->macCommandsHeard, plain->macCommandsHeard, "Mac_Counters.commandsHeard");
    Test_ExpectPassive(shim->nwkCarrierOther, plain->nwkCarrierOther, "Nwk_CarrierOther");
    Test_ExpectPassive(shim->nwkDroppedMalformed, plain->nwkDroppedMalformed, "Nwk_DroppedMalformed");
    Test_ExpectPassive(shim->nwkDroppedUnsupported, plain->nwkDroppedUnsupported, "Nwk_DroppedUnsupported");
    Test_ExpectPassive(shim->nwkDroppedDuplicate, plain->nwkDroppedDuplicate, "Nwk_DroppedDuplicate");
    Test_ExpectPassive(shim->nwkDroppedNotForMe, plain->nwkDroppedNotForMe, "Nwk_DroppedNotForMe");
    Test_ExpectPassive(shim->nwkDroppedNoRoute, plain->nwkDroppedNoRoute, "Nwk_DroppedNoRoute");
    Test_ExpectPassive(shim->nwkDroppedIndications, plain->nwkDroppedIndications, "Nwk_DroppedIndications");
    Test_ExpectPassive(shim->nwkBttFullDrops, plain->nwkBttFullDrops, "Nwk_BttFullDrops");
    Test_ExpectPassive(shim->nwkRecognizedCommands, plain->nwkRecognizedCommands, "Nwk_RecognizedCommands");
    Test_ExpectPassive(shim->nwkRxSecurityFailures, plain->nwkRxSecurityFailures, "Nwk_RxSecurityFailures");
    Test_ExpectPassive(shim->nwkRxFrameCounterRejects, plain->nwkRxFrameCounterRejects, "Nwk_RxFrameCounterRejects");
    Test_ExpectPassive(shim->nwkDroppedUnsecured, plain->nwkDroppedUnsecured, "Nwk_DroppedUnsecured");
    Test_ExpectPassive(shim->nwkNeighborAddsRefused, plain->nwkNeighborAddsRefused, "Nwk_NeighborAddsRefused");
    Test_ExpectPassive(shim->nwkIndicationsAccounted, plain->nwkIndicationsAccounted, "the NLDE indications handed to aps");
    Test_ExpectPassive(shim->nwkIndicationQueue, plain->nwkIndicationQueue, "Nwk_IndicationQueue");
    Test_ExpectPassive(shim->nwkBttQueue, plain->nwkBttQueue, "Nwk_BttQueue (the records a relay was composed from)");
    Test_ExpectPassive(shim->nwkNeighborQueue, plain->nwkNeighborQueue, "Nwk_NeighborQueue");
    Test_ExpectPassive(shim->securityWindows, plain->securityWindows, "the incoming frame-counter windows 4.3.1.2 step 6 committed");
    Test_ExpectPassive(shim->securityOutgoing, plain->securityOutgoing, "this device's own outgoing frame counter, moved by the relay protections either way");
    Test_ExpectPassive(shim->nwkRouteRepliesSent, plain->nwkRouteRepliesSent, "Nwk_RouteRepliesSent");
    Test_ExpectPassive(shim->nwkRreqDroppedEndDevice, plain->nwkRreqDroppedEndDevice, "Nwk_RreqDroppedEndDevice");
    Test_ExpectPassive(shim->nwkRreqDroppedNoNeighbor, plain->nwkRreqDroppedNoNeighbor, "Nwk_RreqDroppedNoNeighbor");
    Test_ExpectPassive(shim->nwkRreqDroppedNoOutgoingCost, plain->nwkRreqDroppedNoOutgoingCost, "Nwk_RreqDroppedNoOutgoingCost");
    Test_ExpectPassive(shim->nwkRreqDroppedGreaterCost, plain->nwkRreqDroppedGreaterCost, "Nwk_RreqDroppedGreaterCost");
    Test_ExpectPassive(shim->nwkRreqDroppedNoDiscoverySlot, plain->nwkRreqDroppedNoDiscoverySlot, "Nwk_RreqDroppedNoDiscoverySlot");
    Test_ExpectPassive(shim->apsRxShapeRefused, plain->apsRxShapeRefused, "Aps_RxShapeRefused");
    Test_ExpectPassive(shim->apsRxMalformed, plain->apsRxMalformed, "Aps_RxMalformed");
    Test_ExpectPassive(shim->apsRxDuplicateDrops, plain->apsRxDuplicateDrops, "Aps_RxDuplicateDrops");
    Test_ExpectPassive(shim->apsDroppedGroupMiss, plain->apsDroppedGroupMiss, "Aps_DroppedGroupMiss");
    Test_ExpectPassive(shim->apsDroppedIndications, plain->apsDroppedIndications, "Aps_DroppedIndications");
    Test_ExpectPassive(shim->apsIndications, plain->apsIndications, "the APSDE indications drained off the ring");
    Test_ExpectPassive(shim->apsIndicationQueue, plain->apsIndicationQueue, "Aps_IndicationQueue");
    Test_ExpectPassive(shim->macPollEvents, plain->macPollEvents, "the Mac_PollArrival events drained");
}

void phaseD(void)
{
    Rig rig;
    Driven driven;
    Ledger ledger;

    rigBuild(&rig, OWN_SHORT, 1, KEY_OCTET, KEY_SEQ, 1);
    rigAssert(&rig, OWN_SHORT);
    Test_Expect(rig.shimmied == 1, "the seam this rig hands band A is the deny-tx shim");

    driveReset(&driven);
    driveReplay(&rig, &s_primary, &driven);
    readLedger(&rig, &driven, &ledger);

    /* The passivity proof, in the order it matters: nothing left this device, everything the receive logic
       tried to send was refused by name, and nothing about a received frame changed. */
    Test_ExpectCount(ledger.backendIssued, 0, "phase D: the wrapped backend accepted no transmit at all");
    Test_ExpectCount(ledger.backendSent, 0, "phase D: LoopbackRadio_Sent is empty, no octet was put on the model's air");
    Test_ExpectCount(ledger.shimRefusals, 46,
                 "phase D: 46 refusals counted at the shim, one per transmit the same capture makes the unshimmed replay attempt, the 6 broadcast relays, the 32 source-routed data frames and the 8 Leaves (every refusal a named number, never silence)");
    Test_ExpectPassive(ledger.shimRefusals, s_plainPrimary.backendIssued,
                  "the shim refused exactly the transmits the plain replay put on the air");
    Test_ExpectCount(ledger.stepsRefusingTx, 0,
                 "phase D: no step answered the shim's ZB_ERR_UNSUPPORTED, because the only attempted transmits were relay refusals and those end their own attempt silently, as an unissued relay always has");

    Test_ExpectCount(ledger.nwkRelaysSent, 0, "phase D Nwk_RelaysSent: 0, the attempt never reached the air, so the counter never moved");
    Test_ExpectCount(ledger.nwkReplyCommands, 0, "phase D Nwk_ReplyCommands: 0");
    Test_ExpectCount(ledger.nwkConfirmsIgnored, 0, "phase D Nwk_ConfirmsIgnored: 0, no transmit, so no completion to ignore (12 in the plain replay)");
    Test_ExpectCount(ledger.nwkRouteRequestsSent, 0,
                 "phase D Nwk_RouteRequestsSent: 0, as in the plain replay, every request having been discarded at 9121");
    Test_ExpectCount(ledger.nwkTxSecurityFailures, 0, "phase D Nwk_TxSecurityFailures: the protections the relays owed still ran and still succeeded");
    Test_ExpectCount(ledger.nwkTransmitQueue, 0, "phase D Nwk_TransmitQueue: no request was ever taken back");
    Test_ExpectCount(ledger.nwkConfirmQueue, 0, "phase D Nwk_ConfirmQueue");
    Test_ExpectCount(ledger.macRefusedRequests, 0, "phase D Mac_Counters.refusedRequests: the refusal is the shim's own, counted there and not folded into mac's validation family");
    Test_ExpectCount(ledger.macPollsUnanswered, 0, "phase D Mac_Counters.pollsUnanswered: a poll whose answer the seam refused is not a poll with nowhere to put the answer");
    Test_ExpectCount(ledger.macPollsSkipped, 0, "phase D Mac_Counters.pollsSkipped");
    Test_ExpectCount(ledger.macOutstanding, 0, "phase D Mac_Counters.outstanding: no track slot is held open by a transmit that never ran");
    Test_ExpectCount(ledger.macTransactionQueue, 0, "phase D Mac_Counters.transactionQueue");
    Test_ExpectCount(ledger.apsAcksGenerated, 0, "phase D Aps_AcksGenerated");
    Test_ExpectCount(ledger.apsAcksRefused, 0, "phase D Aps_AcksRefused");
    Test_ExpectCount(ledger.apsUnmatchedAcks, 0, "phase D Aps_UnmatchedAcks");
    Test_ExpectCount(ledger.apsConfirmsIgnored, 0, "phase D Aps_ConfirmationsIgnored");
    Test_ExpectCount(ledger.apsRetransmitRefusals, 0, "phase D Aps_RetransmitRefusals");

    expectSameLedger(&s_plainPrimary, &ledger);
}
