/* The `interop` suite's secondary phase: the earlier session's 55-PSDU
   capture on the same PAN, replayed through the same device and pinned against its own column of the
   inventory, the run that says the ledger is a property of the stack and not of one capture. */

#include "aps.h"
#include "interop_helpers.h"
#include "mac.h"
#include "nwk.h"
#include "test_harness.h"

void pinSecondary(const Ledger *l)
{
    Test_ExpectCount(l->nwkRxSecurityFailures, 0, "phase B Nwk_RxSecurityFailures: all 26 secured 0xde20 frames of the earlier session authenticate under the same key");
    Test_ExpectCount(l->nwkRxFrameCounterRejects, 0, "phase B Nwk_RxFrameCounterRejects: the session's one repeated counter belongs to a frame whose footer fails");
    Test_ExpectCount(l->macAcksHeard, 27,
                 "phase B Mac_Counters.acksHeard: 27, the ordinary consumption still running under 10.23.1's mode");
    Test_ExpectCount(l->macCommandsHeard, 0, "phase B Mac_Counters.commandsHeard: 0");
    Test_ExpectCount(l->nwkCarrierOther, 27, "phase B Nwk_CarrierOther: the 27 acknowledgments, parsed non-data frames handed up as carriers; the one Data Request's footer does not compute, so 6.6.2 discards it at the MAC and it reaches no layer above");
    Test_ExpectCount(l->macPollEvents, 0, "phase B Mac_PollArrivals: 0, because the one Data Request's footer fails and 6.6.2 discards that frame at the MAC");
    Test_ExpectCount(l->nwkDroppedMalformed, 0, "phase B Nwk_DroppedMalformed: 0, the damaged data PSDU is discarded at the MAC (6.6.2) and never offered to this layer; the parsed acknowledgments are carriers");
    Test_ExpectCount(l->nwkDroppedNotForMe, 0,
                 "phase B Nwk_DroppedNotForMe: 0, the 20 source-routed data frames are decided by 3.6.4.3.2 rather than refused");
    Test_ExpectCount(l->nwkDroppedNoRoute, 3, "phase B Nwk_DroppedNoRoute: 3");
    Test_ExpectCount(l->nwkDroppedDuplicate, 0, "phase B Nwk_DroppedDuplicate: 0");
    Test_ExpectCount(l->nwkRecognizedCommands, 0,
                 "phase B Nwk_RecognizedCommands: 0, the two identifiers being a Route Request and a Link Status, both this layer's own procedures");
    Test_ExpectCount(l->nwkIndicationsAccounted, 1,
                 "phase B: 1 NLDE indication, the two link status carriers having left the count with 3.6.4.4.2");
    Test_ExpectCount(l->apsRxShapeRefused, 0, "phase B Aps_RxShapeRefused: 0, those carriers being link status frames");
    Test_ExpectCount(l->apsRxMalformed, 0, "phase B Aps_RxMalformed: 0, its one endpoint-0x00 broadcast read since D-217");
    Test_ExpectCount(l->apsIndications, 1, "phase B: 1 APSDE indication, that broadcast");
    Test_ExpectCount(l->nwkRelaysSent, 21, "phase B Nwk_RelaysSent: 21, the inventory's one relay and the 20 source-routed data frames 3.6.4.3.2 relays");
    Test_ExpectCount(l->nwkConfirmsIgnored, 18, "phase B Nwk_ConfirmsIgnored: 18, one per transmit less the three still outstanding");
    Test_ExpectCount(l->macOutstanding, 3, "phase B Mac_Counters.outstanding: 3, the last three relay attempts' completions still held when the capture ends; 18 + 3 = 21");
    Test_ExpectCount(l->backendIssued, 21, "phase B: the model accepted 21 transmits, the inventory's relay and the 20 source-routed ones");
    Test_ExpectCount(l->nwkBttQueue, 1,
                 "phase B Nwk_BttQueue: 1 record, the one relayed; the two link status records are gone with 3.6.4.4.1's one hop");
    Test_ExpectCount(l->securityWindows, 1, "phase B: one auxiliary sender, one window");
    Test_ExpectCount(l->securityOutgoing, 21, "phase B: this device's counter moved once per protection, one for each of the 21 transmits");
    Test_ExpectCount(l->steps, 7, "phase B: 7 steps for 55 PSDUs");
    Test_ExpectCount(l->nwkDroppedUnsecured, 0, "phase B Nwk_DroppedUnsecured");
    Test_ExpectCount(l->nwkDroppedUnsupported, 0, "phase B Nwk_DroppedUnsupported");
    Test_ExpectCount(l->nwkDroppedIndications, 0, "phase B Nwk_DroppedIndications");
    Test_ExpectCount(l->nwkBttFullDrops, 0, "phase B Nwk_BttFullDrops");
    Test_ExpectCount(l->nwkNeighborAddsRefused, 0, "phase B Nwk_NeighborAddsRefused");
    Test_ExpectCount(l->nwkReplyCommands, 0, "phase B Nwk_ReplyCommands");
    Test_ExpectCount(l->nwkTxSecurityFailures, 0, "phase B Nwk_TxSecurityFailures");
    Test_ExpectCount(l->nwkRefusedRequests, 0, "phase B Nwk_RefusedRequests");
    Test_ExpectCount(l->nwkIndicationQueue, 0, "phase B Nwk_IndicationQueue left drained");
    Test_ExpectCount(l->nwkConfirmQueue, 0, "phase B Nwk_ConfirmQueue left drained");
    Test_ExpectCount(l->nwkTransmitQueue, 0, "phase B Nwk_TransmitQueue");
    Test_ExpectCount(l->apsRxSecuredDeferred, 0, "phase B Aps_RxSecuredDeferred");
    Test_ExpectCount(l->apsRxCommandDeferred, 0, "phase B Aps_RxCommandDeferred");
    Test_ExpectCount(l->apsRxDuplicateDrops, 0, "phase B Aps_RxDuplicateDrops");
    Test_ExpectCount(l->apsDroppedGroupMiss, 0, "phase B Aps_DroppedGroupMiss");
    Test_ExpectCount(l->apsUnmatchedAcks, 0, "phase B Aps_UnmatchedAcks");
    Test_ExpectCount(l->apsAcksGenerated, 0, "phase B Aps_AcksGenerated");
    Test_ExpectCount(l->apsAcksRefused, 0, "phase B Aps_AcksRefused");
    Test_ExpectCount(l->apsDroppedIndications, 0, "phase B Aps_DroppedIndications");
    Test_ExpectCount(l->apsRefusedRequests, 0, "phase B Aps_RefusedRequests");
    Test_ExpectCount(l->apsConfirmsIgnored, 0, "phase B Aps_ConfirmationsIgnored");
    Test_ExpectCount(l->apsRetransmitRefusals, 0, "phase B Aps_RetransmitRefusals");
    Test_ExpectCount(l->apsIndicationQueue, 0, "phase B Aps_IndicationQueue left drained");
    Test_ExpectCount(l->apsConfirmQueue, 0, "phase B Aps_ConfirmQueue");
    Test_ExpectCount(l->apsTransmitQueue, 0, "phase B Aps_TransmitQueue");
    Test_ExpectCount(l->apsGroupQueue, 0, "phase B Aps_GroupQueue");
    Test_ExpectCount(l->macRefusedRequests, 0, "phase B Mac_Counters.refusedRequests");
    Test_ExpectCount(l->macPollsSkipped, 0, "phase B Mac_Counters.pollsSkipped");
    Test_ExpectCount(l->macPollsUnanswered, 0, "phase B Mac_Counters.pollsUnanswered");
    Test_ExpectCount(l->macPollArrivalsDropped, 0, "phase B Mac_Counters.pollArrivalQueue left empty");
    Test_ExpectCount(l->macTransactionsExpired, 0, "phase B Mac_Counters.transactionsExpired");
    Test_ExpectCount(l->macTransactionQueue, 0, "phase B Mac_Counters.transactionQueue");
    Test_ExpectCount(l->stepsRefusingTx, 0, "phase B: nothing refused, no shim in this phase");
    Test_ExpectCount(l->apsConfirms, 0, "phase B: no APSDE request");
}

void phaseB(void)
{
    Rig rig;
    Driven driven;
    Ledger ledger;

    rigBuild(&rig, OWN_SHORT, 1, KEY_OCTET, KEY_SEQ, 0);
    rigAssert(&rig, OWN_SHORT);

    driveReset(&driven);
    driveReplay(&rig, &s_secondary, &driven);
    readLedger(&rig, &driven, &ledger);
    pinSecondary(&ledger);
}
