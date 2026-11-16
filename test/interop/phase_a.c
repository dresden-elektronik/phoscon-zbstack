/* The `interop` suite's primary phase: the 135-PSDU capture of the
   channel-15 test network replayed through `mac`, `nwk`, `security` and `aps` with the network key arriving as
   application config, every ledger number the capture inventory predicts pinned counter by counter, and the
   MAC's own row measured at the MAC rather than inferred from the layer above. */

#include "aps.h"
#include "interop_helpers.h"
#include "mac.h"
#include "nwk.h"
#include "radio.h"
#include "test_harness.h"

void pinPrimary(const Ledger *l)
{
    /* The headline three first (the envelope proof, then the counters the capture itself explains). */
    Test_ExpectCount(l->nwkRxSecurityFailures, 0,
                 "phase A Nwk_RxSecurityFailures: every FCS-valid secured 0xde20 frame authenticates under the test network's key, nonce form, NwkHeader || AuxiliaryHeader as adata, M = 4, against a running network");
    Test_ExpectCount(l->nwkRxFrameCounterRejects, 3,
                 "phase A Nwk_RxFrameCounterRejects: the three same-(sender, counter) re-arrivals, each strictly inside the window step 6 stored");
    Test_ExpectCount(l->macAcksHeard, 22,
                 "phase A Mac_Counters.acksHeard: 22, because 10.23.1 keeps 6.6.2's acknowledgment consumption even while the mode passes the frame upward");
    Test_ExpectCount(l->nwkCarrierOther, 32,
                 "phase A Nwk_CarrierOther: the 10 Data Requests and the 22 acknowledgments, every parsed non-data frame the promiscuous listener hands up, each with the header it parsed");
    Test_ExpectCount(l->macCommandsHeard, 0, "phase A Mac_Counters.commandsHeard: no beacon request, no realignment");
    Test_ExpectCount(l->macPollEvents, 0, "phase A Mac_PollArrivals: 0, because the 10 Data Requests are addressed to 0x0000 and this device is 0xfff0 (6.6.2 c, d)");

    /* The rest of the primary column. */
    Test_ExpectCount(l->nwkDroppedMalformed, 0,
                 "phase A Nwk_DroppedMalformed: 0, because nothing malformed reaches the network layer any more: the six frames whose octets do not close a frame are discarded at the MAC (6.6.2, 7.2.11)");
    Test_ExpectCount(l->nwkDroppedNotForMe, 0,
                 "phase A Nwk_DroppedNotForMe: 0, because the 32 source-routed data frames the capture carries are no longer refused wholesale: 3.6.4.3.2 decides each one against its relay index");
    Test_ExpectCount(l->nwkDroppedNoRoute, 29, "phase A Nwk_DroppedNoRoute: 29, a unicast this unseeded table has no path to (3.6.4.3)");
    Test_ExpectCount(l->nwkDroppedEndDeviceInitiator, 8,
                     "phase A Nwk_DroppedEndDeviceInitiator: 8, 3.3.1.1.8's exception counting apart from the route refusals");
    Test_ExpectCount(l->nwkDroppedDuplicate, 1,
                 "phase A Nwk_DroppedDuplicate: 1 broadcast record that was already in the table (3.6.6). The 11 the route request family used to cost are Table 3-81's, and 3.6.4.5.1.2 judges those copies on the forward cost before the broadcast table sees them (D-67)");
    Test_ExpectCount(l->nwkRecognizedCommands, 0,
                 "phase A Nwk_RecognizedCommands: 0 Table 3-54 identifiers handed up unprocessed. 0x01 is a Route Request (3.6.4.5.1) and 0x08 a Link Status (3.6.4.4.2), and this layer consumes both");
    Test_ExpectCount(l->nwkIndicationsAccounted, 6,
                 "phase A: the 6 NLDE indications the APS gate accounted for, every one in a disposition; the two link status carriers are no longer among them, 3.6.4.4.2 being this layer's own procedure");
    Test_ExpectCount(l->apsRxShapeRefused, 0,
                 "phase A Aps_RxShapeRefused: 0, the two NWK-command carriers that carry no APDU having been link status frames this layer now consumes");
    Test_ExpectCount(l->apsRxMalformed, 0,
                 "phase A Aps_RxMalformed: 0. The 4 broadcast APDUs whose destination endpoint is 0x00 are the ZDO broadcasts 2.4.3.1.11.1 prints, read since D-217");
    Test_ExpectCount(l->apsIndications, 6, "phase A: 6 APSDE indications reached the NHLE, those 4 among them");
    Test_ExpectCount(l->nwkBttFullDrops, 0, "phase A Nwk_BttFullDrops: 0");
    Test_ExpectCount(l->nwkDroppedUnsupported, 0, "phase A Nwk_DroppedUnsupported: 0");
    Test_ExpectCount(l->nwkDroppedUnsecured, 0,
                 "phase A Nwk_DroppedUnsecured: 0, the capture's one unsecured 0xde20 frame is corrupt twice over, so 3.6.2.2's discard has no fixture behind it (phase C composes one)");
    Test_ExpectCount(l->nwkDroppedIndications, 0, "phase A Nwk_DroppedIndications: 0");
    Test_ExpectCount(l->nwkNeighborAddsRefused, 0, "phase A Nwk_NeighborAddsRefused: 0");
    Test_ExpectCount(l->nwkReplyCommands, 0, "phase A Nwk_ReplyCommands: no 3.6.13 answer owed, none sent");
    Test_ExpectCount(l->nwkRouteRequestsSent, 0,
                 "phase A Nwk_RouteRequestsSent: 0, every request is discarded at 9121 before a relay could be owed");
    Test_ExpectCount(l->nwkRouteRepliesSent, 0, "phase A Nwk_RouteRepliesSent: no request of the capture names 0xfff0 as its destination");
    Test_ExpectCount(l->nwkRreqDroppedEndDevice, 0, "phase A Nwk_RreqDroppedEndDevice: the rig is a coordinator, so 9090's gate never answers");
    Test_ExpectCount(l->nwkRreqDroppedNoNeighbor, 0,
                 "phase A Nwk_RreqDroppedNoNeighbor: 0, 9120's search finds the coordinator: each request observes the hop that carried it as a neighbor entry first (8166-8167)");
    Test_ExpectCount(l->nwkRreqDroppedNoOutgoingCost, 16, "phase A Nwk_RreqDroppedNoOutgoingCost: all 16, for no link status of the capture names this rig, so 8168-8170 leave its cost 0 and 9121 discards");
    Test_ExpectCount(l->nwkRreqDroppedGreaterCost, 0, "phase A Nwk_RreqDroppedGreaterCost: 9137 is reached by no frame here for the same reason");
    Test_ExpectCount(l->nwkRreqDroppedNoDiscoverySlot, 0, "phase A Nwk_RreqDroppedNoDiscoverySlot: no claim was reached, so Table 3-79 was never asked for a slot");
    Test_ExpectCount(l->nwkRelaysSent, 38,
                 "phase A Nwk_RelaysSent: 6 broadcast relay attempts, the inventory's relay count less the 5 route requests 3.6.4.5.1 now consumes, none of which is relayed verbatim any more");
    Test_ExpectCount(l->nwkConfirmsIgnored, 44,
                 "phase A Nwk_ConfirmsIgnored: 44, one per transmit less the two still outstanding; the ten poll answers are gone with the destination filter");
    Test_ExpectCount(l->macOutstanding, 2, "phase A Mac_Counters.outstanding: 2, the last two relay attempts' completions still held when the capture ends; 44 + 2 = 46 is the whole of the plain replay's transmits");
    Test_ExpectCount(l->backendIssued, 46, "phase A: the model accepted 46 transmits, the 6 broadcast relays, the 32 source-routed data frames 3.6.4.3.2 relays, and the 8 Leaves 8678-8680 owes those 8 refused marks");
    Test_ExpectCount(l->nwkBttQueue, 6, "phase A Nwk_BttQueue: 6 broadcast records claimed (3.6.6), 6 of them relayed, 2 having arrived with radius 1 and 3.6.2.2 forbidding the retransmission of a frame whose radius fell to 0. The 5 route request records are gone: 3.6.4.5.1 is decided ahead of Table 3-81, and the two link status records with them, 3.6.4.4.1 making one hop of them");
    Test_ExpectCount(l->securityWindows, 2, "phase A: two incoming windows committed, one per auxiliary sender");
    Test_ExpectCount(l->securityOutgoing, 46, "phase A: this device's own counter moved once per protection, one for each of the 46 transmits (4.3.1.1 step 7)");
    Test_ExpectCount(l->steps, 17, "phase A: 17 steps for 135 PSDUs at RADIO_FRAME_BATCH_MAX 8");
    Test_ExpectCount(l->stepsRefusingTx, 0, "phase A: nothing was refused, there was no shim to refuse it");
    Test_ExpectCount(l->apsConfirms, 0, "phase A: no APSDE request, so no confirmation owed");

    /* Everything else the three modules name. */
    Test_ExpectCount(l->nwkRefusedRequests, 0, "phase A Nwk_RefusedRequests");
    Test_ExpectCount(l->nwkTxSecurityFailures, 0, "phase A Nwk_TxSecurityFailures");
    Test_ExpectCount(l->nwkConfirmQueue, 0, "phase A Nwk_ConfirmQueue left drained");
    Test_ExpectCount(l->nwkTransmitQueue, 0, "phase A Nwk_TransmitQueue");
    Test_ExpectCount(l->nwkRouteQueue, 0, "phase A Nwk_RouteQueue: 0, the discarded requests leave no route (9121 comes before 9130's entry)");
    Test_ExpectCount(l->nwkIndicationQueue, 0, "phase A Nwk_IndicationQueue left drained");
    Test_ExpectCount(l->macRefusedRequests, 0, "phase A Mac_Counters.refusedRequests");
    Test_ExpectCount(l->macPollsSkipped, 0, "phase A Mac_Counters.pollsSkipped");
    Test_ExpectCount(l->macPollsUnanswered, 0, "phase A Mac_Counters.pollsUnanswered");
    Test_ExpectCount(l->macPollArrivalsDropped, 0, "phase A Mac_Counters.pollArrivalQueue left empty (drained every step, as the drive requires)");
    Test_ExpectCount(l->macTransactionsExpired, 0, "phase A Mac_Counters.transactionsExpired");
    Test_ExpectCount(l->macTransactionQueue, 0, "phase A Mac_Counters.transactionQueue (nothing was queued for a sleepy device: the polls this capture holds ask for data this device never held)");
    Test_ExpectCount(l->apsRefusedRequests, 0, "phase A Aps_RefusedRequests");
    Test_ExpectCount(l->apsUnmatchedAcks, 0, "phase A Aps_UnmatchedAcks");
    Test_ExpectCount(l->apsConfirmsIgnored, 0, "phase A Aps_ConfirmationsIgnored");
    Test_ExpectCount(l->apsRetransmitRefusals, 0, "phase A Aps_RetransmitRefusals");
    Test_ExpectCount(l->apsRxSecuredDeferred, 0, "phase A Aps_RxSecuredDeferred (no frame here carries the APS security bit)");
    Test_ExpectCount(l->apsRxCommandDeferred, 0, "phase A Aps_RxCommandDeferred");
    Test_ExpectCount(l->apsRxDuplicateDrops, 0, "phase A Aps_RxDuplicateDrops");
    Test_ExpectCount(l->apsDroppedGroupMiss, 0, "phase A Aps_DroppedGroupMiss");
    Test_ExpectCount(l->apsAcksGenerated, 0, "phase A Aps_AcksGenerated: no accepted unicast data frame asked for an acknowledgement");
    Test_ExpectCount(l->apsAcksRefused, 0, "phase A Aps_AcksRefused");
    Test_ExpectCount(l->apsDroppedIndications, 0, "phase A Aps_DroppedIndications");
    Test_ExpectCount(l->apsGroupRefusals, 0, "phase A Aps_GroupRefusals");
    Test_ExpectCount(l->apsTxNoKeyPair, 0, "phase A Aps_TxNoKeyPair: the crossing has no request to answer here, this replay makes no APSDE request of its own");
    Test_ExpectCount(l->apsTxSecuredFailures, 0, "phase A Aps_TxSecuredFailures: nothing was protected at the APS layer, because nothing was asked to be");
    Test_ExpectCount(l->apsRxSecuredFailuresAuth, 0, "phase A Aps_RxSecuredFailuresAuth: 0, no fixture APDU carries the APS security bit, so 4.4.1.2 was never entered for a fixture frame at this layer");
    Test_ExpectCount(l->apsRxSecuredFailuresCounters, 0, "phase A Aps_RxSecuredFailuresCounters: 0, and the APS `rxSecuredDeferred` row above stays 0 for the same measured reason, the three numbers together are the crossing's regression anchor on this fixture set");
    Test_ExpectCount(l->apsConfirmQueue, 0, "phase A Aps_ConfirmQueue");
    Test_ExpectCount(l->apsTransmitQueue, 0, "phase A Aps_TransmitQueue");
    Test_ExpectCount(l->apsGroupQueue, 0, "phase A Aps_GroupQueue (the table stays empty)");
    Test_ExpectCount(l->apsIndicationQueue, 0, "phase A Aps_IndicationQueue left drained");
}

void pinPrimaryMacRow(const MacView *v)
{
    Test_ExpectCount(v->delivered, 129, "phase A Mac_DataIndicationParameters queue: 129 of the 135 PSDUs delivered upward, measured at the MAC: 10.23.1's promiscuous mode passes every frame correctly received and acknowledges none, and the six whose footer does not compute are not correctly received (6.6.2, 7.2.11)");
    Test_ExpectCount(v->verdictFailing, 0, "phase A: none delivered with a status that is not ZB_OK: every frame the capture cannot vouch for is discarded at the MAC, and the radio reported no duplicate or receive error on it");
    Test_ExpectCount(v->footerRefused, 6, "phase A: six frames whose own octets do not close a frame are counted at the MAC and delivered nowhere, which is 6.6.2's discard and 7.2.11's verification: the five damaged data frames and the truncated command fragment, judged by the footer before its subfields are read as facts");
    Test_ExpectCount(v->refused, 0, "phase A: and nothing reaches the frame type or version tests with a footer that computes and still fails them, which is the order 6.6.2 prints: the fragment's last two octets are not a footer that closes its octets, so the FCS sentence refuses it first");
    Test_ExpectCount(v->headerUnread, 0, "phase A: no delivered frame is left without a parsed header, which is now the property rather than an accident: an unreadable frame never reaches the queue");
    Test_ExpectCount(v->acksHeard, 22, "phase A Mac_Counters.acksHeard at the MAC itself: 22, the ordinary consumption still runs in this mode");
    Test_ExpectCount(v->commandsHeard, 0, "phase A Mac_Counters.commandsHeard at the MAC itself: 0");
    Test_ExpectCount(v->pollEvents, 0, "phase A Mac_PollArrivals at the MAC itself: 0, the Data Requests name 0x0000 and not this 0xfff0 device (6.6.2 c, d)");
    Test_ExpectCount(v->confirms, 0, "phase A: no poll answer was composed, so no poll answer's completion was collected");
}

void phaseA(void)
{
    Rig rig;
    Driven driven;
    Ledger ledger;
    MacView view;

    rigBuild(&rig, OWN_SHORT, 1, KEY_OCTET, KEY_SEQ, 0);
    rigAssert(&rig, OWN_SHORT);

    driveReset(&driven);
    driveReplay(&rig, &s_primary, &driven);
    readLedger(&rig, &driven, &ledger);
    pinPrimary(&ledger);

    measureMacRow(&s_primary, &view);
    pinPrimaryMacRow(&view);

    s_plainPrimary = ledger;
}
