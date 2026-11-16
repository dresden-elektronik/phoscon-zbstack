/* The `nwk_routeflow` suite's case list: every case `nwk_routeflow_main.c` drives, in the one order
   `test/suite_ledger.json` records, so the run order is readable in one place. What each proves lives in the
   six case files beside this header (`cases_rrep.c` for the Route Reply of Figure 3-11, Annex K.3.1.1 and
   3.6.4.5.2.1's forward, `cases_routeflow.c` for 3.6.4.5.1's reception and 3.6.4.5.2's two halves,
   `cases_rreqrelay.c` for 3.6.4.5.1.4's jitter and relay count, `cases_rreqtx.c` for 3.6.4.5.1's initiation
   through the façade, its broadcast schedule and 3.6.4.5.1.7's timer, `cases_rreqflow.c` for the dispatch a
   received request meets and the reply, relay and five drops it leaves, `cases_rrepflow.c` for the dispatch a
   received reply meets and the five discards it leaves) and the machinery they share in
   `nwk_routeflow_helpers.c`. */

#ifndef NWK_ROUTEFLOW_CASES_H
#define NWK_ROUTEFLOW_CASES_H

void caseRrepComposeCarriesFigure311sOctets(void);
void caseRrepComposeWritesFigureK4sTwoOctets(void);
void caseRrepParseRoundTripsTheComposedReply(void);
void caseRrepComposeRefusesAShortBuffer(void);
void caseRrepParseRefusesAShortPayload(void);
void caseRrepParseReadsThroughReservedOptionBits(void);
void caseRrepParseRefusesTheDeprecatedBit(void);
void caseRrepParseRefusesTheThreeOtherIeeeCombinations(void);
void caseRrepParseTakesAnAbsentExtendedRouteInformation(void);
void caseRrepParseTakesTheRequestsThreeOctetForm(void);
void caseRrepParseRefusesADuplicatedTlv(void);
void caseRrepParseRefusesATruncatedTlv(void);
void caseRrepForwardRewritesTheCostAlone(void);

void caseRreqRxDropsWhenThereIsNoNeighbourEntry(void);
void caseRreqRxDropsWhenTheNeighbourHasNoOutgoingCost(void);
void caseRreqRxUsesTheWorseDirection(void);
void caseRreqRxClampsTheForwardCost(void);
void caseRreqRxDedupsOnAGreaterPathCost(void);
void caseRreqRxAnswersForAnEndDeviceChild(void);
void caseRreqRxMakesTheReverseRouteForADestination(void);
void caseRreqRxWritesTable377sFourFields(void);
void caseRreqRxForwardsWithTheRewrittenCost(void);
void caseRreqRxDropsAtAnEndDevice(void);

void caseRreqAnsweredAtTheDestination(void);
void caseRreqRelayedWithTheForwardCost(void);
void caseRreqSecondCopyJudgedOnTheForwardCost(void);
void caseRreqDroppedAtAnEndDevice(void);
void caseRreqDroppedWithoutANeighbourOrAUsableCost(void);
void caseRreqDroppedWhenTheDiscoveryTableIsFull(void);
void caseRreqRelayMarksTheDestinationsRoute(void);
void caseRreqManyToOneKeepsTheConcentratorTlv(void);
void caseRreqChainKeepsTheOriginatorEndToEnd(void);
void caseMeshAirAcknowledgesOnlyBothWays(void);
void caseMeshRouteRequestWaitsForALinkStatus(void);
void caseMeshRouteReplyWaitsForABusyRadio(void);
void caseMeshCoordinatorFindsARouterThatNeverSpoke(void);
void caseMeshRelayDiscoversForItsEndDeviceChild(void);
void caseMeshRelayDiscoversForNoOtherSource(void);
void caseMeshParentClearsItsChildsMark(void);
void caseMeshEndDeviceSendsThroughItsParent(void);
void caseMeshParentAnswersForItsChild(void);
void caseMeshOneWayLinkIsNotUsed(void);
void caseMeshOneWayNeighbourIsTriedDirectly(void);

void caseRrepRxOriginatorTakesTheUnderwayEntry(void);
void caseRrepRxRefusesALoopingReply(void);
void caseRrepRxOriginatorComparesAgainstTheResidualCost(void);
void caseRrepRxOriginatorRemovesTheDiscoveryEntryWithNoRoute(void);
void caseRrepRxWritesTheRespondersRoutingSequenceNumber(void);
void caseRrepRxForwarderComparesAgainstTheResidualCost(void);
void caseRrepRxForwarderActivatesTheUnderwayEntry(void);
void caseRrepRxRepointsAnExistingReverseRoute(void);
void caseRrepRxForwarderWithoutARouteDiscards(void);
void caseRrepRxDiscardsWithNoDiscoveryEntry(void);
void caseRrepRxDiscardsAtAnEndDevice(void);

void caseRrepAtTheOriginatorReleasesTheWaitingRequest(void);
void caseRrepUndefinedLocalTagIsIgnored(void);
void caseRrepCheaperAtTheOriginatorReplacesTheRoute(void);
void caseRrepWithoutARouteRemovesTheDiscoveryEntry(void);
void caseRrepRelayedToTheTableSender(void);
void caseRrepDroppedAtAnEndDevice(void);
void caseRrepDroppedWithNoDiscoveryEntry(void);
void caseRrepDroppedWhenTheForwarderHasNoRoute(void);
void caseRrepDroppedWhenTheForwarderCostIsNotSmaller(void);

void caseNeighborAgesOutOfUse(void);
void caseNoAckComposesTheLinkFailureStatus(void);
void caseRelayRefusedIsAskedAgain(void);
void caseRelayRefusedEveryTimeIsReportedToItsSource(void);
void caseRelayChannelBusyEveryTimeIsReportedToItsSource(void);
void caseRelayNeverOnTheWireBlamesNoNeighbour(void);
void caseFrameLostWithTheRcpBlamesNoNeighbour(void);
void casePassiveAckWithdrawsTheRetransmission(void);
void caseDiscoveryFailureIsRecordedWhileAnotherAttemptLives(void);
void caseAddressMapLearns(void);
void caseAddressMapChangesAreTold(void);
void caseManyToOneFailureHasItsOwnCode(void);

void caseRreqRelayJitterIsInsideTheDoubledBounds(void);
void caseRreqRelayJitterWithNoSeedAnswersZero(void);
void caseRreqRelayCountIsThreePerAttempt(void);

void caseRouteDiscoveryStartsFromTheDataRequest(void);
void caseRouteRequestCarriesTheOriginatorsIeee(void);
void caseRouteDiscoveryIsNotStartedWhenTheRouteExists(void);
void caseRouteDiscoveryIsNotStartedWhenItIsNotAsked(void);
void caseRouteDiscoveryIsNotStartedForABroadcast(void);
void caseRouteDiscoveryIsNotStartedAtAnEndDevice(void);
void caseRouteDiscoveryBroadcastsOnThePrintedSchedule(void);
void caseRouteDiscoveryDoesNotRetryAManyToOneRequest(void);
void caseRouteDiscoveryTimesOut(void);
void caseSecondRequestJoinsTheRunningDiscovery(void);
void caseDiscoveryExpiryAnswersItsOwnRequestOnly(void);
void caseRouteDiscoveryRunsAcrossTheWrap(void);
void caseDiscoveryExpiryForgetsTheSourcesRoute(void);
void caseRouteDiscoveryRefusesAFullDiscoveryTable(void);
void caseTwoDiscoveriesKeepTwoSchedules(void);
void caseTwoRelayedRequestsKeepTwoSchedules(void);
void caseRouteDiscoveryOverAFullRouteTable(void);

#endif /* NWK_ROUTEFLOW_CASES_H */
