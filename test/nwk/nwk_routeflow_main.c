/* The `nwk_routeflow` suite's entry point: a suite is a name and a ledger, not a file, so this file names the
   run and drives its cases in the one order
   `test/suite_ledger.json` records. What each of them proves lives in the six topic case files beside it
   (`cases_rrep.c`, `cases_routeflow.c`, `cases_rreqrelay.c`, `cases_rreqtx.c`, `cases_rreqflow.c`,
   `cases_rrepflow.c`) and the
   machinery they share in `nwk_routeflow_helpers.c` and in the `nwk` suite's `nwk_helpers.c`. The cases are the
   only thing here that asserts. */

#include "nwk_routeflow_cases.h"
#include "test_harness.h"

int main(void)
{
    Test_Begin("nwk_routeflow");

    caseRrepComposeCarriesFigure311sOctets();
    caseRrepComposeWritesFigureK4sTwoOctets();
    caseRrepParseRoundTripsTheComposedReply();
    caseRrepComposeRefusesAShortBuffer();
    caseRrepParseRefusesAShortPayload();
    caseRrepParseReadsThroughReservedOptionBits();
    caseRrepParseRefusesTheDeprecatedBit();
    caseRrepParseRefusesTheThreeOtherIeeeCombinations();
    caseRrepParseTakesAnAbsentExtendedRouteInformation();
    caseRrepParseTakesTheRequestsThreeOctetForm();
    caseRrepParseRefusesADuplicatedTlv();
    caseRrepParseRefusesATruncatedTlv();
    caseRrepForwardRewritesTheCostAlone();

    caseRreqRxDropsWhenThereIsNoNeighbourEntry();
    caseRreqRxDropsWhenTheNeighbourHasNoOutgoingCost();
    caseRreqRxUsesTheWorseDirection();
    caseRreqRxClampsTheForwardCost();
    caseRreqRxAnswersForAnEndDeviceChild();
    caseRreqRxDedupsOnAGreaterPathCost();
    caseRreqRxMakesTheReverseRouteForADestination();
    caseRreqRxWritesTable377sFourFields();
    caseRreqRxForwardsWithTheRewrittenCost();
    caseRreqRxDropsAtAnEndDevice();

    caseRreqAnsweredAtTheDestination();
    caseRreqRelayedWithTheForwardCost();
    caseRreqSecondCopyJudgedOnTheForwardCost();
    caseRreqDroppedAtAnEndDevice();
    caseRreqDroppedWithoutANeighbourOrAUsableCost();
    caseRreqDroppedWhenTheDiscoveryTableIsFull();
    caseRreqRelayMarksTheDestinationsRoute();
    caseRreqManyToOneKeepsTheConcentratorTlv();
    caseRreqChainKeepsTheOriginatorEndToEnd();
    caseMeshAirAcknowledgesOnlyBothWays();
    caseMeshRouteRequestWaitsForALinkStatus();
    caseMeshRouteReplyWaitsForABusyRadio();
    caseMeshCoordinatorFindsARouterThatNeverSpoke();
    caseMeshRelayDiscoversForItsEndDeviceChild();
    caseMeshRelayDiscoversForNoOtherSource();
    caseMeshParentClearsItsChildsMark();
    caseMeshEndDeviceSendsThroughItsParent();
    caseMeshParentAnswersForItsChild();
    caseMeshOneWayLinkIsNotUsed();
    caseMeshOneWayNeighbourIsTriedDirectly();

    caseRrepRxOriginatorTakesTheUnderwayEntry();
    caseRrepRxRefusesALoopingReply();
    caseRrepRxOriginatorComparesAgainstTheResidualCost();
    caseRrepRxOriginatorRemovesTheDiscoveryEntryWithNoRoute();
    caseRrepRxWritesTheRespondersRoutingSequenceNumber();
    caseRrepRxForwarderComparesAgainstTheResidualCost();
    caseRrepRxForwarderActivatesTheUnderwayEntry();
    caseRrepRxRepointsAnExistingReverseRoute();
    caseRrepRxForwarderWithoutARouteDiscards();
    caseRrepRxDiscardsWithNoDiscoveryEntry();
    caseRrepRxDiscardsAtAnEndDevice();

    caseRrepAtTheOriginatorReleasesTheWaitingRequest();
    caseRrepUndefinedLocalTagIsIgnored();
    caseRrepCheaperAtTheOriginatorReplacesTheRoute();
    caseRrepWithoutARouteRemovesTheDiscoveryEntry();
    caseRrepRelayedToTheTableSender();
    caseRrepDroppedAtAnEndDevice();
    caseRrepDroppedWithNoDiscoveryEntry();
    caseRrepDroppedWhenTheForwarderHasNoRoute();
    caseRrepDroppedWhenTheForwarderCostIsNotSmaller();

    caseNeighborAgesOutOfUse();
    caseNoAckComposesTheLinkFailureStatus();
    caseRelayRefusedIsAskedAgain();
    caseRelayRefusedEveryTimeIsReportedToItsSource();
    caseRelayChannelBusyEveryTimeIsReportedToItsSource();
    caseRelayNeverOnTheWireBlamesNoNeighbour();
    caseFrameLostWithTheRcpBlamesNoNeighbour();
    casePassiveAckWithdrawsTheRetransmission();
    caseDiscoveryFailureIsRecordedWhileAnotherAttemptLives();
    caseAddressMapLearns();
    caseAddressMapChangesAreTold();
    caseManyToOneFailureHasItsOwnCode();

    caseRreqRelayJitterIsInsideTheDoubledBounds();
    caseRreqRelayJitterWithNoSeedAnswersZero();
    caseRreqRelayCountIsThreePerAttempt();

    caseRouteDiscoveryStartsFromTheDataRequest();
    caseRouteRequestCarriesTheOriginatorsIeee();
    caseRouteDiscoveryIsNotStartedWhenTheRouteExists();
    caseRouteDiscoveryIsNotStartedWhenItIsNotAsked();
    caseRouteDiscoveryIsNotStartedForABroadcast();
    caseRouteDiscoveryIsNotStartedAtAnEndDevice();
    caseRouteDiscoveryBroadcastsOnThePrintedSchedule();
    caseRouteDiscoveryDoesNotRetryAManyToOneRequest();
    caseRouteDiscoveryTimesOut();
    caseSecondRequestJoinsTheRunningDiscovery();
    caseDiscoveryExpiryAnswersItsOwnRequestOnly();
    caseRouteDiscoveryRunsAcrossTheWrap();
    caseDiscoveryExpiryForgetsTheSourcesRoute();
    caseRouteDiscoveryRefusesAFullDiscoveryTable();
    caseTwoDiscoveriesKeepTwoSchedules();
    caseTwoRelayedRequestsKeepTwoSchedules();
    caseRouteDiscoveryOverAFullRouteTable();

    return Test_Report();
}
