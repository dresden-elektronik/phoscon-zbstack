/* The `mac` suite's entry point: a suite is a name and a ledger, not a file,
   so this file names the run and drives the cases in
   the one order `test/suite_ledger.json` records. What each of them proves lives in the nine topic case files
   beside it (`cases_build.c`, `cases_confirm.c`, `cases_delivery.c`, `cases_indirect.c`, `cases_scan.c`,
   `cases_association.c`, `cases_child.c`, `cases_reapply.c`, `cases_onair.c`) and the machinery three or more of
   them share in `mac_helpers.c`. Nothing here asserts anything: what the cases prove, they assert. */

#include "mac_cases.h"
#include "test_harness.h"

int main(void)
{
    Test_Begin("mac");

    caseAdoption();
    caseDsnStartComesFromTheConfig();
    caseShortAddressRangeChoosesTheSource();
    caseComposition();
    caseAcknowledgementPolicy();
    caseDirectFrameCarriesItsRetries();
    caseConfirmations();
    caseConfirmCarriesTheAcksFramePending();
    casePollAckWithoutPendingIsNoData();
    casePollWithPendingDeliversTheFrame();
    casePollWindowEndsWithNoData();
    casePollEmptyAnswerIsNoData();
    casePollWithoutAReportedBitListens();
    casePollAnswerBeforeItsCompletion();
    casePollNotAcknowledged();
    casePollHearsWhatTheConfigurationKeeps();
    casePollLeavesAnotherDataRequestsWindowOpen();
    caseCompletionThatNeverArrives();
    caseDelivery();
    caseTrackPool();

    caseIndirectEnqueue();
    caseIndirectIgnoredWithoutRole();
    casePendingTableFollowsTheQueue();
    caseUnacknowledgedExtractionLeavesTheQueue();
    caseExtractionIsNotRetransmitted();
    caseAssociationLearnsThePair();
    caseAssociationOutcomeIsCommStatus();
    caseExpiredTransactionReportsItsOwnPrimitive();
    casePollExtractionOrder();
    caseRefusedExtractionKeepsItsNumber();
    caseTimedOutExtractionReleasesItsAttempt();
    caseEmptyPollAnswer();
    caseEmptyPollEndedByTheAck();
    caseOwnDataRequestIsNotAnswered();
    casePollAnsweredWithoutAParentRole();
    casePollAtAnUnassociatedDeviceIsNotAnswered();
    caseBeaconRequestComposes();
    caseBeaconFormsRefused();
    caseBeaconPollTakesTheListedForm();
    caseBeaconPollOwedDespitePayload();
    caseBeaconRequestIsAnswered();
    caseActiveScanVisitsEachChannel();
    caseActiveScanKeepsEveryBeacon();
    caseActiveScanStatuses();
    caseActiveScanRefusesBadRequests();
    caseEnergyScanMeasuresEachChannel();
    caseEnergyScanTakesThePeakOfItsDwells();
    caseEnergyScanNeedsADwell();
    caseOrphanScanNotifiesEachChannel();
    caseOrphanScanTakesTheRealignment();
    caseOrphanNotificationIsAnswered();
    caseBeaconReplyHeldWhileTheDoorIsFull();
    caseBeaconStatesThePendingDevices();
    caseBeaconPendingListIsSevenAddresses();
    caseBeaconOneAnswerPerRequest();
    caseBeaconNamingThisDeviceMakesItPoll();
    caseBeaconWithoutPayloadIsNotIndicated();
    caseBeaconRequestsNotAnswered();
    caseBeaconRequestIsNotDelivered();
    caseZeroSourceIsNotThisDevice();
    caseAttemptOutstanding();
    casePollWithTrackPoolFull();
    casePollAnswerRefusedByTheRadio();
    casePollArrivalRingFull();
    caseTransactionPersistence();
    caseTransactionConfirmsItsOutcome();
    caseCommandTransactionsStatePending();
    caseSourcelessPoll();
    casePollForAnotherDeviceIsNotAnswered();
    caseDataRequestWithContent();
    caseDestinationlessPollNeedsPanCoordinator();
    caseAssociationResponseBroadcastRefused();
    caseExtendedAddressZeroIsNoAddress();

    caseAssociationRequestIsIndicated();
    caseAssociationResponseIsIndirect();
    caseAssociationResponsePinsPending();
    caseAssociationResponseRefuses();
    caseAssociationRequestIsDeclined();
    caseAssociationRequestDestinationless();
    caseAssociationRequestBadFcs();
    caseAssociationRequestForeignSourcePan();
    caseAssociationRequestAddressedForeignSourcePan();
    caseAssociationRequestDestinationPanSource();
    caseAssociationResponseNeedsAnExtendedSource();
    caseAssociationRequestContentLength();

    caseChildAssociationRequestIsComposed();
    caseChildAssociationSucceeds();
    caseChildAssociationRefused();
    caseChildAssociationTimesOut();
    caseChildAssociationRestartsAfterAFailure();
    caseChildAssociationTimesOutWithoutRingRoom();
    caseChildAssociationRefusesCapabilities();
    caseChildAssociationNeedsAnAddress();
    caseChildAssociationIgnoresForeignAnswer();
    caseChildAssociationRestoresPibWhenNothingWasSent();
    caseChildAssociationHeldWhileTheDoorIsFull();
    caseChildAssociationHeldWhileThePibWriteIsRefused();
    caseChildAssociationPibWriteRefusedPastTheHold();
    caseChildAssociationRequestNotAcknowledged();
    caseChildAssociationWithoutAnAddress();
    caseChildAssociationAnswerOnTheDeadline();

    caseClassAddressesAreUnicast();
    caseHeardAckIsConsumed();
    caseHeardCommandIsCounted();
    caseLostReapplication();
    caseLostWithNothingApplied();
    caseLostRestatesTheDeliveryMode();

    caseOnAirBackendIsTheMeasuredRcp();
    caseOnAirCompositionIsTheCapturedFrame();
    caseOnAirReceiptIsTheCapturedFields();

    return Test_Report();
}
