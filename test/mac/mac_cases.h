/* Suite for band A's MAC: the frame it composes is the frame this PAN is measured carrying, the source
   comes from its own PIB, the acknowledgment request is refused where it cannot be answered, and what came
   back is reported rather than interpreted. Runs against the hardware-free backend (loopback_radio), which
   is the point of that backend existing.

   The suite is seven topic case files and this is the one header that names what they prove:
   every case `main` drives is declared here, in the order it drives them, so the run order
   is readable in one place. What each case file carries is its own prose and the scaffolding
   only its cases use (the one Frame Control Field a composition case names, the captured
   octets a delivery case reads, the poll and the air log's own accessors the indirect
   queue needs) and the machinery three or more of them share is `mac_helpers.h` beside it. */

#ifndef MAC_CASES_H
#define MAC_CASES_H

void caseAdoption(void);
void caseDsnStartComesFromTheConfig(void);
void caseShortAddressRangeChoosesTheSource(void);
void caseComposition(void);
void caseAcknowledgementPolicy(void);
void caseActiveScanVisitsEachChannel(void);
void caseActiveScanKeepsEveryBeacon(void);
void caseActiveScanStatuses(void);
void caseActiveScanRefusesBadRequests(void);
void caseEnergyScanMeasuresEachChannel(void);
void caseEnergyScanTakesThePeakOfItsDwells(void);
void caseEnergyScanNeedsADwell(void);
void caseOrphanScanNotifiesEachChannel(void);
void caseOrphanScanTakesTheRealignment(void);
void caseOrphanNotificationIsAnswered(void);
void caseDirectFrameCarriesItsRetries(void);
void caseConfirmations(void);
void caseConfirmCarriesTheAcksFramePending(void);
void casePollAckWithoutPendingIsNoData(void);
void casePollWithPendingDeliversTheFrame(void);
void casePollWindowEndsWithNoData(void);
void casePollEmptyAnswerIsNoData(void);
void casePollWithoutAReportedBitListens(void);
void casePollAnswerBeforeItsCompletion(void);
void casePollNotAcknowledged(void);
void casePollHearsWhatTheConfigurationKeeps(void);
void casePollLeavesAnotherDataRequestsWindowOpen(void);
void caseCompletionThatNeverArrives(void);
void caseDelivery(void);
void caseTrackPool(void);

/* The coordinator half of the poll, in the order the machinery works: what enters the queue, what a Data
   Request takes out of it, what happens to an attempt that was not answered, what an empty queue answers
   instead, what a busy pool answers instead (the track pool and the poll-event ring beside it) how long
   anything is held, and which frames are polls at all. Then the backend underneath all of it: what a step
   does when the seam says its device is gone, and what it owes that device when it answers again. */
void caseIndirectEnqueue(void);
void caseIndirectIgnoredWithoutRole(void);
void casePendingTableFollowsTheQueue(void);
void caseUnacknowledgedExtractionLeavesTheQueue(void);
void caseExtractionIsNotRetransmitted(void);
void caseAssociationLearnsThePair(void);
void caseAssociationOutcomeIsCommStatus(void);
void caseExpiredTransactionReportsItsOwnPrimitive(void);
void casePollExtractionOrder(void);
void caseRefusedExtractionKeepsItsNumber(void);
void caseTimedOutExtractionReleasesItsAttempt(void);
void caseEmptyPollAnswer(void);
void caseEmptyPollEndedByTheAck(void);
void caseOwnDataRequestIsNotAnswered(void);
void casePollAnsweredWithoutAParentRole(void);
void casePollAtAnUnassociatedDeviceIsNotAnswered(void);
void caseBeaconRequestIsAnswered(void);
void caseBeaconReplyHeldWhileTheDoorIsFull(void);
void caseBeaconRequestComposes(void);
void caseBeaconFormsRefused(void);
void caseBeaconPollTakesTheListedForm(void);
void caseBeaconPollOwedDespitePayload(void);
void caseBeaconStatesThePendingDevices(void);
void caseBeaconPendingListIsSevenAddresses(void);
void caseBeaconOneAnswerPerRequest(void);
void caseBeaconNamingThisDeviceMakesItPoll(void);
void caseBeaconWithoutPayloadIsNotIndicated(void);
void caseBeaconRequestsNotAnswered(void);
void caseBeaconRequestIsNotDelivered(void);
void caseZeroSourceIsNotThisDevice(void);
void caseAttemptOutstanding(void);
void casePollWithTrackPoolFull(void);
void casePollAnswerRefusedByTheRadio(void);
void casePollArrivalRingFull(void);
void caseTransactionPersistence(void);
void caseTransactionConfirmsItsOutcome(void);
void caseCommandTransactionsStatePending(void);
void caseSourcelessPoll(void);
void casePollForAnotherDeviceIsNotAnswered(void);
void caseDataRequestWithContent(void);
void caseDestinationlessPollNeedsPanCoordinator(void);
void caseAssociationResponseBroadcastRefused(void);
void caseExtendedAddressZeroIsNoAddress(void);

/* The parent's association doors: the request as an indication, the answer as the indirect transaction the
   child polls for and its pinned/validated fields, the shapes this device declines, the destination-less form,
   and the extended source the answer requires. */
void caseAssociationRequestIsIndicated(void);
void caseAssociationResponseIsIndirect(void);
void caseAssociationResponsePinsPending(void);
void caseAssociationResponseRefuses(void);
void caseAssociationRequestIsDeclined(void);
void caseAssociationRequestDestinationless(void);
void caseAssociationRequestBadFcs(void);
void caseAssociationRequestForeignSourcePan(void);
void caseAssociationRequestAddressedForeignSourcePan(void);
void caseAssociationRequestDestinationPanSource(void);
void caseAssociationResponseNeedsAnExtendedSource(void);
void caseAssociationRequestContentLength(void);

/* The child's half of the same exchange, in the order 10.21.2 runs it: the request 10.21.5.1 prints, the wait
   its acknowledgment starts and the Data Request that ends it, the parent's answer stored and its refusals, an
   answer that never comes, the capability bits this stack will not claim, the address the request cannot be made
   without, and the answer from a device that is not the parent. */
void caseChildAssociationRequestIsComposed(void);
void caseChildAssociationSucceeds(void);
void caseChildAssociationRefused(void);
void caseChildAssociationTimesOut(void);
void caseChildAssociationRestartsAfterAFailure(void);
void caseChildAssociationTimesOutWithoutRingRoom(void);
void caseChildAssociationRefusesCapabilities(void);
void caseChildAssociationNeedsAnAddress(void);
void caseChildAssociationIgnoresForeignAnswer(void);
void caseChildAssociationRestoresPibWhenNothingWasSent(void);
void caseChildAssociationHeldWhileTheDoorIsFull(void);
void caseChildAssociationHeldWhileThePibWriteIsRefused(void);
void caseChildAssociationPibWriteRefusedPastTheHold(void);
void caseChildAssociationRequestNotAcknowledged(void);
void caseChildAssociationWithoutAnAddress(void);
void caseChildAssociationAnswerOnTheDeadline(void);

void caseClassAddressesAreUnicast(void);
void caseHeardAckIsConsumed(void);
void caseHeardCommandIsCounted(void);
void caseLostReapplication(void);

/* The same episode on a band A that applied nothing but the adoption: nothing owed, nothing handed down, and no
   PIB request of any kind reaching the backend, while the device it never addressed still answers the poll in
   front of it. */
void caseLostWithNothingApplied(void);
void caseLostRestatesTheDeliveryMode(void);

/* The known answer two RCPs put on the air: the RCP the transcripts armed, the frames they composed and
   sent on channel 26 read back as the octets their own transcripts printed, and the frames the second RCP
   delivered read back as the fields its transcript dissected. */
void caseOnAirBackendIsTheMeasuredRcp(void);
void caseOnAirCompositionIsTheCapturedFrame(void);
void caseOnAirReceiptIsTheCapturedFields(void);

#endif /* MAC_CASES_H */
