/* Suite for band A's network layer, both halves of it. The transmit half: what a request is refused for, the
   NPDU an accepted one becomes, where it is aimed, how many times it is tried and how late, and what the layer
   above is handed back when it is done. The receive half: what a frame this device did not send is decided as,
   the radius it arrives with and the one it is read at, the destination group its address puts this device in
   or out of, the broadcast transaction table's dedup and expiry and full policy, the retransmissions a relay
   owes and when they are due, the copies the devices that cannot hear are owed, the commands recognized and the
   one command answered, the neighbor entries a consumed frame leaves and what 3.6.2.3 marks on them, and the
   frames that never become NPDUs at all. Runs on top of the hardware-free backend through band A's own MAC,
   which is the point of the arrangement: no Spinel, no HDLC, no property id, no wall clock and no radio anywhere
   in it (docs/internals/testing.md §2).

   The air side of a frame is what this suite reads, because a network layer's decisions are only observable in
   the frames they produce. Two rig facts shape how. `loopback_radio` reclaims a transmit record as soon as the
   MAC has collected its completion (`loopbackOpCompletion` clears the handle and the next transmit takes that
   slot), so the octets of a frame whose answer has been taken are copied into the case's own air log after every
   request and every turn; a case that read the backend after the step that collected an answer would be reading
   whatever frame came after it. And an injected frame never appears in that log at all: the log is what this
   device transmitted, which is what makes "it was not relayed" a sentence with one meaning in every case below.

   One rig fact decides which rules a receive case can reach at all. `rigAt` states this device's
   macRxOnWhenIdle through the PIB the backend accepted, because Table 3-80 prints one of its five destination
   groups as that attribute rather than as a device type and 3.6.6 opens its sleepy-copy paragraph with a device
   whose own receiver is on. A router rig is a listening rig; the end-device rig is the one that is not.

   The suite is six topic case files and this is the one header that names what they prove: every case `main`
   drives is declared here, in the order it drives them, so the run order is readable in one place. The
   machinery two or more of them share (the air log and its accessors, the rigs, the request and NPDU builders
   and the table accessors) is `nwk_helpers.h` beside it, and what the case files carry is their own prose and
   their own scaffolding. */

#ifndef NWK_CASES_H
#define NWK_CASES_H

void caseUnicastDelivery(void);
void caseRefusedAtTheDoor(void);
void caseDiscoverRouteSubfieldIsTheRequests(void);
void caseUnicastRetryLoop(void);
void caseUnicastRetryAcrossWrap(void);
void caseNoRouteIsAConfirm(void);
void caseRetryOnlyThePrintedStatuses(void);
void caseRefusedTransmitIsAskedAgain(void);
void caseRefusedUntilTheBudgetIsGone(void);
void caseRefusedBroadcastIsHeldAndSentNextTurn(void);
void caseRefusedBroadcastPastItsHoldIsNeverSent(void);
void caseFullPoolIsAConfirm(void);
void caseFullRoutingTableRefusesDiscovery(void);
void caseBroadcastClasses(void);
void caseUnicastToASleepyChildIsHeld(void);
void caseHeldUnicastExpires(void);
void caseHeldUnicastQueueFull(void);
void caseHeldUnicastSurvivesALostExtraction(void);
void caseBroadcastMacDestinationPerClass(void);
void caseLocalBroadcastSleepyCopies(void);
void caseLocalBroadcastClaimsRecord(void);
void caseRadiusDerivation(void);
void caseNoSelfDelivery(void);
void caseSequenceNumberStartsFromTheConfig(void);
void caseReceiveUnicastForMe(void);
void caseRadiusDecrementAndDedup(void);
void caseRadiusExhausted(void);
void caseClassGatesAsRouter(void);
void caseClassGatesAsEndDevice(void);
void caseBroadcastTableExpiryAndFull(void);
void caseBroadcastRetransmissionSchedule(void);
void caseBroadcastJitterBoundAndReproducible(void);
void caseBroadcastJitterDrawsAreBounded(void);
void caseSleepyCopiesOnRelay(void);
void caseBroadcastAskingForDiscoveryIsRead(void);
void caseCommandRecognitionAndUnknownReply(void);
void caseLostChildMark(void);
void caseUnreadableAndUnsupportedFrames(void);
void casePollCarrierIsNotAnNpdu(void);
void caseMulticastFrameIsRefusedOnReceipt(void);
void caseIndicationIsBoundedByTable34sNsduLength(void);
void caseUnicastNetworkStatusIsRelayed(void);
void caseBroadcastSourceIsRefused(void);
void caseNetworkStatusAtTheDestinationRemovesTheRoute(void);
void caseNetworkStatusRelayedToAChildRemovesTheRoute(void);
void caseUnknownCommandStatusRemovesNothing(void);
void caseUnknownCommandReplyToARestingChildIsHeld(void);
void caseHeldRelayExpiryIsALinkFailure(void);
void caseTwoHeldRelaysKeepTheirOwnRecords(void);
void caseHeldRelayWithoutAConfirmAgesOut(void);
void caseNetworkStatusAtAnEndDeviceOnlyIndicates(void);
void caseBroadcastWithAFullBttIsRefused(void);
void caseSleepyCopiesFollowTheRole(void);
void caseSecuredUnicastEndToEnd(void);
void caseSecuredTamperRejected(void);
void caseSecuredUnicastReplayRefused(void);
void caseSecuredBroadcastDuplicateProof(void);
void caseSecuredRetryResecuresEveryAttempt(void);
void caseSecuredBroadcastRelayResecures(void);
void caseSecuredSleepyCopiesEachProtected(void);
void caseSecuredUnknownCommandReply(void);
void caseSecuredRouteRecord(void);
void caseUnsecuredDiscardWhileAuthenticated(void);
void caseUnsecuredRejoinOnABroadcastIsDropped(void);
void caseAuthenticatedHopPromotion(void);
void caseProtectionRefusedIsAConfirm(void);
void caseAttachAndDetach(void);
void caseSecuredCommandEmptyPlaintextIsDamage(void);
void caseBeaconInfoOctets(void);
void caseOnlyAParentAnswersABeaconRequest(void);
void caseRejoinRequestIsAccepted(void);
void caseRejoinRequestIsAnsweredWhileJoiningIsNotPermitted(void);
void caseRejoinRequestAddressMismatchIsDenied(void);
void caseRejoinRefusalWritesNothingIntoTheMatchedEntry(void);
void caseRejoinRequestAtASecuredDeviceIsDeniedUnsecured(void);
void caseRejoinRequestAtCapacity(void);
void caseRejoinResponseIsAccepted(void);
void caseRejoinResponseFromAnotherParentIsDropped(void);
void caseRejoinResponseWithNoAddressFails(void);
void caseSecurityTimerCounts(void);
void caseJoinKeyWaitTimesOut(void);
void caseParentDeletesUnauthorizedChild(void);
void caseParentIndicatesOnlyADeliveredAnswer(void);
void caseJoinTriesTheNextParent(void);
void caseJoinDefaultTriesOneParent(void);
void caseJoinOneParentIsNotRetried(void);
void caseJoinNextParentRefusedEndsTheJoin(void);
void caseRejoinTriesTheNextParent(void);
void caseRejoinNextParentAnswers(void);
void caseRejoinOfTheParentItHoldsIsOneAttempt(void);
void caseRejoinNextParentRefusedEndsTheRejoin(void);
void caseRejoinFollowsTheParentsChannel(void);
void caseCommissioningRequestCapabilityOctet(void);
void caseTheBeaconChoosesTheAttachMechanism(void);
void caseDiscoveryEntryFromABeacon(void);
void caseDiscoveryRanksTheParents(void);
void caseJoinAsksTheBestRankedParent(void);
void caseCommissioningToAParentKnownByItsShortAddress(void);
void caseNetworkDiscoveryFillsTheTable(void);
void caseNetworkDiscoveryRepeatKeepsTheTable(void);
void caseEdScanReportsEachChannel(void);
void caseEdScanRefusedOnANetwork(void);
void caseNetworkDiscoveryRefusesBadRequests(void);
void caseCommissioningJoinTimesOut(void);
void caseTheBeaconChoosesTheRejoinMechanism(void);
void caseCommissioningRejoinIsAnswered(void);
void caseRejoinToAParentKnownByItsShortAddress(void);
void caseCommissioningAnswerMustNameBothEnds(void);
void caseCommissioningRefusalGivesThePibBack(void);
void caseCommissioningSleepyJoinerPolls(void);
void caseCommissioningConflictAsksAgain(void);
void caseCommissioningSecondConflictFails(void);
void caseCommissioningTriesTheNextParent(void);
void caseCommissioningConflictIsNotAnAttempt(void);
void caseCommissioningRequestHeldWhileTheDoorIsFull(void);
void caseJoinFrameDroppedAfterTheWait(void);
void caseUnsecuredTransportKeyAccepted(void);
void caseAliasedRequestWritesTheAlias(void);
void caseLocalConflictIsAnnounced(void);
void caseLocalConflictNeedsNoOwnRow(void);
void caseOwnRouteRequestRelayedBackIsNoConflict(void);
void caseReaddressChild(void);
void caseSecuredLeaveRequestHeld(void);
void caseSecuredTimeoutResponse(void);
void caseSecuredTimeoutRequest(void);
void caseSleepyChildPollsAtItsRate(void);
void caseSleepyChildPollsFastWhileAttaching(void);
void caseSleepyChildPollsAgainWhenMoreIsHeld(void);
void caseSyncRetriesOnChannelAccessFailure(void);
void caseSleepyChildReportsAnUnansweredPoll(void);
void caseSyncRefusedOffANetwork(void);
void caseSecuredCommissioningResponse(void);
void caseTimeoutRequestSurvivesARefusal(void);
void caseUnsecuredCommissioningRequest(void);
void caseUnsecuredCommissioningResponseAccepted(void);
void caseCommissioningAnswerHeldForASleepyJoiner(void);
void caseCommissioningAnswerHeldWhileTheDoorIsFull(void);
void caseCommissioningInitialJoinRefused(void);
void caseUnsecuredRejoinChildExpires(void);
void caseUnsecuredCommissioningRejoinRefusedWithoutATrustCentre(void);
void caseSecuredInitialJoinDropped(void);
void caseCommissioningMatchesAKnownDevice(void);
void caseCommissioningAddressHeldByAnother(void);
void caseConfirmRingCannotOverflow(void);
void caseForeignUnicastRreqIsNotConsumed(void);
void caseSourceRouteVerdicts(void);
void caseEndDeviceInitiatorSet(void);
void caseParentLinkFailure(void);
void caseRestoredEndDeviceKeepalive(void);
void caseLinkStatusMetrics(void);
void caseLinkStatusApply(void);
void caseLinkStatusCoverage(void);
void caseLinkStatusEndDeviceIgnores(void);
void caseLinkStatusRefusedIsAskedAgain(void);
void caseLinkStatusEmptyAndItsAnswer(void);
void caseLinkStatusCompose(void);
void caseLinkStatusComposeSplits(void);
void caseLinkStatusSplitOnTheAir(void);
void caseLinkStatusFrameOnTheAir(void);
void caseLinkStatusWaitsForTheKey(void);
void caseRouteRecordCodec(void);
void caseRouteRecordOrigin(void);
void caseRouteRecordOnTheAir(void);
void caseRouteRecordFromANeighbourReplacesTheRoute(void);
void caseSourceRoutedFrameOnTheAir(void);
void caseSourceRouteYieldsToTheRoutingTable(void);
void caseSourceRouteSeedHoldsUntilARecord(void);
void caseRouteRecordNoticesTheTable(void);
void caseCommissioningCodec(void);
void caseCommissioningMalformed(void);
void caseCommissioningParentAnswers(void);
void caseTimeoutTable(void);
void caseNeighborRank(void);
void caseNeighborMakeRoom(void);
void caseLinkStatusRouterAge(void);
void caseNeighborActivityCounters(void);
void caseLinkStatusFullTable(void);
void caseNeighborPromoteBackbone(void);
void caseBackboneSiblingHoldsItsPlace(void);
void caseOriginatedBroadcastIsRepeated(void);
void caseOwnSourceBroadcastNeedsDeliveryTime(void);
void caseBeaconPayloadCarriesTheRouterInformation(void);
void caseBeaconAppendixStepsOverOtherRecords(void);
void casePassiveAckStopsOwnBroadcast(void);
void caseEndDeviceBroadcastGoesToItsParent(void);
void caseLeaveCommandCodec(void);
void caseLeaveOwnRemoval(void);
void caseLeaveWithRejoinKeepsTheNetwork(void);
void caseLeaveRemovesAChild(void);
void caseLeaveAnnouncementHeard(void);
void caseLeaveRequestValidation(void);
void caseLeaveRequestNamesTheChild(void);
void caseLeaveBroadcastRequestIsDropped(void);
void caseLeaveRouterRepeatsItsParentsAnnouncement(void);
void caseLeaveRouterIsNoLongerANeighbour(void);
void caseLeaveAJoinedRouterHasNoParentAndIsNoChild(void);
void caseOrphanRejoinTakesTheRealignment(void);
void caseOrphanRejoinUnanswered(void);
void caseParentRealignsItsOrphanedChild(void);
void caseRejoinRouterFindsTheSiblingItJoined(void);
void caseLeaveEndDeviceHearsItsParentAnnounce(void);
void casePermitJoining(void);
void casePermitJoiningRefusedForAnEndDevice(void);
void casePermitJoiningWithoutBeaconInfo(void);

#endif /* NWK_CASES_H */
