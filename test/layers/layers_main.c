/* The `stack` suite's entry point: a suite is a name and a ledger, not a file, so this file names the run,
   prints the footprint the cases then pin, and drives the cases
   in the one order `test/suite_ledger.json` records. What each case proves lives in the topic case files
   beside it and the machinery they share in `layers_helpers.c`.
   Nothing here asserts anything about the module: the cases do. */

#include <stdio.h>

#include "layers_cases.h"
#include "layers_helpers.h"

#include "test_harness.h"

int main(void)
{
    Test_Begin("stack");

    printf("stack footprint: mac %lu nwk %lu aps %lu security %lu stack %lu\n",
           (unsigned long)sizeof(Mac_Mac), (unsigned long)sizeof(Nwk_Nwk),
           (unsigned long)sizeof(Aps_Aps), (unsigned long)sizeof(Security),
           (unsigned long)sizeof(Zb_Layers));

    caseBuildNamed();
    caseBoundToOwnIeee();
    caseDeviceNamesOwnIeee();
    caseDeviceNamesOtherIeee();
    caseDeviceNamesNoIeee();
    caseRefuseNullSelf();
    caseRefuseNullConfig();
    caseRefuseDeviceType();
    caseRefuseLevelEncOnly();
    caseRefuseLevelAboveMax();
    caseRefuseLevelWithoutSecurity();
    caseRefuseLevelDisagreement();
    caseJoiningEmptyKeySet();
    caseLevelZeroScaffold();
    caseFootprint();
    caseRetryAfterRefusal();
    caseOneStepOneTurn();
    caseDrainsRoute();
    caseEndToEndPair();
    caseJoinNetwork();
    caseCommissioningJoinNetwork();
    caseCommissioningJoinSleepyChild();
    caseRejoinNetwork();
    caseJoinChannelChange();
    caseJoinOrphaning();
    caseTimeoutRequestAfterJoin();
    caseTimeoutRequestAfterRejoin();
    caseChildAgesOutAtTheDefault();
    caseChildPollIsAKeepalive();
    caseUnknownPollerIsAskedToLeave();
    caseSecuredAckBothCrossings();
    caseTransportKeyIsNotNwkSecured();
    caseRefusedStep();
    caseLostReappliesWhatWasApplied();
    caseCaptureRestore();
    caseCaptureRestoreGuards();
    caseSendRefusedAtDoor();
    caseSendCrossingPinsCounters();
    caseSendConfirmAtItsStep();
    caseSendRefusalNamesItsLayer();
    caseSendFrameIsTheLayersWork();
    caseOnAirRigIsTheRecordedDevice();
    caseOnAirUnsecuredFramesAreTheRecordedOctets();
    caseOnAirSecuredFramesAreTheRecordedOctets();
    caseOnAirCopiesAreTheRecordedFrames();
    caseOnAirCopiesArriveAtTheSendingDevice();
    caseOnAirCopiesArriveAtTheRecordedDestination();
    caseDiscardIsReported();

    return Test_Report();
}
