/* The `state` suite's entry point: a suite is a name and a ledger, not a
   file, so this file names the run and drives the 23 cases in
   the one order `test/suite_ledger.json` records. What each case proves lives in the three topic case files
   beside it (`cases_capture.c`, `cases_restore.c` and `cases_security.c`) and the machinery they share in
   `state_helpers.c`. Nothing here asserts anything about the module: the cases do. */

#include "state_cases.h"
#include "state_helpers.h"

int main(void)
{
    Test_Begin("state");

    caseCaptureFresh();
    caseCaptureCounts();
    caseArgumentRefusals();
    caseRoundTrip();
    caseCountsAuthoritative();
    caseIdentityNotIndex();
    caseVersionRefused();
    caseDuplicatesRefused();
    caseZeroNamesRefused();
    caseCountersMoveForward();
    caseKeysOptIn();
    caseKeyWithoutDescriptorRefused();
    caseCounterBankOverflow();
    caseTablesNotWiped();
    caseChildRestoredWithAFullPeriod();
    caseSecurityRestoreRefusals();
    caseRoutingSequenceRoundTrip();
    caseRoutingSequenceForwardOnly();
    caseRoutingSequenceRefused();
    caseGlobalPairRoundTrip();
    caseTrustCentreConfigurationKept();
    caseTrustCentreAddressPersisted();
    caseExtendedPanOctetOrder();
    caseRoleMustMatch();
    caseEndDeviceComesBackJoined();
    caseAddressMapSeededFromTheState();

    return Test_Report();
}
