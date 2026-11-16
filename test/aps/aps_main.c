/* The `aps` suite's entry point: a suite is a name and a ledger, not a file,
   so this file names the run and drives the 33 cases in
   the one order `test/suite_ledger.json` records. What each of them proves lives in the seven topic case files
   beside it (`cases_door.c`, `cases_confirm.c`, `cases_ack.c`, `cases_tx.c`, `cases_group.c`, `cases_rx.c`,
   `cases_security.c`) and the machinery two of them share in `aps_helpers.c`. Nothing here asserts anything: the
   cases do. */

#include "aps_cases.h"
#include "test_harness.h"

int main(void)
{
    Test_Begin("aps");

    caseDoorMatrix();
    caseConfirmVocabularyRefusals();
    caseUnicastNoAck();
    caseConfirmCarriesTheCallersTag();
    caseCounterSequence();
    caseAckHappyPath();
    caseAckMismatchSweep();
    caseRetransmissionShape();
    caseNwkPrecedence();
    caseBroadcastDelivery();
    caseGroupSend();
    caseRxDecided();
    casePoolPolicy();

    caseUnicastIndication();
    caseAckOwedEndToEnd();
    caseBroadcastEndpointPassedUp();
    caseGroupFanOut();
    caseGroupDeliveryUnfiltered();
    caseGroupServiceMatrix();
    caseDuplicateRejection();
    caseSecuredDeferred();
    caseCommandDeferred();
    caseFragmentedUnsupported();
    caseShapeRefused();
    caseMalformedApdu();
    caseIndicationRingPressure();

    caseSecuredUnicastOut();
    caseSecuredInVectors();
    caseSecuredEndToEndPair();
    caseSecuredRetransmissionReprotects();
    caseSecuredReplayRefused();
    caseSecuredTamperRefused();
    caseSecuredNoKeyPair();
    caseSecuredShapesDeferred();
    caseSecuredNoPartnerNamed();
    caseSecuredGlobalPairSender();

    caseTransportKeyComposed();
    caseTransportKeyReceipts();
    caseTransportKeyRequestRefusals();
    caseTransportKeyInstalled();
    caseTransportKeyAuthorizes();
    caseTransportKeyAcknowledged();
    caseTcLinkKeyExchange();
    caseTransportKeyUnderTheGlobalKeyAfterJoining();
    caseTcLinkKeyConfirmFailureGivesUp();
    caseTransportKeyTeachesTheTrustCentre();
    caseUpdateDeviceAtTheTrustCentre();
    caseUpdateDeviceUnencryptedRefused();
    caseUpdateDeviceAwayFromTheTrustCentre();
    caseUpdateDeviceDoor();
    caseTransportKeyTunnelled();
    caseRouterReportsAJoin();
    caseRouterRelaysATunnel();
    caseCommandAcknowledgedInFormatOne();
    caseRemoveDeviceSent();
    caseRouterTakesARemoveDevice();
    caseAddressMapBothWays();
    caseBoundRequest();

    return Test_Report();
}
