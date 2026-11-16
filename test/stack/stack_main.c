/* The `stack` suite: the object an application meets, driven over loopback models and a pseudo-terminal answering as a
   RCP does, read only through its events (docs/internals/decisions.md). */

#include "test_harness.h"

void caseStackVersionStringIsItsNumbers(void);
void caseStackStartRefusesWhatItCannotStartFrom(void);
void caseStackCoordinatorComesUp(void);
void caseStackCoordinatorWithoutEntropyNamesItsKey(void);
void caseStackRouterJoinsAndTheyTalk(void);
void caseStackEndDeviceJoinsAndTheyTalk(void);
void caseStackSleepyEndDeviceJoinsAndTheyTalk(void);
void caseStackSleepyEndDeviceRestoresAndRejoins(void);
void caseStackForgottenEndDeviceRejoins(void);
void caseStackParallelSendsComeBackByTag(void);
void caseStackDeviceObjectSendsAreItsOwn(void);
void caseStackDeviceObjectAnswersMatchAndUnsupported(void);
void caseStackRequestsToItselfAreLoopedBack(void);
void caseStackDrawsFromTheApplicationsEntropy(void);
void caseStackSourceRoutesAreSeededAndTold(void);
void caseStackDeparturesAreTold(void);
void caseStackAddressesAreTold(void);
#if ZB_ZDO_CLIENT
void caseStackZdoRequestsAreNumberedByTheDeviceObject(void);
#endif
void caseStackRcpThatMissesAResetStillComesUp(void);
void caseStackRcpThatNeverAnswersFailsItsStart(void);
void caseStackRcpGoneQuietIsLostAndComesBack(void);
void caseStackRcpUnpluggedIsLostAndComesBack(void);
void caseStackCoordinatorComesBackFromItsState(void);
void caseStackRouterComesBackFromItsState(void);
void caseStackEndDeviceComesBackFromItsState(void);
void caseStackRestoredEndDeviceRejoinsWhenItsParentIsGone(void);
void caseStackRecordsReachTheApplicationsLog(void);
void caseStackRouterJoinsAgainAfterAReset(void);
void caseStackEnergyScanReportsEachChannel(void);
void caseStackEnergyScanNeedsARadioThatMeasures(void);
void caseStackJoinerTakesItsOwnLinkKey(void);
void caseStackJoinerKeepsItsJoinedKey(void);
void caseStackJoinerGivesUpOnASilentTrustCentre(void);

int main(void)
{
    Test_Begin("stack");

    caseStackVersionStringIsItsNumbers();
    caseStackStartRefusesWhatItCannotStartFrom();
    caseStackCoordinatorComesUp();
    caseStackCoordinatorWithoutEntropyNamesItsKey();
    caseStackRouterJoinsAndTheyTalk();
    caseStackEndDeviceJoinsAndTheyTalk();
    caseStackSleepyEndDeviceJoinsAndTheyTalk();
    caseStackSleepyEndDeviceRestoresAndRejoins();
    caseStackForgottenEndDeviceRejoins();
    caseStackParallelSendsComeBackByTag();
    caseStackDeviceObjectSendsAreItsOwn();
    caseStackDeviceObjectAnswersMatchAndUnsupported();
    caseStackRequestsToItselfAreLoopedBack();
    caseStackDrawsFromTheApplicationsEntropy();
    caseStackSourceRoutesAreSeededAndTold();
    caseStackDeparturesAreTold();
    caseStackAddressesAreTold();
#if ZB_ZDO_CLIENT
    caseStackZdoRequestsAreNumberedByTheDeviceObject();
#endif
    caseStackRcpThatMissesAResetStillComesUp();
    caseStackRcpThatNeverAnswersFailsItsStart();
    caseStackRcpGoneQuietIsLostAndComesBack();
    caseStackRcpUnpluggedIsLostAndComesBack();
    caseStackCoordinatorComesBackFromItsState();
    caseStackRouterComesBackFromItsState();
    caseStackEndDeviceComesBackFromItsState();
    caseStackRestoredEndDeviceRejoinsWhenItsParentIsGone();
    caseStackRecordsReachTheApplicationsLog();
    caseStackRouterJoinsAgainAfterAReset();
    caseStackEnergyScanReportsEachChannel();
    caseStackEnergyScanNeedsARadioThatMeasures();
    caseStackJoinerTakesItsOwnLinkKey();
    caseStackJoinerKeepsItsJoinedKey();
    caseStackJoinerGivesUpOnASilentTrustCentre();

    return Test_Report();
}
