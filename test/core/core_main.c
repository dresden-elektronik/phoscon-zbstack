/* The `device` suite's entry point: the surface an application stands on. */

#include "test_harness.h"

void caseDeviceEndpointsRegistered(void);
void caseDeviceSimpleDescriptorAnswered(void);
void caseDeviceUnknownEndpointAnswered(void);
void caseDeviceActiveEndpointsAnswered(void);
void caseDeviceApplicationAsduReachesTheRing(void);
void caseDeviceRingHoldsAWholeTurn(void);
void caseDeviceAnnouncementConsumedAndRepublished(void);
void caseDeviceZdpResponseReachesTheApplication(void);
void caseDeviceSendDoorChecksTheSourceEndpoint(void);
void caseDeviceAnnouncesItsJoin(void);
void caseDevicePairAsksTheZdo(void);
void caseTrustCentreRejoinIsOwedTheKey(void);
void caseTrustCentreRejoinWithoutAUniqueKeyIsRefused(void);
void caseSecuredRejoinIsOwedNothing(void);
void caseRouterReportedJoinIsTunnelled(void);
void caseEveryJoinInsideTheSettleIsOwedTheKey(void);
void caseKeyOwedPoolFullRefusesTheNewest(void);
void caseKeyTheDoorRefusesStaysOwed(void);
void caseJoinScansAsOftenAsConfigured(void);
void caseJoinThroughTheFacade(void);
void caseJoinerIsSentTheActiveKey(void);
void caseJoinThroughARouter(void);
void caseJoinerHoldsOnlyTheLinkKey(void);
void caseRemoveThroughARouter(void);
void caseRemoveFollowsTheParentsAddress(void);
void caseChildLeaveIsReported(void);
void caseTrustCentresOwnChildLeaves(void);
void caseParentLostThenRejoined(void);
void caseRouterLinkFailureStartsNothing(void);
void caseParentAnswerEndsTheRun(void);
void caseTrustCentreForgetsALinkKey(void);
void caseRestoreAnnouncesOnlyWhenAsked(void);
void caseTrustCentreNotesEachParent(void);
void caseOnlyAChildsDepartureIsReported(void);
void caseTrustCentreRemovesItsChildAndARouter(void);
void caseDeviceZdpUnderAnotherProfileRefused(void);
void caseDeviceGroupDeliveryFromTheConfig(void);
void caseDeviceGroupMemberWithoutDescriptor(void);
void caseDeviceBeaconAndPermitDoor(void);
void caseDeviceFiltersTheRadio(void);
void caseDeviceAnnouncementCodec(void);

int main(void)
{
    Test_Begin("device");

    caseDeviceEndpointsRegistered();
    caseDeviceSimpleDescriptorAnswered();
    caseDeviceUnknownEndpointAnswered();
    caseDeviceActiveEndpointsAnswered();
    caseDeviceApplicationAsduReachesTheRing();
    caseDeviceRingHoldsAWholeTurn();
    caseDeviceAnnouncementConsumedAndRepublished();
    caseDeviceZdpResponseReachesTheApplication();
    caseDeviceSendDoorChecksTheSourceEndpoint();
    caseDeviceAnnouncesItsJoin();
    caseDevicePairAsksTheZdo();
    caseTrustCentreRejoinIsOwedTheKey();
    caseTrustCentreRejoinWithoutAUniqueKeyIsRefused();
    caseSecuredRejoinIsOwedNothing();
    caseRouterReportedJoinIsTunnelled();
    caseEveryJoinInsideTheSettleIsOwedTheKey();
    caseKeyOwedPoolFullRefusesTheNewest();
    caseKeyTheDoorRefusesStaysOwed();
    caseJoinScansAsOftenAsConfigured();
    caseJoinThroughTheFacade();
    caseJoinThroughARouter();
    caseJoinerIsSentTheActiveKey();
    caseJoinerHoldsOnlyTheLinkKey();
    caseRemoveThroughARouter();
    caseRemoveFollowsTheParentsAddress();
    caseChildLeaveIsReported();
    caseTrustCentresOwnChildLeaves();
    caseTrustCentreNotesEachParent();
    caseOnlyAChildsDepartureIsReported();
    caseTrustCentreRemovesItsChildAndARouter();
    caseDeviceZdpUnderAnotherProfileRefused();
    caseDeviceGroupDeliveryFromTheConfig();
    caseDeviceGroupMemberWithoutDescriptor();
    caseDeviceBeaconAndPermitDoor();
    caseDeviceFiltersTheRadio();
    caseDeviceAnnouncementCodec();
    caseParentLostThenRejoined();
    caseRouterLinkFailureStartsNothing();
    caseParentAnswerEndsTheRun();
    caseTrustCentreForgetsALinkKey();
    caseRestoreAnnouncesOnlyWhenAsked();

    return Test_Report();
}
