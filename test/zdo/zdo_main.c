/* The `zdo` suite's entry point: the device object's server half. */

#include "test_harness.h"

void caseZdoNodeDescriptor(void);
void caseZdoNodeDescriptorStatesFragmentation(void);
void caseZdoActiveEndpoints(void);
void caseZdoSimpleDescriptorStatuses(void);
void caseZdoSimpleDescriptorParseStaysInsideItsRecord(void);
void caseZdoAddresses(void);
void caseZdoAddressesExtended(void);
void caseZdoAddressesForChildren(void);
void caseZdoMatchForEveryoneNamesItself(void);
void caseZdoUnsupportedCommand(void);
void caseZdoDeviceAnnce(void);
void caseZdoClient(void);
void caseZdoBindings(void);
void caseZdoShortBindRequestIsNotSupported(void);
void caseZdoWithoutAnAddressIsNobody(void);
void caseZdoNeighborReport(void);
void caseZdoDeviceAnnceHeard(void);
void caseZdoDeviceAnnceConflicts(void);
void caseZdoRouteReport(void);
void caseZdoBindingReport(void);
void caseZdoParsersStayInsideTheFrame(void);
void caseZdoPermitJoining(void);
void caseZdoLeaveRequest(void);
void caseZdoLeaveRequestRefused(void);
void caseZdoPowerDescriptorOctets(void);

int main(void)
{
    Test_Begin("zdo");

    caseZdoNodeDescriptor();
    caseZdoNodeDescriptorStatesFragmentation();
    caseZdoActiveEndpoints();
    caseZdoSimpleDescriptorStatuses();
    caseZdoSimpleDescriptorParseStaysInsideItsRecord();
    caseZdoAddresses();
    caseZdoAddressesExtended();
    caseZdoAddressesForChildren();
    caseZdoMatchForEveryoneNamesItself();
    caseZdoUnsupportedCommand();
    caseZdoDeviceAnnce();
    caseZdoClient();
    caseZdoBindings();
    caseZdoShortBindRequestIsNotSupported();
    caseZdoWithoutAnAddressIsNobody();
    caseZdoNeighborReport();
    caseZdoDeviceAnnceHeard();
    caseZdoDeviceAnnceConflicts();
    caseZdoRouteReport();
    caseZdoBindingReport();
    caseZdoParsersStayInsideTheFrame();
    caseZdoPermitJoining();
    caseZdoLeaveRequest();
    caseZdoLeaveRequestRefused();
    caseZdoPowerDescriptorOctets();

    return Test_Report();
}
