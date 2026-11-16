/* The `zdo_client` suite's entry point: the device object's client half, built with ZB_ZDO_CLIENT. */

#include "test_harness.h"

void caseClientDiscoveryRequests(void);
void caseClientNodeDescReqStatesFragmentation(void);
void caseClientAddressResponses(void);
void caseClientMatchAndStatus(void);

int main(void)
{
    Test_Begin("zdo_client");

    caseClientDiscoveryRequests();
    caseClientNodeDescReqStatesFragmentation();
    caseClientAddressResponses();
    caseClientMatchAndStatus();

    return Test_Report();
}
