/* The `af` suite's entry point: the framework's descriptor door and its ASDU path. */

#include "test_harness.h"

void caseAfDescriptorDoor(void);
void caseAfDescriptorReregister(void);
void caseAfDataRequestDoor(void);
void caseAfIndicationDispatch(void);
void caseAfAcknowledgedRequestAsksTheAck(void);

int main(void)
{
    Test_Begin("af");

    caseAfDescriptorDoor();
    caseAfDescriptorReregister();
    caseAfDataRequestDoor();
    caseAfIndicationDispatch();
    caseAfAcknowledgedRequestAsksTheAck();

    return Test_Report();
}
