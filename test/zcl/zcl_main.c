/* The `zcl` suite's entry point: the foundation frame and the Basic cluster's read path. */

#include "test_harness.h"

void caseZclFrameCodec(void);
void caseZclBasicAttributes(void);
void caseZclReadAttributes(void);
void caseZclClientRead(void);
void caseZclReadBounds(void);
void caseZclPayloadCodecs(void);

int main(void)
{
    Test_Begin("zcl");

    caseZclFrameCodec();
    caseZclBasicAttributes();
    caseZclReadAttributes();
    caseZclClientRead();
    caseZclReadBounds();
    caseZclPayloadCodecs();

    return Test_Report();
}
