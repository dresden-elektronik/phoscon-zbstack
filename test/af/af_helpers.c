#include "af_helpers.h"

#include "test_harness.h"
#include "zb_utils.h"

void afRigBuild(Af_Rig *rig, uint16_t own)
{
    Test_BandAConfig cfg;
    ZbStatus status;

    Zb_memset(rig, 0, (uint32_t)sizeof *rig);

    Test_BandADefaults(&cfg);
    cfg.ownAddress = own;
    cfg.ownExtended = 0x00212effff048a12;
    cfg.panId = AF_PAN_ID;

    status = Test_BandABuild(&rig->stack, &cfg);

    Test_ExpectStatus(status, ZB_OK, "the network layer is given a MAC that already has its backend");
    Test_ExpectStatus(Aps_Init(&rig->aps, &rig->stack.nwk), ZB_OK, "and the APS service adopts it");
    Test_ExpectStatus(Af_Init(&rig->af, &rig->aps), ZB_OK, "and the framework adopts the APS service");
}

Af_SimpleDescriptor afDescriptor(uint8_t endpoint, uint16_t profile, uint16_t inputCluster)
{
    Af_SimpleDescriptor descriptor;

    Zb_memset(&descriptor, 0, (uint32_t)sizeof descriptor);

    descriptor.endpoint = endpoint;
    descriptor.profileId = profile;
    descriptor.deviceId = 0x0000;
    descriptor.deviceVersion = 1;
    descriptor.inputClusterCount = 1;
    descriptor.inputClusters[0] = inputCluster;
    descriptor.outputClusterCount = 1;
    descriptor.outputClusters[0] = inputCluster;

    return descriptor;
}

void afRecord(void *context, const Af_Indication *indication)
{
    Af_Seen *seen = (Af_Seen *)context;

    if (seen == 0)
        return;

    if (seen->count >= AF_SEEN_MAX)
        return;

    seen->indications[seen->count++] = *indication;
}

void afInjectIndication(Aps_Aps *aps, const Aps_Indication *indication)
{
    if (aps == 0 || indication == 0)
        return;

    if (aps->indicationCount >= APS_INDICATION_MAX)
        return;

    aps->indications[(aps->indicationHead + aps->indicationCount) % APS_INDICATION_MAX] = *indication;
    aps->indicationCount++;
}
