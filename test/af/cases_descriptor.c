/* 2.3.2.5's simple descriptor and 2.3.2.5.1's endpoint range: what the framework advertises, what it refuses, and
   what it answers a lookup with. */

#include "af_helpers.h"
#include "test_harness.h"
#include "zb_utils.h"

void caseAfDescriptorDoor(void)
{
    Af_Rig rig;
    Af_SimpleDescriptor descriptor;

    afRigBuild(&rig, AF_OWN_SHORT);

    Test_ExpectCount(Af_EndpointCount(&rig.af), 0, "a fresh framework advertises no endpoint");

    descriptor = afDescriptor(1, AF_PROFILE, AF_CLUSTER);

    Test_ExpectStatus(Af_DescriptorCheck(&descriptor), ZB_OK, "Table 2-40's descriptor for endpoint 1 passes the door");
    Test_ExpectStatus(Af_RegisterEndpoint(&rig.af, &descriptor, 0, 0), ZB_OK, "and registers");
    Test_ExpectCount(Af_EndpointCount(&rig.af), 1, "one endpoint is advertised");

    Test_Expect(Af_DescriptorOf(&rig.af, 1) != 0, "and the lookup finds it by its endpoint number");
    Test_Expect(Af_DescriptorOf(&rig.af, 2) == 0, "while one nobody registered is not found");

    descriptor.endpoint = 0;

    Test_ExpectStatus(Af_DescriptorCheck(&descriptor), ZB_ERR_BAD_ARGUMENT,
                      "2.3.2.5.1: endpoint 0 is the device profile's and not an application's");

    descriptor.endpoint = AF_ENDPOINT_ALL;

    Test_ExpectStatus(Af_DescriptorCheck(&descriptor), ZB_ERR_BAD_ARGUMENT,
                      "and 0xff is the broadcast endpoint, which describes nothing");

    descriptor = afDescriptor(2, AF_PROFILE, AF_CLUSTER);
    descriptor.inputClusterCount = AF_CLUSTER_MAX + 1;

    Test_ExpectStatus(Af_DescriptorCheck(&descriptor), ZB_ERR_BAD_ARGUMENT,
                      "a cluster list longer than the pool is refused rather than truncated");

    descriptor = afDescriptor(2, AF_PROFILE, 0);

    Test_ExpectStatus(Af_DescriptorCheck(&descriptor), ZB_OK,
                      "while cluster 0x0000 is the Basic cluster's identifier and a legal entry in Table 2-40's list");

    descriptor = afDescriptor(2, AF_PROFILE, AF_CLUSTER);
    descriptor.deviceVersion = 0x10;

    Test_ExpectStatus(Af_DescriptorCheck(&descriptor), ZB_ERR_BAD_ARGUMENT,
                      "the device version is Table 2-40's four-bit field and 0x10 does not fit it");
}

void caseAfDescriptorReregister(void)
{
    Af_Rig rig;
    Af_SimpleDescriptor first;
    Af_SimpleDescriptor second;
    Af_Seen seen;

    Zb_memset(&seen, 0, (uint32_t)sizeof seen);

    afRigBuild(&rig, AF_OWN_SHORT);

    first = afDescriptor(1, AF_PROFILE, AF_CLUSTER);
    second = afDescriptor(1, 0x0104, 0x0008);

    Test_ExpectStatus(Af_RegisterEndpoint(&rig.af, &first, 0, 0), ZB_OK, "endpoint 1 registers");
    Test_ExpectStatus(Af_RegisterEndpoint(&rig.af, &second, afRecord, &seen), ZB_OK,
                      "and registering it again replaces the row rather than taking a second one");
    Test_ExpectCount(Af_EndpointCount(&rig.af), 1, "so the pool still holds one endpoint");
    Test_ExpectCount(Af_DescriptorOf(&rig.af, 1)->inputClusters[0], 0x0008, "with the descriptor it was given last");
}
