#include "zdo_helpers.h"

#include "test_harness.h"
#include "zb_utils.h"

void zdoRigBuild(Zdo_Rig *rig)
{
    Zdo_NodeDescriptor node;
    Zdo_PowerDescriptor power;
    Test_BandAConfig cfg;
    ZbStatus status;

    Zb_memset(rig, 0, (uint32_t)sizeof *rig);

    Test_BandADefaults(&cfg);
    cfg.ownAddress = ZDO_OWN_SHORT;
    cfg.ownExtended = ZDO_OWN_IEEE;
    cfg.panId = ZDO_PAN_ID;

    status = Test_BandABuild(&rig->stack, &cfg);

    Test_ExpectStatus(status, ZB_OK, "the network layer is given a MAC that already has its backend");
    Test_ExpectStatus(Aps_Init(&rig->aps, &rig->stack.nwk), ZB_OK, "and the APS service adopts it");
    Test_ExpectStatus(Af_Init(&rig->af, &rig->aps), ZB_OK, "and the framework adopts the APS service");

    Zdo_NodeDescriptorDefaults(&node, ZDO_LOGICAL_ROUTER, 0x1037);
    Zdo_PowerDescriptorDefaults(&power);

    Test_ExpectStatus(Zdo_Init(&rig->zdo, &rig->af, ZDO_OWN_SHORT, ZDO_OWN_IEEE, &node, &power), ZB_OK,
                      "and the device object adopts the framework");
}

void zdoDeliver(Zdo_Rig *rig, uint16_t cluster, const uint8_t *asdu, uint32_t asduLength, uint32_t nowMs)
{
    Af_Indication indication;

    Zb_memset(&indication, 0, (uint32_t)sizeof indication);

    indication.dstEndpoint = ZDO_ENDPOINT;
    indication.srcEndpoint = ZDO_PEER_ENDPOINT;
    indication.srcAddress = ZDO_PEER_SHORT;
    indication.profileId = ZDO_PROFILE_ID;
    indication.clusterId = cluster;
    indication.asduLength = asduLength;
    indication.status = 0;

    if (asduLength != 0)
        Zb_memcpy(indication.asdu, asdu, asduLength);

    (void)Zdo_HandleIndication(&rig->zdo, &indication, nowMs);
}

void zdoDeliverCommand(Zdo_Rig *rig, uint16_t cluster, const uint8_t *payload, uint32_t payloadLen, uint32_t nowMs)
{
    uint8_t asdu[ZDO_ASDU_MAX];

    if (payloadLen + 1 > (uint32_t)sizeof asdu)
        return;

    asdu[0] = 0x21;     /* 2.4.2.8.1's transaction sequence number, which the answer must copy */

    if (payloadLen != 0)
        Zb_memcpy(asdu + 1, payload, payloadLen);

    zdoDeliver(rig, cluster, asdu, payloadLen + 1, nowMs);
}

void zdoDeliverBroadcast(Zdo_Rig *rig, uint16_t cluster, const uint8_t *payload, uint32_t payloadLen,
                         uint32_t nowMs)
{
    Af_Indication indication;

    Zb_memset(&indication, 0, (uint32_t)sizeof indication);

    indication.dstEndpoint = ZDO_ENDPOINT;
    indication.dstAddrMode = APS_ADDR_MODE_SHORT;
    indication.dstAddress = 0xffff;
    indication.srcEndpoint = ZDO_PEER_ENDPOINT;
    indication.srcAddress = ZDO_PEER_SHORT;
    indication.profileId = ZDO_PROFILE_ID;
    indication.clusterId = cluster;
    indication.asduLength = payloadLen + 1;
    indication.status = 0;

    indication.asdu[0] = 0x21;

    if (payloadLen != 0)
        Zb_memcpy(indication.asdu + 1, payload, payloadLen);

    (void)Zdo_HandleIndication(&rig->zdo, &indication, nowMs);
}
