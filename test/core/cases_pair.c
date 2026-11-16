/* The `device` suite's pair case: one device asks another's ZDO through the one send door, and reads the answer out
   of the one poll. This is the shape the bench tool runs, on two models instead of two RCPs. */

#include <stdint.h>

#include "core_helpers.h"
#include "test_harness.h"
#include "zb_utils.h"
#include "zdo.h"
#include "nwk.h"
#include "aps.h"
#include <stdio.h>

void caseDevicePairAsksTheZdo(void)
{
    DevicePair pair;
    Af_SimpleDescriptor descriptor;
    Aps_ApsdeReq request;
    Aps_Indication indication;
    Af_SimpleDescriptor parsed;
    uint8_t asdu[4];
    uint32_t turns;

    devicePairAt(&pair);

    deviceDescriptor(&descriptor, DEVICE_EP_FIRST);
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&pair.server, &descriptor), ZB_OK, "the server advertises an endpoint");

    asdu[0] = 0x40;
    asdu[1] = (uint8_t)(DEVICE_SERVER_SHORT & 0xff);
    asdu[2] = (uint8_t)(DEVICE_SERVER_SHORT >> 8);
    asdu[3] = DEVICE_EP_FIRST;

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.dstAddrMode = APS_ADDR_MODE_SHORT;
    request.dstAddress = DEVICE_SERVER_SHORT;
    request.dstEndpoint = ZDO_ENDPOINT;
    request.profileId = ZDO_PROFILE_ID;
    request.clusterId = ZDO_SIMPLE_DESC_REQ;
    request.srcEndpoint = ZDO_ENDPOINT;
    request.asdu = asdu;
    request.asduLength = 4;
    request.txOptions = AF_TX_ACKNOWLEDGED;

    Test_ExpectStatus(Zb_CoreSendRequest(&pair.asker, &request, 1000), ZB_OK,
                      "the asking device sends Simple_Desc_req through the one door");

    for (turns = 0; turns < 6; turns++)
        devicePairTurn(&pair, 1000 + turns * 100);


    printf("DBG srv noRoute %u routeQueue %u apsRefused %u acksGenerated %u acksRefused %u retransmitRefusals %u unmatchedAcks %u\n",
           Nwk_DroppedNoRoute(Zb_CoreNwk(&pair.server)), Nwk_RouteQueue(Zb_CoreNwk(&pair.server)),
           Aps_RefusedRequests(Zb_CoreAps(&pair.server)), Aps_AcksGenerated(Zb_CoreAps(&pair.server)),
           Aps_AcksRefused(Zb_CoreAps(&pair.server)), Aps_RetransmitRefusals(Zb_CoreAps(&pair.server)),
           Aps_UnmatchedAcks(Zb_CoreAps(&pair.server)));

    Test_ExpectCount(Zb_CoreZdpFramesConsumed(&pair.server), 2,
                     "the serving device takes the request, and the asker's announcement beside it");
    Test_ExpectCount(Zdo_ResponsesSent(&pair.server.zdo), 1, "and answers it");
    Test_ExpectCount(Zdo_ResponsesRefused(&pair.server.zdo), 0, "with nothing refused");

    Test_ExpectCount(Zb_CorePollIndications(&pair.asker, &indication, 1), 1, "the answer reaches the asker's ring");
    Test_ExpectCount(indication.clusterId, ZDO_SIMPLE_DESC_REQ | ZDO_RESPONSE_BIT, "on the cluster it answered on");
    Test_ExpectCount(indication.asdu[0], 0x40, "with the sequence number the asker wrote");
    Test_ExpectStatus(Zdo_SimpleDescriptorParse(indication.asdu + 1, indication.asduLength - 1, &parsed), ZB_OK,
                      "and the record reads back as a descriptor");
    Test_ExpectCount(parsed.endpoint, DEVICE_EP_FIRST, "the endpoint the asker named");
    Test_ExpectCount(parsed.profileId, DEVICE_PROFILE_ID, "with the profile the server registered");
}

/* The object's own gate: a ZDP identifier under another profile is not a ZDP command, and the refusal is counted
   rather than silent, which is what a bench instrument needs when an answer never comes. */
void caseDeviceZdpUnderAnotherProfileRefused(void)
{
    DevicePair pair;
    Af_SimpleDescriptor descriptor;
    Aps_ApsdeReq request;
    uint8_t asdu[4];
    uint32_t turns;

    devicePairAt(&pair);

    deviceDescriptor(&descriptor, DEVICE_EP_FIRST);
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&pair.server, &descriptor), ZB_OK, "the server advertises an endpoint");
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&pair.asker, &descriptor), ZB_OK,
                      "and so does the asker, since the frame must come from an endpoint it advertises");

    asdu[0] = 0x41;
    asdu[1] = (uint8_t)(DEVICE_SERVER_SHORT & 0xff);
    asdu[2] = (uint8_t)(DEVICE_SERVER_SHORT >> 8);
    asdu[3] = DEVICE_EP_FIRST;

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.dstAddrMode = APS_ADDR_MODE_SHORT;
    request.dstAddress = DEVICE_SERVER_SHORT;
    request.dstEndpoint = ZDO_ENDPOINT;
    request.profileId = DEVICE_PROFILE_ID;
    request.clusterId = ZDO_SIMPLE_DESC_REQ;
    request.srcEndpoint = DEVICE_EP_FIRST;
    request.asdu = asdu;
    request.asduLength = 4;

    Test_ExpectStatus(Zb_CoreSendRequest(&pair.asker, &request, 1000), ZB_OK,
                      "a Simple_Desc_req under an application profile is sent");

    for (turns = 0; turns < 6; turns++)
        devicePairTurn(&pair, 1000 + turns * 100);

    Test_ExpectCount(Zdo_FramesRefused(&pair.server.zdo), 1,
                     "and the object refuses it, because a ZDP command is the device profile's");
    Test_ExpectCount(Zdo_ResponsesSent(&pair.server.zdo), 0, "with nothing answered");
}
