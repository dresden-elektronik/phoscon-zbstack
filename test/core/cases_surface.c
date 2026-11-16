/* The `device` suite's surface cases: the registry the device object answers from, the routing rule that keeps
   endpoint 0 out of the application's ring, the one frame the object republishes, and the send door's source check. */

#include <stdint.h>

#include "aps_frame.h"
#include "core_helpers.h"
#include "test_harness.h"
#include "zb_utils.h"
#include "nwk_permit.h"
#include "zdo.h"

/* A ZDP request as a peer sends it: the device profile, endpoint 0, the command's own cluster, and the transaction
   sequence number first in the ASDU (2.4.2.8.1). */
static void zdpFrame(Aps_Frame *frame, uint16_t cluster, uint8_t dstEndpoint)
{
    Zb_memset(frame, 0, (uint32_t)sizeof *frame);

    frame->frameType = APS_FRAME_TYPE_DATA;
    frame->deliveryMode = APS_DELIVERY_UNICAST;
    frame->ackRequest = 0;
    frame->dstEndpointPresent = 1;
    frame->dstEndpoint = dstEndpoint;
    frame->clusterPresent = 1;
    frame->clusterId = cluster;
    frame->profilePresent = 1;
    frame->profileId = ZDO_PROFILE_ID;
    frame->srcEndpointPresent = 1;
    frame->srcEndpoint = DEVICE_EP_FIRST;
    frame->apsCounter = 0x30;
}

/* 2.3.2.5's descriptor door: the range 2.3.2.5.1 prints, Table 2-40's own bounds, and one entry per endpoint. */
void caseDeviceEndpointsRegistered(void)
{
    DeviceRig rig;
    Af_SimpleDescriptor descriptor;

    deviceRigBuild(&rig);

    Test_ExpectCount(Zb_CoreEndpointCount(&rig.dev), 1,
                     "a device starts with the device profile's endpoint and nothing else");

    deviceDescriptor(&descriptor, DEVICE_EP_FIRST);

    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_OK, "an application endpoint registers");
    Test_ExpectCount(Zb_CoreEndpointCount(&rig.dev), 2, "and the table holds it beside endpoint 0");

    deviceDescriptor(&descriptor, DEVICE_EP_SECOND);

    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_OK, "a second one registers too");
    Test_ExpectCount(Zb_CoreEndpointCount(&rig.dev), 3, "three rows, one of them the device profile's");

    deviceDescriptor(&descriptor, ZDO_ENDPOINT);
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_ERR_BAD_ARGUMENT,
                      "endpoint 0 is the device profile's and not an application's");

    deviceDescriptor(&descriptor, 0xff);
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_ERR_BAD_ARGUMENT,
                      "and 0xff is the broadcast endpoint, which is no endpoint at all");

    deviceDescriptor(&descriptor, DEVICE_EP_FIRST);
    descriptor.deviceVersion = AF_DEVICE_VERSION_MAX + 1;
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_ERR_BAD_ARGUMENT,
                      "Table 2-40's device version is four bits");

    deviceDescriptor(&descriptor, DEVICE_EP_FIRST);
    descriptor.inputClusterCount = AF_CLUSTER_MAX + 1;
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_ERR_BAD_ARGUMENT,
                      "and a cluster list longer than this stack's own table is refused");

    deviceDescriptor(&descriptor, DEVICE_EP_FIRST);
    descriptor.deviceId = 0x0202;

    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_OK,
                      "registering an endpoint twice replaces it rather than adding a second row");
    Test_ExpectCount(Zb_CoreEndpointCount(&rig.dev), 3, "so the count does not move");
}

/* 2.4.3.1.9's Simple_Desc_req answered out of the registry, and the frame is the device object's and not the
   application's. */
void caseDeviceSimpleDescriptorAnswered(void)
{
    DeviceRig rig;
    Aps_Frame frame;
    Af_SimpleDescriptor descriptor;
    Af_SimpleDescriptor parsed;
    uint8_t asdu[32];
    uint32_t asduLength = 0;
    uint16_t cluster = 0;
    uint8_t request[4];

    deviceRigBuild(&rig);
    deviceDescriptor(&descriptor, DEVICE_EP_FIRST);
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_OK, "the endpoint registers");

    request[0] = 0x21;
    request[1] = (uint8_t)(DEVICE_OWN_SHORT & 0xff);
    request[2] = (uint8_t)(DEVICE_OWN_SHORT >> 8);
    request[3] = DEVICE_EP_FIRST;

    zdpFrame(&frame, ZDO_SIMPLE_DESC_REQ, ZDO_ENDPOINT);
    devicePeerSends(&rig, &frame, request, 4, 1000);

    deviceStep(&rig, 1000);

    Test_ExpectCount(Zb_CoreZdpFramesConsumed(&rig.dev), 1, "the frame is the device object's");
    Test_ExpectCount(Zb_CorePollIndications(&rig.dev, 0, 0), 0, "and never reaches the application's ring");
    Test_Expect(deviceAnswer(&rig, (uint16_t)(ZDO_SIMPLE_DESC_REQ | ZDO_RESPONSE_BIT), &cluster, asdu,
                             (uint32_t)sizeof asdu, &asduLength, 0) == 1,
                "the answer goes out on the cluster the request named, with its response bit set");
    Test_ExpectCount(cluster, ZDO_SIMPLE_DESC_REQ | ZDO_RESPONSE_BIT, "which is that cluster");
    Test_ExpectCount(asdu[0], 0x21, "and it copies the transaction sequence number");
    Test_ExpectCount(asdu[1], ZDO_STATUS_SUCCESS, "with SUCCESS");
    Test_ExpectCount(asdu[4], asduLength - 5, "and the descriptor's own length beside it");

    Test_ExpectStatus(Zdo_SimpleDescriptorParse(asdu + 1, asduLength - 1, &parsed), ZB_OK,
                      "the record reads back as Table 2-40's descriptor");
    Test_ExpectCount(parsed.endpoint, DEVICE_EP_FIRST, "the endpoint the request named");
    Test_ExpectCount(parsed.profileId, DEVICE_PROFILE_ID, "the profile the application registered");
    Test_ExpectCount(parsed.deviceId, descriptor.deviceId, "the device identifier");
    Test_ExpectCount(parsed.inputClusterCount, 1, "one input cluster");
    Test_ExpectCount(parsed.inputClusters[0], DEVICE_INPUT_CLUSTER, "which is the one the descriptor names");
    Test_ExpectCount(parsed.outputClusters[0], DEVICE_OUTPUT_CLUSTER, "and the output cluster beside it");
}

/* An endpoint the registry does not hold is answered, and answered as absent: the table is the only source. */
void caseDeviceUnknownEndpointAnswered(void)
{
    DeviceRig rig;
    Aps_Frame frame;
    uint8_t asdu[16];
    uint32_t asduLength = 0;
    uint8_t request[4];

    deviceRigBuild(&rig);

    request[0] = 0x22;
    request[1] = (uint8_t)(DEVICE_OWN_SHORT & 0xff);
    request[2] = (uint8_t)(DEVICE_OWN_SHORT >> 8);
    request[3] = 0x07;

    zdpFrame(&frame, ZDO_SIMPLE_DESC_REQ, ZDO_ENDPOINT);
    devicePeerSends(&rig, &frame, request, 4, 1000);
    deviceStep(&rig, 1000);

    Test_Expect(deviceAnswer(&rig, (uint16_t)(ZDO_SIMPLE_DESC_REQ | ZDO_RESPONSE_BIT), 0, asdu,
                             (uint32_t)sizeof asdu, &asduLength, 0) == 1, "the request is answered");
    Test_ExpectCount(asdu[1], ZDO_STATUS_NOT_ACTIVE, "with the status that means the endpoint is not active here");
    Test_ExpectCount(asduLength, 5, "and nothing after it, because there is no descriptor to send");
}

/* 2.4.3.1.10's Active_EP_req: the list is the registry's application endpoints, in the order the table prints. */
void caseDeviceActiveEndpointsAnswered(void)
{
    DeviceRig rig;
    Af_SimpleDescriptor descriptor;
    Aps_Frame frame;
    uint8_t asdu[16];
    uint8_t endpoints[8];
    uint32_t asduLength = 0;
    uint32_t count;
    uint8_t request[3];

    deviceRigBuild(&rig);

    deviceDescriptor(&descriptor, DEVICE_EP_FIRST);
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_OK, "one endpoint registers");
    deviceDescriptor(&descriptor, DEVICE_EP_SECOND);
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_OK, "and a second");

    request[0] = 0x23;
    request[1] = (uint8_t)(DEVICE_OWN_SHORT & 0xff);
    request[2] = (uint8_t)(DEVICE_OWN_SHORT >> 8);

    zdpFrame(&frame, ZDO_ACTIVE_EP_REQ, ZDO_ENDPOINT);
    devicePeerSends(&rig, &frame, request, 3, 1000);
    deviceStep(&rig, 1000);

    Test_Expect(deviceAnswer(&rig, (uint16_t)(ZDO_ACTIVE_EP_REQ | ZDO_RESPONSE_BIT), 0, asdu, (uint32_t)sizeof asdu,
                             &asduLength, 0) == 1, "the answer goes out");

    count = Zdo_ActiveEndpointsParse(asdu + 1, asduLength - 1, endpoints, (uint32_t)sizeof endpoints);

    Test_ExpectCount(count, 2, "and names both application endpoints");
    Test_ExpectCount(endpoints[0], DEVICE_EP_FIRST, "the first");
    Test_ExpectCount(endpoints[1], DEVICE_EP_SECOND, "and the second, the device profile's endpoint not among them");
}

/* One turn can hand the application as many frames as the APS ring holds, and the application's ring takes them all:
   none is dropped between the two rings. */
void caseDeviceRingHoldsAWholeTurn(void)
{
    DeviceRig rig;
    Af_SimpleDescriptor descriptor;
    Aps_Frame frame;
    Aps_Indication indication;
    uint8_t asdu[1];
    uint32_t taken = 0;
    uint32_t i;

    deviceRigBuild(&rig);
    deviceDescriptor(&descriptor, DEVICE_EP_FIRST);
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_OK, "the endpoint registers");

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = APS_FRAME_TYPE_DATA;
    frame.deliveryMode = APS_DELIVERY_UNICAST;
    frame.dstEndpointPresent = 1;
    frame.dstEndpoint = DEVICE_EP_FIRST;
    frame.clusterPresent = 1;
    frame.clusterId = DEVICE_INPUT_CLUSTER;
    frame.profilePresent = 1;
    frame.profileId = DEVICE_PROFILE_ID;
    frame.srcEndpointPresent = 1;
    frame.srcEndpoint = DEVICE_EP_SECOND;

    for (i = 0; i < APS_INDICATION_MAX; i++)
    {
        frame.apsCounter = (uint8_t)(0x40 + i);
        asdu[0] = (uint8_t)i;
        devicePeerSends(&rig, &frame, asdu, 1, 1000);
    }

    deviceStep(&rig, 1000);

    while (Zb_CorePollIndications(&rig.dev, &indication, 1) == 1)
        taken++;

    Test_ExpectCount(taken, APS_INDICATION_MAX, "every frame of the turn waits for the application");
    Test_ExpectCount(Zb_CoreIndicationsDropped(&rig.dev), 0, "and none was dropped on the way");
}

/* An ASDU for an application endpoint is the application's: it waits in the ring and the device object never
   answers it. */
void caseDeviceApplicationAsduReachesTheRing(void)
{
    DeviceRig rig;
    Af_SimpleDescriptor descriptor;
    Aps_Frame frame;
    Aps_Indication indication;
    uint8_t asdu[2];

    deviceRigBuild(&rig);
    deviceDescriptor(&descriptor, DEVICE_EP_FIRST);
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_OK, "the endpoint registers");

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = APS_FRAME_TYPE_DATA;
    frame.deliveryMode = APS_DELIVERY_UNICAST;
    frame.dstEndpointPresent = 1;
    frame.dstEndpoint = DEVICE_EP_FIRST;
    frame.clusterPresent = 1;
    frame.clusterId = DEVICE_INPUT_CLUSTER;
    frame.profilePresent = 1;
    frame.profileId = DEVICE_PROFILE_ID;
    frame.srcEndpointPresent = 1;
    frame.srcEndpoint = DEVICE_EP_SECOND;
    frame.apsCounter = 0x31;

    asdu[0] = 0xaa;
    asdu[1] = 0xbb;

    devicePeerSends(&rig, &frame, asdu, 2, 1000);
    deviceStep(&rig, 1000);

    Test_ExpectCount(Zb_CoreZdpFramesConsumed(&rig.dev), 0, "a frame for an application endpoint is not the ZDO's");
    Test_ExpectCount(Zb_CorePollIndications(&rig.dev, &indication, 1), 1, "it waits in the ring");
    Test_ExpectCount(indication.dstEndpoint, DEVICE_EP_FIRST, "named for the endpoint it was addressed to");
    Test_ExpectCount(indication.srcEndpoint, DEVICE_EP_SECOND, "with the source endpoint the peer used");
    Test_ExpectCount(indication.clusterId, DEVICE_INPUT_CLUSTER, "the cluster it carried");
    Test_ExpectCount(indication.profileId, DEVICE_PROFILE_ID, "and the profile");
    Test_ExpectCount(indication.asduLength, 2, "two octets of ASDU");
    Test_Expect(indication.asdu[0] == 0xaa && indication.asdu[1] == 0xbb, "which are the ones the peer sent");
    Test_ExpectCount(Zb_CorePollIndications(&rig.dev, &indication, 1), 0, "and the ring is empty again");
    Test_Expect(deviceAnswer(&rig, 0, 0, 0, 0, 0, 0) == 0, "with nothing put on the air for it");
}

/* 2.4.3.1.11's announcement, broadcast to the ZDO endpoint 0x00 (D-217), is the device object's. It is the one
   frame the object republishes for the application. */
void caseDeviceAnnouncementConsumedAndRepublished(void)
{
    DeviceRig rig;
    Aps_Frame frame;
    Aps_Indication indication;
    uint8_t asdu[12];

    deviceRigBuild(&rig);

    Zb_memset(asdu, 0, (uint32_t)sizeof asdu);

    asdu[0] = 0x24;
    asdu[1] = 0x17;
    asdu[2] = 0x16;
    asdu[3] = 0x15;
    asdu[4] = 0x14;
    asdu[5] = 0x13;
    asdu[6] = 0x12;
    asdu[7] = 0x11;
    asdu[8] = 0x10;
    asdu[9] = (uint8_t)(DEVICE_PEER_SHORT & 0xff);
    asdu[10] = (uint8_t)(DEVICE_PEER_SHORT >> 8);
    asdu[11] = 0x80;

    zdpFrame(&frame, ZDO_DEVICE_ANNCE, ZDO_ENDPOINT);
    frame.deliveryMode = APS_DELIVERY_BROADCAST;
    devicePeerSends(&rig, &frame, asdu, 12, 1000);
    deviceStep(&rig, 1000);

    Test_ExpectCount(Zb_CoreZdpFramesConsumed(&rig.dev), 1,
                     "a broadcast to the ZDO endpoint carrying a ZDP cluster is the device object's");
    Test_ExpectCount(Zdo_AnnouncementsHeard(&rig.dev.zdo), 1, "and the object heard the announcement");
    Test_ExpectCount(Zb_CoreAnnouncementsRepublished(&rig.dev), 1, "which it hands on to the application");
    Test_ExpectCount(Zb_CorePollIndications(&rig.dev, &indication, 1), 1, "so the ring holds it");
    Test_ExpectCount(indication.clusterId, ZDO_DEVICE_ANNCE, "as the announcement it is");
    Test_ExpectCount(indication.dstEndpoint, ZDO_ENDPOINT, "addressed to the ZDO endpoint it was broadcast to, as a TRÅDFRI bulb sends it");
}

/* D-212's source check: endpoint 0 is the library's, any other must be registered, and the request reaches the
   APS service unchanged. */
void caseDeviceSendDoorChecksTheSourceEndpoint(void)
{
    DeviceRig rig;
    Af_SimpleDescriptor descriptor;
    Aps_ApsdeReq request;
    uint8_t asdu[3];

    deviceRigBuild(&rig);
    deviceDescriptor(&descriptor, DEVICE_EP_FIRST);
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_OK, "the endpoint registers");

    asdu[0] = 0x25;
    asdu[1] = 0x00;
    asdu[2] = 0x00;

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.dstAddrMode = APS_ADDR_MODE_SHORT;
    request.dstAddress = DEVICE_PEER_SHORT;
    request.dstEndpoint = ZDO_ENDPOINT;
    request.profileId = ZDO_PROFILE_ID;
    request.clusterId = ZDO_ACTIVE_EP_REQ;
    request.srcEndpoint = 0x05;
    request.asdu = asdu;
    request.asduLength = 3;

    Test_ExpectStatus(Zb_CoreSendRequest(&rig.dev, &request, 1000), ZB_ERR_NOT_FOUND,
                      "a request from an endpoint this device does not advertise is refused");
    Test_Expect(deviceAnswer(&rig, 0, 0, 0, 0, 0, 0) == 0, "and nothing reaches the air for it");

    request.srcEndpoint = DEVICE_EP_FIRST;
    Test_ExpectStatus(Zb_CoreSendRequest(&rig.dev, &request, 1000), ZB_OK,
                      "from a registered endpoint the same request is taken");

    deviceStep(&rig, 1000);

    Test_Expect(deviceAnswer(&rig, 0, 0, 0, 0, 0, 0) == 1, "and put on the air by the device's turn");

    request.srcEndpoint = ZDO_ENDPOINT;
    Test_ExpectStatus(Zb_CoreSendRequest(&rig.dev, &request, 2000), ZB_OK,
                      "endpoint 0 is the device object's, so an application asking another device's ZDO goes out from it");
}

/* 2.4.3.1.11.1: a device on a network announces itself once, and a coordinator does not. */
void caseDeviceAnnouncesItsJoin(void)
{
    DeviceRig rig;
    uint8_t asdu[16];
    uint32_t asduLength = 0;

    deviceRigBuildRouter(&rig);

    deviceStep(&rig, 1000);

    Test_ExpectCount(Zdo_AnnouncementsSent(&rig.dev.zdo), 1, "a router announces itself once it is on a network");
    Test_Expect(deviceAnswer(&rig, ZDO_DEVICE_ANNCE, 0, asdu, (uint32_t)sizeof asdu, &asduLength, 0) == 1,
                "and the announcement is on the air");

    deviceStep(&rig, 2000);

    Test_ExpectCount(Zdo_AnnouncementsSent(&rig.dev.zdo), 1, "and not again on the next turn");

    deviceRigBuild(&rig);
    deviceStep(&rig, 1000);

    Test_ExpectCount(Zdo_AnnouncementsSent(&rig.dev.zdo), 0, "a coordinator announces nothing");
}

/* A ZDP response carries its request's identifier with bit 15 set, and it is the application's: the object answers
   requests and the application correlates what comes back (D-210). */
void caseDeviceZdpResponseReachesTheApplication(void)
{
    DeviceRig rig;
    Aps_Frame frame;
    Aps_Indication indication;
    uint8_t asdu[8];

    deviceRigBuild(&rig);

    Zb_memset(asdu, 0, (uint32_t)sizeof asdu);

    asdu[0] = 0x26;
    asdu[1] = ZDO_STATUS_SUCCESS;

    zdpFrame(&frame, (uint16_t)(ZDO_SIMPLE_DESC_REQ | ZDO_RESPONSE_BIT), ZDO_ENDPOINT);
    devicePeerSends(&rig, &frame, asdu, 2, 1000);
    deviceStep(&rig, 1000);

    Test_ExpectCount(Zb_CoreZdpFramesConsumed(&rig.dev), 0, "a response is not a request, so the object does not take it");
    Test_ExpectCount(Zb_CorePollIndications(&rig.dev, &indication, 1), 1, "it waits for the application");
    Test_ExpectCount(indication.clusterId, ZDO_SIMPLE_DESC_REQ | ZDO_RESPONSE_BIT, "on the cluster it answered on");
    Test_ExpectCount(indication.dstEndpoint, ZDO_ENDPOINT, "and on endpoint 0, where the application sent its request");
    Test_ExpectCount(indication.asdu[0], 0x26, "with the transaction sequence number the application wrote");
}

/* The group arm the config chooses: 2.2.8.4.2's member delivery is the default, and an application that filters its
   own group traffic asks for the other one, which hands it every group frame once. */
void caseDeviceGroupDeliveryFromTheConfig(void)
{
    DeviceRig rig;
    Af_SimpleDescriptor descriptor;
    Aps_Frame frame;
    Aps_Indication indication;
    uint8_t asdu[2];

    deviceRigBuild(&rig);

    Test_ExpectCount(Aps_GroupDelivery(Zb_CoreAps(&rig.dev)), APS_GROUP_DELIVERY_MEMBERS,
                     "a device built without asking delivers to the group table's members and to nothing else");

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = APS_FRAME_TYPE_DATA;
    frame.deliveryMode = APS_DELIVERY_GROUP;
    frame.dstEndpointPresent = 0;
    frame.groupAddressPresent = 1;
    frame.groupAddress = 0x0004;
    frame.clusterPresent = 1;
    frame.clusterId = DEVICE_INPUT_CLUSTER;
    frame.profilePresent = 1;
    frame.profileId = DEVICE_PROFILE_ID;
    frame.srcEndpointPresent = 1;
    frame.srcEndpoint = DEVICE_EP_FIRST;
    frame.apsCounter = 0x32;

    asdu[0] = 0xcc;
    asdu[1] = 0xdd;

    devicePeerSends(&rig, &frame, asdu, 2, 1000);
    deviceStep(&rig, 1000);

    Test_ExpectCount(Aps_DroppedGroupMiss(Zb_CoreAps(&rig.dev)), 1, "a group this device holds nothing in is a miss");
    Test_ExpectCount(Zb_CorePollIndications(&rig.dev, &indication, 1), 0, "and the application hears nothing");

    deviceRigBuild(&rig);
    rig.cfg.groupDelivery = APS_GROUP_DELIVERY_UNFILTERED;

    Test_ExpectStatus(Zb_CoreInit(&rig.dev, LoopbackRadio_Seam(&rig.model), &rig.cfg), ZB_OK,
                      "a device whose config asks for the other arm is built");

    devicePeerSends(&rig, &frame, asdu, 2, 1000);
    deviceStep(&rig, 1000);

    Test_ExpectCount(Zb_CorePollIndications(&rig.dev, &indication, 1), 1, "the same frame is the application's");
    Test_ExpectCount(indication.dstAddrMode, APS_ADDR_MODE_GROUP, "with the group mode it was addressed by");
    Test_ExpectCount(indication.dstAddress, 0x0004, "the group id to filter on");
    Test_ExpectCount(indication.dstEndpoint, APS_ENDPOINT_BROADCAST, "and the broadcast endpoint, since no member owns it");

    deviceRigBuild(&rig);
    rig.cfg.groupDelivery = APS_GROUP_DELIVERY_ENDPOINTS;

    Test_ExpectStatus(Zb_CoreInit(&rig.dev, LoopbackRadio_Seam(&rig.model), &rig.cfg), ZB_OK,
                      "a device that asks for its endpoints' arm is built");
    deviceDescriptor(&descriptor, DEVICE_EP_FIRST);
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_OK, "with two endpoints of the frame's profile");
    deviceDescriptor(&descriptor, DEVICE_EP_SECOND);
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_OK, "the second");
    deviceDescriptor(&descriptor, 0xf2);
    descriptor.profileId = 0xa1e0;
    Test_ExpectStatus(Zb_CoreRegisterEndpoint(&rig.dev, &descriptor), ZB_OK, "and one of another profile");

    frame.apsCounter = 0x34;
    devicePeerSends(&rig, &frame, asdu, 2, 1000);
    deviceStep(&rig, 1000);

    Test_ExpectCount(Zb_CorePollIndications(&rig.dev, &indication, 1), 1, "the frame is the first endpoint's");
    Test_ExpectCount(indication.dstEndpoint, DEVICE_EP_FIRST, "at that endpoint");
    Test_ExpectCount(indication.dstAddress, 0x0004, "with the group it was addressed to");
    Test_ExpectCount(Zb_CorePollIndications(&rig.dev, &indication, 1), 1, "and once more the second's");
    Test_ExpectCount(indication.dstEndpoint, DEVICE_EP_SECOND, "at that one");
    Test_ExpectCount(Zb_CorePollIndications(&rig.dev, &indication, 1), 0, "and not the other profile's");

    frame.profileId = 0xc05e;
    frame.apsCounter = 0x35;
    devicePeerSends(&rig, &frame, asdu, 2, 1100);
    deviceStep(&rig, 1100);

    Test_ExpectCount(Zb_CorePollIndications(&rig.dev, &indication, 1), 0, "a profile no endpoint has reaches none");
    Test_ExpectCount(Zb_CoreGroupFramesUnmatched(&rig.dev), 1, "and is counted");
}

/* The group table is the application's statement about its memberships and the registry the device's about what it
   advertises: an entry naming an endpoint with no descriptor is delivered like any other. */
void caseDeviceGroupMemberWithoutDescriptor(void)
{
    DeviceRig rig;
    Aps_Frame frame;
    Aps_Indication indication;
    uint8_t asdu[2];

    deviceRigBuild(&rig);

    Test_ExpectCount(Aps_AddGroup(Zb_CoreAps(&rig.dev), 0x0006, 0x05), APS_STATUS_SUCCESS,
                     "the application puts endpoint 0x05 in a group, and registers no descriptor for it");

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = APS_FRAME_TYPE_DATA;
    frame.deliveryMode = APS_DELIVERY_GROUP;
    frame.dstEndpointPresent = 0;
    frame.groupAddressPresent = 1;
    frame.groupAddress = 0x0006;
    frame.clusterPresent = 1;
    frame.clusterId = DEVICE_INPUT_CLUSTER;
    frame.profilePresent = 1;
    frame.profileId = DEVICE_PROFILE_ID;
    frame.srcEndpointPresent = 1;
    frame.srcEndpoint = DEVICE_EP_FIRST;
    frame.apsCounter = 0x33;

    asdu[0] = 0xee;
    asdu[1] = 0xff;

    devicePeerSends(&rig, &frame, asdu, 2, 1000);
    deviceStep(&rig, 1000);

    Test_ExpectCount(Zb_CorePollIndications(&rig.dev, &indication, 1), 1, "the member's frame is delivered");
    Test_ExpectCount(indication.dstEndpoint, 0x05, "at the endpoint the table named, descriptor or not");
}

/* The beacon is the device's: Init states it, so 3.2.2.7's permit door has something to open, and the door is the
   only call an application needs to accept a join. */
void caseDeviceBeaconAndPermitDoor(void)
{
    DeviceRig rig;

    deviceRigBuild(&rig);

    Test_ExpectCount(Nwk_PermitJoiningActive(Zb_CoreNwk(&rig.dev)), 0,
                     "a device that was built accepts nobody until it is asked to");
    Test_ExpectCount(Zb_CorePermitJoining(&rig.dev, 60, 1000), ZB_OK,
                     "and the permit door opens without the application stating a beacon first");
    Test_ExpectCount(Nwk_PermitJoiningActive(Zb_CoreNwk(&rig.dev)), 1, "the association permit stands");
    Test_ExpectCount(Zb_CorePermitJoining(&rig.dev, 0, 2000), ZB_OK, "the same door closes it");
    Test_ExpectCount(Nwk_PermitJoiningActive(Zb_CoreNwk(&rig.dev)), 0, "and the permit is gone");

    deviceRigBuild(&rig);
    Test_ExpectCount(Zb_CorePermitJoining(&rig.dev, 1, 1000), ZB_OK, "a one-second permit is taken");
    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 2500), ZB_OK, "the device turns past it");
    Test_ExpectCount(Nwk_PermitJoiningActive(Zb_CoreNwk(&rig.dev)), 0, "and 3.2.2.7.3's countdown closed it");
}

/* The radio's mode is the device's too: an RCP left in receive-all acknowledges nothing, so the first turn states the
   filtered mode and every turn after it leaves it alone. */
void caseDeviceFiltersTheRadio(void)
{
    DeviceRig rig;

    deviceRigBuild(&rig);

    Test_ExpectStatus(Mac_SetPromiscuousMode(Zb_CoreMac(&rig.dev), 1), ZB_OK,
                      "the arm sequence leaves an RCP in receive-all mode, which the case states here");
    Test_ExpectCount(Mac_PromiscuousModeOf(Zb_CoreMac(&rig.dev)), 1, "the radio hears everything");

    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 1000), ZB_OK, "the first turn");

    Test_ExpectCount(Mac_PromiscuousModeOf(Zb_CoreMac(&rig.dev)), 0,
                     "and the device is filtered to its own addresses, which is the state an RCP acknowledges in");
}

/* A ZDP announcement read by the codec the application is given, so an example does not hand-parse Table 2-51. */
void caseDeviceAnnouncementCodec(void)
{
    uint8_t asdu[12];
    uint64_t ieee = 0;
    uint16_t address = 0;
    uint8_t capability = 0;
    uint32_t i;

    asdu[0] = 0x51;
    asdu[1] = 0xa1;
    asdu[2] = 0x1f;

    for (i = 0; i < 8; i++)
        asdu[3 + i] = (uint8_t)(0x00212effff05a888 >> (8 * i));

    asdu[11] = 0x80;

    Test_ExpectStatus(Zdo_DeviceAnnouncementParse(asdu, 12, &ieee, &address, &capability), ZB_OK,
                      "the announcement parses");
    Test_ExpectCount(address, 0x1fa1, "the network address the joiner was given");
    Test_Expect(ieee == 0x00212effff05a888, "its 64-bit address");
    Test_ExpectCount(capability, 0x80, "and Figure 2-16's capability octet, untouched");

    Test_ExpectStatus(Zdo_DeviceAnnouncementParse(asdu, 11, &ieee, &address, &capability), ZB_ERR_BAD_FRAME,
                      "eleven octets are one short of Table 2-51's three fields");
}
