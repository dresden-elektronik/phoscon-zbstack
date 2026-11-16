/* 2.4.4.2's server half: the descriptors it answers with, the endpoints it names, the addresses it resolves, and
   the statuses Table 2-129 prints for the three ways a request can be wrong. */

#include "test_harness.h"
#include "zb_utils.h"
#include "af_helpers.h"
#include "zdo_helpers.h"

/* The APS service's own ring is where a response is left, so a case reads it there: the framework hands the
   device object's answer to the APS layer, which is what the counters below are read beside. */
static uint32_t responsesQueued(const Zdo_Rig *rig)
{
    return Aps_TransmitQueue(&rig->aps) + rig->zdo.responsesSent;
}

void caseZdoNodeDescriptor(void)
{
    Zdo_Rig rig;
    Af_SimpleDescriptor descriptor;
    uint8_t payload[2];

    zdoRigBuild(&rig);

    descriptor = afDescriptor(1, 0x0104, 0x0006);
    Test_ExpectStatus(Af_RegisterEndpoint(&rig.af, &descriptor, 0, 0), ZB_OK, "endpoint 1 advertises a cluster");

    payload[0] = (uint8_t)(ZDO_OWN_SHORT & 0xff);
    payload[1] = (uint8_t)(ZDO_OWN_SHORT >> 8);

    zdoDeliverCommand(&rig, ZDO_NODE_DESC_REQ, payload, 2, 100);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "2.4.4.2.2: a Node_Desc_req for this device is answered once");
    Test_ExpectCount(responsesQueued(&rig), 2, "and the answer is in the APS service's queue as well");

    payload[0] = 0x11;
    payload[1] = 0x00;

    zdoDeliverCommand(&rig, ZDO_NODE_DESC_REQ, payload, 2, 200);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 2, "a Node_Desc_req for another device is answered too");
    Test_ExpectCount(Zdo_ResponsesRefused(&rig.zdo), 0, "and neither answer was refused");
}

/* 2.3.2.3.4: a Revision 23 node descriptor says whether the device reassembles fragments, and 2.3.2.3.10's transfer
   sizes are what one message can carry to it, reassembled or not. */
void caseZdoNodeDescriptorStatesFragmentation(void)
{
    Zdo_NodeDescriptor node;
    Zdo_NodeDescriptor parsed;
    uint8_t body[3 + 13];
    uint16_t size = ZB_APS_FRAGMENTATION ? APS_FRAG_MAX_ASDU : AF_ASDU_MAX;

    Zdo_NodeDescriptorDefaults(&node, ZDO_LOGICAL_ROUTER, 0x1135);
    body[0] = ZDO_STATUS_SUCCESS;
    body[1] = 0;
    body[2] = 0;

    Test_ExpectCount(Zdo_NodeDescriptorCompose(&node, body + 3, 13), 13, "the descriptor is composed");
    Test_ExpectCount((body[3] >> 5) & 0x01, ZB_APS_FRAGMENTATION,
                     "its Fragmentation Supported bit says what this build reassembles");
    Test_ExpectCount((uint32_t)(body[9] | (body[10] << 8)), size, "the incoming transfer size is what one message carries");
    Test_ExpectCount((uint32_t)(body[13] | (body[14] << 8)), size, "and the outgoing one too");

    Test_ExpectStatus(Zdo_NodeDescriptorParse(body, sizeof body, &parsed), ZB_OK, "and read back");
    Test_ExpectCount(parsed.fragmentationSupported, ZB_APS_FRAGMENTATION, "with the bit");
}

void caseZdoActiveEndpoints(void)
{
    Zdo_Rig rig;
    Af_SimpleDescriptor first;
    Af_SimpleDescriptor second;
    uint8_t payload[2];

    zdoRigBuild(&rig);

    first = afDescriptor(1, 0x0104, 0x0006);
    second = afDescriptor(2, 0x0104, 0x0008);

    Test_ExpectStatus(Af_RegisterEndpoint(&rig.af, &first, 0, 0), ZB_OK, "endpoint 1 registers");
    Test_ExpectStatus(Af_RegisterEndpoint(&rig.af, &second, 0, 0), ZB_OK, "and endpoint 2");

    payload[0] = (uint8_t)(ZDO_OWN_SHORT & 0xff);
    payload[1] = (uint8_t)(ZDO_OWN_SHORT >> 8);

    zdoDeliverCommand(&rig, ZDO_ACTIVE_EP_REQ, payload, 2, 100);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "2.4.4.2.6: an Active_EP_req is answered");
    Test_ExpectCount(Af_EndpointCount(&rig.af), 3,
                     "with the two application endpoints and the device profile's own, which 2.4.4.2.6's list leaves out");
}

void caseZdoSimpleDescriptorStatuses(void)
{
    Zdo_Rig rig;
    Af_SimpleDescriptor descriptor;
    uint8_t payload[3];

    zdoRigBuild(&rig);

    descriptor = afDescriptor(1, 0x0104, 0x0006);
    Test_ExpectStatus(Af_RegisterEndpoint(&rig.af, &descriptor, 0, 0), ZB_OK, "endpoint 1 registers");

    payload[0] = (uint8_t)(ZDO_OWN_SHORT & 0xff);
    payload[1] = (uint8_t)(ZDO_OWN_SHORT >> 8);
    payload[2] = 1;

    zdoDeliverCommand(&rig, ZDO_SIMPLE_DESC_REQ, payload, 3, 100);
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "2.4.4.2.5: a Simple_Desc_req for an active endpoint is answered");

    payload[2] = 0;
    zdoDeliverCommand(&rig, ZDO_SIMPLE_DESC_REQ, payload, 3, 200);
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 2, "endpoint 0 is answered too, with INVALID_EP");

    payload[2] = 9;
    zdoDeliverCommand(&rig, ZDO_SIMPLE_DESC_REQ, payload, 3, 300);
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 3, "and an endpoint nobody describes, with NOT_ACTIVE");
}

/* Table 2-40's record ends where its length octet says, so a cluster count that runs past it is a damaged frame and
   not a reason to read on. */
void caseZdoSimpleDescriptorParseStaysInsideItsRecord(void)
{
    Af_SimpleDescriptor parsed;
    uint8_t body[16];

    Zb_memset(body, 0, sizeof body);
    body[0] = ZDO_STATUS_SUCCESS;
    body[1] = (uint8_t)(ZDO_OWN_SHORT & 0xff);
    body[2] = (uint8_t)(ZDO_OWN_SHORT >> 8);
    body[3] = 8;            /* the smallest record: no cluster in either list */
    body[4] = 1;
    body[5] = 0x04;
    body[6] = 0x01;

    Test_ExpectStatus(Zdo_SimpleDescriptorParse(body, 12, &parsed), ZB_OK, "a record with two empty lists is read");

    body[10] = 2;           /* the input list claims two clusters, in octets the record does not hold */
    Test_ExpectStatus(Zdo_SimpleDescriptorParse(body, sizeof body, &parsed), ZB_ERR_BAD_ARGUMENT,
                      "an input list that runs past the record's length is refused, whatever follows it");

    body[10] = 0;
    body[11] = 2;           /* and the output list the same */
    Test_ExpectStatus(Zdo_SimpleDescriptorParse(body, sizeof body, &parsed), ZB_ERR_BAD_ARGUMENT,
                      "and so is an output list");

    body[3] = 7;
    body[11] = 0;
    Test_ExpectStatus(Zdo_SimpleDescriptorParse(body, sizeof body, &parsed), ZB_ERR_BAD_ARGUMENT,
                      "and so is a record too short to hold both counts");
}

void caseZdoUnsupportedCommand(void)
{
    Zdo_Rig rig;
    uint8_t payload[2];

    zdoRigBuild(&rig);

    payload[0] = 0x00;
    payload[1] = 0x00;

    zdoDeliverCommand(&rig, 0x0030, payload, 2, 100);

    Test_ExpectCount(Zdo_CommandsUnsupported(&rig.zdo), 1, "a command this server does not implement is counted");
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "2.4.4.1: and a unicast one is answered, NOT_SUPPORTED");

    zdoDeliverBroadcast(&rig, 0x0030, payload, 2, 200);
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "a broadcast one is dropped with no answer");

    Zdo_SetUnsupportedToApplication(&rig.zdo, 1);
    zdoDeliverCommand(&rig, 0x0030, payload, 2, 300);
    Test_ExpectCount(Zdo_CommandsUnsupported(&rig.zdo), 3, "handed to the application, it is still counted");
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "and the application, not the server, answers it");
}

void caseZdoDeviceAnnce(void)
{
    Zdo_Rig rig;

    zdoRigBuild(&rig);

    Test_ExpectStatus(Zdo_DeviceAnnce(&rig.zdo, 100), ZB_OK, "2.4.3.1.11: the announcement is sent");
    Test_ExpectCount(Zdo_AnnouncementsSent(&rig.zdo), 1, "and counted");
    Test_ExpectCount(Zdo_TransactionSequenceNumber(&rig.zdo), 1,
                     "2.4.2.8.1's counter moved by one, and the next command starts from there");
}

/* 2.4.2.8.1's client half: a request this device sends, the response that copies its transaction sequence number
   matched to it, and the command's own fields read back. */
void caseZdoClient(void)
{
    Zdo_Rig rig;
    Zdo_Response response;
    Zdo_NodeDescriptor node;
    uint8_t payload[2];
    uint8_t asdu[32];
    uint32_t len = 0;

    zdoRigBuild(&rig);

    payload[0] = (uint8_t)(ZDO_OWN_SHORT & 0xff);
    payload[1] = (uint8_t)(ZDO_OWN_SHORT >> 8);

    Test_ExpectStatus(Zdo_SendRequest(&rig.zdo, ZDO_PEER_SHORT, ZDO_ENDPOINT, ZDO_NODE_DESC_REQ, payload, 2, 100),
                      ZB_OK, "a Node_Desc_req is sent to the peer");
    Test_ExpectCount(Zdo_RequestsSent(&rig.zdo), 1, "and counted");
    Test_ExpectCount(Zdo_PendingCount(&rig.zdo), 1, "with one transaction in flight");
    Test_ExpectCount(Zdo_TransactionSequenceNumber(&rig.zdo), 1, "and 2.4.2.8.1's counter moved by one");

    /* The peer's answer, as an APS indication the framework would dispatch: the response cluster, the same
       transaction sequence number, the status, the address of interest and Table 2-31's record. */
    asdu[0] = 0;
    asdu[1] = ZDO_STATUS_SUCCESS;
    asdu[2] = payload[0];
    asdu[3] = payload[1];

    Zdo_NodeDescriptorDefaults(&node, ZDO_LOGICAL_ROUTER, 0x1037);
    len = Zdo_NodeDescriptorCompose(&node, asdu + 4, (uint32_t)sizeof asdu - 4);

    Test_Expect(len != 0, "the descriptor the peer answers with is composed");

    {
        Af_Indication indication;

        Zb_memset(&indication, 0, (uint32_t)sizeof indication);

        indication.dstEndpoint = ZDO_ENDPOINT;
        indication.srcEndpoint = ZDO_ENDPOINT;
        indication.srcAddress = ZDO_PEER_SHORT;
        indication.profileId = ZDO_PROFILE_ID;
        indication.clusterId = (uint16_t)(ZDO_NODE_DESC_REQ | ZDO_RESPONSE_BIT);
        indication.asduLength = 4 + len;
        Zb_memcpy(indication.asdu, asdu, indication.asduLength);

        Test_ExpectStatus(Zdo_HandleIndication(&rig.zdo, &indication, 200), ZB_OK, "the answer is read");
    }

    Test_ExpectCount(Zdo_PendingCount(&rig.zdo), 0, "the transaction it answers is closed");
    Test_ExpectCount(Zdo_PollResponses(&rig.zdo, &response, 1), 1, "and the response is waiting for the application");
    Test_ExpectCount(response.clusterId, ZDO_NODE_DESC_REQ, "keyed by the command it answers");
    Test_ExpectCount(response.sourceAddress, ZDO_PEER_SHORT, "from the device the request went to");

    Test_ExpectStatus(Zdo_NodeDescriptorParse(response.payload, response.length, &node), ZB_OK,
                      "2.3.2.3's descriptor reads back out of it");
    Test_ExpectCount(node.logicalType, ZDO_LOGICAL_ROUTER, "the logical type");
    Test_ExpectCount(node.manufacturerCode, 0x1037, "and the manufacturer's code");

    Test_ExpectCount(Zdo_PollResponses(&rig.zdo, &response, 1), 0, "the ring is empty once it was taken");
}

/* 2.4.3.2.2's Bind_req and 2.4.3.2.3's Unbind_req: Table 2-55's entry written into the table the APS sub-layer
   keeps, and Table 2-97's and Table 2-98's four answers for the four ways the request can be wrong. */
void caseZdoBindings(void)
{
    Zdo_Rig rig;
    Aps_Binding bindings[APS_BIND_MAX];
    uint8_t payload[8 + 1 + 2 + 1 + 8 + 1];
    uint32_t i;

    Zb_memset(bindings, 0, (uint32_t)sizeof bindings);
    Zb_memset(payload, 0, (uint32_t)sizeof payload);

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, 0);
    Aps_SetBindings(&rig.aps, bindings);

    for (i = 0; i < 8; i++)
        payload[i] = (uint8_t)((ZDO_OWN_IEEE >> (8 * i)) & 0xff);

    payload[8] = 1;         /* SrcEndp */
    payload[9] = 0x06;      /* ClusterID 0x0006 */
    payload[11] = 0x01;     /* DstAddrMode: 16-bit group, no DstEndp */
    payload[12] = 0x11;
    payload[13] = 0x00;

    zdoDeliverCommand(&rig, ZDO_BIND_REQ, payload, 14, 100);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "2.4.3.2.2: a Bind_req is answered");
    Test_ExpectCount(Aps_BindCount(bindings), 1, "and the entry is in the table");

    zdoDeliverCommand(&rig, ZDO_BIND_REQ, payload, 14, 200);

    Test_ExpectCount(Aps_BindCount(bindings), 1, "a second Bind_req of the same entry does not duplicate it");

    payload[11] = 0x02;

    zdoDeliverCommand(&rig, ZDO_BIND_REQ, payload, 14, 300);

    Test_ExpectCount(Aps_BindCount(bindings), 1,
                     "the mode Table 2-6 reserves is refused, with INV_REQUESTTYPE, and adds nothing");

    payload[11] = 0x01;
    payload[8] = 0x00;

    zdoDeliverCommand(&rig, ZDO_BIND_REQ, payload, 14, 400);

    Test_ExpectCount(Aps_BindCount(bindings), 1, "a source endpoint outside 0x01-0xfe is refused, with INVALID_EP");

    payload[8] = 1;
    payload[0] = 0x00;

    zdoDeliverCommand(&rig, ZDO_BIND_REQ, payload, 14, 500);

    Test_ExpectCount(Aps_BindCount(bindings), 1,
                     "and a bind for somebody else's endpoint is refused, with NOT_SUPPORTED: this device is neither "
                     "the source nor the coordinator");

    payload[0] = (uint8_t)(ZDO_OWN_IEEE & 0xff);

    zdoDeliverBroadcast(&rig, ZDO_BIND_REQ, payload, 14, 550);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 5,
                     "2.4.3.2.2.2: a broadcast Bind_req is dropped and answered by nothing");
    Test_ExpectCount(Aps_BindCount(bindings), 1, "and the table is not written by it");
    Test_ExpectCount(Zdo_CommandsDroppedBroadcast(&rig.zdo), 1, "which the device object counts");

    zdoDeliverCommand(&rig, ZDO_UNBIND_REQ, payload, 14, 600);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 6, "2.4.3.2.3: an Unbind_req is answered");
    Test_ExpectCount(Aps_BindCount(bindings), 0, "and the entry is gone");

    zdoDeliverCommand(&rig, ZDO_UNBIND_REQ, payload, 14, 700);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 7, "a second Unbind_req is answered too, with NO_ENTRY");
    Test_ExpectCount(Aps_BindCount(bindings), 0, "with nothing left to remove");
}

/* The status octet of a ZDP response the APS layer holds for `cluster`: every response's ASDU is the transaction
   number then the status, behind the APS header. 0xff when none is held. */
static uint8_t zdoHeldResponseStatus(const Zdo_Rig *rig, uint16_t cluster)
{
    uint32_t i;

    for (i = 0; i < APS_TX_MAX; i++)
    {
        if (rig->aps.tx[i].state != APS_TX_FREE && rig->aps.tx[i].clusterId == cluster
            && rig->aps.tx[i].apduLen > rig->aps.tx[i].apduHeaderLen + 1)
            return rig->aps.tx[i].apdu[rig->aps.tx[i].apduHeaderLen + 1];
    }

    return 0xff;
}

/* Octet `at` of a held ZDP response's ASDU on `cluster`, the transaction number being octet 0. -1 when none is held. */
static int zdoHeldResponseOctet(const Zdo_Rig *rig, uint16_t cluster, uint32_t at)
{
    uint32_t i;

    for (i = 0; i < APS_TX_MAX; i++)
    {
        if (rig->aps.tx[i].state != APS_TX_FREE && rig->aps.tx[i].clusterId == cluster
            && rig->aps.tx[i].apduLen > rig->aps.tx[i].apduHeaderLen + at)
            return rig->aps.tx[i].apdu[rig->aps.tx[i].apduHeaderLen + at];
    }

    return -1;
}

/* The length of a held ZDP response's ASDU on `cluster`, the transaction number included; 0 when none is held. */
static uint32_t zdoHeldResponseLength(const Zdo_Rig *rig, uint16_t cluster)
{
    uint32_t i;

    for (i = 0; i < APS_TX_MAX; i++)
    {
        if (rig->aps.tx[i].state != APS_TX_FREE && rig->aps.tx[i].clusterId == cluster)
            return rig->aps.tx[i].apduLen - rig->aps.tx[i].apduHeaderLen;
    }

    return 0;
}

/* The 64-bit address the octets at `at` of a held response carry, low octet first. */
static uint64_t zdoHeldResponseIeee(const Zdo_Rig *rig, uint16_t cluster, uint32_t at)
{
    uint64_t ieee = 0;
    uint32_t i;

    for (i = 0; i < 8; i++)
        ieee |= (uint64_t)(uint8_t)zdoHeldResponseOctet(rig, cluster, at + i) << (8 * i);

    return ieee;
}

/* A request built as Figures 2-18 and 2-19 print it: the address, RequestType, StartIndex. */
static void zdoNwkAddrReq(uint8_t *payload, uint64_t ieee, uint8_t requestType)
{
    uint32_t i;

    for (i = 0; i < 8; i++)
        payload[i] = (uint8_t)((ieee >> (8 * i)) & 0xff);

    payload[8] = requestType;
    payload[9] = 0;
}

void caseZdoAddresses(void)
{
    uint16_t nwkRsp = ZDO_RESPONSE_BIT | ZDO_NWK_ADDR_REQ;
    uint16_t ieeeRsp = ZDO_RESPONSE_BIT | ZDO_IEEE_ADDR_REQ;
    Zdo_Rig rig;
    uint8_t payload[10];

    zdoRigBuild(&rig);
    zdoNwkAddrReq(payload, ZDO_OWN_IEEE, ZDO_REQUEST_TYPE_SINGLE);
    zdoDeliverCommand(&rig, ZDO_NWK_ADDR_REQ, payload, 10, 100);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "2.4.3.1.1.2: this device's own IEEE address is resolved");
    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, nwkRsp, 1), ZDO_STATUS_SUCCESS, "with SUCCESS");
    Test_ExpectCount((uint32_t)(zdoHeldResponseOctet(&rig, nwkRsp, 10) | zdoHeldResponseOctet(&rig, nwkRsp, 11) << 8),
                     ZDO_OWN_SHORT, "and this device's network address");
    Test_ExpectCount(zdoHeldResponseLength(&rig, nwkRsp), 1 + 11,
                     "Table 2-87: a single device response stops after the address, NumAssocDev left out");

    zdoRigBuild(&rig);
    zdoNwkAddrReq(payload, 0x00212effff000001, ZDO_REQUEST_TYPE_SINGLE);
    zdoDeliverCommand(&rig, ZDO_NWK_ADDR_REQ, payload, 10, 200);

    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, nwkRsp, 1), ZDO_STATUS_DEVICE_NOT_FOUND,
                     "an address nobody holds is answered DEVICE_NOT_FOUND");
    Test_Expect(zdoHeldResponseIeee(&rig, nwkRsp, 2) == 0x00212effff000001, "with the IEEE address it asked about");
    Test_ExpectCount((uint32_t)(zdoHeldResponseOctet(&rig, nwkRsp, 10) | zdoHeldResponseOctet(&rig, nwkRsp, 11) << 8),
                     0xffff, "and 0xffff, no known short address");
    Test_ExpectCount(zdoHeldResponseLength(&rig, nwkRsp), 1 + 11, "and nothing after it");

    zdoDeliverBroadcast(&rig, ZDO_NWK_ADDR_REQ, payload, 10, 250);
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "2.4.3.1.1.2: but not when it was broadcast, which is discarded");
    Test_ExpectCount(Zdo_CommandsBroadcastUnanswered(&rig.zdo), 1, "and counted as a broadcast left unanswered");

    zdoRigBuild(&rig);
    payload[0] = (uint8_t)(ZDO_OWN_SHORT & 0xff);
    payload[1] = (uint8_t)(ZDO_OWN_SHORT >> 8);
    payload[2] = ZDO_REQUEST_TYPE_SINGLE;
    payload[3] = 0;
    zdoDeliverCommand(&rig, ZDO_IEEE_ADDR_REQ, payload, 4, 300);

    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, ieeeRsp, 1), ZDO_STATUS_SUCCESS,
                     "2.4.3.1.2.2: this device's own short address is resolved");
    Test_Expect(zdoHeldResponseIeee(&rig, ieeeRsp, 2) == ZDO_OWN_IEEE, "to this device's IEEE address");
    Test_ExpectCount(zdoHeldResponseLength(&rig, ieeeRsp), 1 + 11, "Table 2-88: stopping after the address");

    zdoRigBuild(&rig);
    payload[0] = 0x34;
    payload[1] = 0x12;
    zdoDeliverBroadcast(&rig, ZDO_IEEE_ADDR_REQ, payload, 4, 400);

    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, ieeeRsp, 1), ZDO_STATUS_DEVICE_NOT_FOUND,
                     "2.4.3.1.2.2: an address nobody holds is answered DEVICE_NOT_FOUND, broadcast or not");
    Test_Expect(zdoHeldResponseIeee(&rig, ieeeRsp, 2) == 0xffffffffffffffff, "with the IEEE address of all ones");
    Test_ExpectCount((uint32_t)(zdoHeldResponseOctet(&rig, ieeeRsp, 10) | zdoHeldResponseOctet(&rig, ieeeRsp, 11) << 8),
                     0x1234, "the network address it asked about");
    Test_ExpectCount(zdoHeldResponseLength(&rig, ieeeRsp), 1 + 11, "and nothing after it");
}

/* A neighbour table row as a join leaves one, its IEEE address derived from the short one. */
static void zdoSeedChild(Zdo_Rig *rig, uint16_t address, uint32_t deviceType, uint32_t relationship)
{
    Nwk_NeighborTableEntry *entry = Nwk_NeighborFree(rig->stack.nwk.neighbors);

    Test_Expect(entry != 0, "the neighbour table has a row for the seeded device");

    if (entry == 0)
        return;

    entry->inUse = 1;
    entry->networkAddress = address;
    entry->extendedAddress = 0x00212effff000000 | address;
    entry->ieeeKnown = 1;
    entry->deviceType = deviceType;
    entry->relationship = relationship;
}

/* The extended answer lists the associated end devices from StartIndex; a reserved RequestType is refused. */
void caseZdoAddressesExtended(void)
{
    uint16_t nwkRsp = ZDO_RESPONSE_BIT | ZDO_NWK_ADDR_REQ;
    uint16_t ieeeRsp = ZDO_RESPONSE_BIT | ZDO_IEEE_ADDR_REQ;
    Zdo_Rig rig;
    uint8_t payload[10];

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, 0);
    zdoNwkAddrReq(payload, ZDO_OWN_IEEE, ZDO_REQUEST_TYPE_EXTENDED);
    zdoDeliverCommand(&rig, ZDO_NWK_ADDR_REQ, payload, 10, 100);

    Test_ExpectCount(zdoHeldResponseLength(&rig, nwkRsp), 1 + 12,
                     "Table 2-87: an extended answer with no associated device ends at a NumAssocDev of 0");
    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, nwkRsp, 12), 0, "which is 0");

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, 0);
    zdoSeedChild(&rig, 0x2001, NWK_DEVICE_END_DEVICE, NWK_REL_CHILD);
    zdoSeedChild(&rig, 0x2002, NWK_DEVICE_ROUTER, NWK_REL_CHILD);
    zdoSeedChild(&rig, 0x2003, NWK_DEVICE_END_DEVICE, NWK_REL_PREVIOUS_CHILD);
    zdoSeedChild(&rig, 0x2004, NWK_DEVICE_END_DEVICE, NWK_REL_UNAUTHENTICATED_CHILD);
    zdoSeedChild(&rig, 0x2005, NWK_DEVICE_END_DEVICE, NWK_REL_LOST_CHILD);
    zdoDeliverCommand(&rig, ZDO_NWK_ADDR_REQ, payload, 10, 200);

    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, nwkRsp, 1), ZDO_STATUS_SUCCESS,
                     "2.4.3.1.1.2: an extended request for this device is answered SUCCESS");
    Test_Expect(zdoHeldResponseIeee(&rig, nwkRsp, 2) == ZDO_OWN_IEEE, "with the device itself");
    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, nwkRsp, 12), 2,
                     "NumAssocDev 2: the end device children, not a router, a previous or a lost child (D-297)");
    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, nwkRsp, 13), 0, "from StartIndex 0");
    Test_ExpectCount((uint32_t)(zdoHeldResponseOctet(&rig, nwkRsp, 14) | zdoHeldResponseOctet(&rig, nwkRsp, 15) << 8),
                     0x2001, "the first listed");
    Test_ExpectCount((uint32_t)(zdoHeldResponseOctet(&rig, nwkRsp, 16) | zdoHeldResponseOctet(&rig, nwkRsp, 17) << 8),
                     0x2004, "and the unauthenticated one");
    Test_ExpectCount(zdoHeldResponseLength(&rig, nwkRsp), 1 + 13 + 4, "and nothing after the list");

    Zb_memset(rig.aps.tx, 0, (uint32_t)sizeof rig.aps.tx);
    payload[9] = 1;
    zdoDeliverCommand(&rig, ZDO_NWK_ADDR_REQ, payload, 10, 300);

    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, nwkRsp, 12), 1, "StartIndex 1 lists one");
    Test_ExpectCount((uint32_t)(zdoHeldResponseOctet(&rig, nwkRsp, 14) | zdoHeldResponseOctet(&rig, nwkRsp, 15) << 8),
                     0x2004, "the second");

    Zb_memset(rig.aps.tx, 0, (uint32_t)sizeof rig.aps.tx);
    payload[9] = 5;
    zdoDeliverCommand(&rig, ZDO_NWK_ADDR_REQ, payload, 10, 400);

    Test_ExpectCount(zdoHeldResponseLength(&rig, nwkRsp), 1 + 13,
                     "a StartIndex past the list: NumAssocDev 0, and StartIndex, since devices are associated");
    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, nwkRsp, 13), 5, "the index asked for");

    Zb_memset(rig.aps.tx, 0, (uint32_t)sizeof rig.aps.tx);
    payload[0] = (uint8_t)(ZDO_OWN_SHORT & 0xff);
    payload[1] = (uint8_t)(ZDO_OWN_SHORT >> 8);
    payload[2] = ZDO_REQUEST_TYPE_EXTENDED;
    payload[3] = 0;
    zdoDeliverCommand(&rig, ZDO_IEEE_ADDR_REQ, payload, 4, 500);

    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, ieeeRsp, 12), 2,
                     "2.4.3.1.2.2: an extended IEEE_addr_req lists the same two");
    Test_ExpectCount(zdoHeldResponseLength(&rig, ieeeRsp), 1 + 13 + 4, "whole");

    zdoRigBuild(&rig);
    zdoNwkAddrReq(payload, ZDO_OWN_IEEE, 0x02);
    zdoDeliverCommand(&rig, ZDO_NWK_ADDR_REQ, payload, 10, 600);

    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, nwkRsp, 1), ZDO_STATUS_INV_REQUESTTYPE,
                     "a reserved RequestType sent unicast is answered INV_REQUESTTYPE");
    Test_ExpectCount(zdoHeldResponseLength(&rig, nwkRsp), 1 + 11, "with the addresses alone");

    zdoDeliverBroadcast(&rig, ZDO_NWK_ADDR_REQ, payload, 10, 700);
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "and sent broadcast is discarded, as 2.4.3.1.1.2 answers only a unicast");

    zdoRigBuild(&rig);
    payload[0] = (uint8_t)(ZDO_OWN_SHORT & 0xff);
    payload[1] = (uint8_t)(ZDO_OWN_SHORT >> 8);
    payload[2] = 0x02;
    zdoDeliverBroadcast(&rig, ZDO_IEEE_ADDR_REQ, payload, 4, 800);

    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, ieeeRsp, 1), ZDO_STATUS_INV_REQUESTTYPE,
                     "2.4.3.1.2.2 answers a reserved RequestType even when broadcast");
    Test_Expect(zdoHeldResponseIeee(&rig, ieeeRsp, 2) == ZDO_OWN_IEEE, "with this device's own addresses");

    zdoRigBuild(&rig);
    zdoDeliverCommand(&rig, ZDO_IEEE_ADDR_REQ, payload, 3, 900);
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 0, "Figure 2-19: a request without its StartIndex is not one");
}

/* A parent answers for its associated end devices, and not for one that left or is being heard elsewhere (D-297). */
void caseZdoAddressesForChildren(void)
{
    uint16_t nwkRsp = ZDO_RESPONSE_BIT | ZDO_NWK_ADDR_REQ;
    uint16_t ieeeRsp = ZDO_RESPONSE_BIT | ZDO_IEEE_ADDR_REQ;
    uint16_t matchRsp = ZDO_RESPONSE_BIT | ZDO_MATCH_DESC_REQ;
    uint8_t match[] = { 0x01, 0x20, 0x04, 0x01, 0x01, 0x06, 0x00, 0x00 };
    Zdo_Rig rig;
    uint8_t payload[10];

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, 0);
    zdoSeedChild(&rig, 0x2001, NWK_DEVICE_END_DEVICE, NWK_REL_CHILD);
    zdoSeedChild(&rig, 0x2003, NWK_DEVICE_END_DEVICE, NWK_REL_PREVIOUS_CHILD);
    zdoSeedChild(&rig, 0x2005, NWK_DEVICE_END_DEVICE, NWK_REL_LOST_CHILD);

    zdoNwkAddrReq(payload, 0x00212effff002001, ZDO_REQUEST_TYPE_SINGLE);
    zdoDeliverBroadcast(&rig, ZDO_NWK_ADDR_REQ, payload, 10, 100);

    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, nwkRsp, 1), ZDO_STATUS_SUCCESS,
                     "2.4.3.1.1.2: a broadcast for a child end device's IEEE address is answered by its parent");
    Test_Expect(zdoHeldResponseIeee(&rig, nwkRsp, 2) == 0x00212effff002001, "with the IEEE address asked about");
    Test_ExpectCount((uint32_t)(zdoHeldResponseOctet(&rig, nwkRsp, 10) | zdoHeldResponseOctet(&rig, nwkRsp, 11) << 8),
                     0x2001, "and the child's network address");

    Zb_memset(rig.aps.tx, 0, (uint32_t)sizeof rig.aps.tx);
    zdoNwkAddrReq(payload, 0x00212effff002001, ZDO_REQUEST_TYPE_EXTENDED);
    zdoDeliverCommand(&rig, ZDO_NWK_ADDR_REQ, payload, 10, 150);

    Test_Expect(zdoHeldResponseIeee(&rig, nwkRsp, 2) == ZDO_OWN_IEEE && zdoHeldResponseOctet(&rig, nwkRsp, 12) == 1,
                "an extended one is answered by the parent itself, its child listed, as the procedure prints it");

    zdoNwkAddrReq(payload, 0x00212effff002003, ZDO_REQUEST_TYPE_SINGLE);
    zdoDeliverBroadcast(&rig, ZDO_NWK_ADDR_REQ, payload, 10, 200);
    zdoNwkAddrReq(payload, 0x00212effff002005, ZDO_REQUEST_TYPE_SINGLE);
    zdoDeliverBroadcast(&rig, ZDO_NWK_ADDR_REQ, payload, 10, 250);

    Test_ExpectCount(Zdo_CommandsBroadcastUnanswered(&rig.zdo), 2,
                     "a previous child and a lost child are no match, so their broadcasts are discarded");

    Zb_memset(rig.aps.tx, 0, (uint32_t)sizeof rig.aps.tx);
    payload[0] = 0x01;
    payload[1] = 0x20;
    payload[2] = ZDO_REQUEST_TYPE_SINGLE;
    payload[3] = 0;
    zdoDeliverBroadcast(&rig, ZDO_IEEE_ADDR_REQ, payload, 4, 300);

    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, ieeeRsp, 1), ZDO_STATUS_SUCCESS,
                     "2.4.3.1.2.2: a child end device's network address is resolved by its parent");
    Test_Expect(zdoHeldResponseIeee(&rig, ieeeRsp, 2) == 0x00212effff002001, "to the child's IEEE address");

    Zb_memset(rig.aps.tx, 0, (uint32_t)sizeof rig.aps.tx);
    payload[0] = 0x03;
    zdoDeliverCommand(&rig, ZDO_IEEE_ADDR_REQ, payload, 4, 400);

    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, ieeeRsp, 1), ZDO_STATUS_DEVICE_NOT_FOUND,
                     "but a previous child's is DEVICE_NOT_FOUND");

    zdoDeliverCommand(&rig, ZDO_MATCH_DESC_REQ, match, (uint32_t)sizeof match, 500);
    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, matchRsp, 1), ZDO_STATUS_NO_DESCRIPTOR,
                     "2.4.4.2.7 step 6: a Match_Desc_req for the child is NO_DESCRIPTOR");

    Zb_memset(rig.aps.tx, 0, (uint32_t)sizeof rig.aps.tx);
    match[0] = 0x03;
    zdoDeliverCommand(&rig, ZDO_MATCH_DESC_REQ, match, (uint32_t)sizeof match, 600);
    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, matchRsp, 1), ZDO_STATUS_DEVICE_NOT_FOUND,
                     "step 4b: and for the previous child DEVICE_NOT_FOUND, with the same reading");
}

/* A Match_Desc_req whose address of interest is a broadcast is matched as if it named this device (step 3), and the
   answer names this device: an EmberZNet OTA client takes the address it carries for its server's. */
void caseZdoMatchForEveryoneNamesItself(void)
{
    /* NWKAddrOfInterest 0xfffd, profile 0x0104, input cluster 0x0019, no output clusters (Figure 2-24) */
    static const uint8_t payload[] = { 0xfd, 0xff, 0x04, 0x01, 0x01, 0x19, 0x00, 0x00 };
    Zdo_Rig rig;
    Af_SimpleDescriptor descriptor;
    uint16_t cluster = ZDO_RESPONSE_BIT | ZDO_MATCH_DESC_REQ;

    zdoRigBuild(&rig);

    descriptor = afDescriptor(1, 0x0104, 0x0019);
    Test_ExpectStatus(Af_RegisterEndpoint(&rig.af, &descriptor, 0, 0), ZB_OK, "endpoint 1 serves OTA Upgrade");

    zdoDeliverBroadcast(&rig, ZDO_MATCH_DESC_REQ, payload, (uint32_t)sizeof payload, 100);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "2.4.4.2.7 step 7: a broadcast that matches is answered");
    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, cluster, 1), ZDO_STATUS_SUCCESS, "with SUCCESS");
    Test_ExpectCount((uint32_t)(zdoHeldResponseOctet(&rig, cluster, 2) | zdoHeldResponseOctet(&rig, cluster, 3) << 8),
                     ZDO_OWN_SHORT, "naming this device, not the broadcast address it was asked about");
    Test_ExpectCount((uint32_t)zdoHeldResponseOctet(&rig, cluster, 5), 1, "and endpoint 1 its one match");
}

/* A Bind_req too short to name an entry is answered NOT_SUPPORTED, from no endpoint at all: a frame that names none
   has no endpoint to be invalid. */
void caseZdoShortBindRequestIsNotSupported(void)
{
    Zdo_Rig rig;
    Aps_Binding bindings[APS_BIND_MAX];
    uint8_t payload[5] = { 0x12, 0x8a, 0x04, 0xff, 0xff };

    Zb_memset(bindings, 0, (uint32_t)sizeof bindings);

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, 0);
    Aps_SetBindings(&rig.aps, bindings);

    zdoDeliverCommand(&rig, ZDO_BIND_REQ, payload, (uint32_t)sizeof payload, 100);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "a five-octet Bind_req is answered");
    Test_ExpectCount(zdoHeldResponseStatus(&rig, ZDO_RESPONSE_BIT | ZDO_BIND_REQ), ZDO_STATUS_NOT_SUPPORTED,
                     "with NOT_SUPPORTED 0x84");
    Test_ExpectCount(Aps_BindCount(bindings), 0, "and writes nothing");
}

/* A device whose PIB holds no short address yet is no address at all: a request for 0x0000 is not for it, and it has
   nothing to announce, where reading the raw PIB field would announce it as the coordinator. */
void caseZdoWithoutAnAddressIsNobody(void)
{
    Zdo_Rig rig;
    uint8_t payload[2] = { 0x00, 0x00 };

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, 0);
    rig.stack.mac.pib.present &= ~(uint32_t)RADIO_PIB_SHORT_ADDRESS;
    rig.stack.mac.pib.shortAddress = 0x0000;

    zdoDeliverCommand(&rig, ZDO_NODE_DESC_REQ, payload, (uint32_t)sizeof payload, 100);
    Test_Expect(zdoHeldResponseStatus(&rig, ZDO_RESPONSE_BIT | ZDO_NODE_DESC_REQ) != ZDO_STATUS_SUCCESS,
                "a Node_Desc_req for 0x0000 is not answered as if this device were the coordinator");
    Test_ExpectStatus(Zdo_DeviceAnnce(&rig.zdo, 200), ZB_ERR_NOT_READY, "and there is no address to announce");
}

void caseZdoPowerDescriptorOctets(void)
{
    static const uint8_t mains[] = { 0x00, 0xef, 0x43, 0x10, 0xc1 };
    Zdo_PowerDescriptor power;
    Zdo_PowerDescriptor read;
    uint8_t octets[2];
    uint8_t want[2];

    Test_Case("caseZdoPowerDescriptorOctets");

    Zdo_PowerDescriptorDefaults(&power);
    Test_Expect(power.currentPowerMode == 0x0 && power.availablePowerSources == 0x1 && power.currentPowerSource == 0x1
                && power.currentPowerSourceLevel == 0xc,
                "Tables 2-36 to 2-39: the defaults state a mains-powered device, receiver synchronised, at 100%");
    want[0] = (uint8_t)(power.currentPowerMode | (power.availablePowerSources << 4));
    want[1] = (uint8_t)(power.currentPowerSource | (power.currentPowerSourceLevel << 4));
    Test_ExpectCount(Zdo_PowerDescriptorCompose(&power, octets, (uint32_t)sizeof octets), 2,
                     "2.3.2.4: the power descriptor is two octets");
    Test_ExpectOctets("Table 2-35: the current power mode, then the available sources, the current source and its "
                      "level, the first field of each octet in its low nibble", octets, 2, want, 2);

    Test_ExpectStatus(Zdo_PowerDescriptorParse(mains, (uint32_t)sizeof mains, &read), ZB_OK,
                      "a Power_Desc_rsp a mains-powered router sent, 10 c1, is read");
    Test_Expect(read.currentPowerMode == 0x0 && read.availablePowerSources == 0x1 && read.currentPowerSource == 0x1
                && read.currentPowerSourceLevel == 0xc,
                "Tables 2-36 to 2-39: receiver synchronised, mains available and current, its level 100%");
}
