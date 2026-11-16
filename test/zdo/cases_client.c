/* The device object's client half: each discovery request's fields as its figure frames them, the node descriptor
   request's Fragmentation Parameters TLV, and the responses its readers take, whole, short and overrunning. */

#include "test_harness.h"
#include "zb_utils.h"
#include "zdo_client.h"
#include "zdo_helpers.h"

void caseClientDiscoveryRequests(void)
{
    static const uint8_t nwkAddr[] = { 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x01, 0x02 };
    static const uint8_t ieeeAddr[] = { 0x4d, 0x3c, 0x00, 0x00 };
    static const uint8_t simple[] = { 0x4d, 0x3c, 0x0b };
    static const uint8_t active[] = { 0x4d, 0x3c };
    static const uint8_t match[] = { 0xfd, 0xff, 0x04, 0x01, 0x02, 0x06, 0x00, 0x08, 0x00, 0x01, 0x19, 0x00 };
    static const uint16_t in[] = { 0x0006, 0x0008 };
    static const uint16_t out[] = { 0x0019 };
    uint8_t frame[32];
    uint32_t len;

    Test_Case("caseClientDiscoveryRequests");

    len = ZdoClient_NwkAddrReq(0x1122334455667788, ZDOCLIENT_REQUEST_EXTENDED, 2, frame, (uint32_t)sizeof frame);
    Test_ExpectOctets("Figure 2-18: the IEEE address low octet first, then RequestType and StartIndex", frame, len,
                      nwkAddr, (uint32_t)sizeof nwkAddr);
    len = ZdoClient_IeeeAddrReq(0x3c4d, ZDOCLIENT_REQUEST_SINGLE, 0, frame, (uint32_t)sizeof frame);
    Test_ExpectOctets("Figure 2-19: NWKAddrOfInterest, RequestType, StartIndex", frame, len, ieeeAddr,
                      (uint32_t)sizeof ieeeAddr);
    len = ZdoClient_SimpleDescReq(0x3c4d, 0x0b, frame, (uint32_t)sizeof frame);
    Test_ExpectOctets("Figure 2-22: NWKAddrOfInterest and the endpoint", frame, len, simple, (uint32_t)sizeof simple);
    len = ZdoClient_ActiveEpReq(0x3c4d, frame, (uint32_t)sizeof frame);
    Test_ExpectOctets("Figure 2-23: NWKAddrOfInterest alone", frame, len, active, (uint32_t)sizeof active);
    len = ZdoClient_PowerDescReq(0x3c4d, frame, (uint32_t)sizeof frame);
    Test_ExpectOctets("Figure 2-21: NWKAddrOfInterest alone", frame, len, active, (uint32_t)sizeof active);
    len = ZdoClient_MatchDescReq(0xfffd, 0x0104, in, 2, out, 1, frame, (uint32_t)sizeof frame);
    Test_ExpectOctets("Figure 2-24: the address, ProfileID, then each cluster list behind its count", frame, len,
                      match, (uint32_t)sizeof match);

    Test_ExpectCount(ZdoClient_NwkAddrReq(0x1122334455667788, 0, 0, frame, 9), 0,
                     "a request that does not fit its buffer is not written");
    Test_ExpectCount(ZdoClient_MatchDescReq(0xfffd, 0x0104, in, 2, out, 1, frame, 11), 0,
                     "Figure 2-24: nor one whose last cluster does not fit");
    Test_ExpectCount(ZdoClient_MatchDescReq(0xfffd, 0x0104, 0, 1, out, 1, frame, (uint32_t)sizeof frame), 0,
                     "nor one that counts a list it was not given");
}

void caseClientNodeDescReqStatesFragmentation(void)
{
    Zdo_Rig rig;
    const Zdo_NodeDescriptor *node;
    uint8_t want[9];
    uint8_t frame[16];
    uint32_t len;

    Test_Case("caseClientNodeDescReqStatesFragmentation");

    zdoRigBuild(&rig);
    node = Zdo_OwnNodeDescriptor(&rig.zdo);
    Test_Expect(node != 0, "the device object holds its own node descriptor");

    want[0] = 0x11;
    want[1] = 0x00;
    want[2] = 71;
    want[3] = 4;
    want[4] = (uint8_t)(ZDO_OWN_SHORT & 0xff);
    want[5] = (uint8_t)(ZDO_OWN_SHORT >> 8);
    want[6] = node != 0 && node->fragmentationSupported ? 0x01 : 0x00;
    want[7] = node != 0 ? (uint8_t)(node->maxIncomingTransferSize & 0xff) : 0;
    want[8] = node != 0 ? (uint8_t)(node->maxIncomingTransferSize >> 8) : 0;

    len = ZdoClient_NodeDescReq(&rig.zdo, ZDO_PEER_SHORT, frame, (uint32_t)sizeof frame);
    Test_ExpectOctets("2.4.3.1.3.1 with Figure I-4: the address, then TLV 71 of four octets stating this device's node "
                      "id, its fragmentation bit and its largest incoming transfer", frame, len, want,
                      (uint32_t)sizeof want);
    Test_ExpectCount(ZdoClient_NodeDescReq(&rig.zdo, ZDO_PEER_SHORT, frame, 8), 0,
                     "a request whose TLV does not fit is not written");
}

void caseClientAddressResponses(void)
{
    static const uint8_t single[] = { 0x00, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x4d, 0x3c };
    static const uint8_t extended[] = { 0x00, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x4d, 0x3c,
                                        0x02, 0x05, 0x01, 0x10, 0x02, 0x20 };
    static const uint8_t none[] = { 0x00, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x4d, 0x3c, 0x00 };
    static const uint8_t pastTheList[] = { 0x00, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x4d, 0x3c,
                                           0x00, 0x09 };
    static const uint8_t trailing[] = { 0x00, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x4d, 0x3c,
                                        0x00, 0x09, 0x01 };
    static const uint8_t overrun[] = { 0x00, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x4d, 0x3c,
                                       0x03, 0x00, 0x01, 0x10 };
    static const uint8_t notFound[] = { 0x81, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xff, 0xff };
    ZdoClient_AddressResponse rsp;

    Test_Case("caseClientAddressResponses");

    Test_ExpectStatus(ZdoClient_AddressResponseParse(single, (uint32_t)sizeof single, &rsp), ZB_OK,
                      "Figure 2-56: a single device response is the status and both addresses");
    Test_Expect(rsp.status == ZDO_STATUS_SUCCESS && rsp.ieeeAddrRemoteDev == 0x1122334455667788
                && rsp.nwkAddrRemoteDev == 0x3c4d && rsp.numAssocDev == 0, "Table 2-87: each read as it is printed");
    Test_ExpectStatus(ZdoClient_AddressResponseParse(extended, (uint32_t)sizeof extended, &rsp), ZB_OK,
                      "Figure 2-56: an extended response adds the count, the start index and the list");
    Test_Expect(rsp.numAssocDev == 2 && rsp.startIndex == 5 && rsp.nwkAddrAssocDevList[0] == 0x1001
                && rsp.nwkAddrAssocDevList[1] == 0x2002, "Table 2-87: the list, each address low octet first");
    Test_ExpectStatus(ZdoClient_AddressResponseParse(none, (uint32_t)sizeof none, &rsp), ZB_OK,
                      "Table 2-87: an extended response with no associated device ends at its zero count");
    Test_ExpectStatus(ZdoClient_AddressResponseParse(pastTheList, (uint32_t)sizeof pastTheList, &rsp), ZB_OK,
                      "Table 2-87: a zero count still carries StartIndex when devices are associated past it");
    Test_Expect(rsp.numAssocDev == 0 && rsp.startIndex == 9, "and the index is read");
    Test_ExpectStatus(ZdoClient_AddressResponseParse(trailing, (uint32_t)sizeof trailing, &rsp), ZB_ERR_BAD_FRAME,
                      "but nothing may follow it");
    Test_ExpectStatus(ZdoClient_AddressResponseParse(overrun, (uint32_t)sizeof overrun, &rsp), ZB_ERR_BAD_FRAME,
                      "a count that runs past the frame is refused");
    Test_ExpectStatus(ZdoClient_AddressResponseParse(single, 10, &rsp), ZB_ERR_BAD_FRAME,
                      "Figure 2-56: so is a frame short of the network address");
    Test_ExpectStatus(ZdoClient_AddressResponseParse(notFound, (uint32_t)sizeof notFound, &rsp), ZB_OK,
                      "Table 2-87: an error status is read with the addresses the figure still carries");
    Test_ExpectCount(rsp.status, ZDO_STATUS_DEVICE_NOT_FOUND, "Table 2-129: DEVICE_NOT_FOUND");
}

void caseClientMatchAndStatus(void)
{
    static const uint8_t match[] = { 0x00, 0x4d, 0x3c, 0x02, 0x01, 0x0b };
    static const uint8_t overrun[] = { 0x00, 0x4d, 0x3c, 0x03, 0x01 };
    uint8_t endpoints[4];
    uint16_t address = 0;
    uint32_t count = 0;
    uint8_t status = 0xff;

    Test_Case("caseClientMatchAndStatus");

    Test_ExpectStatus(ZdoClient_MatchDescRspParse(match, (uint32_t)sizeof match, &status, &address, endpoints, 4,
                                                  &count), ZB_OK,
                      "Figure 2-62: the status, the address of interest and the matching endpoints behind their count");
    Test_Expect(status == 0 && address == 0x3c4d && count == 2 && endpoints[0] == 0x01 && endpoints[1] == 0x0b,
                "Table 2-93: each as printed");
    Test_ExpectStatus(ZdoClient_MatchDescRspParse(overrun, (uint32_t)sizeof overrun, &status, &address, endpoints, 4,
                                                  &count), ZB_ERR_BAD_FRAME, "a MatchLength past the frame is refused");
    Test_ExpectStatus(ZdoClient_MatchDescRspParse(match, (uint32_t)sizeof match, &status, &address, endpoints, 1,
                                                  &count), ZB_ERR_BAD_FRAME, "and so is one past the caller's room");

    Test_ExpectStatus(ZdoClient_Status(overrun, 1, &status), ZB_OK, "2.4.4.2: every response opens with its status");
    Test_ExpectStatus(ZdoClient_Status(overrun, 0, &status), ZB_ERR_BAD_FRAME, "and an empty one has none");
}
