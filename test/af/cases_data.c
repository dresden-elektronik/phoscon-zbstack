/* 2.3's ASDU path: the request an application sends, the endpoint's profile being the one it advertises, and the
   dispatch of an indication to the endpoint that names it. */

#include "af_helpers.h"
#include "aps_frame.h"
#include "loopback_radio.h"
#include "mac_frame.h"
#include "nwk_frame.h"
#include "test_harness.h"
#include "zb_utils.h"

void caseAfDataRequestDoor(void)
{
    Af_Rig rig;
    Af_SimpleDescriptor descriptor;
    Af_DataRequestParameters request;
    uint8_t asdu[4];

    Zb_memset(asdu, 0x5a, (uint32_t)sizeof asdu);

    afRigBuild(&rig, AF_OWN_SHORT);

    descriptor = afDescriptor(1, AF_PROFILE, AF_CLUSTER);
    Test_ExpectStatus(Af_RegisterEndpoint(&rig.af, &descriptor, 0, 0), ZB_OK, "endpoint 1 advertises the cluster");

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.dstAddress = AF_PEER_SHORT;
    request.dstEndpoint = 1;
    request.srcEndpoint = 1;
    request.clusterId = AF_CLUSTER;
    request.asdu = asdu;
    request.asduLength = (uint32_t)sizeof asdu;

    Test_ExpectStatus(Af_DataRequest(&rig.af, &request, 100), ZB_OK,
                      "a request from an endpoint the framework holds is handed to the APS layer");
    Test_ExpectCount(Af_RequestsSent(&rig.af), 1, "and counted as sent");

    request.srcEndpoint = 2;

    Test_ExpectStatus(Af_DataRequest(&rig.af, &request, 200), ZB_ERR_NOT_FOUND,
                      "a source endpoint nobody registered has no profile to send under, so it is refused");
    Test_ExpectCount(Af_RefusedRequests(&rig.af), 1, "and counted as refused");

    request.srcEndpoint = 1;
    request.asduLength = AF_ASDU_MAX + 1;

    Test_ExpectStatus(Af_DataRequest(&rig.af, &request, 300), ZB_ERR_BAD_ARGUMENT,
                      "an ASDU over the framework's own ceiling is refused before the APS layer sees it");
}

void caseAfIndicationDispatch(void)
{
    Af_Rig rig;
    Af_SimpleDescriptor descriptor;
    Af_Indication polled;
    Af_Seen seen;
    Aps_Indication indication;

    Zb_memset(&seen, 0, (uint32_t)sizeof seen);

    afRigBuild(&rig, AF_OWN_SHORT);

    descriptor = afDescriptor(1, AF_PROFILE, AF_CLUSTER);
    Test_ExpectStatus(Af_RegisterEndpoint(&rig.af, &descriptor, afRecord, &seen), ZB_OK,
                      "endpoint 1 registers with the handler the case records through");

    /* The APS service's own ring is filled the way a received frame fills it, and the framework's turn reads it. */
    Zb_memset(&indication, 0, (uint32_t)sizeof indication);

    indication.dstEndpoint = 1;
    indication.srcEndpoint = 1;
    indication.srcAddress = AF_PEER_SHORT;
    indication.profileId = AF_PROFILE;
    indication.clusterId = AF_CLUSTER;
    indication.asduLength = 2;
    indication.asdu[0] = 0x11;
    indication.asdu[1] = 0x22;

    afInjectIndication(&rig.aps, &indication);
    Test_ExpectStatus(Af_Step(&rig.af, 100), ZB_OK, "the framework's turn dispatches it");

    Test_ExpectCount(seen.count, 1, "the endpoint's handler was called once");
    Test_ExpectCount(seen.indications[0].clusterId, AF_CLUSTER, "with the cluster the frame named");
    Test_ExpectCount(seen.indications[0].asduLength, 2, "and the ASDU it carried");
    Test_ExpectCount(seen.indications[0].asdu[1], 0x22, "octet for octet");
    Test_ExpectCount(Af_IndicationsDelivered(&rig.af), 1, "and the delivery is counted");

    Zb_memset(&indication, 0, (uint32_t)sizeof indication);
    indication.dstEndpoint = 7;
    indication.asduLength = 1;

    afInjectIndication(&rig.aps, &indication);
    Test_ExpectStatus(Af_Step(&rig.af, 200), ZB_OK, "is not dispatched");

    Test_ExpectCount(seen.count, 1, "so the handler hears nothing more");
    Test_ExpectCount(Af_IndicationsUnrouted(&rig.af), 1, "and it is counted as unrouted");

    Zb_memset(&indication, 0, (uint32_t)sizeof indication);
    indication.dstEndpoint = 1;
    indication.asduLength = 1;
    indication.asdu[0] = 0x33;

    afInjectIndication(&rig.aps, &indication);
    Test_ExpectStatus(Af_Step(&rig.af, 300), ZB_OK, "is dispatched");
    Test_ExpectCount(seen.count, 2, "so the handler is called a second time");
    Test_ExpectCount(Af_PollIndications(&rig.af, &polled, 1), 0,
                     "and nothing is left in the poll ring, the handler having taken it");
}

/* The APS frame an acknowledged AF request put on the rig's air, parsed; 0 when there is none to read. */
static int afSentApsFrame(Af_Rig *rig, Aps_Frame *out)
{
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Mac_Frame macFrame;
    Nwk_Frame nwkFrame;
    const uint8_t *npdu;
    uint32_t mpduLen;
    uint32_t npduOffset;
    uint32_t npduLen;
    uint32_t apduOffset;
    uint32_t apduLen;

    if (LoopbackRadio_Sent(&rig->stack.model, sent, LOOPBACK_TX_MAX) == 0)
        return 0;

    return MacFrame_Parse(sent[0].bytes, sent[0].len, Mac_Caps(&rig->stack.mac)->psduIncludesFcs, &macFrame, &npdu,
                          &mpduLen, 0) == ZB_OK
           && NwkFrame_Parse(npdu, mpduLen, &nwkFrame, &npduOffset, &npduLen) == ZB_OK
           && ApsFrame_Parse(npdu + npduOffset, npduLen, out, &apduOffset, &apduLen) == ZB_OK;
}

void caseAfAcknowledgedRequestAsksTheAck(void)
{
    Af_Rig rig;
    Af_SimpleDescriptor descriptor;
    Af_DataRequestParameters request;
    Aps_Frame frame;
    uint8_t asdu[4];

    Zb_memset(asdu, 0x5a, (uint32_t)sizeof asdu);
    afRigBuild(&rig, AF_OWN_SHORT);
    Test_BandASeedNeighbor(&rig.stack.nwk, AF_PEER_SHORT, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    descriptor = afDescriptor(1, AF_PROFILE, AF_CLUSTER);
    Test_ExpectStatus(Af_RegisterEndpoint(&rig.af, &descriptor, 0, 0), ZB_OK, "endpoint 1 advertises the cluster");

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    request.dstAddress = AF_PEER_SHORT;
    request.dstEndpoint = 1;
    request.srcEndpoint = 1;
    request.clusterId = AF_CLUSTER;
    request.asdu = asdu;
    request.asduLength = (uint32_t)sizeof asdu;
    request.txOptions = AF_TX_ACKNOWLEDGED;

    Test_ExpectCount(AF_TX_ACKNOWLEDGED, 0x04, "Table 2-2's TxOptions: 0x04 is Acknowledged transmission, 0x02 Use NWK key");
    Test_ExpectStatus(Af_DataRequest(&rig.af, &request, 100), ZB_OK, "an acknowledged request is taken");
    Test_Expect(afSentApsFrame(&rig, &frame) && frame.ackRequest == 1 && frame.securityEnabled == 0,
                "2.2.5.1.1: the frame on the air asks for the APS acknowledgement, and asks for no APS security");
}
