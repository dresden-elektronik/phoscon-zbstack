/* 3.4.14's Network Commissioning Request, 3.4.15's response, and the parent's answer to one: the address the
   request named, the 0xF0 conflict that names a new one, and Table 3-22's JoinerMethod. */

#include "nwk_cases.h"
#include "nwk_commissioning.h"
#include "nwk_timeout.h"
#include "nwk_helpers.h"
#include "test_harness.h"
#include "zb_utils.h"

static const uint8_t s_initialJoinOctets[] =
{
    0x00, 0x0a,
    0x48, 0x12,
    0x47, 0x04, 0xa1, 0x1f, 0x01, 0x80, 0x00,
    0x41, 0x09, 0x00, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
};

void caseCommissioningCodec(void)
{
    Nwk_CommissioningRequest request;
    Nwk_CommissioningRequest back;
    uint8_t payload[2 + 2 + 2 + NWK_TLV_FRAGMENTATION_OCTETS + 2 + NWK_TLV_KEY_NEGOTIATION_OCTETS];
    uint16_t address = 0;
    uint8_t status = 0;
    uint32_t len = 0;

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    Zb_memset(&back, 0, (uint32_t)sizeof back);
    Zb_memset(payload, 0, (uint32_t)sizeof payload);

    request.type = NWK_COMMISSIONING_INITIAL_JOIN;
    request.capability = 0x0a;
    request.nodeId = 0x1fa1;
    request.fragmentationOptions = NWK_TLV_FRAGMENTATION_APS_BIT;
    request.maxIncomingTransferUnit = 128;
    request.sourceEui64 = 0x0011223344556677;

    Test_ExpectStatus(Nwk_CommissioningRequestCompose(&request, payload, (uint32_t)sizeof payload, &len), ZB_OK,
                      "Figure 3-36's payload with the two TLVs 3.4.14.3.3 makes mandatory");
    Test_ExpectOctets("an Initial Join octet for octet: tag 72 holding tags 71 and 65, the last with no protocol, no secret and the EUI-64",
                      payload, len, s_initialJoinOctets, (uint32_t)sizeof s_initialJoinOctets);
    Test_ExpectCount(payload[0], NWK_COMMISSIONING_INITIAL_JOIN, "Table 3-64's type first");
    Test_ExpectCount(payload[1], 0x0a, "then the capability octet");
    Test_ExpectCount(payload[2], NWK_TLV_TAG_JOINER_ENCAPSULATION, "then the Joiner Encapsulation TLV, tag 72");
    Test_ExpectCount(payload[4], NWK_TLV_TAG_FRAGMENTATION_PARAMETERS, "which carries the Fragmentation Parameters TLV, tag 71");

    Test_ExpectStatus(Nwk_CommissioningRequestParse(payload, len, &back), ZB_OK, "and it reads back");
    Test_ExpectCount(back.nodeId, 0x1fa1, "the Node ID inside the encapsulation");
    Test_ExpectCount(back.maxIncomingTransferUnit, 128, "and the transfer unit beside it");
    Test_Expect(back.keyNegotiationPresent == 1 && back.keyNegotiationProtocols == 0 && back.preSharedSecrets == 0
                && back.sourceEui64 == 0x0011223344556677, "and Figure I-2's three fields");

    request.type = NWK_COMMISSIONING_REJOIN;
    Test_ExpectStatus(Nwk_CommissioningRequestCompose(&request, payload, (uint32_t)sizeof payload, &len), ZB_OK,
                      "a rejoin's request");
    Test_Expect(len == 11 && payload[3] == 6 && payload[4] == NWK_TLV_TAG_FRAGMENTATION_PARAMETERS,
                "carries the Fragmentation Parameters alone: a rejoining device SHALL NOT include tag 65 (3.4.14.3.3)");
    Test_Expect(Nwk_CommissioningRequestParse(payload, len, &back) == ZB_OK && back.keyNegotiationPresent == 0,
                "and reads back without it");
    request.type = NWK_COMMISSIONING_INITIAL_JOIN;
    Test_ExpectStatus(Nwk_CommissioningRequestCompose(&request, payload, (uint32_t)sizeof payload, &len), ZB_OK,
                      "the Initial Join once more");

    payload[2] = 0x01;      /* a request whose only TLV is not the encapsulation */

    Test_ExpectStatus(Nwk_CommissioningRequestParse(payload, len, &back), ZB_ERR_BAD_ARGUMENT,
                      "a request with no Joiner Encapsulation TLV is refused: 3.4.14.3.3 makes it mandatory");

    Test_ExpectStatus(Nwk_CommissioningResponseCompose(0x1fa1, 0, payload, (uint32_t)sizeof payload, &len), ZB_OK,
                      "Figure 3-37's response");
    Test_ExpectStatus(Nwk_CommissioningResponseParse(payload, len, &address, &status), ZB_OK, "reads back");
    Test_ExpectCount(address, 0x1fa1, "the address the device ends up with");
    Test_ExpectCount(status, 0, "and a success");
}

/* Table I-1's records refused where they break their bounds: a header cut short, a value running past its list, and
   a record nested in the encapsulation running past the encapsulation though not past the payload, and an
   encapsulation inside the encapsulation, which I.2.7 step 3d refuses. A tag the walk does not name is stepped over. */
void caseCommissioningMalformed(void)
{
    static const uint8_t cutHeader[] = { 0x00, 0x0a, 0x48 };
    static const uint8_t pastPayload[] = { 0x00, 0x0a, 0x48, 0x12 };
    static const uint8_t pastEncapsulation[] = { 0x00, 0x0a, 0x48, 0x01, 0x47, 0x04, 0xa1, 0x1f, 0x01, 0x80, 0x00 };
    static const uint8_t shortFragmentation[] = { 0x00, 0x0a, 0x48, 0x03, 0x47, 0x01, 0xa1, 0x1f };
    static const uint8_t shortKeyNegotiation[] = { 0x00, 0x0a, 0x48, 0x02, 0x41, 0x00, 0x00 };
    static const uint8_t unknownTag[] = { 0x00, 0x0a, 0x48, 0x02, 0x10, 0x00, 0xff };
    static const uint8_t nestedJoiner[] = { 0x00, 0x0a, 0x48, 0x04, 0x48, 0x02, 0x10, 0x00, 0xff };
    static const uint8_t nestedBeacon[] = { 0x00, 0x0a, 0x48, 0x04, 0x49, 0x02, 0x10, 0x00, 0xff };
    static const uint8_t shortResponse[] = { 0xa1, 0x1f };
    Nwk_CommissioningRequest back;
    uint16_t address = 0;
    uint8_t status = 0;

    Test_ExpectStatus(Nwk_CommissioningRequestParse(cutHeader, (uint32_t)sizeof cutHeader, &back),
                      ZB_ERR_BAD_ARGUMENT, "a record whose length octet is missing is refused");
    Test_ExpectStatus(Nwk_CommissioningRequestParse(pastPayload, (uint32_t)sizeof pastPayload, &back),
                      ZB_ERR_BAD_ARGUMENT, "a value longer than the payload is refused");
    Test_ExpectStatus(Nwk_CommissioningRequestParse(pastEncapsulation, (uint32_t)sizeof pastEncapsulation, &back),
                      ZB_ERR_BAD_ARGUMENT, "a nested record running past the encapsulation is refused");
    Test_ExpectStatus(Nwk_CommissioningRequestParse(shortFragmentation, (uint32_t)sizeof shortFragmentation, &back),
                      ZB_ERR_BAD_ARGUMENT, "Fragmentation Parameters of any other length than five are refused");
    Test_ExpectStatus(Nwk_CommissioningRequestParse(shortKeyNegotiation, (uint32_t)sizeof shortKeyNegotiation, &back),
                      ZB_ERR_BAD_ARGUMENT, "Supported Key Negotiation under its two bitmasks is refused");
    Test_ExpectStatus(Nwk_CommissioningRequestParse(nestedJoiner, (uint32_t)sizeof nestedJoiner, &back),
                      ZB_ERR_BAD_ARGUMENT, "a Joiner Encapsulation inside the Joiner Encapsulation is refused");
    Test_ExpectStatus(Nwk_CommissioningRequestParse(nestedBeacon, (uint32_t)sizeof nestedBeacon, &back),
                      ZB_ERR_BAD_ARGUMENT, "and so is a Beacon Appendix Encapsulation inside it");
    Test_ExpectStatus(Nwk_CommissioningRequestParse(unknownTag, (uint32_t)sizeof unknownTag, &back), ZB_OK,
                      "a tag the walk does not name is stepped over");
    Test_Expect(back.keyNegotiationPresent == 0 && back.nodeId == 0, "and fills nothing");
    Test_ExpectStatus(Nwk_CommissioningResponseParse(shortResponse, (uint32_t)sizeof shortResponse, &address, &status),
                      ZB_ERR_BAD_ARGUMENT, "a response shorter than Figure 3-37's three octets is refused");
}

void caseCommissioningParentAnswers(void)
{
    Test_BandA dev;
    Nwk_CommissioningRequest request;
    Air air[AIR_LOG_MAX];
    Nwk_JoinIndicationParameters indication;
    Nwk_NeighborTableEntry *entry;
    uint8_t payload[1 + 2 + 2 + 2 + NWK_TLV_FRAGMENTATION_OCTETS + 2 + NWK_TLV_KEY_NEGOTIATION_OCTETS];
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    Nwk_Frame frame;
    uint32_t payloadLen = 0;
    uint32_t npduLen;
    uint32_t airCount = 0;

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    Zb_memset(payload, 0, (uint32_t)sizeof payload);

    rig(&dev, OWN_SHORT, PAN_ID);
    dev.nwk.cfg.deviceType = NWK_DEVICE_COORDINATOR;
    dev.nwk.associationPermit = 1;

    request.type = NWK_COMMISSIONING_INITIAL_JOIN;
    request.capability = 0x8a;    /* Table 3-71: a router (bit 1) on battery, receiver on (bit 3), allocate address (bit 7) */
    request.nodeId = NEIGHBOR;
    request.fragmentationOptions = NWK_TLV_FRAGMENTATION_APS_BIT;
    request.maxIncomingTransferUnit = 128;

    Test_ExpectStatus(Nwk_CommissioningRequestCompose(&request, payload + 1, (uint32_t)sizeof payload - 1,
                                                     &payloadLen), ZB_OK,
                      "a commissioning request from a device that named its own address");

    payload[0] = NWK_CMD_NETWORK_COMMISSIONING_REQUEST;
    payloadLen++;

    /* 3.4.14.2: the source IEEE sub-field SHALL be 1, and the destination's too when it is known. */
    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = NWK_FRAME_TYPE_COMMAND;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.discoverRoute = NWK_DISCOVER_SUPPRESS;
    frame.destAddr = OWN_SHORT;
    frame.srcAddr = NEIGHBOR;
    frame.radius = 1;
    frame.sequenceNumber = 0x51;
    frame.srcIeeePresent = 1;
    frame.srcIeee = 0x00212effff060000;
    frame.destIeeePresent = 1;
    frame.destIeee = 0x00212effff070000;

    Test_ExpectStatus(NwkFrame_Compose(&frame, payload, payloadLen, npdu, (uint32_t)sizeof npdu, &npduLen), ZB_OK,
                      "the request composed as 3.4.14.2 shapes its header");

    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "the coordinator's turn takes the request");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_DroppedUnsecured(&dev.nwk), 0, "the unsecured request is accepted, as 3.4.14's own device is not joined yet");
    Test_ExpectCount(Nwk_PollJoinIndications(&dev.nwk, &indication, 1), 1,
                     "3.2.2.14's indication follows the answer");
    Test_ExpectCount(indication.networkAddress, NEIGHBOR,
                     "3.4.15 confirms the address the request named when nothing else holds it");
    Test_ExpectCount(indication.joinerMethod, 3,
                     "with Table 3-22's method 3, the commissioning join");
    Test_Expect(indication.capability.deviceType == 1 && indication.capability.powerSource == 0
                && indication.capability.rxOnWhenIdle == 1 && indication.capability.allocateAddress == 1,
                "and the capability read at Table 3-71's bits: a router on battery whose receiver stays on");

    entry = Nwk_NeighborOf(dev.nwk.neighbors, NEIGHBOR);
    Test_Expect(entry != 0 && entry->relationship == NWK_REL_UNAUTHENTICATED_CHILD
                && entry->deviceType == NWK_DEVICE_ROUTER && entry->extendedAddress == 0x00212effff060000,
                "the joiner the receive path had only heard is made an unauthenticated child (0x05), a router (3.6.1.6.1.3)");
}

void caseTimeoutTable(void)
{
    uint8_t payload[2];
    uint8_t status = 0;
    uint8_t parentInformation = 0;
    uint8_t configuration = 0;
    uint32_t enumeration = 0;
    uint32_t len = 0;

    Test_ExpectCount(Nwk_TimeoutSeconds(0), 10, "Table 3-58's enumeration 0 is 10 seconds");
    Test_ExpectCount(Nwk_TimeoutSeconds(1), 120, "1 is two minutes");
    Test_ExpectCount(Nwk_TimeoutSeconds(2), 240, "and each later one doubles");
    Test_ExpectCount(Nwk_TimeoutSeconds(NWK_TIMEOUT_MAX), 16384 * 60, "to 16384 minutes at 14, the top of the range");
    Test_ExpectCount(Nwk_TimeoutSeconds(NWK_TIMEOUT_MAX + 1), 0, "and one past it has no value at all");

    Zb_memset(payload, 0, (uint32_t)sizeof payload);

    Test_ExpectStatus(Nwk_TimeoutRequestCompose(2, 0, payload, (uint32_t)sizeof payload, &len), ZB_OK,
                      "Figure 3-31's two fields");
    Test_ExpectStatus(Nwk_TimeoutRequestParse(payload, len, &enumeration, &configuration), ZB_OK, "read back");
    Test_ExpectCount(enumeration, 2, "the enumeration");
    Test_ExpectCount(configuration, 0, "and the configuration field, which this revision defines no bit of");

    Test_ExpectStatus(Nwk_TimeoutResponseCompose(NWK_TIMEOUT_STATUS_SUCCESS, NWK_PARENT_INFORMATION_MAC_DATA_POLL,
                                                 payload, (uint32_t)sizeof payload, &len), ZB_OK,
                      "Figure 3-32's two fields");
    Test_ExpectStatus(Nwk_TimeoutResponseParse(payload, len, &status, &parentInformation), ZB_OK, "read back");
    Test_ExpectCount(status, NWK_TIMEOUT_STATUS_SUCCESS, "a success");
    Test_ExpectCount(parentInformation, 1, "and bit 0, the MAC data poll keepalive this parent asks for");
}
