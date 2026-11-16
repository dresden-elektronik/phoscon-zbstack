/* The Route Request of Figure 3-9 and its Annex K/I tail, case by case: the payload this stack composes,
   octet by octet, and every refusal the frame itself decides. The vectors are computed from Figure 3-9's field
   order, Table 3-54's identifier octet that the figure omits, Figure 3-10's bit positions, Table I-1's
   tag/length pair and Figure K-1's three value octets, and each anchor is asserted as the number the table
   prints rather than as a copy of the builder's own expression. No `Nwk_Nwk`, no radio and no clock anywhere
   in the file: `Nwk_RreqCompose` and `Nwk_RreqParse` are pure octets in and octets out. */

#include "nwk_routedisc_cases.h"

#include "nwk_command.h"
#include "nwk_routedisc_helpers.h"
#include "nwk_rreq.h"
#include "nwk_tlv.h"
#include "test_harness.h"
#include "u_bstream.h"
#include "zb_utils.h"

enum
{
    REQUEST_ID = 0x07,              /* 3.4.1.3.2's octet, one more than the previous request this device issued */
    DESTINATION = 0x1234,
    ROUTING_SEQ_SEED = 0x1234,      /* nwkRoutingSequenceNumber before the request increments it (K.2.1.1.1) */
    INITIAL_RADIUS = 30,            /* 2 x nwkcMaxDepth, Table 3-65; K.5.4's fallback when the TLV is absent */
    CONCENTRATOR_DISCOVERY_TIME = 0x0a, /* nwkConcentratorDiscoveryTime, ten seconds (Table 3-66) */
    MAX_SOURCE_ROUTE = 0x0c,        /* nwkMaxSourceRoute, NIB 0x93, Table 3-66's default */

    OPTIONS_DEST_IEEE = 0x20,       /* Figure 3-10's bit 5 */
    OPTIONS_MANY_TO_ONE_RECORD = 0x08, /* bits 3-4 at Table 3-55's value 1 */
    OPTIONS_MANY_TO_ONE_RESERVED = 0x18, /* bits 3-4 at its value 3 */
    OPTIONS_DEPRECATED = 0x40,      /* bit 6 (3.6.7) */
    TLV_TAG_EXTENDED_ROUTE = 0x00,  /* K.2.1.1's local tag id */
    TLV_TAG_CONCENTRATOR = 0x01,    /* K.2.1.2's */
    TLV_TAG_THREE_VALUE = 0x02,     /* Table I-1: Figure K-1's three octets, one less */
    TLV_TAG_TWO_VALUE = 0x01,       /* Table I-1: Figure K-2's two octets, one less */

    FIXED_OCTETS = 6,               /* identifier, options, request id, destination, path cost */
    IEEE_OCTETS = 8                 /* 3.4.1.3.5 */
};

#define DEST_IEEE_ADDRESS 0x00124b0001abcdef

/* The payload every case starts from: this device's request id, a destination and a path cost of zero (9065) */
static void rreqAt(Nwk_RouteRequestPayload *req, uint16_t destAddr)
{
    Zb_memset(req, 0, (uint32_t)sizeof *req);

    req->requestId = REQUEST_ID;
    req->destAddr = destAddr;
    req->pathCost = 0;
    req->manyToOne = NWK_RREQ_MANY_TO_ONE_NONE;
    req->maxSourceRoute = MAX_SOURCE_ROUTE;
}

/* A whole unicast request's payload, with or without the destination's IEEE address; its length comes back */
static uint32_t unicastPayload(uint8_t *out, uint32_t outMax, int withIeee)
{
    Nwk_RouteRequestPayload req;
    uint32_t routingSeq = ROUTING_SEQ_SEED;

    rreqAt(&req, DESTINATION);

    if (withIeee)
    {
        req.destIeeePresent = 1;
        req.destIeee = DEST_IEEE_ADDRESS;
    }

    return composeRreq(&req, &routingSeq, INITIAL_RADIUS, out, outMax);
}

void caseRreqComposeWithDestinationIeee(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestPayload req;
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t len;

    rreqAt(&req, DESTINATION);
    req.destIeeePresent = 1;
    req.destIeee = DEST_IEEE_ADDRESS;

    len = composeRreq(&req, &routingSeq, INITIAL_RADIUS, payload, (uint32_t)sizeof payload);

    Test_ExpectCount(len, 19, "Figure 3-9's five fields, eight IEEE octets and one five-octet TLV");
    Test_ExpectHex("Figure 3-9's payload with its TLV tail", payload, len,
                   "012007341200efcdab01004b1200000235121e");
    Test_ExpectCount(payload[0], 0x01, "Table 3-54's route request identifier, the octet Figure 3-9 omits");
    Test_ExpectCount(payload[1], OPTIONS_DEST_IEEE, "Figure 3-10: bit 5 alone, many-to-one 0 and bit 6 clear");
    Test_ExpectCount(payload[5], 0x00, "3.4.1.3.4: the initiator's path cost");
    Test_ExpectCount(payload[FIXED_OCTETS + IEEE_OCTETS], TLV_TAG_EXTENDED_ROUTE, "Table I-1's tag field");
    Test_ExpectCount(payload[FIXED_OCTETS + IEEE_OCTETS + 1], TLV_TAG_THREE_VALUE,
                     "Table I-1's length field: Figure K-1's three octets, one less");
    Test_ExpectCount(payload[FIXED_OCTETS + IEEE_OCTETS + 2], 0x35, "K.2.1.1.1's number, low octet first");
    Test_ExpectCount(payload[FIXED_OCTETS + IEEE_OCTETS + 4], INITIAL_RADIUS, "K.2.1.1.2's initial radius");
    Test_ExpectCount(routingSeq, ROUTING_SEQ_SEED + 1, "the counter moved by the one request composed");
}

void caseRreqComposeWithoutDestinationIeee(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    uint32_t len = unicastPayload(payload, (uint32_t)sizeof payload, 0);

    Test_ExpectCount(len, 11, "the same request without the eight IEEE octets of 3.4.1.3.5");
    Test_ExpectHex("Figure 3-9's payload, both address-less and TLV-terminated", payload, len,
                   "010007341200000235121e");
    Test_ExpectCount(payload[1], 0x00, "Figure 3-10: bit 5 clear and every other bit zero");
}

void caseRreqComposeManyToOneWithConcentrator(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestPayload req;
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t len;

    rreqAt(&req, NWK_ADDR_ROUTERS);
    req.manyToOne = NWK_RREQ_MANY_TO_ONE_WITH_RECORD;
    req.concentrator = 1;
    req.concentratorDiscoveryTime = CONCENTRATOR_DISCOVERY_TIME;

    len = composeRreq(&req, &routingSeq, INITIAL_RADIUS, payload, (uint32_t)sizeof payload);

    Test_ExpectCount(len, 15, "the same fields, the Extended Route Information and the Concentrator one");
    Test_ExpectHex("a many-to-one request to all routers and the coordinator", payload, len,
                   "010807fcff00000235121e01010a0c");
    Test_ExpectCount(payload[1], OPTIONS_MANY_TO_ONE_RECORD, "Table 3-55's value 1 in Figure 3-10's bits 3-4");
    Test_ExpectCount(payload[11], TLV_TAG_CONCENTRATOR, "K.2.1.2's local tag id");
    Test_ExpectCount(payload[12], TLV_TAG_TWO_VALUE, "Table I-1: Figure K-2's two octets, one less");
    Test_ExpectCount(payload[13], CONCENTRATOR_DISCOVERY_TIME, "K.2.1.2.1's nwkConcentratorDiscoveryTime");
    Test_ExpectCount(payload[14], MAX_SOURCE_ROUTE, "K.2.1.2.2's nwkMaxSourceRoute");

    /* K.2.1.2 makes the TLV the 0xfffc destination's: the same concentrator asking for a unicast sends none */
    req.destAddr = DESTINATION;
    routingSeq = ROUTING_SEQ_SEED;
    len = composeRreq(&req, &routingSeq, INITIAL_RADIUS, payload, (uint32_t)sizeof payload);

    Test_ExpectCount(len, 11, "a concentrator's unicast request carries no Concentrator Information TLV");
    Test_ExpectCount(payload[1], OPTIONS_MANY_TO_ONE_RECORD, "and still carries its many-to-one value");
}

void caseRreqParseRoundTripsThoseThree(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    Nwk_RouteRequestPayload req;
    uint32_t routingSeq;
    uint32_t len;
    ZbStatus status;

    len = unicastPayload(payload, (uint32_t)sizeof payload, 1);
    status = Nwk_RreqParse(payload, len, &fields);

    Test_ExpectStatus(status, ZB_OK, "the request this module composed is one it reads");
    Test_ExpectCount(fields.requestId, REQUEST_ID, "3.4.1.3.2's octet comes back");
    Test_ExpectCount(fields.destAddr, DESTINATION, "3.4.1.3.3's destination comes back");
    Test_ExpectCount(fields.pathCost, 0, "3.4.1.3.4's path cost comes back");
    Test_ExpectCount(fields.manyToOne, NWK_RREQ_MANY_TO_ONE_NONE, "Table 3-55's value");
    Test_ExpectCount(fields.destIeeePresent, 1, "Figure 3-10's bit 5");
    Test_Expect(fields.destIeee == DEST_IEEE_ADDRESS, "3.4.1.3.5's eight octets, in the order 3.3 prints them");
    Test_ExpectCount(fields.tlvOutcome, NWK_TLV_OK, "K.2.1's tail was read");
    Test_ExpectCount(fields.extendedRouteInfo, 1, "K.2.1.1's TLV was there");
    Test_ExpectCount(fields.routingSequenceNumber, ROUTING_SEQ_SEED + 1, "K.2.1.1.1's number");
    Test_ExpectCount(fields.initialRadius, INITIAL_RADIUS, "K.2.1.1.2's radius");
    Test_ExpectCount(fields.concentratorInfoPresent, 0, "K.2.1.2's TLV was not there");

    len = unicastPayload(payload, (uint32_t)sizeof payload, 0);
    status = Nwk_RreqParse(payload, len, &fields);

    Test_ExpectStatus(status, ZB_OK, "the address-less request reads back too");
    Test_ExpectCount(fields.destIeeePresent, 0, "Figure 3-10's bit 5 clear");
    Test_Expect(fields.destIeee == 0, "and no octet of an address is invented");

    rreqAt(&req, NWK_ADDR_ROUTERS);
    req.manyToOne = NWK_RREQ_MANY_TO_ONE_WITH_RECORD;
    req.concentrator = 1;
    req.concentratorDiscoveryTime = CONCENTRATOR_DISCOVERY_TIME;
    routingSeq = ROUTING_SEQ_SEED;
    len = composeRreq(&req, &routingSeq, INITIAL_RADIUS, payload, (uint32_t)sizeof payload);
    status = Nwk_RreqParse(payload, len, &fields);

    Test_ExpectStatus(status, ZB_OK, "the many-to-one request reads back too");
    Test_ExpectCount(fields.manyToOne, NWK_RREQ_MANY_TO_ONE_WITH_RECORD, "Table 3-55's value 1");
    Test_ExpectCount(fields.destAddr, NWK_ADDR_ROUTERS, "3.4.1.3.3's all-routers destination");
    Test_ExpectCount(fields.concentratorInfoPresent, 1, "K.2.1.2's TLV, read as far as presence");
    Test_ExpectCount(fields.solicitationPresent, 0, "K.2.1.3's TLV was not there");
}

void caseRreqRefusesAShortPayload(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    uint32_t len = unicastPayload(payload, (uint32_t)sizeof payload, 0);
    uint32_t n;

    Test_ExpectStatus(Nwk_RreqParse(payload, len, &fields), ZB_OK,
                      "the payload this case shortens is one that reads whole");

    for (n = 0; n < FIXED_OCTETS; n++)
    {
        Test_ExpectStatus(Nwk_RreqParse(payload, n, &fields), ZB_ERR_BAD_FRAME,
                          "a payload shorter than Figure 3-9's own five fields");
    }
}

void caseRreqRefusesManyToOneReserved(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    Nwk_RouteRequestPayload req;
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t len;
    uint32_t composedLen = 0;

    len = unicastPayload(payload, (uint32_t)sizeof payload, 0);
    payload[1] = OPTIONS_MANY_TO_ONE_RESERVED;

    Test_ExpectStatus(Nwk_RreqParse(payload, len, &fields), ZB_OK,
                      "Table 3-55's value 3 is Reserved, and 1.4.2 asks a receiver to zero a reserved field and process nothing from its content");
    Test_Expect(fields.manyToOne == NWK_RREQ_MANY_TO_ONE_NONE,
                "so the reserved value reads as no many-to-one request at all, which is what a sender that had nothing to say would have written");

    rreqAt(&req, DESTINATION);
    req.manyToOne = NWK_RREQ_OPTION_MANY_TO_ONE_RESERVED;

    Test_ExpectStatus(Nwk_RreqCompose(&req, &routingSeq, INITIAL_RADIUS, payload,
                                      (uint32_t)sizeof payload, &composedLen),
                      ZB_ERR_BAD_ARGUMENT, "and the same value is refused on the way out");
    Test_ExpectCount(routingSeq, ROUTING_SEQ_SEED, "a refused request spends no routing sequence number");
}

/* §1.4.2: Figure 3-10's bits 0-2 and 7 are a reserved field, a device "SHALL zero these fields and SHALL make no
   further assumptions about these fields nor perform processing based on their content", so a received copy
   carrying one is read like any other and the composer writes them zero. */
void caseRreqReadsThroughReservedOptionBits(void)
{
    static const uint8_t reservedBits[4] = {0x01, 0x02, 0x04, 0x80};
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    uint32_t len = unicastPayload(payload, (uint32_t)sizeof payload, 0);
    uint32_t i;
    uint32_t read = 0;
    uint32_t zero = payload[1];

    Test_ExpectCount((uint32_t)(zero & NWK_RREQ_OPTION_RESERVED_MASK), 0,
                     "the composer writes Figure 3-10's reserved bits zero");

    for (i = 0; i < 4; i++)
    {
        payload[1] = (uint8_t)(payload[1] | reservedBits[i]);

        if (Nwk_RreqParse(payload, len, &fields) == ZB_OK
            && fields.destAddr == DESTINATION && fields.requestId == REQUEST_ID)
            read++;
    }

    Test_ExpectCount(read, 4,
                     "and a received request carrying any of them is read, its own fields intact: 1.4.2, no processing on receipt");
}

void caseRreqRefusesTheDeprecatedBit(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    uint32_t len = unicastPayload(payload, (uint32_t)sizeof payload, 0);

    payload[1] = OPTIONS_DEPRECATED;

    Test_ExpectStatus(Nwk_RreqParse(payload, len, &fields), ZB_OK,
                      "Figure 3-10's bit 6, which 3.6.7 deprecates and this stack transmits 0, is a reserved field a receiver zeroes rather than one it refuses (1.4.2)");
}

void caseRreqRefusesIeeeBitWithoutOctets(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    uint32_t len = unicastPayload(payload, (uint32_t)sizeof payload, 0);

    Zb_memset(payload + len, 0, (uint32_t)sizeof payload - len);
    payload[1] = OPTIONS_DEST_IEEE;

    Test_ExpectStatus(Nwk_RreqParse(payload, len, &fields), ZB_ERR_BAD_FRAME,
                      "3.4.1.3.1.2's bit promises the eight octets 3.4.1.3.5 describes");

    Test_ExpectStatus(Nwk_RreqParse(payload, FIXED_OCTETS + IEEE_OCTETS - 1, &fields), ZB_ERR_BAD_FRAME,
                      "one octet short of the eight");
    Test_ExpectStatus(Nwk_RreqParse(payload, FIXED_OCTETS + IEEE_OCTETS, &fields), ZB_OK,
                      "and exactly eight is a request the field itself accepts");
}

void caseRreqRefusesADuplicatedTlv(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    Nwk_TlvSet tlvs;
    uint32_t len = unicastPayload(payload, (uint32_t)sizeof payload, 0);
    uint32_t tailLen = len - FIXED_OCTETS;

    Zb_memcpy(payload + len, payload + FIXED_OCTETS, tailLen);
    len += tailLen;

    Test_ExpectStatus(Nwk_RreqParse(payload, len, &fields), ZB_ERR_BAD_FRAME,
                      "I.2.1: one local tag id twice drops the message");
    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_ROUTE_REQUEST, payload + FIXED_OCTETS, len - FIXED_OCTETS, &tlvs), NWK_TLV_DUPLICATE,
                     "the walk names the duplication rather than the second record");
    Test_ExpectCount(tlvs.extendedRouteInfo, 0, "and reports nothing, the first record included");
}

void caseRreqRefusesATruncatedTlv(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    uint32_t len = unicastPayload(payload, (uint32_t)sizeof payload, 0);

    Zb_memset(payload + len, 0, (uint32_t)sizeof payload - len);
    payload[FIXED_OCTETS] = TLV_TAG_EXTENDED_ROUTE;
    payload[FIXED_OCTETS + 1] = 0x04;   /* five value octets promised, two present */
    payload[FIXED_OCTETS + 2] = 0x34;
    payload[FIXED_OCTETS + 3] = 0x12;

    Test_ExpectStatus(Nwk_RreqParse(payload, FIXED_OCTETS + 4, &fields), ZB_ERR_BAD_FRAME,
                      "I.2.5: a length field that runs past the payload is malformed");
}

void caseExtendedRouteInformationAbsentFallsBack(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    uint32_t len;
    ZbStatus status;

    len = unicastPayload(payload, (uint32_t)sizeof payload, 0);

    Zb_memset(payload + FIXED_OCTETS, 0, len - FIXED_OCTETS);
    status = Nwk_RreqParse(payload, FIXED_OCTETS, &fields);

    Test_ExpectStatus(status, ZB_OK, "K.2.1.1: a request from an earlier revision is tolerated");
    Test_ExpectCount(fields.tlvOutcome, NWK_TLV_ABSENT, "and its tail is reported as no TLVs at all");
    Test_ExpectCount(fields.extendedRouteInfo, 0, "no Extended Route Information was read");
    Test_ExpectCount(fields.initialRadius, 30, "K.5.4 falls back to twice nwkcMaxDepth, 15 in Table 3-65");
}

void caseExtendedRouteInformationLongerIsRead(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    uint32_t len = unicastPayload(payload, (uint32_t)sizeof payload, 0);

    payload[FIXED_OCTETS + 1] = 0x04;   /* five value octets: Figure K-1's three and two more */
    payload[len] = 0xaa;
    payload[len + 1] = 0xbb;

    Test_ExpectStatus(Nwk_RreqParse(payload, len + 2, &fields), ZB_OK,
                      "I.2.4: a known TLV longer than its minimum SHALL NOT be dropped");
    Test_ExpectCount(fields.extendedRouteInfo, 1, "the TLV is read");
    Test_ExpectCount(fields.routingSequenceNumber, ROUTING_SEQ_SEED + 1, "its known prefix is interpreted");
    Test_ExpectCount(fields.initialRadius, INITIAL_RADIUS, "the initial radius with it");
}

void caseRreqRefusesATwoOctetExtendedRouteInformation(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    Nwk_TlvSet tlvs;
    uint32_t len = unicastPayload(payload, (uint32_t)sizeof payload, 0);

    Zb_memset(&fields, 0, (uint32_t)sizeof fields);
    payload[FIXED_OCTETS + 1] = TLV_TAG_TWO_VALUE;  /* Figure K-4's two value octets, not Figure K-1's three */

    Test_ExpectStatus(Nwk_RreqParse(payload, len - 1, &fields), ZB_ERR_BAD_FRAME,
                      "I.2.5: Figure K-1 prints three octets and a request carrying two is malformed");
    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_ROUTE_REQUEST, payload + FIXED_OCTETS, len - 1 - FIXED_OCTETS, &tlvs), NWK_TLV_OK,
                     "the walk reads them: two octets are the shortest value the Annex prints a record with");
    Test_ExpectCount(tlvs.extendedRouteInfo, 1, "so it reports the record it read");
    Test_ExpectCount(tlvs.routingSequenceNumber, ROUTING_SEQ_SEED + 1, "and the number in its first two octets");
    Test_ExpectCount(tlvs.initialRadiusPresent, 0, "while Figure K-1's third octet is reported absent");
    Test_ExpectCount(fields.extendedRouteInfo, 0, "and nothing of the refused message is reported as read");
}

void caseUnknownLocalTagIsIgnored(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    uint32_t len = unicastPayload(payload, (uint32_t)sizeof payload, 0);

    payload[len] = 0x07;                /* a local id no command of this revision defines */
    payload[len + 1] = 0x01;
    payload[len + 2] = 0xaa;
    payload[len + 3] = 0xbb;

    Test_ExpectStatus(Nwk_RreqParse(payload, len + 4, &fields), ZB_OK,
                      "I.2.3: an unknown tag id is ignored and the message still processes");
    Test_ExpectCount(fields.extendedRouteInfo, 1, "the record before it was read");

    /* the same record ahead of the Extended Route Information: I.2.1 makes the order not matter */
    payload[FIXED_OCTETS] = 0x07;
    payload[FIXED_OCTETS + 1] = 0x01;
    payload[FIXED_OCTETS + 2] = 0xaa;
    payload[FIXED_OCTETS + 3] = 0xbb;
    payload[FIXED_OCTETS + 4] = TLV_TAG_EXTENDED_ROUTE;
    payload[FIXED_OCTETS + 5] = TLV_TAG_THREE_VALUE;
    payload[FIXED_OCTETS + 6] = 0x35;
    payload[FIXED_OCTETS + 7] = 0x12;
    payload[FIXED_OCTETS + 8] = INITIAL_RADIUS;

    Test_ExpectStatus(Nwk_RreqParse(payload, FIXED_OCTETS + 9, &fields), ZB_OK,
                      "the same two records in the other order");
    Test_ExpectCount(fields.extendedRouteInfo, 1, "I.2.1: order SHALL NOT matter");

    Test_ExpectStatus(Nwk_RreqParse(payload, FIXED_OCTETS + 4, &fields), ZB_OK,
                      "an unknown tag alone is still a request that reads");
    Test_ExpectCount(fields.extendedRouteInfo, 0, "with no Extended Route Information in it");
    Test_ExpectCount(fields.initialRadius, INITIAL_RADIUS, "and K.5.4's fallback for the radius");
}

void caseMalformedTlvTerminatesWhatPrecededIt(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    Nwk_TlvSet tlvs;
    uint32_t len = unicastPayload(payload, (uint32_t)sizeof payload, 0);

    payload[len] = 0x03;                /* a local id this command does not define, with a bad length */
    payload[len + 1] = 0x05;            /* six value octets promised, one present */
    payload[len + 2] = 0xaa;

    Test_ExpectStatus(Nwk_RreqParse(payload, len + 3, &fields), ZB_ERR_BAD_FRAME,
                      "I.2.5: a truncated TLV terminates the message");
    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_ROUTE_REQUEST, payload + FIXED_OCTETS, len + 3 - FIXED_OCTETS, &tlvs), NWK_TLV_MALFORMED,
                     "the walk answers malformed");
    Test_ExpectCount(tlvs.extendedRouteInfo, 0,
                     "and the valid Extended Route Information before it is not processed either");
    Test_ExpectCount(tlvs.routingSequenceNumber, 0, "nothing it carried is reported");

    /* the malformed record ahead of a whole Extended Route Information: that one is dropped too */
    payload[FIXED_OCTETS] = 0x03;
    payload[FIXED_OCTETS + 1] = 0x08;
    payload[FIXED_OCTETS + 2] = 0xaa;
    payload[FIXED_OCTETS + 3] = TLV_TAG_EXTENDED_ROUTE;
    payload[FIXED_OCTETS + 4] = TLV_TAG_THREE_VALUE;
    payload[FIXED_OCTETS + 5] = 0x35;
    payload[FIXED_OCTETS + 6] = 0x12;
    payload[FIXED_OCTETS + 7] = INITIAL_RADIUS;

    Test_ExpectStatus(Nwk_RreqParse(payload, FIXED_OCTETS + 8, &fields), ZB_ERR_BAD_FRAME,
                      "the drop does not depend on where the offender stands");
}

void caseExtendedRouteInformationWriter(void)
{
    uint8_t octets[8];
    uint8_t narrow[4];
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestPayload req;
    U_BStream stream;
    uint32_t routingSeq = 0xffff;
    uint32_t len;

    U_bstream_init(&stream, octets, (unsigned long)sizeof octets);

    Nwk_TlvPutExtendedRouteInformation(&stream, 0x3412, INITIAL_RADIUS);

    Test_ExpectCount((uint32_t)stream.pos, 5, "Figure K-1's three octets behind Table I-1's two fields");
    Test_ExpectHex("the Extended Route Information TLV as it goes on the wire", octets, (uint32_t)stream.pos,
                   "000212341e");
    Test_ExpectCount(octets[0], NWK_TLV_TAG_EXTENDED_ROUTE, "K.2.1.1's local tag id is zero (I.1.2)");
    Test_ExpectCount(octets[1], 0x02, "Table I-1's length field is the value's octets less one");

    U_bstream_init(&stream, narrow, (unsigned long)sizeof narrow);
    Nwk_TlvPutExtendedRouteInformation(&stream, 0x3412, INITIAL_RADIUS);

    Test_Expect(stream.status == U_BSTREAM_WRITE_PAST_END, "a five-octet record does not fit in four");

    rreqAt(&req, DESTINATION);
    len = composeRreq(&req, &routingSeq, INITIAL_RADIUS, payload, (uint32_t)sizeof payload);

    Test_ExpectCount(len, 11, "the request is still composed");
    Test_ExpectCount(routingSeq, 0, "nwkRoutingSequenceNumber is 0-0xffff (Table 3-66) and this one wrapped");
    Test_ExpectCount(payload[FIXED_OCTETS + 2], 0x00, "K.2.1.1.1's number after the increment, low octet first");
    Test_ExpectCount(payload[FIXED_OCTETS + 3], 0x00, "and its high octet");
}

/* K.2.1.2's "MUST forward this TLV without modification": the relayed payload is the received one with only
   3.4.1.3.4's path cost octet replaced, so the tail and every identity around it stay where they arrived. */
void caseRreqComposeForwardCarriesTheTail(void)
{
    uint8_t composed[NWK_RREQ_PAYLOAD_MAX + IEEE_OCTETS + 6];
    uint8_t forwarded[NWK_RREQ_PAYLOAD_MAX + IEEE_OCTETS + 6];
    Nwk_RouteRequestPayload request;
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t forwardedLen = 0;
    uint32_t composedLen;
    uint32_t i;
    uint32_t differing = 0;
    ZbStatus status;

    rreqAt(&request, NWK_ADDR_ROUTERS);
    request.concentrator = 1;
    request.concentratorDiscoveryTime = CONCENTRATOR_DISCOVERY_TIME;
    request.maxSourceRoute = MAX_SOURCE_ROUTE;
    request.destIeeePresent = 1;
    request.destIeee = DEST_IEEE_ADDRESS;

    composedLen = composeRreq(&request, &routingSeq, INITIAL_RADIUS, composed, (uint32_t)sizeof composed);

    Test_ExpectCount(composedLen, FIXED_OCTETS + IEEE_OCTETS + 5 + 4,
                     "9102-9105: Figure 3-9's five fields, 3.4.1.3.5's address, Figure K-1's record and Figure K-2's");

    /* K.2.1.3's list, appended the way a concentrator writes it: Table I-1's tag, length and two addresses */
    composed[composedLen++] = NWK_TLV_TAG_SOURCE_ROUTE_SOLICITATION;
    composed[composedLen++] = 3;
    composed[composedLen++] = 0x34;
    composed[composedLen++] = 0x12;
    composed[composedLen++] = 0x78;
    composed[composedLen++] = 0x56;

    status = Nwk_RreqComposeRelay(composed, composedLen, 0x22, forwarded, (uint32_t)sizeof forwarded,
                                  &forwardedLen);

    Test_ExpectStatus(status, ZB_OK, "K.2.1.2: the request a forwarder relays is one this module composes");
    Test_ExpectCount(forwardedLen, composedLen, "with the length it arrived with: nothing is appended or dropped");
    Test_ExpectCount(forwarded[FIXED_OCTETS - 1], 0x22, "9124: the path cost is the forward cost this hop computed");
    Test_ExpectCount(forwarded[0], NWK_CMD_ROUTE_REQUEST, "Table 3-54: still a Route Request");
    Test_ExpectCount(forwarded[2], REQUEST_ID, "3.4.1.3.2: with the originator's request id");

    for (i = 0; i < composedLen; i++)
    {
        if (forwarded[i] != composed[i])
            differing++;
    }

    Test_ExpectCount(differing, 1, "exactly one octet differs from the received payload");
    Test_Expect(Zb_memcmp(forwarded, composed, FIXED_OCTETS - 1) == 0,
                "and it is not the identifier, the options, the request id or the destination");
    Test_Expect(Zb_memcmp(forwarded + FIXED_OCTETS, composed + FIXED_OCTETS, composedLen - FIXED_OCTETS) == 0,
                "nor the destination IEEE address and the received tail, both carried where they stood");

    Test_ExpectCount(routingSeq, ROUTING_SEQ_SEED + 1,
                     "K.2.1.1.1's number is the originator's: forwarding moves no counter of this device's");

    Test_ExpectStatus(Nwk_RreqComposeRelay(composed, FIXED_OCTETS - 1, 0x22, forwarded,
                                           (uint32_t)sizeof forwarded, &forwardedLen), ZB_ERR_BAD_FRAME,
                      "a received payload shorter than Figure 3-9's own fields is refused");
    Test_ExpectStatus(Nwk_RreqComposeRelay(composed, composedLen, 0x22, forwarded, composedLen - 1,
                                           &forwardedLen), ZB_ERR_NO_SPACE,
                      "and one that does not fit the caller's buffer is refused, not truncated");
    Test_ExpectStatus(Nwk_RreqComposeRelay(0, composedLen, 0x22, forwarded, (uint32_t)sizeof forwarded,
                                           &forwardedLen), ZB_ERR_BAD_ARGUMENT,
                      "a relay with no received payload is refused at the door");
}

/*
 * I.2.1's duplicate rule is written over every tag id a message carries, and its one exception is a *global*
 * id: "Duplicate TLV Tag IDs in messages are NOT allowed with one exception, described below. When multiple
 * TLVs with the same ID are found in a single message the message SHALL be rejected and dropped. The
 * Manufacturer Specific Global TLV is the one exception and that TLV MAY occur multiple times in a message."
 * A walk that remembers only I.1.2's local range therefore lets the one class of duplicate the Annex names
 * through: two records of a global id are a message that SHALL be dropped, and tag 64 is the only id a message
 * may carry twice.
 */
void caseRreqRefusesADuplicatedGlobalTlv(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    Nwk_TlvSet tlvs;
    uint32_t len = unicastPayload(payload, (uint32_t)sizeof payload, 0);
    uint32_t base;

    /* One global id twice: Table I-3's Router Information, tag 70, two value octets each (I.2.4: a TLV
       longer than its minimum is read and the rest ignored) */
    base = len;
    payload[base] = 70;
    payload[base + 1] = 0x01;
    payload[base + 2] = 0xaa;
    payload[base + 3] = 0xbb;
    payload[base + 4] = 70;
    payload[base + 5] = 0x01;
    payload[base + 6] = 0xcc;
    payload[base + 7] = 0xdd;

    Test_ExpectStatus(Nwk_RreqParse(payload, base + 8, &fields), ZB_ERR_BAD_FRAME,
                      "I.2.1: the same global tag id twice in one message drops it, the manufacturer-specific id being the only id that may repeat");
    Test_Expect(Nwk_TlvRead(NWK_CMD_ROUTE_REQUEST, payload + FIXED_OCTETS, base + 8 - FIXED_OCTETS, &tlvs) == NWK_TLV_DUPLICATE,
                "and the walk says why");
    Test_ExpectCount(tlvs.extendedRouteInfo, 0, "with nothing reported: I.2.5's termination and I.2.1's drop are the same silence");

    /* The Manufacturer Specific Global TLV is that exception: tag 64, twice, and the message stands */
    payload[base] = 64;
    payload[base + 1] = 0x02;
    payload[base + 2] = 0x11;
    payload[base + 3] = 0x22;
    payload[base + 4] = 0x33;
    payload[base + 5] = 64;
    payload[base + 6] = 0x02;
    payload[base + 7] = 0x44;
    payload[base + 8] = 0x55;
    payload[base + 9] = 0x66;

    Test_ExpectStatus(Nwk_RreqParse(payload, base + 10, &fields), ZB_OK,
                      "I.4.1: the Manufacturer Specific Global TLV (id 64) MAY occur more than once, and a message carrying it twice is processed");
    Test_ExpectCount(fields.extendedRouteInfo, 1, "with the request's own record read as it was");

    /* One global and one local id are two ids, not a duplicate */
    payload[base] = 70;
    payload[base + 1] = 0x01;
    payload[base + 2] = 0xaa;
    payload[base + 3] = 0xbb;
    payload[base + 4] = 0x05;
    payload[base + 5] = 0x00;
    payload[base + 6] = 0xcc;

    Test_ExpectStatus(Nwk_RreqParse(payload, base + 7, &fields), ZB_OK,
                      "a global id and a local id that happens to share nothing are two records, and I.2.2 accepts the global one silently");
}

/*
 * I.2.5's second half, which is a rule about *lists*: "Malformed TLVs are also defined as the
 * case where the size is within the minimum and maximum length, but the data contained has
 * been truncated. For example, if the TLV defines a list of 2-byte node IDs and the length
 * value causes the TLV to truncate in the middle of a 2-byte node ID, this is considered
 * malformed." K.2.1.3's Source Route Solicitation TLV is that list ("a list of one or more
 * network short addresses"), so an odd value length is a half address and the message terminates.
 */
void caseRreqRefusesAnOddSolicitationList(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    Nwk_TlvSet tlvs;
    uint32_t len = unicastPayload(payload, (uint32_t)sizeof payload, 0);
    uint32_t base = len;

    /* Tag 2, three value octets: one address and a half */
    payload[base] = 2;
    payload[base + 1] = 0x02;
    payload[base + 2] = 0x34;
    payload[base + 3] = 0x12;
    payload[base + 4] = 0x78;

    Test_ExpectStatus(Nwk_RreqParse(payload, base + 5, &fields), ZB_ERR_BAD_FRAME,
                      "I.2.5: a K.2.1.3 list truncated inside a 2-octet network address is malformed, and processing terminates");
    Test_Expect(Nwk_TlvRead(NWK_CMD_ROUTE_REQUEST, payload + FIXED_OCTETS, base + 5 - FIXED_OCTETS, &tlvs) == NWK_TLV_MALFORMED,
                "the walk names it malformed rather than reading the half address as a well-formed record");

    /* Two addresses: the same tag, a value of four octets, and the message processes */
    payload[base + 1] = 0x03;
    payload[base + 4] = 0x78;
    payload[base + 5] = 0x56;

    Test_ExpectStatus(Nwk_RreqParse(payload, base + 6, &fields), ZB_OK,
                      "and two whole addresses are the list K.2.1.3 prints, which a solicitation this stack only records by presence still accepts");
    Test_Expect(Nwk_TlvRead(NWK_CMD_ROUTE_REQUEST, payload + FIXED_OCTETS, base + 6 - FIXED_OCTETS, &tlvs) == NWK_TLV_OK,
                "read as the list it is");

    /* One octet: shorter than the minimum Figure K-3 prints, which I.2.5 makes malformed on its own */
    payload[base + 1] = 0x00;

    Test_Expect(Nwk_TlvRead(NWK_CMD_ROUTE_REQUEST, payload + FIXED_OCTETS, base + 3 - FIXED_OCTETS, &tlvs) == NWK_TLV_MALFORMED,
                "and a single octet is below Figure K-3's two-octet minimum");
}

/*
 * I.1.2 makes a local tag id "specific to a particular message", so tag 1 means K.2.1.2's Concentrator
 * Information in a request and nothing at all in a reply (K.3.1.1). Figure K-2 prints two value octets: under a
 * request one octet is I.2.5's malformed and terminates the message, and at two it is the record itself.
 */
void caseRreqTagOneIsMalformedAtItsMinimum(void)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestFields fields;
    Nwk_TlvSet tlvs;
    uint32_t len = unicastPayload(payload, (uint32_t)sizeof payload, 0);

    payload[len] = TLV_TAG_CONCENTRATOR;    /* 0x01, Figure K-2's id */
    payload[len + 1] = 0x00;                /* Table I-1: one value octet, Figure K-2 prints two */
    payload[len + 2] = 0xaa;

    Test_ExpectStatus(Nwk_RreqParse(payload, len + 3, &fields), ZB_ERR_BAD_FRAME,
                      "I.2.5: a request's Concentrator Information shorter than Figure K-2's two octets is malformed");
    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_ROUTE_REQUEST, payload + FIXED_OCTETS, len + 3 - FIXED_OCTETS, &tlvs),
                     NWK_TLV_MALFORMED, "the request's walk names the record it is told about malformed");
    Test_ExpectCount(tlvs.extendedRouteInfo, 0, "and reports nothing, the record before it included (I.2.5)");
    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_ROUTE_REPLY, payload + FIXED_OCTETS, len + 3 - FIXED_OCTETS, &tlvs),
                     NWK_TLV_OK, "I.2.3: the same three octets in a reply are a local id K.3.1.1 does not define");
    Test_ExpectCount(tlvs.concentratorInfo, 0, "so no concentrator record is reported there");

    payload[len + 1] = 0x01;                /* Figure K-2's two octets, the minimum */

    Test_ExpectStatus(Nwk_RreqParse(payload, len + 4, &fields), ZB_OK,
                      "at its minimum the record is read and the request processes");
    Test_ExpectCount(fields.concentratorInfoPresent, 1, "K.2.1.2: the request's tag 1 is a Concentrator Information");
    Test_ExpectCount(fields.tlvOutcome, NWK_TLV_OK, "with its tail read whole");
}

/*
 * K.4.1 lists one local TLV for the Network Status command, tag 0, so K.2.1.3's tag 2 is an Unknown Tag there
 * (I.2.3): ignored whatever length it carries, the two-octet minimum and the odd list included, while tag 0 is
 * Figure K-5's two octets and a request's tag 2 of the same octets is the malformed list K.2.1.3 prints.
 */
void caseNetworkStatusTagTwoIsIgnored(void)
{
    /* 3.4.3.3.2's two payload octets are the caller's; the walk sees Figure K-5's record and a stranger */
    static const uint8_t withShortSolicitation[] =
    {
        TLV_TAG_EXTENDED_ROUTE, 0x01, 0x35, 0x12,   /* K.4.1.1: tag 0, Figure K-5's routing sequence number */
        NWK_TLV_TAG_SOURCE_ROUTE_SOLICITATION, 0x00, 0xaa   /* tag 2, one octet: no list at all */
    };
    static const uint8_t withAHalfAddressList[] =
    {
        NWK_TLV_TAG_SOURCE_ROUTE_SOLICITATION, 0x02, 0x34, 0x12, 0x78   /* tag 2, three octets: a half address */
    };
    Nwk_TlvSet tlvs;

    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_NETWORK_STATUS, withShortSolicitation,
                                 (uint32_t)sizeof withShortSolicitation, &tlvs), NWK_TLV_OK,
                     "I.2.3: a network status carrying tag 2 is a message that processes");
    Test_ExpectCount(tlvs.extendedRouteInfo, 1, "K.4.1.1: tag 0 is the one local record the command defines");
    Test_ExpectCount(tlvs.routingSequenceNumber, 0x1235, "Figure K-5's two octets, low octet first");
    Test_ExpectCount(tlvs.sourceRouteSolicitation, 0, "and tag 2 is ignored, so no solicitation is reported");
    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_NETWORK_STATUS, withAHalfAddressList,
                                 (uint32_t)sizeof withAHalfAddressList, &tlvs), NWK_TLV_OK,
                     "an odd list is no malformed record where the command defines no such tag");
    Test_ExpectCount(tlvs.sourceRouteSolicitation, 0, "with nothing reported for it either");
    /* four octets in, past K.4.1.1's tag 0 record: the same list, read under the command that defines it */
    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_ROUTE_REQUEST, withShortSolicitation + 4,
                                 (uint32_t)sizeof withShortSolicitation - 4, &tlvs), NWK_TLV_MALFORMED,
                     "I.2.5: in a request the same octets are K.2.1.3's list shorter than its minimum");
}

/*
 * I.2.1's duplicate rule and I.2.4's extension are rules about the id, not about the message: a global tag id
 * twice drops the message whichever command carries it, and a global tag longer than Table I-3's minimum is
 * read and its unknown octets ignored. Neither is affected by which local tags the command defines.
 */
void caseGlobalTagRulesHoldForEveryCommand(void)
{
    static const uint8_t twice[] =
    {
        70, 0x01, 0xaa, 0xbb,           /* Table I-3's Router Information, the two octets it prints */
        70, 0x01, 0xcc, 0xdd            /* the same id again: I.2.1 rejects the message */
    };
    static const uint8_t longer[] =
    {
        70, 0x03, 0xaa, 0xbb, 0xcc, 0xdd    /* I.2.4: four value octets where Table I-3 prints two */
    };
    Nwk_TlvSet tlvs;

    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_ROUTE_REQUEST, twice, (uint32_t)sizeof twice, &tlvs), NWK_TLV_DUPLICATE,
                     "I.2.1: a duplicated global tag drops a request's message");
    Test_ExpectCount(tlvs.extendedRouteInfo, 0, "and nothing it carried is reported");
    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_ROUTE_REPLY, twice, (uint32_t)sizeof twice, &tlvs), NWK_TLV_DUPLICATE,
                     "a duplicated global tag drops a reply's message");
    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_NETWORK_STATUS, twice, (uint32_t)sizeof twice, &tlvs), NWK_TLV_DUPLICATE,
                     "and a network status's");

    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_ROUTE_REQUEST, longer, (uint32_t)sizeof longer, &tlvs), NWK_TLV_OK,
                     "I.2.4: a global tag longer than its minimum is not dropped from a request");
    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_ROUTE_REPLY, longer, (uint32_t)sizeof longer, &tlvs), NWK_TLV_OK,
                     "nor from a reply");
    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_NETWORK_STATUS, longer, (uint32_t)sizeof longer, &tlvs), NWK_TLV_OK,
                     "nor from a network status");
    Test_ExpectCount(tlvs.extendedRouteInfo, 0, "I.2.2: a global id no clause acts on is silently skipped");
    Test_ExpectCount(tlvs.concentratorInfo, 0, "and it sets nothing a local record would");
    Test_ExpectCount(tlvs.sourceRouteSolicitation, 0, "in any of the three tails");
}

/* I.2.4: a record longer than the octets this stack reads is stepped over whole, so the record behind it is read where
   it starts. */
void caseTlvLongerThanItsFieldsIsSteppedOver(void)
{
    static const uint8_t tlvs[] = {
        NWK_TLV_TAG_EXTENDED_ROUTE, 0x04, 0x34, 0x12, 0x07, 0xee, 0xee,
        NWK_TLV_TAG_CONCENTRATOR, 0x01, 0x0a, 0x05
    };
    Nwk_TlvSet set;

    Test_ExpectCount(Nwk_TlvRead(NWK_CMD_ROUTE_REQUEST, tlvs, (uint32_t)sizeof tlvs, &set), NWK_TLV_OK,
                     "a five-octet Extended Route Information and a Concentrator Information behind it read");
    Test_Expect(set.routingSequenceNumber == 0x1234 && set.initialRadiusPresent && set.initialRadius == 0x07,
                "the fields this stack knows come from the record's first three octets");
    Test_ExpectCount(set.concentratorInfo, 1, "and the record behind it is read from its own tag");
}
