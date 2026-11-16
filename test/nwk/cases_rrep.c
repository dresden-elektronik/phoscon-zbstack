/* The Route Reply of Figure 3-11 and its Annex K/I tail, case by case: the payload this stack composes, octet
   by octet, and every refusal the frame itself decides. The vectors are computed from Figure 3-11's field
   order, Table 3-54's identifier octet that the figure omits, Figure 3-12's bit positions read as 0x30,
   Table I-1's tag/length pair and Figure K-4's two value octets: each anchor asserted as the number the
   table prints rather than as a copy of the builder's own expression. No `Nwk_Nwk`, no radio and no clock
   anywhere in the file: `Nwk_RrepCompose` and `Nwk_RrepParse` are pure octets in and octets out. */

#include "nwk_routeflow_cases.h"

#include "nwk_routeflow_helpers.h"
#include "nwk_rrep.h"
#include "test_harness.h"
#include "zb_utils.h"

enum
{
    REQUEST_ID = 0x07,              /* 3.4.2.3.2: the request this reply answers */
    ORIGINATOR = 0x1234,            /* 3.4.2.3.3 */
    RESPONDER = 0x2345,             /* 3.4.2.3.4 */
    PATH_COST = 2,                  /* 3.4.2.3.5: the link cost of the first hop */
    ROUTING_SEQ_SEED = 0x1234,      /* nwkRoutingSequenceNumber before the reply increments it (9105) */
    INITIAL_RADIUS = 30,            /* 3.4.2.2: nwkcMaxDepth x 2, Table 3-65's 15 */
    RREP_OPTIONS = 0x30,            /* Figure 3-12: bits 4 and 5 set, bit 6 clear, 3.4.2.3.1's two SHALLs */

    IEEE_OCTETS = 8,                /* 3.4.2.3.6 and 3.4.2.3.7 */
    TLV_OCTETS = 4,                 /* Table I-1's tag and length and Figure K-4's two value octets */
    TWO_OCTETS = 0x01,              /* Table I-1: Figure K-4's two octets, one less */
    THREE_OCTETS = 0x02,            /* Table I-1: the request's Figure K-1 carries three, one less */
    TLV_TAG_EXTENDED_ROUTE = 0x00   /* K.3.1.1's local tag id */
};

#define ORIGINATOR_IEEE 0x00124b0001abcdef
#define RESPONDER_IEEE 0x00124b0001ab1234

/* Figure 3-11's whole payload as this module writes it: both addresses, the path cost, both IEEE fields, the TLV */
#define RREP_HEX "0230073412452302efcdab01004b12003412ab01004b120000013512"

/* The one reply every compose case starts from: a request id, the two addresses and a first-hop link cost */
static void rrepAt(Nwk_RouteReplyPayload *reply)
{
    Zb_memset(reply, 0, (uint32_t)sizeof *reply);

    reply->requestId = REQUEST_ID;
    reply->originatorAddr = ORIGINATOR;
    reply->responderAddr = RESPONDER;
    reply->pathCost = PATH_COST;
    reply->originatorIeee = ORIGINATOR_IEEE;
    reply->responderIeee = RESPONDER_IEEE;
}

/* The canonical payload, so the refusal cases patch one field of it rather than rebuild it */
static uint32_t canonicalPayload(uint8_t *out, uint32_t outMax, uint32_t *routingSeq)
{
    Nwk_RouteReplyPayload reply;

    rrepAt(&reply);

    return composeRrep(&reply, routingSeq, out, outMax);
}

void caseRrepComposeCarriesFigure311sOctets(void)
{
    uint8_t payload[NWK_RREP_PAYLOAD_MAX];
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t len;

    len = canonicalPayload(payload, (uint32_t)sizeof payload, &routingSeq);

    Test_ExpectCount(len, 28, "Figure 3-11's six fields, both eight-octet addresses and one four-octet TLV");
    Test_ExpectHex("Figure 3-11's payload with its TLV tail", payload, len, RREP_HEX);
    Test_ExpectCount(payload[0], 0x02, "Table 3-54's route reply identifier, the octet Figure 3-11 omits");
    Test_ExpectCount(payload[1], RREP_OPTIONS, "Figure 3-12 read as 0x30: bits 4 and 5 set, bit 6 clear");
    Test_ExpectCount(payload[2], REQUEST_ID, "3.4.2.3.2: the request identifier copied from the request");
    Test_ExpectCount(payload[3], 0x34, "3.4.2.3.3: the originator's low octet first (3.3)");
    Test_ExpectCount(payload[4], 0x12, "3.4.2.3.3: its high octet");
    Test_ExpectCount(payload[5], 0x45, "3.4.2.3.4: the responder's low octet first");
    Test_ExpectCount(payload[7], PATH_COST, "3.4.2.3.5: the link cost of the first hop");
    Test_ExpectCount(payload[8], 0xef, "3.4.2.3.6: the originator IEEE address, low octet first (3.3)");
    Test_ExpectCount(payload[16], 0x34, "3.4.2.3.7: the responder IEEE address, low octet first");
    Test_ExpectCount(payload[24], TLV_TAG_EXTENDED_ROUTE, "Table I-1's tag field, K.3.1.1's record");
    Test_ExpectCount(payload[25], TWO_OCTETS, "Table I-1's length field: Figure K-4's two octets, one less");
    Test_ExpectCount(payload[26], 0x35, "K.3.1.1.1's routing sequence number, low octet first");
    Test_ExpectCount(payload[27], 0x12, "K.3.1.1.1: and its high octet, the figure's value whole");
    Test_ExpectCount(routingSeq, ROUTING_SEQ_SEED + 1, "9105: the counter moved by the one reply composed");
    Test_ExpectCount(NWK_RREP_RADIUS, INITIAL_RADIUS, "3.4.2.2: the target's radius is nwkcMaxDepth x 2");
    Test_ExpectCount(NWK_RREP_RADIUS_FLOOR, 1, "9229: a received radius of 1 is not a drop");
}

void caseRrepComposeWritesFigureK4sTwoOctets(void)
{
    uint8_t payload[NWK_RREP_PAYLOAD_MAX];
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t len;

    len = canonicalPayload(payload, (uint32_t)sizeof payload, &routingSeq);

    Test_ExpectCount(len - 24, TLV_OCTETS, "Figure K-4's value behind Table I-1's tag and length fields");
    Test_ExpectHex("the Extended Route Information TLV a route reply carries", payload + len - TLV_OCTETS,
                   TLV_OCTETS, "00013512");
    Test_ExpectCount(payload[len - 1], 0x12, "the record ends at the number: Figure K-4 prints no radius after it");
}

void caseRrepParseRoundTripsTheComposedReply(void)
{
    uint8_t payload[NWK_RREP_PAYLOAD_MAX];
    Nwk_RouteReplyFields fields;
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t len;
    ZbStatus status;

    len = canonicalPayload(payload, (uint32_t)sizeof payload, &routingSeq);
    Zb_memset(&fields, 0, (uint32_t)sizeof fields);

    status = Nwk_RrepParse(payload, len, &fields);

    Test_ExpectStatus(status, ZB_OK, "Figure 3-11's own payload reads back");
    Test_ExpectCount(fields.requestId, REQUEST_ID, "3.4.2.3.2");
    Test_ExpectCount(fields.originatorAddr, ORIGINATOR, "3.4.2.3.3");
    Test_ExpectCount(fields.responderAddr, RESPONDER, "3.4.2.3.4");
    Test_ExpectCount(fields.pathCost, PATH_COST, "3.4.2.3.5");
    Test_Expect(fields.originatorIeee == ORIGINATOR_IEEE, "3.4.2.3.6: the eight octets are one address");
    Test_Expect(fields.responderIeee == RESPONDER_IEEE, "3.4.2.3.7: and so are the responder's");
    Test_ExpectCount(fields.routingSequenceNumber, ROUTING_SEQ_SEED + 1, "K.3.1.1.1: the incremented number");
    Test_ExpectCount(fields.tlvOutcome, NWK_TLV_OK, "K.3.1.1's tail was read");
    Test_ExpectCount(fields.extendedRouteInfo, 1, "Figure K-4's record was there");
    Test_ExpectCount(fields.initialRadius, INITIAL_RADIUS,
                     "Figure K-4 prints no radius: K.5.4's 2 x nwkcMaxDepth stands");
}

void caseRrepComposeRefusesAShortBuffer(void)
{
    uint8_t payload[NWK_RREP_PAYLOAD_MAX];
    Nwk_RouteReplyPayload reply;
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t len;
    uint32_t outLen = 0xffffffff;
    ZbStatus status;

    len = canonicalPayload(payload, (uint32_t)sizeof payload, &routingSeq);

    rrepAt(&reply);
    status = Nwk_RrepCompose(&reply, &routingSeq, payload, len - 1, &outLen);

    Test_ExpectStatus(status, ZB_ERR_NO_SPACE, "a buffer one octet short of the payload is refused");
    Test_ExpectCount(routingSeq, ROUTING_SEQ_SEED + 1, "and the sequence number stands where the composed reply left it");
    Test_ExpectCount(outLen, 0xffffffff, "a refused composition writes no length");
}

void caseRrepParseRefusesAShortPayload(void)
{
    uint8_t payload[NWK_RREP_PAYLOAD_MAX];
    Nwk_RouteReplyFields fields;
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t len;
    uint32_t prefix;
    uint32_t refused = 0;

    len = canonicalPayload(payload, (uint32_t)sizeof payload, &routingSeq);

    for (prefix = 0; prefix <= NWK_RREP_FIXED_OCTETS; prefix++)
    {
        if (Nwk_RrepParse(payload, prefix, &fields) != ZB_OK)
            refused++;
    }

    Test_ExpectCount(refused, NWK_RREP_FIXED_OCTETS + 1,
                     "every payload shorter than its own eight octets, and eight octets without the sixteen IEEE octets, is refused");
    Test_Expect(len > NWK_RREP_FIXED_OCTETS, "the vector the prefixes are taken from is the whole payload");
}

/* §1.4.2: Figure 3-12's bits 0-3 and 7 are a reserved field, zeroed on transmission, and on receipt nothing is
   processed on their content, so a reply carrying one is read and not refused. */
void caseRrepParseReadsThroughReservedOptionBits(void)
{
    static const uint8_t reserved[3] = { 0x01, 0x08, 0x80 };
    uint8_t payload[NWK_RREP_PAYLOAD_MAX];
    Nwk_RouteReplyFields fields;
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t len;
    uint32_t i;
    uint32_t read = 0;

    len = canonicalPayload(payload, (uint32_t)sizeof payload, &routingSeq);

    Test_ExpectCount((uint32_t)(payload[1] & NWK_RREP_OPTION_RESERVED_MASK), 0,
                     "the composer writes Figure 3-12's reserved bits zero (3.4.2.3.1 sets only the two IEEE bits)");

    for (i = 0; i < 3; i++)
    {
        payload[1] = (uint8_t)(RREP_OPTIONS | reserved[i]);

        if (Nwk_RrepParse(payload, len, &fields) == ZB_OK && fields.responderAddr == RESPONDER)
            read++;
    }

    Test_ExpectCount(read, 3,
                     "and a received reply carrying any of them is read with its fields intact: 1.4.2, a reserved bit is no processing on receipt");
}

void caseRrepParseRefusesTheDeprecatedBit(void)
{
    uint8_t payload[NWK_RREP_PAYLOAD_MAX];
    Nwk_RouteReplyFields fields;
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t len;
    ZbStatus status;

    len = canonicalPayload(payload, (uint32_t)sizeof payload, &routingSeq);
    payload[1] = (uint8_t)(RREP_OPTIONS | NWK_RREP_OPTION_MULTICAST);

    status = Nwk_RrepParse(payload, len, &fields);

    Test_ExpectStatus(status, ZB_OK,
                  "3.6.7's deprecated multicast bit is a reserved field a receiver zeroes rather than one it refuses, which is 1.4.2's rule for every such field");
}

void caseRrepParseRefusesTheThreeOtherIeeeCombinations(void)
{
    static const char *const vectors[3] = {
        "020007341245230200013512",
        "0210073412452302efcdab01004b120000013512",
        "02200734124523023412ab01004b120000013512"
    };
    uint8_t payload[NWK_RREP_PAYLOAD_MAX];
    Nwk_RouteReplyFields fields;
    uint32_t len;
    uint32_t i;
    uint32_t refused = 0;

    for (i = 0; i < 3; i++)
    {
        len = Test_ParseHex(vectors[i], payload, (uint32_t)sizeof payload);

        if (Nwk_RrepParse(payload, len, &fields) != ZB_OK)
            refused++;
    }

    Test_ExpectCount(refused, 3,
                     "Figure 3-11's 0/8 permits neither IEEE address or one of them; 3.4.2.3.1's SHALL refuses all three");
    Test_ExpectCount((uint32_t)Test_ParseHex(vectors[0], payload, (uint32_t)sizeof payload), 12,
                     "the first vector is eight header octets and the two-octet TLV alone");
}

void caseRrepParseTakesAnAbsentExtendedRouteInformation(void)
{
    static const char *const vectors[2] = {
        "0230073412452302efcdab01004b12003412ab01004b1200",         /* no tail at all */
        "0230073412452302efcdab01004b12003412ab01004b120001010a0c"  /* a tail without K.3.1.1's record */
    };
    uint8_t payload[NWK_RREP_PAYLOAD_MAX];
    Nwk_RouteReplyFields fields;
    uint32_t len;
    ZbStatus status;

    len = Test_ParseHex(vectors[0], payload, (uint32_t)sizeof payload);
    status = Nwk_RrepParse(payload, len, &fields);

    Test_ExpectStatus(status, ZB_OK, "K.3.1.1: an absent Extended Route Information TLV SHALL be tolerated");
    Test_ExpectCount(fields.tlvOutcome, NWK_TLV_ABSENT, "and the tail is reported as no TLVs at all");
    Test_ExpectCount(fields.extendedRouteInfo, 0, "no Figure K-4 record was read");
    Test_ExpectCount(fields.routingSequenceNumber, 0, "so no sequence number arrives with it");
    Test_ExpectCount(fields.initialRadius, INITIAL_RADIUS, "K.5.4 falls back to twice nwkcMaxDepth, 15 in Table 3-65");

    len = Test_ParseHex(vectors[1], payload, (uint32_t)sizeof payload);
    status = Nwk_RrepParse(payload, len, &fields);

    Test_ExpectStatus(status, ZB_OK, "a reply whose tail holds another record and not this one is a reply too");
    Test_ExpectCount(fields.tlvOutcome, NWK_TLV_OK, "the Concentrator Information TLV read and skipped (K.2.1.2)");
    Test_ExpectCount(fields.extendedRouteInfo, 0, "the absence is the one absence K.3.1.1 tolerates");
    Test_ExpectCount(fields.initialRadius, INITIAL_RADIUS, "with the same fallback radius behind it");
}

void caseRrepParseTakesTheRequestsThreeOctetForm(void)
{
    uint8_t payload[NWK_RREP_PAYLOAD_MAX + 1];
    Nwk_RouteReplyFields fields;
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t len;
    ZbStatus status;

    len = canonicalPayload(payload, (uint32_t)sizeof payload - 1, &routingSeq);

    payload[25] = THREE_OCTETS;         /* Figure K-1's five-octet record instead of Figure K-4's */
    payload[len] = 0x11;                /* and its initial radius, a number the reply has no field for */

    status = Nwk_RrepParse(payload, len + 1, &fields);

    Test_ExpectStatus(status, ZB_OK, "I.2.4: a known TLV longer than its minimum SHALL NOT be dropped");
    Test_ExpectCount(fields.extendedRouteInfo, 1, "the record is read");
    Test_ExpectCount(fields.routingSequenceNumber, ROUTING_SEQ_SEED + 1, "its first two octets are the number");
    Test_ExpectCount(fields.initialRadius, INITIAL_RADIUS,
                     "the third octet is the extension I.2.4 ignores: Figure K-4 prints no radius");
}

void caseRrepParseRefusesADuplicatedTlv(void)
{
    uint8_t payload[NWK_RREP_PAYLOAD_MAX + TLV_OCTETS];
    Nwk_RouteReplyFields fields;
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t len;
    uint32_t doubled;
    ZbStatus status;

    len = canonicalPayload(payload, NWK_RREP_PAYLOAD_MAX, &routingSeq);

    Zb_memcpy(payload + len, payload + len - TLV_OCTETS, TLV_OCTETS);
    doubled = len + TLV_OCTETS;

    status = Nwk_RrepParse(payload, doubled, &fields);

    Test_ExpectStatus(status, ZB_ERR_BAD_FRAME, "I.2.1: one local tag id twice in a message drops the message");
}

void caseRrepParseRefusesATruncatedTlv(void)
{
    uint8_t payload[NWK_RREP_PAYLOAD_MAX];
    Nwk_RouteReplyFields fields;
    static const uint8_t truncated[3] = { 0x00, 0x04, 0x35 };
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t len;
    ZbStatus status;

    len = canonicalPayload(payload, (uint32_t)sizeof payload, &routingSeq);

    Zb_memcpy(payload + len - TLV_OCTETS, truncated, 3);

    status = Nwk_RrepParse(payload, len - TLV_OCTETS + 3, &fields);

    Test_ExpectStatus(status, ZB_ERR_BAD_FRAME, "I.2.5: a record shorter than its own length field ends the message");
    Test_ExpectCount((uint32_t)NWK_RREP_FIXED_OCTETS + IEEE_OCTETS + IEEE_OCTETS, 24,
                     "and the eight header octets plus the sixteen IEEE ones are what the tail follows");
}

/* 3.6.4.5.2.1: the forwarder's copy is the received payload with 3.4.2.3.5's octet replaced and nothing else. */
void caseRrepForwardRewritesTheCostAlone(void)
{
    uint8_t received[NWK_RREP_PAYLOAD_MAX];
    uint8_t forwarded[NWK_RREP_PAYLOAD_MAX];
    Nwk_RouteReplyFields before;
    Nwk_RouteReplyFields after;
    uint32_t routingSeq = ROUTING_SEQ_SEED;
    uint32_t forwardedLen = 0;
    uint32_t receivedLen;
    uint32_t i;
    uint32_t changed = 0;

    receivedLen = canonicalPayload(received, (uint32_t)sizeof received, &routingSeq);

    Test_ExpectStatus(Nwk_RrepForward(received, receivedLen, 0x51, forwarded, (uint32_t)sizeof forwarded,
                                      &forwardedLen), ZB_OK,
                      "3.6.4.5.2.1's forward is a payload this module accepts");
    Test_ExpectCount(forwardedLen, receivedLen, "with the length it arrived with: nothing is appended or dropped");

    for (i = 0; i < receivedLen; i++)
    {
        if (forwarded[i] != received[i])
            changed++;
    }

    Test_ExpectCount(changed, 1, "and exactly one octet differs between the two");
    Test_ExpectCount(forwarded[NWK_RREP_PATH_COST_AT], 0x51, "3.4.2.3.5's path cost, the octet 9225-9228 updates");
    Test_ExpectCount(NWK_RREP_PATH_COST_AT, 7, "which is Figure 3-11's eighth field, the identifier octet ahead of it");

    Test_ExpectStatus(Nwk_RrepParse(forwarded, forwardedLen, &after), ZB_OK, "and it reads back as a reply");
    Test_ExpectStatus(Nwk_RrepParse(received, receivedLen, &before), ZB_OK, "as does the one it was forwarded from");

    Test_ExpectCount(after.routingSequenceNumber, before.routingSequenceNumber,
                     "K.3.1.1.1: the responder's routing sequence number is carried, not incremented again");
    Test_ExpectCount(after.requestId, before.requestId, "and 3.4.2.3.2's identifier is the originator's");
    Test_ExpectCount((uint32_t)(after.originatorAddr ^ before.originatorAddr), 0,
                     "3.4.2.3.3: with the originator address untouched");
    Test_ExpectCount((uint32_t)(after.responderAddr ^ before.responderAddr), 0,
                     "3.4.2.3.4: and the responder's, whoever answered");
    Test_ExpectCount((uint32_t)after.pathCost, 0x51, "9243: and the cost the decision carries is the one the payload now holds");

    Test_ExpectStatus(Nwk_RrepForward(forwarded, (uint32_t)NWK_RREP_FIXED_OCTETS + 2 * IEEE_OCTETS - 1, 0,
                                      forwarded, (uint32_t)sizeof forwarded, &forwardedLen), ZB_ERR_BAD_FRAME,
                      "3.4.2.3.6 and 3.4.2.3.7: a payload one octet short of its two mandatory addresses is refused");
    Test_ExpectStatus(Nwk_RrepForward(received, receivedLen, 0, forwarded, receivedLen - 1, &forwardedLen),
                      ZB_ERR_NO_SPACE, "and one that does not fit the caller's buffer is refused, not truncated");
    Test_ExpectStatus(Nwk_RrepForward(0, receivedLen, 0, forwarded, (uint32_t)sizeof forwarded, &forwardedLen),
                      ZB_ERR_BAD_ARGUMENT, "a forward with no payload to read is refused at the door");
}
