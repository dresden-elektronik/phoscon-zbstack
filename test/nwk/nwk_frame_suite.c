/* Suite for band A's Zigbee NWK frame: the FCF of R23.1 Figure 3-5, the octet order of Figure 3-4,
   the source route subframe of 3.3.1.8, the payload boundary that 3.3.2.2.2 puts the command
   identifier at, the security sub-field the codec writes and reads without knowing what it announces,
   and the refusals the clauses name. Every vector here is computed by hand from the clause it cites,
   and not from the codec. */

#include "nwk_addr.h"
#include "nwk_frame.h"
#include "test_harness.h"
#include "zb_utils.h"

/* What the caller's outputs hold before a call that is expected to refuse (docs/internals/coding-rules.md §1). */
enum
{
    SENTINEL_OFFSET = 0xa5a5,
    SENTINEL_LEN = 0x5a5a
};

/*
 * The hand-computed vectors, in Figure 3-4's order with Figure 3-5's Frame Control Field and 3.3's
 * lowest-numbered-bit-octet-first rule:
 *
 * a minimal unsecured unicast data NPDU, FCF 0x0008 (type 00, version
 * 2), destination 0x0001, source 0x0000, radius 30, sequence 05, payload
 * aa bb. Eight octets of header, which is nwkcMinHeaderOverhead.
 *
 * a Route Request riding as a MAC data frame, FCF 0x1009 (type 01, version 2,
 * Source IEEE Address at bit 12), destination 0xfffc which is where 3.6.4.5
 * sends a many-to-one request, source 0x0000, radius 30, sequence 07, source
 * IEEE 0x0123456789abcdef, and payload octet zero the command identifier 0x01.
 *
 * a source-routed data frame, FCF 0x0408 (Source Route at bit 10), destination 0x0004, source
 * 0x0005, radius 30, sequence 09, then the subframe 03 02 01 00 02 00 03 00: relay count 3, relay
 * index 2 = count - 1 as 3.3.1.8 initializes it, then 0x0001 closest to the destination listed
 * first and 0x0003 closest to the originator last, each low octet first.
 *
 * a unicast data frame carrying both IEEE addresses, FCF 0x1808 (bits 11 and 12), then the eight
 * octets of each with the least-significant octet first.
 *
 * a broadcast to every device in the PAN at radius 0: the octet written as it was given, because
 * the "zero means twice nwkcMaxDepth" rule of 3.2.1.1.3 is `nwk`'s and not this codec's.
 */
static const uint8_t vectorMinimal[10] =
{
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x05, 0xaa, 0xbb
};

static const uint8_t vectorCommand[17] =
{
    0x09, 0x10, 0xfc, 0xff, 0x00, 0x00, 0x1e, 0x07,
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
    0x01
};

static const uint8_t vectorRouted[17] =
{
    0x08, 0x04, 0x04, 0x00, 0x05, 0x00, 0x1e, 0x09,
    0x03, 0x02, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
    0x55
};

static const uint8_t vectorIeee[26] =
{
    0x08, 0x18, 0x01, 0x00, 0x02, 0x00, 0x1e, 0x2a,
    0x80, 0x01, 0x2c, 0x0b, 0x00, 0x4a, 0x12, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x40, 0x41
};

static const uint8_t vectorBroadcast[8] =
{
    0x08, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
};

/* vectorMinimal with two payload octets more than any test asked for. */
static const uint8_t vectorPadded[12] =
{
    0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x05, 0xaa, 0xbb, 0xcc, 0xdd
};

/* vectorMinimal's header with the security sub-field set (FCF 0x0208) and eighteen octets past the
   header boundary. The eighteen are an auxiliary header, a payload and a MIC in the shape Figure 4-3
   prints, and this suite writes them as octets and nothing more: the codec has no reading for them and
   asserts none. */
static const uint8_t vectorSecured[26] =
{
    0x08, 0x02, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x05,
    0x28, 0x05, 0x00, 0x00, 0x00, 0xef, 0xcd, 0xab,
    0x89, 0x67, 0x45, 0x23, 0x01, 0x00,
    0xaa, 0xbb, 0xcc, 0xdd
};

static const uint8_t payloadMinimal[2] = { 0xaa, 0xbb };
static const uint8_t payloadCommand[1] = { NWK_CMD_ROUTE_REQUEST };
static const uint8_t payloadRouted[1] = { 0x55 };
static const uint8_t payloadIeee[2] = { 0x40, 0x41 };
static const uint8_t payloadLong[NWK_FRAME_NPDU_MAX] = { 0x00 };

/* A data frame this stack would send: version 2 (nwkcProtocolVersion), route discovery suppressed,
   one destination, the coordinator as source (3.6.1.8 gives that device 0x0000) and radius 30, the
   number 3.2.1.1.3 derives for a requested radius of zero. Held here as a plausible octet and not as
   a rule this codec enforces. */
static Nwk_Frame nwkFrame(int frameType)
{
    Nwk_Frame frame;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = frameType;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.discoverRoute = NWK_DISCOVER_SUPPRESS;
    frame.destAddr = 0x0001;
    frame.srcAddr = 0x0000;
    frame.radius = 30;
    frame.sequenceNumber = 5;

    return frame;
}

static Nwk_Frame frameCommand(void)
{
    Nwk_Frame frame = nwkFrame(NWK_FRAME_TYPE_COMMAND);

    frame.destAddr = NWK_ADDR_ROUTERS;
    frame.sequenceNumber = 7;
    frame.srcIeeePresent = 1;
    frame.srcIeee = 0x0123456789abcdef;

    return frame;
}

static Nwk_Frame frameRouted(void)
{
    Nwk_Frame frame = nwkFrame(NWK_FRAME_TYPE_DATA);

    frame.destAddr = 0x0004;
    frame.srcAddr = 0x0005;
    frame.sequenceNumber = 9;
    frame.sourceRoute = 1;
    frame.relayCount = 3;
    frame.relayIndex = 2;
    frame.relayList[0] = 0x0001;
    frame.relayList[1] = 0x0002;
    frame.relayList[2] = 0x0003;

    return frame;
}

static Nwk_Frame frameIeee(void)
{
    Nwk_Frame frame = nwkFrame(NWK_FRAME_TYPE_DATA);

    frame.srcAddr = 0x0002;
    frame.sequenceNumber = 0x2a;
    frame.destIeeePresent = 1;
    frame.destIeee = 0x00124a000b2c0180;
    frame.srcIeeePresent = 1;
    frame.srcIeee = 0x8877665544332211;

    return frame;
}

/* One subfield of a delivered Frame Control Field, rewritten in a caller's copy of a vector. */
static void setFcfField(uint8_t *npdu, uint32_t shift, uint32_t mask, uint32_t value)
{
    uint16_t fcf;

    fcf = (uint16_t)(npdu[0] | (uint16_t)(npdu[1] << 8));
    fcf = (uint16_t)(fcf & (uint16_t)~(mask << shift));
    fcf = (uint16_t)(fcf | (uint16_t)((value & mask) << shift));
    npdu[0] = (uint8_t)(fcf & 0xff);
    npdu[1] = (uint8_t)(fcf >> 8);
}

static void setDestAddr(uint8_t *npdu, uint16_t address)
{
    npdu[2] = (uint8_t)(address & 0xff);
    npdu[3] = (uint8_t)(address >> 8);
}

/* Compose a frame, parse the octets back, and compare field against field. */
static void expectRoundTrip(const char *what, const Nwk_Frame *frame, const uint8_t *payload,
                            uint32_t payloadLen)
{
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    Nwk_Frame back;
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t parsedLen = SENTINEL_LEN;
    uint32_t headerLen;
    ZbStatus status;

    Zb_memset(&back, 0, (uint32_t)sizeof back);

    status = NwkFrame_Compose(frame, payload, payloadLen, npdu, (uint32_t)sizeof npdu, &len);
    Test_ExpectStatus(status, ZB_OK, what);

    if (status != ZB_OK)
        return;

    headerLen = NwkFrame_HeaderLen(frame);
    Test_Expect(len == headerLen + payloadLen,
           "and the header NwkFrame_HeaderLen describes is the header that was written");

    status = NwkFrame_Parse(npdu, len, &back, &offset, &parsedLen);
    Test_ExpectStatus(status, ZB_OK, "and the same octets parse back as the same frame");

    if (status != ZB_OK)
        return;

    Test_Expect(back.frameType == frame->frameType && back.protocolVersion == frame->protocolVersion
           && back.discoverRoute == frame->discoverRoute
           && back.multicastDeprecated == frame->multicastDeprecated
           && back.securityEnabled == frame->securityEnabled
           && back.sourceRoute == frame->sourceRoute
           && back.destIeeePresent == frame->destIeeePresent
           && back.srcIeeePresent == frame->srcIeeePresent
           && back.endDeviceInitiator == frame->endDeviceInitiator,
           "every Frame Control Field subfield read back as it was written");
    Test_Expect(back.destAddr == frame->destAddr && back.srcAddr == frame->srcAddr,
           "both 16-bit addresses, which 3.3.1.2 and 3.3.1.3 make always-present");
    Test_Expect(back.radius == frame->radius && back.sequenceNumber == frame->sequenceNumber,
           "the one-octet radius and the one-octet sequence number");
    Test_Expect(back.destIeee == frame->destIeee && back.srcIeee == frame->srcIeee,
           "both 64-bit IEEE addresses whole through the low-octet-first round trip");
    Test_Expect(back.relayCount == frame->relayCount && back.relayIndex == frame->relayIndex,
           "the source route subframe's own two octets");
    Test_Expect(Zb_memcmp(back.relayList, frame->relayList, (uint32_t)sizeof frame->relayList) == 0,
           "and the whole relay list, in the order 3.3.1.8 prints it");
    Test_Expect(offset == headerLen && parsedLen == payloadLen,
           "with the payload boundary on the first payload octet");
    Test_Expect(payloadLen == 0 || Zb_memcmp(npdu + offset, payload, payloadLen) == 0,
           "and the payload carried through untouched");
}

static void expectComposeRefusal(const char *what, ZbStatus wanted, const Nwk_Frame *frame,
                                 const uint8_t *payload, uint32_t payloadLen)
{
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint8_t before[NWK_FRAME_NPDU_MAX];
    uint32_t len = 0;
    ZbStatus status;

    Zb_memset(npdu, 0xa5, (uint32_t)sizeof npdu);
    Zb_memcpy(before, npdu, (uint32_t)sizeof npdu);

    status = NwkFrame_Compose(frame, payload, payloadLen, npdu, (uint32_t)sizeof npdu, &len);

    Test_ExpectStatus(status, wanted, what);
    Test_Expect(len == 0, "and no length was reported");
    Test_Expect(Zb_memcmp(npdu, before, (uint32_t)sizeof npdu) == 0, "and nothing was written (docs/internals/coding-rules.md §1)");
}

static void expectParseRefusal(const char *what, ZbStatus wanted, const uint8_t *npdu, uint32_t npduLen)
{
    Nwk_Frame back;
    Nwk_Frame before;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t parsedLen = SENTINEL_LEN;
    ZbStatus status;

    Zb_memset(&back, 0xff, (uint32_t)sizeof back);
    before = back;

    status = NwkFrame_Parse(npdu, npduLen, &back, &offset, &parsedLen);

    Test_ExpectStatus(status, wanted, what);
    Test_Expect(Zb_memcmp(&back, &before, (uint32_t)sizeof back) == 0, "and no field of the caller's frame was written");
    Test_Expect(offset == SENTINEL_OFFSET && parsedLen == SENTINEL_LEN, "nor was the payload span");
}

/* Every prefix of a vector shorter than the header the vector describes. */
static void expectTruncations(const char *what, const uint8_t *vector, uint32_t headerLen)
{
    uint32_t length;

    for (length = 0; length < headerLen; length++)
        expectParseRefusal(what, ZB_ERR_BAD_ARGUMENT, vector, length);
}

static void caseConstants(void)
{
    Test_Expect(NWK_MIN_HEADER_OVERHEAD
           == NWK_FRAME_FCF_OCTETS + 2 * NWK_FRAME_ADDR_OCTETS + NWK_FRAME_RADIUS_OCTETS
              + NWK_FRAME_SEQ_OCTETS,
           "nwkcMinHeaderOverhead 0x08 (Table 3-65) is the five fields 3.3.1.2 … 3.3.1.5 make always-present");
    Test_Expect(NWK_MIN_HEADER_OVERHEAD == 8, "eight octets, the value the table prints");
    Test_Expect(NWK_IEEE_ADDR_OCTETS == 8, "each IEEE address field is 8 octets (3.3.1.1.6, 3.3.1.1.7)");
    Test_Expect(NWK_FRAME_RADIUS_OCTETS == 1 && NWK_FRAME_SEQ_OCTETS == 1,
           "radius one octet (3.3.1.4), sequence number one octet (3.3.1.5)");
    Test_Expect(NWK_MAX_SOURCE_ROUTE == 12, "nwkMaxSourceRoute is 0x0c (NIB attribute 0x93, Table 3-66)");
    Test_Expect(NWK_FRAME_NPDU_MAX == 116,
           "an NPDU is the MAC's payload: aMaxPHYPacketSize 127 less nwkcMACFrameOverhead 11 (Table 3-2 with Table 3-65), which is what an NSDU of 108 leaves room for");
    Test_Expect(NWK_PROTOCOL_VERSION == 2, "nwkcProtocolVersion is 0x02 (Table 3-65)");

    Test_Expect(NWK_FRAME_TYPE_DATA == 0 && NWK_FRAME_TYPE_COMMAND == 1
           && NWK_FRAME_TYPE_RESERVED == 2 && NWK_FRAME_TYPE_INTERPAN == 3,
           "the four frame types of Table 3-52, 0b00 through 0b11");
    Test_Expect(NWK_DISCOVER_SUPPRESS == 0 && NWK_DISCOVER_ENABLE == 1,
           "Table 3-53 prints 0x00 suppress and 0x01 enable, with 0x02 and 0x03 reserved");

    Test_Expect(NWK_CMD_ROUTE_REQUEST == 0x01 && NWK_CMD_ROUTE_REPLY == 0x02
           && NWK_CMD_NETWORK_STATUS == 0x03 && NWK_CMD_LEAVE == 0x04
           && NWK_CMD_ROUTE_RECORD == 0x05 && NWK_CMD_REJOIN_REQUEST == 0x06
           && NWK_CMD_REJOIN_RESPONSE == 0x07 && NWK_CMD_LINK_STATUS == 0x08
           && NWK_CMD_NETWORK_REPORT == 0x09 && NWK_CMD_NETWORK_UPDATE == 0x0a
           && NWK_CMD_END_DEVICE_TIMEOUT_REQUEST == 0x0b
           && NWK_CMD_END_DEVICE_TIMEOUT_RESPONSE == 0x0c
           && NWK_CMD_LINK_POWER_DELTA == 0x0d
           && NWK_CMD_NETWORK_COMMISSIONING_REQUEST == 0x0e
           && NWK_CMD_NETWORK_COMMISSIONING_RESPONSE == 0x0f,
           "the fifteen command identifiers of Table 3-54, as printed, 0x01 through 0x0f");

    Test_Expect(NWK_ADDR_ALL_DEVICES == 0xffff && NWK_ADDR_RESERVED == 0xfffe
           && NWK_ADDR_RX_ON_WHEN_IDLE == 0xfffd && NWK_ADDR_ROUTERS == 0xfffc
           && NWK_ADDR_LOW_POWER_ROUTERS == 0xfffb,
           "the destination classes of Table 3-80, which 3.6.6 makes a receiver compare its own device type against");

    Test_Expect(((NWK_FRAME_FCF_TYPE_MASK << NWK_FRAME_FCF_TYPE_SHIFT)
            | (NWK_FRAME_FCF_PROTOCOL_VERSION_MASK << NWK_FRAME_FCF_PROTOCOL_VERSION_SHIFT)
            | (NWK_FRAME_FCF_DISCOVER_ROUTE_MASK << NWK_FRAME_FCF_DISCOVER_ROUTE_SHIFT)
            | (NWK_FRAME_FCF_MULTICAST_MASK << NWK_FRAME_FCF_MULTICAST_SHIFT)
            | (NWK_FRAME_FCF_SECURITY_MASK << NWK_FRAME_FCF_SECURITY_SHIFT)
            | (NWK_FRAME_FCF_SOURCE_ROUTE_MASK << NWK_FRAME_FCF_SOURCE_ROUTE_SHIFT)
            | (NWK_FRAME_FCF_DEST_IEEE_MASK << NWK_FRAME_FCF_DEST_IEEE_SHIFT)
            | (NWK_FRAME_FCF_SRC_IEEE_MASK << NWK_FRAME_FCF_SRC_IEEE_SHIFT)
            | (NWK_FRAME_FCF_END_DEVICE_INITIATOR_MASK << NWK_FRAME_FCF_END_DEVICE_INITIATOR_SHIFT)
            | (NWK_FRAME_FCF_RESERVED_MASK << NWK_FRAME_FCF_RESERVED_SHIFT))
           == 0xffff,
           "Figure 3-5's ten subfields tile all sixteen bits of the Frame Control Field, and no field was invented here");
}

static void caseMinimalUnsecuredUnicast(void)
{
    Nwk_Frame frame = nwkFrame(NWK_FRAME_TYPE_DATA);
    Nwk_Frame back;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;

    Test_Expect(NwkFrame_HeaderLen(&frame) == NWK_MIN_HEADER_OVERHEAD,
           "a unicast NPDU with no IEEE address and no source route has the minimal header, nwkcMinHeaderOverhead octets long");

    Test_ExpectStatus(NwkFrame_Compose(&frame, payloadMinimal, 2, npdu, (uint32_t)sizeof npdu, &len), ZB_OK,
                 "the minimal unsecured unicast NPDU composes");
    Test_Expect(len == 10, "eight octets of header and two of payload");
    Test_Expect(Zb_memcmp(npdu, vectorMinimal, 10) == 0,
           "08 00 01 00 00 00 1e 05 aa bb: FCF 0x0008, then destination 0x0001, source 0x0000, radius 30, sequence 05, in Figure 3-4's order");
    Test_Expect(npdu[0] == 0x08 && npdu[1] == 0x00,
           "the Frame Control Field travels low octet then high, which is 3.3's rule for every field longer than one octet");
    Test_Expect(npdu[2] == 0x01 && npdu[3] == 0x00, "the destination address low octet first");
    Test_Expect(npdu[4] == 0x00 && npdu[5] == 0x00, "and the source address, both always present (3.3.1.2, 3.3.1.3)");
    Test_Expect(npdu[6] == 30, "the radius in its one octet at offset 6");
    Test_Expect(npdu[7] == 5, "and the sequence number at offset 7");

    Test_ExpectStatus(NwkFrame_Parse(npdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.frameType == NWK_FRAME_TYPE_DATA && back.protocolVersion == NWK_PROTOCOL_VERSION,
           "as a data frame of protocol version 2");
    Test_Expect(!back.discoverRoute && !back.multicastDeprecated && !back.securityEnabled
           && !back.sourceRoute && !back.destIeeePresent && !back.srcIeeePresent
           && !back.endDeviceInitiator,
           "with every optional subfield zero, and so nothing optional read");
    Test_Expect(back.destAddr == 0x0001 && back.srcAddr == 0x0000 && back.radius == 30 && back.sequenceNumber == 5,
           "the four always-present fields read back as themselves");
    Test_Expect(back.destIeee == 0 && back.srcIeee == 0 && back.relayCount == 0,
           "and the fields the subfields said were absent stay zero");
    Test_Expect(offset == NWK_MIN_HEADER_OVERHEAD && payloadLen == 2, "with the payload starting at octet 8");
    Test_Expect(Zb_memcmp(npdu + offset, payloadMinimal, 2) == 0, "which is the two octets that were written there");

    expectRoundTrip("the minimal unsecured unicast NPDU round trips", &frame, payloadMinimal, 2);
}

static void caseCommandFrame(void)
{
    Nwk_Frame frame = frameCommand();
    Nwk_Frame back;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;

    Test_Expect(NwkFrame_HeaderLen(&frame) == 16,
           "eight always-present octets plus the eight of the source IEEE address (3.3.1.1.7)");

    Test_ExpectStatus(NwkFrame_Compose(&frame, payloadCommand, 1, npdu, (uint32_t)sizeof npdu, &len), ZB_OK,
                 "a Route Request composes, as the payload of a data frame (3.4.1.1)");
    Test_Expect(len == 17, "sixteen octets of header and the command identifier");
    Test_Expect(Zb_memcmp(npdu, vectorCommand, 17) == 0,
           "09 10 fc ff 00 00 1e 07 ef cd ab 89 67 45 23 01 01, octet for octet");
    Test_Expect(npdu[0] == 0x09 && npdu[1] == 0x10,
           "FCF 0x1009: type 01 in bits 0-1, version 2 in bits 2-5, Source IEEE Address in bit 12 (Figure 3-5)");
    Test_Expect(npdu[2] == 0xfc && npdu[3] == 0xff,
           "destined for 0xfffc: all routers and the coordinator, where 3.6.4.5 sends a many-to-one route request");
    Test_Expect(npdu[8] == 0xef && npdu[15] == 0x01,
           "the source IEEE address 0x0123456789abcdef least-significant octet first, which 3.4.1.2 requires a route request to carry");

    Test_ExpectStatus(NwkFrame_Parse(npdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.frameType == NWK_FRAME_TYPE_COMMAND && back.srcIeeePresent
           && back.srcIeee == 0x0123456789abcdef,
           "as a command frame carrying its source IEEE address");
    Test_Expect(!back.destIeeePresent && back.destIeee == 0,
           "with no destination IEEE address, as 3.3.1.6 requires of a 0xfffc destination");
    Test_Expect(back.destAddr == NWK_ADDR_ROUTERS && back.srcAddr == 0x0000 && back.radius == 30 && back.sequenceNumber == 7,
           "the broadcast destination, the coordinator's own source address, radius and sequence as written");
    Test_Expect(offset == 16 && payloadLen == 1, "and one payload octet at offset 16");
    Test_Expect(npdu[offset] == NWK_CMD_ROUTE_REQUEST,
           "which is the command identifier: 3.3.2.2.2 puts it in the payload, and this codec carried it instead of inventing it");

    expectRoundTrip("the command frame round trips", &frame, payloadCommand, 1);
}

static void caseSourceRouteSubframe(void)
{
    Nwk_Frame frame = frameRouted();
    Nwk_Frame back;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;
    uint32_t index;

    Test_Expect(NwkFrame_HeaderLen(&frame) == 16,
           "eight octets plus 2 + 2 × 3 for a three-relay source route (3.3.1.8, Figure 3-6)");

    Test_ExpectStatus(NwkFrame_Compose(&frame, payloadRouted, 1, npdu, (uint32_t)sizeof npdu, &len), ZB_OK,
                 "a source-routed data frame composes");
    Test_Expect(len == 17, "with its payload");
    Test_Expect(Zb_memcmp(npdu, vectorRouted, 17) == 0,
           "08 04 04 00 05 00 1e 09 03 02 01 00 02 00 03 00 55");
    Test_Expect(npdu[1] == 0x04,
           "FCF bit 10 set: the Source Route sub-field, 1 if and only if the source route subframe is present (3.3.1.1.5)");
    Test_Expect(npdu[8] == 3 && npdu[9] == 2,
           "relay count 3 and relay index 2: the index initialized to 1 less than the relay count by the originator (3.3.1.8)");
    Test_Expect(npdu[10] == 0x01 && npdu[11] == 0x00 && npdu[12] == 0x02 && npdu[13] == 0x00
           && npdu[14] == 0x03 && npdu[15] == 0x00,
           "the relay list 01 00 02 00 03 00, low octet first, the destination's relay first (3.3.1.8, 3.6.4.3.1)");

    Test_ExpectStatus(NwkFrame_Parse(npdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.sourceRoute && back.relayCount == 3 && back.relayIndex == 2,
           "with the subframe's own two octets read");

    for (index = 0; index < 3; index++)
        Test_Expect(back.relayList[index] == frame.relayList[index], "each relay address in the order it was listed");

    Test_Expect(back.relayList[3] == 0, "and nothing past the relay count was read out of the list");
    Test_Expect(offset == 16 && payloadLen == 1, "with the payload after the subframe and not inside it");

    expectRoundTrip("the source-routed frame round trips", &frame, payloadRouted, 1);
}

static void caseIeeeAddressForm(void)
{
    Nwk_Frame frame = frameIeee();
    Nwk_Frame back;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;
    uint32_t index;

    Test_Expect(NwkFrame_HeaderLen(&frame) == 24,
           "eight plus eight plus eight, both IEEE addresses present (3.3.1.6, 3.3.1.7)");

    Test_ExpectStatus(NwkFrame_Compose(&frame, payloadIeee, 2, npdu, (uint32_t)sizeof npdu, &len), ZB_OK,
                 "a unicast carrying both IEEE addresses composes");
    Test_Expect(len == 26, "with the payload");
    Test_Expect(Zb_memcmp(npdu, vectorIeee, 26) == 0,
           "08 18 01 00 02 00 1e 2a 80 01 2c 0b 00 4a 12 00 11 22 33 44 55 66 77 88 40 41");
    Test_Expect(npdu[0] == 0x08 && npdu[1] == 0x18,
           "FCF 0x1808: bit 11 Destination IEEE Address and bit 12 Source IEEE Address (Figure 3-5)");
    Test_Expect(npdu[2] == 0x01 && npdu[3] == 0x00 && npdu[4] == 0x02 && npdu[5] == 0x00,
           "the two 16-bit addresses still come first and are still there (3.3.1.2, 3.3.1.3)");

    for (index = 0; index < 8; index++)
        Test_Expect(npdu[8 + index] == (uint8_t)(frame.destIeee >> (index * 8)),
               "the destination IEEE address at octet 8, least-significant octet first (3.3)");

    for (index = 0; index < 8; index++)
        Test_Expect(npdu[16 + index] == (uint8_t)(frame.srcIeee >> (index * 8)),
               "and the source IEEE address at octet 16, the same way");

    Test_ExpectStatus(NwkFrame_Parse(npdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.destIeee == 0x00124a000b2c0180 && back.srcIeee == 0x8877665544332211,
           "both 64-bit addresses whole");
    Test_Expect(offset == 24 && payloadLen == 2, "with the payload boundary after twenty-four octets of header");

    expectRoundTrip("and the IEEE-address form round trips", &frame, payloadIeee, 2);
}

static void caseRadiusOctet(void)
{
    Nwk_Frame frame = nwkFrame(NWK_FRAME_TYPE_DATA);
    Nwk_Frame back;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t len = 0;
    uint32_t offset = 0;
    uint32_t payloadLen = 0;

    frame.destAddr = NWK_ADDR_ALL_DEVICES;
    frame.radius = 0;
    frame.sequenceNumber = 0;

    Test_ExpectStatus(NwkFrame_Compose(&frame, 0, 0, npdu, (uint32_t)sizeof npdu, &len), ZB_OK,
                 "a radius of zero composes: the field is one plain octet (3.3.1.4)");
    Test_Expect(len == 8 && Zb_memcmp(npdu, vectorBroadcast, 8) == 0,
           "08 00 ff ff 00 00 00 00: eight octets, no payload, destined for every device in the PAN (Table 3-80)");
    Test_Expect(npdu[6] == 0,
           "the zero written as it was given, because a requested radius of zero means twice nwkcMaxDepth (3.2.1.1.3) and that derivation is `nwk`'s rule and not this codec's");
    Test_Expect(npdu[7] == 0,
           "and a sequence number of zero is a value and not an absence: 3.3.1.5 says nothing about what it may be");

    Test_ExpectStatus(NwkFrame_Parse(npdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.radius == 0 && back.sequenceNumber == 0 && payloadLen == 0,
           "at radius zero, sequence zero, and no payload: a frame with no NSDU in it");

    frame.radius = 255;
    Test_ExpectStatus(NwkFrame_Compose(&frame, 0, 0, npdu, (uint32_t)sizeof npdu, &len), ZB_OK,
                 "the whole one-octet range composes, 0x00 to 0xff as Table 3-2 prints the Radius range");
    Test_Expect(npdu[6] == 255, "including the top of it");

    frame.endDeviceInitiator = 1;
    Test_ExpectStatus(NwkFrame_Compose(&frame, 0, 0, npdu, (uint32_t)sizeof npdu, &len), ZB_OK,
                 "the End Device Initiator bit is carried and not judged (3.3.1.1.8)");
    Test_Expect((npdu[1] & (1 << (NWK_FRAME_FCF_END_DEVICE_INITIATOR_SHIFT - 8))) != 0, "at bit 13, in the high octet");

    frame.destAddr = 0x0009;
    frame.destIeeePresent = 1;
    frame.srcIeeePresent = 1;
    frame.sourceRoute = 1;
    frame.relayCount = 2;
    frame.relayIndex = 1;
    frame.relayList[0] = 0x0007;
    frame.relayList[1] = 0x0008;

    Test_ExpectStatus(NwkFrame_Compose(&frame, 0, 0, npdu, (uint32_t)sizeof npdu, &len), ZB_OK,
                 "and a frame carrying every field this codec can write composes");
    Test_Expect(len == 8 + 8 + 8 + 2 + 4, "the longest header there is: 8 + 8 + 8 + 2 + 2 × 2 = 30 octets");
    Test_Expect((npdu[1] & (uint8_t)(NWK_FRAME_FCF_RESERVED_MASK << (NWK_FRAME_FCF_RESERVED_SHIFT - 8))) == 0,
           "with bits 14-15 zero: the only reading they ever have here, because Nwk_Frame has no field for them (Figure 3-5)");

    Test_ExpectStatus(NwkFrame_Parse(npdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.endDeviceInitiator && back.destIeeePresent && back.srcIeeePresent
           && back.sourceRoute && back.relayCount == 2 && back.relayIndex == 1,
           "with every flag reported and none of them judged");
    Test_Expect(NwkFrame_HeaderLen(&back) == 30, "which is the length the flags describe");
}

static void caseRoundTrips(void)
{
    Nwk_Frame frame;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t len = 0;

    frame = nwkFrame(NWK_FRAME_TYPE_DATA);
    expectRoundTrip("the minimal unsecured unicast NPDU round trips", &frame, payloadMinimal, 2);

    frame = frameCommand();
    expectRoundTrip("the command frame round trips", &frame, payloadCommand, 1);

    frame = frameRouted();
    expectRoundTrip("the source-routed frame round trips", &frame, payloadRouted, 1);

    frame = frameIeee();
    expectRoundTrip("the IEEE-address form round trips", &frame, payloadIeee, 2);

    /* A data frame may carry nothing: 3.3.2.1.2 makes the payload "the sequence of octets that the
       next higher layer has requested the NWK layer to transmit", and it may request none. */
    frame = nwkFrame(NWK_FRAME_TYPE_DATA);
    expectRoundTrip("and a data frame with no payload round trips", &frame, 0, 0);

    /* Every destination class Table 3-80 names, with a source IEEE address beside them: 3.3.1.6 bars
       only the destination one. */
    frame = nwkFrame(NWK_FRAME_TYPE_DATA);
    frame.srcIeeePresent = 1;
    frame.srcIeee = 0x0123456789abcdef;

    /* The four classes Table 3-80 names; its two reserved rows are refused below, because 1.4.2's reserved codes are
       never generated. */
    for (frame.destAddr = NWK_ADDR_ALL_DEVICES; frame.destAddr >= NWK_ADDR_LOW_POWER_ROUTERS; frame.destAddr--)
    {
        if (frame.destAddr == NWK_ADDR_RESERVED)
            continue;

        expectRoundTrip("a broadcast destination with a source IEEE address round trips", &frame, payloadMinimal, 2);
    }

    frame.destAddr = NWK_ADDR_RESERVED;
    Test_ExpectStatus(NwkFrame_Compose(&frame, payloadMinimal, 2, npdu, (uint32_t)sizeof npdu, &len),
                      ZB_ERR_BAD_ARGUMENT,
                      "0xfffe, which Table 3-80 prints Reserved, is a code 1.4.2 never generates");

    frame.destAddr = NWK_ADDR_RESERVED_LOW;
    Test_ExpectStatus(NwkFrame_Compose(&frame, payloadMinimal, 2, npdu, (uint32_t)sizeof npdu, &len),
                      ZB_ERR_BAD_ARGUMENT,
                      "and so is the 0xfff8-0xfffa row above the low-power class");
}

/*
 * The relay count a *received* frame may carry, which is a different bound from the one this device writes.
 * 3.3.1.8.1 says only what the sub-field means ("the number of relays contained in the relay list sub-field")
 * and 3.3.1.8 makes the list that many 16-bit addresses, so a frame is bounded by its own octets: thirteen
 * relays, one more than nwkMaxSourceRoute's default for the routes this device builds, is a frame a receiver
 * may legally be handed and therefore one this codec reads.
 */
static void caseReceivedRelayCountIsBoundedByThePayload(void)
{
    Nwk_Frame back;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;
    uint32_t len;
    uint32_t i;

    Test_Expect(NWK_MAX_RELAYS == (NWK_FRAME_NPDU_MAX - NWK_MIN_HEADER_OVERHEAD - NWK_FRAME_ROUTE_CONTROL_OCTETS)
                                    / NWK_FRAME_RELAY_OCTETS,
           "the widest list a frame can carry is what the 127-octet NPDU leaves for it (3.3.1.8.1, 3.3.1.8)");

    npdu[0] = 0x08;                     /* Figure 3-5: frame type data, nwkcProtocolVersion 0x02 */
    npdu[1] = 0x04;                     /* bit 10, the source route sub-field */
    npdu[2] = 0x00;
    npdu[3] = 0x00;                     /* destination */
    npdu[4] = 0x42;
    npdu[5] = 0x00;                     /* source */
    npdu[6] = 30;                       /* radius */
    npdu[7] = 9;                        /* sequence number */
    npdu[8] = 13;                       /* relay count, one above nwkMaxSourceRoute */
    npdu[9] = 12;                       /* relay index: 3.3.1.8.2 starts it at count - 1 */
    len = 10;

    for (i = 0; i < 13; i++)
    {
        npdu[len] = (uint8_t)(0x30 + i);
        npdu[len + 1] = 0x00;
        len = len + 2;
    }

    npdu[len] = 0xaa;
    len = len + 1;

    Test_ExpectStatus(NwkFrame_Parse(npdu, len, &back, &offset, &payloadLen), ZB_OK,
                 "a source-routed frame carrying thirteen relays parses: 3.3.1.8.1 bounds the count by the octets that hold it, and nwkMaxSourceRoute caps what this device builds rather than what it reads");
    Test_Expect(back.relayCount == 13 && back.relayIndex == 12 && back.relayList[0] == 0x0030
           && back.relayList[12] == 0x003c,
           "with every relay read out of the list, low octet first (3.3)");
    Test_Expect(offset == len - 1 && payloadLen == 1 && npdu[offset] == 0xaa,
           "and the payload boundary where the list ends");

    npdu[8] = (uint8_t)NWK_MAX_RELAYS;
    npdu[9] = (uint8_t)(NWK_MAX_RELAYS - 1);
    len = 10;

    for (i = 0; i < NWK_MAX_RELAYS; i++)
    {
        npdu[len] = 0x01;
        npdu[len + 1] = 0x00;
        len = len + 2;
    }

    Test_ExpectStatus(NwkFrame_Parse(npdu, len, &back, &offset, &payloadLen), ZB_OK,
                 "and the widest list the octets can hold parses too, with no payload behind it");
    Test_Expect(back.relayCount == NWK_MAX_RELAYS && back.relayIndex == NWK_MAX_RELAYS - 1,
           "at the count and index it carried");

    npdu[8] = (uint8_t)(NWK_MAX_RELAYS + 1);
    npdu[9] = (uint8_t)NWK_MAX_RELAYS;
    expectParseRefusal("a count the NPDU cannot hold is not a frame: the relay list runs past its octets",
                       ZB_ERR_BAD_ARGUMENT, npdu, len);

    npdu[8] = 13;
    npdu[9] = 13;
    expectParseRefusal("and an index equal to the count is outside the list (3.3.1.8.2)",
                       ZB_ERR_BAD_ARGUMENT, npdu, 37);
}

static void caseCompositionBounds(void)
{
    Nwk_Frame frame = nwkFrame(NWK_FRAME_TYPE_DATA);
    Nwk_Frame back;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint8_t small[6];
    uint32_t len = 0;
    uint32_t offset = 0;
    uint32_t payloadLen = 0;

    /* Eight octets of minimal header leaves 108 payload octets inside the MAC's 116-octet payload, which is
       Table 3-2's NsduLength ceiling and the size Annex D.5 requires the MAC underneath to carry. */
    Test_ExpectStatus(NwkFrame_Compose(&frame, payloadLong, 108, npdu, (uint32_t)sizeof npdu, &len), ZB_OK,
                 "a data frame at 108 octets of payload composes");
    Test_Expect(len == NWK_FRAME_NPDU_MAX,
                "116 octets, the MAC payload ceiling (127 less nwkcMACFrameOverhead 11), which is MAC_FRAME_MPDU_MAX less its footer");

    expectComposeRefusal("one payload octet more could never be a frame on this PHY, whatever the buffer",
                         ZB_ERR_BAD_ARGUMENT, &frame, payloadLong, 109);

    /* The longest header this codec writes, at the ceiling too. */
    frame = nwkFrame(NWK_FRAME_TYPE_DATA);
    frame.destIeeePresent = 1;
    frame.srcIeeePresent = 1;
    frame.sourceRoute = 1;
    frame.relayCount = NWK_MAX_SOURCE_ROUTE;
    frame.relayIndex = NWK_MAX_SOURCE_ROUTE - 1;

    Test_Expect(NwkFrame_HeaderLen(&frame) == 8 + 8 + 8 + 2 + 2 * NWK_MAX_SOURCE_ROUTE,
           "a full nwkMaxSourceRoute relay list beside both IEEE addresses is 50 octets of header (attribute 0x93)");
    Test_ExpectStatus(NwkFrame_Compose(&frame, payloadLong, 66, npdu, (uint32_t)sizeof npdu, &len), ZB_OK,
                 "and it composes with the 66 octets of payload the MAC payload ceiling leaves it");
    Test_Expect(len == NWK_FRAME_NPDU_MAX, "at the ceiling");

    Test_ExpectStatus(NwkFrame_Parse(npdu, len, &back, &offset, &payloadLen), ZB_OK,
                 "and a frame at the ceiling parses back");
    Test_Expect(offset == 50 && payloadLen == 66, "as a 50-octet header and the 66 octets of payload it carried");

    expectComposeRefusal("while the 77 octets this header used to leave room for are now more than the MAC carries",
                         ZB_ERR_BAD_ARGUMENT, &frame, payloadLong, 77);
    Test_Expect(back.relayCount == NWK_MAX_SOURCE_ROUTE && back.relayIndex == NWK_MAX_SOURCE_ROUTE - 1,
           "at the full relay count and the index 3.3.1.8 gives an originator");

    expectComposeRefusal("one octet more of payload does not fit it", ZB_ERR_BAD_ARGUMENT,
                         &frame, payloadLong, 78);

    Zb_memset(small, 0xa5, (uint32_t)sizeof small);
    len = 0;
    frame = nwkFrame(NWK_FRAME_TYPE_DATA);
    Test_ExpectStatus(NwkFrame_Compose(&frame, payloadMinimal, 2, small, (uint32_t)sizeof small, &len),
                 ZB_ERR_NO_SPACE, "a buffer that cannot hold the frame is named as no space");
    Test_Expect(len == 0, "and no length was reported");
    Test_Expect(small[0] == 0xa5 && small[5] == 0xa5, "and none of it was written");

    len = 0;
    Test_ExpectStatus(NwkFrame_Compose(&frame, payloadMinimal, 2, npdu, (uint32_t)sizeof npdu, 0),
                 ZB_ERR_BAD_ARGUMENT, "and a null output length is an argument error");
    Test_ExpectStatus(NwkFrame_Compose(&frame, payloadMinimal, 2, 0, (uint32_t)sizeof npdu, &len),
                 ZB_ERR_BAD_ARGUMENT, "as is a null buffer");
    Test_Expect(len == 0, "with nothing reported as written");

    expectComposeRefusal("a payload length with no payload is an argument error", ZB_ERR_BAD_ARGUMENT,
                         &frame, 0, 3);
}

static void caseComposeRefusals(void)
{
    Nwk_Frame frame;
    uint32_t index;

    frame = nwkFrame(NWK_FRAME_TYPE_RESERVED);
    expectComposeRefusal("frame type 0b10 is printed Reserved by Table 3-52", ZB_ERR_UNSUPPORTED,
                         &frame, payloadMinimal, 2);

    frame = nwkFrame(NWK_FRAME_TYPE_INTERPAN);
    expectComposeRefusal("and 0b11 is the Inter-PAN path this stack has not built",
                         ZB_ERR_UNSUPPORTED, &frame, payloadMinimal, 2);

    frame.frameType = 7;
    expectComposeRefusal("while a frame type outside Table 3-52's four values is not a frame at all",
                         ZB_ERR_BAD_ARGUMENT, &frame, payloadMinimal, 2);

    frame = nwkFrame(NWK_FRAME_TYPE_DATA);
    frame.protocolVersion = 0;
    expectComposeRefusal("protocol version 0 is outside the three values Table 1-5 prints", ZB_ERR_BAD_ARGUMENT,
                         &frame, payloadMinimal, 2);

    frame.protocolVersion = 4;
    expectComposeRefusal("and so is 0x04", ZB_ERR_BAD_ARGUMENT, &frame, payloadMinimal, 2);

    frame.protocolVersion = 1;
    expectComposeRefusal("version 0x01 is processable (Table 1-5) but this stack transmits nwkcProtocolVersion 0x02 only",
                         ZB_ERR_UNSUPPORTED, &frame, payloadMinimal, 2);

    frame.protocolVersion = 3;
    expectComposeRefusal("and 0x03 is Zigbee Green Power, which Table 1-5 hands to the Interpan APS this stack has not built",
                         ZB_ERR_UNSUPPORTED, &frame, payloadMinimal, 2);

    frame = nwkFrame(NWK_FRAME_TYPE_DATA);
    frame.multicastDeprecated = 1;
    expectComposeRefusal("the deprecated multicast sub-field is refused rather than sent (3.6.7)",
                         ZB_ERR_UNSUPPORTED, &frame, payloadMinimal, 2);

    frame = nwkFrame(NWK_FRAME_TYPE_DATA);
    frame.discoverRoute = 2;
    expectComposeRefusal("discover route 0x02 is a reserved value of Table 3-53", ZB_ERR_BAD_ARGUMENT,
                         &frame, payloadMinimal, 2);

    frame.discoverRoute = 3;
    expectComposeRefusal("and so is 0x03", ZB_ERR_BAD_ARGUMENT, &frame, payloadMinimal, 2);

    frame = nwkFrame(NWK_FRAME_TYPE_COMMAND);
    frame.discoverRoute = NWK_DISCOVER_ENABLE;
    expectComposeRefusal("a command frame may not ask for route discovery (3.4)", ZB_ERR_BAD_ARGUMENT,
                         &frame, payloadCommand, 1);

    frame = frameCommand();
    expectComposeRefusal("a command frame with no payload carries no command identifier (3.3.2.2.2)",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    for (index = 0; index < 5; index++)
    {
        frame = nwkFrame(NWK_FRAME_TYPE_DATA);
        frame.destAddr = (uint16_t)(NWK_ADDR_ALL_DEVICES - index);
        frame.destIeeePresent = 1;
        frame.destIeee = 0x0123456789abcdef;
        expectComposeRefusal("a broadcast or multicast destination carries no destination IEEE address (3.3.1.6)",
                             ZB_ERR_BAD_ARGUMENT, &frame, payloadMinimal, 2);
    }

    frame = nwkFrame(NWK_FRAME_TYPE_DATA);
    frame.sourceRoute = 1;
    frame.relayCount = 0;
    expectComposeRefusal("the Source Route sub-field means the subframe is present, and a zero relay count says it is not (3.3.1.1.5)",
                         ZB_ERR_BAD_ARGUMENT, &frame, payloadMinimal, 2);

    frame.sourceRoute = 0;
    frame.relayCount = 3;
    frame.relayIndex = 2;
    frame.relayList[0] = 0x0001;
    expectComposeRefusal("and a relay list with no Source Route sub-field is the same contradiction",
                         ZB_ERR_BAD_ARGUMENT, &frame, payloadMinimal, 2);

    frame.sourceRoute = 1;
    frame.relayCount = 13;
    frame.relayIndex = 12;
    expectComposeRefusal("a route longer than nwkMaxSourceRoute 0x0c is one this device does not build (NIB attribute 0x93)",
                         ZB_ERR_UNSUPPORTED, &frame, payloadMinimal, 2);

    frame.relayCount = 3;
    frame.relayIndex = 3;
    expectComposeRefusal("a relay index equal to the relay count is outside the list (3.3.1.8)",
                         ZB_ERR_BAD_ARGUMENT, &frame, payloadMinimal, 2);

    frame.relayIndex = 9;
    expectComposeRefusal("and so is one past the end of it", ZB_ERR_BAD_ARGUMENT, &frame, payloadMinimal, 2);
}

static void caseParseRefusals(void)
{
    Nwk_Frame sink;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;
    uint32_t index;

    /* Truncation, vector by vector. */
    expectTruncations("an NPDU cut short inside the always-present octets is not a frame (3.3.1.2 … 3.3.1.5)",
                      vectorMinimal, NWK_MIN_HEADER_OVERHEAD);
    expectTruncations("a command frame cut short inside its source IEEE address is not a frame either",
                      vectorCommand, 16);
    expectTruncations("nor a source-routed frame cut short inside its relay list", vectorRouted, 16);
    expectTruncations("nor a frame cut short inside an IEEE address", vectorIeee, 24);

    expectParseRefusal("and a command frame with its header but no payload carries no command identifier (3.3.2.2.2)",
                       ZB_ERR_BAD_ARGUMENT, vectorCommand, 16);
    expectParseRefusal("a zero length is no frame at all", ZB_ERR_BAD_ARGUMENT, vectorMinimal, 0);

    Zb_memcpy(npdu, vectorMinimal, 10);
    expectParseRefusal("no NPDU is longer than the PSDU that carried it (D.12.1.1.2)",
                       ZB_ERR_BAD_ARGUMENT, npdu, NWK_FRAME_NPDU_MAX + 1);

    /* A subfield the table reserves. */
    Zb_memcpy(npdu, vectorMinimal, 10);
    setFcfField(npdu, NWK_FRAME_FCF_PROTOCOL_VERSION_SHIFT, NWK_FRAME_FCF_PROTOCOL_VERSION_MASK, 0);
    expectParseRefusal("protocol version 0 off the wire is outside Table 1-5's three values",
                       ZB_ERR_BAD_ARGUMENT, npdu, 10);

    Zb_memcpy(npdu, vectorMinimal, 10);
    setFcfField(npdu, NWK_FRAME_FCF_PROTOCOL_VERSION_SHIFT, NWK_FRAME_FCF_PROTOCOL_VERSION_MASK, 4);
    expectParseRefusal("and so is 0x04, for which Table 1-5 prints no meaning", ZB_ERR_BAD_ARGUMENT,
                       npdu, 10);

    Zb_memcpy(npdu, vectorMinimal, 10);
    setFcfField(npdu, NWK_FRAME_FCF_PROTOCOL_VERSION_SHIFT, NWK_FRAME_FCF_PROTOCOL_VERSION_MASK, 15);
    expectParseRefusal("the rest of the four-bit field is reserved too", ZB_ERR_BAD_ARGUMENT, npdu, 10);

    Zb_memcpy(npdu, vectorMinimal, 10);
    setFcfField(npdu, NWK_FRAME_FCF_PROTOCOL_VERSION_SHIFT, NWK_FRAME_FCF_PROTOCOL_VERSION_MASK, 3);
    expectParseRefusal("protocol version 0x03 is Green Power, which Table 1-5 passes to the Interpan APS this stack has not built",
                       ZB_ERR_UNSUPPORTED, npdu, 10);

    Zb_memcpy(npdu, vectorMinimal, 10);
    setFcfField(npdu, NWK_FRAME_FCF_TYPE_SHIFT, NWK_FRAME_FCF_TYPE_MASK, NWK_FRAME_TYPE_RESERVED);
    expectParseRefusal("frame type 0b10 is reserved (Table 3-52)", ZB_ERR_UNSUPPORTED, npdu, 10);

    Zb_memcpy(npdu, vectorMinimal, 10);
    setFcfField(npdu, NWK_FRAME_FCF_TYPE_SHIFT, NWK_FRAME_FCF_TYPE_MASK, NWK_FRAME_TYPE_INTERPAN);
    expectParseRefusal("and 0b11 is the inter-PAN frame this stack has no path for",
                       ZB_ERR_UNSUPPORTED, npdu, 10);

    Zb_memcpy(npdu, vectorMinimal, 10);
    setFcfField(npdu, NWK_FRAME_FCF_SECURITY_SHIFT, NWK_FRAME_FCF_SECURITY_MASK, 1);
    Test_ExpectStatus(NwkFrame_Parse(npdu, 10, &sink, &offset, &payloadLen), ZB_OK,
                 "a security-enabled NPDU parses: the bit is written and read here, its auxiliary header is the crossing's (docs/internals/conformance.md §4)");
    Test_Expect(sink.securityEnabled == 1, "and the sub-field is reported as the octet states it");
    Test_Expect(offset == NWK_MIN_HEADER_OVERHEAD && payloadLen == 2,
           "with the payload boundary exactly where an unsecured frame's would be: the bit costs this codec no header length, because it lays out none of what the bit announces");

    for (index = 0; index < 2; index++)
    {
        Zb_memcpy(npdu, vectorMinimal, 10);
        npdu[1] = (uint8_t)(npdu[1] | (1 << (NWK_FRAME_FCF_RESERVED_SHIFT + index - 8)));
        Test_ExpectStatus(NwkFrame_Parse(npdu, 10, &sink, &offset, &payloadLen), ZB_OK,
                     "either of Figure 3-5's two Reserved bits: 1.4.2, a bit nothing is processed on, so the frame is read and not refused");
        Test_Expect(sink.destAddr == 0x0001 && sink.protocolVersion == NWK_PROTOCOL_VERSION
               && offset == NWK_MIN_HEADER_OVERHEAD && payloadLen == 2,
               "and every field the header does describe reads as it would without the bit");

        offset = SENTINEL_OFFSET;
        payloadLen = SENTINEL_LEN;
    }

    Zb_memcpy(npdu, vectorMinimal, 10);
    setFcfField(npdu, NWK_FRAME_FCF_DISCOVER_ROUTE_SHIFT, NWK_FRAME_FCF_DISCOVER_ROUTE_MASK, 2);
    expectParseRefusal("discover route 0x02 is reserved in Table 3-53", ZB_ERR_BAD_ARGUMENT, npdu, 10);

    Zb_memcpy(npdu, vectorMinimal, 10);
    setFcfField(npdu, NWK_FRAME_FCF_DISCOVER_ROUTE_SHIFT, NWK_FRAME_FCF_DISCOVER_ROUTE_MASK, 3);
    expectParseRefusal("and so is 0x03", ZB_ERR_BAD_ARGUMENT, npdu, 10);

    Zb_memcpy(npdu, vectorCommand, 17);
    setFcfField(npdu, NWK_FRAME_FCF_DISCOVER_ROUTE_SHIFT, NWK_FRAME_FCF_DISCOVER_ROUTE_MASK, NWK_DISCOVER_ENABLE);
    expectParseRefusal("and a command frame that asks for route discovery breaks 3.4", ZB_ERR_BAD_ARGUMENT,
                       npdu, 17);

    Zb_memcpy(npdu, vectorIeee, 26);
    setDestAddr(npdu, NWK_ADDR_ALL_DEVICES);
    expectParseRefusal("a broadcast destination carrying a destination IEEE address breaks 3.3.1.6",
                       ZB_ERR_BAD_ARGUMENT, npdu, 26);

    Zb_memcpy(npdu, vectorIeee, 26);
    setDestAddr(npdu, NWK_ADDR_ROUTERS);
    expectParseRefusal("and so does the all-routers class, which is where 3.6.4.5 sends a many-to-one request",
                       ZB_ERR_BAD_ARGUMENT, npdu, 26);

    /* A subfield that promises octets the frame does not have. */
    Zb_memcpy(npdu, vectorMinimal, 10);
    setFcfField(npdu, NWK_FRAME_FCF_DEST_IEEE_SHIFT, NWK_FRAME_FCF_DEST_IEEE_MASK, 1);
    expectParseRefusal("a Destination IEEE Address sub-field with no octets behind it is a truncated frame (3.3.1.6)",
                       ZB_ERR_BAD_ARGUMENT, npdu, 10);

    Zb_memcpy(npdu, vectorMinimal, 10);
    setFcfField(npdu, NWK_FRAME_FCF_SOURCE_ROUTE_SHIFT, NWK_FRAME_FCF_SOURCE_ROUTE_MASK, 1);
    expectParseRefusal("and a Source Route sub-field with no subframe behind it (3.3.1.1.5)",
                       ZB_ERR_BAD_ARGUMENT, npdu, 10);

    Zb_memcpy(npdu, vectorRouted, 17);
    npdu[8] = 0;
    expectParseRefusal("a relay count of zero with the Source Route sub-field set contradicts it (3.3.1.1.5)",
                       ZB_ERR_BAD_ARGUMENT, npdu, 17);

    Zb_memcpy(npdu, vectorRouted, 17);
    npdu[8] = 13;
    expectParseRefusal("and a relay count over nwkMaxSourceRoute is refused before it bounds anything (attribute 0x93)",
                       ZB_ERR_BAD_ARGUMENT, npdu, 17);

    Zb_memcpy(npdu, vectorRouted, 17);
    npdu[8] = 255;
    expectParseRefusal("including the top of the octet", ZB_ERR_BAD_ARGUMENT, npdu, 17);

    Zb_memcpy(npdu, vectorRouted, 17);
    npdu[9] = 3;
    expectParseRefusal("a relay index equal to the relay count is outside the list (3.3.1.8)",
                       ZB_ERR_BAD_ARGUMENT, npdu, 17);

    Zb_memcpy(npdu, vectorRouted, 17);
    npdu[9] = 255;
    expectParseRefusal("and so is any larger value the octet can hold", ZB_ERR_BAD_ARGUMENT, npdu, 17);

    /* The caller's arguments, before any octet is read. */
    Zb_memset(&sink, 0, (uint32_t)sizeof sink);
    Zb_memcpy(npdu, vectorMinimal, 10);
    Test_ExpectStatus(NwkFrame_Parse(0, 10, &sink, &offset, &payloadLen), ZB_ERR_BAD_ARGUMENT,
                 "no octets is an argument error");
    Test_ExpectStatus(NwkFrame_Parse(npdu, 10, 0, &offset, &payloadLen), ZB_ERR_BAD_ARGUMENT,
                 "as is no frame to report into");
    Test_ExpectStatus(NwkFrame_Parse(npdu, 10, &sink, 0, &payloadLen), ZB_ERR_BAD_ARGUMENT,
                 "nor a missing payload offset");
    Test_ExpectStatus(NwkFrame_Parse(npdu, 10, &sink, &offset, 0), ZB_ERR_BAD_ARGUMENT,
                 "nor a missing payload length");
    Test_Expect(NwkFrame_HeaderLen(0) == 0, "and the length helper answers zero for no frame at all");
}

/* What the codec reports instead of refusing: a form it will not send is still a form it can read. */
static void caseFormsItReports(void)
{
    Nwk_Frame back;
    Nwk_Frame before;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];

    Zb_memcpy(npdu, vectorMinimal, 10);
    setFcfField(npdu, NWK_FRAME_FCF_PROTOCOL_VERSION_SHIFT, NWK_FRAME_FCF_PROTOCOL_VERSION_MASK, 1);
    Test_ExpectStatus(NwkFrame_Parse(npdu, 10, &back, &offset, &payloadLen), ZB_OK,
                 "protocol version 0x01 parses: Table 1-5 makes it processable, a Zigbee 2004 frame on a device that still reads one");
    Test_Expect(back.protocolVersion == 1, "and it is reported as what it is, not rewritten");

    before = nwkFrame(NWK_FRAME_TYPE_DATA);
    before.protocolVersion = 1;
    expectComposeRefusal("while this stack will not transmit it: nwkcProtocolVersion is 0x02 (3.3.1.1.2 with Table 3-65)",
                         ZB_ERR_UNSUPPORTED, &before, payloadMinimal, 2);

    Zb_memcpy(npdu, vectorMinimal, 10);
    setFcfField(npdu, NWK_FRAME_FCF_MULTICAST_SHIFT, NWK_FRAME_FCF_MULTICAST_MASK, 1);
    Test_ExpectStatus(NwkFrame_Parse(npdu, 10, &back, &offset, &payloadLen), ZB_OK,
                 "the deprecated multicast bit parses and is reported, because reading a frame to its payload boundary is the codec's job");
    Test_Expect(back.multicastDeprecated == 1, "named as the deprecated sub-field of Figure 3-5");

    before = nwkFrame(NWK_FRAME_TYPE_DATA);
    before.multicastDeprecated = 1;
    expectComposeRefusal("and refused on the way out, as 3.6.7 deprecated network-level multicast",
                         ZB_ERR_UNSUPPORTED, &before, payloadMinimal, 2);

    /* Octets past the payload boundary are payload: this codec stops at the boundary and does not
       decide what is inside it, which is where a later chunk's auxiliary header and MIC would land. */
    Test_ExpectStatus(NwkFrame_Parse(vectorPadded, 12, &back, &offset, &payloadLen), ZB_OK,
                 "an NPDU carrying more payload than the test asked for parses");
    Test_Expect(offset == 8 && payloadLen == 4,
           "and the whole span past the header is reported as payload: command bodies, an auxiliary header and MIC whenever `nwk` and the security crossing decide what they are");
    Test_Expect(back.sequenceNumber == 5 && back.radius == 30, "with the header fields still themselves");
}

/*
 * Bit 9, the security sub-field, as this codec treats it: one flag among Figure 3-5's ten.
 *
 * The refusal filed here is gone, because the crossing landed and the codec was never the place the auxiliary
 * header belonged: 4.3.2 says the auxiliary frame header "is situated between the NWK header and payload fields",
 * which is a statement about the payload region this codec already reports whole, and 4.3.1.1 step 5 with 4.3.1.2
 * step 4d are the clauses that give those octets and the trailing MIC their meaning, src/zb/security.c. What this
 * module does with the bit is write it on the way out and name it on the way in, and nothing else: the header
 * length its flags describe does not grow by fourteen because this module lays out no fourteen, and the payload
 * boundary stays where the header fields end whether what follows them is an NSDU or a secured frame's auxiliary
 * header, ciphertext and MIC.
 *
 * The octets past the boundary of the last frame below are an auxiliary header, a payload and a MIC in Figure
 * 4-3's shape. The case asserts their span and not their meaning, which is the point of it.
 */
static void caseSecuritySubfieldIsAFlag(void)
{
    Nwk_Frame frame;
    Nwk_Frame back;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;

    frame = nwkFrame(NWK_FRAME_TYPE_DATA);
    frame.securityEnabled = 1;

    Test_Expect(NwkFrame_HeaderLen(&frame) == NWK_MIN_HEADER_OVERHEAD,
           "the security sub-field adds no octet to the header this codec describes: the 14 octets it announces are not fields of a NWK header (3.3.1.2 … 3.3.1.8, Figure 3-4)");

    Test_ExpectStatus(NwkFrame_Compose(&frame, payloadMinimal, 2, npdu, (uint32_t)sizeof npdu, &len), ZB_OK,
                  "and a security-enabled data frame composes: the bit is a flag this stack is allowed to write (3.3.1.1.4)");
    Test_Expect(len == 10, "ten octets: the same eight of header and the same two of payload an unsecured frame of these fields has");
    Test_Expect(npdu[0] == 0x08 && npdu[1] == 0x02,
           "FCF 0x0208 on the wire: bit 9 in the high octet, which is 3.3's lowest-numbered-bit-octet-first rule applied to Figure 3-5's bit numbering");
    Test_Expect(Zb_memcmp(npdu + 2, vectorMinimal + 2, 6) == 0,
           "and every always-present field exactly where vectorMinimal has it: the bit displaces nothing");
    Test_Expect(Zb_memcmp(npdu + NWK_MIN_HEADER_OVERHEAD, payloadMinimal, 2) == 0,
           "with the caller's payload written as payload, because this codec composes a header and no security: the protection is the crossing's act");

    Test_ExpectStatus(NwkFrame_Parse(npdu, len, &back, &offset, &payloadLen), ZB_OK,
                  "the octets the codec wrote parse back");
    Test_Expect(back.securityEnabled == 1, "with the sub-field reported rather than judged");
    Test_Expect(offset == NWK_MIN_HEADER_OVERHEAD && payloadLen == 2, "and the payload boundary unmoved by it");

    expectRoundTrip("a security-enabled data frame round trips", &frame, payloadMinimal, 2);

    /* The bit beside the two optional header forms, which is the shape 4.3.1.1 step 3d authenticates: a source
       route is a header field (3.3.1.8), so the auxiliary header of a source-routed frame sits after the relay
       list, and this codec's payload boundary is the same boundary either way. */
    frame = frameRouted();
    frame.securityEnabled = 1;
    frame.srcIeeePresent = 1;
    frame.srcIeee = 0x0123456789abcdef;

    Test_Expect(NwkFrame_HeaderLen(&frame) == 8 + 8 + 2 + 2 * 3,
           "the always-present octets, the source IEEE address and the source route subframe: 24 octets, every one of them before an auxiliary header can begin (4.3.2)");
    Test_ExpectStatus(NwkFrame_Compose(&frame, payloadRouted, 1, npdu, (uint32_t)sizeof npdu, &len), ZB_OK,
                  "and a secured, source-routed frame composes");
    Test_ExpectStatus(NwkFrame_Parse(npdu, len, &back, &offset, &payloadLen), ZB_OK, "and reads back");
    Test_Expect(back.securityEnabled == 1 && back.sourceRoute == 1 && back.srcIeeePresent == 1,
           "with all three sub-fields named together");
    Test_Expect(offset == 24 && payloadLen == 1,
           "with the payload boundary past the route: the codec stops where the header fields stop, which is where a secured frame's auxiliary header begins");

    /* A whole secured NPDU off the wire: header, 14 octets of auxiliary header, ciphertext, MIC. What this codec
       reports is an 18-octet payload region and no opinion about any of it. */
    Zb_memset(&back, 0, (uint32_t)sizeof back);
    offset = SENTINEL_OFFSET;
    payloadLen = SENTINEL_LEN;

    Test_ExpectStatus(NwkFrame_Parse(vectorSecured, (uint32_t)sizeof vectorSecured, &back, &offset, &payloadLen),
                 ZB_OK, "a secured NPDU of Figure 4-3's shape parses at this codec's own boundary");
    Test_Expect(back.frameType == NWK_FRAME_TYPE_DATA && back.protocolVersion == NWK_PROTOCOL_VERSION,
           "as the data frame its header says it is");
    Test_Expect(back.securityEnabled == 1, "at the security sub-field");
    Test_Expect(back.destAddr == 0x0001 && back.srcAddr == 0x0000 && back.radius == 30 && back.sequenceNumber == 5,
           "with the routing fields read as the four always-present octets they are (3.3.1.2 … 3.3.1.5)");
    Test_Expect(back.destIeeePresent == 0 && back.srcIeeePresent == 0 && back.sourceRoute == 0
           && back.relayCount == 0 && back.endDeviceInitiator == 0,
           "and no field invented out of octets this module does not read");
    Test_Expect(offset == NWK_MIN_HEADER_OVERHEAD && payloadLen == 18,
           "and everything past the header reported as the payload region: auxiliary header, secured payload and MIC, 18 octets");
}

int main(void)
{
    Test_Begin("nwk_frame");

    caseConstants();
    caseMinimalUnsecuredUnicast();
    caseCommandFrame();
    caseSourceRouteSubframe();
    caseIeeeAddressForm();
    caseRadiusOctet();
    caseRoundTrips();
    caseReceivedRelayCountIsBoundedByThePayload();
    caseCompositionBounds();
    caseComposeRefusals();
    caseParseRefusals();
    caseFormsItReports();
    caseSecuritySubfieldIsAFlag();

    return Test_Report();
}
