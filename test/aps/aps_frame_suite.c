/* Suite for band A's Zigbee APS frame: the Frame Control Field of R23.1 Figure 2-4, the column order of
   Figures 2-3/2-7/2-8/2-9, the field-presence matrix those figures and 2.2.5.1.2 … 2.2.5.1.8 fix, the
   extended header sub-frame, the reserved-zero discard of 2.2.5, and the two refusal families that are
   counted differently.

   Provenance, stated because the corpus has nothing to take them from: R23.1 contains no worked
   APS frame; all 649 pages were searched, Annex D.11's three dissected frames included, and they
   are MAC beacons with no NWK or APS layer. Every vector below is therefore computed by hand from
   the column tables and octet counts of Figures 2-3 (p86), 2-7 (p90), 2-8 (p91) and 2-9 (p91)
   with Figure 2-4's bit map, and each was cross-checked before it was written here against an
   independent recomputation of the same bit arithmetic: a throwaway model built from the field
   positions alone, never from this codec. The one printed octet budget on the whole APS path, Table
   4-40's "APS Header for APS Command 2" (p502), is checked against the command form below. This
   is the hand-vector regime the APS codec is held to, the same one the secured NWK vectors keep. */

#include "aps_frame.h"
#include "test_harness.h"
#include "zb_utils.h"

/* What the caller's outputs hold before a call that is expected to refuse (docs/internals/coding-rules.md §1). */
enum
{
    SENTINEL_OFFSET = 0xa5a5,
    SENTINEL_LEN = 0x5a5a
};

/*
 * The nine hand-computed vectors, in Figure 2-3's column order with Figure 2-4's Frame Control Field and
 * 2.2.5's lowest-numbered-bit-octet-first rule for the multi-octet fields:
 *
 * v1 a unicast data frame that owes an acknowledgement, FCF 0x40 (frame type 0b00, delivery mode 0b00, ACK
 * request at bit 6), destination endpoint 0x01, cluster 0x0006 (06 00), profile 0x0104 (04 01), source
 * endpoint 0x03, APS counter 0x11, then the payload aa bb. Eight octets of header.
 *
 * v2 a broadcast data frame to every active endpoint, FCF 0x08 (delivery mode 0b10, ACK request 0 as
 * 2.2.5.1.1.5 requires of a broadcast), destination endpoint 0xff.
 *
 * v3 a group data frame, FCF 0x0c (delivery mode 0b11), group address 0x0002 (02 00) in the place the
 * destination endpoint would hold, and no destination endpoint at all (2.2.5.1.3). Nine octets.
 *
 * v4 the acknowledgement of v1, FCF 0x02 (frame type 0b10, ACK format 0, ACK request 0 per 2.2.8.4.3),
 * destination endpoint 0x03 and source endpoint 0x01 swapped as 2.2.5.2.3.1 states, cluster and profile
 * and APS counter repeated from v1.
 *
 * v5 the acknowledgement of a command frame, ACK format 1, FCF 0x12 (bit 4 set) and the APS counter 0x07
 * repeated from v6, and nothing between them: "the destination endpoint, cluster identifier, profile
 * identifier and source endpoint fields SHALL NOT be included" (2.2.5.2.3.1). Two octets, the shortest
 * header any figure prints.
 *
 * v6 an APS command frame, FCF 0x01 (frame type 0b01), APS counter 0x07, APS command identifier 0x05
 * (APS_CMD_TRANSPORT_KEY, Table 4-31), and three payload octets the codec carries and does not read. Figure
 * 2-8 (p91) prints frame control, APS counter, command identifier and payload and nothing else, and Table
 * 4-40's "APS Header for APS Command 2" counts its first two columns.
 *
 * v7 the first block of a fragmented unicast transmission, FCF 0xc0 (ACK request and extended header present),
 * then v1's addressing, then the extended header: extended frame control 0x01 (fragmentation 0b01) and block
 * number 0x03, which 2.2.5.1.8.2 says is in the first block "the number of blocks in the fragmented
 * transmission", a four-block transmission here.
 *
 * v8 a subsequent block: same FCF, extended frame control 0x02 (fragmentation 0b10) and block number 0x01,
 * which 2.2.5.1.8.2 with 2.2.8.4.5.3 numbers as the second block ("0x01 for the second fragment, 0x02 for the
 * third"). Same APS counter as v7: 2.2.8.4.5.3, "All blocks in a fragmented transmission SHALL have the same
 * APS Counter value."
 *
 * v9 an acknowledgement inside a fragmented transmission, FCF 0x82 (frame type 0b10, ACK format 0, ACK
 * request 0, extended header present, the extended half copied from the transmission it answers per
 * 2.2.5.2.3.1), then the extended header 0x01 0x00 0x01: fragmentation 0b01, block number 0x00 and ACK
 * bitfield 0x01. The block number is deliberately the 0x00 that 2.2.8.4.5.4 prints for an acknowledgement
 * ("the value of the lowest block number in the current receive window, using the value 0 as the value of the
 * first block"), where the data blocks of the same transmission are numbered from 0x01 by 2.2.8.4.5.3. That
 * contrast is printed as such in the standard and is recorded here as a fact about the octet and not a rule
 * this codec judges.
 */
static const uint8_t vectorUnicastData[10] =
{
    0x40, 0x01, 0x06, 0x00, 0x04, 0x01, 0x03, 0x11, 0xaa, 0xbb
};

static const uint8_t vectorBroadcastData[8] =
{
    0x08, 0xff, 0x06, 0x00, 0x04, 0x01, 0x03, 0x11
};

static const uint8_t vectorGroupData[9] =
{
    0x0c, 0x02, 0x00, 0x06, 0x00, 0x04, 0x01, 0x03, 0x11
};

static const uint8_t vectorAcknowledgeData[8] =
{
    0x02, 0x03, 0x06, 0x00, 0x04, 0x01, 0x01, 0x11
};

static const uint8_t vectorAcknowledgeCommand[2] =
{
    0x12, 0x07
};

static const uint8_t vectorCommand[6] =
{
    0x01, 0x07, 0x05, 0x11, 0x22, 0x33
};

static const uint8_t vectorFirstFragment[10] =
{
    0xc0, 0x01, 0x06, 0x00, 0x04, 0x01, 0x03, 0x11, 0x01, 0x03
};

static const uint8_t vectorNextFragment[10] =
{
    0xc0, 0x01, 0x06, 0x00, 0x04, 0x01, 0x03, 0x11, 0x02, 0x01
};

static const uint8_t vectorFragmentedAck[11] =
{
    0x82, 0x01, 0x06, 0x00, 0x04, 0x01, 0x03, 0x11, 0x01, 0x00, 0x01
};

static const uint8_t payloadMinimal[2] = { 0xaa, 0xbb };
static const uint8_t payloadCommand[4] = { 0x05, 0x11, 0x22, 0x33 }; /* Figure 2-8: the identifier opens the payload */
static const uint8_t payloadLong[APS_FRAME_MAX * 2] = { 0x00 };

/* A frame of a given type with a given delivery mode, and nothing else decided. */
static Aps_Frame apsFrame(uint32_t frameType, uint32_t deliveryMode)
{
    Aps_Frame frame;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = frameType;
    frame.deliveryMode = deliveryMode;
    frame.apsCounter = 0x11;

    return frame;
}

/* Figure 2-7's always-present tail: cluster 0x0006, profile 0x0104, source endpoint 0x03, counter 0x11, the
   set the other eight vectors vary one thing at a time. */
static void apsFrameDoDataTail(Aps_Frame *frame)
{
    frame->clusterId = 0x0006;
    frame->clusterPresent = 1;
    frame->profileId = 0x0104;
    frame->profilePresent = 1;
    frame->srcEndpoint = 0x03;
    frame->srcEndpointPresent = 1;
    frame->apsCounter = 0x11;
}

static Aps_Frame frameUnicastData(void)
{
    Aps_Frame frame = apsFrame(APS_FRAME_TYPE_DATA, APS_DELIVERY_UNICAST);

    frame.ackRequest = 1;
    frame.dstEndpoint = 0x01;
    frame.dstEndpointPresent = 1;
    apsFrameDoDataTail(&frame);

    return frame;
}

static Aps_Frame frameBroadcastData(void)
{
    Aps_Frame frame = apsFrame(APS_FRAME_TYPE_DATA, APS_DELIVERY_BROADCAST);

    frame.dstEndpoint = APS_ENDPOINT_ALL;
    frame.dstEndpointPresent = 1;
    apsFrameDoDataTail(&frame);

    return frame;
}

static Aps_Frame frameGroupData(void)
{
    Aps_Frame frame = apsFrame(APS_FRAME_TYPE_DATA, APS_DELIVERY_GROUP);

    frame.groupAddress = 0x0002;
    frame.groupAddressPresent = 1;
    apsFrameDoDataTail(&frame);

    return frame;
}

/* The acknowledgement of vectorUnicastData: endpoints swapped, cluster, profile and counter repeated. */
static Aps_Frame frameAcknowledgeData(void)
{
    Aps_Frame frame = apsFrame(APS_FRAME_TYPE_ACK, APS_DELIVERY_UNICAST);

    frame.dstEndpoint = 0x03;
    frame.dstEndpointPresent = 1;
    frame.clusterId = 0x0006;
    frame.clusterPresent = 1;
    frame.profileId = 0x0104;
    frame.profilePresent = 1;
    frame.srcEndpoint = 0x01;
    frame.srcEndpointPresent = 1;

    return frame;
}

static Aps_Frame frameAcknowledgeCommand(void)
{
    Aps_Frame frame = apsFrame(APS_FRAME_TYPE_ACK, APS_DELIVERY_UNICAST);

    frame.ackFormat = 1;
    frame.apsCounter = 0x07;

    return frame;
}

static Aps_Frame frameCommand(void)
{
    Aps_Frame frame = apsFrame(APS_FRAME_TYPE_COMMAND, APS_DELIVERY_UNICAST);

    frame.apsCounter = 0x07;

    return frame;
}

/* A data frame carrying the extended header of Figure 2-5, at a given fragmentation value. */
static Aps_Frame frameFragment(uint32_t fragmentation, uint8_t blockNumber)
{
    Aps_Frame frame = frameUnicastData();

    frame.extendedHeaderPresent = 1;
    frame.extFrameControl = (uint8_t)fragmentation;
    frame.fragmentation = fragmentation;
    frame.blockNumber = blockNumber;
    frame.blockNumberPresent = fragmentation == APS_FRAG_FIRST || fragmentation == APS_FRAG_SUBSEQUENT ? 1 : 0;

    return frame;
}

/* An ACK format 0 acknowledgement whose extended header is the one copied from the transmission (v9). */
static Aps_Frame frameFragmentedAck(void)
{
    Aps_Frame frame = frameUnicastData();

    frame.frameType = APS_FRAME_TYPE_ACK;
    frame.ackRequest = 0;
    frame.dstEndpoint = 0x01;
    frame.srcEndpoint = 0x03;
    frame.extendedHeaderPresent = 1;
    frame.extFrameControl = APS_FRAG_FIRST;
    frame.fragmentation = APS_FRAG_FIRST;
    frame.blockNumber = 0x00;
    frame.blockNumberPresent = 1;
    frame.ackBitfield = 0x01;
    frame.ackBitfieldPresent = 1;

    return frame;
}

/* One sub-field of a delivered Frame Control Field, rewritten in a caller's copy of a vector. */
static void setFcfField(uint8_t *apdu, uint32_t shift, uint32_t mask, uint32_t value)
{
    uint8_t fcf;

    fcf = (uint8_t)(apdu[0] & (uint8_t)~(mask << shift));
    fcf = (uint8_t)(fcf | ((value & mask) << shift));
    apdu[0] = fcf;
}

static void setOctet(uint8_t *apdu, uint32_t index, uint8_t value)
{
    apdu[index] = value;
}

/* Compose a frame, parse the octets back, and compare field against field. */
static void expectRoundTrip(const char *what, const Aps_Frame *frame, const uint8_t *payload,
                            uint32_t payloadLen)
{
    uint8_t apdu[APS_FRAME_MAX];
    Aps_Frame back;
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t parsedLen = SENTINEL_LEN;
    uint32_t writeOffset = SENTINEL_OFFSET;
    uint32_t headerLen;
    ZbStatus status;

    Zb_memset(&back, 0, (uint32_t)sizeof back);

    status = ApsFrame_Compose(frame, payload, payloadLen, apdu, (uint32_t)sizeof apdu, &len, &writeOffset);
    Test_ExpectStatus(status, ZB_OK, what);

    if (status != ZB_OK)
        return;

    headerLen = ApsFrame_HeaderLen(frame);
    Test_Expect(len == headerLen + payloadLen,
           "and the header ApsFrame_HeaderLen describes is the header that was written");
    Test_Expect(writeOffset == headerLen, "and Compose reports the payload offset the same length");

    status = ApsFrame_Parse(apdu, len, &back, &offset, &parsedLen);
    Test_ExpectStatus(status, ZB_OK, "and the same octets parse back as the same frame");

    if (status != ZB_OK)
        return;

    Test_Expect(back.frameType == frame->frameType && back.deliveryMode == frame->deliveryMode,
           "the frame type and delivery mode of Table 2-20 and Table 2-21 read back as written");
    Test_Expect(back.ackFormat == frame->ackFormat && back.securityEnabled == frame->securityEnabled
           && back.ackRequest == frame->ackRequest && back.extendedHeaderPresent == frame->extendedHeaderPresent,
           "and the four one-bit sub-fields of Figure 2-4 read back as written, security among them");
    Test_Expect(back.dstEndpointPresent == (frame->dstEndpointPresent ? 1 : 0)
           && back.groupAddressPresent == (frame->groupAddressPresent ? 1 : 0)
           && back.clusterPresent == (frame->clusterPresent ? 1 : 0)
           && back.profilePresent == (frame->profilePresent ? 1 : 0)
           && back.srcEndpointPresent == (frame->srcEndpointPresent ? 1 : 0),
           "and every presence flag the matrix fixed came back the way the clauses fix it");
    Test_Expect(back.dstEndpoint == frame->dstEndpoint && back.groupAddress == frame->groupAddress,
           "the destination endpoint and the group address, the only address an APS header carries");
    Test_Expect(back.clusterId == frame->clusterId && back.profileId == frame->profileId,
           "both 16-bit identifiers whole through the low-octet-first round trip (2.2.5, p86)");
    Test_Expect(back.srcEndpoint == frame->srcEndpoint && back.apsCounter == frame->apsCounter,
           "the source endpoint and the one-octet APS counter");
    Test_Expect(back.extFrameControl == frame->extFrameControl && back.fragmentation == frame->fragmentation,
           "the extended frame control as the octet it is and as its decoded bits 0-1");
    Test_Expect(back.blockNumberPresent == (frame->blockNumberPresent ? 1 : 0)
           && back.ackBitfieldPresent == (frame->ackBitfieldPresent ? 1 : 0),
           "the block number and ACK bitfield presence 2.2.5.1.8.2 and 2.2.5.1.8.3 decide");
    Test_Expect((frame->blockNumberPresent ? back.blockNumber == frame->blockNumber : back.blockNumber == 0)
           && (frame->ackBitfieldPresent ? back.ackBitfield == frame->ackBitfield : back.ackBitfield == 0),
           "and their octets where they are present, and zero where the flag says they are not");
    Test_Expect(offset == headerLen && parsedLen == payloadLen,
           "with the payload boundary on the first payload octet");
    Test_Expect(payloadLen == 0 || Zb_memcmp(apdu + offset, payload, payloadLen) == 0,
           "and the payload carried through untouched");
    Test_Expect(ApsFrame_HeaderLen(&back) == headerLen, "and the parsed frame describes the same header length");
}

static void expectComposeRefusal(const char *what, ZbStatus wanted, const Aps_Frame *frame,
                                 const uint8_t *payload, uint32_t payloadLen)
{
    uint8_t apdu[APS_FRAME_MAX];
    uint8_t before[APS_FRAME_MAX];
    uint32_t len = SENTINEL_LEN;
    uint32_t offset = SENTINEL_OFFSET;
    ZbStatus status;

    Zb_memset(apdu, 0xa5, (uint32_t)sizeof apdu);
    Zb_memcpy(before, apdu, (uint32_t)sizeof apdu);

    status = ApsFrame_Compose(frame, payload, payloadLen, apdu, (uint32_t)sizeof apdu, &len, &offset);

    Test_ExpectStatus(status, wanted, what);
    Test_Expect(len == SENTINEL_LEN && offset == SENTINEL_OFFSET,
           "and neither reported length nor reported payload offset was written");
    Test_Expect(Zb_memcmp(apdu, before, (uint32_t)sizeof apdu) == 0, "and nothing was written (docs/internals/coding-rules.md §1)");
}

static void expectParseRefusal(const char *what, ZbStatus wanted, const uint8_t *apdu, uint32_t apduLen)
{
    Aps_Frame back;
    Aps_Frame before;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t parsedLen = SENTINEL_LEN;
    ZbStatus status;

    Zb_memset(&back, 0xff, (uint32_t)sizeof back);
    before = back;

    status = ApsFrame_Parse(apdu, apduLen, &back, &offset, &parsedLen);

    Test_ExpectStatus(status, wanted, what);
    Test_Expect(Zb_memcmp(&back, &before, (uint32_t)sizeof back) == 0, "and no field of the caller's frame was written");
    Test_Expect(offset == SENTINEL_OFFSET && parsedLen == SENTINEL_LEN, "nor was the payload span");
}

/* Every prefix of a vector shorter than the header the vector describes. */
static void expectTruncations(const char *what, const uint8_t *vector, uint32_t headerLen)
{
    uint32_t length;

    for (length = 0; length < headerLen; length++)
        expectParseRefusal(what, ZB_ERR_BAD_FRAME, vector, length);
}

static void caseConstants(void)
{
    Test_Expect(APS_FRAME_FCF_OCTETS + APS_FRAME_COUNTER_OCTETS == APS_FRAME_HEADER_MIN,
           "the shortest header any figure prints is Figure 2-9's ACK format 1 acknowledgement: frame control and APS counter (2.2.5.2.3.1)");
    Test_Expect(APS_FRAME_FCF_OCTETS == 1, "the frame control field is 8 bits in length (2.2.5.1.1)");
    Test_Expect(APS_FRAME_ENDPOINT_OCTETS == 1, "each endpoint field is 8 bits (2.2.5.1.2, 2.2.5.1.6)");
    Test_Expect(APS_FRAME_GROUP_OCTETS == 2 && APS_FRAME_CLUSTER_OCTETS == 2 && APS_FRAME_PROFILE_OCTETS == 2,
           "group address 16 bits, cluster identifier 16 bits, profile identifier two octets (2.2.5.1.3/.4/.5)");
    Test_Expect(APS_FRAME_COMMAND_ID_OCTETS == 1 && APS_FRAME_EXT_CONTROL_OCTETS == 1
           && APS_FRAME_BLOCK_OCTETS == 1 && APS_FRAME_ACK_BITFIELD_OCTETS == 1,
           "one octet each for the command identifier (Figure 2-8) and for the three fields of Figure 2-5");

    Test_Expect(APS_FRAME_MAX == 108,
           "an APDU never exceeds the NSDU that carries it: aMaxPHYPacketSize 127 minus nwkcMACFrameOverhead 0x0b minus nwkcMinHeaderOverhead 0x08, which is Table 3-2 and Table 3-65 and the 108-octet ceiling");
    Test_Expect(APS_ASDU_MAX == 96 && APS_ASDU_MAX == APS_FRAME_MAX - APS_MIN_HEADER_OVERHEAD,
           "the printed payload ceiling: NsduLength - apscMinHeaderOverhead = 108 - 12 = 96 (Table 2-2 with Table 2-23)");
    Test_Expect(APS_MIN_HEADER_OVERHEAD == 12, "apscMinHeaderOverhead is 12 as Table 2-23 prints it");
    Test_Expect(APS_FRAME_FCF_OCTETS + APS_FRAME_CLUSTER_OCTETS + APS_FRAME_PROFILE_OCTETS
               + APS_FRAME_ENDPOINT_OCTETS + APS_FRAME_COUNTER_OCTETS == 7,
           "Figure 2-7's always-present fields (frame control, cluster, profile, source endpoint, APS counter) sum to 7 octets");
    Test_Expect(7 + APS_FRAME_ENDPOINT_OCTETS == 8 && 8 != APS_MIN_HEADER_OVERHEAD,
           "and the mismatch recorded here stands as printed: the same columns counted with the conditional destination endpoint sum to 8, against apscMinHeaderOverhead 12, which no clause explains");

    Test_Expect(((APS_FRAME_FCF_TYPE_MASK << APS_FRAME_FCF_TYPE_SHIFT)
            | (APS_FRAME_FCF_DELIVERY_MODE_MASK << APS_FRAME_FCF_DELIVERY_MODE_SHIFT)
            | (APS_FRAME_FCF_ACK_FORMAT_MASK << APS_FRAME_FCF_ACK_FORMAT_SHIFT)
            | (APS_FRAME_FCF_SECURITY_MASK << APS_FRAME_FCF_SECURITY_SHIFT)
            | (APS_FRAME_FCF_ACK_REQUEST_MASK << APS_FRAME_FCF_ACK_REQUEST_SHIFT)
            | (APS_FRAME_FCF_EXTENDED_MASK << APS_FRAME_FCF_EXTENDED_SHIFT))
           == 0xff,
           "Figure 2-4's six sub-fields tile all eight bits of the Frame Control Field, and no field was invented here");
    Test_Expect(((APS_FRAME_EXT_FRAGMENTATION_MASK << APS_FRAME_EXT_FRAGMENTATION_SHIFT)
            | (APS_FRAME_EXT_RESERVED_MASK << APS_FRAME_EXT_RESERVED_SHIFT))
           == 0xff,
           "Figure 2-6 tiles the extended frame control as fragmentation at bits 0-1 and Reserved at bits 2-7");

    Test_Expect(APS_FRAME_TYPE_DATA == 0 && APS_FRAME_TYPE_COMMAND == 1
           && APS_FRAME_TYPE_ACK == 2 && APS_FRAME_TYPE_INTERPAN == 3,
           "the four frame types of Table 2-20 (p87), 0b00 Data, 0b01 Command, 0b10 Acknowledgement, 0b11 Inter-PAN APS");
    Test_Expect(APS_DELIVERY_UNICAST == 0 && APS_DELIVERY_RESERVED == 1
           && APS_DELIVERY_BROADCAST == 2 && APS_DELIVERY_GROUP == 3,
           "the four delivery modes of Table 2-21 (p87), 0b00 Normal unicast, 0b01 Reserved, 0b10 Broadcast, 0b11 Group addressing");
    Test_Expect(APS_FRAG_NONE == 0 && APS_FRAG_FIRST == 1 && APS_FRAG_SUBSEQUENT == 2
           && APS_FRAG_RESERVED == 3,
           "the four fragmentation values of Table 2-22 (p89), 0b00 not fragmented, 0b01 first fragment, 0b10 not the first part, 0b11 Reserved");

    Test_Expect(APS_ENDPOINT_ZDO == 0x00 && APS_ENDPOINT_LAST == 0xfe && APS_ENDPOINT_ALL == 0xff,
           "0x00 the ZDO, 0x01-0xfe an application endpoint, 0xff all active endpoints except 0x00 (2.2.5.1.2, 2.2.5.1.6)");

    Test_Expect(APS_CMD_TRANSPORT_KEY == 0x05 && APS_CMD_UPDATE_DEVICE == 0x06
           && APS_CMD_REMOVE_DEVICE == 0x07 && APS_CMD_REQUEST_KEY == 0x08
           && APS_CMD_SWITCH_KEY == 0x09 && APS_CMD_TUNNEL == 0x0e
           && APS_CMD_VERIFY_KEY == 0x0f && APS_CMD_CONFIRM_KEY == 0x10
           && APS_CMD_RELAY_MESSAGE_DOWNSTREAM == 0x11
           && APS_CMD_RELAY_MESSAGE_UPSTREAM == 0x12,
           "the ten command identifiers Table 4-31 (p462) prints, as printed: with Reserved at 0x01-0x04 and 0x0a-0x0d around them, which this module names in a comment and not as constants");
}

/* v1: the unicast data frame that owes an acknowledgement. */
static void caseVectorUnicastData(void)
{
    Aps_Frame frame = frameUnicastData();
    Aps_Frame back;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;
    uint32_t writeOffset = SENTINEL_OFFSET;

    Test_Expect(ApsFrame_HeaderLen(&frame) == 8,
           "the data form of Figure 2-7 has an eight-octet header when the destination endpoint is present and the extended header is not");

    Test_ExpectStatus(ApsFrame_Compose(&frame, payloadMinimal, 2, apdu, (uint32_t)sizeof apdu, &len, &writeOffset),
                 ZB_OK, "v1 composes");
    Test_Expect(len == 10, "eight octets of header and two of payload, the vector the brief prints with its payload apart");
    Test_Expect(Zb_memcmp(apdu, vectorUnicastData, 10) == 0,
           "40 01 06 00 04 01 03 11 aa bb, octet for octet");
    Test_Expect(apdu[0] == 0x40,
           "FCF 0x40: frame type 0b00 in bits 0-1, delivery mode 0b00 in bits 2-3, ACK request at bit 6 (Figure 2-4)");
    Test_Expect(apdu[1] == 0x01, "the destination endpoint at octet 1, where Figure 2-3 draws its column");
    Test_Expect(apdu[2] == 0x06 && apdu[3] == 0x00, "cluster identifier 0x0006 low octet first (2.2.5, p86)");
    Test_Expect(apdu[4] == 0x04 && apdu[5] == 0x01, "profile identifier 0x0104 low octet first");
    Test_Expect(apdu[6] == 0x03, "source endpoint 0x03 at octet 6");
    Test_Expect(apdu[7] == 0x11, "the APS counter last in the header, at octet 7 (2.2.5.1.7)");

    Test_ExpectStatus(ApsFrame_Parse(apdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.frameType == APS_FRAME_TYPE_DATA && back.deliveryMode == APS_DELIVERY_UNICAST,
           "as a unicast data frame");
    Test_Expect(back.ackRequest == 1, "with the ACK request sub-field reported and not judged (2.2.5.1.1.5)");
    Test_Expect(back.dstEndpoint == 0x01 && back.clusterId == 0x0006 && back.profileId == 0x0104
           && back.srcEndpoint == 0x03 && back.apsCounter == 0x11,
           "every addressing field present and read as itself");
    Test_Expect(!back.groupAddressPresent && back.groupAddress == 0, "and no group address, which unicast does not carry");
    Test_Expect(offset == 8 && payloadLen == 2, "with the payload starting at octet 8");
    Test_Expect(Zb_memcmp(apdu + offset, payloadMinimal, 2) == 0, "which is the two octets that were written there");

    expectRoundTrip("v1 round trips", &frame, payloadMinimal, 2);
}

/* v2 and v3: the two forms the delivery mode decides, broadcast to 0xff and group addressing. */
static void caseVectorBroadcastAndGroup(void)
{
    Aps_Frame frame = frameBroadcastData();
    Aps_Frame back;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;
    uint32_t writeOffset = SENTINEL_OFFSET;

    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "v2 composes with no payload");
    Test_Expect(len == 8 && Zb_memcmp(apdu, vectorBroadcastData, 8) == 0,
           "08 ff 06 00 04 01 03 11: FCF 0x08 with delivery mode 0b10 and ACK request 0, as 2.2.5.1.1.5 requires of a broadcast");
    Test_Expect(apdu[1] == APS_ENDPOINT_ALL,
           "the destination endpoint 0xff, which 2.2.5.1.1.2 prints as one of the two values a broadcast may carry");

    Test_ExpectStatus(ApsFrame_Parse(apdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.deliveryMode == APS_DELIVERY_BROADCAST && back.dstEndpointPresent == 1
           && back.dstEndpoint == APS_ENDPOINT_ALL,
           "as a broadcast carrying its destination endpoint, 0xff passed upward unchanged");
    Test_Expect(offset == 8 && payloadLen == 0, "with an empty payload region");

    expectRoundTrip("v2 round trips", &frame, 0, 0);

    frame = frameGroupData();

    Test_Expect(ApsFrame_HeaderLen(&frame) == 9,
           "the group form of Figure 2-7 is nine octets: the two of the group address where the one destination endpoint would be");

    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "v3 composes");
    Test_Expect(len == 9 && Zb_memcmp(apdu, vectorGroupData, 9) == 0,
           "0c 02 00 06 00 04 01 03 11: FCF 0x0c with delivery mode 0b11, then the group address 0x0002 low octet first and no destination endpoint at all");
    Test_Expect(apdu[1] == 0x02 && apdu[2] == 0x00,
           "2.2.5.1.3: the group address is present for 0b11 and 'In this case, the destination endpoint SHALL NOT be present'");

    Test_ExpectStatus(ApsFrame_Parse(apdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.groupAddressPresent == 1 && back.groupAddress == 0x0002, "the group address read");
    Test_Expect(back.dstEndpointPresent == 0 && back.dstEndpoint == 0,
           "and no destination endpoint invented out of the octet that is not there");
    Test_Expect(back.srcEndpointPresent == 1 && back.srcEndpoint == 0x03,
           "with the source endpoint still present: 2.2.8.4.1, group addressed transmissions 'SHALL contain a source endpoint field and group address field, but no destination endpoint field'");
    Test_Expect(offset == 9 && payloadLen == 0, "and the payload region empty after nine octets");

    expectRoundTrip("v3 round trips", &frame, 0, 0);
}

/* v4 and v5: the two acknowledgements Figure 2-9 prints, ACK format 0 and ACK format 1. */
static void caseVectorAcknowledgements(void)
{
    Aps_Frame frame = frameAcknowledgeData();
    Aps_Frame back;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;
    uint32_t writeOffset = SENTINEL_OFFSET;

    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "v4 composes");
    Test_Expect(len == 8 && Zb_memcmp(apdu, vectorAcknowledgeData, 8) == 0,
           "02 03 06 00 04 01 01 11, octet for octet");
    Test_Expect(apdu[0] == 0x02,
           "FCF 0x02: frame type 0b10 in bits 0-1, delivery mode 0b00, ACK format 0 at bit 4, ACK request 0 at bit 6 (2.2.8.4.3)");
    Test_Expect(apdu[1] == 0x03 && apdu[6] == 0x01,
           "the endpoints swapped against v1: 2.2.5.2.3.1, 'the source endpoint field SHALL reflect the value in the destination endpoint field of the frame that is being acknowledged. Similarly, the destination endpoint field SHALL reflect the value in the source endpoint field'");
    Test_Expect(apdu[2] == 0x06 && apdu[3] == 0x00 && apdu[4] == 0x04 && apdu[5] == 0x01 && apdu[7] == 0x11,
           "cluster, profile and APS counter repeated from v1, which the same clause requires");

    Test_ExpectStatus(ApsFrame_Parse(apdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.frameType == APS_FRAME_TYPE_ACK && back.ackFormat == 0 && back.ackRequest == 0,
           "as an ACK format 0 acknowledgement that owes nothing");
    Test_Expect(back.dstEndpointPresent && back.clusterPresent && back.profilePresent && back.srcEndpointPresent,
           "with all four fields 2.2.5.2.3.1 says an ACK format 0 acknowledgement SHALL be present");
    Test_Expect(!back.groupAddressPresent, "and no group address, which Figure 2-9 prints no column for");
    Test_Expect(offset == 8 && payloadLen == 0, "and eight octets of header and nothing after them");

    expectRoundTrip("v4 round trips", &frame, 0, 0);

    frame = frameAcknowledgeCommand();

    Test_Expect(ApsFrame_HeaderLen(&frame) == APS_FRAME_HEADER_MIN,
           "an ACK format 1 acknowledgement has the shortest header there is: two octets");

    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "v5 composes");
    Test_Expect(len == 2 && Zb_memcmp(apdu, vectorAcknowledgeCommand, 2) == 0,
           "12 07: FCF 0x12 with bit 4 set, then the APS counter 0x07 repeated from v6, and nothing between them");
    Test_Expect(apdu[0] == 0x12,
           "FCF 0x12: frame type 0b10, delivery mode 0b00, ACK format 1 at bit 4, 'the frame is an APS command frame acknowledgement' (2.2.5.2.3.1)");

    Test_ExpectStatus(ApsFrame_Parse(apdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.ackFormat == 1, "the ACK format sub-field read");
    Test_Expect(!back.dstEndpointPresent && !back.clusterPresent && !back.profilePresent && !back.srcEndpointPresent,
           "and none of the four fields present, which is the split 2.2.5.1.1.3 exists to draw");
    Test_Expect(back.apsCounter == 0x07, "with only the APS counter after the Frame Control Field");
    Test_Expect(offset == 2 && payloadLen == 0, "two octets of header, and the frame ends there");

    expectRoundTrip("v5 round trips", &frame, 0, 0);
}

/* v6: the APS command frame of Figure 2-8. */
static void caseVectorCommand(void)
{
    Aps_Frame frame = frameCommand();
    Aps_Frame back;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;
    uint32_t writeOffset = SENTINEL_OFFSET;

    Test_Expect(ApsFrame_HeaderLen(&frame) == 2,
           "Figure 2-8's APS header is two octets: frame control and APS counter (2.2.5.2.2.1)");

    Test_ExpectStatus(ApsFrame_Compose(&frame, payloadCommand, 4, apdu, (uint32_t)sizeof apdu, &len, &writeOffset),
                 ZB_OK, "v6 composes");
    Test_Expect(len == 6 && Zb_memcmp(apdu, vectorCommand, 6) == 0,
           "01 07 05 11 22 33: FCF 0x01, counter 0x07, then the payload: command identifier 0x05 and three octets");
    Test_Expect(apdu[0] == 0x01, "FCF 0x01: frame type 0b01, delivery mode 0b00, ACK format 0, ACK request 0, no extended header");
    Test_Expect(apdu[1] == 0x07, "the APS counter before the command identifier, which is the order Figure 2-8 prints");
    Test_Expect(writeOffset == 2 && apdu[writeOffset] == APS_CMD_TRANSPORT_KEY,
           "and the command identifier at octet 2 is the payload's first: Figure 2-8 draws it under 'APS payload', so 4.4.10's auxiliary header goes in front of it");

    Test_ExpectStatus(ApsFrame_Parse(apdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.frameType == APS_FRAME_TYPE_COMMAND && apdu[offset] == APS_CMD_TRANSPORT_KEY,
           "as a command frame whose payload opens with a Table 4-31 identifier");
    Test_Expect(ApsFrame_IsKnownCommand(apdu[offset]), "which the recognition set answers yes for");
    Test_Expect(!back.dstEndpointPresent && !back.groupAddressPresent && !back.clusterPresent
           && !back.profilePresent && !back.srcEndpointPresent && !back.extendedHeaderPresent,
           "with no addressing field and no extended header: 2.2.5.2.2.1, 'the APS command frame SHALL NOT be fragmented and the extended header field SHALL NOT be present'");
    Test_Expect(offset == 2 && payloadLen == 4, "and the identifier with the three octets after it reported as payload");
    Test_Expect(Zb_memcmp(apdu + offset, payloadCommand, 4) == 0,
           "carried untouched: the codec hands the payload to 4.4.11 whole, its identifier included");

    expectRoundTrip("v6 round trips", &frame, payloadCommand, 4);
}

/* v7, v8 and v9: the extended header of Figure 2-5, in the data form and in the acknowledgement form. */
static void caseVectorExtended(void)
{
    Aps_Frame frame = frameFragment(APS_FRAG_FIRST, 0x03);
    Aps_Frame back;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;
    uint32_t writeOffset = SENTINEL_OFFSET;

    Test_Expect(ApsFrame_HeaderLen(&frame) == 10,
           "a fragmented data frame's header is Figure 2-7's eight octets plus the extended frame control and the block number");

    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "v7 composes");
    Test_Expect(len == 10 && Zb_memcmp(apdu, vectorFirstFragment, 10) == 0,
           "c0 01 06 00 04 01 03 11 01 03, octet for octet");
    Test_Expect(apdu[0] == 0xc0,
           "FCF 0xc0: ACK request at bit 6 and extended header present at bit 7, 2.2.5.1.1.6, 'If this sub-field is set to 1, then the extended header SHALL be included in the frame'");
    Test_Expect(apdu[8] == 0x01,
           "extended frame control 0x01: fragmentation 0b01 at bits 0-1, 'Frame is first fragment of a fragmented transmission' (Table 2-22), reserved bits 2-7 zero");
    Test_Expect(apdu[9] == 0x03,
           "block number 0x03, which in the first block 2.2.5.1.8.2 says 'SHALL indicate the number of blocks in the fragmented transmission': four blocks here (2.2.8.4.5.3 calls the first block's total too)");

    Test_ExpectStatus(ApsFrame_Parse(apdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.extendedHeaderPresent == 1 && back.fragmentation == APS_FRAG_FIRST
           && back.extFrameControl == 0x01,
           "the extended frame control reported as the octet it is and as its decoded sub-field");
    Test_Expect(back.blockNumberPresent == 1 && back.blockNumber == 0x03, "the block number read");
    Test_Expect(back.ackBitfieldPresent == 0 && back.ackBitfield == 0,
           "and no ACK bitfield, which 2.2.5.1.8.3 restricts to 'an acknowledgement and the fragmentation sub-field indicates a fragmented transmission'");
    Test_Expect(back.apsCounter == 0x11, "with the same APS counter v1 carried: 2.2.8.4.5.3, 'All blocks in a fragmented transmission SHALL have the same APS Counter value'");
    Test_Expect(offset == 10 && payloadLen == 0, "and ten octets of header");

    expectRoundTrip("v7 round trips", &frame, 0, 0);

    frame = frameFragment(APS_FRAG_SUBSEQUENT, 0x01);

    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "v8 composes");
    Test_Expect(len == 10 && Zb_memcmp(apdu, vectorNextFragment, 10) == 0,
           "c0 01 06 00 04 01 03 11 02 01");
    Test_Expect(apdu[8] == 0x02, "extended frame control 0x02: fragmentation 0b10, 'part of a fragmented transmission but not the first part'");
    Test_Expect(apdu[9] == 0x01,
           "block number 0x01, which 2.2.5.1.8.2 with 2.2.8.4.5.3 number as the second block: '0x01 for the second fragment, 0x02 for the third, etc.'");

    Test_ExpectStatus(ApsFrame_Parse(apdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.fragmentation == APS_FRAG_SUBSEQUENT && back.blockNumber == 0x01
           && back.ackBitfieldPresent == 0,
           "the sub-field, the block number and the absence of the ACK bitfield read as the clauses fix them");
    Test_Expect(back.apsCounter == 0x11, "and the counter unchanged across blocks");

    expectRoundTrip("v8 round trips", &frame, 0, 0);

    frame = frameFragmentedAck();

    Test_Expect(ApsFrame_HeaderLen(&frame) == 11,
           "a fragmented acknowledgement is eleven octets: the eight of an ACK format 0 acknowledgement plus all three fields of Figure 2-5");

    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "v9 composes");
    Test_Expect(len == 11 && Zb_memcmp(apdu, vectorFragmentedAck, 11) == 0,
           "82 01 06 00 04 01 03 11 01 00 01, octet for octet");
    Test_Expect(apdu[0] == 0x82,
           "FCF 0x82: frame type 0b10, ACK format 0, ACK request 0 and extended header present at bit 7, 2.2.5.2.3.1, 'The extended header present sub-field SHALL contain the same value as in the frame to which this frame is an acknowledgement'");
    Test_Expect(apdu[8] == 0x01,
           "the fragmentation sub-field copied from the transmission the same clause requires: 'the fragmentation sub-field of the extended frame control field SHALL contain the same value as in the frame to which this frame is an acknowledgement'");
    Test_Expect(apdu[9] == 0x00,
           "block number 0x00: the 0-based window number 2.2.8.4.5.4 prints for an acknowledgement ('using the value 0 as the value of the first block'), where the data blocks of the same transmission are numbered from 0x01 by 2.2.8.4.5.3, recorded as the printed contrast it is, and judged by nobody here");
    Test_Expect(apdu[10] == 0x01,
           "and the ACK bitfield at the last octet of the header, present because this is an acknowledgement of a fragmented transmission (2.2.5.1.8.3 with 2.2.5.2.3.1)");

    Test_ExpectStatus(ApsFrame_Parse(apdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.frameType == APS_FRAME_TYPE_ACK && back.fragmentation == APS_FRAG_FIRST
           && back.blockNumberPresent == 1 && back.blockNumber == 0x00
           && back.ackBitfieldPresent == 1 && back.ackBitfield == 0x01,
           "with the extended header's three fields read in Figure 2-5's order");
    Test_Expect(back.dstEndpointPresent && back.clusterPresent && back.profilePresent && back.srcEndpointPresent,
           "and the four fields ACK format 0 says are present");
    Test_Expect(offset == 11 && payloadLen == 0, "eleven octets and an empty region after them");

    expectRoundTrip("v9 round trips", &frame, 0, 0);
}

/*
 * Every row the matrix allows, each composed and parsed. The rows are the product of the three frame types
 * with the delivery modes and the extended-header forms they each allow, so a presence rule that only one
 * vector exercised cannot pass by accident.
 */
static void caseMatrixRows(void)
{
    Aps_Frame frame;
    uint32_t fragmentation;
    uint32_t mode;

    /* Data, at each delivery mode the table leaves non-reserved, with and without an extended header at each
       non-reserved fragmentation value. A group frame carries a group address and no destination endpoint; a
       unicast or broadcast frame the other way round (2.2.5.1.2/.3, 2.2.8.4.1).

       The extended rows at broadcast and group delivery are the frame-format matrix and nothing more:
       2.2.8.4.5 forbids fragmentation for a transmission that is not an acknowledged unicast ("Transactions
       not using APS acknowledgements MAY not be fragmented. Multicast and broadcast transmissions are not
       permitted to use fragmentation"), which is a rule about what a device may send and not about what a
       header may say. It is named in aps_frame.h as one this codec does not judge and is `aps`'s to enforce
       (this stack never sets the extended header bit on the way out at all). */
    for (mode = 0; mode <= 3; mode++)
    {
        if (mode == APS_DELIVERY_RESERVED)
            continue;

        frame = apsFrame(APS_FRAME_TYPE_DATA, mode);
        apsFrameDoDataTail(&frame);

        if (mode == APS_DELIVERY_GROUP)
        {
            frame.groupAddress = 0x1234;
            frame.groupAddressPresent = 1;
        }
        else
        {
            frame.dstEndpoint = mode == APS_DELIVERY_BROADCAST ? 0x2a : 0x01;
            frame.dstEndpointPresent = 1;

            if (mode == APS_DELIVERY_UNICAST)
                frame.ackRequest = 1;     /* only the unicast row asks: 2.2.5.1.1.5 forbids the rest */
        }

        expectRoundTrip("a data frame at each delivery mode round trips", &frame, payloadMinimal, 2);

        for (fragmentation = 0; fragmentation <= 2; fragmentation++)
        {
            frame.extendedHeaderPresent = 1;
            frame.extFrameControl = (uint8_t)fragmentation;
            frame.fragmentation = fragmentation;
            frame.blockNumberPresent = fragmentation == APS_FRAG_NONE ? 0 : 1;
            frame.blockNumber = frame.blockNumberPresent ? 0x04 : 0x00;
            expectRoundTrip("and with the extended header at each non-reserved fragmentation value", &frame,
                            payloadMinimal, 2);
        }
    }

    /* Command: Figure 2-8's three columns at the two delivery modes 4.4.11's rule 2 prints for an APS command
       frame, with the extended header never present. */
    frame = apsFrame(APS_FRAME_TYPE_COMMAND, APS_DELIVERY_UNICAST);
    frame.apsCounter = 0x20;
    expectRoundTrip("a unicast command frame round trips", &frame, payloadCommand, 4);

    frame.ackRequest = 1;
    expectRoundTrip("and one that asks for an acknowledgement (4.4.11 rule 4)", &frame, payloadCommand, 4);

    frame.ackRequest = 0;
    frame.deliveryMode = APS_DELIVERY_BROADCAST;
    expectRoundTrip("and a broadcast command frame, which Figure 2-8 prints with no destination endpoint column at all",
                    &frame, payloadCommand, 4);

    /* Acknowledgement, both ACK formats, with and without an extended header at each fragmentation value. */
    frame = apsFrame(APS_FRAME_TYPE_ACK, APS_DELIVERY_UNICAST);
    frame.dstEndpoint = 0x03;
    frame.dstEndpointPresent = 1;
    frame.clusterId = 0x0006;
    frame.clusterPresent = 1;
    frame.profileId = 0x0104;
    frame.profilePresent = 1;
    frame.srcEndpoint = 0x01;
    frame.srcEndpointPresent = 1;
    expectRoundTrip("an ACK format 0 acknowledgement round trips", &frame, 0, 0);

    for (fragmentation = 0; fragmentation <= 2; fragmentation++)
    {
        frame.extendedHeaderPresent = 1;
        frame.extFrameControl = (uint8_t)fragmentation;
        frame.fragmentation = fragmentation;
        frame.blockNumberPresent = fragmentation == APS_FRAG_NONE ? 0 : 1;
        frame.blockNumber = 0x00;     /* the window number 2.2.8.4.5.4 numbers from zero */
        frame.ackBitfieldPresent = fragmentation == APS_FRAG_NONE ? 0 : 1;
        frame.ackBitfield = frame.ackBitfieldPresent ? 0xff : 0x00;
        expectRoundTrip("and at each fragmentation value, with the block number and the ACK bitfield the clauses add",
                        &frame, 0, 0);
    }

    frame = frameAcknowledgeCommand();
    expectRoundTrip("an ACK format 1 acknowledgement round trips", &frame, 0, 0);

    frame.extendedHeaderPresent = 1;
    frame.extFrameControl = APS_FRAG_SUBSEQUENT;
    frame.fragmentation = APS_FRAG_SUBSEQUENT;
    frame.blockNumber = 0x02;
    frame.blockNumberPresent = 1;
    frame.ackBitfield = 0x03;
    frame.ackBitfieldPresent = 1;
    expectRoundTrip("and an ACK format 1 acknowledgement carrying an extended header", &frame, 0, 0);

    /* The endpoint values the clauses print, in the forms they belong to: 0x00 addressing the ZDO for a
       unicast, 0x01-0xfe an application endpoint, 0xff the broadcast endpoint for a broadcast destination,
       and 0x00 as a source, which 2.2.5.1.6 says "indicates that the frame originated from the ZDO". */
    frame = apsFrame(APS_FRAME_TYPE_DATA, APS_DELIVERY_UNICAST);
    apsFrameDoDataTail(&frame);
    frame.dstEndpoint = APS_ENDPOINT_ZDO;
    frame.dstEndpointPresent = 1;
    frame.srcEndpoint = APS_ENDPOINT_ZDO;
    expectRoundTrip("a unicast data frame to and from the ZDO round trips", &frame, payloadMinimal, 2);

    frame.dstEndpoint = APS_ENDPOINT_LAST;
    expectRoundTrip("and one to the last application endpoint", &frame, payloadMinimal, 2);

    frame.dstEndpoint = APS_ENDPOINT_ALL;
    expectRoundTrip("and one to 0xff under unicast delivery, which 2.2.5.1.2 prints as a value of the field and 2.2.8.4.2 fans out",
                    &frame, payloadMinimal, 2);

    frame = frameBroadcastData();

    for (frame.dstEndpoint = 0x01; frame.dstEndpoint <= APS_ENDPOINT_LAST; frame.dstEndpoint++)
    {
        expectRoundTrip("a broadcast frame addresses every endpoint value 0x01-0xfe that 2.2.5.1.1.2 prints",
                        &frame, 0, 0);
    }

    frame.dstEndpoint = APS_ENDPOINT_ALL;
    expectRoundTrip("and the broadcast endpoint 0xff too, the other value the same sentence prints", &frame, 0, 0);
}

/*
 * Zero-length payloads are legal everywhere. An acknowledgement carries nothing after its header in the
 * vectors above; a data frame at ASDULength 0 is inside Table 2-2's printed range "0x00 – 256 * (NsduLength -
 * apscMinHeaderOverhead)"; and a command frame with no payload still names its command, because Figure 2-8
 * carries the identifier in the header and not, as 3.3.2.2.2 makes an NWK command's, in payload octet zero.
 * The contrast with nwk_frame's refusal of an empty command payload is the two figures' difference and not a
 * house preference.
 */
static void caseZeroPayload(void)
{
    Aps_Frame frame;
    Aps_Frame back;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;
    uint32_t writeOffset = SENTINEL_OFFSET;

    frame = frameAcknowledgeData();
    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "an acknowledgement with no payload composes");
    Test_Expect(len == 8, "and is eight octets long, Figure 2-9's seven columns");

    frame = apsFrame(APS_FRAME_TYPE_DATA, APS_DELIVERY_UNICAST);
    apsFrameDoDataTail(&frame);
    frame.dstEndpoint = 0x01;
    frame.dstEndpointPresent = 1;

    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "and a data frame at ASDULength 0 composes");
    Test_Expect(len == 8 && writeOffset == 8, "header only, with the payload offset sitting on the end of the frame");
    Test_ExpectStatus(ApsFrame_Parse(apdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(offset == 8 && payloadLen == 0, "with an empty payload region and no complaint about it");

    frame = frameCommand();
    Test_ExpectStatus(ApsFrame_Compose(&frame, payloadCommand, 1, apdu, (uint32_t)sizeof apdu, &len, &writeOffset),
                 ZB_OK, "and a command frame whose payload is its identifier alone composes");
    Test_Expect(len == 3 && Zb_memcmp(apdu, vectorCommand, 3) == 0,
           "01 07 05: two octets of header and the identifier that opens the payload");
    Test_ExpectStatus(ApsFrame_Parse(apdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(offset == 2 && payloadLen == 1 && apdu[offset] == APS_CMD_TRANSPORT_KEY,
           "with the identifier as the whole payload and nothing after it");
}

/*
 * The refusal matrix as coded. The families: ZB_ERR_UNSUPPORTED for the forms this codec has no layout for
 * at all (Table 2-20's Inter-PAN type, the values Tables 2-21 and 2-22 print Reserved, and Figure 2-6's
 * Reserved half of the extended frame control, which 2.2.5's rule discards rather than corrects);
 * ZB_ERR_BAD_ARGUMENT on the way out and ZB_ERR_BAD_FRAME on the way in for a frame that contradicts a clause
 * this codec does read. See the suite's table in the report of this chunk and the header of aps_frame.h.
 */
static void caseComposeRefusals(void)
{
    Aps_Frame frame;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t len;
    uint32_t offset;

    frame = apsFrame(APS_FRAME_TYPE_INTERPAN, APS_DELIVERY_UNICAST);
    expectComposeRefusal("frame type 0b11 is Annex G's Inter-PAN header and not an APDU this codec reads",
                         ZB_ERR_UNSUPPORTED, &frame, payloadMinimal, 2);

    frame.frameType = 4;
    expectComposeRefusal("while a frame type outside Table 2-20's four values is not a frame at all",
                         ZB_ERR_BAD_ARGUMENT, &frame, payloadMinimal, 2);

    frame = apsFrame(APS_FRAME_TYPE_DATA, APS_DELIVERY_RESERVED);
    expectComposeRefusal("delivery mode 0b01 is printed Reserved by Table 2-21 (2.2.5.1.1.2: 'SHALL be set to one of the non-reserved values')",
                         ZB_ERR_UNSUPPORTED, &frame, payloadMinimal, 2);

    frame.deliveryMode = 4;
    expectComposeRefusal("and a delivery mode outside the table's four values is not a frame", ZB_ERR_BAD_ARGUMENT,
                         &frame, payloadMinimal, 2);

    frame = frameUnicastData();
    frame.ackFormat = 2;
    expectComposeRefusal("the ACK format sub-field is one bit (Figure 2-4), so 2 is not a value it has",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameUnicastData();
    frame.ackFormat = 1;
    expectComposeRefusal("and a data frame may not carry it: 2.2.5.1.1.3 defines the sub-field only for an acknowledgement",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameCommand();
    frame.ackFormat = 1;
    expectComposeRefusal("nor a command frame, for the same reason", ZB_ERR_BAD_ARGUMENT, &frame, payloadCommand, 4);

    /* The data frame's presence rules, 2.2.5.1.2 with 2.2.5.1.3 and 2.2.8.4.1. */
    frame = frameGroupData();
    frame.dstEndpoint = 0x01;
    frame.dstEndpointPresent = 1;
    expectComposeRefusal("a group frame carries a destination endpoint, which 2.2.5.1.3 forbids: 'In this case, the destination endpoint SHALL NOT be present'",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameGroupData();
    frame.groupAddressPresent = 0;
    expectComposeRefusal("and a group frame without the group address is not group addressing either",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameUnicastData();
    frame.dstEndpointPresent = 0;
    expectComposeRefusal("a unicast frame without a destination endpoint contradicts 2.2.8.4.1: unicast and broadcast transmissions 'SHALL include both the source endpoint and destination endpoint fields'",
                         ZB_ERR_BAD_ARGUMENT, &frame, payloadMinimal, 2);

    frame = frameBroadcastData();
    frame.dstEndpointPresent = 0;
    expectComposeRefusal("and so does a broadcast frame", ZB_ERR_BAD_ARGUMENT, &frame, payloadMinimal, 2);

    frame = frameUnicastData();
    frame.clusterPresent = 0;
    expectComposeRefusal("Figure 2-7 makes the cluster identifier always-present in a data frame", ZB_ERR_BAD_ARGUMENT,
                         &frame, payloadMinimal, 2);

    frame = frameUnicastData();
    frame.profilePresent = 0;
    expectComposeRefusal("and the profile identifier (2.2.5.1.5)", ZB_ERR_BAD_ARGUMENT, &frame, payloadMinimal, 2);

    frame = frameUnicastData();
    frame.srcEndpointPresent = 0;
    expectComposeRefusal("and the source endpoint (2.2.5.1.6 with 2.2.8.4.1)", ZB_ERR_BAD_ARGUMENT,
                         &frame, payloadMinimal, 2);

    frame = frameUnicastData();
    frame.groupAddress = 0x0002;
    frame.groupAddressPresent = 1;
    expectComposeRefusal("a unicast frame carries no group address: 2.2.5.1.3 makes it present only for 0b11",
                         ZB_ERR_BAD_ARGUMENT, &frame, payloadMinimal, 2);

    /* The acknowledgement request rules, 2.2.5.1.1.5 with 2.2.8.4.3. */
    frame = frameBroadcastData();
    frame.ackRequest = 1;
    expectComposeRefusal("a broadcast frame may not ask for an acknowledgement: 2.2.5.1.1.5, 'This sub-field SHALL be set to 0 for all frames that are broadcast or multicast'",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameGroupData();
    frame.ackRequest = 1;
    expectComposeRefusal("nor a group frame, which is the multicast the same sentence names", ZB_ERR_BAD_ARGUMENT,
                         &frame, 0, 0);

    frame = frameAcknowledgeData();
    frame.ackRequest = 1;
    expectComposeRefusal("nor an acknowledgement: 2.2.8.4.3, 'An acknowledgement frame SHALL always be sent with the acknowledgement request sub-field set to 0'",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameAcknowledgeData();
    frame.deliveryMode = APS_DELIVERY_BROADCAST;
    expectComposeRefusal("an acknowledgement is not broadcast: band A's reading of Figure 2-9, which prints no group column, with 2.2.8.4.3, which forbids a broadcast frame from owing or being owed one",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameAcknowledgeData();
    frame.deliveryMode = APS_DELIVERY_GROUP;
    expectComposeRefusal("and it is not group addressed either, the same reading", ZB_ERR_BAD_ARGUMENT,
                         &frame, 0, 0);

    frame = frameAcknowledgeData();
    frame.groupAddress = 0x0002;
    frame.groupAddressPresent = 1;
    expectComposeRefusal("Figure 2-9 prints no group address column for an acknowledgement", ZB_ERR_BAD_ARGUMENT,
                         &frame, 0, 0);

    frame = frameAcknowledgeCommand();
    frame.dstEndpoint = 0x03;
    frame.dstEndpointPresent = 1;
    expectComposeRefusal("an ACK format 1 acknowledgement carries no destination endpoint: 2.2.5.2.3.1, 'the destination endpoint, cluster identifier, profile identifier and source endpoint fields SHALL NOT be included'",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameAcknowledgeCommand();
    frame.clusterId = 0x0006;
    frame.clusterPresent = 1;
    expectComposeRefusal("no cluster identifier", ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameAcknowledgeCommand();
    frame.profileId = 0x0104;
    frame.profilePresent = 1;
    expectComposeRefusal("no profile identifier", ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameAcknowledgeCommand();
    frame.srcEndpoint = 0x01;
    frame.srcEndpointPresent = 1;
    expectComposeRefusal("and no source endpoint", ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = apsFrame(APS_FRAME_TYPE_ACK, APS_DELIVERY_UNICAST);
    frame.apsCounter = 0x11;
    frame.dstEndpointPresent = 0;
    expectComposeRefusal("an ACK format 0 acknowledgement missing a field 2.2.5.2.3.1 says is present is refused the same way",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    /* The command frame, Figure 2-8 with 2.2.5.2.2.1. */
    frame = frameCommand();
    frame.extendedHeaderPresent = 1;
    frame.extFrameControl = APS_FRAG_FIRST;
    frame.fragmentation = APS_FRAG_FIRST;
    frame.blockNumberPresent = 1;
    expectComposeRefusal("a command frame with an extended header contradicts 2.2.5.2.2.1 outright", ZB_ERR_BAD_ARGUMENT,
                         &frame, payloadCommand, 4);

    frame = frameCommand();
    frame.deliveryMode = APS_DELIVERY_GROUP;
    expectComposeRefusal("and a command frame in group addressing has no group address column to put the group address 2.2.5.1.3 says group addressing has (Figure 2-8, against 4.4.11's rule 2 which prints unicast and broadcast for the frame type)",
                         ZB_ERR_BAD_ARGUMENT, &frame, payloadCommand, 4);

    frame = frameCommand();
    frame.clusterId = 0x0006;
    frame.clusterPresent = 1;
    expectComposeRefusal("a command frame carries no cluster identifier: 2.2.5.1.4, 'SHALL be present only for data or acknowledgement frames'",
                         ZB_ERR_BAD_ARGUMENT, &frame, payloadCommand, 4);

    frame = frameCommand();
    frame.dstEndpoint = 0x01;
    frame.dstEndpointPresent = 1;
    expectComposeRefusal("no destination endpoint", ZB_ERR_BAD_ARGUMENT, &frame, payloadCommand, 4);

    frame = frameCommand();
    frame.srcEndpoint = 0x03;
    frame.srcEndpointPresent = 1;
    expectComposeRefusal("no source endpoint", ZB_ERR_BAD_ARGUMENT, &frame, payloadCommand, 4);

    frame = frameCommand();
    frame.groupAddress = 0x0002;
    frame.groupAddressPresent = 1;
    expectComposeRefusal("no group address", ZB_ERR_BAD_ARGUMENT, &frame, payloadCommand, 4);

    /* The extended header, 2.2.5.1.8 with Figures 2-5 and 2-6 and Table 2-22. */
    frame = frameUnicastData();
    frame.extendedHeaderPresent = 1;
    frame.extFrameControl = 0x04;
    frame.fragmentation = APS_FRAG_NONE;
    expectComposeRefusal("bits 2-7 of the extended frame control are printed Reserved by Figure 2-6 and 2.2.5 forbids a nonzero reserved field on transmission",
                         ZB_ERR_UNSUPPORTED, &frame, 0, 0);

    frame.extFrameControl = 0xfc;
    expectComposeRefusal("including the whole top half of the octet", ZB_ERR_UNSUPPORTED, &frame, 0, 0);

    frame = frameUnicastData();
    frame.extendedHeaderPresent = 1;
    frame.extFrameControl = APS_FRAG_RESERVED;
    frame.fragmentation = APS_FRAG_RESERVED;
    expectComposeRefusal("fragmentation 0b11 is printed Reserved by Table 2-22", ZB_ERR_UNSUPPORTED,
                         &frame, 0, 0);

    frame.fragmentation = 4;
    expectComposeRefusal("while a fragmentation value outside the table's four is not a sub-field value",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameUnicastData();
    frame.extendedHeaderPresent = 1;
    frame.extFrameControl = 0x00;
    frame.fragmentation = APS_FRAG_FIRST;
    expectComposeRefusal("a raw extended frame control that disagrees with the decoded fragmentation sub-field describes an octet this codec would not write (Figure 2-6 draws one field)",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameUnicastData();
    frame.extendedHeaderPresent = 1;
    frame.extFrameControl = APS_FRAG_NONE;
    frame.fragmentation = APS_FRAG_NONE;
    frame.blockNumber = 0x01;
    frame.blockNumberPresent = 1;
    expectComposeRefusal("an extended header of an unfragmented transmission carries no block number: 2.2.5.1.8.2, 'If the fragmentation sub-field is set to indicate that the transmission is not fragmented then the block number field SHALL NOT be included'",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameFragment(APS_FRAG_FIRST, 0x03);
    frame.blockNumberPresent = 0;
    expectComposeRefusal("and a first fragment that omits the block number omits what 2.2.5.1.8.2 says SHALL be included",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameFragment(APS_FRAG_SUBSEQUENT, 0x01);
    frame.blockNumberPresent = 0;
    expectComposeRefusal("and so does a subsequent one", ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameFragment(APS_FRAG_FIRST, 0x03);
    frame.ackBitfield = 0x01;
    frame.ackBitfieldPresent = 1;
    expectComposeRefusal("a data frame carries no ACK bitfield: 2.2.5.1.8.3, 'This field is only present if the frame type sub-field indicates an acknowledgement'",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameFragmentedAck();
    frame.ackBitfieldPresent = 0;
    expectComposeRefusal("while a fragmented acknowledgement that omits it omits a field 2.2.5.2.3.1 says SHALL be present",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameGroupData();
    frame.extendedHeaderPresent = 0;
    frame.extFrameControl = 0x00;
    frame.fragmentation = APS_FRAG_NONE;
    frame.blockNumber = 0x01;
    frame.blockNumberPresent = 1;
    expectComposeRefusal("a block number with no extended header is an octet inside a sub-frame the Frame Control Field does not include (2.2.5.1.1.6, Figure 2-5)",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    frame = frameUnicastData();
    frame.fragmentation = APS_FRAG_FIRST;
    expectComposeRefusal("and a decoded fragmentation sub-field with no extended header to carry it is the same contradiction",
                         ZB_ERR_BAD_ARGUMENT, &frame, 0, 0);

    /* Field values. */
    frame = frameBroadcastData();
    frame.dstEndpoint = APS_ENDPOINT_ZDO;
    expectRoundTrip("a broadcast addressed to endpoint 0x00 round trips: 2.4.3.1.11.1 broadcasts Device_annce to the ZDO, so 2.2.5.1.2's range sentence is not the whole rule (D-217)",
                    &frame, payloadMinimal, 2);

    frame = frameUnicastData();
    frame.srcEndpoint = APS_ENDPOINT_ALL;
    expectComposeRefusal("a source endpoint of 0xff is outside what 2.2.5.1.6 prints and outside Table 2-2's SrcEndpoint range 0x00-0xfe",
                         ZB_ERR_BAD_ARGUMENT, &frame, payloadMinimal, 2);

    /* The caller's own arguments, before any rule is consulted. */
    frame = frameUnicastData();
    len = SENTINEL_LEN;
    offset = SENTINEL_OFFSET;
    Test_ExpectStatus(ApsFrame_Compose(&frame, payloadMinimal, 2, 0, APS_FRAME_MAX, &len, &offset),
                 ZB_ERR_BAD_ARGUMENT, "no output buffer is an argument error");
    Test_ExpectStatus(ApsFrame_Compose(&frame, payloadMinimal, 2, apdu, APS_FRAME_MAX, 0, &offset),
                 ZB_ERR_BAD_ARGUMENT, "as is no reported length");
    Test_ExpectStatus(ApsFrame_Compose(&frame, payloadMinimal, 2, apdu, APS_FRAME_MAX, &len, 0),
                 ZB_ERR_BAD_ARGUMENT, "nor a reported payload offset");
    Test_ExpectStatus(ApsFrame_Compose(0, payloadMinimal, 2, apdu, APS_FRAME_MAX, &len, &offset),
                 ZB_ERR_BAD_ARGUMENT, "and no frame at all is one too");
    Test_Expect(len == SENTINEL_LEN && offset == SENTINEL_OFFSET, "with nothing reported as written either way");

    expectComposeRefusal("a payload length with no payload behind it is an argument error", ZB_ERR_BAD_ARGUMENT,
                         &frame, 0, 3);

    Test_Expect(ApsFrame_HeaderLen(0) == 0, "and the length helper answers zero for no frame at all");
}

/*
 * The same forms off the wire. A contradiction a clause this codec reads is damage, ZB_ERR_BAD_FRAME,
 * because the octets claim something the clauses forbid and reading further would invent a field. A form the
 * codec does not read at all stays ZB_ERR_UNSUPPORTED, and a discarded reserved field is that family too:
 * 2.2.5 says such a frame gets "no further processing" and "SHALL be discarded", which is a refusal to read
 * and not a correction of what was read.
 *
 * Two compose refusals have no wire equivalent and the suite does not pretend otherwise: a claim about an
 * absent field's value (a data frame's ackBitfieldPresent flag, a command frame's addressing flags) is a claim
 * about the caller's struct, because on the wire those fields are simply not there and their absence is what
 * the Frame Control Field decides.
 */
static void caseParseRefusals(void)
{
    uint8_t apdu[APS_FRAME_MAX];

    /* The family this codec has no layout for. */
    Zb_memcpy(apdu, vectorUnicastData, 10);
    setFcfField(apdu, APS_FRAME_FCF_TYPE_SHIFT, APS_FRAME_FCF_TYPE_MASK, APS_FRAME_TYPE_INTERPAN);
    expectParseRefusal("frame type 0b11 off the wire is Annex G's Inter-PAN header (G.3.3: four fields, at most 7 octets, bit 4 printed Reserved), and it is not mis-parsed as an APDU",
                       ZB_ERR_UNSUPPORTED, apdu, 10);

    Zb_memcpy(apdu, vectorUnicastData, 10);
    setFcfField(apdu, APS_FRAME_FCF_DELIVERY_MODE_SHIFT, APS_FRAME_FCF_DELIVERY_MODE_MASK, APS_DELIVERY_RESERVED);
    expectParseRefusal("delivery mode 0b01 is printed Reserved by Table 2-21", ZB_ERR_UNSUPPORTED, apdu, 10);

    Zb_memcpy(apdu, vectorFirstFragment, 10);
    setOctet(apdu, 8, 0x03);
    expectParseRefusal("and fragmentation 0b11 is printed Reserved by Table 2-22", ZB_ERR_UNSUPPORTED, apdu, 10);

    Zb_memcpy(apdu, vectorUnicastData, 10);
    setOctet(apdu, 7, 0x00);
    setFcfField(apdu, APS_FRAME_FCF_EXTENDED_SHIFT, APS_FRAME_FCF_EXTENDED_MASK, 1);
    setOctet(apdu, 8, 0x04);      /* fragmentation 0b00 with Figure 2-6's Reserved half nonzero */
    expectParseRefusal("a nonzero reserved field is discarded whole, per 2.2.5: 'no further processing SHALL be applied to the frame and the frame SHALL be discarded'",
                       ZB_ERR_UNSUPPORTED, apdu, 10);

    Zb_memcpy(apdu, vectorUnicastData, 10);
    setFcfField(apdu, APS_FRAME_FCF_EXTENDED_SHIFT, APS_FRAME_FCF_EXTENDED_MASK, 1);
    setOctet(apdu, 8, 0xf0);
    expectParseRefusal("including every one of those six bits set at once", ZB_ERR_UNSUPPORTED, apdu, 10);

    /* The contradictions. */
    Zb_memcpy(apdu, vectorCommand, 6);
    setFcfField(apdu, APS_FRAME_FCF_EXTENDED_SHIFT, APS_FRAME_FCF_EXTENDED_MASK, 1);
    expectParseRefusal("a command frame with the extended header present off the wire breaks 2.2.5.2.2.1", ZB_ERR_BAD_FRAME,
                       apdu, 6);

    Zb_memcpy(apdu, vectorCommand, 6);
    setFcfField(apdu, APS_FRAME_FCF_DELIVERY_MODE_SHIFT, APS_FRAME_FCF_DELIVERY_MODE_MASK, APS_DELIVERY_GROUP);
    expectParseRefusal("and a command frame claiming group addressing has no column to carry the group address 2.2.5.1.3 says it has",
                       ZB_ERR_BAD_FRAME, apdu, 6);

    Zb_memcpy(apdu, vectorAcknowledgeData, 8);
    setFcfField(apdu, APS_FRAME_FCF_ACK_REQUEST_SHIFT, APS_FRAME_FCF_ACK_REQUEST_MASK, 1);
    expectParseRefusal("an acknowledgement that asks for an acknowledgement breaks 2.2.8.4.3", ZB_ERR_BAD_FRAME,
                       apdu, 8);

    Zb_memcpy(apdu, vectorAcknowledgeData, 8);
    setFcfField(apdu, APS_FRAME_FCF_DELIVERY_MODE_SHIFT, APS_FRAME_FCF_DELIVERY_MODE_MASK, APS_DELIVERY_BROADCAST);
    expectParseRefusal("a broadcast acknowledgement breaks band A's reading of Figure 2-9 with 2.2.8.4.3, stated as the inference it is",
                       ZB_ERR_BAD_FRAME, apdu, 8);

    Zb_memcpy(apdu, vectorAcknowledgeData, 8);
    setFcfField(apdu, APS_FRAME_FCF_DELIVERY_MODE_SHIFT, APS_FRAME_FCF_DELIVERY_MODE_MASK, APS_DELIVERY_GROUP);
    expectParseRefusal("and a group acknowledgement breaks it the same way", ZB_ERR_BAD_FRAME, apdu, 8);

    Zb_memcpy(apdu, vectorBroadcastData, 8);
    setFcfField(apdu, APS_FRAME_FCF_ACK_REQUEST_SHIFT, APS_FRAME_FCF_ACK_REQUEST_MASK, 1);
    expectParseRefusal("a broadcast data frame with ACK request 1 breaks 2.2.5.1.1.5", ZB_ERR_BAD_FRAME, apdu, 8);

    Zb_memcpy(apdu, vectorGroupData, 9);
    setFcfField(apdu, APS_FRAME_FCF_ACK_REQUEST_SHIFT, APS_FRAME_FCF_ACK_REQUEST_MASK, 1);
    expectParseRefusal("and a group data frame with it breaks the same sentence", ZB_ERR_BAD_FRAME, apdu, 9);

    Zb_memcpy(apdu, vectorUnicastData, 10);
    setFcfField(apdu, APS_FRAME_FCF_ACK_FORMAT_SHIFT, APS_FRAME_FCF_ACK_FORMAT_MASK, 1);
    expectParseRefusal("a data frame with the ACK format sub-field set is damage: 2.2.5.1.1.3 defines the bit for an acknowledgement alone",
                       ZB_ERR_BAD_FRAME, apdu, 10);

    Zb_memcpy(apdu, vectorCommand, 6);
    setFcfField(apdu, APS_FRAME_FCF_ACK_FORMAT_SHIFT, APS_FRAME_FCF_ACK_FORMAT_MASK, 1);
    expectParseRefusal("and so is a command frame with it", ZB_ERR_BAD_FRAME, apdu, 6);

    Zb_memcpy(apdu, vectorUnicastData, 10);
    setOctet(apdu, 6, APS_ENDPOINT_ALL);
    expectParseRefusal("a source endpoint of 0xff is outside 2.2.5.1.6 and outside Table 2-2's SrcEndpoint range",
                       ZB_ERR_BAD_FRAME, apdu, 10);

    /* Truncation, every header form the figures print. */
    expectTruncations("an APDU cut short inside the eight always-present octets of Figure 2-7 is not a frame",
                      vectorUnicastData, 8);
    expectTruncations("nor one cut short inside the nine of the group form", vectorGroupData, 9);
    expectTruncations("nor a command frame cut short inside its two", vectorCommand, 2);
    expectTruncations("nor an acknowledgement cut short inside its eight", vectorAcknowledgeData, 8);
    expectTruncations("nor an ACK format 1 acknowledgement cut short inside its two", vectorAcknowledgeCommand, 2);
    expectTruncations("nor a fragmented data frame cut short inside its ten", vectorFirstFragment, 10);
    expectTruncations("nor a fragmented acknowledgement cut short inside its eleven", vectorFragmentedAck, 11);

    /* A header that ends exactly where a sub-field promised more. */
    Zb_memcpy(apdu, vectorFirstFragment, 10);
    expectParseRefusal("the extended frame control read with no block number behind it is a truncated frame (2.2.5.1.8.2)",
                       ZB_ERR_BAD_FRAME, apdu, 9);

    Zb_memcpy(apdu, vectorFragmentedAck, 11);
    expectParseRefusal("and an extended acknowledgement header with its block number and no ACK bitfield (2.2.5.1.8.3)",
                       ZB_ERR_BAD_FRAME, apdu, 10);

    Zb_memcpy(apdu, vectorBroadcastData, 8);
    expectParseRefusal("a frame that stops after the Frame Control Field alone is truncated: every frame type carries an APS counter",
                       ZB_ERR_BAD_FRAME, apdu, 1);

    expectParseRefusal("and a zero-length delivery is no frame at all", ZB_ERR_BAD_FRAME, vectorUnicastData, 0);

    Zb_memcpy(apdu, vectorUnicastData, 10);
    expectParseRefusal("no APDU is longer than the NSDU that carried it, so 109 octets is not a frame (Table 3-2)",
                       ZB_ERR_BAD_FRAME, apdu, APS_FRAME_MAX + 1);

    /* The caller's arguments, which are not the frame's fault. */
    Test_ExpectStatus(ApsFrame_Parse(0, 10, 0, 0, 0), ZB_ERR_BAD_ARGUMENT,
                 "no octets, no frame to report into, no reported offset and no reported length are argument errors");
}

/* Every legal header form, swept at every shorter length: the sweep asserts nothing is half-parsed. */
static void caseTruncationSweep(void)
{
    Aps_Frame frame;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t len = 0;
    uint32_t writeOffset = SENTINEL_OFFSET;
    uint32_t length;

    /* The group form with an extended header: eleven octets, the longest data header there is. */
    frame = frameGroupData();
    frame.extendedHeaderPresent = 1;
    frame.extFrameControl = APS_FRAG_FIRST;
    frame.fragmentation = APS_FRAG_FIRST;
    frame.blockNumber = 0x02;
    frame.blockNumberPresent = 1;
    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "a group frame with an extended header composes");
    Test_Expect(len == 11 && writeOffset == 11, "eleven octets of header, which is ApsFrame_HeaderLen too");
    Test_Expect(ApsFrame_HeaderLen(&frame) == 11, "and the helper agrees");

    for (length = 0; length < 11; length++)
        expectParseRefusal("and every shorter prefix of it is refused as damage, none of it half-parsed",
                           ZB_ERR_BAD_FRAME, apdu, length);

    /* An ACK format 1 acknowledgement carrying an extended header: five octets. */
    Zb_memset(apdu, 0, (uint32_t)sizeof apdu);
    frame = frameAcknowledgeCommand();
    frame.extendedHeaderPresent = 1;
    frame.extFrameControl = APS_FRAG_SUBSEQUENT;
    frame.fragmentation = APS_FRAG_SUBSEQUENT;
    frame.blockNumber = 0x02;
    frame.blockNumberPresent = 1;
    frame.ackBitfield = 0x03;
    frame.ackBitfieldPresent = 1;
    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "an ACK format 1 acknowledgement with a fragmented extended header composes");
    Test_Expect(len == 5, "92 07 02 02 03: two octets of acknowledgement and three of extended header");
    Test_Expect(apdu[0] == 0x92 && apdu[1] == 0x07 && apdu[2] == 0x02 && apdu[3] == 0x02 && apdu[4] == 0x03,
           "FCF 0x92 (bit 7 added to an ACK format 1 acknowledgement's 0x12) then the octet order Figure 2-9 with Figure 2-5 draws");

    for (length = 0; length < 5; length++)
        expectParseRefusal("and every shorter prefix of that form is refused too", ZB_ERR_BAD_FRAME, apdu, length);

    /* The extended header of an unfragmented transmission: the one-octet sub-frame Figure 2-5 with
       2.2.5.1.8.2 allows, at nine octets of header. */
    Zb_memset(apdu, 0, (uint32_t)sizeof apdu);
    frame = frameUnicastData();
    frame.extendedHeaderPresent = 1;
    frame.extFrameControl = APS_FRAG_NONE;
    frame.fragmentation = APS_FRAG_NONE;
    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "an extended header with fragmentation 0b00 composes as one octet and nothing after it");
    Test_Expect(len == 9 && apdu[8] == 0x00, "nine octets, the last of them zero");

    for (length = 0; length < 9; length++)
        expectParseRefusal("and every shorter prefix of that form is refused too", ZB_ERR_BAD_FRAME, apdu, length);
}

/* The recognition set, exactly Table 4-31's printed identifiers. */
static void caseRecognition(void)
{
    uint32_t id;
    uint32_t known = 0;

    for (id = 0; id <= 0xff; id++)
    {
        if (ApsFrame_IsKnownCommand(id))
            known++;
    }

    Test_Expect(known == 10, "exactly ten identifiers in 0x00-0xff are known, which is how many Table 4-31 prints");

    Test_Expect(!ApsFrame_IsKnownCommand(0x00), "0x00 is not one of them");

    for (id = 0x01; id <= 0x04; id++)
        Test_Expect(!ApsFrame_IsKnownCommand(id), "0x01-0x04 are printed Reserved by Table 4-31");

    for (id = 0x0a; id <= 0x0d; id++)
        Test_Expect(!ApsFrame_IsKnownCommand(id), "and so are 0x0a-0x0d");

    Test_Expect(ApsFrame_IsKnownCommand(APS_CMD_TRANSPORT_KEY) && ApsFrame_IsKnownCommand(APS_CMD_UPDATE_DEVICE)
           && ApsFrame_IsKnownCommand(APS_CMD_REMOVE_DEVICE) && ApsFrame_IsKnownCommand(APS_CMD_REQUEST_KEY)
           && ApsFrame_IsKnownCommand(APS_CMD_SWITCH_KEY) && ApsFrame_IsKnownCommand(APS_CMD_TUNNEL)
           && ApsFrame_IsKnownCommand(APS_CMD_VERIFY_KEY) && ApsFrame_IsKnownCommand(APS_CMD_CONFIRM_KEY)
           && ApsFrame_IsKnownCommand(APS_CMD_RELAY_MESSAGE_DOWNSTREAM)
           && ApsFrame_IsKnownCommand(APS_CMD_RELAY_MESSAGE_UPSTREAM),
           "and the ten the table prints are known, by name");

    Test_Expect(!ApsFrame_IsKnownCommand(0x13), "0x13 is above the table");
    Test_Expect(!ApsFrame_IsKnownCommand(0xff), "so is 0xff");
    Test_Expect(!ApsFrame_IsKnownCommand(0x100), "and so is anything outside an octet, which the service may hand this function but which no command identifier is");
}

/*
 * ApsFrame_HeaderLen against the payload offset Compose reports, for all nine vectors and for the forms the
 * matrix adds. A codec that reported a header length its own writer did not write would be describing octets
 * it never laid out.
 */
static void caseHeaderLenAgreement(void)
{
    Aps_Frame frame;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t len = 0;
    uint32_t writeOffset = SENTINEL_OFFSET;

    frame = frameUnicastData();
    Test_ExpectStatus(ApsFrame_Compose(&frame, payloadMinimal, 2, apdu, (uint32_t)sizeof apdu, &len, &writeOffset),
                 ZB_OK, "v1 composes for the length comparison");
    Test_Expect(ApsFrame_HeaderLen(&frame) == writeOffset && writeOffset == 8, "v1: eight");

    frame = frameBroadcastData();
    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "v2 composes for the length comparison");
    Test_Expect(ApsFrame_HeaderLen(&frame) == writeOffset && writeOffset == 8, "v2: eight");

    frame = frameGroupData();
    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "v3 composes for the length comparison");
    Test_Expect(ApsFrame_HeaderLen(&frame) == writeOffset && writeOffset == 9, "v3: nine, the group address displacing the destination endpoint");

    frame = frameAcknowledgeData();
    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "v4 composes for the length comparison");
    Test_Expect(ApsFrame_HeaderLen(&frame) == writeOffset && writeOffset == 8, "v4: eight");

    frame = frameAcknowledgeCommand();
    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "v5 composes for the length comparison");
    Test_Expect(ApsFrame_HeaderLen(&frame) == writeOffset && writeOffset == 2, "v5: two, APS_FRAME_HEADER_MIN");

    frame = frameCommand();
    Test_ExpectStatus(ApsFrame_Compose(&frame, payloadCommand, 4, apdu, (uint32_t)sizeof apdu, &len, &writeOffset),
                 ZB_OK, "v6 composes for the length comparison");
    Test_Expect(ApsFrame_HeaderLen(&frame) == writeOffset && writeOffset == 2,
           "v6: two, which is what Table 4-40 counts for 'APS Header for APS Command'");

    frame = frameFragment(APS_FRAG_FIRST, 0x03);
    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "v7 composes for the length comparison");
    Test_Expect(ApsFrame_HeaderLen(&frame) == writeOffset && writeOffset == 10, "v7: ten");

    frame = frameFragment(APS_FRAG_SUBSEQUENT, 0x01);
    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "v8 composes for the length comparison");
    Test_Expect(ApsFrame_HeaderLen(&frame) == writeOffset && writeOffset == 10, "v8: ten");

    frame = frameFragmentedAck();
    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, apdu, (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "v9 composes for the length comparison");
    Test_Expect(ApsFrame_HeaderLen(&frame) == writeOffset && writeOffset == 11, "v9: eleven, the longest header the figures print");
}

/*
 * The ceiling. APS_FRAME_MAX is the NSDU ceiling of Table 3-2, so a compose that would pass it answers
 * ZB_ERR_NO_SPACE and writes nothing: the frame could not be handed to the layer below whatever the caller's
 * buffer is. The printed payload ceiling of 96 (Table 2-2 with Table 2-23) is `aps`'s budget on a request and
 * not a bound this codec draws: 96 fits the carrier at every header form there is, 96 + 11 = 107, which is
 * one reason the mismatch recorded here between 12 and 8 does not have to be resolved here.
 */
static void caseCeiling(void)
{
    Aps_Frame frame;
    Aps_Frame back;
    uint8_t apdu[APS_FRAME_MAX];
    uint8_t small[20];
    uint8_t roomy[APS_FRAME_MAX + 32];
    uint32_t len = 0;
    uint32_t writeOffset = SENTINEL_OFFSET;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;
    uint32_t longest;

    frame = frameGroupData();
    frame.extendedHeaderPresent = 1;
    frame.extFrameControl = APS_FRAG_FIRST;
    frame.fragmentation = APS_FRAG_FIRST;
    frame.blockNumber = 0x08;
    frame.blockNumberPresent = 1;
    longest = ApsFrame_HeaderLen(&frame);
    Test_Expect(longest == 11, "the longest header this codec can write is eleven octets");

    Test_ExpectStatus(ApsFrame_Compose(&frame, payloadLong, APS_ASDU_MAX, apdu, (uint32_t)sizeof apdu, &len, &writeOffset),
                 ZB_OK, "the printed payload ceiling of 96 composes at the longest header too");
    Test_Expect(len == 107, "96 plus 11 is 107, inside the carrier");

    len = 0;
    writeOffset = SENTINEL_OFFSET;
    Test_ExpectStatus(ApsFrame_Compose(&frame, payloadLong, APS_FRAME_MAX - longest, apdu,
                                  (uint32_t)sizeof apdu, &len, &writeOffset), ZB_OK,
                 "a payload that fills the carrier exactly composes");
    Test_Expect(len == APS_FRAME_MAX, "108 octets, the ceiling");
    Test_Expect(writeOffset == longest, "with the payload offset on the eleven-octet header");
    Test_ExpectStatus(ApsFrame_Parse(apdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back at the ceiling");
    Test_Expect(offset == longest && payloadLen == APS_FRAME_MAX - longest, "as an 11-octet header and 97 payload octets");

    expectComposeRefusal("one payload octet more could not be carried by the NWK layer whatever the buffer is",
                         ZB_ERR_NO_SPACE, &frame, payloadLong, APS_FRAME_MAX - longest + 1);

    expectComposeRefusal("and a payload length so large that only wrapped arithmetic could accept it is refused without wrapping",
                         ZB_ERR_NO_SPACE, &frame, payloadLong, 0xffffffff);

    /* The same refusal at a buffer that could hold the frame: this is the carrier's ceiling firing and not
       the caller's capacity. */
    Zb_memset(roomy, 0xa5, (uint32_t)sizeof roomy);
    len = SENTINEL_LEN;
    writeOffset = SENTINEL_OFFSET;
    Test_ExpectStatus(ApsFrame_Compose(&frame, payloadLong, 129, roomy, (uint32_t)sizeof roomy, &len, &writeOffset),
                 ZB_ERR_NO_SPACE, "eleven octets of header and 129 of payload is 140 octets, refused at the 108-octet ceiling inside a buffer of 140 (Table 3-2)");
    Test_Expect(len == SENTINEL_LEN && writeOffset == SENTINEL_OFFSET, "and nothing was reported as written");
    Test_Expect(roomy[0] == 0xa5 && roomy[139] == 0xa5, "and none of that buffer was written");

    Zb_memset(small, 0xa5, (uint32_t)sizeof small);
    len = SENTINEL_LEN;
    writeOffset = SENTINEL_OFFSET;
    Test_ExpectStatus(ApsFrame_Compose(&frame, payloadLong, 10, small, (uint32_t)sizeof small, &len, &writeOffset),
                 ZB_ERR_NO_SPACE, "a buffer one octet too small for an 11-octet header and ten payload octets is named as no space");
    Test_Expect(len == SENTINEL_LEN && writeOffset == SENTINEL_OFFSET, "and nothing was reported as written");
    Test_Expect(small[0] == 0xa5 && small[19] == 0xa5, "and none of the buffer was written");
}

/*
 * What the codec reports instead of refusing: the security sub-field, which is a flag and nothing else
 * (2.2.5.1.1.4: "The Security Services Provider (see Chapter 4) manages the security sub-field"), and the
 * payload region of a frame whose payload this module does not read. A received APS frame with the security
 * bit set is counted as a refusal by the service, as `nwk` counted a secured NWK frame before the secured
 * paths landed, and the codec is the place that hands the bit over.
 */
static void caseSecuritySubfieldIsAFlag(void)
{
    Aps_Frame frame;
    Aps_Frame back;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;
    uint32_t writeOffset = SENTINEL_OFFSET;

    frame = frameUnicastData();
    frame.securityEnabled = 1;

    Test_Expect(ApsFrame_HeaderLen(&frame) == 8,
           "the security sub-field adds no octet to the header this codec describes: the auxiliary header it announces is 4.4.10's layout and not one of Figure 2-3's columns");

    Test_ExpectStatus(ApsFrame_Compose(&frame, payloadMinimal, 2, apdu, (uint32_t)sizeof apdu, &len, &writeOffset),
                 ZB_OK, "a security-enabled data frame composes: the bit is a flag this stack may write");
    Test_Expect(apdu[0] == 0x60, "FCF 0x60 on the wire: bit 5 added to v1's 0x40, and every other sub-field where v1 has it");
    Test_Expect(Zb_memcmp(apdu + 1, vectorUnicastData + 1, 7) == 0, "the bit displaces no field");
    Test_Expect(Zb_memcmp(apdu + 8, payloadMinimal, 2) == 0,
           "and the caller's payload is written as payload, because this codec composes a header and no security");
    Test_Expect(len == 10, "ten octets: the same eight of header and the same two of payload an unsecured frame of these fields has");

    Test_ExpectStatus(ApsFrame_Parse(apdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.securityEnabled == 1, "with the sub-field reported and not judged");
    Test_Expect(offset == 8 && payloadLen == 2, "and the payload boundary unmoved by it");

    expectRoundTrip("a security-enabled data frame round trips", &frame, payloadMinimal, 2);

    frame = frameCommand();
    frame.securityEnabled = 1;
    expectRoundTrip("a security-enabled command frame round trips", &frame, payloadCommand, 4);

    frame = frameAcknowledgeData();
    frame.securityEnabled = 1;
    expectRoundTrip("and a security-enabled acknowledgement", &frame, 0, 0);

    /* A secured APDU in Figure 4-7's shape: the APS header, then the "5 or 13" octet auxiliary header, then
       the encrypted payload and the trailing MIC. This suite writes them as octets and asserts their span and
       not their meaning, which is the point of the case: 4.4.10 sits the auxiliary "between the APS header and
       payload fields", and the split is the security crossing's when it lands on this path. */
    Zb_memset(apdu, 0, (uint32_t)sizeof apdu);
    Zb_memcpy(apdu, vectorUnicastData, 8);
    apdu[0] = 0x60;
    apdu[8] = 0x28;           /* a security control octet */
    apdu[9] = 0x05;           /* a frame counter */
    apdu[10] = 0x00;
    apdu[11] = 0x00;
    apdu[12] = 0x00;
    apdu[13] = 0xef;          /* an auxiliary source address, eight octets */
    apdu[14] = 0xcd;
    apdu[15] = 0xab;
    apdu[16] = 0x89;
    apdu[17] = 0x67;
    apdu[18] = 0x45;
    apdu[19] = 0x23;
    apdu[20] = 0x01;
    apdu[21] = 0xaa;
    apdu[22] = 0xbb;
    apdu[23] = 0xcc;
    apdu[24] = 0xdd;

    offset = SENTINEL_OFFSET;
    payloadLen = SENTINEL_LEN;
    Zb_memset(&back, 0, (uint32_t)sizeof back);
    Test_ExpectStatus(ApsFrame_Parse(apdu, 25, &back, &offset, &payloadLen), ZB_OK,
                 "a secured APDU of Figure 4-7's shape parses at this codec's own boundary");
    Test_Expect(back.frameType == APS_FRAME_TYPE_DATA && back.securityEnabled == 1,
           "as the data frame its header says it is, at the security sub-field");
    Test_Expect(back.dstEndpoint == 0x01 && back.clusterId == 0x0006 && back.profileId == 0x0104
           && back.srcEndpoint == 0x03 && back.apsCounter == 0x11,
           "with every APS header field read as the columns say it is");
    Test_Expect(offset == 8 && payloadLen == 17,
           "and everything past the header reported as the payload region: auxiliary header, encrypted payload and MIC together, 17 octets, none of them named here");
}

/* What the codec does not decide: the size of the payload region of a frame whose figure prints no payload
   column at all. Figure 2-9 (p91) is seven columns and stops there, while Figure 2-3 prints a payload column
   on every APS frame and 2.2.5.1.9 says it "contains information specific to individual frame types". No
   clause prints a rule that an acknowledgement's region is empty, so the codec names the region it finds and
   enforces nothing about it; deciding what an acknowledgement carries is `aps`'s. */
static void casePayloadRegionIsNotJudged(void)
{
    Aps_Frame frame;
    Aps_Frame back;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t len = 0;
    uint32_t offset = SENTINEL_OFFSET;
    uint32_t payloadLen = SENTINEL_LEN;
    uint32_t writeOffset = SENTINEL_OFFSET;

    frame = frameAcknowledgeData();
    Test_ExpectStatus(ApsFrame_Compose(&frame, payloadMinimal, 2, apdu, (uint32_t)sizeof apdu, &len, &writeOffset),
                 ZB_OK, "an acknowledgement composed with two payload octets composes");
    Test_Expect(len == 10, "eight of header and two of payload");
    Test_ExpectStatus(ApsFrame_Parse(apdu, len, &back, &offset, &payloadLen), ZB_OK, "and it parses back");
    Test_Expect(back.frameType == APS_FRAME_TYPE_ACK && offset == 8 && payloadLen == 2,
           "with the two octets reported as the payload region: the codec names the region and does not decide whether an acknowledgement may fill it");

    /* Octets past the header of every other form are payload too, a command frame's identifier among them. */
    Zb_memset(apdu, 0, (uint32_t)sizeof apdu);
    Zb_memcpy(apdu, vectorCommand, 3);
    apdu[3] = 0x00;
    apdu[4] = 0x01;
    offset = SENTINEL_OFFSET;
    payloadLen = SENTINEL_LEN;
    Test_ExpectStatus(ApsFrame_Parse(apdu, 5, &back, &offset, &payloadLen), ZB_OK,
                 "a command frame carrying more payload than the test asked for parses");
    Test_Expect(offset == 2 && payloadLen == 3, "and the whole span past the header is reported as payload");
    Test_Expect(back.apsCounter == 0x07 && apdu[offset] == APS_CMD_TRANSPORT_KEY,
           "with the header fields still themselves and the identifier first in the payload");
}

int main(void)
{
    Test_Begin("aps_frame");

    caseConstants();
    caseVectorUnicastData();
    caseVectorBroadcastAndGroup();
    caseVectorAcknowledgements();
    caseVectorCommand();
    caseVectorExtended();
    caseMatrixRows();
    caseZeroPayload();
    caseComposeRefusals();
    caseParseRefusals();
    caseTruncationSweep();
    caseRecognition();
    caseHeaderLenAgreement();
    caseCeiling();
    caseSecuritySubfieldIsAFlag();
    casePayloadRegionIsNotJudged();

    return Test_Report();
}
