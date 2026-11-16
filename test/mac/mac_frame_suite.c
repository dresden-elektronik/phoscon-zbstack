/* Suite for band A's 802.15.4 frame: the layout rules of docs/internals/protocol.md §9.1, the byte order
   every captured frame agrees on, the footer of §9.3, and a byte-for-byte round trip of four real
   frames out of test/fixtures/, composed here, transmitted nowhere, checked against the air. */

#include "mac.h"
#include "mac_frame.h"
#include "test_harness.h"
#include "zb_utils.h"

/*
 * Frames as the AT86RF233 build delivered them, footer included: a broadcast data frame, a unicast
 * data frame that asked for an acknowledgment, a sleepy end device's poll, and one acknowledgment
 * (test/fixtures/conbee2_ch15_hex.txt, channel 15, PAN 0xde20).
 */
static const uint8_t airBroadcast[65] =
{
    0x41, 0x88, 0xdf, 0x20, 0xde, 0xff, 0xff, 0x00, 0x00, 0x09, 0x12, 0xfc, 0xff, 0x00, 0x00, 0x01,
    0x07, 0xfb, 0xc5, 0x00, 0xff, 0xff, 0x2e, 0x21, 0x00, 0x28, 0x06, 0xc4, 0x84, 0x74, 0xfb, 0xc5,
    0x00, 0xff, 0xff, 0x2e, 0x21, 0x00, 0x00, 0x2b, 0x58, 0x69, 0x29, 0xfd, 0x78, 0xd4, 0x48, 0xd9,
    0x5d, 0xf4, 0xb9, 0x95, 0xeb, 0x08, 0x11, 0xc8, 0x6f, 0xa9, 0xf3, 0xfb, 0x76, 0xcc, 0xba, 0xe5,
    0xca
};

static const uint8_t airUnicast[47] =
{
    0x61, 0x88, 0xe0, 0x20, 0xde, 0x1f, 0x3c, 0x00, 0x00, 0x08, 0x02, 0x1f, 0x3c, 0x00, 0x00, 0x0a,
    0x08, 0x28, 0x07, 0xc4, 0x84, 0x74, 0xfb, 0xc5, 0x00, 0xff, 0xff, 0x2e, 0x21, 0x00, 0x00, 0xeb,
    0x10, 0xd9, 0xe0, 0x17, 0xbf, 0xcd, 0x98, 0x19, 0x96, 0x1b, 0xc9, 0x66, 0xfd, 0xa3, 0xb9
};

static const uint8_t airPoll[12] =
{
    0x63, 0x88, 0x6f, 0x20, 0xde, 0x00, 0x00, 0x29, 0x3c, 0x04, 0xe8, 0x29
};

static const uint8_t airAck[5] =
{
    0x02, 0x00, 0x1c, 0x55, 0x6f
};

/* IEEE 802.15.4-2024 §7.2.11's own worked example, as docs/internals/protocol.md §9.3 reads it out of the
   transmitted bit string: MHR `02 00 6a`, FCS `e4 79`. */
static const uint8_t specAckMhr[3] = { 0x02, 0x00, 0x6a };
static const uint8_t specAckFcs[2] = { 0xe4, 0x79 };

static Mac_Frame macFrame(uint32_t frameType, uint32_t destMode, uint32_t srcMode)
{
    Mac_Frame frame;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = (Mac_FrameType)frameType;
    frame.frameVersion = 0;         /* R23.1 Annex D.6: this stack pins the version field to zero */
    frame.destAddrMode = (Mac_AddrMode)destMode;
    frame.srcAddrMode = (Mac_AddrMode)srcMode;

    return frame;
}

/* Compose a frame, close it with its footer, and compare the whole thing against octets from the air. */
static void expectRoundTrip(const char *what, const uint8_t *air, uint32_t airLen,
                            const Mac_Frame *frame, const uint8_t *payload, uint32_t payloadLen)
{
    uint8_t mpdu[MAC_FRAME_MPDU_MAX];
    uint32_t len = 0;
    ZbStatus status;

    status = MacFrame_Compose(frame, payload, payloadLen, mpdu, (uint32_t)sizeof mpdu, &len);
    Test_ExpectStatus(status, ZB_OK, what);

    if (status != ZB_OK)
        return;

    status = MacFrame_AppendFcs(mpdu, len, (uint32_t)sizeof mpdu, &len);
    Test_ExpectStatus(status, ZB_OK, "and the same frame closes with its footer");

    if (status != ZB_OK)
        return;

    Test_Expect(len == airLen && Zb_memcmp(mpdu, air, airLen) == 0,
           "and the frame this module composed is the frame the air carried, octet for octet");
    Test_ExpectStatus(MacFrame_CheckFcs(mpdu, len), ZB_OK, "with the footer the frame computes for itself");
}

static void caseSpecVector(void)
{
    Mac_Frame frame = macFrame(MAC_FRAME_TYPE_ACK, MAC_ADDR_NONE, MAC_ADDR_NONE);
    uint8_t mpdu[16];
    uint32_t len = 0;
    uint32_t headerLen = 0;
    ZbStatus status;

    frame.seq = specAckMhr[2];

    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_OK, "an acknowledgment has a header to size");
    Test_Expect(headerLen == 3, "three octets: FCF and sequence, and no addressing field at all (7.3.3)");

    status = MacFrame_Compose(&frame, 0, 0, mpdu, (uint32_t)sizeof mpdu, &len);
    Test_ExpectStatus(status, ZB_OK, "an acknowledgment composes with no payload");
    Test_Expect(len == 3 && Zb_memcmp(mpdu, specAckMhr, 3) == 0,
           "and it is the standard's worked example: 02 00 6a");

    status = MacFrame_AppendFcs(mpdu, len, (uint32_t)sizeof mpdu, &len);
    Test_ExpectStatus(status, ZB_OK, "the footer appends");
    Test_Expect(len == 5 && Zb_memcmp(mpdu + 3, specAckFcs, 2) == 0,
           "e4 79, r0 first as 7.2.11 states it");
    Test_Expect(MacFrame_Fcs(specAckMhr, 3) == 0x79e4,
           "the value, before the wire puts its octets the other way round");
    Test_ExpectStatus(MacFrame_CheckFcs(mpdu, len), ZB_OK, "and checking it against the frame agrees");
}

static void caseCapturedParse(void)
{
    Mac_Frame frame;
    const uint8_t *payload = 0;
    uint32_t payloadLen = 0;
    ZbStatus status;

    /* The broadcast data frame: 0x8841, type 1, no acknowledgment asked for, one PAN field,
       16-bit addresses at both ends. */
    status = MacFrame_Parse(airBroadcast, (uint32_t)sizeof airBroadcast, 1, &frame, &payload, &payloadLen, 0);
    Test_ExpectStatus(status, ZB_OK, "a broadcast data frame off the air parses");
    Test_Expect(frame.frameType == MAC_FRAME_TYPE_DATA && frame.frameVersion == 0,
           "as a data frame of the version Zigbee pins it to");
    Test_Expect(!frame.securityEnabled && !frame.ackRequest && !frame.framePending && frame.panIdCompression,
           "unsecured, unanswered, not pending, one PAN field");
    Test_Expect(frame.destAddrMode == MAC_ADDR_SHORT && frame.srcAddrMode == MAC_ADDR_SHORT,
           "with 16-bit addresses at both ends");
    Test_Expect(frame.seq == 0xdf && frame.destPan == 0xde20 && frame.srcPan == 0xde20,
           "sequence 0xdf and PAN 0xde20, which is 20 de on the wire, least significant octet first (6.3)");
    Test_Expect(frame.destShort == MAC_FRAME_ADDR_BROADCAST && frame.srcShort == 0x0000,
           "to every device in the PAN, from the coordinator");
    Test_Expect(payloadLen == 54 && payload == airBroadcast + 9,
           "and 54 octets of MAC payload between a nine-octet header and the footer");
    Test_ExpectStatus(MacFrame_CheckFcs(airBroadcast, (uint32_t)sizeof airBroadcast), ZB_OK,
                  "the tail this build delivers is the footer the frame computes");

    expectRoundTrip("the broadcast frame composes back out of its own parsed fields",
                    airBroadcast, (uint32_t)sizeof airBroadcast, &frame, payload, payloadLen);

    /* The unicast data frame: 0x8861, the same shape with bit 5 set, and this one is answered. */
    status = MacFrame_Parse(airUnicast, (uint32_t)sizeof airUnicast, 1, &frame, &payload, &payloadLen, 0);
    Test_ExpectStatus(status, ZB_OK, "a unicast data frame parses");
    Test_Expect(frame.ackRequest && !frame.framePending,
           "asking for an acknowledgment, carrying no frame pending of its own");
    Test_Expect(frame.destShort == 0x3c1f && frame.srcShort == 0x0000 && frame.seq == 0xe0,
           "to 0x3c1f from 0x0000 at sequence 0xe0");
    Test_Expect(payloadLen == 36 && payload == airUnicast + 9, "and 36 octets of payload");

    expectRoundTrip("and the unicast frame does the same",
                    airUnicast, (uint32_t)sizeof airUnicast, &frame, payload, payloadLen);

    /* The poll: a MAC command to the coordinator, whose content field is empty (7.2.1.1 Command
       identifier plus nothing) which is why the whole frame is twelve octets. */
    status = MacFrame_Parse(airPoll, (uint32_t)sizeof airPoll, 1, &frame, &payload, &payloadLen, 0);
    Test_ExpectStatus(status, ZB_OK, "a poll parses");
    Test_Expect(frame.frameType == MAC_FRAME_TYPE_COMMAND && frame.ackRequest,
           "a MAC command that asks to be answered");
    Test_Expect(frame.destShort == MAC_FRAME_ADDR_COORDINATOR && frame.srcShort == 0x3c29 && frame.seq == 0x6f,
           "from 0x3c29 to 0x0000 at sequence 0x6f");
    Test_Expect(payloadLen == 1 && payload[0] == 0x04,
           "with one octet of payload: command 0x04, the Data Request, whose Content field is zero-length");
    Test_ExpectStatus(MacFrame_CheckFcs(airPoll, (uint32_t)sizeof airPoll), ZB_ERR_BAD_FRAME,
                  "and this particular poll's tail does not match what its ten octets compute: it is one of the two frames docs/internals/protocol.md §9.3 keeps as a candidate for on-air corruption");
    Test_Expect(MacFrame_Fcs(airPoll, 10) != (uint16_t)(airPoll[10] | (uint16_t)(airPoll[11] << 8)),
           "the footer the frame wants is not the footer it was given");

    /* The acknowledgment: five octets, and nothing else. */
    status = MacFrame_Parse(airAck, (uint32_t)sizeof airAck, 1, &frame, &payload, &payloadLen, 0);
    Test_ExpectStatus(status, ZB_OK, "an acknowledgment parses");
    Test_Expect(frame.frameType == MAC_FRAME_TYPE_ACK && frame.destAddrMode == MAC_ADDR_NONE
           && frame.srcAddrMode == MAC_ADDR_NONE && !frame.ackRequest && !frame.panIdCompression,
           "with every FCF subfield but the type zero, as 7.3.3 requires");
    Test_Expect(frame.seq == 0x1c && payloadLen == 0,
           "answering sequence 0x1c: the poll's own sequence is 0x6f, a different frame");
    Test_ExpectStatus(MacFrame_CheckFcs(airAck, (uint32_t)sizeof airAck), ZB_OK,
                  "02 00 1c computes 55 6f, which is what the RCP delivered");

    expectRoundTrip("and an acknowledgment composes back out byte for byte",
                    airAck, (uint32_t)sizeof airAck, &frame, 0, 0);
}

static void caseFieldPresence(void)
{
    Mac_Frame frame;
    uint8_t mpdu[MAC_FRAME_MPDU_MAX];
    uint32_t headerLen = 0;
    uint32_t len = 0;

    frame = macFrame(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, MAC_ADDR_NONE);
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_OK, "a frame addressed to one destination from the coordinator");
    Test_Expect(headerLen == 7, "FCF, sequence, destination PAN, destination address: seven octets");

    frame = macFrame(MAC_FRAME_TYPE_DATA, MAC_ADDR_NONE, MAC_ADDR_SHORT);
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_OK, "and the mirror case, from one source to the PAN coordinator");
    Test_Expect(headerLen == 7, "which costs the same seven octets with the source fields instead");

    frame = macFrame(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, MAC_ADDR_SHORT);
    frame.panIdCompression = 1;
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_OK, "both addresses with compression");
    Test_Expect(headerLen == 9, "carries one PAN field, which is what test/fixtures/ shows on every frame");

    frame.panIdCompression = 0;
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_OK, "without it");
    Test_Expect(headerLen == 11, "the frame carries both PAN fields");

    frame = macFrame(MAC_FRAME_TYPE_DATA, MAC_ADDR_EXTENDED, MAC_ADDR_EXTENDED);
    frame.panIdCompression = 1;
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_OK, "extended addresses at both ends");
    Test_Expect(headerLen == 21, "two eight-octet addresses and one PAN field");

    frame.panIdCompression = 0;
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_OK, "with both PAN fields too");
    Test_Expect(headerLen == 23, "which is the longest MHR a legacy frame can have");

    /* The rules that make a combination illegal. */
    frame = macFrame(MAC_FRAME_TYPE_DATA, MAC_ADDR_RESERVED, MAC_ADDR_SHORT);
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_ERR_BAD_ARGUMENT,
                 "addressing mode 1 is reserved in Table 80, not a mode");

    frame = macFrame(MAC_FRAME_TYPE_DATA, MAC_ADDR_NONE, MAC_ADDR_NONE);
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_ERR_BAD_ARGUMENT,
                 "a data frame with no address at either end is neither to the coordinator nor from it");

    frame = macFrame(MAC_FRAME_TYPE_COMMAND, MAC_ADDR_NONE, MAC_ADDR_NONE);
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_ERR_BAD_ARGUMENT,
                 "nor is a MAC command");

    frame = macFrame(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, MAC_ADDR_NONE);
    frame.panIdCompression = 1;
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_ERR_BAD_ARGUMENT,
                 "compression means the source PAN is the destination PAN, and needs a source address to mean it");

    frame = macFrame(MAC_FRAME_TYPE_ACK, MAC_ADDR_SHORT, MAC_ADDR_NONE);
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_ERR_BAD_ARGUMENT,
                 "an Imm-Ack carries no addressing field (7.3.3)");

    frame = macFrame(MAC_FRAME_TYPE_ACK, MAC_ADDR_NONE, MAC_ADDR_NONE);
    frame.ackRequest = 1;
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_ERR_BAD_ARGUMENT,
                 "and never asks for one");

    frame.framePending = 1;
    frame.ackRequest = 0;
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_OK,
                  "but frame pending on an acknowledgment is how 10.22.3 answers a poll it cannot serve yet");

    frame = macFrame(MAC_FRAME_TYPE_BEACON, MAC_ADDR_SHORT, MAC_ADDR_SHORT);
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_ERR_BAD_ARGUMENT,
                 "a beacon addresses from itself: 7.3.1 leaves the destination fields out");

    frame = macFrame(MAC_FRAME_TYPE_BEACON, MAC_ADDR_NONE, MAC_ADDR_NONE);
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_ERR_BAD_ARGUMENT,
                 "and its source fields are not optional");

    frame = macFrame(MAC_FRAME_TYPE_BEACON, MAC_ADDR_NONE, MAC_ADDR_SHORT);
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_OK,
                  "the shape itself is legal to describe, even though this stack refuses to compose one");

    /* 7.3.1.2: a version-0 or version-1 beacon's frame control has "all other fields ... set to zero and ignored on
       reception", so an AR bit on a received beacon is not part of its shape, and only the writing side refuses. */
    frame.ackRequest = 1;
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_OK,
                      "an AR bit on a beacon does not change its shape, which the receiver ignores");
    Test_ExpectStatus(MacFrame_Compose(&frame, 0, 0, mpdu, (uint32_t)sizeof mpdu, &len), ZB_ERR_BAD_ARGUMENT,
                      "while composing one with that bit refuses: the clause writes them zero");
    frame.ackRequest = 0;

    frame = macFrame(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, MAC_ADDR_SHORT);
    frame.securityEnabled = 1;
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_ERR_UNSUPPORTED,
                  "a secured frame is refused rather than parsed as if the auxiliary header were absent");

    frame.frameVersion = 3;
    frame.securityEnabled = 0;
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_ERR_BAD_ARGUMENT,
                 "and a reserved version value is refused outright");

    /* Table 7-4 and R23.1 Annex D.6: version 2 is a form this stack must read, so the layout gives it a length;
       what it does not read is a suppressed sequence octet or an IE list (7.2.2.7, 7.2.2.8). */
    frame = macFrame(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, MAC_ADDR_SHORT);
    frame.frameVersion = 2;
    frame.panIdCompression = 1;
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_OK,
                 "a version-2 frame is laid out like the version-0 one whose fields it shares");
    Test_Expect(headerLen == 9, "nine octets with both short addresses and the one PAN field Table 7-2 keeps");

    frame.sequenceSuppressed = 1;
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_ERR_UNSUPPORTED,
                 "a suppressed sequence octet is a version-2 form this stack does not read");
    frame.sequenceSuppressed = 0;

    frame = macFrame(MAC_FRAME_TYPE_MULTIPURPOSE, MAC_ADDR_SHORT, MAC_ADDR_SHORT);
    frame.frameVersion = 2;
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_ERR_UNSUPPORTED,
                 "and the frame types 802.15.4-2024 adds, which no Zigbee device sends, are named as unsupported");

    frame = macFrame(MAC_FRAME_TYPE_RESERVED, MAC_ADDR_SHORT, MAC_ADDR_SHORT);
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_ERR_BAD_ARGUMENT,
                 "while Table 7-1's one reserved type (value 4, not the 2006 table's 4 to 7) is refused by 6.6.2 a)");
}

static void caseCompositionBounds(void)
{
    Mac_Frame frame = macFrame(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, MAC_ADDR_SHORT);
    uint8_t payload[128];
    uint8_t mpdu[160];
    uint8_t untouched[4] = { 0xaa, 0xbb, 0xcc, 0xdd };
    uint8_t small[4] = { 0xaa, 0xbb, 0xcc, 0xdd };
    uint32_t len = 0;
    ZbStatus status;

    frame.panIdCompression = 1;
    frame.destPan = 0xbeef;
    frame.srcPan = 0xbeef;
    frame.destShort = 0x0001;
    frame.srcShort = 0x0002;
    frame.seq = 0x2a;
    Zb_memset(payload, 0x5a, (uint32_t)sizeof payload);

    /* Nine octets of MHR: the payload may reach 116, because the frame is 127 octets with its footer. */
    status = MacFrame_Compose(&frame, payload, 116, mpdu, (uint32_t)sizeof mpdu, &len);
    Test_ExpectStatus(status, ZB_OK, "a frame at the ceiling composes");
    Test_Expect(len == 125, "125 octets before the footer");
    status = MacFrame_AppendFcs(mpdu, len, (uint32_t)sizeof mpdu, &len);
    Test_ExpectStatus(status, ZB_OK, "which closes at 127");
    Test_Expect(len == MAC_FRAME_MPDU_MAX, "the PHY's own limit (13.1.3.2 with Figure 13-4's 7-bit Frame Length field, and phyMaxPacketSize in 12.3.2 Table 12-2: there is no macMaxFrameSize in either edition)");

    status = MacFrame_Compose(&frame, payload, 117, mpdu, (uint32_t)sizeof mpdu, &len);
    Test_ExpectStatus(status, ZB_ERR_BAD_ARGUMENT,
                  "one octet more cannot ever be a frame on this PHY, whatever the buffer is");

    status = MacFrame_Compose(&frame, payload, 116, small, (uint32_t)sizeof small, &len);
    Test_ExpectStatus(status, ZB_ERR_NO_SPACE, "a buffer that cannot hold it is named as no space");
    Test_Expect(Zb_memcmp(small, untouched, 4) == 0, "and nothing of it was written (docs/internals/coding-rules.md §1)");

    status = MacFrame_AppendFcs(mpdu, 126, 127, &len);
    Test_ExpectStatus(status, ZB_ERR_BAD_ARGUMENT, "a footer that would push the frame past 127 is refused");

    status = MacFrame_Compose(&frame, 0, 1, mpdu, (uint32_t)sizeof mpdu, &len);
    Test_ExpectStatus(status, ZB_ERR_BAD_ARGUMENT, "a payload length without a payload is an argument error");

    status = MacFrame_Compose(&frame, 0, 0, mpdu, (uint32_t)sizeof mpdu, &len);
    Test_ExpectStatus(status, ZB_OK, "while no payload at all is a frame this module composes");
    Test_Expect(len == 9, "the header alone");
}

/*
 * A beacon's MAC payload, 7.3.1's Figure 7-5 down to the octets. R23.1 Annex D.7 pins macBeaconOrder and
 * macSuperframeOrder to 0x0F on a Zigbee network, and the Annex's own worked beacon prints the Superframe
 * Specification 0xCFFF: 0x0F, 0x0F, Final CAP Slot 0x0F, battery-life clear, PAN coordinator set, association
 * permit set. That value is the known answer this case composes towards, and the beacon payload is the 15-octet
 * Zigbee Beacon Info Field the same figure prints.
 */
static void caseBeaconPayload(void)
{
    static const uint8_t zigbeeInfo[15] =
    {
        0x00, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xff, 0xff, 0xff, 0x00
    };
    MacFrame_Beacon beacon;
    MacFrame_Beacon readBack;
    const uint8_t *payloadOut;
    uint32_t payloadOutLen = 0;
    uint8_t body[64];
    uint8_t small[4] = { 0xaa, 0xbb, 0xcc, 0xdd };
    uint32_t len = 0;

    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.beaconOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.superframeOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.finalCapSlot = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.panCoordinator = 1;
    beacon.associationPermit = 1;

    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, zigbeeInfo, 15, body, (uint32_t)sizeof body, &len),
                      ZB_OK, "a beacon payload composes");
    Test_Expect(len == 19, "four octets of MAC payload around it: no GTS, no pending address");
    Test_Expect(body[0] == 0xff && body[1] == 0xcf,
                "and its Superframe Specification is 0xCFFF, the value Annex D.7's worked beacon prints");
    Test_Expect(body[2] == 0x00, "the GTS Specification is zero: no descriptor, and GTS Permit clear (10.2.2.1)");
    Test_Expect(body[3] == 0x00, "and no device is pending");
    Test_Expect(Zb_memcmp(body + 4, zigbeeInfo, 15) == 0, "the payload follows the four fields unchanged");

    Test_ExpectStatus(MacFrame_ParseBeaconPayload(body, len, &readBack, &payloadOut, &payloadOutLen), ZB_OK,
                      "and it reads back");
    Test_Expect(readBack.beaconOrder == 15 && readBack.superframeOrder == 15 && readBack.finalCapSlot == 15
                && readBack.panCoordinator == 1 && readBack.associationPermit == 1
                && readBack.batteryLifeExtension == 0,
                "field for field: the four four-bit subfields and the three single bits where Figure 7-7 puts them");
    Test_Expect(payloadOutLen == 15 && Zb_memcmp(payloadOut, zigbeeInfo, 15) == 0,
                "with the beacon payload named as the span that follows them");

    /* 7.3.1.6: the two address lists, in the order the figure prints them, short addresses first. */
    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.pendingShortCount = 2;
    beacon.pendingShort[0] = 0x1234;
    beacon.pendingShort[1] = 0xabcd;
    beacon.pendingExtendedCount = 1;
    beacon.pendingExtended[0] = ((uint64_t)0x11223344 << 32) | 0x55667788;

    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, 0, 0, body, (uint32_t)sizeof body, &len), ZB_OK,
                      "a beacon with pending addresses composes");
    Test_Expect(len == 4 + 4 + 8, "four fields, two short addresses, one extended");
    Test_Expect(body[3] == 0x12, "the Pending Address Specification carries two short and one extended in Figure 7-13's bits");
    Test_Expect(body[4] == 0x34 && body[5] == 0x12, "the short list first, least significant octet first");

    Test_ExpectStatus(MacFrame_ParseBeaconPayload(body, len, &readBack, &payloadOut, &payloadOutLen), ZB_OK,
                      "and it reads back");
    Test_Expect(readBack.pendingShortCount == 2 && readBack.pendingShort[0] == 0x1234
                && readBack.pendingShort[1] == 0xabcd && readBack.pendingExtendedCount == 1
                && readBack.pendingExtended[0] == (((uint64_t)0x11223344 << 32) | 0x55667788),
                "both lists intact, ends and all");

    /* The refusals: the count subfields are three bits wide (Figure 7-13), and a beacon whose counts overrun its
       octets is not a beacon a receiver may trust. */
    beacon.pendingShortCount = MAC_FRAME_PENDING_MAX + 1;
    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, 0, 0, body, (uint32_t)sizeof body, &len),
                      ZB_ERR_BAD_ARGUMENT, "eight short addresses is a count the field cannot state");
    beacon.pendingShortCount = 1;
    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, 0, 0, small, (uint32_t)sizeof small, &len),
                      ZB_ERR_NO_SPACE, "and a buffer that cannot hold it is no space");
    Test_Expect(small[0] == 0xaa && small[1] == 0xbb && small[2] == 0xcc && small[3] == 0xdd,
                "with nothing written");

    Test_ExpectStatus(MacFrame_ParseBeaconPayload(body, 3, &readBack, &payloadOut, &payloadOutLen),
                      ZB_ERR_BAD_FRAME, "a payload shorter than the four fields is not a beacon payload");
    Test_ExpectStatus(MacFrame_ParseBeaconPayload(body, 0, &readBack, &payloadOut, &payloadOutLen),
                      ZB_ERR_BAD_FRAME, "and neither is an empty one");
}

/* 10.21.5.1/10.21.5.2's association bodies: the request one octet (0x8e = FFD, mains, receiver on, allocate),
   the response three (short address, then Table 10-102's status); the 2024 capability bits, with 2006's bit 0
   read past. */
static void caseAssociationBodies(void)
{
    MacFrame_Capability capability;
    MacFrame_Capability readBack;
    MacFrame_AssociationResponse response;
    MacFrame_AssociationResponse readResponse;
    uint8_t body[8];
    uint8_t small[2] = { 0xaa, 0xbb };
    uint32_t len = 0;

    Test_Expect(MAC_CMD_ASSOCIATION_REQUEST == 0x01 && MAC_CMD_ASSOCIATION_RESPONSE == 0x02,
                "Table 7-11 numbers the association pair 0x01 and 0x02");

    Zb_memset(&capability, 0, (uint32_t)sizeof capability);
    capability.deviceType = 1;
    capability.powerSource = 1;
    capability.rxOnWhenIdle = 1;
    capability.allocateAddress = 1;

    Test_ExpectStatus(MacFrame_ComposeAssociationRequest(&capability, body, (uint32_t)sizeof body, &len), ZB_OK,
                      "an Association Request content composes");
    Test_Expect(len == 1 && body[0] == 0x8e,
                "one octet: FFD (bit 1), mains (bit 2), receiver on (bit 3) and allocate address (bit 7), so 0x8e");

    Test_ExpectStatus(MacFrame_ParseAssociationRequest(body, len, &readBack), ZB_OK, "and it reads back");
    Test_Expect(readBack.deviceType == 1 && readBack.powerSource == 1 && readBack.rxOnWhenIdle == 1
                && readBack.allocateAddress == 1,
                "with its four bits where Figure 10-157 puts them");
    Test_Expect(readBack.associationType == 0 && readBack.suspendableCsmaCa == 0
                && readBack.securityCapability == 0,
                "and the three bits this stack never sets clear");

    /* A 2006 device's alternate-PAN-coordinator bit is 2024's reserved bit: read, and ignored. */
    body[0] = 0x01;
    Test_ExpectStatus(MacFrame_ParseAssociationRequest(body, 1, &readBack), ZB_OK,
                      "an octet with bit 0 set is still a request");
    Test_Expect(readBack.deviceType == 0 && readBack.powerSource == 0 && readBack.rxOnWhenIdle == 0
                && readBack.allocateAddress == 0,
                "and the reserved bit is not a field: nothing else moves");

    /* A peer that claims fast association or MAC security is read as claiming it, not silently cleared. */
    body[0] = 0x70;
    Test_ExpectStatus(MacFrame_ParseAssociationRequest(body, 1, &readBack), ZB_OK,
                      "the fast-association and security bits are read");

    Test_Expect(readBack.associationType == 1 && readBack.suspendableCsmaCa == 1
                && readBack.securityCapability == 1,
                "as the three fields they are, for the association procedure to judge");

    Zb_memset(&response, 0, (uint32_t)sizeof response);
    response.shortAddress = 0x1a2b;
    response.status = MAC_ASSOC_STATUS_SUCCESS;

    Test_ExpectStatus(MacFrame_ComposeAssociationResponse(&response, body, (uint32_t)sizeof body, &len), ZB_OK,
                      "an Association Response content composes");
    Test_Expect(len == 3 && body[0] == 0x2b && body[1] == 0x1a && body[2] == 0x00,
                "three octets: the short address least significant first, then Table 10-102's status");

    Test_ExpectStatus(MacFrame_ParseAssociationResponse(body, len, &readResponse), ZB_OK, "and it reads back");
    Test_Expect(readResponse.shortAddress == 0x1a2b && readResponse.status == MAC_ASSOC_STATUS_SUCCESS,
                "with the address and the status intact");

    Test_ExpectStatus(MacFrame_ComposeAssociationRequest(&capability, small, 0, &len),
                      ZB_ERR_NO_SPACE, "a request composed into no room is no space");
    Test_Expect(small[0] == 0xaa && small[1] == 0xbb, "and nothing is written");

    capability.securityCapability = 1;
    Test_ExpectStatus(MacFrame_ComposeAssociationRequest(&capability, body, (uint32_t)sizeof body, &len),
                      ZB_ERR_UNSUPPORTED, "and a request claiming MAC security is refused, since no MAC security exists here");
    capability.securityCapability = 0;
    capability.associationType = 1;
    Test_ExpectStatus(MacFrame_ComposeAssociationRequest(&capability, body, (uint32_t)sizeof body, &len),
                      ZB_ERR_UNSUPPORTED, "as is fast association");
    capability.associationType = 0;
    capability.suspendableCsmaCa = 1;
    Test_ExpectStatus(MacFrame_ComposeAssociationRequest(&capability, body, (uint32_t)sizeof body, &len),
                      ZB_ERR_UNSUPPORTED, "and suspendable CSMA-CA");

    Test_ExpectStatus(MacFrame_ParseAssociationRequest(body, 0, &readBack), ZB_ERR_BAD_FRAME,
                      "a request body with no octet is not a request");
    Test_ExpectStatus(MacFrame_ParseAssociationRequest(body, 2, &readBack), ZB_ERR_BAD_FRAME,
                      "nor is one with a second octet");
    Test_ExpectStatus(MacFrame_ParseAssociationResponse(body, 2, &readResponse), ZB_ERR_BAD_FRAME,
                      "a response body short of its last octet is not a response");
    Test_ExpectStatus(MacFrame_ParseAssociationResponse(body, 4, &readResponse), ZB_ERR_BAD_FRAME,
                      "nor is one with an octet to spare");
    Test_ExpectStatus(MacFrame_ParseAssociationRequest(0, 1, &readBack), ZB_ERR_BAD_ARGUMENT,
                      "and no body at all is a bad argument");
}

static void caseAddressByteOrder(void)
{
    Mac_Frame frame = macFrame(MAC_FRAME_TYPE_DATA, MAC_ADDR_EXTENDED, MAC_ADDR_EXTENDED);
    uint8_t mpdu[64];
    uint8_t payload[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11 };

    /* FCF 0xcc21: type 1, acknowledgment asked for, both modes 3, compression off, version 0. */
    uint8_t expected[29] =
    {
        0x21, 0xcc, 0x11,                                             /* FCF, sequence */
        0x20, 0xde,                                                   /* destination PAN 0xde20 */
        0x80, 0x01, 0x2c, 0x0b, 0x00, 0x4a, 0x12, 0x00,               /* destination 0x00124a000b2c0180 */
        0x11, 0xad,                                                   /* source PAN 0xad11 */
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,               /* source 0x8877665544332211 */
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x11                            /* the payload, untouched */
    };

    Mac_Frame back;
    const uint8_t *parsedPayload = 0;
    uint32_t parsedLen = 0;
    uint32_t headerLen = 0;
    uint32_t len = 0;
    uint32_t i;

    frame.destPan = 0xde20;
    frame.srcPan = 0xad11;
    frame.destExtended = 0x00124a000b2c0180;
    frame.srcExtended = 0x8877665544332211;
    frame.seq = 0x11;
    frame.ackRequest = 1;
    frame.panIdCompression = 0;

    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &headerLen), ZB_OK, "a frame addressed by EUI-64 at both ends");
    Test_Expect(headerLen == 23, "23 octets of header: 2 + 1 + 2 + 8 + 2 + 8 (7.2.1.3 … 7.2.1.6)");

    Test_ExpectStatus(MacFrame_Compose(&frame, payload, 6, mpdu, (uint32_t)sizeof mpdu, &len), ZB_OK,
                 "and it composes");
    Test_Expect(len == 29, "with the payload");
    Test_Expect(Zb_memcmp(mpdu, expected, 29) == 0,
           "every multi-octet field least significant octet first, in the order the frame names them (6.3)");

    for (i = 0; i < 8; i++)
        Test_Expect(mpdu[5 + i] == (uint8_t)(frame.destExtended >> (i * 8)),
               "the destination address travels from its low octet upward");

    for (i = 0; i < 8; i++)
        Test_Expect(mpdu[15 + i] == (uint8_t)(frame.srcExtended >> (i * 8)),
               "and so does the source address");

    Test_ExpectStatus(MacFrame_Parse(mpdu, len, 0, &back, &parsedPayload, &parsedLen, 0), ZB_OK,
                 "and parses back with no footer claimed");
    Test_Expect(back.destExtended == frame.destExtended && back.srcExtended == frame.srcExtended,
           "both 64-bit addresses intact through the round trip");
    Test_Expect(back.destPan == 0xde20 && back.srcPan == 0xad11,
           "both PAN fields distinct, because compression was off");
    Test_Expect(parsedLen == 6 && parsedPayload == mpdu + 23, "and the payload where the header ends");

    frame.panIdCompression = 1;
    Test_ExpectStatus(MacFrame_Compose(&frame, payload, 6, mpdu, (uint32_t)sizeof mpdu, &len), ZB_OK,
                 "the same frame with compression composes");
    Test_Expect(len == 27, "one PAN field shorter");
    Test_ExpectStatus(MacFrame_Parse(mpdu, len, 0, &back, &parsedPayload, &parsedLen, 0), ZB_OK, "and parses back");
    Test_Expect(back.srcPan == back.destPan, "where a parser can only report the source PAN as the destination PAN");
    Test_Expect(back.srcExtended == frame.srcExtended, "while the addresses stay two separate fields");
}

static void caseParseRejections(void)
{
    Mac_Frame frame;
    const uint8_t *payload = 0;
    uint32_t payloadLen = 0;
    uint8_t mpdu[64];
    uint32_t i;

    /* A header that promises more octets than the frame has. */
    Test_ExpectStatus(MacFrame_Parse(airPoll, 6, 1, &frame, &payload, &payloadLen, 0), ZB_ERR_BAD_FRAME,
                 "a poll cut short is not a frame");
    Test_ExpectStatus(MacFrame_Parse(airPoll, (uint32_t)sizeof airPoll, 0, &frame, &payload, &payloadLen, 0),
                 ZB_OK, "the same octets, read as a frame whose radio stripped the footer");
    Test_Expect(payloadLen == 3, "which leaves e8 29 inside the payload, where band A must decide what to do with them");
    Test_ExpectStatus(MacFrame_Parse(airAck, 4, 1, &frame, &payload, &payloadLen, 0), ZB_ERR_BAD_FRAME,
                 "four octets cannot be a frame with a footer");

    /* A stripped acknowledgment, as the other build delivers it. */
    Test_ExpectStatus(MacFrame_Parse(airAck, 3, 0, &frame, &payload, &payloadLen, 0), ZB_OK,
                 "FCF and sequence alone is a frame when no footer is claimed");
    Test_Expect(payloadLen == 0 && frame.seq == 0x1c, "and it has no payload");

    /* Bits 8 and 9 are not writable on a version-0 frame (docs/internals/protocol.md §9.1). */
    for (i = 0; i < 2; i++)
    {
        mpdu[0] = airPoll[0];
        mpdu[1] = (uint8_t)(airPoll[1] | (uint8_t)(1 << (8 + i)));
        Test_ExpectStatus(MacFrame_Parse(mpdu, 2, 1, &frame, &payload, &payloadLen, 0), ZB_ERR_BAD_FRAME,
                     "a version-0 frame with the sequence-suppression or IE-present bit set is a corrupt frame");
    }

    /* A secured frame: this stack has no auxiliary security header to read. */
    mpdu[0] = (uint8_t)(airPoll[0] | (1 << 3));
    mpdu[1] = airPoll[1];
    Test_ExpectStatus(MacFrame_Parse(mpdu, 12, 1, &frame, &payload, &payloadLen, 0), ZB_ERR_UNSUPPORTED,
                 "security enabled is named as unsupported, not misread as a shorter header");

    /* A long value in the length the caller claims. */
    Test_ExpectStatus(MacFrame_Parse(mpdu, MAC_FRAME_MPDU_MAX + 1, 1, &frame, &payload, &payloadLen, 0),
                 ZB_ERR_BAD_FRAME, "and no frame is longer than the PHY's limit");

    /* A footer that does not match: one octet of a frame whose footer does validate. */
    for (i = 0; i < 5; i++)
        mpdu[i] = airAck[i];

    Test_ExpectStatus(MacFrame_CheckFcs(mpdu, 5), ZB_OK, "the captured acknowledgment's footer validates");
    mpdu[1] = (uint8_t)(mpdu[1] ^ 0x01);
    Test_ExpectStatus(MacFrame_CheckFcs(mpdu, 5), ZB_ERR_BAD_FRAME,
                 "flip one octet inside the frame and the delivered footer stops matching");

    mpdu[1] = airAck[1];
    mpdu[4] = (uint8_t)(mpdu[4] ^ 0x01);
    Test_ExpectStatus(MacFrame_CheckFcs(mpdu, 5), ZB_ERR_BAD_FRAME,
                 "and so is a corrupted footer on an intact frame");

    mpdu[4] = airAck[4];
    mpdu[0] = (uint8_t)(mpdu[0] | (1 << 5));
    Test_ExpectStatus(MacFrame_CheckFcs(mpdu, 5), ZB_ERR_BAD_FRAME, "and a frame that changed asks for an answer it cannot");
}

static void caseAckComposeAgainstAir(void)
{
    Mac_Frame frame = macFrame(MAC_FRAME_TYPE_ACK, MAC_ADDR_NONE, MAC_ADDR_NONE);
    Mac_Frame back;
    const uint8_t *payload = 0;
    uint32_t payloadLen = 0;
    uint8_t mpdu[16];
    uint32_t len = 0;

    /* What an answer to the captured poll has to look like: the poll's own sequence number, and
       nothing else a legacy acknowledgment can carry (7.3.3). */
    frame.seq = airPoll[2];
    Test_ExpectStatus(MacFrame_Compose(&frame, 0, 0, mpdu, (uint32_t)sizeof mpdu, &len), ZB_OK,
                 "composing the acknowledgment a poll asked for");
    Test_Expect(len == 3 && mpdu[0] == 0x02 && mpdu[1] == 0x00 && mpdu[2] == 0x6f,
           "02 00 6f: the poll's FCF asks, the answer may not");

    Test_ExpectStatus(MacFrame_AppendFcs(mpdu, len, (uint32_t)sizeof mpdu, &len), ZB_OK, "footer appended");
    Test_Expect(len == MAC_FRAME_MPDU_MIN, "five octets, which is the shortest frame there is");
    Test_ExpectStatus(MacFrame_CheckFcs(mpdu, len), ZB_OK, "and self-consistent");
    Test_ExpectStatus(MacFrame_Parse(mpdu, len, 1, &back, &payload, &payloadLen, 0), ZB_OK, "and it parses back");
    Test_Expect(back.seq == 0x6f && back.frameType == MAC_FRAME_TYPE_ACK && payloadLen == 0,
           "at the sequence the poll asked to be answered");
}

/* 7.2.2.7, 7.2.2.8, 7.3.1.5 and 10.2.2.1, each an obligation the writer can state: the two frame-control bits are
   zero below version 2, the GTS permit is the requester's, and the superframe orders are ordered. */
static void caseWriterRefusesWhatItCannotState(void)
{
    Mac_Frame frame;
    MacFrame_Beacon beacon;
    uint8_t out[128];
    uint8_t body[128];
    const uint8_t *payload;
    uint32_t payloadLen;
    uint32_t len;
    MacFrame_Beacon readBack;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_DATA;
    frame.frameVersion = 0;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.destPan = 0x1234;
    frame.srcPan = 0x1234;
    frame.sequenceSuppressed = 1;
    Test_ExpectStatus(MacFrame_Compose(&frame, 0, 0, out, (uint32_t)sizeof out, &len), ZB_ERR_BAD_ARGUMENT,
                      "a version-0 frame with the suppression bit set is refused: 7.2.2.7 holds it zero");

    frame.sequenceSuppressed = 0;
    frame.iePresent = 1;
    Test_ExpectStatus(MacFrame_Compose(&frame, 0, 0, out, (uint32_t)sizeof out, &len), ZB_ERR_BAD_ARGUMENT,
                      "and one with the IE Present bit set: 7.2.2.8 holds that one zero too");

    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.beaconOrder = 2;
    beacon.superframeOrder = 6;
    beacon.finalCapSlot = 6;
    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, 0, 0, body, (uint32_t)sizeof body, &len),
                      ZB_ERR_BAD_ARGUMENT, "a beacon whose superframe order is above its beacon order is refused (10.2.2.1)");

    beacon.superframeOrder = 2;
    beacon.finalCapSlot = 2;
    beacon.gtsPermit = 1;
    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, 0, 0, body, (uint32_t)sizeof body, &len), ZB_OK,
                      "GTS Permit set composes (7.3.1.5)");
    Test_ExpectStatus(MacFrame_ParseBeaconPayload(body, len, &readBack, &payload, &payloadLen), ZB_OK, "and reads back");
    Test_Expect(readBack.gtsPermit == 1, "with the bit the request named, not a zero written over it");
    Test_Expect(readBack.beaconOrder == 2 && readBack.superframeOrder == 2, "and the orders it was given");
}

/* One row of Table 7-2 as the octets a version-0b10 frame carries: the frame control, the addressing fields, and
   what the row states. The sequence octet every frame carries is supplied by the walk below. */
typedef struct Table72Row
{
    uint8_t fcf[2];
    const uint8_t *addresses;
    uint32_t addressLen;
    const char *reading;
} Table72Row;

/* Table 7-2 row by row: the destination PAN is present with no address at all and absent under compression except
   where the row prints it, and an omitted source PAN repeats the destination's. */
static void caseTable72EveryRow(void)
{
    static const uint8_t none[] = { 0 };
    static const uint8_t panOnly[] = { 0x62, 0x1a };
    static const uint8_t shortOnly[] = { 0x62, 0x1a, 0x01, 0x00 };
    static const uint8_t shortNoPan[] = { 0x01, 0x00 };
    static const uint8_t extendedOverShort[] = { 0x62, 0x1a, 1, 2, 3, 4, 5, 6, 7, 8, 0x01, 0x00 };
    static const uint8_t bothShort[] = { 0x62, 0x1a, 0x01, 0x00, 0x02, 0x00 };
    static const Table72Row rows[] =
    {
        { { 0x01, 0x20 }, none, 0, "row 1: no address and no PAN" },
        { { 0x41, 0x20 }, panOnly, (uint32_t)sizeof panOnly, "row 2: a destination PAN with no address beside it" },
        { { 0x01, 0x28 }, shortOnly, (uint32_t)sizeof shortOnly, "row 3: a short destination and its PAN" },
        { { 0x41, 0x28 }, shortNoPan, (uint32_t)sizeof shortNoPan, "row 4: a short destination and no PAN" },
        { { 0x41, 0xac }, extendedOverShort, (uint32_t)sizeof extendedOverShort,
          "row 13: an extended destination over a short source" },
        { { 0x41, 0xa8 }, bothShort, (uint32_t)sizeof bothShort, "row 14: short both ways, the source PAN omitted" },
    };
    uint8_t mpdu[32];
    Mac_Frame frame;
    const uint8_t *payload;
    uint32_t payloadLen;
    uint32_t len;
    uint32_t i;

    for (i = 0; i < (uint32_t)(sizeof rows / sizeof rows[0]); i++)
    {
        mpdu[0] = rows[i].fcf[0];
        mpdu[1] = rows[i].fcf[1];
        mpdu[2] = 0x31;
        Zb_memcpy(mpdu + 3, rows[i].addresses, rows[i].addressLen);
        len = 3 + rows[i].addressLen;

        Test_ExpectStatus(MacFrame_Parse(mpdu, len, 0, &frame, &payload, &payloadLen, 0), ZB_OK, rows[i].reading);
        Test_Expect(frame.frameVersion == 2, "read as the version its frame control names");
        Test_ExpectCount(payloadLen, 0, "with no payload octet in it");
    }

    mpdu[0] = 0x41;
    mpdu[1] = 0x20;
    mpdu[2] = 0x31;
    mpdu[3] = 0x62;
    mpdu[4] = 0x1a;
    Test_ExpectStatus(MacFrame_Parse(mpdu, 5, 0, &frame, &payload, &payloadLen, 0), ZB_OK, "row 2 parses");
    Test_Expect(frame.destPan == 0x1a62 && frame.destAddrMode == MAC_ADDR_NONE,
                "with the destination PAN and no address beside it");

    mpdu[0] = 0x41;
    mpdu[1] = 0xa8;
    mpdu[2] = 0x31;
    mpdu[3] = 0x62;
    mpdu[4] = 0x1a;
    mpdu[5] = 0x01;
    mpdu[6] = 0x00;
    mpdu[7] = 0x02;
    mpdu[8] = 0x00;
    Test_ExpectStatus(MacFrame_Parse(mpdu, 9, 0, &frame, &payload, &payloadLen, 0), ZB_OK, "row 14 parses");
    Test_Expect(frame.destPan == 0x1a62 && frame.srcPan == 0x1a62,
                "and the omitted source PAN is the destination's, not zero");
}

int main(void)
{
    Test_Begin("mac_frame");

    caseSpecVector();
    caseCapturedParse();
    caseFieldPresence();
    caseCompositionBounds();
    caseBeaconPayload();
    caseAssociationBodies();
    caseAddressByteOrder();
    caseParseRejections();
    caseAckComposeAgainstAir();
    caseWriterRefusesWhatItCannotState();
    caseTable72EveryRow();

    return Test_Report();
}
