/* The `mac` suite's adoption and composition: the PIB this module keeps as
   a mirror of what the backend accepted, the DSN the application seeds and the frame that carries it, the frame
   a request composes, and the acknowledgment request refused where the radio cannot answer one. Runs on the
   hardware-free backend through the shared rig, with nothing above the MAC. */

#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "mac_helpers.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

/* What the same three contradictions compose as in a data frame: Frame Pending set, AR clear, both PAN
   fields present, short addressing at both ends. Composed here, not captured. */
#define DATA_PENDING_FCF 0x8811

void caseAdoption(void)
{
    Loopback_Radio model;
    Mac_Mac mac;
    Radio_Caps caps;
    Loopback_Sent sent[4];
    Mac_DataRequestParameters req;
    Mac_Counters counters;
    const Loopback_Radio *m = &model;

    Test_BandACapsAcks(&caps);

    Test_ExpectStatus(Mac_Init(0, 0, 0), ZB_ERR_BAD_ARGUMENT, "no self, no mac");

    LoopbackRadio_Init(&model, &caps);
    Test_ExpectStatus(Mac_Init(&mac, LoopbackRadio_Seam(&model), 0), ZB_OK, "a backend is adopted");
    Test_Expect(Mac_Pib(&mac)->present == 0,
           "and its PIB starts as what the backend reported, which for a fresh model is nothing at all");

    /* The consequence, asserted where it hurts: a MAC with no address cannot be a source. */
    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0xbeef, 0x1234, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&mac, &req, 0, 0), ZB_ERR_NOT_READY,
                 "a request that needs this device's short address is refused before anything is composed");
    Test_Expect(LoopbackRadio_Sent(m, sent, 4) == 0,
           "nothing was sent: the backend holds no record at all, not a query that could not have answered");
    counters = Mac_CountersOf(&mac);

    Test_Expect(counters.outstanding == 0 && counters.confirmQueue == 0,
           "and no track slot was taken and no confirmation exists, which is the same refusal seen from band A");

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0xbeef, 0x1234, MAC_ADDR_NONE, 1);
    Test_ExpectStatus(Mac_DataRequest(&mac, &req, 0, 0), ZB_OK,
                  "while the coordinator form (no source fields at all) needs no address and is the caller's choice, not this module's guess");

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_RESERVED, 0xbeef, 0x1234, MAC_ADDR_NONE, 0);
    Test_ExpectStatus(Mac_DataRequest(&mac, &req, 0, 0), ZB_ERR_BAD_ARGUMENT,
                  "and a reserved addressing mode is refused on the way in, not by mac_frame downstream");
    counters = Mac_CountersOf(&mac);

    Test_Expect(counters.refusedRequests == 2, "each refusal counted");
}

/*
 * The DSN the application seeds is the DSN the first frame carries.
 *
 * 6.6.1: "Each device shall keep three separate sequence numbers: data sequence number (DSN) stored
 * in macDsn … These sequence numbers are initialized to random values", and Table 8-36 prints
 * `macDsn` as 0x00-0xff with the default "Random value from within the range". The supplying of
 * that value is the application's, and the drawing of it is out of band A's contract entirely;
 * what band A owes is that the seed it was given is the number it numbers with. `Mac_DataRequest`
 * hands the counter to the composition and increments it afterwards, so `dsnStart` is what the
 * Sequence Number field of the first frame carries (7.2.3, "For other frames, the Sequence
 * Number field shall specify a DSN") and every frame after it carries the next number, which
 * is the same schedule the default 0 produces with 0x3c added to it. The `dsnStart` a config
 * carries therefore shifts every DSN this module will ever use rather than only the first one.
 */
/* Table 10-101, the usage of the short address: 0x0000 to 0xfffd send a Data frame from the short address, 0xfffe
   sends it from the extended one, and 0xffff has no Data row at all. The door decides, not the caller. */
static void caseSetOwnExtended(Test_BandA *dev)
{
    Radio_Pib pib;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_EXTENDED_ADDRESS;
    pib.extendedAddress[0] = 0x0a;
    pib.extendedAddress[1] = 0x0b;
    pib.extendedAddress[2] = 0x0c;
    pib.extendedAddress[3] = 0x0d;
    pib.extendedAddress[4] = 0x0e;
    pib.extendedAddress[5] = 0x0f;
    pib.extendedAddress[6] = 0x10;
    pib.extendedAddress[7] = 0x11;

    Test_ExpectStatus(Mac_SetPib(&dev->mac, &pib), ZB_OK, "this device's extended address is set through the seam");
}

void caseShortAddressRangeChoosesTheSource(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_DataRequestParameters req;
    Mac_Counters counters;

    rig(&dev, 0xfffd, PAN_ID);
    caseSetOwnExtended(&dev);

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 100, 0), ZB_OK,
                      "at 0xfffd the last usable short address is a source Table 10-101 lets a Data frame use");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 1, "and the frame goes out");

    rig(&dev, 0xfffe, PAN_ID);
    caseSetOwnExtended(&dev);

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 200, 0), ZB_ERR_NOT_READY,
                      "at 0xfffe the clause makes the extended address the source, so a short one is refused");

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_EXTENDED, PAN_ID, SLEEPY_A, MAC_ADDR_EXTENDED, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 300, 0), ZB_OK, "which is the form that is sent instead");

    rig(&dev, 0xffff, PAN_ID);
    caseSetOwnExtended(&dev);

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 400, 0), ZB_ERR_NOT_READY,
                      "and 0xffff has no Data row at all: a device that is on no PAN sends no Data frame");

    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.refusedRequests, 1, "the refusal counted where it was made");
}

void caseDsnStartComesFromTheConfig(void)
{
    Test_BandA dev;
    Radio_Caps caps;
    Mac_Config config;
    Loopback_Sent sent[4];
    Mac_DataConfirmParameters confirms[4];
    Mac_DataRequestParameters req;
    uint32_t got;
    uint32_t index;

    Test_BandACapsAcks(&caps);

    Zb_memset(&config, 0, (uint32_t)sizeof config);
    config.dsnStart = 0x3c;

    rigConfig(&dev, &caps, 0xdead, 0xbeef, &config);

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0xbeef, 0x1234, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 100, 0), ZB_OK, "a transmit at a MAC whose DSN was seeded");

    got = LoopbackRadio_Sent(&dev.model, sent, 4);
    Test_Expect(got == 1, "one frame reached the backend");
    index = sentIndexFor(sent, got, 0x1234, 0x3c);
    Test_Expect(index < got,
           "and the Sequence Number field of its MHR is the octet the application named: not 0, and not one less than the seed");

    Test_ExpectStatus(Mac_Step(&dev.mac, 101), ZB_OK, "answered");
    Test_Expect(Mac_PollConfirms(&dev.mac, confirms, 4) == 1 && confirms[0].dsn == 0x3c,
           "and the confirmation band A produced names the same number the air carries");

    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 102, 0), ZB_OK, "the next transmit");
    got = LoopbackRadio_Sent(&dev.model, sent, 4);
    index = sentIndexFor(sent, got, 0x1234, 0x3d);
    Test_Expect(index < got, "carries the number after the seed, so the seed shifts every DSN and not only the first");
    Test_Expect(dev.mac.tx.dsn == 0x3e, "and the counter stands at the number the third frame will take");

    /* The same module, seeded at the top of the octet: what a DSN that reaches the range Table 8-36 prints
       does is what MAC_DSN_WRAP says, and the seed does not change the wrap. */
    Zb_memset(&config, 0, (uint32_t)sizeof config);
    config.dsnStart = 0xff;
    rigConfig(&dev, &caps, 0xdead, 0xbeef, &config);

    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 110, 0), ZB_OK, "a MAC seeded at the last octet the field prints");
    got = LoopbackRadio_Sent(&dev.model, sent, 4);
    index = sentIndexFor(sent, got, 0x1234, 0xff);
    Test_Expect(index < got, "its first frame carries 0xff");

    Test_ExpectStatus(Mac_Step(&dev.mac, 111), ZB_OK, "answered");
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 112, 0), ZB_OK, "the next one");
    got = LoopbackRadio_Sent(&dev.model, sent, 4);
    index = sentIndexFor(sent, got, 0x1234, 0x00);
    Test_Expect(index < got,
           "wraps to 0 exactly where an unseeded MAC does, because seeding a counter is not the same act as moving its bound");
}

void caseComposition(void)
{
    Test_BandA dev;
    Loopback_Sent sent[8];
    Mac_DataRequestParameters req;
    uint16_t fcf;
    uint32_t got;
    uint32_t i;

    rig(&dev, 0xdead, 0xbeef);

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0xbeef, 0x1234, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 10, 0), ZB_OK, "a unicast data request");

    got = LoopbackRadio_Sent(&dev.model, sent, 8);
    Test_Expect(got == 1, "one transmit reached the backend");
    Test_Expect(sent[0].ackRequest == 1, "with the acknowledgment request recorded beside it");

    /* 9 octets of MHR + 8 payload + 2 footer = 19, the length the rig measured on air. */
    Test_Expect(sent[0].len == 19, "19 octets out");
    Test_Expect(MacFrame_CheckFcs(sent[0].bytes, sent[0].len) == ZB_OK,
           "and the footer band A appended is the footer those octets compute");

    fcf = (uint16_t)(sent[0].bytes[0] | (sent[0].bytes[1] << 8));
    Test_Expect(fcf == AIR_UNICAST_FCF,
           "the FCF this module composed is the FCF this PAN's acknowledged data frames carry (0x8861)");
    Test_Expect(sent[0].bytes[2] == 0x00, "the first frame carries DSN 0");
    Test_Expect(sent[0].bytes[3] == 0xef && sent[0].bytes[4] == 0xbe, "destination PAN least significant octet first");
    Test_Expect(sent[0].bytes[5] == 0x34 && sent[0].bytes[6] == 0x12, "destination address likewise");
    Test_Expect(sent[0].bytes[7] == 0xad && sent[0].bytes[8] == 0xde,
           "and the source address is the PIB's own, not something the caller supplied");
    Test_Expect(Zb_memcmp(sent[0].bytes + 9, payload, 8) == 0, "then the payload, untouched");

    /* One PAN field, because this device's PAN is the destination's: the compression every captured frame
       on this PAN uses. */
    Test_Expect((fcf & (1 << 6)) != 0, "PAN compression set when the source PAN is the destination PAN");

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0x0042, 0x1234, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 20, 0), ZB_OK, "a frame to another PAN");
    got = LoopbackRadio_Sent(&dev.model, sent, 8);
    Test_Expect(got == 2, "second transmit");
    fcf = (uint16_t)(sent[1].bytes[0] | (sent[1].bytes[1] << 8));
    Test_Expect((fcf & (1 << 6)) == 0, "no compression available");
    Test_Expect(sent[1].len == 21, "so the frame carries both PAN fields: 11 octets of header, 10 more bytes, 2 footer");
    Test_Expect(sent[1].bytes[2] == 0x01, "and the DSN incremented for the frame, not for an answer");

    req = dataReq(MAC_FRAME_TYPE_COMMAND, MAC_ADDR_SHORT, 0xbeef, 0x0000, MAC_ADDR_SHORT, 1);
    req.payload = 0;
    req.payloadLen = 1;
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 30, 0), ZB_ERR_BAD_ARGUMENT,
                 "a payload length without a payload is refused before it becomes a short frame");

    req = dataReq(MAC_FRAME_TYPE_COMMAND, MAC_ADDR_SHORT, 0xbeef, 0x0000, MAC_ADDR_SHORT, 1);
    req.payload = (const uint8_t[]){ 0x04 };
    req.payloadLen = 1;
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 40, 0), ZB_OK, "a poll: command 0x04 to the coordinator");
    got = LoopbackRadio_Sent(&dev.model, sent, 8);
    Test_Expect(got == 3, "three transmits to read");
    Test_Expect(sent[2].len == 12,
           "twelve octets, which is exactly how long a poll is on this PAN (docs/internals/protocol.md §9.2)");
    fcf = (uint16_t)(sent[2].bytes[0] | (sent[2].bytes[1] << 8));
    Test_Expect(fcf == AIR_POLL_FCF, "and its FCF is the captured poll's 0x8863");
    Test_Expect(sent[2].bytes[9] == 0x04, "one octet of payload: the command identifier, and its Content field is empty");

    /* 10.22.4.1 sets the pinned fields rather than honouring a request for them, so a poll
       asked with every one of them contradicted is composed as the pinned frame anyway. The only octet
       that may differ from the poll above is the sequence number, because a second frame carries a second
       DSN (7.2.3), and a footer is computed over that octet, so the two frames' footers differ too. */
    req = dataReq(MAC_FRAME_TYPE_COMMAND, MAC_ADDR_SHORT, 0x1234, 0x0000, MAC_ADDR_SHORT, 0);
    req.framePending = 1;
    req.payload = (const uint8_t[]){ 0x04 };
    req.payloadLen = 1;
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 50, 0), ZB_OK,
                 "a poll whose request contradicts all three pins is accepted: a pinned field is not a validity check");

    got = LoopbackRadio_Sent(&dev.model, sent, 8);
    Test_Expect(got == 4, "four transmits to read");
    Test_Expect(sent[3].len == 12,
           "the same twelve octets: a destination PAN that is not this device's does not buy a second PAN field (10.22.4.1)");
    Test_Expect(MacFrame_CheckFcs(sent[3].bytes, sent[3].len) == ZB_OK,
           "and the footer those octets compute, which cannot be the pinned poll's because its DSN is not");
    Test_Expect(sent[3].bytes[2] == 0x03, "its own DSN, incremented for the frame (7.2.3)");

    fcf = (uint16_t)(sent[3].bytes[0] | (sent[3].bytes[1] << 8));
    Test_Expect(fcf == AIR_POLL_FCF,
           "the same FCF, 0x8863, composed against a request that asked for Frame Pending and no acknowledgment");
    Test_Expect((fcf & FCF_FRAME_PENDING_BIT) == 0,
           "Frame Pending zero: 10.22.4.1, 'shall be set to zero and ignored upon reception'");
    Test_Expect((fcf & FCF_ACK_REQUEST_BIT) != 0, "AR one: 10.22.4.1, 'the AR field shall be set to one'");
    Test_Expect((fcf & FCF_PAN_COMPRESSION_BIT) != 0,
           "one PAN field, because the Source PAN ID field is omitted and the Destination PAN ID is macPanId (10.22.4.1)");
    Test_Expect(sent[3].bytes[3] == 0xef && sent[3].bytes[4] == 0xbe,
           "the Destination PAN on air is this device's own 0xbeef, not the caller's 0x1234");
    Test_Expect(sent[3].bytes[5] == 0x00 && sent[3].bytes[6] == 0x00,
           "while the destination address stays the caller's, 10.22.4.1: 'the destination addressing information shall be the same as that contained in the primitive'");
    Test_Expect(sent[3].bytes[7] == 0xad && sent[3].bytes[8] == 0xde,
           "and the source is still this device's own short address, which is what a poll sets its Source Addressing Mode from (10.22.4.1)");
    Test_Expect(sent[3].bytes[9] == 0x04, "the same command identifier, with a zero-length Content field (10.22.4.1)");
    Test_Expect(Zb_memcmp(sent[3].bytes + 3, sent[2].bytes + 3, 7) == 0,
           "both PAN octets, both addresses and the command identifier byte-identical to the poll asked straight out");

    /* The pin is not only an octet of the FCF. 10.22.4.1 sets the AR field and it is pinned here, so
       the one value binds the air, the seam and the track slot, and it is precisely the request that
       contradicted the pin that shows the radio is not being handed the caller's flag. Searched for by
       handle rather than indexed: which slot band A took is its own business, the ask written into it is
       what is being read. */
    Test_Expect(sent[3].ackRequest == 1,
           "the seam was told this poll asks for an acknowledgment, although the request refused one");
    Test_Expect(sent[2].ackRequest == 1, "and the same for the poll asked straight out: one value for both");

    for (i = 0; i < MAC_TX_TRACK_MAX; i++)
    {
        if (dev.mac.tx.track[i].handle == sent[3].handle)
            break;
    }

    Test_Expect(i < MAC_TX_TRACK_MAX && dev.mac.tx.track[i].ackRequest == 1,
           "and the track slot of that frame records the same ask, so air, seam and track agree");

    /* The pins are a command frame's rule and no other's: 7.2.2.4 makes Frame Pending the sending device's
       own statement about what it still has to send, and a data frame's destination PAN is the caller's
       destination, so the same three contradictions asked of a data frame are answered on the wire. */
    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0x1234, 0x1234, MAC_ADDR_SHORT, 0);
    req.framePending = 1;
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 60, 0), ZB_OK, "a data request asked with the same contradictions");

    got = LoopbackRadio_Sent(&dev.model, sent, 8);
    Test_Expect(got == 5, "five transmits to read");
    fcf = (uint16_t)(sent[4].bytes[0] | (sent[4].bytes[1] << 8));
    Test_Expect(fcf == DATA_PENDING_FCF, "and the FCF that frame describes, 0x8811: nothing about it is pinned");
    Test_Expect((fcf & FCF_FRAME_PENDING_BIT) != 0,
           "Frame Pending passed through: 10.22.4.1 pins a Data Request command, not a data frame (7.2.2.4)");
    Test_Expect((fcf & FCF_ACK_REQUEST_BIT) == 0, "the caller's refusal of an acknowledgment passed through (7.2.2.5)");
    Test_Expect(sent[4].ackRequest == 0,
           "and the refusal the radio was given is the caller's too: the pinned ask is a command frame's rule");
    Test_Expect((fcf & FCF_PAN_COMPRESSION_BIT) == 0,
           "and no compression, because the caller's PAN is not this device's (7.2.2.6)");
    Test_Expect(sent[4].bytes[3] == 0x34 && sent[4].bytes[4] == 0x12, "the Destination PAN on air is the caller's 0x1234");
    Test_Expect(sent[4].bytes[7] == 0xef && sent[4].bytes[8] == 0xbe,
           "with a second PAN field carrying this device's own, which is what an uncompressed frame must say");
    Test_Expect(sent[4].len == 21, "21 octets: 11 of header with both PAN fields, 8 of payload, 2 of footer");
}

void caseAcknowledgementPolicy(void)
{
    Test_BandA dev;
    Loopback_Sent sent[4];
    Mac_DataRequestParameters req;
    Mac_Counters counters;
    uint16_t fcf;
    Mac_Frame frame;
    const uint8_t *payloadOut;
    uint32_t payloadOutLen = 0;

    rig(&dev, 0xdead, 0xbeef);

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0xbeef, MAC_FRAME_ADDR_BROADCAST, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 0, 0), ZB_OK,
                 "a broadcast the caller asks an acknowledgment for is still sent: 6.6.3.1 sets its AR to no acknowledgment, it does not forbid the frame");
    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.ackAskCleared == 1, "and the cleared ask is counted apart from a refusal");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 4) == 1, "the frame went out");
    Test_Expect(sent[0].ackRequest == 0, "asking nothing, which is what the clause requires of a broadcast");
    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &frame, &payloadOut, &payloadOutLen, 0), ZB_OK,
                      "and the frame on the air is the one the seam was told about");
    Test_Expect(frame.ackRequest == 0,
                "its Frame Control bit clear: the benchmark read an AR on the wire from a frame whose seam ask was 0");

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, MAC_FRAME_PAN_BROADCAST, 0x1234, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 0, 0), ZB_OK,
                 "while a unicast to the broadcast PAN identifier goes out asking: 7.2.4 makes that PAN a valid one, and 6.6.3.1 forbids the ask only of a broadcast or group address");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 4) == 2, "and it went out beside the broadcast");
    Test_Expect(sent[1].ackRequest == 1, "with the acknowledgment request it asked for");

    /* The rule reads the request's effective ask, and a command's ask is pinned rather than declined
       (10.22.4.1), so a poll is cleared at a destination that cannot answer it just as a data frame is. */
    req = dataReq(MAC_FRAME_TYPE_COMMAND, MAC_ADDR_SHORT, 0xbeef, MAC_FRAME_ADDR_BROADCAST, MAC_ADDR_SHORT, 0);
    req.payload = (const uint8_t[]){ 0x04 };
    req.payloadLen = 1;
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 0, 0), ZB_OK,
                 "a poll at the broadcast address goes out asking nothing: 6.6.3.1's ask is the destination's");

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0xbeef, MAC_FRAME_ADDR_BROADCAST, MAC_ADDR_SHORT, 0);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 0, 0), ZB_OK, "the broadcast this stack does send asks for nothing");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 4) == 4, "and all of them went out");
    fcf = (uint16_t)(sent[3].bytes[0] | (sent[3].bytes[1] << 8));
    Test_Expect(fcf == AIR_BROADCAST_FCF, "with the FCF every captured broadcast on this PAN carries: 0x8841");

    /* 6.6.2 d)4: a frame with no destination fields is addressed to the PAN coordinator, which answers, so an
       acknowledgment is not impossible there: 10.22.4.1's own Data Request may have no destination at all. */
    rig(&dev, 0xdead, 0xbeef);
    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_NONE, 0xbeef, 0, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 0, 0), ZB_OK,
                      "while a frame with no destination fields may ask: its recipient is the PAN coordinator");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 4) == 1, "and it goes out");
    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &frame, &payloadOut, &payloadOutLen, 0), ZB_OK,
                      "it parses");
    Test_Expect(frame.destAddrMode == MAC_ADDR_NONE && frame.srcPan == 0xbeef && frame.ackRequest == 1,
                "with no destination fields, its source PAN this device's own (10.22.4.1), and the ask set");

    req = dataReq(MAC_FRAME_TYPE_BEACON, MAC_ADDR_NONE, 0xbeef, 0, MAC_ADDR_SHORT, 0);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 0, 0), ZB_ERR_UNSUPPORTED,
                  "a beacon is not composed, because no beacon is in the captured set and its shape here is unmeasured");

    /* 6.6.3.1: "any frame that is broadcast or has a group address as the extended destination address ... shall
       be sent with its AR field set to indicate no acknowledgment requested". An IEEE 802 group address carries
       the I/G bit, the low bit of the first octet transmitted, which is the low bit of the 64-bit value. */
    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_EXTENDED, 0xbeef, 0, MAC_ADDR_SHORT, 1);
    req.destExtended = 0x0000000000000001;
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 0, 0), ZB_OK,
                      "an acknowledgment asked of a group address is cleared and the frame sent, 6.6.3.1 setting its AR");

    req.destExtended = 0x0000000000000002;
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 0, 0), ZB_OK,
                      "while the same request to a unicast extended address, its I/G bit clear, is sent");
}

/* 6.6.3.4's retransmission budget travels with each direct frame that asks for an acknowledgment: Table 8-36's
   default of 3 until macMaxFrameRetries is set, the set value after, and nothing for a frame that asks for none. */
void caseDirectFrameCarriesItsRetries(void)
{
    Test_BandA dev;
    Loopback_Sent sent[4];
    Mac_DataRequestParameters req;
    Radio_Pib pib;

    rig(&dev, 0xdead, 0xbeef);

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0xbeef, 0x1234, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 0, 0), ZB_OK, "an acknowledged unicast");
    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0xbeef, MAC_FRAME_ADDR_BROADCAST, MAC_ADDR_SHORT, 0);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 0, 0), ZB_OK, "and a broadcast");

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_MAX_FRAME_RETRIES;
    pib.maxFrameRetries = 5;
    Test_ExpectStatus(Mac_SetPib(&dev.mac, &pib), ZB_OK, "macMaxFrameRetries set to 5");
    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, 0xbeef, 0x1234, MAC_ADDR_SHORT, 1);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 0, 0), ZB_OK, "another acknowledged unicast");

    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, 4), 3, "three transmits");
    Test_ExpectCount(sent[0].maxFrameRetries, MAC_MAX_FRAME_RETRIES_DEFAULT,
                     "the unicast carries Table 8-36's default of three retries");
    Test_ExpectCount(sent[1].maxFrameRetries, 0, "the broadcast none, since no acknowledgment can fail it");
    Test_ExpectCount(sent[2].maxFrameRetries, 5, "and the next unicast the value the PIB was given");

    pib.maxFrameRetries = RADIO_MAX_FRAME_RETRIES + 1;
    Test_ExpectStatus(Mac_SetPib(&dev.mac, &pib), ZB_ERR_BAD_ARGUMENT, "8 is outside Table 8-36's range of 0 to 7");
}
