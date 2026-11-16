/* The `mac` suite's beacon surface: 7.5.2's Beacon Request and the answer R23.1 3.6.5 and D.11.1.5 owe it,
   the reply's shape on the wire, the PAN's own statement inside it, the devices the queue holds stated as
   pending, and the requests this device is not the one to answer. */

#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "mac_helpers.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

/* 7.5.2's Beacon Request exactly: Frame Control 0x0803 (command type, short destination, no source address,
   no acknowledgment asked) destination PAN 0xffff, destination address 0xffff, Content 0x07. Ten octets with
   its footer. */
static uint32_t composeBeaconRequest(uint8_t *out, uint8_t seq, uint16_t destPan, uint16_t destShort)
{
    Mac_Frame frame;
    static const uint8_t content[1] = { MAC_CMD_BEACON_REQUEST };
    uint32_t len;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 0;
    frame.panIdCompression = 0;      /* 7.2.2.6: one address present, so the single PAN field is kept */
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_NONE;
    frame.destPan = destPan;
    frame.destShort = destShort;
    frame.seq = seq;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, (uint32_t)sizeof content, out, RADIO_MPDU_MAX, &len),
                      ZB_OK, "a Beacon Request composes as 7.5.2 lays it out");
    Test_ExpectStatus(MacFrame_AppendFcs(out, len, RADIO_MPDU_MAX, &len), ZB_OK,
                      "with the footer those octets compute (7.2.11)");

    return len;
}

/* The beacon payload a Zigbee network layer writes into macBeaconPayload: R23.1 Table 3-83's fifteen octets,
   in Figure 3-53's bit order, protocol 0, stack profile 0x2, protocol version 0x2, then the four single bits,
   the extended PAN identifier, the TxOffset and the update id. */
static const uint8_t zigbeeBeaconInfo[15] =
{
    0x00, 0x22, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xff, 0xff, 0x00
};

static void beaconOn(Test_BandA *dev)
{
    Mac_BeaconConfig config;

    Zb_memset(&config, 0, (uint32_t)sizeof config);
    config.answer = 1;
    config.panCoordinator = 1;
    config.associationPermit = 1;
    config.payload = zigbeeBeaconInfo;
    config.payloadLen = (uint32_t)sizeof zigbeeBeaconInfo;

    Test_ExpectStatus(Mac_SetBeaconConfig(&dev->mac, &config), ZB_OK, "the beacon is configured");
}

/* A beacon request answered, and the answer read down to its octets: the PAN's statement, the requester's
   own number left alone, and nothing asked of the air in return. */
void caseBeaconRequestIsAnswered(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_Frame header;
    MacFrame_Beacon beacon;
    Mac_DataConfirmParameters confirm;
    const uint8_t *payloadOut;
    uint32_t payloadOutLen = 0;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint8_t mpdu[RADIO_MPDU_MAX];
    uint16_t fcf;
    uint32_t len;
    uint32_t got;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    beaconOn(&dev);

    len = composeBeaconRequest(bytes, 0x41, MAC_FRAME_PAN_BROADCAST, MAC_FRAME_ADDR_BROADCAST);
    Test_Expect(len == 10, "a Beacon Request is ten octets with its footer");

    injectFrame(&dev.model, bytes, len, 7000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 100), ZB_OK, "one step takes the request and answers it");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.beaconRequestsHeard == 1, "the request is counted where it was read");
    Test_Expect(counters.beaconReplies == 1, "and the answer is counted where it left");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1, "exactly one frame went to the backend");

    Test_ExpectStatus(MacFrame_CheckFcs(sent[0].bytes, sent[0].len), ZB_OK,
                      "and it is closed by the footer its own octets compute (7.2.11)");
    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &header, &payloadOut, &payloadOutLen, 0),
                      ZB_OK, "the beacon parses as the frame it claims to be");
    Test_Expect(header.frameType == MAC_FRAME_TYPE_BEACON && header.srcShort == COORDINATOR_SHORT
                && header.srcPan == PAN_ID,
                "a beacon from this device's own address and PAN (7.3.1.2)");
    Zb_memcpy(mpdu, sent[0].bytes, sent[0].len);
    fcf = fcfOf(&sent[0]);

    Test_Expect(sent[0].len == 7 + 19 + 2, "seven octets of MHR (7.3.1.2: no destination fields), nineteen of payload, two of footer");
    Test_Expect((fcf & 0x07) == 0, "Frame Type zero: a beacon (Table 7-1)");
    Test_Expect((fcf & (1 << 5)) == 0, "the acknowledgment request is clear: a beacon asks for nothing (7.3.1.2)");
    Test_Expect(((fcf >> 10) & 3) == 0, "and the destination addressing mode is zero: a beacon addresses from itself");
    Test_Expect(((fcf >> 14) & 3) == MAC_ADDR_SHORT, "with a short source address, this device's own");
    Test_Expect(sent[0].ackRequest == 0, "the seam was told to ask for no acknowledgment");
    Test_Expect(mpdu[2] == 0x00, "its sequence number is the BSN, seeded at zero here and not the DSN");

    Test_ExpectStatus(MacFrame_ParseBeaconPayload(payloadOut, payloadOutLen, &beacon, &payloadOut, &payloadOutLen),
                      ZB_OK, "and its MAC payload reads back");
    Test_Expect(beacon.beaconOrder == 15 && beacon.superframeOrder == 15, "macBeaconOrder and macSuperframeOrder 0x0F (R23.1 Annex D.7)");
    Test_Expect(beacon.finalCapSlot == 15 && beacon.batteryLifeExtension == 0, "Final CAP Slot 0x0F, no battery-life extension");
    Test_Expect(beacon.panCoordinator == 1 && beacon.associationPermit == 1, "this device says it is the PAN coordinator and is accepting association");
    Test_Expect(beacon.pendingShortCount == 0 && beacon.pendingExtendedCount == 0, "and that nothing is pending for anybody");
    Test_Expect(payloadOutLen == (uint32_t)sizeof zigbeeBeaconInfo
                && Zb_memcmp(payloadOut, zigbeeBeaconInfo, payloadOutLen) == 0,
                "the beacon payload is the octets the layer above wrote, unchanged");

    /* The reply is a transmit like any other, and its completion is not a confirmation this module owes the layer
       above: 8.3.5's MsduHandle is one a caller handed down, and a beacon's reply carries none. */
    Test_ExpectStatus(Mac_Step(&dev.mac, 120), ZB_OK, "a second step takes the completion");
    Test_ExpectCount(Mac_PollConfirms(&dev.mac, &confirm, 1), 0,
                     "and the layer above is owed no confirmation for a frame it did not ask for");
    Test_ExpectCount(Mac_CountersOf(&dev.mac).outstanding, 0, "the beacon's transmit is finished all the same");
}

/* The request side of 7.5.2, composed by a request of band A's own: the scanning device's frame, which is what a
   scan puts on the air. Its pins are the command's and not the caller's (AR zero although every other command
   frame this module composes asks for an acknowledgment, no Frame Pending bit, the broadcast PAN and the
   broadcast short address) and a broadcast destination is legal for it for exactly that reason (M2024 6.6.3.1's
   refusal is about an ask a broadcast cannot answer). */
void caseBeaconRequestComposes(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_DataRequestParameters req;
    Mac_Frame frame;
    const uint8_t *payloadOut;
    uint32_t payloadOutLen = 0;
    uint8_t content = MAC_CMD_BEACON_REQUEST;
    uint16_t fcf;
    uint32_t got;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    req = dataReq(MAC_FRAME_TYPE_COMMAND, MAC_ADDR_SHORT, MAC_FRAME_PAN_BROADCAST,
                  MAC_FRAME_ADDR_BROADCAST, MAC_ADDR_NONE, 1);
    req.payload = &content;
    req.payloadLen = 1;

    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 100, 0), ZB_OK,
                      "a Beacon Request to the broadcast PAN and address is accepted, though it asks for nothing");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1, "one frame went to the backend");
    Test_Expect(sent[0].len == 10, "ten octets: seven of MHR, the command identifier, two of footer");
    Test_Expect(sent[0].ackRequest == 0, "and the seam was told it asks for no acknowledgment");

    fcf = fcfOf(&sent[0]);
    Test_Expect(fcf == 0x0803,
                "Frame Control 0x0803: command type, short destination, no source address, AR clear (7.5.2)");

    Test_ExpectStatus(MacFrame_CheckFcs(sent[0].bytes, sent[0].len), ZB_OK, "with the footer those octets compute");
    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &frame, &payloadOut, &payloadOutLen, 0), ZB_OK,
                      "and it parses back");
    Test_Expect(frame.destPan == MAC_FRAME_PAN_BROADCAST && frame.destShort == MAC_FRAME_ADDR_BROADCAST,
                "addressed to the broadcast PAN and the broadcast short address, as 7.5.2 prints them");
    Test_Expect(payloadOutLen == 1 && payloadOut[0] == MAC_CMD_BEACON_REQUEST,
                "with one octet of payload and no Content field after it (7.5.2)");
}

/* The queue's own contents stated in the beacon: 7.3.1.6's pending address lists are exactly what tells a
   device to poll for what is waiting for it. */
void caseBeaconStatesThePendingDevices(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_Frame header;
    MacFrame_Beacon beacon;
    Mac_DataRequestParameters req;
    const uint8_t *payloadOut;
    uint32_t payloadOutLen = 0;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint8_t queued[2] = { 0xa1, 0x11 };
    uint32_t len;
    uint32_t got;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    beaconOn(&dev);

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, queued, (uint32_t)sizeof queued);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK, "a transaction is queued for a sleepy device");

    len = composeBeaconRequest(bytes, 0x42, MAC_FRAME_PAN_BROADCAST, MAC_FRAME_ADDR_BROADCAST);
    injectFrame(&dev.model, bytes, len, 7100);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "a beacon request is answered");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1, "one frame: the beacon");

    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &header, &payloadOut, &payloadOutLen, 0), ZB_OK,
                      "the beacon parses");
    Test_ExpectStatus(MacFrame_ParseBeaconPayload(payloadOut, payloadOutLen, &beacon, &payloadOut, &payloadOutLen),
                      ZB_OK, "and its MAC payload reads back");
    Test_Expect(beacon.pendingShortCount == 1 && beacon.pendingShort[0] == SLEEPY_A,
                "and it names the device the transaction is held for (7.3.1.6)");
    Test_Expect(beacon.pendingExtendedCount == 0, "with no extended address pending");
    Test_Expect(payloadOutLen == (uint32_t)sizeof zigbeeBeaconInfo, "the beacon payload is still fifteen octets");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 1, "and nothing was delivered by the beacon: it is a statement, not a frame");
}

/* 7.3.1.6, the Address List: seven addresses at most across both forms, shorts first, first-come-first-served,
   one entry per device, and never the broadcast short address. */
void caseBeaconPendingListIsSevenAddresses(void)
{
    uint32_t waiting;
    uint32_t stated;
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_Frame header;
    MacFrame_Beacon beacon;
    Mac_DataRequestParameters req;
    const uint8_t *payloadOut;
    uint32_t payloadOutLen = 0;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint8_t queued[1] = { 0xa1 };
    uint32_t len;
    uint32_t i;
    Mac_BeaconNotification notified;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    beaconOn(&dev);

    /* Four devices with a short address, and a second transaction for the first of them. */
    for (i = 0; i < 4; i++)
    {
        req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, (uint16_t)(SLEEPY_A + i), queued, 1);
        Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100 + i), ZB_OK, "a short-addressed transaction");
    }

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, queued, 1);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 110), ZB_OK, "a second one for a device already listed");

    len = composeBeaconRequest(bytes, 0x50, MAC_FRAME_PAN_BROADCAST, MAC_FRAME_ADDR_BROADCAST);
    injectFrame(&dev.model, bytes, len, 7200);
    Test_ExpectStatus(Mac_Step(&dev.mac, 300), ZB_OK, "a beacon request is answered");

    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 1, "one beacon");
    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &header, &payloadOut, &payloadOutLen, 0), ZB_OK,
                      "it parses");
    Test_ExpectStatus(MacFrame_ParseBeaconPayload(payloadOut, payloadOutLen, &beacon, &payloadOut, &payloadOutLen),
                      ZB_OK, "and its body reads back");
    Test_Expect(beacon.pendingShortCount == 4,
                "the four short addresses are listed once each, the device with two transactions named once");
    Test_Expect(beacon.pendingShort[0] == SLEEPY_A && beacon.pendingShort[3] == (uint16_t)(SLEEPY_A + 3),
                "in the order the queue took them, which is first-come-first-served");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 5, "five transactions are held");

    /* The limit itself, on a device with nothing else queued: one device more than a beacon can state, or as many
       as the pool holds when it holds fewer. */
    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    beaconOn(&dev);
    waiting = MAC_TRANSACTION_MAX < MAC_FRAME_PENDING_MAX + 1 ? MAC_TRANSACTION_MAX : MAC_FRAME_PENDING_MAX + 1;
    stated = waiting < MAC_FRAME_PENDING_MAX ? waiting : MAC_FRAME_PENDING_MAX;

    for (i = 0; i < waiting; i++)
    {
        req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, (uint16_t)(SLEEPY_A + i), queued, 1);
        Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 300 + i), ZB_OK, "one device more than a beacon states");
    }

    len = composeBeaconRequest(bytes, 0x51, MAC_FRAME_PAN_BROADCAST, MAC_FRAME_ADDR_BROADCAST);
    injectFrame(&dev.model, bytes, len, 7300);
    Test_ExpectStatus(Mac_Step(&dev.mac, 400), ZB_OK, "a request is answered");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 1, "one beacon");
    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &header, &payloadOut, &payloadOutLen, 0), ZB_OK,
                      "which parses");
    Test_ExpectStatus(MacFrame_ParseBeaconPayload(payloadOut, payloadOutLen, &beacon, &payloadOut, &payloadOutLen),
                      ZB_OK, "and its body reads back");
    Test_ExpectCount(beacon.pendingShortCount, stated,
                     "seven addresses, which 7.3.1.6 makes the most a beacon can state");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.beaconPendingDropped, waiting - stated,
                     "and the eighth counted where the list was cut rather than silently dropped");

    /* The other form of 7.3.1.6's list, as the receiving side sees it: an extended address is what the event's own
       copy has to carry, since 10.22.3 reads the list and Table 8-3 states none of it. */
    {
        Mac_Frame beaconFrame;
        MacFrame_Beacon heard;
        uint8_t heardPayload[1] = { 0x5a };
        uint8_t body[32];
        uint8_t air[RADIO_MPDU_MAX];
        uint32_t bodyLen = 0;
        uint32_t airLen = 0;

        Zb_memset(&heard, 0, (uint32_t)sizeof heard);
        heard.beaconOrder = MAC_FRAME_BEACON_ORDER_NONE;
        heard.superframeOrder = MAC_FRAME_BEACON_ORDER_NONE;
        heard.finalCapSlot = MAC_FRAME_BEACON_ORDER_NONE;
        heard.pendingExtendedCount = 1;
        heard.pendingExtended[0] = 0x00124a000b2c0180;

        Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&heard, heardPayload, 1, body, (uint32_t)sizeof body,
                                                        &bodyLen),
                          ZB_OK, "a beacon body with one extended pending address");

        Zb_memset(&beaconFrame, 0, (uint32_t)sizeof beaconFrame);
        beaconFrame.frameType = MAC_FRAME_TYPE_BEACON;
        beaconFrame.destAddrMode = MAC_ADDR_NONE;
        beaconFrame.srcAddrMode = MAC_ADDR_SHORT;
        beaconFrame.srcPan = PAN_ID;
        beaconFrame.srcShort = SLEEPY_B;
        beaconFrame.seq = 0x53;

        Test_ExpectStatus(MacFrame_Compose(&beaconFrame, body, bodyLen, air, (uint32_t)sizeof air, &airLen), ZB_OK,
                          "and the beacon that carries it composes");
        Test_ExpectStatus(MacFrame_AppendFcs(air, airLen, (uint32_t)sizeof air, &airLen), ZB_OK, "closed");

        injectFrame(&dev.model, air, airLen, 7500);
        Test_ExpectStatus(Mac_Step(&dev.mac, 700), ZB_OK, "it arrives at this device");
        Test_ExpectCount(Mac_PollBeacons(&dev.mac, &notified, 1), 1, "as one beacon event");
        Test_Expect(notified.pendingExtendedCount == 1 && notified.pendingExtended[0] == 0x00124a000b2c0180
                    && notified.pendingShortCount == 0,
                    "carrying the extended address the beacon stated");
    }
}

/* 10.19: "If a coordinator of a PAN not using superframe structure receives this command, it shall transmit a
   single Beacon frame using unslotted CSMA-CA." Every request in a batch gets its own beacon. */
void caseBeaconOneAnswerPerRequest(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_Frame header;
    Mac_Frame secondHeader;
    const uint8_t *payloadOut;
    uint32_t payloadOutLen = 0;
    uint8_t first[RADIO_MPDU_MAX];
    uint8_t second[RADIO_MPDU_MAX];
    Loopback_FrameSpec specs[2];
    uint32_t firstLen;
    uint32_t secondLen;
    uint32_t got;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    beaconOn(&dev);

    firstLen = composeBeaconRequest(first, 0x60, MAC_FRAME_PAN_BROADCAST, MAC_FRAME_ADDR_BROADCAST);
    secondLen = composeBeaconRequest(second, 0x61, MAC_FRAME_PAN_BROADCAST, MAC_FRAME_ADDR_BROADCAST);

    specs[0].len = firstLen;
    specs[0].bytes = first;
    specs[0].rssiDbm = -70;
    specs[0].lqi = 100;
    specs[0].stampTicks = 8000;
    specs[0].error = ZB_OK;
    specs[1] = specs[0];
    specs[1].len = secondLen;
    specs[1].bytes = second;
    specs[1].stampTicks = 8001;

    Test_ExpectStatus(LoopbackRadio_Inject(&dev.model, specs, 2), ZB_OK, "two Beacon Requests wait in one batch");
    Test_ExpectStatus(Mac_Step(&dev.mac, 400), ZB_OK, "one step takes them");

    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.beaconRequestsHeard, 2, "both are counted as heard");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_ExpectCount(got, 2, "and each is answered: two beacons on the air, not one");
    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &header, &payloadOut, &payloadOutLen, 0), ZB_OK,
                      "the first parses");
    Test_ExpectStatus(MacFrame_Parse(sent[1].bytes, sent[1].len, 1, &secondHeader, &payloadOut, &payloadOutLen, 0),
                      ZB_OK, "and the second");
    Test_Expect((uint8_t)(header.seq + 1) == secondHeader.seq,
                "with successive BSNs: 7.3.1.2's Sequence Number is macBsn and each beacon takes the next value");
    Test_ExpectCount(counters.beaconReplies, 2, "two replies are counted");
}

/* 8.2.4.3 issues the primitive "when either macAutoRequest is set to FALSE or when the Beacon frame contains one or
   more octets of payload", and macNotifyAllBeacons, which would widen it, defaults to FALSE. A beacon with no
   payload is read and not indicated, and 10.22.3's reaction still runs on what its Address List said. */
void caseBeaconWithoutPayloadIsNotIndicated(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_BeaconNotification notified;
    Mac_Frame frame;
    MacFrame_Beacon beacon;
    uint8_t body[32];
    uint8_t air[RADIO_MPDU_MAX];
    uint32_t bodyLen = 0;
    uint32_t airLen = 0;
    Mac_Counters counters;

    rig(&dev, SLEEPY_A, PAN_ID);

    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.beaconOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.superframeOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.finalCapSlot = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.panCoordinator = 1;
    beacon.associationPermit = 1;
    beacon.pendingShortCount = 1;
    beacon.pendingShort[0] = SLEEPY_A;

    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, 0, 0, body, (uint32_t)sizeof body, &bodyLen), ZB_OK,
                      "a beacon with no payload at all, naming this device");

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_BEACON;
    frame.destAddrMode = MAC_ADDR_NONE;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.srcPan = PAN_ID;
    frame.srcShort = COORDINATOR_SHORT;
    frame.seq = 0x70;

    Test_ExpectStatus(MacFrame_Compose(&frame, body, bodyLen, air, (uint32_t)sizeof air, &airLen), ZB_OK, "composes");
    Test_ExpectStatus(MacFrame_AppendFcs(air, airLen, (uint32_t)sizeof air, &airLen), ZB_OK, "closed");

    injectFrame(&dev.model, air, airLen, 9500);
    Test_ExpectStatus(Mac_Step(&dev.mac, 9500), ZB_OK, "it arrives");

    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.beaconsNotified, 0, "and no primitive is owed for it");
    Test_ExpectCount(counters.beaconsNoPayload, 1, "counted where the condition was read");
    Test_ExpectCount(Mac_PollBeacons(&dev.mac, &notified, 1), 0, "so the ring stays empty");
    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1), 1,
                     "while 10.22.3's reaction still runs: the Address List named this device, payload or no payload");
}

/* 10.22.3: "If the address of the device is contained in the Address List field of the Beacon frame and
   macAutoRequest is TRUE, the MLME of the device shall send a Data Request command". 10.22.4.1 gives that request
   its shape: the destination the beacon's own source, omitted where the beacon names the PAN coordinator. */
void caseBeaconNamingThisDeviceMakesItPoll(void)
{
    Test_BandA dev;
    uint8_t heardPayload[1] = { 0x5a };
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_Frame frame;
    Mac_Frame beaconFrame;
    MacFrame_Beacon beacon;
    const uint8_t *payloadOut;
    uint32_t payloadOutLen = 0;
    uint8_t body[32];
    uint8_t air[RADIO_MPDU_MAX];
    uint32_t bodyLen = 0;
    uint32_t airLen = 0;
    uint32_t got;
    Mac_Counters counters;

    rig(&dev, SLEEPY_A, PAN_ID);

    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.beaconOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.superframeOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.finalCapSlot = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.panCoordinator = 1;
    beacon.associationPermit = 1;
    beacon.pendingShortCount = 1;
    beacon.pendingShort[0] = SLEEPY_B;

    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, heardPayload, 1, body, (uint32_t)sizeof body, &bodyLen),
                      ZB_OK, "a beacon that names another device");

    Zb_memset(&beaconFrame, 0, (uint32_t)sizeof beaconFrame);
    beaconFrame.frameType = MAC_FRAME_TYPE_BEACON;
    beaconFrame.destAddrMode = MAC_ADDR_NONE;
    beaconFrame.srcAddrMode = MAC_ADDR_SHORT;
    beaconFrame.srcPan = PAN_ID;
    beaconFrame.srcShort = COORDINATOR_SHORT;
    beaconFrame.seq = 0x60;

    Test_ExpectStatus(MacFrame_Compose(&beaconFrame, body, bodyLen, air, (uint32_t)sizeof air, &airLen), ZB_OK,
                      "composes");
    Test_ExpectStatus(MacFrame_AppendFcs(air, airLen, (uint32_t)sizeof air, &airLen), ZB_OK, "closed");

    injectFrame(&dev.model, air, airLen, 9000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 9000), ZB_OK, "it arrives");
    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1), 0,
                     "and this device polls for nothing: the list does not name it");

    /* The same beacon, naming this device. */
    beacon.pendingShort[0] = SLEEPY_A;
    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, heardPayload, 1, body, (uint32_t)sizeof body, &bodyLen),
                      ZB_OK, "a beacon that names this device");
    Test_ExpectStatus(MacFrame_Compose(&beaconFrame, body, bodyLen, air, (uint32_t)sizeof air, &airLen), ZB_OK,
                      "composes");
    Test_ExpectStatus(MacFrame_AppendFcs(air, airLen, (uint32_t)sizeof air, &airLen), ZB_OK, "closed");

    injectFrame(&dev.model, air, airLen, 9100);
    Test_ExpectStatus(Mac_Step(&dev.mac, 9100), ZB_OK, "it arrives");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_ExpectCount(got, 1, "and one frame goes out: the Data Request 10.22.3 owes");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.beaconRequestsHeard, 0, "the beacon was a beacon and not a request");

    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &frame, &payloadOut, &payloadOutLen, 0), ZB_OK,
                      "the poll parses");
    Test_Expect(frame.frameType == MAC_FRAME_TYPE_COMMAND && payloadOutLen == 1 && payloadOut[0] == MAC_CMD_POLL,
                "as Table 7-11's 0x04 with 10.22.4.1's zero-length Content");
    Test_Expect(frame.ackRequest == 1 && !frame.framePending,
                "with the acknowledgment asked and Frame Pending zero, both of which 10.22.4.1 pins");
    Test_Expect(frame.destAddrMode == MAC_ADDR_SHORT && frame.destShort == COORDINATOR_SHORT
                && frame.destPan == PAN_ID,
                "addressed to the coordinator the beacon came from, which R23.1 Annex D.4 prints as the preferred row");
    Test_Expect(frame.srcAddrMode == MAC_ADDR_SHORT && frame.srcShort == SLEEPY_A,
                "this device's own short address as the source (Table 10-101)");

    /* The ring is drained here so the third beacon's own event is kept, and the reaction is not read through a
       full ring: 10.22.3's poll is the receive path's, and the ring's room decides only whether the event is
       still there to read afterwards. */
    Mac_BeaconNotification drained[2];
    Test_ExpectCount(Mac_PollBeacons(&dev.mac, drained, 2), 2, "the two events are taken");

    /* A coordinator that is not the PAN coordinator is polled by its address, not by omission. */
    beacon.panCoordinator = 0;
    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, heardPayload, 1, body, (uint32_t)sizeof body, &bodyLen),
                      ZB_OK, "a beacon from a router, naming this device");
    Test_ExpectStatus(MacFrame_Compose(&beaconFrame, body, bodyLen, air, (uint32_t)sizeof air, &airLen), ZB_OK,
                      "composes");
    Test_ExpectStatus(MacFrame_AppendFcs(air, airLen, (uint32_t)sizeof air, &airLen), ZB_OK, "closed");

    injectFrame(&dev.model, air, airLen, 9200);
    Test_ExpectStatus(Mac_Step(&dev.mac, 9200), ZB_OK, "it arrives");
    /* The first poll's completion is collected on this step, and a collected frame leaves `Sent`'s list, so what is
       read here is the router's poll alone. */
    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1), 1, "and it polls that router");
    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &frame, &payloadOut, &payloadOutLen, 0), ZB_OK,
                      "the second poll parses");
    Test_Expect(frame.frameType == MAC_FRAME_TYPE_COMMAND && payloadOutLen == 1 && payloadOut[0] == MAC_CMD_POLL,
                "as the same command, with 10.22.4.1's zero-length Content");
    Test_Expect(frame.destAddrMode == MAC_ADDR_SHORT && frame.destShort == COORDINATOR_SHORT
                && frame.destPan == PAN_ID,
                "addressed to the coordinator the beacon came from, with its PAN (10.22.4.1)");
    Test_ExpectCount(dev.mac.beacon.pollIssued, 2, "the step issued both polls it owed");
}

/* What this device does not answer, and why each refusal is a different fact. */
void caseBeaconRequestsNotAnswered(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_BeaconConfig config;
    Radio_Pib pib;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t len;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    len = composeBeaconRequest(bytes, 0x43, MAC_FRAME_PAN_BROADCAST, MAC_FRAME_ADDR_BROADCAST);
    injectFrame(&dev.model, bytes, len, 7200);
    Test_ExpectStatus(Mac_Step(&dev.mac, 300), ZB_OK, "a request heard before any beacon was configured");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.beaconRequestsHeard == 1, "is counted as heard");
    Test_Expect(counters.beaconReplies == 0 && counters.beaconIgnored == 1,
                "and counted as ignored, because this device was given nothing to answer with");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 0, "nothing went on the air");


    /* A request that names another PAN is not this PAN's to answer, whatever this device has to say. */
    beaconOn(&dev);
    len = composeBeaconRequest(bytes, 0x44, 0x1234, MAC_FRAME_ADDR_BROADCAST);
    injectFrame(&dev.model, bytes, len, 7300);
    Test_ExpectStatus(Mac_Step(&dev.mac, 400), ZB_OK, "a request addressed to another PAN");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.beaconReplies == 0 && counters.beaconIgnored == 1,
                "is not answered (7.5.2 pins the broadcast PAN)");
    Test_Expect(counters.panMismatches == 1 && counters.beaconRequestsHeard == 1,
                "and is refused by 6.6.2 c) before any beacon branch reads it, so it is counted there and not here");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1) == 0, "and still nothing went on the air");

    /* A payload past the pool is refused where it is set, and the device keeps the beacon it had. */
    Zb_memset(&config, 0, (uint32_t)sizeof config);
    config.answer = 1;
    config.payload = zigbeeBeaconInfo;
    config.payloadLen = MAC_BEACON_PAYLOAD_MAX + 1;
    Test_ExpectStatus(Mac_SetBeaconConfig(&dev.mac, &config), ZB_ERR_NO_SPACE,
                      "a beacon payload longer than the pool is refused rather than truncated");

    /* 7.3.1.2 and 6.2: a beacon is sourced from this device's own address, so a device whose short address reads
       0xfffe and whose extended address is zero octets has no source to compose one from, and says so. */
    beaconOn(&dev);
    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_SHORT_ADDRESS | RADIO_PIB_EXTENDED_ADDRESS;
    pib.shortAddress = MAC_SHORT_ADDRESS_LAST_USABLE;
    Test_ExpectStatus(Mac_SetPib(&dev.mac, &pib), ZB_OK,
                      "the device is left with 0xfffe as its short address and no extended address at all");
    len = composeBeaconRequest(bytes, 0x45, MAC_FRAME_PAN_BROADCAST, MAC_FRAME_ADDR_BROADCAST);
    injectFrame(&dev.model, bytes, len, 7400);
    Test_ExpectStatus(Mac_Step(&dev.mac, 500), ZB_OK, "a beacon request arrives at it");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.beaconReplies == 0,
                "and no beacon goes out, because an all-zero extended address names no device");
    Test_ExpectCount(counters.beaconIgnored, 2, "counted as ignored, beside the request heard before any config");

    /* An answer the seam will not take is counted and is not a failed turn: the track pool can be held by
       confirmations nobody collected, which is this module's usual full-pool refusal. */
    Test_ExpectStatus(LoopbackRadio_Inject(&dev.model, 0, 0), ZB_ERR_BAD_ARGUMENT,
                      "the backend refuses an injection with nothing to inject");
}

/* A beacon from a device whose extended address is all zeros (a part that was given none) is not this device's
   own echo, even when this device has none either. The echo rule matches an address, and zero octets are not one;
   test/fixtures/conb2_beacon_reply.txt measured the opposite before the rule said so. */
void caseZeroSourceIsNotThisDevice(void)
{
    Test_BandA dev;
    Mac_BeaconNotification notified;
    Mac_Frame header;
    MacFrame_Beacon beacon;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint8_t body[32];
    uint32_t bodyLen = 0;
    uint32_t len = 0;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    /* The frame: a beacon sourced from eight zero octets, which is what an RCP that was never given an extended
       address puts on the air. */
    Zb_memset(&header, 0, (uint32_t)sizeof header);
    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.beaconOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.superframeOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.finalCapSlot = MAC_FRAME_BEACON_ORDER_NONE;

    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, zigbeeBeaconInfo, 15, body,
                                                    (uint32_t)sizeof body, &bodyLen), ZB_OK,
                      "a beacon body");

    header.frameType = MAC_FRAME_TYPE_BEACON;
    header.frameVersion = 0;
    header.destAddrMode = MAC_ADDR_NONE;
    header.srcAddrMode = MAC_ADDR_EXTENDED;   /* eight zero octets, the address this part does not have */
    header.srcPan = PAN_ID;
    header.seq = 0x09;

    Test_ExpectStatus(MacFrame_Compose(&header, body, bodyLen, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                      "composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, (uint32_t)sizeof bytes, &len), ZB_OK, "and closes");

    Zb_memset(&notified, 0, (uint32_t)sizeof notified);
    injectFrame(&dev.model, bytes, len, 7500);
    Test_ExpectStatus(Mac_Step(&dev.mac, 600), ZB_OK, "it is stepped");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.selfEchoes == 0,
                "a source of eight zero octets matches no address this device has, so it is no echo");
    Test_Expect(counters.indicationQueue == 0 && counters.beaconsNotified == 1,
                "8.2.4.3 makes it its own event: a notification, not an NPDU carrier");
    Test_Expect(Mac_PollBeacons(&dev.mac, &notified, 1) == 1 && notified.sn == 0x09
                && notified.coordPanId == PAN_ID && notified.coordAddrMode == MAC_ADDR_EXTENDED
                && notified.payloadLen == 15,
                "with Table 8-4's Sn, Table 8-3's coordinator and R23.1 3.6.8.2's payload");
}

/* A Beacon Request is consumed here and not handed up: it is this module's duty (7.5.2), not a carrier, and the
   indication queue never sees it. */
void caseBeaconRequestIsNotDelivered(void)
{
    Test_BandA dev;
    Mac_DataIndicationParameters indications[4];
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t len;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    beaconOn(&dev);

    len = composeBeaconRequest(bytes, 0x45, MAC_FRAME_PAN_BROADCAST, MAC_FRAME_ADDR_BROADCAST);
    injectFrame(&dev.model, bytes, len, 7400);
    Test_ExpectStatus(Mac_Step(&dev.mac, 500), ZB_OK, "a request is stepped");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.indicationQueue == 0, "nothing entered the queue the layer above reads");
    Test_Expect(Mac_PollIndications(&dev.mac, indications, 4) == 0, "and nothing was reported upward");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.commandsHeard == 0,
                "it is not a 'command heard': that counter is what this module has no duty for, and it has one here");
    Test_Expect(counters.beaconReplies == 1, "the answer is the whole of what the request produced");
}

/* 8.2.4.3's three refusals, each a form this stack does not read rather than one it misreads: a version-2
   beacon (7.3.1.1's Enhanced Beacon, whose body is IEs), a payload larger than the event carries (7.3.1.7), and
   a Beacon Request carrying content, which 7.5.2 says the command has not. */
void caseBeaconFormsRefused(void)
{
    Test_BandA dev;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint8_t body[64];
    uint8_t composed[160];
    Mac_Frame frame;
    MacFrame_Beacon beacon;
    Mac_Counters counters;
    uint32_t bodyLen = 0;
    uint32_t len = 0;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    /* a version-2 frame control carrying a classically shaped body, composed by hand because the writer refuses
       a version R23.1 Annex D.6 does not use */
    len = 0;
    bytes[len++] = 0x00;
    bytes[len++] = 0xa0;                    /* type 0, version 2, source short */
    bytes[len++] = 0x10;                    /* sequence number */
    bytes[len++] = (uint8_t)(PAN_ID & 0xff);
    bytes[len++] = (uint8_t)(PAN_ID >> 8);
    bytes[len++] = 0x34;
    bytes[len++] = 0x12;
    Zb_memset(bytes + len, 0, 4);            /* the classic body's first four octets, all zero */
    len += 4;
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK, "with its footer");
    injectFrame(&dev.model, bytes, len, 5000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 500), ZB_OK, "the step reads it");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.enhancedBeaconsUnbuilt == 1,
                "and refuses it as an Enhanced Beacon this stack does not read (7.3.1.1), counted by name");
    Test_Expect(counters.beaconsNotified == 0, "with no notification claiming fields it never read");

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    Zb_memset(body, 0xa5, (uint32_t)sizeof body);
    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.beaconOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.superframeOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.finalCapSlot = MAC_FRAME_BEACON_ORDER_NONE;
    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, body, MAC_BEACON_PAYLOAD_MAX + 8, composed,
                                                    (uint32_t)sizeof composed, &bodyLen), ZB_OK,
                      "a payload past the event's pool composes all the same");
    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_BEACON;
    frame.frameVersion = 0;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.srcPan = PAN_ID;
    frame.srcShort = 0x1234;
    frame.seq = 0x11;
    Test_ExpectStatus(MacFrame_Compose(&frame, composed, bodyLen, bytes, RADIO_MPDU_MAX, &len), ZB_OK,
                      "the beacon composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK, "with its footer");
    injectFrame(&dev.model, bytes, len, 6000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 600), ZB_OK, "the step reads it");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.beaconsPayloadOverflow == 1,
                "a payload past the pool is refused, not truncated into a shorter one a reader would trust");
    Test_Expect(counters.beaconsNotified == 0, "and nothing is indicated");

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    beaconOn(&dev);
    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 0;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_NONE;
    frame.destPan = MAC_FRAME_PAN_BROADCAST;
    frame.destShort = MAC_FRAME_ADDR_BROADCAST;
    frame.seq = 0x13;

    {
        static const uint8_t withContent[2] = { MAC_CMD_BEACON_REQUEST, 0x00 };

        Test_ExpectStatus(MacFrame_Compose(&frame, withContent, (uint32_t)sizeof withContent, bytes, RADIO_MPDU_MAX,
                                          &len), ZB_OK, "a request carrying an octet composes");
    }

    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK, "with a valid footer");
    injectFrame(&dev.model, bytes, len, 7000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 700), ZB_OK, "the step reads it");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.beaconRequestsHeard == 0, "and it is no Beacon Request: 7.5.2 gives the command no Content");
    Test_Expect(counters.beaconReplies == 0, "so no beacon answers it");
    Test_Expect(counters.commandsHeard == 1, "while the frame is still counted as a command that was heard");
}

/* 10.22.4.1: "If the Data Request command is being sent in response to the receipt of a Beacon frame indicating
   that data are pending for that device, the Source Addressing Mode field shall be set according to the addressing
   mode used for the pending address", and 10.22.3 owes that poll for a beacon whatever its payload carries. */
void caseBeaconPollTakesTheListedForm(void)
{
    Mac_Beacon beacon;
    Mac_BeaconNotification notification;
    Radio_Pib pib;
    Mac_AddrMode first;

    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    Zb_memset(&notification, 0, (uint32_t)sizeof notification);
    Zb_memset(&pib, 0, (uint32_t)sizeof pib);

    pib.present = RADIO_PIB_SHORT_ADDRESS | RADIO_PIB_EXTENDED_ADDRESS;
    pib.shortAddress = SLEEPY_A;

    /* The list names this device by its extended address only, so that is the form the poll must use. */
    notification.coordAddrMode = MAC_ADDR_SHORT;
    notification.coordShort = COORDINATOR_SHORT;
    notification.coordPanId = PAN_ID;
    notification.pendingExtendedCount = 1;
    notification.pendingExtended[0] = 0x00124a000b2c0180;

    MacBeacon_OwePoll(&beacon, &notification, &pib, 1, 0x00124a000b2c0180);
    Test_Expect(beacon.pollOwed == 1, "the extended address in the list owes a poll");
    Test_Expect(beacon.pollSrcMode == MAC_ADDR_EXTENDED,
                "and the poll carries the form the list used, not the short address this device also holds");

    /* The short form, the same device: the poll follows the list again. */
    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    notification.pendingExtendedCount = 0;
    notification.pendingShortCount = 1;
    notification.pendingShort[0] = SLEEPY_A;
    MacBeacon_OwePoll(&beacon, &notification, &pib, 1, 0x00124a000b2c0180);
    Test_Expect(beacon.pollOwed == 1 && beacon.pollSrcMode == MAC_ADDR_SHORT,
                "and the short form where the list gives the short address");

    /* A beacon that names nobody leaves a poll another beacon already owed where it was. */
    first = beacon.pollSrcMode;
    Zb_memset(&notification, 0, (uint32_t)sizeof notification);
    notification.coordAddrMode = MAC_ADDR_SHORT;
    notification.coordShort = SLEEPY_B;
    notification.coordPanId = PAN_ID;
    MacBeacon_OwePoll(&beacon, &notification, &pib, 1, 0x00124a000b2c0180);
    Test_Expect(beacon.pollOwed == 1, "the poll still owed stays owed");
    Test_Expect(beacon.pollCoordShort == COORDINATOR_SHORT && beacon.pollSrcMode == first,
                "and it is still addressed to the coordinator that owed it, not to a later beacon that names nobody");
}

/* 7.3.1.7 sets no length for the Beacon Payload, so a beacon this stack's pool cannot carry is a refused
   indication and still a beacon that owes 10.22.3's poll. */
void caseBeaconPollOwedDespitePayload(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_Frame beaconFrame;
    MacFrame_Beacon beacon;
    uint8_t big[MAC_BEACON_BODY_MAX];
    uint8_t air[RADIO_MPDU_MAX];
    uint32_t bodyLen = 0;
    uint32_t airLen = 0;
    Mac_Counters counters;

    rig(&dev, SLEEPY_A, PAN_ID);

    Zb_memset(big, 0x5a, (uint32_t)sizeof big);
    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.beaconOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.superframeOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.finalCapSlot = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.pendingShortCount = 1;
    beacon.pendingShort[0] = SLEEPY_A;
    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, big, MAC_BEACON_PAYLOAD_MAX + 8, big,
                                                    (uint32_t)sizeof big, &bodyLen), ZB_OK,
                      "a beacon naming this device and carrying more payload than the event's pool holds");

    Zb_memset(&beaconFrame, 0, (uint32_t)sizeof beaconFrame);
    beaconFrame.frameType = MAC_FRAME_TYPE_BEACON;
    beaconFrame.destAddrMode = MAC_ADDR_NONE;
    beaconFrame.srcAddrMode = MAC_ADDR_SHORT;
    beaconFrame.srcPan = PAN_ID;
    beaconFrame.srcShort = COORDINATOR_SHORT;
    beaconFrame.seq = 0x70;
    Test_ExpectStatus(MacFrame_Compose(&beaconFrame, big, bodyLen, air, (uint32_t)sizeof air, &airLen), ZB_OK,
                      "composes");
    Test_ExpectStatus(MacFrame_AppendFcs(air, airLen, (uint32_t)sizeof air, &airLen), ZB_OK, "closed");

    injectFrame(&dev.model, air, airLen, 9500);
    Test_ExpectStatus(Mac_Step(&dev.mac, 9500), ZB_OK, "it arrives");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.beaconsPayloadOverflow == 1, "the event is refused for a payload the pool cannot hold");
    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1), 1,
                     "and the poll 10.22.3 owes for the list is owed all the same");
}

/* A reply the transmit door has no room for is asked again on the next steps, so a parent whose radio is still taking
   a PIB write answers the scan late rather than not at all; refused past MAC_BEACON_HOLD_MS it is counted. */
void caseBeaconReplyHeldWhileTheDoorIsFull(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t len;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    beaconOn(&dev);
    len = composeBeaconRequest(bytes, 0x41, MAC_FRAME_PAN_BROADCAST, MAC_FRAME_ADDR_BROADCAST);

    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 2);
    injectFrame(&dev.model, bytes, len, 7000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 100), ZB_OK, "the request is taken and the door has no room");
    Test_ExpectStatus(Mac_Step(&dev.mac, 110), ZB_OK, "and still none");
    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1), 0, "nothing on the air yet");

    Test_ExpectStatus(Mac_Step(&dev.mac, 120), ZB_OK, "the door takes it");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1), 1, "the beacon goes out");
    Test_ExpectCount(counters.beaconReplies, 1, "counted as the one reply");
    Test_ExpectCount(counters.beaconRefused, 0, "and not as a refusal");

    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 1000);
    injectFrame(&dev.model, bytes, len, 9000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 300), ZB_OK, "a second request meets a door that stays full");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.beaconRefused, 0, "held from its own first refusal, not the earlier reply's");
    Test_ExpectStatus(Mac_Step(&dev.mac, 300 + MAC_BEACON_HOLD_MS + 1), ZB_OK, "past the hold");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.beaconRefused, 1, "it is counted refused");
    Test_ExpectCount(counters.beaconReplies, 1, "and no second reply was sent");

    LoopbackRadio_RefuseTx(&dev.model, ZB_OK, 0);
    Test_ExpectStatus(Mac_Step(&dev.mac, 500), ZB_OK, "a later step with room");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.beaconReplies, 1, "sends nothing for the refused request");
}
