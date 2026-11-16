/* The `mac` suite's delivery: what a frame this device did not send becomes
   (the indication a neighbor's data frame is handed up as) the transaction that ages out of the coordinator's
   queue, the two frames band A consumes and counts instead of delivering (an acknowledgment it overhears and a
   MAC command that is not the Data Request poll), and the damaged frame 6.6.2 discards where no ring can see it. */

#include "log.h"
#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "mac_helpers.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

static const uint8_t airUnicast[47] =
{
    0x61, 0x88, 0xe0, 0x20, 0xde, 0x1f, 0x3c, 0x00, 0x00, 0x08, 0x02, 0x1f, 0x3c, 0x00, 0x00, 0x0a,
    0x08, 0x28, 0x07, 0xc4, 0x84, 0x74, 0xfb, 0xc5, 0x00, 0xff, 0xff, 0x2e, 0x21, 0x00, 0x00, 0xeb,
    0x10, 0xd9, 0xe0, 0x17, 0xbf, 0xcd, 0x98, 0x19, 0x96, 0x1b, 0xc9, 0x66, 0xfd, 0xa3, 0xb9
};

/* ------------------------------------------------------------------ 6.6.2's first-level filter */

#define FILTER_CHILD_EXTENDED (((uint64_t)0x11223344 << 32) | 0x55667788)
#define FILTER_OWN_EXTENDED (((uint64_t)0x08070605 << 32) | 0x04030201)

static const uint8_t filterOwnExtended[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

/* This device's own extended address, through the seam: the rig's part reports eight zero octets, which are no
   address and match nothing (6.2). */
static void filterSetOwnExtended(Test_BandA *dev)
{
    Radio_Pib pib;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_EXTENDED_ADDRESS;
    Zb_memcpy(pib.extendedAddress, filterOwnExtended, RADIO_ADDR_LEN);

    Test_ExpectStatus(Mac_SetPib(&dev->mac, &pib), ZB_OK, "the device's own extended address is set through the seam");
}

/* One frame the filter is asked about: short addressing at both ends and a one-octet content, with `destPan` 0
   leaving the destination fields out, which is the form 6.6.2 d)4 judges by the source PAN instead. */
static void filterInject(Test_BandA *dev, uint32_t frameType, uint16_t destPan, uint16_t destShort,
                         uint16_t srcPan, uint16_t srcShort, uint8_t content, uint64_t stamp)
{
    Mac_Frame frame;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t len;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = (Mac_FrameType)frameType;
    frame.frameVersion = 0;
    frame.destAddrMode = destPan == 0 ? MAC_ADDR_NONE : MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.panIdCompression = destPan == srcPan ? 1 : 0;
    frame.destPan = destPan;
    frame.destShort = destShort;
    frame.srcPan = srcPan;
    frame.srcShort = srcShort;
    frame.seq = 0x30;

    /* A beacon's body is 7.3.1.4's superframe specification, 7.3.1.5's GTS field and 7.3.1.6's pending
       specification, so it is four octets before any payload; anything shorter is not a body that reads. */
    if (frameType == MAC_FRAME_TYPE_BEACON)
    {
        uint8_t body[5] = { 0xff, 0x0f, 0x00, 0x00, 0x5a };   /* 8.2.4.3 wants one payload octet */

        Test_ExpectStatus(MacFrame_Compose(&frame, body, 5, bytes, RADIO_MPDU_MAX, &len), ZB_OK,
                          "a beacon the first-level filter is asked about composes");

        Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK, "with its footer");
        injectFrame(&dev->model, bytes, len, stamp);

        return;
    }

    Test_ExpectStatus(MacFrame_Compose(&frame, &content, 1, bytes, RADIO_MPDU_MAX, &len), ZB_OK,
                      "a frame the first-level filter is asked about composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK, "with its footer");
    injectFrame(&dev->model, bytes, len, stamp);
}

/* A data frame whose destination is an extended address, which `filterInject`'s short form cannot carry. */
static void filterInjectExtended(Test_BandA *dev, uint16_t destPan, uint64_t destExtended, uint64_t stamp)
{
    Mac_Frame frame;
    uint8_t content[1];
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t len;

    content[0] = 0x00;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_DATA;
    frame.frameVersion = 0;
    frame.destAddrMode = MAC_ADDR_EXTENDED;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.panIdCompression = 1;
    frame.destPan = destPan;
    frame.destExtended = destExtended;
    frame.srcPan = destPan;
    frame.srcShort = SLEEPY_A;
    frame.seq = 0x31;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, 1, bytes, RADIO_MPDU_MAX, &len), ZB_OK,
                      "a frame addressed to an extended address composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK, "with its footer");
    injectFrame(&dev->model, bytes, len, stamp);
}

/* 6.6.2's first-level filter, c) to e), one case per refusal it names and one per acceptance the clauses still
   require: the frame is dropped and counted where a clause refuses it, and delivered unchanged where none does. */
static void deliveryFilterCases(void)
{
    Test_BandA dev;
    Test_BandA anywhere;
    Test_BandA unassociated;
    Mac_BeaconConfig beacon;
    Mac_DataIndicationParameters indications[8];
    Mac_Counters counters;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t len;
    uint32_t got;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    filterSetOwnExtended(&dev);

    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.answer = 1;
    beacon.panCoordinator = 1;
    beacon.associationPermit = 1;
    Test_ExpectStatus(Mac_SetBeaconConfig(&dev.mac, &beacon), ZB_OK,
                      "a PAN coordinator that answers beacons and permits association");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.panMismatches == 0 && counters.destinationMismatches == 0
                && counters.beaconPanMismatches == 0,
                "the three refusals start at zero, and the record names each of them");

    /* 6.6.2 c): a destination PAN that is neither this device's own nor the broadcast one. */
    filterInject(&dev, MAC_FRAME_TYPE_DATA, 0xcafe, COORDINATOR_SHORT, 0xcafe, SLEEPY_A, 0x00, 21000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 21000), ZB_OK, "a data frame on a neighbouring PAN arrives");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.panMismatches == 1,
                "it is refused by 6.6.2 c) and counted there, and that refusal is the only trace of it");
    Test_Expect(counters.indicationQueue == 0 && counters.commandsHeard == 0 && counters.acksHeard == 0,
                "dropped where it was read: not delivered and not acted on as anything");

    /* 6.6.2 d)1 and d)2: a destination that is not this device's address. */
    filterInject(&dev, MAC_FRAME_TYPE_DATA, PAN_ID, 0x9999, PAN_ID, SLEEPY_A, 0x00, 21100);
    filterInjectExtended(&dev, PAN_ID, FILTER_OWN_EXTENDED ^ 0xff, 21200);
    Test_ExpectStatus(Mac_Step(&dev.mac, 21200), ZB_OK, "a frame to another short address on this PAN, and one to another extended address");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.destinationMismatches == 2,
                "both are refused by 6.6.2 d), the short form and the extended one, and counted");
    Test_Expect(counters.indicationQueue == 0 && counters.panMismatches == 1,
                "neither is delivered, and their PAN test was satisfied: d) is the clause that refused them");

    /* 6.6.2 e): a beacon whose source PAN is neither this device's nor the broadcast one. */
    filterInject(&dev, MAC_FRAME_TYPE_BEACON, 0, 0, 0xcafe, SLEEPY_A, 0x00, 21300);
    Test_ExpectStatus(Mac_Step(&dev.mac, 21300), ZB_OK, "a beacon from a neighbouring PAN arrives");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.beaconPanMismatches == 1 && counters.indicationQueue == 0,
                "it is refused by 6.6.2 e) and counted, and no beacon is reported");

    /* The acceptances the same clauses require: this device's own extended address, its PAN's beacon, the
       broadcast address, the broadcast PAN, the two destination-less command forms, and an unknown asker. */
    filterInjectExtended(&dev, PAN_ID, FILTER_OWN_EXTENDED, 21400);
    filterInject(&dev, MAC_FRAME_TYPE_BEACON, 0, 0, PAN_ID, SLEEPY_A, 0x00, 21500);
    filterInject(&dev, MAC_FRAME_TYPE_DATA, PAN_ID, MAC_FRAME_ADDR_BROADCAST, PAN_ID, SLEEPY_A, 0x00, 21600);
    filterInject(&dev, MAC_FRAME_TYPE_DATA, MAC_FRAME_PAN_BROADCAST, MAC_FRAME_ADDR_BROADCAST, PAN_ID, SLEEPY_A,
                 0x00, 21700);
    filterInject(&dev, MAC_FRAME_TYPE_COMMAND, 0, 0, PAN_ID, SLEEPY_A, MAC_CMD_POLL, 21800);
    filterInject(&dev, MAC_FRAME_TYPE_COMMAND, PAN_ID, COORDINATOR_SHORT, PAN_ID, 0x0abc, MAC_CMD_POLL, 21900);

    len = composeAssociationRequestToPan(bytes, 0x32, FILTER_CHILD_EXTENDED, 0x8e);
    injectFrame(&dev.model, bytes, len, 22000);

    Test_ExpectStatus(Mac_Step(&dev.mac, 22000), ZB_OK, "six frames the filter must not refuse, and a child's request");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.panMismatches == 1 && counters.destinationMismatches == 2
                && counters.beaconPanMismatches == 1,
                "none of them moved a refusal: the filter dropped nothing the clauses permit");
    Test_Expect(counters.indicationQueue == 5,
                "the four data carriers and the two polls, minus the beacon, which is 8.2.4.3's own event");
    Test_ExpectCount(counters.beaconsNotified, 1, "and that beacon is a notification of its own");
    Test_Expect(counters.selfEchoes == 0, "and none of them was taken for an echo");
    Test_Expect(counters.pollArrivalQueue == 2,
                "both Data Requests are the coordinator's polls: the destination-less one (6.6.2 d)4) and the one "
                "from a device whose address this stack has never seen");
    Test_Expect(counters.associationQueue == 1,
                "and the destination-less Association Request is the parent's event (6.6.2 d)4, R23.1 Annex D.4)");

    got = Mac_PollIndications(&dev.mac, indications, 8);
    Test_ExpectCount(got, 5, "the five carriers are in the ring, in arrival order");
    Test_Expect(indications[0].headerValid == 1 && indications[0].frameType == (uint32_t)MAC_FRAME_TYPE_DATA
                && indications[0].header.destAddrMode == MAC_ADDR_EXTENDED
                && indications[0].header.destExtended == FILTER_OWN_EXTENDED,
                "this device's own extended address is its destination (6.6.2 d)2)");
    Test_Expect(indications[0].headerValid == 1 && indications[1].frameType == (uint32_t)MAC_FRAME_TYPE_DATA,
                "a beacon from this PAN passes 6.6.2 e) and is not among them: 8.2.4.3 delivers it as its own event");

    /* The echo rule keeps its meaning above the filter: a frame naming this device as its source is consumed as
       an echo and counted as one, not as a destination another device holds. */
    filterInject(&dev, MAC_FRAME_TYPE_DATA, PAN_ID, SLEEPY_B, PAN_ID, COORDINATOR_SHORT, 0x00, 22100);
    Test_ExpectStatus(Mac_Step(&dev.mac, 22100), ZB_OK, "this device's own transmission is handed back by the radio");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.selfEchoes == 1 && counters.destinationMismatches == 2 && counters.indicationQueue == 0,
                "it is consumed as an echo and not counted as a frame it was not sent to");

    /* 0xffff is no identity: an unassociated device holds it, so a frame another device sourced from it is an
       arrival rather than this device's own transmission (6.2, Table 8-36's unassigned value). */
    rig(&unassociated, MAC_FRAME_ADDR_BROADCAST, PAN_ID);
    filterInject(&unassociated, MAC_FRAME_TYPE_DATA, PAN_ID, MAC_FRAME_ADDR_BROADCAST, PAN_ID,
                 MAC_FRAME_ADDR_BROADCAST, 0x5a, 22150);
    Test_ExpectStatus(Mac_Step(&unassociated.mac, 22150), ZB_OK, "a frame from an unassociated source arrives");
    counters = Mac_CountersOf(&unassociated.mac);
    Test_ExpectCount(counters.selfEchoes, 0,
                     "and is not taken for an echo of this device, whose own short address is the same 0xffff");

    /* 6.6.2 e)'s own exception, at a device whose macPanId is the broadcast PAN. */
    rig(&anywhere, COORDINATOR_SHORT, MAC_FRAME_PAN_BROADCAST);
    filterInject(&anywhere, MAC_FRAME_TYPE_BEACON, 0, 0, 0x1234, SLEEPY_A, 0x00, 22200);
    filterInject(&anywhere, MAC_FRAME_TYPE_DATA, MAC_FRAME_PAN_BROADCAST, MAC_FRAME_ADDR_BROADCAST, 0x1234,
                 SLEEPY_A, 0x00, 22300);
    Test_ExpectStatus(Mac_Step(&anywhere.mac, 22300), ZB_OK,
                      "a beacon from another PAN and a broadcast frame, at a device whose macPanId is the broadcast one");
    counters = Mac_CountersOf(&anywhere.mac);
    Test_Expect(counters.panMismatches == 0 && counters.beaconPanMismatches == 0,
                "both pass: e) accepts any beacon at the broadcast PAN, and c)'s second alternative is satisfied");
    Test_Expect(counters.indicationQueue == 1 && counters.beaconsNotified == 1,
                "the broadcast frame is an indication and the beacon is a notification: one of each");

    filterInject(&anywhere, MAC_FRAME_TYPE_DATA, 0x1234, COORDINATOR_SHORT, 0x1234, SLEEPY_A, 0x00, 22400);
    Test_ExpectStatus(Mac_Step(&anywhere.mac, 22400), ZB_OK, "a data frame naming one specific PAN arrives");
    counters = Mac_CountersOf(&anywhere.mac);
    Test_Expect(counters.panMismatches == 1,
                "c) refuses it: at the broadcast PAN only the broadcast PAN ID matches, and e)'s exception is the beacon's");
}

/* 6.6.2 d)4 and R23.1 Annex D.4: a destination-less frame belongs to the PAN coordinator alone, and its
   source PAN is macPanId. D.4's broadcast source PAN belongs to the Association Request's addressed rows
   alone, so a Data Request carrying 0xffff is refused; an acknowledgment is never passed upward. */
static void deliveryDestinationlessCases(void)
{
    Test_BandA coordinator;
    Test_BandA router;
    Mac_BeaconConfig beacon;
    Mac_Counters counters;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t len;
    static const uint8_t airAck[5] = { 0x02, 0x00, 0x1c, 0x55, 0x6f };

    /* A parent that answers beacons but is not the PAN coordinator: d)4 names only the coordinator. */
    rig(&router, COORDINATOR_SHORT, PAN_ID);
    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.answer = 1;
    beacon.panCoordinator = 0;
    Test_ExpectStatus(Mac_SetBeaconConfig(&router.mac, &beacon), ZB_OK, "a parent that is not the PAN coordinator");

    filterInject(&router, MAC_FRAME_TYPE_DATA, 0, 0, PAN_ID, SLEEPY_A, 0x00, 23000);
    Test_ExpectStatus(Mac_Step(&router.mac, 23000), ZB_OK,
                      "a destination-less Data frame arrives at a device that is not the PAN coordinator");
    counters = Mac_CountersOf(&router.mac);
    Test_Expect(counters.destinationMismatches == 1 && counters.indicationQueue == 0,
                "6.6.2 d)4 refuses it and counts that refusal: only the PAN coordinator is its destination");

    /* The same frame at the PAN coordinator, its source PAN macPanId: d)4's own match. */
    rig(&coordinator, COORDINATOR_SHORT, PAN_ID);
    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.answer = 1;
    beacon.panCoordinator = 1;
    beacon.associationPermit = 1;
    Test_ExpectStatus(Mac_SetBeaconConfig(&coordinator.mac, &beacon), ZB_OK, "the PAN coordinator itself");

    filterInject(&coordinator, MAC_FRAME_TYPE_DATA, 0, 0, PAN_ID, SLEEPY_A, 0x00, 23100);
    Test_ExpectStatus(Mac_Step(&coordinator.mac, 23100), ZB_OK, "the same frame arrives at the PAN coordinator");
    counters = Mac_CountersOf(&coordinator.mac);
    Test_Expect(counters.destinationMismatches == 0 && counters.indicationQueue == 1,
                "its source PAN matches macPanId, so 6.6.2 d)4 accepts it and delivers the Data frame");

    /* D.4's tables are command headers: a Data frame with the broadcast source PAN is no form they print. */
    filterInject(&coordinator, MAC_FRAME_TYPE_DATA, 0, 0, MAC_FRAME_PAN_BROADCAST, SLEEPY_A, 0x00, 23200);
    Test_ExpectStatus(Mac_Step(&coordinator.mac, 23200), ZB_OK,
                      "a destination-less Data frame whose source PAN is the broadcast one arrives at the coordinator");
    counters = Mac_CountersOf(&coordinator.mac);
    Test_Expect(counters.destinationMismatches == 1 && counters.indicationQueue == 1,
                "6.6.2 d)4 refuses it and counts it: only its source PAN matching macPanId is an acceptance");

    /* A destination-less Data Request is accepted only with macPanId: 0xffff belongs to D.4's addressed rows. */
    filterInject(&coordinator, MAC_FRAME_TYPE_COMMAND, 0, 0, MAC_FRAME_PAN_BROADCAST, SLEEPY_A, MAC_CMD_POLL, 23300);
    Test_ExpectStatus(Mac_Step(&coordinator.mac, 23300), ZB_OK,
                      "a destination-less Data Request with the broadcast source PAN arrives at the coordinator");
    counters = Mac_CountersOf(&coordinator.mac);
    Test_Expect(counters.destinationMismatches == 2 && counters.indicationQueue == 1,
                "6.6.2 d)4 refuses it and counts it: R23.1 Annex D.4 prints no 0xffff header for it");
    Test_Expect(counters.pollArrivalQueue == 0, "so it is no poll this coordinator answers");

    /* The Association Request is the one destination-less command D.4 prints with 0xffff. */
    len = composeAssociationRequestToPan(bytes, 0x33, FILTER_CHILD_EXTENDED, 0x8e);
    injectFrame(&coordinator.model, bytes, len, 23400);
    Test_ExpectStatus(Mac_Step(&coordinator.mac, 23400), ZB_OK,
                      "a destination-less Association Request with the broadcast source PAN arrives");
    counters = Mac_CountersOf(&coordinator.mac);
    Test_Expect(counters.destinationMismatches == 2 && counters.indicationQueue == 1,
                "it passes 6.6.2 d)4 through R23.1 Annex D.4's Association Request table without a refusal");
    Test_Expect(counters.associationQueue == 1, "and is taken as the parent's event, not delivered as data");

    /* The same Data Request with macPanId is d)4's own match, and is the poll. */
    filterInject(&coordinator, MAC_FRAME_TYPE_COMMAND, 0, 0, PAN_ID, SLEEPY_A, MAC_CMD_POLL, 23450);
    Test_ExpectStatus(Mac_Step(&coordinator.mac, 23450), ZB_OK,
                      "a destination-less Data Request whose source PAN is macPanId arrives");
    counters = Mac_CountersOf(&coordinator.mac);
    Test_Expect(counters.destinationMismatches == 2 && counters.indicationQueue == 2,
                "6.6.2 d)4 accepts it, so no new refusal is counted and it is delivered as the poll it is");
    Test_Expect(counters.pollArrivalQueue == 1, "and answered as the coordinator's poll");

    /* A third command id is not D.4's Association Request, so 0xffff is no source PAN it may carry. */
    filterInject(&coordinator, MAC_FRAME_TYPE_COMMAND, 0, 0, MAC_FRAME_PAN_BROADCAST, SLEEPY_A,
                 MAC_CMD_BEACON_REQUEST, 23500);
    Test_ExpectStatus(Mac_Step(&coordinator.mac, 23500), ZB_OK,
                      "a destination-less Beacon Request with the broadcast source PAN arrives at the coordinator");
    counters = Mac_CountersOf(&coordinator.mac);
    Test_Expect(counters.destinationMismatches == 3 && counters.indicationQueue == 2,
                "6.6.2 d)4 refuses it and counts it: D.4 prints no 0xffff header for a third command");

    /* 6.6.2's delivery sentence consumes an acknowledgment, and the filter's own refusals do not describe it. */
    injectFrame(&coordinator.model, airAck, (uint32_t)sizeof airAck, 23600);
    Test_ExpectStatus(Mac_Step(&coordinator.mac, 23600), ZB_OK, "an Imm-Ack arrives");
    counters = Mac_CountersOf(&coordinator.mac);
    Test_Expect(counters.acksHeard == 1, "it is counted where an acknowledgment is counted");
    Test_Expect(counters.panMismatches == 0 && counters.destinationMismatches == 3
                && counters.beaconPanMismatches == 0,
                "and it reaches none of the filter's refusals: 6.6.2 offers only a Data or Multipurpose MSDU "
                "upward, and an Imm-Ack has no addressing fields for d) to test");
}

/* 10.23.1 and Table 10-114: with macPromiscuousMode FALSE the three frames below are handled exactly as the
   first-level filter and the acknowledgment consumption handle them; with it TRUE every correctly received
   frame is an indication, with the Msdu stated as the MHR concatenated with the MAC payload. */
static void deliveryPromiscuousCases(void)
{
    static const uint8_t airAck[5] = { 0x02, 0x00, 0x1c, 0x55, 0x6f };
    Test_BandA filtered;
    Test_BandA all;
    Mac_DataIndicationParameters indications[8];
    Mac_Counters counters;
    uint32_t got;

    /* Operator precedence above the ordinary first-level filter, and the same three frames. */
    rig(&filtered, COORDINATOR_SHORT, PAN_ID);
    Test_Expect(Mac_PromiscuousModeOf(&filtered.mac) == 0,
                "Table 10-114 prints macPromiscuousMode's default as FALSE, and a MAC that names none holds it");

    injectFrame(&filtered.model, airAck, (uint32_t)sizeof airAck, 24000);
    filterInject(&filtered, MAC_FRAME_TYPE_COMMAND, PAN_ID, COORDINATOR_SHORT, PAN_ID, SLEEPY_A, 0x00, 24100);
    filterInject(&filtered, MAC_FRAME_TYPE_DATA, PAN_ID, 0x9999, PAN_ID, SLEEPY_A, 0x00, 24200);

    Test_ExpectStatus(Mac_Step(&filtered.mac, 24200), ZB_OK, "an acknowledgment, a command and another device's data arrive with the mode FALSE");
    counters = Mac_CountersOf(&filtered.mac);
    Test_Expect(counters.acksHeard == 1 && counters.commandsHeard == 1,
                "the acknowledgment is consumed under 6.6.2's delivery sentence and the command reader consumes the command, as before");
    Test_Expect(counters.destinationMismatches == 1 && counters.indicationQueue == 0,
                "and 6.6.2 d) refuses the frame addressed to another device, delivering none of the three");
    Test_Expect(counters.promiscuousDelivered == 0, "the mode's own count names nothing while it is off");

    /* The same three frames with 10.23.1's mode TRUE. */
    rig(&all, COORDINATOR_SHORT, PAN_ID);
    Test_ExpectStatus(Mac_SetPromiscuousMode(&all.mac, 1), ZB_OK, "Table 10-114's Boolean is set TRUE");
    Test_Expect(Mac_PromiscuousModeOf(&all.mac) == 1, "and read back TRUE");

    injectFrame(&all.model, airAck, (uint32_t)sizeof airAck, 24300);
    filterInject(&all, MAC_FRAME_TYPE_COMMAND, PAN_ID, COORDINATOR_SHORT, PAN_ID, SLEEPY_A, 0x00, 24400);
    filterInject(&all, MAC_FRAME_TYPE_DATA, PAN_ID, 0x9999, PAN_ID, SLEEPY_A, 0x00, 24500);

    Test_ExpectStatus(Mac_Step(&all.mac, 24500), ZB_OK, "the same three frames arrive with the mode TRUE");
    counters = Mac_CountersOf(&all.mac);
    Test_Expect(counters.panMismatches == 0 && counters.destinationMismatches == 1
                && counters.beaconPanMismatches == 0,
                "6.6.2 d) still refuses the frame addressed to another device, as 10.23.1 says it shall");
    Test_Expect(counters.acksHeard == 1 && counters.commandsHeard == 1,
                "the acknowledgment and the command are still consumed and counted, and only their delivery is added");
    Test_Expect(counters.indicationQueue == 3 && counters.promiscuousDelivered == 3,
                "all three are indications, and the mode's own count names the three the ordinary path did not deliver");

    got = Mac_PollIndications(&all.mac, indications, 8);
    Test_ExpectCount(got, 3, "the acknowledgment, the command and the other device's frame, in arrival order");
    Test_Expect(indications[0].headerValid == 1 && indications[0].status == ZB_OK
                && indications[0].frameType == (uint32_t)MAC_FRAME_TYPE_ACK
                && indications[0].len == (uint32_t)sizeof airAck && indications[0].payloadLen == 0,
                "the acknowledgment's Msdu is its MHR and no payload, and headerValid is the parser's fact");
    Test_Expect(indications[1].headerValid == 1 && indications[1].status == ZB_OK
                && indications[1].frameType == (uint32_t)MAC_FRAME_TYPE_COMMAND,
                "the command carries the header it parsed too, with its status the verdict rather than headerValid");
    Test_Expect(indications[2].headerValid == 1 && indications[2].payloadLen == 1
                && indications[2].len == indications[2].payloadOffset + indications[2].payloadLen
                   + MAC_FRAME_FCS_OCTETS,
                "the data frame states the carrier in `len` and 10.23.1's Msdu in `payloadOffset`/`payloadLen`");
    Test_Expect(indications[2].bytes[indications[2].payloadOffset] == 0x00,
                "so the Msdu is the MHR it parsed plus the one payload octet, and the footer begins past it");
    Test_Expect(indications[2].lqi == 200 && indications[2].rssiDbm == -70,
                "Msdu, MpduLinkQuality, Timestamp and Rssi stay filled in");

    Test_ExpectStatus(Mac_SetPromiscuousMode(&all.mac, 0), ZB_OK, "the Boolean can be set back to FALSE");
    Test_Expect(Mac_PromiscuousModeOf(&all.mac) == 0, "and reads FALSE again");

    /* 10.23.1 keeps the MAC's duties: a Beacon Request is answered and an Association Request is queued, and
       each is also an indication because the mode adds one for every parsed frame. */
    {
        Test_BandA duties;
        Mac_BeaconConfig config;
        Loopback_Sent sent[4];
        Mac_Frame request;
        uint8_t content[1] = { MAC_CMD_BEACON_REQUEST };
        uint8_t body[RADIO_MPDU_MAX];
        uint32_t bodyLen;

        rig(&duties, COORDINATOR_SHORT, PAN_ID);
        Zb_memset(&config, 0, (uint32_t)sizeof config);
        config.answer = 1;
        config.panCoordinator = 1;
        config.associationPermit = 1;
        Test_ExpectStatus(Mac_SetBeaconConfig(&duties.mac, &config), ZB_OK, "a PAN coordinator with a beacon to send");
        Test_ExpectStatus(Mac_SetPromiscuousMode(&duties.mac, 1), ZB_OK, "and 10.23.1's mode TRUE");

        Zb_memset(&request, 0, (uint32_t)sizeof request);
        request.frameType = MAC_FRAME_TYPE_COMMAND;
        request.frameVersion = 0;
        request.ackRequest = 0;
        request.destAddrMode = MAC_ADDR_SHORT;
        request.srcAddrMode = MAC_ADDR_NONE;
        request.destPan = MAC_FRAME_PAN_BROADCAST;
        request.destShort = MAC_FRAME_ADDR_BROADCAST;
        request.seq = 0x60;
        Test_ExpectStatus(MacFrame_Compose(&request, content, 1, body, RADIO_MPDU_MAX, &bodyLen), ZB_OK,
                          "7.5.2's Beacon Request composes");
        Test_ExpectStatus(MacFrame_AppendFcs(body, bodyLen, RADIO_MPDU_MAX, &bodyLen), ZB_OK, "with its footer");
        injectFrame(&duties.model, body, bodyLen, 24600);
        Test_ExpectStatus(Mac_Step(&duties.mac, 24600), ZB_OK, "it arrives at the coordinator");
        counters = Mac_CountersOf(&duties.mac);
        Test_Expect(counters.beaconReplies == 1 && LoopbackRadio_Sent(&duties.model, sent, 4) == 1,
                    "the Beacon Request is answered and the beacon leaves");
        Test_Expect(counters.indicationQueue == 1 && counters.promiscuousDelivered == 1,
                    "and the request is also indicated, counted as the mode's own delivery");

        bodyLen = composeAssociationRequestToPan(body, 0x61, FILTER_CHILD_EXTENDED, 0x8e);
        injectFrame(&duties.model, body, bodyLen, 24700);
        Test_ExpectStatus(Mac_Step(&duties.mac, 24700), ZB_OK, "a destination-less Association Request arrives");
        counters = Mac_CountersOf(&duties.mac);
        Test_Expect(counters.associationQueue == 1, "the parent still takes it as its own event");
        Test_Expect(counters.indicationQueue == 2 && counters.promiscuousDelivered == 2,
                    "and it is indicated too, as 10.23.1's pass-all sentence requires");
    }
}

/* The memory sink: the records the MAC made, collected so a case can name one (the few lines
   test_log.c and the security suite's helpers use). */
static Log_Record s_fcsSink[LOG_RING_MAX];
static uint32_t s_fcsSinkCount;

static void fcsSinkWrite(void *context, const Log_Record *record)
{
    (void)context;

    if (s_fcsSinkCount < LOG_RING_MAX)
        s_fcsSink[s_fcsSinkCount] = *record;

    s_fcsSinkCount++;
}

static uint32_t fcsDrainLog(Log_Log *log)
{
    Log_Sink sink;

    s_fcsSinkCount = 0;
    sink.context = 0;
    sink.write = fcsSinkWrite;
    Log_Drain(log, &sink);

    return s_fcsSinkCount;
}

static int fcsLogHas(uint16_t component, uint16_t reason, uint32_t argument)
{
    uint32_t index;

    for (index = 0; index < s_fcsSinkCount; index++)
    {
        if (s_fcsSink[index].component == component && s_fcsSink[index].reason == reason
            && s_fcsSink[index].argument == argument)
            return 1;
    }

    return 0;
}


/* Table 7-4 and R23.1 Annex D.6: "the MAC implementation SHALL be able to receive and process MAC data packets
   with the Frame Version field set to any non-reserved value", so a version-2 data frame is read, with Table
   7-2's two PAN-presence rows. */
static void deliveryVersionTwoCases(void)
{
    Test_BandA dev;
    Mac_DataIndicationParameters indications[2];
    Mac_Frame frame;
    uint8_t compressed[RADIO_MPDU_MAX];
    uint8_t explicitPans[RADIO_MPDU_MAX];
    static const uint8_t content[2] = { 0xa1, 0x11 };
    uint32_t compressedLen;
    uint32_t explicitLen;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_DATA;
    frame.frameVersion = 2;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.panIdCompression = 1;
    frame.destPan = PAN_ID;
    frame.srcPan = PAN_ID;
    frame.destShort = COORDINATOR_SHORT;
    frame.srcShort = SLEEPY_A;
    frame.seq = 0x31;

    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &compressedLen), ZB_OK,
                      "Table 7-2's compressed row for two short addresses: the destination PAN and no source PAN");
    Test_Expect(compressedLen == 9, "which is nine octets before the payload");

    /* The octets are built by hand, because composing one is refused: R23.1 D.6 writes version zero. */
    compressed[0] = (uint8_t)((1 << 0) | (1 << 6));                 /* Data, PAN ID compression */
    compressed[1] = (uint8_t)((2 << 2) | (2 << 4) | (2 << 6));      /* both short, version 2 */
    compressed[2] = 0x31;
    compressed[3] = (uint8_t)(PAN_ID & 0xff);
    compressed[4] = (uint8_t)(PAN_ID >> 8);
    compressed[5] = (uint8_t)(COORDINATOR_SHORT & 0xff);
    compressed[6] = (uint8_t)(COORDINATOR_SHORT >> 8);
    compressed[7] = (uint8_t)(SLEEPY_A & 0xff);
    compressed[8] = (uint8_t)(SLEEPY_A >> 8);
    compressed[9] = content[0];
    compressed[10] = content[1];
    Test_ExpectStatus(MacFrame_AppendFcs(compressed, 11, RADIO_MPDU_MAX, &compressedLen), ZB_OK, "closed at its footer");

    injectFrame(&dev.model, compressed, compressedLen, 60000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 60000), ZB_OK, "a version-2 data frame arrives");
    Test_ExpectCount(Mac_PollIndications(&dev.mac, indications, 2), 1,
                     "and is delivered: the receive side owes every non-reserved version (R23.1 Annex D.6)");
    Test_Expect(indications[0].header.frameVersion == 2 && indications[0].header.destShort == COORDINATOR_SHORT
                && indications[0].header.srcShort == SLEEPY_A && indications[0].payloadLen == 2,
                "with its addresses read and its payload where Table 7-2 puts it");
    Test_Expect(indications[0].header.destPan == PAN_ID && indications[0].header.srcPan == PAN_ID,
                "and both PANs the same: Table 7-2's compressed row omits the source field, and the field it repeats is the destination's");

    frame.panIdCompression = 0;
    Test_ExpectStatus(MacFrame_HeaderLen(&frame, &explicitLen), ZB_OK,
                      "and Table 7-2's uncompressed row, both PAN fields present");
    Test_Expect(explicitLen == 11, "eleven octets, two PAN fields more");
    Test_ExpectStatus(MacFrame_Compose(&frame, content, 2, explicitPans, RADIO_MPDU_MAX, &explicitLen),
                      ZB_ERR_UNSUPPORTED, "while composing a version-2 frame is refused: D.6 writes version zero");
}
/* 6.6.2 a) and b), the two reserved values, plus the malformed and unbuilt forms, each refused under its own
   count; the FCS sentence precedes that list, so a damaged frame is refused by the footer first. */
static void deliveryBeaconBitCases(void)
{
    Test_BandA dev;
    Mac_DataIndicationParameters indications[2];
    Mac_BeaconNotification notified;
    Mac_Frame frame;
    uint8_t bytes[RADIO_MPDU_MAX];
    static const uint8_t content[5] = { 0xff, 0x0f, 0x00, 0x00, 0x5a };
    uint32_t len;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_BEACON;
    frame.frameVersion = 0;
    frame.destAddrMode = MAC_ADDR_NONE;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.srcPan = PAN_ID;
    frame.srcShort = SLEEPY_A;
    frame.seq = 0x21;
    frame.ackRequest = 1;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, 5, bytes, RADIO_MPDU_MAX, &len), ZB_ERR_BAD_ARGUMENT,
                      "7.3.1.2 writes a beacon's other frame control bits zero, so this one does not compose");

    frame.ackRequest = 0;
    Test_ExpectStatus(MacFrame_Compose(&frame, content, 5, bytes, RADIO_MPDU_MAX, &len), ZB_OK,
                      "while the same beacon without it composes");
    bytes[0] = (uint8_t)(bytes[0] | 0x20);        /* the AR bit, bit 5 of the frame control field */

    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK,
                      "and a beacon heard with that bit set, its footer computing, is what a receiver gets");

    injectFrame(&dev.model, bytes, len, 50000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 50000), ZB_OK, "the beacon arrives");
    Test_ExpectCount(Mac_PollIndications(&dev.mac, indications, 2), 0,
                     "a beacon is 8.2.4.3's own event, so it is not an indication");
    Test_Expect(Mac_PollBeacons(&dev.mac, &notified, 1) == 1 && notified.sn == 0x21,
                "and it is a notification: 7.3.1.2's ignored bit refused nothing on the way in");
    Test_ExpectCount(Mac_CountersOf(&dev.mac).beaconsUnreadable, 0, "with its body read");
}
static void deliveryRefusalCases(void)
{
    Test_BandA dev;
    Mac_DataIndicationParameters indications[4];
    Mac_Counters counters;
    Mac_Config macCfg;
    Mac_Frame frame;
    Radio_Caps caps;
    Log_Log log;
    uint8_t base[RADIO_MPDU_MAX];
    uint8_t reservedType[RADIO_MPDU_MAX];
    uint8_t reservedVersion[RADIO_MPDU_MAX];
    uint8_t unbuiltVersion[RADIO_MPDU_MAX];
    uint8_t content[2] = { 0xa1, 0x11 };
    uint32_t baseLen;
    uint32_t typeLen;
    uint32_t versionLen;
    uint32_t unbuiltLen;

    Test_ExpectStatus(Log_Init(&log), ZB_OK, "the case's own diagnostics pool");
    Test_BandACapsAcks(&caps);
    Zb_memset(&macCfg, 0, (uint32_t)sizeof macCfg);
    macCfg.log = &log;
    rigConfig(&dev, &caps, COORDINATOR_SHORT, PAN_ID, &macCfg);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_DATA;
    frame.frameVersion = 0;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.panIdCompression = 1;
    frame.destPan = PAN_ID;
    frame.srcPan = PAN_ID;
    frame.destShort = COORDINATOR_SHORT;
    frame.srcShort = SLEEPY_A;
    frame.seq = 0x41;

    /* These frames cannot be composed, which is the point: a reserved subfield is something a frame carries when it
       arrives, so each is the data frame's own octets with the subfield patched and the footer recomputed over them.
       The patched footer computes, so what refuses each frame is the clause that names its subfield and not damage. */
    Test_ExpectStatus(MacFrame_Compose(&frame, content, 2, base, RADIO_MPDU_MAX, &baseLen), ZB_OK,
                      "a data frame addressed to this device composes");
    Test_ExpectStatus(MacFrame_AppendFcs(base, baseLen, RADIO_MPDU_MAX, &baseLen), ZB_OK, "and closes at its footer");

    Zb_memcpy(reservedType, base, baseLen);
    reservedType[0] = (uint8_t)((reservedType[0] & 0xf8) | MAC_FRAME_TYPE_RESERVED);   /* FCF bits 0-2, Table 7-1 */
    Test_ExpectStatus(MacFrame_AppendFcs(reservedType, baseLen - MAC_FRAME_FCS_OCTETS, RADIO_MPDU_MAX, &typeLen),
                      ZB_OK, "the footer these octets compute");

    Zb_memcpy(reservedVersion, base, baseLen);
    reservedVersion[1] = (uint8_t)((reservedVersion[1] & 0xcf) | (3 << 4));   /* FCF bits 12-13, Table 7-4 */
    Test_ExpectStatus(MacFrame_AppendFcs(reservedVersion, baseLen - MAC_FRAME_FCS_OCTETS, RADIO_MPDU_MAX,
                                         &versionLen), ZB_OK, "and this one's");

    /* Table 7-1's 5, a Multipurpose frame: defined by this revision and composed by no Zigbee device */
    Zb_memcpy(unbuiltVersion, base, baseLen);
    unbuiltVersion[0] = (uint8_t)((unbuiltVersion[0] & 0xf8) | MAC_FRAME_TYPE_MULTIPURPOSE);
    Test_ExpectStatus(MacFrame_AppendFcs(unbuiltVersion, baseLen - MAC_FRAME_FCS_OCTETS, RADIO_MPDU_MAX,
                                         &unbuiltLen), ZB_OK, "and the Multipurpose form's");

    injectFrame(&dev.model, reservedType, typeLen, 40000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 40000), ZB_OK, "the reserved frame arrives");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.reservedTypeFrames == 1 && counters.indicationQueue == 0,
                "6.6.2 a) refuses it, it is counted under that clause, and no ring sees it");
    Test_ExpectCount(fcsDrainLog(&log), 1, "one record was written");
    Test_Expect(fcsLogHas(LOG_COMP_MAC_RX, LOG_REASON_REFUSED, MAC_RX_REFUSED_RESERVED_TYPE) == 1,
                "naming the refusal that 6.6.2 a) prints");

    injectFrame(&dev.model, reservedVersion, versionLen, 40100);
    Test_ExpectStatus(Mac_Step(&dev.mac, 40100), ZB_OK, "the reserved version arrives");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.reservedVersionFrames == 1 && counters.reservedTypeFrames == 1
                && counters.indicationQueue == 0,
                "6.6.2 b) refuses it under its own count, and the type counter does not move");
    Test_ExpectCount(fcsDrainLog(&log), 1, "one record, again");
    Test_Expect(fcsLogHas(LOG_COMP_MAC_RX, LOG_REASON_REFUSED, MAC_RX_REFUSED_RESERVED_VERSION) == 1, "naming b)");

    injectFrame(&dev.model, unbuiltVersion, unbuiltLen, 40200);
    Test_ExpectStatus(Mac_Step(&dev.mac, 40200), ZB_OK, "a Multipurpose frame arrives");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.unbuiltForms == 1 && counters.malformedFrames == 0
                && counters.reservedVersionFrames == 1 && counters.indicationQueue == 0,
                "a defined form this build has no header for is counted apart from the standard's own refusals");
    Test_Expect(fcsDrainLog(&log) == 1
                && fcsLogHas(LOG_COMP_MAC_RX, LOG_REASON_REFUSED, MAC_RX_REFUSED_UNBUILT) == 1,
                "and the record says which of the two kinds of refusal this was");

    /* Both at once: the FCS sentence is printed before the list, and a changed subfield is damage first. */
    reservedType[typeLen - 1] = (uint8_t)(reservedType[typeLen - 1] ^ 0xff);
    injectFrame(&dev.model, reservedType, typeLen, 40300);
    Test_ExpectStatus(Mac_Step(&dev.mac, 40300), ZB_OK, "a reserved frame whose footer was then damaged arrives");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.fcsFailures == 1 && counters.reservedTypeFrames == 1,
                "the footer refused it, so the type counter stays where it was: 6.6.2's FCS sentence comes first");
    Test_ExpectCount(fcsDrainLog(&log), 1, "one record, and it names the footer rather than the type");
    Test_Expect(fcsLogHas(LOG_COMP_MAC_RX, LOG_REASON_FCS, MAC_RX_FCS_CHECKSUM) == 1,
                "which is the claim 7.2.11's recomputation made");

    Test_ExpectCount(Mac_PollIndications(&dev.mac, indications, 4), 0, "none of the four reached a caller");
}

/* 6.6.2's FCS sentence with 7.2.11: either claim refuses the frame, counted and logged, and 10.23.1's
   "correctly received" leaves the promiscuous mode no exemption. A duplicate or PHY report names no footer and
   is delivered. */
static void deliveryFcsDiscardCases(void)
{
    Test_BandA dev;
    Loopback_FrameSpec spec;
    Mac_DataIndicationParameters indications[4];
    Mac_Counters counters;
    Mac_Config macCfg;
    Mac_Frame frame;
    Radio_Caps caps;
    Log_Log log;
    uint8_t good[RADIO_MPDU_MAX];
    uint8_t damaged[RADIO_MPDU_MAX];
    uint8_t content[2] = { 0xa1, 0x11 };
    uint32_t len;
    uint32_t got;

    Test_ExpectStatus(Log_Init(&log), ZB_OK, "the case's own diagnostics pool");

    /* The pool is the config's, not a field assigned after the build: `Mac_Config.log` is the door an
       application has (docs/internals/coding-rules.md §5). */
    Test_BandACapsAcks(&caps);
    Zb_memset(&macCfg, 0, (uint32_t)sizeof macCfg);
    macCfg.log = &log;
    rigConfig(&dev, &caps, COORDINATOR_SHORT, PAN_ID, &macCfg);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_DATA;
    frame.frameVersion = 0;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.panIdCompression = 1;
    frame.destPan = PAN_ID;
    frame.srcPan = PAN_ID;
    frame.destShort = COORDINATOR_SHORT;
    frame.srcShort = SLEEPY_A;
    frame.seq = 0x41;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, 2, good, RADIO_MPDU_MAX, &len), ZB_OK,
                      "a data frame addressed to this device composes");
    Test_ExpectStatus(MacFrame_AppendFcs(good, len, RADIO_MPDU_MAX, &len), ZB_OK,
                      "and is closed by the footer those octets compute (7.2.11)");

    Zb_memcpy(damaged, good, len);
    damaged[len - 1] = (uint8_t)(damaged[len - 1] ^ 0xff);   /* one footer octet; the MHR still parses */

    /* The clean frame first, so the case names both halves: it is delivered byte for byte as it always was. */
    injectFrame(&dev.model, good, len, 30000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 30000), ZB_OK, "a frame whose footer computes arrives");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.indicationQueue == 1 && counters.fcsFailures == 0 && Log_Count(&log) == 0,
                "it is delivered, no footer refusal is counted and the log holds nothing about it");
    got = Mac_PollIndications(&dev.mac, indications, 4);
    Test_Expect(got == 1 && indications[0].len == len && indications[0].status == ZB_OK
                && Zb_memcmp(indications[0].bytes, good, len) == 0,
                "the indication carries the PSDU the radio delivered, octet for octet, with the header it parsed");

    /* The same frame with one footer octet changed: 7.2.11's comparison fails and 6.6.2 discards it. */
    injectFrame(&dev.model, damaged, len, 30100);
    Test_ExpectStatus(Mac_Step(&dev.mac, 30100), ZB_OK,
                      "the same frame with a footer that does not compute arrives");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.indicationQueue, 0, "no indication: 6.6.2 discards it and delivers it to no caller");
    Test_ExpectCount(counters.fcsFailures, 1, "the footer counter moved once, under the reason that refused it");
    Test_Expect(counters.panMismatches == 0 && counters.destinationMismatches == 0
                && counters.commandsHeard == 0 && counters.acksHeard == 0,
                "and under no other name: the footer refused it before any clause or duty read it");
    Test_ExpectCount(fcsDrainLog(&log), 1, "one log record was written");
    Test_Expect(fcsLogHas(LOG_COMP_MAC_RX, LOG_REASON_FCS, MAC_RX_FCS_CHECKSUM) == 1,
                "naming the footer as the reason, with 7.2.11's recomputation as the claim that named it");
    Test_ExpectCount(Mac_PollIndications(&dev.mac, indications, 4), 0, "and the PSDU reaches no caller at all");

    /* The other claim: the radio's own flag on a frame whose octets compute, which is the only way that claim
       arrives without 7.2.11 agreeing. Its footer is clean, so only the flag refuses it. */
    spec.len = len;
    spec.bytes = good;
    spec.rssiDbm = -70;
    spec.lqi = 200;
    spec.stampTicks = 30200;
    spec.error = ZB_ERR_BAD_FRAME;
    Test_Expect(MacFrame_CheckFcs(good, len) == ZB_OK,
                "the frame the radio flags carries a footer that computes, so its flag is the only claim");
    Test_ExpectStatus(LoopbackRadio_Inject(&dev.model, &spec, 1), ZB_OK, "it is delivered with the radio's flag on it");
    Test_ExpectStatus(Mac_Step(&dev.mac, 30200), ZB_OK, "and reaches the MAC");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.indicationQueue == 0 && counters.fcsFailures == 2,
                "it is discarded too, by the radio's flag alone, and counted in the same footer count");
    Test_ExpectCount(fcsDrainLog(&log), 1, "one record for it");
    Test_Expect(fcsLogHas(LOG_COMP_MAC_RX, LOG_REASON_FCS, MAC_RX_FCS_RADIO) == 1,
                "with the radio's flag named as the claim that refused it");

    /* 6.6.2's filter is every frame's, a flagged one included: a duplicate report on a frame that is not this
       device's is no arrival, and the refusal is counted where the clause names it. */
    {
        Mac_Frame stranger;
        uint8_t strangerBytes[RADIO_MPDU_MAX];
        uint32_t strangerLen = 0;

        Zb_memset(&stranger, 0, (uint32_t)sizeof stranger);
        stranger.frameType = MAC_FRAME_TYPE_DATA;
        stranger.destAddrMode = MAC_ADDR_SHORT;
        stranger.srcAddrMode = MAC_ADDR_SHORT;
        stranger.destPan = PAN_ID;
        stranger.srcPan = PAN_ID;
        stranger.destShort = 0x9999;        /* neither this device's nor the broadcast one */
        stranger.srcShort = SLEEPY_A;
        stranger.seq = 0x33;
        Test_ExpectStatus(MacFrame_Compose(&stranger, content, (uint32_t)sizeof content, strangerBytes,
                                           RADIO_MPDU_MAX, &strangerLen), ZB_OK,
                          "a data frame addressed to another device composes");
        Test_ExpectStatus(MacFrame_AppendFcs(strangerBytes, strangerLen, RADIO_MPDU_MAX, &strangerLen), ZB_OK,
                          "with a footer that computes");

        spec.len = strangerLen;
        spec.bytes = strangerBytes;
        spec.stampTicks = 30150;
        spec.error = ZB_ERR_BUSY;
        Test_ExpectStatus(LoopbackRadio_Inject(&dev.model, &spec, 1), ZB_OK,
                          "it arrives with a duplicate report on it");
        Test_ExpectStatus(Mac_Step(&dev.mac, 30150), ZB_OK, "and reaches the MAC");
        counters = Mac_CountersOf(&dev.mac);
        Test_ExpectCount(counters.indicationQueue, 0,
                         "6.6.2 d) refuses it whatever the radio reports: a duplicate report is no exemption");
        Test_ExpectCount(counters.destinationMismatches, 1, "counted where the clause named it");

        spec.bytes = good;                  /* the block's own buffer does not outlive it */
        spec.len = len;
    }

    /* A report about something other than the footer refuses nothing: 6.6.2 has no duplicate rule, so a frame
       the radio says it delivered before is an ordinary frame and is delivered with that report, which is what
       it was before the footer rule arrived. Its footer computes, so no claim about it exists. */
    spec.stampTicks = 30250;
    spec.error = ZB_ERR_BUSY;
    Test_ExpectStatus(LoopbackRadio_Inject(&dev.model, &spec, 1), ZB_OK,
                      "the same clean frame arrives with the radio's duplicate report on it");
    Test_ExpectStatus(Mac_Step(&dev.mac, 30250), ZB_OK, "and reaches the MAC");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.indicationQueue == 1 && counters.fcsFailures == 2,
                "it is delivered and no footer count moves: only a footer that does not compute is discarded");
    got = Mac_PollIndications(&dev.mac, indications, 4);
    Test_Expect(got == 1 && indications[0].status == ZB_ERR_BUSY && indications[0].headerValid == 1
                && indications[0].len == len
                && indications[0].payloadOffset + indications[0].payloadLen == len - MAC_FRAME_FCS_OCTETS,
                "the caller gets it with the radio's report on it, its MHR read, the carrier in `len` and 10.23.1's Msdu ending where the footer begins");
    Test_ExpectCount(fcsDrainLog(&log), 0, "and the log holds nothing: no clause refused this frame");

    /* The other report that names no footer: a receive error the PHY had, which 6.6.2 does not read as a
       damaged frame either, so it travels the same way. */
    spec.stampTicks = 30260;
    spec.error = ZB_ERR_DEVICE;
    Test_ExpectStatus(LoopbackRadio_Inject(&dev.model, &spec, 1), ZB_OK,
                      "and again with the receive error the radio names instead");
    Test_ExpectStatus(Mac_Step(&dev.mac, 30260), ZB_OK, "which reaches the MAC too");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.indicationQueue == 1 && counters.fcsFailures == 2,
                "delivered under its own status, with the footer count still where the footer left it");
    got = Mac_PollIndications(&dev.mac, indications, 4);
    Test_Expect(got == 1 && indications[0].status == ZB_ERR_DEVICE, "the report reaches the caller unchanged");
    Test_ExpectCount(fcsDrainLog(&log), 0, "and no record was written for it either");

    /* 10.23.1: "pass all frames correctly received" is not this frame, so the mode adds no indication for it. */
    Test_ExpectStatus(Mac_SetPromiscuousMode(&dev.mac, 1), ZB_OK, "Table 10-114's mode is set TRUE");
    injectFrame(&dev.model, damaged, len, 30300);
    Test_ExpectStatus(Mac_Step(&dev.mac, 30300), ZB_OK, "the damaged frame arrives under the mode");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.indicationQueue == 0 && counters.promiscuousDelivered == 0,
                "the mode delivers none of it: 10.23.1 says correctly received and 6.6.2 discarded this one");
    Test_ExpectCount(counters.fcsFailures, 3, "the footer counter moved again, and the mode changed nothing");
    Test_Expect(fcsDrainLog(&log) == 1 && fcsLogHas(LOG_COMP_MAC_RX, LOG_REASON_FCS, MAC_RX_FCS_CHECKSUM) == 1,
                "and the record is the same one for the same reason");
}

void caseDelivery(void)
{
    Test_BandA dev;
    Loopback_FrameSpec specs[4];
    Mac_DataIndicationParameters indications[8];
    uint8_t corrupt[(uint32_t)sizeof airUnicast];
    uint8_t secured[7];
    uint8_t ieBit[5];
    uint32_t got;
    uint32_t i;
    uint32_t filled;
    uint32_t fcsLen;
    Mac_Counters counters;

    /* The identity the captured frame itself names, destination PAN 0xde20 and destination 0x3c1f: 6.6.2 c)
       refuses a frame this device is not addressed by, so the device that receives it is the one it addresses. */
    rig(&dev, 0x3c1f, 0xde20);

    /* A frame as the AT86RF233 build delivered it: footer included, as the caps say. */
    specs[0].len = (uint32_t)sizeof airUnicast;
    specs[0].bytes = airUnicast;
    specs[0].rssiDbm = -94;
    specs[0].lqi = 255;
    specs[0].stampTicks = 3639678816;
    specs[0].error = ZB_OK;

    Zb_memcpy(corrupt, airUnicast, (uint32_t)sizeof airUnicast);
    corrupt[6] = (uint8_t)(corrupt[6] ^ 0x01);        /* inside the destination address, not the footer */
    specs[1].len = (uint32_t)sizeof corrupt;
    specs[1].bytes = corrupt;
    specs[1].rssiDbm = -94;
    specs[1].lqi = 255;
    specs[1].stampTicks = 3641003816;
    specs[1].error = ZB_OK;                           /* the radio said nothing was wrong */

    /* Both of these close with a footer that computes, so what refuses them is the form their frame control field
       names and not damage: a fixture without one would be refused by 6.6.2's FCS sentence first. */
    secured[0] = (uint8_t)(AIR_UNICAST_FCF | (1 << 3));
    secured[1] = (uint8_t)(AIR_UNICAST_FCF >> 8);
    secured[2] = 0x30;
    secured[3] = 0x00;
    secured[4] = 0x00;
    Test_ExpectStatus(MacFrame_AppendFcs(secured, 5, (uint32_t)sizeof secured, &fcsLen), ZB_OK,
                      "the secured fixture closes at seven octets");
    specs[2].len = fcsLen;
    specs[2].bytes = secured;
    specs[2].rssiDbm = -80;
    specs[2].lqi = 128;
    specs[2].stampTicks = 3642338816;
    specs[2].error = ZB_OK;

    ieBit[0] = (uint8_t)(AIR_UNICAST_FCF & 0xff);
    ieBit[1] = (uint8_t)((AIR_UNICAST_FCF >> 8) | (1 << 0));   /* bit 8 of the FCF is the low bit of octet 1 */
    ieBit[2] = 0x11;
    Test_ExpectStatus(MacFrame_AppendFcs(ieBit, 3, (uint32_t)sizeof ieBit, &fcsLen), ZB_OK,
                      "and the IE-bit fixture at five");
    specs[3].len = fcsLen;
    specs[3].bytes = ieBit;
    specs[3].rssiDbm = -70;
    specs[3].lqi = 0;
    specs[3].stampTicks = 3643003816;
    specs[3].error = ZB_OK;

    Test_ExpectStatus(LoopbackRadio_Inject(&dev.model, specs, 4), ZB_OK, "four frames in front of band A");
    Test_ExpectStatus(Mac_Step(&dev.mac, 500), ZB_OK, "one step takes them all");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.indicationQueue, 1,
                     "one of the four reaches a ring: the damaged frame, the secured one and the one with the IE bit are refused before any duty");
    Test_ExpectCount(counters.fcsFailures, 1, "the footer that does not compute, counted under the reason that refused it");
    Test_ExpectCount(counters.unbuiltForms, 1, "the secured frame's auxiliary header, a form this build has no header for");
    Test_ExpectCount(counters.malformedFrames, 1, "and the version-0 frame demanding an IE list, which 7.2.2.8 forbids");

    got = Mac_PollIndications(&dev.mac, indications, 8);
    Test_ExpectCount(got, 1, "and polled");

    Test_Expect(indications[0].headerValid == 1, "the captured frame parses");
    Test_Expect(indications[0].header.frameType == MAC_FRAME_TYPE_DATA && indications[0].header.ackRequest,
           "as the acknowledged data frame it is");
    Test_Expect(indications[0].header.destPan == 0xde20 && indications[0].header.destShort == 0x3c1f
           && indications[0].header.srcShort == 0x0000,
           "with the addressing read out of the octets, least significant octet first");
    Test_Expect(indications[0].payloadOffset == 9 && indications[0].payloadLen == 36,
           "and the payload where the header ends and the footer begins");
    Test_Expect(Zb_memcmp(indications[0].bytes + indications[0].payloadOffset, airUnicast + 9, 36) == 0,
           "copied into the indication, so it survives the queue slot it came from");
    Test_Expect(indications[0].status == ZB_OK, "clean");
    Test_Expect(indications[0].rssiDbm == -94 && indications[0].lqi == 255
           && indications[0].stampTicks == 3639678816,
           "with the metadata the seam delivered, stamp in device ticks and never converted");

    /* The three refused frames were counted rather than delivered; from here the case is about pool room, so
       the rest of the batch is the frame 6.6.2 leaves standing. */
    for (i = 1; i < 4; i++)
        specs[i] = specs[0];

    /* The pools, and which one a skipped poll belongs to. */
    for (i = 0; i < 3; i++)
        Test_ExpectStatus(LoopbackRadio_Inject(&dev.model, specs, 4), ZB_OK, "twelve frames waiting in band B");

    Test_ExpectStatus(Mac_Step(&dev.mac, 600), ZB_OK, "a step takes one batch");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(LoopbackRadio_Queued(&dev.model), 4, "four still there");
    Test_ExpectCount(counters.indicationQueue, 8,
                     "eight here: the whole batch is delivered now that the case's set is the frame 6.6.2 leaves standing");

    /* The ring is ZB_LIMIT_MAC_INDICATION deep, one batch or more: each further batch fills it by eight. */
    for (filled = RADIO_FRAME_BATCH_MAX; filled < MAC_INDICATION_QUEUE_MAX; filled += RADIO_FRAME_BATCH_MAX)
    {
        for (i = 0; i < 2; i++)
            Test_ExpectStatus(LoopbackRadio_Inject(&dev.model, specs, 4), ZB_OK, "and band B filled again");

        Test_ExpectStatus(Mac_Step(&dev.mac, 650), ZB_OK, "a further batch fits");
    }

    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.indicationQueue, MAC_INDICATION_QUEUE_MAX, "the indications fill the ring exactly");
    Test_ExpectStatus(LoopbackRadio_Inject(&dev.model, specs, 4), ZB_OK, "four more waiting in band B");

    Test_ExpectStatus(Mac_Step(&dev.mac, 700), ZB_OK, "a step with no room for what a batch could hold");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.indicationQueue == MAC_INDICATION_QUEUE_MAX,
           "so it does not ask, and the queue stays as it was: a full ring leaves no room for a batch of eight");
    Test_Expect(counters.pollsSkipped == 1, "counted where the frame was actually kept");
    Test_Expect(LoopbackRadio_Queued(&dev.model) == 8,
           "in band B's ring, which is the same rule applied one layer up: nobody discards a frame a poll would have taken");

    got = Mac_PollIndications(&dev.mac, indications, 8);
    Test_Expect(got == 8, "draining makes room");
    Test_ExpectStatus(Mac_Step(&dev.mac, 800), ZB_OK, "and the next step delivers what band B had been holding");
    Test_Expect(LoopbackRadio_Queued(&dev.model) == 0, "empty at the backend");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.indicationQueue == MAC_INDICATION_QUEUE_MAX,
           "and the step that emptied band B filled the ring again, which is what stops the next poll rather than losing a frame");

    deliveryFcsDiscardCases();
    deliveryBeaconBitCases();
    deliveryVersionTwoCases();
    deliveryRefusalCases();
    deliveryFilterCases();
    deliveryDestinationlessCases();
    deliveryPromiscuousCases();
}

/* Aging, with both sides of the boundary named. 10.22.2 says each transaction "shall persist in the
   coordinator for at most macTransactionPersistenceTime", and that a transaction not extracted within it
   has its information discarded, with "the MAC sublayer … indicate[ing] to the next higher layer a Status of
   TRANSACTION_EXPIRED". The unit that attribute is worded in is a beacon unit and this PAN has no beacon, so
   the number is band A's own and the discard is the count. */
void caseTransactionPersistence(void)
{
    Test_BandA dev;
    Loopback_Sent sent[MAC_TX_TRACK_MAX + 1];
    Mac_DataRequestParameters req;
    uint8_t transaction[2] = { 0xa1, 0x11 };
    uint32_t got;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_A, transaction, 2);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 1000), ZB_OK, "a transaction arrives at time 1000");

    Test_ExpectStatus(Mac_Step(&dev.mac, 1000 + MAC_TRANSACTION_PERSISTENCE_MS - 1), ZB_OK,
                 "a step one millisecond short of the persistence limit");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 1, "is the exclusive side of that boundary: the transaction is still held, because the limit has not been reached");
    Test_Expect(counters.transactionsExpired == 0, "and nothing has been counted as expired");

    Test_ExpectStatus(Mac_Step(&dev.mac, 1000 + MAC_TRANSACTION_PERSISTENCE_MS), ZB_OK, "a step at the limit itself");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 0, "is the inclusive side: discarded, which is what 'at most' permits at the limit and nowhere before it");
    Test_Expect(counters.transactionsExpired == 1, "and the discard is counted, which is this pool's name for TRANSACTION_EXPIRED (10.22.2)");

    injectPoll(&dev.model, 0x20, SLEEPY_A, 5000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1000 + MAC_TRANSACTION_PERSISTENCE_MS + 10), ZB_OK, "A's poll, late, now finds nothing");

    got = LoopbackRadio_Sent(&dev.model, sent, MAC_TX_TRACK_MAX + 1);
    Test_Expect(got == 1, "one answer");
    Test_Expect(sent[0].len == 11 && fcfOf(&sent[0]) == AIR_BROADCAST_FCF,
           "10.22.3's zero-length unacknowledged Data frame rather than the transaction that expired: an expired transaction is not delivered late (10.22.2)");
    Test_Expect(sent[0].bytes[2] == 0x01,
           "at DSN 1, the number the queueing took and never gave back: the answer is a fresh frame, not a re-extraction with a reused number (7.2.3, against 6.6.3.4)");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionsExpired == 1, "and the expiry count did not move again");
}

/*
 * 58.a An acknowledgment frame this device merely overhears is consumed at `mac` and counted there
 * ("acknowledgement command frames are consumed at the `mac` layer … hearing one as a third device
 * is traffic to count, not a frame to deliver"). It is not delivered upward for two reasons, and the
 * first is that the transaction an acknowledgment completes already left this module as the completion
 * report `Mac_DataConfirmParameters` is (`acked`, `status`, `numBackoffs` are that report), so a
 * second copy of the same fact one layer up would be two places for it to disagree. The frame below
 * is the one the ConBee II capture recorded byte for byte in test/fixtures/conbee2_ch15_hex.txt:
 * 7.2.2.3's Frame Control, Sequence Number and FCS, five octets and no addressing field.
 */
void caseHeardAckIsConsumed(void)
{
    Test_BandA dev;
    Mac_DataIndicationParameters indications[4];
    Mac_Counters counters;
    static const uint8_t airAck[5] = { 0x02, 0x00, 0x1c, 0x55, 0x6f };
    uint32_t got;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.acksHeard == 0 && counters.commandsHeard == 0,
           "nothing heard, and the two counters start where a module that has heard nothing says it is");

    injectFrame(&dev.model, airAck, (uint32_t)sizeof airAck, 9000);
    injectPoll(&dev.model, 0x24, SLEEPY_A, 9100);
    Test_ExpectStatus(Mac_Step(&dev.mac, 300), ZB_OK, "one step takes an acknowledgment and a poll");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.acksHeard == 1,
           "the acknowledgment is counted here and nowhere else");
    Test_Expect(counters.indicationQueue == 1,
           "the delivered queue did not move with it: one indication for the poll, none for the ack");
    Test_Expect(counters.pollArrivalQueue == 1, "the poll is still the poll `mac` reports, arrival and all");

    got = Mac_PollIndications(&dev.mac, indications, 4);
    Test_Expect(got == 1 && indications[0].headerValid == 1
           && indications[0].frameType == (uint32_t)MAC_FRAME_TYPE_COMMAND,
           "and the one frame that was delivered carries the type the parse read, so the carrier judgement above "
           "this module has something to judge from");

    injectFrame(&dev.model, airAck, (uint32_t)sizeof airAck, 9200);
    Test_ExpectStatus(Mac_Step(&dev.mac, 310), ZB_OK, "a second overheard acknowledgment");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.acksHeard == 2 && counters.indicationQueue == 0,
           "counts again, delivers nothing again, and no completion is invented for a frame this device was not a party to");
}

/*
 * 58.b A MAC command that is not the Data Request poll is counted at `mac` and not delivered
 * upward (Beacon Request and Realignment are the MLME territory this stack defers, so
 * nothing above this module could act on them, but hearing one is traffic, and a heard
 * frame that is not handed up is counted rather than uncounted). The frame below is a
 * Beacon Request: 802.15.4-2006 Table 82's 0x07, in the same twelve-octet command shape the
 * poll of 10.22.4.1 has, beside one poll that is delivered for the contrast to be visible.
 */
void caseHeardCommandIsCounted(void)
{
    Test_BandA dev;
    Mac_DataIndicationParameters indications[4];
    Mac_Frame frame;
    Mac_Counters counters;
    /* Table 82's 0x08 Coordinator Realignment: a command this module has no duty for, and no beacon path
       consumes it (the 0x07 Beacon Request has its own case, cases_beacon.c). */
    static const uint8_t nonPollCommand[1] = { 0x08 };
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t len;
    uint32_t got;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.ackRequest = 1;
    frame.panIdCompression = 1;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.destPan = PAN_ID;
    frame.srcPan = PAN_ID;
    frame.destShort = COORDINATOR_SHORT;
    frame.srcShort = SLEEPY_A;
    frame.seq = 0x2c;

    Test_ExpectStatus(MacFrame_Compose(&frame, nonPollCommand, (uint32_t)sizeof nonPollCommand, bytes,
                                  RADIO_MPDU_MAX, &len),
                 ZB_OK, "a command frame this module has no duty for (Table 82)");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK,
                 "closed by the footer those octets compute (7.2.11)");

    injectFrame(&dev.model, bytes, len, 9300);
    injectPoll(&dev.model, 0x2d, SLEEPY_B, 9400);
    Test_ExpectStatus(Mac_Step(&dev.mac, 400), ZB_OK, "one step takes the command and a poll");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.commandsHeard == 1, "the non-poll command is counted here");
    Test_Expect(counters.acksHeard == 0, "and it is not an acknowledgment: the two names are two facts");
    Test_Expect(counters.indicationQueue == 1 && counters.pollArrivalQueue == 1,
           "only the poll was delivered, and the poll's own handling is untouched");

    got = Mac_PollIndications(&dev.mac, indications, 4);
    Test_Expect(got == 1 && indications[0].frameType == (uint32_t)MAC_FRAME_TYPE_COMMAND
           && indications[0].payloadLen == 1
           && indications[0].bytes[indications[0].payloadOffset] == MAC_CMD_POLL,
           "the delivered command frame is the poll's, Table 7-11's 0x04, and not the realignment's: "
           "what was consumed here never entered the queue a layer above reads");
}
