/*
 * -------------------------------------------------------------------------------------
 * Part B: the receive policy.
 *
 * A received frame is put in front of the MAC the way a neighbor's frame is: composed as a MAC data frame,
 * every NWK frame, command frames included, rides as a MAC data frame with MAC security disabled (3.4.1.1),
 * closed with the footer those octets compute, and injected into the backend's receive queue. What the suite
 * then reads is what the network layer made of it: the indication it handed up, the table entries it created,
 * the counters it moved, and the frames it put back on the air.
 *
 * Nothing an injected frame does appears in the air log: the log is what this device transmitted, so "not
 * relayed" in these cases means exactly one thing, no new record in it.
 *
 * The addresses: SLEEPY2 is a second sleepy end device, so that a copy is owed to one of them and refused to
 * the other; OFFSPRING is the end device whose message arrives through somebody else's radio in case 9.
 * -------------------------------------------------------------------------------------
 *
 * This file carries the receive half's radius, class, dedup, indication, command and mark cases
 * The broadcast half of the same policy is `cases_broadcast.c` beside it,
 * and the secured crossing is `cases_security.c`. */

#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "nwk.h"
#include "nwk_frame.h"
#include "nwk_helpers.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

#define OFFSPRING 0x3333

/*
 * 6. The radius. A request that states none gets the network default 3.2.1.1.3 derives; a request that states
 * one gets what it stated. The trap is that zero is not zero hops, so the suite asserts the derived number
 * rather than the requested one and the derivation cannot quietly become a pass-through.
 */
void caseRadiusDerivation(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_OK, "a request that states no radius");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1, "one frame");
    Test_Expect(npduOf(&air[0])[6] == NWK_INITIAL_RADIUS,
                "carrying 30, which is 2 * nwkcMaxDepth (3.2.1.1.3 with Table 3-65): a Radius of zero asks for the network default");
    Test_Expect(NWK_INITIAL_RADIUS == 30, "and the constant is the derived number, because R23.1 prints no nwkcMaxRadius");

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 7);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 20), ZB_OK, "a request that states one");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 2, "a second frame");
    Test_Expect(npduOf(&air[1])[6] == 7, "carrying 7, which is a Radius inside the range Table 3-2 prints for the parameter (0x00-0xff) and this module writes as given");

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 255);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 30), ZB_OK, "and one that asks for the top of that range");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 3 && npduOf(&air[2])[6] == 255,
                "is accepted and carries 255: 3.6.1.9's hop limit of 2 * nwkcMaxDepth beside Table 3-2's 0xff parameter bound");
    Test_Expect(Nwk_RefusedRequests(&dev.nwk) == 0, "no refusal on this path");
}

/*
 * 2. The radius decrements on receipt, before this device decides anything, and the broadcast transaction table
 * is what makes a second copy of the same broadcast cost nothing.
 *
 * 3.3.1.4: "The radius field SHALL always be present. It will be 1 octet in length and specifies the range of a
 * radius-limited transmission. The field SHALL be decremented by 1 by each receiving device." 3.6.2.2 says the
 * same thing as a rule about receipt rather than about forwarding: "On receipt of each frame, the radius field of
 * the NWK header SHALL be decremented by 1."
 *
 * So the number a frame this device relays carries is the number after this device's own decrement, and a
 * retransmission of the same frame does not decrement it a second time, because the decrement is what *receipt*
 * costs and this device received the frame once. The relayed copy is otherwise the frame it came from, sequence
 * number and source address included: 3.6.4.3, "The router device relaying a packet SHALL leave the NWK Sequence
 * Number of the originating device in the NWK Sequence Number field".
 *
 * The second half is 3.6.6's dedup, on the pair the standard names: "the device SHALL compare the sequence
 * number and the source address of the broadcast frame with the records in its BTT. If the device has a BTR of
 * this particular broadcast frame in its BTT, it MAY update the BTR to mark the neighboring device as having
 * relayed the broadcast frame. It SHALL then drop the frame." The second copy here arrives from a *different*
 * neighbor, which is exactly the case the record is keyed without: the key is (source, sequence), not (source,
 * sequence, who it came from), and the per-neighbor mark 3.6.6 permits is the one Table 3-75 has no field for.
 */
void caseRadiusDecrementAndDedup(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 3, 7, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a broadcast with three hops left, from a neighbor");
    harvestAir(&dev.model, air, &airCount);

    got = Test_NwkPoll(&dev.nwk, inds, 4);
    Test_Expect(got == 1 && inds[0].radiusRemaining == 2,
          "the indication carries radius 2: the frame arrived with 3 and this device paid the decrement receipt costs (3.3.1.4, 3.6.2.2)");
    Test_Expect(got == 1 && inds[0].wasBroadcast == 1 && inds[0].dstAddr == NWK_ADDR_ALL_DEVICES,
          "and it says the frame arrived as a broadcast to 0xffff");
    Test_Expect(got == 1 && inds[0].securityUsed == 0,
          "with SecurityUse FALSE, which is what a frame whose security sub-field is clear reports on a device with no security attached at all");

    Test_Expect(airCount == 1, "the frame went out once more, because 3.6.6 makes a router or coordinator retransmit a new broadcast whose radius is greater than zero");
    Test_Expect(airDestOf(&air[0]) == NWK_ADDR_ALL_DEVICES && air[0].ackRequest == 0,
          "aimed at the class and asked for nothing: 'Broadcast transmissions SHALL NOT use the MAC sub-layer acknowledgement' (3.6.6)");
    Test_Expect(npduLenOf(&air[0]) == npduLen && npduDiffCount(npduOf(&air[0]), npduLenOf(&air[0]), npdu, npduLen) == 1,
          "the same NPDU with exactly one octet changed");
    Test_Expect(npduOf(&air[0])[NPDU_RADIUS_OCTET] == 2 && npdu[NPDU_RADIUS_OCTET] == 3,
          "and the changed octet is the radius: 2 on the copy, which is what this device read, not 1, which would be a device that decremented its own retransmission as well as its receipt");
    Test_Expect(npduOf(&air[0])[NPDU_SEQ_OCTET] == 7 && airSrcOf(&air[0]) == OWN_SHORT,
          "the originator's sequence number untouched, and the MAC source this device's own address: a relay relays the packet and does not republish it as its own (3.6.4.3, 3.3.1.3)");
    Test_Expect(Nwk_RelaysSent(&dev.nwk) == 1, "one relay counted");

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 3, 7, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "the same broadcast, from a different neighbor");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_DroppedDuplicate(&dev.nwk) == 1, "is dropped by the broadcast transaction table (3.6.6)");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 0, "and is not passed up");
    Test_Expect(airCount == 1, "and is not retransmitted either: a duplicate answers nobody twice");
    Test_Expect(Nwk_BttQueue(&dev.nwk) == 1, "one record, for one broadcast");
    Test_Expect(bttFor(&dev.nwk, NEIGHBOR, 7) != 0,
          "keyed on the pair Table 3-81 prints (the initiator's source address and its sequence number) and not on the neighbor it happened to arrive from");
    Test_Expect(Nwk_ConfirmsIgnored(&dev.nwk) == 1,
          "the MAC's answer to the relay is one this module cannot tie to a request it owes: 3.2.1.2.1, a relay owes no confirm");
}

/*
 * 3. A radius that reaches 0 is not retransmitted, and a radius that arrived at 0 is not wrapped.
 *
 * 3.6.2.2: "If, as a result of being decremented, this value falls to 0, the frame SHALL NOT, under any
 * circumstances, be retransmitted. It MAY, however, be passed to the next higher layer or otherwise processed by
 * the NWK layer as outlined elsewhere in this specification." The frame survives its own exhaustion as long as
 * it is addressed here (a broadcast this device is a destination of is indicated and not relayed) and the number
 * handed up is 0 rather than the 255 an octet subtraction would produce if nobody thought about it.
 *
 * A unicast addressed elsewhere with 0 hops left is the other half: the frame cannot be retransmitted and it is
 * not this device's, so nothing is delivered and the discard is counted. Band A counts it with the routing
 * refusals because the reason is that there is no path this device may take, not that the frame was aimed at
 * somebody else: the same reason 3.6.4.3 gives for a router that finds no routing entry, whose Network Status
 * reply with 0x04 for a device without routing capacity is deprecated by Table 3-56 and deferred.
 */
void caseRadiusExhausted(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 1, 11, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a broadcast with one hop left");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 1 && inds[0].radiusRemaining == 0,
          "is delivered with radius 0, which is what 3.6.2.2 permits a device to do with a frame it may not retransmit");
    Test_Expect(airCount == 0, "and is not retransmitted: 'SHALL NOT, under any circumstances'");
    Test_Expect(Nwk_BttQueue(&dev.nwk) == 1 && bttFor(&dev.nwk, NEIGHBOR, 11) != 0,
          "the record is still created: a new broadcast is recorded whether or not this device forwards it, and 3.6.6's dedup is a record's job");
    Test_Expect(bttFor(&dev.nwk, NEIGHBOR, 11)->relayed == 0,
          "and a record that was never relayed has no retransmission scheduled behind it, so the exhaustion holds across turns and not only inside one step");

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 0, 12, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "and a broadcast that arrived at 0");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 1 && inds[0].radiusRemaining == 0,
          "is delivered with 0, not 255: 3.3.1.4's decrement floors at zero rather than handing on a wrapped 255");
    Test_Expect(airCount == 0 && Nwk_RelaysSent(&dev.nwk) == 0, "and it is not retransmitted either");

    npduLen = makeNpdu(npdu, UNSEEN, NEIGHBOR, 1, 13, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 102), ZB_OK, "a unicast for another device with its last hop spent");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 0 && Nwk_DroppedNoRoute(&dev.nwk) == 1,
          "is discarded and counted with the routing refusals: 3.6.2.2 forbids the retransmission and there is no other thing this device may do with it");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 0, "and it is not indicated: the destination is not this device (3.6.2.2)");
}

/*
 * 4a. Table 3-80, read by a router that is listening.
 *
 * 3.6.6: "When a device receives a broadcast frame from a neighboring device, it SHALL compare the destination
 * address of the frame with its device type. If the destination address does not correspond to the device type
 * of the receiver as outlined in Table 3-80, the frame shall be discarded." The table prints five groups and two
 * reserved bands, and this case walks them: 0xffff "All devices in PAN", 0xfffd "macRxOnWhenIdle = TRUE", 0xfffc
 * "All routers and coordinator", 0xfffb "Low power routers only", 0xfffe and 0xfff8-0xfffa "Reserved".
 *
 * 0xfffb is the finding worth stating. That row is the only place in 649 pages where the phrase "low power
 * router" appears in R23.1, and chapter 3 gives a device nothing that would answer the question: Table 3-75's
 * device type prints 0x00 coordinator, 0x01 router and 0x02 end device and no fourth value, and no NIB attribute
 * in Table 3-66 says a router is a low power one. A group the standard never defines is a group this device
 * cannot prove it is in, so the frame is discarded, while `Nwk_DataRequest` will still put a frame on the air
 * for that address, because 3.6.6 lists it among the broadcast addresses a DstAddr may take. Sending to an
 * undefined group and refusing to be it is what the table as printed means for a stack that knows only that it
 * is a plain router.
 *
 * What the accepted three have in common here is that each is delivered *and* retransmitted: 3.6.6's relay
 * sentence is "If the device is a Zigbee router (ZR) or a Zigbee Coordinator (ZC) and the radius field is greater
 * than zero; then the frame shall be retransmitted. Otherwise it shall be dropped."
 */
void caseClassGatesAsRouter(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint32_t seq;

    rig(&dev, OWN_SHORT, PAN_ID);

    seq = 20;

    /* 0xffff, 0xfffd and 0xfffc: accepted, delivered, relayed. */
    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 2, seq, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a broadcast to 0xffff, 'All devices in PAN'");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 1, "a device of this stack is in that group, so it is delivered");
    Test_Expect(airBroadcastCount(air, airCount, NWK_ADDR_ALL_DEVICES) == 1, "and it is relayed");

    seq = 21;
    npduLen = makeNpdu(npdu, NWK_ADDR_RX_ON_WHEN_IDLE, NEIGHBOR, 2, seq, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "a broadcast to 0xfffd, 'macRxOnWhenIdle = TRUE'");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 1 && inds[0].dstAddr == NWK_ADDR_RX_ON_WHEN_IDLE,
          "accepted by the attribute the row names, read off the MAC's PIB mirror: this rig is a router with its receiver on, which is what an FFD is");
    Test_Expect(airClassCount(air, airCount, NWK_ADDR_RX_ON_WHEN_IDLE) == 1
                && airBroadcastCount(air, airCount, MAC_FRAME_ADDR_BROADCAST) == 2,
          "and relayed: the class rides the NWK header's destination field while every MAC destination on the air is 0xffff (3.2.1.1.3 step 6 a.3)");

    seq = 22;
    npduLen = makeNpdu(npdu, NWK_ADDR_ROUTERS, NEIGHBOR, 2, seq, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 102), ZB_OK, "and a broadcast to 0xfffc, 'All routers and coordinator'");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 1 && inds[0].dstAddr == NWK_ADDR_ROUTERS,
          "accepted because the device type this module was told says router (identity is configured, never inferred)");
    Test_Expect(airClassCount(air, airCount, NWK_ADDR_ROUTERS) == 1
                && airBroadcastCount(air, airCount, MAC_FRAME_ADDR_BROADCAST) == 3,
          "and relayed, which is what 3.6.4.5 uses this class for: a many-to-one route request, its class in the NWK header");

    /* 0xfffb: the class this device cannot state it belongs to. */
    seq = 23;
    npduLen = makeNpdu(npdu, NWK_ADDR_LOW_POWER_ROUTERS, NEIGHBOR, 2, seq, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 103), ZB_OK, "and a broadcast to 0xfffb, 'Low power routers only'");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 0, "is not delivered");
    Test_Expect(airClassCount(air, airCount, NWK_ADDR_LOW_POWER_ROUTERS) == 0 && Nwk_RelaysSent(&dev.nwk) == 3,
          "and is not relayed: a router of this stack has no way to know it is the low power kind, and 3.6.6 discards a frame whose destination group the receiver is not in");
    Test_Expect(Nwk_BttQueue(&dev.nwk) == 3, "and it never reached the broadcast transaction table either, because the class test runs before the record test");
    Test_Expect(Nwk_DroppedNotForMe(&dev.nwk) == 1, "counted as not for me");

    /* 0xfffe and 0xfff8-0xfffa: printed Reserved, so they correspond to no device type. */
    npduLen = makeNpdu(npdu, NWK_ADDR_RESERVED, NEIGHBOR, 2, 24, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 104), ZB_OK, "a frame addressed to 0xfffe, which Table 3-80 prints Reserved");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 0 && airCount == 3 && Nwk_DroppedNotForMe(&dev.nwk) == 2,
          "is discarded: an address that names no group cannot correspond to the receiver's device type either");

    /* A broadcast this device originated, heard again because a neighbour relayed it: the frame's NWK source is
       this device, and its MAC source is the neighbour that put it back on the air. A frame carrying this
       device's own MAC source as well never reaches this layer, band A consumes an echo of its own
       transmission, so the reachable shape is the relayed one, and it is the shape
       3.6.6's warm-up sentence is about. */
    seq = 25;
    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, OWN_SHORT, 2, seq, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 105), ZB_OK, "and a broadcast whose NWK source is this device itself");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 0 && airBroadcastCount(air, airCount, MAC_FRAME_ADDR_BROADCAST) == 3
                && Nwk_DroppedNotForMe(&dev.nwk) == 3,
          "is neither delivered nor retransmitted: 3.6.6, a broadcast whose NWK source is this device is not processed");
    Test_Expect(Nwk_BttQueue(&dev.nwk) == 3, "and it is not recorded, which is what keeps a device from dedupping a broadcast it never accepted");
}

/*
 * 4b. The same table read by an end device that cannot hear.
 *
 * 3.6.6's record duty and relay duty are both stated about devices that listen: "The Zigbee coordinator, each
 * Zigbee router and those Zigbee end devices with macRxOnWhenIdle equal to TRUE, SHALL keep a record of any new
 * broadcast transaction", and "Zigbee end devices with macRxOnWhenIdle equal to FALSE SHALL NOT participate in
 * the relaying of broadcast frames and need not maintain a BTT for broadcast frames that they originate". A
 * device with no table has no dedup either (the record and the duplicate check are one machine), which this
 * case asserts as plainly as it asserts the class gates.
 *
 * The End Device Initiator half is 3.6.2.2's own item 1: "If the receiving device is an end device the message
 * SHALL be dropped, and no further processing SHALL be done."
 */
void caseClassGatesAsEndDevice(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_END_DEVICE, 0);

    npduLen = makeNpdu(npdu, NWK_ADDR_RX_ON_WHEN_IDLE, NEIGHBOR, 2, 30, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "an end device whose receiver is off is asked for the devices that are listening");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 0 && Nwk_DroppedNotForMe(&dev.nwk) == 1,
          "and Table 3-80's row excludes it: 0xfffd is macRxOnWhenIdle = TRUE and this device's macRxOnWhenIdle is FALSE");

    npduLen = makeNpdu(npdu, NWK_ADDR_ROUTERS, NEIGHBOR, 2, 31, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "and it is asked for the routers and the coordinator");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 0 && Nwk_DroppedNotForMe(&dev.nwk) == 2,
          "which an end device is not (Table 3-75's 0x02)");

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 2, 32, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 102), ZB_OK, "but 0xffff means every device in the PAN, including it");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 1 && inds[0].radiusRemaining == 1, "delivered, with the decrement paid");
    Test_Expect(airCount == 0 && Nwk_RelaysSent(&dev.nwk) == 0,
          "and not relayed: 3.6.6's relay sentence is a router or coordinator's, and the same paragraph forbids an end device with its receiver off to 'participate in the relaying of broadcast frames'");
    Test_Expect(Nwk_BttQueue(&dev.nwk) == 0, "and with no broadcast transaction table at all, because 3.6.6's record duty names coordinators, routers and the end devices that are listening");

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 2, 32, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 103), ZB_OK, "the same broadcast a second time");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 1 && Nwk_DroppedDuplicate(&dev.nwk) == 0,
          "is delivered a second time, which is the honest consequence of having no table: 3.6.6 lets such a device skip the BTT, and a device with no record cannot recognize its own duplicate");

    npduLen = makeNpdu(npdu, OWN_SHORT, NEIGHBOR, 2, 33, NWK_FRAME_TYPE_DATA, 1, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 104), ZB_OK, "and a frame with the End Device Initiator sub-field set, addressed to this device");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 0 && Nwk_DroppedNotForMe(&dev.nwk) == 3,
          "is dropped with no further processing even though it is addressed to it: 3.6.2.2 item 1, an end device not its parent");
    Test_Expect(Nwk_NeighborQueue(&dev.nwk) == 1,
          "and it created no neighbor entry either: 'no further processing SHALL be done' is the whole of the instruction, and the observation belongs to the frames this module acts on");
}

/*
 * 1. A unicast addressed to this device is finished here.
 *
 * 3.6.2.2 is the clause: "The following data frames SHALL be passed to the next higher layer using the
 * NLDE-DATA.indication primitive: … Unicast data frames and source-addressed data frames for which the
 * destination address matches the device's network address." Nothing else happens to such a frame: the relay
 * rules of 3.6.2.2 and 3.6.4.3 are the rules for a unicast whose destination is *not* this device's address,
 * and a radius left over is not a reason to put somebody else's finished frame back on the air.
 *
 * The indication carries Table 3-4's parameters, and the one of them a naive stack gets wrong is SrcAddr: "The
 * individual device address from which the NSDU originated", the originator and not the previous hop. This
 * case injects a frame whose MAC source and NWK source are the same device, and asserts both the address the
 * indication names and the neighbor entry the same frame created: the two places a received frame is allowed
 * to leave a fact about where it came from.
 */
void caseReceiveUnicastForMe(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    Nwk_NeighborTableEntry *neighbor;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);

    npduLen = makeNpdu(npdu, OWN_SHORT, UNSEEN, 5, 0x40, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, UNSEEN);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a unicast from a device this stack has never heard of");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 0, "and nothing went out: the frame was addressed here, so it is finished here (3.6.2.2), whatever its radius says");
    Test_Expect(Nwk_RelaysSent(&dev.nwk) == 0, "and nothing was counted as relayed");

    got = Test_NwkPoll(&dev.nwk, inds, 4);
    Test_Expect(got == 1, "the frame is passed up once, as an NLDE-DATA.indication (3.2.1.3.1, Table 3-4)");
    Test_Expect(inds[0].dstAddr == OWN_SHORT && inds[0].srcAddr == UNSEEN,
          "DstAddr is this device and SrcAddr the device the NSDU came from: Table 3-4's SrcAddr is the originator, not the hop");
    Test_Expect(inds[0].seq == 0x40 && inds[0].radiusRemaining == 4,
          "the sequence number as the originator numbered it (3.3.1.5) and the radius as this device read it after its own decrement (3.3.1.4)");
    Test_Expect(inds[0].frameType == NWK_FRAME_TYPE_DATA && inds[0].commandIdentifier == 0 && inds[0].wasBroadcast == 0,
          "a data frame, no command identifier, and not a broadcast");
    Test_Expect(inds[0].lqi == 200,
          "LQA, which Table 3-4 prints on the indication and which this module can only carry up from the frame it was delivered with (Table 8-32's MpduLinkQuality)");
    Test_Expect(inds[0].nsduLength == NSDU_LEN && Zb_memcmp(inds[0].nsdu, nsdu, NSDU_LEN) == 0,
          "and the NSDU itself, octet for octet: Figure 3-7 makes a data frame's payload region the octets the layer above asked for");

    Test_Expect(got == 1 && inds[0].securityUsed == 0,
          "and Table 3-4's SecurityUse reads FALSE: the parameter is the frame's own security sub-field, reported just as plainly by a scaffold device as by one that runs security");

    Test_Expect(Nwk_NeighborQueue(&dev.nwk) == 1, "the frame left one neighbor entry behind (Table 3-66 prints nwkNeighborTable as a 'Null set' that observation fills)");
    neighbor = neighborAt(&dev.nwk, UNSEEN);
    Test_Expect(neighbor != 0 && neighbor->deviceType == NWK_NEIGHBOR_TYPE_UNKNOWN
                && neighbor->relationship == NWK_REL_NONE && neighbor->ieeeKnown == 0 && neighbor->ageFromMs == 100,
          "an entry that states only what the frame could state: Table 3-75's 0x03 relationship, no device type, no receiver duty");
    Test_Expect(neighbor != 0 && neighbor->rxOnWhenIdle == 0,
          "and its rxOnWhenIdle unstated for the same reason: one frame says nothing about whether its sender listens, and 3.6.6 copies frames on the strength of that field");

    npduLen = makeNpdu(npdu, OWN_SHORT, UNSEEN, 5, 0x40, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, UNSEEN);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "the same frame again: same source, same sequence number");
    got = Test_NwkPoll(&dev.nwk, inds, 4);
    Test_Expect(got == 1 && inds[0].seq == 0x40,
          "is delivered again: 3.3.1.5 only says the (source, sequence) pair MAY identify a frame, 3.6.2.2 tolerates the gap");
    Test_Expect(Nwk_DroppedDuplicate(&dev.nwk) == 0, "and the duplicate counter is a broadcast's counter, unmoved here");

    Test_Expect(Nwk_DroppedMalformed(&dev.nwk) == 0 && Nwk_DroppedUnsupported(&dev.nwk) == 0
                && Nwk_DroppedNotForMe(&dev.nwk) == 0 && Nwk_DroppedNoRoute(&dev.nwk) == 0
                && Nwk_DroppedIndications(&dev.nwk) == 0 && Nwk_BttFullDrops(&dev.nwk) == 0
                && Nwk_BttQueue(&dev.nwk) == 0 && Nwk_RecognizedCommands(&dev.nwk) == 0
                && Nwk_ReplyCommands(&dev.nwk) == 0 && Nwk_NeighborAddsRefused(&dev.nwk) == 0,
          "and a frame delivered straight to the layer above needed no refusal of any kind");
}

/*
 * 11. The frames that are not frames at all, and the forms this stack does not have.
 *
 * A received frame is judged by the codec before it is judged by the policy, and that is the point of chapter 3's
 * strictness: the octets either describe an NPDU this stack can read or they do not, and a device that reads a
 * header it is unsure about has already invented part of one. Two counters, because two different things are
 * being refused: `droppedMalformed` for octets that do not add up, and `droppedUnsupported` for a form this stack
 * has deliberately not built, Table 1-5's version 0x03 and Table 3-52's reserved and Inter-PAN frame types, and a
 * secured NPDU at a device that has no key to read it with. A deferral the stack chose has to be countable as a
 * deferral, and a truncated frame is not the same event as an unknown one.
 *
 * Protocol version 0x01 is in the middle and belongs in a suite: Table 1-5 says a conforming device "SHALL
 * discard all frames carrying a protocol version sub-field value other than 0x01, 0x02, or0x03. It SHALL process
 * only protocol versions of 0x01 or 0x02, consistent with the protocol version of the network that the device
 * participates within", so 0x01 is read and delivered, in the shape 0x02 defines, while `nwk_frame` still
 * refuses to *send* it (nwkcProtocolVersion is 0x02) and Table 1-5's own note that a 0x02 network owes no
 * backwards compatibility is what makes that refusal the honest one.
 *
 * The last frame is one the module below has already disowned: a delivered PSDU whose footer does not match the
 * octets it carries. `mac` reports it as an indication with a status, and the network layer does not reach past
 * a carrier it cannot vouch for.
 */
void caseUnreadableAndUnsupportedFrames(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);

    /* Shorter than the eight octets 3.3.1.2 … 3.3.1.5 make always-present. */
    npduLen = makeNpdu(npdu, OWN_SHORT, NEIGHBOR, 2, 90, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, NWK_MIN_HEADER_OVERHEAD - 1, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a frame with seven octets of NWK header");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(Nwk_DroppedMalformed(&dev.nwk) == 1 && Test_NwkPoll(&dev.nwk, inds, 4) == 0,
          "is not an NPDU: nwkcMinHeaderOverhead 0x08 is the floor the codec holds it to (Table 3-65, 3.3.1.2 … 3.3.1.5)");

    /* The security sub-field, at a device with no `Security` attached. */
    npduLen = rawNpdu(npdu, NWK_FCF_DATA_SECURED, OWN_SHORT, NEIGHBOR, 2, 91, nsdu, NSDU_LEN, 0);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "and a frame whose security sub-field is set");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(Nwk_DroppedUnsupported(&dev.nwk) == 1 && Nwk_DroppedMalformed(&dev.nwk) == 1
                && Test_NwkPoll(&dev.nwk, inds, 4) == 0,
          "is counted as unsupported and not as malformed: 4.3.1.2's auxiliary header and MIC, readable to the crossing and not here");

    /* Protocol version 0x03, Green Power: Table 1-5 hands it to the Interpan APS, which this stack has not built. */
    npduLen = rawNpdu(npdu, NWK_FCF_DATA_V3, OWN_SHORT, NEIGHBOR, 2, 92, nsdu, NSDU_LEN, 0);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 102), ZB_OK, "and a frame at protocol version 0x03");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(Nwk_DroppedUnsupported(&dev.nwk) == 2 && Test_NwkPoll(&dev.nwk, inds, 4) == 0,
          "is dropped the same way: Table 1-5 hands protocol version 0x03 to the Interpan APS, a path band A has no end of");

    /* Frame type 0b10, which Table 3-52 prints Reserved. */
    npduLen = rawNpdu(npdu, NWK_FCF_RESERVED_TYPE, OWN_SHORT, NEIGHBOR, 2, 93, nsdu, NSDU_LEN, 0);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 103), ZB_OK, "and a frame whose type is the reserved one");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(Nwk_DroppedUnsupported(&dev.nwk) == 3 && Test_NwkPoll(&dev.nwk, inds, 4) == 0,
          "is unsupported too, not malformed: the type exists in the table and this stack has no layout for it");

    /* Protocol version 0x01: processed, in 0x02's shape. */
    npduLen = rawNpdu(npdu, NWK_FCF_DATA_V1, OWN_SHORT, NEIGHBOR, 2, 94, nsdu, NSDU_LEN, 0);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 104), ZB_OK, "and a frame at protocol version 0x01");
    harvestAir(&dev.model, air, &airCount);

    got = Test_NwkPoll(&dev.nwk, inds, 4);
    Test_Expect(got == 1 && inds[0].radiusRemaining == 1 && inds[0].nsduLength == NSDU_LEN,
          "is processed: Table 1-5 makes 0x01 and 0x02 the two versions a device processes, as one NPDU shape");
    Test_Expect(airCount == 0,
          "and it is not relayed here: nwkcProtocolVersion is 0x02 and Table 1-5 needs no backwards compatibility of it");

    /* A frame the module below has already disowned. */
    npduLen = makeNpdu(npdu, OWN_SHORT, NEIGHBOR, 2, 95, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectBrokenNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 105), ZB_OK, "and a well-formed NPDU inside a MAC frame whose footer does not match");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(Nwk_DroppedMalformed(&dev.nwk) == 1 && Test_NwkPoll(&dev.nwk, inds, 4) == 0
                && airCount == 0,
          "is never offered to this layer: 6.6.2 and 7.2.11 discard it at the MAC, so nothing here counts it and no relay answers it");

    Test_Expect(Nwk_BttQueue(&dev.nwk) == 0 && Nwk_RelaysSent(&dev.nwk) == 0 && Nwk_DroppedNotForMe(&dev.nwk) == 0
                && Nwk_DroppedNoRoute(&dev.nwk) == 0 && Nwk_DroppedDuplicate(&dev.nwk) == 0
                && Nwk_DroppedIndications(&dev.nwk) == 0 && Nwk_RecognizedCommands(&dev.nwk) == 0
                && Nwk_ReplyCommands(&dev.nwk) == 0 && Nwk_NeighborAddsRefused(&dev.nwk) == 0,
          "and no unreadable frame created a record, a relay or a further refusal");
    Test_Expect(Nwk_NeighborQueue(&dev.nwk) == 1,
          "and exactly one neighbor entry exists, for the one frame that was readable enough to be delivered: an address this module could not reach through a header is not an address it observed");

    /* The NSDU ceiling and the MAC's payload ceiling are the same number reached two ways: aMaxPHYPacketSize 127
       less nwkcMACFrameOverhead 11 is 116 for the NPDU, and the eight always-present header octets leave 108 for the
       NSDU. An NSDU one octet longer therefore cannot arrive at all, which is why the receive-side length drop is a
       guard rather than a path a peer can reach. */
    Test_ExpectCount((uint32_t)NWK_FRAME_NPDU_MAX, 116,
                     "Table 3-2's ceiling for an NPDU is aMaxPHYPacketSize less nwkcMACFrameOverhead");
    Test_ExpectCount((uint32_t)NWK_NSDU_MAX, (uint32_t)(NWK_FRAME_NPDU_MAX - NWK_MIN_HEADER_OVERHEAD),
                     "and an NSDU of one octet more than that has no NPDU to ride in: 116 less the eight always-present header octets is 108");
}

/*
 * 58.a A delivered carrier that is not a data frame ("a MAC frame that is not a data frame is not an
 * NPDU carrier … the poll keeps the poll's own handling: the poll indication stands and the raw command
 * frame stops doubling as a malformed NPDU at the NWK door").
 *
 * Before this row the poll `mac` delivers was parsed here like any other delivery, failed the eight-octet
 * minimum of 3.3.1.2 … 3.3.1.5, and was counted as damage: a network layer reporting its own neighbor's
 * traffic as a broken frame. The gate below is `mac`'s parsed frame type, carried on the indication for
 * exactly that reason, and it runs before a single NPDU octet is read.
 */
void casePollCarrierIsNotAnNpdu(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint32_t airCount = 0;
    Mac_Counters counters;

    rig(&dev, OWN_SHORT, PAN_ID);

    composePoll(&dev.model, 9, SLEEPY);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK,
                      "the turn a poll arrives on: this module steps the MAC that delivers it");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1, "and the MAC answered the poll the way a poll is answered: that half is untouched");
    Test_Expect(Nwk_CarrierOther(&dev.nwk) == 1,
                "the poll is counted as the carrier it is: delivered, not an NPDU");
    Test_Expect(Nwk_DroppedMalformed(&dev.nwk) == 0 && Nwk_DroppedUnsupported(&dev.nwk) == 0,
                "and it is neither damage nor a form this stack declines to read: nothing about a Data Request command says the frame is broken, and the old reading said it was");
    Test_Expect(Nwk_DroppedNotForMe(&dev.nwk) == 0 && Nwk_DroppedNoRoute(&dev.nwk) == 0
                && Nwk_DroppedDuplicate(&dev.nwk) == 0 && Nwk_DroppedUnsecured(&dev.nwk) == 0,
                "and no other gate of this module saw it either: the carrier decision stops the frame before the destination, the radius, the table and the security policy are reached");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 0 && Nwk_IndicationQueue(&dev.nwk) == 0,
                "nothing was handed up to the layer above this one, which is the whole point of counting it instead");
    Test_Expect(Nwk_RelaysSent(&dev.nwk) == 0 && Nwk_BttQueue(&dev.nwk) == 0 && Nwk_NeighborQueue(&dev.nwk) == 0,
                "no relay, no broadcast record and no neighbor observation came out of it: a poll carries no NWK source for this module to observe");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.indicationQueue == 0,
                "and the indication was consumed rather than left waiting: one poll, one carrier, one count");
}

/*
 * 8. The fifteen identifiers Table 3-54 prints, the reply for the ones this layer does not support, and the
 * broadcast commands that ride the broadcast rules.
 *
 * Table 3-54 lists 0x01 Route Request through 0x0f Network Commissioning Response and prints "0x10-0xff" beneath
 * them as Reserved; 3.3.2.2.2 says the identifier field "SHALL be set to one of the non-reserved values listed
 * in Table 3-54". Band A acts on three of the fifteen (0x01 by 3.6.4.5.1, 0x02 by 3.6.4.5.2, and 0x03 by
 * indication, which is what 3.6.2.2's "Network status command frames SHALL be handled in the same manner as data
 * frames" leaves it) and the other twelve are "unsupported" in 3.6.13's sense as much as the Reserved band is:
 *
 *   "Whenever an unknown or unsupported unicast NWK command is received and the NWK Destination of the frame is
 *    the address of the local device, it SHALL do the following: … 2. Set the Status field of the command to
 *    0x13, Unknown Command."
 *
 * So a rejoin request, a Route Record or a Link Status exchange addressed to this device is answered, and its
 * machinery is still deferred. What is *not* answered is a broadcast: the clause is written for a unicast whose
 * destination is this device, and a broadcast command rides 3.6.6's rules where it is indicated and relayed like
 * any broadcast frame.
 */
void caseCommandRecognitionAndUnknownReply(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    Nwk_Frame parsed;
    uint8_t payload[5];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t payloadOffset;
    uint32_t payloadLen;
    uint32_t airCount = 0;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);

    /* 0x06, a rejoin request: recognized by Table 3-54 and not supported by this layer, so 3.6.13 answers it. */
    payload[0] = NWK_CMD_REJOIN_REQUEST;
    npduLen = makeNpdu(npdu, OWN_SHORT, NEIGHBOR, 2, 70, NWK_FRAME_TYPE_COMMAND, 0, payload, 1);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a rejoin request addressed to this device");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1 && airDestOf(&air[0]) == NEIGHBOR,
          "draws one frame back at its sender: Table 3-54's 0x06 is unsupported here, so 3.6.13 answers the unknown unicast command");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 0 && Nwk_RecognizedCommands(&dev.nwk) == 0,
          "and it is not handed up: the frame 3.6.13 answers is answered at this layer and nowhere else");
    Test_Expect(Nwk_ReplyCommands(&dev.nwk) == 1, "the reply is counted");

    /* 0x10, inside the band Table 3-54 prints Reserved: the same reply, and the same three octets. */
    payload[0] = 0x10;
    npduLen = makeNpdu(npdu, OWN_SHORT, NEIGHBOR, 2, 71, NWK_FRAME_TYPE_COMMAND, 0, payload, 1);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "and an identifier from the Reserved band, addressed to this device");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 2, "draws exactly one more frame out of this device");
    Test_Expect(airDestOf(&air[1]) == NEIGHBOR && air[1].ackRequest == 1,
          "aimed at the device that sent it and asking acknowledgement: 3.6.13 step 5's NWK Destination, 3.4.3.1's unicast ask");

    Test_ExpectStatus(NwkFrame_Parse(npduOf(&air[1]), npduLenOf(&air[1]), &parsed, &payloadOffset, &payloadLen), ZB_OK,
                  "and the frame this module composed is one this module's own codec reads back");
    Test_Expect(parsed.frameType == NWK_FRAME_TYPE_COMMAND && parsed.destAddr == NEIGHBOR && parsed.srcAddr == OWN_SHORT,
          "a command frame, from this device to the offender");
    Test_Expect(parsed.radius == NWK_INITIAL_RADIUS,
          "with the radius NLDE-DATA.request gives an unstated one (2 * nwkcMaxDepth) because 3.4.3.2 prints no radius rule for a Network Status frame the way 3.4.4.2 prints one for a Leave");
    Test_Expect(payloadLen == 3 && parsed.sequenceNumber == 1,
          "three octets of payload: Figure 3-61's Command ID and 3.4.3.3.1's Status, 3.4.3.3.2's address field absent");

    if (payloadLen <= (uint32_t)sizeof payload)
        Zb_memcpy(payload, npduOf(&air[1]) + payloadOffset, payloadLen);

    Test_Expect(payloadLen == 3 && payload[0] == NWK_CMD_NETWORK_STATUS,
          "first octet 0x03, the Network Status identifier");
    Test_Expect(payloadLen == 3 && payload[1] == NWK_NETWORK_STATUS_UNKNOWN_COMMAND,
          "then the status code 0x13: 3.6.13 step 2, 'Set the Status field of the command to 0x13, Unknown Command', and Table 3-56, 'The NWK command ID is not known to the device'");
    Test_Expect(payloadLen == 3 && payload[2] == 0x10,
          "then the one octet Figure 3-61 requires, 'Octets: 1, Command ID', carrying the identifier that was not supported (3.6.13 step 4)");
    Test_Expect(Nwk_ReplyCommands(&dev.nwk) == 2, "and the reply is counted");

    /* 0x01, a route request: consumed by 3.6.4.5.1, so neither indicated upward nor answered by 3.6.13. */
    payload[0] = NWK_CMD_ROUTE_REQUEST;
    npduLen = makeNpdu(npdu, OWN_SHORT, NEIGHBOR, 2, 72, NWK_FRAME_TYPE_COMMAND, 0, payload, 1);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 102), ZB_OK, "and a Route Request addressed to this device");
    harvestAir(&dev.model, air, &airCount);

    got = Test_NwkPoll(&dev.nwk, inds, 4);
    Test_Expect(got == 0 && Nwk_DroppedMalformed(&dev.nwk) == 1,
          "is not handed up at all: 3.6.4.5.1 is a procedure of this layer, and one payload octet cannot hold 3.4.1.3's six fields, so this frame is counted as damage and the layer above hears nothing");
    Test_Expect(airCount == 2 && Nwk_ReplyCommands(&dev.nwk) == 2,
          "and it draws no Unknown-Command reply: 0x01 is a command this layer processes, so 3.6.13 has nothing to answer");

    /* 0x08, a link status: 3.6.4.4.2 is this layer's own procedure, so the frame is neither indicated upward nor
       relayed, and 3.6.4.4.1 makes it a one-hop broadcast in the first place. */
    payload[0] = NWK_CMD_LINK_STATUS;
    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 2, 73, NWK_FRAME_TYPE_COMMAND, 0, payload, 1);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 103), ZB_OK, "a Link Status broadcast");
    harvestAir(&dev.model, air, &airCount);

    got = Test_NwkPoll(&dev.nwk, inds, 4);
    Test_Expect(got == 0, "is not handed up: 3.6.4.4.2 processes it in this layer");
    Test_Expect(airBroadcastCount(air, airCount, NWK_ADDR_ALL_DEVICES) == 0 && Nwk_BttQueue(&dev.nwk) == 0,
          "and is not relayed and not recorded, 3.6.4.4.1 making it a one-hop broadcast without retries");
    Test_Expect(Nwk_ReplyCommands(&dev.nwk) == 2,
          "and nothing is answered: 3.6.13 is written for a unicast whose destination is the local device, and this frame's destination is a class");

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 2, 73, NWK_FRAME_TYPE_COMMAND, 0, payload, 1);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 104), ZB_OK, "and the same Link Status broadcast from another neighbor");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_DroppedDuplicate(&dev.nwk) == 0 && Test_NwkPoll(&dev.nwk, inds, 4) == 0,
          "is processed again rather than deduplicated: there is no Table 3-81 record to find it in");
    Test_Expect(airBroadcastCount(air, airCount, NWK_ADDR_ALL_DEVICES) == 0, "and nothing goes back on the air");
    Test_Expect(Nwk_RecognizedCommands(&dev.nwk) == 0 && Nwk_RelaysSent(&dev.nwk) == 0,
          "no identifier handed up and nothing relayed: 0x08 is a command this layer consumes");
    Test_Expect(Nwk_DroppedNotForMe(&dev.nwk) == 0 && Nwk_DroppedMalformed(&dev.nwk) == 3 && Nwk_DroppedUnsupported(&dev.nwk) == 0,
          "with nothing refused, and the three unreadable frames being the route request payload too short to be one and the two link status payloads too short to carry a list");
}

/*
 * 9. The lost child.
 *
 * 3.6.2.3 is the whole clause, and the reading that matters is which entry it marks. Step 1 searches for an
 * entry whose Network Address matches the message's **NWK Source** field; step 2 requires that entry to be a
 * Zigbee End Device; step 3 requires the message's MAC source to be somebody else; step 5 then marks "the
 * corresponding neighbor table entry" (the one step 1 found, the end device whose message arrived through
 * another router's radio) with 0x07, neighbor is a lost child. The device that carried the frame is not the
 * child this device lost, and the clause never says to mark it.
 *
 * Two bounds on what band A can do with it. Step 2 needs a neighbor entry that already states a device type, and
 * an entry this module created from an address it heard states none, so only a table that already knows the NWK
 * source is an end device reaches step 5, and learning that is association, which is ZDO work that is deferred.
 * And the sentence after the steps is a deletion this stack cannot time: "The NLME SHALL evaluate the neighbor
 * table after the APS layer has processed the message to ascertain if the Relationship field has a value of 0x07,
 * neighbor is a lost child. If the field is still 0x07 then the neighbor table entry SHALL be deleted." The APS
 * layer band A has no equivalent of is the thing the evaluation waits for, the clause's own example is
 * "sufficient time (as an example 1 second) for the APS layer to process the message and examine whether the
 * stack has an address conflict, such as is done for ZDO Device_annce", so band A marks and never deletes, and a
 * 0x07 entry stays.
 */
void caseLostChildMark(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    Nwk_NeighborTableEntry *child;
    Nwk_NeighborTableEntry *carrier;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, OFFSPRING, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    npduLen = makeNpdu(npdu, OWN_SHORT, OFFSPRING, 4, 80, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK,
                  "a unicast addressed to this device, whose NWK source is an end device this router holds a child entry for and whose MAC source is a different router");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 0, "it is delivered here and not relayed on: the destination is this device");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 1 && inds[0].srcAddr == OFFSPRING,
          "and the indication names the originator, which is the address the frame was sent from and not the address it arrived from (Table 3-4)");

    child = neighborAt(&dev.nwk, OFFSPRING);
    carrier = neighborAt(&dev.nwk, NEIGHBOR);

    Test_Expect(child != 0 && child->relationship == NWK_REL_LOST_CHILD,
          "the child's entry (keyed on the NWK source, the entry 3.6.2.3 step 1 finds) now says 0x07, 'neighbor is a lost child' (step 5)");
    Test_Expect(carrier != 0 && carrier->relationship == NWK_REL_SIBLING,
          "and the entry for the MAC source, the router that carried the frame, is untouched: 3.6.2.3 marks the child this device lost and not the neighbor that delivered the message");
    Test_Expect(child != 0 && child->deviceType == NWK_DEVICE_END_DEVICE,
          "the entry stayed the type it was told to be: a frame this module consumed never supplies a device type, and step 2 of the clause reads one");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + NWK_LOST_CHILD_EVALUATION_MS - 1), ZB_OK,
                      "the last turn inside the window the clause allows the APS layer, with nothing else received");
    harvestAir(&dev.model, air, &airCount);

    child = neighborAt(&dev.nwk, OFFSPRING);
    Test_Expect(child != 0 && child->relationship == NWK_REL_LOST_CHILD,
          "the entry is still there and still 0x07 while 3.6.2.3's window runs: the mark is kept for a conflict found inside it");
    Test_Expect(Nwk_LostChildrenDeleted(&dev.nwk) == 0 && Nwk_NeighborQueue(&dev.nwk) == 2,
          "and the evaluation has deleted nothing yet: the window has not closed");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + NWK_LOST_CHILD_EVALUATION_MS), ZB_OK,
                      "and the first turn after the window closes");
    harvestAir(&dev.model, air, &airCount);

    child = neighborAt(&dev.nwk, OFFSPRING);
    Test_Expect(child == 0 && Nwk_LostChildrenDeleted(&dev.nwk) == 1 && Nwk_NeighborQueue(&dev.nwk) == 1,
          "deletes the entry that is still 0x07: 'If the field is still 0x07 then the neighbor table entry SHALL be deleted' (3.6.2.3)");
    Test_Expect(Nwk_DroppedNoRoute(&dev.nwk) == 0 && Nwk_RelaysSent(&dev.nwk) == 0 && Nwk_DroppedNotForMe(&dev.nwk) == 0,
          "and the examination of a parent change cost nothing else: no drop, no relay, no entry created");
}

/*
 * 3.6.7 deprecates network-level multicast, and 3.3.1.2 makes the distinction the frame control field's bit 8
 * carries: "If the multicast flag sub-field of the frame control field has the value 0, the destination address
 * field SHALL hold the 16-bit network address of the destination device or a broadcast address." With the bit
 * set the sixteen bits are a group id, so the codec's destination field is not an address at all, and a layer
 * that compared it with its own address would deliver a frame aimed at a group to whichever device happens to
 * own that number, deduplicate it, and relay it onward as unicast data.
 */
void caseMulticastFrameIsRefusedOnReceipt(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t payload[NSDU_LEN];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    Zb_memcpy(payload, nsdu, NSDU_LEN);

    /* A data frame with the multicast bit set, its group id equal to this device's own network address: the
       shape that would be delivered as a unicast if nothing refused it. */
    npduLen = rawNpdu(npdu, (uint16_t)(NWK_FCF_DATA | (1 << NWK_FRAME_FCF_MULTICAST_SHIFT)), OWN_SHORT, NEIGHBOR,
                      4, 0x21, payload, NSDU_LEN, 0);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a frame whose multicast bit is set, its group id equal to this device's own address");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_DroppedMulticast(&dev.nwk), 1,
                     "is refused as the form it is, counted under its own name: the destination field is a group id (3.3.1.2), and this stack neither writes the form nor reads one");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 0,
                     "and nothing is handed up: a group id is not the address of the device the frame reached");
    Test_ExpectCount(Nwk_NeighborQueue(&dev.nwk), 0,
                     "no neighbour entry is made for the source of a frame this layer did not accept");
    Test_ExpectCount(airCount, 0, "and none is relayed");
    Test_ExpectCount(Nwk_DroppedMalformed(&dev.nwk), 0,
                     "nor is it damage: the octets are a well-formed NPDU of a deprecated form");

    /* The same frame without the bit is a unicast to this device and is delivered, which is the difference the
       bit makes. */
    npduLen = rawNpdu(npdu, NWK_FCF_DATA, OWN_SHORT, NEIGHBOR, 4, 0x22, payload, NSDU_LEN, 0);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "and the same sixteen bits as a destination address");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 1,
                     "are delivered to this device, the multicast bit being the whole of the difference");
}

/*
 * Table 3-4's NsduLength: "0 to aMaxPHYPacketSize – (nwkcMACFrameOverhead + nwkcMinHeaderOverhead)", which is
 * 127 - (0x0b + 0x08) = 108, the same ceiling 3.2.1.1.1 puts on a request, and the last NSDU a 127-octet PSDU
 * can carry behind these two headers. The ring's array is that number: a pool one octet wider would hand the
 * layer above an NSDU outside the parameter's printed range, under a comment claiming chapter 3 bounds no
 * received length at all.
 */
void caseIndicationIsBoundedByTable34sNsduLength(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t payload[NWK_NSDU_MAX];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    Test_ExpectCount(NWK_NSDU_MAX, 127 - (0x0b + 0x08),
                     "NsduLength's ceiling is aMaxPHYPacketSize less nwkcMACFrameOverhead 0x0b and nwkcMinHeaderOverhead 0x08 (Table 3-4)");

    rig(&dev, OWN_SHORT, PAN_ID);
    Zb_memset(payload, 0x5a, (uint32_t)sizeof payload);

    /* 108 octets of NSDU: the ceiling, and the last payload a 127-octet PSDU leaves room for */
    npduLen = makeNpdu(npdu, OWN_SHORT, NEIGHBOR, 4, 0x32, NWK_FRAME_TYPE_DATA, 0, payload, NWK_NSDU_MAX);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "a data frame carrying 108 octets, the ceiling itself");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 1 && inds[0].nsduLength == NWK_NSDU_MAX,
                "is delivered whole, at the parameter's own range: Table 3-4 prints its top as inclusive");
    Test_Expect(Zb_memcmp(inds[0].nsdu, payload, NWK_NSDU_MAX) == 0,
                "with every octet of it, unaugmented and untruncated");
    Test_ExpectCount(Nwk_DroppedIndications(&dev.nwk), 0, "and nothing was refused");
}

/*
 * 3.6.2.2, in the middle of its relay paragraph: "Route reply command frames for which the destination address
 * does not match the device's network address SHALL be discarded immediately. Network status command frames
 * SHALL be handled in the same manner as data frames." A Network Status frame addressed to somebody else is
 * therefore carried onward by 3.6.4.3's rules like any unicast data frame, and a router that refused every
 * command frame it was not the destination of would kill the one report the NWK layer sends about a broken
 * link two hops away from the source that needs it.
 */
void caseUnicastNetworkStatusIsRelayed(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t payload[3];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, UNSEEN, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    /* 0x03 Network Status, 0x02 Link Failure, and the address the report is about: 3.4.3.3.1 and 3.4.3.3.2's
       destination address field, present because a routing failure is what this one answers. */
    payload[0] = NWK_CMD_NETWORK_STATUS;
    payload[1] = 0x02;
    payload[2] = 0x11;

    npduLen = makeNpdu(npdu, UNSEEN, NEIGHBOR, 4, 0x41, NWK_FRAME_TYPE_COMMAND, 0, payload, 3);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a unicast Network Status frame addressed to another device");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "is carried onward, and 3.6.2.2 prints no other treatment for it: 'Network status command frames SHALL be handled in the same manner as data frames'");
    Test_ExpectCount(airDestOf(&air[0]), UNSEEN, "aimed at the next hop 3.6.4.3's lookup answers");
    Test_ExpectCount(Nwk_RelaysSent(&dev.nwk), 1, "and counted as the relay it is");
    Test_ExpectCount(Nwk_DroppedNotForMe(&dev.nwk), 0,
                     "not as a frame this device is not the end of: a Network Status frame is the one command 3.6.2.2 makes a data frame of");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 0, "and it is not handed up here: it was not addressed to this device");

    /* A Route Record command is relayed by 3.6.4.5.5's own rule and not by 3.6.2.2's: the relay appends its own
       address to the record, which is what makes the list a route when it reaches the destination. */
    payload[0] = NWK_CMD_ROUTE_RECORD;
    payload[1] = 0;     /* Figure 3-16: a relay count of zero and no relay list yet */

    npduLen = makeNpdu(npdu, UNSEEN, NEIGHBOR, 4, 0x42, NWK_FRAME_TYPE_COMMAND, 0, payload, 2);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "a Route Record command frame addressed to another device");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 2, "is carried onward: 3.6.4.5.5 has every relay node forward it");
    Test_ExpectCount(Nwk_RouteRecordsRelayed(&dev.nwk), 1, "and counted as the record it relayed");
    Test_ExpectCount(npduOf(&air[1])[9], 1,
                     "with this device's address appended to the record, so the relay count went from 0 to 1");
    Test_ExpectCount(npduOf(&air[1])[10] | (npduOf(&air[1])[11] << 8), OWN_SHORT,
                     "and the one address it appended is its own");
    Test_ExpectCount(Nwk_DroppedNotForMe(&dev.nwk), 0, "not as a frame this device does not carry");
}

/*
 * Table 3-4 prints SrcAddr's valid range as "any valid device address except a broadcast address", and nothing
 * below this layer tests it: `mac` reads a sixteen-bit field, and the NWK layer compared the source only with
 * its own address. A frame sourcing 0xfffd is therefore parsed, handed up with a SrcAddr the parameter forbids
 * (APS deduplicates and binds on it) and leaves a neighbour entry for a device that is not one, which Table 3-76
 * gives a cost and 3.6.4.3 may pick as a next hop.
 */
void caseBroadcastSourceIsRefused(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);

    npduLen = makeNpdu(npdu, OWN_SHORT, NWK_ADDR_RX_ON_WHEN_IDLE, 4, 0x51, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a data frame whose NWK source is 0xfffd, a broadcast class and no device");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_DroppedBadSource(&dev.nwk), 1,
                     "is refused, counted: Table 3-4's SrcAddr range excludes every broadcast address, and an indication cannot carry it");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 0, "so nothing is handed up under a source the parameter forbids");
    Test_ExpectCount(Nwk_NeighborQueue(&dev.nwk), 0,
                     "and no neighbour entry is made for it: Table 3-75's entries are devices, and a class is not one");

    /* The reserved band is no device address either, and the same gate answers it. */
    npduLen = makeNpdu(npdu, OWN_SHORT, NWK_ADDR_RESERVED, 4, 0x52, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "and a frame whose source is 0xfffe, Table 3-80's Reserved row");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_DroppedBadSource(&dev.nwk), 2, "is refused the same way: it names no device at all");
    Test_ExpectCount(Nwk_NeighborQueue(&dev.nwk), 0, "and leaves no entry behind");

    /* A device address in the ordinary range is unaffected. */
    npduLen = makeNpdu(npdu, OWN_SHORT, NEIGHBOR, 4, 0x53, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 300), ZB_OK, "and a unicast from an ordinary device");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 1, "is delivered as it always was");
    Test_ExpectCount(Nwk_DroppedBadSource(&dev.nwk), 2, "with the new gate silent about it");
}

/*
 * 3.6.4.8.1: "On receipt of a network status command frame by a router that is the intended destination of the
 * command where the status code field of the command frame payload has a value of 0x01 or 0x02 indicating a link
 * failure, the NWK layer will remove the routing table entry corresponding to the value of the destination address
 * field of the command frame payload, if one exists, and inform the next higher layer of the failure using the
 * NLME-NWK-STATUS.indication using the same status code." The address that is removed is the one the payload names
 * (the frame that failed) and not the source the status arrived from.
 */
void caseNetworkStatusAtTheDestinationRemovesTheRoute(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t payload[4];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);

    dev.nwk.routes[0].inUse = 1;
    dev.nwk.routes[0].destinationAddress = NEIGHBOR;
    dev.nwk.routes[0].status = NWK_ROUTE_ACTIVE;
    dev.nwk.routes[0].nextHopAddress = HOP;

    dev.nwk.routes[1].inUse = 1;
    dev.nwk.routes[1].destinationAddress = SLEEPY;
    dev.nwk.routes[1].status = NWK_ROUTE_ACTIVE;
    dev.nwk.routes[1].nextHopAddress = SLEEPY;

    /* 0x03 Network Status, Table 3-56's 0x02 (Link Failure), and 3.4.3.3.2's two-octet destination address: the
       frame that encountered the failure, which is what the removal is decided on */
    payload[0] = NWK_CMD_NETWORK_STATUS;
    payload[1] = NWK_NETWORK_STATUS_LINK_FAILURE;
    payload[2] = (uint8_t)(NEIGHBOR & 0xff);
    payload[3] = (uint8_t)(NEIGHBOR >> 8);

    npduLen = makeNpdu(npdu, OWN_SHORT, ROUTER_NEIGHBOR, 4, 0x61, NWK_FRAME_TYPE_COMMAND, 0, payload, 4);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a Network Status addressed to this device with a 0x02 in it");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_RouteOf(dev.nwk.routes, NEIGHBOR) == 0,
           "removes the routing table entry the payload's destination address names");
    Test_ExpectCount(Nwk_StatusRoutesRemoved(&dev.nwk), 1, "and says so: one entry removed for one route error");
    Test_Expect(Nwk_RouteOf(dev.nwk.routes, SLEEPY) != 0 && dev.nwk.routes[1].nextHopAddress == SLEEPY,
           "the entry it does not name stays where it was");
    Test_ExpectCount(airCount, 0, "and nothing goes out: the status ends here, it is not relayed or answered");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 1,
           "the next higher layer is told, which is the second half of the clause: 9401-9402's indication");
    Test_ExpectCount(inds[0].commandIdentifier, NWK_CMD_NETWORK_STATUS, "with the command it was, and its status code");
    Test_Expect(inds[0].nsduLength == 4 && inds[0].nsdu[1] == NWK_NETWORK_STATUS_LINK_FAILURE,
           "using the same status code the frame carried");

    /* 0x00 is the payload code the parent paragraph adds and this one does not: the destination's removal is
       printed for 0x01 and 0x02 alone, and Table 3-56's legacy 0x00 reaches the table by no rule of its own. */
    dev.nwk.routes[0].inUse = 1;
    dev.nwk.routes[0].destinationAddress = NEIGHBOR;
    dev.nwk.routes[0].status = NWK_ROUTE_ACTIVE;
    dev.nwk.routes[0].nextHopAddress = HOP;

    payload[1] = 0x00;

    npduLen = makeNpdu(npdu, OWN_SHORT, ROUTER_NEIGHBOR, 4, 0x62, NWK_FRAME_TYPE_COMMAND, 0, payload, 4);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "and a 0x00 in the same frame");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_RouteOf(dev.nwk.routes, NEIGHBOR) != 0 && Nwk_StatusRoutesRemoved(&dev.nwk) == 1,
           "removes nothing here: 9392-9395 prints the destination's removal for 0x01 and 0x02");
}

/*
 * The parent's half of 3.6.4.8.1, printed twice: "When relaying a network status command frame by a router to its
 * end device child that is the intended destination of the route error, where the status code field ... has a value
 * of 0x00, 0x01 or 0x02 indicating a link failure, the NWK layer will remove the routing table entry corresponding
 * to the value of the destination address field of the command frame payload, if one exists. It will then relay the
 * frame as usual to the end device." A parent that carries the error on and keeps its own entry pointing at the
 * broken hop has done half the clause.
 */
void caseNetworkStatusRelayedToAChildRemovesTheRoute(void)
{
    Test_BandA dev;
    uint16_t relays[1];
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t payload[4];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    dev.nwk.routes[0].inUse = 1;
    dev.nwk.routes[0].destinationAddress = NEIGHBOR;
    dev.nwk.routes[0].status = NWK_ROUTE_ACTIVE;
    dev.nwk.routes[0].nextHopAddress = HOP;

    dev.nwk.routes[1].inUse = 1;
    dev.nwk.routes[1].destinationAddress = SLEEPY;
    dev.nwk.routes[1].status = NWK_ROUTE_ACTIVE;
    dev.nwk.routes[1].nextHopAddress = SLEEPY;

    payload[0] = NWK_CMD_NETWORK_STATUS;
    payload[1] = NWK_NETWORK_STATUS_LINK_FAILURE;
    payload[2] = (uint8_t)(NEIGHBOR & 0xff);
    payload[3] = (uint8_t)(NEIGHBOR >> 8);

    npduLen = makeNpdu(npdu, SLEEPY, ROUTER_NEIGHBOR, 4, 0x71, NWK_FRAME_TYPE_COMMAND, 0, payload, 4);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a Network Status from a peer, addressed to this device's child");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 0, "is relayed as usual to the end device, whose receiver rests: held for its poll");
    Test_ExpectCount(Mac_CountersOf(&dev.mac).transactionQueue, 1, "on the MAC's transaction queue (10.22.2)");
    composePoll(&dev.model, 7, SLEEPY);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 110), ZB_OK, "the child polls");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "and the relayed frame goes out");
    Test_ExpectCount(airDestOf(&air[0]), SLEEPY, "aimed at the child the command frame names");

    Test_Expect(Nwk_RouteOf(dev.nwk.routes, NEIGHBOR) == 0,
           "and the entry the payload names is removed on the way, which is what a parent that only relays does not do");
    Test_ExpectCount(Nwk_StatusRoutesRemoved(&dev.nwk), 1, "counted once, before the frame left");
    Test_Expect(Nwk_RouteOf(dev.nwk.routes, SLEEPY) != 0, "the child's own entry is the hop the relay used, and stays");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 0, "nothing is handed up here: the frame was not this device's");

    /* 0x00 is a code only this paragraph carries, so the same frame with it removes the same entry: Table 3-56's
       legacy pair "SHALL be treated the same as 0x02, Link failure". */
    dev.nwk.routes[0].inUse = 1;
    dev.nwk.routes[0].destinationAddress = NEIGHBOR;
    dev.nwk.routes[0].status = NWK_ROUTE_ACTIVE;
    dev.nwk.routes[0].nextHopAddress = HOP;

    payload[1] = 0x00;

    npduLen = makeNpdu(npdu, SLEEPY, ROUTER_NEIGHBOR, 4, 0x72, NWK_FRAME_TYPE_COMMAND, 0, payload, 4);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "and the legacy 0x00 addressed to the child");
    composePoll(&dev.model, 8, SLEEPY);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 210), ZB_OK, "which waits for the child's next poll");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_RouteOf(dev.nwk.routes, NEIGHBOR) == 0 && Nwk_StatusRoutesRemoved(&dev.nwk) == 2,
           "removes it too: 9361-9365 is the one paragraph whose codes include 0x00, and it says 'treat as 0x02'");
    Test_ExpectCount(airDestOf(&air[1]), SLEEPY, "with the frame relayed exactly as before");

    /* 0x0b to the child: 9408-9412 remove the source route the payload names, and relay the frame as usual. */
    relays[0] = HOP;
    Test_ExpectCount(Nwk_SourceRouteLearn(dev.nwk.sourceRoutes, NEIGHBOR, relays, 1, 0), NWK_SR_LEARNED,
                     "a source route to the payload's destination");

    payload[1] = 0x0b;

    npduLen = makeNpdu(npdu, SLEEPY, ROUTER_NEIGHBOR, 4, 0x73, NWK_FRAME_TYPE_COMMAND, 0, payload, 4);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 300), ZB_OK, "a 0x0b source route failure addressed to the child");
    composePoll(&dev.model, 9, SLEEPY);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 310), ZB_OK, "which waits for the child's next poll");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_SourceRouteOf(dev.nwk.sourceRoutes, NEIGHBOR, 310) == 0 && Nwk_StatusSourceRoutesRemoved(&dev.nwk) == 1,
           "removes the source route on the way");
    Test_ExpectCount(airCount != 0 ? airDestOf(&air[airCount - 1]) : 0, SLEEPY, "and still relays the frame to the child");
}

/*
 * The two payload codes a received status owes nothing to this stack's routing table. 0x13 is 3.6.13's answer to a
 * command this layer does not support (a code no paragraph of 3.6.4.8.1 names) and 0x0b is the source route
 * failure 9403-9412 prints, whose removal is "the source route... from nwkRouteRecordTable": the source route table
 * loses that row, and no routing entry is touched for it.
 */
void caseUnknownCommandStatusRemovesNothing(void)
{
    Test_BandA dev;
    uint16_t relays[1];
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t payload[4];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);

    dev.nwk.routes[0].inUse = 1;
    dev.nwk.routes[0].destinationAddress = NEIGHBOR;
    dev.nwk.routes[0].status = NWK_ROUTE_ACTIVE;
    dev.nwk.routes[0].nextHopAddress = HOP;

    payload[0] = NWK_CMD_NETWORK_STATUS;
    payload[1] = NWK_NETWORK_STATUS_UNKNOWN_COMMAND;
    payload[2] = (uint8_t)(NEIGHBOR & 0xff);
    payload[3] = (uint8_t)(NEIGHBOR >> 8);

    npduLen = makeNpdu(npdu, OWN_SHORT, ROUTER_NEIGHBOR, 4, 0x81, NWK_FRAME_TYPE_COMMAND, 0, payload, 4);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a 0x13 status naming an entry this device holds");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_RouteOf(dev.nwk.routes, NEIGHBOR) != 0 && Nwk_StatusRoutesRemoved(&dev.nwk) == 0,
           "removes it not: 3.6.4.8.1's removals are 0x00, 0x01, 0x02 and 0x0b, and 0x13 answers a command");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 1, "and the frame is still told to the higher layer");

    /* 0x0b: 9403-9407's removal is of the source route to the payload's destination. */
    relays[0] = HOP;
    Test_ExpectCount(Nwk_SourceRouteLearn(dev.nwk.sourceRoutes, NEIGHBOR, relays, 1, 0), NWK_SR_LEARNED,
                     "a source route to the same destination, learned earlier");
    payload[1] = 0x0b;

    npduLen = makeNpdu(npdu, OWN_SHORT, ROUTER_NEIGHBOR, 4, 0x82, NWK_FRAME_TYPE_COMMAND, 0, payload, 4);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "and a 0x0b source route failure");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_RouteOf(dev.nwk.routes, NEIGHBOR) != 0 && Nwk_StatusRoutesRemoved(&dev.nwk) == 0,
           "removes no routing entry: its subject is the route record table, not Table 3-77");
    Test_Expect(Nwk_SourceRouteOf(dev.nwk.sourceRoutes, NEIGHBOR, 200) == 0 && Nwk_StatusSourceRoutesRemoved(&dev.nwk) == 1,
           "removes the source route instead, and counts it");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 1, "with the failure still indicated upward");
}

/*
 * 3.6.4.8.1's last receipt rule, which is a different act: "On receipt of a network status command frame by an end
 * device, the NWK layer SHALL inform the next higher layer of the failure using the NLME-NWK-STATUS.indication."
 * Nothing is removed, and the entry beside the frame proves it: an end device holds no routing duty to remove
 * anything under, and the indication ring is this stack's informing.
 */
void caseNetworkStatusAtAnEndDeviceOnlyIndicates(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t payload[4];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_END_DEVICE, 1);

    dev.nwk.routes[0].inUse = 1;
    dev.nwk.routes[0].destinationAddress = NEIGHBOR;
    dev.nwk.routes[0].status = NWK_ROUTE_ACTIVE;
    dev.nwk.routes[0].nextHopAddress = HOP;

    payload[0] = NWK_CMD_NETWORK_STATUS;
    payload[1] = NWK_NETWORK_STATUS_LINK_FAILURE;
    payload[2] = (uint8_t)(NEIGHBOR & 0xff);
    payload[3] = (uint8_t)(NEIGHBOR >> 8);

    npduLen = makeNpdu(npdu, OWN_SHORT, ROUTER_NEIGHBOR, 4, 0x91, NWK_FRAME_TYPE_COMMAND, 0, payload, 4);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a Network Status addressed to an end device");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 1,
           "is informed to the next higher layer, which is the whole of what 9401-9402 asks of one");
    Test_ExpectCount(inds[0].commandIdentifier, NWK_CMD_NETWORK_STATUS, "carrying the command frame it was");
    Test_Expect(Nwk_RouteOf(dev.nwk.routes, NEIGHBOR) != 0 && Nwk_StatusRoutesRemoved(&dev.nwk) == 0,
           "and no entry is removed: 9392-9395's removal is printed for a router that is the intended destination");
    Test_ExpectCount(airCount, 0, "with nothing put on the air for it");
}

/*
 * 3.6.4.3's forward for a unicast that is not this device's: a Route Request is normally a broadcast, but a unicast
 * one addressed to another device is still that device's business. The branch that consumes a Route Request must
 * therefore test the destination, as the Route Reply branch beside it does.
 */
void caseForeignUnicastRreqIsNotConsumed(void)
{
    Test_BandA dev;
    Nwk_NeighborTableEntry *neighbor;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint8_t payload[4];
    uint32_t npduLen;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    Zb_memset(payload, 0, (uint32_t)sizeof payload);

    payload[0] = NWK_CMD_ROUTE_REQUEST;
    payload[1] = 0x2a;                  /* the request identifier */
    payload[2] = (uint8_t)(HOP & 0xff); /* the destination, low octet first */
    payload[3] = (uint8_t)(HOP >> 8);

    npduLen = makeNpdu(npdu, HOP, NEIGHBOR, NWK_INITIAL_RADIUS, 0x11, NWK_FRAME_TYPE_COMMAND, 0, payload,
                       (uint32_t)sizeof payload);

    injectNpdu(&dev, npdu, npduLen, OWN_SHORT);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a Route Request unicast to another device");

    neighbor = neighborAt(&dev.nwk, NEIGHBOR);
    Test_Expect(neighbor != 0, "from a neighbour this device knows");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 0,
                     "is not this device's discovery: 3.6.4.5.1 gives the discovery to the request's destination, and this frame names HOP");
}

/*
 * 3.6.4.3.2's four outcomes for a source-routed data frame, decided from the sub-frame alone: the relay index names
 * the hop, the relay list is ordered destination-first, and an end-device child of this device is unicast to rather
 * than relayed onward.
 */
void caseSourceRouteVerdicts(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_Frame frame;
    uint16_t nextHop = 0;

    Zb_memset(neighbors, 0, (uint32_t)sizeof neighbors);
    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = NWK_FRAME_TYPE_DATA;
    frame.sourceRoute = 1;
    frame.relayCount = 3;
    frame.relayIndex = 2;
    frame.destAddr = 0x3333;
    frame.relayList[0] = 0x3333;
    frame.relayList[1] = HOP;
    frame.relayList[2] = OWN_SHORT;

    Test_Expect(Nwk_RxSourceRoute(&frame, OWN_SHORT, NWK_DEVICE_ROUTER, neighbors, &nextHop) == NWK_SR_RELAY_ONWARD
           && nextHop == HOP,
           "the index names this device, so it relays to the relay before it in the list, which is the one closest to the destination");

    Test_Expect(Nwk_RxSourceRoute(&frame, HOP, NWK_DEVICE_ROUTER, neighbors, &nextHop) == NWK_SR_DROP,
           "while a device the index does not name drops the frame and takes no further action");

    frame.relayIndex = 0;
    Test_Expect(Nwk_RxSourceRoute(&frame, HOP, NWK_DEVICE_ROUTER, neighbors, &nextHop) == NWK_SR_RELAY_DIRECT
           && nextHop == 0x3333,
           "a spent index at a device that is not the destination relays straight to the header's destination");

    Test_Expect(Nwk_RxSourceRoute(&frame, 0x3333, NWK_DEVICE_ROUTER, neighbors, &nextHop) == NWK_SR_DELIVER,
           "and one that is the destination has the frame passed up");

    Test_Expect(Nwk_RxSourceRoute(&frame, HOP, NWK_DEVICE_END_DEVICE, neighbors, &nextHop) == NWK_SR_DROP,
           "an end device relays nothing: 3.6.4.3.2 gives that to a router and a coordinator");

    neighbors[0].inUse = 1;
    neighbors[0].networkAddress = 0x3333;
    neighbors[0].deviceType = NWK_DEVICE_END_DEVICE;
    neighbors[0].relationship = NWK_REL_CHILD;
    frame.relayIndex = 1;
    frame.relayList[1] = HOP;

    Test_Expect(Nwk_RxSourceRoute(&frame, HOP, NWK_DEVICE_ROUTER, neighbors, &nextHop) == NWK_SR_RELAY_DIRECT
           && nextHop == 0x3333,
           "and a destination that is this device's own end-device child is unicast to it rather than relayed onward");

    frame.sourceRoute = 0;
    frame.relayCount = 0;

    Test_Expect(Nwk_RxSourceRoute(&frame, HOP, NWK_DEVICE_ROUTER, neighbors, &nextHop) == NWK_SR_DROP,
           "a frame with no sub-frame is not this decision's");
}

/* 3.6.13's answer to a child whose receiver rests waits for its poll like any unicast to it, since a frame sent
   at once is a frame it cannot hear. */
void caseUnknownCommandReplyToARestingChildIsHeld(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    uint8_t payload[1];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);

    payload[0] = 0x10;
    npduLen = makeNpdu(npdu, OWN_SHORT, SLEEPY, 2, 70, NWK_FRAME_TYPE_COMMAND, 0, payload, 1);
    injectNpdu(&dev, npdu, npduLen, SLEEPY);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "the child sends an unknown command to its parent");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "the answer is not sent at once");
    Test_ExpectCount(Mac_CountersOf(&dev.mac).transactionQueue, 1, "it is held on the transaction queue");
    Test_ExpectCount(Nwk_ReplyCommands(&dev.nwk), 1, "and counted as the reply it is");

    composePoll(&dev.model, 7, SLEEPY);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 110), ZB_OK, "the child polls");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "and the answer goes out");
    Test_ExpectCount(airDestOf(&air[0]), SLEEPY, "to the child");
}

/* A frame relayed to a resting child that never polls expires on the transaction queue, and that is this router's
   failure to relay it: 3.6.4.8.1's Network Status, Link Failure, goes back to the frame's source. A relay the child
   does collect leaves no status behind. */
void caseHeldRelayExpiryIsALinkFailure(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    uint8_t payload[2] = { 0xab, 0xcd };
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    Nwk_Frame parsed;
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
    uint32_t nowMs;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(&dev.nwk, ROUTER_NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    npduLen = makeNpdu(npdu, SLEEPY, ROUTER_NEIGHBOR, 4, 0x41, NWK_FRAME_TYPE_DATA, 0, payload, 2);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a data frame for the resting child arrives");
    composePoll(&dev.model, 7, SLEEPY);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 110), ZB_OK, "the child polls and collects it");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "the relayed frame goes out on the poll");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 120), ZB_OK, "and its acknowledgement is read");
    Test_ExpectCount(dev.nwk.heldRelays[0].inUse, 0, "leaving no relay outstanding");

    npduLen = makeNpdu(npdu, SLEEPY, ROUTER_NEIGHBOR, 4, 0x42, NWK_FRAME_TYPE_DATA, 0, payload, 2);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "a second frame for the child arrives, and the child stays silent");

    for (nowMs = 1000; nowMs <= 200 + MAC_TRANSACTION_PERSISTENCE_MS + 1000; nowMs += 1000)
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, nowMs), ZB_OK, "the turns while the transaction waits");

    harvestAir(&dev.model, air, &airCount);

    for (i = 1; i < airCount && airDestOf(&air[i]) != ROUTER_NEIGHBOR; i++)
        continue;

    Test_Expect(i < airCount, "once it expires a frame goes back towards the frame's source");

    if (i >= airCount)
        return;

    Test_ExpectStatus(NwkFrame_Parse(npduOf(&air[i]), npduLenOf(&air[i]), &parsed, &payloadOffset, &payloadLen), ZB_OK,
                      "a network frame");
    Test_Expect(payloadLen >= 4 && npduOf(&air[i])[payloadOffset] == NWK_CMD_NETWORK_STATUS
                && npduOf(&air[i])[payloadOffset + 1] == NWK_NETWORK_STATUS_LINK_FAILURE,
                "a Network Status saying Link Failure");
    Test_Expect(payloadLen >= 4 && npduOf(&air[i])[payloadOffset + 2] == (uint8_t)(SLEEPY & 0xff)
                && npduOf(&air[i])[payloadOffset + 3] == (uint8_t)(SLEEPY >> 8),
                "naming the destination it could not reach");
}

/* Two relays held for two resting children are two records, so the first one's expiry is reported for its own
   source and destination while the second still waits for its child. */
void caseTwoHeldRelaysKeepTheirOwnRecords(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    uint8_t payload[2] = { 0xab, 0xcd };
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    Nwk_Frame parsed;
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
    uint32_t statuses = 0;
    uint32_t nowMs;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(&dev.nwk, SLEEPY + 1, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(&dev.nwk, ROUTER_NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    npduLen = makeNpdu(npdu, SLEEPY, ROUTER_NEIGHBOR, 4, 0x41, NWK_FRAME_TYPE_DATA, 0, payload, 2);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a frame for the first resting child, from one router");

    npduLen = makeNpdu(npdu, SLEEPY + 1, NEIGHBOR, 4, 0x42, NWK_FRAME_TYPE_DATA, 0, payload, 2);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 5000), ZB_OK, "then one for the second child, from another, seconds later");

    for (nowMs = 6000; nowMs <= 100 + MAC_TRANSACTION_PERSISTENCE_MS + 500; nowMs += 500)
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, nowMs), ZB_OK, "the turns until only the first has expired");

    harvestAir(&dev.model, air, &airCount);

    for (i = 0; i < airCount; i++)
    {
        if (NwkFrame_Parse(npduOf(&air[i]), npduLenOf(&air[i]), &parsed, &payloadOffset, &payloadLen) != ZB_OK
            || payloadLen < 4 || npduOf(&air[i])[payloadOffset] != NWK_CMD_NETWORK_STATUS)
            continue;

        statuses++;
        Test_ExpectCount(parsed.destAddr, ROUTER_NEIGHBOR, "the expiry is reported to the first frame's source");
        Test_ExpectCount((uint32_t)(npduOf(&air[i])[payloadOffset + 2] | (npduOf(&air[i])[payloadOffset + 3] << 8)),
                         SLEEPY, "naming the first child");
    }

    Test_ExpectCount(statuses, 1, "one Network Status, for the relay that expired");
    Test_Expect(dev.nwk.heldRelays[0].inUse + dev.nwk.heldRelays[1].inUse == 1
                && (dev.nwk.heldRelays[0].destAddr == SLEEPY + 1 || dev.nwk.heldRelays[1].destAddr == SLEEPY + 1),
                "and the second relay is still recorded, waiting for its child");

    for (nowMs = 100 + MAC_TRANSACTION_PERSISTENCE_MS + 1000; nowMs <= 5000 + MAC_TRANSACTION_PERSISTENCE_MS + 1000;
         nowMs += 500)
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, nowMs), ZB_OK, "the turns until the second expires too");

    harvestAir(&dev.model, air, &airCount);
    statuses = 0;

    for (i = 0; i < airCount; i++)
    {
        if (NwkFrame_Parse(npduOf(&air[i]), npduLenOf(&air[i]), &parsed, &payloadOffset, &payloadLen) != ZB_OK
            || payloadLen < 4 || npduOf(&air[i])[payloadOffset] != NWK_CMD_NETWORK_STATUS
            || parsed.destAddr != NEIGHBOR)
            continue;

        statuses++;
        Test_ExpectCount((uint32_t)(npduOf(&air[i])[payloadOffset + 2] | (npduOf(&air[i])[payloadOffset + 3] << 8)),
                         SLEEPY + 1, "the second expiry names the second child");
    }

    Test_ExpectCount(statuses, 1, "and is reported to the second frame's source");
    Test_ExpectCount(dev.nwk.heldRelays[0].inUse + dev.nwk.heldRelays[1].inUse, 0, "leaving no record behind");
}

/* A held relay whose transaction vanishes with no confirm, as a radio adopted again leaves it, is freed once the MAC's
   persistence has passed, so the records cannot fill with relays nothing will ever answer. */
void caseHeldRelayWithoutAConfirmAgesOut(void)
{
    Test_BandA dev;
    uint8_t payload[2] = { 0xab, 0xcd };
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t nowMs;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(&dev.nwk, ROUTER_NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    npduLen = makeNpdu(npdu, SLEEPY, ROUTER_NEIGHBOR, 4, 0x41, NWK_FRAME_TYPE_DATA, 0, payload, 2);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a frame for the resting child is held");
    Test_ExpectCount(dev.nwk.heldRelays[0].inUse, 1, "and recorded");

    Zb_memset(dev.mac.indirect.transactions, 0, (uint32_t)sizeof dev.mac.indirect.transactions);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + MAC_TRANSACTION_PERSISTENCE_MS), ZB_OK,
                      "the transaction is gone without a confirm, and the persistence passes");
    Test_ExpectCount(dev.nwk.heldRelays[0].inUse, 1, "the record waits a margin past it");

    for (nowMs = 100 + MAC_TRANSACTION_PERSISTENCE_MS + 500; nowMs <= 100 + MAC_TRANSACTION_PERSISTENCE_MS + 1500;
         nowMs += 500)
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, nowMs), ZB_OK, "the turns after it");

    Test_ExpectCount(dev.nwk.heldRelays[0].inUse, 0, "then it is freed");
    Test_ExpectCount(dev.nwk.relaysHeldAgedOut, 1, "and counted");
}
