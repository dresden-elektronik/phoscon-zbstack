/* The `aps` suite's transmit half after the door: a unicast received end to
   end, the broadcast the address decides and not a flag, the broadcast endpoint passed upward unchanged, and the
   indication ring's full policy. */

#include "aps.h"
#include "aps_frame.h"
#include "aps_helpers.h"
#include "nwk.h"
#include "test_harness.h"
#include "zb_utils.h"

/*
 * 13. A unicast received end to end: everything Table 2-4 says an accepted frame leaves behind
 * (2.2.4.1.3, 2.2.8.4.2, Table 2-4).
 *
 * Two complete stacks here, because the reception half is what is under test: A's APS composes the frame, A's
 * network layer carries it, and the device under test decides it. The indication is read field against field
 * against the request A made, which is the only way to show that a delivery is a *report* of a received frame and
 * not a re-statement of what a sender asked for: `dstAddress` is the address the frame arrived on, `srcAddress` is
 * the NWK source of the indication because an APS header carries no source address of its own, and
 * the ASDU is the payload region the codec reported past the header it validated. The frame asked for no
 * acknowledgement, and the counter that stayed at zero is the assertion that says so.
 */
void caseUnicastIndication(void)
{
    Rig rig;
    Rig a;
    Air air[AIR_LOG_MAX];
    Air airA[AIR_LOG_MAX];
    Aps_ApsdeReq req;
    Aps_Confirm confirms[2];
    Aps_Indication inds[2];
    uint32_t airCount = 0;
    uint32_t airCountA = 0;
    uint32_t got;
    static const uint8_t asdu[ASDU_LEN] = { 0x74, 0x77, 0x6f, 0x73, 0x74, 0x61 };

    rigBuild(&rig, OWN_SHORT);
    rigBuild(&a, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&a.stack.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&a.stack.model, LOOPBACK_TX_MAX, 1);

    req = sapReq(APS_ADDR_MODE_SHORT, OWN_SHORT, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);
    Test_ExpectStatus(Aps_DataRequest(&a.aps, &req, 100), ZB_OK, "A sends a unicast that asks for nothing");
    harvestAir(&a.stack.model, airA, &airCountA);
    Test_Expect(airCountA == 1, "one frame on A's side of the seam");

    handOver(&a.stack.model, &rig.stack.model);
    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_IndicationQueue(&rig.aps) == 1, "the device under test has one delivery to hand up, in the ring APSDE-DATA.indication leaves through (2.2.4.1.3)");

    got = Aps_PollIndications(&rig.aps, inds, 2);
    Test_Expect(got == 1, "polled once, oldest first, and nothing else was queued");

    Test_Expect(inds[0].dstAddrMode == APS_ADDR_MODE_SHORT && inds[0].dstAddress == OWN_SHORT,
          "DstAddrMode 0x02 with the NWK destination the frame arrived on: a short address is the only kind of destination this slice accepts for a unicast, and 0x03 and 0x04 wait for the address map (Table 2-4, 2.2.4.1.3.2)");
    Test_Expect(inds[0].dstEndpoint == DST_EP,
          "DstEndpoint is the endpoint the frame carried, passed upward as received (2.2.8.4.2: \"the APSDE SHALL pass it directly to the NHLE at the destination endpoint supplied\")");
    Test_Expect(inds[0].srcAddrMode == APS_ADDR_MODE_SHORT && inds[0].srcAddress == ADDR_PEER,
          "SrcAddrMode 0x02 with the NWK source of the indication: 2.2.4.1.3.2 upgrades a source to 0x03 only when nwkAddressMap knows the sender's IEEE address, and band A has no address map to ask");
    Test_Expect(inds[0].srcEndpoint == SRC_EP, "SrcEndpoint as the frame carried it");
    Test_Expect(inds[0].profileId == PROFILE_ID && inds[0].clusterId == CLUSTER_ID,
          "ProfileId 0x0104 and ClusterId 0x0006 read out of the APS header, which is the only place either of them travelled on (2.2.5.1.4, 2.2.5.1.5)");
    Test_Expect(inds[0].asduLength == ASDU_LEN && Zb_memcmp(inds[0].asdu, asdu, ASDU_LEN) == 0,
          "the ASDU byte for byte, copied whole or not at all (docs/internals/coding-rules.md §1)");
    Test_Expect(inds[0].status == APS_STATUS_SUCCESS && inds[0].securityStatus == APS_STATUS_UNSECURED,
          "Status SUCCESS (\"Under all other circumstances, the APSDE sets the Status parameter to SUCCESS\", 2.2.4.1.3.2) beside SecurityStatus UNSECURED: Table 2-4's two enumerations, one for what the processing decided and one for what the frame was");
    Test_Expect(inds[0].linkQuality == 200,
          "LinkQuality is the NLDE's own indication carried up unchanged (Table 2-4: \"The link quality indication delivered by the NLDE\"), which is the 200 the suite stamps on every injected frame");
    Test_Expect(inds[0].keyIndex == APS_KEY_INDEX_NONE,
          "KeyIndex is the sentinel and not an index: Table 2-4 bounds the field with \"This value is only valid when SecurityStatus is set to SECURED_LINK_KEY\", and no indication this slice issues is secured");

    Test_Expect(Aps_AcksGenerated(&rig.aps) == 0 && airCount == 0,
          "and no acknowledgement went back: 2.2.8.4.3.1, \"A frame that is received by its intended recipient with its acknowledgement request (AR) sub-field set to 0 SHALL NOT be acknowledged\", this device put nothing on its own side of the seam for this frame");
    Test_Expect(Aps_RxShapeRefused(&rig.aps) == 0 && Aps_RxMalformed(&rig.aps) == 0
           && Aps_RxSecuredDeferred(&rig.aps) == 0 && Aps_RxCommandDeferred(&rig.aps) == 0
           && Aps_RxDuplicateDrops(&rig.aps) == 0 && Aps_DroppedGroupMiss(&rig.aps) == 0
           && Aps_DroppedIndications(&rig.aps) == 0 && Aps_UnmatchedAcks(&rig.aps) == 0
           && Aps_AcksRefused(&rig.aps) == 0,
          "and every gate this frame passed is countable as having passed it");

    stepAt(&a, airA, &airCountA, 102);
    Test_Expect(Aps_PollConfirms(&a.aps, confirms, 2) == 1
           && confirms[0].status == ZB_OK && confirms[0].apsStatus == APS_STATUS_SUCCESS
           && confirms[0].attempts == 1,
           "A's own confirm is SUCCESS with one attempt, which is what 2.2.8.4.3.1 promises a sender whose frame owed no answer, whatever the peer below did with it");
    Test_Expect(airCountA == 1, "and A retransmitted nothing");
}

/*
 * 9. Broadcast delivery, which the address decides and not a flag (2.2.5.1.1.2, Table 3-80, 2.2.8.4.3).
 *
 * A mode-0x02 request addressed to one of Table 3-80's destination groups is a broadcast: 2.2.5.1.1.2 defines a
 * broadcast as a message that "will go to all devices defined for the selected broadcast address in use as
 * defined in section 3.6.6", which makes the address the fact and leaves no second way to ask. It never owes an
 * acknowledgement (2.2.8.4.3), so no AWAITING_ACK state ever forms and the answer arrives on the NLDE
 * confirmation and not after apscAckWaitDuration. The acknowledged form of both a broadcast and a group send is
 * refused at the door: case 1.
 */
/*
 * 9. Broadcast delivery, which the address decides and not a flag (2.2.5.1.1.2, Table 3-80, 2.2.8.4.3).
 *
 * A mode-0x02 request addressed to one of Table 3-80's destination groups is a broadcast: 2.2.5.1.1.2 defines a
 * broadcast as a message that "will go to all devices defined for the selected broadcast address in use as
 * defined in section 3.6.6", which makes the address the fact and leaves no second way to ask for it. A broadcast
 * never owes an acknowledgement (2.2.8.4.3), so no AWAITING_ACK state ever forms and the answer arrives on the
 * NLDE confirmation and not after apscAckWaitDuration. The acknowledged form of a broadcast, and of a group send,
 * is refused at the door: case 1.
 *
 * The door judges Table 3-80's Reserved rows as that table prints them (0xfffe, and 0xfff8-0xfffa), the same band
 * `nwkIsReservedAddress` applies one layer down; a class address is outside it, and this module aims every group
 * transmission it sends at 0xfffd (APS_NWK_BROADCAST_GROUP_DEFAULT, src/zb/aps/aps.h; 2.2.8.4.1 prints that
 * address as the one to employ). All four destination groups reach the derivation this case tests.
 */
void caseBroadcastDelivery(void)
{
    Rig rig;
    Air air[AIR_LOG_MAX];
    Aps_Confirm confirms[4];
    Aps_ApsdeReq req;
    uint32_t airCount = 0;
    uint32_t i;
    static const uint8_t wide[ASDU_LEN] = { 0x62, 0x63, 0x61, 0x73, 0x74, 0x21 };
    static const uint16_t classes[] = { NWK_ADDR_LOW_POWER_ROUTERS, NWK_ADDR_ROUTERS, NWK_ADDR_RX_ON_WHEN_IDLE };

    rigBuild(&rig, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);

    req = sapReq(APS_ADDR_MODE_SHORT, NWK_ADDR_ALL_DEVICES, APS_ENDPOINT_ALL, CLUSTER_ID, wide, ASDU_LEN, 0);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK,
                  "a request addressed to Table 3-80's 0xffff, with the broadcast endpoint as its destination (2.2.5.1.6: 0xff is \"all active endpoints except endpoint 0x00\")");

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 1, "one frame");
    Test_Expect(air[0].ackRequest == 0 && fcfOf(&air[0]) == AIR_BROADCAST_FCF,
           "and the network layer asked the radio for nothing: 3.6.6, \"Broadcast transmissions SHALL NOT use the MAC sub-layer acknowledgement\", the class the address names decides that too, one layer down");
    Test_Expect(airDestOf(&air[0]) == NWK_ADDR_ALL_DEVICES,
           "aimed at the MAC's broadcast address, 0xffff, as 3.2.1.1.3 step 6 a.3 requires of every class");
    Test_Expect(npduOf(&air[0])[2] == 0xff && npduOf(&air[0])[3] == 0xff,
           "and the class in the NWK header's destination field too, low octet first as 3.3 orders a multi-octet field: the only place a receiver learns who was meant");
    Test_Expect(apduOf(&air[0])[0] == APS_FCF_DATA_BROADCAST,
           "with the APS Frame Control Field saying broadcast delivery: delivery mode 0b10 in FCF bits 2-3 (Table 2-21), derived from the address and not handed in as a flag. A caller that wanted broadcast delivery addresses a class, and a module that read a flag here would be a module whose frame and whose intention could disagree");
    Test_Expect(((apduOf(&air[0])[0] >> APS_FRAME_FCF_ACK_REQUEST_SHIFT) & APS_FRAME_FCF_ACK_REQUEST_MASK) == 0,
           "and no acknowledgement asked: 2.2.5.1.1.5 forbids the sub-field for a frame that is broadcast or multicast, and 2.2.8.4.3 makes it unowed");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 1 && rig.aps.tx[0].deliveryMode == APS_DELIVERY_BROADCAST,
           "the derived mode is what the slot records, and it is the value the FCF carries");

    /* The other three destination groups Table 3-80 prints: 0xfffd macRxOnWhenIdle TRUE, 0xfffc all routers and
       the coordinator, 0xfffb low power routers only. All three are issued before anything is stepped, so one
       harvest sees all three frames and one turn collects all four confirmations. */
    for (i = 0; i < 3; i++)
    {
        req = sapReq(APS_ADDR_MODE_SHORT, classes[i], APS_ENDPOINT_ALL, CLUSTER_ID, wide, ASDU_LEN, 0);
        Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 101 + i), ZB_OK,
                     "a request addressed to a destination group Table 3-80 prints (Table 3-80, 3.6.6): the class is outside the Reserved rows the door judges, 0xfffe and 0xfff8-0xfffa");
    }

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 4, "the ledger holds all four frames now: the one above plus the three these requests put out");

    for (i = 0; i < 3; i++)
    {
        Test_Expect(airDestOf(&air[1 + i]) == NWK_ADDR_ALL_DEVICES
               && (uint32_t)(npduOf(&air[1 + i])[2] | (npduOf(&air[1 + i])[3] << 8)) == classes[i],
               "each with 0xffff in the MAC destination and its own class in the NWK header: 3.2.1.1.3 step 6 a.3 names 0xfffd and 0xfffc beside 0xffff, and 802.15.4-2024 has no broadcast address of either value");
        Test_Expect(apduOf(&air[1 + i])[0] == APS_FCF_DATA_BROADCAST,
               "with broadcast delivery derived from the address, one octet of FCF and no flag to disagree with it (2.2.5.1.1.2, Table 2-21)");
        Test_Expect(((apduOf(&air[1 + i])[0] >> APS_FRAME_FCF_ACK_REQUEST_SHIFT) & APS_FRAME_FCF_ACK_REQUEST_MASK) == 0,
               "and no acknowledgement asked of it (2.2.5.1.1.5, 2.2.8.4.3)");
    }

    Test_Expect(Aps_RefusedRequests(&rig.aps) == 0 && Aps_TransmitQueue(&rig.aps) == 4,
           "the door refused none of the four classes, and all four transactions await their NLDE confirmation");

    stepAt(&rig, air, &airCount, 110);
    Test_Expect(Aps_PollConfirms(&rig.aps, confirms, 4) == 4,
           "all four answered in the one turn that collected their NLDE confirmations, at 110 ms and not after apscAckWaitDuration");

    for (i = 0; i < 4; i++)
    {
        Test_Expect(confirms[i].apsStatus == APS_STATUS_SUCCESS && confirms[i].attempts == 1,
               "SUCCESS with one transmission each: 2.2.8.4.3.1, \"A frame that is received by its intended recipient with its acknowledgement request (AR) sub-field set to 0 SHALL NOT be acknowledged. The originating device SHALL assume that the transmission of the frame was successful\": restated by Table 2-26's accounting rule");
    }

    Test_Expect(confirms[0].dstAddress == NWK_ADDR_ALL_DEVICES && confirms[0].dstEndpoint == APS_ENDPOINT_ALL,
           "the first echoing the destination the request named");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0, "no AWAITING_ACK ever formed: a broadcast owes nothing (2.2.8.4.3)");

    stepAt(&rig, air, &airCount, 110 + APS_ACK_WAIT_DURATION_MS);
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0 && Aps_ConfirmQueue(&rig.aps) == 0 && Nwk_TransmitQueue(&rig.stack.nwk) == 0,
           "a full wait later nothing is outstanding anywhere below: a broadcast is never retransmitted by this machine, and no layer under it holds one either");
    Test_Expect(airCount >= 4, "and the ledger still holds the four frames the door sent");
    Test_Expect(Aps_ConfirmQueue(&rig.aps) == 0 && Aps_UnmatchedAcks(&rig.aps) == 0,
           "and nothing further was answered or owed by this layer");
    Test_Expect(Nwk_BroadcastRetransmissions(&rig.stack.nwk) <= 4 * NWK_MAX_BROADCAST_RETRIES,
           "while whatever else went out during that wait is the network layer's own 3.6.6 count for the four broadcasts this device sent, at most nwkMaxBroadcastRetries each, and not this layer transmitting again");
}

/*
 * 15. A broadcast receipt, with the broadcast endpoint passed upward unchanged (2.2.5.1.1.2, Table 2-4).
 *
 * 2.2.8.4.2 gives the fan-out for a destination endpoint of 0xff in one sentence, "the APSDE SHALL also present
 * the frame to all non-reserved endpoints (0x01-0xfe) supported by the NHLE", and band A has no NHLE to present
 * it to. What it does instead of inventing one is to hand the octet upward exactly as the frame carried it and
 * count one indication, and the case names that as the deferral: presenting a frame to every active endpoint is
 * the next higher layer's duty, and a slice that pretended to have done it would be reporting deliveries to
 * endpoints it has no way to name.
 */
void caseBroadcastEndpointPassedUp(void)
{
    Rig rig;
    Rig a;
    Air air[AIR_LOG_MAX];
    Aps_ApsdeReq req;
    Aps_Indication inds[2];
    uint32_t airCount = 0;
    static const uint8_t wide[ASDU_LEN] = { 0x61, 0x6c, 0x6c, 0x61, 0x63, 0x74 };

    rigBuild(&rig, OWN_SHORT);
    rigBuild(&a, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&a.stack.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&a.stack.model, LOOPBACK_TX_MAX, 1);

    req = sapReq(APS_ADDR_MODE_SHORT, NWK_ADDR_ALL_DEVICES, APS_ENDPOINT_ALL, CLUSTER_ID, wide, ASDU_LEN, 0);
    Test_ExpectStatus(Aps_DataRequest(&a.aps, &req, 100), ZB_OK,
                  "A broadcasts to Table 3-80's all-devices class with the broadcast endpoint as its destination (2.2.5.1.1.2: 0xff is \"all active endpoints\")");

    handOver(&a.stack.model, &rig.stack.model);
    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_IndicationQueue(&rig.aps) == 1, "one indication and not one per endpoint this device might have: the fan-out is deferred, and the count says so");

    Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1, "taken once");
    Test_Expect(inds[0].dstAddrMode == APS_ADDR_MODE_SHORT && inds[0].dstAddress == NWK_ADDR_ALL_DEVICES,
          "the NWK destination the frame arrived on is what the indication reports, because a broadcast class is the only fact a broadcast delivery carries: Table 2-4's 0x02, \"16-bit address for DstAddress and DstEndpoint present\"");
    Test_Expect(inds[0].dstEndpoint == APS_ENDPOINT_ALL,
          "and DstEndpoint is 0xff, unchanged, although Table 2-4 prints this parameter's range as \"0x00 – 0xfe\": band A passes the octet the frame carried upward rather than dropping a legal broadcast or inventing the endpoints it cannot name (the AF duty it defers)");
    Test_Expect(inds[0].asduLength == ASDU_LEN && Zb_memcmp(inds[0].asdu, wide, ASDU_LEN) == 0
           && inds[0].status == APS_STATUS_SUCCESS && inds[0].securityStatus == APS_STATUS_UNSECURED,
          "the ASDU and both Status fields as they are for any accepted frame");

    Test_Expect(Aps_AcksGenerated(&rig.aps) == 0,
          "no acknowledgement for a broadcast whatever the frame had asked: 2.2.5.1.1.5 forbids the sub-field on a frame that is broadcast or multicast, and the codec turns a wire form that ignores it into damage rather than a delivery with an obligation attached");
    Test_Expect(Aps_DroppedIndications(&rig.aps) == 0 && Aps_RxMalformed(&rig.aps) == 0
           && Aps_DroppedGroupMiss(&rig.aps) == 0,
           "nothing was refused for room, nothing was damage, and nothing was a group miss");
    Test_Expect(airCount == 1 && Nwk_RelaysSent(&rig.stack.nwk) == 1,
           "the one frame on this device's air is the network layer's own retransmission of the broadcast (3.6.6): the layer below doing its forwarding duty for a frame it received, and not an answer this module sent");
}

/*
 * 24. The indication ring, and the ninth delivery it cannot hold (Table 2-4, docs/internals/coding-rules.md §4.3).
 *
 * Eight frames arrive in one turn and the ring holds eight. The ninth increments `droppedIndications` and the ring
 * keeps the eight it had, oldest intact: an indication is somebody else's frame, there is no request to refuse
 * instead, and the most this module can promise is that a delivery it lost is countable by the module that lost
 * it. The frames are told apart by the cluster identifier each carries, because Table 2-4 has no APS counter
 * parameter to report: the counter is a wire field this sub-layer consumes in its own decisions and does not pass
 * upward, which is the same fact case 13 asserts by naming the parameters the table does print.
 */
void caseIndicationRingPressure(void)
{
    Rig rig;
    Test_BandA peer;
    Air air[AIR_LOG_MAX];
    Aps_Frame frame;
    Aps_Indication inds[APS_INDICATION_MAX + 1];
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t airCount = 0;
    uint32_t len;
    uint32_t i;
    static const uint8_t ringAsdu[ASDU_LEN] = { 0x72, 0x69, 0x6e, 0x67, 0x21, 0x00 };

    rigBuild(&rig, OWN_SHORT);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    for (i = 0; i < APS_INDICATION_MAX; i++)
    {
        dataHeader(&frame, APS_DELIVERY_UNICAST, 0, (uint8_t)(0x10 + i), DST_EP, (uint16_t)(0x1000 + i));
        frame.srcEndpoint = 0x05;
        len = composeApdu(&frame, ringAsdu, ASDU_LEN, apdu);
        peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 100 + i);
    }

    stepAt(&rig, air, &airCount, 110);

    Test_Expect(Aps_IndicationQueue(&rig.aps) == APS_INDICATION_MAX,
           "eight deliveries queued, the ring at its named bound: a house pool, because 2.2.4.1.3 prints the primitive and chapter 2 prints no queue it travels through (the house pool's rule)");
    Test_Expect(Aps_DroppedIndications(&rig.aps) == 0, "and nothing lost yet");

    dataHeader(&frame, APS_DELIVERY_UNICAST, 0, 0x18, DST_EP, 0x1008);
    frame.srcEndpoint = 0x05;
    len = composeApdu(&frame, ringAsdu, ASDU_LEN, apdu);
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 111);
    stepAt(&rig, air, &airCount, 112);

    Test_Expect(Aps_DroppedIndications(&rig.aps) == 1,
           "the ninth is refused and counted at the moment of production, which is §4.3's policy and the one `mac` and `nwk` apply one layer down. The frame passed every gate above and was lost for want of a slot, which is why this counter is separate from all of them");
    Test_Expect(Aps_IndicationQueue(&rig.aps) == APS_INDICATION_MAX,
           "and the ring still holds eight: nothing was overwritten in flight to make room for the arrival, because the eight it already held are eight deliveries this module had already decided to make");

    Test_Expect(Aps_PollIndications(&rig.aps, inds, APS_INDICATION_MAX + 1) == APS_INDICATION_MAX, "drained oldest first");

    for (i = 0; i < APS_INDICATION_MAX; i++)
    {
        Test_Expect(inds[i].clusterId == (uint16_t)(0x1000 + i),
               "in the order they arrived, which is the only way \"nothing was overwritten\" is observable: the first out is the first in, eight deep, and the ninth frame's cluster identifier appears nowhere");
        Test_Expect(inds[i].srcEndpoint == 0x05 && inds[i].dstEndpoint == DST_EP
               && inds[i].asduLength == ASDU_LEN && Zb_memcmp(inds[i].asdu, ringAsdu, ASDU_LEN) == 0,
               "and each one whole: a delivery that survived the pressure kept its own parameters and its own copy of the ASDU");
    }

    Test_Expect(Aps_IndicationQueue(&rig.aps) == 0 && Aps_RxDuplicateDrops(&rig.aps) == 0,
           "the ring empty afterwards, and the ninth frame was not a duplicate on the way in either: nine distinct (source, APS counter) keys against a table of eight is the pool forgetting and not the pool refusing (case 18 is where that is asserted)");
    Test_Expect(Aps_AcksGenerated(&rig.aps) == 0 && Aps_AcksRefused(&rig.aps) == 0 && airCount == 0,
           "and no acknowledgement was owed for any of them, since none of them asked for one");
}
