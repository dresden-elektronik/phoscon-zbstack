/* The `aps` suite's transmit half without an acknowledgement: the unicast
   that asks for nothing and what the NLDE answer becomes, the APS counter and its wrap, the network layer's
   answer winning over this module's own, and the four attempts one APDU is retransmitted as. */

#include "aps.h"
#include "aps_frame.h"
#include "aps_helpers.h"
#include "nwk.h"
#include "test_harness.h"
#include "zb_utils.h"

/*
 * 3. A unicast that asks for nothing, end to end (2.2.4.1.1.3, 2.2.8.4.1, 2.2.8.4.3.1).
 *
 * The octets are compared against a composition the service did not make: the same fields handed to
 * `ApsFrame_Compose` by the case, which is the split asserted from the outside, the only way an APDU leaves
 * this module is through the codec, so a byte the codec did not write is a byte this module invented.
 */
void caseUnicastNoAck(void)
{
    Rig rig;
    Air air[AIR_LOG_MAX];
    Aps_Confirm confirms[2];
    Aps_ApsdeReq req;
    Aps_Frame frame;
    uint8_t wanted[APS_FRAME_MAX];
    uint32_t wantedLen;
    uint32_t wantedOffset;
    uint32_t airCount = 0;
    uint32_t got;
    static const uint8_t asdu[ASDU_LEN] = { 0x7a, 0x6e, 0x77, 0x6b, 0x20, 0x61 };

    rigBuild(&rig, OWN_SHORT);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK,
                  "a unicast with no TxOptions is taken back: ZB_OK means \"an answer is coming\", exactly as `Nwk_DataRequest` means it (3.2.1.2.1, 2.2.4.1.2)");

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 1, "one frame on the air, issued inside the request and not one turn later (2.2.8.4.1: \"An APDU transmission is initiated by issuing the NLDE-DATA.request primitive\")");
    Test_Expect(fcfOf(&air[0]) == AIR_UNICAST_FCF && air[0].ackRequest == 1,
          "on this PAN's acknowledged unicast, which is the layer below's decision about a unicast (3.6.4.3) and not this module's acknowledgement ask: an APDU with its AR sub-field 0 still travels on a MAC transaction that asks for a MAC acknowledgment");
    Test_Expect(airDestOf(&air[0]) == ADDR_PEER, "aimed at the neighbor the destination resolves to");
    Test_Expect(npduOf(air)[0] == NWK_FCF_DATA_DISCOVERING && npduOf(air)[1] == 0x00,
          "carried in an unsecured minimal NWK data frame: the security bit this slice never sets at either layer (3.3.1.1.4's \"If security for this frame is implemented at another layer or disabled entirely, it SHALL have a value of 0\")");

    dataHeader(&frame, APS_DELIVERY_UNICAST, 0, 0, DST_EP, CLUSTER_ID);
    Test_ExpectStatus(ApsFrame_Compose(&frame, asdu, ASDU_LEN, wanted, (uint32_t)sizeof wanted, &wantedLen, &wantedOffset), ZB_OK,
                  "the case composes the same frame's header and ASDU through the codec");
    Test_Expect(wantedLen == APS_HEADER_UNICAST_FORM + ASDU_LEN && ApsFrame_HeaderLen(&frame) == APS_HEADER_UNICAST_FORM,
           "eight octets of data header (frame control, destination endpoint, cluster, profile, source endpoint, APS counter) plus the ASDU (Figure 2-3 with Figure 2-7)");

    Test_Expect(apduLenOf(&air[0]) == wantedLen
           && Zb_memcmp(apduOf(&air[0]), wanted, wantedLen) == 0,
           "and the APDU on the air is that composition octet for octet, header and ASDU together as one NSDU");
    Test_Expect(apduOf(&air[0])[0] == APS_FCF_DATA_UNICAST,
           "FCF 0x00: frame type Data, delivery mode Unicast, ack format 0, security 0, ACK request 0, extended header absent");
    Test_Expect(apduOf(&air[0])[APS_COUNTER_OCTET_UNICAST] == 0,
           "and the transaction carried the module's first counter, 0 (2.2.5.1.7)");

    Test_Expect(Aps_TransmitQueue(&rig.aps) == 1, "and the transaction is in a slot, waiting for the network layer's answer (APS_TX_AWAITING_NLDE)");
    Test_Expect(rig.aps.tx[0].state == APS_TX_AWAITING_NLDE, "in that state and not another");
    Test_Expect(Aps_ConfirmQueue(&rig.aps) == 0, "with nothing answered yet");

    stepAt(&rig, air, &airCount, 101);

    Test_Expect(airCount == 1, "one attempt was all it took");
    got = Aps_PollConfirms(&rig.aps, confirms, 2);
    Test_Expect(got == 1 && confirms[0].status == ZB_OK && confirms[0].apsStatus == APS_STATUS_SUCCESS,
           "SUCCESS in both vocabularies: the seam's own name beside the Table 2-29 code (2.2.4.1.2, Table 2-3)");
    Test_Expect(confirms[0].attempts == 1, "with one NLDE transaction behind it");
    Test_Expect(confirms[0].dstAddrMode == APS_ADDR_MODE_SHORT && confirms[0].dstAddress == ADDR_PEER
           && confirms[0].dstEndpoint == DST_EP && confirms[0].srcEndpoint == SRC_EP
           && confirms[0].profileId == PROFILE_ID && confirms[0].clusterId == CLUSTER_ID,
           "and the confirm echoes the parameters of the request it answers: DstAddrMode, DstAddress, DstEndpoint, SrcEndpoint (Table 2-3), the profile and cluster the frame carried");
    Test_Expect(confirms[0].apsCounter == apduOf(&air[0])[APS_COUNTER_OCTET_UNICAST],
           "and the counter it reports is the counter the frame carried, which is the number an acknowledgement would have repeated (2.2.5.2.3.1)");

    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0, "the slot is released by the act that answers it");
    Test_Expect(rig.aps.apsCounter == 1, "and the module's counter moved once, for one new transmission");
    Test_Expect(Aps_UnmatchedAcks(&rig.aps) == 0 && Aps_ConfirmationsIgnored(&rig.aps) == 0
           && Aps_RetransmitRefusals(&rig.aps) == 0 && Aps_AcksGenerated(&rig.aps) == 0
           && Aps_RxMalformed(&rig.aps) == 0 && Aps_RxShapeRefused(&rig.aps) == 0
           && Aps_RxDuplicateDrops(&rig.aps) == 0 && Aps_DroppedIndications(&rig.aps) == 0,
           "and none of the module's counters moved on anything else, including the reception family, which is what a transmission-only case proves: nothing arrived at this device at all, and a counter that stays at zero for a frame nobody sent is the count saying so (2.2.8.4.2 has nothing to decide)");

    /* A zero-length ASDU is inside Table 2-2's printed range "0x00 – …", and the frame it produces is the bare
       header: the door refuses a *length with no octets*, not an ASDU of none. */
    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, 0, 0);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 102), ZB_OK, "an empty ASDU is a legal request");
    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 2 && apduLenOf(&air[1]) == APS_HEADER_UNICAST_FORM,
           "and the APDU it put on the air is eight octets of header and nothing after them");
}

/* Two requests to one device on one cluster, in flight at once, are told apart by the tag each caller gave: the
   confirm carries it back, whatever order the answers come in (docs/internals/decisions.md). */
void caseConfirmCarriesTheCallersTag(void)
{
    Rig rig;
    Air air[AIR_LOG_MAX];
    Aps_Confirm confirms[2];
    Aps_ApsdeReq req;
    uint32_t airCount = 0;
    uint32_t got;
    static const uint8_t asdu[ASDU_LEN] = { 0x7a, 0x6e, 0x77, 0x6b, 0x20, 0x61 };

    rigBuild(&rig, OWN_SHORT);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);
    req.tag = 0x1234;
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK, "the first request, tagged 0x1234");
    req.tag = 0xbeef;
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK, "and a second to the same device and cluster, tagged 0xbeef");

    stepAt(&rig, air, &airCount, 101);

    got = Aps_PollConfirms(&rig.aps, confirms, 2);
    Test_ExpectCount(got, 2, "both are answered");
    Test_Expect(got == 2 && ((confirms[0].tag == 0x1234 && confirms[1].tag == 0xbeef)
                             || (confirms[0].tag == 0xbeef && confirms[1].tag == 0x1234)),
                "and each confirm carries the tag of the request it answers, which nothing else in it tells apart");
    Test_Expect(got == 2 && confirms[0].apsCounter != confirms[1].apsCounter, "the two were two transactions");
}

/*
 * 4. The APS counter sequence, and its wrap (2.2.5.1.7).
 *
 * One number per new transaction, in order, mod 256: an octet is an octet. The wrap is only reachable from the top
 * of an octet, so the case seeds the module's own counter the way nwk/ in test/ seeds `nwk.seq`: a deterministic
 * start is a house choice and so is a way to reach the end of the range.
 */
void caseCounterSequence(void)
{
    Rig rig;
    Air air[AIR_LOG_MAX];
    Aps_Confirm confirms[2];
    Aps_ApsdeReq req;
    Aps_Frame frame;
    uint32_t airCount = 0;
    uint32_t i;
    uint32_t payloadOffset;
    uint32_t payloadLen;
    static const uint8_t asdu[ASDU_LEN] = { 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x31 };

    rigBuild(&rig, OWN_SHORT);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);

    for (i = 0; i < 3; i++)
    {
        req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);
        Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100 + i), ZB_OK, "a new transaction");
        harvestAir(&rig.stack.model, air, &airCount);
        Test_Expect(airCount == i + 1, "one frame for it");
        Test_Expect(apduOf(&air[i])[APS_COUNTER_OCTET_UNICAST] == (uint8_t)i,
               "transmitted with the counter the module had not yet handed out, in order: 0, 1, 2 (2.2.5.1.7's \"SHALL be incremented by one for each new transmission\")");
        stepAt(&rig, air, &airCount, 110 + i);
        Test_Expect(Aps_PollConfirms(&rig.aps, confirms, 2) == 1 && confirms[0].apsStatus == APS_STATUS_SUCCESS,
               "each answered before the next is taken back, so the three transactions never shared a slot");
    }

    Test_Expect(rig.aps.apsCounter == 3, "and the counter is now 3: three new transmissions, three numbers spent");
    Test_Expect(airCount == 3, "and three frames on the air, one per transaction: a counter is not spent by a retransmission, and nothing here retransmitted");

    rig.aps.apsCounter = 0xff;     /* the suite seeds the module's counter, as nwk/ in test/ seeds `nwk.seq`: the wrap of an octet is only reachable from the top of the octet */

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 120), ZB_OK, "a transaction taken back at the top of the range");
    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 4 && apduOf(&air[3])[APS_COUNTER_OCTET_UNICAST] == 0xff, "it carries 0xff");
    stepAt(&rig, air, &airCount, 121);
    Test_Expect(Aps_PollConfirms(&rig.aps, confirms, 2) == 1, "answered");

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN, 0);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 122), ZB_OK, "and the next new transaction");
    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 5, "one frame");
    Test_Expect(apduOf(&air[4])[APS_COUNTER_OCTET_UNICAST] == 0x00,
           "carries 0x00: the counter is one octet and an octet wraps mod 256, exactly as the NWK sequence number does one layer down (2.2.5.1.7 with 3.3.1.5). Nothing in the standard numbers a start or a stop for it");

    Test_ExpectStatus(ApsFrame_Parse(apduOf(&air[4]), apduLenOf(&air[4]), &frame, &payloadOffset, &payloadLen), ZB_OK,
                  "and the wrapped frame is a frame this stack's own codec reads: the wrap produces a legal APDU, not a damaged one");
    Test_Expect(frame.frameType == APS_FRAME_TYPE_DATA && frame.deliveryMode == APS_DELIVERY_UNICAST
           && frame.apsCounter == 0x00 && frame.clusterId == CLUSTER_ID && frame.profileId == PROFILE_ID
           && frame.srcEndpoint == SRC_EP && frame.dstEndpoint == DST_EP
           && payloadLen == ASDU_LEN && Zb_memcmp(apduOf(&air[4]) + payloadOffset, asdu, ASDU_LEN) == 0,
           "with the counter it carries read back as 0x00 and the ASDU reported past the header it composed");
    Test_Expect(rig.aps.apsCounter == 1, "and the module's own counter continues from the wrap, not back at 0");

    stepAt(&rig, air, &airCount, 123);
}

/*
 * 7. The shape of the retransmissions (2.2.8.4.4, 2.2.8.4.5.3 for the counter, 3.3.1.5 for the numbering).
 *
 * No acknowledgement arrives at all. What this module owes is 1 + apscMaxFrameRetries transmissions of *the same
 * APDU*, each followed by a full apscAckWaitDuration, and then NO_ACK. The APDU is byte-identical every time
 * (same fields, same APS counter) because a retransmission is one transmission being repeated and the
 * acknowledgement, when it comes, is matched on the counter the original frame carried. The NWK frames around it
 * are all different, because the layer below numbers each frame it composes.
 */
/*
 * 7. The shape of the retransmissions (2.2.8.4.4, 2.2.5.1.7 with 2.2.8.4.5.3 for the counter, 3.3.1.5 for the
 * numbering).
 *
 * No acknowledgement arrives at all. What this module owes is 1 + apscMaxFrameRetries transmissions of *the same
 * APDU*, each followed by a full apscAckWaitDuration, and then NO_ACK. The APDU is byte-identical every time
 * (same fields, same APS counter) because a retransmission is one transmission being repeated and the
 * acknowledgement, when it comes, is matched on the counter the original frame carried. The NWK frames around it
 * are all different, because the layer below numbers each frame it composes.
 *
 * The clock this case walks is the one the machine runs on: a transmission at t, its NLDE answer collected at
 * t+1, the next transmission due at t+1+1600. The +1 is the suite's own turn and not a standard's margin, and
 * the assertions say which number each wait was armed from.
 */
void caseRetransmissionShape(void)
{
    Rig rig;
    Air air[AIR_LOG_MAX];
    Aps_Confirm confirms[2];
    Aps_ApsdeReq req;
    Aps_Frame frame;
    uint8_t wanted[APS_FRAME_MAX];
    uint32_t wantedLen;
    uint32_t wantedOffset;
    uint32_t airCount = 0;
    uint32_t i;
    static const uint8_t retried[ASDU_LEN] = { 0x72, 0x65, 0x74, 0x72, 0x79, 0x21 };

    rigBuild(&rig, OWN_SHORT);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, retried, ASDU_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK, "an acknowledged unicast that will never be answered");
    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 1, "the first transmission");

    stepAt(&rig, air, &airCount, 101);
    Test_Expect(rig.aps.tx[0].state == APS_TX_AWAITING_ACK && rig.aps.tx[0].ackDeadlineMs == 1701, "the wait is armed to 1701 ms");

    stepAt(&rig, air, &airCount, 1600);
    Test_Expect(airCount == 1, "nothing has been retransmitted at 1600 ms, one millisecond short of the wait: apscAckWaitDuration is the standard's number and not a margin this module chose (2.2.8.4.4, Table 2-23's printed 1.6 seconds)");
    Test_Expect(rig.aps.tx[0].state == APS_TX_AWAITING_ACK && Aps_ConfirmQueue(&rig.aps) == 0, "and the transaction is still waiting, still unanswered");

    stepAt(&rig, air, &airCount, 1701);
    Test_Expect(airCount == 2, "and at exactly one full wait after the first transmission it is transmitted again");
    Test_Expect(rig.aps.tx[0].state == APS_TX_AWAITING_NLDE,
           "the slot is back in AWAITING_NLDE and not in a fourth retrying state: a retry is the first transmission's obligation run again, with a larger attempt count and the same counter (docs/internals/coding-rules.md §3, 2.2.8.4.4)");

    stepAt(&rig, air, &airCount, 1702);
    Test_Expect(rig.aps.tx[0].state == APS_TX_AWAITING_ACK, "answered by the network layer again, waiting again");
    Test_Expect(rig.aps.tx[0].ackDeadlineMs == 3302,
           "with the next wait armed from this transmission's own confirmation: 3302 ms, and not the 3301 ms a wait charged once to the transaction would give. apscAckWaitDuration belongs to each transmission (2.2.8.4.4's \"repeat the process of transmitting the frame and waiting for the acknowledgement\")");

    stepAt(&rig, air, &airCount, 3301);
    Test_Expect(airCount == 2, "and 3301 ms is inside the wait that was armed at 1702 ms: the second retransmission is not due yet");

    stepAt(&rig, air, &airCount, 3302);
    Test_Expect(airCount == 3, "the third transmission, one full wait after the second");
    stepAt(&rig, air, &airCount, 3303);
    Test_Expect(rig.aps.tx[0].ackDeadlineMs == 4903, "wait three armed from transmission three");
    stepAt(&rig, air, &airCount, 4903);
    Test_Expect(airCount == 4, "the fourth transmission, which is 1 + apscMaxFrameRetries and the last one (Table 2-23: apscMaxFrameRetries 3, \"the maximum number of retries allowed after a transmission failure\", additional attempts, on top of the first)");
    Test_Expect(Aps_ConfirmQueue(&rig.aps) == 0, "and still nothing answered: the retries are not yet exhausted");

    stepAt(&rig, air, &airCount, 4904);
    Test_Expect(Aps_ConfirmQueue(&rig.aps) == 0 && airCount == 4, "the fourth wait runs its own turn, unanswered");

    stepAt(&rig, air, &airCount, 6504);
    Test_Expect(Aps_PollConfirms(&rig.aps, confirms, 2) == 1, "and the fifth wait is the one the retries do not survive");
    Test_Expect(confirms[0].apsStatus == APS_STATUS_NO_ACK && confirms[0].status == ZB_ERR_TIMEOUT,
           "NO_ACK 0xa7 beside ZB_ERR_TIMEOUT: Table 2-29's word for \"an APSDE-DATA.request requesting acknowledged transmission failed due to no acknowledgement being received\", and the seam's word for the same outcome (docs/internals/protocol.md §7.3)");
    Test_Expect(confirms[0].attempts == 1 + APS_MAX_FRAME_RETRIES, "with the attempt count the chain produced: four NLDE transactions");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0, "and the transaction released with it");

    dataHeader(&frame, APS_DELIVERY_UNICAST, 1, confirms[0].apsCounter, DST_EP, CLUSTER_ID);
    Test_ExpectStatus(ApsFrame_Compose(&frame, retried, ASDU_LEN, wanted, (uint32_t)sizeof wanted, &wantedLen, &wantedOffset), ZB_OK,
                  "the case composes the APDU this transaction was supposed to send, once, through the codec");
    Test_Expect(wantedLen == APS_HEADER_UNICAST_FORM + ASDU_LEN && ApsFrame_HeaderLen(&frame) == APS_HEADER_UNICAST_FORM,
           "eight octets of data header (frame control, destination endpoint, cluster, profile, source endpoint, APS counter) plus the ASDU (Figure 2-3 with Figure 2-7)");

    for (i = 0; i < 4; i++)
    {
        Test_Expect(apduLenOf(&air[i]) == wantedLen && Zb_memcmp(apduOf(&air[i]), wanted, wantedLen) == 0,
               "and every one of the four frames carried that APDU byte for byte: same fields, same APS counter, same ASDU. A retransmission that recomposed could not promise the counter 2.2.8.4.4 matches on, and 2.2.8.4.5.3 states the same rule for the blocks of a fragmented transmission");
        Test_Expect(apduOf(&air[i])[APS_COUNTER_OCTET_UNICAST] == confirms[0].apsCounter,
               "the counter the confirm reports is the counter all four transmissions carried: one number for one transaction (2.2.5.1.7)");
    }

    Test_Expect(nwkSeqOf(&air[0]) != nwkSeqOf(&air[1]) && nwkSeqOf(&air[1]) != nwkSeqOf(&air[2])
           && nwkSeqOf(&air[2]) != nwkSeqOf(&air[3]),
           "while the four NWK sequence numbers are all different: the layer below numbers each frame it composes (3.3.1.5), which is what makes four identical APDU travels four distinguishable NWK frames. 3.6.4.3's \"The NWK Sequence Number of a replayed packet SHALL NOT be changed\" is a router's rule about someone else's frame, not a sender's rule about retransmitting its own");

    Test_Expect(rig.aps.tx[0].apduLen == 0, "the released slot holds nothing: an answer clears it (docs/internals/coding-rules.md §4.3)");
    Test_Expect(Aps_RetransmitRefusals(&rig.aps) == 0 && Aps_UnmatchedAcks(&rig.aps) == 0,
           "and neither of the counters a retransmission the layer below refused, or an acknowledgement that arrived, would have moved moved: the NWK pool was free at each re-issue, and nothing arrived at all");
}


/*
 * 8. An unicast with no routing entry becomes the discovery 2.2.8.4.1 obliges, and the network layer's own
 * answer is still the one the transaction ends with (2.2.4.1.1.3, 3.6.4.5.1, Table 3-84).
 *
 * 2.2.8.4.1 makes the APS layer issue every frame it constructs with route discovery enabled at the network
 * layer, so the request below does not reach 3.6.4.3's discard: the network layer starts 3.6.4.5.1, holds the
 * frame in its own slot and broadcasts Table 3-79's request. What the case still asserts is the precedence:
 * "If one or more NLDE-DATA.confirm primitives failed, then the Status parameter SHALL be set to that received
 * from the NWK layer" is read as an end and not as a step, 2.2.8.4.4 retransmits the absence of an
 * *acknowledgement* and a frame that never reached the air owed none, and the two tables name one outcome with
 * two numbers.
 */
void caseNwkPrecedence(void)
{
    Rig rig;
    Air air[AIR_LOG_MAX];
    Aps_Confirm confirms[2];
    Aps_ApsdeReq req;
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t i;
    static const uint8_t routed[ASDU_LEN] = { 0x6e, 0x6f, 0x72, 0x6f, 0x75, 0x74 };

    rigBuild(&rig, OWN_SHORT);

    Test_Expect(Nwk_NeighborQueue(&rig.stack.nwk) == 0 && Nwk_RouteQueue(&rig.stack.nwk) == 0,
           "a device that has observed nothing has neither a neighbor entry nor a route (Table 3-66 prints both as \"Null set\")");

    req = sapReq(APS_ADDR_MODE_SHORT, UNSEEN, DST_EP, CLUSTER_ID, routed, ASDU_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK,
                  "an acknowledged request to a destination no route reaches: the sub-layer issued it with DiscoverRoute 0x01 (2.2.8.4.1), so this is 3.6.4.5.1's initiation and not 3.6.4.3's discard");

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 0, "and no frame of either kind has gone on the air yet: the request took a routing duty, not a transmit");
    Test_Expect(Nwk_DiscoveryQueue(&rig.stack.nwk) == 1, "the network layer holds one Table 3-74 entry for it (3.6.4.5.1's own record)");
    Test_Expect(Nwk_ConfirmQueue(&rig.stack.nwk) == 0, "and owes no NLDE confirmation yet: the frame is held, not refused");
    Test_Expect(Nwk_LastRequestHandle(&rig.stack.nwk) == RADIO_HANDLE_NONE,
           "and nothing has been handed the MAC: `Nwk_DataConfirmParameters.handle` is the pairing key normally, and a held frame has none");
    Test_Expect(Nwk_DroppedNoRoute(&rig.stack.nwk) == 0, "no discard counted");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 1, "the transaction is held above it, awaiting the answer the layer below will eventually give");

    stepAt(&rig, air, &airCount, 101);

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount >= 1, "and the discovery's own frame is on the air: Table 3-79's Route Request, broadcast as 3.6.4.5.1 schedules it");
    Test_Expect(airDestOf(&air[0]) == NWK_ADDR_ALL_DEVICES,
           "and the discovery's frame is the broadcast 3.6.6 gives a router-class NWK destination: the MAC name is the PAN's all-devices address (R23.1 3.6.1.7)");
    Test_Expect(Nwk_DroppedNoRoute(&rig.stack.nwk) == 0, "and still no discard counted anywhere: the clause's other answer was never reached");

    for (i = 0; i < 10; i++)
        stepAt(&rig, air, &airCount, 101 + i * (NWK_ROUTE_DISCOVERY_TIME_MS / 8));

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount >= NWK_RREQ_TX_COUNT, "the schedule ran its printed count of broadcasts (3.6.4.5.1's nwkcInitialRREQRetries + 1)");

    got = Aps_PollConfirms(&rig.aps, confirms, 2);
    Test_Expect(got == 1, "3.6.4.5.1.7's timer ends the wait and the transaction is answered once");
    Test_ExpectStatus(confirms[0].status, ZB_ERR_NO_ROUTE,
           "with the seam's name for the outcome, which is what a caller of this stack compares (3.6.4.3, docs/internals/protocol.md §7.3)");
    Test_Expect(confirms[0].apsStatus == NWK_STATUS_ROUTE_ERROR,
           "and with the network layer's own code beside it: 0xd1, Table 3-84's ROUTE_ERROR, because 2.2.4.1.1.3 makes the NLDE's status the APS Status parameter and Table 2-3 permits \"any status values returned from the NLDE-DATA.confirm primitive\". Two tables, one outcome, two numbers: a recorded fact");
    Test_Expect(confirms[0].attempts == 1,
           "one attempt in this module's counting (one NLDE transaction requested) while the frame itself never transmitted: the two attempt counts count different loops, one per transaction here and one per transmission below (3.2.1.1.3)");
    Test_Expect(confirms[0].dstAddress == UNSEEN && confirms[0].clusterId == CLUSTER_ID && confirms[0].dstEndpoint == DST_EP,
           "for the transaction the discovery answered, paired with the slot by the rule the drain states where a frame ran no transmit: the destination, in pool order (see `Aps_Tx.lastHandle` and the pairing note in aps_tx.c)");

    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0, "the transaction ended there: no acknowledgement wait was ever armed for a frame that never reached the air");
    Test_Expect(rig.aps.tx[0].ackDeadlineMs == 0, "the released slot's deadline says so: it was never armed");

    for (i = 0; i < 5; i++)
    {
        stepAt(&rig, air, &airCount, 101 + NWK_ROUTE_DISCOVERY_TIME_MS + 1 + i * (APS_ACK_WAIT_DURATION_MS + 1));
        Test_Expect(Aps_ConfirmQueue(&rig.aps) == 0,
               "a full apscAckWaitDuration later, and again after it, nothing is answered: no APS retry on a network-layer failure, because 2.2.8.4.4's subject is the absence of an acknowledgement (2.2.4.1.1.3's precedence)");
    }

    Test_Expect(Aps_UnmatchedAcks(&rig.aps) == 0 && Aps_RetransmitRefusals(&rig.aps) == 0,
           "and neither of the counters a retransmission would move moved");
    Test_Expect(Nwk_DroppedNoRoute(&rig.stack.nwk) == 0, "and the discard's counter never moved at all: this is the other answer the layer below gives");
}
