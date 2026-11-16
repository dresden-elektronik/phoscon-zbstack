/* The `aps` suite's reception half: what a received frame is decided to be,
   one gate of the reception sequence per case (duplicate rejection, the command this slice defers, the
   fragmentation it does not support, the codec's deferral family and its damage family, the frame that is no APDU
   at all) and the secured frame that is refused whole. */

#include "aps.h"
#include "aps_frame.h"
#include "aps_helpers.h"
#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "nwk.h"
#include "nwk_frame.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

/* A neighbor's NWK *command* frame, put in front of the MAC as the frame it is: the NWK codec composes the NPDU
   with the command identifier as its first payload octet (Figure 3-8 with 3.3.2.2.2), a MAC data frame carries
   that NPDU (3.4.1.1), and the footer closes it. Band A's `nwk` recognizes every identifier Table 3-54 prints and
   hands a recognized one up to the layer above it (the processing is deferred), so this is the one way a
   frame that is not an APDU at all reaches the APS sub-layer's doorstep, and case 22 asserts what the module does
   with it. */
static void injectNwkCommand(Loopback_Radio *model, uint16_t dst, uint16_t src, uint8_t seq,
                             uint8_t commandId, const uint8_t *body, uint32_t bodyLen)
{
    Nwk_Frame npdu;
    Mac_Frame frame;
    Loopback_FrameSpec spec;
    uint8_t payload[8];
    uint8_t octets[NWK_FRAME_NPDU_MAX];
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t len;
    uint32_t i;

    payload[0] = commandId;

    for (i = 0; i < bodyLen; i++)
        payload[1 + i] = body[i];

    Zb_memset(&npdu, 0, (uint32_t)sizeof npdu);
    npdu.frameType = NWK_FRAME_TYPE_COMMAND;
    npdu.protocolVersion = NWK_PROTOCOL_VERSION;
    npdu.discoverRoute = NWK_DISCOVER_SUPPRESS;
    npdu.destAddr = dst;
    npdu.srcAddr = src;
    npdu.radius = 6;
    npdu.sequenceNumber = seq;

    Test_ExpectStatus(NwkFrame_Compose(&npdu, payload, bodyLen + 1, octets, (uint32_t)sizeof octets, &npduLen), ZB_OK,
                  "the NPDU is one this stack's own codec composes, identifier octet first as 3.3.2.2.2 says");

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_DATA;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 1;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.destPan = PAN_ID;
    frame.srcPan = PAN_ID;
    frame.destShort = dst;
    frame.srcShort = src;
    frame.seq = seq;

    Test_ExpectStatus(MacFrame_Compose(&frame, octets, npduLen, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                  "a MAC data frame carries it, as every NWK frame travels (3.4.1.1)");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, (uint32_t)sizeof bytes, &len), ZB_OK,
                  "and the footer those octets compute closes it (7.2.11)");

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = len;
    spec.bytes = bytes;
    spec.rssiDbm = -60;
    spec.lqi = 200;
    spec.stampTicks = 3;
    spec.error = ZB_OK;

    Test_ExpectStatus(LoopbackRadio_Inject(model, &spec, 1), ZB_OK, "and it arrives as a neighbor's frame");
}

/*
 * 11. What a received frame is decided to be, and what the retired marker used to hide
 * (2.2.8.4.2, 2.2.8.4.3.2, 2.2.4.1.3, and the deferrals named below).
 *
 * The transitional `rxDeferred` counter is retired by this slice, and this case is the proof of it rather than a
 * claim: the frame that used to be counted and dropped is now parsed, judged valid, answered with an
 * acknowledgement the module composed and issued itself, and delivered upward as one Table 2-4 indication, while
 * the frame the codec refuses as a shape is counted as the shape it is, with nothing further running for it. The
 * two frames are the two families the codec documents, and the third part of the case is the doctrine that
 * survives from the earlier slice unchanged: a confirmation this module cannot tie to a transaction of its own is
 * taken and counted, because it has one poller of the ring below it.
 *
 * Part B (cases 13-24) is where each gate of the reception sequence gets its own case; this one is the smallest
 * pair that shows the counter is gone rather than renamed. Part C (cases 25-33) is the crossing the security
 * module adds on top of those gates: the two transmit directions of 4.4.1.1, the three partner resolutions
 * of 4.4.1.2, the two failure counters and the failure indication, and the four shapes that keep the
 * deferral counts.
 */
void caseRxDecided(void)
{
    Rig rig;
    Test_BandA peer;
    Air air[AIR_LOG_MAX];
    Aps_Frame frame;
    Aps_Indication inds[2];
    Nwk_DataRequestParameters req;
    uint8_t apdu[APS_FRAME_MAX];
    uint8_t shape[4];
    uint8_t wanted[APS_FRAME_MAX];
    uint32_t wantedLen;
    uint32_t len;
    uint8_t counter;
    uint32_t airCount = 0;
    static const uint8_t peerAsdu[ASDU_LEN] = { 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x21 };
    static const uint8_t direct[ASDU_LEN] = { 0x64, 0x69, 0x72, 0x65, 0x63, 0x74 };

    rigBuild(&rig, OWN_SHORT);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    /* A data frame addressed to this device with its AR sub-field set: exactly the frame that owes an
       acknowledgement, and the one the previous slice refused to answer. */
    dataHeader(&frame, APS_DELIVERY_UNICAST, 1, 0x2a, DST_EP, CLUSTER_ID);
    frame.srcEndpoint = 0x05;
    counter = frame.apsCounter;
    len = composeApdu(&frame, peerAsdu, ASDU_LEN, apdu);
    peerSends(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 100);

    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_IndicationQueue(&rig.aps) == 1,
           "the frame is delivered: one APSDE-DATA.indication in the ring 2.2.4.1.3's primitive leaves through, which is the act `rxDeferred` used to stand in for");
    Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1
           && inds[0].status == APS_STATUS_SUCCESS && inds[0].securityStatus == APS_STATUS_UNSECURED
           && inds[0].dstEndpoint == DST_EP && inds[0].srcEndpoint == 0x05,
           "with Status SUCCESS and the endpoints the frame carried, the source endpoint being the one this peer sent from");
    Test_Expect(Aps_AcksGenerated(&rig.aps) == 1 && airCount == 1,
           "and the acknowledgement this device owes went out (2.2.5.1.1.5 with 2.2.8.4.3.2): 2.2.8.4.3 fixes the moment (\"The transmission of an acknowledgement frame SHALL commence when the APS sub-layer determines that the frame is valid\") and the frame was valid by the time the indication was queued for it");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0 && Aps_ConfirmQueue(&rig.aps) == 0,
           "no transaction was opened by a reception and nothing is confirmed upward for one: what this module received is not what this module asked to send");
    Test_Expect(Aps_UnmatchedAcks(&rig.aps) == 0 && Aps_RxDuplicateDrops(&rig.aps) == 0
           && Aps_RxMalformed(&rig.aps) == 0 && Aps_RxShapeRefused(&rig.aps) == 0
           && Aps_RxSecuredDeferred(&rig.aps) == 0 && Aps_RxCommandDeferred(&rig.aps) == 0
           && Aps_DroppedGroupMiss(&rig.aps) == 0 && Aps_DroppedIndications(&rig.aps) == 0,
           "and not one of the reception counters moved on a refusal: this frame was accepted, and the only thing it cost was the answer it asked for");

    wantedLen = ackApdu(wanted, counter, DST_EP, 0x05, CLUSTER_ID);      /* the swap, read from the frame this peer sent: its source endpoint was 0x05 and its destination endpoint DST_EP, so the answer's destination is 0x05 and its source is DST_EP (2.2.5.2.3.1) */
    Test_Expect(apduLenOf(&air[0]) == wantedLen && Zb_memcmp(apduOf(&air[0]), wanted, wantedLen) == 0,
           "the octets on this device's air are the codec's own ACK format 0 form of 2.2.5.2.3.1's swap, which case 14 follows end to end and compares here only to prove the answer left through the network layer and not through a pool");

    /* A frame the codec will not read at all is counted as the shape it is and nothing further runs for it: the
       family the previous slice had to lump in with everything else. */
    shape[0] = (uint8_t)(APS_FRAME_TYPE_INTERPAN << APS_FRAME_FCF_TYPE_SHIFT);
    shape[1] = 0x00;
    shape[2] = 0x00;
    shape[3] = 0x00;
    peerSends(&peer, &rig.stack.model, OWN_SHORT, shape, 4, 102);

    stepAt(&rig, air, &airCount, 103);
    Test_Expect(Aps_RxShapeRefused(&rig.aps) == 1,
           "an Inter-PAN APS frame (frame type 0b11, Annex G.3.3's header, refused as a shape and never mis-parsed as an APDU) is counted as a shape and not as damage, and not as the delivery it would have been if the module had read it");
    Test_Expect(Aps_IndicationQueue(&rig.aps) == 0 && Aps_AcksGenerated(&rig.aps) == 1 && airCount == 1,
           "nothing was delivered for it and nothing new was answered: the one acknowledgement on the air is still the one the first frame owed");
    Test_Expect(Nwk_IndicationQueue(&rig.stack.nwk) == 0,
           "the ring below is emptied either way: band A has one poller of `Nwk_PollIndications`, and an indication left there is a frame that will refuse the next indication `nwk` tries to queue");

    /* The doctrine a layer up states as `confirmsIgnored`, applied here unchanged: a confirmation this module
       cannot tie to a transaction of its own is taken and counted rather than left to fill a ring that would
       refuse the next frame this module composes. The frame below it is issued straight on `nwk`, past this
       module. */
    req = nldeReq(ADDR_PEER, direct, ASDU_LEN);
    Test_ExpectStatus(Nwk_DataRequest(&rig.stack.nwk, &req, 104), ZB_OK, "the application issues on the network layer directly");
    stepAt(&rig, air, &airCount, 105);
    Test_Expect(Aps_ConfirmationsIgnored(&rig.aps) == 2,
           "two answers now match no transaction of this module's: the network layer's answer to the application's frame, and its answer to the acknowledgement this module sent on its own initiative, one poller of that ring, and an answer that cannot be paired is not an answer it may keep (the `nwk` doctrine, one layer up)");
    Test_Expect(Aps_ConfirmQueue(&rig.aps) == 0, "and it produced no APS confirmation: a frame this module did not compose is not a transaction of this module's");
    Test_Expect(Aps_IndicationQueue(&rig.aps) == 0 && Aps_AcksGenerated(&rig.aps) == 1, "the reception counters untouched by it");
}

/*
 * 18. Duplicate rejection: (source address, APS counter) once, and never twice (2.2.8.4.2, Table 2-23).
 *
 * The clause is one sentence long and it decides three things at once: what the record holds ("at least source
 * address, APS counter, and timing information"), what the table is for ("frames transmitted according to this
 * specification and received more than once are identified as duplicates and only delivered to the NHLE once"),
 * and how small it may be (`apscMinDuplicateRejectionTableSize`, printed as 1 in Table 2-23). It prints no interval
 * and no eviction rule: a record lasts APS_DUP_LIFETIME_MS, as long as a copy of its frame can arrive, and the case
 * reaches the rest: the same APDU twice is one delivery and one acknowledgement, a different counter from the same
 * source is a different frame, and the records this module cannot hold are the oldest of them, after which a frame
 * that *was* a duplicate is not one any more, which is the price of a bounded table and is stated instead of hidden.
 *
 * The order the case leans on is the order 2.2.8.4.2 prints: a duplicate is rejected
 * before the acknowledgement question is reached, so a retransmission from a sender that
 * never got its answer (exactly the case 2.2.8.4.4 describes) is not answered twice
 * either. That is what the counter staying at one while the frame arrives twice asserts.
 */
void caseDuplicateRejection(void)
{
    Rig rig;
    Test_BandA peer;
    Air air[AIR_LOG_MAX];
    Aps_Frame frame;
    Aps_Indication inds[2];
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t airCount = 0;
    uint32_t len;
    uint32_t i;
    static const uint8_t dupe[ASDU_LEN] = { 0x64, 0x75, 0x70, 0x65, 0x64, 0x21 };
    static const uint8_t first = 0x2a;
    static const uint8_t second = 0x2b;

    rigBuild(&rig, OWN_SHORT);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    dataHeader(&frame, APS_DELIVERY_UNICAST, 1, first, DST_EP, CLUSTER_ID);
    frame.srcEndpoint = 0x05;
    len = composeApdu(&frame, dupe, ASDU_LEN, apdu);

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_IndicationQueue(&rig.aps) == 1 && Aps_RxDuplicateDrops(&rig.aps) == 0, "the first copy is delivered");
    Test_Expect(Aps_AcksGenerated(&rig.aps) == 1 && airCount == 1, "and answered, because the frame asked and this device is its intended recipient");
    Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1 && inds[0].srcEndpoint == 0x05, "the delivery taken, so what follows is judged on its own");

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 102);
    stepAt(&rig, air, &airCount, 103);

    Test_Expect(Aps_RxDuplicateDrops(&rig.aps) == 1,
           "the second copy of the same (source address, APS counter) is a duplicate and is counted as one (2.2.8.4.2). The NWK sequence number of the two NPDUs differs, because the neighbor numbered two frames; the APS counter is the same, because it is one frame being sent again, and it is the APS counter the clause keys on");
    Test_Expect(Aps_IndicationQueue(&rig.aps) == 0,
           "and it is not delivered: the frames \"received more than once\" are the ones this table exists to deliver \"only … once\"");
    Test_Expect(Aps_AcksGenerated(&rig.aps) == 2 && airCount == 2,
           "and it is acknowledged a second time: 2.2.8.4.3.2's 'A frame that is received ... with its acknowledgement request sub-field set to 1 SHALL be acknowledged' is unqualified, while the clause that suppresses the duplicate suppresses the delivery alone, so a sender whose first acknowledgement was lost still learns the frame arrived");
    Test_Expect(Aps_RxMalformed(&rig.aps) == 0 && Aps_RxShapeRefused(&rig.aps) == 0,
           "and it is not damage: the frame parsed cleanly, and the only thing this module decided about it is that it had been here before");

    dataHeader(&frame, APS_DELIVERY_UNICAST, 1, second, DST_EP, CLUSTER_ID);
    frame.srcEndpoint = 0x05;
    len = composeApdu(&frame, dupe, ASDU_LEN, apdu);
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 104);
    stepAt(&rig, air, &airCount, 105);

    Test_Expect(Aps_IndicationQueue(&rig.aps) == 1 && Aps_RxDuplicateDrops(&rig.aps) == 1,
           "the same ASDU, the same source and a different APS counter is a different frame: the key is the pair, and 2.2.5.1.7's \"SHALL be incremented by one for each new transmission\" is what makes a new transmission distinguishable at all");
    Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1, "and that delivery is taken too, so every count below is one frame at a time");

    /* The pool's full policy, reached the honest way: enough distinct keys to fill it, then the frames that should
       have been duplicates and no longer are. */
    for (i = 0; i < APS_DUP_MAX; i++)
    {
        dataHeader(&frame, APS_DELIVERY_UNICAST, 0, (uint8_t)(0x40 + i), DST_EP, CLUSTER_ID);
        frame.srcEndpoint = 0x05;
        len = composeApdu(&frame, dupe, ASDU_LEN, apdu);
        peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 110 + i * 10);
        stepAt(&rig, air, &airCount, 111 + i * 10);
        Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1, "each of them delivered, and each one drained, so that it is the duplicate table and not the indication ring that is being tested here");
    }

    Test_Expect(Aps_RxDuplicateDrops(&rig.aps) == 1 && Aps_DroppedIndications(&rig.aps) == 0,
           "as many distinct keys as the table holds, no duplicate and no refusal for want of room: the table is now full at its named bound, and the two records it can no longer hold are the two oldest");

    dataHeader(&frame, APS_DELIVERY_UNICAST, 1, first, DST_EP, CLUSTER_ID);
    frame.srcEndpoint = 0x05;
    len = composeApdu(&frame, dupe, ASDU_LEN, apdu);
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 110 + APS_DUP_MAX * 10);
    stepAt(&rig, air, &airCount, 111 + APS_DUP_MAX * 10);

    Test_Expect(Aps_RxDuplicateDrops(&rig.aps) == 1 && Aps_IndicationQueue(&rig.aps) == 1,
           "and the counter that was a duplicate two injections ago is not one now: its record was the oldest in the pool, and a full pool replaces the oldest. That is band A's policy and not the standard's (2.2.8.4.2 prints no bound above \"at least 1\" and no eviction rule at all) and the cost is stated rather than smoothed over: a bounded table forgets, and a frame it forgot looks new");
    Test_Expect(Aps_AcksGenerated(&rig.aps) == 4,
           "and it is answered again: the pool forgot it, so it is a new frame to both the delivery rule and 2.2.8.4.3.2's acknowledgement");
    Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1, "and the delivery it produced is taken before the last injection");

    dataHeader(&frame, APS_DELIVERY_UNICAST, 0, (uint8_t)(0x40 + APS_DUP_MAX - 1), DST_EP, CLUSTER_ID);
    frame.srcEndpoint = 0x05;
    len = composeApdu(&frame, dupe, ASDU_LEN, apdu);
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 112 + APS_DUP_MAX * 10);
    stepAt(&rig, air, &airCount, 113 + APS_DUP_MAX * 10);

    Test_Expect(Aps_RxDuplicateDrops(&rig.aps) == 2 && Aps_IndicationQueue(&rig.aps) == 0,
           "while the most recent of them is still a duplicate: the eviction took the two oldest records and left the newest holding, which is the whole policy in one comparison");
    Test_Expect(Aps_UnmatchedAcks(&rig.aps) == 0 && Aps_DroppedGroupMiss(&rig.aps) == 0
           && Aps_RxSecuredDeferred(&rig.aps) == 0 && Aps_RxCommandDeferred(&rig.aps) == 0
           && Aps_RxMalformed(&rig.aps) == 0 && Aps_RxShapeRefused(&rig.aps) == 0,
           "and none of it was counted as anything else");
}

/*
 * 20. An APS command frame: recognized or not, deferred the same way (2.2.6, Table 4-31, 4.4.11).
 *
 * 2.2.6 is one sentence, "This specification defines no command frames. Refer to section 4.4.11", and what band A
 * defers is the machinery behind every identifier Table 4-31 prints, because transport key and update device are
 * the joining and trust-center services that are deferred. No indication is issued (Table 2-1 lists APSDE-DATA as
 * this sub-layer's only data service) and no acknowledgement is owed, which is the one judgement in the reception
 * sequence this stack derives rather than quotes and which `apsDoReceive` labels as such: 2.2.5.1.1.5's SHALL is
 * conditional on "determining that the frame is valid", and the deferrals make a command frame's validity
 * undecidable here. Recognition is a separate question, and the case asserts that it is not a different outcome:
 * an identifier the table prints and one it prints as Reserved are both counted, because this module does the
 * same thing to both.
 */
void caseCommandDeferred(void)
{
    Rig rig;
    Test_BandA peer;
    Air air[AIR_LOG_MAX];
    Aps_Frame frame;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t airCount = 0;
    uint32_t len;
    /* Figure 2-8: the identifier opens the APS payload, the command body after it */
    static const uint8_t bodyKey[5] = { APS_CMD_TRANSPORT_KEY, 0x00, 0x11, 0x22, 0x33 };
    static const uint8_t bodyReserved[5] = { 0x01, 0x00, 0x11, 0x22, 0x33 };    /* Table 4-31 prints 0x01-0x04 as Reserved */

    rigBuild(&rig, OWN_SHORT);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = APS_FRAME_TYPE_COMMAND;
    frame.deliveryMode = APS_DELIVERY_UNICAST;      /* 4.4.11's rule 2, quoted at `aps_frame`: "Set the delivery-mode sub-field to 0x00 (Unicast) or 0x10 (broadcast)" */
    frame.ackRequest = 1;
    frame.apsCounter = 0x2a;
    len = composeApdu(&frame, bodyKey, (uint32_t)sizeof bodyKey, apdu);

    Test_Expect(len == 2 + (uint32_t)sizeof bodyKey && frame.clusterPresent == 0 && frame.srcEndpointPresent == 0,
           "Figure 2-8's shape: frame control and APS counter, then a payload that opens with the APS command identifier, and no addressing field at all (2.2.5.2.2), the codec writes it and the case only names the fields");

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_RxMalformed(&rig.aps) == 1 && Aps_RxCommandDeferred(&rig.aps) == 0,
           "refused as damage and not deferred: 0x05 is the transport-key door's now, and this frame's four octets are not Figure 4-10's thirty-four, so the door refuses the body it was handed");
    Test_Expect(Aps_IndicationQueue(&rig.aps) == 0,
           "and indicated by nothing: Table 2-1 prints APSDE-DATA as the only service this sub-layer has, and a command frame is not data");
    Test_Expect(Aps_AcksGenerated(&rig.aps) == 0 && airCount == 0,
           "and answered with nothing, whatever its AR bit. 2.2.5.1.1.5's SHALL is judged against a frame this module determined valid, and a command frame's validity is decided by services this slice defers: the labeled derivation at `apsDoReceive`, and 2.2.5.1.1.3's ACK format 1 acknowledgement, which is the form an APS command is answered with, is named in the codec and composed here nowhere");
    Test_Expect(Aps_RxShapeRefused(&rig.aps) == 0,
           "and the shape family is untouched, the damage family and the deferral family being different counters: the frame's header is well-formed and what failed was the body's own length");

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = APS_FRAME_TYPE_COMMAND;
    frame.deliveryMode = APS_DELIVERY_UNICAST;
    frame.apsCounter = 0x2b;
    len = composeApdu(&frame, bodyReserved, (uint32_t)sizeof bodyReserved, apdu);
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 102);
    stepAt(&rig, air, &airCount, 103);

    Test_Expect(Aps_RxCommandDeferred(&rig.aps) == 1,
           "an identifier the table prints as Reserved is counted as the deferral, and so is every command but 0x05: `ApsFrame_IsKnownCommand` answers recognition and this module processes neither kind, so a counter that separated them would imply a decision nobody made");
    Test_Expect(Aps_IndicationQueue(&rig.aps) == 0 && Aps_AcksGenerated(&rig.aps) == 0 && airCount == 0,
           "with nothing indicated and nothing answered for either");
    Test_Expect(Aps_RxDuplicateDrops(&rig.aps) == 0,
           "and neither reached the duplicate table, for the reason stated at `Aps_DupSeen`: a frame that was never passed up is not a frame that was passed up twice");
}

/*
 * 21. A fragmented frame, at a build that reassembles it (2.2.8.4.5.4) and at one built without fragmentation, where
 * it takes the path 2.2.4.1.3.2 prints for exactly that device, with the null ASDU and no acknowledgement
 * (2.2.4.1.3.2, 2.2.8.4.5, Figure 2-5 with Table 2-22).
 *
 * The standard supplies the deferral, which is why this case invents nothing: "If the extended header is included
 * in the APDU header and the fragmentation sub-field of the extended frame control field indicates that the frame
 * is fragmented but this device does not support fragmentation, the APSDE sets the Status parameter to
 * DEFRAG_UNSUPPORTED", and then "If the Status parameter is not set to SUCCESS, the APSDE sets the ASDULength
 * parameter to 0 and the ASDU parameter to the null set of bytes." The frame is parsed (the extended header is a
 * shape this stack can read, and 2.2.8.4.5.1 requires a Revision 23 device to *support* fragmentation whether or
 * not it uses it) and what is deferred is the reassembly, which is the windows, timers and ACK bitfield of
 * 2.2.8.4.5.4. DEFRAG_DEFERRED is the same clause's other half, the status of a device that can defragment and is
 * currently unable to, and a build without fragmentation does not claim it.
 *
 * The ASDU is proved empty and not merely reported empty: the caller's buffer is polluted with a sentinel before
 * the poll and what comes back is zeros. That is the observable difference between "the null set of bytes" and a
 * truncated delivery handed up as though it were one.
 */
void caseFragmentedUnsupported(void)
{
    Rig rig;
    Test_BandA peer;
    Air air[AIR_LOG_MAX];
    Aps_Frame frame;
    Aps_Indication inds[2];
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t airCount = 0;
    uint32_t len;
    static const uint8_t block[ASDU_LEN] = { 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x31 };

    rigBuild(&rig, OWN_SHORT);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    dataHeader(&frame, APS_DELIVERY_UNICAST, 1, 0x2a, DST_EP, CLUSTER_ID);
    frame.extendedHeaderPresent = 1;
    frame.extFrameControl = (uint8_t)APS_FRAG_FIRST;
    frame.fragmentation = APS_FRAG_FIRST;
    frame.blockNumberPresent = 1;
    frame.blockNumber = 2;
    len = composeApdu(&frame, block, ASDU_LEN, apdu);

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&rig, air, &airCount, 101);

#if !ZB_APS_FRAGMENTATION
    Zb_memset(inds, 0xa5, (uint32_t)sizeof inds);
    Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1, "a build without fragmentation delivers the block at once");
    Test_ExpectCount(inds[0].status, APS_STATUS_DEFRAG_UNSUPPORTED, "as Table 2-4's DEFRAG_UNSUPPORTED");
    Test_Expect(inds[0].asduLength == 0 && inds[0].asdu[0] == 0 && inds[0].asdu[ASDU_LEN - 1] == 0,
                "with the null set of bytes, not the block");
    Test_ExpectCount(Aps_AcksGenerated(&rig.aps), 0, "and acknowledges nothing, so the sender sends no second block");
#else
    Test_Expect(Aps_IndicationQueue(&rig.aps) == 0,
           "the first block of a two-block transmission is kept and nothing is delivered yet, which is 2.2.8.4.5.4's reassembly");
    Test_ExpectCount(Aps_FragmentsReassembled(&rig.aps), 0, "with no ASDU put back together");
    Test_ExpectCount(Aps_AcksGenerated(&rig.aps), 1,
                     "and the window acknowledgement 2.2.8.4.5.4 asks for is composed for it");

    frame.fragmentation = APS_FRAG_SUBSEQUENT;
    frame.extFrameControl = (uint8_t)APS_FRAG_SUBSEQUENT;
    frame.blockNumber = 1;
    len = composeApdu(&frame, block, ASDU_LEN, apdu);
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 102);
    stepAt(&rig, air, &airCount, 103);

    Test_ExpectCount(Aps_RxDuplicateDrops(&rig.aps), 0,
                     "the second block is not a duplicate of the first, though 2.2.8.4.5.3 gives both the same APS counter: the block number is the key's fourth part");
    Test_ExpectCount(Aps_FragmentsReassembled(&rig.aps), 1, "and it completes the transaction");
    Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1, "which is delivered upward as one indication");
    Test_Expect(inds[0].status == APS_STATUS_SUCCESS && inds[0].asduLength == 2 * ASDU_LEN,
           "with Table 2-4's SUCCESS and the whole ASDU, two blocks of six octets");
    Test_Expect(Zb_memcmp(inds[0].asdu, block, ASDU_LEN) == 0
           && Zb_memcmp(inds[0].asdu + ASDU_LEN, block, ASDU_LEN) == 0,
           "in the order the blocks were sent");
#endif
}

/*
 * 22. The codec's deferral family on the wire, counted as the family it is (2.2.5, Annex G.3.3).
 *
 * Four frames that are each a form this stack has deliberately not built, rather than a frame whose octets
 * contradict themselves: Inter-PAN frame type 0b11 (Annex G.3.3's header of "only 4 fields totaling a maximum of 7
 * octets", which is not an APDU and is never mis-parsed as one), delivery mode 0b01 and fragmentation 0b11 (both
 * printed Reserved by Tables 2-21 and 2-22), and the reserved half of the extended frame control nonzero (2.2.5's
 * reception rule: "all fields marked as reserved in this version of the specification SHALL be checked for being
 * equal to zero. If such a reserved field is not equal to zero, no further processing SHALL be applied to the
 * frame and the frame SHALL be discarded"). Plus one frame that is not an APS frame in any shape at all: a
 * neighbor's NWK command frame, which band A's network layer recognizes and hands up and which the APS sub-layer
 * therefore declines before it parses anything. All five land in `rxShapeRefused` and none in `rxMalformed`, which
 * is the split `aps_frame` documents and this module keeps: the same pair `nwk` counts one layer down as
 * `droppedUnsupported` against `droppedMalformed`.
 */
void caseShapeRefused(void)
{
    Rig rig;
    Test_BandA peer;
    Air air[AIR_LOG_MAX];
    uint8_t interPan[4];
    uint8_t reservedMode[4];
    uint8_t reservedFrag[9];
    uint8_t reservedHalf[9];
    uint32_t airCount = 0;
    static const uint8_t statusBody[4] = { 0x00, 0x11, 0x22, 0x33 };

    rigBuild(&rig, OWN_SHORT);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    interPan[0] = (uint8_t)(APS_FRAME_TYPE_INTERPAN << APS_FRAME_FCF_TYPE_SHIFT);
    interPan[1] = 0x00;
    interPan[2] = 0x00;
    interPan[3] = 0x00;

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, interPan, 4, 100);
    stepAt(&rig, air, &airCount, 101);
    Test_Expect(Aps_RxShapeRefused(&rig.aps) == 1,
           "frame type 0b11 is refused as the shape it is and never parsed as an APDU: Annex G.3.3's Inter-PAN header is four fields with bit 4 printed Reserved instead of ACK format, so reading it in Figure 2-3's columns would invent a cluster identifier out of a group address");

    reservedMode[0] = (uint8_t)(APS_DELIVERY_RESERVED << APS_FRAME_FCF_DELIVERY_MODE_SHIFT);
    reservedMode[1] = 0x00;
    reservedMode[2] = 0x00;
    reservedMode[3] = 0x00;

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, reservedMode, 4, 102);
    stepAt(&rig, air, &airCount, 103);
    Test_Expect(Aps_RxShapeRefused(&rig.aps) == 2,
           "delivery mode 0b01 the same way: Table 2-21 prints it Reserved and 2.2.5.1.1.2 says the sub-field \"SHALL be set to one of the non-reserved values from Table 2-21\". The Frame Control Field is judged before a single addressing octet is read, which is why these two are not also counted as truncation: a four-octet sample is not what condemned them");

    reservedFrag[0] = (uint8_t)(1 << APS_FRAME_FCF_EXTENDED_SHIFT);
    reservedFrag[1] = DST_EP;
    reservedFrag[2] = (uint8_t)(CLUSTER_ID & 0xff);
    reservedFrag[3] = (uint8_t)(CLUSTER_ID >> 8);
    reservedFrag[4] = (uint8_t)(PROFILE_ID & 0xff);
    reservedFrag[5] = (uint8_t)(PROFILE_ID >> 8);
    reservedFrag[6] = SRC_EP;
    reservedFrag[7] = 0x2a;
    reservedFrag[8] = (uint8_t)APS_FRAG_RESERVED;
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, reservedFrag, 9, 104);
    stepAt(&rig, air, &airCount, 105);
    Test_Expect(Aps_RxShapeRefused(&rig.aps) == 3,
           "and fragmentation 0b11, Table 2-22's Reserved row: a complete eight-octet data header plus one extended frame control, so nothing is missing from the frame, the value it carries is the one the table does not print");

    Zb_memcpy(reservedHalf, reservedFrag, 9);
    reservedHalf[8] = 0x04;     /* Figure 2-6's bits 2-7, printed Reserved, nonzero; bits 0-1 read back as 0b00 */
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, reservedHalf, 9, 106);
    stepAt(&rig, air, &airCount, 107);
    Test_Expect(Aps_RxShapeRefused(&rig.aps) == 4,
           "and a Reserved field that is nonzero, which 2.2.5 orders discarded rather than corrected: \"no further processing SHALL be applied to the frame and the frame SHALL be discarded\"");

    injectNwkCommand(&rig.stack.model, OWN_SHORT, ADDR_PEER, 7, NWK_CMD_NETWORK_STATUS, statusBody,
                     (uint32_t)sizeof statusBody);
    stepAt(&rig, air, &airCount, 108);
    Test_Expect(Nwk_RecognizedCommands(&rig.stack.nwk) == 1,
           "the fifth frame is not an APS frame in any shape: it is a neighbor's NWK command frame, Table 3-54's Network Status, which the layer below recognizes and hands up because the processing is deferred");
    Test_Expect(Aps_RxShapeRefused(&rig.aps) == 5,
           "and this module declines it before parsing anything, under the same counter as the codec's deferral family, because the alternative is exactly the mis-parse that family exists to prevent: 3.3.2.2.2 makes the payload's first octet the NWK command identifier, so that octet would have been read as an APS Frame Control Field, 0x03 as an Inter-PAN frame type, and Table 3-54's Route Reply 0x02 as an acknowledgement of Figure 2-9 this module would have tried to match against its own transactions. 2.2.8.4.2's subject is \"frames arriving via the NWK layer data service\", and a command frame is not one");

    Test_Expect(Aps_RxMalformed(&rig.aps) == 0,
           "and not one of the four counted as damage. The split is the codec's and this module only keeps it: ZB_ERR_UNSUPPORTED is the family of forms band A does not read, ZB_ERR_BAD_FRAME the family of frames whose own octets contradict each other, and a service that conflated them could not tell a deferral from a fault (the same pair `nwk` counts as `droppedUnsupported` and `droppedMalformed`)");
    Test_Expect(Aps_IndicationQueue(&rig.aps) == 0 && Aps_AcksGenerated(&rig.aps) == 0 && airCount == 0,
           "nothing was delivered for any of them and nothing was answered");
    Test_Expect(Aps_RxSecuredDeferred(&rig.aps) == 0 && Aps_RxCommandDeferred(&rig.aps) == 0
           && Aps_RxDuplicateDrops(&rig.aps) == 0 && Aps_DroppedGroupMiss(&rig.aps) == 0,
           "and none of the service's own deferrals moved, because none of these frames got as far as the service");
}

/*
 * 23. A damaged APDU: counted as damage, which is the other family (2.2.5, Figure 2-4, `aps_frame`'s split).
 *
 * Three frames whose octets claim something the clauses forbid. A header that stops inside a field its own Frame
 * Control Field says is present. An acknowledgement with its ACK request sub-field set, which 2.2.8.4.3 forbids in
 * one sentence. And a source endpoint of 0xff, which 2.2.5.1.6 and Table 2-2 make a destination value alone. None
 * of the three is a form band A has declined to build, and the counter they land in is what tells them apart from
 * case 22.
 */
void caseMalformedApdu(void)
{
    Rig rig;
    Test_BandA peer;
    Air air[AIR_LOG_MAX];
    uint8_t truncated[5];
    uint8_t ackAsking[1];
    uint8_t badSource[APS_HEADER_UNICAST_FORM];
    uint32_t airCount = 0;

    rigBuild(&rig, OWN_SHORT);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    truncated[0] = APS_FCF_DATA_UNICAST;
    truncated[1] = DST_EP;
    truncated[2] = (uint8_t)(CLUSTER_ID & 0xff);
    truncated[3] = (uint8_t)(CLUSTER_ID >> 8);
    truncated[4] = (uint8_t)(PROFILE_ID & 0xff);

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, truncated, 5, 100);
    stepAt(&rig, air, &airCount, 101);
    Test_Expect(Aps_RxMalformed(&rig.aps) == 1,
           "a data unicast header of eight octets that stops at the fifth: \"a frame that ends inside a field its own Frame Control Field says is present\" is damage, and that FCF said cluster, profile, source endpoint and counter were coming");

    ackAsking[0] = (uint8_t)((APS_FRAME_TYPE_ACK << APS_FRAME_FCF_TYPE_SHIFT)
                             | (1 << APS_FRAME_FCF_ACK_REQUEST_SHIFT));
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, ackAsking, 1, 102);
    stepAt(&rig, air, &airCount, 103);
    Test_Expect(Aps_RxMalformed(&rig.aps) == 2,
           "an acknowledgement that asks for an acknowledgement: 2.2.8.4.3, \"An acknowledgement frame SHALL always be sent with the acknowledgement request sub-field set to 0\". It is condemned before any matching attempt, so it is damage and not an unmatched answer, and the counter says which, which matters because `unmatchedAcks` is the counter for an acknowledgement this module had a transaction to consider it a reply to");

    badSource[0] = APS_FCF_DATA_UNICAST;
    badSource[1] = DST_EP;
    badSource[2] = (uint8_t)(CLUSTER_ID & 0xff);
    badSource[3] = (uint8_t)(CLUSTER_ID >> 8);
    badSource[4] = (uint8_t)(PROFILE_ID & 0xff);
    badSource[5] = (uint8_t)(PROFILE_ID >> 8);
    badSource[6] = APS_ENDPOINT_ALL;        /* the broadcast endpoint, used as a source */
    badSource[7] = 0x2a;
    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, badSource, APS_HEADER_UNICAST_FORM, 104);
    stepAt(&rig, air, &airCount, 105);

    Test_Expect(Aps_RxMalformed(&rig.aps) == 3,
           "and a frame whose source endpoint is 0xff: 2.2.5.1.6 prints 0x00 and 0x01-0xfe for the field and Table 2-2 prints SrcEndpoint as \"0x00 – 0xfe\", so a complete eight-octet header can still carry a value the clauses do not print");
    Test_Expect(Aps_RxShapeRefused(&rig.aps) == 0, "and none of the three counted as an unsupported form: the split holds in both directions");
    Test_Expect(Aps_IndicationQueue(&rig.aps) == 0 && Aps_AcksGenerated(&rig.aps) == 0
           && Aps_UnmatchedAcks(&rig.aps) == 0 && Aps_RxDuplicateDrops(&rig.aps) == 0
           && airCount == 0,
           "nothing was delivered, nothing was answered, nothing was matched as an acknowledgement, nothing was recorded as accepted, and nothing went back out");
}

/*
 * 19. A secured APDU at a device with no provider attached: deferred whole, neither delivered nor answered
 * (the deferral count, kept for the secured shapes too; 2.2.5.1.1.4, 2.2.4.1.3.2, 2.2.8.4.3.2).
 *
 * The frame is a legal one (the codec reads FCF bit 5 as the flag it is and reports the payload region
 * untouched, which is where 4.4.10's auxiliary header and MIC sit) and this rig has no `Security`
 * attached, so 2.2.5.1.1.4's Security Services Provider is the one thing this device does not have and
 * no processing can be undertaken. What the case pins is that the deferral is a *decision* with two
 * consequences: no indication, because 2.2.4.1.3.2 puts the security processing of a secured frame before
 * the Status parameter it goes on to set and there is no processing to run; and no acknowledgement
 * even though the frame asked for one, because 2.2.8.4.3.2 obliges the answer of "the intended
 * recipient [that] correctly receives the frame", and a payload this device cannot authenticate was not
 * correctly received. A frame whose payload this stack cannot judge is not a frame it has judged valid.
 *
 * The secured frame's family changed without this outcome changing, and the distinction is what
 * the case now says out loud: a secured frame at a device with no provider, and a secured frame whose control octet
 * names a key identifier band A does not read, are *shapes* and keep `rxSecuredDeferred` with nothing further
 * running for them; a secured frame that reached 4.4.1.2 and failed there is indicated with SECURITY_FAIL and the
 * null ASDU, which is what cases 29, 30 and 33 assert. Attaching the module is what separates them, and this is the
 * one secured case in the suite that never attaches it.
 */
void caseSecuredDeferred(void)
{
    Rig rig;
    Test_BandA peer;
    Air air[AIR_LOG_MAX];
    Aps_Frame frame;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t airCount = 0;
    uint32_t len;
    static const uint8_t sealed[ASDU_LEN] = { 0x73, 0x65, 0x63, 0x75, 0x72, 0x65 };

    rigBuild(&rig, OWN_SHORT);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    dataHeader(&frame, APS_DELIVERY_UNICAST, 1, 0x2a, DST_EP, CLUSTER_ID);
    frame.securityEnabled = 1;
    len = composeApdu(&frame, sealed, ASDU_LEN, apdu);

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_RxSecuredDeferred(&rig.aps) == 1,
           "counted as the deferral it is, exactly the count recorded for every secured frame and which is kept for the shapes this stack does not run: the way `nwk` counted a secured frame it could not read before the secured paths landed");
    Test_Expect(Aps_RxSecuredFailuresAuth(&rig.aps) == 0 && Aps_RxSecuredFailuresCounters(&rig.aps) == 0,
           "and not in either failure counter, which is the line the crossing draws: a failure count is for a frame that reached 4.4.1.2 and failed inside it, and this frame never reached a procedure because this device holds no key material at all");
    Test_Expect(Aps_IndicationQueue(&rig.aps) == 0 && Aps_DroppedIndications(&rig.aps) == 0,
           "nothing indicated upward, and nothing dropped for want of room either: there was no delivery to queue");
    Test_Expect(Aps_AcksGenerated(&rig.aps) == 0 && airCount == 0,
           "no acknowledgement, whatever the AR bit: the obligation is conditional on the frame being valid, and this device has no way to reach that judgement. Answering on fields read out of an unauthenticated octet string would be trusting exactly the octets 4.4.1 exists to make trustworthy");
    Test_Expect(Aps_RxMalformed(&rig.aps) == 0 && Aps_RxShapeRefused(&rig.aps) == 0,
           "and the frame is neither damage nor an unsupported form: the codec parsed it, and it is the service that has nothing to do with it");
    Test_Expect(Aps_RxDuplicateDrops(&rig.aps) == 0,
           "and it never reached the duplicate table at all, which is what makes the next injection count again instead of counting as a repeat");

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 102);
    stepAt(&rig, air, &airCount, 103);
    Test_Expect(Aps_RxSecuredDeferred(&rig.aps) == 2 && Aps_RxDuplicateDrops(&rig.aps) == 0,
           "the same secured frame twice is the deferral twice: the table records frames this module passed up, and this one was not passed up (see `Aps_DupSeen`)");
}
