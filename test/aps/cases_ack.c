/* The `aps` suite's acknowledgement machine: the answer that matches, the
   sweep of answers that do not, and the transaction a peer answers end to end, the case where the
   acknowledgement owed is composed by the module that owes it. */

#include "aps.h"
#include "aps_frame.h"
#include "aps_helpers.h"
#include "nwk.h"
#include "test_harness.h"
#include "zb_utils.h"

#define CHAIN_START_MS 101
#define CHAIN_STRIDE_MS APS_ACK_WAIT_DURATION_MS
#define CHAIN_TURNS 8

/* One transaction's whole acknowledgement chain, in the scripted clock: the turn that collects the NLDE answer,
   then one turn per `apscAckWaitDuration` until the module answers. The stride is the printed wait itself, so a
   case that reaches its answer on this schedule has had every wait it was owed. */
typedef struct Chain
{
    uint32_t turns;
    uint32_t answeredAtMs;
} Chain;

/* Run one acknowledged transaction to the answer 2.2.8.4.4 prints at the end of its waits, stepping by exactly
   `apscAckWaitDuration`. Returns the number of turns it took and the moment it was answered, so a case can say
   how many waits the transaction was owed. */
static void runChain(Rig *rig, Air *air, uint32_t *airCount, uint32_t fromMs, Aps_Confirm *out, Chain *chain)
{
    uint32_t nowMs = fromMs;
    uint32_t turn;

    chain->turns = 0;
    chain->answeredAtMs = 0;

    for (turn = 0; turn < CHAIN_TURNS; turn++)
    {
        stepAt(rig, air, airCount, nowMs);
        chain->turns++;

        if (Aps_ConfirmQueue(&rig->aps) != 0)
        {
            Test_Expect(Aps_PollConfirms(&rig->aps, out, 1) == 1, "the answer is one confirmation, on the SAP's own channel (2.2.4.1.2)");
            chain->answeredAtMs = nowMs;

            return;
        }

        nowMs = nowMs + CHAIN_STRIDE_MS;
    }

    Test_Expect(0, "the transaction was answered within its own chain of waits");
}

/* A script that answers nothing in time: `pendingPumps` is how many pumps must pass before a transmit's result is
   ready, so a case that needs the layers below to still be busy at the end of it asks for a hundred of them
   (test/mac/cases_confirm.c's stand-in for a frame that never gets a MAC acknowledgment). */
static void scriptPending(Loopback_Radio *model, uint32_t count, uint32_t pumps)
{
    Loopback_Outcome outcomes[LOOPBACK_TX_MAX];
    uint32_t i;

    Zb_memset(outcomes, 0, (uint32_t)sizeof outcomes);

    for (i = 0; i < count; i++)
    {
        outcomes[i].status = ZB_OK;
        outcomes[i].isAcked = 1;
        outcomes[i].pendingPumps = pumps;
    }

    LoopbackRadio_ScriptOutcomes(model, outcomes, count);
}

/*
 * 5. The acknowledgement that answers (2.2.8.4.3, 2.2.8.4.4, 2.2.5.2.3.1).
 *
 * Two stacks. A addresses B with AR set; B's own network layer carries an acknowledgement APDU to A; A matches
 * it on the four parts 2.2.8.4.4 prints, cluster identifier, APS counter, source endpoint equal to the
 * destination endpoint it transmitted to, and band A's own guard that the frame came from the device it
 * addressed (the guard band A names), and answers SUCCESS with one attempt and no retransmission.
 */
void caseAckHappyPath(void)
{
    Rig rig;
    Test_BandA peer;
    Air air[AIR_LOG_MAX];
    Aps_Confirm confirms[2];
    Aps_ApsdeReq req;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t apduLen;
    uint8_t counter;
    uint32_t airCount = 0;
    uint32_t got;
    static const uint8_t asked[ASDU_LEN] = { 0x6f, 0x6e, 0x6f, 0x66, 0x66, 0x21 };

    rigBuild(&rig, OWN_SHORT);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asked, ASDU_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK,
                  "an acknowledged unicast: TxOptions 0x04 is the only way this SAP asks for an acknowledgement (Table 2-2, 2.2.5.1.1.5)");

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 1, "one frame on the air");
    Test_Expect(apduOf(&air[0])[0] == APS_FCF_DATA_UNICAST_ACKED,
           "with its ACK request sub-field set (FCF bit 6, 0x40) which is what makes the peer owe a reply at all (2.2.8.4.3.2: \"the intended recipient … SHALL generate and send an acknowledgement frame to the originator\")");
    counter = apduOf(&air[0])[APS_COUNTER_OCTET_UNICAST];

    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_ConfirmQueue(&rig.aps) == 0 && Aps_TransmitQueue(&rig.aps) == 1,
           "the network layer's success is not yet an answer: AR was asked, so the transaction waits for the acknowledgement (2.2.4.1.1.3's precedence, then 2.2.8.4.4)");
    Test_Expect(rig.aps.tx[0].state == APS_TX_AWAITING_ACK, "in AWAITING_ACK");
    Test_Expect(rig.aps.tx[0].ackDeadlineMs == 101 + APS_ACK_WAIT_DURATION_MS,
          "with the wait armed from this transmission: apscAckWaitDuration is charged to each transmission and not to the transaction (2.2.8.4.4's \"repeat the process of transmitting the frame and waiting for the acknowledgement\")");

    apduLen = ackApdu(apdu, counter, DST_EP, SRC_EP, CLUSTER_ID);
    peerSends(&peer, &rig.stack.model, OWN_SHORT, apdu, apduLen, 102);

    stepAt(&rig, air, &airCount, 102);

    got = Aps_PollConfirms(&rig.aps, confirms, 2);
    Test_Expect(got == 1 && confirms[0].status == ZB_OK && confirms[0].apsStatus == APS_STATUS_SUCCESS,
           "the acknowledgement answers the transaction with SUCCESS (2.2.8.4.4: \"the transmission SHALL be considered successful\")");
    Test_Expect(confirms[0].attempts == 1, "after one transmission");
    Test_Expect(confirms[0].apsCounter == counter && confirms[0].clusterId == CLUSTER_ID,
           "for the counter and cluster the acknowledgement repeated");
    Test_Expect(Aps_UnmatchedAcks(&rig.aps) == 0, "and nothing unmatched: the match was the printed one, not an accident");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0, "the slot released");
    Test_Expect(Aps_ConfirmQueue(&rig.aps) == 0, "and exactly one confirmation was owed");

    stepAt(&rig, air, &airCount, 103);
    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 1, "and no retransmission followed the answer: a transaction that was answered has nothing left to transmit (2.2.8.4.4 ends at the acknowledgement)");
    Test_Expect(Aps_ConfirmQueue(&rig.aps) == 0 && Aps_ConfirmationsIgnored(&rig.aps) == 0,
           "nothing further was answered, and the acknowledgement itself was never indicated upward: it carries no ASDU and Table 2-1 prints no primitive that would carry it");
}

/*
 * 6. The mismatch sweep (2.2.8.4.4's match, and the guard band A adds to it).
 *
 * Three transactions, each answered by an acknowledgement that fails the match for one of the three named
 * reasons: a different APS counter, a different source endpoint, and a frame from a device that is not the one
 * the transaction addressed. 2.2.8.4.4 states both halves of what must then happen: the attempt is a failure,
 * so the retries run out and the transaction is answered NO_ACK, and the frame is not an answer to anything
 * else either; it is counted and not indicated.
 *
 * Three stacks: B answers the first and third, and C (a device A has never heard of) answers the second with an
 * acknowledgement whose APS fields are perfect. The guard is band A's and is labeled as band A's in the code
 * and labeled in the code; without it a stranger could answer a transaction it was never part of.
 */
void caseAckMismatchSweep(void)
{
    Rig rig;
    Test_BandA peer;
    Test_BandA other;
    Air air[AIR_LOG_MAX];
    Aps_Confirm confirms[2];
    Chain chain;
    Aps_ApsdeReq req;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t apduLen;
    uint32_t airCount = 0;
    uint32_t i;
    uint8_t counter;
    static const uint8_t sweep[ASDU_LEN] = { 0x73, 0x77, 0x65, 0x65, 0x70, 0x21 };

    rigBuild(&rig, OWN_SHORT);
    peerBuild(&peer, ADDR_PEER);
    peerBuild(&other, ADDR_THIRD);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    seedNeighbor(&other.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);

    /* One: the counter does not match. */
    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, sweep, ASDU_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK, "an acknowledged transaction");
    harvestAir(&rig.stack.model, air, &airCount);
    counter = apduOf(&air[0])[APS_COUNTER_OCTET_UNICAST];
    stepAt(&rig, air, &airCount, 101);

    apduLen = ackApdu(apdu, (uint8_t)(counter + 1), DST_EP, SRC_EP, CLUSTER_ID);
    peerSends(&peer, &rig.stack.model, OWN_SHORT, apdu, apduLen, 102);

    stepAt(&rig, air, &airCount, 103);
    Test_Expect(Aps_UnmatchedAcks(&rig.aps) == 1,
           "an acknowledgement carrying \"the same cluster identifier and APS counter as the original frame\" (2.2.8.4.4) with a counter one off is not an answer: counted as unmatched and not indicated");
    Test_Expect(Aps_ConfirmQueue(&rig.aps) == 0 && Aps_TransmitQueue(&rig.aps) == 1,
           "and the transaction is still outstanding: a mismatch is a failed attempt, not an end");

    runChain(&rig, air, &airCount, 1701, &confirms[0], &chain);
    Test_Expect(confirms[0].apsStatus == APS_STATUS_NO_ACK && confirms[0].status == ZB_ERR_TIMEOUT,
           "answered NO_ACK 0xa7 (Table 2-29) under the seam's own name for a reply that never arrived (docs/internals/protocol.md §7.3)");
    Test_Expect(confirms[0].attempts == 1 + APS_MAX_FRAME_RETRIES,
           "after 1 + apscMaxFrameRetries transmissions (2.2.8.4.4: \"repeat the process of transmitting the frame and waiting for the acknowledgement, up to a maximum of apscMaxFrameRetries times … then … notify the next higher layer of the failure\")");

    /* Two: every APS field matches and the frame is not from the device that was addressed. */
    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, sweep, ASDU_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 8200), ZB_OK, "a second acknowledged transaction, aimed at B");
    harvestAir(&rig.stack.model, air, &airCount);
    counter = apduOf(&air[airCount - 1])[APS_COUNTER_OCTET_UNICAST];
    stepAt(&rig, air, &airCount, 8201);

    apduLen = ackApdu(apdu, counter, DST_EP, SRC_EP, CLUSTER_ID);
    peerSends(&other, &rig.stack.model, OWN_SHORT, apdu, apduLen, 8202);

    stepAt(&rig, air, &airCount, 8203);
    Test_Expect(Aps_UnmatchedAcks(&rig.aps) == 2,
           "and the perfect acknowledgement from C is unmatched too: band A's guard requires the frame's NWK source to be the address the transaction was aimed at, which is the addressing half of \"the transmission SHALL be considered successful\" and 2.2.8.4.3.2's \"the intended recipient … SHALL generate and send an acknowledgement frame to the originator\" (named band A's)");

    runChain(&rig, air, &airCount, 8301, &confirms[0], &chain);
    Test_Expect(confirms[0].apsStatus == APS_STATUS_NO_ACK && confirms[0].clusterId == CLUSTER_ID,
           "so this transaction too runs out its retries and is answered NO_ACK");

    /* Three: the endpoint does not match. */
    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, 0x03, CLUSTER_ID, sweep, ASDU_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 15000), ZB_OK, "a third acknowledged transaction, addressed to endpoint 0x03");
    harvestAir(&rig.stack.model, air, &airCount);
    counter = apduOf(&air[airCount - 1])[APS_COUNTER_OCTET_UNICAST];
    stepAt(&rig, air, &airCount, 15001);

    apduLen = ackApdu(apdu, counter, 0x04, SRC_EP, CLUSTER_ID);
    peerSends(&peer, &rig.stack.model, OWN_SHORT, apdu, apduLen, 15002);

    stepAt(&rig, air, &airCount, 15003);
    Test_Expect(Aps_UnmatchedAcks(&rig.aps) == 3,
           "an acknowledgement whose source endpoint is not \"equal to the destination endpoint to which the original frame was transmitted\" (2.2.8.4.4) is unmatched, whatever else it repeats");

    runChain(&rig, air, &airCount, 15101, &confirms[0], &chain);
    Test_Expect(confirms[0].apsStatus == APS_STATUS_NO_ACK, "and it ends the same way");

    Test_Expect(Aps_UnmatchedAcks(&rig.aps) == 3 && Aps_TransmitQueue(&rig.aps) == 0,
           "three unmatched acknowledgements in the module's own counter, three transactions released");
    Test_Expect(Aps_IndicationQueue(&rig.aps) == 0 && Aps_DroppedIndications(&rig.aps) == 0
           && Aps_RxMalformed(&rig.aps) == 0 && Aps_RxShapeRefused(&rig.aps) == 0
           && Aps_RxDuplicateDrops(&rig.aps) == 0 && Aps_AcksGenerated(&rig.aps) == 0,
           "and none of them left anything behind at the reception half either: an acknowledgement is an answer to this module's transaction and not a delivery, matched or not (2.2.5.2.3: it is a frame type, not a command), so it is indicated by nothing, refused by nothing and answered by nothing, 2.2.8.4.3 states the same fact from the sending side, that an acknowledgement always carries an ACK request sub-field of 0");

    for (i = 0; i < 3; i++)
    {
        Test_Expect(rig.aps.tx[i].state == APS_TX_FREE, "and the slots they used are free again");
    }
}

/*
 * 14. The acknowledgement this device owes, end to end (2.2.5.1.1.5, 2.2.8.4.3.2, Figure 2-9, 2.2.5.2.3.1).
 *
 * The whole round trip, with the answer composed by the module that owes it and not by the case: the device under
 * test acknowledges with a fresh NPDU its own network layer composed and issued, and A's landed match machinery
 * answers its transaction with it. The answer is asserted against an independent composition the case makes for
 * comparison only, and the comparison is the point, because a swapped-pair acknowledgement the case invented and
 * the module wrote would agree with each other and disagree with 2.2.5.2.3.1.
 *
 * What the receiving side has to show as well as what A does: the answer is not a transaction. It
 * consumed no slot of the receiving module's transaction pool, it produced no APS confirmation
 * of that module's, and its own NLDE confirmation matched nothing it had asked to send, which
 * is `confirmsIgnored`, the doctrine `nwk` applies to a relay and a 3.6.13 reply one layer
 * down. And the frame it answers is still delivered upward: 2.2.8.4.3.2 and 2.2.8.4.2 are two
 * obligations, and the second case below shows the first one failing without cancelling the second.
 */
void caseAckOwedEndToEnd(void)
{
    Rig rig;
    Rig a;
    Air air[AIR_LOG_MAX];
    Air airA[AIR_LOG_MAX];
    Aps_ApsdeReq req;
    Aps_Frame frame;
    Aps_Confirm confirms[2];
    Aps_Indication inds[2];
    uint8_t wanted[APS_FRAME_MAX];
    uint8_t answer[APS_FRAME_MAX];
    uint32_t wantedLen;
    uint32_t answerLen;
    uint8_t counter;
    uint32_t airCount = 0;
    uint32_t airCountA = 0;
    uint32_t i;
    static const uint8_t asked[ASDU_LEN] = { 0x61, 0x63, 0x6b, 0x6d, 0x65, 0x21 };

    rigBuild(&rig, OWN_SHORT);
    rigBuild(&a, ADDR_PEER);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    seedNeighbor(&a.stack.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&a.stack.model, LOOPBACK_TX_MAX, 1);

    req = sapReq(APS_ADDR_MODE_SHORT, OWN_SHORT, DST_EP, CLUSTER_ID, asked, ASDU_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Aps_DataRequest(&a.aps, &req, 100), ZB_OK, "A asks for an acknowledgement of a unicast");
    harvestAir(&a.stack.model, airA, &airCountA);
    Test_Expect(airCountA == 1 && apduOf(&airA[0])[0] == APS_FCF_DATA_UNICAST_ACKED,
          "with FCF bit 6 set, which is what makes the peer owe the answer at all (2.2.8.4.3.2)");
    counter = apduOf(&airA[0])[APS_COUNTER_OCTET_UNICAST];

    handOver(&a.stack.model, &rig.stack.model);

    stepAt(&a, airA, &airCountA, 101);
    Test_Expect(a.aps.tx[0].state == APS_TX_AWAITING_ACK,
           "A waits for it, and the peer below has not been stepped yet: the frame is in the neighbor's radio and not yet in its sub-layer, and the order of two devices' turns is the suite's and not the standard's");

    stepAt(&rig, air, &airCount, 102);

    Test_Expect(airCount == 1, "the device under test put exactly one frame on its own side of the seam for this one: the acknowledgement");
    wantedLen = ackApdu(wanted, counter, DST_EP, SRC_EP, CLUSTER_ID);
    Test_Expect(apduLenOf(&air[0]) == wantedLen && Zb_memcmp(apduOf(&air[0]), wanted, wantedLen) == 0,
          "and its APDU is the swapped shape octet for octet: an independent `ApsFrame_Compose` of Figure 2-9 with 2.2.5.2.3.1's swap (\"if an APS data frame is being acknowledged, the source endpoint field SHALL reflect the value in the destination endpoint field of the frame that is being acknowledged. Similarly, the destination endpoint field SHALL reflect the value in the source endpoint field\"), the cluster and profile it repeats and the counter it repeats");
    Test_Expect(apduOf(&air[0])[0] == APS_FCF_ACK,
          "FCF 0x20: frame type Acknowledgement, ACK format 0 for a data acknowledgement (2.2.5.1.1.3), security 0, ACK request 0 (2.2.8.4.3: an acknowledgement never asks)");
    Test_Expect(apduOf(&air[0])[1] == SRC_EP && apduOf(&air[0])[6] == DST_EP,
          "the two endpoints read off the wire, swapped: this device's destination endpoint is the source endpoint A sent from, and its source endpoint is the destination endpoint A addressed");
    Test_Expect(apduOf(&air[0])[APS_COUNTER_OCTET_UNICAST] == counter,
          "and the counter the answer repeats is the counter the frame carried (2.2.5.2.3.1: \"The APS counter field SHALL contain the same value as the frame to which this frame is an acknowledgment\")");

    Test_Expect(fcfOf(&air[0]) == AIR_UNICAST_FCF && airDestOf(&air[0]) == ADDR_PEER,
          "it rode the air as a fresh unicast MAC frame from this device, aimed at A (2.2.8.4.1: a frame generated within the APS sub-layer is transmitted using the NWK layer data service)");
    Test_Expect(npduOf(&air[0])[2] == (uint8_t)(ADDR_PEER & 0xff) && npduOf(&air[0])[3] == (uint8_t)(ADDR_PEER >> 8)
           && npduOf(&air[0])[4] == (uint8_t)(OWN_SHORT & 0xff) && npduOf(&air[0])[5] == (uint8_t)(OWN_SHORT >> 8),
          "with the NWK fields the layer below wrote for it: destination A, source this device. The address the answer is aimed at is the NWK source of the frame being acknowledged, which Table 3-4 pins as that frame's originator and 2.2.8.4.3.2 names the same way");
    Test_Expect(npduOf(&air[0])[0] == NWK_FCF_DATA_DISCOVERING && npduOf(&air[0])[1] == 0x00,
          "in an unsecured minimal NWK data frame: no TxOptions of any request this module made names a frame it composed for itself, so the answer carries neither APS security nor NWK security, and 3.3.1.1.4 states the frame side of that reading");
    Test_Expect(nwkSeqOf(&air[0]) != 0 || npduOf(&air[0])[7] == 0,
          "and the layer below numbered it as its own frame (3.3.1.5), which is what makes it a new NPDU and not the received one turned around");

    Test_Expect(Aps_AcksGenerated(&rig.aps) == 1, "counted as an acknowledgement this module generated (2.2.8.4.3.2's \"SHALL generate and send\")");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0,
          "and it consumed no transaction slot of this module's: the answer is not a transaction, which is the difference between this frame and the eight ASDUs this device would have to hold in its pool to send them");
    Test_Expect(Aps_ConfirmQueue(&rig.aps) == 0,
          "and it produced no APS confirmation, because no APSDE-DATA.request of this module's is waiting for an answer to a frame it never requested");
    Test_Expect(Aps_IndicationQueue(&rig.aps) == 1, "while the frame it answers is delivered upward too: the acknowledgement and the delivery are separate obligations of 2.2.8.4.3.2 and 2.2.8.4.2");

    handOver(&rig.stack.model, &a.stack.model);

    stepAt(&a, airA, &airCountA, 103);
    Test_Expect(Aps_PollConfirms(&a.aps, confirms, 2) == 1
           && confirms[0].status == ZB_OK && confirms[0].apsStatus == APS_STATUS_SUCCESS,
           "A's transaction is answered by the answer it was owed (2.2.8.4.4: \"the transmission SHALL be considered successful\")");
    Test_Expect(confirms[0].attempts == 1, "after one transmission, with no retry and no wait run out");
    Test_Expect(confirms[0].apsCounter == counter && confirms[0].clusterId == CLUSTER_ID,
           "for the counter and cluster the acknowledgement repeated, which is two of the parts the match judged");
    Test_Expect(Aps_UnmatchedAcks(&a.aps) == 0, "matched and not unmatched: the device that answered was the device A addressed");
    Test_Expect(airCountA == 1, "and A retransmitted nothing after it was answered");

    stepAt(&rig, air, &airCount, 104);
    Test_Expect(Aps_ConfirmationsIgnored(&rig.aps) == 1 && Aps_ConfirmQueue(&rig.aps) == 0,
           "this device's own network layer answers the transmission of its acknowledgement, and that answer matches no transaction of this module's: taken and counted, `nwk`'s doctrine for a frame a module issues on its own initiative (the same lineage)");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0 && airCount == 1,
           "and nothing else left: no second acknowledgement for one frame, and no transaction opened by a reception (2.2.8.4.3: \"An acknowledgement frame SHALL always be sent with the acknowledgement request sub-field set to 0\")");

    Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1 && inds[0].status == APS_STATUS_SUCCESS,
           "the delivery this device queued is still there to be taken after all of that, with its Status untouched by the answer it sent");

    /* The one refusal this answer can meet at the module's own door. The device under test is made to hold eight
       transactions of its own, and the radio is scripted so none of them ever answers in time (100 pumps away),
       which fills the network layer's transmit pool. A frame then arrives that this device must acknowledge, and
       the layer below has no slot for the answer. What the case asserts is that the failure stops the answer and
       not the delivery. */
    scriptPending(&rig.stack.model, LOOPBACK_TX_MAX, 100);

    for (i = 0; i < APS_TX_MAX; i++)
    {
        req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asked, ASDU_LEN, 0);
        Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 1400 + i), ZB_OK, "this device takes back eight transmissions of its own");
    }

    Test_Expect(Aps_TransmitQueue(&rig.aps) == APS_TX_MAX, "and its transaction pool is full, which is the state a reception then has to live with");

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 1 + APS_TX_MAX,
           "eight of this device's own transmissions are on its air beside the one acknowledgement it sent earlier, which is the state the next assertion is read against");

    dataHeader(&frame, APS_DELIVERY_UNICAST, 1, 0x3c, DST_EP, CLUSTER_ID);
    answerLen = composeApdu(&frame, asked, ASDU_LEN, answer);
    peerDelivers(&a.stack, &rig.stack.model, OWN_SHORT, answer, answerLen, 1410);
    stepAt(&rig, air, &airCount, 1411);

    Test_Expect(Aps_AcksRefused(&rig.aps) == 1,
           "the acknowledgement this frame owed could not be issued (the network layer below has no transmit slot for it) and that is counted where it happened instead of being invisible (docs/internals/coding-rules.md §4.3). Band A does not queue an answer for a later turn: an acknowledgement of a frame this device already accepted is worth sending now, which is 2.2.8.4.3's \"commence when … valid\" and not a retry schedule, and 2.2.8.4.4's retries belong to the sender");
    Test_Expect(Aps_AcksGenerated(&rig.aps) == 1, "and the one it did send earlier is still the only one on the air");
    Test_Expect(Aps_IndicationQueue(&rig.aps) == 1 && Aps_DroppedIndications(&rig.aps) == 0,
           "while the delivery is still queued: 2.2.8.4.2 obliges the indication whatever the answer costs, and a failed acknowledgement is not a licence to withdraw a frame this device accepted");
    Test_Expect(airCount == 1 + APS_TX_MAX, "and still nothing new on this device's air: the refusal put no frame out");
}
