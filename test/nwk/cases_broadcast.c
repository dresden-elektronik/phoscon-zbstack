/* The `nwk` suite's broadcast half: the five destination classes a broadcast
   request is judged against, the transaction table's dedup and expiry and full policy, the retransmissions a
   relay owes and when they are due, the jitter they are spread by, and the copies the devices that cannot
   hear are owed. */

#include "loopback_radio.h"
#include "mac.h"
#include "nwk.h"
#include "nwk_frame.h"
#include "nwk_helpers.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

#define SLEEPY2 0x2222

/*
 * 6a. The same schedule with a jitter seed in the config: bounded, reproducible, and pinned to numbers a
 * reader can reproduce from the generator's written definition.
 *
 * 3.6.6: "Before the retransmission, it SHALL wait for a random time period called broadcast jitter. This time
 * period shall be bounded by the value of the nwkcMaxBroadcastJitter attribute", and Table 3-65 prints that
 * constant as 0x7d0 OctetDurations: 64 ms on the table's own 32-µs OctetDuration (NWK_MAX_BROADCAST_JITTER_MS
 * and the five-row check named there). No lower bound is printed, so 0 ms is a legal wait and one of the gaps
 * below is exactly the timeout, with nothing added.
 *
 * The seed is JITTER_SEED and the draws are the ones `Nwk_RelayJitterMs` states: xorshift32 (13, 17, 5), each new
 * state mapped by (x * 65) >> 32. For 0x2b3afb57 the first six draws are 64, 36, 13, 0, 49 and 2 ms, and three
 * broadcasts relayed at 100 ms, 2100 ms and 4100 ms therefore arm 664, 1200, 2613, 3113, 4649 and 5151 ms. The
 * three real inter-relay gaps are 564, 513 and 549 ms: all inside [500, 564], one of them at the ceiling and none
 * of them equal to the timeout except where the draw was 0, so the bound case is not vacuous and the timeout-only
 * case is not invented either.
 */
#define JITTER_SEED 0x2b3afb57
#define JITTER_BROADCASTS 3
#define JITTER_ARMS (2 * JITTER_BROADCASTS)
#define JITTER_DRAWS 64

/* One device, three broadcasts, every deadline the module armed, and the gap each relay actually waited for.
   The second deadline of each broadcast is armed for a retransmission the retry ceiling forbids, it is part of
   the schedule a seed reproduces, and it is recorded here rather than dropped, but it is not a gap: no third
   copy is ever issued. */
static void relaySchedule(Test_BandA *dev, uint32_t *arms, uint32_t *gaps)
{
    Air air[AIR_LOG_MAX];
    uint8_t npdu[RADIO_MPDU_MAX];
    Nwk_BroadcastTransactionRecord *record;
    uint32_t airCount;
    uint32_t npduLen;
    uint32_t copies;
    uint32_t i;
    uint32_t t;
    uint32_t due;

    airCount = 0;
    copies = 0;

    for (i = 0; i < JITTER_BROADCASTS; i++)
    {
        npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 2, (uint8_t)(50 + i), NWK_FRAME_TYPE_DATA, 0,
                           nsdu, NSDU_LEN);
        injectNpdu(dev, npdu, npduLen, NEIGHBOR);

        t = 100 + 2000 * i;

        Test_ExpectStatus(Test_NwkStep(&dev->nwk, t), ZB_OK, "a broadcast with two hops left, and the retransmission its receipt issues");
        harvestAir(&dev->model, air, &airCount);
        copies++;
        Test_Expect(airBroadcastCount(air, airCount, NWK_ADDR_ALL_DEVICES) == copies,
                    "the receipt's own copy is on the air in the turn of the receipt: 3.6.6 makes that act conditional on the radius alone, and the jitter bounds the wait before a retransmission that has to be waited for");

        record = bttFor(&dev->nwk, NEIGHBOR, (uint8_t)(50 + i));
        Test_Expect(record != 0 && record->relayed == 1, "one retransmission counted on the record");

        arms[2 * i] = record->nextRelayMs;
        gaps[i] = arms[2 * i] - t;
        due = arms[2 * i];

        Test_ExpectStatus(Test_NwkStep(&dev->nwk, due - 1), ZB_OK, "one millisecond before the jittered deadline");
        harvestAir(&dev->model, air, &airCount);
        Test_Expect(airBroadcastCount(air, airCount, NWK_ADDR_ALL_DEVICES) == copies,
                    "and nothing new on the air: a jittered deadline is still a deadline and not a suggestion");

        Test_ExpectStatus(Test_NwkStep(&dev->nwk, due), ZB_OK, "the turn it is due");
        harvestAir(&dev->model, air, &airCount);
        copies++;
        Test_Expect(airBroadcastCount(air, airCount, NWK_ADDR_ALL_DEVICES) == copies,
                    "the scheduled retransmission went out at the armed instant");

        record = bttFor(&dev->nwk, NEIGHBOR, (uint8_t)(50 + i));
        Test_Expect(record != 0 && record->relayed == NWK_MAX_BROADCAST_RETRIES,
                    "and the record has now retransmitted exactly nwkMaxBroadcastRetries times, which is all 3.6.6 allows");
        arms[2 * i + 1] = record->nextRelayMs;
    }
}

/*
 * 5. The broadcast classes and the copying they cause. A destination of Table 3-80 leaves with 0xffff in the
 * MAC's address field and its own class in the NWK header (3.2.1.1.3 step 6 a.3), unacknowledged, once. Only
 * 0xffff is copied to the devices that cannot hear it (end devices with macRxOnWhenIdle FALSE) one indirect
 * transaction each, never to this device itself and never to a neighbor that is not an end device. And a
 * broadcast the MAC answered for is answered for: 3.6.6 takes the MAC acknowledgment away from broadcasts, so
 * the retry loop 3.2.1.1.3 describes is a unicast's.
 */
void caseBroadcastClasses(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t i;
    Mac_Counters counters;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(&dev.nwk, OWN_SHORT, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);      /* this device, listed as a sleepy end device: the trap that proves the skip is by address and not by type */
    seedNeighbor(&dev.nwk, ROUTER_NEIGHBOR, NWK_DEVICE_ROUTER, 0, NWK_REL_SIBLING);  /* a router whose receiver is off: not an end device, so not copied */

    Test_Expect(Nwk_NeighborQueue(&dev.nwk) == 3,
                "three neighbors seeded, which is the smallest set that shows each condition of 3.6.6 step 1 on its own");

    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK, "a broadcast to every device in the PAN");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1, "one frame on the air");
    Test_Expect(air[0].ackRequest == 0,
                "and the network layer asked for no MAC acknowledgement: 3.6.6, TxOptions' acknowledged transmission flag FALSE");
    Test_Expect(fcfOf(&air[0]) == AIR_BROADCAST_FCF, "which is the FCF every broadcast captured on this PAN carries, 0x8841");
    Test_Expect(airDestOf(&air[0]) == MAC_FRAME_ADDR_BROADCAST,
                "with 0xFFFF in the MAC's destination field: 3.2.1.1.3 step 6 a.3, DstAddr All Devices in PAN");
    Test_Expect(npduOf(&air[0])[2] == 0xff && npduOf(&air[0])[3] == 0xff,
                "and the class in the NWK header's destination field, 0xffff here, low octet first as 3.3 orders a multi-octet field: the only place a receiver learns who was meant");
    Test_Expect(npduLenOf(&air[0]) == NWK_MIN_HEADER_OVERHEAD + NSDU_LEN, "one NPDU, the minimal header and the NSDU");
    Test_Expect(Nwk_TransmitQueue(&dev.nwk) == 1, "and the broadcast holds a slot until it is answered for");

       counters = Mac_CountersOf(&dev.mac);
    /* The copies. `mac` refuses a broadcast destination in its indirect queue precisely because this is the
       network layer's job (3.2.1.1.3 item 6), so what a copy is has to be read in the queue it
       produced, and then made real by the poll that extracts it. */
    Test_Expect(counters.transactionQueue == 1,
                "exactly one indirect transaction is queued for the broadcast: 3.2.1.1.3 item 7 with 3.6.6 step 1, one copy per neighbor of device type 0x02 whose macRxOnWhenIdle is FALSE");

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (dev.mac.indirect.transactions[i].used)
            break;
    }

    Test_Expect(i < MAC_TRANSACTION_MAX && dev.mac.indirect.transactions[i].destShort == SLEEPY,
                "queued for the sleepy end device's address and nobody else's: 3.6.6 step 1, no MCPS-DATA.request for the broadcast's source");
    Test_Expect(dev.mac.indirect.transactions[i].payloadLen == NWK_MIN_HEADER_OVERHEAD + NSDU_LEN
                && Zb_memcmp(dev.mac.indirect.transactions[i].payload, npduOf(&air[0]), dev.mac.indirect.transactions[i].payloadLen) == 0,
                "carrying the same NPDU the broadcast went out as: the copy is the same frame, held for a device that cannot hear it");
    Test_Expect(airCount == 1, "and nothing else went on the air: a queued copy is a transaction and not a transmission (10.22.2)");

    composePoll(&dev.model, 7, SLEEPY);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "the sleepy child polls, and the network layer's turn steps the MAC that answers it");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_CarrierOther(&dev.nwk) == 1,
                "and the poll that extracted the copy is counted as the carrier it is: Nwk_CarrierOther, not droppedMalformed");
    Test_Expect(Nwk_DroppedMalformed(&dev.nwk) == 0, "and no damage is left behind by that re-pointing");

    Test_Expect(airCount == 2, "the copy goes out now, extracted by the poll it waits for");
    Test_Expect(air[1].ackRequest == 1,
                "asking for the acknowledgment an extraction needs: 10.22.2, 'In order to be successfully extracted, an acknowledgment shall be received if one was requested'");
    Test_Expect(airDestOf(&air[1]) == SLEEPY, "to the child's own address");
    Test_Expect(dsnOf(&air[1]) == 1,
                "at the DSN the transaction reserved when it was queued rather than at a new one (6.6.3.4: the broadcast took 0 and the copy had 1 held for it from the start)");
    Test_Expect(npduLenOf(&air[1]) == npduLenOf(&air[0])
                && Zb_memcmp(npduOf(&air[1]), npduOf(&air[0]), npduLenOf(&air[1])) == 0,
                "and with the NPDU byte for byte as the broadcast carried it");
    Test_Expect(Nwk_ConfirmQueue(&dev.nwk) == 1, "while the broadcast's own answer is one NLDE confirmation");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_OK && confirms[0].nwkStatus == NWK_STATUS_SUCCESS
                && confirms[0].dstAddr == NWK_ADDR_ALL_DEVICES && confirms[0].attempts == 1,
                "SUCCESS for the class it was sent to, with one attempt: 3.2.1.1.3 confirms a broadcast with 'the resulting status'");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 102), ZB_OK, "the next turn answers the extraction as well");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(Nwk_ConfirmsIgnored(&dev.nwk) == 1,
                "and the copy's confirmation is one this module did not issue: an answer it cannot tie to a frame is counted, not kept");
    Test_Expect(Nwk_ConfirmQueue(&dev.nwk) == 0 && Nwk_TransmitQueue(&dev.nwk) == 0, "nothing of this module's own is still owed");

    /* The other two classes, each sent and each not copied. 0xfffd addresses the devices that are listening
       and 0xfffc the routers and the coordinator, so a neighbor that is an end device with its receiver off
       is not a device either class means: copying to it would deliver the frame to a device the destination
       address excluded. The gate is stated the way 3.6.6 step 1 prints it: it is 0xffff that is
       copied per sleepy neighbor, and 3.2.1.1.3 item 7 is the same iteration worded without naming the
       destination. */
    req = nldeReq(NWK_ADDR_RX_ON_WHEN_IDLE, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 200), ZB_OK, "a broadcast to every device with macRxOnWhenIdle TRUE (Table 3-80)");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 3 && fcfOf(&air[2]) == AIR_BROADCAST_FCF
                && airDestOf(&air[2]) == MAC_FRAME_ADDR_BROADCAST
                && airClassCount(air, airCount, NWK_ADDR_RX_ON_WHEN_IDLE) == 1,
                "one frame, unacknowledged, with the MAC's 0xFFFF in the destination field and 0xfffd in the NWK header: the second of the three classes 3.2.1.1.3 step 6 a.3 names");

    req = nldeReq(NWK_ADDR_ROUTERS, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 201), ZB_OK, "and one to all routers and the coordinator");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 4 && fcfOf(&air[3]) == AIR_BROADCAST_FCF
                && airDestOf(&air[3]) == MAC_FRAME_ADDR_BROADCAST
                && airClassCount(air, airCount, NWK_ADDR_ROUTERS) == 1,
                "the same shape at 0xfffc, where a many-to-one route request would go (3.6.4.5): same MAC destination, its own NWK class");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 0,
                "and no copy queued for either class: the sleepy neighbor is in neither destination, so item 7's iteration has nothing here to copy to");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 202), ZB_OK, "both answered");
    harvestAir(&dev.model, air, &airCount);
    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 2 && confirms[0].dstAddr == NWK_ADDR_RX_ON_WHEN_IDLE && confirms[1].dstAddr == NWK_ADDR_ROUTERS,
                "each answered for on its own");

    /* A broadcast the MAC refused: no retry path, because 3.6.6 takes the acknowledgment away from a broadcast
       and gives its retransmission to the broadcast transaction table, which is the receive half's machine. */
    rig(&dev, OWN_SHORT, PAN_ID);
    airCount = 0;     /* a fresh rig is a fresh backend, and the air log counts what that backend has seen */
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 0);

    req = nldeReq(NWK_ADDR_LOW_POWER_ROUTERS, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 300), ZB_OK, "a broadcast to the low power routers, Table 3-80's 0xfffb");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1 && airDestOf(&air[0]) == MAC_FRAME_ADDR_BROADCAST
                && airClassCount(air, airCount, NWK_ADDR_LOW_POWER_ROUTERS) == 1,
                "sent once, with 0xFFFF to the MAC and 0xfffb (3.6.6's own list of classes) in the NWK header");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 301), ZB_OK, "and the MAC says no");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(dev.nwk.tx[0].state == NWK_TX_FREE,
                "and no retry is scheduled for a broadcast: 3.2.1.1.3's retry paragraph is on a unicast, 3.6.6's is the BTT's");
    Test_Expect(airCount == 1, "and no second attempt followed it");
    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_DEVICE && confirms[0].attempts == 1,
                "the confirmation is the status the MAC gave, with the one attempt there was");

    /* The pool a broadcast can fill on its own: `mac`'s transaction queue, whose full policy is refusal and
       count at the MAC (10.22.2's TRANSACTION_OVERFLOW). The broadcast this module put on the air
       is unaffected by a copy the queue could not hold. */
    rig(&dev, OWN_SHORT, PAN_ID);
    airCount = 0;

    for (i = 0; i < MAC_TRANSACTION_MAX + 1; i++)
        seedNeighbor(&dev.nwk, (uint16_t)(0x0100 + i), NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);

    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 400), ZB_OK, "a broadcast with nine sleepy neighbors and room for eight transactions");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1, "the broadcast itself went out regardless");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == MAC_TRANSACTION_MAX, "eight copies were queued");
    Test_Expect(counters.refusedRequests == 1, "and the ninth was refused at the MAC's own pool, counted where the refusal happened");
    Test_Expect(Nwk_RefusedRequests(&dev.nwk) == 0,
                "while this module refused nothing of its own: it asked, and the queue beneath it was the thing that was full");
}

/* `count` received broadcasts from NEIGHBOR, sequence numbers `first` on, radius 1 so none costs any air: fed one
   radio batch (RADIO_FRAME_BATCH_MAX) a step, the indications drained between batches so the ring is never what runs
   out. The number delivered. */
static uint32_t broadcastFill(Test_BandA *dev, uint32_t first, uint32_t count, uint32_t nowMs, Air *air,
                              uint32_t *airCount)
{
    Nwk_DataIndicationParameters inds[RADIO_FRAME_BATCH_MAX];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t delivered = 0;
    uint32_t done = 0;
    uint32_t batch;
    uint32_t got;
    uint32_t i;

    while (done < count)
    {
        batch = count - done < RADIO_FRAME_BATCH_MAX ? count - done : RADIO_FRAME_BATCH_MAX;

        for (i = 0; i < batch; i++)
        {
            npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 1, (uint8_t)(first + done + i),
                               NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
            injectNpdu(dev, npdu, npduLen, NEIGHBOR);
        }

        (void)Test_NwkStep(&dev->nwk, nowMs);
        harvestAir(&dev->model, air, airCount);

        while ((got = Test_NwkPoll(&dev->nwk, inds, RADIO_FRAME_BATCH_MAX)) != 0)
            delivered += got;

        done += batch;
    }

    return delivered;
}

/*
 * 5. The broadcast transaction table's two ends: an expired record is not a record, and a full table with
 * nothing expired is a refusal.
 *
 * 3.6.6 on expiry: "A device SHOULD change the status of a BTT entry after nwkNetworkBroadcastDeliveryTime
 * OctetDurations have elapsed since its creation. The entry status SHOULD change to expired and thus the entry
 * can be overwritten if required when a new broadcast is received." The number band A uses is the house's
 * NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS, standing in for a NIB attribute whose printed default is "a calculated quantity
 * based on other NIB attributes. Defined in stack profile" and no number, with nwkcBroadcastDeliveryTime = 9
 * seconds as the only printed neighbor (open as a number).
 *
 * 3.6.6 on full: "If, on receipt of a broadcast frame, the NWK layer finds that the BTT is full and contains no
 * expired entries, then the frame SHOULD be dropped. In this situation the frame SHOULD NOT be retransmitted, nor
 * SHOULD it be passed up to the next higher layer." Nothing below the refusal runs: not the indication, not the
 * relay, not the neighbor observation. The pool size is band A's own (NWK_BTT_MAX): R23.1 names no size for the
 * broadcast transaction table, and the only floor in the chapter is "buffer at least 1 frame at the NWK layer".
 */
void caseBroadcastTableExpiryAndFull(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[NWK_BTT_MAX + 2];
    Nwk_BroadcastTransactionRecord *record;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);

    /* Two copies of one broadcast, further apart than the delivery window. Radius 1 keeps them out of the air
       entirely: the point of this case is the record, not the relay. */
    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 1, 40, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1000), ZB_OK, "a broadcast, recorded at time 1000");
    harvestAir(&dev.model, air, &airCount);

    record = bttFor(&dev.nwk, NEIGHBOR, 40);
    Test_Expect(record != 0 && record->expiresAtMs == 1000 + NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS,
          "one record, expiring a nwkNetworkBroadcastDeliveryTime after it was made: 3.6.6's calculated quantity");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, NWK_BTT_MAX + 2) == 1, "delivered once");
    Test_Expect(airCount == 0 && record != 0 && record->relayed == 0, "and not relayed, because its radius reached 0 on the way in");

    record = bttFor(&dev.nwk, NEIGHBOR, 40);
    Test_Expect(record != 0 && record->npduLen == npduLen,
          "the record holds the copy a retransmission would be made from: 3.6.6 asks a forwarder to retransmit what it received");

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 1, 40, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1000 + NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS + 1), ZB_OK,
                  "the same broadcast again, one delivery window later");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_DroppedDuplicate(&dev.nwk) == 0,
          "is not a duplicate: 3.6.6 ages a record to expired and makes it available to be overwritten, and an expired record of this frame is not a live one");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, NWK_BTT_MAX + 2) == 1, "and is delivered as a new broadcast");
    Test_Expect(Nwk_BttQueue(&dev.nwk) == 1, "without growing the table: the expired record was reused");

    record = bttFor(&dev.nwk, NEIGHBOR, 40);
    Test_Expect(record != 0 && record->expiresAtMs == 1000 + NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS + 1 + NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS,
          "with a fresh expiry counted from this receipt, which is what Table 3-81's 'the initial value is nwkNetworkBroadcastDeliveryTime' means for a record that starts over");

    /* Now fill it. Distinct sequence numbers from one source are distinct records: the key is the pair. */
    rig(&dev, OWN_SHORT, PAN_ID);
    airCount = 0;

    Test_ExpectCount(broadcastFill(&dev, 1, NWK_BTT_MAX, 2000, air, &airCount), NWK_BTT_MAX,
                     "as many new broadcasts from one source as the table holds, each delivered");
    Test_Expect(Nwk_BttQueue(&dev.nwk) == NWK_BTT_MAX, "fill the table to its named bound");
    Test_Expect(airCount == 0 && Nwk_RelaysSent(&dev.nwk) == 0, "and nothing on the air");

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 1, (uint8_t)(NWK_BTT_MAX + 1), NWK_FRAME_TYPE_DATA, 0,
                       nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 2002), ZB_OK, "one more, while none of those has aged");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_BttFullDrops(&dev.nwk) == 1, "is a bttFullDrop (3.6.6)");
    Test_Expect(Nwk_BttQueue(&dev.nwk) == NWK_BTT_MAX, "and the table did not grow or evict anything");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, NWK_BTT_MAX + 2) == 0, "nor was it passed up");
    Test_Expect(airCount == 0 && Nwk_RelaysSent(&dev.nwk) == 0, "nor was it retransmitted");
    Test_Expect(Nwk_NeighborQueue(&dev.nwk) == 1 && Nwk_ConfirmsIgnored(&dev.nwk) == 0
                && Nwk_DroppedDuplicate(&dev.nwk) == 0 && Nwk_DroppedIndications(&dev.nwk) == 0,
          "and the refusal stopped the frame before the neighbor observation too: a frame the table could not take is not a frame this module acted on");

    /* A frame held for the layer above and never taken, which is not the BTT's policy: the next step drops it and
       counts it, and the receive goes on, so what follows is still recorded and, if it owes one, relayed. */
    rig(&dev, OWN_SHORT, PAN_ID);
    airCount = 0;

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 1, 100, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);
    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 2, 101, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Nwk_Step(&dev.nwk, 3000), ZB_OK, "two new broadcasts, and a caller that takes nothing");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_IndicationQueue(&dev.nwk) == 1 && Nwk_BttQueue(&dev.nwk) == 1,
          "the first is held for the layer above and the receive waits behind it: one frame deep");

    Test_ExpectStatus(Nwk_Step(&dev.nwk, 3001), ZB_OK, "the next step, with the first still untaken");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_DroppedIndications(&dev.nwk) == 1,
          "drops it and counts it, refusal at the moment the receive needs the slot: docs/internals/coding-rules.md §4.3");
    Test_Expect(Nwk_BttQueue(&dev.nwk) == 2 && airBroadcastCount(air, airCount, NWK_ADDR_ALL_DEVICES) == 1,
          "and the second is recorded and relayed: losing an indication does not cancel a relay");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, NWK_BTT_MAX + 2) == 1, "and it is the frame held now");
}

/*
 * 6. The retransmission schedule a broadcast this device relayed carries with it.
 *
 * 3.6.6, the whole of it: "A Zigbee coordinator or Zigbee router operating in a non-beacon-enabled Zigbee
 * network SHALL retransmit a previously broadcast frame at most nwkMaxBroadcastRetries times. If the device does
 * not support passive acknowledgement, then it SHALL retransmit the frame exactly nwkMaxBroadcastRetries times.
 * If the device supports passive acknowledgement and any of its neighboring devices have not relayed the
 * broadcast frame within nwkPassiveAckTimeout OctetDurations then it SHALL continue to retransmit the frame on
 * the MAC interfaces which are in communication with such neighbors up to a maximum of nwkMaxBroadcastRetries
 * times."
 *
 * Band A is the device in the middle sentence. Passive acknowledgement means "every Zigbee router and Zigbee
 * coordinator keeps track of which of its neighboring devices have successfully relayed the broadcast
 * transmission" (3.6.6), and nothing in Table 3-75 or Table 3-81 holds that fact (the gap is recorded rather than
 * invented around with a per-neighbor set), so there is nothing to wait for and nothing to stop early: the
 * retransmissions are scheduled on nwkPassiveAckTimeout and there are exactly nwkMaxBroadcastRetries of them. The
 * sentence before all of it is the jitter, "Before the retransmission, it SHALL wait for a random time period
 * called broadcast jitter. This time period shall be bounded by the value of the nwkcMaxBroadcastJitter
 * attribute", and this rig seeds none: `Nwk_Config.jitterSeed` 0 draws 0 ms, so a retransmission here is due at
 * the timeout and at nothing else, which is the schedule that was open and these assertions now pin as the default
 * case. Case 6a is the seeded device.
 *
 * What the copies are is the other half of the case: each one the same NPDU, byte for byte, including the radius
 * this device read. A device that retransmits one frame twice has received it once, and 3.3.1.4 charges the
 * decrement to receipt.
 */
void caseBroadcastRetransmissionSchedule(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    Nwk_BroadcastTransactionRecord *record;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 2, 50, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a broadcast with two hops left");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airBroadcastCount(air, airCount, NWK_ADDR_ALL_DEVICES) == 1,
          "the first retransmission is the receipt: 3.6.6's sentence is conditional on the radius alone");

    record = bttFor(&dev.nwk, NEIGHBOR, 50);
    Test_Expect(record != 0 && record->relayed == 1, "one retransmission counted on the record");
    Test_Expect(record != 0 && record->nextRelayMs == 100 + NWK_PASSIVE_ACK_TIMEOUT_MS,
          "the next one due nwkPassiveAckTimeout later: 500 ms, NIB attribute 0x82's printed default, in the milliseconds band A is given time in rather than the OctetDurations the clause prints");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + NWK_PASSIVE_ACK_TIMEOUT_MS - 1), ZB_OK, "one millisecond before it is due");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airBroadcastCount(air, airCount, NWK_ADDR_ALL_DEVICES) == 1, "and nothing new on the air: the schedule is a deadline and not a suggestion");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + NWK_PASSIVE_ACK_TIMEOUT_MS), ZB_OK, "the turn it is due");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airBroadcastCount(air, airCount, NWK_ADDR_ALL_DEVICES) == 2, "the second retransmission goes out");

    record = bttFor(&dev.nwk, NEIGHBOR, 50);
    Test_Expect(record != 0 && record->relayed == NWK_MAX_BROADCAST_RETRIES,
          "and the record has now retransmitted the broadcast exactly nwkMaxBroadcastRetries times, which is all the clause allows and the whole of what a device with no passive acknowledgement does");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + 2 * NWK_PASSIVE_ACK_TIMEOUT_MS), ZB_OK, "a second timeout after that");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airBroadcastCount(air, airCount, NWK_ADDR_ALL_DEVICES) == 2, "and no third copy");

    Test_Expect(Nwk_RelaysSent(&dev.nwk) == NWK_MAX_BROADCAST_RETRIES, "the module's own count of relays is the bound, not one more");
    Test_Expect(npduLenOf(&air[1]) == npduLenOf(&air[0])
                && npduDiffCount(npduOf(&air[1]), npduLenOf(&air[1]), npduOf(&air[0]), npduLenOf(&air[0])) == 0,
          "and the second copy is the first one octet for octet, radius included: 3.6.6's decrement was paid once, on receipt");
    Test_Expect(npduOf(&air[0])[NPDU_RADIUS_OCTET] == 1 && npdu[NPDU_RADIUS_OCTET] == 2,
          "the radius of both copies is 1, which is what the frame this device received had left after its own decrement");
    Test_Expect(dsnOf(&air[0]) != dsnOf(&air[1]),
          "while the MAC's own sequence numbers differ: two frames on the air, one NPDU (7.2.3, and 3.6.4.3's ban on a relay changing the number the originator chose)");
    Test_Expect(air[0].ackRequest == 0 && air[1].ackRequest == 0, "and neither copy asked anybody to acknowledge anything (3.6.6)");

    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 4) == 1,
          "the frame was delivered once, whatever the number of copies this device put behind it");
    Test_Expect(Nwk_TransmitQueue(&dev.nwk) == 0 && Nwk_ConfirmQueue(&dev.nwk) == 0,
          "and none of it took a transmit slot or produced a confirmation: a relay answers no request, and 3.2.1.2.1 prints an NLDE-DATA.confirm as the answer to one");
    Test_Expect(Nwk_ConfirmsIgnored(&dev.nwk) == NWK_MAX_BROADCAST_RETRIES,
          "the MAC's answers to the two copies are counted as answers this module could not tie to a request it owes");
}

void caseBroadcastJitterBoundAndReproducible(void)
{
    Test_BandA devA;
    Test_BandA devB;
    Test_BandA devC;
    uint32_t armsA[JITTER_ARMS];
    uint32_t armsB[JITTER_ARMS];
    uint32_t armsC[JITTER_ARMS];
    uint32_t gapsA[JITTER_BROADCASTS];
    uint32_t gapsB[JITTER_BROADCASTS];
    uint32_t gapsC[JITTER_BROADCASTS];
    uint32_t i;
    uint32_t overTimeout;

    rigAtSeed(&devA, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1, 0, JITTER_SEED);
    relaySchedule(&devA, armsA, gapsA);

    overTimeout = 0;

    for (i = 0; i < JITTER_BROADCASTS; i++)
    {
        Test_Expect(gapsA[i] >= NWK_PASSIVE_ACK_TIMEOUT_MS
                    && gapsA[i] <= NWK_PASSIVE_ACK_TIMEOUT_MS + NWK_MAX_BROADCAST_JITTER_MS,
                    "every inter-relay gap is inside nwkPassiveAckTimeout plus nwkcMaxBroadcastJitter, inclusive at both ends (3.6.6 against Table 3-65)");

        if (gapsA[i] > NWK_PASSIVE_ACK_TIMEOUT_MS)
            overTimeout++;
    }

    Test_Expect(overTimeout > 0, "and at least one gap is longer than the timeout, so the bound above is a bound on something this device did and not a window everything fits into by default");
    Test_Expect(gapsA[0] == 564 && gapsA[1] == 513 && gapsA[2] == 549,
                "and the gaps are the pinned ones the generator's written definition produces for this seed: 500+64, 500+13, 500+49");
    Test_Expect(armsA[1] == 1200 && armsA[3] == 3113 && armsA[5] == 5151,
                "including the deadlines armed for retransmissions the retry ceiling never issues, which carry the draws between the ones a gap shows");

    rigAtSeed(&devB, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1, 0, JITTER_SEED);
    relaySchedule(&devB, armsB, gapsB);
    Test_Expect(Zb_memcmp(armsA, armsB, (uint32_t)sizeof armsA) == 0,
                "a second device, the same seed, the same three frames: byte for byte the same six deadlines, which is what a seed is for");

    rigAtSeed(&devC, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1, 0, 0);
    relaySchedule(&devC, armsC, gapsC);

    for (i = 0; i < JITTER_BROADCASTS; i++)
    {
        Test_Expect(gapsC[i] == NWK_PASSIVE_ACK_TIMEOUT_MS,
                    "and the device seeded with nothing repeats today's schedule exactly: due at nwkPassiveAckTimeout and at nothing else, which is the compatibility rule and every case above this one depends on");
    }

    Test_Expect(armsC[0] == 600 && armsC[1] == 1100 && armsC[2] == 2600 && armsC[3] == 3100
                && armsC[4] == 4600 && armsC[5] == 5100,
                "the unseeded deadlines, number for number, the ones case 6 asserts one broadcast at a time");
}

/*
 * 6b. The generator on its own, with no schedule in the way: 64 draws, the bound, both ends of the interval
 * reached, and the seed reproducing itself.
 *
 * The drawn values for JITTER_SEED over 64 calls run from 0 to 64 inclusive, so this case bites in both
 * directions: a clamp widened by one produces a 65 and reddens the bound, and a generator whose state is held
 * at 0 produces one number over and over and reddens the two assertions that say the interval is really
 * spanned.
 */
void caseBroadcastJitterDrawsAreBounded(void)
{
    Test_BandA dev;
    uint32_t draws[JITTER_DRAWS];
    uint32_t again[JITTER_DRAWS];
    uint32_t lowest;
    uint32_t highest;
    uint32_t distinct;
    uint32_t zeros;
    uint32_t i;
    uint32_t j;
    int seenBefore;

    rigAtSeed(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1, 0, JITTER_SEED);

    for (i = 0; i < JITTER_DRAWS; i++)
        draws[i] = Nwk_TestJitterMs(&dev.nwk);

    lowest = NWK_MAX_BROADCAST_JITTER_MS;
    highest = 0;

    for (i = 0; i < JITTER_DRAWS; i++)
    {
        if (draws[i] < lowest)
            lowest = draws[i];

        if (draws[i] > highest)
            highest = draws[i];
    }

    Test_Expect(highest <= NWK_MAX_BROADCAST_JITTER_MS,
                "no draw leaves the closed interval 3.6.6 bounds by nwkcMaxBroadcastJitter: 0x7d0 OctetDurations, 64 ms on the verified 32-µs unit");
    Test_Expect(highest == NWK_MAX_BROADCAST_JITTER_MS,
                "and the ceiling is touched, which is what makes that bound the clamp it is instead of a number the generator never approaches");
    Test_Expect(lowest == 0,
                "the other end is touched too: the clause prints no lower bound, so 0 ms is a legal wait and a schedule with a 0 draw in it is not a failure of the jitter");

    distinct = 0;

    for (i = 0; i < JITTER_DRAWS; i++)
    {
        seenBefore = 0;

        for (j = 0; j < i; j++)
        {
            if (draws[j] == draws[i])
                seenBefore = 1;
        }

        if (!seenBefore)
            distinct++;
    }

    Test_Expect(distinct > 1, "and the 64 draws are more than one number repeated, which is the assertion a generator frozen at one state cannot pass");

    rigAtSeed(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1, 0, JITTER_SEED);

    for (i = 0; i < JITTER_DRAWS; i++)
        again[i] = Nwk_TestJitterMs(&dev.nwk);

    Test_Expect(Zb_memcmp(draws, again, (uint32_t)sizeof draws) == 0,
                "the same seed, re-initialised, hands back the same 64 draws: the generator's whole state is the seed plus the calls it has made (docs/internals/coding-rules.md §4.2)");

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1);
    zeros = 0;

    for (i = 0; i < JITTER_DRAWS; i++)
    {
        if (Nwk_TestJitterMs(&dev.nwk) == 0)
            zeros++;
    }

    Test_Expect(zeros == JITTER_DRAWS,
                "and a device the config seeded with nothing draws nothing, 64 times out of 64: '0 disables jitter' is the default case, stated as the generator's own answer and not as a special path in the schedule");
}

/*
 * 7. The sleepy copies a relayed 0xffff broadcast owes, with the source of the broadcast refused one.
 *
 * 3.6.6, in its own order: "A router or coordinator with the macRxOnWhenIdle MAC PIB attribute set to TRUE,
 * which has one or more neighbors with the macRxOnWhenIdle MAC PIB attribute set to FALSE, SHALL do the
 * following: 1. If the NWK destination address of the broadcast is 0xFFFF, for each nwkNeighborTable entry where
 * the device type is 0x02 (Zigbee End Device) and the entry has RxOnWhenIdle = FALSE, the broadcast SHALL be
 * re-transmitted as follows: a. If the end device target is NOT the NWK source of the broadcast, the message
 * SHALL be relayed as a unicast at the MAC layer via an MCPS-DATA.request. b. If the end device target is the
 * NWK source of the broadcast, no MCPS-DATA.request is generated." Item 2 closes it: the neighbors that are
 * listening, and the routers and coordinators among them, "will receive the message when it is re-broadcast as
 * described in the section above".
 *
 * The End Device Initiator bit rides along here because this is the frame it is set on: the broadcast came from
 * a device Table 3-75 says is an end device, this device is a router. 3.3.1.1.8 clears the bit for "a router
 * parent device … when relaying a message sent by one of its end device children", and this device has no
 * parent/child state to tell SLEEPY (an entry a suite seeded as a child) from another router's child, so the bit
 * is carried rather than erased: a router that cleared every end device's bit would tell the next hop that a
 * device which cannot route is itself a router.
 */
void caseSleepyCopiesOnRelay(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Mac_Transaction *copy;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint32_t i;
    uint32_t queued = 0;
    Mac_Counters counters;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(&dev.nwk, SLEEPY2, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, SLEEPY, 2, 60, NWK_FRAME_TYPE_DATA, 1, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, SLEEPY);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a broadcast that started at a sleepy end device, its End Device Initiator bit set");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airBroadcastCount(air, airCount, NWK_ADDR_ALL_DEVICES) == 1, "is relayed as a broadcast, as any accepted broadcast with radius left is");
    Test_Expect((nwkFcfOf(npdu) & NWK_FCF_END_DEVICE) != 0,
          "the frame this device received carries the bit (Figure 3-5, bit 13), which is also what let it past 3.6.2.2's search for a neighbor entry of device type 0x02");
    Test_Expect((nwkFcfOf(npduOf(&air[0])) & NWK_FCF_END_DEVICE) == 0,
          "and the copy that goes back on the air has it cleared: 3.3.1.1.8 clears the bit when a router parent relays a message sent by one of its end device children");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 1,
          "exactly one indirect copy, out of three neighbor entries: one sleepy end device that is not the broadcast's source");

    copy = 0;

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (!dev.mac.indirect.transactions[i].used)
            continue;

        copy = &dev.mac.indirect.transactions[i];
        queued++;
    }

    Test_Expect(queued == 1 && copy != 0 && copy->destShort == SLEEPY2,
          "queued for the sleepy neighbour that is not the source: 3.6.6 step 1a, relayed as a unicast, and 1b, nothing for the source");
    Test_Expect(copy != 0 && copy->payloadLen == npduLenOf(&air[0])
                && Zb_memcmp(copy->payload, npduOf(&air[0]), copy->payloadLen) == 0,
          "the copy carries the same octets the broadcast was retransmitted with: 3.6.6, a copy is the frame held for a sleeping child");

    npduLen = makeNpdu(npdu, NWK_ADDR_RX_ON_WHEN_IDLE, NEIGHBOR, 2, 61, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "and the same shape aimed at 0xfffd instead");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airClassCount(air, airCount, NWK_ADDR_RX_ON_WHEN_IDLE) == 1, "is relayed as a broadcast of its own: the class in the NWK header, 0xffff in the MAC destination field");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 1, "and queues no copy: 3.6.6 step 1 is gated on a destination of 0xFFFF, and 0xfffd addresses the devices that are listening, so the sleepy child is a device that class excludes");

    npduLen = makeNpdu(npdu, NWK_ADDR_ROUTERS, NEIGHBOR, 2, 62, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 102), ZB_OK, "and the same again at 0xfffc");
    harvestAir(&dev.model, air, &airCount);
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(airClassCount(air, airCount, NWK_ADDR_ROUTERS) == 1 && counters.transactionQueue == 1,
          "relayed, still no copy: the class names routers and the coordinator, and a device copied here is by definition an end device");
    Test_Expect(Nwk_NeighborQueue(&dev.nwk) == 3,
          "and the neighbor table is still the three entries the case seeded, because the frames arrived from addresses all three of them name");
}

/* A broadcast that arrives asking for route discovery, as a sleepy end device's Device_annce was measured to: Table
   3-51 binds the frames this layer generates (D-156), so it is delivered here and relayed with the field it came with. */
void caseBroadcastAskingForDiscoveryIsRead(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    npduLen = makeNpdu(npdu, NWK_ADDR_RX_ON_WHEN_IDLE, SLEEPY, 30, 0x1e, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    npdu[0] = (uint8_t)(npdu[0] | NWK_FCF_DISCOVER_ENABLE);
    injectNpdu(&dev, npdu, npduLen, SLEEPY);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a child's broadcast to 0xfffd with Discover Route 01");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_DroppedMalformed(&dev.nwk), 0, "is not refused as malformed");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 1, "is passed up once");
    Test_Expect(airClassCount(air, airCount, NWK_ADDR_RX_ON_WHEN_IDLE) == 1, "and is relayed");
    Test_Expect(airCount != 0 && (nwkFcfOf(npduOf(&air[0])) & NWK_FCF_DISCOVER_ENABLE) != 0,
                "with the Discover Route its sender chose");
}

/*
 * 5a. The wire shape of a broadcast, one class at a time.
 *
 * 3.2.1.1.3 step 6 a.3: "If the DstAddr is set to All Devices in PAN (0xFFFF), macRXOnWhenIdle=TRUE (0xFFFD) or
 * All routers and coordinators (0xFFFC) then examine that entry in the nwkMacInterfaceTable. a. If
 * RoutersAllowed is set to TRUE, do the following. i. Issue an MCPS-DATA.request with the following
 * parameters: … 3. DstAddr SHALL be set to 0xFFFF." 3.6.6 prints 0xfffb among the destinations a broadcast may
 * take as well, and the class stays in the NWK header's destination field whatever the MAC address field says.
 *
 * The two shapes are not interchangeable. 6.2 defines one broadcast short address, "The broadcast short
 * address is defined to be 0xffff", and Table 10-101 prints "0x0000-0xfffd" as the ordinary short addresses
 * (0xfffc and 0xfffd occur nowhere in that standard as broadcast), so a frame whose MAC destination carried
 * the class would be a unicast to an address no device holds, which no receiver's frame filter accepts.
 */
void caseBroadcastMacDestinationPerClass(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    static const uint16_t classes[] = { NWK_ADDR_ALL_DEVICES, NWK_ADDR_ROUTERS, NWK_ADDR_RX_ON_WHEN_IDLE,
                                        NWK_ADDR_LOW_POWER_ROUTERS };
    uint32_t airCount = 0;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    for (i = 0; i < 4; i++)
    {
        req = nldeReq(classes[i], nsdu, NSDU_LEN, 0);
        Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100 + i), ZB_OK,
                     "a broadcast request naming one of the four classes 3.2.1.1.3 step 6 and 3.6.6 print");
        harvestAir(&dev.model, air, &airCount);

        Test_Expect(airCount == i + 1, "one frame on the air per request, and no second attempt of any of them");
        Test_Expect(airDestOf(&air[i]) == MAC_FRAME_ADDR_BROADCAST,
                    "with the MAC's own address fields read: the destination is 0xffff, which is what 3.2.1.1.3 step 6 a.3 makes of every one of these classes");
        Test_Expect((uint16_t)(npduOf(&air[i])[2] | (npduOf(&air[i])[3] << 8)) == classes[i],
                    "and the NWK header's destination field carries the class itself, low octet first, which is the only place a receiver learns which devices were meant");
        Test_Expect(fcfOf(&air[i]) == AIR_BROADCAST_FCF && air[i].ackRequest == 0,
                    "in the unacknowledged shape every broadcast on this PAN carries, 0x8841 (3.6.6, docs/internals/protocol.md §9.1)");
        Test_Expect(airSrcOf(&air[i]) == OWN_SHORT,
                    "from this device's own short address: the class is what the frame is aimed at, not who sent it");
    }

    Test_Expect(airClassCount(air, airCount, NWK_ADDR_ALL_DEVICES) == 1
                && airClassCount(air, airCount, NWK_ADDR_ROUTERS) == 1
                && airClassCount(air, airCount, NWK_ADDR_RX_ON_WHEN_IDLE) == 1
                && airClassCount(air, airCount, NWK_ADDR_LOW_POWER_ROUTERS) == 1,
                "four frames, four classes, each class present once in the NWK headers and none of them in a MAC destination field");
    Test_Expect(Nwk_BttQueue(&dev.nwk) == 4,
                "and each broadcast this device originated claimed a Table 3-81 record of its own (3.6.6)");
}

/*
 * 5b. Step 7 where the broadcast is this device's own.
 *
 * 3.2.1.1.3 step 7: "Examine the nwkNeighborTable. For each device where macRxOnWhenIdle=FALSE, perform the
 * following: a. Issue an MCPS-DATA.request with the following values. … iii. DstAddr SHALL be set to the value
 * of the NetworkAddress in entry of the nwkNeighborTable. iv. IndirectTX SHALL be set to TRUE." It is the only
 * unicast a broadcast produces, and 3.6.6 step 1 writes the same iteration for the relay side, whose gates this
 * reuses: the whole paragraph belongs to a device whose own macRxOnWhenIdle is TRUE, the entry has to be a
 * device of type 0x02 with its receiver off, and 1b exempts the broadcast's own NWK source.
 */
void caseLocalBroadcastSleepyCopies(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    Mac_Transaction *copy[MAC_TRANSACTION_MAX];
    uint32_t airCount = 0;
    uint32_t queued = 0;
    uint32_t i;
    Mac_Counters counters;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);       /* rx off: copied */
    seedNeighbor(&dev.nwk, SLEEPY2, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);      /* rx off: copied */
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);       /* rx on: hears the broadcast */
    seedNeighbor(&dev.nwk, OWN_SHORT, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);    /* this device: the broadcast's source */

    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK,
                 "a broadcast this device originates, with four neighbor entries to judge");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1 && airDestOf(&air[0]) == MAC_FRAME_ADDR_BROADCAST,
                "the broadcast itself, on the MAC's 0xffff (3.2.1.1.3 step 6 a.3)");

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (dev.mac.indirect.transactions[i].used)
            copy[queued++] = &dev.mac.indirect.transactions[i];
    }

    Test_Expect(queued == 2,
                "and exactly two indirect unicasts leave, one per entry step 7 names: two rx-off end devices out of four entries");
    Test_Expect(queued == 2 && copy[0]->destShort == SLEEPY && copy[1]->destShort == SLEEPY2,
                "addressed to the two rx-off addresses and nobody else's: DstAddr 'the value of the NetworkAddress in entry of the nwkNeighborTable', IndirectTX TRUE being the transaction these are");
    Test_Expect(airCount == 1,
                "and nothing besides the broadcast went on the air: an indirect transmission is held for the device's own poll and extracted by it (10.22.2), which is what IndirectTX TRUE means");
    Test_Expect(queued == 2 && copy[0]->payloadLen == npduLenOf(&air[0])
                && Zb_memcmp(copy[0]->payload, npduOf(&air[0]), copy[0]->payloadLen) == 0,
                "and carrying the same NPDU the broadcast went out as: the copy is the same frame, held for a device that could not hear it");

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (!dev.mac.indirect.transactions[i].used)
            continue;

        Test_Expect(dev.mac.indirect.transactions[i].destShort != NEIGHBOR,
                    "nothing for the rx-on router: 3.6.6 item 2, 'For end device neighbors where RxOnWhenIdle = TRUE, and for all router and coordinator neighbors, they will receive the message when it is re-broadcast'");
        Test_Expect(dev.mac.indirect.transactions[i].destShort != OWN_SHORT,
                    "and nothing for this device's own address, which step 1b exempts as the broadcast's NWK source: 'If the end device target is the NWK source of the broadcast, no MCPS-DATA.request is generated'");
    }

    /* A device whose own receiver is off owes none of this: the paragraph step 1 lives in opens with
       "A router or coordinator with the macRxOnWhenIdle MAC PIB attribute set to TRUE". */
    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_END_DEVICE, 0);
    airCount = 0;
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 200), ZB_OK,
                 "the same broadcast from an end device with macRxOnWhenIdle FALSE");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1, "goes out once, as any accepted broadcast does");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 0,
                "and produces no copy at all: 3.6.6's copying paragraph is a listening device's, and 'Zigbee end devices with macRxOnWhenIdle equal to FALSE SHALL NOT participate in the relaying of broadcast frames'");
}

/*
 * 5c. The table record a broadcast this device originated claims.
 *
 * 3.6.6 keeps "a record of any new broadcast transaction" (Table 3-81: "Source Address … of the broadcast
 * initiator", "Sequence Number … of the initiator's broadcast", "Expiration Time … the initial value is
 * nwkNetworkBroadcastDeliveryTime"), and a device's own broadcast is one of the transactions it knows about.
 * What the record buys is the window: at the end of it 3.6.6 makes the entry "available to be overwritten", and
 * not one millisecond before, which a full table shows.
 *
 * The pool is band A's own (NWK_BTT_MAX) and the window is NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS, the house
 * number the expiry case above states the case for.
 */
void caseLocalBroadcastClaimsRecord(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[NWK_BTT_MAX + 2];
    Nwk_DataRequestParameters req;
    Nwk_BroadcastTransactionRecord *record;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint32_t expiry;
    uint32_t seq;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 1000), ZB_OK,
                 "a broadcast this device originates at 1000 ms");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1, "one frame on the air");
    seq = npduOf(&air[0])[NPDU_SEQ_OCTET];

    record = bttFor(&dev.nwk, OWN_SHORT, seq);
    Test_Expect(record != 0,
                "and Table 3-81's record is claimed for it, keyed by this device's own address and the sequence number the frame carries: the key 3.6.6 dedups on, printed for the initiator's broadcast");
    Test_Expect(record != 0 && record->dst == NWK_ADDR_ALL_DEVICES,
                "holding the class it was aimed at, as a record of a received broadcast does");
    Test_Expect(record != 0 && record->npduLen == air[0].len - NPDU_OFFSET - FCS_OCTETS && record->originates == 1,
                "and the frame it would repeat: 3.6.6 gives the count to the device that broadcast the frame, not only to one that relayed it, so the octets are kept here");
    Test_Expect(record != 0 && record->expiresAtMs == 1000 + NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS,
                "expiring nwkNetworkBroadcastDeliveryTime after it was made, which is Table 3-81's own initial value for Expiration Time");

    expiry = 1000 + NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS;

    /* Fill the table beside it with received broadcasts from one neighbor, all but the one record it holds. */
    Test_ExpectCount(broadcastFill(&dev, 1, NWK_BTT_MAX - 1, 2000, air, &airCount), NWK_BTT_MAX - 1,
                     "as many received broadcasts as the table has room left for, each delivered");
    Test_Expect(Nwk_BttQueue(&dev.nwk) == NWK_BTT_MAX, "so the table is full, with this device's own record among them");

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 1, 99, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, expiry - 1), ZB_OK,
                 "a new broadcast one millisecond before this device's own record expires");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_BttFullDrops(&dev.nwk) == 1 && Test_NwkPoll(&dev.nwk, inds, NWK_BTT_MAX + 2) == 0,
                "is dropped: 3.6.6, the BTT full and holding no expired entries, and this record is still live");

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 1, 99, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, expiry), ZB_OK, "and the same frame at the instant the window closes");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_BttFullDrops(&dev.nwk) == 1 && Test_NwkPoll(&dev.nwk, inds, NWK_BTT_MAX + 2) == 1,
                "is recorded and delivered: 3.6.6 ages the entry 'after nwkNetworkBroadcastDeliveryTime OctetDurations have elapsed since its creation', and this is that instant");
    Test_Expect(bttFor(&dev.nwk, OWN_SHORT, seq) == 0 && bttFor(&dev.nwk, NEIGHBOR, 99) != 0,
                "and the slot the expiry freed is this device's own record's: the only entry that had expired is the one the broadcast it sent claimed");
    Test_Expect(Nwk_BttQueue(&dev.nwk) == NWK_BTT_MAX, "the table is its named size again, with nothing evicted before its time");
    Test_Expect(Nwk_RelaysSent(&dev.nwk) == 0,
                "and the relay counter is untouched: the frames that arrived were never relayed here, and an originated broadcast's repetition is not a relay");
    Test_Expect(Nwk_BroadcastRetransmissions(&dev.nwk) <= NWK_MAX_BROADCAST_RETRIES,
                "while the broadcast this device sent was repeated at most nwkMaxBroadcastRetries times, which is 3.6.6's own count for it");
    Test_Expect(airCount >= 1,
                "so the ledger holds that repetition as well as the first transmission");
}

/*
 * 5d. A broadcast the table cannot record is not sent.
 *
 * Table 3-3 (p241) prints `BT_TABLE_FULL` among the NLDE-DATA.confirm's Status values, and Table 3-84 (p413)
 * defines it as "an attempt to send a broadcast frame has failed because there is no room in the BTT". 3.6.6
 * (9465-9469) is what makes a record owed at all: a router "SHALL keep a record of any new broadcast transaction
 * that is either initiated locally or received from a neighboring device". So a broadcast this device originates
 * with every Table 3-81 record live is refused with that status and never reaches the MAC: the frame that could
 * not be tracked would leave the passive acknowledgement of 3.6.6 with nothing to evaluate it against, and a
 * confirmation saying SUCCESS for it would be a lie about a duty the device did not keep.
 *
 * The record's own window is untouched: the same broadcast one nwkNetworkBroadcastDeliveryTime later finds the
 * oldest record expired, is sent, and claims a record of its own.
 */
void caseBroadcastWithAFullBttIsRefused(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    /* Sixteen live records at 100 ms, none of them expired: the table 3.6.6 describes as full */
    for (i = 0; i < NWK_BTT_MAX; i++)
    {
        Zb_memset(&dev.nwk.btt[i], 0, (uint32_t)sizeof dev.nwk.btt[i]);
        dev.nwk.btt[i].inUse = 1;
        dev.nwk.btt[i].sourceAddress = NEIGHBOR;
        dev.nwk.btt[i].sequenceNumber = (uint8_t)(i + 1);
        dev.nwk.btt[i].dst = NWK_ADDR_ALL_DEVICES;
        dev.nwk.btt[i].expiresAtMs = 100 + NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS;
    }

    Test_ExpectCount(Nwk_BttQueue(&dev.nwk), NWK_BTT_MAX, "every record of Table 3-81's pool is live and none has expired");

    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK,
                      "a broadcast this device originates with no room to record it: taken back at the door, so its answer is a confirmation");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 0,
                     "and nothing went on the air: Table 3-84's BT_TABLE_FULL is 'an attempt to send a broadcast frame has failed because there is no room in the BTT', which is an attempt that does not happen");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_ExpectCount(got, 1, "one confirmation");
    Test_ExpectCount(confirms[0].nwkStatus, NWK_STATUS_BT_TABLE_FULL,
                     "carrying Table 3-3's BT_TABLE_FULL, the status that table lists and no path in this layer composed before");
    Test_ExpectStatus(confirms[0].status, ZB_ERR_NO_SPACE,
                      "beside the seam's own word for the refusal, which is the pool and not a transmission");
    Test_ExpectCount(confirms[0].attempts, 0,
                     "with no attempt behind it: 3.2.1.2.2's confirmation reflects the request, and the request was refused before the MAC saw anything");
    Test_Expect(confirms[0].handle == RADIO_HANDLE_NONE, "and no transmit of this module's ever ran for it");
    Test_ExpectCount(Nwk_BttQueue(&dev.nwk), NWK_BTT_MAX,
                     "no record was made: the table holds what it held, and a refusal that evicted a live record would answer 3.6.6 with someone else's window");
    Test_ExpectCount(Nwk_BttFullDrops(&dev.nwk), 1,
                     "counted as the full table it was refused by, the same count 3.6.6's receive half moves on the same condition");
    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), 0, "and the slot is released with the answer it carried");

    /* The window is a window: at the instant the oldest record expires the same broadcast is a broadcast again */
    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100 + NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS), ZB_OK,
                      "the same broadcast at the instant nwkNetworkBroadcastDeliveryTime has passed");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1,
                     "goes out: 3.6.6 makes the record overwritable 'after nwkNetworkBroadcastDeliveryTime OctetDurations', and the refusal above moved no window");
    Test_ExpectCount(Nwk_BttQueue(&dev.nwk), NWK_BTT_MAX, "and claims a record of its own in the slot the expiry freed");
    Test_Expect(bttFor(&dev.nwk, OWN_SHORT, npduOf(&air[0])[NPDU_SEQ_OCTET]) != 0,
                "keyed by this device's address and the sequence number the frame carries (Table 3-81)");
    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), 0, "with no confirmation yet: a broadcast's answer is its MAC's, not its record's");
}

/*
 * 5e. The sleepy-neighbour copy is a role's, not a receiver state.
 *
 * 3.6.6 (9465) opens its BTR paragraph with "The Zigbee coordinator, each Zigbee router and those Zigbee end
 * devices with macRxOnWhenIdle equal to TRUE", and the copying paragraph (9501) with "A router or coordinator
 * with the macRxOnWhenIdle MAC PIB attribute set to TRUE, which has one or more neighbors with the
 * macRxOnWhenIdle MAC PIB attribute set to FALSE". The one place the clause lets a receiver state withdraw a
 * duty is 9487, and it is written of end devices: "Zigbee end devices with macRxOnWhenIdle equal to FALSE SHALL
 * NOT participate in the relaying of broadcast frames". A router whose own receiver is off is still a router.
 *
 * So the gate is the device type: a router with macRxOnWhenIdle FALSE still owes every sleepy child the copy of
 * a 0xffff broadcast, because a child whose receiver is off cannot hear the broadcast at all; and an end device
 * with macRxOnWhenIdle TRUE owes none, because 3.6.6's copy rule names a router or a coordinator and an end
 * device has no children to relay for.
 */
void caseSleepyCopiesFollowTheRole(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    Mac_Transaction *copy;
    uint32_t airCount = 0;
    uint32_t queued;
    uint32_t i;
    Mac_Counters counters;

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 0);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 300), ZB_OK,
                      "a broadcast from a router whose own macRxOnWhenIdle is FALSE");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "goes out once, unacknowledged, as every broadcast does");

    queued = 0;
    copy = 0;

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (!dev.mac.indirect.transactions[i].used)
            continue;

        copy = &dev.mac.indirect.transactions[i];
        queued++;
    }

    Test_ExpectCount(queued, 1,
                     "and is copied for the sleepy child all the same: the receiver state is the child's, and the router's own has no bearing on the duty 3.6.6 step 1 lays down");
    Test_Expect(copy != 0 && copy->destShort == SLEEPY, "the copy aimed at the child that cannot hear the broadcast");

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_END_DEVICE, 1);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);
    airCount = 0;

    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 400), ZB_OK,
                      "the same broadcast from an end device whose own receiver is on");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "goes out");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.transactionQueue, 0,
                     "and produces no copy at all: 'A router or coordinator' is the subject of the copying paragraph, and a receiver that happens to be on does not make an end device into one");
}

/*
 * 3.6.6's own retransmission count for a broadcast this device sent: "A Zigbee coordinator or Zigbee router ...
 * SHALL retransmit a previously broadcast frame at most nwkMaxBroadcastRetries times." The record it claimed holds
 * the octets, the sweep repeats them, and the count stops at the table's 0x02.
 */
void caseOriginatedBroadcastIsRepeated(void)
{
    Test_BandA dev;
    Nwk_DataRequestParameters req;
    Nwk_DataIndicationParameters inds[NWK_INDICATION_MAX];
    Nwk_BroadcastTransactionRecord *record;
    Air air[AIR_LOG_MAX];
    uint8_t nsdu[NSDU_LEN];
    uint32_t airCount = 0;
    uint32_t i;
    uint32_t seq;

    rig(&dev, OWN_SHORT, PAN_ID);

    Zb_memset(nsdu, 0x33, (uint32_t)sizeof nsdu);

    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 1000), ZB_OK, "a broadcast this device sends");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "goes out once at the door, as it always did");
    seq = npduOf(&air[0])[NPDU_SEQ_OCTET];

    record = bttFor(&dev.nwk, OWN_SHORT, seq);
    Test_Expect(record != 0 && record->npduLen != 0 && record->originates == 1,
                "and its Table 3-81 record holds the octets it would repeat, marked as this device's own");

    for (i = 0; i < 4; i++)
    {
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1200 + (i * 1200)), ZB_OK, "a turn past the passive-acknowledgement window");
        (void)Test_NwkPoll(&dev.nwk, inds, NWK_INDICATION_MAX);
    }

    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_BroadcastRetransmissions(&dev.nwk), NWK_MAX_BROADCAST_RETRIES,
                     "so it is repeated nwkMaxBroadcastRetries times and no more: Table 3-81's 0x02 is the ceiling the clause names");
    Test_Expect(record->relayed == NWK_MAX_BROADCAST_RETRIES,
                "and the record's own count is the table's ceiling, which is where the sweep stops");
    Test_Expect(Nwk_RelaysSent(&dev.nwk) == 0,
                "with none of them counted as a relay, which is somebody else's frame's word");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1200 * 8), ZB_OK, "and a later turn");
    Test_ExpectCount(Nwk_BroadcastRetransmissions(&dev.nwk), NWK_MAX_BROADCAST_RETRIES,
                     "adds nothing: the count is spent, and the record is only the window until it expires");
}

/*
 * 3.6.6's passive acknowledgement: "every Zigbee router and Zigbee coordinator keeps track of which of its
 * neighboring devices have successfully relayed the broadcast transmission." A neighbour's relay of this device's own
 * broadcast carries this device's source address, so it is the one frame the receive pipeline drops by that test and
 * still has work to do for: the record it names is marked, and the retransmissions it would have made stop.
 */
void casePassiveAckStopsOwnBroadcast(void)
{
    Test_BandA dev;
    Nwk_DataRequestParameters req;
    Nwk_DataIndicationParameters inds[NWK_INDICATION_MAX];
    Nwk_BroadcastTransactionRecord *record;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint8_t nsdu[NSDU_LEN];
    uint32_t npduLen;
    uint32_t seq;

    rig(&dev, OWN_SHORT, PAN_ID);

    Zb_memset(nsdu, 0x44, (uint32_t)sizeof nsdu);

    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 1000), ZB_OK, "a broadcast this device sends");

    seq = (uint8_t)(dev.nwk.seq - 1);

    record = bttFor(&dev.nwk, OWN_SHORT, seq);
    Test_Expect(record != 0 && record->originates == 1, "whose record is this device's own");

    Test_ExpectCount(Nwk_PassiveAcksHeard(&dev.nwk), 0, "and nothing has acknowledged it yet");

    /* A neighbour's relay of the same broadcast: this device's own source address, this device's own sequence
       number, arriving from a neighbour. */
    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, OWN_SHORT, 1, seq, NWK_FRAME_TYPE_DATA, 0, nsdu,
                       (uint32_t)sizeof nsdu);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1200), ZB_OK, "the turn that hears it");

    Test_ExpectCount(Nwk_PassiveAcksHeard(&dev.nwk), 1,
                     "the relay is the passive acknowledgement, counted once");
    Test_Expect(record->relayedByNeighbor == 1, "and the record carries the mark");

    Test_Expect(Test_NwkPoll(&dev.nwk, inds, NWK_INDICATION_MAX) == 0,
                "with nothing delivered: 3.6.6's power-up guard keeps this device from processing its own broadcast");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 4000), ZB_OK, "and a later turn, past the retransmission window");

    Test_ExpectCount(Nwk_BroadcastRetransmissions(&dev.nwk), 0,
                     "repeats nothing: the neighbour's relay withdrew the count, which is what a passive acknowledgement is for");
    Test_ExpectCount(Nwk_PassiveAckStops(&dev.nwk), 1, "and the withdrawal is counted as the clause's own act");
}

/*
 * 3.6.1.10.2's guard on the own-source broadcast: a broadcast claiming this device's own source address is a conflict
 * on that address only once the device has been operating for nwkNetworkBroadcastDeliveryTime; before that it is the
 * echo of one this device sent, which is why the clause prints the guard at all.
 */
void caseOwnSourceBroadcastNeedsDeliveryTime(void)
{
    Test_BandA dev;
    Nwk_DataRequestParameters req;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint8_t nsdu[NSDU_LEN];
    uint32_t npduLen;

    rig(&dev, OWN_SHORT, PAN_ID);

    Zb_memset(nsdu, 0x55, (uint32_t)sizeof nsdu);

    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    /* A broadcast with this device's own source and a sequence number no record of its own holds. */
    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, OWN_SHORT, NWK_INITIAL_RADIUS, 0x77, NWK_FRAME_TYPE_DATA, 0,
                       nsdu, (uint32_t)sizeof nsdu);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a broadcast naming this device's own source address");

    Test_ExpectCount(Nwk_AddressConflictsLocal(&dev.nwk), 0,
                     "is not a conflict yet: 3.6.1.10.2 withholds the judgement until nwkNetworkBroadcastDeliveryTime of operating has passed");
    Test_ExpectCount(Nwk_PassiveAcksHeard(&dev.nwk), 0, "and it marks no record, because no record of this device's holds that sequence number");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS + 200), ZB_OK,
                      "past that time");
    Test_ExpectCount(Nwk_AddressConflictsLocal(&dev.nwk), 0,
                     "and the frame is gone: the guard is about when the frame arrives, and this one arrived before it");

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, OWN_SHORT, NWK_INITIAL_RADIUS, 0x78, NWK_FRAME_TYPE_DATA, 0,
                       nsdu, (uint32_t)sizeof nsdu);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS + 300), ZB_OK,
                      "while one arriving after it");

    Test_ExpectCount(Nwk_AddressConflictsLocal(&dev.nwk), 0,
                     "is still no conflict on an unsecured frame, which 3.6.1.10.3 keeps from announcing anything");

    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    (void)req;
}

/*
 * 3.6.6: "For a Zigbee end device, the MAC destination address of the broadcast frame SHALL be set equal to the
 * 16-bit network address of the parent of the end device."
 */
void caseEndDeviceBroadcastGoesToItsParent(void)
{
    Test_BandA dev;
    Nwk_DataRequestParameters req;
    Air air[AIR_LOG_MAX];
    uint8_t nsdu[NSDU_LEN];
    uint32_t airCount = 0;

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_END_DEVICE, 1);

    Zb_memset(nsdu, 0x77, (uint32_t)sizeof nsdu);

    seedNeighbor(&dev.nwk, HOP, NWK_DEVICE_ROUTER, 1, NWK_REL_PARENT);

    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK, "an end device's broadcast");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "goes out as one frame");

    if (airCount == 0)
        return;

    Test_Expect(airDestOf(&air[0]) == HOP,
           "addressed at the MAC layer to the parent's network address, which is what 3.6.6 asks of an end device and not the MAC broadcast a router would use");
    Test_Expect((uint32_t)(npduOf(&air[0])[2] | (npduOf(&air[0])[3] << 8)) == NWK_ADDR_ALL_DEVICES,
           "while the NWK header still names the class, so the receivers know what the frame is");
}
