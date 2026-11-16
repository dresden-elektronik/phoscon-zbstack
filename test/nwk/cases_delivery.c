/* The `nwk` suite's transmit half: what a request is refused for, the NPDU
   an accepted one becomes, where it is aimed, how many times it is tried and how late, and what the layer
   above is handed back when it is done. */

#include "loopback_radio.h"
#include "mac.h"
#include "nwk.h"
#include "nwk_frame.h"
#include "nwk_helpers.h"
#include "nwk_status.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

#define SLEEPY2 0x2222

/*
 * 1. A unicast to a device this stack knows a hop to. The frame on air is the codec's minimal form plus the
 * NSDU, aimed at the neighbor through the MAC's own record, asked to be acknowledged; the answer the radio
 * gives becomes one NLDE confirmation with the attempt count the frame went through; the NWK sequence number
 * moves once per frame composed and wraps inside its one octet; and a neighbor entry becomes the route that
 * aims the next frame at it.
 */
void caseUnicastDelivery(void)
{
    Test_BandA dev;
    Nwk_Config bad;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;

    static const uint8_t minimal[8] =
    {
        NWK_FCF_DATA, 0x00,                 /* frame type Data, nwkcProtocolVersion 0x02, nothing else set */
        0x34, 0x12,                         /* DstAddr 0x1234, low octet first (3.3) */
        0xad, 0xde,                         /* SrcAddr macShortAddress, which 3.3.1.3 pins to the PIB */
        NWK_INITIAL_RADIUS, 0x00            /* the default 3.2.1.1.3 derives, then the sequence number */
    };

    Test_ExpectStatus(Nwk_Init(0, 0, 0), ZB_ERR_BAD_ARGUMENT, "no module, no MAC, no identity: an argument error that changes nothing");

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    Zb_memset(&bad, 0, (uint32_t)sizeof bad);
    bad.deviceType = 0x77;
    Test_ExpectStatus(Nwk_Init(&dev.nwk, &dev.mac, &bad), ZB_ERR_BAD_ARGUMENT,
                  "and a device type Table 3-75 does not print is refused, because every broadcast rule this module applies reads that type");
    Test_Expect(dev.nwk.cfg.deviceType == NWK_DEVICE_ROUTER && dev.nwk.mac == &dev.mac,
                "the refusal changes nothing: a module that failed to be re-initialised is still the module it was");

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK, "a unicast to a neighbor this stack holds an entry for");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1, "one frame reached the backend");
    Test_Expect(air[0].ackRequest == 1,
                "and the network layer asked for the acknowledgment: 3.6.4.3, 'Bit b0 of the TxOptions parameter SHOULD be set to 1'; the ask is the NWK's, because Table 3-2 gives the SAP no parameter for it");
    Test_Expect(fcfOf(&air[0]) == AIR_UNICAST_FCF, "on this PAN's acknowledged data frame, 0x8861");
    Test_Expect(airDestOf(&air[0]) == NEIGHBOR, "aimed at the neighbor's short address, which is the next hop a neighbor entry implies");
    Test_Expect(airSrcOf(&air[0]) == OWN_SHORT, "and sourced from the MAC's PIB mirror, which 3.3.1.3 pins the source field to");
    Test_Expect(npduLenOf(&air[0]) == NWK_MIN_HEADER_OVERHEAD + NSDU_LEN,
                "an NPDU of eight octets of header plus the NSDU: nwkcMinHeaderOverhead is 0x08 (Table 3-65)");
    Test_Expect(Zb_memcmp(npduOf(&air[0]), minimal, NWK_MIN_HEADER_OVERHEAD) == 0,
                "the eight octets 3.3.1.2 … 3.3.1.5 make always-present, and nothing else: no IEEE address field, no source route, no security, no deprecated multicast");
    Test_Expect(Zb_memcmp(npduOf(&air[0]) + NWK_MIN_HEADER_OVERHEAD, nsdu, NSDU_LEN) == 0,
                "then the NSDU, octet for octet as it was handed over (3.3.2.1.2)");
    Test_Expect(dsnOf(&air[0]) == 0, "the first MAC frame of the turn, numbered by the MAC (7.2.3)");

    Test_Expect(Nwk_RouteQueue(&dev.nwk) == 1,
                "and the neighbor entry bought a route entry on the spot (3.6.4.3's ordering, the observation-only shortcut: discovery owed)");
    Test_Expect(dev.nwk.routes[0].inUse && dev.nwk.routes[0].destinationAddress == NEIGHBOR
                && dev.nwk.routes[0].status == NWK_ROUTE_ACTIVE && dev.nwk.routes[0].nextHopAddress == NEIGHBOR,
                "ACTIVE, aimed at the destination itself, which is Table 3-78's status for a hop this device can take (0x0)");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "the network layer's turn steps the MAC beneath it");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1, "and answering a frame puts nothing new on the air");
    Test_Expect(Nwk_ConfirmQueue(&dev.nwk) == 1, "a radio that answers a unicast produces exactly one NLDE confirmation");
    Test_Expect(Nwk_TransmitQueue(&dev.nwk) == 0, "the frame leaves the transmit pool when it is answered");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_OK && confirms[0].nwkStatus == NWK_STATUS_SUCCESS,
                "SUCCESS in both vocabularies this stack has: 0x00 is Table 3-84's printed code (3.2.1.2.3: 'If the transmission attempt was successful, the Status parameter will be set to SUCCESS')");
    Test_Expect(confirms[0].dstAddr == NEIGHBOR && confirms[0].seq == 0 && confirms[0].attempts == 1,
                "and the confirmation names the frame it answers by the pair 3.3.1.5 makes the frame's own identity, plus the one attempt it took");

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 200), ZB_OK, "a second request to the same destination");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 2, "a second frame on the air");
    Test_Expect(npduOf(&air[1])[7] == 1,
                "carrying sequence number 1: 3.3.1.5, 'SHALL be incremented by 1 with each new frame transmitted'");
    Test_Expect(dev.nwk.routes[0].status == NWK_ROUTE_ACTIVE && Nwk_RouteQueue(&dev.nwk) == 1,
                "and the route the first request created is what aims this one: no second entry for one destination");
    Test_Expect(airDestOf(&air[1]) == NEIGHBOR, "the same next hop");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 201), ZB_OK, "answered");
    harvestAir(&dev.model, air, &airCount);
    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].seq == 1 && confirms[0].attempts == 1,
                "with its own number and its own single attempt (3.2.1.2.1)");

    /* The one-octet range 3.3.1.5 gives the number. Set by hand because a wrap is otherwise 256 frames away,
       and the property worth asserting is that the wrap stays inside the octet instead of widening it. */
    dev.nwk.seq = 255;
    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 300), ZB_OK, "a request at the top of the range");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 3 && npduOf(&air[2])[7] == 255, "the frame carries 255");
    Test_Expect(dev.nwk.seq == 0, "and the next number the module will use is 0, wrapped mod 256 rather than grown past the octet");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 301), ZB_OK, "answered");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_RefusedRequests(&dev.nwk) == 0 && Nwk_DroppedNoRoute(&dev.nwk) == 0
                && Nwk_ConfirmsIgnored(&dev.nwk) == 0,
                "and nothing on this path was refused, discarded or ignored: a clean delivery has nothing to count");
    Test_Expect(Nwk_DroppedMalformed(&dev.nwk) == 0 && Nwk_DroppedDuplicate(&dev.nwk) == 0
                && Nwk_DroppedNotForMe(&dev.nwk) == 0 && Nwk_BttFullDrops(&dev.nwk) == 0
                && Nwk_RelaysSent(&dev.nwk) == 0 && Nwk_BttQueue(&dev.nwk) == 0,
                "and the receive half's counters and the broadcast transaction table stay empty, because this chunk consumes no indication at all");
}

/*
 * 2. What the SAP refuses, with the reason it refuses it, before anything is composed or aimed. Each one is
 * named in its own assertion because a refusal that cannot be told from another refusal is a status code and
 * not a decision. And the pool: eight frames taken back, the ninth told there is no room.
 */
void caseRefusedAtTheDoor(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint8_t oversize[NWK_NSDU_MAX + 1];
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 0);

    Zb_memset(oversize, 0xa5, (uint32_t)sizeof oversize);

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    req.securityEnable = 1;
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_ERR_UNSUPPORTED,
                  "security asked for at a device that has none attached: 4.2.2's SecurityEnable is a prohibition, not a provision");

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 2;
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_ERR_BAD_ARGUMENT,
                  "DiscoverRoute 0x02, which Table 3-53 prints Reserved beside 0x00 and 0x01: refused at the door, where 0x01 is now the discovery 3.6.4.5.1 starts and no longer a refusal");

    req = nldeReq(NEIGHBOR, oversize, NWK_NSDU_MAX + 1, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_ERR_BAD_ARGUMENT,
                  "109 octets of NSDU over a ceiling of 108: Table 3-2's printed range, aMaxPHYPacketSize 127 minus nwkcMACFrameOverhead 0x0b minus nwkcMinHeaderOverhead 0x08, refused rather than truncated");

    req = nldeReq(NEIGHBOR, nsdu, 4, 0);
    req.nsdu = 0;
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_ERR_BAD_ARGUMENT, "a length with no octets behind it");

    req = nldeReq(NWK_ADDR_RESERVED, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_ERR_BAD_ARGUMENT,
                  "0xfffe, which Table 3-80 prints Reserved: an address that names no device class and no device");

    req = nldeReq(NWK_ADDR_RESERVED_LOW, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_ERR_BAD_ARGUMENT,
                  "and 0xfff8, the first of the 0xfff8-0xfffa the same table reserves below its classes");

    req = nldeReq(0xfffa, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_ERR_BAD_ARGUMENT,
                  "and 0xfffa, the last of them; Table 3-75 bounds a device's own network address at 0xfff7, so nothing above it is one device's");

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 0, "nothing went on the air for any of them");
    Test_Expect(Nwk_RefusedRequests(&dev.nwk) == 7, "and every refusal is counted with the reason it named");
    Test_Expect(Nwk_TransmitQueue(&dev.nwk) == 0 && Nwk_ConfirmQueue(&dev.nwk) == 0,
                "a refusal is answered at the door and not through the confirm ring: the ring is for a request the module took back (3.2.1.1.3 with 3.2.1.2.1)");
    Test_Expect(dev.nwk.seq == NWK_SEQ_START,
                "and no sequence number was spent on a frame that was never composed: 3.3.1.5 increments per new frame");
    Test_Expect(Nwk_RouteQueue(&dev.nwk) == 0,
                "and no route entry was made for a request that never reached the point where a next hop is chosen");

    for (i = 0; i < NWK_TX_MAX; i++)
    {
        req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
        Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_OK, "eight requests the module takes back");
    }

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == NWK_TX_MAX, "every one of them went out, so the refusal below is this module's pool and not the MAC's");
    Test_Expect(Nwk_TransmitQueue(&dev.nwk) == NWK_TX_MAX, "every slot of the named pool is held");

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_ERR_NO_SPACE,
                  "and the ninth is refused by the pool rather than by its argument: refusal-and-count, which is how every full pool in this tree answers (docs/internals/coding-rules.md §4.3)");
    Test_Expect(Nwk_RefusedRequests(&dev.nwk) == 8, "counted with the others");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == NWK_TX_MAX, "and the ninth never reached the MAC beneath it");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_NO_SPACE
                && confirms[0].nwkStatus == NWK_STATUS_FRAME_NOT_BUFFERED,
                "and it is answered as Table 3-3's status list says: FRAME_NOT_BUFFERED (Table 3-84's 0xd3) reaches no primitive but the confirmation, so the pool's refusal is a confirm as well as the return value");
    Test_Expect(got == 1 && confirms[0].attempts == 0 && confirms[0].dstAddr == NEIGHBOR,
                "for the request that had no room, with no attempt behind it: nothing was composed, numbered or sent");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 11), ZB_OK, "one turn, with every outcome scripted as a unicast nobody acknowledged");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(Nwk_ConfirmQueue(&dev.nwk) == 0,
                "and not one frame is confirmed yet: each has retries left, and 3.2.1.1.3 confirms only 'after a MCPS-DATA.confirm is generated indicating success or all retries are exhausted'");
    Test_Expect(Nwk_TransmitQueue(&dev.nwk) == NWK_TX_MAX,
                "the slots hold the waits, which is why a caller that never takes its confirmations is the one that runs out of them");
    Test_Expect(Nwk_ConfirmsIgnored(&dev.nwk) == 0, "and every MAC answer this drain took belonged to a frame this module issued");
}

/*
 * 3. The unicast retry loop: the attempts 3.2.1.1.3 counts, the delay it bounds, and the frame it does not
 * rewrite. One unicast to a known neighbor, answered NO_ACK four times (the first transmission and
 * nwkcUnicastRetries additional attempts), each one the stored NPDU byte for byte, each one a new MAC frame
 * with its own DSN, none of them earlier than nwkcUnicastRetryDelay after the last, and the last answer the
 * status the MAC gave.
 */
void caseUnicastRetryLoop(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 0);

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 0), ZB_OK, "the first attempt, issued at once");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1, "one frame on the air");
    Test_Expect(dev.nwk.tx[0].state == NWK_TX_OUTSTANDING && dev.nwk.tx[0].attempts == 1,
                "and the slot records the attempt it issued, holding the octets it sent");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "the turn the radio answers NO_ACK on");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(dev.nwk.tx[0].state == NWK_TX_AWAITING_RETRY, "a unicast that failed is not yet a failure: 3.2.1.1.3 gives it additional attempts");
    Test_Expect(dev.nwk.tx[0].nextRetryMs == 1 + NWK_UNICAST_RETRY_DELAY_MS,
                "and the wait starts from the confirmation that reported it: nwkcUnicastRetryDelay is 50 ms (Table 3-65), and nowMs is the caller's clock, the only clock this module is given");
    Test_Expect(Nwk_ConfirmQueue(&dev.nwk) == 0,
                "no confirmation yet: 3.2.1.1.3 issues the NLDE-DATA.confirm only 'after a MCPS-DATA.confirm is generated indicating success or all retries are exhausted'");
    Test_Expect(airCount == 1, "and no retry was issued on the turn the failure was learned");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 50), ZB_OK, "the turn one millisecond short of the floor");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1,
                "and nothing new on the air: 'Each attempt SHALL be delayed by at least nwkcUnicastRetryDelay' is a floor, and one millisecond short of it is short of it");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 51), ZB_OK, "the turn at the floor itself");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 2, "the second attempt goes out");
    Test_Expect(dev.nwk.tx[0].attempts == 2, "and the attempt count moves with the frame issued, not with the answer received");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 52), ZB_OK, "answered NO_ACK again");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(dev.nwk.tx[0].nextRetryMs == 52 + NWK_UNICAST_RETRY_DELAY_MS, "delayed again from the confirmation that reported it");
    Test_Expect(airCount == 2, "and again no attempt on the turn that only learned the failure");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 102), ZB_OK, "the third attempt, 51 ms after the second");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 3, "on the air");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 103), ZB_OK, "answered NO_ACK again");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 3, "and nothing issued yet");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 153), ZB_OK, "the fourth attempt, and the last one this frame will see");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1 + NWK_UNICAST_RETRIES, "1 + nwkcUnicastRetries frames, which is all 3.2.1.1.3 asks for: 'the NLDE SHALL issue additional MCPS-DATA.request attempts up to nwkcUnicastRetries'");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 154), ZB_OK, "answered NO_ACK for the fourth time");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1 + NWK_UNICAST_RETRIES,
                "and no fifth attempt: the bound is on what this layer tried, not on the radio's own retries (docs/internals/architecture.md §5.1)");

    Test_Expect(Nwk_ConfirmQueue(&dev.nwk) == 1, "the retries exhausted, the confirmation is issued");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_DEVICE,
                "with 'a status equal to the last received status from the MAC sub-layer' (3.2.1.1.3), which is what NO_ACK becomes at the seam (docs/internals/protocol.md §7.3)");
    Test_Expect(confirms[0].nwkStatus == NWK_STATUS_LAST_MAC_STATUS,
                "and no Table 3-84 code of the NWK layer's own: for a delivery that failed on air the printed status *is* the MAC's, and this stack folds it at the seam instead of keeping its number");
    Test_Expect(confirms[0].attempts == 1 + NWK_UNICAST_RETRIES, "the confirmation counts every attempt the frame took");
    Test_Expect(confirms[0].seq == 0 && confirms[0].dstAddr == NEIGHBOR, "for the one frame they were all attempts at");
    Test_Expect(Nwk_TransmitQueue(&dev.nwk) == 0, "and the slot is released with the answer");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 204), ZB_OK, "one more turn, past where a fifth attempt would have been due");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1 + NWK_UNICAST_RETRIES,
                "and it puts nothing on the air: a frame whose retries ran out is answered, not continued");

    /* The four frames, read against each other: the network layer's octets identical, the MAC's number
       different for every one. */
    Test_Expect(airCount == 4, "four frames to read");

    for (i = 1; i < airCount; i++)
    {
        Test_Expect(npduLenOf(&air[i]) == npduLenOf(&air[0])
                    && Zb_memcmp(npduOf(&air[i]), npduOf(&air[0]), npduLenOf(&air[i])) == 0,
                    "the NPDU of every retry is the first attempt's octet for octet: 3.6.4.3, a replayed packet keeps its sequence number");
        Test_Expect(npduOf(&air[i])[7] == npduOf(&air[0])[7],
                    "read at the sequence octet specifically, since that is the field a module that re-numbered its retries would move");
    }

    for (i = 0; i < airCount; i++)
        Test_Expect(dsnOf(&air[i]) == i, "and each attempt is a new MAC frame with its own DSN: 7.2.3 numbers every frame a device issues, while the number above it does not move");

    Test_Expect(air[0].ackRequest == 1 && air[3].ackRequest == 1,
                "every attempt asked to be acknowledged, the first one and the last: the ask belongs to the frame and not to the retry");

    Test_Expect(Nwk_RefusedRequests(&dev.nwk) == 0 && Nwk_DroppedNoRoute(&dev.nwk) == 0,
                "and a loop that ends in a delivery failure refused nothing and discarded nothing on the way");
}

/*
 * The retry loop across the counter's own wrap: the same unicast answered NO_ACK on the last milliseconds
 * before 0xFFFFFFFF rolls to 0, and the retry read after it. A deadline kept as an absolute number on a
 * `uint32_t` millisecond counter stays "pending" for a further 49.7 days once the counter has passed it, so
 * the frame would sit in its slot and never be retried: the device goes quiet without ever failing
 * (docs/internals/coding-rules.md §4.1, Zb_timeReached in src/utils/zb_time.h). Both directions are here: a deadline the
 * wrap has passed, and a deadline set after it.
 */
void caseUnicastRetryAcrossWrap(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 0);

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 0xFFFFFF00), ZB_OK,
                  "the first attempt, issued on the last quarter-second before the counter wraps");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(dev.nwk.tx[0].attempts == 1 && dev.nwk.tx[0].state == NWK_TX_OUTSTANDING,
                "one attempt, outstanding");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 0xFFFFFF01), ZB_OK, "the turn the radio answers NO_ACK on");
    Test_Expect(dev.nwk.tx[0].state == NWK_TX_AWAITING_RETRY && dev.nwk.tx[0].nextRetryMs == 0xFFFFFF33,
                "the wait starts from the answer and ends 50 ms later, still before the wrap: 0xFFFFFF01 + 50");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1, "and nothing is issued on the turn that only learned the failure");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 0x00000A00), ZB_OK, "the counter has wrapped, and much later than the deadline");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 2, "the retry goes out: a deadline the counter has passed is past, whatever side of the wrap it is on");
    Test_Expect(dev.nwk.tx[0].attempts == 2 && dev.nwk.tx[0].state == NWK_TX_OUTSTANDING,
                "and the frame is on its second attempt rather than sitting pending for the next 49.7 days");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 0x00000A01), ZB_OK, "answered NO_ACK again, after the wrap");
    Test_Expect(dev.nwk.tx[0].state == NWK_TX_AWAITING_RETRY && dev.nwk.tx[0].nextRetryMs == 0x00000A33,
                "a deadline set after the wrap is the plain sum");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 0x00000A32), ZB_OK, "one millisecond short of it");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 2, "and the floor 3.2.1.1.3 prints holds on this side of the wrap too");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 0x00000A33), ZB_OK, "the turn the deadline is reached");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 3 && dev.nwk.tx[0].attempts == 3, "the third attempt, computed from the deadline alone");
}

/*
 * 4. A unicast with no path to its destination. 3.6.4.3 does not answer this at the door: the request is
 * taken back, the frame is discarded, and the answer is a confirm of ROUTE_ERROR with nothing on the air.
 * What a route entry says about itself is what decides it, because an entry that is not ACTIVE is not a
 * route.
 */
void caseNoRouteIsAConfirm(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);

    Test_Expect(Nwk_NeighborQueue(&dev.nwk) == 0 && Nwk_RouteQueue(&dev.nwk) == 0,
                "a device that has observed nothing has neither a neighbor table nor a route table (Table 3-66 prints both as 'Null set')");

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_OK,
                  "a destination with no ACTIVE routing entry is answered, not refused at the door: 3.6.4.3, discarded with ROUTE_ERROR");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 0, "with no attempt on the air for it");
    Test_Expect(Nwk_ConfirmQueue(&dev.nwk) == 1, "and the confirmation is there immediately, not one turn later");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].nwkStatus == NWK_STATUS_ROUTE_ERROR,
                "0xd1, which is what Table 3-84 prints for ROUTE_ERROR");
    Test_Expect(confirms[0].status == ZB_ERR_NO_ROUTE,
                "and the seam's own word for it: ZB_ERR_NO_ROUTE, 3.6.4.3's ROUTE_ERROR named at the layer that decided it");
    Test_Expect(confirms[0].attempts == 0, "the attempt count says what happened: nothing was tried");
    Test_Expect(confirms[0].dstAddr == UNSEEN && confirms[0].seq == 0,
                "for the frame that was composed, numbered and then discarded: 3.3.1.5 spends the number at composition, 3.6.2.2 tolerates the gap");
    Test_Expect(Nwk_DroppedNoRoute(&dev.nwk) == 1, "counted as a discard");
    Test_Expect(Nwk_TransmitQueue(&dev.nwk) == 0, "and the slot the frame was composed in is released by its own answer");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 11), ZB_OK, "a turn afterwards");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 0 && Nwk_ConfirmQueue(&dev.nwk) == 0,
                "nothing has been tried in the meantime, and the answer was not waiting on a step");

    /* A route entry exists and does not qualify. Table 3-78 prints ACTIVE 0x0, DISCOVERY_FAILED 0x2 and
       INACTIVE 0x3, and 3.6.4.3 relays on an ACTIVE entry only. */
    dev.nwk.routes[0].inUse = 1;
    dev.nwk.routes[0].destinationAddress = UNSEEN;
    dev.nwk.routes[0].status = NWK_ROUTE_INACTIVE;
    dev.nwk.routes[0].nextHopAddress = HOP;

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 20), ZB_OK, "a request to a destination with an INACTIVE entry");
    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].nwkStatus == NWK_STATUS_ROUTE_ERROR && confirms[0].attempts == 0,
                "is answered the same way: an entry that is not ACTIVE is not a route, and this module does not relay on Table 3-78's 0x3");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 0 && Nwk_DroppedNoRoute(&dev.nwk) == 2, "nothing on the air, counted again");

    dev.nwk.routes[0].status = NWK_ROUTE_DISCOVERY_FAILED;
    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 30), ZB_OK, "and a DISCOVERY_FAILED entry");
    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].nwkStatus == NWK_STATUS_ROUTE_ERROR && confirms[0].attempts == 0,
                "is not a route either: 0x2 DISCOVERY_FAILED, the status a discovery that gave up leaves on the entry (Table 3-78)");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 0, "still nothing on the air");

    dev.nwk.routes[0].status = NWK_ROUTE_ACTIVE;
    dev.nwk.routes[0].nextHopAddress = HOP;
    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 40), ZB_OK, "and the same entry made ACTIVE is the route the next request takes");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1, "one frame on the air");
    Test_Expect(airDestOf(&air[0]) == HOP,
                "aimed at the next hop the entry names: 3.6.4.3, DstAddr is the routing entry's next-hop address");
    Test_Expect(npduOf(&air[0])[2] == (UNSEEN & 0xff) && npduOf(&air[0])[3] == (uint8_t)(UNSEEN >> 8),
                "while the NPDU's own destination is still the destination: the next hop is who carries the frame, not who it is for (3.3.1.2)");
    Test_Expect(Nwk_ConfirmQueue(&dev.nwk) == 0, "and a frame that found a route produces no confirmation yet: it is on its way");
}

/*
 * 7. A destination that is this device. Refused at the door and named as band A's decision: R23.1 prints no
 * case of a network layer handing a frame to itself through the air, and 3.6.6 step 1 forbids the closest
 * thing to one for a broadcast a device originated. A neighbor entry and an ACTIVE route for our own address
 * do not change the answer, which is what makes the refusal a rule rather than a consequence of the tables.
 */
void caseNoSelfDelivery(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t i;
    Mac_Counters counters;

    rig(&dev, OWN_SHORT, PAN_ID);

    req = nldeReq(OWN_SHORT, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_ERR_BAD_ARGUMENT,
                  "this device's own short address as a destination is refused: the network layer does not send to itself");

    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(&dev.nwk, OWN_SHORT, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);     /* ourselves, listed the way a sleepy child is: eligible for a copy, which is what makes the skip an assertion */
    dev.nwk.routes[0].inUse = 1;
    dev.nwk.routes[0].destinationAddress = OWN_SHORT;
    dev.nwk.routes[0].status = NWK_ROUTE_ACTIVE;
    dev.nwk.routes[0].nextHopAddress = OWN_SHORT;

    req = nldeReq(OWN_SHORT, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 20), ZB_ERR_BAD_ARGUMENT,
                  "and it stays refused with a neighbour entry and an ACTIVE route: the rule and not the absence of a path, R23.1 silent");

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 0, "nothing on the air for either request");
    Test_Expect(Nwk_TransmitQueue(&dev.nwk) == 0 && Nwk_ConfirmQueue(&dev.nwk) == 0,
                "no slot taken and no confirmation owed: a refusal is answered at the door");
    Test_Expect(Nwk_RefusedRequests(&dev.nwk) == 2, "each counted");
    Test_Expect(dev.nwk.seq == NWK_SEQ_START, "and no sequence number spent on frames that were never composed");

    /* The same address as a *broadcast* neighbor is skipped rather than refused, and that is a different
       clause: 3.6.6 step 1's "no MCPS-DATA.request is generated" for the broadcast's own source. */
    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 30), ZB_OK, "a broadcast, with a sleepy child to copy to and ourselves listed the same way");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1, "the broadcast went out once");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 1, "one copy queued, for the child and not for ourselves");

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (dev.mac.indirect.transactions[i].used)
            break;
    }

    Test_Expect(i < MAC_TRANSACTION_MAX && dev.mac.indirect.transactions[i].destShort == SLEEPY,
                "and the queued copy is addressed to the child's address: 3.6.6 step 1, 'If the end device target is the NWK source of the broadcast, no MCPS-DATA.request is generated'");
}

/*
 * Table 3-51, whose two rows for the frame control field are what a data frame may be:
 *
 *   Unicast        Discover Route 00 or 01, Multicast 0, Security 0 or 1, Destination IEEE 0 or 1, Source IEEE 0 or 1
 *   Broadcast      00,                      0,           0 or 1,          0,                  0 or 1
 *
 * So a broadcast data frame may not ask for discovery (it names a class, and 3.6.4.5.1's discovery is about one
 * destination) and a unicast may. 3.2.1.1.3 says which value the frame gets: "The discover route sub-field of
 * the frame control field of the NWK header will be set to the value provided in the DiscoverRoute parameter."
 */
void caseDiscoverRouteSubfieldIsTheRequests(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_Frame frame;
    Nwk_DataRequestParameters req;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    /* A unicast with a known neighbour and DiscoverRoute 0x01: the route exists, so the frame goes out, and it
       carries the discover route value the caller asked for and not a zero. */
    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 4);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK,
                      "a unicast that asks for route discovery at a neighbour the table already knows");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "is sent, not held: 3.6.4.3 finds the next hop without a discovery");

    npduLen = npduLenOf(&air[0]);
    Zb_memcpy(npdu, npduOf(&air[0]), npduLen);

    Test_ExpectStatus(NwkFrame_Parse(npdu, npduLen, &frame, &payloadOffset, &payloadLen), ZB_OK,
                      "and the frame it put on the air reads back");
    Test_ExpectCount((uint32_t)frame.discoverRoute, NWK_DISCOVER_ENABLE,
                     "with 0x01 in the discover route sub-field: 3.2.1.1.3, the value the DiscoverRoute parameter provided");

    Nwk_PollConfirms(&dev.nwk, confirms, 4);

    /* And a broadcast that asks for the same thing is the configuration Table 3-51 does not allow. */
    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 200), ZB_ERR_BAD_ARGUMENT,
                      "a broadcast asking for route discovery is refused at the door: Table 3-51's Broadcast row prints Discover Route 00 and no other value, so the request gets an argument error and no frame is composed");
    Test_ExpectCount(Nwk_RefusedRequests(&dev.nwk), 1, "counted as the refused request it is");

    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "and nothing more went on the air: the only frame in the log is the unicast above, not one under a frame control field the table does not allow");

    /* A broadcast that asks for nothing is the frame Table 3-51 allows. */
    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 0;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 300), ZB_OK, "and the same broadcast suppressing discovery is sent");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 2, "one more frame on the air: the broadcast");

    npduLen = npduLenOf(&air[1]);
    Zb_memcpy(npdu, npduOf(&air[1]), npduLen);

    Test_ExpectStatus(NwkFrame_Parse(npdu, npduLen, &frame, &payloadOffset, &payloadLen), ZB_OK,
                      "whose frame control field is the table's Broadcast row");
    Test_ExpectCount((uint32_t)frame.discoverRoute, NWK_DISCOVER_SUPPRESS, "with Discover Route 00, as the row prints it");
}

/*
 * 8. A retry is owed for three MAC statuses and for no other.
 *
 * 3.2.1.1.3 (p240, 5672-5675): "On receipt of the MCPS-DATA.confirm primitive on a unicast the NLDE SHALL examine
 * the status. If the MCPS-DATA status indicates a NO_ACK, TRANSACTION_OVERFLOW or a CHANNEL_ACCESS_FAILURE, the NLDE
 * SHALL issue additional MCPS-DATA.request attempts up to nwkcUnicastRetries." 5676-5677 closes the loop the other
 * way: "After a MCPS-DATA.confirm is generated indicating success or all retries are exhausted the NLDE issues the
 * NLDE-DATA.confirm primitive with a status equal to the last received status from the MAC sub-layer."
 *
 * So an answer outside that list is the frame's failure at once, with the status the MAC named. The seam names
 * NO_ACK and CHANNEL_ACCESS_FAILURE (docs/internals/protocol.md §7.3) and a MAC with no room for the frame is
 * ZB_ERR_NO_SPACE; everything else (a completion that never arrived, a link that went away) is not retried, and
 * re-offering it three more times would put frames on a link the MAC already knew would not answer.
 */
void caseRetryOnlyThePrintedStatuses(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Loopback_Outcome outcomes[LOOPBACK_TX_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t now;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    Zb_memset(outcomes, 0, (uint32_t)sizeof outcomes);
    outcomes[0].status = ZB_ERR_TIMEOUT;

    LoopbackRadio_ScriptOutcomes(&dev.model, outcomes, 1);

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 0), ZB_OK, "a unicast offered to the MAC");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "one attempt went out");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "the turn the MAC reports a completion that never arrived");
    harvestAir(&dev.model, air, &airCount);

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_ExpectCount(got, 1,
                     "and the frame is answered at once: a status the clause's list does not name is not an attempt owed another try");
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_TIMEOUT,
                "with the status the MAC named, which is 5676-5677's 'a status equal to the last received status from the MAC sub-layer'");
    Test_Expect(got == 1 && confirms[0].attempts == 1, "after exactly the one attempt that ran");
    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), 0, "and the slot is released with it, holding no wait the clause does not owe");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1 + NWK_UNICAST_RETRY_DELAY_MS), ZB_OK,
                      "the instant a retry would have been due had the status been one of the three");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "and nothing further goes on the air");

    /* NO_ACK, which reaches the seam as ZB_ERR_DEVICE: 1 + nwkcUnicastRetries attempts */
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 0);
    airCount = 0;

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 200), ZB_OK, "a second unicast, answered NO_ACK every time");
    now = 200;

    for (i = 0; i < NWK_UNICAST_RETRIES; i++)
    {
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, now + 1), ZB_OK, "answered NO_ACK");
        harvestAir(&dev.model, air, &airCount);
        now = now + 1;

        Test_ExpectStatus(Test_NwkStep(&dev.nwk, now + NWK_UNICAST_RETRY_DELAY_MS), ZB_OK,
                          "the next attempt, one nwkcUnicastRetryDelay later");
        harvestAir(&dev.model, air, &airCount);
        now = now + NWK_UNICAST_RETRY_DELAY_MS;
    }

    Test_ExpectCount(airCount, NWK_UNICAST_RETRIES + 1,
                     "1 + nwkcUnicastRetries attempts: NO_ACK is the first status the clause names, so it is retried to the bound");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, now + 1), ZB_OK, "the last answer");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, NWK_UNICAST_RETRIES + 1, "and no fifth attempt: the retries are exhausted, not renewed");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_DEVICE && confirms[0].attempts == NWK_UNICAST_RETRIES + 1,
                "the confirmation carries NO_ACK's own folding and counts every attempt it took (3.2.1.1.3)");

    /* CHANNEL_ACCESS_FAILURE, the clause's third status: retried to the same bound, and reported as itself */
    Zb_memset(outcomes, 0, (uint32_t)sizeof outcomes);

    for (i = 0; i < LOOPBACK_TX_MAX; i++)
        outcomes[i].status = ZB_ERR_CHANNEL_ACCESS_FAILURE;

    LoopbackRadio_ScriptOutcomes(&dev.model, outcomes, LOOPBACK_TX_MAX);
    airCount = 0;

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 1000), ZB_OK, "a third unicast, the channel busy every time");
    now = 1000;

    for (i = 0; i <= NWK_UNICAST_RETRIES; i++)
    {
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, now + 1), ZB_OK, "answered CHANNEL_ACCESS_FAILURE");
        harvestAir(&dev.model, air, &airCount);
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, now + 1 + NWK_UNICAST_RETRY_DELAY_MS), ZB_OK, "the next attempt");
        harvestAir(&dev.model, air, &airCount);
        now = now + 1 + NWK_UNICAST_RETRY_DELAY_MS;
    }

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_CHANNEL_ACCESS_FAILURE
                && confirms[0].attempts == NWK_UNICAST_RETRIES + 1,
                "1 + nwkcUnicastRetries attempts, and the confirmation names the busy channel and not a device fault");
}

/*
 * 9. A full pool is a confirmation, not only a door refusal.
 *
 * Table 3-3 (p241) prints the confirm's Status as "INV_REQUESTTYPE, MAX_FRM_COUNTER, NO_KEY, BAD_CCM_OUTPUT,
 * ROUTE_ERROR, BT_TABLE_FULL, FRAME_NOT_BUFFERED or any status values returned from security suite or the
 * MCPS-DATA.confirm primitive", and Table 3-84 (p413) defines FRAME_NOT_BUFFERED as "An NLDE-DATA.request has
 * failed due to insufficient buffering available". No primitive but the confirmation carries that status, and
 * 3.2.1.2.2 makes the confirmation the answer to every request the layer takes: so a request a pool has no room
 * for is taken back, confirmed with 0xd3, and the refusal the door names is returned beside it. An application
 * that watches only the confirmation ring therefore still learns that nothing was buffered.
 *
 * The one refusal that cannot be confirmed is the confirmation ring's own: there is nowhere to write the answer.
 * That refusal is the bare return value, and nothing is queued.
 */
void caseFullPoolIsAConfirm(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Loopback_Outcome outcomes[LOOPBACK_TX_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    for (i = 0; i < NWK_TX_MAX; i++)
    {
        req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
        Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 0), ZB_OK, "a request the transmit pool has room for");
    }

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, NWK_TX_MAX, "every one of them went out");
    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), NWK_TX_MAX, "and every slot is held");

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 0), ZB_ERR_NO_SPACE,
                      "the ninth is refused by the pool it needs: the door's own return value, unchanged");
    Test_ExpectCount(Nwk_RefusedRequests(&dev.nwk), 1, "counted as a request this module declined");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_ExpectCount(got, 1, "and it is answered as well: Table 3-3 lists FRAME_NOT_BUFFERED among the confirm's statuses");
    Test_ExpectCount(confirms[0].nwkStatus, NWK_STATUS_FRAME_NOT_BUFFERED,
                     "with Table 3-84's 0xd3, the row printed for a request that failed 'due to insufficient buffering available'");
    Test_ExpectStatus(confirms[0].status, ZB_ERR_NO_SPACE, "beside the seam's word for the same refusal");
    Test_ExpectCount(confirms[0].attempts, 0, "and no attempt behind it: nothing was composed or issued");
    Test_ExpectCount(confirms[0].seq, 0, "and no sequence number was spent on a frame that was never made (3.3.1.5)");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, NWK_TX_MAX, "nothing new on the air");

    /* Fill the ring itself: eight answers the caller never collected, then a request with nowhere to be answered */
    Zb_memset(outcomes, 0, (uint32_t)sizeof outcomes);

    for (i = 0; i < LOOPBACK_TX_MAX; i++)
        outcomes[i].status = ZB_ERR_TIMEOUT;

    LoopbackRadio_ScriptOutcomes(&dev.model, outcomes, LOOPBACK_TX_MAX);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "a turn the MAC answers for every frame the pool holds");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), NWK_CONFIRM_MAX,
                     "eight confirmations, none of them collected: the ring is full");
    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), 0, "and every slot is free again");

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 2), ZB_ERR_NO_SPACE,
                      "a request whose answer has nowhere to go is refused at the door");
    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), NWK_CONFIRM_MAX, "with the ring left exactly as it was: no ninth entry, no overwritten answer");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, NWK_TX_MAX, "and nothing on the air for it");
    Test_ExpectCount(Nwk_RefusedRequests(&dev.nwk), 2, "the refusal counted like every other");
}

/*
 * 4. A transmit the seam refuses. IEEE 7.2.4 prints the condition as `TRANSACTION_OVERFLOW`, "returned when there
 * is no capacity to store another transaction", and 3.2.1.1.3 (p240, 5672-5675) puts it beside NO_ACK and
 * CHANNEL_ACCESS_FAILURE among the statuses whose unicast is asked for again "up to nwkcUnicastRetries", each
 * attempt "delayed by at least nwkcUnicastRetryDelay". A refusal is a request the layer issued, so it spends one
 * of them; the frame is not answered until the budget is spent. A rig run saw a refused route request asked
 * again and a refused unicast answered as a failure, and the difference was this rule.
 */
void caseRefusedTransmitIsAskedAgain(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 1);

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 0), ZB_OK,
                      "a unicast the seam had no room for is still taken back: the refusal is not yet the frame's answer");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "nothing reached the air, because the backend declined to hold the frame");
    Test_Expect(dev.nwk.tx[0].state == NWK_TX_AWAITING_RETRY && dev.nwk.tx[0].attempts == 1,
                "the refused request counts as one of the attempts the clause counts, and the stored frame waits for the next");
    Test_Expect(dev.nwk.tx[0].nextRetryMs == NWK_UNICAST_RETRY_DELAY_MS,
                "the re-ask is owed no earlier than nwkcUnicastRetryDelay after the refusal, the same floor the clause gives a failed completion");
    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), 0, "and no confirmation yet, the retries not being spent");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NWK_UNICAST_RETRY_DELAY_MS - 1), ZB_OK, "the turn one millisecond short of the floor");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "and nothing re-issued: the floor is a floor");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NWK_UNICAST_RETRY_DELAY_MS), ZB_OK, "the turn at the floor itself");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "the same frame asked of the seam again");
    Test_Expect(dev.nwk.tx[0].state == NWK_TX_OUTSTANDING && dev.nwk.tx[0].attempts == 2,
                "accepted this time, with two requests to its name");
    Test_ExpectCount(LoopbackRadio_Refusals(&dev.model), 1, "and the refusal below it counted where it happened");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NWK_UNICAST_RETRY_DELAY_MS + 1), ZB_OK, "the turn the answer is collected on");
    harvestAir(&dev.model, air, &airCount);
    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_OK && confirms[0].nwkStatus == NWK_STATUS_SUCCESS,
                "and the transaction closes as a delivered frame, not as the refusal it began with");
    Test_ExpectCount(confirms[0].attempts, 2, "the confirmation counting both requests the frame cost");
}

/* The same refusals, none of them cured: 3.2.1.1.3 bounds them at 1 + nwkcUnicastRetries and closes with "a status
   equal to the last received status from the MAC sub-layer", Table 3-84's sentinel standing for a refusal it prints
   no code for. A budget spent is spent: nothing is asked after it. */
void caseRefusedUntilTheBudgetIsGone(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t step;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, NWK_UNICAST_RETRIES + 1);

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 0), ZB_OK, "the request taken back, the first attempt refused");

    for (step = NWK_UNICAST_RETRY_DELAY_MS; step <= (uint32_t)NWK_UNICAST_RETRIES * NWK_UNICAST_RETRY_DELAY_MS;
         step += NWK_UNICAST_RETRY_DELAY_MS)
    {
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, step), ZB_OK, "the turn whose floor has passed");
    }

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "and not one of those requests ever reached the air");
    Test_ExpectCount(LoopbackRadio_Refusals(&dev.model), NWK_UNICAST_RETRIES + 1,
                     "1 + nwkcUnicastRetries refusals, which is all the clause asks this frame for");
    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), 0, "the slot released with the budget spent");
    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), 1, "and the confirmation issued at the last refusal");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_NO_SPACE,
                "the seam's own word for the refusal, the status the layer beneath this one answered with");
    Test_ExpectCount(confirms[0].nwkStatus, NWK_STATUS_LAST_MAC_STATUS,
                     "beside Table 3-84's sentinel: the clause closes with 'a status equal to the last received status from the MAC sub-layer', and no code of Table 3-84's names a refusal no delay cures");
    Test_ExpectCount(confirms[0].attempts, NWK_UNICAST_RETRIES + 1, "and the attempt count names every request it took");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, (uint32_t)(NWK_UNICAST_RETRIES + 1) * NWK_UNICAST_RETRY_DELAY_MS), ZB_OK,
                      "a turn a whole delay later");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "and nothing asked after the budget was spent: a refusal retried without a bound would re-ask on every step forever");
}

/* D-243: a broadcast the door refused for room never reached the air, so it is not confirmed but held and asked again
   on the next turn; once sent, its broadcast-table record counts the passive-acknowledgment wait from that send. */
void caseRefusedBroadcastIsHeldAndSentNextTurn(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);

    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 1);

    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 0), ZB_OK, "a broadcast the module took back");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "refused before it reached the air");
    Test_ExpectCount(Nwk_PollConfirms(&dev.nwk, confirms, 4), 0, "and not confirmed: it was not sent yet");
    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), 1, "its slot held for the next ask");
    Test_ExpectCount(Mac_CountersOf(&dev.mac).transactionQueue, 0, "and no copy queued for the resting child yet");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "the next turn");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "sends it, with no retry delay to wait out");
    Test_Expect(airCount == 1 && Zb_memcmp(npduOf(&air[0]) + NWK_MIN_HEADER_OVERHEAD, nsdu, NSDU_LEN) == 0,
                "carrying the NSDU the request named");
    Test_ExpectCount(Mac_CountersOf(&dev.mac).transactionQueue, 1, "and the resting child's copy queued with it");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 2), ZB_OK, "and the turn its completion comes back on");
    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_OK && confirms[0].attempts == 2,
                "is confirmed SUCCESS, the refused request and the sent one both counted");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NWK_PASSIVE_ACK_TIMEOUT_MS), ZB_OK, "nwkPassiveAckTimeout after the refusal");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "the table has not resent it: its wait counts from the send, one turn later");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1 + NWK_PASSIVE_ACK_TIMEOUT_MS), ZB_OK, "nwkPassiveAckTimeout after the send");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 2, "and then it does, as for any broadcast no neighbour relayed (3.6.6)");
}

/* A broadcast refused for room past its hold was never sent: it is confirmed with the refusal, and its record goes, so
   the table never sends a frame confirmed unsent. */
void caseRefusedBroadcastPastItsHoldIsNeverSent(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t nowMs;
    uint32_t got = 0;

    rig(&dev, OWN_SHORT, PAN_ID);

    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 1000);

    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 0), ZB_OK, "a broadcast the door keeps refusing");

    for (nowMs = 10; nowMs < NWK_BROADCAST_HOLD_MS && got == 0; nowMs += 10)
    {
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, nowMs), ZB_OK, "a turn inside the hold");
        got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    }

    Test_ExpectCount(got, 0, "is held through its hold");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NWK_BROADCAST_HOLD_MS + 10), ZB_OK, "a turn past it");
    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_NO_SPACE, "and confirmed with the refusal");
    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), 0, "its slot freed");

    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 0);

    for (nowMs = NWK_BROADCAST_HOLD_MS + 20; nowMs <= 3 * NWK_BROADCAST_HOLD_MS + NWK_PASSIVE_ACK_TIMEOUT_MS; nowMs += 10)
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, nowMs), ZB_OK, "turns with the door open again");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "and nothing ever sends it: its broadcast-table record went with the confirm");
}

/* 3.6.4.3's no-capacity rule reaches a discovery's own route entry: a routing table with no room refuses the
   discovery rather than writing through the entry it could not claim. */
void caseFullRoutingTableRefusesDiscovery(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    for (i = 0; i < NWK_ROUTE_MAX; i++)
    {
        dev.nwk.routes[i].inUse = 1;
        dev.nwk.routes[i].destinationAddress = (uint16_t)(0x3000 + i);
        dev.nwk.routes[i].nextHopAddress = NEIGHBOR;
        dev.nwk.routes[i].status = NWK_ROUTE_ACTIVE;
    }

    Test_ExpectCount(Nwk_RouteQueue(&dev.nwk), NWK_ROUTE_MAX, "the routing table is full of routes that answer");

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, NWK_DISCOVER_ENABLE);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK,
                      "a request to a destination with no route asks for a discovery");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "nothing goes on the air: there is no entry to hold the discovery the request owes");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_ExpectCount(got, 1, "and the request is answered");
    Test_ExpectCount(confirms[0].nwkStatus, NWK_STATUS_ROUTE_ERROR,
                     "with Table 3-84's ROUTE_ERROR, 3.6.4.3's own outcome for a frame with no route and no room");
    Test_ExpectStatus(confirms[0].status, ZB_ERR_NO_ROUTE, "beside the seam's word for it");
    Test_ExpectCount(Nwk_RouteQueue(&dev.nwk), NWK_ROUTE_MAX, "the table is untouched");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 0, "and the discovery entry the attempt claimed is released");
}

/*
 * The confirmation ring's own bound, which the door's arithmetic cannot reach: eight slots held and a refusal for
 * every request that finds no room fills the ring to its last entry, and the ninth such refusal has nowhere to go.
 * 3.2.1.2.1 gives one NLDE-DATA.confirm per request and docs/internals/coding-rules.md §4.3 gives a full pool one answer,
 * refusal and count, so the answer that cannot be delivered is counted rather than written over an unread one.
 */
void caseConfirmRingCannotOverflow(void)
{
    Test_BandA dev;
    Nwk_DataRequestParameters req;
    Nwk_DataConfirmParameters confirms[NWK_CONFIRM_MAX];
    uint8_t nsdu[NSDU_LEN];
    uint32_t i;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);

    Zb_memset(nsdu, 0x5a, (uint32_t)sizeof nsdu);

    for (i = 0; i < NWK_TX_MAX; i++)
    {
        req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
        Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_OK, "eight requests the module takes back");
    }

    for (i = 0; i < NWK_CONFIRM_MAX; i++)
    {
        req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
        Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_ERR_NO_SPACE,
                      "and every request behind them is refused by the pool");
    }

    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), NWK_CONFIRM_MAX,
                     "so the ring fills to its own bound and not past it: eight slots held and eight refusals is the most this module can owe at once");
    Test_ExpectCount(Nwk_ConfirmsDropped(&dev.nwk), 0,
                     "and nothing was dropped yet, because the door's own test stops writing once the ring is full");

    got = Nwk_PollConfirms(&dev.nwk, confirms, NWK_CONFIRM_MAX);
    Test_ExpectCount(got, NWK_CONFIRM_MAX, "the ring hands back exactly the answers it holds");
    Test_Expect(got == NWK_CONFIRM_MAX && Nwk_ConfirmQueue(&dev.nwk) == 0, "and nothing is left behind");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 11), ZB_OK, "a turn in which every slot's frame goes unanswered");

    Test_Expect(Nwk_ConfirmsDropped(&dev.nwk) == 0 || Nwk_ConfirmQueue(&dev.nwk) <= NWK_CONFIRM_MAX,
                "and whatever the turn confirms, the ring never reports more answers than it can hold: the count a caller polls is bounded by the pool it reads");
    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk) <= NWK_CONFIRM_MAX, 1,
                     "which is the invariant this case pins: no write to the ring without a place in it");
}

/*
 * 3.2.1.1.1 with Table 3-2: an aliased request carries the alias source address and the alias sequence number it
 * names, and neither of this device's own is written or spent.
 */
void caseAliasedRequestWritesTheAlias(void)
{
    Test_BandA dev;
    Nwk_DataRequestParameters req;
    Air air[AIR_LOG_MAX];
    uint8_t nsdu[NSDU_LEN];
    uint32_t airCount = 0;
    uint32_t seqBefore;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    Zb_memset(nsdu, 0x66, (uint32_t)sizeof nsdu);

    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    req.useAlias = 1;
    req.aliasSrcAddr = HOP;
    req.aliasSeqNumb = 0x77;

    seqBefore = dev.nwk.seq;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 10), ZB_OK, "an aliased request is taken");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "and one frame went out");

    if (airCount == 0)
        return;

    Test_Expect(npduOf(&air[0])[NPDU_SEQ_OCTET] == 0x77,
                "carrying the alias sequence number, which Table 3-2 makes one of the two rows UseAlias selects");
    Test_Expect((uint32_t)(npduOf(&air[0])[4] | (npduOf(&air[0])[5] << 8)) == HOP,
                "and the alias source address rather than this device's own, in Figure 3-5's source field");
    Test_ExpectCount(dev.nwk.seq, seqBefore,
                     "with the device's own sequence number unspent, which is what an alias means");
}

/*
 * 3.3.1.1.8's transmit half: an end device whose NIB's nwkParentInformation is non-zero sets the End Device
 * Initiator bit on the frames it sends, and a device with the field at 0 does not.
 */

/*
 * 3.3.1.1.8's transmit half: an end device whose NIB field `nwkParentInformation` is non-zero sets the End Device
 * Initiator bit on what it sends, and one whose field is 0 does not. 3.2.2.13 clears the field at every join and
 * rejoin, which the second half pins.
 */
void caseEndDeviceInitiatorSet(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    uint8_t nsdu[NSDU_LEN];
    uint32_t airCount = 0;

    Zb_memset(nsdu, 0x5a, (uint32_t)sizeof nsdu);

    rig(&dev, OWN_SHORT, PAN_ID);
    dev.nwk.cfg.deviceType = NWK_DEVICE_END_DEVICE;
    dev.nwk.cfg.parentInformation = 1;
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_PARENT);

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK,
                      "an end device with nwkParentInformation non-zero sends its own frame");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1, "one frame reached the backend");
    Test_Expect((nwkFcfOf(npduOf(&air[0])) & NWK_FCF_END_DEVICE) != 0,
                "and it carries the End Device Initiator bit, which is what a parent needs to know its child sent it");

    dev.nwk.cfg.parentInformation = 0;

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 200), ZB_OK, "the same device with the field back at 0");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect((nwkFcfOf(npduOf(&air[1])) & NWK_FCF_END_DEVICE) == 0,
                "sets no bit: the clause makes it the field's value that decides");
}

/* 3.6.4.8.1's last rule: an end device whose frame to its parent ran out of attempts tells the layer above with
   0x09, naming the parent; a router whose frame to a neighbour failed the same way raises no such status. */
static uint32_t parentLinkFailuresAfterNoAck(uint32_t deviceType, uint32_t relationship, Nwk_NwkStatusIndication *out)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    uint8_t nsdu[NSDU_LEN];
    uint32_t airCount = 0;
    uint32_t now;

    Zb_memset(nsdu, 0x5a, (uint32_t)sizeof nsdu);

    rig(&dev, OWN_SHORT, PAN_ID);
    dev.nwk.cfg.deviceType = deviceType;
    dev.nwk.joinParentShort = NEIGHBOR;
    dev.nwk.joinParentShortKnown = 1;
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, relationship);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 0);

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 0), ZB_OK, "a unicast to the neighbour goes out");

    for (now = 1; now <= 300; now++)
    {
        (void)Test_NwkStep(&dev.nwk, now);
        harvestAir(&dev.model, air, &airCount);
    }

    Test_Expect(airCount == 1 + NWK_UNICAST_RETRIES, "and every attempt it was owed was answered NO_ACK");
    Test_ExpectCount(Nwk_ParentLinkFailures(&dev.nwk), Nwk_PollStatusIndications(&dev.nwk, out, 2),
                     "and the counter names every indication raised");

    return Nwk_ParentLinkFailures(&dev.nwk);
}

void caseParentLinkFailure(void)
{
    Nwk_NwkStatusIndication inds[2];

    Zb_memset(inds, 0, (uint32_t)sizeof inds);

    Test_ExpectCount(parentLinkFailuresAfterNoAck(NWK_DEVICE_END_DEVICE, NWK_REL_PARENT, inds), 1,
                     "an end device whose frame to its parent failed raises one indication");
    Test_Expect(inds[0].status == NWK_STATUS_CODE_PARENT_LINK_FAILURE && inds[0].shortAddr == NEIGHBOR,
                "0x09, Parent Link Failure, naming the parent (3.6.4.8.1)");

    Test_ExpectCount(parentLinkFailuresAfterNoAck(NWK_DEVICE_ROUTER, NWK_REL_SIBLING, inds), 0,
                     "and a router whose frame to a neighbour failed raises none: the status is an end device's");
}

/* A unicast to a child whose receiver rests is held for the poll that can extract it, and is confirmed when that
   happens; the same request to a child that listens goes out at once. */
void caseUnicastToASleepyChildIsHeld(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(SLEEPY, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK, "a unicast to a sleeping child");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 0, "puts nothing on the air");
    Test_ExpectCount(Mac_IndirectHeldFor(&dev.mac, SLEEPY), 1, "and is held for the child's poll");
    Test_ExpectCount(Nwk_PollConfirms(&dev.nwk, confirms, 4), 0, "with no answer yet, since nothing has been tried");
    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), 1, "its slot still owed");

    composePoll(&dev.model, 7, SLEEPY);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "the child polls");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1 && airDestOf(&air[0]) == SLEEPY && air[0].ackRequest == 1,
                "and the frame goes out to it, acknowledgement requested");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 102), ZB_OK, "the turn after the extraction answers for it");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_OK && confirms[0].dstAddr == SLEEPY
                && confirms[0].attempts == 1, "one SUCCESS for the child, after one attempt");
    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), 0, "and the slot is free");

    req = nldeReq(NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 200), ZB_OK, "a unicast to a child that listens");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 2 && airDestOf(&air[1]) == NEIGHBOR, "goes out at once");
    Test_ExpectCount(Mac_IndirectHeldFor(&dev.mac, NEIGHBOR), 0, "and is held for nobody");

    seedNeighbor(&dev.nwk, ROUTER_NEIGHBOR, NWK_DEVICE_END_DEVICE, 0, NWK_REL_SIBLING);
    req = nldeReq(ROUTER_NEIGHBOR, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 300), ZB_OK, "a unicast to a resting device that is no child of this one");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 3 && airDestOf(&air[2]) == ROUTER_NEIGHBOR, "is not held, since this device has no poll to wait for");

    seedNeighbor(&dev.nwk, SLEEPY2, NWK_DEVICE_END_DEVICE, 0, NWK_REL_UNAUTHENTICATED_CHILD);
    req = nldeReq(SLEEPY2, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 400), ZB_OK, "a unicast to a resting child not yet authenticated");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 3 && Mac_IndirectHeldFor(&dev.mac, SLEEPY2) == 1, "is held for its poll as well");
}

/* 3.2.1.1.3 retries a request the MAC refused for want of room in its transaction queue, so a full queue holds the
   request back for its retry instead of failing it. */
void caseHeldUnicastQueueFull(void)
{
    Test_BandA dev;
    Mac_DataRequestParameters held;
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    Zb_memset(&held, 0, (uint32_t)sizeof held);
    held.frameType = MAC_FRAME_TYPE_DATA;
    held.destAddrMode = MAC_ADDR_SHORT;
    held.srcAddrMode = MAC_ADDR_SHORT;
    held.destPan = PAN_ID;
    held.destShort = NEIGHBOR;
    held.ackRequest = 1;
    held.payload = nsdu;
    held.payloadLen = NSDU_LEN;

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
        Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &held, 50), ZB_OK, "the MAC's queue is filled");

    req = nldeReq(SLEEPY, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK, "a unicast to a sleeping child finds it full");
    Test_ExpectCount(Nwk_PollConfirms(&dev.nwk, confirms, 4), 0, "and is not failed for it");
    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), 1, "but kept for the retry");
}

/* A frame held for a child that never polls is discarded by the MAC when its persistence runs out, and the
   request is answered with that failure rather than left owed. */
void caseHeldUnicastExpires(void)
{
    Test_BandA dev;
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(SLEEPY, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK, "a unicast to a sleeping child");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + MAC_TRANSACTION_PERSISTENCE_MS / 2), ZB_OK, "is still held half way");
    Test_ExpectCount(Nwk_PollConfirms(&dev.nwk, confirms, 4), 0, "and not yet answered");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + MAC_TRANSACTION_PERSISTENCE_MS + 1000), ZB_OK,
                      "a turn after its persistence ran out");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_TRANSACTION_EXPIRED
                && confirms[0].nwkStatus == NWK_STATUS_LAST_MAC_STATUS && confirms[0].dstAddr == SLEEPY,
                "answers the request with the MAC's TRANSACTION_EXPIRED");
    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), 0, "and the slot is free");
    Test_ExpectCount(Mac_IndirectHeldFor(&dev.mac, SLEEPY), 0, "with nothing left held");
}

/* A held frame whose extraction was not acknowledged is still held: the MAC keeps the transaction for the child's next
   poll, so the request is neither retried (a second copy) nor answered, and the next poll that is acknowledged
   completes it once. */
void caseHeldUnicastSurvivesALostExtraction(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Loopback_Outcome outcomes[2];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);

    Zb_memset(outcomes, 0, (uint32_t)sizeof outcomes);
    outcomes[0].status = ZB_ERR_DEVICE;
    outcomes[1].status = ZB_OK;
    outcomes[1].isAcked = 1;
    LoopbackRadio_ScriptOutcomes(&dev.model, outcomes, 2);

    req = nldeReq(SLEEPY, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK, "a unicast to a sleeping child");

    composePoll(&dev.model, 7, SLEEPY);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "the child polls and the extraction goes unacknowledged");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 151), ZB_OK, "and the turn after it hears so");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 251), ZB_OK, "a retry's delay later");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "nothing but the one extraction has gone out");
    Test_ExpectCount(Mac_IndirectHeldFor(&dev.mac, SLEEPY), 1, "and the MAC holds the frame once, not twice");
    Test_ExpectCount(Nwk_PollConfirms(&dev.nwk, confirms, 4), 0, "with the request still unanswered");
    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), 1, "and its slot owed");

    composePoll(&dev.model, 8, SLEEPY);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 301), ZB_OK, "the child polls again");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 351), ZB_OK, "and this extraction is acknowledged");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_OK && confirms[0].dstAddr == SLEEPY, "one SUCCESS answers the request");
    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), 0, "and frees its slot");
    Test_ExpectCount(Mac_IndirectHeldFor(&dev.mac, SLEEPY), 0, "with nothing left held");
}
