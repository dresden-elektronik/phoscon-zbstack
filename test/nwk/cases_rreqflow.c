/* 3.6.4.5.1's reception as the façade runs it: the dispatch that sits ahead of the broadcast transaction table,
   3.6.4.5.1.1's reply, 3.6.4.5.1.2's and 3.6.4.5.1.4's relay with its jittered schedule, and the five drops the
   clause prints, each counted where it is taken. Every number a case asserts is one a clause or a table prints,
   and each case names the branch it reddens if the branch is taken differently. The rig is the shared band-A
   device in `nwk_helpers.c`; the request is composed by `nwk_rreq`'s own codec, so nothing here hand-writes an
   octet it can compute. */

#include "nwk_routeflow_cases.h"

#include "loopback_radio.h"
#include "mac.h"
#include "nwk.h"
#include "nwk_discovery.h"
#include "nwk_frame.h"
#include "nwk_helpers.h"
#include "nwk_route.h"
#include "nwk_routeflow_helpers.h"
#include "nwk_rrep.h"
#include "nwk_rreq.h"
#include "nwk_rreqrelay.h"
#include "nwk_rreqtx.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

enum
{
    /* 3.4.1.3's field order inside a route request payload, and 3.4.2.3's inside a route reply */
    /* 3.4.1.2 makes every Route Request carry the originator's source IEEE address, so the payload starts
       one IEEE field past the minimal header: 8 + 8 octets */
    RREQ_PAYLOAD_OFFSET = NWK_MIN_HEADER_OVERHEAD + NWK_IEEE_ADDR_OCTETS,
    RREQ_REQUEST_ID = 2,
    RREQ_DESTINATION = 3,
    RREQ_PATH_COST = 5,
    RREQ_TLV_ROUTING_SEQUENCE = 8,
    RREQ_TLV_INITIAL_RADIUS = 10,

    RREP_REQUEST_ID = 2,
    RREP_ORIGINATOR = 3,
    RREP_RESPONDER = 5,
    RREP_PATH_COST = 7,
    RREP_ORIGINATOR_IEEE = 8,
    RREP_RESPONDER_IEEE = 16,

    REQUEST_ID = 0x31,              /* 3.4.1.3.2's request id, the same in every request a case of this file sends */
    RELAY_SEQ = 0x40,               /* the sequence number the received request's header carries (3.3.1.5) */
    FORWARDER_LQA = 200,            /* Table 3-76: 192 < 200 <= 255, so the measured direction costs 1 */
    FORWARDER_OUTGOING_COST = 2,    /* Table 3-75's Outgoing Cost: the worse direction, so the hop costs 2 */
    HELD_PATH_COST = 2,             /* the first copy's path cost, so Table 3-79 records 4 for it */
    GREATER_PATH_COST = 5,          /* 9137: 5 plus the hop's 2 is greater than the recorded forward cost of 4 */
    LOWER_PATH_COST = 0,            /* a cheaper arrival: 0 plus the hop's 2 is less than 4 */
    CONCENTRATOR_DISCOVERY_TIME = 0x10, /* nwkConcentratorDiscoveryTime, Figure K-2's first value octet */
    INTEREST_LOW = 0x1234,          /* K.2.1.3's first nwkAddressOfInterest */
    INTEREST_HIGH = 0x5678,         /* and its second */
    NOW_MS = 1000,                  /* the clock the reception arrives at */
    JITTER_SEED = 0x1234            /* 3.6.4.5.1.4's draw needs a seed; 0 would draw nothing */
};

/* The request a neighbor sends: Figure 3-9's payload from this stack's own codec, in a header 3.4.1.2
   describes (`headerDest` 0xfffc for the broadcast a discovery is, or the device address of 3.6.4.5.1.2's
   unicast form) with a radius of 30 and a sequence number the case names. */
static uint32_t composeReceivedRreq(uint8_t *npdu, uint16_t headerDest, uint16_t sourceAddr, uint16_t destAddr,
                                    uint8_t pathCost)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestPayload request;
    uint32_t payloadLen;
    uint32_t routingSeq;

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.requestId = REQUEST_ID;
    request.destAddr = destAddr;
    request.pathCost = pathCost;
    request.manyToOne = NWK_RREQ_MANY_TO_ONE_NONE;
    request.maxSourceRoute = NWK_MAX_SOURCE_ROUTE;

    routingSeq = 0x1234;

    Test_ExpectStatus(Nwk_RreqCompose(&request, &routingSeq, NWK_INITIAL_RADIUS, payload,
                                      (uint32_t)sizeof payload, &payloadLen), ZB_OK,
                      "the request a case injects is a payload this stack's own codec composes");

    return makeNpdu(npdu, headerDest, sourceAddr, NWK_INITIAL_RADIUS, RELAY_SEQ, NWK_FRAME_TYPE_COMMAND,
                    0, payload, payloadLen);
}

/* A many-to-one request with both of Annex K.2's optional records: Figure K-1's, Figure K-2's, and K.2.1.3's
   solicitation list appended behind them exactly as a concentrator writes them (Table I-1's tag, length, value). */
static uint32_t composeManyToOneRreq(uint8_t *npdu, uint16_t sourceAddr)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX + 6];
    Nwk_RouteRequestPayload request;
    uint32_t payloadLen;
    uint32_t routingSeq;

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.requestId = REQUEST_ID;
    request.destAddr = NWK_ADDR_ROUTERS;
    request.pathCost = 0;
    request.manyToOne = NWK_RREQ_MANY_TO_ONE_WITH_RECORD;
    request.concentrator = 1;
    request.concentratorDiscoveryTime = CONCENTRATOR_DISCOVERY_TIME;
    request.maxSourceRoute = NWK_MAX_SOURCE_ROUTE;

    routingSeq = 0x1234;

    Test_ExpectStatus(Nwk_RreqCompose(&request, &routingSeq, NWK_INITIAL_RADIUS, payload,
                                      (uint32_t)sizeof payload, &payloadLen), ZB_OK,
                      "the many-to-one request a case injects is a payload this stack's own codec composes");

    payload[payloadLen++] = NWK_TLV_TAG_SOURCE_ROUTE_SOLICITATION;      /* K.2.1.3 */
    payload[payloadLen++] = 3;                                         /* four value octets, the field less one */
    payload[payloadLen++] = (uint8_t)(INTEREST_LOW & 0xff);
    payload[payloadLen++] = (uint8_t)(INTEREST_LOW >> 8);
    payload[payloadLen++] = (uint8_t)(INTEREST_HIGH & 0xff);
    payload[payloadLen++] = (uint8_t)(INTEREST_HIGH >> 8);

    return makeNpdu(npdu, NWK_ADDR_ROUTERS, sourceAddr, NWK_INITIAL_RADIUS, RELAY_SEQ, NWK_FRAME_TYPE_COMMAND,
                    0, payload, payloadLen);
}

/* A neighbor that is not the request's initiator, with the two Table 3-75 cost fields a link status exchange
   would fill: the measured direction is the carrier's LQA, the outgoing one is the worse. */
static void seedForwarder(Nwk_Nwk *nwk, uint16_t addr)
{
    Nwk_NeighborTableEntry *forwarder;

    seedNeighbor(nwk, addr, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    forwarder = neighborAt(nwk, addr);

    Test_Expect(forwarder != 0, "the neighbor table holds the forwarding device");

    if (forwarder == 0)
        return;

    forwarder->lqi = FORWARDER_LQA;
    forwarder->outgoingCost = FORWARDER_OUTGOING_COST;
}

/*
 * 3.6.4.5.1.1 and 3.6.4.5.1.5: a request that names this device is answered, once, to the address Table 3-79
 * holds as its sender, and the reply's path cost is that one hop's link cost. The assertions are the reply's own
 * octets and the MAC destination of the frame that carried it: not the request's struct.
 */
void caseRreqAnsweredAtTheDestination(void)
{
    static const uint8_t initiatorIeee[RADIO_ADDR_LEN] = { 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    Nwk_Frame header;
    Nwk_RouteReplyFields reply;
    Nwk_NeighborTableEntry *initiator;
    Nwk_RouteDiscoveryTableEntry *entry;
    Radio_Pib pib;
    const uint8_t *payload;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t payloadOffset;
    uint32_t payloadLen;
    uint32_t airCount = 0;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    initiator = neighborAt(&dev.nwk, NEIGHBOR);

    Test_Expect(initiator != 0, "the initiator has a neighbor entry, so 3.4.2.3.6 has its address to read");

    if (initiator == 0)
        return;

    initiator->extendedAddress = (uint64_t)NEIGHBOR;
    initiator->ieeeKnown = 1;
    initiator->outgoingCost = 1;

    /* The operational extended address the backend took: 3.4.2.3.7 is a field this device can only get here */
    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_EXTENDED_ADDRESS;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        pib.extendedAddress[i] = (uint8_t)(0xf0 + i);

    Test_ExpectStatus(Mac_SetPib(&dev.mac, &pib), ZB_OK, "and this device's own extended address is written");

    npduLen = composeReceivedRreq(npdu, NWK_ADDR_ROUTERS, NEIGHBOR, OWN_SHORT, 0);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS), ZB_OK, "the turn 3.4.1.3.3's destination names this device");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "exactly one frame leaves: 3.6.4.5.1.1's reply, and no relay");
    Test_ExpectCount(Nwk_RouteRepliesSent(&dev.nwk), 1, "counted once, against the request it answered");
    Test_ExpectCount(airDestOf(&air[0]), NEIGHBOR,
                     "9200-9201: the MAC destination is the address Table 3-79 holds as the request's sender");
    Test_Expect(air[0].ackRequest == 1,
                "3.4.3.1 forbids the acknowledgment ask only where the destination MAC address is 0xffff, and this is a unicast");

    Test_ExpectStatus(NwkFrame_Parse(npduOf(&air[0]), npduLenOf(&air[0]), &header, &payloadOffset, &payloadLen),
                      ZB_OK, "and the frame is one this module's own codec reads back");

    Test_Expect(header.frameType == NWK_FRAME_TYPE_COMMAND && header.srcAddr == OWN_SHORT
                && header.destAddr == NEIGHBOR,
                "a command frame of this device's, aimed at the sender 3.6.4.5.1.5 names");
    Test_ExpectCount(header.radius, NWK_RREP_RADIUS, "3.4.2.2: the target of a request sets the radius to nwkcMaxDepth x 2");

    payload = npduOf(&air[0]) + payloadOffset;

    Test_ExpectStatus(Nwk_RrepParse(payload, payloadLen, &reply), ZB_OK,
                      "and its payload is Figure 3-11's, read by this stack's own parser");

    Test_ExpectCount((uint32_t)payload[0], NWK_CMD_ROUTE_REPLY, "Table 3-54: payload octet zero is 0x02");
    Test_ExpectCount(payload[RREP_REQUEST_ID], REQUEST_ID, "3.4.2.3.2: the request's identifier, copied");
    Test_ExpectCount((uint32_t)(payload[RREP_ORIGINATOR] | (payload[RREP_ORIGINATOR + 1] << 8)), NEIGHBOR,
                     "3.4.2.3.3: the originator is the source address of the request's NWK header");
    Test_ExpectCount((uint32_t)(payload[RREP_RESPONDER] | (payload[RREP_RESPONDER + 1] << 8)), OWN_SHORT,
                     "3.4.2.3.4: the responder is the device that composed the reply, this one");
    Test_ExpectCount(payload[RREP_PATH_COST], 1,
                     "3.4.2.3.5 with 9104-9105: the link cost of that one hop, Table 3-76's level for the LQA the carrier carried, and never the request's path cost");
    Test_Expect(Zb_memcmp(payload + RREP_ORIGINATOR_IEEE, initiatorIeee, RADIO_ADDR_LEN) == 0,
                "3.4.2.3.6: the initiator's IEEE address, the one the neighbor table holds for it");
    Test_Expect(Zb_memcmp(payload + RREP_RESPONDER_IEEE, pib.extendedAddress, RADIO_ADDR_LEN) == 0,
                "3.4.2.3.7: this device's own, the octets the PIB carries, least significant first");
    Test_ExpectCount(reply.routingSequenceNumber, 1,
                     "K.3.1.1.1: the Extended Route Information TLV carries nwkRoutingSequenceNumber after its increment, and this is the first");
    Test_ExpectCount(dev.nwk.routingSequenceNumber, 1, "and NIB 0xBE holds the value the TLV carries");

    entry = Nwk_DiscoveryOf(dev.nwk.discoveries, NEIGHBOR, REQUEST_ID);

    Test_ExpectCount(entry ? entry->senderAddress : 0, NEIGHBOR, "Table 3-79's Sender address is the hop the reply went to");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 0,
                     "and the request is not indicated upward: 3.6.4.5.1 is a procedure of this layer");
    Test_ExpectCount(Nwk_BttQueue(&dev.nwk), 0, "and it claims no Table 3-81 record, which is not what judges it");
}

/*
 * 3.6.4.5.1.2 and 3.6.4.5.1.4: a request that names somebody else is relayed as the frame it arrived as,
 * with the forward cost in its path cost field and its radius already spent once. The originator's source
 * address, sequence number and End Device Initiator bit do not move: 3.3.1.5 numbers a new frame, and this
 * retransmission is 3.6.6's copy of the one received.
 */
void caseRreqRelayedWithTheForwardCost(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    Nwk_Frame header;
    Nwk_Frame received;
    Nwk_RouteRequestFields relayed;
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_RoutingTableEntry *reverse;
    const uint8_t *payload;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t payloadOffset;
    uint32_t payloadLen;
    uint32_t airCount = 0;
    uint32_t jitterState;
    uint32_t jitter;
    uint32_t firstMs;

    rigAtSeed(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1, 0, JITTER_SEED);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);
    seedForwarder(&dev.nwk, NEIGHBOR);
    seedNeighbor(&dev.nwk, HOP, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);

    npduLen = composeReceivedRreq(npdu, NWK_ADDR_ROUTERS, HOP, UNSEEN, HELD_PATH_COST);
    npdu[1] = (uint8_t)(npdu[1] | (NWK_FCF_END_DEVICE >> 8));   /* 3.3.1.1.8: the originator is an end device */

    Test_ExpectStatus(NwkFrame_Parse(npdu, npduLen, &received, &payloadOffset, &payloadLen), ZB_OK,
                      "the injected request is one this stack reads, with its End Device Initiator bit set");

    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    jitterState = dev.nwk.jitterState;
    jitter = Nwk_RreqRelayJitterMs(&jitterState, JITTER_SEED);
    firstMs = NOW_MS + jitter;

    Test_Expect(jitter >= NWK_MIN_RREQ_RELAY_MS && jitter <= NWK_MAX_RREQ_RELAY_MS,
                "3.6.4.5.1.4: the wait is 2 x R[nwkcMinRREQJitter, nwkcMaxRREQJitter], a closed 4-256 ms");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS), ZB_OK, "the turn the request arrives on");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 0, "and nothing goes out on it: 3.6.4.5.1.4 delays the relay by its jitter");

    reverse = Nwk_RouteOf(dev.nwk.routes, HOP);
    entry = Nwk_DiscoveryOf(dev.nwk.discoveries, HOP, REQUEST_ID);

    Test_Expect(reverse != 0 && reverse->nextHopAddress == NEIGHBOR,
                "9125-9142: the routing table gains a reverse route to the request's source through the device that sent it");
    Test_ExpectCount(entry ? entry->forwardCost : 0, HELD_PATH_COST + FORWARDER_OUTGOING_COST,
                     "9128-9129: the forward cost is the request's path cost plus the link cost of the hop, whose worse direction is the outgoing cost of 2");
    Test_Expect(entry != 0 && entry->destAddr == UNSEEN,
                "and the entry names the request's destination, which the expiry keys on when it decides whether the routing entry it stands for is still needed (3.6.4.5.1.7)");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, firstMs - 1), ZB_OK, "a turn one millisecond before the jitter's instant");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 0, "and the relay is not on the air: not before the draw, whatever the draw is");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, firstMs), ZB_OK, "the turn the jitter's instant falls on");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "and the relay goes out, at that instant and not earlier");
    Test_ExpectCount(Nwk_RouteRequestsSent(&dev.nwk), 1, "counted as the Route Request it is");

    Test_ExpectStatus(NwkFrame_Parse(npduOf(&air[0]), npduLenOf(&air[0]), &header, &payloadOffset, &payloadLen),
                      ZB_OK, "the relayed copy is a frame this stack composes");
    Test_ExpectCount(header.srcAddr, HOP,
                     "3.4.1.2 with 3.3.1.3: the source address is the originator's, not the relaying device's");
    Test_ExpectCount(header.sequenceNumber, RELAY_SEQ,
                     "3.3.1.5: the sequence number is the one the frame arrived with, not a fresh one");
    Test_Expect(header.endDeviceInitiator == 1,
                "3.3.1.1.8: the End Device Initiator bit travels as received; this device is not the child's parent");
    Test_ExpectCount(header.destAddr, NWK_ADDR_ROUTERS, "3.4.1.2: the destination field is the received one");
    Test_ExpectCount(header.radius, NWK_INITIAL_RADIUS - 1,
                     "3.3.1.4: the radius as received, whose decrement this device already paid");
    Test_ExpectCount(airDestOf(&air[0]), MAC_FRAME_ADDR_BROADCAST,
                     "3.2.1.1.3 step 6 a.3: a NWK broadcast leaves with the MAC's 0xFFFF");

    Test_ExpectCount(npduDiffCount(npdu, npduLen, npduOf(&air[0]), npduLenOf(&air[0])), 2,
                     "exactly two octets of the received frame differ: the decremented radius and the rewritten path cost");
    Test_ExpectCount(npduOf(&air[0])[NPDU_RADIUS_OCTET], (uint8_t)(npdu[NPDU_RADIUS_OCTET] - 1),
                     "and the radius octet is one of them");
    Test_ExpectCount(npduOf(&air[0])[NPDU_SEQ_OCTET], npdu[NPDU_SEQ_OCTET],
                     "while the sequence octet is not");

    payload = npduOf(&air[0]) + payloadOffset;

    Test_ExpectStatus(Nwk_RreqParse(payload, payloadLen, &relayed), ZB_OK,
                      "with Figure 3-9's payload, read back by this stack's own parser");
    Test_ExpectCount(payload[0], NWK_CMD_ROUTE_REQUEST, "Table 3-54: still a Route Request");
    Test_Expect(payload[RREQ_REQUEST_ID] == REQUEST_ID, "3.4.1.3.2: the identifier is the originator's, unchanged");
    Test_Expect((uint32_t)(payload[RREQ_DESTINATION] | (payload[RREQ_DESTINATION + 1] << 8)) == UNSEEN,
                "3.4.1.3.3: and so is the destination it is looking for");
    Test_ExpectCount(payload[RREQ_PATH_COST], HELD_PATH_COST + FORWARDER_OUTGOING_COST,
                     "3.4.1.3.4 with 9109-9110: the forward cost, which is what a relay rewrites and what the received 0 was not");
    Test_ExpectCount((uint32_t)(payload[RREQ_TLV_ROUTING_SEQUENCE]
                                | (payload[RREQ_TLV_ROUTING_SEQUENCE + 1] << 8)), 0x1235,
                     "K.2.1.1.1: the originator's routing sequence number, forwarded unmodified");
    Test_ExpectCount(payload[RREQ_TLV_INITIAL_RADIUS], NWK_INITIAL_RADIUS,
                     "K.2.1.1.2: and the first instance's radius, likewise");
    Test_ExpectCount(dev.nwk.routingSequenceNumber, 0,
                     "K.2.1.1.1's number is the originator's: forwarding a request does not move this device's counter");
    Test_ExpectCount(dev.nwk.seq, 0,
                     "3.3.1.5: a relayed request does not spend this device's sequence number either");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, firstMs + NWK_RREQ_RETRY_INTERVAL_MS - 1), ZB_OK,
                      "a turn one millisecond before nwkcRREQRetryInterval has passed");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "and the retry is not owed yet");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, firstMs + NWK_RREQ_RETRY_INTERVAL_MS), ZB_OK,
                      "the turn nwkcRREQRetryInterval falls on");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, firstMs + 2 * NWK_RREQ_RETRY_INTERVAL_MS), ZB_OK,
                      "and the one after the second interval, which is 3.6.4.5.1.4's last of three");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, Nwk_RreqRelayCount(),
                     "3.6.4.5.1.4: nwkcRREQRetries + 1 relays per relay attempt, so three frames in all");
    Test_ExpectCount(npduDiffCount(npduOf(&air[0]), npduLenOf(&air[0]), npduOf(&air[1]), npduLenOf(&air[1])), 0,
                     "the relay and its retry are the same frame: one stored set of octets, repeated");
    Test_ExpectCount(npduDiffCount(npduOf(&air[0]), npduLenOf(&air[0]), npduOf(&air[2]), npduLenOf(&air[2])), 0,
                     "and the third with them, down to the originator's sequence number they share");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, firstMs + 3 * NWK_RREQ_RETRY_INTERVAL_MS), ZB_OK,
                      "and a turn past the last retry");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, Nwk_RreqRelayCount(), "puts nothing further on the air: the schedule is spent");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 0,
                     "and no copy of the request was handed upward: a relayed request is a command this layer consumed");
    Test_ExpectCount(Nwk_DroppedDuplicate(&dev.nwk), 0,
                     "Table 3-81's duplicate test never saw it: 3.6.4.5.1's dedup is Table 3-79's forward cost");
}

/*
 * 3.6.4.5.1.2's dedup, on the pair Table 3-81 cannot see: a second copy of one request judged by its forward
 * cost, so the cheaper arrival is taken and the recorded sender replaced. The higher copy is 9137's drop.
 */
void caseRreqSecondCopyJudgedOnTheForwardCost(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_Frame header;
    Nwk_RouteDiscoveryTableEntry *entry;
    const uint8_t *payload;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t payloadOffset;
    uint32_t payloadLen;
    uint32_t airCount = 0;

    rigAtSeed(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1, 0, JITTER_SEED);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);
    seedForwarder(&dev.nwk, NEIGHBOR);
    seedForwarder(&dev.nwk, ROUTER_NEIGHBOR);

    npduLen = composeReceivedRreq(npdu, NWK_ADDR_ROUTERS, HOP, UNSEEN, HELD_PATH_COST);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS), ZB_OK, "the first copy of one request, through the cheaper hop");
    harvestAir(&dev.model, air, &airCount);

    entry = Nwk_DiscoveryOf(dev.nwk.discoveries, HOP, REQUEST_ID);

    Test_ExpectCount(entry ? entry->forwardCost : 0, HELD_PATH_COST + FORWARDER_OUTGOING_COST,
                     "Table 3-79 records the forward cost the first copy computed");
    Test_ExpectCount(entry ? entry->senderAddress : 0, NEIGHBOR, "and the sender it came from");

    npduLen = composeReceivedRreq(npdu, NWK_ADDR_ROUTERS, HOP, UNSEEN, GREATER_PATH_COST);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS + 1), ZB_OK,
                      "and a second copy of the same request, with a greater path cost");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_RreqDroppedGreaterCost(&dev.nwk), 1,
                     "9137-9138: the greater forward cost drops the frame and terminates route request processing");
    Test_ExpectCount(airCount, 0, "so nothing is relayed for it and the schedule the first copy armed is untouched");
    Test_ExpectCount(entry ? entry->forwardCost : 0, HELD_PATH_COST + FORWARDER_OUTGOING_COST,
                     "the recorded forward cost stands");
    Test_ExpectCount(entry ? entry->senderAddress : 0, NEIGHBOR, "and so does the recorded sender");

    npduLen = composeReceivedRreq(npdu, NWK_ADDR_ROUTERS, HOP, UNSEEN, LOWER_PATH_COST);
    injectNpdu(&dev, npdu, npduLen, ROUTER_NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS + 2), ZB_OK, "and a third with a lower one");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_RreqDroppedGreaterCost(&dev.nwk), 1, "which 9137 does not drop: a drop count that stayed put");
    Test_ExpectCount(entry ? entry->senderAddress : 0, ROUTER_NEIGHBOR,
                     "9140-9141: the sender address is updated with the cheaper arrival's device");
    Test_ExpectCount(entry ? entry->forwardCost : 0, LOWER_PATH_COST + FORWARDER_OUTGOING_COST,
                     "and so is the forward cost");

    Test_ExpectCount(airCount, 0, "and neither copy is on the air yet, each relay being jittered");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS + NWK_MAX_RREQ_RELAY_MS + 2), ZB_OK,
                      "a turn past the longest wait 3.6.4.5.1.4 allows");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1,
                     "and exactly one frame: the cheaper copy's schedule replaced the one the first copy armed, rather than joining it");

    Test_ExpectStatus(NwkFrame_Parse(npduOf(&air[0]), npduLenOf(&air[0]), &header, &payloadOffset, &payloadLen),
                      ZB_OK, "and the relayed copy is a frame this stack reads");
    payload = npduOf(&air[0]) + payloadOffset;

    Test_ExpectCount(payload[RREQ_PATH_COST], LOWER_PATH_COST + FORWARDER_OUTGOING_COST,
                     "with the cheaper forward cost in its path cost field");
    Test_ExpectCount(Nwk_DroppedDuplicate(&dev.nwk), 0,
                     "and Table 3-81's duplicate counter is untouched: neither copy was ever judged by it");
    Test_ExpectCount(Nwk_BttQueue(&dev.nwk), 0, "no broadcast record was claimed for either of them");
}

/* 9090 and its count: an end device drops every Route Request it receives, whatever the request names. */
void caseRreqDroppedAtAnEndDevice(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_END_DEVICE, 1);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);
    seedForwarder(&dev.nwk, NEIGHBOR);

    /* 0xfffc corresponds to no end device (Table 3-80) and is refused a class earlier, so the shape a request
       reaches an end device in is 3.6.4.5.1.2's unicast one, addressed to it. */
    npduLen = composeReceivedRreq(npdu, OWN_SHORT, HOP, OWN_SHORT, 0);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS), ZB_OK, "a Route Request received at an end device");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_RreqDroppedEndDevice(&dev.nwk), 1, "3.6.4.5.1, 9090: an end device SHALL drop the frame, and the counter says so");
    Test_ExpectCount(airCount, 0, "so nothing is relayed");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 0, "and nothing is indicated upward");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 0, "and Table 3-79 takes no entry: the drop is the clause's first act");
    Test_ExpectCount(Nwk_RouteQueue(&dev.nwk), 0, "and no reverse route is made");
}

/* 9120 and 9121: no neighbor entry for the transmitting device, which takes a full table since the frame is observed
   first (8166-8167), and an entry whose outgoing cost is 0, which is any device no link status has named this one. */
void caseRreqDroppedWithoutANeighbourOrAUsableCost(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    Nwk_NeighborTableEntry *hop;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
        seedNeighbor(&dev.nwk, (uint16_t)(0x4000 + i), NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    npduLen = composeReceivedRreq(npdu, NWK_ADDR_ROUTERS, HOP, UNSEEN, 0);
    injectNpdu(&dev, npdu, npduLen, UNSEEN);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS), ZB_OK, "a request whose transmitting device has no neighbor entry");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_RreqDroppedNoNeighbor(&dev.nwk), 1,
                     "9119-9120: the neighbor table is searched for the transmitting device, and the frame is discarded when the search fails");
    Test_ExpectCount(airCount, 0, "so nothing is relayed");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 0, "and Table 3-79 takes no entry for it");

    Zb_memset(dev.nwk.neighbors, 0, (uint32_t)sizeof dev.nwk.neighbors);

    injectNpdu(&dev, npdu, npduLen, UNSEEN);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS + 1), ZB_OK,
                      "and the same request once the table has room, which makes the entry and no cost");
    harvestAir(&dev.model, air, &airCount);

    hop = neighborAt(&dev.nwk, UNSEEN);

    Test_Expect(hop != 0 && hop->outgoingCost == 0, "the frame's own observation made the entry, and stated no cost");
    Test_ExpectCount(Nwk_RreqDroppedNoOutgoingCost(&dev.nwk), 1,
                     "9121: an outgoing cost of 0 is no measurement and not the best link there is, so the frame is discarded");
    Test_ExpectCount(airCount, 0, "and nothing is relayed");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 0, "and neither request was indicated upward");
    Test_ExpectCount(Nwk_RreqDroppedNoNeighbor(&dev.nwk), 1, "the no-neighbour counter did not move a second time");
}

/* Table 3-79's pool: a claim that finds no slot is refusal-and-count, and the frame is answered by nothing. */
void caseRreqDroppedWhenTheDiscoveryTableIsFull(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);
    seedForwarder(&dev.nwk, NEIGHBOR);

    for (i = 0; i < NWK_DISCOVERY_MAX; i++)
        (void)seedDiscovery(dev.nwk.discoveries, i, (uint16_t)(0x3000 + i), (uint8_t)(0x50 + i), 1, 0,
                            NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), NWK_DISCOVERY_MAX, "every slot of Table 3-79 holds a live entry");

    npduLen = composeReceivedRreq(npdu, NWK_ADDR_ROUTERS, HOP, UNSEEN, 0);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS), ZB_OK, "a request whose key the table does not hold, arriving at a full table");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_RreqDroppedNoDiscoverySlot(&dev.nwk), 1, "the claim finds no slot, and the refusal is counted");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), NWK_DISCOVERY_MAX, "no live entry was recycled to make room");
    Test_ExpectCount(airCount, 0, "and the frame is silent: it is neither relayed nor answered");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 0, "nor indicated upward");
    Test_ExpectCount(Nwk_RouteQueue(&dev.nwk), 0, "and 9125's reverse route is not made for a request that got no entry");
}

/*
 * 9152-9155: a relayed request also sets the routing entry for the request's *destination* to DISCOVERY_UNDERWAY
 * (the forwarder's record that a discovery for that address passes through it) and leaves an ACTIVE entry alone.
 * The creation is the unicast branch's: 9154's "and the frame is a unicast route request" is what makes it, and the
 * case beside this one reads what a many-to-one request makes instead.
 */
void caseRreqRelayMarksTheDestinationsRoute(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_RoutingTableEntry *reverse;
    Nwk_RoutingTableEntry *destination;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rigAtSeed(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1, 0, JITTER_SEED);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);
    seedForwarder(&dev.nwk, NEIGHBOR);

    npduLen = composeReceivedRreq(npdu, NWK_ADDR_ROUTERS, HOP, UNSEEN, HELD_PATH_COST);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS), ZB_OK, "a request this device is not the destination of");

    reverse = Nwk_RouteOf(dev.nwk.routes, HOP);
    destination = Nwk_RouteOf(dev.nwk.routes, UNSEEN);

    Test_Expect(reverse != 0 && reverse->status == NWK_ROUTE_ACTIVE,
                "9125-9142: the reverse route to the request's source is ACTIVE and exists for the way back");
    Test_Expect(destination != 0,
                "9154: the routing entry for the routing address of the destination field is created, the frame being a unicast route request");
    Test_ExpectCount(destination ? destination->status : 0xff, NWK_ROUTE_DISCOVERY_UNDERWAY,
                     "with its status field set to DISCOVERY_UNDERWAY, which is this forwarder's record of a discovery passing through");
    Test_ExpectCount(destination ? destination->destinationAddress : 0, UNSEEN, "for the address the request is looking for");
    Test_ExpectCount(Nwk_RouteQueue(&dev.nwk), 2, "two entries and no third: the discoverer's own is the ACTIVE one");

    /* 9152: an entry that is already ACTIVE keeps the status it holds, whatever passes through it */
    npduLen = composeReceivedRreq(npdu, NWK_ADDR_ROUTERS, HOP, HOP, LOWER_PATH_COST);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS + 1), ZB_OK,
                      "and a cheaper copy of a request whose destination is the forwarding device's own source");

    Test_ExpectCount(reverse->status, NWK_ROUTE_ACTIVE,
                     "an entry that is already ACTIVE is not moved: 9152 sets DISCOVERY_UNDERWAY only where the status is not ACTIVE");
    Test_ExpectCount(reverse->nextHopAddress, NEIGHBOR, "and it keeps the next hop the reverse route gave it");
    Test_ExpectCount(Nwk_RouteQueue(&dev.nwk), 2, "no third entry is claimed for an address the table already holds");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS + NWK_MAX_RREQ_RELAY_MS + 2), ZB_OK,
                      "a turn past the longest jitter 3.6.4.5.1.4 allows");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "one relay went out, so the entry the mark made did not stop the discovery it records");
}

/*
 * K.2.1.2 and K.2.1.3 through a relay: a many-to-one request's Concentrator Information TLV and Source Route
 * Solicitation list are forwarded "without modification", which a presence-only parse cannot promise, so the
 * received tail is carried octet for octet, and a class destination claims no routing entry.
 */
void caseRreqManyToOneKeepsTheConcentratorTlv(void)
{
    static const uint8_t expectedTail[] =
    {
        /* K.2.1.1: tag 0, two octets less one, the originator's number low octet first, the first radius */
        NWK_TLV_TAG_EXTENDED_ROUTE, 2, 0x35, 0x12, NWK_INITIAL_RADIUS,

        /* K.2.1.2: tag 1, one octet less one, the concentrator's two settings */
        NWK_TLV_TAG_CONCENTRATOR, 1, CONCENTRATOR_DISCOVERY_TIME, NWK_MAX_SOURCE_ROUTE,

        /* K.2.1.3: tag 2, three octets less one, the solicited addresses low octet first */
        NWK_TLV_TAG_SOURCE_ROUTE_SOLICITATION, 3, 0x34, 0x12, 0x78, 0x56
    };
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_Frame header;
    Nwk_RoutingTableEntry *reverse;
    Nwk_TlvSet tlvs;
    const uint8_t *payload;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t payloadOffset;
    uint32_t payloadLen;
    uint32_t airCount = 0;

    rigAtSeed(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1, 0, JITTER_SEED);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);
    seedForwarder(&dev.nwk, NEIGHBOR);

    npduLen = composeManyToOneRreq(npdu, HOP);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS), ZB_OK, "a many-to-one request carrying both of Annex K.2's records");

    reverse = Nwk_RouteOf(dev.nwk.routes, HOP);

    Test_Expect(Nwk_RouteOf(dev.nwk.routes, NWK_ADDR_ROUTERS) == 0,
                "9154: creating an entry is the unicast branch (\"and the frame is a unicast route request\") so a many-to-one request creates none for the class it names");
    Test_Expect(reverse != 0 && reverse->status == NWK_ROUTE_ACTIVE && reverse->nextHopAddress == NEIGHBOR,
                "9155-9163: the entry a many-to-one request does make is the one for its source, ACTIVE, next hop the previous device");
    Test_Expect(reverse != 0 && reverse->manyToOne == 1 && reverse->routeRecordRequired == 1,
                "and 9157-9162's two flags are set on it");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS + NWK_MAX_RREQ_RELAY_MS + 2), ZB_OK,
                      "a turn past the longest jitter 3.6.4.5.1.4 allows");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "and the relay goes out");

    Test_ExpectStatus(NwkFrame_Parse(npduOf(&air[0]), npduLenOf(&air[0]), &header, &payloadOffset, &payloadLen),
                      ZB_OK, "read back by this stack's own codec");

    payload = npduOf(&air[0]) + payloadOffset;

    Test_ExpectCount(payload[RREQ_PATH_COST], FORWARDER_OUTGOING_COST,
                     "9109-9110: the path cost is the received 0 plus the hop's 2, as every relayed copy's is");
    Test_ExpectCount(payloadLen, NWK_RREQ_FIXED_OCTETS + (uint32_t)sizeof expectedTail,
                     "and the payload is the fixed fields and the received tail, nothing added and nothing lost");
    Test_Expect(Zb_memcmp(payload + NWK_RREQ_FIXED_OCTETS, expectedTail, (uint32_t)sizeof expectedTail) == 0,
                "K.2.1.1-K.2.1.3: all three records are forwarded octet for octet as the originator wrote them");

    Test_ExpectCount((uint32_t)Nwk_TlvRead(NWK_CMD_ROUTE_REQUEST, payload + NWK_RREQ_FIXED_OCTETS, (uint32_t)sizeof expectedTail, &tlvs),
                      NWK_TLV_OK, "and they still read as the records they are");

    Test_ExpectCount(tlvs.concentratorInfo, 1, "K.2.1.2: the Concentrator Information TLV survives the relay");
    Test_ExpectCount(tlvs.sourceRouteSolicitation, 1, "and K.2.1.3's solicitation list with it");
    Test_ExpectCount(tlvs.routingSequenceNumber, 0x1235, "K.2.1.1.1: the originator's number, unmodified");
    Test_ExpectCount(tlvs.initialRadius, NWK_INITIAL_RADIUS, "K.2.1.1.2: and the first instance's radius");
    Test_ExpectCount(dev.nwk.routingSequenceNumber, 0,
                     "while this device's own nwkRoutingSequenceNumber does not move for a forwarded request");
}

/* The three-device chain's cast: A initiates, R is the only device both ends can hear, B is behind R. */
#define CHAIN_A 0x11a1
#define CHAIN_R 0x22b2
#define CHAIN_B 0x33c3

/* The three identities 3.4.1.2 and 3.4.2.2 make every command frame carry. */
#define CHAIN_A_IEEE 0x00000000000000a1
#define CHAIN_R_IEEE 0x00000000000000b2
#define CHAIN_B_IEEE 0x00000000000000c3

#define CHAIN_T0 1000
#define CHAIN_JITTER_SEED 0x1234

/*
 * The end-to-end witness: A's request reaches R, R relays it to B, B answers A, R forwards the answer to the
 * sender Table 3-79 holds, and A's route becomes ACTIVE. One clock drives the whole chain, A's four
 * broadcasts, R's jittered relay and the reply's two hops are all read against the same `nowMs`. Each
 * assertion group is one hop, and the three devices' tables are read at the end as the network they made.
 */
void caseRreqChainKeepsTheOriginatorEndToEnd(void)
{
    static const uint8_t aIeee[NWK_IEEE_ADDR_OCTETS] = { 0xa1, 0, 0, 0, 0, 0, 0, 0 };
    Test_BandA a;
    Test_BandA r;
    Test_BandA b;
    Air airA[AIR_LOG_MAX];
    Air airR[AIR_LOG_MAX];
    Air airB[AIR_LOG_MAX];
    Nwk_Frame aFrame;
    Nwk_Frame relayedFrame;
    Nwk_Frame replyFrame;
    Nwk_Frame forwardedFrame;
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataIndicationParameters inds[1];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_NeighborTableEntry *hop;
    Nwk_DataRequestParameters req;
    Nwk_RoutingTableEntry *route;
    const uint8_t *payload;
    uint8_t requestNpdu[RADIO_MPDU_MAX];
    uint8_t originalPayload[NWK_RREQ_PAYLOAD_MAX];
    uint32_t requestLen;
    uint32_t originalPayloadLen;
    uint32_t payloadOffset;
    uint32_t payloadLen;
    uint32_t airCountA = 0;
    uint32_t airCountR = 0;
    uint32_t airCountB = 0;
    uint32_t jitterState;
    uint32_t jitter;
    uint32_t receiveMs;
    uint32_t relayMs;
    uint32_t i;
    uint32_t got;

    rigAtSeed(&a, CHAIN_A, PAN_ID, NWK_DEVICE_ROUTER, 1, 0, 0);
    rigAtSeed(&r, CHAIN_R, PAN_ID, NWK_DEVICE_ROUTER, 1, 0, CHAIN_JITTER_SEED);
    rigAtSeed(&b, CHAIN_B, PAN_ID, NWK_DEVICE_ROUTER, 1, 0, 0);
    setOwnIeee(&a, CHAIN_A_IEEE);
    setOwnIeee(&r, CHAIN_R_IEEE);
    setOwnIeee(&b, CHAIN_B_IEEE);
    scriptOutcomes(&a.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&r.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&b.model, LOOPBACK_TX_MAX, 1);

    /* R hears A directly; B hears R only. B's link to R is Table 3-75's worse direction of 2, so the reply
       leaves B costing 2 and every later hop adds its own. */
    seedNeighbor(&r.nwk, CHAIN_A, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    neighborAt(&r.nwk, CHAIN_A)->outgoingCost = 1;
    seedNeighbor(&b.nwk, CHAIN_R, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    hop = neighborAt(&b.nwk, CHAIN_R);

    Test_Expect(hop != 0, "B holds the neighbor entry of the only device it can hear");

    if (hop == 0)
        return;

    hop->lqi = 200;
    hop->outgoingCost = 2;

    /* A's own door starts the discovery, and 3.6.4.5.1's four broadcasts go out on the one clock. */
    req = nldeReq(CHAIN_B, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&a.nwk, &req, CHAIN_T0), ZB_OK,
                      "A asks for a route to B with DiscoverRoute 0x01 and has neither route nor neighbor");

    for (i = 0; i < NWK_RREQ_TX_COUNT; i++)
    {
        Test_ExpectStatus(Test_NwkStep(&a.nwk, CHAIN_T0 + i * NWK_RREQ_RETRY_INTERVAL_MS), ZB_OK,
                          "one turn of A's four-broadcast schedule");
        harvestAir(&a.model, airA, &airCountA);
        Test_ExpectCount(Nwk_RouteRequestsSent(&a.nwk), i + 1, "and one more Route Request is on the air");
    }

    Test_ExpectCount(airCountA, NWK_RREQ_TX_COUNT, "each broadcast is a MAC frame with its own DSN, so four leave");

    for (i = 1; i < airCountA; i++)
    {
        Test_ExpectCount(npduDiffCount(npduOf(&airA[0]), npduLenOf(&airA[0]), npduOf(&airA[i]),
                                       npduLenOf(&airA[i])), 0,
                         "and every copy carries the same NPDU: the schedule repeats one composition");
    }

    Test_ExpectStatus(NwkFrame_Parse(npduOf(&airA[0]), npduLenOf(&airA[0]), &aFrame, &payloadOffset, &payloadLen),
                      ZB_OK, "read back by this stack's codec");
    Test_ExpectCount(aFrame.srcAddr, CHAIN_A, "3.3.1.3: A's own source address");
    Test_Expect(aFrame.srcIeeePresent == 1 && aFrame.srcIeee == CHAIN_A_IEEE,
                "3.4.1.2: A's source IEEE address, with its sub-field set");
    Test_ExpectCount(aFrame.sequenceNumber, 1,
                     "3.3.1.5: the request's own number, the data frame composed before it having spent 0");

    requestLen = npduLenOf(&airA[0]);
    Zb_memcpy(requestNpdu, npduOf(&airA[0]), requestLen);

    payload = requestNpdu + payloadOffset;
    originalPayloadLen = payloadLen;
    Zb_memcpy(originalPayload, payload, originalPayloadLen);

    Test_ExpectCount(payload[RREQ_PATH_COST], 0, "3.4.1.3.4: an initiator's path cost is 0");

    /* R receives A's request at the fourth broadcast's instant and owes its relay one jitter later. The draw
       is taken before the reception, because the reception is what advances R's generator. */
    receiveMs = CHAIN_T0 + (NWK_RREQ_TX_COUNT - 1) * NWK_RREQ_RETRY_INTERVAL_MS;
    jitterState = r.nwk.jitterState;
    jitter = Nwk_RreqRelayJitterMs(&jitterState, CHAIN_JITTER_SEED);
    relayMs = receiveMs + jitter;

    injectNpdu(&r, requestNpdu, requestLen, CHAIN_A);
    Test_ExpectStatus(Test_NwkStep(&r.nwk, receiveMs), ZB_OK, "the instant R hears A's fourth broadcast");
    harvestAir(&r.model, airR, &airCountR);
    Test_ExpectCount(airCountR, 0, "and R has not relayed it yet");

    Test_ExpectStatus(Test_NwkStep(&r.nwk, relayMs - 1), ZB_OK, "one millisecond before R's jitter expires");
    harvestAir(&r.model, airR, &airCountR);
    Test_ExpectCount(airCountR, 0, "and the relay is not on the air");

    Test_ExpectStatus(Test_NwkStep(&r.nwk, relayMs), ZB_OK, "the instant 3.6.4.5.1.4's delay expires");
    harvestAir(&r.model, airR, &airCountR);

    Test_ExpectCount(airCountR, 1, "R puts exactly one relayed request on the air, on the same clock");
    Test_ExpectStatus(NwkFrame_Parse(npduOf(&airR[0]), npduLenOf(&airR[0]), &relayedFrame, &payloadOffset, &payloadLen),
                      ZB_OK, "and it is a frame this stack reads");

    Test_ExpectCount(relayedFrame.srcAddr, CHAIN_A,
                     "3.3.1.3: the relayed request keeps A's source address, not R's");
    Test_ExpectCount(relayedFrame.sequenceNumber, aFrame.sequenceNumber,
                     "3.3.1.5: and A's sequence number, because a relay is the same frame retransmitted");
    Test_Expect(relayedFrame.srcIeeePresent == 1 && relayedFrame.srcIeee == CHAIN_A_IEEE,
                "3.4.1.2: and A's source IEEE address, with its sub-field still set");
    Test_ExpectCount(relayedFrame.destAddr, NWK_ADDR_ROUTERS, "3.4.1.2: the destination field is as received");
    Test_Expect(relayedFrame.destIeeePresent == 0, "3.3.1.6: and its IEEE sub-field is absent as received");
    Test_ExpectCount(relayedFrame.endDeviceInitiator, aFrame.endDeviceInitiator,
                     "3.3.1.1.8: the End Device Initiator bit travels as received");
    Test_ExpectCount(relayedFrame.radius, (uint32_t)aFrame.radius - 1,
                     "3.3.1.4: the radius is one lower, the decrement R paid on receipt");

    Test_ExpectCount(npduDiffCount(requestNpdu, requestLen, npduOf(&airR[0]), npduLenOf(&airR[0])), 2,
                     "9109-9110 with 3.3.1.4: exactly two octets change, the radius and the path cost");
    Test_ExpectCount(npduOf(&airR[0])[NPDU_RADIUS_OCTET], (uint8_t)(requestNpdu[NPDU_RADIUS_OCTET] - 1),
                     "the radius octet is the first");
    Test_ExpectCount(npduOf(&airR[0])[NPDU_SEQ_OCTET], requestNpdu[NPDU_SEQ_OCTET],
                     "and the sequence octet is untouched");

    payload = npduOf(&airR[0]) + payloadOffset;

    Test_ExpectCount(payloadLen, originalPayloadLen, "3.4.1.3: the payload length is the received one");
    Test_ExpectCount(payload[RREQ_PATH_COST], 1,
                     "9122-9124: R's link cost is Table 3-76's 1 for the LQA it measured, so the path cost becomes 1");
    Test_Expect(Zb_memcmp(payload + NWK_RREQ_FIXED_OCTETS, originalPayload + NWK_RREQ_FIXED_OCTETS,
                         originalPayloadLen - NWK_RREQ_FIXED_OCTETS) == 0,
                "K.2.1.1-K.2.1.3: the received tail is carried octet for octet");

    entry = Nwk_DiscoveryOf(r.nwk.discoveries, CHAIN_A, 1);

    Test_ExpectCount(entry ? entry->senderAddress : 0, CHAIN_A, "Table 3-79 at R records A as the sender it heard");
    Test_ExpectCount(entry ? entry->forwardCost : 0, 1, "and the forward cost R computed for the path back to A");

    /* B hears the relay, sees itself as the destination, and answers A. */
    injectNpdu(&b, npduOf(&airR[0]), npduLenOf(&airR[0]), CHAIN_R);
    Test_ExpectStatus(Test_NwkStep(&b.nwk, relayMs), ZB_OK,
                      "the same instant, B receives the relayed request and finds itself named");
    harvestAir(&b.model, airB, &airCountB);

    Test_ExpectCount(airCountB, 1, "B answers with exactly one reply");
    Test_ExpectStatus(NwkFrame_Parse(npduOf(&airB[0]), npduLenOf(&airB[0]), &replyFrame, &payloadOffset, &payloadLen),
                      ZB_OK, "which is a frame this stack reads");
    Test_ExpectCount(replyFrame.srcAddr, CHAIN_B, "3.4.2.2: B is the frame's source");
    Test_ExpectCount(replyFrame.destAddr, CHAIN_R, "9200-9201: and the next hop is Table 3-79's sender, R");
    Test_ExpectCount(replyFrame.radius, NWK_RREP_RADIUS, "3.4.2.2: a reply leaves its target at nwkcMaxDepth x 2");
    Test_ExpectCount(airDestOf(&airB[0]), CHAIN_R, "and the MAC destination is R");

    payload = npduOf(&airB[0]) + payloadOffset;

    Test_ExpectCount((uint32_t)(payload[RREP_ORIGINATOR] | (payload[RREP_ORIGINATOR + 1] << 8)), CHAIN_A,
                     "3.4.2.3.3: the reply's originator is A, the source address in the request's NWK header");
    Test_ExpectCount((uint32_t)(payload[RREP_RESPONDER] | (payload[RREP_RESPONDER + 1] << 8)), CHAIN_B,
                     "3.4.2.3.4: and the responder is B, the device that composed it");
    Test_ExpectCount(payload[RREP_PATH_COST], 2,
                     "3.4.2.3.5: B's link cost to R is the seeded worse direction of 2");
    Test_Expect(Zb_memcmp(payload + RREP_ORIGINATOR_IEEE, aIeee, NWK_IEEE_ADDR_OCTETS) == 0,
                "3.4.2.3.6: the originator IEEE is A's, carried through the relay");

    entry = Nwk_DiscoveryOf(b.nwk.discoveries, CHAIN_A, 1);
    route = Nwk_RouteOf(b.nwk.routes, CHAIN_A);

    Test_ExpectCount(entry ? entry->senderAddress : 0, CHAIN_R, "Table 3-79 at B records the hop the request came from");
    Test_ExpectCount(entry ? entry->forwardCost : 0, 3, "and the forward cost of the path to A through R");
    Test_Expect(route != 0 && route->status == NWK_ROUTE_ACTIVE && route->nextHopAddress == CHAIN_R,
                "9125-9142: B's route to A is ACTIVE through R");

    /* R receives B's reply and forwards it to the sender its Table 3-79 entry holds: A. */
    injectNpdu(&r, npduOf(&airB[0]), npduLenOf(&airB[0]), CHAIN_B);
    Test_ExpectStatus(Test_NwkStep(&r.nwk, relayMs), ZB_OK,
                      "R receives the reply at the same instant, addressed to it");
    harvestAir(&r.model, airR, &airCountR);

    Test_ExpectCount(airCountR, 2, "and the relay plus the forwarded reply are the two frames R has put on the air");
    Test_ExpectCount(Nwk_RouteRepliesForwarded(&r.nwk), 1, "9231-9272: one reply forwarded and counted");
    Test_ExpectStatus(NwkFrame_Parse(npduOf(&airR[1]), npduLenOf(&airR[1]), &forwardedFrame, &payloadOffset,
                                     &payloadLen), ZB_OK, "the forwarded reply is a frame this stack reads");
    Test_ExpectCount(forwardedFrame.srcAddr, CHAIN_R, "3.4.2.2: R creates a new frame, with its own source");
    Test_ExpectCount(forwardedFrame.destAddr, CHAIN_A,
                     "9266-9272: the next hop is Table 3-79's sender for A's request, which is A");
    Test_ExpectCount(forwardedFrame.radius, (uint32_t)replyFrame.radius - 1,
                     "3.4.2.2: the radius is one lower again");
    Test_ExpectCount(airDestOf(&airR[1]), CHAIN_A, "and the MAC destination is A, not B and not the originator's peer");

    payload = npduOf(&airR[1]) + payloadOffset;

    Test_ExpectCount((uint32_t)(payload[RREP_ORIGINATOR] | (payload[RREP_ORIGINATOR + 1] << 8)), CHAIN_A,
                     "the payload's originator is still A");
    Test_ExpectCount((uint32_t)(payload[RREP_RESPONDER] | (payload[RREP_RESPONDER + 1] << 8)), CHAIN_B,
                     "and its responder is still B");
    Test_ExpectCount(payload[RREP_PATH_COST], 3,
                     "9225-9228: R advances the cost again by its link to B, 2 + 1");

    entry = Nwk_DiscoveryOf(r.nwk.discoveries, CHAIN_A, 1);
    route = Nwk_RouteOf(r.nwk.routes, CHAIN_A);

    Test_Expect(entry != 0 && entry->senderAddress == CHAIN_A,
                "9266-9268: Table 3-79 still holds A as the sender the reply is forwarded to");
    Test_ExpectCount(entry ? entry->residualCost : 0, 2,
                     "9262-9263: the residual cost is the value the reply command frame carried into R, which is 2");
    Test_Expect(route != 0 && route->status == NWK_ROUTE_ACTIVE && route->nextHopAddress == CHAIN_A,
                "9279-9285: R's reverse route to A stays ACTIVE with next hop A");

    /* A receives R's forward and its route to B becomes ACTIVE. */
    injectNpdu(&a, npduOf(&airR[1]), npduLenOf(&airR[1]), CHAIN_R);
    Test_ExpectStatus(Test_NwkStep(&a.nwk, relayMs), ZB_OK,
                      "A receives the reply on the same clock, and 3.6.4.5.2's originator half runs");
    harvestAir(&a.model, airA, &airCountA);

    Test_ExpectCount(airCountA, NWK_RREQ_TX_COUNT + 1,
                     "A's schedule stopped at four broadcasts and the frame that waited for the route went out on the same turn (3.6.4.5.2, 3.2.1.1.3)");
    Test_ExpectCount(airDestOf(&airA[NWK_RREQ_TX_COUNT]), CHAIN_R,
                     "over Table 3-77's next hop R, the device that forwarded the reply");
    Test_ExpectCount(Nwk_RouteRequestsSent(&a.nwk), NWK_RREQ_TX_COUNT, "after the four broadcasts that began the chain");

    route = Nwk_RouteOf(a.nwk.routes, CHAIN_B);
    entry = Nwk_DiscoveryOf(a.nwk.discoveries, CHAIN_A, 1);

    Test_Expect(route != 0 && route->status == NWK_ROUTE_ACTIVE,
                "9240-9243: A's entry for B leaves DISCOVERY_UNDERWAY and becomes ACTIVE, not written by hand");
    Test_ExpectCount(route ? route->nextHopAddress : 0, CHAIN_R, "and its next hop is R, the device that forwarded the reply");
    Test_ExpectCount(entry ? entry->residualCost : 0, 3,
                     "9243: the residual cost is the value the reply carried into A, which is 3");

    Test_ExpectCount(Nwk_ConfirmQueue(&a.nwk), 0, "the frame went out on the turn the reply arrived, so its answer is the next drain's");

    Test_ExpectStatus(Test_NwkStep(&a.nwk, relayMs + 1), ZB_OK, "the turn that answer is drained on");
    harvestAir(&a.model, airA, &airCountA);
    Test_ExpectCount(airCountA, NWK_RREQ_TX_COUNT + 1, "and nothing else went out on it");

    got = Nwk_PollConfirms(&a.nwk, confirms, 4);

    Test_ExpectCount(got, 1, "the request that waited is answered once");
    Test_ExpectStatus(confirms[0].status, ZB_OK, "with the status 3.2.1.1.3's confirm carries for an attempt that reached the seam");
    Test_ExpectCount(confirms[0].nwkStatus, NWK_STATUS_SUCCESS, "and Table 3-84's code beside it");
    Test_ExpectCount(confirms[0].attempts, 1, "one attempt, the one the reply made possible");
    Test_ExpectCount(Test_NwkPoll(&a.nwk, inds, 1), 0,
                     "and the reply is consumed by this layer, never indicated upward");

    /* The three tables at the end, read as the network the chain made. */
    route = Nwk_RouteOf(r.nwk.routes, CHAIN_B);
    Test_Expect(route != 0 && route->status == NWK_ROUTE_ACTIVE && route->nextHopAddress == CHAIN_B,
                "9152-9155 marked R's entry for B underway; the reply R forwarded leaves it ACTIVE with B as next hop (8852-8856)");
    Test_ExpectCount(Nwk_RouteQueue(&r.nwk), 2, "R holds the reverse route to A and the discovery's route to B");

    route = Nwk_RouteOf(b.nwk.routes, CHAIN_A);
    Test_Expect(route != 0 && route->status == NWK_ROUTE_ACTIVE && route->nextHopAddress == CHAIN_R,
                "9125-9142: B's table ends with A ACTIVE through R");

    entry = Nwk_DiscoveryOf(r.nwk.discoveries, CHAIN_A, 1);
    Test_ExpectCount(entry ? entry->destAddr : 0, CHAIN_B, "Table 3-79 at R names the destination the discovery is for");
    Test_ExpectCount(Nwk_RouteQueue(&a.nwk), 1, "A's routing table holds the one route it asked for");
    Test_ExpectCount(Nwk_RouteQueue(&b.nwk), 1, "B's holds the reverse route the request made");
}
