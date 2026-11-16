/* 3.6.4.5.2's reception as the façade runs it: the dispatch that sits beside 3.6.4.5.1's, the originator's half
   answering the request that waited through `nwkDoDiscoveryRelease`, the forwarder's 3.6.4.5.2.1 recomposition
   to Table 3-79's sender address, the reverse route re-pointed to that same hop, and the five discards the clause prints, each counted where it was taken.
   Every reply a case injects is composed by `nwk_rrep`'s own codec and every number it asserts is one a clause
   or a table prints; the rig is the shared band-A device in `nwk_helpers.c`. */

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
#include "nwk_rreqtx.h"
#include "nwk_tlv.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

enum
{
    /* 3.4.2.3's field order inside a route reply payload, behind Table 3-54's identifier octet */
    /* 3.4.2.2 makes every Route Reply carry its source IEEE address, so the payload starts one IEEE field
       past the minimal header */
    RREP_PAYLOAD_OFFSET = NWK_MIN_HEADER_OVERHEAD + NWK_IEEE_ADDR_OCTETS,
    RREP_REQUEST_ID = 2,
    RREP_ORIGINATOR = 3,
    RREP_RESPONDER = 5,
    RREP_PATH_COST = 7,

    ORIGINATOR_ADDRESS = 0x1111,    /* 3.4.2.3.3: the device that started the discovery */
    PREVIOUS_HOP = 0x2222,          /* Table 3-79's sender address: the device the request came from, 9266-9268 */
    RESPONDER_ADDRESS = 0x3333,     /* 3.4.2.3.4: the device that answered the request */
    FAR_HOP = 0x4444,               /* 3.4.2.2: the previous device that forwarded the reply, and its NWK source */

    REQUEST_ID = 0x31,              /* 3.4.1.3.2's identifier, the key Table 3-79 is searched by */
    RECORDED_RESIDUAL_COST = 4,     /* Table 3-79's residual cost a reply is compared against (9244-9249) */
    DEARER_PATH_COST = 9,           /* with this hop's link cost of 1, a cost no recorded resident admits */
    CHEAPER_PATH_COST = 2,          /* 2 plus 1 is smaller than the recorded 4 */
    FORWARDED_PATH_COST = 3,        /* a forwarder's payload value, one less than what it sends on */
    LINK_COST_ONE = 1,              /* Table 3-76: the carrier's LQA of 200 is the incoming cost 1 */
    RECEIVED_RADIUS = 29,           /* 3.4.2.2: the radius a reply arrives with, one decrement in */
    REPLY_SEQUENCE = 0x1235,        /* K.3.1.1.1: the responder's routing sequence number, never this device's */
    REPLY_SEQ = 0x50,               /* the NWK sequence number the received frame's header carries (3.3.1.5) */
    DISCOVERY_START_MS = 1000,      /* the clock a discovery starts at; 9151's timer is 10000 ms past it */
    NOW_MS = 1000                   /* the clock a reception arrives at where a case starts nothing */
};

/* The reply a neighbor sends: Figure 3-11's payload from this stack's own codec, in a header the caller names,
   3.4.2.2 makes a route reply newly created by each hop, so its NWK source is the hop that just sent it. */
static uint32_t composeReceivedRrep(uint8_t *npdu, uint16_t headerDest, uint16_t previousHop, uint16_t originator,
                                    uint16_t responder, uint8_t pathCost, uint8_t requestId)
{
    uint8_t payload[NWK_RREP_PAYLOAD_MAX];
    Nwk_RouteReplyPayload reply;
    uint32_t payloadLen;
    uint32_t routingSeq;

    Zb_memset(&reply, 0, (uint32_t)sizeof reply);

    reply.requestId = requestId;
    reply.originatorAddr = originator;
    reply.responderAddr = responder;
    reply.pathCost = pathCost;
    reply.originatorIeee = 0x1112131415161718;
    reply.responderIeee = 0x2122232425262728;

    /* K.3.1.1.1: the composer writes the value it is handed plus one, so a case hands it one less than the
       number it means the responder's record to carry */
    routingSeq = (uint32_t)(REPLY_SEQUENCE - 1);

    Test_ExpectStatus(Nwk_RrepCompose(&reply, &routingSeq, payload, (uint32_t)sizeof payload, &payloadLen), ZB_OK,
                      "the reply a case injects is a payload this stack's own codec composes");

    return makeNpdu(npdu, headerDest, previousHop, (uint8_t)RECEIVED_RADIUS, REPLY_SEQ,
                    NWK_FRAME_TYPE_COMMAND, 0, payload, payloadLen);
}

/* The request a discovery waits on: an NLDE-DATA.request for an address with no route and no neighbour */
static void startDiscovery(Test_BandA *dev, uint16_t destAddr)
{
    Nwk_DataRequestParameters req;

    req = nldeReq(destAddr, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev->nwk, &req, DISCOVERY_START_MS), ZB_OK,
                      "a request that names DiscoverRoute 0x01 starts 3.6.4.5.1's discovery");
    Test_ExpectStatus(Test_NwkStep(&dev->nwk, DISCOVERY_START_MS), ZB_OK,
                      "and its next step puts the first of the four broadcasts on the air");
}

/*
 * 3.6.4.5.2's originator half, as the flow a real reply produces: the entry a discovery left DISCOVERY_UNDERWAY
 * becomes ACTIVE, the frame the waiting request holds goes out over the hop that reply made, and 3.6.4.5.1.4's
 * schedule stops where the discovery does.
 */
void caseRrepAtTheOriginatorReleasesTheWaitingRequest(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataIndicationParameters inds[4];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_RoutingTableEntry *route;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint32_t got;
    uint8_t requestId;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    startDiscovery(&dev, RESPONDER_ADDRESS);

    route = Nwk_RouteOf(dev.nwk.routes, RESPONDER_ADDRESS);
    requestId = dev.nwk.routeRequestId;

    Test_Expect(route != 0 && route->status == NWK_ROUTE_DISCOVERY_UNDERWAY,
                "9047-9054: the entry the initiation left is DISCOVERY_UNDERWAY and the request waits on it");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "one broadcast of the schedule has gone out");

    npduLen = composeReceivedRrep(npdu, OWN_SHORT, FAR_HOP, OWN_SHORT, RESPONDER_ADDRESS, CHEAPER_PATH_COST,
                                  requestId);
    injectNpdu(&dev, npdu, npduLen, FAR_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + 1), ZB_OK, "the turn the reply arrives on");

    Test_ExpectCount(route->status, NWK_ROUTE_ACTIVE,
                     "9240-9243: a DISCOVERY_UNDERWAY entry is changed to ACTIVE by the reply that answers it");
    Test_ExpectCount(route->nextHopAddress, FAR_HOP,
                     "and its next hop is 9242's previous device that forwarded the route reply");
    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_ExpectCount(got, 0, "nothing is answered on the turn the reply arrives: the held frame is issued on it and its answer is the next drain's (3.2.1.1.3)");

    entry = Nwk_DiscoveryOf(dev.nwk.discoveries, OWN_SHORT, requestId);

    Test_Expect(entry != 0,
                "3.6.4.5.1.3: the discovery entry is kept until it expires, because it holds the residual cost");
    Test_ExpectCount(entry ? entry->residualCost : 0, CHEAPER_PATH_COST,
                     "9243: the residual cost is the path cost field the payload carried, 2");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 0,
                     "and the reply is not indicated upward: 3.6.4.5.2 is a procedure of this layer");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + 1 + NWK_RREQ_RETRY_INTERVAL_MS), ZB_OK,
                      "the instant the second broadcast would have been due, and the turn the MAC's answer to the held frame is drained");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 2, "the schedule's one broadcast plus the frame 3.6.4.5.1's MAY chose to hold");
    Test_ExpectCount(airDestOf(&air[1]), FAR_HOP, "sent to the next hop the reply established (3.6.4.3, Table 3-77)");
    Test_ExpectCount(route->ageMs, DISCOVERY_START_MS + 1,
                     "Table 3-77's RecentActivity is stamped at the turn the reply made the route and the send took it (3.6.4.8.1)");
    Test_ExpectCount(Nwk_RouteRequestsSent(&dev.nwk), 1, "and no second broadcast: 3.6.4.5.1.4's schedule stopped when the route answered it");

    npduLen = composeReceivedRrep(npdu, OWN_SHORT, FAR_HOP, OWN_SHORT, RESPONDER_ADDRESS, CHEAPER_PATH_COST,
                                  requestId);
    injectNpdu(&dev, npdu, npduLen, FAR_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + 2 + NWK_RREQ_RETRY_INTERVAL_MS), ZB_OK,
                      "and the same reply once more");

    Test_ExpectCount(Nwk_RrepDroppedNotSmaller(&dev.nwk), 1,
                     "9247-9249: a cost that is not smaller than the recorded one discards the reply and stops there");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_ExpectCount(got, 1, "the held frame is answered by the attempt it made, once");
    Test_ExpectStatus(confirms[0].status, ZB_OK, "with SUCCESS, the status 3.2.1.1.3's own confirm carries");
    Test_ExpectCount(confirms[0].nwkStatus, NWK_STATUS_SUCCESS, "and Table 3-84's code for it");
    Test_ExpectCount(confirms[0].attempts, 1, "one attempt, the one the reply made possible");
    Test_ExpectCount(confirms[0].dstAddr, RESPONDER_ADDRESS, "for the destination the request named");
    Test_Expect(confirms[0].handle != RADIO_HANDLE_NONE, "and the handle the MAC gave for the transmit");
    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), 0, "and no second request is answered: one request, one answer");

    Test_ExpectCount(Nwk_RouteRepliesSent(&dev.nwk), 0, "no Route Reply is composed for a reply that arrived");
    Test_ExpectCount(Nwk_RouteRepliesForwarded(&dev.nwk), 0, "and none is forwarded: this device is the originator");
    Test_ExpectCount(airCount, 2, "the schedule's broadcast and the frame the discovery held: nothing else this case put on the air");
}

/*
 * 9244-9249 both ways on an ACTIVE entry: a cheaper reply replaces the next hop and the residual cost, a dearer
 * one is discarded and counted.
 */
void caseRrepCheaperAtTheOriginatorReplacesTheRoute(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_RoutingTableEntry *route;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    route = seedRoute(dev.nwk.routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_ACTIVE, PREVIOUS_HOP);
    entry = seedDiscovery(dev.nwk.discoveries, 0, OWN_SHORT, REQUEST_ID, 0, RECORDED_RESIDUAL_COST,
                          NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    npduLen = composeReceivedRrep(npdu, OWN_SHORT, FAR_HOP, OWN_SHORT, RESPONDER_ADDRESS, DEARER_PATH_COST,
                                  REQUEST_ID);
    injectNpdu(&dev, npdu, npduLen, FAR_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS), ZB_OK, "a reply dearer than the route this device already has");

    Test_ExpectCount(Nwk_RrepDroppedNotSmaller(&dev.nwk), 1,
                     "9246-9249: 'If the path cost in the route reply is not smaller, the route reply shall be discarded'");
    Test_ExpectCount(entry->residualCost, RECORDED_RESIDUAL_COST, "and the recorded residual cost stands");
    Test_ExpectCount(route->nextHopAddress, PREVIOUS_HOP, "and so does the next hop the entry routes through");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "and nothing goes on the air for it: a reply is consumed, never re-issued by its target");

    npduLen = composeReceivedRrep(npdu, OWN_SHORT, FAR_HOP, OWN_SHORT, RESPONDER_ADDRESS, CHEAPER_PATH_COST,
                                  REQUEST_ID);
    injectNpdu(&dev, npdu, npduLen, FAR_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS + 1), ZB_OK, "and a cheaper one afterwards");

    Test_ExpectCount(entry->residualCost, CHEAPER_PATH_COST,
                     "9244-9245: an ACTIVE entry's residual cost takes the payload's smaller cost, 2");
    Test_ExpectCount(route->nextHopAddress, FAR_HOP, "and its next hop takes the device that forwarded that reply");
    Test_ExpectCount(route->status, NWK_ROUTE_ACTIVE, "with the status it held: a cheaper reply moves a route, not its state");
    Test_ExpectCount(Nwk_RrepDroppedNotSmaller(&dev.nwk), 1, "and the discard counter did not move a second time");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "and the cheaper reply is consumed too: a reply's target sends nothing on");
}

/*
 * 9231-9239 with no routing entry for the responder: the reply is discarded, Table 3-79's entry goes with it, and
 * a later reply for the same identifier finds nothing to be judged against.
 */
void caseRrepWithoutARouteRemovesTheDiscoveryEntry(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_RoutingTableEntry *route;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    startDiscovery(&dev, RESPONDER_ADDRESS);

    route = Nwk_RouteOf(dev.nwk.routes, RESPONDER_ADDRESS);

    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 1, "the discovery holds Table 3-79's entry, as an initiation leaves it");

    /* 9236-9239 searches the routing table for the *responder*'s address, so a reply that names a device no
       route leads to is the case, whatever the entry the discovery holds is for */
    npduLen = composeReceivedRrep(npdu, OWN_SHORT, FAR_HOP, OWN_SHORT, UNSEEN, CHEAPER_PATH_COST,
                                  dev.nwk.routeRequestId);
    injectNpdu(&dev, npdu, npduLen, FAR_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + 1), ZB_OK,
                      "a reply whose responder has no routing entry");

    Test_ExpectCount(Nwk_RrepDroppedNoRoute(&dev.nwk), 1,
                     "9237-9239: the reply is discarded, the discovery entry is removed with it and processing ends");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 0, "the discovery table is a slot emptier than it was");
    Test_Expect(route != 0 && route->status == NWK_ROUTE_DISCOVERY_UNDERWAY,
                "and the routing entry for the destination the discovery sought is untouched: no reply moved it");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "nothing further went on the air");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + 2), ZB_OK, "a turn later");

    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), 0,
                     "and the request that waited is not answered: a route entry that is not ACTIVE confirms nothing");

    npduLen = composeReceivedRrep(npdu, OWN_SHORT, FAR_HOP, OWN_SHORT, UNSEEN, CHEAPER_PATH_COST,
                                  dev.nwk.routeRequestId);
    injectNpdu(&dev, npdu, npduLen, FAR_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + 3), ZB_OK,
                      "and a second reply for the same request identifier");

    Test_ExpectCount(Nwk_RrepDroppedNoDiscovery(&dev.nwk), 1,
                     "9231-9234: Table 3-79 no longer answers for that key, so the reply is discarded where it stands");
    Test_ExpectCount(Nwk_RrepDroppedNoRoute(&dev.nwk), 1, "and the removal is not counted twice");
    Test_ExpectCount(Nwk_PollConfirms(&dev.nwk, confirms, 4), 0, "and no confirmation is owed by either of them");
}

/*
 * 3.6.4.5.2.1: a forwarder sends the reply on with 9225-9228's cost, to the sender address Table 3-79 holds
 * (the device the request came from) and not to the originator the payload names.
 */
void caseRrepRelayedToTheTableSender(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_Frame header;
    Nwk_DataIndicationParameters inds[4];
    Nwk_RoutingTableEntry *route;
    Nwk_TlvSet tlvs;
    const uint8_t *payload;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t payloadOffset;
    uint32_t payloadLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, PREVIOUS_HOP, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    Nwk_NeighborOf(dev.nwk.neighbors, PREVIOUS_HOP)->lqi = 200;   /* Table 3-76: 192 < 200 <= 255, the link cost 1 */
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    route = seedRoute(dev.nwk.routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_ACTIVE, FAR_HOP);
    entry = seedDiscovery(dev.nwk.discoveries, 0, ORIGINATOR_ADDRESS, REQUEST_ID, RECORDED_RESIDUAL_COST, 0,
                          NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);
    entry->senderAddress = PREVIOUS_HOP;

    npduLen = composeReceivedRrep(npdu, OWN_SHORT, FAR_HOP, ORIGINATOR_ADDRESS, RESPONDER_ADDRESS,
                                  FORWARDED_PATH_COST, REQUEST_ID);
    injectNpdu(&dev, npdu, npduLen, FAR_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS), ZB_OK, "a reply this device is neither the originator nor the responder of");

    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "9264-9265: the reply is forwarded, once");
    Test_ExpectCount(airDestOf(&air[0]), PREVIOUS_HOP,
                     "9270-9272: the MAC destination is the sender address Table 3-79 holds, which is the way the request came");
    Test_Expect(airDestOf(&air[0]) != ORIGINATOR_ADDRESS,
                "and not the originator the payload names: 3.6.4.5.2.1 forwards one hop, not to the end");
    Test_Expect(air[0].ackRequest == 1, "3.4.3.1: the acknowledgment is asked for on a unicast");

    Test_ExpectStatus(NwkFrame_Parse(npduOf(&air[0]), npduLenOf(&air[0]), &header, &payloadOffset, &payloadLen),
                      ZB_OK, "and the forwarded frame is one this module's own codec reads back");

    payload = npduOf(&air[0]) + payloadOffset;

    Test_Expect(header.srcAddr == OWN_SHORT && header.destAddr == PREVIOUS_HOP,
                "3.4.2.2: the frame is this device's own, aimed at the next hop Table 3-79 names");
    Test_ExpectCount(header.radius, RECEIVED_RADIUS - 1, "and it carries the radius as received, one decrement paid");
    Test_Expect(header.sequenceNumber != REPLY_SEQ, "with a NWK sequence number of its own (3.3.1.5)");

    Test_ExpectCount((uint32_t)payload[0], NWK_CMD_ROUTE_REPLY, "Table 3-54: still a Route Reply");
    Test_ExpectCount(payload[RREP_REQUEST_ID], REQUEST_ID, "3.4.2.3.2: the identifier is the originator's");
    Test_ExpectCount((uint32_t)(payload[RREP_ORIGINATOR] | (payload[RREP_ORIGINATOR + 1] << 8)), ORIGINATOR_ADDRESS,
                     "3.4.2.3.3: and so is the originator address");
    Test_ExpectCount((uint32_t)(payload[RREP_RESPONDER] | (payload[RREP_RESPONDER + 1] << 8)), RESPONDER_ADDRESS,
                     "3.4.2.3.4: while the responder stays the device that answered");
    Test_ExpectCount(payload[RREP_PATH_COST], FORWARDED_PATH_COST + LINK_COST_ONE,
                     "9225-9228: the path cost is the received 3 plus this hop's link cost of 1");

    Test_ExpectCount(payloadLen,
                     NWK_RREP_FIXED_OCTETS + 2 * NWK_IEEE_ADDR_OCTETS + NWK_TLV_HEADER_OCTETS
                     + NWK_TLV_ROUTING_SEQUENCE_OCTETS,
                     "K.3.1.1's record is five octets and nothing was appended to the payload that arrived");

    Test_ExpectCount((uint32_t)Nwk_TlvRead(NWK_CMD_ROUTE_REPLY, payload + NWK_RREP_FIXED_OCTETS + 2 * NWK_IEEE_ADDR_OCTETS,
                                  payloadLen - NWK_RREP_FIXED_OCTETS - 2 * NWK_IEEE_ADDR_OCTETS, &tlvs),
                      NWK_TLV_OK, "and its tail still reads as Annex K.3.1.1's record");

    Test_ExpectCount(tlvs.routingSequenceNumber, REPLY_SEQUENCE,
                     "K.3.1.1.1: the number is the responder's, forwarded as it arrived and not incremented again");
    Test_ExpectCount(dev.nwk.routingSequenceNumber, 0,
                     "so forwarding a reply does not move this device's own nwkRoutingSequenceNumber");

    Test_ExpectCount(entry->residualCost, FORWARDED_PATH_COST,
                     "9261-9263: the discovery entry's residual cost is the value in the reply command frame, 3");
    Test_ExpectCount(route->nextHopAddress, FAR_HOP, "and the routing entry's next hop is the device that forwarded it");
    Test_ExpectCount(Nwk_RouteRepliesForwarded(&dev.nwk), 1, "counted as a reply forwarded, which is not one composed");
    Test_ExpectCount(Nwk_RouteRepliesSent(&dev.nwk), 0, "and not as a reply this device answered a request with");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 0, "and the reply is not indicated upward");
}

/* 9231-9235: Table 3-79 holds nothing for the reply's key, so nothing is judged and nothing is answered. */
void caseRrepDroppedWithNoDiscoveryEntry(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    Nwk_RoutingTableEntry *route;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    route = seedRoute(dev.nwk.routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_DISCOVERY_UNDERWAY, PREVIOUS_HOP);

    npduLen = composeReceivedRrep(npdu, OWN_SHORT, FAR_HOP, OWN_SHORT, RESPONDER_ADDRESS, CHEAPER_PATH_COST,
                                  REQUEST_ID);
    injectNpdu(&dev, npdu, npduLen, FAR_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS), ZB_OK, "a reply for a discovery this device never started");

    Test_ExpectCount(Nwk_RrepDroppedNoDiscovery(&dev.nwk), 1,
                     "9231-9235: the reply is discarded and route reply processing is terminated");
    Test_ExpectCount(route->status, NWK_ROUTE_DISCOVERY_UNDERWAY, "so no entry is moved to ACTIVE");
    Test_ExpectCount(route->nextHopAddress, PREVIOUS_HOP, "and no next hop is replaced");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "nothing is sent on and nothing is answered");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 0, "and the reply is not data: nothing reaches the ring");
    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), 0, "and no confirmation is owed by it");
}

/*
 * 9224-9225 at the dispatch: "If the receiving device has no routing capacity it SHALL discard the command
 * frame." An end device's tables do not move, and the counter names the gate 3.6.4.5.1's reception already puts in
 * front of a request.
 */
void caseRrepDroppedAtAnEndDevice(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_DataIndicationParameters inds[4];
    Nwk_RoutingTableEntry *route;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_END_DEVICE, 1);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    route = seedRoute(dev.nwk.routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_DISCOVERY_UNDERWAY, PREVIOUS_HOP);
    entry = seedDiscovery(dev.nwk.discoveries, 0, OWN_SHORT, REQUEST_ID, 0, 0,
                          NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    npduLen = composeReceivedRrep(npdu, OWN_SHORT, FAR_HOP, OWN_SHORT, RESPONDER_ADDRESS, CHEAPER_PATH_COST,
                                  REQUEST_ID);
    injectNpdu(&dev, npdu, npduLen, FAR_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS), ZB_OK, "a Route Reply received at an end device");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_RrepDroppedNoCapacity(&dev.nwk), 1,
                     "9224-9225: the reply is discarded, and the counter names the gate that refused it");
    Test_ExpectCount(route->status, NWK_ROUTE_DISCOVERY_UNDERWAY, "so no routing entry moves to ACTIVE");
    Test_ExpectCount(route->nextHopAddress, PREVIOUS_HOP, "and no next hop is replaced");
    Test_ExpectCount(entry->residualCost, 0, "and 9243's residual cost is not filled");
    Test_ExpectCount(Nwk_RrepDroppedNotSmaller(&dev.nwk), 0, "the cost comparisons never ran, so their counter stands");
    Test_ExpectCount(airCount, 0, "nothing is forwarded");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 0, "and nothing is indicated upward");
    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), 0, "nor is a confirmation owed by it");
}

/* 9258-9260: a forwarder's discovery entry with no routing entry for the responder is an error, and a discard. */
void caseRrepDroppedWhenTheForwarderHasNoRoute(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_RouteDiscoveryTableEntry *entry;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    entry = seedDiscovery(dev.nwk.discoveries, 0, ORIGINATOR_ADDRESS, REQUEST_ID, RECORDED_RESIDUAL_COST, 0,
                          NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);
    entry->senderAddress = PREVIOUS_HOP;

    npduLen = composeReceivedRrep(npdu, OWN_SHORT, FAR_HOP, ORIGINATOR_ADDRESS, RESPONDER_ADDRESS,
                                  FORWARDED_PATH_COST, REQUEST_ID);
    injectNpdu(&dev, npdu, npduLen, FAR_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS), ZB_OK, "a reply a forwarder holds a discovery entry for and a route for nobody");

    Test_ExpectCount(Nwk_RrepDroppedNoReverseRoute(&dev.nwk), 1,
                     "9258-9260: 'it is an error if the route discovery table entry exists and there is no corresponding routing table entry', and the frame SHOULD be discarded");
    Test_Expect(Nwk_DiscoveryOf(dev.nwk.discoveries, ORIGINATOR_ADDRESS, REQUEST_ID) != 0,
                "the entry the error names is left where it is: this branch removes nothing");
    Test_ExpectCount(Nwk_RouteQueue(&dev.nwk), 0, "and no route is made for the originator either");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "nothing is forwarded");
    Test_ExpectCount(Nwk_RouteRepliesForwarded(&dev.nwk), 0, "and the forward count says so");
}

/* 9254-9256: the forwarder's comparison, both ways, a dearer reply is dropped and a tying one is sent on. */
void caseRrepDroppedWhenTheForwarderCostIsNotSmaller(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_RoutingTableEntry *route;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    route = seedRoute(dev.nwk.routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_ACTIVE, FAR_HOP);
    entry = seedDiscovery(dev.nwk.discoveries, 0, ORIGINATOR_ADDRESS, REQUEST_ID, RECORDED_RESIDUAL_COST, 0,
                          NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);
    entry->senderAddress = PREVIOUS_HOP;
    entry->residualCost = CHEAPER_PATH_COST + LINK_COST_ONE;

    npduLen = composeReceivedRrep(npdu, OWN_SHORT, FAR_HOP, ORIGINATOR_ADDRESS, RESPONDER_ADDRESS,
                                  RECORDED_RESIDUAL_COST, REQUEST_ID);
    injectNpdu(&dev, npdu, npduLen, FAR_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS), ZB_OK,
                      "a reply whose cost through this hop is 5, against a recorded 3");

    Test_ExpectCount(Nwk_RrepDroppedNotSmaller(&dev.nwk), 1,
                     "9254-9256: 'If the route discovery table entry value is less than the route reply value, the route reply command frame shall be discarded'");
    Test_ExpectCount(entry->residualCost, CHEAPER_PATH_COST + LINK_COST_ONE, "and the recorded cost stands");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "with nothing forwarded");

    npduLen = composeReceivedRrep(npdu, OWN_SHORT, FAR_HOP, ORIGINATOR_ADDRESS, RESPONDER_ADDRESS,
                                  CHEAPER_PATH_COST, REQUEST_ID);
    injectNpdu(&dev, npdu, npduLen, FAR_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW_MS + 1), ZB_OK, "and one that ties the recorded cost");

    Test_ExpectCount(Nwk_RrepDroppedNotSmaller(&dev.nwk), 1,
                     "9255 says 'less than', not 'not greater': a tie is not the discard it prints");
    Test_ExpectCount(Nwk_RouteRepliesForwarded(&dev.nwk), 1, "so that reply is forwarded");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "one frame on the air, for the reply that was sent on");
    Test_ExpectCount(airDestOf(&air[0]), PREVIOUS_HOP, "aimed at the sender address Table 3-79 holds");
    Test_ExpectCount(route->nextHopAddress, FAR_HOP, "and the routing entry's next hop is the device the reply came from");
}

/*
 * I.2.3 over a received reply: tag 1 is K.2.1.2's Concentrator Information in a *request*, and K.3.1.1 defines
 * no local id but tag 0, so tag 1 in a reply's tail is an Unknown Tag "neither a defined global ID nor … a
 * Local ID defined for the specific command", ignored whatever its length, and the route it brings is taken.
 */
void caseRrepUndefinedLocalTagIsIgnored(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_RoutingTableEntry *route;
    Nwk_RouteReplyPayload reply;
    Nwk_RouteReplyFields fields;
    Nwk_TlvSet tlvs;
    uint8_t payload[NWK_RREP_PAYLOAD_MAX + 3];   /* K.3.1.1's five octets and the three a stranger adds */
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t payloadLen;
    uint32_t npduLen;
    uint32_t routingSeq = REPLY_SEQUENCE - 1;
    uint32_t tail;
    uint32_t airCount = 0;
    uint32_t got;
    uint8_t requestId;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    startDiscovery(&dev, RESPONDER_ADDRESS);

    route = Nwk_RouteOf(dev.nwk.routes, RESPONDER_ADDRESS);
    requestId = dev.nwk.routeRequestId;

    harvestAir(&dev.model, air, &airCount);
    Test_Expect(route != 0 && route->status == NWK_ROUTE_DISCOVERY_UNDERWAY && airCount == 1,
                "the discovery is running: its first broadcast is out and its entry waits on a reply");

    Zb_memset(&reply, 0, (uint32_t)sizeof reply);

    reply.requestId = requestId;
    reply.originatorAddr = OWN_SHORT;
    reply.responderAddr = RESPONDER_ADDRESS;
    reply.pathCost = CHEAPER_PATH_COST;
    reply.originatorIeee = 0x1112131415161718;
    reply.responderIeee = 0x2122232425262728;

    Test_ExpectStatus(Nwk_RrepCompose(&reply, &routingSeq, payload, (uint32_t)sizeof payload, &payloadLen), ZB_OK,
                      "Figure 3-11's payload, composed by this stack's own codec");

    tail = payloadLen;
    payload[payloadLen++] = NWK_TLV_TAG_CONCENTRATOR;   /* 1: K.2.1.2's id, which a reply does not define */
    payload[payloadLen++] = 0x00;                       /* Table I-1: one value octet, Figure K-2 prints two */
    payload[payloadLen++] = 0xaa;

    Test_ExpectCount((uint32_t)Nwk_TlvRead(NWK_CMD_ROUTE_REPLY, payload + tail, payloadLen - tail, &tlvs),
                     NWK_TLV_OK, "I.2.3: the reply's walk ignores it and names no record");
    Test_ExpectCount(tlvs.concentratorInfo, 0, "K.2.1.2's record is the request's, so nothing of it is reported");
    Test_ExpectStatus(Nwk_RrepParse(payload, payloadLen, &fields), ZB_OK,
                      "so the reply itself is a message this stack reads");
    Test_ExpectCount(fields.tlvOutcome, NWK_TLV_OK, "with its tail read and the unknown id passed over");
    Test_ExpectCount(fields.routingSequenceNumber, REPLY_SEQUENCE, "K.3.1.1.1: and its own record interpreted");

    npduLen = makeNpdu(npdu, OWN_SHORT, FAR_HOP, (uint8_t)RECEIVED_RADIUS, REPLY_SEQ, NWK_FRAME_TYPE_COMMAND, 0,
                       payload, payloadLen);
    injectNpdu(&dev, npdu, npduLen, FAR_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + 1), ZB_OK, "the turn the reply arrives on");

    Test_ExpectCount(route->status, NWK_ROUTE_ACTIVE,
                     "9240-9243: the route the reply brings is taken, where a dropped reply would have left it waiting");
    Test_ExpectCount(route->nextHopAddress, FAR_HOP, "and its next hop is the device that forwarded the reply");
    Test_ExpectCount(Nwk_DroppedMalformed(&dev.nwk), 0, "nothing was malformed on receipt");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_ExpectCount(got, 0, "the held frame is not answered on the turn that made the route, since the send is the next step's");

    entry = Nwk_DiscoveryOf(dev.nwk.discoveries, OWN_SHORT, requestId);

    Test_ExpectCount(entry ? entry->residualCost : 0, CHEAPER_PATH_COST,
                     "9243: and the residual cost is the payload's own field, 2");
    Test_ExpectCount(Nwk_RrepDroppedNoDiscovery(&dev.nwk), 0, "no reply was discarded for want of an entry");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + 1 + NWK_RREQ_RETRY_INTERVAL_MS), ZB_OK,
                      "the turn the MAC's answer to that frame is drained");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 2, "the discovery's broadcast plus the frame 3.6.4.5.1's MAY chose to hold, issued the turn the reply arrived");
    Test_ExpectCount(airDestOf(&air[1]), FAR_HOP, "over Table 3-77's next hop, not over the reply's source alone");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_ExpectCount(got, 1, "and the request that waited on the discovery is answered, once, by that attempt");
    Test_ExpectStatus(confirms[0].status, ZB_OK, "with SUCCESS");
    Test_ExpectCount(confirms[0].dstAddr, RESPONDER_ADDRESS, "for the destination it was asked about");
    Test_ExpectCount(confirms[0].attempts, 1, "one attempt counted");
}
