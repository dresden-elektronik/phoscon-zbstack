/* 3.6.4.5.1's reception and 3.6.4.5.2's two halves, case by case: a small network built from the pools the
   suite owns and the decision each received command leaves. Every number a case asserts is one the clause
   prints (Table 3-76's mapping, 9122-9124's worse direction, gap G3's clamp, 9137's "greater", 9247's "not
   smaller", 9151's timer) and each case names the branch it reddens if the branch is taken differently.
   No `Nwk_Nwk`, no MAC and no radio: the tables are arrays on the case's stack and the clock is `nowMs`. */

#include "nwk_routeflow_cases.h"

#include "nwk.h"
#include "nwk_cost.h"
#include "nwk_discovery.h"
#include "nwk_neighbor.h"
#include "nwk_rreprx.h"
#include "nwk_rreqrx.h"
#include "nwk_route.h"
#include "nwk_routeflow_helpers.h"
#include "test_harness.h"
#include "zb_utils.h"

enum
{
    OWN_ADDRESS = 0x1010,           /* this device: 3.4.1.3.3's destination for a discovery aimed at itself */
    SENDER_ADDRESS = 0x0100,        /* the device that transmitted the frame: 9125's next hop */
    SOURCE_ADDRESS = 0x1234,        /* the request's initiator in the NWK header (3.4.1.2) */
    RESPONDER_ADDRESS = 0x2345,     /* 3.4.2.3.4 */
    FORWARDER_ADDRESS = 0x0303,     /* a device that is neither the originator nor the responder */
    PREVIOUS_HOP = 0x0200,          /* Table 3-79's sender address a seeded discovery holds: the way back to the source */
    CHILD_ADDRESS = 0x0c11,         /* an end device this router parents (9112-9116) */
    OLD_NEXT_HOP = 0x0bad,          /* the next hop a seeded entry already holds */
    LQA_WORSE_INCOMING = 200,       /* Table 3-76: 192 < 200 <= 255, so the incoming cost is 1 */
    OUTGOING_COST_TWO = 2,          /* Table 3-75's Outgoing Cost, the other half of 9122-9124 */
    NOW_MS = 1000,                  /* the clock a case hands in; 9151's timer is 10000 ms past it */
    RECORDED_RESIDUAL_COST = 2,     /* Table 3-79's residual cost, the local route's cost 3.6.4.5.3 compares against */
    LOOPING_PATH_COST = 6,          /* with this hop's link cost of 1, a route dearer than the one held */
    LINK_COST_ONE = 1               /* Table 3-76: an LQA of 200 and an outgoing cost of 1 are the worse direction 1 */
};

/* The three pools every flow case owns, cleared together so a leftover entry cannot pass for a decision */
static void clearPools(Nwk_NeighborTableEntry *neighbors, Nwk_RoutingTableEntry *routes, Nwk_RouteDiscoveryTableEntry *discoveries)
{
    Zb_memset(neighbors, 0, (uint32_t)sizeof(Nwk_NeighborTableEntry) * NWK_NEIGHBOR_MAX);
    Zb_memset(routes, 0, (uint32_t)sizeof(Nwk_RoutingTableEntry) * NWK_ROUTE_MAX);
    Zb_memset(discoveries, 0, (uint32_t)sizeof(Nwk_RouteDiscoveryTableEntry) * NWK_DISCOVERY_MAX);
}

/* A neighbor whose measured link is Table 3-76's cost 1 and whose outgoing cost is the same 1: link cost 1 */
static void clearPoolsWithLinkOfOne(Nwk_NeighborTableEntry *neighbors, Nwk_RoutingTableEntry *routes, Nwk_RouteDiscoveryTableEntry *discoveries)
{
    clearPools(neighbors, routes, discoveries);
    (void)seedFlowNeighbor(neighbors, 0, SENDER_ADDRESS, LQA_WORSE_INCOMING, 1);
}

void caseRreqRxDropsWhenThereIsNoNeighbourEntry(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RouteRequestFields fields = rreqFieldsAt(OWN_ADDRESS, 0);
    Nwk_Frame frame = receivedRreq(SOURCE_ADDRESS, 29);
    Nwk_RreqRxDecision decision;

    clearPools(neighbors, routes, discoveries);

    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_NO_NEIGHBOR, "9119-9120: no neighbor entry for the transmitting device");
    Test_ExpectCount(Nwk_DiscoveryCount(discoveries), 0, "and Table 3-79 takes no entry");
    Test_ExpectCount(Nwk_RouteCount(routes), 0, "and no reverse route is made");

    Test_Expect(Nwk_DiscoveryOf(discoveries, SOURCE_ADDRESS, fields.requestId) == 0,
                "the key answers no slot either, live or expired");
}

void caseRreqRxDropsWhenTheNeighbourHasNoOutgoingCost(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RouteRequestFields fields = rreqFieldsAt(OWN_ADDRESS, 0);
    Nwk_Frame frame = receivedRreq(SOURCE_ADDRESS, 29);
    Nwk_RreqRxDecision decision;

    clearPools(neighbors, routes, discoveries);
    (void)seedFlowNeighbor(neighbors, 0, SENDER_ADDRESS, LQA_WORSE_INCOMING, 0);

    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_OUTGOING_COST_ZERO,
                     "9121-9124: the outgoing cost field has a value of 0, so the frame is discarded");
    Test_ExpectCount(Nwk_CostFromLqa(LQA_WORSE_INCOMING), 1,
                     "and the incoming cost of that neighbor is not 0: the gate is the outgoing field, not the measurement");
    Test_ExpectCount(Nwk_DiscoveryCount(discoveries), 0, "route request processing is terminated: nothing is created");
    Test_ExpectCount(Nwk_RouteCount(routes), 0, "and no reverse route is made");
    Test_ExpectCount(decision.forwardCost, 0, "a dropped request carries no forwarded cost");
}

void caseRreqRxUsesTheWorseDirection(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RouteRequestFields fields = rreqFieldsAt(RESPONDER_ADDRESS, 0);
    Nwk_Frame frame = receivedRreq(SOURCE_ADDRESS, 29);
    Nwk_RreqRxDecision decision;

    clearPools(neighbors, routes, discoveries);
    (void)seedFlowNeighbor(neighbors, 0, SENDER_ADDRESS, LQA_WORSE_INCOMING, OUTGOING_COST_TWO);

    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_FORWARD_RELAY, "a forwarder relays the request with the cost it rewrote");
    Test_ExpectCount(Nwk_CostFromLqa(LQA_WORSE_INCOMING), 1, "Table 3-76: an LQA of 200 is the incoming cost 1");
    Test_ExpectCount(OUTGOING_COST_TWO, 2, "and the outgoing cost is 2");
    Test_ExpectCount(decision.forwardCost, OUTGOING_COST_TWO,
                     "9122-9124: the maximum of the two, so the path cost grows by 2 and not by 1");
}

void caseRreqRxClampsTheForwardCost(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_RouteRequestFields fields = rreqFieldsAt(RESPONDER_ADDRESS, 0xfe);
    Nwk_Frame frame = receivedRreq(SOURCE_ADDRESS, 29);
    Nwk_RreqRxDecision decision;

    clearPools(neighbors, routes, discoveries);
    (void)seedFlowNeighbor(neighbors, 0, SENDER_ADDRESS, LQA_WORSE_INCOMING, OUTGOING_COST_TWO);

    (void)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries, OWN_ADDRESS,
                     NWK_DEVICE_ROUTER, NOW_MS, &decision);

    entry = Nwk_DiscoveryOf(discoveries, SOURCE_ADDRESS, fields.requestId);

    Test_ExpectCount(decision.forwardCost, NWK_COST_MAX,
                     "gap G3: 0xfe plus 2 is clamped at 0xff, the cap C(P) prints, and never wraps to 0x00");
    Test_ExpectCount(entry ? entry->forwardCost : 0, NWK_COST_MAX,
                     "Table 3-79 stores the clamped cost, which is what the dedup then compares");
}

/* 3.6.4.5.1.1 (9112-9116): the destination test is this device *or one of its end device children*, a router
   answering on the child's behalf because a sleepy child never hears the request itself. */
void caseRreqRxAnswersForAnEndDeviceChild(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_NeighborTableEntry *child;
    Nwk_RouteRequestFields fields = rreqFieldsAt(0x0000, 0);
    Nwk_Frame frame = receivedRreq(SOURCE_ADDRESS, 29);
    Nwk_RreqRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);

    child = seedFlowNeighbor(neighbors, 1, CHILD_ADDRESS, LQA_WORSE_INCOMING, 1);
    Test_Expect(child != 0, "a neighbour entry for the child this device parents");

    child->relationship = NWK_REL_CHILD;
    child->deviceType = NWK_DEVICE_END_DEVICE;

    fields.destAddr = CHILD_ADDRESS;
    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_DESTINATION_REPLY,
                     "9112-9116: a request whose destination is this device's end device child is answered here, the child itself being asleep");

    child->deviceType = NWK_DEVICE_ROUTER;
    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_FORWARD_RELAY,
                     "while a child that is a router answers for itself, so the request is forwarded");

    child->deviceType = NWK_DEVICE_END_DEVICE;
    child->relationship = NWK_REL_SIBLING;
    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_FORWARD_RELAY,
                     "and an end device that is not this device's child is not answered for either");
}

void caseRreqRxDedupsOnAGreaterPathCost(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_RouteRequestFields fields = rreqFieldsAt(RESPONDER_ADDRESS, 0);
    Nwk_Frame frame = receivedRreq(SOURCE_ADDRESS, 29);
    Nwk_RreqRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);
    entry = seedDiscovery(discoveries, 0, SOURCE_ADDRESS, 0x09, 3, 0, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    fields.pathCost = 4;
    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_GREATER_FORWARD_COST,
                     "9137-9141: a path cost greater than the recorded forward cost drops the frame");
    Test_ExpectCount(entry->forwardCost, 3, "and the recorded forward cost stands");
    Test_ExpectCount(entry->senderAddress, 0x0200, "and so does the recorded sender");

    fields.pathCost = 2;
    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_FORWARD_RELAY, "a lower path cost is taken");
    Test_ExpectCount(entry->forwardCost, 3, "and the forward cost is rewritten: 2 plus the link cost of 1");
    Test_ExpectCount(entry->senderAddress, SENDER_ADDRESS, "and the sender address is updated with it");
    Test_ExpectCount(Nwk_DiscoveryCount(discoveries), 1, "the key keeps its one slot");

    /* 9137's value is the frame's path cost *plus* this link's: 3 and 1 against a recorded 3 is greater, though the
       frame's own field is not. Comparing the raw field would take this frame, which is the mutation this case holds. */
    fields.pathCost = 3;
    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_GREATER_FORWARD_COST,
                     "9134-9140: the value compared is the link cost added to the frame's path cost, so 3 plus 1 is greater than the recorded 3 even though the field itself is not");
    Test_ExpectCount(entry->forwardCost, 3, "and neither cost moves: the advertisement updated nothing");
    Test_ExpectCount(entry->senderAddress, SENDER_ADDRESS, "nor did the sender address");
    Test_ExpectCount(Nwk_DiscoveryCount(discoveries), 1, "no second slot was ever claimed for the same key");

    /* The recorded forward cost 3 and a copy that advertises exactly that: LoopFree's printed boundary is "<=", so
       an as-good advertisement is no loop, but it is a duplicate of the arrival the relay already answered, which
       is what the queue behind this module decides (3.6.4.5.1.4's MAY) rather than this test */
    fields.pathCost = 2;
    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_FORWARD_RELAY,
                     "a copy whose accumulated cost equals the recorded one is accepted: 'path-cost(R1) <= path-cost(R2)'");
    Test_ExpectCount(entry->forwardCost, 3, "with the forward cost where it was");
    Test_ExpectCount(entry->senderAddress, SENDER_ADDRESS, "and the sender it came from");
}

void caseRreqRxMakesTheReverseRouteForADestination(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RoutingTableEntry *reverse;
    Nwk_RouteRequestFields fields = rreqFieldsAt(OWN_ADDRESS, 0);
    Nwk_Frame frame = receivedRreq(SOURCE_ADDRESS, 29);
    Nwk_RreqRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);

    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_DESTINATION_REPLY, "3.6.4.5.1.1: this device is 3.4.1.3.3's destination");

    reverse = Nwk_RouteOf(routes, SOURCE_ADDRESS);

    Test_Expect(reverse != 0, "9125-9142: the routing table gains an entry for the request's source");
    Test_ExpectCount(reverse ? reverse->nextHopAddress : 0, SENDER_ADDRESS,
                     "with the previous device that transmitted the command frame as its next hop");
    Test_ExpectCount(reverse ? reverse->status : 0xff, NWK_ROUTE_ACTIVE, "and the status field set to ACTIVE");
    Test_ExpectCount(decision.sourceAddr, SOURCE_ADDRESS, "the decision answers with the source the route names");
    Test_ExpectCount(decision.senderAddr, SENDER_ADDRESS, "and with the sender the reply is aimed at");
    Test_ExpectCount(decision.requestId, 0x09, "and with the request id the reply copies (3.4.2.3.2)");
    Test_ExpectCount(decision.expiryMs, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS,
                     "9151: the route request timer expires in nwkcRouteDiscoveryTime, 10000 ms");
}

/*
 * Table 3-77's four fields nothing used to write, each with the writer its own clause names: 9154-9162 marks a
 * many-to-one reverse route, 3.6.4.5.1.8 keeps that mark when a unicast request finds it, and K.2.1.1.1's record is
 * the "last route message that successfully updated this entry and conveyed a sequence number".
 */
void caseRreqRxWritesTable377sFourFields(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RoutingTableEntry *reverse;
    Nwk_RouteRequestFields fields = rreqFieldsAt(NWK_ADDR_ROUTERS, 0);
    Nwk_Frame frame = receivedRreq(SOURCE_ADDRESS, 29);
    Nwk_RreqRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);

    fields.manyToOne = NWK_RREQ_MANY_TO_ONE_WITHOUT_RECORD;
    fields.extendedRouteInfo = 1;
    fields.routingSequenceNumber = 0x4321;

    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_FORWARD_RELAY, "a many-to-one request, relayed on");

    reverse = Nwk_RouteOf(routes, SOURCE_ADDRESS);

    Test_Expect(reverse != 0, "9125-9142 makes the reverse route towards the request's source");
    Test_ExpectCount(reverse ? reverse->manyToOne : 0, 1,
                     "9158: the many-to-one field in the routing table entry SHALL be set to TRUE");
    Test_ExpectCount(reverse ? reverse->routeRecordRequired : 0, 1,
                     "9159: and the route record required field SHALL be set to TRUE");
    Test_ExpectCount(reverse ? reverse->noRouteCache : 0, 1,
                     "9160: the no route cache flag is TRUE for Table 3-55's value 2, the sender without a record table");
    Test_ExpectCount(reverse ? reverse->sequenceNumber : 0, 0x4321,
                     "Table 3-77: the number the last route message conveyed, K.2.1.1.1's");
    Test_ExpectCount(reverse ? reverse->sequenceNumberValid : 0, 1, "with its valid flag set");

    /* 3.6.4.5.1.8: "When a device receives a route request command, which is not a many-to-one route request, where a
       routing table entry for the destination exists, which has the many-to-one flag set to TRUE, it will not reset
       this flag to FALSE", and Table 3-55's value 1 is the record-table half of the same field */
    fields.manyToOne = NWK_RREQ_MANY_TO_ONE_NONE;

    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_FORWARD_RELAY, "a unicast request through the same device");

    Test_ExpectCount(reverse ? reverse->manyToOne : 0, 1, "3.6.4.5.1.8: the many-to-one flag is not reset");
    Test_ExpectCount(reverse ? reverse->noRouteCache : 0, 1, "and the no route cache flag it was given stands");

    Zb_memset(routes, 0, (uint32_t)sizeof(Nwk_RoutingTableEntry) * NWK_ROUTE_MAX);
    Zb_memset(discoveries, 0, (uint32_t)sizeof(Nwk_RouteDiscoveryTableEntry) * NWK_DISCOVERY_MAX);

    fields.manyToOne = NWK_RREQ_MANY_TO_ONE_WITH_RECORD;

    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_FORWARD_RELAY, "a many-to-one request whose sender keeps a route record table");

    reverse = Nwk_RouteOf(routes, SOURCE_ADDRESS);

    Test_ExpectCount(reverse ? reverse->noRouteCache : 0xffff, 0,
                     "9160-9161: the flag is FALSE for Table 3-55's value 1, and TRUE only for 2");
}

void caseRreqRxForwardsWithTheRewrittenCost(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RouteRequestFields fields = rreqFieldsAt(RESPONDER_ADDRESS, 5);
    Nwk_Frame frame = receivedRreq(SOURCE_ADDRESS, 29);
    Nwk_RreqRxDecision decision;

    clearPools(neighbors, routes, discoveries);
    (void)seedFlowNeighbor(neighbors, 0, SENDER_ADDRESS, LQA_WORSE_INCOMING, OUTGOING_COST_TWO);

    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_ROUTER, NOW_MS, &decision),
                     NWK_RREQ_RX_FORWARD_RELAY, "a device that is not the destination relays the request");
    Test_ExpectCount(decision.forwardCost, 7, "with the rewritten path cost: 5 plus the worse direction's 2");
    Test_Expect(decision.outcome != NWK_RREQ_RX_FORWARDER_REPLY,
                "9142-9147's forwarder reply stays the named deviation: only the destination answers");
    Test_ExpectCount(decision.destination, RESPONDER_ADDRESS, "the destination the caller compares against itself");
    Test_ExpectCount(decision.radius, 29, "and 3.4.1.2's radius as received, whose decrement is the header's");
}

void caseRreqRxDropsAtAnEndDevice(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RouteRequestFields fields = rreqFieldsAt(OWN_ADDRESS, 0);
    Nwk_Frame frame = receivedRreq(SOURCE_ADDRESS, 29);
    Nwk_RreqRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);

    Test_ExpectCount((uint32_t)Nwk_RreqRx(&fields, &frame, SENDER_ADDRESS, neighbors, routes, discoveries,
                                          OWN_ADDRESS, NWK_DEVICE_END_DEVICE, NOW_MS, &decision),
                     NWK_RREQ_RX_END_DEVICE, "3.6.4.5.1, 9090: an end device SHALL drop the frame");
    Test_ExpectCount(Nwk_DiscoveryCount(discoveries), 0, "even for a neighbor with a usable link");
    Test_ExpectCount(Nwk_RouteCount(routes), 0, "nothing is created at all");
}

void caseRrepRxOriginatorTakesTheUnderwayEntry(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_RoutingTableEntry *route;
    Nwk_RouteReplyFields fields = rrepFieldsAt(OWN_ADDRESS, RESPONDER_ADDRESS, 4);
    Nwk_Frame frame = receivedRrep(SENDER_ADDRESS);
    Nwk_RrepRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);
    route = seedRoute(routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_DISCOVERY_UNDERWAY, OLD_NEXT_HOP);
    entry = seedDiscovery(discoveries, 0, OWN_ADDRESS, 0x09, 3, 0, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, OWN_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_ORIGINATOR_ROUTE,
                     "9240-9243: a DISCOVERY_UNDERWAY entry is changed to ACTIVE by the reply that answers it");
    Test_ExpectCount(decision.pathCost, 0,
                     "9266-9269: the originator forwards nothing, so no incremented cost is produced for a relay");
    Test_ExpectCount(route->status, NWK_ROUTE_ACTIVE, "the routing entry's status");
    Test_ExpectCount(route->nextHopAddress, SENDER_ADDRESS, "and its next hop is the device that forwarded the reply");
    Test_ExpectCount(route->ageMs, NOW_MS, "the entry was used now");
    Test_ExpectCount(entry->residualCost, 4,
                     "9243: the residual cost is the path cost field the payload carries, not that field plus this hop's link cost");
    Test_ExpectCount(decision.originator, 1, "3.4.2.3.3 named this device as the originator");
}

/*
 * 3.6.4.5.3 step 2 at the one acceptance that prints no cost comparison of its own: 9240-9243 takes a
 * `DISCOVERY_UNDERWAY` entry to ACTIVE whatever the reply costs, so the loop test is the only thing standing between
 * a dearer advertisement and a route re-pointed at a path that runs back through this device. Table 3-79's residual
 * cost is the local route's cost: the only record of it Table 3-77 does not print (9248, 9256).
 */
void caseRrepRxRefusesALoopingReply(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_RoutingTableEntry *route;
    Nwk_RouteReplyFields fields = rrepFieldsAt(OWN_ADDRESS, RESPONDER_ADDRESS, LOOPING_PATH_COST);
    Nwk_Frame frame = receivedRrep(SENDER_ADDRESS);
    Nwk_RrepRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);
    route = seedRoute(routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_DISCOVERY_UNDERWAY, OLD_NEXT_HOP);
    entry = seedDiscovery(discoveries, 0, OWN_ADDRESS, 0x09, 3, RECORDED_RESIDUAL_COST,
                          NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, OWN_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_UNSUITABLE,
                     "3.6.4.5.3 step 2: the advertised route costs more than the one this device holds, so LoopFree answers FALSE and the reply is discarded (9248)");
    Test_ExpectCount(decision.pathCost, 0,
                     "9266-9269: an originator forwards nothing, so no incremented cost is produced");
    Test_ExpectCount(entry ? entry->residualCost : 0, RECORDED_RESIDUAL_COST,
                     "9244-9249: the compared value is the payload's own field, so the recorded residual stands unchanged");
    Test_Expect(route != 0 && route->status == NWK_ROUTE_DISCOVERY_UNDERWAY,
                "and the entry it would have re-pointed is untouched: the acceptance 9240-9243 prints never ran");
    Test_ExpectCount(route ? route->nextHopAddress : 0, OLD_NEXT_HOP, "its next hop is the one it held");
    Test_ExpectCount(entry ? entry->residualCost : 0, RECORDED_RESIDUAL_COST,
                     "and 9243's residual cost is still the path this device holds");

    /* The boundary the definition prints: "path-cost(R1) <= path-cost(R2)". A reply whose cost lands exactly on the
       recorded one is no loop, and the acceptance goes ahead. */
    fields.pathCost = (uint8_t)(RECORDED_RESIDUAL_COST - LINK_COST_ONE);

    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, OWN_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_ORIGINATOR_ROUTE,
                     "a reply whose cost equals the recorded one passes step 2: the comparison is <=, not <");
    Test_Expect(route != 0 && route->status == NWK_ROUTE_ACTIVE, "and the entry becomes ACTIVE");
    Test_ExpectCount(route ? route->nextHopAddress : 0, SENDER_ADDRESS, "with the forwarding device as its next hop");
}

void caseRrepRxOriginatorComparesAgainstTheResidualCost(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_RoutingTableEntry *route;
    Nwk_RouteReplyFields fields = rrepFieldsAt(OWN_ADDRESS, RESPONDER_ADDRESS, 3);
    Nwk_Frame frame = receivedRrep(SENDER_ADDRESS);
    Nwk_RrepRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);
    route = seedRoute(routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_ACTIVE, OLD_NEXT_HOP);
    entry = seedDiscovery(discoveries, 0, OWN_ADDRESS, 0x09, 3, 3, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, OWN_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_COST_NOT_SMALLER,
                     "9247-9249: a path cost that is not smaller than the recorded one discards the reply");
    Test_ExpectCount(entry->residualCost, 3, "and the recorded residual cost stands");
    Test_ExpectCount(route->nextHopAddress, OLD_NEXT_HOP, "and so does the next hop");

    fields.pathCost = 1;
    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, OWN_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_ORIGINATOR_CHEAPER, "9244-9249: a smaller path cost is taken");
    Test_ExpectCount(decision.pathCost, 0, "9266-9269: an originator forwards nothing");
    Test_ExpectCount(entry->residualCost, 1,
                     "9244-9246: the residual follows the payload's own field, 1, and not that field plus this hop's link cost");
    Test_ExpectCount(route->nextHopAddress, SENDER_ADDRESS, "and the route turns onto the cheaper path");

    fields.pathCost = 2;
    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, OWN_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_COST_NOT_SMALLER,
                     "9250's 'not smaller' is not 'greater': a reply that ties the recorded cost is discarded");
    Test_ExpectCount(entry->residualCost, 1, "and the tie changes nothing");
}

void caseRrepRxOriginatorRemovesTheDiscoveryEntryWithNoRoute(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RouteReplyFields fields = rrepFieldsAt(OWN_ADDRESS, RESPONDER_ADDRESS, 4);
    Nwk_Frame frame = receivedRrep(SENDER_ADDRESS);
    Nwk_RrepRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);
    (void)seedDiscovery(discoveries, 0, OWN_ADDRESS, 0x09, 3, 0, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, OWN_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_NO_ROUTE_REMOVED,
                     "9231-9249: no routing entry for the responder's address discards the reply");
    Test_Expect(Nwk_DiscoveryOf(discoveries, OWN_ADDRESS, 0x09) == 0,
                "and the discovery entry is removed, not merely ignored: the key answers no slot");
    Test_ExpectCount(Nwk_DiscoveryCount(discoveries), 0, "the table is a slot emptier than it was");
    Test_ExpectCount(Nwk_RouteCount(routes), 0, "and no route was made for the responder");
}

/*
 * Table 3-77's Sequence Number and its valid flag as a route reply writes them: "obtained from the last route message
 * that successfully updated this entry and conveyed a sequence number", which for a reply is K.3.1.1.1's record, and
 * K.4.1.1 reads the same flag before it puts that number in a route-error status.
 */
void caseRrepRxWritesTheRespondersRoutingSequenceNumber(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RoutingTableEntry *route;
    Nwk_RouteReplyFields fields = rrepFieldsAt(OWN_ADDRESS, RESPONDER_ADDRESS, 4);
    Nwk_Frame frame = receivedRrep(SENDER_ADDRESS);
    Nwk_RrepRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);
    route = seedRoute(routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_ACTIVE, OLD_NEXT_HOP);
    (void)seedDiscovery(discoveries, 0, OWN_ADDRESS, 0x09, 3, 9, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    fields.extendedRouteInfo = 1;
    fields.routingSequenceNumber = 0x1235;

    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, OWN_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_ORIGINATOR_CHEAPER, "9244-9249: a cheaper reply replaces the next hop");

    Test_ExpectCount(route ? route->sequenceNumber : 0, 0x1235,
                     "Table 3-77: the routing sequence number the reply's record conveyed (K.3.1.1.1)");
    Test_ExpectCount(route ? route->sequenceNumberValid : 0, 1, "and its valid flag");

    /* K.3.1.1 tolerates a reply from a device built to an earlier revision; with no record there is no number to
       record, and the flag K.4.1.1 reads stays where it was */
    Zb_memset(routes, 0, (uint32_t)sizeof(Nwk_RoutingTableEntry) * NWK_ROUTE_MAX);
    route = seedRoute(routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_ACTIVE, OLD_NEXT_HOP);
    fields.extendedRouteInfo = 0;
    fields.pathCost = 2;

    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, OWN_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_ORIGINATOR_CHEAPER, "the same reply from a device that conveys no number");

    Test_ExpectCount(route ? route->sequenceNumberValid : 0xff, 0,
                     "and the valid flag stays clear: there is no sequence number (Table 3-77's own condition)");
}

void caseRrepRxForwarderComparesAgainstTheResidualCost(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_RoutingTableEntry *route;
    Nwk_RoutingTableEntry *reverse;
    Nwk_RouteReplyFields fields = rrepFieldsAt(SOURCE_ADDRESS, RESPONDER_ADDRESS, 4);
    Nwk_Frame frame = receivedRrep(SENDER_ADDRESS);
    Nwk_RrepRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);
    (void)seedFlowNeighbor(neighbors, 1, PREVIOUS_HOP, LQA_WORSE_INCOMING, 1);
    route = seedRoute(routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_ACTIVE, OLD_NEXT_HOP);
    entry = seedDiscovery(discoveries, 0, SOURCE_ADDRESS, 0x09, 3, 3, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, FORWARDER_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_COST_NOT_SMALLER,
                     "9251-9256: the entry's residual cost is the lesser one, so the reply is discarded");
    Test_ExpectCount(entry->residualCost, 3, "and it stands");
    Test_ExpectCount(route->nextHopAddress, OLD_NEXT_HOP, "and so does the route the entry names");

    fields.pathCost = 1;
    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, FORWARDER_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_FORWARDED, "a lesser path cost is relayed on");
    Test_ExpectCount(decision.pathCost, 2,
                     "9266-9269: the forwarded cost is the payload's 1 plus the link cost to the next hop, which this rig gives 1");
    Test_ExpectCount(entry->residualCost, 1,
                     "9262-9263: the residual cost is replaced by the value in the route reply command frame, which is 1");
    Test_ExpectCount(route->nextHopAddress, SENDER_ADDRESS, "9256-9260: and the next hop by the forwarding device");

    reverse = Nwk_RouteOf(routes, SOURCE_ADDRESS);

    Test_Expect(reverse != 0, "9279-9285: relaying the reply makes a reverse route where none exists");
    Test_ExpectCount(reverse ? reverse->destinationAddress : 0, SOURCE_ADDRESS, "its destination is the reply's originator");
    Test_ExpectCount(reverse ? reverse->nextHopAddress : 0, PREVIOUS_HOP,
                     "9282-9283: its next hop is Table 3-79's sender address (the next hop in the route reply being relayed (9266-9272)) and not the device the reply came from");
    Test_Expect(reverse != 0 && reverse->nextHopAddress != SENDER_ADDRESS,
                "which is the value the forward route to the responder took (9256-9261), a different hop");
    Test_ExpectCount(reverse ? reverse->status : 0xff, NWK_ROUTE_ACTIVE, "and its status is ACTIVE");

    entry->residualCost = 0;
    fields.pathCost = 9;
    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, FORWARDER_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_FORWARDED,
                     "a residual cost of 0 is one no reply has filled: the first reply through an entry is taken");
    Test_ExpectCount(entry->residualCost, 9,
                     "9262-9263: and the entry holds the payload's 9, the forwarded copy being the one that carries the link cost");
    Test_ExpectCount(Nwk_RouteCount(routes), 2, "the reverse route is made once and never a second time");
}

/* A relay's entry is the one 9195 marked DISCOVERY_UNDERWAY, and 9258-9263 prints only its next hop and cost; the
   reply it forwards takes it to ACTIVE as the originator's does (docs/internals/decisions.md), or 8852-8856 would have it rediscover the
   route, and a route through two relays would carry nothing. */
void caseRrepRxForwarderActivatesTheUnderwayEntry(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RoutingTableEntry *route;
    Nwk_RouteReplyFields fields = rrepFieldsAt(SOURCE_ADDRESS, RESPONDER_ADDRESS, 1);
    Nwk_Frame frame = receivedRrep(SENDER_ADDRESS);
    Nwk_RrepRxDecision decision;
    uint16_t nextHop = 0;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);
    (void)seedFlowNeighbor(neighbors, 1, PREVIOUS_HOP, LQA_WORSE_INCOMING, 1);
    route = seedRoute(routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_DISCOVERY_UNDERWAY, 0xffff);
    (void)seedDiscovery(discoveries, 0, SOURCE_ADDRESS, 0x09, 0, 0, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, FORWARDER_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_FORWARDED, "9251-9263: the reply passes a relay that holds the request's entry");
    Test_ExpectCount(route->nextHopAddress, SENDER_ADDRESS, "9261-9262: its next hop is the device that forwarded the reply");
    Test_ExpectCount(route->status, NWK_ROUTE_ACTIVE,
                     "and the relay's entry is ACTIVE, or 8852-8856 would have it rediscover what it just relayed");
    Test_Expect(Nwk_RouteNextHop(routes, neighbors, RESPONDER_ADDRESS, NOW_MS, &nextHop) && nextHop == SENDER_ADDRESS,
                "3.6.4.3: data for the responder is relayed over that next hop");
}

/*
 * 9283-9285: "If the reverse routing table entry already exists the next-hop address field shall be updated, if
 * necessary subject to suitability of incoming route information as defined in section 3.6.4.5.3." A reply the
 * comparison 9254-9256 lets through re-points the entry at Table 3-79's sender address; a dearer one (the
 * unsuitable advertisement of 9256) leaves it where it stands.
 */
void caseRrepRxRepointsAnExistingReverseRoute(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RoutingTableEntry *reverse;
    Nwk_RouteReplyFields fields = rrepFieldsAt(SOURCE_ADDRESS, RESPONDER_ADDRESS, 1);
    Nwk_Frame frame = receivedRrep(SENDER_ADDRESS);
    Nwk_RrepRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);
    (void)seedRoute(routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_ACTIVE, OLD_NEXT_HOP);
    reverse = seedRoute(routes, 1, SOURCE_ADDRESS, NWK_ROUTE_ACTIVE, OLD_NEXT_HOP);
    (void)seedDiscovery(discoveries, 0, SOURCE_ADDRESS, 0x09, 3, 3, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, FORWARDER_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_FORWARDED, "a reply whose cost the entry admits is relayed on");
    Test_ExpectCount(reverse->nextHopAddress, PREVIOUS_HOP,
                     "9279-9285: the reverse entry that already exists is re-pointed at Table 3-79's sender address");
    Test_ExpectCount(reverse->status, NWK_ROUTE_ACTIVE, "and it is ACTIVE, as the paragraph prints");
    Test_ExpectCount(Nwk_RouteCount(routes), 2, "no second entry is claimed for the originator it already answers for");

    fields.pathCost = LOOPING_PATH_COST;
    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, FORWARDER_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_COST_NOT_SMALLER,
                     "9254-9256 with 3.6.4.5.3 step 2: a dearer advertisement is the unsuitable incoming route, discarded");
    Test_ExpectCount(reverse->nextHopAddress, PREVIOUS_HOP, "and the reverse entry keeps the hop it holds: the update is conditional");
    Test_ExpectCount(Nwk_RouteCount(routes), 2, "with no entry added or dropped by the refusal");
}

/*
 * 9224-9225: "If the receiving device has no routing capacity it SHALL discard the command frame." An end device
 * judges nothing and writes nothing, the same gate 9090 puts in front of a route request.
 */
void caseRrepRxDiscardsAtAnEndDevice(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_RoutingTableEntry *route;
    Nwk_RouteReplyFields fields = rrepFieldsAt(OWN_ADDRESS, RESPONDER_ADDRESS, 1);
    Nwk_Frame frame = receivedRrep(SENDER_ADDRESS);
    Nwk_RrepRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);
    route = seedRoute(routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_DISCOVERY_UNDERWAY, OLD_NEXT_HOP);
    entry = seedDiscovery(discoveries, 0, OWN_ADDRESS, 0x09, 3, 0, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, OWN_ADDRESS, NWK_DEVICE_END_DEVICE, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_NO_ROUTING_CAPACITY,
                     "9224-9225: a reply at a device with no routing capacity is discarded where it stands");
    Test_ExpectCount(route->status, NWK_ROUTE_DISCOVERY_UNDERWAY, "so no routing entry moves to ACTIVE");
    Test_ExpectCount(route->nextHopAddress, OLD_NEXT_HOP, "and no next hop is replaced");
    Test_ExpectCount(entry->residualCost, 0, "and 9243's residual cost is not filled (Table 3-79's 0 stands)");
    Test_ExpectCount(Nwk_RouteCount(routes), 1, "nothing is made for the originator either");

    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, OWN_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_ORIGINATOR_ROUTE,
                     "and the same frame at a device with routing capacity takes the printed path: the gate is the device's device type");
}

void caseRrepRxForwarderWithoutARouteDiscards(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_RouteReplyFields fields = rrepFieldsAt(SOURCE_ADDRESS, RESPONDER_ADDRESS, 1);
    Nwk_Frame frame = receivedRrep(SENDER_ADDRESS);
    Nwk_RrepRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);
    entry = seedDiscovery(discoveries, 0, SOURCE_ADDRESS, 0x09, 3, 0, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);
    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, FORWARDER_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_NO_ROUTE_DISCARDED,
                     "9251-9256: a discovery entry with no corresponding routing entry is an error");
    Test_ExpectCount(entry->residualCost, 0, "the entry the error names is left as it was");
    Test_ExpectCount(Nwk_RouteCount(routes), 0, "and no route is made for either address");
}

void caseRrepRxDiscardsWithNoDiscoveryEntry(void)
{
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];
    Nwk_RoutingTableEntry *route;
    Nwk_RouteReplyFields fields = rrepFieldsAt(OWN_ADDRESS, RESPONDER_ADDRESS, 1);
    Nwk_Frame frame = receivedRrep(SENDER_ADDRESS);
    Nwk_RrepRxDecision decision;

    clearPoolsWithLinkOfOne(neighbors, routes, discoveries);
    route = seedRoute(routes, 0, RESPONDER_ADDRESS, NWK_ROUTE_DISCOVERY_UNDERWAY, OLD_NEXT_HOP);

    Test_ExpectCount((uint32_t)Nwk_RrepRx(&fields, &frame, OWN_ADDRESS, NWK_DEVICE_ROUTER, neighbors,
                                          routes, discoveries, NOW_MS, &decision),
                     NWK_RREP_RX_NO_DISCOVERY,
                     "9231: the reply is judged against a discovery entry, and none answers for its key");
    Test_ExpectCount(route->status, NWK_ROUTE_DISCOVERY_UNDERWAY, "so no entry is moved to ACTIVE");
    Test_ExpectCount(route->nextHopAddress, OLD_NEXT_HOP, "and no next hop is replaced");
}
