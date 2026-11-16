/* Route discovery across a gap, on an air where some devices cannot hear others: nothing here is seeded, so the
   neighbour tables and their costs are what the devices' own link status frames made of them. */

#include "mesh_air.h"
#include "nwk.h"
#include "nwk_helpers.h"
#include "nwk_route.h"
#include "nwk_routeflow_cases.h"
#include "test_harness.h"
#include "zb_utils.h"

enum
{
    MESH_PAN = 0xbeef,
    MESH_C = 0x0000,
    MESH_R1 = 0x1111,
    MESH_R2 = 0x2222,
    MESH_E = 0x3333,
    MESH_STRANGER = 0x5555,
    MESH_STEP_MS = 50,
    MESH_SETTLED_MS = 3 * NWK_LINK_STATUS_PERIOD_MS,
    MESH_DISCOVERY_MS = 12000
};

static Test_BandA s_c;
static Test_BandA s_r1;
static Test_BandA s_r2;
static Test_BandA s_e;
static Mesh_Air s_air;
static uint32_t s_nodeC;
static uint32_t s_nodeR1;
static uint32_t s_nodeR2;

static void meshLine(void)
{
    rigAtSeed(&s_c, MESH_C, MESH_PAN, NWK_DEVICE_COORDINATOR, 1, 0, 0x101);
    rigAtSeed(&s_r1, MESH_R1, MESH_PAN, NWK_DEVICE_ROUTER, 1, 0, 0x202);
    rigAtSeed(&s_r2, MESH_R2, MESH_PAN, NWK_DEVICE_ROUTER, 1, 0, 0x303);

    MeshAir_Init(&s_air);
    s_nodeC = MeshAir_Add(&s_air, &s_c);
    s_nodeR1 = MeshAir_Add(&s_air, &s_r1);
    s_nodeR2 = MeshAir_Add(&s_air, &s_r2);
}

/* `from` hands its NWK a frame for `to`, with discovery allowed. */
static void meshSend(Test_BandA *from, uint16_t to, uint32_t nowMs)
{
    static const uint8_t nsdu[4] = { 0xde, 0xad, 0xbe, 0xef };
    Nwk_DataRequestParameters req;

    req = nldeReq(to, nsdu, (uint32_t)sizeof nsdu, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&from->nwk, &req, nowMs), ZB_OK, "a frame handed to the NWK");
}

/* A data frame for the coordinator that `source` hands R2 asking for discovery, R2 holding no route there: the line
   settled, C and R2 deaf to each other, and E seeded as R2's end device child. */
static uint32_t meshChildFrameMarked(uint16_t source, int endDeviceInitiator)
{
    static const uint8_t nsdu[4] = { 0xc0, 0xff, 0xee, 0x01 };
    Nwk_Frame frame;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen = 0;
    uint32_t at;

    meshLine();
    MeshAir_Deaf(&s_air, s_nodeC, s_nodeR2);
    MeshAir_Deaf(&s_air, s_nodeR2, s_nodeC);

    at = MeshAir_Run(&s_air, 1, 1 + MESH_SETTLED_MS, MESH_STEP_MS);
    seedNeighbor(&s_r2.nwk, MESH_E, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);

    Test_Expect(Nwk_RouteOf(s_r2.nwk.routes, MESH_C) == 0, "R2 holds no route to the coordinator");

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = NWK_FRAME_TYPE_DATA;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.discoverRoute = NWK_DISCOVER_ENABLE;
    frame.destAddr = MESH_C;
    frame.srcAddr = source;
    frame.radius = 10;
    frame.sequenceNumber = 0x42;
    frame.endDeviceInitiator = endDeviceInitiator;

    Test_ExpectStatus(NwkFrame_Compose(&frame, nsdu, (uint32_t)sizeof nsdu, npdu, (uint32_t)sizeof npdu, &npduLen),
                      ZB_OK, "a data frame asking for discovery");

    injectNpdu(&s_r2, npdu, npduLen, source);

    return MeshAir_Run(&s_air, at, at + MESH_DISCOVERY_MS, MESH_STEP_MS);
}

static uint32_t meshChildFrame(uint16_t source)
{
    return meshChildFrameMarked(source, 0);
}

/* 9120-9122 on the air: C and R2 cannot hear each other. A route request sent before any link status dies at R1, whose
   cost for R2 is still 0; once the devices have exchanged link status the same request crosses, and the frame with it. */
void caseMeshRouteRequestWaitsForALinkStatus(void)
{
    Nwk_DataIndicationParameters inds[4];
    Nwk_NeighborTableEntry *entry;
    Nwk_RoutingTableEntry *route;
    uint32_t at;

    meshLine();
    MeshAir_Deaf(&s_air, s_nodeC, s_nodeR2);
    MeshAir_Deaf(&s_air, s_nodeR2, s_nodeC);

    at = MeshAir_Run(&s_air, 1, 1, MESH_STEP_MS);
    meshSend(&s_r2, MESH_C, at);
    at = MeshAir_Run(&s_air, at, at + MESH_DISCOVERY_MS, MESH_STEP_MS);

    Test_Expect(Nwk_RouteRequestsSent(&s_r2.nwk) > 0, "R2 broadcast its route request");
    Test_Expect(Nwk_RreqDroppedNoOutgoingCost(&s_r1.nwk) > 0, "9121: R1 discards it, no link status having named R1");
    Test_ExpectCount(Nwk_RouteRequestsSent(&s_r1.nwk), 0, "so R1 relays nothing");
    Test_ExpectCount(Test_NwkPoll(&s_c.nwk, inds, 4), 0, "and the coordinator has heard nothing of it");

    at = MeshAir_Run(&s_air, at, at + MESH_SETTLED_MS, MESH_STEP_MS);

    Test_Expect(Nwk_NeighborOf(s_c.nwk.neighbors, MESH_R2) == 0, "the gap holds: the coordinator holds no entry for R2");
    Test_Expect(Nwk_NeighborOf(s_r2.nwk.neighbors, MESH_C) == 0, "nor R2 for the coordinator");

    entry = Nwk_NeighborOf(s_r1.nwk.neighbors, MESH_R2);

    Test_ExpectCount(entry ? entry->outgoingCost : 0, 1, "and the link status exchange gave R1 a cost for R2");
    Test_ExpectCount(entry ? entry->relationship : 0xff, NWK_REL_SIBLING, "as a sibling");

    meshSend(&s_r2, MESH_C, at);
    at = MeshAir_Run(&s_air, at, at + MESH_DISCOVERY_MS, MESH_STEP_MS);

    route = Nwk_RouteOf(s_r2.nwk.routes, MESH_C);

    Test_Expect(Nwk_RouteRequestsSent(&s_r1.nwk) > 0, "this time R1 relays the request");
    Test_Expect(route != 0 && route->status == NWK_ROUTE_ACTIVE, "and R2's route to the coordinator is ACTIVE");
    Test_ExpectCount(route ? route->nextHopAddress : 0, MESH_R1, "through R1, the only device it can hear");
    Test_ExpectCount(Test_NwkPoll(&s_c.nwk, inds, 4), 1, "and the frame that waited reaches the coordinator");
    Test_ExpectCount(inds[0].srcAddr, MESH_R2, "with R2 as its source, carried across the gap");
}

/* 8874-8877 on radios that take one frame at a time, as an RCP does: R1 relays the request, its radio is still busy
   when the coordinator answers, and the reply R1 owes R2 has to be asked again, not lost. */
void caseMeshRouteReplyWaitsForABusyRadio(void)
{
    Nwk_DataIndicationParameters inds[4];
    Nwk_RoutingTableEntry *route;
    uint32_t at;

    meshLine();
    MeshAir_Deaf(&s_air, s_nodeC, s_nodeR2);
    MeshAir_Deaf(&s_air, s_nodeR2, s_nodeC);

    at = MeshAir_Run(&s_air, 1, 1 + MESH_SETTLED_MS, MESH_STEP_MS);

    MeshAir_OneFrameAtATime(&s_air, 1);

    meshSend(&s_r2, MESH_C, at);
    at = MeshAir_Run(&s_air, at, at + MESH_DISCOVERY_MS, MESH_STEP_MS);

    route = Nwk_RouteOf(s_r2.nwk.routes, MESH_C);

    Test_Expect(route != 0 && route->status == NWK_ROUTE_ACTIVE, "R2's route to the coordinator is ACTIVE");
    Test_ExpectCount(route ? route->nextHopAddress : 0, MESH_R1, "through R1");
    Test_Expect(Nwk_RouteRepliesForwarded(&s_r1.nwk) > 0, "R1 carried the reply on");
    Test_ExpectCount(Test_NwkPoll(&s_c.nwk, inds, 4), 1, "and the frame that waited reaches the coordinator");

    meshSend(&s_c, MESH_R2, at);
    at = MeshAir_Run(&s_air, at, at + MESH_DISCOVERY_MS, MESH_STEP_MS);

    Test_ExpectCount(Test_NwkPoll(&s_r2.nwk, inds, 4), 1, "and the coordinator reaches R2 the same way");
}

/* 9266-9272: the coordinator asks first, so R1's discovery entry names 0x0000 as the hop the request came from, and
   R1 carries R2's reply back to it. Nothing R2 sent beforehand leaves the coordinator a reverse route to lean on. */
void caseMeshCoordinatorFindsARouterThatNeverSpoke(void)
{
    Nwk_DataIndicationParameters inds[4];
    Nwk_RoutingTableEntry *route;
    uint32_t at;

    meshLine();
    MeshAir_Deaf(&s_air, s_nodeC, s_nodeR2);
    MeshAir_Deaf(&s_air, s_nodeR2, s_nodeC);

    at = MeshAir_Run(&s_air, 1, 1 + MESH_SETTLED_MS, MESH_STEP_MS);
    meshSend(&s_c, MESH_R2, at);
    at = MeshAir_Run(&s_air, at, at + MESH_DISCOVERY_MS, MESH_STEP_MS);

    route = Nwk_RouteOf(s_c.nwk.routes, MESH_R2);

    Test_Expect(Nwk_RouteRepliesForwarded(&s_r1.nwk) > 0, "R1 carries R2's reply to the coordinator");
    Test_ExpectCount(Nwk_RrepDroppedNoDiscovery(&s_r1.nwk), 0, "and finds the discovery entry the request left");
    Test_Expect(route != 0 && route->status == NWK_ROUTE_ACTIVE, "the coordinator's route to R2 is ACTIVE");
    Test_ExpectCount(route ? route->nextHopAddress : 0, MESH_R1, "through R1");
    Test_ExpectCount(Test_NwkPoll(&s_r2.nwk, inds, 4), 1, "and the frame that waited reaches R2");
}

/* 3.6.4.5.1's third case (9037-9041): a frame from the MAC asking for discovery, whose source is R2's end device
   child, starts one at R2, and 9060 lets the frame wait for the route. */
void caseMeshRelayDiscoversForItsEndDeviceChild(void)
{
    Nwk_DataIndicationParameters inds[4];
    Nwk_RoutingTableEntry *route;

    (void)meshChildFrame(MESH_E);

    route = Nwk_RouteOf(s_r2.nwk.routes, MESH_C);

    Test_Expect(Nwk_RouteRequestsSent(&s_r2.nwk) > 0, "R2 starts a discovery for its child's frame");
    Test_ExpectCount(Nwk_ChildDiscoveries(&s_r2.nwk), 1, "counted as one for a child");
    Test_ExpectCount(Nwk_ChildFramesHeld(&s_r2.nwk), 1, "with the frame held for the route");
    Test_Expect(route != 0 && route->status == NWK_ROUTE_ACTIVE, "and its route to the coordinator is ACTIVE");
    Test_ExpectCount(route ? route->nextHopAddress : 0, MESH_R1, "through R1");
    Test_ExpectCount(Test_NwkPoll(&s_c.nwk, inds, 4), 1, "the frame that waited reaches the coordinator");
    Test_ExpectCount(inds[0].srcAddr, MESH_E, "with the child as its source");
}

/* An end device's unicast for a device that is not its parent: R23.1 prints no next hop for it, and 9457-9458 (a
   broadcast's), 8773 and 9037-9041 all have it travel through the parent. E, R2's child, reaches the coordinator. */
void caseMeshEndDeviceSendsThroughItsParent(void)
{
    Nwk_DataIndicationParameters inds[4];
    uint32_t nodeE;
    uint32_t at;

    meshLine();
    rigAtSeed(&s_e, MESH_E, MESH_PAN, NWK_DEVICE_END_DEVICE, 1, 0, 0x404);
    nodeE = MeshAir_Add(&s_air, &s_e);
    MeshAir_Deaf(&s_air, s_nodeC, s_nodeR2);
    MeshAir_Deaf(&s_air, s_nodeR2, s_nodeC);
    MeshAir_Deaf(&s_air, s_nodeC, nodeE);
    MeshAir_Deaf(&s_air, nodeE, s_nodeC);
    MeshAir_Deaf(&s_air, s_nodeR1, nodeE);
    MeshAir_Deaf(&s_air, nodeE, s_nodeR1);

    at = MeshAir_Run(&s_air, 1, 1 + MESH_SETTLED_MS, MESH_STEP_MS);
    seedNeighbor(&s_r2.nwk, MESH_E, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);
    seedNeighbor(&s_e.nwk, MESH_R2, NWK_DEVICE_ROUTER, 1, NWK_REL_PARENT);

    meshSend(&s_e, MESH_C, at);
    at = MeshAir_Run(&s_air, at, at + MESH_DISCOVERY_MS, MESH_STEP_MS);

    Test_ExpectCount(Nwk_DroppedNoRoute(&s_e.nwk), 0, "E finds a next hop, its parent");
    Test_Expect(Nwk_RouteRequestsSent(&s_r2.nwk) > 0, "R2 discovers the route for its child's frame");
    Test_ExpectCount(Test_NwkPoll(&s_c.nwk, inds, 4), 1, "and the frame reaches the coordinator");
    Test_ExpectCount(inds[0].srcAddr, MESH_E, "with E as its source");
}

/* 9112-9116 with 7075-7076 and 7085-7086: R1 answers a request for E, its end device child, and the reply names E as
   the responder, so R2's route to E is the one that comes out of the discovery and R2's frame reaches E. */
void caseMeshParentAnswersForItsChild(void)
{
    Nwk_DataIndicationParameters inds[4];
    Nwk_RoutingTableEntry *route;
    uint32_t nodeE;
    uint32_t at;

    meshLine();
    rigAtSeed(&s_e, MESH_E, MESH_PAN, NWK_DEVICE_END_DEVICE, 1, 0, 0x404);
    setOwnIeee(&s_e, 0x3333333333333333);
    nodeE = MeshAir_Add(&s_air, &s_e);
    MeshAir_Deaf(&s_air, s_nodeC, s_nodeR2);
    MeshAir_Deaf(&s_air, s_nodeR2, s_nodeC);
    MeshAir_Deaf(&s_air, s_nodeR2, nodeE);
    MeshAir_Deaf(&s_air, nodeE, s_nodeR2);
    MeshAir_Deaf(&s_air, s_nodeC, nodeE);
    MeshAir_Deaf(&s_air, nodeE, s_nodeC);

    at = MeshAir_Run(&s_air, 1, 1 + MESH_SETTLED_MS, MESH_STEP_MS);
    seedNeighbor(&s_r1.nwk, MESH_E, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);
    seedNeighbor(&s_e.nwk, MESH_R1, NWK_DEVICE_ROUTER, 1, NWK_REL_PARENT);

    meshSend(&s_r2, MESH_E, at);
    at = MeshAir_Run(&s_air, at, at + MESH_DISCOVERY_MS, MESH_STEP_MS);

    route = Nwk_RouteOf(s_r2.nwk.routes, MESH_E);

    Test_Expect(Nwk_RouteRepliesSent(&s_r1.nwk) > 0, "R1 answers for its child");
    Test_Expect(route != 0 && route->status == NWK_ROUTE_ACTIVE, "R2's route to E is ACTIVE");
    Test_ExpectCount(route ? route->nextHopAddress : 0, MESH_R1, "through R1");
    Test_ExpectCount(Test_NwkPoll(&s_e.nwk, inds, 4), 1, "and the frame reaches E");
}

/* 6869-6873: E marks its frame as an end device's, and R2, its parent, clears the mark relaying it, so R1, which
   holds no entry for E, carries it on rather than refusing a mark it cannot check. */
void caseMeshParentClearsItsChildsMark(void)
{
    Nwk_DataIndicationParameters inds[4];

    (void)meshChildFrameMarked(MESH_E, 1);

    Test_ExpectCount(Nwk_DroppedEndDeviceInitiator(&s_r1.nwk), 0, "R1 refuses no mark");
    Test_ExpectCount(Test_NwkPoll(&s_c.nwk, inds, 4), 1, "and the frame reaches the coordinator");
}

/* 9042: in every other circumstance no discovery is started, so a relay without a route discards the frame. */
void caseMeshRelayDiscoversForNoOtherSource(void)
{
    Nwk_DataIndicationParameters inds[4];

    (void)meshChildFrame(MESH_STRANGER);

    Test_ExpectCount(Nwk_RouteRequestsSent(&s_r2.nwk), 0, "R2 starts no discovery for a source that is not its child");
    Test_ExpectCount(Nwk_ChildDiscoveries(&s_r2.nwk), 0, "and counts none for a child");
    Test_Expect(Nwk_DroppedNoRoute(&s_r2.nwk) > 0, "and drops the frame");
    Test_ExpectCount(Test_NwkPoll(&s_c.nwk, inds, 4), 0, "which never reaches the coordinator");
}

/* 8961 and 9121 on a one-way link: the coordinator hears R2, R2 does not hear the coordinator. R2's lists can never name
   the coordinator, so what arrives directly is discarded, and the copy R1 relays is the one answered. */
void caseMeshOneWayLinkIsNotUsed(void)
{
    Nwk_DataIndicationParameters inds[4];
    Nwk_NeighborTableEntry *entry;
    Nwk_RoutingTableEntry *route;
    uint32_t at;

    meshLine();
    MeshAir_Deaf(&s_air, s_nodeR2, s_nodeC);

    at = MeshAir_Run(&s_air, 1, 1 + MESH_SETTLED_MS, MESH_STEP_MS);

    entry = Nwk_NeighborOf(s_c.nwk.neighbors, MESH_R2);

    Test_Expect(entry != 0, "the coordinator heard R2 and holds an entry for it");
    Test_ExpectCount(entry ? entry->outgoingCost : 0xff, 0, "at cost 0: R2's link status covers it and does not name it");

    meshSend(&s_r2, MESH_C, at);
    at = MeshAir_Run(&s_air, at, at + MESH_DISCOVERY_MS, MESH_STEP_MS);

    route = Nwk_RouteOf(s_r2.nwk.routes, MESH_C);

    Test_Expect(Nwk_RreqDroppedNoOutgoingCost(&s_c.nwk) > 0, "9121: the request that arrived directly is discarded");
    Test_ExpectCount(route ? route->nextHopAddress : 0, MESH_R1, "and the answered copy leaves R2's route through R1");
    Test_ExpectCount(Test_NwkPoll(&s_c.nwk, inds, 4), 1, "and the frame arrives");

    meshSend(&s_c, MESH_R2, at);
    (void)MeshAir_Run(&s_air, at, at + MESH_DISCOVERY_MS, MESH_STEP_MS);

    Test_ExpectCount(Test_NwkPoll(&s_r2.nwk, inds, 4), 1, "and the request's reverse route carries one back through R1");
}

/* 8832-8834 let a router send straight to a device in its table, which the table's cost does not hold back, so before
   any route exists a frame goes to the one-way neighbour and fails there; 3.6.4.8 then has its link failure to report. */
void caseMeshOneWayNeighbourIsTriedDirectly(void)
{
    Nwk_DataConfirmParameters confirm[4];
    Nwk_DataIndicationParameters inds[4];
    uint32_t at;

    meshLine();
    MeshAir_Deaf(&s_air, s_nodeR2, s_nodeC);

    at = MeshAir_Run(&s_air, 1, 1 + MESH_SETTLED_MS, MESH_STEP_MS);

    meshSend(&s_c, MESH_R2, at);
    (void)MeshAir_Run(&s_air, at, at + MESH_DISCOVERY_MS, MESH_STEP_MS);

    Test_ExpectCount((uint32_t)Nwk_PollConfirms(&s_c.nwk, confirm, 4), 1, "the send is answered");
    Test_Expect(confirm[0].status != ZB_OK, "and it failed: R2 cannot hear the coordinator");
    Test_ExpectCount(Test_NwkPoll(&s_r2.nwk, inds, 4), 0, "and R2 never got it");
}

/* The air itself: a frame reaches who hears the sender, and a unicast across a gap is not acknowledged. */
void caseMeshAirAcknowledgesOnlyBothWays(void)
{
    static const uint8_t nsdu[2] = { 1, 2 };
    Nwk_DataRequestParameters req;
    Nwk_DataConfirmParameters confirm[4];

    meshLine();
    MeshAir_Deaf(&s_air, s_nodeR2, s_nodeC);
    seedNeighbor(&s_c.nwk, MESH_R2, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    (void)MeshAir_Run(&s_air, 1, 1, MESH_STEP_MS);

    req = nldeReq(MESH_R2, nsdu, (uint32_t)sizeof nsdu, 0);

    Test_ExpectStatus(Nwk_DataRequest(&s_c.nwk, &req, 2), ZB_OK, "the coordinator sends to a device that cannot hear it");

    (void)MeshAir_Run(&s_air, 3, 3 + 40 * MESH_STEP_MS, MESH_STEP_MS);

    Test_ExpectCount((uint32_t)Nwk_PollConfirms(&s_c.nwk, confirm, 4), 1, "one confirmation");
    Test_Expect(confirm[0].status != ZB_OK, "and it says the frame was not answered");
    Test_Expect(s_air.notHeard > 0, "for R2 never had it");
}
