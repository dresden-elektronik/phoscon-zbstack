/* 3.4.5's route record command and Table 3-67's source route table: the codec, the record's own order against the
   wire's, the replacement 3.6.4.5.5 prints, and the lifetime a record outlives its frame by. */

#include "nwk_cases.h"
#include "nwk_command.h"
#include "nwk_frame.h"
#include "nwk_helpers.h"
#include "nwk_route.h"
#include "nwk_sourceroute.h"
#include "test_harness.h"
#include "zb_utils.h"

void caseRouteRecordCodec(void)
{
    Nwk_SourceRouteEntry pool[NWK_SOURCE_ROUTE_MAX];
    uint8_t payload[1 + 3 * NWK_FRAME_RELAY_OCTETS];
    uint16_t relays[NWK_MAX_RELAYS];
    uint16_t record[3];
    uint32_t count = 0;
    uint32_t len = 0;
    uint32_t i;

    Zb_memset(pool, 0, (uint32_t)sizeof pool);
    Zb_memset(relays, 0, (uint32_t)sizeof relays);
    Zb_memset(payload, 0, (uint32_t)sizeof payload);

    record[0] = HOP;
    record[1] = ROUTER_NEIGHBOR;
    record[2] = NEIGHBOR;

    Test_ExpectStatus(Nwk_RouteRecordCompose(record, 3, payload, (uint32_t)sizeof payload, &len), ZB_OK,
                      "Figure 3-16's payload: the relay count first, then the relay list");
    Test_ExpectCount(len, 1 + 3 * NWK_FRAME_RELAY_OCTETS, "one octet for the count and two per relay");
    Test_ExpectCount(payload[0], 3, "the count the list is read with");

    Test_ExpectStatus(Nwk_RouteRecordParse(payload, len, relays, NWK_MAX_RELAYS, &count), ZB_OK,
                      "and it reads back as the codec wrote it");
    Test_ExpectCount(count, 3, "three relays");

    for (i = 0; i < 3; i++)
        Test_ExpectCount(relays[i], record[i], "in the order the record was collected in");

    Test_ExpectStatus(Nwk_RouteRecordParse(payload, len - 1, relays, NWK_MAX_RELAYS, &count), ZB_ERR_BAD_ARGUMENT,
                      "a payload that does not fill the count is refused rather than read short");

    Test_ExpectCount(Nwk_SourceRouteLearn(pool, UNSEEN, record, 3, 1000), NWK_SR_LEARNED,
                     "3.6.4.5.5's destination stores the record it was handed");
    Test_ExpectCount(Nwk_SourceRouteOf(pool, UNSEEN, 1000)->relayList[0], HOP,
                     "3.3.1.8.3: the relay closest to the destination is listed first, which is the record's own order");
    Test_ExpectCount(Nwk_SourceRouteOf(pool, UNSEEN, 1000)->relayList[2], NEIGHBOR,
                     "and the relay closest to the originator last");

    Test_ExpectCount(Nwk_SourceRouteLearn(pool, UNSEEN, record, 3, 1100), NWK_SR_SAME,
                     "a second record with the same relays only starts the lifetime again");
    record[1] = SLEEPY;
    Test_ExpectCount(Nwk_SourceRouteLearn(pool, UNSEEN, record, 3, 1100), NWK_SR_UPDATED,
                     "and one with other relays replaces the first");
    Test_ExpectCount(Nwk_SourceRouteOf(pool, UNSEEN, 1100)->relayList[1], SLEEPY, "with its own list");
    Test_Expect(Nwk_SourceRouteOf(pool, UNSEEN, 1100 + NWK_SOURCE_ROUTE_LIFETIME_MS + 1) == 0,
                "and a record the lifetime has passed is gone");
}

void caseRouteRecordOrigin(void)
{
    Nwk_SourceRouteEntry pool[NWK_SOURCE_ROUTE_MAX];
    uint16_t record[2];
    uint32_t i;

    Zb_memset(pool, 0, (uint32_t)sizeof pool);
    Zb_memset(record, 0, (uint32_t)sizeof record);

    for (i = 0; i < NWK_SOURCE_ROUTE_MAX; i++)
    {
        Test_ExpectCount(Nwk_SourceRouteLearn(pool, (uint16_t)(0x2000 + i), record, 2, 0), NWK_SR_LEARNED,
                         "every row of Table 3-67's pool takes a record");
    }

    Test_ExpectCount(Nwk_SourceRouteLearn(pool, 0x3000, record, 2, 0), NWK_SR_FULL,
                     "and a ninth is refused rather than overwriting a live record");

    Test_ExpectCount(Nwk_SourceRouteExpire(pool, NWK_SOURCE_ROUTE_LIFETIME_MS + 1), NWK_SOURCE_ROUTE_MAX,
                     "while the lifetime releases the whole pool");

    Test_ExpectCount(Nwk_SourceRouteLearn(pool, 0x2000, record, 2, 0), NWK_SR_LEARNED, "a record learned again");
    Test_Expect(Nwk_SourceRouteForget(pool, 0x2000) && Nwk_SourceRouteOf(pool, 0x2000, 0) == 0
                && !Nwk_SourceRouteForget(pool, 0x2000), "is let go of once, and a second time finds none");
}

/* A route record this router initiates ahead of a data frame to a concentrator, read off the air. */
void caseRouteRecordOnTheAir(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_RoutingTableEntry *route = 0;
    Nwk_DataRequestParameters req;
    Nwk_Frame frame;
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
    uint32_t airCount = 0;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    for (i = 0; i < NWK_ROUTE_MAX && route == 0; i++)
    {
        if (!dev.nwk.routes[i].inUse)
            route = &dev.nwk.routes[i];
    }

    Test_Expect(route != 0, "a free row of the routing table");

    if (route == 0)
        return;

    Zb_memset(route, 0, (uint32_t)sizeof *route);
    route->inUse = 1;
    route->destinationAddress = UNSEEN;
    route->status = NWK_ROUTE_ACTIVE;
    route->nextHopAddress = NEIGHBOR;
    route->manyToOne = 1;
    route->routeRecordRequired = 1;

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK,
                      "3.6.4.5.5: a data frame to a destination whose entry is many-to-one and owes a record");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 2, "goes behind a route record command");
    Test_ExpectStatus(airCount != 0 ? NwkFrame_Parse(npduOf(&air[0]), npduLenOf(&air[0]), &frame, &payloadOffset,
                                                     &payloadLen)
                                    : ZB_ERR_BAD_FRAME,
                      ZB_OK, "which parses as a network frame");
    Test_Expect(frame.frameType == NWK_FRAME_TYPE_COMMAND && frame.destAddr == UNSEEN && frame.srcAddr == OWN_SHORT,
                "3.4.5.2: a command from this device to the concentrator");
    Test_Expect(frame.srcIeeePresent == 1 && frame.sourceRoute == 0,
                "3.4.5.2: with the source IEEE address sub-field set and no source route");
    Test_Expect(payloadLen == 2 && npduOf(&air[0])[payloadOffset] == NWK_CMD_ROUTE_RECORD
                && npduOf(&air[0])[payloadOffset + 1] == 0,
                "3.4.5.3 and 3.4.5.3.1: the route record's identifier, then a relay count of 0 for a frame it originates");
    Test_ExpectCount(route->routeRecordRequired, 0, "and the entry owes no record until a new request asks for one");
    Test_ExpectCount(Nwk_RouteRecordsSent(&dev.nwk), 1, "counted as the one it sent");
}

/* A neighbour's record with no relay, at its destination: the route is direct, and the source route it replaces goes. */
void caseRouteRecordFromANeighbourReplacesTheRoute(void)
{
    Test_BandA dev;
    uint8_t payload[2];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint16_t relays[1];
    uint32_t npduLen;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    relays[0] = HOP;
    Test_ExpectCount(Nwk_SourceRouteLearn(dev.nwk.sourceRoutes, NEIGHBOR, relays, 1, 0), NWK_SR_LEARNED,
                     "a source route to the neighbour through another device, learned earlier");

    payload[0] = NWK_CMD_ROUTE_RECORD;
    payload[1] = 0;
    npduLen = makeNpdu(npdu, OWN_SHORT, NEIGHBOR, 4, 0x61, NWK_FRAME_TYPE_COMMAND, 0, payload, 2);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a route record the neighbour sends this device, no relay in it");
    Test_ExpectCount(Nwk_RouteRecordsReceived(&dev.nwk), 1, "is counted at its destination");
    Test_Expect(Nwk_SourceRouteOf(dev.nwk.sourceRoutes, NEIGHBOR, 100) == 0,
                "3.6.4.5.5: and replaces the source route it had, the new route being direct");
}

/* A record of three relays, then a data frame to its originator: the frame carries the relays in the order the record
   collected them, and goes first to the relay the record reached this device through. */
void caseSourceRoutedFrameOnTheAir(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    Nwk_Frame frame;
    uint16_t record[3];
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    record[0] = HOP;
    record[1] = ROUTER_NEIGHBOR;
    record[2] = NEIGHBOR;
    Test_ExpectCount(Nwk_SourceRouteLearn(dev.nwk.sourceRoutes, UNSEEN, record, 3, 0), NWK_SR_LEARNED,
                     "3.4.5.3.2: the relay next to the originator appended first, this device's neighbour last");

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    req.discoverRoute = NWK_DISCOVER_ENABLE;
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK,
                      "8857-8860: a frame to a destination with no route, asking for discovery as the APS does");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "goes out once");
    Test_ExpectStatus(airCount != 0 ? NwkFrame_Parse(npduOf(&air[0]), npduLenOf(&air[0]), &frame, &payloadOffset,
                                                     &payloadLen)
                                    : ZB_ERR_BAD_FRAME,
                      ZB_OK, "which parses as a network frame");
    Test_Expect(frame.sourceRoute && frame.relayCount == 3 && frame.relayIndex == 2,
                "3.6.4.3.1: source routed, three relays, the index one less than the count");
    Test_ExpectCount((uint32_t)frame.discoverRoute, NWK_DISCOVER_SUPPRESS,
                     "Table 3-51: and Discover Route 00, the source-routed row's only value");
    Test_Expect(frame.relayList[0] == HOP && frame.relayList[1] == ROUTER_NEIGHBOR && frame.relayList[2] == NEIGHBOR,
                "3.3.1.8.3: the relay closest to the destination first, the one closest to the originator last");
    Test_ExpectCount(airCount != 0 ? airDestOf(&air[0]) : 0, NEIGHBOR,
                     "3.6.4.3.1: and the MAC destination is the final relay of the list");
}

/* A source route row is the last resort: an ACTIVE routing entry and an end device child are sent to as 8826-8837
   say, though the table holds a row for each. */
void caseSourceRouteYieldsToTheRoutingTable(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    Nwk_Frame frame;
    uint16_t record[2];
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    seedNeighbor(&dev.nwk, ROUTER_NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    seedNeighbor(&dev.nwk, SLEEPY, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);

    dev.nwk.routes[0].inUse = 1;
    dev.nwk.routes[0].destinationAddress = UNSEEN;
    dev.nwk.routes[0].status = NWK_ROUTE_ACTIVE;
    dev.nwk.routes[0].nextHopAddress = ROUTER_NEIGHBOR;

    record[0] = HOP;
    record[1] = NEIGHBOR;
    Test_ExpectCount(Nwk_SourceRouteLearn(dev.nwk.sourceRoutes, UNSEEN, record, 2, 0), NWK_SR_LEARNED,
                     "a source route to a destination the routing table also holds ACTIVE");
    Test_ExpectCount(Nwk_SourceRouteLearn(dev.nwk.sourceRoutes, SLEEPY, record, 2, 0), NWK_SR_LEARNED,
                     "and one to this device's end device child");

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK, "a frame to the routed destination");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "goes out once");
    Test_ExpectStatus(airCount != 0 ? NwkFrame_Parse(npduOf(&air[0]), npduLenOf(&air[0]), &frame, &payloadOffset,
                                                     &payloadLen)
                                    : ZB_ERR_BAD_FRAME,
                      ZB_OK, "which parses as a network frame");
    Test_Expect(!frame.sourceRoute && airDestOf(&air[0]) == ROUTER_NEIGHBOR,
                "8835-8837: over the ACTIVE entry's next hop, with no source route");

    req = nldeReq(SLEEPY, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 200), ZB_OK, "a frame to the end device child");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 2, "goes out once after the first");
    Test_ExpectStatus(airCount == 2 ? NwkFrame_Parse(npduOf(&air[1]), npduLenOf(&air[1]), &frame, &payloadOffset,
                                                     &payloadLen)
                                    : ZB_ERR_BAD_FRAME,
                      ZB_OK, "which parses as a network frame");
    Test_Expect(!frame.sourceRoute && airDestOf(&air[1]) == SLEEPY,
                "8826-8829: directly to the child, with no source route");
}

/* A route record from `originator`, at this device, through `count` relays in the order it collected them. */
static void injectRecord(Test_BandA *dev, uint16_t originator, const uint16_t *relays, uint32_t count, uint8_t seq,
                         uint32_t nowMs)
{
    uint8_t payload[2 + 2 * NWK_MAX_SOURCE_ROUTE];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t len = 0;
    uint32_t npduLen;

    payload[0] = NWK_CMD_ROUTE_RECORD;
    (void)Nwk_RouteRecordCompose(relays, count, payload + 1, (uint32_t)sizeof payload - 1, &len);
    npduLen = makeNpdu(npdu, OWN_SHORT, originator, 4, seq, NWK_FRAME_TYPE_COMMAND, 0, payload, 1 + len);
    injectNpdu(dev, npdu, npduLen, count != 0 ? relays[count - 1] : originator);
    Test_ExpectStatus(Test_NwkStep(&dev->nwk, nowMs), ZB_OK, "a route record reaches this device");
}

/* The higher layer's row: refused where it names no device or this one, held past the lifetime a learned row has,
   used for the frame, and replaced by the first record. */
void caseSourceRouteSeedHoldsUntilARecord(void)
{
    Test_BandA dev;
    Test_BandA sleepy;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    Nwk_SourceRouteNotice notices[4];
    Nwk_Frame frame;
    uint16_t relays[NWK_MAX_SOURCE_ROUTE + 1];
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
    uint32_t airCount = 0;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    Zb_memset(relays, 0, (uint32_t)sizeof relays);

    relays[0] = HOP;
    relays[1] = NEIGHBOR;
    Test_ExpectStatus(Nwk_SetSourceRoute(&dev.nwk, OWN_SHORT, relays, 2, 0), ZB_ERR_BAD_ARGUMENT,
                      "a row to this device itself is refused");
    Test_ExpectStatus(Nwk_SetSourceRoute(&dev.nwk, 0xfffd, relays, 2, 0), ZB_ERR_BAD_ARGUMENT,
                      "and to a broadcast address");
    Test_ExpectStatus(Nwk_SetSourceRoute(&dev.nwk, HOP, relays, 2, 0), ZB_ERR_BAD_ARGUMENT,
                      "and one whose relays hold its destination");
    Test_ExpectStatus(Nwk_SetSourceRoute(&dev.nwk, UNSEEN, relays, NWK_MAX_SOURCE_ROUTE + 1, 0), ZB_ERR_BAD_ARGUMENT,
                      "and one longer than nwkMaxSourceRoute");

    rigAt(&sleepy, OWN_SHORT, PAN_ID, NWK_DEVICE_END_DEVICE, 0);
    Test_ExpectStatus(Nwk_SetSourceRoute(&sleepy.nwk, UNSEEN, relays, 2, 0), ZB_ERR_BAD_STATE,
                      "an end device keeps no source route table");

    Test_ExpectStatus(Nwk_SetSourceRoute(&dev.nwk, UNSEEN, relays, 2, 0), ZB_OK, "the higher layer's row is taken");
    Test_Expect(Nwk_SourceRouteOf(dev.nwk.sourceRoutes, UNSEEN, NWK_SOURCE_ROUTE_LIFETIME_MS + 1) != 0
                && Nwk_SourceRouteExpire(dev.nwk.sourceRoutes, NWK_SOURCE_ROUTE_LIFETIME_MS + 1) == 0,
                "and outlives the lifetime a learned row has");
    Test_ExpectCount(Nwk_PollSourceRouteNotices(&dev.nwk, notices, 4), 0, "the higher layer is not told of its own row");

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK, "a frame to the seeded destination");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectStatus(airCount == 1 ? NwkFrame_Parse(npduOf(&air[0]), npduLenOf(&air[0]), &frame, &payloadOffset,
                                                     &payloadLen)
                                    : ZB_ERR_BAD_FRAME,
                      ZB_OK, "goes out once, as a network frame");
    Test_Expect(frame.sourceRoute && frame.relayCount == 2 && frame.relayList[0] == HOP
                && airDestOf(&air[0]) == NEIGHBOR, "source routed over the seed, to its last relay");

    relays[0] = ROUTER_NEIGHBOR;
    relays[1] = NEIGHBOR;
    injectRecord(&dev, UNSEEN, relays, 2, 0x41, 200);
    Test_ExpectCount(Nwk_PollSourceRouteNotices(&dev.nwk, notices, 4), 1, "a record with other relays is told");
    Test_Expect(notices[0].destinationAddress == UNSEEN && notices[0].reason == NWK_SR_NOTICE_CHANGED
                && notices[0].relayCount == 2 && notices[0].relayList[0] == ROUTER_NEIGHBOR,
                "as a change of the seeded row, with the record's relays");
    Test_Expect(Nwk_SourceRouteOf(dev.nwk.sourceRoutes, UNSEEN, 200 + NWK_SOURCE_ROUTE_LIFETIME_MS + 1) == 0,
                "and the row the record replaced the seed with is a learned one, which the lifetime ends");

    Test_ExpectStatus(Nwk_SetSourceRoute(&dev.nwk, UNSEEN, relays, 2, 0), ZB_OK, "seeded again");
    Test_ExpectStatus(Nwk_SetSourceRoute(&dev.nwk, UNSEEN, 0, 0, 0), ZB_OK, "and no relays let the row go");
    Test_Expect(Nwk_SourceRouteOf(dev.nwk.sourceRoutes, UNSEEN, 0) == 0, "so the table holds none");

    for (i = 0; i < NWK_SOURCE_ROUTE_MAX; i++)
        (void)Nwk_SetSourceRoute(&dev.nwk, (uint16_t)(0x3000 + i), relays, 2, 0);

    Test_ExpectStatus(Nwk_SetSourceRoute(&dev.nwk, UNSEEN, relays, 2, 0), ZB_ERR_NO_SPACE,
                      "a seed into a full table is refused");
}

/* What a record does to the table, as the higher layer is told: a new route, the same one again, another one, the
   routes to the relays already held, and a neighbour's direct one; and a 0x0b's removal. */
void caseRouteRecordNoticesTheTable(void)
{
    Test_BandA dev;
    Nwk_SourceRouteNotice notices[8];
    uint8_t payload[4];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint16_t relays[3];
    uint32_t npduLen;
    uint32_t taken;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    seedNeighbor(&dev.nwk, ROUTER_NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    relays[0] = HOP;
    relays[1] = NEIGHBOR;
    injectRecord(&dev, UNSEEN, relays, 2, 0x51, 100);
    taken = Nwk_PollSourceRouteNotices(&dev.nwk, notices, 8);
    Test_Expect(taken == 1 && notices[0].destinationAddress == UNSEEN && notices[0].reason == NWK_SR_NOTICE_LEARNED
                && notices[0].relayCount == 2 && notices[0].relayList[0] == HOP && notices[0].relayList[1] == NEIGHBOR,
                "a destination with no row is learned and told, its relays in the frame's order");

    injectRecord(&dev, UNSEEN, relays, 2, 0x52, 200);
    Test_ExpectCount(Nwk_PollSourceRouteNotices(&dev.nwk, notices, 8), 0, "the same record again is not told");

    relays[1] = ROUTER_NEIGHBOR;
    Test_ExpectStatus(Nwk_SetSourceRoute(&dev.nwk, HOP, relays + 1, 1, 0), ZB_OK, "a row to the record's first relay");
    Test_ExpectStatus(Nwk_SetSourceRoute(&dev.nwk, ROUTER_NEIGHBOR, &relays[0], 1, 0), ZB_OK,
                      "and one to its second, which is this device's neighbour");
    relays[1] = NEIGHBOR;
    relays[2] = ROUTER_NEIGHBOR;
    Test_ExpectStatus(Nwk_SetSourceRoute(&dev.nwk, NEIGHBOR, &relays[2], 1, 0), ZB_OK, "and one to its last");

    relays[0] = HOP;
    relays[1] = ROUTER_NEIGHBOR;
    relays[2] = NEIGHBOR;
    injectRecord(&dev, UNSEEN, relays, 3, 0x53, 300);
    taken = Nwk_PollSourceRouteNotices(&dev.nwk, notices, 8);
    Test_ExpectCount(taken, 4, "3.6.4.5.5: a record of three relays replaces four rows");
    Test_Expect(taken == 4 && notices[0].destinationAddress == UNSEEN && notices[0].reason == NWK_SR_NOTICE_CHANGED
                && notices[0].relayCount == 3, "its originator's");
    Test_Expect(taken == 4 && notices[1].destinationAddress == HOP && notices[1].reason == NWK_SR_NOTICE_CHANGED
                && notices[1].relayCount == 2 && notices[1].relayList[0] == ROUTER_NEIGHBOR
                && notices[1].relayList[1] == NEIGHBOR, "the first relay's, the part of the list beyond it");
    Test_Expect(taken == 4 && notices[2].destinationAddress == ROUTER_NEIGHBOR
                && notices[2].reason == NWK_SR_NOTICE_CHANGED && notices[2].relayCount == 1
                && notices[2].relayList[0] == NEIGHBOR, "the second relay's");
    Test_Expect(taken == 4 && notices[3].destinationAddress == NEIGHBOR && notices[3].reason == NWK_SR_NOTICE_DIRECT
                && Nwk_SourceRouteOf(dev.nwk.sourceRoutes, NEIGHBOR, 300) == 0,
                "and the last relay's, which is reached directly, so its row goes");

    injectRecord(&dev, ROUTER_NEIGHBOR, relays, 0, 0x54, 400);
    taken = Nwk_PollSourceRouteNotices(&dev.nwk, notices, 8);
    Test_Expect(taken == 1 && notices[0].destinationAddress == ROUTER_NEIGHBOR
                && notices[0].reason == NWK_SR_NOTICE_DIRECT && notices[0].relayCount == 0,
                "a neighbour's record with no relay removes its row, and is told");

    payload[0] = NWK_CMD_NETWORK_STATUS;
    payload[1] = 0x0b;
    payload[2] = (uint8_t)(UNSEEN & 0xff);
    payload[3] = (uint8_t)(UNSEEN >> 8);
    npduLen = makeNpdu(npdu, OWN_SHORT, NEIGHBOR, 4, 0x55, NWK_FRAME_TYPE_COMMAND, 0, payload, 4);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 500), ZB_OK, "a 0x0b naming the record's originator");
    taken = Nwk_PollSourceRouteNotices(&dev.nwk, notices, 8);
    Test_Expect(taken == 1 && notices[0].destinationAddress == UNSEEN && notices[0].reason == NWK_SR_NOTICE_FAILED,
                "removes its row, and is told");
    Test_ExpectCount(Nwk_SourceRouteNoticesDropped(&dev.nwk), 0, "with nothing the ring lost");
}
