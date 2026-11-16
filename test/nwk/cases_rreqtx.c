/* 3.6.4.5.1's initiation, its broadcast schedule and its timer, driven through the façade: an NLDE-DATA.request
   that names DiscoverRoute 0x01 and has no route starts the discovery, the four broadcasts Table 3-65's constants
   print go out at the printed interval, and 3.6.4.5.1.7's expiry answers the request with Table 3-84's
   ROUTE_ERROR. Every number a case asserts is one a clause or a table prints, and each case names the branch it
   reddens if the branch is taken differently. The rig is the shared band-A device in `nwk_helpers.c`. */

#include "nwk_routeflow_cases.h"

#include "loopback_radio.h"
#include "mac.h"
#include "nwk.h"
#include "nwk_discovery.h"
#include "nwk_frame.h"
#include "nwk_helpers.h"
#include "nwk_route.h"
#include "nwk_routeflow_helpers.h"
#include "nwk_rreq.h"
#include "nwk_rreqrelay.h"
#include "nwk_rreqtx.h"
#include "nwk_tlv.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

enum
{
    /* 3.3.1.2 … 3.3.1.5 are the five fields every header carries: where a command's payload begins (Figure 3-4) */
    /* 3.4.1.2: the request carries the originator's source IEEE address, so its payload starts one IEEE
       field past the minimal header */
    RREQ_PAYLOAD_OFFSET = NWK_MIN_HEADER_OVERHEAD + NWK_IEEE_ADDR_OCTETS,

    /* Inside the payload, 3.4.1.3's order: identifier, options, request id, destination 2, path cost, TLVs */
    RREQ_IDENTIFIER = 0,
    RREQ_OPTIONS = 1,
    RREQ_REQUEST_ID = 2,
    RREQ_DESTINATION = 3,
    RREQ_PATH_COST = 5,
    RREQ_TLV_TAG = 6,
    RREQ_TLV_LENGTH = 7,
    RREQ_TLV_ROUTING_SEQUENCE = 8,
    RREQ_TLV_INITIAL_RADIUS = 10,

    DISCOVERY_START_MS = 1000,      /* the clock the first case hands in; the schedule is read against it */
    ROUTE_SOURCE = 0x1234           /* the initiator 3.6.4.5.6 names when a discovery entry expires */
};

/* The device's own extended address, as 7.2.1.4 writes one into the PIB: the 64-bit identity 3.4.1.2 makes
   every route request carry (nwk_helpers.c `setOwnIeee`). */
#define OWN_IEEE_VALUE 0x0123456789abcdef

/* 4096 ms before the millisecond counter wraps: 3.6.4.5.1's whole run crosses it. Written as a macro and not an
   enumerator because an enum value must be representable as an int (C99 §6.7.2.2), as `nwk_route.h` says too. */
#define WRAP_START_MS 0xfffff000

/* The four transmissions 3.6.4.5.1 prints, at the interval nwkcRREQRetryInterval names (Table 3-65) */
static uint32_t scheduleAt(uint32_t index)
{
    return DISCOVERY_START_MS + index * NWK_RREQ_RETRY_INTERVAL_MS;
}

/* A discovery started at `DISCOVERY_START_MS` and stepped through its whole schedule, each step's frames taken
   before the backend's slots are reused for the next one. */
static void runTheSchedule(Test_BandA *dev, Air *air, uint32_t *airCount)
{
    uint32_t i;

    for (i = 0; i < NWK_RREQ_TX_COUNT; i++)
    {
        Test_ExpectStatus(Test_NwkStep(&dev->nwk, scheduleAt(i)), ZB_OK, "the turn 3.6.4.5.1's next transmission is due");
        harvestAir(&dev->model, air, airCount);
    }
}

void caseRouteDiscoveryStartsFromTheDataRequest(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_DataRequestParameters req;
    Nwk_RoutingTableEntry *route;
    const uint8_t *npdu;
    const uint8_t *payload;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS), ZB_OK,
                      "a request that names DiscoverRoute 0x01 for an address with neither a route nor a neighbor: 3.6.4.5.1's second case is taken");
    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), 1, "the request is taken back and waits, its frame unsent");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "and the request's own call puts nothing on the air: the broadcast is the next step's");
    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), 0, "with no confirmation yet, because nothing is answered yet");

    route = Nwk_RouteOf(dev.nwk.routes, UNSEEN);
    entry = Nwk_DiscoveryOf(dev.nwk.discoveries, OWN_SHORT, 1);

    Test_Expect(route != 0 && route->status == NWK_ROUTE_DISCOVERY_UNDERWAY,
                "9047-9054: a routing entry for the destination is established with status DISCOVERY_UNDERWAY");
    Test_ExpectCount(route ? route->destinationAddress : 0, UNSEEN, "for the address the request named");

    Test_Expect(entry != 0, "and Table 3-79's entry is established for it: 9047-9054's last sentence");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 1, "one entry, the one this discovery created");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS), ZB_OK, "the next step, which issues the first broadcast");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "exactly one frame on the air");
    Test_Expect(air[0].ackRequest == 0, "3.4.1.1: the MAC acknowledgment is not asked for on a Route Request");
    Test_ExpectCount(airDestOf(&air[0]), MAC_FRAME_ADDR_BROADCAST,
                     "3.2.1.1.3 step 6 a.3: for a NWK destination of 0xFFFC, DstAddr is 0xFFFF, so the MAC destination is the broadcast address");

    npdu = npduOf(&air[0]);
    payload = npdu + RREQ_PAYLOAD_OFFSET;

    Test_ExpectCount((uint32_t)(npdu[2] | (npdu[3] << 8)), NWK_ADDR_ROUTERS,
                     "and 3.4.1.2's routers class, 0xfffc, travels in the NWK header's destination field, which is the only place a receiver learns who was meant");

    Test_ExpectCount(payload[RREQ_IDENTIFIER], NWK_CMD_ROUTE_REQUEST, "Table 3-54: payload octet zero is 0x01");
    Test_ExpectCount(payload[RREQ_OPTIONS], 0,
                     "Figure 3-10: no many-to-one bits, no destination IEEE address the table does not know, no deprecated bit");
    Test_ExpectCount(payload[RREQ_REQUEST_ID], 1, "3.4.1.3.2: the request id the first initiation numbers");
    Test_ExpectCount((uint32_t)(payload[RREQ_DESTINATION] | (payload[RREQ_DESTINATION + 1] << 8)), UNSEEN,
                     "3.4.1.3.3: the destination the route is to be discovered for, low octet first");
    Test_ExpectCount(payload[RREQ_PATH_COST], 0, "9068: an initiator sets the path cost field to 0");
    Test_ExpectCount(payload[RREQ_TLV_TAG], NWK_TLV_TAG_EXTENDED_ROUTE, "K.2.1.1: tag 0 is the Extended Route Information TLV");
    Test_ExpectCount(payload[RREQ_TLV_LENGTH], NWK_TLV_EXTENDED_ROUTE_OCTETS - NWK_TLV_LENGTH_BIAS,
                     "Table I-1: the Length field is the value's octets less one");
    Test_ExpectCount((uint32_t)(payload[RREQ_TLV_ROUTING_SEQUENCE] | (payload[RREQ_TLV_ROUTING_SEQUENCE + 1] << 8)), 1,
                     "Annex K.5: the TLV carries nwkRoutingSequenceNumber after its increment, and this is the first");
    Test_ExpectCount(payload[RREQ_TLV_INITIAL_RADIUS], NWK_INITIAL_RADIUS,
                     "K.2.1.1.2: the initial radius, twice nwkcMaxDepth, which is also the header's radius");

    Test_ExpectCount(dev.nwk.routingSequenceNumber, 1, "NIB 0xBE holds the value the TLV carries");
    Test_ExpectCount(dev.nwk.routeRequestId, 1, "and 3.4.1.3.2's counter is the request id it stored in Table 3-79");

    Test_ExpectCount(entry ? entry->routeRequestId : 0xff, 1, "Table 3-79's Route request ID");
    Test_ExpectCount(entry ? entry->sourceAddress : 0, OWN_SHORT, "its Source address: the request's initiator");
    Test_ExpectCount(entry ? entry->senderAddress : 0xffff, 0, "its Sender address: nothing has answered yet");
    Test_ExpectCount(entry ? entry->forwardCost : 0xff, 0, "its Forward cost");
    Test_ExpectCount(entry ? entry->residualCost : 0xff, 0, "and its Residual cost (3.6.4.5.2 fills it)");
    Test_ExpectCount(entry ? entry->destAddr : 0, UNSEEN, "and the destination 3.6.4.5.1.7's deletion rule will name");
    Test_ExpectCount(entry ? entry->expiresAtMs : 0, DISCOVERY_START_MS + NWK_ROUTE_DISCOVERY_TIME_MS,
                     "9151: the timer expires in nwkcRouteDiscoveryTime, 10 s (Table 3-65)");

    Test_ExpectCount(Nwk_RouteRequestsSent(&dev.nwk), 1, "one Route Request on the air");
    Test_ExpectCount(Nwk_PollConfirms(&dev.nwk, confirms, 4), 0,
                     "and still no confirmation: the request waits for the route or for the timer, never for a broadcast");
}

void caseRouteDiscoveryIsNotStartedWhenTheRouteExists(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    Nwk_RoutingTableEntry *route;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, HOP, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(HOP, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS), ZB_OK,
                      "3.6.4.5.1's second case needs an address the routing table has no entry for; 3.6.4.3 answers this one with the neighbor entry that is a direct hop");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "so the frame itself goes out");
    Test_Expect(air[0].ackRequest == 1, "to that neighbor, asking for its acknowledgment");

    route = Nwk_RouteOf(dev.nwk.routes, HOP);

    Test_Expect(route != 0 && route->status == NWK_ROUTE_ACTIVE, "with an ACTIVE entry made for it");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 0, "and no discovery entry: no discovery was initiated");
    Test_ExpectCount(Nwk_RouteRequestsSent(&dev.nwk), 0, "and no Route Request was broadcast");
}

void caseRouteDiscoveryIsNotStartedWhenItIsNotAsked(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);

    Test_ExpectCount(req.discoverRoute, 0, "DiscoverRoute 0x00, Table 3-53's suppress");
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS), ZB_OK,
                      "the request is accepted and 3.6.4.3 has no route for it");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_NO_ROUTE && confirms[0].nwkStatus == NWK_STATUS_ROUTE_ERROR,
                "and it is answered at once with Table 3-84's ROUTE_ERROR, 3.6.4.3's third case: a request that suppresses discovery is not made to wait");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "nothing went on the air, the frame discarded rather than sent");

    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 0, "and no discovery was initiated");
    Test_ExpectCount(Nwk_RouteRequestsSent(&dev.nwk), 0, "no Route Request was broadcast");
    Test_ExpectCount(Nwk_DroppedNoRoute(&dev.nwk), 1, "the discard is counted where 3.6.4.3's third case counts it");
}

void caseRouteDiscoveryIsNotStartedForABroadcast(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    /* 3.6.4.5.1's second case speaks of the destination address's routing entry, which a class has none of; and
       Table 3-51's Broadcast row prints Discover Route 00, so a broadcast may not ask for a discovery either. */
    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS), ZB_ERR_BAD_ARGUMENT,
                      "a broadcast that names DiscoverRoute 0x01 is refused at the door: Table 3-51 allows a broadcast Discover Route 00 and no other value, and the codec's claim refuses the frame the request would compose");
    Test_ExpectCount(Nwk_RefusedRequests(&dev.nwk), 1, "counted as a refused request");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "and nothing went on the air");

    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 0, "and no discovery was initiated");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS), ZB_OK, "the next step");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(Nwk_RouteRequestsSent(&dev.nwk), 0, "and 0xfffc is not broadcast a Route Request for");

    /* The same broadcast suppressing discovery is what the table's row is written for. */
    req = nldeReq(NWK_ADDR_ALL_DEVICES, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 0;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS), ZB_OK,
                      "and the same broadcast suppressing discovery is sent, as it always was");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "one frame on the air");
    Test_ExpectCount(airDestOf(&air[0]), NWK_ADDR_ALL_DEVICES, "aimed at the class it named");
    Test_Expect(air[0].ackRequest == 0, "with no acknowledgment asked, as every broadcast");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 0, "and still no discovery: a class is not a destination");
}

void caseRouteDiscoveryIsNotStartedAtAnEndDevice(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_END_DEVICE, 1);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS), ZB_OK,
                      "an end device asks for a discovery, and 3.6.2.2 gives the routing duty (and with it a routing table) to a coordinator or an operating router");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_NO_ROUTE && confirms[0].nwkStatus == NWK_STATUS_ROUTE_ERROR,
                "so the request falls to 3.6.4.3's third case and is answered ROUTE_ERROR: Table 3-84 prints no code for it");

    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 0, "no discovery entry was made");
    Test_ExpectCount(Nwk_RouteQueue(&dev.nwk), 0, "and no routing entry");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS), ZB_OK, "the next step");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "and nothing went on the air");
    Test_ExpectCount(Nwk_RouteRequestsSent(&dev.nwk), 0, "no Route Request was broadcast");
}

void caseRouteDiscoveryBroadcastsOnThePrintedSchedule(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    Nwk_RreqTx *record;
    uint32_t airCount = 0;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS), ZB_OK, "a discovery starts");

    for (i = 0; i < NWK_RREQ_TX_COUNT; i++)
    {
        Test_ExpectCount(scheduleAt(i), DISCOVERY_START_MS + i * 254,
                         "3.6.4.5.1's retries are separated by nwkcRREQRetryInterval, Table 3-65's 0xfe msec at 2.4 GHz");

        if (i != 0)
        {
            Test_ExpectStatus(Test_NwkStep(&dev.nwk, scheduleAt(i) - 1), ZB_OK, "one millisecond before the next one is due");
            harvestAir(&dev.model, air, &airCount);
            Test_ExpectCount(airCount, i, "and nothing new went out: a deadline is a deadline");
        }

        Test_ExpectStatus(Test_NwkStep(&dev.nwk, scheduleAt(i)), ZB_OK, "the turn it is due");
        harvestAir(&dev.model, air, &airCount);
        Test_ExpectCount(airCount, i + 1, "and one more Route Request is on the air");
        record = Nwk_RreqTxOf(dev.nwk.rreqTx, UNSEEN, dev.nwk.routeRequestId);
        Test_Expect(record != 0, "the schedule this discovery owns, found by Table 3-79's key (destination, request id)");
        Test_ExpectCount(record != 0 ? record->nextTxMs : 0, scheduleAt(i) + NWK_RREQ_RETRY_INTERVAL_MS,
                         "with the next one armed exactly one nwkcRREQRetryInterval later");
        Test_ExpectCount(npduLenOf(&air[i]), npduLenOf(&air[0]),
                         "at the same length as the first");
        Test_Expect(Zb_memcmp(npduOf(&air[i]), npduOf(&air[0]), npduLenOf(&air[0])) == 0,
                    "and with the same octets byte for byte: a retry repeats the request and composes nothing new");
    }

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, scheduleAt(NWK_RREQ_TX_COUNT - 1) + NWK_RREQ_RETRY_INTERVAL_MS), ZB_OK,
                      "one interval after the fourth");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, NWK_RREQ_TX_COUNT, "and the schedule is over: nwkcInitialRREQRetries + 1 transmissions and no more (9070-9075)");
    record = Nwk_RreqTxOf(dev.nwk.rreqTx, UNSEEN, dev.nwk.routeRequestId);
    Test_Expect(record != 0 && record->transmissions == NWK_RREQ_TX_COUNT, "the record counts four");
    Test_ExpectCount(Nwk_RouteRequestsSent(&dev.nwk), NWK_RREQ_TX_COUNT, "and so does the module's own count");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 1, "while Table 3-79's entry is still live: the schedule ends, the discovery does not");
}

void caseRouteDiscoveryDoesNotRetryAManyToOneRequest(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_RreqTx pool[NWK_RREQ_TX_MAX];
    Nwk_RreqTx *record;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    int sent;
    int protectRefused;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    npduLen = makeNpdu(npdu, NWK_ADDR_ROUTERS, OWN_SHORT, NWK_INITIAL_RADIUS, 7, NWK_FRAME_TYPE_COMMAND, 0,
                       nsdu, NSDU_LEN);

    Zb_memset(pool, 0, (uint32_t)sizeof pool);

    Test_ExpectStatus(Nwk_RreqTxStart(pool, NWK_ADDR_ROUTERS, 1, NWK_RREQ_MANY_TO_ONE_WITH_RECORD, npdu,
                                      npduLen, NWK_MIN_HEADER_OVERHEAD, 0, DISCOVERY_START_MS),
                      ZB_OK, "a many-to-one request: Table 3-55's value 1");

    record = Nwk_RreqTxOf(pool, NWK_ADDR_ROUTERS, 1);
    Test_Expect(record != 0, "armed in the pool under its own key");

    Test_ExpectStatus(Nwk_RreqTxRun(record, &dev.mac, 0, 0, 0, DISCOVERY_START_MS, &sent, &protectRefused), ZB_OK,
                      "its first transmission, at the instant the schedule is armed");
    Test_Expect(sent == 1, "went out");

    Test_ExpectStatus(Nwk_RreqTxRun(record, &dev.mac, 0, 0, 0, DISCOVERY_START_MS + NWK_RREQ_RETRY_INTERVAL_MS,
                                    &sent, &protectRefused), ZB_OK,
                      "9078: \"A many-to-one route request command frame is not retried\", so the interval passes unheeded");

    Test_Expect(sent == 0, "and nothing was sent for it");
    Test_Expect(record != 0 && record->transmissions == 1, "the record counts one transmission of the schedule it is worth");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "one frame on the air, and the discovery entry 9078 still creates is the receipt half's");
    Test_ExpectCount(airDestOf(&air[0]), MAC_FRAME_ADDR_BROADCAST,
                     "with 0xffff in the MAC destination for Table 3-80's routers class, which is where a many-to-one request goes (3.6.4.5) and what 3.2.1.1.3 step 6 a.3 makes of it");
}

void caseRouteDiscoveryTimesOut(void)
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

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS), ZB_OK, "a discovery starts");
    runTheSchedule(&dev, air, &airCount);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + NWK_ROUTE_DISCOVERY_TIME_MS - 1), ZB_OK,
                      "one millisecond before nwkcRouteDiscoveryTime has run out");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 1, "and the discovery is still live");
    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), 0, "with the request still waiting, unanswered");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + NWK_ROUTE_DISCOVERY_TIME_MS), ZB_OK,
                      "the millisecond the timer expires");

    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 0, "3.6.4.5.1.7: the entry is deleted from the route discovery table");
    Test_Expect(Nwk_RouteOf(dev.nwk.routes, UNSEEN) == 0,
                "and the routing entry for that destination with it, its status being DISCOVERY_UNDERWAY and no other entry seeking the destination");
    Test_ExpectCount(Nwk_RouteQueue(&dev.nwk), 0, "the routing table is a slot emptier than it was");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_ExpectCount(got, 1, "one confirmation, and exactly one: one request, one answer");
    Test_ExpectCount(confirms[0].nwkStatus, NWK_STATUS_ROUTE_ERROR,
                     "Table 3-84's ROUTE_ERROR, 0xd1: an attempt to discover a route has failed");
    Test_ExpectStatus(confirms[0].status, ZB_ERR_NO_ROUTE, "the seam's word for it, no transmit having run at all");
    Test_ExpectCount(confirms[0].dstAddr, UNSEEN, "for the destination it was asked about");
    Test_ExpectCount(confirms[0].attempts, 0, "no attempt of the application's frame ran");
    Test_Expect(confirms[0].handle == RADIO_HANDLE_NONE, "and no transmit of it was ever issued");

    Test_ExpectCount(airCount, NWK_RREQ_TX_COUNT, "four frames on the air and no fifth");

    for (i = 0; i < airCount; i++)
        Test_Expect(npduLenOf(&air[i]) == npduLenOf(&air[0])
                    && Zb_memcmp(npduOf(&air[i]), npduOf(&air[0]), npduLenOf(&air[0])) == 0,
                    "and every one of them is the Route Request: the application's frame is never silently re-sent, it is dropped and its request answered");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + NWK_ROUTE_DISCOVERY_TIME_MS + NWK_RREQ_RETRY_INTERVAL_MS),
                      ZB_OK, "a turn later");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, NWK_RREQ_TX_COUNT, "and the air stays empty: nothing was armed behind the timer");
    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), 0, "and no second confirmation was produced");
}

void caseRouteDiscoveryRunsAcrossTheWrap(void)
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

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, WRAP_START_MS), ZB_OK,
                      "a discovery started 4 s before the millisecond counter wraps");

    for (i = 0; i < NWK_RREQ_TX_COUNT; i++)
    {
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, WRAP_START_MS + i * NWK_RREQ_RETRY_INTERVAL_MS), ZB_OK,
                          "the turn of one transmission of the schedule");
        harvestAir(&dev.model, air, &airCount);
        Test_ExpectCount(airCount, i + 1, "which went out across the wrap like any other deadline");
    }

    Test_ExpectCount(WRAP_START_MS + NWK_ROUTE_DISCOVERY_TIME_MS, 0x1710,
                     "the timer's own instant is 0x1710, past the wrap: that is what makes this the case");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, WRAP_START_MS + NWK_ROUTE_DISCOVERY_TIME_MS), ZB_OK,
                      "the turn nwkcRouteDiscoveryTime has run out, read as a distance and not as two counters");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 0, "and the discovery entry is gone");
    Test_Expect(Nwk_RouteOf(dev.nwk.routes, UNSEEN) == 0, "with the routing entry 3.6.4.5.1.7 deletes");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_Expect(got == 1 && confirms[0].nwkStatus == NWK_STATUS_ROUTE_ERROR,
                "one ROUTE_ERROR confirmation, so the whole run (initiation, four broadcasts, timer) survived the wrap");
}

void caseDiscoveryExpiryForgetsTheSourcesRoute(void)
{
    Test_BandA dev;
    Nwk_RouteDiscoveryTableEntry *other;
    Nwk_RoutingTableEntry *route;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    route = seedRoute(dev.nwk.routes, 0, ROUTE_SOURCE, NWK_ROUTE_ACTIVE, HOP);
    (void)seedDiscovery(dev.nwk.discoveries, 0, ROUTE_SOURCE, 0x31, 1, 0, DISCOVERY_START_MS);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS), ZB_OK, "a discovery entry's expiration arrives");
    Test_Expect(Nwk_DiscoveryOf(dev.nwk.discoveries, ROUTE_SOURCE, 0x31) == 0,
                "3.6.4.5.1.7: the entry is deleted from the route discovery table");
    Test_ExpectCount(route->inUse, 1,
                     "3.6.4.5.6: and the routing entry for that entry's source, being ACTIVE, is left alone");
    Test_ExpectCount(route->status, NWK_ROUTE_ACTIVE, "with the status it holds");

    route->status = NWK_ROUTE_INACTIVE;
    (void)seedDiscovery(dev.nwk.discoveries, 0, ROUTE_SOURCE, 0x32, 1, 0, DISCOVERY_START_MS);
    other = seedDiscovery(dev.nwk.discoveries, 1, ROUTE_SOURCE, 0x33, 1, 0,
                          DISCOVERY_START_MS + 2 * NWK_RREQ_RETRY_INTERVAL_MS);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + 1), ZB_OK,
                      "an entry expires against a routing entry whose status is not ACTIVE");
    Test_ExpectCount(route->inUse, 1,
                     "and the routing entry stays: another discovery entry corresponds to it, which is the clause's second test");

    other->expiresAtMs = DISCOVERY_START_MS + 1;

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + 2), ZB_OK, "and the last entry corresponding to it expires");
    Test_ExpectCount(route->inUse, 0,
                     "3.6.4.5.6: now the routing entry is deleted too, any status other than ACTIVE, and nothing left seeking it");
    Test_ExpectCount(route->destinationAddress, 0, "the released slot carries nothing of the entry that was deleted");
}

void caseRouteDiscoveryRefusesAFullDiscoveryTable(void)
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

    for (i = 0; i < NWK_DISCOVERY_MAX; i++)
        (void)seedDiscovery(dev.nwk.discoveries, i, 0x2100 + i, (uint8_t)i, 1, 0,
                            DISCOVERY_START_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), NWK_DISCOVERY_MAX, "every slot of Table 3-79's pool is live and none has expired");

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS), ZB_OK,
                      "a request whose discovery has no slot: accepted, then refused by the pool it needs");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_ExpectCount(got, 1, "one confirmation");
    Test_ExpectStatus(confirms[0].status, ZB_ERR_NO_SPACE,
                      "the pool's own refusal, which is what 3.6.4.5.1's establishment cannot answer without a slot");
    Test_ExpectCount(confirms[0].nwkStatus, NWK_STATUS_ROUTE_DISCOVERY_FAILED,
                     "with Table 3-84's 0xd0: a full discovery table is a failure for a reason other than a lack of routing capacity, which 0xd0 excludes and the routing table's own claim never produces");
    Test_ExpectCount(confirms[0].dstAddr, UNSEEN, "for the destination it was asked about");

    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), NWK_DISCOVERY_MAX, "the pool holds what it held before");
    Test_Expect(Nwk_RouteOf(dev.nwk.routes, UNSEEN) == 0,
                "and no DISCOVERY_UNDERWAY entry was left behind for a discovery that never began");
    Test_ExpectCount(dev.nwk.routeRequestId, 0, "3.4.1.3.2's counter did not move: no request was issued");
    Test_ExpectCount(dev.nwk.routingSequenceNumber, 0, "and neither did nwkRoutingSequenceNumber");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS), ZB_OK, "the next step");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "and nothing went on the air");
    Test_ExpectCount(Nwk_RouteRequestsSent(&dev.nwk), 0, "no Route Request was broadcast");
}

void caseRouteDiscoveryOverAFullRouteTable(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    Nwk_RoutingTableEntry *route;
    uint32_t airCount = 0;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    for (i = 0; i < NWK_ROUTE_MAX; i++)
        (void)seedRoute(dev.nwk.routes, i, 0x2100 + i, NWK_ROUTE_ACTIVE, HOP);

    Test_ExpectCount(Nwk_RouteQueue(&dev.nwk), NWK_ROUTE_MAX, "every slot of the routing table's pool is held by an ACTIVE route elsewhere");

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS), ZB_OK,
                      "and a discovery for one more destination is still started");

    route = Nwk_RouteOf(dev.nwk.routes, UNSEEN);

    Test_Expect(route != 0 && route->status == NWK_ROUTE_DISCOVERY_UNDERWAY,
                "9047-9054's entry is claimed rather than refused: 3.6.4.8's ranking evicts the least-used entry, so a full routing table never answers with a status");
    Test_ExpectCount(Nwk_RouteQueue(&dev.nwk), NWK_ROUTE_MAX, "and the table holds what it held");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 1, "with Table 3-79's entry for it made");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS), ZB_OK, "the next step");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "and the Route Request went out, which is what a refused claim could not have produced");
}


/*
 * 3.6.4.3 puts a second frame for a destination whose discovery is under way into that discovery: "If the device
 * initiated the discovery, the frame SHALL be treated as though route discovery has been initiated for this
 * frame", the routing entry carries DISCOVERY_UNDERWAY, Table 3-79 holds the entry this device created, and the
 * frame waits on it. A second initiation instead would spend a second request id, a second Table 3-79 slot and a
 * second copy of 3.6.4.5.1's schedule, and (3.6.4.5.1.7) let the first entry's timer fail the second request.
 */
void caseSecondRequestJoinsTheRunningDiscovery(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    Nwk_RouteDiscoveryTableEntry *entry;
    uint32_t airCount = 0;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS), ZB_OK, "a discovery starts for a destination");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS), ZB_OK, "and its first broadcast goes out");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "one Route Request on the air");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 1, "and one Table 3-79 entry holding it");
    Test_ExpectCount(dev.nwk.routeRequestId, 1, "numbered with the first request id 3.4.1.3.2 spends");

    entry = Nwk_DiscoveryOf(dev.nwk.discoveries, OWN_SHORT, 1);

    Test_Expect(entry != 0 && entry->destAddr == UNSEEN,
                "the entry names the destination this device is discovering, which is the pair 3.6.4.3 asks the table for");

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS + 10), ZB_OK,
                      "and a second request for the same destination, ten milliseconds later");

    Test_ExpectCount(Nwk_TransmitQueue(&dev.nwk), 2, "waits like the first");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 1, "on the one discovery this device is running: no second Table 3-79 slot was taken");
    Test_ExpectCount(dev.nwk.routeRequestId, 1, "and no second request id was spent");
    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), 0, "with nothing answered: both requests wait for the same route");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + NWK_RREQ_RETRY_INTERVAL_MS), ZB_OK,
                      "the turn the first schedule's second broadcast is due");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 2, "which is one more Route Request and not two: the schedule is the one discovery's");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + NWK_ROUTE_DISCOVERY_TIME_MS), ZB_OK,
                      "and the turn that discovery's timer expires");
    harvestAir(&dev.model, air, &airCount);

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_ExpectCount(got, 2, "answers both requests the discovery carried, and only those: one reply per waiting frame");
    Test_ExpectCount(confirms[0].nwkStatus, NWK_STATUS_ROUTE_ERROR, "with Table 3-84's ROUTE_ERROR, as the timer's own answer");
    Test_ExpectCount(confirms[1].nwkStatus, NWK_STATUS_ROUTE_ERROR, "for each of them");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 0, "and the entry the timer judged is gone");
}

/*
 * 3.6.4.5.1.7's timer names the entry it deletes and the routing entry that goes with it; what it says nothing
 * about is which of Table 3-79's entries a waiting frame belongs to, and a stack that answers by destination
 * alone fails one discovery's requests with another's timer. Two discoveries for two destinations run at once
 * here, and each timer answers only its own.
 */
void caseDiscoveryExpiryAnswersItsOwnRequestOnly(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS), ZB_OK,
                      "a discovery for one destination, at one instant");

    req = nldeReq(HOP, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS + 5000), ZB_OK,
                      "and a second for another destination, five seconds later");

    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 2, "two discoveries, two Table 3-79 entries");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + NWK_ROUTE_DISCOVERY_TIME_MS), ZB_OK,
                      "the first entry's timer expires");
    harvestAir(&dev.model, air, &airCount);

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_ExpectCount(got, 1, "one confirmation, for the request whose discovery ran out");
    Test_ExpectCount(confirms[0].dstAddr, UNSEEN, "and it is the first destination's");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 1, "the other discovery is still live, its own timer not yet due");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + 5000 + NWK_ROUTE_DISCOVERY_TIME_MS - 1), ZB_OK,
                      "a millisecond before the second timer is due");

    Test_ExpectCount(Nwk_ConfirmQueue(&dev.nwk), 0,
                     "and nothing has answered the second request: one discovery's timer does not fail another's");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + 5000 + NWK_ROUTE_DISCOVERY_TIME_MS), ZB_OK,
                      "the millisecond it is due");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_ExpectCount(got, 1, "and the second request is answered by its own discovery's timer");
    Test_ExpectCount(confirms[0].dstAddr, HOP, "for the destination that discovery was for");
    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 0, "with no entry left behind");
}

/*
 * 3.4.1.2, the second of its two bullets: "The source IEEE address sub-field of the frame control field SHALL be
 * set to 1 and the source IEEE address field of the NWK header SHALL be present and SHALL contain the 64-bit
 * IEEE address of the originator of the frame." 3.3.1.7 gives the field its use (a receiver checks the source
 * IEEE against the neighbour entry it holds for the network address) and 3.4.2.3.6 makes it the address a reply
 * names the originator by, so a request without it cannot be answered as the clause requires.
 */
void caseRouteRequestCarriesTheOriginatorsIeee(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_Frame frame;
    Nwk_DataRequestParameters req;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    setOwnIeee(&dev, OWN_IEEE_VALUE);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS), ZB_OK,
                      "a request for an address with no route starts 3.6.4.5.1's discovery");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS), ZB_OK, "and the first broadcast of its schedule goes out");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "one Route Request on the air");

    npduLen = npduLenOf(&air[0]);
    Zb_memcpy(npdu, npduOf(&air[0]), npduLen);

    Test_ExpectStatus(NwkFrame_Parse(npdu, npduLen, &frame, &payloadOffset, &payloadLen), ZB_OK,
                      "whose header this stack's own codec reads back");
    Test_ExpectCount((uint32_t)frame.srcIeeePresent, 1,
                     "with the source IEEE address sub-field set to 1: 3.4.1.2 says it SHALL be, for every route request");
    Test_Expect(frame.srcIeee == OWN_IEEE_VALUE,
                "and the field holding the originator's 64-bit extended address: this device's, the frame's originator being the device that broadcasts it");
    Test_ExpectCount(payloadOffset, NWK_MIN_HEADER_OVERHEAD + NWK_IEEE_ADDR_OCTETS,
                     "so the payload begins one IEEE field past the minimal header, which is where 3.4.1.3's command identifier is read");
    Test_ExpectCount((uint32_t)npdu[payloadOffset], NWK_CMD_ROUTE_REQUEST,
                     "and it begins with Table 3-54's 0x01");

    /* 3.4.1.2 is the request's own clause; the relay 3.6.4.5.1.4 puts on the air is a frame of this device's,
       with this device's address in the source field, and it carries that address's IEEE beside it. */
    Test_Expect(Nwk_RouteRequestsSent(&dev.nwk) == 1 && Nwk_DiscoveryQueue(&dev.nwk) == 1,
                "one request sent, one discovery running");
}

/* A third destination, so a case can show one discovery's stop leaving another's schedule alone. */
#define THIRD_DESTINATION 0x5555

/*
 * 9b. One schedule per discovery, not one schedule for the device.
 *
 * 3.6.4.5.1 (9072-9075): "When broadcasting a route request command frame at the initiation of route discovery,
 * the NWK layer SHALL retry the broadcast nwkcInitialRREQRetries times after the initial broadcast, resulting in a
 * maximum of nwkcInitialRREQRetries + 1 transmissions." That count belongs to the initiation, and 3.6.4.3 makes a
 * second destination's request a discovery of its own: "the device SHALL initiate route discovery as described in
 * section 3.6.4.5.1". Two live discoveries are therefore two live schedules, each found by Table 3-79's key, the
 * destination and the request id its initiation numbered (3.4.1.3.2), and a timer that deletes one entry
 * (3.6.4.5.1.7) stops that request's schedule and no other.
 *
 * The pool is the discovery table's own size, which is what makes the two tables agree: every initiation claims
 * one entry and one record, and both are released by the same key. The second half of the case reuses a freed
 * slot before the next expiry so that a stop which took "the" record rather than the named one would be visible.
 */
void caseTwoDiscoveriesKeepTwoSchedules(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    Nwk_RreqTx *first;
    Nwk_RreqTx *second;
    uint8_t firstId;
    uint8_t secondId;
    uint32_t airCount = 0;
    uint32_t got;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS), ZB_OK, "a discovery for one destination");
    firstId = dev.nwk.routeRequestId;

    req = nldeReq(HOP, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS + 1), ZB_OK,
                      "and a second one millisecond later for another destination, which 3.6.4.3 makes a discovery of its own");
    secondId = dev.nwk.routeRequestId;

    Test_ExpectCount(Nwk_DiscoveryQueue(&dev.nwk), 2, "two Table 3-79 entries");
    Test_ExpectCount(Nwk_RreqTxHeld(dev.nwk.rreqTx), 2,
                     "and two schedules beside them: one record per entry an initiation creates, in a pool of that table's size");

    first = Nwk_RreqTxOf(dev.nwk.rreqTx, UNSEEN, firstId);
    second = Nwk_RreqTxOf(dev.nwk.rreqTx, HOP, secondId);

    Test_Expect(first != 0 && second != 0 && first != second,
                "each found by (destination, request id), so neither initiation can be mistaken for the other");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS), ZB_OK, "the first turn, which owes the first request's first broadcast");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "one Route Request on the air");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + 1), ZB_OK, "and the next, which owes the second's");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 2, "two of them, one per discovery: the second initiation did not spend the first's schedule");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, scheduleAt(1)), ZB_OK, "the first retry interval");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 3,
                     "gives the first discovery its second broadcast: one record for the whole device would owe nothing here, the second initiation having wiped the first's count");
    Test_Expect(first != 0 && first->transmissions == 2 && second != 0 && second->transmissions == 1,
                "and each record counts only its own transmissions");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, scheduleAt(1) + 1), ZB_OK, "one millisecond later the second schedule is due");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 4, "and the second discovery has its second broadcast too");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, scheduleAt(2)), ZB_OK, "the third transmissions, each on its own schedule's instant");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, scheduleAt(2) + 1), ZB_OK, "the second one millisecond later");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, scheduleAt(3)), ZB_OK, "and the fourth");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, scheduleAt(3) + 1), ZB_OK, "one millisecond after it");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 2 * NWK_RREQ_TX_COUNT, "eight broadcasts: nwkcInitialRREQRetries + 1 for each of the two discoveries");
    Test_Expect(first != 0 && first->transmissions == NWK_RREQ_TX_COUNT
                && second != 0 && second->transmissions == NWK_RREQ_TX_COUNT,
                "both schedules complete, neither one having spent the other's count");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + NWK_ROUTE_DISCOVERY_TIME_MS), ZB_OK,
                      "the first discovery's timer arrives");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 2 * NWK_RREQ_TX_COUNT, "and no broadcast is owed: both schedules are spent, the entries are not");

    Test_Expect(Nwk_RreqTxOf(dev.nwk.rreqTx, UNSEEN, firstId) == 0,
                "3.6.4.5.1.7's deletion stops the schedule of the request it deleted");
    Test_Expect(Nwk_RreqTxOf(dev.nwk.rreqTx, HOP, secondId) != 0,
                "and leaves the other destination's alone: the stop names a request and not 'the' schedule");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);

    Test_Expect(got == 1 && confirms[0].dstAddr == UNSEEN && confirms[0].nwkStatus == NWK_STATUS_ROUTE_ERROR,
                "the frame that waited on the first discovery is confirmed Table 3-84's ROUTE_ERROR, and only it");

    /* The record the stop freed is taken again at once, so the next stop has two candidates to choose between */
    req = nldeReq(THIRD_DESTINATION, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, DISCOVERY_START_MS + NWK_ROUTE_DISCOVERY_TIME_MS), ZB_OK,
                      "a third discovery at that instant, which takes the record the first one released");
    Test_ExpectCount(Nwk_RreqTxHeld(dev.nwk.rreqTx), 2, "two schedules again");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, DISCOVERY_START_MS + NWK_ROUTE_DISCOVERY_TIME_MS + 1), ZB_OK,
                      "and the turn the second discovery's own timer arrives on");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_RreqTxOf(dev.nwk.rreqTx, HOP, secondId) == 0, "the second discovery's schedule stops with its entry");
    Test_Expect(Nwk_RreqTxOf(dev.nwk.rreqTx, THIRD_DESTINATION, dev.nwk.routeRequestId) != 0,
                "and the third's, holding the slot the first stop freed, is untouched: a stop that took 'the' record would take this one instead");
    Test_ExpectCount(Nwk_RreqTxHeld(dev.nwk.rreqTx), 1, "one schedule left");
    Test_ExpectCount(airCount, 2 * NWK_RREQ_TX_COUNT + 1, "and the third discovery's first broadcast, which that turn owed, is the only frame on the air");
}

/* A request this device forwards is a schedule of its own: two senders, two identifiers, two records. */
#define RELAY_SOURCE_B 0x3a3a
#define RELAY_REQUEST_ID_A 0x21
#define RELAY_REQUEST_ID_B 0x22
#define RELAY_NOW_MS 5000

/* One Route Request as a neighbour sends it: Figure 3-9's payload behind 3.4.1.2's header, at the initial radius. */
static uint32_t relayedRequestNpdu(uint8_t *npdu, uint16_t sourceAddr, uint16_t destAddr, uint8_t requestId)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestPayload request;
    uint32_t payloadLen;
    uint32_t routingSeq;

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.requestId = requestId;
    request.destAddr = destAddr;
    request.manyToOne = NWK_RREQ_MANY_TO_ONE_NONE;
    request.maxSourceRoute = NWK_MAX_SOURCE_ROUTE;

    routingSeq = 0x1234;

    Test_ExpectStatus(Nwk_RreqCompose(&request, &routingSeq, NWK_INITIAL_RADIUS, payload,
                                      (uint32_t)sizeof payload, &payloadLen), ZB_OK,
                      "the request the case injects is a payload this stack's own codec composes");

    return makeNpdu(npdu, NWK_ADDR_ROUTERS, sourceAddr, NWK_INITIAL_RADIUS, 0x40, NWK_FRAME_TYPE_COMMAND, 0,
                    payload, payloadLen);
}

/* A forwarding neighbour with both Table 3-75 cost fields a link status exchange would fill. */
static void relayForwarder(Nwk_Nwk *nwk, uint16_t addr)
{
    Nwk_NeighborTableEntry *forwarder;

    seedNeighbor(nwk, addr, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    forwarder = neighborAt(nwk, addr);

    Test_Expect(forwarder != 0, "the neighbor table holds the forwarding device");

    if (forwarder == 0)
        return;

    forwarder->outgoingCost = 2;
}

/*
 * 9c. One schedule per relayed request, not one for the device.
 *
 * 3.6.4.5.1.4 (9190-9192): "The NWK layer SHALL retry the broadcast nwkcRREQRetries times after the original relay
 * resulting in a maximum of nwkcRREQRetries + 1 relays per relay attempt. Implementers MAY choose to discard route
 * request command frames awaiting retransmission in the case that a frame with the same source and route request
 * identifier arrives with a lower path cost than the one awaiting retransmission." Two devices' requests are two
 * "frames awaiting retransmission" and have different (source, request id) keys, so the discard the clause permits
 * does not reach them: each is relayed nwkcRREQRetries + 1 times, and a record for the device alone would spend one
 * of them on wiping the other's count.
 */
void caseTwoRelayedRequestsKeepTwoSchedules(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    uint8_t first[RADIO_MPDU_MAX];
    uint8_t second[RADIO_MPDU_MAX];
    uint32_t firstLen;
    uint32_t secondLen;
    uint32_t airCount = 0;

    /* No jitter seed: 3.6.4.5.1.4's draw is 0 ms, so both relays are due in the turn they are armed */
    rigAtSeed(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1, 0, 0);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);
    relayForwarder(&dev.nwk, NEIGHBOR);
    relayForwarder(&dev.nwk, RELAY_SOURCE_B);

    firstLen = relayedRequestNpdu(first, NEIGHBOR, UNSEEN, RELAY_REQUEST_ID_A);
    secondLen = relayedRequestNpdu(second, RELAY_SOURCE_B, HOP, RELAY_REQUEST_ID_B);

    injectNpdu(&dev, first, firstLen, NEIGHBOR);
    injectNpdu(&dev, second, secondLen, RELAY_SOURCE_B);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, RELAY_NOW_MS), ZB_OK, "the turn two neighbours' requests arrive on");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, RELAY_NOW_MS), ZB_OK, "and the turn their equally-jittered relays are due on");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 2, "two relays on the air, one per request this device owes one for");
    Test_ExpectCount(Nwk_RreqTxHeld(dev.nwk.rreqRelay), 2,
                     "and two records beside them: each keyed by the request's originator and identifier, the pair 9191-9192's discard rule names");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, RELAY_NOW_MS + NWK_RREQ_RETRY_INTERVAL_MS), ZB_OK,
                      "the interval 3.6.4.5.1.4 shares with 3.6.4.5.1");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 4, "gives both requests their second relay");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, RELAY_NOW_MS + 2 * NWK_RREQ_RETRY_INTERVAL_MS), ZB_OK,
                      "and the next one their third");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 2 * (NWK_RREQ_RETRIES + 1),
                     "six: nwkcRREQRetries + 1 relays for each of the two requests, neither one having taken the other's count");
    Test_ExpectCount(Nwk_RreqTxHeld(dev.nwk.rreqRelay), 0,
                     "and both records are released with their last transmission: a relay is a moment in one frame's transit");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, RELAY_NOW_MS + 3 * NWK_RREQ_RETRY_INTERVAL_MS), ZB_OK,
                      "a turn a fourth relay would have been due on");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 2 * (NWK_RREQ_RETRIES + 1), "and nothing more goes out");

    /* The device's own discovery schedule is a different pool and was never touched by either relay */
    req = nldeReq(UNSEEN, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, RELAY_NOW_MS + 3 * NWK_RREQ_RETRY_INTERVAL_MS), ZB_OK,
                      "a discovery of this device's own, begun beside both relays");
    Test_ExpectCount(Nwk_RreqTxHeld(dev.nwk.rreqRelay), 0, "moves no relay record");
    Test_ExpectCount(Nwk_RreqTxHeld(dev.nwk.rreqTx), 1, "and claims its own");
}
