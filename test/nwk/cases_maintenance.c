/* 3.6.4.4.4's ageing, 3.6.4.8.1's failed-link signal, 3.6.6's passive acknowledgement and Table 3-78's
   DISCOVERY_FAILED, as the façade runs them: four rules that need a device rather than a pool, the sweep a step
   performs, the answer a MAC confirmation carries, the copy a neighbour relays and the timer that ends a discovery
   whose destination somebody else is still asking about. Every number a case asserts is one a clause or a table
   prints, and each case names the clause it enforces; the rig, the frame builder and the air log are
   `nwk_helpers.c`'s, as in every other case file of this suite. */

#include "nwk_routeflow_cases.h"

#include "loopback_radio.h"
#include "mac.h"
#include "nwk.h"
#include "nwk_discovery.h"
#include "nwk_frame.h"
#include "nwk_status.h"
#include "nwk_helpers.h"
#include "nwk_linkstatus.h"
#include "nwk_route.h"
#include "nwk_routeflow_helpers.h"
#include "nwk_cost.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

enum
{
    AGED_HOP = 0x4444,              /* the neighbour a route request arrives from, and the link that ages out */
    FAR_DEST = 0x6666,              /* a unicast destination the routing table holds a route to */
    BROKEN_HOP = 0x7777,            /* the next hop that answers NO_ACK: 3.6.4.8.1's broken link */
    RELAY_SOURCE = 0x8888,          /* the device whose unicast this device forwards, and the status's destination */
    BROADCAST_SOURCE = 0x2345,      /* the neighbour whose broadcast this device relays (3.6.6) */
    OTHER_RELAY = 0x5555,           /* a second neighbour, whose copy of that broadcast is the passive acknowledgement */

    REPORT_RADIUS = 5,              /* a radius a relayed frame arrives with, one decrement in */
    NOW = 1000,                     /* the clock a case starts its device at */
    LATER = 5000,                   /* a second clock, inside the 10 s a Table 3-79 entry lives */
    ROUTE_REQUEST_ID = 0x21,        /* 3.4.1.3.2's identifier of the request a case injects */
    BROADCAST_SEQ = 0x33,           /* 3.3.1.5's number of the broadcast a case injects */
    FAILURE_COST = 0x1234           /* Table 3-77's Sequence Number a broken route carries */
};

/* The route request a neighbour sends towards a device of no interest: 3.6.4.5.1.2 looks its sender up. */
/* A link status from `sender` with one entry naming `named` at the cost it measures for it. */
static uint32_t composeLinkStatusNaming(uint8_t *npdu, uint16_t sender, uint16_t named, uint32_t cost, uint8_t seq)
{
    uint8_t payload[2 + NWK_LINK_STATUS_ENTRY_LEN];

    payload[0] = NWK_CMD_LINK_STATUS;
    payload[1] = NWK_LINK_STATUS_OPTIONS_FIRST | NWK_LINK_STATUS_OPTIONS_LAST | 1;
    payload[2] = (uint8_t)(named & 0xff);
    payload[3] = (uint8_t)(named >> 8);
    payload[4] = (uint8_t)cost;

    return makeNpdu(npdu, NWK_ADDR_ROUTERS, sender, 1, seq, NWK_FRAME_TYPE_COMMAND, 0, payload, (uint32_t)sizeof payload);
}

static uint32_t composeRequest(uint8_t *npdu, uint16_t source, uint8_t pathCost)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    Nwk_RouteRequestPayload request;
    uint32_t payloadLen;
    uint32_t routingSeq = 0x3000;

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.requestId = ROUTE_REQUEST_ID;
    request.destAddr = FAR_DEST;
    request.pathCost = pathCost;
    request.maxSourceRoute = NWK_MAX_SOURCE_ROUTE;

    Test_ExpectStatus(Nwk_RreqCompose(&request, &routingSeq, NWK_INITIAL_RADIUS, payload,
                                      (uint32_t)sizeof payload, &payloadLen), ZB_OK,
                      "the request a case injects is a payload this stack's own codec composes");

    return makeNpdu(npdu, NWK_ADDR_ROUTERS, source, NWK_INITIAL_RADIUS, 0x40, NWK_FRAME_TYPE_COMMAND, 0,
                    payload, payloadLen);
}

/*
 * 3.6.4.4.4: a link nobody has been heard over for more than nwkRouterAgeLimit link status periods has no outgoing
 * cost left, so 3.6.4.5.1.2 terminates route request processing over it and 3.6.4.8.1's consequence takes the routes
 * that used it out of the table's use; a dead link stops being chosen instead of being chosen forever.
 */
void caseNeighborAgesOutOfUse(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_NeighborTableEntry *aged;
    Nwk_RoutingTableEntry *through;
    Nwk_DataRequestParameters req;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);
    seedNeighbor(&dev.nwk, AGED_HOP, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    through = seedRoute(dev.nwk.routes, 0, FAR_DEST, NWK_ROUTE_ACTIVE, AGED_HOP);

    Test_Expect(through != 0, "the routing table holds a route to a distant destination through that neighbour");

    /* A link status naming this device, the one frame 8168-8172 take a cost and an age from */
    npduLen = composeLinkStatusNaming(npdu, AGED_HOP, OWN_SHORT, 2, 0x52);
    injectNpdu(&dev, npdu, npduLen, AGED_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW), ZB_OK, "a link status arrives from the neighbour");

    aged = neighborAt(&dev.nwk, AGED_HOP);

    Test_ExpectCount(aged ? aged->outgoingCost : 0xff, 2, "8168: the outgoing cost is what that frame stated");
    Test_Expect(aged != 0 && aged->ageFromMs == NOW, "with the moment it arrived stamped beside it");
    Test_ExpectCount(aged ? aged->age : 0xff, 0, "and 3.6.4.4.4's interval count at zero: it was heard this interval");

    req = nldeReq(FAR_DEST, nsdu, NSDU_LEN, 0);

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, NOW + 1), ZB_OK,
                      "a unicast to that destination is taken over the route the table holds");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airDestOf(&air[0]), AGED_HOP, "3.6.4.3: aimed at the next hop of the ACTIVE entry");

    /* Data from the neighbour is no link status, so the count below still runs out */
    npduLen = makeNpdu(npdu, OWN_SHORT, AGED_HOP, REPORT_RADIUS, 0x54, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, AGED_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + 3 * NWK_LINK_STATUS_PERIOD_MS), ZB_OK, "a data frame three periods on");
    Test_ExpectCount(aged ? aged->outgoingCost : 0xff, 2, "leaves the cost as stated");
    Test_ExpectCount(aged ? aged->age : 0xff, NWK_ROUTER_AGE_LIMIT, "and the age counting from that link status");

    /* One tick past nwkRouterAgeLimit's three nwkLinkStatusPeriod intervals of Table 3-66's 0xa6 */
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + 4 * NWK_LINK_STATUS_PERIOD_MS), ZB_OK,
                      "time passes with nothing heard from the neighbour");

    Test_ExpectCount(Nwk_NeighborsAgedOut(&dev.nwk), 1,
                     "3.6.4.4.4: the age exceeded nwkRouterAgeLimit, so the entry's outgoing cost is set to 0");
    Test_Expect(aged != 0 && aged->outgoingCost == 0, "and 0 is Table 3-75's 'no outgoing cost is available'");
    Test_Expect(aged != 0 && aged->age == NWK_ROUTER_AGE_LIMIT + 1,
                "in the unit Table 3-75 prints: nwkLinkStatusPeriod intervals");

    /* 3.6.4.8: a link with nothing measured is a failed link, and its consequence is that the routes through it are
       invalidated rather than used again (3.6.4.8.1) */
    Test_ExpectCount(Nwk_RoutesInvalidated(&dev.nwk), 1, "the route through that hop is invalidated");
    Test_ExpectCount(through ? through->status : 0xff, NWK_ROUTE_INACTIVE, "Table 3-78's 0x3");

    req = nldeReq(FAR_DEST, nsdu, NSDU_LEN, 0);

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, NOW + 4 * NWK_LINK_STATUS_PERIOD_MS + 1), ZB_OK,
                      "a second unicast to the same destination");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount((uint32_t)Nwk_PollConfirms(&dev.nwk, confirms, 4), 2,
                     "two confirmations: the first unicast's success and this one's refusal");
    Test_ExpectCount(confirms[1].nwkStatus, NWK_STATUS_ROUTE_ERROR,
                     "3.6.4.3's third case: no route, and Table 3-84's ROUTE_ERROR beside the seam's refusal");
    Test_ExpectCount(airCount, 2, "and the air holds the first unicast and this period's link status");
    Test_ExpectCount(airDestOf(&air[1]), 0xffff, "which is a broadcast: the dead link is no longer chosen");

    /* Only a link status brings the cost and the count back */
    npduLen = makeNpdu(npdu, OWN_SHORT, AGED_HOP, REPORT_RADIUS, 0x53, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, AGED_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + 4 * NWK_LINK_STATUS_PERIOD_MS + 2), ZB_OK,
                      "a data frame from the device that had gone quiet");
    Test_Expect(aged != 0 && aged->outgoingCost == 0, "does not bring the cost back");

    npduLen = composeLinkStatusNaming(npdu, AGED_HOP, OWN_SHORT, 2, 0x55);
    injectNpdu(&dev, npdu, npduLen, AGED_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + 4 * NWK_LINK_STATUS_PERIOD_MS + 3), ZB_OK, "a link status from it");
    Test_Expect(aged != 0 && aged->outgoingCost == 2 && aged->age == 0, "does: the cost it stated, and the count at zero");
}

/* 8874-8877: a relay every attempt of which ends NO_ACK: the first has just been answered, and each retry waits out
   nwkcUnicastRetryDelay. Answers the time the last answer came. */
static uint32_t relayExhausted(Test_BandA *dev, Air *air, uint32_t *airCount, uint32_t answeredAt)
{
    uint32_t at = answeredAt;
    uint32_t attempt;

    for (attempt = 0; attempt < NWK_UNICAST_RETRIES; attempt++)
    {
        Test_ExpectCount(*airCount, attempt + 1, "the attempts so far, and no status while any is left");

        at += NWK_UNICAST_RETRY_DELAY_MS;
        Test_ExpectStatus(Test_NwkStep(&dev->nwk, at), ZB_OK, "the turn the delay ends on");
        harvestAir(&dev->model, air, airCount);
        at++;
        Test_ExpectStatus(Test_NwkStep(&dev->nwk, at), ZB_OK, "and the turn the MAC answers it on");
        harvestAir(&dev->model, air, airCount);
    }

    return at;
}

/*
 * 3.6.4.8.1: a unicast this device is forwarding that fails with NO_ACK is a broken link, so the entries that used
 * that hop are invalidated (Table 3-78's INACTIVE) and a Network Status with Table 3-56's 0x02 goes back to the
 * frame's source, carrying 3.4.3.3.2's two-octet destination and K.4.1.1's routing sequence number.
 */
void caseNoAckComposesTheLinkFailureStatus(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_RoutingTableEntry *through;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint32_t at;

    rig(&dev, OWN_SHORT, PAN_ID);

    /* The answer the radio gives: NO_ACK, which is ZB_ERR_DEVICE at the seam (docs/internals/protocol.md §7.3) */
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 0);
    seedNeighbor(&dev.nwk, RELAY_SOURCE, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    through = seedRoute(dev.nwk.routes, 0, FAR_DEST, NWK_ROUTE_ACTIVE, BROKEN_HOP);
    through->sequenceNumber = FAILURE_COST;
    through->sequenceNumberValid = 1;

    npduLen = makeNpdu(npdu, FAR_DEST, RELAY_SOURCE, REPORT_RADIUS, 0x51, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, RELAY_SOURCE);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW), ZB_OK, "a unicast this device is not the end of");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "is forwarded once, over the hop the routing table names");
    Test_ExpectCount(airDestOf(&air[0]), BROKEN_HOP, "3.6.4.3: the next hop of the ACTIVE entry for that destination");
    Test_ExpectCount(Nwk_RelaysSent(&dev.nwk), 1, "and counted as the relay it is");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + 1), ZB_OK, "the turn the MAC answers NO_ACK on");
    harvestAir(&dev.model, air, &airCount);

    at = relayExhausted(&dev, air, &airCount, NOW + 1);

    Test_ExpectCount(Nwk_LinkFailuresReported(&dev.nwk), 1,
                     "3.6.4.8.1: \"the device SHALL issue a network status command frame back to the source device of the frame with a status code of 0x02\"");
    Test_ExpectCount(airCount, 2 + NWK_UNICAST_RETRIES, "and one frame followed the failed attempts: the status itself");
    Test_ExpectCount(airDestOf(&air[1 + NWK_UNICAST_RETRIES]), RELAY_SOURCE,
                     "3.4.3.2: its NWK header destination is the source address of the frame that failed");
    Test_Expect(fcfOf(&air[1 + NWK_UNICAST_RETRIES]) == AIR_UNICAST_FCF,
                "an ordinary unsecured command frame, acknowledged like any unicast this layer sends");

    Test_ExpectCount(npduLenOf(&air[1 + NWK_UNICAST_RETRIES]), NWK_MIN_HEADER_OVERHEAD + NWK_IEEE_ADDR_OCTETS + 8,
                     "3.4.3.2 makes the source IEEE address mandatory, and 3.4.3.3.2 with K.4.1.1's record is eight payload octets");
    Test_ExpectHex("the payload 3.4.3.3 and K.4.1.1 print: identifier, Table 3-56's 0x02, 3.4.3.3.2's destination, Figure K-5's record",
                   npduOf(&air[1 + NWK_UNICAST_RETRIES]) + NWK_MIN_HEADER_OVERHEAD + NWK_IEEE_ADDR_OCTETS, 8,
                   "0302666600013412");

    Test_ExpectCount(through->status, NWK_ROUTE_INACTIVE,
                     "and 3.6.4.8.1's second consequence: every entry that used the broken link is invalidated");
    Test_ExpectCount(Nwk_RoutesInvalidated(&dev.nwk), 1, "one entry, counted once");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, at + 1), ZB_OK, "a turn later");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_PollConfirms(&dev.nwk, confirms, 4), 0, "and the frame was this device's to carry, not to confirm");
}

/* 8874-8877 with a radio that has no room: the relay is not lost, and waits out the delay before it is asked again. */
void caseRelayRefusedIsAskedAgain(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, RELAY_SOURCE, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    (void)seedRoute(dev.nwk.routes, 0, FAR_DEST, NWK_ROUTE_ACTIVE, BROKEN_HOP);

    npduLen = makeNpdu(npdu, FAR_DEST, RELAY_SOURCE, REPORT_RADIUS, 0x53, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, RELAY_SOURCE);
    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW), ZB_OK, "a unicast to carry, on a radio with no room");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "is not on the air");
    Test_ExpectCount(Nwk_TxOccupied(dev.nwk.tx), 1, "but is held in a slot");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + NWK_UNICAST_RETRY_DELAY_MS - 1), ZB_OK, "a turn before the delay ends");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "still waits");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + NWK_UNICAST_RETRY_DELAY_MS), ZB_OK, "the turn the delay ends on");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "goes out");
    Test_ExpectCount(airDestOf(&air[0]), BROKEN_HOP, "to the hop it was going to");
    Test_ExpectCount(Nwk_RelaysSent(&dev.nwk), 1, "counted once");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + NWK_UNICAST_RETRY_DELAY_MS + 1), ZB_OK, "the turn the MAC answers on");
    Test_ExpectCount(Nwk_TxOccupied(dev.nwk.tx), 0, "and the slot is free again");
    Test_ExpectCount(Nwk_LinkFailuresReported(&dev.nwk), 0, "with nothing to report");
}

/* 9357 and D-261: a radio that refuses every attempt for room has shown no failed link. The frame is given up and
   counted, and a route that still stands is not torn down, here or at the source. */
void caseRelayRefusedEveryTimeIsReportedToItsSource(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_RoutingTableEntry *through;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint32_t at = NOW;
    uint32_t attempt;

    rig(&dev, OWN_SHORT, PAN_ID);
    seedNeighbor(&dev.nwk, RELAY_SOURCE, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    through = seedRoute(dev.nwk.routes, 0, FAR_DEST, NWK_ROUTE_ACTIVE, BROKEN_HOP);

    npduLen = makeNpdu(npdu, FAR_DEST, RELAY_SOURCE, REPORT_RADIUS, 0x54, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, RELAY_SOURCE);
    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 1 + NWK_UNICAST_RETRIES);

    for (attempt = 0; attempt <= NWK_UNICAST_RETRIES; attempt++)
    {
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, at), ZB_OK, "an attempt the radio has no room for");
        at += NWK_UNICAST_RETRY_DELAY_MS;
    }

    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "the relayed frame never reached the air and one frame did");
    Test_ExpectCount(airDestOf(&air[0]), RELAY_SOURCE, "8882-8883: the network status goes back to the frame's source");
    Test_ExpectCount(npduOf(&air[0])[NWK_MIN_HEADER_OVERHEAD + NWK_IEEE_ADDR_OCTETS + 1], NWK_NETWORK_STATUS_LINK_FAILURE,
                     "under the one code Table 3-56 prints for a frame that did not cross");
    Test_ExpectCount(dev.nwk.forwardsGivenUp, 1, "the frame is counted as given up");
    Test_ExpectCount(Nwk_LinkFailuresReported(&dev.nwk), 1, "and its failure as reported");
    Test_ExpectCount(through->status, NWK_ROUTE_ACTIVE, "no link was seen failing, so the route stands here");
    Test_ExpectCount(dev.nwk.routesInvalidated, 0, "and nothing was invalidated");
}

/* Every attempt at a relayed frame ends in a completion carrying `failure`, and the status that follows goes out. */
static void relayEndsEveryAttemptWith(Test_BandA *dev, ZbStatus failure, Air *air, uint32_t *airCount)
{
    Loopback_Outcome outcomes[LOOPBACK_TX_MAX];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t attempt;

    rig(dev, OWN_SHORT, PAN_ID);

    Zb_memset(outcomes, 0, (uint32_t)sizeof outcomes);

    for (attempt = 0; attempt <= NWK_UNICAST_RETRIES; attempt++)
        outcomes[attempt].status = failure;

    outcomes[NWK_UNICAST_RETRIES + 1].status = ZB_OK;
    outcomes[NWK_UNICAST_RETRIES + 1].isAcked = 1;
    LoopbackRadio_ScriptOutcomes(&dev->model, outcomes, NWK_UNICAST_RETRIES + 2);

    seedNeighbor(&dev->nwk, RELAY_SOURCE, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    seedNeighbor(&dev->nwk, BROKEN_HOP, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    seedRoute(dev->nwk.routes, 0, FAR_DEST, NWK_ROUTE_ACTIVE, BROKEN_HOP);

    npduLen = makeNpdu(npdu, FAR_DEST, RELAY_SOURCE, REPORT_RADIUS, 0x55, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(dev, npdu, npduLen, RELAY_SOURCE);

    Test_ExpectStatus(Test_NwkStep(&dev->nwk, NOW), ZB_OK, "a unicast to carry");
    harvestAir(&dev->model, air, airCount);
    Test_ExpectStatus(Test_NwkStep(&dev->nwk, NOW + 1), ZB_OK, "the turn the MAC answers on");
    harvestAir(&dev->model, air, airCount);
    relayExhausted(dev, air, airCount, NOW + 1);

    Test_ExpectCount(*airCount, 2 + NWK_UNICAST_RETRIES, "every attempt, and one frame after them");
    Test_ExpectCount(airDestOf(&air[1 + NWK_UNICAST_RETRIES]), RELAY_SOURCE, "the status, back to the frame's source");
    Test_ExpectCount(Nwk_LinkFailuresReported(&dev->nwk), 1, "reported once");
    Test_ExpectCount(dev->nwk.routes[0].status, NWK_ROUTE_ACTIVE, "and no link was seen failing, so the route stands");
}

/* 8874: "for any reason". A channel too busy to carry the frame on every attempt ends the same way as a neighbour that never answered, except that no link was seen failing. */
void caseRelayChannelBusyEveryTimeIsReportedToItsSource(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    uint32_t airCount = 0;

    relayEndsEveryAttemptWith(&dev, ZB_ERR_CHANNEL_ACCESS_FAILURE, air, &airCount);

    Test_ExpectCount(dev.nwk.forwardsGivenUp, 0, "the radio tried, so nothing was given up for room");
}

/* A frame that waited in the radio's line and never reached the wire says so in its completion, and that is not its neighbour's failure. */
/* An RCP that went quiet says nothing of the link: the frame may never have left, and every frame ends at once. */
void caseFrameLostWithTheRcpBlamesNoNeighbour(void)
{
    static const ZbStatus endings[] = { ZB_ERR_TIMEOUT, ZB_ERR_DEVICE_LOST };
    Test_BandA dev;
    Loopback_Outcome outcomes[LOOPBACK_TX_MAX];
    Air air[AIR_LOG_MAX];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount;
    uint32_t e;
    uint32_t i;

    for (e = 0; e < (uint32_t)(sizeof endings / sizeof endings[0]); e++)
    {
        airCount = 0;
        rig(&dev, OWN_SHORT, PAN_ID);

        Zb_memset(outcomes, 0, (uint32_t)sizeof outcomes);
        outcomes[0].status = endings[e];
        outcomes[1].status = ZB_OK;
        outcomes[1].isAcked = 1;
        LoopbackRadio_ScriptOutcomes(&dev.model, outcomes, 2);

        seedNeighbor(&dev.nwk, RELAY_SOURCE, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
        seedNeighbor(&dev.nwk, BROKEN_HOP, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
        seedRoute(dev.nwk.routes, 0, FAR_DEST, NWK_ROUTE_ACTIVE, BROKEN_HOP);

        npduLen = makeNpdu(npdu, FAR_DEST, RELAY_SOURCE, REPORT_RADIUS, 0x55, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
        injectNpdu(&dev, npdu, npduLen, RELAY_SOURCE);

        Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW), ZB_OK, "a unicast to carry");
        harvestAir(&dev.model, air, &airCount);
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + 1), ZB_OK, "the turn the MAC answers on");
        harvestAir(&dev.model, air, &airCount);

        Test_ExpectCount(dev.nwk.routes[0].status, NWK_ROUTE_ACTIVE, "the route stands");

        for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
        {
            if (dev.nwk.neighbors[i].inUse && dev.nwk.neighbors[i].networkAddress == BROKEN_HOP)
                Test_ExpectCount(dev.nwk.neighbors[i].transmitFailures, 0, "and the next hop is not charged with it");
        }
    }
}

void caseRelayNeverOnTheWireBlamesNoNeighbour(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    uint32_t airCount = 0;
    uint32_t i;

    relayEndsEveryAttemptWith(&dev, ZB_ERR_NO_SPACE, air, &airCount);

    Test_ExpectCount(dev.nwk.forwardsGivenUp, 1, "counted as given up, as a refusal at the door is");

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (dev.nwk.neighbors[i].inUse && dev.nwk.neighbors[i].networkAddress == BROKEN_HOP)
            Test_ExpectCount(dev.nwk.neighbors[i].transmitFailures, 0, "and the next hop is not charged with it");
    }
}

/*
 * 3.6.6: a passive acknowledgement is "every Zigbee router and Zigbee coordinator keeps track of which of its
 * neighboring devices have successfully relayed the broadcast transmission", and a device that supports it stops
 * retransmitting once its neighbours have. A copy of the same broadcast arriving from a device that is not the
 * broadcast's own source is that evidence (a neighbour relayed it) and the record's schedule ends there.
 */
void casePassiveAckWithdrawsTheRetransmission(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_BroadcastTransactionRecord *record;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint32_t silence = 0;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);
    seedNeighbor(&dev.nwk, OTHER_RELAY, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, BROADCAST_SOURCE, REPORT_RADIUS, BROADCAST_SEQ,
                       NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, BROADCAST_SOURCE);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW), ZB_OK,
                      "a neighbour's broadcast, received straight from the device that originated it");
    harvestAir(&dev.model, air, &airCount);

    record = bttFor(&dev.nwk, BROADCAST_SOURCE, BROADCAST_SEQ);

    Test_Expect(record != 0 && record->relayed == 1, "3.6.6: the record is made and its first retransmission is on receipt");
    Test_Expect(record != 0 && record->relayedByNeighbor == 0,
                "and no passive acknowledgement yet: the frame came from its own source, which is nobody's relay");
    Test_ExpectCount(airCount, 1, "one frame on the air, this device's own retransmission of it");
    Test_ExpectCount(Nwk_PassiveAckStops(&dev.nwk), 0, "so the schedule stands");

    /* The same broadcast heard again, relayed by a device next door: the same key, another MAC source */
    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, BROADCAST_SOURCE, REPORT_RADIUS - 1, BROADCAST_SEQ,
                       NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, OTHER_RELAY);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + 1), ZB_OK, "and a copy of the same broadcast, relayed by another neighbour");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(record != 0 && record->relayedByNeighbor == 1,
                "3.6.6's MAY: the record is marked with the neighbouring device that relayed the frame");
    Test_ExpectCount(Nwk_DroppedDuplicate(&dev.nwk), 1, "\"It SHALL then drop the frame\"");
    Test_ExpectCount(airCount, 1, "and nothing is put on the air for the duplicate");

    silence = airCount;

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + 1 + NWK_PASSIVE_ACK_TIMEOUT_MS), ZB_OK,
                      "the turn the retransmission would have been due");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_PassiveAckStops(&dev.nwk), 1,
                     "3.6.6: a neighbour that relayed the frame inside nwkPassiveAckTimeout ends the retransmissions");
    Test_ExpectCount(airCount, silence, "so the window passes in silence");
    Test_ExpectCount(Nwk_RelaysSent(&dev.nwk), 1, "one retransmission in all: the one that went out on receipt");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + 1 + 3 * NWK_PASSIVE_ACK_TIMEOUT_MS), ZB_OK, "and later still");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, silence, "nothing: the retransmissions the clause bounds this device with are withdrawn");
    Test_ExpectCount(Nwk_PassiveAckStops(&dev.nwk), 1, "counted once, not once per turn the record is looked at");
}

/*
 * Table 3-78's DISCOVERY_FAILED, which nothing used to write. 3.6.4.5.1.7 deletes a routing entry that is still
 * DISCOVERY_UNDERWAY when the timer fires, and only when "there are no other entries in the route discovery table
 * created as a result of a route discovery for that destination address", so an attempt whose timer ends while
 * another one for that destination is still live is recorded in the status the table prints for it.
 */
void caseDiscoveryFailureIsRecordedWhileAnotherAttemptLives(void)
{
    Test_BandA dev;
    Nwk_RouteDiscoveryTableEntry *other;
    Nwk_RoutingTableEntry *route;
    Nwk_DataRequestParameters req;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;

    rig(&dev, OWN_SHORT, PAN_ID);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);
    seedNeighbor(&dev.nwk, AGED_HOP, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    /* 3.6.1.7's refresh is keyed on the frame's NWK source, so a relayed request teaches this table nothing about
       the device that carried it: the link a relay forwards over is measured some other way */
    neighborAt(&dev.nwk, AGED_HOP)->outgoingCost = NWK_COST_BEST;

    req = nldeReq(FAR_DEST, nsdu, NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, NOW), ZB_OK, "a request for a destination no table knows");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW), ZB_OK, "and the first broadcast of its discovery");

    route = Nwk_RouteOf(dev.nwk.routes, FAR_DEST);

    Test_Expect(route != 0 && route->status == NWK_ROUTE_DISCOVERY_UNDERWAY,
                "the routing entry a discovery establishes carries DISCOVERY_UNDERWAY");

    /* The second attempt for the same destination, and not this device's: a neighbour's request naming it */
    npduLen = composeRequest(npdu, BROADCAST_SOURCE, 0);
    injectNpdu(&dev, npdu, npduLen, AGED_HOP);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + LATER), ZB_OK, "another device's route request for the same destination arrives");

    other = Nwk_DiscoveryOf(dev.nwk.discoveries, BROADCAST_SOURCE, ROUTE_REQUEST_ID);

    Test_Expect(other != 0 && other->destAddr == FAR_DEST, "Table 3-79 holds an entry for it, under its own key");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + NWK_ROUTE_DISCOVERY_TIME_MS + 1), ZB_OK,
                      "and this device's own timer runs out at nwkcRouteDiscoveryTime first");

    Test_ExpectCount(route ? route->status : 0xff, NWK_ROUTE_DISCOVERY_FAILED,
                     "Table 3-78's 0x2: the discovery for that destination failed while another one for it was still live, so 3.6.4.5.1.7's deletion did not apply");
    Test_ExpectCount(Nwk_RouteCount(dev.nwk.routes), 2,
                     "and the entry is still held, not deleted: the reverse route the request made beside it");
    Test_Expect(route != 0 && route->status == NWK_ROUTE_DISCOVERY_FAILED,
                "and it is not ACTIVE, so 3.6.4.3 forwards nothing over it until a discovery repairs it");

    /* The last attempt for that destination expires, and the deletion 3.6.4.5.1.7 prints is the one that takes it */
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + LATER + NWK_ROUTE_DISCOVERY_TIME_MS + 2), ZB_OK,
                      "and the other attempt's timer runs out afterwards");

    Test_Expect(Nwk_RouteOf(dev.nwk.routes, FAR_DEST) == 0,
                "3.6.4.5.1.7: with no discovery entry left for that destination, the routing entry is deleted");
    Test_ExpectCount(Nwk_RouteCount(dev.nwk.routes), 1, "and only the reverse route towards the neighbour is left");
}

/*
 * 3.6.1.10.1 and 3.6.1.10.2 over Table 3-68's map: the null IEEE address is no information, a matching row is
 * consistency, a null row is filled, a different non-null row at either address is a conflict, and a new row is added
 * only when there is no conflict, no row at either address, and room in the pool.
 */
void caseAddressMapLearns(void)
{
    Nwk_AddressMapEntry map[NWK_ADDR_MAP_MAX];
    uint16_t shortAddress = 0;
    uint64_t extended = 0;
    uint32_t i;

    Zb_memset(map, 0, (uint32_t)sizeof map);

    Test_Expect(Nwk_AddrMapLearn(map, 0x1234, 0, OWN_SHORT, 10) == NWK_ADDRMAP_IGNORED,
                "the null IEEE address is no information and adds no row");
    Test_Expect(Nwk_AddrMapLearn(map, NWK_ADDR_ALL_DEVICES, 0x00212effff05a888, OWN_SHORT, 10) == NWK_ADDRMAP_IGNORED,
                "and neither does a class: Table 3-68 bounds the network address at 0xfff7");

    Test_Expect(Nwk_AddrMapLearn(map, 0x1234, 0x00212effff05a888, OWN_SHORT, 10) == NWK_ADDRMAP_LEARNED,
                "a short and a long address together are a row");
    Test_ExpectCount(Nwk_AddrMapCount(map), 1, "the first row");

    Test_Expect(Nwk_AddrMapLearn(map, 0x1234, 0x00212effff05a888, OWN_SHORT, 20) == NWK_ADDRMAP_IGNORED,
                "and the same pair again is consistency, not a second row");
    Test_ExpectCount(Nwk_AddrMapCount(map), 1, "with the pool unchanged");

    Test_Expect(Nwk_AddrMapLearn(map, 0x1234, 0x00212effff060000, OWN_SHORT, 30) == NWK_ADDRMAP_CONFLICT_OTHER,
                "while a second IEEE address at the same short address is 3.6.1.10.2's conflict on somebody else's address");

    Test_Expect(Nwk_AddrMapLearn(map, 0x2222, 0x00212effff05a888, OWN_SHORT, 40) == NWK_ADDRMAP_UPDATED,
                "and one IEEE address at a second short address updates the row, which is what a device that changed its address leaves behind");
    Test_Expect(Nwk_AddrMapShortOf(map, 0x00212effff05a888, &shortAddress) == 1 && shortAddress == 0x2222,
                "so the map's own lookup answers the new address");

    Zb_memset(map, 0, (uint32_t)sizeof map);
    map[0].inUse = 1;
    map[0].networkAddress = 0x1234;

    Test_Expect(Nwk_AddrMapLearn(map, 0x1234, 0x00212effff05a888, OWN_SHORT, 50) == NWK_ADDRMAP_UPDATED,
                "a row whose 64-bit address is null can be filled, which the clause allows outright");
    Test_Expect(Nwk_AddrMapExtendedOf(map, 0x1234, &extended) == 1 && extended == 0x00212effff05a888,
                "and its reverse lookup answers");

    for (i = 0; i < 2; i++)
    {
        Zb_memset(map, 0, (uint32_t)sizeof map);
        map[i].inUse = 1;
        map[i].networkAddress = 0x1234;
        map[1 - i].inUse = 1;
        map[1 - i].networkAddress = 0x2222;
        map[1 - i].extendedAddress = 0x00212effff05a888;

        Test_Expect(Nwk_AddrMapLearn(map, 0x1234, 0x00212effff05a888, OWN_SHORT, 55) == NWK_ADDRMAP_UPDATED,
                    "an IEEE address held at one short address, announced at another whose row holds no IEEE address");
        Test_ExpectCount(Nwk_AddrMapCount(map), 1, "is one device: the two rows become one, whichever the pool holds first");
        Test_Expect(Nwk_AddrMapShortOf(map, 0x00212effff05a888, &shortAddress) == 1 && shortAddress == 0x1234
                    && Nwk_AddrMapExtendedOf(map, 0x1234, &extended) == 1 && extended == 0x00212effff05a888,
                    "the row that names the device, at the announced address");
    }

    Zb_memset(map, 0, (uint32_t)sizeof map);
    Test_ExpectStatus(Nwk_AddrMapSeedOwn(map, OWN_SHORT, 0x00212effff048a12, 60), ZB_OK,
                  "this device's own row is what makes its own address decidable");
    Test_Expect(Nwk_AddrMapLearn(map, OWN_SHORT, 0x00212effff060000, OWN_SHORT, 70) == NWK_ADDRMAP_CONFLICT_LOCAL,
                "so a frame carrying this device's short address and another IEEE address is a local conflict");

    Zb_memset(map, 0, (uint32_t)sizeof map);

    for (i = 0; i < NWK_ADDR_MAP_MAX; i++)
        Test_Expect(Nwk_AddrMapLearn(map, (uint16_t)(0x0100 + i), 0x00212efff0000000 + i, OWN_SHORT, 80) == NWK_ADDRMAP_LEARNED,
                    "a full pool is filled one row at a time");

    Test_Expect(Nwk_AddrMapLearn(map, 0x3333, 0x00212efff1000000, OWN_SHORT, 90) == NWK_ADDRMAP_FULL,
                "and the row behind them is refused by the pool, which is the clause's third condition");
    Test_ExpectCount(Nwk_AddrMapCount(map), NWK_ADDR_MAP_MAX, "with nothing evicted to make room");
}

/*
 * 3.6.4.8.1's second code: a broken route whose entry carries 3.6.4.5.1.3's many-to-one mark is reported with 0x0c,
 * the many-to-one failure, where a plain link failure takes 0x02.
 */
void caseManyToOneFailureHasItsOwnCode(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_RoutingTableEntry *through;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    rig(&dev, OWN_SHORT, PAN_ID);

    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 0);
    seedNeighbor(&dev.nwk, RELAY_SOURCE, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    through = seedRoute(dev.nwk.routes, 0, FAR_DEST, NWK_ROUTE_ACTIVE, BROKEN_HOP);
    through->manyToOne = 1;

    npduLen = makeNpdu(npdu, FAR_DEST, RELAY_SOURCE, REPORT_RADIUS, 0x52, NWK_FRAME_TYPE_DATA, 0, nsdu, NSDU_LEN);
    injectNpdu(&dev, npdu, npduLen, RELAY_SOURCE);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW), ZB_OK, "a unicast this device is not the end of");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "is forwarded once");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, NOW + 1), ZB_OK, "and the turn the MAC answers NO_ACK on");
    harvestAir(&dev.model, air, &airCount);

    (void)relayExhausted(&dev, air, &airCount, NOW + 1);

    Test_ExpectCount(Nwk_LinkFailuresReported(&dev.nwk), 1, "the failure is reported");
    Test_ExpectCount(airCount, 2 + NWK_UNICAST_RETRIES, "with one status frame behind the failed attempts");

    if (airCount < 2 + NWK_UNICAST_RETRIES)
        return;

    Test_Expect(npduOf(&air[1 + NWK_UNICAST_RETRIES])[NWK_MIN_HEADER_OVERHEAD + NWK_IEEE_ADDR_OCTETS + 1] == NWK_STATUS_CODE_MANY_TO_ONE_FAILURE,
           "and its payload's status octet is Table 3-56's 0x0c, the many-to-one failure, because the route the frame was relayed over carries 3.6.4.5.1.3's mark");
    Test_ExpectCount(through->status, NWK_ROUTE_INACTIVE, "while the entry that used the broken link is invalidated all the same");
}

/* The map's changes as the higher layer is told them: a device announced, the same pair again, the device at a new
   address, and a second device claiming that address. */
void caseAddressMapChangesAreTold(void)
{
    Test_BandA dev;
    Nwk_AddressNotice notices[4];
    uint16_t holder = 0;
    uint32_t taken;

    rig(&dev, OWN_SHORT, PAN_ID);

    Nwk_AddressAnnounced(&dev.nwk, 0x1111, 0x00212effff05a888, 10);
    taken = Nwk_PollAddressNotices(&dev.nwk, notices, 4);
    Test_Expect(taken == 1 && notices[0].networkAddress == 0x1111 && notices[0].extendedAddress == 0x00212effff05a888
                && notices[0].reason == NWK_ADDRESS_NOTICE_LEARNED, "a device's first announcement is a new pair");

    Nwk_AddressAnnounced(&dev.nwk, 0x1111, 0x00212effff05a888, 20);
    Test_ExpectCount(Nwk_PollAddressNotices(&dev.nwk, notices, 4), 0, "the same pair again is nothing to tell");

    Nwk_AddressAnnounced(&dev.nwk, 0x2222, 0x00212effff05a888, 30);
    taken = Nwk_PollAddressNotices(&dev.nwk, notices, 4);
    Test_Expect(taken == 1 && notices[0].networkAddress == 0x2222 && notices[0].reason == NWK_ADDRESS_NOTICE_CHANGED,
                "the device at another address is a change");

    Nwk_AddressAnnounced(&dev.nwk, 0x2222, 0x00212effff060000, 40);
    taken = Nwk_PollAddressNotices(&dev.nwk, notices, 4);
    Test_Expect(taken == 1 && notices[0].networkAddress == 0x2222 && notices[0].extendedAddress == 0x00212effff060000
                && notices[0].reason == NWK_ADDRESS_NOTICE_CONFLICT,
                "and a second device announcing that address is a conflict, told with the claimant");
    Test_Expect(Nwk_AddressOfIeee(&dev.nwk, 0x00212effff05a888, &holder) == 1 && holder == 0x2222,
                "while the map keeps the first holder");
    Test_ExpectCount(Nwk_AddressNoticesDropped(&dev.nwk), 0, "with nothing the ring lost");
}
