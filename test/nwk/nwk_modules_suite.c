/* Suite for the topic modules band A's network layer directory holds: `nwk_tx`, `nwk_rx`, `nwk_relay`,
   `nwk_command`, `nwk_cost` and the neighbor and route tables the receive stages and the next-hop lookup
   write (docs/internals/coding-rules.md §4.5). Direct calls to each
   module's public operations through its own header:
   no `Nwk_Nwk`, no `Mac_Mac`, no backend, no radio and no clock of its own anywhere in the file, the one MAC
   thing in it is the `Mac_Frame` header 3.6.2.3 reads, handed in as a plain struct. Every pool is
   a plain array the suite owns, exactly as the façade embeds one array of each type as a named member, and
   every call hands that array in. The one fixture that is not a plain array is a `Security`, seeded the way
   `test/security/cases_nwk.c` seeds one, because `Nwk_TxProtect` and the three shapes `Nwk_TxSecurityRuns` answers are
   crossings into that module and cannot be reached without it.

   What is asserted is what each body actually answers, not what the pipeline that calls it does with the
   answer: the Table 3-84 code a refused protection has, which slot of the transmit pool is on offer and what
   "held" means, whether this device runs NWK security at all, the octet growth and the counter step of one
   protection, the band Table 3-54 prints, what a forwarded copy carries and what it refuses, the shape of one
   jitter draw and the bound on it, and the three rules the receive stages write into a neighbor entry. The
   counters, the order and the confirmation a pipeline attaches to each of those answers are asserted in the
   `nwk` suite, which drives the façade over a backend; nothing here is a second copy of that.

   Six rules here are pinned by mutation rather than by more cases, and all six are named at the bottom of the
   file beside the change each one stands for. */

#include "log.h"
#include "mac.h"
#include "nwk_status.h"
#include "nwk.h"          /* only for `Nwk_Config`, which `Nwk_RelayJitterMs` names as a parameter and does not
                             own: the seed is the application's. No `Nwk_Nwk` is built here. */
#include "nwk_command.h"
#include "nwk_cost.h"
#include "nwk_frame.h"
#include "nwk_neighbor.h"
#include "nwk_relay.h"
#include "nwk_route.h"
#include "nwk_rx.h"
#include "nwk_addr.h"
#include "nwk_tx.h"
#include "security.h"
#include "test_harness.h"
#include "zb_utils.h"

/* This device's extended address and its neighbour's, the two the security fixture and the auxiliary
   sender of 4.3.1.2 step 8 are built from. The IEEE is the one `test/security/cases_nwk.c` pins its vectors with, so
   the protected frame this suite compares against is the same frame. */
#define OWN_IEEE 0x0123456789abcdef
#define HOP_IEEE 0x0000000000000011
#define OTHER_IEEE 0x2222222222222222

#define ADDR_A 0x0042
#define ADDR_B 0x0100
#define ADDR_C 0x0200
#define ADDR_ORIGIN 0x0001          /* the NWK destination of the protected vector */
#define CHILD_ADDR 0x1234           /* the NWK source 3.6.2.3 step 1 searches for */
#define CARRIER_ADDR 0x9999         /* the MAC source that carried the child's message */
#define COORDINATOR 0x0000          /* the coordinator's NWK address, which 3.6.1.7 observes like any other */
#define SEQ 5                       /* the sequence number of the protected vector */
#define RADIUS 30                   /* NWK_INITIAL_RADIUS: the radius the vector carries */
#define RADIUS_READ 7               /* a radius a frame this device read still holds */
#define LQA_MEASURED 200            /* the LQI a carrier hands up: Table 3-76's level 1, the best link printed */
#define LQA_FLOOR 0                 /* Table 3-75's LQA (LQI) at its floor, which is still a measurement */
#define NOW_MS 100000
#define LATER_MS 101000

/* The seed `test/nwk/` case 6a pins its schedule with, so the two suites name the same draws. */
#define JITTER_SEED 0x2b3afb57

/* The network key of `test/security/cases_nwk.c`'s s1 vector, and that vector's header, payload and frame: the frame
   this suite hands `Nwk_TxProtect` is s1's, so the octets that come back are s1's octets and the split
   the split is what is being asserted. */
static const char *s_keyAHex = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
static const char *s_payloadHex = "40414243444546";
static const char *s_frame1Hex = "0802010000001e052805000000efcdab896745230100621e81731bba4c15db7c75";

/* The pools, as the suite owns them: plain arrays, zero-filled before each case, exactly the shape
   `Nwk_Nwk` embeds. */
static Nwk_Tx s_tx[NWK_TX_MAX];
static Nwk_NeighborTableEntry s_neighbors[NWK_NEIGHBOR_MAX];
static Nwk_RoutingTableEntry s_routes[NWK_ROUTE_MAX];

/* --- the security fixture, seeded as `test/security/cases_nwk.c` seeds one ---------------- */

static Security_KeyDescriptor keyAt(uint8_t keySeqNumber, const char *keyHex, uint32_t outgoing)
{
    Security_KeyDescriptor descriptor;

    Zb_memset(&descriptor, 0, (uint32_t)sizeof descriptor);
    descriptor.keySeqNumber = keySeqNumber;
    descriptor.inUse = 1;
    descriptor.outgoingFrameCounter = outgoing;
    Test_ParseHex(keyHex, descriptor.key, SECURITY_KEY_OCTETS);

    return descriptor;
}

typedef struct Fixture
{
    Log_Log log;
    Security security;
} Fixture;

static void fixtureAt(Fixture *fixture, uint32_t level, const Security_KeyDescriptor *keys,
                      uint32_t keyCount)
{
    Security_Config cfg;

    Zb_memset(fixture, 0, (uint32_t)sizeof *fixture);
    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);

    Log_Init(&fixture->log);

    cfg.ownIeee = OWN_IEEE;
    cfg.nwkSecurityLevel = (uint8_t)level;
    cfg.nwkActiveKeySeqNumber = 0x00;
    cfg.authenticated = 1;
    cfg.nwkAllFresh = 1;
    cfg.keys = keys;
    cfg.keyCount = keyCount;
    cfg.log = &fixture->log;

    Test_ExpectStatus(Security_Init(&fixture->security, &cfg), ZB_OK, "the fixture's security module initialised");
}

/* The NIB default level (Table 4-2's nwkSecurityLevel 0x05) with one descriptor under the active key
   sequence number, the counters seeded where the case wants them, and the level-0 scaffold this stack
   keeps. */
static void fixture5(Fixture *fixture, uint32_t outgoing)
{
    Security_KeyDescriptor keys[1];

    keys[0] = keyAt(0x00, s_keyAHex, outgoing);
    fixtureAt(fixture, SECURITY_LEVEL_ENC_MIC_32, keys, 1);
}

static void fixtureLevel0(Fixture *fixture)
{
    fixtureAt(fixture, SECURITY_LEVEL_NONE, 0, 0);
}

/* --- the frame the receive stages are given, and the entries a suite seeds --------------------- */

static Nwk_Frame frameAt(int frameType, uint16_t src, uint16_t dst, uint8_t radius, uint8_t seq,
                         uint64_t srcIeee, int srcIeeePresent)
{
    Nwk_Frame frame;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = frameType;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.discoverRoute = NWK_DISCOVER_SUPPRESS;
    frame.destAddr = dst;
    frame.srcAddr = src;
    frame.radius = radius;
    frame.sequenceNumber = seq;
    frame.srcIeee = srcIeee;
    frame.srcIeeePresent = srcIeeePresent;

    return frame;
}

static Nwk_NeighborTableEntry *seedNeighbor(uint32_t slot, uint16_t addr, uint64_t ieee, int ieeeKnown,
                                  uint32_t deviceType, int rxOnWhenIdle, uint32_t relationship)
{
    s_neighbors[slot].inUse = 1;
    s_neighbors[slot].networkAddress = addr;
    s_neighbors[slot].extendedAddress = ieee;
    s_neighbors[slot].ieeeKnown = ieeeKnown;
    s_neighbors[slot].deviceType = deviceType;
    s_neighbors[slot].rxOnWhenIdle = rxOnWhenIdle;
    s_neighbors[slot].relationship = relationship;
    s_neighbors[slot].ageFromMs = NOW_MS;

    return &s_neighbors[slot];
}

/* One carrier as `mac` hands it up, read for the two things 3.6.2.3 reads off it: the addressing mode of
   its source and the short address that mode carries. */
static Mac_DataIndicationParameters carrierAt(uint32_t srcAddrMode, uint16_t srcShort)
{
    Mac_DataIndicationParameters ind;

    Zb_memset(&ind, 0, (uint32_t)sizeof ind);
    ind.headerValid = 1;
    ind.frameType = MAC_FRAME_TYPE_DATA;
    ind.header.frameType = MAC_FRAME_TYPE_DATA;
    ind.header.srcAddrMode = (Mac_AddrMode)srcAddrMode;
    ind.header.srcShort = srcShort;

    return ind;
}

/* One routing entry, seeded the way only a suite can seed it: a status, a next hop and a usage count no
   body in this tree assigns yet (Table 3-77). */
static Nwk_RoutingTableEntry *seedRoute(uint32_t slot, uint16_t dest, uint32_t status, uint16_t nextHop,
                            uint32_t ageMs, uint32_t totalUsageCount)
{
    s_routes[slot].inUse = 1;
    s_routes[slot].destinationAddress = dest;
    s_routes[slot].status = status;
    s_routes[slot].nextHopAddress = nextHop;
    s_routes[slot].ageMs = ageMs;
    s_routes[slot].totalUsageCount = totalUsageCount;

    return &s_routes[slot];
}

/* --- 3.6.4.4.4's ageing, 3.6.4.8's failure count and 3.6.4.8.1's invalidation ------------------- */

/*
 * Table 3-75's Age in the unit the table prints: nwkLinkStatusPeriod intervals since the entry was refreshed, with
 * 0xa6 at 0x0f seconds and 0xa7's limit of 3. Past the limit the outgoing cost becomes 0 ("no measurement", which
 * 3.6.4.5.1.2 discards on) and an end device's entry is never stale ("they SHOULD never be considered stale").
 */
static void caseNeighborAgeCountsLinkStatusPeriods(void)
{
    Nwk_NeighborTableEntry *router;
    Nwk_NeighborTableEntry *child;
    uint32_t retired;
    uint32_t i;

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    router = seedNeighbor(0, ADDR_A, 0, 0, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    child = seedNeighbor(1, ADDR_B, 0, 0, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);

    router->outgoingCost = 3;
    child->outgoingCost = 6;

    retired = Nwk_NeighborAge(s_neighbors, NOW_MS + NWK_LINK_STATUS_PERIOD_MS - 1);

    Test_Expect(retired == 0 && router->age == 0,
           "one millisecond short of nwkLinkStatusPeriod 0xa6's 0x0f seconds is no interval: the age is 0 and no cost was retired");

    retired = Nwk_NeighborAge(s_neighbors, NOW_MS + NWK_LINK_STATUS_PERIOD_MS);

    Test_Expect(retired == 0 && router->age == 1,
           "the interval itself is one tick, and one tick is inside nwkRouterAgeLimit 0xa7's 3");

    Test_Expect(Nwk_NeighborAge(s_neighbors, NOW_MS + 3 * NWK_LINK_STATUS_PERIOD_MS) == 0 && router->age == 3,
           "three ticks are the limit itself ('If the value exceeds nwkRouterAgeLimit') so the cost stands");

    retired = Nwk_NeighborAge(s_neighbors, NOW_MS + 4 * NWK_LINK_STATUS_PERIOD_MS);

    Test_Expect(retired == 1 && router->age == 4,
           "the fourth tick exceeds the limit and retires the router's outgoing cost: one entry, counted once");
    Test_ExpectCount(router->outgoingCost, 0,
           "and 0 is Table 3-75's 'no outgoing cost available', which 3.6.4.5.1.2 terminates route request processing on");
    Test_ExpectCount(child->outgoingCost, 6,
           "while the end device child keeps its cost: 3.6.4.4.4 ages routers, and end devices issue no link status frames");

    Test_Expect(Nwk_NeighborAge(s_neighbors, NOW_MS + 5 * NWK_LINK_STATUS_PERIOD_MS) == 0,
           "a cost already retired is not counted a second time: the sweep answers transitions");

    /* 3.6.4.4.4's other half: "the neighbor entry is considered stale and MAY be reused if necessary to make room for
       a new neighbor", which is the slot a full table hands out */
    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    for (i = 0; i < NWK_NEIGHBOR_MAX - 1; i++)
        (void)seedNeighbor(i, (uint16_t)(ADDR_A + i), 0, 0, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    child = seedNeighbor(NWK_NEIGHBOR_MAX - 1, ADDR_C, 0, 0, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);

    (void)Nwk_NeighborAge(s_neighbors, NOW_MS + 4 * NWK_LINK_STATUS_PERIOD_MS);

    Test_Expect(Nwk_NeighborFree(s_neighbors) == &s_neighbors[0],
           "a full table whose routers have all aged out offers the oldest of them first");
    Test_Expect(s_neighbors[0].inUse == 0 && s_neighbors[0].age == 0,
           "handed over cleared, so the new neighbour inherits neither the slot nor its age");
    Test_ExpectCount(Nwk_NeighborCount(s_neighbors), NWK_NEIGHBOR_MAX - 1, "and the pool is a slot emptier than it was");

    /* The exclusion the same paragraph prints: routers age out, end devices do not */
    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    for (i = 0; i < NWK_NEIGHBOR_MAX - 1; i++)
        (void)seedNeighbor(i, (uint16_t)(ADDR_A + i), 0, 0, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    child = seedNeighbor(NWK_NEIGHBOR_MAX - 1, ADDR_C, 0, 0, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    child->ageFromMs = NOW_MS - 5 * NWK_LINK_STATUS_PERIOD_MS;

    (void)Nwk_NeighborAge(s_neighbors, NOW_MS);

    Test_Expect(child->age > NWK_ROUTER_AGE_LIMIT && Nwk_NeighborFree(s_neighbors) == 0,
           "a silent end device is never stale, so a full table of fresh routers offers nothing: its entry outlives its radio");
}

/*
 * Table 3-75's Transmit Failure and 3.6.4.8's failure counter for a neighbour with an outgoing link: one per failed
 * transmit, saturating at the octet the table prints, cleared by a transmit that succeeded.
 */
static void caseNeighborTransmitFailureSaturatesAndClears(void)
{
    Nwk_NeighborTableEntry *router;
    uint32_t i;

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    router = seedNeighbor(0, ADDR_A, 0, 0, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    Test_ExpectCount(Nwk_NeighborTxFailure(s_neighbors, ADDR_A), 1, "a failed transmit to the neighbour counts 1");
    Test_ExpectCount(Nwk_NeighborTxFailure(s_neighbors, ADDR_A), 2, "and the next one 2: 'higher values indicate more failures'");

    for (i = 0; i < 300; i++)
        (void)Nwk_NeighborTxFailure(s_neighbors, ADDR_A);

    Test_ExpectCount(router->transmitFailures, NWK_TRANSMIT_FAILURE_MAX,
           "the count saturates at Table 3-75's 0xff rather than wrapping to zero, which would report a dead link as a fresh one");

    Nwk_NeighborTxSuccess(s_neighbors, ADDR_A);

    Test_ExpectCount(router->transmitFailures, 0, "and a transmit that succeeded clears it: the simple counting scheme 3.6.4.8 permits");

    Test_ExpectCount(Nwk_NeighborTxFailure(s_neighbors, ADDR_C), 0,
           "a neighbour the table holds no entry for has no counter to move: the clause counts neighbours with an outgoing link");
}

/*
 * 3.6.4.8.1's invalidation: "It SHALL further invalidate all routing table entries that used the broken link as their
 * next hop", Table 3-78's INACTIVE, which is what stops 3.6.4.3 choosing that hop again.
 */
static void caseRouteInvalidateMovesEveryEntryThroughTheBrokenLink(void)
{
    Nwk_RoutingTableEntry *through;
    Nwk_RoutingTableEntry *other;
    uint16_t nextHop = 0;

    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);
    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    through = seedRoute(0, ADDR_A, NWK_ROUTE_ACTIVE, ADDR_B, NOW_MS, 4);
    other = seedRoute(1, ADDR_C, NWK_ROUTE_ACTIVE, ADDR_C, NOW_MS, 4);

    Test_ExpectCount(Nwk_RouteInvalidate(s_routes, ADDR_B), 1, "one entry used that hop, and it is invalidated");
    Test_ExpectCount(through->status, NWK_ROUTE_INACTIVE, "Table 3-78's 0x3");
    Test_ExpectCount(other->status, NWK_ROUTE_ACTIVE, "and a route through another hop keeps its status");
    Test_ExpectCount(through->nextHopAddress, ADDR_B, "the entry keeps the hop it was learned over: only the status that decides forwarding moves");
    Test_ExpectCount(Nwk_RouteInvalidate(s_routes, ADDR_B), 0, "a second walk over the same broken link moves nothing further");

    Test_Expect(Nwk_RouteNextHop(s_routes, s_neighbors, ADDR_A, NOW_MS + 1, &nextHop) == 0,
           "3.6.4.3 takes an ACTIVE entry only, so the invalidated route forwards nothing");
    Test_ExpectCount(Nwk_RouteCount(s_routes), 2, "and the entry is held, not deleted: 3.6.4.5.3's repair has to find it");
}

/*
 * 3.6.4.5.3's step 2 as its definition prints it: "LoopFree(R1, R2) := path-cost(R1) <= path-cost(R2)", asked of the
 * advertised route and the local one. The boundary is the whole of the rule (a dearer advertisement is refused and
 * an equal one is not) and a local cost of 0 is the caller's "nothing recorded", not a cost.
 */
static void caseCostLoopFreeIsThePrintedComparison(void)
{
    Test_Expect(Nwk_CostLoopFree(3, 3) == 1, "an advertised cost equal to the local one is loop free: the definition is <=");
    Test_Expect(Nwk_CostLoopFree(2, 3) == 1, "a cheaper advertisement is loop free, and is what step 3 updates on");
    Test_Expect(Nwk_CostLoopFree(4, 3) == 0,
           "a dearer advertisement is not: 9300-9301 says it 'SHALL be ignored and SHALL NOT be used to update the routing table'");
    Test_Expect(Nwk_CostLoopFree(0, 0) == 1, "and two costs of nothing compare as the definition says: what 0 is worth is the caller's reading");
}

/* --- nwk_tx: the Table 3-84 crossing ----------------------------------------------------------- */

/*
 * The mapping: the one place the seam's words for a failed outgoing protection become the codes Table
 * 3-84 prints on an NLDE-DATA.confirm. The whole table as landed, over every status the seam can answer
 * with: the three security codes named by name, and everything else reported as the sentinel that says
 * the NWK layer has no code of its own for it.
 *
 * The two cases the table prints no code for are asserted as un-coded rather than dressed up.
 * A secured frame that will not fit the band's 127-octet ceiling (4.3.1.1 step 6) arrives
 * as ZB_ERR_NO_SPACE, and 0xd3 FRAME_NOT_BUFFERED is "insufficient buffering available" (a
 * pool's answer, not a length's), so it is not used here. A route this stack has no path
 * over is ZB_ERR_NO_ROUTE, and Table 3-84's ROUTE_ERROR 0xd1 is applied by the pipeline that
 * refused the route, not by this mapping, because a protection never named that outcome.
 */
static void caseTxConfirmStatusIsTable384sMapping(void)
{
    Test_Expect(NWK_STATUS_MAX_FRM_COUNTER == 0xcc && NWK_STATUS_NO_KEY == 0xcd
           && NWK_STATUS_BAD_CCM_OUTPUT == 0xce,
           "the three codes are the octets Table 3-84 prints");

    Test_Expect(Nwk_TxConfirmStatus(ZB_ERR_BAD_FRAME_COUNTER) == NWK_STATUS_MAX_FRM_COUNTER,
           "4.3.1.1 step 1's exhausted outgoing counter is MAX_FRM_COUNTER 0xcc");

    Test_Expect(Nwk_TxConfirmStatus(ZB_ERR_AUTH) == NWK_STATUS_NO_KEY,
           "4.3.1.1 step 1's 'if the key cannot be obtained' is NO_KEY 0xcd");

    Test_Expect(Nwk_TxConfirmStatus(ZB_ERR_INTERNAL) == NWK_STATUS_BAD_CCM_OUTPUT,
           "4.3.1.1 step 4's output of 'invalid' is BAD_CCM_OUTPUT 0xce");

    Test_Expect(Nwk_TxConfirmStatus(ZB_ERR_BAD_ARGUMENT) == NWK_STATUS_BAD_CCM_OUTPUT,
           "and a seam call that could not be made at all is the same erroneous output");

    Test_Expect(Nwk_TxConfirmStatus(ZB_ERR_NO_SPACE) == NWK_STATUS_LAST_MAC_STATUS,
           "a secured frame too long for the band's own ceiling has no NWK code: 0xd3 is a pool's answer, not a length's");

    Test_Expect(Nwk_TxConfirmStatus(ZB_ERR_UNSUPPORTED) == NWK_STATUS_LAST_MAC_STATUS,
           "a level-0 refusal never reaches this mapping (`Nwk_TxSecurityRuns` answers it before an attempt is made) and is reported as itself if it ever did");

    Test_Expect(Nwk_TxConfirmStatus(ZB_ERR_NO_ROUTE) == NWK_STATUS_LAST_MAC_STATUS,
           "ROUTE_ERROR 0xd1 is applied by the call site that refused the route, not by the mapping of a security refusal");

    Test_Expect(Nwk_TxConfirmStatus(ZB_OK) == NWK_STATUS_LAST_MAC_STATUS
           && Nwk_TxConfirmStatus(ZB_ERR_NOT_OPEN) == NWK_STATUS_LAST_MAC_STATUS
           && Nwk_TxConfirmStatus(ZB_ERR_DEVICE_LOST) == NWK_STATUS_LAST_MAC_STATUS
           && Nwk_TxConfirmStatus(ZB_ERR_DEVICE) == NWK_STATUS_LAST_MAC_STATUS
           && Nwk_TxConfirmStatus(ZB_ERR_TIMEOUT) == NWK_STATUS_LAST_MAC_STATUS,
           "every other status the seam can answer with is carried unchanged beside the sentinel that says the NWK layer names no code of its own (3.2.1.1.3 hands that last word to the MAC)");

    Test_Expect(NWK_STATUS_LAST_MAC_STATUS > NWK_STATUS_BAD_CCM_OUTPUT
           && NWK_STATUS_LAST_MAC_STATUS > NWK_STATUS_ROUTE_ERROR,
           "and the sentinel sits above every Table 3-84 code this tree names, so a code is never guessed from it");
}

/* --- nwk_tx: the slot pool --------------------------------------------------------------------- */

static void caseTxFreeHandsTheFirstIdleSlotOfThePool(void)
{
    Zb_memset(s_tx, 0, (uint32_t)sizeof s_tx);

    Test_Expect(Nwk_TxFree(s_tx) == &s_tx[0], "an empty pool offers its first slot");
    Test_Expect(Nwk_TxOccupied(s_tx) == 0, "and holds nothing");

    s_tx[0].state = NWK_TX_OUTSTANDING;

    Test_Expect(Nwk_TxFree(s_tx) == &s_tx[1], "a slot issued to the MAC and not yet answered is taken");

    s_tx[1].state = NWK_TX_AWAITING_RETRY;

    Test_Expect(Nwk_TxFree(s_tx) == &s_tx[2],
           "and a slot waiting for its retry floor is taken too: an unanswered attempt and a due-later attempt are both work this module owes");
    Test_Expect(Nwk_TxOccupied(s_tx) == 2, "the two modes are two held frames");

    s_tx[0].state = NWK_TX_FREE;

    Test_Expect(Nwk_TxFree(s_tx) == &s_tx[0],
           "the slot a confirmation released is the next one on offer: reuse is the pool order, not the release order");
    Test_Expect(Nwk_TxOccupied(s_tx) == 1, "and the pool is one frame deep again");
}

/* The walk is over the whole pool, not up to the first hole, and the count is `state != NWK_TX_FREE` and
   nothing more specific: a caller cannot make a held slot look free by leaving it in a mode it did not set. */
static void caseTxOccupiedCountsEveryHeldSlot(void)
{
    uint32_t i;

    Zb_memset(s_tx, 0, (uint32_t)sizeof s_tx);

    s_tx[0].state = NWK_TX_OUTSTANDING;
    s_tx[4].state = NWK_TX_AWAITING_RETRY;
    s_tx[NWK_TX_MAX - 1].state = NWK_TX_OUTSTANDING;

    Test_Expect(Nwk_TxOccupied(s_tx) == 3, "the count walks the whole pool and not up to the last hole");
    Test_Expect(Nwk_TxFree(s_tx) == &s_tx[1], "and the offer is the first idle slot, between the held ones");

    s_tx[4].state = NWK_TX_FREE;

    Test_Expect(Nwk_TxOccupied(s_tx) == 2, "a slot released is a slot counted free, wherever it sits");

    for (i = 0; i < NWK_TX_MAX; i++)
        s_tx[i].state = NWK_TX_OUTSTANDING;

    Test_Expect(Nwk_TxOccupied(s_tx) == NWK_TX_MAX, "every slot held is the pool at its named bound");
}

/* Full is refusal and nothing else: no slot is taken back out of a frame that is still owed an answer, and
   no mode of a held slot changes when the pool says no. */
static void caseTxFreeRefusesAFullPoolAndReusesAReleasedSlot(void)
{
    uint32_t i;

    Zb_memset(s_tx, 0, (uint32_t)sizeof s_tx);

    for (i = 0; i < NWK_TX_MAX; i++)
        s_tx[i].state = (i % 2 == 0) ? NWK_TX_OUTSTANDING : NWK_TX_AWAITING_RETRY;

    Test_Expect(Nwk_TxFree(s_tx) == 0, "a full pool offers no slot");
    Test_Expect(Nwk_TxOccupied(s_tx) == NWK_TX_MAX, "and the refusal moves nothing");

    for (i = 0; i < NWK_TX_MAX; i++)
    {
        if (s_tx[i].state == NWK_TX_FREE)
            break;
    }

    Test_Expect(i == NWK_TX_MAX, "no held frame was dropped to make room: 3.2.1.1.3 owes each of them its answer");

    s_tx[5].state = NWK_TX_FREE;

    Test_Expect(Nwk_TxFree(s_tx) == &s_tx[5], "the one slot an answer released is the slot on offer");
}

/*
 * The three shapes, seen from the gate a transmit attempt asks before it protects anything:
 * no `Security` attached at all, one attached at nwkSecurityLevel 0x00, and one attached at the NIB default.
 *
 * 3.2.1.1.3 conditions the security processing of a frame going out on a non-zero `nwkSecurityLevel` and on
 * SecurityEnable TRUE, and 4.3.1.2's whole incoming procedure is conditioned on the same thing existing. An
 * attached module answering `Security_IsEnabled` 0 is the level 0x00 of Table 4-2; no attached module is the
 * same device from the other side. Both mean this stack makes no security call in either direction, which is
 * the scaffold it must not disturb.
 */
static void caseTxSecurityRunsIsTheGateBeforeAProtection(void)
{
    Fixture level0;
    Fixture enabled;

    fixtureLevel0(&level0);
    fixture5(&enabled, SEQ);

    Test_Expect(Nwk_TxSecurityRuns(0) == 0, "a device with no Security attached runs no NWK security");
    Test_Expect(Nwk_TxSecurityRuns(&level0.security) == 0,
           "and a device whose nwkSecurityLevel is 0x00 runs none either: Security_IsEnabled answers it");
    Test_Expect(Nwk_TxSecurityRuns(&enabled.security) == 1,
           "an attached module at the NIB default level 0x05 with a descriptor under the active key sequence number is the device that protects every attempt");

    Security_Reset(&enabled.security);

    Test_Expect(Nwk_TxSecurityRuns(&enabled.security) == 0,
           "and a module wiped by Security_Reset is inert at this gate too (the wipe duty)");
}

/*
 * One real protection through the crossing `Nwk_TxProtect` names: the s1 shape of `test/security/cases_nwk.c`,
 * handed over as unsecured octets plus the split, taken back as the framed frame.
 *
 * What is pinned is what this module is responsible for and nothing the seam is responsible for again: the
 * frame grew by the 14-octet auxiliary header and the 4-octet MIC Table 4-38 gives level 0x05; the auxiliary
 * sits between the NWK header and the payload region; the header octets travel into the authenticated string
 * unchanged; the octets the caller holds are the unsecured frame after the call exactly as before it, which
 * is the rule that no frame this stack stores is ever a secured one; the descriptor's outgoing counter
 * advanced by exactly one; and a second call (the retry of the same frame) advanced it again and produced a
 * different frame out of the same stored octets.
 */
static void caseTxProtectGrowsTheFrameAndStepsTheCounterOncePerIssue(void)
{
    Fixture fixture;
    Nwk_Frame frame;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint8_t stored[NWK_FRAME_NPDU_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t scratch[NWK_FRAME_NPDU_MAX];
    Security_KeyState before;
    Security_KeyState after;
    uint32_t payloadLen;
    uint32_t npduLen = 0;
    uint32_t headerLen;
    uint32_t outLen = 0;

    payloadLen = Test_ParseHex(s_payloadHex, payload, (uint32_t)sizeof payload);

    frame = frameAt(NWK_FRAME_TYPE_DATA, 0x0000, ADDR_ORIGIN, RADIUS, SEQ, 0, 0);
    frame.securityEnabled = 1;

    Test_ExpectStatus(NwkFrame_Compose(&frame, payload, payloadLen, npdu,
                                  (uint32_t)sizeof npdu, &npduLen), ZB_OK,
                 "the unsecured NPDU of the vector is composed by the codec");
    Test_Expect(npduLen == 15, "eight header octets and seven payload octets, in the clear");

    headerLen = NwkFrame_HeaderLen(&frame);
    Test_Expect(headerLen == 8, "the split the codec's own flags describe is where the payload begins");

    Zb_memcpy(stored, npdu, npduLen);

    fixture5(&fixture, SEQ);

    Test_ExpectStatus(Nwk_TxProtect(&fixture.security, npdu, npduLen, headerLen, scratch,
                               (uint32_t)sizeof scratch, &outLen), ZB_OK,
                 "one protection of those octets");

    Test_Expect(outLen == 33, "the frame grew by the 14-octet auxiliary header and the 4-octet MIC of level 0x05");
    Test_Expect(outLen == npduLen + SECURITY_AUX_LEN + 4, "which is the arithmetic of 4.3.1.1 step 5, not a coincidence of this frame");
    Test_ExpectHex("the secured frame is the s1 vector, octet for octet: the proof that the header half and the payload half were split where the seam splits them",
                scratch, outLen, s_frame1Hex);
    Test_Expect(scratch[headerLen] == 0x28,
           "the auxiliary header sits after every NWK header field, with the level sub-field zeroed by 4.3.1.1 step 8");
    Test_Expect(Zb_memcmp(scratch, npdu, headerLen) == 0,
           "the NWK header travels into the authenticated string unchanged (4.3.1.1 step 3d)");
    Test_Expect(Zb_memcmp(scratch + headerLen + SECURITY_AUX_LEN, payload, payloadLen) != 0,
           "and the payload region does not: level 0x05 encrypts (Table 4-38)");

    Test_Expect(Zb_memcmp(npdu, stored, npduLen) == 0,
           "the octets the caller holds are still the unsecured frame: a stored slot is never a secured one");

    Security_Snapshot(&fixture.security, &before);
    Test_Expect(before.keyCount == 1 && before.outgoingFrameCounter[0] == SEQ + 1,
           "the descriptor's OutgoingFrameCounter advanced by exactly one (4.3.1.1 step 7)");

    Test_ExpectStatus(Nwk_TxProtect(&fixture.security, npdu, npduLen, headerLen, scratch,
                               (uint32_t)sizeof scratch, &outLen), ZB_OK,
                 "a second issue of the same stored octets is a second protection");

    Security_Snapshot(&fixture.security, &after);
    Test_Expect(after.keyCount == 1 && after.outgoingFrameCounter[0] == SEQ + 2,
           "and it advanced the counter again: 3.2.1.1.3's 'each attempt SHALL be re-encrypted with the newest network frame counter' is the per-issue law");
    Test_Expect(outLen == 33, "the frame is the same length");
    Test_Expect(scratch[headerLen + 1] == (uint8_t)(SEQ + 1) && scratch[headerLen + 2] == 0
           && scratch[headerLen + 3] == 0 && scratch[headerLen + 4] == 0,
           "and it differs from the first by the counter it carries (4.5.1.3, frame counter low octet first)");
    Test_Expect(Zb_memcmp(npdu, stored, npduLen) == 0, "and the stored octets are untouched by either call");
}

/* --- nwk_command: Table 3-54 recognition ------------------------------------------------------- */

/*
 * The band the landed function answers over: `id < NWK_CMD_ROUTE_REQUEST` and `id >
 * NWK_CMD_NETWORK_COMMISSIONING_RESPONSE` are the two edges, which is Table 3-54's own shape (0x01 through
 * 0x0f printed by name, "0x10-0xff Reserved" printed beneath them) and 3.3.2.2.2's "SHALL be set to one of
 * the non-reserved values listed in Table 3-54".
 *
 * The consequence for 3.6.13 is the reason the band is asserted at both edges: an identifier outside it is
 * what makes a unicast "an unknown or unsupported NWK command", and 3.6.13 answers that with a Network Status
 * frame carrying 0x13; an identifier inside it is counted as recognized and gets no such answer even when
 * nothing in this stack acts on it. Route Record 0x05 is the inside case that matters: recognized, and
 * deferred as machinery, which is the difference between recognition and support that
 * `nwk_command.h` states.
 */
static void caseCommandIsKnownIsTable354sBand(void)
{
    uint32_t id;
    int allKnown;

    Test_Expect(NWK_CMD_ROUTE_REQUEST == 0x01 && NWK_CMD_NETWORK_COMMISSIONING_RESPONSE == 0x0f,
           "the two identifiers the band is bounded by are the first and the last Table 3-54 prints");

    Test_Expect(Nwk_CommandIsKnown(NWK_CMD_ROUTE_REQUEST) == 1, "the lower boundary is known");
    Test_Expect(Nwk_CommandIsKnown(NWK_CMD_NETWORK_COMMISSIONING_RESPONSE) == 1, "the upper boundary is known");

    allKnown = 1;

    for (id = NWK_CMD_ROUTE_REQUEST; id <= NWK_CMD_NETWORK_COMMISSIONING_RESPONSE; id++)
    {
        if (!Nwk_CommandIsKnown(id))
            allKnown = 0;
    }

    Test_Expect(allKnown, "and the whole band between them is known: the fifteen are contiguous, 3.3.2.2.2");

    Test_Expect(Nwk_CommandIsKnown(NWK_CMD_ROUTE_RECORD) == 1,
           "a command this stack defers the machinery for is still recognized: 0x05 Route Record is Table 3-54's");

    Test_Expect(Nwk_CommandIsKnown(NWK_CMD_REJOIN_REQUEST) == 1,
           "and 0x06 Rejoin Request is, which is the identifier 3.6.2.2 carves out of its unsecured discard");

    Test_Expect(Nwk_CommandIsKnown(0x00) == 0, "below the band is not a command identifier at all");
    Test_Expect(Nwk_CommandIsKnown(NWK_CMD_NETWORK_COMMISSIONING_RESPONSE + 1) == 0,
           "the first Reserved identifier above the band is not known, and it is the one that starts 3.6.13's answer");
    Test_Expect(Nwk_CommandIsKnown(NWK_ADDR_ALL_DEVICES) == 0, "and 0xff is the table's own '0x10-0xff Reserved'");
    Test_Expect(Nwk_CommandIsKnown(0x100) == 0 && Nwk_CommandIsKnown(0xffffffff) == 0,
           "the parameter is a uint32_t, so the band is asserted against the widths a caller can hand it, not only against an octet");
}

/* --- nwk_rx: the forwarded copy -------------------------------------------------------------- */

/*
 * The octets a forwarding device puts back on the air, read as the body actually makes them. The frame is
 * composed and then parsed, so what the copy is made from is a frame as this device read it.
 *
 * What the body does: the source, the destination, the sequence number and the payload are carried, the
 * radius is carried as the frame already holds it (the decrement 3.3.1.4 and 3.6.2.2 oblige is paid by the
 * device that received the frame, in the façade's dispatcher, before this composition), the End Device
 * Initiator is cleared (3.3.1.1.8: "a router parent device SHALL clear this field when relaying a message
 * sent by one of its end device children"), and the security sub-field is kept because the copy is the
 * unsecured form of a frame that has to be protected again before it goes out (4.3.2).
 */
/*
 * The octets a forwarding device puts back on the air, read as the body actually makes them. The frame is
 * composed and then parsed, so what the copy is made from is a frame as this device read it.
 *
 * What the body does: every octet is the frame's, the source, the destination, the sequence number, the radius
 * the receipt already decremented (3.3.1.4, 3.6.2.2) and the payload, and the End Device Initiator is carried
 * too. 3.3.1.1.8 clears that bit for "a router parent device … relaying a message sent by one of its end device
 * children", and this slice has no parent state to know a child of its own from another router's, so it does not
 * clear what is not its to clear. The security sub-field is kept because the copy is the unsecured form of a
 * frame that has to be protected again before it goes out (4.3.2).
 */
static void caseRxForwardCopyCarriesTheFrameItReadsAndClearsNothing(void)
{
    Nwk_Frame frame;
    Nwk_Frame copy;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint8_t out[NWK_FRAME_NPDU_MAX];
    uint8_t payload[8];
    uint32_t payloadLen;
    uint32_t npduLen = 0;
    uint32_t outLen = 0;
    uint32_t payloadOffset = 0;
    uint32_t copyPayloadOffset = 0;
    uint32_t copyPayloadLen = 0;
    uint32_t i;

    for (i = 0; i < 8; i++)
        payload[i] = (uint8_t)(0x70 + i);

    payloadLen = 8;

    frame = frameAt(NWK_FRAME_TYPE_DATA, ADDR_A, NWK_ADDR_ALL_DEVICES, RADIUS_READ, 0x2a, 0, 0);
    frame.endDeviceInitiator = 1;

    Test_ExpectStatus(NwkFrame_Compose(&frame, payload, payloadLen, npdu,
                                  (uint32_t)sizeof npdu, &npduLen), ZB_OK,
                 "an unsecured frame with the End Device Initiator set, as a device with an end-device child received it");
    Test_ExpectStatus(NwkFrame_Parse(npdu, npduLen, &frame, &payloadOffset, &payloadLen), ZB_OK,
                 "and read back out of those octets");
    Test_Expect(frame.endDeviceInitiator == 1 && frame.radius == RADIUS_READ,
           "the parsed frame carries the bit and the radius this device received");

    Test_ExpectStatus(Nwk_RxForwardCopy(&frame, npdu + payloadOffset, payloadLen, out,
                                   (uint32_t)sizeof out, &outLen), ZB_OK,
                 "the forwarded copy is composed");

    Test_Expect(outLen == npduLen, "the copy is the same length as the frame it was made from: nothing is dropped and nothing is added");

    Test_Expect(Zb_memcmp(out, npdu, npduLen) == 0,
           "every octet of the copy is the octet the frame was read from: 3.6.4.3's sequence number left standing, 3.3.1.1.8's bit kept");

    Test_ExpectStatus(NwkFrame_Parse(out, outLen, &copy, &copyPayloadOffset, &copyPayloadLen), ZB_OK,
                 "and the copy is a frame");
    Test_Expect(copy.destAddr == NWK_ADDR_ALL_DEVICES && copy.srcAddr == ADDR_A && copy.sequenceNumber == 0x2a,
           "destination, source and sequence number carried as the frame held them");
    Test_Expect(copy.radius == RADIUS_READ,
           "the radius carried, not decremented a second time: the decrement is what receipt costs and this body is the copy, not the receipt");
    Test_Expect(copy.endDeviceInitiator == 1,
           "the End Device Initiator is the frame's: a device that is not this frame's source's parent does not clear it (3.3.1.1.8)");
    Test_Expect(copyPayloadOffset == payloadOffset && copyPayloadLen == payloadLen
           && Zb_memcmp(out + copyPayloadOffset, npdu + payloadOffset, payloadLen) == 0,
           "and the payload appended verbatim");

    frame.securityEnabled = 1;
    frame.endDeviceInitiator = 1;

    Test_ExpectStatus(NwkFrame_Compose(&frame, payload, payloadLen, npdu,
                                  (uint32_t)sizeof npdu, &npduLen), ZB_OK,
                 "the same frame with the security sub-field set");
    Test_ExpectStatus(NwkFrame_Parse(npdu, npduLen, &frame, &payloadOffset, &payloadLen), ZB_OK,
                 "read back");

    Test_ExpectStatus(Nwk_RxForwardCopy(&frame, npdu + payloadOffset, payloadLen, out,
                                   (uint32_t)sizeof out, &outLen), ZB_OK,
                 "and copied for forwarding");
    Test_Expect((out[1] & 0x02) == 0x02,
           "the security bit is carried into the copy along with everything else: it is what tells the next issue to protect this copy again");
}

/*
 * The two refusals this body can answer with, both reported and both writing nothing.
 *
 * A buffer one octet short is the codec's ZB_ERR_NO_SPACE, and the caller counts it; a frame this stack will
 * not put back on the air is the codec's ZB_ERR_UNSUPPORTED: here a protocol-version 0x01 frame, which Table
 * 1-5 says a device may process and which this codec therefore parses, and which nwkcProtocolVersion 0x02
 * means this network does not transmit. Both leave the caller's buffer exactly as it was: a relay that
 * forwarded a half-written frame would be a relay that put a corrupt NPDU on the air.
 */
static void caseRxForwardCopyRefusesAndLeavesTheBufferUntouched(void)
{
    Nwk_Frame frame;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint8_t out[NWK_FRAME_NPDU_MAX];
    uint8_t payload[4];
    uint32_t npduLen = 0;
    uint32_t outLen = 0;
    uint32_t i;
    int untouched;

    for (i = 0; i < 4; i++)
        payload[i] = (uint8_t)(0x90 + i);

    frame = frameAt(NWK_FRAME_TYPE_DATA, ADDR_A, ADDR_B, RADIUS_READ, 0x11, 0, 0);

    Test_ExpectStatus(NwkFrame_Compose(&frame, payload, 4, npdu, (uint32_t)sizeof npdu, &npduLen), ZB_OK,
                 "a frame composed to a known length");
    Test_Expect(npduLen == 12, "eight header octets and four payload octets");

    for (i = 0; i < NWK_FRAME_NPDU_MAX; i++)
        out[i] = 0xa5;

    outLen = 0xdead;

    Test_ExpectStatus(Nwk_RxForwardCopy(&frame, payload, 4, out, npduLen - 1, &outLen), ZB_ERR_NO_SPACE,
                 "a buffer one octet short is refused with the codec's own answer for a buffer that cannot hold the frame");

    untouched = 1;

    for (i = 0; i < NWK_FRAME_NPDU_MAX; i++)
    {
        if (out[i] != 0xa5)
            untouched = 0;
    }

    Test_Expect(untouched, "and the caller's buffer is provably untouched: no half-written frame");
    Test_Expect(outLen == 0xdead, "and the length the refusal did not produce is not written into the caller's answer");

    /* A Zigbee 2004 frame: parsed, because Table 1-5 obliges a 0x02 network to process 0x01, and not
       relayed, because nwkcProtocolVersion is 0x02 and Table 1-5 prints no backwards-compatibility duty. */
    npdu[0] = 0x04;
    npdu[1] = 0x00;
    npdu[2] = (uint8_t)(ADDR_C & 0xff);
    npdu[3] = (uint8_t)(ADDR_C >> 8);
    npdu[4] = (uint8_t)(ADDR_A & 0xff);
    npdu[5] = (uint8_t)(ADDR_A >> 8);
    npdu[6] = RADIUS_READ;
    npdu[7] = 0x11;
    npdu[8] = 0x90;
    npdu[9] = 0x91;
    npdu[10] = 0x92;
    npdu[11] = 0x93;

    for (i = 0; i < NWK_FRAME_NPDU_MAX; i++)
        out[i] = 0x5a;

    Test_ExpectStatus(NwkFrame_Parse(npdu, 12, &frame, &outLen, &npduLen), ZB_OK,
                 "the 0x01 frame is a frame this device reads");
    Test_Expect(frame.protocolVersion == 1, "and it says which version it is (Table 1-5)");

    outLen = 0xbeef;

    Test_ExpectStatus(Nwk_RxForwardCopy(&frame, payload, 4, out, (uint32_t)sizeof out, &outLen), ZB_ERR_UNSUPPORTED,
                 "and the copy of it is refused: this stack composes nwkcProtocolVersion 0x02 and nothing else, so a 0x01 frame it read is not a frame it puts back on the air");

    untouched = 1;

    for (i = 0; i < NWK_FRAME_NPDU_MAX; i++)
    {
        if (out[i] != 0x5a)
            untouched = 0;
    }

    Test_Expect(untouched, "with the buffer untouched again");
    Test_Expect(outLen == 0xbeef, "and no length claimed for a frame that was not composed");
}

/* --- nwk_relay: the broadcast jitter --------------------------------------------------------- */

static Nwk_Config configAt(uint32_t jitterSeed)
{
    Nwk_Config cfg;

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.deviceType = NWK_DEVICE_ROUTER;
    cfg.jitterSeed = jitterSeed;

    return cfg;
}

/*
 * The generator as `nwk_relay.c` states it: xorshift32 with the (13, 17, 5) triple, the new state mapped by
 * (x * (ceiling + 1)) >> 32 onto the 65 slots the closed interval 0..64 has, and the draw reading the state
 * the call advanced. Seeded with `JITTER_SEED` the draws are the six numbers `test/nwk/` case 6a pins its
 * schedule with: the same seed reaching the same schedule through the façade and through this direct call is
 * the reproducibility claimed for a derived draw.
 */
static void caseRelayJitterIsTheDerivedScheduleItIsWrittenAs(void)
{
    static const uint32_t draws[6] = { 64, 36, 13, 0, 49, 2 };
    Nwk_Config cfg = configAt(JITTER_SEED);
    uint32_t stateA = JITTER_SEED;
    uint32_t stateB = JITTER_SEED;
    uint32_t previous;
    uint32_t draw;
    uint32_t i;
    int same;

    for (i = 0; i < 6; i++)
    {
        draw = Nwk_RelayJitterMs(&stateA, &cfg);

        if (draw != draws[i])
            break;
    }

    Test_Expect(i == 6, "the six draws one seed produces are the six this tree's relay schedule is pinned with");

    stateA = JITTER_SEED;
    same = 1;

    for (i = 0; i < 8; i++)
    {
        if (Nwk_RelayJitterMs(&stateA, &cfg) != Nwk_RelayJitterMs(&stateB, &cfg))
            same = 0;
    }

    Test_Expect(same, "and the same state plus the same config answers the same value twice: no clock, no platform, nothing drawn");

    stateA = JITTER_SEED;

    for (i = 0; i < 8; i++)
    {
        previous = stateA;
        Nwk_RelayJitterMs(&stateA, &cfg);

        if (stateA == previous)
            break;
    }

    Test_Expect(i == 8, "and the state advances between calls: 0 is xorshift32's only fixed point, so a nonzero state is never left where it was");
}

/* The bound 3.6.6 prints, "This time period shall be bounded by the value of the nwkcMaxBroadcastJitter
   attribute", against the ceiling Table 3-65's 0x7d0 OctetDurations becomes at the table's own 32-µs
   OctetDuration. Over a long run the interval is shown to be closed at both ends rather than claimed. */
static void caseRelayJitterIsBoundedByThePrintedCeilingOverA64DrawRun(void)
{
    Nwk_Config cfg = configAt(0xdeadbeef);
    uint32_t state = 0xdeadbeef;
    uint32_t draw;
    uint32_t i;
    int overCeiling;
    int atCeiling;
    int atZero;

    Test_Expect(NWK_MAX_BROADCAST_JITTER_MS
           == NWK_MAX_BROADCAST_JITTER_UNITS * NWK_OCTET_DURATION_US / 1000,
           "the ceiling is the derivation the module holds at build time too: 2000 OctetDurations at 32 µs is 64 ms");
    Test_Expect(NWK_MAX_BROADCAST_JITTER_MS == 64, "and it is Table 3-65's own printed '0x40 msec on 2.4GHz', not a paraphrase of the unit");

    overCeiling = 0;
    atCeiling = 0;
    atZero = 0;

    for (i = 0; i < 64; i++)
    {
        draw = Nwk_RelayJitterMs(&state, &cfg);

        if (draw > NWK_MAX_BROADCAST_JITTER_MS)
            overCeiling++;

        if (draw == NWK_MAX_BROADCAST_JITTER_MS)
            atCeiling++;

        if (draw == 0)
            atZero++;
    }

    Test_Expect(overCeiling == 0, "no draw of 64 exceeds nwkcMaxBroadcastJitter");
    Test_Expect(atCeiling != 0, "and the bound is met, not merely obeyed: the multiply-shift reaches the ceiling value itself");
    Test_Expect(atZero != 0, "and 0 is inside the closed interval, because 3.6.6 prints no lower bound");
}

/* "0 disables jitter": a config that seeds no entropy answers 0 and does not touch the state
   it was handed. That is what makes every schedule written before the jitter landed still assertable, and it
   is a refusal to invent a draw the application did not seed. */
static void caseRelayJitterWithNoSeedAnswersZeroAndTouchesNoState(void)
{
    Nwk_Config cfg = configAt(0);
    uint32_t state = 0x12345678;
    uint32_t i;
    int drewZero;

    drewZero = 1;

    for (i = 0; i < 4; i++)
    {
        if (Nwk_RelayJitterMs(&state, &cfg) != 0)
            drewZero = 0;
    }

    Test_Expect(drewZero, "a config with jitterSeed 0 draws 0 every time");
    Test_Expect(state == 0x12345678, "and the generator's state is not advanced by a draw that never happened");
}

/* The guard beside the seed: xorshift32's only fixed point is 0, so a state that ever reaches 0 would stay
   there and the cycle would be short. The landed body substitutes 1 and advances; the draw it produces is
   still inside the bound. */
static void caseRelayJitterDoesNotLeaveItsStateStuckAtZero(void)
{
    Nwk_Config cfg = configAt(0x00000001);
    uint32_t state = 0;
    uint32_t draw;

    draw = Nwk_RelayJitterMs(&state, &cfg);

    Test_Expect(draw == 0 && state == 0x42021,
           "a zero state with a seed is advanced through 1, not left at 0: the draw is (0x42021 * 65) >> 32 and the state is 0x42021");

    draw = Nwk_RelayJitterMs(&state, &cfg);

    Test_Expect(state != 0 && draw <= NWK_MAX_BROADCAST_JITTER_MS,
           "and the generator keeps running from there, bounded as every other draw is");
}

/* --- nwk_rx: the three neighbor-writing stages ----------------------------------------------- */

/*
 * 3.6.6 and 3.6.2.2 act on a neighbor entry's device type and receiver duty, and a frame can only speak for
 * its NWK source and (when 3.3.1.7 says the sender put one there) its source IEEE address. So an entry born
 * from observation is NWK_NEIGHBOR_TYPE_UNKNOWN, its receiver unstated, its relationship Table 3-75's 0x03
 * "none of the above", its age the turn it was seen in, and its two cost fields the measurement the carrier
 * came with (`caseRxObserveRecordsTheMeasuredLinkCost` below). A second observation refreshes the age and
 * writes an IEEE address the frame carried, without duplicating the entry; the coordinator's 0x0000 is an
 * address like any other, so a frame from it creates its own entry (3.6.1.7).
 */
static void caseRxObserveRecordsOnlyWhatAFrameCanSay(void)
{
    Nwk_Frame frame;
    int addRefused;

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    frame = frameAt(NWK_FRAME_TYPE_DATA, ADDR_A, NWK_ADDR_ALL_DEVICES, RADIUS_READ, 0x01, HOP_IEEE, 1);

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, LQA_MEASURED, 0, 0, NOW_MS, &addRefused);

    Test_Expect(addRefused == 0, "a table with room refused nothing");
    Test_Expect(s_neighbors[0].inUse == 1 && s_neighbors[0].networkAddress == ADDR_A,
           "the NWK source the header names becomes an entry (3.6.6)");
    Test_Expect(s_neighbors[0].deviceType == NWK_NEIGHBOR_TYPE_UNKNOWN && s_neighbors[0].rxOnWhenIdle == 0,
           "and it states no device type and no receiver duty: Table 3-75 prints three types and no 'seen on the air', so every rule that reads one declines for it");
    Test_Expect(s_neighbors[0].relationship == NWK_REL_NONE,
           "the relationship an observation can support is Table 3-75's 0x03, 'none of the above'");
    Test_Expect(s_neighbors[0].ageFromMs == NOW_MS, "the age counts from the turn the entry was made");
    Test_Expect(s_neighbors[0].extendedAddress == HOP_IEEE && s_neighbors[0].ieeeKnown == 1,
           "the source IEEE address when the frame carried one (3.3.1.7)");
    Test_Expect(Nwk_NeighborCount(s_neighbors) == 1, "one entry for one source");

    frame.srcIeeePresent = 0;
    frame.srcIeee = 0;

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, LQA_MEASURED, 0, 0, LATER_MS, &addRefused);

    Test_Expect(addRefused == 0 && Nwk_NeighborCount(s_neighbors) == 1,
           "the same source again is one entry refreshed and not a second entry");
    Test_Expect(s_neighbors[0].ageFromMs == NOW_MS,
           "its age did not move: 8171 and Table 3-75 count it from the last link status, and this frame is not one");
    Test_Expect(s_neighbors[0].extendedAddress == HOP_IEEE && s_neighbors[0].ieeeKnown == 1,
           "and an address this module already knows is not forgotten by a frame that carried none");

    frame = frameAt(NWK_FRAME_TYPE_DATA, COORDINATOR, ADDR_B, RADIUS_READ, 0x02, 0, 0);

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, LQA_MEASURED, 0, 0, LATER_MS + 1, &addRefused);

    Test_Expect(addRefused == 0 && Nwk_NeighborCount(s_neighbors) == 2
                    && Nwk_NeighborOf(s_neighbors, COORDINATOR) != 0,
           "the coordinator's 0x0000 is an address like any other: Figure 3-4 always carries a source, so 3.6.1.7 observes it as its own entry rather than reading it as 'no address'");
}

/* 3.6.1.6.1.3: an unsecured frame claiming to come from a neighbour must not rewrite what the table holds of it,
   so a known IEEE address stands against an unsecured source, an unknown one is filled, and a secured frame
   states it with authority. */
static void caseRxObserveKeepsAKnownIeeeAgainstAnUnsecuredFrame(void)
{
    Nwk_Frame frame;
    int addRefused;

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);
    seedNeighbor(0, ADDR_A, HOP_IEEE, 1, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);

    frame = frameAt(NWK_FRAME_TYPE_COMMAND, ADDR_A, COORDINATOR, RADIUS_READ, 0x03, HOP_IEEE + 1, 1);

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, LQA_MEASURED, 0, 0, NOW_MS, &addRefused);

    Test_Expect(s_neighbors[0].extendedAddress == HOP_IEEE && s_neighbors[0].relationship == NWK_REL_CHILD,
                "an unsecured frame naming a known neighbour's address with another IEEE address changes neither");

    frame.securityEnabled = 1;

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, LQA_MEASURED, HOP_IEEE + 1, 1, LATER_MS, &addRefused);

    Test_Expect(s_neighbors[0].extendedAddress == HOP_IEEE + 1, "the authenticated hop's IEEE address is taken at its word");

    s_neighbors[0].ieeeKnown = 0;
    s_neighbors[0].extendedAddress = 0;
    frame.securityEnabled = 0;

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, LQA_MEASURED, 0, 0, LATER_MS + 1, &addRefused);

    Test_Expect(s_neighbors[0].ieeeKnown == 1 && s_neighbors[0].extendedAddress == HOP_IEEE + 1,
                "and an unsecured frame fills the address an entry lacks");
}

/*
 * Two Table 3-75 fields, written where the entry is written: the LQA (LQI) is the measurement the carrier
 * came with and the Outgoing Cost is Table 3-76's level for it. Band A exchanges no link status, so a
 * neighbor's outgoing direction is taken to be its measured incoming one (the symmetry the carrier's own
 * measurement states), which is why one measurement fills both fields.
 *
 * The asymmetry the module's two vocabularies turn on is asserted beside them: an LQA of 0 is a measurement
 * (cost 7, the worst link there is), while a cost of 0 is the absence of one, which 3.6.4.5.1.2 discards a
 * route request on. A neighbor nothing measured (an entry an association wrote rather than a frame) is the
 * only kind that answers 0.
 */
static void caseRxObserveRecordsTheMeasuredLinkCost(void)
{
    Nwk_Frame frame;
    Nwk_NeighborTableEntry *unmeasured;
    int addRefused;

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    frame = frameAt(NWK_FRAME_TYPE_DATA, ADDR_A, NWK_ADDR_ALL_DEVICES, RADIUS_READ, 0x05, HOP_IEEE, 1);

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, LQA_MEASURED, 0, 0, NOW_MS, &addRefused);

    Test_Expect(s_neighbors[0].lqi == LQA_MEASURED,
           "Table 3-75's LQA (LQI) is the measurement the carrier carried, recorded verbatim");
    Test_Expect(s_neighbors[0].outgoingCost == 0,
           "and Outgoing Cost stays 0: 8168-8170 take it only from a link status, and 0 is that none listing this device arrived");
    Test_Expect(Nwk_CostUsable(s_neighbors[0].outgoingCost) == 0,
           "which is the value 3.6.4.5.1.2 discards a route request on");

    s_neighbors[0].outgoingCost = 3;

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, 20, 0, 0, LATER_MS, &addRefused);

    Test_Expect(s_neighbors[0].lqi == 20 && s_neighbors[0].outgoingCost == 3,
           "a later frame moves the LQA, measured per receipt (3.6.3), and leaves the cost the link status stated");

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, LQA_FLOOR, 0, 0, LATER_MS + 1, &addRefused);

    Test_Expect(s_neighbors[0].lqi == LQA_FLOOR && Nwk_CostFromLqa(s_neighbors[0].lqi) == NWK_COST_WORST,
           "an LQA of 0 is cost 7 and not cost 0: \"7 | LQA ≤ 16\" has no exception for the floor");

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, 0x1234, 0, 0, LATER_MS + 2, &addRefused);

    Test_Expect(s_neighbors[0].lqi == NWK_LQA_MAX && Nwk_CostFromLqa(s_neighbors[0].lqi) == NWK_COST_BEST,
           "a measurement wider than Table 3-75's octet is clamped into the field rather than truncated, and still lands on the best level");

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    unmeasured = seedNeighbor(0, ADDR_B, 0, 0, NWK_DEVICE_ROUTER, 1, NWK_REL_NONE);

    Test_Expect(unmeasured->outgoingCost == 0 && Nwk_CostUsable(unmeasured->outgoingCost) == 0,
           "a neighbor no link status stated a cost for has an outgoing cost of 0, and 3.6.4.5.1.2 discards a route request whose sender answers 0");
    Test_Expect(Nwk_CostUsable(0) == 0 && Nwk_CostUsable(1) == 1 && Nwk_CostUsable(7) == 1,
           "the usability test is that one value: 0 is no measurement and every level 1-7 is one, worst included");
}

/* 8160-8167: the table holds who is in transmission range, so a frame a relay carried in is the relay's measurement
   and says nothing of the originator two hops off, which 3.3.1.7's source address still names. */
static void caseRxObserveRecordsTheHopNotTheOriginator(void)
{
    Nwk_Frame frame;
    int addRefused;

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    frame = frameAt(NWK_FRAME_TYPE_DATA, ADDR_A, NWK_ADDR_ALL_DEVICES, RADIUS_READ, 0x06, OTHER_IEEE, 1);

    Nwk_RxObserve(s_neighbors, &frame, ADDR_B, LQA_MEASURED, 0, 0, NOW_MS, &addRefused);

    Test_Expect(Nwk_NeighborCount(s_neighbors) == 1 && s_neighbors[0].networkAddress == ADDR_B,
                "the entry is the hop's, and the originator gets none");
    Test_ExpectCount(s_neighbors[0].lqi, LQA_MEASURED, "with the hop's measurement");
    Test_Expect(s_neighbors[0].ieeeKnown == 0, "and the originator's IEEE address is not written beside the hop's short one");

    Nwk_RxObserve(s_neighbors, &frame, ADDR_B, LQA_MEASURED, HOP_IEEE, 1, LATER_MS, &addRefused);

    Test_Expect(s_neighbors[0].ieeeKnown == 1 && s_neighbors[0].extendedAddress == HOP_IEEE,
                "4.5.1.3's auxiliary source is the hop's, so that one is");
}

/* The one refusal this stage can meet on its own: a table with no slot left for a new address. It comes back
   as a flag the call site counts under Table 3-84's NEIGHBOR_TABLE_FULL, it displaces nothing, and it is not
   what an address the table already holds meets. */
/* 8757-8767: the final LQA is the median of the 3 most recent raw samples, over fewer while fewer exist, so one outlier
   moves nothing; of two there is no middle, and D-257 takes the lower rather than the average 8760 sets aside. */
static void caseRxObserveFiltersTheLqa(void)
{
    Nwk_Frame frame;
    int addRefused;

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    frame = frameAt(NWK_FRAME_TYPE_DATA, ADDR_A, NWK_ADDR_ALL_DEVICES, RADIUS_READ, 0x08, 0, 0);

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, 200, 0, 0, NOW_MS, &addRefused);
    Test_ExpectCount(s_neighbors[0].lqi, 200, "8764: a new entry's one measurement is its final value");

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, 180, 0, 0, NOW_MS, &addRefused);
    Test_ExpectCount(s_neighbors[0].lqi, 180, "of two the lower");

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, 20, 0, 0, NOW_MS, &addRefused);
    Test_ExpectCount(s_neighbors[0].lqi, 180, "of three the middle, so a single bad frame does not count");
    Test_ExpectCount(Nwk_CostFromLqa(s_neighbors[0].lqi), 2, "and the cost does not jump with it");

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, 200, 0, 0, NOW_MS, &addRefused);
    Test_ExpectCount(s_neighbors[0].lqi, 180, "the window is the 3 most recent: 180, 20, 200");

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, 30, 0, 0, NOW_MS, &addRefused);
    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, 30, 0, 0, NOW_MS, &addRefused);
    Test_ExpectCount(s_neighbors[0].lqi, 30, "and a real change takes two frames: 8766's fast response");

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, 0x1234, 0, 0, NOW_MS, &addRefused);
    Test_ExpectCount(s_neighbors[0].lqi, 30, "a sample wider than the octet is clamped before the window takes it");
}

static void caseRxObserveRefusesAFullTableAndRefreshesAnEntryItHolds(void)
{
    Nwk_Frame frame;
    int addRefused;
    uint32_t i;

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
        seedNeighbor(i, (uint16_t)(ADDR_A + i), 0, 0, NWK_NEIGHBOR_TYPE_UNKNOWN, 0, NWK_REL_NONE);

    frame = frameAt(NWK_FRAME_TYPE_DATA, ADDR_C, NWK_ADDR_ALL_DEVICES, RADIUS_READ, 0x03, 0, 0);

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, LQA_MEASURED, 0, 0, LATER_MS, &addRefused);

    Test_Expect(addRefused == 1, "a full table refuses the new address, and says so (Table 3-84's NEIGHBOR_TABLE_FULL)");
    Test_Expect(Nwk_NeighborCount(s_neighbors) == NWK_NEIGHBOR_MAX, "and evicts nothing to make room (the pool is refusal-and-count)");

    Test_Expect(s_neighbors[NWK_NEIGHBOR_MAX - 1].networkAddress == (uint16_t)(ADDR_A + NWK_NEIGHBOR_MAX - 1)
           && s_neighbors[NWK_NEIGHBOR_MAX - 1].ageFromMs == NOW_MS,
           "the entry the refusal would have displaced is exactly as it was");

    frame = frameAt(NWK_FRAME_TYPE_DATA, ADDR_A, NWK_ADDR_ALL_DEVICES, RADIUS_READ, 0x04, OTHER_IEEE, 1);

    Nwk_RxObserve(s_neighbors, &frame, frame.srcAddr, LQA_MEASURED, 0, 0, LATER_MS + 1, &addRefused);

    Test_Expect(addRefused == 0, "a full table still refreshes a source it already holds: the refusal is for a new neighbor, not for any observation");
    Test_Expect(s_neighbors[0].ageFromMs == NOW_MS && s_neighbors[0].extendedAddress == OTHER_IEEE
           && s_neighbors[0].ieeeKnown == 1, "and the refresh writes the address the frame carried, not the age");
}

/*
 * 4.3.1.2 step 8, verbatim: "If there is an entry in nwkNeighborTable in the NIB whose extended address
 * matches SenderAddress and whose relationship field has value 0x05 (unauthenticated child), then set
 * relationship field in that entry to the value 0x01 (child)".
 *
 * The address matched is the one `Security_Unprotect` names in its result: the auxiliary source
 * field, which 4.5.1.3 pins to "the extended 64-bit address of the device responsible for securing
 * the frame", the hop, and not the originator the NWK header names. Every entry the clause
 * describes is flipped, because the clause has no reading in which one of two entries saying the
 * same thing about the same device stays unauthenticated. An entry whose extended address is
 * unknown cannot match, which is the honest state of a table band A feeds from frames that carry
 * no IEEE address. Nothing else moves, and nothing is counted: the step has no failure to report.
 */
static void caseRxAuthenticateHopFlipsEveryMatchingUnauthenticatedChild(void)
{
    Security_Result result;
    Nwk_NeighborTableEntry *kept;

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);
    Zb_memset(&result, 0, (uint32_t)sizeof result);

    result.senderIeee = HOP_IEEE;
    result.keySeqNumber = 0x00;
    result.frameCounter = 7;
    result.activeKeyAdopted = 0;

    seedNeighbor(0, ADDR_A, HOP_IEEE, 1, NWK_NEIGHBOR_TYPE_UNKNOWN, 0, NWK_REL_UNAUTHENTICATED_CHILD);
    seedNeighbor(1, ADDR_B, HOP_IEEE, 1, NWK_DEVICE_END_DEVICE, 0, NWK_REL_UNAUTHENTICATED_CHILD);
    seedNeighbor(2, ADDR_C, HOP_IEEE, 1, NWK_NEIGHBOR_TYPE_UNKNOWN, 1, NWK_REL_CHILD);
    seedNeighbor(3, (uint16_t)(ADDR_C + 1), OTHER_IEEE, 1, NWK_NEIGHBOR_TYPE_UNKNOWN, 0, NWK_REL_UNAUTHENTICATED_CHILD);
    seedNeighbor(4, (uint16_t)(ADDR_C + 2), HOP_IEEE, 1, NWK_NEIGHBOR_TYPE_UNKNOWN, 0, NWK_REL_LOST_CHILD);
    seedNeighbor(5, (uint16_t)(ADDR_C + 3), 0, 0, NWK_NEIGHBOR_TYPE_UNKNOWN, 0, NWK_REL_UNAUTHENTICATED_CHILD);

    s_neighbors[6].inUse = 0;
    s_neighbors[6].networkAddress = (uint16_t)(ADDR_C + 4);
    s_neighbors[6].extendedAddress = HOP_IEEE;
    s_neighbors[6].ieeeKnown = 1;
    s_neighbors[6].relationship = NWK_REL_UNAUTHENTICATED_CHILD;

    Nwk_RxAuthenticateHop(s_neighbors, &result);

    Test_Expect(s_neighbors[0].relationship == NWK_REL_CHILD && s_neighbors[1].relationship == NWK_REL_CHILD,
           "0x05 becomes 0x01 for every entry whose extended address is the hop the auxiliary named (4.3.1.2 step 8)");
    Test_Expect(s_neighbors[0].networkAddress == ADDR_A && s_neighbors[0].extendedAddress == HOP_IEEE
           && s_neighbors[0].ageFromMs == NOW_MS && s_neighbors[0].deviceType == NWK_NEIGHBOR_TYPE_UNKNOWN,
           "and only the relationship moved: a step with no failure to report moves nothing else");

    kept = &s_neighbors[2];

    Test_Expect(kept->relationship == NWK_REL_CHILD,
           "an entry that is already a child is not re-decided by the step that makes unauthenticated children children");
    Test_Expect(s_neighbors[3].relationship == NWK_REL_UNAUTHENTICATED_CHILD,
           "and an entry whose extended address is another device's is left alone: the match is on SenderAddress, the hop, not on the NWK source 4.5.1.3 distinguishes it from");
    Test_Expect(s_neighbors[4].relationship == NWK_REL_LOST_CHILD,
           "a 0x07 is not an 0x05, and 3.6.2.3's lost child is not what step 8 speaks to");
    Test_Expect(s_neighbors[5].relationship == NWK_REL_UNAUTHENTICATED_CHILD,
           "and an entry whose extended address is unknown cannot match (Table 3-75 prints the field; band A has no way to learn one yet)");
    Test_Expect(s_neighbors[6].relationship == NWK_REL_UNAUTHENTICATED_CHILD,
           "a slot that claims no entry is not a neighbor whatever its octets say");
    Test_Expect(Nwk_NeighborCount(s_neighbors) == 6, "and no entry was added, aged out or dropped");
}

/*
 * 3.6.2.3's lost-child observation, on the one path the clause prints that band A can reach: a router or
 * coordinator, a frame whose MAC source is a short address, an entry keyed on the frame's *NWK* source (step
 * 1) whose Device Type is 0x02 (step 2), and a MAC source that is not that NWK source (step 3), the message
 * arrived through somebody else's radio, so the child this device thought it had is relayed by another device
 * and the entry's Relationship becomes 0x07 (step 5).
 *
 * The entry is keyed on the NWK source and the comparison is between two short addresses; the entry's own
 * extended address is not read at all, which is what the clause prints and what the landed body does. The
 * deletion 3.6.2.3 asks the NLME for is the stage beside this one: the mark carries the moment the clause's own
 * paragraph re-evaluates it, and `Nwk_RxReleaseLostChildren` deletes what is still 0x07 then.
 */
static void caseRxExamineParentsMarksTheChildWhoseMessageArrivedThroughAnotherRadio(void)
{
    Nwk_Frame frame;
    Mac_DataIndicationParameters ind;

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    seedNeighbor(0, CHILD_ADDR, HOP_IEEE, 1, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(1, CARRIER_ADDR, HOP_IEEE, 1, NWK_NEIGHBOR_TYPE_UNKNOWN, 1, NWK_REL_NONE);

    frame = frameAt(NWK_FRAME_TYPE_DATA, CHILD_ADDR, ADDR_B, RADIUS_READ, 0x07, 0, 0);
    ind = carrierAt(MAC_ADDR_SHORT, CARRIER_ADDR);

    Nwk_RxExamineParents(s_neighbors, NWK_DEVICE_ROUTER, &ind, &frame, NOW_MS);

    Test_Expect(s_neighbors[0].relationship == NWK_REL_LOST_CHILD,
           "0x07 on the entry keyed on the frame's NWK source: its message arrived through a MAC source that is not it (3.6.2.3 steps 1-5)");
    Test_Expect(s_neighbors[0].lostChildMs == NOW_MS + NWK_LOST_CHILD_EVALUATION_MS,
           "and the moment the clause's own paragraph re-evaluates the mark is stamped beside it, LATER_MS being inside that window");
    Test_Expect(s_neighbors[0].networkAddress == CHILD_ADDR && s_neighbors[0].extendedAddress == HOP_IEEE
           && s_neighbors[0].ieeeKnown == 1 && s_neighbors[0].deviceType == NWK_DEVICE_END_DEVICE
           && s_neighbors[0].ageFromMs == NOW_MS && s_neighbors[0].rxOnWhenIdle == 0,
           "marked and nothing else rewritten: the entry keeps every field that seeded it");
    Test_Expect(s_neighbors[1].relationship == NWK_REL_NONE,
           "and the device that carried the frame is not the entry the clause marks: 3.6.2.3 says nothing about marking the MAC source");
    Test_Expect(Nwk_NeighborCount(s_neighbors) == 2, "the stage adds nothing and deletes nothing, and counts nothing either");
}

/* Every gate the same clause prints, in the order it prints them: the duty of the device (a router or a
   coordinator, and no other), step 1's entry existing at all, step 2's Device Type, step 3's MAC source being
   the NWK source. Each one declines, and declining is what keeps an observation-only table (where every entry
   states no device type) out of a rule it cannot support. */
static void caseRxExamineParentsDeclinesEveryGateTheClausePrints(void)
{
    Nwk_Frame frame;
    Mac_DataIndicationParameters ind;

    frame = frameAt(NWK_FRAME_TYPE_DATA, CHILD_ADDR, ADDR_B, RADIUS_READ, 0x07, 0, 0);
    ind = carrierAt(MAC_ADDR_SHORT, CARRIER_ADDR);

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);
    seedNeighbor(0, CHILD_ADDR, HOP_IEEE, 1, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);

    Nwk_RxExamineParents(s_neighbors, NWK_DEVICE_END_DEVICE, &ind, &frame, NOW_MS);

    Test_Expect(s_neighbors[0].relationship == NWK_REL_CHILD,
           "the clause belongs to 'a router and coordinator', so an end device runs no examination at all");

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);
    seedNeighbor(0, CHILD_ADDR, HOP_IEEE, 1, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);

    ind = carrierAt(MAC_ADDR_NONE, CARRIER_ADDR);
    Nwk_RxExamineParents(s_neighbors, NWK_DEVICE_ROUTER, &ind, &frame, NOW_MS);

    Test_Expect(s_neighbors[0].relationship == NWK_REL_CHILD,
           "a carrier that named no short source address cannot be compared with the NWK source (step 3 has no field to read)");

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);
    seedNeighbor(0, CHILD_ADDR, HOP_IEEE, 1, NWK_NEIGHBOR_TYPE_UNKNOWN, 0, NWK_REL_NONE);

    ind = carrierAt(MAC_ADDR_SHORT, CARRIER_ADDR);
    Nwk_RxExamineParents(s_neighbors, NWK_DEVICE_ROUTER, &ind, &frame, NOW_MS);

    Test_Expect(s_neighbors[0].relationship == NWK_REL_NONE,
           "step 2 bounds what an observation-only table can support: an entry that states no device type is not 'a Zigbee End Device', and the examination stops there");

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);
    seedNeighbor(0, CHILD_ADDR, HOP_IEEE, 1, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    Nwk_RxExamineParents(s_neighbors, NWK_DEVICE_COORDINATOR, &ind, &frame, NOW_MS);

    Test_Expect(s_neighbors[0].relationship == NWK_REL_SIBLING,
           "and a source the table says is a router is not a lost child either");

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);
    seedNeighbor(0, CHILD_ADDR, HOP_IEEE, 1, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);

    ind = carrierAt(MAC_ADDR_SHORT, CHILD_ADDR);
    Nwk_RxExamineParents(s_neighbors, NWK_DEVICE_ROUTER, &ind, &frame, NOW_MS);

    Test_Expect(s_neighbors[0].relationship == NWK_REL_CHILD,
           "step 3's match is the frame coming directly from its own source: 'If it does go to step 6', and no marking happens (3.6.2.3)");

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);
    seedNeighbor(0, ADDR_A, HOP_IEEE, 1, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);

    Nwk_RxExamineParents(s_neighbors, NWK_DEVICE_ROUTER, &ind, &frame, NOW_MS);

    Test_Expect(Nwk_NeighborCount(s_neighbors) == 1 && s_neighbors[0].relationship == NWK_REL_CHILD,
           "step 1 searches for the NWK source and finds nothing: the stage neither marks an unrelated entry nor creates the entry it was looking for");
}

/*
 * 3.6.2.3's last paragraph, which the mark above is only the first half of: "Routers and Coordinators need to
 * allow for sufficient time (as an example 1 second) for the APS layer to process the message … The NLME SHALL
 * evaluate the neighbor table after the APS layer has processed the message to ascertain if the Relationship
 * field has a value of 0x07 … If the field is still 0x07 then the neighbor table entry SHALL be deleted."
 *
 * The window is the clause's own example, so the entry survives inside it and goes at its end; an entry no stage
 * of this one marked carries no window and is nobody's to delete, which is what a table seeded by a suite holds.
 */
static void caseRxLostChildIsDeletedOnceTheClauseWindowCloses(void)
{
    Nwk_Frame frame;
    Mac_DataIndicationParameters ind;
    uint32_t before;

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);
    seedNeighbor(0, CHILD_ADDR, HOP_IEEE, 1, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(1, CARRIER_ADDR, HOP_IEEE, 1, NWK_NEIGHBOR_TYPE_UNKNOWN, 1, NWK_REL_NONE);

    frame = frameAt(NWK_FRAME_TYPE_DATA, CHILD_ADDR, ADDR_B, RADIUS_READ, 0x08, 0, 0);
    ind = carrierAt(MAC_ADDR_SHORT, CARRIER_ADDR);

    Nwk_RxExamineParents(s_neighbors, NWK_DEVICE_ROUTER, &ind, &frame, NOW_MS);

    before = Nwk_NeighborCount(s_neighbors);

    Test_Expect(before == 2 && s_neighbors[0].relationship == NWK_REL_LOST_CHILD,
           "the child that changed parents is marked at the moment of receipt (3.6.2.3 step 5)");
    Test_Expect(Nwk_RxReleaseLostChildren(s_neighbors, NOW_MS) == 0
           && Nwk_NeighborCount(s_neighbors) == 2 && s_neighbors[0].relationship == NWK_REL_LOST_CHILD,
           "and nothing is evaluated inside the window the clause allows the APS layer: the mark is still there to be found");

    Test_Expect(Nwk_RxReleaseLostChildren(s_neighbors, NOW_MS + NWK_LOST_CHILD_EVALUATION_MS) == 1
           && Nwk_NeighborCount(s_neighbors) == 1,
           "and once the window has closed the entry is deleted: 'If the field is still 0x07 then the neighbor table entry SHALL be deleted'");
    Test_Expect(s_neighbors[0].inUse == 0 && s_neighbors[1].networkAddress == CARRIER_ADDR
           && s_neighbors[1].relationship == NWK_REL_NONE,
           "the entry deleted is the child's, and the device that carried its message keeps the entry it had (3.6.2.3 marks the NWK source and nothing else)");

    Test_Expect(Nwk_RxReleaseLostChildren(s_neighbors, NOW_MS + NWK_LOST_CHILD_EVALUATION_MS) == 0,
           "and the evaluation answers nothing twice: the entry is gone, and a table with no lost child in it is left alone");
}

/* --- nwk_cost: Table 3-76, the worse direction, and the octet's ceiling -------------------------- */

/*
 * Table 3-76 as printed, asserted on every boundary it prints: one assertion per edge, so a threshold read
 * off by one reddens the level on each side of it and nothing else. The table is contiguous over the whole
 * 0–255 LQA range with no holes and no unmeasured level, which is why LQA 0 is asserted first and named: it
 * is cost 7, the worst link, and not the cost 0 that means "no measurement" at the entry level (an asymmetry
 * this module exists to keep straight).
 */
static void caseCostFromLqaIsTable376sEightLevels(void)
{
    Test_Expect(Nwk_CostFromLqa(0) == 7,
           "LQA 0 is cost 7, and not cost 0: Table 3-76's last row is \"LQA ≤ 16\" with no exception for the floor, so the worst measurement is a level and not a silence");
    Test_Expect(Nwk_CostFromLqa(1) == 7, "LQA 1 is cost 7");
    Test_Expect(Nwk_CostFromLqa(16) == 7, "LQA 16 is cost 7: Table 3-76 prints \"7 | LQA ≤ 16\", inclusive at its top");
    Test_Expect(Nwk_CostFromLqa(17) == 6, "LQA 17 is cost 6, the first octet above 16");
    Test_Expect(Nwk_CostFromLqa(32) == 6, "LQA 32 is cost 6: \"6 | 16 < LQA ≤ 32\", inclusive at its top");
    Test_Expect(Nwk_CostFromLqa(33) == 5, "LQA 33 is cost 5");
    Test_Expect(Nwk_CostFromLqa(64) == 5, "LQA 64 is cost 5: \"5 | 32 < LQA ≤ 64\"");
    Test_Expect(Nwk_CostFromLqa(65) == 4, "LQA 65 is cost 4");
    Test_Expect(Nwk_CostFromLqa(96) == 4, "LQA 96 is cost 4: \"4 | 64 < LQA ≤ 96\"");
    Test_Expect(Nwk_CostFromLqa(97) == 3, "LQA 97 is cost 3");
    Test_Expect(Nwk_CostFromLqa(128) == 3, "LQA 128 is cost 3: \"3 | 96 < LQA ≤ 128\"");
    Test_Expect(Nwk_CostFromLqa(129) == 2, "LQA 129 is cost 2");
    Test_Expect(Nwk_CostFromLqa(192) == 2, "LQA 192 is cost 2: \"2 | 128 < LQA ≤ 192\"");
    Test_Expect(Nwk_CostFromLqa(193) == 1, "LQA 193 is cost 1");
    Test_Expect(Nwk_CostFromLqa(255) == 1, "LQA 255 is cost 1: \"1 | 192 < LQA ≤ 255\", the best link the table prints");

    Test_Expect(NWK_LQA_MAX == 0xff && NWK_COST_MAX == 0xff,
           "the two octets the metric spans are the widths it is printed in: LQA 0x00-0xff in (Table 3-75) and a path cost capped at 0xff out (3.6.4.1)");
    Test_Expect(NWK_COST_UNMEASURED == 0 && NWK_COST_BEST == 1 && NWK_COST_WORST == 7,
           "and the levels are 0 for no measurement and 1-7 for the eight the table prints, 1 the best and 7 the worst");
}

/*
 * 3.6.4.5.1.2: "The maximum of the incoming and outgoing costs for the neighbor is used for the purposes of
 * the path cost calculation, instead of the incoming cost." The combine is that maximum, symmetric in its
 * two arguments, and 0 only when neither direction was measured.
 */
static void caseCostCombineTakesTheWorseDirection(void)
{
    Test_Expect(Nwk_CostCombine(1, 4) == 4,
           "the greater of the two answers when the outgoing direction is the worse one (3.6.4.5.1.2)");
    Test_Expect(Nwk_CostCombine(4, 1) == 4,
           "and when the incoming direction is: the worse direction is a maximum and not the incoming cost, which is the reading the clause replaces");
    Test_Expect(Nwk_CostCombine(3, 3) == 3, "two equal costs answer that cost");
    Test_Expect(Nwk_CostCombine(0, 5) == 5, "a direction nothing measured does not hide the one that was measured");
    Test_Expect(Nwk_CostCombine(5, 0) == 5, "in either order");
    Test_Expect(Nwk_CostCombine(0, 0) == 0,
           "and 0 with 0 is 0: the one case where the worse direction is no measurement at all, which is the value 3.6.4.5.1.2 discards a route request for");
    Test_Expect(Nwk_CostCombine(NWK_COST_WORST, NWK_COST_BEST) == NWK_COST_WORST
           && Nwk_CostCombine(NWK_COST_MAX, NWK_COST_BEST) == NWK_COST_MAX,
           "the octet's own ends combine as any other two numbers do");
}

/*
 * 3.6.4.1's "link cost values are summed to produce the cost for the path as a whole", one hop further, with
 * the clamp gap G3's silence forces: the field is eight bits and the document prints no overflow rule, so a
 * sum past 0xff stays at 0xff instead of wrapping into a route that reads better than it is.
 */
static void caseCostAccumulateClampsAtTheOctetsCeiling(void)
{
    Test_Expect(Nwk_CostAccumulate(0, 3) == 3, "a path cost of 0 and a link cost of 3 is 3");
    Test_Expect(Nwk_CostAccumulate(7, 5) == 12, "and 7 plus 5 is the printed sum, 12, with nothing clamped");
    Test_Expect(Nwk_CostAccumulate(0xfe, 1) == NWK_COST_MAX, "the last octet before the ceiling is reached exactly");
    Test_Expect(Nwk_CostAccumulate(0xfe, 2) == NWK_COST_MAX, "and one more is clamped, not wrapped (gap G3)");
    Test_Expect(Nwk_CostAccumulate(NWK_COST_MAX, 1) == NWK_COST_MAX, "0xff plus anything stays 0xff");
    Test_Expect(Nwk_CostAccumulate(NWK_COST_MAX, NWK_COST_MAX) == NWK_COST_MAX, "however large the second term is");
    Test_Expect(Nwk_CostAccumulate(0, 0) == 0, "and 0 with 0 is 0: two directions nothing measured still sum to nothing measured");
    Test_Expect(Nwk_CostAccumulate(0x1234, 1) == NWK_COST_MAX,
           "a path cost already past the octet is clamped before it is added, so no uint32_t sum can wrap on the way to a 0xff that hides it");
    Test_Expect(Nwk_CostUsable(NWK_COST_MAX) == 1 && Nwk_CostUsable(0) == 0,
           "and 3.6.4.5.1.2's usability test is 0 alone: 0xff is a path cost that was measured, and 0 is the absence of one");
}

/* --- nwk_route: Table 3-77's widened entry, the claim's eviction and the usage counter ---------- */

/*
 * A claim on a table with room is the free-slot claim the module already had: 3.6.4.3's "new routing table
 * entry" has no reason to evict while a slot is idle, and a claim is not an entry, the caller marks it.
 */
static void caseRouteClaimHandsAFreeSlotWhenOneExists(void)
{
    Nwk_RoutingTableEntry *claimed;

    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);

    claimed = Nwk_RouteClaim(s_routes);

    Test_Expect(claimed == Nwk_RouteFree(s_routes),
           "a table with room claims the slot the free lookup would have offered, and evicts nothing");
    Test_Expect(claimed == &s_routes[0] && Nwk_RouteCount(s_routes) == 0,
           "the first idle slot, and the pool still holds no route: a claim is a slot, not an entry");

    seedRoute(0, ADDR_A, NWK_ROUTE_ACTIVE, ADDR_A, NOW_MS, 9);

    Test_Expect(Nwk_RouteClaim(s_routes) == &s_routes[1],
           "with slot 0 held, the claim takes the next free one, and not the used entry beside it");
    Test_Expect(Nwk_RouteOf(s_routes, ADDR_A) == &s_routes[0] && s_routes[0].totalUsageCount == 9,
           "which is left exactly as it was");
}

/*
 * 3.6.4.8's eviction: "it is important that the ranking of the entries to be evicted is based on
 * RecentActivity and TotalUsageCount". Band A has the counter and not the tick, so the least-used entry is
 * the one given up, and the slot comes back empty: a new entry must not inherit the next hop of a route it
 * is not a route to.
 */
static void caseRouteClaimEvictsTheLowestTotalUsageCount(void)
{
    Nwk_RoutingTableEntry *claimed;
    uint32_t i;

    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);

    for (i = 0; i < NWK_ROUTE_MAX; i++)
        seedRoute(i, (uint16_t)(ADDR_A + i), NWK_ROUTE_ACTIVE, (uint16_t)(ADDR_A + i), NOW_MS,
                  (i == 5) ? 1 : 40 + i);

    Test_Expect(Nwk_RouteFree(s_routes) == 0, "the table is full: no free slot is on offer");

    claimed = Nwk_RouteClaim(s_routes);

    Test_Expect(claimed == &s_routes[5],
           "so the claim gives up the entry used least recently, which here is also the one with the lowest TotalUsageCount: 3.6.4.8 ranks RecentActivity first and TotalUsageCount only between equals");
    Test_Expect(claimed->inUse == 0 && claimed->destinationAddress == 0 && claimed->nextHopAddress == 0
           && claimed->totalUsageCount == 0 && claimed->ageMs == 0,
           "and the evicted slot is emptied before it is handed over: no next hop, no counter, no age survives the eviction");
    Test_Expect(Nwk_RouteCount(s_routes) == NWK_ROUTE_MAX - 1, "the eviction costs the table exactly one entry");
    Test_Expect(Nwk_RouteOf(s_routes, (uint16_t)(ADDR_A + 5)) == 0, "the destination the evicted entry aimed at has no route any more");
    Test_Expect(Nwk_RouteOf(s_routes, (uint16_t)(ADDR_A + 6)) == &s_routes[6]
           && s_routes[6].totalUsageCount == 46,
           "while every entry the ranking did not choose is untouched");
}

/* The tie 3.6.4.8's ranking needs a second key for: equal TotalUsageCount, so the oldest ageMs goes, the
   reading of RecentActivity Table 3-77 prints, which band A keeps as its own stamp. */
static void caseRouteClaimBreaksATieByTheOldestAge(void)
{
    Nwk_RoutingTableEntry *claimed;
    uint32_t i;

    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);

    for (i = 0; i < NWK_ROUTE_MAX; i++)
        seedRoute(i, (uint16_t)(ADDR_A + i), NWK_ROUTE_ACTIVE, (uint16_t)(ADDR_A + i),
                  (i == 9) ? NOW_MS - 5000 : NOW_MS, 7);

    claimed = Nwk_RouteClaim(s_routes);

    Test_Expect(claimed == &s_routes[9],
           "with every TotalUsageCount equal, the claim takes the entry whose ageMs is oldest, and not the first slot the pool holds");
    Test_Expect(claimed->inUse == 0 && Nwk_RouteCount(s_routes) == NWK_ROUTE_MAX - 1,
           "which is one entry given up and a slot emptied, exactly as the ranked eviction is");
    Test_Expect(Nwk_RouteOf(s_routes, (uint16_t)(ADDR_A + 8)) == &s_routes[8],
           "and an equally used but younger entry beside it is left alone");
}

/* 3.6.4.8's two keys disagreeing: an entry used a moment ago but rarely overall must survive one not used for a
 * while but often overall, because the clause ranks recency first and calls on TotalUsageCount only "in case two
 * routes have been used equally often recently". */
static void caseRouteClaimPrefersRecencyOverTotalUsage(void)
{
    Nwk_RoutingTableEntry *claimed;
    uint32_t i;

    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);

    for (i = 0; i < NWK_ROUTE_MAX; i++)
        seedRoute(i, (uint16_t)(ADDR_A + i), NWK_ROUTE_ACTIVE, (uint16_t)(ADDR_A + i),
                  (i == 3) ? NOW_MS - 60000 : NOW_MS, (i == 3) ? 40 : 1);

    claimed = Nwk_RouteClaim(s_routes);

    Test_Expect(claimed == &s_routes[3],
           "9352-9355: the entry not used recently goes first, though its TotalUsageCount is the highest in the pool");
    Test_Expect(Nwk_RouteOf(s_routes, (uint16_t)(ADDR_A + 4)) == &s_routes[4],
           "while a lightly-used entry used a moment ago stays, which the inverted ranking would have evicted");
}

/* What a claim and a fill produce, read back through the lookup: Table 3-77's fields the claim scopes,
   every one of them still stating what was written. */
static void caseRouteEntryRoundTripsTable377sFields(void)
{
    Nwk_RoutingTableEntry *route;

    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);

    route = Nwk_RouteClaim(s_routes);

    Test_Expect(route != 0, "an empty table has a slot for a route");

    if (route == 0)
        return;

    route->inUse = 1;
    route->destinationAddress = ADDR_B;
    route->status = NWK_ROUTE_DISCOVERY_UNDERWAY;
    route->sequenceNumber = 0xbeef;
    route->sequenceNumberValid = 1;
    route->manyToOne = 1;
    route->noRouteCache = 1;
    route->routeRecordRequired = 1;
    route->totalUsageCount = 1234;
    route->nextHopAddress = ADDR_C;
    route->ageMs = NOW_MS;

    route = Nwk_RouteOf(s_routes, ADDR_B);

    Test_Expect(route == &s_routes[0], "the entry a claim filled is the entry the lookup finds");

    if (route == 0)
        return;

    Test_Expect(NWK_ROUTE_DISCOVERY_UNDERWAY == 0x1,
           "DISCOVERY_UNDERWAY is Table 3-78's 0x1 and a status an entry may carry again: 3.6.4.5.1 sets it");
    Test_Expect(route->status == NWK_ROUTE_DISCOVERY_UNDERWAY,
           "and the status an entry holds is the one it was given, not ACTIVE by default");
    Test_Expect(route->sequenceNumber == 0xbeef && route->sequenceNumberValid == 1,
           "the 2-octet Sequence Number and its one-bit validity round-trip (Table 3-77)");
    Test_Expect(route->manyToOne == 1 && route->noRouteCache == 1 && route->routeRecordRequired == 1,
           "and the three flags 3.6.4.5.1.3's many-to-one, 3.6.4.5.5's route record and the source-route cache read");
    Test_Expect(route->totalUsageCount == 1234 && route->nextHopAddress == ADDR_C && route->ageMs == NOW_MS,
           "and the counter, the next hop and the age come back as they were written");
}

/*
 * Table 3-77 prints TotalUsageCount as "the number of times this routing table entry has been used to forward
 * a data packet": 3.6.4.2 prints it as "incremented whenever this routing table entry is used to forward a
 * data packet", a 32-bit saturating counter. `Nwk_RouteNextHop`'s hit is that use; nothing else in this slice
 * is, and an entry that forwards nothing is not counted.
 */
static void caseRouteNextHopCountsEveryUseAndSaturates(void)
{
    Nwk_RoutingTableEntry *route;
    uint16_t nextHop = 0;

    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);
    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    seedRoute(0, ADDR_A, NWK_ROUTE_ACTIVE, ADDR_C, NOW_MS - 10, 0);

    Test_Expect(Nwk_RouteNextHop(s_routes, s_neighbors, ADDR_A, NOW_MS, &nextHop) == 1 && nextHop == ADDR_C,
           "an ACTIVE entry answers the hop it holds (3.6.4.3's first choice)");

    route = Nwk_RouteOf(s_routes, ADDR_A);

    Test_Expect(route != 0 && route->totalUsageCount == 1,
           "and that use is counted: Table 3-77's counter, incremented wherever an entry is used to forward");
    Test_Expect(route != 0 && route->ageMs == NOW_MS, "with the age stamped as it was before the counter moved");

    Test_Expect(Nwk_RouteNextHop(s_routes, s_neighbors, ADDR_A, NOW_MS + 1, &nextHop) == 1
           && route != 0 && route->totalUsageCount == 2,
           "a second look is a second use");

    if (route != 0)
        route->totalUsageCount = NWK_ROUTE_USAGE_MAX - 1;

    Test_Expect(Nwk_RouteNextHop(s_routes, s_neighbors, ADDR_A, NOW_MS + 2, &nextHop) == 1
           && route != 0 && route->totalUsageCount == NWK_ROUTE_USAGE_MAX,
           "the counter reaches 0xffffffff exactly");

    Test_Expect(Nwk_RouteNextHop(s_routes, s_neighbors, ADDR_A, NOW_MS + 3, &nextHop) == 1
           && route != 0 && route->totalUsageCount == NWK_ROUTE_USAGE_MAX,
           "and saturates there: the table prints a 32-bit saturating counter, so the use after the ceiling is a use and not a wrap to zero");

    /* An entry that is not ACTIVE forwards nothing and is not counted; a neighbor that answers the lookup
       with a route made on the spot is a new entry, which has not forwarded anything yet. */
    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);
    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    seedRoute(0, ADDR_C, NWK_ROUTE_DISCOVERY_UNDERWAY, ADDR_C, NOW_MS, 5);

    Test_Expect(Nwk_RouteNextHop(s_routes, s_neighbors, ADDR_C, NOW_MS, &nextHop) == 0,
           "a destination whose entry is DISCOVERY_UNDERWAY has no next hop yet: 3.6.4.3 takes an ACTIVE entry only");
    Test_Expect(Nwk_RouteOf(s_routes, ADDR_C) != 0 && s_routes[0].totalUsageCount == 5,
           "and an entry that forwarded nothing is not counted");

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);
    seedNeighbor(0, ADDR_B, 0, 0, NWK_DEVICE_ROUTER, 1, NWK_REL_NONE);

    Test_Expect(Nwk_RouteNextHop(s_routes, s_neighbors, ADDR_B, NOW_MS, &nextHop) == 1 && nextHop == ADDR_B,
           "a known neighbor is still a hop without a routing entry (the observation-only shortcut)");

    route = Nwk_RouteOf(s_routes, ADDR_B);

    Test_Expect(route != 0 && route->status == NWK_ROUTE_ACTIVE && route->totalUsageCount == 1,
           "and the entry made on the spot counts the use that made it: 3.6.4.3's 'It SHALL increment the routing table entry's TotalUsageCount', applied by the lookup that forwards through it");
}

/*
 * 3.6.4.3: a device relaying through an ACTIVE entry "SHALL increment the routing table entry's TotalUsageCount and
 * RecentActivity fields ... and also increment the next hop's RouterOutboundActivity counter, again saturating".
 * Table 3-75 gives that counter its octet, so the hop the lookup settles on is the only entry whose field moves,
 * and it moves for the neighbour shortcut's direct hop as well, because that is a next hop chosen to forward too.
 */
static void caseRouteNextHopMovesTheOutboundActivity(void)
{
    Nwk_NeighborTableEntry *hop;
    Nwk_NeighborTableEntry *other;
    uint16_t nextHop = 0;

    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);
    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    hop = seedNeighbor(0, ADDR_C, 0, 0, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    other = seedNeighbor(1, ADDR_B, 0, 0, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    seedRoute(0, ADDR_A, NWK_ROUTE_ACTIVE, ADDR_C, NOW_MS, 0);

    Test_Expect(Nwk_RouteNextHop(s_routes, s_neighbors, ADDR_A, NOW_MS, &nextHop) == 1 && nextHop == ADDR_C,
           "an ACTIVE entry answers the hop it holds");
    Test_ExpectCount(hop->routerOutboundActivity, 1, "and the frame 3.6.4.3 relays through it moves that hop's RouterOutboundActivity");

    Test_Expect(Nwk_RouteNextHop(s_routes, s_neighbors, ADDR_A, NOW_MS + 1, &nextHop) == 1
           && hop->routerOutboundActivity == 2,
           "a second forward through the same hop is a second count");
    Test_ExpectCount(other->routerOutboundActivity, 0,
           "and a neighbour the lookup did not choose keeps its own counter: Table 3-75 prints one field per entry");

    /* The observation-only shortcut picks the neighbour itself as the hop, and that is a next hop chosen to
       forward as much as a Table 3-77 entry's: 3.6.4.3 prints the increment for the hop and not for the table. */
    Test_Expect(Nwk_RouteNextHop(s_routes, s_neighbors, ADDR_B, NOW_MS, &nextHop) == 1 && nextHop == ADDR_B,
           "a known neighbour with no routing entry is still a hop");
    Test_ExpectCount(other->routerOutboundActivity, 1, "and the hop that shortcut settles on is counted too");

    Test_ExpectCount(Nwk_NeighborOutboundActivity(s_neighbors, ADDR_B), 2,
           "the counter is readable through its own operation, which answers the value it now holds");
    Test_ExpectCount(Nwk_NeighborOutboundActivity(s_neighbors, ADDR_A), 0,
           "and an address the table holds no entry for has no counter to move");
}

/*
 * Both counters are Table 3-75's 0x00-0xff, a ceiling and not a width: the use after it stays at the maximum
 * rather than wrapping to zero, which is what makes 3.6.4.4.3's rank(nᵢ) read a busy neighbour as busy instead of
 * as a fresh one.
 */
static void caseRouterActivitySaturatesAtTheOctets(void)
{
    Nwk_NeighborTableEntry *hop;
    uint16_t nextHop = 0;

    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);
    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    hop = seedNeighbor(0, ADDR_C, 0, 0, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    seedRoute(0, ADDR_A, NWK_ROUTE_ACTIVE, ADDR_C, NOW_MS, 0);

    hop->routerOutboundActivity = NWK_ROUTER_ACTIVITY_MAX;

    Test_Expect(Nwk_RouteNextHop(s_routes, s_neighbors, ADDR_A, NOW_MS, &nextHop) == 1
           && hop->routerOutboundActivity == NWK_ROUTER_ACTIVITY_MAX,
           "a forward through a hop whose RouterOutboundActivity is at 0xff leaves it at 0xff");

    hop->routerInboundActivity = NWK_ROUTER_ACTIVITY_MAX;

    Test_ExpectCount(Nwk_NeighborInboundActivity(s_neighbors, ADDR_C), NWK_ROUTER_ACTIVITY_MAX,
           "and the inbound counter saturates at the same octet rather than wrapping to zero");
    Test_Expect(NWK_ROUTER_ACTIVITY_MAX == 0xff,
           "which is the range Table 3-75 prints for both fields, and not this stack's own number");
}


/*
 * 3.4.3.3.2: the destination address is present "if, and only if", the frame answers a routing failure or an address
 * conflict. A 3.6.13 answer names the offending command and no destination, so the module's own composer and its own
 * reader must agree about both shapes.
 */
static void caseStatusReadsTheDestinationOnlyWhereTheClausePrintsIt(void)
{
    Nwk_NetworkStatusPayload status;
    Nwk_Frame offender;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint8_t linkFailure[4];
    uint32_t npduLen = 0;
    uint32_t seq = 0;

    Zb_memset(&offender, 0, (uint32_t)sizeof offender);
    offender.frameType = NWK_FRAME_TYPE_COMMAND;
    offender.destAddr = ADDR_A;
    offender.srcAddr = ADDR_B;
    offender.sequenceNumber = 9;

    Test_ExpectStatus(Nwk_CommandComposeReply(&offender, &offender, 0x33, ADDR_A, OWN_IEEE, 0, 0, &seq,
                                              npdu, (uint32_t)sizeof npdu, &npduLen), ZB_OK,
                      "a 3.6.13 answer is composed");
    Test_ExpectCount(npduLen, NWK_MIN_HEADER_OVERHEAD + NWK_IEEE_ADDR_OCTETS + NWK_COMMAND_REPLY_PAYLOAD_MAX,
                     "with 3.4.3.2's source IEEE address field, then Table 3-54's identifier, the status code and the offending command, and no destination");

    status = Nwk_StatusRead(npdu + NWK_MIN_HEADER_OVERHEAD + NWK_IEEE_ADDR_OCTETS, NWK_COMMAND_REPLY_PAYLOAD_MAX);
    Test_Expect(status.valid == 1 && status.statusCode == NWK_NETWORK_STATUS_UNKNOWN_COMMAND,
                "and the module's own reader reads it: the destination is absent because a 0x13 names none");
    Test_ExpectCount(status.targetAddress, 0, "with no target address claimed");

    linkFailure[0] = NWK_CMD_NETWORK_STATUS;
    linkFailure[1] = NWK_NETWORK_STATUS_LINK_FAILURE;
    linkFailure[2] = 0x34;
    linkFailure[3] = 0x12;

    status = Nwk_StatusRead(linkFailure, 4);
    Test_Expect(status.valid == 1 && status.statusCode == NWK_NETWORK_STATUS_LINK_FAILURE
                && status.targetAddress == 0x1234,
                "a link failure carries the destination of the frame that failed (3.4.3.3.2)");

    status = Nwk_StatusRead(linkFailure, 2);
    Test_ExpectCount(status.valid, 0,
                     "and a link failure without it is no frame this module reads: the address is present if and only if the clause prints it");
}

/*
 * 3.6.4.3's second choice with a destination whose entry is not ACTIVE: the neighbour answers the lookup, and the entry
 * it makes replaces the one already there rather than shadowing it in a second slot, because Table 3-77 holds one entry
 * per destination.
 */
static void caseRouteNextHopReplacesAnInactiveEntryInPlace(void)
{
    Nwk_RoutingTableEntry *route;
    uint16_t nextHop = 0;
    uint32_t stamped;
    uint32_t count = 0;
    uint32_t i;

    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);
    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    seedRoute(0, ADDR_A, NWK_ROUTE_INACTIVE, ADDR_C, NOW_MS - 10, 4);
    seedNeighbor(0, ADDR_A, 0, 0, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    stamped = s_neighbors[0].ageFromMs;

    Test_Expect(Nwk_RouteNextHop(s_routes, s_neighbors, ADDR_A, NOW_MS, &nextHop) == 1 && nextHop == ADDR_A,
                "a known neighbour answers a destination whose entry is INACTIVE");

    for (i = 0; i < NWK_ROUTE_MAX; i++)
    {
        if (s_routes[i].inUse && s_routes[i].destinationAddress == ADDR_A)
            count++;
    }

    Test_ExpectCount(count, 1, "and one entry per destination is what the table holds afterwards");
    route = Nwk_RouteOf(s_routes, ADDR_A);
    Test_Expect(route != 0 && route->status == NWK_ROUTE_ACTIVE && route->nextHopAddress == ADDR_A,
                "ACTIVE and aimed at the hop the lookup settled on, not at the entry it replaced");
    Test_ExpectCount(s_neighbors[0].ageFromMs, stamped,
                     "and the neighbour's own stamp did not move: 3.6.4.4.2 ages an entry by what it heard, not by what this device sent it");
}

/* Table 3-80's rows and the two predicates `nwk` classifies a frame with, at their boundaries: 0xfff7 is the last
 * unicast address Table 3-66 gives a device, 0xfff8-0xfffa and 0xfffe are the table's reserved rows, and the four
 * destination classes are 0xffff, 0xfffd, 0xfffc and 0xfffb. */
static void caseAddrClassesAtTheirBoundaries(void)
{
    Test_Expect(!Nwk_AddrIsBroadcast(NWK_ADDR_LAST_UNICAST), "0xfff7 is a device's own address, not a class");
    Test_Expect(!Nwk_AddrIsReserved(NWK_ADDR_LAST_UNICAST), "and it is reserved by nothing");
    Test_Expect(Nwk_AddrIsReserved(0xfff8) && Nwk_AddrIsReserved(0xfffa),
                "0xfff8 and 0xfffa are the printed reserved range, its first and last");
    Test_Expect(!Nwk_AddrIsBroadcast(0xfff8) && !Nwk_AddrIsBroadcast(0xfffa),
                "and neither of them names a group");
    Test_Expect(Nwk_AddrIsBroadcast(0xfffb) && Nwk_AddrIsBroadcast(0xfffc) && Nwk_AddrIsBroadcast(0xfffd)
                && Nwk_AddrIsBroadcast(0xffff),
                "the four destination classes the table prints are classes");
    Test_Expect(Nwk_AddrIsReserved(0xfffe) && !Nwk_AddrIsBroadcast(0xfffe),
                "and 0xfffe sits inside the classes' numeric span while the table prints it Reserved, which is the reading Table 3-80 gives and Table 3-66's nwkBroadcastAddress span does not");
    Test_Expect(!Nwk_AddrIsBroadcast(0x0000) && !Nwk_AddrIsBroadcast(0x1234), "an ordinary short address is neither");
}

/* The duty and the table that follow from the configured device type (3.6.2.2, 3.6.6), and the one type that has
 * neither. `Nwk_Init` takes only Table 3-75's three values, so the set is closed at the door; the predicate says the
 * same thing rather than relying on it. */
static void caseAddrDutyFollowsTheDeviceType(void)
{
    Test_Expect(Nwk_AddrHasRoutingDuty(NWK_DEVICE_COORDINATOR) && Nwk_AddrHasRoutingDuty(NWK_DEVICE_ROUTER),
                "a coordinator and a router carry the routing duty");
    Test_Expect(!Nwk_AddrHasRoutingDuty(NWK_DEVICE_END_DEVICE), "an end device does not");
    Test_Expect(!Nwk_AddrHasRoutingDuty(0x03),
                "and neither does a value Table 3-75 does not print, which the door refuses and this predicate would otherwise promote to a router");

    Test_Expect(Nwk_AddrKeepsBtt(NWK_DEVICE_COORDINATOR, 0) && Nwk_AddrKeepsBtt(NWK_DEVICE_ROUTER, 0),
                "3.6.6's BTT is kept by a coordinator and a router whatever their receiver does");
    Test_Expect(Nwk_AddrKeepsBtt(NWK_DEVICE_END_DEVICE, 1),
                "and by an end device whose macRxOnWhenIdle is TRUE");
    Test_Expect(!Nwk_AddrKeepsBtt(NWK_DEVICE_END_DEVICE, 0),
                "while a sleepy end device need not, which 3.6.6 leaves to the device");

    Test_Expect(Nwk_AddrClassAccepts(NWK_ADDR_ALL_DEVICES, NWK_DEVICE_END_DEVICE, 0),
                "every device is in the all-devices group");
    Test_Expect(Nwk_AddrClassAccepts(NWK_ADDR_ROUTERS, NWK_DEVICE_ROUTER, 1)
                && !Nwk_AddrClassAccepts(NWK_ADDR_ROUTERS, NWK_DEVICE_END_DEVICE, 1),
                "the routers' class is a router's, whatever its receiver does, and not an end device's");
    Test_Expect(Nwk_AddrClassAccepts(NWK_ADDR_RX_ON_WHEN_IDLE, NWK_DEVICE_END_DEVICE, 1)
                && !Nwk_AddrClassAccepts(NWK_ADDR_RX_ON_WHEN_IDLE, NWK_DEVICE_END_DEVICE, 0),
                "the receiver's class follows macRxOnWhenIdle and not the device type, which is what its row names");
    Test_Expect(!Nwk_AddrClassAccepts(NWK_ADDR_LOW_POWER_ROUTERS, NWK_DEVICE_ROUTER, 1),
                "and the low-power routers' class is one no device of this stack is in");
}

int main(void)
{
    Test_Begin("nwk_modules");

    caseTxConfirmStatusIsTable384sMapping();
    caseTxFreeHandsTheFirstIdleSlotOfThePool();
    caseTxOccupiedCountsEveryHeldSlot();
    caseTxFreeRefusesAFullPoolAndReusesAReleasedSlot();
    caseTxSecurityRunsIsTheGateBeforeAProtection();
    caseTxProtectGrowsTheFrameAndStepsTheCounterOncePerIssue();
    caseCommandIsKnownIsTable354sBand();
    caseRxForwardCopyCarriesTheFrameItReadsAndClearsNothing();
    caseRxForwardCopyRefusesAndLeavesTheBufferUntouched();
    caseRelayJitterIsTheDerivedScheduleItIsWrittenAs();
    caseRelayJitterIsBoundedByThePrintedCeilingOverA64DrawRun();
    caseRelayJitterWithNoSeedAnswersZeroAndTouchesNoState();
    caseRelayJitterDoesNotLeaveItsStateStuckAtZero();
    caseRxObserveRecordsOnlyWhatAFrameCanSay();
    caseRxObserveKeepsAKnownIeeeAgainstAnUnsecuredFrame();
    caseRxObserveRecordsTheMeasuredLinkCost();
    caseRxObserveRefusesAFullTableAndRefreshesAnEntryItHolds();
    caseRxObserveRecordsTheHopNotTheOriginator();
    caseRxObserveFiltersTheLqa();
    caseRxAuthenticateHopFlipsEveryMatchingUnauthenticatedChild();
    caseRxExamineParentsMarksTheChildWhoseMessageArrivedThroughAnotherRadio();
    caseRxExamineParentsDeclinesEveryGateTheClausePrints();
    caseRxLostChildIsDeletedOnceTheClauseWindowCloses();
    caseCostFromLqaIsTable376sEightLevels();
    caseCostCombineTakesTheWorseDirection();
    caseCostAccumulateClampsAtTheOctetsCeiling();
    caseRouteClaimHandsAFreeSlotWhenOneExists();
    caseRouteClaimEvictsTheLowestTotalUsageCount();
    caseRouteClaimBreaksATieByTheOldestAge();
    caseRouteClaimPrefersRecencyOverTotalUsage();
    caseRouteEntryRoundTripsTable377sFields();
    caseRouteNextHopCountsEveryUseAndSaturates();
    caseRouteNextHopReplacesAnInactiveEntryInPlace();
    caseStatusReadsTheDestinationOnlyWhereTheClausePrintsIt();
    caseRouteNextHopMovesTheOutboundActivity();
    caseRouterActivitySaturatesAtTheOctets();
    caseNeighborAgeCountsLinkStatusPeriods();
    caseNeighborTransmitFailureSaturatesAndClears();
    caseRouteInvalidateMovesEveryEntryThroughTheBrokenLink();
    caseCostLoopFreeIsThePrintedComparison();
    caseAddrClassesAtTheirBoundaries();
    caseAddrDutyFollowsTheDeviceType();

    return Test_Report();
}

/*
 * The six mutations this suite is written to catch, run against this file and named here because a mutation
 * that is not stated is a claim and not a proof.
 *
 * 1. `nwk_tx.c`, `Nwk_TxConfirmStatus`: drop the `ZB_ERR_AUTH` arm so a missing key falls through
 * to the sentinel. `caseTxConfirmStatusIsTable384sMapping` reddens on the NO_KEY 0xcd assertion and
 * on nothing else, and the `nwk`, `aps` and `interop` suites stay green: no fixture in this tree
 * runs out of a key on the way out, so the key arm of the mapping (the crossing the NWK layer owns)
 * is pinned here and nowhere else. The counter arm is pinned twice over, here and in the `nwk`
 * suite's exhausted-outgoing-counter case, which is stated as a fact about this table and not a gap
 * in it. 2. `nwk_rx.c`, `Nwk_RxForwardCopy`: loosen its buffer gate by one, truncate the payload to
 * what the caller's buffer holds instead of handing `npduMax` to the codec unchanged and taking the
 * refusal. `caseRxForwardCopyRefusesAndLeavesTheBufferUntouched` reddens three times over: the
 * ZB_ERR_NO_SPACE refusal becomes a success, the sentinel-filled buffer is found overwritten, and a
 * length is claimed for a frame the refusal was supposed not to produce. No pipeline case moves:
 * the façade's record and relay buffers are the 127-octet NPDU ceiling, which a frame this stack
 * composes never exceeds, so the only place a short buffer is offered to this body is the direct
 * call. That is the case this suite exists for: the record fill and `Nwk_RelayUnicast` both take
 * this body's answer as their `NWK_RELAY_FORWARD_COPY_FAILED`, and a relay that drops an octet to
 * fit a buffer puts a short frame on the air under a name the façade counts as a composition
 * failure. 3. `nwk_rx.c`, `Nwk_RxExamineParents`: mark 0x05 (unauthenticated child) where the
 * clause says 0x07. `caseRxExamineParentsMarksTheChildWhoseMessageArrivedThroughAnotherRadio`
 * reddens on the 0x07 assertion and on nothing else in this file, and the `nwk` suite reddens with
 * it on its two 3.6.2.3 cases, so this rule is pinned at both gates, which is what the 0x05 the
 * mutation writes makes visible: it is the value 4.3.1.2 step 8 waits for, so the mutation swaps
 * the two neighbor-table clauses for each other rather than merely changing a number. 4.
 * `nwk_cost.c`, `Nwk_CostFromLqa`: move Table 3-76's top bound by one (`192` written as `191`), so
 * an LQA of 192 answers cost 1 where the table prints cost 2.
 * `caseCostFromLqaIsTable376sEightLevels` reddens on the 192 assertion and on nothing else in the
 * file, and no other suite moves: nothing in the tree consumes a link cost yet, so the table's
 * edges are pinned here alone until RD2's route request is composed out of them. 5. `nwk_cost.c`,
 * `Nwk_CostCombine`: return `incoming` instead of the greater of the two, a mutation invisible to
 * the pipeline and visible only here, which is why the case is written with both orders:
 * 3.6.4.5.1.2's reading is symmetric, and a body that answers the incoming cost happens to be right
 * whenever the incoming direction is the worse one. `caseCostCombineTakesTheWorseDirection` reddens
 * on `(1, 4)` and `(0, 5)`: the incoming-worse order beside them stays green, which is the
 * measurement of what the mutation did. 6. `nwk_route.c`, `Nwk_RouteClaim`: evict the *highest*
 * TotalUsageCount instead of the lowest, 3.6.4.8's ranking read backwards.
 * `caseRouteClaimEvictsTheLowestTotalUsageCount` reddens on which slot came back and on the evicted
 * destination keeping its route, while `caseRouteClaimBreaksATieByTheOldestAge` stays green because
 * every count in it is equal: two cases, two rules, and the mutation separates them.
 */
