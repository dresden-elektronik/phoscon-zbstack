/* Suite for the three table modules band A's network layer keeps: `nwk_neighbor`, `nwk_route` and
   `nwk_btt`. Driven through those three headers and `Zb_memset` and
   nothing else: no `Nwk_Nwk`, no `Mac`, no radio, no config and no clock of its own. Every pool is a plain
   array the suite owns, exactly as the façade owns one array of each type as a named member, and every
   call hands that array in.

   What is asserted is the module's own contract and not the pipeline's use of it: which slot a lookup
   answers, which slot a claim takes, what a claim refuses, and what a record keeps when it is recycled. The
   three full-pool policies are named because they are the house's and are the ones a caller cannot see for
   itself: the neighbor table refuses with no eviction, the broadcast transaction table recycles an expired
   record before it refuses (3.6.6), and the route table's free-slot lookup refuses with no eviction, its
   `Nwk_RouteClaim` being the one operation that evicts, by TotalUsageCount (3.6.4.8). The claim's own cases
   are in the `nwk_modules` suite, beside the cost module its ranking shares a row with.

   Two rules here are pinned by mutation rather than by more cases, and both are named at the bottom of
   the file beside the change each one stands for. */

#include "nwk_btt.h"
#include "nwk_neighbor.h"
#include "nwk_route.h"
#include "test_harness.h"
#include "zb_utils.h"

enum
{
    OWN = 0x0000,                 /* an address the tables are never asked for, kept named so a miss is a miss */
    ADDR_A = 0x0042,
    ADDR_B = 0x0100,
    ADDR_C = 0x0200,
    ADDR_DEAD = 0x0300,           /* the address that lives in a slot nobody claimed */
    HOP = 0x0100,
    TTL_MS = 9000,                /* a record's life, named here because the record is filled by its owner:
                                     nwk_btt.h states no delivery time, and
                                     `NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS` is the façade's config
                                     number, not this module's */
    NOW_MS = 100000
};

#define IEEE_A 0x0123456789abcdef

/* The tables, as the suite owns them: plain arrays, zero-filled before each case, exactly the shape
   `Nwk_Nwk` embeds. */
static Nwk_NeighborTableEntry s_neighbors[NWK_NEIGHBOR_MAX];
static Nwk_RoutingTableEntry s_routes[NWK_ROUTE_MAX];
static Nwk_BroadcastTransactionRecord s_btt[NWK_BTT_MAX];

/* One neighbor, seeded the way only a suite can seed it: with a device type and a receiver duty no frame
   this stack has ever heard could state (Table 3-75). */
static Nwk_NeighborTableEntry *seedNeighbor(uint32_t slot, uint16_t addr, uint32_t deviceType,
                                  int rxOnWhenIdle, uint32_t relationship)
{
    s_neighbors[slot].inUse = 1;
    s_neighbors[slot].networkAddress = addr;
    s_neighbors[slot].deviceType = deviceType;
    s_neighbors[slot].rxOnWhenIdle = rxOnWhenIdle;
    s_neighbors[slot].relationship = relationship;

    return &s_neighbors[slot];
}

static Nwk_RoutingTableEntry *seedRoute(uint32_t slot, uint16_t dest, uint32_t status, uint16_t nextHop,
                            uint32_t ageMs)
{
    s_routes[slot].inUse = 1;
    s_routes[slot].destinationAddress = dest;
    s_routes[slot].status = status;
    s_routes[slot].nextHopAddress = nextHop;
    s_routes[slot].ageMs = ageMs;

    return &s_routes[slot];
}

/* One broadcast transaction record, filled the way the receive half fills it: the (source, sequence) key,
   the destination class, and an expiry computed by the owner of the record and not by this module. The
   stored frame and the relay count are written on purpose, so that a claim that recycles the slot can be
   seen to clear them. */
static Nwk_BroadcastTransactionRecord *seedRecord(uint32_t slot, uint16_t src, uint8_t seq, uint32_t expiryMs)
{
    s_btt[slot].inUse = 1;
    s_btt[slot].sourceAddress = src;
    s_btt[slot].sequenceNumber = seq;
    s_btt[slot].dst = ADDR_B;
    s_btt[slot].expiresAtMs = expiryMs;
    s_btt[slot].relayed = 1;
    s_btt[slot].nextRelayMs = expiryMs - 1;
    s_btt[slot].npduLen = 8;
    s_btt[slot].headerLen = 8;
    s_btt[slot].reprotect = 1;
    s_btt[slot].npdu[0] = 0xaa;
    s_btt[slot].npdu[7] = 0xbb;

    return &s_btt[slot];
}

/* --- nwk_neighbor --------------------------------------------------------------- */

static void caseNeighborEmptyTable(void)
{
    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    Test_Expect(Nwk_NeighborOf(s_neighbors, ADDR_A) == 0, "an empty table answers for no address");
    Test_Expect(Nwk_NeighborCount(s_neighbors) == 0, "and holds nothing");
    Test_Expect(Nwk_NeighborFree(s_neighbors) == &s_neighbors[0], "while every slot is free");
}

static void caseNeighborOfFindsASeededEntry(void)
{
    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    seedNeighbor(0, ADDR_A, NWK_NEIGHBOR_TYPE_UNKNOWN, 0, NWK_REL_NONE);
    seedNeighbor(1, ADDR_B, NWK_NEIGHBOR_TYPE_UNKNOWN, 1, NWK_REL_SIBLING);

    Test_Expect(Nwk_NeighborOf(s_neighbors, ADDR_B) == &s_neighbors[1],
           "the entry the table holds for that address is the entry it hands back");
    Test_Expect(Nwk_NeighborOf(s_neighbors, ADDR_C) == 0,
           "and an address it does not hold is not a neighbor (3.6.2.2, 3.6.4.3)");
}

/* An address written into a slot nobody claimed is not a neighbor: the lookup is over entries, not over
   the octets of a pool. This is the gate that makes a recycled slot inert before its owner fills it. */
static void caseNeighborOfDeclinesAnUnusedSlot(void)
{
    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    s_neighbors[2].inUse = 0;
    s_neighbors[2].networkAddress = ADDR_DEAD;

    Test_Expect(Nwk_NeighborOf(s_neighbors, ADDR_DEAD) == 0,
           "a slot that holds the address and claims no entry is not a neighbor");
    Test_Expect(Nwk_NeighborCount(s_neighbors) == 0, "and it is not counted");
}

/* Table 3-75 prints an Age field, 3.6.1.9 and 3.6.4.4.3.1 discuss ageing a router neighbor out, and band A
   has no such machinery: a full table refuses, and Table 3-84's NEIGHBOR_TABLE_FULL is the name the
   standard has for that refusal. */
static void caseNeighborFreeRefusesAFullTable(void)
{
    uint32_t i;

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
        seedNeighbor(i, (uint16_t)(ADDR_A + i), NWK_NEIGHBOR_TYPE_UNKNOWN, 0, NWK_REL_NONE);

    Test_Expect(Nwk_NeighborFree(s_neighbors) == 0, "a full table gives up no slot");
    Test_Expect(Nwk_NeighborOf(s_neighbors, (uint16_t)(ADDR_A + NWK_NEIGHBOR_MAX - 1)) == &s_neighbors[NWK_NEIGHBOR_MAX - 1],
           "and evicts nothing while it refuses: the entry it would have displaced is still there");
    Test_Expect(Nwk_NeighborCount(s_neighbors) == NWK_NEIGHBOR_MAX, "the refusal does not change the depth");
}

static void caseNeighborCountWalksThePool(void)
{
    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    seedNeighbor(0, ADDR_A, NWK_NEIGHBOR_TYPE_UNKNOWN, 0, NWK_REL_NONE);
    seedNeighbor(3, ADDR_B, NWK_NEIGHBOR_TYPE_UNKNOWN, 1, NWK_REL_CHILD);
    seedNeighbor(NWK_NEIGHBOR_MAX - 1, ADDR_C, NWK_NEIGHBOR_TYPE_UNKNOWN, 0, NWK_REL_LOST_CHILD);

    Test_Expect(Nwk_NeighborCount(s_neighbors) == 3,
           "the count walks the whole pool and not up to the last hole");

    s_neighbors[3].inUse = 0;

    Test_Expect(Nwk_NeighborCount(s_neighbors) == 2, "and drops an entry the moment its slot is released");
    Test_Expect(Nwk_NeighborFree(s_neighbors) == &s_neighbors[1],
           "and the claim takes the first unused slot of the pool, not the one a caller just released");
}

/* What a claim and a fill produce, read back through the lookup: every field the entry states, stated
   still. The device type is the one this module can name for an entry it made from an address it heard:
   the three printed types arrive with configuration and association, which is why they are `Nwk_Config`'s
   vocabulary and not this table's. */
static void caseNeighborRoundTrip(void)
{
    Nwk_NeighborTableEntry *neighbor;

    Zb_memset(s_neighbors, 0, (uint32_t)sizeof s_neighbors);

    neighbor = Nwk_NeighborFree(s_neighbors);
    Test_Expect(neighbor != 0, "an empty table has room");

    neighbor->inUse = 1;
    neighbor->networkAddress = ADDR_B;
    neighbor->extendedAddress = IEEE_A;
    neighbor->ieeeKnown = 1;
    neighbor->deviceType = NWK_NEIGHBOR_TYPE_UNKNOWN;
    neighbor->rxOnWhenIdle = 1;
    neighbor->relationship = NWK_REL_UNAUTHENTICATED_CHILD;
    neighbor->ageFromMs = NOW_MS;

    neighbor = Nwk_NeighborOf(s_neighbors, ADDR_B);
    Test_Expect(neighbor == &s_neighbors[0], "the entry a claim filled is the entry the lookup finds");

    if (neighbor == 0)
        return;

    Test_Expect(neighbor->inUse == 1 && neighbor->networkAddress == ADDR_B, "the key survives");
    Test_Expect(neighbor->extendedAddress == IEEE_A && neighbor->ieeeKnown == 1, "the extended address 3.3.1.7 can bring (Table 3-75)");
    Test_Expect(neighbor->deviceType == NWK_NEIGHBOR_TYPE_UNKNOWN && neighbor->rxOnWhenIdle == 1,
           "the type the module claims for an observed entry, and the receiver duty it was told");
    Test_Expect(neighbor->relationship == NWK_REL_UNAUTHENTICATED_CHILD,
           "the relationship code Table 3-75 prints, 0x05, which is the one 4.3.1.2 step 8 looks for");
    Test_Expect(neighbor->ageFromMs == NOW_MS, "and the age");
}

/* --- nwk_route ------------------------------------------------------------------ */

static void caseRouteEmptyTable(void)
{
    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);

    Test_Expect(Nwk_RouteOf(s_routes, ADDR_A) == 0, "an empty route table aims nothing");
    Test_Expect(Nwk_RouteCount(s_routes) == 0, "and holds nothing");
    Test_Expect(Nwk_RouteFree(s_routes) == &s_routes[0], "while every slot is free");
}

static void caseRouteOfFindsASeededEntry(void)
{
    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);

    seedRoute(0, ADDR_A, NWK_ROUTE_INACTIVE, HOP, 10);
    seedRoute(2, ADDR_B, NWK_ROUTE_ACTIVE, HOP, 20);

    Test_Expect(Nwk_RouteOf(s_routes, ADDR_B) == &s_routes[2],
           "the entry for that destination (3.6.4.3's first choice, read before any neighbor entry)");
    Test_Expect(Nwk_RouteOf(s_routes, ADDR_C) == 0, "and no entry for a destination it does not hold");

    s_routes[1].inUse = 0;
    s_routes[1].destinationAddress = ADDR_DEAD;

    Test_Expect(Nwk_RouteOf(s_routes, ADDR_DEAD) == 0,
           "and an unused slot is not a route whatever its destination field says");
}

static void caseRouteFreeRefusesAFullTable(void)
{
    Nwk_RoutingTableEntry *oldest;
    uint32_t i;

    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);

    for (i = 0; i < NWK_ROUTE_MAX; i++)
        seedRoute(i, (uint16_t)(ADDR_A + i), NWK_ROUTE_ACTIVE, (uint16_t)(ADDR_A + i), 10);

    Test_Expect(Nwk_RouteFree(s_routes) == 0, "a full route table gives up no slot, and displaces no route");
    Test_Expect(Nwk_RouteCount(s_routes) == NWK_ROUTE_MAX, "which is the refusal-and-count of a pool with no size in the standard");

    oldest = Nwk_RouteOf(s_routes, ADDR_A);
    Test_Expect(oldest != 0 && oldest->status == NWK_ROUTE_ACTIVE,
           "and the oldest entry is untouched by the refusal");
}

static void caseRouteCountWalksThePool(void)
{
    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);

    seedRoute(0, ADDR_A, NWK_ROUTE_ACTIVE, HOP, 10);
    seedRoute(7, ADDR_B, NWK_ROUTE_DISCOVERY_FAILED, HOP, 20);
    seedRoute(NWK_ROUTE_MAX - 1, ADDR_C, NWK_ROUTE_INACTIVE, HOP, 30);

    Test_Expect(Nwk_RouteCount(s_routes) == 3, "the count is the whole pool walked, at any slot");

    s_routes[7].inUse = 0;

    Test_Expect(Nwk_RouteCount(s_routes) == 2, "and an entry released is a slot free");
    Test_Expect(Nwk_RouteFree(s_routes) == &s_routes[1],
           "and the claim takes the first unused slot of the pool, not the one a caller just released");
}

/* Table 3-78's printed numbers, asserted as numbers: ACTIVE 0x0, DISCOVERY_UNDERWAY 0x1, DISCOVERY_FAILED
   0x2, INACTIVE 0x3, all four of them, because the hole at 0x1 is closed again: 3.6.4.5.1
   creates an entry carrying DISCOVERY_UNDERWAY, 3.6.4.5.2 changes it to ACTIVE and 3.6.4.5.1.7 deletes an
   entry that still carries it. */
static void caseRouteStatusesAreTable378sNumbers(void)
{
    Nwk_RoutingTableEntry *route;

    Zb_memset(s_routes, 0, (uint32_t)sizeof s_routes);

    Test_Expect(NWK_ROUTE_ACTIVE == 0x0 && NWK_ROUTE_DISCOVERY_UNDERWAY == 0x1
           && NWK_ROUTE_DISCOVERY_FAILED == 0x2 && NWK_ROUTE_INACTIVE == 0x3,
           "the four statuses carry the numbers Table 3-78 prints");
    Test_Expect(NWK_ROUTE_DISCOVERY_UNDERWAY != NWK_ROUTE_ACTIVE,
           "and 0x1 is a status of its own again: the status a device in the middle of a route discovery sets is not the status of a route it can use (3.6.4.5.1)");

    route = Nwk_RouteFree(s_routes);
    Test_Expect(route != 0, "an empty table has room");

    route->inUse = 1;
    route->destinationAddress = ADDR_B;
    route->status = NWK_ROUTE_ACTIVE;
    route->nextHopAddress = HOP;
    route->ageMs = NOW_MS;

    route = Nwk_RouteOf(s_routes, ADDR_B);
    Test_Expect(route == &s_routes[0], "the route a claim filled is the route the lookup finds");

    if (route == 0)
        return;

    Test_Expect(route->status == NWK_ROUTE_ACTIVE && route->nextHopAddress == HOP && route->ageMs == NOW_MS,
           "and its status, its next hop and its age come back as they were written (Table 3-77)");
}

/* --- nwk_btt -------------------------------------------------------------------- */

static void caseBttOfFindsALiveRecord(void)
{
    Zb_memset(s_btt, 0, (uint32_t)sizeof s_btt);

    Test_Expect(Nwk_BttOf(s_btt, OWN, 1) == 0, "an empty table has no record of any frame");
    Test_Expect(Nwk_BttCount(s_btt) == 0, "and holds nothing");

    seedRecord(4, ADDR_A, 7, NOW_MS + TTL_MS);

    Test_Expect(Nwk_BttOf(s_btt, ADDR_A, 7) == &s_btt[4],
           "the record keyed on that source address and that sequence number (3.6.6)");
    Test_Expect(Nwk_BttOf(s_btt, ADDR_A, 8) == 0, "while the same source at another sequence number is a different frame");
    Test_Expect(Nwk_BttOf(s_btt, ADDR_B, 7) == 0, "and a different source is one too");
}

/* Live-or-expired precedence, in both of the readings it has. 3.6.6's comparison is "the sequence number
 * and the source address of the broadcast frame with the records in its BTT" and nothing about a record's
 * age: the age decides whether a slot may be overwritten, which is the claim's question and not this one.
 * And the scan is first-match-wins: a table this module never dedups can hold two slots claiming one key,
 * and the earlier slot is the record it answers with, which is the slot an expiry has already aged out. */
static void caseBttOfFindsAnExpiredRecord(void)
{
    Zb_memset(s_btt, 0, (uint32_t)sizeof s_btt);

    seedRecord(2, ADDR_A, 40, NOW_MS - 1);

    Test_Expect(Nwk_BttOf(s_btt, ADDR_A, 40) == &s_btt[2],
           "a record past its delivery time is still the record of that frame until something overwrites it");

    seedRecord(9, ADDR_A, 40, NOW_MS + TTL_MS);

    Test_Expect(Nwk_BttOf(s_btt, ADDR_A, 40) == &s_btt[2],
           "and with two slots claiming one key, the first the table holds answers, aged or not");
}

/* The free scan runs before the expired scan, which is the order 3.6.6 prints: a table with an unused slot
   has a record to fill and has no reason to touch one that is still holding a frame. */
static void caseBttClaimTakesAFreeSlotBeforeAnExpiredOne(void)
{
    Nwk_BroadcastTransactionRecord *slot;

    Zb_memset(s_btt, 0, (uint32_t)sizeof s_btt);

    seedRecord(0, ADDR_A, 1, NOW_MS - 1);          /* already expired, and still holding its frame */
    Test_Expect(Nwk_BttCount(s_btt) == 1, "one record held");

    slot = Nwk_BttClaim(s_btt, NOW_MS);

    Test_Expect(slot == &s_btt[1], "the claim takes the unused slot, not the expired one");
    Test_Expect(s_btt[0].npduLen == 8 && s_btt[0].relayed == 1 && s_btt[0].npdu[0] == 0xaa,
           "and the aged record keeps the frame a neighbor may still need from it");
    Test_Expect(Nwk_BttCount(s_btt) == 1, "and a claim only offers a slot: holding a record is the fill that follows it");

    slot->inUse = 1;
    slot->sourceAddress = ADDR_C;
    slot->sequenceNumber = 20;
    slot->expiresAtMs = NOW_MS + TTL_MS;

    Test_Expect(Nwk_BttCount(s_btt) == 2, "and the record its caller filled is then held");
}

/* With no free slot, the claim recycles a record that has aged past its delivery time ("The entry status
   SHOULD change to expired and thus the entry can be overwritten if required when a new broadcast is
   received") and it recycles the *least*-expired of them, which is the one whose frame was delivered
   longest ago. The slot comes back empty: a record that inherited the previous occupant's stored frame or
   relay count would retransmit a broadcast it is not a record of. */
static void caseBttClaimRecyclesTheLeastExpiredRecord(void)
{
    Nwk_BroadcastTransactionRecord *slot;
    uint32_t i;

    Zb_memset(s_btt, 0, (uint32_t)sizeof s_btt);

    for (i = 0; i < NWK_BTT_MAX; i++)
        seedRecord(i, (uint16_t)(ADDR_A + i), (uint8_t)(10 + i), NOW_MS + TTL_MS);

    s_btt[5].expiresAtMs = NOW_MS - 1;        /* expired a millisecond ago: the most recent loss */
    s_btt[9].expiresAtMs = NOW_MS - 4000;     /* expired, and the middle candidate */
    s_btt[14].expiresAtMs = 1;                /* expired first of all, parked at the end of the pool */

    Test_Expect(Nwk_BttCount(s_btt) == NWK_BTT_MAX, "a full table ages out, and has no free slot to offer instead");

    slot = Nwk_BttClaim(s_btt, NOW_MS);

    Test_Expect(slot == &s_btt[14], "the least-expired record is the one overwritten (3.6.6)");
    Test_Expect(s_btt[5].expiresAtMs == NOW_MS - 1 && s_btt[5].npduLen == 8 && s_btt[5].relayed == 1,
           "and the record that aged most recently is left exactly as it was");
    Test_Expect(s_btt[9].expiresAtMs == NOW_MS - 4000 && s_btt[9].npdu[0] == 0xaa,
           "and so is the candidate in between");
    Test_Expect(s_btt[0].expiresAtMs == NOW_MS + TTL_MS && s_btt[0].npdu[0] == 0xaa && s_btt[0].relayed == 1,
           "and a live record is no candidate at all");

    Test_Expect(slot->inUse == 0 && slot->sourceAddress == 0 && slot->sequenceNumber == 0 && slot->dst == 0 && slot->expiresAtMs == 0
           && slot->relayed == 0 && slot->nextRelayMs == 0 && slot->npduLen == 0 && slot->headerLen == 0
           && slot->reprotect == 0 && slot->npdu[0] == 0 && slot->npdu[7] == 0,
           "the recycled slot comes back cleared, so its next occupant inherits no frame, no counter and no due time");
    Test_Expect(Nwk_BttCount(s_btt) == NWK_BTT_MAX - 1,
           "and a recycle hands over an emptied slot, which is one record fewer until the fill arrives");

    slot->inUse = 1;
    slot->sourceAddress = ADDR_C;
    slot->sequenceNumber = 40;
    slot->expiresAtMs = NOW_MS + TTL_MS;

    Test_Expect(Nwk_BttCount(s_btt) == NWK_BTT_MAX, "and refilled, the table is full again: a recycle is not a shrinking");
}

/* "If, on receipt of a broadcast frame, the NWK layer finds that the BTT is full and contains no expired
   entries, then the frame SHOULD be dropped. In this situation the frame SHOULD NOT be retransmitted, nor
   SHOULD it be passed up to the next higher layer": the claim is the refusal, and it refuses without
   disturbing one record. */
static void caseBttClaimRefusesAFullLiveTable(void)
{
    uint32_t i;

    Zb_memset(s_btt, 0, (uint32_t)sizeof s_btt);

    for (i = 0; i < NWK_BTT_MAX; i++)
        seedRecord(i, (uint16_t)(ADDR_A + i), (uint8_t)(20 + i), NOW_MS + TTL_MS);

    Test_Expect(Nwk_BttClaim(s_btt, NOW_MS) == 0, "a full table of live records claims nothing");
    Test_Expect(Nwk_BttCount(s_btt) == NWK_BTT_MAX, "and nothing aged out or was dropped to make room");

    for (i = 0; i < NWK_BTT_MAX; i++)
    {
        if (s_btt[i].npduLen != 8 || s_btt[i].relayed != 1)
            break;
    }

    Test_Expect(i == NWK_BTT_MAX, "every record still holds the frame it is a record of");
}

/* The boundary the module actually decides, in the caller's own arithmetic: a record is live while
   nowMs < expiresAtMs, and expiresAtMs is nowMs + the delivery time the fill chose. One millisecond short of
   that sum the table is full and refuses; on it, the record has aged and its slot is the one on offer. */
static void caseBttExpiryBoundaryIsTheCallsOwn(void)
{
    uint32_t i;

    Zb_memset(s_btt, 0, (uint32_t)sizeof s_btt);

    for (i = 0; i < NWK_BTT_MAX; i++)
        seedRecord(i, (uint16_t)(ADDR_A + i), (uint8_t)(30 + i), NOW_MS + TTL_MS);

    Test_Expect(Nwk_BttClaim(s_btt, NOW_MS + TTL_MS - 1) == 0,
           "one millisecond inside the delivery time, every record is live and the table is full");
    Test_Expect(Nwk_BttCount(s_btt) == NWK_BTT_MAX, "and nothing was aged out early");

    Test_Expect(Nwk_BttClaim(s_btt, NOW_MS + TTL_MS) == &s_btt[0],
           "at the delivery time the records have expired and a slot is offered");
    Test_Expect(Nwk_BttCount(s_btt) == NWK_BTT_MAX - 1,
           "and the table is one record short of full, which is a recycle and not a shrinking");
}

/* The record a broadcast this device originates claims (3.6.6, Table 3-81): opened under its own key, the
   class it was aimed at and the window the caller passed; with no stored frame, a retransmission is
   what a record of somebody else's broadcast is for. The key is the table's, so opening it twice is one
   record rewritten and not two. */
static void caseBttOpenClaimsAKeyOfItsOwn(void)
{
    Nwk_BroadcastTransactionRecord *record;

    Zb_memset(s_btt, 0, (uint32_t)sizeof s_btt);

    record = Nwk_BttOpen(s_btt, OWN, 3, ADDR_B, NOW_MS, NOW_MS + TTL_MS);

    Test_Expect(record == &s_btt[0] && record->inUse == 1, "an empty table offers its first slot");
    Test_Expect(record->sourceAddress == OWN && record->sequenceNumber == 3, "keyed on the source address and the sequence number Table 3-81 prints");
    Test_Expect(record->dst == ADDR_B && record->expiresAtMs == NOW_MS + TTL_MS,
           "with the class it was aimed at and the expiry its caller computed");
    Test_Expect(record->npduLen == 0 && record->relayed == 0 && record->nextRelayMs == 0,
           "and no frame and no relay count, so the retransmission pass has nothing of this record to re-offer");
    Test_Expect(Nwk_BttCount(s_btt) == 1, "one record held");

    record = Nwk_BttOpen(s_btt, OWN, 3, ADDR_C, NOW_MS + 1, NOW_MS + 1 + TTL_MS);

    Test_Expect(Nwk_BttCount(s_btt) == 1 && record == &s_btt[0],
           "the same key opened again rewrites the record it already has rather than claiming a second slot");
    Test_Expect(record->dst == ADDR_C && record->expiresAtMs == NOW_MS + 1 + TTL_MS,
           "and the rewrite carries the class and the window of the broadcast that made it");
}

/* The refusal, and it is not the send's: a window is bookkeeping, so a table with nothing to give answers 0
   and leaves every record where it was, the caller sends its broadcast unrecorded rather than not at all. */
static void caseBttOpenRefusesAFullLiveTable(void)
{
    Nwk_BroadcastTransactionRecord *record;
    uint32_t i;

    Zb_memset(s_btt, 0, (uint32_t)sizeof s_btt);

    for (i = 0; i < NWK_BTT_MAX; i++)
        seedRecord(i, (uint16_t)(ADDR_A + i), (uint8_t)(60 + i), NOW_MS + TTL_MS);

    record = Nwk_BttOpen(s_btt, OWN, 4, ADDR_B, NOW_MS, NOW_MS + TTL_MS);

    Test_Expect(record == 0, "a full table with nothing expired has no record to give the broadcast");
    Test_Expect(Nwk_BttCount(s_btt) == NWK_BTT_MAX, "and nothing was evicted to make room for it");
    Test_Expect(s_btt[0].npdu[0] == 0xaa && s_btt[0].relayed == 1,
           "every record still holds the frame it is a record of");

    s_btt[NWK_BTT_MAX - 1].expiresAtMs = NOW_MS - 1;

    record = Nwk_BttOpen(s_btt, OWN, 4, ADDR_B, NOW_MS, NOW_MS + TTL_MS);

    Test_Expect(record == &s_btt[NWK_BTT_MAX - 1],
           "while a record that has aged is the slot it takes: 3.6.6 makes an expired entry overwritable");
    Test_Expect(record->npduLen == 0 && record->relayed == 0 && record->sourceAddress == OWN && record->sequenceNumber == 4,
           "and it comes back as this broadcast's record and not the previous occupant's");
}

/*
 * 3.6.6's passive acknowledgement, at the only place a record can hold it: a neighbour's copy of a broadcast the
 * record already stands for is the evidence that the frame went on, and the mark answers once so the caller counts
 * one acknowledgement rather than one per copy of a flood.
 */
static void caseBttMarkRelayedAnswersOnce(void)
{
    Nwk_BroadcastTransactionRecord *record;

    Zb_memset(s_btt, 0, (uint32_t)sizeof s_btt);

    seedRecord(0, ADDR_A, 7, NOW_MS + TTL_MS);

    Test_Expect(s_btt[0].relayedByNeighbor == 0, "a record of a frame nobody has relayed carries no acknowledgement");
    Test_Expect(Nwk_BttMarkRelayed(&s_btt[0]) == 1, "the first neighbour heard to relay it sets the mark");
    Test_Expect(s_btt[0].relayedByNeighbor == 1, "3.6.6's MAY, an optional mark and the only evidence a broadcast went on");
    Test_Expect(Nwk_BttMarkRelayed(&s_btt[0]) == 0, "a second copy answers 0: one acknowledgement, however many neighbours repeat it");
    Test_Expect(Nwk_BttMarkRelayed(0) == 0, "and no record at all is nothing to mark");

    record = Nwk_BttOpen(s_btt, OWN, 9, ADDR_B, NOW_MS, NOW_MS + TTL_MS);

    Test_Expect(record != 0 && record->relayedByNeighbor == 0,
           "a record a device opens for its own broadcast starts unmarked: no neighbour has relayed it yet");
}

int main(void)
{
    Test_Begin("nwk_tables");

    caseNeighborEmptyTable();
    caseNeighborOfFindsASeededEntry();
    caseNeighborOfDeclinesAnUnusedSlot();
    caseNeighborFreeRefusesAFullTable();
    caseNeighborCountWalksThePool();
    caseNeighborRoundTrip();
    caseRouteEmptyTable();
    caseRouteOfFindsASeededEntry();
    caseRouteFreeRefusesAFullTable();
    caseRouteCountWalksThePool();
    caseRouteStatusesAreTable378sNumbers();
    caseBttOfFindsALiveRecord();
    caseBttOfFindsAnExpiredRecord();
    caseBttClaimTakesAFreeSlotBeforeAnExpiredOne();
    caseBttClaimRecyclesTheLeastExpiredRecord();
    caseBttClaimRefusesAFullLiveTable();
    caseBttExpiryBoundaryIsTheCallsOwn();
    caseBttOpenClaimsAKeyOfItsOwn();
    caseBttOpenRefusesAFullLiveTable();
    caseBttMarkRelayedAnswersOnce();

    return Test_Report();
}

/*
 * The two mutations this suite is written to catch, run against this file and named here because a
 * mutation that is not stated is a claim and not a proof.
 *
 * 1. `nwk_btt.c`, the lookup's precedence: hold the match in a local and return the
 * last one the scan reaches instead of returning the first. The aged record stops
 * being the one the lookup answers with (the live slot that shadows it wins) and
 * `caseBttOfFindsAnExpiredRecord` reddens, on the assertion that names what 3.6.6's
 * comparison answers with. The pipeline suites do not see this mutation: the receive
 * half never stores two records under one key today, which is exactly why the table is
 * asserted at the table. 2. `nwk_btt.c`, the recycle's choice: `record->expiresAtMs >
 * expired->expiresAtMs` instead of `<`. The claim then takes the *most* recently expired
 * record, and `caseBttClaimRecyclesTheLeastExpiredRecord` reddens, on both the identity of the
 * slot on offer and the survival of the record that aged last. Again no pipeline case moves.
 */
