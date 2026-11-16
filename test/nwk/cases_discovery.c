/* Table 3-79's route discovery table, driven as a plain array: the key lookup 3.6.4.2 leaves to the
   implementer, the claim the transient table's reuse sentence allows, the depth, and the two deletions
   3.6.4.5.1.7's timer makes. No `Nwk_Nwk`, no radio and no clock: every `nowMs` is a number a case chose, and
   the pool is the case's own stack. */

#include "nwk_routedisc_cases.h"

#include "nwk_discovery.h"
#include "nwk_routedisc_helpers.h"
#include "test_harness.h"
#include "zb_utils.h"

enum
{
    NOW_MS = 100000,
    AUTHORITY = 0x0a11,             /* the initiator whose key every case starts from */
    SENDER = 0x0100,
    REQUEST_ID = 0x21,
    OTHER_ID = 0x22
};

static Nwk_RouteDiscoveryTableEntry s_pool[NWK_DISCOVERY_MAX];

void caseDiscoveryClaimFindAndCount(void)
{
    Nwk_RouteDiscoveryTableEntry *first;
    Nwk_RouteDiscoveryTableEntry *second;

    Zb_memset(s_pool, 0, (uint32_t)sizeof s_pool);

    Test_Expect(Nwk_DiscoveryOf(s_pool, AUTHORITY, REQUEST_ID) == 0, "an empty table answers for no key");
    Test_ExpectCount(Nwk_DiscoveryCount(s_pool), 0, "and holds nothing");

    first = Nwk_DiscoveryClaim(s_pool, NOW_MS);

    Test_Expect(first == &s_pool[0], "the first claim takes the first slot");

    first->inUse = 1;
    first->sourceAddress = AUTHORITY;
    first->routeRequestId = REQUEST_ID;
    first->senderAddress = SENDER;
    first->expiresAtMs = NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS;

    Test_Expect(Nwk_DiscoveryOf(s_pool, AUTHORITY, REQUEST_ID) == first, "the key finds the entry it names");
    Test_Expect(Nwk_DiscoveryOf(s_pool, AUTHORITY, OTHER_ID) == 0, "and no other request id does");

    second = Nwk_DiscoveryClaim(s_pool, NOW_MS);

    Test_Expect(second == &s_pool[1], "a second key takes a second slot");
    Test_ExpectCount(Nwk_DiscoveryCount(s_pool), 1, "the depth counts the slots in use");

    Test_ExpectCount(NWK_ROUTE_DISCOVERY_TIME_MS, 10000,
                     "nwkcRouteDiscoveryTime is 0x2710 msec at 2.4 GHz (Table 3-65)");
}

void caseDiscoverySameKeyAnswersOneSlot(void)
{
    Nwk_RouteDiscoveryTableEntry *first;
    Nwk_RouteDiscoveryTableEntry *other;

    Zb_memset(s_pool, 0, (uint32_t)sizeof s_pool);

    first = seedDiscovery(s_pool, 0, AUTHORITY, REQUEST_ID, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);
    other = seedDiscovery(s_pool, 1, AUTHORITY, OTHER_ID, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    Test_Expect(Nwk_DiscoveryOf(s_pool, AUTHORITY, REQUEST_ID) == first,
                "3.6.4.5.1.2: the pair the procedure compares answers one entry");
    Test_Expect(Nwk_DiscoveryOf(s_pool, AUTHORITY, OTHER_ID) == other,
                "and a request id one higher is another discovery");
    Test_ExpectCount(Nwk_DiscoveryCount(s_pool), 2, "two keys, two entries");
}

void caseDiscoveryExpiresAtThePrintedTime(void)
{
    Nwk_RouteDiscoveryTableEntry *record;
    uint32_t deadline = NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS;

    Zb_memset(s_pool, 0, (uint32_t)sizeof s_pool);

    record = seedDiscovery(s_pool, 0, AUTHORITY, REQUEST_ID, deadline);

    Test_ExpectCount(Nwk_DiscoveryExpire(s_pool, deadline - 1), 0, "not one millisecond before the printed time");
    Test_ExpectCount(record->inUse, 1, "the entry is still there");
    Test_Expect(Nwk_DiscoveryOf(s_pool, AUTHORITY, REQUEST_ID) == record, "and still answers its key");

    Test_ExpectCount(Nwk_DiscoveryExpire(s_pool, deadline), 1, "3.6.4.5.1.7: the timer's own instant expires it");
    Test_ExpectCount(record->inUse, 0, "the slot is released");
    Test_Expect(Nwk_DiscoveryOf(s_pool, AUTHORITY, REQUEST_ID) == 0, "and answers no key");
    Test_ExpectCount(Nwk_DiscoveryCount(s_pool), 0, "the depth follows");
    Test_ExpectCount(record->routeRequestId, REQUEST_ID, "the released record still says what it was");
}

void caseDiscoveryReclaimsAnExpiredSlot(void)
{
    Nwk_RouteDiscoveryTableEntry *slot;
    uint32_t i;

    Zb_memset(s_pool, 0, (uint32_t)sizeof s_pool);

    for (i = 0; i < NWK_DISCOVERY_MAX; i++)
    {
        seedDiscovery(s_pool, i, (uint16_t)(AUTHORITY + i), REQUEST_ID,
                      NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);
    }

    s_pool[3].expiresAtMs = NOW_MS - 1;
    s_pool[6].expiresAtMs = NOW_MS - 500;

    slot = Nwk_DiscoveryClaim(s_pool, NOW_MS);

    Test_Expect(slot == &s_pool[6], "the expired entry with the smallest expiration is the one recycled");
    Test_ExpectCount(slot->inUse, 0, "the recycled slot is handed over released");
    Test_ExpectCount(slot->sourceAddress, 0, "and empty, so no key it never held answers through it");
    Test_ExpectCount(Nwk_DiscoveryCount(s_pool), NWK_DISCOVERY_MAX - 1, "the other seven stand");
    Test_Expect(Nwk_DiscoveryOf(s_pool, AUTHORITY + 3, REQUEST_ID) == &s_pool[3],
                "3.6.4.2: a claim recycles one expired entry, not every one of them");

    slot->inUse = 1;
    slot->sourceAddress = AUTHORITY + 6;
    slot->routeRequestId = OTHER_ID;

    Test_Expect(Nwk_DiscoveryOf(s_pool, AUTHORITY + 6, OTHER_ID) == slot, "and the recycled slot answers its new key");
}

void caseDiscoveryFullPoolRefusesTheNinth(void)
{
    Nwk_RouteDiscoveryTableEntry *slot;
    uint32_t claimed = 0;
    uint32_t i;

    Zb_memset(s_pool, 0, (uint32_t)sizeof s_pool);

    for (i = 0; i < NWK_DISCOVERY_MAX; i++)
    {
        slot = Nwk_DiscoveryClaim(s_pool, NOW_MS);

        if (slot == 0)
            continue;

        slot->inUse = 1;
        slot->sourceAddress = (uint16_t)(AUTHORITY + i);
        slot->routeRequestId = (uint8_t)(REQUEST_ID + i);
        slot->expiresAtMs = NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS;
        claimed++;
    }

    Test_ExpectCount(claimed, NWK_DISCOVERY_MAX, "eight live entries fill the pool");
    Test_ExpectCount(Nwk_DiscoveryCount(s_pool), NWK_DISCOVERY_MAX, "and the depth says so");
    Test_Expect(Nwk_DiscoveryClaim(s_pool, NOW_MS) == 0, "a ninth claim is refused, and evicts nothing");
    Test_ExpectCount(Nwk_DiscoveryCount(s_pool), NWK_DISCOVERY_MAX, "with every entry still there");

    Test_ExpectCount(Nwk_DiscoveryExpire(s_pool, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS), NWK_DISCOVERY_MAX,
                     "and all eight expire at the printed time");
}

void caseDiscoveryRemoveDeletesByKey(void)
{
    Nwk_RouteDiscoveryTableEntry *record;
    Nwk_RouteDiscoveryTableEntry *removed;

    Zb_memset(s_pool, 0, (uint32_t)sizeof s_pool);

    record = seedDiscovery(s_pool, 0, AUTHORITY, REQUEST_ID, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);
    seedDiscovery(s_pool, 1, AUTHORITY, OTHER_ID, NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS);

    removed = Nwk_DiscoveryRemove(s_pool, AUTHORITY, REQUEST_ID);

    Test_Expect(removed == record, "the removal answers the record it deleted");
    Test_ExpectCount(removed->senderAddress, SENDER, "3.6.4.5.6: with what the entry held, for the report");
    Test_ExpectCount(record->inUse, 0, "and the slot released");
    Test_Expect(Nwk_DiscoveryOf(s_pool, AUTHORITY, REQUEST_ID) == 0, "the key answers nothing afterwards");
    Test_ExpectCount(Nwk_DiscoveryCount(s_pool), 1, "the other discovery stands");
    Test_Expect(Nwk_DiscoveryOf(s_pool, AUTHORITY, OTHER_ID) != 0, "by its own key");
    Test_Expect(Nwk_DiscoveryRemove(s_pool, AUTHORITY, REQUEST_ID) == 0, "and a second removal of it deletes nothing");
}

/*
 * 3.6.4.3's own question to this table: "If the device has a routing table entry corresponding to the routing
 * destination of the frame but the value of the route status field for that entry is DISCOVERY_UNDERWAY, the
 * device SHALL determine if it initiated the discovery by consulting its discovery table." That question is a
 * pair (the initiator and the destination) and not Table 3-79's key, because the request id a second frame
 * would be numbered with has not been spent yet.
 */
void caseDiscoveryRunningAnswersForAnInitiatorAndADestination(void)
{
    Nwk_RouteDiscoveryTableEntry *first;

    Zb_memset(s_pool, 0, (uint32_t)sizeof s_pool);

    Test_Expect(Nwk_DiscoveryRunning(s_pool, AUTHORITY, SENDER) == 0, "an empty table runs no discovery for anybody");

    first = Nwk_DiscoveryClaim(s_pool, NOW_MS);

    first->inUse = 1;
    first->sourceAddress = AUTHORITY;
    first->routeRequestId = REQUEST_ID;
    first->senderAddress = SENDER;
    first->destAddr = SENDER;
    first->expiresAtMs = NOW_MS + NWK_ROUTE_DISCOVERY_TIME_MS;

    Test_Expect(Nwk_DiscoveryRunning(s_pool, AUTHORITY, SENDER) == first,
                "the entry this initiator is running for that destination is the one the question answers");
    Test_Expect(Nwk_DiscoveryRunning(s_pool, AUTHORITY, OTHER_ID) == 0,
                "and another destination is another discovery, whatever slot it would land in");
    Test_Expect(Nwk_DiscoveryRunning(s_pool, SENDER, SENDER) == 0,
                "nor does another initiator's discovery answer for this one: the question is the initiator's own");

    first->inUse = 0;

    Test_Expect(Nwk_DiscoveryRunning(s_pool, AUTHORITY, SENDER) == 0,
                "and a released entry runs nothing: the pair is answered over live slots only");
}
