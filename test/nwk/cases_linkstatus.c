/* 3.4.8's link status command, the two metrics 3.6.4.4.2 derives from it, and 3.6.4.4.3's ranking: the rank
   formula, the assessment pool, the removal that makes room and the promotion to backbone mesh sibling. */

#include "nwk_cases.h"
#include "nwk_cost.h"
#include "nwk_helpers.h"
#include "nwk_linkstatus.h"
#include "test_harness.h"
#include "zb_utils.h"

/* Figure 3-19's payload: the options octet with the frame bits asked for, then `count` entries whose addresses run
   from 0x1000 upward and whose status octets the caller writes. */
static uint32_t linkStatusPayload(uint8_t *out, uint32_t count, int first, int last)
{
    uint32_t len = 1;
    uint32_t i;

    out[0] = (uint8_t)(count & 0x1f);

    if (first)
        out[0] = (uint8_t)(out[0] | NWK_LINK_STATUS_OPTIONS_FIRST);

    if (last)
        out[0] = (uint8_t)(out[0] | NWK_LINK_STATUS_OPTIONS_LAST);

    for (i = 0; i < count; i++)
    {
        out[len] = (uint8_t)((0x1000 + i) & 0xff);
        out[len + 1] = (uint8_t)(((0x1000 + i) >> 8) & 0xff);
        out[len + 2] = 0x00;
        len += 3;
    }

    return len;
}

/* Where a link status's command identifier sits in an unsecured NPDU: Figure 3-4's eight octets, then 3.4.8.2's source
   IEEE address. */
#define LINK_STATUS_NPDU_COMMAND 16

static Nwk_NeighborTableEntry *neighborSlot(Nwk_NeighborTableEntry *pool, uint32_t index)
{
    Nwk_NeighborTableEntry *entry = &pool[index];

    Zb_memset(entry, 0, (uint32_t)sizeof *entry);

    return entry;
}

void caseLinkStatusMetrics(void)
{
    Nwk_NeighborTableEntry pool[NWK_NEIGHBOR_MAX];
    Nwk_LinkStatus list;
    uint8_t payload[1 + 3 * 4];
    uint32_t len;
    uint32_t i;

    Zb_memset(pool, 0, (uint32_t)sizeof pool);
    Zb_memset(payload, 0, (uint32_t)sizeof payload);

    len = linkStatusPayload(payload, 2, 1, 1);
    payload[3] = 0x12;      /* 0x1000: incoming 2, outgoing 1 */
    payload[6] = 0x34;      /* 0x1001: incoming 4, outgoing 3 */

    Test_ExpectStatus(Nwk_LinkStatusParse(payload, len, &list), ZB_OK,
                      "3.4.8.3.1's options octet counts the list, and 3.4.8.3.2's entries follow it");
    Test_ExpectCount(list.count, 2, "two entries, as the count sub-field says");
    Test_Expect(list.firstFrame == 1 && list.lastFrame == 1, "and both frame bits, a list that fits in one frame");
    Test_ExpectCount(list.entries[0].networkAddress, 0x1000, "the address least significant octet first");
    Test_ExpectCount(list.entries[0].incomingCost, 2, "bits 0-2 are the incoming cost");
    Test_ExpectCount(list.entries[0].outgoingCost, 1, "bits 4-6 the outgoing one");

    Test_ExpectStatus(Nwk_LinkStatusParse(payload, len - 1, &list), ZB_ERR_BAD_ARGUMENT,
                      "a list that does not fill the count is refused rather than read short");
    Test_ExpectStatus(Nwk_LinkStatusParse(payload, len, &list), ZB_OK, "and the whole payload reads again");

    Test_ExpectCount(Nwk_LinkStatusConnectivity(&list), (7 - 2) + (7 - 4),
                     "3.6.4.4.2 step 2: 7 less the larger cost of each entry, accumulated");

    for (i = 0; i < 2; i++)
        neighborSlot(pool, i);

    pool[0].inUse = 1;
    pool[0].networkAddress = 0x1000;
    pool[0].outgoingCost = 2;

    Test_ExpectCount(Nwk_LinkStatusDiversity(&list, pool), 7 - 4,
                     "3.6.4.4.2 step 3: only the advertised neighbour this device does not hold with a cost of its own counts");
}

void caseLinkStatusApply(void)
{
    Nwk_NeighborTableEntry pool[NWK_NEIGHBOR_MAX];
    Nwk_LinkStatus list;
    Nwk_NeighborTableEntry *sender;
    uint8_t payload[1 + 3 * 2];
    uint32_t len;

    Zb_memset(pool, 0, (uint32_t)sizeof pool);
    Zb_memset(payload, 0, (uint32_t)sizeof payload);

    sender = neighborSlot(pool, 0);
    sender->inUse = 1;
    sender->networkAddress = NEIGHBOR;
    sender->deviceType = NWK_DEVICE_ROUTER;
    sender->relationship = NWK_REL_SIBLING;
    sender->ageFromMs = 1;
    sender->age = 5;

    len = linkStatusPayload(payload, 2, 1, 1);
    payload[3] = 0x14;      /* 0x1000: incoming 4 */
    payload[6] = 0x22;      /* 0x1001: incoming 2 */

    Test_ExpectStatus(Nwk_LinkStatusParse(payload, len, &list), ZB_OK, "the list as the sender wrote it");

    Test_ExpectCount(Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1001, &list, 1, 1000), 1,
                      "3.6.4.4.2 applies a list that covers this device's address");
    Test_ExpectCount(sender->outgoingCost, 2,
                      "and the sender's outgoing cost is the incoming cost it stated for this device");
    Test_ExpectCount(sender->age, 0, "the age field is reset by the frame's arrival");

    sender->outgoingCost = 3;
    Test_ExpectCount(Nwk_LinkStatusApply(pool, NEIGHBOR, 0x0fff, &list, 1, 2000), 1,
                     "a frame that is both the first and the last covers every address (8955-8956)");
    Test_ExpectCount(sender->outgoingCost, 0, "so a device it does not name learns the sender does not hear it (8961)");

    sender->outgoingCost = 3;
    Test_ExpectCount(Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1000, &list, 1, 3000), 1,
                      "a frame naming this device at the list's first entry");
    Test_ExpectCount(sender->outgoingCost, 4, "sets the cost from that entry's incoming cost");

    sender->outgoingCost = 3;
    len = linkStatusPayload(payload, 1, 1, 1);
    payload[3] = 0x14;
    Test_ExpectStatus(Nwk_LinkStatusParse(payload, len, &list), ZB_OK, "a one-entry list");
    Test_ExpectCount(Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1000, &list, 1, 4000), 1, "which covers 0x1000");
    Test_ExpectCount(sender->outgoingCost, 4, "and states the cost for it");

    sender->deviceType = NWK_NEIGHBOR_TYPE_UNKNOWN;
    sender->relationship = NWK_REL_NONE;
    sender->rxOnWhenIdle = 0;
    (void)Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1000, &list, 1, 5000);
    Test_ExpectCount(sender->deviceType, NWK_DEVICE_ROUTER, "3.6.4.4.1: only a router or the coordinator sends one");
    Test_ExpectCount((uint32_t)sender->rxOnWhenIdle, 1, "9465: whose receiver is on, which Mgmt_Lqi_rsp then reports");
    Test_ExpectCount(sender->relationship, NWK_REL_SIBLING, "and a neighbouring router is a sibling, Table 3-75's only row for it");

    sender->networkAddress = 0x0000;
    sender->deviceType = NWK_NEIGHBOR_TYPE_UNKNOWN;
    (void)Nwk_LinkStatusApply(pool, 0x0000, 0x1000, &list, 1, 5100);
    Test_ExpectCount(sender->deviceType, NWK_DEVICE_COORDINATOR, "the coordinator being the one at address 0");
    sender->networkAddress = NEIGHBOR;

    sender->relationship = NWK_REL_PARENT;
    (void)Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1000, &list, 1, 5200);
    Test_ExpectCount(sender->relationship, NWK_REL_SIBLING, "7935-7936: a router's parent is its sibling once the join is complete");

    sender->relationship = NWK_REL_CHILD;
    (void)Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1000, &list, 1, 5300);
    Test_ExpectCount(sender->relationship, NWK_REL_SIBLING, "and so is a router child, which sends one only once it is");

    sender->relationship = NWK_REL_BACKBONE_SIBLING;
    (void)Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1000, &list, 1, 5400);
    Test_ExpectCount(sender->relationship, NWK_REL_BACKBONE_SIBLING, "and a backbone sibling stays one");

    sender->deviceType = NWK_DEVICE_END_DEVICE;
    sender->relationship = NWK_REL_CHILD;
    (void)Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1000, &list, 1, 5500);
    Test_ExpectCount(sender->relationship, NWK_REL_CHILD, "an end device child the frame cannot be from keeps its row");
}

/* 8955-8958: the bits of a frame in a split list say which side of its addresses it also covers, 8959-8961 search
   whichever frame covers the receiver, and 8937-8953 take the sums from the first frame whoever it covers. */
void caseLinkStatusCoverage(void)
{
    Nwk_NeighborTableEntry pool[NWK_NEIGHBOR_MAX];
    Nwk_LinkStatus list;
    Nwk_NeighborTableEntry *sender;
    uint8_t payload[1 + 3 * 2];
    uint32_t len;

    Zb_memset(pool, 0, (uint32_t)sizeof pool);
    Zb_memset(payload, 0, (uint32_t)sizeof payload);

    sender = neighborSlot(pool, 0);
    sender->inUse = 1;
    sender->networkAddress = NEIGHBOR;
    sender->deviceType = NWK_DEVICE_ROUTER;

    len = linkStatusPayload(payload, 2, 1, 0);
    payload[3] = 0x14;      /* 0x1000: incoming 4, outgoing 1 */
    payload[6] = 0x22;      /* 0x1001: incoming 2, outgoing 2 */
    Test_ExpectStatus(Nwk_LinkStatusParse(payload, len, &list), ZB_OK, "a first frame, with more to follow");

    sender->outgoingCost = 3;
    Test_ExpectCount(Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1002, &list, 1, 1000), 0,
                     "an address above its last entry waits for a later frame");
    Test_ExpectCount(sender->outgoingCost, 3, "leaving the cost alone");
    Test_ExpectCount(sender->routerConnectivity, Nwk_LinkStatusConnectivity(&list),
                     "while the sums are the first frame's, for a receiver it does not cover too");

    Test_ExpectCount(Nwk_LinkStatusApply(pool, NEIGHBOR, 0x0fff, &list, 1, 1000), 1,
                     "and an address below its first entry is covered: nothing comes before a first frame");
    Test_ExpectCount(sender->outgoingCost, 0, "so it is not listed at all");

    len = linkStatusPayload(payload, 2, 0, 1);
    payload[3] = 0x14;
    payload[6] = 0x22;
    Test_ExpectStatus(Nwk_LinkStatusParse(payload, len, &list), ZB_OK, "a last frame, with others before it");

    sender->outgoingCost = 3;
    sender->routerConnectivity = 99;
    Test_ExpectCount(Nwk_LinkStatusApply(pool, NEIGHBOR, 0x0fff, &list, 1, 2000), 0,
                     "an address below its first entry was a former frame's");
    Test_ExpectCount(Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1001, &list, 1, 2000), 1, "one it names is covered");
    Test_ExpectCount(sender->outgoingCost, 2, "and searched, although this is not the first frame");
    Test_ExpectCount(sender->routerConnectivity, 99, "and the sums stay the first frame's");

    sender->outgoingCost = 3;
    Test_ExpectCount(Nwk_LinkStatusApply(pool, NEIGHBOR, 0x2000, &list, 1, 2000), 1,
                     "an address above its last entry is covered: nothing comes after a last frame");
    Test_ExpectCount(sender->outgoingCost, 0, "and it is not listed");

    len = linkStatusPayload(payload, 2, 0, 0);
    payload[3] = 0x14;
    payload[6] = 0x22;
    Test_ExpectStatus(Nwk_LinkStatusParse(payload, len, &list), ZB_OK, "a frame from the middle of a list");

    sender->outgoingCost = 3;
    Test_ExpectCount(Nwk_LinkStatusApply(pool, NEIGHBOR, 0x2000, &list, 1, 3000), 0, "covers only its own span above");
    Test_ExpectCount(Nwk_LinkStatusApply(pool, NEIGHBOR, 0x0fff, &list, 1, 3000), 0, "and below");
    Test_ExpectCount(sender->outgoingCost, 3, "so neither moves the cost");

    len = linkStatusPayload(payload, 0, 1, 1);
    Test_ExpectStatus(Nwk_LinkStatusParse(payload, len, &list), ZB_OK, "an empty list");

    sender->outgoingCost = 3;
    Test_ExpectCount(Nwk_LinkStatusApply(pool, NEIGHBOR, 0x2000, &list, 1, 4000), 1, "covers everyone");
    Test_ExpectCount(sender->outgoingCost, 0, "and names no one");
}

/* 8969: an end device does not process the frame, should one reach it on the all-devices address. */
void caseLinkStatusEndDeviceIgnores(void)
{
    Test_BandA dev;
    Nwk_NeighborTableEntry *sender;
    uint8_t payload[2];
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t npduLen;

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_END_DEVICE, 1);
    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_PARENT);
    Nwk_NeighborOf(dev.nwk.neighbors, NEIGHBOR)->outgoingCost = 3;

    payload[0] = NWK_CMD_LINK_STATUS;
    payload[1] = NWK_LINK_STATUS_OPTIONS_FIRST | NWK_LINK_STATUS_OPTIONS_LAST;
    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, NEIGHBOR, 1, 9, NWK_FRAME_TYPE_COMMAND, 0, payload, 2);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 10), ZB_OK, "a link status at an end device");

    sender = Nwk_NeighborOf(dev.nwk.neighbors, NEIGHBOR);

    Test_ExpectCount(Nwk_LinkStatusApplied(&dev.nwk), 0, "is not applied");
    Test_Expect(sender != 0 && sender->outgoingCost == 3, "so what it holds for its parent is not zeroed");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 10 + 5 * NWK_LINK_STATUS_PERIOD_MS), ZB_OK, "and five periods with no link status");
    Test_ExpectCount(sender ? sender->age : 0xff, 0, "age nothing: 3.6.4.4.4 is for devices using link status");
    Test_ExpectCount(sender ? sender->outgoingCost : 0xff, 3, "so an end device does not lose its parent to them");
}

/* 3.6.4.4.1 sends one every period, and a transmit path with no room at that moment is no reason to skip one: three
   periods of that and every neighbour reads this router's cost as 0 (9011). Measured on six RCPs under traffic. */
void caseLinkStatusRefusedIsAskedAgain(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    uint32_t airCount = 0;
    uint32_t due = 1 + NWK_LINK_STATUS_PERIOD_MS;

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "the turn that arms the period");
    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 2);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, due), ZB_OK, "the turn it runs out on, with no room");
    Test_ExpectCount(Nwk_LinkStatusSent(&dev.nwk), 0, "sends nothing");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, due + NWK_LINK_STATUS_RETRY_MS - 1), ZB_OK, "a turn before the retry");
    Test_ExpectCount(Nwk_LinkStatusSent(&dev.nwk), 0, "does not ask again");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, due + NWK_LINK_STATUS_RETRY_MS), ZB_OK, "the retry, still no room");
    Test_ExpectCount(Nwk_LinkStatusSent(&dev.nwk), 0, "still nothing");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, due + 2 * NWK_LINK_STATUS_RETRY_MS), ZB_OK, "the next retry, with room");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1 && Nwk_LinkStatusSent(&dev.nwk) == 1, "that period's frame goes out after all");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, due + 3 * NWK_LINK_STATUS_RETRY_MS), ZB_OK, "and then");
    Test_ExpectCount(Nwk_LinkStatusSent(&dev.nwk), 1, "only one of them");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, due + 2 * NWK_LINK_STATUS_RETRY_MS + 2 * NWK_LINK_STATUS_PERIOD_MS), ZB_OK,
                      "and the period goes on from it");
    Test_ExpectCount(Nwk_LinkStatusSent(&dev.nwk), 2, "with the next one");
}

/* 3.6.4.4.1 has a router send one every period, with no exception for having no neighbour yet: this is how the first
   neighbour hears of it, and 8966-8968 have that neighbour answer between 500 ms and 1 s later. */
void caseLinkStatusEmptyAndItsAnswer(void)
{
    Test_BandA dev;
    Test_BandA seeded;
    Air air[AIR_LOG_MAX];
    Nwk_LinkStatus list;
    uint8_t payload[2 + NWK_LINK_STATUS_ENTRY_LEN];
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint32_t at;

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "the turn that arms the period");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1 + NWK_LINK_STATUS_PERIOD_MS), ZB_OK, "and the turn it runs out on");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1 && Nwk_LinkStatusSent(&dev.nwk) == 1, "a router with no neighbour still sends");
    Test_ExpectCount(npduOf(&air[0])[LINK_STATUS_NPDU_COMMAND], NWK_CMD_LINK_STATUS, "a link status");
    Test_ExpectCount(npduOf(&air[0])[LINK_STATUS_NPDU_COMMAND + 1],
                     NWK_LINK_STATUS_OPTIONS_FIRST | NWK_LINK_STATUS_OPTIONS_LAST,
                     "whose list is empty, the first and the last frame of it");

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1);
    airCount = 0;
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "another router, its period armed");

    payload[0] = NWK_CMD_LINK_STATUS;
    payload[1] = NWK_LINK_STATUS_OPTIONS_FIRST | NWK_LINK_STATUS_OPTIONS_LAST;
    npduLen = makeNpdu(npdu, NWK_ADDR_ROUTERS, NEIGHBOR, 1, 9, NWK_FRAME_TYPE_COMMAND, 0, payload, 2);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "hears an empty list from a device it has no entry for");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + NWK_ROUTER_BOOTSTRAP_JITTER_MIN_MS - 1), ZB_OK, "just inside the bound");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "nothing before nwkcMinRouterBootstrapJitter");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + NWK_ROUTER_BOOTSTRAP_JITTER_MIN_MS), ZB_OK, "at the bound");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "the gratuitous frame, with no jitter configured");
    Test_ExpectStatus(Nwk_LinkStatusParse(&npduOf(&air[0])[LINK_STATUS_NPDU_COMMAND + 1],
                                          npduLenOf(&air[0]) - LINK_STATUS_NPDU_COMMAND - 1, &list), ZB_OK,
                      "it reads back");
    Test_Expect(list.count == 1 && list.entries[0].networkAddress == NEIGHBOR, "and names the device that was alone");

    npduLen = makeNpdu(npdu, NWK_ADDR_ROUTERS, NEIGHBOR, 1, 10, NWK_FRAME_TYPE_COMMAND, 0, payload, 2);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 700), ZB_OK, "the same device's next empty list, the entry now held");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 700 + NWK_ROUTER_BOOTSTRAP_JITTER_MAX_MS), ZB_OK, "past the upper bound");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "draws no answer, or two routers would talk for ever");

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1);
    airCount = 0;
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "a third router");
    npduLen = linkStatusPayload(payload + 1, 1, 1, 1) + 1;
    npduLen = makeNpdu(npdu, NWK_ADDR_ROUTERS, NEIGHBOR, 1, 11, NWK_FRAME_TYPE_COMMAND, 0, payload, npduLen);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "hearing a list that is not empty from a new device");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + NWK_ROUTER_BOOTSTRAP_JITTER_MAX_MS), ZB_OK, "past the upper bound");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "waits for its own period");

    rigAtSeed(&seeded, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1, 0, 0x1234);
    Test_ExpectStatus(Test_NwkStep(&seeded.nwk, 1), ZB_OK, "a router with jitter configured");
    payload[1] = NWK_LINK_STATUS_OPTIONS_FIRST | NWK_LINK_STATUS_OPTIONS_LAST;
    npduLen = makeNpdu(npdu, NWK_ADDR_ROUTERS, NEIGHBOR, 1, 12, NWK_FRAME_TYPE_COMMAND, 0, payload, 2);
    injectNpdu(&seeded, npdu, npduLen, NEIGHBOR);
    Test_ExpectStatus(Test_NwkStep(&seeded.nwk, 100), ZB_OK, "hears the same empty list");

    airCount = 0;

    for (at = 100 + NWK_ROUTER_BOOTSTRAP_JITTER_MIN_MS - 1; at <= 100 + NWK_ROUTER_BOOTSTRAP_JITTER_MAX_MS; at += 10)
    {
        Test_ExpectStatus(Test_NwkStep(&seeded.nwk, at), ZB_OK, "a turn across the bounds");
        harvestAir(&seeded.model, air, &airCount);

        if (airCount != 0)
            break;
    }

    Test_Expect(airCount == 1 && at >= 100 + NWK_ROUTER_BOOTSTRAP_JITTER_MIN_MS
                && at <= 100 + NWK_ROUTER_BOOTSTRAP_JITTER_MAX_MS,
                "its answer falls between the two bounds of Table 3-65");
}

void caseNeighborRank(void)
{
    Nwk_NeighborTableEntry entry;
    Nwk_NeighborTableEntry pool[NWK_NEIGHBOR_MAX];
    int indices[NWK_NEIGHBOR_MAX];
    uint32_t count;
    uint32_t i;

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.routerNeighborSetDiversity = 2;
    entry.routerConnectivity = 5;
    entry.routerOutboundActivity = 3;
    entry.routerInboundActivity = 1;

    Test_ExpectCount(Nwk_NeighborRank(&entry), 4 * 2 + 5 + 8 * 3 + 8 * 1,
                     "3.6.4.4.3's rank: 4 * RouterNeighborSetDiversity + RouterConnectivity + 8 * each activity");

    Zb_memset(pool, 0, (uint32_t)sizeof pool);
    Zb_memset(indices, 0, (uint32_t)sizeof indices);

    for (i = 0; i < 3; i++)
        neighborSlot(pool, i);

    pool[0].inUse = 1;
    pool[0].relationship = NWK_REL_SIBLING;
    pool[0].routerAge = 4;
    pool[1].inUse = 1;
    pool[1].relationship = NWK_REL_SIBLING;
    pool[1].routerAge = 1;
    pool[2].inUse = 1;
    pool[2].relationship = NWK_REL_CHILD;
    pool[2].routerAge = 9;

    count = Nwk_NeighborAssessmentPool(pool, 2, indices, NWK_NEIGHBOR_MAX);

    Test_ExpectCount(count, 1, "the assessment pool holds only a sibling past nwkcMinRouterObservationTime");
    Test_ExpectCount(indices[0], 0, "which is the one entry of the three that qualifies");
}

void caseNeighborMakeRoom(void)
{
    Nwk_NeighborTableEntry pool[NWK_NEIGHBOR_MAX];
    uint32_t i;

    Zb_memset(pool, 0, (uint32_t)sizeof pool);

    for (i = 0; i < 4; i++)
        neighborSlot(pool, i);

    pool[0].inUse = 1;
    pool[0].relationship = NWK_REL_SIBLING;
    pool[0].routerAge = 5;
    pool[0].routerInboundActivity = 9;

    pool[1].inUse = 1;
    pool[1].relationship = NWK_REL_SIBLING;
    pool[1].routerAge = 5;
    pool[1].routerInboundActivity = 1;

    pool[2].inUse = 1;
    pool[2].relationship = NWK_REL_BACKBONE_SIBLING;
    pool[2].routerAge = 5;

    pool[3].inUse = 1;
    pool[3].deviceType = NWK_DEVICE_END_DEVICE;
    pool[3].relationship = NWK_REL_CHILD;
    pool[3].routerAge = 5;

    Test_ExpectCount(Nwk_NeighborMakeRoom(pool, 2), 1,
                     "3.6.4.4.3.1 removes the lowest-ranked entry that is no backbone sibling and no end-device child");

    pool[0].routerAge = 1;
    pool[1].routerAge = 1;
    Test_Expect(Nwk_NeighborMakeRoom(pool, 2) == -1,
                "and refuses when every candidate is still inside the observation window");

    pool[0].routerAge = 5;
    pool[0].relationship = NWK_REL_NONE;
    pool[1].routerAge = 5;
    pool[1].relationship = NWK_REL_PARENT;
    Test_Expect(Nwk_NeighborMakeRoom(pool, 2) == -1,
                "8990-8993: and the pool it ranks holds siblings alone, so a parent or an unplaced entry is not offered");
}

/* 8990-9001 at a full table: a link status from a device with no entry takes the lowest-ranked sibling's place and is
   read as 3.6.4.4.2 reads any other; with no sibling past the window it is dropped, which leaves nothing to answer. */
void caseLinkStatusFullTable(void)
{
    enum { NEWCOMER = 0x7777, FIRST_HELD = 0x4000 };
    Test_BandA dev;
    Nwk_NeighborTableEntry *entry;
    uint8_t payload[2 + NWK_LINK_STATUS_ENTRY_LEN];
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t npduLen;
    uint32_t i;

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "the turn that arms the period");

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        seedNeighbor(&dev.nwk, (uint16_t)(FIRST_HELD + i), NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
        entry = Nwk_NeighborOf(dev.nwk.neighbors, (uint16_t)(FIRST_HELD + i));
        entry->routerInboundActivity = i == 3 ? 1 : 9;
        entry->routerOutboundActivity = 9;
    }

    payload[0] = NWK_CMD_LINK_STATUS;
    payload[1] = NWK_LINK_STATUS_OPTIONS_FIRST | NWK_LINK_STATUS_OPTIONS_LAST;
    npduLen = makeNpdu(npdu, NWK_ADDR_ROUTERS, NEWCOMER, 1, 9, NWK_FRAME_TYPE_COMMAND, 0, payload, 2);
    injectNpdu(&dev, npdu, npduLen, NEWCOMER);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 2), ZB_OK, "an empty list at a full table of siblings still in their window");
    Test_Expect(Nwk_NeighborOf(dev.nwk.neighbors, NEWCOMER) == 0, "8992-8993: the pool is empty, so it is dropped");
    Test_ExpectCount(Nwk_NeighborQueue(&dev.nwk), NWK_NEIGHBOR_MAX, "and nothing makes way");
    Test_ExpectCount(Nwk_LinkStatusApplied(&dev.nwk), 0, "and it is not applied");
    Test_Expect(dev.nwk.linkStatusAtMs > 2 + NWK_ROUTER_BOOTSTRAP_JITTER_MAX_MS,
                "and draws no gratuitous answer: no further processing is done");

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
        Nwk_NeighborOf(dev.nwk.neighbors, (uint16_t)(FIRST_HELD + i))->routerAge = 5;

    payload[1] = NWK_LINK_STATUS_OPTIONS_FIRST | NWK_LINK_STATUS_OPTIONS_LAST | 1;
    payload[2] = (uint8_t)(OWN_SHORT & 0xff);
    payload[3] = (uint8_t)(OWN_SHORT >> 8);
    payload[4] = 0x12;
    npduLen = makeNpdu(npdu, NWK_ADDR_ROUTERS, NEWCOMER, 1, 10, NWK_FRAME_TYPE_COMMAND, 0, payload,
                       (uint32_t)sizeof payload);
    injectNpdu(&dev, npdu, npduLen, NEWCOMER);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 3), ZB_OK, "a list naming this device, the siblings past the window");

    entry = Nwk_NeighborOf(dev.nwk.neighbors, NEWCOMER);

    Test_Expect(Nwk_NeighborOf(dev.nwk.neighbors, FIRST_HELD + 3) == 0, "9000: the lowest-ranked sibling is removed");
    Test_Expect(entry != 0, "9000-9001: and an entry is made for the sender");
    Test_ExpectCount(Nwk_LinkStatusApplied(&dev.nwk), 1, "and the frame is read");
    Test_ExpectCount(entry ? entry->outgoingCost : 0xff, 2, "the cost it states for this device");
    Test_ExpectCount(entry ? entry->routerAge : 0xff, 0, "8954: RouterAge from 0");
    Test_ExpectCount(entry ? entry->relationship : 0xff, NWK_REL_SIBLING, "a sibling");
    Test_ExpectCount(entry ? entry->routerConnectivity : 0xff, 7 - 2, "with 8940's sum from this frame");
}

/* 8886-8888 and Table 3-75: a unicast-addressed frame moves the hop's RouterInboundActivity, from the pre-loaded
   nwkRouterAgeLimit, a broadcast does not, and both counters fall by one each period and rest at 0. */
void caseNeighborActivityCounters(void)
{
    enum { HEARD = 0x2345 };
    Test_BandA dev;
    Nwk_NeighborTableEntry *entry;
    uint8_t nsdu[1] = { 0 };
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t npduLen;
    uint32_t at = 1;
    uint32_t i;

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, at), ZB_OK, "the turn that arms the period");

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, HEARD, 1, 1, NWK_FRAME_TYPE_DATA, 0, nsdu, 1);
    injectNpdu(&dev, npdu, npduLen, HEARD);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, ++at), ZB_OK, "a broadcast from a device the table did not hold");

    entry = Nwk_NeighborOf(dev.nwk.neighbors, HEARD);

    Test_Expect(entry != 0, "makes its entry");

    if (entry == 0)
        return;

    Test_ExpectCount(entry->routerInboundActivity, NWK_ROUTER_AGE_LIMIT, "pre-loaded, and not moved by a broadcast");
    Test_ExpectCount(entry->routerOutboundActivity, NWK_ROUTER_AGE_LIMIT, "and the other direction pre-loaded");

    npduLen = makeNpdu(npdu, OWN_SHORT, HEARD, 1, 2, NWK_FRAME_TYPE_DATA, 0, nsdu, 1);
    injectNpdu(&dev, npdu, npduLen, HEARD);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, ++at), ZB_OK, "a unicast from it");
    Test_ExpectCount(entry->routerInboundActivity, NWK_ROUTER_AGE_LIMIT + 1, "moves the count by one");
    Test_ExpectCount(entry->routerOutboundActivity, NWK_ROUTER_AGE_LIMIT, "in that direction alone");

    at = 1 + NWK_LINK_STATUS_PERIOD_MS;
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, at), ZB_OK, "a period on");
    Test_ExpectCount(entry->routerInboundActivity, NWK_ROUTER_AGE_LIMIT, "each falls by one");
    Test_ExpectCount(entry->routerOutboundActivity, NWK_ROUTER_AGE_LIMIT - 1, "unconditionally");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, at + 1), ZB_OK, "and the next turn, inside that period");
    Test_ExpectCount(entry->routerOutboundActivity, NWK_ROUTER_AGE_LIMIT - 1, "moves nothing");

    for (i = 0; i < NWK_ROUTER_AGE_LIMIT + 2; i++)
    {
        at += NWK_LINK_STATUS_PERIOD_MS;
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, at), ZB_OK, "more periods");
    }

    Test_ExpectCount(entry->routerInboundActivity, 0, "and they rest at 0");
    Test_ExpectCount(entry->routerOutboundActivity, 0, "and do not wrap");
}

/* 8938 and 8954: RouterAge counts a sender's first frames, starts at 0 for an entry the frame itself made, saturates at
   Table 3-75's 0xffff, and is not the age, which every link status resets. */
void caseLinkStatusRouterAge(void)
{
    Nwk_NeighborTableEntry pool[NWK_NEIGHBOR_MAX];
    Nwk_NeighborTableEntry *sender;
    Nwk_LinkStatus list;
    uint8_t payload[1 + 3 * 2];
    uint32_t len;

    Zb_memset(pool, 0, (uint32_t)sizeof pool);
    Zb_memset(payload, 0, (uint32_t)sizeof payload);

    sender = neighborSlot(pool, 0);
    sender->inUse = 1;
    sender->networkAddress = NEIGHBOR;
    sender->deviceType = NWK_DEVICE_ROUTER;

    len = linkStatusPayload(payload, 2, 1, 0);
    Test_ExpectStatus(Nwk_LinkStatusParse(payload, len, &list), ZB_OK, "a first frame");

    (void)Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1000, &list, 0, 100);
    Test_ExpectCount(sender->routerAge, 0, "8954: an entry the frame made starts at 0");

    (void)Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1000, &list, 1, 200);
    (void)Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1000, &list, 1, 300);
    Test_ExpectCount(sender->routerAge, 2, "8938: one that held it counts each first frame");
    Test_ExpectCount(sender->age, 0, "while the age stays reset");

    len = linkStatusPayload(payload, 2, 0, 1);
    Test_ExpectStatus(Nwk_LinkStatusParse(payload, len, &list), ZB_OK, "a later frame of the same list");
    (void)Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1000, &list, 1, 400);
    Test_ExpectCount(sender->routerAge, 2, "does not count: 8937 marks the first fragment");

    sender->routerAge = NWK_ROUTER_AGE_MAX;
    len = linkStatusPayload(payload, 2, 1, 0);
    Test_ExpectStatus(Nwk_LinkStatusParse(payload, len, &list), ZB_OK, "a first frame at the ceiling");
    (void)Nwk_LinkStatusApply(pool, NEIGHBOR, 0x1000, &list, 1, 500);
    Test_ExpectCount(sender->routerAge, NWK_ROUTER_AGE_MAX, "8938-8939: and saturates, no roll-over");
}

void caseNeighborPromoteBackbone(void)
{
    Nwk_NeighborTableEntry pool[NWK_NEIGHBOR_MAX];
    uint32_t i;

    Zb_memset(pool, 0, (uint32_t)sizeof pool);

    for (i = 0; i < 4; i++)
        neighborSlot(pool, i);

    pool[0].inUse = 1;
    pool[0].relationship = NWK_REL_SIBLING;
    pool[0].routerAge = 9;
    pool[0].routerInboundActivity = 1;

    pool[1].inUse = 1;
    pool[1].relationship = NWK_REL_SIBLING;
    pool[1].routerAge = 9;
    pool[1].routerInboundActivity = 5;

    pool[2].inUse = 1;
    pool[2].relationship = NWK_REL_SIBLING;
    pool[2].routerAge = 1;

    pool[3].inUse = 1;
    pool[3].relationship = NWK_REL_CHILD;
    pool[3].routerAge = 9;

    Test_ExpectCount(Nwk_NeighborPromoteBackbone(pool, 4, 1), 1,
                     "3.6.4.4.3.1 promotes one entry: the topmost of the combined set becomes a backbone mesh sibling");
    Test_ExpectCount(pool[1].relationship, NWK_REL_BACKBONE_SIBLING,
                     "and it is the highest-ranked sibling past nwkcBackboneMeshFormationTime");
    Test_ExpectCount(pool[0].relationship, NWK_REL_SIBLING, "while the other stays a sibling");
    Test_ExpectCount(pool[2].relationship, NWK_REL_SIBLING,
                     "and an entry still under observation is not in the set at all");
    Test_ExpectCount(pool[3].relationship, NWK_REL_CHILD, "nor is a child");

    Test_ExpectCount(Nwk_NeighborPromoteBackbone(pool, 4, 1), 0,
                     "a second pass over an unchanged table changes nothing, so the classification is stable");
}

/* 9006-9008, D-258: a backbone sibling gives way only to a rank past its own by a quarter and one frame's worth, and
   an empty place is filled at once. */
void caseBackboneSiblingHoldsItsPlace(void)
{
    Nwk_NeighborTableEntry pool[NWK_NEIGHBOR_MAX];
    uint32_t i;

    Zb_memset(pool, 0, (uint32_t)sizeof pool);

    for (i = 0; i < 2; i++)
    {
        neighborSlot(pool, i);
        pool[i].inUse = 1;
        pool[i].routerAge = 9;
        pool[i].relationship = NWK_REL_SIBLING;
    }

    pool[0].relationship = NWK_REL_BACKBONE_SIBLING;
    pool[0].routerInboundActivity = 10;
    pool[1].routerInboundActivity = 11;

    Test_ExpectCount(Nwk_NeighborPromoteBackbone(pool, 4, 1), 0, "a rank one frame past the holder's changes nothing");

    pool[1].routerInboundActivity = 13;

    Test_ExpectCount(Nwk_NeighborPromoteBackbone(pool, 4, 1), 0, "and neither does 104 against a holder's 80");
    Test_ExpectCount(pool[0].relationship, NWK_REL_BACKBONE_SIBLING, "so the holder is still the backbone sibling");

    pool[1].routerInboundActivity = 14;

    Test_ExpectCount(Nwk_NeighborPromoteBackbone(pool, 4, 1), 2, "112 is past 80 + 20 + 8, and the two change places");
    Test_ExpectCount(pool[1].relationship, NWK_REL_BACKBONE_SIBLING, "the new one holds it");
    Test_ExpectCount(pool[0].relationship, NWK_REL_SIBLING, "and the old one is a sibling again");

    pool[0].routerInboundActivity = 0;
    pool[1].routerInboundActivity = 0;
    pool[0].routerOutboundActivity = 1;

    Test_ExpectCount(Nwk_NeighborPromoteBackbone(pool, 4, 1), 0, "with nothing to lose, the holder still has the one frame");

    pool[1].relationship = NWK_REL_SIBLING;

    Test_ExpectCount(Nwk_NeighborPromoteBackbone(pool, 4, 2), 2, "and an empty place takes whoever is there, whatever its rank");
}

void caseLinkStatusCompose(void)
{
    Nwk_NeighborTableEntry pool[NWK_NEIGHBOR_MAX];
    Nwk_LinkStatus list;
    uint8_t payload[1 + NWK_LINK_STATUS_ENTRY_MAX * NWK_LINK_STATUS_ENTRY_LEN];
    uint32_t len = 0;
    uint32_t entries = 0;
    uint32_t i;
    int last = 0;
    uint16_t lastAddress = 0;

    Zb_memset(pool, 0, (uint32_t)sizeof pool);

    for (i = 0; i < 3; i++)
        neighborSlot(pool, i);

    pool[0].inUse = 1;
    pool[0].networkAddress = 0x3000;
    pool[0].deviceType = NWK_DEVICE_ROUTER;
    pool[0].lqi = 200;
    pool[0].outgoingCost = 3;

    pool[1].inUse = 1;
    pool[1].networkAddress = 0x1000;
    pool[1].deviceType = NWK_DEVICE_ROUTER;
    pool[1].lqi = 20;
    pool[1].outgoingCost = 5;

    pool[2].inUse = 1;
    pool[2].networkAddress = 0x2000;
    pool[2].deviceType = NWK_DEVICE_END_DEVICE;
    pool[2].lqi = 200;
    pool[2].outgoingCost = 2;

    Test_ExpectStatus(Nwk_LinkStatusCompose(pool, 1, 0, payload, (uint32_t)sizeof payload, &len, &entries, &last, &lastAddress), ZB_OK,
                      "3.6.4.4.1's frame composed from this device's own neighbour table");
    Test_ExpectCount(entries, 2, "two entries: a router's, and not the end device's, which sends no link status of its own");
    Test_ExpectCount(len, 1 + 2 * NWK_LINK_STATUS_ENTRY_LEN, "the options octet and one entry per router");
    Test_ExpectStatus(Nwk_LinkStatusParse(payload, len, &list), ZB_OK, "and it reads back as the codec expects");
    Test_Expect(list.firstFrame == 1 && list.lastFrame == 1, "a list that fits in one frame sets both bits");
    Test_ExpectCount(list.entries[0].networkAddress, 0x1000,
                     "sorted by address, as 3.4.8.3.2 requires of a link status list");
    Test_ExpectCount(list.entries[1].networkAddress, 0x3000, "and the second address after it");
    Test_ExpectCount(list.entries[0].incomingCost, Nwk_CostFromLqa(20),
                     "3.4.8.3.2: the incoming cost is this device's own estimate, from what it measures of the neighbour");
    Test_ExpectCount(list.entries[0].outgoingCost, 5,
                     "3.4.8.3.2: and the outgoing cost is the neighbour table's");
    Test_ExpectCount(list.entries[1].incomingCost, Nwk_CostFromLqa(200), "for each entry");
    Test_ExpectCount(list.entries[1].outgoingCost, 3, "the two costs told apart");
    Test_Expect(Nwk_LinkStatusConnectivity(&list) != 0,
                "so a receiver's 3.6.4.4.2 sums, which skip an outgoing cost of 0, count this sender's links");

    pool[0].outgoingCost = 0;
    Test_ExpectStatus(Nwk_LinkStatusCompose(pool, 1, 0, payload, (uint32_t)sizeof payload, &len, &entries, &last, &lastAddress), ZB_OK,
                      "a router that has not yet listed this device");
    Test_ExpectCount(entries, 2, "is still a router neighbour: listing it is how it learns it was heard");

    pool[0].age = NWK_ROUTER_AGE_LIMIT + 1;
    Test_ExpectStatus(Nwk_LinkStatusCompose(pool, 1, 0, payload, (uint32_t)sizeof payload, &len, &entries, &last, &lastAddress), ZB_OK,
                      "a router past 3.6.4.4.4's age limit");
    Test_ExpectCount(entries, 2, "is still one: 7338 and 7341 list router neighbours and except no stale one");
    pool[0].age = 0;

    pool[0].deviceType = NWK_DEVICE_COORDINATOR;
    Test_ExpectStatus(Nwk_LinkStatusCompose(pool, 1, 0, payload, (uint32_t)sizeof payload, &len, &entries, &last, &lastAddress), ZB_OK,
                      "the coordinator");
    Test_ExpectCount(entries, 2, "is listed as a router is, sending link status as one does (8929)");

    pool[0].deviceType = NWK_NEIGHBOR_TYPE_UNKNOWN;
    Test_ExpectStatus(Nwk_LinkStatusCompose(pool, 1, 0, payload, (uint32_t)sizeof payload, &len, &entries, &last, &lastAddress), ZB_OK,
                      "a device whose type is not known");
    Test_ExpectCount(entries, 1, "is not a router neighbour until its own link status says so");
    pool[0].deviceType = NWK_DEVICE_ROUTER;

    Test_ExpectStatus(Nwk_LinkStatusCompose(pool, 1, 0, payload, 1 + NWK_LINK_STATUS_ENTRY_LEN, &len, &entries, &last,
                                            &lastAddress), ZB_ERR_NO_SPACE,
                      "room for one entry when two are to state cannot make progress: a next frame starts on this one's last address");
    Test_ExpectStatus(Nwk_LinkStatusCompose(pool, 1, 0, payload, 0, &len, &entries, &last, &lastAddress), ZB_ERR_NO_SPACE,
                      "and no room even for the options octet is refused");
}

/* 3.4.8.3.2: routers that do not fit one frame take several, sorted, frame N's last address the first of frame N+1. */
void caseLinkStatusComposeSplits(void)
{
    Nwk_NeighborTableEntry pool[NWK_NEIGHBOR_MAX];
    Nwk_LinkStatus list;
    uint8_t payload[1 + NWK_LINK_STATUS_ENTRY_MAX * NWK_LINK_STATUS_ENTRY_LEN];
    uint32_t perFrame = 5;
    uint32_t frames = 0;
    uint32_t len = 0;
    uint32_t entries = 0;
    uint32_t i;
    uint32_t j;
    int last = 0;
    uint16_t from = 0;
    uint16_t previous = 0;
    uint16_t next = 0x1000;

    Zb_memset(pool, 0, (uint32_t)sizeof pool);

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        pool[i].inUse = 1;
        pool[i].networkAddress = (uint16_t)(0x1000 + (NWK_NEIGHBOR_MAX - 1 - i));
        pool[i].deviceType = NWK_DEVICE_ROUTER;
    }

    while (!last && frames < NWK_NEIGHBOR_MAX)
    {
        Test_ExpectStatus(Nwk_LinkStatusCompose(pool, frames == 0, from, payload, 1 + perFrame * NWK_LINK_STATUS_ENTRY_LEN,
                                                &len, &entries, &last, &from), ZB_OK, "one frame of the sender's list");
        Test_ExpectStatus(Nwk_LinkStatusParse(payload, len, &list), ZB_OK, "which reads back");
        Test_ExpectCount(list.firstFrame, frames == 0, "the first frame's bit on the first frame only");
        Test_ExpectCount(list.lastFrame, last, "and the last frame's on the last only");

        for (j = (frames == 0) ? 0 : 1; j < list.count; j++)
        {
            Test_ExpectCount(list.entries[j].networkAddress, next, "every router in ascending order");
            next++;
        }

        if (frames != 0)
            Test_ExpectCount(list.entries[0].networkAddress, previous,
                             "and a later frame begins on the address the frame before it ended on");

        previous = from;
        frames++;
    }

    Test_Expect(last, "the list ends");
    Test_ExpectCount(next, 0x1000 + NWK_NEIGHBOR_MAX, "with every router of the table stated");
    Test_ExpectCount(frames, 1 + (NWK_NEIGHBOR_MAX - 2) / (perFrame - 1), "in as many frames as the overlap costs");
}

/* The same list as frames on the air, one a turn. It takes a table larger than one frame holds, so it runs only in a
   build that sizes one (docs/configuration.md). */
void caseLinkStatusSplitOnTheAir(void)
{
#if ZB_LIMIT_NWK_NEIGHBOR > 32
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_LinkStatus first;
    Nwk_LinkStatus second;
    uint32_t airCount = 0;
    uint32_t i;

    rigAt(&dev, OWN_SHORT, PAN_ID, NWK_DEVICE_ROUTER, 1);

    for (i = 0; i < NWK_LINK_STATUS_ENTRY_MAX + 2; i++)
        seedNeighbor(&dev.nwk, (uint16_t)(0x1000 + i), NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "the turn that arms the period");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1 + NWK_LINK_STATUS_PERIOD_MS), ZB_OK, "and the turn it runs out on");
    Test_ExpectCount(Nwk_LinkStatusSent(&dev.nwk), 1, "the first frame of a list one frame cannot hold");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 2 + NWK_LINK_STATUS_PERIOD_MS), ZB_OK, "the next turn");
    Test_ExpectCount(Nwk_LinkStatusSent(&dev.nwk), 2, "the rest of it");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 3 + NWK_LINK_STATUS_PERIOD_MS), ZB_OK, "and the turn after");
    Test_ExpectCount(Nwk_LinkStatusSent(&dev.nwk), 2, "nothing until the next period");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 2, "two frames on the air");
    Test_ExpectStatus(Nwk_LinkStatusParse(&npduOf(&air[0])[LINK_STATUS_NPDU_COMMAND + 1],
                                          npduLenOf(&air[0]) - LINK_STATUS_NPDU_COMMAND - 1, &first), ZB_OK, "the first reads");
    Test_ExpectStatus(Nwk_LinkStatusParse(&npduOf(&air[1])[LINK_STATUS_NPDU_COMMAND + 1],
                                          npduLenOf(&air[1]) - LINK_STATUS_NPDU_COMMAND - 1, &second), ZB_OK, "the second reads");
    Test_Expect(first.firstFrame && !first.lastFrame && !second.firstFrame && second.lastFrame, "first, then last");
    Test_ExpectCount(second.entries[0].networkAddress, first.entries[first.count - 1].networkAddress,
                     "sharing the address where they meet");
    Test_ExpectCount(second.entries[second.count - 1].networkAddress, 0x1000 + NWK_LINK_STATUS_ENTRY_MAX + 1,
                     "and reaching the table's last router");

#endif
}
