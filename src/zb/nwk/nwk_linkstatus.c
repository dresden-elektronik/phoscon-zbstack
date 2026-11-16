#include "nwk.h"

#include "nwk_linkstatus.h"

#include "nwk_cost.h"
#include "zb_bstream.h"
#include "zb_utils.h"

/* R23.1: 3.4.8, 3.4.8.3.1, 3.4.8.3.2, 3.6.1.6, 3.6.4.4.1, 3.6.4.4.2, 3.6.4.4.3, 3.6.4.4.3.1, 3.6.4.4.4 ok. */

/* 3.4.8.3.1 and 3.4.8.3.2: the options octet counts the list, and an entry is the address least significant octet
   first then the status octet whose bits 0-2 and 4-6 are the two costs. */
ZbStatus Nwk_LinkStatusParse(const uint8_t *payload, uint32_t payloadLen, Nwk_LinkStatus *out)
{
    U_BStream stream;
    uint8_t options;
    uint8_t status;
    uint32_t i;

    if (payload == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payloadLen < 1)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_bstream_init_const(&stream, payload, payloadLen);

    options = (uint8_t)U_bstream_get_u8(&stream);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(out, 0, (uint32_t)sizeof *out);

    out->count = (uint32_t)(options & 0x1f);
    out->firstFrame = (options & NWK_LINK_STATUS_OPTIONS_FIRST) != 0;
    out->lastFrame = (options & NWK_LINK_STATUS_OPTIONS_LAST) != 0;

    if (out->count > NWK_LINK_STATUS_ENTRY_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (payloadLen != 1 + out->count * NWK_LINK_STATUS_ENTRY_LEN)
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < out->count; i++)
    {
        out->entries[i].networkAddress = U_bstream_get_u16_le(&stream);
        status = (uint8_t)U_bstream_get_u8(&stream);

        if (!Zb_bstream_ok(&stream))
            return ZB_ERR_BAD_ARGUMENT;

        out->entries[i].incomingCost = (uint32_t)(status & 0x07);
        out->entries[i].outgoingCost = (uint32_t)((status >> 4) & 0x07);
    }

    return ZB_OK;
}

/* 3.6.4.4.2 step 2: 7 less the larger of the two costs, summed over the entries the sender gave a cost for. */
uint32_t Nwk_LinkStatusConnectivity(const Nwk_LinkStatus *list)
{
    uint32_t sum = 0;
    uint32_t cost;
    uint32_t i;

    if (list == 0)
        return 0;

    for (i = 0; i < list->count; i++)
    {
        if (list->entries[i].outgoingCost == 0)
            continue;

        cost = list->entries[i].incomingCost > list->entries[i].outgoingCost ? list->entries[i].incomingCost
                                                                           : list->entries[i].outgoingCost;

        if (cost < NWK_LINK_STATUS_COST_MAX)
            sum += NWK_LINK_STATUS_COST_MAX - cost;
    }

    return sum;
}

/* 3.6.4.4.2 step 3: the same sum over the advertised neighbours this device does not hold with a cost of its own. */
uint32_t Nwk_LinkStatusDiversity(const Nwk_LinkStatus *list, const Nwk_NeighborTableEntry *pool)
{
    const Nwk_NeighborTableEntry *held;
    uint32_t sum = 0;
    uint32_t cost;
    uint32_t i;

    if (list == 0 || pool == 0)
        return 0;

    for (i = 0; i < list->count; i++)
    {
        if (list->entries[i].outgoingCost == 0)
            continue;

        held = Nwk_NeighborOf((Nwk_NeighborTableEntry *)pool, list->entries[i].networkAddress);

        if (held != 0 && held->outgoingCost != 0)
            continue;

        cost = list->entries[i].incomingCost > list->entries[i].outgoingCost ? list->entries[i].incomingCost
                                                                           : list->entries[i].outgoingCost;

        if (cost < NWK_LINK_STATUS_COST_MAX)
            sum += NWK_LINK_STATUS_COST_MAX - cost;
    }

    return sum;
}

/* 8955-8958: the addresses between its first and last entry, every lower one when it is the sender's first frame and
   every higher one when it is the last, or everyone when the list was empty. */
static int nwkLinkStatusCovers(const Nwk_LinkStatus *list, uint16_t own)
{
    uint16_t low;
    uint16_t high;

    if (list->count == 0)
        return 1;

    low = list->entries[0].networkAddress;
    high = list->entries[list->count - 1].networkAddress;

    if (low > high)
    {
        low = list->entries[list->count - 1].networkAddress;
        high = list->entries[0].networkAddress;
    }

    if (list->firstFrame)
        low = 0;

    if (list->lastFrame)
        high = 0xffff;

    return own >= low && own <= high;
}

/* 8933: only a router or the coordinator sends one, at 0x0000 for the coordinator, so it settles the type and, by 9465,
   a receiver kept on; 7935-7936 make a router and the device it joined siblings once the join is complete, and a link
   status, secured with the network key, is that device having completed it. An end device entry it cannot be from stays. */
static void nwkLinkStatusSibling(Nwk_NeighborTableEntry *entry)
{
    if (entry->deviceType == NWK_DEVICE_END_DEVICE)
        return;

    if (entry->deviceType == NWK_NEIGHBOR_TYPE_UNKNOWN)
        entry->deviceType = entry->networkAddress == 0x0000 ? NWK_DEVICE_COORDINATOR : NWK_DEVICE_ROUTER;

    entry->rxOnWhenIdle = 1;

    if (entry->relationship != NWK_REL_BACKBONE_SIBLING)
        entry->relationship = NWK_REL_SIBLING;
}

/* 3.6.4.4.2's order: the first frame's sums for any receiver, then the range check, then the search of a frame that
   covers this device, which sets the outgoing cost or, when it names someone else, clears it. */
int Nwk_LinkStatusApply(Nwk_NeighborTableEntry *pool, uint16_t sender, uint16_t own, const Nwk_LinkStatus *list,
                        int senderWasKnown, uint32_t nowMs)
{
    Nwk_NeighborTableEntry *entry;
    uint32_t i;

    if (pool == 0 || list == 0)
        return 0;

    entry = Nwk_NeighborOf(pool, sender);

    if (entry == 0)
        return 0;

    entry->ageFromMs = nowMs;
    entry->age = 0;

    nwkLinkStatusSibling(entry);

    if (list->firstFrame)
    {
        if (senderWasKnown && entry->routerAge < NWK_ROUTER_AGE_MAX)
            entry->routerAge++;

        entry->routerConnectivity = Nwk_LinkStatusConnectivity(list);
        entry->routerNeighborSetDiversity = Nwk_LinkStatusDiversity(list, pool);
    }

    if (!nwkLinkStatusCovers(list, own))
        return 0;

    entry->outgoingCost = 0;

    for (i = 0; i < list->count; i++)
    {
        if (list->entries[i].networkAddress != own)
            continue;

        entry->outgoingCost = list->entries[i].incomingCost;
        break;
    }

    return 1;
}

/* 7338 and 7341: every router neighbour, which is how one that has not listed this device yet learns it was heard. */
static int nwkLinkStatusStates(const Nwk_NeighborTableEntry *entry)
{
    if (!entry->inUse)
        return 0;

    return entry->deviceType == NWK_DEVICE_ROUTER || entry->deviceType == NWK_DEVICE_COORDINATOR;
}

/* The stated entry with the lowest address at or above `from`, or -1 when none is left. */
static int nwkLinkStatusNext(const Nwk_NeighborTableEntry *pool, uint32_t from)
{
    int best = -1;
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!nwkLinkStatusStates(&pool[i]) || pool[i].networkAddress < from)
            continue;

        if (best < 0 || pool[i].networkAddress < pool[best].networkAddress)
            best = (int)i;
    }

    return best;
}

/* 3.4.8.3.2: an entry's incoming cost is this device's own estimate for the neighbour, from what it measures of it, and
   its outgoing cost is the neighbour table's; a next frame starts on the address this one ended on, so a frame that
   holds one entry and leaves others could never finish. */
ZbStatus Nwk_LinkStatusCompose(const Nwk_NeighborTableEntry *pool, int firstFrame, uint16_t fromAddress, uint8_t *out,
                               uint32_t outCap, uint32_t *outLen, uint32_t *entryCount, int *lastFrame,
                               uint16_t *lastAddress)
{
    const Nwk_NeighborTableEntry *entry;
    U_BStream stream;
    uint32_t cursor = fromAddress;
    uint32_t count = 0;
    uint32_t capacity;
    uint32_t cost;
    uint32_t incoming;
    uint8_t options;
    int next;
    int more;

    if (pool == 0 || out == 0 || outLen == 0 || lastFrame == 0 || lastAddress == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (outCap < 1)
        return ZB_ERR_NO_SPACE;

    capacity = (outCap - 1) / NWK_LINK_STATUS_ENTRY_LEN;

    if (capacity > NWK_LINK_STATUS_ENTRY_MAX)
        capacity = NWK_LINK_STATUS_ENTRY_MAX;

    U_bstream_init(&stream, out, (unsigned long)outCap);
    U_bstream_advance(&stream, 1);

    while (count < capacity)
    {
        next = nwkLinkStatusNext(pool, cursor);

        if (next < 0)
            break;

        entry = &pool[next];
        cost = entry->outgoingCost > NWK_LINK_STATUS_COST_MAX ? NWK_LINK_STATUS_COST_MAX : entry->outgoingCost;
        incoming = Nwk_CostFromLqa(entry->lqi);

        U_bstream_put_u16_le(&stream, entry->networkAddress);
        U_bstream_put_u8(&stream, (uint8_t)((incoming & 0x07) | ((cost & 0x07) << 4)));

        *lastAddress = entry->networkAddress;
        cursor = (uint32_t)entry->networkAddress + 1;
        count++;
    }

    more = nwkLinkStatusNext(pool, cursor) >= 0;

    if (more && count < 2)
        return ZB_ERR_NO_SPACE;

    options = (uint8_t)(count & 0x1f);

    if (firstFrame)
        options = (uint8_t)(options | NWK_LINK_STATUS_OPTIONS_FIRST);

    if (!more)
        options = (uint8_t)(options | NWK_LINK_STATUS_OPTIONS_LAST);

    Zb_bstream_put_u8_at(&stream, 0, options);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = Zb_bstream_pos(&stream);
    *lastFrame = !more;

    if (entryCount != 0)
        *entryCount = count;

    return ZB_OK;
}

/* 3.6.4.4.3's rank: 4 * diversity + connectivity + 8 * outbound + 8 * inbound, each term capped where Table 3-75
   caps its field so a saturated counter cannot wrap the sum. */
uint32_t Nwk_NeighborRank(const Nwk_NeighborTableEntry *entry)
{
    uint32_t rank;

    if (entry == 0)
        return 0;

    rank = 4 * entry->routerNeighborSetDiversity;
    rank += entry->routerConnectivity;
    rank += 8 * entry->routerOutboundActivity;
    rank += 8 * entry->routerInboundActivity;

    return rank;
}

/* 8990-8992: a sibling observed past the window. */
static int nwkNeighborInPool(const Nwk_NeighborTableEntry *entry, uint32_t minObservationAge)
{
    return entry->inUse && entry->relationship == NWK_REL_SIBLING && entry->routerAge > minObservationAge;
}

uint32_t Nwk_NeighborAssessmentPool(const Nwk_NeighborTableEntry *pool, uint32_t minObservationAge, int *out,
                                    uint32_t outMax)
{
    uint32_t count = 0;
    uint32_t i;

    if (pool == 0)
        return 0;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!nwkNeighborInPool(&pool[i], minObservationAge))
            continue;

        if (out != 0 && count < outMax)
            out[count] = (int)i;

        count++;
    }

    return count;
}

/* 3.6.4.4.3.1: the lowest-ranked of the assessment pool, whose siblings are neither a backbone router nor an end-device
   child; -1 when the pool is empty, on which 8992-8993 drop the frame. */
int Nwk_NeighborMakeRoom(const Nwk_NeighborTableEntry *pool, uint32_t minObservationAge)
{
    int lowest = -1;
    uint32_t lowestRank = 0;
    uint32_t rank;
    uint32_t i;

    if (pool == 0)
        return -1;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!nwkNeighborInPool(&pool[i], minObservationAge))
            continue;

        rank = Nwk_NeighborRank(&pool[i]);

        if (lowest >= 0 && rank >= lowestRank)
            continue;

        lowest = (int)i;
        lowestRank = rank;
    }

    return lowest;
}

/* What an entry stands at in that ranking: a backbone sibling keeps its place until the metrics change considerably
   (9007-9008), and a sibling is its rank. */
static uint32_t nwkLinkStatusStanding(const Nwk_NeighborTableEntry *entry)
{
    uint32_t rank = Nwk_NeighborRank(entry);

    if (entry->relationship != NWK_REL_BACKBONE_SIBLING)
        return rank;

    return rank + rank / NWK_BACKBONE_HOLD_DIVISOR + NWK_BACKBONE_HOLD_FRAME;
}

/* 3.6.4.4.3.1's promotion: the backbone siblings and the assessment pool ranked together, the top `backboneMax`
   becoming backbone mesh siblings. Ties keep the entry that already holds the relationship, so a pass over an
   unchanged table changes nothing. */
uint32_t Nwk_NeighborPromoteBackbone(Nwk_NeighborTableEntry *pool, uint32_t formationAge, uint32_t backboneMax)
{
    uint32_t chosen[NWK_NEIGHBOR_MAX];
    uint32_t chosenCount = 0;
    uint32_t wanted;
    uint32_t rank;
    uint32_t best;
    uint32_t bestRank;
    uint32_t changed = 0;
    uint32_t i;
    uint32_t j;

    if (pool == 0)
        return 0;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (pool[i].relationship != NWK_REL_SIBLING && pool[i].relationship != NWK_REL_BACKBONE_SIBLING)
            continue;

        if (pool[i].routerAge <= formationAge)
            continue;

        chosen[chosenCount++] = i;
    }

    if (chosenCount == 0)
        return 0;

    wanted = chosenCount < backboneMax ? chosenCount : backboneMax;

    for (i = 0; i < wanted; i++)
    {
        best = i;
        bestRank = nwkLinkStatusStanding(&pool[chosen[i]]);

        for (j = i + 1; j < chosenCount; j++)
        {
            rank = nwkLinkStatusStanding(&pool[chosen[j]]);

            if (rank > bestRank || (rank == bestRank && pool[chosen[j]].relationship == NWK_REL_BACKBONE_SIBLING))
            {
                best = j;
                bestRank = rank;
            }
        }

        if (best != i)
        {
            rank = chosen[i];
            chosen[i] = chosen[best];
            chosen[best] = rank;
        }
    }

    for (i = 0; i < chosenCount; i++)
    {
        uint32_t wantedRelationship = i < wanted ? NWK_REL_BACKBONE_SIBLING : NWK_REL_SIBLING;

        if (pool[chosen[i]].relationship == wantedRelationship)
            continue;

        pool[chosen[i]].relationship = wantedRelationship;
        changed++;
    }

    return changed;
}
