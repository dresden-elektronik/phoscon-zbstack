#include "aps.h"

#include "aps_group.h"

#include "zb_utils.h"

/* R23.1 2.2.4.5 2.2.4.5.1 2.2.4.5.3 2.2.4.5.5 2.2.8.3 2.2.8.3.1 2.2.8.4.2 ok; the INVALID_PARAMETER an endpoint
   this device does not implement owes waits for the endpoint registry the layer above has not built, and the
   parameter judgement itself is the APSME doors' in aps.c. docs/internals/conformance.md pages 81-84, 101. */

/* The pair APSME-ADD-GROUP calls a repeat and APSME-REMOVE-GROUP looks for (2.2.4.5.1.3, 2.2.4.5.3.3). */
Aps_Group *Aps_GroupFind(Aps_Group *pool, uint16_t groupAddress, uint8_t endpoint)
{
    Aps_Group *slot;
    uint32_t i;

    for (i = 0; i < APS_GROUP_MAX; i++)
    {
        slot = &pool[i];

        if (slot->inUse && slot->groupAddress == groupAddress && slot->endpoint == endpoint)
            return slot;
    }

    return 0;
}

/* The first slot that holds no pair, and no eviction of one that does: the entries are what 2.2.8.4.2 delivers to. */
Aps_Group *Aps_GroupFree(Aps_Group *pool)
{
    uint32_t i;

    for (i = 0; i < APS_GROUP_MAX; i++)
    {
        if (!pool[i].inUse)
            return &pool[i];
    }

    return 0;
}

/*
 * The next member of the group at or after index `from`, or APS_NO_GROUP_MEMBER. 2.2.8.3 makes the table the
 * acceptance rule for a group frame, so a lookup answers a list of members and not a yes/no, which is what
 * 2.2.8.3.1's printed shape and Table 2-25's entry say, and what licenses the flat pool and this index order.
 */
uint32_t Aps_GroupMemberAt(const Aps_Group *pool, uint16_t groupAddress, uint32_t from)
{
    uint32_t i;

    for (i = from; i < APS_GROUP_MAX; i++)
    {
        if (pool[i].inUse && pool[i].groupAddress == groupAddress)
            return i;
    }

    return APS_NO_GROUP_MEMBER;
}

/* How many pairs the table holds: the façade's `Aps_GroupQueue`. */
uint32_t Aps_GroupCount(const Aps_Group *pool)
{
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < APS_GROUP_MAX; i++)
    {
        if (pool[i].inUse)
            count++;
    }

    return count;
}

/*
 * APSME-ADD-GROUP's act on the pool (2.2.4.5.1): a pair the table already holds is left alone and answers
 * SUCCESS, and a pool with no free slot takes nothing.
 */
uint32_t Aps_GroupAdd(Aps_Group *pool, uint16_t groupAddress, uint8_t endpoint)
{
    Aps_Group *slot;

    if (Aps_GroupFind(pool, groupAddress, endpoint) != 0)
        return APS_STATUS_SUCCESS;      

    slot = Aps_GroupFree(pool);

    if (slot == 0)
        return APS_STATUS_TABLE_FULL;      

    slot->inUse = 1;
    slot->groupAddress = groupAddress;
    slot->endpoint = endpoint;

    return APS_STATUS_SUCCESS;
}

/*
 * APSME-REMOVE-GROUP's act on the pool (2.2.4.5.3): one pair and not one group, Table 2-25's entry being a
 * group with a *list* of endpoints.
 */
uint32_t Aps_GroupRemove(Aps_Group *pool, uint16_t groupAddress, uint8_t endpoint)
{
    Aps_Group *slot;

    slot = Aps_GroupFind(pool, groupAddress, endpoint);

    if (slot == 0)
        return APS_STATUS_INVALID_GROUP;      

    Zb_memset(slot, 0, (uint32_t)sizeof *slot);

    return APS_STATUS_SUCCESS;
}

/*
 * APSME-REMOVE-ALL-GROUPS' act on the pool (2.2.4.5.5): every pair carrying the endpoint goes, SUCCESS
 * answering whether or not anything was there to remove.
 */
uint32_t Aps_GroupRemoveAll(Aps_Group *pool, uint8_t endpoint)
{
    uint32_t i;

    for (i = 0; i < APS_GROUP_MAX; i++)
    {
        if (pool[i].inUse && pool[i].endpoint == endpoint)
            Zb_memset(&pool[i], 0, (uint32_t)sizeof pool[i]);
    }

    return APS_STATUS_SUCCESS;
}

