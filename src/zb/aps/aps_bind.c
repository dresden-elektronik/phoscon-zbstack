#include "aps_bind.h"

#include "zb_utils.h"

/* R23.1: 2.2.4.1.1.3, 2.2.8.2, Table 2-6, Table 2-24 ok. */

/* The source endpoint is 0x01-0xfe, the destination mode is one of Table 2-6's two non-reserved values, and the
   destination endpoint is present for exactly one of them. */
ZbStatus Aps_BindCheck(const Aps_Binding *entry)
{
    if (entry == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (entry->srcEndpoint < 0x01 || entry->srcEndpoint > 0xfe)
        return ZB_ERR_BAD_ARGUMENT;

    if (entry->dstAddrMode == 0x01)
    {
        if (entry->dstEndpoint != 0)
            return ZB_ERR_BAD_ARGUMENT;

        return ZB_OK;
    }

    if (entry->dstAddrMode != 0x03)
        return ZB_ERR_BAD_ARGUMENT;

    if (entry->dstEndpoint < 0x01 || entry->dstEndpoint > 0xfe)
        return ZB_ERR_BAD_ARGUMENT;

    return ZB_OK;
}

/* Table 2-6's index into the table as it lies: the index-th entry in use, whole. */
const Aps_Binding *Aps_BindEntryAt(const Aps_Binding *pool, uint32_t index)
{
    uint32_t seen = 0;
    uint32_t i;

    if (pool == 0)
        return 0;

    for (i = 0; i < APS_BIND_MAX; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (seen == index)
            return &pool[i];

        seen++;
    }

    return 0;
}

/* Two entries are one entry when every field Table 2-6 prints is equal. */
static int apsBindSame(const Aps_Binding *left, const Aps_Binding *right)
{
    if (left->srcIeee != right->srcIeee || left->srcEndpoint != right->srcEndpoint)
        return 0;

    if (left->clusterId != right->clusterId || left->dstAddrMode != right->dstAddrMode)
        return 0;

    if (left->dstAddress != right->dstAddress || left->dstEndpoint != right->dstEndpoint)
        return 0;

    if (left->dstAddrMode == 0x03 && left->dstExtendedAddress != right->dstExtendedAddress)
        return 0;

    return 1;
}

uint32_t Aps_BindAdd(Aps_Binding *pool, const Aps_Binding *entry)
{
    uint32_t i;

    if (pool == 0 || entry == 0)
        return APS_BIND_ILLEGAL;

    for (i = 0; i < APS_BIND_MAX; i++)
    {
        if (!pool[i].inUse || !apsBindSame(&pool[i], entry))
            continue;

        return APS_BIND_PRESENT;
    }

    for (i = 0; i < APS_BIND_MAX; i++)
    {
        if (pool[i].inUse)
            continue;

        pool[i] = *entry;
        pool[i].inUse = 1;

        return APS_BIND_ADDED;
    }

    return APS_BIND_FULL;
}

uint32_t Aps_BindRemove(Aps_Binding *pool, const Aps_Binding *entry)
{
    uint32_t i;

    if (pool == 0 || entry == 0)
        return APS_BIND_ILLEGAL;

    for (i = 0; i < APS_BIND_MAX; i++)
    {
        if (!pool[i].inUse || !apsBindSame(&pool[i], entry))
            continue;

        Zb_memset(&pool[i], 0, (uint32_t)sizeof pool[i]);

        return APS_BIND_REMOVED;
    }

    return APS_BIND_MISSING;
}

uint32_t Aps_BindOf(const Aps_Binding *pool, uint64_t srcIeee, uint8_t srcEndpoint, uint16_t clusterId,
                    uint32_t *out, uint32_t outMax)
{
    uint32_t count = 0;
    uint32_t i;

    if (pool == 0)
        return 0;

    for (i = 0; i < APS_BIND_MAX; i++)
    {
        if (!pool[i].inUse || pool[i].srcEndpoint != srcEndpoint || pool[i].srcIeee != srcIeee)
            continue;

        if (pool[i].clusterId != clusterId)
            continue;

        if (out != 0 && count < outMax)
            out[count] = i;

        count++;
    }

    return count;
}

const Aps_Binding *Aps_BindFind(const Aps_Binding *pool, uint64_t srcIeee, uint8_t srcEndpoint, uint16_t clusterId)
{
    uint32_t i;

    if (pool == 0)
        return 0;

    for (i = 0; i < APS_BIND_MAX; i++)
    {
        if (!pool[i].inUse || pool[i].srcEndpoint != srcEndpoint || pool[i].srcIeee != srcIeee)
            continue;

        if (pool[i].clusterId != clusterId)
            continue;

        return &pool[i];
    }

    return 0;
}

uint32_t Aps_BindCount(const Aps_Binding *pool)
{
    uint32_t count = 0;
    uint32_t i;

    if (pool == 0)
        return 0;

    for (i = 0; i < APS_BIND_MAX; i++)
    {
        if (pool[i].inUse)
            count++;
    }

    return count;
}
