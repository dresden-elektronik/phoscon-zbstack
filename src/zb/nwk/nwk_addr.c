#include "nwk_addr.h"

#include "nwk.h"
#include "nwk_frame.h"
#include "radio.h"
#include "zb_utils.h"

/* R23.1: 3.2.1.1.3, 3.3.1.2, 3.3.1.3, 3.6.1.10.1, 3.6.1.10.2, 3.6.2.2, 3.6.6 ok (the classes, the PIB reads, the BTT
   duty, Table 3-68's map; 0xfffb names the low power routers and this device is none, so 3.6.6 discards it). */

/* Table 3-80's four destination classes, 0xffff 0xfffd 0xfffc 0xfffb, with 0xfffe and 0xfff8-0xfffa printed Reserved: a class names devices, a reserved value names none (3.6.6) */
int Nwk_AddrIsBroadcast(uint16_t address)
{
    if (address < NWK_ADDR_LOW_POWER_ROUTERS)
        return 0;

    if (address == NWK_ADDR_RESERVED)
        return 0;

    return 1;
}

int Nwk_AddrIsReserved(uint16_t address)
{
    if (address == NWK_ADDR_RESERVED)
        return 1;

    if (address >= NWK_ADDR_RESERVED_LOW && address < NWK_ADDR_LOW_POWER_ROUTERS)
        return 1;

    return 0;
}

/* 3.3.1.3 sets the source field from macShortAddress, read off the PIB mirror `mac` keeps, and 3.3.1.2's closing note says the same of a device's own address. Everything from 0xfff8 up is no unicast address: Table 3-80 makes it two reserved rows and four classes, and 0xffff is the default Table 3-66 prints. */
int Nwk_AddrOwn(const Radio_Pib *pib, uint16_t *outAddress)
{
    if (pib == 0 || outAddress == 0)
        return 0;

    if ((pib->present & RADIO_PIB_SHORT_ADDRESS) == 0)
        return 0;

    if (pib->shortAddress > NWK_ADDR_LAST_UNICAST)
        return 0;

    *outAddress = pib->shortAddress;

    return 1;
}

/* The same mirror's macRxOnWhenIdle, which Table 3-80's 0xfffd row and 3.6.6 read: a mirror that never named it reads as not listening, the MAC attribute's own default being FALSE */
int Nwk_AddrOwnRxOnWhenIdle(const Radio_Pib *pib)
{
    if (pib == 0)
        return 0;

    if ((pib->present & RADIO_PIB_RX_ON_WHEN_IDLE) == 0)
        return 0;

    return pib->rxOnWhenIdle ? 1 : 0;
}

/* The device-type half of 3.6.6's retransmission duty and of its BTT, taken off `cfg.deviceType`, whose three values are the only ones `Nwk_Init` takes; the radius half is the relay path's, which asks it beside this predicate. 3.6.2.2's "operating Zigbee router" has no state in this stack to answer it, so a caller that needs that qualifier does not get it here. */
int Nwk_AddrHasRoutingDuty(uint32_t deviceType)
{
    if (deviceType == NWK_DEVICE_COORDINATOR || deviceType == NWK_DEVICE_ROUTER)
        return 1;

    return 0;
}

/* Whether this device keeps a broadcast transaction table: 3.6.6's coordinator, its routers, and those end devices whose macRxOnWhenIdle is TRUE, a sleepy one being allowed to keep none for the frames it originates (docs/internals/conformance.md §2) */
int Nwk_AddrKeepsBtt(uint32_t deviceType, int rxOnWhenIdle)
{
    if (Nwk_AddrHasRoutingDuty(deviceType))
        return 1;

    return rxOnWhenIdle ? 1 : 0;
}

/* Table 3-80 as 3.6.6 applies it: the destination against this device's type and receiver duty. 0xfffb is the
   low-power routers' class, a kind R23.1 never defines beyond that row and this stack has no way to be. Sending to it is
   3.6.6's business like any other class; how the MAC carries it is what 3.2.1.1.3 step 6 leaves open. */
int Nwk_AddrClassAccepts(uint16_t address, uint32_t deviceType, int rxOnWhenIdle)
{
    if (address == NWK_ADDR_ALL_DEVICES)
        return 1;

    if (address == NWK_ADDR_ROUTERS)
        return Nwk_AddrHasRoutingDuty(deviceType);

    if (address == NWK_ADDR_RX_ON_WHEN_IDLE)
        return rxOnWhenIdle;

    return 0;
}

/* A pair meeting both a row that holds its IEEE address elsewhere and a row at its network address that holds none is
   one device: the IEEE row takes the address, being the one that names the device, and the null row goes, whichever
   the pool holds first; this device's own address is the conflict rule's, never merged. */
static int nwkAddrMapMergeNull(Nwk_AddressMapEntry *pool, uint16_t networkAddress, uint64_t extendedAddress,
                               uint16_t ownAddress, uint32_t nowMs)
{
    Nwk_AddressMapEntry *ieeeRow = 0;
    Nwk_AddressMapEntry *nullRow = 0;
    uint32_t i;

    if (networkAddress == ownAddress)
        return 0;

    for (i = 0; i < NWK_ADDR_MAP_MAX; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (pool[i].extendedAddress == extendedAddress && pool[i].networkAddress != networkAddress)
            ieeeRow = &pool[i];
        else if (pool[i].networkAddress == networkAddress && pool[i].extendedAddress == 0)
            nullRow = &pool[i];
    }

    if (ieeeRow == 0 || nullRow == 0)
        return 0;

    Zb_memset(nullRow, 0, (uint32_t)sizeof *nullRow);
    ieeeRow->networkAddress = networkAddress;
    ieeeRow->seenMs = nowMs;

    return 1;
}

Nwk_AddrMapVerdict Nwk_AddrMapLearn(Nwk_AddressMapEntry *pool, uint16_t networkAddress, uint64_t extendedAddress,
                                    uint16_t ownAddress, uint32_t nowMs)
{
    Nwk_AddressMapEntry *freeSlot;
    Nwk_AddressMapEntry *entry;
    uint32_t i;

    if (pool == 0)
        return NWK_ADDRMAP_IGNORED;

    if (extendedAddress == 0)
        return NWK_ADDRMAP_IGNORED;

    if (networkAddress > NWK_ADDR_LAST_UNICAST)
        return NWK_ADDRMAP_IGNORED;

    if (nwkAddrMapMergeNull(pool, networkAddress, extendedAddress, ownAddress, nowMs))
        return NWK_ADDRMAP_UPDATED;

    freeSlot = 0;

    for (i = 0; i < NWK_ADDR_MAP_MAX; i++)
    {
        entry = &pool[i];

        if (!entry->inUse)
        {
            if (freeSlot == 0)
                freeSlot = entry;

            continue;
        }

        if (entry->networkAddress == networkAddress && entry->extendedAddress == extendedAddress)
        {
            entry->seenMs = nowMs;

            return NWK_ADDRMAP_IGNORED;
        }

        if (entry->networkAddress == networkAddress && entry->extendedAddress == 0)
        {
            entry->extendedAddress = extendedAddress;
            entry->seenMs = nowMs;

            return NWK_ADDRMAP_UPDATED;
        }

        if (entry->extendedAddress == extendedAddress && entry->networkAddress != networkAddress)
        {
            entry->networkAddress = networkAddress;
            entry->seenMs = nowMs;

            return NWK_ADDRMAP_UPDATED;
        }

        if (entry->networkAddress == networkAddress || entry->extendedAddress == extendedAddress)
        {
            if (networkAddress == ownAddress)
                return NWK_ADDRMAP_CONFLICT_LOCAL;

            return NWK_ADDRMAP_CONFLICT_OTHER;
        }
    }

    if (freeSlot == 0)
        return NWK_ADDRMAP_FULL;

    freeSlot->inUse = 1;
    freeSlot->networkAddress = networkAddress;
    freeSlot->extendedAddress = extendedAddress;
    freeSlot->seenMs = nowMs;

    return NWK_ADDRMAP_LEARNED;
}

int Nwk_AddrMapShortOf(const Nwk_AddressMapEntry *pool, uint64_t extendedAddress, uint16_t *outAddress)
{
    uint32_t i;

    if (pool == 0 || outAddress == 0 || extendedAddress == 0)
        return 0;

    for (i = 0; i < NWK_ADDR_MAP_MAX; i++)
    {
        if (!pool[i].inUse || pool[i].extendedAddress != extendedAddress)
            continue;

        *outAddress = pool[i].networkAddress;

        return 1;
    }

    return 0;
}

int Nwk_AddrMapExtendedOf(const Nwk_AddressMapEntry *pool, uint16_t networkAddress, uint64_t *outExtended)
{
    uint32_t i;

    if (pool == 0 || outExtended == 0)
        return 0;

    for (i = 0; i < NWK_ADDR_MAP_MAX; i++)
    {
        if (!pool[i].inUse || pool[i].networkAddress != networkAddress)
            continue;

        if (pool[i].extendedAddress == 0)
            return 0;

        *outExtended = pool[i].extendedAddress;

        return 1;
    }

    return 0;
}

uint32_t Nwk_AddrMapCount(const Nwk_AddressMapEntry *pool)
{
    uint32_t count = 0;
    uint32_t i;

    if (pool == 0)
        return 0;

    for (i = 0; i < NWK_ADDR_MAP_MAX; i++)
    {
        if (pool[i].inUse)
            count++;
    }

    return count;
}

ZbStatus Nwk_AddrMapSeedOwn(Nwk_AddressMapEntry *pool, uint16_t ownAddress, uint64_t ownExtended, uint32_t nowMs)
{
    uint32_t i;

    if (pool == 0)
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < NWK_ADDR_MAP_MAX; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (pool[i].networkAddress != ownAddress)
            continue;

        pool[i].extendedAddress = ownExtended;
        pool[i].seenMs = nowMs;

        return ZB_OK;
    }

    for (i = 0; i < NWK_ADDR_MAP_MAX; i++)
    {
        if (pool[i].inUse)
            continue;

        pool[i].inUse = 1;
        pool[i].networkAddress = ownAddress;
        pool[i].extendedAddress = ownExtended;
        pool[i].seenMs = nowMs;

        return ZB_OK;
    }

    return ZB_ERR_NO_SPACE;
}
