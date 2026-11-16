#ifndef NWK_ADDR_H
#define NWK_ADDR_H

/*
 * The address classes and identity predicates; docs/internals/conformance.md §2 owns their contract.
 */

#include <stdint.h>

#include "radio.h"
#include "zb_limits.h"
#include "zb_status.h"

enum
{
    /* Table 3-80 in the order it prints its rows, which puts its first Reserved row second, between two classes; the
       values below 0xfff8 are unicast addresses, Table 3-66 bounding a device's own at 0x0000-0xfff7. */
    NWK_ADDR_ALL_DEVICES = 0xffff,
    NWK_ADDR_RESERVED = 0xfffe,
    NWK_ADDR_RX_ON_WHEN_IDLE = 0xfffd,
    NWK_ADDR_ROUTERS = 0xfffc,          /* a many-to-one route request's destination (3.6.4.5.1) */
    NWK_ADDR_LOW_POWER_ROUTERS = 0xfffb,
    NWK_ADDR_RESERVED_LOW = 0xfff8,     /* the second reserved row, 0xfff8-0xfffa */
    NWK_ADDR_LAST_UNICAST = 0xfff7,     /* the last address a device of this stack may hold */
    NWK_ADDR_COORDINATOR = 0x0000,      /* the coordinator's, which has no parent to draw one */

    /* Table 3-66 prints nwkAddressMap and no size for it: a trust centre wants one row per device it may remove */
    NWK_ADDR_MAP_MAX = ZB_LIMIT_NWK_ADDR_MAP
};

/* Table 3-80's classes: a destination that names a group of devices, and one that names none. */
int Nwk_AddrIsBroadcast(uint16_t address);
int Nwk_AddrIsReserved(uint16_t address);

/* This device's own short address (3.3.1.2, 3.3.1.3) and its macRxOnWhenIdle (Table 3-80's 0xfffd row, 3.6.6), both
   read off the caller's PIB mirror. */
int Nwk_AddrOwn(const Radio_Pib *pib, uint16_t *outAddress);
int Nwk_AddrOwnRxOnWhenIdle(const Radio_Pib *pib);

/* The duty a coordinator or a router carries by its configured type, and the table that goes with it (3.6.6). The
   operating qualifier 3.6.2.2 prints is not modelled: this stack has no NLME-START-ROUTER primitive to invoke. */
int Nwk_AddrHasRoutingDuty(uint32_t deviceType);
int Nwk_AddrKeepsBtt(uint32_t deviceType, int rxOnWhenIdle);   /* the table 3.6.6 requires; Table 3-81 is its record's format */

/* Whether this device is a member of Table 3-80's group `address` (3.6.6), `rxOnWhenIdle` being this device's own PIB
   value and not a neighbour's: a receive-side test, which a send path does not use to decide what it may send. A unicast
   address is no group and answers 0, so a receive path pairs this with the device's own address. */
int Nwk_AddrClassAccepts(uint16_t address, uint32_t deviceType, int rxOnWhenIdle);

/* Table 3-68's entry: a 64-bit IEEE address, which may be the null one when it is not known, and a 16-bit network
   address. `inUse` and `seenMs` are this stack's. */
typedef struct Nwk_AddressMapEntry
{
    uint64_t extendedAddress;
    uint16_t networkAddress;
    int inUse;
    uint32_t seenMs;
} Nwk_AddressMapEntry;

/* What learning one frame's address information answered. The two conflicts are kept apart because they are two
   different acts: a local one is this device's own address, and the other is a third device's, which the caller
   reports and resolves and this module does not. */
typedef enum Nwk_AddrMapVerdict
{
    NWK_ADDRMAP_IGNORED = 0,          /* no IEEE address to learn, or one already consistent */
    NWK_ADDRMAP_LEARNED = 1,          /* a new Table 3-68 row */
    NWK_ADDRMAP_UPDATED = 2,          /* an entry whose 64-bit address was the null one */
    NWK_ADDRMAP_CONFLICT_LOCAL = 3,   /* this device's own address, held by somebody else */
    NWK_ADDRMAP_CONFLICT_OTHER = 4,   /* a third device's address, held by two 64-bit addresses */
    NWK_ADDRMAP_FULL = 5              /* no room, which the clause's third condition names */
} Nwk_AddrMapVerdict;

/* 3.6.1.10.1 and 3.6.1.10.2 over one frame's address information: the null IEEE address is no information, a
   matching row is consistency, a null row is filled (or merged into the row already naming that IEEE address), a
   different non-null row at either address is a conflict, and only then is a new row added if the pool has room. */
Nwk_AddrMapVerdict Nwk_AddrMapLearn(Nwk_AddressMapEntry *pool, uint16_t networkAddress, uint64_t extendedAddress,
                                    uint16_t ownAddress, uint32_t nowMs);

/* This device's own row, which is what makes 3.6.1.10.2's local case decidable: a frame whose network address is
   this one and whose IEEE address is not is a conflict on this device's own address. ZB_ERR_NO_SPACE when the pool
   is full. */
ZbStatus Nwk_AddrMapSeedOwn(Nwk_AddressMapEntry *pool, uint16_t ownAddress, uint64_t ownExtended, uint32_t nowMs);

/* Table 3-68 read in its two directions: the network address an IEEE address maps to, and the reverse. 0 when the
   pool holds no such row, which is also how a caller tells the two apart from a row holding 0x0000. */
int Nwk_AddrMapShortOf(const Nwk_AddressMapEntry *pool, uint64_t extendedAddress, uint16_t *outAddress);
int Nwk_AddrMapExtendedOf(const Nwk_AddressMapEntry *pool, uint16_t networkAddress, uint64_t *outExtended);

/* How many rows the pool holds (Table 3-66's nwkAddressMap, whose size R23.1 does not print). */
uint32_t Nwk_AddrMapCount(const Nwk_AddressMapEntry *pool);

#endif /* NWK_ADDR_H */
