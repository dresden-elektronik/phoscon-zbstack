#ifndef APS_BIND_H
#define APS_BIND_H

/*
 * 2.2.8.2's binding table: Table 2-24's `apsBindingTable`, the entry Table 2-6 prints, and 2.2.4.1.1.3's search that
 * turns a destination mode of 0x00 into a list of recipients.
 * docs/internals/conformance.md §3 owns the clause marks; the two APSME services and their membership gate are the façade's.
 */

#include <stdint.h>

#include "zb_limits.h"
#include "zb_status.h"

enum
{
    APS_BIND_MAX = ZB_LIMIT_APS_BIND /* a house size: Table 2-24 prints no count */
};

/* Figure 2-28's entry: the source it binds, the cluster, and where the frames go. */
typedef struct Aps_Binding
{
    int inUse;
    uint64_t srcIeee;
    uint8_t srcEndpoint;
    uint16_t clusterId;
    uint32_t dstAddrMode;           /* 0x01 group or 0x03 extended: Table 2-6's two non-reserved modes */
    uint16_t dstAddress;
    uint64_t dstExtendedAddress;
    uint8_t dstEndpoint;
} Aps_Binding;

enum
{
    APS_BIND_ADDED = 0,             /* a row was free and took the entry */
    APS_BIND_PRESENT = 1,           /* the table already held this entry, which the binding procedure answers SUCCESS to */
    APS_BIND_FULL = 2,              /* 2.2.8.2.2's TABLE_FULL: no row free */
    APS_BIND_REMOVED = 3,           /* the entry was there and is gone */
    APS_BIND_MISSING = 4,           /* 2.2.8.2.2's INVALID_BINDING: the entry was not there */
    APS_BIND_ILLEGAL = 5            /* ILLEGAL_REQUEST: the table is not there, or the parameters are out of range */
};

/* An entry already present is not duplicated. */
uint32_t Aps_BindAdd(Aps_Binding *pool, const Aps_Binding *entry);

/* Every field must match, which is what makes an unbind of one entry not another. */
uint32_t Aps_BindRemove(Aps_Binding *pool, const Aps_Binding *entry);

/* 2.2.8.2.1's mapping: a device's own frames are fan-out searched among the entries whose source it is, under the
   request's endpoint and cluster. */
uint32_t Aps_BindOf(const Aps_Binding *pool, uint64_t srcIeee, uint8_t srcEndpoint, uint16_t clusterId,
                    uint32_t *out, uint32_t outMax);

/* The one entry a search would find first, 0 when the table holds none. */
const Aps_Binding *Aps_BindFind(const Aps_Binding *pool, uint64_t srcIeee, uint8_t srcEndpoint, uint16_t clusterId);

/* Table 2-6's three printed ranges: the source endpoint, the destination mode, and the destination endpoint a mode
   of 0x03 carries and a mode of 0x01 must not. */
ZbStatus Aps_BindCheck(const Aps_Binding *entry);

/* The entry at that index in the table's own order, 0 when the table holds no such element. */
const Aps_Binding *Aps_BindEntryAt(const Aps_Binding *pool, uint32_t index);

uint32_t Aps_BindCount(const Aps_Binding *pool);

#endif
