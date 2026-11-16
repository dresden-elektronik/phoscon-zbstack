#ifndef NWK_GET_H
#define NWK_GET_H

/* 3.2.2.27's read of the NIB, narrowed to the two tables a device object reports. An index counts the entries in
   use, in the order the table lies; docs/internals/conformance.md §2 owns the clause marks. */

#include <stdint.h>

#include "nwk.h"

/* The count the report's "total entries" octet states, and the element at that index, 0 past the end. */
uint32_t Nwk_NeighborTableEntries(const Nwk_Nwk *self);
const Nwk_NeighborTableEntry *Nwk_NeighborTableAt(const Nwk_Nwk *self, uint32_t index);

uint32_t Nwk_RouteTableEntries(const Nwk_Nwk *self);
const Nwk_RoutingTableEntry *Nwk_RouteTableAt(const Nwk_Nwk *self, uint32_t index);

#endif
