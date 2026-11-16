#ifndef NWK_INDIRECT_H
#define NWK_INDIRECT_H

/*
 * The copies a broadcast owes the devices that cannot hear it; docs/internals/conformance.md §1 and §9.5 own their contract.
 */

#include <stdint.h>

#include "mac.h"
#include "nwk_neighbor.h"
#include "security.h"
#include "zb_status.h"

/* One pass of 3.6.6 step 1 over the caller's neighbor table; `deviceType` is the role, not this device's receiver state. */
ZbStatus Nwk_IndirectTransactionCopies(const Nwk_NeighborTableEntry *neighbors, uint32_t deviceType, Mac_Mac *mac,
                                         Security *security, uint16_t dstAddr, uint16_t srcAddr,
                                         const uint8_t *npdu, uint32_t npduLen, uint32_t headerLen,
                                         int secured, uint8_t *scratch, uint32_t scratchMax, uint32_t nowMs);

#endif /* NWK_INDIRECT_H */
