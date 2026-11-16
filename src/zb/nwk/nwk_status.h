#ifndef NWK_STATUS_H
#define NWK_STATUS_H

/*
 * The receive half of 3.6.4.8.1's Network Status; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "nwk_neighbor.h"

/* Table 3-56's payload codes this module answers, 0x00 and 0x01 being 0x02's legacy pair. */
enum
{
    NWK_STATUS_CODE_LEGACY_NO_ROUTE = 0x00,
    NWK_STATUS_CODE_LEGACY_LINK_FAILURE = 0x01,
    NWK_STATUS_CODE_LINK_FAILURE = 0x02,
    NWK_STATUS_CODE_PARENT_LINK_FAILURE = 0x09,
    NWK_STATUS_CODE_SOURCE_ROUTE_FAILURE = 0x0b,
    NWK_STATUS_CODE_MANY_TO_ONE_FAILURE = 0x0c,
    NWK_STATUS_CODE_ADDRESS_CONFLICT = 0x0d,
    NWK_STATUS_CODE_PAN_ID_UPDATE = 0x0f,
    NWK_STATUS_CODE_NETWORK_ADDRESS_UPDATE = 0x10,
    NWK_STATUS_CODE_UNKNOWN_COMMAND = 0x13,

    /* 3.4.3.3.1's status code, then 3.4.3.3.2's destination address, which is present "in case of a routing
       failure" and absent behind a 3.6.13 answer: the two octets this module needs are always below four */
    NWK_STATUS_PAYLOAD_MIN = 4
};

/* Figure 3-13, the network status payload: `statusCode` and `targetAddress` are its Status code and Target address rows,
   the latter 3.4.3.3.2's destination address of the failed frame; the record holds no TLVs row, and `valid` is this
   stack's, 0 when the payload ended before the address. */
typedef struct Nwk_NetworkStatusPayload
{
    int valid;
    uint32_t statusCode;
    uint16_t targetAddress;
} Nwk_NetworkStatusPayload;

/* The payload of a 0x03 command frame behind Table 3-54's identifier octet (3.4.3.3, Figure 3-13). */
Nwk_NetworkStatusPayload Nwk_StatusRead(const uint8_t *payload, uint32_t payloadLen);

/* 3.6.4.8.1's removal at the intended destination of a 0x01 or 0x02, for a router. */
int Nwk_StatusRemovesAtDestination(const Nwk_NetworkStatusPayload *status, uint32_t deviceType);

/* 3.6.4.8.1's parent rule: 0x00, 0x01 and 0x02 for the Table 3-75 0x01 child the frame's destination names. */
int Nwk_StatusRemovesAtParent(const Nwk_NetworkStatusPayload *status, const Nwk_NeighborTableEntry *addressed);

/* 3.6.4.8.1's 0x0b rule: the source route to the payload's destination is removed. */
int Nwk_StatusOwesSourceRouteRemoval(const Nwk_NetworkStatusPayload *status);

#endif /* NWK_STATUS_H */
