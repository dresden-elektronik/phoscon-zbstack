#ifndef NWK_TIMEOUT_H
#define NWK_TIMEOUT_H

/* 3.4.11's End Device Timeout Request and 3.4.12's response, Table 3-58's enumeration that turns one into seconds,
   and 3.6.10's aging of a child's neighbour entry; docs/internals/conformance.md owns the clause marks. */

#include <stdint.h>

#include "nwk_neighbor.h"
#include "zb_status.h"

enum
{
    NWK_TIMEOUT_REQUEST_OCTETS = 2,     /* Figure 3-31: the requested enumeration and the configuration field */
    NWK_TIMEOUT_RESPONSE_OCTETS = 2,    /* Figure 3-32: the status and the parent information bitmask */

    NWK_TIMEOUT_MAX = 14,               /* Table 3-58 prints 0 to 14 */

    /* Table 3-61's statuses */
    NWK_TIMEOUT_STATUS_SUCCESS = 0x00,
    NWK_TIMEOUT_STATUS_INCORRECT_VALUE = 0x01,
    NWK_TIMEOUT_STATUS_UNSUPPORTED_FEATURE = 0x02,

    /* Table 3-62: bit 0 is the MAC data poll keepalive, bit 1 the timeout request's own keepalive */
    NWK_PARENT_INFORMATION_MAC_DATA_POLL = 0x01,
    NWK_PARENT_INFORMATION_TIMEOUT_REQUEST = 0x02,

    NWK_END_DEVICE_TIMEOUT_DEFAULT = 8, /* Table 3-66's nwkEndDeviceTimeoutDefault (0xAC), an enumeration of Table 3-58 */

    NWK_TIMEOUT_SECONDS_FIRST = 10,     /* Table 3-58's value for enumeration 0 */
    NWK_TIMEOUT_MINUTES_FIRST = 2       /* and for enumeration 1, which every later one doubles */
};

/* Table 3-58's actual timeout in seconds for an enumeration, 0 for one outside 0-14. */
uint32_t Nwk_TimeoutSeconds(uint32_t enumeration);

/* 3.6.10.5's starting values for a child's entry: Device Timeout and the Timeout Counter both at
   nwkEndDeviceTimeoutDefault, the counter's clock started at `nowMs`. */
void Nwk_TimeoutDefault(Nwk_NeighborTableEntry *entry, uint32_t nowMs);

/* The counter back at the entry's Device Timeout and its clock restarted, which a Timeout Request (3.6.10.2 step 4) and
   a keepalive poll (3.6.10.4 step 2) both do. */
void Nwk_TimeoutRestart(Nwk_NeighborTableEntry *entry, uint32_t nowMs);

/* 3.4.11's payload, both fields printed. */
ZbStatus Nwk_TimeoutRequestParse(const uint8_t *payload, uint32_t payloadLen, uint32_t *enumerationOut,
                                 uint8_t *configurationOut);

ZbStatus Nwk_TimeoutRequestCompose(uint32_t enumeration, uint8_t configuration, uint8_t *out, uint32_t outCap,
                                   uint32_t *outLen);

/* 3.4.12's payload. */
ZbStatus Nwk_TimeoutResponseCompose(uint8_t status, uint8_t parentInformation, uint8_t *out, uint32_t outCap,
                                    uint32_t *outLen);

ZbStatus Nwk_TimeoutResponseParse(const uint8_t *payload, uint32_t payloadLen, uint8_t *statusOut,
                                  uint8_t *parentInformationOut);

#endif
