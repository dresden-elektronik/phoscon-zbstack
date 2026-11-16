#ifndef NWK_RREQ_H
#define NWK_RREQ_H

/*
 * The Route Request command of 3.4.1.3; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "nwk_frame.h"
#include "nwk_tlv.h"
#include "zb_status.h"

enum
{
    /* Figure 3-9's fields, with the identifier octet 3.4.1.3 puts ahead of them (Table 3-54) */
    NWK_RREQ_FIXED_OCTETS = 6,      /* identifier, command options, request id, destination 2, path cost */
    NWK_RREQ_PATH_COST_OCTET = 5,   /* 3.4.1.3.4: the one fixed field 9109-9110 rewrites in a relay */

    /* Figure 3-10's bits: 0-2 reserved (0), 3-4 many-to-one, 5 destination IEEE address, 6 deprecated, 7 reserved */
    NWK_RREQ_OPTION_MANY_TO_ONE_SHIFT = 3,
    NWK_RREQ_OPTION_MANY_TO_ONE_MASK = 3,
    NWK_RREQ_OPTION_MANY_TO_ONE_RESERVED = 3, /* Table 3-55's third value */
    NWK_RREQ_OPTION_DEST_IEEE = 0x20,
    NWK_RREQ_OPTION_MULTICAST = 0x40,         /* deprecated 3.6.7: transmitted 0 and read as a frame this stack is not */
    NWK_RREQ_OPTION_RESERVED_MASK = 0x87,     /* bits 0-2 and 7: 1.4.2 zeroes them on transmission and ignores them on receipt */

    NWK_RREQ_MANY_TO_ONE_NONE = 0,  /* Table 3-55: not a many-to-one route request */
    NWK_RREQ_MANY_TO_ONE_WITH_RECORD = 1,     /* many-to-one, and the sender supports a route record table */
    NWK_RREQ_MANY_TO_ONE_WITHOUT_RECORD = 2,  /* many-to-one, and the sender does not */

    /* Table I-1's overhead twice and Figure K-1's value: the longest payload this module writes */
    NWK_RREQ_PAYLOAD_MAX = NWK_RREQ_FIXED_OCTETS + NWK_IEEE_ADDR_OCTETS
                           + NWK_TLV_HEADER_OCTETS + NWK_TLV_EXTENDED_ROUTE_OCTETS
                           + NWK_TLV_HEADER_OCTETS + NWK_TLV_CONCENTRATOR_OCTETS,

    NWK_ROUTE_SEQUENCE_WRAP = 0x10000 /* nwkRoutingSequenceNumber, NIB 0xBE, is 0-0xffff (Table 3-66) */
};

/* Figure 3-9, the route request payload: `requestId`, `destAddr`, `pathCost`, `destIeee` are its rows and its
   Command options row is `manyToOne`/`destIeeePresent` (Figure 3-10); its TLVs row is Figure K-2's
   `concentratorDiscoveryTime`/`maxSourceRoute`, K.2.1.1's record being the compose's, and `concentrator` is ours. */
typedef struct Nwk_RouteRequestPayload
{
    uint8_t requestId;
    uint16_t destAddr;
    uint8_t pathCost;
    uint32_t manyToOne;
    int destIeeePresent;
    uint64_t destIeee;
    int concentrator;
    uint8_t concentratorDiscoveryTime;
    uint8_t maxSourceRoute;
} Nwk_RouteRequestPayload;

/* Figure 3-9 as read: its rows under the payload's names, and `tlvOutcome`, `extendedRouteInfo`,
   `concentratorInfoPresent`, `solicitationPresent` plus `routingSequenceNumber`/`initialRadius`, the parse's
   outcome and K.2.1's records, which the figure does not print: Figure K-1's pair, no label of its own naming them. */
typedef struct Nwk_RouteRequestFields
{
    uint8_t requestId;
    uint16_t destAddr;
    uint8_t pathCost;
    uint32_t manyToOne;
    int destIeeePresent;
    uint64_t destIeee;
    Nwk_TlvOutcome tlvOutcome;
    int extendedRouteInfo;
    uint16_t routingSequenceNumber;
    uint8_t initialRadius;
    int concentratorInfoPresent;
    int solicitationPresent;
} Nwk_RouteRequestFields;

/* Compose 3.4.1.3's payload with K.2.1.1's route-information TLV and, for a 0xfffc destination, K.2.1.2's. */
ZbStatus Nwk_RreqCompose(const Nwk_RouteRequestPayload *req, uint32_t *routingSeq, uint8_t initialRadius,
                         uint8_t *out, uint32_t outMax, uint32_t *outLen);

/* A forwarder's request: 3.4.1.3.4's path cost replaced by 9109-9110's, every other octet as it arrived. */
ZbStatus Nwk_RreqComposeRelay(const uint8_t *received, uint32_t receivedLen, uint8_t pathCost,
                              uint8_t *out, uint32_t outMax, uint32_t *outLen);

/* Read 3.4.1.3's payload: Table 3-55's reserved many-to-one value and Figure 3-10's deprecated multicast bit are
   refused, while the reserved bits are ignored as 1.4.2 asks of a receiver. */
ZbStatus Nwk_RreqParse(const uint8_t *payload, uint32_t payloadLen, Nwk_RouteRequestFields *out);

#endif /* NWK_RREQ_H */
