#ifndef NWK_RREP_H
#define NWK_RREP_H

/*
 * The Route Reply command of 3.4.2.3; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "nwk_frame.h"
#include "nwk_tlv.h"
#include "zb_status.h"

enum
{
    /* Figure 3-11's fields, with the identifier octet 3.4.2.3 puts ahead of them (Table 3-54) */
    NWK_RREP_FIXED_OCTETS = 8,      /* identifier, options, request id, originator 2, responder 2, path cost */
    NWK_RREP_PATH_COST_AT = 7,      /* 3.4.2.3.5's octet: 9225-9228's update on a forward rewrites this one and nothing else */

    /* Figure 3-12's bits, read as 0-3 reserved, 4 originator IEEE, 5 responder IEEE, 6 deprecated, 7 reserved */
    NWK_RREP_OPTION_ORIGINATOR_IEEE = 0x10,
    NWK_RREP_OPTION_RESPONDER_IEEE = 0x20,
    NWK_RREP_OPTION_MULTICAST = 0x40,         /* deprecated 3.6.7: transmitted 0 and refused on receipt */
    NWK_RREP_OPTION_RESERVED_MASK = 0x8f,     /* bits 0-3 and 7: reserved, zeroed on transmission (R23.1 1.4.2) */
    NWK_RREP_OPTIONS = 0x30,                  /* 3.4.2.3.1: both IEEE bits set, the deprecated bit clear */

    /* 3.4.2.3.6 and 3.4.2.3.7 are both present, so the longest payload this module writes */
    NWK_RREP_PAYLOAD_MAX = NWK_RREP_FIXED_OCTETS + 2 * NWK_IEEE_ADDR_OCTETS
                           + NWK_TLV_HEADER_OCTETS + NWK_TLV_ROUTING_SEQUENCE_OCTETS,

    NWK_RREP_RADIUS = 30,           /* 3.4.2.2: nwkcMaxDepth x 2, Table 3-65's 15, the target's initial radius */
    NWK_RREP_RADIUS_FLOOR = 1       /* 9229: a route reply received with a radius of 1 SHALL NOT be dropped */
};

/* Figure 3-11, the route reply payload: `requestId`, `originatorAddr`, `responderAddr`, `pathCost`, `originatorIeee`
   and `responderIeee` are its rows; its Command options row is the fixed 0x30 of 3.4.2.3.1, which the record does not
   hold, and its TLVs row is K.3.1.1's record, the compose's `*routingSeq`. */
typedef struct Nwk_RouteReplyPayload
{
    uint8_t requestId;
    uint16_t originatorAddr;
    uint16_t responderAddr;
    uint8_t pathCost;
    uint64_t originatorIeee;
    uint64_t responderIeee;
} Nwk_RouteReplyPayload;

/* Figure 3-11 as read: its rows under the payload's names, and `tlvOutcome`, `extendedRouteInfo`,
   `routingSequenceNumber` (K.3.1.1's record and the parse's outcome, which the figure does not print) plus
   `initialRadius`, which Figure K-4 has no octet for and K.5.4's 2 x nwkcMaxDepth fills. */
typedef struct Nwk_RouteReplyFields
{
    uint8_t requestId;
    uint16_t originatorAddr;
    uint16_t responderAddr;
    uint8_t pathCost;
    uint64_t originatorIeee;
    uint64_t responderIeee;
    Nwk_TlvOutcome tlvOutcome;
    int extendedRouteInfo;
    uint16_t routingSequenceNumber;
    uint8_t initialRadius;
} Nwk_RouteReplyFields;

/* 3.4.2.3's fields behind Table 3-54's identifier, with K.3.1.1's Extended Route Information TLV of Figure K-4. */
ZbStatus Nwk_RrepCompose(const Nwk_RouteReplyPayload *reply, uint32_t *routingSeq,
                         uint8_t *out, uint32_t outMax, uint32_t *outLen);

/* Read Figure 3-11's payload; 3.4.2.3.1 makes both IEEE bits mandatory, so a reply outside 0x30 is refused rather than read. */
ZbStatus Nwk_RrepParse(const uint8_t *payload, uint32_t payloadLen, Nwk_RouteReplyFields *out);

/* A forwarder's reply: 3.4.2.3.5's cost octet rewritten, every other octet as it arrived (3.6.4.5.2.1). */
ZbStatus Nwk_RrepForward(const uint8_t *received, uint32_t receivedLen, uint8_t pathCost,
                         uint8_t *out, uint32_t outMax, uint32_t *outLen);

#endif /* NWK_RREP_H */
