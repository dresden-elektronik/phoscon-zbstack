#ifndef NWK_COMMISSIONING_H
#define NWK_COMMISSIONING_H

/* 3.4.14's Network Commissioning Request and 3.4.15's response, with Table 3-64's three types and the Annex I.4 TLVs
   the request carries; docs/internals/conformance.md owns the clause marks. */

#include <stdint.h>

#include "zb_status.h"

enum
{
    /* Table 3-64's commissioning types, the request's first octet */
    NWK_COMMISSIONING_INITIAL_JOIN = 0x00,
    NWK_COMMISSIONING_REJOIN = 0x01,
    NWK_COMMISSIONING_TRUSTED_LINK = 0x02,

    NWK_COMMISSIONING_OCTETS = 2,           /* Figure 3-36: the type and the capability octet, ahead of the TLVs */
    NWK_COMMISSIONING_RESPONSE_OCTETS = 3,  /* Figure 3-37: the network address and the status */

    /* Annex I.4: the tags 3.4.14.3.3 puts in the request, and the sizes Figures I-2 and I-4 print */
    NWK_TLV_TAG_SUPPORTED_KEY_NEGOTIATION = 65,
    NWK_TLV_TAG_FRAGMENTATION_PARAMETERS = 71,
    NWK_TLV_TAG_JOINER_ENCAPSULATION = 72,
    NWK_TLV_TAG_BEACON_APPENDIX_ENCAPSULATION = 73, /* I.4.10's, which I.2.7 step 3d refuses inside the other */
    NWK_TLV_KEY_NEGOTIATION_OCTETS = 10,
    NWK_TLV_KEY_NEGOTIATION_MIN_OCTETS = 2, /* Table I-3's minimum: the two bitmasks without the source EUI-64 */
    NWK_TLV_FRAGMENTATION_OCTETS = 5,
    NWK_TLV_FRAGMENTATION_APS_BIT = 0x01,

    /* 3.4.15.2.1.2: the one status 3.4.15 prints of its own, an address conflict the device may retry */
    NWK_COMMISSIONING_STATUS_ADDRESS_CONFLICT = 0xf0
};

/* Figure 3-36's payload: the type, the capability octet, and the TLV tail 3.4.14.3.3 requires. The key negotiation
   fields are Figure I-2's, composed for every type but a rejoin and `keyNegotiationPresent` when parsed. */
typedef struct Nwk_CommissioningRequest
{
    uint32_t type;
    uint8_t capability;
    uint16_t nodeId;
    uint32_t fragmentationOptions;
    uint32_t maxIncomingTransferUnit;
    uint32_t keyNegotiationProtocols;
    uint32_t preSharedSecrets;
    uint64_t sourceEui64;
    int keyNegotiationPresent;
} Nwk_CommissioningRequest;

ZbStatus Nwk_CommissioningRequestParse(const uint8_t *payload, uint32_t payloadLen, Nwk_CommissioningRequest *out);

ZbStatus Nwk_CommissioningRequestCompose(const Nwk_CommissioningRequest *request, uint8_t *out, uint32_t outCap,
                                         uint32_t *outLen);

/* Figure 3-37's payload. */
ZbStatus Nwk_CommissioningResponseCompose(uint16_t networkAddress, uint8_t status, uint8_t *out, uint32_t outCap,
                                          uint32_t *outLen);

ZbStatus Nwk_CommissioningResponseParse(const uint8_t *payload, uint32_t payloadLen, uint16_t *addressOut,
                                        uint8_t *statusOut);

#endif
