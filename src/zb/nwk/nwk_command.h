#ifndef NWK_COMMAND_H
#define NWK_COMMAND_H

/*
 * Table 3-54's command identifiers and the two replies; docs/internals/conformance.md §2 owns their contract.
 */

#include <stdint.h>

#include "nwk_frame.h"
#include "nwk_neighbor.h"
#include "nwk_tlv.h"
#include "zb_status.h"

enum
{
    /* Table 3-54's identifiers, as printed: payload octet zero, not a header field (3.3.2.2.2) */
    NWK_CMD_ROUTE_REQUEST = 0x01,
    NWK_CMD_ROUTE_REPLY = 0x02,
    NWK_CMD_NETWORK_STATUS = 0x03,
    NWK_CMD_LEAVE = 0x04,
    NWK_CMD_ROUTE_RECORD = 0x05,
    NWK_CMD_REJOIN_REQUEST = 0x06,
    NWK_CMD_REJOIN_RESPONSE = 0x07,
    NWK_CMD_LINK_STATUS = 0x08,
    NWK_CMD_NETWORK_REPORT = 0x09,
    NWK_CMD_NETWORK_UPDATE = 0x0a,
    NWK_CMD_END_DEVICE_TIMEOUT_REQUEST = 0x0b,
    NWK_CMD_END_DEVICE_TIMEOUT_RESPONSE = 0x0c,
    NWK_CMD_LINK_POWER_DELTA = 0x0d,
    NWK_CMD_NETWORK_COMMISSIONING_REQUEST = 0x0e,
    NWK_CMD_NETWORK_COMMISSIONING_RESPONSE = 0x0f,

    /* Table 3-56's payload codes (3.4.3.3.1), not Table 3-84's confirm codes: 0x13 is 3.6.13's own status */
    NWK_NETWORK_STATUS_UNKNOWN_COMMAND = 0x13,
    NWK_NETWORK_STATUS_LINK_FAILURE = 0x02,     /* 3.6.4.8.1: "a status code of 0x02 (Link Failure)" */
    NWK_NETWORK_STATUS_ADDRESS_CONFLICT = 0x0d, /* 3.6.1.10.5: "a status code of 0x0d indicating address conflict" */

    /* 3.6.13 and 3.4.3.3.2 with Figure 3-61: Command ID, Status, and the one octet naming the received
       identifier. The two-octet target address 3.4.3.3.2 prints is present only for a routing failure or an
       address conflict, and 0x13 is neither. */
    NWK_COMMAND_REPLY_PAYLOAD_MAX = 3,

    /* 3.4.3.3.2's "destination address field SHALL be 2 octets ... in case of a routing failure" plus Figure K-5's
       two value octets behind Table I-1's tag and length: the longest route-error payload this module writes. */
    NWK_COMMAND_STATUS_PAYLOAD_MAX = 2 + 2 + NWK_TLV_HEADER_OCTETS + NWK_TLV_ROUTING_SEQUENCE_OCTETS,

    /* A rejoin response: the command identifier, the two-octet network address and the rejoin status */
    NWK_COMMAND_REJOIN_RESPONSE_OCTETS = 4
};

/* Whether Table 3-54 prints this identifier: the fifteen it names, not the Reserved band (3.3.2.2.2). */
int Nwk_CommandIsKnown(uint32_t id);

/* 3.6.2.2's dispatch: 0x01 and 0x02 to 3.6.4.5.1 and 3.6.4.5.2, 0x03 indicated, the rest what 3.6.13 answers. */
int Nwk_CommandIsProcessed(uint32_t id);

/* 3.6.4.8.1's Network Status for a failed link (3.4.3.2, 3.4.3.3.2), with Figure K-5's record behind it. */
ZbStatus Nwk_CommandComposeStatus(Nwk_Frame *replyOut, uint16_t ownAddr, uint64_t ownIeee,
                                  uint16_t destination, const Nwk_NeighborTableEntry *destinationEntry, uint16_t status,
                                  uint16_t failedDestination, int sequenceNumberValid,
                                  uint16_t routingSequenceNumber, int securityEnabled, uint32_t *seq,
                                  uint8_t *npdu, uint32_t npduMax, uint32_t *npduLen);

/* 3.6.13's answer to an identifier this layer does not support: Figure 3-61's three payload octets. */
ZbStatus Nwk_CommandComposeReply(Nwk_Frame *replyOut, const Nwk_Frame *offender, uint32_t commandId,
                                 uint16_t ownAddr, uint64_t ownIeee,
                                 const Nwk_NeighborTableEntry *offenderEntry, int securityEnabled,
                                 uint32_t *seq, uint8_t *npdu, uint32_t npduMax, uint32_t *npduLen);

#endif /* NWK_COMMAND_H */
