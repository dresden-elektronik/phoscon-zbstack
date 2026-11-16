#ifndef APS_TRANSPORTKEY_H
#define APS_TRANSPORTKEY_H

/* The body of 4.4.11.1's Transport-Key command: Table 4-9's StandardKeyType and one of 4.4.11.1.3's three descriptors,
   which Figure 4-8 puts after the command identifier the APS frame codec already carries. */

/* The descriptor decides its own length: Figure 4-10's network key has no TLV sub-field, Figures 4-9 and 4-11 end in
   one, and this module walks that run's tag and length without interpreting its value. */

/* The 64-bit addresses travel low octet first, which 1.2.3 (1186-1194) states for every field of more than one octet
   and 2.2.5 repeats for the APS formats; 4.4.11.1.3 indicates no other order. */

/* 4.4.2.1.3's duty on the sender, that the source address sub-field be the local device address, belongs to the door
   that composes the command frame; this module writes the octets it is given. */

#include <stdint.h>
#include "zb_status.h"

enum
{
    /* Table 4-31's command identifier for the frame this body rides in, so the caller has one name for it */
    APS_TK_COMMAND_ID = 0x05,

    /* Table 4-9 (p430): the values a StandardKeyType field may hold. 0x00, 0x02 and 0x05-0xAF, 0xB4-0xFF are reserved
       there. 0xB0-0xB3 are enumerated, not reserved, and belong to the Zigbee Direct specification this profile does
       not implement, so they are refused as a scope this stack has not taken rather than as a reserved value. */
    APS_TK_TYPE_NETWORK_KEY = 0x01,
    APS_TK_TYPE_APPLICATION_LINK_KEY = 0x03,
    APS_TK_TYPE_TC_LINK_KEY = 0x04,

    APS_TK_KEY_OCTETS = 16,
    APS_TK_IEEE_OCTETS = 8,

    /* Figure 4-8's own octet, which 4.4.11.1.2 makes the first thing after the command identifier */
    APS_TK_TYPE_OCTETS = 1,

    /* Figure 4-10's descriptor: key, sequence number, destination address, source address, and nothing after it */
    APS_TK_NETWORK_DESCRIPTOR_OCTETS = 33,

    /* Figure 4-9's: key, destination address, source address, then TLVs */
    APS_TK_TC_LINK_DESCRIPTOR_OCTETS = 32,

    /* Figure 4-11's: key, partner address, initiator flag, then TLVs */
    APS_TK_APP_LINK_DESCRIPTOR_OCTETS = 25,

    /* What the body occupies with no TLVs: Figure 4-8's type octet and the descriptor behind it */
    APS_TK_NETWORK_BODY_OCTETS = APS_TK_TYPE_OCTETS + APS_TK_NETWORK_DESCRIPTOR_OCTETS,
    APS_TK_TC_LINK_BODY_OCTETS = APS_TK_TYPE_OCTETS + APS_TK_TC_LINK_DESCRIPTOR_OCTETS,
    APS_TK_APP_LINK_BODY_OCTETS = APS_TK_TYPE_OCTETS + APS_TK_APP_LINK_DESCRIPTOR_OCTETS
};

typedef struct Aps_TransportKey
{
    uint32_t standardKeyType;
    uint8_t key[APS_TK_KEY_OCTETS];
    uint8_t keySeqNumber;
    uint64_t destinationIeee;
    uint64_t sourceIeee;
    uint64_t partnerIeee;
    int initiator;
    const uint8_t *tlvs;
    uint32_t tlvLen;
} Aps_TransportKey;

/* Write the body this struct describes. ZB_OK, ZB_ERR_BAD_ARGUMENT for a type Table 4-9 does not give, for TLVs on a
   network key descriptor, or for a missing buffer, and ZB_ERR_NO_SPACE when outMax cannot hold it. */
ZbStatus Aps_TransportKeyCompose(const Aps_TransportKey *tk, uint8_t *out, uint32_t outMax, uint32_t *outLen);

/* Read one: `bodyLen` is what the payload region holds, and a body is read whole or refused, never in part. ZB_OK, or
   ZB_ERR_BAD_ARGUMENT for a body shorter than its own figure, a reserved type, a network key descriptor with octets
   after it, or a TLV run whose tag and length do not fill the tail. Nothing is written to `out` on a refusal. */
ZbStatus Aps_TransportKeyParse(const uint8_t *body, uint32_t bodyLen, Aps_TransportKey *out);

#endif /* APS_TRANSPORTKEY_H */
