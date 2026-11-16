#ifndef APS_FRAME_H
#define APS_FRAME_H

/*
 * Band A's APS frame: the APDU header of 2.2.5, written and read in Figure 2-3's octet order with the
 * extended sub-frame of 2.2.5.1.8. APS is chapter 2 and not chapter 4; 2.2.5.2.2's cross-reference is
 * broken at source and resolves by heading to Figure 2-3, as every citation here does. The header carries
 * no device address, the 16-bit group address is the only address in it (2.2.5.1.3), device addressing
 * riding the NWK header, and an endpoint is an octet, not an address (2.2.5.1.2). Multi-octet fields
 * travel low octet first (2.2.5, p86). No state, no device, no clock: the counter is carried and never
 * incremented, numbering being `aps`'s (2.2.5.1.7). Not here: APS security, bit 5 being set and reported
 * while 4.4.10's auxiliary sits in the payload region this codec reports whole; fragmentation
 * (2.2.8.4.5); Inter-PAN (Annex G.3.3); command bodies (2.2.6 → 4.4.11); all of 2.2.8.
 */

#include <stdint.h>
#include "zb_status.h"

enum
{
    /* the ceiling on the NSDU that carries it: 127 - 0x0b - 0x08 (2.2.8.4.1, Table 3-2 with 3-65) */
    APS_FRAME_MAX = 108,

    /* NsduLength - apscMinHeaderOverhead = 108 - 12, as printed; the printed 12 not matching Figure 2-7's
       field sum is a recorded mismatch, kept rather than smoothed. 96 bounds a request, 108 a
       frame, and the frame bound is the one this module enforces */
    APS_ASDU_MAX = 96,
    APS_MIN_HEADER_OVERHEAD = 12,   /* apscMinHeaderOverhead (Table 2-23) */

    /* Field counts checked against Table 4-40 (p502), the only printed octet budget for a whole APS path */
    APS_FRAME_FCF_OCTETS = 1,       /* 2.2.5.1.1, Figure 2-4: "The frame control field is 8 bits in length" */
    APS_FRAME_ENDPOINT_OCTETS = 1,  /* 2.2.5.1.2 and 2.2.5.1.6: "8-bits in length" each */
    APS_FRAME_GROUP_OCTETS = 2,     /* 2.2.5.1.3: "16 bits in length" */
    APS_FRAME_CLUSTER_OCTETS = 2,   /* 2.2.5.1.4: "16 bits in length" */
    APS_FRAME_PROFILE_OCTETS = 2,   /* 2.2.5.1.5: "two octets in length" */
    APS_FRAME_COUNTER_OCTETS = 1,   /* 2.2.5.1.7: "This field is eight bits in length" */
    APS_FRAME_COMMAND_ID_OCTETS = 1, /* Figure 2-8 (p91): the APS command identifier, 1 octet, first of the payload */
    APS_FRAME_EXT_CONTROL_OCTETS = 1, /* 2.2.5.1.8.1 with Figure 2-5: "eight bits in length" */
    APS_FRAME_BLOCK_OCTETS = 1,     /* 2.2.5.1.8.2: "one octet in length" */
    APS_FRAME_ACK_BITFIELD_OCTETS = 1, /* 2.2.5.1.8.3: "one octet in length" */
    APS_FRAME_HEADER_MIN = 2,       /* the shortest the figures print: Figure 2-9 with 2.2.5.2.3.1; Figure 2-8's is 3 */

    /* Frame type, Table 2-20 */
    APS_FRAME_TYPE_DATA = 0,        /* 0b00 Data */
    APS_FRAME_TYPE_COMMAND = 1,     /* 0b01 Command */
    APS_FRAME_TYPE_ACK = 2,         /* 0b10 Acknowledgement */
    APS_FRAME_TYPE_INTERPAN = 3,    /* Annex G.3.3: a different header, named and not read */

    /* Delivery mode, Table 2-21; 2.2.5.1.1.2 allows only the non-reserved values */
    APS_DELIVERY_UNICAST = 0,       /* 0b00 unicast */
    APS_DELIVERY_RESERVED = 1,      /* 0b01 Reserved */
    APS_DELIVERY_BROADCAST = 2,     /* 0b10 broadcast */
    APS_DELIVERY_GROUP = 3,         /* 0b11 group */

    /* Fragmentation, Table 2-22: bits 0-1 of the extended frame control (Figure 2-6) */
    APS_FRAG_NONE = 0,              /* 0b00 Transmission is not fragmented */
    APS_FRAG_FIRST = 1,             /* 0b01 Frame is first fragment of a fragmented transmission */
    APS_FRAG_SUBSEQUENT = 2,        /* 0b10 Frame is part of a fragmented transmission but not the first part */
    APS_FRAG_RESERVED = 3,          /* 0b11 Reserved */

    /* Endpoints, 2.2.5.1.2 with 2.2.5.1.6: 0xff is a destination value alone */
    APS_ENDPOINT_ZDO = 0x00,        /* the ZDO */
    APS_ENDPOINT_LAST = 0xfe,       /* top application endpoint */
    APS_ENDPOINT_ALL = 0xff,        /* all active endpoints except 0x00 */

    /* APS command identifiers, Table 4-31: recognition for a caller, no command body invented here */
    APS_CMD_TRANSPORT_KEY = 0x05,
    APS_CMD_UPDATE_DEVICE = 0x06,
    APS_CMD_REMOVE_DEVICE = 0x07,
    APS_CMD_REQUEST_KEY = 0x08,
    APS_CMD_SWITCH_KEY = 0x09,
    APS_CMD_TUNNEL = 0x0e,
    APS_CMD_VERIFY_KEY = 0x0f,
    APS_CMD_CONFIRM_KEY = 0x10,
    APS_CMD_RELAY_MESSAGE_DOWNSTREAM = 0x11,
    APS_CMD_RELAY_MESSAGE_UPSTREAM = 0x12
};

/*
 * The Frame Control Field, bit for bit from Figure 2-4. Every bit is a named field, so unlike NWK's
 * Figure 3-5 there is no part of the octet this module cannot describe, and 2.2.5's reserved-zero rule
 * lands on the fields that carry it: delivery mode 0b01, fragmentation 0b11, bits 2-7 of the extended
 * frame control (Figure 2-6).
 */
enum
{
    APS_FRAME_FCF_TYPE_SHIFT = 0,
    APS_FRAME_FCF_DELIVERY_MODE_SHIFT = 2,
    APS_FRAME_FCF_ACK_FORMAT_SHIFT = 4,
    APS_FRAME_FCF_SECURITY_SHIFT = 5,
    APS_FRAME_FCF_ACK_REQUEST_SHIFT = 6,
    APS_FRAME_FCF_EXTENDED_SHIFT = 7,

    APS_FRAME_FCF_TYPE_MASK = 3,
    APS_FRAME_FCF_DELIVERY_MODE_MASK = 3,
    APS_FRAME_FCF_ACK_FORMAT_MASK = 1,
    APS_FRAME_FCF_SECURITY_MASK = 1,
    APS_FRAME_FCF_ACK_REQUEST_MASK = 1,
    APS_FRAME_FCF_EXTENDED_MASK = 1,

    APS_FRAME_EXT_FRAGMENTATION_SHIFT = 0,    /* Figure 2-6: bits 0-1 */
    APS_FRAME_EXT_RESERVED_SHIFT = 2,         /* Figure 2-6: bits 2-7, Reserved */

    APS_FRAME_EXT_FRAGMENTATION_MASK = 3,
    APS_FRAME_EXT_RESERVED_MASK = 0x3f
};

/*
 * The APS header's fields: one per conditional field of Figure 2-3 plus the flags that gate them, each read
 * or written only when its flag says it is present. The matrix 2.2.5.1.2 … 2.2.5.2 fixes per frame type,
 * data carrying cluster, profile, source endpoint and counter, group mode trading destination endpoint for
 * the group address, command nothing but control, counter and identifier, an acknowledgement the endpoints
 * swapped (Figure 2-7/2-8/2-9), and a flag that contradicts it is a refusal in both directions.
 */
typedef struct Aps_Frame
{
    uint32_t frameType;             /* APS_FRAME_TYPE_* (Table 2-20) */
    uint32_t deliveryMode;          /* APS_DELIVERY_* (Table 2-21) */
    int ackFormat;                  /* FCF bit 4: Figure 2-9's split, ack frames only */
    int securityEnabled;            /* FCF bit 5: 2.2.5.1.1.4's provider manages what it means */
    int ackRequest;                 /* FCF bit 6, 2.2.5.1.1.5 */

    uint8_t dstEndpoint;            /* 2.2.5.1.2 */
    int dstEndpointPresent;
    uint16_t groupAddress;          /* 2.2.5.1.3: the only address an APS header carries */
    int groupAddressPresent;
    uint16_t clusterId;             /* 2.2.5.1.4 */
    int clusterPresent;
    uint16_t profileId;             /* 2.2.5.1.5 */
    int profilePresent;
    uint8_t srcEndpoint;            /* 2.2.5.1.6 */
    int srcEndpointPresent;

    uint8_t apsCounter;             /* 2.2.5.1.7's octet; numbering is `aps`'s duty */

    int extendedHeaderPresent;      /* FCF bit 7, 2.2.5.1.1.6 */
    uint8_t extFrameControl;        /* Figure 2-5's first column, bits 2-7 Reserved */
    uint32_t fragmentation;         /* the decoded bits 0-1, which must agree with that octet */
    uint8_t blockNumber;            /* 2.2.5.1.8.2 */
    int blockNumberPresent;
    uint8_t ackBitfield;            /* 2.2.5.1.8.3 */
    int ackBitfieldPresent;
} Aps_Frame;

/*
 * The header length the flags describe: arithmetic over the presence matrix, 8 for the minimal data form
 * (not the printed apscMinHeaderOverhead, see APS_ASDU_MAX), 9 for the group form, 3 for a command, 8 for
 * an ACK format 0 and 2 for an ACK format 1. It answers a number and no status, as NwkFrame_HeaderLen does.
 */
uint32_t ApsFrame_HeaderLen(const Aps_Frame *frame);

/*
 * Write the header and payload in Figure 2-3's column order, multi-octet fields low octet first. A zero-length
 * payload is legal. The refusals are the two families the service counts apart: ZB_ERR_UNSUPPORTED for forms
 * this codec has no layout for, ZB_ERR_BAD_ARGUMENT for a struct that contradicts the matrix, and
 * ZB_ERR_NO_SPACE for a frame over the 108 the layer below offers, 2.2.5's transmission half setting Reserved
 * fields to zero. Nothing is written in any of those cases.
 */
ZbStatus ApsFrame_Compose(const Aps_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                          uint8_t *out, uint32_t outMax, uint32_t *outLen, uint32_t *payloadOffset);

/*
 * Read an APDU out of a NWK delivery's NSDU and report everything past the validated header as the payload
 * region: a secured frame's auxiliary and MIC included in it, named by the crossing (4.4.10 with 4.5.1). A
 * frame that contradicts the matrix is damage (ZB_ERR_BAD_FRAME), a form this codec does not read is
 * ZB_ERR_UNSUPPORTED (2.2.5's reception half discarding rather than correcting), truncation is damage, and
 * the status a frame hits first wins. Nothing of the caller's is written on a refusal.
 */
ZbStatus ApsFrame_Parse(const uint8_t *in, uint32_t inLen, Aps_Frame *frame,
                        uint32_t *payloadOffset, uint32_t *payloadLen);

/*
 * Table 4-31 recognition only: 1 for the ten identifiers that table prints, 0 for its Reserved bands, for zero
 * and for anything above 0x12. Whether a known command is processed is `aps`'s question.
 */
int ApsFrame_IsKnownCommand(uint32_t id);

#endif /* APS_FRAME_H */
