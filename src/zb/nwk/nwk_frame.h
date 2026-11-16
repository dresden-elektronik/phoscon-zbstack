#ifndef NWK_FRAME_H
#define NWK_FRAME_H

/*
 * The NWK frame codec of R23.1 3.3; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>
#include "nwk_addr.h"
#include "zb_status.h"

enum
{
    NWK_FRAME_NPDU_MAX = 116,       /* the MAC's payload ceiling, not a NWK one: aMaxPHYPacketSize 127 less nwkcMACFrameOverhead 11 (Table 3-2 with Table 3-65) */
    NWK_MIN_HEADER_OVERHEAD = 8,    /* nwkcMinHeaderOverhead, Table 3-65: the always-present fields of 3.3.1.2 … 3.3.1.5 */
    NWK_FRAME_FCF_OCTETS = 2,       /* 3.3.1.1's frame control, Figure 3-5's two octets */
    NWK_FRAME_ADDR_OCTETS = 2,      /* 3.3.1.2 and 3.3.1.3: always present, 2 octets each */
    NWK_FRAME_RADIUS_OCTETS = 1,    /* 3.3.1.4: always present, 1 octet */
    NWK_FRAME_SEQ_OCTETS = 1,       /* 3.3.1.5: present in every frame, 1 octet */
    NWK_IEEE_ADDR_OCTETS = 8,       /* 3.3.1.6 and 3.3.1.7: the 0/8 Destination and Source IEEE Address fields */
    NWK_FRAME_ROUTE_CONTROL_OCTETS = 2, /* 3.3.1.8, Figure 3-6: Relay count and Relay index, one octet each */
    NWK_FRAME_RELAY_OCTETS = 2,     /* 3.3.1.8: each Relay list entry is a 16-bit network address */
    NWK_MAX_SOURCE_ROUTE = 12,      /* nwkMaxSourceRoute, NIB attribute 0x93, default 0x0c (Table 3-66): our own routes */

    /* 3.3.1.8.1 bounds a received relay count by nothing but the octets that carry it, so the list a frame can hold
       is this wide: what is left of the NPDU's ceiling after the eight always-present header octets and the two
       route-control octets, two octets per relay. */
    NWK_MAX_RELAYS = (NWK_FRAME_NPDU_MAX - NWK_MIN_HEADER_OVERHEAD - NWK_FRAME_ROUTE_CONTROL_OCTETS)
                     / NWK_FRAME_RELAY_OCTETS,

    /* nwkcProtocolVersion (3.3.1.1.2, Table 3-65): reads 0x01 and 0x02 per Table 1-5, refuses 0x03 */
    NWK_PROTOCOL_VERSION = 2,

    /* Frame type, Table 3-52. */
    NWK_FRAME_TYPE_DATA = 0,        /* 0b00 Data */
    NWK_FRAME_TYPE_COMMAND = 1,     /* 0b01 NWK command */
    NWK_FRAME_TYPE_RESERVED = 2,    /* 0b10 Reserved */
    NWK_FRAME_TYPE_INTERPAN = 3,    /* 0b11 Inter-PAN */

    /* Discover route, Table 3-53; 3.4 pins 0x00 for a command frame, and Table 3-51 for a broadcast */
    NWK_DISCOVER_SUPPRESS = 0,
    NWK_DISCOVER_ENABLE = 1
};

/* Figure 3-5's Frame Control Field, bit for bit; bits 14-15 have no member in `Nwk_Frame`, a frame written here carrying zero. */
enum
{
    NWK_FRAME_FCF_TYPE_SHIFT = 0,
    NWK_FRAME_FCF_PROTOCOL_VERSION_SHIFT = 2,
    NWK_FRAME_FCF_DISCOVER_ROUTE_SHIFT = 6,
    NWK_FRAME_FCF_MULTICAST_SHIFT = 8,
    NWK_FRAME_FCF_SECURITY_SHIFT = 9,
    NWK_FRAME_FCF_SOURCE_ROUTE_SHIFT = 10,
    NWK_FRAME_FCF_DEST_IEEE_SHIFT = 11,
    NWK_FRAME_FCF_SRC_IEEE_SHIFT = 12,
    NWK_FRAME_FCF_END_DEVICE_INITIATOR_SHIFT = 13,
    NWK_FRAME_FCF_RESERVED_SHIFT = 14,

    NWK_FRAME_FCF_TYPE_MASK = 3,
    NWK_FRAME_FCF_PROTOCOL_VERSION_MASK = 0x0f,
    NWK_FRAME_FCF_DISCOVER_ROUTE_MASK = 3,
    NWK_FRAME_FCF_MULTICAST_MASK = 1,
    NWK_FRAME_FCF_SECURITY_MASK = 1,
    NWK_FRAME_FCF_SOURCE_ROUTE_MASK = 1,
    NWK_FRAME_FCF_DEST_IEEE_MASK = 1,
    NWK_FRAME_FCF_SRC_IEEE_MASK = 1,
    NWK_FRAME_FCF_END_DEVICE_INITIATOR_MASK = 1,
    NWK_FRAME_FCF_RESERVED_MASK = 3    /* the two bits at shift 14: Figure 3-5 prints them Reserved, zeroed on transmission (R23.1 1.4.2) */
};

/* Figure 3-4, the general NWK frame: `destAddr`, `srcAddr`, `radius`, `sequenceNumber`, `destIeee`, `srcIeee` and the source
   route subframe's three rows are its own; its Frame control row is Figure 3-5's nine flags, codec-set, bits 14-15
   having no member, its Frame payload row is the codec's `payload`, and `headerLen`/`payloadOffset` are ours. */
typedef struct Nwk_Frame
{
    int frameType;
    int protocolVersion;
    int discoverRoute;
    int multicastDeprecated;
    int securityEnabled;
    int sourceRoute;
    int destIeeePresent;
    int srcIeeePresent;
    int endDeviceInitiator;

    uint16_t destAddr;
    uint16_t srcAddr;
    uint8_t radius;
    uint8_t sequenceNumber;

    uint64_t destIeee;
    uint64_t srcIeee;

    uint8_t relayCount;
    uint8_t relayIndex;
    uint16_t relayList[NWK_MAX_RELAYS];
} Nwk_Frame;

/* Below `Nwk_Frame` because `Nwk_CommandComposeReply` names it; headers stay includable in any order (docs/internals/coding-rules.md §2). */
#include "nwk_command.h"

uint32_t NwkFrame_HeaderLen(const Nwk_Frame *frame);

/* Write Figure 3-4's header and the payload in its octet order (3.3). */
ZbStatus NwkFrame_Compose(const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                          uint8_t *out, uint32_t outCap, uint32_t *outLen);

/* The same, for a frame this device carries on rather than builds: nwkMaxSourceRoute caps the routes a device
   constructs and not the source route it relays, which is somebody else's and bounded by the octets' room. */
ZbStatus NwkFrame_ComposeRelay(const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                               uint8_t *out, uint32_t outCap, uint32_t *outLen);

/* Read an NPDU: 3.4.1.1 puts both a command and a NWK-secured frame behind a clear MAC security bit, so `payloadOffset`
   lands on the command identifier only while the frame is unsecured; 4.3.2's auxiliary header sits in between otherwise. */
ZbStatus NwkFrame_Parse(const uint8_t *npdu, uint32_t npduLen, Nwk_Frame *frame,
                        uint32_t *payloadOffset, uint32_t *payloadLen);

#endif /* NWK_FRAME_H */
