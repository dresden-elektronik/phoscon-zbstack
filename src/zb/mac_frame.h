#ifndef MAC_FRAME_H
#define MAC_FRAME_H

/* Band A's 802.15.4 frame: the MHR written and read, the footer computed and checked. docs/internals/protocol.md §9.1
   owns the layout and its citations; docs/internals/architecture.md §8 holds the forms deliberately left out. */

#include <stdint.h>
#include "zb_status.h"

enum
{
    MAC_FRAME_MPDU_MAX = 127,   /* 13.1.3.2's Frame Length ceiling on this PHY, Table 12-2's
                                   phyMaxPacketSize and the seam's RADIO_MPDU_MAX: one number */
    MAC_FRAME_MPDU_MIN = 5,     /* the shortest legal MPDU: an acknowledgment is FCF, sequence, FCS */
    MAC_FRAME_FCF_OCTETS = 2,
    MAC_FRAME_SEQ_OCTETS = 1,
    MAC_FRAME_PAN_OCTETS = 2,
    MAC_FRAME_SHORT_OCTETS = 2,
    MAC_FRAME_EXTENDED_OCTETS = 8,
    MAC_FRAME_FCS_OCTETS = 2,

    /* 7.3.1.4 the Superframe Specification (16 bits), 7.3.1.5 the GTS Info fields (8 bits, with the
       Directions field and list absent at a zero descriptor count), 7.3.1.6 the Pending Address Specification
       (8 bits). Every beacon a receiver reads is at least these four octets of MAC payload. */
    MAC_FRAME_SUPERFRAME_SPEC_OCTETS = 2,
    MAC_FRAME_GTS_FIELDS_OCTETS = 1,
    MAC_FRAME_PENDING_SPEC_OCTETS = 1,

    /* 6.2 with 7.2.4: 0xffff is both the broadcast short address and the broadcast PAN ID, and a destination
       PAN of it "shall be accepted as a valid PAN ID by all devices currently listening to the channel". */
    MAC_FRAME_PAN_BROADCAST = 0xffff,
    MAC_FRAME_ADDR_BROADCAST = 0xffff,
    MAC_FRAME_ADDR_COORDINATOR = 0x0000,

    MAC_FRAME_FCS_POLY_REVERSED = 0x8408    /* G16(x) = x^16 + x^12 + x^5 + 1, bit-reflected */
};

/* FCF Frame Type subfield in Table 7-1's numbering, which docs/internals/protocol.md §9.1 prints: 4 is Reserved, 5 to 7
   are Multipurpose, Fragment and Extended. The 2006 table these names came from printed 4 to 7 as reserved,
   hence the shift: 6.6.2 a) refuses value 4 alone. */
typedef enum Mac_FrameType
{
    MAC_FRAME_TYPE_BEACON = 0,
    MAC_FRAME_TYPE_DATA = 1,
    MAC_FRAME_TYPE_ACK = 2,
    MAC_FRAME_TYPE_COMMAND = 3,
    MAC_FRAME_TYPE_RESERVED = 4,
    MAC_FRAME_TYPE_MULTIPURPOSE = 5,
    MAC_FRAME_TYPE_FRAGMENT = 6,
    MAC_FRAME_TYPE_EXTENDED = 7
} Mac_FrameType;

/* Addressing mode. 802.15.4-2006 Table 80's addressing-mode subfields and Table 41's SrcAddrMode and
   DstAddrMode are the same enumeration, so the seam translates nothing: 0 omits the address and its PAN
   field, 1 is reserved in both. */
typedef enum Mac_AddrMode
{
    MAC_ADDR_NONE = 0,
    MAC_ADDR_RESERVED = 1,
    MAC_ADDR_SHORT = 2,
    MAC_ADDR_EXTENDED = 3
} Mac_AddrMode;

/* Figure 7-1, the general MAC frame: the MHR the figure prints, the Frame Control subfields of Figure 7-2 (with
   Table 7-4's frame versions), and each address field split by the mode that says whether it is present (7.2.2.9). */
typedef struct Mac_Frame
{
    Mac_FrameType frameType;
    uint32_t frameVersion;
    int securityEnabled;
    int framePending;
    int ackRequest;
    int panIdCompression;
    int sequenceSuppressed;
    int iePresent;
    Mac_AddrMode destAddrMode;
    Mac_AddrMode srcAddrMode;
    uint8_t seq;

    uint16_t destPan;
    uint16_t srcPan;
    uint16_t destShort;
    uint64_t destExtended;
    uint16_t srcShort;
    uint64_t srcExtended;
} Mac_Frame;

/* 7.3.1.6, Figure 7-13: the pending-address list holds at most seven short and seven extended addresses, the
   count subfields three bits wide each. */
enum
{
    MAC_FRAME_PENDING_MAX = 7,

    /* Table 7-4's beacon and the value R23.1 Annex D.7 pins: "macBeaconOrder SHALL be set to 0x0F;
       macSuperframeOrder SHALL be set to 0x0F", the non-superframe configuration 10.2.2.1 describes, in which
       "a coordinator shall not transmit beacons, except upon receipt of a Beacon Request command". */
    MAC_FRAME_BEACON_ORDER_NONE = 15
};

/* Figure 7-5: a beacon's MAC payload is 7.3.1.4's Superframe Specification, 7.3.1.5's GTS fields,
   7.3.1.6's pending address lists, and then the beacon payload, the coordinator's statement about its PAN. */
typedef struct MacFrame_Beacon
{
    uint32_t beaconOrder;
    uint32_t superframeOrder;
    uint32_t finalCapSlot;
    int batteryLifeExtension;
    int panCoordinator;
    int associationPermit;
    int gtsPermit;

    uint16_t pendingShort[MAC_FRAME_PENDING_MAX];
    uint32_t pendingShortCount;
    uint64_t pendingExtended[MAC_FRAME_PENDING_MAX];
    uint32_t pendingExtendedCount;
} MacFrame_Beacon;

/* Compose the beacon's MAC payload from `beacon` and the payload the layer above wrote, opaque here (R23.1
   3.6.8.2). The GTS fields are 7.3.1.5's zero: no descriptor and GTS Permit clear, as 10.2.2.1 forbids GTSs. */
ZbStatus MacFrame_ComposeBeaconPayload(const MacFrame_Beacon *beacon, const uint8_t *payload,
                                       uint32_t payloadLen, uint8_t *out, uint32_t outCap,
                                       uint32_t *outLen);

/* Read a beacon's MAC payload back: the fields above, and a span naming the beacon payload that follows them. A
   payload too short for the four fields (or one whose counts do not match the addresses present) is
   ZB_ERR_BAD_FRAME. */
ZbStatus MacFrame_ParseBeaconPayload(const uint8_t *bytes, uint32_t len, MacFrame_Beacon *outBeacon,
                                     const uint8_t **outPayload, uint32_t *outPayloadLen);

/* 10.21.5.1, Figure 10-157: the Capability Information field, the 2024 edition's bit numbering (bit 0 reserved,
   bits 4-5 association type and suspendable CSMA-CA, bits 6-7 security and allocate address). The 2006 Figure 56
   puts the alternate-PAN-coordinator bit at 0 and leaves 4-5 reserved; bit 0 is read past. */
typedef struct MacFrame_Capability
{
    int deviceType;
    int powerSource;
    int rxOnWhenIdle;
    int associationType;
    int suspendableCsmaCa;
    int securityCapability;
    int allocateAddress;
} MacFrame_Capability;

/* 10.21.5.2, Figure 10-158: the Association Response content field. `status` is Table 10-102's octet, carried as
   it arrived: the association procedure is where a value is judged, not the codec. */
typedef struct MacFrame_AssociationResponse
{
    uint16_t shortAddress;
    uint8_t status;
} MacFrame_AssociationResponse;

/* Write the Association Request content (10.21.5.1's one octet) or read it back. A capability that claims one of
   the three forms this stack does not implement is ZB_ERR_UNSUPPORTED on compose; a body of any length but one
   is ZB_ERR_BAD_FRAME on parse. The caller writes the Command ID and the MHR. */
ZbStatus MacFrame_ComposeAssociationRequest(const MacFrame_Capability *capability, uint8_t *out, uint32_t outCap,
                                            uint32_t *outLen);
ZbStatus MacFrame_ParseAssociationRequest(const uint8_t *body, uint32_t len, MacFrame_Capability *outCapability);

/* Write or read the Association Response content (10.21.5.2's three octets, the short address first). */
ZbStatus MacFrame_ComposeAssociationResponse(const MacFrame_AssociationResponse *response, uint8_t *out,
                                             uint32_t outCap, uint32_t *outLen);
ZbStatus MacFrame_ParseAssociationResponse(const uint8_t *body, uint32_t len,
                                          MacFrame_AssociationResponse *outResponse);

/* The MHR length this frame describes under the layout rules docs/internals/protocol.md §9.1 states, with the status
   MacFrame_Compose answers for a frame those rules refuse. */
ZbStatus MacFrame_HeaderLen(const Mac_Frame *frame, uint32_t *outLen);

/* 6.6.2 c) applies "if a destination PAN ID is included", and Table 7-2 prints frames that carry none. */
int MacFrame_DestPanPresent(const Mac_Frame *frame);

/* Write the MHR and the payload into the caller's buffer, the footer still to come: a full MPDU needs
   MacFrame_AppendFcs, or a radio that computes its own footer. Nothing is written on a refusal:
   ZB_ERR_NO_SPACE for the buffer, ZB_ERR_BAD_ARGUMENT for a frame past the 127-octet ceiling. */
ZbStatus MacFrame_Compose(const Mac_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                          uint8_t *out, uint32_t outCap, uint32_t *outLen);

/* Close an MPDU with the footer its own octets compute, in the order 7.2.11, the FCS field, prints: "the
   remainder … r0 … is passed to the PHY first", the low octet of MacFrame_Fcs. */
ZbStatus MacFrame_AppendFcs(uint8_t *mpdu, uint32_t mpduLen, uint32_t outCap, uint32_t *outLen);

/* The 16-bit footer value for the given octets, before it is put on the wire. */
uint16_t MacFrame_Fcs(const uint8_t *bytes, uint32_t len);

/* ZB_OK when the last two octets are the footer everything before them computes. */
ZbStatus MacFrame_CheckFcs(const uint8_t *mpdu, uint32_t mpduLen);

/* Why a delivered frame was not read: 6.6.2 a) a reserved frame type (Table 7-1's 4), b) a reserved version
   (Table 7-4's 3), a reserved addressing mode (Table 7-2), a malformed header, or one of the forms this build has
   no header for, which is a deferral here and not the standard's refusal. */
typedef enum Mac_FrameRefusal
{
    MAC_FRAME_REFUSAL_NONE = 0,
    MAC_FRAME_REFUSAL_RESERVED_TYPE,
    MAC_FRAME_REFUSAL_RESERVED_VERSION,
    MAC_FRAME_REFUSAL_MALFORMED,
    MAC_FRAME_REFUSAL_UNBUILT
} Mac_FrameRefusal;

/* Read a delivered frame. `hasFrameFcs` is the delivering radio's property (Radio_Caps, in
   docs/internals/protocol.md §9.3), not a guess from the length, and the payload span points inside `mpdu`. A frame whose
   fields do not add up is ZB_ERR_BAD_FRAME; a form this stack has no header for is ZB_ERR_UNSUPPORTED. */
ZbStatus MacFrame_Parse(const uint8_t *mpdu, uint32_t mpduLen, int hasFrameFcs,
                        Mac_Frame *outFrame, const uint8_t **outPayload, uint32_t *outPayloadLen,
                        Mac_FrameRefusal *outRefusal);

#endif /* MAC_FRAME_H */
