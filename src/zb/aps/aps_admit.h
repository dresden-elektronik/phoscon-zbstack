#ifndef APS_ADMIT_H
#define APS_ADMIT_H

/* The bodies of 4.4.11.2's Update Device, 4.4.11.3's Remove Device and 4.4.11.6's Tunnel, the three commands a trust
   centre and a parent router admit and remove a device with (4.6.3.2.1, 4.6.3.6.2, 4.6.3.7.1). Each body is
   what follows the command identifier, which Figure 2-8 makes the payload's first octet; the identifiers are
   `aps_frame`'s Table 4-31 names. */

/* The 64-bit addresses and the short address travel low octet first, which 1.2.3 states for every field of more than
   one octet. */

#include <stdint.h>
#include "zb_status.h"

enum
{
    /* Table 4-14's Status values; 0x04 to 0x07 are reserved */
    APS_UPDATE_DEVICE_SECURED_REJOIN = 0x00,
    APS_UPDATE_DEVICE_UNSECURED_JOIN = 0x01,
    APS_UPDATE_DEVICE_LEFT = 0x02,
    APS_UPDATE_DEVICE_TC_REJOIN = 0x03,

    /* Table 4-14's DeviceShortAddress range on the request */
    APS_UPDATE_DEVICE_SHORT_MIN = 0x0001,
    APS_UPDATE_DEVICE_SHORT_MAX = 0xfff7,

    /* Figures 4-13 and 4-14 after the identifier: Figure 4-13's JoinerTLVs follow its eleven */
    APS_UPDATE_DEVICE_OCTETS = 8 + 2 + 1,
    APS_REMOVE_DEVICE_OCTETS = 8,

    /* Figure 4-17 after the identifier: the destination, then the secured command it carries, which is the two-octet
       header of Figure 2-8, 4.4.11.6.3's auxiliary frame with the extended nonce and no key sequence number (4.5.1),
       at least the encrypted command identifier, and the four-octet MIC */
    APS_TUNNEL_DEST_OCTETS = 8,
    APS_TUNNEL_HEADER_OCTETS = 2,
    APS_TUNNEL_AUX_OCTETS = 1 + 4 + 8,
    APS_TUNNEL_MIC_OCTETS = 4,
    APS_TUNNEL_SECURED_MIN = APS_TUNNEL_HEADER_OCTETS + APS_TUNNEL_AUX_OCTETS + 1 + APS_TUNNEL_MIC_OCTETS
};

typedef struct Aps_UpdateDevice
{
    uint64_t deviceIeee;             /* 4.4.11.2.2 */
    uint16_t deviceShortAddress;     /* 4.4.11.2.3 */
    uint8_t status;                  /* 4.4.11.2.4, Table 4-14 */
    const uint8_t *joinerTlvs;       /* 4.4.11.2.5, carried verbatim and not walked: 0 when absent */
    uint32_t joinerTlvLen;
} Aps_UpdateDevice;

typedef struct Aps_Tunnel
{
    uint64_t destinationIeee;        /* 4.4.11.6.2 */
    const uint8_t *secured;          /* 4.6.3.7.2's extracted command: header, auxiliary frame, command and MIC */
    uint32_t securedLen;
} Aps_Tunnel;

/* An Update Device body: ZB_OK, or ZB_ERR_BAD_FRAME when shorter than Figure 4-13's fixed fields. A reserved status is
   returned as read; what a trust centre does with it is the caller's. */
ZbStatus Aps_UpdateDeviceParse(const uint8_t *body, uint32_t bodyLen, Aps_UpdateDevice *out);

/* An Update Device command's payload, its identifier first. ZB_ERR_BAD_ARGUMENT for a reserved status or a short
   address outside Table 4-14's range. */
ZbStatus Aps_UpdateDeviceCompose(const Aps_UpdateDevice *in, uint8_t *out, uint32_t outMax, uint32_t *outLen);

/* A Remove Device body: ZB_OK, or ZB_ERR_BAD_FRAME for any length but Figure 4-14's. */
ZbStatus Aps_RemoveDeviceParse(const uint8_t *body, uint32_t bodyLen, uint64_t *targetIeee);

/* A Remove Device command's payload, its identifier first: 9 octets. */
ZbStatus Aps_RemoveDeviceCompose(uint64_t targetIeee, uint8_t *out, uint32_t outMax, uint32_t *outLen);

/* A Tunnel body: ZB_OK with `secured` pointing into `body`, or ZB_ERR_BAD_FRAME when the carried frame is not a secured
   command under a link key with the extended nonce (4.4.11.6.3, 4.6.3.7.1). */
ZbStatus Aps_TunnelParse(const uint8_t *body, uint32_t bodyLen, Aps_Tunnel *out);

/* A Tunnel command's payload, its identifier first, around a command already secured; the same shape the parse
   demands is demanded here, as ZB_ERR_BAD_ARGUMENT. */
ZbStatus Aps_TunnelCompose(uint64_t destinationIeee, const uint8_t *secured, uint32_t securedLen, uint8_t *out,
                           uint32_t outMax, uint32_t *outLen);

#endif /* APS_ADMIT_H */
