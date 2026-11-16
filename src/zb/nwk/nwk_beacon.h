#ifndef NWK_BEACON_H
#define NWK_BEACON_H

/* R23.1 3.6.8's beacon payload: Table 3-83's fields in Figure 3-53's order. This is the network layer's own
   statement about the PAN, which 3.6.8.2 has the NWK layer compose and hand to the MAC as opaque octets
   (macBeaconPayload), which is why it lives here and not in the frame codec. */

#include <stdint.h>
#include "zb_status.h"

enum
{
    /* Figure 3-53's field widths: the info field is 15 octets */
    NWK_BEACON_INFO_LEN = 15,

    /* 3.6.8.1's appendix: the info field and the Router Information Global TLV the clause makes a minimum, which is
       Annex I.4.7's two-octet bitmap behind Annex I.4.1's tag and length */
    NWK_BEACON_TLV_ROUTER_INFORMATION = 70,
    NWK_BEACON_TLV_ROUTER_INFO_VALUE_OCTETS = 2,
    NWK_ROUTER_INFO_HUB_CONNECTIVITY = 0x0001,  /* Table I-6's bit 0 */
    NWK_ROUTER_INFO_LONG_UPTIME = 0x0002,       /* bit 1: up for more than 24 hours */
    NWK_ROUTER_INFO_PREFERRED_PARENT = 0x0004,  /* bit 2 */
    NWK_BEACON_PAYLOAD_LEN = NWK_BEACON_INFO_LEN + 2 + NWK_BEACON_TLV_ROUTER_INFO_VALUE_OCTETS,

    NWK_BEACON_PROTOCOL_ID = 0x00,   /* Table 3-83: "SHALL always be set to 0, indicating the Zigbee protocols" */
    NWK_BEACON_PROTOCOL_VERSION = 0x02,
    NWK_BEACON_STACK_PROFILE = 0x02, /* the Zigbee PRO profile (Table 3-83's Stack profile) */
    NWK_BEACON_TX_OFFSET_NONE = 0xffffff, /* Table 3-83: "0xFFFFFF in beaconless networks" */
    NWK_STACK_PROFILE_PRO = 0x02           /* Table 3-83: the profile every Zigbee 2007 and later network states */
};

typedef struct Nwk_BeaconInfo
{
    uint32_t stackProfile;
    uint32_t protocolVersion;
    int routerCapacity;
    uint32_t deviceDepth;
    int endDeviceCapacity;
    uint64_t extendedPanId;
    uint32_t txOffset;
    uint32_t updateId;
} Nwk_BeaconInfo;

/* Write Table 3-83's fifteen octets in Figure 3-53's bit order, the extended PAN identifier least significant
   octet first: the order R23.1's own worked beacon prints it in. */
ZbStatus Nwk_ComposeBeaconInfo(const Nwk_BeaconInfo *info, uint8_t *out, uint32_t outCap, uint32_t *outLen);

/* 3.6.8.1's payload: those fifteen octets and the Router Information Global TLV behind them, which the clause makes
   a minimum of the device's own appendix. The bitmap reports only what this device can state, and it states none of
   the six capabilities Table I-6 names, so every bit of it is zero. */
ZbStatus Nwk_ComposeBeaconPayload(const Nwk_BeaconInfo *info, uint8_t *out, uint32_t outCap, uint32_t *outLen);

/* Read those octets back. A span shorter than the fifteen is ZB_ERR_BAD_FRAME. */
ZbStatus Nwk_ParseBeaconInfo(const uint8_t *bytes, uint32_t len, Nwk_BeaconInfo *outInfo);

/* Whether a beacon payload carries 3.6.8.1's appendix, the mark of an R23 or later parent: the octets behind the
   info field read as whole TLVs, the Router Information Global TLV among them. */
int Nwk_BeaconHasAppendix(const uint8_t *payload, uint32_t len);

/* The same walk, and the Router Information Global TLV's two-octet bitmap (Annex I.4.7, Table I-6), low octet first;
   0 when the payload carries no appendix. */
int Nwk_BeaconRouterInformation(const uint8_t *payload, uint32_t len, uint16_t *outBitmap);

#endif /* NWK_BEACON_H */
