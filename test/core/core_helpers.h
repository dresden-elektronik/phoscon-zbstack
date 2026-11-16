/* The `device` suite's shared machinery: one whole device on a loopback model, and a band-A peer whose own network
   layer composes the frames that arrive at it, so a case reads a frame the stack built rather than octets it wrote. */

#ifndef DEVICE_HELPERS_H
#define DEVICE_HELPERS_H

#include <stdint.h>

#include "aps_frame.h"
#include "loopback_radio.h"
#include "rig_band_a.h"
#include "zb_core.h"

/* The device under test and the peer that talks to it: one PAN, channel 26, and two identities. Channel 26 is the
   one every host rig in this tree arms, so nothing composed here can be taken for measured traffic
   (docs/internals/hardware.md §7). */
#define DEVICE_OWN_SHORT 0x0042
#define DEVICE_OWN_IEEE 0x0123456789abcdef
#define DEVICE_PEER_SHORT 0x0053
#define DEVICE_PEER_IEEE 0x1011121314151617
#define DEVICE_PAN_ID 0x1a2b
#define DEVICE_EXTENDED_PAN_ID 0x0f0e0d0c0b0a0908
#define DEVICE_CHANNEL 26

/* The trust centre's two keys: the network key it hands out and the global link key that protects the handing. */
#define DEVICE_NETWORK_KEY_HEX "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
#define DEVICE_LINK_KEY_HEX "5a6967426565416c6c69616e63653039"

/* The two endpoints a case registers, and the profile and clusters its descriptors name. */
#define DEVICE_EP_FIRST 0x01
#define DEVICE_EP_SECOND 0x02
#define DEVICE_PROFILE_ID 0x0104
#define DEVICE_INPUT_CLUSTER 0x0006
#define DEVICE_OUTPUT_CLUSTER 0x0008
#define DEVICE_MANUFACTURER_CODE 0x1037

/* A second pair, one device on each side of the air: the asking end device and the serving coordinator. */
#define DEVICE_ASKER_SHORT 0x0042
#define DEVICE_ASKER_IEEE 0x0123456789abcdef
#define DEVICE_SERVER_SHORT 0x0000
#define DEVICE_SERVER_IEEE 0x1011121314151617

typedef struct DeviceRig
{
    Loopback_Radio model;
    Zb_Core dev;
    Test_BandA peer;
    Zb_CoreConfig cfg;
} DeviceRig;

/* The device as a coordinator, so no case sees a join announcement it did not ask for, and a router peer that holds
   it as a neighbour. */
void deviceRigBuild(DeviceRig *rig);

/* The same rig with a router under test, which announces itself once it is on a network. */
void deviceRigBuildRouter(DeviceRig *rig);

/* The same rig with an end device under test, the peer its parent and the extended PAN its network's. */
void deviceRigBuildEndDevice(DeviceRig *rig);

/* The coordinator as its network's trust centre: it holds the network key and the global trust centre link key, and
   a device that joins it is sent the network key. */
void deviceRigBuildTrustCentre(DeviceRig *rig);

/* Two devices, one asking and one serving, with the neighbour entry each needs to reach the other. */
typedef struct DevicePair
{
    Loopback_Radio askerModel;
    Loopback_Radio serverModel;
    Zb_Core asker;
    Zb_Core server;
    Zb_CoreConfig askerCfg;
    Zb_CoreConfig serverCfg;
    Radio_Handle askerSeen;
    Radio_Handle serverSeen;
} DevicePair;

void devicePairAt(DevicePair *pair);
void devicePairTurn(DevicePair *pair, uint32_t nowMs);

/* Three devices for a join through a router: the trust centre at 0x0000, a router already on its network, and a
   joiner that holds only the global link key and hears the router alone, the air crossing as that range says. */
#define DEVICE_TRIO_TC_IEEE 0x2021222324252627
#define DEVICE_TRIO_ROUTER_SHORT 0x1001
#define DEVICE_TRIO_ROUTER_IEEE 0x3031323334353637
#define DEVICE_TRIO_JOINER_IEEE 0x4041424344454647

typedef struct DeviceTrio
{
    Loopback_Radio tcModel;
    Loopback_Radio routerModel;
    Loopback_Radio joinerModel;
    Zb_Core tc;
    Zb_Core router;
    Zb_Core joiner;
    Zb_CoreConfig tcCfg;
    Zb_CoreConfig routerCfg;
    Zb_CoreConfig joinerCfg;
    Radio_Handle tcToRouter;
    Radio_Handle routerToTc;
    Radio_Handle routerToJoiner;
    Radio_Handle joinerToRouter;
} DeviceTrio;

void deviceTrioAt(DeviceTrio *trio);

/* The same three devices with the router not on the network yet: no address of its own and no network key, only the
   trust centre's link key, so it joins through the façade's door like the end device does. */
void deviceTrioUnjoinedAt(DeviceTrio *trio);
void deviceTrioTurn(DeviceTrio *trio, uint32_t nowMs);

/* A descriptor of Table 2-40's shape with both cluster lists filled. */
void deviceDescriptor(Af_SimpleDescriptor *descriptor, uint8_t endpoint);

/* An APDU handed to the device through the peer's own network layer, which is the only way an APS frame arrives
   (2.2.8.4.1). */
void devicePeerSends(DeviceRig *rig, const Aps_Frame *frame, const uint8_t *asdu, uint32_t asduLength,
                     uint32_t nowMs);

/* The device's turn, with the air it produced left in its own model. */
void deviceStep(DeviceRig *rig, uint32_t nowMs);

/* The newest data frame the device put on the air whose cluster is `cluster`, or 0 when it answered nothing. The
   cluster 0 asks for any data frame, and an acknowledgement is never one. */
int deviceAnswer(DeviceRig *rig, uint16_t cluster, uint16_t *clusterOut, uint8_t *asdu, uint32_t asduCap,
                 uint32_t *asduLength, uint8_t *dstEndpoint);

#endif
