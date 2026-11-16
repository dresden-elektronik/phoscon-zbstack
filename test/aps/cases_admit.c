/* A trust centre admitting a device through a router (docs/internals/conformance.md §3, docs/internals/conformance.md's `aps.c` row): R23.1
   4.4.3's update-device door, a router's command judged by 4.4.3.2.3 and Table 4-6, and 4.6.3.7.1's tunnelled key.
   Every frame is secured or opened by the module of the device it belongs to, not by the one under test. */

#include "aps.h"
#include "aps_admit.h"
#include "aps_helpers.h"
#include "aps_keydoor.h"
#include "aps_transportkey.h"
#include "security.h"
#include "test_harness.h"
#include "zb_utils.h"

/* This device, the router that reports a join to it, and the device that joined through that router. */
#define OWN_SHORT 0xdead
#define ADDR_PEER 0x0011

#define OWN_IEEE 0x00212effff048a12
#define PEER_IEEE 0x00212effff05a888
#define JOINER_IEEE 0x00212effff070001
#define OTHER_IEEE 0x00212effff060000

#define JOINER_SHORT 0x1234

static const char *s_linkKeyHex = "0f0e0d0c0b0a09080706050403020100";
static const char *s_nwkKeyHex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";

/* The trust centre's side and the router's, wired: `trustCenter` names the AIB's apsTrustCenterAddress on the
   receiving device, and `unique` whether the receiver's pair for the router is a unique link key or the global one. */
typedef struct AdmitRig
{
    Rig rig;
    Test_BandA peer;
    Security receiver;
    Security router;
    Security_KeyDescriptor key;
    Security_KeyPairEntry receiverPairs[1];
    Security_KeyPairEntry routerPairs[1];
    Air air[AIR_LOG_MAX];
    uint32_t airCount;
} AdmitRig;

static Security_KeyPairEntry admitPair(uint64_t partner, uint32_t linkKeyType)
{
    Security_KeyPairEntry entry;

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.deviceIeee = partner;
    entry.keyAttributes = SECURITY_KEYPAIR_ATTR_VERIFIED;
    entry.outgoingFrameCounter = 1;
    entry.linkKeyType = linkKeyType;
    entry.verifiedFrameCounter = 1;
    Test_ParseHex(s_linkKeyHex, entry.key, SECURITY_KEY_OCTETS);

    return entry;
}

static void admitBuildAt(AdmitRig *a, uint64_t trustCenter, int unique, uint16_t peerShort)
{
    Security_Config cfg;

    Zb_memset(a, 0, sizeof *a);

    a->receiverPairs[0] = unique ? admitPair(PEER_IEEE, SECURITY_LINK_KEY_UNIQUE)
                                 : admitPair(0, SECURITY_LINK_KEY_GLOBAL);
    a->routerPairs[0] = admitPair(OWN_IEEE, unique ? SECURITY_LINK_KEY_UNIQUE : SECURITY_LINK_KEY_GLOBAL);

    a->key.inUse = 1;
    a->key.outgoingFrameCounter = 1;
    Test_ParseHex(s_nwkKeyHex, a->key.key, SECURITY_KEY_OCTETS);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = OWN_IEEE;
    cfg.trustCenterIeee = trustCenter;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.authenticated = 1;
    cfg.keys = &a->key;
    cfg.keyCount = 1;
    cfg.keyPairs = a->receiverPairs;
    cfg.keyPairCount = 1;
    Test_ExpectStatus(Security_Init(&a->receiver, &cfg), ZB_OK, "the receiving device's module");

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = PEER_IEEE;
    cfg.trustCenterIeee = OWN_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.keyPairs = a->routerPairs;
    cfg.keyPairCount = 1;
    Test_ExpectStatus(Security_Init(&a->router, &cfg), ZB_OK, "and the router's, holding the link key for the trust centre");

    rigBuild(&a->rig, OWN_SHORT);
    Aps_AttachSecurity(&a->rig.aps, &a->receiver);
    peerBuild(&a->peer, peerShort);
    seedNeighbor(&a->rig.stack.nwk, peerShort);
    seedNeighbor(&a->peer.nwk, OWN_SHORT);
    scriptOutcomes(&a->rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&a->peer.model, LOOPBACK_TX_MAX, 1);
}

static void admitBuild(AdmitRig *a, uint64_t trustCenter, int unique)
{
    admitBuildAt(a, trustCenter, unique, ADDR_PEER);
}

/* Figure 4-13's command for the joiner after a two-octet header of `fcf` and `counter`: 14 octets. */
static uint32_t admitCommand(uint8_t *out, uint8_t fcf, uint8_t counter, uint8_t status)
{
    Aps_UpdateDevice body;
    uint32_t len = 0;

    out[0] = fcf;
    out[1] = counter;

    Zb_memset(&body, 0, (uint32_t)sizeof body);
    body.deviceIeee = JOINER_IEEE;
    body.deviceShortAddress = JOINER_SHORT;
    body.status = status;

    Test_ExpectStatus(Aps_UpdateDeviceCompose(&body, out + 2, APS_FRAME_MAX - 2, &len), ZB_OK,
                      "the router's Update Device for the joiner (Figure 4-13)");

    return 2 + len;
}

/* The router's command delivered, APS secured by its own module or with NWK security alone. */
static void admitDeliver(AdmitRig *a, int apsSecured, uint8_t counter, uint8_t status, uint32_t nowMs)
{
    uint8_t plain[APS_FRAME_MAX];
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t plainLen;
    uint32_t len = 0;

    plainLen = admitCommand(plain, apsSecured ? 0x21 : 0x01, counter, status);

    if (apsSecured)
    {
        Test_ExpectStatus(Security_ProtectAps(&a->router, 0, SECURITY_KEY_ID_DATA, plain, 2, plain + 2, plainLen - 2, 1,
                                              apdu, (uint32_t)sizeof apdu, &len), ZB_OK,
                          "the router secures it under the link key it holds for the trust centre");
        peerDelivers(&a->peer, &a->rig.stack.model, OWN_SHORT, apdu, len, nowMs);
    }
    else
        peerDelivers(&a->peer, &a->rig.stack.model, OWN_SHORT, plain, plainLen, nowMs);

    stepAt(&a->rig, a->air, &a->airCount, nowMs + 1);
}

/* 4.4.3.2.2 and 4.6.3.2.1 under a global trust centre link key: the router's APS secured copy is indicated with the
   router as its source, and its second, NWK-only copy of the same report adds nothing to the ring. */
void caseUpdateDeviceAtTheTrustCentre(void)
{
    AdmitRig a;
    Aps_UpdateDeviceIndication got[APS_UPDATE_DEVICE_INDICATION_MAX];

    admitBuild(&a, OWN_IEEE, 0);
    Test_Expect(Nwk_AddrMapLearn(Nwk_AddrMapOf(&a.rig.stack.nwk), ADDR_PEER, PEER_IEEE, OWN_SHORT, 90)
                == NWK_ADDRMAP_LEARNED, "the map holds the router, as its own NWK headers teach it");

    admitDeliver(&a, 1, 0x40, APS_UPDATE_DEVICE_UNSECURED_JOIN, 100);
    Test_ExpectCount(Aps_UpdateDevicesIndicated(&a.rig.aps), 1, "the APS secured copy is indicated (4.4.3.2.2)");

    admitDeliver(&a, 0, 0x41, APS_UPDATE_DEVICE_UNSECURED_JOIN, 110);
    Test_ExpectCount(Aps_UpdateDevicesRefused(&a.rig.aps), 0,
                     "the NWK-only copy is accepted: Table 4-6 requires no APS encryption under a global key");
    Test_ExpectCount(Aps_UpdateDevicesRepeated(&a.rig.aps), 1, "and taken as the report already queued");
    Test_ExpectCount(Aps_UpdateDevicesIndicated(&a.rig.aps), 1, "so one join is one indication");

    Test_ExpectCount(Aps_PollUpdateDeviceIndications(&a.rig.aps, got, APS_UPDATE_DEVICE_INDICATION_MAX), 1,
                     "the ring holds it alone");
    Test_Expect(got[0].srcIeee == PEER_IEEE && got[0].srcAddress == ADDR_PEER,
                "with the router as Table 4-15's SrcAddress, and its network address beside it");
    Test_Expect(got[0].deviceIeee == JOINER_IEEE && got[0].deviceShortAddress == JOINER_SHORT
                    && got[0].status == APS_UPDATE_DEVICE_UNSECURED_JOIN,
                "and the joiner's two addresses and status 0x01 as the command carried them");
}

/* Table 4-6's Update Device row: a router whose trust centre link key is unique must APS encrypt, and a router this
   device cannot name by its 64-bit address has no key type to judge by. */
void caseUpdateDeviceUnencryptedRefused(void)
{
    AdmitRig a;

    admitBuild(&a, OWN_IEEE, 1);
    Test_Expect(Nwk_AddrMapLearn(Nwk_AddrMapOf(&a.rig.stack.nwk), ADDR_PEER, PEER_IEEE, OWN_SHORT, 90)
                == NWK_ADDRMAP_LEARNED, "the map holds the router");

    admitDeliver(&a, 0, 0x40, APS_UPDATE_DEVICE_UNSECURED_JOIN, 100);
    Test_ExpectCount(Aps_UpdateDevicesRefused(&a.rig.aps), 1,
                     "a NWK-only copy from a router with a unique link key is refused (Table 4-6)");
    Test_ExpectCount(Aps_UpdateDevicesIndicated(&a.rig.aps), 0, "and indicates nothing");

    admitDeliver(&a, 1, 0x41, APS_UPDATE_DEVICE_UNSECURED_JOIN, 110);
    Test_ExpectCount(Aps_UpdateDevicesIndicated(&a.rig.aps), 1, "while its APS secured copy is indicated");

    admitBuild(&a, OWN_IEEE, 0);
    admitDeliver(&a, 0, 0x40, APS_UPDATE_DEVICE_UNSECURED_JOIN, 100);
    Test_ExpectCount(Aps_UpdateDevicesRefused(&a.rig.aps), 1,
                     "and under a global key, a NWK-only copy from a router the address map does not name is refused too");
}

/* 4.4.3.2.3 and 4.4.3.1.3: a device that is not the trust centre ignores the command, and its own
   APSME-UPDATE-DEVICE.request becomes the command to its trust centre. */
void caseUpdateDeviceAwayFromTheTrustCentre(void)
{
    AdmitRig a;
    Aps_UpdateDeviceReq req;

    admitBuild(&a, OTHER_IEEE, 0);

    admitDeliver(&a, 1, 0x40, APS_UPDATE_DEVICE_UNSECURED_JOIN, 100);
    Test_ExpectCount(Aps_UpdateDevicesIgnored(&a.rig.aps), 1,
                     "a device whose apsTrustCenterAddress names another device ignores an Update Device (4.4.3.2.3)");
    Test_ExpectCount(Aps_UpdateDevicesIndicated(&a.rig.aps), 0, "and indicates nothing");

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.destIeee = OTHER_IEEE;
    req.deviceIeee = JOINER_IEEE;
    req.deviceShortAddress = JOINER_SHORT;
    req.status = APS_UPDATE_DEVICE_UNSECURED_JOIN;

    Test_ExpectStatus(Aps_UpdateDeviceRequest(&a.rig.aps, &req, 120), ZB_OK,
                      "while its own request is taken as the command to its trust centre (4.4.3.1.3)");
    Test_ExpectCount(Aps_UpdateDevicesSent(&a.rig.aps), 1, "and counted as one report");
}

/* 4.4.3.1.3 at the trust centre: the request is the indication with this device as its source, and the ring's own
   rules, a repeat, a reserved status and a full ring. */
void caseUpdateDeviceDoor(void)
{
    AdmitRig a;
    Aps_UpdateDeviceReq req;
    Aps_UpdateDeviceIndication got[APS_UPDATE_DEVICE_INDICATION_MAX];
    uint32_t i;

    admitBuild(&a, OWN_IEEE, 0);

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.destIeee = OWN_IEEE;
    req.deviceIeee = JOINER_IEEE;
    req.deviceShortAddress = JOINER_SHORT;
    req.status = APS_UPDATE_DEVICE_TC_REJOIN;

    Test_ExpectStatus(Aps_UpdateDeviceRequest(&a.rig.aps, &req, 100), ZB_OK, "a trust centre's own request is taken");
    Test_ExpectStatus(Aps_UpdateDeviceRequest(&a.rig.aps, &req, 101), ZB_OK, "and the same request again");
    Test_ExpectCount(Aps_UpdateDevicesRepeated(&a.rig.aps), 1, "is the report already queued");

    Test_ExpectCount(Aps_PollUpdateDeviceIndications(&a.rig.aps, got, APS_UPDATE_DEVICE_INDICATION_MAX), 1,
                     "so the ring holds one indication");
    Test_Expect(got[0].srcIeee == OWN_IEEE && got[0].srcAddress == OWN_SHORT && got[0].deviceIeee == JOINER_IEEE
                    && got[0].status == APS_UPDATE_DEVICE_TC_REJOIN,
                "with this device as its source and the request's parameters (4.4.3.1.3)");

    req.status = 0x04;
    Test_ExpectStatus(Aps_UpdateDeviceRequest(&a.rig.aps, &req, 110), ZB_ERR_BAD_ARGUMENT,
                      "a status Table 4-14 reserves is refused");

    for (i = 0; i < APS_UPDATE_DEVICE_INDICATION_MAX; i++)
    {
        req.status = APS_UPDATE_DEVICE_UNSECURED_JOIN;
        req.deviceIeee = JOINER_IEEE + i;
        Test_ExpectStatus(Aps_UpdateDeviceRequest(&a.rig.aps, &req, 120), ZB_OK, "a distinct join fills the ring");
    }

    req.deviceIeee = JOINER_IEEE + APS_UPDATE_DEVICE_INDICATION_MAX;
    Test_ExpectStatus(Aps_UpdateDeviceRequest(&a.rig.aps, &req, 130), ZB_ERR_NO_SPACE,
                      "and one more finds it full");
    Test_ExpectCount(Aps_UpdateDevicesDropped(&a.rig.aps), 1, "dropped and counted (docs/internals/coding-rules.md §4.3)");
}

/* 4.4.2.1.3's TunnelCommand and 4.6.3.7.1: the network key for a device that joined through a router goes to that
   router inside a Tunnel, the Transport-Key within it secured for the joiner under the key-transport key with the
   extended nonce and the trust centre as its source, and opened by the joiner's own module. */
void caseTransportKeyTunnelled(void)
{
    AdmitRig a;
    Security joiner;
    Security_Config cfg;
    Security_KeyPairEntry joinerPairs[1];
    Security_ApsResult result;
    Aps_TransportKeyReq req;
    Aps_TransportKey body;
    Aps_Tunnel tunnel;
    uint8_t clear[APS_FRAME_MAX];
    uint8_t want[SECURITY_KEY_OCTETS];
    const uint8_t *apdu;
    uint32_t clearLen = 0;
    uint32_t apduLen;

    admitBuild(&a, OWN_IEEE, 0);

    joinerPairs[0] = admitPair(OWN_IEEE, SECURITY_LINK_KEY_GLOBAL);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = JOINER_IEEE;
    cfg.trustCenterIeee = OWN_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.keyPairs = joinerPairs;
    cfg.keyPairCount = 1;
    Test_ExpectStatus(Security_Init(&joiner, &cfg), ZB_OK, "a joiner holding the global trust centre link key");

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.destIeee = JOINER_IEEE;
    req.nwkDst = JOINER_SHORT;
    req.standardKeyType = APS_TK_TYPE_NETWORK_KEY;
    req.destinationIeee = JOINER_IEEE;
    req.tunnel = 1;
    req.tunnelNwk = ADDR_PEER;
    req.tunnelIeee = PEER_IEEE;
    Test_ParseHex(s_nwkKeyHex, req.key, APS_TK_KEY_OCTETS);
    Zb_memcpy(want, req.key, SECURITY_KEY_OCTETS);

    Test_ExpectStatus(Aps_TransportKeyRequest(&a.rig.aps, &req, 100), ZB_OK,
                      "the trust centre sends the joiner its key through the router that reported it");
    Test_Expect(a.rig.aps.tx[0].nwkDst == ADDR_PEER && a.rig.aps.tx[0].nwkSecurity == 1
                    && a.rig.aps.tx[0].apsSecurity == 0,
                "as one transaction to the router, protected by the network layer and not by APS (Table 4-7's Tunnel row)");

    stepAt(&a.rig, a.air, &a.airCount, 101);
    Test_ExpectCount(a.airCount, 1, "one frame on the air");

    if (a.airCount != 1)
        return;

    Test_ExpectCount(airDestOf(&a.air[0]), ADDR_PEER, "addressed to the router");

    apdu = apduOf(&a.air[0]);
    apduLen = apduLenOf(&a.air[0]);

    Test_Expect(apduLen > 3 && apdu[0] == 0x41 && apdu[2] == APS_CMD_TUNNEL,
                "an unsecured command asking for its acknowledgement, identifier 0x0e (Table 4-31)");
    Test_ExpectStatus(Aps_TunnelParse(apdu + 3, apduLen - 3, &tunnel), ZB_OK, "which reads as Figure 4-17's body");
    Test_Expect(tunnel.destinationIeee == JOINER_IEEE, "naming the joiner as its destination (4.4.11.6.2)");
    Test_Expect(tunnel.secured[0] == 0x21,
                "around a secured command that asks for no acknowledgement, which a joiner without the network key could not return");
    Test_ExpectCount(tunnel.secured[2], 0x30,
                     "its auxiliary frame naming the key-transport key with the extended nonce (4.6.3.7.1)");

    Test_ExpectStatus(Security_UnprotectAps(&joiner, tunnel.secured, tunnel.securedLen, 2, OWN_IEEE, 1, clear,
                                            (uint32_t)sizeof clear, &clearLen, &result), ZB_OK,
                      "the joiner's module opens it with the key it holds, the trust centre the nonce's source");
    Test_Expect(clearLen > 1 && clear[0] == APS_TK_COMMAND_ID
                    && Aps_TransportKeyParse(clear + 1, clearLen - 1, &body) == ZB_OK,
                "and reads a Transport-Key");
    Test_Expect(body.standardKeyType == APS_TK_TYPE_NETWORK_KEY && Zb_memcmp(body.key, want, SECURITY_KEY_OCTETS) == 0
                    && body.destinationIeee == JOINER_IEEE && body.sourceIeee == OWN_IEEE,
                "carrying the network key, to the joiner from the trust centre (Figure 4-10)");
}

/* 4.6.3.2.1 at a router whose trust centre is the peer: the report goes APS encrypted, and under the global trust
   centre link key a second, NWK-only copy follows; under a unique key one copy alone; and a router that does not yet
   know its trust centre has nobody to report to. */
void caseRouterReportsAJoin(void)
{
    AdmitRig a;
    Aps_UpdateDeviceReq req;
    Aps_UpdateDevice body;
    Security_ApsResult result;
    uint8_t clear[APS_FRAME_MAX];
    uint32_t clearLen = 0;
    const uint8_t *apdu;
    uint32_t apduLen;

    admitBuild(&a, PEER_IEEE, 0);
    Test_Expect(Nwk_AddrMapLearn(Nwk_AddrMapOf(&a.rig.stack.nwk), ADDR_PEER, PEER_IEEE, OWN_SHORT, 90)
                == NWK_ADDRMAP_LEARNED, "the router's map places its trust centre");

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.destIeee = PEER_IEEE;
    req.deviceIeee = JOINER_IEEE;
    req.deviceShortAddress = JOINER_SHORT;
    req.status = APS_UPDATE_DEVICE_UNSECURED_JOIN;

    Test_ExpectStatus(Aps_UpdateDeviceRequest(&a.rig.aps, &req, 100), ZB_OK, "a router reports a child's join");
    stepAt(&a.rig, a.air, &a.airCount, 101);
    Test_ExpectCount(a.airCount, 2, "as two frames under the global key (4.6.3.2.1)");

    if (a.airCount != 2)
        return;

    Test_Expect(airDestOf(&a.air[0]) == ADDR_PEER && airDestOf(&a.air[1]) == ADDR_PEER, "both to the trust centre");

    apdu = apduOf(&a.air[0]);
    apduLen = apduLenOf(&a.air[0]);
    Test_Expect(apdu[0] == 0x61, "the first a secured command asking for its acknowledgement");
    Test_ExpectStatus(Security_UnprotectAps(&a.router, apdu, apduLen, 2, OWN_IEEE, 1, clear, (uint32_t)sizeof clear,
                                            &clearLen, &result), ZB_OK,
                      "which the trust centre's module opens under the link key it holds");
    Test_Expect(clearLen > 1 && clear[0] == APS_CMD_UPDATE_DEVICE
                    && Aps_UpdateDeviceParse(clear + 1, clearLen - 1, &body) == ZB_OK,
                "and reads as Update Device");
    Test_Expect(body.deviceIeee == JOINER_IEEE && body.deviceShortAddress == JOINER_SHORT
                    && body.status == APS_UPDATE_DEVICE_UNSECURED_JOIN,
                "naming the joiner and status 0x01 (Figure 4-13)");

    apdu = apduOf(&a.air[1]);
    apduLen = apduLenOf(&a.air[1]);
    Test_Expect(apdu[0] == 0x41 && apdu[2] == APS_CMD_UPDATE_DEVICE
                    && Aps_UpdateDeviceParse(apdu + 3, apduLen - 3, &body) == ZB_OK && body.deviceIeee == JOINER_IEEE,
                "and the second the same command with APS security off, readable as it stands");

    admitBuild(&a, PEER_IEEE, 1);
    Test_ExpectStatus(Aps_UpdateDeviceRequest(&a.rig.aps, &req, 100), ZB_OK, "under a unique link key");
    stepAt(&a.rig, a.air, &a.airCount, 101);
    Test_ExpectCount(a.airCount, 1, "the report is one APS-encrypted frame");

    admitBuild(&a, 0, 0);
    Test_ExpectStatus(Aps_UpdateDeviceRequest(&a.rig.aps, &req, 100), ZB_ERR_NOT_READY,
                      "and a router that has not learned its trust centre (4.9.2) has nobody to report to");
}

/* The router's child the cases below tunnel to: in the table under its extended address, at `relationship`. */
static void admitChild(AdmitRig *a, uint32_t relationship)
{
    Nwk_NeighborTableEntry *entry;

    seedNeighbor(&a->rig.stack.nwk, JOINER_SHORT);
    entry = Nwk_NeighborOf(a->rig.stack.nwk.neighbors, JOINER_SHORT);
    Test_Expect(entry != 0, "the router holds the joiner as a neighbour");

    if (entry == 0)
        return;

    entry->extendedAddress = JOINER_IEEE;
    entry->ieeeKnown = 1;
    entry->deviceType = NWK_DEVICE_END_DEVICE;
    entry->relationship = relationship;
}

/* A Tunnel for the joiner from the peer, around a secured command written out by hand: 2 + 13 + 2 + 4 octets. */
static uint32_t admitTunnel(uint8_t *apdu, uint8_t *secured, uint32_t *securedLen)
{
    uint32_t len = 0;

    *securedLen = Test_ParseHex("2117" "30" "01000000" "128a04ffff2e2100" "c3d4" "a1b2c3d4", secured, 32);

    apdu[0] = 0x01;
    apdu[1] = 0x50;
    Test_ExpectStatus(Aps_TunnelCompose(JOINER_IEEE, secured, *securedLen, apdu + 2, APS_FRAME_MAX - 2, &len), ZB_OK,
                      "the trust centre's Tunnel for the joiner (Figure 4-17)");

    return 2 + len;
}

/* 4.6.3.7.2 and 4.6.3.2.1: a router takes a Tunnel from its trust centre for a child still at 0x05 and hands the
   command inside to that child unchanged and with NWK security off; a Tunnel for a child already authenticated, or
   one whose unencrypted source is not 0x0000, it refuses silently. */
void caseRouterRelaysATunnel(void)
{
    AdmitRig a;
    uint8_t apdu[APS_FRAME_MAX];
    uint8_t secured[32];
    uint32_t securedLen = 0;
    uint32_t len;
    const uint8_t *npdu;

    admitBuildAt(&a, PEER_IEEE, 0, 0x0000);
    admitChild(&a, NWK_REL_UNAUTHENTICATED_CHILD);
    len = admitTunnel(apdu, secured, &securedLen);

    peerDelivers(&a.peer, &a.rig.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&a.rig, a.air, &a.airCount, 101);

    Test_ExpectCount(Aps_TunnelsRelayed(&a.rig.aps), 1, "the router relays the Tunnel's command");
    Test_ExpectCount(a.airCount, 1, "as one frame");

    if (a.airCount == 1)
    {
        npdu = npduOf(&a.air[0]);
        Test_ExpectCount(airDestOf(&a.air[0]), JOINER_SHORT, "to the child");
        Test_Expect((npdu[1] & 0x02) == 0, "with network security off, the child holding no network key (4.6.3.7.2)");
        Test_ExpectOctets("carrying the secured command exactly as the Tunnel held it: header, auxiliary frame, payload, MIC",
                          apduOf(&a.air[0]), apduLenOf(&a.air[0]), secured, securedLen);
    }

    admitBuildAt(&a, PEER_IEEE, 0, 0x0000);
    admitChild(&a, NWK_REL_CHILD);
    len = admitTunnel(apdu, secured, &securedLen);
    peerDelivers(&a.peer, &a.rig.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&a.rig, a.air, &a.airCount, 101);
    Test_Expect(Aps_TunnelsDropped(&a.rig.aps) == 1 && Aps_TunnelsRelayed(&a.rig.aps) == 0,
                "a Tunnel for a child already authenticated is refused (4.6.3.2.1)");

    admitBuildAt(&a, PEER_IEEE, 0, ADDR_PEER);
    admitChild(&a, NWK_REL_UNAUTHENTICATED_CHILD);
    len = admitTunnel(apdu, secured, &securedLen);
    peerDelivers(&a.peer, &a.rig.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&a.rig, a.air, &a.airCount, 101);
    Test_Expect(Aps_TunnelsDropped(&a.rig.aps) == 1 && Aps_TunnelsRelayed(&a.rig.aps) == 0,
                "and so is an unencrypted Tunnel whose source is not 0x0000, which 4.4.1.3 cannot take as the trust centre's");
}

/* 2.2.5.1.1.3 and 2.2.5.2.3.1: a command is acknowledged with ACK format 1, and its acknowledgement carries none of
   the endpoint, cluster and profile fields a data frame's does: two octets, frame control and counter. */
void caseCommandAcknowledgedInFormatOne(void)
{
    AdmitRig a;
    uint8_t plain[APS_FRAME_MAX];
    uint32_t len;

    admitBuild(&a, OTHER_IEEE, 0);

    len = admitCommand(plain, 0x41, 0x5a, APS_UPDATE_DEVICE_UNSECURED_JOIN);
    peerDelivers(&a.peer, &a.rig.stack.model, OWN_SHORT, plain, len, 100);
    stepAt(&a.rig, a.air, &a.airCount, 101);

    Test_ExpectCount(a.airCount, 1, "a command asking for its acknowledgement is answered");

    if (a.airCount == 1)
        Test_ExpectHex("with frame type acknowledgement and ACK format 1 (0x12), then the command's own counter",
                       apduOf(&a.air[0]), apduLenOf(&a.air[0]), "125a");
}

/* 4.4.4.1.3 at the trust centre: the command naming the target goes to the parent APS encrypted under the parent's
   pair (Table 4-7), and a parent with no pair is not sent one. */
void caseRemoveDeviceSent(void)
{
    AdmitRig a;
    Aps_RemoveDeviceReq req;
    Security_ApsResult result;
    uint8_t clear[APS_FRAME_MAX];
    uint32_t clearLen = 0;
    uint64_t target = 0;
    const uint8_t *apdu;

    admitBuild(&a, OWN_IEEE, 1);

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.parentIeee = OTHER_IEEE;
    req.parentNwk = ADDR_PEER;
    req.targetIeee = JOINER_IEEE;

    Test_ExpectStatus(Aps_RemoveDeviceRequest(&a.rig.aps, &req, 100), ZB_ERR_NOT_FOUND,
                      "a parent this device holds no link key for is not sent the command");

    req.parentIeee = PEER_IEEE;

    Test_ExpectStatus(Aps_RemoveDeviceRequest(&a.rig.aps, &req, 100), ZB_OK,
                      "the trust centre asks the router to remove the joiner");
    Test_ExpectCount(Aps_RemoveDevicesSent(&a.rig.aps), 1, "counted as one command");

    stepAt(&a.rig, a.air, &a.airCount, 101);
    Test_ExpectCount(a.airCount, 1, "one frame on the air");

    if (a.airCount != 1)
        return;

    apdu = apduOf(&a.air[0]);
    Test_ExpectCount(airDestOf(&a.air[0]), ADDR_PEER, "addressed to the parent");
    Test_Expect(apdu[0] == 0x61, "a secured command asking for its acknowledgement");
    Test_ExpectStatus(Security_UnprotectAps(&a.router, apdu, apduLenOf(&a.air[0]), 2, OWN_IEEE, 1, clear,
                                            (uint32_t)sizeof clear, &clearLen, &result), ZB_OK,
                      "which the router's module opens under its link key");
    Test_Expect(clearLen > 1 && clear[0] == APS_CMD_REMOVE_DEVICE
                    && Aps_RemoveDeviceParse(clear + 1, clearLen - 1, &target) == ZB_OK && target == JOINER_IEEE,
                "and reads as Remove Device naming the joiner (Figure 4-14)");
}

/* A Remove Device for `target` delivered to the rig, APS secured by the `sender` module or, with none, not at all. */
static void admitRemoveDeliver(AdmitRig *a, Security *sender, uint8_t counter, uint64_t target, uint32_t nowMs)
{
    uint8_t plain[APS_FRAME_MAX];
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t len = 0;

    plain[0] = sender != 0 ? 0x21 : 0x01;
    plain[1] = counter;
    Test_ExpectStatus(Aps_RemoveDeviceCompose(target, plain + 2, APS_FRAME_MAX - 2, &len), ZB_OK,
                      "the trust centre's Remove Device (Figure 4-14)");

    if (sender != 0)
    {
        Test_ExpectStatus(Security_ProtectAps(sender, 0, SECURITY_KEY_ID_DATA, plain, 2, plain + 2, len, 1, apdu,
                                              (uint32_t)sizeof apdu, &len), ZB_OK,
                          "secured under the link key the sender holds");
        peerDelivers(&a->peer, &a->rig.stack.model, OWN_SHORT, apdu, len, nowMs);
    }
    else
        peerDelivers(&a->peer, &a->rig.stack.model, OWN_SHORT, plain, 2 + len, nowMs);

    stepAt(&a->rig, a->air, &a->airCount, nowMs + 1);
}

/* 4.4.4.2 and 4.6.3.6.2 at a router whose trust centre is the peer: an APS encrypted Remove Device from it is indicated,
   and the ring's full policy; an unencrypted one, which Table 4-7 forbids, one from a device that is not the trust
   centre, and any at the trust centre itself are refused. */
void caseRouterTakesARemoveDevice(void)
{
    AdmitRig a;
    Aps_RemoveDeviceIndication got[APS_REMOVE_DEVICE_INDICATION_MAX];

    admitBuild(&a, PEER_IEEE, 0);

    admitRemoveDeliver(&a, &a.router, 0x40, JOINER_IEEE, 100);
    Test_ExpectCount(Aps_RemoveDevicesIndicated(&a.rig.aps), 1, "the trust centre's encrypted command is indicated");
    Test_ExpectCount(Aps_PollRemoveDeviceIndications(&a.rig.aps, got, APS_REMOVE_DEVICE_INDICATION_MAX), 1,
                     "the ring holds it");
    Test_Expect(got[0].srcIeee == PEER_IEEE && got[0].targetIeee == JOINER_IEEE,
                "with the trust centre as its source and the joiner as its target (Table 4-17)");

    admitRemoveDeliver(&a, 0, 0x41, JOINER_IEEE, 110);
    Test_ExpectCount(Aps_RemoveDevicesRefused(&a.rig.aps), 1, "an unencrypted one is refused (Table 4-7)");

    admitRemoveDeliver(&a, &a.router, 0x42, JOINER_IEEE, 120);
    admitRemoveDeliver(&a, &a.router, 0x43, JOINER_IEEE + 1, 130);
    admitRemoveDeliver(&a, &a.router, 0x44, JOINER_IEEE + 2, 140);
    Test_ExpectCount(Aps_RemoveDevicesIndicated(&a.rig.aps), 1 + APS_REMOVE_DEVICE_INDICATION_MAX, "two more fill the ring");
    Test_ExpectCount(Aps_RemoveDevicesDropped(&a.rig.aps), 1, "and the third is dropped and counted");

    admitBuild(&a, OTHER_IEEE, 0);
    admitRemoveDeliver(&a, &a.router, 0x40, JOINER_IEEE, 100);
    Test_Expect(Aps_RemoveDevicesRefused(&a.rig.aps) == 1 && Aps_RemoveDevicesIndicated(&a.rig.aps) == 0,
                "and one from a device that is not the trust centre is refused (4.6.3.6.2)");
    admitBuild(&a, 0, 0);
    admitRemoveDeliver(&a, 0, 0x40, JOINER_IEEE, 100);
    Test_Expect(Aps_RemoveDevicesRefused(&a.rig.aps) == 1 && Aps_RemoveDevicesIndicated(&a.rig.aps) == 0,
                "as is an unencrypted one at a router that has not learned its trust centre, the two names both unset");
    admitBuild(&a, OWN_IEEE, 0);
    admitRemoveDeliver(&a, &a.receiver, 0x40, JOINER_IEEE, 100);
    Test_Expect(Aps_RemoveDevicesRefused(&a.rig.aps) == 1 && Aps_RemoveDevicesIndicated(&a.rig.aps) == 0,
                "and a trust centre takes none, even one its own key secured in its own name");
}
