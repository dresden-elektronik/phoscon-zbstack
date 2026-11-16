/* The `device` suite's trust centre half: the network key a join is owed, decided from the update-device indication
   a join becomes at the trust centre (R23.1 4.6.3.2.1, 4.4.3.2.3). The joiner is the peer's own network layer making
   3.6.1.6.1.2's rejoin, with or without the network key, so the frame the trust centre reads is one a stack built. */

#include <stdint.h>

#include "aps_admit.h"
#include "aps_frame.h"
#include "core_helpers.h"
#include "nwk.h"
#include "nwk_addr.h"
#include "nwk_leave.h"
#include "nwk_neighbor.h"
#include "security.h"
#include "test_harness.h"
#include "zb_utils.h"

/* Hand the newest frame `from` put on its side of the seam to `to`, as the frame it is. */
static void trustHandOver(Loopback_Radio *from, Loopback_Radio *to)
{
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Loopback_FrameSpec spec;
    uint32_t got;
    uint32_t newest = 0;
    uint32_t index;

    got = LoopbackRadio_Sent(from, sent, LOOPBACK_TX_MAX);

    if (got == 0)
    {
        Test_Fault("the sending side put no frame on its own side of the seam for this case to hand over");

        return;
    }

    for (index = 1; index < got; index++)
    {
        if (sent[index].handle > sent[newest].handle)
            newest = index;
    }

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);

    spec.len = sent[newest].len;
    spec.bytes = sent[newest].bytes;
    spec.rssiDbm = -60;
    spec.lqi = 200;
    spec.stampTicks = 2;

    if (LoopbackRadio_Inject(to, &spec, 1) != ZB_OK)
        Test_Fault("the frame the sending side put on the air did not arrive in front of the other MAC");
}

/* The peer asks the trust centre, which it holds as its parent, to keep it on the network: 3.2.2.13's RejoinNetwork
   0x02 as the router the trust centre already holds it as, secured when the peer holds the network key. */
static void trustRejoin(DeviceRig *rig, Security *peerSecurity, uint32_t nowMs)
{
    Nwk_JoinRequestParameters req;
    Nwk_NeighborTableEntry *parent;

    parent = Nwk_NeighborOf(rig->peer.nwk.neighbors, DEVICE_OWN_SHORT);
    Test_Expect(parent != 0, "the peer holds the trust centre as a neighbour");

    if (parent == 0)
        return;

    parent->relationship = NWK_REL_PARENT;
    parent->extendedAddress = DEVICE_OWN_IEEE;
    parent->ieeeKnown = 1;

    if (peerSecurity != 0)
        Nwk_AttachSecurity(&rig->peer.nwk, peerSecurity);

    /* A rejoin is answered whether or not joining is permitted (8077-8082, 8090), so the trust centre opens nothing. */
    Test_ExpectStatus(Zb_CoreStep(&rig->dev, nowMs - 100), ZB_OK, "the trust centre's turn states its radio's mode");

    /* An extended PAN of zero is the network the device is on, so the request goes to the parent it holds. */
    Zb_memset(&req, 0, (uint32_t)sizeof req);

    req.rejoinNetwork = 0x02;
    req.capability.deviceType = 1;
    req.capability.rxOnWhenIdle = 1;
    req.capability.allocateAddress = 1;
    req.securityEnable = peerSecurity != 0 ? 1 : 0;

    Test_ExpectStatus(Nwk_JoinRequest(&rig->peer.nwk, &req, nowMs), ZB_OK,
                      "the peer asks its parent to rejoin it (3.6.1.6.1.2)");

    trustHandOver(&rig->peer.model, &rig->model);

    Test_ExpectStatus(Zb_CoreStep(&rig->dev, nowMs + 100), ZB_OK, "the trust centre's turn reads the rejoin request");
    Test_ExpectCount(Zb_CoreJoinsHeard(&rig->dev), 1, "and its network layer indicates the rejoin (3.2.2.14)");
}

/* 4.4.3.2.3 with 4.6.3.2.2.3: a rejoin without security is Table 4-14's trust centre rejoin, owed the network key
   when the trust centre holds a unique link key for the device (12483-12487). */
void caseTrustCentreRejoinIsOwedTheKey(void)
{
    DeviceRig rig;
    uint8_t unique[SECURITY_KEY_OCTETS];

    deviceRigBuildTrustCentre(&rig);

    Zb_memset(unique, 0x5a, (uint32_t)sizeof unique);
    Test_Expect(Security_SetUnverifiedPair(&Zb_CoreLayers(&rig.dev)->security, DEVICE_PEER_IEEE, DEVICE_PEER_SHORT,
                                           unique) >= 0,
                "the trust centre holds a unique link key for the device");

    trustRejoin(&rig, 0, 1000);

    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 1600), ZB_OK, "the trust centre's turn after the rejoin's own exchange");
    Test_ExpectCount(Zb_CoreNetworkKeysSent(&rig.dev), 1, "sends the device the network key");
    Test_ExpectCount(Zb_CoreTrustCentreRejoinsRefused(&rig.dev), 0, "and refuses nothing");
}

/* 12483-12487: a trust centre rejoin from a device the trust centre holds no unique link key for is rejected, and
   12579-12582 leaves the device to time out, so no key is sent. */
void caseTrustCentreRejoinWithoutAUniqueKeyIsRefused(void)
{
    DeviceRig rig;

    deviceRigBuildTrustCentre(&rig);

    trustRejoin(&rig, 0, 1000);

    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 1600), ZB_OK, "the trust centre's turn after the rejoin's own exchange");
    Test_ExpectCount(Zb_CoreNetworkKeysSent(&rig.dev), 0, "sends no key: the global key is not the device's own");
    Test_ExpectCount(Zb_CoreTrustCentreRejoinsRefused(&rig.dev), 1, "and counts the refusal");
}

/* The peer's module, holding the trust centre's network key. */
static void trustPeerSecurity(Security *security, Security_KeyDescriptor *key)
{
    Security_Config cfg;

    Zb_memset(key, 0, sizeof *key);
    key->inUse = 1;
    key->outgoingFrameCounter = 1;
    Test_ParseHex(DEVICE_NETWORK_KEY_HEX, key->key, SECURITY_KEY_OCTETS);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = DEVICE_PEER_IEEE;
    cfg.trustCenterIeee = DEVICE_OWN_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.authenticated = 1;
    cfg.keys = key;
    cfg.keyCount = 1;
    Test_ExpectStatus(Security_Init(security, &cfg), ZB_OK, "a peer holding the network key");
}

/* 4.4.3.2.3: a secured rejoin is Table 4-14's 0x00, and the device that made it already holds the key it secured
   the request with, so the trust centre sends none. */
void caseSecuredRejoinIsOwedNothing(void)
{
    DeviceRig rig;
    Security peerSecurity;
    Security_KeyDescriptor key;

    deviceRigBuildTrustCentre(&rig);
    trustPeerSecurity(&peerSecurity, &key);

    trustRejoin(&rig, &peerSecurity, 1000);

    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 1600), ZB_OK, "the trust centre's turn after the rejoin's own exchange");
    Test_ExpectCount(Zb_CoreNetworkKeysSent(&rig.dev), 0, "sends no key");
}

/* The peer, a router the trust centre's map holds, reports `deviceIeee` joined it with Update Device: NWK secured, no
   APS encryption, the frame handed to the trust centre's side of the seam. */
static void trustRouterReports(DeviceRig *rig, uint64_t deviceIeee, uint16_t deviceShort, uint8_t apsCounter,
                               uint32_t nowMs)
{
    Nwk_DataRequestParameters req;
    Aps_UpdateDevice body;
    Aps_Frame frame;
    uint8_t asdu[APS_FRAME_MAX];
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t asduLen = 0;
    uint32_t apduLen = 0;
    uint32_t offset = 0;

    Zb_memset(&body, 0, (uint32_t)sizeof body);
    body.deviceIeee = deviceIeee;
    body.deviceShortAddress = deviceShort;
    body.status = APS_UPDATE_DEVICE_UNSECURED_JOIN;
    Test_ExpectStatus(Aps_UpdateDeviceCompose(&body, asdu, (uint32_t)sizeof asdu, &asduLen), ZB_OK,
                      "the router's Update Device for a device that joined it (Figure 4-13)");

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = APS_FRAME_TYPE_COMMAND;
    frame.deliveryMode = APS_DELIVERY_UNICAST;
    frame.apsCounter = apsCounter;
    Test_ExpectStatus(ApsFrame_Compose(&frame, asdu, asduLen, apdu, (uint32_t)sizeof apdu, &apduLen, &offset), ZB_OK,
                      "as an unencrypted APS command");

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.dstAddr = DEVICE_OWN_SHORT;
    req.nsdu = apdu;
    req.nsduLength = apduLen;
    req.securityEnable = 1;
    Test_ExpectStatus(Nwk_DataRequest(&rig->peer.nwk, &req, nowMs), ZB_OK, "which the router's network layer secures");

    trustHandOver(&rig->peer.model, &rig->model);
}

/* A trust centre with the peer as a router it knows, the peer holding the network key. */
static void trustRouterRig(DeviceRig *rig, Security *peerSecurity, Security_KeyDescriptor *key)
{
    deviceRigBuildTrustCentre(rig);
    trustPeerSecurity(peerSecurity, key);
    Nwk_AttachSecurity(&rig->peer.nwk, peerSecurity);

    Test_Expect(Nwk_AddrMapLearn(Nwk_AddrMapOf(Zb_CoreNwk(&rig->dev)), DEVICE_PEER_SHORT, DEVICE_PEER_IEEE,
                                 DEVICE_OWN_SHORT, 900) == NWK_ADDRMAP_LEARNED,
                "the trust centre's map holds the router, as the router's own frames teach it");
}

/* 4.6.3.2.1 and 4.6.3.2.2.3 from the trust centre's side: a router reports a join with Update Device, and the network
   key for that device leaves inside a Tunnel to the router (4.6.3.7.1). The router's command is NWK secured and
   carries no APS encryption, which Table 4-6 accepts under the global link key this trust centre holds. */
void caseRouterReportedJoinIsTunnelled(void)
{
    DeviceRig rig;
    Security peerSecurity;
    Security_KeyDescriptor key;
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    uint32_t got;
    uint32_t newest = 0;
    uint32_t i;

    trustRouterRig(&rig, &peerSecurity, &key);
    trustRouterReports(&rig, 0x0011223344556677, 0x2345, 0x30, 1000);

    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 1100), ZB_OK, "the trust centre's turn reads the report");
    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 1600), ZB_OK, "and a later turn sends the key it owes");
    Test_ExpectCount(Zb_CoreNetworkKeysTunnelled(&rig.dev), 1, "through the router: one key, tunnelled");

    got = LoopbackRadio_Sent(&rig.model, sent, LOOPBACK_TX_MAX);
    Test_Expect(got > 0, "the trust centre put a frame on the air");

    if (got == 0)
        return;

    for (i = 1; i < got; i++)
    {
        if (sent[i].handle > sent[newest].handle)
            newest = i;
    }

    Test_Expect(sent[newest].len > 7
                    && (uint16_t)(sent[newest].bytes[5] | (sent[newest].bytes[6] << 8)) == DEVICE_PEER_SHORT,
                "and its newest frame is addressed at the MAC to the router, not to the device it carries a key for");
}

/* The trust centre and the router switch to `key` under sequence number 1, as a key update would leave them
   (4.6.3.4): installed beside the configured key, then made the active one. */
static void trustTrioRotate(DeviceTrio *trio, const uint8_t key[SECURITY_KEY_OCTETS])
{
    Security *tc = &Zb_CoreLayers(&trio->tc)->security;
    Security *router = &Zb_CoreLayers(&trio->router)->security;

    Test_ExpectStatus(Security_InstallNetworkKey(tc, key, 1, 1, 1), ZB_OK, "the trust centre holds a second key");
    Test_ExpectStatus(Security_InstallNetworkKey(router, key, 1, 1, 1), ZB_OK, "and so does the router");
    tc->nwkActiveKeySeqNumber = 1;
    router->nwkActiveKeySeqNumber = 1;
}

/* Two joins reported inside one settle are each owed the key, and one device reported twice is owed it once: each
   join keeps its own slot until its key goes. */
void caseEveryJoinInsideTheSettleIsOwedTheKey(void)
{
    DeviceRig rig;
    Security peerSecurity;
    Security_KeyDescriptor key;
    uint32_t nowMs;

    trustRouterRig(&rig, &peerSecurity, &key);
    trustRouterReports(&rig, 0x0011223344556677, 0x2345, 0x30, 1000);
    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 1100), ZB_OK, "the trust centre reads the first report");
    trustRouterReports(&rig, 0x0011223344556688, 0x2346, 0x31, 1150);
    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 1200), ZB_OK, "and a second, for another device, inside the settle");
    trustRouterReports(&rig, 0x0011223344556688, 0x2346, 0x32, 1250);
    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 1300), ZB_OK, "and the second device again");

    for (nowMs = 1500; nowMs <= 2500; nowMs += 50)
        Test_ExpectStatus(Zb_CoreStep(&rig.dev, nowMs), ZB_OK, "the turns after the settle");

    Test_ExpectCount(Zb_CoreNetworkKeysTunnelled(&rig.dev), 2, "two keys, one for each device");
    Test_ExpectCount(Zb_CoreKeysOwedRefused(&rig.dev), 0, "and no join refused a slot");
}

/* A join owed the key while every slot holds one is refused and counted; the joins already noted keep theirs. */
void caseKeyOwedPoolFullRefusesTheNewest(void)
{
    DeviceRig rig;
    Security peerSecurity;
    Security_KeyDescriptor key;
    uint32_t nowMs;
    uint32_t i;

    trustRouterRig(&rig, &peerSecurity, &key);

    for (i = 0; i <= ZB_CORE_KEY_OWED_MAX; i++)
    {
        trustRouterReports(&rig, 0x0011223344556600 + i, (uint16_t)(0x2340 + i), (uint8_t)(0x30 + i), 1000 + 20 * i);
        Test_ExpectStatus(Zb_CoreStep(&rig.dev, 1010 + 20 * i), ZB_OK, "the trust centre reads one more report");
    }

    for (nowMs = 1500; nowMs <= 3000; nowMs += 50)
        Test_ExpectStatus(Zb_CoreStep(&rig.dev, nowMs), ZB_OK, "the turns after the settle");

    Test_ExpectCount(Zb_CoreKeysOwedRefused(&rig.dev), 1, "the join past the pool is refused and counted");
    Test_ExpectCount(Zb_CoreNetworkKeysTunnelled(&rig.dev), ZB_CORE_KEY_OWED_MAX, "and each noted one is sent its key");
}

/* Every APS slot taken by a transaction waiting on a confirm that never comes, for a destination nothing answers. */
static void trustFillApsDoor(Aps_Aps *aps)
{
    uint32_t i;

    for (i = 0; i < APS_TX_MAX; i++)
    {
        Zb_memset(&aps->tx[i], 0, (uint32_t)sizeof aps->tx[i]);
        aps->tx[i].state = APS_TX_AWAITING_NLDE;
        aps->tx[i].nwkDst = 0x7777;
        aps->tx[i].lastHandle = RADIO_HANDLE_NONE;
    }
}

/* A key the APS door has no room for stays owed and goes once the door has room; one refused past the hold is
   counted, not lost silently. The pool is filled by hand, standing in for transactions that hold every slot. */
void caseKeyTheDoorRefusesStaysOwed(void)
{
    DeviceRig rig;
    Security peerSecurity;
    Security_KeyDescriptor key;
    Aps_Tx saved[APS_TX_MAX];
    Aps_Aps *aps;

    trustRouterRig(&rig, &peerSecurity, &key);
    aps = &Zb_CoreLayers(&rig.dev)->aps;
    trustRouterReports(&rig, 0x0011223344556677, 0x2345, 0x30, 1000);
    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 1100), ZB_OK, "the trust centre reads the report");

    Zb_memcpy(saved, aps->tx, (uint32_t)sizeof saved);

    trustFillApsDoor(aps);

    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 1600), ZB_OK, "the key is due and the APS door has no slot");
    Test_ExpectCount(Zb_CoreNetworkKeysSent(&rig.dev), 0, "so none is sent");
    Test_ExpectCount(Zb_CoreNetworkKeysRefused(&rig.dev), 0, "and none is counted refused");

    Zb_memcpy(aps->tx, saved, (uint32_t)sizeof saved);
    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 1700), ZB_OK, "the door has room again");
    Test_ExpectCount(Zb_CoreNetworkKeysTunnelled(&rig.dev), 1, "and the owed key goes");

    trustRouterReports(&rig, 0x0011223344556688, 0x2346, 0x31, 2000);
    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 2100), ZB_OK, "a second join is reported");
    Zb_memcpy(saved, aps->tx, (uint32_t)sizeof saved);

    trustFillApsDoor(aps);

    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 2600), ZB_OK, "its key meets a full door");
    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 4000), ZB_OK, "and the door stays full past the hold");
    Test_ExpectCount(Zb_CoreNetworkKeysRefused(&rig.dev), 1, "the key is counted refused");
    Zb_memcpy(aps->tx, saved, (uint32_t)sizeof saved);
    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 4100), ZB_OK, "with room again");
    Test_ExpectCount(Zb_CoreNetworkKeysTunnelled(&rig.dev), 1, "nothing more is sent for it");
}

/* The joiner associates with the router, three devices of this stack turning until 5000 ms: the authorization
   through a router the cases below start from, under a rotated key when `rotated` names one. */
static void trustTrioJoinUnder(DeviceTrio *trio, const uint8_t *rotated)
{
    Nwk_JoinParent row;
    Nwk_JoinRequestParameters jr;
    uint32_t nowMs;
    uint32_t i;

    deviceTrioAt(trio);

    for (nowMs = 0; nowMs < 200; nowMs += 50)
        deviceTrioTurn(trio, nowMs);

    if (rotated != 0)
        trustTrioRotate(trio, rotated);

    Test_ExpectStatus(Zb_CorePermitJoining(&trio->router, 60, 200), ZB_OK, "the router permits joining (3.2.2.7)");

    Zb_memset(&row, 0, (uint32_t)sizeof row);

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        row.extendedPanId[i] = (uint8_t)(DEVICE_EXTENDED_PAN_ID >> (8 * i));

    row.panId = DEVICE_PAN_ID;
    row.shortAddress = DEVICE_TRIO_ROUTER_SHORT;
    row.shortKnown = 1;
    row.extendedAddress = DEVICE_TRIO_ROUTER_IEEE;
    row.channel = DEVICE_CHANNEL;
    row.associationPermit = 1;
    row.deviceType = NWK_DEVICE_ROUTER;
    row.rxOnWhenIdle = 1;

    Test_ExpectStatus(Nwk_JoinParentAdd(Zb_CoreNwk(&trio->joiner), &row), ZB_OK,
                      "the joiner's discovery table holds the router, as its beacon would have written it");

    Zb_memset(&jr, 0, (uint32_t)sizeof jr);
    Zb_memcpy(jr.extendedPanId, row.extendedPanId, RADIO_ADDR_LEN);
    jr.capability.rxOnWhenIdle = 1;
    jr.capability.allocateAddress = 1;

    Test_ExpectStatus(Nwk_JoinRequest(Zb_CoreNwk(&trio->joiner), &jr, 250), ZB_OK,
                      "and asks to join through it (3.2.2.13)");

    for (nowMs = 300; nowMs <= 5000; nowMs += 50)
        deviceTrioTurn(trio, nowMs);
}

static void trustTrioJoin(DeviceTrio *trio)
{
    trustTrioJoinUnder(trio, 0);
}

/* The key a joiner is sent is the trust centre's active one, not the one its configuration named: after a switch to
   sequence number 1 the joiner holds that key under that number. */
void caseJoinerIsSentTheActiveKey(void)
{
    DeviceTrio trio;
    uint8_t rotated[SECURITY_KEY_OCTETS];
    const Security_KeyDescriptor *held;

    Test_ParseHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", rotated, SECURITY_KEY_OCTETS);
    trustTrioJoinUnder(&trio, rotated);

    held = Security_ActiveNetworkKey(&Zb_CoreLayers(&trio.joiner)->security);
    Test_ExpectCount(Aps_KeyInstalled(&Zb_CoreLayers(&trio.joiner)->aps), 1, "the joiner installed a network key");
    Test_Expect(held != 0 && held->keySeqNumber == 1, "under the sequence number the trust centre switched to");
    Test_Expect(held != 0 && Zb_memcmp(held->key, rotated, SECURITY_KEY_OCTETS) == 0, "and with that key's octets");
}

/* 4.6.3.2's authorization through a router, three devices of this stack: the router reports the join (4.6.3.2.1), the
   trust centre tunnels the key to it (4.6.3.7.1), the router hands it to its unauthenticated child (4.6.3.7.2), and the
   joiner, which never hears the trust centre, installs it and learns the trust centre from it (4.9.2). */
void caseJoinThroughARouter(void)
{
    DeviceTrio trio;
    const Nwk_NeighborTableEntry *child;
    uint64_t holder = 0;

    trustTrioJoin(&trio);

    Test_ExpectCount(Nwk_JoinStateOf(Zb_CoreNwk(&trio.joiner)), NWK_JOIN_JOINED,
                     "the joiner associated with the router");
    Test_Expect(Aps_UpdateDevicesSent(&Zb_CoreLayers(&trio.router)->aps) >= 1,
                "the router reported the join to the trust centre (4.6.3.2.1)");
    Test_ExpectCount(Aps_UpdateDevicesIndicated(&Zb_CoreLayers(&trio.tc)->aps), 1,
                     "the trust centre took it as one join, both copies notwithstanding");
    Test_ExpectCount(Zb_CoreNetworkKeysTunnelled(&trio.tc), 1, "and tunnelled the key to the router (4.6.3.7.1)");
    Test_ExpectCount(Aps_TunnelsRelayed(&Zb_CoreLayers(&trio.router)->aps), 1,
                     "which handed the command inside to its child (4.6.3.7.2)");
    Test_ExpectCount(Aps_KeyInstalled(&Zb_CoreLayers(&trio.joiner)->aps), 1,
                     "and the joiner installed the network key");
    Test_Expect(Zb_CoreLayers(&trio.joiner)->security.trustCenterIeee == DEVICE_TRIO_TC_IEEE,
                "taking the trust centre's address from it (4.9.2), a device it has never heard");

    child = Nwk_NeighborOf(Zb_CoreNwk(&trio.router)->neighbors, Nwk_OwnAddress(Zb_CoreNwk(&trio.joiner)));
    Test_ExpectCount(Zb_CoreZdpFramesConsumed(&trio.router), 1,
                     "then it announced itself, once it held the key, and the router read the announcement");
    Test_Expect(child != 0 && child->relationship == NWK_REL_CHILD,
                "as the network-secured frame that makes the joiner an authenticated child of the router");
    Test_Expect(Nwk_AddrMapExtendedOf(Nwk_AddrMapOf(Zb_CoreNwk(&trio.tc)), Nwk_OwnAddress(Zb_CoreNwk(&trio.joiner)),
                                      &holder) && holder == DEVICE_TRIO_JOINER_IEEE,
                "and the announcement carried the address the join gave it, which the trust centre now maps");
}

/* 4.6.3.6.1 and 4.6.3.6.2 end to end: the trust centre noted the router as the joiner's parent, so its removal goes to
   the router as Remove Device, which sends its child the leave request; the joiner leaves, and the note is gone. */
void caseRemoveThroughARouter(void)
{
    DeviceTrio trio;
    uint64_t parent = 0;
    uint32_t nowMs;

    trustTrioJoin(&trio);

    Test_Expect(Zb_CoreParentOf(&trio.tc, DEVICE_TRIO_JOINER_IEEE, &parent) == 1 && parent == DEVICE_TRIO_ROUTER_IEEE,
                "the trust centre noted the router as the joiner's parent");

    Test_ExpectStatus(Zb_CoreRemove(&trio.tc, DEVICE_TRIO_JOINER_IEEE, 5050), ZB_OK,
                      "the trust centre removes the joiner (4.6.3.6.1)");
    Test_ExpectCount(Aps_RemoveDevicesSent(&Zb_CoreLayers(&trio.tc)->aps), 1, "by one Remove Device to the router");
    Test_ExpectCount(Zb_CoreParentOf(&trio.tc, DEVICE_TRIO_JOINER_IEEE, &parent), 0, "and forgets the parent");

    for (nowMs = 5100; nowMs <= 6000; nowMs += 50)
        deviceTrioTurn(&trio, nowMs);

    Test_ExpectCount(Aps_RemoveDevicesIndicated(&Zb_CoreLayers(&trio.router)->aps), 1,
                     "the router takes the command from its trust centre (4.6.3.6.2)");
    Test_ExpectCount(Zb_CoreRemovalsTaken(&trio.router), 1, "and carries it out on its child");
    Test_ExpectCount(Nwk_IsPartOfNetwork(Zb_CoreNwk(&trio.joiner)), 0, "so the joiner is off the network");
    Test_ExpectCount(Nwk_IsPartOfNetwork(Zb_CoreNwk(&trio.router)), 1, "while the router stays on it");
}

/* The row a trust centre keeps for `ieee`, for a case that ages it. */
static Zb_CoreJoiner *trustJoinerRow(Zb_Core *tc, uint64_t ieee)
{
    uint32_t i;

    for (i = 0; i < ZB_CORE_JOINER_MAX; i++)
    {
        if (tc->joiners[i].inUse && tc->joiners[i].deviceIeee == ieee)
            return &tc->joiners[i];
    }

    return 0;
}

/* The router takes another short address, as an address conflict would make it, and says so with its Device_annce:
   every device that hears it, the trust centre included, maps its IEEE address to the new one. */
static void trustRouterMoves(DeviceTrio *trio, uint16_t newShort, uint32_t fromMs)
{
    Radio_Pib pib;
    uint32_t nowMs;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_SHORT_ADDRESS;
    pib.shortAddress = newShort;
    Test_ExpectStatus(Mac_SetPib(Zb_CoreMac(&trio->router), &pib), ZB_OK, "the router takes a new short address");
    Test_ExpectStatus(Zb_CoreAnnounce(&trio->router, fromMs), ZB_OK, "and announces it");

    for (nowMs = fromMs; nowMs <= fromMs + 500; nowMs += 50)
        deviceTrioTurn(trio, nowMs);
}

/* Remove Device goes where the parent is now: its address map follows its announcements, so a parent that changed
   address since it reported the join is still reached, and a map that does not hold it leaves the noted address. */
void caseRemoveFollowsTheParentsAddress(void)
{
    DeviceTrio trio;
    Zb_CoreJoiner *row;
    Nwk_AddressMapEntry *map;
    uint64_t holder = 0;
    uint32_t nowMs;
    uint32_t i;

    trustTrioJoin(&trio);
    row = trustJoinerRow(&trio.tc, DEVICE_TRIO_JOINER_IEEE);
    Test_Expect(row != 0 && row->parentShort == DEVICE_TRIO_ROUTER_SHORT, "the note holds the router's address");
    trustRouterMoves(&trio, 0x2b2b, 5000);
    Test_Expect(row != 0 && row->parentShort == DEVICE_TRIO_ROUTER_SHORT, "the note still holds the old one");
    Test_Expect(Nwk_AddrMapExtendedOf(Nwk_AddrMapOf(Zb_CoreNwk(&trio.tc)), 0x2b2b, &holder)
                && holder == DEVICE_TRIO_ROUTER_IEEE, "while the map follows the router's announcement");

    Test_ExpectStatus(Zb_CoreRemove(&trio.tc, DEVICE_TRIO_JOINER_IEEE, 5550), ZB_OK,
                      "the note is stale, the map is not");

    for (nowMs = 5600; nowMs <= 7000; nowMs += 50)
        deviceTrioTurn(&trio, nowMs);

    Test_ExpectCount(Zb_CoreRemovalsTaken(&trio.router), 1, "and the router takes the removal at its new address");

    trustTrioJoin(&trio);
    map = Nwk_AddrMapOf(Zb_CoreNwk(&trio.tc));

    for (i = 0; i < NWK_ADDR_MAP_MAX; i++)
    {
        if (map[i].extendedAddress == DEVICE_TRIO_ROUTER_IEEE)
            map[i].inUse = 0;
    }

    Test_ExpectStatus(Zb_CoreRemove(&trio.tc, DEVICE_TRIO_JOINER_IEEE, 5050), ZB_OK,
                      "the map holds no row for the parent");

    for (nowMs = 5100; nowMs <= 6000; nowMs += 50)
        deviceTrioTurn(&trio, nowMs);

    Test_ExpectCount(Zb_CoreRemovalsTaken(&trio.router), 1, "and the removal goes to the address the note holds");
}

static int trustReportedDeparture(Zb_Core *tc, uint64_t ieee);

/* 4.6.3.6.2's second duty: a child that leaves without rejoin is reported to the trust centre as status 0x02, and the
   trust centre forgets the parent it noted. */
void caseChildLeaveIsReported(void)
{
    DeviceTrio trio;
    uint64_t parent = 0;
    uint32_t nowMs;

    trustTrioJoin(&trio);

    Test_ExpectStatus(Zb_CoreLeave(&trio.joiner, 0, 5050), ZB_OK, "the joiner leaves on its own say");

    for (nowMs = 5100; nowMs <= 6000; nowMs += 50)
        deviceTrioTurn(&trio, nowMs);

    Test_ExpectCount(Aps_UpdateDevicesIndicated(&Zb_CoreLayers(&trio.tc)->aps), 2,
                     "the router reported the departure, the trust centre's second indication after the join");
    Test_ExpectCount(Zb_CoreParentOf(&trio.tc, DEVICE_TRIO_JOINER_IEEE, &parent), 0,
                     "and the trust centre forgot the joiner's parent");
    Test_ExpectCount(Zb_CoreLeavesUnreported(&trio.router), 0, "with nothing the router failed to report");
    Test_Expect(trustReportedDeparture(&trio.tc, DEVICE_TRIO_JOINER_IEEE),
                "and the application hears the router's report as one, informative only (10591-10593)");
}

/* Whether the trust centre's departures hold `ieee` as a router reported it. */
static int trustReportedDeparture(Zb_Core *tc, uint64_t ieee)
{
    Zb_CoreDeparture departures[ZB_CORE_DEPARTURE_MAX];
    uint32_t taken = Zb_CorePollDepartures(tc, departures, ZB_CORE_DEPARTURE_MAX);
    uint32_t i;

    for (i = 0; i < taken; i++)
    {
        if (departures[i].ieee == ieee && departures[i].reported && !departures[i].rejoin)
            return 1;
    }

    return 0;
}

/* 11979: the trust centre that is the parent issues no update-device for its own child, forgets the note itself,
   and tells the application of the leave it heard. */
void caseTrustCentresOwnChildLeaves(void)
{
    DeviceTrio trio;
    Aps_UpdateDeviceReq req;
    Nwk_LeaveCommand command;
    Nwk_NeighborTableEntry *child;
    Zb_CoreDeparture departures[ZB_CORE_DEPARTURE_MAX];
    uint64_t parent = 0;
    Nwk_Nwk *nwk;

    deviceTrioAt(&trio);
    nwk = Zb_CoreNwk(&trio.tc);

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.destIeee = DEVICE_TRIO_TC_IEEE;
    req.deviceIeee = DEVICE_TRIO_JOINER_IEEE;
    req.deviceShortAddress = 0x2002;
    req.status = APS_UPDATE_DEVICE_SECURED_REJOIN;
    Test_ExpectStatus(Aps_UpdateDeviceRequest(&Zb_CoreLayers(&trio.tc)->aps, &req, 100), ZB_OK,
                      "a join the trust centre notes as its own");
    Test_ExpectStatus(Zb_CoreStep(&trio.tc, 100), ZB_OK, "taken on its turn");
    Test_ExpectCount(Zb_CoreParentOf(&trio.tc, DEVICE_TRIO_JOINER_IEEE, &parent), 1, "noted");

    Test_BandASeedNeighbor(nwk, 0x2002, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);
    child = Nwk_NeighborOf(nwk->neighbors, 0x2002);
    child->extendedAddress = DEVICE_TRIO_JOINER_IEEE;
    child->ieeeKnown = 1;

    Zb_memset(&command, 0, (uint32_t)sizeof command);
    Nwk_LeaveRx(nwk, 0x2002, DEVICE_TRIO_JOINER_IEEE, &command, 0, 200);
    Test_ExpectStatus(Zb_CoreStep(&trio.tc, 200), ZB_OK, "its child leaves without rejoin");

    Test_ExpectCount(Aps_UpdateDevicesSent(&Zb_CoreLayers(&trio.tc)->aps), 0, "and no update-device is issued");
    Test_ExpectCount(Zb_CoreParentOf(&trio.tc, DEVICE_TRIO_JOINER_IEEE, &parent), 0, "the note is forgotten");
    Test_Expect(Zb_CorePollDepartures(&trio.tc, departures, ZB_CORE_DEPARTURE_MAX) == 1
                && departures[0].ieee == DEVICE_TRIO_JOINER_IEEE && departures[0].networkAddress == 0x2002
                && !departures[0].rejoin && !departures[0].reported,
                "and the application hears the leave itself, once");
}

/* The trust centre's table of parents: a join noted with its parent, a repeat taking its own row, a departure
   forgetting it, and a full table evicting the oldest note and counting it. */
void caseTrustCentreNotesEachParent(void)
{
    DeviceTrio trio;
    Aps_UpdateDeviceReq req;
    uint64_t parent = 0;
    uint32_t i;

    deviceTrioAt(&trio);

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.destIeee = DEVICE_TRIO_TC_IEEE;
    req.status = APS_UPDATE_DEVICE_SECURED_REJOIN;

    for (i = 0; i <= ZB_CORE_JOINER_MAX; i++)
    {
        req.deviceIeee = DEVICE_TRIO_JOINER_IEEE + i;
        req.deviceShortAddress = (uint16_t)(0x2000 + i);
        Test_ExpectStatus(Aps_UpdateDeviceRequest(&Zb_CoreLayers(&trio.tc)->aps, &req, 100 + i), ZB_OK,
                          "a join at the trust centre");
        Test_ExpectStatus(Zb_CoreStep(&trio.tc, 100 + i), ZB_OK, "taken on its turn");
    }

    Test_ExpectCount(Zb_CoreJoinersEvicted(&trio.tc), 1, "one join past the table's size evicts a note");
    Test_ExpectCount(Zb_CoreParentOf(&trio.tc, DEVICE_TRIO_JOINER_IEEE, &parent), 0, "the oldest");
    Test_Expect(Zb_CoreParentOf(&trio.tc, DEVICE_TRIO_JOINER_IEEE + ZB_CORE_JOINER_MAX, &parent) == 1
                    && parent == DEVICE_TRIO_TC_IEEE,
                "and the newest is noted with the trust centre as its parent, the join being its own");

    req.deviceIeee = DEVICE_TRIO_JOINER_IEEE + 1;
    req.status = APS_UPDATE_DEVICE_TC_REJOIN;
    Test_ExpectStatus(Aps_UpdateDeviceRequest(&Zb_CoreLayers(&trio.tc)->aps, &req, 200), ZB_OK, "a noted device rejoins");
    Test_ExpectStatus(Zb_CoreStep(&trio.tc, 200), ZB_OK, "taken on its turn");
    Test_ExpectCount(Zb_CoreJoinersEvicted(&trio.tc), 1, "and keeps its own row");

    req.status = APS_UPDATE_DEVICE_LEFT;
    Test_ExpectStatus(Aps_UpdateDeviceRequest(&Zb_CoreLayers(&trio.tc)->aps, &req, 300), ZB_OK, "then it leaves");
    Test_ExpectStatus(Zb_CoreStep(&trio.tc, 300), ZB_OK, "taken on its turn");
    Test_ExpectCount(Zb_CoreParentOf(&trio.tc, DEVICE_TRIO_JOINER_IEEE + 1, &parent), 0, "and its note is forgotten");

    Test_ExpectStatus(Zb_CoreRemove(&trio.router, DEVICE_TRIO_JOINER_IEEE, 400), ZB_ERR_BAD_STATE,
                      "a device that is not the trust centre removes nobody");
    Test_ExpectStatus(Zb_CoreRemove(&trio.tc, DEVICE_TRIO_TC_IEEE, 400), ZB_ERR_BAD_ARGUMENT,
                      "and the trust centre does not remove itself");

    Test_ExpectStatus(Zb_CoreLeave(&trio.tc, 0, 500), ZB_OK, "once the trust centre has left its network");
    Test_ExpectStatus(Zb_CoreRemove(&trio.tc, DEVICE_TRIO_ROUTER_IEEE, 500), ZB_ERR_BAD_STATE,
                      "its leave request is refused, and no Remove Device is tried in its place");
}

/* A device configured with the global trust centre link key and no network key is a joiner of a secured network: it
   initialises at that network's level, holding the pair and no key yet, and is not enabled until a key arrives. */
void caseJoinerHoldsOnlyTheLinkKey(void)
{
    DeviceTrio trio;

    deviceTrioAt(&trio);

    Test_Expect(Zb_CoreIsRunning(&trio.joiner), "the joiner is built");
    Test_ExpectCount(Security_Level(&Zb_CoreLayers(&trio.joiner)->security), SECURITY_LEVEL_ENC_MIC_32,
                     "at the network's level, a key pair needing one");
    Test_Expect(Security_IsEnabled(&Zb_CoreLayers(&trio.joiner)->security) == 0,
                "and not enabled: it holds no network key to protect a frame with");
    Test_Expect(Zb_CoreLayers(&trio.joiner)->security.trustCenterIeee == 0,
                "and knows no trust centre yet (4.9.2)");
}

/* 4.6.3.6.2's report is a child's departure without rejoin alone: a stranger's leave and a child's leave to rejoin are
   not reported, and a router of an unsecured network has no trust centre to report to. */
void caseOnlyAChildsDepartureIsReported(void)
{
    DeviceTrio trio;
    DeviceRig rig;
    Nwk_LeaveCommand command;
    Nwk_NeighborTableEntry *child;
    Nwk_Nwk *nwk;

    deviceTrioAt(&trio);
    nwk = Zb_CoreNwk(&trio.router);

    Test_BandASeedNeighbor(nwk, 0x2002, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);
    child = Nwk_NeighborOf(nwk->neighbors, 0x2002);
    child->extendedAddress = DEVICE_TRIO_JOINER_IEEE;
    child->ieeeKnown = 1;

    Zb_memset(&command, 0, (uint32_t)sizeof command);

    Nwk_LeaveRx(nwk, 0x3003, DEVICE_TRIO_JOINER_IEEE + 1, &command, 0, 100);
    Test_ExpectStatus(Zb_CoreStep(&trio.router, 100), ZB_OK, "a stranger's departure is read");
    Test_ExpectCount(Aps_UpdateDevicesSent(&Zb_CoreLayers(&trio.router)->aps), 0, "and not reported");

    command.rejoin = 1;
    Nwk_LeaveRx(nwk, 0x2002, DEVICE_TRIO_JOINER_IEEE, &command, 0, 200);
    Test_ExpectStatus(Zb_CoreStep(&trio.router, 200), ZB_OK, "a child's leave to rejoin is read");
    Test_ExpectCount(Aps_UpdateDevicesSent(&Zb_CoreLayers(&trio.router)->aps), 0, "and not reported either");

    child->relationship = NWK_REL_CHILD;
    command.rejoin = 0;
    Nwk_LeaveRx(nwk, 0x2002, DEVICE_TRIO_JOINER_IEEE, &command, 0, 300);
    Test_ExpectStatus(Zb_CoreStep(&trio.router, 300), ZB_OK, "a child's departure is read");
    Test_ExpectCount(Aps_UpdateDevicesSent(&Zb_CoreLayers(&trio.router)->aps), 1, "and reported as one 0x02");

    deviceRigBuildRouter(&rig);
    nwk = Zb_CoreNwk(&rig.dev);
    Test_BandASeedNeighbor(nwk, 0x2002, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);
    Nwk_LeaveRx(nwk, 0x2002, 0, &command, 0, 100);
    Test_ExpectStatus(Zb_CoreStep(&rig.dev, 100), ZB_OK, "a router of an unsecured network hears its child leave");
    Test_ExpectCount(Zb_CoreLeavesUnreported(&rig.dev), 0, "and has nobody to report it to, which is no refusal");
}

/* 4.6.3.6.1's other two arms: the trust centre's own child is sent the leave request with no Remove Device, and a
   router it noted no parent for is sent Remove Device naming itself, once the address map places it (4.4.4.1.2). The
   router leaves, after discarding a Remove Device for a device that is neither it nor its child. */
void caseTrustCentreRemovesItsChildAndARouter(void)
{
    DeviceTrio trio;
    Aps_RemoveDeviceReq req;
    Nwk_NeighborTableEntry *child;
    Nwk_Nwk *nwk;
    uint16_t learned = 0;
    uint32_t nowMs;
    uint32_t i;

    deviceTrioAt(&trio);
    nwk = Zb_CoreNwk(&trio.tc);

    for (nowMs = 0; nowMs < 200; nowMs += 50)
        deviceTrioTurn(&trio, nowMs);

    Test_BandASeedNeighbor(nwk, 0x2002, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);
    child = Nwk_NeighborOf(nwk->neighbors, 0x2002);
    child->extendedAddress = DEVICE_TRIO_JOINER_IEEE;
    child->ieeeKnown = 1;

    Test_ExpectStatus(Zb_CoreRemove(&trio.tc, DEVICE_TRIO_JOINER_IEEE, 200), ZB_OK, "the trust centre removes its child");
    Test_ExpectCount(Nwk_LeaveCommandsSent(nwk), 1, "by the network layer's leave request");
    Test_ExpectCount(Aps_RemoveDevicesSent(&Zb_CoreLayers(&trio.tc)->aps), 0, "and no Remove Device");

    Test_Expect(Nwk_AddressOfIeee(nwk, DEVICE_TRIO_ROUTER_IEEE, &learned) && learned == DEVICE_TRIO_ROUTER_SHORT,
                "the router's announcement taught the trust centre's map its address (2.5.4.5.4.3)");

    for (i = 0; i < NWK_ADDR_MAP_MAX; i++)
    {
        if (Nwk_AddrMapOf(nwk)[i].extendedAddress == DEVICE_TRIO_ROUTER_IEEE)
            Nwk_AddrMapOf(nwk)[i].inUse = 0;
    }

    Test_ExpectStatus(Zb_CoreRemove(&trio.tc, DEVICE_TRIO_ROUTER_IEEE, 250), ZB_ERR_NOT_FOUND,
                      "a router the address map cannot place is not removed");
    Test_Expect(Nwk_AddrMapLearn(Nwk_AddrMapOf(nwk), DEVICE_TRIO_ROUTER_SHORT, DEVICE_TRIO_ROUTER_IEEE, 0x0000, 260)
                == NWK_ADDRMAP_LEARNED, "until the map holds it");

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.parentIeee = DEVICE_TRIO_ROUTER_IEEE;
    req.parentNwk = DEVICE_TRIO_ROUTER_SHORT;
    req.targetIeee = DEVICE_TRIO_JOINER_IEEE + 1;
    Test_ExpectStatus(Aps_RemoveDeviceRequest(&Zb_CoreLayers(&trio.tc)->aps, &req, 270), ZB_OK,
                      "a Remove Device for a device that is not the router's child");

    for (nowMs = 300; nowMs <= 600; nowMs += 50)
        deviceTrioTurn(&trio, nowMs);

    Test_ExpectCount(Zb_CoreRemovalsDiscarded(&trio.router), 1, "is discarded by the router (4.6.3.6.2)");

    Test_ExpectStatus(Zb_CoreRemove(&trio.tc, DEVICE_TRIO_ROUTER_IEEE, 650), ZB_OK, "then the router is removed");
    Test_ExpectCount(Aps_RemoveDevicesSent(&Zb_CoreLayers(&trio.tc)->aps), 2, "by Remove Device naming itself");

    for (nowMs = 700; nowMs <= 1200; nowMs += 50)
        deviceTrioTurn(&trio, nowMs);

    Test_ExpectCount(Zb_CoreRemovalsTaken(&trio.router), 1, "which the router carries out");
    Test_ExpectCount(Nwk_IsPartOfNetwork(Zb_CoreNwk(&trio.router)), 0, "by leaving the network itself");
}

/* 5228-5231 and Table 2-135: the discovery runs :Config_NWK_Scan_Attempts times before a network is chosen, each
   separated by :Config_NWK_Time_btwn_Scans; the trust centre hearing one Beacon Request a scan counts them. */
void caseJoinScansAsOftenAsConfigured(void)
{
    DeviceTrio trio;
    Zb_CoreJoinParameters params;
    Zb_CoreJoinResult result;
    uint32_t nowMs;
    uint32_t answersAtTheGap = 0;
    int ended = 0;

    deviceTrioUnjoinedAt(&trio);

    for (nowMs = 0; nowMs < 200; nowMs += 50)
        deviceTrioTurn(&trio, nowMs);

    Test_ExpectStatus(Zb_CorePermitJoining(&trio.tc, 120, 200), ZB_OK, "the trust centre permits joining");

    Zb_memset(&params, 0, (uint32_t)sizeof params);
    params.scanChannels = (uint32_t)1 << DEVICE_CHANNEL;
    params.scanDuration = 2;
    params.scanAttempts = 256;
    Test_ExpectStatus(Zb_CoreJoin(&trio.router, &params, 200), ZB_ERR_BAD_ARGUMENT, "valid values end at 255");

    params.scanAttempts = 2;
    params.scanGapMs = 1000;
    Test_ExpectStatus(Zb_CoreJoin(&trio.router, &params, 200), ZB_OK, "two scans a second apart");

    for (nowMs = 250; nowMs <= 15000 && !ended; nowMs += 50)
    {
        deviceTrioTurn(&trio, nowMs);
        ended = Zb_CorePollJoinResult(&trio.router, &result) == 1;

        if (nowMs == 1000)
            answersAtTheGap = Zb_CoreMac(&trio.tc)->beacon.beaconRequestsHeard;
    }

    Test_ExpectCount(answersAtTheGap, 1, "the first scan is over and the gap has not ended");
    Test_ExpectCount(Zb_CoreMac(&trio.tc)->beacon.beaconRequestsHeard, 2, "and the second came after it");
    Test_Expect(ended && result.status == 0x00 && result.parentsHeard == 1, "then it joined the one parent it heard");

    deviceTrioUnjoinedAt(&trio);

    for (nowMs = 0; nowMs < 200; nowMs += 50)
        deviceTrioTurn(&trio, nowMs);

    Test_ExpectStatus(Zb_CorePermitJoining(&trio.tc, 120, 200), ZB_OK, "and again");

    params.scanAttempts = 0;
    params.scanGapMs = 0;
    Test_ExpectStatus(Zb_CoreJoin(&trio.router, &params, 200), ZB_OK, "at the defaults");
    ended = 0;

    for (nowMs = 250; nowMs <= 15000 && !ended; nowMs += 50)
    {
        deviceTrioTurn(&trio, nowMs);
        ended = Zb_CorePollJoinResult(&trio.router, &result) == 1;
    }

    Test_ExpectCount(Zb_CoreMac(&trio.tc)->beacon.beaconRequestsHeard, 5, "the attribute's default is five scans");
    Test_Expect(ended && result.status == 0x00, "and the join ends the same");
}

/* The whole child procedure through the façade's door alone: the router, configured onto no network, discovers the
   trust centre on channel 26 and joins it, is sent the network key and beacons for the network; the end device, which
   hears the router only, discovers it and joins through it, its key tunnelled to the router (4.6.3.7.1). */
void caseJoinThroughTheFacade(void)
{
    DeviceTrio trio;
    Zb_CoreJoinParameters params;
    Zb_CoreJoinResult result;
    uint32_t nowMs;
    int routerJoined = 0;
    int joinerJoined = 0;

    deviceTrioUnjoinedAt(&trio);

    for (nowMs = 0; nowMs < 200; nowMs += 50)
        deviceTrioTurn(&trio, nowMs);

    Test_ExpectStatus(Zb_CorePermitJoining(&trio.tc, 120, 200), ZB_OK, "the trust centre permits joining");
    Test_ExpectCount(Zb_CoreMac(&trio.router)->beacon.beaconAnswers, 0, "a router on no network answers no Beacon Request");

    Zb_memset(&params, 0, (uint32_t)sizeof params);
    params.scanChannels = (uint32_t)1 << DEVICE_CHANNEL;
    params.scanDuration = 2;
    Test_ExpectStatus(Zb_CoreJoin(&trio.tc, &params, 200), ZB_ERR_BAD_STATE, "a coordinator joins nothing");
    params.scanChannels = 0;
    Test_ExpectStatus(Zb_CoreJoin(&trio.router, &params, 200), ZB_ERR_BAD_ARGUMENT, "a join names its channels");
    params.scanChannels = (uint32_t)1 << DEVICE_CHANNEL;
    Test_ExpectStatus(Zb_CoreJoin(&trio.router, &params, 200), ZB_OK, "the router asks to join any network");
    Test_ExpectStatus(Zb_CoreJoin(&trio.router, &params, 200), ZB_ERR_BUSY, "once");

    for (nowMs = 250; nowMs <= 15000 && !routerJoined; nowMs += 50)
    {
        deviceTrioTurn(&trio, nowMs);
        routerJoined = Zb_CorePollJoinResult(&trio.router, &result) == 1;
    }

    Test_Expect(routerJoined, "the router's join ends");
    Test_Expect(result.status == 0x00 && result.extendedPanId == DEVICE_EXTENDED_PAN_ID
                && result.channel == DEVICE_CHANNEL && result.parentsHeard == 1,
                "joined, to the one network it heard, on channel 26");
    Test_Expect(Security_IsEnabled(&Zb_CoreLayers(&trio.router)->security), "holding the network key");
    Test_ExpectCount(Zb_CoreMac(&trio.router)->beacon.beaconAnswers, 1, "and beacons for the network it joined");

    for (; nowMs <= 16000; nowMs += 50)
        deviceTrioTurn(&trio, nowMs);

    Test_ExpectStatus(Zb_CorePermitJoining(&trio.router, 120, nowMs), ZB_OK, "the router permits joining");
    Test_ExpectStatus(Zb_CoreJoin(&trio.joiner, &params, nowMs), ZB_OK, "the end device asks to join");

    for (nowMs += 50; nowMs <= 40000 && !joinerJoined; nowMs += 50)
    {
        deviceTrioTurn(&trio, nowMs);
        joinerJoined = Zb_CorePollJoinResult(&trio.joiner, &result) == 1;
    }

    Test_Expect(joinerJoined, "the end device's join ends");
    Test_Expect(result.status == 0x00 && result.extendedPanId == DEVICE_EXTENDED_PAN_ID,
                "joined, through the router it alone could hear");
    Test_ExpectCount(Zb_CoreNetworkKeysTunnelled(&trio.tc), 1, "the trust centre tunnelled its key to the router");
    Test_Expect(Security_IsEnabled(&Zb_CoreLayers(&trio.joiner)->security), "and the end device holds it");
}
