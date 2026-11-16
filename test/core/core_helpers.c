/* The `device` suite's shared machinery: the bodies. See `core_helpers.h` for what this file is. */

#include "core_helpers.h"

#include "nwk.h"
#include "test_harness.h"
#include "zb_utils.h"

static void deviceIdentity(Zb_LayersConfig *stack, uint16_t shortAddress, uint64_t ieee, uint32_t deviceType)
{
    uint32_t i;

    stack->present = RADIO_PIB_CHANNEL | RADIO_PIB_PAGE | RADIO_PIB_PAN_ID | RADIO_PIB_SHORT_ADDRESS
                     | RADIO_PIB_EXTENDED_ADDRESS | RADIO_PIB_RX_ON_WHEN_IDLE;

    stack->channel = DEVICE_CHANNEL;
    stack->page = 0;
    stack->panId = DEVICE_PAN_ID;
    stack->shortAddress = shortAddress;
    stack->rxOnWhenIdle = 1;
    stack->deviceType = deviceType;
    stack->seqStart = 0x11;
    stack->jitterSeed = 0;
    stack->joinSeed = 0;
    stack->dsnStart = 0x21;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        stack->extendedAddress[i] = (uint8_t)(ieee >> (8 * i));

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        stack->extendedPanId[i] = (uint8_t)(DEVICE_EXTENDED_PAN_ID >> (8 * i));
}

static void deviceRigAt(DeviceRig *rig, uint32_t deviceType, uint8_t logicalType, int trustCentre)
{
    Test_BandAConfig peerCfg;
    uint8_t octets[RADIO_ADDR_LEN];
    Radio_Caps caps;
    uint32_t i;

    Zb_memset(rig, 0, (uint32_t)sizeof *rig);

    Test_BandACapsAcks(&caps);
    LoopbackRadio_Init(&rig->model, &caps);

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        octets[i] = (uint8_t)(DEVICE_OWN_IEEE >> (8 * i));

    LoopbackRadio_SetFactoryAddress(&rig->model, octets);

    deviceIdentity(&rig->cfg.layers, DEVICE_OWN_SHORT, DEVICE_OWN_IEEE, deviceType);

    Zdo_NodeDescriptorDefaults(&rig->cfg.node, logicalType, DEVICE_MANUFACTURER_CODE);
    Zdo_PowerDescriptorDefaults(&rig->cfg.power);

    if (trustCentre)
    {
        Test_ParseHex(DEVICE_NETWORK_KEY_HEX, rig->cfg.networkKey, SECURITY_KEY_OCTETS);
        Test_ParseHex(DEVICE_LINK_KEY_HEX, rig->cfg.trustCentreLinkKey, SECURITY_KEY_OCTETS);
        rig->cfg.transportNetworkKey = 1;
    }

    Test_ExpectStatus(Zb_CoreInit(&rig->dev, LoopbackRadio_Seam(&rig->model), &rig->cfg), ZB_OK,
                      "the device is built the way an application builds one");

    Test_BandADefaults(&peerCfg);
    peerCfg.ownAddress = DEVICE_PEER_SHORT;
    peerCfg.ownExtended = DEVICE_PEER_IEEE;
    peerCfg.panId = DEVICE_PAN_ID;

    Test_ExpectStatus(Test_BandABuild(&rig->peer, &peerCfg), ZB_OK, "and a peer stands beside it with a network layer");

    Test_BandASeedNeighbor(&rig->peer.nwk, DEVICE_OWN_SHORT, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    Test_BandASeedNeighbor(Zb_CoreNwk(&rig->dev), DEVICE_PEER_SHORT, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
}

void deviceRigBuild(DeviceRig *rig)
{
    deviceRigAt(rig, NWK_DEVICE_COORDINATOR, ZDO_LOGICAL_COORDINATOR, 0);
}

void deviceRigBuildRouter(DeviceRig *rig)
{
    deviceRigAt(rig, NWK_DEVICE_ROUTER, ZDO_LOGICAL_ROUTER, 0);
}

void deviceRigBuildEndDevice(DeviceRig *rig)
{
    Nwk_Nwk *nwk;
    uint32_t i;

    deviceRigAt(rig, NWK_DEVICE_END_DEVICE, ZDO_LOGICAL_END_DEVICE, 0);

    nwk = Zb_CoreNwk(&rig->dev);
    Nwk_NeighborOf(nwk->neighbors, DEVICE_PEER_SHORT)->relationship = NWK_REL_PARENT;
    nwk->joinParentShort = DEVICE_PEER_SHORT;
    nwk->joinParentShortKnown = 1;
    nwk->joinParentExtended = DEVICE_PEER_IEEE;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        nwk->joinExtendedPanId[i] = (uint8_t)(DEVICE_EXTENDED_PAN_ID >> (8 * i));
}

void deviceRigBuildTrustCentre(DeviceRig *rig)
{
    deviceRigAt(rig, NWK_DEVICE_COORDINATOR, ZDO_LOGICAL_COORDINATOR, 1);
}

void deviceDescriptor(Af_SimpleDescriptor *descriptor, uint8_t endpoint)
{
    Zb_memset(descriptor, 0, (uint32_t)sizeof *descriptor);

    descriptor->endpoint = endpoint;
    descriptor->profileId = DEVICE_PROFILE_ID;
    descriptor->deviceId = (uint16_t)(0x0100 + endpoint);
    descriptor->deviceVersion = 1;
    descriptor->inputClusterCount = 1;
    descriptor->inputClusters[0] = DEVICE_INPUT_CLUSTER;
    descriptor->outputClusterCount = 1;
    descriptor->outputClusters[0] = DEVICE_OUTPUT_CLUSTER;
}

void devicePeerSends(DeviceRig *rig, const Aps_Frame *frame, const uint8_t *asdu, uint32_t asduLength,
                     uint32_t nowMs)
{
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Loopback_FrameSpec spec;
    Nwk_DataRequestParameters req;
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t apduLen = 0;
    uint32_t payloadOffset = 0;
    uint32_t got;
    uint32_t newest = 0;
    uint32_t i;

    Test_ExpectStatus(ApsFrame_Compose(frame, asdu, asduLength, apdu, (uint32_t)sizeof apdu, &apduLen,
                                       &payloadOffset), ZB_OK,
                      "the APDU is written by `aps_frame`, the only module in this stack that writes one");

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.dstAddr = DEVICE_OWN_SHORT;
    req.nsdu = apdu;
    req.nsduLength = apduLen;

    Test_ExpectStatus(Nwk_DataRequest(&rig->peer.nwk, &req, nowMs), ZB_OK,
                      "and the peer's own network layer carries it, which is how an APS frame reaches the air");

    got = LoopbackRadio_Sent(&rig->peer.model, sent, LOOPBACK_TX_MAX);
    Test_Expect(got > 0, "the peer put a frame on its own side of the seam");

    if (got == 0)
        return;

    for (i = 1; i < got; i++)
    {
        if (sent[i].handle > sent[newest].handle)
            newest = i;
    }

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = sent[newest].len;
    spec.bytes = sent[newest].bytes;
    spec.rssiDbm = -60;
    spec.lqi = 200;
    spec.stampTicks = 2;

    Test_ExpectStatus(LoopbackRadio_Inject(&rig->model, &spec, 1), ZB_OK,
                      "and the frame arrives in front of the device's MAC");
}

void deviceStep(DeviceRig *rig, uint32_t nowMs)
{
    Test_ExpectStatus(Zb_CoreStep(&rig->dev, nowMs), ZB_OK, "the device takes its turn");
}

int deviceAnswer(DeviceRig *rig, uint16_t cluster, uint16_t *clusterOut, uint8_t *asdu, uint32_t asduCap,
                 uint32_t *asduLength, uint8_t *dstEndpoint)
{
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Mac_Frame mac;
    Nwk_Frame npdu;
    Aps_Frame aps;
    const uint8_t *body;
    const uint8_t *payload;
    uint32_t bodyLen = 0;
    uint32_t npduOffset = 0;
    uint32_t npduLen = 0;
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
    uint32_t got;
    uint32_t i;

    got = LoopbackRadio_Sent(&rig->model, sent, LOOPBACK_TX_MAX);

    for (i = got; i > 0; i--)
    {
        if (MacFrame_Parse(sent[i - 1].bytes, sent[i - 1].len, 1, &mac, &body, &bodyLen, 0) != ZB_OK)
            continue;

        if (NwkFrame_Parse(body, bodyLen, &npdu, &npduOffset, &npduLen) != ZB_OK)
            continue;

        if (ApsFrame_Parse(body + npduOffset, npduLen, &aps, &payloadOffset, &payloadLen) != ZB_OK)
            continue;

        if (aps.frameType != APS_FRAME_TYPE_DATA)
            continue;

        if (cluster != 0 && aps.clusterId != cluster)
            continue;

        payload = body + npduOffset + payloadOffset;

        if (clusterOut != 0)
            *clusterOut = aps.clusterId;

        if (dstEndpoint != 0)
            *dstEndpoint = aps.dstEndpoint;

        if (asduLength != 0)
            *asduLength = payloadLen > asduCap ? asduCap : payloadLen;

        if (asdu != 0 && payloadLen != 0)
            Zb_memcpy(asdu, payload, payloadLen > asduCap ? asduCap : payloadLen);

        return 1;
    }

    return 0;
}

void devicePairAt(DevicePair *pair)
{
    uint8_t octets[RADIO_ADDR_LEN];
    Radio_Caps caps;
    uint32_t i;

    Zb_memset(pair, 0, (uint32_t)sizeof *pair);

    Test_BandACapsAcks(&caps);
    LoopbackRadio_Init(&pair->askerModel, &caps);
    LoopbackRadio_Init(&pair->serverModel, &caps);

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        octets[i] = (uint8_t)(DEVICE_ASKER_IEEE >> (8 * i));

    LoopbackRadio_SetFactoryAddress(&pair->askerModel, octets);

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        octets[i] = (uint8_t)(DEVICE_SERVER_IEEE >> (8 * i));

    LoopbackRadio_SetFactoryAddress(&pair->serverModel, octets);

    deviceIdentity(&pair->askerCfg.layers, DEVICE_ASKER_SHORT, DEVICE_ASKER_IEEE, NWK_DEVICE_END_DEVICE);
    Zdo_NodeDescriptorDefaults(&pair->askerCfg.node, ZDO_LOGICAL_END_DEVICE, DEVICE_MANUFACTURER_CODE);
    Zdo_PowerDescriptorDefaults(&pair->askerCfg.power);

    deviceIdentity(&pair->serverCfg.layers, DEVICE_SERVER_SHORT, DEVICE_SERVER_IEEE, NWK_DEVICE_COORDINATOR);
    Zdo_NodeDescriptorDefaults(&pair->serverCfg.node, ZDO_LOGICAL_COORDINATOR, DEVICE_MANUFACTURER_CODE);
    Zdo_PowerDescriptorDefaults(&pair->serverCfg.power);

    Test_ExpectStatus(Zb_CoreInit(&pair->asker, LoopbackRadio_Seam(&pair->askerModel), &pair->askerCfg), ZB_OK,
                      "the asking device is built");
    Test_ExpectStatus(Zb_CoreInit(&pair->server, LoopbackRadio_Seam(&pair->serverModel), &pair->serverCfg), ZB_OK,
                      "and the serving one");

    Test_BandASeedNeighbor(Zb_CoreNwk(&pair->asker), DEVICE_SERVER_SHORT, NWK_DEVICE_COORDINATOR, 1, NWK_REL_PARENT);
    Test_BandASeedNeighbor(Zb_CoreNwk(&pair->server), DEVICE_ASKER_SHORT, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);
}

static void deviceCrossModel(Loopback_Radio *from, Loopback_Radio *to, Radio_Handle *seen)
{
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Loopback_FrameSpec spec[LOOPBACK_TX_MAX];
    Radio_Handle newest = *seen;
    uint32_t got;
    uint32_t count = 0;
    uint32_t i;

    got = LoopbackRadio_Sent(from, sent, LOOPBACK_TX_MAX);

    for (i = 0; i < got; i++)
    {
        if (sent[i].handle == RADIO_HANDLE_NONE || sent[i].handle <= *seen)
            continue;

        Zb_memset(&spec[count], 0, (uint32_t)sizeof spec[count]);

        spec[count].len = sent[i].len;
        spec[count].bytes = sent[i].bytes;
        spec[count].rssiDbm = -60;
        spec[count].lqi = 200;
        spec[count].stampTicks = 2;

        count++;

        if (sent[i].handle > newest)
            newest = sent[i].handle;
    }

    if (count == 0)
        return;

    Test_ExpectStatus(LoopbackRadio_Inject(to, spec, count), ZB_OK,
                      "what one device put on the air arrived in front of the other");

    *seen = newest;
}

/* The air is carried before either device is stepped: a step polls its own completions, and a collected frame is no
   longer in the model's ledger for a crossing to read. */
void devicePairTurn(DevicePair *pair, uint32_t nowMs)
{
    deviceCrossModel(&pair->askerModel, &pair->serverModel, &pair->askerSeen);
    deviceCrossModel(&pair->serverModel, &pair->askerModel, &pair->serverSeen);

    Test_ExpectStatus(Zb_CoreStep(&pair->asker, nowMs), ZB_OK, "the asking device takes its turn");
    Test_ExpectStatus(Zb_CoreStep(&pair->server, nowMs), ZB_OK, "and the serving one");
}

static void deviceTrioModel(Loopback_Radio *model, uint64_t ieee)
{
    uint8_t octets[RADIO_ADDR_LEN];
    Radio_Caps caps;
    uint32_t i;

    Test_BandACapsAcks(&caps);
    LoopbackRadio_Init(model, &caps);

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        octets[i] = (uint8_t)(ieee >> (8 * i));

    LoopbackRadio_SetFactoryAddress(model, octets);
}

void deviceTrioAt(DeviceTrio *trio)
{
    Zb_memset(trio, 0, (uint32_t)sizeof *trio);

    deviceTrioModel(&trio->tcModel, DEVICE_TRIO_TC_IEEE);
    deviceTrioModel(&trio->routerModel, DEVICE_TRIO_ROUTER_IEEE);
    deviceTrioModel(&trio->joinerModel, DEVICE_TRIO_JOINER_IEEE);

    deviceIdentity(&trio->tcCfg.layers, 0x0000, DEVICE_TRIO_TC_IEEE, NWK_DEVICE_COORDINATOR);
    Zdo_NodeDescriptorDefaults(&trio->tcCfg.node, ZDO_LOGICAL_COORDINATOR, DEVICE_MANUFACTURER_CODE);
    Zdo_PowerDescriptorDefaults(&trio->tcCfg.power);
    Test_ParseHex(DEVICE_NETWORK_KEY_HEX, trio->tcCfg.networkKey, SECURITY_KEY_OCTETS);
    Test_ParseHex(DEVICE_LINK_KEY_HEX, trio->tcCfg.trustCentreLinkKey, SECURITY_KEY_OCTETS);
    trio->tcCfg.transportNetworkKey = 1;

    deviceIdentity(&trio->routerCfg.layers, DEVICE_TRIO_ROUTER_SHORT, DEVICE_TRIO_ROUTER_IEEE, NWK_DEVICE_ROUTER);
    Zdo_NodeDescriptorDefaults(&trio->routerCfg.node, ZDO_LOGICAL_ROUTER, DEVICE_MANUFACTURER_CODE);
    Zdo_PowerDescriptorDefaults(&trio->routerCfg.power);
    Test_ParseHex(DEVICE_NETWORK_KEY_HEX, trio->routerCfg.networkKey, SECURITY_KEY_OCTETS);
    Test_ParseHex(DEVICE_LINK_KEY_HEX, trio->routerCfg.trustCentreLinkKey, SECURITY_KEY_OCTETS);

    deviceIdentity(&trio->joinerCfg.layers, 0xffff, DEVICE_TRIO_JOINER_IEEE, NWK_DEVICE_END_DEVICE);
    Zdo_NodeDescriptorDefaults(&trio->joinerCfg.node, ZDO_LOGICAL_END_DEVICE, DEVICE_MANUFACTURER_CODE);
    Zdo_PowerDescriptorDefaults(&trio->joinerCfg.power);
    Test_ParseHex(DEVICE_LINK_KEY_HEX, trio->joinerCfg.trustCentreLinkKey, SECURITY_KEY_OCTETS);
    trio->joinerCfg.layers.joinSeed = 0x12345678;

    Test_ExpectStatus(Zb_CoreInit(&trio->tc, LoopbackRadio_Seam(&trio->tcModel), &trio->tcCfg), ZB_OK,
                      "the trust centre is built");
    Test_ExpectStatus(Zb_CoreInit(&trio->router, LoopbackRadio_Seam(&trio->routerModel), &trio->routerCfg), ZB_OK,
                      "and the router");
    Test_ExpectStatus(Zb_CoreInit(&trio->joiner, LoopbackRadio_Seam(&trio->joinerModel), &trio->joinerCfg), ZB_OK,
                      "and the joiner, unassociated");

    /* The router is already on the network: it has learned its trust centre (4.9.2), and the two are neighbours. */
    Zb_CoreLayers(&trio->router)->security.trustCenterIeee = DEVICE_TRIO_TC_IEEE;
    Nwk_SetTrustCenter(Zb_CoreNwk(&trio->router), DEVICE_TRIO_TC_IEEE);
    Test_BandASeedNeighbor(Zb_CoreNwk(&trio->router), 0x0000, NWK_DEVICE_COORDINATOR, 1, NWK_REL_PARENT);
    Test_BandASeedNeighbor(Zb_CoreNwk(&trio->tc), DEVICE_TRIO_ROUTER_SHORT, NWK_DEVICE_ROUTER, 1, NWK_REL_CHILD);
}

void deviceTrioUnjoinedAt(DeviceTrio *trio)
{
    Zb_memset(trio, 0, (uint32_t)sizeof *trio);

    deviceTrioModel(&trio->tcModel, DEVICE_TRIO_TC_IEEE);
    deviceTrioModel(&trio->routerModel, DEVICE_TRIO_ROUTER_IEEE);
    deviceTrioModel(&trio->joinerModel, DEVICE_TRIO_JOINER_IEEE);

    deviceIdentity(&trio->tcCfg.layers, 0x0000, DEVICE_TRIO_TC_IEEE, NWK_DEVICE_COORDINATOR);
    Zdo_NodeDescriptorDefaults(&trio->tcCfg.node, ZDO_LOGICAL_COORDINATOR, DEVICE_MANUFACTURER_CODE);
    Zdo_PowerDescriptorDefaults(&trio->tcCfg.power);
    Test_ParseHex(DEVICE_NETWORK_KEY_HEX, trio->tcCfg.networkKey, SECURITY_KEY_OCTETS);
    Test_ParseHex(DEVICE_LINK_KEY_HEX, trio->tcCfg.trustCentreLinkKey, SECURITY_KEY_OCTETS);
    trio->tcCfg.transportNetworkKey = 1;

    deviceIdentity(&trio->routerCfg.layers, 0xffff, DEVICE_TRIO_ROUTER_IEEE, NWK_DEVICE_ROUTER);
    Zdo_NodeDescriptorDefaults(&trio->routerCfg.node, ZDO_LOGICAL_ROUTER, DEVICE_MANUFACTURER_CODE);
    Zdo_PowerDescriptorDefaults(&trio->routerCfg.power);
    Test_ParseHex(DEVICE_LINK_KEY_HEX, trio->routerCfg.trustCentreLinkKey, SECURITY_KEY_OCTETS);
    trio->routerCfg.layers.joinSeed = 0x0badcafe;

    deviceIdentity(&trio->joinerCfg.layers, 0xffff, DEVICE_TRIO_JOINER_IEEE, NWK_DEVICE_END_DEVICE);
    Zdo_NodeDescriptorDefaults(&trio->joinerCfg.node, ZDO_LOGICAL_END_DEVICE, DEVICE_MANUFACTURER_CODE);
    Zdo_PowerDescriptorDefaults(&trio->joinerCfg.power);
    Test_ParseHex(DEVICE_LINK_KEY_HEX, trio->joinerCfg.trustCentreLinkKey, SECURITY_KEY_OCTETS);
    trio->joinerCfg.layers.joinSeed = 0x12345678;

    Test_ExpectStatus(Zb_CoreInit(&trio->tc, LoopbackRadio_Seam(&trio->tcModel), &trio->tcCfg), ZB_OK,
                      "the trust centre is built");
    Test_ExpectStatus(Zb_CoreInit(&trio->router, LoopbackRadio_Seam(&trio->routerModel), &trio->routerCfg), ZB_OK,
                      "and the router, on no network yet");
    Test_ExpectStatus(Zb_CoreInit(&trio->joiner, LoopbackRadio_Seam(&trio->joinerModel), &trio->joinerCfg), ZB_OK,
                      "and the joiner, unassociated");
}

/* The air as the range has it: the trust centre and the router hear each other, the router and the joiner hear each
   other, and the joiner never hears the trust centre. */
void deviceTrioTurn(DeviceTrio *trio, uint32_t nowMs)
{
    deviceCrossModel(&trio->tcModel, &trio->routerModel, &trio->tcToRouter);
    deviceCrossModel(&trio->routerModel, &trio->tcModel, &trio->routerToTc);
    deviceCrossModel(&trio->routerModel, &trio->joinerModel, &trio->routerToJoiner);
    deviceCrossModel(&trio->joinerModel, &trio->routerModel, &trio->joinerToRouter);

    Test_ExpectStatus(Zb_CoreStep(&trio->tc, nowMs), ZB_OK, "the trust centre takes its turn");
    Test_ExpectStatus(Zb_CoreStep(&trio->router, nowMs), ZB_OK, "and the router");
    Test_ExpectStatus(Zb_CoreStep(&trio->joiner, nowMs), ZB_OK, "and the joiner");
}
