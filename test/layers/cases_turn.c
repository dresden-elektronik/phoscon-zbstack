/* The `stack` suite's turn half: what one `Zb_LayersStep` is, what the two drains answer with, a frame carried from
   one façade to another, the join two devices make and the rejoin one of them repeats, the step a façade that was
   never built refuses, the turn a device that came back is asked again for what the façade had applied, and the
   record a turn writes into the pool its config named. See `layers_cases.h` for the list and `layers_helpers.h` for
   the rest. */

#include "layers_cases.h"
#include "layers_helpers.h"

#include "log.h"
#include "mac_frame.h"
#include "nwk_leave.h"
#include "rig_band_a.h"
#include "zb_utils.h"

/* The peer the frames of these four cases travel to and from: a second device on the same PAN and channel, with
   an identity of its own, which is the whole of what a pair of stacks needs to be two devices. */
#define TURN_PEER_SHORT 0x0053
#define TURN_PEER_IEEE 0x1011121314151617
#define TURN_PEER_IEEE_HEX "1716151413121110"

/* The application endpoints, profile and cluster the acknowledgement has to repeat (2.2.5.2.3.1). */
#define TURN_SRC_EP 0x01
#define TURN_DST_EP 0x02
#define TURN_PROFILE_ID 0x0104
#define TURN_CLUSTER_ID 0x0006

#define TURN_PAYLOAD_LEN 6

/* The pair's OutgoingFrameCounter seed: the first frame either device protects with its link key carries it. */
#define TURN_PAIR_SEED 4

/* The first link-key octet; the rest follow it, so the two entries share one key the way a link key is shared. */
#define TURN_LINK_KEY_FIRST_OCTET 0xa0

/* The device that was never a member: an identity of its own on the same PAN and channel, which 3.2.2.13's
   membership test and Table 3-74's search are read against. */
#define TURN_STRANGER_SHORT 0x0061
#define TURN_STRANGER_IEEE 0x2021222324252627

/* The extended PAN identifier of the network the join and the rejoin are for: the octets an application would
   name, in the order the field travels in (Table 3-21's ExtendedPANId, Table 3-74's). */
static const uint8_t s_turnExtendedPan[RADIO_ADDR_LEN] =
{
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
};

/* The device a case starts from, named by the identity the case wants: the identity `stackDevicePlain` builds is
   this suite's own device with its extended address, so a peer is that device's config with two fields replaced.
   A device at level 0x00 is this call and nothing else. */
static void turnDeviceAt(StackDevice *dev, uint16_t shortAddress, uint64_t ieee)
{
    stackDevicePlain(dev);

    dev->cfg.shortAddress = shortAddress;
    stackExtendedOctets(ieee, dev->cfg.extendedAddress);
}

/* The same device with the crossing's material: the one key descriptor a level that protects frames requires,
   this device's own extended address as the nonce's address half (4.4.1.1 step 5c), and the key pairs the
   application seeds for its partners. The façade attaches the module to both layers, which is why one call fills
   the one config both of them read. `authenticated` is the join 3.6.2.2 conditions the unsecured discard on. */
static void turnSecureAt(StackDevice *dev, uint64_t ownIeee, const Security_KeyPairEntry *pairs,
                         uint32_t pairCount, int authenticated, uint32_t level)
{
    stackKeyAt(&dev->key, STACK_KEY_SEQ);

    dev->secCfg.ownIeee = ownIeee;
    dev->secCfg.nwkSecurityLevel = level;
    dev->secCfg.nwkActiveKeySeqNumber = STACK_KEY_SEQ;
    dev->secCfg.authenticated = authenticated;
    dev->secCfg.nwkAllFresh = 1;
    dev->secCfg.keys = &dev->key;
    dev->secCfg.keyCount = 1;
    dev->secCfg.keyPairs = pairs;
    dev->secCfg.keyPairCount = pairCount;

    dev->cfg.nwkSecurityLevel = level;
    dev->cfg.security = &dev->secCfg;
}

/* One entry of `apsDeviceKeyPairSet` as an application seeds it: the partner, the 16-bit alias this stack's
   addressing gives it, the attribute the gate of 4.4.1.1 step 1a-ii requires, the shared link key and both
   counters. */
static Security_KeyPairEntry turnPairAt(uint64_t partner, uint16_t alias, uint32_t outgoing)
{
    Security_KeyPairEntry entry;
    uint32_t index;

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);

    entry.deviceIeee = partner;
    entry.shortAddress = alias;
    entry.shortKnown = 1;
    entry.keyAttributes = SECURITY_KEYPAIR_ATTR_VERIFIED;
    entry.outgoingFrameCounter = outgoing;
    entry.incomingFrameCounter = 0;
    entry.linkKeyType = SECURITY_LINK_KEY_UNIQUE;
    entry.featuresCapabilities = SECURITY_FEATURES_NONE;
    entry.verifiedFrameCounter = 1;

    for (index = 0; index < SECURITY_KEY_OCTETS; index++)
        entry.key[index] = (uint8_t)(TURN_LINK_KEY_FIRST_OCTET + index);

    return entry;
}

/* Table 2-2's parameters, filled the way a caller of this SAP fills them: an application endpoint at each end, a
   profile and a cluster, and the raw `TxOptions` bitmap the table prints. */
static Aps_ApsdeReq turnRequest(uint16_t dst, const uint8_t *asdu, uint32_t asduLength, uint32_t txOptions)
{
    Aps_ApsdeReq req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    req.dstAddrMode = APS_ADDR_MODE_SHORT;
    req.dstAddress = dst;
    req.dstEndpoint = TURN_DST_EP;
    req.profileId = TURN_PROFILE_ID;
    req.clusterId = TURN_CLUSTER_ID;
    req.srcEndpoint = TURN_SRC_EP;
    req.asdu = asdu;
    req.asduLength = asduLength;
    req.txOptions = txOptions;

    return req;
}

/* Every transmit either backend is asked for is acknowledged: a model is not a radio, so what happened to a
   frame sent is whatever the script said (docs/internals/protocol.md §8.3). */
static void turnAnswer(Loopback_Radio *model)
{
    Loopback_Outcome outcomes[LOOPBACK_TX_MAX];
    uint32_t index;

    Zb_memset(outcomes, 0, (uint32_t)sizeof outcomes);

    for (index = 0; index < LOOPBACK_TX_MAX; index++)
    {
        outcomes[index].status = ZB_OK;
        outcomes[index].isAcked = 1;
    }

    LoopbackRadio_ScriptOutcomes(model, outcomes, LOOPBACK_TX_MAX);
}

/* Hand the newest frame one stack put on its side of the seam to the other stack's doorstep, as the frame it is:
   the octets with the trailer band A reads. Neither stack is stepped here, so the newest is the one with the
   largest handle the backend handed out. */
static void turnHandOver(Loopback_Radio *from, Loopback_Radio *to)
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
        if (sent[index].issuedIndex > sent[newest].issuedIndex)
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

/* The one way these cases give a unicast destination a path: a neighbor entry put in on each side, which is what
   3.6.4.3 relays on, with both backends scripted to answer every transmit they are given. */
static void turnWire(StackDevice *dev, uint16_t devShort, StackDevice *peer, uint16_t peerShort)
{
    Test_BandASeedNeighbor(Zb_LayersNwk(&dev->stack), peerShort, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    Test_BandASeedNeighbor(Zb_LayersNwk(&peer->stack), devShort, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    turnAnswer(&dev->model);
    turnAnswer(&peer->model);
}

void caseOneStepOneTurn(void)
{
    StackDevice dev;
    StackDevice peer;
    Aps_Aps *aps;
    Aps_ApsdeReq req;
    Aps_Indication indications[2];
    static const uint8_t asked[TURN_PAYLOAD_LEN] = { 0x74, 0x75, 0x72, 0x6e, 0x21, 0x21 };

    turnDeviceAt(&dev, STACK_SHORT_ADDRESS, STACK_OWN_IEEE);
    turnDeviceAt(&peer, TURN_PEER_SHORT, TURN_PEER_IEEE);

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "case 7: two level-0x00 stacks are built by the façade");
    Test_ExpectStatus(stackInit(&peer), ZB_OK, "one for the device under test and one for the peer it hears from");

    turnWire(&dev, STACK_SHORT_ADDRESS, &peer, TURN_PEER_SHORT);

    aps = Zb_LayersAps(&dev.stack);

    req = turnRequest(STACK_SHORT_ADDRESS, asked, TURN_PAYLOAD_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Aps_DataRequest(Zb_LayersAps(&peer.stack), &req, 90), ZB_OK,
                      "the peer sends one acknowledged APS unicast, so the device under test owes an answer as well as a delivery");
    turnHandOver(&peer.model, &dev.model);

    Test_ExpectStatus(Zb_LayersStep(&dev.stack, 100), ZB_OK,
                      "one Zb_LayersStep is one turn of the three layers: the APS turn runs the NWK turn, which runs the MAC turn, and no layer is advanced twice");
    Test_ExpectCount(Aps_IndicationQueue(aps), 1,
                     "the frame the backend was holding is delivered upward exactly once");
    Test_ExpectCount(Aps_AcksGenerated(aps), 1, "and the acknowledgement the same frame makes this device owe is composed once");
    Test_ExpectCount(Aps_ConfirmationsIgnored(aps), 0,
                     "with the answer to that acknowledgement's own transmission still owed by the next turn, which is the one fact that separates a turn of three layers from a turn that advanced one of them twice");

    Test_ExpectStatus(Zb_LayersStep(&dev.stack, 200), ZB_OK, "a second turn finds nothing left to deliver");

    Test_ExpectCount(Aps_IndicationQueue(aps), 1,
                     "the ring the first turn filled still holds one delivery and not two: a frame a layer consumed is not delivered again by a second turn");
    Test_ExpectCount(Aps_AcksGenerated(aps), 1,
                     "and one frame does not make two acknowledgements (2.2.8.4.3)");
    Test_ExpectCount(Aps_ConfirmationsIgnored(aps), 1,
                     "while the answer to the acknowledgement's own transmission is the one fact this second turn adds");

    Zb_memset(indications, 0, (uint32_t)sizeof indications);
    Test_ExpectCount(Zb_LayersPollIndications(&dev.stack, indications, 2), 1,
                     "the delivery the single turn made is there to be taken, and it is the peer's frame");
    Test_ExpectOctets("carrying the six octets the peer's application asked to have sent",
                      indications[0].asdu, indications[0].asduLength, asked, TURN_PAYLOAD_LEN);
    Test_ExpectCount(Zb_LayersPollIndications(&dev.stack, indications, 2), 0,
                     "and nothing behind it: one frame is one delivery");
}

void caseDrainsRoute(void)
{
    StackDevice dev;
    StackDevice peer;
    Aps_ApsdeReq req;
    Aps_Confirm confirms[2];
    Aps_Indication indications[2];
    static const uint8_t asked[TURN_PAYLOAD_LEN] = { 0x72, 0x6f, 0x75, 0x74, 0x65, 0x64 };

    turnDeviceAt(&dev, STACK_SHORT_ADDRESS, STACK_OWN_IEEE);
    turnDeviceAt(&peer, TURN_PEER_SHORT, TURN_PEER_IEEE);

    Test_ExpectStatus(stackInit(&dev), ZB_OK, "case 8: a pair of stacks is built by the façade");
    Test_ExpectStatus(stackInit(&peer), ZB_OK, "and the peer is the one the case reads the delivery off");

    turnWire(&dev, STACK_SHORT_ADDRESS, &peer, TURN_PEER_SHORT);

    req = turnRequest(TURN_PEER_SHORT, asked, TURN_PAYLOAD_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Aps_DataRequest(Zb_LayersAps(&dev.stack), &req, 90), ZB_OK,
                      "the device under test sends one acknowledged unicast to its peer");
    turnHandOver(&dev.model, &peer.model);

    Test_ExpectStatus(Zb_LayersStep(&peer.stack, 100), ZB_OK, "the peer's turn delivers it and composes the answer it owes");
    turnHandOver(&peer.model, &dev.model);
    Test_ExpectStatus(Zb_LayersStep(&dev.stack, 110), ZB_OK, "and this device's turn collects the acknowledgement");

    Zb_memset(confirms, 0, (uint32_t)sizeof confirms);
    Test_ExpectCount(Zb_LayersPollConfirms(&dev.stack, confirms, 2), 1,
                     "Zb_LayersPollConfirms answers with the one confirmation the finished transaction produced, without the caller naming a layer");
    Test_ExpectStatus(confirms[0].status, ZB_OK, "SUCCESS in the seam's vocabulary");
    Test_ExpectCount(confirms[0].apsStatus, APS_STATUS_SUCCESS, "and Table 2-29's SUCCESS in the APS one");
    Test_ExpectCount(confirms[0].dstAddress, TURN_PEER_SHORT, "for the transaction that was aimed at the peer");
    Test_ExpectCount(confirms[0].attempts, 1, "after one transmission");

    Zb_memset(indications, 0, (uint32_t)sizeof indications);
    Test_ExpectCount(Zb_LayersPollIndications(&peer.stack, indications, 2), 1,
                     "Zb_LayersPollIndications answers with what the peer delivered");
    Test_ExpectCount(indications[0].status, APS_STATUS_SUCCESS, "SUCCESS at the peer");
    Test_ExpectCount(indications[0].srcAddress, STACK_SHORT_ADDRESS, "from this device's own address, as the layer below carried it");
    Test_ExpectOctets("and the six octets the request named", indications[0].asdu, indications[0].asduLength,
                      asked, TURN_PAYLOAD_LEN);

    Test_ExpectCount(Zb_LayersPollConfirms(0, confirms, 2), 0,
                     "a null stack answers no confirmations rather than reaching into nothing");
    Test_ExpectCount(Zb_LayersPollConfirms(&dev.stack, 0, 2), 0, "and neither does a null output buffer");
    Test_ExpectCount(Zb_LayersPollConfirms(&dev.stack, confirms, 0), 0, "and a maximum of zero is not a drain");
    Test_ExpectCount(Zb_LayersPollIndications(0, indications, 2), 0, "the indication drain refuses the same three");
    Test_ExpectCount(Zb_LayersPollIndications(&peer.stack, 0, 2), 0, "a null stack, a null output");
    Test_ExpectCount(Zb_LayersPollIndications(&peer.stack, indications, 0), 0, "and a maximum of zero");
}

void caseEndToEndPair(void)
{
    StackDevice dev;
    StackDevice peer;
    Security_KeyPairEntry devPair;
    Security_KeyPairEntry peerPair;
    Aps_ApsdeReq req;
    Aps_Confirm confirms[2];
    Aps_Indication indications[2];
    static const uint8_t pairAsdu[TURN_PAYLOAD_LEN] = { 0x70, 0x61, 0x69, 0x72, 0x65, 0x64 };

    turnDeviceAt(&dev, STACK_SHORT_ADDRESS, STACK_OWN_IEEE);
    turnDeviceAt(&peer, TURN_PEER_SHORT, TURN_PEER_IEEE);

    devPair = turnPairAt(TURN_PEER_IEEE, TURN_PEER_SHORT, TURN_PAIR_SEED);
    peerPair = turnPairAt(STACK_OWN_IEEE, STACK_SHORT_ADDRESS, TURN_PAIR_SEED);

    turnSecureAt(&dev, STACK_OWN_IEEE, &devPair, 1, 0, SECURITY_LEVEL_ENC_MIC_32);
    turnSecureAt(&peer, TURN_PEER_IEEE, &peerPair, 1, 0, SECURITY_LEVEL_ENC_MIC_32);

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "case 9: two stacks, each built by Zb_LayersInit with its own identity and its own key material, neither of them joined");
    Test_ExpectStatus(stackInit(&peer), ZB_OK, "and each holding the one key pair that names the other");

    Test_Expect(Zb_LayersAps(&dev.stack)->security == &dev.stack.security
                && Zb_LayersNwk(&dev.stack)->security == &dev.stack.security,
                "the façade attaches the one Security it built to both layers that cross into it (2.2.5.1.1.4)");

    turnWire(&dev, STACK_SHORT_ADDRESS, &peer, TURN_PEER_SHORT);

    req = turnRequest(TURN_PEER_SHORT, pairAsdu, TURN_PAYLOAD_LEN,
                      APS_TX_OPTION_SECURITY | APS_TX_OPTION_ACK);
    Test_ExpectStatus(Aps_DataRequest(Zb_LayersAps(&dev.stack), &req, 90), ZB_OK,
                      "A sends one APS-secured acknowledged unicast to B's address: 0x01 selects the link key, 0x04 the acknowledgement ask (Table 2-2)");
    turnHandOver(&dev.model, &peer.model);

    Test_ExpectStatus(Zb_LayersStep(&peer.stack, 100), ZB_OK, "B's turn takes the frame");

    Test_ExpectCount(Nwk_DroppedUnsecured(Zb_LayersNwk(&peer.stack)), 0,
                     "and 3.6.2.2's discard has nothing to catch: the carrier is protected by the network that holds the key (4.2.2), not by an option the application set");

    Zb_memset(indications, 0, (uint32_t)sizeof indications);
    Test_ExpectCount(Zb_LayersPollIndications(&peer.stack, indications, 2), 1, "B delivers one indication");
    Test_ExpectCount(indications[0].status, APS_STATUS_SUCCESS,
                     "SUCCESS: the NWK frame authenticated and the APSDU inside it authenticated with the pair that names A (4.4.1.2)");
    Test_ExpectOctets("carrying the six octets A's application asked to have sent",
                      indications[0].asdu, indications[0].asduLength, pairAsdu, TURN_PAYLOAD_LEN);
    Test_ExpectCount(Aps_AcksGenerated(Zb_LayersAps(&peer.stack)), 1,
                     "B composes the one acknowledgement the frame asked for (2.2.8.4.3.2)");

    turnHandOver(&peer.model, &dev.model);
    Test_ExpectStatus(Zb_LayersStep(&dev.stack, 110), ZB_OK, "A's turn collects the answer");

    Zb_memset(confirms, 0, (uint32_t)sizeof confirms);
    Test_ExpectCount(Zb_LayersPollConfirms(&dev.stack, confirms, 2), 1,
                     "one confirmation, the answer to the transaction 2.2.8.4.4 matched by its four parts");
    Test_ExpectStatus(confirms[0].status, ZB_OK, "ZB_OK");
    Test_ExpectCount(Aps_UnmatchedAcks(Zb_LayersAps(&dev.stack)), 0,
                     "and nothing arrived that matched no transaction (2.2.8.4.4)");
}

/* Table 3-21's request as these two cases fill it: the network both joins are for, the one capability octet the
   child is a device with (an end device whose receiver rests, asking for an address), no scan because the channel
   is the radio's own, and no security at level 0x00. `rejoinNetwork` is the row that decides which half of
   3.6.1.6.1 the request asks for: 0 the association, 0x02 the NWK rejoin. */
static Nwk_JoinRequestParameters joinRequest(uint32_t rejoinNetwork)
{
    Nwk_JoinRequestParameters req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    Zb_memcpy(req.extendedPanId, s_turnExtendedPan, RADIO_ADDR_LEN);
    req.rejoinNetwork = rejoinNetwork;
    req.scanChannels = 0;
    req.scanDuration = 0;
    req.capability.deviceType = 0;
    req.capability.powerSource = 0;
    req.capability.rxOnWhenIdle = 0;
    req.capability.associationType = 0;
    req.capability.suspendableCsmaCa = 0;
    req.capability.securityCapability = 0;
    req.capability.allocateAddress = 1;
    req.securityEnable = 0;

    return req;
}

/* Table 3-74's entry for that network, as the discovery of the parent's beacon would have written it: the one
   parent that permits joining, at the coordinator's address. */
static void joinParentRow(Nwk_JoinParent *row)
{
    Zb_memset(row, 0, (uint32_t)sizeof *row);

    Zb_memcpy(row->extendedPanId, s_turnExtendedPan, RADIO_ADDR_LEN);
    row->panId = STACK_PAN_ID;
    row->shortAddress = 0x0000;
    row->shortKnown = 1;
    row->extendedAddress = STACK_OWN_IEEE;
    row->channel = STACK_CHANNEL;
    row->page = 0;
    row->associationPermit = 1;
    row->deviceType = NWK_DEVICE_COORDINATOR;
    row->rxOnWhenIdle = 1;
}

/* 3.6.1.6.1's join, the one both network cases begin from: the coordinator 3.6.1.6.1.3 makes a parent and the end
   device 3.6.1.6.1.1 brings as a child, the discovery row the parent's beacon would have written, the request
   itself and the turns 10.21.2's exchange takes -- child 0 (the acknowledgment), parent 100 (the decision, queued
   as an indirect transaction), child 123 (the Data Request, a guard after the acknowledgment and inside the one
   window), parent 150 (the transaction extracted onto the air), child 200 (the answer read, and the join), every
   one of them inside the 492 ms that window runs. The pair comes back joined, with both rings exactly as the join
   left them: the parent's one indication and the child's one confirm are the caller's to take or assert. */
static void joinPair(StackDevice *parent, StackDevice *child)
{
    Nwk_BeaconInfo info;
    Nwk_JoinParent row;
    Nwk_JoinRequestParameters jr;
    Mac_Counters counters;

    turnDeviceAt(parent, 0x0000, STACK_OWN_IEEE);
    turnDeviceAt(child, 0xffff, STACK_OTHER_IEEE);

    /* The parent is its own network's trust centre, the AIB's apsTrustCenterAddress: an unsecured rejoin is
       refused only where that address is all ones (3.6.1.6.1.3). */
    parent->cfg.trustCenterIeee = STACK_OWN_IEEE;

    /* The parent is its own network's trust centre, the AIB's apsTrustCenterAddress: an unsecured rejoin is
       refused only where that address is all ones (3.6.1.6.1.3). */
    parent->cfg.trustCenterIeee = STACK_OWN_IEEE;

    /* The child is the device 3.6.1.6.1.1 has joining: an end device whose receiver rests, holding no address yet
       (0xffff is Table 8-36's unassociated macShortAddress) and no key at either layer. */
    child->cfg.deviceType = NWK_DEVICE_END_DEVICE;
    child->cfg.rxOnWhenIdle = 0;
    child->cfg.panId = STACK_PAN_ID;
    child->cfg.shortAddress = 0xffff;
    child->cfg.nwkSecurityLevel = 0;
    child->cfg.security = 0;
    child->cfg.joinSeed = 0x12345678;

    Test_ExpectStatus(stackInit(parent), ZB_OK,
                      "a coordinator at level 0x00 on this PAN is the parent: 10.21.5.1's exchange is one no key protects");
    Test_ExpectStatus(stackInit(child), ZB_OK, "and an end device at the same level is the child that joins it");

    /* The join's four frames are a request, its acknowledgment, a poll and an answer: every one of them is a
       transmit the model must answer, an unacknowledged request being a failure at its own gate (10.21.2). */
    turnAnswer(&parent->model);
    turnAnswer(&child->model);

    Zb_memset(&info, 0, (uint32_t)sizeof info);

    info.stackProfile = NWK_BEACON_STACK_PROFILE;
    info.protocolVersion = NWK_BEACON_PROTOCOL_VERSION;
    info.routerCapacity = 1;
    info.deviceDepth = 0;
    info.endDeviceCapacity = 1;
    info.extendedPanId = 0x08090a0b0c0d0e0f;
    info.txOffset = NWK_BEACON_TX_OFFSET_NONE;
    info.updateId = 0;

    Test_ExpectStatus(Nwk_SetBeaconInfo(Zb_LayersNwk(&parent->stack), &info, 1), ZB_OK,
                      "3.6.8.2's beacon payload, with Table 3-83's permit set: the parent states that it takes a child");

    joinParentRow(&row);

    Test_ExpectStatus(Nwk_JoinParentAdd(Zb_LayersNwk(&child->stack), &row), ZB_OK,
                      "Table 3-74's entry, as the discovery of that beacon would have written it: the one parent that permits joining");
    Test_ExpectCount(Nwk_JoinParentCount(Zb_LayersNwk(&child->stack)), 1,
                     "one network, so 3.2.2.13's search has the one row to find it by");

    jr = joinRequest(0);

    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&child->stack), &jr, 0), ZB_OK,
                      "3.2.2.13's request: an end device asking the PAN for an address, which 3.6.1.6.1.1 turns into 10.21.2's exchange");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&child->stack)), NWK_JOIN_ASSOCIATING,
                     "and the child is associating: the request is on the air and its answer is not here yet");

    Test_ExpectStatus(Zb_LayersStep(&child->stack, 0), ZB_OK,
                      "the child's first turn collects the Association Request's acknowledgment");
    Test_ExpectCount(Mac_AssocStateOf(Zb_LayersMac(&child->stack)), MAC_ASSOC_WAITING,
                     "which is 10.21.2's gate and not its outcome: the acknowledgment says the request was heard, not what the parent decided");

    turnHandOver(&child->model, &parent->model);

    Test_ExpectStatus(Zb_LayersStep(&parent->stack, 100), ZB_OK,
                      "the parent's turn takes the request 10.21.5.1 indicated and makes 3.6.1.6.1.3's answer");
    Test_ExpectCount(Nwk_JoinAddressesAssigned(Zb_LayersNwk(&parent->stack)), 1,
                     "one address was drawn for the one child, out of 3.6.1.8's range and no entry's");
    counters = Mac_CountersOf(Zb_LayersMac(&parent->stack));
    Test_ExpectCount(counters.transactionQueue, 1,
                     "and 10.21.5.2's answer waits on the transaction queue, which is 10.22.2's indirect form");
    Test_ExpectCount(Nwk_JoinIndicationQueue(Zb_LayersNwk(&parent->stack)), 0,
                     "and no indication yet: 3.6.1.6.1.3 tells the next higher layer only once the answer is delivered");

    Test_ExpectStatus(Zb_LayersStep(&child->stack, MAC_RESPONSE_WAIT_MS), ZB_OK,
                      "a turn one macResponseWaitTime after the acknowledgment is where 10.21.2 has the child attempt the extraction");
    Test_ExpectCount(Mac_AssocStateOf(Zb_LayersMac(&child->stack)), MAC_ASSOC_POLLING,
                     "so 10.22.3's Data Request has gone out and the child is polling for the decision the parent holds");

    turnHandOver(&child->model, &parent->model);

    Test_ExpectStatus(Zb_LayersStep(&parent->stack, MAC_RESPONSE_WAIT_MS + 50), ZB_OK,
                      "the parent's turn reads the poll and extracts the queued answer onto the air");

    turnHandOver(&parent->model, &child->model);

    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&child->stack)), NWK_JOIN_ASSOCIATING,
                     "while the child is still associating: the answer is in front of its MAC and no turn has read it");
    Test_ExpectStatus(Zb_LayersStep(&child->stack, MAC_RESPONSE_WAIT_MS + 100), ZB_OK,
                      "the child's turn reads 10.21.5.2's answer inside the window the attempt opened, and the exchange 10.21.2 describes is over");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&child->stack)), NWK_JOIN_JOINED,
                     "and a successful association is a join: 3.6.1.6.1.1 is the half of it that needed a parent");

    Test_ExpectStatus(Zb_LayersStep(&parent->stack, MAC_RESPONSE_WAIT_MS + 150), ZB_OK,
                      "the parent's turn reads the answer's acknowledgement as 10.21.5.2's MLME-COMM-STATUS");
    Test_ExpectCount(Nwk_JoinResponsesDelivered(Zb_LayersNwk(&parent->stack)), 1,
                     "a delivered answer, so 3.6.1.6.1.3's last sentence holds: the join is indicated now");
    Test_ExpectCount(Nwk_JoinIndicationQueue(Zb_LayersNwk(&parent->stack)), 1,
                     "with 3.2.2.14's indication pushed for the application the parent's network belongs to");
}

/* The two halves of 3.6.1.6.1.1 end to end, one exchange carrying no payload of the application's: the child asks
   10.21.2's association of the parent, the parent draws 3.6.1.8's address and queues 10.21.5.2's answer, the child's
   10.22.3 Data Request extracts it, and both devices come away holding what the exchange made them: the child its
   address and its parent, the parent a child. */
void caseJoinNetwork(void)
{
    StackDevice parent;
    StackDevice child;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    Nwk_JoinIndicationParameters ji;
    Nwk_NeighborTableEntry *entry;
    const Radio_Pib *pib;

    joinPair(&parent, &child);

    Zb_memset(&jc, 0, (uint32_t)sizeof jc);
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&child.stack), &jc), 1,
                     "3.2.2.15's confirm is there to be taken, once the MAC has handed its own over");
    Test_ExpectCount(jc.status, 0x00, "SUCCESS, the octet Table 10-102 prints and the MAC reported unchanged");
    Test_Expect(jc.networkAddress >= 0x0001 && jc.networkAddress <= 0xfff7,
                "with an address 3.6.1.8 draws: 0x0000 is the coordinator's own and 0xfff8-0xffff are Table 10-101's reserved forms");
    Test_ExpectOctets("and the extended PAN identifier of the network joined, as Table 3-23's row carries it",
                      jc.extendedPanId, RADIO_ADDR_LEN, s_turnExtendedPan, RADIO_ADDR_LEN);
    Test_ExpectCount(jc.channel, STACK_CHANNEL, "on the channel the parent's row named, the scan having had no list to choose from");
    Test_Expect(jc.parentShort == 0x0000 && jc.parentShortKnown == 1,
                "naming the parent's short address, which the row carried and the request therefore addressed");
    Test_Expect(jc.parentExtended == STACK_OWN_IEEE,
                "and the parent's own extended address, which 10.21.5.2 makes the answer's source and not a field of it");

    Zb_memset(&ji, 0, (uint32_t)sizeof ji);
    Test_ExpectCount(Nwk_PollJoinIndications(Zb_LayersNwk(&parent.stack), &ji, 1), 1,
                     "3.2.2.14's indication is there at the parent, and one child made one of them");
    Test_ExpectCount(ji.networkAddress, jc.networkAddress, "for the address the child's own confirm names");
    Test_Expect(ji.extendedAddress == STACK_OTHER_IEEE,
                "and the extended address 10.21.5.1 fixed the request's source to, read straight off the frame");
    Test_ExpectCount(ji.joinerMethod, 0,
                     "joiner method 0: the association, the mechanism Table 3-22 names for the exchange this case runs");
    Test_Expect(ji.capability.deviceType == 0 && ji.capability.allocateAddress == 1,
                "with Figure 10-157's octet as the child wrote it, an end device asking for an address rather than a router bringing its own");

    pib = Mac_Pib(Zb_LayersMac(&child.stack));
    Test_Expect((pib->present & RADIO_PIB_SHORT_ADDRESS) != 0 && pib->shortAddress == jc.networkAddress,
                "10.21.2 stores the answer's Short Address field in macShortAddress, and the child's PIB now carries it");
    Test_ExpectCount(pib->panId, STACK_PAN_ID, "on the PAN the association joined");

    entry = Nwk_NeighborOf(Zb_LayersNwk(&parent.stack)->neighbors, jc.networkAddress);
    Test_Expect(entry != 0, "the parent's neighbor table holds the child, keyed by the address 3.6.1.8 gave it");

    if (entry != 0)
    {
        Test_Expect(entry->extendedAddress == STACK_OTHER_IEEE && entry->ieeeKnown == 1,
                    "with the extended address the request carried, which is what makes the entry one a frame can be matched on");
        Test_ExpectCount(entry->relationship, NWK_REL_UNAUTHENTICATED_CHILD,
                         "0x05, Table 3-75's relationship for a child no key has authenticated (3.6.2.1)");
        Test_ExpectCount(entry->deviceType, NWK_DEVICE_END_DEVICE,
                         "an end device, which is what Figure 10-157's device type bit said");
        Test_ExpectCount(entry->rxOnWhenIdle, 0, "and one whose receiver rests, as the same octet said");
    }

    entry = Nwk_NeighborOf(Zb_LayersNwk(&child.stack)->neighbors, 0x0000);
    Test_Expect(entry != 0, "while the child's table holds its parent, keyed by the short address the row named");

    if (entry != 0)
    {
        Test_ExpectCount(entry->relationship, NWK_REL_PARENT, "0x00, Table 3-75's parent and the relationship a join writes");
        Test_Expect(entry->extendedAddress == STACK_OWN_IEEE,
                    "carrying the parent's extended address, which is the one field of the parent a beaconless join has");
    }

    Zb_memset(&jc, 0, (uint32_t)sizeof jc);
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&child.stack), &jc), 0,
                     "and the confirm was handed over once: one join is one NLME-JOIN.confirm");

    /* 3.6.1.6.1.1's INV_REQUESTTYPE: a member is not a device that joins. The refusal is the confirm of the request
       that made it, and the membership the join made stands where it was. */
    jr = joinRequest(0);

    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&child.stack), &jr, 800), ZB_ERR_BAD_STATE,
                      "a second NLME-JOIN.request from a device that is already a member is refused");

    Zb_memset(&jc, 0, (uint32_t)sizeof jc);
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&child.stack), &jc), 1,
                     "the refusal is a confirm of its own, and it is there to be taken");
    Test_ExpectCount(jc.status, NWK_STATUS_INV_REQUESTTYPE,
                     "0xc2, Table 3-84's INV_REQUESTTYPE, carried by the confirm of the request it refused");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&child.stack)), NWK_JOIN_JOINED,
                     "and the device is still a member: a request this layer would not execute changed nothing");
}

/* 3.4.14's commissioning join end to end, the attach mechanism 3.6.1.6.1.1 prefers: the child claims an address on the
   parent's PAN and channel, asks the parent, and takes 3.4.15's answer as its join; the parent indicates method 3. */
void caseCommissioningJoinNetwork(void)
{
    StackDevice parent;
    StackDevice child;
    Nwk_BeaconInfo info;
    Nwk_JoinParent row;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    Nwk_JoinIndicationParameters ji;
    Nwk_DataRequestParameters dr;
    Nwk_NeighborTableEntry *entry;
    const Radio_Pib *pib;
    uint16_t claimed;
    static const uint8_t nsdu[2] = { 0x01, 0x02 };

    turnDeviceAt(&parent, 0x0000, STACK_OWN_IEEE);
    turnDeviceAt(&child, 0xffff, STACK_OTHER_IEEE);
    parent.cfg.trustCenterIeee = STACK_OWN_IEEE;

    child.cfg.deviceType = NWK_DEVICE_END_DEVICE;
    child.cfg.rxOnWhenIdle = 1;
    child.cfg.panId = 0xffff;
    child.cfg.shortAddress = 0xffff;
    child.cfg.nwkSecurityLevel = 0;
    child.cfg.security = 0;
    child.cfg.joinSeed = 0x12345678;

    Test_ExpectStatus(stackInit(&parent), ZB_OK, "a coordinator is the parent");
    Test_ExpectStatus(stackInit(&child), ZB_OK, "and an end device on no PAN is the child");
    Zb_LayersNwk(&child.stack)->cfg.attachMechanism = NWK_ATTACH_COMMISSIONING;

    turnAnswer(&parent.model);
    turnAnswer(&child.model);

    Zb_memset(&info, 0, (uint32_t)sizeof info);
    info.stackProfile = NWK_BEACON_STACK_PROFILE;
    info.protocolVersion = NWK_BEACON_PROTOCOL_VERSION;
    info.routerCapacity = 1;
    info.endDeviceCapacity = 1;
    info.extendedPanId = 0x08090a0b0c0d0e0f;
    info.txOffset = NWK_BEACON_TX_OFFSET_NONE;

    Test_ExpectStatus(Nwk_SetBeaconInfo(Zb_LayersNwk(&parent.stack), &info, 1), ZB_OK, "the parent permits joining");

    joinParentRow(&row);
    Test_ExpectStatus(Nwk_JoinParentAdd(Zb_LayersNwk(&child.stack), &row), ZB_OK, "the child's discovery entry");

    jr = joinRequest(0);
    jr.capability.rxOnWhenIdle = 1;

    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&child.stack), &jr, 0), ZB_OK,
                      "3.2.2.13's request goes out as a Network Commissioning Request");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&child.stack)), NWK_JOIN_COMMISSIONING, "and the child waits for its answer");

    pib = Mac_Pib(Zb_LayersMac(&child.stack));
    claimed = pib->shortAddress;
    Test_Expect(pib->panId == STACK_PAN_ID && pib->channel == STACK_CHANNEL && claimed >= 0x0001 && claimed <= 0xfff7,
                "the PIB holds the parent's PAN and channel and the address the request claims (3.4.14.1)");
    Test_ExpectCount(Nwk_IsPartOfNetwork(Zb_LayersNwk(&child.stack)), 0, "which does not make the child a member yet");

    Zb_memset(&dr, 0, (uint32_t)sizeof dr);
    dr.dstAddr = 0x0000;
    dr.nsdu = nsdu;
    dr.nsduLength = (uint32_t)sizeof nsdu;
    Test_ExpectStatus(Nwk_DataRequest(Zb_LayersNwk(&child.stack), &dr, 1), ZB_ERR_NOT_READY,
                      "and the data door stays shut until the answer comes");
    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&child.stack), &jr, 1), ZB_ERR_BUSY,
                      "while a second join is refused as busy, not as a member's");

    Test_ExpectStatus(Zb_LayersStep(&child.stack, 0), ZB_OK, "the child collects the request's acknowledgment");
    turnHandOver(&child.model, &parent.model);

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, 50), ZB_OK, "the parent takes the request and answers it");
    Zb_memset(&ji, 0, (uint32_t)sizeof ji);
    Test_ExpectCount(Nwk_PollJoinIndications(Zb_LayersNwk(&parent.stack), &ji, 1), 1, "and indicates the join");
    Test_Expect(ji.networkAddress == claimed && ji.extendedAddress == STACK_OTHER_IEEE && ji.joinerMethod == 3,
                "for the address the child claimed, with Table 3-22's method 3");

    turnHandOver(&parent.model, &child.model);

    Test_ExpectStatus(Zb_LayersStep(&child.stack, 100), ZB_OK, "the child reads 3.4.15's answer");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&child.stack)), NWK_JOIN_JOINED, "and has joined");

    Zb_memset(&jc, 0, (uint32_t)sizeof jc);
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&child.stack), &jc), 1, "with one NLME-JOIN.confirm");
    Test_Expect(jc.status == 0x00 && jc.networkAddress == claimed && jc.channel == STACK_CHANNEL,
                "SUCCESS, the address the answer named, on the parent's channel");
    Test_Expect(jc.parentShortKnown == 1 && jc.parentShort == 0x0000 && jc.parentExtended == STACK_OWN_IEEE,
                "naming the parent it asked");
    Test_ExpectOctets("and the network it joined", jc.extendedPanId, RADIO_ADDR_LEN, s_turnExtendedPan,
                      RADIO_ADDR_LEN);

    Test_Expect(pib->shortAddress == claimed && pib->panId == STACK_PAN_ID, "the PIB keeps the address and PAN");
    Test_ExpectCount(Nwk_IsPartOfNetwork(Zb_LayersNwk(&child.stack)), 1, "and the child is now a member");

    entry = Nwk_NeighborOf(Zb_LayersNwk(&child.stack)->neighbors, 0x0000);
    Test_Expect(entry != 0 && entry->relationship == NWK_REL_PARENT && entry->extendedAddress == STACK_OWN_IEEE,
                "its neighbor table holds the parent, as an associated child's does");
    Test_ExpectCount(Zb_LayersNwk(&child.stack)->timeoutRequestPending, 1,
                     "and 3.6.10.2's End Device Timeout Request is owed to that parent");

    entry = Nwk_NeighborOf(Zb_LayersNwk(&parent.stack)->neighbors, claimed);
    Test_Expect(entry != 0 && entry->extendedAddress == STACK_OTHER_IEEE && entry->relationship == NWK_REL_UNAUTHENTICATED_CHILD,
                "while the parent holds the child as an unauthenticated child");
}

/* The same join for an end device whose receiver rests: the parent holds 3.4.15's answer (3.4.15.1), the child's
   Data Request inside its countdown extracts it (3.6.1.6.1.2), and the extracted answer is the join. */
void caseCommissioningJoinSleepyChild(void)
{
    StackDevice parent;
    StackDevice child;
    Nwk_BeaconInfo info;
    Nwk_JoinParent row;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    uint32_t polled = MAC_ASSOC_POLL_DELAY_MS + 1;

    turnDeviceAt(&parent, 0x0000, STACK_OWN_IEEE);
    turnDeviceAt(&child, 0xffff, STACK_OTHER_IEEE);
    parent.cfg.trustCenterIeee = STACK_OWN_IEEE;

    child.cfg.deviceType = NWK_DEVICE_END_DEVICE;
    child.cfg.rxOnWhenIdle = 0;
    child.cfg.panId = 0xffff;
    child.cfg.shortAddress = 0xffff;
    child.cfg.nwkSecurityLevel = 0;
    child.cfg.security = 0;
    child.cfg.joinSeed = 0x12345678;

    Test_ExpectStatus(stackInit(&parent), ZB_OK, "a coordinator is the parent");
    Test_ExpectStatus(stackInit(&child), ZB_OK, "and a sleepy end device on no PAN is the child");
    Zb_LayersNwk(&child.stack)->cfg.attachMechanism = NWK_ATTACH_COMMISSIONING;

    turnAnswer(&parent.model);
    turnAnswer(&child.model);

    Zb_memset(&info, 0, (uint32_t)sizeof info);
    info.stackProfile = NWK_BEACON_STACK_PROFILE;
    info.protocolVersion = NWK_BEACON_PROTOCOL_VERSION;
    info.routerCapacity = 1;
    info.endDeviceCapacity = 1;
    info.extendedPanId = 0x08090a0b0c0d0e0f;
    info.txOffset = NWK_BEACON_TX_OFFSET_NONE;

    Test_ExpectStatus(Nwk_SetBeaconInfo(Zb_LayersNwk(&parent.stack), &info, 1), ZB_OK, "the parent permits joining");

    joinParentRow(&row);
    Test_ExpectStatus(Nwk_JoinParentAdd(Zb_LayersNwk(&child.stack), &row), ZB_OK, "the child's discovery entry");

    jr = joinRequest(0);

    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&child.stack), &jr, 0), ZB_OK, "the commissioning request goes out");
    Test_ExpectStatus(Zb_LayersStep(&child.stack, 0), ZB_OK, "and its acknowledgment is collected");
    turnHandOver(&child.model, &parent.model);

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, 50), ZB_OK, "the parent answers");
    Test_ExpectCount(Mac_CountersOf(Zb_LayersMac(&parent.stack)).transactionQueue, 1,
                     "and holds the answer, since the request said the child's receiver rests");

    Test_ExpectStatus(Zb_LayersStep(&child.stack, polled), ZB_OK, "the child's countdown sends its Data Request");
    turnHandOver(&child.model, &parent.model);

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, polled + 10), ZB_OK, "which extracts the held answer");
    turnHandOver(&parent.model, &child.model);

    Test_ExpectStatus(Zb_LayersStep(&child.stack, polled + 20), ZB_OK, "the child reads it");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&child.stack)), NWK_JOIN_JOINED, "and has joined");
    Zb_memset(&jc, 0, (uint32_t)sizeof jc);
    Test_Expect(Nwk_PollJoinConfirm(Zb_LayersNwk(&child.stack), &jc) == 1 && jc.status == 0x00
                && jc.networkAddress == Mac_Pib(Zb_LayersMac(&child.stack))->shortAddress,
                "with SUCCESS for the address the PIB holds");
}

/* 3.6.1.6.1.2 and 3.6.1.6.1.3, the rejoin a device that is still on the network makes: 3.4.6's request to the
   parent its neighbor table already names, 3.6.1.6.1.3's three comparisons answered with the address the first
   join gave it, 3.4.7's answer, and the child joined again under that address while the parent's indication names
   the mechanism that kept it there. Also the three refusals the pair of primitives is held to. */
void caseRejoinNetwork(void)
{
    StackDevice parent;
    StackDevice child;
    StackDevice stranger;
    Nwk_JoinParent row;
    Nwk_JoinRequestParameters rr;
    Nwk_JoinRequestParameters other;
    Nwk_JoinConfirmParameters jc;
    Nwk_JoinConfirmParameters jc2;
    Nwk_JoinIndicationParameters ji;
    Nwk_JoinIndicationParameters ji2;
    Nwk_NeighborTableEntry *entry;
    const Radio_Pib *pib;
    Radio_Pib write;
    uint16_t addr;

    joinPair(&parent, &child);

    /* The join's own two rings are taken first, so everything this case reads afterwards is the rejoin's alone. */
    Zb_memset(&jc, 0, (uint32_t)sizeof jc);
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&child.stack), &jc), 1,
                     "the join's confirm is taken first, so the ring the rejoin answers into starts empty");
    Test_ExpectStatus(jc.status, 0x00, "SUCCESS: the association 3.6.1.6.1.1 made came back with an address");
    Test_Expect(jc.networkAddress >= 0x0001 && jc.networkAddress <= 0xfff7,
                "an address 3.6.1.8 drew, which the rejoin has to be answered with again");
    addr = jc.networkAddress;
    Test_Expect(jc.parentShort == 0x0000 && jc.parentShortKnown == 1,
                "from the coordinator at 0x0000, which is the parent the rejoin is addressed to");

    Zb_memset(&ji, 0, (uint32_t)sizeof ji);
    Test_ExpectCount(Nwk_PollJoinIndications(Zb_LayersNwk(&parent.stack), &ji, 1), 1,
                     "and the parent's one indication for that join, leaving its ring empty as well");
    Test_ExpectCount(ji.networkAddress, addr, "for the address the parent gave the child");

    /* Table 3-21's request as the device that is still on the network makes it: the network it is on, 0x02's NWK
       rejoin, no scan because it stays on its own channel, and no security, level 0x00 holding no key. */
    rr = joinRequest(0x02);

    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&child.stack), &rr, 1000), ZB_OK,
                      "3.2.2.13 with RejoinNetwork 0x02: a device that is on the network asks its parent to keep it there");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&child.stack)), NWK_JOIN_REJOINING,
                     "which is 3.6.1.6.1.2's countdown running: 3.4.6's request is on the air and its answer is not here");

    Test_ExpectStatus(Zb_LayersStep(&child.stack, 1000), ZB_OK,
                      "the child's turn collects the rejoin request's acknowledgment");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&child.stack)), NWK_JOIN_REJOINING,
                     "and an acknowledgment is not an outcome: the countdown still runs");
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&child.stack), &jc2), 0,
                     "so this device owes no confirm yet");

    turnHandOver(&child.model, &parent.model);

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, 1100), ZB_OK,
                      "the parent's turn takes the request and makes 3.6.1.6.1.3's answer");
    Test_ExpectCount(Nwk_JoinIndicationsDropped(Zb_LayersNwk(&parent.stack)), 0,
                     "3.2.2.14's ring had room for the one indication this rejoin makes");
    Test_ExpectCount(Nwk_JoinIndicationQueue(Zb_LayersNwk(&parent.stack)), 1,
                     "and it holds exactly that one: an answer is not an indication and a rejoin is not a join");

    entry = Nwk_NeighborOf(Zb_LayersNwk(&parent.stack)->neighbors, addr);
    Test_Expect(entry != 0, "the parent's neighbor table still holds the child, keyed by the address the request named");

    if (entry != 0)
    {
        Test_ExpectCount(entry->relationship, NWK_REL_UNAUTHENTICATED_CHILD,
                         "0x05: 3.6.1.6.1.3 step 2 writes the values the request carried and leaves a relationship only a secured frame promotes (4.3.1.2 step 8)");
        Test_Expect(entry->extendedAddress == STACK_OTHER_IEEE,
                    "under the extended address the request's own source IEEE field named");
        Test_ExpectCount(entry->networkAddress, addr,
                         "and addressed this device from, which is the address the answer repeats");
    }

    turnHandOver(&parent.model, &child.model);

    Test_ExpectStatus(Zb_LayersStep(&child.stack, 1200), ZB_OK,
                      "the child's turn makes 10.22.3's Data Request, 200 ms after its request and inside the 492 ms countdown");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&child.stack)), NWK_JOIN_REJOINING,
                     "and a poll is not an answer: 3.6.1.6.1.2's countdown still runs");

    turnHandOver(&child.model, &parent.model);

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, 1210), ZB_OK,
                      "the parent's turn reads the poll and extracts the answer the transaction held onto the air");

    turnHandOver(&parent.model, &child.model);

    Test_ExpectStatus(Zb_LayersStep(&child.stack, 1220), ZB_OK,
                      "the child's turn reads 3.4.7's answer, which arrives inside 3.6.1.6.1.2's 492 ms countdown");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&child.stack)), NWK_JOIN_JOINED,
                     "and a rejoin answered with SUCCESS is a device on the network again");

    Zb_memset(&jc2, 0, (uint32_t)sizeof jc2);
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&child.stack), &jc2), 1,
                     "3.2.2.15's confirm is there for the rejoin, once and once only");
    Test_ExpectCount(jc2.status, 0x00, "SUCCESS, the octet the answer's Status field carried");
    Test_ExpectCount(jc2.networkAddress, addr,
                     "with the address the child already had: a rejoin keeps what the join gave it");
    Test_ExpectOctets("and the extended PAN identifier of the network it rejoined, which the request named",
                      jc2.extendedPanId, RADIO_ADDR_LEN, s_turnExtendedPan, RADIO_ADDR_LEN);
    Test_ExpectCount(jc2.channel, STACK_CHANNEL, "on the channel its own radio holds, no scan having been asked for");
    Test_Expect(jc2.parentShort == 0x0000 && jc2.parentShortKnown == 1, "naming the parent it addressed");
    Test_Expect(jc2.parentExtended == STACK_OWN_IEEE,
                "and the parent's own extended address, read off the answer's source IEEE field");

    pib = Mac_Pib(Zb_LayersMac(&child.stack));
    Test_Expect((pib->present & RADIO_PIB_SHORT_ADDRESS) != 0 && pib->shortAddress == addr,
                "3.6.1.6.1.2 writes the answer's address into macShortAddress, and the one it wrote is the one already there");

    Zb_memset(&jc2, 0, (uint32_t)sizeof jc2);
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&child.stack), &jc2), 0,
                     "one rejoin is one confirm: the ring behind it is empty");

    Zb_memset(&ji2, 0, (uint32_t)sizeof ji2);
    Test_ExpectCount(Nwk_PollJoinIndications(Zb_LayersNwk(&parent.stack), &ji2, 1), 1,
                     "3.2.2.14's indication at the parent, for the rejoin it answered");
    Test_ExpectCount(ji2.networkAddress, addr, "naming the address the answer carried");
    Test_Expect(ji2.extendedAddress == STACK_OTHER_IEEE,
                "and the extended address the request's source field named");
    Test_ExpectCount(ji2.joinerMethod, 1,
                     "joiner method 1: Table 3-22's NWK rejoin without security, the mechanism that kept this child, and not the 0 an association makes");
    Test_Expect(ji2.capability.deviceType == 0 && ji2.capability.allocateAddress == 1,
                "with Figure 10-157's octet as the request carried it");

    /* Table 3-21's SecurityEnable: 0x02 with it set is 3.4.6's secured request, which needs a network key a
       level-0x00 stack does not hold. */
    rr.securityEnable = 1;

    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&child.stack), &rr, 1300), ZB_ERR_UNSUPPORTED,
                      "a rejoin the device cannot secure is refused by the layer that would have had to protect it");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&child.stack)), NWK_JOIN_JOINED,
                     "and nothing was started: the child is joined where it was");

    rr.securityEnable = 0;

    /* 3.2.2.13's "a device that is currently joined to a network", as this stack reads it: the address the
       device's own PIB holds. A device holding none is not on the network the request names. */
    turnDeviceAt(&stranger, 0xffff, TURN_STRANGER_IEEE);

    stranger.cfg.deviceType = NWK_DEVICE_END_DEVICE;
    stranger.cfg.panId = STACK_PAN_ID;
    stranger.cfg.rxOnWhenIdle = 0;
    stranger.cfg.nwkSecurityLevel = 0;
    stranger.cfg.security = 0;

    Test_ExpectStatus(stackInit(&stranger), ZB_OK,
                      "a third device at the same level, holding no address of its own");

    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&stranger.stack), &rr, 1400), ZB_ERR_NOT_FOUND,
                      "a rejoin from a device 10.21.2 never gave an address draws one first (3.4.6.2's random self-assignment) and is refused as not found when no parent for the network it names was discovered");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&stranger.stack)), NWK_JOIN_IDLE,
                     "and nothing was started: the state is the one a device that never joined holds");

    /* Table 3-74's table, which 3.4.6.2's second parent comes from: a device holding an address but no parent
       entry is sent to the row for the network the request names, and the search is by that identity. */
    Zb_memset(&write, 0, (uint32_t)sizeof write);

    write.present = RADIO_PIB_SHORT_ADDRESS;
    write.shortAddress = TURN_STRANGER_SHORT;

    Test_ExpectStatus(Mac_SetPib(Zb_LayersMac(&stranger.stack), &write), ZB_OK,
                      "the third device is then given an address a rejoin could be made from");

    joinParentRow(&row);

    Test_ExpectStatus(Nwk_JoinParentAdd(Zb_LayersNwk(&stranger.stack), &row), ZB_OK,
                      "with the one discovered network in its table, so what the next request finds is the search's decision");
    Test_ExpectCount(Nwk_JoinParentCount(Zb_LayersNwk(&stranger.stack)), 1,
                     "one row, the network the join was for");

    other = rr;
    other.extendedPanId[3] = (uint8_t)(other.extendedPanId[3] ^ 0xff);

    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&stranger.stack), &other, 1500), ZB_ERR_NOT_FOUND,
                      "a rejoin for a network no row and no parent entry names is 3.2.2.13's NOT_PERMITTED: there is no parent to address");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&stranger.stack)), NWK_JOIN_IDLE,
                     "and again nothing was started, so no frame of this device is on the air");

    /* 3.6.1.6.1.2's countdown, which is the one outcome no answer can give: the request goes out, no response is
       ever handed to this device, and the wait the clause names runs out with NO_DATA, Table 78's 0xeb. */
    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&child.stack), &rr, 1600), ZB_OK,
                      "a third rejoin from the child, whose request nothing answers this time");
    Test_ExpectStatus(Zb_LayersStep(&child.stack, 1600), ZB_OK,
                      "the child's turn collects the acknowledgment of a request no parent will see");

    Test_ExpectStatus(Zb_LayersStep(&child.stack, 1600 + (2 * MAC_RESPONSE_WAIT_MS) + 1), ZB_OK,
                      "a turn past the attempt's own window is where 10.21.2 stops waiting (decision 142)");

    Zb_memset(&jc2, 0, (uint32_t)sizeof jc2);
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&child.stack), &jc2), 1,
                     "the countdown's outcome is a confirm, which no frame brought");
    Test_ExpectCount(jc2.status, 0xeb,
                     "0x0c as the NWK's countdown writes it today: no response to the request in macResponseWaitTime (0xeb, the MAC's own NO_DATA, once the NWK half lands)");
    Test_ExpectCount(jc2.networkAddress, 0xffff,
                     "and 3.4.7.3.1's broadcast address, a failed rejoin naming no device");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&child.stack)), NWK_JOIN_FAILED,
                     "with the procedure failed rather than joined");

    pib = Mac_Pib(Zb_LayersMac(&child.stack));
    Test_Expect((pib->present & RADIO_PIB_SHORT_ADDRESS) != 0 && pib->shortAddress == addr,
                "and the PIB untouched: 3.6.1.6.1.2 writes no address but the answer's, and no answer came");
}

void caseSecuredAckBothCrossings(void)
{
    StackDevice dev;
    StackDevice peer;
    Security_KeyPairEntry devPair;
    Security_KeyPairEntry peerPair;
    Aps_ApsdeReq req;
    Aps_Confirm confirms[2];
    Aps_Indication indications[2];
    static const uint8_t bothAsdu[TURN_PAYLOAD_LEN] = { 0x62, 0x6f, 0x74, 0x68, 0x21, 0x21 };

    turnDeviceAt(&dev, STACK_SHORT_ADDRESS, STACK_OWN_IEEE);
    turnDeviceAt(&peer, TURN_PEER_SHORT, TURN_PEER_IEEE);

    devPair = turnPairAt(TURN_PEER_IEEE, TURN_PEER_SHORT, TURN_PAIR_SEED);
    peerPair = turnPairAt(STACK_OWN_IEEE, STACK_SHORT_ADDRESS, TURN_PAIR_SEED);

    turnSecureAt(&dev, STACK_OWN_IEEE, &devPair, 1, 1, SECURITY_LEVEL_ENC_MIC_32);
    turnSecureAt(&peer, TURN_PEER_IEEE, &peerPair, 1, 1, SECURITY_LEVEL_ENC_MIC_32);

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "two stacks at the NIB default level 0x05, each joined and authenticated and holding the network key, so 3.6.2.2's unsecured discard runs at both of them");
    Test_ExpectStatus(stackInit(&peer), ZB_OK, "and each holding the one key pair that names the other");

    turnWire(&dev, STACK_SHORT_ADDRESS, &peer, TURN_PEER_SHORT);

    req = turnRequest(TURN_PEER_SHORT, bothAsdu, TURN_PAYLOAD_LEN,
                      APS_TX_OPTION_SECURITY | APS_TX_OPTION_NWK_KEY | APS_TX_OPTION_ACK);
    Test_ExpectStatus(Aps_DataRequest(Zb_LayersAps(&dev.stack), &req, 90), ZB_OK,
                      "A sends one acknowledged unicast with both crossings asked for: 0x01 the link key, 0x02 the network key, 0x04 the acknowledgement (Table 2-2)");
    turnHandOver(&dev.model, &peer.model);

    Test_ExpectStatus(Zb_LayersStep(&peer.stack, 100), ZB_OK, "B's turn takes the frame and owes the answer");

    Zb_memset(indications, 0, (uint32_t)sizeof indications);
    Test_ExpectCount(Zb_LayersPollIndications(&peer.stack, indications, 2), 1, "B delivers exactly one indication");
    Test_ExpectCount(indications[0].status, APS_STATUS_SUCCESS, "SUCCESS: the NWK frame authenticated and so did the APSDU");
    Test_ExpectOctets("carrying the six octets A's application asked to have sent",
                      indications[0].asdu, indications[0].asduLength, bothAsdu, TURN_PAYLOAD_LEN);
    Test_ExpectCount(Nwk_DroppedUnsecured(Zb_LayersNwk(&peer.stack)), 0,
                     "and B discarded nothing at 3.6.2.2's gate, because the frame it was handed was secured at NWK");
    Test_ExpectCount(Aps_AcksGenerated(Zb_LayersAps(&peer.stack)), 1,
                     "B composed the one acknowledgement the frame owes (2.2.8.4.3.2)");

    turnHandOver(&peer.model, &dev.model);
    Test_ExpectStatus(Zb_LayersStep(&dev.stack, 110), ZB_OK, "A's turn collects the answer");

    Test_ExpectCount(Nwk_DroppedUnsecured(Zb_LayersNwk(&dev.stack)), 0,
                     "A's gate discarded nothing either: the NWK frame carrying that acknowledgement is secured, because the crossing is the device's own state and not a value the acknowledgement asked for");

    Zb_memset(confirms, 0, (uint32_t)sizeof confirms);
    Test_ExpectCount(Zb_LayersPollConfirms(&dev.stack, confirms, 2), 1, "so A's transaction is answered: one confirmation");
    Test_ExpectStatus(confirms[0].status, ZB_OK, "ZB_OK");
    Test_ExpectCount(confirms[0].apsStatus, APS_STATUS_SUCCESS, "with Table 2-29's SUCCESS");
    Test_ExpectCount(confirms[0].attempts, 1, "after one transmission, with no retry and no wait run out");
    Test_ExpectCount(Aps_UnmatchedAcks(Zb_LayersAps(&dev.stack)), 0,
                     "and the answer that released it is the one B owed (2.2.8.4.4)");
}

void caseRefusedStep(void)
{
    Zb_Layers unbuilt;

    Zb_memset(&unbuilt, 0, (uint32_t)sizeof unbuilt);

    Test_ExpectStatus(Zb_LayersStep(0, 0), ZB_ERR_BAD_ARGUMENT,
                      "case 10: a null stack is refused before any layer is asked to turn, whatever time it is given");
    Test_ExpectStatus(Zb_LayersStep(&unbuilt, 100), ZB_ERR_BAD_ARGUMENT,
                      "and a stack that was never built (every byte zero, so not running) is refused rather than stepped");
    Test_ExpectStatus(Zb_LayersStep(&unbuilt, 0), ZB_ERR_BAD_ARGUMENT,
                      "at time zero as at any other, because the refusal is about the stack and not about the clock");
}

/* The device coming back holding nothing it was told to hold, which the model does not do on its own and the
   measured RCPs do (docs/internals/protocol.md §7.2 records `PHY_CHAN` as `0` after a plain reset). Clearing the backend's
   PIB is the suite standing in for a re-arming band A may not perform, with a part's own identity scripted back in. */
static void turnDeviceForget(Loopback_Radio *model)
{
    uint8_t octets[RADIO_ADDR_LEN];

    Zb_memcpy(octets, model->pib.hwAddress, RADIO_ADDR_LEN);

    Zb_memset(&model->pib, 0, (uint32_t)sizeof model->pib);

    LoopbackRadio_SetFactoryAddress(model, octets);
}

/* The façade's own identity writes from the far side of a lost event: `Zb_LayersInit` handed the device the config's
   identity in one call, so that mask and nothing else is owed when the device comes back from its defaults, on a
   model scripted with the factory address both measured RCPs report. */
void caseLostReappliesWhatWasApplied(void)
{
    StackDevice dev;
    Radio_Radio *seam;
    Radio_Pib writes[LOOPBACK_PIB_WRITE_MAX];
    Radio_Pib read;
    const Radio_Pib *mirror;
    uint32_t kept;
    Mac_Counters counters;

    stackDevice(&dev);
    stackDeviceFactory(&dev.model, STACK_OWN_IEEE);

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "case 11: a built stack whose device reports the config's own extended address as its factory one");

    seam = LoopbackRadio_Seam(&dev.model);
    mirror = Mac_Pib(&dev.stack.mac);

    Test_Expect((mirror->present & RADIO_PIB_HW_ADDRESS) != 0,
                "so the mirror the façade reads its identity from holds the address the device reported");
    Test_ExpectHex("read as the device's own octets, which is the address ownIeee was bound against",
                   mirror->hwAddress, RADIO_ADDR_LEN, STACK_OWN_IEEE_HEX);

    kept = LoopbackRadio_PibWrites(&dev.model, writes, LOOPBACK_PIB_WRITE_MAX);
    Test_ExpectCount(kept, 1, "the build handed the device one PIB request: the config's identity, in the one call");
    Test_Expect(writes[0].present == dev.cfg.present,
                "naming the mask the config carries, field for field: channel, page, PAN, short address, extended address and receiver duty");

    LoopbackRadio_SetLost(&dev.model, 1);

    Test_ExpectStatus(Zb_LayersStep(&dev.stack, 100), ZB_OK, "the episode reaches band A through the façade's own step");
    Test_Expect(Zb_LayersMac(&dev.stack)->reapplyPending == 1,
                "and what the façade applied is recorded as owed, which is the only debt a re-armed device has");
    Test_ExpectCount(LoopbackRadio_PibWrites(&dev.model, writes, LOOPBACK_PIB_WRITE_MAX), kept,
                "while nothing was handed down into a device the seam says is gone");

    turnDeviceForget(&dev.model);
    LoopbackRadio_SetLost(&dev.model, 0);

    Test_ExpectStatus(Zb_LayersStep(&dev.stack, 200), ZB_OK, "the turn the device answers again, holding its reset defaults");

    kept = LoopbackRadio_PibWrites(&dev.model, writes, LOOPBACK_PIB_WRITE_MAX);
    Test_ExpectCount(kept, 2, "and one request on it: the re-application, kept beside the apply it repeats");
    Test_Expect(writes[1].present == dev.cfg.present,
                "naming exactly the fields the config asked this device to hold, with nothing the device reported added to them and nothing the config named dropped from them");
    Test_Expect((writes[1].present & (RADIO_PIB_HW_ADDRESS | RADIO_PIB_ACK_WAIT_MS | RADIO_PIB_CCA_THRESHOLD_DBM)) == 0,
                "and no read-only field among them: the factory address is the device's own, and neither acknowledgment wait nor CCA threshold is a write this seam carries (docs/internals/protocol.md §7)");
    Test_Expect(writes[1].channel == STACK_CHANNEL && writes[1].panId == STACK_PAN_ID
                && writes[1].shortAddress == STACK_SHORT_ADDRESS && writes[1].rxOnWhenIdle == 1
                && Zb_memcmp(writes[1].extendedAddress, dev.cfg.extendedAddress, RADIO_ADDR_LEN) == 0,
                "with the values the config named, octet for octet and field for field, rather than the defaults the reset left the device holding");

    Test_ExpectStatus(seam->ops->pibGet(seam, &read), ZB_OK, "the device answers a read of what it now holds");
    Test_Expect(read.channel == STACK_CHANNEL && read.panId == STACK_PAN_ID
                && read.shortAddress == STACK_SHORT_ADDRESS && read.rxOnWhenIdle == 1
                && Zb_memcmp(read.extendedAddress, dev.cfg.extendedAddress, RADIO_ADDR_LEN) == 0,
                "and the identity is back on it, which is what every frame the layers compose below is composed from");

    counters = Mac_CountersOf(&dev.stack.mac);
    Test_ExpectCount(counters.pibReapplications, 1, "the debt discharged on the turn it landed, counted once");
    Test_Expect(Zb_LayersMac(&dev.stack)->reapplyPending == 0, "with nothing left owed for a later turn to try");
    Test_ExpectCount(LoopbackRadio_Refusals(&dev.model), 0,
                "and no refusal anywhere in the episode: the re-application the mask band A applied describes is one this backend takes");
    Test_ExpectHex("while the mirror still carries the factory address for reading, unreadable band A would have been without it",
                   mirror->hwAddress, RADIO_ADDR_LEN, STACK_OWN_IEEE_HEX);

    Test_ExpectStatus(Zb_LayersStep(&dev.stack, 300), ZB_OK, "a turn after it, with no episode and nothing to make good");
    Test_ExpectCount(LoopbackRadio_PibWrites(&dev.model, writes, LOOPBACK_PIB_WRITE_MAX), 2,
                     "and no further request: an applied mask lands once and is not re-asked for every step");
    counters = Mac_CountersOf(&dev.stack.mac);
    Test_ExpectCount(counters.pibReapplications, 1, "with the counter where the turn that landed left it");
}

/* The memory sink: the one record this case expects, collected so the case can name its fields (the shape
   `test_log.c` and the security suite's helpers use). */
static void turnSinkWrite(void *context, const Log_Record *record)
{
    Log_Record *out = (Log_Record *)context;

    *out = *record;
}

/* The diagnostics pool the config names: `Zb_LayersInit` adopts it and hands it to the MAC, the way the security
   module is handed its own config's pool, so a frame 6.6.2 discards is a record the caller can read instead of
   a silence. The frame is one this device is addressed by with one footer octet changed: it reaches no ring,
   moves the MAC's footer count once, and writes the one record naming the claim that refused it. */
void caseDiscardIsReported(void)
{
    StackDevice dev;
    Loopback_FrameSpec spec;
    Aps_Indication indications[2];
    Mac_Counters counters;
    Mac_Frame frame;
    Log_Record record;
    Log_Sink sink;
    Log_Log log;
    uint8_t content[2] = { 0xa1, 0x11 };
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t len;

    turnDeviceAt(&dev, STACK_SHORT_ADDRESS, STACK_OWN_IEEE);

    Test_ExpectStatus(Log_Init(&log), ZB_OK, "the application's own diagnostics pool");
    dev.cfg.log = &log;   /* the pool the config names, so the façade is the door and no field is assigned after it */

    Test_ExpectStatus(stackInit(&dev), ZB_OK, "a stack whose config names that pool builds");

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_DATA;
    frame.frameVersion = 0;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.panIdCompression = 1;
    frame.destPan = STACK_PAN_ID;
    frame.srcPan = STACK_PAN_ID;
    frame.destShort = STACK_SHORT_ADDRESS;
    frame.srcShort = TURN_PEER_SHORT;
    frame.seq = 0x31;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, 2, bytes, RADIO_MPDU_MAX, &len), ZB_OK,
                      "one data frame addressed to this device composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK,
                      "closed by the footer those octets compute (7.2.11)");
    bytes[len - 1] = (uint8_t)(bytes[len - 1] ^ 0xff);   /* one footer octet; the MHR still parses */

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = len;
    spec.bytes = bytes;
    spec.rssiDbm = -60;
    spec.lqi = 200;
    spec.stampTicks = 100;
    Test_ExpectStatus(LoopbackRadio_Inject(&dev.model, &spec, 1), ZB_OK, "it arrives with the radio's flag clear");

    Test_ExpectStatus(Zb_LayersStep(&dev.stack, 100), ZB_OK, "and the façade's turn takes it");
    counters = Mac_CountersOf(Zb_LayersMac(&dev.stack));
    Test_Expect(counters.fcsFailures == 1 && counters.indicationQueue == 0,
                "6.6.2 discards it: the MAC's footer count moved once and no indication was queued");
    Test_ExpectCount(Log_Count(&log), 1, "the pool the config named holds the one record the discard wrote");
    Test_ExpectCount(Zb_LayersPollIndications(&dev.stack, indications, 2), 0,
                     "and nothing of it reaches the service above");

    Zb_memset(&record, 0, (uint32_t)sizeof record);
    sink.context = &record;
    sink.write = turnSinkWrite;
    Test_ExpectCount(Log_Drain(&log, &sink), 1, "the record drains to the caller's sink");
    Test_Expect(record.component == LOG_COMP_MAC_RX && record.reason == LOG_REASON_FCS
                && record.argument == MAC_RX_FCS_CHECKSUM,
                "naming the receive classification, the footer as the reason and 7.2.11's recomputation as the claim that refused it");
}

/*
 * 4.6.3.2.1's last sentence: "The transport-key command and Relay Message Downstream sent from the router to the
 * joiner SHALL NOT be secured at the network layer." A device that holds the network key protects every data frame
 * it sends with it, so the transport key is the one frame this crossing must leave alone: the joiner it is sent to
 * does not have that key yet, which is the whole reason the key is being sent.
 */
void caseTransportKeyIsNotNwkSecured(void)
{
    StackDevice dev;
    StackDevice peer;
    Security_KeyPairEntry devPair;
    Aps_TransportKeyReq keyReq;
    Aps_ApsdeReq req;
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Mac_Frame macFrame;
    Nwk_Frame nwkFrame;
    Aps_Frame apsFrame;
    const uint8_t *npdu;
    uint32_t npduLen;
    uint32_t nsduOffset;
    uint32_t nsduLen;
    uint32_t apduOffset;
    uint32_t apduLen;
    uint32_t got;
    static const uint8_t key[16] =
    {
        0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x30, 0x39
    };
    static const uint8_t asdu[TURN_PAYLOAD_LEN] = { 0x6b, 0x65, 0x79, 0x21, 0x21, 0x21 };

    turnDeviceAt(&dev, STACK_SHORT_ADDRESS, STACK_OWN_IEEE);
    turnDeviceAt(&peer, TURN_PEER_SHORT, TURN_PEER_IEEE);

    devPair = turnPairAt(TURN_PEER_IEEE, TURN_PEER_SHORT, TURN_PAIR_SEED);

    turnSecureAt(&dev, STACK_OWN_IEEE, &devPair, 1, 1, SECURITY_LEVEL_ENC_MIC_32);

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "a device at level 0x05 holding the network key and one link key pair, for the child it is about to give that key to");
    Test_ExpectStatus(stackInit(&peer), ZB_OK, "and the child, built for its half of the wiring");

    turnWire(&dev, STACK_SHORT_ADDRESS, &peer, TURN_PEER_SHORT);

    Zb_memset(&keyReq, 0, (uint32_t)sizeof keyReq);
    keyReq.destIeee = TURN_PEER_IEEE;
    keyReq.nwkDst = TURN_PEER_SHORT;
    keyReq.standardKeyType = APS_TK_TYPE_NETWORK_KEY;
    keyReq.keySeqNumber = 0x00;
    keyReq.destinationIeee = TURN_PEER_IEEE;
    Zb_memcpy(keyReq.key, key, (uint32_t)sizeof key);

    Test_ExpectStatus(Aps_TransportKeyRequest(Zb_LayersAps(&dev.stack), &keyReq, 90), ZB_OK,
                      "4.4.2.1.3's request is taken: a network key for the child, protected with the key-transport key of the pair's link key");

    got = LoopbackRadio_Sent(&dev.model, sent, LOOPBACK_TX_MAX);
    Test_ExpectCount(got, 1, "and it left as one frame");

    if (got == 0)
        return;

    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &macFrame, &npdu, &npduLen, 0), ZB_OK,
                      "which parses as an 802.15.4 frame");
    Test_ExpectStatus(NwkFrame_Parse(npdu, npduLen, &nwkFrame, &nsduOffset, &nsduLen), ZB_OK,
                      "carrying a NWK frame");
    Test_ExpectStatus(ApsFrame_Parse(npdu + nsduOffset, nsduLen, &apsFrame, &apduOffset, &apduLen), ZB_OK,
                      "carrying an APS frame");

    Test_Expect(nwkFrame.securityEnabled == 0,
          "and that NWK frame carries no security: 4.6.3.2.1 forbids the network layer to secure a transport key sent to a joiner, and this device holds the network key it would have used");
    Test_Expect(apsFrame.securityEnabled == 1 && apsFrame.frameType == APS_FRAME_TYPE_COMMAND,
          "while the APS half is a secured command, which is 4.4.1.5's encryption of a transport key under the link key");
    Test_Expect(nwkFrame.destAddr == TURN_PEER_SHORT,
          "addressed to the child's own address, which is 4.4.2.1.3's destination for a key that is not a broadcast");

    /* The contrast that makes the assertion above about the clause and not about the device: a data frame from the
       same stack, at the same level, is secured at the network layer. */
    req = turnRequest(TURN_PEER_SHORT, asdu, TURN_PAYLOAD_LEN, APS_TX_OPTION_SECURITY | APS_TX_OPTION_ACK);

    Test_ExpectStatus(Aps_DataRequest(Zb_LayersAps(&dev.stack), &req, 100), ZB_OK,
                      "a secured unicast from the same device is taken");

    got = LoopbackRadio_Sent(&dev.model, sent, LOOPBACK_TX_MAX);
    Test_ExpectCount(got, 2, "and it is the second frame on the air");

    if (got < 2)
        return;

    Test_ExpectStatus(MacFrame_Parse(sent[1].bytes, sent[1].len, 1, &macFrame, &npdu, &npduLen, 0), ZB_OK,
                      "which parses too");
    Test_ExpectStatus(NwkFrame_Parse(npdu, npduLen, &nwkFrame, &nsduOffset, &nsduLen), ZB_OK,
                      "carrying a NWK frame");

    Test_Expect(nwkFrame.securityEnabled == 1,
          "and this one IS secured at the network layer, so the transport key's clear bit is the clause's doing and not the crossing being off");
}

/* A radio that cannot be told to change channel: only the seam's `pibSet` is replaced, so every other call still
   reaches the loopback model behind it. */
static ZbStatus channelRefused(Radio_Radio *radio, const Radio_Pib *pib)
{
    (void)radio;
    (void)pib;

    return ZB_ERR_UNSUPPORTED;
}

static Radio_Ops s_opsNoChannel;

/* 3.2.2.13's RejoinNetwork 0x03: one channel named is set on the radio and confirmed, more than one is
   INV_REQUESTTYPE, and a radio that cannot be set is UNSUPPORTED_ATTRIBUTE. */
void caseJoinChannelChange(void)
{
    StackDevice dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    const Radio_Pib *pib;

    stackDevice(&dev);
    dev.cfg.deviceType = NWK_DEVICE_END_DEVICE;
    dev.cfg.shortAddress = 0xffff;
    dev.cfg.joinSeed = 0x12345678;

    Test_ExpectStatus(stackInit(&dev), ZB_OK, "an end device on channel 26, holding no address yet");

    pib = Mac_Pib(Zb_LayersMac(&dev.stack));
    Test_ExpectCount(pib->channel, STACK_CHANNEL, "on the channel the config names, which the change is about to leave");

    jr = joinRequest(0x03);
    jr.scanChannels = (uint32_t)1 << 15;

    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&dev.stack), &jr, 0), ZB_OK,
                      "3.2.2.13 with RejoinNetwork 0x03 and one channel in ScanChannels: a change of channel, not a join");

    Zb_memset(&jc, 0, (uint32_t)sizeof jc);
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&dev.stack), &jc), 1,
                     "and the confirm is owed at once, because nothing goes on the air for it");
    Test_ExpectCount(jc.status, NWK_STATUS_SUCCESS, "SUCCESS, the channel having been set");
    Test_ExpectCount(jc.channel, 15, "and the confirm names the channel the device is on now");
    Test_ExpectCount(Mac_Pib(Zb_LayersMac(&dev.stack))->channel, 15, "which is the radio's channel too");

    jr.scanChannels = ((uint32_t)1 << 15) | ((uint32_t)1 << 20);

    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&dev.stack), &jr, 10), ZB_ERR_BAD_ARGUMENT,
                      "two channels is a request 3.2.2.13 refuses rather than guesses between");

    Zb_memset(&jc, 0, (uint32_t)sizeof jc);
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&dev.stack), &jc), 1, "with a confirm behind it");
    Test_ExpectCount(jc.status, NWK_STATUS_INV_REQUESTTYPE, "INV_REQUESTTYPE, Table 3-84's word for a request that cannot be executed");
    Test_ExpectCount(Mac_Pib(Zb_LayersMac(&dev.stack))->channel, 15, "and the radio stays where it was");

    s_opsNoChannel = *dev.model.seam.ops;
    s_opsNoChannel.pibSet = channelRefused;
    dev.model.seam.ops = &s_opsNoChannel;
    jr.scanChannels = (uint32_t)1 << 15;

    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&dev.stack), &jr, 20), ZB_ERR_UNSUPPORTED,
                      "a radio with no way to set phyCurrentChannel refuses the request itself");

    Zb_memset(&jc, 0, (uint32_t)sizeof jc);
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&dev.stack), &jc), 1, "and answers");
    Test_ExpectCount(jc.status, NWK_STATUS_UNSUPPORTED_ATTRIBUTE,
                      "UNSUPPORTED_ATTRIBUTE, which 3.2.2.13 prints for exactly this device");
}

/* 3.2.2.13's RejoinNetwork 0x01 is the MAC's orphaning procedure (6168): an orphan scan, which with no coordinator
   to realign the device ends with the scan's NO_BEACON on the confirm (6163-6165). */
void caseJoinOrphaning(void)
{
    StackDevice dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    uint32_t nowMs;

    stackDevice(&dev);
    dev.cfg.deviceType = NWK_DEVICE_END_DEVICE;
    dev.cfg.shortAddress = 0x1fa1;
    dev.cfg.joinSeed = 0x12345678;

    Test_ExpectStatus(stackInit(&dev), ZB_OK, "an end device that holds an address of its own");

    jr = joinRequest(0x01);
    jr.scanChannels = (uint32_t)1 << STACK_CHANNEL;

    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&dev.stack), &jr, 0), ZB_OK,
                      "with no parent in its neighbour table, the orphaning form scans");

    Zb_memset(&jc, 0, (uint32_t)sizeof jc);

    for (nowMs = 0; nowMs < 2 * MAC_RESPONSE_WAIT_MS && Nwk_PollJoinConfirm(Zb_LayersNwk(&dev.stack), &jc) == 0;
         nowMs += 10)
        Test_ExpectStatus(Zb_LayersStep(&dev.stack, nowMs), ZB_OK, "a turn of the scan");

    Test_ExpectCount(jc.status, 0xea, "and nothing realigns it: NO_BEACON");
}

/* The child's 10.22.3 Data Request to its parent at 0x0000, put on its side of the seam by its own MAC. */
static void turnPoll(StackDevice *child, uint32_t nowMs)
{
    Mac_DataRequestParameters poll;
    uint8_t content[1];

    content[0] = MAC_CMD_POLL;

    Zb_memset(&poll, 0, (uint32_t)sizeof poll);

    poll.frameType = MAC_FRAME_TYPE_COMMAND;
    poll.destAddrMode = MAC_ADDR_SHORT;
    poll.srcAddrMode = MAC_ADDR_SHORT;
    poll.destPan = Mac_Pib(Zb_LayersMac(&child->stack))->panId;
    poll.destShort = 0x0000;
    poll.ackRequest = 1;
    poll.payload = content;
    poll.payloadLen = 1;

    Test_ExpectStatus(Mac_DataRequest(Zb_LayersMac(&child->stack), &poll, nowMs, 0), ZB_OK,
                      "the child's MAC puts a Data Request to its parent on the air");
}

/* 3.6.10.2: an end device that has just joined sends its timeout request to the parent on the turn after it has
   taken the confirm, and the parent's answer sets the bitmask the End Device Initiator bit reads. */
void caseTimeoutRequestAfterJoin(void)
{
    StackDevice parent;
    StackDevice child;
    Nwk_JoinConfirmParameters jc;

    joinPair(&parent, &child);

    Zb_memset(&jc, 0, (uint32_t)sizeof jc);
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&child.stack), &jc), 1, "the join's own confirm is taken first");
    Test_ExpectCount(jc.status, NWK_STATUS_SUCCESS, "SUCCESS");

    Test_ExpectCount(Nwk_TimeoutRequestsSent(Zb_LayersNwk(&child.stack)), 0,
                     "and the timeout request waits: it is not the join's own exchange");

    Test_ExpectStatus(Zb_LayersStep(&child.stack, 1000), ZB_OK,
                      "the child's next turn sends 3.4.11's request to its parent");
    Test_ExpectCount(Nwk_TimeoutRequestsSent(Zb_LayersNwk(&child.stack)), 1, "once, and counted");

    turnHandOver(&child.model, &parent.model);

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, 1100), ZB_OK,
                      "the parent's turn reads it and answers with 3.4.12's response");
    Test_ExpectCount(Nwk_TimeoutResponsesSent(Zb_LayersNwk(&parent.stack)), 1, "one answer");
    Test_ExpectCount(Nwk_ChildrenAgedOut(Zb_LayersNwk(&parent.stack)), 0, "and the child's entry is not aged out by it");
    Test_ExpectCount(Mac_CountersOf(Zb_LayersMac(&parent.stack)).transactionQueue, 1,
                     "held for the child's poll, since its receiver rests (10.22.2)");

    turnPoll(&child, 1150);
    turnHandOver(&child.model, &parent.model);

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, 1160), ZB_OK, "the parent's turn reads the poll and extracts the answer");
    turnHandOver(&parent.model, &child.model);

    Test_ExpectStatus(Zb_LayersStep(&child.stack, 1200), ZB_OK, "the child's turn takes the answer");
    Test_ExpectCount(Zb_LayersNwk(&child.stack)->cfg.parentInformation, 1,
                     "and stores Table 3-62's bit 0, which 3.3.1.1.8's End Device Initiator bit reads");
}

/* 3.6.10.2: an end device sends its timeout request after joining or rejoining, even to the same parent, so a rejoin
   that ends in SUCCESS owes the parent a second one. */
void caseTimeoutRequestAfterRejoin(void)
{
    StackDevice parent;
    StackDevice child;
    Nwk_JoinRequestParameters rr;
    Nwk_JoinConfirmParameters jc;

    joinPair(&parent, &child);

    Zb_memset(&jc, 0, (uint32_t)sizeof jc);
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&child.stack), &jc), 1, "the join's confirm is taken");
    Test_ExpectStatus(Zb_LayersStep(&child.stack, 300), ZB_OK, "and the next turn sends the join's timeout request");
    Test_ExpectCount(Nwk_TimeoutRequestsSent(Zb_LayersNwk(&child.stack)), 1, "one request for the join");

    turnHandOver(&child.model, &parent.model);
    Test_ExpectStatus(Zb_LayersStep(&parent.stack, 350), ZB_OK, "the parent answers it");
    turnHandOver(&parent.model, &child.model);
    Test_ExpectStatus(Zb_LayersStep(&child.stack, 400), ZB_OK, "and the child takes the answer, closing that exchange");

    rr = joinRequest(0x02);
    Test_ExpectStatus(Nwk_JoinRequest(Zb_LayersNwk(&child.stack), &rr, 1000), ZB_OK, "the child rejoins its parent");
    Test_ExpectStatus(Zb_LayersStep(&child.stack, 1000), ZB_OK, "its acknowledgment is collected");
    turnHandOver(&child.model, &parent.model);
    Test_ExpectStatus(Zb_LayersStep(&parent.stack, 1100), ZB_OK, "the parent answers");
    turnHandOver(&parent.model, &child.model);
    Test_ExpectStatus(Zb_LayersStep(&child.stack, 1200), ZB_OK, "the child polls");
    turnHandOver(&child.model, &parent.model);
    Test_ExpectStatus(Zb_LayersStep(&parent.stack, 1210), ZB_OK, "and the parent extracts the answer");
    turnHandOver(&parent.model, &child.model);
    Test_ExpectStatus(Zb_LayersStep(&child.stack, 1220), ZB_OK, "which the child reads");
    Test_ExpectCount(Nwk_JoinStateOf(Zb_LayersNwk(&child.stack)), NWK_JOIN_JOINED, "and is on the network again");

    Zb_memset(&jc, 0, (uint32_t)sizeof jc);
    Test_ExpectCount(Nwk_PollJoinConfirm(Zb_LayersNwk(&child.stack), &jc), 1, "the rejoin's confirm is taken");
    Test_ExpectStatus(Zb_LayersStep(&child.stack, 1300), ZB_OK, "and the next turn sends the timeout request");
    Test_ExpectCount(Nwk_TimeoutRequestsSent(Zb_LayersNwk(&child.stack)), 2, "a second request, for the rejoin");
}

/* The parent's entry for the child `joinPair` made. */
static Nwk_NeighborTableEntry *turnChildEntry(StackDevice *parent, StackDevice *child)
{
    return Nwk_NeighborOf(Zb_LayersNwk(&parent->stack)->neighbors, Mac_Pib(Zb_LayersMac(&child->stack))->shortAddress);
}

/* 3.6.10.5 and 3.6.10.1: a child that never asks for a timeout is given nwkEndDeviceTimeoutDefault's, and its entry
   goes on the second the counter runs out and not one before. */
void caseChildAgesOutAtTheDefault(void)
{
    StackDevice parent;
    StackDevice child;
    Nwk_NeighborTableEntry *entry;
    uint32_t base;

    joinPair(&parent, &child);

    entry = turnChildEntry(&parent, &child);
    Test_Expect(entry != 0, "the parent holds the child's entry the join wrote");

    if (entry == 0)
        return;

    Test_ExpectCount(entry->deviceTimeout, 256 * 60,
                     "with Device Timeout at Table 3-66's nwkEndDeviceTimeoutDefault, 8, which Table 3-58 makes 256 minutes");
    Test_ExpectCount(entry->timeoutCounter, 256 * 60, "and its Timeout Counter set to the same (3.6.10.5)");

    base = entry->timeoutMs;

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, base + (256 * 60 - 1) * 1000), ZB_OK,
                      "the parent's turn one second short of the period");
    Test_ExpectCount(Nwk_ChildrenAgedOut(Zb_LayersNwk(&parent.stack)), 0, "leaves the child where it is");

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, base + 256 * 60 * 1000), ZB_OK,
                      "and the turn at the period");
    Test_ExpectCount(Nwk_ChildrenAgedOut(Zb_LayersNwk(&parent.stack)), 1,
                     "deletes it: the counter reached 0, and 3.6.10.1 says the entry goes");
    Test_Expect(turnChildEntry(&parent, &child) == 0, "so the parent holds no entry for that address");
}

/* 3.6.10.4 step 2: a poll from the child puts its counter back at the full Device Timeout, so a child that keeps
   polling is never aged out. */
void caseChildPollIsAKeepalive(void)
{
    StackDevice parent;
    StackDevice child;
    Nwk_NeighborTableEntry *entry;
    uint32_t base;
    uint32_t heard;

    joinPair(&parent, &child);

    entry = turnChildEntry(&parent, &child);
    Test_Expect(entry != 0, "the parent holds the child's entry the join wrote");

    if (entry == 0)
        return;

    base = entry->timeoutMs;
    heard = Nwk_KeepalivesReceived(Zb_LayersNwk(&parent.stack));

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, base + 15000 * 1000), ZB_OK, "the parent's turn 15000 seconds on");
    Test_ExpectCount(entry->timeoutCounter, 256 * 60 - 15000, "leaves the child 360 seconds of its 256 minutes");

    turnPoll(&child, 1000);
    turnHandOver(&child.model, &parent.model);

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, base + 15000 * 1000 + 100), ZB_OK, "the parent's turn reads the poll");
    Test_ExpectCount(Nwk_KeepalivesReceived(Zb_LayersNwk(&parent.stack)), heard + 1, "as one keepalive");
    Test_ExpectCount(entry->timeoutCounter, 256 * 60, "which puts the counter back at the Device Timeout");
    Test_Expect(entry->keepaliveReceived == 1, "and sets Table 3-75's Keepalive Received");

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, base + (15000 + 256 * 60 - 1) * 1000), ZB_OK,
                      "so a turn where the old count would long have run out");
    Test_ExpectCount(Nwk_ChildrenAgedOut(Zb_LayersNwk(&parent.stack)), 0, "still holds the child");
}

/* 3.6.10.4 step 1 and 3.6.10.4.1: a device that polls with no entry is held a leave request asking it to rejoin, and
   the child reads it as one. */
void caseUnknownPollerIsAskedToLeave(void)
{
    StackDevice parent;
    StackDevice child;
    Nwk_NeighborTableEntry *entry;
    Mac_Counters counters;
    uint32_t base;
    uint32_t heard;

    joinPair(&parent, &child);

    entry = turnChildEntry(&parent, &child);
    Test_Expect(entry != 0, "the parent holds the child's entry the join wrote");

    if (entry == 0)
        return;

    base = entry->timeoutMs;

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, base + 256 * 60 * 1000), ZB_OK,
                      "the parent ages the silent child out");
    Test_Expect(turnChildEntry(&parent, &child) == 0, "and holds no entry for it");

    turnPoll(&child, 1000);
    turnHandOver(&child.model, &parent.model);

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, base + 256 * 60 * 1000 + 100), ZB_OK,
                      "the parent's turn reads a poll from the address it no longer holds");
    Test_ExpectCount(Nwk_UnknownPollLeaves(Zb_LayersNwk(&parent.stack)), 1, "and holds one leave request for it");
    counters = Mac_CountersOf(Zb_LayersMac(&parent.stack));
    Test_ExpectCount(counters.transactionQueue, 1,
                     "on the transaction queue, which 3.6.10.4 step 1 names, for the child's next poll to extract");

    turnPoll(&child, 1100);
    turnHandOver(&child.model, &parent.model);

    Test_ExpectStatus(Zb_LayersStep(&parent.stack, base + 256 * 60 * 1000 + 200), ZB_OK,
                      "the child's next poll extracts it");
    Test_ExpectCount(Nwk_UnknownPollLeaves(Zb_LayersNwk(&parent.stack)), 1,
                     "and draws no second one while the first is still held");

    heard = Nwk_LeaveCommandsHeard(Zb_LayersNwk(&child.stack));
    turnHandOver(&parent.model, &child.model);

    Test_ExpectStatus(Zb_LayersStep(&child.stack, 1200), ZB_OK, "the child's turn reads what its poll extracted");
    Test_ExpectCount(Nwk_LeaveCommandsHeard(Zb_LayersNwk(&child.stack)), heard + 1,
                     "a leave command from its parent, which 3.6.10.4.1 makes a request with rejoin set");
}
