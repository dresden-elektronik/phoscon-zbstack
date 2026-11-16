/* The `stack` suite's send half: the door a stack that is not running answers with its own refusal, the one
   cascade an accepted request becomes through APS, NWK and MAC, and the frame the three layers composed
   arriving at the hardware-free backend. `layers_cases.h` names the cases, `layers_helpers.h` the machinery. */

#include "layers_cases.h"
#include "layers_helpers.h"

#include "aps_frame.h"
#include "mac_frame.h"
#include "nwk_frame.h"
#include "rig_band_a.h"
#include "zb_utils.h"

/* The peer one façade is aimed at: a second short address on this suite's PAN, with an identity of its own, and
   the endpoints, profile and cluster a data frame has to carry (2.2.5.1.2 … 2.2.5.1.5). */
#define SEND_PEER_SHORT 0x0064
#define SEND_PEER_IEEE 0x2021222324252627
#define SEND_SRC_EP 0x01
#define SEND_DST_EP 0x02
#define SEND_PROFILE_ID 0x0104
#define SEND_CLUSTER_ID 0x0006
#define SEND_PAYLOAD_LEN 6

/* Each header run below is the sum of the fields its figure prints: Figure 7-2/7-3's MHR with the source PAN
   compressed away and both addresses short, Figure 3-4's always-present octets, and Figure 2-3's data-header
   columns, control, destination endpoint, cluster, profile, source endpoint, counter. */
#define SEND_MAC_HEADER_FORM (MAC_FRAME_FCF_OCTETS + MAC_FRAME_SEQ_OCTETS + MAC_FRAME_PAN_OCTETS \
                              + MAC_FRAME_SHORT_OCTETS + MAC_FRAME_SHORT_OCTETS)
#define SEND_APS_HEADER_FORM (APS_FRAME_FCF_OCTETS + APS_FRAME_ENDPOINT_OCTETS \
                              + APS_FRAME_CLUSTER_OCTETS + APS_FRAME_PROFILE_OCTETS \
                              + APS_FRAME_ENDPOINT_OCTETS + APS_FRAME_COUNTER_OCTETS)
#define SEND_ASDU_OFFSET (SEND_MAC_HEADER_FORM + NWK_MIN_HEADER_OVERHEAD + SEND_APS_HEADER_FORM)
#define SEND_MAC_SEQ_OCTET MAC_FRAME_FCF_OCTETS
#define SEND_NWK_SEQ_OCTET (SEND_MAC_HEADER_FORM + NWK_FRAME_FCF_OCTETS + NWK_FRAME_ADDR_OCTETS \
                            + NWK_FRAME_ADDR_OCTETS + NWK_FRAME_RADIUS_OCTETS)
#define SEND_APS_COUNTER_OCTET (SEND_ASDU_OFFSET - 1)
#define SEND_FRAME_FORM (SEND_ASDU_OFFSET + SEND_PAYLOAD_LEN + MAC_FRAME_FCS_OCTETS)

/* Table 2-2's parameters as an application fills them: the addressing mode the case is about, a destination,
   one endpoint at each end, a profile, a cluster, the ASDU and the raw `TxOptions` bitmap. */
static Aps_ApsdeReq sendRequest(uint32_t dstAddrMode, uint16_t dst, const uint8_t *asdu,
                                uint32_t asduLength, uint32_t txOptions)
{
    Aps_ApsdeReq req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    req.dstAddrMode = dstAddrMode;
    req.dstAddress = dst;
    req.dstEndpoint = SEND_DST_EP;
    req.profileId = SEND_PROFILE_ID;
    req.clusterId = SEND_CLUSTER_ID;
    req.srcEndpoint = SEND_SRC_EP;
    req.asdu = asdu;
    req.asduLength = asduLength;
    req.txOptions = txOptions;

    return req;
}

/* The peer's identity written over the suite's own device: same PAN, same channel, same seeds, two addresses. */
static void sendPeerAt(StackDevice *peer)
{
    stackDevicePlain(peer);

    peer->cfg.shortAddress = SEND_PEER_SHORT;
    stackExtendedOctets(SEND_PEER_IEEE, peer->cfg.extendedAddress);
}

/* Every transmit a model is asked for is acknowledged, so what a cascade gets back is the answer a radio that
   answers gives (docs/internals/protocol.md §8.3). */
static void sendAnswer(Loopback_Radio *model)
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

/* A unicast needs a next hop: one neighbour entry on each side, and both backends scripted to answer. */
static void sendWire(StackDevice *dev, StackDevice *peer)
{
    Test_BandASeedNeighbor(Zb_LayersNwk(&dev->stack), SEND_PEER_SHORT, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    Test_BandASeedNeighbor(Zb_LayersNwk(&peer->stack), STACK_SHORT_ADDRESS, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    sendAnswer(&dev->model);
    sendAnswer(&peer->model);
}

/* The newest frame one stack handed its backend, injected in front of the other stack's MAC as the frame it is. */
static void sendHandOver(Loopback_Radio *from, Loopback_Radio *to)
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

/* What a refusal at the door owes as proof: the three layers' own refusal counters unmoved, no pool holding
   anything the call took, and the backend handed no frame. Shared by the door case's two refusals, each of
   which states its own reason for reaching nothing. */
static void sendExpectNoLayerReached(StackDevice *dev)
{
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Mac_Counters counters;

    counters = Mac_CountersOf(Zb_LayersMac(&dev->stack));
    Test_Expect(Aps_RefusedRequests(Zb_LayersAps(&dev->stack)) == 0
                && Nwk_RefusedRequests(Zb_LayersNwk(&dev->stack)) == 0
                && counters.refusedRequests == 0,
                "no layer was asked, so no layer counted a refusal: the sub-layer's own door counter, the network layer's and the MAC's all stand where they were");
    Test_Expect(Aps_TransmitQueue(Zb_LayersAps(&dev->stack)) == 0
                && Aps_ConfirmQueue(Zb_LayersAps(&dev->stack)) == 0
                && Nwk_TransmitQueue(Zb_LayersNwk(&dev->stack)) == 0
                && Nwk_ConfirmQueue(Zb_LayersNwk(&dev->stack)) == 0
                && counters.outstanding == 0
                && counters.confirmQueue == 0,
                "and no pool of any layer holds a transaction, a confirmation or a track slot the call took");
    Test_ExpectCount(LoopbackRadio_Sent(&dev->model, sent, LOOPBACK_TX_MAX), 0,
                     "the model's air is empty: a refusal that reaches no layer composes no frame");
}

void caseSendRefusedAtDoor(void)
{
    StackDevice dev;
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Radio_Pib pibWrites[LOOPBACK_PIB_WRITE_MAX];
    Aps_ApsdeReq req;
    Mac_Counters counters;
    static const uint8_t asdu[SEND_PAYLOAD_LEN] = { 0x64, 0x6f, 0x6f, 0x72, 0x21, 0x21 };

    stackDevice(&dev);
    req = sendRequest(APS_ADDR_MODE_SHORT, SEND_PEER_SHORT, asdu, SEND_PAYLOAD_LEN, APS_TX_OPTION_ACK);

    Test_ExpectStatus(Zb_LayersDataRequest(0, &req, 100), ZB_ERR_BAD_ARGUMENT,
                      "a request aimed at no façade is refused before any layer is named, at the door `Zb_LayersStep` and `Zb_LayersCapture` refuse at");

    Test_Expect(stackIsZero(&dev.stack),
                "the façade a case has built but not yet initialised is every byte zero, so this is the request an application makes before `Zb_LayersInit` lands");
    Test_ExpectStatus(Zb_LayersDataRequest(&dev.stack, &req, 100), ZB_ERR_BAD_ARGUMENT,
                      "and it is answered with the door's own refusal: a stack that is not running is not a stack an application may send through");
    sendExpectNoLayerReached(&dev);
    Test_Expect(stackIsZero(&dev.stack), "the refused call wrote nothing into the object it was refused at");

    dev.cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_64;
    Test_ExpectStatus(stackInit(&dev), ZB_ERR_BAD_ARGUMENT,
                      "an init that refuses the level its security config does not agree with refuses before it applies anything");
    Test_Expect(stackIsZero(&dev.stack),
                "and leaves the façade zero bytes, which is what makes the next refusal a claim about a stack that is not running rather than about half a stack");
    Test_ExpectStatus(Zb_LayersDataRequest(&dev.stack, &req, 110), ZB_ERR_BAD_ARGUMENT,
                      "the same request at that door is refused by the door: a failed init did not make the stack a running one");
    sendExpectNoLayerReached(&dev);
    Test_ExpectCount(LoopbackRadio_PibWrites(&dev.model, pibWrites, LOOPBACK_PIB_WRITE_MAX), 0,
                     "and the backend was handed no PIB request either: an init that never applied its config never reached the seam, so the refused request had nothing to disturb");

    dev.cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "with the disagreement removed the same struct builds, which is what makes the last two refusals the door of a running stack and not an unbuilt one");
    Test_ExpectStatus(Zb_LayersDataRequest(&dev.stack, 0, 120), ZB_ERR_BAD_ARGUMENT,
                      "a request that names no parameters at all is refused at that door, before the service is asked to read one");
    Test_Expect(Aps_RefusedRequests(Zb_LayersAps(&dev.stack)) == 0
                && Aps_ConfirmQueue(Zb_LayersAps(&dev.stack)) == 0,
                "the service never saw it: it counts the parameters it declined, it declined nothing, and no confirmation is owed for a request no layer was asked about");
    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, LOOPBACK_TX_MAX), 0,
                     "with the air of a running stack that refused a request at its own door still empty");

    /* The contrast that says the refusals above were about the stack and not about the request: the very
     * parameters the door declined are accepted by the same struct the moment it is running. */
    Test_BandASeedNeighbor(Zb_LayersNwk(&dev.stack), SEND_PEER_SHORT, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    sendAnswer(&dev.model);
    Test_ExpectStatus(Zb_LayersDataRequest(&dev.stack, &req, 130), ZB_OK,
                      "the same request the door refused is accepted by the same façade once its init has landed: what refused was the state of the stack, not the parameters of the request");
    counters = Mac_CountersOf(Zb_LayersMac(&dev.stack));
    Test_Expect(Aps_TransmitQueue(Zb_LayersAps(&dev.stack)) == 1
                && Nwk_TransmitQueue(Zb_LayersNwk(&dev.stack)) == 1
                && counters.outstanding == 1,
                "and this time the layers were reached, each holding the one slot the same call takes at each depth");
    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, LOOPBACK_TX_MAX), 1,
                     "with one frame at the backend where every refusal above left the air empty");
}

void caseSendCrossingPinsCounters(void)
{
    StackDevice dev;
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Aps_ApsdeReq req;
    Zb_State before;
    Zb_State after;
    uint32_t sentCount;
    Mac_Counters counters;
    static const uint8_t asdu[SEND_PAYLOAD_LEN] = { 0x63, 0x61, 0x73, 0x63, 0x61, 0x64 };

    stackDevicePlain(&dev);

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "a level-0x00 stack built by the façade: the crossing is the layers' work, and no key material belongs in it");

    Test_BandASeedNeighbor(Zb_LayersNwk(&dev.stack), SEND_PEER_SHORT, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    sendAnswer(&dev.model);

    Test_ExpectStatus(Zb_LayersCapture(&dev.stack, 0, &before), ZB_OK,
                      "the numbering the case is about, read back through the façade before the request, so what moves is measured and not assumed");
    Test_Expect(before.apsCounter == APS_COUNTER_START && before.nwkSequenceNumber == STACK_SEQ_START
                && before.macDsn == STACK_DSN_START,
                "and it is where the config put it: the three numbers a frame is made of belong to the three layers and are seeded by the application");
    counters = Mac_CountersOf(Zb_LayersMac(&dev.stack));
    Test_Expect(Aps_TransmitQueue(Zb_LayersAps(&dev.stack)) == 0
                && Nwk_TransmitQueue(Zb_LayersNwk(&dev.stack)) == 0
                && Nwk_RouteQueue(Zb_LayersNwk(&dev.stack)) == 0
                && counters.outstanding == 0,
                "with nothing taken back anywhere: a neighbour entry on its own makes no route and holds no slot");

    req = sendRequest(APS_ADDR_MODE_SHORT, SEND_PEER_SHORT, asdu, SEND_PAYLOAD_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Zb_LayersDataRequest(&dev.stack, &req, 100), ZB_OK,
                      "one accepted request answers with the status the sub-layer gave it: `ZB_OK` for a request that transmitted, and no richer word the façade invented");

    sentCount = LoopbackRadio_Sent(&dev.model, sent, LOOPBACK_TX_MAX);
    Test_ExpectCount(sentCount, 1,
                     "and exactly one frame reached the loopback backend: one call, one cascade, one transmit, with no second issue and no frame left waiting for a later turn");
    Test_ExpectCount((uint32_t) sent[0].ackRequest, 1,
                     "handed over asking for the acknowledgment the network layer asks for on every unicast of its own (3.6.4.3), the ask the request's 0x04 bit neither adds nor removes");
    counters = Mac_CountersOf(Zb_LayersMac(&dev.stack));
    Test_Expect(Aps_TransmitQueue(Zb_LayersAps(&dev.stack)) == 1
                && Nwk_TransmitQueue(Zb_LayersNwk(&dev.stack)) == 1
                && counters.outstanding == 1,
                "one transaction is held by all three services at once, one slot each, which is the whole claim that the request crossed: nothing skipped and nothing doubled");
    Test_ExpectCount(Nwk_RouteQueue(Zb_LayersNwk(&dev.stack)), 1,
                     "and the neighbour entry bought the route entry the frame was aimed through: 3.6.4.3's shortcut is the network layer's act, not a state the façade keeps");

    Test_Expect(Aps_RefusedRequests(Zb_LayersAps(&dev.stack)) == 0
                && Aps_ConfirmQueue(Zb_LayersAps(&dev.stack)) == 0
                && Aps_IndicationQueue(Zb_LayersAps(&dev.stack)) == 0
                && Aps_AcksGenerated(Zb_LayersAps(&dev.stack)) == 0
                && Aps_UnmatchedAcks(Zb_LayersAps(&dev.stack)) == 0
                && Aps_ConfirmationsIgnored(Zb_LayersAps(&dev.stack)) == 0
                && Aps_RetransmitRefusals(Zb_LayersAps(&dev.stack)) == 0
                && Aps_TxNoKeyPair(Zb_LayersAps(&dev.stack)) == 0
                && Aps_TxSecuredFailures(Zb_LayersAps(&dev.stack)) == 0,
                "every other counter of the sub-layer is unmoved: no refusal, no answer, no delivery, no acknowledgement owed, no retransmission refused and no security act. The one thing this request did was transmit");
    Test_Expect(Nwk_RefusedRequests(Zb_LayersNwk(&dev.stack)) == 0
                && Nwk_ConfirmQueue(Zb_LayersNwk(&dev.stack)) == 0
                && Nwk_IndicationQueue(Zb_LayersNwk(&dev.stack)) == 0
                && Nwk_DroppedNoRoute(Zb_LayersNwk(&dev.stack)) == 0
                && Nwk_ConfirmsIgnored(Zb_LayersNwk(&dev.stack)) == 0
                && Nwk_RelaysSent(Zb_LayersNwk(&dev.stack)) == 0
                && Nwk_RouteRequestsSent(Zb_LayersNwk(&dev.stack)) == 0
                && Nwk_BttQueue(Zb_LayersNwk(&dev.stack)) == 0,
                "and the same at the network layer: a unicast with a next hop is neither dropped for want of a route, nor relayed, nor sent to discovery, nor recorded in the broadcast transaction table");
    counters = Mac_CountersOf(Zb_LayersMac(&dev.stack));
    Test_Expect(counters.refusedRequests == 0
                && counters.confirmQueue == 0
                && counters.indicationQueue == 0
                && counters.transactionQueue == 0
                && counters.pollArrivalQueue == 0
                && counters.pibReapplications == 0
                && counters.acksHeard == 0,
                "and at the MAC: the indirect queue no sleepy device needed stays empty, no PIB was reapplied, and nothing came back yet");

    Test_ExpectStatus(Zb_LayersCapture(&dev.stack, 0, &after), ZB_OK, "the same numbering, read back through the façade after the request");
    Test_ExpectCount(after.apsCounter, before.apsCounter + 1,
                     "the APS counter moved by exactly one: one number per new transaction, spent on a frame that transmitted (2.2.5.1.7)");
    Test_ExpectCount(after.nwkSequenceNumber, before.nwkSequenceNumber + 1,
                     "the network sequence number by exactly one, incremented with each new frame transmitted (3.3.1.5)");
    Test_ExpectCount(after.macDsn, before.macDsn + 1,
                     "and the MAC's own number by exactly one, one per frame issued and not per attempt (7.2.3)");

    Test_Expect(LoopbackRadio_Queued(&dev.model) == 0 && LoopbackRadio_Refusals(&dev.model) == 0,
                "the backend was given one transmit and nothing else: no frame waiting on this device's doorstep and no refusal of its own");
}

void caseSendConfirmAtItsStep(void)
{
    StackDevice dev;
    StackDevice peer;
    Aps_ApsdeReq req;
    Aps_Confirm confirms[2];
    Aps_Indication indications[2];
    static const uint8_t asdu[SEND_PAYLOAD_LEN] = { 0x61, 0x6e, 0x73, 0x77, 0x65, 0x72 };

    stackDevicePlain(&dev);
    sendPeerAt(&peer);

    Test_ExpectStatus(stackInit(&dev), ZB_OK, "the pair this case drives: two stacks, each built by the façade over its own model");
    Test_ExpectStatus(stackInit(&peer), ZB_OK, "and the second is the peer the acknowledged unicast is aimed at");

    sendWire(&dev, &peer);

    req = sendRequest(APS_ADDR_MODE_SHORT, SEND_PEER_SHORT, asdu, SEND_PAYLOAD_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Zb_LayersDataRequest(&dev.stack, &req, 100), ZB_OK,
                      "one acknowledged unicast goes in through the façade, which is the only service call this case makes");

    Zb_memset(confirms, 0, (uint32_t)sizeof confirms);
    Test_ExpectCount(Zb_LayersPollConfirms(&dev.stack, confirms, 2), 0,
                     "and the façade answers with nothing yet: the request was accepted and transmitted, and the answer to it is owed by the turn that collects the layer below");

    Test_ExpectStatus(Zb_LayersStep(&dev.stack, 110), ZB_OK, "one turn of the three layers, taken through the façade");
    Test_ExpectCount(Zb_LayersPollConfirms(&dev.stack, confirms, 2), 0,
                     "is a step earlier than the confirmation: the radio answered and the transaction became the one awaiting the peer's acknowledgement (2.2.8.4.4), so nothing has been answered upward");

    sendHandOver(&dev.model, &peer.model);
    Test_ExpectStatus(Zb_LayersStep(&peer.stack, 120), ZB_OK, "the peer's turn takes the frame");

    Zb_memset(indications, 0, (uint32_t)sizeof indications);
    Test_ExpectCount(Zb_LayersPollIndications(&peer.stack, indications, 2), 1,
                     "and delivers it upward through the peer's façade, which is what makes this device owe the acknowledgement the sender is waiting for");
    Test_ExpectOctets("carrying the six octets the request named, across two façades and four layers",
                      indications[0].asdu, indications[0].asduLength, asdu, SEND_PAYLOAD_LEN);

    sendHandOver(&peer.model, &dev.model);
    Test_ExpectCount(Zb_LayersPollConfirms(&dev.stack, confirms, 2), 0,
                     "the answer is on this device's doorstep before its next turn, and a drain run before that turn finds nothing to hand over");

    Test_ExpectStatus(Zb_LayersStep(&dev.stack, 130), ZB_OK, "the sender's next turn is the step that produces the confirmation");
    Test_ExpectCount(Zb_LayersPollConfirms(&dev.stack, confirms, 2), 1,
                     "and `Zb_LayersPollConfirms` reports it through the façade alone, oldest first, with no layer named by the caller");
    Test_ExpectStatus(confirms[0].status, ZB_OK, "with the status the cascade answered with, passed through unchanged");
    Test_ExpectCount(confirms[0].apsStatus, APS_STATUS_SUCCESS,
                     "and Table 2-29's SUCCESS beside it, the code 2.2.4.1.2 answers a transaction that delivered with");
    Test_Expect(confirms[0].dstAddrMode == APS_ADDR_MODE_SHORT && confirms[0].dstAddress == SEND_PEER_SHORT
                && confirms[0].srcEndpoint == SEND_SRC_EP && confirms[0].dstEndpoint == SEND_DST_EP
                && confirms[0].profileId == SEND_PROFILE_ID && confirms[0].clusterId == SEND_CLUSTER_ID,
                "the confirmation names the transaction it answers with the parameters the request gave it, so a caller can match it without holding anything itself");
    Test_ExpectCount((uint32_t) confirms[0].apsCounter, APS_COUNTER_START,
                     "carrying the first counter this stack ever handed out, which is the number the acknowledgement was matched on (2.2.5.2.3.1)");
    Test_ExpectCount(confirms[0].attempts, 1, "after one NLDE transaction and no retransmission");

    Test_ExpectCount(Zb_LayersPollConfirms(&dev.stack, confirms, 2), 0, "and nothing behind it: one transaction is one answer");

    Test_ExpectStatus(Zb_LayersStep(&dev.stack, 140), ZB_OK, "a further turn finds nothing left to run");
    Test_ExpectCount(Zb_LayersPollConfirms(&dev.stack, confirms, 2), 0,
                     "and the confirmation is not produced a second time, which is what separates the step that made it from the steps on either side of it");
}

void caseSendRefusalNamesItsLayer(void)
{
    StackDevice dev;
    StackDevice scaffold;
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Aps_ApsdeReq req;
    Aps_Confirm confirms[2];
    Mac_Counters devCounters;
    Mac_Counters scaffoldCounters;
    static const uint8_t asdu[SEND_PAYLOAD_LEN] = { 0x6e, 0x61, 0x6d, 0x65, 0x64, 0x21 };

    stackDevice(&dev);
    stackDevicePlain(&scaffold);

    Test_ExpectStatus(stackInit(&dev), ZB_OK, "a built stack at a level that protects frames, with the neighbour the refusals are aimed at");
    Test_ExpectStatus(stackInit(&scaffold), ZB_OK,
                      "and a built stack at level 0x00 with no security module attached to either layer, which is the device the second refusal is about");

    Test_BandASeedNeighbor(Zb_LayersNwk(&dev.stack), SEND_PEER_SHORT, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    Test_BandASeedNeighbor(Zb_LayersNwk(&scaffold.stack), SEND_PEER_SHORT, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    sendAnswer(&dev.model);
    sendAnswer(&scaffold.model);

    /* The sub-layer's own refusal: a parameter outside the range Table 2-2 prints. */
    req = sendRequest((uint32_t) (APS_ADDR_MODE_MAX + 1), SEND_PEER_SHORT, asdu, SEND_PAYLOAD_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Zb_LayersDataRequest(&dev.stack, &req, 100), ZB_ERR_BAD_ARGUMENT,
                      "a DstAddressMode in Table 2-2's reserved band 0x04-0xff reaches the caller as the argument error that door named, in the vocabulary the layer refused it with");
    Test_ExpectCount(Aps_RefusedRequests(Zb_LayersAps(&dev.stack)), 1,
                     "counted by the layer that refused it, which is what makes the refusal nameable as that layer's and not as the façade's");
    devCounters = Mac_CountersOf(Zb_LayersMac(&dev.stack));
    Test_Expect(Nwk_RefusedRequests(Zb_LayersNwk(&dev.stack)) == 0 && devCounters.refusedRequests == 0,
                 "and by no layer below it: the parameter was judged before any address was derived, so the network layer and the MAC were never asked");
    Test_Expect(Aps_TransmitQueue(Zb_LayersAps(&dev.stack)) == 0
                && Nwk_TransmitQueue(Zb_LayersNwk(&dev.stack)) == 0
                && devCounters.outstanding == 0,
                "nothing was taken back at any depth: a request refused for its parameters spends no slot, no sequence number and no frame");
    Test_ExpectCount(Zb_LayersPollConfirms(&dev.stack, confirms, 2), 0,
                     "and no confirmation is produced for it: 2.2.4.1.1.3 answers an argument error by refusing the primitive, and the façade keeps no ring of its own to answer out of");
    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, LOOPBACK_TX_MAX), 0, "with nothing on the model's air");

    /* The option that is not the caller's to supply: Table 2-2's 0x02 asks for the network key as the carrier's
       protection, and 4.2.2 leaves that decision to the network. A device holding no key material has no protection
       to run, so the network composes the frame unprotected instead of refusing the request. */
    req = sendRequest(APS_ADDR_MODE_SHORT, SEND_PEER_SHORT, asdu, SEND_PAYLOAD_LEN, APS_TX_OPTION_NWK_KEY);
    Test_ExpectStatus(Zb_LayersDataRequest(&scaffold.stack, &req, 100), ZB_OK,
                      "TxOptions 0x02 at a device holding no security: the option asks the network and does not provide a key, and the network's own state answers it by taking the request");
    Test_ExpectCount(Nwk_RefusedRequests(Zb_LayersNwk(&scaffold.stack)), 0,
                     "no refusal at that door: 4.2.2 prohibits protection where the parameter says FALSE, and nothing here says FALSE");
    Test_Expect(Aps_RefusedRequests(Zb_LayersAps(&scaffold.stack)) == 0
                && Aps_TransmitQueue(Zb_LayersAps(&scaffold.stack)) == 1,
                "the transaction is held by the service above, so its answer comes through the ring and not back through the door");
    Test_Expect(Aps_TxNoKeyPair(Zb_LayersAps(&scaffold.stack)) == 0
                && Aps_TxSecuredFailures(Zb_LayersAps(&scaffold.stack)) == 0,
                "and it is not the security family's answer either: 0x01 was not set, so no key pair was looked for and no APS protection was attempted");
    scaffoldCounters = Mac_CountersOf(Zb_LayersMac(&scaffold.stack));
    Test_ExpectCount(scaffoldCounters.refusedRequests, 0,
                     "the MAC composed it without refusing: an unprotected frame is a frame the MAC frames the same way");
    Test_ExpectCount(Zb_LayersPollConfirms(&scaffold.stack, confirms, 2), 0,
                     "no confirmation yet: the answer is owed, and this turn has not run");
    Test_ExpectCount(LoopbackRadio_Sent(&scaffold.model, sent, LOOPBACK_TX_MAX), 1,
                     "one frame on the model's air, which is the option's own claim: the ask changed nothing about the frame the network could compose");
}

void caseSendFrameIsTheLayersWork(void)
{
    StackDevice dev;
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Mac_Frame macFrame;
    Nwk_Frame nwkFrame;
    Aps_Frame apsFrame;
    Aps_ApsdeReq req;
    const uint8_t *mpdu;
    const uint8_t *npdu;
    uint32_t mpduLen;
    uint32_t npduOffset;
    uint32_t npduLen;
    uint32_t apduOffset;
    uint32_t apduLen;
    uint32_t sentCount;
    static const uint8_t asdu[SEND_PAYLOAD_LEN] = { 0x66, 0x72, 0x61, 0x6d, 0x65, 0x64 };
    static const uint8_t asduAgain[SEND_PAYLOAD_LEN] = { 0x61, 0x67, 0x61, 0x69, 0x6e, 0x21 };

    /* The whole header run of the frame this case sends, written out of the figures rather than read back off
     * this stack's own codec, at this suite's own identity and seeds: PAN 0x1a2b, short 0x0042 sending to
     * 0x0064, macDsn seeded 0x21, nwkSequenceNumber seeded 0x11, and no Radius asked for. */
    static const uint8_t headers[SEND_ASDU_OFFSET] =
    {
        0x61, 0x88,                         /* Frame Control Field: data, acknowledgment asked, source PAN
                                              compressed away, both address fields short (Figure 7-2) */
        0x21,                               /* Sequence Number: the seeded macDsn, first frame of the session */
        0x2b, 0x1a,                         /* Destination PAN ID 0x1a2b, low octet first */
        0x64, 0x00,                         /* Destination 0x0064: the neighbour, which is the next hop */
        0x42, 0x00,                         /* Source 0x0042: this device, its PAN compressed away */
        0x48, 0x00,                         /* NWK frame control: data, nwkcProtocolVersion 0x02 and the route
                                              discovery 2.2.8.4.1 obliges a unicast to ask for */
        0x64, 0x00,                         /* Destination Address */
        0x42, 0x00,                         /* Source Address */
        NWK_INITIAL_RADIUS,                 /* Radius 30, the default 3.2.1.1.3 derives for a request that named none */
        STACK_SEQ_START,                    /* Sequence Number, the seeded nwkSequenceNumber */
        0x40,                               /* APS frame control: data, unicast, the acknowledgment asked for */
        SEND_DST_EP,                        /* DstEndpoint */
        0x06, 0x00,                         /* ClusterId 0x0006, low octet first (2.2.5) */
        0x04, 0x01,                         /* ProfileId 0x0104, low octet first */
        SEND_SRC_EP,                        /* SrcEndpoint */
        APS_COUNTER_START                   /* APS counter, the first this stack hands out (2.2.5.1.7) */
    };

    stackDevicePlain(&dev);

    Test_ExpectStatus(stackInit(&dev), ZB_OK,
                      "one scaffold device: only a frame the three layers write in the clear can be read whole at the backend, a secured one handing over ciphertext");

    Test_BandASeedNeighbor(Zb_LayersNwk(&dev.stack), SEND_PEER_SHORT, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    sendAnswer(&dev.model);

    req = sendRequest(APS_ADDR_MODE_SHORT, SEND_PEER_SHORT, asdu, SEND_PAYLOAD_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Zb_LayersDataRequest(&dev.stack, &req, 100), ZB_OK, "one accepted data request");

    sentCount = LoopbackRadio_Sent(&dev.model, sent, LOOPBACK_TX_MAX);
    Test_ExpectCount(sentCount, 1, "and one MPDU is what the backend was handed");

    mpdu = sent[0].bytes;
    Test_ExpectOctets("the octets ahead of the payload are the layers' work as a byte string: the MHR 7.2.1 orders, the NWK header Figure 3-4 writes, the APS header Figure 2-3 frames",
                      mpdu, (uint32_t) sizeof headers, headers, (uint32_t) sizeof headers);
    Test_ExpectOctets("and behind them the NSDU holds the six octets the request named, where the APS header put them",
                      mpdu + (uint32_t) sizeof headers, SEND_PAYLOAD_LEN, asdu, SEND_PAYLOAD_LEN);
    Test_ExpectCount(sent[0].len, SEND_FRAME_FORM,
                     "the frame handed to the seam is those headers, the ASDU and the two footer octets band A writes for it (7.2.11), and nothing the façade added");
    Test_ExpectStatus(MacFrame_CheckFcs(mpdu, sent[0].len), ZB_OK,
                      "the footer validates against the octets it was written behind: this host's own arithmetic, which is what the model keeps and not what a device puts on the air");

    Test_ExpectStatus(MacFrame_Parse(mpdu, sent[0].len, Mac_Caps(Zb_LayersMac(&dev.stack))->psduIncludesFcs,
                                     &macFrame, &npdu, &mpduLen, 0), ZB_OK,
                      "the same octets parse as a MAC data frame, the footer counted as the backend this device was built on reports it");
    Test_Expect(macFrame.frameType == MAC_FRAME_TYPE_DATA && macFrame.frameVersion == 0
                && macFrame.ackRequest == 1 && macFrame.panIdCompression == 1
                && macFrame.securityEnabled == 0 && macFrame.destAddrMode == MAC_ADDR_SHORT
                && macFrame.srcAddrMode == MAC_ADDR_SHORT,
                "data, frame version 0, the acknowledgment asked, this PAN written once, no MAC security, both address fields short: the shape the layer below composes for a unicast of its own");
    Test_Expect(macFrame.destPan == STACK_PAN_ID && macFrame.destShort == SEND_PEER_SHORT
                && macFrame.srcShort == STACK_SHORT_ADDRESS
                && macFrame.seq == (uint8_t) STACK_DSN_START,
                "aimed at the neighbour that is the next hop, sourced from the PIB's short address, numbered by the seeded macDsn (3.3.1.3, 7.2.3)");
    Test_ExpectCount(mpduLen, NWK_MIN_HEADER_OVERHEAD + SEND_APS_HEADER_FORM + SEND_PAYLOAD_LEN,
                     "and the MAC codec reports the whole NPDU as the payload span, its own footer counted out of that span and still on the end of the MPDU");

    Test_ExpectStatus(NwkFrame_Parse(npdu, mpduLen, &nwkFrame, &npduOffset, &npduLen), ZB_OK,
                      "the MAC payload parses as a network frame");
    Test_Expect(nwkFrame.frameType == NWK_FRAME_TYPE_DATA && nwkFrame.protocolVersion == NWK_PROTOCOL_VERSION
                && nwkFrame.securityEnabled == 0 && nwkFrame.sourceRoute == 0
                && nwkFrame.destIeeePresent == 0 && nwkFrame.srcIeeePresent == 0
                && nwkFrame.discoverRoute == NWK_DISCOVER_ENABLE,
                "the eight always-present fields and one ask: no IEEE address, no source route and no security, each a form this stack has not built and therefore absent rather than guessed at, and the discovery sub-field set because 2.2.8.4.1 makes the sub-layer ask the network layer for a route on every frame it hands down");
    Test_Expect(nwkFrame.destAddr == SEND_PEER_SHORT && nwkFrame.srcAddr == STACK_SHORT_ADDRESS
                && nwkFrame.radius == NWK_INITIAL_RADIUS
                && nwkFrame.sequenceNumber == (uint8_t) STACK_SEQ_START,
                "the destination the request named and the source the PIB holds, the radius 3.2.1.1.3 derives, and the sequence number the config seeded");
    Test_ExpectCount(npduOffset, NWK_MIN_HEADER_OVERHEAD, "the NSDU begins past nwkcMinHeaderOverhead octets (Table 3-65)");
    Test_ExpectCount(npduLen, SEND_APS_HEADER_FORM + SEND_PAYLOAD_LEN,
                     "and it is exactly the APDU: no octet of it belongs to the layer that carried it");

    Test_ExpectStatus(ApsFrame_Parse(npdu + npduOffset, npduLen, &apsFrame, &apduOffset, &apduLen), ZB_OK,
                      "the NSDU parses as an APS data frame");
    Test_Expect(apsFrame.frameType == APS_FRAME_TYPE_DATA && apsFrame.deliveryMode == APS_DELIVERY_UNICAST
                && apsFrame.ackRequest == 1 && apsFrame.securityEnabled == 0
                && apsFrame.extendedHeaderPresent == 0,
                "the delivery mode the addressing derived, the acknowledgment bit the request's 0x04 asked for, no security and no extended header (2.2.5.1.1)");
    Test_Expect(apsFrame.dstEndpointPresent == 1 && apsFrame.dstEndpoint == SEND_DST_EP
                && apsFrame.srcEndpointPresent == 1 && apsFrame.srcEndpoint == SEND_SRC_EP
                && apsFrame.clusterPresent == 1 && apsFrame.clusterId == SEND_CLUSTER_ID
                && apsFrame.profilePresent == 1 && apsFrame.profileId == SEND_PROFILE_ID,
                "one endpoint at each end and the profile and cluster a data header must carry (2.2.5.1.2, 2.2.5.1.4, 2.2.5.1.5, 2.2.5.1.6)");
    Test_ExpectCount((uint32_t) apsFrame.apsCounter, APS_COUNTER_START,
                     "numbered with the first counter this stack hands out, inside the frame and not beside it (2.2.5.1.7)");
    Test_ExpectCount(apduOffset, SEND_APS_HEADER_FORM, "the ASDU begins past the data header the figures print");
    Test_ExpectCount(apduLen, SEND_PAYLOAD_LEN, "and the payload region the codec reports is exactly as long as the ASDU was");

    /* The same call made twice: what the façade does not keep is visible as each layer's number moving by one
     * and each frame carrying the octets of the call that composed it. */
    req = sendRequest(APS_ADDR_MODE_SHORT, SEND_PEER_SHORT, asduAgain, SEND_PAYLOAD_LEN, APS_TX_OPTION_ACK);
    Test_ExpectStatus(Zb_LayersDataRequest(&dev.stack, &req, 110), ZB_OK, "a second request on the same stack, with different ASDU octets");

    sentCount = LoopbackRadio_Sent(&dev.model, sent, LOOPBACK_TX_MAX);
    Test_ExpectCount(sentCount, 2, "produced a second frame at the backend rather than queueing the first or re-issuing it");
    Test_Expect(sent[1].bytes[SEND_MAC_SEQ_OCTET] == (uint8_t) (STACK_DSN_START + 1)
                && sent[1].bytes[SEND_NWK_SEQ_OCTET] == (uint8_t) (STACK_SEQ_START + 1)
                && sent[1].bytes[SEND_APS_COUNTER_OCTET] == (uint8_t) (APS_COUNTER_START + 1),
                "with each layer's number one further than the first frame's: the DSN the MAC counts, the sequence the network layer counts and the counter the sub-layer counts, none of them held by the façade");
    Test_ExpectOctets("and the second frame carries the second request's octets, so nothing was buffered between the two calls",
                      sent[1].bytes + (uint32_t) sizeof headers, SEND_PAYLOAD_LEN, asduAgain, SEND_PAYLOAD_LEN);
    Test_ExpectOctets("while the first frame still holds the first request's: the octets were composed once, by the call that made them",
                      sent[0].bytes + (uint32_t) sizeof headers, SEND_PAYLOAD_LEN, asdu, SEND_PAYLOAD_LEN);
}
