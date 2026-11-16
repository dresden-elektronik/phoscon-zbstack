/* The `aps` suite's shared machinery: the bodies. See `aps_helpers.h` for what this file is and why it is
   here. */

#include "aps.h"
#include "aps_frame.h"
#include "aps_helpers.h"
#include "loopback_radio.h"
#include "mac.h"
#include "nwk.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

/* A data frame with short addressing at both ends and one PAN field (9 octets), carrying a minimal NWK data
   header (8 octets, Figure 3-5 with nwkcProtocolVersion 0x02): past these the APDU begins. Every frame this
   suite captures is that shape, because 3.6.4.3 pins both address modes and both PAN fields of a Zigbee data
   frame, and none of these cases asks for NWK security. */
#define NPDU_OFFSET 9
#define FCS_OCTETS 2
#define APDU_OFFSET (NPDU_OFFSET + NWK_MIN_HEADER_OVERHEAD)

/* The band-A device under the service, configured with the identity the network layer reads about itself. The
   build is `Test_BandABuild`'s, one layer down and unchanged from nwk/ in test/'s rig: the same PIB bits, the same
   router device type, because a case that changed them would be testing a different module. What stays here is
   this suite's reading of what the build produced. */
static void stackAt(Test_BandA *stack, uint16_t own)
{
    Test_BandAConfig cfg;
    ZbStatus status;

    Test_BandADefaults(&cfg);
    cfg.ownAddress = own;
    cfg.ownExtended = OWN_IEEE;
    cfg.panId = PAN_ID;

    status = Test_BandABuild(stack, &cfg);

    Test_ExpectStatus(status, ZB_OK, "the network layer is given a MAC that already has its backend");
    Test_Expect(Mac_Pib(&stack->mac)->shortAddress == own && Mac_Pib(&stack->mac)->rxOnWhenIdle == 1,
           "whose PIB mirror carries this device's address and receiver duty");
    Test_Expect(stack->nwk.mac == &stack->mac, "and the network layer adopts the MAC by pointer");
}

/* The device under test: that stack, and the APS service that adopts it. `Aps_Init` has no configuration to
   take (the module doc says why), so the rig has none to pass either. */
void rigBuild(Rig *rig, uint16_t own)
{
    stackAt(&rig->stack, own);

    Test_ExpectStatus(Aps_Init(&rig->aps, &rig->stack.nwk), ZB_OK, "the APS service adopts the network layer by pointer, as `nwk` adopts `mac` (the same lineage)");
    Test_Expect(rig->aps.nwk == &rig->stack.nwk, "adopted and not copied: the layer below is still its owner's to re-arm");
    Test_Expect(rig->aps.apsCounter == APS_COUNTER_START, "and its APS counter starts where the module names its deterministic start");
    Test_Expect(Aps_TransmitQueue(&rig->aps) == 0 && Aps_ConfirmQueue(&rig->aps) == 0, "with both pools empty");
}

/* A peer stack, without an APS service on it: see the suite note in `aps_cases.h` on why an acknowledgement
   can only be composed by the codec and carried by the peer's own network layer. A rig is a constructor, so
   nothing is asserted here: a peer that could not be built leaves a case with no frames to read, which is what
   that case then reports. */
void peerBuild(Test_BandA *peer, uint16_t own)
{
    Test_BandAConfig cfg;

    Test_BandADefaults(&cfg);
    cfg.ownAddress = own;
    cfg.ownExtended = OWN_IEEE;
    cfg.panId = PAN_ID;

    (void)Test_BandABuild(peer, &cfg);
}

/* The one way this suite gives a unicast destination a route: a neighbor entry put in by hand, exactly as
   nwk/ in test/ seeds them. What band A observes for itself is an address; a device type comes from association,
   which is deferred, and 3.6.4.3 relays on an ACTIVE route or a known neighbor and on nothing else. */
void seedNeighbor(Nwk_Nwk *nwk, uint16_t addr)
{
    uint32_t before = Nwk_NeighborQueue(nwk);

    Test_BandASeedNeighbor(nwk, addr, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    Test_Expect(Nwk_NeighborQueue(nwk) == before + 1, "the neighbor table has room for the entry the suite seeds");
}

Nwk_DataRequestParameters nldeReq(uint16_t dst, const uint8_t *what, uint32_t len)
{
    Nwk_DataRequestParameters req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.dstAddr = dst;
    req.nsdu = what;
    req.nsduLength = len;
    req.radius = 0;

    return req;
}

/* Table 2-2's parameters, filled the way a caller of this SAP fills them. `txOptions` is the raw bitmap the
   table prints, and everything the case does not name is zero: radiusCounter 0 is the network default the layer below
   derives (3.2.1.1.3), `nwkBroadcastAddress` 0 is the module's named group default. */
Aps_ApsdeReq sapReq(uint32_t dstAddrMode, uint16_t dstAddress, uint8_t dstEndpoint, uint16_t clusterId,
                          const uint8_t *asdu, uint32_t asduLength, uint32_t txOptions)
{
    Aps_ApsdeReq req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.dstAddrMode = dstAddrMode;
    req.dstAddress = dstAddress;
    req.dstEndpoint = dstEndpoint;
    req.profileId = PROFILE_ID;
    req.clusterId = clusterId;
    req.srcEndpoint = SRC_EP;
    req.asdu = asdu;
    req.asduLength = asduLength;
    req.txOptions = txOptions;

    return req;
}

void scriptOutcomes(Loopback_Radio *model, uint32_t count, int answered)
{
    Loopback_Outcome outcomes[LOOPBACK_TX_MAX];
    uint32_t i;

    Zb_memset(outcomes, 0, (uint32_t)sizeof outcomes);

    for (i = 0; i < count; i++)
    {
        outcomes[i].status = answered ? ZB_OK : ZB_ERR_DEVICE;
        outcomes[i].isAcked = answered ? 1 : 0;
    }

    LoopbackRadio_ScriptOutcomes(model, outcomes, count);
}

void harvestAir(Loopback_Radio *model, Air *log, uint32_t *count)
{
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    uint32_t got;
    uint32_t i;
    uint32_t j;

    got = LoopbackRadio_Sent(model, sent, LOOPBACK_TX_MAX);

    for (i = 0; i < got; i++)
    {
        for (j = 0; j < *count; j++)
        {
            if (log[j].len == sent[i].len && log[j].ackRequest == sent[i].ackRequest
                && Zb_memcmp(log[j].bytes, sent[i].bytes, sent[i].len) == 0)
                break;
        }

        if (j < *count)
            continue;

        Test_Expect(*count < AIR_LOG_MAX, "the suite's own air log has room for what this case puts on the air");

        if (*count >= AIR_LOG_MAX)
            return;

        log[*count].len = sent[i].len;
        log[*count].ackRequest = sent[i].ackRequest;
        Zb_memcpy(log[*count].bytes, sent[i].bytes, sent[i].len);
        (*count)++;
    }
}

uint16_t fcfOf(const Air *air)
{
    return (uint16_t)(air->bytes[0] | (air->bytes[1] << 8));
}

uint16_t airDestOf(const Air *air)
{
    return (uint16_t)(air->bytes[5] | (air->bytes[6] << 8));
}

const uint8_t *npduOf(const Air *air)
{
    return air->bytes + NPDU_OFFSET;
}

static uint32_t npduLenOf(const Air *air)
{
    if (air->len < NPDU_OFFSET + FCS_OCTETS)
        return 0;

    return air->len - NPDU_OFFSET - FCS_OCTETS;
}

const uint8_t *apduOf(const Air *air)
{
    return air->bytes + APDU_OFFSET;
}

uint32_t apduLenOf(const Air *air)
{
    if (npduLenOf(air) < NWK_MIN_HEADER_OVERHEAD)
        return 0;

    return npduLenOf(air) - NWK_MIN_HEADER_OVERHEAD;
}

/* The NWK sequence number of a captured frame: octet 7 of the minimal header, the half of the identity 3.3.1.5
   gives a frame. Four retransmissions of one APDU are four frames, and this is the field that says so. */
uint8_t nwkSeqOf(const Air *air)
{
    return npduOf(air)[7];
}

/* The data-header shape this module composes, spelled out here so a case can compare the octets on the air
   against a composition the service did not make: the delivery mode derived from the request, a destination
   endpoint for unicast and broadcast and none for group, the group address for group alone, and cluster,
   profile, source endpoint and counter for every data frame (2.2.5.1.2 … 2.2.5.1.7, 2.2.8.4.1). */
void dataHeader(Aps_Frame *frame, uint32_t deliveryMode, int ackRequest, uint8_t apsCounter,
                       uint8_t dstEndpoint, uint16_t clusterId)
{
    Zb_memset(frame, 0, (uint32_t)sizeof *frame);

    frame->frameType = APS_FRAME_TYPE_DATA;
    frame->deliveryMode = deliveryMode;
    frame->ackRequest = ackRequest;

    frame->dstEndpointPresent = deliveryMode == APS_DELIVERY_GROUP ? 0 : 1;
    frame->dstEndpoint = dstEndpoint;

    frame->groupAddressPresent = deliveryMode == APS_DELIVERY_GROUP ? 1 : 0;
    frame->groupAddress = GROUP_ID;

    frame->clusterPresent = 1;
    frame->clusterId = clusterId;
    frame->profilePresent = 1;
    frame->profileId = PROFILE_ID;
    frame->srcEndpointPresent = 1;
    frame->srcEndpoint = SRC_EP;
    frame->apsCounter = apsCounter;
}

/* An acknowledgement APDU, composed by the codec and nothing else: Figure 2-9's ACK format 0
   field set with 2.2.5.2.3.1's endpoint swap (its source endpoint is the destination endpoint of the frame it
   answers, its destination endpoint that frame's source endpoint), its ACK request sub-field 0 (2.2.8.4.3) and
   the cluster, profile and counter of the frame it answers. */
uint32_t ackApdu(uint8_t *out, uint8_t apsCounter, uint8_t srcEndpoint, uint8_t dstEndpoint,
                        uint16_t clusterId)
{
    Aps_Frame frame;
    uint32_t len;
    uint32_t payloadOffset;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = APS_FRAME_TYPE_ACK;
    frame.deliveryMode = APS_DELIVERY_UNICAST;
    frame.ackFormat = 0;
    frame.ackRequest = 0;
    frame.dstEndpointPresent = 1;
    frame.dstEndpoint = dstEndpoint;
    frame.clusterPresent = 1;
    frame.clusterId = clusterId;
    frame.profilePresent = 1;
    frame.profileId = PROFILE_ID;
    frame.srcEndpointPresent = 1;
    frame.srcEndpoint = srcEndpoint;
    frame.apsCounter = apsCounter;

    Test_ExpectStatus(ApsFrame_Compose(&frame, 0, 0, out, APS_FRAME_MAX, &len, &payloadOffset), ZB_OK,
                  "the acknowledgement is a frame this stack's own codec composes (2.2.5.2.3.1, Figure 2-9)");
    Test_Expect(len == ApsFrame_HeaderLen(&frame) && len == APS_HEADER_UNICAST_FORM,
           "and it is the eight-octet ACK format 0 form: the same six columns a data unicast header carries (Figure 2-9, 2.2.5.2.3.1)");

    return len;
}

/* Hand the newest frame one stack put on its side of the seam to another stack's doorstep, as the frame it is:
   the octets the peer's MAC closed with a footer of its own, injected with the trailer band A reads. The peer
   is never stepped, so every one of its transmits is still outstanding and the newest is the one with the
   largest handle the backend handed it. */
void handOver(Loopback_Radio *from, Loopback_Radio *to)
{
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Loopback_FrameSpec spec;
    uint32_t got;
    uint32_t newest;
    uint32_t i;

    got = LoopbackRadio_Sent(from, sent, LOOPBACK_TX_MAX);
    Test_Expect(got > 0, "the peer put a frame on its own side of the seam");

    if (got == 0)
        return;

    newest = 0;

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
    spec.error = ZB_OK;

    Test_ExpectStatus(LoopbackRadio_Inject(to, &spec, 1), ZB_OK,
                  "and it arrives in front of the target's MAC, which is what a neighbor's frame is");
}

/* Send an APDU down a peer's own network layer and deliver the frame it became to `to`. The peer addresses it
   as a unicast to `dst`, which is the only way the network layer below hands an APS frame over at all
   (2.2.8.4.1: "All frames handled by or generated within the APS sub-layer SHALL be constructed according to
   the general frame format … and transmitted using the NWK layer data service"). */
void peerSends(Test_BandA *peer, Loopback_Radio *to, uint16_t dst, const uint8_t *apdu,
                      uint32_t apduLen, uint32_t nowMs)
{
    Nwk_DataRequestParameters req = nldeReq(dst, apdu, apduLen);

    Test_ExpectStatus(Nwk_DataRequest(&peer->nwk, &req, nowMs), ZB_OK, "the peer issues it through its own NLDE");
    handOver(&peer->model, to);
}

/* One turn of the device under test, with the air it produced. */
/* Deliver an APDU down a peer's own network layer, hand the frame it became to `to`, then run the peer's own turn
   and take what that turn answered. Two parts and not one, because the peer has no APS layer of its own in the
   cases that use it: its NLDE confirmations have no consumer, and `nwk`'s door counts what is sitting in its
   confirmation ring, so a suite that handed frames over without draining the peer would be refused for a reason
   that is about this rig and not about the module under test. */
void peerDelivers(Test_BandA *peer, Loopback_Radio *to, uint16_t dst, const uint8_t *apdu,
                         uint32_t apduLen, uint32_t nowMs)
{
    Nwk_DataConfirmParameters confirms[NWK_CONFIRM_MAX];

    peerSends(peer, to, dst, apdu, apduLen, nowMs);

    Test_ExpectStatus(Test_NwkStep(&peer->nwk, nowMs), ZB_OK, "and the peer is stepped, so the answer to the frame it sent is collected before the next frame is asked of it");
    Test_Expect(Nwk_PollConfirms(&peer->nwk, confirms, NWK_CONFIRM_MAX) == 1,
          "and taken: a peer modelled without an APS layer has nobody to read its confirmations, and a ring full of them is a ring that refuses the next request");
}

/* Compose an APDU through the codec and nothing else: the case names the fields and the codec
   writes the octets, which is what keeps a case from being able to tell a module's composition and its own. */
uint32_t composeApdu(const Aps_Frame *frame, const uint8_t *asdu, uint32_t asduLength, uint8_t *out)
{
    uint32_t len;
    uint32_t payloadOffset;

    Test_ExpectStatus(ApsFrame_Compose(frame, asdu, asduLength, out, APS_FRAME_MAX, &len, &payloadOffset), ZB_OK,
                  "the frame this case hands down is written by `aps_frame`, the only module in this stack that writes an APDU");

    return len;
}

/* One turn of the device under test, with the air it produced. */
void stepAt(Rig *rig, Air *air, uint32_t *airCount, uint32_t nowMs)
{
    Test_ExpectStatus(Aps_Step(&rig->aps, nowMs), ZB_OK, "the module's turn runs the layer below first and then its own three passes (2.2.4.1.1.3)");
    harvestAir(&rig->stack.model, air, airCount);
}
