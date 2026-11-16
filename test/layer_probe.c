/* Differential behaviour probe (docs/internals/testing.md §5): drives band A over loopback_radio through
   the public façade API and prints every frame the device puts on the air plus every counter, so a build of
   a reference revision and a build of the working tree can be compared line for line. Run it through
   test/refactor_gate.py --probe; it is not a ctest entry and it asserts nothing by itself. */

#include <stdio.h>

#include "aps.h"
#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "nwk.h"
#include "nwk_frame.h"
#include "rig_band_a.h"
#include "security.h"
#include "zb_utils.h"
#include "zb_layers.h"

#define OWN 0xdead
#define PAN 0xbeef
#define PROBE_CHANNEL 26
#define SLEEPY_A 0x1357
#define SLEEPY_B 0x2468
#define SLEEPY_SRC 0x3579
#define KNOWN_NEIGHBOR 0x4680
#define UNSEEN 0x9999
#define OFFENDER 0x1111
#define OWN_IEEE 0x0123456789abcdef
#define SLEEPY_IEEE 0x0000000000001357
#define OFFENDER_IEEE 0x1111111111111111
#define NEIGHBOR_IEEE 0x0000000000004680
#define APS_GROUP_ID 0x1234
#define APS_GROUP_ENDPOINT 0x03
#define APS_SRC_ENDPOINT 0x01
#define APS_DST_ENDPOINT 0x02
#define APS_PROFILE_ID 0x0104
#define APS_CLUSTER_ID 0x0006

static uint32_t s_injectDsn;

static const uint8_t s_key[SECURITY_KEY_OCTETS] = {
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};

static const uint8_t s_nsdu[6] = { 0x7a, 0x6e, 0x6b, 0x20, 0x70, 0x61 };

static void seedNeighbor(Nwk_Nwk *nwk, uint16_t addr, uint64_t ieee, int ieeeKnown, uint32_t deviceType,
                         int rxOnWhenIdle, uint32_t relationship)
{
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!nwk->neighbors[i].inUse)
            break;
    }

    nwk->neighbors[i].inUse = 1;
    nwk->neighbors[i].networkAddress = addr;
    nwk->neighbors[i].extendedAddress = ieee;
    nwk->neighbors[i].ieeeKnown = ieeeKnown;
    nwk->neighbors[i].deviceType = deviceType;
    nwk->neighbors[i].rxOnWhenIdle = rxOnWhenIdle;
    nwk->neighbors[i].relationship = relationship;
}

static void seedTable(Nwk_Nwk *nwk)
{
    seedNeighbor(nwk, SLEEPY_A, SLEEPY_IEEE, 1, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(nwk, SLEEPY_B, 0, 0, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(nwk, SLEEPY_SRC, 0, 0, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(nwk, KNOWN_NEIGHBOR, 0, 0, NWK_DEVICE_ROUTER, 1, NWK_REL_NONE);
}

static void secSeed(Security *sec, uint32_t outgoingCounter, int authenticated)
{
    Security_KeyDescriptor key;
    Security_Config cfg;

    Zb_memset(&key, 0, (uint32_t)sizeof key);
    key.keySeqNumber = 0x00;
    key.inUse = 1;
    key.outgoingFrameCounter = outgoingCounter;
    Zb_memcpy(key.key, s_key, SECURITY_KEY_OCTETS);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = OWN_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.nwkActiveKeySeqNumber = 0x00;
    cfg.authenticated = authenticated;
    cfg.nwkAllFresh = 1;
    cfg.keys = &key;
    cfg.keyCount = 1;

    Security_Init(sec, &cfg);
}

/* The probe's device: the model backend, the façade over it, and the identity the probe's scenes were always
   given, short address `OWN` on PAN `PAN` on the channel every band-A rig in this tree arms. Built by
   `Zb_LayersInit` and driven silently: a probe asserts nothing, so the status the constructor answers is dropped
   rather than examined, the frames and the counters it prints are the whole of its claim. What is this file's own
   is the table the scenes need seeded and the two `Security` fixtures the crossing is armed from. */
typedef struct ProbeDev
{
    Loopback_Radio model;
    Zb_Layers stack;
} ProbeDev;

static void rigAt(ProbeDev *dev, uint32_t deviceType, int rxOnWhenIdle, Security *sec, uint32_t counterSeed)
{
    Radio_Caps caps;
    Zb_LayersConfig cfg;

    Test_BandACapsAcks(&caps);
    LoopbackRadio_Init(&dev->model, &caps);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.present = RADIO_PIB_CHANNEL | RADIO_PIB_PAN_ID | RADIO_PIB_SHORT_ADDRESS | RADIO_PIB_RX_ON_WHEN_IDLE;
    cfg.channel = PROBE_CHANNEL;
    cfg.panId = PAN;
    cfg.shortAddress = OWN;
    cfg.rxOnWhenIdle = rxOnWhenIdle;
    cfg.deviceType = deviceType;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_NONE;

    (void)Zb_LayersInit(&dev->stack, LoopbackRadio_Seam(&dev->model), &cfg);

    if (sec != 0)
    {
        secSeed(sec, counterSeed, 1);
        Nwk_AttachSecurity(Zb_LayersNwk(&dev->stack), sec);
    }

    seedTable(Zb_LayersNwk(&dev->stack));
}

static void dump(Loopback_Radio *model, Nwk_Nwk *nwk, const char *tag)
{
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    uint32_t got;
    uint32_t i;
    uint32_t j;

    got = LoopbackRadio_Sent(model, sent, LOOPBACK_TX_MAX);

    for (i = 0; i < got; i++)
    {
        printf("%s air #%u len=%u ack=%u dest=%04x npdu:", tag, i, sent[i].len, (uint32_t)sent[i].ackRequest,
               (uint32_t)(sent[i].bytes[5] | (sent[i].bytes[6] << 8)));

        for (j = 9; j + 2 <= sent[i].len; j++)
            printf("%02x", sent[i].bytes[j]);

        printf("\n");
    }

    printf("%s counters refused=%u noRoute=%u ignored=%u malformed=%u unsupported=%u duplicate=%u notForMe=%u"
           " indications=%u bttFull=%u relays=%u recognized=%u replies=%u neighborsRefused=%u rxSec=%u"
           " rxCtr=%u unsecured=%u txSec=%u other=%u seq=%u\n",
           tag, Nwk_RefusedRequests(nwk), Nwk_DroppedNoRoute(nwk), Nwk_ConfirmsIgnored(nwk),
           Nwk_DroppedMalformed(nwk), Nwk_DroppedUnsupported(nwk), Nwk_DroppedDuplicate(nwk),
           Nwk_DroppedNotForMe(nwk), Nwk_DroppedIndications(nwk), Nwk_BttFullDrops(nwk),
           Nwk_RelaysSent(nwk), Nwk_RecognizedCommands(nwk), Nwk_ReplyCommands(nwk),
           Nwk_NeighborAddsRefused(nwk), Nwk_RxSecurityFailures(nwk), Nwk_RxFrameCounterRejects(nwk),
           Nwk_DroppedUnsecured(nwk), Nwk_TxSecurityFailures(nwk), Nwk_CarrierOther(nwk), nwk->seq);
}

static void script(Loopback_Radio *model, uint32_t count, int answered)
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

static void injectNpdu(Loopback_Radio *model, const uint8_t *npdu, uint32_t npduLen, uint16_t macSrc,
                       uint16_t macDst)
{
    Mac_Frame frame;
    Loopback_FrameSpec spec;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t len;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_DATA;
    frame.frameVersion = 0;
    frame.ackRequest = macDst >= NWK_ADDR_LOW_POWER_ROUTERS ? 0 : 1;
    frame.panIdCompression = 1;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.destPan = PAN;
    frame.srcPan = PAN;
    frame.destShort = macDst;
    frame.srcShort = macSrc;
    frame.seq = (uint8_t)(s_injectDsn % 256);
    s_injectDsn = s_injectDsn + 1;

    MacFrame_Compose(&frame, npdu, npduLen, bytes, RADIO_MPDU_MAX, &len);
    MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len);

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = len;
    spec.bytes = bytes;
    spec.rssiDbm = -70;
    spec.lqi = 200;
    spec.stampTicks = 1;

    LoopbackRadio_Inject(model, &spec, 1);
}

static void injectPoll(Loopback_Radio *model, uint16_t src)
{
    Mac_Frame frame;
    Loopback_FrameSpec spec;
    const uint8_t content[1] = { MAC_CMD_POLL };
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t len;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 1;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.destPan = PAN;
    frame.srcPan = PAN;
    frame.destShort = OWN;
    frame.srcShort = src;
    frame.seq = (uint8_t)(s_injectDsn % 256);
    s_injectDsn = s_injectDsn + 1;

    MacFrame_Compose(&frame, content, (uint32_t)sizeof content, bytes, RADIO_MPDU_MAX, &len);
    MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len);

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = len;
    spec.bytes = bytes;
    spec.rssiDbm = -70;
    spec.lqi = 200;
    spec.stampTicks = 1;

    LoopbackRadio_Inject(model, &spec, 1);
}

static uint32_t composeNpdu(uint8_t *out, uint16_t dst, uint16_t src, uint8_t radius, uint8_t seq,
                            uint32_t frameType, const uint8_t *payload, uint32_t payloadLen)
{
    Nwk_Frame frame;
    uint32_t len;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = (int)frameType;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.discoverRoute = NWK_DISCOVER_SUPPRESS;
    frame.destAddr = dst;
    frame.srcAddr = src;
    frame.radius = radius;
    frame.sequenceNumber = seq;

    NwkFrame_Compose(&frame, payload, payloadLen, out, RADIO_MPDU_MAX, &len);

    return len;
}

static uint32_t secureNpdu(Security *sender, uint8_t *out, uint16_t dst, uint16_t src, uint8_t radius,
                           uint8_t seq, uint32_t frameType, const uint8_t *payload, uint32_t payloadLen)
{
    Nwk_Frame frame;
    uint8_t plain[NWK_FRAME_NPDU_MAX];
    uint32_t plainLen;
    uint32_t outLen;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = (int)frameType;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.discoverRoute = NWK_DISCOVER_SUPPRESS;
    frame.destAddr = dst;
    frame.srcAddr = src;
    frame.radius = radius;
    frame.sequenceNumber = seq;
    frame.securityEnabled = 1;

    NwkFrame_Compose(&frame, payload, payloadLen, plain, (uint32_t)sizeof plain, &plainLen);
    Security_Protect(sender, plain, NwkFrame_HeaderLen(&frame), plain + NwkFrame_HeaderLen(&frame),
                     plainLen - NwkFrame_HeaderLen(&frame), out, RADIO_MPDU_MAX, &outLen);

    return outLen;
}

static void run(const char *label, int secured, uint32_t counterSeed)
{
    ProbeDev dev;
    Nwk_Nwk *nwk;
    Security sec;
    Nwk_DataConfirmParameters confirms[8];
    Nwk_DataIndicationParameters indications[8];
    Nwk_DataRequestParameters req;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint8_t payload[4];
    uint32_t len;
    uint32_t i;

    printf("=== %s ===\n", label);

    rigAt(&dev, NWK_DEVICE_ROUTER, 1, secured ? &sec : 0, counterSeed);

    nwk = Zb_LayersNwk(&dev.stack);

    /* 1. a broadcast this device originates: the air frame and the copies the sleepy children are owed */
    script(&dev.model, 8, 1);
    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.dstAddr = NWK_ADDR_ALL_DEVICES;
    req.nsdu = s_nsdu;
    req.nsduLength = (uint32_t)sizeof s_nsdu;
    req.radius = 0;
    req.securityEnable = secured;
    printf("request -> %u\n", (uint32_t)Nwk_DataRequest(nwk, &req, 100));
    dump(&dev.model, nwk, "bcast");

    injectPoll(&dev.model, SLEEPY_A);
    Test_NwkStep(nwk, 200);
    dump(&dev.model, nwk, "pollA");

    injectPoll(&dev.model, SLEEPY_B);
    Test_NwkStep(nwk, 300);
    dump(&dev.model, nwk, "pollB");

    Nwk_PollConfirms(nwk, confirms, 8);
    Test_NwkPoll(nwk, indications, 8);

    /* 2. a unicast with no path */
    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.dstAddr = UNSEEN;
    req.nsdu = s_nsdu;
    req.nsduLength = (uint32_t)sizeof s_nsdu;
    req.radius = 4;
    req.securityEnable = secured;
    printf("noRoute request -> %u\n", (uint32_t)Nwk_DataRequest(nwk, &req, 400));
    dump(&dev.model, nwk, "noroute");
    Nwk_PollConfirms(nwk, confirms, 8);

    /* 3. somebody else's broadcast: record, relay, and the copies of the relayed frame */
    len = composeNpdu(npdu, NWK_ADDR_ALL_DEVICES, OFFENDER, 8, 7, NWK_FRAME_TYPE_DATA, s_nsdu,
                      (uint32_t)sizeof s_nsdu);
    injectNpdu(&dev.model, npdu, len, OFFENDER, OWN);
    Test_NwkStep(nwk, 500);
    dump(&dev.model, nwk, "rxbcast");

    injectPoll(&dev.model, SLEEPY_A);
    Test_NwkStep(nwk, 600);
    dump(&dev.model, nwk, "rxpollA");

    injectPoll(&dev.model, SLEEPY_SRC);
    Test_NwkStep(nwk, 700);
    dump(&dev.model, nwk, "rxpollSrc");

    Nwk_PollConfirms(nwk, confirms, 8);
    Test_NwkPoll(nwk, indications, 8);

    /* 4. the retransmissions the record schedules */
    Test_NwkStep(nwk, 1500);
    Test_NwkStep(nwk, 2100);
    Test_NwkStep(nwk, 2700);
    dump(&dev.model, nwk, "due");

    for (i = 0; i < 4; i++)
        injectPoll(&dev.model, i == 0 ? SLEEPY_A : (i == 1 ? SLEEPY_B : KNOWN_NEIGHBOR));

    Test_NwkStep(nwk, 2800);
    dump(&dev.model, nwk, "duePolls");

    Nwk_PollConfirms(nwk, confirms, 8);
    Test_NwkPoll(nwk, indications, 8);

    /* 5. the 3.6.13 answer, from a neighbor this device knows and from one it does not */
    payload[0] = 0x10;
    len = composeNpdu(npdu, OWN, OFFENDER, 5, 9, NWK_FRAME_TYPE_COMMAND, payload, 1);
    injectNpdu(&dev.model, npdu, len, OFFENDER, OWN);
    Test_NwkStep(nwk, 2900);
    dump(&dev.model, nwk, "replyKnown");

    payload[0] = 0x11;
    len = composeNpdu(npdu, OWN, KNOWN_NEIGHBOR, 5, 10, NWK_FRAME_TYPE_COMMAND, payload, 1);
    injectNpdu(&dev.model, npdu, len, KNOWN_NEIGHBOR, OWN);
    Test_NwkStep(nwk, 3000);
    dump(&dev.model, nwk, "replyNeighbor");

    payload[0] = 0x12;
    len = composeNpdu(npdu, OWN, UNSEEN, 5, 11, NWK_FRAME_TYPE_COMMAND, payload, 1);
    injectNpdu(&dev.model, npdu, len, UNSEEN, OWN);
    Test_NwkStep(nwk, 3100);
    dump(&dev.model, nwk, "replyNoRoute");

    /* 6. a recognized identifier, and an identifier on a broadcast (never answered) */
    payload[0] = NWK_CMD_ROUTE_REQUEST;
    len = composeNpdu(npdu, OWN, OFFENDER, 5, 12, NWK_FRAME_TYPE_COMMAND, payload, 1);
    injectNpdu(&dev.model, npdu, len, OFFENDER, OWN);
    Test_NwkStep(nwk, 3200);
    dump(&dev.model, nwk, "recognized");

    payload[0] = NWK_CMD_LINK_STATUS;
    len = composeNpdu(npdu, NWK_ADDR_ALL_DEVICES, OFFENDER, 5, 13, NWK_FRAME_TYPE_COMMAND, payload, 1);
    injectNpdu(&dev.model, npdu, len, OFFENDER, OWN);
    Test_NwkStep(nwk, 3300);
    dump(&dev.model, nwk, "broadcastCommand");

    /* 7. an offender this device knows the extended address of, and a secured unknown command */
    payload[0] = 0x14;
    len = composeNpdu(npdu, OWN, SLEEPY_A, 5, 14, NWK_FRAME_TYPE_COMMAND, payload, 1);
    injectNpdu(&dev.model, npdu, len, SLEEPY_A, OWN);
    Test_NwkStep(nwk, 3400);
    dump(&dev.model, nwk, "replyIeee");

    if (secured)
    {
        Security sender;
        const uint8_t offending[1] = { 0x15 };

        secSeed(&sender, 0x5000, 1);
        len = secureNpdu(&sender, npdu, OWN, OFFENDER, 5, 15, NWK_FRAME_TYPE_COMMAND, offending, 1);
        injectNpdu(&dev.model, npdu, len, OFFENDER, OWN);
        Test_NwkStep(nwk, 3500);
        dump(&dev.model, nwk, "securedReply");
    }

    Nwk_PollConfirms(nwk, confirms, 8);

    {
        uint32_t took = Test_NwkPoll(nwk, indications, 8);

        for (i = 0; i < took; i++)
            printf("indication dst=%04x src=%04x seq=%u radius=%u type=%u cmd=%02x len=%u wasBroadcast=%u"
                   " sec=%u lqi=%u\n",
                   indications[i].dstAddr, indications[i].srcAddr, indications[i].seq,
                   indications[i].radiusRemaining, indications[i].frameType, indications[i].commandIdentifier,
                   indications[i].nsduLength, (uint32_t)indications[i].wasBroadcast,
                   (uint32_t)indications[i].securityUsed, indications[i].lqi);
    }

    printf("pools tx=%u neighbor=%u route=%u btt=%u confirm=%u indication=%u\n", Nwk_TransmitQueue(nwk),
           Nwk_NeighborQueue(nwk), Nwk_RouteQueue(nwk), Nwk_BttQueue(nwk), Nwk_ConfirmQueue(nwk),
           Nwk_IndicationQueue(nwk));

}

/* --- the aps leg -------------------------------------------------------------------------------
 *
 * Chapter 2 on top of the same rig: the APS service adopting the secured network layer, the application's
 * `Security` with the one `apsDeviceKeyPairSet` entry the crossing needs attached to it, and a group membership
 * seeded by hand. Two unicast Data Requests go down (one unsecured and acknowledged at a neighbor the layer
 * below has a path to, one secured at the 16-bit alias that entry names) and then the acknowledgement waits of
 * 2.2.8.4.4 run out their retransmissions. What is printed is the air the device puts down through the layer
 * below, in `dump`'s own shape, and every counter the service keeps. */

static Security_KeyPairEntry apsPairAt(uint64_t partner, uint16_t alias)
{
    Security_KeyPairEntry entry;

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.deviceIeee = partner;
    entry.shortAddress = alias;
    entry.shortKnown = 1;
    entry.keyAttributes = SECURITY_KEYPAIR_ATTR_VERIFIED;
    entry.outgoingFrameCounter = 4;
    entry.incomingFrameCounter = 1;
    entry.linkKeyType = SECURITY_LINK_KEY_UNIQUE;
    entry.featuresCapabilities = SECURITY_FEATURES_NONE;
    entry.verifiedFrameCounter = 1;
    Zb_memcpy(entry.key, s_key, SECURITY_KEY_OCTETS);

    return entry;
}

/* The crossing's material as an application seeds it: the descriptor 4.4.1.1 step 3 borrows
   a level from, and the pairs it reads. The `nwk` underneath keeps its own `Security`, which is what the probe
   already arms the retransmission scenes with. */
static void apsSecSeed(Security *sec, const Security_KeyPairEntry *pairs, uint32_t pairCount)
{
    Security_KeyDescriptor key;
    Security_Config cfg;

    Zb_memset(&key, 0, (uint32_t)sizeof key);
    key.keySeqNumber = 0x00;
    key.inUse = 1;
    key.outgoingFrameCounter = 1;
    Zb_memcpy(key.key, s_key, SECURITY_KEY_OCTETS);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = OWN_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.nwkActiveKeySeqNumber = 0x00;
    cfg.authenticated = 1;
    cfg.nwkAllFresh = 1;
    cfg.keys = &key;
    cfg.keyCount = 1;
    cfg.keyPairs = pairs;
    cfg.keyPairCount = pairCount;

    Security_Init(sec, &cfg);
}

static Aps_ApsdeReq apsReqAt(uint32_t dstAddrMode, uint16_t dstAddress, uint32_t txOptions)
{
    Aps_ApsdeReq req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.dstAddrMode = dstAddrMode;
    req.dstAddress = dstAddress;
    req.dstEndpoint = APS_DST_ENDPOINT;
    req.profileId = APS_PROFILE_ID;
    req.clusterId = APS_CLUSTER_ID;
    req.srcEndpoint = APS_SRC_ENDPOINT;
    req.asdu = s_nsdu;
    req.asduLength = (uint32_t)sizeof s_nsdu;
    req.txOptions = txOptions;

    return req;
}

static void dumpAps(Loopback_Radio *model, const Aps_Aps *aps, const char *tag)
{
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    uint32_t got;
    uint32_t i;
    uint32_t j;

    got = LoopbackRadio_Sent(model, sent, LOOPBACK_TX_MAX);

    for (i = 0; i < got; i++)
    {
        printf("%s air #%u len=%u ack=%u dest=%04x npdu:", tag, i, sent[i].len, (uint32_t)sent[i].ackRequest,
               (uint32_t)(sent[i].bytes[5] | (sent[i].bytes[6] << 8)));

        for (j = 9; j + 2 <= sent[i].len; j++)
            printf("%02x", sent[i].bytes[j]);

        printf("\n");
    }

    printf("%s apsCounters refused=%u unmatched=%u ignored=%u retransmitRefusals=%u rxShape=%u rxMalformed=%u"
           " rxSecuredDeferred=%u rxCommandDeferred=%u rxDuplicate=%u groupMiss=%u acksGenerated=%u"
           " acksRefused=%u droppedIndications=%u groupRefusals=%u txNoKeyPair=%u txSecuredFailures=%u"
           " rxSecuredAuth=%u rxSecuredCounters=%u txQueue=%u confirmQueue=%u indicationQueue=%u groupQueue=%u"
           " counter=%u\n",
           tag, Aps_RefusedRequests(aps), Aps_UnmatchedAcks(aps), Aps_ConfirmationsIgnored(aps),
           Aps_RetransmitRefusals(aps), Aps_RxShapeRefused(aps), Aps_RxMalformed(aps),
           Aps_RxSecuredDeferred(aps), Aps_RxCommandDeferred(aps), Aps_RxDuplicateDrops(aps),
           Aps_DroppedGroupMiss(aps), Aps_AcksGenerated(aps), Aps_AcksRefused(aps),
           Aps_DroppedIndications(aps), Aps_GroupRefusals(aps), Aps_TxNoKeyPair(aps),
           Aps_TxSecuredFailures(aps), Aps_RxSecuredFailuresAuth(aps),
           Aps_RxSecuredFailuresCounters(aps), Aps_TransmitQueue(aps), Aps_ConfirmQueue(aps),
           Aps_IndicationQueue(aps), Aps_GroupQueue(aps), aps->apsCounter);
}

static void runAps(void)
{
    ProbeDev dev;
    Security nwkSec;
    Security apsSec;
    Security_KeyPairEntry pairs[1];
    Aps_Aps *aps;
    Aps_ApsdeReq req;
    Aps_Confirm confirms[8];
    Aps_Indication indications[8];
    uint32_t took;
    uint32_t i;

    printf("=== aps coordinator ===\n");

    rigAt(&dev, NWK_DEVICE_COORDINATOR, 1, &nwkSec, 0x1000);

    aps = Zb_LayersAps(&dev.stack);

    pairs[0] = apsPairAt(NEIGHBOR_IEEE, KNOWN_NEIGHBOR);
    apsSecSeed(&apsSec, pairs, 1);

    Aps_AttachSecurity(aps, &apsSec);

    printf("aps group add -> %u\n", Aps_AddGroup(aps, APS_GROUP_ID, APS_GROUP_ENDPOINT));

    script(&dev.model, 8, 1);

    /* 1. an acknowledged unicast at a neighbor the layer below has a path to, and the wait its NLDE answer arms */
    req = apsReqAt(APS_ADDR_MODE_SHORT, KNOWN_NEIGHBOR, APS_TX_OPTION_ACK);
    printf("aps unsecured request -> %u\n", (uint32_t)Aps_DataRequest(aps, &req, 100));
    dumpAps(&dev.model, aps, "apsSend");

    /* 2. a secured unicast at the alias one key pair names: TxOptions 0x01, so the APSDU is the protected frame */
    req = apsReqAt(APS_ADDR_MODE_SHORT, KNOWN_NEIGHBOR, APS_TX_OPTION_SECURITY);
    printf("aps secured request -> %u\n", (uint32_t)Aps_DataRequest(aps, &req, 120));
    dumpAps(&dev.model, aps, "apsSecured");

    /* 3. the drain that arms `apscAckWaitDuration`, then the retransmissions it owes and the answer it ends in */
    Zb_LayersStep(&dev.stack, 200);
    dumpAps(&dev.model, aps, "apsArm");

    Zb_LayersStep(&dev.stack, 1800);
    Zb_LayersStep(&dev.stack, 1900);
    Zb_LayersStep(&dev.stack, 3500);
    dumpAps(&dev.model, aps, "apsRetry");

    Zb_LayersStep(&dev.stack, 3600);
    Zb_LayersStep(&dev.stack, 5200);
    Zb_LayersStep(&dev.stack, 5300);
    dumpAps(&dev.model, aps, "apsRetryLast");

    Zb_LayersStep(&dev.stack, 6900);
    dumpAps(&dev.model, aps, "apsNoAck");

    took = Zb_LayersPollConfirms(&dev.stack, confirms, 8);

    for (i = 0; i < took; i++)
        printf("aps confirm dstMode=%u dst=%04x dstEndpoint=%02x srcEndpoint=%02x cluster=%04x profile=%04x"
               " counter=%u attempts=%u status=%u apsStatus=%u\n",
               confirms[i].dstAddrMode, confirms[i].dstAddress, confirms[i].dstEndpoint,
               confirms[i].srcEndpoint, confirms[i].clusterId, confirms[i].profileId, confirms[i].apsCounter,
               confirms[i].attempts, (uint32_t)confirms[i].status, confirms[i].apsStatus);

    took = Zb_LayersPollIndications(&dev.stack, indications, 8);

    for (i = 0; i < took; i++)
        printf("aps indication dstMode=%u dst=%04x src=%04x srcEndpoint=%02x dstEndpoint=%02x cluster=%04x"
               " profile=%04x status=%u security=%u keyIndex=%u keyStatus=%u asduLen=%u lqi=%u\n",
               indications[i].dstAddrMode, indications[i].dstAddress, indications[i].srcAddress,
               indications[i].srcEndpoint, indications[i].dstEndpoint, indications[i].clusterId,
               indications[i].profileId, indications[i].status, indications[i].securityStatus,
               indications[i].keyIndex, indications[i].keyStatus, indications[i].asduLength,
               indications[i].linkQuality);

    printf("aps pools tx=%u confirm=%u indication=%u group=%u\n", Aps_TransmitQueue(aps),
           Aps_ConfirmQueue(aps), Aps_IndicationQueue(aps), Aps_GroupQueue(aps));
}

int main(void)
{
    run("scaffold router", 0, 0x1000);
    run("secured router", 1, 0x1000);
    run("exhausted counter router", 1, 0xfffffffe);
    runAps();

    return 0;
}
