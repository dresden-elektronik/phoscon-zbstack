/* The `nwk` suite's shared machinery: the bodies. See `nwk_helpers.h` for what this file is and why it is
   here. */

#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "nwk.h"
#include "nwk_helpers.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

/* The NSDU every accepted request carries. Its octets are the point of two assertions: the NPDU payload is
   the NSDU untouched, and a retry re-offers the same octets. */
const uint8_t nsdu[NSDU_LEN] = { 0x7a, 0x6e, 0x6b, 0x20, 0x70, 0x61 };

/* Injected frames are a neighbor's, not this device's, so their DSN is the suite's and counts up so that two
   frames one case injects are never mistaken for each other. */
static uint32_t s_injectDsn;

/* A band-A device, configured the way the application configures one: a device type, a short
   address and a PAN the backend took, and the receiver duty the backend accepted, because Table 3-80 states one
   of its five destination groups as macRxOnWhenIdle rather than as a device type, and 3.6.6 opens its
   sleepy-copy paragraph with a device whose own receiver is on. A router or coordinator of this PAN is such a
   device: 3.6.2.2 limits the relay duties to a coordinator or router and 3.6.6 refuses the relay duty outright
   to a device with macRxOnWhenIdle FALSE, so the two are the same device in practice and the rig says so rather
   than leaving the field unstated. The seeds the application supplies are the other two things a rig
   may name: `rigAtSeed` takes the initial sequence number and the jitter seed, `rigAt` takes none and so builds
   today's device.

   The build itself is `Test_BandABuild`'s (test/support/rig_band_a.h): the model, the seam, the MAC on it and
   the PIB write, whose statuses it folds into the one status this rig asserts. What stays here is this suite's
   own reading of what the build produced: the PIB the backend took, the network layer on the MAC by pointer and
   not by copy, and the device type and the numbering the config named. */
void rigAtSeed(Test_BandA *rig, uint16_t own, uint16_t panId, uint32_t deviceType, int rxOnWhenIdle,
               uint32_t seqStart, uint32_t jitterSeed)
{
    Test_BandAConfig cfg;
    ZbStatus status;

    Test_BandADefaults(&cfg);
    cfg.ownAddress = own;
    cfg.panId = panId;
    cfg.deviceType = deviceType;
    cfg.rxOnWhenIdle = rxOnWhenIdle;
    cfg.seqStart = seqStart;
    cfg.jitterSeed = jitterSeed;

    status = Test_BandABuild(rig, &cfg);

    Test_ExpectStatus(status, ZB_OK, "the network layer is given a MAC that already has its backend");
    Test_Expect(Mac_Pib(&rig->mac)->shortAddress == own && Mac_Pib(&rig->mac)->panId == panId
                && Mac_Pib(&rig->mac)->rxOnWhenIdle == rxOnWhenIdle,
                "whose PIB mirror carries this device's address, PAN and receiver duty: the three things the network layer reads about itself and the only place it may read them from");
    /* The build answers one status for all three stages, so the stage that says this (`Nwk_Init`'s) and the
       pointer check this suite has always made sit at two sites, both of them this one fact. */
    Test_Expect(rig->nwk.mac == &rig->mac, "and the network layer adopts the MAC by pointer");
    Test_Expect(rig->nwk.mac == &rig->mac, "adopted and not copied: the MAC owns the backend beneath it, and re-arming it stays its owner's act");
    Test_Expect(rig->nwk.cfg.deviceType == deviceType, "with the device type it was told, which is what every broadcast rule below reads");
    Test_Expect(rig->nwk.seq == seqStart,
                "and a sequence number that starts where the config says: Table 3-66's random default, 3.6.2.1, is the application's");
    Test_Expect(rig->nwk.jitterState == jitterSeed,
                "and the jitter generator's state is the seed it was given, so a schedule is a function of a seed and a call order and nothing else");
}

/* The device's own extended address, in the octet order 7.2.1.4 writes it (least significant first) */
void setOwnIeee(Test_BandA *rig, uint64_t ieee)
{
    Radio_Pib pib;
    uint32_t i;

    pib = *Mac_Pib(&rig->mac);

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        pib.extendedAddress[i] = (uint8_t)(ieee >> (i * 8));

    pib.present = pib.present | RADIO_PIB_EXTENDED_ADDRESS;

    Test_ExpectStatus(Mac_SetPib(&rig->mac, &pib), ZB_OK,
                      "the device's own extended address is a PIB field the backend takes, and it is what a command frame carries as its source IEEE");
}

/* The rig as every case that asks for no seed builds it: the default config, today's numbering and today's
   retransmission schedules. */
void rigAt(Test_BandA *rig, uint16_t own, uint16_t panId, uint32_t deviceType, int rxOnWhenIdle)
{
    rigAtSeed(rig, own, panId, deviceType, rxOnWhenIdle, 0, 0);
}

/* The rig every case that speaks as a router uses: an FFD, listening, with routing duties (3.6.2.2, 3.6.6). */
void rig(Test_BandA *rig, uint16_t own, uint16_t panId)
{
    rigAt(rig, own, panId, NWK_DEVICE_ROUTER, 1);
}

/* The neighbor table as a case seeds it: an entry put in by hand, for the one thing a received frame cannot
   supply. What band A observes for itself is an address and, if the frame carried one, an IEEE address; a
   device type and a receiver duty come from association, which is ZDO work that is deferred. A case that
   wants a rule that reads a device type (3.6.6's copying, 3.6.2.2's End Device Initiator search, 3.6.2.3's
   lost-child examination) has to seed one, which is what these entries are for. */
void seedNeighbor(Nwk_Nwk *nwk, uint16_t addr, uint32_t deviceType, int rxOnWhenIdle,
                  uint32_t relationship)
{
    uint32_t before = Nwk_NeighborQueue(nwk);

    Test_BandASeedNeighbor(nwk, addr, deviceType, rxOnWhenIdle, relationship);

    Test_Expect(Nwk_NeighborQueue(nwk) == before + 1, "the neighbor table has room for the entry the suite seeds");
}

Nwk_DataRequestParameters nldeReq(uint16_t dst, const uint8_t *what, uint32_t len, uint8_t radius)
{
    Nwk_DataRequestParameters req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.dstAddr = dst;
    req.nsdu = what;
    req.nsduLength = len;
    req.radius = radius;

    return req;
}

/* Scripted outcomes for the next `count` transmits: answered, or refused the way a radio answers a unicast
   nobody acknowledged (ZB_ERR_DEVICE, which is what NO_ACK becomes at the seam, docs/internals/protocol.md §7.3). */
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

/* Every frame this module has put on the air, in issue order, copied where the suite can keep reading it
   after the answer that reclaimed the backend's record. Nothing two frames of this suite share is the DSN:
   7.2.3 gives every frame a device issues a number of its own, so a record already logged cannot be
   confused with a later one. */
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

uint8_t dsnOf(const Air *air)
{
    return air->bytes[2];
}

uint16_t airDestOf(const Air *air)
{
    return (uint16_t)(air->bytes[5] | (air->bytes[6] << 8));
}

uint16_t airSrcOf(const Air *air)
{
    return (uint16_t)(air->bytes[7] | (air->bytes[8] << 8));
}

const uint8_t *npduOf(const Air *air)
{
    return air->bytes + NPDU_OFFSET;
}

uint32_t npduLenOf(const Air *air)
{
    if (air->len < NPDU_OFFSET + FCS_OCTETS)
        return 0;

    return air->len - NPDU_OFFSET - FCS_OCTETS;
}

/* The child side of the indirect copy, composed by the suite because the suite is what puts a poll in front
   of the device holding the copy: 10.22.4.1's twelve octets, Command ID 0x04, Destination PAN this device's
   own, AR one and Frame Pending zero. */
void composePoll(Loopback_Radio *model, uint8_t dsn, uint16_t src)
{
    composePollTo(model, dsn, src, OWN_SHORT);
}

void composePollTo(Loopback_Radio *model, uint8_t dsn, uint16_t src, uint16_t dst)
{
    Mac_Frame frame;
    static const uint8_t content[1] = { MAC_CMD_POLL };
    Loopback_FrameSpec spec;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t len;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 1;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.destPan = PAN_ID;
    frame.srcPan = PAN_ID;
    frame.destShort = dst;
    frame.srcShort = src;
    frame.seq = dsn;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, (uint32_t)sizeof content, bytes, RADIO_MPDU_MAX, &len),
                      ZB_OK, "the poll that extracts a sleepy child's copy is a frame this stack can compose (10.22.4.1)");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK,
                      "closed by the footer those octets compute (7.2.11)");

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = len;
    spec.bytes = bytes;
    spec.rssiDbm = -70;
    spec.lqi = 200;
    spec.stampTicks = 1;
    spec.error = ZB_OK;

    Test_ExpectStatus(LoopbackRadio_Inject(model, &spec, 1), ZB_OK, "and it is put in front of the MAC");
}

/* An NPDU this stack can compose, because the codec is the honest way to build one: the case names the fields
   and the codec writes the octets. */
/* Table 3-80's reserved rows are codes 1.4.2 never generates, so a case that injects a frame addressed to one
   composes a valid frame and rewrites the two destination octets: the receive side is what it is testing. */
uint32_t makeNpdu(uint8_t *out, uint16_t dst, uint16_t src, uint8_t radius, uint8_t seq,
                  uint32_t frameType, uint32_t endDeviceInitiator, const uint8_t *payload,
                  uint32_t payloadLen)
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
    frame.endDeviceInitiator = (int)endDeviceInitiator;

    if (dst == NWK_ADDR_RESERVED)
        frame.destAddr = 0x1234;

    Test_ExpectStatus(NwkFrame_Compose(&frame, payload, payloadLen, out, RADIO_MPDU_MAX, &len), ZB_OK,
                  "the NPDU the case injects is one this stack's own codec composes");

    if (dst == NWK_ADDR_RESERVED)
    {
        out[2] = (uint8_t)(dst & 0xff);
        out[3] = (uint8_t)(dst >> 8);
    }

    return len;
}

/* The rejoin requests this suite builds are a joiner's, and two of them in one case must not be the same frame:
   the number is the suite's and counts up, the way the injected frames' DSN does. */
static uint32_t s_rejoinSeq;

/* 3.4.6.2's header, field for field: the frame type and the protocol version, the prospective parent's and this
   device's network addresses, the radius 1 the pair is printed with, and both IEEE address sub-fields present,
   which is the form 3.4.6.2 requires of a NWK rejoin. Figure 3-17's payload is the identifier and the one
   Capability Information octet, which `MacFrame_ParseAssociationRequest` reads at the parent. */
uint32_t makeRejoinNpdu(uint8_t *out, uint16_t dst, uint16_t src, uint64_t srcIeee, uint64_t dstIeee,
                        uint8_t capability)
{
    Nwk_Frame frame;
    uint8_t payload[2];
    uint32_t len;

    payload[0] = NWK_CMD_REJOIN_REQUEST;
    payload[1] = capability;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = NWK_FRAME_TYPE_COMMAND;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.discoverRoute = NWK_DISCOVER_SUPPRESS;    /* 3.4: a command frame suppresses route discovery */
    frame.destAddr = dst;
    frame.srcAddr = src;
    frame.radius = 1;                               /* 3.4.6.2: "The radius field SHALL be set to 1" */
    frame.sequenceNumber = (uint8_t)(s_rejoinSeq % NWK_SEQ_WRAP);
    frame.srcIeeePresent = 1;
    frame.srcIeee = srcIeee;
    frame.destIeeePresent = 1;
    frame.destIeee = dstIeee;

    s_rejoinSeq = s_rejoinSeq + 1;

    Test_ExpectStatus(NwkFrame_Compose(&frame, payload, (uint32_t)sizeof payload, out, RADIO_MPDU_MAX, &len), ZB_OK,
                      "the rejoin request the case injects is one this stack's own codec composes (3.4.6, Figure 3-17)");

    return len;
}

/* An NPDU the codec will not compose, written octet by octet: the forms a received frame can carry that a
   transmitted one may not, and a truncated frame. Table 1-5's versions, Table 3-52's reserved frame type, the
   security bit of Figure 3-5 and a header shorter than the eight octets 3.3.1.2 … 3.3.1.5 make always-present. */
uint32_t rawNpdu(uint8_t *out, uint16_t fcf, uint16_t dst, uint16_t src, uint8_t radius, uint8_t seq,
                 const uint8_t *payload, uint32_t payloadLen, uint32_t truncateTo)
{
    uint32_t len;

    out[0] = (uint8_t)(fcf & 0xff);
    out[1] = (uint8_t)(fcf >> 8);
    out[2] = (uint8_t)(dst & 0xff);
    out[3] = (uint8_t)(dst >> 8);
    out[4] = (uint8_t)(src & 0xff);
    out[5] = (uint8_t)(src >> 8);
    out[6] = radius;
    out[7] = seq;
    len = 8;

    if (payload != 0 && payloadLen != 0)
    {
        Zb_memcpy(out + len, payload, payloadLen);
        len = len + payloadLen;
    }

    if (truncateTo != 0 && truncateTo < len)
        len = truncateTo;

    return len;
}

/* The MAC destination a received frame carries, from the NPDU it is carrying: 3.2.1.1.3 step 6 a.3 sets it to
   0xFFFF for the classes 3.6.6 prints, which 6.2 makes the one broadcast short address; every other frame is a
   unicast whose next hop is the device it arrives at, this one. */
static uint16_t injectDestination(const uint8_t *npdu, uint32_t npduLen, const Radio_Pib *pib)
{
    uint16_t nwkDest;

    if (npduLen >= 4)
    {
        nwkDest = (uint16_t)(npdu[2] | (npdu[3] << 8));

        if (Nwk_AddrIsBroadcast(nwkDest))
            return MAC_FRAME_ADDR_BROADCAST;
    }

    return pib->shortAddress;
}

/* One NPDU arriving as a neighbor's frame: short addressing at both ends of the MAC frame, one PAN field,
   the acknowledgment asked for exactly as this PAN's broadcasts and unicasts are asked (docs/internals/protocol.md §9.1),
   and the MAC destination `injectDestination` derives, because it is the MAC frame's business (3.4.1.1). A frame
   whose MAC destination named a third device is not a frame this MAC hands up at all (6.6.2 d), so the suite has
   no way to inject one and no case asks for one. */
void injectNpduAs(Test_BandA *dev, const uint8_t *npdu, uint32_t npduLen, Mac_AddrMode srcAddrMode,
                  uint16_t macSrc)
{
    Mac_Frame frame;
    Loopback_FrameSpec spec;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint16_t macDst;
    uint32_t len;

    macDst = injectDestination(npdu, npduLen, Mac_Pib(&dev->mac));

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_DATA;
    frame.frameVersion = 0;
    frame.ackRequest = macDst == MAC_FRAME_ADDR_BROADCAST ? 0 : 1;
    /* 7.2.2.6: "If only either the destination or the source addressing information is present, the PAN ID
       Compression field shall be set to zero, and the PAN ID field of the single address shall be included in the
       transmitted frame." A frame with no source address is therefore a frame with its PAN field spelled out, and
       it is the only shape that leaves room for an NPDU longer than this PAN's ordinary ones. */
    frame.panIdCompression = srcAddrMode == MAC_ADDR_NONE ? 0 : 1;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = srcAddrMode;
    frame.destPan = PAN_ID;
    frame.srcPan = PAN_ID;
    frame.destShort = macDst;
    frame.srcShort = macSrc;
    frame.seq = (uint8_t)(s_injectDsn % MAC_DSN_WRAP);
    s_injectDsn = s_injectDsn + 1;

    Test_ExpectStatus(MacFrame_Compose(&frame, npdu, npduLen, bytes, RADIO_MPDU_MAX, &len), ZB_OK,
                  "the NPDU is carried in a MAC data frame, which is how every NWK frame travels (3.4.1.1)");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK,
                  "and the footer those octets compute closes it (7.2.11)");

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = len;
    spec.bytes = bytes;
    spec.rssiDbm = -70;
    spec.lqi = 200;
    spec.stampTicks = 1;
    spec.error = ZB_OK;

    Test_ExpectStatus(LoopbackRadio_Inject(&dev->model, &spec, 1), ZB_OK,
                  "and it is put in front of the MAC, which is what a neighbor's frame is");
}

void injectNpdu(Test_BandA *dev, const uint8_t *npdu, uint32_t npduLen, uint16_t macSrc)
{
    injectNpduAs(dev, npdu, npduLen, MAC_ADDR_SHORT, macSrc);
}

/* A frame the MAC below will not hand over cleanly: the same composition with its last octet changed, so the
   footer the delivered octets compute is not the footer the frame carries. */
void injectBrokenNpdu(Test_BandA *dev, const uint8_t *npdu, uint32_t npduLen, uint16_t macSrc)
{
    Loopback_FrameSpec spec;
    uint8_t bytes[RADIO_MPDU_MAX];
    Mac_Frame frame;
    uint32_t len;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_DATA;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 1;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.destPan = PAN_ID;
    frame.srcPan = PAN_ID;
    frame.destShort = injectDestination(npdu, npduLen, Mac_Pib(&dev->mac));
    frame.srcShort = macSrc;
    frame.seq = (uint8_t)(s_injectDsn % MAC_DSN_WRAP);
    s_injectDsn = s_injectDsn + 1;

    Test_ExpectStatus(MacFrame_Compose(&frame, npdu, npduLen, bytes, RADIO_MPDU_MAX, &len), ZB_OK,
                  "a well-formed frame …");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK, "… with its footer computed …");

    bytes[len - 1] = (uint8_t)(bytes[len - 1] ^ 0xff);

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = len;
    spec.bytes = bytes;
    spec.rssiDbm = -70;
    spec.lqi = 200;
    spec.stampTicks = 1;
    spec.error = ZB_OK;

    Test_ExpectStatus(LoopbackRadio_Inject(&dev->model, &spec, 1), ZB_OK,
                  "… and then damaged, so the check band A runs over the delivered octets is the thing that fails (7.2.11, docs/internals/protocol.md §9.3)");
}

uint32_t npduDiffCount(const uint8_t *a, uint32_t aLen, const uint8_t *b, uint32_t bLen)
{
    uint32_t count = 0;
    uint32_t i;

    if (aLen != bLen)
        return NPDU_LENGTHS_DIFFER;

    for (i = 0; i < aLen; i++)
    {
        if (a[i] != b[i])
            count++;
    }

    return count;
}

/* The neighbor entry a case wants the assertion to be about, read the way a suite reads a table. */
Nwk_NeighborTableEntry *neighborAt(Nwk_Nwk *nwk, uint16_t address)
{
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (nwk->neighbors[i].inUse && nwk->neighbors[i].networkAddress == address)
            return &nwk->neighbors[i];
    }

    return 0;
}

/* The broadcast transaction record of that (source, sequence) pair, for a case that has to read what the table
   holds rather than only how deep it is. */
Nwk_BroadcastTransactionRecord *bttFor(Nwk_Nwk *nwk, uint16_t src, uint8_t seq)
{
    uint32_t i;

    for (i = 0; i < NWK_BTT_MAX; i++)
    {
        if (nwk->btt[i].inUse && nwk->btt[i].sourceAddress == src && nwk->btt[i].sequenceNumber == seq)
            return &nwk->btt[i];
    }

    return 0;
}

uint32_t airBroadcastCount(const Air *air, uint32_t count, uint16_t dest)
{
    uint32_t found = 0;
    uint32_t i;

    for (i = 0; i < count; i++)
    {
        if (airDestOf(&air[i]) == dest)
            found++;
    }

    return found;
}

uint32_t airClassCount(const Air *air, uint32_t count, uint16_t nwkDest)
{
    const uint8_t *npdu;
    uint32_t found = 0;
    uint32_t i;

    for (i = 0; i < count; i++)
    {
        npdu = npduOf(&air[i]);

        if ((uint16_t)(npdu[2] | (npdu[3] << 8)) == nwkDest)
            found++;
    }

    return found;
}

/* The Frame Control Field of an NPDU, read the way 3.3 writes it: low octet then high. */
uint16_t nwkFcfOf(const uint8_t *npdu)
{
    return (uint16_t)(npdu[0] | (npdu[1] << 8));
}
