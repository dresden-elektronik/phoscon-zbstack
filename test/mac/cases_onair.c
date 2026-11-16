/* The `mac` suite's known answer: the frames two RCPs composed and put on channel 26, and the frames its
   second RCP delivered back. `test/fixtures/` is the claim; every expectation here is a line of a transcript,
   and no frame is composed that a transcript does not name. */

#include "fixtures_frames.h"
#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "mac_helpers.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

#ifndef ZB_SAMPLES_DIR
#define ZB_SAMPLES_DIR "."
#endif

/* The identity the `loopback_ch26_*` transcripts armed their RCPs with: `RADIO_CAPS 0x010d` as both ConBee
   IIs answer it (docs/internals/hardware.md §4), channel 26 and the inert PAN the rig transmissions were issued into. */
#define ON_AIR_CAPS 0x10d
#define ON_AIR_CHANNEL 26
#define ON_AIR_PAN 0xbeef
#define ON_AIR_SOURCE 0xdead
#define ON_AIR_PEER 0x1234

enum
{
    ON_AIR_FRAMES = 10,
    ON_AIR_RECEIPTS = 2
};

/* Table 8-30 as one transcript's `sent` line states it, beside the PSDU line beneath it and the peer's own
   transcript of the same frame where the host amended the one it wrote. */
typedef struct OnAirFrame
{
    const char *path;
    const char *name;
    const char *peerPath;
    uint8_t dsn;
    uint16_t destShort;
    uint32_t payloadLen;
    uint32_t octets;
    int ackRequest;
} OnAirFrame;

/* A row of `test/fixtures/loopback_ch26_tx_*.txt`, its `sent` line read as Table 8-30. `peerPath` is set only
   where the transcript says the host amended the footer it wrote, and the known answer for that row is then the
   peer's copy of the frame. */
static const OnAirFrame s_transcripts[ON_AIR_FRAMES] =
{
    { ZB_SAMPLES_DIR "/" "loopback_ch26_tx_ackreq_answered.txt",
      "the seq 29 frame to 0x1234 that its peer answered", 0, 0x29, 0x1234, 0, 11, 1 },
    { ZB_SAMPLES_DIR "/" "loopback_ch26_tx_ackreq_filtered.txt",
      "the seq 21 frame to 0x1234 its peer was filtered to", 0, 0x21, 0x1234, 0, 11, 1 },
    { ZB_SAMPLES_DIR "/" "loopback_ch26_tx_ackreq_nopeer.txt",
      "the seq 2b frame to 0x1234 with no peer armed at all", 0, 0x2b, 0x1234, 0, 11, 1 },
    { ZB_SAMPLES_DIR "/" "loopback_ch26_tx_ackreq_promisc.txt",
      "the seq 1f frame to 0x1234 whose peer listened promiscuous", 0, 0x1f, 0x1234, 0, 11, 1 },
    { ZB_SAMPLES_DIR "/" "loopback_ch26_tx_ackreq_unaddressed.txt",
      "the seq 09 frame addressed to this device's own 0xdead", 0, 0x09, 0xdead, 8, 19, 1 },
    { ZB_SAMPLES_DIR "/" "loopback_ch26_tx_corrupt_fcs.txt",
      "the seq 1e broadcast whose footer the host amended",
      ZB_SAMPLES_DIR "/" "loopback_ch26_rx_corrupt_fcs.txt", 0x1e, 0xffff, 8, 19, 0 },
    { ZB_SAMPLES_DIR "/" "loopback_ch26_tx_noreq_filtered.txt",
      "the seq 22 frame to 0x1234 that asked for nothing", 0, 0x22, 0x1234, 0, 11, 0 },
    { ZB_SAMPLES_DIR "/" "loopback_ch26_tx_noreq_promisc.txt",
      "the seq 20 frame to 0x1234 that asked for nothing", 0, 0x20, 0x1234, 0, 11, 0 },
    { ZB_SAMPLES_DIR "/" "loopback_ch26_tx_seq07.txt",
      "the seq 07 broadcast to 0xffff", 0, 0x07, 0xffff, 8, 19, 0 },
    { ZB_SAMPLES_DIR "/" "loopback_ch26_tx_seq08.txt",
      "the seq 08 broadcast to 0xffff", 0, 0x08, 0xffff, 8, 19, 0 }
};

/* The peer transcript's two frame lines and the dissection line beneath each
   (`test/fixtures/loopback_ch26_rx_promisc.txt`): the sequence octet the harness read, the metadata the radio
   reported, and whether that line names an acknowledgment request. */
typedef struct OnAirReception
{
    uint8_t dsn;
    int32_t rssiDbm;
    uint32_t lqi;
    uint64_t stampTicks;
    int ackRequest;
    const char *name;
} OnAirReception;

static const OnAirReception s_receipts[ON_AIR_RECEIPTS] =
{
    { 0x1f, -94, 255, 3754489816, 1, "the peer's frame 1, seq 1f" },
    { 0x20, -94, 255, 3757522816, 0, "the peer's frame 2, seq 20" }
};

/* One transcript read as the PSDUs it carries, through the loader the `interop` suite uses (docs/internals/testing.md
   §4): the annotation lines are a decoder's remarks and are ignored, so not one octet of a captured frame is
   retyped here. The three assertions are the three things a case expects of a file it names. */
static uint32_t onAirLoad(const char *path, uint8_t *bytes, uint32_t *lengths, uint32_t wanted)
{
    ZbStatus status;
    uint32_t count = 0;

    status = Test_FixtureLoad(path, bytes, lengths, wanted, RADIO_MPDU_MAX, wanted, &count);

    Test_Expect(status != ZB_ERR_NOT_OPEN, "the transcript opens for reading");

    if (status == ZB_ERR_NOT_OPEN)
        return 0;

    Test_Expect(status != ZB_ERR_NO_SPACE, "no transcript line runs past the table it was read into");
    Test_ExpectCount(count, wanted, "the transcript holds the PSDU lines this case names");

    return count;
}

/* The device one row composes from: the hardware-free backend of docs/internals/architecture.md §1 with the capabilities
   both RCPs reported, armed with this case's PAN, its own short address and the transcript's sequence octet
   as the seed band A numbers from (6.6.1, Table 8-36, wrapped at MAC_DSN_WRAP). */
static void onAirRig(Test_BandA *rig, uint16_t ownAddress, uint8_t dsnStart)
{
    Radio_Caps caps;
    Mac_Config config;

    Test_BandACapsAcks(&caps);

    Zb_memset(&config, 0, (uint32_t)sizeof config);
    config.dsnStart = dsnStart;

    rigConfig(rig, &caps, ownAddress, ON_AIR_PAN, &config);
}

/* The backend every row below was composed against, pinned to what the RCP reported: a backend with other
   capabilities composes another frame and witnesses nothing. */
void caseOnAirBackendIsTheMeasuredRcp(void)
{
    Test_BandA dev;
    const Radio_Caps *caps;

    onAirRig(&dev, ON_AIR_SOURCE, 0x29);
    caps = Mac_Caps(&dev.mac);

    Test_Expect(caps->radioCaps == ON_AIR_CAPS,
           "the backend reports the capability bitmap every transcript here prints (docs/internals/hardware.md §4)");

    Test_Expect(caps->hasTransmit == 1 && caps->hasEnergyScan == 0 && caps->hasAckMetadata == 0,
           "with the three flags the same line prints beside it: it transmits, it reports no scan, and it says "
           "nothing beside a completion");

    Test_Expect(caps->psduIncludesFcs == 1,
           "the footer travels inside the PSDU, so the two footer octets are part of what the seam is handed");

    Test_Expect(caps->handlesAckTimeout == 1,
           "and the ACK_TIMEOUT named in that bitmap is band B's reading of it, which is what this module's "
           "acknowledgment wait branches on");

    Test_Expect(Mac_Pib(&dev.mac)->channel == ON_AIR_CHANNEL,
           "the mirror this module keeps is armed on channel 26, the quiet channel the rig measured on");

    Test_Expect(dev.model.pib.channel == ON_AIR_CHANNEL && dev.model.pib.panId == ON_AIR_PAN
           && dev.model.pib.shortAddress == ON_AIR_SOURCE,
           "and the backend was armed with the same channel, the inert PAN and the address every captured frame "
           "carries as its source");
}

/* One transcript's frame, composed and read back at the seam. */
static void onAirCompose(const OnAirFrame *row)
{
    Test_BandA dev;
    Loopback_Sent sent[1];
    Mac_DataRequestParameters req;
    Mac_Frame parsed;
    const uint8_t *parsedPayload = 0;
    uint8_t air[RADIO_MPDU_MAX];
    uint8_t peer[RADIO_MPDU_MAX];
    uint32_t peerLengths[1];
    uint32_t airLengths[1];
    uint32_t parsedPayloadLen = 0;
    uint32_t airLen;
    uint32_t differing;
    uint32_t lastDifference;
    uint32_t index;
    uint32_t got;
    ZbStatus status;

    if (onAirLoad(row->path, air, airLengths, 1) != 1)
        return;

    airLen = airLengths[0];

    Test_ExpectCount(airLen, row->octets, "the captured frame is as long as its own line counts it");

    /* The transcription guard: the octets in the file this row names carry exactly the request the same
       transcript's `sent` line states, so a row wired to the wrong transcript reddens here rather than
       quietly comparing against another frame. */
    status = MacFrame_Parse(air, airLen, 1, &parsed, &parsedPayload, &parsedPayloadLen, 0);

    Test_Expect(status == ZB_OK
                && parsed.frameType == MAC_FRAME_TYPE_DATA
                && parsed.frameVersion == 0
                && parsed.seq == row->dsn
                && parsed.ackRequest == row->ackRequest
                && !parsed.framePending
                && parsed.panIdCompression
                && parsed.destAddrMode == MAC_ADDR_SHORT
                && parsed.srcAddrMode == MAC_ADDR_SHORT
                && parsed.destPan == ON_AIR_PAN
                && parsed.srcPan == ON_AIR_PAN
                && parsed.destShort == row->destShort
                && parsed.srcShort == ON_AIR_SOURCE
                && parsedPayloadLen == row->payloadLen
                && (parsedPayloadLen == 0 || Zb_memcmp(parsedPayload, payload, parsedPayloadLen) == 0),
                "the captured octets name the request this row states");

    onAirRig(&dev, ON_AIR_SOURCE, row->dsn);

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, ON_AIR_PAN, row->destShort,
                  MAC_ADDR_SHORT, row->ackRequest);
    req.payload = row->payloadLen == 0 ? 0 : payload;
    req.payloadLen = row->payloadLen;

    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 100, 0), ZB_OK, "the request composes");

    got = LoopbackRadio_Sent(&dev.model, sent, 1);
    Test_ExpectCount(got, 1, "one MPDU reached the seam");

    if (got != 1)
        return;

    Test_Expect(sent[0].ackRequest == row->ackRequest,
           "and the ask the radio was given is the ask the request named");

    if (row->peerPath == 0)
    {
        Test_ExpectOctets(row->name, sent[0].bytes, sent[0].len, air, airLen);
        return;
    }

    /* The one transmission whose transcript amended the frame it wrote: the host flipped the last octet of the
       footer band A computed, and the peer's RCP delivered the footer the frame computes for itself (7.2.11), which is the copy this row compares against. */
    if (onAirLoad(row->peerPath, peer, peerLengths, 1) != 1)
        return;

    Test_Expect(MacFrame_CheckFcs(air, airLen) == ZB_ERR_BAD_FRAME
                && MacFrame_CheckFcs(sent[0].bytes, sent[0].len) == ZB_OK,
           "the transcript's footer fails the arithmetic its own octets state, and this module's validates");

    Test_ExpectOctets("the frame this module handed the seam is the frame the peer's RCP delivered",
                      sent[0].bytes, sent[0].len, peer, peerLengths[0]);

    differing = 0;
    lastDifference = 0;

    for (index = 0; index < airLen && index < sent[0].len; index++)
    {
        if (air[index] == sent[0].bytes[index])
            continue;

        differing++;
        lastDifference = index;
    }

    Test_Expect(differing == 1 && lastDifference + 1 == airLen,
           "one octet of the host's copy is not this module's, and it is the last one");
}

void caseOnAirCompositionIsTheCapturedFrame(void)
{
    uint32_t row;

    for (row = 0; row < ON_AIR_FRAMES; row++)
        onAirCompose(&s_transcripts[row]);
}

/* The other half of the same runs: the frames the second RCP delivered, read through this module and
   required to answer the field line its transcript printed beside each. */
void caseOnAirReceiptIsTheCapturedFields(void)
{
    Test_BandA dev;
    Loopback_FrameSpec specs[ON_AIR_RECEIPTS];
    Mac_DataIndicationParameters indications[ON_AIR_RECEIPTS];
    uint8_t psdus[ON_AIR_RECEIPTS][RADIO_MPDU_MAX];
    uint32_t lengths[ON_AIR_RECEIPTS];
    Mac_Counters counters;
    uint32_t row;
    uint32_t got;

    if (onAirLoad(ZB_SAMPLES_DIR "/" "loopback_ch26_rx_promisc.txt", &psdus[0][0], lengths,
                  ON_AIR_RECEIPTS) != ON_AIR_RECEIPTS)
        return;

    /* The peer RCP's own identity, from the same transcript's `addressed` line: the frames were received at
       0x1234 in PAN 0xbeef on channel 26. */
    onAirRig(&dev, ON_AIR_PEER, 0);

    for (row = 0; row < ON_AIR_RECEIPTS; row++)
    {
        specs[row].len = lengths[row];
        specs[row].bytes = psdus[row];
        specs[row].rssiDbm = s_receipts[row].rssiDbm;
        specs[row].lqi = s_receipts[row].lqi;
        specs[row].stampTicks = s_receipts[row].stampTicks;
        specs[row].error = ZB_OK;
    }

    Test_ExpectStatus(LoopbackRadio_Inject(&dev.model, specs, ON_AIR_RECEIPTS), ZB_OK,
                 "both delivered frames are put in front of this module");

    Test_ExpectStatus(Mac_Step(&dev.mac, 100), ZB_OK, "one step takes the batch");

    counters = Mac_CountersOf(&dev.mac);

    Test_ExpectCount(counters.indicationQueue, ON_AIR_RECEIPTS, "and hands both up");

    got = Mac_PollIndications(&dev.mac, indications, ON_AIR_RECEIPTS);
    Test_ExpectCount(got, ON_AIR_RECEIPTS, "neither is consumed here: both are data frames");

    for (row = 0; row < ON_AIR_RECEIPTS; row++)
    {
        const Mac_DataIndicationParameters *ind = &indications[row];
        const OnAirReception *receipt = &s_receipts[row];

        Test_Expect(ind->headerValid == 1 && ind->frameType == (uint32_t)MAC_FRAME_TYPE_DATA
               && ind->header.frameType == MAC_FRAME_TYPE_DATA && ind->header.frameVersion == 0
               && ind->header.seq == receipt->dsn,
               "the delivered frame is the data frame its line names, at its own sequence octet");

        Test_Expect(ind->header.ackRequest == receipt->ackRequest && !ind->header.framePending
               && ind->header.panIdCompression,
               "with the acknowledgment request that line names or withholds, no pending bit, and one PAN field");

        Test_Expect(ind->header.destAddrMode == MAC_ADDR_SHORT && ind->header.srcAddrMode == MAC_ADDR_SHORT
               && ind->header.destPan == ON_AIR_PAN,
               "16-bit addressing at both ends and the PAN the frame says it is in");

        Test_Expect(ind->header.destShort == ON_AIR_PEER && ind->header.srcShort == ON_AIR_SOURCE
               && ind->payloadLen == 0 && ind->status == ZB_OK,
               "both short addresses in the order the frame carries them, no content, and a footer the "
               "delivered octets compute");

        Test_Expect(ind->len == lengths[row] && ind->stampTicks == receipt->stampTicks
               && Zb_memcmp(ind->bytes, psdus[row], ind->len) == 0,
               "and the whole PSDU, stamp included, as it arrived");
    }
}
