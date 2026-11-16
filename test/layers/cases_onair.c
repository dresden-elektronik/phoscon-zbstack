/* The `stack` suite's known answer from the air: the frames two RCPs recorded (the four each rig
   run handed `tx` and the eight the peer's RCP delivered) required of the whole cascade, and of no octet this
   suite wrote down for itself. */

#include "layers_cases.h"
#include "layers_helpers.h"

#include "aps.h"
#include "aps_frame.h"
#include "fixtures_frames.h"
#include "loopback_radio.h"
#include "mac_frame.h"
#include "nwk_frame.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

#ifndef ZB_SAMPLES_DIR
#define ZB_SAMPLES_DIR "."
#endif

/* The two tee transcripts and the peer's window on the same two runs. */
#define ON_AIR_TX_PLAIN ZB_SAMPLES_DIR "/loopback_ch26_tx_nsdu_unsecured_discovery.txt"
#define ON_AIR_TX_SECURED ZB_SAMPLES_DIR "/loopback_ch26_tx_nsdu_secured_discovery.txt"
#define ON_AIR_RX_COPIES ZB_SAMPLES_DIR "/loopback_ch26_rx_nsdu_discovery.txt"

/* The device every recorded frame carries: `coordinator, own short 0xdead, PAN 0xbeef, channel 26,
 * rxOnWhenIdle 1`, its extended address the factory one the RCP reported. */
#define ON_AIR_OWN_SHORT 0xdead
#define ON_AIR_PEER_SHORT 0x1234
#define ON_AIR_PAN 0xbeef
#define ON_AIR_CHANNEL 26
#define ON_AIR_OWN_IEEE 0x00212effff048a12
#define ON_AIR_OWN_IEEE_TRANSMITTED "128a04ffff2e2100"

/* The three seeds printed beside that identity: `nwk sequence seeded 0x11, mac dsn seeded 0x21, no jitter seed`. */
#define ON_AIR_SEQ_START 0x11
#define ON_AIR_DSN_START 0x21

/* The secured run's material: `level 0x05 (encrypted, 32-bit mic), key sequence 00, authenticated, all-fresh`, the
 * network key as application config, its descriptor's outgoing counter standing at zero. */
#define ON_AIR_LEVEL 0x05
#define ON_AIR_KEY_SEQ 0x00

/* The request both runs issued: `unicast data to 0x1234 endpoint 02 from endpoint 01, profile 0x0104, cluster
 * 0x0006`, TxOptions 0x04 unsecured and 0x06 secured, a six-octet ASDU and Radius 0. */
#define ON_AIR_SRC_EP 0x01
#define ON_AIR_DST_EP 0x02
#define ON_AIR_PROFILE 0x0104
#define ON_AIR_CLUSTER 0x0006
#define ON_AIR_TX_OPTIONS_PLAIN 0x04
#define ON_AIR_TX_OPTIONS_SECURED 0x06
#define ON_AIR_ASDU_LEN 6

/* What each run put on the channel, and how long each of those frames was: the unsecured one carries the eight
 * data-header octets over the ASDU, the secured one the auxiliary, the ciphertext and the MIC. */
#define ON_AIR_ATTEMPTS 4
#define ON_AIR_UNSECURED_LEN 33
#define ON_AIR_SECURED_LEN 51
#define ON_AIR_DATA_HEADER_LEN 8
#define ON_AIR_AUX_LEN 14
#define ON_AIR_CIPHER_LEN 14
#define ON_AIR_MIC_LEN 4
#define ON_AIR_UNSECURED_NSDU_LEN (ON_AIR_DATA_HEADER_LEN + ON_AIR_ASDU_LEN)
#define ON_AIR_SECURED_NSDU_LEN (ON_AIR_AUX_LEN + ON_AIR_CIPHER_LEN + ON_AIR_MIC_LEN)
#define ON_AIR_UNSECURED_NPDU_LEN (NWK_MIN_HEADER_OVERHEAD + ON_AIR_UNSECURED_NSDU_LEN)
#define ON_AIR_SECURED_NPDU_LEN (NWK_MIN_HEADER_OVERHEAD + ON_AIR_SECURED_NSDU_LEN)

/* This window heard every attempt: four unsecured and four secured, each one the tee record it is. */
#define ON_AIR_COPIES 8
#define ON_AIR_UNSECURED_COPIES 4
#define ON_AIR_SECURED_COPIES 4

/* One level for the injection, named as invented: the transcript's own readings run -89 to -88 and no assertion
   in this suite rests on a received level. */
#define ON_AIR_COPY_RSSI_DBM -94

/* The clock the four issues run on: the request, then one turn every nwkcUnicastRetryDelay (Table 3-65), with a
 * turn one millisecond early to prove the floor is owed and not merely spent. */
#define ON_AIR_REQUEST_MS 100
#define ON_AIR_TURNS 10

/* The octet positions the transcripts' own `field` lines count: MHR at 0..8, NWK header at 9..16, then
 * (unsecured) the data header at 17..24 and the ASDU at 25..30, or (secured) the auxiliary at 17..30, the
 * ciphertext at 31..44 and the MIC at 45..48, every frame closed by its two footer octets. */
enum
{
    ON_AIR_OCTET_DSN = 2,
    ON_AIR_OCTET_NWK_RADIUS = 15,
    ON_AIR_OCTET_NWK_SEQ = 16,
    ON_AIR_OCTET_AUX_CONTROL = 17,
    ON_AIR_OCTET_AUX_COUNTER = 18,
    ON_AIR_OCTET_AUX_SOURCE = 22,
    ON_AIR_OCTET_AUX_KEY_SEQ = 30,
    ON_AIR_OCTET_CIPHER = 31,
    ON_AIR_OCTET_MIC = 45,
    ON_AIR_OCTET_APS_COUNTER = 24,
    ON_AIR_OCTET_ASDU = 25,
    ON_AIR_AUX_SOURCE_LEN = 8,
    ON_AIR_HEADER_AHEAD_OF_AUX = 18
};

/* One tee record as its transcript labels it: the sequence octet its `field mac` line prints, the handle beside
 * it, and the low octet of the auxiliary counter the secured run's `field aux` line prints. */
typedef struct OnAirAttempt
{
    uint8_t dsn;
    uint8_t auxCounter;
    Radio_Handle handle;
    const char *name;
} OnAirAttempt;

static const OnAirAttempt s_attempts[ON_AIR_ATTEMPTS] =
{
    { 0x21, 0x00, 1, "tee record 0: DSN 0x21, handle 1" },
    { 0x22, 0x01, 2, "tee record 1: DSN 0x22, handle 2" },
    { 0x23, 0x02, 3, "tee record 2: DSN 0x23, handle 3" },
    { 0x24, 0x03, 4, "tee record 3: DSN 0x24, handle 4" }
};

/* One turn of that clock, and how many frames the seam has been handed by then. */
typedef struct OnAirTurn
{
    uint32_t nowMs;
    uint32_t issues;
} OnAirTurn;

static const OnAirTurn s_turns[ON_AIR_TURNS] =
{
    { 110, 1 }, { 159, 1 }, { 160, 2 }, { 210, 2 }, { 259, 2 },
    { 260, 3 }, { 310, 3 }, { 359, 3 }, { 360, 4 }, { 410, 4 }
};

/* The peer's window as its transcript prints it: the sequence octet, whether the frame carries the NWK security
 * bit, the auxiliary counter and the tee row of the secured ones, and the length each line counts. */
typedef struct OnAirCopy
{
    uint8_t dsn;
    uint32_t secured;
    uint8_t auxCounter;
    uint32_t teeRow;
    uint32_t len;
    const char *name;
} OnAirCopy;

static const OnAirCopy s_copies[ON_AIR_COPIES] =
{
    { 0x21, 0, 0x00, 0, ON_AIR_UNSECURED_LEN, "the peer's copy at DSN 0x21, unsecured" },
    { 0x22, 0, 0x00, 1, ON_AIR_UNSECURED_LEN, "the peer's copy at DSN 0x22, unsecured" },
    { 0x23, 0, 0x00, 2, ON_AIR_UNSECURED_LEN, "the peer's copy at DSN 0x23, unsecured" },
    { 0x24, 0, 0x00, 3, ON_AIR_UNSECURED_LEN, "the peer's copy at DSN 0x24, unsecured" },
    { 0x21, 1, 0x00, 0, ON_AIR_SECURED_LEN, "the peer's copy at DSN 0x21, secured at counter 00" },
    { 0x22, 1, 0x01, 1, ON_AIR_SECURED_LEN, "the peer's copy at DSN 0x22, secured at counter 01" },
    { 0x23, 1, 0x02, 2, ON_AIR_SECURED_LEN, "the peer's copy at DSN 0x23, secured at counter 02" },
    { 0x24, 1, 0x03, 3, ON_AIR_SECURED_LEN, "the peer's copy at DSN 0x24, secured at counter 03" }
};

/* The network key and the six ASDU octets, as the two transcripts print them. */
static const uint8_t s_networkKey[SECURITY_KEY_OCTETS] =
{
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static const uint8_t s_asdu[ON_AIR_ASDU_LEN] = { 0x66, 0x72, 0x61, 0x6d, 0x65, 0x64 };

/* The four MICs of the secured run, as a dissector that had never seen this source read them off the trailing
 * four octets of each frame. */
static const char *s_mics[ON_AIR_ATTEMPTS] =
{
    "e6c4cc7f", "bdd55836", "425b97d1", "909dcd84"
};

/* ------------------------------------------------------------------ the tee */

/* What the seam was handed, kept as the rig's tee kept it: the exact octets, the acknowledgment ask, and the
 * handle the backend answered with. A backend recycles its own transmit record once the completion is collected,
 * so the four attempts of one run are only comparable from the side band A handed them. */
#define ON_AIR_TEE_MAX 8

typedef struct OnAirTeeRecord
{
    uint32_t len;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t ackRequest;
    Radio_Handle handle;
} OnAirTeeRecord;

typedef struct OnAirTee
{
    Radio_Radio seam;
    Radio_Radio *backend;
    uint32_t records;
    uint32_t txCalls;
    OnAirTeeRecord record[ON_AIR_TEE_MAX];
} OnAirTee;

static ZbStatus onAirTeeCaps(Radio_Radio *radio, Radio_Caps *outCaps)
{
    OnAirTee *self = (OnAirTee *)radio->provider;

    return self->backend->ops->caps(self->backend, outCaps);
}

static ZbStatus onAirTeePibSet(Radio_Radio *radio, const Radio_Pib *pib)
{
    OnAirTee *self = (OnAirTee *)radio->provider;

    return self->backend->ops->pibSet(self->backend, pib);
}

static ZbStatus onAirTeePibGet(Radio_Radio *radio, Radio_Pib *pib)
{
    OnAirTee *self = (OnAirTee *)radio->provider;

    return self->backend->ops->pibGet(self->backend, pib);
}

static ZbStatus onAirTeeFilter(Radio_Radio *radio, const Radio_Filter *filter)
{
    OnAirTee *self = (OnAirTee *)radio->provider;

    return self->backend->ops->filter(self->backend, filter);
}

/* The one call the tee is for: forward, and write down what was forwarded, before the backend touches it. */
static ZbStatus onAirTeeTx(Radio_Radio *radio, const uint8_t *mpdu, uint32_t len, int ackRequest,
                           uint32_t maxFrameRetries, Radio_Handle *outHandle)
{
    OnAirTee *self = (OnAirTee *)radio->provider;
    OnAirTeeRecord *slot;
    ZbStatus status;

    self->txCalls++;

    status = self->backend->ops->tx(self->backend, mpdu, len, ackRequest, maxFrameRetries, outHandle);

    if (status != ZB_OK || !mpdu || len == 0 || len > RADIO_MPDU_MAX)
        return status;

    if (self->records >= ON_AIR_TEE_MAX)
        return status;

    slot = &self->record[self->records];

    slot->len = len;
    Zb_memcpy(slot->bytes, mpdu, len);
    slot->ackRequest = ackRequest ? 1 : 0;
    slot->handle = *outHandle;

    self->records++;

    return status;
}

static ZbStatus onAirTeeCompletion(Radio_Radio *radio, Radio_Handle handle, Radio_TxResult *outResult)
{
    OnAirTee *self = (OnAirTee *)radio->provider;

    return self->backend->ops->completion(self->backend, handle, outResult);
}

static uint32_t onAirTeeRxPoll(Radio_Radio *radio, Radio_Frame *outFrames, uint32_t maxFrames)
{
    OnAirTee *self = (OnAirTee *)radio->provider;

    return self->backend->ops->rxPoll(self->backend, outFrames, maxFrames);
}

static int onAirTeeIsLost(Radio_Radio *radio)
{
    OnAirTee *self = (OnAirTee *)radio->provider;

    return self->backend->ops->isLost(self->backend);
}

static ZbStatus onAirTeeScanStart(Radio_Radio *radio, uint32_t channel, uint32_t dwellUnits)
{
    OnAirTee *self = (OnAirTee *)radio->provider;

    return self->backend->ops->scanStart(self->backend, channel, dwellUnits);
}

static ZbStatus onAirTeeScanCollect(Radio_Radio *radio, uint32_t *outChannel, int32_t *outDbm)
{
    OnAirTee *self = (OnAirTee *)radio->provider;

    return self->backend->ops->scanCollect(self->backend, outChannel, outDbm);
}

static const Radio_Ops s_teeOps =
{
    onAirTeeCaps,
    onAirTeePibSet,
    onAirTeePibGet,
    onAirTeeFilter,
    onAirTeeTx,
    onAirTeeCompletion,
    onAirTeeRxPoll,
    onAirTeeIsLost,
    onAirTeeScanStart,
    onAirTeeScanCollect
    , 0    /* no pending table on this backend */
};

/* ------------------------------------------------------------------ the rig, and the transcripts */

/* The transcript read as the PSDU lines it carries, through the loader the `mac` suite's known answers use: the
   annotation lines are a decoder's remarks and are ignored, so not one octet of a recorded frame is retyped
   here. The three assertions are what a case expects of a file it names. */
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

/* The rig's device, at a short address a caller names: the same identity, the same seeds, and for the secured
 * half the same level, key sequence and key the transcripts print, the model scripting the factory address the
 * RCP reported, because no write above the seam reaches it. */
static void onAirDevice(StackDevice *dev, uint16_t shortAddress, uint32_t secured)
{
    if (secured)
        stackDevice(dev);
    else
        stackDevicePlain(dev);

    dev->cfg.deviceType = NWK_DEVICE_COORDINATOR;
    dev->cfg.channel = ON_AIR_CHANNEL;
    dev->cfg.panId = ON_AIR_PAN;
    dev->cfg.shortAddress = shortAddress;
    dev->cfg.rxOnWhenIdle = 1;
    dev->cfg.seqStart = ON_AIR_SEQ_START;
    dev->cfg.dsnStart = ON_AIR_DSN_START;
    dev->cfg.jitterSeed = 0;

    stackExtendedOctets(ON_AIR_OWN_IEEE, dev->cfg.extendedAddress);
    stackDeviceFactory(&dev->model, ON_AIR_OWN_IEEE);

    if (secured)
    {
        Zb_memcpy(dev->key.key, s_networkKey, SECURITY_KEY_OCTETS);
        dev->key.keySeqNumber = ON_AIR_KEY_SEQ;
        dev->key.outgoingFrameCounter = 0;

        dev->secCfg.ownIeee = ON_AIR_OWN_IEEE;
        dev->secCfg.nwkSecurityLevel = ON_AIR_LEVEL;
        dev->secCfg.nwkActiveKeySeqNumber = ON_AIR_KEY_SEQ;
        dev->secCfg.authenticated = 1;
        dev->secCfg.nwkAllFresh = 1;

        dev->cfg.nwkSecurityLevel = ON_AIR_LEVEL;
    }
}

/* The façade over that device and the tee in front of its backend. */
static ZbStatus onAirInit(StackDevice *dev, OnAirTee *tee)
{
    Zb_memset(tee, 0, (uint32_t)sizeof *tee);

    tee->backend = LoopbackRadio_Seam(&dev->model);
    tee->seam.ops = &s_teeOps;
    tee->seam.provider = tee;

    return Zb_LayersInit(&dev->stack, &tee->seam, &dev->cfg);
}

/* Table 2-2's parameters as the transcripts state them, down to the Radius the request left at 0 and the network
 * layer derived (3.2.1.1.3). */
static Aps_ApsdeReq onAirRequest(uint32_t txOptions)
{
    Aps_ApsdeReq req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    req.dstAddrMode = APS_ADDR_MODE_SHORT;
    req.dstAddress = ON_AIR_PEER_SHORT;
    req.dstEndpoint = ON_AIR_DST_EP;
    req.profileId = ON_AIR_PROFILE;
    req.clusterId = ON_AIR_CLUSTER;
    req.srcEndpoint = ON_AIR_SRC_EP;
    req.asdu = s_asdu;
    req.asduLength = ON_AIR_ASDU_LEN;
    req.txOptions = txOptions;

    return req;
}

/* Every answer the four issues get: `completion status radio-error acked 0 retries 0`, the answer an RCP gives a
 * peer that was never armed with an address of its own, which the seam folds to the one
 * status it carries for a MAC refusal (docs/internals/protocol.md §7.3). */
static void onAirScript(Loopback_Radio *model)
{
    Loopback_Outcome outcomes[ON_AIR_ATTEMPTS];
    uint32_t index;

    Zb_memset(outcomes, 0, (uint32_t)sizeof outcomes);

    for (index = 0; index < ON_AIR_ATTEMPTS; index++)
    {
        outcomes[index].status = ZB_ERR_DEVICE;
        outcomes[index].isAcked = 0;
        outcomes[index].retries = 0;
        outcomes[index].pendingPumps = 0;
    }

    LoopbackRadio_ScriptOutcomes(model, outcomes, ON_AIR_ATTEMPTS);
}

/* One recorded unsecured frame, read as the request its own `field` lines state: a row wired to another
 * transcript reddens here, before any composition is compared against it. */
static void onAirGuardPlain(const uint8_t *mpdu, uint32_t len, uint8_t dsn)
{
    Mac_Frame macFrame;
    Nwk_Frame nwkFrame;
    Aps_Frame apsFrame;
    const uint8_t *npdu;
    uint32_t npduLen;
    uint32_t nsduOffset;
    uint32_t nsduLen;
    uint32_t apduOffset;
    uint32_t apduLen;

    Test_ExpectCount(len, ON_AIR_UNSECURED_LEN, "the unsecured record is 33 octets, as its own line counts it");

    if (MacFrame_Parse(mpdu, len, 1, &macFrame, &npdu, &npduLen, 0) != ZB_OK)
    {
        Test_Fault("the recorded octets do not parse as an 802.15.4 frame");
        return;
    }

    Test_Expect(macFrame.frameType == MAC_FRAME_TYPE_DATA && macFrame.frameVersion == 0
                && macFrame.securityEnabled == 0 && macFrame.ackRequest == 1
                && !macFrame.framePending && macFrame.panIdCompression == 1
                && macFrame.destAddrMode == MAC_ADDR_SHORT && macFrame.srcAddrMode == MAC_ADDR_SHORT
                && macFrame.seq == dsn && macFrame.destPan == ON_AIR_PAN
                && macFrame.destShort == ON_AIR_PEER_SHORT && macFrame.srcShort == ON_AIR_OWN_SHORT
                && npduLen == ON_AIR_UNSECURED_NPDU_LEN,
                "its MHR is data at frame version 0 with MAC security clear, the acknowledgment asked for, one PAN "
                "field, both addresses short, the sequence octet this record prints, PAN 0xbeef, destination 0x1234 "
                "and source 0xdead (7.2.1, Figure 7-2)");

    if (NwkFrame_Parse(npdu, npduLen, &nwkFrame, &nsduOffset, &nsduLen) != ZB_OK)
    {
        Test_Fault("the recorded MAC payload does not parse as a network frame");
        return;
    }

    Test_Expect(nwkFrame.frameType == NWK_FRAME_TYPE_DATA && nwkFrame.protocolVersion == NWK_PROTOCOL_VERSION
                && nwkFrame.securityEnabled == 0 && nwkFrame.sourceRoute == 0
                && nwkFrame.destIeeePresent == 0 && nwkFrame.srcIeeePresent == 0
                && nwkFrame.discoverRoute == NWK_DISCOVER_ENABLE && nwkFrame.endDeviceInitiator == 0
                && nwkFrame.destAddr == ON_AIR_PEER_SHORT && nwkFrame.srcAddr == ON_AIR_OWN_SHORT
                && nwkFrame.radius == NWK_INITIAL_RADIUS && nwkFrame.sequenceNumber == (uint8_t) ON_AIR_SEQ_START
                && nsduOffset == NWK_MIN_HEADER_OVERHEAD && nsduLen == ON_AIR_UNSECURED_NSDU_LEN,
                "the NPDU beneath it is data at protocol version 2 with source routing and security clear and the "
                "route discovery 2.2.8.4.1 obliges the sub-layer to ask for, the addresses the request names, the radius "
                "3.2.1.1.3 derives for a request that named none, and the sequence number 0x11 every one of the four "
                "carries (3.3.1.1-3.3.1.5, Figure 3-4)");

    if (ApsFrame_Parse(npdu + nsduOffset, nsduLen, &apsFrame, &apduOffset, &apduLen) != ZB_OK)
    {
        Test_Fault("the recorded NSDU does not parse as an APS data frame");
        return;
    }

    Test_Expect(apsFrame.frameType == APS_FRAME_TYPE_DATA && apsFrame.deliveryMode == APS_DELIVERY_UNICAST
                && apsFrame.securityEnabled == 0 && apsFrame.ackRequest == 1
                && apsFrame.extendedHeaderPresent == 0 && apsFrame.dstEndpoint == ON_AIR_DST_EP
                && apsFrame.srcEndpoint == ON_AIR_SRC_EP && apsFrame.clusterId == ON_AIR_CLUSTER
                && apsFrame.profileId == ON_AIR_PROFILE && apsFrame.apsCounter == APS_COUNTER_START
                && apduOffset == ON_AIR_DATA_HEADER_LEN && apduLen == ON_AIR_ASDU_LEN
                && mpdu[ON_AIR_OCTET_ASDU] == s_asdu[0]
                && Zb_memcmp(npdu + nsduOffset + apduOffset, s_asdu, ON_AIR_ASDU_LEN) == 0,
                "and the data header is data, unicast, unsecured, the acknowledgment asked for, no extended header, "
                "endpoint 02 at one end and 01 at the other, cluster 0x0006, profile 0x0104 and the counter 00 the "
                "whole transaction keeps, over the six ASDU octets in the clear (2.2.5.1.1-2.2.5.1.7, Figure 2-3)");
}

/* One recorded secured frame, read as far as a secured frame reads without a key: its MHR, its NPDU, and the
 * auxiliary the transcript spells out. What sits behind the MIC is read by the arrival half, at the rig's key. */
static void onAirGuardSecured(const uint8_t *mpdu, uint32_t len, uint8_t dsn, uint8_t auxCounter)
{
    Mac_Frame macFrame;
    Nwk_Frame nwkFrame;
    const uint8_t *npdu;
    uint32_t npduLen;
    uint32_t nsduOffset;
    uint32_t nsduLen;

    Test_ExpectCount(len, ON_AIR_SECURED_LEN, "the secured record is 51 octets, as its own line counts it");

    if (MacFrame_Parse(mpdu, len, 1, &macFrame, &npdu, &npduLen, 0) != ZB_OK)
    {
        Test_Fault("the recorded octets do not parse as an 802.15.4 frame");
        return;
    }

    Test_Expect(macFrame.frameType == MAC_FRAME_TYPE_DATA && macFrame.frameVersion == 0
                && macFrame.securityEnabled == 0 && macFrame.ackRequest == 1
                && macFrame.panIdCompression == 1 && macFrame.destAddrMode == MAC_ADDR_SHORT
                && macFrame.srcAddrMode == MAC_ADDR_SHORT && macFrame.seq == dsn
                && macFrame.destPan == ON_AIR_PAN && macFrame.destShort == ON_AIR_PEER_SHORT
                && macFrame.srcShort == ON_AIR_OWN_SHORT && npduLen == ON_AIR_SECURED_NPDU_LEN,
                "its MHR is the unsecured one octet for octet but for the sequence octet this record prints: MAC "
                "security is not what either of these transactions uses");

    if (NwkFrame_Parse(npdu, npduLen, &nwkFrame, &nsduOffset, &nsduLen) != ZB_OK)
    {
        Test_Fault("the recorded MAC payload does not parse as a secured network frame");
        return;
    }

    Test_Expect(nwkFrame.frameType == NWK_FRAME_TYPE_DATA && nwkFrame.protocolVersion == NWK_PROTOCOL_VERSION
                && nwkFrame.securityEnabled == 1 && nwkFrame.sourceRoute == 0
                && nwkFrame.destIeeePresent == 0 && nwkFrame.srcIeeePresent == 0
                && nwkFrame.destAddr == ON_AIR_PEER_SHORT && nwkFrame.srcAddr == ON_AIR_OWN_SHORT
                && nwkFrame.radius == NWK_INITIAL_RADIUS && nwkFrame.sequenceNumber == (uint8_t) ON_AIR_SEQ_START
                && nsduOffset == NWK_MIN_HEADER_OVERHEAD && nsduLen == ON_AIR_SECURED_NSDU_LEN,
                "its NPDU is those same eight always-present fields with the security bit set: the same addresses, "
                "radius and sequence number: over a payload region the auxiliary, the ciphertext and the MIC "
                "together fill (3.3.1.1, 4.5.1.3)");

    Test_Expect(mpdu[ON_AIR_OCTET_AUX_CONTROL] == 0x28
                && mpdu[ON_AIR_OCTET_AUX_KEY_SEQ] == (uint8_t) ON_AIR_KEY_SEQ
                && mpdu[ON_AIR_OCTET_AUX_COUNTER] == auxCounter
                && mpdu[ON_AIR_OCTET_AUX_COUNTER + 1] == 0
                && mpdu[ON_AIR_OCTET_AUX_COUNTER + 2] == 0
                && mpdu[ON_AIR_OCTET_AUX_COUNTER + 3] == 0,
                "and the auxiliary is control 0x28: level sub-field zero on the air, key id 01 network, extended "
                "nonce set, RVFC clear: carrying the counter this record prints and key sequence 00 (4.5.1.3, "
                "Table 4-38)");

    Test_ExpectHex("with its extended source the factory address this device reported, in the order the air carries "
                   "it",
                   mpdu + ON_AIR_OCTET_AUX_SOURCE, ON_AIR_AUX_SOURCE_LEN, ON_AIR_OWN_IEEE_TRANSMITTED);
}

/* The four MAC issues one request becomes: the ask at the façade, then the turns that collect each answer and
 * issue the retry it arms, counting the records the tee wrote after every turn so the loop is visible as four
 * issues and not as one. */
static void onAirRun(StackDevice *dev, OnAirTee *tee, uint32_t txOptions, Aps_Confirm *confirm,
                     uint32_t *confirmCount)
{
    Aps_ApsdeReq req;
    uint32_t turn;

    Test_BandASeedNeighbor(Zb_LayersNwk(&dev->stack), ON_AIR_PEER_SHORT, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    onAirScript(&dev->model);

    req = onAirRequest(txOptions);

    Test_ExpectStatus(Zb_LayersDataRequest(&dev->stack, &req, ON_AIR_REQUEST_MS), ZB_OK,
                      "the request the transcripts state is accepted by the façade: one call crossing the sub-layer, "
                      "the network layer and the MAC");

    for (turn = 0; turn < ON_AIR_TURNS; turn++)
    {
        Test_ExpectStatus(Zb_LayersStep(&dev->stack, s_turns[turn].nowMs), ZB_OK,
                          "one turn of the three layers, on the clock this case names");
        Test_ExpectCount(tee->records, s_turns[turn].issues,
                         "with the records the tee wrote the count the retry loop owes at that instant: an answer "
                         "collected, and the next attempt due only nwkcUnicastRetryDelay after it (3.2.1.1.3, "
                         "Table 3-65)");
    }

    Test_ExpectCount(tee->txCalls, tee->records, "every record is a call the tee forwarded, and nothing was refused");

    *confirmCount = Zb_LayersPollConfirms(&dev->stack, confirm, 1);
}

/* The answer one transaction ends with, in both runs. */
static void onAirConfirm(const Aps_Confirm *confirm, uint32_t confirmCount)
{
    Test_ExpectCount(confirmCount, 1, "and the four issues answer as one transaction, with one confirmation");
    Test_ExpectStatus(confirm->status, ZB_ERR_DEVICE, "carrying the seam's own word up unchanged");
    Test_ExpectCount(confirm->apsStatus, APS_STATUS_LAST_SEAM_STATUS,
                     "beside the network layer's sentinel, the code it writes when no Table 3-84 word of its own "
                     "names the answer it was given");
    Test_ExpectCount(confirm->apsCounter, APS_COUNTER_START,
                     "for the one transaction, at the one counter it ran under");
    Test_ExpectCount(confirm->attempts, 1,
                     "with one attempt as this layer counts attempts: the failed confirmation answered first, so no "
                     "acknowledgment wait was ever started and no retransmission ran (docs/internals/conformance.md §3)");
    Test_Expect(confirm->dstAddrMode == APS_ADDR_MODE_SHORT && confirm->dstAddress == ON_AIR_PEER_SHORT
                && confirm->dstEndpoint == ON_AIR_DST_EP && confirm->srcEndpoint == ON_AIR_SRC_EP
                && confirm->profileId == ON_AIR_PROFILE && confirm->clusterId == ON_AIR_CLUSTER,
                "and naming the transaction it answers with the parameters the request gave it");
}

/* The four frames of one run against the four records of its transcript. */
static void onAirAttemptsAreTheRecords(const OnAirTee *tee, const uint8_t *records, const uint32_t *recordLens,
                                       uint32_t secured)
{
    uint32_t index;
    uint32_t offset;
    uint32_t differing;
    const OnAirTeeRecord *attempt;
    const uint8_t *record;

    for (index = 0; index < ON_AIR_ATTEMPTS; index++)
    {
        attempt = &tee->record[index];
        record = records + (index * RADIO_MPDU_MAX);

        Test_ExpectOctets(s_attempts[index].name, attempt->bytes, attempt->len, record, recordLens[index]);
        Test_ExpectCount(attempt->ackRequest, 1,
                         "every one of them handed the seam asking for the acknowledgment a unicast of this shape "
                         "asks for (3.2.1.1.3 step 6)");
        Test_ExpectCount(attempt->handle, s_attempts[index].handle,
                         "at the handle its record prints beside the octets: four issues, four handles, one after "
                         "the other");
        Test_Expect(attempt->bytes[ON_AIR_OCTET_DSN] == s_attempts[index].dsn,
                    "with the sequence octet advancing 0x21 0x22 0x23 0x24, each attempt a fresh MAC issue (7.2.3)");
        Test_Expect(attempt->bytes[ON_AIR_OCTET_NWK_SEQ] == (uint8_t) ON_AIR_SEQ_START
                    && attempt->bytes[ON_AIR_OCTET_NWK_RADIUS] == (uint8_t) NWK_INITIAL_RADIUS,
                    "while the network layer's number stands at the seeded 0x11 and its radius at 30 across all "
                    "four: the same frame re-offered, each time under a new MAC number (3.3.1.5)");

        if (secured)
        {
            Test_Expect(attempt->bytes[ON_AIR_OCTET_AUX_COUNTER] == s_attempts[index].auxCounter,
                        "and every attempt re-protected at the next outgoing counter: 00 00 00 00, 01 00 00 00, "
                        "02 00 00 00, 03 00 00 00 (4.3.1.1 step 7)");
            Test_ExpectHex("with the four-octet tag this run produced, the same one a dissector that had never seen "
                           "this source read at the trailing octets before the footer",
                           attempt->bytes + ON_AIR_OCTET_MIC, ON_AIR_MIC_LEN, s_mics[index]);
        }
        else
        {
            Test_Expect(attempt->bytes[ON_AIR_OCTET_APS_COUNTER] == (uint8_t) APS_COUNTER_START,
                        "while the sub-layer's counter stands at 00 in all four, the four frames being one "
                        "transaction (2.2.5.1.7)");
        }

        Test_ExpectStatus(MacFrame_CheckFcs(attempt->bytes, attempt->len), ZB_OK,
                          "the footer of what this stack composed validates over the octets ahead of it");
        Test_ExpectStatus(MacFrame_CheckFcs(record, recordLens[index]), ZB_OK,
                          "and so does the footer the transcript wrote, which is what those two octets are: this "
                          "host's arithmetic agreeing with what the device regenerated. An RCP is measured "
                          "replacing the footer it is handed, so the match is no claim about what "
                          "the silicon emitted (7.2.11)");
    }

    if (!secured)
        return;

    for (index = 1; index < ON_AIR_ATTEMPTS; index++)
    {
        differing = 0;

        for (offset = 0; offset < ON_AIR_HEADER_AHEAD_OF_AUX; offset++)
        {
            if (offset == ON_AIR_OCTET_DSN)
                continue;

            if (tee->record[index].bytes[offset] != tee->record[0].bytes[offset])
                differing++;
        }

        Test_ExpectCount(differing, 0,
                         "every header octet ahead of the auxiliary is the same in all four secured frames, the "
                         "sequence octet the MAC numbers per issue aside");

        differing = 0;

        for (offset = ON_AIR_OCTET_CIPHER; offset < ON_AIR_SECURED_LEN; offset++)
        {
            if (tee->record[index].bytes[offset] != tee->record[0].bytes[offset])
                differing++;
        }

        Test_Expect(differing >= ON_AIR_MIC_LEN,
                    "and the region from the ciphertext to the footer is not one run of octets carried four times: "
                    "each issue is a fresh protection of the same authenticated string (4.3.1.1 step 7)");
    }
}

/* Whether a run of octets contains another: what the secured transcripts prove of their own cleartext. */
static int onAirContains(const uint8_t *haystack, uint32_t haystackLen, const uint8_t *needle, uint32_t needleLen)
{
    uint32_t start;
    uint32_t offset;

    if (needleLen > haystackLen)
        return 1;

    for (start = 0; start + needleLen <= haystackLen; start++)
    {
        offset = 0;

        while (offset < needleLen && haystack[start + offset] == needle[offset])
            offset++;

        if (offset == needleLen)
            return 1;
    }

    return 0;
}

/* The eight copies of the peer's window, laid into the specs one injection takes, with no metadata the transcript
 * does not name. */
static void onAirSpecs(Loopback_FrameSpec *specs, const uint8_t *copies, const uint32_t *copyLens)
{
    uint32_t index;

    for (index = 0; index < ON_AIR_COPIES; index++)
    {
        Zb_memset(&specs[index], 0, (uint32_t)sizeof specs[index]);

        specs[index].len = copyLens[index];
        specs[index].bytes = copies + (index * RADIO_MPDU_MAX);
        specs[index].rssiDbm = ON_AIR_COPY_RSSI_DBM;
        specs[index].stampTicks = index + 1;
        specs[index].error = ZB_OK;
    }
}

/* The device the transcripts built, as the identity they print rather than as anything this case improvised. */
void caseOnAirRigIsTheRecordedDevice(void)
{
    StackDevice plain;
    StackDevice secured;
    const Radio_Pib *mirror;
    Radio_Pib read;
    Radio_Pib writes[LOOPBACK_PIB_WRITE_MAX];
    Zb_State state;
    uint32_t writeCount;

    onAirDevice(&plain, ON_AIR_OWN_SHORT, 0);
    onAirDevice(&secured, ON_AIR_OWN_SHORT, 1);

    Test_ExpectStatus(stackInit(&plain), ZB_OK,
                      "the unsecured run's device builds: a coordinator with no security config and no key material");
    Test_ExpectStatus(stackInit(&secured), ZB_OK,
                      "and the secured run's device builds on the same identity, at the level, key sequence and key "
                      "the secured transcript prints");

    Test_ExpectStatus(LoopbackRadio_Seam(&secured.model)->ops->pibGet(LoopbackRadio_Seam(&secured.model), &read),
                      ZB_OK, "the backend answers a read of the identity it holds");
    Test_Expect(read.channel == ON_AIR_CHANNEL && read.panId == ON_AIR_PAN
                && read.shortAddress == ON_AIR_OWN_SHORT && read.rxOnWhenIdle == 1,
                "channel 26, PAN 0xbeef, short 0xdead, rxOnWhenIdle 1: the four the `armed` line read back off the "
                "RCP after band A's own write reached it");
    Test_ExpectHex("and the extended address the model scripts where an RCP's silicon carries its factory one, in "
                   "the PIB's octet order",
                   read.hwAddress, RADIO_ADDR_LEN, ON_AIR_OWN_IEEE_TRANSMITTED);

    writeCount = LoopbackRadio_PibWrites(&secured.model, writes, LOOPBACK_PIB_WRITE_MAX);
    Test_Expect(writeCount > 0 && (writes[0].present & RADIO_PIB_HW_ADDRESS) == 0,
                 "and the identity write the façade made names no factory field: that address is read off the "
                 "device and never written to it");

    mirror = Mac_Pib(Zb_LayersMac(&secured.stack));
    Test_Expect(mirror->channel == ON_AIR_CHANNEL && mirror->panId == ON_AIR_PAN
                && mirror->shortAddress == ON_AIR_OWN_SHORT && mirror->rxOnWhenIdle == 1,
                 "with the same four in the mirror every frame this device composes is composed from");

    Test_ExpectStatus(Zb_LayersCapture(&secured.stack, 1, &state), ZB_OK, "the secured device read back as state");
    Test_Expect(state.ownIeee == ON_AIR_OWN_IEEE && state.nwkSecurityLevel == ON_AIR_LEVEL
                && state.nwkActiveKeySeqNumber == ON_AIR_KEY_SEQ && state.authenticated == 1
                && state.nwkAllFresh == 1,
                "ownIeee 0x00212effff048a12: the address the device reports, which is what a security config is "
                "bound to: at level 0x05, key sequence 00, joined and authenticated, all-fresh");
    Test_ExpectCount(state.keyCount, 1,
                     "one descriptor: the whole material set either secured half of this file runs on");
    Test_Expect(state.keys[0].keyPresent == 1 && state.keys[0].keySeqNumber == ON_AIR_KEY_SEQ
                && Zb_memcmp(state.keys[0].key, s_networkKey, SECURITY_KEY_OCTETS) == 0
                && state.keys[0].outgoingFrameCounter == 0,
                "holding the sixteen key octets the transcript prints, at sequence 00, its outgoing counter standing "
                "at 0: the counter the first recorded frame carries");

    Test_ExpectStatus(Zb_LayersCapture(&plain.stack, 1, &state), ZB_OK, "the unsecured device read back as state");
    Test_Expect(state.ownIeee == 0 && state.nwkSecurityLevel == SECURITY_LEVEL_NONE
                && state.keyCount == 0 && Security_IsEnabled(Zb_LayersSecurity(&plain.stack)) == 0,
                "level 0x00 with no security config and no key material anywhere: the scaffold its `security` line "
                "states, its security module never initialised and so reporting no ownIeee of its own");
    Test_ExpectStatus(LoopbackRadio_Seam(&plain.model)->ops->pibGet(LoopbackRadio_Seam(&plain.model), &read),
                      ZB_OK, "and the identity that device was armed with is the same one, read through its seam");
    Test_Expect(read.channel == ON_AIR_CHANNEL && read.panId == ON_AIR_PAN
                && read.shortAddress == ON_AIR_OWN_SHORT && read.rxOnWhenIdle == 1,
                "channel, PAN, short address and receiver duty as the transcripts print them");
    Test_ExpectHex("with the extended address the config named written into the PIB, in the order the air carries it",
                   read.extendedAddress, RADIO_ADDR_LEN, ON_AIR_OWN_IEEE_TRANSMITTED);
    Test_Expect(state.nwkSequenceNumber == ON_AIR_SEQ_START && state.macDsn == ON_AIR_DSN_START
                && state.apsCounter == APS_COUNTER_START,
                "and the three seeds as the transcripts print them, read where the layers keep them: network "
                "sequence 0x11, MAC sequence 0x21, and the first counter the sub-layer hands out");
}

/* The unsecured run: one request on the rig's device, and the four frames it put on the air. */
void caseOnAirUnsecuredFramesAreTheRecordedOctets(void)
{
    StackDevice dev;
    OnAirTee tee;
    Aps_Indication indications[APS_INDICATION_MAX];
    Aps_Confirm confirm;
    Zb_State before;
    Zb_State after;
    uint8_t records[ON_AIR_ATTEMPTS * RADIO_MPDU_MAX];
    uint32_t recordLens[ON_AIR_ATTEMPTS];
    uint32_t confirmCount;
    uint32_t index;

    if (onAirLoad(ON_AIR_TX_PLAIN, records, recordLens, ON_AIR_ATTEMPTS) != ON_AIR_ATTEMPTS)
        return;

    for (index = 0; index < ON_AIR_ATTEMPTS; index++)
        onAirGuardPlain(records + (index * RADIO_MPDU_MAX), recordLens[index], s_attempts[index].dsn);

    onAirDevice(&dev, ON_AIR_OWN_SHORT, 0);

    Test_ExpectStatus(onAirInit(&dev, &tee), ZB_OK, "the device the unsecured run built, its seam behind a tee");

    Test_ExpectStatus(Zb_LayersCapture(&dev.stack, 0, &before), ZB_OK, "its numbering before the request");
    Test_ExpectCount(before.nwkSequenceNumber, ON_AIR_SEQ_START, "the seeded network sequence");
    Test_ExpectCount(before.macDsn, ON_AIR_DSN_START, "the seeded MAC sequence");
    Test_ExpectCount(before.apsCounter, APS_COUNTER_START, "and the first counter the sub-layer hands out");

    onAirRun(&dev, &tee, ON_AIR_TX_OPTIONS_PLAIN, &confirm, &confirmCount);

    Test_ExpectCount(tee.records, ON_AIR_ATTEMPTS,
                     "four frames reached the backend for one request: the four tee records the transcript counts");

    onAirAttemptsAreTheRecords(&tee, records, recordLens, 0);

    for (index = 0; index < ON_AIR_ATTEMPTS; index++)
        onAirGuardPlain(tee.record[index].bytes, tee.record[index].len, s_attempts[index].dsn);

    onAirConfirm(&confirm, confirmCount);

    Test_ExpectStatus(Zb_LayersCapture(&dev.stack, 0, &after), ZB_OK, "and the numbering after it");
    Test_ExpectCount(after.nwkSequenceNumber, before.nwkSequenceNumber + 1,
                     "the network layer's number moved once for four frames, because a retry takes no new one "
                     "(3.3.1.5)");
    Test_ExpectCount(after.macDsn, before.macDsn + ON_AIR_ATTEMPTS, "the MAC's own number moved with every issue");
    Test_ExpectCount(after.apsCounter, before.apsCounter + 1,
                     "and the sub-layer's once, for the one transaction all four frames carry");
    Test_ExpectCount(Zb_LayersPollIndications(&dev.stack, indications, APS_INDICATION_MAX), 0,
                     "with nothing delivered to the device that sent them");
    Test_Expect(LoopbackRadio_Queued(&dev.model) == 0 && LoopbackRadio_Refusals(&dev.model) == 0,
                "and the backend was handed four transmits and refused nothing of its own");
}

/* The secured run: the same request at TxOptions 0x06, four protected frames, one transaction. */
void caseOnAirSecuredFramesAreTheRecordedOctets(void)
{
    StackDevice dev;
    OnAirTee tee;
    Aps_Indication indications[APS_INDICATION_MAX];
    Aps_Confirm confirm;
    Zb_State state;
    uint8_t records[ON_AIR_ATTEMPTS * RADIO_MPDU_MAX];
    uint32_t recordLens[ON_AIR_ATTEMPTS];
    uint32_t confirmCount;
    uint32_t index;

    if (onAirLoad(ON_AIR_TX_SECURED, records, recordLens, ON_AIR_ATTEMPTS) != ON_AIR_ATTEMPTS)
        return;

    for (index = 0; index < ON_AIR_ATTEMPTS; index++)
        onAirGuardSecured(records + (index * RADIO_MPDU_MAX), recordLens[index], s_attempts[index].dsn,
                          s_attempts[index].auxCounter);

    onAirDevice(&dev, ON_AIR_OWN_SHORT, 1);

    Test_ExpectStatus(onAirInit(&dev, &tee), ZB_OK,
                      "the device the secured run built, at level 0x05 with the rig's key, its seam behind a tee");

    onAirRun(&dev, &tee, ON_AIR_TX_OPTIONS_SECURED, &confirm, &confirmCount);

    Test_ExpectCount(tee.records, ON_AIR_ATTEMPTS,
                     "four frames again for one request: TxOptions 0x06 asked the network layer to protect each "
                     "issue of it (Table 2-2, 3.2.1.1.3)");

    onAirAttemptsAreTheRecords(&tee, records, recordLens, 1);

    for (index = 0; index < ON_AIR_ATTEMPTS; index++)
    {
        onAirGuardSecured(tee.record[index].bytes, tee.record[index].len, s_attempts[index].dsn,
                          s_attempts[index].auxCounter);

        Test_Expect(!onAirContains(tee.record[index].bytes, tee.record[index].len, s_asdu, ON_AIR_ASDU_LEN),
                    "and the six ASDU octets appear nowhere in the 51 octets handed the seam: what the MIC stands "
                    "for is protected, not copied");
    }

    onAirConfirm(&confirm, confirmCount);

    Test_ExpectStatus(Zb_LayersCapture(&dev.stack, 1, &state), ZB_OK, "the security state after the run");
    Test_ExpectCount(state.keyCount, 1, "the one descriptor the device was built with");
    Test_ExpectCount(state.keys[0].outgoingFrameCounter, ON_AIR_ATTEMPTS,
                     "its outgoing counter spent four times, the frames having carried 00, 01, 02 and 03 "
                     "(4.3.1.1 step 7)");
    Test_ExpectCount(state.nwkSequenceNumber, ON_AIR_SEQ_START + 1,
                     "with the network sequence number one past its seed: one number for the whole transaction");
    Test_ExpectCount(state.apsCounter, APS_COUNTER_START + 1, "and one counter spent at the sub-layer");
    Test_ExpectCount(Nwk_TxSecurityFailures(Zb_LayersNwk(&dev.stack)), 0,
                     "and no protection refused on the way: every attempt was secured");
    Test_ExpectCount(Zb_LayersPollIndications(&dev.stack, indications, APS_INDICATION_MAX), 0,
                     "with nothing delivered to the device that sent them");
}

/* The peer's window as a fixture: eight frames, each one the tee record its own transcript says it is. */
void caseOnAirCopiesAreTheRecordedFrames(void)
{
    uint8_t copies[ON_AIR_COPIES * RADIO_MPDU_MAX];
    uint32_t copyLens[ON_AIR_COPIES];
    uint8_t plain[ON_AIR_ATTEMPTS * RADIO_MPDU_MAX];
    uint32_t plainLens[ON_AIR_ATTEMPTS];
    uint8_t secured[ON_AIR_ATTEMPTS * RADIO_MPDU_MAX];
    uint32_t securedLens[ON_AIR_ATTEMPTS];
    const uint8_t *record;
    uint32_t recordLen;
    uint32_t index;

    if (onAirLoad(ON_AIR_RX_COPIES, copies, copyLens, ON_AIR_COPIES) != ON_AIR_COPIES)
        return;

    if (onAirLoad(ON_AIR_TX_PLAIN, plain, plainLens, ON_AIR_ATTEMPTS) != ON_AIR_ATTEMPTS)
        return;

    if (onAirLoad(ON_AIR_TX_SECURED, secured, securedLens, ON_AIR_ATTEMPTS) != ON_AIR_ATTEMPTS)
        return;

    for (index = 0; index < ON_AIR_COPIES; index++)
    {
        if (s_copies[index].secured)
        {
            record = secured + (s_copies[index].teeRow * RADIO_MPDU_MAX);
            recordLen = securedLens[s_copies[index].teeRow];
        }
        else
        {
            record = plain + (s_copies[index].teeRow * RADIO_MPDU_MAX);
            recordLen = plainLens[s_copies[index].teeRow];
        }

        Test_ExpectCount(copyLens[index], s_copies[index].len, "the peer's line counts this copy as long as it is");
        Test_ExpectOctets(s_copies[index].name, copies + (index * RADIO_MPDU_MAX), copyLens[index], record,
                          recordLen);

        if (s_copies[index].secured)
            onAirGuardSecured(copies + (index * RADIO_MPDU_MAX), copyLens[index], s_copies[index].dsn,
                              s_copies[index].auxCounter);
        else
            onAirGuardPlain(copies + (index * RADIO_MPDU_MAX), copyLens[index], s_copies[index].dsn);

        Test_ExpectStatus(MacFrame_CheckFcs(copies + (index * RADIO_MPDU_MAX), copyLens[index]), ZB_OK,
                          "and every copy the peer delivered is FCS-valid here too, which is what the transcript "
                          "reports from the receiving RCP");
    }

    Test_ExpectCount(ON_AIR_COPIES, ON_AIR_UNSECURED_COPIES + ON_AIR_SECURED_COPIES,
                     "eight copies: every attempt of both runs, each delivered");
    Test_Expect(s_copies[4].auxCounter == 0x00 && s_copies[5].auxCounter == 0x01
                && s_copies[6].auxCounter == 0x02 && s_copies[7].auxCounter == 0x03,
                "the four secured copies carrying counters 00, 01, 02 and 03 at DSN 0x21, 0x22, 0x23 and 0x24, the "
                "1 + apscMaxFrameRetries walk in order and each one re-protected at its own counter "
                "(2.2.8.4.4's last sentence)");
}

/* The eight copies put in front of the device that sent them: the rig's own identity, short 0xdead. A frame
 * cannot arrive from the device that would have transmitted it, so band A consumes them where they are read and
 * the network layer never hears of them. */
void caseOnAirCopiesArriveAtTheSendingDevice(void)
{
    StackDevice plain;
    StackDevice secured;
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Aps_Indication indications[APS_INDICATION_MAX];
    Loopback_FrameSpec specs[ON_AIR_COPIES];
    Zb_State state;
    uint8_t copies[ON_AIR_COPIES * RADIO_MPDU_MAX];
    uint32_t copyLens[ON_AIR_COPIES];
    Mac_Counters plainCounters;
    Mac_Counters securedCounters;

    if (onAirLoad(ON_AIR_RX_COPIES, copies, copyLens, ON_AIR_COPIES) != ON_AIR_COPIES)
        return;

    onAirSpecs(specs, copies, copyLens);

    onAirDevice(&plain, ON_AIR_OWN_SHORT, 0);

    Test_ExpectStatus(stackInit(&plain), ZB_OK, "the unsecured run's own device, at short 0xdead in PAN 0xbeef");

    Test_ExpectStatus(LoopbackRadio_Inject(&plain.model, specs, ON_AIR_COPIES), ZB_OK,
                      "the eight copies are put in front of it, at one invented level and with no other metadata "
                      "invented for them");
    Test_ExpectStatus(Zb_LayersStep(&plain.stack, ON_AIR_REQUEST_MS), ZB_OK, "and one turn takes the batch");

    Test_ExpectCount(LoopbackRadio_Queued(&plain.model), 0,
                     "the MAC took all eight off the backend: it hands up what it read as a data frame and leaves "
                     "the destination to the layer above");
    Test_ExpectCount(Zb_LayersPollIndications(&plain.stack, indications, APS_INDICATION_MAX), 0,
                     "and the façade reports no indication for any of them");
    plainCounters = Mac_CountersOf(Zb_LayersMac(&plain.stack));
    Test_ExpectCount(plainCounters.selfEchoes, ON_AIR_COPIES,
                     "every one of the eight names this device as its source, so the MAC consumed it as an echo of a "
                     "transmission rather than an arrival: a radio does not put what it transmits on its own receive "
                     "path, and an RCP that hands one back must not be read as the air");
    Test_ExpectCount(Nwk_DroppedNoRoute(Zb_LayersNwk(&plain.stack)), 0,
                     "so the network layer was handed nothing to discard for want of a route (3.6.4.3)");
    Test_ExpectCount(Nwk_DroppedUnsupported(Zb_LayersNwk(&plain.stack)), 0,
                     "and nothing to refuse as unreadable (4.3.1.2, docs/internals/conformance.md §2)");
    Test_ExpectCount(Nwk_RxSecurityFailures(Zb_LayersNwk(&plain.stack)), 0,
                     "no authentication failure is counted, because none was attempted");
    Test_ExpectCount(Nwk_RelaysSent(Zb_LayersNwk(&plain.stack)), 0,
                     "and nothing was carried onward: the discard is the whole of the act");
    Test_ExpectCount(LoopbackRadio_Sent(&plain.model, sent, LOOPBACK_TX_MAX), 0, "with nothing put on the air");
    Test_ExpectStatus(Zb_LayersStep(&plain.stack, ON_AIR_REQUEST_MS + 1), ZB_OK, "a further turn finds nothing left");
    Test_ExpectCount(Zb_LayersPollIndications(&plain.stack, indications, APS_INDICATION_MAX), 0,
                     "and still reports no indication");

    onAirDevice(&secured, ON_AIR_OWN_SHORT, 1);

    Test_ExpectStatus(stackInit(&secured), ZB_OK, "the secured run's own device: same identity, level 0x05");

    Test_ExpectStatus(LoopbackRadio_Inject(&secured.model, specs, ON_AIR_COPIES), ZB_OK,
                      "the same eight copies, at the device that holds the rig's network key");
    Test_ExpectStatus(Zb_LayersStep(&secured.stack, ON_AIR_REQUEST_MS), ZB_OK, "one turn decides all eight");

    securedCounters = Mac_CountersOf(Zb_LayersMac(&secured.stack));
    Test_ExpectCount(securedCounters.selfEchoes, ON_AIR_COPIES,
                     "the same eight are echoes here too, and the security module is not asked about any of them");
    Test_ExpectCount(Nwk_DroppedUnsecured(Zb_LayersNwk(&secured.stack)), 0,
                     "so nothing is discarded at 3.6.2.2 for arriving unsecured while this device is authenticated");
    Test_Expect(Nwk_RxSecurityFailures(Zb_LayersNwk(&secured.stack)) == 0
                && Nwk_RxFrameCounterRejects(Zb_LayersNwk(&secured.stack)) == 0,
                "and nothing authenticates: no failure, no counter refusal");
    Test_ExpectCount(Nwk_DroppedNoRoute(Zb_LayersNwk(&secured.stack)), 0,
                     "no route discard either, because the frame never became one");
    Test_ExpectCount(Zb_LayersPollIndications(&secured.stack, indications, APS_INDICATION_MAX), 0,
                     "so the façade reports no indication for any of the eight");
    Test_ExpectCount(LoopbackRadio_Sent(&secured.model, sent, LOOPBACK_TX_MAX), 0,
                     "and this device composed nothing: a frame it consumes owes no answer");

    Test_ExpectStatus(Zb_LayersCapture(&secured.stack, 1, &state), ZB_OK,
                      "what the arrivals left in the security module");
    Test_ExpectCount(state.windowCount, 0,
                     "no incoming window: a frame this device is the source of is not unprotected, so 4.3.1.2's "
                     "count is never advanced by it");
}

/* The eight copies put in front of a device at the destination every one of them names: 0x1234, the same PAN,
 * channel, seeds and (for the secured half) the same key. */
void caseOnAirCopiesArriveAtTheRecordedDestination(void)
{
    StackDevice plain;
    StackDevice secured;
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Aps_Indication indications[APS_INDICATION_MAX];
    Loopback_FrameSpec specs[ON_AIR_COPIES];
    Mac_Frame macFrame;
    Nwk_Frame nwkFrame;
    Aps_Frame apsFrame;
    Zb_State state;
    const uint8_t *npdu;
    uint8_t copies[ON_AIR_COPIES * RADIO_MPDU_MAX];
    uint32_t copyLens[ON_AIR_COPIES];
    uint32_t npduLen;
    uint32_t nsduOffset;
    uint32_t nsduLen;
    uint32_t apduOffset;
    uint32_t apduLen;
    uint32_t index;

    if (onAirLoad(ON_AIR_RX_COPIES, copies, copyLens, ON_AIR_COPIES) != ON_AIR_COPIES)
        return;

    onAirSpecs(specs, copies, copyLens);

    /* The unsecured family, at a device with the unsecured run's config: four issues of one transaction, and one
     * transaction is one delivery. */
    onAirDevice(&plain, ON_AIR_PEER_SHORT, 0);

    Test_ExpectStatus(stackInit(&plain), ZB_OK,
                      "a device at 0x1234 (the destination every recorded frame names) on the unsecured run's "
                      "config");

    Test_ExpectStatus(LoopbackRadio_Inject(&plain.model, specs, ON_AIR_COPIES), ZB_OK, "the eight copies go in");
    Test_ExpectStatus(Zb_LayersStep(&plain.stack, ON_AIR_REQUEST_MS), ZB_OK, "and one turn decides them");

    Test_ExpectCount(Zb_LayersPollIndications(&plain.stack, indications, APS_INDICATION_MAX), 1,
                     "one indication at the façade: the first copy of the transaction");
    Test_Expect(indications[0].dstAddrMode == APS_ADDR_MODE_SHORT
                && indications[0].dstAddress == ON_AIR_PEER_SHORT
                && indications[0].srcAddrMode == APS_ADDR_MODE_SHORT
                && indications[0].srcAddress == ON_AIR_OWN_SHORT
                && indications[0].dstEndpoint == ON_AIR_DST_EP
                && indications[0].srcEndpoint == ON_AIR_SRC_EP
                && indications[0].profileId == ON_AIR_PROFILE && indications[0].clusterId == ON_AIR_CLUSTER
                && indications[0].status == APS_STATUS_SUCCESS,
                "aimed at this device from the address that sent it, endpoint 02 from endpoint 01, cluster 0x0006, "
                "profile 0x0104, Table 2-4's SUCCESS (2.2.4.1.3.2)");
    Test_ExpectCount(indications[0].asduLength, ON_AIR_ASDU_LEN, "and an ASDU as long as the request named");
    Test_ExpectOctets("carrying the six octets it was sent with, in the clear where the data header put them",
                      indications[0].asdu, indications[0].asduLength, s_asdu, ON_AIR_ASDU_LEN);
    Test_ExpectCount(Aps_RxDuplicateDrops(Zb_LayersAps(&plain.stack)), ON_AIR_UNSECURED_COPIES - 1,
                     "with the other three copies of the same (source, APS counter) key dropped as duplicates and "
                     "indicated none of them (2.2.8.4.2)");
    Test_ExpectCount(Aps_IndicationQueue(Zb_LayersAps(&plain.stack)), 0,
                     "and no further delivery waiting at the sub-layer");
    Test_ExpectCount(Nwk_DroppedUnsupported(Zb_LayersNwk(&plain.stack)), ON_AIR_SECURED_COPIES,
                     "while the three secured copies are refused as unreadable, this device holding no key to read "
                     "them with");
    Test_Expect(Nwk_DroppedNoRoute(Zb_LayersNwk(&plain.stack)) == 0
                && Nwk_DroppedNotForMe(Zb_LayersNwk(&plain.stack)) == 0,
                "and none of the eight counted as a frame this device was not the end of: the destination field in "
                "every one of them names this device");

    Test_ExpectCount(Aps_AcksGenerated(Zb_LayersAps(&plain.stack)), ON_AIR_COPIES - ON_AIR_SECURED_COPIES,
                     "one acknowledgement per copy received: 2.2.8.4.3.2's 'SHALL be acknowledged' is unqualified, and "
                     "the clause that suppresses the duplicate suppresses the delivery alone (2.2.8.4.2)");
    Test_ExpectCount(LoopbackRadio_Sent(&plain.model, sent, LOOPBACK_TX_MAX), ON_AIR_COPIES - ON_AIR_SECURED_COPIES,
                     "and those acknowledgements are the only frames this device put on its own air");

    if (MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &macFrame, &npdu, &npduLen, 0) == ZB_OK
        && NwkFrame_Parse(npdu, npduLen, &nwkFrame, &nsduOffset, &nsduLen) == ZB_OK
        && ApsFrame_Parse(npdu + nsduOffset, nsduLen, &apsFrame, &apduOffset, &apduLen) == ZB_OK)
    {
        Test_Expect(macFrame.destShort == ON_AIR_OWN_SHORT && macFrame.srcShort == ON_AIR_PEER_SHORT
                    && nwkFrame.destAddr == ON_AIR_OWN_SHORT && nwkFrame.srcAddr == ON_AIR_PEER_SHORT,
                    "carried back to the address the recorded frames came from (2.2.5.2.3.1)");
        Test_Expect(apsFrame.frameType == APS_FRAME_TYPE_ACK && apsFrame.ackRequest == 0
                    && apsFrame.dstEndpoint == ON_AIR_SRC_EP && apsFrame.srcEndpoint == ON_AIR_DST_EP
                    && apsFrame.clusterId == ON_AIR_CLUSTER && apsFrame.profileId == ON_AIR_PROFILE
                    && apsFrame.apsCounter == APS_COUNTER_START,
                    "as an acknowledgement in Figure 2-8's shape: nothing asked for, the endpoints swapped, and the "
                    "cluster, profile and counter of the transaction it answers");
    }
    else
    {
        Test_Fault("the acknowledgement this device owes does not read as a frame at all");
    }

    /* The secured family, at a device with the secured run's config: the rig's key at the rig's level. */
    onAirDevice(&secured, ON_AIR_PEER_SHORT, 1);

    Test_ExpectStatus(stackInit(&secured), ZB_OK,
                      "and the same destination at the secured run's config: level 0x05, key sequence 00, the rig's "
                      "network key");

    Test_ExpectStatus(LoopbackRadio_Inject(&secured.model, specs, ON_AIR_COPIES), ZB_OK, "the same eight copies");
    Test_ExpectStatus(Zb_LayersStep(&secured.stack, ON_AIR_REQUEST_MS), ZB_OK, "one turn decides them");

    Test_ExpectCount(Nwk_DroppedUnsecured(Zb_LayersNwk(&secured.stack)), ON_AIR_UNSECURED_COPIES,
                     "the four unsecured copies are discarded here at a joined, authenticated device (3.6.2.2): "
                     "what a promiscuous listener delivered, this device will not take");
    Test_Expect(Nwk_RxSecurityFailures(Zb_LayersNwk(&secured.stack)) == 0
                && Nwk_RxFrameCounterRejects(Zb_LayersNwk(&secured.stack)) == 0,
                "while all three secured ones authenticate at the rig's network key, each at its own counter");
    Test_ExpectCount(Zb_LayersPollIndications(&secured.stack, indications, APS_INDICATION_MAX), 1,
                     "and one of them is delivered");
    Test_ExpectCount(indications[0].asduLength, ON_AIR_ASDU_LEN, "with an ASDU as long as the one that was sent");
    Test_ExpectOctets("and the six octets the request named, recovered from behind the MIC rather than read out of "
                      "the frame's own octets",
                      indications[0].asdu, indications[0].asduLength, s_asdu, ON_AIR_ASDU_LEN);
    Test_Expect(indications[0].dstEndpoint == ON_AIR_DST_EP && indications[0].srcEndpoint == ON_AIR_SRC_EP
                && indications[0].clusterId == ON_AIR_CLUSTER && indications[0].profileId == ON_AIR_PROFILE
                && indications[0].srcAddress == ON_AIR_OWN_SHORT
                && indications[0].status == APS_STATUS_SUCCESS,
                "under the data header that unprotection recovers: endpoint 02, endpoint 01, cluster 0x0006, "
                "profile 0x0104, counter 00: the APDU the secured transcript states and this device authenticated");
    Test_ExpectCount(Aps_RxDuplicateDrops(Zb_LayersAps(&secured.stack)), ON_AIR_SECURED_COPIES - 1,
                     "with the other two secured copies counted as duplicates of that transaction after they "
                     "authenticated (2.2.8.4.2, 4.3.1.2 step 6)");
    Test_ExpectCount(Aps_AcksGenerated(Zb_LayersAps(&secured.stack)), ON_AIR_SECURED_COPIES,
                     "and one acknowledgement per secured copy, the delivery being the one thing the duplicate rule "
                     "suppresses (2.2.8.4.2, 2.2.8.4.3.2)");
    Test_ExpectCount(LoopbackRadio_Sent(&secured.model, sent, LOOPBACK_TX_MAX), ON_AIR_SECURED_COPIES,
                     "issued as the four frames this device put on its air, one acknowledgement per authenticated copy");

    for (index = ON_AIR_UNSECURED_COPIES; index < ON_AIR_COPIES; index++)
        Test_Expect(!onAirContains(copies + (index * RADIO_MPDU_MAX), copyLens[index], s_asdu, ON_AIR_ASDU_LEN),
                    "and the six cleartext octets appear nowhere in the copy this device recovered them from");

    Test_ExpectStatus(Zb_LayersCapture(&secured.stack, 1, &state), ZB_OK, "what the three arrivals left behind");
    Test_ExpectCount(state.windowCount, 1, "one incoming window");
    Test_Expect(state.windows[0].senderIeee == ON_AIR_OWN_IEEE
                && state.windows[0].keySeqNumber == ON_AIR_KEY_SEQ
                && state.windows[0].frameCounter == ON_AIR_ATTEMPTS,
                "for the sender the auxiliary headers name, standing at 4: the next count it refuses, one past the "
                "00, 01 and 03 it authenticated");
    Test_ExpectCount(state.nwkSequenceNumber, ON_AIR_SEQ_START + ON_AIR_SECURED_COPIES,
                     "a network sequence number spent per acknowledgement, four of them");
}
