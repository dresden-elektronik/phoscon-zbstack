#define _POSIX_C_SOURCE 200809    /* nanosleep is POSIX; glibc hides it under -std=c99 without this, before any include */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aps.h"
#include "aps_frame.h"
#include "device_map.h"
#include "protect.h"
#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "nwk.h"
#include "port.h"
#include "port_posix.h"
#include "props.h"
#include "radio.h"
#include "rcp_radio.h"
#include "security.h"
#include "zb_time.h"
#include "zb_utils.h"
#include "zb_layers.h"

/* The tool that composes one NSDU through the façade and writes down the octets the seam was handed:
   APS, NWK, MAC and the seam in one call, with a band-B wrapper between the seam and the backend that
   records what band A gave it. */

/* Two modes and only two: --model is the façade over band B's hardware-free backend, opening no port and
   naming no device; --path is the façade over `RcpRadio_Seam` on a device named on the command line, because
   no port is ever defaulted (docs/internals/hardware.md §8). */

/* The tee is the point of the tool: it forwards every seam operation and records the exact octets band A
   handed `tx`, the acknowledgment ask, the handle the backend answered with and the completion it answered.
   A claim about what was sent that is not byte-exact witnesses nothing. */

/* A transmission needs both --tx and --allow-tx, on a channel and in a PAN the run does not protect. An ask missing its authorisation is refused at the door; a run that never
   asked composes and prints behind a tee that refuses `tx` (docs/internals/hardware.md §1, §7). */

/* A model has no air, so a transmission flag beside --model names nothing and is refused at the door. Every
   run that opened a port ends with a reset rather than with a close, because armed state survives the
   hang-up. */

/* On a path run the tee forwards, so band A's own identity write reaches the stick: it is armed as the
   sender of the frame it was asked to carry. The channel and the PAN it may be armed in are judged before
   the port is opened, so what this program can arm is only what it may send on. */

/* The clock is band C's on a path run and the tool's own counter on a model run, which has no clock to read
   (docs/porting.md §4). A pump never blocks, so the pause is what makes a run against a stick a conversation
   rather than a burn. */

#define BRINGUP_TIMEOUT_MS 6000
#define FLUSH_PUMPS_MAX 400
#define END_PUMPS 3
#define PUMP_PAUSE_MS 2
/* The turn bound is the wait budget read in the unit a turn actually costs: a turn pauses PUMP_PAUSE_MS and
   pumps without blocking, so a --wait of N ms is worth about N / PUMP_PAUSE_MS turns, with a slack for the turns
   a pump spends inside the stick's own windows. */
#define TURN_SLACK 200
#define TURN_MAX 8000
#define MODEL_TURN_MAX 3
#define TURN_STEP_MS 10

/* How long a path run waits for the transmit completion the seam owes (docs/internals/protocol.md §8.3). */
#define TX_WAIT_MS 1500

/* The defaults a run arms on: a channel and an inert PAN; --protect-channel and --protect-pan name what it may not. */
#define CHANNEL_DEFAULT 26

#define PAN_INERT 0xbeef

/* The addressing the rig transcripts in test/fixtures/ were taken with. */
#define OWN_SHORT_DEFAULT 0xdead
#define DEST_SHORT_DEFAULT 0x1234

#define LEVEL_NONE 0
#define LEVEL_NWK_ENC_MIC_32 SECURITY_LEVEL_ENC_MIC_32
#define KEY_SEQ 0

/* The three seeds the application owns, and the frame the two composed runs carry. */
#define SEQ_START 0x11
#define DSN_START 0x21
#define JITTER_SEED 0
#define SRC_ENDPOINT 0x01
#define DST_ENDPOINT 0x02
#define PROFILE_ID 0x0104
#define CLUSTER_ID 0x0006

/* What the façade is handed as the identity to apply, in both modes: every PIB field the seam's own list lets a
   caller name, in one call. Band B sizes its write queue to hold a whole seam call, and the channel is band A's
   decision once the stick is armed (docs/internals/protocol.md §7.1, docs/internals/coding-rules.md §4.3). */
#define PRESENT_FULL (RADIO_PIB_CHANNEL | RADIO_PIB_PAGE | RADIO_PIB_PAN_ID | RADIO_PIB_SHORT_ADDRESS \
                      | RADIO_PIB_EXTENDED_ADDRESS | RADIO_PIB_RX_ON_WHEN_IDLE)

#define ASDU_MAX 48
#define TEE_TX_MAX 16

/* What came back up the seam during one run: a discovery, a reply to it and an acknowledgement are all frames
   the tool never asked for, and a transcript that printed only what went down cannot say what arrived. */
#define TEE_RX_MAX 12
#define NOT_FOUND 0xffffffff

#define MODE_NONE 0
#define MODE_MODEL 1
#define MODE_PATH 2

/* The six octets both runs carry unless --asdu names others: the same ASDU the stack suite's known answer
   is written with. */
static const uint8_t s_asduDefault[6] =
{
    0x66, 0x72, 0x61, 0x6d, 0x65, 0x64
};

/* What the tee was handed and what came back: one transmit the stack asked for, kept byte for byte. */
typedef struct TeeRecord
{
    uint32_t len;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t ackRequest;
    uint32_t issued;
    Radio_Handle handle;
    ZbStatus seamStatus;
    uint32_t completionSeen;
    Radio_TxResult completion;
    uint32_t completionTail;   /* what band B recorded of the device's own two bits; 0 where there was no record */
    uint32_t deviceCode;
    int deviceCodeKnown;
} TeeRecord;

/* The band-B wrapper: the backend behind it, the ask this run may make, and the records it wrote. */
typedef struct SendTee
{
    Radio_Radio seam;
    Radio_Radio *backend;
    Rcp_Radio *rcp;              /* the band-B state behind that backend, 0 when the run has no band B */
    uint32_t authorised;
    uint32_t records;
    uint32_t recordDrops;
    uint32_t txRefusals;
    uint32_t backendTxCalls;
    uint32_t completionCalls;
    uint32_t rxFrames;
    uint32_t rxKept;
    TeeRecord record[TEE_TX_MAX];
    Radio_Frame rx[TEE_RX_MAX];
} SendTee;

/* The run the command line describes: its mode, the device identity, the key, the request and the ask. */
typedef struct SendRun
{
    Protect protect;
    uint32_t mode;
    uint32_t wantTx;
    uint32_t allowTx;
    uint32_t noNeighbour;
    uint32_t filtered;
    uint32_t waitMs;
    uint32_t sendAtMs;
    int listenOn;
    uint32_t channel;
    uint32_t level;
    uint32_t keyGiven;
    uint32_t ieeeGiven;
    uint32_t seqStart;
    uint32_t dsnStart;
    uint64_t ownIeee;
    uint32_t panId;
    uint32_t ownShort;
    uint32_t destShort;
    uint8_t key[SECURITY_KEY_OCTETS];
    uint8_t asdu[ASDU_MAX];
    uint32_t asduLen;
    uint32_t present;
    uint32_t timeoutMs;
    uint32_t baud;
    uint32_t rxRing;
    uint32_t txRing;
    const char *path;
} SendRun;

/* ------------------------------------------------------------------ host machinery */

static void pauseHost(void)
{
    struct timespec ts;

    ts.tv_sec = 0;
    ts.tv_nsec = (long)PUMP_PAUSE_MS * 1000000;
    nanosleep(&ts, 0);
}

static const char *statusName(ZbStatus status)
{
    if (status == ZB_OK)
        return "ok";

    if (status == ZB_ERR_BAD_ARGUMENT)
        return "bad-argument";

    if (status == ZB_ERR_UNSUPPORTED)
        return "unsupported";

    if (status == ZB_ERR_NOT_READY)
        return "not-ready";

    if (status == ZB_ERR_NO_SPACE)
        return "no-space";

    if (status == ZB_ERR_TIMEOUT)
        return "timeout";

    if (status == ZB_ERR_DEVICE_LOST)
        return "device-lost";

    if (status == ZB_ERR_NO_DEVICE)
        return "no-device";

    if (status == ZB_ERR_BUSY)
        return "busy";

    if (status == ZB_ERR_INTERNAL)
        return "internal";

    if (status == ZB_ERR_NOT_OPEN)
        return "not-open";

    if (status == ZB_ERR_BAD_FRAME)
        return "bad-frame";

    if (status == ZB_ERR_AUTH)
        return "auth-failed";

    if (status == ZB_ERR_NO_ROUTE)
        return "no-route";

    if (status == ZB_ERR_BAD_FRAME_COUNTER)
        return "bad-frame-counter";

    if (status == ZB_ERR_CHANNEL_ACCESS_FAILURE)
        return "channel-access-failure";

    if (status == ZB_ERR_DEVICE)
        return "radio-error";

    return "refused";
}

static const char *modeName(Rcp_RadioMode mode)
{
    if (mode == RCP_RADIO_MODE_CLOSED)
        return "closed";

    if (mode == RCP_RADIO_MODE_RESET)
        return "reset";

    if (mode == RCP_RADIO_MODE_DISCOVER)
        return "discover";

    if (mode == RCP_RADIO_MODE_ARM)
        return "arm";

    if (mode == RCP_RADIO_MODE_RUNNING)
        return "running";

    return "fault";
}

static const char *typeName(Mac_FrameType type)
{
    if (type == MAC_FRAME_TYPE_BEACON)
        return "beacon";

    if (type == MAC_FRAME_TYPE_DATA)
        return "data";

    if (type == MAC_FRAME_TYPE_ACK)
        return "ack";

    if (type == MAC_FRAME_TYPE_COMMAND)
        return "command";

    return "other";
}

static const char *addrModeName(Mac_AddrMode mode)
{
    if (mode == MAC_ADDR_NONE)
        return "absent";

    if (mode == MAC_ADDR_SHORT)
        return "16-bit";

    return "64-bit";
}

static const char *deliveryName(uint32_t mode)
{
    if (mode == APS_DELIVERY_UNICAST)
        return "unicast";

    if (mode == APS_DELIVERY_GROUP)
        return "group";

    if (mode == APS_DELIVERY_BROADCAST)
        return "broadcast";

    return "unknown";
}

static void printOctets(const char *label, const uint8_t *bytes, uint32_t len)
{
    uint32_t index;

    printf("%s", label);

    for (index = 0; index < len; index++)
        printf(" %02x", bytes[index]);

    printf("\n");
}

/* The first place a run of octets appears in the record, or NOT_FOUND: the absence the secured frame is
   judged against is a search over the recorded octets, not an assertion about them. */
static uint32_t findRun(const uint8_t *haystack, uint32_t hayLen, const uint8_t *needle, uint32_t needleLen)
{
    uint32_t start;
    uint32_t index;
    uint32_t differs;

    if (needleLen == 0 || needleLen > hayLen)
        return NOT_FOUND;

    for (start = 0; start + needleLen <= hayLen; start++)
    {
        differs = 0;

        for (index = 0; index < needleLen; index++)
        {
            if (haystack[start + index] != needle[index])
                differs = 1;
        }

        if (!differs)
            return start;
    }

    return NOT_FOUND;
}

/* ------------------------------------------------------------------ the seam tee */

static ZbStatus teeCaps(Radio_Radio *radio, Radio_Caps *outCaps)
{
    SendTee *self = (SendTee *)radio->provider;

    return self->backend->ops->caps(self->backend, outCaps);
}

static ZbStatus teePibSet(Radio_Radio *radio, const Radio_Pib *pib)
{
    SendTee *self = (SendTee *)radio->provider;

    return self->backend->ops->pibSet(self->backend, pib);
}

static ZbStatus teePibGet(Radio_Radio *radio, Radio_Pib *pib)
{
    SendTee *self = (SendTee *)radio->provider;

    return self->backend->ops->pibGet(self->backend, pib);
}

static ZbStatus teeFilter(Radio_Radio *radio, const Radio_Filter *filter)
{
    SendTee *self = (SendTee *)radio->provider;

    return self->backend->ops->filter(self->backend, filter);
}

static uint32_t teeRxPoll(Radio_Radio *radio, Radio_Frame *outFrames, uint32_t maxFrames)
{
    SendTee *self = (SendTee *)radio->provider;
    uint32_t got;
    uint32_t i;

    /* What the backend handed band A is kept here too: a run that started a route discovery receives frames it
      never asked for, and a transcript that printed only the octet strings going down could not say what came
      back. */
    got = self->backend->ops->rxPoll(self->backend, outFrames, maxFrames);

    for (i = 0; i < got; i++)
    {
        self->rxFrames++;

        if (self->rxKept < TEE_RX_MAX)
            self->rx[self->rxKept++] = outFrames[i];
    }

    return got;
}

static int teeIsLost(Radio_Radio *radio)
{
    SendTee *self = (SendTee *)radio->provider;

    return self->backend->ops->isLost(self->backend);
}

static ZbStatus teeScanStart(Radio_Radio *radio, uint32_t channel, uint32_t dwellUnits)
{
    SendTee *self = (SendTee *)radio->provider;

    return self->backend->ops->scanStart(self->backend, channel, dwellUnits);
}

static ZbStatus teeScanCollect(Radio_Radio *radio, uint32_t *outChannel, int32_t *outDbm)
{
    SendTee *self = (SendTee *)radio->provider;

    return self->backend->ops->scanCollect(self->backend, outChannel, outDbm);
}

/* The completion belongs to the record that carries the handle it was asked for. */
static ZbStatus teeCompletion(Radio_Radio *radio, Radio_Handle handle, Radio_TxResult *outResult)
{
    SendTee *self = (SendTee *)radio->provider;
    TeeRecord *slot;
    uint32_t index;
    uint32_t code = 0;
    int known = 0;
    ZbStatus status;

    /* Read before collecting: the device's own code belongs to the transmit, and collection is what releases
       it (RcpRadio_TxStatusCode says so). A bench run has to see the code, not only the status this host folded
       from it, NO_ACK and FAILURE fold to the same ZB_ERR_DEVICE here. */
    code = 0;
    known = 0;

    if (self->rcp != 0 && RcpRadio_TxStatusCode(self->rcp, handle, &code) == ZB_OK)
        known = 1;

    status = self->backend->ops->completion(self->backend, handle, outResult);
    self->completionCalls++;

    if (status == ZB_ERR_NOT_READY)
        return status;

    for (index = 0; index < self->records; index++)
    {
        slot = &self->record[index];

        if (slot->issued && slot->handle == handle)
        {
            slot->completionSeen = 1;
            slot->seamStatus = status;
            slot->completionTail = self->rcp != 0 ? RcpRadio_CompletionTail(self->rcp) : 0;
            slot->deviceCode = code;
            slot->deviceCodeKnown = (uint32_t)known;

            if (outResult != 0)
                slot->completion = *outResult;

            break;
        }
    }

    return status;
}

/* Every octet band A composed is recorded before the ask is judged: a frame this tool refused to issue is
   still a claim about what the stack handed the seam, and refusing after the copy is what makes the two
   authorised and unauthorised runs print the same octets. */
static ZbStatus teeTx(Radio_Radio *radio, const uint8_t *mpdu, uint32_t len, int ackRequest,
                      uint32_t maxFrameRetries, Radio_Handle *outHandle)
{
    SendTee *self = (SendTee *)radio->provider;
    TeeRecord *slot;
    ZbStatus status;

    if (!mpdu || len == 0 || len > RADIO_MPDU_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->records >= TEE_TX_MAX)
    {
        self->recordDrops++;

        if (!self->authorised)
            return ZB_ERR_UNSUPPORTED;

        return self->backend->ops->tx(self->backend, mpdu, len, ackRequest, maxFrameRetries, outHandle);
    }

    slot = &self->record[self->records];

    slot->len = len;
    Zb_memcpy(slot->bytes, mpdu, len);
    slot->ackRequest = (uint32_t)ackRequest;
    slot->issued = 0;
    slot->handle = RADIO_HANDLE_NONE;
    slot->seamStatus = ZB_ERR_UNSUPPORTED;
    slot->completionSeen = 0;
    Zb_memset(&slot->completion, 0, (uint32_t)sizeof slot->completion);

    self->records++;

    if (!self->authorised)
    {
        self->txRefusals++;

        if (outHandle != 0)
            *outHandle = RADIO_HANDLE_NONE;

        return ZB_ERR_UNSUPPORTED;
    }

    status = self->backend->ops->tx(self->backend, mpdu, len, ackRequest, maxFrameRetries, outHandle);

    self->backendTxCalls++;
    slot->issued = 1;
    slot->seamStatus = status;
    slot->handle = outHandle != 0 ? *outHandle : RADIO_HANDLE_NONE;

    return status;
}

static const Radio_Ops s_teeOps =
{
    teeCaps,
    teePibSet,
    teePibGet,
    teeFilter,
    teeTx,
    teeCompletion,
    teeRxPoll,
    teeIsLost,
    teeScanStart,
    teeScanCollect
    , 0    /* no pending table: this backend states 10.22.3's bit itself or not at all */
};

/* ------------------------------------------------------------------ what the tee recorded */

static void printRecord(const SendTee *tee, uint32_t index)
{
    const TeeRecord *slot = &tee->record[index];

    printf("tee %u      %u octets handed tx  ackRequest %u  issued %u  handle %s",
           index, slot->len, slot->ackRequest, slot->issued,
           slot->issued ? "" : "none");

    if (slot->issued)
        printf("%u", slot->handle);

    printf("  the seam answered %s", statusName(slot->seamStatus));

    if (slot->completionSeen)
    {
        printf("  completion status %s acked %d retries %u",
               statusName(slot->completion.status), slot->completion.isAcked, slot->completion.retries);

        /* The two bits §8.9.4.2 puts after the status code, as the device sent them. Printed apart from the
           acked value band B derives, because they are the device's claim and `acked` is this host's reading
           of it (D-47): a measurement has to see which of the two it is looking at. */
        if (slot->deviceCodeKnown)
            printf("  device code %u", slot->deviceCode);

        if ((slot->completionTail & RCP_RADIO_TAIL_REPORTED) != 0)
            printf("  device said pending %u header-updated %u",
                   (slot->completionTail & RCP_RADIO_TAIL_PENDING) ? 1 : 0,
                   (slot->completionTail & RCP_RADIO_TAIL_HEADER_UPDATED) ? 1 : 0);
        else
            printf("  device said nothing after the code");
    }
    else
        printf("  completion none owed");

    printf("\n");

    printOctets("           ", slot->bytes, slot->len);
}

/* Every record the tee holds: a transmit the layers re-issued is a second claim about the octets band A
   handed tx, and a transcript that printed only the first of them would not be the tee's own account. */
static void printRecords(const SendTee *tee)
{
    uint32_t index;

    for (index = 0; index < tee->records; index++)
        printRecord(tee, index);
}

/* Every frame the backend handed band A, in the order it handed them, with the device's own stamp beside it. */
static void printRx(const SendTee *tee)
{
    uint32_t index;

    printf("rx         frames %u  kept %u\n", tee->rxFrames, tee->rxKept);

    for (index = 0; index < tee->rxKept; index++)
    {
        printf("rx %u      len %u  rssi %d  lqi %u  device stamp %llu  %s%s\n",
               index, tee->rx[index].len, tee->rx[index].rssiDbm, tee->rx[index].lqi,
               (unsigned long long) tee->rx[index].deviceStampTicks,
               tee->rx[index].error == ZB_OK ? "ok" : statusName(tee->rx[index].error),
               tee->rx[index].ackedWithFramePending ? "  ack-frame-pending 1" : "");
        printOctets("           ", tee->rx[index].bytes, tee->rx[index].len);
    }
}

/* The record read back through band A's own codecs, so every field printed here comes out of the recorded
   octets and nothing out of the request that produced them. */
static void printFields(const SendTee *tee, const Radio_Caps *caps, const SendRun *run)
{
    const TeeRecord *slot = &tee->record[0];
    Mac_Frame macFrame;
    Nwk_Frame nwkFrame;
    Aps_Frame apsFrame;
    const uint8_t *npdu;
    uint32_t npduLen;
    uint32_t apduLen;
    uint32_t apduOffset;
    uint32_t nwkOffset;
    uint32_t nwkPayloadLen;
    uint32_t macHeaderLen;
    uint32_t apsForm;
    uint32_t auxOffset;
    uint32_t cipherLen;
    uint32_t micLen;
    uint32_t at;
    int parsed;
    ZbStatus status;

    npdu = 0;
    npduLen = 0;

    status = MacFrame_Parse(slot->bytes, slot->len, caps->psduIncludesFcs, &macFrame, &npdu, &npduLen, 0);

    if (status != ZB_OK)
    {
        printf("field      the record does not parse as a MAC frame: %s\n", statusName(status));
        return;
    }

    macHeaderLen = slot->len - npduLen - (caps->psduIncludesFcs ? MAC_FRAME_FCS_OCTETS : 0);

    printf("fields     the block below reads tee record 0, the first octet string this run handed tx: on a run that\n"
           "           started a route discovery, that frame is the discovery's own and not the request's\n");
    printf("field mac  fcf %02x %02x  %s v%u  security %d  ack %d  pending %d  pan-compressed %d  dst %s src %s\n",
           slot->bytes[0], slot->bytes[1], typeName(macFrame.frameType), macFrame.frameVersion,
           macFrame.securityEnabled, macFrame.ackRequest, macFrame.framePending, macFrame.panIdCompression,
           addrModeName(macFrame.destAddrMode), addrModeName(macFrame.srcAddrMode));
    printf("           seq %02x  dst pan 0x%04x  dst 0x%04x  src 0x%04x  header %u octets at 0..%u\n",
           macFrame.seq, macFrame.destPan, macFrame.destShort, macFrame.srcShort,
           macHeaderLen, macHeaderLen - 1);

    if (caps->psduIncludesFcs)
    {
        at = slot->len - MAC_FRAME_FCS_OCTETS;

        printf("           footer %02x %02x at %u..%u  %s against the octets ahead of it: the host's own\n"
               "           arithmetic, which the RCP is measured replacing\n",
               slot->bytes[at], slot->bytes[at + 1], at, slot->len - 1,
               MacFrame_CheckFcs(slot->bytes, slot->len) == ZB_OK ? "validates" : "does not validate");
    }

    status = NwkFrame_Parse(npdu, npduLen, &nwkFrame, &nwkOffset, &nwkPayloadLen);

    if (status != ZB_OK)
    {
        printf("field nwk  the MAC payload does not parse as a network frame: %s\n", statusName(status));
        return;
    }

    parsed = nwkFrame.securityEnabled ? 1 : 0;

    printf("field nwk  fcf %02x %02x  %s  protocol %u  discover %u  security %d  source-route %d  dst ieee %d  src ieee %d\n",
           npdu[0], npdu[1], nwkFrame.frameType == NWK_FRAME_TYPE_DATA ? "data" : "other",
           nwkFrame.protocolVersion, nwkFrame.discoverRoute, nwkFrame.securityEnabled,
           nwkFrame.sourceRoute, nwkFrame.destIeeePresent, nwkFrame.srcIeeePresent);
    printf("           dst 0x%04x  src 0x%04x  radius %u  sequence %02x  header %u octets at %u..%u  payload %u\n",
           nwkFrame.destAddr, nwkFrame.srcAddr, nwkFrame.radius, nwkFrame.sequenceNumber,
           nwkOffset, macHeaderLen, macHeaderLen + nwkOffset - 1, nwkPayloadLen);

    apsForm = APS_FRAME_FCF_OCTETS + APS_FRAME_ENDPOINT_OCTETS + APS_FRAME_CLUSTER_OCTETS
              + APS_FRAME_PROFILE_OCTETS + APS_FRAME_ENDPOINT_OCTETS + APS_FRAME_COUNTER_OCTETS
              + run->asduLen;

    if (!parsed)
    {
        status = ApsFrame_Parse(npdu + nwkOffset, nwkPayloadLen, &apsFrame, &apduOffset, &apduLen);

        if (status != ZB_OK)
        {
            printf("field aps  the NSDU does not parse as an aps frame: %s\n", statusName(status));
            return;
        }

        printf("field aps  fcf %02x  %s  %s  security %d  ack-request %d  extended header %d\n",
               npdu[nwkOffset], apsFrame.frameType == APS_FRAME_TYPE_DATA ? "data" : "other",
               deliveryName(apsFrame.deliveryMode), apsFrame.securityEnabled, apsFrame.ackRequest,
               apsFrame.extendedHeaderPresent);
        printf("           dst ep %02x  src ep %02x  cluster 0x%04x  profile 0x%04x  aps counter %02x  header %u octets\n",
               apsFrame.dstEndpoint, apsFrame.srcEndpoint, apsFrame.clusterId, apsFrame.profileId,
               apsFrame.apsCounter, apduOffset);
        printf("field asdu %u octets at %u..%u: ", apduLen, macHeaderLen + nwkOffset + apduOffset,
               macHeaderLen + nwkOffset + apduOffset + apduLen - 1);

        for (at = 0; at < apduLen; at++)
            printf("%s%02x", at ? " " : "", npdu[nwkOffset + apduOffset + at]);

        printf("  %s the request's own octets, in the clear where the data header put them\n",
               Zb_memcmp(npdu + nwkOffset + apduOffset, run->asdu, apduLen) == 0 ? "the same as" : "not");

        return;
    }

    auxOffset = nwkOffset;

    if (nwkPayloadLen < SECURITY_AUX_LEN + apsForm)
    {
        printf("field mic  the payload left after the network header is shorter than the auxiliary header and\n"
               "           the aps form the request named together: %u octets for %u + %u\n",
               nwkPayloadLen, SECURITY_AUX_LEN, apsForm);
        return;
    }

    micLen = nwkPayloadLen - SECURITY_AUX_LEN - apsForm;
    cipherLen = apsForm;

    printf("field aux  control %02x  security level bits %u  key id %u (network)  extended nonce %u  rvfc %u  %u octets at %u..%u\n",
           npdu[auxOffset], npdu[auxOffset] & SECURITY_CONTROL_LEVEL_MASK,
           (npdu[auxOffset] >> SECURITY_CONTROL_KEY_ID_SHIFT) & SECURITY_CONTROL_KEY_ID_MASK,
           (npdu[auxOffset] >> SECURITY_CONTROL_EXTENDED_NONCE_SHIFT) & SECURITY_CONTROL_EXTENDED_NONCE_MASK,
           (npdu[auxOffset] >> SECURITY_CONTROL_RVFC_SHIFT) & 1,
           SECURITY_AUX_LEN, macHeaderLen + auxOffset, macHeaderLen + auxOffset + SECURITY_AUX_LEN - 1);
    printOctets("           frame counter", npdu + auxOffset + 1, 4);
    printOctets("           extended source", npdu + auxOffset + 5, 8);
    printf("           key sequence %02x\n", npdu[auxOffset + 13]);
    printf("field mic  %u octets at %u..%u, the length level 0x%02x names; the level itself is this device's\n"
           "           config, and the air's control octet carries it as zero for a network-key frame\n",
           micLen, slot->len - MAC_FRAME_FCS_OCTETS - micLen, slot->len - MAC_FRAME_FCS_OCTETS - 1,
           run->level);
    printf("field cipher %u octets at %u..%u: the whole APDU, header and ASDU protected together\n",
           cipherLen, macHeaderLen + auxOffset + SECURITY_AUX_LEN,
           macHeaderLen + auxOffset + SECURITY_AUX_LEN + cipherLen - 1);

    /* The label is part of the fixture: `harness/check_samples.py` reads a bare indented octet line as a
       recorded PSDU, and a ciphertext run is not one. */
    printOctets("           ciphertext", npdu + auxOffset + SECURITY_AUX_LEN, cipherLen);

    at = findRun(slot->bytes, slot->len, run->asdu, run->asduLen);

    if (at == NOT_FOUND)
        printf("proof      the %u ASDU octets appear nowhere in the %u recorded octets: the cleartext the mic\n"
               "           stands for is what `shadow` below recovers from these octets and searches for there\n",
               run->asduLen, slot->len);
    else
        printf("candidate-new the ASDU is present in the clear at octet %u of the record\n", at);
}

/* A second `Security`, seeded with the same key and touched by nothing else: the record it reads back is
   the ciphertext the tee wrote, so the plaintext it answers is a claim about the recorded octets. */
static void shadowUnprotect(const SendRun *run, uint64_t ownIeee, const Radio_Caps *caps, const SendTee *tee)
{
    const TeeRecord *slot = &tee->record[0];
    Security shadow;
    Security_Config cfg;
    Security_KeyDescriptor descriptor;
    Mac_Frame macFrame;
    Nwk_Frame nwkFrame;
    const uint8_t *npdu;
    uint8_t plain[NWK_FRAME_NPDU_MAX];
    uint32_t npduLen;
    uint32_t nwkOffset;
    uint32_t nwkPayloadLen;
    uint32_t plainLen;
    uint32_t at;
    Security_Result result;
    ZbStatus status;

    Zb_memset(&descriptor, 0, (uint32_t)sizeof descriptor);
    descriptor.keySeqNumber = KEY_SEQ;
    descriptor.inUse = 1;
    descriptor.outgoingFrameCounter = 0;
    Zb_memcpy(descriptor.key, run->key, SECURITY_KEY_OCTETS);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = ownIeee;
    cfg.nwkSecurityLevel = (uint8_t)run->level;
    cfg.nwkActiveKeySeqNumber = KEY_SEQ;
    cfg.authenticated = 1;
    cfg.nwkAllFresh = 1;
    cfg.keys = &descriptor;
    cfg.keyCount = 1;

    if (Security_Init(&shadow, &cfg) != ZB_OK)
    {
        printf("shadow     the second Security would not be built; the record stays unread\n");
        return;
    }

    npdu = 0;
    npduLen = 0;

    if (MacFrame_Parse(slot->bytes, slot->len, caps->psduIncludesFcs, &macFrame, &npdu, &npduLen, 0) != ZB_OK)
        return;

    if (NwkFrame_Parse(npdu, npduLen, &nwkFrame, &nwkOffset, &nwkPayloadLen) != ZB_OK)
        return;

    status = Security_Unprotect(&shadow, npdu, npduLen, nwkOffset, plain,
                                (uint32_t)sizeof plain, &plainLen, &result);

    if (status != ZB_OK)
    {
        printf("shadow     the record does not unprotect: %s\n", statusName(status));
        return;
    }

    printOctets("shadow     the record unprotected by a second Security answers the cleartext APDU", plain, plainLen);

    at = findRun(slot->bytes, slot->len, plain, plainLen);

    if (at == NOT_FOUND)
        printf("           that %u-octet cleartext APDU appears nowhere in the %u recorded octets\n",
               plainLen, slot->len);
    else
        printf("candidate-new the cleartext APDU is present in the record at octet %u\n", at);

    at = findRun(plain, plainLen, run->asdu, run->asduLen);

    if (at != NOT_FOUND)
        printf("           its last %u octets are the request's ASDU at %u..%u of the cleartext, and the mic\n"
               "           validated before they were handed over\n",
               run->asduLen, at, at + run->asduLen - 1);
    else
        printf("           the request's ASDU is not what came back\n");

    printf("           frame counter used %llu  key sequence %02u  source ieee %016llx\n",
           (unsigned long long)result.frameCounter, result.keySeqNumber,
           (unsigned long long)result.senderIeee);
}

/* ------------------------------------------------------------------ usage */

static void usage(void)
{
    printf("usage: rcp_send --model [--channel 12|26] [--pan hex] [--own hex] [--dst hex]\n"
           "                [--level 0|5] [--key 32-hex-digits] [--ieee 16-hex-digits]\n"
           "                [--asdu hex] [--seq n] [--dsn n]\n"
           "       rcp_send --path <path>|--device <name> [same options] --tx --allow-tx\n"
           "                [--timeout ms] [--baud n] [--rx-ring n] [--tx-ring n]\n"
           "--no-neighbour keeps the destination out of the neighbour table, which is the only way this tool"
           "  reaches 3.6.4.5.1's route discovery rather than 3.6.4.3's direct next hop;"
           "--no-promisc states 10.23.1's filtered mode through band A's own door, because the arm sequence"
           "  leaves the radio in receive-all mode and a receive-all stick acknowledges nothing"
           "; without it a run of two of these tools has no"
           "  acknowledgment at either end;"""
           "an identifier is hex without the 0x (--pan beef, --own 42, --dst 1234, --level 5, --seq 11,\n"
           "  --dsn 21, --key, --asdu); a quantity is decimal (--channel 26, --timeout 1000, --baud,\n"
           "  --rx-ring, --tx-ring). An address is written in transmitted octet order, the order the PIB's\n"
           "  extended address and a frame's source field carry it: 0x0123456789abcdef is --ieee\n"
           "  efcdab8967452301. A path run takes the extended address the device reports as its factory one\n"
           "  unless --ieee names another, because a security config is bound to the address the device reports.\n"
           "                [--no-neighbour] [--wait ms] [--listen-on] [--send-at ms]\n"
           "--send-at holds the request back that many ms while the stack keeps turning, so a run can transmit after\n"
           "  a peer that started earlier has finished arming;\n"
           "--listen-on keeps the tool turning for the whole --wait after its own request is answered, so a peer\n"
           "  that starts later is still heard; without it a refused request ends the run in about 50 ms;\n"
           "--wait is how long the tool keeps turning after the request: 1500 ms by default, and longer when"
           "  the exchange below the tool's own request has to run its own clocks;"
           "defaults: channel 26, pan 0xbeef, own short 0xdead, dst 0x1234, level 0, one asdu of\n"
           "  66 72 61 6d 65 64, nwk sequence seeded 0x11, mac dsn seeded 0x21, endpoint 0x01 out and 0x02\n"
           "  in, profile 0x0104, cluster 0x0006, one unicast APS data request, TxOptions 0x04 (0x06 at a\n"
           "  level that protects frames), the completion waited for 1500 ms\n");
    printf("this program cannot:\n"
           "  arm an RCP on a channel given with --protect-channel, or carry a PAN given with --protect-pan, in\n"
           "  either mode; its own default PAN is the inert 0xbeef, and no flag lifts a protection;\n"
           "  transmit at all in --model mode: --tx and --allow-tx are both refused beside a model, which has\n"
           "  no air to authorise, and a model run opens no port and names no device;\n"
           "  treat --allow-tx as a transmission or --tx as an authorised one: both are needed, and without\n"
           "  both the tee records the frame band A composed and answers the seam unsupported;\n"
           "  default a port: --path or --device names one or the run is refused (docs/internals/hardware.md §8);\n"
           "  leave a stick armed: every run that opened a port ends with a reset, every refusal included\n"
           ", and a run that opened none owes none.\n");
}

/* Two hex digits per octet, separators optional, and a refusal rather than a partial read. */
static int parseOctets(const char *text, uint8_t *out, uint32_t cap, uint32_t *outLen)
{
    uint32_t len = 0;
    uint32_t high;
    uint32_t low;
    const char *p = text;

    while (*p != 0)
    {
        while (*p == ' ' || *p == ':')
            p++;

        if (*p == 0)
            break;

        if (sscanf(p, "%1x%1x", &high, &low) != 2)
            return 0;

        if (len >= cap)
            return 0;

        out[len] = (uint8_t)((high << 4) | low);
        len++;
        p += 2;
    }

    *outLen = len;

    return len != 0;
}

static uint32_t hexValue(const char *text)
{
    return (uint32_t)strtoul(text, 0, 16);
}

static uint32_t decValue(const char *text)
{
    return (uint32_t)strtoul(text, 0, 10);
}

static uint64_t extendedValueOf(const uint8_t *octets)
{
    uint64_t value;
    uint32_t index;

    value = 0;

    for (index = 0; index < RADIO_ADDR_LEN; index++)
        value = value | ((uint64_t)octets[index] << (index * 8));

    return value;
}

/* A 64-bit address as the eight octets the PIB's extended address and a frame's source field carry it in:
   least significant first (7.2.1.4). */
static void printExtended(uint64_t value)
{
    uint32_t index;

    for (index = 0; index < RADIO_ADDR_LEN; index++)
        printf("%s%02x", index ? " " : "", (uint8_t)(value >> (index * 8)));
}

static void extendedOctetsOf(uint64_t value, uint8_t *out)
{
    uint32_t index;

    for (index = 0; index < RADIO_ADDR_LEN; index++)
        out[index] = (uint8_t)(value >> (index * 8));
}

/* ------------------------------------------------------------------ the authorisation, in code */

static int judgeChannel(const Protect *protect, uint32_t channel)
{
    if (channel < PROPS_CHANNEL_MIN || channel > PROPS_CHANNEL_MAX)
    {
        printf("refused    channel %u is outside 11..26: no 2.4 GHz O-QPSK PHY numbers one\n", channel);
        return 1;
    }

    if (protectChannel(protect, channel))
    {
        printf("refused    channel %u is protected, and an armed RCP answers frames addressed to it: this\n"
               "           program has no mode that arms there\n",
               channel);
        return 1;
    }

    return 0;
}

static int judgePan(const Protect *protect, uint32_t pan)
{
    if (protectPan(protect, pan))
    {
        printf("refused    PAN 0x%04x is protected: this program will not compose a frame for it or arm an RCP\n"
               "           in it, in either mode, and there is no flag that lifts this\n",
               pan);
        return 1;
    }

    if (pan > 0xffff)
    {
        printf("refused    0x%x is not a 16-bit PAN identifier\n", pan);
        return 1;
    }

    return 0;
}

/* Every refusal a command line can meet before a device is touched, in the order it meets them. */
static int judgeRun(const SendRun *run)
{
    if (run->mode == MODE_NONE)
    {
        printf("refused    no mode named: --model composes over the hardware-free backend, --path composes over\n"
               "           a stick. This program has no default mode and no default port\n\n");
        usage();
        return 1;
    }

    if (run->mode == MODE_MODEL && (run->wantTx || run->allowTx))
    {
        printf("refused    --tx and --allow-tx beside --model: a model has no air to authorise, and a pair of\n"
               "           flags this mode cannot mean anything by is not left defined\n");
        return 1;
    }

    if (run->wantTx && !run->allowTx)
    {
        printf("refused    --tx without --allow-tx: nothing goes on the air without both flags\n"
               "           (docs/internals/hardware.md §8). Nothing was opened and nothing was composed\n");
        return 1;
    }

    if (judgeChannel(&run->protect, run->channel))
        return 1;

    if (judgePan(&run->protect, run->panId))
        return 1;

    if (run->ownShort > 0xffff || run->destShort > 0xffff)
    {
        printf("refused    0x%x and 0x%x: --own and --dst are 16-bit short addresses, and a value wider than\n"
               "           the field is not a number this program will quietly cut down\n",
               run->ownShort, run->destShort);
        return 1;
    }

    if (run->level != LEVEL_NONE && run->level != LEVEL_NWK_ENC_MIC_32)
    {
        printf("refused    security level 0x%x: this program composes at 0x00, unsecured, and at 0x05, the\n"
               "           encrypted 32-bit mic every band-A rig in this tree holds\n",
               run->level);
        return 1;
    }

    if (run->level == LEVEL_NONE && run->keyGiven)
    {
        printf("refused    a --key at level 0x00: a device with no security holds no key material, and a key it\n"
               "           cannot use is not a config this program will take\n");
        return 1;
    }

    if (run->level != LEVEL_NONE && !run->keyGiven)
    {
        printf("refused    level 0x%02x with no --key: the network key is the application's config, and a\n"
               "           secured device built without it is a device whose frames this tool cannot write\n",
               run->level);
        return 1;
    }

    if (run->mode == MODE_PATH && !run->path)
    {
        printf("refused    --path with no device named: no port is ever defaulted (docs/internals/hardware.md §8)\n");
        return 1;
    }

    if (run->asduLen == 0 || run->asduLen > ASDU_MAX)
    {
        printf("refused    an ASDU of %u octets: this program carries between 1 and %d of them\n",
               run->asduLen, ASDU_MAX);
        return 1;
    }

    return 0;
}

/* ------------------------------------------------------------------ the device both modes build */

static void stackConfigOf(const SendRun *run, uint64_t ownIeee, Zb_LayersConfig *cfg, Security_Config *secCfg,
                          Security_KeyDescriptor *descriptor)
{
    Zb_memset(cfg, 0, (uint32_t)sizeof *cfg);

    cfg->present = run->present;
    cfg->channel = run->channel;
    cfg->page = 0;
    cfg->panId = (uint16_t)run->panId;
    cfg->shortAddress = (uint16_t)run->ownShort;
    cfg->rxOnWhenIdle = 1;
    cfg->deviceType = NWK_DEVICE_COORDINATOR;
    cfg->seqStart = run->seqStart;
    cfg->jitterSeed = JITTER_SEED;
    cfg->dsnStart = run->dsnStart;
    cfg->nwkSecurityLevel = run->level;

    extendedOctetsOf(ownIeee, cfg->extendedAddress);

    if (run->level == LEVEL_NONE)
        return;

    Zb_memset(descriptor, 0, (uint32_t)sizeof *descriptor);
    descriptor->keySeqNumber = KEY_SEQ;
    descriptor->inUse = 1;
    descriptor->outgoingFrameCounter = 0;
    Zb_memcpy(descriptor->key, run->key, SECURITY_KEY_OCTETS);

    Zb_memset(secCfg, 0, (uint32_t)sizeof *secCfg);
    secCfg->ownIeee = ownIeee;
    secCfg->nwkSecurityLevel = (uint8_t)run->level;
    secCfg->nwkActiveKeySeqNumber = KEY_SEQ;
    secCfg->authenticated = 1;
    secCfg->nwkAllFresh = 1;
    secCfg->keys = descriptor;
    secCfg->keyCount = 1;

    cfg->security = secCfg;
}

/* A unicast needs a next hop, and only an association or a received frame puts one in the neighbour table:
   the entry a suite seeds by hand is seeded here through the table module's own free-slot search. */
static void seedNeighbour(Nwk_Nwk *nwk, uint32_t address)
{
    Nwk_NeighborTableEntry *entry;

    entry = Nwk_NeighborFree(nwk->neighbors);

    if (!entry)
        return;

    entry->inUse = 1;
    entry->networkAddress = (uint16_t)address;
    entry->ieeeKnown = 0;
    entry->deviceType = NWK_DEVICE_ROUTER;
    entry->rxOnWhenIdle = 1;
    entry->relationship = NWK_REL_SIBLING;
}

static Aps_ApsdeReq requestOf(const SendRun *run)
{
    Aps_ApsdeReq req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    req.dstAddrMode = APS_ADDR_MODE_SHORT;
    req.dstAddress = (uint16_t)run->destShort;
    req.dstEndpoint = DST_ENDPOINT;
    req.profileId = PROFILE_ID;
    req.clusterId = CLUSTER_ID;
    req.srcEndpoint = SRC_ENDPOINT;
    req.asdu = run->asdu;
    req.asduLength = run->asduLen;
    req.txOptions = run->level == LEVEL_NONE ? APS_TX_OPTION_ACK
                                             : (APS_TX_OPTION_NWK_KEY | APS_TX_OPTION_ACK);

    return req;
}

static void printDevice(const SendRun *run, uint64_t ownIeee)
{
    printf("mode       %s\n", run->mode == MODE_MODEL ? "model: loopback_radio, no port opened, no device named"
                                                      : "path: RcpRadio_Seam behind the tee");

    if (run->mode == MODE_PATH)
        printf("device     %s\n", run->path);

    printf("stack      coordinator, own short 0x%04x, PAN 0x%04x, channel %u, rxOnWhenIdle 1\n",
           run->ownShort, run->panId, run->channel);
    printf("           the identity band A was told to apply: channel, page, pan, short, extended address,"
           " rxOnWhenIdle\n");
    printf("           ownIeee %016llx, transmitted as ", (unsigned long long)ownIeee);
    printExtended(ownIeee);
    printf(", nwk sequence seeded 0x%02x, mac dsn seeded 0x%02x, no jitter seed\n",
           run->seqStart, run->dsnStart);

    if (run->level == LEVEL_NONE)
        printf("security   level 0x00, no security config, no key material\n");
    else
    {
        printf("security   level 0x%02x (encrypted, 32-bit mic), key sequence %02x, authenticated, all-fresh\n",
               run->level, KEY_SEQ);
        printOctets("           network key as application config", run->key, SECURITY_KEY_OCTETS);
    }

    printf("request    %s to 0x%04x endpoint %02x from endpoint %02x, profile 0x%04x, cluster 0x%04x\n",
           "unicast data", run->destShort, DST_ENDPOINT, SRC_ENDPOINT, PROFILE_ID, CLUSTER_ID);
    printf("           TxOptions 0x%02x, asdu %u octets, Radius 0 (the network layer's own default)\n",
           run->level == LEVEL_NONE ? APS_TX_OPTION_ACK : (APS_TX_OPTION_NWK_KEY | APS_TX_OPTION_ACK),
           run->asduLen);

    printOctets("           asdu      ", run->asdu, run->asduLen);
}

/* The counters that say what the cascade took, read out of the three layers after the one call. */
static void printLayers(Zb_Layers *stack, const SendTee *tee)
{
    const Aps_Aps *aps = Zb_LayersAps(stack);
    const Nwk_Nwk *nwk = Zb_LayersNwk(stack);
    const Mac_Mac *mac = Zb_LayersMac(stack);
    Mac_Counters counters;

    counters = Mac_CountersOf(mac);

    printf("counters   aps queue %u refused %u  nwk queue %u refused %u  mac outstanding %u refused %u\n",
           Aps_TransmitQueue(aps), Aps_RefusedRequests(aps),
           Nwk_TransmitQueue(nwk), Nwk_RefusedRequests(nwk),
           counters.outstanding, counters.refusedRequests);
    printf("           nwk routes %u discovery %u no-route %u  aps confirms %u indications %u\n",
           Nwk_RouteQueue(nwk), Nwk_DiscoveryQueue(nwk), Nwk_DroppedNoRoute(nwk),
           Aps_ConfirmQueue(aps), Aps_IndicationQueue(aps));
    printf("           aps unmatched acks %u retransmit refusals %u duplicates %u confirmations ignored %u\n",
           Aps_UnmatchedAcks(aps), Aps_RetransmitRefusals(aps), Aps_RxDuplicateDrops(aps),
           Aps_ConfirmationsIgnored(aps));
    printf("           receive  mac self-echo %u dest-mismatch %u pan-mismatch %u malformed %u unbuilt %u\n",
           counters.selfEchoes, counters.destinationMismatches, counters.panMismatches,
           counters.malformedFrames, counters.unbuiltForms);
    printf("           nwk drops not-for-me %u bad-source %u malformed %u unsupported %u duplicate %u carrier-other %u\n",
           Nwk_DroppedNotForMe(nwk), Nwk_DroppedBadSource(nwk), Nwk_DroppedMalformed(nwk),
           Nwk_DroppedUnsupported(nwk), Nwk_DroppedDuplicate(nwk), Nwk_CarrierOther(nwk));
    printf("tee        records %u  refused by the tee %u  backend tx calls %u  completion calls %u  drops %u\n",
           tee->records, tee->txRefusals, tee->backendTxCalls, tee->completionCalls, tee->recordDrops);
}

/* ------------------------------------------------------------------ the model run */

static int runModel(const SendRun *run)
{
    Loopback_Radio model;
    SendTee tee;
    Zb_Layers stack;
    Zb_LayersConfig cfg;
    Security_Config secCfg;
    Security_KeyDescriptor descriptor;
    Aps_ApsdeReq req;
    Aps_Confirm confirms[APS_CONFIRM_MAX];
    Aps_Indication indications[APS_INDICATION_MAX];
    Radio_Caps caps;
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    uint32_t index;
    uint32_t nowMs;
    uint32_t turns;
    uint32_t taken;
    uint32_t sentCount;
    ZbStatus status;

    Zb_memset(&tee, 0, (uint32_t)sizeof tee);
    Zb_memset(&caps, 0, (uint32_t)sizeof caps);

    caps.radioCaps = 0x10d;
    caps.hasTransmit = 1;
    caps.psduIncludesFcs = 1;
    caps.handlesAckTimeout = 1;

    if (LoopbackRadio_Init(&model, &caps) != ZB_OK)
    {
        printf("backend    the hardware-free model would not initialise\n");
        return 1;
    }

    tee.backend = LoopbackRadio_Seam(&model);
    tee.seam.ops = &s_teeOps;
    tee.seam.provider = &tee;
    tee.authorised = 0;

    stackConfigOf(run, run->ownIeee, &cfg, &secCfg, &descriptor);

    if (Zb_LayersInit(&stack, &tee.seam, &cfg) != ZB_OK)
    {
        printf("stack      band A would not adopt the tee over the model\n");
        return 1;
    }

    if (!run->noNeighbour)
        seedNeighbour(Zb_LayersNwk(&stack), run->destShort);

    if (tee.backend->ops->caps(tee.backend, &caps) != ZB_OK)
        Zb_memset(&caps, 0, (uint32_t)sizeof caps);

    printDevice(run, run->ownIeee);

    printf("tee        band A was handed this seam and nothing else: it forwards every operation to the model\n"
           "           and refuses every tx it is asked, because a model has no air to authorise\n");

    req = requestOf(run);
    nowMs = TURN_STEP_MS;

    status = Zb_LayersDataRequest(&stack, &req, nowMs);

    printf("request    the façade answered %s\n", statusName(status));

    for (turns = 0; turns < MODEL_TURN_MAX; turns++)
    {
        nowMs = nowMs + TURN_STEP_MS;

        if (LoopbackRadio_Pump(&model, nowMs) != ZB_OK)
            break;

        if (Zb_LayersStep(&stack, nowMs) != ZB_OK)
            printf("turn       the layers refused t+%u ms\n", nowMs);

        taken = Zb_LayersPollConfirms(&stack, confirms, APS_CONFIRM_MAX);

        for (index = 0; index < taken; index++)
        {
            printf("confirm    aps counter %02x  %s  aps status 0x%02x  attempts %u  dst 0x%04x ep %02x <- ep %02x\n",
                   confirms[index].apsCounter, statusName(confirms[index].status), confirms[index].apsStatus,
                   confirms[index].attempts, confirms[index].dstAddress, confirms[index].dstEndpoint,
                   confirms[index].srcEndpoint);
        }

        printf("turn %u     confirms %u  indications %u\n", turns, taken,
               Zb_LayersPollIndications(&stack, indications, APS_INDICATION_MAX));
    }

    printLayers(&stack, &tee);

    if (tee.records == 0)
    {
        printf("tee        no record: the request composed nothing this tool could print\n");
        return 1;
    }

    printRecords(&tee);
    printRx(&tee);
    printFields(&tee, &caps, run);

    if (run->level != LEVEL_NONE)
        shadowUnprotect(run, run->ownIeee, &caps, &tee);

    sentCount = LoopbackRadio_Sent(&model, sent, LOOPBACK_TX_MAX);

    printf("proof      the model backend was handed %u transmit(s) and refused %u of its own: the refusal the\n"
           "           tee recorded is the tee's, and nothing reached the model's air\n",
           sentCount, LoopbackRadio_Refusals(&model));
    printf("proof      %u record(s) of %u octet(s) above were written from the octets band A handed tx\n",
           tee.records, tee.record[0].len);
    printf("port       none opened, no device named, no stick touched\n");

    return 0;
}

/* ------------------------------------------------------------------ the path run */

/* Band B queues a seam write and puts it on the link on a pump: this is the bounded wait for its own queue
   to be empty. `drain` takes every frame the link delivered off it while waiting, which is what a bring-up
   must do before band A can see the seam at all (docs/internals/protocol.md §7.1). */
static int flushWrites(Rcp_Radio *radio, uint32_t *outPumps, uint32_t *outHeard, uint32_t drain)
{
    Radio_Frame frames[RADIO_FRAME_BATCH_MAX];
    const Radio_Radio *seam;
    uint32_t pumps;
    uint32_t taken;

    seam = RcpRadio_Seam(radio);

    for (pumps = 0; pumps < FLUSH_PUMPS_MAX; pumps++)
    {
        if (RcpRadio_Pump(radio, Port_NowMs()) != ZB_OK)
        {
            *outPumps = pumps;
            return 1;
        }

        if (drain)
        {
            taken = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);
            *outHeard = *outHeard + taken;
        }

        if (radio->writeCount == 0)
            break;

        pauseHost();
    }

    *outPumps = pumps;

    return 0;
}

/* A session that opened a port ends with a reset, and this is the only way out of a path run: every exit
   after the open takes it, a refusal included. Nothing else closes the
   port. */
static void endSession(Rcp_Radio *radio, uint32_t nowMs)
{
    uint32_t pump;

    RcpRadio_Restart(radio, nowMs);

    for (pump = 0; pump < END_PUMPS; pump++)
    {
        RcpRadio_Pump(radio, Port_NowMs());
        pauseHost();
    }

    RcpRadio_Close(radio);

    printf("reset      RESET issued through RcpRadio_Restart, %u pumps put it on the link, then band B's\n"
           "           teardown writes and the close: the stick is left unarmed\n",
           END_PUMPS);
}

static int runPath(const SendRun *run)
{
    Rcp_Radio radio;
    SendTee tee;
    Zb_Layers stack;
    Zb_LayersConfig cfg;
    Security_Config secCfg;
    Security_KeyDescriptor descriptor;
    Aps_ApsdeReq req;
    Aps_Confirm confirms[APS_CONFIRM_MAX];
    Aps_Indication indications[APS_INDICATION_MAX];
    Radio_Caps caps;
    Radio_Frame frames[RADIO_FRAME_BATCH_MAX];
    Radio_Pib pib;
    PortConfig portCfg;
    uint8_t version[96];
    uint32_t versionLen;
    uint32_t pumps;
    uint32_t flushPumps;
    uint32_t bringUpMs;
    uint32_t nowMs;
    uint32_t startMs;
    uint32_t deadline;
    uint32_t taken;
    uint32_t heard;
    uint32_t turnBudget;
    uint32_t turns;
    uint32_t confirmGot;
    uint32_t indicationGot;
    uint32_t txCode;
    uint32_t txCodeKnown;
    uint32_t requests;
    uint32_t replies;
    uint32_t notifications;
    uint32_t stale;
    uint32_t timeouts;
    uint32_t malformed;
    const Radio_Radio *seam;
    uint64_t ownIeee;
    uint64_t factory;
    ZbStatus status;
    int linkFault;

    Zb_memset(&tee, 0, (uint32_t)sizeof tee);
    Zb_memset(&caps, 0, (uint32_t)sizeof caps);
    Zb_memset(&pib, 0, (uint32_t)sizeof pib);

    linkFault = 0;
    heard = 0;

    portCfg.baud = run->baud;
    portCfg.rxRingSize = run->rxRing;
    portCfg.txRingSize = run->txRing;
    portCfg.exclusive = 1;

    if (RcpRadio_Init(&radio, PortPosixOps(), run->timeoutMs) != ZB_OK)
    {
        printf("backend    the backend would not initialise\n");
        return 1;
    }

    if (RcpRadio_Open(&radio, run->path, &portCfg) != ZB_OK)
    {
        printf("%s: could not open the link (platform error %u). No port was opened, so no reset is owed\n",
               run->path, Port_PlatformErrno(&radio.port));
        return 1;
    }

    seam = RcpRadio_Seam(&radio);

    pib.present = RADIO_PIB_CHANNEL;
    pib.channel = run->channel;

    if (seam->ops->pibSet((Radio_Radio *)seam, &pib) != ZB_OK)
    {
        printf("armed      the channel was refused\n");
        endSession(&radio, Port_NowMs());
        return 1;
    }

    startMs = Port_NowMs();
    deadline = startMs + BRINGUP_TIMEOUT_MS;
    pumps = 0;

    while (RcpRadio_Mode(&radio) != RCP_RADIO_MODE_RUNNING && !Zb_timeReached(Port_NowMs(), deadline))
    {
        if (RcpRadio_Pump(&radio, Port_NowMs()) != ZB_OK)
            break;

        pumps++;
        taken = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);
        heard = heard + taken;

        if (RcpRadio_RxQueued(&radio) == 0 && RcpRadio_Mode(&radio) != RCP_RADIO_MODE_RUNNING)
            pauseHost();
    }

    bringUpMs = Port_NowMs() - startMs;
    versionLen = RcpRadio_VersionText(&radio, version, (uint32_t)sizeof version);

    if (flushWrites(&radio, &flushPumps, &heard, 1))
    {
        printf("link       the link went away during bring-up (last error %d)\n", RcpRadio_LastError(&radio));
        endSession(&radio, Port_NowMs());
        return 1;
    }

    /* The extended address a security config is bound to is the one the device reports as its own factory
       address, so a secured run on a stick takes it from the stick unless --ieee named one: that is the
       address the arming filter has to match. */
    ownIeee = run->ownIeee;
    factory = 0;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);

    if (seam->ops->pibGet((Radio_Radio *)seam, &pib) == ZB_OK)
        factory = extendedValueOf(pib.hwAddress);

    if (!run->ieeeGiven && factory != 0)
        ownIeee = factory;

    printDevice(run, ownIeee);

    printf("dialect    %.*s\n", (int)versionLen, version);
    printf("bring-up   %s in %u pumps over %u ms, last error %d, %u frame(s) taken off the link on the way\n",
           modeName(RcpRadio_Mode(&radio)), pumps, bringUpMs, RcpRadio_LastError(&radio), heard);

    printf("identity   %s\n", run->ieeeGiven ? "the --ieee address the command line named"
                                             : "the extended address this device reported as its factory one");
    printf("           ownIeee for the security config %016llx, transmitted as ", (unsigned long long)ownIeee);
    printExtended(ownIeee);
    printf(", the factory address as this device reported it ");
    printExtended(factory);
    printf("\n");

    if (RcpRadio_Mode(&radio) != RCP_RADIO_MODE_RUNNING)
    {
        printf("armed      not armed: %s (last error %d)\n", modeName(RcpRadio_Mode(&radio)),
               RcpRadio_LastError(&radio));
        endSession(&radio, Port_NowMs());
        return 1;
    }

    tee.backend = (Radio_Radio *)seam;
    tee.rcp = &radio;
    tee.seam.ops = &s_teeOps;
    tee.seam.provider = &tee;
    tee.authorised = (run->wantTx && run->allowTx) ? 1 : 0;

    stackConfigOf(run, ownIeee, &cfg, &secCfg, &descriptor);

    status = Zb_LayersInit(&stack, &tee.seam, &cfg);

    if (status != ZB_OK)
    {
        printf("stack      band A would not adopt the tee over the stick: %s, band B last error %d in %s\n",
               statusName(status), RcpRadio_LastError(&radio), modeName(RcpRadio_Mode(&radio)));

        if (status == ZB_ERR_BAD_ARGUMENT)
            printf("           a refused argument is the identity binding or a field band B will not take: name one\n"
                   "           with --ieee, or drop --level and its key\n");

        endSession(&radio, Port_NowMs());
        return 1;
    }

    if (!run->noNeighbour)
        seedNeighbour(Zb_LayersNwk(&stack), run->destShort);

    if (flushWrites(&radio, &flushPumps, &heard, 0))
    {
        printf("link       the link went away while band A's own identity write was being put on it (last error %d)\n",
               RcpRadio_LastError(&radio));
        endSession(&radio, Port_NowMs());
        return 1;
    }

    if (tee.backend->ops->caps(tee.backend, &caps) != ZB_OK)
        Zb_memset(&caps, 0, (uint32_t)sizeof caps);

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);

    if (seam->ops->pibGet((Radio_Radio *)seam, &pib) != ZB_OK)
    {
        printf("read-back  band B would not report the armed PIB\n");
        endSession(&radio, Port_NowMs());
        return 1;
    }

    printf("armed      channel %u  pan 0x%04x  short 0x%04x  rxOnWhenIdle %d, read back through the seam after\n"
           "           %u pumps put band A's own PIB write on the link; the tee forwards, so the stick is armed\n"
           "           as the sender of the frame it was asked to carry\n",
           pib.channel, pib.panId, pib.shortAddress, pib.rxOnWhenIdle, flushPumps);

    if (run->filtered)
    {
        for (turns = 0; turns < TURN_SLACK; turns++)
        {
            status = Mac_SetPromiscuousMode(Zb_LayersMac(&stack), 0);

            if (status == ZB_OK)
                break;

            if (RcpRadio_Pump(&radio, Port_NowMs()) != ZB_OK)
                break;
        }

        printf("delivery   %s\n", status == ZB_OK
                                 ? "filtered to its own address, promiscuous mode off through band A's own door (10.23.1)"
                                 : "the promiscuous mode could not be stated: the stick keeps the mode the arm "
                                   "sequence left it in, and a receive-all stick acknowledges nothing (6.20)");
    }

    printf("send       %s\n", tee.authorised ? "--tx and --allow-tx both named: the tee forwards tx to the backend"
                                             : "no authorisation: the tee records the frame and answers the seam unsupported");

    /* `--send-at` holds the request back while the stack keeps turning, so a run can transmit after a peer that
       started earlier has finished arming. Without it the first transmission is always the first thing this run does,
       which is what makes a two-stick measurement of an acknowledgement a race between arming and sending. */
    if (run->sendAtMs != 0)
    {
        uint32_t sendDeadline = Port_NowMs() + run->sendAtMs;

        printf("send       the request is held for %u ms while this stack keeps turning\n", run->sendAtMs);

        while (!Zb_timeReached(Port_NowMs(), sendDeadline))
        {
            if (RcpRadio_Pump(&radio, Port_NowMs()) != ZB_OK)
                break;

            (void)Zb_LayersStep(&stack, Port_NowMs());
            pauseHost();
        }
    }

    req = requestOf(run);
    nowMs = Port_NowMs();

    status = Zb_LayersDataRequest(&stack, &req, nowMs);

    printf("request    the façade answered %s at t+%u ms\n", statusName(status), nowMs - startMs);

    deadline = Port_NowMs() + run->waitMs;

    turnBudget = run->waitMs / PUMP_PAUSE_MS + TURN_SLACK;

    if (turnBudget > TURN_MAX)
        turnBudget = TURN_MAX;

    for (turns = 0; turns < turnBudget && !Zb_timeReached(Port_NowMs(), deadline); turns++)
    {
        if (RcpRadio_Pump(&radio, Port_NowMs()) != ZB_OK)
        {
            printf("link       the link went away: %s (last error %d)\n", modeName(RcpRadio_Mode(&radio)),
                   RcpRadio_LastError(&radio));
            linkFault = 1;
            break;
        }

        nowMs = Port_NowMs();

        if (Zb_LayersStep(&stack, nowMs) != ZB_OK)
            printf("turn       the layers refused t+%u ms\n", nowMs - startMs);

        confirmGot = Zb_LayersPollConfirms(&stack, confirms, APS_CONFIRM_MAX);

        for (pumps = 0; pumps < confirmGot; pumps++)
        {
            printf("confirm    aps counter %02x  %s  aps status 0x%02x  attempts %u  dst 0x%04x ep %02x <- ep %02x\n",
                   confirms[pumps].apsCounter, statusName(confirms[pumps].status),
                   confirms[pumps].apsStatus, confirms[pumps].attempts,
                   confirms[pumps].dstAddress, confirms[pumps].dstEndpoint, confirms[pumps].srcEndpoint);
        }

        indicationGot = Zb_LayersPollIndications(&stack, indications, APS_INDICATION_MAX);

        if (indicationGot != 0)
            printf("indicate   %u delivery/deliveries through the façade\n", indicationGot);

        if (!tee.authorised)
            break;

        /* The wait is a listening window and not a deadline for the request: a request answered in 50 ms would
           otherwise end the run before a peer that started later ever transmitted, and the frames a case is
           measuring are the peer's (a measured asymmetry needs both RCPs on the air at once). */
        if (confirmGot != 0 && Mac_CountersOf(Zb_LayersMac(&stack)).outstanding == 0 && !run->listenOn)
            break;

        pauseHost();
    }

    if (tee.records != 0 && tee.record[0].issued && tee.record[0].handle != RADIO_HANDLE_NONE)
    {
        txCodeKnown = 0;

        if (RcpRadio_TxStatusCode(&radio, tee.record[0].handle, &txCode) == ZB_OK)
            txCodeKnown = 1;

        if (txCodeKnown)
            printf("tx status  device code %u, the stick's own word for the outcome\n", txCode);
    }

    printLayers(&stack, &tee);

    if (tee.records == 0)
    {
        printf("tee        no record: the request composed nothing this tool could print\n");
        endSession(&radio, Port_NowMs());
        return 1;
    }

    printRecords(&tee);
    printRx(&tee);
    printFields(&tee, &caps, run);

    if (run->level != LEVEL_NONE && tee.record[0].issued)
        shadowUnprotect(run, ownIeee, &caps, &tee);

    RcpRadio_Transactions(&radio, &requests, &replies, &notifications, &stale, &timeouts, &malformed);

    printf("link       requests %u replies %u notifications %u stale %u timeouts %u malformed %u  "
           "rxOverflows %u linkDrops %u writeFailures %u resets %u  heard %u\n",
           requests, replies, notifications, stale, timeouts, malformed,
           RcpRadio_RxOverflows(&radio), RcpRadio_LinkDrops(&radio), RcpRadio_WriteFailures(&radio),
           RcpRadio_ResetsSeen(&radio), heard);

    endSession(&radio, Port_NowMs());

    return linkFault ? 1 : 0;
}
/* ------------------------------------------------------------------ the command line */

int main(int argc, char **argv)
{
    SendRun run;
    uint32_t index;
    uint32_t keyLen;
    uint32_t ieeeLen;
    uint8_t ieee[RADIO_ADDR_LEN];
    uint32_t asduLen;
    const char *next;
    int protectTaken;

    Zb_memset(&run, 0, (uint32_t)sizeof run);

    run.mode = MODE_NONE;
    run.channel = CHANNEL_DEFAULT;
    run.panId = PAN_INERT;
    run.ownShort = OWN_SHORT_DEFAULT;
    run.destShort = DEST_SHORT_DEFAULT;
    run.level = LEVEL_NONE;
    run.seqStart = SEQ_START;
    run.dsnStart = DSN_START;
    run.ownIeee = 0x0123456789abcdef;
    run.timeoutMs = 1000;
    run.waitMs = TX_WAIT_MS;

    Zb_memcpy(run.asdu, s_asduDefault, (uint32_t)sizeof s_asduDefault);
    run.asduLen = (uint32_t)sizeof s_asduDefault;

    for (index = 1; index < (uint32_t)argc; index++)
    {
        next = index + 1 < (uint32_t)argc ? argv[index + 1] : 0;

        if ((protectTaken = protectOption(&run.protect, argc, argv, index)) != 0)
        {
            if (protectTaken < 0)
            {
                printf("refused    --protect-channel takes a channel 11..26, --protect-pan a PAN id in hex, at most %u\n",
                       (unsigned)PROTECT_PAN_MAX);
                return 2;
            }

            index++;
        }
        else if (strcmp(argv[index], "--model") == 0)
        {
            if (run.mode != MODE_NONE)
            {
                printf("refused    two modes named: --model and --path are alternatives, not a pair\n");
                return 2;
            }

            run.mode = MODE_MODEL;
        }
        else if (strcmp(argv[index], "--path") == 0 && next != 0)
        {
            if (run.mode != MODE_NONE)
            {
                printf("refused    two modes named: --model and --path/--device are alternatives, not a pair\n");
                return 2;
            }

            run.mode = MODE_PATH;
            run.path = deviceMapResolve(next);
            index++;
        }
        else if (strcmp(argv[index], "--device") == 0 && next != 0)
        {
            const char *named = deviceMapLookup(next);

            if (run.mode != MODE_NONE)
            {
                printf("refused    two modes named: --model and --path/--device are alternatives, not a pair\n");
                return 2;
            }

            if (!named)
            {
                printf("refused    --device takes a name the file ZB_DEVICE_MAP names; give --path otherwise\n");
                return 2;
            }

            run.mode = MODE_PATH;
            run.path = named;
            index++;
        }
        else if (strcmp(argv[index], "--channel") == 0 && next != 0)
        {
            run.channel = decValue(next);
            index++;
        }
        else if (strcmp(argv[index], "--pan") == 0 && next != 0)
        {
            run.panId = hexValue(next);
            index++;
        }
        else if (strcmp(argv[index], "--own") == 0 && next != 0)
        {
            run.ownShort = hexValue(next);
            index++;
        }
        else if (strcmp(argv[index], "--dst") == 0 && next != 0)
        {
            run.destShort = hexValue(next);
            index++;
        }
        else if (strcmp(argv[index], "--level") == 0 && next != 0)
        {
            run.level = hexValue(next);
            index++;
        }
        else if (strcmp(argv[index], "--seq") == 0 && next != 0)
        {
            run.seqStart = hexValue(next) & 0xff;
            index++;
        }
        else if (strcmp(argv[index], "--dsn") == 0 && next != 0)
        {
            run.dsnStart = hexValue(next) & 0xff;
            index++;
        }
        else if (strcmp(argv[index], "--key") == 0 && next != 0)
        {
            if (!parseOctets(next, run.key, SECURITY_KEY_OCTETS, &keyLen) || keyLen != SECURITY_KEY_OCTETS)
            {
                printf("refused    --key wants %d octets: %u came\n", SECURITY_KEY_OCTETS, keyLen);
                return 2;
            }

            run.keyGiven = 1;
            index++;
        }
        else if (strcmp(argv[index], "--ieee") == 0 && next != 0)
        {
            if (!parseOctets(next, ieee, RADIO_ADDR_LEN, &ieeeLen) || ieeeLen != RADIO_ADDR_LEN)
            {
                printf("refused    --ieee wants %d octets: %u came\n", RADIO_ADDR_LEN, ieeeLen);
                return 2;
            }

            run.ownIeee = extendedValueOf(ieee);
            run.ieeeGiven = 1;
            index++;
        }
        else if (strcmp(argv[index], "--asdu") == 0 && next != 0)
        {
            if (!parseOctets(next, run.asdu, ASDU_MAX, &asduLen))
            {
                printf("refused    --asdu wants hex octets, at most %d of them\n", ASDU_MAX);
                return 2;
            }

            run.asduLen = asduLen;
            index++;
        }
        else if (strcmp(argv[index], "--timeout") == 0 && next != 0)
        {
            run.timeoutMs = decValue(next);
            index++;
        }
        else if (strcmp(argv[index], "--baud") == 0 && next != 0)
        {
            run.baud = decValue(next);
            index++;
        }
        else if (strcmp(argv[index], "--rx-ring") == 0 && next != 0)
        {
            run.rxRing = decValue(next);
            index++;
        }
        else if (strcmp(argv[index], "--tx-ring") == 0 && next != 0)
        {
            run.txRing = decValue(next);
            index++;
        }
        else if (strcmp(argv[index], "--help") == 0)
        {
            usage();
            return 0;
        }
        else if (strcmp(argv[index], "--no-neighbour") == 0)
            run.noNeighbour = 1;
        else if (strcmp(argv[index], "--no-promisc") == 0)
            run.filtered = 1;
        else if (strcmp(argv[index], "--listen-on") == 0)
            run.listenOn = 1;
        else if (strcmp(argv[index], "--send-at") == 0 && next != 0)
        {
            run.sendAtMs = decValue(next);
            index++;
        }
        else if (strcmp(argv[index], "--wait") == 0 && next != 0)
        {
            run.waitMs = decValue(next);
            index++;

            if (run.waitMs < 100 || run.waitMs > 15000)
            {
                printf("refused    --wait wants a turn budget of 100 to 15000 ms\n");
                return 2;
            }
        }
        else if (strcmp(argv[index], "--tx") == 0)
            run.wantTx = 1;
        else if (strcmp(argv[index], "--allow-tx") == 0)
            run.allowTx = 1;
        else
        {
            usage();
            return 2;
        }
    }

    if (judgeRun(&run))
        return 2;

    run.present = PRESENT_FULL;

    if (run.mode == MODE_MODEL)
        return runModel(&run);

    return runPath(&run);
}
