#define _POSIX_C_SOURCE 200809    /* nanosleep is POSIX; glibc hides it under -std=c99 without this, before any include */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aps.h"
#include "aps_frame.h"
#include "device_map.h"
#include "mac.h"
#include "mac_frame.h"
#include "nwk.h"
#include "nwk_frame.h"
#include "port.h"
#include "port_posix.h"
#include "props.h"
#include "radio.h"
#include "rcp_radio.h"
#include "security.h"
#include "zb_time.h"
#include "zb_utils.h"
#include "zb_layers.h"

/*
 * The live observer: the stack of src/zb run against a running network, by default the
 * channel-15 test network the interop fixtures come from (PAN 0xde20), as a strictly passive
 * listener, with that network's key arriving as application config.
 *
 * This program has no transmit path at all, and that is a construction rather than a policy:
 *
 *   - it takes no `--tx` and no `--allow-tx`; an argument naming one is refused at the door;
 *   - the seam band A is handed is a deny-tx shim (the same table
 *     `test/interop/` asserts offline): every operation is forwarded to the real backend unchanged
 *     except `tx`, which the shim answers `ZB_ERR_UNSUPPORTED` before the backend is reached, counted;
 *   - the shim's `backendTxCalls` is a counter no code path in this file increments, because nothing in
 *     this table calls the backend's `tx`. It is the machine-readable half of the passive promise; the
 *     poll answers, APS acknowledgements, broadcast relays and 3.6.13 answers the receive logic generates
 *     are refused as facts and every refusal is a named number.
 *
 * Arming mirrors `harness/rcp_sniffer.py`'s measured passive configuration, reached through band
 * B's own API rather than invented here: the dialect's arm sequence (docs/internals/protocol.md §6's sniffer
 * variant, `PHY_ENABLED` → `PHY_CHAN` → `MAC_PROMISCUOUS_MODE` full → `MAC_RX_ON_WHEN_IDLE`
 * → `MAC_RAW_STREAM_ENABLED`, the order `src/rcp/props.c` holds for this dialect), then the
 * sniffer identity the harness writes as its defaults, `MAC_15_4_SADDR` an unused short address
 * and `MAC_15_4_PANID` 0xffff match-any, because the harness measures that a stick armed to
 * one specific PAN is silenced even in promiscuous full mode, and then the seam's own filter
 * call saying promiscuous. No property outside the ones docs/internals/protocol.md §7 records is written,
 * and no property read is invented: band B's discovery GETs (NCP_VERSION, INTERFACE_TYPE,
 * RCP_API_VERSION, RCP_MIN_HOST_API_VERSION, CAPS, RADIO_CAPS, HWADDR) are the reads this backend
 * performs, and the armed state printed below is band B's own PIB as `pibGet` reports it.
 *
 * Band A's identity and the radio's identity are deliberately different, and the shim is where that
 * decision is made and counted. The config pins this device as a coordinator with short 0xfff0 on PAN
 * 0xde20: the identity the *stack* judges delivery with. Writing that identity to the stick would arm the
 * stick's own filter with it, and a stick addressed by a live frame answers that frame (docs/internals/protocol.md §6): an transmission caused by our configuration on the network this arc may only read.
 * So the shim holds `RADIO_PIB_PAN_ID` and `RADIO_PIB_SHORT_ADDRESS` off the wire, counts every hold, and
 * the stick keeps the sniffer identity above. Band A's mirror holds the identity this shim accepted.
 *
 * The stick is left as a session must leave it: `RcpRadio_Restart` issues the reset, one pump puts it on
 * the link, and `RcpRadio_Close` writes §6's teardown order before hanging up.
 */

#define BRINGUP_TIMEOUT_MS 6000
#define FLUSH_PUMPS_MAX 400
#define LEDGER_INTERVAL_MS 5000
#define PUMP_PAUSE_MS 2
#define END_PUMPS 3

#define CHANNEL_DEFAULT 15
#define SECONDS_DEFAULT 45
#define REPLY_TIMEOUT_MS 1000

/* The config, the same numbers test/interop/ pins offline. ownIeee is a sentinel: no
   captured auxiliary source address and no captured NWK source IEEE equals it, so nothing this device
   hears can be mistaken for its own traffic. */
#define DEFAULT_OWN_SHORT 0xfff0
#define DEFAULT_PAN_ID 0xde20
#define CHANNEL 15
#define DEFAULT_KEY_OCTET 0xcc
#define DEFAULT_KEY_SEQ 0
#define DEFAULT_LEVEL 5

/* The identity the measured sniffer arms the radio with: an unused short address and the match-any PAN
   (harness/rcp_sniffer.py's --own-addr and --own-pan defaults). */
#define SNIFFER_SHORT 0x4242
#define SNIFFER_PAN 0xffff

#define HEARD_LOG_MAX 256         /* PSDUs this session handed up, kept for the deviation prints */
#define HEX_MAX 2                 /* example frames printed per family, the brief's cap */
#define HEX_OCTETS (RADIO_MPDU_MAX * 3 + 4)

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

/* ------------------------------------------------------------------ the port's clock */

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

    if (status == ZB_ERR_UNSUPPORTED)
        return "unsupported";

    if (status == ZB_ERR_BAD_FRAME)
        return "bad-frame";

    if (status == ZB_ERR_NO_SPACE)
        return "no-space";

    if (status == ZB_ERR_TIMEOUT)
        return "timeout";

    if (status == ZB_ERR_NOT_READY)
        return "not-ready";

    if (status == ZB_ERR_DEVICE_LOST)
        return "device-lost";

    return "refused";
}

/* ------------------------------------------------------------------ the deny-tx shim */

typedef struct HeardFrame
{
    uint32_t len;
    uint8_t bytes[RADIO_MPDU_MAX];
} HeardFrame;

/*
 * The deny-tx table, mirrored from the one test/interop/ asserts: forward every seam call to
 * the backend with its own provider, refuse `tx`, and count. Plus this tool's two own decisions: the sniffer
 * identity fields held off the wire (counted), and a copy of every PSDU handed up, so a deviation can be
 * printed as octets rather than as a counter.
 */
typedef struct DenyTx
{
    Radio_Radio *backend;
    Radio_Radio seam;

    uint32_t txRefusals;
    uint32_t backendTxCalls;      /* structurally zero: no function below calls backend->ops->tx */
    uint32_t identityHolds;       /* PAN_ID and SHORT_ADDRESS fields this tool kept off the wire */
    uint32_t framesHandedUp;
    uint32_t logCount;
    uint32_t logDrops;            /* a frame with no room left in the log: counted, never silently dropped */
    HeardFrame log[HEARD_LOG_MAX];
} DenyTx;

static ZbStatus denyCaps(Radio_Radio *radio, Radio_Caps *outCaps)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->caps(self->backend, outCaps);
}

static ZbStatus denyPibSet(Radio_Radio *radio, const Radio_Pib *pib)
{
    DenyTx *self = (DenyTx *)radio->provider;
    Radio_Pib forwarded;

    if (pib == 0)
        return ZB_ERR_BAD_ARGUMENT;

    forwarded = *pib;
    forwarded.present = pib->present;

    if ((forwarded.present & RADIO_PIB_PAN_ID) != 0)
    {
        forwarded.present = forwarded.present & ~RADIO_PIB_PAN_ID;
        forwarded.panId = 0;
        self->identityHolds++;
    }

    if ((forwarded.present & RADIO_PIB_SHORT_ADDRESS) != 0)
    {
        forwarded.present = forwarded.present & ~RADIO_PIB_SHORT_ADDRESS;
        forwarded.shortAddress = 0;
        self->identityHolds++;
    }

    if (forwarded.present == 0)
        return ZB_OK;

    return self->backend->ops->pibSet(self->backend, &forwarded);
}

static ZbStatus denyPibGet(Radio_Radio *radio, Radio_Pib *pib)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->pibGet(self->backend, pib);
}

static ZbStatus denyFilter(Radio_Radio *radio, const Radio_Filter *filter)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->filter(self->backend, filter);
}

static ZbStatus denyCompletion(Radio_Radio *radio, Radio_Handle handle, Radio_TxResult *outResult)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->completion(self->backend, handle, outResult);
}

static uint32_t denyRxPoll(Radio_Radio *radio, Radio_Frame *outFrames, uint32_t maxFrames)
{
    DenyTx *self = (DenyTx *)radio->provider;
    uint32_t got;
    uint32_t i;

    got = self->backend->ops->rxPoll(self->backend, outFrames, maxFrames > 1 ? 1 : maxFrames);

    for (i = 0; i < got; i++)
    {
        self->framesHandedUp++;

        if (self->logCount >= HEARD_LOG_MAX)
        {
            self->logDrops++;
            continue;
        }

        self->log[self->logCount].len = outFrames[i].len;
        Zb_memcpy(self->log[self->logCount].bytes, outFrames[i].bytes, outFrames[i].len);
        self->logCount++;
    }

    return got;
}

static int denyIsLost(Radio_Radio *radio)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->isLost(self->backend);
}

static ZbStatus denyScanStart(Radio_Radio *radio, uint32_t channel, uint32_t dwellUnits)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->scanStart(self->backend, channel, dwellUnits);
}

static ZbStatus denyScanCollect(Radio_Radio *radio, uint32_t *outChannel, int32_t *outDbm)
{
    DenyTx *self = (DenyTx *)radio->provider;

    return self->backend->ops->scanCollect(self->backend, outChannel, outDbm);
}

/* The one seam member this table does not forward. No handle is handed back: the shim named the refusal. */
static ZbStatus denyTx(Radio_Radio *radio, const uint8_t *mpdu, uint32_t len, int ackRequest,
                       uint32_t maxFrameRetries, Radio_Handle *outHandle)
{
    DenyTx *self = (DenyTx *)radio->provider;

    (void)mpdu;
    (void)len;
    (void)ackRequest;
    (void)maxFrameRetries;
    (void)outHandle;

    self->txRefusals++;

    return ZB_ERR_UNSUPPORTED;
}

static const Radio_Ops s_denyOps =
{
    denyCaps,
    denyPibSet,
    denyPibGet,
    denyFilter,
    denyTx,
    denyCompletion,
    denyRxPoll,
    denyIsLost,
    denyScanStart,
    denyScanCollect
    , 0    /* no pending table on this backend */
};

/* ------------------------------------------------------------------ what this run drove */

typedef struct DrivenCounters
{
    uint32_t pollEvents;
    uint32_t indications;
    uint32_t confirms;
    uint32_t stepsRefusingTx;
    uint32_t pumps;
} DrivenCounters;

/* ------------------------------------------------------------------ deviation capture */

typedef struct Deviation
{
    uint32_t malformedTotal;
    uint32_t malformedExpectedFamily;     /* a broadcast APDU whose destination endpoint is 0x00 */
    uint32_t malformedOther;
    uint32_t expectedHexCount;
    uint32_t otherHexCount;
    char expectedHex[HEX_MAX][HEX_OCTETS];
    char otherHex[HEX_MAX][HEX_OCTETS];
} Deviation;

static void hexOf(const uint8_t *bytes, uint32_t len, char *out, uint32_t cap)
{
    uint32_t i;
    uint32_t used;

    used = 0;
    out[0] = '\0';

    for (i = 0; i < len; i++)
    {
        if (used + 3 >= cap)
            break;

        used += (uint32_t)snprintf(out + used, cap - used, "%s%02x", i ? " " : "", bytes[i]);
    }
}

static void deviationRecord(Deviation *dev, const uint8_t *nsdu, uint32_t nsduLen, int expectedFamily)
{
    char hex[HEX_OCTETS];

    dev->malformedTotal++;

    if (expectedFamily)
    {
        dev->malformedExpectedFamily++;

        if (dev->expectedHexCount < HEX_MAX)
        {
            hexOf(nsdu, nsduLen, hex, (uint32_t)sizeof hex);
            Zb_memcpy(dev->expectedHex[dev->expectedHexCount], hex, HEX_OCTETS);
            dev->expectedHexCount++;
        }

        return;
    }

    dev->malformedOther++;

    if (dev->otherHexCount < HEX_MAX)
    {
        hexOf(nsdu, nsduLen, hex, (uint32_t)sizeof hex);
        Zb_memcpy(dev->otherHex[dev->otherHexCount], hex, HEX_OCTETS);
        dev->otherHexCount++;
    }
}

/*
 * The codec's own verdict on an NSDU, in the two families `aps` counts: a form it does not read is
 * `rxShapeRefused` and a frame whose fields contradict each other is `rxMalformed` (2.2.8.4.2).
 * The expected deviation family is the one test/interop/ pins: a broadcast
 * APDU whose destination endpoint is 0x00, refused by 2.2.5.1.1.2 as read by `aps_frame`. Naming it here
 * labels an example; it bends nothing. The shim hands the MAC one frame per poll, so a step decides at most
 * one and `aps` reads it by reference: the frame a refusal named is the network layer's last indication, where
 * the step left it. Called only when a frame was refused.
 */
static void classifyIndication(const Nwk_Nwk *nwk, Deviation *dev)
{
    const Nwk_DataIndicationParameters *ind = &nwk->indication;
    Aps_Frame frame;
    uint32_t payloadOffset;
    uint32_t payloadLen;
    uint32_t fcf;
    int expectedFamily;
    ZbStatus status;

    if (ind->nsduLength == 0)
        return;

    status = ApsFrame_Parse(ind->nsdu, ind->nsduLength, &frame, &payloadOffset, &payloadLen);

    if (status == ZB_OK || status == ZB_ERR_UNSUPPORTED)
        return;

    fcf = ind->nsdu[0];

    expectedFamily = ((fcf & APS_FRAME_FCF_TYPE_MASK) == APS_FRAME_TYPE_DATA
                      && ((fcf >> APS_FRAME_FCF_DELIVERY_MODE_SHIFT) & APS_FRAME_FCF_DELIVERY_MODE_MASK) == APS_DELIVERY_BROADCAST
                      && ind->nsduLength >= 2
                      && ind->nsdu[1] == APS_ENDPOINT_ZDO) ? 1 : 0;

    deviationRecord(dev, ind->nsdu, ind->nsduLength, expectedFamily);
}

/* ------------------------------------------------------------------ the ledger
 *
 * The regression anchor for the APS security crossing, and it belongs with the numbers it anchors: no APS-secured
 * APDU exists in this session's traffic, and none exists in the two captured fixtures the same wiring runs offline
 * in `test/interop/`; the bit was measured clear in 79 of 79 and 24 of 24 APDUs. Every secured path in `aps`
 * (4.4.1.1 on the way out, 4.4.1.2 on the way in, the two transmit counters and the two receive failure counters)
 * is therefore untouched by anything this ledger prints, and the APS columns here are numbers for a fixture set
 * that cannot reach them. That is what makes the offline replay's pinned ledger a gate on the crossing as well as
 * on the layers it already pinned: a number that moves there is now a regression of the crossing's wiring too, not
 * only of the layer the number belongs to. */

typedef struct Ledger
{
    uint32_t macAcksHeard;
    uint32_t macCommandsHeard;
    uint32_t macBeaconRequestsHeard;
    uint32_t macRefusedRequests;
    uint32_t macPollsUnanswered;
    uint32_t macPollEvents;
    uint32_t macOutstanding;

    uint32_t carrierOther;
    uint32_t nwkMalformed;
    uint32_t nwkUnsupported;
    uint32_t nwkDuplicate;
    uint32_t nwkNotForMe;
    uint32_t nwkNoRoute;
    uint32_t nwkUnsecured;
    uint32_t nwkIndicationsDropped;
    uint32_t nwkBttFull;
    uint32_t nwkCommands;
    uint32_t nwkRelays;
    uint32_t nwkReplies;
    uint32_t nwkSecurityFailures;
    uint32_t nwkCounterRejects;
    uint32_t nwkTransmitQueue;
    uint32_t nwkIndicationQueue;

    uint32_t windows;
    uint32_t outgoingCounter;

    uint32_t apsShape;
    uint32_t apsMalformed;
    uint32_t apsSecured;
    uint32_t apsCommand;
    uint32_t apsDuplicate;
    uint32_t apsGroupMiss;
    uint32_t apsIndicationsDropped;
    uint32_t apsAcksGenerated;
    uint32_t apsAcksRefused;
    uint32_t apsUnmatchedAcks;
    uint32_t apsRefusedRequests;
    uint32_t apsTransmitQueue;

    uint32_t indications;
    uint32_t confirms;
    uint32_t stepsRefusingTx;
    uint32_t pumps;
} Ledger;

static void readLedger(Ledger *out, const Mac_Mac *mac, const Nwk_Nwk *nwk, const Security *security,
                       const Aps_Aps *aps, const DrivenCounters *driven)
{
    Security_KeyState state;
    Mac_Counters counters;
    uint32_t i;

    Zb_memset(out, 0, (uint32_t)sizeof *out);

    counters = Mac_CountersOf(mac);

    out->macAcksHeard = counters.acksHeard;
    out->macCommandsHeard = counters.commandsHeard;
    out->macBeaconRequestsHeard = counters.beaconRequestsHeard;
    out->macRefusedRequests = counters.refusedRequests;
    out->macPollsUnanswered = counters.pollsUnanswered;
    out->macOutstanding = counters.outstanding;

    out->carrierOther = Nwk_CarrierOther(nwk);
    out->nwkMalformed = Nwk_DroppedMalformed(nwk);
    out->nwkUnsupported = Nwk_DroppedUnsupported(nwk);
    out->nwkDuplicate = Nwk_DroppedDuplicate(nwk);
    out->nwkNotForMe = Nwk_DroppedNotForMe(nwk);
    out->nwkNoRoute = Nwk_DroppedNoRoute(nwk);
    out->nwkUnsecured = Nwk_DroppedUnsecured(nwk);
    out->nwkIndicationsDropped = Nwk_DroppedIndications(nwk);
    out->nwkBttFull = Nwk_BttFullDrops(nwk);
    out->nwkCommands = Nwk_RecognizedCommands(nwk);
    out->nwkRelays = Nwk_RelaysSent(nwk);
    out->nwkReplies = Nwk_ReplyCommands(nwk);
    out->nwkSecurityFailures = Nwk_RxSecurityFailures(nwk);
    out->nwkCounterRejects = Nwk_RxFrameCounterRejects(nwk);
    out->nwkTransmitQueue = Nwk_TransmitQueue(nwk);
    out->nwkIndicationQueue = Nwk_IndicationQueue(nwk);

    out->windows = 0;

    for (i = 0; i < SECURITY_INCOMING_MAX; i++)
    {
        if (security->incoming[i].inUse)
            out->windows++;
    }

    Security_Snapshot(security, &state);
    out->outgoingCounter = state.keyCount != 0 ? state.outgoingFrameCounter[0] : 0;

    out->apsShape = Aps_RxShapeRefused(aps);
    out->apsMalformed = Aps_RxMalformed(aps);
    out->apsSecured = Aps_RxSecuredDeferred(aps);
    out->apsCommand = Aps_RxCommandDeferred(aps);
    out->apsDuplicate = Aps_RxDuplicateDrops(aps);
    out->apsGroupMiss = Aps_DroppedGroupMiss(aps);
    out->apsIndicationsDropped = Aps_DroppedIndications(aps);
    out->apsAcksGenerated = Aps_AcksGenerated(aps);
    out->apsAcksRefused = Aps_AcksRefused(aps);
    out->apsUnmatchedAcks = Aps_UnmatchedAcks(aps);
    out->apsRefusedRequests = Aps_RefusedRequests(aps);
    out->apsTransmitQueue = Aps_TransmitQueue(aps);

    out->macPollEvents = driven->pollEvents;
    out->indications = driven->indications;
    out->confirms = driven->confirms;
    out->stepsRefusingTx = driven->stepsRefusingTx;
    out->pumps = driven->pumps;
}

static void printLedger(uint32_t elapsedMs, const Ledger *l, const DenyTx *deny, uint32_t delivered)
{
    printf("t+%3u s  heard %4u deliv %4u  ack %3u cmd %3u bcnreq %3u poll %3u other %3u  "
           "nwk bad %3u unsup %3u dup %3u notme %4u route %3u unsec %3u relay %3u btt %3u  "
           "sec fail %2u ctr %3u win %2u  "
           "aps shape %3u mal %3u sec %2u cmd %2u dup %2u grp %2u ind %3u ackRefused %2u  "
           "shim %4u backendTx %u\n",
           elapsedMs / 1000, deny->framesHandedUp, delivered,
           l->macAcksHeard, l->macCommandsHeard, l->macBeaconRequestsHeard, l->macPollEvents, l->carrierOther,
           l->nwkMalformed, l->nwkUnsupported, l->nwkDuplicate, l->nwkNotForMe, l->nwkNoRoute,
           l->nwkUnsecured, l->nwkRelays, l->nwkBttFull,
           l->nwkSecurityFailures, l->nwkCounterRejects, l->windows,
           l->apsShape, l->apsMalformed, l->apsSecured, l->apsCommand, l->apsDuplicate,
           l->apsGroupMiss, l->indications, l->apsAcksRefused,
           deny->txRefusals, deny->backendTxCalls);
}

/* ------------------------------------------------------------------ config helpers */

static void fillSecurityConfig(Security_Config *cfg, Security_KeyDescriptor *descriptor,
                               const uint8_t *key, uint8_t keySeq, uint64_t ownIeee, uint32_t level)
{
    Zb_memset(descriptor, 0, (uint32_t)sizeof *descriptor);
    descriptor->keySeqNumber = keySeq;
    descriptor->inUse = 1;
    descriptor->outgoingFrameCounter = 0;
    Zb_memcpy(descriptor->key, key, SECURITY_KEY_OCTETS);

    Zb_memset(cfg, 0, (uint32_t)sizeof *cfg);
    cfg->ownIeee = ownIeee;
    cfg->nwkSecurityLevel = (uint8_t)level;
    cfg->nwkActiveKeySeqNumber = keySeq;
    cfg->authenticated = 1;
    cfg->nwkAllFresh = 1;
    cfg->keys = descriptor;
    cfg->keyCount = 1;
}

/* The identity this session's stack runs under: the private PAN a two-RCP test uses, or the channel-15 test network's
   defaults, and the extended address the security config is bound to, which must be the one the device reports. */
typedef struct SniffIdentity
{
    uint16_t panId;
    uint16_t ownShort;
    uint32_t level;
    uint8_t keySeq;
    uint8_t key[SECURITY_KEY_OCTETS];
    uint64_t ownIeee;
} SniffIdentity;

static int parseKeyHex(const char *text, uint8_t *out, uint32_t octets, uint32_t *outLen)
{
    uint32_t index;

    if (Zb_strlen(text, octets * 2 + 1) != octets * 2)
        return 0;

    for (index = 0; index < octets; index++)
    {
        unsigned value = 0;

        if (sscanf(text + index * 2, "%2x", &value) != 1)
            return 0;

        out[index] = (uint8_t)value;
    }

    *outLen = octets;
    return 1;
}

/* The device's factory EUI-64 as the value a security config names it by, most significant octet first. */
static uint64_t factoryIdentityOf(const Rcp_Radio *radio)
{
    const uint8_t *octets = RcpRadio_Address(radio);
    uint64_t value = 0;
    uint32_t index;

    if (octets == 0)
        return 0;

    for (index = 0; index < RADIO_ADDR_LEN; index++)
        value = (value << 8) | octets[index];

    return value;
}

/*
 * A second `Security`, used only to name frames. The live crossing's windows, counters and joined flag are
 * never touched by it: it is fed the same octets in the same order after the session, so a frame the live
 * stack refused for its key or its counter can be printed as octets instead of vanishing into a counter.
 * The gates `nwk` runs before the crossing (an unreadable header, a footer that does not match, an NPDU
 * form it does not read) are mirrored here so the two counts are comparable rather than merely printed.
 */
typedef struct Shadow
{
    uint32_t securedFrames;
    uint32_t securityFailures;
    uint32_t counterRejects;
    uint32_t formRefused;
    uint32_t hexCount;
    char hex[HEX_MAX][HEX_OCTETS];
} Shadow;

static void shadowPass(const DenyTx *deny, const Radio_Caps *caps, const SniffIdentity *identity, Shadow *out)
{
    Security_KeyDescriptor descriptor;
    Security_Config cfg;
    Security shadow;
    Mac_Frame macFrame;
    Nwk_Frame nwkFrame;
    Security_Result result;
    const uint8_t *payload;
    uint8_t plain[NWK_NSDU_MAX + 1];
    uint32_t payloadLen;
    uint32_t payloadOffset;
    uint32_t headerLen;
    uint32_t plainLen;
    uint32_t i;
    char hex[HEX_OCTETS];
    ZbStatus status;

    Zb_memset(out, 0, (uint32_t)sizeof *out);
    fillSecurityConfig(&cfg, &descriptor, identity->key, identity->keySeq, identity->ownIeee, identity->level);

    if (Security_Init(&shadow, &cfg) != ZB_OK)
    {
        printf("shadow     the labelling pass could not be built\n");
        return;
    }

    for (i = 0; i < deny->logCount; i++)
    {
        status = MacFrame_Parse(deny->log[i].bytes, deny->log[i].len, caps->psduIncludesFcs,
                                &macFrame, &payload, &payloadLen, 0);

        if (status != ZB_OK)
            continue;

        if (macFrame.frameType != MAC_FRAME_TYPE_DATA)
            continue;

        if (caps->psduIncludesFcs && MacFrame_CheckFcs(deny->log[i].bytes, deny->log[i].len) != ZB_OK)
            continue;

        status = NwkFrame_Parse(payload, payloadLen, &nwkFrame, &payloadOffset, &plainLen);

        if (status != ZB_OK)
        {
            out->formRefused++;
            continue;
        }

        if (!nwkFrame.securityEnabled)
            continue;

        headerLen = payloadOffset;
        out->securedFrames++;

        status = Security_Unprotect(&shadow, payload, payloadLen, headerLen, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result);

        if (status == ZB_OK)
            continue;

        if (status == ZB_ERR_BAD_FRAME_COUNTER)
        {
            out->counterRejects++;
            continue;
        }

        out->securityFailures++;

        if (out->hexCount < HEX_MAX)
        {
            hexOf(deny->log[i].bytes, deny->log[i].len, hex, (uint32_t)sizeof hex);
            Zb_memcpy(out->hex[out->hexCount], hex, HEX_OCTETS);
            out->hexCount++;
        }
    }
}

/* ------------------------------------------------------------------ usage */

static void usage(void)
{
    printf("usage: interop_sniff --path <path>|--device <name> [--channel 15] [--seconds 45]\n"
           "                     [--timeout ms] [--baud n] [--rx-ring n]\n"
           "this program has no transmit option and no transmit path: --tx and --allow-tx are refused,\n"
           "the seam band A is handed refuses every tx, and nothing in this file reaches the backend's tx.\n");
}

int main(int argc, char **argv)
{
    Rcp_Radio radio;
    DenyTx deny;
    Zb_Layers stack;
    Zb_LayersConfig stackCfg;
    Security_KeyDescriptor descriptor;
    Security_Config securityCfg;
    Mac_Mac *mac;
    Nwk_Nwk *nwk;
    Aps_Aps *aps;
    Security *security;
    Aps_Indication indications[APS_INDICATION_MAX];
    Aps_Confirm confirms[APS_CONFIRM_MAX];
    Mac_PollArrival polls[MAC_POLL_EVENT_MAX];
    Radio_Pib pib;
    Radio_Filter filter;
    Radio_Caps caps;
    Radio_Frame frames[RADIO_FRAME_BATCH_MAX];
    PortConfig config;
    Ledger ledger;
    DrivenCounters driven;
    const Prop_Entry *entry;
    Deviation deviation;
    Shadow shadow;
    const Radio_Radio *seam;
    uint8_t version[96];
    uint32_t versionLen;
    uint32_t channel;
    SniffIdentity sniff;
    ZbStatus initStatus;
    uint32_t seconds;
    uint32_t timeoutMs;
    uint32_t taken;
    uint32_t pumps;
    uint32_t bringUpFrames;
    uint32_t flushPumps;
    uint32_t bringUpMs;
    uint32_t nowMs;
    uint32_t nextLedgerMs;
    uint32_t delivered;
    uint32_t malformedBefore;
    uint32_t requests;
    uint32_t replies;
    uint32_t notifications;
    uint32_t stale;
    uint32_t timeouts;
    uint32_t malformed;
    uint32_t i;
    uint32_t startMs;
    uint32_t deadline;
    const char *path;
    const Prop_Step *armSteps;
    uint32_t armCount;
    ZbStatus status;
    int linkFault;

    path = 0;
    channel = CHANNEL_DEFAULT;

    Zb_memset(&sniff, 0, (uint32_t)sizeof sniff);
    sniff.panId = DEFAULT_PAN_ID;
    sniff.ownShort = DEFAULT_OWN_SHORT;
    sniff.level = DEFAULT_LEVEL;
    sniff.keySeq = DEFAULT_KEY_SEQ;
    Zb_memset(sniff.key, DEFAULT_KEY_OCTET, SECURITY_KEY_OCTETS);
    seconds = SECONDS_DEFAULT;
    timeoutMs = REPLY_TIMEOUT_MS;
    pumps = 0;
    bringUpFrames = 0;
    flushPumps = 0;
    delivered = 0;
    linkFault = 0;

    Zb_memset(&deny, 0, (uint32_t)sizeof deny);
    Zb_memset(&driven, 0, (uint32_t)sizeof driven);
    Zb_memset(&deviation, 0, (uint32_t)sizeof deviation);
    Zb_memset(&ledger, 0, (uint32_t)sizeof ledger);
    Zb_memset(&shadow, 0, (uint32_t)sizeof shadow);

    config.baud = 0;
    config.rxRingSize = 0;
    config.txRingSize = 0;
    config.exclusive = 1;

    for (i = 1; i < (uint32_t)argc; i++)
    {
        if (strcmp(argv[i], "--path") == 0 && i + 1 < (uint32_t)argc)
            path = deviceMapResolve(argv[++i]);
        else if (strcmp(argv[i], "--device") == 0 && i + 1 < (uint32_t)argc)
        {
            const char *named = deviceMapLookup(argv[++i]);

            if (!named)
            {
                printf("--device takes a name the file ZB_DEVICE_MAP names; give --path otherwise\n");
                return 2;
            }

            path = named;
        }
        else if (strcmp(argv[i], "--channel") == 0 && i + 1 < (uint32_t)argc)
            channel = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--pan") == 0 && i + 1 < (uint32_t)argc)
            sniff.panId = (uint16_t)strtoul(argv[++i], 0, 16);
        else if (strcmp(argv[i], "--own") == 0 && i + 1 < (uint32_t)argc)
            sniff.ownShort = (uint16_t)strtoul(argv[++i], 0, 16);
        else if (strcmp(argv[i], "--level") == 0 && i + 1 < (uint32_t)argc)
            sniff.level = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--ieee") == 0 && i + 1 < (uint32_t)argc)
            sniff.ownIeee = strtoull(argv[++i], 0, 16);
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < (uint32_t)argc)
        {
            uint32_t len = 0;

            if (!parseKeyHex(argv[++i], sniff.key, SECURITY_KEY_OCTETS, &len))
            {
                printf("--key wants %u hex digits\n", SECURITY_KEY_OCTETS * 2);
                return 2;
            }
        }
        else if (strcmp(argv[i], "--seconds") == 0 && i + 1 < (uint32_t)argc)
            seconds = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < (uint32_t)argc)
            timeoutMs = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--baud") == 0 && i + 1 < (uint32_t)argc)
            config.baud = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--rx-ring") == 0 && i + 1 < (uint32_t)argc)
            config.rxRingSize = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--tx") == 0 || strcmp(argv[i], "--allow-tx") == 0
                 || strcmp(argv[i], "--tx-psdu") == 0)
        {
            printf("refused    this tool has no transmit path: no --tx, no --allow-tx, and a seam that refuses tx\n");
            return 2;
        }
        else
        {
            usage();
            return 2;
        }
    }

    if (path == 0)
    {
        printf("a device is required: --path <path>, or --device with a name the file ZB_DEVICE_MAP holds;\n"
               "no port is ever defaulted (docs/internals/hardware.md §8)\n");
        return 2;
    }

    if (channel < PROPS_CHANNEL_MIN || channel > PROPS_CHANNEL_MAX)
    {
        printf("channel %u is outside 11..26: no 2.4 GHz O-QPSK PHY numbers one\n", channel);
        return 2;
    }

    if (seconds == 0)
        seconds = 1;

    if (RcpRadio_Init(&radio, PortPosixOps(), timeoutMs) != ZB_OK)
    {
        printf("the backend would not initialise\n");
        return 1;
    }

    if (RcpRadio_Open(&radio, path, &config) != ZB_OK)
    {
        printf("%s: could not open the link (platform error %u)\n", path, Port_PlatformErrno(&radio.port));
        return 1;
    }

    /* The channel is band B's arm-step value: pibJudge takes it from the PIB because the arm sequence
       writes it (docs/internals/protocol.md §6), and nothing else is written before the stick has said what it is. */
    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_CHANNEL;
    pib.channel = channel;

    seam = RcpRadio_Seam(&radio);

    if (seam->ops->pibSet((Radio_Radio *)seam, &pib) != ZB_OK)
    {
        printf("the channel was refused\n");
        RcpRadio_Close(&radio);
        return 1;
    }

    startMs = Port_NowMs();
    deadline = startMs + BRINGUP_TIMEOUT_MS;

    while (RcpRadio_Mode(&radio) != RCP_RADIO_MODE_RUNNING && !Zb_timeReached(Port_NowMs(), deadline))
    {
        nowMs = Port_NowMs() - startMs;

        if (RcpRadio_Pump(&radio, nowMs) != ZB_OK)
            break;

        pumps++;

        /* Band A has not adopted the seam yet, so anything the stick delivers during bring-up has nowhere
           to go. Taking it off band B's queue is what keeps the queue room for the arm replies the
           bring-up is waiting for: a full queue stops band B pulling from the wire at all (the
           `radioPull` rule), and a bring-up stalled behind its own backlog is a bring-up that times out. */
        taken = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);
        bringUpFrames = bringUpFrames + taken;

        /* An RCP on a busy channel puts frames in band B's queue as fast as it answers a request,
           and band B stops pulling when its queue has no room: a bring-up that never paused would spin,
           and a bring-up that paused on every pump would wait out the arm sequence. What is paused on is
           a link that has produced nothing this pump. */
        if (RcpRadio_RxQueued(&radio) == 0 && RcpRadio_Mode(&radio) != RCP_RADIO_MODE_RUNNING)
            pauseHost();
    }

    bringUpMs = Port_NowMs() - startMs;

    versionLen = RcpRadio_VersionText(&radio, version, (uint32_t)sizeof version);
    armSteps = Props_ArmSteps(RcpRadio_Dialect(&radio), &armCount);

    printf("device     %s\n", path);
    printf("dialect    %.*s\n", (int)versionLen, version);
    printf("bring-up   %s in %u pumps over %u ms, last error %d, %u frames taken off the queue before band A\n"
           "           adopted the seam (they are not in the ledger: nothing above the radio ran for them)\n",
           modeName(RcpRadio_Mode(&radio)), pumps, bringUpMs, RcpRadio_LastError(&radio), bringUpFrames);

    if (armSteps != 0)
    {
        printf("armed      ");

        for (i = 0; i < armCount; i++)
        {
            entry = Props_Find(RcpRadio_Dialect(&radio), armSteps[i].id);

            printf("%s%s", i ? " " : "", entry != 0 ? entry->name : "?");
        }

        printf("  (docs/internals/protocol.md §6's sniffer variant, this dialect's arm table)\n");
    }

    /* The sniffer identity, written the way the harness writes it, and the delivery selection the seam
       carries as the promiscuous-mode write (§7.2). Both are queued by band B and put on the link by the
       pumps below, which are waited for: the armed state this tool prints is a state the stick answered. */
    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_SHORT_ADDRESS | RADIO_PIB_PAN_ID;
    pib.shortAddress = (uint16_t)SNIFFER_SHORT;
    pib.panId = (uint16_t)SNIFFER_PAN;

    if (seam->ops->pibSet((Radio_Radio *)seam, &pib) != ZB_OK)
    {
        printf("the sniffer identity was refused\n");
        RcpRadio_Close(&radio);
        return 1;
    }

    Zb_memset(&filter, 0, (uint32_t)sizeof filter);
    filter.isPromiscuous = 1;

    if (seam->ops->filter((Radio_Radio *)seam, &filter) != ZB_OK)
    {
        printf("promiscuous delivery was refused\n");
        RcpRadio_Close(&radio);
        return 1;
    }

    for (flushPumps = 0; flushPumps < FLUSH_PUMPS_MAX; flushPumps++)
    {
        nowMs = Port_NowMs() - startMs;

        if (RcpRadio_Pump(&radio, nowMs) != ZB_OK)
        {
            linkFault = 1;
            break;
        }

        if (radio.writeCount == 0)
            break;

        taken = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);
        bringUpFrames = bringUpFrames + taken;

        pauseHost();
    }

    if (linkFault || RcpRadio_Mode(&radio) != RCP_RADIO_MODE_RUNNING)
    {
        printf("not armed  %s (last error %d)\n", statusName(RcpRadio_LastError(&radio)),
               RcpRadio_LastError(&radio));
        RcpRadio_Close(&radio);
        return 1;
    }

    /* Band A, on the shim, in that config. */
    deny.backend = (Radio_Radio *)seam;
    deny.seam.ops = &s_denyOps;
    deny.seam.provider = &deny;

    if (sniff.ownIeee == 0)
        sniff.ownIeee = factoryIdentityOf(&radio);

    fillSecurityConfig(&securityCfg, &descriptor, sniff.key, sniff.keySeq, sniff.ownIeee, sniff.level);

    Zb_memset(&stackCfg, 0, (uint32_t)sizeof stackCfg);
    stackCfg.present = RADIO_PIB_SHORT_ADDRESS | RADIO_PIB_PAN_ID | RADIO_PIB_CHANNEL | RADIO_PIB_RX_ON_WHEN_IDLE;
    stackCfg.shortAddress = sniff.ownShort;
    stackCfg.panId = sniff.panId;
    stackCfg.channel = channel;
    stackCfg.rxOnWhenIdle = 1;
    stackCfg.deviceType = NWK_DEVICE_COORDINATOR;
    stackCfg.seqStart = 0;
    stackCfg.jitterSeed = 0;
    stackCfg.dsnStart = 0;
    stackCfg.nwkSecurityLevel = sniff.level;

    if (sniff.level != SECURITY_LEVEL_NONE)
        stackCfg.security = &securityCfg;

    initStatus = Zb_LayersInit(&stack, &deny.seam, &stackCfg);

    if (initStatus != ZB_OK)
    {
        printf("band A would not adopt the shimmed seam (status %d)\n", (int)initStatus);
        RcpRadio_Close(&radio);
        return 1;
    }

    mac = Zb_LayersMac(&stack);
    nwk = Zb_LayersNwk(&stack);
    aps = Zb_LayersAps(&stack);
    security = Zb_LayersSecurity(&stack);

    if (seam->ops->caps((Radio_Radio *)seam, &caps) != ZB_OK)
        Zb_memset(&caps, 0, (uint32_t)sizeof caps);

    /* The armed state, read back through the seam after every write this tool made has been answered.
       Band B reports the PIB it holds; the promiscuous setting is the write its filter call queued
       (`MAC_PROMISCUOUS_MODE` full, docs/internals/protocol.md §6 and §7.2) and not a PIB field, and LADDR is left
       at the all-zero reset value the harness never writes either. */
    Zb_memset(&pib, 0, (uint32_t)sizeof pib);

    if (seam->ops->pibGet((Radio_Radio *)seam, &pib) != ZB_OK)
    {
        printf("read-back  band B would not report the armed PIB\n");
        RcpRadio_Close(&radio);
        return 1;
    }

    printf("read-back  channel %u  pan 0x%04x  short 0x%04x  rxOnWhenIdle %d  promiscuous full, LADDR at its\n"
           "           reset value; %u pumps put the arming writes on the link, writeFailures %u\n",
           pib.channel, pib.panId, pib.shortAddress, pib.rxOnWhenIdle, flushPumps,
           RcpRadio_WriteFailures(&radio));

    printf("stack      coordinator, own short 0x%04x, PAN 0x%04x, channel %u\n", sniff.ownShort, sniff.panId,
           channel);
    printf("           ownIeee %016llx, rxOnWhenIdle 1, jitterSeed 0, group table empty\n",
           (unsigned long long)sniff.ownIeee);
    printf("           security level %u, key %02x x %u, key sequence %u, authenticated, nwkAllFresh\n",
           sniff.level, sniff.key[0], SECURITY_KEY_OCTETS, sniff.keySeq);
    printf("wire hold  %u PIB identity fields kept off the stick: the radio answers to 0x%04x in PAN 0x%04x,\n"
           "           band A judges delivery as 0x%04x in PAN 0x%04x\n",
           deny.identityHolds, SNIFFER_SHORT, SNIFFER_PAN, sniff.ownShort, sniff.panId);
    printf("counters   no Spinel transmit-counter property is answered on this stick (docs/internals/protocol.md §7.2),\n"
           "           so zero-tx is proven at the shim and at band B, not read from the radio\n");

    /* One session on one stick: pump the link, run the layers on the port's own monotonic counter, drain every ring, and
       print one ledger line every LEDGER_INTERVAL_MS. `aps.nwkIndications` is zeroed before each step:
       the module treats it as scratch, and clearing it lets the print of a deviation name the frame that
       caused it rather than guess at it. */
    nextLedgerMs = LEDGER_INTERVAL_MS;
    malformedBefore = 0;
    deadline = startMs + seconds * 1000;

    while (!Zb_timeReached(Port_NowMs(), deadline))
    {
        nowMs = Port_NowMs() - startMs;

        if (RcpRadio_Pump(&radio, nowMs) != ZB_OK)
        {
            printf("link       %s (last error %d)\n", statusName(RcpRadio_LastError(&radio)),
                   RcpRadio_LastError(&radio));
            linkFault = 1;
            break;
        }

        malformedBefore = Aps_RxMalformed(aps);
        status = Aps_Step(aps, nowMs);

        if (status == ZB_ERR_UNSUPPORTED)
            driven.stepsRefusingTx = driven.stepsRefusingTx + 1;
        else if (status != ZB_OK)
            printf("step       %s at t+%u ms\n", statusName(status), nowMs);

        if (Aps_RxMalformed(aps) != malformedBefore)
            classifyIndication(nwk, &deviation);

        taken = Mac_PollArrivals(mac, polls, MAC_POLL_EVENT_MAX);
        driven.pollEvents = driven.pollEvents + taken;

        taken = Aps_PollConfirms(aps, confirms, APS_CONFIRM_MAX);
        driven.confirms = driven.confirms + taken;

        taken = Aps_PollIndications(aps, indications, APS_INDICATION_MAX);
        driven.indications = driven.indications + taken;

        for (i = 0; i < taken; i++)
        {
            uint32_t octet;

            printf("aps ind    dst ep %02x src ep %02x cluster 0x%04x profile 0x%04x  %u octets:",
                   indications[i].dstEndpoint, indications[i].srcEndpoint, indications[i].clusterId,
                   indications[i].profileId, indications[i].asduLength);

            for (octet = 0; octet < indications[i].asduLength && octet < 16; octet++)
                printf(" %02x", indications[i].asdu[octet]);

            printf("\n");
        }

        driven.pumps++;

        readLedger(&ledger, mac, nwk, security, aps, &driven);
        delivered = deny.framesHandedUp - ledger.macAcksHeard - ledger.macCommandsHeard;

        if (nowMs >= nextLedgerMs)
        {
            printLedger(nowMs, &ledger, &deny, delivered);
            nextLedgerMs = nextLedgerMs + LEDGER_INTERVAL_MS;
        }

        if (Mac_CountersOf(mac).needsRearm)
        {
            printf("rearm      band A asks for it; band B is restarted (the RCP is re-armed)\n");
            RcpRadio_Restart(&radio, nowMs);
        }

        pauseHost();
    }

    nowMs = Port_NowMs() - startMs;
    readLedger(&ledger, mac, nwk, security, aps, &driven);
    delivered = deny.framesHandedUp - ledger.macAcksHeard - ledger.macCommandsHeard;

    printf("\nfinal      ");
    printLedger(nowMs, &ledger, &deny, delivered);

    RcpRadio_Transactions(&radio, &requests, &replies, &notifications, &stale, &timeouts, &malformed);

    printf("link       requests %u replies %u notifications %u stale %u timeouts %u malformed %u  "
           "rxOverflows %u linkDrops %u portDrops %u resets %u\n",
           requests, replies, notifications, stale, timeouts, malformed,
           RcpRadio_RxOverflows(&radio), RcpRadio_LinkDrops(&radio), RcpRadio_PortDrops(&radio),
           RcpRadio_ResetsSeen(&radio));

    shadowPass(&deny, &caps, &sniff, &shadow);

    printf("shadow     %u secured frames re-run through a second Security (the live one untouched): "
           "failures %u  counter rejects %u  forms refused %u\n",
           shadow.securedFrames, shadow.securityFailures, shadow.counterRejects, shadow.formRefused);

    for (i = 0; i < shadow.hexCount; i++)
        printf("candidate-new security failure: %s\n", shadow.hex[i]);

    if (deviation.malformedExpectedFamily != 0)
    {
        printf("recorded deviation family (%u): a broadcast APDU whose destination endpoint is 0x00, refused by\n"
               "           2.2.5.1.1.2 as `aps_frame` reads it (an open question, labelled as recorded)\n",
               deviation.malformedExpectedFamily);

        for (i = 0; i < deviation.expectedHexCount; i++)
            printf("           nsdu %s\n", deviation.expectedHex[i]);
    }

    if (deviation.malformedOther != 0)
    {
        printf("candidate-new deviation (%u): aps damage that is not the endpoint-0x00 family\n",
               deviation.malformedOther);

        for (i = 0; i < deviation.otherHexCount; i++)
            printf("           nsdu %s\n", deviation.otherHex[i]);
    }

    if (deviation.malformedTotal == 0)
        printf("deviation  no aps damage counted this session\n");

    printf("proof      backend tx calls %u  shim refusals %u  band A transmits outstanding %u  "
           "nwk transmit queue %u  aps transmit queue %u  identity holds %u\n",
           deny.backendTxCalls, deny.txRefusals, ledger.macOutstanding, ledger.nwkTransmitQueue,
           ledger.apsTransmitQueue, deny.identityHolds);
    printf("proof      the shim is the only seam band A sees and it never calls the backend's tx: the zero above\n"
           "           is a construction, not a measurement. No Spinel counter property exists to measure with.\n");

    /* A session ends with a reset: the reset is issued, pumped onto the
       link, and Close then writes §6's teardown order before hanging up. */
    RcpRadio_Restart(&radio, nowMs);

    for (i = 0; i < END_PUMPS; i++)
    {
        RcpRadio_Pump(&radio, Port_NowMs() - startMs);
        pauseHost();
    }

    RcpRadio_Close(&radio);

    printf("reset      RESET issued through RcpRadio_Restart, %u pumps put it on the link, then §6's teardown and close\n",
           END_PUMPS);

    return linkFault ? 1 : 0;
}
