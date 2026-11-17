#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "device_map.h"
#include "protect.h"
#include "mac.h"
#include "mac_frame.h"
#include "port.h"
#include "props.h"
#include "radio.h"
#include "rcp_radio.h"
#include "zb_time.h"

/*
 * Bench tool: bring a stick up through band B, print what the stack read from it, read frames through
 * band A's frame module, and (only when the transmission is authorised with --tx --allow-tx) put one
 * composed frame on the air.
 *
 * Two guards, both enforced before anything is written. A channel given with --protect-channel is not
 * armed on, because an armed RCP acknowledges frames addressed to itself (docs/internals/protocol.md §6),
 * which is a transmission by the RCP. And a transmit needs both --tx and --allow-tx
 * (docs/internals/hardware.md §8), with the inert PAN 0xbeef as the destination and a PAN given with
 * --protect-pan refused: a program that can transmit must not be one that transmits to the network that
 * happens to be there.
 *
 * The bring-up order is docs/internals/protocol.md §6 and nothing else is written without --tx, so a run without
 * it stays a read-only run.
 *
 * The clock is band C's (Port_NowMs, docs/porting.md §4) and this tool holds none of its own: the counter
 * every timed decision in the stack is pumped with is the one a deadline here is measured against, so a
 * run cannot mix two clocks. A pump never blocks, so a program that pumped as fast as it could would spin
 * tens of thousands of times while a stick composed one reply: the pause below makes a run a listen
 * rather than a burn, and the pump count it produces is a number worth reporting.
 */
#define PROBE_PAUSE_MS 2
#define PROBE_TX_WAIT_MS 1500
/* A dwell is asked for at the period docs/internals/protocol.md §7.4.1 measured with, and waited for past the
   343..505 host milliseconds that period took there so a run can tell a slow
   answer from no answer. */
#define PROBE_SCAN_PERIOD 200
#define PROBE_SCAN_WAIT_MS 6000
#define PROBE_SCAN_MAX 26

#define CAP_NAMED 9
#define PROBE_VERSION_MAX 96
#define PROBE_HEX_MAX 127
#define PROBE_PAYLOAD_MAX 60

static const char *capNames[CAP_NAMED] =
{
    "ACK_TIMEOUT", "ENERGY_SCAN", "TRANSMIT_RETRIES", "CSMA_BACKOFF", "SLEEP_TO_TX",
    "TRANSMIT_SEC", "TRANSMIT_TIMING", "RECEIVE_TIMING", "RX_ON_WHEN_IDLE"
};

static void probePause(void)
{
    Port_SleepMs(PROBE_PAUSE_MS);
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

static const char *dialectName(Props_Dialect dialect)
{
    if (dialect == PROPS_DIALECT_OPENTHREAD)
        return "SL-OPENTHREAD radio build";

    if (dialect == PROPS_DIALECT_DSPINEL)
        return "DSPINEL";

    return "unknown";
}

/* Why a delivered frame is suspect, in the words band B used for it. */
static const char *statusName(ZbStatus status)
{
    if (status == ZB_OK)
        return "ok";

    if (status == ZB_ERR_BAD_ARGUMENT)
        return "bad-argument";

    if (status == ZB_ERR_UNSUPPORTED)
        return "unsupported";

    if (status == ZB_ERR_NOT_OPEN)
        return "not-open";

    if (status == ZB_ERR_NO_DEVICE)
        return "no-device";

    if (status == ZB_ERR_BAD_FRAME)
        return "fcs-invalid";

    if (status == ZB_ERR_BUSY)
        return "duplicate";

    if (status == ZB_ERR_DEVICE_LOST)
        return "device-lost";

    if (status == ZB_ERR_NO_SPACE)
        return "no-space";

    if (status == ZB_ERR_INTERNAL)
        return "internal";

    if (status == ZB_ERR_TIMEOUT)
        return "timeout";

    if (status == ZB_ERR_NOT_READY)
        return "not-ready";

    if (status == ZB_ERR_CHANNEL_ACCESS_FAILURE)
        return "channel-access-failure";

    if (status == ZB_ERR_DEVICE)
        return "radio-error";

    if (status == ZB_ERR_NO_ACK)
        return "no-ack";

    if (status == ZB_ERR_TRANSACTION_EXPIRED)
        return "transaction-expired";

    if (status == ZB_ERR_TRANSACTION_OVERFLOW)
        return "transaction-overflow";

    return "suspect";
}

/* The table ends here. This build's property table bounds what it may ask, and a build outside the
   table is the device's own answer, not this tool's guess; the harness is the instrument that asks a
   device a question no table names (docs/internals/testing.md §7). */
static void printAskTheDevice(const char *what)
{
    printf("%s\n", what);
    printf("  this tree's table does not bound it; ask the device itself:\n"
           "  harness/spinel_probe.py --device <name> --no-reset --get 2 5 0x120B 0xB0 0xB1\n");
}

/* What band A made of the octets band B delivered. */
static const char *parseName(ZbStatus status)
{
    if (status == ZB_ERR_UNSUPPORTED)
        return "a frame form this stack does not read";

    if (status == ZB_ERR_BAD_FRAME)
        return "not a frame: its fields do not add up to the octets it has";

    return "unreadable";
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

/* What the seam answers for the identity it was told to apply. This is the seam's own PIB (every field it
   reports was accepted by the stick's echo before band B stored it) and not a fresh property read of the
   device: band B's pibGet is a local answer by construction, because a core module does not block on a link.
   What a stick itself currently holds is asked of the stick, through the property probe, in its own session
   (docs/internals/protocol.md §10 question 17). */
static void printPibReadback(const Radio_Radio *seam, const char *when)
{
    Radio_Pib pib;

    memset(&pib, 0, sizeof pib);

    if (seam->ops->pibGet((Radio_Radio *)seam, &pib) != ZB_OK)
    {
        printf("seam pib   %s: refused\n", when);
        return;
    }

    printf("seam pib   %s: channel %u  short 0x%04x  pan 0x%04x  rxOnWhenIdle %d",
           when, pib.channel, pib.shortAddress, pib.panId, pib.rxOnWhenIdle);

    if (pib.present & RADIO_PIB_SHORT_ADDRESS)
        printf("  (short set)");
    else
        printf("  (short unset)");

    printf("\n");
}

static void printCaps(const Radio_Caps *caps)
{
    uint32_t unknown;
    uint32_t bit;
    int first;

    printf("RADIO_CAPS   0x%04x [", caps->radioCaps);
    first = 1;

    for (bit = 0; bit < CAP_NAMED; bit++)
    {
        if ((caps->radioCaps & ((uint32_t)1 << bit)) == 0)
            continue;

        printf("%s%s", first ? "" : " ", capNames[bit]);
        first = 0;
    }

    unknown = Props_RadioCapsUnknown(caps->radioCaps);

    for (bit = CAP_NAMED; bit < 32; bit++)
    {
        /* `(uint32_t)1`, because a signed 1 shifted 31 places is not a number this language defines,
           and the point of listing the unnamed bits is to look at the top of the bitmap. */
        if ((unknown & ((uint32_t)1 << bit)) == 0)
            continue;

        printf("%sbit%u", first ? "" : " ", bit);
        first = 0;
    }

    if (first)
        printf("none");

    printf("]\n");
    printf("           hasTransmit=%d hasEnergyScan=%d psduIncludesFcs=%d hasAckMetadata=%d handlesAckTimeout=%d\n",
           caps->hasTransmit, caps->hasEnergyScan, caps->psduIncludesFcs, caps->hasAckMetadata,
           caps->handlesAckTimeout);
}

static void printAddress(const uint8_t *addr)
{
    uint32_t i;

    if (addr == 0)
    {
        printf("HWADDR       (not answered by this build)\n");
        return;
    }

    printf("HWADDR       ");

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        printf("%s%02x", i ? " " : "", addr[i]);

    printf("  (address order) = ");

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        printf("%s%02x", i ? ":" : "", addr[RADIO_ADDR_LEN - 1 - i]);

    printf("  (Zigbee display)\n");
}

static void printHex(const uint8_t *bytes, uint32_t len)
{
    uint32_t i;

    printf("           ");

    for (i = 0; i < len && i < PROBE_HEX_MAX; i++)
        printf("%02x ", bytes[i]);

    printf("\n");
}

/*
 * One delivered frame: what the radio said about it, and what band A reads inside it. The footer
 * verdict is band A's own arithmetic, independent of the flag the radio set, which is the whole point
 * of having both (docs/internals/protocol.md §9.3).
 *
 * `elapsedMs` is the tool's own clock since it opened the port. The stamp in the frame is the stick's,
 * and the two are printed side by side precisely because nothing in this stack may assume they run at
 * the same rate: a bench transcript that carries both is the
 * only way to find out what the device's unit actually is.
 */
static void printFrame(const Radio_Frame *frame, const Radio_Caps *caps, uint32_t index,
                       uint32_t elapsedMs, int showHex)
{
    Mac_Frame parsed;
    const uint8_t *payload = 0;
    uint32_t payloadLen = 0;
    uint32_t i;
    ZbStatus status;

    printf("frame %3u  len %3u  rssi %4d  lqi %3u  at +%5u ms  device stamp %8llu  %s%s\n",
           index, frame->len, frame->rssiDbm, frame->lqi, elapsedMs,
           (unsigned long long)frame->deviceStampTicks, statusName(frame->error),
           frame->ackedWithFramePending ? "  ack-frame-pending 1" : "");

    status = MacFrame_Parse(frame->bytes, frame->len, caps->psduIncludesFcs,
                            &parsed, &payload, &payloadLen, 0);

    if (status != ZB_OK)
    {
        printf("           %s\n", parseName(status));

        if (showHex)
            printHex(frame->bytes, frame->len);

        return;
    }

    printf("           %s seq %02x  %s%s%s  dst %s",
           typeName(parsed.frameType), parsed.seq,
           parsed.ackRequest ? "ackreq " : "",
           parsed.framePending ? "pending " : "",
           parsed.panIdCompression ? "pan-compressed" : "two PAN fields",
           addrModeName(parsed.destAddrMode));

    if (parsed.destAddrMode == MAC_ADDR_NONE)
        printf("  src %s", addrModeName(parsed.srcAddrMode));
    else
        printf("  pan %04x", parsed.destPan);

    if (parsed.srcAddrMode != MAC_ADDR_NONE)
        printf("  src %s", addrModeName(parsed.srcAddrMode));

    if (parsed.frameType != MAC_FRAME_TYPE_BEACON && parsed.destAddrMode == MAC_ADDR_SHORT)
        printf("  dst 0x%04x", parsed.destShort);

    if (parsed.srcAddrMode == MAC_ADDR_SHORT)
        printf("  src 0x%04x", parsed.srcShort);

    if (parsed.destAddrMode == MAC_ADDR_EXTENDED)
        printf("  dst 0x%016llx", (unsigned long long)parsed.destExtended);

    if (parsed.srcAddrMode == MAC_ADDR_EXTENDED)
        printf("  src 0x%016llx", (unsigned long long)parsed.srcExtended);

    printf("  payload %u", payloadLen);

    if (payloadLen != 0)
    {
        printf("  ");

        for (i = 0; i < payloadLen && i < 16; i++)
            printf("%02x ", payload[i]);
    }

    if (caps->psduIncludesFcs)
        printf("  footer %s", MacFrame_CheckFcs(frame->bytes, frame->len) == ZB_OK ? "ok" : "does not match");
    else
        printf("  footer none delivered");

    printf("\n");

    if (showHex)
        printHex(frame->bytes, frame->len);
}

/* What band A reports about a delivered frame: the header parsed, the payload where the header ends,
   and band A's own verdict on the footer beside the radio's flag. A frame band A cannot read is
   reported with its status and its octets' count rather than dropped, which is the contract above. */
/* 8.2.4.3's beacon event as Table 8-4 and Table 8-3 name it, then the payload octets. */
static void printMacBeacon(const Mac_BeaconNotification *beacon, uint32_t number, uint32_t tMs, int showHex)
{
    printf("mac beacon %3u  t+%u ms  sn %02x  coord 0x%04x pan 0x%04x  BO %u SO %u  gts permit %d  "
           "association permit %d  payload %u octets\n",
           number, tMs, beacon->sn, beacon->coordShort, beacon->coordPanId, beacon->beaconOrder,
           beacon->superframeOrder, beacon->gtsPermit, beacon->associationPermit, beacon->payloadLen);

    if (beacon->pendingShortCount + beacon->pendingExtendedCount != 0)
    {
        uint32_t i;

        printf("            pending  %u short, %u extended:", beacon->pendingShortCount,
               beacon->pendingExtendedCount);

        for (i = 0; i < beacon->pendingShortCount; i++)
            printf(" 0x%04x", beacon->pendingShort[i]);

        for (i = 0; i < beacon->pendingExtendedCount; i++)
            printf(" %016llx", (unsigned long long)beacon->pendingExtended[i]);

        printf("\n");
    }

    if (showHex && beacon->payloadLen != 0)
        printHex(beacon->payload, beacon->payloadLen);
}

static void printMacIndication(const Mac_DataIndicationParameters *ind, uint32_t number, uint32_t tMs, int showHex)
{
    if (ind->headerValid)
    {
        const Mac_Frame *h = &ind->header;

        printf("mac ind %3u  t+%u ms  %s  v%u %s%s  dst 0x%04x pan 0x%04x  src ",
               number, tMs, typeName(h->frameType), h->frameVersion,
               h->ackRequest ? "AR " : "", h->panIdCompression ? "PAN-C " : "",
               h->destShort, h->destPan);

        if (h->srcAddrMode == MAC_ADDR_EXTENDED)
            printf("0x%016llx", (unsigned long long)h->srcExtended);
        else
            printf("0x%04x", h->srcShort);

        printf(" pan 0x%04x  seq %02u  payload %u B", h->srcPan, h->seq, ind->payloadLen);
        printf("  footer %s", ind->status == ZB_OK ? "validates" : "does not validate against the octets");

        if (ind->ackedWithFramePending)
            printf("  ack-frame-pending 1");

        printf("\n");

        if (showHex)
            printHex(ind->bytes, ind->len);
        else if (ind->payloadLen != 0)
            printHex(ind->bytes + ind->payloadOffset, ind->payloadLen);

        return;
    }

    printf("mac ind %3u  t+%u ms  %s  %u octets band A cannot read\n",
           number, tMs, statusName(ind->status), ind->len);

    if (showHex)
        printHex(ind->bytes, ind->len);
}

static void usage(void)
{
    printf("usage: rcp_probe --path <path>|--device <name> [--channel n]\n"
           "                 [--listen s] [--reset-after s] [--timeout ms] [--baud n]\n"
           "                 [--rx-ring n] [--tx-ring n] [--hex] [--quiet]\n"
           "                 [--protect-channel n]... [--protect-pan hex]... [--allow-live-channel]\n"
           "                 --tx --allow-tx [--dst-pan hex] [--dst hex] [--dst-ext eui64] [--src hex]\n"
           "                 [--payload hex]\n"
           "                 [--seq n] [--ack-req] [--tx-wait ms] [--tx-corrupt]\n"
           "                 [--short hex] [--pan hex] [--no-promisc] [--promisc] [--mac]\n"
           "                 [--mac-frame data|command] [--pib-page n] [--pib-ieee hex]\n"
           "                 [--rx-on-when-idle] [--src-mode none]\n"
           "                 [--beacon-answer] [--beacon-info <30 hex>] [--pending <aaaa,bbbb,...>]\n"
           "                 [--pair <aaaa:eui64>,...] [--scan n[,...]] [--scan-period n]\n");
}

/* 7.3.1.6's pending list as this tool states it: short addresses, four hex digits each, comma separated. */
static int parsePending(const char *text, uint16_t *out, uint32_t cap, uint32_t *outCount)
{
    uint32_t count = 0;
    const char *p = text;

    while (*p != 0)
    {
        unsigned value = 0;

        if (count >= cap)
            return 0;

        if (sscanf(p, "%4x", &value) != 1)
            return 0;

        out[count] = (uint16_t)value;
        count++;

        while (*p != 0 && *p != ',')
            p++;

        if (*p == ',')
            p++;
    }

    *outCount = count;

    return count != 0;
}

/* The two forms of one device, `aaaa:eui64`, comma separated: what the association door learns from 10.21.5.2
   and what a run that never associates has to state itself. */
static int parsePairs(const char *text, uint16_t *shorts, uint64_t *extendeds, uint32_t cap, uint32_t *outCount)
{
    uint32_t count = 0;
    const char *p = text;

    while (*p != 0)
    {
        unsigned shortValue = 0;
        unsigned long long extendedValue = 0;
        int used = 0;

        if (count >= cap)
            return 0;

        if (sscanf(p, "%4x:%16llx%n", &shortValue, &extendedValue, &used) != 2 || used == 0)
            return 0;

        shorts[count] = (uint16_t)shortValue;
        extendeds[count] = (uint64_t)extendedValue;
        count++;
        p += used;

        if (*p == ',')
            p++;
        else if (*p != 0)
            return 0;
    }

    *outCount = count;

    return count != 0;
}

/* Two hex digits per octet, no separators required, and a refusal rather than a partial payload. */
static int parseHex(const char *text, uint8_t *out, uint32_t cap, uint32_t *outLen)
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

    return 1;
}

static uint32_t hexValue(const char *text)
{
    return (uint32_t)strtoul(text, 0, 16);
}

int main(int argc, char **argv)
{
    Rcp_Radio radio;
    const Radio_Radio *seam;
    Radio_Caps caps;
    Radio_Frame frames[RADIO_FRAME_BATCH_MAX];
    Radio_Pib pib;
    Radio_Filter filter;
    Radio_Handle handle = RADIO_HANDLE_NONE;
    Radio_TxResult result;
    Mac_Frame frame;
    Mac_Mac mac;
    Mac_Counters counters;
    Radio_Pending pendingTable;
    Mac_DataConfirmParameters mconfs[8];
    Mac_DataIndicationParameters inds[MAC_INDICATION_QUEUE_MAX];
    Mac_BeaconNotification heardAsBeacons[MAC_BEACON_NOTIFY_MAX];
    PortConfig config;
    uint8_t version[PROBE_VERSION_MAX];
    uint8_t payload[PROBE_PAYLOAD_MAX];
    uint8_t mpdu[MAC_FRAME_MPDU_MAX];
    uint32_t versionLen;
    uint32_t payloadLen;
    uint32_t mpduLen;
    uint32_t taken;
    uint32_t timeoutMs;
    uint32_t txWaitMs;
    uint32_t listenSec;
    uint32_t resetAfter;
    uint32_t channel;
    uint32_t dstPan;
    uint32_t dstAddr;
    uint64_t dstExtended;
    int haveDstExt;
    uint32_t srcAddr;
    uint32_t shortAddr;
    uint32_t ownPan;
    uint32_t seq;
    uint32_t framesBeforeReset;
    uint32_t framesSeen;
    uint32_t bringUpMs;
    uint32_t flagged;
    uint32_t requests;
    uint32_t replies;
    uint32_t notifications;
    uint32_t stale;
    uint32_t timeouts;
    uint32_t malformed;
    uint32_t pumps;
    uint32_t txPumps;
    uint32_t txCode;
    uint32_t i;
    uint32_t txStartMs;
    uint32_t startMs;
    uint32_t deadline;
    const char *path;
    int showHex;
    int quiet;
    int allowLive;
    Protect protect;
    int protectTaken;
    uint32_t scanChannels[PROBE_SCAN_MAX];
    uint32_t scanCount = 0;
    uint32_t scanPeriod = PROBE_SCAN_PERIOD;
    int allowTx;
    int wantTx;
    int ackRequest;
    int txCorrupt;
    int txCodeKnown;
    int noPromisc;
    int wantPromisc;
    int macMode;
    uint32_t macFrameType;
    int wantPage;
    uint32_t pageValue;
    int haveIeee;
    uint8_t ieee[8];
    int wroteIdentity;
    int wantRxOnWhenIdle;
    int srcModeNone;
    int haveShort;
    int beaconAnswer;
    int haveBeaconInfo;
    uint16_t pendingShort[16];   /* more than 7.3.1.6's seven, so a run can read the limit */
    uint32_t pendingCount;
    uint16_t pairShort[8];       /* the two forms of a device the association door would have named */
    uint64_t pairExtended[8];
    uint32_t pairCount;
    uint8_t pendingBytes[2] = { 0xa1, 0x11 };
    uint8_t beaconInfo[15];
    uint32_t beaconInfoLen;
    int resetDone;
    int status;
    ZbStatus stepStatus;

    path = 0;
    channel = 12;
    listenSec = 10;
    resetAfter = 0;
    timeoutMs = 1000;
    txWaitMs = PROBE_TX_WAIT_MS;
    dstPan = 0xbeef;      /* the inert PAN docs/internals/hardware.md §1 names as the default destination */
    dstAddr = MAC_FRAME_ADDR_BROADCAST;
    srcAddr = 0xdead;
    seq = 0;
    showHex = 0;
    quiet = 0;
    allowLive = 0;
    memset(&protect, 0, sizeof protect);
    allowTx = 0;
    wantTx = 0;
    ackRequest = 0;
    txCorrupt = 0;
    txCodeKnown = 0;
    noPromisc = 0;
    wantPromisc = 0;
    macMode = 0;
    macFrameType = MAC_FRAME_TYPE_DATA;
    wantPage = 0;
    pageValue = 0;
    haveIeee = 0;
    wroteIdentity = 0;
    wantRxOnWhenIdle = 0;
    memset(ieee, 0, sizeof ieee);
    srcModeNone = 0;
    haveShort = 0;
    dstExtended = 0;
    haveDstExt = 0;
    beaconAnswer = 0;
    haveBeaconInfo = 0;
    beaconInfoLen = 0;
    pendingCount = 0;
    pairCount = 0;
    memset(beaconInfo, 0, sizeof beaconInfo);
    shortAddr = 0;
    ownPan = 0;
    payloadLen = 0;
    status = 0;
    stepStatus = ZB_OK;
    framesSeen = 0;
    flagged = 0;
    framesBeforeReset = 0;
    resetDone = 0;
    mpduLen = 0;

    memset(&pib, 0, sizeof pib);
    memset(&filter, 0, sizeof filter);
    memset(&frame, 0, sizeof frame);
    memset(&caps, 0, sizeof caps);
    memset(&mac, 0, sizeof mac);

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
        else if (strcmp(argv[i], "--listen") == 0 && i + 1 < (uint32_t)argc)
            listenSec = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--reset-after") == 0 && i + 1 < (uint32_t)argc)
            resetAfter = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < (uint32_t)argc)
            timeoutMs = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--tx-wait") == 0 && i + 1 < (uint32_t)argc)
            txWaitMs = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--dst-pan") == 0 && i + 1 < (uint32_t)argc)
            dstPan = hexValue(argv[++i]);
        else if (strcmp(argv[i], "--dst") == 0 && i + 1 < (uint32_t)argc)
            dstAddr = hexValue(argv[++i]);
        else if (strcmp(argv[i], "--dst-ext") == 0 && i + 1 < (uint32_t)argc)
        {
            /* 10.21.5.2's answer is addressed to the extended address a joining device holds before it has a short
               one, so the form has to be askable: band A composes it from `destExtended` and the destination mode. */
            char *end = 0;
            unsigned long long value = strtoull(argv[++i], &end, 16);

            if (end == argv[i] || *end != 0)
            {
                printf("--dst-ext takes one EUI-64, hex\n");
                return 2;
            }

            dstExtended = (uint64_t)value;
            haveDstExt = 1;
        }
        else if (strcmp(argv[i], "--src") == 0 && i + 1 < (uint32_t)argc)
            srcAddr = hexValue(argv[++i]);
        else if (strcmp(argv[i], "--seq") == 0 && i + 1 < (uint32_t)argc)
            seq = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--payload") == 0 && i + 1 < (uint32_t)argc)
        {
            if (!parseHex(argv[++i], payload, (uint32_t)sizeof payload, &payloadLen))
            {
                printf("--payload wants hex octets, at most %d of them\n", PROBE_PAYLOAD_MAX);
                return 2;
            }
        }
        else if (strcmp(argv[i], "--baud") == 0 && i + 1 < (uint32_t)argc) config.baud = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--rx-ring") == 0 && i + 1 < (uint32_t)argc) config.rxRingSize = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--tx-ring") == 0 && i + 1 < (uint32_t)argc) config.txRingSize = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--hex") == 0) showHex = 1;
        else if (strcmp(argv[i], "--quiet") == 0) quiet = 1;
        else if (strcmp(argv[i], "--allow-live-channel") == 0) allowLive = 1;
        else if ((protectTaken = protectOption(&protect, argc, argv, i)) != 0)
        {
            if (protectTaken < 0)
            {
                printf("--protect-channel takes a channel 11..26, --protect-pan a PAN id, at most %u\n",
                       (unsigned)PROTECT_PAN_MAX);
                return 2;
            }

            i++;
        }
        else if (strcmp(argv[i], "--scan-period") == 0 && i + 1 < (uint32_t)argc) scanPeriod = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--pair") == 0 && i + 1 < (uint32_t)argc)
        {
            if (!parsePairs(argv[++i], pairShort, pairExtended,
                            (uint32_t)sizeof pairShort / (uint32_t)sizeof pairShort[0], &pairCount))
            {
                printf("--pair takes up to %u short:eui64 pairs, hex, comma separated\n",
                       (unsigned)((uint32_t)sizeof pairShort / (uint32_t)sizeof pairShort[0]));
                return 2;
            }
        }
        else if (strcmp(argv[i], "--scan") == 0 && i + 1 < (uint32_t)argc)
        {
            char *cursor = argv[++i];

            while (cursor != 0 && *cursor != 0 && scanCount < PROBE_SCAN_MAX)
            {
                scanChannels[scanCount] = (uint32_t)strtoul(cursor, &cursor, 10);
                scanCount++;

                if (*cursor == ',')
                    cursor++;
                else
                    break;
            }
        }
        else if (strcmp(argv[i], "--ack-req") == 0) ackRequest = 1;
        else if (strcmp(argv[i], "--tx-corrupt") == 0) txCorrupt = 1;
        else if (strcmp(argv[i], "--no-promisc") == 0) noPromisc = 1;
        else if (strcmp(argv[i], "--promisc") == 0) wantPromisc = 1;
        else if (strcmp(argv[i], "--short") == 0 && i + 1 < (uint32_t)argc)
        {
            shortAddr = hexValue(argv[++i]);
            haveShort = 1;   /* 0x0000 is the coordinator's own address, and it is written like any other */
        }
        else if (strcmp(argv[i], "--pan") == 0 && i + 1 < (uint32_t)argc) ownPan = hexValue(argv[++i]);
        else if (strcmp(argv[i], "--mac") == 0) macMode = 1;
        else if (strcmp(argv[i], "--pib-page") == 0 && i + 1 < (uint32_t)argc)
        {
            wantPage = 1;
            pageValue = (uint32_t)strtoul(argv[++i], 0, 10);
        }
        else if (strcmp(argv[i], "--pib-ieee") == 0 && i + 1 < (uint32_t)argc)
        {
            uint32_t octets = 0;

            if (!parseHex(argv[++i], ieee, (uint32_t)sizeof ieee, &octets) || octets != 8)
            {
                printf("--pib-ieee wants 8 octets of hex, in the order the PIB carries them\n");
                return 2;
            }

            haveIeee = 1;
        }
        else if (strcmp(argv[i], "--rx-on-when-idle") == 0) wantRxOnWhenIdle = 1;
        else if (strcmp(argv[i], "--src-mode") == 0 && i + 1 < (uint32_t)argc)
        {
            if (strcmp(argv[++i], "none") != 0)
            {
                printf("--src-mode takes one value: none (the Source Addressing Mode 7.5.2 pins for a request)\n");
                return 2;
            }

            srcModeNone = 1;
        }
        else if (strcmp(argv[i], "--beacon-answer") == 0) beaconAnswer = 1;
        else if (strcmp(argv[i], "--pending") == 0 && i + 1 < (uint32_t)argc)
        {
            if (!parsePending(argv[++i], pendingShort,
                              (uint32_t)sizeof pendingShort / (uint32_t)sizeof pendingShort[0], &pendingCount))
            {
                printf("--pending takes up to %u short addresses, four hex digits each, comma separated\n",
                       (unsigned)((uint32_t)sizeof pendingShort / (uint32_t)sizeof pendingShort[0]));
                return 2;
            }
        }
        else if (strcmp(argv[i], "--beacon-info") == 0 && i + 1 < (uint32_t)argc)
        {
            if (!parseHex(argv[++i], beaconInfo, (uint32_t)sizeof beaconInfo, &beaconInfoLen)
                || beaconInfoLen != 15)
            {
                printf("--beacon-info wants the 15 octets of R23.1's Beacon Info Field, hex\n");
                return 2;
            }

            haveBeaconInfo = 1;
        }
        else if (strcmp(argv[i], "--mac-frame") == 0 && i + 1 < (uint32_t)argc)
        {
            const char *what = argv[++i];

            if (strcmp(what, "data") == 0)
                macFrameType = MAC_FRAME_TYPE_DATA;
            else if (strcmp(what, "command") == 0)
                macFrameType = MAC_FRAME_TYPE_COMMAND;
            else
            {
                printf("--mac-frame wants data or command\n");
                return 2;
            }
        }
        else if (strcmp(argv[i], "--tx") == 0) wantTx = 1;
        else if (strcmp(argv[i], "--allow-tx") == 0) allowTx = 1;
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

    if (wantTx && !allowTx)
    {
        printf("--tx needs --allow-tx: nothing goes on the air without both flags\n");
        return 2;
    }

    if (channel < PROPS_CHANNEL_MIN || channel > PROPS_CHANNEL_MAX)
    {
        printf("channel %u is outside 11..26: no 2.4 GHz O-QPSK PHY numbers one\n", channel);
        return 2;
    }

    /* An armed RCP acknowledges frames addressed to itself (docs/internals/protocol.md §6), which is a
       transmission by the device rather than by this program, so a protected channel is not armed on. */
    if (!allowLive && protectChannel(&protect, channel))
    {
        printf("channel %u is protected, and an armed RCP acknowledges frames addressed to it:\n"
               "pass --allow-live-channel to arm there anyway\n",
               channel);
        return 1;
    }

    /* The channel guard is about the air; this one is about the address inside the frame. A frame
       addressed to a protected PAN is a frame to its devices, whatever channel carried it. */
    if (wantTx && protectPan(&protect, dstPan) && !allowLive)
    {
        printf("PAN 0x%04x is protected: --tx to it needs --allow-live-channel\n", (unsigned)dstPan);
        return 1;
    }

    if (RcpRadio_Init(&radio, Port_DefaultOps(), timeoutMs) != ZB_OK)
    {
        printf("the backend would not initialise\n");
        return 1;
    }

    if (RcpRadio_Open(&radio, path, &config) != ZB_OK)
    {
        printf("%s: could not open the link (platform error %u)\n", path, Port_PlatformErrno(&radio.port));
        return 1;
    }

    pib.present = RADIO_PIB_CHANNEL;
    pib.channel = channel;

    seam = RcpRadio_Seam(&radio);

    {
        ZbStatus channelStatus = seam->ops->pibSet((Radio_Radio *)seam, &pib);

        if (channelStatus != ZB_OK)
        {
            printf("the channel was refused: %s\n", statusName(channelStatus));
            RcpRadio_Close(&radio);
            return 1;
        }
    }

    startMs = Port_NowMs();
    deadline = startMs + 5000;
    pumps = 0;

    while (RcpRadio_Mode(&radio) != RCP_RADIO_MODE_RUNNING && !Zb_timeReached(Port_NowMs(), deadline))
    {
        if (RcpRadio_Pump(&radio, Port_NowMs()) != ZB_OK)
            break;

        pumps++;

        if (RcpRadio_RxQueued(&radio) == 0)
            probePause();
    }

    bringUpMs = Port_NowMs() - startMs;

    if (!quiet)
    {
        versionLen = RcpRadio_VersionText(&radio, version, (uint32_t)sizeof version);

        printf("device     %s\n", path);
        printf("dialect    %s", dialectName(RcpRadio_Dialect(&radio)));

        if (versionLen != 0)
            printf("  \"%.*s\"", (int)versionLen, version);

        printf("\n");
        printf("api        RCP %u, host must be at least %u, interface type %u\n",
               radio.apiVersion, radio.minHostApiVersion, radio.interfaceType);

        if (seam->ops->caps((Radio_Radio *)seam, &caps) != ZB_OK)
            printf("RADIO_CAPS   (refused)\n");
        else
            printCaps(&caps);

        printAddress(RcpRadio_Address(&radio));
        printf("armed      channel %u\n", channel);
        printf("brought up %s in %u pumps over %u ms\n", modeName(RcpRadio_Mode(&radio)), pumps, bringUpMs);
    }

    if (RcpRadio_Mode(&radio) != RCP_RADIO_MODE_RUNNING)
    {
        printf("not armed: %s (last error %d)\n", modeName(RcpRadio_Mode(&radio)),
               RcpRadio_LastError(&radio));

        if (RcpRadio_Dialect(&radio) == PROPS_DIALECT_UNKNOWN)
            printAskTheDevice("the dialect is not one this build's table names");

        RcpRadio_Close(&radio);
        return 1;
    }

    /* What the stick should consider its own address and PAN. They are PIB writes like any other,
       queued here and put on the wire by the pumps that follow, which is what band B's seam is for:
       the address a peer aims a frame at has to be set through the same door as the channel, and an
       acknowledgment decision at the far end consults both (docs/internals/protocol.md §6). */
    /* Delivery selection through the seam's filter call, which band B carries as the promiscuous-mode
       write §7.2 measured. A stick that filters to its own address is the only way to see whether a
       peer answers a frame that asked to be answered: a promiscuous stick takes everything and this
       bench measured it doing exactly that (docs/internals/hardware.md §6). */
    if (noPromisc)
    {
        memset(&filter, 0, sizeof filter);
        filter.isPromiscuous = 0;

        if (seam->ops->filter((Radio_Radio *)seam, &filter) != ZB_OK)
        {
            printf("the filter change was refused\n");
            RcpRadio_Close(&radio);
            return 1;
        }
    }

    if (haveShort || ownPan != 0 || wantPage || haveIeee || wantRxOnWhenIdle || RcpRadio_Address(&radio) != 0)
    {
        memset(&pib, 0, sizeof pib);
        pib.present = 0;

        if (wantPage)
        {
            pib.present = pib.present | RADIO_PIB_PAGE;
            pib.page = (uint8_t)pageValue;
        }

        /* The pair docs/internals/protocol.md §7.2 names: the stick's own factory address is read from it at bring-up and is
           never written, and the operational long address is the host's to write. A host that only reads the first
           leaves the second unset, and a frame it transmits is then sourced from eight zero octets: measured at
           the receiver. Unless the caller named one, this writes the factory address. */
        if (haveIeee)
        {
            pib.present = pib.present | RADIO_PIB_EXTENDED_ADDRESS;
            memcpy(pib.extendedAddress, ieee, sizeof ieee);
            wroteIdentity = 1;
        }
        else if (RcpRadio_Address(&radio) != 0)
        {
            const uint8_t *factory = RcpRadio_Address(&radio);
            uint32_t octet;

            /* The PIB carries an extended address least significant octet first, and the HWADDR this device
               answered is in address order: copying it verbatim sources every extended frame from the reversed
               address. */
            pib.present = pib.present | RADIO_PIB_EXTENDED_ADDRESS;

            for (octet = 0; octet < RADIO_ADDR_LEN; octet++)
                pib.extendedAddress[octet] = factory[RADIO_ADDR_LEN - 1 - octet];

            wroteIdentity = 2;   /* the factory address, written as the operational one */
        }

        if (wantRxOnWhenIdle)
        {
            pib.present = pib.present | RADIO_PIB_RX_ON_WHEN_IDLE;
            pib.rxOnWhenIdle = 1;
        }

        if (haveShort)
        {
            pib.present = pib.present | RADIO_PIB_SHORT_ADDRESS;
            pib.shortAddress = (uint16_t)shortAddr;
        }

        if (ownPan != 0)
        {
            pib.present = pib.present | RADIO_PIB_PAN_ID;
            pib.panId = (uint16_t)ownPan;
        }

        {
            ZbStatus pibStatus = seam->ops->pibSet((Radio_Radio *)seam, &pib);

            if (pibStatus != ZB_OK)
            {
                printf("the PIB write was refused: %s\n", statusName(pibStatus));

                if (pibStatus == ZB_ERR_UNSUPPORTED)
                    printAskTheDevice("one of these fields is not in this build's table");

                RcpRadio_Close(&radio);
                return 1;
            }
        }

        for (i = 0; i < 20; i++)
        {
            if (RcpRadio_Pump(&radio, Port_NowMs()) != ZB_OK)
                break;

            probePause();
        }

        if (!quiet)
            printf("addressed  short 0x%04x  pan 0x%04x  written: %s%s%s%s%s\n", shortAddr, ownPan,
                   haveShort ? "short " : "",
                   ownPan != 0 ? "pan " : "",
                   wantPage ? "page " : "",
                   wroteIdentity != 0 ? "longAddr " : "",
                   wantRxOnWhenIdle ? "rxOnWhenIdle" : "");

        if (!quiet && wroteIdentity != 0)
            printf("identity   %s\n", wroteIdentity == 2
                   ? "the factory address this device reported, written as its operational long address"
                   : "the long address the caller named, written as this device's operational one");
    }

    if (noPromisc)
    {
        for (i = 0; i < 20; i++)
        {
            if (RcpRadio_Pump(&radio, Port_NowMs()) != ZB_OK)
                break;

            probePause();
        }

        if (!quiet)
            printf("delivery   filtered to its own address, promiscuous mode off\n");
    }

    if (!quiet && (shortAddr != 0 || ownPan != 0 || noPromisc))
        printPibReadback(seam, "after the writes");

    /* With --mac, band A is what reports: it adopts the seam, mirrors the PIB the stick was told
       (channel and, where set, the short address and the PAN), and from here on the loop pumps, steps
       it and prints its confirmations and its indications instead of the raw frames band B hands out. */
    if (macMode)
    {
        if (Mac_Init(&mac, RcpRadio_Seam(&radio), 0) != ZB_OK)
        {
            printf("band A would not adopt the seam\n");
            RcpRadio_Close(&radio);
            return 1;
        }

        memset(&pib, 0, sizeof pib);
        pib.present = RADIO_PIB_CHANNEL;
        pib.channel = (uint8_t)channel;

        if (haveShort)
            pib.present = pib.present | RADIO_PIB_SHORT_ADDRESS, pib.shortAddress = (uint16_t)shortAddr;

        if (ownPan != 0)
            pib.present = pib.present | RADIO_PIB_PAN_ID, pib.panId = (uint16_t)ownPan;

        if (Mac_SetPib(&mac, &pib) != ZB_OK)
        {
            printf("band A would not take the PIB\n");
            RcpRadio_Close(&radio);
            return 1;
        }

        /* 7.3.1.6's pending list is the beacon's statement about the transactions this device holds, so a run that
           wants to read that list has to have some queued. Each address is a short one, four hex digits. */
        if (pendingCount != 0 && !macMode)
        {
            printf("--pending needs --mac: the queue is band A's, and without it nothing is held\n");
            RcpRadio_Close(&radio);
            return 1;
        }

        if (pairCount != 0 && !macMode)
        {
            printf("--pair needs --mac: the pair is band A's, and without it nothing holds one\n");
            RcpRadio_Close(&radio);
            return 1;
        }

        /* The two forms of a device that did not associate with this run: the pair the association door learns from
           10.21.5.2, stated here so a table that names both forms can be measured without an association. */
        for (i = 0; i < pairCount; i++)
        {
            if (MacIndirect_LearnPair(&mac.indirect, pairShort[i], pairExtended[i]) != ZB_OK)
            {
                printf("band A would not learn the pair 0x%04x:%016llx\n", pairShort[i],
                       (unsigned long long)pairExtended[i]);
                RcpRadio_Close(&radio);
                return 1;
            }

            if (!quiet)
                printf("pair       0x%04x is %016llx\n", pairShort[i], (unsigned long long)pairExtended[i]);
        }

        for (i = 0; i < pendingCount; i++)
        {
            Mac_DataRequestParameters pending;

            memset(&pending, 0, sizeof pending);
            pending.frameType = MAC_FRAME_TYPE_DATA;
            pending.destAddrMode = MAC_ADDR_SHORT;
            pending.srcAddrMode = MAC_ADDR_SHORT;
            pending.destPan = pib.panId;
            pending.destShort = pendingShort[i];
            pending.payload = pendingBytes;
            pending.payloadLen = (uint32_t)sizeof pendingBytes;

            /* The queue ages a transaction against the clock it was given, so it is given this run's. */
            if (Mac_IndirectRequest(&mac, &pending, Port_NowMs()) != ZB_OK)
            {
                printf("band A would not queue a transaction for 0x%04x\n", pendingShort[i]);
                RcpRadio_Close(&radio);
                return 1;
            }
        }

        if (pendingCount != 0 && !quiet)
            printf("pending    %u transactions queued for the beacon's address list (7.3.1.6), %u held\n",
                   pendingCount, Mac_CountersOf(&mac).transactionQueue);

        if (beaconAnswer || haveBeaconInfo)
        {
            Mac_BeaconConfig beacon;

            memset(&beacon, 0, sizeof beacon);
            beacon.answer = beaconAnswer;
            beacon.panCoordinator = 1;
            beacon.associationPermit = 1;
            beacon.payload = haveBeaconInfo ? beaconInfo : 0;
            beacon.payloadLen = haveBeaconInfo ? beaconInfoLen : 0;

            if (Mac_SetBeaconConfig(&mac, &beacon) != ZB_OK)
            {
                printf("band A would not take the beacon configuration\n");
                RcpRadio_Close(&radio);
                return 1;
            }
        }

        if (!quiet)
            printf("mac        band A adopted the seam; it reports from here on\n");

        if (!quiet && (beaconAnswer || haveBeaconInfo))
            printf("beacon     %s, PAN coordinator, association permit set, payload %u B\n",
                   beaconAnswer ? "a Beacon Request is answered" : "configured but not answering",
                   beaconInfoLen);
    }

    /* 10.23.1's mode through band A's own door, which is the seat that states it to the radio: a run that wants to
       read whether the stick now takes other devices' frames sets it here and not through the seam. */
    if (wantPromisc)
    {
        if (Mac_SetPromiscuousMode(&mac, 1) != ZB_OK)
        {
            printf("band A would not take the promiscuous mode\n");
            RcpRadio_Close(&radio);
            return 1;
        }

        if (!quiet)
            printf("delivery   promiscuous mode on through band A's own door (10.23.1)\n");
    }


    if (wantTx && macMode)
    {
        Mac_DataRequestParameters req;

        memset(&req, 0, sizeof req);
        req.frameType = macFrameType;
        req.destAddrMode = haveDstExt ? MAC_ADDR_EXTENDED : MAC_ADDR_SHORT;

        /* Table 10-101 decides the source from the short address the PIB holds; `--src-mode none` states 7.5.2's
           no-source Beacon Request. */
        if (srcModeNone)
            req.srcAddrMode = MAC_ADDR_NONE;
        else if (haveShort && (uint16_t)shortAddr < MAC_SHORT_ADDRESS_LAST_USABLE)
            req.srcAddrMode = MAC_ADDR_SHORT;
        else
            req.srcAddrMode = MAC_ADDR_EXTENDED;

        req.destPan = (uint16_t)dstPan;
        req.destShort = (uint16_t)dstAddr;
        req.destExtended = dstExtended;
        req.payload = payload;
        req.payloadLen = payloadLen;
        req.ackRequest = ackRequest;

        status = Mac_DataRequest(&mac, &req, Port_NowMs(), 0);

        if (!quiet)
        {
            if (status == ZB_OK && haveDstExt)
                printf("mac tx     requested by band A  %s  dst 0x%016llx pan 0x%04x  payload %u B  ackRequest %d\n",
                       macFrameType == MAC_FRAME_TYPE_COMMAND ? "command" : "data",
                       (unsigned long long)dstExtended, dstPan, payloadLen, ackRequest);
            else if (status == ZB_OK)
                printf("mac tx     requested by band A  %s  dst 0x%04x pan 0x%04x  payload %u B  ackRequest %d\n",
                       macFrameType == MAC_FRAME_TYPE_COMMAND ? "command" : "data",
                       dstAddr, dstPan, payloadLen, ackRequest);
            else
                printf("mac tx     refused by band A: %s\n", statusName(status));
        }

        if (status != ZB_OK)
        {
            RcpRadio_Close(&radio);
            return 1;
        }
    }

    /*
     * The frame, composed by band A and handed to band B complete with its footer. A beacon is not
     * among the frames this stack composes (docs/internals/protocol.md §10 question 7: none is in the captured
     * set, so its shape on this PAN is unmeasured), so what a loopback sends is a data frame: the
     * form every frame in test/fixtures/ is.
     */
    if (wantTx && !macMode)
    {
        frame.frameType = MAC_FRAME_TYPE_DATA;
        frame.frameVersion = 0;         /* R23.1 Annex D.6 */
        frame.ackRequest = ackRequest;
        frame.panIdCompression = 1;
        frame.destAddrMode = MAC_ADDR_SHORT;
        frame.srcAddrMode = MAC_ADDR_SHORT;
        frame.seq = (uint8_t)seq;
        frame.destPan = (uint16_t)dstPan;
        frame.srcPan = (uint16_t)dstPan;
        frame.destShort = (uint16_t)dstAddr;
        frame.srcShort = (uint16_t)srcAddr;

        if (MacFrame_Compose(&frame, payload, payloadLen, mpdu, (uint32_t)sizeof mpdu, &mpduLen) != ZB_OK
            || MacFrame_AppendFcs(mpdu, mpduLen, (uint32_t)sizeof mpdu, &mpduLen) != ZB_OK)
        {
            printf("the frame would not compose\n");
            RcpRadio_Close(&radio);
            return 1;
        }

        /* One deliberate mistake, for measurement. docs/internals/protocol.md §8.2 records that this build
           regenerates a frame's footer rather than appending the host's, which means a composed
           footer never reaches the air on its own: corrupt one here and see whether the peer's
           radio still hands over a frame whose footer validates. If it does, the octets band A
           computed were thrown away; if the peer flags the frame, they travelled. */
        if (txCorrupt)
        {
            mpdu[mpduLen - 1] = (uint8_t)(mpdu[mpduLen - 1] ^ 0x01);

            if (!quiet)
                printf("corrupted  the last octet of the footer band A computed\n");
        }

        status = seam->ops->tx((Radio_Radio *)seam, mpdu, mpduLen, ackRequest, 0, &handle);

        if (!quiet)
        {
            printf("sent       %s seq %02x  pan %04x compressed  dst 0x%04x  src 0x%04x  payload %u  (%u octets)\n",
                   typeName(frame.frameType), frame.seq, frame.destPan, frame.destShort, frame.srcShort,
                   payloadLen, mpduLen);
            printHex(mpdu, mpduLen);
            printf("tx         %s  handle %u\n", status == ZB_OK ? "issued" : statusName(status), handle);
        }

        if (status != ZB_OK)
        {
            RcpRadio_Close(&radio);
            return 1;
        }

        /* §8.3: completion is a second transaction, not the answer to the first. Ask for it until it
           comes or the wait named in the seam says the stick is stuck. */
        txStartMs = Port_NowMs();
        deadline = txStartMs + txWaitMs;
        txPumps = 0;
        status = ZB_ERR_NOT_READY;

        txCodeKnown = 0;

        while (status == ZB_ERR_NOT_READY && !Zb_timeReached(Port_NowMs(), deadline))
        {
            if (RcpRadio_Pump(&radio, Port_NowMs()) != ZB_OK)
                break;

            /* Read the device's code before collecting the result: the code belongs to the transmit
               while it is outstanding, and collecting it is what ends that. */
            if (RcpRadio_TxStatusCode(&radio, handle, &txCode) == ZB_OK)
                txCodeKnown = 1;

            status = seam->ops->completion((Radio_Radio *)seam, handle, &result);
            txPumps++;
            probePause();
        }

        if (!quiet)
        {
            /* The device's own word for the outcome, beside the status band B folded it into:
               NO_ACK, BUSY and FAILURE are one seam status and three different measurements. */
            if (txCodeKnown)
                printf("tx status  device code %u\n", txCode);

            if (status == ZB_ERR_NOT_READY)
                printf("tx result  no completion inside %u ms (%u pumps)\n", txWaitMs, txPumps);
            else if (status != ZB_OK)
                printf("tx result  %s after %u pumps over %u ms\n", statusName(status), txPumps,
                       Port_NowMs() - txStartMs);
            else
                printf("tx result  %s  acked %d  retries %u  after %u pumps over %u ms\n",
                       statusName(result.status), result.isAcked, result.retries, txPumps,
                       Port_NowMs() - txStartMs);
        }

        status = 0;
    }

    deadline = Port_NowMs() + listenSec * 1000;

    while (!Zb_timeReached(Port_NowMs(), deadline))
    {
        /* Once, at the requested time. A reset issued on every pump is not a recovery test, it is a
           stick being reset until it stops answering. */
        if (resetAfter != 0 && !resetDone && Zb_timeReached(Port_NowMs(), startMs + resetAfter * 1000))
        {
            resetDone = 1;
            framesBeforeReset = framesSeen;
            RcpRadio_Restart(&radio, Port_NowMs());

            if (!quiet)
                printf("reset issued at %u s\n", resetAfter);
        }

        if (RcpRadio_Pump(&radio, Port_NowMs()) != ZB_OK)
        {
            printf("the link went away: %s (last error %d)\n", modeName(RcpRadio_Mode(&radio)),
                   RcpRadio_LastError(&radio));
            status = 1;
            break;
        }

        if (macMode)
        {
            stepStatus = Mac_Step(&mac, Port_NowMs());

            if (stepStatus != ZB_OK)
            {
                /* The reason and not only the fact: a step that reports a status is reporting a device-level
                   failure, and a line that names none leaves the failure to be guessed at. */
                printf("band A would not step: %s\n", statusName(stepStatus));
                status = 1;
                break;
            }

            taken = Mac_PollConfirms(&mac, mconfs, (uint32_t)sizeof mconfs / (uint32_t)sizeof mconfs[0]);

            for (i = 0; i < taken; i++)
            {
                if (quiet)
                    continue;

                printf("mac confirm  dsn %02u  %s  acked %d  (band A collected the completion; band B only carried it)\n",
                       mconfs[i].dsn, statusName(mconfs[i].status), mconfs[i].acked);

                /* The two bits §8.9.4.2 puts after the status code, as the device sent them, and the only
                   host-visible statement of an Ack's Frame Pending bit: the radio composes that frame itself
                   and delivers it to no host (docs/internals/protocol.md §10 question 8). */
                if ((RcpRadio_CompletionTail(&radio) & RCP_RADIO_TAIL_REPORTED) != 0)
                    printf("             device said pending %u header-updated %u\n",
                           (RcpRadio_CompletionTail(&radio) & RCP_RADIO_TAIL_PENDING) ? 1 : 0,
                           (RcpRadio_CompletionTail(&radio) & RCP_RADIO_TAIL_HEADER_UPDATED) ? 1 : 0);
            }

            taken = Mac_PollIndications(&mac, inds, MAC_INDICATION_QUEUE_MAX);

            for (i = 0; i < taken; i++)
            {
                framesSeen++;

                if (inds[i].status != ZB_OK)
                    flagged++;

                if (quiet)
                    continue;

                printMacIndication(&inds[i], framesSeen, Port_NowMs() - startMs, showHex);
            }

            /* 8.2.4.3: a received beacon is its own event and never an indication, so the window prints it here. */
            taken = Mac_PollBeacons(&mac, heardAsBeacons, MAC_BEACON_NOTIFY_MAX);

            for (i = 0; i < taken; i++)
            {
                framesSeen++;

                if (quiet)
                    continue;

                printMacBeacon(&heardAsBeacons[i], framesSeen, Port_NowMs() - startMs, showHex);
            }
        }
        else
        {
            taken = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);

            while (taken != 0)
            {
                for (i = 0; i < taken; i++)
                {
                    framesSeen++;

                    if (frames[i].error != ZB_OK)
                        flagged++;

                    if (quiet)
                        continue;

                    printFrame(&frames[i], &caps, framesSeen,
                               Port_NowMs() - startMs, showHex);
                }

                taken = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);
            }
        }

        probePause();
    }

    /*
     * An energy dwell asks the stick to measure one channel and says nothing on the air, so it belongs to a
     * read-only run: no --tx and no --allow-tx are involved (docs/internals/hardware.md §7). What is written to the port
     * is band B's own three property writes, and what is waited for is the notification they produce
     * (docs/internals/protocol.md §7.4.1). The wait is longer than band B's bound on purpose: a run should report what
     * band B decided, not compete with it.
     */
    for (i = 0; i < scanCount; i++)
    {
        uint32_t levelChannel = 0;
        int32_t levelDbm = 0;
        ZbStatus scanStatus;
        uint32_t scanDeadline;
        uint32_t pumps = 0;

        scanStatus = seam->ops->scanStart((Radio_Radio *)seam, scanChannels[i], scanPeriod);

        if (scanStatus != ZB_OK)
        {
            printf("scan       channel %u refused at the ask: %s\n", scanChannels[i], statusName(scanStatus));
            status = 1;
            break;
        }

        scanDeadline = Port_NowMs() + PROBE_SCAN_WAIT_MS;

        for (;;)
        {
            scanStatus = seam->ops->scanCollect((Radio_Radio *)seam, &levelChannel, &levelDbm);

            if (scanStatus != ZB_ERR_NOT_READY)
                break;

            if (Zb_timeReached(Port_NowMs(), scanDeadline))
                break;

            if (RcpRadio_Pump(&radio, Port_NowMs()) != ZB_OK)
            {
                printf("scan       channel %u lost the link: %s\n", scanChannels[i],
                       modeName(RcpRadio_Mode(&radio)));
                status = 1;
                break;
            }

            pumps++;
            probePause();
        }

        if (scanStatus == ZB_OK)
        {
            if (levelDbm == RADIO_SCAN_NO_LEVEL)
                printf("scan       channel %u  period %u  no level reported  (%u pumps)\n",
                       scanChannels[i], scanPeriod, pumps);
            else
                printf("scan       channel %u  period %u  %d dBm on channel %u  (%u pumps)\n",
                       scanChannels[i], scanPeriod, levelDbm, levelChannel, pumps);
        }
        else
        {
            printf("scan       channel %u  period %u  the dwell answered %s\n",
                   scanChannels[i], scanPeriod, statusName(scanStatus));
            status = 1;
        }
    }

    if (!quiet)
    {
        printf("scans      %u dwells asked, %u ended with nothing to report\n",
               RcpRadio_ScanDwells(&radio), RcpRadio_ScanAbandons(&radio));

        /* What band A made of the traffic it was shown, which is where an echo of this device's own transmission
           lands rather than as an indication (D-125). The first number is the indication
           queue's occupancy at this moment and not a total: what it delivered is in the `mac ind` lines above. */
        if (macMode)
        {
            counters = Mac_CountersOf(&mac);

            printf("mac queue  %u held for the layer above, %u consumed as this device's own, "
                   "%u acknowledgments, %u other commands\n",
                   counters.indicationQueue, counters.selfEchoes, counters.acksHeard, counters.commandsHeard);
        }

        if (macMode && (beaconAnswer || haveBeaconInfo))
        {
            counters = Mac_CountersOf(&mac);

            printf("beacons    %u requests heard, %u answered, %u ignored, %u refused, %u pending dropped\n",
                   counters.beaconRequestsHeard, counters.beaconReplies, counters.beaconIgnored,
                   counters.beaconRefused, counters.beaconPendingDropped);
            printf("transactions %u held after %u expired\n", counters.transactionQueue,
                   counters.transactionsExpired);

        }

        /* 10.22.3's table as the radio last answered it: what its Acks were decided from. */
        if (macMode && RcpRadio_PendingWritten(&radio, &pendingTable))
        {
            printf("pending tbl %s, %u short, %u extended, %u writes, %u refusals",
                   pendingTable.isComplete ? "complete" : "the fallback (every Ack claims pending)",
                   pendingTable.shortCount, pendingTable.extendedCount,
                   RcpRadio_PendingWrites(&radio), RcpRadio_PendingRefusals(&radio));

            for (i = 0; i < pendingTable.shortCount; i++)
                printf(" 0x%04x", pendingTable.shortAddress[i]);

            for (i = 0; i < pendingTable.extendedCount; i++)
                printf(" %016llx", (unsigned long long)pendingTable.extendedAddress[i]);

            printf("\n");
        }
    }

    if (macMode && !quiet)
        printf("poll owed  %u issued, %u refused (last: %s)\n",
               (unsigned)mac.beacon.pollIssued, (unsigned)mac.beacon.pollRefused,
               statusName(mac.beacon.pollStatus));

    if (resetDone && !quiet)
    {
        printf("re-armed   %s after the reset, %u frames before it and %u after\n",
               modeName(RcpRadio_Mode(&radio)), framesBeforeReset, framesSeen - framesBeforeReset);
    }

    if (!quiet)
    {
        RcpRadio_Transactions(&radio, &requests, &replies, &notifications, &stale, &timeouts, &malformed);

        printf("counters   frames %u  flagged %u  linkDrops %u  portDrops %u  rejects %u  "
               "overflows %u  writeFailures %u  resets %u  framesNamingAck %u\n",
               framesSeen, flagged, RcpRadio_LinkDrops(&radio), RcpRadio_PortDrops(&radio),
               RcpRadio_FrameRejects(&radio), RcpRadio_RxOverflows(&radio),
               RcpRadio_WriteFailures(&radio), RcpRadio_ResetsSeen(&radio), RcpRadio_RxWithAckMetadata(&radio));
        printf("           requests %u  replies %u  notifications %u  stale %u  timeouts %u  malformed %u\n",
               requests, replies, notifications, stale, timeouts, malformed);
    }

    /* A session ends with a reset, not a close: a stick stays armed after its host hangs up, and RcpRadio_Close writes §6's teardown order for exactly that. */
    RcpRadio_Close(&radio);
    return status;
}
