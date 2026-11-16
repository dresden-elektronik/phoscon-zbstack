#define _POSIX_C_SOURCE 200809    /* clock_gettime is POSIX; glibc hides it under -std=c99 without this, before any include */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hearing.h"
#include "mac_frame.h"
#include "nwk.h"
#include "nwk_frame.h"
#include "port_posix.h"
#include "protect.h"
#include "rcp_radio.h"
#include "zb_time.h"
#include "zb_utils.h"
#include "zb_stack.h"

/*
 * One node of a mesh on the bench: a coordinator, a router or an end device over `Zb_Stack`, sending counted traffic
 * and printing what became of it, with `--ignore` standing in for the distance the sticks do not have
 * (src/stack/hearing.h, D-260).
 * `--role`, `--path` and `--epid` are always named, and no port is ever defaulted (docs/internals/hardware.md §8); a run
 * ends with a reset. It transmits, so it needs `--tx --allow-tx`, and it runs on PAN 0xbeef only, on channel 12 or on
 * the other channel `--channel` names from 11, 25 and 26 (§7).
 *
 * A line C - R1 - R2 is built by naming each cut pair at both ends and by opening each parent's permit in turn, since a
 * beacon carries no extended address: docs/internals/testing.md §7 has the recipe.
 * `--forget-children-at` clears this parent's end device children, as a parent that aged them out or restarted would.
 * `--lockstep` keeps one unicast out at a time, to the devices that announced themselves, and sends the next `--uni-ms`
 * after its confirm.
 */

#define MESH_CHANNEL 12           /* the default; --channel names another, any 11..26 not protected */
#define MESH_PAN 0xbeef
#define MESH_ENDPOINT 1
#define MESH_PROFILE 0x0104
#define MESH_CLUSTER 0xfc00
#define MESH_DEVICE 0x0100
#define MESH_GHOST 0x7777        /* an address no device holds: a discovery that has to end in no route */
#define MESH_ALL_ROUTERS 0xfffc

#define PEERS_MAX 16
#define SEQ_MAX 16384
#define WAIT_MS 5
#define BRINGUP_MS 3000
#define STOP_PUMPS 3
#define STATS_S 30
#define SLOW_REPLY_MS 200
#define SLOW_REPLIES_MAX 40

enum { TAG_UNI = 1, TAG_BROADCAST = 2, TAG_GHOST = 3 };

/* What one request to the stick is timed under: a transmit by its answer, its wait in line before it, and the rest. */
enum { TIMING_TX_OK, TIMING_TX_NO_ACK, TIMING_TX_BUSY, TIMING_TX_OTHER, TIMING_LINE, TIMING_PROP, TIMING_KINDS };
enum { TIMING_BUCKETS = 8 };

typedef struct Timing
{
    uint32_t count, maxMs;
    uint32_t bucket[TIMING_BUCKETS];
} Timing;

typedef struct Tx
{
    uint16_t address;
    int inUse;
    uint32_t taken, refused, ok, noAck, noRoute, other, attempts;
} Tx;

typedef struct Rx
{
    uint16_t address;
    int inUse;
    uint32_t uni, uniTwice, broadcast, broadcastTwice;
    uint8_t seenUni[SEQ_MAX / 8];
    uint8_t seenBroadcast[SEQ_MAX / 8];
} Rx;

typedef struct Options
{
    const char *path;
    const char *role;
    unsigned baud, channel, permit, seconds, trafficAt, uniMs, broadcastS, ghostS, leaveAt, scanAttempts, forgetAt;
    unsigned pollMs;
    unsigned long long epid;
    int toAll, tx, allowTx, lockstep, sleepy, hearsWhileAsleep;
    Protect protect;
} Options;

static Rcp_Radio s_stick;
static Hearing s_hearing;
static Timing s_timing[TIMING_KINDS];
static Timing s_turns;
static uint8_t s_askedTid;
static uint32_t s_askedSinceMs;
static uint32_t s_askedProp;
static uint32_t s_slowReplies;
static uint32_t s_lastPumpMs;
static Zb_Stack s_stack;
static Tx s_tx[PEERS_MAX];
static Rx s_rx[PEERS_MAX];
static Tx s_broadcast;
static Tx s_ghost;
static uint16_t s_self = 0xffff;
static uint8_t s_asdu[12];
static int s_unicastOut;
static volatile sig_atomic_t s_signal;

static void onSignal(int number)
{
    (void)number;
    s_signal = 1;
}

static Tx *txOf(uint16_t address)
{
    uint32_t i;

    for (i = 0; i < PEERS_MAX; i++)
    {
        if (s_tx[i].inUse && s_tx[i].address == address)
            return &s_tx[i];

        if (!s_tx[i].inUse)
        {
            s_tx[i].inUse = 1;
            s_tx[i].address = address;

            return &s_tx[i];
        }
    }

    return &s_ghost;
}

static Rx *rxOf(uint16_t address)
{
    uint32_t i;

    for (i = 0; i < PEERS_MAX; i++)
    {
        if (s_rx[i].inUse && s_rx[i].address == address)
            return &s_rx[i];

        if (!s_rx[i].inUse)
        {
            s_rx[i].inUse = 1;
            s_rx[i].address = address;

            return &s_rx[i];
        }
    }

    return &s_rx[PEERS_MAX - 1];
}

static void compose(uint32_t sequence, uint8_t kind)
{
    s_asdu[0] = 'Z';
    s_asdu[1] = kind;
    s_asdu[2] = (uint8_t)sequence;
    s_asdu[3] = (uint8_t)(sequence >> 8);
    memset(s_asdu + 4, 0xa5, 8);
}

static int send(uint16_t destination, uint16_t tag, uint32_t options, Tx *tx)
{
    Aps_ApsdeReq request;

    memset(&request, 0, sizeof request);
    request.dstAddrMode = APS_ADDR_MODE_SHORT;
    request.dstAddress = destination;
    request.dstEndpoint = MESH_ENDPOINT;
    request.profileId = MESH_PROFILE;
    request.clusterId = MESH_CLUSTER;
    request.srcEndpoint = MESH_ENDPOINT;
    request.asdu = s_asdu;
    request.asduLength = sizeof s_asdu;
    request.txOptions = options;
    request.tag = tag;

    if (Zb_StackApsRequest(&s_stack, &request) != ZB_OK)
    {
        tx->refused++;
        return 0;
    }

    tx->taken++;

    return 1;
}

/* Every end device child cleared from the neighbour table: what a parent that aged them out holds. */
static uint32_t forgetChildren(void)
{
    Nwk_Nwk *nwk = Zb_CoreNwk(Zb_StackCore(&s_stack));
    uint32_t forgotten = 0;
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (nwk->neighbors[i].inUse && nwk->neighbors[i].relationship == NWK_REL_CHILD
            && nwk->neighbors[i].deviceType == NWK_DEVICE_END_DEVICE)
        {
            memset(&nwk->neighbors[i], 0, sizeof nwk->neighbors[i]);
            forgotten++;
        }
    }

    return forgotten;
}

/* The next neighbour with a cost: traffic that needs no route. */
static uint16_t nextNeighbour(void)
{
    static uint32_t cursor;
    const Nwk_Nwk *nwk = Zb_CoreNwk(Zb_StackCore(&s_stack));
    const Nwk_NeighborTableEntry *entry;
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        entry = &nwk->neighbors[(cursor + i) % NWK_NEIGHBOR_MAX];

        if (entry->inUse && entry->outgoingCost != 0 && entry->outgoingCost < 7 && entry->networkAddress != s_self)
        {
            cursor = (cursor + i + 1) % NWK_NEIGHBOR_MAX;

            return entry->networkAddress;
        }
    }

    return 0xffff;
}

/* The next device heard from, directly or through others, and the coordinator: traffic that may have to be routed. */
static uint16_t nextPeer(void)
{
    static uint32_t cursor;
    uint32_t i;
    uint16_t candidate;

    for (i = 0; i <= PEERS_MAX; i++)
    {
        uint32_t at = (cursor + i) % (PEERS_MAX + 1);

        if (at == PEERS_MAX)
            candidate = 0x0000;
        else if (s_rx[at].inUse)
            candidate = s_rx[at].address;
        else
            continue;

        if (candidate == s_self)
            continue;

        cursor = at + 1;

        return candidate;
    }

    return 0xffff;
}

static void onData(const Aps_Indication *data)
{
    uint32_t sequence;
    Rx *rx;
    uint8_t *seen;

    if (data->asduLength < 4 || data->asdu[0] != 'Z')
        return;

    rx = rxOf(data->srcAddress);
    sequence = ((uint32_t)data->asdu[2] | ((uint32_t)data->asdu[3] << 8)) % SEQ_MAX;
    seen = data->asdu[1] == 'U' ? rx->seenUni : rx->seenBroadcast;

    if (seen[sequence / 8] & (1 << (sequence % 8)))
    {
        if (data->asdu[1] == 'U')
            rx->uniTwice++;
        else
            rx->broadcastTwice++;

        return;
    }

    seen[sequence / 8] |= (uint8_t)(1 << (sequence % 8));

    if (data->asdu[1] == 'U')
        rx->uni++;
    else
        rx->broadcast++;
}

static void onSent(const Aps_Confirm *confirm, ZbStatus status, long t)
{
    Tx *tx = confirm->tag == TAG_BROADCAST ? &s_broadcast : confirm->tag == TAG_GHOST ? &s_ghost : txOf(confirm->dstAddress);

    tx->attempts += confirm->attempts;

    if (confirm->tag == TAG_UNI)
        s_unicastOut = 0;

    if (status != ZB_OK && confirm->tag != TAG_GHOST)
        printf("sentfail t=%ld dst=0x%04x tag=%u status=%d aps=0x%x attempts=%u\n", t, confirm->dstAddress, confirm->tag,
               (int)status, (unsigned)confirm->apsStatus, (unsigned)confirm->attempts);

    if (status == ZB_OK)
        tx->ok++;
    else if (status == ZB_ERR_NO_ACK)
        tx->noAck++;
    else if (status == ZB_ERR_NO_ROUTE)
        tx->noRoute++;
    else
        tx->other++;
}

#define COUNTER(name) printf(" %s=%u", #name, (unsigned)nwk->name)

static void timingAdd(Timing *timing, uint32_t ms)
{
    static const uint32_t limits[TIMING_BUCKETS - 1] = { 10, 20, 50, 100, 200, 500, 1000 };
    uint32_t i = 0;

    while (i < TIMING_BUCKETS - 1 && ms >= limits[i])
        i++;

    timing->bucket[i]++;
    timing->count++;

    if (ms > timing->maxMs)
        timing->maxMs = ms;
}

static void timingPrint(const char *kind, const Timing *timing)
{
    printf("timing self=0x%04x kind=%s n=%u max=%u lt10=%u lt20=%u lt50=%u lt100=%u lt200=%u lt500=%u lt1000=%u ge1000=%u\n",
           s_self, kind, (unsigned)timing->count, (unsigned)timing->maxMs, (unsigned)timing->bucket[0],
           (unsigned)timing->bucket[1], (unsigned)timing->bucket[2], (unsigned)timing->bucket[3], (unsigned)timing->bucket[4],
           (unsigned)timing->bucket[5], (unsigned)timing->bucket[6], (unsigned)timing->bucket[7]);
}

static uint32_t txSlotOf(uint8_t tid)
{
    uint32_t i;

    for (i = 0; i < RCP_RADIO_TX_TRACK_MAX; i++)
    {
        if (s_stick.txFilled[i] && !s_stick.txWaiting[i] && s_stick.txTid[i] == tid)
            return i;
    }

    return RCP_RADIO_TX_TRACK_MAX;
}

/* The request that just ended, timed by the clock it was asked under; a slow one also gets a line of its own. */
static void timingRequestEnded(uint32_t nowMs)
{
    uint32_t slot = s_askedProp == PROP_STREAM_RAW ? txSlotOf(s_askedTid) : RCP_RADIO_TX_TRACK_MAX;
    uint32_t ms = nowMs - s_askedSinceMs;
    int kind = TIMING_PROP;
    ZbStatus status = ZB_OK;

    if (s_askedProp == PROP_STREAM_RAW)
    {
        kind = TIMING_TX_OTHER;

        if (slot < RCP_RADIO_TX_TRACK_MAX && s_stick.txAnswered[slot])
        {
            status = s_stick.txResult[slot].status;
            kind = status == ZB_OK ? TIMING_TX_OK : status == ZB_ERR_NO_ACK ? TIMING_TX_NO_ACK
                : status == ZB_ERR_CHANNEL_ACCESS_FAILURE ? TIMING_TX_BUSY : TIMING_TX_OTHER;
        }
    }

    timingAdd(&s_timing[kind], ms);

    if (ms >= SLOW_REPLY_MS && s_slowReplies < SLOW_REPLIES_MAX)
    {
        s_slowReplies++;
        printf("slowreply at=%u ms=%u prop=0x%x status=%d len=%u\n", (unsigned)nowMs, (unsigned)ms, (unsigned)s_askedProp,
               (int)status, slot < RCP_RADIO_TX_TRACK_MAX ? (unsigned)s_stick.txFrameLen[slot] : 0);
    }
}

/* Called after everything that can end or start a request. A request ends in the pump, before its slot can be collected. */
static void timingWatch(uint32_t nowMs)
{
    uint8_t tid = SpinelSession_PendingTid(&s_stick.session);
    uint32_t slot;

    if (tid == s_askedTid)
        return;

    if (s_askedTid != SPINEL_TID_NONE)
        timingRequestEnded(nowMs);

    s_askedTid = tid;

    if (tid == SPINEL_TID_NONE)
        return;

    s_askedSinceMs = s_stick.session.pendingSinceMs;
    s_askedProp = SpinelSession_PendingProp(&s_stick.session);
    slot = s_askedProp == PROP_STREAM_RAW ? txSlotOf(tid) : RCP_RADIO_TX_TRACK_MAX;

    if (slot < RCP_RADIO_TX_TRACK_MAX)
        timingAdd(&s_timing[TIMING_LINE], s_askedSinceMs - s_stick.txAskedMs[slot]);
}

static void printCounters(long t)
{
    const Nwk_Nwk *nwk = Zb_CoreNwk(Zb_StackCore(&s_stack));

    printf("nwkstat t=%ld self=0x%04x", t, s_self);
    COUNTER(linkStatusSent); COUNTER(linkStatusApplied); COUNTER(droppedUnsecured); COUNTER(rxSecurityFailures);
    COUNTER(rxFrameCounterRejects); COUNTER(txSecurityFailures); COUNTER(droppedDuplicate); COUNTER(droppedNotForMe);
    COUNTER(droppedMalformed); COUNTER(droppedIndications); COUNTER(confirmsDropped); COUNTER(confirmsIgnored);
    COUNTER(relaysSent); COUNTER(routeRequestsSent); COUNTER(routeRepliesSent); COUNTER(rreqDroppedNoNeighbor);
    COUNTER(rreqDroppedNoOutgoingCost); COUNTER(rreqDroppedGreaterCost); COUNTER(rreqDroppedNoDiscoverySlot);
    COUNTER(droppedNoRoute); COUNTER(neighborAddsRefused); COUNTER(linkFailuresReported); COUNTER(backbonePromotions);
    COUNTER(refusedRequests); COUNTER(routesInvalidated); COUNTER(routeRepliesForwarded); COUNTER(rrepDroppedNoDiscovery);
    COUNTER(childDiscoveries); COUNTER(childFramesHeld);
    COUNTER(rrepDroppedNoRoute); COUNTER(rrepDroppedNoReverseRoute); COUNTER(rrepDroppedNotSmaller);
    COUNTER(rrepDroppedUnsuitable); COUNTER(rrepDroppedNoCapacity); COUNTER(statusRoutesRemoved); COUNTER(forwardsRefused);
    COUNTER(forwardsGivenUp); COUNTER(bttFullDrops); COUNTER(droppedEndDeviceInitiator); COUNTER(timeoutRequestsSent);
    COUNTER(unknownSenderLeaves);
    printf(" rejoins=%u rejoinsFailed=%u", (unsigned)Zb_CoreRejoins(Zb_StackCore(&s_stack)),
           (unsigned)Zb_CoreRejoinsFailed(Zb_StackCore(&s_stack)));
    printf(" polls=%u pollsWithData=%u pollsNoData=%u heardAsleep=%u", (unsigned)Nwk_PollsSent(nwk),
           (unsigned)Mac_CountersOf(Zb_CoreMac(Zb_StackCore(&s_stack))).pollsWithData,
           (unsigned)Mac_CountersOf(Zb_CoreMac(Zb_StackCore(&s_stack))).pollsNoData,
           (unsigned)Mac_CountersOf(Zb_CoreMac(Zb_StackCore(&s_stack))).heardAsleep);
    printf(" unheard=%u unsent=%u txWaitsExpired=%u txResultsUncollected=%u replyTimeouts=%u resetsSeen=%u\n",
           (unsigned)s_hearing.framesDropped, (unsigned)s_hearing.framesUnsent, (unsigned)s_stick.txWaitsExpired,
           (unsigned)s_stick.txResultsUncollected, (unsigned)s_stick.session.timeouts, (unsigned)s_stick.resetsSeen);
}

static void printFinal(void)
{
    const Nwk_Nwk *nwk = Zb_CoreNwk(Zb_StackCore(&s_stack));
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        const Nwk_NeighborTableEntry *entry = &nwk->neighbors[i];

        if (entry->inUse)
            printf("neighbor self=0x%04x addr=0x%04x ieee=%016llx type=%u rel=0x%02x lqa=%u cost=%u age=%u routerAge=%u txFail=%u in=%u out=%u\n",
                   s_self, entry->networkAddress, (unsigned long long)entry->extendedAddress, (unsigned)entry->deviceType,
                   (unsigned)entry->relationship, entry->lqi, (unsigned)entry->outgoingCost, (unsigned)entry->age,
                   entry->routerAge, (unsigned)entry->transmitFailures, (unsigned)entry->routerInboundActivity,
                   (unsigned)entry->routerOutboundActivity);
    }

    for (i = 0; i < NWK_ROUTE_MAX; i++)
    {
        const Nwk_RoutingTableEntry *route = &nwk->routes[i];

        if (route->inUse)
            printf("route self=0x%04x dst=0x%04x next=0x%04x status=%u\n", s_self, route->destinationAddress,
                   route->nextHopAddress, (unsigned)route->status);
    }

    for (i = 0; i < PEERS_MAX; i++)
    {
        const Tx *tx = &s_tx[i];

        if (tx->inUse)
            printf("txsum self=0x%04x dst=0x%04x taken=%u refused=%u ok=%u noAck=%u noRoute=%u other=%u attempts=%u\n", s_self,
                   tx->address, tx->taken, tx->refused, tx->ok, tx->noAck, tx->noRoute, tx->other, tx->attempts);
    }

    timingPrint("txOk", &s_timing[TIMING_TX_OK]);
    timingPrint("txNoAck", &s_timing[TIMING_TX_NO_ACK]);
    timingPrint("txBusy", &s_timing[TIMING_TX_BUSY]);
    timingPrint("txOther", &s_timing[TIMING_TX_OTHER]);
    timingPrint("line", &s_timing[TIMING_LINE]);
    timingPrint("prop", &s_timing[TIMING_PROP]);
    timingPrint("turn", &s_turns);

    printf("bcsum self=0x%04x taken=%u refused=%u ok=%u other=%u\n", s_self, s_broadcast.taken, s_broadcast.refused,
           s_broadcast.ok, s_broadcast.noAck + s_broadcast.noRoute + s_broadcast.other);
    printf("ghostsum self=0x%04x taken=%u refused=%u ok=%u noAck=%u noRoute=%u other=%u\n", s_self, s_ghost.taken,
           s_ghost.refused, s_ghost.ok, s_ghost.noAck, s_ghost.noRoute, s_ghost.other);

    for (i = 0; i < PEERS_MAX; i++)
    {
        const Rx *rx = &s_rx[i];

        if (rx->inUse)
            printf("rxsum self=0x%04x src=0x%04x uni=%u uniDup=%u bc=%u bcDup=%u\n", s_self, rx->address, rx->uni, rx->uniTwice,
                   rx->broadcast, rx->broadcastTwice);
    }
}

static uint32_t txTrackInUse(void)
{
    uint32_t used = 0;
    uint32_t i;

    for (i = 0; i < RCP_RADIO_TX_TRACK_MAX; i++)
        used += s_stick.txFilled[i] ? 1 : 0;

    return used;
}

/* --trace: one line a frame, the part of it that is in the clear. A command's identifier is not, so a line says only
   command or data, its length, both headers' addresses, and a transmit's status with the stick's own track in use. */
static void traceFrame(const uint8_t *mpdu, uint32_t len, int sent, int cut, ZbStatus status)
{
    Mac_Frame mac;
    Mac_FrameRefusal refusal;
    Nwk_Frame nwk;
    const uint8_t *payload = 0;
    uint32_t payloadLen = 0;
    uint32_t offset = 0;
    uint32_t nwkPayloadLen = 0;
    struct timespec ts;

    if (MacFrame_Parse(mpdu, len, 0, &mac, &payload, &payloadLen, &refusal) != ZB_OK)
        return;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    printf("frame %ld.%03ld %s%s status=%d track=%u writes=%u asking=%x mac=%u dsn=%u", (long)ts.tv_sec, ts.tv_nsec / 1000000,
           sent ? "tx" : "rx", cut ? " cut" : "", (int)status, (unsigned)txTrackInUse(), (unsigned)s_stick.writeCount,
           SpinelSession_Busy(&s_stick.session) ? (unsigned)SpinelSession_PendingProp(&s_stick.session) : 0,
           (unsigned)mac.frameType, (unsigned)mac.seq);
    printf(" macsrc=%04x macdst=%04x len=%u", mac.srcAddrMode == MAC_ADDR_SHORT ? mac.srcShort : 0xffee,
           mac.destAddrMode == MAC_ADDR_SHORT ? mac.destShort : 0xffee, (unsigned)len);

    if (mac.frameType == MAC_FRAME_TYPE_DATA && payload != 0
        && NwkFrame_Parse(payload, payloadLen, &nwk, &offset, &nwkPayloadLen) == ZB_OK)
        printf(" nwk=%s src=%04x dst=%04x radius=%u seq=%u sec=%d", nwk.frameType == NWK_FRAME_TYPE_COMMAND ? "cmd" : "data",
               nwk.srcAddr, nwk.destAddr, (unsigned)nwk.radius, (unsigned)nwk.sequenceNumber, nwk.securityEnabled);

    printf("\n");
}

static int usage(void)
{
    printf("usage: zb_mesh --role c|r|e --path <device> --epid <hex> --seconds <n> --tx --allow-tx\n"
           "               [--baud <n>] [--channel <n>] [--protect-channel <n>]... [--protect-pan <hex>]... [--permit <s>] [--scan-attempts <n>] [--leave-at <s>] [--trace]\n"
           "               [--ignore <eui64 hex>]... [--ignore-short <hex>]...\n"
           "               [--traffic-at <s>] [--uni-ms <n>] [--to all|neighbours] [--bc-s <n>] [--ghost-s <n>]\n"
           "               [--lockstep] [--forget-children-at <s>] [--sleepy] [--poll-ms <n>] [--hears-while-asleep]\n");

    return 2;
}

/* A channel the run protects, and the mesh's own PAN when the run protects it, are never armed on
   (docs/internals/hardware.md §8). */
static int channelAllowed(const Options *options)
{
    return options->channel >= 11 && options->channel <= 26 && !protectChannel(&options->protect, options->channel) &&
           !protectPan(&options->protect, MESH_PAN);
}

static int parseArguments(int argc, char **argv, Options *options)
{
    int i;

    memset(options, 0, sizeof *options);
    options->channel = MESH_CHANNEL;
    options->trafficAt = 45;

    for (i = 1; i < argc; i++)
    {
        const char *key = argv[i];
        const char *value = i + 1 < argc ? argv[i + 1] : 0;

        int protectTaken = protectOption(&options->protect, argc, argv, (uint32_t)i);

        if (protectTaken < 0)
            return 0;

        if (protectTaken > 0)
        {
            i++;
            continue;
        }

        if (strcmp(key, "--tx") == 0)
        {
            options->tx = 1;
            continue;
        }

        if (strcmp(key, "--allow-tx") == 0)
        {
            options->allowTx = 1;
            continue;
        }

        if (strcmp(key, "--lockstep") == 0)
        {
            options->lockstep = 1;
            continue;
        }

        if (strcmp(key, "--sleepy") == 0)
        {
            options->sleepy = 1;
            continue;
        }

        if (strcmp(key, "--hears-while-asleep") == 0)
        {
            options->hearsWhileAsleep = 1;
            continue;
        }

        if (strcmp(key, "--trace") == 0)
        {
            s_hearing.observe = traceFrame;
            continue;
        }

        if (value == 0)
            return 0;

        i++;

        if (strcmp(key, "--path") == 0)
            options->path = value;
        else if (strcmp(key, "--role") == 0)
            options->role = value;
        else if (strcmp(key, "--baud") == 0)
            options->baud = (unsigned)atoi(value);
        else if (strcmp(key, "--channel") == 0)
            options->channel = (unsigned)atoi(value);
        else if (strcmp(key, "--epid") == 0)
            options->epid = strtoull(value, 0, 16);
        else if (strcmp(key, "--permit") == 0)
            options->permit = (unsigned)atoi(value);
        else if (strcmp(key, "--seconds") == 0)
            options->seconds = (unsigned)atoi(value);
        else if (strcmp(key, "--traffic-at") == 0)
            options->trafficAt = (unsigned)atoi(value);
        else if (strcmp(key, "--uni-ms") == 0)
            options->uniMs = (unsigned)atoi(value);
        else if (strcmp(key, "--bc-s") == 0)
            options->broadcastS = (unsigned)atoi(value);
        else if (strcmp(key, "--ghost-s") == 0)
            options->ghostS = (unsigned)atoi(value);
        else if (strcmp(key, "--leave-at") == 0)
            options->leaveAt = (unsigned)atoi(value);
        else if (strcmp(key, "--forget-children-at") == 0)
            options->forgetAt = (unsigned)atoi(value);
        else if (strcmp(key, "--poll-ms") == 0)
            options->pollMs = (unsigned)atoi(value);
        else if (strcmp(key, "--scan-attempts") == 0)
            options->scanAttempts = (unsigned)atoi(value);
        else if (strcmp(key, "--to") == 0)
            options->toAll = strcmp(value, "all") == 0;
        else if (strcmp(key, "--ignore") == 0)
        {
            if (Hearing_IgnoreIeee(&s_hearing, strtoull(value, 0, 16)) != ZB_OK)
                return 0;
        }
        else if (strcmp(key, "--ignore-short") == 0)
        {
            if (Hearing_IgnoreShort(&s_hearing, (uint16_t)strtoul(value, 0, 16)) != ZB_OK)
                return 0;
        }
        else
            return 0;
    }

    return options->path != 0 && options->role != 0 && options->epid != 0 && options->seconds != 0 &&
           channelAllowed(options);
}

static void fillConfig(const Options *options, Zb_StackConfig *cfg)
{
    Af_SimpleDescriptor *endpoint;

    if (options->role[0] == 'c')
    {
        Zb_StackCoordinatorDefaults(cfg);
        cfg->channel = options->channel;
        cfg->panId = MESH_PAN;
        (void)Port_Entropy(&s_stick.port, cfg->networkKey, ZB_STACK_KEY_OCTETS);
    }
    else
    {
        if (options->role[0] == 'e')
        {
            Zb_StackEndDeviceDefaults(cfg);
            cfg->sleepy = options->sleepy;
            cfg->pollIntervalMs = options->pollMs;
            cfg->hearsWhileAsleep = options->hearsWhileAsleep;
        }
        else
            Zb_StackRouterDefaults(cfg);

        cfg->channelMask = (uint32_t)1 << options->channel;
    }

    cfg->radio = Hearing_Seam(&s_hearing);
    cfg->baud = options->baud;
    cfg->extendedPanId = options->epid;
    cfg->permitSeconds = (uint8_t)options->permit;
    cfg->scanAttempts = options->scanAttempts;

    endpoint = &cfg->endpoints[0];
    endpoint->endpoint = MESH_ENDPOINT;
    endpoint->profileId = MESH_PROFILE;
    endpoint->deviceId = MESH_DEVICE;
    endpoint->deviceVersion = 1;
    endpoint->inputClusterCount = 1;
    endpoint->inputClusters[0] = MESH_CLUSTER;
    cfg->endpointCount = 1;
}

/* The stick the stack is handed, already running: a stack over a radio of the caller's own never opens or pumps one. */
static int openStick(const Options *options)
{
    PortConfig portCfg;
    Radio_Pib channel;
    uint32_t startMs;
    uint32_t nowMs;

    if (RcpRadio_Init(&s_stick, PortPosixOps(), RCP_RADIO_REPLY_TIMEOUT_MS) != ZB_OK)
        return 0;

    memset(&portCfg, 0, sizeof portCfg);
    portCfg.exclusive = 1;
    portCfg.baud = options->baud;

    if (RcpRadio_Open(&s_stick, options->path, &portCfg) != ZB_OK)
        return 0;

    memset(&channel, 0, sizeof channel);
    channel.present = RADIO_PIB_CHANNEL;
    channel.channel = options->channel;

    if (RcpRadio_Seam(&s_stick)->ops->pibSet(RcpRadio_Seam(&s_stick), &channel) != ZB_OK)
        return 0;

    startMs = Port_NowMs();
    nowMs = startMs;

    while (RcpRadio_Mode(&s_stick) != RCP_RADIO_MODE_RUNNING)
    {
        ZbStatus status = RcpRadio_Pump(&s_stick, nowMs);

        if (!Zb_timeWithin(nowMs, startMs, BRINGUP_MS) || (status != ZB_OK && status != ZB_ERR_TIMEOUT))
            return 0;

        (void)Port_Wait(&s_stick.port, WAIT_MS);
        nowMs = Port_NowMs();
    }

    return 1;
}

/* Armed state survives the hang-up (docs/internals/hardware.md §8), so the run ends with a reset, given the pumps
   that put it on the link and not the ones that would arm the stick again once it answers. */
static void closeStick(void)
{
    uint32_t nowMs = 0;
    uint32_t i;

    nowMs = Port_NowMs();
    (void)RcpRadio_Restart(&s_stick, nowMs);

    for (i = 0; i < STOP_PUMPS; i++)
    {
        nowMs = Port_NowMs();
        (void)RcpRadio_Pump(&s_stick, nowMs);
        (void)Port_Wait(&s_stick.port, WAIT_MS);
    }

    RcpRadio_Close(&s_stick);
}

int main(int argc, char **argv)
{
    static Options options;
    static Zb_StackConfig cfg;
    Zb_StackEvent event;
    time_t start;
    time_t stopAt;
    time_t nextStats;
    time_t upAt = 0;
    time_t nextBroadcast = 0;
    time_t nextGhost = 0;
    struct timespec lastUni = { 0, 0 };
    uint32_t sequenceUni = 0;
    uint32_t sequenceBroadcast = 0;
    int up = 0;
    int left = 0;
    int stopping = 0;
    int running = 1;
    int done = 0;
    int result = 0;

    Hearing_Init(&s_hearing, 0);

    if (!parseArguments(argc, argv, &options))
        return usage();

    if (!options.tx || !options.allowTx)
    {
        printf("zb_mesh transmits, so it needs --tx and --allow-tx (docs/internals/hardware.md §8)\n");
        return 2;
    }

    setvbuf(stdout, 0, _IOLBF, 0);

    if (!openStick(&options))
    {
        printf("the stick did not come up\n");
        return 1;
    }

    s_hearing.backend = RcpRadio_Seam(&s_stick);
    fillConfig(&options, &cfg);

    if (Zb_StackStart(&s_stack, &cfg) != ZB_OK)
    {
        printf("did not start\n");
        closeStick();
        return 1;
    }

    signal(SIGINT, onSignal);
    signal(SIGTERM, onSignal);
    start = time(0);
    stopAt = start + options.seconds;
    nextStats = start + STATS_S;
    printf("start role=%s path=%s ignored=%u\n", options.role, options.path, (unsigned)s_hearing.ignoredCount);

    while (!done)
    {
        uint32_t nowMs = 0;
        time_t now = time(0);
        long t = (long)(now - start);

        nowMs = Port_NowMs();

        if (s_lastPumpMs != 0)
            timingAdd(&s_turns, nowMs - s_lastPumpMs);

        s_lastPumpMs = nowMs;
        (void)RcpRadio_Pump(&s_stick, nowMs);
        timingWatch(nowMs);
        Zb_StackTurn(&s_stack, nowMs);
        timingWatch(nowMs);

        if (running != (RcpRadio_Mode(&s_stick) == RCP_RADIO_MODE_RUNNING))
        {
            running = !running;
            printf("stick %s t=%ld\n", running ? "back" : "lost", t);
        }

        while (Zb_StackPollEvent(&s_stack, &event))
        {
            switch (event.type)
            {
            case ZB_EVENT_NETWORK_UP:
                s_self = event.network.networkAddress;
                up = 1;
                upAt = now;
                nextBroadcast = upAt + options.trafficAt;
                nextGhost = upAt + options.trafficAt + 7;
                printf("up t=%ld self=0x%04x pan=%04x epid=%016llx ieee=%016llx\n", t, s_self, event.network.panId,
                       (unsigned long long)event.network.extendedPanId, (unsigned long long)event.network.ieee);
                break;

            case ZB_EVENT_NETWORK_FAILED:
                printf("failed t=%ld status=%d\n", t, (int)event.status);
                result = 1;
                (void)Zb_StackStop(&s_stack);
                stopping = 1;
                break;

            case ZB_EVENT_DEVICE_JOINED:
                printf("joined t=%ld 0x%04x %016llx\n", t, event.joined.networkAddress, (unsigned long long)event.joined.ieee);

                if (options.lockstep)
                    (void)rxOf(event.joined.networkAddress);

                break;

            case ZB_EVENT_DATA:
                onData(&event.data);
                break;

            case ZB_EVENT_SENT:
                onSent(&event.sent, event.status, t);

                if (options.lockstep && event.sent.tag == TAG_UNI)
                    clock_gettime(CLOCK_MONOTONIC, &lastUni);

                break;

            case ZB_EVENT_STOPPED:
                done = 1;
                break;

            default:
                break;
            }
        }

        if (up && !stopping && !left && now >= upAt + options.trafficAt)
        {
            struct timespec ts;

            clock_gettime(CLOCK_MONOTONIC, &ts);

            if (options.uniMs != 0 && !(options.lockstep && s_unicastOut)
                && (ts.tv_sec - lastUni.tv_sec) * 1000 + (ts.tv_nsec - lastUni.tv_nsec) / 1000000 >= (long)options.uniMs)
            {
                uint16_t destination = options.toAll ? nextPeer() : nextNeighbour();

                lastUni = ts;

                if (destination != 0xffff)
                {
                    compose(sequenceUni++, 'U');
                    s_unicastOut = send(destination, TAG_UNI, APS_TX_OPTION_ACK, txOf(destination));
                }
            }

            if (options.broadcastS != 0 && now >= nextBroadcast)
            {
                nextBroadcast = now + options.broadcastS;
                compose(sequenceBroadcast++, 'B');
                send(MESH_ALL_ROUTERS, TAG_BROADCAST, 0, &s_broadcast);
            }

            if (options.ghostS != 0 && now >= nextGhost)
            {
                nextGhost = now + options.ghostS;
                compose(0, 'G');
                send(MESH_GHOST, TAG_GHOST, APS_TX_OPTION_ACK, &s_ghost);
            }
        }

        if (up && !stopping && options.forgetAt != 0 && now >= start + options.forgetAt)
        {
            printf("forgot t=%ld children=%u\n", t, (unsigned)forgetChildren());
            options.forgetAt = 0;
        }

        if (up && !stopping && !left && options.leaveAt != 0 && now >= start + options.leaveAt)
        {
            printf("leave t=%ld status=%d\n", t, (int)Zb_CoreLeave(Zb_StackCore(&s_stack), 0, nowMs));
            left = 1;
        }

        if (!stopping && up && now >= nextStats)
        {
            printCounters(t);
            nextStats += STATS_S;
        }

        if (!stopping && (s_signal || now >= stopAt))
        {
            if (up)
            {
                printCounters(t);
                printFinal();
            }

            (void)Zb_StackStop(&s_stack);
            stopping = 1;
        }

        if (!done)
            (void)Port_Wait(&s_stick.port, WAIT_MS);
    }

    closeStick();
    printf("end\n");

    return result;
}
