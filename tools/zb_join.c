#define _POSIX_C_SOURCE 200809    /* nanosleep is POSIX; glibc hides it under -std=c99 without this, before any include */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aps.h"
#include "zb_core.h"
#include "device_map.h"
#include "protect.h"
#include "mac.h"
#include "nwk.h"
#include "port.h"
#include "port_posix.h"
#include "props.h"
#include "radio.h"
#include "rcp_radio.h"
#include "zb_time.h"
#include "zb_utils.h"
#include "zb_layers.h"

/*
 * The join on two sticks. One runs the parent's half (7.3.1's beacon, 10.21.5.2's answer, 3.6.1.8's address);
 * the other scans with 7.5.2's request, adds the parent it heard to Table 3-74, calls 3.2.2.13's NLME-JOIN.request
 * and reports 3.2.2.15's confirm, then proves the join with one APS unicast to the coordinator.
 *
 * Two modes and only two, and no port is ever defaulted (docs/internals/hardware.md §8): `--parent` and `--join` name the
 * role, `--path`/`--device` the RCP. A run that opened a port ends with a reset, because armed state survives
 * the hang-up. Both modes transmit, so both need `--tx --allow-tx`, and refuse a channel or PAN given with
 * `--protect-channel` or `--protect-pan`.
 */

#define BRINGUP_TIMEOUT_MS 6000
#define FLUSH_PUMPS_MAX 400
#define END_PUMPS 3
#define PUMP_PAUSE_MS 2
#define STEP_MS 5
#define BEACON_WAIT_MS 3000
#define BEACON_TRIES 4
#define JOIN_TRIES 3
#define JOIN_WAIT_MS 6000
#define DATA_WAIT_MS 3000
#define LEDGER_MS 1000

#define CHANNEL_DEFAULT 12

#define PAN_INERT 0xbeef

/* The extended PAN identifier both sides carry: a value the parent states in its beacon and the child copies out of
   it, so the two cannot disagree about it (Table 3-83, Table 3-74). */
#define EXTENDED_PAN_DEFAULT 0x000000000000beef

#define PARENT_SHORT 0x0000
#define UNASSOCIATED 0xffff

/* The address a `--zdo-ask` run sends from, and the two endpoints a `--zdo-serve` run registers: a ZDO exchange
   needs a device that advertises something, and this is what an application would register. */
#define BENCH_ASKER_SHORT 0x0042
#define BENCH_EP_FIRST 0x01
#define BENCH_EP_SECOND 0x02
#define BENCH_APP_PROFILE 0x0104      /* the profile an application endpoint advertises, not the device profile */
#define BENCH_DEVICE_ID 0x0100
#define BENCH_MANUFACTURER_CODE 0x1037
#define BEACON_REQUEST 0x07

#define STACK_PROFILE 0x02
#define PROTOCOL_VERSION 0x02
#define UPDATE_ID 0

#define SEQ_START 0x11
#define DSN_START 0x21
#define JITTER_SEED 0
#define JOIN_SEED 0
#define SRC_ENDPOINT 0x01
#define DST_ENDPOINT 0x02
#define PROFILE_ID 0x0104
#define CLUSTER_ID 0x0006
#define APS_TX_ACK 0x04

/* Table 4-3's KeySeqNumber the tool's one test network key carries, and the octet count of Table 4-9's key material */
#define KEY_SEQ_NUMBER 0x00
#define KEY_OCTETS 16
#define KEY_HEX_OCTETS (KEY_OCTETS * 2)

/* How long the parent lets the association exchange finish before it sends the key (4.6.3.2.1's trust centre) */
#define KEY_SETTLE_MS 400

#define PRESENT_FULL (RADIO_PIB_CHANNEL | RADIO_PIB_PAGE | RADIO_PIB_PAN_ID | RADIO_PIB_SHORT_ADDRESS \
                      | RADIO_PIB_EXTENDED_ADDRESS | RADIO_PIB_RX_ON_WHEN_IDLE)

#define ASDU_MAX 48

static const uint8_t s_asduDefault[6] =
{
    0x66, 0x72, 0x61, 0x6d, 0x65, 0x64
};

/* The tool's own test key material, named here and nowhere else: a network key this PAN is configured with and the
   trust centre link key every device on it shares, both readable on purpose so a capture can be read against them. */
static const uint8_t s_networkKeyDefault[SECURITY_KEY_OCTETS] =
{
    0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x30, 0x39
};

static const uint8_t s_linkKeyDefault[SECURITY_KEY_OCTETS] =
{
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
};

/* The run the command line describes: the role, the private PAN, and the stick. */
typedef struct JoinRun
{
    int isParent;
    uint64_t ownIeee;
    int permit;

    /* The key material a run is configured with: `--transport-key` makes the parent hold the network key and a
       link key pair for the child it is about to transport it to, `--no-key` makes the child state the level and
       hold nothing, which is 4.6.3.2.4's device waiting for one. */
    int transportKey;
    int noKey;
    uint64_t childIeee;
    uint8_t networkKey[SECURITY_KEY_OCTETS];
    uint8_t linkKey[SECURITY_KEY_OCTETS];
    int asRouter;
    int commission;                 /* the child attaches by 3.4.14's Network Commissioning whatever the beacon says */
    int associate;                  /* the child attaches by 10.21.2's association whatever the beacon says */
    int zdoServe;
    int zdoAskSet;
    uint32_t zdoAsk;
    int groupSend;
    int groupListen;
    uint32_t groupId;
    uint32_t groupMode;             /* APS_GROUP_DELIVERY_*, which arm a group frame with no member takes */
    uint32_t zdoPeer;               /* the asker's address, seeded on the serving side */                /* the address a `--zdo-ask` run asks, 0 when the run serves instead */
    uint32_t channel;
    uint32_t panId;
    uint64_t extendedPanId;
    uint64_t parentIeee;
    uint32_t seconds;
    uint32_t timeoutMs;
    uint32_t baud;
    uint32_t rxRing;
    uint32_t txRing;
    const char *path;
    uint8_t asdu[ASDU_MAX];
    uint32_t asduLen;
} JoinRun;

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

    if (status == ZB_ERR_NOT_FOUND)
        return "not-found";

    if (status == ZB_ERR_BAD_STATE)
        return "bad-state";

    if (status == ZB_ERR_NO_SPACE)
        return "no-space";

    if (status == ZB_ERR_BUSY)
        return "busy";

    if (status == ZB_ERR_NO_ROUTE)
        return "no-route";

    if (status == ZB_ERR_NO_ACK)
        return "no-ack";

    if (status == ZB_ERR_CHANNEL_ACCESS_FAILURE)
        return "channel-access-failure";

    if (status == ZB_ERR_DEVICE)
        return "device";

    if (status == ZB_ERR_DEVICE_LOST)
        return "device-lost";

    return "other";
}

static const char *modeName(Rcp_RadioMode mode)
{
    if (mode == RCP_RADIO_MODE_RUNNING)
        return "running";

    if (mode == RCP_RADIO_MODE_RESET)
        return "reset";

    if (mode == RCP_RADIO_MODE_DISCOVER)
        return "discover";

    if (mode == RCP_RADIO_MODE_ARM)
        return "arm";

    if (mode == RCP_RADIO_MODE_FAULT)
        return "fault";

    return "closed";
}

/* The eight octets a Table 3-74 or Table 3-21 row carries, least significant octet first, the order Table 3-83's
   beacon writes the extended PAN identifier in. */
static void extendedPanOctets(uint64_t value, uint8_t *out)
{
    uint32_t index;

    for (index = 0; index < RADIO_ADDR_LEN; index++)
        out[index] = (uint8_t)(value >> (index * 8));
}

static uint64_t extendedValueOf(const uint8_t *octets)
{
    uint64_t value = 0;
    uint32_t index;

    for (index = 0; index < RADIO_ADDR_LEN; index++)
        value = value | ((uint64_t)octets[index] << (index * 8));

    return value;
}

/* The same eight octets the seam's extended address takes: least significant octet first. */
static void extendedOctetsOf(uint64_t value, uint8_t *out)
{
    uint32_t index;

    for (index = 0; index < RADIO_ADDR_LEN; index++)
        out[index] = (uint8_t)(value >> (index * 8));
}

static void endSession(Rcp_Radio *radio)
{
    uint32_t pump;

    RcpRadio_Restart(radio, Port_NowMs());

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

/* The bring-up docs/internals/protocol.md §6 records: the channel first, because the arm sequence writes it from the PIB,
   then a pump loop until the backend says it is running. */
static int bringUp(Rcp_Radio *radio, const JoinRun *run)
{
    Radio_Frame frames[RADIO_FRAME_BATCH_MAX];
    const Radio_Radio *seam;
    PortConfig portCfg;
    Radio_Pib pib;
    uint32_t startMs;
    uint32_t deadline;
    uint32_t pumps = 0;
    uint32_t taken;

    portCfg.baud = run->baud;
    portCfg.rxRingSize = run->rxRing;
    portCfg.txRingSize = run->txRing;
    portCfg.exclusive = 1;

    if (RcpRadio_Init(radio, PortPosixOps(), run->timeoutMs) != ZB_OK)
    {
        printf("backend    the backend would not initialise\n");
        return 0;
    }

    if (RcpRadio_Open(radio, run->path, &portCfg) != ZB_OK)
    {
        printf("%s: could not open the link (platform error %u). No port was opened, so no reset is owed\n",
               run->path, Port_PlatformErrno(&radio->port));
        return 0;
    }

    seam = RcpRadio_Seam(radio);

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_CHANNEL;
    pib.channel = run->channel;

    if (seam->ops->pibSet((Radio_Radio *)seam, &pib) != ZB_OK)
    {
        printf("armed      the channel was refused\n");
        endSession(radio);
        return 0;
    }

    startMs = Port_NowMs();
    deadline = startMs + BRINGUP_TIMEOUT_MS;

    while (RcpRadio_Mode(radio) != RCP_RADIO_MODE_RUNNING && !Zb_timeReached(Port_NowMs(), deadline))
    {
        if (RcpRadio_Pump(radio, Port_NowMs()) != ZB_OK)
            break;

        pumps++;
        taken = seam->ops->rxPoll((Radio_Radio *)seam, frames, RADIO_FRAME_BATCH_MAX);
        (void)taken;

        if (RcpRadio_RxQueued(radio) == 0 && RcpRadio_Mode(radio) != RCP_RADIO_MODE_RUNNING)
            pauseHost();
    }

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    (void)seam->ops->pibGet((Radio_Radio *)seam, &pib);

    printf("bring-up   %s in %u pumps over %u ms, last error %d; the radio reports channel %u, pan 0x%04x, short 0x%04x\n",
           modeName(RcpRadio_Mode(radio)), pumps, Port_NowMs() - startMs, RcpRadio_LastError(radio), pib.channel,
           pib.panId, pib.shortAddress);

    if (RcpRadio_Mode(radio) != RCP_RADIO_MODE_RUNNING)
    {
        printf("armed      not armed: %s (last error %d)\n", modeName(RcpRadio_Mode(radio)),
               RcpRadio_LastError(radio));
        endSession(radio);
        return 0;
    }

    return 1;
}

/* The stack this run drives: the identity the device reported, the role the mode named, and no security, because
   the join this tool exercises is 3.6.1.6.1.1's unsecured one (the keyed join is the next milestone). */
/* The key material a run names, kept alive across the init call the config points into. `Security_Init` copies the
   descriptors by value, so this only has to outlive that call. */
typedef struct BenchSecurity
{
    Security_Config cfg;
    Security_KeyDescriptor keys[1];
    Security_KeyPairEntry pairs[1];
} BenchSecurity;

/* What the application tells the stack about the device: one builder for both façades, so a run of either states
   the same identity. */
static ZbStatus stackConfigOf(Rcp_Radio *radio, const JoinRun *run, Zb_LayersConfig *cfg, BenchSecurity *sec,
                              uint64_t *outOwnIeee)
{
    const Radio_Radio *seam = RcpRadio_Seam(radio);
    Radio_Pib pib;
    uint64_t factory = 0;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    Zb_memset(cfg, 0, (uint32_t)sizeof *cfg);
    Zb_memset(sec, 0, (uint32_t)sizeof *sec);

    if (seam->ops->pibGet((Radio_Radio *)seam, &pib) == ZB_OK)
        factory = extendedValueOf(pib.hwAddress);

    /* An address the run names wins over the device's: early sticks report one that is not theirs yet. */
    if (run->ownIeee != 0)
        factory = run->ownIeee;

    if (factory == 0)
    {
        printf("identity   this device reported no factory address, and a join names one\n");
        return ZB_ERR_NO_DEVICE;
    }

    cfg->present = PRESENT_FULL;
    cfg->channel = run->channel;
    cfg->page = 0;
    cfg->panId = (uint16_t)run->panId;
    cfg->shortAddress = run->isParent ? PARENT_SHORT : ((run->zdoAskSet || run->groupSend) ? BENCH_ASKER_SHORT : UNASSOCIATED);
    extendedOctetsOf(factory, cfg->extendedAddress);
    extendedPanOctets(run->extendedPanId, cfg->extendedPanId);
    cfg->rxOnWhenIdle = 1;
    cfg->deviceType = run->isParent ? NWK_DEVICE_COORDINATOR
                                    : (run->asRouter ? NWK_DEVICE_ROUTER : NWK_DEVICE_END_DEVICE);
    cfg->seqStart = SEQ_START;
    cfg->jitterSeed = JITTER_SEED;
    cfg->joinSeed = JOIN_SEED;
    cfg->dsnStart = DSN_START;

    *outOwnIeee = factory;

    if (run->transportKey || run->noKey)
    {
        sec->cfg.ownIeee = factory;
        sec->cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
        sec->cfg.authenticated = run->transportKey ? 1 : 0;

        sec->pairs[0].deviceIeee = run->transportKey ? run->childIeee : run->parentIeee;
        sec->pairs[0].keyAttributes = SECURITY_KEYPAIR_ATTR_VERIFIED;
        sec->pairs[0].linkKeyType = SECURITY_LINK_KEY_UNIQUE;
        sec->pairs[0].verifiedFrameCounter = 1;
        sec->pairs[0].outgoingFrameCounter = 1;
        Zb_memcpy(sec->pairs[0].key, run->linkKey, SECURITY_KEY_OCTETS);

        sec->cfg.keyPairs = sec->pairs;
        sec->cfg.keyPairCount = sec->pairs[0].deviceIeee != 0 ? 1 : 0;

        if (run->transportKey)
        {
            sec->keys[0].keySeqNumber = KEY_SEQ_NUMBER;
            sec->keys[0].inUse = 1;
            Zb_memcpy(sec->keys[0].key, run->networkKey, SECURITY_KEY_OCTETS);

            sec->cfg.keys = sec->keys;
            sec->cfg.keyCount = 1;
            sec->cfg.nwkActiveKeySeqNumber = KEY_SEQ_NUMBER;
            sec->cfg.trustCenterIeee = factory;
        }
        else
            sec->cfg.trustCenterIeee = run->parentIeee != 0 ? run->parentIeee : NWK_TRUST_CENTER_NONE;

        cfg->nwkSecurityLevel = sec->cfg.nwkSecurityLevel;
        cfg->security = &sec->cfg;
        cfg->trustCenterIeee = sec->cfg.trustCenterIeee;
    }

    return ZB_OK;
}

static ZbStatus initStack(Zb_Layers *stack, Rcp_Radio *radio, const JoinRun *run, uint64_t *outOwnIeee)
{
    BenchSecurity sec;
    Zb_LayersConfig cfg;
    ZbStatus status;

    status = stackConfigOf(radio, run, &cfg, &sec, outOwnIeee);

    if (status != ZB_OK)
        return status;

    return Zb_LayersInit(stack, RcpRadio_Seam(radio), &cfg);
}

/* The device façade over the same config: what an application stands on, with the two descriptors it advertises
   about the device as a whole. */
static ZbStatus initDevice(Zb_Core *dev, Rcp_Radio *radio, const JoinRun *run, uint64_t *outOwnIeee)
{
    BenchSecurity sec;
    Zb_CoreConfig cfg;
    ZbStatus status;

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);

    status = stackConfigOf(radio, run, &cfg.layers, &sec, outOwnIeee);

    if (status != ZB_OK)
        return status;

    Zdo_NodeDescriptorDefaults(&cfg.node, run->isParent ? ZDO_LOGICAL_COORDINATOR : ZDO_LOGICAL_ROUTER,
                               BENCH_MANUFACTURER_CODE);
    Zdo_PowerDescriptorDefaults(&cfg.power);
    cfg.groupDelivery = run->groupMode;

    return Zb_CoreInit(dev, RcpRadio_Seam(radio), &cfg);
}

/* One turn: the link moves, then every layer above it runs on band C's clock. */
static int stepOnce(Rcp_Radio *radio, Zb_Layers *stack)
{
    uint32_t nowMs = Port_NowMs();

    if (RcpRadio_Pump(radio, nowMs) != ZB_OK)
        return 0;

    return Zb_LayersStep(stack, nowMs) == ZB_OK;
}

/* One turn of the beacon wait: the MAC runs first, so the Beacon Request's own confirm is read here and not
   drained unmatched by the network layer inside the stack's step. */
static int stepForConfirm(Rcp_Radio *radio, Zb_Layers *stack, Mac_DataConfirmParameters *confirm, uint32_t *got)
{
    uint32_t nowMs = Port_NowMs();

    if (RcpRadio_Pump(radio, nowMs) != ZB_OK)
        return 0;

    if (Mac_Step(Zb_LayersMac(stack), nowMs) != ZB_OK)
        return 0;

    *got = Mac_PollConfirms(Zb_LayersMac(stack), confirm, 1);

    return Zb_LayersStep(stack, nowMs) == ZB_OK;
}

/* Turns with nothing asked of them: the link and every layer above it move, which is what a caller owes a seam
   whose last request is still in flight before it asks the next one. */
static void settle(Rcp_Radio *radio, Zb_Layers *stack, uint32_t turns)
{
    uint32_t turn;

    for (turn = 0; turn < turns; turn++)
    {
        if (!stepOnce(radio, stack))
            return;

        pauseHost();
    }
}

/* 7.5.2's Beacon Request as the child sends it: a MAC command whose Content is Table 7-11's 0x07, the broadcast
   PAN and address, and no source fields at all (the clause's own shape). */
static ZbStatus sendBeaconRequest(Mac_Mac *mac, uint32_t nowMs)
{
    Mac_DataRequestParameters req;
    static const uint8_t content[1] = { BEACON_REQUEST };

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    req.frameType = MAC_FRAME_TYPE_COMMAND;
    req.destAddrMode = MAC_ADDR_SHORT;
    req.srcAddrMode = MAC_ADDR_NONE;
    req.destPan = MAC_FRAME_PAN_BROADCAST;
    req.destShort = MAC_FRAME_ADDR_BROADCAST;
    req.ackRequest = 0;
    req.payload = content;
    req.payloadLen = 1;

    return Mac_DataRequest(mac, &req, nowMs, 0);
}

static void printBeacon(const Mac_BeaconNotification *beacon)
{
    Nwk_BeaconInfo info;
    ZbStatus status;

    printf("beacon     sn %02x  coord ", beacon->sn);

    if (beacon->coordAddrMode == MAC_ADDR_SHORT)
        printf("0x%04x", beacon->coordShort);
    else
        printf("0x%016llx", (unsigned long long)beacon->coordExtended);

    printf("  pan 0x%04x  permit %d  pan-coordinator %d  pending %u short  payload %u octet(s)\n",
           beacon->coordPanId, beacon->associationPermit, beacon->panCoordinator,
           beacon->pendingShortCount + beacon->pendingExtendedCount, beacon->payloadLen);

    status = Nwk_ParseBeaconInfo(beacon->payload, beacon->payloadLen, &info);

    if (status == ZB_OK)
    {
        printf("           Table 3-83: stack profile %u protocol %u depth %u  extended pan 0x%016llx  permit %d, "
               "and the appendix %s\n", info.stackProfile, info.protocolVersion, info.deviceDepth,
               (unsigned long long)info.extendedPanId, beacon->associationPermit,
               beacon->payloadLen > NWK_BEACON_INFO_LEN ? "present" : "absent");
    }
    else
    {
        printf("           and the payload is not Table 3-83's fifteen octets (%s)\n", statusName(status));
    }
}

/* The parent's half: 3.6.5's on-demand beacon carrying Table 3-83's payload, and 10.21.5.2's answer composed by the
   layer above the MAC when a child asks (nwk_join.c drains the MAC's association ring and allocates 3.6.1.8's
   address). This run only states the beacon and prints what the layer above reports. */
static int runParent(Rcp_Radio *radio, Zb_Layers *stack, const JoinRun *run, uint32_t ownIeee)
{
    Nwk_JoinIndicationParameters indications[NWK_JOIN_INDICATION_MAX];
    Aps_Indication apsIndications[APS_INDICATION_MAX];
    Aps_TransportKeyReq keyReq;
    Nwk_BeaconInfo info;
    Mac_Counters macCounters;
    ZbStatus status;
    uint32_t deadline;
    uint32_t taken;
    uint32_t joins = 0;
    uint32_t keysSent = 0;
    uint32_t keyPendingAddress = 0;
    uint32_t keySeenMs = 0;
    int keyPending = 0;
    uint32_t i;
    int keyOwed = run->transportKey;

    (void)ownIeee;

    Zb_memset(&info, 0, (uint32_t)sizeof info);
    info.stackProfile = STACK_PROFILE;
    info.protocolVersion = PROTOCOL_VERSION;
    info.routerCapacity = 1;
    info.deviceDepth = 0;
    info.endDeviceCapacity = 1;
    info.extendedPanId = run->extendedPanId;
    info.txOffset = NWK_BEACON_TX_OFFSET_NONE;
    info.updateId = UPDATE_ID;

    status = Nwk_SetBeaconInfo(Zb_LayersNwk(stack), &info, run->permit);

    if (status != ZB_OK)
    {
        printf("parent     the beacon was refused: %s\n", statusName(status));
        return 1;
    }

    printf("parent     coordinator at 0x%04x in PAN 0x%04x, channel %u, extended PAN 0x%016llx\n", PARENT_SHORT,
           run->panId, run->channel, (unsigned long long)run->extendedPanId);
    printf("           beacon answered on demand (7.5.2, 3.6.5) with Table 3-83's info field and the Router "
           "Information Global TLV behind it (3.6.8.1), macAssociationPermit %d\n", run->permit);

    deadline = Port_NowMs() + run->seconds * 1000;

    while (!Zb_timeReached(Port_NowMs(), deadline))
    {
        if (!stepOnce(radio, stack))
        {
            printf("parent     the link went away (last error %d)\n", RcpRadio_LastError(radio));
            return 1;
        }

        taken = Nwk_PollJoinIndications(Zb_LayersNwk(stack), indications, NWK_JOIN_INDICATION_MAX);

        for (i = 0; i < taken; i++)
        {
            joins++;

            printf("join ind   child 0x%04x  ieee %016llx  capability %s %s  method %u\n",
                   indications[i].networkAddress, (unsigned long long)indications[i].extendedAddress,
                   indications[i].capability.deviceType ? "router" : "end device",
                   indications[i].capability.rxOnWhenIdle ? "receiver-on" : "sleepy",
                   indications[i].joinerMethod);

            if (keyOwed && indications[i].extendedAddress == run->childIeee)
            {
                keyPending = 1;
                keyPendingAddress = indications[i].networkAddress;
                keySeenMs = Port_NowMs();
            }
        }

        /* The key is sent on a later turn, not inside the turn that answered the association: the exchange the join
           just ran still owns the MAC's session then, and a trust centre sends after it. */
        if (keyPending && !Zb_timeReached(Port_NowMs(), keySeenMs + KEY_SETTLE_MS))
        {
            pauseHost();
            continue;
        }

        if (keyPending)
        {
            Zb_memset(&keyReq, 0, (uint32_t)sizeof keyReq);

            keyReq.destIeee = run->childIeee;
            keyReq.nwkDst = keyPendingAddress;
            keyReq.standardKeyType = APS_TK_TYPE_NETWORK_KEY;
            keyReq.keySeqNumber = KEY_SEQ_NUMBER;
            keyReq.destinationIeee = run->childIeee;
            Zb_memcpy(keyReq.key, run->networkKey, SECURITY_KEY_OCTETS);

            status = Aps_TransportKeyRequest(Zb_LayersAps(stack), &keyReq, Port_NowMs());

            keyPending = 0;

            if (status == ZB_OK)
            {
                keysSent++;
                keyOwed = 0;

                printf("key        Transport Key to 0x%04x (%016llx): 4.4.2.1.3's network key, sequence %u, "
                       "protected with the key-transport key of the pair's link key (4.4.1.1 step 1 b ii)\n",
                       keyPendingAddress, (unsigned long long)run->childIeee, (unsigned)KEY_SEQ_NUMBER);
            }
            else
                printf("key        the Transport Key was refused: %s\n", statusName(status));
        }

        taken = Aps_PollIndications(Zb_LayersAps(stack), apsIndications, APS_INDICATION_MAX);

        for (i = 0; i < taken; i++)
        {
            printf("aps ind    from 0x%04x endpoint %02x to endpoint %02x, cluster 0x%04x profile 0x%04x, "
                   "%u octet(s)\n", apsIndications[i].srcAddress, apsIndications[i].srcEndpoint,
                   apsIndications[i].dstEndpoint, apsIndications[i].clusterId, apsIndications[i].profileId,
                   apsIndications[i].asduLength);
        }

        pauseHost();
    }

    macCounters = Mac_CountersOf(Zb_LayersMac(stack));

    printf("parent     %u Transport Key(s) sent, %u answered, %u failed, %u refusal(s) at the aps door\n", keysSent,
           Aps_CommandAnswers(Zb_LayersAps(stack)), Aps_CommandFailures(Zb_LayersAps(stack)),
           Aps_RefusedRequests(Zb_LayersAps(stack)));
    printf("parent     %u join indication(s), %u command(s) heard, %u transaction(s) still held, "
           "%u poll(s) unanswered, %u association(s) dropped\n", joins, macCounters.commandsHeard,
           macCounters.transactionQueue, macCounters.pollsUnanswered, macCounters.associationsDropped);
    printf("parent     join answers dropped %u, timeout responses sent %u, commissioning joins %u, held frames "
           "dropped %u\n", Nwk_JoinResponsesDropped(Zb_LayersNwk(stack)), Nwk_TimeoutResponsesSent(Zb_LayersNwk(stack)),
           Zb_LayersNwk(stack)->commissioningJoins, Nwk_JoinSendsDropped(Zb_LayersNwk(stack)));
    printf("parent     receive: pan-mismatch %u dest-mismatch %u src-pan-mismatch %u malformed %u "
           "reserved-type %u reserved-version %u fcs-failure %u unbuilt %u promiscuous-delivered %u "
           "beacon-request %u\n", macCounters.panMismatches, macCounters.destinationMismatches,
           macCounters.sourcePanMismatches, macCounters.malformedFrames, macCounters.reservedTypeFrames,
           macCounters.reservedVersionFrames, macCounters.fcsFailures, macCounters.unbuiltForms,
           macCounters.promiscuousDelivered, macCounters.beaconRequestsHeard);
    printf("parent     beacons: refused %u, ignored %u\n", macCounters.beaconRefused,
           macCounters.beaconIgnored);
    printf("parent     routing table %u, discovery table %u, aps indications held %u\n",
           Nwk_RouteQueue(Zb_LayersNwk(stack)), Nwk_DiscoveryQueue(Zb_LayersNwk(stack)),
           Aps_IndicationQueue(Zb_LayersAps(stack)));
    printf("parent     nwk receive: unsecured %u not-for-me %u no-route %u bad-source %u malformed %u "
           "indications %u refused %u\n", Nwk_DroppedUnsecured(Zb_LayersNwk(stack)),
           Nwk_DroppedNotForMe(Zb_LayersNwk(stack)), Nwk_DroppedNoRoute(Zb_LayersNwk(stack)),
           Nwk_DroppedBadSource(Zb_LayersNwk(stack)), Nwk_DroppedMalformed(Zb_LayersNwk(stack)),
           Nwk_IndicationQueue(Zb_LayersNwk(stack)), Nwk_RefusedRequests(Zb_LayersNwk(stack)));
    printf("parent     link status sent %u applied %u, backbone promotions %u, neighbour rank %u\n",
           Nwk_LinkStatusSent(Zb_LayersNwk(stack)), Nwk_LinkStatusApplied(Zb_LayersNwk(stack)),
           Nwk_BackbonePromotions(Zb_LayersNwk(stack)), Nwk_NeighborRankOf(Zb_LayersNwk(stack), 0x0000));
    printf("parent     nwk tx queue %u refused %u neighbour table %u, aps confirmations held %u ignored %u\n",
           Nwk_TransmitQueue(Zb_LayersNwk(stack)), Nwk_RefusedRequests(Zb_LayersNwk(stack)),
           Nwk_NeighborQueue(Zb_LayersNwk(stack)),
           Aps_ConfirmQueue(Zb_LayersAps(stack)), Aps_ConfirmationsIgnored(Zb_LayersAps(stack)));
    printf("parent     mac outstanding %u refused %u confirm queue %u indications queued %u\n",
           macCounters.outstanding, macCounters.refusedRequests, macCounters.confirmQueue,
           macCounters.indicationQueue);
    printf("parent     aps acknowledgements composed %u, refused %u, duplicates rejected %u\n",
           Aps_AcksGenerated(Zb_LayersAps(stack)), Aps_AcksRefused(Zb_LayersAps(stack)),
           Aps_RxDuplicateDrops(Zb_LayersAps(stack)));

    return joins != 0 ? 0 : 1;
}

/* The child's half: 7.5.2's request, the beacon it hears, Table 3-74's entry, 3.2.2.13's request and 3.2.2.15's
   confirm, then one APS unicast to the coordinator the join named. */
/* One turn of the device façade: the link moves, then the device's own turn, which is the stack's and then the one
   read of the APS ring. */
static int stepDevice(Rcp_Radio *radio, Zb_Core *dev)
{
    uint32_t nowMs = Port_NowMs();

    if (RcpRadio_Pump(radio, nowMs) != ZB_OK)
        return 0;

    return Zb_CoreStep(dev, nowMs) == ZB_OK;
}

static void deviceSettle(Rcp_Radio *radio, Zb_Core *dev, uint32_t turns)
{
    uint32_t turn;

    for (turn = 0; turn < turns; turn++)
    {
        if (!stepDevice(radio, dev))
            return;

        pauseHost();
    }
}

/* The two endpoints an application would register: 2.3.2.5's descriptor, one cluster in each list. */
static void zdoRegisterEndpoints(Zb_Core *dev)
{
    Af_SimpleDescriptor descriptor;
    uint32_t endpoint;

    for (endpoint = BENCH_EP_FIRST; endpoint <= BENCH_EP_SECOND; endpoint++)
    {
        Zb_memset(&descriptor, 0, (uint32_t)sizeof descriptor);

        descriptor.endpoint = (uint8_t)endpoint;
        descriptor.profileId = BENCH_APP_PROFILE;
        descriptor.deviceId = (uint16_t)(BENCH_DEVICE_ID + endpoint);
        descriptor.deviceVersion = 1;
        descriptor.inputClusterCount = 1;
        descriptor.inputClusters[0] = 0x0006;
        descriptor.outputClusterCount = 1;
        descriptor.outputClusters[0] = 0x0008;

        if (Zb_CoreRegisterEndpoint(dev, &descriptor) != ZB_OK)
            printf("zdo        endpoint 0x%02x was refused\n", endpoint);
    }
}

/* A unicast needs a next hop and only an association or a received frame puts one in the neighbour table, so a run
   that isolates the ZDO exchange from the join states the asker's entry by hand: it is what the association would
   have left there. */
static void zdoSeedPeer(Nwk_Nwk *nwk, uint32_t address)
{
    Nwk_NeighborTableEntry *entry = Nwk_NeighborFree(nwk->neighbors);

    if (entry == 0)
    {
        printf("zdo        the neighbour table has no room for 0x%04x\n", address);
        return;
    }

    entry->inUse = 1;
    entry->networkAddress = (uint16_t)address;
    entry->ieeeKnown = 0;
    entry->deviceType = NWK_DEVICE_END_DEVICE;
    entry->rxOnWhenIdle = 1;
    entry->relationship = NWK_REL_CHILD;
}

/* `--zdo-serve`: the device object answers from the registry, and the counters say what it consumed, what it
   answered and what the application's ring received. */
static int runZdoServe(Rcp_Radio *radio, Zb_Core *dev, const JoinRun *run)
{
    Nwk_BeaconInfo info;
    uint32_t second;
    uint32_t turn;
    uint32_t turnsPerSecond = 1000 / (PUMP_PAUSE_MS + 1);
    ZbStatus status;

    Zb_memset(&info, 0, (uint32_t)sizeof info);

    info.stackProfile = STACK_PROFILE;
    info.protocolVersion = PROTOCOL_VERSION;
    info.routerCapacity = 1;
    info.deviceDepth = 0;
    info.endDeviceCapacity = 1;
    info.extendedPanId = run->extendedPanId;
    info.txOffset = NWK_BEACON_TX_OFFSET_NONE;
    info.updateId = UPDATE_ID;

    status = Nwk_SetBeaconInfo(Zb_CoreNwk(dev), &info, run->permit);

    if (status != ZB_OK)
    {
        printf("zdo        the beacon was refused: %s\n", statusName(status));
        return 1;
    }

    zdoRegisterEndpoints(dev);

    if (run->zdoPeer != 0)
        zdoSeedPeer(Zb_CoreNwk(dev), run->zdoPeer);

    printf("zdo        serving at 0x%04x in PAN 0x%04x, channel %u, %u endpoints registered, permit %u\n",
           PARENT_SHORT, run->panId, run->channel, Zb_CoreEndpointCount(dev), run->permit);

    for (second = 0; second < run->seconds; second++)
    {
        for (turn = 0; turn < turnsPerSecond; turn++)
            deviceSettle(radio, dev, 1);

        printf("zdo        %2u s  zdp consumed %u  answers %u refused %u  republished %u  dropped %u  "
               "unsupported %u refused-frame %u  heard %u  aps refused %u  routes %u  last zdp %04x profile %04x "
               "ep %02x  edinit %u  acks %u/%u  noRoute %u\n",
               second + 1, Zb_CoreZdpFramesConsumed(dev), Zdo_ResponsesSent(&dev->zdo),
               Zdo_ResponsesRefused(&dev->zdo), Zb_CoreAnnouncementsRepublished(dev),
               Zb_CoreIndicationsDropped(dev), Zdo_CommandsUnsupported(&dev->zdo), Zdo_FramesRefused(&dev->zdo),
               Zdo_AnnouncementsHeard(&dev->zdo), Aps_RefusedRequests(Zb_CoreAps(dev)),
               Nwk_RouteQueue(Zb_CoreNwk(dev)),
               Zb_CoreLastZdpCluster(dev), Zb_CoreLastZdpProfile(dev), Zb_CoreLastZdpEndpoint(dev),
               Nwk_DroppedEndDeviceInitiator(Zb_CoreNwk(dev)), Aps_AcksGenerated(Zb_CoreAps(dev)),
               Aps_AcksRefused(Zb_CoreAps(dev)), Nwk_DroppedNoRoute(Zb_CoreNwk(dev)));
    }

    return 0;
}

/* One ZDP request, its answer taken out of the application's ring and read by the codec that owns the shape. */
static int zdoAskOnce(Rcp_Radio *radio, Zb_Core *dev, uint32_t destination, uint16_t cluster,
                      const uint8_t *asdu, uint32_t asduLength, uint8_t *answer, uint32_t answerCap,
                      uint32_t *answerLength, uint32_t waitMs)
{
    Aps_ApsdeReq request;
    Aps_Indication indication;
    uint32_t waited;

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.dstAddrMode = APS_ADDR_MODE_SHORT;
    request.dstAddress = (uint16_t)destination;
    request.dstEndpoint = ZDO_ENDPOINT;
    request.profileId = ZDO_PROFILE_ID;
    request.clusterId = cluster;
    request.srcEndpoint = ZDO_ENDPOINT;
    request.asdu = asdu;
    request.asduLength = asduLength;
    request.txOptions = AF_TX_ACKNOWLEDGED;

    if (Zb_CoreSendRequest(dev, &request, Port_NowMs()) != ZB_OK)
        return 0;

    for (waited = 0; waited < waitMs; waited++)
    {
        deviceSettle(radio, dev, 1);

        while (Zb_CorePollIndications(dev, &indication, 1) == 1)
        {
            if (indication.clusterId != (uint16_t)(cluster | ZDO_RESPONSE_BIT))
                continue;

            *answerLength = indication.asduLength > answerCap ? answerCap : indication.asduLength;
            Zb_memcpy(answer, indication.asdu, *answerLength);

            return 1;
        }
    }

    return 0;
}

/* `--zdo-ask`: the application asks another device's ZDO through the one send door, and reads the answer out of the
   ring the one poll owns. Three attempts two seconds apart, because the serving stick may still be arming. */
static int runZdoAsk(Rcp_Radio *radio, Zb_Core *dev, const JoinRun *run)
{
    Nwk_NeighborTableEntry *entry;
    Af_SimpleDescriptor descriptor;
    uint8_t asdu[4];
    uint8_t answer[ZDO_ASDU_MAX];
    uint32_t answerLength = 0;
    uint8_t endpoints[8];
    uint32_t count;
    uint32_t attempt;
    uint8_t tsn = 0x40;

    entry = Nwk_NeighborFree(Zb_CoreNwk(dev)->neighbors);

    if (entry != 0)
    {
        entry->inUse = 1;
        entry->networkAddress = (uint16_t)run->zdoAsk;
        entry->ieeeKnown = 0;
        entry->deviceType = NWK_DEVICE_ROUTER;
        entry->rxOnWhenIdle = 1;
        entry->relationship = NWK_REL_SIBLING;
    }

    zdoRegisterEndpoints(dev);

    printf("zdo        asking 0x%04x from 0x%04x in PAN 0x%04x, channel %u\n", run->zdoAsk, BENCH_ASKER_SHORT, run->panId,
           run->channel);

    asdu[0] = tsn++;
    asdu[1] = (uint8_t)(run->zdoAsk & 0xff);
    asdu[2] = (uint8_t)(run->zdoAsk >> 8);
    asdu[3] = BENCH_EP_FIRST;

    for (attempt = 0; attempt < 3 && answerLength == 0; attempt++)
    {
        if (!zdoAskOnce(radio, dev, run->zdoAsk, ZDO_SIMPLE_DESC_REQ, asdu, 4, answer, (uint32_t)sizeof answer,
                        &answerLength, 2000))
            continue;

        printf("simple     answered: tsn 0x%02x status 0x%02x\n", answer[0], answer[1]);

        if (Zdo_SimpleDescriptorParse(answer + 1, answerLength - 1, &descriptor) == ZB_OK)
            printf("simple     endpoint 0x%02x profile 0x%04x device 0x%04x version %u, clusters in %u out %u\n",
                   descriptor.endpoint, descriptor.profileId, descriptor.deviceId, descriptor.deviceVersion,
                   descriptor.inputClusterCount, descriptor.outputClusterCount);
    }

    if (answerLength == 0)
    {
        printf("simple     no answer in three attempts\n");
        return 1;
    }

    answerLength = 0;

    asdu[0] = tsn++;
    asdu[1] = (uint8_t)(run->zdoAsk & 0xff);
    asdu[2] = (uint8_t)(run->zdoAsk >> 8);

    if (zdoAskOnce(radio, dev, run->zdoAsk, ZDO_ACTIVE_EP_REQ, asdu, 3, answer, (uint32_t)sizeof answer,
                   &answerLength, 3000))
    {
        count = Zdo_ActiveEndpointsParse(answer + 1, answerLength - 1, endpoints, (uint32_t)sizeof endpoints);

        printf("active     answered: tsn 0x%02x status 0x%02x, %u endpoints", answer[0], answer[1], count);

        while (count-- > 0)
            printf(" 0x%02x", endpoints[count]);

        printf("\n");
    }
    else
        printf("active     no answer\n");

    printf("zdo        zdp consumed %u, dropped %u\n", Zb_CoreZdpFramesConsumed(dev),
           Zb_CoreIndicationsDropped(dev));

    return 0;
}

/* `--group-send`: 2.2.8.4.1's group transmission, which consults no membership, and the confirm it earns. */
static int runGroupSend(Rcp_Radio *radio, Zb_Core *dev, const JoinRun *run)
{
    Aps_ApsdeReq request;
    Aps_Confirm confirm;
    uint32_t turn;
    uint32_t confirms = 0;
    static const uint8_t asdu[4] = { 0x67, 0x72, 0x6f, 0x75 };

    zdoRegisterEndpoints(dev);

    printf("group      sending to 0x%04x from 0x%04x in PAN 0x%04x, channel %u, membership not consulted\n", run->groupId,
           Nwk_OwnAddress(Zb_CoreNwk(dev)), run->panId, run->channel);

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.dstAddrMode = APS_ADDR_MODE_GROUP;
    request.dstAddress = (uint16_t)run->groupId;
    request.profileId = BENCH_APP_PROFILE;
    request.clusterId = 0x0006;
    request.srcEndpoint = BENCH_EP_FIRST;
    request.asdu = asdu;
    request.asduLength = (uint32_t)sizeof asdu;

    /* The arm sequence's PIB writes are queued ahead of the first frame and the seam's write queue holds six, so a
       transmit asked for at once is refused for room. The run settles first, which is also
       when the join announcement goes out. */
    deviceSettle(radio, dev, 60);

    if (Zb_CoreSendRequest(dev, &request, Port_NowMs()) != ZB_OK)
    {
        printf("group      the request was refused at the door\n");
        return 1;
    }

    for (turn = 0; turn < run->seconds * 500; turn++)
    {
        if (!stepDevice(radio, dev))
            break;

        while (Zb_CorePollConfirms(dev, &confirm, 1) == 1)
        {
            if (confirm.dstAddrMode != APS_ADDR_MODE_GROUP || confirm.dstAddress != (uint16_t)run->groupId)
                continue;

            confirms++;
            printf("group      confirm %s (aps 0x%02x) for 0x%04x, mode 0x%02x, cluster 0x%04x, %u attempt(s)\n",
                   statusName(confirm.status), (unsigned)confirm.apsStatus, confirm.dstAddress,
                   (unsigned)confirm.dstAddrMode, confirm.clusterId, confirm.attempts);

            if (confirm.status != ZB_OK)
                printf("group      btt full %u, no route %u, relays %u, aps refused %u\n",
                       Nwk_BttFullDrops(Zb_CoreNwk(dev)), Nwk_DroppedNoRoute(Zb_CoreNwk(dev)),
                       Nwk_RelaysSent(Zb_CoreNwk(dev)), Aps_RefusedRequests(Zb_CoreAps(dev)));
        }

        if (confirms != 0)
            break;

        pauseHost();
    }

    if (confirms == 0)
        printf("group      no confirm in %u s\n", run->seconds);

    return confirms != 0 ? 0 : 1;
}

/* `--group-listen`: which arm a group frame takes here, and what the application is handed. */
static int runGroupListen(Rcp_Radio *radio, Zb_Core *dev, const JoinRun *run)
{
    Aps_Indication indications[APS_INDICATION_MAX];
    uint32_t second;
    uint32_t turn;
    uint32_t turnsPerSecond = 1000 / (PUMP_PAUSE_MS + 1);
    uint32_t heard = 0;
    uint32_t taken;
    uint32_t i;

    zdoRegisterEndpoints(dev);

    printf("group      listening for 0x%04x at 0x%04x in PAN 0x%04x, channel %u, delivery %s\n", run->groupId,
           Nwk_OwnAddress(Zb_CoreNwk(dev)), run->panId, run->channel,
           Aps_GroupDelivery(Zb_CoreAps(dev)) == APS_GROUP_DELIVERY_UNFILTERED ? "unfiltered" : "members only");

    for (second = 0; second < run->seconds; second++)
    {
        for (turn = 0; turn < turnsPerSecond; turn++)
            deviceSettle(radio, dev, 1);

        while ((taken = Zb_CorePollIndications(dev, indications, APS_INDICATION_MAX)) != 0)
        {
            for (i = 0; i < taken; i++)
            {
                if (indications[i].dstAddrMode != APS_ADDR_MODE_GROUP)
                    continue;

                heard++;
                printf("group      heard 0x%04x at endpoint 0x%02x, cluster 0x%04x, %u octets, status %u\n",
                       indications[i].dstAddress, indications[i].dstEndpoint, indications[i].clusterId,
                       indications[i].asduLength, indications[i].status);
            }
        }

        printf("group      %2u s  heard %u  member miss %u  unfiltered %u  aps queue %u\n", second + 1, heard,
               Aps_DroppedGroupMiss(Zb_CoreAps(dev)), Aps_GroupDeliveredUnfiltered(Zb_CoreAps(dev)),
               Aps_IndicationQueue(Zb_CoreAps(dev)));
    }

    return heard != 0 ? 0 : 1;
}

/* Who a failed join's status belongs to: Table 10-102's two refusals are the parent's answer, the rest this
   device's own MAC outcome (8.2.2's names). */
static const char *joinFailureName(uint32_t status)
{
    if (status == 0x01 || status == 0x02)
        return "the parent declined with Table 10-102's";

    if (status == 0xe1)
        return "the channel was busy, the request never sent: CHANNEL_ACCESS_FAILURE";

    if (status == 0xe9)
        return "the request was not acknowledged: NO_ACK";

    if (status == 0xeb)
        return "no answer was extracted in macResponseWaitTime: NO_DATA";

    if (status == 0xee)
        return "the transmit door never had room: TRANSACTION_OVERFLOW";

    return "the join failed with";
}

/* A failure of this device's own transmissions, which another join from the discovered network may not meet again;
   the parent's refusal is an answer, and asking again changes nothing. */
static int joinTryAgain(uint32_t status)
{
    return status == 0xe1 || status == 0xe9 || status == 0xeb || status == 0xee;
}

/* The attach mechanism the join used: the one the run forced, or 3.6.1.6.1.1's choice from the first entry's beacon */
static const char *joinMechanismName(const Nwk_Nwk *nwk, const JoinRun *run)
{
    if (run->commission)
        return "Network Commissioning (3.4.14), forced";

    if (run->associate)
        return "MAC association (10.21.2), forced";

    if (nwk->joinParents[0].inUse && nwk->joinParents[0].r23Appendix)
        return "Network Commissioning (3.4.14), the beacon's R23 appendix choosing it";

    return "MAC association (10.21.2), the beacon carrying no R23 appendix";
}

/* One NLME-JOIN.request and its confirm: 0 when the request is refused or no confirm comes */
static int joinOnce(Rcp_Radio *radio, Zb_Layers *stack, const JoinRun *run, const Nwk_JoinRequestParameters *req,
                    Nwk_JoinConfirmParameters *confirm)
{
    Nwk_Nwk *nwk = Zb_LayersNwk(stack);
    ZbStatus status;
    uint32_t deadline;
    uint32_t i;

    /* The MAC composes the association request itself, so the session beneath it has to be idle: the beacon request's
       completion is still on the link when the beacon arrives, and BUSY is the answer until it is collected. */
    settle(radio, stack, 30);

    status = ZB_ERR_BUSY;

    for (i = 0; i < 6 && status == ZB_ERR_BUSY; i++)
    {
        status = Nwk_JoinRequest(nwk, req, Port_NowMs());

        if (status == ZB_ERR_BUSY)
            settle(radio, stack, 10);
    }

    printf("join       NLME-JOIN.request: RejoinNetwork 0x00, channel %u, allocate-address 1, by %s  -> %s\n",
           run->channel, joinMechanismName(nwk, run), statusName(status));

    if (status != ZB_OK)
    {
        printf("join       refused before the exchange, and 3.2.2.15's confirm is the channel it would have used\n");
        return 0;
    }

    deadline = Port_NowMs() + JOIN_WAIT_MS;

    while (!Zb_timeReached(Port_NowMs(), deadline))
    {
        if (!stepOnce(radio, stack))
            break;

        /* Nothing here drains the MAC's confirms: the association exchange reads its own track inside the step
           (mac_assoc.c's MacAssoc_Progress), and a caller that drains it first takes the answer away from it. */
        if (Nwk_PollJoinConfirm(nwk, confirm) != 0)
            return 1;

        pauseHost();
    }

    printf("join       no NLME-JOIN.confirm in %u ms (state %u)\n", JOIN_WAIT_MS, (uint32_t)Nwk_JoinStateOf(nwk));
    return 0;
}

static int runChild(Rcp_Radio *radio, Zb_Layers *stack, const JoinRun *run, uint64_t ownIeee)
{
    Mac_BeaconNotification beacon;
    Nwk_JoinConfirmParameters confirm;
    Nwk_JoinRequestParameters req;
    Nwk_JoinParent parent;
    Aps_ApsdeReq apsReq;
    Aps_Confirm apsConfirms[2];
    Mac_Mac *mac = Zb_LayersMac(stack);
    Nwk_Nwk *nwk = Zb_LayersNwk(stack);
    ZbStatus status;
    uint32_t deadline;
    uint32_t got = 0;
    uint32_t tries = 1;
    uint32_t attempt;
    int resendOwed = 0;
    uint32_t i;

    printf("child      %s, no address of its own (0x%04x), channel %u, extended PAN 0x%016llx\n",
           run->asRouter ? "router" : "end device", UNASSOCIATED, run->channel,
           (unsigned long long)run->extendedPanId);
    printf("           ownIeee %016llx\n", (unsigned long long)ownIeee);

    Zb_LayersNwk(stack)->cfg.attachMechanism = run->commission ? (uint32_t)NWK_ATTACH_COMMISSIONING
                                              : run->associate ? (uint32_t)NWK_ATTACH_ASSOCIATION
                                              : (uint32_t)NWK_ATTACH_BY_BEACON;

    /* 7.5.2's request, and the wait for the beacon it owes. */
    status = sendBeaconRequest(mac, Port_NowMs());
    deadline = Port_NowMs() + BEACON_WAIT_MS;

    while (status == ZB_ERR_NO_SPACE && !Zb_timeReached(Port_NowMs(), deadline) && stepOnce(radio, stack))
    {
        pauseHost();
        status = sendBeaconRequest(mac, Port_NowMs());
    }

    if (status != ZB_OK)
    {
        printf("child      the Beacon Request was refused: %s\n", statusName(status));
        return 1;
    }

    printf("scan       Beacon Request submitted (7.5.2's shape: broadcast PAN and address, no source fields)\n");

    deadline = Port_NowMs() + BEACON_WAIT_MS;
    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);

    while (got == 0 && !Zb_timeReached(Port_NowMs(), deadline))
    {
        Mac_DataConfirmParameters sent;
        uint32_t confirmed = 0;

        if (!stepForConfirm(radio, stack, &sent, &confirmed))
            break;

        if (confirmed != 0)
        {
            printf("scan       Beacon Request confirm: %s (try %u of %u)\n", statusName(sent.status), tries,
                   BEACON_TRIES);
            resendOwed = sent.status != ZB_OK && tries < BEACON_TRIES;
        }

        /* A resend the MAC refuses stays owed: the link is still answering the last request. */
        if (resendOwed && sendBeaconRequest(mac, Port_NowMs()) == ZB_OK)
        {
            resendOwed = 0;
            tries++;
        }

        got = Mac_PollBeacons(mac, &beacon, 1);
        pauseHost();
    }

    if (got == 0)
    {
        Mac_Counters counters = Mac_CountersOf(mac);

        printf("scan       no beacon answered in %u ms: nothing to join\n", BEACON_WAIT_MS);
        printf("scan       the radio heard %u beacon(s) and %u beacon request(s); its own requests refused %u\n",
               counters.beaconsNotified, counters.beaconRequestsHeard, counters.refusedRequests);
        return 1;
    }

    printBeacon(&beacon);

    /* Table 3-74's entry, out of the beacon: the extended PAN identifier is the payload's, the addresses and the
       permit are Table 8-3's. A beacon leaves the parent's short address out unless it is the coordinator's, which
       is why `shortKnown` is the address mode's answer and not an assumption. */
    Zb_memset(&parent, 0, (uint32_t)sizeof parent);
    extendedPanOctets(run->extendedPanId, parent.extendedPanId);
    parent.panId = beacon.coordPanId;
    parent.shortKnown = beacon.coordAddrMode == MAC_ADDR_SHORT ? 1 : 0;
    parent.shortAddress = beacon.coordShort;
    /* A coordinator beacons from its short address, so the beacon names no IEEE: the association's destination
       is still the extended address 10.21.5.1 sends it to, and the installer knows it. */
    parent.extendedAddress = beacon.coordExtended != 0 ? beacon.coordExtended : run->parentIeee;

    if (parent.extendedAddress == 0)
        printf("parent     this beacon named no extended address, which a coordinator's short-form beacon never does:\n"
               "           name the parent with --parent-ieee <eui64>, or the discovery entry has no address to reach\n");

    parent.channel = run->channel;
    parent.page = 0;
    parent.associationPermit = beacon.associationPermit;
    parent.deviceType = beacon.panCoordinator ? NWK_DEVICE_COORDINATOR : NWK_DEVICE_ROUTER;
    parent.rxOnWhenIdle = 1;
    parent.r23Appendix = Nwk_BeaconHasAppendix(beacon.payload, beacon.payloadLen);
    parent.inUse = 1;

    status = Nwk_JoinParentAdd(nwk, &parent);

    if (status != ZB_OK)
    {
        printf("parent     the discovery entry was refused: %s\n", statusName(status));
        return 1;
    }

    /* 3.2.2.13's request: RejoinNetwork 0x00, the one channel the scan heard, and the capability octet a device
       that wants an address sends. */
    Zb_memset(&req, 0, (uint32_t)sizeof req);
    extendedPanOctets(run->extendedPanId, req.extendedPanId);
    req.rejoinNetwork = 0;
    req.scanChannels = (uint32_t)1 << run->channel;
    req.scanDuration = 0;
    req.capability.deviceType = run->asRouter ? 1 : 0;
    req.capability.powerSource = 1;
    req.capability.rxOnWhenIdle = 1;
    req.capability.associationType = 0;
    req.capability.suspendableCsmaCa = 0;
    req.capability.securityCapability = 0;
    req.capability.allocateAddress = 1;
    req.securityEnable = 0;

    /* 3.6.1.6.1.1 leaves a failed join to this layer, which may join again from the discovered network. */
    for (attempt = 1; ; attempt++)
    {
        if (!joinOnce(radio, stack, run, &req, &confirm))
            return 1;

        printf("join       NLME-JOIN.confirm: status 0x%02x, network address 0x%04x, channel %u, parent ",
               confirm.status, confirm.networkAddress, confirm.channel);

        if (confirm.parentShortKnown)
            printf("0x%04x", confirm.parentShort);
        else
            printf("0x%016llx", (unsigned long long)confirm.parentExtended);

        printf(" (try %u of %u)\n", attempt, JOIN_TRIES);

        if (confirm.status == 0 || !joinTryAgain(confirm.status) || attempt >= JOIN_TRIES)
            break;

        printf("join       %s 0x%02x: joining again from the discovery table\n", joinFailureName(confirm.status),
               confirm.status);
    }

    if (confirm.status != 0)
    {
        Mac_Counters seen = Mac_CountersOf(mac);

        printf("join       %s 0x%02x\n", joinFailureName(confirm.status), confirm.status);
        printf("join       receive: pan-mismatch %u dest-mismatch %u src-pan-mismatch %u malformed %u "
               "reserved-type %u reserved-version %u fcs-failure %u unbuilt %u promiscuous-delivered %u "
               "command %u\n", seen.panMismatches, seen.destinationMismatches, seen.sourcePanMismatches,
               seen.malformedFrames, seen.reservedTypeFrames, seen.reservedVersionFrames, seen.fcsFailures,
               seen.unbuiltForms, seen.promiscuousDelivered, seen.commandsHeard);
        return 1;
    }

    /* 3.6.1.6.1.1's wait, which is what a run configured with `--no-key` came to measure: the device joined and has
       no network key, so it waits apsSecurityTimeOutPeriod and reports NO_KEY on a second confirmation. */
    if (run->noKey)
    {
        uint32_t waited = 0;

        printf("key        this device holds the trust centre's link key and no network key: 4.6.3.2.4's device\n");
        printf("key        waiting apsSecurityTimeOutPeriod (%u s) for a Transport Key\n",
               (unsigned)NWK_SECURITY_TIMEOUT_DEFAULT);

        deadline = Port_NowMs() + (NWK_SECURITY_TIMEOUT_DEFAULT + 6) * 1000;

        while (!Zb_timeReached(Port_NowMs(), deadline))
        {
            if (!stepOnce(radio, stack))
                break;

            if (Nwk_PollJoinConfirm(nwk, &confirm) != 0)
            {
                waited++;

                printf("key        NLME-JOIN.confirm: status 0x%02x (%s), network address 0x%04x\n",
                       confirm.status,
                       confirm.status == NWK_STATUS_NO_KEY ? "NO_KEY, 3.6.1.6.1.1's own code" : "not NO_KEY",
                       confirm.networkAddress);
            }

            if (Security_IsEnabled(Zb_LayersSecurity(stack)))
            {
                printf("key        the NIB was given the network key: the wait ended before it timed out\n");
                break;
            }

            pauseHost();
        }

        {
            Mac_Counters seen = Mac_CountersOf(mac);
            Aps_Aps *aps = Zb_LayersAps(stack);

            printf("key        %u confirmation(s) after the join, NO_KEY outcome(s) %u, network key installed %s\n",
                   waited, Nwk_JoinKeyTimeouts(nwk),
                   Security_IsEnabled(Zb_LayersSecurity(stack)) ? "yes" : "no");
            printf("key        mac receive: pan-mismatch %u dest-mismatch %u src-pan-mismatch %u malformed %u "
                   "fcs-failure %u unbuilt %u promiscuous-delivered %u command %u\n",
                   seen.panMismatches, seen.destinationMismatches, seen.sourcePanMismatches,
                   seen.malformedFrames, seen.fcsFailures, seen.unbuiltForms, seen.promiscuousDelivered,
                   seen.commandsHeard);
            printf("key        aps receive: secured-deferred %u auth-failure %u malformed %u shape-refused %u "
                   "command-deferred %u\n", Aps_RxSecuredDeferred(aps), Aps_RxSecuredFailuresAuth(aps),
                   Aps_RxMalformed(aps), Aps_RxShapeRefused(aps), Aps_RxCommandDeferred(aps));
            printf("key        key door: installed %u not-trust-centre %u policy %u unsecured %u distributed %u "
                   "forward %u indications %u\n", Aps_KeyInstalled(aps), Aps_KeyDroppedNotTrustCenter(aps),
                   Aps_KeyDroppedPolicy(aps), Aps_KeyDroppedUnsecured(aps), Aps_KeyDroppedDistributed(aps),
                   Aps_KeyForwardDeferred(aps), Aps_KeyIndicationQueue(aps));
            printf("key        nwk receive: unsecured %u not-for-me %u no-route %u bad-source %u malformed %u "
                   "indications %u refused %u\n", Nwk_DroppedUnsecured(nwk), Nwk_DroppedNotForMe(nwk),
                   Nwk_DroppedNoRoute(nwk), Nwk_DroppedBadSource(nwk), Nwk_DroppedMalformed(nwk),
                   Nwk_IndicationQueue(nwk), Nwk_RefusedRequests(nwk));
        }

        /* The run is a measurement, so it succeeds when the wait concluded either way: the key arrived, or the
           period passed and NO_KEY was reported. Neither means the wait is still running. */
        return (waited != 0 || Security_IsEnabled(Zb_LayersSecurity(stack))) ? 0 : 1;
    }

    /* The join is the claim; a frame to the coordinator is the proof. The MAC's own PIB holds the address the
       association gave, and the NWK layer reads it from there. */
    Zb_memset(&apsReq, 0, (uint32_t)sizeof apsReq);
    apsReq.dstAddrMode = 0x02;
    apsReq.dstAddress = PARENT_SHORT;
    apsReq.dstEndpoint = DST_ENDPOINT;
    apsReq.profileId = PROFILE_ID;
    apsReq.clusterId = CLUSTER_ID;
    apsReq.srcEndpoint = SRC_ENDPOINT;
    apsReq.asdu = run->asdu;
    apsReq.asduLength = run->asduLen;
    apsReq.txOptions = APS_TX_ACK;

    settle(radio, stack, 30);

    status = Aps_DataRequest(Zb_LayersAps(stack), &apsReq, Port_NowMs());

    printf("data       APS unicast to the coordinator at 0x%04x, %u octets  -> %s\n", PARENT_SHORT, run->asduLen,
           statusName(status));

    deadline = Port_NowMs() + DATA_WAIT_MS;

    while (!Zb_timeReached(Port_NowMs(), deadline))
    {
        if (!stepOnce(radio, stack))
            break;

        if (Aps_PollConfirms(Zb_LayersAps(stack), apsConfirms, 2) != 0)
        {
            printf("data       APS confirm: %s, aps status 0x%02x, %u attempt(s), aps counter %02x\n",
                   statusName(apsConfirms[0].status), (unsigned)apsConfirms[0].apsStatus,
                   apsConfirms[0].attempts, apsConfirms[0].apsCounter);

            /* 2.2.4.1.3.1's confirm may name a refusal the APS layer will try again (a MAC session still busy
               from the association exchange), so only a confirm that carried the frame ends the wait. */
            if (apsConfirms[0].status != ZB_ERR_BUSY)
            {
                /* 3.6.10.2's timeout pair runs beside the unicast; a few turns let its answer arrive. */
                settle(radio, stack, 40);
                printf("timeout    %u End Device Timeout Request(s) sent, parent information 0x%02x from the response\n",
                       Nwk_TimeoutRequestsSent(Zb_LayersNwk(stack)), Zb_LayersNwk(stack)->cfg.parentInformation);

                return apsConfirms[0].status == ZB_OK ? 0 : 1;
            }
        }

        i = 0;
        (void)i;
        pauseHost();
    }

    printf("data       no APS confirm in %u ms\n", DATA_WAIT_MS);

    return 1;
}

static void usage(void)
{
    printf("usage: zb_join (--parent|--join) --path <path>|--device <name> --tx --allow-tx\n"
           "               [--channel 11|12|25|26] [--pan hex] [--extended-pan hex] [--permit 0|1] [--parent-ieee hex]\n"
           "               [--seconds n] [--transport-key eui64] [--no-key] [--router] [--commission|--associate]\n"
           "               [--own-ieee hex]\n"
           "               [--network-key hex] [--link-key hex] [--zdo-serve [--peer hex] | --zdo-ask hex]\n"
           "               [--group-send | --group-listen] --group hex [--group-mode members|unfiltered]\n"
           "               [--asdu hex] [--timeout ms] [--baud n] [--rx-ring n] [--tx-ring n]\n"
           "  --parent  runs the coordinator's half: 3.6.5's beacon with Table 3-83's payload, the permit it is\n"
           "            given, and the association door the layer above the MAC answers through\n"
           "  --join    runs the child's half: 7.5.2's Beacon Request, Table 3-74's entry, 3.2.2.13's request,\n"
           "            3.2.2.15's confirm, then one APS unicast to the coordinator (with --no-key, the wait for\n"
           "            the network key instead of the unicast)\n"
           "  --transport-key <eui64> makes the coordinator hold the network key and a link key pair for that child\n"
           "            and send 4.4.2.1.3's Transport Key to it once it has joined\n"
           "  --own-ieee names this device's extended address, over the one the stick reports (or does not)\n"
           "  --commission  makes the child attach by 3.4.14's Network Commissioning Request whatever the beacon says;\n"
           "            without it or --associate, 3.6.1.6.1.1 chooses: commissioning to a parent whose beacon carries the\n"
           "            R23 appendix, 10.21.2's association to any other\n"
           "  --associate  makes the child attach by 10.21.2's association whatever the beacon says\n"
           "  --router  makes the joining device a router rather than an end device, which is the only role a\n"
           "            neighbour's link status list names (3.4.8.3.2)\n"
           "  --no-key  makes the child hold the trust centre's link key and no network key, which is 4.6.3.2.4's\n"
           "            device waiting for one: the run prints 3.6.1.6.1.1's NO_KEY when the wait times out\n"
           "  --parent-ieee names the parent's extended address on the child's run, which a beacon sourced from the\n"
           "            coordinator's short address cannot carry; defaults: channel 12, PAN 0xbeef, extended PAN\n"
           "            0x000000000000beef, permit 1, 20 s parent window,\n"
           "  one asdu of 66 72 61 6d 65 64; a channel given with --protect-channel needs --allow-live-channel,\n"
           "  and a PAN given with --protect-pan is refused (docs/internals/hardware.md §8)\n");
}

static int parseHexOctets(const char *text, uint8_t *out, uint32_t cap, uint32_t *outLen)
{
    uint32_t len = 0;
    const char *p = text;

    while (*p != 0)
    {
        unsigned value = 0;

        if (len >= cap)
            return 0;

        if (sscanf(p, "%2x", &value) != 1)
            return 0;

        out[len] = (uint8_t)value;
        len++;
        p += 2;

        while (*p == ' ' || *p == ':')
            p++;
    }

    *outLen = len;
    return len != 0;
}

int main(int argc, char **argv)
{
    JoinRun run;
    Rcp_Radio radio;
    Zb_Layers stack;
    Zb_Core device;
    Zb_Layers *stackPtr;
    ZbStatus status;
    uint64_t ownIeee = 0;
    uint32_t i;
    uint32_t turn;
    int parent = 0;
    int child = 0;
    int wantTx = 0;
    int allowTx = 0;
    int allowLiveChannel = 0;
    int protectTaken;
    Protect protect;
    int result;

    Zb_memset(&run, 0, (uint32_t)sizeof run);
    Zb_memset(&protect, 0, (uint32_t)sizeof protect);

    run.permit = 1;
    run.channel = CHANNEL_DEFAULT;
    run.panId = PAN_INERT;
    run.extendedPanId = EXTENDED_PAN_DEFAULT;
    run.seconds = 20;
    run.timeoutMs = 1000;
    run.baud = 0;
    run.rxRing = 0;
    run.txRing = 0;
    run.path = 0;
    run.asduLen = (uint32_t)sizeof s_asduDefault;
    Zb_memcpy(run.asdu, s_asduDefault, (uint32_t)sizeof s_asduDefault);
    Zb_memcpy(run.networkKey, s_networkKeyDefault, SECURITY_KEY_OCTETS);
    Zb_memcpy(run.linkKey, s_linkKeyDefault, SECURITY_KEY_OCTETS);

    for (i = 1; i < (uint32_t)argc; i++)
    {
        if (strcmp(argv[i], "--parent") == 0)
            parent = 1;
        else if (strcmp(argv[i], "--join") == 0)
            child = 1;
        else if (strcmp(argv[i], "--tx") == 0)
            wantTx = 1;
        else if (strcmp(argv[i], "--allow-tx") == 0)
            allowTx = 1;
        else if (strcmp(argv[i], "--allow-live-channel") == 0)
            allowLiveChannel = 1;
        else if ((protectTaken = protectOption(&protect, argc, argv, i)) != 0)
        {
            if (protectTaken < 0)
            {
                printf("--protect-channel takes a channel 11..26, --protect-pan a PAN id in hex, at most %u\n",
                       (unsigned)PROTECT_PAN_MAX);
                return 2;
            }

            i++;
        }
        else if (strcmp(argv[i], "--path") == 0 && i + 1 < (uint32_t)argc)
            run.path = deviceMapResolve(argv[++i]);
        else if (strcmp(argv[i], "--device") == 0 && i + 1 < (uint32_t)argc)
        {
            const char *named = deviceMapLookup(argv[++i]);

            if (!named)
            {
                printf("--device takes a name the file ZB_DEVICE_MAP names; give --path otherwise\n");
                return 2;
            }

            run.path = named;
        }
        else if (strcmp(argv[i], "--channel") == 0 && i + 1 < (uint32_t)argc)
            run.channel = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--pan") == 0 && i + 1 < (uint32_t)argc)
            run.panId = (uint32_t)strtoul(argv[++i], 0, 16);
        else if (strcmp(argv[i], "--extended-pan") == 0 && i + 1 < (uint32_t)argc)
            run.extendedPanId = strtoull(argv[++i], 0, 16);
        else if (strcmp(argv[i], "--parent-ieee") == 0 && i + 1 < (uint32_t)argc)
            run.parentIeee = strtoull(argv[++i], 0, 16);
        else if (strcmp(argv[i], "--transport-key") == 0 && i + 1 < (uint32_t)argc)
        {
            run.transportKey = 1;
            run.childIeee = strtoull(argv[++i], 0, 16);
        }
        else if (strcmp(argv[i], "--own-ieee") == 0 && i + 1 < (uint32_t)argc)
            run.ownIeee = strtoull(argv[++i], 0, 16);
        else if (strcmp(argv[i], "--no-key") == 0)
            run.noKey = 1;
        else if (strcmp(argv[i], "--router") == 0)
            run.asRouter = 1;
        else if (strcmp(argv[i], "--commission") == 0)
            run.commission = 1;
        else if (strcmp(argv[i], "--associate") == 0)
            run.associate = 1;
        else if (strcmp(argv[i], "--zdo-serve") == 0)
        {
            run.zdoServe = 1;
            parent = 1;
        }
        else if (strcmp(argv[i], "--group") == 0 && i + 1 < (uint32_t)argc)
            run.groupId = (uint32_t)strtoul(argv[++i], 0, 16);
        else if (strcmp(argv[i], "--group-send") == 0)
        {
            run.groupSend = 1;
            child = 1;
        }
        else if (strcmp(argv[i], "--group-listen") == 0)
        {
            run.groupListen = 1;
            parent = 1;
        }
        else if (strcmp(argv[i], "--group-mode") == 0 && i + 1 < (uint32_t)argc)
        {
            run.groupMode = strcmp(argv[++i], "unfiltered") == 0 ? APS_GROUP_DELIVERY_UNFILTERED
                                                                 : APS_GROUP_DELIVERY_MEMBERS;
        }
        else if (strcmp(argv[i], "--peer") == 0 && i + 1 < (uint32_t)argc)
            run.zdoPeer = (uint32_t)strtoul(argv[++i], 0, 16);
        else if (strcmp(argv[i], "--zdo-ask") == 0 && i + 1 < (uint32_t)argc)
        {
            run.zdoAsk = (uint32_t)strtoul(argv[++i], 0, 16);
            run.zdoAskSet = 1;
            child = 1;
        }
        else if (strcmp(argv[i], "--network-key") == 0 && i + 1 < (uint32_t)argc)
        {
            uint32_t keyLen = 0;

            if (!parseHexOctets(argv[++i], run.networkKey, SECURITY_KEY_OCTETS, &keyLen)
                || keyLen != SECURITY_KEY_OCTETS)
            {
                printf("--network-key wants %u hex octets\n", (unsigned)SECURITY_KEY_OCTETS);
                return 2;
            }
        }
        else if (strcmp(argv[i], "--link-key") == 0 && i + 1 < (uint32_t)argc)
        {
            uint32_t keyLen = 0;

            if (!parseHexOctets(argv[++i], run.linkKey, SECURITY_KEY_OCTETS, &keyLen)
                || keyLen != SECURITY_KEY_OCTETS)
            {
                printf("--link-key wants %u hex octets\n", (unsigned)SECURITY_KEY_OCTETS);
                return 2;
            }
        }
        else if (strcmp(argv[i], "--permit") == 0 && i + 1 < (uint32_t)argc)
            run.permit = (int)strtoul(argv[++i], 0, 10) != 0;
        else if (strcmp(argv[i], "--seconds") == 0 && i + 1 < (uint32_t)argc)
            run.seconds = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--asdu") == 0 && i + 1 < (uint32_t)argc)
        {
            if (!parseHexOctets(argv[++i], run.asdu, ASDU_MAX, &run.asduLen))
            {
                printf("--asdu wants hex octets, at most %u of them\n", ASDU_MAX);
                return 2;
            }
        }
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < (uint32_t)argc)
            run.timeoutMs = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--baud") == 0 && i + 1 < (uint32_t)argc)
            run.baud = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--rx-ring") == 0 && i + 1 < (uint32_t)argc)
            run.rxRing = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--tx-ring") == 0 && i + 1 < (uint32_t)argc)
            run.txRing = (uint32_t)strtoul(argv[++i], 0, 10);
        else
        {
            usage();
            return 2;
        }
    }

    if (parent == child)
    {
        printf("name one role: --parent or --join\n");
        return 2;
    }

    if (run.path == 0)
    {
        printf("no port is ever defaulted: --path or --device names one (docs/internals/hardware.md §8)\n");
        return 2;
    }

    if (!wantTx || !allowTx)
    {
        printf("this tool transmits in both roles: --tx and --allow-tx are both needed (docs/internals/hardware.md §8)\n");
        return 2;
    }

    /* A protected channel needs its own authorisation, named apart from --allow-tx because every run gives
       that flag, so it would authorise nothing (docs/internals/hardware.md §8). */
    if (protectChannel(&protect, run.channel))
    {
        if (!allowLiveChannel)
        {
            printf("channel %u is protected: --allow-live-channel is the authorisation "
                   "(docs/internals/hardware.md §8)\n", run.channel);
            return 2;
        }

        printf("channel    %u is protected and was authorised for this run\n", run.channel);
    }

    if (protectPan(&protect, run.panId))
    {
        printf("PAN 0x%04x is protected: this tool refuses it\n", (unsigned)run.panId);
        return 2;
    }

    run.isParent = parent != 0;

    if (!bringUp(&radio, &run))
        return 1;

    if (run.zdoServe || run.zdoAskSet || run.groupSend || run.groupListen)
        status = initDevice(&device, &radio, &run, &ownIeee);
    else
        status = initStack(&stack, &radio, &run, &ownIeee);

    if (status != ZB_OK)
    {
        printf("stack      the layer above would not adopt the seam: %s\n", statusName(status));
        endSession(&radio);
        return 1;
    }

    stackPtr = (run.zdoServe || run.zdoAskSet || run.groupSend || run.groupListen) ? Zb_CoreLayers(&device) : &stack;

    /* The arm sequence leaves the radio in 10.23.1's receive-all mode, and a promiscuous receiver does not
       acknowledge. Both ends of this exchange must be filtered: every frame is
       addressed to one of them and every one of them is acknowledged, and 10.21.5.2's Association Response is
       addressed to the child's extended address, which a filtered stick hands up on every Phoscon RCP release. Adoption queued its PIB writes first and the seam's write queue holds six, so
       the turns below drain it before this one is asked: a refusal leaves the radio acknowledging nothing, and the
       exchange dies in a way nothing reports. */
    for (turn = 0; turn < 20; turn++)
    {
        status = Mac_SetPromiscuousMode(Zb_LayersMac(stackPtr), 0);

        if (status == ZB_OK)
            break;

        settle(&radio, stackPtr, 1);
    }

    if (status != ZB_OK)
    {
        printf("delivery   the promiscuous mode could not be stated: %s\n", statusName(status));
        endSession(&radio);
        return 1;
    }

    printf("stack      %s, own short 0x%04x, PAN 0x%04x, channel %u, ownIeee 0x%016llx, level 0, promiscuous off\n",
           run.isParent ? "coordinator" : (run.asRouter ? "router" : "end device"),
           Nwk_OwnAddress(Zb_LayersNwk(stackPtr)), run.panId,
           run.channel, (unsigned long long)ownIeee);

    if (run.groupSend)
        result = runGroupSend(&radio, &device, &run);
    else if (run.groupListen)
        result = runGroupListen(&radio, &device, &run);
    else if (run.zdoServe)
        result = runZdoServe(&radio, &device, &run);
    else if (run.zdoAskSet)
        result = runZdoAsk(&radio, &device, &run);
    else
        result = run.isParent ? runParent(&radio, &stack, &run, ownIeee) : runChild(&radio, &stack, &run, ownIeee);

    endSession(&radio);

    return result;
}
