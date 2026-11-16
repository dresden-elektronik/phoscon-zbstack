#include "zb_stack.h"

#include "nwk_addr.h"
#include "nwk_timeout.h"
#include "port.h"
#include "zb_bstream.h"
#include "zb_time.h"
#include "zb_utils.h"
#include "zdo.h"

/* The stack's own phases, never an application's: an event is reported on each move an application acts on. */
enum
{
    ZB_STACK_PHASE_IDLE = 0,
    ZB_STACK_PHASE_BRINGUP = 1,     /* the RCP is reset, identified and armed; then the library adopts it */
    ZB_STACK_PHASE_JOINING = 2,     /* a router's discovery, join and key wait */
    ZB_STACK_PHASE_OPENING = 3,     /* the permit, which an RCP takes only once it acknowledges */
    ZB_STACK_PHASE_UP = 4,
    ZB_STACK_PHASE_FAILED = 5,
    ZB_STACK_PHASE_STOPPING = 6,    /* the reset is on the wire; a few pumps carry it before the port closes */
    ZB_STACK_PHASE_STOPPED = 7,
    ZB_STACK_PHASE_SCANNING = 8     /* a Zb_StackEnergyScan's dwells, on a device that joins nothing */
};

enum
{
    ZB_STACK_BRINGUP_MS = 3000,     /* an RCP that is not armed by then is not coming up */
    ZB_STACK_WAIT_MS = 5,           /* the longest sleep between turns: the library's timers run in milliseconds */
    ZB_STACK_REOPEN_MS = 1000,      /* how often a path whose port went away is opened again */
    ZB_STACK_STOP_TURNS = 3,        /* the pumps a reset is given to reach the RCP before the port closes */
    ZB_STACK_SCAN_DURATION = 3,     /* 3.2.2.3's exponent: about 138 ms on each channel */
    ZB_STACK_UNJOINED = 0xffff,     /* macPanId and macShortAddress until a network gives them */
    ZB_STACK_CHANNEL_FIRST = 11,
    ZB_STACK_CHANNEL_LAST = 26,
    ZB_STACK_MANUFACTURER = 0x1037, /* dresden elektronik's, the node descriptor's default */
    ZB_STACK_MAINS_POWERED = 0x04,  /* 802.15.4's Capability Information, bit 2, as the power descriptor states it */
    ZB_STACK_RECEIVER_ON = 0x08,    /* bit 3, as Device_annce carries it */
    ZB_STACK_ALLOCATE_ADDRESS = 0x80 /* and bit 7: an end device is an RFD that asks for an address */
};

/* Zigbee 3.0's global trust-centre link key: the literal "ZigBeeAlliance09", which every device holds until a network
   gives it one of its own. */
static const uint8_t s_globalLinkKey[ZB_STACK_KEY_OCTETS] =
{
    0x5a, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6c, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x30, 0x39
};

static int zbStackIsZero(const uint8_t *octets, uint32_t len)
{
    uint32_t i;

    for (i = 0; i < len; i++)
    {
        if (octets[i] != 0)
            return 0;
    }

    return 1;
}

/* The channel a coordinator forms on or a restored device comes back on: the config's, else the state's. */
static uint32_t zbStackNamedChannel(const Zb_StackConfig *cfg)
{
    if (cfg->channel != 0 || cfg->state == 0)
        return cfg->channel;

    return cfg->state->channel;
}

static uint32_t zbStackLowestChannel(uint32_t mask)
{
    uint32_t channel;

    for (channel = ZB_STACK_CHANNEL_FIRST; channel <= ZB_STACK_CHANNEL_LAST; channel++)
    {
        if ((mask & ((uint32_t)1 << channel)) != 0)
            return channel;
    }

    return 0;
}

static void zbStackPut64(uint8_t *out, uint64_t value)
{
    uint32_t i;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        out[i] = (uint8_t)(value >> (8 * i));
}

static uint32_t zbStackGet32(const uint8_t *in)
{
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static void zbStackPush(Zb_Stack *self, Zb_StackEventType type, ZbStatus status)
{
    Zb_StackEvent *event;

    if (self->lifecycleCount >= ZB_STACK_LIFECYCLE_MAX)
        return;

    event = &self->lifecycle[self->lifecycleCount++];
    Zb_memset(event, 0, (uint32_t)sizeof *event);
    event->type = type;
    event->status = status;
}

static void zbStackScanEnd(Zb_Stack *self, ZbStatus status, const Nwk_EdScanConfirmParameters *confirm);

static void zbStackFail(Zb_Stack *self, ZbStatus status)
{
    if (self->energyScan)
    {
        zbStackScanEnd(self, status, 0);
        return;
    }

    zbStackPush(self, ZB_EVENT_NETWORK_FAILED, status);
    self->phase = ZB_STACK_PHASE_FAILED;
}

/* The application's entropy where it names a source, else the port's, which a stack over a radio of the caller's own
   does not have. */
static ZbStatus zbStackDraw(Zb_Stack *self, uint8_t *out, uint32_t len)
{
    if (self->config.entropy != 0)
        return self->config.entropy(self->config.entropyContext, out, len);

    if (!self->rcpOpen)
        return ZB_ERR_UNSUPPORTED;

    return Port_Entropy(&self->rcp.port, out, len);
}

/* The network key a saved state runs on: the active entry's, when the state carries its octets. */
static const uint8_t *zbStackStateKey(const Zb_State *state)
{
    uint32_t i;

    for (i = 0; i < state->keyCount && i < SECURITY_KEY_SET_MAX; i++)
    {
        if (state->keys[i].keySeqNumber == state->nwkActiveKeySeqNumber && state->keys[i].keyPresent)
            return state->keys[i].key;
    }

    return 0;
}

/* This device's extended address: a saved state's, the configured one, or the factory address the radio reports. */
static uint64_t zbStackIdentity(Zb_Stack *self)
{
    Radio_Pib pib;
    uint64_t ieee = self->config.state != 0 ? self->config.state->ownIeee : self->config.ieee;
    uint32_t i;

    if (ieee != 0)
        return ieee;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);

    if (self->radio->ops->pibGet(self->radio, &pib) != ZB_OK)
        return 0;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        ieee |= (uint64_t)pib.hwAddress[i] << (8 * i);

    return ieee;
}

/* The library adopts the running radio: the config the application stated, turned into the one Zb_Core reads, the
   seeds and keys drawn here so no application picks a sequence number or a key by hand. */
static ZbStatus zbStackAdopt(Zb_Stack *self)
{
    const Zb_StackConfig *cfg = &self->config;
    int coordinator = cfg->role == ZB_STACK_COORDINATOR;
    Zb_CoreConfig core;
    uint8_t seed[ZB_STACK_KEY_OCTETS];
    uint8_t linkKeySeed[ZB_STACK_KEY_OCTETS];
    int seeded;
    uint16_t panId = cfg->state != 0 ? cfg->state->panId : cfg->panId;
    uint64_t extendedPanId = cfg->state != 0 ? cfg->state->extendedPanId : cfg->extendedPanId;
    const uint8_t *stateKey = cfg->state != 0 ? zbStackStateKey(cfg->state) : 0;
    ZbStatus status;
    uint32_t i;

    self->ieee = zbStackIdentity(self);

    if (self->ieee == 0)
        return ZB_ERR_NOT_FOUND;

    seeded = zbStackDraw(self, seed, (uint32_t)sizeof seed) == ZB_OK;

    if (!seeded)
    {
        Zb_memset(seed, 0, (uint32_t)sizeof seed);
        zbStackPut64(seed, self->ieee);
    }

    Zb_memset(&core, 0, (uint32_t)sizeof core);

    core.layers.present = RADIO_PIB_CHANNEL | RADIO_PIB_PAGE | RADIO_PIB_PAN_ID | RADIO_PIB_SHORT_ADDRESS
                          | RADIO_PIB_EXTENDED_ADDRESS | RADIO_PIB_RX_ON_WHEN_IDLE;
    core.layers.channel = coordinator ? zbStackNamedChannel(cfg) : zbStackLowestChannel(cfg->channelMask);
    core.layers.page = 0;
    core.layers.rxOnWhenIdle = !(cfg->role == ZB_STACK_END_DEVICE && cfg->sleepy);
    core.layers.indirectPollRateMs = cfg->pollIntervalMs;
    core.layers.hearsWhileAsleep = cfg->hearsWhileAsleep;
    core.layers.seqStart = seed[8];
    core.layers.dsnStart = seed[9];
    core.layers.jitterSeed = zbStackGet32(&seed[10]);
    core.layers.joinSeed = zbStackGet32(&seed[0]) | 1;
    core.layers.log = cfg->log;
    zbStackPut64(core.layers.extendedAddress, self->ieee);

    if (coordinator)
    {
        if (panId == 0 || panId == ZB_STACK_UNJOINED)
            panId = (uint16_t)(1 + (zbStackGet32(&seed[4]) % (ZB_STACK_UNJOINED - 1)));

        core.layers.deviceType = NWK_DEVICE_COORDINATOR;
        core.layers.panId = panId;
        core.layers.shortAddress = 0x0000;
        self->extendedPanId = extendedPanId != 0 ? extendedPanId : self->ieee;
        zbStackPut64(core.layers.extendedPanId, self->extendedPanId);

        if (stateKey != 0)
        {
            Zb_memcpy(self->networkKey, stateKey, ZB_STACK_KEY_OCTETS);
            core.networkKeySeq = cfg->state->nwkActiveKeySeqNumber;
        }
        else if (zbStackIsZero(cfg->networkKey, ZB_STACK_KEY_OCTETS))
        {
            status = zbStackDraw(self, self->networkKey, ZB_STACK_KEY_OCTETS);

            if (status != ZB_OK)
                return status;
        }
        else
        {
            Zb_memcpy(self->networkKey, cfg->networkKey, ZB_STACK_KEY_OCTETS);
        }

        Zb_memcpy(core.networkKey, self->networkKey, ZB_STACK_KEY_OCTETS);
        core.transportNetworkKey = 1;

        if (!zbStackIsZero(cfg->linkKeySeed, ZB_STACK_KEY_OCTETS))
            Zb_memcpy(core.linkKeySeed, cfg->linkKeySeed, ZB_STACK_KEY_OCTETS);
        else if (zbStackDraw(self, linkKeySeed, (uint32_t)sizeof linkKeySeed) == ZB_OK)
            Zb_memcpy(core.linkKeySeed, linkKeySeed, ZB_STACK_KEY_OCTETS);
    }
    else
    {
        core.layers.deviceType = cfg->role == ZB_STACK_END_DEVICE ? NWK_DEVICE_END_DEVICE : NWK_DEVICE_ROUTER;
        core.layers.endDeviceTimeout = NWK_END_DEVICE_TIMEOUT_DEFAULT;
        core.layers.panId = cfg->state != 0 ? panId : ZB_STACK_UNJOINED;
        core.layers.shortAddress = cfg->state != 0 ? cfg->state->networkAddress : ZB_STACK_UNJOINED;

        if (cfg->state != 0)
        {
            core.layers.channel = zbStackNamedChannel(cfg);
            self->extendedPanId = extendedPanId;
            zbStackPut64(core.layers.extendedPanId, extendedPanId);
        }
    }

    Zb_memcpy(core.trustCentreLinkKey,
             zbStackIsZero(cfg->trustCentreLinkKey, ZB_STACK_KEY_OCTETS) ? s_globalLinkKey : cfg->trustCentreLinkKey,
             ZB_STACK_KEY_OCTETS);

    Zdo_NodeDescriptorDefaults(&core.node, coordinator ? ZDO_LOGICAL_COORDINATOR
                               : cfg->role == ZB_STACK_END_DEVICE ? ZDO_LOGICAL_END_DEVICE : ZDO_LOGICAL_ROUTER,
                               cfg->manufacturerCode);
    Zdo_PowerDescriptorDefaults(&core.power);

    if (cfg->role == ZB_STACK_END_DEVICE)
        core.node.macCapabilityFlags = (uint8_t)(ZB_STACK_ALLOCATE_ADDRESS | ZB_STACK_MAINS_POWERED
                                                 | (core.layers.rxOnWhenIdle ? ZB_STACK_RECEIVER_ON : 0));

    core.zdpUnsupportedToApplication = cfg->zdpUnsupportedToApplication;
    core.tcLinkKeyUpdate = !coordinator && !cfg->keepJoinedLinkKey;

    status = Zb_CoreInit(&self->core, self->radio, &core);

    if (status != ZB_OK)
        return status;

    self->coreRunning = 1;

    if (cfg->state != 0)
    {
        status = Zb_CoreRestore(&self->core, cfg->state, cfg->announceAfterRestore);

        if (status != ZB_OK)
            return status;
    }

    for (i = 0; i < cfg->endpointCount; i++)
    {
        status = Zb_CoreRegisterEndpoint(&self->core, &cfg->endpoints[i]);

        if (status != ZB_OK)
            return status;
    }

    return ZB_OK;
}

static void zbStackUp(Zb_Stack *self)
{
    const Radio_Pib *pib = Mac_Pib(Zb_CoreMac(&self->core));
    Zb_StackEvent *event;

    zbStackPush(self, ZB_EVENT_NETWORK_UP, ZB_OK);

    if (self->lifecycleCount != 0)
    {
        event = &self->lifecycle[self->lifecycleCount - 1];
        event->network.networkAddress = pib->shortAddress;
        event->network.panId = pib->panId;
        event->network.channel = pib->channel;
        event->network.ieee = self->ieee;
        event->network.extendedPanId = self->extendedPanId;
    }

    self->phase = ZB_STACK_PHASE_UP;
}

/* The scan's end: its levels, or why it measured nothing, and the RCP reset as a stop resets it. */
static void zbStackScanEnd(Zb_Stack *self, ZbStatus status, const Nwk_EdScanConfirmParameters *confirm)
{
    Zb_StackEvent *event;
    uint32_t i;

    zbStackPush(self, ZB_EVENT_ENERGY_SCAN, status);

    if (confirm != 0 && self->lifecycleCount != 0)
    {
        event = &self->lifecycle[self->lifecycleCount - 1];

        for (i = 0; i < confirm->channelCount && i < ZB_STACK_ENERGY_MAX; i++)
        {
            event->energy.levels[i].channel = confirm->channels[i].channelNumber;
            event->energy.levels[i].dbm = confirm->channels[i].energyDetected;
            event->energy.levels[i].measured = confirm->channels[i].measured;
        }

        event->energy.count = i;
    }

    self->phase = ZB_STACK_PHASE_FAILED;
    (void)Zb_StackStop(self);
}

/* The library adopts the radio as a router on no network, which sends nothing of its own, and asks NLME-ED-SCAN. */
static void zbStackScanBegin(Zb_Stack *self, uint32_t nowMs)
{
    Nwk_EdScanRequestParameters scan;
    Zb_CoreConfig core;
    ZbStatus status;

    self->ieee = zbStackIdentity(self);

    Zb_memset(&core, 0, (uint32_t)sizeof core);
    core.layers.present = RADIO_PIB_CHANNEL | RADIO_PIB_PAGE | RADIO_PIB_PAN_ID | RADIO_PIB_SHORT_ADDRESS
                          | RADIO_PIB_EXTENDED_ADDRESS | RADIO_PIB_RX_ON_WHEN_IDLE;
    core.layers.channel = zbStackLowestChannel(self->energyMask);
    core.layers.rxOnWhenIdle = 1;
    core.layers.deviceType = NWK_DEVICE_ROUTER;
    core.layers.panId = ZB_STACK_UNJOINED;
    core.layers.shortAddress = ZB_STACK_UNJOINED;
    core.layers.log = self->config.log;
    zbStackPut64(core.layers.extendedAddress, self->ieee);
    Zb_memcpy(core.trustCentreLinkKey, s_globalLinkKey, ZB_STACK_KEY_OCTETS);
    Zdo_NodeDescriptorDefaults(&core.node, ZDO_LOGICAL_ROUTER, self->config.manufacturerCode);
    Zdo_PowerDescriptorDefaults(&core.power);

    status = Zb_CoreInit(&self->core, self->radio, &core);

    if (status != ZB_OK)
    {
        zbStackScanEnd(self, status, 0);
        return;
    }

    self->coreRunning = 1;

    if (!Mac_Caps(Zb_CoreMac(&self->core))->hasEnergyScan)
    {
        zbStackScanEnd(self, ZB_ERR_UNSUPPORTED, 0);    /* a radio with no dwell, docs/internals/protocol.md §7.4 */
        return;
    }

    Zb_memset(&scan, 0, (uint32_t)sizeof scan);
    scan.scanChannels = self->energyMask;
    scan.scanDuration = self->energyDuration;
    status = Nwk_EdScanRequest(&Zb_CoreLayers(&self->core)->nwk, &scan, nowMs);

    if (status != ZB_OK)
    {
        zbStackScanEnd(self, status, 0);
        return;
    }

    self->phase = ZB_STACK_PHASE_SCANNING;
}

static void zbStackScanning(Zb_Stack *self)
{
    Nwk_EdScanConfirmParameters confirm;

    if (Nwk_PollEdScanConfirm(&Zb_CoreLayers(&self->core)->nwk, &confirm) != 1)
        return;

    zbStackScanEnd(self, confirm.status == 0 ? ZB_OK : ZB_ERR_DEVICE, &confirm);
}

static void zbStackBringUp(Zb_Stack *self, uint32_t nowMs)
{
    Zb_CoreJoinParameters join;
    ZbStatus status;

    if (!self->deadlineArmed)
    {
        self->deadlineMs = nowMs + ZB_STACK_BRINGUP_MS;
        self->deadlineArmed = 1;
    }

    if (self->rcpOpen && RcpRadio_Mode(&self->rcp) != RCP_RADIO_MODE_RUNNING)
    {
        if (Zb_timeReached(nowMs, self->deadlineMs))
            zbStackFail(self, ZB_ERR_TIMEOUT);

        return;
    }

    self->rcpRunning = 1;

    if (self->energyScan)
    {
        zbStackScanBegin(self, nowMs);
        return;
    }

    status = zbStackAdopt(self);

    if (status != ZB_OK)
    {
        zbStackFail(self, status);
        return;
    }

    if (self->config.role == ZB_STACK_COORDINATOR || self->config.state != 0)
    {
        self->phase = ZB_STACK_PHASE_OPENING;
        return;
    }

    Zb_memset(&join, 0, (uint32_t)sizeof join);
    join.extendedPanId = self->config.extendedPanId;
    join.scanChannels = self->config.channelMask;
    join.scanDuration = ZB_STACK_SCAN_DURATION;
    join.scanAttempts = self->config.scanAttempts;
    join.scanGapMs = self->config.scanGapMs;

    status = Zb_CoreJoin(&self->core, &join, nowMs);

    if (status != ZB_OK)
    {
        zbStackFail(self, status);
        return;
    }

    self->phase = ZB_STACK_PHASE_JOINING;
}

static void zbStackJoining(Zb_Stack *self)
{
    Zb_CoreJoinResult result;

    if (!Zb_CorePollJoinResult(&self->core, &result))
        return;

    if (result.status != 0)
    {
        zbStackFail(self, ZB_ERR_NOT_FOUND);
        return;
    }

    self->extendedPanId = result.extendedPanId;
    self->phase = ZB_STACK_PHASE_OPENING;
}

static void zbStackOpening(Zb_Stack *self, uint32_t nowMs)
{
    ZbStatus status;

    if (self->config.permitSeconds == 0 || self->config.role == ZB_STACK_END_DEVICE)
    {
        zbStackUp(self);
        return;
    }

    status = Zb_CorePermitJoining(&self->core, self->config.permitSeconds, nowMs);

    if (status == ZB_ERR_NOT_READY)
        return;

    if (status != ZB_OK)
    {
        zbStackFail(self, status);
        return;
    }

    zbStackUp(self);
}

static void zbStackPortConfig(const Zb_Stack *self, PortConfig *portCfg)
{
    Zb_memset(portCfg, 0, (uint32_t)sizeof *portCfg);
    portCfg->exclusive = 1;
    portCfg->baud = self->config.baud;
}

/* A port that faulted is closed at once, which lets its descriptor go, and opened again at the same path until one
   opens: an RCP put back comes up through its own bring-up. An RCP that refused its arming faults with no port
   fault, and is left alone. */
static void zbStackWatchPort(Zb_Stack *self, uint32_t nowMs)
{
    PortConfig portCfg;

    if (!self->rcpOpen)
        return;

    if (!self->rcpGone)
    {
        if (Port_Fault(&self->rcp.port) == PORT_FAULT_NONE)
            return;

        self->rcpGone = 1;
        self->rcpLostPort = 1;
        self->reopenAtMs = nowMs;
    }

    if (!Zb_timeReached(nowMs, self->reopenAtMs))
        return;

    zbStackPortConfig(self, &portCfg);

    if (RcpRadio_Reopen(&self->rcp, &portCfg) == ZB_OK)
    {
        self->rcpGone = 0;
        self->rcpReopens++;
        return;
    }

    self->reopenAtMs = nowMs + ZB_STACK_REOPEN_MS;
}

/* An RCP that reset, went quiet or went away, and the RCP running again: reported, and recovered by the library. */
static void zbStackWatchRcp(Zb_Stack *self)
{
    int running;

    if (!self->rcpOpen)
        return;

    running = RcpRadio_Mode(&self->rcp) == RCP_RADIO_MODE_RUNNING;

    if (self->rcpRunning && !running)
    {
        zbStackPush(self, ZB_EVENT_RCP_LOST, self->rcpLostPort ? ZB_ERR_NO_DEVICE : ZB_ERR_DEVICE_LOST);
    }
    else if (!self->rcpRunning && running)
    {
        self->rcpLostPort = 0;
        zbStackPush(self, ZB_EVENT_RCP_BACK, ZB_OK);
    }

    self->rcpRunning = running;
}

static void zbStackStopping(Zb_Stack *self)
{
    if (self->stopTurns > 0)
    {
        self->stopTurns--;
        return;
    }

    RcpRadio_Close(&self->rcp);
    self->rcpOpen = 0;
    self->phase = ZB_STACK_PHASE_STOPPED;
    zbStackPush(self, ZB_EVENT_STOPPED, ZB_OK);
}

void Zb_StackCoordinatorDefaults(Zb_StackConfig *cfg)
{
    if (cfg == 0)
        return;

    Zb_memset(cfg, 0, (uint32_t)sizeof *cfg);
    cfg->role = ZB_STACK_COORDINATOR;
    cfg->permitSeconds = 180;
    cfg->manufacturerCode = ZB_STACK_MANUFACTURER;
}

void Zb_StackRouterDefaults(Zb_StackConfig *cfg)
{
    if (cfg == 0)
        return;

    Zb_memset(cfg, 0, (uint32_t)sizeof *cfg);
    cfg->role = ZB_STACK_ROUTER;
    cfg->permitSeconds = 180;
    cfg->manufacturerCode = ZB_STACK_MANUFACTURER;
}

void Zb_StackEndDeviceDefaults(Zb_StackConfig *cfg)
{
    if (cfg == 0)
        return;

    Zb_memset(cfg, 0, (uint32_t)sizeof *cfg);
    cfg->role = ZB_STACK_END_DEVICE;
    cfg->manufacturerCode = ZB_STACK_MANUFACTURER;
}

/* A saved state is of this schema and this role, a joiner's carries the network key it was sent, and it names the
   network the config names where it names one. */
static ZbStatus zbStackStateFits(const Zb_StackConfig *cfg)
{
    const Zb_State *state = cfg->state;
    uint32_t deviceType = cfg->role == ZB_STACK_COORDINATOR ? NWK_DEVICE_COORDINATOR
                          : cfg->role == ZB_STACK_ROUTER   ? NWK_DEVICE_ROUTER
                                                           : NWK_DEVICE_END_DEVICE;

    if (state->version < ZB_STATE_VERSION_OLDEST || state->version > ZB_STATE_VERSION || state->deviceType != deviceType)
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->channel != 0 && state->channel != 0 && cfg->channel != state->channel)
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->role != ZB_STACK_COORDINATOR && zbStackStateKey(state) == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if ((cfg->ieee != 0 && cfg->ieee != state->ownIeee) || (cfg->panId != 0 && cfg->panId != state->panId)
        || (cfg->extendedPanId != 0 && cfg->extendedPanId != state->extendedPanId))
        return ZB_ERR_BAD_ARGUMENT;

    return ZB_OK;
}

/* The RCP at the config's path opened and armed on `armChannel`, or the caller's radio taken, for the bring-up. */
static ZbStatus zbStackOpen(Zb_Stack *self, const Zb_StackConfig *cfg, uint32_t armChannel)
{
    PortConfig portCfg;
    Radio_Pib channel;
    ZbStatus status;

    Zb_memset(self, 0, (uint32_t)sizeof *self);
    self->config = *cfg;
    self->phase = ZB_STACK_PHASE_BRINGUP;

    if (cfg->radio != 0)
    {
        self->radio = cfg->radio;
        return ZB_OK;
    }

    status = RcpRadio_Init(&self->rcp, Port_DefaultOps(), RCP_RADIO_REPLY_TIMEOUT_MS);

    if (status != ZB_OK)
        return status;

    zbStackPortConfig(self, &portCfg);
    status = RcpRadio_Open(&self->rcp, cfg->path, &portCfg);

    if (status != ZB_OK)
        return status;

    self->rcpOpen = 1;
    self->radio = RcpRadio_Seam(&self->rcp);

    /* The RCP arms on a channel, so it is named before the bring-up; the library states it again when it adopts. */
    Zb_memset(&channel, 0, (uint32_t)sizeof channel);
    channel.present = RADIO_PIB_CHANNEL;
    channel.channel = armChannel;

    status = self->radio->ops->pibSet(self->radio, &channel);

    if (status != ZB_OK)
    {
        RcpRadio_Close(&self->rcp);
        self->rcpOpen = 0;
        return status;
    }

    return ZB_OK;
}

ZbStatus Zb_StackStart(Zb_Stack *self, const Zb_StackConfig *cfg)
{
    uint32_t armChannel;
    ZbStatus status;

    if (self == 0 || cfg == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->role == ZB_STACK_COORDINATOR || (cfg->state != 0 && cfg->role <= ZB_STACK_END_DEVICE))
    {
        armChannel = zbStackNamedChannel(cfg);

        if (armChannel < ZB_STACK_CHANNEL_FIRST || armChannel > ZB_STACK_CHANNEL_LAST)
            armChannel = 0;
    }
    else if (cfg->role == ZB_STACK_ROUTER || cfg->role == ZB_STACK_END_DEVICE)
        armChannel = zbStackLowestChannel(cfg->channelMask);
    else
        armChannel = 0;

    if (cfg->role != ZB_STACK_COORDINATOR && cfg->state != 0 && cfg->channelMask != 0 && armChannel != 0
        && (cfg->channelMask & ((uint32_t)1 << armChannel)) == 0)
        armChannel = 0;

    if (armChannel == 0 || cfg->endpointCount > ZB_STACK_ENDPOINT_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->radio == 0 && (cfg->path == 0 || cfg->path[0] == 0))
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->state != 0)
    {
        status = zbStackStateFits(cfg);

        if (status != ZB_OK)
            return status;
    }

    return zbStackOpen(self, cfg, armChannel);
}

ZbStatus Zb_StackEnergyScan(Zb_Stack *self, const Zb_StackConfig *cfg, uint32_t channelMask, uint32_t scanDuration)
{
    uint32_t valid = 0;
    uint32_t channel;
    ZbStatus status;

    if (self == 0 || cfg == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->phase != ZB_STACK_PHASE_IDLE && self->phase != ZB_STACK_PHASE_FAILED
        && self->phase != ZB_STACK_PHASE_STOPPED)
        return ZB_ERR_BUSY;

    for (channel = ZB_STACK_CHANNEL_FIRST; channel <= ZB_STACK_CHANNEL_LAST; channel++)
        valid |= (uint32_t)1 << channel;

    if (channelMask == 0 || (channelMask & ~valid) != 0 || scanDuration > NWK_DISCOVERY_SCAN_DURATION_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->radio == 0 && (cfg->path == 0 || cfg->path[0] == 0))
        return ZB_ERR_BAD_ARGUMENT;

    status = zbStackOpen(self, cfg, zbStackLowestChannel(channelMask));

    if (status != ZB_OK)
    {
        self->phase = ZB_STACK_PHASE_IDLE;
        return status;
    }

    self->energyScan = 1;
    self->energyMask = channelMask;
    self->energyDuration = scanDuration;

    return ZB_OK;
}

void Zb_StackTurn(Zb_Stack *self, uint32_t nowMs)
{
    ZbStatus status;

    if (self == 0)
        return;

    self->lastNowMs = nowMs;

    /* An RCP that did not answer in time has been asked again, and the bring-up's deadline says when that is enough. */
    status = self->rcpOpen ? RcpRadio_Pump(&self->rcp, nowMs) : ZB_OK;

    if (status != ZB_OK && status != ZB_ERR_TIMEOUT && self->phase == ZB_STACK_PHASE_BRINGUP)
    {
        zbStackFail(self, RcpRadio_LastError(&self->rcp));
        return;
    }

    switch (self->phase)
    {
    case ZB_STACK_PHASE_BRINGUP:
        zbStackBringUp(self, nowMs);
        break;

    case ZB_STACK_PHASE_JOINING:
        (void)Zb_CoreStep(&self->core, nowMs);
        zbStackJoining(self);
        break;

    case ZB_STACK_PHASE_OPENING:
        (void)Zb_CoreStep(&self->core, nowMs);
        zbStackOpening(self, nowMs);
        break;

    case ZB_STACK_PHASE_UP:
        zbStackWatchPort(self, nowMs);
        zbStackWatchRcp(self);
        (void)Zb_CoreStep(&self->core, nowMs);
        break;

    case ZB_STACK_PHASE_SCANNING:
        (void)Zb_CoreStep(&self->core, nowMs);
        zbStackScanning(self);
        break;

    case ZB_STACK_PHASE_STOPPING:
        zbStackStopping(self);
        break;

    default:
        break;
    }
}

int Zb_StackPollEvent(Zb_Stack *self, Zb_StackEvent *out)
{
    Nwk_SourceRouteNotice notice;
    Zb_CoreDeparture departure;
    Nwk_AddressNotice pair;
    Nwk_SyncConfirmParameters sync;
    Aps_Confirm confirm;
    uint8_t capability = 0;
    uint32_t i;

    if (self == 0 || out == 0)
        return 0;

    if (self->lifecycleCount != 0)
    {
        *out = self->lifecycle[0];

        for (i = 1; i < self->lifecycleCount; i++)
            self->lifecycle[i - 1] = self->lifecycle[i];

        self->lifecycleCount--;
        return 1;
    }

    /* The library's rings are read one entry at a time, straight into the event, and only once the network is up. */
    if (self->phase != ZB_STACK_PHASE_UP)
        return 0;

    /* A send under the device object's own tag is an answer or an announcement: its outcome is not the application's */
    while (Zb_CorePollConfirms(&self->core, &confirm, 1) == 1)
    {
        if (confirm.srcEndpoint == ZDO_ENDPOINT && confirm.tag == ZB_STACK_TAG_DEVICE_OBJECT)
            continue;

        Zb_memset(out, 0, (uint32_t)sizeof *out);
        out->type = ZB_EVENT_SENT;
        out->sent = confirm;
        out->status = confirm.status;
        return 1;
    }

    Zb_memset(out, 0, (uint32_t)sizeof *out);

    if (Nwk_PollSourceRouteNotices(&Zb_CoreLayers(&self->core)->nwk, &notice, 1) == 1)
    {
        out->type = ZB_EVENT_ROUTE;
        out->route.destination = notice.destinationAddress;
        out->route.reason = notice.reason;
        out->route.relayCount = notice.relayCount;
        Zb_memcpy(out->route.relays, notice.relayList, notice.relayCount * (uint32_t)sizeof notice.relayList[0]);
        return 1;
    }

    if (Nwk_PollSyncConfirm(&Zb_CoreLayers(&self->core)->nwk, &sync) == 1)
    {
        out->type = ZB_EVENT_POLLED;
        out->status = sync.status;
        return 1;
    }

    if (Nwk_PollAddressNotices(&Zb_CoreLayers(&self->core)->nwk, &pair, 1) == 1)
    {
        out->type = ZB_EVENT_ADDRESS;
        out->address.networkAddress = pair.networkAddress;
        out->address.ieee = pair.extendedAddress;
        out->address.reason = pair.reason;
        return 1;
    }

    if (Zb_CorePollDepartures(&self->core, &departure, 1) == 1)
    {
        out->type = ZB_EVENT_DEVICE_LEFT;
        out->left.networkAddress = departure.networkAddress;
        out->left.ieee = departure.ieee;
        out->left.rejoin = departure.rejoin;
        out->left.reported = departure.reported;
        return 1;
    }

    if (Zb_CorePollIndications(&self->core, &out->data, 1) != 1)
        return 0;

    if (out->data.profileId == 0x0000 && out->data.clusterId == ZDO_DEVICE_ANNCE
        && Zdo_DeviceAnnouncementParse(out->data.asdu, out->data.asduLength, &out->joined.ieee,
                                       &out->joined.networkAddress, &capability) == ZB_OK)
    {
        out->type = ZB_EVENT_DEVICE_JOINED;
        out->joined.receiverOn = (capability & ZB_STACK_RECEIVER_ON) != 0;
        out->joined.capability = capability;
        return 1;
    }

    out->type = ZB_EVENT_DATA;
    return 1;
}

int Zb_StackNextEvent(Zb_Stack *self, Zb_StackEvent *out, uint32_t timeoutMs)
{
    uint32_t startMs;
    uint32_t nowMs;
    uint32_t waitMs;

    if (self == 0 || out == 0)
        return 0;

    if (Zb_StackPollEvent(self, out))
        return 1;

    if (!self->rcpOpen)
        return 0;

    startMs = Port_NowMs();
    nowMs = startMs;

    for (;;)
    {
        Zb_StackTurn(self, nowMs);

        if (Zb_StackPollEvent(self, out))
            return 1;

        if (!self->rcpOpen)
            return 0;

        nowMs = Port_NowMs();

        if (!Zb_timeWithin(nowMs, startMs, timeoutMs))
            return 0;

        waitMs = timeoutMs - (nowMs - startMs);

        if (waitMs > ZB_STACK_WAIT_MS)
            waitMs = ZB_STACK_WAIT_MS;

        if (Port_Wait(&self->rcp.port, waitMs) != ZB_OK)
            Port_SleepMs(waitMs);

        nowMs = Port_NowMs();
    }
}

ZbStatus Zb_StackApsRequest(Zb_Stack *self, const Aps_ApsdeReq *request)
{
    if (self == 0 || request == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->phase != ZB_STACK_PHASE_UP)
        return ZB_ERR_NOT_READY;

    if (request->tag == ZB_STACK_TAG_DEVICE_OBJECT)
        return ZB_ERR_BAD_ARGUMENT;

    return Zb_CoreSendRequest(&self->core, request, self->lastNowMs);
}

#if ZB_ZDO_CLIENT
/* The frame is the device object's counter and the request's fields, acknowledged when it is a unicast; the counter
   moves only when the request is taken. */
ZbStatus Zb_StackZdoRequest(Zb_Stack *self, uint16_t destination, uint16_t clusterId, const uint8_t *payload,
                         uint32_t payloadLen, uint16_t tag, uint8_t *transactionSequenceNumber)
{
    uint8_t asdu[ZDO_ASDU_MAX];
    Aps_ApsdeReq request;
    U_BStream stream;
    uint8_t number;
    ZbStatus status;

    if (self == 0 || transactionSequenceNumber == 0 || (payload == 0 && payloadLen != 0)
        || clusterId > ZDO_CLUSTER_LAST || tag == ZB_STACK_TAG_DEVICE_OBJECT)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->phase != ZB_STACK_PHASE_UP)
        return ZB_ERR_NOT_READY;

    if (payloadLen + 1 > (uint32_t)sizeof asdu)
        return ZB_ERR_NO_SPACE;

    number = Zdo_TransactionSequenceNumber(&self->core.zdo);
    U_bstream_init(&stream, asdu, (unsigned long)sizeof asdu);
    U_bstream_put_u8(&stream, number);

    if (payloadLen != 0)
        U_bstream_put_bytes(&stream, payload, (unsigned long)payloadLen);

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    request.dstAddrMode = APS_ADDR_MODE_SHORT;
    request.dstAddress = destination;
    request.dstEndpoint = ZDO_ENDPOINT;
    request.profileId = ZDO_PROFILE_ID;
    request.clusterId = clusterId;
    request.srcEndpoint = ZDO_ENDPOINT;
    request.asdu = asdu;
    request.asduLength = payloadLen + 1;
    request.txOptions = Nwk_AddrIsBroadcast(destination) ? 0 : APS_TX_OPTION_ACK;
    request.tag = tag;

    status = Zb_CoreSendRequest(&self->core, &request, self->lastNowMs);

    if (status != ZB_OK)
        return status;

    Zdo_AdvanceTransactionSequenceNumber(&self->core.zdo);
    *transactionSequenceNumber = number;

    return ZB_OK;
}
#endif

ZbStatus Zb_StackSetSourceRoute(Zb_Stack *self, uint16_t destination, const uint16_t *relays, uint32_t count)
{
    if (self == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->phase != ZB_STACK_PHASE_UP)
        return ZB_ERR_NOT_READY;

    return Nwk_SetSourceRoute(&Zb_CoreLayers(&self->core)->nwk, destination, relays, count, self->lastNowMs);
}

ZbStatus Zb_StackPoll(Zb_Stack *self)
{
    if (self == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->phase != ZB_STACK_PHASE_UP)
        return ZB_ERR_NOT_READY;

    if (self->config.role != ZB_STACK_END_DEVICE)
        return ZB_ERR_BAD_STATE;

    return Nwk_SyncRequest(&Zb_CoreLayers(&self->core)->nwk);
}

ZbStatus Zb_StackSetPollInterval(Zb_Stack *self, uint32_t intervalMs)
{
    if (self == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->phase != ZB_STACK_PHASE_UP)
        return ZB_ERR_NOT_READY;

    if (self->config.role != ZB_STACK_END_DEVICE)
        return ZB_ERR_BAD_STATE;

    Nwk_SetPollRate(&Zb_CoreLayers(&self->core)->nwk, intervalMs);

    return ZB_OK;
}

ZbStatus Zb_StackPermitJoining(Zb_Stack *self, uint8_t seconds)
{
    if (self == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->phase != ZB_STACK_PHASE_UP)
        return ZB_ERR_NOT_READY;

    return Zb_CorePermitJoining(&self->core, seconds, self->lastNowMs);
}

ZbStatus Zb_StackCapture(Zb_Stack *self, int includeKeys, Zb_State *out)
{
    if (self == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->phase != ZB_STACK_PHASE_UP)
        return ZB_ERR_NOT_READY;

    return Zb_LayersCapture(Zb_CoreLayers(&self->core), includeKeys, out);
}

ZbStatus Zb_StackStop(Zb_Stack *self)
{
    if (self == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->phase == ZB_STACK_PHASE_STOPPING || self->phase == ZB_STACK_PHASE_STOPPED)
        return ZB_OK;

    if (!self->rcpOpen)
    {
        self->phase = ZB_STACK_PHASE_STOPPED;
        zbStackPush(self, ZB_EVENT_STOPPED, ZB_OK);
        return ZB_OK;
    }

    (void)RcpRadio_Restart(&self->rcp, self->lastNowMs);
    self->stopTurns = ZB_STACK_STOP_TURNS;
    self->phase = ZB_STACK_PHASE_STOPPING;

    return ZB_OK;
}

Zb_Core *Zb_StackCore(Zb_Stack *self)
{
    return self ? &self->core : 0;
}
