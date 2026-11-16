#ifndef ZB_STACK_H
#define ZB_STACK_H

/* The Phoscon Zigbee Stack as an application meets it: one object, started with one config, reporting what happens as
   events. It owns the RCP, the port, the clock, entropy, bring-up and teardown, so an application is a small state
   machine over the events and nothing else (docs/internals/decisions.md). */

#include <stdint.h>

#include "aps.h"
#include "rcp_radio.h"
#include "zb_core.h"
#include "zb_status.h"

enum
{
    ZB_STACK_COORDINATOR = 0,       /* forms the network on `channel` and is its trust centre */
    ZB_STACK_ROUTER = 1,            /* joins a network found on `channelMask` and lets devices join through it */
    ZB_STACK_END_DEVICE = 2,        /* joins as a router does, its receiver always on, and routes nothing */

    ZB_STACK_ENDPOINT_MAX = AF_ENDPOINT_MAX,
    ZB_STACK_KEY_OCTETS = SECURITY_KEY_OCTETS,
    ZB_STACK_RELAY_MAX = NWK_MAX_SOURCE_ROUTE,  /* the relays a source route holds */
    ZB_STACK_ENERGY_MAX = 16,       /* the channels an energy scan reports, 11 to 26 */
    ZB_STACK_LIFECYCLE_MAX = 4,     /* lifecycle events waiting for NextEvent: start, join and stop come one at a time */
    ZB_STACK_TAG_DEVICE_OBJECT = ZDO_TAG_OWN
};

typedef enum Zb_StackEventType
{
    ZB_EVENT_NONE = 0,
    ZB_EVENT_NETWORK_UP = 1,        /* formed, or joined and holding the network key: `network` says which */
    ZB_EVENT_NETWORK_FAILED = 2,    /* the RCP did not come up, or the join ended without a network: `status` */
    ZB_EVENT_DEVICE_JOINED = 3,     /* a device announced itself: `joined`, and the Device_annce itself in `data` */
    ZB_EVENT_DATA = 4,              /* a frame for the application: `data` */
    ZB_EVENT_SENT = 5,              /* what became of a Zb_StackApsRequest: `sent` */
    ZB_EVENT_RCP_LOST = 6,        /* DEVICE_LOST: the RCP reset or went quiet; NO_DEVICE: its port went away. The
                                       stack brings it back by itself: arms it again, or opens the path again */
    ZB_EVENT_RCP_BACK = 7,        /* the RCP runs again, holding what the stack told it */
    ZB_EVENT_STOPPED = 8,           /* the RCP was reset and the port closed after Zb_StackStop */
    ZB_EVENT_ROUTE = 9,             /* a route record or a source route failure changed a source route: `route` */
    ZB_EVENT_DEVICE_LEFT = 10,      /* another device left: `left`. `rejoin` 1: it comes back with its key; `reported`
                                       1: its parent said so, informative only, no key may go on it (R23.1 10591) */
    ZB_EVENT_ADDRESS = 11,          /* the address map learned or changed a device's network address: `address` */
    ZB_EVENT_ENERGY_SCAN = 12,      /* a Zb_StackEnergyScan ended: `energy`, or ZB_ERR_UNSUPPORTED on a radio that
                                       measures nothing; ZB_EVENT_STOPPED follows */
    ZB_EVENT_POLLED = 13            /* a Zb_StackPoll ended: `status` ZB_OK when the parent sent a frame, ZB_ERR_NO_DATA
                                       when it held none, or why the poll failed */
} Zb_StackEventType;

/* Why the address map told a pair. A conflict is a network address a second extended address claimed; the map keeps
   the first holder, and the parent of an end device it is gives that device a new address, told in turn. */
enum
{
    ZB_ADDRESS_LEARNED = NWK_ADDRESS_NOTICE_LEARNED,
    ZB_ADDRESS_CHANGED = NWK_ADDRESS_NOTICE_CHANGED,
    ZB_ADDRESS_CONFLICT = NWK_ADDRESS_NOTICE_CONFLICT
};

/* Why a source route changed. A lifetime's expiry and the application's own Zb_StackSetSourceRoute are not told. */
enum
{
    ZB_ROUTE_LEARNED = NWK_SR_NOTICE_LEARNED,   /* a record gave a destination with no route its relays */
    ZB_ROUTE_CHANGED = NWK_SR_NOTICE_CHANGED,   /* a record gave it other relays */
    ZB_ROUTE_DIRECT = NWK_SR_NOTICE_DIRECT,     /* a record said it is reached directly: the route is gone */
    ZB_ROUTE_FAILED = NWK_SR_NOTICE_FAILED      /* a network status 0x0b said the route failed: it is gone */
};

/* A source route as the stack holds it: relays[0] next to the destination, relays[relayCount - 1] this device's
   neighbour, the order of a route record and of the frame. None when it is gone. */
typedef struct Zb_StackRoute
{
    uint16_t destination;
    uint32_t reason;
    uint32_t relayCount;
    uint16_t relays[ZB_STACK_RELAY_MAX];
} Zb_StackRoute;

typedef struct Zb_StackNetwork
{
    uint16_t networkAddress;
    uint16_t panId;
    uint64_t extendedPanId;
    uint32_t channel;
    uint64_t ieee;                  /* this device's extended address */
} Zb_StackNetwork;

typedef struct Zb_StackJoined
{
    uint16_t networkAddress;
    uint64_t ieee;
    int receiverOn;                 /* 1: a router or a mains device; 0: it sleeps, and its parent holds its frames */
    uint8_t capability;             /* the announcement's Capability Information octet, which receiverOn is bit 3 of */
} Zb_StackJoined;

typedef struct Zb_StackAddress
{
    uint16_t networkAddress;
    uint64_t ieee;
    uint32_t reason;
} Zb_StackAddress;

typedef struct Zb_StackLeft
{
    uint16_t networkAddress;
    uint64_t ieee;
    int rejoin;
    int reported;
} Zb_StackLeft;

/* One channel an energy scan measured: its peak in the radio's dBm, or `measured` 0 and no level when nothing was. */
typedef struct Zb_StackEnergyLevel
{
    uint8_t channel;
    int8_t dbm;
    uint8_t measured;
} Zb_StackEnergyLevel;

/* The channels the scan asked for, lowest first. */
typedef struct Zb_StackEnergy
{
    uint32_t count;
    Zb_StackEnergyLevel levels[ZB_STACK_ENERGY_MAX];
} Zb_StackEnergy;

typedef struct Zb_StackEvent
{
    Zb_StackEventType type;
    ZbStatus status;
    Zb_StackNetwork network;
    Zb_StackJoined joined;
    Aps_Indication data;
    Aps_Confirm sent;
    Zb_StackRoute route;
    Zb_StackLeft left;
    Zb_StackAddress address;
    Zb_StackEnergy energy;
} Zb_StackEvent;

/* What the application states once. Zb_StackCoordinatorDefaults, Zb_StackRouterDefaults and Zb_StackEndDeviceDefaults fill it; an
   application then names its port, its channel or channels, and its endpoints, and leaves the rest. */
typedef struct Zb_StackConfig
{
    const char *path;               /* the RCP's device node, or usb-serial:<serial> found wherever it is; never defaulted */
    uint32_t baud;                  /* 0: 115 200; a ConBee I or a RaspBee I runs at 57 600 */
    uint32_t role;                  /* ZB_STACK_COORDINATOR, ZB_STACK_ROUTER or ZB_STACK_END_DEVICE */

    uint32_t channel;               /* a coordinator's channel, and a restored router's or end device's; required
                                       unless `state` names one, which it then must not contradict */
    uint32_t channelMask;           /* a router's channels, bit n for channel n; required, a scan transmits on each */
    uint16_t panId;                 /* a coordinator's PAN; 0 draws one */
    uint64_t extendedPanId;         /* a coordinator's: 0 is its own address. A router's: 0 joins the best it hears */
    uint64_t ieee;                  /* this device's extended address; 0 is the RCP's own */
    uint32_t scanAttempts;          /* a router's scans before it chooses a network; 0 is the standard's 5 */
    uint32_t scanGapMs;             /* the time between them; 0 is the standard's 100 ms */

    uint8_t permitSeconds;          /* how long devices may join once the network is up; 0 keeps it closed */

    uint8_t networkKey[ZB_STACK_KEY_OCTETS];          /* a coordinator's; all zero draws a random one */
    uint8_t trustCentreLinkKey[ZB_STACK_KEY_OCTETS];  /* all zero is Zigbee 3.0's global key, ZigBeeAlliance09 */
    uint8_t linkKeySeed[ZB_STACK_KEY_OCTETS];         /* a coordinator's, its joiners' own link keys come from it:
                                                         all zero draws one, which a later boot cannot reproduce */
    uint16_t manufacturerCode;      /* the node descriptor's */
    int zdpUnsupportedToApplication; /* 1: a ZDP request the device object does not support is ZB_EVENT_DATA, which
                                        the application answers; 0: a unicast one is answered NOT_SUPPORTED */

    uint32_t endpointCount;
    Af_SimpleDescriptor endpoints[ZB_STACK_ENDPOINT_MAX];

    Radio_Radio *radio;             /* 0: the RCP at `path`. A radio of the caller's own, driven by Zb_StackTurn */
    /* 0: the port's entropy. The application's own source otherwise, `len` octets into `out`, ZB_OK when it filled
       them; the stack draws its seeds, a network key and a link key seed from it, so it must be a secure one */
    ZbStatus (*entropy)(void *context, uint8_t *out, uint32_t len);
    void *entropyContext;
    Log_Log *log;                   /* 0 records nothing; the application's pool, which it drains (log.h) */

    /* The network as Zb_StackCapture saved it, 0 to form or join one: the device comes back with the state's address,
       PAN, extended PAN and network key, a joiner on `channel` with no join. It is read once the RCP comes up, so it
       outlives ZB_EVENT_NETWORK_UP or ZB_EVENT_NETWORK_FAILED, which a state the restore refuses ends in. */
    const Zb_State *state;
    int announceAfterRestore;       /* a joiner restored from `state` sends a Device_annce, as many products do */
    int keepJoinedLinkKey;          /* a joiner's: 1 never asks for a trust centre link key of its own, as a device
                                       before Zigbee 3.0; 0 asks once joined and verifies it (R23.1 4.7.3.8) */

    int sleepy;                     /* an end device's: 1 rests its receiver and polls its parent for what it holds */
    uint32_t pollIntervalMs;        /* a sleepy device's polls once attached; 0 is 7.5 s. It polls at 250 ms while it
                                       attaches, whatever this says */
    int hearsWhileAsleep;           /* a sleepy device's: 1 keeps what the RCP heard between polls, for debugging;
                                       0 discards it, as a sleeping radio would not have heard it */
} Zb_StackConfig;

/* The object, the caller's memory: large, so static storage or the application's own state, never a small stack
   frame. Every field is the stack's own. */
typedef struct Zb_Stack
{
    Zb_StackConfig config;
    Rcp_Radio rcp;
    Radio_Radio *radio;
    Zb_Core core;

    uint32_t phase;
    uint32_t deadlineMs;
    int deadlineArmed;
    uint32_t lastNowMs;
    uint32_t stopTurns;
    uint64_t ieee;
    uint64_t extendedPanId;         /* the network's: a coordinator's own, or the one a router joined */
    uint8_t networkKey[ZB_STACK_KEY_OCTETS];
    int rcpOpen;
    int rcpRunning;
    int rcpGone;                  /* the port faulted: closed, and opened again at reopenAtMs */
    int rcpLostPort;              /* the loss being reported is the port's, not the RCP's own reset */
    uint32_t reopenAtMs;
    uint32_t rcpReopens;
    int coreRunning;
    int stopAsked;
    int energyScan;                 /* this run is a Zb_StackEnergyScan's, which forms and joins nothing */
    uint32_t energyMask;
    uint32_t energyDuration;

    Zb_StackEvent lifecycle[ZB_STACK_LIFECYCLE_MAX];
    uint32_t lifecycleCount;
} Zb_Stack;

void Zb_StackCoordinatorDefaults(Zb_StackConfig *cfg);
void Zb_StackRouterDefaults(Zb_StackConfig *cfg);
void Zb_StackEndDeviceDefaults(Zb_StackConfig *cfg);

/* Opens the RCP and starts the bring-up; what follows arrives as events. Before anything is armed, a config the
   stack cannot start from (no path, no channel, a router with no channels, a state of another role or one it
   contradicts) is ZB_ERR_BAD_ARGUMENT, and a port that does not open answers its own status. */
ZbStatus Zb_StackStart(Zb_Stack *self, const Zb_StackConfig *cfg);

/* NLME-ED-SCAN before a network forms: the RCP or radio `cfg` names comes up, each channel `channelMask` names (11
   to 26) is measured for ScanDuration `scanDuration` (0 to 14) and nothing is sent. ZB_ERR_BUSY while the stack runs,
   ZB_ERR_BAD_ARGUMENT for another mask or duration; role, channels and network in `cfg` are not read. */
ZbStatus Zb_StackEnergyScan(Zb_Stack *self, const Zb_StackConfig *cfg, uint32_t channelMask, uint32_t scanDuration);

/* Turns the stack until an event happens or `timeoutMs` passes, sleeping on the RCP in between: 1 with `out`
   written, 0 when nothing happened. A timeout of 0 turns once and does not wait. */
int Zb_StackNextEvent(Zb_Stack *self, Zb_StackEvent *out, uint32_t timeoutMs);

/* An APS data request from one of the configured endpoints, or from endpoint 0; its outcome is a ZB_EVENT_SENT under
   its tag. One to this device's own address is not sent but delivered here, a ZDP request to the device object. ZB_ERR_NOT_READY before the network is up, ZB_ERR_BAD_ARGUMENT for ZB_STACK_TAG_DEVICE_OBJECT, the tag the
   device object's own sends carry and whose outcomes are not the application's. */
ZbStatus Zb_StackApsRequest(Zb_Stack *self, const Aps_ApsdeReq *request);

#if ZB_ZDO_CLIENT
/* A ZDP request from endpoint 0, `payload` its fields (zdo_client.h), numbered by the device object into
   `*transactionSequenceNumber` and acknowledged when unicast; its answer is ZB_EVENT_DATA on profile 0 under that
   number, its outcome ZB_EVENT_SENT under `tag`. ZB_ERR_BAD_ARGUMENT for a response or the device object's tag. */
ZbStatus Zb_StackZdoRequest(Zb_Stack *self, uint16_t destination, uint16_t clusterId, const uint8_t *payload,
                         uint32_t payloadLen, uint16_t tag, uint8_t *transactionSequenceNumber);
#endif

/* A source route the application kept from a ZB_EVENT_ROUTE, held until a route record or a 0x0b replaces it; no
   relays remove it. ZB_ERR_NOT_READY before the network is up, ZB_ERR_BAD_STATE on an end device, ZB_ERR_NO_SPACE
   when the table is full, ZB_ERR_BAD_ARGUMENT for an address no device has, this one's, or too many relays. */
ZbStatus Zb_StackSetSourceRoute(Zb_Stack *self, uint16_t destination, const uint16_t *relays, uint32_t count);

/* A sleepy end device asks its parent for what it holds now, beside its own schedule; ZB_EVENT_POLLED follows.
   ZB_ERR_NOT_READY before the network is up, ZB_ERR_BAD_STATE on a device that is no end device, ZB_ERR_BUSY while
   an earlier poll is unanswered. */
ZbStatus Zb_StackPoll(Zb_Stack *self);

/* A sleepy end device's interval between polls from now on, 0 its default: shorter while it expects answers, longer
   again after. ZB_ERR_NOT_READY before the network is up, ZB_ERR_BAD_STATE on a device that is no end device. */
ZbStatus Zb_StackSetPollInterval(Zb_Stack *self, uint32_t intervalMs);

/* Opens joining for `seconds`, 0 closes it. ZB_ERR_NOT_READY before the network is up. */
ZbStatus Zb_StackPermitJoining(Zb_Stack *self, uint8_t seconds);

/* The network as it stands, for the application to keep and hand back as `state` at the next start: keys too when
   `includeKeys` is 1. ZB_ERR_NOT_READY before the network is up. */
ZbStatus Zb_StackCapture(Zb_Stack *self, int includeKeys, Zb_State *out);

/* Resets the RCP and closes the port; ZB_EVENT_STOPPED follows. */
ZbStatus Zb_StackStop(Zb_Stack *self);

/* For an integration that runs its own loop, its own radio, or both: one turn at the caller's time, and the next
   event if one is waiting, which is what Zb_StackNextEvent does with the port's clock and wait. */
void Zb_StackTurn(Zb_Stack *self, uint32_t nowMs);
int Zb_StackPollEvent(Zb_Stack *self, Zb_StackEvent *out);

/* The library under the stack, for what the stack does not wrap: binding, groups, leaving, the counters. */
Zb_Core *Zb_StackCore(Zb_Stack *self);

#endif /* ZB_STACK_H */
