#ifndef NWK_H
#define NWK_H

/*
 * Band A's NWK façade; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "mac.h"
#include "nwk_addr.h"
#include "nwk_beacon.h"
#include "nwk_btt.h"
#include "nwk_command.h"
#include "nwk_discovery.h"
#include "nwk_frame.h"
#include "nwk_indirect.h"
#include "nwk_neighbor.h"
#include "nwk_sourceroute.h"
#include "nwk_rreqtx.h"
#include "nwk_rx.h"
#include "nwk_route.h"
#include "security.h"
#include "zb_limits.h"
#include "zb_status.h"

/* 3.6.1.6.1.1's attach mechanism for an Initial Join: the parent's beacon chooses (Network Commissioning when it
   carries the R23 appendix, MAC association otherwise), or a bench forces one for a parent the rule would not. */
typedef enum Nwk_AttachMechanism
{
    NWK_ATTACH_BY_BEACON = 0,
    NWK_ATTACH_COMMISSIONING = 1,
    NWK_ATTACH_ASSOCIATION = 2
} Nwk_AttachMechanism;

/* The type and the two seeds are the config's, identity stays the MAC's PIB mirror (Table 3-75). */
typedef struct Nwk_Config
{
    uint32_t deviceType;            /* NWK_DEVICE_COORDINATOR, NWK_DEVICE_ROUTER or NWK_DEVICE_END_DEVICE */

    uint32_t seqStart;              /* the initial nwkSequenceNumber: 0x00-0xff, 0 a legal seed (Table 3-66) */

    uint32_t jitterSeed;            /* the seed of `Nwk_RelayJitterMs`: 0 disables jitter */

    uint32_t joinSeed;              /* 3.6.1.8's assignment seed, the application's entropy: 0 takes the house constant */

    uint32_t parentInformation;     /* 3.3.1.1.8's NIB field: non-zero sets the End Device Initiator bit on an end device */

    uint32_t attachMechanism;       /* Nwk_AttachMechanism: 0 lets the parent's beacon choose, as 3.6.1.6.1.1 does */

    uint32_t goodParentLqa;         /* Table 3-66's nwkGoodParentLQA: 0 takes its default, 75 */

    uint32_t endDeviceTimeout;      /* Table 3-58's enumeration an end device asks its parent for: 1 is two minutes */

    uint64_t trustCenterIeee;       /* the AIB's apsTrustCenterAddress (Table 4-35): 0 names none, which is 3.6.1.6.1.3's all-ones */

    uint32_t apsSecurityTimeOutPeriod; /* Table 4-35's attribute in seconds, the unit 3.6.1.6.1.1 counts in; 0 is 10 */

    uint32_t maxInitialJoinParentAttempts; /* Table 3-50's nwkMaxInitialJoinParentAttempts (0xC2): 0 is its default, 1 */

    uint32_t maxRejoinParentAttempts;      /* Table 3-50's nwkMaxRejoinParentAttempts (0xC3): 0 is its default, 3 */

    uint32_t indirectPollRateMs;    /* :Config_NWK_indirectPollRate: 0 takes NWK_POLL_RATE_DEFAULT_MS (nwk_poll.h) */
} Nwk_Config;

/* The AIB's apsTrustCenterAddress with no trust centre: 3.6.1.6.1.3's 0xFFFFFFFFFFFFFFFF, which a config that names
   0 takes. A macro and not an enumerator, for the reason `NWK_JOIN_SEED_DEFAULT` states: this value is no `int`. */
#define NWK_TRUST_CENTER_NONE 0xffffffffffffffff

/* Table 3-2, the NLDE-DATA.request parameters (3.2.1.1.1): its DstAddr, Nsdu, NsduLength, Radius, DiscoverRoute,
   SecurityEnable and the three alias rows are held and DstAddrMode is fixed at 0x02; NsduHandle is the row the record
   has not got, the handle the confirm answers with being the transmit this request became. */
typedef struct Nwk_DataRequestParameters
{
    uint16_t dstAddr;
    const uint8_t *nsdu;
    uint32_t nsduLength;
    uint8_t radius;
    uint32_t discoverRoute;
    int securityEnable;
    int useAlias;
    uint16_t aliasSrcAddr;
    uint32_t aliasSeqNumb;
} Nwk_DataRequestParameters;

/* `Nwk_TxCompose` names `Nwk_DataRequestParameters` and `Nwk_RelayJitterMs` names `Nwk_Config`: the SAP types come first. */

#include "nwk_beacon.h"
#include "nwk_relay.h"
#include "nwk_tx.h"

enum
{
    NWK_NSDU_MAX = 108,             /* Table 3-2/3-4: 127 - 0x0b - 0x08, Table 3-65's constants; refused, not truncated */
    NWK_INITIAL_RADIUS = 30,        /* 3.2.1.1.3: a requested Radius of zero is 2 * nwkcMaxDepth, 15 (Table 3-65) */
    NWK_UNICAST_RETRIES = 3,        /* nwkcUnicastRetries, Table 3-65: additional attempts, on top of the first (3.2.1.1.3) */

/* The relay's schedule is named by `nwk_relay.h`; the unicast retry law is still this façade's. */

/* R23.1 prints no pool size, so each is the house's: named, bounded, full is refusal-and-count (docs/internals/coding-rules.md §4.3). */
    /* the NLDE-DATA.indication ring: a house pool with the house's full policy (docs/internals/coding-rules.md §4.3) */
    NWK_INDICATION_MAX = ZB_LIMIT_NWK_INDICATION,

    NWK_SEQ_START = 0,              /* nwkSequenceNumber (NIB 0x81): what a zero-seeded config produces (Table 3-66) */
    NWK_SEQ_WRAP = 256,             /* 3.3.1.5: one octet, incremented by 1 with each new frame transmitted */

/* Sized to the pool that answers it and guarded at the door: a frame owed is in a slot or in the ring, never both (docs/internals/coding-rules.md §4.3) */
    NWK_CONFIRM_MAX = NWK_TX_MAX,

/* Device types, Table 3-75: configuration, never inferred from traffic */
    NWK_DEVICE_COORDINATOR = 0x00,
    NWK_DEVICE_ROUTER = 0x01,
    NWK_DEVICE_END_DEVICE = 0x02,

/* NWK layer status values, Table 3-84: the confirm's own `Status` vocabulary (3.2.1.2.1) */
    NWK_STATUS_SUCCESS = 0x00,
    NWK_STATUS_INV_REQUESTTYPE = 0xc2,          /* Table 3-84: "a request that is invalid or cannot be executed given the current state" */
    NWK_STATUS_UNSUPPORTED_ATTRIBUTE = 0xc9,    /* Table 3-84: 3.2.2.13's channel change a radio cannot be told to make */
    NWK_STATUS_NOT_PERMITTED = 0xc3,            /* Table 3-84: "an NLME-JOIN.request has been disallowed", Table 3-23's own name */
    NWK_STATUS_ROUTE_DISCOVERY_FAILED = 0xd0,   /* Table 3-84: a discovery that failed for a reason other than a lack of routing capacity */
    NWK_STATUS_ROUTE_ERROR = 0xd1,
    NWK_STATUS_BT_TABLE_FULL = 0xd2,            /* Table 3-84: "an attempt to send a broadcast frame has failed because there is no room in the BTT" */
    NWK_STATUS_FRAME_NOT_BUFFERED = 0xd3,       /* Table 3-84: "an NLDE-DATA.request has failed due to insufficient buffering available" */

/* Table 3-84's three security codes; Nwk_TxConfirmStatus ties them to the seam's words */
    NWK_STATUS_MAX_FRM_COUNTER = 0xcc,
    NWK_STATUS_NO_KEY = 0xcd,
    NWK_STATUS_BAD_CCM_OUTPUT = 0xce,

/* Not a printed code: 3.2.1.1.3 hands the last word to the MAC, folded at the seam (docs/internals/protocol.md §7.3) */
    NWK_STATUS_LAST_MAC_STATUS = 0xff,

    /* Table 3-54's identifiers and the Network Status payload status are named by `nwk_command.h`. */
};

/* A resting end device's polls, whose clauses nwk_poll.c cites: the rate while attaching, the default normal rate
   and NLME-SYNC's additional retries, the last two the house's and open. */
enum
{
    NWK_POLL_ATTACH_MS = 250,
    NWK_POLL_RATE_DEFAULT_MS = 7500,
    NWK_POLL_ADDITIONAL_RETRIES = 3
};

/* NLME-SYNC.confirm (Table 3-31): SUCCESS, or the last MLME-POLL.confirm's status. */
typedef struct Nwk_SyncConfirmParameters
{
    ZbStatus status;
} Nwk_SyncConfirmParameters;

/* 3.6.1.6.1's joining and 3.6.1.8's assignment: Table 3-74 prints a minimum of six discovery entries, and each
   other size here is the house's, named and bounded with the full policy of docs/internals/coding-rules.md §4.3. */
enum
{
    NWK_JOIN_PARENT_MAX = 6,
    NWK_GOOD_PARENT_LQA_DEFAULT = 75,       /* Table 3-66's nwkGoodParentLQA (0xBF) default */
    NWK_DISCOVERY_SCAN_DURATION_MAX = 14,   /* Table 3-11's ScanDuration range, 0x00 to 0x0e */
    NWK_DISCOVERY_SUPERFRAME_SYMBOLS = 960, /* aBaseSuperframeDuration, which ScanDuration's dwell is counted in */
    NWK_JOIN_INITIAL_ATTEMPTS_DEFAULT = 1,  /* Table 3-50's nwkMaxInitialJoinParentAttempts default */
    NWK_JOIN_REJOIN_ATTEMPTS_DEFAULT = 3,   /* and its nwkMaxRejoinParentAttempts default */
    NWK_JOIN_INDICATION_MAX = 8,
    NWK_JOIN_ADDRESS_TRIES = 64,
    NWK_JOIN_ADDRESS_MAX = 0xfff7,
    NWK_JOIN_STATUS_SUCCESS = 0x00,

    /* R23.1 prints no size for the status indication ring: bounded, named, full is refusal and count */
    NWK_STATUS_INDICATION_MAX = 4,

    /* 3.6.10.3's wait for the timeout response, macResponseWaitTime from the transmission, which is one more after
       the request was handed to the MAC */
    NWK_KEEPALIVE_RESPONSE_WAIT_MS = 2 * MAC_RESPONSE_WAIT_MS
};

/* Table 4-35's apsSecurityTimeOutPeriod default, 10 seconds, and the 0..255 Table 3-75 gives its countdown */
#define NWK_SECURITY_TIMEOUT_DEFAULT 10
#define NWK_SECURITY_TIMEOUT_MAX 255

/* 3.6.1.8's seed where the application names none: the golden ratio's fraction, so a zeroed config is never a
   generator stuck at its one fixed point. A macro because this value is no `int` and a C99 enumerator must be. */
#define NWK_JOIN_SEED_DEFAULT 0x9e3779b9

/* Table 3-3, the NLDE-DATA.confirm parameters (3.2.1.2.1): `status` is its Status row as the seam words it, beside
   `nwkStatus`, the same verdict in Table 3-84's codes; `handle` is its NsduHandle as the transmit the request became,
   and `dstAddr`, `seq` and `attempts` are this stack's; TxTime is absent. */
typedef struct Nwk_DataConfirmParameters
{
    ZbStatus status;
    uint32_t nwkStatus;
    uint16_t dstAddr;
    uint8_t seq;
    uint32_t attempts;
    Radio_Handle handle;
} Nwk_DataConfirmParameters;

/* Table 3-4, the NLDE-DATA.indication parameters (3.2.1.3.1), `nsdu` pointing into the receive's buffers until
   `Nwk_IndicationDone`; DstAddrMode and RxTime are absent, and `seq`, `radiusRemaining`, `frameType`,
   `commandIdentifier` and `wasBroadcast` are this stack's own. */
typedef struct Nwk_DataIndicationParameters
{
    uint16_t dstAddr;
    uint16_t srcAddr;
    uint8_t seq;
    uint8_t radiusRemaining;
    uint32_t frameType;
    uint32_t commandIdentifier;
    uint32_t lqi;
    const uint8_t *nsdu;
    uint32_t nsduLength;
    int wasBroadcast;
    int securityUsed;
} Nwk_DataIndicationParameters;

/* 3.6.4.8.1's failed link for a relay held for a resting child. */
typedef struct Nwk_RelayTrack
{
    int inUse;
    Radio_Handle handle;          /* the transmit the MAC ran for the relay, and the key its answer carries */
    uint16_t sourceAddr;          /* the failed frame's NWK source: 3.4.3.2 puts it in the status's header */
    uint16_t destAddr;            /* the failed frame's NWK destination: 3.4.3.3.2 puts it in the status's payload */
    uint16_t nextHop;             /* the broken link: what 3.6.4.8.1 invalidates the routing table against */
    uint32_t issuedMs;            /* when the relay was handed down, which a held one is aged out from */
} Nwk_RelayTrack;

/* 3.6.1.6.1's child half: where the device is in 10.21.2's exchange, and the state a rejoin would add. */
typedef enum Nwk_JoinState
{
    NWK_JOIN_IDLE = 0,
    NWK_JOIN_ASSOCIATING = 1,
    NWK_JOIN_JOINED = 2,
    NWK_JOIN_FAILED = 3,
    NWK_JOIN_REJOINING = 4,
    NWK_JOIN_COMMISSIONING = 5,
    NWK_JOIN_ORPHANING = 6
} Nwk_JoinState;

/* Table 3-74, the network discovery table entry: `extendedPanId`, `channel`, `shortAddress`, `lqa`, `updateId` and the
   appendix as `r23Appendix` and `routerInformation`'s bitmap, beside the beacon's `panId`, `extendedAddress`, `page`,
   `associationPermit`, `deviceType`, `rxOnWhenIdle`, `depth` and capacities; `inUse` and `shortKnown` are ours. */
typedef struct Nwk_JoinParent
{
    int inUse;
    uint8_t extendedPanId[8];
    uint16_t panId;
    uint16_t shortAddress;
    int shortKnown;
    uint64_t extendedAddress;
    uint32_t channel;
    uint32_t page;
    int associationPermit;
    uint32_t deviceType;
    int rxOnWhenIdle;
    int r23Appendix;
    uint32_t lqa;
    uint32_t updateId;
    uint16_t routerInformation;
    uint32_t depth;
    int routerCapacity;
    int endDeviceCapacity;
} Nwk_JoinParent;

/* Table 3-11, the NLME-NETWORK-AND-PARENT-DISCOVERY.request parameters (3.2.2.3): ScanChannelsListStructure as a
   mask of page 0's channels (bit n for channel n), ScanDuration's exponent, OnlyPermitJoinNetworks, OnlyEndDeviceCapacity,
   and this stack's keepTable: a repeat of the scan adds to what the last scans heard. */
typedef struct Nwk_NetworkDiscoveryRequestParameters
{
    uint32_t scanChannels;
    uint32_t scanDuration;
    int onlyPermitJoinNetworks;
    int onlyEndDeviceCapacity;
    int keepTable;
} Nwk_NetworkDiscoveryRequestParameters;

/* Table 3-12, the confirm (3.2.2.4): its Status, the MLME-SCAN.confirm's, and how many networks' parents the
   discovery table holds, which `Nwk_DiscoveryEntries` reads back as 3.2.2.4.3's NLME-GET of nwkDiscoveryTable. */
typedef struct Nwk_NetworkDiscoveryConfirmParameters
{
    uint8_t status;
    uint32_t entries;
} Nwk_NetworkDiscoveryConfirmParameters;

/* Table 3-19, the NLME-ED-SCAN.request parameters: ScanChannelsListStructure as a mask of page 0's
   channels (bit n for channel n) and ScanDuration's exponent. */
typedef struct Nwk_EdScanRequestParameters
{
    uint32_t scanChannels;
    uint32_t scanDuration;
} Nwk_EdScanRequestParameters;

/* Table 3-10's EnergyDetectChannelInfo, EnergyDetected in the radio's dBm rather than an octet and `measured` 0 for a
   channel no dwell measured, which then carries no level. */
typedef struct Nwk_EnergyDetectChannelInfo
{
    uint8_t channelPage;
    uint8_t channelNumber;
    int8_t energyDetected;
    uint8_t measured;
} Nwk_EnergyDetectChannelInfo;

/* Table 3-20, the NLME-ED-SCAN.confirm: its Status, the MLME-SCAN.confirm's, and Table 3-9's
   EnergyDetectListStructure, one entry per channel scanned, lowest first. */
typedef struct Nwk_EdScanConfirmParameters
{
    uint8_t status;
    uint32_t channelCount;
    Nwk_EnergyDetectChannelInfo channels[MAC_SCAN_CHANNEL_LAST - MAC_SCAN_CHANNEL_FIRST + 1];
} Nwk_EdScanConfirmParameters;

/* Where an end device's keepalive (3.6.10.3) is: owed, its poll's acknowledgement awaited, its timeout request
   waiting to go out, or the request's response awaited. */
typedef enum Nwk_Keepalive
{
    NWK_KEEPALIVE_NONE = 0,
    NWK_KEEPALIVE_OWED = 1,
    NWK_KEEPALIVE_POLLING = 2,
    NWK_KEEPALIVE_REQUESTING = 3,
    NWK_KEEPALIVE_AWAITING_RESPONSE = 4
} Nwk_Keepalive;

/* Table 3-21's RejoinNetwork values beside 0x00, an association */
enum
{
    NWK_JOIN_ORPHAN = 0x01,
    NWK_JOIN_REJOIN_NETWORK = 0x02,
    NWK_JOIN_CHANNEL_CHANGE = 0x03
};

/* Table 3-21, the NLME-JOIN.request parameters (3.2.2.13): its ExtendedPANId, RejoinNetwork, ScanChannels,
   ScanDuration, CapabilityInformation and SecurityEnable rows, in the table's order. */
typedef struct Nwk_JoinRequestParameters
{
    uint8_t extendedPanId[8];
    uint32_t rejoinNetwork;
    uint32_t scanChannels;
    uint32_t scanDuration;
    MacFrame_Capability capability;
    int securityEnable;
} Nwk_JoinRequestParameters;

/* Table 3-23, the NLME-JOIN.confirm parameters (3.2.2.15): `status`, `networkAddress`, `extendedPanId` and
   `channel` are its rows, the parent it was answered for is 10.21.2's record here, and `status` is Table 10-102's
   octet as the MAC reported it. */
typedef struct Nwk_JoinConfirmParameters
{
    uint32_t status;
    uint16_t networkAddress;
    uint8_t extendedPanId[8];
    uint32_t channel;
    uint16_t parentShort;
    int parentShortKnown;
    uint64_t parentExtended;
} Nwk_JoinConfirmParameters;

/* Table 3-22's JoinerMethod */
enum
{
    NWK_JOIN_METHOD_ASSOCIATION = 0x00,
    NWK_JOIN_METHOD_REJOIN_UNSECURED = 0x01,
    NWK_JOIN_METHOD_REJOIN_SECURED = 0x02,
    NWK_JOIN_METHOD_COMMISSIONING_JOIN = 0x03,
    NWK_JOIN_METHOD_COMMISSIONING_REJOIN = 0x04,
    NWK_JOIN_METHOD_COMMISSIONING_REJOIN_SECURED = 0x05
};

/* Table 3-22, the NLME-JOIN.indication parameters (3.2.2.14), in its order; JoiningDeviceTLVs is not kept. */
typedef struct Nwk_JoinIndicationParameters
{
    uint32_t interfaceIndex;
    uint16_t networkAddress;
    uint64_t extendedAddress;
    MacFrame_Capability capability;
    uint32_t joinerMethod;
} Nwk_JoinIndicationParameters;

/* Table 3-25's NLME-NWK-STATUS.indication: what a status this layer decided was worth telling the higher layer
   about, oldest first. */
typedef struct Nwk_NwkStatusIndication
{
    uint32_t status;
    uint16_t shortAddr;
} Nwk_NwkStatusIndication;

enum
{
    NWK_LEAVE_INDICATION_MAX = 4,   /* the leave indication ring's depth, this stack's own */
    NWK_LEAVE_COMMAND_OCTETS = 2,   /* Figure 3-14: the identifier octet and the command options octet */
    NWK_LEAVE_ADDRESS_OCTETS = 8,   /* the 64-bit address the leave request carries */
    NWK_LEAVE_RADIUS = 1,           /* 3.4.4.2's radius rule */

    /* Figure 3-15's three sub-fields, with the five reserved bits below them */
    NWK_LEAVE_OPTION_REJOIN = 0x20,
    NWK_LEAVE_OPTION_REQUEST = 0x40,
    NWK_LEAVE_OPTION_REMOVE_CHILDREN = 0x80,

    /* Table 3-26's DeviceAddress NULL */
    NWK_LEAVE_ADDRESS_NULL = 0,

    /* Table 3-28's Status values this stack can answer */
    NWK_LEAVE_STATUS_SUCCESS = 0,
    NWK_LEAVE_STATUS_INV_REQUESTTYPE = 1,
    NWK_LEAVE_STATUS_UNKNOWN_DEVICE = 2,
    NWK_LEAVE_STATUS_FRAME_NOT_BUFFERED = 3,      /* Table 3-84: a frame that could not be buffered for the air */
};

/* The leave command's three options read apart. */
typedef struct Nwk_LeaveCommand
{
    uint32_t rejoin;
    uint32_t request;
    uint32_t removeChildren;
} Nwk_LeaveCommand;

enum
{
    NWK_ADDRESS_NOTICE_MAX = 8,     /* the address notice ring's depth, this stack's own */

    /* Why the map told the higher layer of a pair, which keeps the mappings an application knows current */
    NWK_ADDRESS_NOTICE_LEARNED = 1, /* a pair the map had no row for */
    NWK_ADDRESS_NOTICE_CHANGED = 2, /* an extended address with another network address, or a row's unknown one */
    NWK_ADDRESS_NOTICE_CONFLICT = 3 /* a network address another extended address holds: the map keeps the first */
};

typedef struct Nwk_AddressNotice
{
    uint64_t extendedAddress;
    uint16_t networkAddress;
    uint32_t reason;
} Nwk_AddressNotice;

/* The parameters an indication to the next higher layer carries, and two Table 3-27 does not: the sender's network
   address, and whether it was this device's child, which a router reports to its trust centre. */
typedef struct Nwk_LeaveIndication
{
    uint64_t deviceAddress;
    uint16_t networkAddress;
    uint32_t child;
    uint32_t rejoin;
} Nwk_LeaveIndication;

typedef struct Nwk_Nwk
{
    Mac_Mac *mac;                 /* adopted, never owned: band A's MAC sits on a backend this module cannot see */
    Security *security;           /* adopted, never owned: it runs 4.3.1.1 and 4.3.1.2 on the application's keys */
    Nwk_Config cfg;
    uint64_t trustCenterIeee;     /* the AIB's apsTrustCenterAddress as 3.6.1.6.1.3 reads it: all ones is no trust centre */
    uint32_t seq;                 /* the sequence number the next frame this module composes will carry */

    /* This module's jitter generator state, advanced one draw per retransmission armed, reached through a pointer (docs/internals/coding-rules.md §4.2) */
    uint32_t jitterState;

    /* What the last accepted request became at the seam, or NONE if it ran none, and the sequence number it carries
       through every retry; `aps` pairs on the two */
    Radio_Handle lastRequestHandle;
    uint8_t lastRequestSeq;

    Nwk_Tx tx[NWK_TX_MAX];
    Nwk_NeighborTableEntry neighbors[NWK_NEIGHBOR_MAX];
    Nwk_SourceRouteEntry sourceRoutes[NWK_SOURCE_ROUTE_MAX];
    Nwk_AddressMapEntry addressMap[NWK_ADDR_MAP_MAX];   /* Table 3-66's nwkAddressMap, Table 3-68's rows */
    Nwk_RoutingTableEntry routes[NWK_ROUTE_MAX];
    Nwk_BroadcastTransactionRecord btt[NWK_BTT_MAX];
    Nwk_RouteDiscoveryTableEntry discoveries[NWK_DISCOVERY_MAX];

    /* 3.6.4.5.1's two counters: Table 3-79's request id incremented per initiation (3.4.1.3.2) and NIB 0xBE's
       routing sequence number */
    uint8_t routeRequestId;
    uint32_t routingSequenceNumber;

    /* 3.6.4.5.1's schedules, one record per discovery entry an initiation creates and keyed by
       (destination, request id): Table 3-79's pool size and its key, so the two tables cannot disagree */
    Nwk_RreqTx rreqTx[NWK_RREQ_TX_MAX];

    /* 3.6.4.5.1.4's relay schedules, keyed by (originator, request id): 9191-9192's pair, which speaks of
       "frames awaiting retransmission" in the plural and permits a discard only for that same pair */
    Nwk_RreqTx rreqRelay[NWK_RREQ_TX_MAX];

    /* 3.6.4.8.1's failed link for the relays held for a resting child, each with a record of its own, a held one's
       confirm naming it; a direct relay's record is its transmit slot. */
    Nwk_RelayTrack heldRelays[NWK_RELAY_HELD_MAX];
    uint32_t relaysHeldUntracked;
    uint32_t relaysHeldAgedOut;   /* held records no confirm ever closed, freed past the MAC's persistence */

    /* Confirmation ring, oldest first: the module's answer leaves the way `mac`'s queues do. */
    Nwk_DataConfirmParameters confirms[NWK_CONFIRM_MAX];
    uint32_t confirmHead;
    uint32_t confirmCount;
    uint32_t confirmsDropped;     /* an answer the ring had no room for, which is full as refusal and count */

    /* The one frame held for the layer above: the receive waits until it is done, and so does the step's rest */
    Nwk_DataIndicationParameters indication;
    int indicationHeld;
    int stepRestOwed;             /* the tasks after the receive, run once the receive has drained */
    uint32_t stepMs;              /* the time of the step a resumed receive belongs to */
    uint32_t stepReceived;        /* MAC frames this step has taken, at most one ring's worth */

    /* Scratch, not a pool: the MAC confirmations one drain took, overwritten by the next step */
    Mac_DataConfirmParameters macConfirms[MAC_TX_TRACK_MAX];

    /* The same for the MAC's other primitive: what became of a transaction an MLME response started */
    Mac_CommStatusParameters macCommStatus[MAC_COMM_STATUS_MAX];

    /* The same for the MLME-POLL.indication ring, which 3.6.10.4 reads */
    Mac_PollArrival macPolls[MAC_POLL_EVENT_MAX];

    /* Scratch, not a pool: the one delivered carrier being decided, taken from the MAC's ring one at a time */
    Mac_DataIndicationParameters macIndication;

    /* Scratch: the copy a unicast relay or a 3.6.13 reply is composed into and issued from, in one call */
    uint8_t relayNpdu[NWK_FRAME_NPDU_MAX];

    /* Scratch for the issue and the receipt running now: a secured form is never stored, and the buffer is NPDU-sized */
    uint8_t secureScratch[NWK_FRAME_NPDU_MAX];

    /* Scratch: the received payload decrypted, which nothing but the receive writes */
    uint8_t plainScratch[NWK_FRAME_NPDU_MAX];

    uint32_t refusedRequests;     /* requests this module declined, each with the reason it named counted here */
    uint32_t droppedNoRoute;      /* ROUTE_ERROR discards, and a received frame with no path onward (3.6.4.3, docs/internals/conformance.md §2) */
    uint32_t droppedEndDeviceInitiator; /* 3.3.1.1.8's exception: a router that cannot name the end device the frame came from */
    uint32_t confirmsIgnored;     /* Answers to transmits issued outside the transmit pool: a relay, a copy, a 3.6.13 reply */
    uint32_t commStatusSeen;      /* the MLME's indication for an MLME-instigated transaction, drained and recorded */
    uint32_t droppedMalformed;    /* A frame whose octets are not an NPDU this stack can read (3.6.2.2) */
    uint32_t droppedUnsupported;
    uint32_t droppedDuplicate;
    uint32_t droppedNotForMe;
    uint32_t droppedIndications;
    uint32_t droppedMulticast;    /* FCF bit 8 set: the destination field is a group id and no device address (3.6.7) */
    uint32_t droppedBadSource;    /* a NWK source that is a broadcast or reserved address, which Table 3-4 forbids */
    uint32_t lostChildrenDeleted; /* 3.6.2.3: entries still marked 0x07 when the window for APS processing closed */
    uint32_t bttFullDrops;        /* 3.6.6's full table, on receipt and on a broadcast this device cannot track */
    uint32_t relaysSent;
    uint32_t forwardsRefused;     /* unicasts this device owed the network with no transmit slot left to carry them */
    uint32_t forwardsGivenUp;     /* and those whose every attempt the radio refused, reported to their source when relayed */
    uint32_t recognizedCommands;  /* a Table 3-54 identifier this module handed up without acting on: 0x03, and any on a broadcast */
    uint32_t replyCommands;       /* the Network Status replies 3.6.13 required for an identifier it did not */
    uint32_t neighborAddsRefused; /* A neighbor heard with no room to record it (Table 3-84's NEIGHBOR_TABLE_FULL) */
    uint32_t rxSecurityFailures;  /* 4.3.1.2 steps 2, 5a and 6: no code in the corpus for any of them */
    uint32_t rxFrameCounterRejects; /* 4.3.1.2 steps 1 and 3: "bad frame counter" */
    uint32_t droppedUnsecured;    /* 3.6.2.2's unsecured discard, data frames and commands outside the carve-out alike (docs/internals/conformance.md §2) */
    uint32_t txSecurityFailures;  /* 4.3.1.1 steps 1, 4 and 6, with the over-ceiling refusal */
    uint32_t carrierOther;        /* A carrier `mac` delivered that is not a data frame: today the poll */
    uint32_t routeRequestsSent;   /* the Route Requests this device broadcast: its own schedule and the relays it owed */
    uint32_t routeRepliesSent;    /* the Route Replies 3.6.4.5.1.1 and 3.6.4.5.1.5 made this device compose */
    uint32_t routeRepliesForwarded; /* the Route Replies 3.6.4.5.2.1 made it carry on with 9225-9228's cost */
    uint32_t childDiscoveries;    /* 9037-9041: the discoveries started, or joined, for an end device child's frame */
    uint32_t childFramesHeld;     /* 9060: those frames held in a transmit slot for the route */

    /* 3.6.4.5.2's five printed discards, one counter per reason: the gate that refused and nothing else (docs/internals/conformance.md §2) */
    uint32_t rrepDroppedNoDiscovery;    /* 9231-9235, 9251-9253: Table 3-79 holds no entry for the reply's key */
    uint32_t rrepDroppedNoRoute;        /* 9237-9239: no routing entry for the responder; the discovery entry goes with it */
    uint32_t rrepDroppedNoReverseRoute; /* 9259-9260: a forwarder's entry with no routing entry, a SHOULD discard */
    uint32_t rrepDroppedNotSmaller;     /* 9246-9249, 9254-9256: the recorded cost is the smaller one */
    uint32_t rrepDroppedUnsuitable;     /* 3.6.4.5.3 step 2 with 9248 and 9256: the advertised route is not loop-free */
    uint32_t rrepDroppedNoCapacity;     /* 9224-9225: a reply at a device with no routing capacity */

    /* 3.6.4.5.1's five printed drops, one counter per reason: the gate that refused and nothing else (docs/internals/conformance.md §2) */
    uint32_t rreqDroppedEndDevice;       /* 9090: an end device drops every route request it receives */
    uint32_t rreqDroppedNoNeighbor;      /* 9120: no neighbor entry for the transmitting device */
    uint32_t rreqDroppedNoOutgoingCost;  /* 9121: the entry's outgoing cost is 0, which is no measurement */
    uint32_t rreqDroppedGreaterCost;     /* 9137: a copy whose forward cost is greater than Table 3-79's */
    uint32_t rreqDroppedNoDiscoverySlot; /* Table 3-79's pool is full: refusal-and-count (docs/internals/coding-rules.md §4.3) */

    /* 3.6.4.4.4's ageing, 3.6.4.8.1's failure signal and 3.6.6's passive acknowledgement, each counted once per event */
    uint32_t neighborsAgedOut;      /* entries whose outgoing cost the age retired: 0 is "no measurement" */
    uint32_t backbonePromotions;    /* 3.6.4.4.3.1's relationship changes, promotion and demotion together */
    /* The leave indication ring, oldest first, and the Boolean that says whether this device honours a leave
       request. */
    Nwk_LeaveIndication leaveIndications[NWK_LEAVE_INDICATION_MAX];
    uint32_t leaveIndicationHead;
    uint32_t leaveIndicationCount;
    uint32_t leaveIndicationsDropped;
    uint32_t leaveCommandsSent;     /* the leave commands this device put on the air */
    uint32_t leaveCommandsHeard;    /* the leave commands its receive pipeline read */
    uint32_t leavesTaken;           /* the departures this device carried out with no rejoin asked */
    int leaveRequestAllowed;      /* nwkLeaveRequestAllowed, TRUE from Table 3-66 until NLME-SET says otherwise */

    uint32_t linkStatusAtMs;        /* 3.6.4.4.1's next broadcast, 0 before the first turn */
    uint32_t activityDecayAtMs;     /* Table 3-75's next activity decrement, 0 before the first turn */
    int linkStatusContinues;        /* a list split over frames has more to send (3.4.8.3.2) */
    uint16_t linkStatusFromAddr;    /* the address the frame sent last ended on, which the next one starts on */
    uint32_t linkStatusSent;        /* the frames 3.6.4.4.1 put on the air */
    uint32_t linkStatusApplied;     /* the frames the metrics' clause applied to an entry */
    uint32_t sourceRoutesLearned;   /* 3.6.4.5.5's records stored, learned and updated together */
    Nwk_SourceRouteNotice sourceRouteNotices[NWK_SOURCE_ROUTE_NOTICE_MAX];  /* the table's changes, oldest first */
    uint32_t sourceRouteNoticeHead;
    uint32_t sourceRouteNoticeCount;
    uint32_t sourceRouteNoticesDropped;
    Nwk_AddressNotice addressNotices[NWK_ADDRESS_NOTICE_MAX];  /* the map's changes, oldest first */
    uint32_t addressNoticeHead;
    uint32_t addressNoticeCount;
    uint32_t addressNoticesDropped;
    uint32_t routeRecordsReceived;  /* every record this device was the destination of, a neighbour's empty one too */
    uint32_t routeRecordsRelayed;   /* the route record commands this device appended to and forwarded */
    uint32_t routeRecordsSent;      /* the route record commands this device initiated */
    uint32_t commissioningJoins;    /* 3.4.14's exchanges this device took part in, on either side */
    uint32_t childrenAgedOut;       /* 3.6.10.1's end device entries the timeout deleted */
    uint32_t keepalivesReceived;    /* 3.6.10.4's polls that restarted a child's Timeout Counter */
    uint32_t unknownPollLeaves;     /* 3.6.10.4.1's leave requests queued for a device polling with no entry */
    uint32_t unknownSenderLeaves;   /* 8678-8680's sent to an end device's marked frame with no entry */
    uint32_t timeoutResponsesSent;  /* 3.4.12's answers this device gave */
    uint32_t timeoutRequestsSent;   /* 3.4.11's requests this device sent after a join */
    int timeoutRequestPending;      /* the request a join or rejoin owes on the next turn */
    Nwk_Keepalive keepalive;        /* the keepalive 3.6.10.8 has a restored end device send first */
    Radio_Handle keepaliveHandle;   /* its poll's transmit, which the MAC's answer names */
    uint32_t keepaliveSinceMs;      /* the instant its timeout request went to the MAC */
    uint32_t keepalivesSent;
    uint32_t routesInvalidated;     /* entries 3.6.4.8.1 moved to Table 3-78's INACTIVE */
    uint32_t linkFailuresReported;  /* the 0x02 Network Status frames composed for a link that could not deliver */
    uint32_t statusRoutesRemoved;      /* 3.6.4.8.1's received-status removals: the entry a peer's route error named */
    uint32_t statusSourceRoutesRemoved; /* the source routes a 0x0b status removed */
    uint32_t passiveAckStops;       /* broadcast retransmissions withdrawn because a neighbour relayed the frame */
    uint32_t passiveAcksHeard;      /* 3.6.6's mark landed: a neighbour relayed a broadcast this device sent */
    uint32_t addressMapLearned;     /* 3.6.1.10.2's new rows and the rows it filled */
    uint32_t addressConflictsLocal; /* 3.6.1.10.2's conflict on this device's own address */
    uint32_t addressConflictsOther; /* 3.6.1.10.2's conflict on a third device's address */

    /* 3.6.1.10.5's broadcast: the address this device owes one for, the turn it goes out on, and what it has done */
    uint32_t conflictBroadcastAddress;
    uint32_t conflictBroadcastAtMs;
    int conflictBroadcastPending;
    uint32_t operatingSinceMs;      /* when this device began operating on the network, for 3.6.1.10.2's guard */
    uint32_t addressUpdatesSent;     /* 3.6.1.10.5's unsolicited rejoin responses, the parent's half */
    uint32_t addressUpdatesTaken;    /* and the child's: the new address an unsolicited response gave it */
    uint32_t parentLinkFailures;     /* 3.6.4.8.1's 0x09 indications an end device raised about its parent */
    uint32_t parentLinkHeld;         /* and the frames and keepalives the parent answered */

    /* A resting end device's polls: the rate, the attach rate asked from above, the MLME-POLL out and whether
       NLME-SYNC asked it, the re-poll a frame's Frame Pending owes, and NLME-SYNC's retries and its confirm. */
    uint32_t pollRateMs;
    int pollFast;
    int pollOut;
    int pollIsSync;
    int pollAgain;
    int pollLastKnown;
    uint32_t pollLastMs;
    int syncOwed;
    uint32_t syncRetries;
    Nwk_SyncConfirmParameters syncConfirm;
    int syncConfirmReady;
    uint32_t pollsSent;

    /* Table 3-25's NLME-NWK-STATUS.indication, which 3.6.1.10.5 makes the child's report of a new address */
    Nwk_NwkStatusIndication statusIndications[NWK_STATUS_INDICATION_MAX];
    uint32_t statusIndicationHead;
    uint32_t statusIndicationCount;
    uint32_t conflictBroadcastsSent;
    uint32_t conflictBroadcastsCancelled;

    /* 3.6.1.6.1's association, one state for the child and one set of doors for the parent; `joinSeedState` is
       3.6.1.8's generator, advanced one draw per address chosen (docs/internals/coding-rules.md §4.2). */
    Nwk_JoinState joinState;
    uint32_t joinSeedState;
    uint32_t joinParentShort;
    uint32_t joinAttemptMs;         /* 3.6.1.6.1.2: the instant the rejoin request went out, where its countdown starts */
    uint32_t joinPollMs;            /* 3.6.1.6.1.2's MLME-POLL.request: the instant the last Data Request went out */
    uint64_t joinParentExtended;
    int joinParentShortKnown;
    uint8_t joinExtendedPanId[8];
    uint32_t joinChannel;
    uint32_t joinScanChannels;      /* the request's ScanChannels, which every parent 3.6.1.6.1.1 tries is held to */
    uint32_t joinParentsTried;      /* one bit per `joinParents` entry this join has associated with */
    uint32_t joinAttempts;          /* and how many it has made, against Table 3-50's bound for its kind */
    uint32_t joinParentIndex;       /* the `joinParents` entry the attempt in flight went to */
    int joinConflictRetried;        /* 1 once that parent's 0xF0 address conflict has been asked again */
    uint8_t joinOwedNpdu[NWK_FRAME_NPDU_MAX]; /* one frame of this layer's own the transmit door had no room for */
    uint32_t joinOwedLen;
    uint32_t joinOwedSinceMs;
    uint16_t joinOwedNextHop;
    int joinOwedInUse;
    int joinOwedIndirect;
    int joinOwedCountdown;          /* 1 for a request whose answer's countdown starts when it goes out */
    uint32_t joinSendsDropped;      /* held frames the door still refused when MAC_ASSOC_SEND_WAIT_MS ran out */
    uint16_t joinRejoinSource;      /* the address a rejoin's requests come from, drawn once when the PIB holds none */
    int joinRejoinSecured;          /* the request's SecurityEnable, which every rejoin request it sends carries */
    int joinRejoinByCommissioning;  /* 1 while the rejoin's request is a Commissioning Request of type Rejoin */
    MacFrame_Capability joinCapability;
    Nwk_JoinConfirmParameters joinConfirm;
    int joinConfirmReady;
    int joinMethod;                 /* Table 3-22's JoinerMethod for the rejoin this device ran (1 unsecured, 2 secured) */

    Nwk_JoinIndicationParameters joinIndications[NWK_JOIN_INDICATION_MAX];
    uint32_t joinIndicationHead;
    uint32_t joinIndicationCount;

    /* 3.6.1.6.1.3: an association answered and not yet delivered, whose indication waits for MLME-COMM-STATUS */
    Nwk_JoinIndicationParameters joinPending[NWK_JOIN_INDICATION_MAX];
    int joinPendingInUse[NWK_JOIN_INDICATION_MAX];
    uint32_t joinResponsesDelivered;
    uint32_t joinResponsesUndelivered;

    Nwk_JoinParent joinParents[NWK_JOIN_PARENT_MAX];
    int discoveryRunning;
    Nwk_NetworkDiscoveryRequestParameters discoveryRequest;
    Nwk_NetworkDiscoveryConfirmParameters discoveryConfirm;
    int discoveryConfirmReady;
    int edScanRunning;
    Nwk_EdScanRequestParameters edScanRequest;
    uint32_t discoveryBeaconsTaken;
    uint32_t discoveryBeaconsDiscarded;
    uint32_t joinIndicationsDropped;
    uint32_t joinAddressesAssigned;
    uint32_t joinResponsesDropped;
    uint32_t joinCommandsDropped;   /* 3.6.1.6.1.2's 0x07 consumed and not accepted: an unsolicited or a malformed answer */
    uint32_t orphansRealigned;      /* orphan notifications from a child this parent holds, answered with a realignment */
    uint32_t orphansUnknown;        /* orphan notifications from a device this parent holds no child entry for */
    uint32_t joinRoutesDeleted;     /* 3.6.1.6.1.3's routing table search: the entries the accepted rejoin removed */
    uint32_t joinKeyTimeouts;       /* 3.6.1.6.1.1's NO_KEY: a join whose apsSecurityTimeOutPeriod passed with no key */
    uint32_t joinKeyConfirmsDropped; /* that confirmation with the slot still holding the one before it */
    uint32_t joinChildrenExpired;   /* 3.6.1.6.1.3's deletion: an unauthorized child whose SecurityTimer reached zero */
    uint32_t broadcastRetransmissions; /* 3.6.6's count for a broadcast this device sent, which is not a relay */

    int associationPermit;          /* macAssociationPermit as `Nwk_SetBeaconInfo` handed it to the MAC */

    /* The permit leg re-states the beacon, so the info this layer was last given is kept, and the countdown and its
       counters ride along. */
    Nwk_BeaconInfo beaconInfo;
    int beaconInfoKnown;
    uint32_t permitUntilMs;
    uint32_t permitRequests;
    uint32_t permitExpiries;
} Nwk_Nwk;

ZbStatus Nwk_Init(Nwk_Nwk *self, Mac_Mac *mac, const Nwk_Config *cfg);

/* R23.1 3.6.8.2 has this layer compose the Beacon Info Field and write it into macBeaconPayload, and D.11.1.5
   obliges coordinators and routers (and nobody else) to answer a request. So this call does both, and an end
   device enables nothing. */
ZbStatus Nwk_SetBeaconInfo(Nwk_Nwk *self, const Nwk_BeaconInfo *info, int associationPermit);

void Nwk_AttachSecurity(Nwk_Nwk *self, Security *security);

/* The AIB's apsTrustCenterAddress as this layer reads it, learned once a joining device is sent its key; 0 names none. */
void Nwk_SetTrustCenter(Nwk_Nwk *self, uint64_t trustCenterIeee);

/* Whether the neighbour table holds `extendedAddress` as a child still at relationship 0x05, the one a parent hands a
   tunnelled command to, and its network address. */
int Nwk_UnauthenticatedChildOf(const Nwk_Nwk *self, uint64_t extendedAddress, uint16_t *outAddress);

/* The module that call adopted, so a layer that issues a frame of its own can ask the one that will secure it */
const Security *Nwk_Security(const Nwk_Nwk *self);

/* 3.2.1.1.3's NLDE-DATA.request, composed and aimed per 3.6.4.3; docs/internals/conformance.md §2 owns the delivery policy. */
ZbStatus Nwk_DataRequest(Nwk_Nwk *self, const Nwk_DataRequestParameters *req, uint32_t nowMs);

/* One step of the protocol band, the only place the pipeline runs (docs/internals/coding-rules.md §4.7); while a frame
   is held its tasks after the receive wait for `Nwk_IndicationDone`, or for the next step if it is never done. */
ZbStatus Nwk_Step(Nwk_Nwk *self, uint32_t nowMs);

uint32_t Nwk_PollConfirms(Nwk_Nwk *self, Nwk_DataConfirmParameters *out, uint32_t max);

/* The frame the receive holds for the layer above, or 0; done, the receive takes the step's next frame. */
const Nwk_DataIndicationParameters *Nwk_Indication(const Nwk_Nwk *self);
void Nwk_IndicationDone(Nwk_Nwk *self);

/* How many entries the confirmation ring holds now, so a reader can take only those and leave what its own work adds. */
uint32_t Nwk_ConfirmsWaiting(const Nwk_Nwk *self);

/* Table 3-74's table, as the application fills it: a beacon heard is the discovery's, and a device that never
   scanned only has what it was told. */
ZbStatus Nwk_JoinParentAdd(Nwk_Nwk *self, const Nwk_JoinParent *entry);
uint32_t Nwk_JoinParentCount(const Nwk_Nwk *self);

/* 3.2.2.3's NLME-NETWORK-AND-PARENT-DISCOVERY.request: the discovery table emptied and an active scan of the channels
   asked that this PHY has, each beacon filtered by 3.6.1.5.1 into the table as it arrives. ZB_ERR_BAD_ARGUMENT for no
   such channel or a ScanDuration past 14 (INVALID_PARAMETER), ZB_ERR_BUSY while a discovery or join runs. */
ZbStatus Nwk_NetworkDiscoveryRequest(Nwk_Nwk *self, const Nwk_NetworkDiscoveryRequestParameters *req, uint32_t nowMs);

/* 3.2.2.4's confirm, once: 1 when it was taken, 0 while the scan runs. */
uint32_t Nwk_PollNetworkDiscoveryConfirm(Nwk_Nwk *self, Nwk_NetworkDiscoveryConfirmParameters *out);

/* The discovery table's entries, best-ranked first, at most `max`: the count copied. */
uint32_t Nwk_DiscoveryEntries(const Nwk_Nwk *self, Nwk_JoinParent *out, uint32_t max);

/* NLME-ED-SCAN.request: the MAC's ED scan of the channels asked. ZB_ERR_BAD_ARGUMENT for a channel this PHY
   lacks or a ScanDuration past 14 (INVALID_PARAMETER), ZB_ERR_BUSY while a scan or join runs, ZB_ERR_BAD_STATE on a
   network, which this stack does not leave to scan. */
ZbStatus Nwk_EdScanRequest(Nwk_Nwk *self, const Nwk_EdScanRequestParameters *req, uint32_t nowMs);

/* NLME-ED-SCAN.confirm, once: 1 when it was taken, 0 while the scan runs. */
uint32_t Nwk_PollEdScanConfirm(Nwk_Nwk *self, Nwk_EdScanConfirmParameters *out);

/* 3.2.2.13's NLME-JOIN.request: the association half of 3.6.1.6.1.1, whose outcome is `Nwk_PollJoinConfirm`'s. */
ZbStatus Nwk_JoinRequest(Nwk_Nwk *self, const Nwk_JoinRequestParameters *req, uint32_t nowMs);

/* 3.2.2.15's NLME-JOIN.confirm, once: 1 when it was taken and 0 when the exchange is still running. */
uint32_t Nwk_PollJoinConfirm(Nwk_Nwk *self, Nwk_JoinConfirmParameters *out);

Nwk_JoinState Nwk_JoinStateOf(const Nwk_Nwk *self);

/* 3.2.2.14's NLME-JOIN.indication, oldest first: the children this device answered for. */
uint32_t Nwk_PollJoinIndications(Nwk_Nwk *self, Nwk_JoinIndicationParameters *out, uint32_t max);
uint32_t Nwk_JoinIndicationQueue(const Nwk_Nwk *self);
uint32_t Nwk_JoinIndicationsDropped(const Nwk_Nwk *self);
uint32_t Nwk_JoinAddressesAssigned(const Nwk_Nwk *self);
uint32_t Nwk_JoinResponsesDropped(const Nwk_Nwk *self);

/* The 0x07 answers this device consumed without accepting one, and the routing entries an accepted rejoin removed */
uint32_t Nwk_JoinCommandsDropped(const Nwk_Nwk *self);
uint32_t Nwk_JoinRoutesDeleted(const Nwk_Nwk *self);

/* 3.6.1.6.1.1's NO_KEY outcome and 3.6.1.6.1.3's deletion, each counted where it happened. */
uint32_t Nwk_JoinKeyTimeouts(const Nwk_Nwk *self);
uint32_t Nwk_JoinSendsDropped(const Nwk_Nwk *self);
uint32_t Nwk_JoinKeyConfirmsDropped(const Nwk_Nwk *self);
uint32_t Nwk_JoinChildrenExpired(const Nwk_Nwk *self);

/* 3.6.6's retransmissions of a broadcast this device originated, which its relay counter does not hold. */
uint32_t Nwk_BroadcastRetransmissions(const Nwk_Nwk *self);

/* 3.6.6's passive acknowledgement, the half that was missing: the marks a neighbour's relay landed. */
uint32_t Nwk_PassiveAcksHeard(const Nwk_Nwk *self);

/* Table 3-66's nwkAddressMap: the rows, what learning them answered, and the two lookups 2.2.4.1.1.3's mode 0x03
   needs. `Nwk_AddrMapOf` is the pool itself, for a caller that wants to walk it. */
Nwk_AddressMapEntry *Nwk_AddrMapOf(Nwk_Nwk *self);
const Nwk_AddressMapEntry *Nwk_AddrMapConst(const Nwk_Nwk *self);
uint32_t Nwk_AddressMapLearned(const Nwk_Nwk *self);
uint32_t Nwk_AddressConflictsLocal(const Nwk_Nwk *self);
uint32_t Nwk_AddressConflictsOther(const Nwk_Nwk *self);
int Nwk_AddressOfIeee(const Nwk_Nwk *self, uint64_t extendedAddress, uint16_t *outAddress);

/* The address map's new pairs, changes and conflicts, oldest first, and the ones the full ring lost. */
uint32_t Nwk_PollAddressNotices(Nwk_Nwk *self, Nwk_AddressNotice *out, uint32_t max);
uint32_t Nwk_AddressNoticesDropped(const Nwk_Nwk *self);

/* The pair a Device_annce carries, which the ZDO hands down because a broadcast's header states no IEEE address. The
   row of that IEEE address follows its new network address; a pair that contradicts the map, or this device's own
   address, is a conflict and moves no row. All ones and this device's own IEEE address are not learned. */
void Nwk_AddressAnnounced(Nwk_Nwk *self, uint16_t networkAddress, uint64_t extendedAddress, uint32_t nowMs);

/* The same table read the other way, which 2.2.4.1.3.2 makes the APS layer's: a delivery whose source the map holds
   is indicated with its 64-bit address. */
int Nwk_IeeeOfAddress(const Nwk_Nwk *self, uint16_t networkAddress, uint64_t *outExtended);

/* Whether this device is part of a network at all: it holds a unicast address, which Table 3-66 bounds at 0xfff7. */
int Nwk_IsPartOfNetwork(const Nwk_Nwk *self);

/* 3.6.1.10.5's announcement of a conflict: what the jittered broadcast did. */
uint32_t Nwk_ConflictBroadcastsSent(const Nwk_Nwk *self);

/* Drain the status indications, oldest first, at most `max`, and the two counters 3.6.1.10.5's re-addressing has. */
uint32_t Nwk_PollStatusIndications(Nwk_Nwk *self, Nwk_NwkStatusIndication *out, uint32_t max);
uint32_t Nwk_AddressUpdatesSent(const Nwk_Nwk *self);
uint32_t Nwk_AddressUpdatesTaken(const Nwk_Nwk *self);
uint32_t Nwk_ConflictBroadcastsCancelled(const Nwk_Nwk *self);

/* 3.6.1.6.1.3's routing table search: the entry whose destination is that device is deleted whatever Table 3-78
   status it carries, and 1 is the count of the ones that were there. */
uint32_t Nwk_RouteDelete(Nwk_Nwk *self, uint16_t destAddr);

/* What the module holds and what it has done: the depth of each pool, and the counters. */
uint32_t Nwk_TransmitQueue(const Nwk_Nwk *self);
/* This device's own network address, which the same mirror carries. */
uint16_t Nwk_OwnAddress(const Nwk_Nwk *self);

/* The same address only when the PIB holds one in Table 3-68's unicast range: 0 for a device that has none yet. */
int Nwk_OwnAddressKnown(const Nwk_Nwk *self, uint16_t *outAddress);

/* This device's own extended address, which the PIB mirror the MAC carries. */
uint64_t Nwk_OwnExtendedAddress(const Nwk_Nwk *self);

uint32_t Nwk_NeighborQueue(const Nwk_Nwk *self);

/* What the layer sent and applied, the promotions it made, and the rank it gave one entry. */
uint32_t Nwk_LinkStatusSent(const Nwk_Nwk *self);
uint32_t Nwk_LinkStatusApplied(const Nwk_Nwk *self);
uint32_t Nwk_BackbonePromotions(const Nwk_Nwk *self);
uint32_t Nwk_NeighborRankOf(const Nwk_Nwk *self, uint16_t address);

/* 3.6.4.5.5's two counters: the records stored at a destination and the commands relayed toward one. */
uint32_t Nwk_TimeoutRequestsSent(const Nwk_Nwk *self);
uint32_t Nwk_TimeoutResponsesSent(const Nwk_Nwk *self);
uint32_t Nwk_ChildrenAgedOut(const Nwk_Nwk *self);
uint32_t Nwk_KeepalivesReceived(const Nwk_Nwk *self);
uint32_t Nwk_UnknownPollLeaves(const Nwk_Nwk *self);
uint32_t Nwk_ParentLinkFailures(const Nwk_Nwk *self);
uint32_t Nwk_ParentLinkHeld(const Nwk_Nwk *self);
uint32_t Nwk_PollsSent(const Nwk_Nwk *self);

/* NLME-SYNC.request: one MLME-POLL to the parent, asked again up to NWK_POLL_ADDITIONAL_RETRIES times on
   TRANSACTION_OVERFLOW or CHANNEL_ACCESS_FAILURE. ZB_ERR_BAD_STATE on a device that is no joined end device, and
   ZB_ERR_BUSY while an earlier request is unconfirmed. */
ZbStatus Nwk_SyncRequest(Nwk_Nwk *self);

/* 1 when NLME-SYNC.confirm was taken. */
uint32_t Nwk_PollSyncConfirm(Nwk_Nwk *self, Nwk_SyncConfirmParameters *out);

/* :Config_NWK_indirectPollRate at run time, 0 its default; and the attach rate, which the layer above asks while it
   negotiates or receives a fragmented message. */
void Nwk_SetPollRate(Nwk_Nwk *self, uint32_t rateMs);
void Nwk_SetPollFast(Nwk_Nwk *self, int fast);
uint32_t Nwk_KeepalivesSent(const Nwk_Nwk *self);
uint32_t Nwk_UnknownSenderLeaves(const Nwk_Nwk *self);
uint32_t Nwk_SourceRoutesLearned(const Nwk_Nwk *self);

/* The higher layer's source route to `destination` (Nwk_SourceRouteSeed), the relay next to it first; no relays let
   the row go. ZB_ERR_BAD_ARGUMENT for a destination or a relay that is no device's address, this device's own, or
   a relay that is the destination; ZB_ERR_BAD_STATE on a device without routing duty. */
ZbStatus Nwk_SetSourceRoute(Nwk_Nwk *self, uint16_t destination, const uint16_t *relays, uint32_t count, uint32_t nowMs);

/* The source route table's changes, oldest first, and the ones the full ring lost. */
uint32_t Nwk_PollSourceRouteNotices(Nwk_Nwk *self, Nwk_SourceRouteNotice *out, uint32_t max);
uint32_t Nwk_SourceRouteNoticesDropped(const Nwk_Nwk *self);
uint32_t Nwk_RouteRecordsReceived(const Nwk_Nwk *self);
uint32_t Nwk_RouteRecordsSent(const Nwk_Nwk *self);
uint32_t Nwk_RouteRecordsRelayed(const Nwk_Nwk *self);
uint32_t Nwk_RouteQueue(const Nwk_Nwk *self);
uint32_t Nwk_DiscoveryQueue(const Nwk_Nwk *self);
uint32_t Nwk_BttQueue(const Nwk_Nwk *self);
uint32_t Nwk_ConfirmQueue(const Nwk_Nwk *self);

/* Answers the confirmation ring had no room for, which is the one outcome a full pool may not swallow silently. */
uint32_t Nwk_ConfirmsDropped(const Nwk_Nwk *self);
uint32_t Nwk_IndicationQueue(const Nwk_Nwk *self);

/* The handle the most recent accepted `Nwk_DataRequest` became, or RADIO_HANDLE_NONE when it ran no
   transmit: the other half of the pairing `Nwk_DataConfirmParameters.handle` starts. */
Radio_Handle Nwk_LastRequestHandle(const Nwk_Nwk *self);

/* The sequence number the most recent accepted `Nwk_DataRequest` was composed with (3.6.2.1), which its confirm
   carries as `seq` whether or not a transmit ran, 3.2.1.1.3's retries re-sending the same frame. */
uint8_t Nwk_LastRequestSeq(const Nwk_Nwk *self);

uint32_t Nwk_RefusedRequests(const Nwk_Nwk *self);
uint32_t Nwk_DroppedNoRoute(const Nwk_Nwk *self);
uint32_t Nwk_DroppedEndDeviceInitiator(const Nwk_Nwk *self);
uint32_t Nwk_ConfirmsIgnored(const Nwk_Nwk *self);

/* How many MLME-COMM-STATUS indications this module drained: the outcome of a transaction an MLME response
   started, which no NLME primitive of this stack consumes yet. */
uint32_t Nwk_CommStatusSeen(const Nwk_Nwk *self);

/* 3.6.1.6.1.3's two outcomes of an association answer: delivered, so the join was indicated, or not, so the procedure
   ended and the child's entry went with it. */
uint32_t Nwk_JoinResponsesDelivered(const Nwk_Nwk *self);
uint32_t Nwk_JoinResponsesUndelivered(const Nwk_Nwk *self);
uint32_t Nwk_DroppedMalformed(const Nwk_Nwk *self);
uint32_t Nwk_DroppedUnsupported(const Nwk_Nwk *self);
uint32_t Nwk_DroppedDuplicate(const Nwk_Nwk *self);
uint32_t Nwk_DroppedNotForMe(const Nwk_Nwk *self);
uint32_t Nwk_DroppedIndications(const Nwk_Nwk *self);
uint32_t Nwk_DroppedMulticast(const Nwk_Nwk *self);
uint32_t Nwk_DroppedBadSource(const Nwk_Nwk *self);
uint32_t Nwk_LostChildrenDeleted(const Nwk_Nwk *self);
uint32_t Nwk_BttFullDrops(const Nwk_Nwk *self);
uint32_t Nwk_RelaysSent(const Nwk_Nwk *self);
uint32_t Nwk_RecognizedCommands(const Nwk_Nwk *self);
uint32_t Nwk_ReplyCommands(const Nwk_Nwk *self);
uint32_t Nwk_NeighborAddsRefused(const Nwk_Nwk *self);

uint32_t Nwk_RxSecurityFailures(const Nwk_Nwk *self);
uint32_t Nwk_RxFrameCounterRejects(const Nwk_Nwk *self);
uint32_t Nwk_DroppedUnsecured(const Nwk_Nwk *self);
uint32_t Nwk_TxSecurityFailures(const Nwk_Nwk *self);

/* Carriers `mac` delivered that its own header said were not data frames */
uint32_t Nwk_CarrierOther(const Nwk_Nwk *self);

/* The Route Requests this device put on the air: its own discovery's schedule, and the relays 3.6.4.5.1.4 owed */
uint32_t Nwk_RouteRequestsSent(const Nwk_Nwk *self);

/* The Route Replies this device composed and issued (3.6.4.5.1.1, 3.6.4.5.1.5) */
uint32_t Nwk_RouteRepliesSent(const Nwk_Nwk *self);

/* The Route Replies it forwarded for somebody else's discovery, with 9225-9228's cost in the path cost field */
uint32_t Nwk_RouteRepliesForwarded(const Nwk_Nwk *self);
uint32_t Nwk_ChildDiscoveries(const Nwk_Nwk *self);
uint32_t Nwk_ChildFramesHeld(const Nwk_Nwk *self);

/* What a received route reply met, one read per printed branch: 3.6.4.5.2's four discards and 9225's gate */
uint32_t Nwk_RrepDroppedNoDiscovery(const Nwk_Nwk *self);
uint32_t Nwk_RrepDroppedNoRoute(const Nwk_Nwk *self);
uint32_t Nwk_RrepDroppedNoReverseRoute(const Nwk_Nwk *self);
uint32_t Nwk_RrepDroppedNotSmaller(const Nwk_Nwk *self);
uint32_t Nwk_RrepDroppedUnsuitable(const Nwk_Nwk *self);

/* 9224-9225: a received route reply at a device that has no routing capacity */
uint32_t Nwk_RrepDroppedNoCapacity(const Nwk_Nwk *self);

/* What a received route request met, one read per printed branch: the five drops of 3.6.4.5.1's reception */
uint32_t Nwk_RreqDroppedEndDevice(const Nwk_Nwk *self);
uint32_t Nwk_RreqDroppedNoNeighbor(const Nwk_Nwk *self);
uint32_t Nwk_RreqDroppedNoOutgoingCost(const Nwk_Nwk *self);
uint32_t Nwk_RreqDroppedGreaterCost(const Nwk_Nwk *self);
uint32_t Nwk_RreqDroppedNoDiscoverySlot(const Nwk_Nwk *self);

/* The passive acknowledgements that ended a broadcast's retransmissions (3.6.6) */
uint32_t Nwk_PassiveAckStops(const Nwk_Nwk *self);

/* The routing entries and the source routes a received Network Status removed */
uint32_t Nwk_StatusRoutesRemoved(const Nwk_Nwk *self);
uint32_t Nwk_StatusSourceRoutesRemoved(const Nwk_Nwk *self);

/* The neighbours the age retired, the routes a broken link invalidated, and the 0x02 statuses it composed */
uint32_t Nwk_NeighborsAgedOut(const Nwk_Nwk *self);
uint32_t Nwk_RoutesInvalidated(const Nwk_Nwk *self);
uint32_t Nwk_LinkFailuresReported(const Nwk_Nwk *self);

/* Suite hook: one draw on this struct's own state, exactly as arming a retransmission arms the next */
uint32_t Nwk_TestJitterMs(Nwk_Nwk *self);

#endif /* NWK_H */
