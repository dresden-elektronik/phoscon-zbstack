#ifndef ZB_CORE_H
#define ZB_CORE_H

/*
 * The surface an application stands on: the stack, the endpoint registry the device object answers from, the device
 * object itself and one binding table the service searches and the object fills.
 * An application registers 2.3.2.5's simple descriptors, sends through one door, and polls one ring; it never
 * allocates or steps a layer, and endpoint 0 never reaches it (docs/internals/decisions.md D-210, D-212).
 * docs/internals/conformance.md §7 owns the clause marks; docs/internals/architecture.md §5 the module's duty.
 */

#include <stdint.h>

#include "af.h"
#include "aps.h"
#include "aps_bind.h"
#include "radio.h"
#include "zb_limits.h"
#include "zdo.h"
#include "zb_layers.h"

enum
{
    /* the ASDUs no endpoint took, waiting for the application's poll */
    ZB_CORE_INDICATION_MAX = ZB_LIMIT_CORE_INDICATION,
    /* the joiners whose parent a trust centre keeps; full evicts the oldest note */
    ZB_CORE_JOINER_MAX = ZB_LIMIT_CORE_JOINER,
    ZB_CORE_KEY_OWED_MAX = 4,      /* the joiners owed a network key and waiting out the settle; full refuses the newest */
    ZB_CORE_DEPARTURE_MAX = 8      /* the departures waiting for the application's poll; full counts the newest */
};

/* Another device that left: its leave command heard (3.6.1.11.3's NLME-LEAVE.indication, with its rejoin flag), or
   `reported`, a router's Device Left for a child that left without rejoin (11973-11978), which 10591-10593 make
   informative: no security action is taken on it. */
typedef struct Zb_CoreDeparture
{
    uint64_t ieee;
    uint16_t networkAddress;
    int rejoin;
    int reported;
} Zb_CoreDeparture;

/* A device that joined, and the parent it joined through with that parent's network address, as a trust centre
   learned them from an update-device indication; `order` is when, for the eviction. */
typedef struct Zb_CoreJoiner
{
    uint64_t deviceIeee;
    uint64_t parentIeee;
    uint16_t parentShort;
    uint32_t order;
    int inUse;
} Zb_CoreJoiner;

/* A joiner a trust centre owes the network key: where it goes, the router that reported it when the key is tunnelled,
   and when the join was heard, since the key waits a turn for the association's own exchange to end. */
typedef struct Zb_CoreKeyOwed
{
    uint64_t deviceIeee;
    uint16_t deviceShort;
    uint64_t parentIeee;
    uint16_t parentShort;
    int tunnel;
    uint32_t armedMs;
    int inUse;
} Zb_CoreKeyOwed;

/* The join door's request: the network by its extended PAN identifier, 0 for whichever the discovery ranks first, the
   channels the discovery visits (bit n for channel n, named by the caller: a scan transmits on every one), 3.2.2.3's
   ScanDuration exponent, and Table 2-135's two attributes for repeating the scan, 0 for the defaults it prints. */
enum
{
    ZB_CORE_SCAN_ATTEMPTS_DEFAULT = 5,
    ZB_CORE_SCAN_ATTEMPTS_MAX = 255,
    ZB_CORE_SCAN_GAP_DEFAULT_MS = 100,  /* Table 2-135's 0xc35 OctetDurations at 32 microseconds each */
    ZB_CORE_SCAN_DURATION_DEFAULT = 3,  /* D.9's ScanDuration for this band, a rejoin's when no join named one */

    /* 2.5.4.5.5.2 leaves the three to the application: this stack's defaults */
    ZB_CORE_PARENT_LINK_RETRY_THRESHOLD_DEFAULT = 3,
    ZB_CORE_REJOIN_INTERVAL_DEFAULT_MS = 10000,
    ZB_CORE_MAX_REJOIN_INTERVAL_DEFAULT_MS = 900000,

    /* 4.7.3.8 asks a joiner to update its trust centre link key and prints no timing: this stack's own numbers, how
       long one Request-Key waits for its Confirm-Key and how many are sent before the joined key is kept */
    ZB_CORE_TC_LINK_KEY_WAIT_MS = 5000,
    ZB_CORE_TC_LINK_KEY_ATTEMPTS = 3,
    ZB_CORE_TC_LINK_KEY_RETRY_MS = 100     /* a Request-Key the APS door had no room for is asked again after this */
};

typedef struct Zb_CoreJoinParameters
{
    uint64_t extendedPanId;
    uint32_t scanChannels;
    uint32_t scanDuration;
    uint32_t scanAttempts;          /* :Config_NWK_Scan_Attempts, 1 to 255; 0 is 5 */
    uint32_t scanGapMs;             /* :Config_NWK_Time_btwn_Scans; 0 is 100 ms */
} Zb_CoreJoinParameters;

/* Where the join door is: idle, discovering, joining, and joined to a secured network but waiting for its key. */
typedef enum Zb_CoreJoinState
{
    ZB_CORE_JOIN_IDLE = 0,
    ZB_CORE_JOIN_DISCOVERING = 1,
    ZB_CORE_JOIN_JOINING = 2,
    ZB_CORE_JOIN_KEY_WAIT = 3,
    ZB_CORE_JOIN_SCAN_GAP = 4,
    ZB_CORE_JOIN_REJOINING = 5,
    ZB_CORE_JOIN_REJOIN_DISCOVERING = 6
} Zb_CoreJoinState;

/* What a join came to: Table 3-23's status (or the discovery's, when it found nothing to join), the address and the
   network joined, its channel, and how many potential parents the discovery kept. */
typedef struct Zb_CoreJoinResult
{
    uint8_t status;
    uint16_t networkAddress;
    uint64_t extendedPanId;
    uint32_t channel;
    uint32_t parentsHeard;
} Zb_CoreJoinResult;

/* The stack's own config, plus the two descriptors the device object advertises about the device as a whole.
   Endpoints are the application's, registered after init. */
typedef struct Zb_CoreConfig
{
    Zb_LayersConfig layers;
    Zdo_NodeDescriptor node;
    Zdo_PowerDescriptor power;

    /* Which arm a group frame with no member takes: `APS_GROUP_DELIVERY_MEMBERS` is 2.2.8.4.2's and the zero value
       every config starts at, `APS_GROUP_DELIVERY_UNFILTERED` hands the application every group frame once, and
       `APS_GROUP_DELIVERY_ENDPOINTS` once per registered endpoint whose profile is the frame's. */
    uint32_t groupDelivery;

    /* A ZDP request the device object does not support: 0 answers a unicast one with NOT_SUPPORTED, 1 hands
       it to the application as an indication, which then owes the answer. */
    int zdpUnsupportedToApplication;

    /* The network key this device holds, and its sequence number: all zero means an unsecured network, which is what
       a scaffold wants and no product does. */
    uint8_t networkKey[SECURITY_KEY_OCTETS];
    uint8_t networkKeySeq;

    /* The trust-centre link key, all zero when this device is nobody's trust centre. A device that joins without a
       pair of its own is answered with this one, which is how a coordinator hands the network key to a device it has
       never met. */
    uint8_t trustCentreLinkKey[SECURITY_KEY_OCTETS];

    /* The seed a trust centre derives each device's own trust-centre link key from when that device asks for one
       (D-218). All zero answers no request: the application draws it, the library never does (D-56). */
    uint8_t linkKeySeed[SECURITY_KEY_OCTETS];

    /* This device is the trust centre: a device that joins is sent the network key, and the application cannot
       forget it. */
    int transportNetworkKey;

    /* The tree depth the beacon states. The stack does not record its own depth, so a router says what it knows and a
       coordinator says 0. */
    uint8_t depth;

    /* An end device that loses its parent (2.5.4.5.5.2): the failures it takes before it rejoins, and the gap between
       two rejoins, doubled after each that fails up to the maximum; 0 for the defaults above. */
    uint32_t parentLinkRetryThreshold;
    uint32_t rejoinIntervalMs;
    uint32_t maxRejoinIntervalMs;

    /* A joiner's trust centre link key update (4.7.3.8): 1 asks for its own key once joined and verifies it; 0 keeps
       the key it joined with, as an older device does. */
    int tcLinkKeyUpdate;
} Zb_CoreConfig;

typedef struct Zb_Core
{
    Zb_Layers layers;
    Af_Af af;                                   /* the registry, and the door the device object sends through */
    Zdo_Zdo zdo;
    Aps_Binding bindings[APS_BIND_MAX];

    /* The security material this device states, owned here so a config names a key and not a table: one network key
       descriptor and the pairs, of which the first is the global one when the config names it. */
    Security_Config security;
    Security_KeyDescriptor keys[1];
    Security_KeyPairEntry pairs[1];

    Aps_Indication indications[ZB_CORE_INDICATION_MAX];
    uint32_t indicationCount;
    uint32_t indicationsDropped;
    uint32_t groupFramesUnmatched;  /* APS_GROUP_DELIVERY_ENDPOINTS: group frames no endpoint's profile matched */
    Zb_CoreDeparture departures[ZB_CORE_DEPARTURE_MAX];
    uint32_t departureCount;
    uint32_t departuresDropped;

    uint32_t zdpFramesConsumed;
    uint32_t announcementsRepublished;
    uint32_t joinsHeard;
    uint32_t networkKeysSent;
    uint32_t networkKeysTunnelled;  /* of those, the keys sent through the router that reported the join */
    uint32_t joinsUnreported;       /* joins the update-device request refused to report */
    uint32_t leavesUnreported;      /* a child's departures the update-device request refused to report */
    uint32_t removalsTaken;         /* a trust centre's Remove Device carried out, on a child or on this device */
    uint32_t removalsDiscarded;     /* and those naming neither (4.6.3.6.2) */
    uint32_t rejoins;               /* rejoins after a leave that asked this device to rejoin */
    uint32_t rejoinsFailed;

    /* At a trust centre, the parent each joiner came through, which a Remove Device is sent to */
    Zb_CoreJoiner joiners[ZB_CORE_JOINER_MAX];
    uint32_t joinerOrder;
    uint32_t joinersEvicted;

    /* The last ZDP frame the object was handed, which a bench instrument reads when an answer it expected never
       came: the routing rule and the object's own gate both decide on these three fields. */
    uint16_t lastZdpCluster;
    uint16_t lastZdpProfile;
    uint8_t lastZdpEndpoint;

    int joinAnnounced;
    int filtered;                   /* the radio's mode was stated, which an RCP must be told before it acknowledges */
    Zb_CoreKeyOwed keysOwed[ZB_CORE_KEY_OWED_MAX];
    uint32_t keysOwedRefused;       /* joins owed a key while every slot already held one */
    uint32_t trustCentreRejoinsRefused; /* trust centre rejoins from a device without a unique link key */
    uint32_t networkKeysRefused;    /* keys the APS door refused for good, or held past the hold */
    int transportNetworkKey;        /* this device is the trust centre, as the config said at init */
    Zb_CoreJoinState joinState;
    Zb_CoreJoinParameters joinParams;
    uint64_t joinExtendedPanId;     /* the network chosen from the discovery, which the join request names */
    int joinOwed;                   /* the join request is still to be taken: the door was busy on its turn */
    int rejoinOwed;                 /* told to leave and rejoin, by its parent or its application, or its parent lost */
    uint32_t parentLinkFailures;    /* 2.5.4.5.5.2's failure counter of consecutive failures, cleared by a rejoin */
    uint32_t parentLinkHeld;        /* the network layer's count of answered exchanges, the last one seen */
    uint32_t rejoinFailuresInRow;   /* the failed rejoins since the last that succeeded */
    uint32_t tcLinkKeyAttempts;     /* the Request-Keys this join has sent */
    uint32_t tcLinkKeyDeadlineMs;   /* when the one outstanding is given up */
    int tcLinkKeyDone;              /* verified, given up, or restored: nothing more is asked */
    uint32_t parentLinkRetryThreshold;
    uint32_t rejoinIntervalFirstMs;
    uint32_t rejoinIntervalMaxMs;
    uint32_t rejoinIntervalMs;      /* :Config_Rejoin_Interval as it stands, doubled from the second failed rejoin on */
    uint32_t rejoinStartMs;         /* when the last rejoin started, which the interval counts from */
    int rejoinStarted;
    uint32_t joinScansLeft;         /* :Config_NWK_Scan_Attempts still to run, the one under way among them */
    uint32_t joinScanAtMs;          /* when the gap between two of them ends */
    Nwk_JoinConfirmParameters joinConfirm;  /* the SUCCESS confirm a key wait follows */
    Zb_CoreJoinResult joinResult;
    int joinResultReady;
    int running;
} Zb_Core;

ZbStatus Zb_CoreInit(Zb_Core *self, Radio_Radio *radio, const Zb_CoreConfig *cfg);

/* A saved state put back after init (Zb_LayersRestore): the device is on its network again with no join, a router
   beacons for it, and a joiner announces itself only when `announce` asks, since no join or rejoin happened. */
ZbStatus Zb_CoreRestore(Zb_Core *self, const Zb_State *state, int announce);

/* The stack's turn, then the one read of the APS ring: a frame addressed to endpoint 0 is the device object's, and so
   is a ZDP request broadcast to 0xff, which this stack sent before D-217 moved it to 0x00. Everything else waits
   for the application's poll: its own clusters, a group frame, and a ZDP response, which it correlates itself. */
ZbStatus Zb_CoreStep(Zb_Core *self, uint32_t nowMs);

/* 2.3.2.5's descriptor. It is the one statement of what the device advertises: the device object answers
   Simple_Desc_req, Active_EP_req and Match_Desc_req out of this table and nowhere else. */
ZbStatus Zb_CoreRegisterEndpoint(Zb_Core *self, const Af_SimpleDescriptor *descriptor);

/* 2.2.4.1.1's request. Endpoint 0 is the device object's; any other source endpoint must be one this device
   registered, which is this repository's rule and not a clause (D-212). */
ZbStatus Zb_CoreSendRequest(Zb_Core *self, const Aps_ApsdeReq *request, uint32_t nowMs);

/* What no endpoint took, oldest first. */
uint32_t Zb_CorePollIndications(Zb_Core *self, Aps_Indication *out, uint32_t max);

/* Other devices' departures, oldest first; one departure may be told twice, by its own leave and by its parent. */
uint32_t Zb_CorePollDepartures(Zb_Core *self, Zb_CoreDeparture *out, uint32_t max);
uint32_t Zb_CorePollConfirms(Zb_Core *self, Aps_Confirm *out, uint32_t max);

/* The three duties the device carries rather than the application: 2.4.3.1.11.1's announcement, 3.2.2.7's permit
   beside the beacon it belongs to, and 3.6.1.11's departure. A permit asked for before the radio can acknowledge
   answers ZB_ERR_NOT_READY, and the caller asks again on a later turn. */
ZbStatus Zb_CoreAnnounce(Zb_Core *self, uint32_t nowMs);

/* 3.6.1.6.1.1's child procedure from its start: 3.2.2.3's discovery of permitting networks on the channels named, the
   network chosen (the one asked for, or the best-ranked), then NLME-JOIN, run by the device's turns, with the key wait
   and the announcement after it. ZB_ERR_BUSY during a join, ZB_ERR_BAD_STATE on a coordinator or a joined device. */
ZbStatus Zb_CoreJoin(Zb_Core *self, const Zb_CoreJoinParameters *params, uint32_t nowMs);

/* 1 when a join ended and its result was taken. */
uint32_t Zb_CorePollJoinResult(Zb_Core *self, Zb_CoreJoinResult *out);
ZbStatus Zb_CorePermitJoining(Zb_Core *self, uint8_t duration, uint32_t nowMs);
ZbStatus Zb_CoreLeave(Zb_Core *self, int rejoin, uint32_t nowMs);

/* The fourth, 4.6.3.6.1's removal at the trust centre: a child by the leave request, another device by Remove Device
   to the parent it joined through at the address the map now holds, one with none noted as a router (4.4.4.1.2).
   NOT_FOUND unless the map places that router; BAD_STATE away from the trust centre or off its network. */
ZbStatus Zb_CoreRemove(Zb_Core *self, uint64_t targetIeee, uint32_t nowMs);

/* At the trust centre, a device's own link key forgotten on the operator's word, so the device can join again after a
   factory reset with the global key (Security_ForgetLinkKey). NOT_FOUND for a device holding no key of its own,
   BAD_STATE away from the trust centre. */
ZbStatus Zb_CoreForgetLinkKey(Zb_Core *self, uint64_t deviceIeee);

/* The parent a trust centre noted for `deviceIeee`: 1 with it written, 0 when none is noted. */
int Zb_CoreParentOf(const Zb_Core *self, uint64_t deviceIeee, uint64_t *parentIeee);

Zb_Layers *Zb_CoreLayers(Zb_Core *self);
Aps_Aps *Zb_CoreAps(Zb_Core *self);
Nwk_Nwk *Zb_CoreNwk(Zb_Core *self);
Mac_Mac *Zb_CoreMac(Zb_Core *self);
Aps_Binding *Zb_CoreBindings(Zb_Core *self);

uint32_t Zb_CoreEndpointCount(const Zb_Core *self);
uint32_t Zb_CoreZdpFramesConsumed(const Zb_Core *self);
uint16_t Zb_CoreLastZdpCluster(const Zb_Core *self);
uint16_t Zb_CoreLastZdpProfile(const Zb_Core *self);
uint8_t Zb_CoreLastZdpEndpoint(const Zb_Core *self);
uint32_t Zb_CoreAnnouncementsRepublished(const Zb_Core *self);
uint32_t Zb_CoreIndicationsDropped(const Zb_Core *self);
uint32_t Zb_CoreDeparturesDropped(const Zb_Core *self);
uint32_t Zb_CoreGroupFramesUnmatched(const Zb_Core *self);
uint32_t Zb_CoreNetworkKeysSent(const Zb_Core *self);
uint32_t Zb_CoreJoinsHeard(const Zb_Core *self);
uint32_t Zb_CoreNetworkKeysTunnelled(const Zb_Core *self);
uint32_t Zb_CoreJoinsUnreported(const Zb_Core *self);
uint32_t Zb_CoreLeavesUnreported(const Zb_Core *self);
uint32_t Zb_CoreRemovalsTaken(const Zb_Core *self);
uint32_t Zb_CoreRemovalsDiscarded(const Zb_Core *self);
uint32_t Zb_CoreRejoins(const Zb_Core *self);
uint32_t Zb_CoreRejoinsFailed(const Zb_Core *self);
uint32_t Zb_CoreParentLinkFailures(const Zb_Core *self);
uint32_t Zb_CoreJoinersEvicted(const Zb_Core *self);
uint32_t Zb_CoreKeysOwedRefused(const Zb_Core *self);
uint32_t Zb_CoreTrustCentreRejoinsRefused(const Zb_Core *self);
uint32_t Zb_CoreNetworkKeysRefused(const Zb_Core *self);
int Zb_CoreIsRunning(const Zb_Core *self);

#endif
