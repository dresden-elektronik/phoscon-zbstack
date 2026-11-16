#ifndef NWK_NEIGHBOR_H
#define NWK_NEIGHBOR_H

/*
 * The neighbor table of Table 3-75; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "zb_limits.h"

enum
{
    /* the nwkNeighborTable of NIB attribute 0x87, whose entries Table 3-75 describes */
    NWK_NEIGHBOR_MAX = ZB_LIMIT_NWK_NEIGHBOR,

    /* Table 3-66 prints nwkLinkStatusPeriod 0xa6 as 0x0f seconds and nwkRouterAgeLimit 0xa7 as 3, and Table 3-75
       prints Age in units of the first: "the number of nwkLinkStatusPeriod intervals since a link status command
       was received". A tick is therefore 15 s and a router is stale after three of them (3.6.4.4.4). */
    NWK_LINK_STATUS_PERIOD_MS = 15000,
    NWK_LINK_STATUS_RETRY_MS = 50,    /* how soon a link status the transmit path had no room for is asked again */
    NWK_ROUTER_AGE_LIMIT = 3,
    NWK_ROUTER_BOOTSTRAP_JITTER_MIN_MS = 500,    /* nwkcMinRouterBootstrapJitter, Table 3-65 */
    NWK_ROUTER_BOOTSTRAP_JITTER_MAX_MS = 1000,   /* nwkcMaxRouterBootstrapJitter, Table 3-65 */

    NWK_TRANSMIT_FAILURE_MAX = 0xff, /* Table 3-75 prints Transmit Failure as 0x00-0xff: higher means more failures */
    NWK_AGE_UNBOUNDED = 0xff,      /* Table 3-75 prints Age as 0x00-0xff: the saturating ceiling of the tick count */

    /* Table 3-75 prints RouterOutboundActivity and RouterInboundActivity as Integer 0x00-0xff, each a "saturating
       counter, which is pre-loaded with nwkRouterAgeLimit when this neighbor table entry is created" */
    NWK_ROUTER_ACTIVITY_MAX = 0xff,
    NWK_ROUTER_AGE_MAX = 0xffff,   /* Table 3-75's RouterAge: "a saturating up-counter" */

    /* 3.6.4.4.3.1's windows are named by Table 3-66 and printed with no value, so these three are this stack's,
       chosen and recorded in docs/internals/decisions.md. */
    NWK_LINK_STATUS_MIN_OBSERVATION_TICKS = 2,
    NWK_LINK_STATUS_BACKBONE_FORMATION_TICKS = 8,
    NWK_LINK_STATUS_BACKBONE_NEIGHBORS = 2,

    /* What "change considerably" takes at 9007-9008, printed with no number: a quarter of the holder's rank and the 8
       one frame adds to it, recorded in docs/internals/decisions.md. */
    NWK_BACKBONE_HOLD_DIVISOR = 4,
    NWK_BACKBONE_HOLD_FRAME = 8
};

/* Table 3-75's two coded fields: the device types are `Nwk_Config`'s vocabulary, and what an entry can say beyond them is this stack's. */
enum
{
    NWK_NEIGHBOR_TYPE_UNKNOWN = 0xff, /* not printed: an entry made from an address heard, no device type observed */

    /* Relationship, Table 3-75: 0x07 is the one observation this module can make on its own (3.6.2.3) */
    NWK_REL_PARENT = 0x00,
    NWK_REL_CHILD = 0x01,
    NWK_REL_SIBLING = 0x02,
    NWK_REL_NONE = 0x03,
    NWK_REL_PREVIOUS_CHILD = 0x04,
    NWK_REL_UNAUTHENTICATED_CHILD = 0x05,
    NWK_REL_UNAUTHORIZED_CHILD = 0x06,
    NWK_REL_LOST_CHILD = 0x07,
    NWK_REL_ADDRESS_CONFLICT = 0x08,
    NWK_REL_BACKBONE_SIBLING = 0x09
};

/* Table 3-75, the neighbor table entry: `networkAddress`, `extendedAddress`, `lqi` (3.6.3's final LQA),
   `routerOutboundActivity`, `routerInboundActivity`, `routerAge` and `securityTimer` are its rows; `inUse`, `ieeeKnown`, `lqaRaw`,
   `lqaRawCount`, `ageFromMs`, `lostChildMs` and `securityTimerMs` are this stack's, and its other eleven rows are not held. */
typedef struct Nwk_NeighborTableEntry
{
    int inUse;
    uint16_t networkAddress;
    uint16_t routerAge;
    uint64_t extendedAddress;
    int ieeeKnown;
    uint32_t deviceType;
    int rxOnWhenIdle;
    uint32_t relationship;
    uint8_t lqi;
    uint8_t lqaRaw[2];
    uint8_t lqaRawCount;
    uint32_t outgoingCost;
    uint32_t age;
    uint32_t transmitFailures;
    uint32_t routerOutboundActivity;
    uint32_t routerInboundActivity;
    uint32_t routerConnectivity;
    uint32_t routerNeighborSetDiversity;
    uint32_t ageFromMs;
    uint32_t lostChildMs;
    uint32_t securityTimer;
    uint32_t securityTimerMs;

    uint32_t deviceTimeout;
    uint32_t timeoutCounter;
    uint32_t timeoutMs;
    int timeoutStarted;
    int keepaliveReceived;
    uint32_t endDeviceConfiguration;
} Nwk_NeighborTableEntry;

/* The entry for that address, or 0 when the table has none (3.6.2.2, 3.6.2.3, 3.6.4.3, 3.6.6). */
Nwk_NeighborTableEntry *Nwk_NeighborOf(Nwk_NeighborTableEntry *pool, uint16_t address);

/* Whether a unicast to that address must wait for the neighbour's poll: a child end device whose receiver rests,
   which hears nothing it did not ask for (3.6.4.3). */
int Nwk_NeighborRestsReceiver(Nwk_NeighborTableEntry *pool, uint16_t address);

/* A slot for a new entry, and no eviction of an old one: 0 when the table is full (3.6.1.9, 3.6.4.4.3.1). */
Nwk_NeighborTableEntry *Nwk_NeighborFree(Nwk_NeighborTableEntry *pool);

/* 3.6.4.4.4's ageing in Table 3-75's unit: past nwkRouterAgeLimit the outgoing cost becomes 0, which 3.6.4.5.1.2 discards on. */
uint32_t Nwk_NeighborAge(Nwk_NeighborTableEntry *pool, uint32_t nowMs);

/* 3.6.3's median of the 3 most recent raw samples, this one included, and of fewer while fewer exist; of two the lower. */
void Nwk_NeighborLqaSample(Nwk_NeighborTableEntry *entry, uint32_t raw);

/* 3.6.4.8's failure counter for the neighbour at `address`, saturating at Table 3-75's 0xff. */
uint32_t Nwk_NeighborTxFailure(Nwk_NeighborTableEntry *pool, uint16_t address);

/* The other half of the simple counting scheme 3.6.4.8 permits: a transmit that succeeded clears the count. */
void Nwk_NeighborTxSuccess(Nwk_NeighborTableEntry *pool, uint16_t address);

/* 3.6.4.3's two activity counters, each saturating at Table 3-75's 0xff. */
uint32_t Nwk_NeighborOutboundActivity(Nwk_NeighborTableEntry *pool, uint16_t address);
uint32_t Nwk_NeighborInboundActivity(Nwk_NeighborTableEntry *pool, uint16_t address);

/* Table 3-75: both counters down by one, the caller running it once every nwkLinkStatusPeriod. */
void Nwk_NeighborActivityDecay(Nwk_NeighborTableEntry *pool);

/* Table 3-75's SecurityTimer armed to `seconds` and counted from `nowMs`, which 3.6.1.6.1.1 and 3.6.1.6.1.3 both
   set to apsSecurityTimeOutPeriod. A `seconds` of 0 leaves the countdown off. */
void Nwk_NeighborSecurityTimerArm(Nwk_NeighborTableEntry *entry, uint32_t seconds, uint32_t nowMs);

/* The countdown of Table 3-75, one second at a time from the anchor: 1 when this call took it to zero, 0 otherwise,
   and an entry with no countdown running answers 0. */
int Nwk_NeighborSecurityTimerTick(Nwk_NeighborTableEntry *entry, uint32_t nowMs);

/* How many slots of the pool hold a neighbor (3.6.6, Table 3-75). */
uint32_t Nwk_NeighborCount(const Nwk_NeighborTableEntry *pool);

#endif /* NWK_NEIGHBOR_H */
