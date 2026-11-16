#ifndef NWK_RELAY_H
#define NWK_RELAY_H

/*
 * The forward machinery: a unicast relay, a broadcast retransmission, its jitter; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "mac.h"
#include "nwk_btt.h"
#include "nwk_frame.h"
#include "nwk_neighbor.h"
#include "nwk_route.h"
#include "nwk_tx.h"
#include "security.h"
#include "zb_status.h"

enum
{
    NWK_MAX_BROADCAST_RETRIES = 2,  /* nwkMaxBroadcastRetries, NIB attribute 0x83, default 0x02 (Table 3-66, 3.6.6) */
    NWK_PASSIVE_ACK_TIMEOUT_MS = 500, /* nwkPassiveAckTimeout, NIB attribute 0x82, default 500 ms (3.6.6, Table 3-66) */
    NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS = 9000, /* stand-in for an attribute that prints no number: NIB 0x88, open */

    NWK_MAX_BROADCAST_JITTER_UNITS = 0x7d0, /* nwkcMaxBroadcastJitter, Table 3-65: 0x7d0 OctetDurations */
    NWK_OCTET_DURATION_US = 32,     /* **derived** from Table 3-65's own unit pairs; 32 µs is one symbol at 2.4 GHz */
    NWK_MAX_BROADCAST_JITTER_MS = 64,       /* **derived**: 2000 × 32 / 1000 = 64 ms, the closed upper bound of one draw */
};

/* What a relay attempt ended as: a protection's two families are one outcome here, both failing for the same reason. */
typedef enum Nwk_RelayOutcome
{
    NWK_RELAY_ISSUED = 0,           /* the frame went out on this device's own initiative */
    NWK_RELAY_NOT_FOR_ME,           /* no routing duty for this device, or a frame a device of this stack does not carry onward */
    NWK_RELAY_NO_ROUTE,             /* the radius this device's receipt spent, or no next hop to aim the copy at */
    NWK_RELAY_FORWARD_COPY_FAILED,  /* the frame the relay would have sent could not be composed or would not fit */
    NWK_RELAY_PROTECT_REFUSED,      /* a protection this device could not make; its status arrives beside it */
    NWK_RELAY_ISSUE_FAILED          /* the MAC underneath had no room for the frame, and counts that refusal itself */
} Nwk_RelayOutcome;

/* One draw of the broadcast jitter in milliseconds: `*state` is the caller's own generator state, advanced
   as arming one retransmission arms the next; 0, state untouched, when the config seeds none. */
uint32_t Nwk_RelayJitterMs(uint32_t *state, const Nwk_Config *cfg);

/* One draw of when a gratuitous link status goes out, from the same state: the lower bound when the config seeds none. */
uint32_t Nwk_RelayBootstrapJitterMs(uint32_t *state, const Nwk_Config *cfg);

/* 3.6.2.2's duty over 3.6.4.3's order of choices. A next hop that listens takes `slot`, 0 when the pool is full, for
   8874-8877's retries; a resting one's frame is held under `heldHandle`. The next hop is what a failed link needs. */
ZbStatus Nwk_RelayUnicast(const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                          const Nwk_Config *cfg, Nwk_RoutingTableEntry *routes, Nwk_NeighborTableEntry *neighbors,
                          Mac_Mac *mac, Security *security, uint8_t *scratch, uint32_t scratchMax,
                          uint8_t *relayNpdu, uint32_t relayNpduMax, uint8_t heldHandle, Nwk_Tx *slot, uint32_t nowMs,
                          Nwk_RelayOutcome *outcomeOut, uint16_t *nextHopOut);

/* One retransmission of a broadcast this device has a record of, and the sleepy-neighbor copies that go with it (3.6.6). */
Nwk_RelayOutcome Nwk_RelayBroadcast(Nwk_BroadcastTransactionRecord *record, Nwk_NeighborTableEntry *neighbors, const Nwk_Config *cfg,
                                    uint32_t *jitterState, Mac_Mac *mac, Security *security,
                                    uint8_t *scratch, uint32_t scratchMax, uint32_t nowMs,
                                    ZbStatus *protectStatusOut, ZbStatus *copiesStatusOut);

#endif /* NWK_RELAY_H */
