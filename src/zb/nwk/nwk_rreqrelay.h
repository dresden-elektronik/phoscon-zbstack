#ifndef NWK_RREQRELAY_H
#define NWK_RREQRELAY_H

/*
 * 3.6.4.5.1.4's jitter and relay count for a relayed request; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

enum
{
    NWK_MIN_RREQ_JITTER_MS = 2,     /* nwkcMinRREQJitter, Table 3-65: 0x3f OctetDurations, 2 msec at 2.4 GHz */
    NWK_MAX_RREQ_JITTER_MS = 128,   /* nwkcMaxRREQJitter, Table 3-65: 0xfa0 OctetDurations, 128 msec */
    NWK_RREQ_JITTER_FACTOR = 2,     /* 3.6.4.5.1.4: "2 x R[nwkcMinRREQJitter, nwkcMaxRREQJitter]" */
    NWK_MIN_RREQ_RELAY_MS = 4,      /* derived: 2 x 2, the closed lower bound of the wait */
    NWK_MAX_RREQ_RELAY_MS = 256,    /* derived: 2 x 128, the closed upper bound */

    NWK_RREQ_RETRIES = 2            /* nwkcRREQRetries, Table 3-65, the retries after the original relay */
};

/* One draw of 3.6.4.5.1.4's jitter inside 4-256 ms, from `nwk_relay`'s one generator; a 0 seed draws nothing. */
uint32_t Nwk_RreqRelayJitterMs(uint32_t *state, uint32_t seed);

/* 3.6.4.5.1.4: "nwkcRREQRetries + 1 relays per relay attempt", the original relay and its two retries. */
uint32_t Nwk_RreqRelayCount(void);

#endif /* NWK_RREQRELAY_H */
