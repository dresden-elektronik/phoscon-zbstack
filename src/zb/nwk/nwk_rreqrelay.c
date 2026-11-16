#include "nwk.h"

#include "nwk_rreqrelay.h"

#include "nwk_relay.h"
#include "zb_utils.h"

/* R23.1: 3.6.4.5.1 ok (the jitter and the relay count); 2.4 elsewhere (ZDO and APS discovery, nothing here binds). */

uint32_t Nwk_RreqRelayJitterMs(uint32_t *state, uint32_t seed)
{
    Nwk_Config cfg;
    uint32_t draw;

    if (seed == 0)
        return 0;

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.jitterSeed = seed;

    draw = Nwk_RelayJitterMs(state, &cfg);

    return NWK_RREQ_JITTER_FACTOR
           * (NWK_MIN_RREQ_JITTER_MS
              + (draw * (NWK_MAX_RREQ_JITTER_MS - NWK_MIN_RREQ_JITTER_MS)) / NWK_MAX_BROADCAST_JITTER_MS);
}

uint32_t Nwk_RreqRelayCount(void)
{
    return (uint32_t)NWK_RREQ_RETRIES + 1;
}
