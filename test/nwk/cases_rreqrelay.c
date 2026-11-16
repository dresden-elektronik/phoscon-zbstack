/* 3.6.4.5.1.4's two numbers, case by case: the jitter a forwarder holds the frame for (Table 3-65's
   `nwkcMinRREQJitter` and `nwkcMaxRREQJitter`, which the clause's "2 x R[...]" doubles to a closed 4-256 ms)
   and `nwkcRREQRetries`, which its "nwkcRREQRetries + 1 relays per relay attempt" turns into three. The
   generator is `nwk_relay`'s one xorshift32, so what arrives is the caller's seed and the caller's state: no
   clock, no global state, no platform call, and a seed reaches the same delay twice. */

#include "nwk_routeflow_cases.h"

#include "nwk_rreqrelay.h"
#include "test_harness.h"

enum
{
    SEED_A = 0x1234abcd,            /* the caller's seed of the generator `nwk_relay` already runs */
    SEED_B = 0x0f1e2d3c
};

void caseRreqRelayJitterIsInsideTheDoubledBounds(void)
{
    uint32_t stateA = SEED_A;
    uint32_t stateB = SEED_B;
    uint32_t first;
    uint32_t second;
    uint32_t i;
    uint32_t draw;
    uint32_t outside = 0;

    first = Nwk_RreqRelayJitterMs(&stateA, SEED_A);
    second = Nwk_RreqRelayJitterMs(&stateB, SEED_B);

    Test_ExpectCount(NWK_MIN_RREQ_JITTER_MS, 2, "nwkcMinRREQJitter, Table 3-65: 0x3f OctetDurations, 2 msec");
    Test_ExpectCount(NWK_MAX_RREQ_JITTER_MS, 128, "nwkcMaxRREQJitter, Table 3-65: 0xfa0 OctetDurations, 128 msec");
    Test_ExpectCount(NWK_MIN_RREQ_RELAY_MS, 4, "3.6.4.5.1.4's 2 x R[2,128], its lower bound doubled");
    Test_ExpectCount(NWK_MAX_RREQ_RELAY_MS, 256, "and its upper bound doubled: the wait is 4-256 ms");
    Test_Expect(first >= NWK_MIN_RREQ_RELAY_MS && first <= NWK_MAX_RREQ_RELAY_MS,
                "one seed's draw is inside the printed bounds");
    Test_Expect(second >= NWK_MIN_RREQ_RELAY_MS && second <= NWK_MAX_RREQ_RELAY_MS,
                "and so is another seed's");
    Test_Expect(first != second, "two seeds answer different delays: nothing is drawn from a constant");

    stateA = SEED_A;

    for (i = 0; i < 64; i++)
    {
        draw = Nwk_RreqRelayJitterMs(&stateA, SEED_A);

        if (draw < NWK_MIN_RREQ_RELAY_MS || draw > NWK_MAX_RREQ_RELAY_MS)
            outside++;
    }

    Test_ExpectCount(outside, 0, "no draw of a 64-draw run leaves the closed interval");
}

void caseRreqRelayJitterWithNoSeedAnswersZero(void)
{
    uint32_t state = 0x00c0ffee;
    uint32_t untouched = state;

    Test_ExpectCount(Nwk_RreqRelayJitterMs(&state, 0), 0, "a caller that seeded no entropy draws no delay");
    Test_ExpectCount(state, untouched, "and the state it was handed stands where it was");
}

void caseRreqRelayCountIsThreePerAttempt(void)
{
    Test_ExpectCount(NWK_RREQ_RETRIES, 2, "nwkcRREQRetries, Table 3-65");
    Test_ExpectCount(Nwk_RreqRelayCount(), 3,
                     "3.6.4.5.1.4: the original relay plus nwkcRREQRetries retries is a maximum of 3 relays");
}
