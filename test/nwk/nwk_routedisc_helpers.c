/* The `nwk_routedisc` suite's shared machinery: the one composition and the one seeding function.
   See `nwk_routedisc_helpers.h` for the contract. */

#include "nwk_routedisc_helpers.h"

#include "test_harness.h"

uint32_t composeRreq(const Nwk_RouteRequestPayload *req, uint32_t *routingSeq, uint8_t initialRadius,
                     uint8_t *out, uint32_t outMax)
{
    uint32_t len = 0;
    ZbStatus status;

    status = Nwk_RreqCompose(req, routingSeq, initialRadius, out, outMax, &len);

    if (status != ZB_OK)
        Test_Fault("the route request this case composes was refused");

    return len;
}

Nwk_RouteDiscoveryTableEntry *seedDiscovery(Nwk_RouteDiscoveryTableEntry *pool, uint32_t slot, uint16_t sourceAddr, uint8_t requestId,
                             uint32_t expiryMs)
{
    pool[slot].inUse = 1;
    pool[slot].sourceAddress = sourceAddr;
    pool[slot].routeRequestId = requestId;
    pool[slot].senderAddress = 0x0100;
    pool[slot].forwardCost = 2;
    pool[slot].residualCost = 3;
    pool[slot].expiresAtMs = expiryMs;

    return &pool[slot];
}
