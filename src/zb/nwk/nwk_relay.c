#include "nwk.h"

#include "nwk_relay.h"

#include "mac.h"
#include "nwk_addr.h"
#include "nwk_command.h"
#include "nwk_frame.h"
#include "nwk_indirect.h"
#include "nwk_neighbor.h"
#include "nwk_route.h"
#include "nwk_rx.h"
#include "nwk_tx.h"
#include "security.h"

/* R23.1: 3.6.2.2, 3.6.4.3, 3.6.4.8.1, 3.6.6 ok (the spent-radius discard, the unicast relay through a next hop, the
   broadcast relay and its retransmission schedule, the failed-forward status; 3.6.4.3's source-route half is
   `nwk.c`'s and `nwk_rx.c`'s); 2.4 elsewhere (ZDO). */

/* the derived unit fact held against the printed constant: disagreement stops the build (docs/internals/coding-rules.md §7) */
typedef char NwkMaxBroadcastJitterDerivation[(NWK_MAX_BROADCAST_JITTER_MS ==
                                                NWK_MAX_BROADCAST_JITTER_UNITS * NWK_OCTET_DURATION_US / 1000)
                                               ? 1 : -1];

/* One draw from 0 to `span` over the caller's own state, never a platform call (docs/internals/coding-rules.md §4.1) */
static uint32_t nwkRelayDrawMs(uint32_t *state, const Nwk_Config *cfg, uint32_t span)
{
    uint32_t x;

    if (cfg->jitterSeed == 0)
        return 0;

    x = *state;

    if (x == 0)
        x = 1;

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;

    *state = x;

    return (uint32_t)(((uint64_t)x * (span + 1)) >> 32);
}

/* 3.6.6's nwkcMaxBroadcastJitter bounds the draw and prints no lower bound, so the interval is closed: 0-64 ms */
uint32_t Nwk_RelayJitterMs(uint32_t *state, const Nwk_Config *cfg)
{
    return nwkRelayDrawMs(state, cfg, NWK_MAX_BROADCAST_JITTER_MS);
}

/* 8967-8968 and Table 3-65: a gratuitous link status falls between the two bootstrap jitters. */
uint32_t Nwk_RelayBootstrapJitterMs(uint32_t *state, const Nwk_Config *cfg)
{
    return NWK_ROUTER_BOOTSTRAP_JITTER_MIN_MS
           + nwkRelayDrawMs(state, cfg, NWK_ROUTER_BOOTSTRAP_JITTER_MAX_MS - NWK_ROUTER_BOOTSTRAP_JITTER_MIN_MS);
}

/* 3.6.2.2's discard, its gates in the order docs/internals/conformance.md §2 states: not for me, and a spent radius or no next hop as one no-route outcome */
ZbStatus Nwk_RelayUnicast(const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                          const Nwk_Config *cfg, Nwk_RoutingTableEntry *routes, Nwk_NeighborTableEntry *neighbors,
                          Mac_Mac *mac, Security *security, uint8_t *scratch, uint32_t scratchMax,
                          uint8_t *relayNpdu, uint32_t relayNpduMax, uint8_t heldHandle, Nwk_Tx *slot, uint32_t nowMs,
                          Nwk_RelayOutcome *outcomeOut, uint16_t *nextHopOut)
{
    const uint8_t *octets;
    uint16_t nextHop;
    uint32_t len;
    uint32_t octetLen;
    uint32_t securedLen;
    ZbStatus status;

    if (nextHopOut != 0)
        *nextHopOut = 0;

    if (frame->sourceRoute)
    {
        *outcomeOut = NWK_RELAY_NOT_FOR_ME;
        return ZB_OK;
    }

    if (frame->frameType == NWK_FRAME_TYPE_COMMAND)
    {
        if (payloadLen == 0 || payload[0] != NWK_CMD_NETWORK_STATUS)
        {
            *outcomeOut = NWK_RELAY_NOT_FOR_ME;
            return ZB_OK;
        }
    }
    else if (frame->frameType != NWK_FRAME_TYPE_DATA)
    {
        *outcomeOut = NWK_RELAY_NOT_FOR_ME;
        return ZB_OK;
    }

    if (!Nwk_AddrHasRoutingDuty(cfg->deviceType))
    {
        *outcomeOut = NWK_RELAY_NOT_FOR_ME;
        return ZB_OK;
    }

    if (frame->radius == 0)
    {
        *outcomeOut = NWK_RELAY_NO_ROUTE;
        return ZB_OK;
    }

    if (!Nwk_RouteNextHop(routes, neighbors, frame->destAddr, nowMs, &nextHop))
    {
        *outcomeOut = NWK_RELAY_NO_ROUTE;
        return ZB_OK;
    }

    if (nextHopOut != 0)
        *nextHopOut = nextHop;

    status = Nwk_RxForwardCopy(frame, payload, payloadLen, relayNpdu, relayNpduMax, &len);

    if (status != ZB_OK)
    {
        *outcomeOut = NWK_RELAY_FORWARD_COPY_FAILED;
        return status;
    }

    if (!Nwk_NeighborRestsReceiver(neighbors, nextHop))
    {
        int protectRefused;

        status = Nwk_TxForward(slot, mac, security, scratch, scratchMax, relayNpdu, len, NwkFrame_HeaderLen(frame),
                               frame->securityEnabled, frame->sequenceNumber, nextHop, frame->destAddr, nowMs,
                               &protectRefused);

        if (status != ZB_OK)
        {
            *outcomeOut = protectRefused ? NWK_RELAY_PROTECT_REFUSED : NWK_RELAY_ISSUE_FAILED;
            return status;
        }

        slot->sourceAddr = frame->srcAddr;
        slot->reportsFailure = frame->frameType == NWK_FRAME_TYPE_DATA;
        *outcomeOut = NWK_RELAY_ISSUED;

        return ZB_OK;
    }

    octets = relayNpdu;
    octetLen = len;

    if (frame->securityEnabled)
    {
        status = Nwk_TxProtect(security, relayNpdu, len, NwkFrame_HeaderLen(frame), scratch,
                               scratchMax, &securedLen);

        if (status != ZB_OK)
        {
            *outcomeOut = NWK_RELAY_PROTECT_REFUSED;
            return status;
        }

        octets = scratch;
        octetLen = securedLen;
    }

    status = Nwk_TxOfferRaw(mac, octets, octetLen, nextHop, 1, heldHandle, nowMs, 0);

    if (status != ZB_OK)
    {
        *outcomeOut = NWK_RELAY_ISSUE_FAILED;
        return status;
    }

    *outcomeOut = NWK_RELAY_ISSUED;

    return ZB_OK;
}

/* One retransmission of a recorded broadcast with the copies that go with it: the record's own octets re-offered, on 3.6.6's schedule for a device without passive acknowledgement (docs/internals/conformance.md §2) */
Nwk_RelayOutcome Nwk_RelayBroadcast(Nwk_BroadcastTransactionRecord *record, Nwk_NeighborTableEntry *neighbors, const Nwk_Config *cfg,
                                    uint32_t *jitterState, Mac_Mac *mac, Security *security,
                                    uint8_t *scratch, uint32_t scratchMax, uint32_t nowMs,
                                    ZbStatus *protectStatusOut, ZbStatus *copiesStatusOut)
{
    const uint8_t *octets;
    Nwk_RelayOutcome outcome;
    uint32_t octetLen;
    uint32_t securedLen;
    ZbStatus status;

    *protectStatusOut = ZB_OK;
    *copiesStatusOut = ZB_OK;

    record->relayed = record->relayed + 1;
    record->nextRelayMs = nowMs + NWK_PASSIVE_ACK_TIMEOUT_MS + Nwk_RelayJitterMs(jitterState, cfg);

    octets = record->npdu;
    octetLen = record->npduLen;

    if (record->reprotect)
    {
        status = Nwk_TxProtect(security, record->npdu, record->npduLen, record->headerLen, scratch,
                               scratchMax, &securedLen);

        if (status != ZB_OK)
        {
            record->relayed = NWK_MAX_BROADCAST_RETRIES;
            *protectStatusOut = status;

            return NWK_RELAY_PROTECT_REFUSED;
        }

        octets = scratch;
        octetLen = securedLen;
    }

    status = Nwk_TxIssueRaw(mac, octets, octetLen, record->dst, 1, nowMs, 0);

    if (status == ZB_OK)
        outcome = NWK_RELAY_ISSUED;
    else
        outcome = NWK_RELAY_ISSUE_FAILED;

    status = Nwk_IndirectTransactionCopies(neighbors, cfg->deviceType, mac, security, record->dst, record->sourceAddress,
                                             record->npdu, record->npduLen, record->headerLen, record->reprotect,
                                             scratch, scratchMax, nowMs);

    if (status != ZB_OK)
        *copiesStatusOut = status;

    return outcome;
}
