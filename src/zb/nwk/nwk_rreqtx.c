#include "nwk.h"

#include "nwk_rreqtx.h"

#include "nwk_rreq.h"
#include "nwk_rreqrelay.h"
#include "nwk_tx.h"
#include "zb_time.h"
#include "zb_utils.h"

/* R23.1: 3.6.4.5.1 ok (the retries and the many-to-one single broadcast); 3.4.1.1, 3.4.1.2 elsewhere (nwk_tx.c's
   header and MAC destination); 2.4 elsewhere (ZDO and APS). docs/internals/conformance.md pages. */

/* 9070-9075 and 9078, and 9190-9191 for the relay: the transmissions one attempt of this record is worth */
static uint32_t nwkRreqTxCount(const Nwk_RreqTx *record)
{
    if (record->relay)
        return Nwk_RreqRelayCount();

    if (record->manyToOne != NWK_RREQ_MANY_TO_ONE_NONE)
        return 1;

    return NWK_RREQ_TX_COUNT;
}

/* The one body both doors arm: the octets stored once, the count left to the run, and the refusals stated twice */
static ZbStatus nwkRreqTxArm(Nwk_RreqTx *record, const uint8_t *npdu, uint32_t npduLen, uint32_t headerLen,
                             int secured, uint32_t firstTxMs)
{
    if (npdu == 0 || npduLen == 0 || npduLen > (uint32_t)sizeof record->npdu)
        return ZB_ERR_BAD_ARGUMENT;

    if (headerLen > npduLen)
        return ZB_ERR_BAD_ARGUMENT;     

    Zb_memset(record, 0, (uint32_t)sizeof *record);

    record->inUse = 1;
    record->nextTxMs = firstTxMs;
    record->npduLen = npduLen;
    record->headerLen = headerLen;
    record->secured = secured;
    Zb_memcpy(record->npdu, npdu, npduLen);

    return ZB_OK;
}

/* A record no schedule holds: the pool's full policy, which the caller counts where it is refused */
static Nwk_RreqTx *nwkRreqTxIdle(Nwk_RreqTx *pool)
{
    uint32_t i;

    for (i = 0; i < NWK_RREQ_TX_MAX; i++)
    {
        if (!pool[i].inUse)
            return &pool[i];
    }

    return 0;
}

Nwk_RreqTx *Nwk_RreqTxOf(Nwk_RreqTx *pool, uint16_t keyAddr, uint8_t requestId)
{
    uint32_t i;

    for (i = 0; i < NWK_RREQ_TX_MAX; i++)
    {
        if (!pool[i].inUse)
            continue;

        if (pool[i].keyAddr == keyAddr && pool[i].requestId == requestId)
            return &pool[i];
    }

    return 0;
}

uint32_t Nwk_RreqTxHeld(const Nwk_RreqTx *pool)
{
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < NWK_RREQ_TX_MAX; i++)
    {
        if (pool[i].inUse)
            count++;
    }

    return count;
}

ZbStatus Nwk_RreqTxStart(Nwk_RreqTx *pool, uint16_t destAddr, uint8_t requestId, uint32_t manyToOne,
                         const uint8_t *npdu, uint32_t npduLen, uint32_t headerLen, int secured,
                         uint32_t nowMs)
{
    Nwk_RreqTx *record;
    ZbStatus status;

    if (pool == 0)
        return ZB_ERR_BAD_ARGUMENT;

    record = Nwk_RreqTxOf(pool, destAddr, requestId);

    if (record == 0)
        record = nwkRreqTxIdle(pool);

    if (record == 0)
        return ZB_ERR_NO_SPACE;

    status = nwkRreqTxArm(record, npdu, npduLen, headerLen, secured, nowMs);

    if (status != ZB_OK)
        return status;

    record->keyAddr = destAddr;
    record->requestId = requestId;
    record->manyToOne = manyToOne;

    return ZB_OK;
}

ZbStatus Nwk_RreqTxStartRelay(Nwk_RreqTx *pool, uint16_t sourceAddr, uint8_t requestId, const uint8_t *npdu,
                              uint32_t npduLen, uint32_t headerLen, int secured, uint32_t firstTxMs)
{
    Nwk_RreqTx *record;
    ZbStatus status;

    if (pool == 0)
        return ZB_ERR_BAD_ARGUMENT;

    record = Nwk_RreqTxOf(pool, sourceAddr, requestId);

    if (record == 0)
        record = nwkRreqTxIdle(pool);

    if (record == 0)
        return ZB_ERR_NO_SPACE;

    status = nwkRreqTxArm(record, npdu, npduLen, headerLen, secured, firstTxMs);

    if (status != ZB_OK)
        return status;

    record->keyAddr = sourceAddr;
    record->requestId = requestId;
    record->relay = 1;

    return ZB_OK;
}

/* One transmission of a schedule at its jittered time: a refused transmit spends its attempt like a sent one, because
   the refusal is the layer's underneath and that layer counts it (nwk_relay.h), while an untouched budget would retry
   on every step of a replay that refuses every transmit (docs/internals/coding-rules.md §4.3). */
ZbStatus Nwk_RreqTxRun(Nwk_RreqTx *record, Mac_Mac *mac, Security *security, uint8_t *scratch,
                       uint32_t scratchMax, uint32_t nowMs, int *outSent, int *outProtectRefused)
{
    const uint8_t *octets;
    uint32_t octetLen;
    uint32_t securedLen;
    ZbStatus status;

    *outSent = 0;
    *outProtectRefused = 0;

    if (record == 0 || mac == 0 || !record->inUse)
        return ZB_OK;

    if (record->transmissions >= nwkRreqTxCount(record))
        return ZB_OK;

    if (!Zb_timeReached(nowMs, record->nextTxMs))
        return ZB_OK;

    octets = record->npdu;
    octetLen = record->npduLen;

    if (record->secured)
    {
        status = Nwk_TxProtect(security, record->npdu, record->npduLen, record->headerLen, scratch,
                               scratchMax, &securedLen);

        if (status != ZB_OK)
        {
            *outProtectRefused = 1;
            return status;
        }

        octets = scratch;
        octetLen = securedLen;
    }

    status = Nwk_TxIssueRaw(mac, octets, octetLen, NWK_ADDR_ROUTERS, 1, nowMs, 0);

    if (status != ZB_OK)
    {
        record->transmissions = record->transmissions + 1;
        record->nextTxMs = nowMs + NWK_RREQ_RETRY_INTERVAL_MS;

        if (record->relay && record->transmissions >= nwkRreqTxCount(record))
            Zb_memset(record, 0, (uint32_t)sizeof *record);

        return ZB_OK;
    }

    record->transmissions = record->transmissions + 1;
    record->nextTxMs = nowMs + NWK_RREQ_RETRY_INTERVAL_MS;
    *outSent = 1;

    if (record->relay && record->transmissions >= nwkRreqTxCount(record))
        Zb_memset(record, 0, (uint32_t)sizeof *record);

    return ZB_OK;
}

void Nwk_RreqTxStop(Nwk_RreqTx *pool, uint16_t keyAddr, uint8_t requestId)
{
    Nwk_RreqTx *record;

    if (pool == 0)
        return;

    record = Nwk_RreqTxOf(pool, keyAddr, requestId);

    if (record == 0)
        return;

    Zb_memset(record, 0, (uint32_t)sizeof *record);
}
