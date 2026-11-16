#ifndef NWK_RREQTX_H
#define NWK_RREQTX_H

/*
 * 3.6.4.5.1's Route Request broadcast schedule; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "mac.h"
#include "nwk_discovery.h"
#include "nwk_frame.h"
#include "security.h"
#include "zb_status.h"

enum
{
    NWK_INITIAL_RREQ_RETRIES = 3,      /* nwkcInitialRREQRetries, Table 3-65, the retries after the initial broadcast */
    NWK_RREQ_RETRY_INTERVAL_MS = 254,  /* nwkcRREQRetryInterval, Table 3-65: 0xfe msec at 2.4 GHz */
    NWK_RREQ_TX_COUNT = NWK_INITIAL_RREQ_RETRIES + 1, /* 3.6.4.5.1: "nwkcInitialRREQRetries + 1 transmissions" */

    /* One schedule per Table 3-79 entry an initiation creates, so the two pools are one number and agree: a
       discovery slot claimed is a schedule slot claimed, and the relay schedules sit in the same bound because
       9152-9155 gives each request this device forwards an entry of that same table */
    NWK_RREQ_TX_MAX = NWK_DISCOVERY_MAX
};

/* One schedule, keyed as 9191-9192's discard rule names the pair: the octets are stored once and repeated verbatim. */
typedef struct Nwk_RreqTx
{
    int inUse;
    int relay;                      /* 1 for 3.6.4.5.1.4's schedule: a count of nwkcRREQRetries + 1, never the initiator's */
    uint16_t keyAddr;               /* the discovery's destination, or the relayed request's originator */
    uint8_t requestId;              /* Table 3-79's request id: the other half of the key, so a retry, a stop and a supersede find theirs */
    uint32_t manyToOne;             /* Table 3-55; 9078 retries none of it */
    uint32_t transmissions;         /* how much of 3.6.4.5.1's schedule has gone out */
    uint32_t nextTxMs;              /* the instant the next transmission is due */
    uint32_t npduLen;
    uint32_t headerLen;             /* the header split a protection of these octets is given */
    int secured;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
} Nwk_RreqTx;

/* The record the key names, live or idle, or 0 when the pool holds none. */
Nwk_RreqTx *Nwk_RreqTxOf(Nwk_RreqTx *pool, uint16_t keyAddr, uint8_t requestId);

/* How many records hold a schedule; a schedule that has run its count still holds its record until it is stopped. */
uint32_t Nwk_RreqTxHeld(const Nwk_RreqTx *pool);

/* Arm 3.6.4.5.1's schedule for one initiation: a first transmission due at `nowMs`. */
ZbStatus Nwk_RreqTxStart(Nwk_RreqTx *pool, uint16_t destAddr, uint8_t requestId, uint32_t manyToOne,
                         const uint8_t *npdu, uint32_t npduLen, uint32_t headerLen, int secured,
                         uint32_t nowMs);

/* Arm 3.6.4.5.1.4's relay schedule: the same record and the same octets-once rule, the first transmission at the jitter's instant. */
ZbStatus Nwk_RreqTxStartRelay(Nwk_RreqTx *pool, uint16_t sourceAddr, uint8_t requestId, const uint8_t *npdu,
                              uint32_t npduLen, uint32_t headerLen, int secured, uint32_t firstTxMs);

/* One transmission if one is due at `nowMs`: Table 3-80's routers broadcast, no acknowledgment asked. */
ZbStatus Nwk_RreqTxRun(Nwk_RreqTx *record, Mac_Mac *mac, Security *security, uint8_t *scratch,
                       uint32_t scratchMax, uint32_t nowMs, int *outSent, int *outProtectRefused);

/* Release the record the key names: the schedule stops when its purpose is met or its timer expires. */
void Nwk_RreqTxStop(Nwk_RreqTx *pool, uint16_t keyAddr, uint8_t requestId);

#endif /* NWK_RREQTX_H */
