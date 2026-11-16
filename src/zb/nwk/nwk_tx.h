#ifndef NWK_TX_H
#define NWK_TX_H

/*
 * The transmit slots and the machinery that fills them; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "mac.h"
#include "nwk_frame.h"
#include "security.h"
#include "zb_limits.h"
#include "zb_status.h"

enum
{
    /* frames taken back and not yet answered: sized like the MAC track pool (docs/internals/coding-rules.md §4.3) */
    NWK_TX_MAX = ZB_LIMIT_NWK_TX,
    NWK_TX_HELD_UNTRACKED = 0,      /* the MSDU handle of a held raw frame whose confirm nothing pairs */
    NWK_TX_HELD_RELAY_FIRST = NWK_TX_MAX + 1, /* the first held relay's MSDU handle, past every slot's (1 to NWK_TX_MAX) */
    NWK_RELAY_HELD_MAX = 4,         /* relays held for a resting child and tracked at once, each under its own handle */
    NWK_UNICAST_RETRY_DELAY_MS = 50, /* nwkcUnicastRetryDelay, Table 3-65: a floor on the gap between attempts, not a schedule */
    NWK_BROADCAST_HOLD_MS = 500,    /* how long a broadcast refused for room is asked again; no longer than nwkPassiveAckTimeout, so its table record never resends it while held */
};

/* One frame this module has taken back, its NPDU stored byte for byte in the unsecured form each attempt protects afresh (3.6.4.3, 3.2.1.1.3). */
typedef enum Nwk_TxState
{
    NWK_TX_FREE = 0,            /* no frame in this slot */
    NWK_TX_OUTSTANDING = 1,     /* issued to the MAC; its answer has not come back yet */
    NWK_TX_AWAITING_RETRY = 2,  /* an attempt failed and the next one is not due yet */
    NWK_TX_AWAITING_ROUTE = 3   /* the stored NPDU waits for 3.6.4.5.1's discovery, which is what 3.3.1.1.3 says the bit is for */
} Nwk_TxState;

typedef struct Nwk_Tx
{
    uint32_t state;             /* Nwk_TxState */
    uint16_t dstAddr;           /* the NWK destination the request named */
    uint16_t nextHop;           /* the unicast next hop; a broadcast carries the class here and 0xffff to the MAC (3.2.1.1.3 step 6 a.3) */
    uint8_t requestId;          /* for NWK_TX_AWAITING_ROUTE: Table 3-79's key of the discovery this request waits on */
    uint8_t seq;
    uint32_t npduLen;
    uint32_t headerLen;           /* the NWK header half of `npdu`: the split Security_Protect is given */
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    int secured;                  /* 1 when each attempt protects the stored octets afresh, 0 when they go on the air verbatim */
    uint32_t attempts;
    uint32_t nextRetryMs;       /* the floor: not a moment before this, whatever else is ready */
    uint32_t heldSinceMs;       /* a broadcast refused for room: its first refusal, where the hold is counted from */
    Radio_Handle lastHandle;    /* the transmit the MAC last ran for this frame, which is how its answer is matched back */
    int isBroadcast;
    int toParent;                 /* 3.6.6: an end device's broadcast goes to its parent's address at the MAC layer */
    int indirect;                 /* the next hop is a child whose receiver rests, so the MAC holds the frame for its poll */
    uint8_t msduHandle;           /* what the MAC's confirm of a held frame names it by: this slot's index plus one */
    int forwarded;                /* carried for the network rather than asked by the next higher layer: no confirm is owed */
    int reportsFailure;           /* a relayed data frame, whose final failure 8882-8884 report to its source */
    uint16_t sourceAddr;          /* that frame's NWK source */
} Nwk_Tx;

/* The slot that holds a frame this module still owes an answer for, or 0 when the pool is full. */
Nwk_Tx *Nwk_TxFree(Nwk_Tx *pool);

/* How many slots hold a frame: the number the request door adds to the confirmation ring's depth before it
   refuses, a frame being in one of the two and never in both (docs/internals/coding-rules.md §4.3). */
uint32_t Nwk_TxOccupied(const Nwk_Tx *pool);

/* Compose the NPDU a slot stores from an accepted request (3.2.1.1.3); the sequence number is taken here, where the frame is made (3.3.1.5). */
ZbStatus Nwk_TxCompose(Nwk_Tx *tx, const Nwk_DataRequestParameters *req, uint16_t srcAddr, uint32_t *seq,
                       int endDeviceInitiator, const Nwk_SourceRouteEntry *sourceRoute);

/* 8874-8877: a unicast this device carries for the network, already composed, takes a slot so that its retries run and
   each attempt is secured anew; a refusal the clause retries is not a failure yet. ZB_ERR_NO_SPACE with no slot. */
ZbStatus Nwk_TxForward(Nwk_Tx *tx, Mac_Mac *mac, Security *security, uint8_t *scratch, uint32_t scratchMax,
                       const uint8_t *npdu, uint32_t npduLen, uint32_t headerLen, int secured, uint8_t seq,
                       uint16_t nextHop, uint16_t dstAddr, uint32_t nowMs, int *protectRefused);

/* The same copy stored and not yet sent, for a relay that waits on a route discovery (9060). ZB_ERR_NO_SPACE with no
   slot or no room for the octets. */
ZbStatus Nwk_TxHold(Nwk_Tx *tx, const uint8_t *npdu, uint32_t npduLen, uint32_t headerLen, int secured, uint8_t seq,
                    uint16_t dstAddr);

/* One attempt at the frame a slot holds, the only way a slot gets onto the air (3.2.1.1.3). */
ZbStatus Nwk_TxIssueAttempt(Nwk_Tx *tx, Mac_Mac *mac, Security *security, uint8_t *scratch,
                            uint32_t scratchMax, uint32_t nowMs, int *retryable, int *protectRefused);

/* Whether a status the seam answered calls for another attempt, stated once for the refusal at the door and the failed completion above it (3.2.1.1.3, docs/internals/protocol.md §7.3). */
int Nwk_TxRetryOwed(ZbStatus status);

/* Whether the door refused for want of room, so the frame never reached the air: the one refusal a broadcast waits out. */
int Nwk_TxRefusedForRoom(ZbStatus status);

/* Whether a failed frame says anything of the link to its next hop: not one refused for room, nor one that ended with the RCP. */
int Nwk_TxBlamesNextHop(ZbStatus status);

/* A NWK destination as a MAC one: every one of Table 3-80's classes goes to 0xffff (3.2.1.1.3 step 6 a.3). */
uint16_t Nwk_TxMacDestination(uint16_t nextHop, int isBroadcast, int toParent);

/* Octets the caller already holds, onto the air with no slot taken and no confirmation owed (3.2.1.2.1). */
ZbStatus Nwk_TxIssueRaw(Mac_Mac *mac, const uint8_t *npdu, uint32_t npduLen, uint16_t nextHop,
                        int isBroadcast, uint32_t nowMs, Radio_Handle *outHandle);

/* The same octets onto the air at once or, `held`, onto the MAC's transaction queue for the neighbour's poll
   (10.22.2), which a frame for a child whose receiver rests needs; a held frame has no radio handle, and its
   confirm carries `heldHandle` as its MSDU handle. */
ZbStatus Nwk_TxOfferRaw(Mac_Mac *mac, const uint8_t *npdu, uint32_t npduLen, uint16_t nextHop, int held,
                        uint8_t heldHandle, uint32_t nowMs, Radio_Handle *outHandle);

/* The secured form of unsecured octets in the caller's scratch: 4.3.2's auxiliary header goes between the header fields and the payload. */
ZbStatus Nwk_TxProtect(Security *security, const uint8_t *npdu, uint32_t npduLen, uint32_t headerLen,
                       uint8_t *scratch, uint32_t scratchMax, uint32_t *outLen);

/* Whether a device runs NWK security at all: a `Security` attached, and that module answering enabled. */
int Nwk_TxSecurityRuns(const Security *security);

/* The Table 3-84 code of a protection this device attempted and did not get, for the `nwkStatus` a
   confirmation carries: the one place the seam's words and the NWK layer's octets are tied together. */
uint32_t Nwk_TxConfirmStatus(ZbStatus status);

#endif /* NWK_TX_H */
