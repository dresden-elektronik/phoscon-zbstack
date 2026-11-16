#ifndef MAC_TX_H
#define MAC_TX_H

/*
 * The transmit track pool and the frame composition; docs/internals/protocol.md §9.1 owns its contract.
 */

#include <stdint.h>

#include "radio.h"
#include "zb_status.h"

/* The transmit subject's own state: the track pool, and the DSN the next frame this module composes will carry
   (7.2.3, the Sequence Number field). */
typedef struct Mac_Tx
{
    Mac_Track track[MAC_TX_TRACK_MAX];
    uint32_t dsn;
} Mac_Tx;

/* What one collection pass leaves the façade to answer for: the timeouts the seam declared, the re-arm they or a
   lost device ask for, and the slots whose answers an attempt this module issued is owed to (10.22.2, 6.6.1). */
typedef struct Mac_TxCompletions
{
    uint32_t timeouts;
    int needsRearm;
    Mac_Track *answered[MAC_TX_TRACK_MAX];
    uint32_t answeredCount;
} Mac_TxCompletions;

/* The ask a command frame carries, which is the command's own law and not the caller's (10.22.4.1, 7.5.2). */
int MacTx_CommandAckRequest(const Mac_DataRequestParameters *req);

/* Whether the frame a request will compose is Table 7-11's 0x04 or 0x02, read off its Content's first octet. */
int MacTx_IsDataRequestCommand(const Mac_DataRequestParameters *req);
int MacTx_IsAssociationResponseCommand(const Mac_DataRequestParameters *req);

/* 6.2's broadcast short address, and the 64-bit broadcast a frame sent to it asks no acknowledgment of. */
int MacTx_IsBroadcastShortAddress(uint16_t shortAddress);
int MacTx_IsBroadcastExtendedAddress(uint64_t extendedAddress);

/* 6.6.3.1: whether the destination forbids the acknowledgment the caller asked for. */
int MacTx_AskIsImpossible(const Mac_DataRequestParameters *req, int ackRequest);

/* Whether the frame a request will become still fits one 127-octet MPDU: the composition's own ceiling, applied at
   the door (`ownExtended` being this device's address, the frame's source field). */
int MacTx_TransactionFits(const Mac_DataRequestParameters *req, const Radio_Pib *pib, uint64_t ownExtended);

/* The checks a request passes before anything is composed, counted where the door counts them: every check but the
   first is a refusal this module counted, not a loss. */
ZbStatus MacTx_ValidateRequest(const Mac_DataRequestParameters *req, const Radio_Pib *pib, int ownExtendedKnown,
                               uint32_t *refusedRequests);

/* One already-validated request composed into a free slot at the DSN the caller names and put on the air
   (10.22.4.1's ask, R23.1 Annex D.6's version); the slot is the frame's confirmation once the seam answers.
   `indirect` says the frame answers a poll, which 6.6.3.4 never retransmits. */
ZbStatus MacTx_IssueFrame(Mac_Tx *tx, const Mac_DataRequestParameters *req, const Radio_Pib *pib,
                          uint64_t ownExtended, Radio_Radio *radio, uint8_t *mpdu, uint32_t mpduCap,
                          uint32_t dsn, uint32_t nowMs, int indirect, Mac_Track **outSlot,
                          uint32_t *refusedRequests);

/* The slot a transmit is tracked in, or 0 when the pool is full: full is refusal-and-count at the door
   (docs/internals/coding-rules.md §4.3, §7's free/filled/in-flight). */
Mac_Track *MacTx_FreeSlot(Mac_Tx *tx);

/* The slot a handle names, whether the seam has said what became of it, and the release that returns a slot with no
   confirmation reported for it. */
Mac_Track *MacTx_TrackNamed(Mac_Tx *tx, uint32_t handle, int valid);
int MacTx_TrackAnswered(const Mac_Track *slot);
void MacTx_TrackRelease(Mac_Track *slot);

/* A frame this MAC issued on its own account owes the caller no confirmation: the module that asked for it reads
   the outcome from the slot and reports it through its own primitive. */
void MacTx_TrackNoConfirm(Mac_Tx *tx, Radio_Handle handle);

/* The seam's answer for every transmit in flight: the slot's state and status, `acked` only where the radio reports
   one, and a completion that never arrives declared a timeout (6.6.1). */
void MacTx_CollectCompletions(Mac_Tx *tx, Radio_Radio *radio, const Radio_Caps *caps, uint32_t nowMs,
                              Mac_TxCompletions *out);

#endif /* MAC_TX_H */
