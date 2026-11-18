#ifndef MAC_INDIRECT_H
#define MAC_INDIRECT_H

/*
 * 10.22.2's transaction queue and the poll that extracts it; docs/internals/conformance.md §1 owns its contract.
 */

#include <stdint.h>

#include "mac_tx.h"
#include "radio.h"
#include "zb_status.h"

/* How many short/extended pairs this queue can join. A pairing is only ever looked up to match a transaction or
   a poll, so it is the transaction pool's own size. */
enum
{
    MAC_ADDRESS_PAIR_MAX = MAC_TRANSACTION_MAX
};

/* One device's two address forms, learned where this MAC is told both: the association door is the only place a
   frame names one and the layer above supplies the other (10.21.5.2). */
typedef struct Mac_AddressPair
{
    int used;
    uint16_t shortAddress;
    uint64_t extendedAddress;
} Mac_AddressPair;

/* The indirect subject's own state: the pool 10.22.2 holds a sleeping device's frames in, the two numbers the
   queue is read by, and the pairs its address forms are matched through; `pendingStatedComplete` says the radio
   holds a complete pending table, so its Ack's bit is the queue's and an empty poll its Ack ended is counted. */
typedef struct Mac_Indirect
{
    Mac_Transaction transactions[MAC_TRANSACTION_MAX];
    uint32_t transactionsExpired;
    uint32_t confirmsRefused;

    Mac_DataConfirmParameters confirms[MAC_INDIRECT_CONFIRM_MAX];
    uint32_t confirmHead;
    uint32_t confirmCount;
    uint32_t pollsUnanswered;
    uint32_t pollsEndedByAck;
    int pendingStatedComplete;

    Mac_AddressPair pairs[MAC_ADDRESS_PAIR_MAX];
    uint32_t pairsLearned;
    uint32_t pairsRefused;

    Mac_CommStatusParameters commStatus[MAC_COMM_STATUS_MAX];
    uint32_t commStatusHead;
    uint32_t commStatusCount;
    uint32_t commStatusRefused;
} Mac_Indirect;

/* Queue one indirect transmission request (10.22.2) at the DSN the caller issues at, which the queue reserves so a
   re-extraction reuses it (6.6.3.4). `isMlmeInstigated` marks a transaction a response primitive started, whose
   outcome belongs to MLME-COMM-STATUS.indication rather than to a caller's confirm. */
ZbStatus MacIndirect_Queue(Mac_Indirect *indirect, int isMlmeInstigated, const Mac_DataRequestParameters *req,
                           const Radio_Pib *pib, int ownExtendedKnown, uint64_t ownExtended, Radio_Radio *radio,
                           uint32_t *dsn, uint32_t *refusedRequests, uint32_t nowMs);

/* The same queue through the layer above's door, which refuses 10.21.5.2's answer: only Mac_AssociateResponse may
   write that body, its status and short-address rules needing the request's Allocate Address capability. */
ZbStatus MacIndirect_Request(Mac_Indirect *indirect, const Mac_DataRequestParameters *req, const Radio_Pib *pib,
                             int ownExtendedKnown, uint64_t ownExtended, Radio_Radio *radio, uint32_t *dsn,
                             uint32_t *refusedRequests, uint32_t nowMs);

/* Everything the queue holds for the device a poll came from, attempt outstanding or not. */
uint32_t MacIndirect_QueuedFor(const Mac_Indirect *indirect, const Mac_PollArrival *poll);

/* One detected poll answered from the queue: the oldest transaction held for that device, or 10.22.3's empty
   answer, issued from the caller's track pool and MPDU scratch. */
ZbStatus MacIndirect_DoPollAnswer(Mac_Indirect *indirect, const Mac_PollArrival *poll, Mac_Tx *tx,
                                  const Radio_Pib *pib, int ownExtendedKnown, uint64_t ownExtended,
                                  Radio_Radio *radio, uint8_t *mpdu, uint32_t mpduCap, uint32_t *dsn,
                                  uint32_t *refusedRequests, uint32_t nowMs);

/* 10.22.2's persistence: a transaction older than macTransactionPersistenceTime is discarded and counted. */
void MacIndirect_AgeTransactions(Mac_Indirect *indirect, uint32_t nowMs);

/* What an answered track slot means for the transaction it was an attempt of: acknowledged it leaves, refused or
   timed out only the attempt flag drops (10.22.2, 6.6.3.4, 6.6.1). */
/* 10.22.2's confirmation for a transaction that finished: SUCCESS once the extraction was acknowledged, and the
   failure statuses the clause names otherwise. */
uint32_t MacIndirect_PollConfirms(Mac_Indirect *indirect, Mac_DataConfirmParameters *out, uint32_t max);

void MacIndirect_ReleaseAttempt(Mac_Indirect *indirect, Mac_Track *slot);

/* 10.22.2's other primitive: the outcome of a transaction an MLME response started, related to it by the
   destination address the frame named. Same full-pool policy as the confirm ring. */
uint32_t MacIndirect_PollCommStatus(Mac_Indirect *indirect, Mac_CommStatusParameters *out, uint32_t max);

/* 10.21.5.2's answer names the device's extended address and the short address it is given, which is the one place
   both forms of a child are known to this MAC. A short address that was never allocated (0xfffe, 0xffff) or no
   extended address at all is no pairing, and a full pool refuses rather than dropping another device's. */
ZbStatus MacIndirect_LearnPair(Mac_Indirect *indirect, uint16_t shortAddress, uint64_t extendedAddress);

/* The pair a device's form belongs to, or 0 where this queue holds none: what lets a poll in either form find the
   transaction, and what tells band A whether it can name every device it holds a frame for (10.22.3). */
const Mac_AddressPair *MacIndirect_PairFor(const Mac_Indirect *indirect, Mac_AddrMode mode,
                                           uint16_t shortAddress, uint64_t extendedAddress);

/* The device half of 10.22.3: no poll out, a Data Request sent and its acknowledgment awaited, or the receiver held
   on for the frame an Ack with Frame Pending one promised. */
typedef enum Mac_ChildPollState
{
    MAC_CHILD_POLL_IDLE = 0,
    MAC_CHILD_POLL_SENT = 1,
    MAC_CHILD_POLL_LISTENING = 2
} Mac_ChildPollState;

/* One Data Request's window: the transmit its Ack is read from, the coordinator its answer comes from, and the
   instant the receiver began listening. */
typedef struct Mac_ChildPollWindow
{
    Mac_ChildPollState state;
    Radio_Handle handle;
    Mac_AddrMode coordMode;
    uint16_t coordShort;
    uint64_t coordExtended;
    uint32_t listenMs;
} Mac_ChildPollWindow;

/* The device half's own state: the window of the poll MLME-POLL.request sent, which owes a confirm, and of the
   latest Data Request this MAC sent otherwise, each open on its own; whether MLME-POLL is issuing one now, the
   confirm, and what was counted. */
enum
{
    MAC_CHILD_POLL_OTHER = 0,
    MAC_CHILD_POLL_PRIMITIVE = 1,
    MAC_CHILD_POLL_WINDOWS = 2
};

typedef struct Mac_ChildPoll
{
    Mac_ChildPollWindow window[MAC_CHILD_POLL_WINDOWS];
    uint8_t pollBytes[1];
    int issuing;
    Mac_PollConfirmParameters confirm;
    int confirmReady;
    uint32_t pollsRequested;
    uint32_t pollsWithData;
    uint32_t pollsNoData;
    uint32_t heardAsleep;
} Mac_ChildPoll;

/* A Data Request this device sent: its window opens now, so a frame its parent answers with before the completion
   is collected is still heard. */
void MacIndirect_ChildPollSent(Mac_ChildPoll *poll, const Mac_DataRequestParameters *req, Radio_Handle handle,
                               int isPrimitive);

/* The Data Request's completion: no acknowledgment ends the poll with the transmit's status, an Ack that reported
   Frame Pending zero ends it with NO_DATA, and any other holds the receiver on for MAC_POLL_WAIT_MS. */
void MacIndirect_ChildPollAnswered(Mac_ChildPoll *poll, const Mac_Track *slot, uint32_t nowMs);

/* A window whose frame did not come in MAC_POLL_WAIT_MS ends with NO_DATA (10.22.5.3). */
void MacIndirect_ChildPollExpire(Mac_ChildPoll *poll, uint32_t nowMs);

/* Whether a received frame is kept: 1 for every frame while `hears`, and while a window is open. A frame from the
   coordinator addressed to this device ends one window, MLME-POLL's first: SUCCESS with a payload, else NO_DATA. */
int MacIndirect_ChildPollAdmits(Mac_ChildPoll *poll, const Radio_Frame *frame, int hasFrameFcs, const Radio_Pib *pib,
                                uint64_t ownExtended, int hears);

int MacIndirect_ChildPollOpen(const Mac_ChildPoll *poll);
int MacIndirect_ChildPollRequested(const Mac_ChildPoll *poll);
uint32_t MacIndirect_ChildPollConfirm(Mac_ChildPoll *poll, Mac_PollConfirmParameters *out);

#endif /* MAC_INDIRECT_H */
