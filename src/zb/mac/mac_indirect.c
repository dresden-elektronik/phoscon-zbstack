#include "mac.h"

#include "mac_indirect.h"

#include "zb_time.h"
#include "zb_utils.h"

/* M2024: 6.6.1, 6.6.3.4, 6.6.6, 10.21.5.2, 10.22.2, 10.22.5.2, 10.22.5.3 ok; 7.2.2.4 ok for a device whose two
   address forms the association door named, deferred for one it never named; 8.3.4 unbuilt (the GTS limb); 10.22.3 ok
   (both halves: the Ack bit stated from the table this queue writes, bench 6.67, and read from a poll's completion). */

ZbStatus MacIndirect_Queue(Mac_Indirect *indirect, int isMlmeInstigated, const Mac_DataRequestParameters *req,
                           const Radio_Pib *pib, int ownExtendedKnown, uint64_t ownExtended, Radio_Radio *radio,
                           uint32_t *dsn, uint32_t *refusedRequests, uint32_t nowMs)
{
    Mac_Transaction *slot;
    uint32_t i;
    ZbStatus status;

    if (indirect == 0 || req == 0 || radio == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if ((req->destAddrMode == MAC_ADDR_SHORT && MacTx_IsBroadcastShortAddress(req->destShort))
        || (req->destAddrMode == MAC_ADDR_EXTENDED && MacTx_IsBroadcastExtendedAddress(req->destExtended)))
    {
        (*refusedRequests)++;
        return ZB_ERR_UNSUPPORTED;    /* a broadcast is never a transaction: the beacon is its only pending form here, docs/internals/conformance.md §1 */
    }

    status = MacTx_ValidateRequest(req, pib, ownExtendedKnown, refusedRequests);

    if (status != ZB_OK)
        return status;

    if (MacTx_IsDataRequestCommand(req))
    {
        (*refusedRequests)++;
        return ZB_ERR_UNSUPPORTED;    /* a poll is the asking device's own act, never a transaction held, docs/internals/conformance.md §1 */
    }

    if (!MacTx_TransactionFits(req, pib, ownExtended))
    {
        (*refusedRequests)++;
        return ZB_ERR_BAD_ARGUMENT;   
    }

    slot = 0;

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (!indirect->transactions[i].used)
        {
            slot = &indirect->transactions[i];
            break;
        }
    }

    if (slot == 0)
    {
        (*refusedRequests)++;
        return ZB_ERR_TRANSACTION_OVERFLOW;
    }

    Zb_memset(slot, 0, (uint32_t)sizeof *slot);

    slot->used = 1;

    slot->dsn = *dsn;

    slot->arrivedMs = nowMs;

    slot->msduHandle = req->msduHandle;
    slot->frameType = req->frameType;
    slot->ackRequest = req->ackRequest;
    slot->isMlmeInstigated = isMlmeInstigated ? 1 : 0;
    slot->destAddrMode = req->destAddrMode;
    slot->srcAddrMode = req->srcAddrMode;
    slot->destPan = req->destPan;
    slot->destShort = req->destShort;
    slot->destExtended = req->destExtended;
    slot->payloadLen = req->payloadLen;

    if (req->payloadLen != 0)
        Zb_memcpy(slot->payload, req->payload, req->payloadLen);

    *dsn = *dsn + 1;

    return ZB_OK;
}

ZbStatus MacIndirect_Request(Mac_Indirect *indirect, const Mac_DataRequestParameters *req, const Radio_Pib *pib,
                             int ownExtendedKnown, uint64_t ownExtended, Radio_Radio *radio, uint32_t *dsn,
                             uint32_t *refusedRequests, uint32_t nowMs)
{
    if (indirect == 0 || req == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (req->destAddrMode == MAC_ADDR_NONE)
    {
        (*refusedRequests)++;
        return ZB_ERR_BAD_ARGUMENT;
    }

    if (MacTx_IsAssociationResponseCommand(req))
    {
        (*refusedRequests)++;
        return ZB_ERR_UNSUPPORTED;    /* 10.21.5.2's answer is queued only by Mac_AssociateResponse: not built, docs/internals/conformance.md §1 */
    }

    return MacIndirect_Queue(indirect, 0, req, pib, ownExtendedKnown, ownExtended, radio, dsn, refusedRequests,
                             nowMs);
}

/* 10.21.5.2's answer names the device's extended address and the short address it is given, which is the one place
   both forms of a child are known here. */
ZbStatus MacIndirect_LearnPair(Mac_Indirect *indirect, uint16_t shortAddress, uint64_t extendedAddress)
{
    Mac_AddressPair *free = 0;
    uint32_t i;

    if (indirect == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (shortAddress >= MAC_SHORT_ADDRESS_LAST_USABLE || extendedAddress == 0)
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < MAC_ADDRESS_PAIR_MAX; i++)
    {
        if (!indirect->pairs[i].used)
        {
            if (free == 0)
                free = &indirect->pairs[i];

            continue;
        }

        if (indirect->pairs[i].shortAddress == shortAddress
                || indirect->pairs[i].extendedAddress == extendedAddress)
        {
            indirect->pairs[i].shortAddress = shortAddress;
            indirect->pairs[i].extendedAddress = extendedAddress;
            indirect->pairsLearned++;
            return ZB_OK;
        }
    }

    if (free == 0)
    {
        indirect->pairsRefused++;
        return ZB_ERR_NO_SPACE;
    }

    free->used = 1;
    free->shortAddress = shortAddress;
    free->extendedAddress = extendedAddress;
    indirect->pairsLearned++;
    return ZB_OK;
}

const Mac_AddressPair *MacIndirect_PairFor(const Mac_Indirect *indirect, Mac_AddrMode mode,
                                           uint16_t shortAddress, uint64_t extendedAddress)
{
    uint32_t i;

    if (indirect == 0)
        return 0;

    for (i = 0; i < MAC_ADDRESS_PAIR_MAX; i++)
    {
        if (!indirect->pairs[i].used)
            continue;

        if (mode == MAC_ADDR_SHORT && indirect->pairs[i].shortAddress == shortAddress)
            return &indirect->pairs[i];

        if (mode == MAC_ADDR_EXTENDED && indirect->pairs[i].extendedAddress == extendedAddress)
            return &indirect->pairs[i];
    }

    return 0;
}

/* Whether two address forms name one device: equal forms compare directly, and different forms meet where the
   association door learned the pair. A form this queue knows no pair for names no device it can find. */
static int macSameDevice(const Mac_Indirect *indirect, Mac_AddrMode modeLeft, uint16_t shortLeft,
                         uint64_t extendedLeft, Mac_AddrMode modeRight, uint16_t shortRight,
                         uint64_t extendedRight)
{
    const Mac_AddressPair *pair;

    if (modeLeft == modeRight)
    {
        if (modeLeft == MAC_ADDR_SHORT)
            return shortLeft == shortRight;

        if (modeLeft == MAC_ADDR_EXTENDED)
            return extendedLeft == extendedRight;

        return 0;
    }

    pair = MacIndirect_PairFor(indirect, modeLeft, shortLeft, extendedLeft);

    if (pair == 0)
        return 0;

    if (modeRight == MAC_ADDR_SHORT)
        return pair->shortAddress == shortRight;

    if (modeRight == MAC_ADDR_EXTENDED)
        return pair->extendedAddress == extendedRight;

    return 0;
}

static int macTransactionIsFor(const Mac_Indirect *indirect, const Mac_Transaction *transaction,
                               const Mac_PollArrival *poll)
{
    return macSameDevice(indirect, transaction->destAddrMode, transaction->destShort, transaction->destExtended,
                         poll->addrMode, poll->shortAddress, poll->extendedAddress);
}

/* The transaction this poll extracts: the oldest queued for that device that is not already on its way, arrival
   order being the reserved DSN's, and no second frame for one already outstanding. */
static Mac_Transaction *macTransactionFor(Mac_Indirect *indirect, const Mac_PollArrival *poll)
{
    Mac_Transaction *first;
    Mac_Transaction *transaction;
    uint32_t i;

    first = 0;

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        transaction = &indirect->transactions[i];

        if (!transaction->used || !macTransactionIsFor(indirect, transaction, poll))
            continue;

        if (first == 0 || transaction->dsn < first->dsn)
            first = transaction;
    }

    if (first == 0 || first->attemptPending)
        return 0;

    return first;
}

/* How many transactions for that device are left once `sent` has gone out, which is the Frame Pending fact and
   zero on the last one. One holding an outstanding attempt counts: it may yet be re-extracted, and a device told
   that nothing is pending stops asking. */
static uint32_t macTransactionsRemaining(const Mac_Indirect *indirect, const Mac_Transaction *sent)
{
    const Mac_Transaction *transaction;
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        transaction = &indirect->transactions[i];

        if (transaction == sent)
            continue;

        if (!transaction->used)
            continue;

        if (!macSameDevice(indirect, transaction->destAddrMode, transaction->destShort,
                           transaction->destExtended, sent->destAddrMode, sent->destShort,
                           sent->destExtended))
            continue;

        count++;
    }

    return count;
}

/* Everything the queue holds for that device, attempt outstanding or not: what a poll found something for. */
static uint32_t macTransactionsQueuedFor(const Mac_Indirect *indirect, const Mac_PollArrival *poll)
{
    uint32_t i;
    uint32_t count = 0;

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (!indirect->transactions[i].used)
            continue;

        if (!macTransactionIsFor(indirect, &indirect->transactions[i], poll))
            continue;

        count++;
    }

    return count;
}

/* The source form of a frame this module sends on its own account: Table 10-101 sends a Data frame from the short
   address below 0xfffe and from the extended one at 0xfffe, and 0xffff is the value with no Data row at all, a
   device that is on no PAN. NONE is that last case and the caller refuses rather than composing. */
static Mac_AddrMode macCoordinatorSrcMode(const Radio_Pib *pib, int ownExtendedKnown)
{
    if ((pib->present & RADIO_PIB_SHORT_ADDRESS) != 0
        && pib->shortAddress < MAC_SHORT_ADDRESS_LAST_USABLE)
        return MAC_ADDR_SHORT;

    if ((pib->present & RADIO_PIB_SHORT_ADDRESS) != 0 && pib->shortAddress >= MAC_FRAME_ADDR_BROADCAST)
        return MAC_ADDR_NONE;

    if ((pib->present & RADIO_PIB_EXTENDED_ADDRESS) != 0 && ownExtendedKnown)
        return MAC_ADDR_EXTENDED;

    return MAC_ADDR_NONE;
}

/* One detected poll, answered: the oldest transaction queued for it goes out with Frame Pending stating whether
   more is behind it (10.22.2), or a zero-length frame that asks no acknowledgment says nothing is pending
   (10.22.3). A poll whose transactions are all mid-attempt gets neither and is counted (6.6.3.4). */
ZbStatus MacIndirect_DoPollAnswer(Mac_Indirect *indirect, const Mac_PollArrival *poll, Mac_Tx *tx,
                                  const Radio_Pib *pib, int ownExtendedKnown, uint64_t ownExtended,
                                  Radio_Radio *radio, uint8_t *mpdu, uint32_t mpduCap, uint32_t *dsn,
                                  uint32_t *refusedRequests, uint32_t nowMs)
{
    Mac_Transaction *transaction;
    Mac_DataRequestParameters req;
    Mac_Track *slot;
    ZbStatus status;

    transaction = macTransactionFor(indirect, poll);

    if (transaction != 0)
    {
        Zb_memset(&req, 0, (uint32_t)sizeof req);

        req.frameType = transaction->frameType;
        req.destAddrMode = transaction->destAddrMode;
        req.srcAddrMode = transaction->srcAddrMode;
        req.destPan = transaction->destPan;
        req.destShort = transaction->destShort;
        req.destExtended = transaction->destExtended;
        req.payload = transaction->payload;
        req.payloadLen = transaction->payloadLen;

        req.ackRequest = transaction->ackRequest;
        req.framePending = macTransactionsRemaining(indirect, transaction) != 0;
        req.msduHandle = transaction->msduHandle;

        status = MacTx_IssueFrame(tx, &req, pib, ownExtended, radio, mpdu, mpduCap,
                                  transaction->dsn % MAC_DSN_WRAP, nowMs, 1, &slot, refusedRequests);

        if (status == ZB_ERR_NO_SPACE || status == ZB_ERR_BUSY)
        {
            indirect->pollsUnanswered++;
            return ZB_OK;
        }

        if (status != ZB_OK)
            return status;

        slot->msduHandle = transaction->msduHandle;
        slot->confirmOwed = 1;
        slot->isExtraction = 1;

        transaction->attemptPending = 1;
        transaction->attemptHandle = slot->handle;

        return ZB_OK;
    }

    if (macTransactionsQueuedFor(indirect, poll) != 0)
    {
        indirect->pollsUnanswered++;
        return ZB_OK;
    }

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    req.frameType = MAC_FRAME_TYPE_DATA;
    req.destAddrMode = poll->addrMode;
    req.destPan = pib->panId;
    req.destShort = poll->shortAddress;
    req.destExtended = poll->extendedAddress;
    req.srcAddrMode = macCoordinatorSrcMode(pib, ownExtendedKnown);

    if (req.srcAddrMode == MAC_ADDR_NONE)
    {
        indirect->pollsUnanswered++;
        return ZB_OK;
    }

    req.ackRequest = 0;     
    req.framePending = 0;   

    status = MacTx_IssueFrame(tx, &req, pib, ownExtended, radio, mpdu, mpduCap, *dsn % MAC_DSN_WRAP, nowMs, 1, &slot,
                              refusedRequests);

    if (status == ZB_ERR_NO_SPACE || status == ZB_ERR_BUSY)
    {
        indirect->pollsUnanswered++;
        return ZB_OK;
    }

    if (status != ZB_OK)
        return status;

    *dsn = *dsn + 1;

    return ZB_OK;
}

/* The confirmation a transaction's completion owes its caller, under the handle it queued it with. The newest is
   refused and counted when the ring is full, like every other pool here. */
static void macIndirectConfirm(Mac_Indirect *indirect, const Mac_Transaction *transaction, ZbStatus status, int acked)
{
    Mac_DataConfirmParameters *slot;

    if (indirect->confirmCount >= MAC_INDIRECT_CONFIRM_MAX)
    {
        indirect->confirmsRefused++;
        return;
    }

    slot = &indirect->confirms[(indirect->confirmHead + indirect->confirmCount) % MAC_INDIRECT_CONFIRM_MAX];

    Zb_memset(slot, 0, (uint32_t)sizeof *slot);

    slot->msduHandle = transaction->msduHandle;
    slot->dsn = transaction->dsn;
    slot->frameType = (int)transaction->frameType;
    slot->status = status;
    slot->acked = acked;

    indirect->confirmCount++;
}

/* The status, and the destination the frame named, which is what relates the indication to the response. */
static void macIndirectCommStatus(Mac_Indirect *indirect, const Mac_Transaction *transaction, ZbStatus status,
                                  int acked)
{
    Mac_CommStatusParameters *slot;

    if (indirect->commStatusCount >= MAC_COMM_STATUS_MAX)
    {
        indirect->commStatusRefused++;
        return;
    }

    slot = &indirect->commStatus[(indirect->commStatusHead + indirect->commStatusCount) % MAC_COMM_STATUS_MAX];

    Zb_memset(slot, 0, (uint32_t)sizeof *slot);

    slot->status = status;
    slot->destAddrMode = transaction->destAddrMode;
    slot->destPan = transaction->destPan;
    slot->destShort = transaction->destShort;
    slot->destExtended = transaction->destExtended;
    slot->acked = acked;

    indirect->commStatusCount++;
}

/* The primitive a finished transaction's outcome belongs to: the MLME's own for a response-instigated one, the
   caller's confirm otherwise. */
static void macIndirectReport(Mac_Indirect *indirect, const Mac_Transaction *transaction, ZbStatus status, int acked)
{
    if (transaction->isMlmeInstigated)
        macIndirectCommStatus(indirect, transaction, status, acked);
    else
        macIndirectConfirm(indirect, transaction, status, acked);
}

/* 10.22.2's persistence: a transaction persists for at most macTransactionPersistenceTime and is then discarded
   and counted TRANSACTION_EXPIRED, and 6.6.6 issues the failure confirmation with it. An attempt outstanding goes
   with it: the frame is on the air, not to be recalled. */
void MacIndirect_AgeTransactions(Mac_Indirect *indirect, uint32_t nowMs)
{
    uint32_t i;

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (!indirect->transactions[i].used)
            continue;

        if (Zb_timeWithin(nowMs, indirect->transactions[i].arrivedMs, MAC_TRANSACTION_PERSISTENCE_MS))
            continue;

        macIndirectReport(indirect, &indirect->transactions[i], ZB_ERR_TRANSACTION_EXPIRED, 0);

        Zb_memset(&indirect->transactions[i], 0, (uint32_t)sizeof indirect->transactions[i]);
        indirect->transactionsExpired++;
    }
}

/* The transaction an answered slot was an attempt of, found by the handle the extraction went out as.
   Acknowledged, it leaves (10.22.2); refused, only the attempt flag drops and the reserved DSN stays (6.6.3.4);
   a slot whose transaction expired while its frame was on the air owes nothing (6.6.1). */
uint32_t MacIndirect_PollConfirms(Mac_Indirect *indirect, Mac_DataConfirmParameters *out, uint32_t max)
{
    uint32_t taken = 0;

    if (indirect == 0 || out == 0)
        return 0;

    while (taken < max && indirect->confirmCount > 0)
    {
        out[taken] = indirect->confirms[indirect->confirmHead];
        indirect->confirmHead = (indirect->confirmHead + 1) % MAC_INDIRECT_CONFIRM_MAX;
        indirect->confirmCount--;
        taken++;
    }

    return taken;
}

uint32_t MacIndirect_PollCommStatus(Mac_Indirect *indirect, Mac_CommStatusParameters *out, uint32_t max)
{
    uint32_t taken = 0;

    if (indirect == 0 || out == 0)
        return 0;

    while (taken < max && indirect->commStatusCount > 0)
    {
        out[taken] = indirect->commStatus[indirect->commStatusHead];
        indirect->commStatusHead = (indirect->commStatusHead + 1) % MAC_COMM_STATUS_MAX;
        indirect->commStatusCount--;
        taken++;
    }

    return taken;
}

/* Whether an answered attempt was the extraction: an acknowledgment is proof only where one was asked, and a frame
   that asked for none succeeded when the radio reported it sent. */
static int macAttemptSucceeded(const Mac_Track *slot)
{
    return !slot->ackRequest && slot->state == MAC_TX_ANSWERED && slot->status == ZB_OK;
}

void MacIndirect_ReleaseAttempt(Mac_Indirect *indirect, Mac_Track *slot)
{
    uint32_t i;

    if (slot->handle == RADIO_HANDLE_NONE)
        return;

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (!indirect->transactions[i].used || !indirect->transactions[i].attemptPending)
            continue;

        if (indirect->transactions[i].attemptHandle != slot->handle)
            continue;

        if (indirect->transactions[i].isMlmeInstigated)
        {
            macIndirectReport(indirect, &indirect->transactions[i], slot->acked ? ZB_OK : slot->status,
                              slot->acked);

            slot->confirmOwed = 0;
        }

        if (slot->acked || macAttemptSucceeded(slot))
        {
            Zb_memset(&indirect->transactions[i], 0, (uint32_t)sizeof indirect->transactions[i]);
            return;
        }

        indirect->transactions[i].attemptPending = 0;
        indirect->transactions[i].attemptHandle = RADIO_HANDLE_NONE;
        return;
    }

    if (slot->isExtraction)
        slot->confirmOwed = 0;
}

static void macChildPollEnd(Mac_ChildPoll *poll, uint32_t which, ZbStatus status, int framePending)
{
    if (status == ZB_OK)
        poll->pollsWithData++;
    else if (status == ZB_ERR_NO_DATA)
        poll->pollsNoData++;

    if (which == MAC_CHILD_POLL_PRIMITIVE)
    {
        poll->confirm.status = status;
        poll->confirm.framePending = framePending;
        poll->confirmReady = 1;
    }

    poll->window[which].state = MAC_CHILD_POLL_IDLE;
    poll->window[which].handle = RADIO_HANDLE_NONE;
}

void MacIndirect_ChildPollSent(Mac_ChildPoll *poll, const Mac_DataRequestParameters *req, Radio_Handle handle,
                               int isPrimitive)
{
    Mac_ChildPollWindow *window = &poll->window[isPrimitive ? MAC_CHILD_POLL_PRIMITIVE : MAC_CHILD_POLL_OTHER];

    window->state = MAC_CHILD_POLL_SENT;
    window->handle = handle;
    window->coordMode = req->destAddrMode;
    window->coordShort = req->destShort;
    window->coordExtended = req->destExtended;

    if (isPrimitive)
        poll->pollsRequested++;
}

void MacIndirect_ChildPollAnswered(Mac_ChildPoll *poll, const Mac_Track *slot, uint32_t nowMs)
{
    uint32_t i;

    for (i = 0; i < MAC_CHILD_POLL_WINDOWS; i++)
    {
        if (poll->window[i].state != MAC_CHILD_POLL_SENT || slot->handle != poll->window[i].handle)
            continue;

        if (slot->status != ZB_OK)
            macChildPollEnd(poll, i, slot->status, 0);
        else if (slot->acked && slot->framePendingReported && !slot->framePending)
            macChildPollEnd(poll, i, ZB_ERR_NO_DATA, 0);
        else
        {
            poll->window[i].state = MAC_CHILD_POLL_LISTENING;
            poll->window[i].listenMs = nowMs;
        }
    }
}

void MacIndirect_ChildPollExpire(Mac_ChildPoll *poll, uint32_t nowMs)
{
    uint32_t i;

    for (i = 0; i < MAC_CHILD_POLL_WINDOWS; i++)
    {
        if (poll->window[i].state == MAC_CHILD_POLL_LISTENING
            && !Zb_timeWithin(nowMs, poll->window[i].listenMs, MAC_POLL_WAIT_MS))
            macChildPollEnd(poll, i, ZB_ERR_NO_DATA, 0);
    }
}

/* The frame a poll asked for: from the coordinator the Data Request went to, and addressed to this device in either
   of its forms, so the parent's own broadcasts leave the window open. */
static int macChildPollAnswers(const Mac_ChildPollWindow *window, const Mac_Frame *header, const Radio_Pib *pib,
                               uint64_t ownExtended)
{
    if (window->state == MAC_CHILD_POLL_IDLE)
        return 0;

    if (header->frameType != MAC_FRAME_TYPE_DATA && header->frameType != MAC_FRAME_TYPE_COMMAND)
        return 0;

    if (header->srcAddrMode != window->coordMode)
        return 0;

    if (window->coordMode == MAC_ADDR_SHORT && header->srcShort != window->coordShort)
        return 0;

    if (window->coordMode == MAC_ADDR_EXTENDED && header->srcExtended != window->coordExtended)
        return 0;

    if (header->destAddrMode == MAC_ADDR_SHORT)
        return header->destShort == pib->shortAddress && !MacTx_IsBroadcastShortAddress(header->destShort);

    return header->destAddrMode == MAC_ADDR_EXTENDED && header->destExtended == ownExtended;
}

int MacIndirect_ChildPollAdmits(Mac_ChildPoll *poll, const Radio_Frame *frame, int hasFrameFcs, const Radio_Pib *pib,
                                uint64_t ownExtended, int hears)
{
    static const uint32_t order[MAC_CHILD_POLL_WINDOWS] = { MAC_CHILD_POLL_PRIMITIVE, MAC_CHILD_POLL_OTHER };
    Mac_Frame header;
    Mac_FrameRefusal refusal;
    const uint8_t *payload;
    uint32_t payloadLen;
    uint32_t i;
    int open = MacIndirect_ChildPollOpen(poll);

    if (!open && !hears)
    {
        poll->heardAsleep++;
        return 0;
    }

    if (!open)
        return 1;

    if (MacFrame_Parse(frame->bytes, frame->len, hasFrameFcs, &header, &payload, &payloadLen, &refusal) != ZB_OK)
        return 1;

    for (i = 0; i < MAC_CHILD_POLL_WINDOWS; i++)
    {
        if (!macChildPollAnswers(&poll->window[order[i]], &header, pib, ownExtended))
            continue;

        if (header.frameType == MAC_FRAME_TYPE_DATA && payloadLen != 0)
            macChildPollEnd(poll, order[i], ZB_OK, header.framePending);
        else
            macChildPollEnd(poll, order[i], ZB_ERR_NO_DATA, header.framePending);

        break;
    }

    return 1;
}

int MacIndirect_ChildPollOpen(const Mac_ChildPoll *poll)
{
    return poll->window[MAC_CHILD_POLL_OTHER].state != MAC_CHILD_POLL_IDLE
           || poll->window[MAC_CHILD_POLL_PRIMITIVE].state != MAC_CHILD_POLL_IDLE;
}

int MacIndirect_ChildPollRequested(const Mac_ChildPoll *poll)
{
    return poll->window[MAC_CHILD_POLL_PRIMITIVE].state != MAC_CHILD_POLL_IDLE;
}

uint32_t MacIndirect_ChildPollConfirm(Mac_ChildPoll *poll, Mac_PollConfirmParameters *out)
{
    if (!poll->confirmReady)
        return 0;

    *out = poll->confirm;
    poll->confirmReady = 0;

    return 1;
}
