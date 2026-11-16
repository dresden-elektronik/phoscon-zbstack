#include "mac.h"

#include "mac_tx.h"

#include "zb_time.h"
#include "zb_utils.h"

/* M2024 6.2 6.6.1 6.6.2 6.6.3.1 6.6.3.4 7.2.2.4 7.2.2.6 7.2.3 7.2.4 7.2.11 7.3.1 7.3.4.2 7.3.4.3 7.5.2 10.21.5.1
   10.21.5.2 10.22.2 10.22.4.1 ok; R23.1 3.2.1.1.3 ok; M2024 6.6.1 delegated (the RCP runs the unslotted CSMA-CA,
   and repeats a frame as often as the count it carries); 7.3.7 ok (the 2006 edition's 7.5.2); docs/internals/conformance.md pages. */

static int macIsAssociationRequestCommand(const Mac_DataRequestParameters *req);

/* Whether a request is the command `command` names, read by its Command ID, the payload's first octet. */
static int macIsCommandOf(const Mac_DataRequestParameters *req, uint8_t command)
{
    return req->frameType == MAC_FRAME_TYPE_COMMAND && req->payload != 0 && req->payloadLen != 0
           && req->payload[0] == command;
}

/* One PAN field or two: 7.2.2.6 sets compression when both addresses are present and the two PAN identifiers
   identical. A command frame's destination PAN is this device's own whatever the request named (10.22.4.1's
   macPanId; 7.2.4, the Destination PAN ID field), so equality holds there; a data frame's is the caller's. */
static int macPanCompressed(const Mac_DataRequestParameters *req, const Radio_Pib *pib)
{
    if (macIsAssociationRequestCommand(req) || macIsCommandOf(req, MAC_CMD_COORDINATOR_REALIGNMENT))
        return 0;

    if (req->destAddrMode == MAC_ADDR_NONE)
        return 0;

    if (req->frameType == MAC_FRAME_TYPE_COMMAND)
        return req->srcAddrMode != MAC_ADDR_NONE && req->destAddrMode != MAC_ADDR_NONE;

    return req->srcAddrMode != MAC_ADDR_NONE && pib->panId == req->destPan;
}

/* Whether the frame a request will compose is the Data Request command itself: the Frame Pending pin below is
   10.22.4.1's rule for Table 7-11's 0x04 alone, and 7.3.4.2 pins no FCF subfield of a command frame in
   general. The Command ID is the payload's first octet (7.3.4.3), so an empty payload composes no command. */
int MacTx_IsDataRequestCommand(const Mac_DataRequestParameters *req)
{
    if (req->frameType != MAC_FRAME_TYPE_COMMAND)
        return 0;

    if (req->payload == 0 || req->payloadLen == 0)
        return 0;

    return req->payload[0] == MAC_CMD_POLL;
}

/* 7.5.2's Beacon Request, whose every pinned field the door states below because a caller cannot word it another
   way. It is read by its Command ID, the payload's first octet (7.3.4.3). */
static int macIsBeaconRequestCommand(const Mac_DataRequestParameters *req)
{
    if (req->frameType != MAC_FRAME_TYPE_COMMAND)
        return 0;

    if (req->payload == 0 || req->payloadLen == 0)
        return 0;

    return req->payload[0] == MAC_CMD_BEACON_REQUEST;
}

/* 10.21.5.1: the Association Request command, whose Content is the one Capability Information octet. */
static int macIsAssociationRequestCommand(const Mac_DataRequestParameters *req)
{
    if (req->frameType != MAC_FRAME_TYPE_COMMAND)
        return 0;

    if (req->payload == 0 || req->payloadLen == 0)
        return 0;

    return req->payload[0] == MAC_CMD_ASSOCIATION_REQUEST;
}

/* 10.21.5.2: the Association Response command. Its Frame Pending field is pinned to zero like the request's,
   whatever the poll's queue holds when it is extracted. */
int MacTx_IsAssociationResponseCommand(const Mac_DataRequestParameters *req)
{
    if (req->frameType != MAC_FRAME_TYPE_COMMAND)
        return 0;

    if (req->payload == 0 || req->payloadLen == 0)
        return 0;

    return req->payload[0] == MAC_CMD_ASSOCIATION_RESPONSE;
}

/* The ask a command frame carries is the command's own law and not the caller's (10.22.4.1 for a Data Request,
   7.5.2 for a Beacon Request); every other command frame keeps the ask this module has always stated for one. */
int MacTx_CommandAckRequest(const Mac_DataRequestParameters *req)
{
    if (macIsBeaconRequestCommand(req) || macIsCommandOf(req, MAC_CMD_ORPHAN_NOTIFICATION))
        return 0;

    return 1;
}

/* The MHR a request describes, `ownExtended` being this device's extended address as the frame field carries it. */
static void macFrameFromRequest(const Mac_DataRequestParameters *req, const Radio_Pib *pib, uint64_t ownExtended,
                                int compressPan, Mac_Frame *frame)
{
    Zb_memset(frame, 0, (uint32_t)sizeof *frame);

    frame->frameType = (Mac_FrameType)req->frameType;
    frame->frameVersion = 0;      
    frame->securityEnabled = 0;
    frame->panIdCompression = compressPan;
    frame->destAddrMode = req->destAddrMode;
    frame->srcAddrMode = req->srcAddrMode;
    frame->destShort = req->destShort;
    frame->destExtended = req->destExtended;

    if (req->frameType == MAC_FRAME_TYPE_COMMAND)
    {
        frame->ackRequest = MacTx_CommandAckRequest(req);

        if (MacTx_IsDataRequestCommand(req))
        {
            frame->framePending = 0;
            frame->destPan = pib->panId;
        }
        else if (macIsBeaconRequestCommand(req))
        {
            frame->framePending = 0;
            frame->destPan = req->destPan;
        }
        else if (macIsAssociationRequestCommand(req) || macIsCommandOf(req, MAC_CMD_ORPHAN_NOTIFICATION)
                 || macIsCommandOf(req, MAC_CMD_COORDINATOR_REALIGNMENT))
        {
            frame->framePending = 0;
            frame->destPan = req->destPan;
        }
        else if (MacTx_IsAssociationResponseCommand(req))
        {
            frame->framePending = 0;
            frame->destPan = pib->panId;
        }
        else
        {
            frame->framePending = req->framePending;
            frame->destPan = pib->panId;
        }
    }
    else
    {
        frame->framePending = req->framePending;
        frame->ackRequest = req->ackRequest;
        frame->destPan = req->destPan;
    }

    if (macIsAssociationRequestCommand(req))
        frame->srcPan = MAC_FRAME_PAN_BROADCAST;
    else
        frame->srcPan = compressPan ? frame->destPan : pib->panId;

    if (req->srcAddrMode == MAC_ADDR_SHORT)
        frame->srcShort = pib->shortAddress;

    if (req->srcAddrMode == MAC_ADDR_EXTENDED)
        frame->srcExtended = ownExtended;
}

int MacTx_IsBroadcastExtendedAddress(uint64_t extendedAddress)
{
    return extendedAddress == 0xffffffffffffffff;
}

/* 6.6.3.1: a broadcast or a group frame "shall be sent with its AR field set to indicate no acknowledgment
   requested", so the ask is cleared and the frame still sent. The broadcast PAN is no broadcast, 7.2.4 accepting
   it as a valid one, and R23.1 3.2.1.1.3 item 6 hands the MAC one 0xffff for all of Table 3-80's classes. */
int MacTx_AskIsImpossible(const Mac_DataRequestParameters *req, int ackRequest)
{
    if (!ackRequest)
        return 0;

    if (req->destAddrMode == MAC_ADDR_SHORT && req->destShort == MAC_FRAME_ADDR_BROADCAST)
        return 1;

    if (req->destAddrMode == MAC_ADDR_EXTENDED && MacTx_IsBroadcastExtendedAddress(req->destExtended))
        return 1;

    if (req->destAddrMode == MAC_ADDR_EXTENDED && (req->destExtended & 1) != 0)
        return 1;

    return 0;
}

static int macSlotFree(const Mac_Track *slot)
{
    return slot->state == MAC_TX_FREE;
}

Mac_Track *MacTx_FreeSlot(Mac_Tx *tx)
{
    uint32_t i;

    for (i = 0; i < MAC_TX_TRACK_MAX; i++)
    {
        if (macSlotFree(&tx->track[i]))
            return &tx->track[i];
    }

    return 0;
}

/* The track slot a handle this module holds names, and what became of it: a slot is free, filled, or in flight, and
   a freed slot's handle is RADIO_HANDLE_NONE (docs/internals/coding-rules.md §7). `valid` is the caller's record of whether
   it asked for an answer at all, so a nil handle is never matched against a slot. */
Mac_Track *MacTx_TrackNamed(Mac_Tx *tx, uint32_t handle, int valid)
{
    uint32_t i;

    if (!valid)
        return 0;

    for (i = 0; i < MAC_TX_TRACK_MAX; i++)
    {
        if (tx->track[i].state == MAC_TX_FREE)
            continue;

        if (tx->track[i].handle == handle)
            return &tx->track[i];
    }

    return 0;
}

/* Whether the seam has said what became of a transmit: answered is a result, and gave-up-on is one too. */
int MacTx_TrackAnswered(const Mac_Track *slot)
{
    if (slot == 0)
        return 0;

    return slot->state == MAC_TX_ANSWERED || slot->state == MAC_TX_TIMED_OUT;
}

/* One transmit whose answer this module has read and the layer above must not: the slot goes back to the pool as
   Mac_PollConfirms leaves it, so no confirmation is ever reported for a frame housekeeping issued. */
void MacTx_TrackRelease(Mac_Track *slot)
{
    slot->state = MAC_TX_FREE;
    slot->handle = RADIO_HANDLE_NONE;
    slot->confirmOwed = 0;
    slot->isExtraction = 0;
}

void MacTx_TrackNoConfirm(Mac_Tx *tx, Radio_Handle handle)
{
    Mac_Track *slot = MacTx_TrackNamed(tx, handle, handle != RADIO_HANDLE_NONE);

    if (slot != 0)
        slot->confirmOwed = 0;
}

int MacTx_IsBroadcastShortAddress(uint16_t shortAddress)
{
    return shortAddress == MAC_FRAME_ADDR_BROADCAST;
}

/* Whether the frame a transaction will become still fits one 127-octet MPDU: the ceiling MacFrame_Compose
   applies, applied at the door, with the header length from `mac_frame`'s own rules and the footer counted
   because band A appends it (7.2.11, the FCS field; docs/internals/protocol.md §9.3). */
int MacTx_TransactionFits(const Mac_DataRequestParameters *req, const Radio_Pib *pib, uint64_t ownExtended)
{
    Mac_Frame frame;
    uint32_t headerLen;

    macFrameFromRequest(req, pib, ownExtended, macPanCompressed(req, pib), &frame);
    frame.seq = 0;

    if (MacFrame_HeaderLen(&frame, &headerLen) != ZB_OK)
        return 0;

    return headerLen + req->payloadLen + MAC_FRAME_FCS_OCTETS <= MAC_FRAME_MPDU_MAX;
}

/* The checks a request passes before anything is composed, shared by both entry points so the two cannot drift.
   7.3.4.3 gives a command its identifier, Table 7-11 names the ones that exist, 10.22.4.1 gives the Data Request
   no Content and 7.5.2 pins the Beacon Request's addressing. A refusal here is counted, not lost. */
ZbStatus MacTx_ValidateRequest(const Mac_DataRequestParameters *req, const Radio_Pib *pib, int ownExtendedKnown,
                               uint32_t *refusedRequests)
{
    if (req->payload == 0 && req->payloadLen != 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (req->frameType != MAC_FRAME_TYPE_DATA && req->frameType != MAC_FRAME_TYPE_COMMAND)
    {
        (*refusedRequests)++;
        return ZB_ERR_UNSUPPORTED;    /* a Beacon is mac_beacon's to compose and a schedule of them is forbidden, docs/internals/conformance.md §1 */
    }

    if (req->frameType == MAC_FRAME_TYPE_COMMAND)
    {
        if (req->payloadLen == 0)
        {
            (*refusedRequests)++;
            return ZB_ERR_BAD_ARGUMENT;
        }

        if (req->payload[0] >= MAC_CMD_RESERVED_FIRST)
        {
            (*refusedRequests)++;
            return ZB_ERR_BAD_ARGUMENT;
        }
    }

    if (MacTx_IsDataRequestCommand(req) && req->payloadLen != MAC_CMD_FRAME_OCTETS)
    {
        (*refusedRequests)++;
        return ZB_ERR_BAD_ARGUMENT;
    }

    if (macIsBeaconRequestCommand(req)
        && (req->payloadLen != MAC_CMD_FRAME_OCTETS || req->destAddrMode != MAC_ADDR_SHORT
            || req->destShort != MAC_FRAME_ADDR_BROADCAST || req->destPan != MAC_FRAME_PAN_BROADCAST
            || req->srcAddrMode != MAC_ADDR_NONE))
    {
        (*refusedRequests)++;
        return ZB_ERR_BAD_ARGUMENT;
    }


    if (req->srcAddrMode == MAC_ADDR_RESERVED || req->destAddrMode == MAC_ADDR_RESERVED)
    {
        (*refusedRequests)++;
        return ZB_ERR_BAD_ARGUMENT;
    }

    if (MacTx_IsAssociationResponseCommand(req))
    {
        if (req->srcAddrMode != MAC_ADDR_EXTENDED || req->destAddrMode != MAC_ADDR_EXTENDED
            || req->payloadLen != 4)
        {
            (*refusedRequests)++;
            return ZB_ERR_BAD_ARGUMENT;
        }
    }

    if (macIsAssociationRequestCommand(req))
    {
        if (req->srcAddrMode != MAC_ADDR_EXTENDED || req->payloadLen != 2)
        {
            (*refusedRequests)++;
            return ZB_ERR_BAD_ARGUMENT;
        }

        if ((req->payload[1] & 0x70) != 0)
        {
            (*refusedRequests)++;
            return ZB_ERR_UNSUPPORTED;    /* fast association, suspendable CSMA-CA and MAC security: not built, docs/internals/protocol.md §9.2 */
        }
    }

    if (req->srcAddrMode == MAC_ADDR_SHORT && (pib->present & RADIO_PIB_SHORT_ADDRESS) == 0)
    {
        (*refusedRequests)++;
        return ZB_ERR_NOT_READY;
    }

    if (req->srcAddrMode == MAC_ADDR_SHORT && pib->shortAddress >= MAC_SHORT_ADDRESS_LAST_USABLE)
    {
        (*refusedRequests)++;
        return ZB_ERR_NOT_READY;
    }

    if (req->srcAddrMode == MAC_ADDR_EXTENDED
        && ((pib->present & RADIO_PIB_EXTENDED_ADDRESS) == 0 || !ownExtendedKnown))
    {
        (*refusedRequests)++;
        return ZB_ERR_NOT_READY;
    }

    return ZB_OK;
}

/* A direct frame that asks for an acknowledgment is sent again up to macMaxFrameRetries times, and an indirect
   one is not, staying queued for the next poll; a frame that asks for nothing has nothing to retry. */
static uint32_t macTxFrameRetries(const Radio_Pib *pib, int ackRequest, int indirect)
{
    if (!ackRequest || indirect)
        return 0;

    if ((pib->present & RADIO_PIB_MAX_FRAME_RETRIES) == 0)
        return MAC_MAX_FRAME_RETRIES_DEFAULT;

    return pib->maxFrameRetries;
}

/* The pool is the policy (docs/internals/coding-rules.md §5): compose one already-validated request into a free track slot
   at the DSN the caller names. 6.6.3.1's ask goes to the FCF, the seam and the slot alike, being the frame's and
   not the caller's; the counter is untouched because an extraction re-uses its transaction's number (6.6.3.4). */
ZbStatus MacTx_IssueFrame(Mac_Tx *tx, const Mac_DataRequestParameters *req, const Radio_Pib *pib,
                          uint64_t ownExtended, Radio_Radio *radio, uint8_t *mpdu, uint32_t mpduCap,
                          uint32_t dsn, uint32_t nowMs, int indirect, Mac_Track **outSlot,
                          uint32_t *refusedRequests)
{
    Mac_Frame frame;
    Mac_Track *slot;
    Radio_Handle handle = RADIO_HANDLE_NONE;
    uint32_t len = 0;
    int compressPan;
    int ackRequest;
    ZbStatus status;

    *outSlot = 0;

    slot = MacTx_FreeSlot(tx);

    if (slot == 0)
        return ZB_ERR_NO_SPACE;

    ackRequest = req->frameType == MAC_FRAME_TYPE_COMMAND ? MacTx_CommandAckRequest(req) : req->ackRequest;

    if (MacTx_AskIsImpossible(req, ackRequest))
        ackRequest = 0;

    compressPan = macPanCompressed(req, pib);
    macFrameFromRequest(req, pib, ownExtended, compressPan, &frame);
    frame.seq = (uint8_t)(dsn % MAC_DSN_WRAP);
    frame.ackRequest = ackRequest;

    status = MacFrame_Compose(&frame, req->payload, req->payloadLen, mpdu, mpduCap, &len);

    if (status != ZB_OK)
    {
        (*refusedRequests)++;
        return status;
    }

    status = MacFrame_AppendFcs(mpdu, len, mpduCap, &len);

    if (status != ZB_OK)
    {
        (*refusedRequests)++;
        return status;
    }

    status = radio->ops->tx(radio, mpdu, len, ackRequest, macTxFrameRetries(pib, ackRequest, indirect), &handle);

    if (status != ZB_OK)
        return status;                

    slot->handle = handle;
    slot->dsn = dsn % MAC_DSN_WRAP;
    slot->issuedMs = nowMs;
    slot->frameType = req->frameType;
    slot->ackRequest = ackRequest;
    slot->state = MAC_TX_OUTSTANDING;
    slot->status = ZB_ERR_NOT_READY;
    slot->acked = 0;
    slot->numBackoffs = 0;
    slot->framePending = 0;
    slot->framePendingReported = 0;
    slot->isExtraction = 0;

    *outSlot = slot;

    return ZB_OK;
}

/* The acknowledgment question, asked the only way this seam can answer it: a radio carrying ACK_TIMEOUT runs
   the wait and says in its completion whether the frame was answered, `0 OK` against an addressed peer,
   `17 NO_ACK` against one that was not. A radio without it cannot report one. */
static int macTrustsRadioAcknowledgement(const Radio_Caps *caps)
{
    return caps->handlesAckTimeout;
}

static void macConfirmTimedOut(Mac_Track *slot, Mac_TxCompletions *out)
{
    slot->state = MAC_TX_TIMED_OUT;
    slot->status = ZB_ERR_TIMEOUT;
    slot->acked = 0;
    slot->numBackoffs = 0;
    slot->framePending = 0;
    slot->framePendingReported = 0;
    slot->isExtraction = 0;
    out->timeouts++;
    out->needsRearm = 1;

    out->answered[out->answeredCount] = slot;
    out->answeredCount++;
}

void MacTx_CollectCompletions(Mac_Tx *tx, Radio_Radio *radio, const Radio_Caps *caps, uint32_t nowMs,
                              Mac_TxCompletions *out)
{
    Radio_TxResult result;
    uint32_t i;

    out->timeouts = 0;
    out->needsRearm = 0;
    out->answeredCount = 0;

    for (i = 0; i < MAC_TX_TRACK_MAX; i++)
    {
        if (tx->track[i].state != MAC_TX_OUTSTANDING)
            continue;

        if (radio->ops->completion(radio, tx->track[i].handle, &result) != ZB_OK)
        {
            if (!Zb_timeWithin(nowMs, tx->track[i].issuedMs, MAC_COMPLETION_TIMEOUT_MS))
                macConfirmTimedOut(&tx->track[i], out);

            continue;
        }

        tx->track[i].state = MAC_TX_ANSWERED;
        tx->track[i].status = result.status;
        tx->track[i].acked = macTrustsRadioAcknowledgement(caps) ? result.isAcked : 0;
        tx->track[i].numBackoffs = result.retries;
        tx->track[i].framePendingReported = tx->track[i].acked && result.framePendingReported;
        tx->track[i].framePending = tx->track[i].framePendingReported && result.framePending;

        if (result.status == ZB_ERR_DEVICE_LOST)
            out->needsRearm = 1;

        out->answered[out->answeredCount] = &tx->track[i];
        out->answeredCount++;
    }
}
