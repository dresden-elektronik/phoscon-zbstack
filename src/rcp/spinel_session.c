#include "spinel_session.h"

#include "hdlc.h"
#include "zb_time.h"

static void sessionBeginRequest(Spinel_Session *session, uint8_t tid, uint8_t command,
                                uint32_t propId, uint32_t nowMs)
{
    session->pendingTid = tid;
    session->pendingCommand = command;
    session->pendingProp = propId;
    session->pendingSinceMs = nowMs;
    session->requests++;
}

static uint8_t sessionTakeTid(Spinel_Session *session)
{
    uint8_t tid = session->nextTid;

    session->nextTid = (uint8_t)(tid + 1);

    if (session->nextTid > SPINEL_TID_MAX)
        session->nextTid = SPINEL_TID_MIN;

    return tid;
}

static void sessionClear(Spinel_Session *session)
{
    session->pendingTid = SPINEL_TID_NONE;
    session->pendingCommand = 0;
    session->pendingProp = 0;
    session->pendingSinceMs = 0;
}

void SpinelSession_Init(Spinel_Session *session, uint32_t timeoutMs)
{
    session->nextTid = SPINEL_TID_MIN;
    session->timeoutMs = timeoutMs;
    session->requests = 0;
    session->replies = 0;
    session->notifications = 0;
    session->stale = 0;
    session->malformed = 0;
    session->timeouts = 0;
    sessionClear(session);
}

int SpinelSession_Busy(const Spinel_Session *session)
{
    return session->pendingTid != SPINEL_TID_NONE;
}

uint8_t SpinelSession_PendingTid(const Spinel_Session *session)
{
    return session->pendingTid;
}

uint32_t SpinelSession_PendingProp(const Spinel_Session *session)
{
    return session->pendingProp;
}

uint8_t SpinelSession_PendingCommand(const Spinel_Session *session)
{
    return session->pendingCommand;
}

void SpinelSession_Abandon(Spinel_Session *session)
{
    sessionClear(session);
}

void SpinelSession_CountForeign(Spinel_Session *session)
{
    session->stale++;
}

ZbStatus SpinelSession_Compose(Spinel_Session *session, uint8_t command, uint32_t propId,
                               uint32_t nowMs, U_BStream *stream)
{
    uint8_t tid;

    if (session == 0 || stream == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (Zb_bstream_size(stream) == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (session->pendingTid != SPINEL_TID_NONE)
        return ZB_ERR_BUSY;

    if (!Spinel_TidValid(session->nextTid))
        return ZB_ERR_INTERNAL;

    if (Spinel_Remaining(stream) < SPINEL_SESSION_OVERHEAD_MAX)
        return ZB_ERR_NO_SPACE;

    tid = sessionTakeTid(session);
    Spinel_WriteHeader(stream, tid);
    Spinel_WritePackedUint(stream, command);
    Spinel_WritePackedUint(stream, propId);

    if (Spinel_StreamFailed(stream))
        return ZB_ERR_NO_SPACE;

    sessionBeginRequest(session, tid, command, propId, nowMs);
    return ZB_OK;
}

ZbStatus SpinelSession_Expires(Spinel_Session *session, uint32_t nowMs)
{
    if (session == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (session->pendingTid == SPINEL_TID_NONE)
        return ZB_OK;

    if (session->timeoutMs == 0)
        return ZB_OK;

    if (Zb_timeWithin(nowMs, session->pendingSinceMs, session->timeoutMs))
        return ZB_OK;

    sessionClear(session);
    session->timeouts++;
    return ZB_ERR_TIMEOUT;
}

ZbStatus SpinelSession_StatusToZb(uint32_t statusCode)
{
    if (statusCode == SPINEL_STATUS_OK)
        return ZB_OK;

    if (statusCode == SPINEL_STATUS_INVALID_ARGUMENT)
        return ZB_ERR_BAD_ARGUMENT;

    if (statusCode == SPINEL_STATUS_INVALID_STATE)
        return ZB_ERR_NOT_READY;

    if (statusCode == SPINEL_STATUS_PARSE_ERROR)
        return ZB_ERR_BAD_FRAME;

    if (statusCode == SPINEL_STATUS_BUSY)
        return ZB_ERR_BUSY;

    if (statusCode == SPINEL_STATUS_PROP_NOT_FOUND || statusCode == SPINEL_STATUS_UNIMPLEMENTED)
        return ZB_ERR_UNSUPPORTED;

    if (SpinelSession_IsResetStatus(statusCode))
        return ZB_ERR_DEVICE_LOST;

    return ZB_ERR_DEVICE;
}

int SpinelSession_IsResetStatus(uint32_t statusCode)
{
    return statusCode >= SPINEL_STATUS_RESET_FIRST && statusCode <= SPINEL_STATUS_RESET_LAST;
}

/*
 * The payload of a device frame is header, command, property id, value (docs/internals/protocol.md §3). A
 * refusal is a frame whose property id is LAST_STATUS with the code as its whole value, which is
 * how `PROP_NOT_FOUND` reaches the host (§7.3): recognising that shape here is what keeps every
 * later reader pointed at a value instead than at a status.
 */
Spinel_Outcome SpinelSession_Absorb(Spinel_Session *session, uint8_t *payload, uint32_t len,
                                    uint32_t nowMs, Spinel_Reply *out)
{
    Spinel_Header header;
    Spinel_Outcome outcome;
    U_BStream values;
    uint32_t propId;
    uint32_t statusCode;
    uint32_t remaining;
    uint8_t command;
    uint8_t tid;
    int hasValues;

    (void)nowMs;

    if (session == 0 || payload == 0 || len < SPINEL_HEADER_BYTES + 1 || len > HDLC_PAYLOAD_MAX)
    {
        if (session != 0)
            session->malformed++;

        return SPINEL_OUTCOME_MALFORMED;
    }

    if (!Spinel_HeaderValid(payload[0]))
    {
        session->malformed++;
        return SPINEL_OUTCOME_MALFORMED;
    }

    Spinel_ReadHeader(payload[0], &header);
    tid = header.tid;
    U_bstream_init(&values, payload + SPINEL_HEADER_BYTES, (unsigned long)(len - SPINEL_HEADER_BYTES));

    remaining = Spinel_Remaining(&values);
    command = 0;
    propId = 0;
    statusCode = SPINEL_STATUS_OK;
    hasValues = 0;

    if (remaining == 0)
    {
        session->malformed++;
        return SPINEL_OUTCOME_MALFORMED;
    }

    command = (uint8_t)Spinel_ReadPackedUint(&values);

    if (Spinel_Remaining(&values) == 0)
    {
        session->malformed++;
        return SPINEL_OUTCOME_MALFORMED;
    }

    propId = Spinel_ReadPackedUint(&values);

    if (propId == PROP_LAST_STATUS)
        statusCode = Spinel_ReadPackedUint(&values);
    else
        hasValues = 1;

    if (Spinel_StreamFailed(&values))
    {
        session->malformed++;
        return SPINEL_OUTCOME_MALFORMED;
    }

    if (Spinel_IsNotification(&header))
    {
        outcome = SPINEL_OUTCOME_NOTIFY;
        session->notifications++;
    }
    else if (session->pendingTid != SPINEL_TID_NONE && tid == session->pendingTid)
    {
        outcome = SPINEL_OUTCOME_REPLY;
        session->replies++;
        sessionClear(session);
    }
    else
    {
        outcome = SPINEL_OUTCOME_STALE;
        session->stale++;
    }

    if (out != 0)
    {
        out->tid = tid;
        out->command = command;
        out->propId = propId;
        out->statusCode = statusCode;
        out->status = SpinelSession_StatusToZb(statusCode);
        out->hasValues = hasValues;
        out->values = values;
    }

    return outcome;
}
