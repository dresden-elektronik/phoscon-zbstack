#ifndef SPINEL_SESSION_H
#define SPINEL_SESSION_H

/*
 * Band B: the transaction half of a Spinel link (docs/internals/protocol.md §3, §5, §7.3). spinel.h turns a
 * payload into argument octets and back; this module owns which request is outstanding, which
 * arriving frame answers it, and what a status code becomes for the layers above.
 *
 * It owns no buffer. A request is composed into the caller's stream, which the caller then
 * continues writing and hands to hdlc.h; a reply is absorbed from the payload the caller's HDLC
 * decoder copied, and its value is read through a bounded view over that same buffer. `payload` is
 * not const because the vendored stream type has no const reader: `Spinel_Reply.values` aliases the
 * caller's bytes, and nothing in this module writes through them. Two
 * sessions in one process therefore share nothing, which is what makes a two-RCP driver possible
 * without a global.
 *
 * One request is outstanding at a time, and its TID is never 0: a frame with TID 0 is unsolicited
 * and is never matched against a request (docs/internals/protocol.md §3). A frame carrying a TID this session
 * did not issue is counted as stale rather than accepted, because an RCP that repeats a
 * notification is a known behaviour here and a matcher that forgave it
 * would hide the difference.
 */

#include <stdint.h>
#include "props.h"
#include "spinel.h"
#include "zb_bstream.h"
#include "zb_status.h"

/* The status codes measured on the wire, named as docs/internals/protocol.md §7.3 records them. 112 and 114
   are not answers to a request: they arrive unsolicited and mean the device's configuration is
   gone. 113 and 115 are named nowhere in this repository and are not invented here. */
enum
{
    SPINEL_STATUS_OK = 0,
    SPINEL_STATUS_FAILURE = 1,
    SPINEL_STATUS_UNIMPLEMENTED = 2,
    SPINEL_STATUS_INVALID_ARGUMENT = 3,
    SPINEL_STATUS_INVALID_STATE = 4,
    SPINEL_STATUS_PARSE_ERROR = 9,
    SPINEL_STATUS_BUSY = 12,
    SPINEL_STATUS_PROP_NOT_FOUND = 13,
    SPINEL_STATUS_NO_ACK = 17,          /* the exchange this radio ran was not answered (docs/internals/protocol.md §7.3) */
    SPINEL_STATUS_CCA_FAILURE = 18,     /* the radio's CCA found the channel busy and sent nothing (docs/internals/protocol.md §7.3) */
    SPINEL_STATUS_RESET_POWER_ON = 112,
    SPINEL_STATUS_RESET_SOFTWARE = 114,
    SPINEL_STATUS_RESET_FIRST = SPINEL_STATUS_RESET_POWER_ON,
    SPINEL_STATUS_RESET_LAST = SPINEL_STATUS_RESET_SOFTWARE
};

enum
{
    SPINEL_SESSION_TID_MIN = SPINEL_TID_MIN,
    SPINEL_SESSION_TID_COUNT = SPINEL_TID_MAX,   /* 1..15: 15 ids, and 0 reserved for unsolicited */
    SPINEL_SESSION_OVERHEAD_MAX = SPINEL_HEADER_BYTES + SPINEL_PACKED_UINT_MAX_BYTES * 2
};

typedef enum SpinelOutcome
{
    SPINEL_OUTCOME_REPLY = 0,         /* answers the one request this session has outstanding */
    SPINEL_OUTCOME_NOTIFY = 1,        /* TID 0: an answer to nothing */
    SPINEL_OUTCOME_STALE = 2,         /* a TID this session never issued */
    SPINEL_OUTCOME_MALFORMED = 3      /* not decodable at all */
} Spinel_Outcome;

/*
 * What a frame said. `statusCode` is the LAST_STATUS a device puts in front of every answer it
 * gives as a value: a refusal carries property 0 and the code, and a success carries the property
 * and its value, so `hasValues` is 1 only for the latter. `values` is positioned on the first
 * value octet and reads the caller's buffer directly: it is valid only while that buffer lives.
 */
typedef struct SpinelReply
{
    uint8_t tid;
    uint8_t command;
    uint32_t propId;
    uint32_t statusCode;
    ZbStatus status;
    int hasValues;
    U_BStream values;
} Spinel_Reply;

typedef struct SpinelSession
{
    uint8_t nextTid;
    uint8_t pendingTid;
    uint8_t pendingCommand;
    uint32_t pendingProp;
    uint32_t pendingSinceMs;

    uint32_t timeoutMs;       /* 0: no expiry is tracked, the caller decides when a reply is late */

    uint32_t requests;
    uint32_t replies;
    uint32_t notifications;
    uint32_t stale;
    uint32_t malformed;
    uint32_t timeouts;
} Spinel_Session;

void SpinelSession_Init(Spinel_Session *session, uint32_t timeoutMs);

/*
 * Allocate a TID and write header, command and property id into `stream`, which the caller has
 * opened over its own buffer, leaving it positioned for the value. ZB_ERR_BUSY when a request is
 * already outstanding (a second TID in flight would make a reply ambiguous), ZB_ERR_NO_SPACE when the
 * buffer cannot hold the header, in which case nothing is written and no request is outstanding, and
 * ZB_ERR_BAD_ARGUMENT for a stream that was never opened. A RESET or NOOP carries no property id on
 * the wire; pass PROP_LAST_STATUS, which is what was measured (`7e 80 01 02 92 7e`).
 */
ZbStatus SpinelSession_Compose(Spinel_Session *session, uint8_t command, uint32_t propId,
                               uint32_t nowMs, U_BStream *stream);

/* 1 when a request is outstanding. */
int SpinelSession_Busy(const Spinel_Session *session);
uint8_t SpinelSession_PendingTid(const Spinel_Session *session);
uint32_t SpinelSession_PendingProp(const Spinel_Session *session);
uint8_t SpinelSession_PendingCommand(const Spinel_Session *session);

/*
 * Classify one decoded frame payload and, when `out` is not 0, describe it. A matching reply ends
 * the transaction; anything else leaves the outstanding request where it was. The value itself is
 * not read here: `out->values` is positioned on it, and what it means belongs to whoever asked for
 * the property.
 */
Spinel_Outcome SpinelSession_Absorb(Spinel_Session *session, uint8_t *payload, uint32_t len,
                                    uint32_t nowMs, Spinel_Reply *out);

/* ZB_ERR_TIMEOUT when the outstanding request has gone unanswered, which also abandons it. ZB_OK
   when there is nothing outstanding or the window still holds. */
ZbStatus SpinelSession_Expires(Spinel_Session *session, uint32_t nowMs);

/* Drop an outstanding request without counting a timeout: the link went away under us. */
void SpinelSession_Abandon(Spinel_Session *session);

/* The seam status a device's code becomes: `OK` to `ZB_OK`, `INVALID_ARGUMENT` to
   `ZB_ERR_BAD_ARGUMENT`, `INVALID_STATE` to `ZB_ERR_NOT_READY`, `PARSE_ERROR` to `ZB_ERR_BAD_FRAME`,
   `BUSY` to `ZB_ERR_BUSY`, `PROP_NOT_FOUND` and `UNIMPLEMENTED` to `ZB_ERR_UNSUPPORTED`, a reset
   announcement to `ZB_ERR_DEVICE_LOST`, and anything else to `ZB_ERR_DEVICE`, a refusal whose
   reason this stack does not name, with the code still in the reply. */
ZbStatus SpinelSession_StatusToZb(uint32_t statusCode);

/* 1 for the unsolicited codes that mean the configuration is gone (docs/internals/protocol.md §5). */
int SpinelSession_IsResetStatus(uint32_t statusCode);

/* Count a frame this session was not part of, so a driver's byte pump and its transaction counters
   stay reconcilable. */
void SpinelSession_CountForeign(Spinel_Session *session);

#endif /* SPINEL_SESSION_H */
