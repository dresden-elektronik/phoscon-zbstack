#ifndef LOG_H
#define LOG_H

/*
 * Log: the stack's diagnostics. A record is twelve bytes (a 16-bit component, a 16-bit
 * line, a 16-bit reason, a 32-bit argument) and this module is everything there is to
 * logging in the portable set: it holds the records in a named fixed pool and hands them
 * to a sink. It formats nothing, prints nothing and knows no platform; a human-readable
 * line is built host-side, by a platform sink in src/port or by a suite or a tool, from
 * the host-side name table (docs/internals/coding-rules.md §5).
 *
 * The dependency direction is the core/glue split of docs/internals/coding-rules.md §4: the sink
 * implements the interface this header names; the core calls the sink and never the platform.
 * A target is chosen by which sink file the build links (docs/porting.md §3).
 *
 * The pool is fixed at LOG_RING_MAX and its full policy is stated: a report into a full ring
 * is refused with ZB_ERR_NO_SPACE and counted, and nothing is ever overwritten. The caller
 * owns the Log_Log, drains it from its own loop, and is told through the counter when the
 * drain is falling behind: a ring that silently dropped records would hide exactly the fault
 * the records exist to name.
 */

#include <stdint.h>

#include "zb_status.h"

/*
 * Component codes: which module is speaking, as one 16-bit value, the section
 * in the top byte, the topic in the low byte. Topic 0x00 is unattributed: a
 * code whose low byte is 0x00 names the section itself, and the files within
 * a section take the 0x10-blocks. Append-only: a code is never reused or
 * renumbered (docs/internals/coding-rules.md §5); adding one is one line, and a code the
 * core does not know is still a valid report (the name table answers "unknown").
 * The old 1..9 component numbering is gone because nothing consumed it.
 */
#define LOG_SECTION_NONE 0x00
#define LOG_SECTION_PORT 0x01
#define LOG_SECTION_HDLC 0x02
#define LOG_SECTION_SPINEL 0x03
#define LOG_SECTION_RCP 0x04
#define LOG_SECTION_LOOPBACK 0x05
#define LOG_SECTION_MAC 0x06
#define LOG_SECTION_NWK 0x07
#define LOG_SECTION_APS 0x08
#define LOG_SECTION_ZDO 0x09
#define LOG_SECTION_SECURITY 0x0A
#define LOG_SECTION_APP 0x0B

/* The none section, 0x0000 - 0x00FF. */
#define LOG_COMP_NONE 0x0000

/* The port section, 0x0100 - 0x01FF. */
#define LOG_COMP_PORT_CORE 0x0110
#define LOG_COMP_PORT_POSIX 0x0120
#define LOG_COMP_PORT_NULL 0x0130
#define LOG_COMP_PORT_WIN32 0x0140
#define LOG_COMP_PORT_LOG 0x0150

/* The hdlc section, 0x0200 - 0x02FF. */
#define LOG_COMP_HDLC 0x0210

/* The spinel section, 0x0300 - 0x03FF. */
#define LOG_COMP_SPINEL_CODEC 0x0310
#define LOG_COMP_SPINEL_SESSION 0x0320

/* The rcp section, 0x0400 - 0x04FF. */
#define LOG_COMP_RCP_RADIO 0x0410
#define LOG_COMP_RCP_PROPS 0x0420

/* The loopback section, 0x0500 - 0x05FF. */
#define LOG_COMP_LOOPBACK 0x0510

/* The mac section, 0x0600 - 0x06FF. */
#define LOG_COMP_MAC_FRAME 0x0610
#define LOG_COMP_MAC 0x0620
/* 6.6.2's receive refusals, reported from the receive classification. argument: for a discarded footer,
   the claims that named it (bit 0 the radio's own flag, bit 1 7.2.11's recomputation). */
#define LOG_COMP_MAC_RX 0x0630

/* The nwk section, 0x0700 - 0x07FF. */
#define LOG_COMP_NWK 0x0710

/* The aps section, 0x0800 - 0x08FF. */
#define LOG_COMP_APS 0x0810

/* The zdo section, 0x0900 - 0x09FF. */
#define LOG_COMP_ZDO 0x0910

/* The security section, 0x0A00 - 0x0AFF. The topics are the refusals and the one state change
   band A's NWK security crossing can report: the unattributed 0x0A10 stays available for a record
   that names the section only. */
#define LOG_COMP_SECURITY 0x0A10
/* 4.3.1.1 refused to compose a frame. argument: the ZbStatus the caller was given. */
#define LOG_COMP_SECURITY_PROTECT_REFUSED 0x0A11
/* 4.3.1.2 refused a frame it was handed. argument: the ZbStatus the caller was given. */
#define LOG_COMP_SECURITY_UNPROTECT_FAILED 0x0A12
/* nwkActiveKeySeqNumber moved on a received key sequence number that is newer than it (4.3.1.2 step 7).
   argument: the new sequence number. */
#define LOG_COMP_SECURITY_KEY_ADOPTED 0x0A13
/* The incoming frame counter store (4.3.1.2 step 6) held no slot for a sender. argument: how many
   entries the pool holds, which is its bound. */
#define LOG_COMP_SECURITY_INCOMING_FULL 0x0A14
/* A secured frame this module was asked to compose is longer than the band's ceiling. argument: the
   length it would have been. */
#define LOG_COMP_SECURITY_FRAME_TOO_LONG 0x0A15

/* The app section, 0x0B00 - 0x0BFF. */
#define LOG_COMP_APP 0x0B10

/* Reason codes: what happened, in one vocabulary for every component. The argument field
   carries the detail each reason names in its comment. Append-only, like the components. */
typedef enum LogReason
{
    LOG_REASON_NONE = 0,
    /* An operation was refused or faulted. argument: the ZbStatus that was returned. */
    LOG_REASON_ERROR = 1,
    /* A wait ran out before its answer arrived. argument: the handle that was waited on,
       or the elapsed time in the unit the caller timed in. */
    LOG_REASON_TIMEOUT = 2,
    /* A pool was full and something was refused or left behind. argument: how many. */
    LOG_REASON_DROPPED = 3,
    /* A named state changed. argument: the new state, in the machine's own numbering. */
    LOG_REASON_STATE = 4,
    /* A device was reset or re-armed. argument: the device's code for the reset. */
    LOG_REASON_RESET = 5,
    /* A configuration write went out through a seam. argument: the field mask that was set. */
    LOG_REASON_CONFIG = 6,
    /* A stated invariant held false, via ZB_ASSERT. argument: the field the site passed, or 0. */
    LOG_REASON_ASSERT = 7,
    /* A received frame's frame check sequence did not compute and 6.6.2 discarded it. argument: the claims
       that named it, as bits (bit 0 the radio's own bad-FCS flag, bit 1 7.2.11's recomputation). */
    LOG_REASON_FCS = 8,
    /* A received frame was refused before any duty and 6.6.2 discarded it. argument: mac_rx.h's Mac_RxRefusal
       numbering, which names a) a reserved type, b) a reserved version, a malformed header or an unbuilt form. */
    LOG_REASON_REFUSED = 9
} LogReason;

/*
 * The record: twelve bytes, integer only. component is the 16-bit section|topic value
 * from the table above: the canonical display of a record is its hex component. line is
 * 16 bits: the source line of the reporting call, taken with __LINE__ at the call site,
 * so a record and a hexdump name the same place. reason is 16 bits, from the one
 * vocabulary below. argument is 32 bits and carries the detail each reason names in its
 * comment: a status, a handle, a count, a time in the unit the caller timed in.
 */
typedef struct Log_Record
{
    uint16_t component;   /* section << 8 | topic */
    uint16_t line;
    uint16_t reason;
    uint32_t argument;
} Log_Record;

/*
 * The sink: host-side. One call per record, in the order the records were reported. The
 * core makes no other promise about how it calls the sink, so a sink may do whatever its
 * platform allows (write a line, count, do nothing) and stays testable with a memory
 * sink of a few lines.
 */
typedef struct Log_Sink
{
    void *context;
    void (*write)(void *context, const Log_Record *record);
} Log_Sink;

/* The pool: 64 records, the size every measured drain window fits in twice over. */
#define LOG_RING_MAX 64

typedef struct Log_Log
{
    Log_Record ring[LOG_RING_MAX];
    uint32_t head;      /* where the next drain hands off from */
    uint32_t count;     /* what the ring holds */
    uint32_t refused;   /* reports turned away because the ring was full */
    uint32_t drained;   /* records handed to a sink, all time */
} Log_Log;

/* Resets the pool. The record array is written before it is read, so nothing is cleared. */
ZbStatus Log_Init(Log_Log *self);

/*
 * Takes one record. Refused with ZB_ERR_NO_SPACE when the pool is full (counted in
 * Log_Refused) and with ZB_ERR_BAD_ARGUMENT when self is 0. Not synchronised: the caller
 * reports from one execution context, as the rest of the stack does (docs/internals/coding-rules.md §4.7).
 */
ZbStatus Log_Report(Log_Log *self, uint16_t component, uint16_t line, uint16_t reason, uint32_t argument);

/*
 * Hands every pending record to the sink, oldest first, one call per record. Returns how
 * many it handed over. A 0 sink, or a sink with no write, hands over nothing and changes
 * nothing.
 */
uint32_t Log_Drain(Log_Log *self, const Log_Sink *sink);

uint32_t Log_Count(const Log_Log *self);
uint32_t Log_Refused(const Log_Log *self);
uint32_t Log_Drained(const Log_Log *self);

#endif /* LOG_H */
