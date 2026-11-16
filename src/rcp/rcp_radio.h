#ifndef RCP_RADIO_H
#define RCP_RADIO_H

/*
 * Band B's RCP backend: the seam of docs/internals/architecture.md §4 carried by a real RCP. It owns a
 * band C port, the HDLC framing, the Spinel codec and transaction, and the dialect table, and it
 * is the only module in band B that talks to all four. Band A sees `Radio_Ops` and nothing else.
 *
 * The bring-up order is the one docs/internals/protocol.md §6 records, the arm writes come from props.h
 * rather than from a list here, and the values come from the PIB. Which dialect an RCP is, what
 * it can do, and what its EUI-64 is are all *read from it*, never assumed.
 *
 * Nothing here blocks. A seam call either queues work or answers with a stated status; the link
 * moves when RcpRadio_Pump runs, and time arrives as `nowMs` (docs/internals/coding-rules.md §4.2). A reply
 * that never arrives ends the transaction and re-arms the sequence (§5).
 *
 * Three PIB fields (the CSMA backoff count, the frame retry count and their kin) are carried per
 * transmit in the §8.2 trailer rather than as properties: band B keeps them and writes them on
 * every request, and never looks for a property that carries them. `ackWaitMs` has neither a
 * property nor a trailer field on either dialect, so band B refuses it: how long band A waits for
 * an acknowledgment is band A's own decision.
 */

#include <stdint.h>
#include "hdlc.h"
#include "port.h"
#include "props.h"
#include "radio.h"
#include "spinel_session.h"
#include "zb_status.h"

enum
{
    RCP_RADIO_VERSION_MAX = 64,       /* the version string an RCP answered, kept for a driver's log */
    RCP_RADIO_RX_QUEUE_MAX = 16,      /* delivered frames waiting for band A to call rxPoll */
    RCP_RADIO_WRITE_QUEUE_MAX = 6,    /* One whole seam call must fit, so this is the number of PIB fields band B's
       own list carries that a dialect table maps to a property write, four on the OpenThread table and six on
       the DSPINEL one: channel, PAN id, short address, extended address, idle receive and, since the write was
       measured (docs/internals/protocol.md §7.4.3), the CCA threshold. A caller owns the mask (docs/internals/coding-rules.md §4.3,
       §7, docs/internals/decisions.md D-121). */
    RCP_RADIO_TX_TRACK_MAX = 4,       /* transmits taken and not yet collected, waiting for the wire included */
    RCP_RADIO_TX_WAIT_MS = 500,       /* how long a frame waits for the wire, inside band A's MAC_COMPLETION_TIMEOUT_MS */
    RCP_RADIO_TX_KEEP_MS = 2000,      /* how long a result waits to be collected, past band A's MAC_COMPLETION_TIMEOUT_MS */
    RCP_RADIO_REPLY_TIMEOUT_MS = 1000,  /* how long an RCP may take to answer a request before it counts as lost */
    RCP_RADIO_READ_CHUNK = 64,        /* octets pulled from the port per pump */

    /* The most §8.1 notifications that many octets can hold: the smallest value that shape allows is
       31 octets (header, command, id, length prefix, one octet of PSDU, RSSI, noise, MD_FLAG and the
       three metadata groups), and escaped octets only make a frame longer. */
    RCP_RADIO_CHUNK_FRAMES_MAX = 2,

    /* A queued write whose value lives in the PIB rather than in the queue slot: an EUI-64 has no
       scalar form, and the PIB is where band B keeps it. Every scalar this seam can queue is far
       below this value, which is why it can serve as the marker. */
    RCP_RADIO_VALUE_FROM_PIB = 0x7fffffff
};

/*
 * How far the bring-up has got. FAULT is a device that refused something the table promised, or a
 * link that went away; it is not a retry state, and only RcpRadio_Open, RcpRadio_Reopen or an explicit reset leaves
 * it. The two pre-running states are separate because the first GET of each pair is what makes the
 * other possible: the dialect is unknown until NCP_VERSION has been read, and everything after it
 * is chosen from that dialect's table.
 */
typedef enum RcpRadioMode
{
    RCP_RADIO_MODE_CLOSED = 0,
    RCP_RADIO_MODE_RESET = 1,
    RCP_RADIO_MODE_DISCOVER = 2,
    RCP_RADIO_MODE_ARM = 3,
    RCP_RADIO_MODE_RUNNING = 4,
    RCP_RADIO_MODE_FAULT = 5
} Rcp_RadioMode;

/*
 * One dwell, in the states its dialogue has on this family: three writes to start it, a notification
 * carrying its level, another saying it is over (docs/internals/protocol.md §7.4.1). A state below DWELL means a write
 * of the start is what this backend owes the device, and one Pump sends one write.
 */
typedef enum RcpRadioScan
{
    RCP_RADIO_SCAN_NONE = 0,      /* nothing asked */
    RCP_RADIO_SCAN_MASK = 1,      /* the channel list is the write owed */
    RCP_RADIO_SCAN_PERIOD = 2,    /* the period is the write owed */
    RCP_RADIO_SCAN_START = 3,     /* the write that puts the dwell on the air is owed */
    RCP_RADIO_SCAN_DWELL = 4,     /* started; the device has not reported */
    RCP_RADIO_SCAN_LEVEL = 5,     /* the device reported, or its dwell ended with nothing to report */
    RCP_RADIO_SCAN_REFUSED = 6,   /* the device refused this dwell and said why */
    RCP_RADIO_SCAN_NOTHERE = 7    /* it answered `PROP_NOT_FOUND`: this RCP has no dwell to ask for */
} Rcp_RadioScan;

/*
 * The source-match table's dialogue: 0x1303 says whether the table decides the Ack's Frame Pending bit, and
 * 0x1304/0x1305 carry the two lists. A list is replaced whole, so the three writes are one statement
 * (docs/internals/protocol.md §7.4).
 */
typedef enum RcpRadioPending
{
    RCP_RADIO_PENDING_NONE = 0,       /* the device holds what band A last stated */
    RCP_RADIO_PENDING_ENABLED = 1,    /* the write of 0x1303 is owed */
    RCP_RADIO_PENDING_SHORT = 2,      /* the write of 0x1304 is owed */
    RCP_RADIO_PENDING_EXTENDED = 3    /* the write of 0x1305 is owed */
} Rcp_RadioPending;

/*
 * A period above 4095 is clamped by the RCP rather than refused (docs/internals/protocol.md §7.4.1); band B refuses at
 * that bound instead of leaning on a clamp it cannot read back. The dwell bound is band B's own watchdog in
 * host milliseconds, from what a dwell takes here, 200 units answered in 343 to 505 ms and 1000 in 2128 ms,
 * because a dwell cut short by a transmit answers nothing at all, and a host
 * that waits forever cannot tell that from a dwell that is still running.
 */
enum
{
    RCP_RADIO_SCAN_PERIOD_MAX = 4095,
    RCP_RADIO_SCAN_MS_PER_UNIT = 4,
    RCP_RADIO_SCAN_SLACK_MS = 1000
};


/* One queued property write whose value is a scalar the seam can express in a uint32_t. */
typedef struct RcpRadioWrite
{
    uint32_t propId;
    uint32_t value;
    uint32_t order;     /* its place in line among transmits, the same for one seam call's writes */
} Rcp_RadioWrite;

typedef struct RcpRadio
{
    Port port;
    Hdlc_Decoder decoder;
    Spinel_Session session;

    Rcp_RadioMode mode;
    Props_Dialect dialect;
    Radio_Caps caps;
    Radio_Pib pib;

    uint8_t hwaddr[RADIO_ADDR_LEN];
    Prop_Surface surface;   /* what this device answered, learned from its answers (D-123) */
    uint8_t versionText[RCP_RADIO_VERSION_MAX];
    uint32_t versionLen;
    uint32_t apiVersion;
    uint32_t minHostApiVersion;
    uint32_t interfaceType;

    uint32_t discoveryIndex;      /* cursor into this module's discovery list */
    uint32_t armIndex;            /* cursor into the dialect's arm sequence */

    Rcp_RadioWrite writes[RCP_RADIO_WRITE_QUEUE_MAX];
    uint32_t writeCount;

    Radio_Handle nextHandle;
    Radio_Handle txHandle[RCP_RADIO_TX_TRACK_MAX];
    uint8_t txTid[RCP_RADIO_TX_TRACK_MAX];
    uint8_t txAckRequest[RCP_RADIO_TX_TRACK_MAX];
    uint8_t txFrame[RCP_RADIO_TX_TRACK_MAX][RADIO_MPDU_MAX]; /* the PSDU of a frame until the wire takes it */
    uint8_t txFrameLen[RCP_RADIO_TX_TRACK_MAX];
    uint8_t txMaxBackoffs[RCP_RADIO_TX_TRACK_MAX];
    uint8_t txMaxRetries[RCP_RADIO_TX_TRACK_MAX];
    uint32_t txOrder[RCP_RADIO_TX_TRACK_MAX];
    uint32_t txAskedMs[RCP_RADIO_TX_TRACK_MAX];
    uint32_t orderNext;            /* the place the next frame or write takes in line */
    uint32_t txWaitsExpired;       /* frames the wire never took within RCP_RADIO_TX_WAIT_MS */
    uint32_t txResultsUncollected; /* results no caller came for within RCP_RADIO_TX_KEEP_MS */
    Radio_TxResult txResult[RCP_RADIO_TX_TRACK_MAX];
    uint32_t txStatusCode[RCP_RADIO_TX_TRACK_MAX];
    uint32_t lastCompletionTail;   /* RCP_RADIO_TAIL_* of the last completion answered */

    uint32_t scanState;          /* one of RCP_RADIO_SCAN_* */
    uint32_t scanChannel;        /* the channel the dwell was asked for */
    uint32_t scanDwellUnits;
    uint32_t scanLevelChannel;   /* the channel the level arrived for */
    int32_t scanLevelDbm;
    uint32_t scanDeadlineMs;
    ZbStatus scanRefusal;        /* what a refused dwell reported */
    uint32_t scanDwells;         /* dwells this backend put on the wire */
    uint32_t scanAbandons;       /* dwells it stopped asking about */
    uint32_t scanRefusals;       /* dwells the device refused */

    /* The source-match table as band A stated it and as the device last answered it, the write owed of the
       three-write statement, and what became of it (docs/internals/protocol.md §7.4). */
    Radio_Pending pendingDesired;
    Radio_Pending pendingWritten;
    uint32_t pendingState;       /* one of RCP_RADIO_PENDING_* */
    int pendingWrittenValid;     /* 0 until the device has answered all three writes */
    int pendingDirty;
    uint32_t pendingWrites;      /* statements the device accepted */
    uint32_t pendingRefusals;    /* statements it refused */
    uint32_t rxAckedPending;     /* delivered frames whose acknowledgment this radio sent with Frame Pending one */
    uint32_t rxWithAckMetadata;  /* delivered frames whose MD_MAC names an acknowledgment */
    int txFilled[RCP_RADIO_TX_TRACK_MAX];
    int txAnswered[RCP_RADIO_TX_TRACK_MAX];
    int txWaiting[RCP_RADIO_TX_TRACK_MAX];

    Radio_Frame rxQueue[RCP_RADIO_RX_QUEUE_MAX];
    uint32_t rxHead;
    uint32_t rxCount;

    uint8_t frame[HDLC_PAYLOAD_MAX];
    uint8_t request[HDLC_PAYLOAD_MAX];
    uint8_t wire[PORT_TX_RING_MAX];
    uint8_t chunk[RCP_RADIO_READ_CHUNK];

    uint32_t writeFailures;       /* a device that refused a write its own table allowed */
    uint32_t frameLen;            /* the decoded payload the current dispatch is reading */
    uint32_t lastPumpMs;          /* the clock a seam call timestamps its request with */
    ZbStatus lastError;
    uint32_t frameRejects;        /* frames that arrived legibly but not usefully */
    uint32_t rxOverflows;         /* the last resort: a frame with nowhere left to wait */
    uint32_t rxUnarmed;           /* frames heard before the bring-up finished */
    uint32_t resetsSeen;          /* unsolicited reset announcements, each of which re-armed us */
    int lossOwed;                 /* a running RCP reset: isLost says so until it runs again and once after */
    uint32_t pumps;

    const Radio_Ops *ops;
    Radio_Radio seam;
} Rcp_Radio;

/*
 * Open a link and start bringing it up. The port is opened here (which is the one call allowed to
 * touch a device), the RESET is not sent until the first pump, and a flush flag goes out first
 * because §6 records it and an RCP left mid-frame needs it.
 */
/* Fill a backend's own state and bind its ops. No device is touched, nothing is sent, and the
   radio is in RCP_RADIO_MODE_CLOSED until RcpRadio_Open. */
ZbStatus RcpRadio_Init(Rcp_Radio *self, const PortDeviceOps *ops, uint32_t replyTimeoutMs);
ZbStatus RcpRadio_Open(Rcp_Radio *self, const char *path, const PortConfig *config);
void RcpRadio_Close(Rcp_Radio *self);

/*
 * Move the link: pull what the port has, decode every frame it yields, dispatch it, then send the
 * next thing the sequence needs. Pulling stops when the queue no longer has room for what one more
 * chunk could hold: bytes already read out of band C's ring cannot be put back, and a stack that
 * lost a frame because band A had not polled would be losing frames it was told to deliver. Returns ZB_OK when nothing went wrong and the stated error when
 * it did, so a driver can react without reading internals.
 */
ZbStatus RcpRadio_Pump(Rcp_Radio *self, uint32_t nowMs);

/* The handle band A calls through. Valid for the lifetime of `self`. */
Radio_Radio *RcpRadio_Seam(Rcp_Radio *self);

Rcp_RadioMode RcpRadio_Mode(const Rcp_Radio *self);
Props_Dialect RcpRadio_Dialect(const Rcp_Radio *self);
ZbStatus RcpRadio_LastError(const Rcp_Radio *self);
const uint8_t *RcpRadio_Address(const Rcp_Radio *self);   /* 0 until HWADDR has been answered */

/* The NCP_VERSION string this RCP answered, copied out. Kept because a driver has to say which
   firmware it is talking about, and because two builds of one dialect's family differ in what they
   answer (docs/internals/hardware.md §3). Truncated at RCP_RADIO_VERSION_MAX with the length reported. */
uint32_t RcpRadio_VersionText(const Rcp_Radio *self, uint8_t *out, uint32_t cap);
uint32_t RcpRadio_WriteFailures(const Rcp_Radio *self);
uint32_t RcpRadio_FrameRejects(const Rcp_Radio *self);
uint32_t RcpRadio_ResetsSeen(const Rcp_Radio *self);

/*
 * What a device put after the status code of a completion: §8.9.4.2's `y + sbb`, measured as
 * three value octets with both bits zero (D-47). `RCP_RADIO_TAIL_REPORTED` says
 * the device sent the two bits at all, which is a different fact from a reported zero; the other two name what
 * it said. The pending bit is the acknowledgment's, as the radio heard it, and
 * the seam's Radio_TxResult carries it with `framePendingReported` set from `RCP_RADIO_TAIL_REPORTED`.
 */
enum
{
    RCP_RADIO_TAIL_PENDING = 1,
    RCP_RADIO_TAIL_HEADER_UPDATED = 2,
    RCP_RADIO_TAIL_REPORTED = 4
};

uint32_t RcpRadio_CompletionTail(const Rcp_Radio *self);

/* Which of the RCP_RADIO_SCAN_* states one dwell is in, and the two counters beside it: dwells this backend put
   on the wire, and dwells it stopped asking about because the device said nothing. */
uint32_t RcpRadio_ScanState(const Rcp_Radio *self);
uint32_t RcpRadio_ScanDwells(const Rcp_Radio *self);
uint32_t RcpRadio_ScanAbandons(const Rcp_Radio *self);
uint32_t RcpRadio_ScanRefusals(const Rcp_Radio *self);

/* How many delivered frames carried a non-zero MD_MAC key id or frame counter: the fields the dialect
 * reserves for a frame the radio transmitted itself. Every frame captured from the air carried zeros in
 * all five (§4), so a delivered frame that does not is telling a different story: an RCP has been measured
 * handing back the frame it had just sent. */
uint32_t RcpRadio_RxWithAckMetadata(const Rcp_Radio *self);

/* How many delivered frames this radio acknowledged with the Frame Pending bit set (MD_FLAG's ACKED_FP):
   10.22.3's answer read off the side that gave it, since the Ack itself reaches no host. */
uint32_t RcpRadio_RxAckedPending(const Rcp_Radio *self);

/* Which of the RCP_RADIO_PENDING_* writes the source-match table is owed, what the device accepted and what it
   refused, and the table it last answered it took. A backend without the family answers nothing here. */
uint32_t RcpRadio_PendingState(const Rcp_Radio *self);
uint32_t RcpRadio_PendingWrites(const Rcp_Radio *self);
uint32_t RcpRadio_PendingRefusals(const Rcp_Radio *self);
int RcpRadio_PendingWritten(const Rcp_Radio *self, Radio_Pending *out);

/*
 * What this device answered for one property id: PROPS_SURFACE_KNOWN, PROPS_SURFACE_ABSENT, or
 * PROPS_SURFACE_UNKNOWN when this session has never asked (docs/internals/decisions.md D-123). The dialect's table says
 * what a build may be asked about; this says what the device on the port answered.
 */
int RcpRadio_SurfaceState(const Rcp_Radio *self, uint32_t propId);
uint32_t RcpRadio_LinkDrops(const Rcp_Radio *self);       /* HDLC frames discarded by the framing */
uint32_t RcpRadio_PortDrops(const Rcp_Radio *self);       /* octets the ring could not hold */
uint32_t RcpRadio_RxQueued(const Rcp_Radio *self);
uint32_t RcpRadio_RxOverflows(const Rcp_Radio *self);

/*
 * The transaction counters of this backend's session, copied out. A driver reads them to tell a
 * device that refused from a device that was silent, and to reconcile what it asked for with what
 * answered: requests, matched replies, unsolicited notifications, frames carrying a TID this session
 * never issued, expired transactions, and frames that were not decodable.
 */
void RcpRadio_Transactions(const Rcp_Radio *self, uint32_t *outRequests, uint32_t *outReplies,
                           uint32_t *outNotifications, uint32_t *outStale, uint32_t *outTimeouts,
                           uint32_t *outMalformed);

/*
 * The LAST_STATUS code a tracked transmit was answered with, as the device put it on the wire.
 * SpinelSession_StatusToZb folds several codes into one status on purpose (§7.3), which is right for a
 * stack and useless for a measurement: telling NO_ACK from BUSY from FAILURE is the whole reason to put
 * a frame on the air in the first place. Readable until the result is collected.
 */
ZbStatus RcpRadio_TxStatusCode(const Rcp_Radio *self, Radio_Handle handle, uint32_t *outCode);

/*
 * Send a RESET and start over, without closing the link: what §5 requires
 * when a completion never arrives. Queued writes and tracked transmits are dropped with a stated
 * status, because a device that reset has forgotten them.
 */
ZbStatus RcpRadio_Restart(Rcp_Radio *self, uint32_t nowMs);

/* Open the link again at the path it was opened at, after the device behind it went away: the old descriptor is
   closed without a teardown, and the loss stays owed, so isLost answers 1 while nothing is there, through the bring-up,
   and once after. NO_DEVICE while the path opens nothing; the radio stays FAULT until an attempt opens. */
ZbStatus RcpRadio_Reopen(Rcp_Radio *self, const PortConfig *config);

#endif /* RCP_RADIO_H */
