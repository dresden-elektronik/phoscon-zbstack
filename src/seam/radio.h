#ifndef RADIO_H
#define RADIO_H

/*
 * The seam (docs/internals/architecture.md §4): the only header both sides of band A and band B may
 * include, and it holds types and function pointers, not code (docs/internals/coding-rules.md §4.6).
 * Nothing here knows a serial link, a property id, an RCP API level, a trailer, a dialect, or
 * an 802.15.4 frame layout: band B discovers those from the device and reports them as
 * capabilities.
 *
 * Delivery is pulled, never pushed: band A calls down and calls for frames when it is ready,
 * so band B holds no reference into band A and a frame is owned outright by whoever received
 * it. Band B never calls a function of band A.
 *
 * Append-only: a member is added here, never renumbered or reused (docs/internals/coding-rules.md §5).
 */

#include <stdint.h>
#include "zb_status.h"

enum
{
    RADIO_MPDU_MAX = 127,       /* one 802.15.4 PSDU: IEEE 802.15.4-2024 12.3.2 phyMaxPacketSize (127 for the 2.4 GHz O-QPSK PHY) read as Frame Length by 13.1.3.2 */
    RADIO_FRAME_BATCH_MAX = 8,  /* frames one rxPoll may hand over in one call */
    RADIO_ADDR_LEN = 8,         /* EUI-64 */
    RADIO_MAX_FRAME_RETRIES = 7 /* IEEE 802.15.4-2024 Table 8-36: macMaxFrameRetries ranges 0 to 7 */
};

/*
 * What the silicon actually does, read from it rather than assumed. `radioCaps`
 * is the device's own bitmap, passed through uninterpreted; the flags below are what band A
 * branches on, and band B derives them, because two firmwares answer the same property with
 * different contents (docs/internals/hardware.md §4).
 */
typedef struct Radio_Caps
{
    uint32_t radioCaps;
    int hasTransmit;
    int hasEnergyScan;
    int psduIncludesFcs;    /* 1: a delivered PSDU still carries its own 2-octet FCS */
    int hasAckMetadata;     /* 1: the radio reports the acknowledgement a transmit received */

    /* 1: the radio runs the acknowledgement wait itself and its completion says whether the frame was
       answered. This is the flag band A branches on, because the alternative (band A waiting for a frame
       no radio promised to report) is a different machine. `radioCaps` above is one dialect's vocabulary
       and band A may not read it (docs/internals/coding-rules.md §4.6); both RCPs here report the bit
       (docs/internals/hardware.md §4), and both outcomes are measured. */
    int handlesAckTimeout;

    /* 1: the radio sets the acknowledgment's Frame Pending bit from a table the host writes, one entry per
       address with a transaction waiting (the shape other host stacks program through the source address match
       list). 10.22.3 asks exactly that of the coordinator, and without the property no host can answer it
       (docs/internals/decisions.md D-157). */
    int hasPendingTable;
} Radio_Caps;

/*
 * The PIB subset the seam carries (docs/internals/protocol.md §7). A field is read or written only when
 * its bit is set in `present`, so one call can carry a partial change and a refused value
 * comes back as a stated status rather than as silence.
 */
enum
{
    RADIO_PIB_CHANNEL = 1,
    RADIO_PIB_PAGE = 2,
    RADIO_PIB_PAN_ID = 4,
    RADIO_PIB_SHORT_ADDRESS = 8,
    RADIO_PIB_EXTENDED_ADDRESS = 16,
    RADIO_PIB_RX_ON_WHEN_IDLE = 32,
    RADIO_PIB_MAX_CSMA_BACKOFFS = 64,
    RADIO_PIB_MAX_FRAME_RETRIES = 128,
    RADIO_PIB_ACK_WAIT_MS = 256,
    RADIO_PIB_CCA_THRESHOLD_DBM = 512,
    RADIO_PIB_HW_ADDRESS = 1024
};

typedef struct Radio_Pib
{
    uint32_t present;
    uint32_t channel;
    uint32_t page;
    uint16_t panId;
    uint16_t shortAddress;
    uint8_t extendedAddress[RADIO_ADDR_LEN];
    int rxOnWhenIdle;
    uint32_t maxCsmaBackoffs;
    uint32_t maxFrameRetries;
    uint32_t ackWaitMs;
    int32_t ccaThresholdDbm;

    /* The device's own factory EUI-64, in the same octet order as `extendedAddress` above: reported by the
       backend, never written by anyone above it, and all zero on a part that has none. `extendedAddress` is the
       operational address this host sets; this is the identity the silicon was given. */
    uint8_t hwAddress[RADIO_ADDR_LEN];
} Radio_Pib;

/*
 * Delivery selection. Only promiscuous receive is measured (docs/internals/hardware.md §6); the address
 * fields are here because the seam must be writable before the rig proves the filtered path,
 * and a backend that cannot honour them answers ZB_ERR_UNSUPPORTED rather than approximating.
 */
/* The addresses the acknowledgment should state pending, as 10.22.3's table holds them: one entry per device
   with a frame waiting, short addresses and extended addresses apart, seven at most each as 7.3.1.6 caps a
   beacon's list. Empty means no device is owed anything. */
enum
{
    RADIO_PENDING_MAX = 7
};

typedef struct Radio_Pending
{
    uint16_t shortAddress[RADIO_PENDING_MAX];
    uint32_t shortCount;
    uint64_t extendedAddress[RADIO_PENDING_MAX];
    uint32_t extendedCount;

    /* 1: the two lists are the whole answer, so a device they do not name has nothing waiting and its
       acknowledgment states zero. 0: band A holds a frame for a device it cannot name in the form that device
       will poll with, so the answer to any poll is 10.22.3's fallback, one, and the lists are not what decides it. */
    int isComplete;
} Radio_Pending;

typedef struct Radio_Filter
{
    int isPromiscuous;
    uint16_t panId;
    uint16_t shortAddress;
    uint8_t extendedAddress[RADIO_ADDR_LEN];
} Radio_Filter;

/*
 * One received PSDU, copied: the backend's ring is reused the moment rxPoll returns,
 * so a frame band A holds is band A's. `deviceStampTicks` is the device's own
 * clock, in the device's own unit: Spinel names the field microseconds and the
 * AT86RF233 build ticks at about 2.4 µs, so nothing
 * may convert it or compare it against a host clock. `deviceStampTicks` the
 * metadata (docs/internals/protocol.md §8.1): comparable between frames from one session,
 * not wall time, and not the host clock, which band C does not provide yet.
 */
typedef struct Radio_Frame
{
    uint32_t len;
    uint8_t bytes[RADIO_MPDU_MAX];
    int32_t rssiDbm;
    uint32_t lqi;
    uint64_t deviceStampTicks;    /* device ticks, not microseconds */
    ZbStatus error;         /* ZB_OK, or why the frame is suspect: it is still delivered */

    /* 1: the radio states that the acknowledgment it sent for this frame carried the Frame Pending bit, which is
       10.22.3's answer given on the air and the only report a host gets of an Ack it never sees. 0 says nothing:
       the bit may have been zero, or the radio may not report it at all (docs/internals/protocol.md §7.4). */
    int ackedWithFramePending;
} Radio_Frame;

/*
 * A transmit request. 0 is no handle; band B issues non-zero handles and keeps a result
 * available until band A collects it, because a completion that never arrives is itself a
 * named outcome (docs/internals/protocol.md §8.3).
 */
typedef uint32_t Radio_Handle;

enum
{
    RADIO_HANDLE_NONE = 0
};

/*
 * What a dwell reports when it measured nothing it could hand over: the device's own `+127`, the octet a
 * disarm reports and the reading a refused or interrupted dwell ends with (docs/internals/protocol.md §7.4.1). It is
 * a level, so it arrives with `ZB_OK` and a channel, and it is not a refusal: a host that cannot tell
 * "nothing here" from "not yet" will wait forever or believe a floor.
 */
enum
{
    RADIO_SCAN_NO_LEVEL = 127,

    /* The dwell bound the device itself states, in its own units. Measured at both ends: a period of 10000
       was stored verbatim and the dwell ran to about 1000, and a period of 0 ended the dwell with no reading
       behind it (docs/internals/protocol.md §7.4.3). band B refuses both at the seam rather than reporting a dwell that
       measured nothing as a measurement. */
    RADIO_SCAN_DWELL_MIN = 1,
    RADIO_SCAN_DWELL_MAX = 1000
};

typedef struct Radio_TxResult
{
    ZbStatus status;        /* what the device said about the request */
    int isAcked;            /* 1: an acknowledgment was asked for and the radio says it happened */
    uint32_t retries;

    /* 10.22.3's answer to a frame that asked to be acknowledged: `framePending` is the Frame Pending bit of the
       acknowledgment the radio heard, and only when `framePendingReported` is 1. 0 there says nothing about the
       bit, because a completion may come without it, and a device then reads no answer into it. */
    int framePendingReported;
    int framePending;
} Radio_TxResult;

typedef struct Radio_Radio Radio_Radio;

/* Every seam call takes the radio it belongs to, so a backend's own state stays its own. */
typedef struct Radio_Ops
{
    ZbStatus (*caps)(Radio_Radio *radio, Radio_Caps *outCaps);
    ZbStatus (*pibSet)(Radio_Radio *radio, const Radio_Pib *pib);
    ZbStatus (*pibGet)(Radio_Radio *radio, Radio_Pib *pib);
    ZbStatus (*filter)(Radio_Radio *radio, const Radio_Filter *filter);

    /* A refusal travels as the condition it means: NO_SPACE for no room for another transaction, which is IEEE
       7.2.4's TRANSACTION_OVERFLOW and the refusal band A re-asks under 3.2.1.1.3; NOT_READY for a backend that is
       not running; UNSUPPORTED where the device has no raw stream (docs/internals/protocol.md §7.3). `maxFrameRetries` is
       this frame's own retransmission budget, 0 to RADIO_MAX_FRAME_RETRIES, because a direct frame is retried and
       an indirect one never is (802.15.4-2024 6.6.3.4); a number past the bound is BAD_ARGUMENT. */
    ZbStatus (*tx)(Radio_Radio *radio, const uint8_t *mpdu, uint32_t len,
                   int ackRequest, uint32_t maxFrameRetries, Radio_Handle *outHandle);
    ZbStatus (*completion)(Radio_Radio *radio, Radio_Handle handle, Radio_TxResult *outResult);
    uint32_t (*rxPoll)(Radio_Radio *radio, Radio_Frame *outFrames, uint32_t maxFrames);

    /* 1 while what band A wrote is gone from the device: a faulted link, or a device that reset itself while it
       ran, for as long as it is being brought back and on the first ask after; band A holds, then re-applies. */
    int (*isLost)(Radio_Radio *radio);


    /*
     * An energy dwell, issued and collected, because that is what a device can be asked for.
     *
     * `scanStart` asks for one dwell on one channel and returns without waiting for it: the dialects on
     * measured answer a start with an echo, then a level as a notification a period later, then an end
     * as a third (docs/internals/protocol.md §7.4.1). `scanCollect` reports the level at a later call, and
     * `ZB_ERR_NOT_READY` while the dwell runs. Nothing in this pair blocks, because a call that pumped the
     * link until a band of dwells finished would run inside `Zb_LayersStep`, where band A's every deadline
     * is judged against the `nowMs` its caller hands it (docs/internals/decisions.md D-124).
     *
     * `dwellUnits` is the device's own period, in the unit the device measures its dwell
     * with, the unit of `MAC_SCAN_PERIOD`, not a millisecond of the host's clock: a dwell
     * asked for as 200 occupies 343 to 505 host milliseconds as measured and 1000 occupies
     * about 2130. The name carries no unit because the seam must
     * not assert one it has not measured. A band B refuses a number outside the bound the
     * device states rather than leaning on the clamp it measured (docs/internals/protocol.md §7.4.3).
     *
     * `scanCollect` answers `ZB_ERR_NOT_READY` while the dwell runs, `ZB_OK` with the channel and the level
     * when it has one, and `ZB_OK` carrying `RADIO_SCAN_NO_LEVEL` when the device measured nothing it could
     * report: a refusal, a completion with no reading behind it, or a dwell cut short by a transmit
     * (docs/internals/protocol.md §7.4.1). A device with no scan surface answers `ZB_ERR_UNSUPPORTED` at `scanStart`
     * and nothing is queued (D-123).
     */
    ZbStatus (*scanStart)(Radio_Radio *radio, uint32_t channel, uint32_t dwellUnits);
    ZbStatus (*scanCollect)(Radio_Radio *radio, uint32_t *outChannel, int32_t *outDbm);
    /*
     * 10.22.3's Frame Pending fact, stated to a radio that can put it on the air itself: the addresses a frame is
     * waiting for, written whenever band A's transaction queue changes. A radio without `hasPendingTable` has no
     * such property and is never called, so the table's absence is a capability's absence and not an error.
     */
    ZbStatus (*pendingTable)(Radio_Radio *radio, const Radio_Pending *pending);
} Radio_Ops;

/*
 * `provider` is band B's state; band A must not read it, and nothing in band A may cast it.
 * A backend constructor fills `ops` and `provider` and owns everything behind them.
 */
struct Radio_Radio
{
    const Radio_Ops *ops;
    void *provider;
};

#endif /* RADIO_H */
