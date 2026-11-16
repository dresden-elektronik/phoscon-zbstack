#ifndef LOOPBACK_RADIO_H
#define LOOPBACK_RADIO_H

/*
 * Band B's backend with no hardware behind it (docs/internals/architecture.md §1). It answers the seam
 * exactly as an RCP does (same `Radio_Ops` table, same bounds, same handle discipline,
 * same pulled delivery) with one difference that is the whole reason it exists: what
 * it does is *scripted*, so a suite can say which transmit was acknowledged, which was
 * refused, and which never answered at all. Band A's suites run against this rather than
 * against an RCP, and a target with no radio at all can link it.
 *
 * A model, not a simulation. There is no CSMA here, no timing, no probability and no correlation
 * between the transmit and the receive side: a frame injected is a frame band A receives, and what
 * happened to a frame sent is whatever the script said. Nothing may be inferred from this module's
 * behaviour about a real device, and nothing about a real device is asserted here: the measured
 * device behaviour lives in `docs/internals/hardware.md` and in `rcp_radio.c` (docs/internals/coding-rules.md §9).
 *
 * Like `rcp_radio`, nothing here blocks and no wall clock is read: time arrives as `nowMs`, and a
 * transmit whose answer is scripted to take several pumps answers ZB_ERR_NOT_READY until then
 * (docs/internals/coding-rules.md §4.2).
 */

#include <stdint.h>
#include "radio.h"
#include "zb_status.h"

enum
{
    LOOPBACK_TX_MAX = 8,            /* transmits kept, observable and awaiting their result */
    LOOPBACK_RX_MAX = 16,           /* injected frames waiting for rxPoll (§32's queue) */
    LOOPBACK_SCAN_MAX = 16,         /* one result per channel this stack numbers (11..26) */
    LOOPBACK_PIB_WRITE_MAX = 8,     /* PIB requests kept, in the order the seam was handed them */

    /* The 2.4 GHz O-QPSK channel set, from the standard rather than from a device: neither build
       answers a channel list. */
    LOOPBACK_CHANNEL_MIN = 11,
    LOOPBACK_CHANNEL_MAX = 26,

    /* The two trailer octets of docs/internals/protocol.md §8.2 are uint8_t fields: a PIB value above 255
       cannot be handed to a radio that takes them, whichever backend it is. */
    LOOPBACK_TRAILER_MAX = 255
};

/*
 * The answer a transmit gets. `pendingPumps` says how many LoopbackRadio_Pump calls must pass before the
 * result is available, which is how a suite reaches into the "a completion that never arrives" case
 * (docs/internals/protocol.md §8.3) without waiting for anything. `isAcked` and `retries` are the model's own
 * claims: they are only meaningful when the caps this module was given say the radio reports them, which
 * is the capability band B measured as absent on both RCPs (docs/internals/hardware.md §4). `framePending`
 * is the acknowledgment's bit the model reports, when `framePendingReported` says it reports one.
 */
typedef struct Loopback_Outcome
{
    ZbStatus status;
    int isAcked;
    uint32_t retries;
    uint32_t pendingPumps;
    int framePendingReported;
    int framePending;
} Loopback_Outcome;

/* Told of each transmit as it is issued, and free to change its answer: what lets a suite put several of these radios
   on one air, where whether a frame was acknowledged depends on who can hear it. */
typedef void (*Loopback_TxObserver)(void *context, const uint8_t *mpdu, uint32_t len, int ackRequest,
                                    Loopback_Outcome *outcome);

/* One frame to hand to band A. `bytes` is copied, as at the real seam. */
typedef struct Loopback_FrameSpec
{
    uint32_t len;
    const uint8_t *bytes;
    int32_t rssiDbm;
    uint32_t lqi;
    uint64_t stampTicks;
    ZbStatus error;
    int ackedWithFramePending;
} Loopback_FrameSpec;

/* A transmit this backend handed out, kept so a suite can read what band A composed. */
typedef struct Loopback_Sent
{
    uint32_t len;
    uint8_t bytes[RADIO_MPDU_MAX];
    int ackRequest;
    Radio_Handle handle;
    int collected;
    uint32_t maxFrameRetries;
    uint32_t issuedIndex;           /* the transmit's place in issue order, which a reused slot does not keep */
} Loopback_Sent;

typedef struct Loopback_Radio
{
    Radio_Caps caps;
    Radio_Pib pib;
    Radio_Filter filter;

    Radio_Pib pibWrites[LOOPBACK_PIB_WRITE_MAX];
    uint32_t pibWriteCount;

    Loopback_Sent sent[LOOPBACK_TX_MAX];
    uint32_t sentCount;

    Radio_Frame queue[LOOPBACK_RX_MAX];
    uint32_t queueHead;
    uint32_t queueCount;

    Loopback_Outcome script[LOOPBACK_TX_MAX];
    uint32_t scriptCount;           /* scripted answers, consumed in issue order */
    uint32_t issued;                /* transmits so far: the cursor into that list */
    uint32_t issuedTotal;           /* transmits since Init, which a new script does not reset */
    Loopback_TxObserver txObserver;
    void *txObserverContext;

    int txAnswered[LOOPBACK_TX_MAX];
    uint32_t txPending[LOOPBACK_TX_MAX];
    Radio_TxResult txResult[LOOPBACK_TX_MAX];

    int32_t energy[LOOPBACK_SCAN_MAX];
    uint32_t energyCount;           /* 0 until a script fills it */
    int dwellOutstanding;           /* 1: one dwell is issued and not yet collected */
    uint32_t dwellChannel;
    uint32_t dwellAnswers;          /* pumps that must pass before the level is reportable */
    uint32_t refusePib;             /* one PIB bit answered ZB_ERR_DEVICE, then cleared */
    int filteredDelivery;           /* 1: this model accepts a non-promiscuous filter */
    uint32_t refusals;              /* scripted refusals, counted for a suite that asserts one happened */
    Radio_Pending pending;          /* 10.22.3's table as band A last stated it */
    uint32_t pendingWrites;         /* how often band A stated it */
    ZbStatus txRefuseStatus;        /* what the next `txRefuseCount` transmits answer instead of ZB_OK */
    uint32_t txRefuseCount;
    ZbStatus pibRefuseStatus;       /* what the next `pibRefuseCount` PIB writes answer instead of ZB_OK */
    uint32_t pibRefuseCount;
    int lost;

    Radio_Handle nextHandle;
    const Radio_Ops *ops;
    Radio_Radio seam;
} Loopback_Radio;

/*
 * Fill a backend and say what kind of radio it pretends to be. The caps are the model's declaration:
 * `hasEnergyScan` decides whether the dwell pair answers or refuses, and `psduIncludesFcs` is carried so
 * band A's FCS decisions can be exercised against both dialect rules without an RCP (docs/internals/protocol.md
 * §8.2). No transmit is issued and nothing is queued yet.
 */
ZbStatus LoopbackRadio_Init(Loopback_Radio *self, const Radio_Caps *caps);

/*
 * Advance the model: a pump decrements the pending count of every outstanding transmit whose answer is
 * scripted to arrive later. It never fails, because there is no link to fail; a device that goes away is
 * LoopbackRadio_SetLost's business. A band A suite pumps between its own seam calls, which is what a host
 * loop does for a real backend.
 */
ZbStatus LoopbackRadio_Pump(Loopback_Radio *self, uint32_t nowMs);

/* The handle band A calls through. Valid for the lifetime of `self`. */
Radio_Radio *LoopbackRadio_Seam(Loopback_Radio *self);

/*
 * Script the answer to the next `count` transmits, in issue order. Transmits beyond the script get the
 * default: acknowledged if the frame asked to be acknowledged, and successful.
 */
void LoopbackRadio_ScriptOutcomes(Loopback_Radio *self, const Loopback_Outcome *outcomes,
                                   uint32_t count);

/* 0 takes the observer away. */
void LoopbackRadio_SetTxObserver(Loopback_Radio *self, Loopback_TxObserver observer, void *context);

/* Put frames in front of band A: the next rxPoll hands them over, copied, in injection order. */
ZbStatus LoopbackRadio_Inject(Loopback_Radio *self, const Loopback_FrameSpec *frames, uint32_t count);

/* 10.22.3's table as band A last stated it: what it holds, and how often it was written. */
uint32_t LoopbackRadio_PendingWrites(const Loopback_Radio *self);
uint32_t LoopbackRadio_PendingShortCount(const Loopback_Radio *self);
int LoopbackRadio_PendingIsComplete(const Loopback_Radio *self);
uint16_t LoopbackRadio_PendingShort(const Loopback_Radio *self, uint32_t index);
uint32_t LoopbackRadio_PendingExtendedCount(const Loopback_Radio *self);

/*
 * Script the level the model reports for the channel at index `i` counting from
 * 11: one dwell per channel is what a device runs, and band A iterates a band
 * (docs/internals/decisions.md D-124). An unscripted channel answers `RADIO_SCAN_NO_LEVEL`, the
 * figure a device reports when it measured nothing: not a level the model invented.
 */
void LoopbackRadio_ScriptEnergy(Loopback_Radio *self, const int32_t *dbm, uint32_t count);

/* Refuse the next `count` transmits with `status`, recording nothing. A completion model cannot reach this: a
   refusal is the seam's answer to the request itself, not the outcome of a frame that went out. */
void LoopbackRadio_RefuseTx(Loopback_Radio *self, ZbStatus status, uint32_t count);

/* The next pibSet that carries this bit answers ZB_ERR_DEVICE once, then the model accepts again. */
void LoopbackRadio_RefusePib(Loopback_Radio *self, uint32_t presentBit);

/* Refuse the next `count` PIB writes with `status`, as a band B whose write queue has no room answers: the write
   is recorded as asked and nothing of it is applied. */
void LoopbackRadio_RefusePibWrites(Loopback_Radio *self, ZbStatus status, uint32_t count);

/* Script the identity this part was given: the factory EUI-64 `pibGet` reports and `pibSet` refuses, as an RCP's
   own backend does. All zero is a part that has none, which is then reported as absent; nothing above the seam can
   put it there, so it is the one PIB field a suite scripts rather than writes. */
void LoopbackRadio_SetFactoryAddress(Loopback_Radio *self, const uint8_t octets[RADIO_ADDR_LEN]);

/* Say the radio went away: every seam call that needs a device answers accordingly after this, and an
   outstanding transmit is answered with ZB_ERR_DEVICE_LOST rather than left waiting. */
void LoopbackRadio_SetLost(Loopback_Radio *self, int lost);

/* Whether this model accepts a filter that is not promiscuous. Default 1: what both measured builds do
   (§7.2), and 0 is how a suite reaches the refusal band B answers with on a build that cannot filter. */
void LoopbackRadio_SetFilteredDelivery(Loopback_Radio *self, int allowed);

/* What band A sent, in issue order: the composed octets, the acknowledgment it asked for, its handle. */
uint32_t LoopbackRadio_Sent(const Loopback_Radio *self, Loopback_Sent *out, uint32_t max);
uint32_t LoopbackRadio_Queued(const Loopback_Radio *self);
uint32_t LoopbackRadio_Refusals(const Loopback_Radio *self);

/* What band A asked the device to change, in issue order: every request the seam was handed, the ones this
   model refused included, because a request declined was still a request. The count answers how many were
   kept, so a suite that asserts nothing carries a field also says the record was not empty. */
uint32_t LoopbackRadio_PibWrites(const Loopback_Radio *self, Radio_Pib *out, uint32_t max);

#endif /* LOOPBACK_RADIO_H */
