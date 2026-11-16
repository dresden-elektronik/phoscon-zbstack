#include "loopback_radio.h"

#include "zb_utils.h"

/*
 * The model's own defaults. -128 is the sentinel a ConBee II's PHY_RSSI answers when it has nothing to
 * report, with no frame in front of it, which is a better
 * lie than a plausible number: an energy script that was never written says so.
 */
#define LOOPBACK_NO_ENERGY (-128)

enum
{
    LOOPBACK_FCS_OCTETS = 2
};

static const uint32_t pibOrder[] =
{
    RADIO_PIB_CHANNEL,
    RADIO_PIB_PAGE,
    RADIO_PIB_PAN_ID,
    RADIO_PIB_SHORT_ADDRESS,
    RADIO_PIB_EXTENDED_ADDRESS,
    RADIO_PIB_RX_ON_WHEN_IDLE,
    RADIO_PIB_MAX_CSMA_BACKOFFS,
    RADIO_PIB_MAX_FRAME_RETRIES,
    RADIO_PIB_ACK_WAIT_MS,
    RADIO_PIB_CCA_THRESHOLD_DBM,
    RADIO_PIB_HW_ADDRESS
};

#define PIB_FIELD_COUNT (sizeof pibOrder / sizeof pibOrder[0])

/*
 * A field the model cannot hold, as opposed to one it was scripted to refuse: the bounds are the ones
 * the seam's own types and the §8.2 trailer impose, and they are the same bounds rcp_radio enforces, so
 * a band A that passes one backend does not fail the other for a reason its own code caused.
 */
static ZbStatus loopbackJudgePib(Loopback_Radio *self, uint32_t field, const Radio_Pib *pib)
{
    (void)self;

    if (field == RADIO_PIB_CHANNEL)
    {
        if (pib->channel < LOOPBACK_CHANNEL_MIN || pib->channel > LOOPBACK_CHANNEL_MAX)
            return ZB_ERR_BAD_ARGUMENT;
    }

    if (field == RADIO_PIB_PAGE && pib->page != 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (field == RADIO_PIB_HW_ADDRESS)
        return ZB_ERR_UNSUPPORTED;

    if (field == RADIO_PIB_MAX_CSMA_BACKOFFS && pib->maxCsmaBackoffs > LOOPBACK_TRAILER_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (field == RADIO_PIB_MAX_FRAME_RETRIES && pib->maxFrameRetries > LOOPBACK_TRAILER_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    return ZB_OK;
}

static ZbStatus loopbackOpCaps(Radio_Radio *radio, Radio_Caps *outCaps)
{
    Loopback_Radio *self = (Loopback_Radio *)radio->provider;

    if (outCaps == 0)
        return ZB_ERR_BAD_ARGUMENT;

    *outCaps = self->caps;

    return ZB_OK;
}

static ZbStatus loopbackOpPibSet(Radio_Radio *radio, const Radio_Pib *pib)
{
    Loopback_Radio *self = (Loopback_Radio *)radio->provider;
    uint32_t i;
    ZbStatus status;

    if (pib == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->pibWriteCount < LOOPBACK_PIB_WRITE_MAX)
    {
        self->pibWrites[self->pibWriteCount] = *pib;
        self->pibWriteCount++;
    }

    if (self->lost)
        return ZB_ERR_NOT_OPEN;

    if (self->pibRefuseCount > 0)
    {
        self->pibRefuseCount--;
        self->refusals++;
        return self->pibRefuseStatus;
    }

    for (i = 0; i < PIB_FIELD_COUNT; i++)
    {
        if ((pib->present & pibOrder[i]) == 0)
            continue;

        if (self->refusePib == pibOrder[i])
        {
            self->refusePib = 0;
            self->refusals++;
            return ZB_ERR_DEVICE;
        }

        status = loopbackJudgePib(self, pibOrder[i], pib);

        if (status != ZB_OK)
            return status;
    }

    if ((pib->present & RADIO_PIB_CHANNEL) != 0)
        self->pib.channel = pib->channel;

    if ((pib->present & RADIO_PIB_PAGE) != 0)
        self->pib.page = pib->page;

    if ((pib->present & RADIO_PIB_PAN_ID) != 0)
        self->pib.panId = pib->panId;

    if ((pib->present & RADIO_PIB_SHORT_ADDRESS) != 0)
        self->pib.shortAddress = pib->shortAddress;

    if ((pib->present & RADIO_PIB_EXTENDED_ADDRESS) != 0)
        Zb_memcpy(self->pib.extendedAddress, pib->extendedAddress, RADIO_ADDR_LEN);

    if ((pib->present & RADIO_PIB_RX_ON_WHEN_IDLE) != 0)
        self->pib.rxOnWhenIdle = pib->rxOnWhenIdle;

    if ((pib->present & RADIO_PIB_MAX_CSMA_BACKOFFS) != 0)
        self->pib.maxCsmaBackoffs = pib->maxCsmaBackoffs;

    if ((pib->present & RADIO_PIB_MAX_FRAME_RETRIES) != 0)
        self->pib.maxFrameRetries = pib->maxFrameRetries;

    if ((pib->present & RADIO_PIB_ACK_WAIT_MS) != 0)
        self->pib.ackWaitMs = pib->ackWaitMs;

    if ((pib->present & RADIO_PIB_CCA_THRESHOLD_DBM) != 0)
        self->pib.ccaThresholdDbm = pib->ccaThresholdDbm;

    self->pib.present |= pib->present;

    return ZB_OK;
}

/* Whether this part was scripted with an identity of its own. All zero is the answer a part that has none
   gives, and "none" is what the backend reports, not an address a caller may write back. */
static int loopbackHasFactoryAddress(const Loopback_Radio *self)
{
    static const uint8_t none[RADIO_ADDR_LEN] = { 0, 0, 0, 0, 0, 0, 0, 0 };

    return Zb_memcmp(self->pib.hwAddress, none, RADIO_ADDR_LEN) != 0;
}

static ZbStatus loopbackOpPibGet(Radio_Radio *radio, Radio_Pib *pib)
{
    Loopback_Radio *self = (Loopback_Radio *)radio->provider;

    if (pib == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->lost)
        return ZB_ERR_NOT_OPEN;

    *pib = self->pib;

    if (loopbackHasFactoryAddress(self))
        pib->present |= RADIO_PIB_HW_ADDRESS;
    else
        pib->present &= ~RADIO_PIB_HW_ADDRESS;

    return ZB_OK;
}

static ZbStatus loopbackOpFilter(Radio_Radio *radio, const Radio_Filter *filter)
{
    Loopback_Radio *self = (Loopback_Radio *)radio->provider;

    if (filter == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->lost)
        return ZB_ERR_NOT_OPEN;

    if (!filter->isPromiscuous && !self->filteredDelivery)
    {
        self->refusals++;
        return ZB_ERR_UNSUPPORTED;
    }

    self->filter = *filter;

    return ZB_OK;
}

static Loopback_Outcome loopbackOutcomeFor(Loopback_Radio *self, int ackRequest)
{
    Loopback_Outcome outcome;

    Zb_memset(&outcome, 0, (uint32_t)sizeof outcome);

    if (self->issued < self->scriptCount)
    {
        outcome = self->script[self->issued];
    }
    else
    {
        outcome.status = ZB_OK;
        outcome.isAcked = ackRequest;
    }

    return outcome;
}

static ZbStatus loopbackOpTx(Radio_Radio *radio, const uint8_t *mpdu, uint32_t len, int ackRequest,
                             uint32_t maxFrameRetries, Radio_Handle *outHandle)
{
    Loopback_Radio *self = (Loopback_Radio *)radio->provider;
    Loopback_Outcome outcome;
    uint32_t slot;
    uint32_t radioLen;

    if (mpdu == 0 || outHandle == 0 || maxFrameRetries > RADIO_MAX_FRAME_RETRIES)
        return ZB_ERR_BAD_ARGUMENT;

    if (len == 0 || len > RADIO_MPDU_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->lost)
        return ZB_ERR_NOT_OPEN;

    if (!self->caps.psduIncludesFcs && len <= LOOPBACK_FCS_OCTETS)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->txRefuseCount > 0)
    {
        self->txRefuseCount--;
        self->refusals++;
        return self->txRefuseStatus;
    }

    for (slot = 0; slot < LOOPBACK_TX_MAX; slot++)
    {
        if (self->sent[slot].handle == RADIO_HANDLE_NONE)
            break;
    }

    if (slot >= LOOPBACK_TX_MAX)
        return ZB_ERR_NO_SPACE;

    radioLen = self->caps.psduIncludesFcs ? len : len - 2;

    self->sent[slot].len = radioLen;
    Zb_memcpy(self->sent[slot].bytes, mpdu, radioLen);
    self->sent[slot].ackRequest = ackRequest ? 1 : 0;
    self->sent[slot].maxFrameRetries = maxFrameRetries;
    self->sent[slot].collected = 0;
    self->sent[slot].handle = self->nextHandle;
    self->sent[slot].issuedIndex = self->issuedTotal++;

    outcome = loopbackOutcomeFor(self, ackRequest);

    if (self->txObserver != 0)
        self->txObserver(self->txObserverContext, mpdu, radioLen, ackRequest ? 1 : 0, &outcome);

    self->txResult[slot].status = outcome.status;
    self->txResult[slot].isAcked = outcome.isAcked;
    self->txResult[slot].retries = outcome.retries;
    self->txResult[slot].framePendingReported = outcome.isAcked && outcome.framePendingReported;
    self->txResult[slot].framePending = self->txResult[slot].framePendingReported && outcome.framePending;
    self->txPending[slot] = outcome.pendingPumps;
    self->txAnswered[slot] = outcome.pendingPumps == 0 ? 1 : 0;
    self->issued++;

    *outHandle = self->nextHandle;
    self->nextHandle = self->nextHandle + 1;

    if (self->nextHandle == 0)
        self->nextHandle = 1;

    return ZB_OK;
}

static ZbStatus loopbackOpCompletion(Radio_Radio *radio, Radio_Handle handle, Radio_TxResult *outResult)
{
    Loopback_Radio *self = (Loopback_Radio *)radio->provider;
    uint32_t slot;

    if (outResult == 0 || handle == RADIO_HANDLE_NONE)
        return ZB_ERR_BAD_ARGUMENT;

    for (slot = 0; slot < LOOPBACK_TX_MAX; slot++)
    {
        if (self->sent[slot].handle == handle && !self->sent[slot].collected)
            break;
    }

    if (slot >= LOOPBACK_TX_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (!self->txAnswered[slot])
        return ZB_ERR_NOT_READY;

    *outResult = self->txResult[slot];
    self->sent[slot].collected = 1;
    self->sent[slot].handle = RADIO_HANDLE_NONE;
    self->txAnswered[slot] = 0;

    return ZB_OK;
}

static uint32_t loopbackOpRxPoll(Radio_Radio *radio, Radio_Frame *outFrames, uint32_t maxFrames)
{
    Loopback_Radio *self = (Loopback_Radio *)radio->provider;
    uint32_t taken = 0;

    if (outFrames == 0 || maxFrames == 0)
        return 0;

    while (taken < maxFrames && self->queueCount > 0)
    {
        outFrames[taken] = self->queue[self->queueHead];
        self->queueHead = (self->queueHead + 1) % LOOPBACK_RX_MAX;
        self->queueCount--;
        taken++;
    }

    return taken;
}

static int loopbackOpIsLost(Radio_Radio *radio)
{
    Loopback_Radio *self = (Loopback_Radio *)radio->provider;

    return self->lost;
}

/*
 * One dwell on one channel, and the level it measured, available at a later call. The model answers the
 * way the RCP does: the start is accepted at once, the level arrives after the link has been pumped, and
 * a second start while one is outstanding is refused rather than queued (docs/internals/protocol.md §7.4.1).
 */
static ZbStatus loopbackOpScanStart(Radio_Radio *radio, uint32_t channel, uint32_t dwellUnits)
{
    Loopback_Radio *self = (Loopback_Radio *)radio->provider;

    if (self->lost)
        return ZB_ERR_NOT_OPEN;

    if (!self->caps.hasEnergyScan)
        return ZB_ERR_UNSUPPORTED;

    if (channel < LOOPBACK_CHANNEL_MIN || channel > LOOPBACK_CHANNEL_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (dwellUnits < RADIO_SCAN_DWELL_MIN || dwellUnits > RADIO_SCAN_DWELL_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->dwellOutstanding)
        return ZB_ERR_BUSY;

    self->dwellOutstanding = 1;
    self->dwellChannel = channel;
    self->dwellAnswers = 1;       
    return ZB_OK;
}

static ZbStatus loopbackOpScanCollect(Radio_Radio *radio, uint32_t *outChannel, int32_t *outDbm)
{
    Loopback_Radio *self = (Loopback_Radio *)radio->provider;
    uint32_t index;

    if (outChannel == 0 || outDbm == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->lost)
        return ZB_ERR_NOT_OPEN;

    if (!self->caps.hasEnergyScan)
        return ZB_ERR_UNSUPPORTED;

    if (!self->dwellOutstanding)
        return ZB_ERR_NOT_READY;

    if (self->dwellAnswers > 0)
        return ZB_ERR_NOT_READY;

    index = self->dwellChannel - LOOPBACK_CHANNEL_MIN;

    *outChannel = self->dwellChannel;
    *outDbm = index < self->energyCount ? self->energy[index] : RADIO_SCAN_NO_LEVEL;
    self->dwellOutstanding = 0;
    return ZB_OK;
}

/* 10.22.3's table kept as the model was told it, so a suite can read what band A stated and whether the mode it
   claims is the one this model honours. */
static ZbStatus loopbackOpPendingTable(Radio_Radio *radio, const Radio_Pending *pending)
{
    Loopback_Radio *self = (Loopback_Radio *)radio->provider;

    if (pending == 0)
        return ZB_ERR_BAD_ARGUMENT;

    self->pending = *pending;
    self->pendingWrites++;

    return ZB_OK;
}

static const Radio_Ops loopbackOps =
{
    loopbackOpCaps,
    loopbackOpPibSet,
    loopbackOpPibGet,
    loopbackOpFilter,
    loopbackOpTx,
    loopbackOpCompletion,
    loopbackOpRxPoll,
    loopbackOpIsLost,
    loopbackOpScanStart,
    loopbackOpScanCollect,
    loopbackOpPendingTable
};

ZbStatus LoopbackRadio_Init(Loopback_Radio *self, const Radio_Caps *caps)
{
    uint32_t i;

    if (self == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(self, 0, (uint32_t)sizeof *self);

    if (caps != 0)
        self->caps = *caps;

    self->filteredDelivery = 1;
    self->nextHandle = 1;
    self->ops = &loopbackOps;
    self->seam.ops = self->ops;
    self->seam.provider = self;

    for (i = 0; i < LOOPBACK_SCAN_MAX; i++)
        self->energy[i] = RADIO_SCAN_NO_LEVEL;

    return ZB_OK;
}

ZbStatus LoopbackRadio_Pump(Loopback_Radio *self, uint32_t nowMs)
{
    uint32_t slot;

    if (self == 0)
        return ZB_ERR_BAD_ARGUMENT;

    (void)nowMs;

    for (slot = 0; slot < LOOPBACK_TX_MAX; slot++)
    {
        if (self->sent[slot].handle == RADIO_HANDLE_NONE || self->txAnswered[slot])
            continue;

        if (self->txPending[slot] == 0)
        {
            self->txAnswered[slot] = 1;
            continue;
        }

        self->txPending[slot]--;

        if (self->txPending[slot] == 0)
            self->txAnswered[slot] = 1;
    }

    if (self->dwellOutstanding && self->dwellAnswers > 0)
        self->dwellAnswers--;

    return ZB_OK;
}

Radio_Radio *LoopbackRadio_Seam(Loopback_Radio *self)
{
    if (self == 0)
        return 0;

    return &self->seam;
}

void LoopbackRadio_ScriptOutcomes(Loopback_Radio *self, const Loopback_Outcome *outcomes, uint32_t count)
{
    uint32_t i;

    if (self == 0 || outcomes == 0)
        return;

    if (count > LOOPBACK_TX_MAX)
        count = LOOPBACK_TX_MAX;

    for (i = 0; i < count; i++)
        self->script[i] = outcomes[i];

    self->scriptCount = count;
    self->issued = 0;
}

ZbStatus LoopbackRadio_Inject(Loopback_Radio *self, const Loopback_FrameSpec *frames, uint32_t count)
{
    uint32_t i;
    uint32_t slot;

    if (self == 0 || frames == 0 || count == 0)
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < count; i++)
    {
        if (frames[i].bytes == 0 || frames[i].len == 0 || frames[i].len > RADIO_MPDU_MAX)
            return ZB_ERR_BAD_ARGUMENT;
    }

    if (count > LOOPBACK_RX_MAX - self->queueCount)
        return ZB_ERR_NO_SPACE;     

    for (i = 0; i < count; i++)
    {
        slot = (self->queueHead + self->queueCount) % LOOPBACK_RX_MAX;

        self->queue[slot].len = frames[i].len;
        Zb_memcpy(self->queue[slot].bytes, frames[i].bytes, frames[i].len);
        self->queue[slot].rssiDbm = frames[i].rssiDbm;
        self->queue[slot].lqi = frames[i].lqi;
        self->queue[slot].deviceStampTicks = frames[i].stampTicks;
        self->queue[slot].error = frames[i].error;
        self->queue[slot].ackedWithFramePending = frames[i].ackedWithFramePending;
        self->queueCount++;
    }

    return ZB_OK;
}

void LoopbackRadio_ScriptEnergy(Loopback_Radio *self, const int32_t *dbm, uint32_t count)
{
    uint32_t i;

    if (self == 0 || dbm == 0)
        return;

    if (count > LOOPBACK_SCAN_MAX)
        count = LOOPBACK_SCAN_MAX;

    for (i = 0; i < count; i++)
        self->energy[i] = dbm[i];

    self->energyCount = count;
}

void LoopbackRadio_RefuseTx(Loopback_Radio *self, ZbStatus status, uint32_t count)
{
    if (self == 0)
        return;

    self->txRefuseStatus = status;
    self->txRefuseCount = count;
}

void LoopbackRadio_RefusePibWrites(Loopback_Radio *self, ZbStatus status, uint32_t count)
{
    if (self == 0)
        return;

    self->pibRefuseStatus = status;
    self->pibRefuseCount = count;
}

void LoopbackRadio_RefusePib(Loopback_Radio *self, uint32_t presentBit)
{
    if (self == 0)
        return;

    self->refusePib = presentBit;
}

void LoopbackRadio_SetFactoryAddress(Loopback_Radio *self, const uint8_t octets[RADIO_ADDR_LEN])
{
    if (self == 0 || octets == 0)
        return;

    Zb_memcpy(self->pib.hwAddress, octets, RADIO_ADDR_LEN);
}

void LoopbackRadio_SetLost(Loopback_Radio *self, int lost)
{
    uint32_t slot;

    if (self == 0)
        return;

    self->lost = lost ? 1 : 0;

    if (!self->lost)
        return;

    for (slot = 0; slot < LOOPBACK_TX_MAX; slot++)
    {
        if (self->sent[slot].handle == RADIO_HANDLE_NONE)
            continue;

        self->txResult[slot].status = ZB_ERR_DEVICE_LOST;
        self->txResult[slot].isAcked = 0;
        self->txResult[slot].framePendingReported = 0;
        self->txResult[slot].framePending = 0;
        self->txAnswered[slot] = 1;
    }
}

void LoopbackRadio_SetFilteredDelivery(Loopback_Radio *self, int allowed)
{
    if (self == 0)
        return;

    self->filteredDelivery = allowed ? 1 : 0;
}

void LoopbackRadio_SetTxObserver(Loopback_Radio *self, Loopback_TxObserver observer, void *context)
{
    self->txObserver = observer;
    self->txObserverContext = context;
}

uint32_t LoopbackRadio_Sent(const Loopback_Radio *self, Loopback_Sent *out, uint32_t max)
{
    uint32_t slot;
    uint32_t taken = 0;

    if (self == 0 || out == 0)
        return 0;

    for (slot = 0; slot < LOOPBACK_TX_MAX && taken < max; slot++)
    {
        if (self->sent[slot].handle == RADIO_HANDLE_NONE && !self->sent[slot].collected)
            continue;

        out[taken] = self->sent[slot];
        taken++;
    }

    return taken;
}

uint32_t LoopbackRadio_PibWrites(const Loopback_Radio *self, Radio_Pib *out, uint32_t max)
{
    uint32_t taken;

    if (self == 0 || out == 0)
        return 0;

    for (taken = 0; taken < self->pibWriteCount && taken < max; taken++)
        out[taken] = self->pibWrites[taken];

    return taken;
}

uint32_t LoopbackRadio_Queued(const Loopback_Radio *self)
{
    if (self == 0)
        return 0;

    return self->queueCount;
}

uint32_t LoopbackRadio_Refusals(const Loopback_Radio *self)
{
    if (self == 0)
        return 0;

    return self->refusals;
}

uint32_t LoopbackRadio_PendingWrites(const Loopback_Radio *self)
{
    return self == 0 ? 0 : self->pendingWrites;
}

int LoopbackRadio_PendingIsComplete(const Loopback_Radio *self)
{
    return self == 0 ? 0 : self->pending.isComplete;
}

uint32_t LoopbackRadio_PendingShortCount(const Loopback_Radio *self)
{
    return self == 0 ? 0 : self->pending.shortCount;
}

uint16_t LoopbackRadio_PendingShort(const Loopback_Radio *self, uint32_t index)
{
    return self == 0 || index >= self->pending.shortCount ? 0 : self->pending.shortAddress[index];
}

uint32_t LoopbackRadio_PendingExtendedCount(const Loopback_Radio *self)
{
    return self == 0 ? 0 : self->pending.extendedCount;
}
