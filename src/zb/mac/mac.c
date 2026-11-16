#include "mac.h"

#include "zb_time.h"
#include "zb_utils.h"

/* M2024: 6.2, 6.6.1, 6.6.2, 6.6.3.4, 7.2.1.4, 7.2.3, 7.3.1, 7.3.1.2, 7.3.1.6, 7.5.2, 7.5.4, 8.2.4.3, 8.2.8.2, 8.2.8.3, 8.3.4,
   8.3.5, 8.3.6, 10.19, 10.20, 10.21.2, 10.21.5, 10.21.5.1, 10.21.5.2, 10.21.6.1.5, 10.22.2, 10.22.3, 10.22.4.1, 10.22.5.2, 10.22.5.3 ok; 10.23.1 ok (measured); 8.2.2, 8.3.2 unbuilt; Table 8-36's defaults adopted. docs/internals/conformance.md pages. */
/* Whether this device was given an extended address at all: 6.2 makes the 64-bit address the device's, and a part
   that has none reports zero octets, which is no address rather than the address zero (8.2.2's own reading of the
   unprogrammed user row a measured RCP carries, docs/internals/hardware.md §6). */
static int macExtendedAddressKnown(const Mac_Mac *self)
{
    uint32_t i;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
    {
        if (self->pib.extendedAddress[i] != 0)
            return 1;
    }

    return 0;
}

/* The PIB's extended address is the octets the device reported, least significant octet first: the order
   HWADDR arrives in (docs/internals/hardware.md §3) and the order the frame field travels in (802.15.4-2006 7.2.1.4, the
   Destination Address field). The conversion happens here and nowhere else. */
static uint64_t macExtendedValue(const uint8_t *octets)
{
    uint64_t value;
    uint32_t i;

    value = 0;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        value = value | ((uint64_t)octets[i] << (i * 8));

    return value;
}

/* Stated wherever band A learns the mode, adoption included. */
static ZbStatus macStatePromiscuous(Mac_Mac *self);

/* Stated wherever the transaction queue moves, adoption included. */
static void macStatePendingTable(Mac_Mac *self);

ZbStatus Mac_Init(Mac_Mac *self, Radio_Radio *radio, const Mac_Config *config)
{
    Radio_Caps caps;
    Radio_Pib pib;

    if (self == 0 || radio == 0 || radio->ops == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(self, 0, (uint32_t)sizeof *self);

    if (radio->ops->caps(radio, &caps) != ZB_OK)
        return ZB_ERR_NOT_READY;      

    if (radio->ops->pibGet(radio, &pib) != ZB_OK)
        return ZB_ERR_NOT_READY;      

    self->radio = radio;
    self->caps = caps;
    self->pib = pib;

    self->tx.dsn = config ? config->dsnStart : 0;
    self->bsn = config ? config->bsnStart : 0;

    self->macPromiscuousMode = config != 0 && config->macPromiscuousMode != 0;
    self->hearsWhileAsleep = config != 0 && config->hearsWhileAsleep != 0;

    self->log = config != 0 ? config->log : 0;

    if (self->macPromiscuousMode && macStatePromiscuous(self) == ZB_OK)
        self->filterStated = 1;

    macStatePendingTable(self);

    return ZB_OK;
}

/* The fields a PIB call may carry, copied one by one into a record, the mask grown by what the call named. One
   routine for both records band A keeps, so the mirror and the applied record cannot disagree about which fields
   a call carried; `hwAddress` is not in the list, being the device's own field (docs/internals/protocol.md §7). */
static void macPibMerge(Radio_Pib *into, const Radio_Pib *from)
{
    if ((from->present & RADIO_PIB_CHANNEL) != 0)
        into->channel = from->channel;

    if ((from->present & RADIO_PIB_PAGE) != 0)
        into->page = from->page;

    if ((from->present & RADIO_PIB_PAN_ID) != 0)
        into->panId = from->panId;

    if ((from->present & RADIO_PIB_SHORT_ADDRESS) != 0)
        into->shortAddress = from->shortAddress;

    if ((from->present & RADIO_PIB_EXTENDED_ADDRESS) != 0)
        Zb_memcpy(into->extendedAddress, from->extendedAddress, RADIO_ADDR_LEN);

    if ((from->present & RADIO_PIB_RX_ON_WHEN_IDLE) != 0)
        into->rxOnWhenIdle = from->rxOnWhenIdle;

    if ((from->present & RADIO_PIB_MAX_CSMA_BACKOFFS) != 0)
        into->maxCsmaBackoffs = from->maxCsmaBackoffs;

    if ((from->present & RADIO_PIB_MAX_FRAME_RETRIES) != 0)
        into->maxFrameRetries = from->maxFrameRetries;

    if ((from->present & RADIO_PIB_ACK_WAIT_MS) != 0)
        into->ackWaitMs = from->ackWaitMs;

    if ((from->present & RADIO_PIB_CCA_THRESHOLD_DBM) != 0)
        into->ccaThresholdDbm = from->ccaThresholdDbm;

    into->present |= from->present;
}

ZbStatus Mac_SetPib(Mac_Mac *self, const Radio_Pib *pib)
{
    Radio_Pib mirror;
    ZbStatus status;

    if (self == 0 || pib == 0 || self->radio == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (pib->present == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if ((pib->present & RADIO_PIB_MAX_FRAME_RETRIES) != 0 && pib->maxFrameRetries > RADIO_MAX_FRAME_RETRIES)
        return ZB_ERR_BAD_ARGUMENT;

    status = self->radio->ops->pibSet(self->radio, pib);

    if (status != ZB_OK)
    {
        return status;
    }

    mirror = self->pib;
    macPibMerge(&mirror, pib);
    self->pib = mirror;

    macPibMerge(&self->applied, pib);

    return ZB_OK;
}

const Radio_Caps *Mac_Caps(const Mac_Mac *self)
{
    if (self == 0)
        return 0;

    return &self->caps;
}

const Radio_Pib *Mac_Pib(const Mac_Mac *self)
{
    if (self == 0)
        return 0;

    return &self->pib;
}

/* Table 10-114's macPromiscuousMode and 10.23.1's receiver request: the mode is stated to the seam as well as
   kept here, the seam carrying the mode alone because the address filter is the PIB's. A backend without the
   property leaves it in force here, band A's own footprint being what the receive path reads. */
/* 10.23.1's delivery selection stated to the radio, and the radio's answer kept: a seam that refused the write
   (a full write queue, NO_SPACE) leaves the mode where it was, so a caller that reads this back learns the radio
   is not the mode it believes (docs/internals/architecture.md §7). */
static ZbStatus macStatePromiscuous(Mac_Mac *self)
{
    Radio_Filter filter;

    if (self->radio == 0 || self->radio->ops->filter == 0)
        return ZB_OK;

    Zb_memset(&filter, 0, (uint32_t)sizeof filter);
    filter.isPromiscuous = self->macPromiscuousMode;

    return self->radio->ops->filter(self->radio, &filter);
}

/* One address once: two transactions for one device, or a queued form and its pair, are one entry. Answers 0 when
   the list is full, because a device the table cannot name is a device whose acknowledgment would say zero. */
static int macPendingAddShort(Radio_Pending *pending, uint16_t address)
{
    uint32_t i;

    for (i = 0; i < pending->shortCount; i++)
    {
        if (pending->shortAddress[i] == address)
            return 1;
    }

    if (pending->shortCount >= RADIO_PENDING_MAX)
        return 0;

    pending->shortAddress[pending->shortCount] = address;
    pending->shortCount++;
    return 1;
}

static int macPendingAddExtended(Radio_Pending *pending, uint64_t address)
{
    uint32_t i;

    for (i = 0; i < pending->extendedCount; i++)
    {
        if (pending->extendedAddress[i] == address)
            return 1;
    }

    if (pending->extendedCount >= RADIO_PENDING_MAX)
        return 0;

    pending->extendedAddress[pending->extendedCount] = address;
    pending->extendedCount++;
    return 1;
}

/* The pending fact, stated to a radio that can put it on the air: one entry per device with a transaction
   waiting, in both forms where this MAC knows them, because a poll may name either. A device it cannot name makes
   the statement incomplete, which is the standard's fallback rather than a claim that nothing waits for it. */
static void macStatePendingTable(Mac_Mac *self)
{
    const Mac_AddressPair *pair;
    const Mac_Transaction *transaction;
    Radio_Pending pending;
    int complete = 1;
    uint32_t i;

    if (self->radio == 0 || self->radio->ops->pendingTable == 0 || !self->caps.hasPendingTable)
        return;

    Zb_memset(&pending, 0, (uint32_t)sizeof pending);

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        transaction = &self->indirect.transactions[i];

        if (!transaction->used || transaction->attemptPending)
            continue;

        if (transaction->destAddrMode == MAC_ADDR_SHORT && transaction->destShort != MAC_FRAME_ADDR_BROADCAST)
            complete = macPendingAddShort(&pending, transaction->destShort) && complete;
        else if (transaction->destAddrMode == MAC_ADDR_EXTENDED)
            complete = macPendingAddExtended(&pending, transaction->destExtended) && complete;
        else
            continue;

        pair = MacIndirect_PairFor(&self->indirect, transaction->destAddrMode, transaction->destShort,
                                   transaction->destExtended);

        if (pair == 0)
        {
            complete = 0;
        }
        else
        {
            complete = macPendingAddShort(&pending, pair->shortAddress) && complete;
            complete = macPendingAddExtended(&pending, pair->extendedAddress) && complete;
        }
    }

    pending.isComplete = complete;
    (void)self->radio->ops->pendingTable(self->radio, &pending);
}

/* Set after Mac_Init, which resets band A's own footprint, and stated to the radio there as well. */
ZbStatus Mac_SetPromiscuousMode(Mac_Mac *self, int on)
{
    if (self == 0)
        return ZB_ERR_BAD_ARGUMENT;

    int previous = self->macPromiscuousMode;
    ZbStatus status;

    self->macPromiscuousMode = on != 0;
    status = macStatePromiscuous(self);

    if (status != ZB_OK)
        self->macPromiscuousMode = previous;
    else
        self->filterStated = 1;

    return status;
}

int Mac_PromiscuousModeOf(const Mac_Mac *self)
{
    if (self == 0)
        return 0;

    return self->macPromiscuousMode;
}

ZbStatus Mac_DataRequest(Mac_Mac *self, const Mac_DataRequestParameters *req, uint32_t nowMs, Radio_Handle *outHandle)
{
    Mac_Track *slot;
    int ackRequest;
    ZbStatus status;

    if (self == 0 || req == 0 || self->radio == 0)
        return ZB_ERR_BAD_ARGUMENT;

    ackRequest = req->frameType == MAC_FRAME_TYPE_COMMAND ? MacTx_CommandAckRequest(req) : req->ackRequest;

    if (MacTx_AskIsImpossible(req, ackRequest))
    {
        self->ackAskCleared++;
        ackRequest = 0;
    }

    status = MacTx_ValidateRequest(req, &self->pib, macExtendedAddressKnown(self), &self->refusedRequests);

    if (status != ZB_OK)
        return status;

    if (MacTx_IsAssociationResponseCommand(req))
    {
        self->refusedRequests++;
        return ZB_ERR_UNSUPPORTED;    /* 10.21.2, the Association Response is an indirect transaction: not built here, docs/internals/conformance.md §1 */
    }

    status = MacTx_IssueFrame(&self->tx, req, &self->pib, macExtendedValue(self->pib.extendedAddress),
                           self->radio, self->mpdu, (uint32_t)sizeof self->mpdu,
                           self->tx.dsn % MAC_DSN_WRAP, nowMs, 0, &slot, &self->refusedRequests);

    if (status != ZB_OK)
    {
        if (status == ZB_ERR_NO_SPACE)
            self->refusedRequests++;

        return status;
    }

    self->tx.dsn = self->tx.dsn + 1;

    slot->msduHandle = req->msduHandle;
    slot->confirmOwed = 1;

    if (MacTx_IsDataRequestCommand(req))
        MacIndirect_ChildPollSent(&self->childPoll, req, slot->handle, self->childPoll.issuing);

    if (outHandle != 0)
        *outHandle = slot->handle;

    return ZB_OK;
}

/* 8.3.4 asks whether this device is a coordinator before it may hold a transaction; nothing else in band A states
   the role, so the layer above states it, and until it does the question is unanswered rather than answered no. */
ZbStatus Mac_SetCoordinator(Mac_Mac *self, int known, int isCoordinator)
{
    if (self == 0)
        return ZB_ERR_BAD_ARGUMENT;

    self->coordinatorKnown = known;
    self->coordinatorIs = isCoordinator;

    return ZB_OK;
}

uint32_t Mac_IndirectHeldFor(const Mac_Mac *self, uint16_t shortAddress)
{
    uint32_t held = 0;
    uint32_t i;

    if (self == 0)
        return 0;

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (self->indirect.transactions[i].used && self->indirect.transactions[i].destAddrMode == MAC_ADDR_SHORT
            && self->indirect.transactions[i].destShort == shortAddress)
            held++;
    }

    return held;
}

/* 8.3.4: the indirect option is ignored, and an ignored option is a direct transmission rather than a refusal,
   where the request names no destination and where this device's role says it is no coordinator. */
ZbStatus Mac_IndirectRequest(Mac_Mac *self, const Mac_DataRequestParameters *req, uint32_t nowMs)
{
    if (self == 0 || req == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (req->destAddrMode == MAC_ADDR_NONE || (self->coordinatorKnown && !self->coordinatorIs))
    {
        self->indirectIgnored++;

        return Mac_DataRequest(self, req, nowMs, 0);
    }

    ZbStatus status = MacIndirect_Request(&self->indirect, req, &self->pib, macExtendedAddressKnown(self),
                                          macExtendedValue(self->pib.extendedAddress), self->radio, &self->tx.dsn,
                                          &self->refusedRequests, nowMs);

    if (status == ZB_OK)
        macStatePendingTable(self);

    return status;
}

/* One collection pass, and what the façade's own ledger answers for: the timeouts, the re-arm, and every slot
   whose answer an indirect attempt is decided by, the track slot being the confirmation and the attempt a fact
   about it (10.22.2, 6.6.1). */
static void macDoCompletions(Mac_Mac *self, uint32_t nowMs)
{
    Mac_TxCompletions completions;
    uint32_t i;

    MacTx_CollectCompletions(&self->tx, self->radio, &self->caps, nowMs, &completions);

    self->timeouts = self->timeouts + completions.timeouts;

    if (completions.needsRearm)
        self->needsRearm = 1;

    for (i = 0; i < completions.answeredCount; i++)
    {
        MacIndirect_ReleaseAttempt(&self->indirect, completions.answered[i]);
        MacIndirect_ChildPollAnswered(&self->childPoll, completions.answered[i], nowMs);
    }

    if (completions.answeredCount != 0)
        macStatePendingTable(self);
}

/* The frames one receive pass may take: no more than the indication ring has free slots, and during an active scan,
   when any may be a beacon owing a notification, no more than that ring has; the rest wait in the radio until the
   layer above drains: a bridged RCP hands over a scan's beacons in one read. */
static uint32_t macRxBatchMax(const Mac_Mac *self)
{
    uint32_t room = MacRx_Room(&self->rx);
    uint32_t notifications;

    if (MacScan_ActiveRunning(&self->scan))
    {
        notifications = MacBeacon_NotificationRoom(&self->beacon);

        if (notifications < room)
            room = notifications;
    }

    return room < RADIO_FRAME_BATCH_MAX ? room : RADIO_FRAME_BATCH_MAX;
}

/* What a device hears outside a poll's window: everything with macRxOnWhenIdle TRUE or the configuration keeping it,
   and otherwise only while promiscuous mode, a scan or an association holds its receiver on. */
static int macHearsBetweenPolls(const Mac_Mac *self)
{
    Mac_AssocState assoc = MacAssoc_StateOf(&self->assoc);

    if ((self->pib.present & RADIO_PIB_RX_ON_WHEN_IDLE) == 0 || self->pib.rxOnWhenIdle || self->hearsWhileAsleep)
        return 1;

    if (self->macPromiscuousMode || MacScan_Running(&self->scan))
        return 1;

    return assoc == MAC_ASSOC_REQUESTING || assoc == MAC_ASSOC_WAITING || assoc == MAC_ASSOC_POLLING
           || assoc == MAC_ASSOC_SENDING;
}

/* One turn of the MAC: recover, collect, progress, age, receive, answer, and answer a beacon. 8.3.5's confirmation
   is one a caller queued, so the two frames this function issues itself, the owed poll and the beacon, owe none. */
ZbStatus Mac_Step(Mac_Mac *self, uint32_t nowMs)
{
    uint32_t taken;
    uint32_t batchMax;
    uint32_t expired;
    uint32_t i;
    int lost;
    ZbStatus status;
    ZbStatus answer;
    ZbStatus mirrorStatus;

    if (self == 0 || self->radio == 0)
        return ZB_ERR_BAD_ARGUMENT;

    lost = self->radio->ops->isLost(self->radio);

    if (lost)
    {
        self->lostEpisode = 1;
        self->needsRearm = 1;

        if (self->applied.present != 0)
            self->reapplyPending = 1;

        self->restatePending = 1;

        return ZB_OK;
    }

    self->lostEpisode = 0;

    if (self->reapplyPending)
    {
        mirrorStatus = Mac_SetPib(self, &self->applied);

        if (mirrorStatus == ZB_OK)
        {
            self->reapplyPending = 0;
            self->pibReapplications++;
        }
    }

    if (self->restatePending && !self->reapplyPending)
    {
        if (!self->filterStated || macStatePromiscuous(self) == ZB_OK)
        {
            macStatePendingTable(self);
            self->restatePending = 0;
        }
    }

    macDoCompletions(self, nowMs);

    MacAssoc_Progress(&self->assoc, self, &self->tx, &self->pib, nowMs);

    MacScan_Progress(&self->scan, self, &self->tx, nowMs);

    expired = self->indirect.transactionsExpired;
    MacIndirect_AgeTransactions(&self->indirect, nowMs);

    if (self->indirect.transactionsExpired != expired)
        macStatePendingTable(self);

    batchMax = macRxBatchMax(self);

    if (batchMax == 0)
    {
        MacAssoc_Expire(&self->assoc, self, nowMs);
        MacIndirect_ChildPollExpire(&self->childPoll, nowMs);

        self->pollsSkipped++;
        return ZB_OK;
    }

    taken = self->radio->ops->rxPoll(self->radio, self->rx.batch, batchMax);

    self->rx.stepPollCount = 0;

    for (i = 0; i < taken; i++)
    {
        if (!MacScan_Admits(&self->scan, &self->rx.batch[i]))
            continue;

        if (!MacIndirect_ChildPollAdmits(&self->childPoll, &self->rx.batch[i], self->caps.psduIncludesFcs, &self->pib,
                                         macExtendedValue(self->pib.extendedAddress), macHearsBetweenPolls(self)))
            continue;

        MacRx_QueueFrame(&self->rx, &self->rx.batch[i], &self->pib, &self->caps, macExtendedAddressKnown(self),
                         macExtendedValue(self->pib.extendedAddress), self->beacon.beaconAnswers,
                         self->beacon.beaconPanCoordinator, self->macPromiscuousMode, &self->beacon, &self->polls,
                         &self->assoc, &self->tx, self);
    }

    MacAssoc_Expire(&self->assoc, self, nowMs);
    MacIndirect_ChildPollExpire(&self->childPoll, nowMs);

    status = ZB_OK;

    for (i = 0; i < self->rx.stepPollCount; i++)
    {
        answer = MacIndirect_DoPollAnswer(&self->indirect, &self->rx.stepPolls[i], &self->tx, &self->pib,
                                          macExtendedAddressKnown(self),
                                          macExtendedValue(self->pib.extendedAddress), self->radio, self->mpdu,
                                          (uint32_t)sizeof self->mpdu, &self->tx.dsn, &self->refusedRequests,
                                          nowMs);

        if (answer != ZB_OK && status == ZB_OK)
            status = answer;
    }

    if (self->rx.stepPollCount != 0)
        macStatePendingTable(self);

    self->rx.stepPollCount = 0;

    if (self->beacon.pollOwed)
    {
        Radio_Handle handle = RADIO_HANDLE_NONE;
        Mac_DataRequestParameters poll;

        self->beacon.pollBytes[0] = MAC_CMD_POLL;

        Zb_memset(&poll, 0, (uint32_t)sizeof poll);

        poll.frameType = MAC_FRAME_TYPE_COMMAND;
        poll.ackRequest = 1;
        poll.payload = self->beacon.pollBytes;
        poll.payloadLen = 1;

        poll.destAddrMode = self->beacon.pollCoordMode;
        poll.destPan = self->beacon.pollCoordPan;
        poll.destShort = self->beacon.pollCoordShort;
        poll.destExtended = self->beacon.pollCoordExtended;

        poll.srcAddrMode = self->beacon.pollSrcMode;

        self->beacon.pollStatus = Mac_DataRequest(self, &poll, nowMs, &handle);

        if (self->beacon.pollStatus == ZB_OK)
        {
            Mac_Track *slot = MacTx_TrackNamed(&self->tx, handle, 1);

            if (slot != 0)
                slot->confirmOwed = 0;
        }

        if (self->beacon.pollStatus == ZB_OK)
        {
            self->beacon.pollOwed = 0;
            self->beacon.pollIssued++;
        }
        else
        {
            self->beacon.pollRefused++;

            if (self->beacon.pollStatus != ZB_ERR_BUSY && self->beacon.pollStatus != ZB_ERR_NO_SPACE)
                self->beacon.pollOwed = 0;
        }
    }

    MacBeacon_ReplyOwed(&self->beacon, self->indirect.transactions, &self->tx, &self->pib,
                        macExtendedAddressKnown(self), macExtendedValue(self->pib.extendedAddress),
                        self->radio, &self->bsn, self->mpdu, (uint32_t)sizeof self->mpdu, nowMs);

    return status;
}

uint32_t Mac_PollCommStatus(Mac_Mac *self, Mac_CommStatusParameters *out, uint32_t max)
{
    if (self == 0 || out == 0 || max == 0)
        return 0;

    return MacIndirect_PollCommStatus(&self->indirect, out, max);
}

uint32_t Mac_PollConfirms(Mac_Mac *self, Mac_DataConfirmParameters *out, uint32_t max)
{
    uint32_t taken = 0;
    uint32_t i;

    if (self == 0 || out == 0 || max == 0)
        return 0;

    taken = MacIndirect_PollConfirms(&self->indirect, out, max);

    for (i = 0; i < MAC_TX_TRACK_MAX && taken < max; i++)
    {
        if (self->tx.track[i].state != MAC_TX_ANSWERED && self->tx.track[i].state != MAC_TX_TIMED_OUT)
            continue;

        if (!self->tx.track[i].confirmOwed)
        {
            self->tx.track[i].state = MAC_TX_FREE;
            self->tx.track[i].handle = RADIO_HANDLE_NONE;
            continue;
        }

        out[taken].msduHandle = self->tx.track[i].msduHandle;
        out[taken].handle = self->tx.track[i].handle;
        out[taken].dsn = self->tx.track[i].dsn;
        out[taken].frameType = self->tx.track[i].frameType;
        out[taken].status = self->tx.track[i].status;
        out[taken].acked = self->tx.track[i].acked;
        out[taken].numBackoffs = self->tx.track[i].numBackoffs;
        out[taken].framePending = self->tx.track[i].framePending;

        self->tx.track[i].state = MAC_TX_FREE;
        self->tx.track[i].handle = RADIO_HANDLE_NONE;
        taken++;
    }

    return taken;
}

/* The frames the receive path delivered, oldest first: the ring is the receive subject's, in `mac_rx`. */
uint32_t Mac_PollIndications(Mac_Mac *self, Mac_DataIndicationParameters *out, uint32_t max)
{
    if (self == 0)
        return 0;

    return MacRx_PollIndications(&self->rx, out, max);
}

/* The polls R23.1 D.10.2 says a coordinator must be able to report, oldest first: the ring is the band's, and the
   classification that queues into it is `mac_rx`'s. */
uint32_t Mac_PollArrivals(Mac_Mac *self, Mac_PollArrival *out, uint32_t max)
{
    if (self == 0)
        return 0;

    return MacRx_PollArrivals(&self->polls, out, max);
}

/* The parent's association traffic, oldest first: the ring is the association subject's, in `mac_assoc`. */
uint32_t Mac_PollBeacons(Mac_Mac *self, Mac_BeaconNotification *out, uint32_t max)
{
    if (self == 0)
        return 0;

    return MacBeacon_PollNotifications(&self->beacon, out, max);
}

uint32_t Mac_PollAssociations(Mac_Mac *self, Mac_AssociationIndication *out, uint32_t max)
{
    if (self == 0)
        return 0;

    return MacAssoc_PollRequests(&self->assoc, out, max);
}

/* 10.21.5.2's answer, queued as the transaction the child's Data Request extracts (10.21.2). */
ZbStatus Mac_AssociateResponse(Mac_Mac *self, const Mac_AssociationResponse *response, uint32_t nowMs)
{
    ZbStatus status;

    if (self == 0 || response == 0)
        return ZB_ERR_BAD_ARGUMENT;

    status = MacAssoc_Response(&self->indirect, response, self->beacon.beaconAnswers, &self->pib,
                               macExtendedAddressKnown(self), macExtendedValue(self->pib.extendedAddress),
                               self->radio, &self->tx.dsn, &self->refusedRequests, nowMs);

    if (status == ZB_OK)
        macStatePendingTable(self);

    return status;
}

/* Table 10-104, MLME-ASSOCIATE.request written where 10.21.2 puts it, then 10.21.5.1's request. A door with no
   room for it holds the request and re-asks each step (docs/internals/decisions.md); one that refuses it otherwise leaves no PAN written,
   no address and a failed confirm carrying TRANSACTION_OVERFLOW, while the caller keeps the door's own status. */
ZbStatus Mac_AssociateRequest(Mac_Mac *self, const Mac_AssociateRequestParameters *req, uint32_t nowMs)
{
    if (self == 0 || req == 0 || self->radio == 0)
        return ZB_ERR_BAD_ARGUMENT;

    return MacAssoc_Request(&self->assoc, self, req, macExtendedAddressKnown(self), &self->refusedRequests, nowMs);
}

/* 1 when the association's outcome was taken: Table 10-107's Status and AssociationStatus, 0xeb NO_DATA (Table 78)
   on a window that saw none, 0xe9 NO_ACK only where an acknowledgment was outstanding, and the short address
   10.21.2 stores into macShortAddress. */
uint32_t Mac_PollAssociateConfirm(Mac_Mac *self, Mac_AssociateConfirmParameters *out)
{
    if (self == 0)
        return 0;

    return MacAssoc_PollConfirm(&self->assoc, out);
}

/* What the exchange is doing, for an owner that reads the state and not only the confirm. */
ZbStatus Mac_ScanRequest(Mac_Mac *self, const Mac_ScanRequestParameters *req, uint32_t nowMs)
{
    if (self == 0 || req == 0 || self->radio == 0)
        return ZB_ERR_BAD_ARGUMENT;

    return MacScan_Start(&self->scan, self, req, nowMs);
}

uint32_t Mac_PollScanConfirm(Mac_Mac *self, Mac_ScanConfirmParameters *out)
{
    if (self == 0 || out == 0)
        return 0;

    return MacScan_PollConfirm(&self->scan, out);
}

uint32_t Mac_PollOrphans(Mac_Mac *self, Mac_OrphanIndication *out, uint32_t max)
{
    if (self == 0 || out == 0)
        return 0;

    return MacScan_PollOrphans(&self->scan, out, max);
}

ZbStatus Mac_OrphanResponse(Mac_Mac *self, const Mac_OrphanResponseParameters *response, uint32_t nowMs)
{
    if (self == 0 || response == 0)
        return ZB_ERR_BAD_ARGUMENT;

    return MacScan_Respond(&self->scan, self, &self->tx, response, nowMs);
}

ZbStatus Mac_PollRequest(Mac_Mac *self, const Mac_PollRequestParameters *req, uint32_t nowMs)
{
    Mac_DataRequestParameters poll;
    Mac_Track *slot;
    Radio_Handle handle = RADIO_HANDLE_NONE;
    ZbStatus status;

    if (self == 0 || req == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (req->coordAddrMode != MAC_ADDR_SHORT && req->coordAddrMode != MAC_ADDR_EXTENDED)
        return ZB_ERR_BAD_ARGUMENT;

    if (MacIndirect_ChildPollRequested(&self->childPoll))
        return ZB_ERR_BUSY;

    self->childPoll.pollBytes[0] = MAC_CMD_POLL;

    Zb_memset(&poll, 0, (uint32_t)sizeof poll);
    poll.frameType = MAC_FRAME_TYPE_COMMAND;
    poll.destAddrMode = req->coordAddrMode;
    poll.destPan = req->coordPanId;
    poll.destShort = req->coordShort;
    poll.destExtended = req->coordExtended;
    poll.srcAddrMode = self->pib.shortAddress < MAC_SHORT_ADDRESS_LAST_USABLE ? MAC_ADDR_SHORT : MAC_ADDR_EXTENDED;
    poll.ackRequest = 1;
    poll.payload = self->childPoll.pollBytes;
    poll.payloadLen = 1;

    self->childPoll.issuing = 1;
    status = Mac_DataRequest(self, &poll, nowMs, &handle);
    self->childPoll.issuing = 0;

    if (status != ZB_OK)
        return status;

    slot = MacTx_TrackNamed(&self->tx, handle, 1);

    if (slot != 0)
        slot->confirmOwed = 0;

    return ZB_OK;
}

uint32_t Mac_PollRequestConfirm(Mac_Mac *self, Mac_PollConfirmParameters *out)
{
    if (self == 0 || out == 0)
        return 0;

    return MacIndirect_ChildPollConfirm(&self->childPoll, out);
}

int Mac_Hears(const Mac_Mac *self)
{
    return self != 0 && (macHearsBetweenPolls(self) || MacIndirect_ChildPollOpen(&self->childPoll));
}

int Mac_Scanning(const Mac_Mac *self)
{
    return self != 0 && MacScan_Running(&self->scan);
}

Mac_AssocState Mac_AssocStateOf(const Mac_Mac *self)
{
    if (self == 0)
        return MAC_ASSOC_IDLE;

    return MacAssoc_StateOf(&self->assoc);
}

/* The whole ledger at one instant: the stored counters as they are, and each pool's depth from the pool
   itself, so nothing here is a second copy that could state a number the pool does not hold. */
Mac_Counters Mac_CountersOf(const Mac_Mac *self)
{
    Mac_Counters counters;
    uint32_t i;

    Zb_memset(&counters, 0, (uint32_t)sizeof counters);

    if (self == 0)
        return counters;

    counters.refusedRequests = self->refusedRequests;
    counters.ackAskCleared = self->ackAskCleared;
    counters.indirectIgnored = self->indirectIgnored;
    counters.pollsSkipped = self->pollsSkipped;
    counters.indicationQueue = self->rx.indicationCount;
    counters.pollArrivalQueue = self->polls.count;
    counters.transactionsExpired = self->indirect.transactionsExpired;
    counters.commStatusQueue = self->indirect.commStatusCount;
    counters.commStatusRefused = self->indirect.commStatusRefused;
    counters.pollsUnanswered = self->indirect.pollsUnanswered;
    counters.pibReapplications = self->pibReapplications;
    counters.acksHeard = self->rx.acksHeard;
    counters.commandsHeard = self->rx.commandsHeard;
    counters.selfEchoes = self->rx.selfEchoes;
    counters.fcsFailures = self->rx.fcsFailures;
    counters.reservedTypeFrames = self->rx.reservedTypeFrames;
    counters.reservedVersionFrames = self->rx.reservedVersionFrames;
    counters.malformedFrames = self->rx.malformedFrames;
    counters.unbuiltForms = self->rx.unbuiltForms;
    counters.panMismatches = self->rx.panMismatches;
    counters.destinationMismatches = self->rx.destinationMismatches;
    counters.beaconPanMismatches = self->rx.beaconPanMismatches;
    counters.sourcePanMismatches = self->rx.sourcePanMismatches;
    counters.promiscuousDelivered = self->rx.promiscuousDelivered;
    counters.beaconRequestsHeard = self->beacon.beaconRequestsHeard;
    counters.beaconReplies = self->beacon.beaconReplies;
    counters.beaconIgnored = self->beacon.beaconIgnored;
    counters.beaconRefused = self->beacon.beaconRefused;
    counters.beaconPendingDropped = self->beacon.beaconPendingDropped;
    counters.beaconsNotified = self->beacon.beaconsNotified;
    counters.beaconsNoPayload = self->beacon.beaconsNoPayload;
    counters.beaconsNotifyDropped = self->beacon.beaconsNotifyDropped;
    counters.beaconsUnreadable = self->beacon.beaconsUnreadable;
    counters.enhancedBeaconsUnbuilt = self->beacon.enhancedBeaconsUnbuilt;
    counters.beaconsPayloadOverflow = self->beacon.beaconsPayloadOverflow;
    counters.associationQueue = self->assoc.associationCount;
    counters.associationsDropped = self->assoc.associationsDropped;
    counters.assocDroppedNotAsked = self->assoc.assocsDroppedNotAsked;
    counters.assocDroppedNotOurs = self->assoc.assocsDroppedNotOurs;
    counters.assocDroppedSource = self->assoc.assocsDroppedSource;
    counters.assocDroppedParent = self->assoc.assocsDroppedParent;
    counters.assocDroppedMalformed = self->assoc.assocsDroppedMalformed;
    counters.assocDroppedAddress = self->assoc.assocsDroppedAddress;
    counters.assocRequestDroppedSource = self->assoc.requestsDroppedSource;
    counters.assocRequestDroppedContent = self->assoc.requestsDroppedContent;
    counters.assocRequestDroppedNotOurs = self->assoc.requestsDroppedNotOurs;
    counters.assocRequestDroppedFast = self->assoc.requestsDroppedFast;
    counters.assocRequestDroppedUnparsable = self->assoc.requestsDroppedUnparsable;
    counters.pollsRequested = self->childPoll.pollsRequested;
    counters.pollsWithData = self->childPoll.pollsWithData;
    counters.pollsNoData = self->childPoll.pollsNoData;
    counters.heardAsleep = self->childPoll.heardAsleep;
    counters.needsRearm = self->needsRearm;

    for (i = 0; i < MAC_TX_TRACK_MAX; i++)
    {
        if ((self->tx.track[i].state == MAC_TX_ANSWERED || self->tx.track[i].state == MAC_TX_TIMED_OUT)
            && self->tx.track[i].confirmOwed)
            counters.confirmQueue++;

        if (self->tx.track[i].state == MAC_TX_OUTSTANDING)
            counters.outstanding++;
    }

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (self->indirect.transactions[i].used)
            counters.transactionQueue++;
    }

    return counters;
}

ZbStatus Mac_SetBeaconConfig(Mac_Mac *self, const Mac_BeaconConfig *config)
{
    if (self == 0)
        return ZB_ERR_BAD_ARGUMENT;

    return MacBeacon_SetConfig(&self->beacon, config);
}
