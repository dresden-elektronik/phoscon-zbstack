#include "mac.h"

#include "mac_scan.h"

#include "zb_bstream.h"
#include "zb_time.h"
#include "zb_utils.h"

/* M2024: 6.4.1, 6.4.1.2, 6.6.2, 7.5.2, 7.5.4, 8.2.8.2, 8.2.8.3, 10.18, 10.19, 10.20.1, 10.20.2.1, 10.20.3.1,
   10.20.4.2, 10.20.4.3 ok (the ED scan's levels in dBm, the active scan under the 2006 edition's broadcast PAN, the
   orphan scan, MLME-ORPHAN); 10.20.4's MLME-COMM-STATUS after a realignment deferred (nothing above reads it). */

enum
{
    MAC_SCAN_STATUS_SUCCESS = 0x00,
    MAC_SCAN_STATUS_CHANNEL_ACCESS_FAILURE = 0xe1,
    MAC_SCAN_STATUS_NO_BEACON = 0xea
};

/* The dwell ScanDuration's symbol periods make on the host's clock, rounded up to a whole millisecond. */
static uint32_t macScanDwellMs(uint32_t symbols)
{
    return (symbols * (uint32_t)MAC_SYMBOL_US + 999) / 1000;
}

/* The lowest channel the mask still names, taken off it; 0 when none is left. */
static uint32_t macScanNextChannel(Mac_Scan *scan)
{
    uint32_t channel;

    for (channel = MAC_SCAN_CHANNEL_FIRST; channel <= MAC_SCAN_CHANNEL_LAST; channel++)
    {
        if ((scan->channelsLeft & ((uint32_t)1 << channel)) == 0)
            continue;

        scan->channelsLeft &= ~((uint32_t)1 << channel);

        return channel;
    }

    return 0;
}

/* The next channel to tune to, or to measure with the whole of ScanDuration still owed, or the restore once every
   channel was visited. */
static void macScanAdvance(Mac_Scan *scan, uint32_t nowMs)
{
    int energy = scan->scanType == (uint32_t)MAC_SCAN_ENERGY;

    scan->channel = macScanNextChannel(scan);
    scan->state = scan->channel == 0 ? MAC_SCAN_RESTORING : energy ? MAC_SCAN_MEASURING : MAC_SCAN_TUNING;
    scan->stateMs = nowMs;
    scan->energyUnitsLeft = scan->dwellMs;
    scan->energyAsked = 0;
    scan->energyMeasured = 0;
}

/* A channel the scan could not ask on is reported unscanned and the scan goes on. */
static void macScanSkip(Mac_Scan *scan, uint32_t nowMs)
{
    scan->unscanned |= (uint32_t)1 << scan->channel;
    macScanAdvance(scan, nowMs);
}

/* Whether a refusal is the want of room the scan waits out, and it is still inside the hold. */
static int macScanWaits(const Mac_Scan *scan, ZbStatus status, uint32_t nowMs)
{
    return (status == ZB_ERR_BUSY || status == ZB_ERR_NO_SPACE)
           && Zb_timeWithin(nowMs, scan->stateMs, MAC_SCAN_HOLD_MS);
}

/* A scan type `Mac_ScanType` does not name, a channel outside page 0's 11 to 26, or a dwell past a Zigbee discovery's
   longest is an argument error; one scan at a time. */
ZbStatus MacScan_Start(Mac_Scan *scan, Mac_Mac *self, const Mac_ScanRequestParameters *req, uint32_t nowMs)
{
    const Radio_Pib *pib = Mac_Pib(self);
    uint32_t valid = 0;
    uint32_t channel;

    if (scan->state != MAC_SCAN_IDLE)
        return ZB_ERR_BAD_STATE;

    for (channel = MAC_SCAN_CHANNEL_FIRST; channel <= MAC_SCAN_CHANNEL_LAST; channel++)
        valid |= (uint32_t)1 << channel;

    if ((req->scanType != (uint32_t)MAC_SCAN_ENERGY && req->scanType != (uint32_t)MAC_SCAN_ACTIVE
         && req->scanType != (uint32_t)MAC_SCAN_ORPHAN)
        || (req->scanChannels & valid) == 0
        || (req->scanChannels & ~valid) != 0 || req->scanDuration > (uint32_t)MAC_SCAN_SYMBOLS_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(&scan->confirm, 0, (uint32_t)sizeof scan->confirm);

    scan->scanType = req->scanType;
    scan->channelsLeft = req->scanChannels;
    scan->unscanned = 0;
    scan->dwellMs = req->scanType == (uint32_t)MAC_SCAN_ORPHAN ? (uint32_t)MAC_RESPONSE_WAIT_MS
                                                                : macScanDwellMs(req->scanDuration);
    scan->savedPanId = (pib->present & RADIO_PIB_PAN_ID) != 0 ? pib->panId : MAC_FRAME_PAN_BROADCAST;
    scan->savedChannelKnown = (pib->present & RADIO_PIB_CHANNEL) != 0;
    scan->savedChannel = pib->channel;
    scan->requestSent = 0;
    scan->beaconsAtStart = self->beacon.beaconsHeard;
    scan->handleValid = 0;
    scan->confirmReady = 0;
    self->beacon.scanning = 1;

    macScanAdvance(scan, nowMs);

    return ZB_OK;
}

/* The channel, and with the first one the broadcast PAN, written before the Beacon Request goes out on it. */
static void macScanTune(Mac_Scan *scan, Mac_Mac *self, uint32_t nowMs)
{
    Radio_Pib pib;
    ZbStatus status;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_CHANNEL | RADIO_PIB_PAGE | RADIO_PIB_PAN_ID;
    pib.channel = scan->channel;
    pib.page = 0;
    pib.panId = MAC_FRAME_PAN_BROADCAST;

    status = Mac_SetPib(self, &pib);

    if (status == ZB_OK)
    {
        scan->state = MAC_SCAN_ASKING;
        scan->stateMs = nowMs;
        return;
    }

    if (!macScanWaits(scan, status, nowMs))
        macScanSkip(scan, nowMs);
}

/* The Beacon Request, or an orphan scan's Orphan Notification from this device's extended address, this module's own
   frame: it owes the layer above no confirm. */
static void macScanAsk(Mac_Scan *scan, Mac_Mac *self, Mac_Tx *tx, uint32_t nowMs)
{
    Mac_DataRequestParameters req;
    Radio_Handle handle = RADIO_HANDLE_NONE;
    Mac_Track *slot;
    ZbStatus status;
    int orphan = scan->scanType == (uint32_t)MAC_SCAN_ORPHAN;

    scan->requestBytes[0] = orphan ? MAC_CMD_ORPHAN_NOTIFICATION : MAC_CMD_BEACON_REQUEST;

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.frameType = MAC_FRAME_TYPE_COMMAND;
    req.destAddrMode = MAC_ADDR_SHORT;
    req.srcAddrMode = orphan ? MAC_ADDR_EXTENDED : MAC_ADDR_NONE;
    req.destPan = MAC_FRAME_PAN_BROADCAST;
    req.destShort = MAC_FRAME_ADDR_BROADCAST;
    req.payload = scan->requestBytes;
    req.payloadLen = 1;

    status = Mac_DataRequest(self, &req, nowMs, &handle);

    if (status != ZB_OK)
    {
        if (!macScanWaits(scan, status, nowMs))
            macScanSkip(scan, nowMs);

        return;
    }

    slot = MacTx_TrackNamed(tx, handle, 1);

    if (slot != 0)
        slot->confirmOwed = 0;

    scan->handle = handle;
    scan->handleValid = 1;
    scan->state = MAC_SCAN_SENT;
    scan->stateMs = nowMs;
}

/* The receiver listens from the request's successful transmission (the 2006 edition's active scan); a request the
   channel's CCA refused leaves the channel unscanned. */
static void macScanSent(Mac_Scan *scan, Mac_Tx *tx, uint32_t nowMs)
{
    Mac_Track *slot;
    int sent;

    slot = MacTx_TrackNamed(tx, scan->handle, scan->handleValid);

    if (slot == 0)
    {
        scan->handleValid = 0;
        macScanSkip(scan, nowMs);
        return;
    }

    if (!MacTx_TrackAnswered(slot))
        return;

    sent = slot->state == MAC_TX_ANSWERED && slot->status == ZB_OK;
    MacTx_TrackRelease(slot);
    scan->handleValid = 0;

    if (!sent)
    {
        macScanSkip(scan, nowMs);
        return;
    }

    scan->requestSent = 1;
    scan->state = MAC_SCAN_LISTENING;
    scan->stateMs = nowMs;
}

/* An ED scan's channel done: its peak kept, or the channel unscanned when no dwell measured it. */
static void macScanEnergyChannelDone(Mac_Scan *scan, uint32_t nowMs)
{
    if (scan->energyMeasured)
        scan->confirm.energyDbm[scan->channel - MAC_SCAN_CHANNEL_FIRST] = (int8_t)scan->energyPeak;
    else
        scan->unscanned |= (uint32_t)1 << scan->channel;

    macScanAdvance(scan, nowMs);
}

/* The repeated measurement as the radio's dwells: ScanDuration's milliseconds asked as that many of the radio's units,
   one dwell at most the bound it states, so a duration past it takes several; a radio with no dwell refuses each. */
static void macScanMeasure(Mac_Scan *scan, Mac_Mac *self, uint32_t nowMs)
{
    uint32_t asked = scan->energyUnitsLeft;
    ZbStatus status;

    if (asked > (uint32_t)RADIO_SCAN_DWELL_MAX)
        asked = RADIO_SCAN_DWELL_MAX;

    if (asked < (uint32_t)RADIO_SCAN_DWELL_MIN)
        asked = RADIO_SCAN_DWELL_MIN;

    status = self->radio->ops->scanStart(self->radio, scan->channel, asked);

    if (status == ZB_OK)
    {
        scan->energyAsked = asked;
        scan->state = MAC_SCAN_COLLECTING;
        scan->stateMs = nowMs;
        return;
    }

    if (!macScanWaits(scan, status, nowMs))
        macScanEnergyChannelDone(scan, nowMs);
}

/* A dwell's level, or the radio's word that it measured nothing, which is no level and never a floor. */
static void macScanCollect(Mac_Scan *scan, Mac_Mac *self, uint32_t nowMs)
{
    uint32_t channel = 0;
    int32_t dbm = RADIO_SCAN_NO_LEVEL;
    ZbStatus status;

    status = self->radio->ops->scanCollect(self->radio, &channel, &dbm);

    if (status == ZB_ERR_NOT_READY)
        return;

    if (status == ZB_OK && dbm != RADIO_SCAN_NO_LEVEL && channel == scan->channel)
    {
        if (!scan->energyMeasured || dbm > scan->energyPeak)
            scan->energyPeak = dbm;

        scan->energyMeasured = 1;
    }

    scan->energyUnitsLeft = scan->energyUnitsLeft > scan->energyAsked ? scan->energyUnitsLeft - scan->energyAsked : 0;

    if (status != ZB_OK || scan->energyUnitsLeft == 0)
    {
        macScanEnergyChannelDone(scan, nowMs);
        return;
    }

    scan->state = MAC_SCAN_MEASURING;
    scan->stateMs = nowMs;
}

/* An ED scan ends with no channel or PAN to put back, since a dwell never moved the radio's: SUCCESS, the channels no
   dwell measured unscanned. */
static void macScanEnergyFinish(Mac_Scan *scan, Mac_Mac *self, uint32_t nowMs)
{
    scan->confirm.scanType = scan->scanType;
    scan->confirm.unscannedChannels = scan->unscanned;
    scan->confirm.status = MAC_SCAN_STATUS_SUCCESS;
    scan->confirmReady = 1;
    scan->state = MAC_SCAN_IDLE;
    scan->stateMs = nowMs;
    self->beacon.scanning = 0;
}

/* ScanDuration's dwell on the channel, then the next one; a realignment ends the dwell and the scan at once. */
static void macScanListen(Mac_Scan *scan, uint32_t nowMs)
{
    if (scan->confirm.realigned || Zb_timeReached(nowMs, scan->stateMs + scan->dwellMs))
        macScanAdvance(scan, nowMs);
}

/* The channel and PAN the scan began with, written back, or the PAN, channel and short address a realignment named;
   then the confirm. */
static void macScanRestore(Mac_Scan *scan, Mac_Mac *self, uint32_t nowMs)
{
    Radio_Pib pib;
    uint32_t heard;
    ZbStatus status;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_PAN_ID;
    pib.panId = scan->savedPanId;

    if (scan->savedChannelKnown)
    {
        pib.present |= RADIO_PIB_CHANNEL | RADIO_PIB_PAGE;
        pib.channel = scan->savedChannel;
        pib.page = 0;
    }

    if (scan->confirm.realigned)
    {
        pib.present = RADIO_PIB_PAN_ID | RADIO_PIB_CHANNEL | RADIO_PIB_PAGE | RADIO_PIB_SHORT_ADDRESS;
        pib.panId = scan->confirm.panId;
        pib.channel = scan->confirm.channel;
        pib.page = 0;
        pib.shortAddress = scan->confirm.shortAddress;
    }

    status = Mac_SetPib(self, &pib);

    if (status != ZB_OK && (status == ZB_ERR_BUSY || status == ZB_ERR_NO_SPACE))
        return;

    heard = self->beacon.beaconsHeard - scan->beaconsAtStart;

    scan->confirm.scanType = scan->scanType;
    scan->confirm.unscannedChannels = scan->unscanned;
    scan->confirm.beaconsHeard = heard;

    if (heard != 0 || scan->confirm.realigned)
        scan->confirm.status = MAC_SCAN_STATUS_SUCCESS;
    else if (scan->requestSent)
        scan->confirm.status = MAC_SCAN_STATUS_NO_BEACON;
    else
        scan->confirm.status = MAC_SCAN_STATUS_CHANNEL_ACCESS_FAILURE;

    scan->confirmReady = 1;
    scan->state = MAC_SCAN_IDLE;
    scan->stateMs = nowMs;
    self->beacon.scanning = 0;
}

/* The end of a scan: an ED scan's confirm, or the restore an active or orphan scan owes first. */
static void macScanEnd(Mac_Scan *scan, Mac_Mac *self, uint32_t nowMs)
{
    if (scan->scanType == (uint32_t)MAC_SCAN_ENERGY)
    {
        macScanEnergyFinish(scan, self, nowMs);
        return;
    }

    macScanRestore(scan, self, nowMs);
}

void MacScan_Progress(Mac_Scan *scan, Mac_Mac *self, Mac_Tx *tx, uint32_t nowMs)
{
    switch (scan->state)
    {
        case MAC_SCAN_TUNING:
            macScanTune(scan, self, nowMs);
            return;

        case MAC_SCAN_ASKING:
            macScanAsk(scan, self, tx, nowMs);
            return;

        case MAC_SCAN_SENT:
            macScanSent(scan, tx, nowMs);
            return;

        case MAC_SCAN_LISTENING:
            macScanListen(scan, nowMs);
            return;

        case MAC_SCAN_RESTORING:
            macScanEnd(scan, self, nowMs);
            return;

        case MAC_SCAN_MEASURING:
            macScanMeasure(scan, self, nowMs);
            return;

        case MAC_SCAN_COLLECTING:
            macScanCollect(scan, self, nowMs);
            return;

        case MAC_SCAN_IDLE:
        default:
            return;
    }
}

int MacScan_Admits(Mac_Scan *scan, const Radio_Frame *frame)
{
    uint32_t wanted;

    if (scan->state == MAC_SCAN_IDLE || frame->len == 0)
        return 1;

    if (scan->scanType == (uint32_t)MAC_SCAN_ENERGY)
    {
        scan->framesDiscarded++;
        return 0;
    }

    wanted = scan->scanType == (uint32_t)MAC_SCAN_ORPHAN ? MAC_FRAME_TYPE_COMMAND : MAC_FRAME_TYPE_BEACON;

    if ((frame->bytes[0] & 0x07) == wanted)
        return 1;

    scan->framesDiscarded++;

    return 0;
}

int MacScan_OrphanRunning(const Mac_Scan *scan)
{
    return scan->state != MAC_SCAN_IDLE && scan->scanType == (uint32_t)MAC_SCAN_ORPHAN;
}

int MacScan_ActiveRunning(const Mac_Scan *scan)
{
    return scan->state != MAC_SCAN_IDLE && scan->scanType == (uint32_t)MAC_SCAN_ACTIVE;
}

/* 10.20.2.1: a Coordinator Realignment from a coordinator's extended address, directed to this device, ends the scan
   on the channel it was heard on; the first-level filter has already judged the destination. */
void MacScan_TakeOrphanFrame(Mac_Scan *scan, const Mac_Frame *header, const uint8_t *payload, uint32_t payloadLen)
{
    U_BStream stream;

    if (scan->confirm.realigned || header->frameType != MAC_FRAME_TYPE_COMMAND || payload == 0
        || payloadLen < MAC_REALIGNMENT_OCTETS || payload[0] != MAC_CMD_COORDINATOR_REALIGNMENT
        || header->destAddrMode != MAC_ADDR_EXTENDED || header->srcAddrMode != MAC_ADDR_EXTENDED)
    {
        scan->framesDiscarded++;
        return;
    }

    Zb_bstream_init_const(&stream, payload, payloadLen);
    U_bstream_advance(&stream, 1);
    scan->confirm.realigned = 1;
    scan->confirm.panId = U_bstream_get_u16_le(&stream);
    scan->confirm.coordShort = U_bstream_get_u16_le(&stream);
    scan->confirm.channel = U_bstream_get_u8(&stream);
    scan->confirm.shortAddress = U_bstream_get_u16_le(&stream);
    scan->confirm.coordExtended = header->srcExtended;

    scan->channelsLeft = 0;
}

int MacScan_TakeOrphanNotification(Mac_Scan *scan, const Mac_Frame *header, const uint8_t *payload,
                                   uint32_t payloadLen, int beaconAnswers)
{
    if (header->frameType != MAC_FRAME_TYPE_COMMAND || payload == 0 || payloadLen != MAC_CMD_FRAME_OCTETS
        || payload[0] != MAC_CMD_ORPHAN_NOTIFICATION)
        return 0;

    if (!beaconAnswers || header->srcAddrMode != MAC_ADDR_EXTENDED || header->srcExtended == 0)
        return 0;

    if (scan->orphanCount >= MAC_ORPHAN_MAX)
    {
        scan->orphansDropped++;
        return 1;
    }

    scan->orphans[(scan->orphanHead + scan->orphanCount) % MAC_ORPHAN_MAX].orphanAddress = header->srcExtended;
    scan->orphanCount++;

    return 1;
}

uint32_t MacScan_PollOrphans(Mac_Scan *scan, Mac_OrphanIndication *out, uint32_t max)
{
    uint32_t taken = 0;

    while (taken < max && scan->orphanCount > 0)
    {
        out[taken] = scan->orphans[scan->orphanHead];
        scan->orphanHead = (scan->orphanHead + 1) % MAC_ORPHAN_MAX;
        scan->orphanCount--;
        taken++;
    }

    return taken;
}

/* 7.5.4's realignment to a member: this device's PAN, short address and channel, and the orphan's short address,
   from this device's extended address to the orphan's on the broadcast PAN; it owes the layer above no confirm. */
ZbStatus MacScan_Respond(Mac_Scan *scan, Mac_Mac *self, Mac_Tx *tx, const Mac_OrphanResponseParameters *response,
                         uint32_t nowMs)
{
    const Radio_Pib *pib = Mac_Pib(self);
    Mac_DataRequestParameters req;
    U_BStream stream;
    Radio_Handle handle = RADIO_HANDLE_NONE;
    Mac_Track *slot;
    ZbStatus status;

    if (!response->associatedMember)
        return ZB_OK;

    if (!self->beacon.beaconAnswers || response->orphanAddress == 0)
        return ZB_ERR_BAD_STATE;

    U_bstream_init(&stream, scan->realignBytes, MAC_REALIGNMENT_OCTETS);
    U_bstream_put_u8(&stream, MAC_CMD_COORDINATOR_REALIGNMENT);
    U_bstream_put_u16_le(&stream, pib->panId);
    U_bstream_put_u16_le(&stream, pib->shortAddress);
    U_bstream_put_u8(&stream, (uint8_t)pib->channel);
    U_bstream_put_u16_le(&stream, response->shortAddress);

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.frameType = MAC_FRAME_TYPE_COMMAND;
    req.destAddrMode = MAC_ADDR_EXTENDED;
    req.destPan = MAC_FRAME_PAN_BROADCAST;
    req.destExtended = response->orphanAddress;
    req.srcAddrMode = MAC_ADDR_EXTENDED;
    req.ackRequest = 1;
    req.payload = scan->realignBytes;
    req.payloadLen = MAC_REALIGNMENT_OCTETS;

    status = Mac_DataRequest(self, &req, nowMs, &handle);

    if (status != ZB_OK)
        return status;

    slot = MacTx_TrackNamed(tx, handle, 1);

    if (slot != 0)
        slot->confirmOwed = 0;

    scan->realignmentsSent++;

    return ZB_OK;
}

int MacScan_Running(const Mac_Scan *scan)
{
    return scan->state != MAC_SCAN_IDLE;
}

uint32_t MacScan_PollConfirm(Mac_Scan *scan, Mac_ScanConfirmParameters *out)
{
    if (!scan->confirmReady)
        return 0;

    *out = scan->confirm;
    scan->confirmReady = 0;

    return 1;
}
