#include "rcp_radio.h"

#include "spinel.h"
#include "zb_time.h"
#include "zb_utils.h"

/*
 * What band B reads before it writes anything. `NCP_VERSION` first, because it is the only thing
 * that says which dialect the rest of the list means; then the two API levels, which are recorded
 * but not yet acted on (docs/internals/protocol.md §10 question 9); then the capability bitmap, and the
 * RCP's own EUI-64. `CAPS` and `PROTOCOL_VERSION` are part of §6's probe and are not asked here:
 * nothing in band A consumes them yet, and a read nobody uses is a round trip nobody needs. The
 * source-match family's enable bit is read last: a dialect whose table names it may still be a device
 * that refuses it, and D-123 makes the device's own answer the gate.
 */
static const uint32_t discoveryProps[] =
{
    PROP_NCP_VERSION,
    PROP_INTERFACE_TYPE,
    PROP_RCP_API_VERSION,
    PROP_RCP_MIN_HOST_API_VERSION,
    PROP_RADIO_CAPS,
    PROP_HWADDR,
    PROP_MAC_SRC_MATCH_ENABLED
};

/* The §6 flush, and the only octet band B writes that is not a frame. */
static const uint8_t flushFlag = HDLC_FLAG;

static uint32_t radioTrackFind(Rcp_Radio *self, uint8_t tid)
{
    uint32_t i;

    for (i = 0; i < RCP_RADIO_TX_TRACK_MAX; i++)
    {
        if (self->txFilled[i] && !self->txWaiting[i] && self->txTid[i] == tid && !self->txAnswered[i])
            return i;
    }

    return RCP_RADIO_TX_TRACK_MAX;
}

/* A frame's end, whether it reached the wire or not: a frame still in line leaves the line here. */
static void radioTxAnswer(Rcp_Radio *self, uint32_t slot, ZbStatus status)
{
    self->txResult[slot].status = status;
    self->txAnswered[slot] = 1;
    self->txWaiting[slot] = 0;
}

static void radioTrackAbandon(Rcp_Radio *self, ZbStatus status)
{
    uint32_t i;

    for (i = 0; i < RCP_RADIO_TX_TRACK_MAX; i++)
    {
        if (!self->txFilled[i])
            continue;

        radioTxAnswer(self, i, status);
    }
}

static void radioResetSequence(Rcp_Radio *self)
{
    if (self->mode == RCP_RADIO_MODE_RUNNING)
        self->lossOwed = 1;

    self->discoveryIndex = 0;
    self->armIndex = 0;
    self->writeCount = 0;
    Props_SurfaceInit(&self->surface);

    if (self->scanState != RCP_RADIO_SCAN_NONE && self->scanState != RCP_RADIO_SCAN_LEVEL)
        self->scanAbandons++;

    self->scanState = RCP_RADIO_SCAN_NONE;
    self->scanDeadlineMs = 0;
    self->scanRefusal = ZB_OK;
    self->versionLen = 0;

    self->pendingState = RCP_RADIO_PENDING_NONE;
    self->pendingWrittenValid = 0;

    if (self->caps.hasPendingTable)
    {
        self->pendingState = RCP_RADIO_PENDING_ENABLED;
        self->pendingDirty = 1;
    }

    self->rxHead = 0;
    self->rxCount = 0;

    SpinelSession_Abandon(&self->session);
}

static void radioEnterReset(Rcp_Radio *self)
{
    radioResetSequence(self);
    self->mode = RCP_RADIO_MODE_RESET;
}

/*
 * An RCP that announces a reset has thrown away every property this host wrote, so the arm
 * sequence runs again from the top rather than continuing where it was interrupted.
 * Whether the announcement answers the RESET this host sent or arrives on
 * its own does not change what has to happen next, so both go the same way; the distinction is
 * docs/internals/protocol.md §10 question 12 and is recorded by `resetsSeen` rather than by two states.
 */
static void radioHandleReset(Rcp_Radio *self)
{
    self->resetsSeen++;
    radioTrackAbandon(self, ZB_ERR_DEVICE_LOST);
    radioResetSequence(self);

    self->mode = RCP_RADIO_MODE_DISCOVER;
}

static ZbStatus radioSendFlush(Rcp_Radio *self)
{
    uint32_t written = 0;
    ZbStatus status;

    status = Port_Write(&self->port, (const uint8_t *)&flushFlag, 1, &written);

    if (status != ZB_OK || written != 1)
        return ZB_ERR_NO_SPACE;

    return ZB_OK;
}

/* Open the frame this module is composing, positioned after header, command and property id. */
static ZbStatus radioCompose(Rcp_Radio *self, uint8_t command, uint32_t propId, uint32_t nowMs,
                             U_BStream *stream)
{
    ZbStatus status;

    U_bstream_init(stream, self->request, (unsigned long)sizeof self->request);
    status = SpinelSession_Compose(&self->session, command, propId, nowMs, stream);

    return status;
}

/*
 * Frame what has been composed and hand it to the port as one write. A request this host could not
 * put on the wire in whole is abandoned rather than left outstanding with a TID the RCP never
 * saw, because an unanswered TID is a timeout the driver would have to guess the cause of.
 */
static ZbStatus radioFlush(Rcp_Radio *self, U_BStream *stream)
{
    uint32_t payloadLen;
    uint32_t wireLen = 0;
    uint32_t written = 0;
    ZbStatus status;

    payloadLen = Zb_bstream_pos(stream);
    status = Hdlc_Encode(self->request, payloadLen, self->wire, (uint32_t)sizeof self->wire, &wireLen);

    if (status != ZB_OK)
    {
        SpinelSession_Abandon(&self->session);
        return status;
    }

    status = Port_Write(&self->port, self->wire, wireLen, &written);

    if (status != ZB_OK || written != wireLen)
    {
        SpinelSession_Abandon(&self->session);
        return ZB_ERR_NO_SPACE;
    }

    return ZB_OK;
}

/*
 * The octet order across this seam. A `'E'` field is MSB-first on the wire, the order the property table's
 * `PROP_KIND_ADDR_BE` names and the order `HWADDR` answers in (docs/internals/protocol.md §7.2), while `Radio_Pib`'s
 * address fields are LSB-first, because that is what `macExtendedValue` reads: octet i is bits i×8. Spinel's
 * address writers copy octets verbatim, so every extended address crossing in this module is reversed here and
 * nowhere else, in both directions.
 */
static void rcpRadioWriteEui(U_BStream *stream, const uint8_t *octets)
{
    uint32_t index;

    for (index = 0; index < RADIO_ADDR_LEN; index++)
        Spinel_WriteUint8(stream, octets[RADIO_ADDR_LEN - 1 - index]);
}

static void rcpRadioReadEui(const uint8_t *wire, uint8_t *octets)
{
    uint32_t index;

    for (index = 0; index < RADIO_ADDR_LEN; index++)
        octets[index] = wire[RADIO_ADDR_LEN - 1 - index];
}

static ZbStatus radioWriteValue(U_BStream *stream, const Prop_Entry *entry, uint32_t value)
{
    if (entry->kind == PROP_KIND_BOOL)
        Spinel_WriteBool(stream, value != 0);
    else if (entry->kind == PROP_KIND_U8)
        Spinel_WriteUint8(stream, (uint8_t)value);
    else if (entry->kind == PROP_KIND_I8)
        Spinel_WriteInt8(stream, (int8_t)value);
    else if (entry->kind == PROP_KIND_U16_LE)
        Spinel_WriteUint16(stream, (uint16_t)value);
    else if (entry->kind == PROP_KIND_PACKED_U)
        Spinel_WritePackedUint(stream, value);
    else
        return ZB_ERR_UNSUPPORTED;

    if (Spinel_StreamFailed(stream))
        return ZB_ERR_NO_SPACE;

    return ZB_OK;
}

static ZbStatus radioSendSet(Rcp_Radio *self, uint32_t propId, uint32_t value, uint32_t nowMs)
{
    const Prop_Entry *entry = Props_Find(self->dialect, propId);
    U_BStream stream;
    ZbStatus status;

    if (entry == 0)
        return ZB_ERR_UNSUPPORTED;

    status = radioCompose(self, SPINEL_CMD_PROP_VALUE_SET, propId, nowMs, &stream);

    if (status != ZB_OK)
        return status;

    if (value == RCP_RADIO_VALUE_FROM_PIB)
    {
        if (entry->kind != PROP_KIND_ADDR_BE)
        {
            SpinelSession_Abandon(&self->session);
            return ZB_ERR_UNSUPPORTED;
        }

        rcpRadioWriteEui(&stream, self->pib.extendedAddress);
        status = Spinel_StreamFailed(&stream) ? ZB_ERR_NO_SPACE : ZB_OK;
    }
    else
    {
        status = radioWriteValue(&stream, entry, value);
    }

    if (status != ZB_OK)
    {
        SpinelSession_Abandon(&self->session);
        return status;
    }

    return radioFlush(self, &stream);
}

/* The property one owed write of the table goes to (docs/internals/protocol.md §7.4). */
static uint32_t radioPendingStepProp(uint32_t state)
{
    if (state == RCP_RADIO_PENDING_ENABLED)
        return PROP_MAC_SRC_MATCH_ENABLED;

    if (state == RCP_RADIO_PENDING_SHORT)
        return PROP_MAC_SRC_MATCH_SHORT_ADDRESSES;

    return PROP_MAC_SRC_MATCH_EXTENDED_ADDRESSES;
}

static int radioPendingOwesWrite(const Rcp_Radio *self)
{
    return self->pendingDirty && self->pendingState != RCP_RADIO_PENDING_NONE && self->writeCount == 0;
}

/* One of the three writes, in the order the statement is read in. */
static ZbStatus radioSendPendingStep(Rcp_Radio *self, uint32_t nowMs)
{
    U_BStream stream;
    ZbStatus status;
    uint32_t propId;
    uint32_t i;

    propId = radioPendingStepProp(self->pendingState);
    status = radioCompose(self, SPINEL_CMD_PROP_VALUE_SET, propId, nowMs, &stream);

    if (status != ZB_OK)
        return status;

    if (self->pendingState == RCP_RADIO_PENDING_ENABLED)
    {
        Spinel_WriteBool(&stream, self->pendingDesired.isComplete != 0);
    }
    else if (self->pendingState == RCP_RADIO_PENDING_SHORT)
    {
        for (i = 0; i < self->pendingDesired.shortCount; i++)
            Spinel_WriteUint16(&stream, self->pendingDesired.shortAddress[i]);
    }
    else
    {
        for (i = 0; i < self->pendingDesired.extendedCount; i++)
        {
            uint64_t value = self->pendingDesired.extendedAddress[i];
            uint32_t k;

            for (k = 0; k < RADIO_ADDR_LEN; k++)
                Spinel_WriteUint8(&stream, (uint8_t)(value >> ((RADIO_ADDR_LEN - 1 - k) * 8)));
        }
    }

    if (Spinel_StreamFailed(&stream))
    {
        SpinelSession_Abandon(&self->session);
        return ZB_ERR_NO_SPACE;
    }

    return radioFlush(self, &stream);
}

/* Which write of a dwell start a scan state stands for, in the order docs/internals/protocol.md §7.4.1 measured them. */
static uint32_t radioScanStepProp(uint32_t state)
{
    if (state == RCP_RADIO_SCAN_MASK)
        return PROP_MAC_SCAN_MASK;

    if (state == RCP_RADIO_SCAN_PERIOD)
        return PROP_MAC_SCAN_PERIOD;

    return PROP_MAC_SCAN_STATE;
}

/* What the device on this port answered for one id, which is not the same question as what its dialect's
 * table lists (docs/internals/decisions.md D-123). */
static int radioSurfaceState(const Rcp_Radio *self, uint32_t propId)
{
    return Props_SurfaceState(&self->surface, self->dialect, propId);
}

/* The reason a dwell cannot be asked for here at all, as opposed to being asked and waited for: no entry in
 * this dialect's table, or a device that answered `PROP_NOT_FOUND` when the group was asked about. Both halves
 * of the pair answer UNSUPPORTED for it, because "not yet" would send a caller pumping for something that will
 * never arrive. */
static int radioScanHasNoSurface(const Rcp_Radio *self)
{
    if (!Props_Supports(self->dialect, PROP_MAC_SCAN_STATE, PROPS_OP_SET))
        return 1;

    if (self->scanState == RCP_RADIO_SCAN_NOTHERE)
        return 1;

    return radioSurfaceState(self, PROP_MAC_SCAN_STATE) == PROPS_SURFACE_ABSENT;
}

static int radioScanOwesWrite(const Rcp_Radio *self)
{
    return self->scanState == RCP_RADIO_SCAN_MASK
           || self->scanState == RCP_RADIO_SCAN_PERIOD
           || self->scanState == RCP_RADIO_SCAN_START;
}

/*
 * What a refusal of a dwell write means. `PROP_NOT_FOUND` says the RCP has no dwell to ask for at all, and
 * that is remembered so no later ask reaches the port. `INVALID_STATE`, which is what this build answers when
 * `PHY_ENABLED` is 0 (§7.4.1), is reported as a device refusal rather than the `ZB_ERR_NOT_READY` the general
 * status mapping gives it, because "not ready" reads as "ask again in a moment" to a caller that is pumping a
 * dwell, and this is a dwell that will not arrive.
 */
static void radioScanRefused(Rcp_Radio *self, uint32_t statusCode, ZbStatus mapped)
{
    self->scanRefusals++;

    if (statusCode == SPINEL_STATUS_PROP_NOT_FOUND || statusCode == SPINEL_STATUS_UNIMPLEMENTED)
    {
        Props_SurfaceNote(&self->surface, self->dialect, radioScanStepProp(self->scanState), 0);
        self->scanState = RCP_RADIO_SCAN_NOTHERE;
        self->scanRefusal = ZB_ERR_UNSUPPORTED;
    }
    else
    {
        self->scanState = RCP_RADIO_SCAN_REFUSED;

        if (statusCode == SPINEL_STATUS_INVALID_STATE)
            self->scanRefusal = ZB_ERR_DEVICE;
        else
            self->scanRefusal = mapped;
    }

    self->scanDeadlineMs = 0;
    self->lastError = self->scanRefusal;
}

/*
 * The two notifications that end a dwell (§7.4.1): a level for the channel it measured, then the scan state
 * going idle. `+127` in the level is the device's own marker for "nothing usable here", which is the figure the
 * seam names for the same fact, so it crosses unchanged rather than being dressed up as a measurement.
 */
static void radioScanLevel(Rcp_Radio *self, Spinel_Reply *reply)
{
    uint32_t channel;
    int8_t level;

    if (self->scanState != RCP_RADIO_SCAN_DWELL)
        return;

    channel = Spinel_ReadUint8(&reply->values);
    level = Spinel_ReadInt8(&reply->values);

    if (Spinel_StreamFailed(&reply->values))
    {
        self->frameRejects++;
        self->lastError = ZB_ERR_BAD_FRAME;
        return;
    }

    self->scanLevelChannel = channel;
    self->scanLevelDbm = (int32_t)level;
    self->scanState = RCP_RADIO_SCAN_LEVEL;
}

static void radioScanEnd(Rcp_Radio *self, Spinel_Reply *reply)
{
    uint32_t state;

    state = Spinel_ReadUint8(&reply->values);

    if (Spinel_StreamFailed(&reply->values) || state != SPINEL_SCAN_STATE_IDLE)
        return;

    if (self->scanState != RCP_RADIO_SCAN_DWELL)
        return;

    self->scanLevelChannel = self->scanChannel;
    self->scanLevelDbm = RADIO_SCAN_NO_LEVEL;
    self->scanAbandons++;
    self->scanState = RCP_RADIO_SCAN_LEVEL;
}

/* One write of the dwell start. The channel list is a Spinel array (a count then that many channel octets),
   which is why it is composed here and not through the scalar path the other property writes take: §7.4.1
   measured `01 0c` for a dwell on 12, and the RCP echoed those two octets verbatim. */
static ZbStatus radioSendScanStep(Rcp_Radio *self, uint32_t nowMs)
{
    U_BStream stream;
    ZbStatus status;

    status = radioCompose(self, SPINEL_CMD_PROP_VALUE_SET, radioScanStepProp(self->scanState), nowMs, &stream);

    if (status != ZB_OK)
        return status;

    if (self->scanState == RCP_RADIO_SCAN_MASK)
    {
        Spinel_WriteUint8(&stream, 1);
        Spinel_WriteUint8(&stream, (uint8_t)self->scanChannel);
    }
    else if (self->scanState == RCP_RADIO_SCAN_PERIOD)
    {
        Spinel_WriteUint16(&stream, (uint16_t)self->scanDwellUnits);
    }
    else
    {
        Spinel_WriteUint8(&stream, SPINEL_SCAN_STATE_ENERGY);
    }

    if (Spinel_StreamFailed(&stream))
    {
        SpinelSession_Abandon(&self->session);
        return ZB_ERR_NO_SPACE;
    }

    return radioFlush(self, &stream);
}

static ZbStatus radioSendGet(Rcp_Radio *self, uint32_t propId, uint32_t nowMs)
{
    U_BStream stream;
    ZbStatus status;

    status = radioCompose(self, SPINEL_CMD_PROP_VALUE_GET, propId, nowMs, &stream);

    if (status != ZB_OK)
        return status;

    return radioFlush(self, &stream);
}

/*
 * RESET goes out with a TID even though §6 records the harness sending it with TID 0. §5 says a
 * TID-0 command queues no response, and a driver that cannot tell "the RCP is rearming" from
 * "the RCP is silent" has no way to bound either; a TID makes the silence a timeout. The answer
 * measured is an unsolicited notification, which this module handles the same way, and
 * whether a TID-bearing RESET is answered with the same TID is docs/internals/protocol.md §10 question 12.
 */
static ZbStatus radioSendReset(Rcp_Radio *self, uint32_t nowMs)
{
    U_BStream stream;
    ZbStatus status;

    status = radioCompose(self, SPINEL_CMD_RESET, PROP_LAST_STATUS, nowMs, &stream);

    if (status != ZB_OK)
        return status;

    return radioFlush(self, &stream);
}

enum
{
    RCP_RADIO_MD_PHY_LEN = 10,      
    RCP_RADIO_MD_VEND_LEN = 1,      
    RCP_RADIO_MD_MAC_LEN = 5,       
    RCP_RADIO_MD_MAX = RCP_RADIO_MD_PHY_LEN,
    RCP_RADIO_MD_PHY_FIELDS = 2,
    RCP_RADIO_TX_TRAILER_LEN = 16,

    RCP_RADIO_FCS_OCTETS = 2
};

static void radioDeliver(Rcp_Radio *self, const Radio_Frame *frame)
{
    uint32_t slot;

    /* Before the RCP runs, no band A reads the ring, and a full ring would stop the pull short of the answer
       the bring-up waits for: a frame of that time is counted and let go. */
    if (self->mode != RCP_RADIO_MODE_RUNNING)
    {
        self->rxUnarmed++;
        return;
    }

    if (self->rxCount >= RCP_RADIO_RX_QUEUE_MAX)
    {
        self->rxOverflows++;
        return;
    }

    slot = (self->rxHead + self->rxCount) % RCP_RADIO_RX_QUEUE_MAX;
    self->rxQueue[slot] = *frame;
    self->rxCount++;
}

/*
 * The three metadata groups are read in the order §8.1 records them, by length rather than by
 * MD_FLAG: every measured notification carries all three, with MD_VEND and MD_MAC present and
 * zero even when MD_FLAG is zero (docs/internals/protocol.md §8.1). A group whose declared length is not the
 * one the firmware sends is a device this stack does not recognise, and the frame is rejected
 * rather than partially believed.
 */
static void radioReadStreamRaw(Rcp_Radio *self, Spinel_Reply *reply)
{
    U_BStream *values = &reply->values;
    U_BStream mdStream;
    U_BStream ackStream;
    Radio_Frame frame;
    uint8_t mdScratch[RCP_RADIO_MD_MAX];
    const uint8_t *psdu;
    const uint8_t *md;
    uint32_t psduLen = 0;
    uint32_t mdLen = 0;
    uint32_t rxError;
    uint32_t mdFlag;
    uint32_t channel;
    uint32_t ackKeyId;
    uint32_t ackFrameCounter;
    int8_t rssi;
    int8_t noise;

    frame.len = 0;
    frame.rssiDbm = 0;
    frame.lqi = 0;
    frame.deviceStampTicks = 0;
    frame.error = ZB_OK;
    frame.ackedWithFramePending = 0;
    Zb_memset(frame.bytes, 0, RADIO_MPDU_MAX);

    psdu = Spinel_ReadPrefixed(values, &psduLen);

    if (psdu == 0 || Spinel_StreamFailed(values))
    {
        self->frameRejects++;
        self->lastError = ZB_ERR_BAD_FRAME;
        return;
    }

    rssi = Spinel_ReadInt8(values);
    noise = Spinel_ReadInt8(values);
    mdFlag = Spinel_ReadUint16(values);

    md = Spinel_ReadPrefixed(values, &mdLen);

    if (md == 0 || mdLen != RCP_RADIO_MD_PHY_LEN)
    {
        self->frameRejects++;
        self->lastError = ZB_ERR_BAD_FRAME;
        return;
    }

    Zb_memcpy(mdScratch, md, mdLen);
    U_bstream_init(&mdStream, mdScratch, RCP_RADIO_MD_PHY_LEN);
    channel = Spinel_ReadUint8(&mdStream);
    frame.lqi = Spinel_ReadUint8(&mdStream);
    frame.rssiDbm = rssi;

    frame.deviceStampTicks = Spinel_ReadUint64(&mdStream);

    (void)channel;

    if (psduLen > RADIO_MPDU_MAX)
    {
        self->frameRejects++;
        self->lastError = ZB_ERR_NO_SPACE;
        return;
    }

    frame.len = psduLen;

    md = Spinel_ReadPrefixed(values, &mdLen);

    if (md == 0 || mdLen != RCP_RADIO_MD_VEND_LEN)
    {
        self->frameRejects++;
        self->lastError = ZB_ERR_BAD_FRAME;
        return;
    }

    Zb_memcpy(mdScratch, md, mdLen);
    U_bstream_init(&mdStream, mdScratch, mdLen);
    rxError = Spinel_ReadPackedUint(&mdStream);

    md = Spinel_ReadPrefixed(values, &mdLen);

    if (md == 0 || mdLen != RCP_RADIO_MD_MAC_LEN)
    {
        self->frameRejects++;
        self->lastError = ZB_ERR_BAD_FRAME;
        return;
    }

    Zb_memcpy(mdScratch, md, mdLen);
    U_bstream_init(&ackStream, mdScratch, mdLen);
    ackKeyId = Spinel_ReadUint8(&ackStream);
    ackFrameCounter = Spinel_ReadUint32(&ackStream);

    if (Spinel_StreamFailed(&ackStream))
    {
        self->frameRejects++;
        self->lastError = ZB_ERR_BAD_FRAME;
        return;
    }

    if (ackKeyId != 0 || ackFrameCounter != 0)
        self->rxWithAckMetadata++;

    Zb_memcpy(frame.bytes, psdu, frame.len);

    if ((mdFlag & SPINEL_MD_BAD_FCS) != 0)
        frame.error = ZB_ERR_BAD_FRAME;
    else if (rxError != 0)
        frame.error = ZB_ERR_DEVICE;
    else if ((mdFlag & SPINEL_MD_DUPE) != 0)
        frame.error = ZB_ERR_BUSY;

    if ((mdFlag & SPINEL_MD_ACKED_FP) != 0)
    {
        frame.ackedWithFramePending = 1;
        self->rxAckedPending++;
    }

    (void)noise;
    radioDeliver(self, &frame);
}

/* Apply the value a discovery read answered. A dialect is chosen here and nowhere else. */
static void radioApplyDiscovery(Rcp_Radio *self, uint32_t propId, Spinel_Reply *reply)
{
    U_BStream *values = &reply->values;
    const uint8_t *text;
    uint32_t len = 0;

    if (propId == PROP_NCP_VERSION)
    {
        text = Spinel_ReadString(values, &len);

        if (text == 0)
        {
            self->lastError = ZB_ERR_BAD_FRAME;
            return;
        }

        self->versionLen = len > RCP_RADIO_VERSION_MAX ? RCP_RADIO_VERSION_MAX : len;
        Zb_memcpy(self->versionText, text, self->versionLen);
        self->dialect = Props_Detect(text, len);

        if (!Props_Known(self->dialect))
        {
            self->mode = RCP_RADIO_MODE_FAULT;
            self->lastError = ZB_ERR_UNSUPPORTED;
        }

        return;
    }

    if (propId == PROP_INTERFACE_TYPE)
    {
        self->interfaceType = Spinel_ReadUint8(values);
        return;
    }

    if (propId == PROP_RCP_API_VERSION)
    {
        self->apiVersion = Spinel_ReadPackedUint(values);
        return;
    }

    if (propId == PROP_RCP_MIN_HOST_API_VERSION)
    {
        self->minHostApiVersion = Spinel_ReadPackedUint(values);
        return;
    }

    if (propId == PROP_RADIO_CAPS)
    {
        if (Props_DeriveCaps(self->dialect, Spinel_ReadPackedUint(values), &self->caps) != ZB_OK)
        {
            self->mode = RCP_RADIO_MODE_FAULT;
            self->lastError = ZB_ERR_UNSUPPORTED;
        }

        return;
    }

    if (propId == PROP_HWADDR)
    {
        if (Spinel_ReadAddrBe(values, self->hwaddr, RADIO_ADDR_LEN) == 0)
        {
            self->lastError = ZB_ERR_BAD_FRAME;
            return;
        }
    }

    if (propId == PROP_MAC_SRC_MATCH_ENABLED)
    {
        uint32_t deviceEnabled = Spinel_ReadBool(values);

        if (Spinel_StreamFailed(values))
        {
            self->lastError = ZB_ERR_BAD_FRAME;
            return;
        }

        (void)deviceEnabled;
        self->caps.hasPendingTable = 1;
    }

    Props_SurfaceNote(&self->surface, self->dialect, propId, 1);
}

static int radioPropIsArmStep(Rcp_Radio *self, uint32_t propId)
{
    const Prop_Step *steps;
    uint32_t count;
    uint32_t i;

    steps = Props_ArmSteps(self->dialect, &count);

    if (steps == 0)
        return 0;

    for (i = 0; i < count; i++)
    {
        if (steps[i].id == propId)
            return 1;
    }

    return 0;
}

static int radioPropIsDiscovery(uint32_t propId)
{
    uint32_t i;

    for (i = 0; i < (uint32_t)(sizeof discoveryProps / sizeof discoveryProps[0]); i++)
    {
        if (discoveryProps[i] == propId)
            return 1;
    }

    return 0;
}

/*
 * One bring-up write. `PROPS_STEP_RUNTIME` means the value belongs to the PIB, not to the table:
 * today that is the channel and nothing else, because every other arm step is a fixed octet this
 * dialect is known to require.
 */
static ZbStatus radioSendArmStep(Rcp_Radio *self, const Prop_Step *step, uint32_t nowMs)
{
    uint32_t value = step->value;

    if (value == PROPS_STEP_RUNTIME)
    {
        if (!Props_ChannelValid(self->dialect, self->pib.channel))
            return ZB_ERR_BAD_ARGUMENT;

        value = self->pib.channel;
    }

    return radioSendSet(self, step->id, value, nowMs);
}

/* The frame next in line, or the track's size when none waits. */
static uint32_t radioTxNext(const Rcp_Radio *self)
{
    uint32_t next = RCP_RADIO_TX_TRACK_MAX;
    uint32_t i;

    for (i = 0; i < RCP_RADIO_TX_TRACK_MAX; i++)
    {
        if (!self->txFilled[i] || !self->txWaiting[i])
            continue;

        if (next == RCP_RADIO_TX_TRACK_MAX || (int32_t)(self->txOrder[i] - self->txOrder[next]) < 0)
            next = i;
    }

    return next;
}

/*
 * One frame onto the wire. The value is the §8.2 shape, always with the full 16-octet trailer even on a
 * dialect that would accept a shorter one, because the AT86RF233 build answers PARSE_ERROR to a
 * short value and one encoder that fits both is the point of encoding it once. A port with no room keeps the frame in line for a later pump.
 */
static ZbStatus radioTxSend(Rcp_Radio *self, uint32_t slot, uint32_t nowMs)
{
    U_BStream stream;
    uint8_t tid;
    ZbStatus status;

    status = radioCompose(self, SPINEL_CMD_PROP_VALUE_SET, PROP_STREAM_RAW, nowMs, &stream);

    if (status != ZB_OK)
    {
        radioTxAnswer(self, slot, status);
        return ZB_OK;
    }

    Spinel_WritePrefixed(&stream, self->txFrame[slot], self->txFrameLen[slot]);

    Spinel_WriteUint8(&stream, 0);                             
    Spinel_WriteUint8(&stream, self->txMaxBackoffs[slot]);
    Spinel_WriteUint8(&stream, self->txMaxRetries[slot]);
    Spinel_WriteBool(&stream, 1);                              
    Spinel_WriteBool(&stream, 0);                              
    Spinel_WriteBool(&stream, 0);                              
    Spinel_WriteBool(&stream, 0);                              
    Spinel_WriteUint32(&stream, 0);                            
    Spinel_WriteUint32(&stream, 0);                            
    Spinel_WriteUint8(&stream, 0);                             

    if (Spinel_StreamFailed(&stream))
    {
        SpinelSession_Abandon(&self->session);
        radioTxAnswer(self, slot, ZB_ERR_NO_SPACE);
        return ZB_OK;
    }

    tid = SpinelSession_PendingTid(&self->session);
    status = radioFlush(self, &stream);

    if (status == ZB_ERR_NO_SPACE)
        return ZB_OK;

    if (status != ZB_OK)
    {
        radioTxAnswer(self, slot, status);
        return ZB_OK;
    }

    self->txTid[slot] = tid;
    self->txWaiting[slot] = 0;

    return ZB_OK;
}

/* A line that does not move answers what waits in it while band A is still listening, with the word it re-asks on.
   A result band A stopped waiting for is never asked for, so its slot goes back to the track. */
static void radioTxAgeTrack(Rcp_Radio *self, uint32_t nowMs)
{
    uint32_t i;

    for (i = 0; i < RCP_RADIO_TX_TRACK_MAX; i++)
    {
        if (!self->txFilled[i])
            continue;

        if (self->txWaiting[i] && !Zb_timeWithin(nowMs, self->txAskedMs[i], RCP_RADIO_TX_WAIT_MS))
        {
            radioTxAnswer(self, i, ZB_ERR_NO_SPACE);
            self->txWaitsExpired++;
        }
        else if (self->txAnswered[i] && !Zb_timeWithin(nowMs, self->txAskedMs[i], RCP_RADIO_TX_KEEP_MS))
        {
            self->txFilled[i] = 0;
            self->txHandle[i] = RADIO_HANDLE_NONE;
            self->txResultsUncollected++;
        }
    }
}

static ZbStatus radioAdvance(Rcp_Radio *self, uint32_t nowMs)
{
    const Prop_Entry *entry;
    const Prop_Step *steps;
    uint32_t count;
    uint32_t propId;
    uint32_t nextFrame;
    int firstRead;

    if (SpinelSession_Busy(&self->session))
        return ZB_OK;

    if (self->mode == RCP_RADIO_MODE_RESET)
        return radioSendReset(self, nowMs);

    if (self->mode == RCP_RADIO_MODE_DISCOVER)
    {
        count = (uint32_t)(sizeof discoveryProps / sizeof discoveryProps[0]);

        while (self->discoveryIndex < count)
        {
            propId = discoveryProps[self->discoveryIndex];
            firstRead = self->discoveryIndex == 0;
            self->discoveryIndex++;

            if (firstRead || Props_Supports(self->dialect, propId, PROPS_OP_GET))
                return radioSendGet(self, propId, nowMs);
        }

        self->mode = RCP_RADIO_MODE_ARM;
        self->armIndex = 0;
    }

    if (self->mode == RCP_RADIO_MODE_ARM)
    {
        steps = Props_ArmSteps(self->dialect, &count);

        if (steps == 0)
            return ZB_ERR_UNSUPPORTED;

        if (self->armIndex < count)
            return radioSendArmStep(self, &steps[self->armIndex], nowMs);

        self->mode = RCP_RADIO_MODE_RUNNING;
    }

    nextFrame = radioTxNext(self);

    /* A write and a frame leave in the order the seam took them, so a frame never overtakes the address or channel set for it, nor leaves on one set after it. */
    if (self->mode == RCP_RADIO_MODE_RUNNING && self->writeCount > 0
        && (nextFrame == RCP_RADIO_TX_TRACK_MAX || (int32_t)(self->writes[0].order - self->txOrder[nextFrame]) < 0))
    {
        propId = self->writes[0].propId;
        entry = Props_Find(self->dialect, propId);

        if (entry == 0)
        {
            self->writeFailures++;
            self->lastError = ZB_ERR_UNSUPPORTED;
            self->writeCount = 0;
            return ZB_OK;
        }

        return radioSendSet(self, propId, self->writes[0].value, nowMs);
    }

    if (self->mode == RCP_RADIO_MODE_RUNNING && radioPendingOwesWrite(self))
        return radioSendPendingStep(self, nowMs);

    if (self->mode == RCP_RADIO_MODE_RUNNING && nextFrame < RCP_RADIO_TX_TRACK_MAX)
        return radioTxSend(self, nextFrame, nowMs);

    if (self->mode == RCP_RADIO_MODE_RUNNING && radioScanOwesWrite(self))
    {
        if (self->writeCount > 0 || SpinelSession_Busy(&self->session))
            return ZB_OK;

        return radioSendScanStep(self, nowMs);
    }

    if (self->mode == RCP_RADIO_MODE_RUNNING && self->scanState == RCP_RADIO_SCAN_DWELL
            && nowMs >= self->scanDeadlineMs)
    {
        self->scanLevelChannel = self->scanChannel;
        self->scanLevelDbm = RADIO_SCAN_NO_LEVEL;
        self->scanAbandons++;
        self->scanState = RCP_RADIO_SCAN_LEVEL;
    }

    return ZB_OK;
}

/*
 * The bring-up cursor and the queued-write list both move on the same event: an answer that names
 * the property this host wrote. Keeping it in one place is what stops the two paths from drifting
 * into different ideas of what "accepted" means.
 */
static void radioStepAccepted(Rcp_Radio *self, uint32_t askedProp)
{
    uint32_t i;

    Props_SurfaceNote(&self->surface, self->dialect, askedProp, 1);

    if (radioPendingOwesWrite(self) && askedProp == radioPendingStepProp(self->pendingState))
    {
        self->pendingState++;

        if (self->pendingState > RCP_RADIO_PENDING_EXTENDED)
        {
            self->pendingState = RCP_RADIO_PENDING_NONE;
            self->pendingWritten = self->pendingDesired;
            self->pendingWrittenValid = 1;
            self->pendingDirty = 0;
            self->pendingWrites++;
        }

        return;
    }

    if (radioScanOwesWrite(self) && askedProp == radioScanStepProp(self->scanState))
    {
        self->scanState++;

        if (self->scanState == RCP_RADIO_SCAN_DWELL)
        {
            self->scanDwells++;
            self->scanDeadlineMs = self->lastPumpMs
                                   + self->scanDwellUnits * RCP_RADIO_SCAN_MS_PER_UNIT
                                   + RCP_RADIO_SCAN_SLACK_MS;
        }

        return;
    }

    if (self->mode == RCP_RADIO_MODE_ARM)
        self->armIndex++;

    if (self->writeCount > 0 && self->writes[0].propId == askedProp)
    {
        self->writeCount--;

        for (i = 0; i < self->writeCount; i++)
            self->writes[i] = self->writes[i + 1];

        if (self->writeCount == 0)
            self->lastError = ZB_OK;
    }
}

/*
 * A reply to something this host asked for. The pending request is read *before* the frame is
 * absorbed, because absorbing is what ends it: a dispatch that wanted to know what it was answering
 * would otherwise have thrown that away.
 */
/*
 * A tracked transmit was answered. The status band A branches on and the device's own code both come
 * from the reply; what may be said about the acknowledgment is a dialect statement, not an inference
 * from silence. Neither measured build carries ack metadata (docs/internals/hardware.md §4), so the
 * only acknowledgment this kind of radio reports is the outcome of the exchange it ran itself: a frame
 * that asked to be answered and came back OK was answered, and one answered with NO_ACK (code 17,
 * docs/internals/protocol.md §7.3, measured in test/fixtures/loopback_ch26_tx_ackreq_promisc.txt) was not. A frame
 * that asked for nothing is never claimed to have been answered.
 */
static void radioTxComplete(Rcp_Radio *self, uint32_t slot, const Spinel_Reply *reply)
{
    U_BStream tail;
    uint32_t bits = 0;
    int pending;
    int headerUpdated;

    self->txResult[slot].status = reply->status;
    self->txStatusCode[slot] = reply->statusCode;
    self->txResult[slot].isAcked = (self->txAckRequest[slot] && reply->status == ZB_OK) ? 1 : 0;

    if (self->txAckRequest[slot] && reply->statusCode == SPINEL_STATUS_NO_ACK)
        self->txResult[slot].status = ZB_ERR_NO_ACK;

    if (reply->statusCode == SPINEL_STATUS_CCA_FAILURE)
        self->txResult[slot].status = ZB_ERR_CHANNEL_ACCESS_FAILURE;

    tail = reply->values;

    if (Spinel_Remaining(&tail) >= 2)
    {
        pending = Spinel_ReadBool(&tail);
        headerUpdated = Spinel_ReadBool(&tail);

        if (!Spinel_StreamFailed(&tail))
        {
            bits = RCP_RADIO_TAIL_REPORTED;

            if (pending)
                bits |= RCP_RADIO_TAIL_PENDING;

            if (headerUpdated)
                bits |= RCP_RADIO_TAIL_HEADER_UPDATED;
        }
    }

    self->lastCompletionTail = bits;
    self->txResult[slot].framePendingReported = self->txResult[slot].isAcked && (bits & RCP_RADIO_TAIL_REPORTED);
    self->txResult[slot].framePending = self->txResult[slot].framePendingReported && (bits & RCP_RADIO_TAIL_PENDING);
    self->txAnswered[slot] = 1;
}

static void radioDispatch(Rcp_Radio *self, uint32_t frameLen, uint32_t nowMs)
{
    Spinel_Reply reply;
    uint32_t askedProp;
    uint32_t slot;
    uint8_t askedTid;
    uint8_t askedCommand;
    Spinel_Outcome outcome;

    askedTid = SpinelSession_PendingTid(&self->session);
    askedProp = SpinelSession_PendingProp(&self->session);
    askedCommand = SpinelSession_PendingCommand(&self->session);
    outcome = SpinelSession_Absorb(&self->session, self->frame, frameLen, nowMs, &reply);

    if (outcome == SPINEL_OUTCOME_MALFORMED)
    {
        self->frameRejects++;
        self->lastError = ZB_ERR_BAD_FRAME;
        return;
    }

    if (reply.propId == PROP_LAST_STATUS && SpinelSession_IsResetStatus(reply.statusCode))
    {
        radioHandleReset(self);
        return;
    }

    if (reply.propId == PROP_STREAM_RAW)
    {
        radioReadStreamRaw(self, &reply);
        return;
    }

    if (reply.propId == PROP_MAC_ENERGY_SCAN_RESULT)
    {
        radioScanLevel(self, &reply);
        return;
    }

    if (reply.propId == PROP_MAC_SCAN_STATE && outcome == SPINEL_OUTCOME_NOTIFY)
    {
        radioScanEnd(self, &reply);
        return;
    }

    if (outcome != SPINEL_OUTCOME_REPLY)
        return;

    if (reply.propId == PROP_LAST_STATUS)
    {
        slot = radioTrackFind(self, askedTid);

        if (slot < RCP_RADIO_TX_TRACK_MAX)
        {
            radioTxComplete(self, slot, &reply);
            return;
        }

        if (radioPropIsDiscovery(askedProp) && askedCommand == SPINEL_CMD_PROP_VALUE_GET)
        {
            if (reply.statusCode == SPINEL_STATUS_PROP_NOT_FOUND)
            {
                Props_SurfaceNote(&self->surface, self->dialect, askedProp, 0);

                if (askedProp == PROP_MAC_SRC_MATCH_ENABLED)
                    self->caps.hasPendingTable = 0;
            }

            self->lastError = reply.status;
            return;
        }

        if (reply.statusCode == SPINEL_STATUS_OK)
        {
            radioStepAccepted(self, askedProp);
            return;
        }

        if (radioScanOwesWrite(self) && askedProp == radioScanStepProp(self->scanState))
        {
            radioScanRefused(self, reply.statusCode, reply.status);
            return;
        }

        if (radioPendingOwesWrite(self) && askedProp == radioPendingStepProp(self->pendingState))
        {
            self->pendingRefusals++;
            self->pendingState = RCP_RADIO_PENDING_NONE;
            self->pendingWrittenValid = 0;
            self->pendingDirty = 0;
            self->lastError = reply.status;

            if (reply.statusCode == SPINEL_STATUS_PROP_NOT_FOUND)
                self->caps.hasPendingTable = 0;

            return;
        }

        self->writeFailures++;
        self->lastError = reply.status;

        if (self->mode != RCP_RADIO_MODE_RUNNING)
            self->mode = RCP_RADIO_MODE_FAULT;

        return;
    }

    if (radioPropIsDiscovery(askedProp) && askedCommand == SPINEL_CMD_PROP_VALUE_GET && reply.propId == askedProp)
    {
        radioApplyDiscovery(self, askedProp, &reply);
        return;
    }

    slot = radioTrackFind(self, askedTid);

    if (slot < RCP_RADIO_TX_TRACK_MAX)
    {
        radioTxComplete(self, slot, &reply);
        return;
    }

    if (reply.propId == askedProp)
    {
        radioStepAccepted(self, askedProp);
        return;
    }

    self->writeFailures++;
    self->lastError = ZB_ERR_DEVICE;
}

static ZbStatus radioPull(Rcp_Radio *self, uint32_t nowMs)
{
    uint32_t got = 0;
    uint32_t i;
    ZbStatus status;

    for (;;)
    {
        if (self->rxCount + RCP_RADIO_CHUNK_FRAMES_MAX > RCP_RADIO_RX_QUEUE_MAX)
            return ZB_OK;

        status = Port_Read(&self->port, self->chunk, (uint32_t)sizeof self->chunk, &got);

        if (status != ZB_OK)
            return status;

        if (got == 0)
            return ZB_OK;

        for (i = 0; i < got; i++)
        {
            if (Hdlc_Feed(&self->decoder, self->chunk[i], self->frame, &self->frameLen) == HDLC_EVENT_FRAME)
                radioDispatch(self, self->frameLen, nowMs);
        }
    }
}
#define PIB_FIELD_COUNT 11

/* The order band B walks the PIB in: a transmit's own fields come from here, so a PIB change that
   arrives out of order still produces the same writes in the same order. */
static const uint32_t pibOrder[PIB_FIELD_COUNT] =
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

typedef struct PibJudgement
{
    uint32_t field;
    uint32_t propId;      
    uint32_t value;       
    ZbStatus status;
} Pib_Judgement;

static uint32_t pibFieldValue(const Radio_Pib *pib, uint32_t field)
{
    if (field == RADIO_PIB_CHANNEL)
        return pib->channel;

    if (field == RADIO_PIB_PAN_ID)
        return pib->panId;

    if (field == RADIO_PIB_SHORT_ADDRESS)
        return pib->shortAddress;

    if (field == RADIO_PIB_RX_ON_WHEN_IDLE)
        return (uint32_t)(pib->rxOnWhenIdle ? 1 : 0);

    if (field == RADIO_PIB_MAX_CSMA_BACKOFFS)
        return pib->maxCsmaBackoffs;

    if (field == RADIO_PIB_MAX_FRAME_RETRIES)
        return pib->maxFrameRetries;

    if (field == RADIO_PIB_ACK_WAIT_MS)
        return pib->ackWaitMs;

    if (field == RADIO_PIB_PAGE)
        return pib->page;

    if (field == RADIO_PIB_CCA_THRESHOLD_DBM)
        return (uint32_t)pib->ccaThresholdDbm;

    return 0;
}

static void pibStore(Rcp_Radio *self, const Radio_Pib *pib, uint32_t field)
{
    if (field == RADIO_PIB_CHANNEL)
        self->pib.channel = pib->channel;
    else if (field == RADIO_PIB_PAGE)
        self->pib.page = pib->page;
    else if (field == RADIO_PIB_PAN_ID)
        self->pib.panId = pib->panId;
    else if (field == RADIO_PIB_SHORT_ADDRESS)
        self->pib.shortAddress = pib->shortAddress;
    else if (field == RADIO_PIB_EXTENDED_ADDRESS)
        Zb_memcpy(self->pib.extendedAddress, pib->extendedAddress, RADIO_ADDR_LEN);
    else if (field == RADIO_PIB_RX_ON_WHEN_IDLE)
        self->pib.rxOnWhenIdle = pib->rxOnWhenIdle ? 1 : 0;
    else if (field == RADIO_PIB_MAX_CSMA_BACKOFFS)
        self->pib.maxCsmaBackoffs = pib->maxCsmaBackoffs;
    else if (field == RADIO_PIB_CCA_THRESHOLD_DBM)
        self->pib.ccaThresholdDbm = pib->ccaThresholdDbm;
}

/*
 * One PIB field: what it takes, and how it reaches the device. Three answers exist and the difference
 * between them is the point. A field a *property* carries is judged by the dialect's table: its
 * shape, its range, whether the table offers a write at all. A field the §8.2 trailer carries needs
 * no property and is range-checked against the octet it goes into. A field neither carries is
 * refused: `ackWaitMs` is the one, and how long band A waits for an acknowledgment is band A's
 * decision, not a value band B can put on this wire.
 *
 * Before the dialect is known the table does not exist yet. The channel is still accepted, because
 * the bring-up sequence writes it from the PIB anyway (§6) and a driver that could not name a channel
 * before arming could never arm at all; the number is judged against the 2.4 GHz O-QPSK PHY's own
 * numbering rather than a table.
 */
static ZbStatus pibJudge(Rcp_Radio *self, uint32_t field, uint32_t value, Pib_Judgement *out)
{
    Prop_Entry entry;
    int32_t lo;
    int32_t hi;
    ZbStatus status;

    out->field = field;
    out->propId = 0;
    out->value = 0;
    out->status = ZB_OK;

    if (field == RADIO_PIB_PAGE)
        return out->status = (value == 0) ? ZB_OK : ZB_ERR_UNSUPPORTED;

    if (field == RADIO_PIB_HW_ADDRESS)
        return out->status = ZB_ERR_UNSUPPORTED;

    if (field == RADIO_PIB_MAX_CSMA_BACKOFFS || field == RADIO_PIB_MAX_FRAME_RETRIES)
        return out->status = (value <= 255) ? ZB_OK : ZB_ERR_BAD_ARGUMENT;

    if (field == RADIO_PIB_CHANNEL)
    {
        if (!Props_Known(self->dialect))
        {
            if (value < PROPS_CHANNEL_MIN || value > PROPS_CHANNEL_MAX)
                return out->status = ZB_ERR_BAD_ARGUMENT;

            return ZB_OK;
        }

        if (!Props_ChannelValid(self->dialect, value))
            return out->status = ZB_ERR_BAD_ARGUMENT;

        if (self->mode != RCP_RADIO_MODE_RUNNING && radioPropIsArmStep(self, PROP_PHY_CHAN))
            return ZB_OK;
    }

    status = Props_ForPib(self->dialect, field, &entry);

    if (status != ZB_OK)
        return out->status = ZB_ERR_UNSUPPORTED;

    if (!Props_Supports(self->dialect, entry.id, PROPS_OP_SET))
        return out->status = ZB_ERR_UNSUPPORTED;

    status = Props_KindRange(entry.kind, &lo, &hi);

    if (status == ZB_OK && ((int32_t)value < lo || (int32_t)value > hi))
        return out->status = ZB_ERR_BAD_ARGUMENT;

    out->propId = entry.id;
    out->value = entry.kind == PROP_KIND_ADDR_BE ? RCP_RADIO_VALUE_FROM_PIB : value;
    return ZB_OK;
}

static ZbStatus radioOpPibSet(Radio_Radio *radio, const Radio_Pib *pib)
{
    Rcp_Radio *self = (Rcp_Radio *)radio->provider;
    Pib_Judgement judged[PIB_FIELD_COUNT];
    uint32_t field;
    uint32_t writes = 0;
    uint32_t judgedCount = 0;
    uint32_t i;

    if (pib == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->mode == RCP_RADIO_MODE_CLOSED || self->mode == RCP_RADIO_MODE_FAULT)
        return ZB_ERR_NOT_OPEN;

    for (i = 0; i < PIB_FIELD_COUNT; i++)
    {
        field = pibOrder[i];

        if ((pib->present & field) == 0)
            continue;

        judged[judgedCount].status = pibJudge(self, field, pibFieldValue(pib, field), &judged[judgedCount]);

        if (judged[judgedCount].status != ZB_OK)
        {
            self->lastError = judged[judgedCount].status;
            return judged[judgedCount].status;
        }

        if (judged[judgedCount].propId != 0)
            writes++;

        judgedCount++;
    }

    if (writes > RCP_RADIO_WRITE_QUEUE_MAX - self->writeCount)
    {
        self->lastError = ZB_ERR_NO_SPACE;
        return ZB_ERR_NO_SPACE;
    }

    for (i = 0; i < judgedCount; i++)
    {
        pibStore(self, pib, judged[i].field);

        if (judged[i].propId == 0)
            continue;

        self->writes[self->writeCount].propId = judged[i].propId;
        self->writes[self->writeCount].value = judged[i].value;
        self->writes[self->writeCount].order = self->orderNext;
        self->writeCount++;
    }

    self->orderNext++;
    self->pib.present |= pib->present;
    self->lastError = ZB_OK;
    return ZB_OK;
}

/* What band B holds, reported present. No frame retry count is among it: each transmit carries its own, so a
   count reported here would be one no frame uses, and band A would adopt it in place of its own default. */
static ZbStatus radioOpPibGet(Radio_Radio *radio, Radio_Pib *pib)
{
    Rcp_Radio *self = (Rcp_Radio *)radio->provider;

    if (pib == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->mode == RCP_RADIO_MODE_CLOSED || self->mode == RCP_RADIO_MODE_RESET
            || self->mode == RCP_RADIO_MODE_DISCOVER)
        return ZB_ERR_NOT_READY;

    *pib = self->pib;
    pib->present = RADIO_PIB_PAGE | RADIO_PIB_CHANNEL | RADIO_PIB_PAN_ID | RADIO_PIB_SHORT_ADDRESS
                   | RADIO_PIB_MAX_CSMA_BACKOFFS;

    if ((self->pib.present & RADIO_PIB_EXTENDED_ADDRESS) != 0)
        pib->present |= RADIO_PIB_EXTENDED_ADDRESS;

    if (radioSurfaceState(self, PROP_HWADDR) == PROPS_SURFACE_KNOWN)
    {
        rcpRadioReadEui(self->hwaddr, pib->hwAddress);
        pib->present |= RADIO_PIB_HW_ADDRESS;
    }

    if (Props_Supports(self->dialect, PROP_MAC_RX_ON_WHEN_IDLE, PROPS_OP_GET))
    {
        pib->present |= RADIO_PIB_RX_ON_WHEN_IDLE;
        pib->rxOnWhenIdle = self->pib.rxOnWhenIdle;
    }

    if (Props_Supports(self->dialect, PROP_PHY_CCA_THRESHOLD, PROPS_OP_SET)
            && (self->pib.present & RADIO_PIB_CCA_THRESHOLD_DBM) != 0)
    {
        pib->present |= RADIO_PIB_CCA_THRESHOLD_DBM;
        pib->ccaThresholdDbm = self->pib.ccaThresholdDbm;
    }

    return ZB_OK;
}

/*
 * Delivery selection as measured: `MAC_PROMISCUOUS_MODE` full or off, which are
 * the two values §6 puts on the wire. The identity a *filtered* RCP would filter to does not
 * belong in a filter at all: §6 sets it with `MAC_15_4_LADDR`, `MAC_15_4_SADDR` and
 * `MAC_15_4_PANID`, and those are pibSet's business, so a filter that carries identity is refused
 * instead of writing the same property twice from two places.
 *
 * Promiscuous is not inert. An RCP in that mode still acknowledges frames addressed to its own
 * short address (§6), which is why band B opens with no short address and no PAN id at all and hands
 * the choice to band A: an RCP that ACKs everything it hears is not a sniffer.
 */
static ZbStatus radioOpFilter(Radio_Radio *radio, const Radio_Filter *filter)
{
    Rcp_Radio *self = (Rcp_Radio *)radio->provider;
    uint32_t value;

    if (filter == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (filter->panId != 0 || filter->shortAddress != 0 || filter->extendedAddress[0] != 0)
        return ZB_ERR_UNSUPPORTED;

    if (self->mode == RCP_RADIO_MODE_CLOSED || self->mode == RCP_RADIO_MODE_FAULT)
        return ZB_ERR_NOT_OPEN;

    if (!Props_Supports(self->dialect, PROP_MAC_PROMISCUOUS_MODE, PROPS_OP_SET))
        return ZB_ERR_UNSUPPORTED;

    if (self->writeCount >= RCP_RADIO_WRITE_QUEUE_MAX)
        return ZB_ERR_NO_SPACE;

    value = filter->isPromiscuous ? PROPS_PROMISCUOUS_FULL : PROPS_PROMISCUOUS_OFF;
    self->writes[self->writeCount].propId = PROP_MAC_PROMISCUOUS_MODE;
    self->writes[self->writeCount].value = value;
    self->writes[self->writeCount].order = self->orderNext++;
    self->writeCount++;
    return ZB_OK;
}
/*
 * A transmit, taken into the track. The RCP carries one request at a time and a frame can spend tens of
 * milliseconds on the air, so waiting for it is this module's work and not band A's: a frame stays in line
 * until the wire is free, and only a full track refuses (docs/internals/protocol.md §7.3).
 *
 * The frame arrives complete, footer included (radio.h), and this module neither computes a footer
 * nor invents one: it forwards the footer to a radio that reports its frames as carrying one, and
 * takes it off for a radio that computes its own. Which of the two applies is a dialect fact read
 * from the device, never a choice (docs/internals/protocol.md §8.2, §9.3). The backoff octet was range-checked
 * by pibSet and the retry octet is the caller's per-frame count, bounded below, so neither truncates.
 */
static ZbStatus radioOpTx(Radio_Radio *radio, const uint8_t *mpdu, uint32_t len, int ackRequest,
                          uint32_t maxFrameRetries, Radio_Handle *outHandle)
{
    Rcp_Radio *self = (Rcp_Radio *)radio->provider;
    uint32_t slot;
    uint32_t psduLen;

    if (mpdu == 0 || outHandle == 0 || maxFrameRetries > RADIO_MAX_FRAME_RETRIES)
        return ZB_ERR_BAD_ARGUMENT;

    if (len == 0 || len > RADIO_MPDU_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->mode != RCP_RADIO_MODE_RUNNING)
        return ZB_ERR_NOT_READY;

    if (!self->caps.psduIncludesFcs && len <= RCP_RADIO_FCS_OCTETS)
        return ZB_ERR_BAD_ARGUMENT;

    if (!Props_Supports(self->dialect, PROP_STREAM_RAW, PROPS_OP_SET))
        return ZB_ERR_UNSUPPORTED;

    for (slot = 0; slot < RCP_RADIO_TX_TRACK_MAX; slot++)
    {
        if (!self->txFilled[slot])
            break;
    }

    if (slot >= RCP_RADIO_TX_TRACK_MAX)
        return ZB_ERR_NO_SPACE;

    psduLen = self->caps.psduIncludesFcs ? len : len - RCP_RADIO_FCS_OCTETS;

    Zb_memcpy(self->txFrame[slot], mpdu, psduLen);
    self->txFrameLen[slot] = (uint8_t)psduLen;
    self->txMaxBackoffs[slot] = (uint8_t)self->pib.maxCsmaBackoffs;
    self->txMaxRetries[slot] = (uint8_t)maxFrameRetries;
    self->txOrder[slot] = self->orderNext++;
    self->txAskedMs[slot] = self->lastPumpMs;
    self->txWaiting[slot] = 1;

    self->txFilled[slot] = 1;
    self->txAnswered[slot] = 0;
    self->txAckRequest[slot] = ackRequest ? 1 : 0;
    self->txHandle[slot] = self->nextHandle;
    self->txResult[slot].status = ZB_ERR_NOT_READY;
    self->txResult[slot].isAcked = 0;
    self->txResult[slot].retries = 0;
    self->txResult[slot].framePendingReported = 0;
    self->txResult[slot].framePending = 0;
    self->txStatusCode[slot] = SPINEL_STATUS_FAILURE;
    *outHandle = self->nextHandle;

    self->nextHandle = self->nextHandle + 1;

    if (self->nextHandle == 0)
        self->nextHandle = 1;

    (void)radioAdvance(self, self->lastPumpMs);

    return ZB_OK;
}

/*
 * The code travels with the handle and not inside the seam's Radio_TxResult: what a device called a
 * failure is a fact about that device's dialect, while band A has one status to branch on
 * (docs/internals/coding-rules.md §4.6).
 */
ZbStatus RcpRadio_TxStatusCode(const Rcp_Radio *self, Radio_Handle handle, uint32_t *outCode)
{
    uint32_t slot;

    if (self == 0 || outCode == 0 || handle == RADIO_HANDLE_NONE)
        return ZB_ERR_BAD_ARGUMENT;

    for (slot = 0; slot < RCP_RADIO_TX_TRACK_MAX; slot++)
    {
        if (self->txFilled[slot] && self->txHandle[slot] == handle)
            break;
    }

    if (slot >= RCP_RADIO_TX_TRACK_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (!self->txAnswered[slot])
        return ZB_ERR_NOT_READY;

    *outCode = self->txStatusCode[slot];

    return ZB_OK;
}

static ZbStatus radioOpCompletion(Radio_Radio *radio, Radio_Handle handle, Radio_TxResult *outResult)
{
    Rcp_Radio *self = (Rcp_Radio *)radio->provider;
    uint32_t slot;

    if (outResult == 0 || handle == RADIO_HANDLE_NONE)
        return ZB_ERR_BAD_ARGUMENT;

    for (slot = 0; slot < RCP_RADIO_TX_TRACK_MAX; slot++)
    {
        if (self->txFilled[slot] && self->txHandle[slot] == handle)
            break;
    }

    if (slot >= RCP_RADIO_TX_TRACK_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (!self->txAnswered[slot])
        return ZB_ERR_NOT_READY;

    *outResult = self->txResult[slot];
    self->txFilled[slot] = 0;
    self->txHandle[slot] = RADIO_HANDLE_NONE;
    return ZB_OK;
}

static uint32_t radioOpRxPoll(Radio_Radio *radio, Radio_Frame *outFrames, uint32_t maxFrames)
{
    Rcp_Radio *self = (Rcp_Radio *)radio->provider;
    uint32_t taken;
    uint32_t i;

    if (outFrames == 0 || maxFrames == 0)
        return 0;

    if (maxFrames > RADIO_FRAME_BATCH_MAX)
        maxFrames = RADIO_FRAME_BATCH_MAX;

    taken = self->rxCount < maxFrames ? self->rxCount : maxFrames;

    for (i = 0; i < taken; i++)
    {
        outFrames[i] = self->rxQueue[self->rxHead];
        self->rxHead = (self->rxHead + 1) % RCP_RADIO_RX_QUEUE_MAX;
    }

    self->rxCount -= taken;
    return taken;
}

static int radioOpIsLost(Radio_Radio *radio)
{
    Rcp_Radio *self = (Rcp_Radio *)radio->provider;

    if (self->mode == RCP_RADIO_MODE_FAULT)
        return 1;

    if (Port_Fault(&self->port) != PORT_FAULT_NONE)
        return 1;

    if (!self->lossOwed)
        return 0;

    if (self->mode == RCP_RADIO_MODE_RUNNING)
        self->lossOwed = 0;

    return 1;
}

/*
 * Ask for one dwell on one channel and return without waiting for it (D-124). Three writes start it (the channel
 * list, the period, and the state that puts the dwell on the air) in the order §7.4.1 measured them, one per
 * pump, and its answer comes later as a notification this module routes like every other. The refusals are named
 * apart because a caller has to react to them differently (D-123): a dialect whose table names no scan group is
 * something this host does not have; a device that answered `PROP_NOT_FOUND` when the group was asked about is
 * something this RCP does not have, and that is remembered so a later ask never reaches the port; and a
 * capability bitmap that says "can" is still not a licence to ask. A dwell already outstanding is refused here
 * rather than sent to a device that was measured refusing a second start while one ran (§7.4.1), and a period
 * this RCP would clamp is refused rather than clamped for it.
 */
static ZbStatus radioOpScanStart(Radio_Radio *radio, uint32_t channel, uint32_t dwellUnits)
{
    Rcp_Radio *self = (Rcp_Radio *)radio->provider;

    if (self->mode != RCP_RADIO_MODE_RUNNING)
        return ZB_ERR_NOT_READY;

    if (!Props_ChannelValid(self->dialect, channel))
        return ZB_ERR_BAD_ARGUMENT;

    if (dwellUnits < RADIO_SCAN_DWELL_MIN || dwellUnits > RCP_RADIO_SCAN_PERIOD_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (radioScanHasNoSurface(self))
        return ZB_ERR_UNSUPPORTED;

    if (self->scanState != RCP_RADIO_SCAN_NONE)
        return ZB_ERR_BUSY;

    self->scanState = RCP_RADIO_SCAN_MASK;
    self->scanChannel = channel;
    self->scanDwellUnits = dwellUnits;
    self->scanDeadlineMs = 0;
    self->scanRefusal = ZB_OK;
    self->scanLevelChannel = 0;
    self->scanLevelDbm = RADIO_SCAN_NO_LEVEL;
    return ZB_OK;
}

/*
 * What the dwell said, at a later call: `ZB_ERR_NOT_READY` while it runs; `ZB_OK` with the channel and the level
 * the device reported; `ZB_OK` carrying the device's own nothing-was-measured figure for a dwell that ended
 * without reporting or that band B stopped asking about; and the status the device used when it refused. A
 * report is collected once, like a transmit result.
 */
static ZbStatus radioOpScanCollect(Radio_Radio *radio, uint32_t *outChannel, int32_t *outDbm)
{
    Rcp_Radio *self = (Rcp_Radio *)radio->provider;
    ZbStatus status;

    if (outChannel == 0 || outDbm == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (radioScanHasNoSurface(self))
        return ZB_ERR_UNSUPPORTED;

    if (self->scanState != RCP_RADIO_SCAN_LEVEL && self->scanState != RCP_RADIO_SCAN_REFUSED)
        return ZB_ERR_NOT_READY;

    if (self->scanState == RCP_RADIO_SCAN_REFUSED)
    {
        status = self->scanRefusal;
        *outChannel = 0;
        *outDbm = RADIO_SCAN_NO_LEVEL;
    }
    else
    {
        status = ZB_OK;
        *outChannel = self->scanLevelChannel;
        *outDbm = self->scanLevelDbm;
    }

    self->scanState = RCP_RADIO_SCAN_NONE;
    self->scanRefusal = ZB_OK;
    self->scanDeadlineMs = 0;
    self->lastError = status;
    return status;
}

/* 10.22.3's table, stated to a radio that puts the bit on the air itself: queued, never waited for, and only
   written when band A says the queue moved. */
static ZbStatus radioOpPendingTable(Radio_Radio *radio, const Radio_Pending *pending)
{
    Rcp_Radio *self = (Rcp_Radio *)radio->provider;

    if (pending == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->mode == RCP_RADIO_MODE_CLOSED || self->mode == RCP_RADIO_MODE_FAULT)
        return ZB_ERR_NOT_OPEN;

    if (self->caps.hasPendingTable == 0)
        return ZB_ERR_UNSUPPORTED;

    if (pending->shortCount > RADIO_PENDING_MAX || pending->extendedCount > RADIO_PENDING_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    /* Band A states the table after every completed transmit, and three writes would hold up the next transmit. */
    if (self->pendingWrittenValid && !self->pendingDirty
        && Zb_memcmp(&self->pendingWritten, pending, (uint32_t)sizeof *pending) == 0)
        return ZB_OK;

    self->pendingDesired = *pending;
    self->pendingState = RCP_RADIO_PENDING_ENABLED;
    self->pendingDirty = 1;
    return ZB_OK;
}

static ZbStatus radioOpCaps(Radio_Radio *radio, Radio_Caps *outCaps)
{
    Rcp_Radio *self = (Rcp_Radio *)radio->provider;

    if (outCaps == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->mode == RCP_RADIO_MODE_CLOSED || self->mode == RCP_RADIO_MODE_RESET
            || self->mode == RCP_RADIO_MODE_DISCOVER)
        return ZB_ERR_NOT_READY;

    *outCaps = self->caps;
    return ZB_OK;
}

static const Radio_Ops rcpRadioOps =
{
    radioOpCaps,
    radioOpPibSet,
    radioOpPibGet,
    radioOpFilter,
    radioOpTx,
    radioOpCompletion,
    radioOpRxPoll,
    radioOpIsLost,
    radioOpScanStart,
    radioOpScanCollect
    , radioOpPendingTable
};
/*
 * The teardown writes of §6 in the order that order matters, each one sent without waiting for its
 * answer: the sequence is what the firmware cares about, and a close that blocked on three replies
 * from a link it is about to hang up on would be a close that can hang.
 */
static void radioSendTeardown(Rcp_Radio *self)
{
    const Prop_Step *steps;
    uint32_t count;
    uint32_t i;

    steps = Props_TeardownSteps(self->dialect, &count);

    if (steps == 0)
        return;

    for (i = 0; i < count; i++)
    {
        if (radioSendSet(self, steps[i].id, steps[i].value, self->lastPumpMs) != ZB_OK)
        {
            self->writeFailures++;
            continue;
        }

        SpinelSession_Abandon(&self->session);
    }
}

ZbStatus RcpRadio_Init(Rcp_Radio *self, const PortDeviceOps *ops, uint32_t replyTimeoutMs)
{
    if (self == 0 || ops == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(self, 0, (uint32_t)sizeof *self);
    Port_Init(&self->port, ops);
    Hdlc_Init(&self->decoder);
    SpinelSession_Init(&self->session, replyTimeoutMs);

    self->mode = RCP_RADIO_MODE_CLOSED;
    self->dialect = PROPS_DIALECT_UNKNOWN;
    self->nextHandle = 1;
    self->lastError = ZB_OK;

    self->pib.panId = 0xffff;
    self->pib.shortAddress = 0xffff;
    self->pib.present = 0;

    self->ops = &rcpRadioOps;
    self->seam.ops = self->ops;
    self->seam.provider = self;
    return ZB_OK;
}

ZbStatus RcpRadio_Open(Rcp_Radio *self, const char *path, const PortConfig *config)
{
    if (self == 0 || path == 0 || config == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->mode != RCP_RADIO_MODE_CLOSED)
        return ZB_ERR_BUSY;

    if (Port_Open(&self->port, path, config) != ZB_OK)
    {
        self->lastError = ZB_ERR_NO_DEVICE;
        return ZB_ERR_NO_DEVICE;
    }

    radioResetSequence(self);
    self->mode = RCP_RADIO_MODE_RESET;
    self->lastError = radioSendFlush(self);
    return ZB_OK;
}

void RcpRadio_Close(Rcp_Radio *self)
{
    if (self == 0)
        return;

    if (Port_IsOpen(&self->port))
        radioSendTeardown(self);

    Port_Close(&self->port);
    radioResetSequence(self);
    self->mode = RCP_RADIO_MODE_CLOSED;
    self->lossOwed = 0;
}

ZbStatus RcpRadio_Pump(Rcp_Radio *self, uint32_t nowMs)
{
    ZbStatus notable = ZB_OK;
    ZbStatus status;

    if (self == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->mode == RCP_RADIO_MODE_CLOSED)
        return ZB_ERR_NOT_OPEN;

    self->pumps++;
    self->lastPumpMs = nowMs;

    if (Port_Fault(&self->port) != PORT_FAULT_NONE)
    {
        self->mode = RCP_RADIO_MODE_FAULT;
        self->lastError = ZB_ERR_DEVICE_LOST;
        return ZB_ERR_DEVICE_LOST;
    }

    status = radioPull(self, nowMs);

    if (status != ZB_OK)
    {
        self->mode = RCP_RADIO_MODE_FAULT;
        self->lastError = status;
        return status;
    }

    status = SpinelSession_Expires(&self->session, nowMs);

    if (status == ZB_ERR_TIMEOUT)
    {
        radioTrackAbandon(self, ZB_ERR_TIMEOUT);
        radioEnterReset(self);
        self->lastError = ZB_ERR_TIMEOUT;
        notable = ZB_ERR_TIMEOUT;
    }

    radioTxAgeTrack(self, nowMs);

    status = radioAdvance(self, nowMs);

    if (status != ZB_OK)
    {
        self->lastError = status;

        if (status == ZB_ERR_UNSUPPORTED || status == ZB_ERR_BAD_ARGUMENT || status == ZB_ERR_INTERNAL)
            self->mode = RCP_RADIO_MODE_FAULT;

        if (notable == ZB_OK)
            notable = status;
    }

    return notable;
}

ZbStatus RcpRadio_Restart(Rcp_Radio *self, uint32_t nowMs)
{
    if (self == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->mode == RCP_RADIO_MODE_CLOSED)
        return ZB_ERR_NOT_OPEN;

    radioTrackAbandon(self, ZB_ERR_DEVICE_LOST);
    radioEnterReset(self);
    self->lastError = radioSendFlush(self);
    self->lastPumpMs = nowMs;
    return self->lastError;
}

ZbStatus RcpRadio_Reopen(Rcp_Radio *self, const PortConfig *config)
{
    if (self == 0 || config == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->mode == RCP_RADIO_MODE_CLOSED)
        return ZB_ERR_NOT_OPEN;

    radioTrackAbandon(self, ZB_ERR_DEVICE_LOST);
    Port_Close(&self->port);
    radioResetSequence(self);
    self->lossOwed = 1;
    self->mode = RCP_RADIO_MODE_FAULT;

    if (Port_Open(&self->port, self->port.path, config) != ZB_OK)
    {
        self->lastError = ZB_ERR_NO_DEVICE;
        return ZB_ERR_NO_DEVICE;
    }

    self->mode = RCP_RADIO_MODE_RESET;
    self->lastError = radioSendFlush(self);
    return ZB_OK;
}

Rcp_RadioMode RcpRadio_Mode(const Rcp_Radio *self)
{
    return self ? self->mode : RCP_RADIO_MODE_CLOSED;
}

Props_Dialect RcpRadio_Dialect(const Rcp_Radio *self)
{
    return self ? self->dialect : PROPS_DIALECT_UNKNOWN;
}

ZbStatus RcpRadio_LastError(const Rcp_Radio *self)
{
    return self ? self->lastError : ZB_ERR_BAD_ARGUMENT;
}

const uint8_t *RcpRadio_Address(const Rcp_Radio *self)
{
    if (self == 0 || radioSurfaceState(self, PROP_HWADDR) != PROPS_SURFACE_KNOWN)
        return 0;

    return self->hwaddr;
}

int RcpRadio_SurfaceState(const Rcp_Radio *self, uint32_t propId)
{
    if (self == 0)
        return PROPS_SURFACE_UNKNOWN;

    return radioSurfaceState(self, propId);
}

uint32_t RcpRadio_VersionText(const Rcp_Radio *self, uint8_t *out, uint32_t cap)
{
    uint32_t len;

    if (self == 0 || out == 0)
        return 0;

    len = self->versionLen < cap ? self->versionLen : cap;
    Zb_memcpy(out, self->versionText, len);
    return len;
}

uint32_t RcpRadio_WriteFailures(const Rcp_Radio *self)
{
    return self ? self->writeFailures : 0;
}

uint32_t RcpRadio_FrameRejects(const Rcp_Radio *self)
{
    return self ? self->frameRejects : 0;
}

uint32_t RcpRadio_ScanState(const Rcp_Radio *self)
{
    return self == 0 ? RCP_RADIO_SCAN_NONE : self->scanState;
}

uint32_t RcpRadio_ScanDwells(const Rcp_Radio *self)
{
    return self == 0 ? 0 : self->scanDwells;
}

uint32_t RcpRadio_ScanAbandons(const Rcp_Radio *self)
{
    return self == 0 ? 0 : self->scanAbandons;
}

uint32_t RcpRadio_RxWithAckMetadata(const Rcp_Radio *self)
{
    return self == 0 ? 0 : self->rxWithAckMetadata;
}

uint32_t RcpRadio_RxAckedPending(const Rcp_Radio *self)
{
    return self == 0 ? 0 : self->rxAckedPending;
}

uint32_t RcpRadio_PendingState(const Rcp_Radio *self)
{
    return self == 0 ? RCP_RADIO_PENDING_NONE : self->pendingState;
}

uint32_t RcpRadio_PendingWrites(const Rcp_Radio *self)
{
    return self == 0 ? 0 : self->pendingWrites;
}

uint32_t RcpRadio_PendingRefusals(const Rcp_Radio *self)
{
    return self == 0 ? 0 : self->pendingRefusals;
}

int RcpRadio_PendingWritten(const Rcp_Radio *self, Radio_Pending *out)
{
    if (self == 0 || out == 0 || !self->pendingWrittenValid)
        return 0;

    *out = self->pendingWritten;
    return 1;
}

uint32_t RcpRadio_ScanRefusals(const Rcp_Radio *self)
{
    return self == 0 ? 0 : self->scanRefusals;
}

uint32_t RcpRadio_CompletionTail(const Rcp_Radio *self)
{
    return self == 0 ? 0 : self->lastCompletionTail;
}

uint32_t RcpRadio_ResetsSeen(const Rcp_Radio *self)
{
    return self ? self->resetsSeen : 0;
}

uint32_t RcpRadio_LinkDrops(const Rcp_Radio *self)
{
    return self ? Hdlc_Drops(&self->decoder) : 0;
}

uint32_t RcpRadio_PortDrops(const Rcp_Radio *self)
{
    return self ? Port_Drops(&self->port) : 0;
}

uint32_t RcpRadio_RxQueued(const Rcp_Radio *self)
{
    return self ? self->rxCount : 0;
}

uint32_t RcpRadio_RxOverflows(const Rcp_Radio *self)
{
    return self ? self->rxOverflows : 0;
}

void RcpRadio_Transactions(const Rcp_Radio *self, uint32_t *outRequests, uint32_t *outReplies,
                           uint32_t *outNotifications, uint32_t *outStale, uint32_t *outTimeouts,
                           uint32_t *outMalformed)
{
    if (self == 0)
        return;

    if (outRequests != 0)
        *outRequests = self->session.requests;

    if (outReplies != 0)
        *outReplies = self->session.replies;

    if (outNotifications != 0)
        *outNotifications = self->session.notifications;

    if (outStale != 0)
        *outStale = self->session.stale;

    if (outTimeouts != 0)
        *outTimeouts = self->session.timeouts;

    if (outMalformed != 0)
        *outMalformed = self->session.malformed;
}

Radio_Radio *RcpRadio_Seam(Rcp_Radio *self)
{
    if (self == 0)
        return 0;

    return &self->seam;
}
