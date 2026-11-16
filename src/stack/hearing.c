#include "hearing.h"

#include "mac_frame.h"
#include "nwk_frame.h"
#include "security.h"
#include "zb_utils.h"

#define HEARING_UNHEARD_FLAG ((Radio_Handle)1 << 31)    /* a band B never issues this many handles in a bench run */

enum
{
    HEARING_AUX_CONTROL_OCTETS = 1,
    HEARING_AUX_COUNTER_OCTETS = 4,
    HEARING_IEEE_OCTETS = 8
};

static Hearing_Ignored *hearingOfIeee(Hearing *self, uint64_t ieee)
{
    uint32_t i;

    for (i = 0; i < self->ignoredCount; i++)
    {
        if (self->ignored[i].ieee != 0 && self->ignored[i].ieee == ieee)
            return &self->ignored[i];
    }

    return 0;
}

static Hearing_Ignored *hearingOfShort(Hearing *self, uint16_t shortAddress)
{
    uint32_t i;

    for (i = 0; i < self->ignoredCount; i++)
    {
        if (self->ignored[i].shortKnown && self->ignored[i].shortAddress == shortAddress)
            return &self->ignored[i];
    }

    return 0;
}

/* The extended address of the hop behind a NWK-secured frame, or 0: 4.3.2's auxiliary header is in the clear, and
   every hop secures the frame anew, so it names whoever sent this copy and not who originated it. */
static uint64_t hearingHopIeee(const uint8_t *npdu, uint32_t npduLen)
{
    Nwk_Frame frame;
    uint32_t offset = 0;
    uint32_t payloadLen = 0;
    uint64_t ieee = 0;
    uint32_t i;

    if (NwkFrame_Parse(npdu, npduLen, &frame, &offset, &payloadLen) != ZB_OK || !frame.securityEnabled)
        return 0;

    if (offset + HEARING_AUX_CONTROL_OCTETS + HEARING_AUX_COUNTER_OCTETS + HEARING_IEEE_OCTETS > npduLen)
        return 0;

    if (((npdu[offset] >> SECURITY_CONTROL_EXTENDED_NONCE_SHIFT) & SECURITY_CONTROL_EXTENDED_NONCE_MASK) == 0)
        return 0;

    offset += HEARING_AUX_CONTROL_OCTETS + HEARING_AUX_COUNTER_OCTETS;

    for (i = 0; i < HEARING_IEEE_OCTETS; i++)
        ieee |= (uint64_t)npdu[offset + i] << (8 * i);

    return ieee;
}

/* Whether this frame's last hop is ignored, its short address learned when the auxiliary header is what says so. */
static int hearingDropsFrame(Hearing *self, const Radio_Frame *frame, int hasFcs)
{
    Mac_Frame header;
    Mac_FrameRefusal refusal;
    Hearing_Ignored *entry;
    const uint8_t *payload = 0;
    uint32_t payloadLen = 0;

    if (frame->error != ZB_OK
        || MacFrame_Parse(frame->bytes, frame->len, hasFcs, &header, &payload, &payloadLen, &refusal) != ZB_OK)
        return 0;

    if (header.srcAddrMode == MAC_ADDR_EXTENDED)
        return hearingOfIeee(self, header.srcExtended) != 0;

    if (header.srcAddrMode != MAC_ADDR_SHORT)
        return 0;

    if (hearingOfShort(self, header.srcShort) != 0)
        return 1;

    if (header.frameType != MAC_FRAME_TYPE_DATA || payload == 0)
        return 0;

    entry = hearingOfIeee(self, hearingHopIeee(payload, payloadLen));

    if (entry == 0)
        return 0;

    entry->shortAddress = header.srcShort;
    entry->shortKnown = 1;

    return 1;
}

static uint32_t hearingRxPoll(Radio_Radio *radio, Radio_Frame *outFrames, uint32_t maxFrames)
{
    Hearing *self = (Hearing *)radio->provider;
    Radio_Caps caps;
    uint32_t got;
    uint32_t kept = 0;
    uint32_t i;

    got = self->backend->ops->rxPoll(self->backend, outFrames, maxFrames);

    if (got == 0)
        return 0;

    Zb_memset(&caps, 0, (uint32_t)sizeof caps);
    (void)self->backend->ops->caps(self->backend, &caps);

    for (i = 0; i < got; i++)
    {
        int drops = hearingDropsFrame(self, &outFrames[i], caps.psduIncludesFcs);

        if (self->observe != 0)
            self->observe(outFrames[i].bytes, outFrames[i].len, 0, drops, ZB_OK);

        if (drops)
        {
            self->framesDropped++;
            continue;
        }

        if (kept != i)
            outFrames[kept] = outFrames[i];

        kept++;
    }

    return kept;
}

static int hearingCutsUnicast(Hearing *self, const uint8_t *mpdu, uint32_t len)
{
    Mac_Frame header;
    Mac_FrameRefusal refusal;
    const uint8_t *payload = 0;
    uint32_t payloadLen = 0;

    if (MacFrame_Parse(mpdu, len, 0, &header, &payload, &payloadLen, &refusal) != ZB_OK)
        return 0;

    if (header.destAddrMode == MAC_ADDR_EXTENDED)
        return hearingOfIeee(self, header.destExtended) != 0;

    return header.destAddrMode == MAC_ADDR_SHORT && hearingOfShort(self, header.destShort) != 0;
}

static ZbStatus hearingTx(Radio_Radio *radio, const uint8_t *mpdu, uint32_t len, int ackRequest,
                          uint32_t maxFrameRetries, Radio_Handle *outHandle)
{
    Hearing *self = (Hearing *)radio->provider;
    int cuts = ackRequest && hearingCutsUnicast(self, mpdu, len);
    uint32_t i;

    if (!cuts)
    {
        ZbStatus status = self->backend->ops->tx(self->backend, mpdu, len, ackRequest, maxFrameRetries, outHandle);

        if (self->observe != 0)
            self->observe(mpdu, len, 1, 0, status);

        return status;
    }

    if (self->observe != 0)
        self->observe(mpdu, len, 1, 1, ZB_OK);

    for (i = 0; i < HEARING_UNHEARD_MAX; i++)
    {
        if (self->unheard[i] != RADIO_HANDLE_NONE)
            continue;

        self->nextUnheard = (self->nextUnheard + 1) & ~HEARING_UNHEARD_FLAG;
        self->unheard[i] = self->nextUnheard | HEARING_UNHEARD_FLAG;
        *outHandle = self->unheard[i];
        self->framesUnsent++;

        return ZB_OK;
    }

    return ZB_ERR_NO_SPACE;
}

static ZbStatus hearingCompletion(Radio_Radio *radio, Radio_Handle handle, Radio_TxResult *outResult)
{
    Hearing *self = (Hearing *)radio->provider;
    uint32_t i;

    if ((handle & HEARING_UNHEARD_FLAG) == 0)
        return self->backend->ops->completion(self->backend, handle, outResult);

    for (i = 0; i < HEARING_UNHEARD_MAX; i++)
    {
        if (self->unheard[i] != handle)
            continue;

        self->unheard[i] = RADIO_HANDLE_NONE;
        Zb_memset(outResult, 0, (uint32_t)sizeof *outResult);
        outResult->status = ZB_ERR_NO_ACK;

        return ZB_OK;
    }

    return ZB_ERR_BAD_ARGUMENT;
}

static ZbStatus hearingCaps(Radio_Radio *radio, Radio_Caps *outCaps)
{
    Hearing *self = (Hearing *)radio->provider;

    return self->backend->ops->caps(self->backend, outCaps);
}

static ZbStatus hearingPibSet(Radio_Radio *radio, const Radio_Pib *pib)
{
    Hearing *self = (Hearing *)radio->provider;

    return self->backend->ops->pibSet(self->backend, pib);
}

static ZbStatus hearingPibGet(Radio_Radio *radio, Radio_Pib *pib)
{
    Hearing *self = (Hearing *)radio->provider;

    return self->backend->ops->pibGet(self->backend, pib);
}

static ZbStatus hearingFilter(Radio_Radio *radio, const Radio_Filter *filter)
{
    Hearing *self = (Hearing *)radio->provider;

    return self->backend->ops->filter(self->backend, filter);
}

static int hearingIsLost(Radio_Radio *radio)
{
    Hearing *self = (Hearing *)radio->provider;

    return self->backend->ops->isLost(self->backend);
}

static ZbStatus hearingScanStart(Radio_Radio *radio, uint32_t channel, uint32_t dwellUnits)
{
    Hearing *self = (Hearing *)radio->provider;

    return self->backend->ops->scanStart(self->backend, channel, dwellUnits);
}

static ZbStatus hearingScanCollect(Radio_Radio *radio, uint32_t *outChannel, int32_t *outDbm)
{
    Hearing *self = (Hearing *)radio->provider;

    return self->backend->ops->scanCollect(self->backend, outChannel, outDbm);
}

static ZbStatus hearingPendingTable(Radio_Radio *radio, const Radio_Pending *pending)
{
    Hearing *self = (Hearing *)radio->provider;

    return self->backend->ops->pendingTable(self->backend, pending);
}

static const Radio_Ops s_hearingOps = {
    hearingCaps,
    hearingPibSet,
    hearingPibGet,
    hearingFilter,
    hearingTx,
    hearingCompletion,
    hearingRxPoll,
    hearingIsLost,
    hearingScanStart,
    hearingScanCollect,
    hearingPendingTable
};

void Hearing_Init(Hearing *self, Radio_Radio *backend)
{
    Zb_memset(self, 0, (uint32_t)sizeof *self);
    self->backend = backend;
    self->seam.ops = &s_hearingOps;
    self->seam.provider = self;
}

ZbStatus Hearing_IgnoreIeee(Hearing *self, uint64_t ieee)
{
    if (self->ignoredCount >= HEARING_IGNORED_MAX)
        return ZB_ERR_NO_SPACE;

    self->ignored[self->ignoredCount++].ieee = ieee;

    return ZB_OK;
}

ZbStatus Hearing_IgnoreShort(Hearing *self, uint16_t shortAddress)
{
    if (self->ignoredCount >= HEARING_IGNORED_MAX)
        return ZB_ERR_NO_SPACE;

    self->ignored[self->ignoredCount].shortAddress = shortAddress;
    self->ignored[self->ignoredCount].shortKnown = 1;
    self->ignoredCount++;

    return ZB_OK;
}

Radio_Radio *Hearing_Seam(Hearing *self)
{
    return &self->seam;
}
