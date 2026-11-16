#include "mac_frame.h"

#include "zb_bstream.h"
#include "zb_utils.h"

/* M2024: 6.2, 7.2.2, 7.2.3, 7.2.4, 7.2.11, 7.3.1.2, 7.3.1.4, 7.3.1.6, 7.3.3, 10.2.2.1 ok; 7.2.8, 7.3.1.5's list, 7.3.5
   unbuilt; docs/internals/conformance.md pages. */
/* FCF subfield positions: Figure 7-2, the Frame Control field format docs/internals/protocol.md §9.1 records. Bits 8 and 9
   are read and never stored, the Sequence Number Suppression and IE Present fields of 7.2.2.7 and 7.2.2.8
   requiring zero while the version subfield is 0 or 1. */
enum
{
    MAC_FRAME_FCF_TYPE_SHIFT = 0,
    MAC_FRAME_FCF_SECURITY_SHIFT = 3,
    MAC_FRAME_FCF_PENDING_SHIFT = 4,
    MAC_FRAME_FCF_ACK_SHIFT = 5,
    MAC_FRAME_FCF_PAN_COMPRESSION_SHIFT = 6,
    MAC_FRAME_FCF_SEQUENCE_SUPPRESSION_SHIFT = 8,
    MAC_FRAME_FCF_IE_SHIFT = 9,
    MAC_FRAME_FCF_DEST_MODE_SHIFT = 10,
    MAC_FRAME_FCF_VERSION_SHIFT = 12,
    MAC_FRAME_FCF_SRC_MODE_SHIFT = 14,

    MAC_FRAME_FCF_TYPE_MASK = 7,
    MAC_FRAME_FCF_MODE_MASK = 3,
    MAC_FRAME_FCF_VERSION_MASK = 3,

    MAC_FRAME_VERSION_LAST_KNOWN = 2
};

static uint16_t macFrameFcf(const Mac_Frame *frame)
{
    uint16_t fcf;

    fcf = (uint16_t)(((uint16_t)frame->frameType & MAC_FRAME_FCF_TYPE_MASK) << MAC_FRAME_FCF_TYPE_SHIFT);

    if (frame->securityEnabled)
        fcf = (uint16_t)(fcf | (1 << MAC_FRAME_FCF_SECURITY_SHIFT));

    if (frame->framePending)
        fcf = (uint16_t)(fcf | (1 << MAC_FRAME_FCF_PENDING_SHIFT));

    if (frame->ackRequest)
        fcf = (uint16_t)(fcf | (1 << MAC_FRAME_FCF_ACK_SHIFT));

    if (frame->panIdCompression)
        fcf = (uint16_t)(fcf | (1 << MAC_FRAME_FCF_PAN_COMPRESSION_SHIFT));

    if (frame->sequenceSuppressed)
        fcf = (uint16_t)(fcf | (1 << MAC_FRAME_FCF_SEQUENCE_SUPPRESSION_SHIFT));

    if (frame->iePresent)
        fcf = (uint16_t)(fcf | (1 << MAC_FRAME_FCF_IE_SHIFT));

    fcf = (uint16_t)(fcf | (uint16_t)(((uint16_t)frame->destAddrMode & MAC_FRAME_FCF_MODE_MASK) << MAC_FRAME_FCF_DEST_MODE_SHIFT));
    fcf = (uint16_t)(fcf | (uint16_t)(((uint16_t)frame->frameVersion & MAC_FRAME_FCF_VERSION_MASK) << MAC_FRAME_FCF_VERSION_SHIFT));
    fcf = (uint16_t)(fcf | (uint16_t)(((uint16_t)frame->srcAddrMode & MAC_FRAME_FCF_MODE_MASK) << MAC_FRAME_FCF_SRC_MODE_SHIFT));

    return fcf;
}

/* Table 7-2, every row of it: below version 0b10 a PAN follows its own address and compression takes the source
   one; at 0b10 the row decides, so a destination PAN is present with no address at all and is absent only for an
   extended pair under compression. 7.3.1.2 has a beacon's other frame control bits ignored on reception. */
static int macFramePanPresent(const Mac_Frame *frame, int isDestination)
{
    int compressed = frame->panIdCompression;

    if (frame->frameType == MAC_FRAME_TYPE_BEACON && frame->frameVersion <= 1)
        compressed = 0;

    if (!isDestination)
        return frame->srcAddrMode != MAC_ADDR_NONE && !compressed;

    if (frame->frameVersion != 2)
        return frame->destAddrMode != MAC_ADDR_NONE;

    if (!compressed)
        return frame->destAddrMode != MAC_ADDR_NONE;

    if (frame->destAddrMode == MAC_ADDR_NONE)
        return 1;

    if (frame->srcAddrMode == MAC_ADDR_NONE)
        return 0;

    return !(frame->destAddrMode == MAC_ADDR_EXTENDED && frame->srcAddrMode == MAC_ADDR_EXTENDED);
}

/* One layout rule per step, in 7.2.2's order, each naming its source; the first refusal a frame hits is its
   status, so an unsupported form reads apart from a contradiction. 7.2.2.7 and 7.2.2.8 hold their two bits zero
   below version 2 and are counted unbuilt above it. */
static ZbStatus macFrameLayout(const Mac_Frame *frame, uint32_t *outLen, Mac_FrameRefusal *outRefusal)
{
    uint32_t len;

    if (outRefusal != 0)
        *outRefusal = MAC_FRAME_REFUSAL_NONE;

    if (frame == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->frameType == MAC_FRAME_TYPE_RESERVED || frame->frameType > MAC_FRAME_TYPE_EXTENDED)
    {
        if (outRefusal != 0)
            *outRefusal = MAC_FRAME_REFUSAL_RESERVED_TYPE;

        return ZB_ERR_BAD_ARGUMENT;
    }

    if (frame->frameType == MAC_FRAME_TYPE_MULTIPURPOSE
        || frame->frameType == MAC_FRAME_TYPE_FRAGMENT
        || frame->frameType == MAC_FRAME_TYPE_EXTENDED)
    {
        if (outRefusal != 0)
            *outRefusal = MAC_FRAME_REFUSAL_UNBUILT;

        return ZB_ERR_UNSUPPORTED;    /* 7.3.5 to 7.3.7, no Zigbee sender: docs/internals/protocol.md §9.1 */
    }

    if (frame->frameVersion > MAC_FRAME_VERSION_LAST_KNOWN)
    {
        if (outRefusal != 0)
            *outRefusal = MAC_FRAME_REFUSAL_RESERVED_VERSION;

        return ZB_ERR_BAD_ARGUMENT;
    }

    if (frame->frameVersion <= 1 && (frame->sequenceSuppressed || frame->iePresent))
    {
        if (outRefusal != 0)
            *outRefusal = MAC_FRAME_REFUSAL_MALFORMED;

        return ZB_ERR_BAD_ARGUMENT;
    }

    if (frame->frameVersion == 2 && (frame->sequenceSuppressed || frame->iePresent))
    {
        if (outRefusal != 0)
            *outRefusal = MAC_FRAME_REFUSAL_UNBUILT;

        return ZB_ERR_UNSUPPORTED;    /* 7.2.2.7, 7.2.2.8: a suppressed sequence or an IE list, docs/internals/protocol.md §9.1 */
    }

    if (frame->destAddrMode == MAC_ADDR_RESERVED || frame->srcAddrMode == MAC_ADDR_RESERVED)
    {
        if (outRefusal != 0)
            *outRefusal = MAC_FRAME_REFUSAL_MALFORMED;

        return ZB_ERR_BAD_ARGUMENT;
    }

    if (frame->securityEnabled)
    {
        if (outRefusal != 0)
            *outRefusal = MAC_FRAME_REFUSAL_UNBUILT;

        return ZB_ERR_UNSUPPORTED;    /* 7.2.8, the auxiliary security header: docs/internals/protocol.md §9.1 */
    }

    len = MAC_FRAME_FCF_OCTETS + MAC_FRAME_SEQ_OCTETS;

    if (macFramePanPresent(frame, 1))
        len = len + MAC_FRAME_PAN_OCTETS;

    if (frame->destAddrMode == MAC_ADDR_SHORT)
        len = len + MAC_FRAME_SHORT_OCTETS;
    else if (frame->destAddrMode == MAC_ADDR_EXTENDED)
        len = len + MAC_FRAME_EXTENDED_OCTETS;

    if (macFramePanPresent(frame, 0))
        len = len + MAC_FRAME_PAN_OCTETS;

    if (frame->srcAddrMode == MAC_ADDR_SHORT)
        len = len + MAC_FRAME_SHORT_OCTETS;
    else if (frame->srcAddrMode == MAC_ADDR_EXTENDED)
        len = len + MAC_FRAME_EXTENDED_OCTETS;

    if (frame->frameVersion <= 1)
    {
        if (frame->destAddrMode == MAC_ADDR_NONE && frame->srcAddrMode == MAC_ADDR_NONE
            && frame->frameType != MAC_FRAME_TYPE_ACK)
        {
            if (outRefusal != 0)
                *outRefusal = MAC_FRAME_REFUSAL_MALFORMED;

            return ZB_ERR_BAD_ARGUMENT;
        }

        if (frame->panIdCompression
            && (frame->destAddrMode == MAC_ADDR_NONE || frame->srcAddrMode == MAC_ADDR_NONE))
        {
            if (outRefusal != 0)
                *outRefusal = MAC_FRAME_REFUSAL_MALFORMED;

            return ZB_ERR_BAD_ARGUMENT;
        }
    }

    if (frame->frameType == MAC_FRAME_TYPE_ACK)
    {
        if (frame->destAddrMode != MAC_ADDR_NONE || frame->srcAddrMode != MAC_ADDR_NONE
            || frame->ackRequest || frame->panIdCompression)
        {
            if (outRefusal != 0)
                *outRefusal = MAC_FRAME_REFUSAL_MALFORMED;

            return ZB_ERR_BAD_ARGUMENT;
        }
    }
    else if (frame->frameType == MAC_FRAME_TYPE_BEACON)
    {
        if (frame->destAddrMode != MAC_ADDR_NONE || frame->srcAddrMode == MAC_ADDR_NONE)
        {
            if (outRefusal != 0)
                *outRefusal = MAC_FRAME_REFUSAL_MALFORMED;

            return ZB_ERR_BAD_ARGUMENT;
        }
    }

    *outLen = len;

    return ZB_OK;
}

int MacFrame_DestPanPresent(const Mac_Frame *frame)
{
    return frame != 0 && macFramePanPresent(frame, 1);
}

ZbStatus MacFrame_HeaderLen(const Mac_Frame *frame, uint32_t *outLen)
{
    return macFrameLayout(frame, outLen, 0);
}

uint16_t MacFrame_Fcs(const uint8_t *bytes, uint32_t len)
{
    uint16_t crc;
    uint32_t index;
    uint32_t bit;

    if (bytes == 0)
        return 0;

    crc = 0;

    for (index = 0; index < len; index++)
    {
        crc = (uint16_t)(crc ^ bytes[index]);

        for (bit = 0; bit < 8; bit++)
        {
            if ((crc & 1) != 0)
                crc = (uint16_t)((crc >> 1) ^ MAC_FRAME_FCS_POLY_REVERSED);
            else
                crc = (uint16_t)(crc >> 1);
        }
    }

    return crc;
}

/* 7.3.1.2: a version-0 or version-1 beacon's frame control is the source addressing it names and "all other
   fields ... set to zero"; a receiver ignores the rest, so only the writing side refuses them. */
static int macBeaconBitsWritable(const Mac_Frame *frame)
{
    if (frame->frameType != MAC_FRAME_TYPE_BEACON || frame->frameVersion > 1)
        return 1;

    return !frame->ackRequest && !frame->framePending && !frame->panIdCompression && !frame->securityEnabled;
}

ZbStatus MacFrame_Compose(const Mac_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                          uint8_t *out, uint32_t outCap, uint32_t *outLen)
{
    U_BStream stream;
    uint32_t headerLen;
    uint32_t totalLen;
    ZbStatus status;

    if (out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payload == 0 && payloadLen != 0)
        return ZB_ERR_BAD_ARGUMENT;

    status = macFrameLayout(frame, &headerLen, 0);

    if (status != ZB_OK)
        return status;

    if (!macBeaconBitsWritable(frame))
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->frameVersion != 0)
        return ZB_ERR_UNSUPPORTED;    /* R23.1 Annex D.6 writes version zero and no other, docs/internals/protocol.md §9.1 */

    totalLen = headerLen + payloadLen;

    if (totalLen > MAC_FRAME_MPDU_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (totalLen + MAC_FRAME_FCS_OCTETS > MAC_FRAME_MPDU_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (outCap < totalLen)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outCap);

    U_bstream_put_u16_le(&stream, macFrameFcf(frame));
    U_bstream_put_u8(&stream, frame->seq);

    if (macFramePanPresent(frame, 1))
        U_bstream_put_u16_le(&stream, frame->destPan);

    if (frame->destAddrMode == MAC_ADDR_SHORT)
        U_bstream_put_u16_le(&stream, frame->destShort);
    else if (frame->destAddrMode == MAC_ADDR_EXTENDED)
        U_bstream_put_u64_le(&stream, frame->destExtended);

    if (macFramePanPresent(frame, 0))
        U_bstream_put_u16_le(&stream, frame->srcPan);

    if (frame->srcAddrMode == MAC_ADDR_SHORT)
        U_bstream_put_u16_le(&stream, frame->srcShort);
    else if (frame->srcAddrMode == MAC_ADDR_EXTENDED)
        U_bstream_put_u64_le(&stream, frame->srcExtended);

    if (payload != 0 && payloadLen != 0)
        U_bstream_put_bytes(&stream, payload, (unsigned long)payloadLen);

    if (!Zb_bstream_ok(&stream) || Zb_bstream_pos(&stream) != totalLen)
        return ZB_ERR_NO_SPACE;     

    *outLen = totalLen;

    return ZB_OK;
}

ZbStatus MacFrame_AppendFcs(uint8_t *mpdu, uint32_t mpduLen, uint32_t outCap, uint32_t *outLen)
{
    U_BStream stream;

    if (mpdu == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (mpduLen < MAC_FRAME_FCF_OCTETS + MAC_FRAME_SEQ_OCTETS)
        return ZB_ERR_BAD_ARGUMENT;     

    if (mpduLen + MAC_FRAME_FCS_OCTETS > MAC_FRAME_MPDU_MAX)
        return ZB_ERR_BAD_ARGUMENT;     

    if (outCap < mpduLen + MAC_FRAME_FCS_OCTETS)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, mpdu, (unsigned long)outCap);
    U_bstream_seek(&stream, (unsigned long)mpduLen);
    U_bstream_put_u16_le(&stream, MacFrame_Fcs(mpdu, mpduLen));

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = mpduLen + MAC_FRAME_FCS_OCTETS;

    return ZB_OK;
}

ZbStatus MacFrame_CheckFcs(const uint8_t *mpdu, uint32_t mpduLen)
{
    uint16_t expected;
    uint16_t computed;

    if (mpdu == 0 || mpduLen < MAC_FRAME_FCF_OCTETS + MAC_FRAME_SEQ_OCTETS + MAC_FRAME_FCS_OCTETS)
        return ZB_ERR_BAD_FRAME;

    expected = (uint16_t)(mpdu[mpduLen - 2] | (uint16_t)(mpdu[mpduLen - 1] << 8));
    computed = MacFrame_Fcs(mpdu, mpduLen - MAC_FRAME_FCS_OCTETS);

    if (expected != computed)
        return ZB_ERR_BAD_FRAME;

    return ZB_OK;
}

ZbStatus MacFrame_Parse(const uint8_t *mpdu, uint32_t mpduLen, int hasFrameFcs,
                        Mac_Frame *outFrame, const uint8_t **outPayload, uint32_t *outPayloadLen,
                        Mac_FrameRefusal *outRefusal)
{
    U_BStream stream;
    Mac_Frame frame;
    uint16_t fcf;
    uint32_t headerLen;
    uint32_t payloadEnd;
    ZbStatus status;

    if (outRefusal != 0)
        *outRefusal = MAC_FRAME_REFUSAL_NONE;

    if (mpdu == 0 || outFrame == 0 || outPayload == 0 || outPayloadLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (mpduLen > MAC_FRAME_MPDU_MAX || (hasFrameFcs && mpduLen < MAC_FRAME_MPDU_MIN))
    {
        if (outRefusal != 0)
            *outRefusal = MAC_FRAME_REFUSAL_MALFORMED;

        return ZB_ERR_BAD_FRAME;
    }

    payloadEnd = mpduLen;

    if (hasFrameFcs)
        payloadEnd = mpduLen - MAC_FRAME_FCS_OCTETS;

    Zb_bstream_init_const(&stream, mpdu, mpduLen);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    fcf = U_bstream_get_u16_le(&stream);
    frame.frameType = (Mac_FrameType)(fcf & MAC_FRAME_FCF_TYPE_MASK);
    frame.securityEnabled = (fcf & (1 << MAC_FRAME_FCF_SECURITY_SHIFT)) ? 1 : 0;
    frame.framePending = (fcf & (1 << MAC_FRAME_FCF_PENDING_SHIFT)) ? 1 : 0;
    frame.ackRequest = (fcf & (1 << MAC_FRAME_FCF_ACK_SHIFT)) ? 1 : 0;
    frame.panIdCompression = (fcf & (1 << MAC_FRAME_FCF_PAN_COMPRESSION_SHIFT)) ? 1 : 0;
    frame.sequenceSuppressed = (fcf & (1 << MAC_FRAME_FCF_SEQUENCE_SUPPRESSION_SHIFT)) ? 1 : 0;
    frame.iePresent = (fcf & (1 << MAC_FRAME_FCF_IE_SHIFT)) ? 1 : 0;
    frame.destAddrMode = (Mac_AddrMode)((fcf >> MAC_FRAME_FCF_DEST_MODE_SHIFT) & MAC_FRAME_FCF_MODE_MASK);
    frame.frameVersion = (uint32_t)((fcf >> MAC_FRAME_FCF_VERSION_SHIFT) & MAC_FRAME_FCF_VERSION_MASK);
    frame.srcAddrMode = (Mac_AddrMode)((fcf >> MAC_FRAME_FCF_SRC_MODE_SHIFT) & MAC_FRAME_FCF_MODE_MASK);

    if (frame.frameVersion <= 1 && (frame.sequenceSuppressed || frame.iePresent))
    {
        if (outRefusal != 0)
            *outRefusal = MAC_FRAME_REFUSAL_MALFORMED;

        return ZB_ERR_BAD_FRAME;
    }

    if (frame.frameVersion == 2 && (frame.sequenceSuppressed || frame.iePresent))
    {
        if (outRefusal != 0)
            *outRefusal = MAC_FRAME_REFUSAL_UNBUILT;

        return ZB_ERR_UNSUPPORTED;    /* docs/internals/protocol.md §9.1: the version-2 forms not built */
    }

    status = macFrameLayout(&frame, &headerLen, outRefusal);

    if (status != ZB_OK)
        return status;

    if (headerLen > payloadEnd)
    {
        if (outRefusal != 0)
            *outRefusal = MAC_FRAME_REFUSAL_MALFORMED;

        return ZB_ERR_BAD_FRAME;
    }

    frame.seq = U_bstream_get_u8(&stream);

    if (macFramePanPresent(&frame, 1))
        frame.destPan = U_bstream_get_u16_le(&stream);

    if (frame.destAddrMode == MAC_ADDR_SHORT)
        frame.destShort = U_bstream_get_u16_le(&stream);
    else if (frame.destAddrMode == MAC_ADDR_EXTENDED)
        frame.destExtended = U_bstream_get_u64_le(&stream);

    if (macFramePanPresent(&frame, 0))
        frame.srcPan = U_bstream_get_u16_le(&stream);
    else
        frame.srcPan = frame.destPan;

    if (frame.srcAddrMode == MAC_ADDR_SHORT)
        frame.srcShort = U_bstream_get_u16_le(&stream);
    else if (frame.srcAddrMode == MAC_ADDR_EXTENDED)
        frame.srcExtended = U_bstream_get_u64_le(&stream);

    if (!Zb_bstream_ok(&stream) || Zb_bstream_pos(&stream) != headerLen)
    {
        if (outRefusal != 0)
            *outRefusal = MAC_FRAME_REFUSAL_MALFORMED;

        return ZB_ERR_BAD_FRAME;
    }

    *outFrame = frame;
    *outPayload = mpdu + headerLen;
    *outPayloadLen = payloadEnd - headerLen;

    return ZB_OK;
}

/* 7.3.1.4's Superframe Specification, bit for bit as Figure 7-7 prints it: the four four-bit subfields, then the
   battery-life bit, the reserved bit that follows it, the PAN-coordinator bit and the association-permit bit. */
static uint16_t macFrameSuperframeSpec(const MacFrame_Beacon *beacon)
{
    uint16_t value;

    value = (uint16_t)(beacon->beaconOrder & 0x0f);
    value = (uint16_t)(value | ((beacon->superframeOrder & 0x0f) << 4));
    value = (uint16_t)(value | ((beacon->finalCapSlot & 0x0f) << 8));

    if (beacon->batteryLifeExtension)
        value = (uint16_t)(value | (1 << 12));

    if (beacon->panCoordinator)
        value = (uint16_t)(value | (1 << 14));

    if (beacon->associationPermit)
        value = (uint16_t)(value | (1 << 15));

    return value;
}

/* 10.2.2.1: the field widths bound each order, and 0 <= macSuperframeOrder <= macBeaconOrder <= 14 holds besides,
   where the two 0x0F values are the pair that states no superframe at all. */
ZbStatus MacFrame_ComposeBeaconPayload(const MacFrame_Beacon *beacon, const uint8_t *payload,
                                       uint32_t payloadLen, uint8_t *out, uint32_t outCap,
                                       uint32_t *outLen)
{
    U_BStream stream;
    uint32_t total;
    uint32_t i;

    if (beacon == 0 || out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payload == 0 && payloadLen != 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (beacon->beaconOrder > MAC_FRAME_BEACON_ORDER_NONE
        || beacon->superframeOrder > MAC_FRAME_BEACON_ORDER_NONE
        || beacon->finalCapSlot > MAC_FRAME_BEACON_ORDER_NONE)
        return ZB_ERR_BAD_ARGUMENT;

    if (beacon->beaconOrder != MAC_FRAME_BEACON_ORDER_NONE
        && beacon->superframeOrder > beacon->beaconOrder)
        return ZB_ERR_BAD_ARGUMENT;

    if (beacon->pendingShortCount > MAC_FRAME_PENDING_MAX
        || beacon->pendingExtendedCount > MAC_FRAME_PENDING_MAX
        || beacon->pendingShortCount + beacon->pendingExtendedCount > MAC_FRAME_PENDING_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    total = MAC_FRAME_SUPERFRAME_SPEC_OCTETS + MAC_FRAME_GTS_FIELDS_OCTETS
            + MAC_FRAME_PENDING_SPEC_OCTETS
            + (beacon->pendingShortCount * MAC_FRAME_SHORT_OCTETS)
            + (beacon->pendingExtendedCount * MAC_FRAME_EXTENDED_OCTETS)
            + payloadLen;

    if (outCap < total)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outCap);

    U_bstream_put_u16_le(&stream, macFrameSuperframeSpec(beacon));

    U_bstream_put_u8(&stream, beacon->gtsPermit ? (uint8_t)0x80 : (uint8_t)0);

    U_bstream_put_u8(&stream, (uint8_t)((beacon->pendingShortCount & 0x07)
                                        | ((beacon->pendingExtendedCount & 0x07) << 4)));

    for (i = 0; i < beacon->pendingShortCount; i++)
        U_bstream_put_u16_le(&stream, beacon->pendingShort[i]);

    for (i = 0; i < beacon->pendingExtendedCount; i++)
        U_bstream_put_u64_le(&stream, beacon->pendingExtended[i]);

    for (i = 0; i < payloadLen; i++)
        U_bstream_put_u8(&stream, payload[i]);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = total;

    return ZB_OK;
}

ZbStatus MacFrame_ParseBeaconPayload(const uint8_t *bytes, uint32_t len, MacFrame_Beacon *outBeacon,
                                    const uint8_t **outPayload, uint32_t *outPayloadLen)
{
    U_BStream stream;
    MacFrame_Beacon beacon;
    uint16_t spec;
    uint32_t pendingSpec;
    uint8_t gtsSpec;
    uint32_t i;

    if (bytes == 0 || outBeacon == 0 || outPayload == 0 || outPayloadLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (len < MAC_FRAME_SUPERFRAME_SPEC_OCTETS + MAC_FRAME_GTS_FIELDS_OCTETS + MAC_FRAME_PENDING_SPEC_OCTETS)
        return ZB_ERR_BAD_FRAME;

    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    Zb_bstream_init_const(&stream, bytes, len);

    spec = U_bstream_get_u16_le(&stream);
    beacon.beaconOrder = (uint32_t)(spec & 0x0f);
    beacon.superframeOrder = (uint32_t)((spec >> 4) & 0x0f);
    beacon.finalCapSlot = (uint32_t)((spec >> 8) & 0x0f);
    beacon.batteryLifeExtension = ((spec >> 12) & 1) != 0;
    beacon.panCoordinator = ((spec >> 14) & 1) != 0;
    beacon.associationPermit = ((spec >> 15) & 1) != 0;

    gtsSpec = U_bstream_get_u8(&stream);

    if ((gtsSpec & 0x07) != 0)
        return ZB_ERR_UNSUPPORTED;    /* a GTS descriptor count above zero needs the GTS fields: not built, docs/internals/conformance.md §1 */

    beacon.gtsPermit = ((gtsSpec >> 7) & 1) != 0;

    pendingSpec = U_bstream_get_u8(&stream);
    beacon.pendingShortCount = pendingSpec & 0x07;
    beacon.pendingExtendedCount = (pendingSpec >> 4) & 0x07;

    if (beacon.pendingShortCount > MAC_FRAME_PENDING_MAX
        || beacon.pendingExtendedCount > MAC_FRAME_PENDING_MAX)
        return ZB_ERR_BAD_FRAME;

    for (i = 0; i < beacon.pendingShortCount; i++)
        beacon.pendingShort[i] = U_bstream_get_u16_le(&stream);

    for (i = 0; i < beacon.pendingExtendedCount; i++)
        beacon.pendingExtended[i] = U_bstream_get_u64_le(&stream);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_BAD_FRAME;

    *outBeacon = beacon;
    *outPayloadLen = Zb_bstream_remaining(&stream);
    *outPayload = Zb_bstream_get_span(&stream, *outPayloadLen);

    return ZB_OK;
}

/* 10.21.5.1, Figure 10-157's octet, bit by bit. Bit 0 is the reserved bit 802.15.4-2024 prints there and is
   written zero; the alternate-PAN-coordinator meaning 802.15.4-2006's Figure 56 gave the same bit belongs to a
   field this stack does not have. */
static uint8_t macFrameCapabilityOctet(const MacFrame_Capability *capability)
{
    uint8_t value = 0;

    if (capability->deviceType)
        value = (uint8_t)(value | 0x02);

    if (capability->powerSource)
        value = (uint8_t)(value | 0x04);

    if (capability->rxOnWhenIdle)
        value = (uint8_t)(value | 0x08);

    if (capability->associationType)
        value = (uint8_t)(value | 0x10);

    if (capability->suspendableCsmaCa)
        value = (uint8_t)(value | 0x20);

    if (capability->securityCapability)
        value = (uint8_t)(value | 0x40);

    if (capability->allocateAddress)
        value = (uint8_t)(value | 0x80);

    return value;
}

/* The same octet read the 2024 way: bit 0 is reserved and ignored, which is also how a 2006 device's
   alternate-PAN-coordinator bit is read past rather than mistaken for a field. */
static void macFrameCapabilityFromOctet(uint8_t value, MacFrame_Capability *capability)
{
    Zb_memset(capability, 0, (uint32_t)sizeof *capability);

    capability->deviceType = (value & 0x02) ? 1 : 0;
    capability->powerSource = (value & 0x04) ? 1 : 0;
    capability->rxOnWhenIdle = (value & 0x08) ? 1 : 0;
    capability->associationType = (value & 0x10) ? 1 : 0;
    capability->suspendableCsmaCa = (value & 0x20) ? 1 : 0;
    capability->securityCapability = (value & 0x40) ? 1 : 0;
    capability->allocateAddress = (value & 0x80) ? 1 : 0;
}

ZbStatus MacFrame_ComposeAssociationRequest(const MacFrame_Capability *capability, uint8_t *out, uint32_t outCap,
                                            uint32_t *outLen)
{
    U_BStream stream;

    if (capability == 0 || out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (capability->associationType || capability->suspendableCsmaCa || capability->securityCapability)
        return ZB_ERR_UNSUPPORTED;    /* fast association, suspendable CSMA-CA and MAC security: not built, docs/internals/protocol.md §9.2 */

    if (outCap < 1)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outCap);
    U_bstream_put_u8(&stream, macFrameCapabilityOctet(capability));

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = 1;

    return ZB_OK;
}

ZbStatus MacFrame_ParseAssociationRequest(const uint8_t *body, uint32_t len, MacFrame_Capability *outCapability)
{
    if (body == 0 || outCapability == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (len != 1)
        return ZB_ERR_BAD_FRAME;

    macFrameCapabilityFromOctet(body[0], outCapability);

    return ZB_OK;
}

ZbStatus MacFrame_ComposeAssociationResponse(const MacFrame_AssociationResponse *response, uint8_t *out,
                                             uint32_t outCap, uint32_t *outLen)
{
    U_BStream stream;

    if (response == 0 || out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (outCap < 3)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outCap);
    U_bstream_put_u16_le(&stream, response->shortAddress);
    U_bstream_put_u8(&stream, response->status);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = 3;

    return ZB_OK;
}

ZbStatus MacFrame_ParseAssociationResponse(const uint8_t *body, uint32_t len,
                                           MacFrame_AssociationResponse *outResponse)
{
    U_BStream stream;

    if (body == 0 || outResponse == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (len != 3)
        return ZB_ERR_BAD_FRAME;

    Zb_bstream_init_const(&stream, body, len);
    outResponse->shortAddress = U_bstream_get_u16_le(&stream);
    outResponse->status = U_bstream_get_u8(&stream);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_BAD_FRAME;

    return ZB_OK;
}
