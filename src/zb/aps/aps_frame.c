#include "aps_frame.h"

#include "zb_bstream.h"
#include "zb_utils.h"

/* R23.1 2.2.5 2.2.5.1.1 2.2.5.1.2 2.2.5.1.3 2.2.5.1.4 2.2.5.1.5 2.2.5.1.6 2.2.5.1.7 2.2.5.1.8 2.2.5.2 2.2.5.2.2
   2.2.5.2.3 4.4.11 ok; 2.2.8.4.1 2.2.8.4.3 4.4.10 4.5.1 elsewhere (aps_tx.c's field rules, aps_ack.c's mirrored
   acknowledgement, security.c's auxiliary header). */

/* Figure 2-3 up to the extended header: the addressing fields the clauses fix and the counter every frame carries.
   A command's identifier is payload, Figure 2-8's "APS payload" column, so the auxiliary header goes in front of
   it and it is encrypted with the body. */
static uint32_t apsFrameBaseLen(const Aps_Frame *frame)
{
    uint32_t len;

    len = APS_FRAME_FCF_OCTETS + APS_FRAME_COUNTER_OCTETS;

    if (frame->dstEndpointPresent)
        len = len + APS_FRAME_ENDPOINT_OCTETS;

    if (frame->groupAddressPresent)
        len = len + APS_FRAME_GROUP_OCTETS;

    if (frame->clusterPresent)
        len = len + APS_FRAME_CLUSTER_OCTETS;

    if (frame->profilePresent)
        len = len + APS_FRAME_PROFILE_OCTETS;

    if (frame->srcEndpointPresent)
        len = len + APS_FRAME_ENDPOINT_OCTETS;

    return len;
}

/* 2.2.5.1.8 with Figure 2-5: the extended frame control, then what its own clauses ask for */
static uint32_t apsFrameExtendedLen(const Aps_Frame *frame)
{
    uint32_t len;

    if (!frame->extendedHeaderPresent)
        return 0;

    len = APS_FRAME_EXT_CONTROL_OCTETS;

    if (frame->blockNumberPresent)
        len = len + APS_FRAME_BLOCK_OCTETS;

    if (frame->ackBitfieldPresent)
        len = len + APS_FRAME_ACK_BITFIELD_OCTETS;

    return len;
}

uint32_t ApsFrame_HeaderLen(const Aps_Frame *frame)
{
    if (frame == 0)
        return 0;

    return apsFrameBaseLen(frame) + apsFrameExtendedLen(frame);
}

/* 2.2.5.1.2 with 2.2.5.1.1.3: unicast and broadcast data frames and ACK format 0 acknowledgements; absent for
   group, for a command, and for an ACK format 1 */
static int apsFrameWantDstEndpoint(const Aps_Frame *frame)
{
    if (frame->frameType == APS_FRAME_TYPE_DATA)
        return frame->deliveryMode == APS_DELIVERY_UNICAST || frame->deliveryMode == APS_DELIVERY_BROADCAST ? 1 : 0;

    if (frame->frameType == APS_FRAME_TYPE_ACK)
        return frame->ackFormat == 0 ? 1 : 0;

    return 0;
}

/* 2.2.5.1.3: 0b11 only, and then no destination endpoint; Figure 2-9 prints no group column */
static int apsFrameWantGroup(const Aps_Frame *frame)
{
    if (frame->frameType == APS_FRAME_TYPE_DATA && frame->deliveryMode == APS_DELIVERY_GROUP)
        return 1;

    return 0;
}

/* 2.2.5.1.4 with 2.2.5.1.5: data or acknowledgement frames, ACK format 0 only */
static int apsFrameWantCluster(const Aps_Frame *frame)
{
    if (frame->frameType == APS_FRAME_TYPE_DATA)
        return 1;

    if (frame->frameType == APS_FRAME_TYPE_ACK && frame->ackFormat == 0)
        return 1;

    return 0;
}

/* 2.2.5.1.5: the same sentence, the other 16-bit field */
static int apsFrameWantProfile(const Aps_Frame *frame)
{
    return apsFrameWantCluster(frame);
}

/* 2.2.5.1.6 with Figure 2-7 and 2.2.5.2.3.1: absent for ACK format 1 and for a command */
static int apsFrameWantSrcEndpoint(const Aps_Frame *frame)
{
    if (frame->frameType == APS_FRAME_TYPE_DATA)
        return 1;

    if (frame->frameType == APS_FRAME_TYPE_ACK && frame->ackFormat == 0)
        return 1;

    return 0;
}

/* 2.2.5.1.8.2: absent for fragmentation 0b00, present for 0b01 and 0b10 */
static int apsFrameFragmented(const Aps_Frame *frame)
{
    return frame->fragmentation == APS_FRAG_FIRST || frame->fragmentation == APS_FRAG_SUBSEQUENT ? 1 : 0;
}

/* present when the fragmentation sub-field says the transmission is fragmented, absent when it says it is not */
static int apsFrameWantBlockNumber(const Aps_Frame *frame)
{
    if (frame->extendedHeaderPresent && apsFrameFragmented(frame))
        return 1;

    return 0;
}

/* 2.2.5.1.8.3 with 2.2.5.2.3.1: an acknowledgement of a fragmented transmission */
static int apsFrameWantAckBitfield(const Aps_Frame *frame)
{
    if (frame->extendedHeaderPresent
        && frame->frameType == APS_FRAME_TYPE_ACK
        && apsFrameFragmented(frame))
        return 1;

    return 0;
}

/* Figure 2-4's sub-fields in the order the figure names them, against the tables it points at: a value no table
 * prints is an argument error, and a value printed Reserved or Annex G's Inter-PAN type is a form this codec does
 * not read, in either direction; the acknowledgement ask is 0 for broadcast and group. */
static ZbStatus apsFrameFcfRules(const Aps_Frame *frame)
{
    if (frame->frameType > APS_FRAME_TYPE_INTERPAN)
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->frameType == APS_FRAME_TYPE_INTERPAN)
        return ZB_ERR_UNSUPPORTED;

    if (frame->deliveryMode > APS_DELIVERY_GROUP)
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->deliveryMode == APS_DELIVERY_RESERVED)
        return ZB_ERR_UNSUPPORTED;

    if (frame->ackFormat != 0 && frame->ackFormat != 1)
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->ackFormat != 0 && frame->frameType != APS_FRAME_TYPE_ACK)
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->ackRequest && frame->frameType == APS_FRAME_TYPE_ACK)
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->ackRequest
        && (frame->deliveryMode == APS_DELIVERY_BROADCAST || frame->deliveryMode == APS_DELIVERY_GROUP))
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->frameType == APS_FRAME_TYPE_ACK && frame->deliveryMode != APS_DELIVERY_UNICAST)
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->frameType == APS_FRAME_TYPE_COMMAND && frame->extendedHeaderPresent)
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->frameType == APS_FRAME_TYPE_COMMAND && frame->deliveryMode == APS_DELIVERY_GROUP)
        return ZB_ERR_BAD_ARGUMENT;

    return ZB_OK;
}

/*
 * The matrix as the caller's struct claims it: every Present flag compared against what the clause fixes.
 * This judgement is the compose side's alone: on the wire the Frame Control Field *is* the claim, and the
 * derive helpers below turn it into the flags that decide how many octets are read.
 */
static ZbStatus apsFramePresence(const Aps_Frame *frame)
{
    if (frame->dstEndpointPresent != apsFrameWantDstEndpoint(frame))
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->groupAddressPresent != apsFrameWantGroup(frame))
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->clusterPresent != apsFrameWantCluster(frame))
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->profilePresent != apsFrameWantProfile(frame))
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->srcEndpointPresent != apsFrameWantSrcEndpoint(frame))
        return ZB_ERR_BAD_ARGUMENT;

    return ZB_OK;
}

/* 2.2.5.1.8 with Figures 2-5 and 2-6 and Table 2-22: the octet is the value, so the disagreement check is the
   compose side's alone; Tables 2-20, 2-21 and 2-22 print no reserved value as usable, so a reserved sub-field is
   answered "not read here" rather than corrected. */
static ZbStatus apsFrameExtended(const Aps_Frame *frame)
{
    if (!frame->extendedHeaderPresent)
    {
        if (frame->extFrameControl || frame->fragmentation)
            return ZB_ERR_BAD_ARGUMENT;

        if (frame->blockNumberPresent || frame->ackBitfieldPresent)
            return ZB_ERR_BAD_ARGUMENT;

        return ZB_OK;
    }

    if (((frame->extFrameControl >> APS_FRAME_EXT_RESERVED_SHIFT) & APS_FRAME_EXT_RESERVED_MASK) != 0)
        return ZB_ERR_UNSUPPORTED;

    if (frame->fragmentation > APS_FRAG_RESERVED)
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->fragmentation == APS_FRAG_RESERVED)
        return ZB_ERR_UNSUPPORTED;

    if ((uint32_t)(frame->extFrameControl & APS_FRAME_EXT_FRAGMENTATION_MASK) != frame->fragmentation)
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->blockNumberPresent != apsFrameWantBlockNumber(frame))
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->ackBitfieldPresent != apsFrameWantAckBitfield(frame))
        return ZB_ERR_BAD_ARGUMENT;

    return ZB_OK;
}

/* Field values once the field is present: a broadcast may name the ZDO endpoint, which the broadcast Device_annce
   needs (D-217), and the source values the clause names stop at the last application endpoint */
static ZbStatus apsFrameValues(const Aps_Frame *frame)
{
    if (frame->srcEndpointPresent && frame->srcEndpoint > APS_ENDPOINT_LAST)
        return ZB_ERR_BAD_ARGUMENT;

    return ZB_OK;
}

/* The same judgements, named for the wire: on the read path a contradicting octet is damage, not an argument. */
static ZbStatus apsFrameAsDamage(ZbStatus status)
{
    if (status == ZB_ERR_BAD_ARGUMENT)
        return ZB_ERR_BAD_FRAME;

    return status;
}

static uint8_t apsFrameFcf(const Aps_Frame *frame)
{
    uint8_t fcf;

    fcf = (uint8_t)(((uint32_t)frame->frameType & APS_FRAME_FCF_TYPE_MASK) << APS_FRAME_FCF_TYPE_SHIFT);
    fcf = (uint8_t)(fcf | (uint32_t)(((uint32_t)frame->deliveryMode & APS_FRAME_FCF_DELIVERY_MODE_MASK) << APS_FRAME_FCF_DELIVERY_MODE_SHIFT));

    if (frame->ackFormat)
        fcf = (uint8_t)(fcf | (1 << APS_FRAME_FCF_ACK_FORMAT_SHIFT));

    if (frame->securityEnabled)
        fcf = (uint8_t)(fcf | (1 << APS_FRAME_FCF_SECURITY_SHIFT));

    if (frame->ackRequest)
        fcf = (uint8_t)(fcf | (1 << APS_FRAME_FCF_ACK_REQUEST_SHIFT));

    if (frame->extendedHeaderPresent)
        fcf = (uint8_t)(fcf | (1 << APS_FRAME_FCF_EXTENDED_SHIFT));

    return fcf;
}

/* The addressing presence the Frame Control Field alone decides, written into a frame being read. A wire
   frame claims its fields through Figure 2-4 and not through flags, so the flags are derived here and the
   matrix above is then a restatement of the clauses rather than a judgement of a caller's struct. */
static void apsFrameDeriveAddressPresence(Aps_Frame *frame)
{
    frame->dstEndpointPresent = apsFrameWantDstEndpoint(frame);
    frame->groupAddressPresent = apsFrameWantGroup(frame);
    frame->clusterPresent = apsFrameWantCluster(frame);
    frame->profilePresent = apsFrameWantProfile(frame);
    frame->srcEndpointPresent = apsFrameWantSrcEndpoint(frame);
}

static void apsFrameDeriveExtendedPresence(Aps_Frame *frame)
{
    frame->blockNumberPresent = apsFrameWantBlockNumber(frame);
    frame->ackBitfieldPresent = apsFrameWantAckBitfield(frame);
}

/* Figure 2-3 left to right, which 2.2.5 (p86) states is transmission order; multi-octet fields low octet first */
static void apsFrameDoWriteHeader(U_BStream *stream, const Aps_Frame *frame)
{
    U_bstream_put_u8(stream, apsFrameFcf(frame));

    if (frame->dstEndpointPresent)
        U_bstream_put_u8(stream, frame->dstEndpoint);

    if (frame->groupAddressPresent)
        U_bstream_put_u16_le(stream, frame->groupAddress);

    if (frame->clusterPresent)
        U_bstream_put_u16_le(stream, frame->clusterId);

    if (frame->profilePresent)
        U_bstream_put_u16_le(stream, frame->profileId);

    if (frame->srcEndpointPresent)
        U_bstream_put_u8(stream, frame->srcEndpoint);

    U_bstream_put_u8(stream, frame->apsCounter);

    if (frame->extendedHeaderPresent)
    {
        U_bstream_put_u8(stream, frame->extFrameControl);

        if (frame->blockNumberPresent)
            U_bstream_put_u8(stream, frame->blockNumber);

        if (frame->ackBitfieldPresent)
            U_bstream_put_u8(stream, frame->ackBitfield);
    }
}

ZbStatus ApsFrame_Compose(const Aps_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                          uint8_t *out, uint32_t outMax, uint32_t *outLen, uint32_t *payloadOffset)
{
    U_BStream stream;
    uint32_t headerLen;
    uint32_t totalLen;
    ZbStatus status;

    if (frame == 0 || out == 0 || outLen == 0 || payloadOffset == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payload == 0 && payloadLen != 0)
        return ZB_ERR_BAD_ARGUMENT;

    status = apsFrameFcfRules(frame);

    if (status != ZB_OK)
        return status;

    status = apsFramePresence(frame);

    if (status != ZB_OK)
        return status;

    status = apsFrameExtended(frame);

    if (status != ZB_OK)
        return status;

    status = apsFrameValues(frame);

    if (status != ZB_OK)
        return status;

    headerLen = apsFrameBaseLen(frame) + apsFrameExtendedLen(frame);

    if (payloadLen > APS_FRAME_MAX - headerLen)
        return ZB_ERR_NO_SPACE;

    totalLen = headerLen + payloadLen;

    if (outMax < totalLen)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outMax);

    apsFrameDoWriteHeader(&stream, frame);

    if (payload != 0 && payloadLen != 0)
        U_bstream_put_bytes(&stream, payload, (unsigned long)payloadLen);

    if (!Zb_bstream_ok(&stream) || Zb_bstream_pos(&stream) != totalLen)
        return ZB_ERR_NO_SPACE;

    *outLen = totalLen;
    *payloadOffset = headerLen;

    return ZB_OK;
}

ZbStatus ApsFrame_Parse(const uint8_t *in, uint32_t inLen, Aps_Frame *frame,
                        uint32_t *payloadOffset, uint32_t *payloadLen)
{
    U_BStream stream;
    Aps_Frame parsed;
    uint8_t fcf;
    uint32_t claimedLen;
    uint32_t headerLen;
    ZbStatus status;

    if (in == 0 || frame == 0 || payloadOffset == 0 || payloadLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (inLen == 0 || inLen > APS_FRAME_MAX)
        return ZB_ERR_BAD_FRAME;

    Zb_bstream_init_const(&stream, in, inLen);

    Zb_memset(&parsed, 0, (uint32_t)sizeof parsed);

    fcf = U_bstream_get_u8(&stream);
    parsed.frameType = (uint32_t)((fcf >> APS_FRAME_FCF_TYPE_SHIFT) & APS_FRAME_FCF_TYPE_MASK);
    parsed.deliveryMode = (uint32_t)((fcf >> APS_FRAME_FCF_DELIVERY_MODE_SHIFT) & APS_FRAME_FCF_DELIVERY_MODE_MASK);
    parsed.ackFormat = (fcf >> APS_FRAME_FCF_ACK_FORMAT_SHIFT) & APS_FRAME_FCF_ACK_FORMAT_MASK;
    parsed.securityEnabled = (fcf >> APS_FRAME_FCF_SECURITY_SHIFT) & APS_FRAME_FCF_SECURITY_MASK;
    parsed.ackRequest = (fcf >> APS_FRAME_FCF_ACK_REQUEST_SHIFT) & APS_FRAME_FCF_ACK_REQUEST_MASK;
    parsed.extendedHeaderPresent = (fcf >> APS_FRAME_FCF_EXTENDED_SHIFT) & APS_FRAME_FCF_EXTENDED_MASK;

    status = apsFrameFcfRules(&parsed);

    if (status != ZB_OK)
        return apsFrameAsDamage(status);

    apsFrameDeriveAddressPresence(&parsed);

    claimedLen = apsFrameBaseLen(&parsed)
                 + (parsed.extendedHeaderPresent ? APS_FRAME_EXT_CONTROL_OCTETS : 0);

    if (inLen < claimedLen)
        return ZB_ERR_BAD_FRAME;

    if (parsed.dstEndpointPresent)
        parsed.dstEndpoint = U_bstream_get_u8(&stream);

    if (parsed.groupAddressPresent)
        parsed.groupAddress = U_bstream_get_u16_le(&stream);

    if (parsed.clusterPresent)
        parsed.clusterId = U_bstream_get_u16_le(&stream);

    if (parsed.profilePresent)
        parsed.profileId = U_bstream_get_u16_le(&stream);

    if (parsed.srcEndpointPresent)
        parsed.srcEndpoint = U_bstream_get_u8(&stream);

    parsed.apsCounter = U_bstream_get_u8(&stream);

    if (parsed.extendedHeaderPresent)
    {
        parsed.extFrameControl = U_bstream_get_u8(&stream);
        parsed.fragmentation = (uint32_t)(parsed.extFrameControl & APS_FRAME_EXT_FRAGMENTATION_MASK);
        apsFrameDeriveExtendedPresence(&parsed);
    }

    status = apsFrameExtended(&parsed);

    if (status != ZB_OK)
        return apsFrameAsDamage(status);

    headerLen = claimedLen
                + (parsed.blockNumberPresent ? APS_FRAME_BLOCK_OCTETS : 0)
                + (parsed.ackBitfieldPresent ? APS_FRAME_ACK_BITFIELD_OCTETS : 0);

    if (inLen < headerLen)
        return ZB_ERR_BAD_FRAME;

    if (parsed.blockNumberPresent)
        parsed.blockNumber = U_bstream_get_u8(&stream);

    if (parsed.ackBitfieldPresent)
        parsed.ackBitfield = U_bstream_get_u8(&stream);

    status = apsFrameValues(&parsed);

    if (status != ZB_OK)
        return apsFrameAsDamage(status);

    if (!Zb_bstream_ok(&stream) || Zb_bstream_pos(&stream) != headerLen)
        return ZB_ERR_BAD_FRAME;

    *frame = parsed;
    *payloadOffset = headerLen;
    *payloadLen = inLen - headerLen;

    return ZB_OK;
}

int ApsFrame_IsKnownCommand(uint32_t id)
{
    if (id == APS_CMD_TRANSPORT_KEY
        || id == APS_CMD_UPDATE_DEVICE
        || id == APS_CMD_REMOVE_DEVICE
        || id == APS_CMD_REQUEST_KEY
        || id == APS_CMD_SWITCH_KEY
        || id == APS_CMD_TUNNEL
        || id == APS_CMD_VERIFY_KEY
        || id == APS_CMD_CONFIRM_KEY
        || id == APS_CMD_RELAY_MESSAGE_DOWNSTREAM
        || id == APS_CMD_RELAY_MESSAGE_UPSTREAM)
        return 1;

    return 0;
}
