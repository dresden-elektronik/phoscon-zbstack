#include "aps_admit.h"

#include "aps_frame.h"
#include "security.h"
#include "zb_bstream.h"
#include "zb_utils.h"

/* R23.1 1.2.3 4.4.3.1.1 4.4.11.2 4.4.11.2.2 4.4.11.2.3 4.4.11.2.4 4.4.11.2.5 4.4.11.3 4.4.11.3.2 4.4.11.6 4.4.11.6.2
   4.4.11.6.3 4.4.11.6.4 4.5.1 ok (the three bodies' field orders and octet counts, Table 4-14's status and short
   address ranges, the tunnelled frame's link key and extended nonce); 4.4.3.2.3 4.4.4.2.3 4.6.3.2.1 4.6.3.6.2
   4.6.3.7.1 4.6.3.7.2 elsewhere (`aps.c` decides who sends and accepts them, `security.c` secures what a Tunnel
   carries). docs/internals/conformance.md pages 45, 438-441, 465, 467, 477, 483, 495-497. */

ZbStatus Aps_UpdateDeviceParse(const uint8_t *body, uint32_t bodyLen, Aps_UpdateDevice *out)
{
    U_BStream stream;
    Aps_UpdateDevice parsed;

    if (body == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (bodyLen < APS_UPDATE_DEVICE_OCTETS)
        return ZB_ERR_BAD_FRAME;

    Zb_memset(&parsed, 0, (uint32_t)sizeof parsed);
    Zb_bstream_init_const(&stream, body, bodyLen);

    parsed.deviceIeee = U_bstream_get_u64_le(&stream);
    parsed.deviceShortAddress = U_bstream_get_u16_le(&stream);
    parsed.status = U_bstream_get_u8(&stream);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_BAD_FRAME;

    if (bodyLen > APS_UPDATE_DEVICE_OCTETS)
    {
        parsed.joinerTlvs = body + APS_UPDATE_DEVICE_OCTETS;
        parsed.joinerTlvLen = bodyLen - APS_UPDATE_DEVICE_OCTETS;
    }

    *out = parsed;

    return ZB_OK;
}

ZbStatus Aps_UpdateDeviceCompose(const Aps_UpdateDevice *in, uint8_t *out, uint32_t outMax, uint32_t *outLen)
{
    U_BStream stream;
    uint32_t len;

    if (in == 0 || out == 0 || outLen == 0 || (in->joinerTlvLen != 0 && in->joinerTlvs == 0))
        return ZB_ERR_BAD_ARGUMENT;

    if (in->status > APS_UPDATE_DEVICE_TC_REJOIN || in->deviceShortAddress < APS_UPDATE_DEVICE_SHORT_MIN
        || in->deviceShortAddress > APS_UPDATE_DEVICE_SHORT_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    len = APS_FRAME_COMMAND_ID_OCTETS + APS_UPDATE_DEVICE_OCTETS + in->joinerTlvLen;

    if (outMax < len)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outMax);
    U_bstream_put_u8(&stream, APS_CMD_UPDATE_DEVICE);
    U_bstream_put_u64_le(&stream, in->deviceIeee);
    U_bstream_put_u16_le(&stream, in->deviceShortAddress);
    U_bstream_put_u8(&stream, in->status);

    if (in->joinerTlvLen != 0)
        U_bstream_put_bytes(&stream, in->joinerTlvs, (unsigned long)in->joinerTlvLen);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = len;

    return ZB_OK;
}

ZbStatus Aps_RemoveDeviceParse(const uint8_t *body, uint32_t bodyLen, uint64_t *targetIeee)
{
    U_BStream stream;
    uint64_t target;

    if (body == 0 || targetIeee == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (bodyLen != APS_REMOVE_DEVICE_OCTETS)
        return ZB_ERR_BAD_FRAME;

    Zb_bstream_init_const(&stream, body, bodyLen);
    target = U_bstream_get_u64_le(&stream);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_BAD_FRAME;

    *targetIeee = target;

    return ZB_OK;
}

ZbStatus Aps_RemoveDeviceCompose(uint64_t targetIeee, uint8_t *out, uint32_t outMax, uint32_t *outLen)
{
    U_BStream stream;

    if (out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (outMax < APS_FRAME_COMMAND_ID_OCTETS + APS_REMOVE_DEVICE_OCTETS)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outMax);
    U_bstream_put_u8(&stream, APS_CMD_REMOVE_DEVICE);
    U_bstream_put_u64_le(&stream, targetIeee);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = APS_FRAME_COMMAND_ID_OCTETS + APS_REMOVE_DEVICE_OCTETS;

    return ZB_OK;
}

/* Whether the octets are a tunnelled command: Figure 2-8's two-octet header with security on and no extended header,
   then an auxiliary frame naming a link-derived key and carrying the extended nonce. */
static int apsAdmitIsTunnelled(const uint8_t *secured, uint32_t securedLen)
{
    uint32_t fcf;
    uint32_t control;
    uint32_t keyId;

    if (securedLen < APS_TUNNEL_SECURED_MIN)
        return 0;

    fcf = secured[0];
    control = secured[APS_TUNNEL_HEADER_OCTETS];
    keyId = (control >> SECURITY_CONTROL_KEY_ID_SHIFT) & SECURITY_CONTROL_KEY_ID_MASK;

    return ((fcf >> APS_FRAME_FCF_TYPE_SHIFT) & APS_FRAME_FCF_TYPE_MASK) == APS_FRAME_TYPE_COMMAND
           && ((fcf >> APS_FRAME_FCF_SECURITY_SHIFT) & APS_FRAME_FCF_SECURITY_MASK) == 1
           && ((fcf >> APS_FRAME_FCF_EXTENDED_SHIFT) & APS_FRAME_FCF_EXTENDED_MASK) == 0
           && ((control >> SECURITY_CONTROL_EXTENDED_NONCE_SHIFT) & SECURITY_CONTROL_EXTENDED_NONCE_MASK) == 1
           && keyId != SECURITY_KEY_ID_NETWORK;
}

ZbStatus Aps_TunnelParse(const uint8_t *body, uint32_t bodyLen, Aps_Tunnel *out)
{
    U_BStream stream;
    Aps_Tunnel parsed;

    if (body == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (bodyLen < APS_TUNNEL_DEST_OCTETS
        || !apsAdmitIsTunnelled(body + APS_TUNNEL_DEST_OCTETS, bodyLen - APS_TUNNEL_DEST_OCTETS))
        return ZB_ERR_BAD_FRAME;

    Zb_bstream_init_const(&stream, body, bodyLen);
    parsed.destinationIeee = U_bstream_get_u64_le(&stream);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_BAD_FRAME;

    parsed.secured = body + APS_TUNNEL_DEST_OCTETS;
    parsed.securedLen = bodyLen - APS_TUNNEL_DEST_OCTETS;

    *out = parsed;

    return ZB_OK;
}

ZbStatus Aps_TunnelCompose(uint64_t destinationIeee, const uint8_t *secured, uint32_t securedLen, uint8_t *out,
                           uint32_t outMax, uint32_t *outLen)
{
    U_BStream stream;
    uint32_t len;

    if (secured == 0 || out == 0 || outLen == 0 || !apsAdmitIsTunnelled(secured, securedLen))
        return ZB_ERR_BAD_ARGUMENT;

    len = APS_FRAME_COMMAND_ID_OCTETS + APS_TUNNEL_DEST_OCTETS + securedLen;

    if (outMax < len)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outMax);
    U_bstream_put_u8(&stream, APS_CMD_TUNNEL);
    U_bstream_put_u64_le(&stream, destinationIeee);
    U_bstream_put_bytes(&stream, secured, (unsigned long)securedLen);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = len;

    return ZB_OK;
}
