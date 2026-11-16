#include "nwk_beacon.h"

#include "zb_bstream.h"
#include "zb_utils.h"

/* R23.1: 3.6.8.1, 3.6.8.2 ok (Table 3-83's fifteen octets, the field ranges, the read-back, an absent appendix accepted
   as a beacon this device reads, and the Router Information Global TLV the clause makes a minimum; an unknown TLV is
   ignored by never being read). */

ZbStatus Nwk_ComposeBeaconInfo(const Nwk_BeaconInfo *info, uint8_t *out, uint32_t outCap, uint32_t *outLen)
{
    U_BStream stream;

    if (info == 0 || out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (info->stackProfile > 0x0f || info->protocolVersion > 0x0f)
        return ZB_ERR_BAD_ARGUMENT;   

    if (info->deviceDepth != 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (info->txOffset > NWK_BEACON_TX_OFFSET_NONE)
        return ZB_ERR_BAD_ARGUMENT;   

    if (info->updateId > 0xff)
        return ZB_ERR_BAD_ARGUMENT;

    if (outCap < NWK_BEACON_INFO_LEN)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outCap);

    U_bstream_put_u8(&stream, NWK_BEACON_PROTOCOL_ID);
    U_bstream_put_u8(&stream, (uint8_t)((info->stackProfile & 0x0f) | ((info->protocolVersion & 0x0f) << 4)));

    U_bstream_put_u8(&stream, (uint8_t)((info->routerCapacity ? (1 << 2) : 0)
                                        | ((info->deviceDepth & 0x0f) << 3)
                                        | (info->endDeviceCapacity ? (1 << 7) : 0)));

    U_bstream_put_u64_le(&stream, info->extendedPanId);

    Zb_bstream_put_u24_le(&stream, info->txOffset);

    U_bstream_put_u8(&stream, (uint8_t)(info->updateId & 0xff));

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = NWK_BEACON_INFO_LEN;

    return ZB_OK;
}

/* 3.6.8.1: "Revision 23 devices SHALL accept beacons without this field", so an absent appendix is a beacon this
   device reads, with every field of it at its zero. */
ZbStatus Nwk_ParseBeaconInfo(const uint8_t *bytes, uint32_t len, Nwk_BeaconInfo *outInfo)
{
    U_BStream stream;
    Nwk_BeaconInfo info;
    uint32_t packed;

    if (bytes == 0 || outInfo == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (len < NWK_BEACON_INFO_LEN)
    {
        Zb_memset(outInfo, 0, (uint32_t)sizeof *outInfo);

        return ZB_OK;
    }

    Zb_memset(&info, 0, (uint32_t)sizeof info);
    Zb_bstream_init_const(&stream, bytes, len);

    info.protocolVersion = 0;

    if (U_bstream_get_u8(&stream) != NWK_BEACON_PROTOCOL_ID)
        return ZB_ERR_UNSUPPORTED;    /* Table 3-83 pins the protocol identifier to zero, docs/internals/protocol.md §9.2 */

    packed = U_bstream_get_u8(&stream);
    info.stackProfile = packed & 0x0f;
    info.protocolVersion = (packed >> 4) & 0x0f;

    packed = U_bstream_get_u8(&stream);
    info.routerCapacity = ((packed >> 2) & 1) != 0;
    info.deviceDepth = (packed >> 3) & 0x0f;
    info.endDeviceCapacity = ((packed >> 7) & 1) != 0;

    info.extendedPanId = U_bstream_get_u64_le(&stream);

    info.txOffset = Zb_bstream_get_u24_le(&stream);

    info.updateId = U_bstream_get_u8(&stream);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_BAD_FRAME;

    *outInfo = info;

    return ZB_OK;
}

ZbStatus Nwk_ComposeBeaconPayload(const Nwk_BeaconInfo *info, uint8_t *out, uint32_t outCap, uint32_t *outLen)
{
    U_BStream stream;
    uint32_t infoLen;
    ZbStatus status;

    if (out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    status = Nwk_ComposeBeaconInfo(info, out, outCap, &infoLen);

    if (status != ZB_OK)
        return status;

    if (outCap < (uint32_t)NWK_BEACON_PAYLOAD_LEN)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)NWK_BEACON_PAYLOAD_LEN);
    U_bstream_seek(&stream, (unsigned long)infoLen);
    U_bstream_put_u8(&stream, (uint8_t)NWK_BEACON_TLV_ROUTER_INFORMATION);
    U_bstream_put_u8(&stream, (uint8_t)(NWK_BEACON_TLV_ROUTER_INFO_VALUE_OCTETS - 1));
    U_bstream_put_u16_le(&stream, 0);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = (uint32_t)NWK_BEACON_PAYLOAD_LEN;

    return ZB_OK;
}

int Nwk_BeaconRouterInformation(const uint8_t *payload, uint32_t len, uint16_t *outBitmap)
{
    U_BStream stream;
    U_BStream value;
    uint32_t tag;
    uint32_t valueLen;
    int found = 0;
    uint16_t bitmap = 0;

    if (payload == 0 || len <= (uint32_t)NWK_BEACON_INFO_LEN)
        return 0;

    Zb_bstream_init_const(&stream, payload, len);
    U_bstream_seek(&stream, (unsigned long)NWK_BEACON_INFO_LEN);

    while (Zb_bstream_remaining(&stream) > 0)
    {
        if (!Zb_bstream_fits(&stream, 2))
            return 0;

        tag = U_bstream_get_u8(&stream);
        valueLen = (uint32_t)U_bstream_get_u8(&stream) + 1;

        if (!Zb_bstream_fits(&stream, valueLen))
            return 0;

        Zb_bstream_sub(&stream, &value, valueLen);

        if (tag == (uint32_t)NWK_BEACON_TLV_ROUTER_INFORMATION
            && valueLen >= (uint32_t)NWK_BEACON_TLV_ROUTER_INFO_VALUE_OCTETS)
        {
            found = 1;
            bitmap = U_bstream_get_u16_le(&value);
        }
    }

    if (found && outBitmap != 0)
        *outBitmap = bitmap;

    return found;
}

int Nwk_BeaconHasAppendix(const uint8_t *payload, uint32_t len)
{
    return Nwk_BeaconRouterInformation(payload, len, 0);
}
