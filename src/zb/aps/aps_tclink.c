#include "aps_tclink.h"

#include "zb_bstream.h"
#include "zb_utils.h"

/* R23.1 1.2.3 4.4.11.4 4.4.11.4.2 4.4.11.4.3 4.4.11.7 4.4.11.7.3 4.4.11.8 ok (the three bodies' field orders and octet
   counts, the RequestKeyType's own table, the partner field's one case); 4.4.5.2 4.4.7.2.3 4.4.8.1 4.4.11.7.4 4.7.3.8
   4.7.3.8.1 elsewhere (`aps.c` decides what a trust centre does with them, `security.c` computes the hash).
   docs/internals/conformance.md pages 443-449, 466-468, 519. */

ZbStatus Aps_RequestKeyParse(const uint8_t *body, uint32_t bodyLen, Aps_RequestKey *out)
{
    U_BStream stream;
    Aps_RequestKey parsed;

    if (body == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (bodyLen < APS_TCLINK_REQUEST_TC_OCTETS)
        return ZB_ERR_BAD_FRAME;

    Zb_memset(&parsed, 0, (uint32_t)sizeof parsed);
    parsed.requestKeyType = body[0];

    if (parsed.requestKeyType == APS_TCLINK_REQUEST_APPLICATION_KEY)
    {
        if (bodyLen != APS_TCLINK_REQUEST_APP_OCTETS)
            return ZB_ERR_BAD_FRAME;

        Zb_bstream_init_const(&stream, body, bodyLen);
        U_bstream_advance(&stream, 1);
        parsed.partnerIeee = U_bstream_get_u64_le(&stream);
    }
    else if (bodyLen != APS_TCLINK_REQUEST_TC_OCTETS)
        return ZB_ERR_BAD_FRAME;

    *out = parsed;

    return ZB_OK;
}

ZbStatus Aps_VerifyKeyParse(const uint8_t *body, uint32_t bodyLen, Aps_VerifyKey *out)
{
    U_BStream stream;
    Aps_VerifyKey parsed;

    if (body == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (bodyLen != APS_TCLINK_VERIFY_OCTETS)
        return ZB_ERR_BAD_FRAME;

    Zb_bstream_init_const(&stream, body, bodyLen);

    parsed.standardKeyType = U_bstream_get_u8(&stream);
    parsed.sourceIeee = U_bstream_get_u64_le(&stream);
    U_bstream_get_bytes(&stream, parsed.hash, APS_TCLINK_HASH_OCTETS);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_BAD_FRAME;

    *out = parsed;

    return ZB_OK;
}

ZbStatus Aps_ConfirmKeyCompose(uint8_t status, uint8_t standardKeyType, uint64_t destinationIeee, uint8_t *out,
                               uint32_t outMax, uint32_t *outLen)
{
    U_BStream stream;

    if (out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (outMax < 1 + APS_TCLINK_CONFIRM_OCTETS)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outMax);
    U_bstream_put_u8(&stream, APS_TCLINK_CONFIRM_KEY_ID);
    U_bstream_put_u8(&stream, status);
    U_bstream_put_u8(&stream, standardKeyType);
    U_bstream_put_u64_le(&stream, destinationIeee);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = 1 + APS_TCLINK_CONFIRM_OCTETS;

    return ZB_OK;
}

ZbStatus Aps_RequestKeyCompose(uint8_t requestKeyType, uint8_t *out, uint32_t outMax, uint32_t *outLen)
{
    if (out == 0 || outLen == 0 || requestKeyType != APS_TCLINK_REQUEST_TC_LINK_KEY)
        return ZB_ERR_BAD_ARGUMENT;

    if (outMax < 1 + APS_TCLINK_REQUEST_TC_OCTETS)
        return ZB_ERR_NO_SPACE;

    out[0] = APS_TCLINK_REQUEST_KEY_ID;
    out[1] = requestKeyType;
    *outLen = 1 + APS_TCLINK_REQUEST_TC_OCTETS;

    return ZB_OK;
}

ZbStatus Aps_VerifyKeyCompose(const Aps_VerifyKey *verify, uint8_t *out, uint32_t outMax, uint32_t *outLen)
{
    U_BStream stream;

    if (verify == 0 || out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (outMax < 1 + APS_TCLINK_VERIFY_OCTETS)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outMax);
    U_bstream_put_u8(&stream, APS_TCLINK_VERIFY_KEY_ID);
    U_bstream_put_u8(&stream, verify->standardKeyType);
    U_bstream_put_u64_le(&stream, verify->sourceIeee);
    U_bstream_put_bytes(&stream, verify->hash, APS_TCLINK_HASH_OCTETS);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = 1 + APS_TCLINK_VERIFY_OCTETS;

    return ZB_OK;
}

ZbStatus Aps_ConfirmKeyParse(const uint8_t *body, uint32_t bodyLen, Aps_ConfirmKey *out)
{
    U_BStream stream;
    Aps_ConfirmKey parsed;

    if (body == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (bodyLen != APS_TCLINK_CONFIRM_OCTETS)
        return ZB_ERR_BAD_FRAME;

    Zb_bstream_init_const(&stream, body, bodyLen);

    parsed.status = U_bstream_get_u8(&stream);
    parsed.standardKeyType = U_bstream_get_u8(&stream);
    parsed.destinationIeee = U_bstream_get_u64_le(&stream);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_BAD_FRAME;

    *out = parsed;

    return ZB_OK;
}
