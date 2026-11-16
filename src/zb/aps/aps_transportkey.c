#include "aps.h"

#include "aps_transportkey.h"

#include "zb_utils.h"

/* R23.1 1.2.3 2.2.5 4.4.11.1.2 4.4.11.1.3 4.4.11.1.3.1 4.4.11.1.3.2 4.4.11.1.3.3 4.4.11.1.4 ok (the three types, the three
   descriptors' octet counts and field orders, the octet order, and the TLV run's frame); 4.4.2.1.3 elsewhere (the door
   that composes the frame owns the source address). docs/internals/conformance.md page 461-463. */

/* How many octets a body of this type occupies before its TLVs, the StandardKeyType octet included, or 0 for a type
   this profile does not implement. */
static uint32_t apsTransportKeyFixedLen(uint32_t standardKeyType)
{
    if (standardKeyType == APS_TK_TYPE_NETWORK_KEY)
        return APS_TK_NETWORK_BODY_OCTETS;

    if (standardKeyType == APS_TK_TYPE_TC_LINK_KEY)
        return APS_TK_TC_LINK_BODY_OCTETS;

    if (standardKeyType == APS_TK_TYPE_APPLICATION_LINK_KEY)
        return APS_TK_APP_LINK_BODY_OCTETS;

    return 0;
}

/* Figure 4-10 prints no TLV sub-field for a network key, so a descriptor of that type ends at its source address. */
static int apsTransportKeyTakesTlvs(uint32_t standardKeyType)
{
    return standardKeyType != APS_TK_TYPE_NETWORK_KEY;
}

/* The run of TLVs a descriptor may end in: each is a tag, a length and that many octets of value, and the run fills the
   tail exactly. The values are carried, never interpreted: only the frame around them is checked. */
static int apsTransportKeyTlvsAreWhole(const uint8_t *tlvs, uint32_t tlvLen)
{
    uint32_t at = 0;

    while (at < tlvLen)
    {
        if (tlvLen - at < 2)
            return 0;

        if ((uint32_t)tlvs[at + 1] > tlvLen - at - 2)
            return 0;

        at = at + 2 + (uint32_t)tlvs[at + 1];
    }

    return 1;
}

ZbStatus Aps_TransportKeyCompose(const Aps_TransportKey *tk, uint8_t *out, uint32_t outMax, uint32_t *outLen)
{
    U_BStream stream;
    uint32_t fixedLen;
    uint32_t total;

    if (tk == 0 || out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (tk->initiator != 0 && tk->initiator != 1)
        return ZB_ERR_BAD_ARGUMENT;

    fixedLen = apsTransportKeyFixedLen(tk->standardKeyType);

    if (fixedLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (tk->tlvLen != 0)
    {
        if (tk->tlvs == 0 || !apsTransportKeyTakesTlvs(tk->standardKeyType))
            return ZB_ERR_BAD_ARGUMENT;

        if (!apsTransportKeyTlvsAreWhole(tk->tlvs, tk->tlvLen))
            return ZB_ERR_BAD_ARGUMENT;

        if (tk->tlvLen > outMax)
            return ZB_ERR_NO_SPACE;
    }

    total = fixedLen + tk->tlvLen;

    if (total > outMax)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outMax);
    U_bstream_put_u8(&stream, (uint8_t)tk->standardKeyType);
    U_bstream_put_bytes(&stream, tk->key, APS_TK_KEY_OCTETS);

    if (tk->standardKeyType == APS_TK_TYPE_NETWORK_KEY)
    {
        U_bstream_put_u8(&stream, tk->keySeqNumber);
        U_bstream_put_u64_le(&stream, tk->destinationIeee);
        U_bstream_put_u64_le(&stream, tk->sourceIeee);
    }
    else if (tk->standardKeyType == APS_TK_TYPE_TC_LINK_KEY)
    {
        U_bstream_put_u64_le(&stream, tk->destinationIeee);
        U_bstream_put_u64_le(&stream, tk->sourceIeee);
    }
    else
    {
        U_bstream_put_u64_le(&stream, tk->partnerIeee);
        U_bstream_put_u8(&stream, (uint8_t)tk->initiator);
    }

    if (tk->tlvLen != 0)
        U_bstream_put_bytes(&stream, tk->tlvs, (unsigned long)tk->tlvLen);

    if (!Zb_bstream_ok(&stream) || Zb_bstream_pos(&stream) != total)
        return ZB_ERR_NO_SPACE;

    *outLen = total;

    return ZB_OK;
}

ZbStatus Aps_TransportKeyParse(const uint8_t *body, uint32_t bodyLen, Aps_TransportKey *out)
{
    U_BStream stream;
    uint32_t fixedLen;
    uint32_t standardKeyType;
    int initiatorOctet;

    if (body == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (bodyLen < 1)
        return ZB_ERR_BAD_ARGUMENT;

    standardKeyType = body[0];
    fixedLen = apsTransportKeyFixedLen(standardKeyType);

    if (fixedLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (bodyLen < fixedLen)
        return ZB_ERR_BAD_ARGUMENT;

    if (!apsTransportKeyTakesTlvs(standardKeyType) && bodyLen != fixedLen)
        return ZB_ERR_BAD_ARGUMENT;

    if (!apsTransportKeyTlvsAreWhole(body + fixedLen, bodyLen - fixedLen))
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(out, 0, (uint32_t)sizeof *out);
    out->standardKeyType = standardKeyType;

    Zb_bstream_init_const(&stream, body, bodyLen);
    U_bstream_advance(&stream, 1);
    U_bstream_get_bytes(&stream, out->key, APS_TK_KEY_OCTETS);

    if (standardKeyType == APS_TK_TYPE_NETWORK_KEY)
    {
        out->keySeqNumber = U_bstream_get_u8(&stream);
        out->destinationIeee = U_bstream_get_u64_le(&stream);
        out->sourceIeee = U_bstream_get_u64_le(&stream);
    }
    else if (standardKeyType == APS_TK_TYPE_TC_LINK_KEY)
    {
        out->destinationIeee = U_bstream_get_u64_le(&stream);
        out->sourceIeee = U_bstream_get_u64_le(&stream);
    }
    else
    {
        out->partnerIeee = U_bstream_get_u64_le(&stream);

        initiatorOctet = U_bstream_get_u8(&stream);
        out->initiator = (initiatorOctet == 1) ? 1 : 0;
    }

    if (!Zb_bstream_ok(&stream) || Zb_bstream_pos(&stream) != fixedLen)
    {
        Zb_memset(out, 0, (uint32_t)sizeof *out);
        return ZB_ERR_BAD_ARGUMENT;
    }

    out->tlvs = body + fixedLen;
    out->tlvLen = bodyLen - fixedLen;

    return ZB_OK;
}
