#include "nwk.h"

#include "nwk_commissioning.h"

#include "zb_bstream.h"
#include "zb_utils.h"

/* R23.1: 3.4.14, 3.4.15, I.2.7, I.4.2, I.4.8, I.4.9 ok. */

/* Table I-1's record: the tag, the length as value-minus-one, then the value. */
static uint32_t nwkCommissioningTlvLen(uint32_t valueLen)
{
    return 2 + valueLen;
}

/* Table I-1's next record: its tag, and its value as a stream of its own length, so a field never reads past its
   record. */
static ZbStatus nwkCommissioningNext(U_BStream *list, uint32_t *tag, U_BStream *value)
{
    uint32_t len;

    if (!Zb_bstream_fits(list, 2))
        return ZB_ERR_BAD_ARGUMENT;

    *tag = U_bstream_get_u8(list);
    len = (uint32_t)U_bstream_get_u8(list) + 1;

    if (!Zb_bstream_fits(list, len))
        return ZB_ERR_BAD_ARGUMENT;

    Zb_bstream_sub(list, value, len);

    return ZB_OK;
}

/* One record other than an encapsulation, read when 3.4.14.3.3 names it and stepped over otherwise; Annex I carries
   an EUI-64 low octet first. */
static ZbStatus nwkCommissioningRecord(uint32_t tag, U_BStream *value, Nwk_CommissioningRequest *out)
{
    uint32_t len = Zb_bstream_remaining(value);

    if (tag == NWK_TLV_TAG_SUPPORTED_KEY_NEGOTIATION)
    {
        if (len < NWK_TLV_KEY_NEGOTIATION_MIN_OCTETS)
            return ZB_ERR_BAD_ARGUMENT;

        out->keyNegotiationPresent = 1;
        out->keyNegotiationProtocols = U_bstream_get_u8(value);
        out->preSharedSecrets = U_bstream_get_u8(value);

        if (len >= NWK_TLV_KEY_NEGOTIATION_OCTETS)
            out->sourceEui64 = U_bstream_get_u64_le(value);
    }
    else if (tag == NWK_TLV_TAG_FRAGMENTATION_PARAMETERS)
    {
        if (len != NWK_TLV_FRAGMENTATION_OCTETS)
            return ZB_ERR_BAD_ARGUMENT;

        out->nodeId = U_bstream_get_u16_le(value);
        out->fragmentationOptions = U_bstream_get_u8(value);
        out->maxIncomingTransferUnit = (uint32_t)U_bstream_get_u16_le(value);
    }

    return ZB_OK;
}

/* The records inside the Joiner Encapsulation: I.4.9 lets no encapsulation sit inside another, and I.2.7 step 3d
   refuses the message that has one, so this walk takes no encapsulation and never calls itself. */
static ZbStatus nwkCommissioningEncapsulated(U_BStream *list, Nwk_CommissioningRequest *out)
{
    U_BStream value;
    uint32_t tag;

    while (Zb_bstream_remaining(list) > 0)
    {
        if (nwkCommissioningNext(list, &tag, &value) != ZB_OK)
            return ZB_ERR_BAD_ARGUMENT;

        if (tag == NWK_TLV_TAG_JOINER_ENCAPSULATION || tag == NWK_TLV_TAG_BEACON_APPENDIX_ENCAPSULATION)
            return ZB_ERR_BAD_ARGUMENT;

        if (nwkCommissioningRecord(tag, &value, out) != ZB_OK)
            return ZB_ERR_BAD_ARGUMENT;
    }

    return ZB_OK;
}

/* The request's own records, walked to the ones 3.4.14.3.3 names: `sawEncapsulation` reports the Joiner
   Encapsulation, whose records are walked in their turn. */
static ZbStatus nwkCommissioningWalk(U_BStream *list, Nwk_CommissioningRequest *out, int *sawEncapsulation)
{
    U_BStream value;
    uint32_t tag;

    while (Zb_bstream_remaining(list) > 0)
    {
        if (nwkCommissioningNext(list, &tag, &value) != ZB_OK)
            return ZB_ERR_BAD_ARGUMENT;

        if (tag == NWK_TLV_TAG_JOINER_ENCAPSULATION)
        {
            *sawEncapsulation = 1;

            if (nwkCommissioningEncapsulated(&value, out) != ZB_OK)
                return ZB_ERR_BAD_ARGUMENT;
        }
        else if (nwkCommissioningRecord(tag, &value, out) != ZB_OK)
            return ZB_ERR_BAD_ARGUMENT;
    }

    return ZB_OK;
}

ZbStatus Nwk_CommissioningRequestParse(const uint8_t *payload, uint32_t payloadLen, Nwk_CommissioningRequest *out)
{
    U_BStream stream;
    int encapsulation;

    if (payload == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payloadLen < NWK_COMMISSIONING_OCTETS)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(out, 0, (uint32_t)sizeof *out);

    encapsulation = 0;
    Zb_bstream_init_const(&stream, payload, payloadLen);
    out->type = U_bstream_get_u8(&stream);
    out->capability = U_bstream_get_u8(&stream);

    if (out->type > NWK_COMMISSIONING_TRUSTED_LINK)
        return ZB_ERR_BAD_ARGUMENT;

    if (nwkCommissioningWalk(&stream, out, &encapsulation) != ZB_OK)
        return ZB_ERR_BAD_ARGUMENT;

    return encapsulation ? ZB_OK : ZB_ERR_BAD_ARGUMENT;
}

ZbStatus Nwk_CommissioningRequestCompose(const Nwk_CommissioningRequest *request, uint8_t *out, uint32_t outCap,
                                         uint32_t *outLen)
{
    U_BStream stream;
    uint32_t encapsulatedLen;
    uint32_t total;
    int keyNegotiation;

    if (request == 0 || out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (request->type > NWK_COMMISSIONING_TRUSTED_LINK)
        return ZB_ERR_BAD_ARGUMENT;

    keyNegotiation = request->type != NWK_COMMISSIONING_REJOIN;
    encapsulatedLen = nwkCommissioningTlvLen(NWK_TLV_FRAGMENTATION_OCTETS)
                      + (keyNegotiation ? nwkCommissioningTlvLen(NWK_TLV_KEY_NEGOTIATION_OCTETS) : 0);
    total = NWK_COMMISSIONING_OCTETS + nwkCommissioningTlvLen(encapsulatedLen);

    if (outCap < total)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outCap);
    U_bstream_put_u8(&stream, (uint8_t)request->type);
    U_bstream_put_u8(&stream, request->capability);

    U_bstream_put_u8(&stream, NWK_TLV_TAG_JOINER_ENCAPSULATION);
    U_bstream_put_u8(&stream, (uint8_t)(encapsulatedLen - 1));

    U_bstream_put_u8(&stream, NWK_TLV_TAG_FRAGMENTATION_PARAMETERS);
    U_bstream_put_u8(&stream, (uint8_t)(NWK_TLV_FRAGMENTATION_OCTETS - 1));
    U_bstream_put_u16_le(&stream, request->nodeId);
    U_bstream_put_u8(&stream, (uint8_t)(request->fragmentationOptions & 0xff));
    U_bstream_put_u16_le(&stream, (uint16_t)(request->maxIncomingTransferUnit & 0xffff));

    if (keyNegotiation)
    {
        U_bstream_put_u8(&stream, NWK_TLV_TAG_SUPPORTED_KEY_NEGOTIATION);
        U_bstream_put_u8(&stream, (uint8_t)(NWK_TLV_KEY_NEGOTIATION_OCTETS - 1));
        U_bstream_put_u8(&stream, (uint8_t)(request->keyNegotiationProtocols & 0xff));
        U_bstream_put_u8(&stream, (uint8_t)(request->preSharedSecrets & 0xff));
        U_bstream_put_u64_le(&stream, request->sourceEui64);
    }

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = Zb_bstream_pos(&stream);

    return ZB_OK;
}

ZbStatus Nwk_CommissioningResponseCompose(uint16_t networkAddress, uint8_t status, uint8_t *out, uint32_t outCap,
                                          uint32_t *outLen)
{
    U_BStream stream;

    if (out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (outCap < NWK_COMMISSIONING_RESPONSE_OCTETS)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outCap);
    U_bstream_put_u16_le(&stream, networkAddress);
    U_bstream_put_u8(&stream, status);

    *outLen = NWK_COMMISSIONING_RESPONSE_OCTETS;

    return ZB_OK;
}

ZbStatus Nwk_CommissioningResponseParse(const uint8_t *payload, uint32_t payloadLen, uint16_t *addressOut,
                                        uint8_t *statusOut)
{
    U_BStream stream;

    if (payload == 0 || addressOut == 0 || statusOut == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payloadLen != NWK_COMMISSIONING_RESPONSE_OCTETS)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_bstream_init_const(&stream, payload, payloadLen);
    *addressOut = U_bstream_get_u16_le(&stream);
    *statusOut = U_bstream_get_u8(&stream);

    return ZB_OK;
}
