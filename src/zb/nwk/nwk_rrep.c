#include "nwk.h"

#include "nwk_rrep.h"

#include "nwk_tlv.h"
#include "zb_bstream.h"
#include "zb_utils.h"

/* R23.1: 1.4.2, 3.4.2.3, 3.4.2.3.1, 3.4.2.3.5, 3.4.2.3.6, 3.4.2.3.7, 3.6.4.5.2, 3.6.7 ok (a reserved or deprecated bit is
   zeroed and ignored on receipt; the forward rewrites only the cost octet); 3.4.2.2, 3.4.2.3.4 elsewhere (the header
   the caller composes). */

ZbStatus Nwk_RrepCompose(const Nwk_RouteReplyPayload *reply, uint32_t *routingSeq,
                         uint8_t *out, uint32_t outMax, uint32_t *outLen)
{
    U_BStream stream;
    uint32_t nextRoutingSeq;

    if (reply == 0 || routingSeq == 0 || out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    U_bstream_init(&stream, out, (unsigned long)outMax);

    U_bstream_put_u8(&stream, NWK_CMD_ROUTE_REPLY);     
    U_bstream_put_u8(&stream, NWK_RREP_OPTIONS);        
    U_bstream_put_u8(&stream, reply->requestId);
    U_bstream_put_u16_le(&stream, reply->originatorAddr);
    U_bstream_put_u16_le(&stream, reply->responderAddr);
    U_bstream_put_u8(&stream, reply->pathCost);
    U_bstream_put_u64_le(&stream, reply->originatorIeee);
    U_bstream_put_u64_le(&stream, reply->responderIeee);

    nextRoutingSeq = (uint32_t)(uint16_t)(*routingSeq + 1);
    Nwk_TlvPutRoutingSequenceNumber(&stream, (uint16_t)nextRoutingSeq);   

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *routingSeq = nextRoutingSeq;
    *outLen = Zb_bstream_pos(&stream);

    return ZB_OK;
}

/* 3.4.2.3's fields, the TLV tail by nwk_tlv; Figure K-4 prints no radius in an RREP's extension, so K.5.4's
   2 x nwkcMaxDepth stands whatever octet arrived (I.2.4). */
ZbStatus Nwk_RrepParse(const uint8_t *payload, uint32_t payloadLen, Nwk_RouteReplyFields *out)
{
    U_BStream stream;
    Nwk_RouteReplyFields parsed;
    Nwk_TlvSet tlvs;
    Nwk_TlvOutcome outcome;
    uint32_t consumed;
    uint8_t options;

    if (payload == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payloadLen < NWK_RREP_FIXED_OCTETS)
        return ZB_ERR_BAD_FRAME;

    Zb_memset(&parsed, 0, (uint32_t)sizeof parsed);

    Zb_bstream_init_const(&stream, payload, payloadLen);

    (void)U_bstream_get_u8(&stream);
    options = U_bstream_get_u8(&stream);


    if ((options & NWK_RREP_OPTIONS) != NWK_RREP_OPTIONS)
        return ZB_ERR_BAD_FRAME;        

    parsed.requestId = U_bstream_get_u8(&stream);
    parsed.originatorAddr = U_bstream_get_u16_le(&stream);
    parsed.responderAddr = U_bstream_get_u16_le(&stream);
    parsed.pathCost = U_bstream_get_u8(&stream);

    if (payloadLen < NWK_RREP_FIXED_OCTETS + 2 * NWK_IEEE_ADDR_OCTETS)
        return ZB_ERR_BAD_FRAME;        

    parsed.originatorIeee = U_bstream_get_u64_le(&stream);
    parsed.responderIeee = U_bstream_get_u64_le(&stream);

    consumed = Zb_bstream_pos(&stream);
    outcome = Nwk_TlvRead(NWK_CMD_ROUTE_REPLY, payload + consumed, payloadLen - consumed, &tlvs);

    if (outcome == NWK_TLV_MALFORMED || outcome == NWK_TLV_DUPLICATE)
        return ZB_ERR_BAD_FRAME;

    parsed.tlvOutcome = outcome;
    parsed.extendedRouteInfo = tlvs.extendedRouteInfo;
    parsed.routingSequenceNumber = tlvs.routingSequenceNumber;
    parsed.initialRadius = NWK_INITIAL_RADIUS;  

    *out = parsed;

    return ZB_OK;
}

/* 3.6.4.5.2.1's forward: the received payload, its cost octet replaced, and K.3.1.1's record carried as it came */
ZbStatus Nwk_RrepForward(const uint8_t *received, uint32_t receivedLen, uint8_t pathCost,
                         uint8_t *out, uint32_t outMax, uint32_t *outLen)
{
    if (received == 0 || out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (receivedLen < NWK_RREP_FIXED_OCTETS + 2 * NWK_IEEE_ADDR_OCTETS)
        return ZB_ERR_BAD_FRAME;        

    if (receivedLen > outMax)
        return ZB_ERR_NO_SPACE;

    Zb_memcpy(out, received, receivedLen);
    out[NWK_RREP_PATH_COST_AT] = pathCost;

    *outLen = receivedLen;

    return ZB_OK;
}
