#include "nwk.h"

#include "nwk_rreq.h"

#include "nwk_tlv.h"
#include "zb_bstream.h"
#include "zb_utils.h"

/* R23.1: 1.4.2, 3.3.1.5, 3.4.1.3, 3.4.1.3.1, 3.4.1.3.1.2, 3.4.1.3.2, 3.4.1.3.4, 3.4.1.3.5, 3.6.4.5.1, 3.6.7 ok (a
   received frame's reserved and deprecated bits are zeroed and ignored, which is what the clause asks). */

/* Figure 3-10's bits 3-4 and 5; bit 6 is transmitted 0 (3.6.7) and bits 0-2 and 7 are reserved */
static uint8_t nwkRreqOptions(const Nwk_RouteRequestPayload *req)
{
    uint8_t options = (uint8_t)((req->manyToOne & NWK_RREQ_OPTION_MANY_TO_ONE_MASK)
                                << NWK_RREQ_OPTION_MANY_TO_ONE_SHIFT);

    if (req->destIeeePresent)
        options |= NWK_RREQ_OPTION_DEST_IEEE;

    return options;
}

/* Figure 3-9's fields up to the tail: the identifier, Figure 3-10's options, 3.4.1.3.2-3.4.1.3.5, the optional
   destination IEEE address, and nothing of Annex K.2.1, which tail a caller supplies, composed or as received */
static void nwkRreqPutFixed(U_BStream *stream, const Nwk_RouteRequestPayload *req)
{
    U_bstream_put_u8(stream, NWK_CMD_ROUTE_REQUEST);    
    U_bstream_put_u8(stream, nwkRreqOptions(req));
    U_bstream_put_u8(stream, req->requestId);
    U_bstream_put_u16_le(stream, req->destAddr);
    U_bstream_put_u8(stream, req->pathCost);

    if (req->destIeeePresent)
        U_bstream_put_u64_le(stream, req->destIeee);
}

ZbStatus Nwk_RreqCompose(const Nwk_RouteRequestPayload *req, uint32_t *routingSeq, uint8_t initialRadius,
                         uint8_t *out, uint32_t outMax, uint32_t *outLen)
{
    U_BStream stream;
    uint32_t nextRoutingSeq;

    if (req == 0 || routingSeq == 0 || out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (req->manyToOne > NWK_RREQ_MANY_TO_ONE_WITHOUT_RECORD)
        return ZB_ERR_BAD_ARGUMENT;     

    U_bstream_init(&stream, out, (unsigned long)outMax);

    nwkRreqPutFixed(&stream, req);

    nextRoutingSeq = (*routingSeq + 1) % NWK_ROUTE_SEQUENCE_WRAP;
    Nwk_TlvPutExtendedRouteInformation(&stream, (uint16_t)nextRoutingSeq, initialRadius);   

    if (req->concentrator && req->destAddr == NWK_ADDR_ROUTERS)
    {
        U_bstream_put_u8(&stream, NWK_TLV_TAG_CONCENTRATOR);
        U_bstream_put_u8(&stream, (unsigned char)(NWK_TLV_CONCENTRATOR_OCTETS - NWK_TLV_LENGTH_BIAS));
        U_bstream_put_u8(&stream, req->concentratorDiscoveryTime);
        U_bstream_put_u8(&stream, req->maxSourceRoute);
    }

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;         

    *routingSeq = nextRoutingSeq;
    *outLen = Zb_bstream_pos(&stream);

    return ZB_OK;
}

/* 3.6.4.5.1.2's relayed copy: the received payload with 3.4.1.3.4's path cost replaced by 9109-9110's forward
   cost and nothing else touched, so K.2.1.2's "MUST forward this TLV without modification" holds for the whole
   tail and 3.3.1.5's pair of source and sequence stays the originator's */
ZbStatus Nwk_RreqComposeRelay(const uint8_t *received, uint32_t receivedLen, uint8_t pathCost,
                              uint8_t *out, uint32_t outMax, uint32_t *outLen)
{
    U_BStream stream;
    uint32_t i;

    if (received == 0 || out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (receivedLen < NWK_RREQ_FIXED_OCTETS)
        return ZB_ERR_BAD_FRAME;

    U_bstream_init(&stream, out, (unsigned long)outMax);

    for (i = 0; i < receivedLen; i++)
    {
        if (i == NWK_RREQ_PATH_COST_OCTET)
            U_bstream_put_u8(&stream, pathCost);
        else
            U_bstream_put_u8(&stream, received[i]);
    }

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    *outLen = Zb_bstream_pos(&stream);

    return ZB_OK;
}

ZbStatus Nwk_RreqParse(const uint8_t *payload, uint32_t payloadLen, Nwk_RouteRequestFields *out)
{
    U_BStream stream;
    Nwk_RouteRequestFields parsed;
    Nwk_TlvSet tlvs;
    Nwk_TlvOutcome outcome;
    uint32_t consumed;
    uint8_t options;

    if (payload == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payloadLen < NWK_RREQ_FIXED_OCTETS)
        return ZB_ERR_BAD_FRAME;

    Zb_memset(&parsed, 0, (uint32_t)sizeof parsed);

    Zb_bstream_init_const(&stream, payload, payloadLen);

    (void)U_bstream_get_u8(&stream);    
    options = U_bstream_get_u8(&stream);


    parsed.manyToOne = ((uint32_t)options >> NWK_RREQ_OPTION_MANY_TO_ONE_SHIFT)
                       & NWK_RREQ_OPTION_MANY_TO_ONE_MASK;

    if (parsed.manyToOne == NWK_RREQ_OPTION_MANY_TO_ONE_RESERVED)
        parsed.manyToOne = NWK_RREQ_MANY_TO_ONE_NONE;

    parsed.destIeeePresent = (options & NWK_RREQ_OPTION_DEST_IEEE) ? 1 : 0;
    parsed.requestId = U_bstream_get_u8(&stream);
    parsed.destAddr = U_bstream_get_u16_le(&stream);
    parsed.pathCost = U_bstream_get_u8(&stream);

    if (parsed.destIeeePresent)
    {
        if (payloadLen < NWK_RREQ_FIXED_OCTETS + NWK_IEEE_ADDR_OCTETS)
            return ZB_ERR_BAD_FRAME;    

        parsed.destIeee = U_bstream_get_u64_le(&stream);
    }

    consumed = Zb_bstream_pos(&stream);
    outcome = Nwk_TlvRead(NWK_CMD_ROUTE_REQUEST, payload + consumed, payloadLen - consumed, &tlvs);

    if (outcome == NWK_TLV_MALFORMED || outcome == NWK_TLV_DUPLICATE)
        return ZB_ERR_BAD_FRAME;

    if (tlvs.extendedRouteInfo && !tlvs.initialRadiusPresent)
        return ZB_ERR_BAD_FRAME;        

    parsed.tlvOutcome = outcome;
    parsed.extendedRouteInfo = tlvs.extendedRouteInfo;
    parsed.routingSequenceNumber = tlvs.routingSequenceNumber;
    parsed.initialRadius = tlvs.extendedRouteInfo ? tlvs.initialRadius : NWK_INITIAL_RADIUS;
    parsed.concentratorInfoPresent = tlvs.concentratorInfo;
    parsed.solicitationPresent = tlvs.sourceRouteSolicitation;

    *out = parsed;

    return ZB_OK;
}
