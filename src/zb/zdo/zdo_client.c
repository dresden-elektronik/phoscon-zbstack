#include "zdo_client.h"

#include "nwk_commissioning.h"
#include "zb_bstream.h"
#include "zb_utils.h"

/* R23.1: 2.4.3.1.1, 2.4.3.1.2, 2.4.3.1.3, 2.4.3.1.3.1, 2.4.3.1.4, 2.4.3.1.5, 2.4.3.1.6, 2.4.3.1.7, 2.4.4.2.1,
   2.4.4.2.2, 2.4.4.2.7, I.4.8 ok. */

/* The stream's octets so far, or 0 when one did not fit. */
static uint32_t zdoClientLength(const U_BStream *stream)
{
    return Zb_bstream_ok(stream) ? Zb_bstream_pos(stream) : 0;
}

uint32_t ZdoClient_NwkAddrReq(uint64_t ieeeAddr, uint8_t requestType, uint8_t startIndex, uint8_t *out,
                              uint32_t outCap)
{
    U_BStream stream;

    if (out == 0)
        return 0;

    U_bstream_init(&stream, out, (unsigned long)outCap);
    U_bstream_put_u64_le(&stream, ieeeAddr);
    U_bstream_put_u8(&stream, requestType);
    U_bstream_put_u8(&stream, startIndex);

    return zdoClientLength(&stream);
}

uint32_t ZdoClient_IeeeAddrReq(uint16_t nwkAddrOfInterest, uint8_t requestType, uint8_t startIndex, uint8_t *out,
                               uint32_t outCap)
{
    U_BStream stream;

    if (out == 0)
        return 0;

    U_bstream_init(&stream, out, (unsigned long)outCap);
    U_bstream_put_u16_le(&stream, nwkAddrOfInterest);
    U_bstream_put_u8(&stream, requestType);
    U_bstream_put_u8(&stream, startIndex);

    return zdoClientLength(&stream);
}

uint32_t ZdoClient_NodeDescReq(const Zdo_Zdo *zdo, uint16_t nwkAddrOfInterest, uint8_t *out, uint32_t outCap)
{
    const Zdo_NodeDescriptor *node = Zdo_OwnNodeDescriptor(zdo);
    U_BStream stream;

    if (out == 0 || node == 0)
        return 0;

    U_bstream_init(&stream, out, (unsigned long)outCap);
    U_bstream_put_u16_le(&stream, nwkAddrOfInterest);
    U_bstream_put_u8(&stream, NWK_TLV_TAG_FRAGMENTATION_PARAMETERS);
    U_bstream_put_u8(&stream, (uint8_t)(NWK_TLV_FRAGMENTATION_OCTETS - 1));
    U_bstream_put_u16_le(&stream, Zdo_OwnAddress(zdo));
    U_bstream_put_u8(&stream, node->fragmentationSupported ? NWK_TLV_FRAGMENTATION_APS_BIT : 0);
    U_bstream_put_u16_le(&stream, node->maxIncomingTransferSize);

    return zdoClientLength(&stream);
}

/* A request that is only the address of interest. */
static uint32_t zdoClientAddressOnly(uint16_t nwkAddrOfInterest, uint8_t *out, uint32_t outCap)
{
    U_BStream stream;

    if (out == 0)
        return 0;

    U_bstream_init(&stream, out, (unsigned long)outCap);
    U_bstream_put_u16_le(&stream, nwkAddrOfInterest);

    return zdoClientLength(&stream);
}

uint32_t ZdoClient_PowerDescReq(uint16_t nwkAddrOfInterest, uint8_t *out, uint32_t outCap)
{
    return zdoClientAddressOnly(nwkAddrOfInterest, out, outCap);
}

uint32_t ZdoClient_ActiveEpReq(uint16_t nwkAddrOfInterest, uint8_t *out, uint32_t outCap)
{
    return zdoClientAddressOnly(nwkAddrOfInterest, out, outCap);
}

uint32_t ZdoClient_SimpleDescReq(uint16_t nwkAddrOfInterest, uint8_t endPoint, uint8_t *out, uint32_t outCap)
{
    U_BStream stream;

    if (out == 0)
        return 0;

    U_bstream_init(&stream, out, (unsigned long)outCap);
    U_bstream_put_u16_le(&stream, nwkAddrOfInterest);
    U_bstream_put_u8(&stream, endPoint);

    return zdoClientLength(&stream);
}

uint32_t ZdoClient_MatchDescReq(uint16_t nwkAddrOfInterest, uint16_t profileId, const uint16_t *inClusterList,
                                uint32_t numInClusters, const uint16_t *outClusterList, uint32_t numOutClusters,
                                uint8_t *out, uint32_t outCap)
{
    U_BStream stream;
    uint32_t i;

    if (out == 0 || numInClusters > 0xff || numOutClusters > 0xff || (inClusterList == 0 && numInClusters != 0)
        || (outClusterList == 0 && numOutClusters != 0))
        return 0;

    U_bstream_init(&stream, out, (unsigned long)outCap);
    U_bstream_put_u16_le(&stream, nwkAddrOfInterest);
    U_bstream_put_u16_le(&stream, profileId);
    U_bstream_put_u8(&stream, (uint8_t)numInClusters);

    for (i = 0; i < numInClusters; i++)
        U_bstream_put_u16_le(&stream, inClusterList[i]);

    U_bstream_put_u8(&stream, (uint8_t)numOutClusters);

    for (i = 0; i < numOutClusters; i++)
        U_bstream_put_u16_le(&stream, outClusterList[i]);

    return zdoClientLength(&stream);
}

ZbStatus ZdoClient_Status(const uint8_t *payload, uint32_t length, uint8_t *status)
{
    if (payload == 0 || status == 0 || length == 0)
        return ZB_ERR_BAD_FRAME;

    *status = payload[0];

    return ZB_OK;
}

ZbStatus ZdoClient_AddressResponseParse(const uint8_t *payload, uint32_t length, ZdoClient_AddressResponse *out)
{
    U_BStream stream;
    uint32_t i;

    if (out == 0 || payload == 0 || length == 0)
        return ZB_ERR_BAD_FRAME;

    Zb_memset(out, 0, (uint32_t)sizeof *out);
    Zb_bstream_init_const(&stream, payload, length);
    out->status = U_bstream_get_u8(&stream);
    out->ieeeAddrRemoteDev = U_bstream_get_u64_le(&stream);
    out->nwkAddrRemoteDev = U_bstream_get_u16_le(&stream);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_BAD_FRAME;

    if (Zb_bstream_remaining(&stream) == 0)
        return ZB_OK;

    out->numAssocDev = U_bstream_get_u8(&stream);

    if (out->numAssocDev == 0 && Zb_bstream_remaining(&stream) == 0)
        return ZB_OK;

    out->startIndex = U_bstream_get_u8(&stream);

    if (out->numAssocDev > ZDOCLIENT_ASSOC_MAX || !Zb_bstream_fits(&stream, (uint32_t)out->numAssocDev * 2))
        return ZB_ERR_BAD_FRAME;

    for (i = 0; i < out->numAssocDev; i++)
        out->nwkAddrAssocDevList[i] = U_bstream_get_u16_le(&stream);

    return Zb_bstream_ok(&stream) && Zb_bstream_remaining(&stream) == 0 ? ZB_OK : ZB_ERR_BAD_FRAME;
}

ZbStatus ZdoClient_MatchDescRspParse(const uint8_t *payload, uint32_t length, uint8_t *status,
                                     uint16_t *nwkAddrOfInterest, uint8_t *matchList, uint32_t matchMax,
                                     uint32_t *matchLength)
{
    U_BStream stream;
    uint32_t count;

    if (payload == 0 || status == 0 || nwkAddrOfInterest == 0 || matchLength == 0 || length < 4)
        return ZB_ERR_BAD_FRAME;

    Zb_bstream_init_const(&stream, payload, length);
    *status = U_bstream_get_u8(&stream);
    *nwkAddrOfInterest = U_bstream_get_u16_le(&stream);
    count = U_bstream_get_u8(&stream);

    if (count > matchMax || (matchList == 0 && count != 0) || !Zb_bstream_fits(&stream, count))
        return ZB_ERR_BAD_FRAME;

    if (count != 0)
        U_bstream_get_bytes(&stream, matchList, (unsigned long)count);

    *matchLength = count;

    return ZB_OK;
}
