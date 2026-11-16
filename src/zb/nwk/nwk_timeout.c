#include "nwk.h"

#include "nwk_timeout.h"

#include "zb_utils.h"

/* R23.1: 3.4.11, 3.4.12, 3.6.10 ok. */

/* Table 3-58: 10 seconds, then two minutes and doubling to 16384 minutes at enumeration 14. */
uint32_t Nwk_TimeoutSeconds(uint32_t enumeration)
{
    uint32_t minutes;

    if (enumeration > NWK_TIMEOUT_MAX)
        return 0;

    if (enumeration == 0)
        return NWK_TIMEOUT_SECONDS_FIRST;

    minutes = NWK_TIMEOUT_MINUTES_FIRST << (enumeration - 1);

    return minutes * 60;
}

void Nwk_TimeoutDefault(Nwk_NeighborTableEntry *entry, uint32_t nowMs)
{
    if (entry == 0)
        return;

    entry->deviceTimeout = Nwk_TimeoutSeconds(NWK_END_DEVICE_TIMEOUT_DEFAULT);

    Nwk_TimeoutRestart(entry, nowMs);
}

void Nwk_TimeoutRestart(Nwk_NeighborTableEntry *entry, uint32_t nowMs)
{
    if (entry == 0)
        return;

    entry->timeoutCounter = entry->deviceTimeout;
    entry->timeoutMs = nowMs;
    entry->timeoutStarted = 1;
}

ZbStatus Nwk_TimeoutRequestParse(const uint8_t *payload, uint32_t payloadLen, uint32_t *enumerationOut,
                                 uint8_t *configurationOut)
{
    if (payload == 0 || enumerationOut == 0 || configurationOut == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payloadLen != NWK_TIMEOUT_REQUEST_OCTETS)
        return ZB_ERR_BAD_ARGUMENT;

    *enumerationOut = payload[0];
    *configurationOut = payload[1];

    return ZB_OK;
}

ZbStatus Nwk_TimeoutRequestCompose(uint32_t enumeration, uint8_t configuration, uint8_t *out, uint32_t outCap,
                                   uint32_t *outLen)
{
    if (out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (enumeration > NWK_TIMEOUT_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (outCap < NWK_TIMEOUT_REQUEST_OCTETS)
        return ZB_ERR_NO_SPACE;

    out[0] = (uint8_t)enumeration;
    out[1] = configuration;

    *outLen = NWK_TIMEOUT_REQUEST_OCTETS;

    return ZB_OK;
}

/* The response's own payload, which is the parent's word on the request it just read. */
ZbStatus Nwk_TimeoutResponseCompose(uint8_t status, uint8_t parentInformation, uint8_t *out, uint32_t outCap,
                                    uint32_t *outLen)
{
    if (out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (outCap < NWK_TIMEOUT_RESPONSE_OCTETS)
        return ZB_ERR_NO_SPACE;

    out[0] = status;
    out[1] = parentInformation;

    *outLen = NWK_TIMEOUT_RESPONSE_OCTETS;

    return ZB_OK;
}

ZbStatus Nwk_TimeoutResponseParse(const uint8_t *payload, uint32_t payloadLen, uint8_t *statusOut,
                                  uint8_t *parentInformationOut)
{
    if (payload == 0 || statusOut == 0 || parentInformationOut == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payloadLen != NWK_TIMEOUT_RESPONSE_OCTETS)
        return ZB_ERR_BAD_ARGUMENT;

    *statusOut = payload[0];
    *parentInformationOut = payload[1];

    return ZB_OK;
}
