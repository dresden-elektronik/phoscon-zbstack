#include "af.h"

#include "zb_utils.h"

/* R23.1: 2.3.1.3, 2.3.2.5, 2.3.2.5.1, 2.2.4.1.1, Table 2-2 ok; the ZDO endpoint's commands are `zdo`'s. */

ZbStatus Af_Init(Af_Af *self, Aps_Aps *aps)
{
    if (self == 0 || aps == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(self, 0, (uint32_t)sizeof *self);
    self->aps = aps;

    return ZB_OK;
}

/* 2.3.2.5.1's endpoint range and Table 2-40's own counts, tested before an endpoint is advertised. */
ZbStatus Af_DescriptorCheck(const Af_SimpleDescriptor *descriptor)
{

    if (descriptor == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (descriptor->endpoint < AF_ENDPOINT_FIRST || descriptor->endpoint > AF_ENDPOINT_LAST)
        return ZB_ERR_BAD_ARGUMENT;

    if (descriptor->deviceVersion > AF_DEVICE_VERSION_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (descriptor->inputClusterCount > AF_CLUSTER_MAX || descriptor->outputClusterCount > AF_CLUSTER_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    return ZB_OK;
}

ZbStatus Af_RegisterEndpoint(Af_Af *self, const Af_SimpleDescriptor *descriptor, Af_Handler handler, void *context)
{
    Af_Endpoint *endpoint;
    uint32_t i;

    if (self == 0 || descriptor == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (Af_DescriptorCheck(descriptor) != ZB_OK)
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < AF_ENDPOINT_MAX; i++)
    {
        if (self->endpoints[i].inUse && self->endpoints[i].descriptor.endpoint == descriptor->endpoint)
        {
            endpoint = &self->endpoints[i];
            goto fill;
        }
    }

    for (i = 0; i < AF_ENDPOINT_MAX; i++)
    {
        if (!self->endpoints[i].inUse)
        {
            endpoint = &self->endpoints[i];
            goto fill;
        }
    }

    return ZB_ERR_NO_SPACE;

fill:
    Zb_memset(endpoint, 0, (uint32_t)sizeof *endpoint);

    endpoint->inUse = 1;
    endpoint->descriptor = *descriptor;
    endpoint->handler = handler;
    endpoint->context = context;

    return ZB_OK;
}

/* The device profile's endpoint: 0x0000's profile and no clusters, because its commands are the ZDP's and not a
   cluster's. */
ZbStatus Af_RegisterDeviceProfile(Af_Af *self, Af_Handler handler, void *context)
{
    Af_Endpoint *endpoint;
    uint32_t i;

    if (self == 0)
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < AF_ENDPOINT_MAX; i++)
    {
        if (!self->endpoints[i].inUse)
            continue;

        if (self->endpoints[i].descriptor.endpoint != AF_ENDPOINT_ZDO)
            continue;

        self->endpoints[i].handler = handler;
        self->endpoints[i].context = context;

        return ZB_OK;
    }

    for (i = 0; i < AF_ENDPOINT_MAX; i++)
    {
        if (self->endpoints[i].inUse)
            continue;

        endpoint = &self->endpoints[i];
        Zb_memset(endpoint, 0, (uint32_t)sizeof *endpoint);

        endpoint->inUse = 1;
        endpoint->descriptor.endpoint = AF_ENDPOINT_ZDO;
        endpoint->descriptor.profileId = 0x0000;
        endpoint->handler = handler;
        endpoint->context = context;

        return ZB_OK;
    }

    return ZB_ERR_NO_SPACE;
}

const Af_SimpleDescriptor *Af_DescriptorOf(const Af_Af *self, uint8_t endpoint)
{
    uint32_t i;

    if (self == 0)
        return 0;

    for (i = 0; i < AF_ENDPOINT_MAX; i++)
    {
        if (!self->endpoints[i].inUse || self->endpoints[i].descriptor.endpoint != endpoint)
            continue;

        return &self->endpoints[i].descriptor;
    }

    return 0;
}

/* 2.2.4.1.1's request: the source endpoint names the application, and its descriptor's profile is the one the frame
   is sent under, so an application cannot send on a profile it does not advertise. */
ZbStatus Af_DataRequest(Af_Af *self, const Af_DataRequestParameters *request, uint32_t nowMs)
{
    const Af_SimpleDescriptor *descriptor;
    Aps_ApsdeReq apsRequest;
    ZbStatus status;

    if (self == 0 || request == 0 || self->aps == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (request->asdu == 0 && request->asduLength != 0)
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;
    }

    if (request->asduLength > AF_ASDU_MAX)
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;
    }

    descriptor = Af_DescriptorOf(self, request->srcEndpoint);

    if (descriptor == 0)
    {
        self->refusedRequests++;
        return ZB_ERR_NOT_FOUND;
    }

    Zb_memset(&apsRequest, 0, (uint32_t)sizeof apsRequest);

    apsRequest.dstAddrMode = APS_ADDR_MODE_SHORT;
    apsRequest.dstAddress = request->dstAddress;
    apsRequest.dstEndpoint = request->dstEndpoint;
    apsRequest.profileId = descriptor->profileId;
    apsRequest.clusterId = request->clusterId;
    apsRequest.srcEndpoint = request->srcEndpoint;
    apsRequest.asdu = request->asdu;
    apsRequest.asduLength = request->asduLength;
    apsRequest.txOptions = request->txOptions;
    apsRequest.radiusCounter = request->radiusCounter;
    apsRequest.tag = request->tag;

    status = Aps_DataRequest(self->aps, &apsRequest, nowMs);

    if (status != ZB_OK)
    {
        self->refusedRequests++;
        return status;
    }

    self->requestsSent++;

    return ZB_OK;
}

/* The endpoint a message was addressed to, or the first registered one when it names the broadcast endpoint; the
   device profile's endpoint is not an application's and is never routed here. */
static Af_Endpoint *afEndpointFor(Af_Af *self, uint8_t endpoint)
{
    uint32_t i;

    for (i = 0; i < AF_ENDPOINT_MAX; i++)
    {
        if (!self->endpoints[i].inUse)
            continue;

        if (self->endpoints[i].descriptor.endpoint == endpoint)
            return &self->endpoints[i];
    }

    return 0;
}

/* One endpoint's turn: the indication the framework hands it, and the ring or the handler it lands in. */
static void afDoDispatch(Af_Af *self, const Aps_Indication *apsIndication, Af_Endpoint *endpoint)
{
    Af_Indication indication;

    Zb_memset(&indication, 0, (uint32_t)sizeof indication);

    indication.dstEndpoint = endpoint->descriptor.endpoint;
    indication.srcEndpoint = apsIndication->srcEndpoint;
    indication.srcAddress = apsIndication->srcAddress;
    indication.dstAddrMode = apsIndication->dstAddrMode;
    indication.dstAddress = apsIndication->dstAddress;
    indication.profileId = apsIndication->profileId;
    indication.clusterId = apsIndication->clusterId;
    indication.status = apsIndication->status;
    indication.linkQuality = apsIndication->linkQuality;

    indication.asduLength = apsIndication->asduLength > AF_ASDU_MAX ? AF_ASDU_MAX : apsIndication->asduLength;

    if (indication.asduLength != 0)
        Zb_memcpy(indication.asdu, apsIndication->asdu, indication.asduLength);

    if (endpoint->handler != 0)
    {
        endpoint->handler(endpoint->context, &indication);
        self->indicationsDelivered++;

        return;
    }

    if (self->indicationCount >= AF_ENDPOINT_MAX)
    {
        self->indicationsDropped++;

        return;
    }

    self->indications[self->indicationCount++] = indication;
}

ZbStatus Af_Step(Af_Af *self, uint32_t nowMs)
{
    Aps_Indication apsIndication;
    Af_Endpoint *endpoint;
    uint32_t taken;
    uint32_t slot;
    uint32_t matched;

    (void)nowMs;

    if (self == 0 || self->aps == 0)
        return ZB_ERR_BAD_ARGUMENT;

    while ((taken = Aps_PollIndications(self->aps, &apsIndication, 1)) == 1)
    {
        if (apsIndication.dstEndpoint == AF_ENDPOINT_ALL)
        {
            matched = 0;

            for (slot = 0; slot < AF_ENDPOINT_MAX; slot++)
            {
                if (!self->endpoints[slot].inUse)
                    continue;

                afDoDispatch(self, &apsIndication, &self->endpoints[slot]);
                matched++;
            }

            if (matched == 0)
                self->indicationsUnrouted++;

            continue;
        }

        endpoint = afEndpointFor(self, apsIndication.dstEndpoint);

        if (endpoint == 0)
        {
            self->indicationsUnrouted++;
            continue;
        }

        afDoDispatch(self, &apsIndication, endpoint);
    }

    return ZB_OK;
}

uint32_t Af_PollIndications(Af_Af *self, Af_Indication *out, uint32_t max)
{
    uint32_t taken = 0;
    uint32_t i;

    if (self == 0 || out == 0)
        return 0;

    while (taken < max && self->indicationCount > 0)
    {
        out[taken++] = self->indications[0];

        for (i = 1; i < self->indicationCount; i++)
            self->indications[i - 1] = self->indications[i];

        self->indicationCount--;
    }

    return taken;
}

uint32_t Af_EndpointCount(const Af_Af *self)
{
    uint32_t count = 0;
    uint32_t i;

    if (self == 0)
        return 0;

    for (i = 0; i < AF_ENDPOINT_MAX; i++)
    {
        if (self->endpoints[i].inUse)
            count++;
    }

    return count;
}

uint32_t Af_RequestsSent(const Af_Af *self)
{
    return self != 0 ? self->requestsSent : 0;
}

uint32_t Af_RefusedRequests(const Af_Af *self)
{
    return self != 0 ? self->refusedRequests : 0;
}

uint32_t Af_IndicationsDelivered(const Af_Af *self)
{
    return self != 0 ? self->indicationsDelivered : 0;
}

uint32_t Af_IndicationsUnrouted(const Af_Af *self)
{
    return self != 0 ? self->indicationsUnrouted : 0;
}

uint32_t Af_IndicationsDropped(const Af_Af *self)
{
    return self != 0 ? self->indicationsDropped : 0;
}
