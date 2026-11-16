#include "interview.h"

#include <stdio.h>

#include "zb_utils.h"
#include "zb_time.h"
#include "zcl.h"
#include "zdo_client.h"

#define PROFILE_HOME_AUTOMATION 0x0104
#define BASIC_MANUFACTURER_NAME 0x0004   /* ZCL R8 Table 3-7 */
#define BASIC_MODEL_IDENTIFIER 0x0005

static const char *stepName(InterviewStep step)
{
    switch (step)
    {
    case INTERVIEW_NODE_DESCRIPTOR:
        return "node descriptor";

    case INTERVIEW_ACTIVE_ENDPOINTS:
        return "active endpoints";

    case INTERVIEW_SIMPLE_DESCRIPTOR:
        return "simple descriptor";

    case INTERVIEW_BASIC:
        return "basic cluster";

    case INTERVIEW_COMPLETE:
        return "complete";

    default:
        return "failed";
    }
}

static const char *logicalTypeName(uint8_t logicalType)
{
    switch (logicalType)
    {
    case ZDO_LOGICAL_COORDINATOR:
        return "coordinator";

    case ZDO_LOGICAL_ROUTER:
        return "router";

    case ZDO_LOGICAL_END_DEVICE:
        return "end device";

    default:
        return "reserved type";
    }
}

static InterviewDevice *deviceByAddress(Interview *self, uint16_t networkAddress)
{
    uint32_t i;

    for (i = 0; i < INTERVIEW_DEVICE_MAX; i++)
        if (self->devices[i].inUse && self->devices[i].networkAddress == networkAddress)
            return &self->devices[i];

    return 0;
}

/* The device a 64-bit address names, or a free place for it; a full table gives the oldest finished one away. */
static InterviewDevice *deviceForJoin(Interview *self, uint64_t ieee)
{
    InterviewDevice *free = 0;
    InterviewDevice *finished = 0;
    uint32_t i;

    for (i = 0; i < INTERVIEW_DEVICE_MAX; i++)
    {
        InterviewDevice *device = &self->devices[i];

        if (device->inUse && device->ieee == ieee)
            return device;

        if (!device->inUse && free == 0)
            free = device;

        if (device->inUse && !device->asking && finished == 0
            && (device->step == INTERVIEW_COMPLETE || device->step == INTERVIEW_FAILED))
            finished = device;
    }

    return free != 0 ? free : finished;
}

static uint32_t askingCount(const Interview *self)
{
    uint32_t count = 0;
    uint32_t i;

    for (i = 0; i < INTERVIEW_DEVICE_MAX; i++)
        if (self->devices[i].inUse && self->devices[i].asking)
            count++;

    return count;
}

/* The next step's first request, asked at once. */
static void enterStep(InterviewDevice *device, InterviewStep step, uint32_t nowMs)
{
    device->step = step;
    device->attempts = 0;
    device->asking = 0;
    device->nextAskMs = nowMs;
}

static void printSummary(const InterviewDevice *device)
{
    uint32_t i;
    uint32_t c;

    printf("interview  0x%04x %016llx complete: %s, manufacturer code 0x%04x\n", device->networkAddress,
           (unsigned long long)device->ieee, logicalTypeName(device->node.logicalType),
           device->node.manufacturerCode);

    for (i = 0; i < device->endpointCount; i++)
    {
        const Af_SimpleDescriptor *simple = &device->simple[i];

        printf("interview  0x%04x   endpoint 0x%02x profile 0x%04x device 0x%04x, in", device->networkAddress,
               simple->endpoint, simple->profileId, simple->deviceId);

        for (c = 0; c < simple->inputClusterCount; c++)
            printf(" %04x", simple->inputClusters[c]);

        printf(", out");

        for (c = 0; c < simple->outputClusterCount; c++)
            printf(" %04x", simple->outputClusters[c]);

        printf("\n");
    }

    if (device->basicEndpoint != 0)
        printf("interview  0x%04x   manufacturer \"%s\", model \"%s\"\n", device->networkAddress,
               device->manufacturer, device->model);
    else
        printf("interview  0x%04x   no endpoint serves the Basic cluster\n", device->networkAddress);
}

/* What follows the simple descriptors: the Basic cluster on the first endpoint that serves it, or the end. */
static void afterEndpoints(InterviewDevice *device, uint32_t nowMs)
{
    uint32_t i;
    uint32_t c;

    device->basicEndpoint = 0;

    for (i = 0; i < device->endpointCount && device->basicEndpoint == 0; i++)
        for (c = 0; c < device->simple[i].inputClusterCount; c++)
            if (device->simple[i].inputClusters[c] == ZCL_CLUSTER_BASIC)
            {
                device->basicEndpoint = device->simple[i].endpoint;
                break;
            }

    if (device->basicEndpoint != 0)
    {
        enterStep(device, INTERVIEW_BASIC, nowMs);
        return;
    }

    enterStep(device, INTERVIEW_COMPLETE, nowMs);
    printSummary(device);
}

/* A ZDP request through the device object's client half: it numbers the request, and the answer carries the number. */
static ZbStatus askZdo(Interview *self, InterviewDevice *device, uint16_t cluster, const uint8_t *payload,
                       uint32_t payloadLen)
{
    ZbStatus status;

    status = Zb_StackZdoRequest(self->stack, device->networkAddress, cluster, payload, payloadLen, device->tag,
                                &device->sequence);
    device->cluster = (uint16_t)(cluster | ZDO_RESPONSE_BIT);

    return status;
}

/* A Read Attributes command to the Basic cluster, numbered by this application's own ZCL counter. */
static ZbStatus askBasic(Interview *self, InterviewDevice *device)
{
    static const uint16_t ids[] = { BASIC_MANUFACTURER_NAME, BASIC_MODEL_IDENTIFIER };
    Zcl_Header header;
    Aps_ApsdeReq request;
    uint8_t payload[sizeof ids];
    uint8_t asdu[ZCL_HEADER_MAX + sizeof ids];
    uint32_t payloadLen;
    uint32_t asduLen = 0;

    Zb_memset(&header, 0, (uint32_t)sizeof header);
    header.frameControl = ZCL_FRAME_TYPE_GLOBAL;
    header.transactionSequenceNumber = self->zclSequence;
    header.commandIdentifier = ZCL_CMD_READ_ATTRIBUTES;

    payloadLen = Zcl_ReadAttributesCompose(ids, 2, payload, (uint32_t)sizeof payload);

    if (Zcl_FrameCompose(&header, payload, payloadLen, asdu, (uint32_t)sizeof asdu, &asduLen) != ZB_OK)
        return ZB_ERR_NO_SPACE;

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    request.dstAddrMode = APS_ADDR_MODE_SHORT;
    request.dstAddress = device->networkAddress;
    request.dstEndpoint = device->basicEndpoint;
    request.profileId = PROFILE_HOME_AUTOMATION;
    request.clusterId = ZCL_CLUSTER_BASIC;
    request.srcEndpoint = self->ownEndpoint;
    request.asdu = asdu;
    request.asduLength = asduLen;
    request.txOptions = APS_TX_OPTION_ACK;
    request.tag = device->tag;

    device->sequence = self->zclSequence++;
    device->cluster = ZCL_CLUSTER_BASIC;

    return Zb_StackApsRequest(self->stack, &request);
}

/* The request the device's step asks, under a tag of its own so a late outcome of an earlier request is told apart. */
static void ask(Interview *self, InterviewDevice *device, uint32_t nowMs)
{
    uint8_t payload[ZDO_ASDU_MAX];
    uint32_t payloadLen = 0;
    ZbStatus status;

    device->tag = (uint16_t)(((uint32_t)(device - self->devices) << 8) | self->tagSequence++);
    device->attempts++;

    switch (device->step)
    {
    case INTERVIEW_NODE_DESCRIPTOR:
        payloadLen = ZdoClient_NodeDescReq(&Zb_StackCore(self->stack)->zdo, device->networkAddress, payload,
                                           (uint32_t)sizeof payload);
        status = askZdo(self, device, ZDO_NODE_DESC_REQ, payload, payloadLen);
        break;

    case INTERVIEW_ACTIVE_ENDPOINTS:
        payloadLen = ZdoClient_ActiveEpReq(device->networkAddress, payload, (uint32_t)sizeof payload);
        status = askZdo(self, device, ZDO_ACTIVE_EP_REQ, payload, payloadLen);
        break;

    case INTERVIEW_SIMPLE_DESCRIPTOR:
        payloadLen = ZdoClient_SimpleDescReq(device->networkAddress, device->endpoints[device->endpointIndex],
                                             payload, (uint32_t)sizeof payload);
        status = askZdo(self, device, ZDO_SIMPLE_DESC_REQ, payload, payloadLen);
        break;

    case INTERVIEW_BASIC:
        status = askBasic(self, device);
        break;

    default:
        return;
    }

    if (status != ZB_OK)
    {
        /* not taken, most often for room: the same attempt goes again a little later */
        device->attempts--;
        device->nextAskMs = nowMs + INTERVIEW_RETRY_MS;
        return;
    }

    device->asking = 1;
    device->askedMs = nowMs;

    if (device->step == INTERVIEW_SIMPLE_DESCRIPTOR)
        printf("interview  0x%04x asks for the %s of endpoint 0x%02x, attempt %u\n", device->networkAddress,
               stepName(device->step), device->endpoints[device->endpointIndex], device->attempts);
    else
        printf("interview  0x%04x asks for its %s, attempt %u\n", device->networkAddress, stepName(device->step),
               device->attempts);
}

/* A step that was not answered: asked again after a pause, until its attempts run out. */
static void missed(InterviewDevice *device, const char *why, uint32_t nowMs)
{
    device->asking = 0;

    if (device->attempts < INTERVIEW_ATTEMPTS)
    {
        printf("interview  0x%04x %s: %s, asked again\n", device->networkAddress, stepName(device->step), why);
        device->nextAskMs = nowMs + INTERVIEW_RETRY_MS;
        return;
    }

    printf("interview  0x%04x %s: %s after %u attempts; the interview stops here\n", device->networkAddress,
           stepName(device->step), why, device->attempts);
    device->step = INTERVIEW_FAILED;
}

/* A ZDP answer, read by the step it answers; a status other than SUCCESS leaves that part out and moves on. */
static void answerZdo(InterviewDevice *device, const uint8_t *fields, uint32_t length, uint32_t nowMs)
{
    uint8_t status = 0xff;
    ZbStatus read;

    (void)ZdoClient_Status(fields, length, &status);

    switch (device->step)
    {
    case INTERVIEW_NODE_DESCRIPTOR:
        read = Zdo_NodeDescriptorParse(fields, length, &device->node);

        if (read != ZB_OK)
            printf("interview  0x%04x node descriptor: status 0x%02x, left out\n", device->networkAddress, status);

        enterStep(device, INTERVIEW_ACTIVE_ENDPOINTS, nowMs);
        break;

    case INTERVIEW_ACTIVE_ENDPOINTS:
        device->endpointCount = Zdo_ActiveEndpointsParse(fields, length, device->endpoints, INTERVIEW_ENDPOINT_MAX);
        device->endpointIndex = 0;

        if (device->endpointCount == 0)
        {
            printf("interview  0x%04x active endpoints: none (status 0x%02x)\n", device->networkAddress, status);
            afterEndpoints(device, nowMs);
            break;
        }

        enterStep(device, INTERVIEW_SIMPLE_DESCRIPTOR, nowMs);
        break;

    case INTERVIEW_SIMPLE_DESCRIPTOR:
        read = Zdo_SimpleDescriptorParse(fields, length, &device->simple[device->endpointIndex]);

        if (read != ZB_OK)
        {
            printf("interview  0x%04x simple descriptor of endpoint 0x%02x: status 0x%02x, left out\n",
                   device->networkAddress, device->endpoints[device->endpointIndex], status);
            Zb_memset(&device->simple[device->endpointIndex], 0, (uint32_t)sizeof device->simple[0]);
            device->simple[device->endpointIndex].endpoint = device->endpoints[device->endpointIndex];
        }

        if (++device->endpointIndex < device->endpointCount)
        {
            enterStep(device, INTERVIEW_SIMPLE_DESCRIPTOR, nowMs);
            break;
        }

        afterEndpoints(device, nowMs);
        break;

    default:
        break;
    }
}

/* A character string record into a C string: the length octet first, then that many characters. */
static void copyText(char *out, const Zcl_ReadRecord *record)
{
    uint32_t length = record->valueLength > 0 ? record->value[0] : 0;

    if (record->status != ZCL_STATUS_SUCCESS || record->type != ZCL_TYPE_STRING || length == 0xff)
        length = 0;

    if (length > INTERVIEW_TEXT_MAX || length + 1 > record->valueLength)
        length = 0;

    Zb_memcpy(out, &record->value[1], length);
    out[length] = '\0';
}

/* The Basic cluster's answer: a Read Attributes Response's records, or a Default Response refusing the read. */
static void answerBasic(InterviewDevice *device, const Zcl_Header *header, const uint8_t *payload, uint32_t length,
                        uint32_t nowMs)
{
    Zcl_ReadRecord records[2];
    uint32_t count;
    uint32_t i;

    device->manufacturer[0] = '\0';
    device->model[0] = '\0';

    if (header->commandIdentifier == ZCL_CMD_READ_ATTRIBUTES_RESPONSE)
    {
        count = Zcl_ReadResponseParse(payload, length, records, 2);

        for (i = 0; i < count; i++)
        {
            if (records[i].attributeId == BASIC_MANUFACTURER_NAME)
                copyText(device->manufacturer, &records[i]);
            else if (records[i].attributeId == BASIC_MODEL_IDENTIFIER)
                copyText(device->model, &records[i]);
        }
    }
    else
        printf("interview  0x%04x basic cluster: the read was refused, status 0x%02x\n", device->networkAddress,
               length >= 2 ? payload[1] : 0xff);

    enterStep(device, INTERVIEW_COMPLETE, nowMs);
    printSummary(device);
}

void Interview_Init(Interview *self, Zb_Stack *stack, uint8_t ownEndpoint)
{
    Zb_memset(self, 0, (uint32_t)sizeof *self);
    self->stack = stack;
    self->ownEndpoint = ownEndpoint;
}

void Interview_Joined(Interview *self, const Zb_StackJoined *joined, uint32_t nowMs)
{
    InterviewDevice *device = deviceForJoin(self, joined->ieee);

    if (device == 0)
    {
        printf("interview  0x%04x not interviewed: %u devices are being asked already\n", joined->networkAddress,
               (unsigned)INTERVIEW_DEVICE_MAX);
        return;
    }

    Zb_memset(device, 0, (uint32_t)sizeof *device);
    device->inUse = 1;
    device->ieee = joined->ieee;
    device->networkAddress = joined->networkAddress;
    device->receiverOn = joined->receiverOn;
    enterStep(device, INTERVIEW_NODE_DESCRIPTOR, nowMs);
}

int Interview_Data(Interview *self, const Aps_Indication *data, uint32_t nowMs)
{
    InterviewDevice *device = deviceByAddress(self, data->srcAddress);
    Zcl_Header header;
    uint32_t offset = 0;

    if (device == 0 || !device->asking || data->asduLength == 0 || data->clusterId != device->cluster)
        return 0;

    if (device->step == INTERVIEW_BASIC)
    {
        if (data->profileId != PROFILE_HOME_AUTOMATION || data->srcEndpoint != device->basicEndpoint
            || Zcl_FrameParse(data->asdu, data->asduLength, &header, &offset) != ZB_OK
            || header.transactionSequenceNumber != device->sequence || (header.frameControl & ZCL_FC_DIRECTION) == 0
            || (header.frameControl & ZCL_FC_TYPE_MASK) != ZCL_FRAME_TYPE_GLOBAL
            || (header.commandIdentifier != ZCL_CMD_READ_ATTRIBUTES_RESPONSE
                && header.commandIdentifier != ZCL_CMD_DEFAULT_RESPONSE))
            return 0;

        device->asking = 0;
        answerBasic(device, &header, data->asdu + offset, data->asduLength - offset, nowMs);
        return 1;
    }

    /* A ZDP answer: profile 0 from endpoint 0, its first octet the request's transaction sequence number. It may come
       before the request's own confirm, as some products send it; the step moves on and the late confirm is ignored. */
    if (data->profileId != ZDO_PROFILE_ID || data->srcEndpoint != ZDO_ENDPOINT || data->asdu[0] != device->sequence)
        return 0;

    device->asking = 0;
    answerZdo(device, data->asdu + 1, data->asduLength - 1, nowMs);
    return 1;
}

/* Every tag below INTERVIEW_TAG_END is an interview's, so the outcome of a request whose step has moved on, an answer
   having come before its confirm, is still the interview's to drop. */
int Interview_Sent(Interview *self, ZbStatus status, const Aps_Confirm *sent, uint32_t nowMs)
{
    InterviewDevice *device;

    if (sent->tag >= INTERVIEW_TAG_END)
        return 0;

    device = &self->devices[sent->tag >> 8];

    if (device->inUse && device->asking && sent->tag == device->tag && status != ZB_OK)
        missed(device, "not delivered", nowMs);

    return 1;
}

void Interview_Turn(Interview *self, uint32_t nowMs)
{
    uint32_t i;

    for (i = 0; i < INTERVIEW_DEVICE_MAX; i++)
    {
        InterviewDevice *device = &self->devices[i];

        if (device->inUse && device->asking && !Zb_timeWithin(nowMs, device->askedMs, INTERVIEW_ANSWER_MS))
            missed(device, "no answer", nowMs);
    }

    for (i = 0; i < INTERVIEW_DEVICE_MAX && askingCount(self) < INTERVIEW_PARALLEL; i++)
    {
        InterviewDevice *device = &self->devices[i];

        if (device->inUse && !device->asking && device->step < INTERVIEW_COMPLETE
            && (int32_t)(nowMs - device->nextAskMs) >= 0)
            ask(self, device, nowMs);
    }
}
