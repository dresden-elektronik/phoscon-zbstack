#include "zcl.h"

#include "zb_bstream.h"
#include "zb_utils.h"

/* ZCL R8: 2.4.1, 2.4.1.1, 2.4.1.2, 2.4.1.3, 2.4.1.4, 2.5.1, 2.5.2, 2.5.2.1, 2.5.12, 3.2.1.3, 3.2.2.2, Table 2-3, Table 2-15,
   Table 2-18 ok; the cluster's optional commands and every other cluster are not this module's. */

ZbStatus Zcl_FrameParse(const uint8_t *asdu, uint32_t asduLength, Zcl_Header *header, uint32_t *payloadOffset)
{
    U_BStream stream;

    if (asdu == 0 || header == 0 || payloadOffset == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (asduLength < 1)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(header, 0, (uint32_t)sizeof *header);

    Zb_bstream_init_const(&stream, asdu, asduLength);
    header->frameControl = U_bstream_get_u8(&stream);

    if ((header->frameControl & ZCL_FC_MANUFACTURER) != 0)
    {
        if (!Zb_bstream_fits(&stream, 2))
            return ZB_ERR_BAD_ARGUMENT;

        header->manufacturerCode = U_bstream_get_u16_le(&stream);
    }

    if (!Zb_bstream_fits(&stream, 2))
        return ZB_ERR_BAD_ARGUMENT;

    header->transactionSequenceNumber = U_bstream_get_u8(&stream);
    header->commandIdentifier = U_bstream_get_u8(&stream);

    *payloadOffset = Zb_bstream_pos(&stream);

    return ZB_OK;
}

/* The frame is built in a scratch and copied out, so a caller that hands the payload in the destination's own buffer
   gets its frame rather than the header written over the octets still to be copied. */
ZbStatus Zcl_FrameCompose(const Zcl_Header *header, const uint8_t *payload, uint32_t payloadLen, uint8_t *out,
                          uint32_t outCap, uint32_t *outLen)
{
    uint8_t frame[AF_ASDU_MAX];
    U_BStream stream;
    uint32_t total;

    if (header == 0 || out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payload == 0 && payloadLen != 0)
        return ZB_ERR_BAD_ARGUMENT;

    total = 3 + payloadLen + ((header->frameControl & ZCL_FC_MANUFACTURER) != 0 ? 2 : 0);

    if (outCap < total || total > (uint32_t)sizeof frame)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, frame, (unsigned long)total);
    U_bstream_put_u8(&stream, header->frameControl);

    if ((header->frameControl & ZCL_FC_MANUFACTURER) != 0)
        U_bstream_put_u16_le(&stream, header->manufacturerCode);

    U_bstream_put_u8(&stream, header->transactionSequenceNumber);
    U_bstream_put_u8(&stream, header->commandIdentifier);

    if (payloadLen != 0)
        U_bstream_put_bytes(&stream, payload, (unsigned long)payloadLen);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    Zb_memcpy(out, frame, total);

    *outLen = total;

    return ZB_OK;
}

/* Table 3-7's two mandatory attributes and the optional ones a caller names; a string carries its length octet
   ahead of its characters, which is Table 2-18's character string. */
static void zclDoString(Zcl_Attribute *attribute, uint16_t id, const char *text)
{
    uint32_t len = 0;

    attribute->id = id;
    attribute->type = ZCL_TYPE_STRING;

    while (text != 0 && text[len] != 0 && len < ZCL_BASIC_MANUFACTURER_NAME_MAX)
        len++;

    attribute->valueLength = (uint8_t)(len + 1);
    attribute->value[0] = (uint8_t)len;

    if (len != 0)
        Zb_memcpy(attribute->value + 1, text, len);
}

void Zcl_BasicDefaults(Zcl_Cluster *cluster, uint8_t powerSource, const char *manufacturerName, const char *model)
{
    Zcl_Attribute *attribute;

    if (cluster == 0)
        return;

    Zb_memset(cluster, 0, (uint32_t)sizeof *cluster);

    cluster->clusterId = ZCL_CLUSTER_BASIC;

    attribute = &cluster->attributes[0];
    attribute->id = 0x0000;
    attribute->type = ZCL_TYPE_UINT8;
    attribute->value[0] = ZCL_BASIC_ZCL_VERSION;
    attribute->valueLength = 1;

    attribute = &cluster->attributes[1];
    attribute->id = 0x0007;
    attribute->type = ZCL_TYPE_ENUM8;
    attribute->value[0] = powerSource;
    attribute->valueLength = 1;

    cluster->attributeCount = 2;

    if (manufacturerName != 0)
        zclDoString(&cluster->attributes[cluster->attributeCount++], 0x0004, manufacturerName);

    if (model != 0)
        zclDoString(&cluster->attributes[cluster->attributeCount++], 0x0005, model);
}

const Zcl_Attribute *Zcl_AttributeOf(const Zcl_Cluster *cluster, uint16_t id)
{
    uint32_t i;

    if (cluster == 0)
        return 0;

    for (i = 0; i < cluster->attributeCount && i < ZCL_ATTRIBUTE_MAX; i++)
    {
        if (cluster->attributes[i].id == id)
            return &cluster->attributes[i];
    }

    return 0;
}

/* The framework's dispatch calls this for a frame that named the cluster's endpoint: the cluster is that
   endpoint's application object, and the context is the object itself. */
static void zclDoDispatch(void *context, const Af_Indication *indication)
{
    Zcl_Zcl *self = (Zcl_Zcl *)context;

    if (self == 0 || indication == 0)
        return;

    (void)Zcl_HandleIndication(self, indication, 0);
}

ZbStatus Zcl_Init(Zcl_Zcl *self, Af_Af *af, uint8_t endpoint, uint16_t profileId, const Zcl_Cluster *cluster)
{
    Af_SimpleDescriptor descriptor;

    if (self == 0 || af == 0 || cluster == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (cluster->attributeCount > ZCL_ATTRIBUTE_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(self, 0, (uint32_t)sizeof *self);

    self->af = af;
    self->endpoint = endpoint;
    self->cluster = *cluster;

    Zb_memset(&descriptor, 0, (uint32_t)sizeof descriptor);

    descriptor.endpoint = endpoint;
    descriptor.profileId = profileId;
    descriptor.deviceVersion = 1;
    descriptor.inputClusterCount = 1;
    descriptor.inputClusters[0] = cluster->clusterId;

    return Af_RegisterEndpoint(af, &descriptor, zclDoDispatch, self);
}

/* The answer's own envelope: the request's transaction sequence number, the direction bit set because a server is
   writing, and the default response disabled because this frame is the immediate effect of another. */
static ZbStatus zclDoRespond(Zcl_Zcl *self, const Af_Indication *indication, uint8_t command, const uint8_t *payload,
                             uint32_t payloadLen, uint32_t nowMs)
{
    Af_DataRequestParameters request;
    Zcl_Header header;
    uint8_t asdu[AF_ASDU_MAX];
    uint32_t asduLength = 0;
    ZbStatus status;

    Zb_memset(&header, 0, (uint32_t)sizeof header);

    header.frameControl = (uint8_t)(ZCL_FRAME_TYPE_GLOBAL | ZCL_FC_DIRECTION | ZCL_FC_DISABLE_DEFAULT_RESPONSE);
    header.transactionSequenceNumber = indication->asduLength != 0 ? indication->asdu[0] : 0;
    header.commandIdentifier = command;

    status = Zcl_FrameCompose(&header, payload, payloadLen, asdu, (uint32_t)sizeof asdu, &asduLength);

    if (status != ZB_OK)
    {
        self->responsesRefused++;
        return status;
    }

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.dstAddress = indication->srcAddress;
    request.dstEndpoint = indication->srcEndpoint;
    request.srcEndpoint = self->endpoint;
    request.clusterId = self->cluster.clusterId;
    request.asdu = asdu;
    request.asduLength = asduLength;
    request.txOptions = AF_TX_ACKNOWLEDGED;

    status = Af_DataRequest(self->af, &request, nowMs);

    if (status != ZB_OK)
    {
        self->responsesRefused++;
        return status;
    }

    self->responsesSent++;

    return ZB_OK;
}

/* One record per identifier the request named: the attribute's type and value on SUCCESS, no value at all on
   UNSUPPORTED_ATTRIBUTE, and a record that does not fit ends the answer where it stands. */
uint32_t Zcl_ReadAttributesAnswer(const Zcl_Cluster *cluster, const uint8_t *request, uint32_t requestLen,
                                  uint8_t *out, uint32_t outCap, uint32_t *read, uint32_t *unsupported)
{
    const Zcl_Attribute *attribute;
    U_BStream reader;
    U_BStream writer;
    uint16_t id;

    if (read != 0)
        *read = 0;

    if (unsupported != 0)
        *unsupported = 0;

    if (cluster == 0 || out == 0 || (request == 0 && requestLen != 0))
        return 0;

    Zb_bstream_init_const(&reader, request, requestLen);
    U_bstream_init(&writer, out, (unsigned long)outCap);

    while (Zb_bstream_fits(&reader, 2))
    {
        id = U_bstream_get_u16_le(&reader);
        attribute = Zcl_AttributeOf(cluster, id);

        if (!Zb_bstream_fits(&writer, 3))
            break;

        U_bstream_put_u16_le(&writer, id);

        if (attribute == 0)
        {
            U_bstream_put_u8(&writer, ZCL_STATUS_UNSUPPORTED_ATTRIBUTE);

            if (unsupported != 0)
                (*unsupported)++;

            continue;
        }

        if (!Zb_bstream_fits(&writer, 2 + attribute->valueLength))
        {
            U_bstream_put_u8(&writer, ZCL_STATUS_INSUFFICIENT_SPACE);
            break;
        }

        U_bstream_put_u8(&writer, ZCL_STATUS_SUCCESS);
        U_bstream_put_u8(&writer, attribute->type);
        U_bstream_put_bytes(&writer, attribute->value, (unsigned long)attribute->valueLength);

        if (read != 0)
            (*read)++;
    }

    return Zb_bstream_pos(&writer);
}

static ZbStatus zclDoReadAttributes(Zcl_Zcl *self, const Af_Indication *indication, uint32_t payloadOffset,
                                    uint32_t nowMs)
{
    uint8_t response[ZCL_PAYLOAD_MAX];
    uint32_t responseLen;
    uint32_t read;
    uint32_t unsupported;

    responseLen = Zcl_ReadAttributesAnswer(&self->cluster, indication->asdu + payloadOffset,
                                           indication->asduLength - payloadOffset, response,
                                           (uint32_t)sizeof response, &read, &unsupported);
    self->attributesRead += read;
    self->attributesUnsupported += unsupported;

    return zclDoRespond(self, indication, ZCL_CMD_READ_ATTRIBUTES_RESPONSE, response, responseLen, nowMs);
}

/* A command this stack does not implement draws a Default Response naming it and its status. */
static ZbStatus zclDoDefaultResponse(Zcl_Zcl *self, const Af_Indication *indication, uint8_t command, uint8_t status,
                                     uint32_t nowMs)
{
    uint8_t payload[2];
    U_BStream stream;

    U_bstream_init(&stream, payload, (unsigned long)sizeof payload);
    U_bstream_put_u8(&stream, command);
    U_bstream_put_u8(&stream, status);

    return zclDoRespond(self, indication, ZCL_CMD_DEFAULT_RESPONSE, payload, Zb_bstream_pos(&stream), nowMs);
}

/* The identifiers a Read Attributes command names, two octets each. */
uint32_t Zcl_ReadAttributesCompose(const uint16_t *ids, uint32_t count, uint8_t *out, uint32_t outCap)
{
    U_BStream stream;
    uint32_t i;

    if (ids == 0 || out == 0 || count == 0 || count * 2 > outCap)
        return 0;

    U_bstream_init(&stream, out, (unsigned long)outCap);

    for (i = 0; i < count; i++)
        U_bstream_put_u16_le(&stream, ids[i]);

    return Zb_bstream_pos(&stream);
}

/* The read this device sends: a global command from a client, this device's own transaction sequence number, and the
   identifiers it names. */
ZbStatus Zcl_ReadAttributes(Zcl_Zcl *self, uint16_t destination, uint8_t destinationEndpoint, const uint16_t *ids,
                            uint32_t count, uint32_t nowMs)
{
    Af_DataRequestParameters request;
    Zcl_Header header;
    uint8_t asdu[AF_ASDU_MAX];
    uint8_t payload[AF_ASDU_MAX];
    uint32_t asduLength = 0;
    uint32_t payloadLen;
    ZbStatus status;

    if (self == 0 || self->af == 0 || ids == 0 || count == 0)
        return ZB_ERR_BAD_ARGUMENT;

    payloadLen = count * 2;

    if (payloadLen + ZCL_HEADER_MAX > (uint32_t)sizeof asdu)
    {
        self->readsRefused++;
        return ZB_ERR_NO_SPACE;
    }

    Zb_memset(&header, 0, (uint32_t)sizeof header);

    header.frameControl = ZCL_FRAME_TYPE_GLOBAL;
    header.transactionSequenceNumber = self->transactionSequenceNumber++;
    header.commandIdentifier = ZCL_CMD_READ_ATTRIBUTES;

    payloadLen = Zcl_ReadAttributesCompose(ids, count, payload, (uint32_t)sizeof payload);
    status = Zcl_FrameCompose(&header, payload, payloadLen, asdu, (uint32_t)sizeof asdu, &asduLength);

    if (status != ZB_OK)
    {
        self->readsRefused++;
        return status;
    }

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.dstAddress = destination;
    request.dstEndpoint = destinationEndpoint;
    request.srcEndpoint = self->endpoint;
    request.clusterId = self->cluster.clusterId;
    request.asdu = asdu;
    request.asduLength = asduLength;
    request.txOptions = AF_TX_ACKNOWLEDGED;

    status = Af_DataRequest(self->af, &request, nowMs);

    if (status != ZB_OK)
    {
        self->readsRefused++;
        return status;
    }

    self->readsSent++;

    return ZB_OK;
}

/* One record per identifier the answer carries, its type and value only where the status says SUCCESS, and a record
   that runs past the frame ends the read where it stands. */
uint32_t Zcl_ReadResponseParse(const uint8_t *payload, uint32_t length, Zcl_ReadRecord *out, uint32_t max)
{
    Zcl_ReadRecord *record;
    U_BStream stream;
    uint32_t valueLen;
    uint32_t count = 0;

    if (payload == 0 || out == 0)
        return 0;

    Zb_bstream_init_const(&stream, payload, length);

    while (Zb_bstream_fits(&stream, 3) && count < max)
    {
        record = &out[count];

        Zb_memset(record, 0, (uint32_t)sizeof *record);

        record->attributeId = U_bstream_get_u16_le(&stream);
        record->status = U_bstream_get_u8(&stream);

        if (record->status == ZCL_STATUS_SUCCESS)
        {
            if (!Zb_bstream_fits(&stream, 1))
                break;

            record->type = U_bstream_get_u8(&stream);
            valueLen = record->type == ZCL_TYPE_STRING ? (uint32_t)Zb_bstream_peek_u8(&stream) + 1 : 1;

            if (!Zb_bstream_fits(&stream, valueLen) || valueLen > (uint32_t)sizeof record->value)
                break;

            record->valueLength = (uint8_t)valueLen;
            U_bstream_get_bytes(&stream, record->value, (unsigned long)valueLen);
        }

        count++;
    }

    return count;
}

static void zclDoReadResponse(Zcl_Zcl *self, const Af_Indication *indication, uint32_t payloadOffset)
{
    self->recordCount += Zcl_ReadResponseParse(indication->asdu + payloadOffset,
                                               indication->asduLength - payloadOffset,
                                               &self->records[self->recordCount],
                                               ZCL_ATTRIBUTE_MAX - self->recordCount);
}

/* A frame on the cluster's endpoint: a response this device asked for is read and not answered, and every other
   command is the server's to answer. */
ZbStatus Zcl_HandleIndication(Zcl_Zcl *self, const Af_Indication *indication, uint32_t nowMs)
{
    Zcl_Header header;
    uint32_t payloadOffset = 0;
    ZbStatus status;

    if (self == 0 || indication == 0 || self->af == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (indication->dstEndpoint != self->endpoint || indication->clusterId != self->cluster.clusterId)
        return ZB_ERR_NOT_FOUND;

    if (Zcl_FrameParse(indication->asdu, indication->asduLength, &header, &payloadOffset) != ZB_OK)
        return ZB_ERR_BAD_ARGUMENT;

    if (header.commandIdentifier == ZCL_CMD_READ_ATTRIBUTES_RESPONSE
        && (header.frameControl & ZCL_FC_DIRECTION) != 0)
    {
        zclDoReadResponse(self, indication, payloadOffset);

        return ZB_OK;
    }

    if ((header.frameControl & ZCL_FC_TYPE_MASK) != ZCL_FRAME_TYPE_GLOBAL)
    {
        self->commandsUnsupported++;
        return zclDoDefaultResponse(self, indication, header.commandIdentifier, ZCL_STATUS_UNSUP_CLUSTER_COMMAND, nowMs);
    }

    switch (header.commandIdentifier)
    {
    case ZCL_CMD_READ_ATTRIBUTES:
        status = zclDoReadAttributes(self, indication, payloadOffset, nowMs);
        break;

    default:
        self->commandsUnsupported++;
        status = zclDoDefaultResponse(self, indication, header.commandIdentifier, ZCL_STATUS_UNSUP_CLUSTER_COMMAND,
                                      nowMs);
        break;
    }

    return status;
}

uint32_t Zcl_PollReadRecords(Zcl_Zcl *self, Zcl_ReadRecord *out, uint32_t max)
{
    uint32_t taken = 0;
    uint32_t i;

    if (self == 0 || out == 0)
        return 0;

    while (taken < max && self->recordCount > 0)
    {
        out[taken++] = self->records[0];

        for (i = 1; i < self->recordCount; i++)
            self->records[i - 1] = self->records[i];

        self->recordCount--;
    }

    return taken;
}

uint32_t Zcl_ReadsSent(const Zcl_Zcl *self)
{
    return self != 0 ? self->readsSent : 0;
}

uint32_t Zcl_ReadsRefused(const Zcl_Zcl *self)
{
    return self != 0 ? self->readsRefused : 0;
}

uint32_t Zcl_ResponsesSent(const Zcl_Zcl *self)
{
    return self != 0 ? self->responsesSent : 0;
}

uint32_t Zcl_ResponsesRefused(const Zcl_Zcl *self)
{
    return self != 0 ? self->responsesRefused : 0;
}

uint32_t Zcl_CommandsUnsupported(const Zcl_Zcl *self)
{
    return self != 0 ? self->commandsUnsupported : 0;
}

uint32_t Zcl_AttributesRead(const Zcl_Zcl *self)
{
    return self != 0 ? self->attributesRead : 0;
}

uint32_t Zcl_AttributesUnsupported(const Zcl_Zcl *self)
{
    return self != 0 ? self->attributesUnsupported : 0;
}

uint8_t Zcl_TransactionSequenceNumber(const Zcl_Zcl *self)
{
    return self != 0 ? self->transactionSequenceNumber : 0;
}
