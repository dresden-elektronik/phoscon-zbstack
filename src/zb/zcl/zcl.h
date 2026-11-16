#ifndef ZCL_H
#define ZCL_H

/*
 * The Cluster Library R8's foundation: Figure 2-2's frame, Table 2-3's global commands, Table 2-15's statuses and
 * Table 2-18's data types, over one cluster: Basic (3.2, Table 3-7).
 * docs/internals/conformance.md §7 owns the clause marks.
 */

#include <stdint.h>

#include "af.h"
#include "zb_status.h"

enum
{
    /* Figure 2-4's frame types, the two this stack writes */
    ZCL_FRAME_TYPE_GLOBAL = 0x00,
    ZCL_FRAME_TYPE_CLUSTER = 0x01,

    /* Figure 2-3's frame control bits */
    ZCL_FC_TYPE_MASK = 0x03,
    ZCL_FC_MANUFACTURER = 0x04,
    ZCL_FC_DIRECTION = 0x08,        /* 1: server to client */
    ZCL_FC_DISABLE_DEFAULT_RESPONSE = 0x10,

    /* Table 2-3's global commands this stack answers */
    ZCL_CMD_READ_ATTRIBUTES = 0x00,
    ZCL_CMD_READ_ATTRIBUTES_RESPONSE = 0x01,
    ZCL_CMD_DEFAULT_RESPONSE = 0x0b,

    /* Table 2-15's statuses this stack can answer with */
    ZCL_STATUS_SUCCESS = 0x00,
    ZCL_STATUS_FAILURE = 0x01,
    ZCL_STATUS_UNSUP_CLUSTER_COMMAND = 0x81,
    ZCL_STATUS_UNSUPPORTED_ATTRIBUTE = 0x86,
    ZCL_STATUS_INSUFFICIENT_SPACE = 0x89,

    /* Table 2-18's data types this stack's one cluster uses */
    ZCL_TYPE_UINT8 = 0x20,
    ZCL_TYPE_ENUM8 = 0x30,
    ZCL_TYPE_STRING = 0x42,

    /* the Basic cluster's identifier, and the ZCLVersion this revision prints */
    ZCL_CLUSTER_BASIC = 0x0000,
    ZCL_BASIC_ZCL_VERSION = 8,
    ZCL_BASIC_MANUFACTURER_NAME_MAX = 32,
    ZCL_BASIC_MODEL_MAX = 32,

    ZCL_ATTRIBUTE_MAX = 8,          /* the attributes one endpoint's cluster holds, a house size */
    ZCL_HEADER_MAX = 5,             /* Figure 2-2's four header fields at their widest: 1 + 2 + 1 + 1 */
    ZCL_PAYLOAD_MAX = AF_ASDU_MAX - ZCL_HEADER_MAX
};

/* Figure 2-2's header: the frame control, the manufacturer code when its bit is set, the transaction sequence
   number and the command identifier. */
typedef struct Zcl_Header
{
    uint8_t frameControl;
    uint16_t manufacturerCode;
    uint8_t transactionSequenceNumber;
    uint8_t commandIdentifier;
} Zcl_Header;

/* One attribute as this stack holds it: Table 3-7's id, type and value, the value in the widest simple type the
   one cluster needs. */
typedef struct Zcl_Attribute
{
    uint16_t id;
    uint8_t type;
    uint8_t value[ZCL_BASIC_MANUFACTURER_NAME_MAX + 1];  /* a string carries its length octet first */
    uint8_t valueLength;
} Zcl_Attribute;

typedef struct Zcl_Cluster
{
    uint16_t clusterId;
    uint8_t attributeCount;
    Zcl_Attribute attributes[ZCL_ATTRIBUTE_MAX];
} Zcl_Cluster;

/* One record of a Read Attributes Response, as the application reads it: the identifier, Table 2-15's status, and
   the type and value on SUCCESS. */
typedef struct Zcl_ReadRecord
{
    uint16_t attributeId;
    uint8_t status;
    uint8_t type;
    uint8_t valueLength;
    uint8_t value[ZCL_BASIC_MANUFACTURER_NAME_MAX + 1];
} Zcl_ReadRecord;

typedef struct Zcl_Zcl
{
    Af_Af *af;
    uint8_t endpoint;
    Zcl_Cluster cluster;

    uint8_t transactionSequenceNumber;
    uint32_t responsesSent;
    uint32_t responsesRefused;
    uint32_t commandsUnsupported;
    uint32_t attributesRead;
    uint32_t attributesUnsupported;

    Zcl_ReadRecord records[ZCL_ATTRIBUTE_MAX];
    uint32_t recordCount;
    uint32_t readsSent;
    uint32_t readsRefused;
} Zcl_Zcl;

/* Figure 2-2 read off an ASDU: the header's four fields and the offset the payload starts at, 0 when the frame is
   too short or its manufacturer bit disagrees with the octets that follow. */
ZbStatus Zcl_FrameParse(const uint8_t *asdu, uint32_t asduLength, Zcl_Header *header, uint32_t *payloadOffset);

/* The same header written ahead of a payload: the frame control, the manufacturer code when its bit says so, the
   transaction sequence number and the command identifier. */
ZbStatus Zcl_FrameCompose(const Zcl_Header *header, const uint8_t *payload, uint32_t payloadLen, uint8_t *out,
                          uint32_t outCap, uint32_t *outLen);

/* The Basic cluster's attributes, the two mandatory ones filled and the optional ones the caller names. */
void Zcl_BasicDefaults(Zcl_Cluster *cluster, uint8_t powerSource, const char *manufacturerName, const char *model);

/* The attribute an identifier names, or 0 when the cluster has none. */
const Zcl_Attribute *Zcl_AttributeOf(const Zcl_Cluster *cluster, uint16_t id);

/* The codecs under the server and the client, for an application that serves or reads a cluster over Zb_Stack's own
   requests and events: payloads only, the header being Zcl_FrameCompose's and Zcl_FrameParse's.
   Zcl_ReadAttributesCompose writes the identifiers a Read Attributes command names, 0 when they do not fit `outCap`.
   Zcl_ReadAttributesAnswer writes `cluster`'s Read Attributes Response to a request's payload and answers its length,
   counting the attributes it read and those it does not hold into `read` and `unsupported` (either may be 0).
   Zcl_ReadResponseParse reads up to `max` records of a Read Attributes Response and answers how many. */
uint32_t Zcl_ReadAttributesCompose(const uint16_t *ids, uint32_t count, uint8_t *out, uint32_t outCap);
uint32_t Zcl_ReadAttributesAnswer(const Zcl_Cluster *cluster, const uint8_t *request, uint32_t requestLen,
                                  uint8_t *out, uint32_t outCap, uint32_t *read, uint32_t *unsupported);
uint32_t Zcl_ReadResponseParse(const uint8_t *payload, uint32_t length, Zcl_ReadRecord *out, uint32_t max);

/* The cluster installed on an endpoint: the framework's descriptor for that endpoint names the cluster as an input,
   and the framework's dispatch hands this cluster's frames to `Zcl_HandleIndication`. */
ZbStatus Zcl_Init(Zcl_Zcl *self, Af_Af *af, uint8_t endpoint, uint16_t profileId, const Zcl_Cluster *cluster);

/* The general commands on one endpoint's cluster: a Read Attributes command is answered record by record, and a
   command this stack does not implement draws a Default Response. */
ZbStatus Zcl_HandleIndication(Zcl_Zcl *self, const Af_Indication *indication, uint32_t nowMs);

/* The client half: a Read Attributes command naming `count` identifiers, sent to an endpoint's cluster. */
ZbStatus Zcl_ReadAttributes(Zcl_Zcl *self, uint16_t destination, uint8_t destinationEndpoint, const uint16_t *ids,
                            uint32_t count, uint32_t nowMs);

/* The records a Read Attributes Response left for the application, oldest first. */
uint32_t Zcl_PollReadRecords(Zcl_Zcl *self, Zcl_ReadRecord *out, uint32_t max);

uint32_t Zcl_ReadsSent(const Zcl_Zcl *self);
uint32_t Zcl_ReadsRefused(const Zcl_Zcl *self);
uint32_t Zcl_ResponsesSent(const Zcl_Zcl *self);
uint32_t Zcl_ResponsesRefused(const Zcl_Zcl *self);
uint32_t Zcl_CommandsUnsupported(const Zcl_Zcl *self);
uint32_t Zcl_AttributesRead(const Zcl_Zcl *self);
uint32_t Zcl_AttributesUnsupported(const Zcl_Zcl *self);
uint8_t Zcl_TransactionSequenceNumber(const Zcl_Zcl *self);

#endif
