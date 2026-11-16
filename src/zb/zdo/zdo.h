#ifndef ZDO_H
#define ZDO_H

/*
 * 2.4's Zigbee Device Object: Table 2-129's statuses, the ZDP frame of Figure 2-17, the node and power descriptors,
 * and the server half of the device and service discovery commands on endpoint 0.
 * docs/internals/conformance.md §7 owns the clause marks; `zcl` and the binding table are their own modules.
 */

#include <stdint.h>

#include "af.h"
#include "aps_bind.h"
#include "nwk.h"
#include "zb_status.h"

enum
{
    ZDO_ADDRESS_NONE = 0xffff,      /* the own address of a device that holds none yet (Table 3-66's 0xffff) */

    /* Table 2-129's ZDP statuses, the ones this server can answer with */
    ZDO_STATUS_SUCCESS = 0x00,
    ZDO_STATUS_INV_REQUESTTYPE = 0x80,
    ZDO_STATUS_DEVICE_NOT_FOUND = 0x81,
    ZDO_STATUS_INVALID_EP = 0x82,
    ZDO_STATUS_NOT_ACTIVE = 0x83,
    ZDO_STATUS_NOT_SUPPORTED = 0x84,
    ZDO_STATUS_NO_ENTRY = 0x88,
    ZDO_STATUS_NO_DESCRIPTOR = 0x89,
    ZDO_STATUS_INSUFFICIENT_SPACE = 0x8a,
    ZDO_STATUS_TABLE_FULL = 0x8c,
    ZDO_STATUS_NOT_PERMITTED = 0x8b,
    ZDO_STATUS_NOT_AUTHORIZED = 0xa5,

    /* Table 2-107 and 2-108 also admit a status the layer below answered with: these are the NWK layer's own codes
       from Table 3-84, reached through that door. */
    ZDO_STATUS_UNKNOWN_DEVICE = 0xc8,

    /* Table 2-84's command identifiers, the ones this server answers; the response is the request with bit 15 set */
    ZDO_NWK_ADDR_REQ = 0x0000,
    ZDO_IEEE_ADDR_REQ = 0x0001,
    ZDO_NODE_DESC_REQ = 0x0002,
    ZDO_POWER_DESC_REQ = 0x0003,
    ZDO_SIMPLE_DESC_REQ = 0x0004,
    ZDO_ACTIVE_EP_REQ = 0x0005,
    ZDO_MATCH_DESC_REQ = 0x0006,    /* 2.4.3.1.7's Match_Desc_req, Figure 2-24 */
    ZDO_DEVICE_ANNCE = 0x0013,      /* 2.4.3.1.11's client command, which this server also reads */
    ZDO_BIND_REQ = 0x0021,          /* 2.4.3.2.2's Bind_req, Figure 2-28 */
    ZDO_UNBIND_REQ = 0x0022,        /* 2.4.3.2.3's Unbind_req, the same fields */
    ZDO_MGMT_LQI_REQ = 0x0031,      /* 2.4.3.3.2's Mgmt_Lqi_req, Figure 2-32's single StartIndex octet */
    ZDO_MGMT_RTG_REQ = 0x0032,      /* 2.4.3.3.3's Mgmt_Rtg_req, Figure 2-33's */
    ZDO_MGMT_BIND_REQ = 0x0033,     /* 2.4.3.3.4's Mgmt_Bind_req, Figure 2-34's */
    ZDO_MGMT_PERMIT_JOINING_REQ = 0x0036, /* 2.4.3.3.7's Mgmt_Permit_Joining_req, Figure 2-36's */
    ZDO_MGMT_LEAVE_REQ = 0x0034,          /* 2.4.3.3.5's Mgmt_Leave_req, Figure 2-35's */
    ZDO_RESPONSE_BIT = 0x8000,

    ZDO_ENDPOINT = 0x00,            /* 2.3.1.3: endpoint 0 is the device profile's, which every device employs */
    ZDO_PROFILE_ID = 0x0000,        /* the device profile */
    ZDO_CLUSTER_ZDO = 0x0000,       /* the cluster the device profile's messages ride on */
    ZDO_CLUSTER_LAST = 0x003f,      /* the last ZDP identifier; its responses are ZDO_RESPONSE_BIT plus this */
    ZDO_TAG_OWN = 0xffff,           /* the tag on the device object's own sends; ownership: no clause names a tag */

    /* Table 2-31's node descriptor, the fields this stack states */
    ZDO_LOGICAL_COORDINATOR = 0,
    ZDO_LOGICAL_ROUTER = 1,
    ZDO_LOGICAL_END_DEVICE = 2,

    ZDO_FREQUENCY_BAND_2G4 = 0x08,  /* Table 2-34's 2.4 GHz row */
    ZDO_STACK_COMPLIANCE_REVISION = 23,

    /* 2.4.4.1's request types for NWK_addr_req and IEEE_addr_req: a single device, or the extended form */
    ZDO_REQUEST_TYPE_SINGLE = 0x00,
    ZDO_REQUEST_TYPE_EXTENDED = 0x01,

    ZDO_ASDU_MAX = AF_ASDU_MAX,
    ZDO_CLUSTER_MAX = AF_CLUSTER_MAX,
    ZDO_MATCH_CLUSTERS_MAX = ZDO_ASDU_MAX / 2,  /* a Match_Desc_req's list, which no frame carries more of */

    /* Table 2-101, 2-103 and 2-105 print the same four header octets, and Table 2-101 caps a neighbour report at
       two records. */
    ZDO_REPORT_HEADER_OCTETS = 4,
    ZDO_NEIGHBOR_RECORD_OCTETS = 22,
    ZDO_ROUTE_RECORD_OCTETS = 5,
    ZDO_NEIGHBOR_LIST_MAX = 0x02,

    /* What Table 2-102 prints where a value is not available, and what the deprecated tree depth states */
    ZDO_REPORT_UNKNOWN = 0x02,
    ZDO_REPORT_DEPTH_DEPRECATED = 0x00,
    ZDO_NEIGHBOR_TYPE_UNKNOWN = 0x03,

    ZDO_REPORT_MAX = 16,            /* records a reader is offered at once, the widest of the three tables */

    /* Figure 2-35's two bits, above the six it reserves */
    ZDO_LEAVE_OPTION_REMOVE_CHILDREN = 0x40,
    ZDO_LEAVE_OPTION_REJOIN = 0x80
};

/* Table 2-31's node descriptor: the octets the server answers a Node_Desc_req with, kept as the fields a reader
   needs rather than as the bit layout, which `zdoDoWriteNodeDescriptor` owns. */
typedef struct Zdo_NodeDescriptor
{
    uint8_t logicalType;
    uint8_t fragmentationSupported;   /* 2.3.2.3.4's bit, read only from a Revision 23 device */
    uint8_t apsFlags;
    uint8_t frequencyBand;
    uint8_t macCapabilityFlags;
    uint16_t manufacturerCode;
    uint8_t maxBufferSize;
    uint16_t maxIncomingTransferSize;
    uint16_t serverMask;
    uint16_t maxOutgoingTransferSize;
    uint8_t descriptorCapability;
} Zdo_NodeDescriptor;

/* Table 2-38's power descriptor, as the four nibbles Table 2-39 defines them. */
typedef struct Zdo_PowerDescriptor
{
    uint8_t currentPowerMode;
    uint8_t availablePowerSources;
    uint8_t currentPowerSource;
    uint8_t currentPowerSourceLevel;
} Zdo_PowerDescriptor;

/* What a response answers, as the application reads it: the cluster it belongs to, the transaction sequence number
   it copied, and the command's own fields. */
typedef struct Zdo_Response
{
    uint16_t clusterId;
    uint8_t transactionSequenceNumber;
    uint16_t sourceAddress;
    uint8_t sourceEndpoint;
    uint32_t length;
    uint8_t payload[ZDO_ASDU_MAX];
} Zdo_Response;

enum
{
    ZDO_PENDING_MAX = 4,            /* the requests this device may have in flight at once, a house size */
    ZDO_RESPONSE_MAX = 4            /* and the responses waiting for the application to read them */
};

typedef struct Zdo_PendingRequest
{
    int inUse;
    uint16_t clusterId;
    uint8_t transactionSequenceNumber;
    uint16_t destination;
} Zdo_PendingRequest;

/* Table 2-101, 2-103 and 2-105's four header octets, shared by the three reports. */
typedef struct Zdo_TableReport
{
    uint32_t status;
    uint32_t totalEntries;
    uint32_t startIndex;
    uint32_t listCount;
} Zdo_TableReport;

/* Table 2-102's NeighborTableList record. */
typedef struct Zdo_NeighborReport
{
    uint64_t extendedPanId;
    uint64_t extendedAddress;
    uint16_t networkAddress;
    uint32_t deviceType;
    uint32_t rxOnWhenIdle;
    uint32_t affinity;
    uint32_t permitJoining;
    uint32_t depth;
    uint32_t lqa;
} Zdo_NeighborReport;

/* Table 2-104's RoutingTableList record. */
typedef struct Zdo_RouteReport
{
    uint16_t destinationAddress;
    uint32_t status;
    int memoryConstrained;
    int manyToOne;
    int routeRecordRequired;
    uint16_t nextHopAddress;
} Zdo_RouteReport;

/* Table 2-106's BindingTableList record. */
typedef struct Zdo_BindingReport
{
    uint64_t srcIeee;
    uint8_t srcEndpoint;
    uint16_t clusterId;
    uint32_t dstAddrMode;
    uint16_t dstAddress;
    uint64_t dstExtendedAddress;
    uint8_t dstEndpoint;
} Zdo_BindingReport;

typedef struct Zdo_Zdo
{
    Af_Af *af;
    Nwk_Nwk *nwk;                   /* the layer whose two tables a management request reads, adopted */
    Aps_Aps *aps;                   /* the sub-layer whose binding table these commands write, adopted */
    uint64_t extendedPanId;         /* this network's, which every neighbour on it shares */
    Zdo_NodeDescriptor node;
    Zdo_PowerDescriptor power;

    uint8_t transactionSequenceNumber;   /* 2.4.2.8.1's own counter, one per command sent */
    uint16_t ownAddress;
    uint64_t ownIeee;

    uint32_t requestsSent;
    uint32_t requestsRefused;
    uint32_t responsesSent;
    uint32_t responsesRefused;
    uint32_t commandsUnsupported;
    int unsupportedToApplication;   /* an unsupported request is the application's to answer, not NOT_SUPPORTED */
    uint32_t framesRefused;         /* a frame that named another endpoint or profile, which the gate refuses */
    uint32_t commandsDroppedBroadcast;
    uint32_t commandsBroadcastUnanswered;
    uint32_t announcementsSent;
    uint32_t announcementsHeard;

    Zdo_PendingRequest pending[ZDO_PENDING_MAX];
    Zdo_Response responses[ZDO_RESPONSE_MAX];
    uint32_t responseCount;
    uint32_t responsesUnmatched;
} Zdo_Zdo;

/* The node descriptor a device of this type answers with: Table 2-31's fields, with the manufacturer's code and the
   transfer sizes the application states. */
void Zdo_NodeDescriptorDefaults(Zdo_NodeDescriptor *descriptor, uint8_t logicalType, uint16_t manufacturerCode);

void Zdo_PowerDescriptorDefaults(Zdo_PowerDescriptor *descriptor);

ZbStatus Zdo_Init(Zdo_Zdo *self, Af_Af *af, uint16_t ownAddress, uint64_t ownIeee, const Zdo_NodeDescriptor *node,
                  const Zdo_PowerDescriptor *power);

/* The network the device object reports on: the two layers a management request reads and the extended PAN id a
   neighbour report states. A report whose layer is absent answers NOT_SUPPORTED with nothing after the status. */
void Zdo_SetNetwork(Zdo_Zdo *self, Nwk_Nwk *nwk, Aps_Aps *aps, uint64_t extendedPanId);

/* 2.3.2.3's node descriptor as Figure 2-38 prints it, for a Node_Desc_rsp. */
uint32_t Zdo_NodeDescriptorCompose(const Zdo_NodeDescriptor *descriptor, uint8_t *out, uint32_t outCap);

/* 2.3.2.4's power descriptor, four nibbles in two octets. */
uint32_t Zdo_PowerDescriptorCompose(const Zdo_PowerDescriptor *descriptor, uint8_t *out, uint32_t outCap);

/* 2.3.2.5's simple descriptor, the octets a Simple_Desc_rsp carries. */
uint32_t Zdo_SimpleDescriptorCompose(const Af_SimpleDescriptor *descriptor, uint8_t *out, uint32_t outCap);

/* The three reports of 2.4.4.3.2, 2.4.4.3.3 and 2.4.4.3.4, composed from the index the request named: whole records
   only, up to the room the caller gives. The length of the body, or 0 when the tables are not there. */
uint32_t Zdo_NeighborReportCompose(const Zdo_Zdo *self, uint32_t startIndex, uint8_t *out, uint32_t outCap);
uint32_t Zdo_RouteReportCompose(const Zdo_Zdo *self, uint32_t startIndex, uint8_t *out, uint32_t outCap);
uint32_t Zdo_BindingReportCompose(const Zdo_Zdo *self, uint32_t startIndex, uint8_t *out, uint32_t outCap);

/* The same three read back by the device that asked: the four header octets, then as many whole records as the
   reader has room for. */
ZbStatus Zdo_NeighborReportParse(const uint8_t *body, uint32_t length, Zdo_TableReport *head,
                                 Zdo_NeighborReport *out, uint32_t max);
ZbStatus Zdo_RouteReportParse(const uint8_t *body, uint32_t length, Zdo_TableReport *head, Zdo_RouteReport *out,
                              uint32_t max);
ZbStatus Zdo_BindingReportParse(const uint8_t *body, uint32_t length, Zdo_TableReport *head, Zdo_BindingReport *out,
                                uint32_t max);

/* The server: an ASDU that arrived on endpoint 0 is a ZDP command, and the answer goes back on the same cluster
   with 2.4.2.8.1's transaction sequence number copied from the request. A unicast request it does not support, or does
   not know, is answered with its response cluster and NOT_SUPPORTED alone and a broadcast one dropped (2.4.4.1), unless
   the application takes them; either way ZB_ERR_UNSUPPORTED says so. */
ZbStatus Zdo_HandleIndication(Zdo_Zdo *self, const Af_Indication *indication, uint32_t nowMs);

/* Whether a ZDP request this server does not support is left to the application, which answers it, rather than
   answered with NOT_SUPPORTED here: off unless the application asks. */
void Zdo_SetUnsupportedToApplication(Zdo_Zdo *self, int on);

/* The client half: a request sent with 2.4.2.8.1's own counter, and the response that copies it back matched to the
   transaction it answers. `payload` is the command's own fields, without the transaction sequence number. */
ZbStatus Zdo_SendRequest(Zdo_Zdo *self, uint16_t destination, uint8_t destinationEndpoint, uint16_t cluster,
                         const uint8_t *payload, uint32_t payloadLen, uint32_t nowMs);

/* A response the application takes, oldest first; 0 when none is waiting. */
uint32_t Zdo_PollResponses(Zdo_Zdo *self, Zdo_Response *out, uint32_t max);

/* What a response's own fields say, each read by the command it answers: 2.4.4.2's status first, then the
   command's. `Zdo_SimpleDescriptorParse` reads Table 2-40's record back into the framework's own type. */
ZbStatus Zdo_NodeDescriptorParse(const uint8_t *payload, uint32_t length, Zdo_NodeDescriptor *out);
ZbStatus Zdo_PowerDescriptorParse(const uint8_t *payload, uint32_t length, Zdo_PowerDescriptor *out);
ZbStatus Zdo_SimpleDescriptorParse(const uint8_t *payload, uint32_t length, Af_SimpleDescriptor *out);
uint32_t Zdo_ActiveEndpointsParse(const uint8_t *payload, uint32_t length, uint8_t *out, uint32_t outMax);

/* Table 2-51's announcement as it arrives: 2.4.2.8.1's transaction sequence number first, then the network address,
   the 64-bit address and Figure 2-16's capability octet. */
ZbStatus Zdo_DeviceAnnouncementParse(const uint8_t *asdu, uint32_t length, uint64_t *ieee, uint16_t *nwkAddress,
                                     uint8_t *capability);

uint32_t Zdo_ResponsesUnmatched(const Zdo_Zdo *self);

/* A command whose clause prints unicast addressing, received as a broadcast. */
uint32_t Zdo_CommandsDroppedBroadcast(const Zdo_Zdo *self);

/* A command that was processed anyway and owes no answer to a broadcast. */
uint32_t Zdo_CommandsBroadcastUnanswered(const Zdo_Zdo *self);
uint32_t Zdo_PendingCount(const Zdo_Zdo *self);

/* The announcement a device broadcasts once it has joined or changed address: ZB_ERR_NOT_READY while it holds no
   address of its own to announce. */
ZbStatus Zdo_DeviceAnnce(Zdo_Zdo *self, uint32_t nowMs);

uint32_t Zdo_RequestsSent(const Zdo_Zdo *self);
uint32_t Zdo_ResponsesSent(const Zdo_Zdo *self);
uint32_t Zdo_ResponsesRefused(const Zdo_Zdo *self);
uint32_t Zdo_CommandsUnsupported(const Zdo_Zdo *self);
uint32_t Zdo_FramesRefused(const Zdo_Zdo *self);
uint32_t Zdo_AnnouncementsSent(const Zdo_Zdo *self);
uint32_t Zdo_AnnouncementsHeard(const Zdo_Zdo *self);
uint8_t Zdo_TransactionSequenceNumber(const Zdo_Zdo *self);

/* Built with ZB_ZDO_CLIENT: the counter 2.4.2.8.1 has the device object keep, moved past a request the client sent
   under it; the device's own address, ZDO_ADDRESS_NONE before it holds one; and its node descriptor. */
void Zdo_AdvanceTransactionSequenceNumber(Zdo_Zdo *self);
uint16_t Zdo_OwnAddress(const Zdo_Zdo *self);
const Zdo_NodeDescriptor *Zdo_OwnNodeDescriptor(const Zdo_Zdo *self);

#endif
