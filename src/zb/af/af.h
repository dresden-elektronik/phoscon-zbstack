#ifndef AF_H
#define AF_H

/*
 * 2.3's application framework: the endpoint table with Table 2-40's simple descriptor, the ASDU path an application
 * sends and receives through, and the dispatch that hands an APS indication to the endpoint it names.
 * docs/internals/conformance.md owns the clause marks; docs/internals/architecture.md §5 the module's duty.
 */

#include <stdint.h>

#include "aps.h"
#include "zb_limits.h"
#include "zb_status.h"

enum
{
    AF_ENDPOINT_MAX = ZB_LIMIT_AF_ENDPOINT, /* a house size: an application registers what it has, up to the pool */
    AF_CLUSTER_MAX = ZB_LIMIT_AF_CLUSTER, /* Table 2-40's input and output cluster lists, a house size each */
    AF_ASDU_MAX = 82,               /* what one AF message carries: the APS ceiling less the header it adds */
    AF_DEVICE_VERSION_MAX = 0x0f,   /* Table 2-40's four-bit field */

    AF_ENDPOINT_FIRST = 0x01,       /* 2.3.2.5.1: "Applications SHALL only use endpoints 1-254" */
    AF_ENDPOINT_LAST = 0xfe,
    AF_ENDPOINT_ZDO = 0x00,         /* the device profile, which every Zigbee device SHALL employ */
    AF_ENDPOINT_ALL = 0xff,         /* 2.3.1.3: the broadcast endpoint */

    /* Table 2-2's TxOptions bits, which the AF passes down unchanged */
    AF_TX_SECURED = APS_TX_OPTION_SECURITY,
    AF_TX_NWK_KEY = APS_TX_OPTION_NWK_KEY,
    AF_TX_ACKNOWLEDGED = APS_TX_OPTION_ACK,
    AF_TX_FRAGMENT = APS_TX_OPTION_FRAGMENT
};

/* Table 2-40's simple descriptor, one per endpoint: the order of transmission is the order of these fields. */
typedef struct Af_SimpleDescriptor
{
    uint8_t endpoint;
    uint16_t profileId;
    uint16_t deviceId;
    uint8_t deviceVersion;
    uint8_t inputClusterCount;
    uint16_t inputClusters[AF_CLUSTER_MAX];
    uint8_t outputClusterCount;
    uint16_t outputClusters[AF_CLUSTER_MAX];
} Af_SimpleDescriptor;

/* What an application hands the framework: Table 2-2's request, with the source endpoint naming the application. */
typedef struct Af_DataRequestParameters
{
    uint16_t dstAddress;
    uint8_t dstEndpoint;
    uint8_t srcEndpoint;
    uint16_t clusterId;
    const uint8_t *asdu;
    uint32_t asduLength;
    uint32_t txOptions;
    uint8_t radiusCounter;
    uint16_t tag;                   /* the caller's name for the request, given back in its confirm; never on the air */
} Af_DataRequestParameters;

/* One ASDU that arrived for an endpoint, as the application reads it. */
typedef struct Af_Indication
{
    uint8_t dstEndpoint;
    uint8_t srcEndpoint;
    uint16_t srcAddress;
    uint32_t dstAddrMode;           /* what the frame was addressed with, which a command's own clause reads */
    uint16_t dstAddress;
    uint16_t profileId;
    uint16_t clusterId;
    uint32_t asduLength;
    uint8_t asdu[AF_ASDU_MAX];
    uint32_t status;
    uint32_t linkQuality;
} Af_Indication;

/* An endpoint's answer to one message: the framework has already taken the ASDU apart. */
typedef void (*Af_Handler)(void *context, const Af_Indication *indication);

typedef struct Af_Endpoint
{
    int inUse;
    Af_SimpleDescriptor descriptor;
    Af_Handler handler;
    void *context;
} Af_Endpoint;

typedef struct Af_Af
{
    Aps_Aps *aps;
    Af_Endpoint endpoints[AF_ENDPOINT_MAX];

    Af_Indication indications[AF_ENDPOINT_MAX];
    uint32_t indicationCount;

    uint32_t requestsSent;
    uint32_t refusedRequests;
    uint32_t indicationsDelivered;
    uint32_t indicationsUnrouted;
    uint32_t indicationsDropped;
} Af_Af;

ZbStatus Af_Init(Af_Af *self, Aps_Aps *aps);

/* 2.3.2.5: an endpoint and the descriptor it advertises, with the handler that answers on it. */
ZbStatus Af_RegisterEndpoint(Af_Af *self, const Af_SimpleDescriptor *descriptor, Af_Handler handler, void *context);

/* 2.3.1.3's device profile: endpoint 0 is not an application's, so it has no simple descriptor and is installed
   by its own door, which is what the device object does at birth. */
ZbStatus Af_RegisterDeviceProfile(Af_Af *self, Af_Handler handler, void *context);

const Af_SimpleDescriptor *Af_DescriptorOf(const Af_Af *self, uint8_t endpoint);

/* 2.3.2.5.1's endpoint range and Table 2-40's own bounds, as the descriptor door tests them. */
ZbStatus Af_DescriptorCheck(const Af_SimpleDescriptor *descriptor);

/* 2.2.4.1.1's request from an application: the source endpoint must be one this framework holds, and the ASDU is
   handed to the APS layer with the endpoint's profile. */
ZbStatus Af_DataRequest(Af_Af *self, const Af_DataRequestParameters *request, uint32_t nowMs);

/* The framework's turn: every APS indication that names an endpoint this device holds is dispatched to it. */
ZbStatus Af_Step(Af_Af *self, uint32_t nowMs);

/* The indications no handler took, as the ring the application polls: `Af_Step` dispatches what it can and leaves
   the rest here, so an application without handlers still sees what arrived. */
uint32_t Af_PollIndications(Af_Af *self, Af_Indication *out, uint32_t max);

uint32_t Af_EndpointCount(const Af_Af *self);
uint32_t Af_RequestsSent(const Af_Af *self);
uint32_t Af_RefusedRequests(const Af_Af *self);
uint32_t Af_IndicationsDelivered(const Af_Af *self);
uint32_t Af_IndicationsUnrouted(const Af_Af *self);
uint32_t Af_IndicationsDropped(const Af_Af *self);

#endif
