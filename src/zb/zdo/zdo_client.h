#ifndef ZDO_CLIENT_H
#define ZDO_CLIENT_H

/*
 * The device object's client half, built with ZB_ZDO_CLIENT: 2.4.3.1's device and service discovery requests as
 * Figures 2-18 to 2-24 frame them, and the responses the device object's own readers leave out.
 * docs/internals/conformance.md owns the clause marks; Zb_StackZdoRequest numbers and sends a request.
 */

#include <stdint.h>

#include "zdo.h"
#include "zb_status.h"

enum
{
    ZDOCLIENT_MATCH_DESC_REQ = 0x0006,           /* 2.4.3.1.7's ClusterID */

    /* Table 2-44's RequestType */
    ZDOCLIENT_REQUEST_SINGLE = 0x00,
    ZDOCLIENT_REQUEST_EXTENDED = 0x01,

    /* the associated devices one response can list: what is left of an ASDU past Figure 2-56's fixed fields */
    ZDOCLIENT_ASSOC_MAX = (ZDO_ASDU_MAX - 1 - 13) / 2
};

/* Each writes a request's own fields into `out`, without the transaction sequence number, and answers their length,
   or 0 when they do not fit `outCap`. */
uint32_t ZdoClient_NwkAddrReq(uint64_t ieeeAddr, uint8_t requestType, uint8_t startIndex, uint8_t *out,
                              uint32_t outCap);
uint32_t ZdoClient_IeeeAddrReq(uint16_t nwkAddrOfInterest, uint8_t requestType, uint8_t startIndex, uint8_t *out,
                               uint32_t outCap);

/* With the Fragmentation Parameters Global TLV 2.4.3.1.3.1 asks for, stating `zdo`'s own address and node
   descriptor. */
uint32_t ZdoClient_NodeDescReq(const Zdo_Zdo *zdo, uint16_t nwkAddrOfInterest, uint8_t *out, uint32_t outCap);
uint32_t ZdoClient_PowerDescReq(uint16_t nwkAddrOfInterest, uint8_t *out, uint32_t outCap);
uint32_t ZdoClient_SimpleDescReq(uint16_t nwkAddrOfInterest, uint8_t endPoint, uint8_t *out, uint32_t outCap);
uint32_t ZdoClient_ActiveEpReq(uint16_t nwkAddrOfInterest, uint8_t *out, uint32_t outCap);
uint32_t ZdoClient_MatchDescReq(uint16_t nwkAddrOfInterest, uint16_t profileId, const uint16_t *inClusterList,
                                uint32_t numInClusters, const uint16_t *outClusterList, uint32_t numOutClusters,
                                uint8_t *out, uint32_t outCap);

/* Figure 2-56's NWK_addr_rsp, which Figure 2-57's IEEE_addr_rsp repeats. */
typedef struct ZdoClient_AddressResponse
{
    uint8_t status;
    uint64_t ieeeAddrRemoteDev;
    uint16_t nwkAddrRemoteDev;
    uint8_t numAssocDev;
    uint8_t startIndex;
    uint16_t nwkAddrAssocDevList[ZDOCLIENT_ASSOC_MAX];
} ZdoClient_AddressResponse;

/* A response's own fields, without the transaction sequence number: ZB_OK for one that is whole, whatever its status
   says, ZB_ERR_BAD_FRAME for one that is short or runs past its counts. */
ZbStatus ZdoClient_AddressResponseParse(const uint8_t *payload, uint32_t length, ZdoClient_AddressResponse *out);
ZbStatus ZdoClient_MatchDescRspParse(const uint8_t *payload, uint32_t length, uint8_t *status,
                                     uint16_t *nwkAddrOfInterest, uint8_t *matchList, uint32_t matchMax,
                                     uint32_t *matchLength);

/* The status, every response's first field. */
ZbStatus ZdoClient_Status(const uint8_t *payload, uint32_t length, uint8_t *status);

#endif /* ZDO_CLIENT_H */
