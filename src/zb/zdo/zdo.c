#include "zdo.h"

#include "nwk_addr.h"
#include "nwk_get.h"
#include "nwk_leave.h"
#include "nwk_permit.h"
#include "zb_bstream.h"
#include "zb_utils.h"

/* R23.1: 2.2.5.1.1, 2.3.1.3, 2.3.2.3, 2.3.2.3.4, 2.3.2.3.10, 2.3.2.4, 2.3.2.5, 2.4, 2.4.2.8, 2.4.2.8.1, 2.4.2.8.4, 2.4.3.1.7, 2.4.3.1.11, 2.4.3.2.2, 2.4.3.2.3,
   2.4.3.3.2, 2.4.3.3.3, 2.4.3.3.4, 2.4.4.1, 2.4.4.2.1, 2.4.4.2.2, 2.4.4.2.3, 2.4.4.2.4, 2.4.4.2.5, 2.4.4.2.6, 2.4.4.2.7,
   2.4.3.3.5, 2.4.3.3.7, 2.4.4.3.2, 2.4.4.3.3, 2.4.4.3.4, 2.4.4.3.5, 2.4.4.3.7, 2.5.4.5.4.3, Table 2-129 ok; 2.4.3.3.7.2 deferred (the Beacon Appendix
   Encapsulation Global TLV of I.4.10 and the NIB value it sets are not built); 2.4.4.2 deferred (an entry that held an
   announced address is not marked as having no known valid one, the map having no such state); the client's request/response
   matching, the report's paging by the MSDU's room and the tables themselves are not this module's. */

/* Table 2-31's fields for a device of this type: the MAC capability octet says the receiver rests on and the device
   routes, 2.3.2.3.4's bit says whether the build reassembles fragments, and 2.3.2.3.10's transfer sizes are what it
   can reassemble, or one message where it reassembles nothing. */
void Zdo_NodeDescriptorDefaults(Zdo_NodeDescriptor *descriptor, uint8_t logicalType, uint16_t manufacturerCode)
{
    if (descriptor == 0)
        return;

    Zb_memset(descriptor, 0, (uint32_t)sizeof *descriptor);

    descriptor->logicalType = logicalType;
    descriptor->frequencyBand = ZDO_FREQUENCY_BAND_2G4;
    descriptor->macCapabilityFlags = 0x8e;
    descriptor->manufacturerCode = manufacturerCode;
    descriptor->maxBufferSize = 0x50;
    descriptor->fragmentationSupported = ZB_APS_FRAGMENTATION;
    descriptor->maxIncomingTransferSize = ZB_APS_FRAGMENTATION ? APS_FRAG_MAX_ASDU : AF_ASDU_MAX;
    descriptor->serverMask = ZDO_STACK_COMPLIANCE_REVISION << 9;
    descriptor->maxOutgoingTransferSize = descriptor->maxIncomingTransferSize;
}

/* Tables 2-36 to 2-39 for a mains-powered device: receiver synchronised, mains available and current, at 100%. */
void Zdo_PowerDescriptorDefaults(Zdo_PowerDescriptor *descriptor)
{
    if (descriptor == 0)
        return;

    Zb_memset(descriptor, 0, (uint32_t)sizeof *descriptor);

    descriptor->currentPowerMode = 0x00;
    descriptor->availablePowerSources = 0x01;
    descriptor->currentPowerSource = 0x01;
    descriptor->currentPowerSourceLevel = 0x0c;
}

/* The framework's dispatch calls this for a message that named endpoint 0: the device object is that endpoint's
   application object, and the context is the object itself. */
static void zdoDoDispatch(void *context, const Af_Indication *indication)
{
    Zdo_Zdo *self = (Zdo_Zdo *)context;

    if (self == 0 || indication == 0)
        return;

    (void)Zdo_HandleIndication(self, indication, 0);
}

ZbStatus Zdo_Init(Zdo_Zdo *self, Af_Af *af, uint16_t ownAddress, uint64_t ownIeee, const Zdo_NodeDescriptor *node,
                  const Zdo_PowerDescriptor *power)
{
    if (self == 0 || af == 0 || node == 0 || power == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(self, 0, (uint32_t)sizeof *self);

    self->af = af;
    self->node = *node;
    self->power = *power;
    self->ownAddress = ownAddress;
    self->ownIeee = ownIeee;

    return Af_RegisterDeviceProfile(af, zdoDoDispatch, self);
}

/* 2.3.2.3 with Table 2-31: the logical type and the two deprecated bits in the first octet, the APS flags and the
   frequency band in the second, then the MAC capabilities, the manufacturer code, the buffer size, the two transfer
   sizes, the server mask and the descriptor capability, little-endian where a field is wider than one octet. */
uint32_t Zdo_NodeDescriptorCompose(const Zdo_NodeDescriptor *descriptor, uint8_t *out, uint32_t outCap)
{
    U_BStream stream;
    uint32_t len = 13;

    if (descriptor == 0 || out == 0 || outCap < len)
        return 0;

    U_bstream_init(&stream, out, (unsigned long)len);
    U_bstream_put_u8(&stream, (uint8_t)((descriptor->logicalType & 0x07)
                                        | ((descriptor->fragmentationSupported & 0x01) << 5)));
    U_bstream_put_u8(&stream, (uint8_t)(((descriptor->apsFlags & 0x07) << 5) | (descriptor->frequencyBand & 0x1f)));
    U_bstream_put_u8(&stream, descriptor->macCapabilityFlags);
    U_bstream_put_u16_le(&stream, descriptor->manufacturerCode);
    U_bstream_put_u8(&stream, descriptor->maxBufferSize);
    U_bstream_put_u16_le(&stream, descriptor->maxIncomingTransferSize);
    U_bstream_put_u16_le(&stream, descriptor->serverMask);
    U_bstream_put_u16_le(&stream, descriptor->maxOutgoingTransferSize);
    U_bstream_put_u8(&stream, descriptor->descriptorCapability);

    return Zb_bstream_ok(&stream) ? len : 0;
}

/* 2.3.2.4: Table 2-35's four fields in the order of their transmission, the first of each octet its low nibble. */
uint32_t Zdo_PowerDescriptorCompose(const Zdo_PowerDescriptor *descriptor, uint8_t *out, uint32_t outCap)
{
    U_BStream stream;

    if (descriptor == 0 || out == 0 || outCap < 2)
        return 0;

    U_bstream_init(&stream, out, 2);
    U_bstream_put_u8(&stream, (uint8_t)((descriptor->currentPowerMode & 0x0f)
                                        | ((descriptor->availablePowerSources & 0x0f) << 4)));
    U_bstream_put_u8(&stream, (uint8_t)((descriptor->currentPowerSource & 0x0f)
                                        | ((descriptor->currentPowerSourceLevel & 0x0f) << 4)));

    return Zb_bstream_ok(&stream) ? 2 : 0;
}

/* Table 2-40: the endpoint, the profile and device identifiers, the version in the low nibble of the fourth octet,
   then the two counts and their lists. */
uint32_t Zdo_SimpleDescriptorCompose(const Af_SimpleDescriptor *descriptor, uint8_t *out, uint32_t outCap)
{
    U_BStream stream;
    uint32_t len;
    uint32_t i;

    if (descriptor == 0 || out == 0)
        return 0;

    len = 8 + 2 * descriptor->inputClusterCount + 2 * descriptor->outputClusterCount;

    if (outCap < len)
        return 0;

    U_bstream_init(&stream, out, (unsigned long)len);
    U_bstream_put_u8(&stream, descriptor->endpoint);
    U_bstream_put_u16_le(&stream, descriptor->profileId);
    U_bstream_put_u16_le(&stream, descriptor->deviceId);
    U_bstream_put_u8(&stream, (uint8_t)(descriptor->deviceVersion & 0x0f));
    U_bstream_put_u8(&stream, descriptor->inputClusterCount);

    for (i = 0; i < descriptor->inputClusterCount; i++)
        U_bstream_put_u16_le(&stream, descriptor->inputClusters[i]);

    U_bstream_put_u8(&stream, descriptor->outputClusterCount);

    for (i = 0; i < descriptor->outputClusterCount; i++)
        U_bstream_put_u16_le(&stream, descriptor->outputClusters[i]);

    return Zb_bstream_ok(&stream) ? len : 0;
}

/* A request's fields, behind the transaction sequence number every ZDP frame starts with */
static void zdoDoOpenRequest(U_BStream *stream, const Af_Indication *indication)
{
    Zb_bstream_init_const(stream, indication->asdu, indication->asduLength);
    U_bstream_advance(stream, 1);
}

/* An answer's status and the address of interest it echoes, the head of the descriptor and endpoint responses */
static void zdoDoWriteStatusAddress(U_BStream *stream, uint8_t status, uint16_t address)
{
    U_bstream_put_u8(stream, status);
    U_bstream_put_u16_le(stream, address);
}

/* The answer's own envelope: the transaction sequence number the request carried, then the payload, sent to the
   device that asked and on the cluster it asked on. */
static ZbStatus zdoDoRespond(Zdo_Zdo *self, const Af_Indication *indication, uint16_t cluster, const uint8_t *body,
                             uint32_t bodyLen, uint32_t nowMs)
{
    Af_DataRequestParameters request;
    uint8_t asdu[ZDO_ASDU_MAX];
    U_BStream stream;
    ZbStatus status;

    if (bodyLen + 1 > (uint32_t)sizeof asdu)
    {
        self->responsesRefused++;
        return ZB_ERR_NO_SPACE;
    }

    U_bstream_init(&stream, asdu, (unsigned long)sizeof asdu);
    U_bstream_put_u8(&stream, indication->asduLength != 0 ? indication->asdu[0] : 0);

    if (bodyLen != 0)
        U_bstream_put_bytes(&stream, body, (unsigned long)bodyLen);

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.dstAddress = indication->srcAddress;
    request.dstEndpoint = indication->srcEndpoint;
    request.srcEndpoint = ZDO_ENDPOINT;
    request.tag = ZDO_TAG_OWN;
    request.clusterId = (uint16_t)(cluster | ZDO_RESPONSE_BIT);
    request.asdu = asdu;
    request.asduLength = bodyLen + 1;
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

/* This device's own network address as the network layer holds it now, which a join assigns and a conflict changes,
   or 0xffff while it has none; the address given at init only while no network layer is attached. */
static uint16_t zdoDoOwnAddress(const Zdo_Zdo *self)
{
    uint16_t own = ZDO_ADDRESS_NONE;

    if (self->nwk == 0)
        return self->ownAddress;

    (void)Nwk_OwnAddressKnown(self->nwk, &own);

    return own;
}

/* Whether a request's address of interest is this device: never while it holds no address of its own. */
static int zdoDoIsOwnAddress(const Zdo_Zdo *self, uint16_t address)
{
    return address != ZDO_ADDRESS_NONE && address == zdoDoOwnAddress(self);
}

/* The node descriptor's answer: the status, the address of interest and, on SUCCESS, the descriptor itself. */
static ZbStatus zdoDoNodeDescriptor(Zdo_Zdo *self, const Af_Indication *indication, uint32_t nowMs)
{
    uint8_t body[1 + 2 + 13];
    U_BStream request;
    U_BStream answer;
    uint16_t address;
    uint8_t status;
    uint32_t len;

    if (indication->asduLength < 3)
        return ZB_ERR_BAD_ARGUMENT;

    zdoDoOpenRequest(&request, indication);
    address = U_bstream_get_u16_le(&request);
    status = zdoDoIsOwnAddress(self, address) ? ZDO_STATUS_SUCCESS : ZDO_STATUS_DEVICE_NOT_FOUND;

    U_bstream_init(&answer, body, (unsigned long)sizeof body);
    zdoDoWriteStatusAddress(&answer, status, address);

    if (status != ZDO_STATUS_SUCCESS)
        return zdoDoRespond(self, indication, ZDO_NODE_DESC_REQ, body, 3, nowMs);

    len = Zdo_NodeDescriptorCompose(&self->node, body + 3, (uint32_t)sizeof body - 3);

    if (len == 0)
        return ZB_ERR_BAD_ARGUMENT;

    return zdoDoRespond(self, indication, ZDO_NODE_DESC_REQ, body, 3 + len, nowMs);
}

/* The power descriptor's answer: the same envelope and Table 2-38's two octets. */
static ZbStatus zdoDoPowerDescriptor(Zdo_Zdo *self, const Af_Indication *indication, uint32_t nowMs)
{
    uint8_t body[1 + 2 + 2];
    U_BStream request;
    U_BStream answer;
    uint16_t address;
    uint8_t status;
    uint32_t len;

    if (indication->asduLength < 3)
        return ZB_ERR_BAD_ARGUMENT;

    zdoDoOpenRequest(&request, indication);
    address = U_bstream_get_u16_le(&request);
    status = zdoDoIsOwnAddress(self, address) ? ZDO_STATUS_SUCCESS : ZDO_STATUS_DEVICE_NOT_FOUND;

    U_bstream_init(&answer, body, (unsigned long)sizeof body);
    zdoDoWriteStatusAddress(&answer, status, address);

    if (status != ZDO_STATUS_SUCCESS)
        return zdoDoRespond(self, indication, ZDO_POWER_DESC_REQ, body, 3, nowMs);

    len = Zdo_PowerDescriptorCompose(&self->power, body + 3, (uint32_t)sizeof body - 3);

    if (len == 0)
        return ZB_ERR_BAD_ARGUMENT;

    return zdoDoRespond(self, indication, ZDO_POWER_DESC_REQ, body, 3 + len, nowMs);
}

/* The simple descriptor's answer: INVALID_EP for 0x00 and 0xff, NOT_ACTIVE for an endpoint with no descriptor, and
   the descriptor itself otherwise. */
static ZbStatus zdoDoSimpleDescriptor(Zdo_Zdo *self, const Af_Indication *indication, uint32_t nowMs)
{
    const Af_SimpleDescriptor *descriptor;
    uint8_t body[1 + 2 + 1 + 8 + 2 * ZDO_CLUSTER_MAX * 2];
    U_BStream request;
    U_BStream answer;
    uint16_t address;
    uint8_t endpoint;
    uint8_t status = ZDO_STATUS_SUCCESS;
    uint32_t len = 0;

    if (indication->asduLength < 4)
        return ZB_ERR_BAD_ARGUMENT;

    zdoDoOpenRequest(&request, indication);
    address = U_bstream_get_u16_le(&request);
    endpoint = U_bstream_get_u8(&request);

    if (!zdoDoIsOwnAddress(self, address))
        status = ZDO_STATUS_DEVICE_NOT_FOUND;
    else if (endpoint == ZDO_ENDPOINT || endpoint == AF_ENDPOINT_ALL)
        status = ZDO_STATUS_INVALID_EP;
    else
    {
        descriptor = Af_DescriptorOf(self->af, endpoint);

        if (descriptor == 0)
            status = ZDO_STATUS_NOT_ACTIVE;
        else
            len = Zdo_SimpleDescriptorCompose(descriptor, body + 4, (uint32_t)sizeof body - 4);
    }

    U_bstream_init(&answer, body, (unsigned long)sizeof body);
    zdoDoWriteStatusAddress(&answer, status, address);
    U_bstream_put_u8(&answer, (uint8_t)len);

    return zdoDoRespond(self, indication, ZDO_SIMPLE_DESC_REQ, body, 4 + len, nowMs);
}

/* The active endpoints' answer: the count and the list, which is every application endpoint the framework holds. */
static ZbStatus zdoDoActiveEndpoints(Zdo_Zdo *self, const Af_Indication *indication, uint32_t nowMs)
{
    uint8_t body[1 + 2 + 1 + AF_ENDPOINT_MAX];
    uint8_t endpoints[AF_ENDPOINT_MAX];
    const Af_SimpleDescriptor *descriptor;
    U_BStream request;
    U_BStream answer;
    uint16_t address;
    uint8_t status;
    uint32_t count = 0;
    uint32_t i;

    if (indication->asduLength < 3)
        return ZB_ERR_BAD_ARGUMENT;

    zdoDoOpenRequest(&request, indication);
    address = U_bstream_get_u16_le(&request);
    status = zdoDoIsOwnAddress(self, address) ? ZDO_STATUS_SUCCESS : ZDO_STATUS_DEVICE_NOT_FOUND;

    if (status == ZDO_STATUS_SUCCESS)
    {
        for (i = AF_ENDPOINT_FIRST; i <= AF_ENDPOINT_LAST && count < AF_ENDPOINT_MAX; i++)
        {
            descriptor = Af_DescriptorOf(self->af, (uint8_t)i);

            if (descriptor != 0)
                endpoints[count++] = descriptor->endpoint;
        }
    }

    U_bstream_init(&answer, body, (unsigned long)sizeof body);
    zdoDoWriteStatusAddress(&answer, status, address);
    U_bstream_put_u8(&answer, (uint8_t)count);
    U_bstream_put_bytes(&answer, endpoints, (unsigned long)count);

    return zdoDoRespond(self, indication, ZDO_ACTIVE_EP_REQ, body, Zb_bstream_pos(&answer), nowMs);
}

/* A command whose clause prints unicast addressing is not processed when it arrived as a broadcast, and nothing is
   sent back. */
static int zdoDoArrivedBroadcast(const Af_Indication *indication)
{
    if (indication->dstAddrMode == APS_ADDR_MODE_GROUP)
        return 1;

    if (indication->dstAddrMode == APS_ADDR_MODE_SHORT && Nwk_AddrIsBroadcast(indication->dstAddress))
        return 1;

    return 0;
}

/* Whether a descriptor matches: its profile, or the wildcard, then any listed cluster among its input clusters or any
   among its output clusters. */
static int zdoDoMatchesDescriptor(const Af_SimpleDescriptor *descriptor, uint16_t profileId, const uint16_t *in,
                                  uint32_t inCount, const uint16_t *out, uint32_t outCount)
{
    uint32_t i;
    uint32_t j;

    if (profileId != descriptor->profileId && profileId != 0xffff)
        return 0;

    for (i = 0; i < inCount; i++)
    {
        for (j = 0; j < descriptor->inputClusterCount; j++)
        {
            if (in[i] == descriptor->inputClusters[j])
                return 1;
        }
    }

    for (i = 0; i < outCount; i++)
    {
        for (j = 0; j < descriptor->outputClusterCount; j++)
        {
            if (out[i] == descriptor->outputClusters[j])
                return 1;
        }
    }

    return 0;
}

/* An end device the neighbour table holds as this device's child, authenticated or not: an associated device the
   address answers list, which a previous or a lost child no longer is (D-297). */
static int zdoDoIsAssociatedChild(const Nwk_NeighborTableEntry *entry)
{
    return entry->inUse && entry->deviceType == NWK_DEVICE_END_DEVICE
           && (entry->relationship == NWK_REL_CHILD || entry->relationship == NWK_REL_UNAUTHENTICATED_CHILD);
}

/* The associated child a request names by its network address, or by an IEEE address the table knows; 0 for none. */
static const Nwk_NeighborTableEntry *zdoDoChildOf(const Zdo_Zdo *self, uint16_t address, const uint64_t *ieee)
{
    uint32_t i;

    for (i = 0; self->nwk != 0 && i < NWK_NEIGHBOR_MAX; i++)
    {
        const Nwk_NeighborTableEntry *entry = &self->nwk->neighbors[i];

        if (!zdoDoIsAssociatedChild(entry))
            continue;

        if (ieee == 0 ? entry->networkAddress == address : entry->ieeeKnown && entry->extendedAddress == *ieee)
            return entry;
    }

    return 0;
}

/* The Match_Desc_req's answer. The address of interest is this device, a broadcast, a child end device whose
   descriptors a parent holds none of (NO_DESCRIPTOR), or no one it knows (DEVICE_NOT_FOUND). A broadcast that matches
   nothing is not answered, and every answer carries the address of interest, as Figure 2-62 prints it (D-289); for a
   broadcast one that is this device's own, the address step 3 matched, which a client takes for the server's. */
static ZbStatus zdoDoMatchDescriptor(Zdo_Zdo *self, const Af_Indication *indication, uint32_t nowMs)
{
    uint16_t in[ZDO_MATCH_CLUSTERS_MAX];
    uint16_t out[ZDO_MATCH_CLUSTERS_MAX];
    uint8_t body[1 + 2 + 1 + AF_ENDPOINT_MAX];
    uint8_t matches[AF_ENDPOINT_MAX];
    const Af_SimpleDescriptor *descriptor;
    U_BStream request;
    U_BStream answer;
    uint16_t address;
    uint16_t profileId;
    uint32_t inCount;
    uint32_t outCount;
    uint32_t count = 0;
    uint32_t i;
    uint8_t status = ZDO_STATUS_SUCCESS;
    int endDevice = self->nwk != 0 && self->nwk->cfg.deviceType == NWK_DEVICE_END_DEVICE;
    int interestBroadcast;

    if (indication->asduLength < 6)
        return ZB_ERR_BAD_ARGUMENT;

    zdoDoOpenRequest(&request, indication);
    address = U_bstream_get_u16_le(&request);
    profileId = U_bstream_get_u16_le(&request);
    inCount = U_bstream_get_u8(&request);

    if (inCount > ZDO_MATCH_CLUSTERS_MAX || !Zb_bstream_fits(&request, 2 * inCount + 1))
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < inCount; i++)
        in[i] = U_bstream_get_u16_le(&request);

    outCount = U_bstream_get_u8(&request);

    if (outCount > ZDO_MATCH_CLUSTERS_MAX || !Zb_bstream_fits(&request, 2 * outCount))
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < outCount; i++)
        out[i] = U_bstream_get_u16_le(&request);

    interestBroadcast = Nwk_AddrIsBroadcast(address);

    if (endDevice && !interestBroadcast && !zdoDoIsOwnAddress(self, address))
    {
        if (zdoDoArrivedBroadcast(indication))
            return ZB_OK;

        status = ZDO_STATUS_INV_REQUESTTYPE;
    }
    else if (interestBroadcast || zdoDoIsOwnAddress(self, address))
    {
        for (i = AF_ENDPOINT_FIRST; i <= AF_ENDPOINT_LAST && count < AF_ENDPOINT_MAX; i++)
        {
            descriptor = Af_DescriptorOf(self->af, (uint8_t)i);

            if (descriptor != 0 && zdoDoMatchesDescriptor(descriptor, profileId, in, inCount, out, outCount))
                matches[count++] = descriptor->endpoint;
        }
    }
    else
    {
        status = zdoDoChildOf(self, address, 0) != 0 ? ZDO_STATUS_NO_DESCRIPTOR : ZDO_STATUS_DEVICE_NOT_FOUND;
    }

    if (status == ZDO_STATUS_SUCCESS && count == 0 && zdoDoArrivedBroadcast(indication))
    {
        self->commandsBroadcastUnanswered++;

        return ZB_OK;
    }

    U_bstream_init(&answer, body, (unsigned long)sizeof body);
    zdoDoWriteStatusAddress(&answer, status, interestBroadcast ? zdoDoOwnAddress(self) : address);
    U_bstream_put_u8(&answer, (uint8_t)count);
    U_bstream_put_bytes(&answer, matches, (unsigned long)count);

    return zdoDoRespond(self, indication, ZDO_MATCH_DESC_REQ, body, Zb_bstream_pos(&answer), nowMs);
}

/* An address answer: the status and the two addresses, then for an extended one the associated devices from
   StartIndex in as many whole entries as the answer holds. NumAssocDev counts this answer's list, and StartIndex and
   the list are left out only where no device is associated (Tables 2-87 and 2-88). */
static uint32_t zdoDoWriteAddressAnswer(const Zdo_Zdo *self, uint8_t *body, uint32_t bodyMax, uint8_t status,
                                        uint64_t ieee, uint16_t address, int extended, uint8_t startIndex)
{
    U_BStream answer;
    uint32_t countAt;
    uint32_t index = 0;
    uint32_t listed = 0;
    uint32_t total = 0;
    uint32_t i;

    U_bstream_init(&answer, body, (unsigned long)bodyMax);
    U_bstream_put_u8(&answer, status);
    U_bstream_put_u64_le(&answer, ieee);
    U_bstream_put_u16_le(&answer, address);

    if (!extended)
        return Zb_bstream_pos(&answer);

    for (i = 0; self->nwk != 0 && i < NWK_NEIGHBOR_MAX; i++)
        total += zdoDoIsAssociatedChild(&self->nwk->neighbors[i]) ? 1 : 0;

    countAt = Zb_bstream_pos(&answer);
    U_bstream_put_u8(&answer, 0);

    if (total == 0)
        return Zb_bstream_pos(&answer);

    U_bstream_put_u8(&answer, startIndex);

    for (i = 0; i < NWK_NEIGHBOR_MAX && listed < 0xff && Zb_bstream_pos(&answer) + 2 <= bodyMax; i++)
    {
        if (!zdoDoIsAssociatedChild(&self->nwk->neighbors[i]) || index++ < startIndex)
            continue;

        U_bstream_put_u16_le(&answer, self->nwk->neighbors[i].networkAddress);
        listed++;
    }

    body[countAt] = (uint8_t)listed;

    return Zb_bstream_pos(&answer);
}

/* The network address's answer: the address the IEEE belongs to, this device's own or an associated child's. A
   broadcast that names another, or that asks a reserved RequestType, is discarded unanswered. */
static ZbStatus zdoDoNwkAddress(Zdo_Zdo *self, const Af_Indication *indication, uint32_t nowMs)
{
    uint8_t body[ZDO_ASDU_MAX - 1];
    const Nwk_NeighborTableEntry *child;
    U_BStream request;
    uint64_t ieee;
    uint32_t length;
    uint16_t address;
    uint8_t requestType;
    uint8_t startIndex;
    int matched;

    if (indication->asduLength < 1 + 8 + 1 + 1)
        return ZB_ERR_BAD_ARGUMENT;

    zdoDoOpenRequest(&request, indication);
    ieee = U_bstream_get_u64_le(&request);
    requestType = U_bstream_get_u8(&request);
    startIndex = U_bstream_get_u8(&request);

    child = ieee == self->ownIeee ? 0 : zdoDoChildOf(self, 0, &ieee);
    matched = ieee == self->ownIeee || child != 0;
    address = child != 0 ? child->networkAddress : zdoDoOwnAddress(self);

    if ((!matched || requestType > ZDO_REQUEST_TYPE_EXTENDED) && zdoDoArrivedBroadcast(indication))
    {
        self->commandsBroadcastUnanswered++;

        return ZB_OK;
    }

    if (!matched)
        length = zdoDoWriteAddressAnswer(self, body, (uint32_t)sizeof body, ZDO_STATUS_DEVICE_NOT_FOUND, ieee,
                                         ZDO_ADDRESS_NONE, 0, 0);
    else if (requestType > ZDO_REQUEST_TYPE_EXTENDED)
        length = zdoDoWriteAddressAnswer(self, body, (uint32_t)sizeof body, ZDO_STATUS_INV_REQUESTTYPE, ieee,
                                         address, 0, 0);
    else if (requestType == ZDO_REQUEST_TYPE_SINGLE)
        length = zdoDoWriteAddressAnswer(self, body, (uint32_t)sizeof body, ZDO_STATUS_SUCCESS, ieee, address, 0, 0);
    else
        length = zdoDoWriteAddressAnswer(self, body, (uint32_t)sizeof body, ZDO_STATUS_SUCCESS, self->ownIeee,
                                         zdoDoOwnAddress(self), 1, startIndex);

    return zdoDoRespond(self, indication, ZDO_NWK_ADDR_REQ, body, length, nowMs);
}

/* The 64-bit address's answer: this device's own or an associated child's, else all ones; every request is answered,
   broadcast or not. */
static ZbStatus zdoDoIeeeAddress(Zdo_Zdo *self, const Af_Indication *indication, uint32_t nowMs)
{
    uint8_t body[ZDO_ASDU_MAX - 1];
    const Nwk_NeighborTableEntry *child;
    U_BStream request;
    uint32_t length;
    uint16_t address;
    uint8_t requestType;
    uint8_t startIndex;

    if (indication->asduLength < 1 + 2 + 1 + 1)
        return ZB_ERR_BAD_ARGUMENT;

    zdoDoOpenRequest(&request, indication);
    address = U_bstream_get_u16_le(&request);
    requestType = U_bstream_get_u8(&request);
    startIndex = U_bstream_get_u8(&request);

    child = zdoDoIsOwnAddress(self, address) ? 0 : zdoDoChildOf(self, address, 0);

    if (!zdoDoIsOwnAddress(self, address) && (child == 0 || !child->ieeeKnown))
        length = zdoDoWriteAddressAnswer(self, body, (uint32_t)sizeof body, ZDO_STATUS_DEVICE_NOT_FOUND,
                                         0xffffffffffffffff, address, 0, 0);
    else if (requestType > ZDO_REQUEST_TYPE_EXTENDED)
        length = zdoDoWriteAddressAnswer(self, body, (uint32_t)sizeof body, ZDO_STATUS_INV_REQUESTTYPE,
                                         self->ownIeee, zdoDoOwnAddress(self), 0, 0);
    else if (requestType == ZDO_REQUEST_TYPE_SINGLE)
        length = zdoDoWriteAddressAnswer(self, body, (uint32_t)sizeof body, ZDO_STATUS_SUCCESS,
                                         child != 0 ? child->extendedAddress : self->ownIeee, address, 0, 0);
    else
        length = zdoDoWriteAddressAnswer(self, body, (uint32_t)sizeof body, ZDO_STATUS_SUCCESS, self->ownIeee,
                                         zdoDoOwnAddress(self), 1, startIndex);

    return zdoDoRespond(self, indication, ZDO_IEEE_ADDR_REQ, body, length, nowMs);
}

/* A received announcement: the spec has every device update its address map to the pair it carries, and a router
   detect a conflict from it, which the network layer judges. */
static ZbStatus zdoDoDeviceAnnouncement(Zdo_Zdo *self, const Af_Indication *indication, uint32_t nowMs)
{
    uint64_t ieee = 0;
    uint16_t nwkAddress = 0;

    if (Zdo_DeviceAnnouncementParse(indication->asdu, indication->asduLength, &ieee, &nwkAddress, 0) != ZB_OK)
        return ZB_ERR_BAD_ARGUMENT;

    self->announcementsHeard++;

    if (self->nwk != 0)
        Nwk_AddressAnnounced(self->nwk, nwkAddress, ieee, nowMs);

    return ZB_OK;
}

/* The client's own frame: the counter, the command's fields, and a pending row so the answer can be matched to
   it. A request whose response never comes keeps its row until the pool is asked for another. */
ZbStatus Zdo_SendRequest(Zdo_Zdo *self, uint16_t destination, uint8_t destinationEndpoint, uint16_t cluster,
                         const uint8_t *payload, uint32_t payloadLen, uint32_t nowMs)
{
    Af_DataRequestParameters request;
    Zdo_PendingRequest *pending = 0;
    uint8_t asdu[ZDO_ASDU_MAX];
    U_BStream stream;
    uint8_t transactionSequenceNumber;
    ZbStatus status;
    uint32_t i;

    if (self == 0 || self->af == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payload == 0 && payloadLen != 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payloadLen + 1 > (uint32_t)sizeof asdu)
    {
        self->requestsRefused++;
        return ZB_ERR_NO_SPACE;
    }

    for (i = 0; i < ZDO_PENDING_MAX; i++)
    {
        if (!self->pending[i].inUse)
        {
            pending = &self->pending[i];
            break;
        }
    }

    if (pending == 0)
    {
        self->requestsRefused++;
        return ZB_ERR_NO_SPACE;
    }

    transactionSequenceNumber = self->transactionSequenceNumber++;

    U_bstream_init(&stream, asdu, (unsigned long)sizeof asdu);
    U_bstream_put_u8(&stream, transactionSequenceNumber);

    if (payloadLen != 0)
        U_bstream_put_bytes(&stream, payload, (unsigned long)payloadLen);

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.dstAddress = destination;
    request.dstEndpoint = destinationEndpoint;
    request.srcEndpoint = ZDO_ENDPOINT;
    request.tag = ZDO_TAG_OWN;
    request.clusterId = cluster;
    request.asdu = asdu;
    request.asduLength = payloadLen + 1;
    request.txOptions = AF_TX_ACKNOWLEDGED;

    status = Af_DataRequest(self->af, &request, nowMs);

    if (status != ZB_OK)
    {
        self->requestsRefused++;
        return status;
    }

    pending->inUse = 1;
    pending->clusterId = cluster;
    pending->transactionSequenceNumber = transactionSequenceNumber;
    pending->destination = destination;

    self->requestsSent++;

    return ZB_OK;
}

/* The match: a response is the request's cluster with bit 15 set and the same transaction sequence number, from the
   device the request went to. */
static int zdoDoMatch(Zdo_Zdo *self, const Af_Indication *indication)
{
    uint32_t i;

    for (i = 0; i < ZDO_PENDING_MAX; i++)
    {
        if (!self->pending[i].inUse)
            continue;

        if (self->pending[i].clusterId != (uint16_t)(indication->clusterId & (uint16_t)~ZDO_RESPONSE_BIT))
            continue;

        if (self->pending[i].transactionSequenceNumber != indication->asdu[0])
            continue;

        if (self->pending[i].destination != indication->srcAddress)
            continue;

        self->pending[i].inUse = 0;

        return 1;
    }

    return 0;
}

void Zdo_SetNetwork(Zdo_Zdo *self, Nwk_Nwk *nwk, Aps_Aps *aps, uint64_t extendedPanId)
{
    if (self == 0)
        return;

    self->nwk = nwk;
    self->aps = aps;
    self->extendedPanId = extendedPanId;
}

/* Table 2-101, 2-103 and 2-105's four header octets. */
static void zdoDoWriteHead(U_BStream *stream, uint32_t status, uint32_t total, uint32_t startIndex,
                           uint32_t listCount)
{
    U_bstream_put_u8(stream, (uint8_t)status);
    U_bstream_put_u8(stream, (uint8_t)total);
    U_bstream_put_u8(stream, (uint8_t)startIndex);
    U_bstream_put_u8(stream, (uint8_t)listCount);
}

/* Table 2-102's record. A neighbour is on this network or the report would not name it, so the extended PAN id is
   this network's; the tree depth is what this specification deprecated it to; the four fields whose "unknown" value
   the record prints are answered with it wherever the entry observed nothing; and every relationship from 0x03 up, a
   backbone mesh sibling's too, is affinity 0x03, "none of the above". */
static void zdoDoWriteNeighborRecord(U_BStream *stream, const Nwk_NeighborTableEntry *entry, uint64_t extendedPanId)
{
    uint32_t observed = entry->deviceType != NWK_NEIGHBOR_TYPE_UNKNOWN;

    U_bstream_put_u64_le(stream, extendedPanId);
    U_bstream_put_u64_le(stream, entry->ieeeKnown ? entry->extendedAddress : 0xffffffffffffffff);
    U_bstream_put_u16_le(stream, entry->networkAddress);
    U_bstream_put_u8(stream, (uint8_t)(((observed ? entry->deviceType : ZDO_NEIGHBOR_TYPE_UNKNOWN) & 0x03)
                                       | ((observed ? (uint32_t)entry->rxOnWhenIdle : ZDO_REPORT_UNKNOWN) << 2)
                                       | ((entry->relationship <= 0x02 ? entry->relationship : 0x03) << 4)));
    U_bstream_put_u8(stream, ZDO_REPORT_UNKNOWN);
    U_bstream_put_u8(stream, ZDO_REPORT_DEPTH_DEPRECATED);
    U_bstream_put_u8(stream, (uint8_t)(entry->lqi & 0xff));
}

/* Table 2-101's cap of two records, and 2.4.4.3.2.1's rule that only whole records are reported, up to the MSDU's
   room. */
uint32_t Zdo_NeighborReportCompose(const Zdo_Zdo *self, uint32_t startIndex, uint8_t *out, uint32_t outCap)
{
    U_BStream stream;
    uint32_t total;
    uint32_t listCount = 0;
    uint32_t index;

    if (self == 0 || self->nwk == 0 || out == 0)
        return 0;

    total = Nwk_NeighborTableEntries(self->nwk);

    for (index = startIndex; index < total && listCount < ZDO_NEIGHBOR_LIST_MAX; index++)
    {
        if (Nwk_NeighborTableAt(self->nwk, index) == 0)
            break;

        if (ZDO_REPORT_HEADER_OCTETS + (listCount + 1) * ZDO_NEIGHBOR_RECORD_OCTETS > outCap)
            break;

        listCount++;
    }

    U_bstream_init(&stream, out, (unsigned long)outCap);
    zdoDoWriteHead(&stream, ZDO_STATUS_SUCCESS, total, startIndex, listCount);

    for (index = 0; index < listCount; index++)
        zdoDoWriteNeighborRecord(&stream, Nwk_NeighborTableAt(self->nwk, startIndex + index), self->extendedPanId);

    return Zb_bstream_ok(&stream) ? Zb_bstream_pos(&stream) : 0;
}

/* Table 2-104's record: the two addresses and the five flags in one octet, of which Table 3-55's many-to-one form
   that asks for no route record is the concentrator Table 2-104 calls memory constrained. */
static void zdoDoWriteRouteRecord(U_BStream *stream, const Nwk_RoutingTableEntry *entry)
{
    U_bstream_put_u16_le(stream, entry->destinationAddress);
    U_bstream_put_u8(stream, (uint8_t)((entry->status & 0x07) | ((uint32_t)entry->noRouteCache << 3)
                                       | ((uint32_t)entry->manyToOne << 4)
                                       | ((uint32_t)entry->routeRecordRequired << 5)));
    U_bstream_put_u16_le(stream, entry->nextHopAddress);
}

uint32_t Zdo_RouteReportCompose(const Zdo_Zdo *self, uint32_t startIndex, uint8_t *out, uint32_t outCap)
{
    U_BStream stream;
    uint32_t total;
    uint32_t listCount = 0;
    uint32_t index;

    if (self == 0 || self->nwk == 0 || out == 0)
        return 0;

    total = Nwk_RouteTableEntries(self->nwk);

    for (index = startIndex; index < total; index++)
    {
        if (Nwk_RouteTableAt(self->nwk, index) == 0)
            break;

        if (ZDO_REPORT_HEADER_OCTETS + (listCount + 1) * ZDO_ROUTE_RECORD_OCTETS > outCap)
            break;

        listCount++;
    }

    U_bstream_init(&stream, out, (unsigned long)outCap);
    zdoDoWriteHead(&stream, ZDO_STATUS_SUCCESS, total, startIndex, listCount);

    for (index = 0; index < listCount; index++)
        zdoDoWriteRouteRecord(&stream, Nwk_RouteTableAt(self->nwk, startIndex + index));

    return Zb_bstream_ok(&stream) ? Zb_bstream_pos(&stream) : 0;
}

/* Table 2-106's record, whose length turns on its own destination mode: 14 octets for a group, 21 for an extended
   address with the endpoint it names. */
static uint32_t zdoDoBindingRecordLength(const Aps_Binding *entry)
{
    return entry->dstAddrMode == 0x03 ? 21 : 14;
}

static void zdoDoWriteBindingRecord(U_BStream *stream, const Aps_Binding *entry)
{
    U_bstream_put_u64_le(stream, entry->srcIeee);
    U_bstream_put_u8(stream, entry->srcEndpoint);
    U_bstream_put_u16_le(stream, entry->clusterId);
    U_bstream_put_u8(stream, (uint8_t)entry->dstAddrMode);

    if (entry->dstAddrMode == 0x03)
    {
        U_bstream_put_u64_le(stream, entry->dstExtendedAddress);
        U_bstream_put_u8(stream, entry->dstEndpoint);

        return;
    }

    U_bstream_put_u16_le(stream, entry->dstAddress);
}

/* An empty table is reported as SUCCESS with three zero octets after the status. */
uint32_t Zdo_BindingReportCompose(const Zdo_Zdo *self, uint32_t startIndex, uint8_t *out, uint32_t outCap)
{
    const Aps_Binding *pool = Aps_BindingPool(self != 0 ? self->aps : 0);
    uint32_t total = Aps_BindCount(pool);
    U_BStream stream;
    uint32_t octets = 0;
    uint32_t listCount = 0;
    uint32_t index;

    if (self == 0 || pool == 0 || out == 0)
        return 0;

    for (index = startIndex; index < total && listCount < ZDO_REPORT_MAX; index++)
    {
        const Aps_Binding *entry = Aps_BindEntryAt(pool, index);
        uint32_t length;

        if (entry == 0)
            break;

        length = zdoDoBindingRecordLength(entry);

        if (ZDO_REPORT_HEADER_OCTETS + octets + length > outCap)
            break;

        listCount++;
        octets += length;
    }

    if (total == 0)
        startIndex = 0;

    U_bstream_init(&stream, out, (unsigned long)outCap);
    zdoDoWriteHead(&stream, ZDO_STATUS_SUCCESS, total, startIndex, listCount);

    for (index = 0; index < listCount; index++)
        zdoDoWriteBindingRecord(&stream, Aps_BindEntryAt(pool, startIndex + index));

    return Zb_bstream_ok(&stream) ? Zb_bstream_pos(&stream) : 0;
}

/* Table 2-101, 2-103 and 2-105's four header octets, and their rule that a status which is not SUCCESS is the only
   octet such a report carries. */
static ZbStatus zdoDoReadHead(U_BStream *stream, const uint8_t *body, uint32_t length, Zdo_TableReport *head)
{
    if (body == 0 || head == 0 || length == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_bstream_init_const(stream, body, length);
    head->status = U_bstream_get_u8(stream);

    if (head->status != ZDO_STATUS_SUCCESS)
    {
        head->totalEntries = 0;
        head->startIndex = 0;
        head->listCount = 0;

        return ZB_OK;
    }

    if (length < ZDO_REPORT_HEADER_OCTETS)
        return ZB_ERR_BAD_ARGUMENT;

    head->totalEntries = U_bstream_get_u8(stream);
    head->startIndex = U_bstream_get_u8(stream);
    head->listCount = U_bstream_get_u8(stream);

    return ZB_OK;
}

ZbStatus Zdo_NeighborReportParse(const uint8_t *body, uint32_t length, Zdo_TableReport *head,
                                 Zdo_NeighborReport *out, uint32_t max)
{
    U_BStream stream;
    uint8_t flags;
    uint32_t i;

    if (zdoDoReadHead(&stream, body, length, head) != ZB_OK || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (head->listCount > ZDO_NEIGHBOR_LIST_MAX
        || !Zb_bstream_fits(&stream, (head->listCount * ZDO_NEIGHBOR_RECORD_OCTETS)))
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < head->listCount && i < max; i++)
    {
        Zdo_NeighborReport *report = &out[i];

        Zb_memset(report, 0, (uint32_t)sizeof *report);

        report->extendedPanId = U_bstream_get_u64_le(&stream);
        report->extendedAddress = U_bstream_get_u64_le(&stream);
        report->networkAddress = U_bstream_get_u16_le(&stream);
        flags = U_bstream_get_u8(&stream);
        report->deviceType = flags & 0x03;
        report->rxOnWhenIdle = (flags >> 2) & 0x03;
        report->affinity = (flags >> 4) & 0x07;
        report->permitJoining = U_bstream_get_u8(&stream) & 0x03;
        report->depth = U_bstream_get_u8(&stream);
        report->lqa = U_bstream_get_u8(&stream);

        if (report->deviceType > 0x03 || report->rxOnWhenIdle > ZDO_REPORT_UNKNOWN || report->affinity > 0x03
            || report->permitJoining > ZDO_REPORT_UNKNOWN)
            return ZB_ERR_BAD_ARGUMENT;
    }

    return ZB_OK;
}

ZbStatus Zdo_RouteReportParse(const uint8_t *body, uint32_t length, Zdo_TableReport *head, Zdo_RouteReport *out,
                              uint32_t max)
{
    U_BStream stream;
    uint8_t flags;
    uint32_t i;

    if (zdoDoReadHead(&stream, body, length, head) != ZB_OK || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (!Zb_bstream_fits(&stream, (head->listCount * ZDO_ROUTE_RECORD_OCTETS)))
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < head->listCount && i < max; i++)
    {
        Zdo_RouteReport *report = &out[i];

        Zb_memset(report, 0, (uint32_t)sizeof *report);

        report->destinationAddress = U_bstream_get_u16_le(&stream);
        flags = U_bstream_get_u8(&stream);
        report->status = flags & 0x07;
        report->memoryConstrained = (flags >> 3) & 0x01;
        report->manyToOne = (flags >> 4) & 0x01;
        report->routeRecordRequired = (flags >> 5) & 0x01;
        report->nextHopAddress = U_bstream_get_u16_le(&stream);

        if (report->status > NWK_ROUTE_INACTIVE)
            return ZB_ERR_BAD_ARGUMENT;
    }

    return ZB_OK;
}

ZbStatus Zdo_BindingReportParse(const uint8_t *body, uint32_t length, Zdo_TableReport *head, Zdo_BindingReport *out,
                                uint32_t max)
{
    U_BStream stream;
    uint32_t i;

    if (zdoDoReadHead(&stream, body, length, head) != ZB_OK || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < head->listCount && i < max; i++)
    {
        Zdo_BindingReport *report = &out[i];

        Zb_memset(report, 0, (uint32_t)sizeof *report);

        if (!Zb_bstream_fits(&stream, 14))
            return ZB_ERR_BAD_ARGUMENT;

        report->srcIeee = U_bstream_get_u64_le(&stream);
        report->srcEndpoint = U_bstream_get_u8(&stream);
        report->clusterId = U_bstream_get_u16_le(&stream);
        report->dstAddrMode = U_bstream_get_u8(&stream);

        if (report->dstAddrMode != 0x01 && report->dstAddrMode != 0x03)
            return ZB_ERR_BAD_ARGUMENT;

        if (report->dstAddrMode == 0x03)
        {
            if (!Zb_bstream_fits(&stream, 9))
                return ZB_ERR_BAD_ARGUMENT;

            report->dstExtendedAddress = U_bstream_get_u64_le(&stream);
            report->dstEndpoint = U_bstream_get_u8(&stream);

            if (report->dstEndpoint < 0x01 || report->dstEndpoint > 0xfe)
                return ZB_ERR_BAD_ARGUMENT;

            continue;
        }

        report->dstAddress = U_bstream_get_u16_le(&stream);
    }

    return ZB_OK;
}

/* The duration is the network layer's, 0xff in a command is read as 0xfe seconds, the TC_Significance octet is
   treated as 1 whatever the frame printed, and a broadcast is carried out with no answer. */
static ZbStatus zdoDoPermitJoining(Zdo_Zdo *self, const Af_Indication *indication, uint32_t nowMs)
{
    uint8_t body[1];
    U_BStream request;
    uint32_t permitDuration;
    uint32_t verdict;

    if (indication->asduLength < 3)
    {
        if (zdoDoArrivedBroadcast(indication))
        {
            self->commandsBroadcastUnanswered++;

            return ZB_OK;
        }

        body[0] = ZDO_STATUS_INV_REQUESTTYPE;
        return zdoDoRespond(self, indication, ZDO_MGMT_PERMIT_JOINING_REQ, body, 1, nowMs);
    }

    zdoDoOpenRequest(&request, indication);
    permitDuration = U_bstream_get_u8(&request);

    if (permitDuration == 0xff)
        permitDuration = NWK_PERMIT_SECONDS_MAX;

    verdict = Nwk_PermitJoining(self->nwk, permitDuration, nowMs);

    if (zdoDoArrivedBroadcast(indication))
    {
        self->commandsBroadcastUnanswered++;

        return ZB_OK;
    }

    if (verdict == NWK_PERMIT_SUCCESS)
        body[0] = ZDO_STATUS_SUCCESS;
    else
        body[0] = ZDO_STATUS_INV_REQUESTTYPE;

    return zdoDoRespond(self, indication, ZDO_MGMT_PERMIT_JOINING_REQ, body, 1, nowMs);
}

/* The leave verdicts rendered as Table 2-129's codes: a device that is not there, a request this device is not
   allowed to carry out, a frame the layer could not put on the air. */
static uint8_t zdoDoStatusOf(uint32_t verdict)
{
    if (verdict == NWK_LEAVE_STATUS_SUCCESS)
        return ZDO_STATUS_SUCCESS;

    if (verdict == NWK_LEAVE_STATUS_UNKNOWN_DEVICE)
        return ZDO_STATUS_UNKNOWN_DEVICE;

    if (verdict == NWK_LEAVE_STATUS_FRAME_NOT_BUFFERED)
        return ZDO_STATUS_NOT_SUPPORTED;

    return ZDO_STATUS_INV_REQUESTTYPE;
}

/* A request naming this device is carried out with the two parameters its clause fixes, and a request naming
   another device is the parent's removal of its own child. */
static ZbStatus zdoDoLeaveRequest(Zdo_Zdo *self, const Af_Indication *indication, uint32_t nowMs)
{
    uint8_t body[1];
    U_BStream request;
    uint64_t deviceAddress;
    uint8_t options;
    uint32_t removeChildren;
    uint32_t rejoin;
    uint32_t verdict;
    ZbStatus status;

    if (indication->asduLength < 10)
    {
        body[0] = ZDO_STATUS_INV_REQUESTTYPE;
        return zdoDoRespond(self, indication, ZDO_MGMT_LEAVE_REQ, body, 1, nowMs);
    }

    zdoDoOpenRequest(&request, indication);
    deviceAddress = U_bstream_get_u64_le(&request);
    options = U_bstream_get_u8(&request);
    removeChildren = (options & ZDO_LEAVE_OPTION_REMOVE_CHILDREN) ? 1 : 0;
    rejoin = (options & ZDO_LEAVE_OPTION_REJOIN) ? 1 : 0;

    if (deviceAddress == 0 || deviceAddress == self->ownIeee)
    {
        if (!Nwk_LeaveRequestAllowedFrom(self->nwk, indication->srcAddress,
                                         zdoDoArrivedBroadcast(indication)))
        {
            body[0] = ZDO_STATUS_NOT_AUTHORIZED;

            return zdoDoRespond(self, indication, ZDO_MGMT_LEAVE_REQ, body, 1, nowMs);
        }

        body[0] = ZDO_STATUS_SUCCESS;
        status = zdoDoRespond(self, indication, ZDO_MGMT_LEAVE_REQ, body, 1, nowMs);

        (void)Nwk_LeaveRequest(self->nwk, deviceAddress == 0 ? self->ownIeee : deviceAddress, 0, 0, nowMs);

        return status;
    }

    verdict = Nwk_LeaveRequest(self->nwk, deviceAddress, removeChildren, rejoin, nowMs);
    body[0] = zdoDoStatusOf(verdict);

    return zdoDoRespond(self, indication, ZDO_MGMT_LEAVE_REQ, body, 1, nowMs);
}

/* The three management requests, which are one StartIndex octet each, and the answer the three reports give when the
   layer they read is not there: the status alone. */
static ZbStatus zdoDoTableReport(Zdo_Zdo *self, const Af_Indication *indication, uint16_t cluster, uint32_t which,
                                 uint32_t nowMs)
{
    uint8_t body[ZDO_ASDU_MAX];
    U_BStream request;
    uint32_t startIndex;
    uint32_t length;

    if (indication->asduLength < 2)
    {
        body[0] = ZDO_STATUS_NOT_SUPPORTED;
        return zdoDoRespond(self, indication, cluster, body, 1, nowMs);
    }

    zdoDoOpenRequest(&request, indication);
    startIndex = U_bstream_get_u8(&request);

    if (which == 0)
        length = self->nwk != 0 ? Zdo_NeighborReportCompose(self, startIndex, body, (uint32_t)sizeof body) : 0;
    else if (which == 1)
        length = self->nwk != 0 ? Zdo_RouteReportCompose(self, startIndex, body, (uint32_t)sizeof body) : 0;
    else
        length = Aps_BindingPool(self->aps) != 0 ? Zdo_BindingReportCompose(self, startIndex, body,
                                                                            (uint32_t)sizeof body) : 0;

    if (length == 0)
    {
        body[0] = ZDO_STATUS_NOT_SUPPORTED;
        length = 1;
    }

    return zdoDoRespond(self, indication, cluster, body, length, nowMs);
}

/* Figure 2-28's entry out of a Bind_req or Unbind_req: source IEEE and endpoint, cluster, destination mode, then the
   destination and, where the mode names one, its endpoint. Exactly Table 2-55's octets; a mode it reserves is refused,
   a frame too short to name an entry is ZB_ERR_BAD_FRAME, and `out` is zeroed either way. */
static ZbStatus zdoDoReadBinding(const uint8_t *payload, uint32_t length, Aps_Binding *out)
{
    U_BStream stream;

    if (out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(out, 0, (uint32_t)sizeof *out);

    if (payload == 0 || length < 13)
        return ZB_ERR_BAD_FRAME;

    Zb_bstream_init_const(&stream, payload, length);
    U_bstream_advance(&stream, 1);
    out->srcIeee = U_bstream_get_u64_le(&stream);
    out->srcEndpoint = U_bstream_get_u8(&stream);
    out->clusterId = U_bstream_get_u16_le(&stream);
    out->dstAddrMode = U_bstream_get_u8(&stream);

    if (out->dstAddrMode == 0x03)
    {
        if (Zb_bstream_remaining(&stream) != 9)
            return ZB_ERR_BAD_ARGUMENT;

        out->dstExtendedAddress = U_bstream_get_u64_le(&stream);
        out->dstEndpoint = U_bstream_get_u8(&stream);

        return Aps_BindCheck(out);
    }

    if (out->dstAddrMode != 0x01)
        return ZB_ERR_BAD_ARGUMENT;

    if (Zb_bstream_remaining(&stream) != 2)
        return ZB_ERR_BAD_ARGUMENT;

    out->dstAddress = U_bstream_get_u16_le(&stream);

    return Aps_BindCheck(out);
}

/* The two endpoints Table 2-55 prints a range for, read out of an entry the request named even when the entry was
   refused. */
static int zdoDoEndpointFault(const Aps_Binding *entry)
{
    if (entry->srcEndpoint < 0x01 || entry->srcEndpoint > 0xfe)
        return 1;

    if (entry->dstAddrMode == 0x03 && (entry->dstEndpoint < 0x01 || entry->dstEndpoint > 0xfe))
        return 1;

    return 0;
}

/* Table 2-97's and Table 2-98's four answers: SUCCESS for the entry written or removed, INVALID_EP for a source
   endpoint outside the range the two commands print, TABLE_FULL for a table with no room, NO_ENTRY for an unbind of
   an entry the table does not hold, and NOT_SUPPORTED for a device that is neither the source nor the coordinator. */
static ZbStatus zdoDoBindingCommand(Zdo_Zdo *self, const Af_Indication *indication, uint16_t cluster, int add,
                                    uint32_t nowMs)
{
    Aps_Binding entry;
    const Aps_Binding *pool;
    uint8_t body[1];
    uint32_t verdict;
    ZbStatus shape;

    shape = zdoDoReadBinding(indication->asdu, indication->asduLength, &entry);

    if (shape != ZB_OK)
    {
        body[0] = shape != ZB_ERR_BAD_FRAME && zdoDoEndpointFault(&entry) ? ZDO_STATUS_INVALID_EP
                                                                         : ZDO_STATUS_NOT_SUPPORTED;
        return zdoDoRespond(self, indication, cluster, body, 1, nowMs);
    }

    pool = Aps_BindingPool(self->aps);

    if (pool == 0 || (entry.srcIeee != self->ownIeee && self->node.logicalType != ZDO_LOGICAL_COORDINATOR))
    {
        body[0] = ZDO_STATUS_NOT_SUPPORTED;
        return zdoDoRespond(self, indication, cluster, body, 1, nowMs);
    }

    verdict = Aps_BindRequest(self->aps, &entry, add);

    switch (verdict)
    {
    case APS_BIND_ADDED:
    case APS_BIND_PRESENT:
    case APS_BIND_REMOVED:
        body[0] = ZDO_STATUS_SUCCESS;
        break;

    case APS_BIND_FULL:
        body[0] = ZDO_STATUS_TABLE_FULL;
        break;

    case APS_BIND_ILLEGAL:
        body[0] = ZDO_STATUS_NOT_SUPPORTED;
        break;

    default:
        body[0] = ZDO_STATUS_NO_ENTRY;
        break;
    }

    return zdoDoRespond(self, indication, cluster, body, 1, nowMs);
}

ZbStatus Zdo_HandleIndication(Zdo_Zdo *self, const Af_Indication *indication, uint32_t nowMs)
{
    Zdo_Response *response;
    uint8_t notSupported[1];

    if (self != 0 && indication != 0 && (indication->clusterId & ZDO_RESPONSE_BIT) != 0
        && indication->asduLength != 0)
    {
        if (!zdoDoMatch(self, indication))
        {
            self->responsesUnmatched++;
            return ZB_OK;
        }

        if (self->responseCount >= ZDO_RESPONSE_MAX)
            return ZB_ERR_NO_SPACE;

        response = &self->responses[self->responseCount++];

        Zb_memset(response, 0, (uint32_t)sizeof *response);

        response->clusterId = (uint16_t)(indication->clusterId & (uint16_t)~ZDO_RESPONSE_BIT);
        response->transactionSequenceNumber = indication->asdu[0];
        response->sourceAddress = indication->srcAddress;
        response->sourceEndpoint = indication->srcEndpoint;
        response->length = indication->asduLength - 1;

        if (response->length != 0)
            Zb_memcpy(response->payload, indication->asdu + 1, response->length);

        return ZB_OK;
    }

    if (self == 0 || indication == 0 || self->af == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (indication->dstEndpoint != ZDO_ENDPOINT || indication->profileId != ZDO_PROFILE_ID)
    {
        self->framesRefused++;

        return ZB_ERR_NOT_FOUND;
    }

    if (zdoDoArrivedBroadcast(indication)
        && (indication->clusterId == ZDO_BIND_REQ || indication->clusterId == ZDO_UNBIND_REQ
            || indication->clusterId == ZDO_MGMT_LQI_REQ || indication->clusterId == ZDO_MGMT_RTG_REQ
            || indication->clusterId == ZDO_MGMT_BIND_REQ
            || indication->clusterId == ZDO_MGMT_LEAVE_REQ))
    {
        self->commandsDroppedBroadcast++;

        return ZB_OK;
    }

    if (indication->asduLength == 0)
        return ZB_ERR_BAD_ARGUMENT;

    switch (indication->clusterId)
    {
    case ZDO_NWK_ADDR_REQ:
        return zdoDoNwkAddress(self, indication, nowMs);

    case ZDO_IEEE_ADDR_REQ:
        return zdoDoIeeeAddress(self, indication, nowMs);

    case ZDO_NODE_DESC_REQ:
        return zdoDoNodeDescriptor(self, indication, nowMs);

    case ZDO_POWER_DESC_REQ:
        return zdoDoPowerDescriptor(self, indication, nowMs);

    case ZDO_SIMPLE_DESC_REQ:
        return zdoDoSimpleDescriptor(self, indication, nowMs);

    case ZDO_ACTIVE_EP_REQ:
        return zdoDoActiveEndpoints(self, indication, nowMs);

    case ZDO_MATCH_DESC_REQ:
        return zdoDoMatchDescriptor(self, indication, nowMs);

    case ZDO_DEVICE_ANNCE:
        return zdoDoDeviceAnnouncement(self, indication, nowMs);

    case ZDO_BIND_REQ:
        return zdoDoBindingCommand(self, indication, ZDO_BIND_REQ, 1, nowMs);

    case ZDO_UNBIND_REQ:
        return zdoDoBindingCommand(self, indication, ZDO_UNBIND_REQ, 0, nowMs);

    case ZDO_MGMT_LQI_REQ:
        return zdoDoTableReport(self, indication, ZDO_MGMT_LQI_REQ, 0, nowMs);

    case ZDO_MGMT_RTG_REQ:
        return zdoDoTableReport(self, indication, ZDO_MGMT_RTG_REQ, 1, nowMs);

    case ZDO_MGMT_BIND_REQ:
        return zdoDoTableReport(self, indication, ZDO_MGMT_BIND_REQ, 2, nowMs);

    case ZDO_MGMT_PERMIT_JOINING_REQ:
        return zdoDoPermitJoining(self, indication, nowMs);

    case ZDO_MGMT_LEAVE_REQ:
        return zdoDoLeaveRequest(self, indication, nowMs);

    default:
        self->commandsUnsupported++;
        break;
    }

    if (!self->unsupportedToApplication && !zdoDoArrivedBroadcast(indication))
    {
        notSupported[0] = ZDO_STATUS_NOT_SUPPORTED;
        (void)zdoDoRespond(self, indication, indication->clusterId, notSupported, 1, nowMs);
    }

    return ZB_ERR_UNSUPPORTED;
}

void Zdo_SetUnsupportedToApplication(Zdo_Zdo *self, int on)
{
    if (self != 0)
        self->unsupportedToApplication = on ? 1 : 0;
}


/* 2.4.3.1.11: a broadcast on cluster 0x0013 carrying the address, the 64-bit address and the capability octet, to
   the ZDO endpoint 0x00 every receiver's device object answers on (D-217): 0xff is "all active endpoints except
   endpoint 0x00", which a device object would never see. */
ZbStatus Zdo_DeviceAnnce(Zdo_Zdo *self, uint32_t nowMs)
{
    Af_DataRequestParameters request;
    uint8_t asdu[1 + 2 + 8 + 1];
    U_BStream stream;
    ZbStatus status;

    if (self == 0 || self->af == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (zdoDoOwnAddress(self) == ZDO_ADDRESS_NONE)
        return ZB_ERR_NOT_READY;

    U_bstream_init(&stream, asdu, (unsigned long)sizeof asdu);
    U_bstream_put_u8(&stream, self->transactionSequenceNumber++);
    U_bstream_put_u16_le(&stream, zdoDoOwnAddress(self));
    U_bstream_put_u64_le(&stream, self->ownIeee);
    U_bstream_put_u8(&stream, self->node.macCapabilityFlags);

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.dstAddress = 0xfffd;
    request.dstEndpoint = ZDO_ENDPOINT;
    request.srcEndpoint = ZDO_ENDPOINT;
    request.tag = ZDO_TAG_OWN;
    request.clusterId = ZDO_DEVICE_ANNCE;
    request.asdu = asdu;
    request.asduLength = (uint32_t)sizeof asdu;
    request.txOptions = 0;

    status = Af_DataRequest(self->af, &request, nowMs);

    if (status != ZB_OK)
    {
        self->requestsRefused++;
        return status;
    }

    self->announcementsSent++;
    self->requestsSent++;

    return ZB_OK;
}

uint32_t Zdo_RequestsSent(const Zdo_Zdo *self)
{
    return self != 0 ? self->requestsSent : 0;
}

uint32_t Zdo_ResponsesSent(const Zdo_Zdo *self)
{
    return self != 0 ? self->responsesSent : 0;
}

uint32_t Zdo_ResponsesRefused(const Zdo_Zdo *self)
{
    return self != 0 ? self->responsesRefused : 0;
}

uint32_t Zdo_FramesRefused(const Zdo_Zdo *self)
{
    return self != 0 ? self->framesRefused : 0;
}

uint32_t Zdo_CommandsUnsupported(const Zdo_Zdo *self)
{
    return self != 0 ? self->commandsUnsupported : 0;
}

uint32_t Zdo_AnnouncementsSent(const Zdo_Zdo *self)
{
    return self != 0 ? self->announcementsSent : 0;
}

/* Table 2-31 read back: the same two octets of flags, then the fields, the status and address of interest ahead of
   them being the caller's to check. */
ZbStatus Zdo_NodeDescriptorParse(const uint8_t *payload, uint32_t length, Zdo_NodeDescriptor *out)
{
    U_BStream stream;
    uint8_t octet;

    if (payload == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_bstream_init_const(&stream, payload, length);

    if (length < 3 + 13 || U_bstream_get_u8(&stream) != ZDO_STATUS_SUCCESS)
        return ZB_ERR_BAD_ARGUMENT;

    U_bstream_advance(&stream, 2);
    Zb_memset(out, 0, (uint32_t)sizeof *out);

    octet = U_bstream_get_u8(&stream);
    out->logicalType = (uint8_t)(octet & 0x07);
    out->fragmentationSupported = (uint8_t)((octet >> 5) & 0x01);
    octet = U_bstream_get_u8(&stream);
    out->apsFlags = (uint8_t)((octet >> 5) & 0x07);
    out->frequencyBand = (uint8_t)(octet & 0x1f);
    out->macCapabilityFlags = U_bstream_get_u8(&stream);
    out->manufacturerCode = U_bstream_get_u16_le(&stream);
    out->maxBufferSize = U_bstream_get_u8(&stream);
    out->maxIncomingTransferSize = U_bstream_get_u16_le(&stream);
    out->serverMask = U_bstream_get_u16_le(&stream);
    out->maxOutgoingTransferSize = U_bstream_get_u16_le(&stream);
    out->descriptorCapability = U_bstream_get_u8(&stream);

    return ZB_OK;
}

ZbStatus Zdo_PowerDescriptorParse(const uint8_t *payload, uint32_t length, Zdo_PowerDescriptor *out)
{
    U_BStream stream;
    uint8_t octet;

    if (payload == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_bstream_init_const(&stream, payload, length);

    if (length < 3 + 2 || U_bstream_get_u8(&stream) != ZDO_STATUS_SUCCESS)
        return ZB_ERR_BAD_ARGUMENT;

    U_bstream_advance(&stream, 2);
    octet = U_bstream_get_u8(&stream);
    out->currentPowerMode = (uint8_t)(octet & 0x0f);
    out->availablePowerSources = (uint8_t)((octet >> 4) & 0x0f);
    octet = U_bstream_get_u8(&stream);
    out->currentPowerSource = (uint8_t)(octet & 0x0f);
    out->currentPowerSourceLevel = (uint8_t)((octet >> 4) & 0x0f);

    return ZB_OK;
}

/* Table 2-40 read back: the status and address of interest first, then the length, then the record, read no
   further than the length says. */
ZbStatus Zdo_SimpleDescriptorParse(const uint8_t *payload, uint32_t length, Af_SimpleDescriptor *out)
{
    U_BStream stream;
    U_BStream record;
    uint32_t recordLen;
    uint32_t i;

    if (payload == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_bstream_init_const(&stream, payload, length);

    if (length < 4 || U_bstream_get_u8(&stream) != ZDO_STATUS_SUCCESS)
        return ZB_ERR_BAD_ARGUMENT;

    U_bstream_advance(&stream, 2);
    recordLen = U_bstream_get_u8(&stream);

    if (recordLen < 8 || length < 4 + recordLen)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_bstream_sub(&stream, &record, recordLen);
    Zb_memset(out, 0, (uint32_t)sizeof *out);

    out->endpoint = U_bstream_get_u8(&record);
    out->profileId = U_bstream_get_u16_le(&record);
    out->deviceId = U_bstream_get_u16_le(&record);
    out->deviceVersion = (uint8_t)(U_bstream_get_u8(&record) & 0x0f);
    out->inputClusterCount = U_bstream_get_u8(&record);

    if (out->inputClusterCount > AF_CLUSTER_MAX
        || !Zb_bstream_fits(&record, 2 * out->inputClusterCount + 1))
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < out->inputClusterCount; i++)
        out->inputClusters[i] = U_bstream_get_u16_le(&record);

    out->outputClusterCount = U_bstream_get_u8(&record);

    if (out->outputClusterCount > AF_CLUSTER_MAX
        || !Zb_bstream_fits(&record, 2 * out->outputClusterCount))
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < out->outputClusterCount; i++)
        out->outputClusters[i] = U_bstream_get_u16_le(&record);

    return ZB_OK;
}

/* Table 2-92 read back: the status and the address of interest, then the count and its list. */
uint32_t Zdo_ActiveEndpointsParse(const uint8_t *payload, uint32_t length, uint8_t *out, uint32_t outMax)
{
    U_BStream stream;
    uint32_t count;

    if (payload == 0 || out == 0 || length < 4)
        return 0;

    Zb_bstream_init_const(&stream, payload, length);

    if (U_bstream_get_u8(&stream) != ZDO_STATUS_SUCCESS)
        return 0;

    U_bstream_advance(&stream, 2);
    count = U_bstream_get_u8(&stream);

    if (count > outMax || !Zb_bstream_fits(&stream, count))
        return 0;

    U_bstream_get_bytes(&stream, out, (unsigned long)count);

    return count;
}

ZbStatus Zdo_DeviceAnnouncementParse(const uint8_t *asdu, uint32_t length, uint64_t *ieee, uint16_t *nwkAddress,
                                     uint8_t *capability)
{
    U_BStream stream;
    uint16_t address;
    uint64_t extended;
    uint8_t octet;

    if (asdu == 0 || length < 12)
        return ZB_ERR_BAD_FRAME;

    Zb_bstream_init_const(&stream, asdu, length);
    U_bstream_advance(&stream, 1);
    address = U_bstream_get_u16_le(&stream);
    extended = U_bstream_get_u64_le(&stream);
    octet = U_bstream_get_u8(&stream);

    if (nwkAddress != 0)
        *nwkAddress = address;

    if (ieee != 0)
        *ieee = extended;

    if (capability != 0)
        *capability = octet;

    return ZB_OK;
}

uint32_t Zdo_PollResponses(Zdo_Zdo *self, Zdo_Response *out, uint32_t max)
{
    uint32_t taken = 0;
    uint32_t i;

    if (self == 0 || out == 0)
        return 0;

    while (taken < max && self->responseCount > 0)
    {
        out[taken++] = self->responses[0];

        for (i = 1; i < self->responseCount; i++)
            self->responses[i - 1] = self->responses[i];

        self->responseCount--;
    }

    return taken;
}

uint32_t Zdo_ResponsesUnmatched(const Zdo_Zdo *self)
{
    return self != 0 ? self->responsesUnmatched : 0;
}

uint32_t Zdo_PendingCount(const Zdo_Zdo *self)
{
    uint32_t count = 0;
    uint32_t i;

    if (self == 0)
        return 0;

    for (i = 0; i < ZDO_PENDING_MAX; i++)
    {
        if (self->pending[i].inUse)
            count++;
    }

    return count;
}

uint32_t Zdo_AnnouncementsHeard(const Zdo_Zdo *self)
{
    return self != 0 ? self->announcementsHeard : 0;
}

uint8_t Zdo_TransactionSequenceNumber(const Zdo_Zdo *self)
{
    return self != 0 ? self->transactionSequenceNumber : 0;
}

#if ZB_ZDO_CLIENT
void Zdo_AdvanceTransactionSequenceNumber(Zdo_Zdo *self)
{
    if (self != 0)
        self->transactionSequenceNumber++;
}

uint16_t Zdo_OwnAddress(const Zdo_Zdo *self)
{
    return self != 0 ? zdoDoOwnAddress(self) : ZDO_ADDRESS_NONE;
}

const Zdo_NodeDescriptor *Zdo_OwnNodeDescriptor(const Zdo_Zdo *self)
{
    return self != 0 ? &self->node : 0;
}
#endif

uint32_t Zdo_CommandsDroppedBroadcast(const Zdo_Zdo *self)
{
    return self != 0 ? self->commandsDroppedBroadcast : 0;
}

uint32_t Zdo_CommandsBroadcastUnanswered(const Zdo_Zdo *self)
{
    return self != 0 ? self->commandsBroadcastUnanswered : 0;
}
