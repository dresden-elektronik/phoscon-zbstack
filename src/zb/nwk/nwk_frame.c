#include "nwk_frame.h"

#include "nwk_addr.h"

#include "zb_bstream.h"
#include "zb_utils.h"

/* R23.1: 3.3, 3.3.1.1, 3.3.1.1.2, 3.3.1.1.5, 3.3.1.2, 3.3.1.3, 3.3.1.4, 3.3.1.5, 3.3.1.6, 3.3.1.7, 3.3.1.8, 3.3.2.2.2,
   3.4, 3.6.4.3, 3.6.6, 3.6.7, 4.3.2, 1.4.2 ok (Figure 3-4 both ways, the sub-field rules, Table 3-51 on generation and
   Table 3-80's classes with its reserved rows); 3.3.1.8.1, 3.4.1.1, 3.6.4.5 elsewhere. docs/internals/conformance.md pages. */

/* Table 3-80's four destination classes, which 3.3.1.6 gates a header field on; whether a class corresponds to this
   device is 3.6.6's question, asked in `nwk`. 0xfffe and 0xfff8-0xfffa are the table's reserved rows, not classes. */
static int nwkFrameIsBroadcastAddress(uint16_t address)
{
    if (address == NWK_ADDR_RESERVED)
        return 0;

    return address >= NWK_ADDR_LOW_POWER_ROUTERS ? 1 : 0;
}

/* The two rows of Table 3-80 that name no class: 0xfff8-0xfffa and 0xfffe. */
static int nwkFrameIsReservedDestination(uint16_t address)
{
    if (address == NWK_ADDR_RESERVED)
        return 1;

    return address >= NWK_ADDR_RESERVED_LOW && address < NWK_ADDR_LOW_POWER_ROUTERS;
}

/* Figure 3-4 up to the routing fields: the five fields 3.3.1.2 … 3.3.1.5 make always-present, then
   each IEEE address the FCF says is there. */
static uint32_t nwkFrameBaseLen(const Nwk_Frame *frame)
{
    uint32_t len;

    len = NWK_MIN_HEADER_OVERHEAD;

    if (frame->destIeeePresent)
        len = len + NWK_IEEE_ADDR_OCTETS;

    if (frame->srcIeeePresent)
        len = len + NWK_IEEE_ADDR_OCTETS;

    return len;
}

/* 3.3.1.8 with Figure 3-6: relay count, relay index, then two octets per relay. */
static uint32_t nwkFrameRouteLen(const Nwk_Frame *frame)
{
    if (!frame->sourceRoute)
        return 0;

    return NWK_FRAME_ROUTE_CONTROL_OCTETS + NWK_FRAME_RELAY_OCTETS * (uint32_t)frame->relayCount;
}

uint32_t NwkFrame_HeaderLen(const Nwk_Frame *frame)
{
    if (frame == 0)
        return 0;

    return nwkFrameBaseLen(frame) + nwkFrameRouteLen(frame);
}

static uint16_t nwkFrameFcf(const Nwk_Frame *frame)
{
    uint16_t fcf;

    fcf = (uint16_t)(((uint16_t)frame->frameType & NWK_FRAME_FCF_TYPE_MASK) << NWK_FRAME_FCF_TYPE_SHIFT);
    fcf = (uint16_t)(fcf | (uint16_t)(((uint16_t)frame->protocolVersion & NWK_FRAME_FCF_PROTOCOL_VERSION_MASK) << NWK_FRAME_FCF_PROTOCOL_VERSION_SHIFT));
    fcf = (uint16_t)(fcf | (uint16_t)(((uint16_t)frame->discoverRoute & NWK_FRAME_FCF_DISCOVER_ROUTE_MASK) << NWK_FRAME_FCF_DISCOVER_ROUTE_SHIFT));

    if (frame->multicastDeprecated)
        fcf = (uint16_t)(fcf | (1 << NWK_FRAME_FCF_MULTICAST_SHIFT));

    if (frame->securityEnabled)
        fcf = (uint16_t)(fcf | (1 << NWK_FRAME_FCF_SECURITY_SHIFT));

    if (frame->sourceRoute)
        fcf = (uint16_t)(fcf | (1 << NWK_FRAME_FCF_SOURCE_ROUTE_SHIFT));

    if (frame->destIeeePresent)
        fcf = (uint16_t)(fcf | (1 << NWK_FRAME_FCF_DEST_IEEE_SHIFT));

    if (frame->srcIeeePresent)
        fcf = (uint16_t)(fcf | (1 << NWK_FRAME_FCF_SRC_IEEE_SHIFT));

    if (frame->endDeviceInitiator)
        fcf = (uint16_t)(fcf | (1 << NWK_FRAME_FCF_END_DEVICE_INITIATOR_SHIFT));

    return fcf;
}

/* Figure 3-5's sub-field order, one judgement per step; bits 14-15 have no field at all and bit 9 is the security crossing's (4.3.2) */
static ZbStatus nwkFrameClaim(const Nwk_Frame *frame, uint32_t *outLen)
{
    if (frame == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->frameType < NWK_FRAME_TYPE_DATA || frame->frameType > NWK_FRAME_TYPE_INTERPAN)
        return ZB_ERR_BAD_ARGUMENT;     

    if (frame->frameType == NWK_FRAME_TYPE_RESERVED
        || frame->frameType == NWK_FRAME_TYPE_INTERPAN)
        return ZB_ERR_UNSUPPORTED;    /* 0b10 is reserved; 0b11 is Inter-PAN, not built, docs/internals/architecture.md §8 */

    if (frame->protocolVersion < 1 || frame->protocolVersion > 3)
        return ZB_ERR_BAD_ARGUMENT;     

    if (frame->protocolVersion == 3)
        return ZB_ERR_UNSUPPORTED;    /* 0x03 is Green Power (Annex G), handed to the Interpan APS: not built, docs/internals/architecture.md §8 */

    if (frame->discoverRoute < NWK_DISCOVER_SUPPRESS || frame->discoverRoute > NWK_DISCOVER_ENABLE)
        return ZB_ERR_BAD_ARGUMENT;     

    if (frame->frameType == NWK_FRAME_TYPE_COMMAND && frame->discoverRoute != NWK_DISCOVER_SUPPRESS)
        return ZB_ERR_BAD_ARGUMENT;     

    if (frame->destIeeePresent && nwkFrameIsBroadcastAddress(frame->destAddr))
        return ZB_ERR_BAD_ARGUMENT;     

    *outLen = nwkFrameBaseLen(frame);

    return ZB_OK;
}

/* 3.3.1.1.5 with 3.3.1.8: the sub-field set if and only if the subframe is present, the relay index inside the count, and the count bounded by the octets' room rather than by nwkMaxSourceRoute's smaller number */
static ZbStatus nwkFrameRoute(const Nwk_Frame *frame, uint32_t *outLen)
{
    if ((frame->sourceRoute ? 1 : 0) != (frame->relayCount > 0 ? 1 : 0))
        return ZB_ERR_BAD_ARGUMENT;

    if (frame->relayCount > NWK_MAX_RELAYS)
        return ZB_ERR_BAD_ARGUMENT;     

    if (frame->relayCount > 0 && (uint32_t)frame->relayIndex >= (uint32_t)frame->relayCount)
        return ZB_ERR_BAD_ARGUMENT;

    *outLen = nwkFrameRouteLen(frame);

    return ZB_OK;
}

/* 3.3.2.2.2 with Figure 3-8: the NWK command identifier is the first octet of the payload, so a
   command frame with no payload octet carries no command and is not a command frame. */
static ZbStatus nwkFrameCommandId(const Nwk_Frame *frame, uint32_t payloadLen)
{
    if (frame->frameType == NWK_FRAME_TYPE_COMMAND && payloadLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    return ZB_OK;
}

/* What only the transmit side enforces: the two subfields a device of this network does not write, Table 3-51's
   Source routed row and the nwkMaxSourceRoute cap on the routes it builds (3.6.4.3 transmits a source route
   shorter than that). The Broadcast row binds a broadcast this device originates; a relay carries the sender's. */
/* Table 3-51's rows are what this layer generates: a real network's source-routed frames carry Discover Route 01
   when they arrive (the interop fixtures), so the configuration is refused on the way out and read as it comes.
   Table 3-80's two reserved rows are 1.4.2's reserved codes and are refused here for the same reason. */
static ZbStatus nwkFrameTransmit(const Nwk_Frame *frame, int relayed)
{
    if (frame->protocolVersion != NWK_PROTOCOL_VERSION)
        return ZB_ERR_UNSUPPORTED;    /* Table 3-65 pins nwkcProtocolVersion to 0x02, docs/internals/architecture.md §5 */

    if (frame->multicastDeprecated)
        return ZB_ERR_UNSUPPORTED;    /* 3.6.7 deprecates network-level multicast: refused as the printed answer, docs/internals/conformance.md §2 */

    /* nwkMaxSourceRoute (NIB 0x93) caps the routes this device builds; a relayed one is bounded by the octets' room
       alone, which `nwkFrameRoute` tests, docs/internals/conformance.md §2. */
    if (!relayed && frame->sourceRoute && frame->relayCount > NWK_MAX_SOURCE_ROUTE)
        return ZB_ERR_UNSUPPORTED;

    if (!relayed && frame->frameType == NWK_FRAME_TYPE_DATA && frame->discoverRoute != NWK_DISCOVER_SUPPRESS
        && nwkFrameIsBroadcastAddress(frame->destAddr))
        return ZB_ERR_BAD_ARGUMENT;

    if (nwkFrameIsReservedDestination(frame->destAddr))
        return ZB_ERR_BAD_ARGUMENT;

    return ZB_OK;
}

/* Figure 3-4 in transmission order; 3.3's bit rule makes each put_*_le the stated order */
static void nwkFrameDoWriteHeader(U_BStream *stream, const Nwk_Frame *frame)
{
    U_bstream_put_u16_le(stream, nwkFrameFcf(frame));
    U_bstream_put_u16_le(stream, frame->destAddr);
    U_bstream_put_u16_le(stream, frame->srcAddr);
    U_bstream_put_u8(stream, frame->radius);
    U_bstream_put_u8(stream, frame->sequenceNumber);

    if (frame->destIeeePresent)
        U_bstream_put_u64_le(stream, frame->destIeee);

    if (frame->srcIeeePresent)
        U_bstream_put_u64_le(stream, frame->srcIeee);
}

/* 3.3.1.8: relay count, relay index, then the list closest-to-destination first, low octet first */
static void nwkFrameDoWriteRouteSubframe(U_BStream *stream, const Nwk_Frame *frame)
{
    uint32_t index;

    U_bstream_put_u8(stream, frame->relayCount);
    U_bstream_put_u8(stream, frame->relayIndex);

    for (index = 0; index < (uint32_t)frame->relayCount; index++)
        U_bstream_put_u16_le(stream, frame->relayList[index]);
}

/* Table 3-51's Source routed row allows Discover Route 00 and nothing else, and it governs what this device sends: the
   same combination arriving from a peer is still read, which is why the rule sits here and not in the shared claim. */
static ZbStatus nwkFrameDoCompose(const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                                 uint8_t *out, uint32_t outCap, uint32_t *outLen, int relayed)
{
    U_BStream stream;
    uint32_t baseLen;
    uint32_t routeLen;
    uint32_t headerLen;
    uint32_t totalLen;
    ZbStatus status;

    if (out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (payload == 0 && payloadLen != 0)
        return ZB_ERR_BAD_ARGUMENT;

    status = nwkFrameClaim(frame, &baseLen);

    if (status == ZB_OK && frame->sourceRoute && frame->discoverRoute != NWK_DISCOVER_SUPPRESS)
        return ZB_ERR_BAD_ARGUMENT;

    if (status != ZB_OK)
        return status;

    status = nwkFrameRoute(frame, &routeLen);

    if (status != ZB_OK)
        return status;

    status = nwkFrameTransmit(frame, relayed);

    if (status != ZB_OK)
        return status;

    status = nwkFrameCommandId(frame, payloadLen);

    if (status != ZB_OK)
        return status;

    headerLen = baseLen + routeLen;
    totalLen = headerLen + payloadLen;

    if (totalLen > NWK_FRAME_NPDU_MAX)
        return ZB_ERR_BAD_ARGUMENT;     

    if (outCap < totalLen)
        return ZB_ERR_NO_SPACE;

    U_bstream_init(&stream, out, (unsigned long)outCap);

    nwkFrameDoWriteHeader(&stream, frame);

    if (frame->sourceRoute)
        nwkFrameDoWriteRouteSubframe(&stream, frame);

    if (payload != 0 && payloadLen != 0)
        U_bstream_put_bytes(&stream, payload, (unsigned long)payloadLen);

    if (!Zb_bstream_ok(&stream) || Zb_bstream_pos(&stream) != totalLen)
        return ZB_ERR_NO_SPACE;     

    *outLen = totalLen;

    return ZB_OK;
}

ZbStatus NwkFrame_Compose(const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                          uint8_t *out, uint32_t outCap, uint32_t *outLen)
{
    return nwkFrameDoCompose(frame, payload, payloadLen, out, outCap, outLen, 0);
}

ZbStatus NwkFrame_ComposeRelay(const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                               uint8_t *out, uint32_t outCap, uint32_t *outLen)
{
    return nwkFrameDoCompose(frame, payload, payloadLen, out, outCap, outLen, 1);
}

ZbStatus NwkFrame_Parse(const uint8_t *npdu, uint32_t npduLen, Nwk_Frame *frame,
                        uint32_t *payloadOffset, uint32_t *payloadLen)
{
    U_BStream stream;
    Nwk_Frame parsed;
    uint16_t fcf;
    uint32_t baseLen;
    uint32_t routeLen;
    uint32_t headerLen;
    uint32_t claimedLen;
    uint32_t payloadSpan;
    uint32_t index;
    ZbStatus status;

    if (npdu == 0 || frame == 0 || payloadOffset == 0 || payloadLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (npduLen < NWK_MIN_HEADER_OVERHEAD || npduLen > NWK_FRAME_NPDU_MAX)
        return ZB_ERR_BAD_ARGUMENT;     

    Zb_bstream_init_const(&stream, npdu, npduLen);

    Zb_memset(&parsed, 0, (uint32_t)sizeof parsed);

    fcf = U_bstream_get_u16_le(&stream);
    parsed.frameType = (fcf >> NWK_FRAME_FCF_TYPE_SHIFT) & NWK_FRAME_FCF_TYPE_MASK;
    parsed.protocolVersion = (fcf >> NWK_FRAME_FCF_PROTOCOL_VERSION_SHIFT) & NWK_FRAME_FCF_PROTOCOL_VERSION_MASK;
    parsed.discoverRoute = (fcf >> NWK_FRAME_FCF_DISCOVER_ROUTE_SHIFT) & NWK_FRAME_FCF_DISCOVER_ROUTE_MASK;
    parsed.multicastDeprecated = (fcf >> NWK_FRAME_FCF_MULTICAST_SHIFT) & NWK_FRAME_FCF_MULTICAST_MASK;
    parsed.securityEnabled = (fcf >> NWK_FRAME_FCF_SECURITY_SHIFT) & NWK_FRAME_FCF_SECURITY_MASK;
    parsed.sourceRoute = (fcf >> NWK_FRAME_FCF_SOURCE_ROUTE_SHIFT) & NWK_FRAME_FCF_SOURCE_ROUTE_MASK;
    parsed.destIeeePresent = (fcf >> NWK_FRAME_FCF_DEST_IEEE_SHIFT) & NWK_FRAME_FCF_DEST_IEEE_MASK;
    parsed.srcIeeePresent = (fcf >> NWK_FRAME_FCF_SRC_IEEE_SHIFT) & NWK_FRAME_FCF_SRC_IEEE_MASK;
    parsed.endDeviceInitiator = (fcf >> NWK_FRAME_FCF_END_DEVICE_INITIATOR_SHIFT) & NWK_FRAME_FCF_END_DEVICE_INITIATOR_MASK;


    parsed.destAddr = U_bstream_get_u16_le(&stream);
    parsed.srcAddr = U_bstream_get_u16_le(&stream);
    parsed.radius = U_bstream_get_u8(&stream);
    parsed.sequenceNumber = U_bstream_get_u8(&stream);

    status = nwkFrameClaim(&parsed, &baseLen);

    if (status != ZB_OK)
        return status;

    claimedLen = baseLen + (parsed.sourceRoute ? NWK_FRAME_ROUTE_CONTROL_OCTETS : 0);

    if (npduLen < claimedLen)
        return ZB_ERR_BAD_ARGUMENT;

    if (parsed.destIeeePresent)
        parsed.destIeee = U_bstream_get_u64_le(&stream);

    if (parsed.srcIeeePresent)
        parsed.srcIeee = U_bstream_get_u64_le(&stream);

    if (parsed.sourceRoute)
    {
        parsed.relayCount = U_bstream_get_u8(&stream);
        parsed.relayIndex = U_bstream_get_u8(&stream);

        status = nwkFrameRoute(&parsed, &routeLen);

        if (status != ZB_OK)
            return status;

        for (index = 0; index < (uint32_t)parsed.relayCount; index++)
            parsed.relayList[index] = U_bstream_get_u16_le(&stream);
    }
    else
        routeLen = 0;

    headerLen = baseLen + routeLen;

    if (!Zb_bstream_ok(&stream) || Zb_bstream_pos(&stream) != headerLen)
        return ZB_ERR_BAD_ARGUMENT;

    payloadSpan = npduLen - headerLen;

    status = nwkFrameCommandId(&parsed, payloadSpan);

    if (status != ZB_OK)
        return status;

    *frame = parsed;
    *payloadOffset = headerLen;
    *payloadLen = payloadSpan;

    return ZB_OK;
}
