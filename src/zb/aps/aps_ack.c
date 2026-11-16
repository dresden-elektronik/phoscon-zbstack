#include "aps.h"

#include "aps_ack.h"

#include "aps_frame.h"
#include "nwk.h"
#include "zb_utils.h"

/* R23.1 2.2.4.1.1 2.2.5.1.1 2.2.5.2.3 2.2.8.4.1 2.2.8.4.2 2.2.8.4.3 2.2.8.4.4 2.2.8.4.5.4 4.2.2 4.4.1 ok (the window
   acknowledgement included; the receive path that asks for it is `aps.c`'s). docs/internals/conformance.md pages 61, 86, 91,
   101-103, 105, 417, 425. */

/* Which transaction an acknowledgement answers: 2.2.8.4.4's fields on a waiting slot, plus band A's guard on its source
   (docs/internals/conformance.md §3). An ACK format 1 carries no cluster or endpoint, so it answers a slot whose own frame is a
   command on the counter and the source alone. */
Aps_Tx *Aps_AckSlotForAck(Aps_Tx *txPool, const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame)
{
    uint32_t i;
    int commandSlot;

    for (i = 0; i < APS_TX_MAX; i++)
    {
        if (txPool[i].state != APS_TX_AWAITING_ACK)
            continue;

        commandSlot = ((txPool[i].apdu[0] >> APS_FRAME_FCF_TYPE_SHIFT) & APS_FRAME_FCF_TYPE_MASK)
                      == APS_FRAME_TYPE_COMMAND;

        if (frame->ackFormat != (commandSlot ? 1 : 0))
            continue;

        if (!commandSlot)
        {
            if (!frame->clusterPresent || frame->clusterId != txPool[i].clusterId)
                continue;

            if (!frame->srcEndpointPresent || frame->srcEndpoint != txPool[i].dstEndpoint)
                continue;
        }

        if (frame->apsCounter != txPool[i].apsCounter)
            continue;

        if (ind->srcAddr != txPool[i].dstAddress)
            continue;

        return &txPool[i];
    }

    return 0;
}

/* The acknowledgement this device owes a frame it accepted: Figure 2-9 with 2.2.5.2.3.1's copies, out at 2.2.8.4.3.2's
   moment, issued as a unicast with the route discovery 2.2.8.4.1 obliges, protected as 4.2.2 asks with the ask taken
   from the network's own state. Band A reads "correctly receives" as the Status the façade settled on, so a frame it
   refused goes unanswered (docs/internals/conformance.md §3). */
/* The one answer both doors compose and hand down: the fields are the same either way, and only the block number and
   the bitfield of the extended header differ. */
static Aps_AckOutcome apsDoAckIssue(const Nwk_DataIndicationParameters *ind, Aps_Frame *ack,
                                    Nwk_Nwk *nwk, uint8_t *scratch, uint32_t scratchMax, uint32_t nowMs)
{
    Nwk_DataRequestParameters req;
    const Security *security;
    uint32_t ackLen;
    uint32_t payloadOffset;
    ZbStatus status;

    status = ApsFrame_Compose(ack, 0, 0, scratch, scratchMax, &ackLen, &payloadOffset);

    if (status != ZB_OK)
        return APS_ACK_COMPOSE_REFUSED;

    if (nwk == 0)
        return APS_ACK_ISSUE_REFUSED;

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    req.dstAddr = ind->srcAddr;
    req.nsdu = scratch;
    req.nsduLength = ackLen;
    req.radius = 0;
    req.discoverRoute = NWK_DISCOVER_ENABLE;

    security = Nwk_Security(nwk);
    req.securityEnable = (security != 0 && Security_IsEnabled(security)) ? 1 : 0;

    if (Nwk_DataRequest(nwk, &req, nowMs) != ZB_OK)
        return APS_ACK_ISSUE_REFUSED;

    return APS_ACK_RESPONDED;
}

Aps_AckOutcome Aps_AckRespond(const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame, uint32_t deliveryStatus,
                              Nwk_Nwk *nwk, uint8_t *scratch, uint32_t scratchMax, uint32_t nowMs)
{
    Aps_Frame ack;

    if (!frame->ackRequest)
        return APS_ACK_NOT_REQUESTED;

    if (frame->deliveryMode != APS_DELIVERY_UNICAST)
        return APS_ACK_NOT_UNICAST;

    if (deliveryStatus != APS_STATUS_SUCCESS)
        return APS_ACK_NOT_ACCEPTED;

    Zb_memset(&ack, 0, (uint32_t)sizeof ack);

    ack.frameType = APS_FRAME_TYPE_ACK;
    ack.deliveryMode = APS_DELIVERY_UNICAST;
    ack.ackFormat = frame->frameType == APS_FRAME_TYPE_COMMAND ? 1 : 0;
    ack.ackRequest = 0;
    ack.securityEnabled = 0;
    ack.apsCounter = frame->apsCounter;

    if (!ack.ackFormat)
    {
        ack.dstEndpointPresent = 1;
        ack.dstEndpoint = frame->srcEndpoint;
        ack.srcEndpointPresent = 1;
        ack.srcEndpoint = frame->dstEndpoint;

        ack.clusterPresent = 1;
        ack.clusterId = frame->clusterId;
        ack.profilePresent = 1;
        ack.profileId = frame->profileId;
    }

    ack.extendedHeaderPresent = frame->extendedHeaderPresent;
    ack.extFrameControl = frame->extFrameControl;
    ack.fragmentation = frame->fragmentation;
    ack.blockNumberPresent = frame->blockNumberPresent;
    ack.blockNumber = frame->blockNumber;
    ack.ackBitfieldPresent = frame->ackBitfieldPresent;
    ack.ackBitfield = frame->ackBitfield;

    return apsDoAckIssue(ind, &ack, nwk, scratch, scratchMax, nowMs);
}

Aps_AckOutcome Aps_AckRespondFragment(const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame,
                                      uint8_t windowBlockNumber, uint8_t windowBitfield,
                                      Nwk_Nwk *nwk, uint8_t *scratch, uint32_t scratchMax, uint32_t nowMs)
{
    Aps_Frame ack;

    if (!frame->ackRequest)
        return APS_ACK_NOT_REQUESTED;

    if (frame->deliveryMode != APS_DELIVERY_UNICAST)
        return APS_ACK_NOT_UNICAST;

    if (frame->fragmentation != (uint32_t)APS_FRAG_FIRST && frame->fragmentation != (uint32_t)APS_FRAG_SUBSEQUENT)
        return APS_ACK_NOT_ACCEPTED;

    Zb_memset(&ack, 0, (uint32_t)sizeof ack);

    ack.frameType = APS_FRAME_TYPE_ACK;
    ack.deliveryMode = APS_DELIVERY_UNICAST;
    ack.ackFormat = 0;
    ack.ackRequest = 0;
    ack.securityEnabled = 0;

    ack.dstEndpointPresent = 1;
    ack.dstEndpoint = frame->srcEndpoint;
    ack.srcEndpointPresent = 1;
    ack.srcEndpoint = frame->dstEndpoint;

    ack.clusterPresent = 1;
    ack.clusterId = frame->clusterId;
    ack.profilePresent = 1;
    ack.profileId = frame->profileId;
    ack.apsCounter = frame->apsCounter;

    ack.extendedHeaderPresent = 1;
    ack.extFrameControl = frame->extFrameControl;
    ack.fragmentation = frame->fragmentation;
    ack.blockNumberPresent = 1;
    ack.blockNumber = windowBlockNumber;
    ack.ackBitfieldPresent = 1;
    ack.ackBitfield = windowBitfield;

    return apsDoAckIssue(ind, &ack, nwk, scratch, scratchMax, nowMs);
}
