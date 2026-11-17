#include "mac.h"

#include "mac_indirect.h"
#include "mac_rx.h"

#include "log.h"
#include "zb_utils.h"

/* M2024 6.2 6.6.2 7.2.11 7.3.1.4 7.5.2 8.2.4.3 10.21.5.1 10.21.5.2 10.22.4.1 ok; 10.21.4 unbuilt; 10.23.1 ok
   (promiscuous mode delivers what no duty consumed, measured); docs/internals/conformance.md pages. */

/* The ring's own admission: a poll asks for no more frames than there are free slots, so no slot is claimed and
   abandoned, and a ring shallower than a batch still polls. */
uint32_t MacRx_Room(const Mac_Rx *rx)
{
    return MAC_INDICATION_QUEUE_MAX - rx->indicationCount;
}

/* The 0x04 Data Request: its Content is zero-length, so the payload is one octet */
static int macPollCommand(const Mac_Frame *header, const uint8_t *payload, uint32_t payloadLen)
{
    if (header->frameType != MAC_FRAME_TYPE_COMMAND)
        return 0;

    if (payloadLen != MAC_CMD_FRAME_OCTETS || payload == 0)
        return 0;

    return payload[0] == MAC_CMD_POLL;
}

/* The broadcast destination: the one acceptance the association door treats differently, the filter having
   already judged whether this frame is this device's at all */
static int macDestinationIsBroadcast(const Mac_Frame *header)
{
    return header->destAddrMode == MAC_ADDR_SHORT && header->destShort == MAC_FRAME_ADDR_BROADCAST;
}

/* The filter's verdicts: one per refusal it can state, and the acceptance that names none. */
typedef enum MacRxFilterVerdict
{
    MAC_RX_FILTER_ACCEPT = 0,
    MAC_RX_FILTER_PAN = 1,           
    MAC_RX_FILTER_DESTINATION = 2,   
    MAC_RX_FILTER_BEACON_PAN = 3,    
    MAC_RX_FILTER_SOURCE_PAN = 4     
} MacRxFilterVerdict;

/* The source PAN a request may name: 0xffff, the destination's PAN, or that PAN compressed away, so a fourth
   value is refused and an absent field is nothing to compare. */
static int macRequestSourcePan(const Mac_Frame *header, const uint8_t *payload, uint32_t payloadLen)
{
    if (header->frameType != MAC_FRAME_TYPE_COMMAND || payload == 0 || payloadLen < MAC_CMD_FRAME_OCTETS)
        return 0;

    if (header->srcAddrMode == MAC_ADDR_NONE || header->panIdCompression)
        return 0;

    if (payload[0] != MAC_CMD_POLL && payload[0] != MAC_CMD_ASSOCIATION_REQUEST)
        return 0;

    return header->srcPan != header->destPan && header->srcPan != MAC_FRAME_PAN_BROADCAST;
}

/* A beacon's source PAN, macPanId equal to the broadcast PAN accepting it whatever that PAN is */
static MacRxFilterVerdict macFilterBeacon(const Radio_Pib *pib, const Mac_Frame *header)
{
    if (pib->panId == MAC_FRAME_PAN_BROADCAST || header->srcAddrMode == MAC_ADDR_NONE)
        return MAC_RX_FILTER_ACCEPT;

    return header->srcPan == pib->panId ? MAC_RX_FILTER_ACCEPT : MAC_RX_FILTER_BEACON_PAN;
}

/* A destination-less frame at the PAN coordinator, with the one command the request table lets name the
   broadcast source PAN */
static MacRxFilterVerdict macFilterDestinationless(const Radio_Pib *pib, int beaconPanCoordinator,
                                                   const Mac_Frame *header, const uint8_t *payload,
                                                   uint32_t payloadLen)
{
    int isRequest;

    if (!beaconPanCoordinator || header->srcAddrMode == MAC_ADDR_NONE)
        return MAC_RX_FILTER_DESTINATION;

    if (header->frameType != MAC_FRAME_TYPE_DATA && header->frameType != MAC_FRAME_TYPE_COMMAND)
        return MAC_RX_FILTER_DESTINATION;

    if (header->srcPan == pib->panId)
        return MAC_RX_FILTER_ACCEPT;

    isRequest = header->frameType == MAC_FRAME_TYPE_COMMAND && payload != 0
                && payloadLen >= MAC_CMD_FRAME_OCTETS && payload[0] == MAC_CMD_ASSOCIATION_REQUEST;

    return header->srcPan == MAC_FRAME_PAN_BROADCAST && isRequest ? MAC_RX_FILTER_ACCEPT
                                                                 : MAC_RX_FILTER_DESTINATION;
}

/* The destination address: the broadcast one, this device's own in either form, with macImplicitBroadcast
   FALSE and the group addresses needing a mode this stack does not carry */
static MacRxFilterVerdict macFilterDestinationAddress(const Radio_Pib *pib, int ownExtendedKnown,
                                                      uint64_t ownExtended, const Mac_Frame *header)
{
    int shortIsOurs;

    if (header->destAddrMode == MAC_ADDR_SHORT)
    {
        shortIsOurs = (pib->present & RADIO_PIB_SHORT_ADDRESS) != 0 && header->destShort == pib->shortAddress;

        if (header->destShort == MAC_FRAME_ADDR_BROADCAST || shortIsOurs)
            return MAC_RX_FILTER_ACCEPT;
    }

    if (header->destAddrMode == MAC_ADDR_EXTENDED && ownExtendedKnown
        && (pib->present & RADIO_PIB_EXTENDED_ADDRESS) != 0 && header->destExtended == ownExtended)
        return MAC_RX_FILTER_ACCEPT;

    return MAC_RX_FILTER_DESTINATION;
}

/* The first-level filter: the destination PAN, the destination address, a beacon's source PAN, then a request's
   source PAN. A refusal is dropped here and counted by the step that named it. */
static MacRxFilterVerdict macFirstLevelFilter(const Radio_Pib *pib, int ownExtendedKnown, uint64_t ownExtended,
                                              int beaconPanCoordinator, const Mac_Frame *header,
                                              const uint8_t *payload, uint32_t payloadLen)
{
    MacRxFilterVerdict verdict;

    if (header->frameType == MAC_FRAME_TYPE_BEACON)
        return macFilterBeacon(pib, header);

    if (header->destAddrMode == MAC_ADDR_NONE)
        return macFilterDestinationless(pib, beaconPanCoordinator, header, payload, payloadLen);

    if (MacFrame_DestPanPresent(header) && header->destPan != pib->panId
        && header->destPan != MAC_FRAME_PAN_BROADCAST)
        return MAC_RX_FILTER_PAN;

    verdict = macFilterDestinationAddress(pib, ownExtendedKnown, ownExtended, header);

    if (verdict != MAC_RX_FILTER_ACCEPT)
        return verdict;

    return macRequestSourcePan(header, payload, payloadLen) ? MAC_RX_FILTER_SOURCE_PAN : MAC_RX_FILTER_ACCEPT;
}

/* The source address is the transmitter's: an RCP hands its own transmission back, so a frame naming this
   device as its source is no arrival. 0xfffe and 0xffff are no identity, and an
   unassociated device here holds 0xffff, so matching it would discard other devices' frames. */
static int macSelfEcho(const Radio_Pib *pib, int ownExtendedKnown, uint64_t ownExtended, const Mac_Frame *header)
{
    if (header->srcAddrMode == MAC_ADDR_SHORT && (pib->present & RADIO_PIB_SHORT_ADDRESS) != 0
        && pib->shortAddress < MAC_SHORT_ADDRESS_LAST_USABLE)
        return header->srcShort == pib->shortAddress;

    if (header->srcAddrMode == MAC_ADDR_EXTENDED && ownExtendedKnown
        && header->srcExtended == ownExtended)
        return 1;

    return 0;
}

/* The poll event, which the standard has no notification of: a Data Request the filter accepted and whose
   source names a device */
static int macPollFromDevice(const Mac_Frame *header, const uint8_t *payload, uint32_t payloadLen)
{
    if (!macPollCommand(header, payload, payloadLen))
        return 0;

    if (header->srcAddrMode == MAC_ADDR_SHORT)
        return header->srcShort != MAC_FRAME_ADDR_BROADCAST;

    return header->srcAddrMode == MAC_ADDR_EXTENDED && header->srcExtended != 0;
}

/* The slot a ring's next write claims, whose room `MacRx_Room` established; `head` is its oldest
   entry and `count` how many it holds. */
static uint32_t macRingWriteAt(uint32_t head, uint32_t count, uint32_t max)
{
    return (head + count) % max;
}

/* The poll event, queued in arrival order; full is a refusal and a count and the newest is what is dropped,
   the older ones being polls the layer above has still to act on. */
static void macQueuePollArrival(Mac_PollEvents *polls, const Mac_PollArrival *arrival)
{
    Mac_PollArrival *slot;

    if (polls->count >= MAC_POLL_EVENT_MAX)
    {
        polls->dropped++;
        return;
    }

    slot = &polls->arrival[macRingWriteAt(polls->head, polls->count, MAC_POLL_EVENT_MAX)];
    *slot = *arrival;
    polls->count++;
}

/* One Data Request reported: the step's own list learns of it in arrival order and the event ring receives it
   under the full-pool policy `macQueuePollArrival` states, with whether the queue held something for it then. */
static void macRecordPoll(Mac_Rx *rx, Mac_PollEvents *polls, const Mac_Indirect *indirect, const Radio_Frame *frame,
                          const Mac_Frame *header)
{
    Mac_PollArrival arrival;

    Zb_memset(&arrival, 0, (uint32_t)sizeof arrival);

    arrival.addrMode = header->srcAddrMode;
    arrival.shortAddress = header->srcShort;
    arrival.extendedAddress = header->srcExtended;
    arrival.dsn = header->seq;
    arrival.stampTicks = frame->deviceStampTicks;
    arrival.framePending = MacIndirect_QueuedFor(indirect, &arrival) != 0;

    rx->stepPolls[rx->stepPollCount] = arrival;
    rx->stepPollCount++;

    macQueuePollArrival(polls, &arrival);
}

/* The discard of a frame whose footer does not compute: one counter for the one reason that refused it, the
   radio's flag and the recomputation being two names for that reason, and one record naming the footer with the
   claims in its argument (an absent pool reports nowhere, by the caller's choice). */
static void macReportFooterDiscard(Mac_Rx *rx, const Mac_Mac *mac, uint16_t line, uint32_t claims)
{
    rx->fcsFailures++;

    if (mac->log == 0)
        return;

    Log_Report(mac->log, LOG_COMP_MAC_RX, line, LOG_REASON_FCS, claims);
}

/* One filter verdict, its refusal counted under the step that named it. */
static int macFilterAccepted(Mac_Rx *rx, MacRxFilterVerdict verdict)
{
    switch (verdict)
    {
    case MAC_RX_FILTER_ACCEPT:
        return 1;

    case MAC_RX_FILTER_PAN:
        rx->panMismatches++;
        return 0;

    case MAC_RX_FILTER_BEACON_PAN:
        rx->beaconPanMismatches++;
        return 0;

    case MAC_RX_FILTER_SOURCE_PAN:
        rx->sourcePanMismatches++;
        return 0;

    case MAC_RX_FILTER_DESTINATION:
    default:
        rx->destinationMismatches++;
        return 0;
    }
}

/* Each refusal counted under the step that named it, and written to the log */
static void macReportRefusal(Mac_Rx *rx, const Mac_Mac *mac, uint16_t line, Mac_FrameRefusal refusal)
{
    uint32_t reason;

    switch (refusal)
    {
    case MAC_FRAME_REFUSAL_RESERVED_TYPE:
        rx->reservedTypeFrames++;
        reason = MAC_RX_REFUSED_RESERVED_TYPE;
        break;

    case MAC_FRAME_REFUSAL_RESERVED_VERSION:
        rx->reservedVersionFrames++;
        reason = MAC_RX_REFUSED_RESERVED_VERSION;
        break;

    case MAC_FRAME_REFUSAL_UNBUILT:
        rx->unbuiltForms++;
        reason = MAC_RX_REFUSED_UNBUILT;
        break;

    case MAC_FRAME_REFUSAL_MALFORMED:
    default:
        rx->malformedFrames++;
        reason = MAC_RX_REFUSED_MALFORMED;
        break;
    }

    if (mac->log == 0)
        return;

    Log_Report(mac->log, LOG_COMP_MAC_RX, line, LOG_REASON_REFUSED, reason);
}

/* The ring's next slot, whose room the step established through `MacRx_Room` (docs/internals/coding-rules.md §4.3):
   the radio's octets and their length, the rssi, lqi and stamp, and the count that publishes the claim. */
static Mac_DataIndicationParameters *macClaimIndication(Mac_Rx *rx, const Radio_Frame *frame)
{
    Mac_DataIndicationParameters *slot;

    slot = &rx->indications[macRingWriteAt(rx->indicationHead, rx->indicationCount, MAC_INDICATION_QUEUE_MAX)];
    Zb_memset(slot, 0, (uint32_t)sizeof *slot);

    slot->len = frame->len;
    Zb_memcpy(slot->bytes, frame->bytes, frame->len);
    slot->rssiDbm = frame->rssiDbm;
    slot->lqi = frame->lqi;
    slot->stampTicks = frame->deviceStampTicks;
    slot->ackedWithFramePending = frame->ackedWithFramePending;
    rx->indicationCount++;

    return slot;
}

/* The header the parser read, filling the Msdu boundary: `payloadOffset` and `payloadLen` in the carrier. */
static void macSetIndicationHeader(Mac_DataIndicationParameters *slot, const Radio_Frame *frame,
                                   const Mac_Frame *header, const uint8_t *payload, uint32_t payloadLen)
{
    slot->headerValid = 1;
    slot->header = *header;
    slot->frameType = (uint32_t)header->frameType;
    slot->payloadOffset = (uint32_t)(payload - frame->bytes);
    slot->payloadLen = payloadLen;
}

/* The association request, with the fast form declined rather than answered by the slow path: queued when this
   device is its parent, and a request it cannot take is a command heard and counted */
static int macTakeAssociationRequest(Mac_Assoc *assoc, const Mac_Frame *header, const uint8_t *payload,
                                     uint32_t payloadLen, int beaconPanCoordinator, uint64_t stampTicks)
{
    MacFrame_Capability capability;

    if (header->srcAddrMode != MAC_ADDR_EXTENDED || header->srcExtended == 0)
    {
        MacAssoc_CountRefusedRequest(assoc, MAC_ASSOC_REQUEST_SOURCE);
        return 0;
    }

    if (payloadLen != MAC_ASSOC_REQUEST_PAYLOAD_OCTETS)
    {
        MacAssoc_CountRefusedRequest(assoc, MAC_ASSOC_REQUEST_CONTENT);
        return 0;
    }

    if (!MacAssoc_RequestForThisDevice(header, beaconPanCoordinator, !macDestinationIsBroadcast(header)))
    {
        MacAssoc_CountRefusedRequest(assoc, MAC_ASSOC_REQUEST_NOT_OURS);
        return 0;
    }

    if (MacFrame_ParseAssociationRequest(payload + MAC_CMD_FRAME_OCTETS, payloadLen - MAC_CMD_FRAME_OCTETS,
                                         &capability) != ZB_OK)
    {
        MacAssoc_CountRefusedRequest(assoc, MAC_ASSOC_REQUEST_UNPARSABLE);
        return 0;
    }

    if (capability.associationType)
    {
        MacAssoc_CountRefusedRequest(assoc, MAC_ASSOC_REQUEST_FAST);
        return 0;
    }

    MacAssoc_QueueRequest(assoc, header, &capability, stampTicks);

    return 1;
}

/* The doors a delivered frame reaches, in the order it reaches them: the self echo, the acknowledgment, a beacon
   request, the beacon's own event, an association's request and answer, and a poll. 1 when an indication was
   claimed, 0 when a duty took the frame or a clause refused it. */
static int macClassifyOrdinary(Mac_Rx *rx, const Radio_Frame *frame, const Radio_Pib *pib,
                               int ownExtendedKnown, uint64_t ownExtended, int beaconAnswers,
                               int beaconPanCoordinator, Mac_Beacon *beacon, Mac_PollEvents *polls,
                               Mac_Assoc *assoc, Mac_Tx *tx, Mac_Mac *mac, const Mac_Frame *header,
                               const uint8_t *payload, uint32_t payloadLen)
{
    Mac_DataIndicationParameters *slot;
    int isPoll;

    if (macSelfEcho(pib, ownExtendedKnown, ownExtended, header))
    {
        rx->selfEchoes++;
        return 0;
    }

    if (header->frameType == MAC_FRAME_TYPE_ACK)
    {
        rx->acksHeard++;
        return 0;
    }

    if (!macFilterAccepted(rx, macFirstLevelFilter(pib, ownExtendedKnown, ownExtended, beaconPanCoordinator,
                                                  header, payload, payloadLen)))
        return 0;

    if (MacScan_OrphanRunning(&mac->scan))
    {
        MacScan_TakeOrphanFrame(&mac->scan, header, payload, payloadLen);
        return 0;
    }

    isPoll = macPollCommand(header, payload, payloadLen);

    if (MacBeacon_TakeRequest(beacon, pib, header, payload, payloadLen))
        return 0;

    if (MacScan_TakeOrphanNotification(&mac->scan, header, payload, payloadLen, beaconAnswers))
        return 0;

    if (header->frameType == MAC_FRAME_TYPE_BEACON)
    {
        MacBeacon_Notify(beacon, header, payload, payloadLen, frame, pib, ownExtendedKnown, ownExtended);
        return 0;
    }

    if (MacAssoc_RequestCommand(header, payload, payloadLen))
    {
        if (!beaconAnswers
            || !macTakeAssociationRequest(assoc, header, payload, payloadLen, beaconPanCoordinator,
                                          frame->deviceStampTicks))
            rx->commandsHeard++;

        return 0;
    }

    if (MacAssoc_ResponseCommand(header, payload, payloadLen))
    {
        if (!MacAssoc_TakeResponse(assoc, mac, tx, header, payload, !macDestinationIsBroadcast(header)))
            rx->commandsHeard++;

        return 0;
    }

    if (header->frameType == MAC_FRAME_TYPE_COMMAND && !isPoll)
    {
        rx->commandsHeard++;
        return 0;
    }

    slot = macClaimIndication(rx, frame);
    macSetIndicationHeader(slot, frame, header, payload, payloadLen);
    slot->status = frame->error;

    if (macPollFromDevice(header, payload, payloadLen))
        macRecordPoll(rx, polls, &mac->indirect, frame, header);

    return 1;
}

/* One delivered PSDU: the footer, then a) and b), then the filter every frame passes, then the duties 6.6.2 gives
   this device, 10.23.1 adding an indication where a duty consumed none. A duplicate or a PHY error is delivered
   with its report once the filter has accepted it. */
void MacRx_QueueFrame(Mac_Rx *rx, const Radio_Frame *frame, const Radio_Pib *pib, const Radio_Caps *caps,
                      int ownExtendedKnown, uint64_t ownExtended, int beaconAnswers, int beaconPanCoordinator,
                      int promiscuous, Mac_Beacon *beacon, Mac_PollEvents *polls, Mac_Assoc *assoc,
                      Mac_Tx *tx, Mac_Mac *mac)
{
    Mac_DataIndicationParameters *slot;
    Mac_Frame header;
    const uint8_t *payload = 0;
    uint32_t payloadLen = 0;
    int delivered;
    uint32_t claims;
    ZbStatus status;
    Mac_FrameRefusal refusal;

    claims = 0;

    if (frame->error == ZB_ERR_BAD_FRAME)
        claims = MAC_RX_FCS_RADIO;

    if (caps->psduIncludesFcs && MacFrame_CheckFcs(frame->bytes, frame->len) != ZB_OK)
        claims |= MAC_RX_FCS_CHECKSUM;

    if (claims != 0)
    {
        macReportFooterDiscard(rx, mac, (uint16_t)__LINE__, claims);
        return;
    }

    refusal = MAC_FRAME_REFUSAL_NONE;
    status = MacFrame_Parse(frame->bytes, frame->len, caps->psduIncludesFcs, &header, &payload, &payloadLen,
                            &refusal);

    if (status != ZB_OK)
    {
        macReportRefusal(rx, mac, (uint16_t)__LINE__, refusal);
        return;
    }

    if (frame->error != ZB_OK)
    {
        if (!macFilterAccepted(rx, macFirstLevelFilter(pib, ownExtendedKnown, ownExtended, beaconPanCoordinator,
                                                      &header, payload, payloadLen)))
            return;

        slot = macClaimIndication(rx, frame);
        macSetIndicationHeader(slot, frame, &header, payload, payloadLen);

        slot->status = frame->error;
        return;
    }

    delivered = macClassifyOrdinary(rx, frame, pib, ownExtendedKnown, ownExtended, beaconAnswers,
                                    beaconPanCoordinator, beacon, polls, assoc, tx, mac, &header, payload,
                                    payloadLen);

    if (promiscuous && !delivered)
    {
        slot = macClaimIndication(rx, frame);
        slot->status = frame->error;
        macSetIndicationHeader(slot, frame, &header, payload, payloadLen);
        rx->promiscuousDelivered++;
    }
}

/* The indications the receive path queued, oldest first, taken the way the confirmations are. */
uint32_t MacRx_PollIndications(Mac_Rx *rx, Mac_DataIndicationParameters *out, uint32_t max)
{
    uint32_t taken = 0;

    if (rx == 0 || out == 0 || max == 0)
        return 0;

    while (taken < max && rx->indicationCount > 0)
    {
        out[taken] = rx->indications[rx->indicationHead];
        rx->indicationHead = (rx->indicationHead + 1) % MAC_INDICATION_QUEUE_MAX;
        rx->indicationCount--;
        taken++;
    }

    return taken;
}

/* The polls R23.1 D.10.2 says a coordinator must be able to report, oldest first, taken the same way the
   confirmations and the indications are taken. The queue is bounded, so a layer above that never reads it is
   what `Mac_CountersOf`'s pollArrivalQueue and pollsUnanswered make visible. */
uint32_t MacRx_PollArrivals(Mac_PollEvents *polls, Mac_PollArrival *out, uint32_t max)
{
    uint32_t taken = 0;

    if (polls == 0 || out == 0 || max == 0)
        return 0;

    while (taken < max && polls->count > 0)
    {
        out[taken] = polls->arrival[polls->head];
        polls->head = (polls->head + 1) % MAC_POLL_EVENT_MAX;
        polls->count--;
        taken++;
    }

    return taken;
}
