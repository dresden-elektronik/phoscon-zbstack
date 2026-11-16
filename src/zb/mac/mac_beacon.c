#include "mac.h"

#include "mac_beacon.h"

#include "zb_time.h"
#include "zb_utils.h"

/* M2024: 7.3.1, 7.3.1.2, 7.3.1.6, 7.3.1.7, 7.5.2, 8.2.4.3, 10.19, 10.22.3, 10.22.4.1 ok; 7.3.1.4 constructed
   (D.7's 0x0F, no superframe); 7.3.1.5 unbuilt; docs/internals/conformance.md pages. */

/* The on-demand beacon: 7.5.2's request answered as 7.3.1 lays a beacon out, 0xCFFF's superframe fields
   (Annex D.7's 0x0F/0x0F and the Annex's own Final CAP Slot) and the pending devices 7.3.1.6 states. An
   answer the seam has no room for is asked again a while, any other refusal is counted; neither is fatal. */
/* Whether the Address List already names this device: the list states one device once. */
static int macBeaconListsShort(const MacFrame_Beacon *macBeacon, uint16_t shortAddress)
{
    uint32_t i;

    for (i = 0; i < macBeacon->pendingShortCount; i++)
    {
        if (macBeacon->pendingShort[i] == shortAddress)
            return 1;
    }

    return 0;
}

static int macBeaconListsExtended(const MacFrame_Beacon *macBeacon, uint64_t extendedAddress)
{
    uint32_t i;

    for (i = 0; i < macBeacon->pendingExtendedCount; i++)
    {
        if (macBeacon->pendingExtended[i] == extendedAddress)
            return 1;
    }

    return 0;
}

/* The Address List: seven addresses at most, shorts first, first-come-first-served, never the broadcast short
   address, and one device with several transactions is still one address. The queue's DSNs are its arrival order,
   which is also the order the extraction reads. */
static void macBeaconPendingAddresses(MacFrame_Beacon *macBeacon, const Mac_Transaction *transactions,
                                      Mac_Beacon *beacon)
{
    uint32_t order[MAC_TRANSACTION_MAX];
    uint32_t count = 0;
    uint32_t i;
    uint32_t j;

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (transactions[i].used)
        {
            order[count] = i;
            count++;
        }
    }

    for (i = 1; i < count; i++)
    {
        uint32_t key = order[i];

        for (j = i; j > 0 && transactions[order[j - 1]].dsn > transactions[key].dsn; j--)
            order[j] = order[j - 1];

        order[j] = key;
    }

    for (i = 0; i < count; i++)
    {
        const Mac_Transaction *transaction = &transactions[order[i]];

        if (macBeacon->pendingShortCount + macBeacon->pendingExtendedCount >= MAC_FRAME_PENDING_MAX)
        {
            beacon->beaconPendingDropped++;
            continue;
        }

        if (transaction->destAddrMode == MAC_ADDR_SHORT && transaction->destShort != MAC_FRAME_ADDR_BROADCAST
            && !macBeaconListsShort(macBeacon, transaction->destShort))
        {
            macBeacon->pendingShort[macBeacon->pendingShortCount] = transaction->destShort;
            macBeacon->pendingShortCount++;
            continue;
        }

        if (transaction->destAddrMode == MAC_ADDR_EXTENDED
            && !macBeaconListsExtended(macBeacon, transaction->destExtended))
        {
            macBeacon->pendingExtended[macBeacon->pendingExtendedCount] = transaction->destExtended;
            macBeacon->pendingExtendedCount++;
        }
    }
}

/* 8.2.4.3 and Table 8-3: a received beacon's own event, its body read into the PanDescriptor's fields. Full is a
   refusal of the newest and a count, the older notifications being beacons a reader has still to see. */
/* 10.22.3's poll is owed for the Address List's sake and not the payload's, so it is decided before an
   indication can be refused for a payload this stack's pool cannot carry. A beacon naming nobody owes none. */
void MacBeacon_Notify(Mac_Beacon *beacon, const Mac_Frame *header, const uint8_t *payload, uint32_t payloadLen,
                      const Radio_Frame *frame, const Radio_Pib *pib, int ownExtendedKnown, uint64_t ownExtended)
{
    Mac_BeaconNotification notification;
    MacFrame_Beacon body;
    const uint8_t *payloadOut;
    uint32_t payloadOutLen;

    if (header->frameVersion == 2)
    {
        beacon->enhancedBeaconsUnbuilt++;
        return;
    }

    if (MacFrame_ParseBeaconPayload(payload, payloadLen, &body, &payloadOut, &payloadOutLen) != ZB_OK)
    {
        beacon->beaconsUnreadable++;
        return;
    }

    Zb_memset(&notification, 0, (uint32_t)sizeof notification);

    if (header->srcAddrMode != MAC_ADDR_SHORT && header->srcAddrMode != MAC_ADDR_EXTENDED)
    {
        beacon->beaconsUnreadable++;
        return;
    }

    beacon->beaconsHeard++;
    notification.channel = pib->channel;
    notification.sn = header->seq;
    notification.coordAddrMode = header->srcAddrMode;
    notification.coordPanId = header->srcPan;
    notification.coordShort = header->srcShort;
    notification.coordExtended = header->srcExtended;
    notification.rssiDbm = frame->rssiDbm;
    notification.lqi = frame->lqi;
    notification.stampTicks = frame->deviceStampTicks;
    notification.beaconOrder = body.beaconOrder;
    notification.superframeOrder = body.superframeOrder;
    notification.finalCapSlot = body.finalCapSlot;
    notification.batteryLifeExtension = body.batteryLifeExtension;
    notification.panCoordinator = body.panCoordinator;
    notification.associationPermit = body.associationPermit;
    notification.gtsPermit = body.gtsPermit;
    notification.pendingShortCount = body.pendingShortCount;
    notification.pendingExtendedCount = body.pendingExtendedCount;
    Zb_memcpy(notification.pendingShort, body.pendingShort,
             body.pendingShortCount * (uint32_t)sizeof body.pendingShort[0]);
    Zb_memcpy(notification.pendingExtended, body.pendingExtended,
             body.pendingExtendedCount * (uint32_t)sizeof body.pendingExtended[0]);

    if (!beacon->scanning)
        MacBeacon_OwePoll(beacon, &notification, pib, ownExtendedKnown, ownExtended);

    if (payloadOutLen > MAC_BEACON_PAYLOAD_MAX)
    {
        beacon->beaconsPayloadOverflow++;
        return;
    }

    notification.payloadLen = payloadOutLen;

    if (payloadOutLen != 0)
        Zb_memcpy(notification.payload, payloadOut, payloadOutLen);

    if (notification.payloadLen == 0)
    {
        beacon->beaconsNoPayload++;
        return;
    }

    if (beacon->notificationCount >= MAC_BEACON_NOTIFY_MAX)
    {
        beacon->beaconsNotifyDropped++;
        return;
    }

    beacon->notifications[(beacon->notificationHead + beacon->notificationCount) % MAC_BEACON_NOTIFY_MAX]
        = notification;
    beacon->notificationCount++;
    beacon->beaconsNotified++;
}

/* 10.22.3's reaction to a beacon that names this device, with 10.22.4.1's destination for the request it sends: the
   beacon's own source is the coordinator, and where the beacon says it came from the PAN coordinator the
   destination fields may be omitted, which R23.1 Annex D.4's request table also prefers. */
void MacBeacon_OwePoll(Mac_Beacon *beacon, const Mac_BeaconNotification *notification, const Radio_Pib *pib,
                       int ownExtendedKnown, uint64_t ownExtended)
{
    uint32_t i;
    Mac_AddrMode matched = MAC_ADDR_NONE;

    for (i = 0; i < notification->pendingShortCount; i++)
    {
        if (notification->pendingShort[i] == pib->shortAddress && (pib->present & RADIO_PIB_SHORT_ADDRESS) != 0)
            matched = MAC_ADDR_SHORT;
    }

    for (i = 0; i < notification->pendingExtendedCount; i++)
    {
        if (ownExtendedKnown && notification->pendingExtended[i] == ownExtended)
            matched = MAC_ADDR_EXTENDED;
    }

    if (matched == MAC_ADDR_NONE)
        return;

    beacon->pollOwed = 1;
    beacon->pollSrcMode = matched;

    beacon->pollCoordIsPanCoordinator = notification->panCoordinator;
    beacon->pollCoordMode = notification->coordAddrMode;
    beacon->pollCoordShort = notification->coordShort;
    beacon->pollCoordExtended = notification->coordExtended;
    beacon->pollCoordPan = notification->coordPanId;
}

uint32_t MacBeacon_NotificationRoom(const Mac_Beacon *beacon)
{
    return MAC_BEACON_NOTIFY_MAX - beacon->notificationCount;
}

uint32_t MacBeacon_PollNotifications(Mac_Beacon *beacon, Mac_BeaconNotification *out, uint32_t max)
{
    uint32_t taken = 0;

    if (beacon == 0 || out == 0)
        return 0;

    while (taken < max && beacon->notificationCount > 0)
    {
        out[taken] = beacon->notifications[beacon->notificationHead];
        beacon->notificationHead = (beacon->notificationHead + 1) % MAC_BEACON_NOTIFY_MAX;
        beacon->notificationCount--;
        taken++;
    }

    return taken;
}

/* 8.3.5's confirmation is one a caller queued, and a beacon is this module's own: its slot owes none. */
ZbStatus MacBeacon_Reply(Mac_Beacon *beacon, const Mac_Transaction *transactions, Mac_Tx *tx, const Radio_Pib *pib,
                         int ownExtendedKnown, uint64_t ownExtended, Radio_Radio *radio, uint32_t *bsn,
                         uint8_t *mpdu, uint32_t mpduCap, uint32_t nowMs)
{
    Mac_Frame frame;
    MacFrame_Beacon macBeacon;
    Mac_Track *slot;
    Radio_Handle handle = RADIO_HANDLE_NONE;
    uint32_t bodyLen = 0;
    uint32_t len = 0;
    ZbStatus status;

    slot = MacTx_FreeSlot(tx);

    if (slot == 0)
        return ZB_ERR_NO_SPACE;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    Zb_memset(&macBeacon, 0, (uint32_t)sizeof macBeacon);

    frame.frameType = MAC_FRAME_TYPE_BEACON;
    frame.frameVersion = 0;
    frame.destAddrMode = MAC_ADDR_NONE;
    frame.seq = (uint8_t)(*bsn % MAC_DSN_WRAP);
    frame.srcPan = pib->panId;
    frame.framePending = 0;   
    frame.ackRequest = 0;
    frame.panIdCompression = 0;

    if ((pib->present & RADIO_PIB_SHORT_ADDRESS) != 0 && pib->shortAddress < MAC_SHORT_ADDRESS_LAST_USABLE)
    {
        frame.srcAddrMode = MAC_ADDR_SHORT;
        frame.srcShort = pib->shortAddress;
    }
    else if (ownExtendedKnown && (pib->present & RADIO_PIB_EXTENDED_ADDRESS) != 0)
    {
        frame.srcAddrMode = MAC_ADDR_EXTENDED;
        frame.srcExtended = ownExtended;
    }
    else
    {
        beacon->beaconIgnored++;
        return ZB_OK;
    }

    macBeacon.beaconOrder = MAC_FRAME_BEACON_ORDER_NONE;
    macBeacon.superframeOrder = MAC_FRAME_BEACON_ORDER_NONE;
    macBeacon.finalCapSlot = MAC_FRAME_BEACON_ORDER_NONE;
    macBeacon.batteryLifeExtension = 0;
    macBeacon.panCoordinator = beacon->beaconPanCoordinator;
    macBeacon.associationPermit = beacon->beaconAssociationPermit;

    macBeaconPendingAddresses(&macBeacon, transactions, beacon);

    status = MacFrame_ComposeBeaconPayload(&macBeacon, beacon->beaconPayload, beacon->beaconPayloadLen,
                                           beacon->beaconBody, (uint32_t)sizeof beacon->beaconBody, &bodyLen);

    if (status != ZB_OK)
    {
        beacon->beaconRefused++;
        return ZB_OK;
    }

    status = MacFrame_Compose(&frame, beacon->beaconBody, bodyLen, mpdu, mpduCap, &len);

    if (status != ZB_OK)
    {
        beacon->beaconRefused++;
        return ZB_OK;
    }

    status = MacFrame_AppendFcs(mpdu, len, mpduCap, &len);

    if (status != ZB_OK)
    {
        beacon->beaconRefused++;
        return ZB_OK;
    }

    status = radio->ops->tx(radio, mpdu, len, 0, 0, &handle);

    if (status == ZB_ERR_BUSY || status == ZB_ERR_NO_SPACE)
        return status;

    if (status != ZB_OK)
    {
        beacon->beaconRefused++;
        return ZB_OK;
    }

    slot->handle = handle;
    slot->confirmOwed = 0;
    slot->dsn = *bsn % MAC_DSN_WRAP;
    slot->issuedMs = nowMs;
    slot->frameType = MAC_FRAME_TYPE_BEACON;
    slot->ackRequest = 0;
    slot->state = MAC_TX_OUTSTANDING;
    slot->status = ZB_ERR_NOT_READY;
    slot->acked = 0;
    slot->numBackoffs = 0;
    slot->framePending = 0;
    slot->framePendingReported = 0;

    *bsn = *bsn + 1;
    beacon->beaconReplies++;

    return ZB_OK;
}

void MacBeacon_ReplyOwed(Mac_Beacon *beacon, const Mac_Transaction *transactions, Mac_Tx *tx, const Radio_Pib *pib,
                         int ownExtendedKnown, uint64_t ownExtended, Radio_Radio *radio, uint32_t *bsn,
                         uint8_t *mpdu, uint32_t mpduCap, uint32_t nowMs)
{
    ZbStatus status;

    while (beacon->stepBeacons > 0)
    {
        status = MacBeacon_Reply(beacon, transactions, tx, pib, ownExtendedKnown, ownExtended, radio, bsn, mpdu,
                                 mpduCap, nowMs);

        if (status == ZB_ERR_BUSY || status == ZB_ERR_NO_SPACE)
        {
            if (!beacon->replyHeld)
            {
                beacon->replyHeld = 1;
                beacon->replyHeldMs = nowMs;
            }

            if (Zb_timeWithin(nowMs, beacon->replyHeldMs, MAC_BEACON_HOLD_MS))
                return;

            beacon->beaconRefused++;
        }

        beacon->replyHeld = 0;
        beacon->stepBeacons--;
    }
}

/* The 0x07 Beacon Request and the shape it is pinned to: short destination, no source address, the broadcast PAN
   and short address, acknowledgment request clear. Frame Pending is pinned too but ignored on reception, and
   Security Enabled is refused for every frame this module reads. */
static int macBeaconRequestCommand(const Mac_Frame *header, const uint8_t *payload, uint32_t payloadLen)
{
    if (header->frameType != MAC_FRAME_TYPE_COMMAND)
        return 0;

    if (payloadLen != MAC_CMD_FRAME_OCTETS || payload == 0)
        return 0;

    return payload[0] == MAC_CMD_BEACON_REQUEST;
}

/* 7.5.2's own request is version 0; 7.5.3's Enhanced form is version 2, and no enhanced beacon is built here.
   8.2.4.3's PanDescriptor names a coordinator address in one of its two forms, and a beacon with neither names
   none this event can carry. */
static int macBeaconRequestShape(const Mac_Frame *header)
{
    if (header->frameVersion != 0)
        return 0;

    if (header->destAddrMode != MAC_ADDR_SHORT || header->srcAddrMode != MAC_ADDR_NONE)
        return 0;

    if (header->destPan != MAC_FRAME_PAN_BROADCAST || header->destShort != MAC_FRAME_ADDR_BROADCAST)
        return 0;

    return header->ackRequest == 0;
}

/* Whether this device is one R23.1 D.11.1.5 obliges to answer ("All coordinators/routers SHALL respond to
   Beacon Requests with a Beacon"), which on this PAN means it has a short address of its own to write into the
   beacon's Source Address field and has been given something to say in it. */
static int macBeaconReady(const Mac_Beacon *beacon, const Radio_Pib *pib)
{
    if (!beacon->beaconAnswers)
        return 0;

    if ((pib->present & RADIO_PIB_SHORT_ADDRESS) != 0 && pib->shortAddress < MAC_SHORT_ADDRESS_LAST_USABLE)
        return 1;

    return (pib->present & RADIO_PIB_EXTENDED_ADDRESS) != 0;
}

/* One delivered frame the receive path asks this device about: 1 when it was a Beacon Request, counted here and
   added to the step's replies where R23.1 D.11.1.5 obliges one, and 0 when it was any other frame. 10.19 answers
   each request with "a single Beacon frame", so the step counts them rather than remembering that there was one. */
int MacBeacon_TakeRequest(Mac_Beacon *beacon, const Radio_Pib *pib, const Mac_Frame *header, const uint8_t *payload,
                          uint32_t payloadLen)
{
    if (!macBeaconRequestCommand(header, payload, payloadLen))
        return 0;

    beacon->beaconRequestsHeard++;

    if (!macBeaconRequestShape(header) || !macBeaconReady(beacon, pib))
        beacon->beaconIgnored++;
    else
        beacon->stepBeacons++;

    return 1;
}

/* The caller's record, adopted against the pool's ceiling: a beacon payload too long is refused rather than
   truncated, and nothing is changed by the refusal (docs/internals/coding-rules.md §4.3). */
ZbStatus MacBeacon_SetConfig(Mac_Beacon *beacon, const Mac_BeaconConfig *config)
{
    if (beacon == 0 || config == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (config->payload == 0 && config->payloadLen != 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (config->payloadLen > MAC_BEACON_PAYLOAD_MAX)
        return ZB_ERR_NO_SPACE;   

    Zb_memset(beacon->beaconPayload, 0, (uint32_t)sizeof beacon->beaconPayload);

    if (config->payloadLen != 0)
        Zb_memcpy(beacon->beaconPayload, config->payload, config->payloadLen);

    beacon->beaconPayloadLen = config->payloadLen;
    beacon->beaconPanCoordinator = config->panCoordinator;
    beacon->beaconAssociationPermit = config->associationPermit;
    beacon->beaconAnswers = config->answer;

    return ZB_OK;
}
