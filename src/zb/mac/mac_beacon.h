#ifndef MAC_BEACON_H
#define MAC_BEACON_H

/*
 * 7.5.2's Beacon Request and 7.3.1's beacon in answer; docs/internals/conformance.md §1 owns the pending lists it states.
 */

#include <stdint.h>

#include "mac_tx.h"
#include "radio.h"
#include "zb_status.h"

/* The beacon subject's own state: whether this device answers at all and what 7.3.1.4's two bits say, the
   payload R23.1 3.6.8.2 hands down as opaque octets, the MAC payload composed around it, and the five numbers
   the answers are read by. */
typedef struct Mac_Beacon
{
    int beaconAnswers;
    int beaconPanCoordinator;
    int beaconAssociationPermit;
    uint8_t beaconPayload[MAC_BEACON_PAYLOAD_MAX];
    uint32_t beaconPayloadLen;
    uint8_t beaconBody[MAC_BEACON_BODY_MAX];
    uint32_t stepBeacons;
    int scanning;
    uint32_t beaconsHeard;
    int replyHeld;
    uint32_t replyHeldMs;
    uint32_t beaconRequestsHeard;
    uint32_t beaconReplies;
    uint32_t beaconIgnored;
    uint32_t beaconRefused;
    uint32_t beaconPendingDropped;
    uint32_t beaconsNotified;
    uint32_t beaconsNoPayload;
    uint32_t beaconsNotifyDropped;
    uint32_t beaconsUnreadable;
    uint32_t enhancedBeaconsUnbuilt;
    uint32_t beaconsPayloadOverflow;

    Mac_BeaconNotification notifications[MAC_BEACON_NOTIFY_MAX];

    int pollOwed;
    int pollCoordIsPanCoordinator;
    Mac_AddrMode pollSrcMode;
    Mac_AddrMode pollCoordMode;
    uint16_t pollCoordShort;
    uint64_t pollCoordExtended;
    uint16_t pollCoordPan;
    uint8_t pollBytes[1];
    uint32_t pollRefused;
    uint32_t pollIssued;
    ZbStatus pollStatus;
    uint32_t notificationHead;
    uint32_t notificationCount;
} Mac_Beacon;

/* The beacon's whole composition: 7.3.1's fields, the pending devices `transactions` holds (7.3.1.6) and the
   footer, issued from the caller's track pool and MPDU scratch. */
/* One received beacon, its body read into 8.2.4.3's parameters and queued; full is a refusal and a count. */
void MacBeacon_Notify(Mac_Beacon *beacon, const Mac_Frame *header, const uint8_t *payload, uint32_t payloadLen,
                      const Radio_Frame *frame, const Radio_Pib *pib, int ownExtendedKnown, uint64_t ownExtended);
uint32_t MacBeacon_PollNotifications(Mac_Beacon *beacon, Mac_BeaconNotification *out, uint32_t max);
uint32_t MacBeacon_NotificationRoom(const Mac_Beacon *beacon);

/* 10.22.3: "If the address of the device is contained in the Address List field of the Beacon frame and
   macAutoRequest is TRUE, the MLME of the device shall send a Data Request command". Sets the poll the step owes. */
void MacBeacon_OwePoll(Mac_Beacon *beacon, const Mac_BeaconNotification *notification, const Radio_Pib *pib,
                       int ownExtendedKnown, uint64_t ownExtended);

ZbStatus MacBeacon_Reply(Mac_Beacon *beacon, const Mac_Transaction *transactions, Mac_Tx *tx, const Radio_Pib *pib,
                         int ownExtendedKnown, uint64_t ownExtended, Radio_Radio *radio, uint32_t *bsn,
                         uint8_t *mpdu, uint32_t mpduCap, uint32_t nowMs);

/* The replies the step owes, in turn: one the door has no room for stops the turn and is asked again on the next
   step, for MAC_BEACON_HOLD_MS from its first refusal, then counted refused and the rest go on. */
void MacBeacon_ReplyOwed(Mac_Beacon *beacon, const Mac_Transaction *transactions, Mac_Tx *tx, const Radio_Pib *pib,
                         int ownExtendedKnown, uint64_t ownExtended, Radio_Radio *radio, uint32_t *bsn,
                         uint8_t *mpdu, uint32_t mpduCap, uint32_t nowMs);

/* One delivered frame the receive path asks this device about: 1 when it is 7.5.2's Beacon Request, counted here,
   and marked for the step's reply where R23.1 D.11.1.5 obliges one. */
int MacBeacon_TakeRequest(Mac_Beacon *beacon, const Radio_Pib *pib, const Mac_Frame *header, const uint8_t *payload,
                          uint32_t payloadLen);

/* What a beacon is answered with: `payload` is macBeaconPayload's octets, copied and never read (R23.1 3.6.8.2),
   and the two bits are 7.3.1.4's. A payload past MAC_BEACON_PAYLOAD_MAX is ZB_ERR_NO_SPACE, changing nothing. */
typedef struct Mac_BeaconConfig
{
    int answer;
    int panCoordinator;
    int associationPermit;
    const uint8_t *payload;
    uint32_t payloadLen;
} Mac_BeaconConfig;

ZbStatus MacBeacon_SetConfig(Mac_Beacon *beacon, const Mac_BeaconConfig *config);

#endif /* MAC_BEACON_H */
