#ifndef MAC_SCAN_H
#define MAC_SCAN_H

/* MLME-SCAN's ED, active and orphan scans and MLME-ORPHAN (802.15.4-2024 8.2.8, 10.18, 10.19, 10.20);
   docs/internals/conformance.md §1 owns its contract. */

#include <stdint.h>

#include "radio.h"
#include "zb_status.h"

/* Where the scan is on the channel it visits: tuning to it, asking with a Beacon Request, waiting for that request to
   leave, listening, and putting the channel and PAN back once every channel was visited; an ED scan instead asks the
   radio for a dwell on the channel and collects its level. */
typedef enum Mac_ScanState
{
    MAC_SCAN_IDLE = 0,
    MAC_SCAN_TUNING = 1,
    MAC_SCAN_ASKING = 2,
    MAC_SCAN_SENT = 3,
    MAC_SCAN_LISTENING = 4,
    MAC_SCAN_RESTORING = 5,
    MAC_SCAN_MEASURING = 6,
    MAC_SCAN_COLLECTING = 7
} Mac_ScanState;

/* The scan subject's own state: the request's channels still to visit and the ones left unscanned, the channel being
   visited, its dwell and the instant the current state began, the PAN and channel to restore, the confirm, and an ED
   scan's dwell units its channel still owes, the dwell asked and the peak so far. */
typedef struct Mac_Scan
{
    Mac_ScanState state;
    uint32_t scanType;
    uint32_t channelsLeft;
    uint32_t unscanned;
    uint32_t channel;
    uint32_t dwellMs;
    uint32_t stateMs;
    uint16_t savedPanId;
    uint32_t savedChannel;
    int savedChannelKnown;
    int requestSent;
    uint32_t beaconsAtStart;
    uint32_t handle;
    int handleValid;
    uint8_t requestBytes[1];
    Mac_ScanConfirmParameters confirm;
    int confirmReady;
    uint32_t framesDiscarded;
    Mac_OrphanIndication orphans[MAC_ORPHAN_MAX];
    uint32_t orphanHead;
    uint32_t orphanCount;
    uint32_t orphansDropped;
    uint8_t realignBytes[MAC_REALIGNMENT_OCTETS];
    uint32_t realignmentsSent;

    uint32_t energyUnitsLeft;
    uint32_t energyAsked;
    int32_t energyPeak;
    int energyMeasured;
} Mac_Scan;

/* One request taken: the PAN and channel saved, and an active or orphan scan's broadcast PAN written with its first
   channel. */
ZbStatus MacScan_Start(Mac_Scan *scan, Mac_Mac *self, const Mac_ScanRequestParameters *req, uint32_t nowMs);

/* The scan advanced once per step from the same nowMs. */
void MacScan_Progress(Mac_Scan *scan, Mac_Mac *self, Mac_Tx *tx, uint32_t nowMs);

/* Whether a received frame is one the scan keeps: every frame but a beacon is discarded while an active scan runs
   (6.4.1.2), and every frame while an ED scan runs (10.18). */
int MacScan_Admits(Mac_Scan *scan, const Radio_Frame *frame);

/* An active scan's beacons each owe the layer above a notification, so it is the scan a receive pass holds back
   for. */
int MacScan_ActiveRunning(const Mac_Scan *scan);

/* An orphan scan consumes every frame it is handed: a realignment from a coordinator ends it, any other is discarded. */
int MacScan_OrphanRunning(const Mac_Scan *scan);
void MacScan_TakeOrphanFrame(Mac_Scan *scan, const Mac_Frame *header, const uint8_t *payload, uint32_t payloadLen);

/* 10.20.4.2 at a coordinator: 1 when the frame was an Orphan Notification this device took, 0 otherwise. */
int MacScan_TakeOrphanNotification(Mac_Scan *scan, const Mac_Frame *header, const uint8_t *payload,
                                   uint32_t payloadLen, int beaconAnswers);
uint32_t MacScan_PollOrphans(Mac_Scan *scan, Mac_OrphanIndication *out, uint32_t max);
ZbStatus MacScan_Respond(Mac_Scan *scan, Mac_Mac *self, Mac_Tx *tx, const Mac_OrphanResponseParameters *response,
                         uint32_t nowMs);

int MacScan_Running(const Mac_Scan *scan);
uint32_t MacScan_PollConfirm(Mac_Scan *scan, Mac_ScanConfirmParameters *out);

#endif /* MAC_SCAN_H */
