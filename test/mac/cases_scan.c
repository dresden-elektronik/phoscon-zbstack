/* The `mac` suite's scans: MLME-SCAN.request's per-channel Beacon Request and dwell (10.19) under the broadcast PAN
   and the channel and PAN put back after it, the beacons it notifies, the frames it discards, the three statuses its
   confirm can carry (8.2.8.3), the orphan scan (10.20), and the ED scan's dwells and peak levels (10.18). */

#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "mac_helpers.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

#define SCAN_HOME_CHANNEL 12
#define SCAN_ONE_DWELL_SYMBOLS 1920     /* aBaseSuperframeDuration * (2^0 + 1): 30.72 ms, 31 on the host's clock */

/* The device on the channel it works on, PAN_ID its own. */
static void scanRig(Test_BandA *dev)
{
    Radio_Pib pib;

    rig(dev, SLEEPY_A, PAN_ID);

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_CHANNEL | RADIO_PIB_PAGE;
    pib.channel = SCAN_HOME_CHANNEL;
    Test_ExpectStatus(Mac_SetPib(&dev->mac, &pib), ZB_OK, "the device works on channel 12");
}

static Mac_ScanRequestParameters scanRequest(uint32_t channels)
{
    Mac_ScanRequestParameters req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.scanType = MAC_SCAN_ACTIVE;
    req.scanChannels = channels;
    req.scanDuration = SCAN_ONE_DWELL_SYMBOLS;

    return req;
}

/* A coordinator's beacon on PAN 0x1a62, a PAN not this device's, carrying three octets of payload, from `src` with
   sequence number `seq`. */
static uint32_t scanBeaconFrom(uint8_t *out, uint16_t src, uint8_t seq)
{
    static const uint8_t content[3] = { 0x00, 0x22, 0x84 };
    MacFrame_Beacon beacon;
    Mac_Frame frame;
    uint8_t body[32];
    uint32_t bodyLen = 0;
    uint32_t len = 0;

    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.beaconOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.superframeOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.finalCapSlot = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.panCoordinator = 1;
    beacon.associationPermit = 1;

    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, content, (uint32_t)sizeof content, body,
                                                    (uint32_t)sizeof body, &bodyLen), ZB_OK, "a beacon body");

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_BEACON;
    frame.destAddrMode = MAC_ADDR_NONE;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.srcPan = 0x1a62;
    frame.srcShort = src;
    frame.seq = seq;

    Test_ExpectStatus(MacFrame_Compose(&frame, body, bodyLen, out, RADIO_MPDU_MAX, &len), ZB_OK, "a beacon frame");
    Test_ExpectStatus(MacFrame_AppendFcs(out, len, RADIO_MPDU_MAX, &len), ZB_OK, "closed by its footer");

    return len;
}

static uint32_t scanBeacon(uint8_t *out)
{
    return scanBeaconFrom(out, 0x0000, 0x51);
}

/* Whether a frame the log holds is 7.5.2's Beacon Request: a command to the broadcast PAN and address. */
static int scanIsBeaconRequest(const Air *air)
{
    return air->len >= 8 && (air->bytes[0] & 0x07) == MAC_FRAME_TYPE_COMMAND && air->bytes[3] == 0xff
           && air->bytes[4] == 0xff && air->bytes[5] == 0xff && air->bytes[6] == 0xff
           && air->bytes[7] == MAC_CMD_BEACON_REQUEST;
}

/* 10.19 on two channels: a Beacon Request on each, lowest first, the first refused once for want of room and asked
   again; a foreign PAN's beacon heard on channel 11 under the broadcast PAN and notified with that channel; a poll
   discarded; and channel 12 and PAN_ID back at the end, with a SUCCESS confirm. */
void caseActiveScanVisitsEachChannel(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Mac_ScanRequestParameters req;
    Mac_ScanConfirmParameters confirm;
    Mac_BeaconNotification notified;
    Mac_DataIndicationParameters indications[2];
    uint8_t beacon[RADIO_MPDU_MAX];
    uint32_t beaconLen;
    uint32_t count = 0;
    uint32_t requests = 0;
    uint32_t nowMs;
    uint32_t i;
    int injected = 0;

    scanRig(&dev);
    beaconLen = scanBeacon(beacon);
    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 1);

    req = scanRequest(((uint32_t)1 << 11) | ((uint32_t)1 << 20));
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 1000), ZB_OK, "an active scan of channels 11 and 20");
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 1000), ZB_ERR_BAD_STATE, "and no second one beside it");
    Test_Expect(Mac_Scanning(&dev.mac), "the scan runs");

    for (nowMs = 1000; nowMs < 1300 && Mac_Scanning(&dev.mac); nowMs++)
    {
        if (!injected && dev.mac.scan.state == MAC_SCAN_LISTENING && dev.mac.scan.channel == 11)
        {
            Test_ExpectCount(Mac_Pib(&dev.mac)->panId, MAC_FRAME_PAN_BROADCAST, "listening under the broadcast PAN");
            injectFrame(&dev.model, beacon, beaconLen, nowMs);
            injectPoll(&dev.model, 0x30, SLEEPY_B, nowMs);
            injected = 1;
        }

        Test_ExpectStatus(Mac_Step(&dev.mac, nowMs), ZB_OK, "a turn of the scan");
        harvestAir(&dev.model, air, &count);
    }

    for (i = 0; i < count; i++)
        requests += scanIsBeaconRequest(&air[i]) ? 1 : 0;

    Test_Expect(!Mac_Scanning(&dev.mac), "the scan ends");
    Test_ExpectCount(requests, 2, "one Beacon Request on each channel, the refused one asked again");
    Test_ExpectCount(dev.mac.scan.framesDiscarded, 1, "the poll heard during the scan is discarded (6.4.1.2)");
    Test_ExpectCount(Mac_PollIndications(&dev.mac, indications, 2), 0, "and never indicated");
    Test_ExpectCount(Mac_PollBeacons(&dev.mac, &notified, 1), 1, "the beacon is notified");
    Test_Expect(notified.channel == 11 && notified.coordPanId == 0x1a62 && notified.payloadLen == 3,
                "with the channel it was heard on, its PAN and its payload");

    Test_ExpectCount(Mac_PollScanConfirm(&dev.mac, &confirm), 1, "the confirm is taken");
    Test_ExpectCount(confirm.status, 0x00, "SUCCESS");
    Test_ExpectCount(confirm.beaconsHeard, 1, "one beacon heard");
    Test_ExpectCount(confirm.unscannedChannels, 0, "every channel scanned");
    Test_ExpectCount(Mac_Pib(&dev.mac)->channel, SCAN_HOME_CHANNEL, "the device is back on its channel");
    Test_ExpectCount(Mac_Pib(&dev.mac)->panId, PAN_ID, "and its PAN");
}

/* Four beacons answering one Beacon Request, handed to the MAC in one turn as a bridged RCP's read delivers them,
   are all notified though the ring holds two: the receive pass takes no more than the ring has room for while the
   scan runs, and the layer above drains one a turn. */
void caseActiveScanKeepsEveryBeacon(void)
{
    static const uint16_t sources[4] = { 0x6a6d, 0x9ce6, 0xd18b, 0x2527 };
    Test_BandA dev;
    Mac_ScanRequestParameters req;
    Mac_BeaconNotification notified;
    uint8_t beacon[RADIO_MPDU_MAX];
    uint32_t beaconLen;
    uint32_t heard[4] = { 0, 0, 0, 0 };
    uint32_t nowMs;
    uint32_t i;
    int injected = 0;

    scanRig(&dev);
    req = scanRequest((uint32_t)1 << 11);
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 1000), ZB_OK, "an active scan of channel 11");

    for (nowMs = 1000; nowMs < 1300 && Mac_Scanning(&dev.mac); nowMs++)
    {
        if (!injected && dev.mac.scan.state == MAC_SCAN_LISTENING)
        {
            for (i = 0; i < 4; i++)
            {
                beaconLen = scanBeaconFrom(beacon, sources[i], (uint8_t)(0x60 + i));
                injectFrame(&dev.model, beacon, beaconLen, nowMs);
            }

            injected = 1;
        }

        Test_ExpectStatus(Mac_Step(&dev.mac, nowMs), ZB_OK, "a turn of the scan");

        if (Mac_PollBeacons(&dev.mac, &notified, 1) == 1)
        {
            for (i = 0; i < 4; i++)
                heard[i] += notified.coordShort == sources[i] && notified.sn == 0x60 + i ? 1 : 0;
        }
    }

    Test_Expect(injected && !Mac_Scanning(&dev.mac), "the four beacons arrive while the scan listens, and it ends");
    Test_Expect(heard[0] == 1 && heard[1] == 1 && heard[2] == 1 && heard[3] == 1,
                "each beacon is notified once, the third and fourth as well as the two the ring holds");
    Test_ExpectCount(Mac_CountersOf(&dev.mac).beaconsNotifyDropped, 0, "and none is dropped for want of room");
}

/* A scan whose Beacon Requests nobody answers ends NO_BEACON, the null descriptor list 8.2.8.3 prints; one whose
   requests the channel's CCA refused ends CHANNEL_ACCESS_FAILURE with that channel unscanned. */
void caseActiveScanStatuses(void)
{
    Test_BandA dev;
    Mac_ScanRequestParameters req;
    Mac_ScanConfirmParameters confirm;
    Loopback_Outcome busy;
    uint32_t nowMs;

    scanRig(&dev);
    req = scanRequest((uint32_t)1 << 20);
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 0), ZB_OK, "a scan of channel 20");

    for (nowMs = 0; nowMs < 200 && Mac_Scanning(&dev.mac); nowMs++)
        Test_ExpectStatus(Mac_Step(&dev.mac, nowMs), ZB_OK, "a turn");

    Test_ExpectCount(Mac_PollScanConfirm(&dev.mac, &confirm), 1, "ends");
    Test_ExpectCount(confirm.status, 0xea, "NO_BEACON: the request went out and nothing answered");

    Zb_memset(&busy, 0, (uint32_t)sizeof busy);
    busy.status = ZB_ERR_CHANNEL_ACCESS_FAILURE;
    LoopbackRadio_ScriptOutcomes(&dev.model, &busy, 1);
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 300), ZB_OK, "the same scan on a busy channel");

    for (nowMs = 300; nowMs < 500 && Mac_Scanning(&dev.mac); nowMs++)
        Test_ExpectStatus(Mac_Step(&dev.mac, nowMs), ZB_OK, "a turn");

    Test_ExpectCount(Mac_PollScanConfirm(&dev.mac, &confirm), 1, "ends");
    Test_ExpectCount(confirm.status, 0xe1, "CHANNEL_ACCESS_FAILURE: no Beacon Request could be sent");
    Test_ExpectCount(confirm.unscannedChannels, (uint32_t)1 << 20, "and channel 20 is unscanned");
    Test_ExpectCount(Mac_Pib(&dev.mac)->channel, SCAN_HOME_CHANNEL, "the device is back on its channel");
}

/* A scan type the module does not name, a channel outside 11 to 26, and a dwell past a discovery's longest are
   argument errors, and none starts a scan. */
void caseActiveScanRefusesBadRequests(void)
{
    Test_BandA dev;
    Mac_ScanRequestParameters req;

    scanRig(&dev);

    req = scanRequest((uint32_t)1 << 11);
    req.scanType = 2;
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 0), ZB_ERR_BAD_ARGUMENT, "another scan type");

    req = scanRequest((uint32_t)1 << 10);
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 0), ZB_ERR_BAD_ARGUMENT, "channel 10");

    req = scanRequest(0);
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 0), ZB_ERR_BAD_ARGUMENT, "no channel at all");

    req = scanRequest((uint32_t)1 << 11);
    req.scanDuration = MAC_SCAN_SYMBOLS_MAX + 1;
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 0), ZB_ERR_BAD_ARGUMENT, "a dwell past the longest");
    Test_Expect(!Mac_Scanning(&dev.mac), "and no scan runs");
}

#define SCAN_RIG_CHANNEL 26           /* the rig's own channel, which a coordinator built by `rig` works on */
#define SCAN_OWN_EXTENDED (((uint64_t)0x11223344 << 32) | 0x55667788)
#define SCAN_COORD_EXTENDED (((uint64_t)0x08070605 << 32) | 0x04030201)

/* The scanning device's own extended address, which an orphan notification carries and a realignment names. */
static void scanOwnExtended(Test_BandA *dev, uint64_t extended)
{
    Radio_Pib pib;
    uint32_t i;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_EXTENDED_ADDRESS;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        pib.extendedAddress[i] = (uint8_t)(extended >> (8 * i));

    Test_ExpectStatus(Mac_SetPib(&dev->mac, &pib), ZB_OK, "the device's own extended address");
}

/* Whether a frame the log holds is 10.20.3.1's Orphan Notification: a command with no acknowledgment asked, the
   PAN ID compressed, a short destination and an extended source, to the broadcast PAN and address, from `own`. */
static int scanIsOrphanNotification(const Air *air, uint64_t own)
{
    uint64_t source = 0;
    uint32_t i;

    if (air->len < 16 || air->bytes[0] != (MAC_FRAME_TYPE_COMMAND | 0x40) || air->bytes[1] != 0xc8)
        return 0;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        source |= (uint64_t)air->bytes[7 + i] << (8 * i);

    return air->bytes[3] == 0xff && air->bytes[4] == 0xff && air->bytes[5] == 0xff && air->bytes[6] == 0xff
           && source == own && air->bytes[15] == MAC_CMD_ORPHAN_NOTIFICATION;
}

/* 7.5.4's Coordinator Realignment directed to `to`: from the coordinator's extended address on its PAN 0x1a62, to the
   broadcast PAN, naming PAN 0x1a62, coordinator 0x0000, `channel` and the short address 0x2345. */
static uint32_t scanRealignment(uint8_t *out, uint64_t to, uint32_t channel)
{
    Mac_Frame frame;
    uint8_t content[8] = { MAC_CMD_COORDINATOR_REALIGNMENT, 0x62, 0x1a, 0x00, 0x00, 0x00, 0x45, 0x23 };
    uint32_t len = 0;

    content[5] = (uint8_t)channel;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.ackRequest = 1;
    frame.destAddrMode = MAC_ADDR_EXTENDED;
    frame.destPan = MAC_FRAME_PAN_BROADCAST;
    frame.destExtended = to;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.srcPan = 0x1a62;
    frame.srcExtended = SCAN_COORD_EXTENDED;
    frame.seq = 0x52;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, (uint32_t)sizeof content, out, RADIO_MPDU_MAX, &len), ZB_OK,
                      "a coordinator realignment");
    Test_ExpectStatus(MacFrame_AppendFcs(out, len, RADIO_MPDU_MAX, &len), ZB_OK, "closed by its footer");

    return len;
}

/* 7.5.2's Beacon Request from nobody to the broadcast PAN and address: a command every first-level filter passes. */
static uint32_t scanBeaconRequest(uint8_t *out)
{
    Mac_Frame frame;
    uint8_t content[1] = { MAC_CMD_BEACON_REQUEST };
    uint32_t len = 0;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.destPan = MAC_FRAME_PAN_BROADCAST;
    frame.destShort = MAC_FRAME_ADDR_BROADCAST;
    frame.srcAddrMode = MAC_ADDR_NONE;
    frame.seq = 0x53;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, (uint32_t)sizeof content, out, RADIO_MPDU_MAX, &len), ZB_OK,
                      "a beacon request");
    Test_ExpectStatus(MacFrame_AppendFcs(out, len, RADIO_MPDU_MAX, &len), ZB_OK, "closed by its footer");

    return len;
}

/* 10.20.2.1 with nobody answering: an Orphan Notification on each channel, macResponseWaitTime on each, a status of
   NO_BEACON (8.2.8.3), and the channel and PAN put back as they were. */
void caseOrphanScanNotifiesEachChannel(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Mac_ScanRequestParameters req;
    Mac_ScanConfirmParameters confirm;
    uint32_t count = 0;
    uint32_t notifications = 0;
    uint32_t nowMs;
    uint32_t i;

    scanRig(&dev);
    scanOwnExtended(&dev, SCAN_OWN_EXTENDED);

    req = scanRequest(((uint32_t)1 << 20) | ((uint32_t)1 << 21));
    req.scanType = MAC_SCAN_ORPHAN;
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 0), ZB_OK, "an orphan scan of channels 20 and 21");

    for (nowMs = 0; nowMs < 4 * MAC_RESPONSE_WAIT_MS && Mac_Scanning(&dev.mac); nowMs++)
    {
        Test_ExpectStatus(Mac_Step(&dev.mac, nowMs), ZB_OK, "a turn of the scan");
        harvestAir(&dev.model, air, &count);
    }

    for (i = 0; i < count; i++)
        notifications += scanIsOrphanNotification(&air[i], SCAN_OWN_EXTENDED) ? 1 : 0;

    Test_Expect(!Mac_Scanning(&dev.mac), "the scan ends");
    Test_Expect(nowMs >= 2 * MAC_RESPONSE_WAIT_MS, "after macResponseWaitTime on each channel");
    Test_ExpectCount(notifications, 2, "one Orphan Notification on each channel, as 10.20.3.1 shapes it");
    Test_ExpectCount(Mac_PollScanConfirm(&dev.mac, &confirm), 1, "the confirm is taken");
    Test_ExpectCount(confirm.status, 0xea, "NO_BEACON: a notification went out and no realignment came");
    Test_ExpectCount(confirm.scanType, MAC_SCAN_ORPHAN, "for the orphan scan");
    Test_ExpectCount(confirm.realigned, 0, "realigning nothing");
    Test_ExpectCount(Mac_Pib(&dev.mac)->channel, SCAN_HOME_CHANNEL, "the device is back on its channel");
    Test_ExpectCount(Mac_Pib(&dev.mac)->panId, PAN_ID, "and its PAN");
}

/* 10.20.2.1's termination and 10.20.1's update: a realignment for this device ends the scan on the channel it came
   on, the PIB takes its PAN, channel and short address, and every other command heard in the scan is discarded. */
void caseOrphanScanTakesTheRealignment(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Mac_ScanRequestParameters req;
    Mac_ScanConfirmParameters confirm;
    Mac_DataIndicationParameters indications[2];
    uint8_t frame[RADIO_MPDU_MAX];
    uint32_t frameLen;
    uint32_t count = 0;
    uint32_t notifications = 0;
    uint32_t nowMs;
    uint32_t i;
    int injected = 0;

    scanRig(&dev);
    scanOwnExtended(&dev, SCAN_OWN_EXTENDED);

    req = scanRequest(((uint32_t)1 << 20) | ((uint32_t)1 << 21));
    req.scanType = MAC_SCAN_ORPHAN;
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 0), ZB_OK, "an orphan scan of channels 20 and 21");

    for (nowMs = 0; nowMs < 4 * MAC_RESPONSE_WAIT_MS && Mac_Scanning(&dev.mac); nowMs++)
    {
        if (!injected && dev.mac.scan.state == MAC_SCAN_LISTENING && dev.mac.scan.channel == 20)
        {
            frameLen = scanBeaconRequest(frame);
            injectFrame(&dev.model, frame, frameLen, nowMs);
            frameLen = scanRealignment(frame, SCAN_OWN_EXTENDED + 1, 20);
            injectFrame(&dev.model, frame, frameLen, nowMs);
            frameLen = scanRealignment(frame, SCAN_OWN_EXTENDED, 20);
            injectFrame(&dev.model, frame, frameLen, nowMs);
            injected = 1;
        }

        Test_ExpectStatus(Mac_Step(&dev.mac, nowMs), ZB_OK, "a turn of the scan");
        harvestAir(&dev.model, air, &count);
    }

    for (i = 0; i < count; i++)
        notifications += scanIsOrphanNotification(&air[i], SCAN_OWN_EXTENDED) ? 1 : 0;

    Test_Expect(!Mac_Scanning(&dev.mac), "the scan ends");
    Test_ExpectCount(notifications, 1, "on channel 20: channel 21 is never visited");
    Test_ExpectCount(Mac_PollScanConfirm(&dev.mac, &confirm), 1, "the confirm is taken");
    Test_ExpectCount(confirm.status, 0x00, "SUCCESS");
    Test_ExpectCount(confirm.realigned, 1, "the realignment found");
    Test_Expect(confirm.panId == 0x1a62 && confirm.coordShort == 0x0000 && confirm.coordExtended == SCAN_COORD_EXTENDED
                    && confirm.channel == 20 && confirm.shortAddress == 0x2345,
                "naming the PAN, the coordinator, the channel and the short address 7.5.4 carries");
    Test_Expect(Mac_Pib(&dev.mac)->panId == 0x1a62 && Mac_Pib(&dev.mac)->channel == 20
                    && Mac_Pib(&dev.mac)->shortAddress == 0x2345,
                "and the PIB holds them (10.20.1)");
    Test_ExpectCount(dev.mac.scan.framesDiscarded, 1,
                     "the beacon request is discarded unanswered (10.20.2.1), the other device's realignment filtered");
    Test_ExpectCount(Mac_PollIndications(&dev.mac, indications, 2), 0, "and never indicated");
}

/* 10.20.4.2 and 10.20.4.3 at a coordinator: an Orphan Notification is indicated with the orphan's address, a response
   naming a member sends it 7.5.4's realignment, directed and acknowledged, and one naming no member sends nothing. */
void caseOrphanNotificationIsAnswered(void)
{
    Test_BandA dev;
    Test_BandA child;
    Air air[AIR_LOG_MAX];
    Mac_BeaconConfig beacon;
    Mac_OrphanIndication orphan;
    Mac_OrphanResponseParameters response;
    Mac_ScanRequestParameters req;
    Mac_Frame header;
    Mac_FrameRefusal refusal = MAC_FRAME_REFUSAL_NONE;
    const uint8_t *payload = 0;
    uint32_t payloadLen = 0;
    uint32_t count = 0;
    uint32_t nowMs;

    rig(&dev, 0x0000, PAN_ID);
    scanOwnExtended(&dev, SCAN_COORD_EXTENDED);

    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.answer = 1;
    beacon.panCoordinator = 1;
    Test_ExpectStatus(Mac_SetBeaconConfig(&dev.mac, &beacon), ZB_OK, "a coordinator, its permit closed");

    scanRig(&child);
    scanOwnExtended(&child, SCAN_OWN_EXTENDED);
    req = scanRequest((uint32_t)1 << SCAN_RIG_CHANNEL);
    req.scanType = MAC_SCAN_ORPHAN;
    Test_ExpectStatus(Mac_ScanRequest(&child.mac, &req, 0), ZB_OK, "an orphan scans the coordinator's channel");

    for (nowMs = 0; nowMs < 20 && count == 0; nowMs++)
    {
        Test_ExpectStatus(Mac_Step(&child.mac, nowMs), ZB_OK, "a turn of the orphan's scan");
        harvestAir(&child.model, air, &count);
    }

    Test_Expect(count == 1 && scanIsOrphanNotification(&air[0], SCAN_OWN_EXTENDED), "its notification is on the air");

    if (count == 1)
        injectFrame(&dev.model, air[0].bytes, air[0].len, 100);

    count = 0;
    Test_ExpectStatus(Mac_Step(&dev.mac, 100), ZB_OK, "the coordinator hears it");
    Test_ExpectCount(Mac_PollOrphans(&dev.mac, &orphan, 1), 1, "and indicates it (10.20.4.2)");
    Test_Expect(orphan.orphanAddress == SCAN_OWN_EXTENDED, "with the orphan's extended address");

    Zb_memset(&response, 0, (uint32_t)sizeof response);
    response.orphanAddress = SCAN_OWN_EXTENDED + 1;
    response.shortAddress = 0xffff;
    response.associatedMember = 0;
    Test_ExpectStatus(Mac_OrphanResponse(&dev.mac, &response, 110), ZB_OK, "a response naming no member");
    Test_ExpectStatus(Mac_Step(&dev.mac, 111), ZB_OK, "a turn");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, 0, "sends nothing");

    response.orphanAddress = SCAN_OWN_EXTENDED;
    response.shortAddress = 0x2345;
    response.associatedMember = 1;
    Test_ExpectStatus(Mac_OrphanResponse(&dev.mac, &response, 120), ZB_OK, "a response naming the member");
    Test_ExpectStatus(Mac_Step(&dev.mac, 121), ZB_OK, "a turn");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, 1, "sends one frame");

    if (count != 1)
        return;

    Test_ExpectStatus(MacFrame_Parse(air[0].bytes, air[0].len, 1, &header, &payload, &payloadLen, &refusal), ZB_OK,
                      "a frame this MAC reads back");
    Test_Expect(header.frameType == MAC_FRAME_TYPE_COMMAND && header.ackRequest == 1 && header.framePending == 0
                    && header.panIdCompression == 0 && header.frameVersion == 0,
                "a command asking for an acknowledgment, both PAN IDs present, frame version 0 (7.5.4)");
    Test_Expect(header.destAddrMode == MAC_ADDR_EXTENDED && header.destPan == MAC_FRAME_PAN_BROADCAST
                    && header.destExtended == SCAN_OWN_EXTENDED,
                "to the orphan's extended address on the broadcast PAN");
    Test_Expect(header.srcAddrMode == MAC_ADDR_EXTENDED && header.srcPan == PAN_ID
                    && header.srcExtended == SCAN_COORD_EXTENDED,
                "from the coordinator's extended address on its PAN");
    Test_Expect(payloadLen == 8 && payload[0] == MAC_CMD_COORDINATOR_REALIGNMENT && payload[1] == (PAN_ID & 0xff)
                    && payload[2] == (PAN_ID >> 8) && payload[3] == 0x00 && payload[4] == 0x00
                    && payload[5] == SCAN_RIG_CHANNEL && payload[6] == 0x45 && payload[7] == 0x23,
                "carrying the PAN, the coordinator's short address, the channel and the orphan's address");
}

#define SCAN_LONG_DWELL_SYMBOLS 123840  /* aBaseSuperframeDuration * (2^7 + 1): 1981.44 ms, two dwells of the radio's */

/* The device on channel 12 with a radio that measures: the dwell pair answers. */
static void scanEnergyRig(Test_BandA *dev)
{
    Radio_Caps caps;
    Radio_Pib pib;

    Test_BandACapsAcks(&caps);
    caps.hasEnergyScan = 1;
    rigConfig(dev, &caps, SLEEPY_A, PAN_ID, 0);

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_CHANNEL | RADIO_PIB_PAGE;
    pib.channel = SCAN_HOME_CHANNEL;
    Test_ExpectStatus(Mac_SetPib(&dev->mac, &pib), ZB_OK, "the device works on channel 12");
}

/* 10.18 on four channels: one dwell each, lowest first, nothing on the air and every frame discarded; the level each
   reported, and the channel whose dwell measured nothing unscanned rather than given a level; channel and PAN kept. */
void caseEnergyScanMeasuresEachChannel(void)
{
    static const int32_t levels[16] = { -80, -94, -94, -94, -60, -94, -94, -94,
                                        -94, RADIO_SCAN_NO_LEVEL, -94, -94, -94, -94, -91, -94 };
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Mac_ScanRequestParameters req;
    Mac_ScanConfirmParameters confirm;
    Mac_DataIndicationParameters indications[2];
    uint32_t count = 0;
    uint32_t nowMs;
    int injected = 0;

    scanEnergyRig(&dev);
    LoopbackRadio_ScriptEnergy(&dev.model, levels, 16);

    req = scanRequest(((uint32_t)1 << 11) | ((uint32_t)1 << 15) | ((uint32_t)1 << 20) | ((uint32_t)1 << 25));
    req.scanType = MAC_SCAN_ENERGY;
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 1000), ZB_OK, "an ED scan of channels 11, 15, 20 and 25");
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 1000), ZB_ERR_BAD_STATE, "and no second one beside it");

    for (nowMs = 1000; nowMs < 1300 && Mac_Scanning(&dev.mac); nowMs++)
    {
        if (!injected && dev.mac.scan.state == MAC_SCAN_COLLECTING)
        {
            Test_ExpectCount(dev.mac.scan.energyAsked, 31, "a dwell of ScanDuration's 31 ms, in the radio's units");
            injectPoll(&dev.model, 0x30, SLEEPY_B, nowMs);
            injected = 1;
        }

        Test_ExpectStatus(Mac_Step(&dev.mac, nowMs), ZB_OK, "a turn of the scan");
        Test_ExpectStatus(LoopbackRadio_Pump(&dev.model, nowMs), ZB_OK, "and of the radio");
        harvestAir(&dev.model, air, &count);
    }

    Test_Expect(!Mac_Scanning(&dev.mac), "the scan ends");
    Test_ExpectCount(count, 0, "with nothing on the air");
    Test_ExpectCount(dev.mac.scan.framesDiscarded, 1, "the poll heard during the scan is discarded (10.18)");
    Test_ExpectCount(Mac_PollIndications(&dev.mac, indications, 2), 0, "and never indicated");

    Test_ExpectCount(Mac_PollScanConfirm(&dev.mac, &confirm), 1, "the confirm is taken");
    Test_ExpectCount(confirm.status, 0x00, "SUCCESS");
    Test_ExpectCount(confirm.scanType, MAC_SCAN_ENERGY, "for the ED scan");
    Test_Expect(confirm.energyDbm[11 - 11] == -80 && confirm.energyDbm[15 - 11] == -60
                && confirm.energyDbm[25 - 11] == -91, "each channel's level as the radio reported it, in dBm");
    Test_ExpectCount(confirm.unscannedChannels, (uint32_t)1 << 20,
                     "and channel 20, whose dwell measured nothing, unscanned rather than given a level");
    Test_ExpectCount(Mac_Pib(&dev.mac)->channel, SCAN_HOME_CHANNEL, "the device is still on its channel");
    Test_ExpectCount(Mac_Pib(&dev.mac)->panId, PAN_ID, "and its PAN");
}

/* A ScanDuration longer than one dwell is two, 1000 units and the 982 left, and the channel's level is their peak,
   the louder first one rather than the last: 10.18's maximum over the whole duration. */
void caseEnergyScanTakesThePeakOfItsDwells(void)
{
    int32_t first[1] = { -70 };
    int32_t second[1] = { -90 };
    Test_BandA dev;
    Mac_ScanRequestParameters req;
    Mac_ScanConfirmParameters confirm;
    uint32_t asked[3] = { 0, 0, 0 };
    uint32_t dwells = 0;
    uint32_t nowMs;
    int collecting = 0;

    scanEnergyRig(&dev);
    LoopbackRadio_ScriptEnergy(&dev.model, first, 1);

    req = scanRequest((uint32_t)1 << 11);
    req.scanType = MAC_SCAN_ENERGY;
    req.scanDuration = SCAN_LONG_DWELL_SYMBOLS;
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 1000), ZB_OK, "an ED scan of channel 11 at ScanDuration 7");

    for (nowMs = 1000; nowMs < 1100 && Mac_Scanning(&dev.mac); nowMs++)
    {
        if (!collecting && dev.mac.scan.state == MAC_SCAN_COLLECTING)
        {
            if (dwells < 3)
                asked[dwells] = dev.mac.scan.energyAsked;

            dwells++;
        }

        collecting = dev.mac.scan.state == MAC_SCAN_COLLECTING;
        Test_ExpectStatus(Mac_Step(&dev.mac, nowMs), ZB_OK, "a turn of the scan");
        Test_ExpectStatus(LoopbackRadio_Pump(&dev.model, nowMs), ZB_OK, "and of the radio");

        if (dwells == 1 && dev.mac.scan.state == MAC_SCAN_MEASURING)
            LoopbackRadio_ScriptEnergy(&dev.model, second, 1);
    }

    Test_ExpectCount(dwells, 2, "two dwells on the channel");
    Test_Expect(asked[0] == 1000 && asked[1] == 982, "1000 units, the bound the radio states, then the 982 left");
    Test_ExpectCount(Mac_PollScanConfirm(&dev.mac, &confirm), 1, "the confirm is taken");
    Test_ExpectCount((uint32_t)(int32_t)confirm.energyDbm[0], (uint32_t)-70, "the first dwell's level, the louder: the peak, not the last");
    Test_ExpectCount(confirm.unscannedChannels, 0, "and the channel measured");
}

/* An ED scan on a radio with no dwell surface measures nothing: the radio refuses each dwell, and every channel is
   unscanned rather than given a level. */
void caseEnergyScanNeedsADwell(void)
{
    Test_BandA dev;
    Mac_ScanRequestParameters req;
    Mac_ScanConfirmParameters confirm;
    uint32_t channels = ((uint32_t)1 << 11) | ((uint32_t)1 << 26);
    uint32_t nowMs;

    scanRig(&dev);

    req = scanRequest(channels);
    req.scanType = MAC_SCAN_ENERGY;
    Test_ExpectStatus(Mac_ScanRequest(&dev.mac, &req, 1000), ZB_OK, "an ED scan on a radio that has no dwell");

    for (nowMs = 1000; nowMs < 1010 && Mac_Scanning(&dev.mac); nowMs++)
    {
        Test_ExpectStatus(Mac_Step(&dev.mac, nowMs), ZB_OK, "a turn of the scan");
        Test_ExpectStatus(LoopbackRadio_Pump(&dev.model, nowMs), ZB_OK, "and of the radio");
    }

    Test_Expect(!Mac_Scanning(&dev.mac), "ends at once");
    Test_ExpectCount(Mac_PollScanConfirm(&dev.mac, &confirm), 1, "the confirm is taken");
    Test_ExpectCount(confirm.unscannedChannels, channels, "with both channels unscanned, nothing measured");
}
