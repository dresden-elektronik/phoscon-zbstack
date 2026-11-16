/* The child's half of association: 10.21.2's exchange from the associating device's side. The PIB is written
   first, 10.21.5.1's request goes to the parent, its acknowledgment opens the ONE macResponseWaitTime window the
   clause gives the decision, the Data Requests 10.22.3 extracts it with are issued inside that window (R23.1
   3.6.1.6.1.2 asks for at least one before the timer expires and permits more), and 10.21.5.2's answer is the only
   frame that ends the exchange. What the parent decided is a status in the confirm (Table 10-107); what the child
   does with a failure -- 10.21.2's return to macPanId and macShortAddress 0xffff -- is asserted at the PIB.

   The rig here is a device and not a parent (`rig`, whose own short address is the caller's): an associating
   device has no beacon to answer and no transaction queue to extract, and the frames it must read are the ones
   this file injects. */

#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "mac_helpers.h"
#include "radio.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

/* 6.2's short-address and PAN-ID defaults, Table 8-36's macShortAddress/macPanId pair: 0xffff is what an
   unassociated device holds and what 10.21.2 returns to after a failure. */
#define ASSOC_UNASSOCIATED 0xffff

/* Table 10-107's Status for the two waits these cases reach: the request was acknowledged and no decision arrived
   inside macResponseWaitTime, which 10.21.2 answers NO_DATA 0xeb, and a request that never left at all, which is
   NO_ACK 0xe9. Both numbers are 802.15.4-2006 Table 78's (7.1.17) and neither is in the reserved 0x01-0xda band.
   The names are mac.c's own, spelled here because they are what this suite asserts and not statuses the header
   publishes. */
#define ASSOC_NO_DATA 0xeb
#define ASSOC_NO_ACK 0xe9
#define ASSOC_CHANNEL_ACCESS_FAILURE 0xe1

/* The associating device and the parent it addresses. The child's extended address is the one the PIB is given;
   the parent's is the one a response must come from. */
#define CHILD_EXTENDED UINT64_C(0x0123456789abcdef)
#define PARENT_EXTENDED UINT64_C(0x1111111111111111)
#define FOREIGN_PARENT_EXTENDED UINT64_C(0x2222222222222222)
#define CHILD_SHORT 0x1234

/* The child's extended address as it travels: 7.2.2.9's address fields are transmitted least significant octet
   first, the order `mac_frame` writes and docs/internals/protocol.md §9.1 records. */
static const uint8_t childExtendedOctets[8] = { 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01 };

/* The offset the Source Address field of an Association Request occupies: FCF, sequence number, Destination
   PAN ID, Destination Address (short) and Source PAN ID, then the eight address octets (docs/internals/protocol.md §9.1). */
#define ASSOC_REQUEST_SRC_OFFSET 9

/* The stack's façade writes the operational address through `Mac_SetPib` and so does this suite: a part's
   factory address is the backend's own and 10.21.5.1's source is macExtendedAddress, which a device that was
   given none does not have. */
static void setChildExtended(Test_BandA *dev)
{
    Radio_Pib pib;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_EXTENDED_ADDRESS;
    Zb_memcpy(pib.extendedAddress, childExtendedOctets, RADIO_ADDR_LEN);

    Test_ExpectStatus(Mac_SetPib(&dev->mac, &pib), ZB_OK,
                      "the child's own extended address is set through the seam");
}

/* Table 10-104's parameters for the one exchange these cases run: the PAN to join, the parent as the beacon named
   it (a short address that is not 6.2's broadcast one), no channel (0 leaves the radio where it is), and Figure
   10-157's capability octet with Allocate Address the only bit set -- 0x80 on the wire, the association an end
   device makes when it is asking for an address. */
static Mac_AssociateRequestParameters childRequest(void)
{
    Mac_AssociateRequestParameters req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.destPan = PAN_ID;
    req.parentShortKnown = 1;
    req.parentShort = COORDINATOR_SHORT;
    req.parentExtended = PARENT_EXTENDED;
    req.channel = 0;                 /* 0 leaves the radio's channel alone (Table 10-104's ChannelInfo) */
    req.capability.deviceType = 0;         /* an RFD */
    req.capability.powerSource = 0;        /* on its own battery */
    req.capability.rxOnWhenIdle = 0;       /* a sleepy end device */
    req.capability.allocateAddress = 1;    /* the bit 10.21.2's address allocation hangs on */
    req.capability.associationType = 0;
    req.capability.suspendableCsmaCa = 0;
    req.capability.securityCapability = 0;

    return req;
}

/* The request's acknowledgment collected and the wait started: every case after the first begins here, because
   the two frames the child composes and the waits between them are one exchange and not seven. Each frame is
   harvested while the record of it is still live, since the turn that collects its completion reclaims it. */
static void startChildAssociation(Test_BandA *dev, Air *air, uint32_t *count)
{
    Mac_AssociateRequestParameters req = childRequest();

    Test_ExpectStatus(Mac_AssociateRequest(&dev->mac, &req, 0), ZB_OK,
                      "the child's Association Request is accepted (10.21.2)");
    harvestAir(&dev->model, air, count);

    Test_ExpectStatus(Mac_Step(&dev->mac, 0), ZB_OK, "and the acknowledgment of it is collected");
    Test_ExpectCount(Mac_AssocStateOf(&dev->mac), MAC_ASSOC_WAITING,
                     "so the exchange is waiting for the parent's decision, with macResponseWaitTime running");
}

/* 10.21.2 and decision 142: the extraction is attempted "after macResponseWaitTime", and the window the attempt
   opens for the answer is that same wait wide, so the first Data Request is due one wait after the acknowledgment
   and the deadline is two. */
static void pollForDecision(Test_BandA *dev, Air *air, uint32_t *count)
{
    Test_ExpectStatus(Mac_Step(&dev->mac, MAC_RESPONSE_WAIT_MS), ZB_OK,
                      "the turn at macResponseWaitTime after the acknowledgment asks the parent for its decision");
    Test_Expect(Mac_AssocStateOf(&dev->mac) == MAC_ASSOC_POLLING,
                "with the Data Request 10.22.3 makes on the air, inside the one macResponseWaitTime window the acknowledgment opened (10.21.2)");
    harvestAir(&dev->model, air, count);
}

static void injectDecision(Test_BandA *dev, uint64_t parent, uint16_t shortAddress, uint8_t status, uint64_t stamp)
{
    uint8_t frame[RADIO_MPDU_MAX];
    uint32_t len;

    len = composeAssociationResponse(frame, 0x33, CHILD_EXTENDED, parent, shortAddress, status);
    injectFrame(&dev->model, frame, len, stamp);
}

/* The request is one command frame, and what it says about this device is the whole of 10.21.5.1: extended
   source addressing from the PIB, the source PAN the broadcast one because the device is not associated with
   anything yet, the destination the parent and the PAN to join, and the two content octets 0x01 and the
   capability. The PIB beside it is what 10.21.2 writes before the request goes out. */
void caseChildAssociationRequestIsComposed(void)
{
    Test_BandA dev;
    Mac_AssociateConfirmParameters confirm;
    Mac_AssociateRequestParameters req;
    Mac_Frame frame;
    const uint8_t *payloadOut = 0;
    uint32_t payloadLen = 0;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&dev);

    req = childRequest();
    Test_ExpectStatus(Mac_AssociateRequest(&dev.mac, &req, 0), ZB_OK,
                      "10.21.5.1's request is issued");

    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_REQUESTING,
                "the exchange is in flight and 10.21.2's sequence has begun (Figure 10-152)");
    Test_Expect(Mac_Pib(&dev.mac)->panId == PAN_ID,
                "the PAN to join is written into macPanId before anything is composed (10.21.2)");
    Test_Expect(Mac_Pib(&dev.mac)->shortAddress == ASSOC_UNASSOCIATED,
                "and macShortAddress stays 0xffff, which is what an unassociated device holds (Table 8-36)");

    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, 1, "exactly one frame went on the air: the request, and nothing else");

    if (count < 1)
        return;

    Test_ExpectStatus(MacFrame_Parse(air[0].bytes, air[0].len, 1, &frame, &payloadOut, &payloadLen, 0), ZB_OK,
                      "the request parses");

    Test_Expect(frame.frameType == MAC_FRAME_TYPE_COMMAND && frame.ackRequest == 1,
                "a command frame that asks for an acknowledgment (10.21.2's request is acknowledged)");
    Test_Expect(frame.framePending == 0, "with Frame Pending zero, the request having nothing to announce");
    Test_Expect(frame.destAddrMode == MAC_ADDR_SHORT && frame.destShort == COORDINATOR_SHORT,
                "addressed to the parent's short address, the form the beacon named (10.21.5.1)");
    Test_Expect(frame.destPan == PAN_ID, "on the PAN to join");
    Test_Expect(frame.panIdCompression == 0 && frame.srcPan == MAC_FRAME_PAN_BROADCAST,
                "and the source PAN is the broadcast PAN, which is why the frame carries both fields (10.21.5.1)");
    Test_Expect(frame.srcAddrMode == MAC_ADDR_EXTENDED && frame.srcExtended == CHILD_EXTENDED,
                "the source is this device's extended address, macShortAddress not being one yet (10.21.5.1)");
    Test_ExpectOctets("and the field says so on the wire, least significant octet first (7.2.2.9)",
                      air[0].bytes + ASSOC_REQUEST_SRC_OFFSET, 8, childExtendedOctets, 8);

    Test_ExpectCount(payloadLen, 2, "the content field is two octets");
    Test_Expect(payloadOut[0] == MAC_CMD_ASSOCIATION_REQUEST && payloadOut[1] == 0x80,
                "Command ID 0x01 and the capability octet 0x80: Figure 10-157's Allocate Address bit is the only one set, an RFD on battery whose receiver is off when idle having nothing else to say (10.21.5.1)");

    Test_Expect(Mac_PollAssociateConfirm(&dev.mac, &confirm) == 0,
                "nothing has been decided yet, so the layer above is owed no confirm");
}

/* The exchange end to end: the acknowledgment opens the window, a Data Request inside it extracts the decision,
   and the answer the parent gave is stored -- the short address into macShortAddress and the status into the
   confirm -- 292 ms before that window closes. */
void caseChildAssociationSucceeds(void)
{
    Test_BandA dev;
    Mac_AssociateConfirmParameters confirm;
    Mac_Frame frame;
    const uint8_t *payloadOut = 0;
    uint32_t payloadLen = 0;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;
    uint32_t poll;

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&dev);
    startChildAssociation(&dev, air, &count);
    pollForDecision(&dev, air, &count);

    Test_ExpectCount(count, 2, "the air holds the request and the Data Request it earned, and nothing else");

    poll = airIndexOf(air, count, COORDINATOR_SHORT, 1);
    Test_Expect(poll < count, "the second frame issued carries the next DSN (6.6.1) and is addressed to the parent");

    if (poll < count)
    {
        Test_ExpectStatus(MacFrame_Parse(air[poll].bytes, air[poll].len, 1, &frame, &payloadOut, &payloadLen, 0),
                          ZB_OK, "the Data Request parses");

        Test_Expect(frame.frameType == MAC_FRAME_TYPE_COMMAND && frame.ackRequest == 1,
                    "10.22.4.1's Data Request is a command frame that asks to be acknowledged");
        Test_Expect(frame.destAddrMode == MAC_ADDR_SHORT && frame.destShort == COORDINATOR_SHORT,
                    "addressed to the parent");
        Test_Expect(frame.srcAddrMode == MAC_ADDR_EXTENDED && frame.srcExtended == CHILD_EXTENDED,
                    "and sourced from the extended address, macShortAddress being 0xffff until the answer is read (10.22.4.1)");
        Test_ExpectCount(payloadLen, 1, "its content field is the one Command ID octet");
        Test_Expect(payloadOut[0] == MAC_CMD_POLL, "Command ID 0x04, the Data Request (Table 7-11)");
    }

    injectDecision(&dev, PARENT_EXTENDED, CHILD_SHORT, MAC_ASSOC_STATUS_SUCCESS, 200);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK,
                      "the answer arrives 77 ms after the poll and 292 before the window closes (10.21.2)");

    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_DONE, "and the exchange is concluded");
    Test_Expect(Mac_PollAssociateConfirm(&dev.mac, &confirm) == 1, "the confirm is handed up once");
    Test_Expect(confirm.status == MAC_ASSOC_STATUS_SUCCESS, "with Table 10-102's success");
    Test_Expect(confirm.shortAddress == CHILD_SHORT,
                "and the short address the parent allocated (Table 10-107's AssocShortAddress)");
    Test_Expect(confirm.parentExtended == PARENT_EXTENDED, "naming the parent whose answer it was");
    Test_Expect(confirm.parentShortKnown == 1 && confirm.parentShort == COORDINATOR_SHORT,
                "and the parent the request addressed");

    Test_Expect(Mac_Pib(&dev.mac)->shortAddress == CHILD_SHORT,
                "10.21.2 stores that address in macShortAddress");
    Test_Expect(Mac_Pib(&dev.mac)->panId == PAN_ID, "and the PAN is still the one that was joined");

    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_IDLE,
                "the machine is idle again, ready for another attempt (10.21.6.1.5)");
}

/* Table 10-102's failure: the parent declined, so the status is the parent's own octet and 10.21.2 returns the
   device to the pair it held before the request wrote anything. */
void caseChildAssociationRefused(void)
{
    Test_BandA dev;
    Mac_AssociateConfirmParameters confirm;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&dev);
    startChildAssociation(&dev, air, &count);
    pollForDecision(&dev, air, &count);

    injectDecision(&dev, PARENT_EXTENDED, ASSOC_UNASSOCIATED, MAC_ASSOC_STATUS_PAN_ACCESS_DENIED, 200);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "the parent's refusal arrives inside the window");

    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_FAILED, "and the exchange has failed");
    Test_Expect(Mac_PollAssociateConfirm(&dev.mac, &confirm) == 1, "the confirm is handed up once");
    Test_Expect(confirm.status == MAC_ASSOC_STATUS_SUCCESS && confirm.associationStatus == MAC_ASSOC_STATUS_PAN_ACCESS_DENIED,
                "with Status SUCCESS, the exchange having worked, and Table 10-102's PAN access denied as the parent's decision");
    Test_Expect(confirm.shortAddress == ASSOC_UNASSOCIATED,
                "and 0xffff, which Table 10-107 prints for an association that did not happen");

    Test_Expect(Mac_Pib(&dev.mac)->panId == ASSOC_UNASSOCIATED && Mac_Pib(&dev.mac)->shortAddress == ASSOC_UNASSOCIATED,
                "10.21.2 returns macPanId and macShortAddress to 0xffff after a failure");
    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_IDLE, "and the machine is idle again");
}

/* No answer inside the window: 10.21.2's NO_DATA, concluded AT the deadline the acknowledgment opened and not a
   second wait later. The Data Requests went on the air inside the window and none went out after it, because the
   492 ms is the acknowledgment's and not the last poll's. */
void caseChildAssociationTimesOut(void)
{
    Test_BandA dev;
    Mac_AssociateConfirmParameters confirm;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;
    uint32_t airCount = 0;

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&dev);
    startChildAssociation(&dev, air, &count);
    pollForDecision(&dev, air, &count);

    Test_ExpectCount(count, 2, "the request and one Data Request are on the air");

    airCount = count;

    Test_ExpectStatus(Mac_Step(&dev.mac, 2 * MAC_RESPONSE_WAIT_MS), ZB_OK,
                      "the turn at two macResponseWaitTimes ends the wait for an answer (10.21.2)");

    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, airCount,
                     "and nothing more went on the air: the deadline is the first attempt's window closing, not a poll's");

    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_FAILED, "the attempt has failed");
    Test_Expect(Mac_PollAssociateConfirm(&dev.mac, &confirm) == 1, "the confirm is handed up once");
    Test_Expect(confirm.status == ASSOC_NO_DATA,
                "with NO_DATA 0xeb (Table 78): an answer was asked for inside the window and none came (10.21.2)");
    Test_Expect(confirm.shortAddress == ASSOC_UNASSOCIATED, "and 0xffff for the address (Table 10-107)");

    Test_Expect(Mac_Pib(&dev.mac)->panId == ASSOC_UNASSOCIATED && Mac_Pib(&dev.mac)->shortAddress == ASSOC_UNASSOCIATED,
                "the PIB is back to the pair a device that is not associated holds (10.21.2)");
}

/* A broadcast data frame from another device, which every device on the PAN is addressed by (6.6.2 d)1). */
static void injectBroadcastData(Test_BandA *dev, uint8_t *bytes, uint8_t seq)
{
    Mac_Frame frame;
    uint8_t content[1] = { 0x5a };
    const uint8_t *payloadOut;
    uint32_t payloadOutLen;
    uint32_t len;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_DATA;
    frame.frameVersion = 0;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.destPan = Mac_Pib(&dev->mac)->panId;
    frame.destShort = MAC_FRAME_ADDR_BROADCAST;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.panIdCompression = 1;
    frame.srcShort = SLEEPY_A;
    frame.seq = seq;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, 1, bytes, RADIO_MPDU_MAX, &len), ZB_OK,
                      "a broadcast data frame from another device composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK, "with its footer");
    Test_Expect(MacFrame_Parse(bytes, len, 1, &frame, &payloadOut, &payloadOutLen, 0) == ZB_OK,
                "and reads back as the frame it is");
    injectFrame(&dev->model, bytes, len, 200 + seq);
}

/* 10.21.2's deadline is not the ring's: a turn with nowhere to put a delivered frame reads no batch, and the
   window still closes on it, or an application that stops draining would hold the association open for ever. */
void caseChildAssociationTimesOutWithoutRingRoom(void)
{
    Test_BandA dev;
    Mac_AssociateConfirmParameters confirm;
    Air air[AIR_LOG_MAX];
    uint8_t filler[RADIO_MPDU_MAX];
    uint32_t count = 0;
    uint32_t i;

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&dev);
    startChildAssociation(&dev, air, &count);
    pollForDecision(&dev, air, &count);

    /* The ring filled by broadcast data frames, which 6.6.2 d)1 delivers upward whatever this device's own
       address is: as many as the ring holds, a batch of them a turn. */
    for (i = 0; i < MAC_INDICATION_QUEUE_MAX; i++)
        injectBroadcastData(&dev, filler, 0x40 + i);

    for (i = 0; i * RADIO_FRAME_BATCH_MAX < MAC_INDICATION_QUEUE_MAX; i++)
        Test_ExpectStatus(Mac_Step(&dev.mac, 100 + i), ZB_OK, "a batch is delivered into the ring");

    Test_ExpectCount(Mac_CountersOf(&dev.mac).indicationQueue, MAC_INDICATION_QUEUE_MAX,
                     "the indication ring is full, so the next turn has no room for a frame");

    Test_ExpectStatus(Mac_Step(&dev.mac, 2 * MAC_RESPONSE_WAIT_MS + 1000), ZB_OK,
                      "the turn at the deadline has no batch to read");
    Test_Expect(Mac_CountersOf(&dev.mac).pollsSkipped == 1, "and says so, keeping the frame in band B's ring");
    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_FAILED,
                "while 10.21.2's window closes anyway: the deadline is not the ring's to enforce");
    Test_Expect(Mac_PollAssociateConfirm(&dev.mac, &confirm) == 1 && confirm.status == ASSOC_NO_DATA,
                "with NO_DATA, the confirmation an expired window owes");
}

/* 10.21.2's one association at a time is about an attempt in flight, not about an outcome nobody has read: a
   second request after a failed attempt is the next attempt, and the first one's confirm is discarded. */
void caseChildAssociationRestartsAfterAFailure(void)
{
    Test_BandA dev;
    Mac_AssociateRequestParameters req;
    Mac_AssociateConfirmParameters confirm;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&dev);
    startChildAssociation(&dev, air, &count);
    Test_ExpectStatus(Mac_Step(&dev.mac, 2 * MAC_RESPONSE_WAIT_MS), ZB_OK, "the first attempt times out");
    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_FAILED, "leaving the machine failed");

    req = childRequest();
    Test_ExpectStatus(Mac_AssociateRequest(&dev.mac, &req, 2000), ZB_OK,
                      "the next request is accepted: the attempt is over, and the machine is idle again");
    Test_Expect(Mac_PollAssociateConfirm(&dev.mac, &confirm) == 0,
                "the outcome nobody took is discarded rather than handed up beside the second attempt");
    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_REQUESTING, "and the second attempt is the one in flight");
}

/* Figure 10-157's three bits this stack does not implement: fast association, suspendable CSMA-CA and MAC
   security. Each is refused at the door rather than written as a capability this device would not honour, and a
   refusal that never composed a frame leaves the air empty and the exchange idle. */
void caseChildAssociationRefusesCapabilities(void)
{
    Test_BandA dev;
    Mac_AssociateRequestParameters req;
    Loopback_Sent sent[2];
    Mac_Counters counters;

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&dev);

    req = childRequest();
    req.capability.associationType = 1;
    Test_ExpectStatus(Mac_AssociateRequest(&dev.mac, &req, 0), ZB_ERR_UNSUPPORTED,
                      "a fast-association request is refused: its answer would have to be direct (10.21.4)");
    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_IDLE, "and nothing is in flight");

    req = childRequest();
    req.capability.suspendableCsmaCa = 1;
    Test_ExpectStatus(Mac_AssociateRequest(&dev.mac, &req, 0), ZB_ERR_UNSUPPORTED,
                      "so is a claim this device can suspend CSMA-CA");
    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_IDLE, "with nothing in flight");

    req = childRequest();
    req.capability.securityCapability = 1;
    Test_ExpectStatus(Mac_AssociateRequest(&dev.mac, &req, 0), ZB_ERR_UNSUPPORTED,
                      "and a claim of MAC security, which no frame this device sends carries");
    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_IDLE, "with nothing in flight");

    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 2) == 0,
                "not one frame was composed for any of the three refusals");
    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.refusedRequests == 3, "and each of them is counted rather than swallowed");
}

/* 10.21.5.1's source is macExtendedAddress: a device that was given none has no request to make, and 10.21.2
   allows one exchange at a time. */
void caseChildAssociationNeedsAnAddress(void)
{
    Test_BandA dev;
    Mac_AssociateRequestParameters req;
    Loopback_Sent sent[2];

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);

    req = childRequest();
    Test_ExpectStatus(Mac_AssociateRequest(&dev.mac, &req, 0), ZB_ERR_NOT_READY,
                      "a device with no extended address has no request to make (10.21.5.1)");
    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_IDLE, "and no exchange begins");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 2) == 0, "nothing went on the air");
    Test_Expect(Mac_Pib(&dev.mac)->panId == ASSOC_UNASSOCIATED,
                "and the PIB was not written, the refusal coming before 10.21.2's write");

    setChildExtended(&dev);

    req = childRequest();
    Test_ExpectStatus(Mac_AssociateRequest(&dev.mac, &req, 0), ZB_OK, "with the address written the request is issued");
    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_REQUESTING, "and the exchange is in flight");

    req = childRequest();
    Test_ExpectStatus(Mac_AssociateRequest(&dev.mac, &req, 0), ZB_ERR_BUSY,
                      "a second request while one is in flight is refused (10.21.2)");
    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_REQUESTING,
                "and the exchange already in flight is left exactly as it was");
}

/* 10.21.2 writes macPanId before anything is composed, so a door that refuses the frame afterwards would leave
   the device naming a PAN it never joined. The clause covers exactly that: "if there were a communication failure
   during the association process due to a missed Ack frame, or if the Association Response command was not
   received, the device shall set macPanId to the default value". The track pool is what makes the refusal
   reachable here -- eight transmits nobody collected fill it -- so the request is held, and when no room comes
   inside the bound the exchange fails once and the PIB goes back once. */
void caseChildAssociationRestoresPibWhenNothingWasSent(void)
{
    Test_BandA dev;
    Mac_AssociateConfirmParameters confirm;
    Mac_AssociateRequestParameters req;
    Mac_DataRequestParameters data;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;
    uint32_t before;
    uint32_t i;

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&dev);

    data = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, COORDINATOR_SHORT, MAC_ADDR_EXTENDED, 0);

    for (i = 0; i < MAC_TX_TRACK_MAX; i++)
        Test_ExpectStatus(Mac_DataRequest(&dev.mac, &data, 0, 0), ZB_OK,
                          "a transmit whose confirmation nobody collects, until the track pool is full");

    harvestAir(&dev.model, air, &count);
    before = count;

    req = childRequest();
    Test_ExpectStatus(Mac_AssociateRequest(&dev.mac, &req, 0), ZB_OK,
                      "the pool the request would live in is full, so the door holds it after the PIB write");
    Test_ExpectCount(Mac_AssocStateOf(&dev.mac), MAC_ASSOC_SENDING, "waiting for room, not yet failed");
    Test_Expect(Mac_Pib(&dev.mac)->panId == PAN_ID, "with the PAN 10.21.2 writes still written");

    Test_ExpectStatus(Mac_Step(&dev.mac, MAC_ASSOC_SEND_WAIT_MS - 1), ZB_OK, "a turn inside the bound");
    Test_ExpectCount(Mac_AssocStateOf(&dev.mac), MAC_ASSOC_SENDING, "still held while the pool stays full");
    Test_ExpectStatus(Mac_Step(&dev.mac, MAC_ASSOC_SEND_WAIT_MS), ZB_OK, "the turn the bound runs out");

    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, before, "and no Association Request went on the air");

    Test_Expect(Mac_Pib(&dev.mac)->panId == ASSOC_UNASSOCIATED && Mac_Pib(&dev.mac)->shortAddress == ASSOC_UNASSOCIATED,
                "macPanId and macShortAddress are back at Table 8-36's 0xffff, not naming the PAN the write named (10.21.2)");
    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_FAILED,
                "the exchange has failed rather than being left idle with a PAN written");

    Test_Expect(Mac_PollAssociateConfirm(&dev.mac, &confirm) == 1, "the outcome is owed as a confirm and handed up once");
    Test_Expect(confirm.status == 0xee,
                "with TRANSACTION_OVERFLOW 0xee: 8.2.2's name for a frame no capacity could hold, where NO_ACK would claim a transmission that never happened");
    Test_Expect(confirm.shortAddress == ASSOC_UNASSOCIATED, "and 0xffff for the address (Table 10-107)");
    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_IDLE,
                "the machine is idle again once the outcome has been taken (10.21.6.1.5)");
}

/* A request that was not acknowledged ends the exchange, with Table 10-107's Status saying why: 8.2.2's
   CHANNEL_ACCESS_FAILURE 0xe1 where CSMA-CA found the channel busy, NO_ACK 0xe9 where the frame went out unanswered. */
void caseChildAssociationRequestNotAcknowledged(void)
{
    static const ZbStatus outcome[2] = { ZB_ERR_CHANNEL_ACCESS_FAILURE, ZB_OK };
    static const uint8_t expected[2] = { ASSOC_CHANNEL_ACCESS_FAILURE, ASSOC_NO_ACK };
    Test_BandA dev;
    Loopback_Outcome script[1];
    Mac_AssociateConfirmParameters confirm;
    Mac_AssociateRequestParameters req;
    uint32_t i;

    for (i = 0; i < 2; i++)
    {
        rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
        setChildExtended(&dev);

        Zb_memset(script, 0, (uint32_t)sizeof script);
        script[0].status = outcome[i];
        script[0].isAcked = 0;
        LoopbackRadio_ScriptOutcomes(&dev.model, script, 1);

        req = childRequest();
        Test_ExpectStatus(Mac_AssociateRequest(&dev.mac, &req, 0), ZB_OK, "the request goes out");
        Test_ExpectStatus(Mac_Step(&dev.mac, 1), ZB_OK, "and its completion is collected, unacknowledged");
        Test_ExpectCount(Mac_AssocStateOf(&dev.mac), MAC_ASSOC_FAILED, "so the exchange has failed");
        Test_Expect(Mac_PollAssociateConfirm(&dev.mac, &confirm) == 1 && confirm.status == expected[i],
                    i == 0 ? "with CHANNEL_ACCESS_FAILURE 0xe1: the channel was busy, and nothing was sent"
                           : "with NO_ACK 0xe9: the frame was sent and no acknowledgment came");
        Test_Expect(Mac_Pib(&dev.mac)->panId == ASSOC_UNASSOCIATED, "and macPanId back at 0xffff (10.21.2)");
    }
}

/* A transmit door with no room for the request -- band B's session still waiting on a reply -- is a wait: the request
   is held with the PIB written once, re-asked each step, and goes out as soon as the door takes it. */
void caseChildAssociationHeldWhileTheDoorIsFull(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Mac_AssociateRequestParameters req;
    uint32_t count = 0;
    Radio_Pib writes[LOOPBACK_PIB_WRITE_MAX];
    uint32_t writesBefore;

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&dev);
    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 3);
    writesBefore = LoopbackRadio_PibWrites(&dev.model, writes, LOOPBACK_PIB_WRITE_MAX);

    req = childRequest();
    Test_ExpectStatus(Mac_AssociateRequest(&dev.mac, &req, 0), ZB_OK, "the door has no room, and the request is held");
    Test_ExpectCount(Mac_AssocStateOf(&dev.mac), MAC_ASSOC_SENDING, "waiting for room");

    Test_ExpectStatus(Mac_Step(&dev.mac, 1), ZB_OK, "refused again");
    Test_ExpectStatus(Mac_Step(&dev.mac, 2), ZB_OK, "and once more");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, 0, "nothing on the air while the door refuses");

    Test_ExpectStatus(Mac_Step(&dev.mac, 3), ZB_OK, "the door takes it");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, 1, "one Association Request on the air");
    Test_Expect(count == 1 && air[0].ackRequest == 1, "asking to be acknowledged, as the request does (10.21.5.1)");
    Test_ExpectCount(LoopbackRadio_PibWrites(&dev.model, writes, LOOPBACK_PIB_WRITE_MAX) - writesBefore, 1,
                     "the PIB written once: no write-back between the refusals");

    Test_ExpectStatus(Mac_Step(&dev.mac, 4), ZB_OK, "the acknowledgment is collected");
    Test_ExpectCount(Mac_AssocStateOf(&dev.mac), MAC_ASSOC_WAITING, "and the exchange goes on as if never held");
}

/* A PIB write band B has no room for is a wait too: the request is held before anything is written, the write is
   asked again each step, and once it is taken the request goes out behind it. */
void caseChildAssociationHeldWhileThePibWriteIsRefused(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Mac_AssociateRequestParameters req;
    uint32_t count = 0;

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&dev);
    LoopbackRadio_RefusePibWrites(&dev.model, ZB_ERR_NO_SPACE, 1000);

    req = childRequest();
    Test_ExpectStatus(Mac_AssociateRequest(&dev.mac, &req, 0), ZB_OK, "the PIB write has no room, and the request is held");
    Test_ExpectCount(Mac_AssocStateOf(&dev.mac), MAC_ASSOC_SENDING, "waiting for room");
    Test_Expect(Mac_Pib(&dev.mac)->panId == ASSOC_UNASSOCIATED, "with the parent's PAN not yet written");

    Test_ExpectStatus(Mac_Step(&dev.mac, 1), ZB_OK, "the write is refused again");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, 0, "and nothing goes on the air ahead of it");

    LoopbackRadio_RefusePibWrites(&dev.model, ZB_OK, 0);
    Test_ExpectStatus(Mac_Step(&dev.mac, 2), ZB_OK, "band B has room again, and the write is taken");
    harvestAir(&dev.model, air, &count);
    Test_Expect(Mac_Pib(&dev.mac)->panId == PAN_ID, "the parent's PAN is written");
    Test_ExpectCount(count, 1, "and the Association Request goes out behind it");

    Test_ExpectStatus(Mac_Step(&dev.mac, 3), ZB_OK, "the acknowledgment is collected");
    Test_ExpectCount(Mac_AssocStateOf(&dev.mac), MAC_ASSOC_WAITING, "and the exchange goes on as if never held");
}

/* A write refused for longer than the hold ends as a request the door kept refusing: the exchange fails with
   TRANSACTION_OVERFLOW and nothing was sent. */
void caseChildAssociationPibWriteRefusedPastTheHold(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Mac_AssociateRequestParameters req;
    Mac_AssociateConfirmParameters confirm;
    uint32_t count = 0;

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&dev);
    LoopbackRadio_RefusePibWrites(&dev.model, ZB_ERR_NO_SPACE, 1000);

    req = childRequest();
    Test_ExpectStatus(Mac_AssociateRequest(&dev.mac, &req, 0), ZB_OK, "the request is held");
    Test_ExpectStatus(Mac_Step(&dev.mac, MAC_ASSOC_SEND_WAIT_MS / 2), ZB_OK, "still refused inside the hold");
    Test_ExpectCount(Mac_AssocStateOf(&dev.mac), MAC_ASSOC_SENDING, "and still held");
    Test_ExpectStatus(Mac_Step(&dev.mac, MAC_ASSOC_SEND_WAIT_MS + 1), ZB_OK, "refused past it");

    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, 0, "nothing was sent");
    Test_ExpectCount(Mac_AssocStateOf(&dev.mac), MAC_ASSOC_FAILED, "the exchange has failed");
    Test_Expect(Mac_PollAssociateConfirm(&dev.mac, &confirm) == 1 && confirm.status == 0xee,
                "with TRANSACTION_OVERFLOW 0xee, as for a transmit the door kept refusing");
}

/* 10.21.5.2's Short Address field: "If the coordinator was not able to associate the device to its PAN, the Short
   Address field shall be set to 0xffff", and Table 10-101 gives 0xffff no address of the PAN to be -- so a success
   that carries it is an association that did not happen. 0xfffe is the clause's other special case, "successfully
   associated with a PAN but has not been allocated a short address", and the MAC takes it: whether 0xfffe is a
   network address the layer above can use is that layer's question. */
void caseChildAssociationWithoutAnAddress(void)
{
    Test_BandA dev;
    Test_BandA other;
    Mac_AssociateConfirmParameters confirm;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&dev);
    startChildAssociation(&dev, air, &count);
    pollForDecision(&dev, air, &count);

    injectDecision(&dev, PARENT_EXTENDED, ASSOC_UNASSOCIATED, MAC_ASSOC_STATUS_SUCCESS, 200);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "a SUCCESS whose Short Address field is 0xffff arrives");

    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_FAILED,
                "and is the failure its field says it is, not a success (10.21.5.2)");
    Test_Expect(Mac_PollAssociateConfirm(&dev.mac, &confirm) == 1, "the confirm is handed up once");
    Test_Expect(confirm.status == ASSOC_NO_DATA,
                "with NO_DATA 0xeb (Table 78): an address was asked for and the answer names none");
    Test_Expect(confirm.shortAddress == ASSOC_UNASSOCIATED, "and 0xffff for the address (Table 10-107)");
    Test_Expect(Mac_Pib(&dev.mac)->shortAddress == ASSOC_UNASSOCIATED && Mac_Pib(&dev.mac)->panId == ASSOC_UNASSOCIATED,
                "with 10.21.2's failure path run: no PAN and no address stand at the PIB");

    /* 0xfffe is the clause's success without an allocation, and it is the MAC's to accept. */
    rig(&other, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&other);
    count = 0;
    startChildAssociation(&other, air, &count);
    pollForDecision(&other, air, &count);

    injectDecision(&other, PARENT_EXTENDED, 0xfffe, MAC_ASSOC_STATUS_SUCCESS, 200);
    Test_ExpectStatus(Mac_Step(&other.mac, 200), ZB_OK, "a SUCCESS whose Short Address field is 0xfffe arrives");

    Test_Expect(Mac_AssocStateOf(&other.mac) == MAC_ASSOC_DONE, "and the association succeeded (10.21.5.2)");
    Test_Expect(Mac_PollAssociateConfirm(&other.mac, &confirm) == 1, "the confirm is handed up once");
    Test_Expect(confirm.status == MAC_ASSOC_STATUS_SUCCESS && confirm.shortAddress == 0xfffe,
                "with SUCCESS and the address the answer named: 0xfffe is an association with no allocation, not a failure");
    Test_Expect(Mac_Pib(&other.mac)->shortAddress == 0xfffe,
                "which 10.21.2 stores in macShortAddress like any other successful value");
    Test_Expect(Mac_Pib(&other.mac)->panId == PAN_ID, "on the PAN that was joined");
}

/* 10.21.2's deadline and 10.21.5.2's answer can meet on one turn, and the answer is the outcome while the deadline
   is only the absence of one: a frame delivered on the very turn the window closes ends the exchange, and NO_DATA is
   what is left when no frame came (which the case above pins). */
void caseChildAssociationAnswerOnTheDeadline(void)
{
    Test_BandA dev;
    Mac_AssociateConfirmParameters confirm;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&dev);
    startChildAssociation(&dev, air, &count);
    pollForDecision(&dev, air, &count);

    injectDecision(&dev, PARENT_EXTENDED, CHILD_SHORT, MAC_ASSOC_STATUS_SUCCESS, 2 * MAC_RESPONSE_WAIT_MS);
    Test_ExpectStatus(Mac_Step(&dev.mac, 2 * MAC_RESPONSE_WAIT_MS), ZB_OK,
                      "the answer arrives on the turn the deadline would have closed (10.21.2)");

    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_DONE,
                "and the frame is read before the deadline fires, so the exchange is concluded and not timed out");
    Test_Expect(Mac_PollAssociateConfirm(&dev.mac, &confirm) == 1, "the confirm is handed up once");
    Test_Expect(confirm.status == MAC_ASSOC_STATUS_SUCCESS, "with the parent's SUCCESS (Table 10-102)");
    Test_Expect(confirm.shortAddress == CHILD_SHORT, "and the address it allocated");
    Test_Expect(Mac_Pib(&dev.mac)->shortAddress == CHILD_SHORT, "which 10.21.2 stores in macShortAddress");
    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_IDLE, "and the machine is idle again (10.21.6.1.5)");
}

/* 10.21.2's answer is the parent's: the request addressed one device, so an Association Response from another
   is a command this module heard and could not use. The exchange keeps waiting for the answer it asked for,
   and the answer that was not the parent's is counted as dropped. */
void caseChildAssociationIgnoresForeignAnswer(void)
{
    Test_BandA dev;
    Mac_AssociateConfirmParameters confirm;
    Air air[AIR_LOG_MAX];
    Mac_Counters counters;
    uint32_t count = 0;

    rig(&dev, ASSOC_UNASSOCIATED, ASSOC_UNASSOCIATED);
    setChildExtended(&dev);
    startChildAssociation(&dev, air, &count);
    pollForDecision(&dev, air, &count);

    injectDecision(&dev, FOREIGN_PARENT_EXTENDED, CHILD_SHORT, MAC_ASSOC_STATUS_SUCCESS, 600);
    Test_ExpectStatus(Mac_Step(&dev.mac, 600), ZB_OK, "an answer from a device that is not the parent arrives");

    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_POLLING,
                "and does not conclude the exchange: only the parent the request addressed answers it (10.21.5.2)");
    Test_Expect(Mac_PollAssociateConfirm(&dev.mac, &confirm) == 0, "so no confirm is handed up");
    counters = Mac_CountersOf(&dev.mac);

    Test_Expect(counters.assocDroppedMalformed + counters.assocDroppedNotOurs + counters.assocDroppedSource
                + counters.assocDroppedParent + counters.assocDroppedNotAsked + counters.assocDroppedAddress == 1,
                "and the answer is counted as one this device could not use, under the reason that refused it");

    injectDecision(&dev, PARENT_EXTENDED, CHILD_SHORT, MAC_ASSOC_STATUS_SUCCESS, 700);
    Test_ExpectStatus(Mac_Step(&dev.mac, 700), ZB_OK, "the parent's own answer arrives inside the window");

    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, 3,
                     "and the air holds the request and two Data Requests: a second poll inside the one window is what R23.1 3.6.1.6.1.2 permits");

    Test_Expect(Mac_PollAssociateConfirm(&dev.mac, &confirm) == 1, "and concludes the exchange");
    Test_Expect(confirm.status == MAC_ASSOC_STATUS_SUCCESS && confirm.shortAddress == CHILD_SHORT,
                "with the parent's success and the address it allocated");
    Test_Expect(Mac_Pib(&dev.mac)->shortAddress == CHILD_SHORT, "which 10.21.2 stores in macShortAddress");
    Test_Expect(Mac_AssocStateOf(&dev.mac) == MAC_ASSOC_IDLE, "and the machine is idle again");
}
