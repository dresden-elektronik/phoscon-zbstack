/* The parent's association doors: 10.21.5.1's request as an indication, 10.21.5.2's answer as the indirect
   transaction the child polls for, the response's status and address rules, and the shapes this device declines. */

#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "mac_helpers.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"

#define PARENT_EXTENDED (((uint64_t)0x08070605 << 32) | 0x04030201)
#define CHILD_EXTENDED (((uint64_t)0x11223344 << 32) | 0x55667788)

static const uint8_t parentExtended[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

static void setExtendedAddress(Test_BandA *dev)
{
    Radio_Pib pib;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_EXTENDED_ADDRESS;
    Zb_memcpy(pib.extendedAddress, parentExtended, RADIO_ADDR_LEN);

    Test_ExpectStatus(Mac_SetPib(&dev->mac, &pib), ZB_OK,
                      "the coordinator's own extended address is set through the seam");
}

/* A parent is what the beacon surface says it is: D.11.1.5's coordinator or router and 10.21.2's
   macAssociationPermit. The association door consults both, so a case that wants one configures them. */
static void configureParent(Test_BandA *dev, int withExtended, int panCoordinator, int associationPermit)
{
    Mac_BeaconConfig beacon;

    if (withExtended)
        setExtendedAddress(dev);

    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.answer = 1;
    beacon.panCoordinator = panCoordinator;
    beacon.associationPermit = associationPermit;

    Test_ExpectStatus(Mac_SetBeaconConfig(&dev->mac, &beacon), ZB_OK,
                      "the device is configured as a parent with the permit the case names");
}

static void injectAssociationRequest(Test_BandA *dev, uint8_t dsn, uint8_t capability)
{
    uint8_t frame[64];
    uint32_t len;

    len = composeAssociationRequest(frame, dsn, CHILD_EXTENDED, capability);
    injectFrame(&dev->model, frame, len, 1000);
}

static void injectAssociationRequestToPan(Test_BandA *dev, uint8_t dsn, uint8_t capability)
{
    uint8_t frame[64];
    uint32_t len;

    len = composeAssociationRequestToPan(frame, dsn, CHILD_EXTENDED, capability);
    injectFrame(&dev->model, frame, len, 1000);
}

/* 10.21.5.1's request is the parent's event: the child's extended address, the PAN it named and the
   Capability Information field, and not a data frame the layer above would read as an NPDU. */
void caseAssociationRequestIsIndicated(void)
{
    Test_BandA dev;
    Mac_AssociationIndication indication;
    uint32_t got;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 1, 1, 1);

    injectAssociationRequest(&dev, 0x11, 0x8e);

    Test_ExpectStatus(Mac_Step(&dev.mac, 1000), ZB_OK, "the Association Request is delivered");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.associationQueue == 1,
                "the request is the parent's event, not a data frame");
    Test_Expect(counters.indicationQueue == 0,
                "and it is not in the data indication queue");
    Test_Expect(counters.commandsHeard == 0,
                "nor counted as a command this module could not act on");

    got = Mac_PollAssociations(&dev.mac, &indication, 1);

    Test_Expect(got == 1, "the layer above takes the indication");
    Test_Expect(indication.extendedAddress == CHILD_EXTENDED, "with the child's extended address");
    Test_Expect(indication.destPan == PAN_ID, "the PAN the request named");
    Test_Expect(indication.capability.deviceType == 1 && indication.capability.powerSource == 1
                && indication.capability.rxOnWhenIdle == 1 && indication.capability.allocateAddress == 1,
                "and the capability bits: FFD, mains, receiver on, allocate");
    Test_Expect(indication.capability.associationType == 0 && indication.capability.suspendableCsmaCa == 0
                && indication.capability.securityCapability == 0,
                "with the three bits this stack never sets clear");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.associationQueue == 0, "and the ring is empty again");
}

/* The answer is a transaction, not a transmit: 10.21.2 makes the Association Response indirect, so it goes on
   the air only when the child's Data Request extracts it, and then as 10.21.5.2's shape. */
void caseAssociationResponseIsIndirect(void)
{
    Test_BandA dev;
    Mac_AssociationIndication indication;
    Mac_AssociationResponse response;
    Loopback_Sent sent[2];
    Mac_Frame frame;
    const uint8_t *payload = 0;
    uint32_t payloadLen = 0;
    uint8_t poll[64];
    uint32_t pollLen;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 1, 1, 1);

    injectAssociationRequest(&dev, 0x11, 0x8e);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1000), ZB_OK, "the request arrives");
    Test_Expect(Mac_PollAssociations(&dev.mac, &indication, 1) == 1, "and is taken");

    Zb_memset(&response, 0, (uint32_t)sizeof response);
    response.request = indication;
    response.shortAddress = 0x1234;
    response.status = MAC_ASSOC_STATUS_SUCCESS;

    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 1100), ZB_OK,
                      "10.21.5.2's answer is queued");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 1, "as an indirect transaction");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 2) == 0,
                "and nothing goes on the air until the child asks (10.21.2)");

    pollLen = composePollExtended(poll, 0x22, CHILD_EXTENDED);
    injectFrame(&dev.model, poll, pollLen, 1200);

    Test_ExpectStatus(Mac_Step(&dev.mac, 1200), ZB_OK, "the child polls");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 1,
                "the transaction is still held while its answer is on the way (6.6.3.4)");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 2) == 1, "and exactly one frame went out");

    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &frame, &payload, &payloadLen, 0), ZB_OK,
                      "the answer parses");
    Test_Expect(frame.frameType == MAC_FRAME_TYPE_COMMAND && frame.ackRequest == 1,
                "a command frame that asks for an acknowledgment");
    Test_Expect(frame.framePending == 0, "and Frame Pending zero, which 10.21.5.2 pins");
    Test_Expect(frame.panIdCompression == 1, "with one PAN field, both addresses present (7.2.2.6)");
    Test_Expect(frame.destAddrMode == MAC_ADDR_EXTENDED && frame.srcAddrMode == MAC_ADDR_EXTENDED,
                "extended addressing at both ends (10.21.5.2)");
    Test_Expect(frame.destExtended == CHILD_EXTENDED && frame.srcExtended == PARENT_EXTENDED,
                "the child's address and the coordinator's own");
    Test_Expect(payloadLen == 4 && payload[0] == MAC_CMD_ASSOCIATION_RESPONSE
                && payload[1] == 0x34 && payload[2] == 0x12 && payload[3] == MAC_ASSOC_STATUS_SUCCESS,
                "and the content: the short address least significant first, then the status");
    Test_Expect(sent[0].ackRequest == 1, "the seam was asked for the acknowledgment the clause requires");

    Test_ExpectStatus(Mac_Step(&dev.mac, 1300), ZB_OK, "the acknowledgment is collected");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 0,
                "and the acknowledged transaction is discarded (10.22.2)");
}

/* 10.21.5.2 pins the response's Frame Pending to zero even when the child has another transaction waiting;
   a response that carried the poll's queue state would be a frame the clause forbids. */
void caseAssociationResponsePinsPending(void)
{
    Test_BandA dev;
    Mac_AssociationIndication indication;
    Mac_AssociationResponse response;
    Mac_DataRequestParameters req;
    Loopback_Sent sent[2];
    Mac_Frame frame;
    const uint8_t *payloadOut = 0;
    uint32_t payloadLen = 0;
    uint8_t poll[64];
    uint32_t pollLen;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 1, 1, 1);

    injectAssociationRequest(&dev, 0x11, 0x8e);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1000), ZB_OK, "the request arrives");
    Test_Expect(Mac_PollAssociations(&dev.mac, &indication, 1) == 1, "and is taken");

    Zb_memset(&response, 0, (uint32_t)sizeof response);
    response.request = indication;
    response.shortAddress = 0x1234;
    response.status = MAC_ASSOC_STATUS_SUCCESS;
    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 1100), ZB_OK, "the answer is queued");

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.frameType = MAC_FRAME_TYPE_DATA;
    req.destAddrMode = MAC_ADDR_EXTENDED;
    req.srcAddrMode = MAC_ADDR_SHORT;
    req.destPan = PAN_ID;
    req.destExtended = CHILD_EXTENDED;
    req.ackRequest = 1;
    req.payload = payload;
    req.payloadLen = PAYLOAD_LEN;
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 1150), ZB_OK,
                      "a second transaction for the same child is queued");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 2, "so two are held");

    pollLen = composePollExtended(poll, 0x23, CHILD_EXTENDED);
    injectFrame(&dev.model, poll, pollLen, 1200);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1200), ZB_OK, "the child polls");

    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 2) == 1, "the oldest transaction is extracted");
    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &frame, &payloadOut, &payloadLen, 0), ZB_OK,
                      "the answer parses");

    Test_Expect(frame.framePending == 0,
                "Frame Pending is zero on the Association Response even though a second transaction for the child remains (10.21.5.2)");
    Test_Expect(payloadLen == 4 && payloadOut[0] == MAC_CMD_ASSOCIATION_RESPONSE,
                "and it is the association answer that went out");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 2,
                "while both transactions are still held, the answer awaiting its acknowledgment");
}

/* The answer's status and short address are held to Table 10-102 and to 10.21.2's Allocate Address rule. */
void caseAssociationResponseRefuses(void)
{
    Test_BandA dev;
    Test_BandA other;
    Mac_AssociationIndication indication;
    Mac_AssociationResponse response;
    Mac_Counters devCounters;
    Mac_Counters otherCounters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 1, 1, 1);

    injectAssociationRequest(&dev, 0x11, 0x8e);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1000), ZB_OK, "the request arrives");
    Test_Expect(Mac_PollAssociations(&dev.mac, &indication, 1) == 1, "and is taken");

    Zb_memset(&response, 0, (uint32_t)sizeof response);
    response.request = indication;
    response.shortAddress = 0x1234;
    response.status = 0x05;

    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 1100), ZB_ERR_BAD_ARGUMENT,
                      "a reserved Association Status is refused (Table 10-102)");
    devCounters = Mac_CountersOf(&dev.mac);
    Test_Expect(devCounters.transactionQueue == 0, "and nothing was queued");

    response.status = MAC_ASSOC_STATUS_SUCCESS;
    response.shortAddress = 0xffff;
    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 1100), ZB_ERR_BAD_ARGUMENT,
                      "a success cannot carry the failure address 0xffff (10.21.5.2)");

    response.status = MAC_ASSOC_STATUS_PAN_AT_CAPACITY;
    response.shortAddress = 0x1234;
    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 1100), ZB_ERR_BAD_ARGUMENT,
                      "a failure must carry 0xffff (10.21.5.2)");

    response.status = MAC_ASSOC_STATUS_SUCCESS;
    response.shortAddress = 0x1234;
    response.request.capability.allocateAddress = 0;
    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 1100), ZB_ERR_BAD_ARGUMENT,
                      "a child that asked for no address must be given 0xfffe (10.21.2)");

    response.shortAddress = 0xfffe;
    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 1100), ZB_OK,
                      "and 0xfffe is the success the clause names");
    devCounters = Mac_CountersOf(&dev.mac);
    Test_Expect(devCounters.transactionQueue == 1, "one transaction is held");

    response.status = MAC_ASSOC_STATUS_PAN_AT_CAPACITY;
    response.shortAddress = 0xffff;
    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 1100), ZB_OK,
                      "and a failure with 0xffff is the other valid answer");
    devCounters = Mac_CountersOf(&dev.mac);
    Test_Expect(devCounters.transactionQueue == 2, "two transactions are held");

    response.request.extendedAddress = 0;
    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 1100), ZB_ERR_BAD_ARGUMENT,
                      "no child address is no device to answer");
    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, 0, 1100), ZB_ERR_BAD_ARGUMENT,
                      "and no response at all is a bad argument");

    rig(&other, COORDINATOR_SHORT, PAN_ID);
    setExtendedAddress(&other);

    Zb_memset(&response, 0, (uint32_t)sizeof response);
    response.request = indication;
    response.shortAddress = 0x1234;
    response.status = MAC_ASSOC_STATUS_SUCCESS;

    Test_ExpectStatus(Mac_AssociateResponse(&other.mac, &response, 1100), ZB_ERR_NOT_READY,
                      "a device that is not a parent sends no Association Response (10.21.5.2)");
    otherCounters = Mac_CountersOf(&other.mac);
    Test_Expect(otherCounters.transactionQueue == 0, "and queues nothing");
}

/* The shapes that are not this device's request: another destination, a short source, a content field that is
   not the one octet, the request the ring has no room for, a parent whose macAssociationPermit is FALSE -- which
   the MAC still indicates, because R23.1 3.6.1.6.1.3 makes 0x02 PAN_ACCESS_DENIED the answer and an answer is
   composed above this module -- and a device that is no parent at all, which consumes the command. */
void caseAssociationRequestIsDeclined(void)
{
    Test_BandA dev;
    Test_BandA other;
    Test_BandA endDevice;
    Mac_BeaconConfig noBeacon;
    Mac_Frame frame;
    uint8_t bytes[64];
    uint8_t content[3];
    uint32_t len;
    uint32_t i;
    Mac_Counters devCounters;
    Mac_Counters otherCounters;
    Mac_Counters endDeviceCounters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 1, 1, 1);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.destPan = PAN_ID;
    frame.destShort = 0x2222;
    frame.srcPan = MAC_FRAME_PAN_BROADCAST;
    frame.srcExtended = CHILD_EXTENDED;
    frame.seq = 0x33;

    content[0] = MAC_CMD_ASSOCIATION_REQUEST;
    content[1] = 0x8e;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, 2, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                      "a request addressed to another device composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, (uint32_t)sizeof bytes, &len), ZB_OK, "with its footer");
    injectFrame(&dev.model, bytes, len, 1000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1000), ZB_OK, "and arrives");

    devCounters = Mac_CountersOf(&dev.mac);
    Test_Expect(devCounters.associationQueue == 0, "another device's request is not this device's");
    Test_Expect(devCounters.destinationMismatches == 1 && devCounters.commandsHeard == 0,
                "and 6.6.2 d) refuses it before any command branch reads it: counted as that refusal, not as a command");

    /* 10.21.5.1 fixes the source addressing mode to extended. */
    frame.destShort = COORDINATOR_SHORT;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.srcShort = 0x1234;
    frame.panIdCompression = 1;
    frame.srcPan = PAN_ID;
    Test_ExpectStatus(MacFrame_Compose(&frame, content, 2, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                      "a request with a short source composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, (uint32_t)sizeof bytes, &len), ZB_OK, "with its footer");
    injectFrame(&dev.model, bytes, len, 1001);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1001), ZB_OK, "and arrives");

    devCounters = Mac_CountersOf(&dev.mac);
    Test_Expect(devCounters.associationQueue == 0, "a short source is not the frame the clause prints");
    Test_Expect(devCounters.commandsHeard == 1, "and is counted");

    /* The content field is the one capability octet: a second one is not a request this stack reads. */
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.srcExtended = CHILD_EXTENDED;
    frame.panIdCompression = 0;
    frame.srcPan = MAC_FRAME_PAN_BROADCAST;
    Test_ExpectStatus(MacFrame_Compose(&frame, content, 3, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                      "a request with a second content octet composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, (uint32_t)sizeof bytes, &len), ZB_OK, "with its footer");
    injectFrame(&dev.model, bytes, len, 1002);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1002), ZB_OK, "and arrives");

    devCounters = Mac_CountersOf(&dev.mac);
    Test_Expect(devCounters.associationQueue == 0, "a two-octet content is not the association request");
    Test_Expect(devCounters.commandsHeard == 2, "and is counted");

    /* 10.21.4: fast association asks for a direct response this stack does not implement. */
    injectAssociationRequest(&dev, 0x44, 0x90);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1003), ZB_OK, "a fast-association request arrives");

    devCounters = Mac_CountersOf(&dev.mac);
    Test_Expect(devCounters.associationQueue == 0, "and is declined, because the answer would have to be direct");
    Test_Expect(devCounters.commandsHeard == 3, "counted as a command consumed");
    Test_ExpectCount(devCounters.assocRequestDroppedFast, 1,
                     "and counted under 10.21.4's reason, apart from a command that was somebody else's");

    /* 6.6.2 c): the destination PAN is this device's own or the broadcast one. */
    frame.destPan = 0x1234;
    frame.destShort = COORDINATOR_SHORT;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.srcExtended = CHILD_EXTENDED;
    frame.panIdCompression = 0;
    frame.srcPan = MAC_FRAME_PAN_BROADCAST;
    Test_ExpectStatus(MacFrame_Compose(&frame, content, 2, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                      "a request naming another PAN composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, (uint32_t)sizeof bytes, &len), ZB_OK, "with its footer");
    injectFrame(&dev.model, bytes, len, 1004);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1004), ZB_OK, "and arrives");

    devCounters = Mac_CountersOf(&dev.mac);
    Test_Expect(devCounters.associationQueue == 0, "a foreign destination PAN is filtered out (6.6.2 c)");
    Test_Expect(devCounters.panMismatches == 1 && devCounters.commandsHeard == 3,
                "and counted under the clause that refused it, where no command branch can reach it");

    /* The ring's own bound: eight requests are held, the ninth is dropped and counted. */
    for (i = 0; i < MAC_ASSOCIATION_MAX + 1; i++)
        injectAssociationRequest(&dev, (uint8_t)(0x40 + i), 0x8e);

    for (i = 0; i < 3; i++)
        Test_ExpectStatus(Mac_Step(&dev.mac, 1100 + i), ZB_OK, "the requests are delivered");

    devCounters = Mac_CountersOf(&dev.mac);
    Test_Expect(devCounters.associationQueue == MAC_ASSOCIATION_MAX, "the ring holds its bound");
    Test_Expect(devCounters.associationsDropped == 1, "and the ninth request is refused and counted");

    /* R23.1 3.6.1.6.1.3: "If the parent receives a MLME-ASSOCIATE.indication primitive and the MAC PIB attribute
       macAssociationPermit is FALSE it SHALL issue MLME-ASSOCIATE.response with a status of 0x02,
       PAN_ACCESS_DENIED." The answer can only be composed above this module, so the MAC's half is the indication:
       10.21.2's "the command shall be ignored" is the base default the profile replaces. */
    rig(&other, COORDINATOR_SHORT, PAN_ID);
    configureParent(&other, 1, 1, 0);
    injectAssociationRequest(&other, 0x55, 0x8e);
    Test_ExpectStatus(Mac_Step(&other.mac, 1200), ZB_OK, "the request arrives at a parent whose permit is off");

    otherCounters = Mac_CountersOf(&other.mac);
    Test_Expect(otherCounters.associationQueue == 1,
                "and is still the layer above's decision, so it is indicated (R23.1 3.6.1.6.1.3)");
    Test_Expect(otherCounters.commandsHeard == 0,
                "not consumed as a command this device can do nothing with");
    Test_Expect(otherCounters.transactionQueue == 0,
                "and the MAC queues no answer of its own: the 0x02 PAN_ACCESS_DENIED is the parent's to make");
    Test_Expect(otherCounters.associationsDropped == 0, "not as a full ring");

    /* D.11.1.5: only a Zigbee coordinator or a router is a parent, and a device that answers no beacon is neither;
       the same request reaching it is a command it heard and consumed. */
    rig(&endDevice, COORDINATOR_SHORT, PAN_ID);
    setExtendedAddress(&endDevice);

    Zb_memset(&noBeacon, 0, (uint32_t)sizeof noBeacon);
    Test_ExpectStatus(Mac_SetBeaconConfig(&endDevice.mac, &noBeacon), ZB_OK,
                      "a device with no beacon to answer and no permit to advertise");

    injectAssociationRequest(&endDevice, 0x56, 0x8e);
    Test_ExpectStatus(Mac_Step(&endDevice.mac, 1300), ZB_OK, "the same request arrives at that device");

    endDeviceCounters = Mac_CountersOf(&endDevice.mac);
    Test_Expect(endDeviceCounters.associationQueue == 0, "which has no association to offer, so nothing is indicated");
    Test_Expect(endDeviceCounters.commandsHeard == 1, "and the command is counted as consumed");
}

/* R23.1 Annex D.4: a frame whose destination is the PAN coordinator may omit the destination fields. */
void caseAssociationRequestDestinationless(void)
{
    Test_BandA dev;
    Test_BandA router;
    Mac_Frame frame;
    Mac_AssociationIndication indication;
    Mac_Counters devCounters;
    Mac_Counters routerCounters;
    uint8_t content[2] = { MAC_CMD_ASSOCIATION_REQUEST, 0x8e };
    uint8_t bytes[64];
    uint32_t len;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 1, 1, 1);

    injectAssociationRequestToPan(&dev, 0x11, 0x8e);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1000), ZB_OK, "the destination-less request arrives");

    devCounters = Mac_CountersOf(&dev.mac);
    Test_Expect(devCounters.associationQueue == 1, "and the PAN coordinator takes it (R23.1 Annex D.4)");
    Test_Expect(Mac_PollAssociations(&dev.mac, &indication, 1) == 1, "the indication is taken");
    Test_Expect(indication.extendedAddress == CHILD_EXTENDED, "with the child's extended address");
    Test_Expect(indication.destPan == 0, "and no destination PAN, because the frame named none");

    /* R23.1 Annex D.4's other source-PAN form: the destination's own PAN rather than the broadcast one. */
    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 0;
    frame.destAddrMode = MAC_ADDR_NONE;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.srcPan = PAN_ID;
    frame.srcExtended = CHILD_EXTENDED ^ 1;
    frame.seq = 0x13;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, 2, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                      "the same destination-less request with the destination's own source PAN composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, (uint32_t)sizeof bytes, &len), ZB_OK, "with its footer");
    injectFrame(&dev.model, bytes, len, 1001);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1001), ZB_OK, "and arrives");

    devCounters = Mac_CountersOf(&dev.mac);
    Test_Expect(devCounters.associationQueue == 1 && devCounters.destinationMismatches == 0,
                "the PAN coordinator takes it too: 6.6.2 d)4's source PAN is macPanId here");

    rig(&router, COORDINATOR_SHORT, PAN_ID);
    configureParent(&router, 1, 0, 1);

    injectAssociationRequestToPan(&router, 0x12, 0x8e);
    Test_ExpectStatus(Mac_Step(&router.mac, 1000), ZB_OK, "the same frame arrives at a router");

    routerCounters = Mac_CountersOf(&router.mac);
    Test_Expect(routerCounters.associationQueue == 0, "which is not the destination R23.1 Annex D.4 names");
    Test_Expect(routerCounters.destinationMismatches == 1 && routerCounters.commandsHeard == 0,
                "and 6.6.2 d)4 refuses it before any command branch reads it: counted as that refusal");
}

/* 6.6.2: a frame whose footer is wrong is discarded at the MAC. The Association Request is the frame that makes
   it visible, because a delivered one would be the parent's event: nothing here is delivered instead. */
void caseAssociationRequestBadFcs(void)
{
    Test_BandA dev;
    Mac_DataIndicationParameters indications[2];
    uint8_t frame[64];
    uint32_t len;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 1, 1, 1);

    len = composeAssociationRequest(frame, 0x11, CHILD_EXTENDED, 0x8e);
    frame[len - 1] ^= 0xff;
    injectFrame(&dev.model, frame, len, 1000);

    Test_ExpectStatus(Mac_Step(&dev.mac, 1000), ZB_OK, "a request whose footer is wrong arrives");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.associationQueue == 0, "and is not the parent's event (6.6.2)");
    Test_Expect(counters.commandsHeard == 0, "nor a command acted on");
    Test_ExpectCount(counters.fcsFailures, 1, "it is counted under the reason that refused it (6.6.2, 7.2.11)");
    Test_ExpectCount(counters.indicationQueue, 0, "and reaches no ring: the MAC discards what the footer refuses");
    Test_ExpectCount(Mac_PollIndications(&dev.mac, indications, 2), 0, "so nothing of its PSDU reaches a caller");
}

/* 6.6.2 d) and 10.21.5.1: a destination-less request's Source PAN is this device's own or the broadcast one. */
void caseAssociationRequestForeignSourcePan(void)
{
    Test_BandA dev;
    Mac_Frame frame;
    uint8_t content[2] = { MAC_CMD_ASSOCIATION_REQUEST, 0x8e };
    uint8_t bytes[64];
    uint32_t len;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 1, 1, 1);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 0;
    frame.destAddrMode = MAC_ADDR_NONE;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.srcPan = 0x1234;
    frame.srcExtended = CHILD_EXTENDED;
    frame.seq = 0x13;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, 2, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                      "a destination-less request naming a third PAN composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, (uint32_t)sizeof bytes, &len), ZB_OK, "with its footer");
    injectFrame(&dev.model, bytes, len, 1000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1000), ZB_OK, "and arrives");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.associationQueue == 0,
                "the source PAN is neither this device's nor the broadcast one (6.6.2 d, 10.21.5.1)");
    Test_Expect(counters.destinationMismatches == 1 && counters.commandsHeard == 0,
                "and 6.6.2 d)4 refuses it before the association gate reads it: counted as that refusal");
}

/* 10.21.5.1 on the addressed form: "If the Version field is set to 0b10, the Source PAN ID field is omitted.
   Otherwise, the Source PAN ID field shall contain the broadcast PAN ID." A request whose destination is this
   device and whose Source PAN ID is a third PAN is therefore not the command the clause prints, even though the
   destination names this device: it is a command heard and consumed, and no association is queued for it. */
void caseAssociationRequestAddressedForeignSourcePan(void)
{
    Test_BandA dev;
    Mac_Frame frame;
    uint8_t content[2] = { MAC_CMD_ASSOCIATION_REQUEST, 0x8e };
    uint8_t bytes[64];
    uint32_t len;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 1, 1, 1);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 0;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.destPan = PAN_ID;
    frame.destShort = COORDINATOR_SHORT;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.srcPan = 0x1234;
    frame.srcExtended = CHILD_EXTENDED;
    frame.seq = 0x14;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, 2, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                      "a request addressed to this device with a third PAN at its source composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, (uint32_t)sizeof bytes, &len), ZB_OK, "with its footer");
    injectFrame(&dev.model, bytes, len, 1000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1000), ZB_OK, "and arrives");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.associationQueue == 0,
                "a third PAN is none of the options R23.1 Annex D.4's request table prints, so the request is refused");
    Test_Expect(counters.sourcePanMismatches == 1, "counted under the clause that refused it, and no other");
    Test_Expect(counters.commandsHeard == 0 && counters.indicationQueue == 0,
                "so it is neither a command consumed nor an NPDU handed upward");
}

/* R23.1 Annex D.4's other two source-PAN options, at an addressed request: the destination device's PAN written
   out, and the same PAN compressed away. 10.21.5.1's broadcast PAN is the form this stack sends, and the three are
   what a device "SHALL ... recognize", so all three are this device's request. */
void caseAssociationRequestDestinationPanSource(void)
{
    Test_BandA dev;
    Mac_Frame frame;
    Mac_AssociationIndication indication;
    uint8_t content[2] = { MAC_CMD_ASSOCIATION_REQUEST, 0x8e };
    uint8_t bytes[64];
    uint32_t len;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 1, 1, 1);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 0;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.destPan = PAN_ID;
    frame.destShort = COORDINATOR_SHORT;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.srcPan = PAN_ID;
    frame.srcExtended = CHILD_EXTENDED;
    frame.seq = 0x15;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, 2, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                      "an addressed request naming the destination's own PAN composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, (uint32_t)sizeof bytes, &len), ZB_OK, "with its footer");
    injectFrame(&dev.model, bytes, len, 1000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1000), ZB_OK, "and arrives");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.associationQueue == 1 && counters.sourcePanMismatches == 0 && counters.commandsHeard == 0,
                "D.4's third option is recognized: the request is queued, not consumed as a command");
    Test_Expect(Mac_PollAssociations(&dev.mac, &indication, 1) == 1 && indication.extendedAddress == CHILD_EXTENDED,
                "with the child's extended address, as the other two forms are taken");

    frame.panIdCompression = 1;
    frame.srcExtended = CHILD_EXTENDED ^ 1;
    frame.seq = 0x16;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, 2, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                      "the compressed form composes, its source PAN omitted because IntraPAN is set");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, (uint32_t)sizeof bytes, &len), ZB_OK, "with its footer");
    injectFrame(&dev.model, bytes, len, 1001);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1001), ZB_OK, "and arrives");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.associationQueue == 1 && counters.sourcePanMismatches == 0,
                "and it is the same request: the fourth source PAN is the only form refused");
}

/* The answer needs the parent's own extended address: 10.21.5.2 gives the response no other source. */
void caseAssociationResponseNeedsAnExtendedSource(void)
{
    Test_BandA dev;
    Mac_AssociationIndication request;
    Mac_AssociationResponse response;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 0, 1, 1);

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    request.extendedAddress = CHILD_EXTENDED;
    request.capability.allocateAddress = 1;

    Zb_memset(&response, 0, (uint32_t)sizeof response);
    response.request = request;
    response.shortAddress = 0x1234;
    response.status = MAC_ASSOC_STATUS_SUCCESS;

    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 100), ZB_ERR_NOT_READY,
                      "a coordinator with no extended address cannot be the source the clause requires");
    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.transactionQueue == 0, "nothing was queued");
}

/* 10.21.5.1's content is the one capability octet: the transmit door refuses the shapes this module's own
   receiver would decline, and composes the right one with the source PAN the clause names. */
void caseAssociationRequestContentLength(void)
{
    Test_BandA dev;
    Mac_DataRequestParameters req;
    Loopback_Sent sent[2];
    Mac_Frame frame;
    const uint8_t *payload = 0;
    uint32_t payloadLen = 0;
    uint8_t content[3] = { MAC_CMD_ASSOCIATION_REQUEST, 0x8e, 0x00 };
    uint8_t response[4];

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    setExtendedAddress(&dev);

    req = dataReq(MAC_FRAME_TYPE_COMMAND, MAC_ADDR_SHORT, PAN_ID, COORDINATOR_SHORT, MAC_ADDR_EXTENDED, 1);
    req.payload = content;
    req.payloadLen = 3;

    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 100, 0), ZB_ERR_BAD_ARGUMENT,
                      "a two-octet content is not the Association Request (10.21.5.1)");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 2) == 0, "and nothing went out");

    /* 10.21.4: the fast-association bit asks for a direct response this stack does not implement, and the
       codec refuses the octet; the transmit door refuses it too, so a caller cannot compose it around the
       codec. */
    content[1] = 0x90;
    req.payloadLen = 2;
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 101, 0), ZB_ERR_UNSUPPORTED,
                      "a capability octet with the fast-association bit is refused before it reaches the air");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 2) == 0, "and nothing went out");
    content[1] = 0x8e;

    req.payloadLen = 2;
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 100, 0), ZB_OK, "the one-octet content composes");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 2) == 1, "and goes out");

    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &frame, &payload, &payloadLen, 0), ZB_OK,
                      "the request parses");
    Test_Expect(frame.frameType == MAC_FRAME_TYPE_COMMAND && frame.framePending == 0,
                "a command frame with Frame Pending zero");
    Test_Expect(frame.srcAddrMode == MAC_ADDR_EXTENDED && frame.srcExtended == PARENT_EXTENDED,
                "the source is this device's extended address (10.21.5.1)");
    Test_Expect(frame.panIdCompression == 0 && frame.srcPan == MAC_FRAME_PAN_BROADCAST,
                "and the source PAN is the broadcast PAN, which forbids compression (10.21.5.1, 7.2.2.6)");
    Test_Expect(frame.destPan == PAN_ID && frame.destShort == COORDINATOR_SHORT,
                "while the destination is the PAN and address the request named");
    Test_Expect(payloadLen == 2 && payload[0] == MAC_CMD_ASSOCIATION_REQUEST && payload[1] == 0x8e,
                "with the command and its capability octet");

    /* 10.21.2: the Association Response is indirect, and 10.21.5.2 gives it three content octets. */
    response[0] = MAC_CMD_ASSOCIATION_RESPONSE;
    response[1] = 0x34;
    response[2] = 0x12;
    response[3] = 0x00;
    req.payload = response;
    req.payloadLen = 4;
    req.destAddrMode = MAC_ADDR_EXTENDED;
    req.destExtended = CHILD_EXTENDED;

    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 200, 0), ZB_ERR_UNSUPPORTED,
                      "the Association Response is an indirect transaction, never a direct transmit (10.21.2)");

    /* The generic queue door refuses the Association Response whatever its shape: only Mac_AssociateResponse
       carries the status and short-address judgement 10.21.5.2 needs. */
    req = indirectReq(MAC_FRAME_TYPE_COMMAND, MAC_ADDR_SHORT, PAN_ID, COORDINATOR_SHORT, response, 4);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 210), ZB_ERR_UNSUPPORTED,
                      "a short-addressed Association Response is refused by the generic queue door");

    req.destAddrMode = MAC_ADDR_EXTENDED;
    req.destExtended = CHILD_EXTENDED;
    req.srcAddrMode = MAC_ADDR_EXTENDED;
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 220), ZB_ERR_UNSUPPORTED,
                      "and so is the extended form: only Mac_AssociateResponse queues the answer (10.21.5.2)");

    req.payloadLen = 2;
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 200, 0), ZB_ERR_BAD_ARGUMENT,
                      "and a response short of its three content octets is not one (10.21.5.2)");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 2) == 1, "so only the request went out");
}

/* 6.6.2 d)4: only the PAN coordinator is the destination of a frame that names no destination. A router that
   answered such a poll would put a frame on the air the asking device aimed at another device. */
void caseDestinationlessPollNeedsPanCoordinator(void)
{
    Test_BandA dev;
    Test_BandA router;
    Loopback_Sent sent[2];
    uint8_t frame[64];
    uint32_t len;
    Mac_Counters devCounters;
    Mac_Counters routerCounters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 1, 1, 1);

    len = composePollToPan(frame, 0x20, CHILD_EXTENDED);
    injectFrame(&dev.model, frame, len, 5000);
    Test_ExpectStatus(Mac_Step(&dev.mac, 200), ZB_OK, "a destination-less poll arrives at the PAN coordinator");

    devCounters = Mac_CountersOf(&dev.mac);
    Test_Expect(devCounters.pollArrivalQueue == 1, "and is the coordinator's poll (6.6.2 d)4, 10.22.5.2)");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 2) == 1, "which answers it");

    rig(&router, COORDINATOR_SHORT, PAN_ID);
    configureParent(&router, 1, 0, 1);

    len = composePollToPan(frame, 0x21, CHILD_EXTENDED);
    injectFrame(&router.model, frame, len, 5000);
    Test_ExpectStatus(Mac_Step(&router.mac, 200), ZB_OK, "the same destination-less poll arrives at a router");

    routerCounters = Mac_CountersOf(&router.mac);
    Test_Expect(routerCounters.pollArrivalQueue == 0, "which is not the destination 6.6.2 d)4 names");
    Test_Expect(LoopbackRadio_Sent(&router.model, sent, 2) == 0, "and nothing is answered");
}

/* 6.2 and 6.6.3.1: the 64-bit broadcast address is a broadcast, so no other-than-DATA frame may ask for its
   acknowledgment and the Association Response to it asks one by construction. */
void caseAssociationResponseBroadcastRefused(void)
{
    Test_BandA dev;
    Mac_AssociationResponse response;
    Mac_DataRequestParameters req;
    Loopback_Sent sent[2];

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 1, 1, 1);

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_EXTENDED, PAN_ID, 0, 0, 0);
    req.destExtended = 0xffffffffffffffff;
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_ERR_UNSUPPORTED,
                      "a transaction for the 64-bit broadcast address is refused (6.2, 6.6.3.1)");

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_EXTENDED, PAN_ID, 0, MAC_ADDR_SHORT, 1);
    req.destExtended = 0xffffffffffffffff;
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 110, 0), ZB_OK,
                      "a direct frame to the 64-bit broadcast address goes out, its ask cleared (6.6.3.1)");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 2) == 1, "and goes out");
    Test_Expect(sent[0].ackRequest == 0, "asking nothing, as a broadcast must");

    req.ackRequest = 0;
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 120, 0), ZB_OK,
                      "and the same frame asking none composes the same way");

    Zb_memset(&response, 0, (uint32_t)sizeof response);
    response.request.extendedAddress = 0xffffffffffffffff;
    response.request.capability.allocateAddress = 1;
    response.shortAddress = 0x1234;
    response.status = MAC_ASSOC_STATUS_SUCCESS;
    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 130), ZB_ERR_UNSUPPORTED,
                      "and the Association Response to it cannot be queued, because 10.21.5.2's answer asks an acknowledgment");
}

/* 6.2 and a measured RCP's own report: eight zero octets are what a part with no extended
   address reports, not an address, so a destination or a source that holds them is no device. */
void caseExtendedAddressZeroIsNoAddress(void)
{
    Test_BandA dev;
    Mac_AssociationIndication indication;
    Mac_AssociationResponse response;
    Mac_DataRequestParameters req;
    Radio_Pib pib;
    Mac_Frame frame;
    uint8_t bytes[64];
    uint8_t content[2] = { MAC_CMD_ASSOCIATION_REQUEST, 0x8e };
    uint32_t len;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 0, 1, 1);

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_EXTENDED_ADDRESS;
    Test_ExpectStatus(Mac_SetPib(&dev.mac, &pib), ZB_OK, "the PIB reports eight zero octets for its extended address");

    req = dataReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, COORDINATOR_SHORT, MAC_ADDR_EXTENDED, 0);
    Test_ExpectStatus(Mac_DataRequest(&dev.mac, &req, 100, 0), ZB_ERR_NOT_READY,
                      "a frame with an extended source is refused (6.2, docs/internals/conformance.md §1)");

    Zb_memset(&response, 0, (uint32_t)sizeof response);
    response.request.extendedAddress = CHILD_EXTENDED;
    response.request.capability.allocateAddress = 1;
    response.shortAddress = 0x1234;
    response.status = MAC_ASSOC_STATUS_SUCCESS;
    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 110), ZB_ERR_NOT_READY,
                      "and so is an Association Response, whose source is that same field (10.21.5.2)");

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_COMMAND;
    frame.frameVersion = 0;
    frame.ackRequest = 1;
    frame.panIdCompression = 0;
    frame.destAddrMode = MAC_ADDR_EXTENDED;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.destPan = PAN_ID;
    frame.srcPan = MAC_FRAME_PAN_BROADCAST;
    frame.destExtended = 0;
    frame.srcExtended = CHILD_EXTENDED;
    frame.seq = 0x14;

    Test_ExpectStatus(MacFrame_Compose(&frame, content, 2, bytes, (uint32_t)sizeof bytes, &len), ZB_OK,
                      "a request whose destination is the zero extended address composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, (uint32_t)sizeof bytes, &len), ZB_OK, "with its footer");
    injectFrame(&dev.model, bytes, len, 1200);
    Test_ExpectStatus(Mac_Step(&dev.mac, 120), ZB_OK, "and arrives");

    counters = Mac_CountersOf(&dev.mac);
    Test_Expect(counters.associationQueue == 0, "it names no device this stack was given (6.6.2 d)2)");
    Test_Expect(counters.destinationMismatches == 1 && counters.commandsHeard == 0,
                "and 6.6.2 d) refuses it before the association gate reads it: counted as that refusal");
    Test_Expect(Mac_PollAssociations(&dev.mac, &indication, 1) == 0, "no indication was queued");
}

/* 10.21.5.2 is the one place this MAC is told both forms of a child: the extended address the request came from
   and the short address it is given. That pair is what lets a poll in either form find the answer, and what makes
   the pending table a complete answer for the device (10.22.3). */
void caseAssociationLearnsThePair(void)
{
    Test_BandA dev;
    Radio_Caps caps;
    Mac_AssociationIndication indication;
    Mac_AssociationResponse response;
    Loopback_Sent sent[2];
    Mac_Frame frame;
    const uint8_t *payload = 0;
    uint32_t payloadLen = 0;
    uint8_t poll[64];
    uint32_t pollLen;

    Test_BandACapsPendingTable(&caps);
    rigConfig(&dev, &caps, COORDINATOR_SHORT, PAN_ID, 0);
    configureParent(&dev, 1, 1, 1);

    injectAssociationRequest(&dev, 0x11, 0x8e);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1000), ZB_OK, "the request arrives");
    Test_Expect(Mac_PollAssociations(&dev.mac, &indication, 1) == 1, "and is taken");

    Zb_memset(&response, 0, (uint32_t)sizeof response);
    response.request = indication;
    response.shortAddress = SLEEPY_A;
    response.status = MAC_ASSOC_STATUS_SUCCESS;
    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 1100), ZB_OK, "the answer is queued");

    Test_Expect(LoopbackRadio_PendingShortCount(&dev.model) == 1
                && LoopbackRadio_PendingShort(&dev.model, 0) == SLEEPY_A,
                "and the pending table names the short address the child was given, which no frame but this one tells this MAC");
    Test_Expect(LoopbackRadio_PendingExtendedCount(&dev.model) == 1,
                "beside the extended address the request came from, which is where the answer is held (10.21.5.2)");
    Test_Expect(LoopbackRadio_PendingIsComplete(&dev.model) == 1,
                "as a complete answer: every device holding a frame is named in both of its forms");

    pollLen = composePoll(poll, 0x22, SLEEPY_A);
    injectFrame(&dev.model, poll, pollLen, 1200);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1200), ZB_OK,
                      "the child polls in the short form it will use from now on");
    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, 2) == 1,
                "and the answer queued under its extended form is extracted anyway (10.22.2)");
    Test_ExpectStatus(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &frame, &payload, &payloadLen, 0), ZB_OK,
                      "the frame parses");
    Test_Expect(frame.destExtended == CHILD_EXTENDED,
                "as the extended-addressed answer 10.21.5.2 composed it");
}

/* 10.22.2: a transaction a response primitive started is reported through MLME-COMM-STATUS.indication, related to
   the response by the destination address, and not through the MCPS confirm a caller's MsduHandle would match. */
void caseAssociationOutcomeIsCommStatus(void)
{
    Test_BandA dev;
    Mac_AssociationIndication indication;
    Mac_AssociationResponse response;
    Mac_CommStatusParameters commStatus[2];
    Mac_DataConfirmParameters confirms[2];
    uint8_t poll[64];
    uint32_t pollLen;
    Mac_Counters counters;

    rig(&dev, COORDINATOR_SHORT, PAN_ID);
    configureParent(&dev, 1, 1, 1);

    injectAssociationRequest(&dev, 0x11, 0x8e);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1000), ZB_OK, "the request arrives");
    Test_Expect(Mac_PollAssociations(&dev.mac, &indication, 1) == 1, "and is taken");

    Zb_memset(&response, 0, (uint32_t)sizeof response);
    response.request = indication;
    response.shortAddress = SLEEPY_A;
    response.status = MAC_ASSOC_STATUS_SUCCESS;
    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 1100), ZB_OK, "the answer is queued");

    pollLen = composePollExtended(poll, 0x22, CHILD_EXTENDED);
    injectFrame(&dev.model, poll, pollLen, 1200);
    Test_ExpectStatus(Mac_Step(&dev.mac, 1200), ZB_OK, "the child polls and the answer goes out");
    Test_ExpectStatus(Mac_Step(&dev.mac, 1300), ZB_OK, "and the acknowledgment is collected");

    Test_ExpectCount(Mac_PollConfirms(&dev.mac, confirms, 2), 0,
                     "no MCPS-DATA.confirm: 10.22.2 sends a response-instigated transaction's status to the other primitive");
    Test_ExpectCount(Mac_PollCommStatus(&dev.mac, commStatus, 2), 1,
                     "one MLME-COMM-STATUS.indication, which is where that outcome belongs");
    Test_Expect(commStatus[0].status == ZB_OK && commStatus[0].acked == 1,
                "carrying SUCCESS, the only proof 10.22.2 accepts for an extraction");
    Test_Expect(commStatus[0].destAddrMode == MAC_ADDR_EXTENDED && commStatus[0].destExtended == CHILD_EXTENDED
                && commStatus[0].destPan == PAN_ID,
                "and the destination the frame named, which is how 10.22.2 relates it to the response");
    Test_ExpectCount(Mac_PollCommStatus(&dev.mac, commStatus, 2), 0, "taken once, like every other ring here");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.commStatusQueue, 0, "with the ring empty again");
    Test_ExpectCount(counters.transactionQueue, 0, "and the acknowledged transaction discarded (10.22.2)");
}

/* The same primitive carries the failure: a transaction that outlives macTransactionPersistenceTime is reported
   TRANSACTION_EXPIRED, and a request-instigated one beside it keeps its MCPS confirm. */
void caseExpiredTransactionReportsItsOwnPrimitive(void)
{
    Test_BandA dev;
    Radio_Caps caps;
    Mac_AssociationResponse response;
    Mac_CommStatusParameters commStatus[2];
    Mac_DataConfirmParameters confirms[2];
    Mac_DataRequestParameters req;
    uint8_t payload[1] = { 0xa1 };

    Test_BandACapsPendingTable(&caps);
    rigConfig(&dev, &caps, COORDINATOR_SHORT, PAN_ID, 0);
    configureParent(&dev, 1, 1, 1);

    Zb_memset(&response, 0, (uint32_t)sizeof response);
    response.request.extendedAddress = CHILD_EXTENDED;
    response.request.capability.allocateAddress = 1;
    response.shortAddress = SLEEPY_A;
    response.status = MAC_ASSOC_STATUS_SUCCESS;
    Test_ExpectStatus(Mac_AssociateResponse(&dev.mac, &response, 100), ZB_OK, "an answer is queued for a child");

    req = indirectReq(MAC_FRAME_TYPE_DATA, MAC_ADDR_SHORT, PAN_ID, SLEEPY_B, payload, 1);
    Test_ExpectStatus(Mac_IndirectRequest(&dev.mac, &req, 100), ZB_OK,
                      "and a data frame is held for another device, by a request and not by an MLME response");

    Test_ExpectStatus(Mac_Step(&dev.mac, 100 + MAC_TRANSACTION_PERSISTENCE_MS + 1), ZB_OK,
                      "both transactions outlive macTransactionPersistenceTime");
    Test_ExpectCount(Mac_PollCommStatus(&dev.mac, commStatus, 2), 1,
                     "the response-instigated one is reported through MLME-COMM-STATUS.indication");
    Test_Expect(commStatus[0].status == ZB_ERR_TRANSACTION_EXPIRED && commStatus[0].acked == 0
                && commStatus[0].destExtended == CHILD_EXTENDED,
                "with TRANSACTION_EXPIRED and the child's address");
    Test_ExpectCount(Mac_PollConfirms(&dev.mac, confirms, 2), 1,
                     "the request-instigated one keeps the MCPS confirm its caller's handle is matched against");
    Test_Expect(confirms[0].status == ZB_ERR_TRANSACTION_EXPIRED && confirms[0].msduHandle == req.msduHandle,
                "under the handle it was queued with (6.6.6)");
}
