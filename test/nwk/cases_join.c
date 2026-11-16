/* The `nwk` suite's rejoin half: R23.1 3.4.6 and 3.4.7, the NWK rejoin's command pair as 3.6.1.6.1.2 and
   3.6.1.6.1.3 run it.

   The parent's half (0x06 in, 0x07 out) is the one a rig with a beacon payload and macAssociationPermit TRUE can
   be handed: a joiner's request arrives as a neighbour's frame, and what the case reads is the answer the device
   put back on the air, the indication it pushed, and the neighbour entry the request left. The child's half (0x07
   in) is a device in the middle of a rejoin, which no frame can put a rig into, so those cases set the join state
   the way the application's NLME-JOIN.request would have and then hand the response to
   `Nwk_JoinHandleCommand` directly: 3.6.1.6.1.2's two IEEE comparisons are the clause's whole check, and they are
   the thing those three cases are about.

   One observation shapes every parent-side case here. A received frame is observed before it is dispatched
   (3.6.1.7, `Nwk_RxObserve`), so the table already holds an entry for the joiner's address, with the joiner's
   IEEE address and no device type, by the time 3.6.1.6.1.3 looks for one. What the clause's own new-entry branch
   adds is a child; what the observation adds is a neighbour, and the cases distinguish the two by the
   relationship and the device type, not by the depth of the table.

   The rig's own extended address and the joiner's are the same value in the first three cases, as the suite's
   fixture names them: the destination IEEE sub-field of a 0x06 is the prospective parent's address, which the
   joiner knows, and the source one is its own, so the two fields are distinguishable by name and not by value. */

#include "loopback_radio.h"
#include "mac.h"
#include "mac_frame.h"
#include "nwk.h"
#include "nwk_commissioning.h"
#include "nwk_frame.h"
#include "nwk_helpers.h"
#include "nwk_join.h"
#include "nwk_parents.h"
#include "nwk_status.h"
#include "nwk_timeout.h"
#include "rig_band_a.h"
#include "security.h"
#include "test_harness.h"
#include "zb_utils.h"

/* The device this rig is, and the joiner that asks it for a place: the addresses `nwk_helpers.h` does not name,
   because they are this half's cast rather than the suite's. */
#define JOIN_OWN_IEEE 0x0011223344556677     /* the parent's own extended address, which a 0x07 carries (3.4.7.2) */
#define JOIN_CHILD 0x2222                    /* the joiner's current network address (3.4.6.2) */
#define JOIN_CHILD_IEEE 0x0011223344556677   /* and its extended one, the identity a rejoin is matched on */
#define JOIN_OTHER 0x3333                    /* a request from a second address claiming the first device's IEEE */
#define JOIN_NEW 0x5555                      /* a request at a device whose table has no room at all */
#define JOIN_NEW_IEEE 0x0102030405060708
#define JOIN_PARENT_IEEE 0x1111111111111111  /* the parent a rejoining device is waiting for */
#define JOIN_STRANGER_IEEE 0x2222222222222222 /* a parent that is not the one its request went to */
#define JOIN_EXTENDED_PAN_ID 0x08090a0b0c0d0e0f

/* Figure 10-157's bit 7 alone: a device that asks the parent to allocate its address and states nothing else, so
   3.4.7.1 has its answer held for it. 0x80 with bit 3 is the same device with its receiver on, which takes its
   answer directly (bit 3 is RxOnWhenIdle, bit 7 Allocate Address). */
#define JOIN_CAPABILITY_ALLOCATE 0x80
#define JOIN_CAPABILITY_LISTENING 0x88

/* 3.4.7.3.1's address field for an unsuccessful rejoin: "If the rejoin was not successful, this field contains
   the broadcast address (0xffff)", which is the address every refusal in this half answers with. */
#define JOIN_REJOIN_ADDRESS_NONE 0xffff

/* The four payload octets Figure 3-18 prints: Command ID, the two-octet address, the status. */
#define JOIN_RESPONSE_OCTETS 4

/* Table 3-83's beacon payload, as the beacon suite builds it: a local record of the PAN this device would
   advertise, which is what `Nwk_SetBeaconInfo` needs before it will accept a macAssociationPermit of TRUE. */
static void joinBeaconInfo(Nwk_BeaconInfo *info)
{
    Zb_memset(info, 0, (uint32_t)sizeof *info);

    info->stackProfile = NWK_BEACON_STACK_PROFILE;
    info->protocolVersion = NWK_BEACON_PROTOCOL_VERSION;
    info->routerCapacity = 1;
    info->deviceDepth = 0;
    info->endDeviceCapacity = 1;
    info->extendedPanId = JOIN_EXTENDED_PAN_ID;
    info->txOffset = NWK_BEACON_TX_OFFSET_NONE;
    info->updateId = 0;
}

/* 3.6.1.6.1.3's first condition: a device that takes children at all is one that permits joining. The config's
   `trustCenterIeee` is the AIB's apsTrustCenterAddress, and a case that wants an unsecured rejoin accepted has to
   name one: 0 leaves the all-ones default, which is no trust centre. */
static void joinPermit(Test_BandA *rig)
{
    Nwk_BeaconInfo info;

    joinBeaconInfo(&info);

    Test_ExpectStatus(Nwk_SetBeaconInfo(&rig->nwk, &info, 1), ZB_OK,
                      "a router takes the beacon payload with macAssociationPermit TRUE, which is the door 3.6.1.6.1.3 opens");
}

/* The parent rig with a trust centre in its AIB: 3.6.1.6.1.3's first paragraph refuses an unsecured rejoin only
   when apsTrustCenterAddress is 0xFFFFFFFFFFFFFFFF, so every case that wants the matching steps 1-3 read has to
   give the device one. The address the config names is the parent's own, which is the value it carries as its
   extended address, and the network layer keeps it as `Nwk_Init` reads it. */
static void joinTrustedRig(Test_BandA *rig, uint16_t own, uint16_t panId, uint64_t trustCenterIeee)
{
    Test_BandAConfig cfg;

    Test_BandADefaults(&cfg);
    cfg.ownAddress = own;
    cfg.panId = panId;
    cfg.deviceType = NWK_DEVICE_ROUTER;
    cfg.rxOnWhenIdle = 1;
    cfg.trustCenterIeee = trustCenterIeee;

    Test_ExpectStatus(Test_BandABuild(rig, &cfg), ZB_OK,
                      "a router of this PAN is built from the config the application supplies");
    Test_Expect(rig->nwk.trustCenterIeee == trustCenterIeee,
                "and the AIB's apsTrustCenterAddress the config named is the one the network layer holds, which is what 3.6.1.6.1.3's first paragraph reads");
}

/* The child's half of the pair, which no frame can put a rig into: a device that is on the network (its own PIB
   address and PAN) and is in the middle of 3.6.1.6.1.2's rejoin, waiting for the parent its request went to.
   Setting the state by hand is what NLME-JOIN.request's rejoin half does after the request is on the air, and the
   three cases that need it read 3.6.1.6.1.2's comparisons, which is the whole of what the response is judged by. */
static void rejoinChildRig(Test_BandA *rig)
{
    uint32_t i;

    rigAt(rig, 0x2345, PAN_ID, NWK_DEVICE_END_DEVICE, 1);
    setOwnIeee(rig, JOIN_OWN_IEEE);

    rig->nwk.joinState = NWK_JOIN_REJOINING;
    rig->nwk.joinParentExtended = JOIN_PARENT_IEEE;
    rig->nwk.joinParentShort = 0x0000;
    rig->nwk.joinParentShortKnown = 1;
    rig->nwk.joinChannel = Mac_Pib(&rig->mac)->channel;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        rig->nwk.joinExtendedPanId[i] = (uint8_t)(JOIN_EXTENDED_PAN_ID >> (i * 8));
}

/* 3.4.7.2's header as a rejoining device receives it: the destination IEEE field is its own address, the source
   one is the parent's, and the two network addresses are the pair the answer was exchanged between. */
static void rejoinResponseFrame(Nwk_Frame *frame, uint64_t srcIeee)
{
    Zb_memset(frame, 0, (uint32_t)sizeof *frame);

    frame->frameType = NWK_FRAME_TYPE_COMMAND;
    frame->protocolVersion = NWK_PROTOCOL_VERSION;
    frame->discoverRoute = NWK_DISCOVER_SUPPRESS;
    frame->destAddr = 0x2345;
    frame->srcAddr = 0x0000;
    frame->radius = 1;
    frame->sequenceNumber = 0x40;
    frame->destIeeePresent = 1;
    frame->destIeee = JOIN_OWN_IEEE;
    frame->srcIeeePresent = 1;
    frame->srcIeee = srcIeee;
}

/* The payload of the one answer a case reads off the air, at the boundary the codec reports: 3.4.7.2's header
   carries both IEEE address sub-fields, so the payload is not an offset a case could count by hand. */
static uint32_t joinAnswerPayload(const Air *air, uint8_t *out, uint32_t cap)
{
    Nwk_Frame parsed;
    uint32_t payloadOffset;
    uint32_t payloadLen;

    Test_ExpectStatus(NwkFrame_Parse(npduOf(air), npduLenOf(air), &parsed, &payloadOffset, &payloadLen), ZB_OK,
                      "the answer this device put on the air is an NPDU its own codec reads back");
    Test_Expect(parsed.frameType == NWK_FRAME_TYPE_COMMAND,
                "and it is a command frame, which is the only shape 3.4.7 prints for the pair");

    if (payloadLen > cap)
        payloadLen = cap;

    Zb_memcpy(out, npduOf(air) + payloadOffset, payloadLen);

    return payloadLen;
}

/*
 * 1. 3.6.1.6.1.3's new entry: a request from a device this table has never held is answered with the address the
 *    request named and SUCCESS, the layer above hears about it, and the entry it leaves is an unauthenticated
 *    child. Nothing is allocated: 3.6.1.8's generator belongs to the association half, and a rejoin's address is
 *    the one the requesting device already has. The routing entry 3.6.1.6.1.3 has the parent search for goes with
 *    it, whatever Table 3-78 status it carries.
 *
 *    The second half is 3.4.7.1's other TXOptions: the same request from a device whose capability says its
 *    receiver rests leaves a transaction and no frame, and 3.6.1.6.1.2's own MLME-POLL.request is what extracts it.
 */
void caseRejoinRequestIsAccepted(void)
{
    Test_BandA dev;
    Nwk_JoinIndicationParameters inds[2];
    Nwk_NeighborTableEntry *child;
    Nwk_RoutingTableEntry *route;
    Air air[AIR_LOG_MAX];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint8_t answer[JOIN_RESPONSE_OCTETS];
    uint32_t npduLen;
    uint32_t answerLen;
    uint32_t airCount = 0;
    uint32_t before;
    Mac_Counters counters;

    joinTrustedRig(&dev, OWN_SHORT, PAN_ID, JOIN_OWN_IEEE);
    joinPermit(&dev);

    /* Table 3-77's entry for the child, ACTIVE: the deletion 3.6.1.6.1.3 makes is the corpus's one unconditional one */
    route = &dev.nwk.routes[0];

    Zb_memset(route, 0, (uint32_t)sizeof *route);
    route->inUse = 1;
    route->destinationAddress = JOIN_CHILD;
    route->status = NWK_ROUTE_ACTIVE;

    Test_ExpectCount(Nwk_RouteQueue(&dev.nwk), 1, "the routing table holds a route to 0x2222 before the rejoin");

    npduLen = makeRejoinNpdu(npdu, OWN_SHORT, JOIN_CHILD, JOIN_CHILD_IEEE, JOIN_OWN_IEEE,
                             JOIN_CAPABILITY_LISTENING);
    injectNpdu(&dev, npdu, npduLen, JOIN_CHILD);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a rejoin request addressed to this device is stepped");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1, "exactly one frame goes back on the air: the answer the request owes and nothing else");
    Test_Expect(airDestOf(&air[0]) == JOIN_CHILD && air[0].ackRequest == 1,
                "a unicast to the requesting device, which 3.4.7.1 asks to be acknowledged");

    answerLen = joinAnswerPayload(&air[0], answer, (uint32_t)sizeof answer);
    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS, "four payload octets, as Figure 3-18 prints them");
    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[0] == NWK_CMD_REJOIN_RESPONSE,
                "first octet 0x07, the NWK Rejoin Response identifier");
    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[1] == 0x22 && answer[2] == 0x22,
                "then 0x2222, the address the request named, low octet first (3.4.7.3.1): the parent accepted it and allocated nothing");
    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[3] == NWK_JOIN_STATUS_SUCCESS,
                "and Table 10-102's success, 0x00");

    Test_Expect(Nwk_JoinIndicationQueue(&dev.nwk) == 1,
                "the parent's next higher layer is told once (3.2.2.14, the last paragraph of 3.6.1.6.1.3)");
    Test_Expect(Nwk_PollJoinIndications(&dev.nwk, inds, 2) == 1 && inds[0].networkAddress == JOIN_CHILD
                && inds[0].extendedAddress == JOIN_CHILD_IEEE,
                "naming the child's network and extended addresses");
    Test_Expect(inds[0].joinerMethod == 1,
                "with JoinerMethod 1: the rejoin without security, which is the mechanism that added this child (Table 3-22)");
    Test_Expect(inds[0].capability.allocateAddress == 1,
                "and the capability octet the request carried, bit 7 set (Figure 10-157)");

    child = neighborAt(&dev.nwk, JOIN_CHILD);
    Test_Expect(child != 0 && child->extendedAddress == JOIN_CHILD_IEEE && child->ieeeKnown == 1,
                "the neighbor table holds 0x2222 with the IEEE address the request named");
    Test_Expect(child != 0 && child->relationship == NWK_REL_UNAUTHENTICATED_CHILD,
                "as an unauthenticated child, 0x05: 3.6.1.6.1.3 makes no claim that the device is authorized until a secured frame proves it (4.3.1.2 step 8)");
    Test_Expect(Nwk_JoinAddressesAssigned(&dev.nwk) == 0,
                "and 3.6.1.8's address generator drew nothing: the rejoin asked for its own address, which the parent accepted");
    Test_ExpectCount(child->rxOnWhenIdle, 1,
                     "and the receiver duty the capability named, which is what 3.4.7.1 reads to decide how the answer travels");
    Test_ExpectCount(Nwk_RouteQueue(&dev.nwk), 0,
                     "while the routing table's entry for 0x2222 is gone: 3.6.1.6.1.3, the rejoining device's entry deleted");
    Test_ExpectCount(Nwk_JoinRoutesDeleted(&dev.nwk), 1, "counted once, as the one entry the search removed");

    /* The same request from a device whose receiver rests: 3.4.7.1's indirect TXOptions. */
    npduLen = makeRejoinNpdu(npdu, OWN_SHORT, JOIN_NEW, JOIN_NEW_IEEE, JOIN_OWN_IEEE, JOIN_CAPABILITY_ALLOCATE);
    injectNpdu(&dev, npdu, npduLen, JOIN_NEW);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK,
                      "a rejoin request from a device whose capability says its receiver is off when idle");
    before = airCount;
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount - before, 0,
                     "puts nothing on the air: 'The TXOptions SHALL request indirect transmission to be used if the Receiver on when idle bit ... is equal to 0x00' (3.4.7.1)");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.transactionQueue, 1,
                     "one transaction is held for it instead, which is 10.22.2's indirect form in the MAC beneath this layer");
    Test_ExpectCount(Nwk_JoinAddressesAssigned(&dev.nwk), 0,
                     "and no address was allocated for it either: a rejoin's address is the one the request named");

    composePoll(&dev.model, 0x21, JOIN_NEW);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 300), ZB_OK,
                      "then 3.6.1.6.1.2's MLME-POLL.request, which the rejoining device has to make for itself, extracts it");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount - before, 1, "one frame goes out on that poll, and it is the answer the transaction held");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 301), ZB_OK,
                      "the next turn collects the acknowledgment that retires the transaction 10.22.2 says the answer asks for");
    counters = Mac_CountersOf(&dev.mac);
    Test_ExpectCount(counters.transactionQueue, 0, "so the queue the answer waited in is empty again");
    Test_ExpectCount(Nwk_JoinIndicationsDropped(&dev.nwk), 0, "and nothing is lost for want of room in the indication ring");

    if (airCount - before == 1)
    {
        answerLen = joinAnswerPayload(&air[before], answer, (uint32_t)sizeof answer);

        Test_ExpectCount(answerLen, JOIN_RESPONSE_OCTETS, "four payload octets, as Figure 3-18 prints them");
        Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[0] == NWK_CMD_REJOIN_RESPONSE,
                    "first octet 0x07, the NWK Rejoin Response identifier");
        Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[1] == 0x55 && answer[2] == 0x55,
                    "then 0x5555, the address the request named, low octet first (3.4.7.3.1)");
        Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[3] == NWK_JOIN_STATUS_SUCCESS,
                    "and Table 10-102's success, 0x00");
        Test_Expect(airDestOf(&air[before]) == JOIN_NEW,
                    "addressed to the device the poll came from, which is the address the transaction was held for");
    }

    Test_ExpectCount(Nwk_JoinIndicationQueue(&dev.nwk), 1,
                     "and 3.2.2.14's ring owes one indication still: the first child was reported and taken, the second was reported and left");
}

/* A rejoin is answered while joining is not permitted: 8077-8082 name the association and an Initial Join as what
   the permit refuses, 8090 has a rejoin received at any time, and 14045-14048 has the flag used only by new devices. */
void caseRejoinRequestIsAnsweredWhileJoiningIsNotPermitted(void)
{
    Test_BandA dev;
    Nwk_BeaconInfo info;
    Air air[AIR_LOG_MAX];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint8_t answer[JOIN_RESPONSE_OCTETS];
    uint32_t npduLen;
    uint32_t answerLen = 0;
    uint32_t airCount = 0;

    joinTrustedRig(&dev, OWN_SHORT, PAN_ID, JOIN_OWN_IEEE);
    joinBeaconInfo(&info);
    Test_ExpectStatus(Nwk_SetBeaconInfo(&dev.nwk, &info, 0), ZB_OK, "a router whose macAssociationPermit is FALSE");

    npduLen = makeRejoinNpdu(npdu, OWN_SHORT, JOIN_CHILD, JOIN_CHILD_IEEE, JOIN_OWN_IEEE,
                             JOIN_CAPABILITY_LISTENING);
    injectNpdu(&dev, npdu, npduLen, JOIN_CHILD);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "takes a rejoin request addressed to it");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 1, "and answers it");

    if (airCount == 1)
        answerLen = joinAnswerPayload(&air[0], answer, (uint32_t)sizeof answer);

    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[0] == NWK_CMD_REJOIN_RESPONSE
                    && answer[1] == 0x22 && answer[2] == 0x22 && answer[3] == NWK_JOIN_STATUS_SUCCESS,
                "with the address the request named and success");
    Test_ExpectCount(Nwk_JoinIndicationQueue(&dev.nwk), 1, "and the layer above hears of the rejoin");
}

/*
 * 2. 3.6.1.6.1.3 steps 1 and 3: a request whose network address is not the one the table holds for that extended
 *    address is PAN ACCESS DENIED, "and no changes SHALL be made". The entry that matched by IEEE keeps its
 *    address, and the offending address gains no child.
 */
void caseRejoinRequestAddressMismatchIsDenied(void)
{
    Test_BandA dev;
    Nwk_NeighborTableEntry *seeded;
    Nwk_NeighborTableEntry *stranger;
    Air air[AIR_LOG_MAX];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint8_t answer[JOIN_RESPONSE_OCTETS];
    uint32_t npduLen;
    uint32_t answerLen;
    uint32_t airCount = 0;

    joinTrustedRig(&dev, OWN_SHORT, PAN_ID, JOIN_OWN_IEEE);
    joinPermit(&dev);

    seedNeighbor(&dev.nwk, JOIN_CHILD, NWK_DEVICE_END_DEVICE, 0, NWK_REL_UNAUTHENTICATED_CHILD);

    seeded = Nwk_NeighborOf(dev.nwk.neighbors, JOIN_CHILD);
    Test_Expect(seeded != 0, "the table holds the entry the case seeds for 0x2222");

    if (seeded != 0)
    {
        seeded->extendedAddress = JOIN_CHILD_IEEE;
        seeded->ieeeKnown = 1;
    }

    npduLen = makeRejoinNpdu(npdu, OWN_SHORT, JOIN_OTHER, JOIN_CHILD_IEEE, JOIN_OWN_IEEE,
                             JOIN_CAPABILITY_LISTENING);
    injectNpdu(&dev, npdu, npduLen, JOIN_OTHER);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK,
                      "a rejoin request from 0x3333 claiming the IEEE address the table holds for 0x2222");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1, "is answered: 3.6.1.6.1.3 answers a request it refuses as well as one it takes");
    answerLen = joinAnswerPayload(&air[0], answer, (uint32_t)sizeof answer);
    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[0] == NWK_CMD_REJOIN_RESPONSE, "with a 0x07");
    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[1] == 0xff && answer[2] == 0xff,
                "whose address field is 0xffff, the broadcast 3.4.7.3.1 prints for an unsuccessful rejoin");
    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[3] == MAC_ASSOC_STATUS_PAN_ACCESS_DENIED,
                "and Table 10-102's 0x02: the request's short address is not the one this table has for that extended address, so step 1's comparison fails and step 3 refuses");

    Test_Expect(Nwk_JoinIndicationQueue(&dev.nwk) == 0,
                "and no child is reported: a refused request adds nobody (3.6.1.6.1.3 step 3, 'no changes SHALL be made')");

    Test_Expect(seeded != 0 && seeded->networkAddress == JOIN_CHILD && seeded->extendedAddress == JOIN_CHILD_IEEE
                && seeded->relationship == NWK_REL_UNAUTHENTICATED_CHILD,
                "the entry that matched by extended address keeps its address, its IEEE address and its relationship");
    stranger = neighborAt(&dev.nwk, JOIN_OTHER);
    Test_Expect(stranger != 0 && stranger->relationship == NWK_REL_NONE
                && stranger->deviceType == NWK_NEIGHBOR_TYPE_UNKNOWN,
                "and 0x3333 gains no child: 3.6.1.7's observation alone, and 3.6.1.6.1.3 step 3 writes nothing into it");
}

/*
 * 2b. 3.6.1.6.1.3 step 3's "no changes SHALL be made" where the entry the extended address matched is a bare
 *     observation: the refusal writes neither the relationship nor the device type into the entry that matched.
 */
void caseRejoinRefusalWritesNothingIntoTheMatchedEntry(void)
{
    Test_BandA dev;
    Nwk_NeighborTableEntry *observed;
    Air air[AIR_LOG_MAX];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint8_t answer[JOIN_RESPONSE_OCTETS];
    uint32_t npduLen;
    uint32_t answerLen;
    uint32_t airCount = 0;

    joinTrustedRig(&dev, OWN_SHORT, PAN_ID, JOIN_OWN_IEEE);
    joinPermit(&dev);

    /* The entry 3.6.1.7's observation leaves: an address and an extended address, no device type and no
       relationship, which is all a received frame states. */
    seedNeighbor(&dev.nwk, JOIN_CHILD, NWK_NEIGHBOR_TYPE_UNKNOWN, 0, NWK_REL_NONE);

    observed = Nwk_NeighborOf(dev.nwk.neighbors, JOIN_CHILD);

    Test_Expect(observed != 0, "the table holds the bare observation 3.6.1.7 makes of 0x2222");

    if (observed != 0)
    {
        observed->extendedAddress = JOIN_CHILD_IEEE;
        observed->ieeeKnown = 1;
    }

    npduLen = makeRejoinNpdu(npdu, OWN_SHORT, JOIN_OTHER, JOIN_CHILD_IEEE, JOIN_OWN_IEEE,
                             JOIN_CAPABILITY_LISTENING);
    injectNpdu(&dev, npdu, npduLen, JOIN_OTHER);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK,
                      "a rejoin request naming the extended address the observation holds and an address it does not");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1, "is answered, because a parent answers a request it refuses as well as one it takes");
    answerLen = joinAnswerPayload(&air[0], answer, (uint32_t)sizeof answer);
    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[3] == MAC_ASSOC_STATUS_PAN_ACCESS_DENIED,
                "with Table 10-102's 0x02 PAN ACCESS DENIED");

    Test_Expect(observed != 0 && observed->relationship == NWK_REL_NONE,
                "and the matched entry keeps Table 3-75's 0x00: 3.6.1.6.1.3 step 3 says 'No changes SHALL be made to the existing nwkNeighborTable entry'");
    Test_Expect(observed != 0 && observed->deviceType == NWK_NEIGHBOR_TYPE_UNKNOWN,
                "with the device type it had, which the refusal was not entitled to write either");
    Test_ExpectCount(Nwk_JoinIndicationQueue(&dev.nwk), 0, "and no child is reported for a rejoin nobody accepted");
}

/*
 * 3. 3.6.1.6.1.3's first paragraph: a parent that has a trust center refuses an unsecured rejoin. This stack reads
 *    "a trust center is present" as a `Security` attached at a level other than 0, so a router with one, and an
 *    unsecured 0x06, is the refused case: PAN ACCESS DENIED with no address, and no child.
 */
void caseRejoinRequestAtASecuredDeviceIsDeniedUnsecured(void)
{
    Test_BandA dev;
    Security sec;
    Security_KeyDescriptor key;
    Security_Config cfg;
    Nwk_NeighborTableEntry *child;
    Air air[AIR_LOG_MAX];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint8_t answer[JOIN_RESPONSE_OCTETS];
    uint32_t npduLen;
    uint32_t answerLen;
    uint32_t airCount = 0;
    uint32_t i;

    rig(&dev, OWN_SHORT, PAN_ID);
    setOwnIeee(&dev, JOIN_OWN_IEEE);

    /* The one key Table 4-2's nwkSecurityMaterialSet holds, at sequence number 0, and the default level 0x05 */
    Zb_memset(&key, 0, (uint32_t)sizeof key);
    key.keySeqNumber = 0x00;
    key.inUse = 1;
    key.outgoingFrameCounter = 1;

    for (i = 0; i < SECURITY_KEY_OCTETS; i++)
        key.key[i] = (uint8_t)i;

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = JOIN_OWN_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.nwkActiveKeySeqNumber = 0x00;
    cfg.authenticated = 1;
    cfg.nwkAllFresh = 1;
    cfg.keys = &key;
    cfg.keyCount = 1;

    Test_ExpectStatus(Security_Init(&sec, &cfg), ZB_OK, "a security fixture the application could have configured");
    Test_Expect(Security_Level(&sec) == SECURITY_LEVEL_ENC_MIC_32, "at the level 3.6.1.6.1.3's reading keys on");

    Nwk_AttachSecurity(&dev.nwk, &sec);
    Test_Expect(Nwk_Security(&dev.nwk) == &sec, "adopted by the network layer, which is how a device comes to have a trust center here");

    joinPermit(&dev);

    npduLen = makeRejoinNpdu(npdu, OWN_SHORT, JOIN_CHILD, JOIN_CHILD_IEEE, JOIN_OWN_IEEE,
                             JOIN_CAPABILITY_LISTENING);
    injectNpdu(&dev, npdu, npduLen, JOIN_CHILD);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK,
                      "an unsecured rejoin request arriving at a device that holds a key (3.6.2.2 leaves the request through)");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1, "draws one frame back");
    answerLen = joinAnswerPayload(&air[0], answer, (uint32_t)sizeof answer);
    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[0] == NWK_CMD_REJOIN_RESPONSE, "a 0x07");
    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[1] == 0xff && answer[2] == 0xff,
                "with 0xffff in the address field, because no address was granted");
    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[3] == MAC_ASSOC_STATUS_PAN_ACCESS_DENIED,
                "and Table 10-102's 0x02: the trust center this device has refuses an unsecured rejoin, whatever the address it named");

    Test_Expect(Nwk_JoinIndicationQueue(&dev.nwk) == 0, "and nothing is pushed upward: nobody was added");
    child = neighborAt(&dev.nwk, JOIN_CHILD);
    Test_Expect(child != 0 && child->relationship == NWK_REL_NONE
                && child->deviceType == NWK_NEIGHBOR_TYPE_UNKNOWN,
                "and the table gained no child: the entry 0x2222 has is the observation 3.6.1.7 makes of any sender, with no device type and no relationship");
}

/*
 * 4. 3.6.1.6.1.3's capacity answer: "if the potential parent does not have the capacity to accept more children",
 *    Table 10-102's 0x01 PAN AT CAPACITY with no address. A full neighbor table is that condition here, and the
 *    request leaves the table exactly as full as it was.
 */
void caseRejoinRequestAtCapacity(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint8_t answer[JOIN_RESPONSE_OCTETS];
    uint32_t npduLen;
    uint32_t answerLen;
    uint32_t airCount = 0;
    uint32_t i;

    joinTrustedRig(&dev, OWN_SHORT, PAN_ID, JOIN_OWN_IEEE);
    joinPermit(&dev);

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
        seedNeighbor(&dev.nwk, (uint16_t)(0x0100 + i), NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);

    Test_Expect(Nwk_NeighborQueue(&dev.nwk) == NWK_NEIGHBOR_MAX, "the neighbor table is full to its last slot");

    npduLen = makeRejoinNpdu(npdu, OWN_SHORT, JOIN_NEW, JOIN_NEW_IEEE, JOIN_OWN_IEEE,
                             JOIN_CAPABILITY_LISTENING);
    injectNpdu(&dev, npdu, npduLen, JOIN_NEW);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a rejoin request from a device the full table cannot hold");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1, "is answered rather than silently dropped");
    answerLen = joinAnswerPayload(&air[0], answer, (uint32_t)sizeof answer);
    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[0] == NWK_CMD_REJOIN_RESPONSE, "with a 0x07");
    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[1] == 0xff && answer[2] == 0xff,
                "whose address field is 0xffff");
    Test_Expect(answerLen == JOIN_RESPONSE_OCTETS && answer[3] == MAC_ASSOC_STATUS_PAN_AT_CAPACITY,
                "and Table 10-102's 0x01 PAN AT CAPACITY: 3.6.1.6.1.3 has no room to hold the child");

    Test_Expect(Nwk_JoinIndicationQueue(&dev.nwk) == 0, "no indication: nobody joined");
    Test_Expect(Nwk_NeighborQueue(&dev.nwk) == NWK_NEIGHBOR_MAX, "and the table is as full as it was");
    Test_Expect(neighborAt(&dev.nwk, JOIN_NEW) == 0, "with no entry at the requesting device's address");
}

/*
 * 5. 3.6.1.6.1.2's accepted response: the destination IEEE field is this device's own and the source one is the
 *    parent its request went to, the status is SUCCESS and the address is a usable one. The answer is the join's:
 *    the state becomes JOINED, the PIB takes the address, the confirm is ready, and the parent becomes the entry
 *    3.6.1.6.1.1 describes.
 */
void caseRejoinResponseIsAccepted(void)
{
    Test_BandA dev;
    Nwk_Frame frame;
    Nwk_JoinConfirmParameters confirm;
    Nwk_NeighborTableEntry *parent;
    static const uint8_t payload[JOIN_RESPONSE_OCTETS] = { 0x07, 0x45, 0x23, 0x00 };

    rejoinChildRig(&dev);
    rejoinResponseFrame(&frame, JOIN_PARENT_IEEE);

    Test_Expect(Nwk_JoinHandleCommand(&dev.nwk, &frame, payload, (uint32_t)sizeof payload, 100) == 1,
                "a rejoin response for the parent this device is waiting for is a command the layer consumed");

    Test_Expect(Nwk_JoinStateOf(&dev.nwk) == NWK_JOIN_JOINED,
                "and the rejoin 3.6.1.6.1.2 was running has succeeded");
    Test_Expect(Nwk_PollJoinConfirm(&dev.nwk, &confirm) == 1, "the confirm 3.2.2.15 owes is ready");
    Test_Expect(confirm.status == NWK_JOIN_STATUS_SUCCESS, "with Table 10-102's success");
    Test_Expect(confirm.networkAddress == 0x2345, "and the address the answer named, 0x2345, which 3.6.1.6.1.1 puts in the NIB");
    Test_Expect(confirm.parentExtended == JOIN_PARENT_IEEE, "naming the parent the rejoin addressed");
    Test_Expect(confirm.channel == Mac_Pib(&dev.mac)->channel,
                "and the channel the rejoin ran on, which 3.6.1.6.1.2 leaves alone: the PIB's own, because a device that is already on the network stays where its radio is");
    Test_Expect(Mac_Pib(&dev.mac)->shortAddress == 0x2345,
                "and the PIB really carries it: nwkNetworkAddress is a NIB attribute written through the MAC");

    parent = neighborAt(&dev.nwk, 0x0000);
    Test_Expect(parent != 0 && parent->extendedAddress == JOIN_PARENT_IEEE && parent->ieeeKnown == 1,
                "the neighbor table holds the parent at 0x0000 with its extended address");
    Test_Expect(parent != 0 && parent->relationship == NWK_REL_PARENT,
                "with relationship 0x00: 'the NWK layer SHALL then set the Relationship field ... to indicate that the neighbor is its parent' (3.6.1.6.1.1)");
}

/*
 * 6. 3.6.1.6.1.2's second comparison: a source IEEE field that is not the parent the request went to means the
 *    response "shall be discarded without further processing". It is still a command of this layer's procedure,
 *    so the frame is consumed; nothing else about it is.
 */
void caseRejoinResponseFromAnotherParentIsDropped(void)
{
    Test_BandA dev;
    Nwk_Frame frame;
    Nwk_JoinConfirmParameters confirm;
    static const uint8_t payload[JOIN_RESPONSE_OCTETS] = { 0x07, 0x45, 0x23, 0x00 };

    rejoinChildRig(&dev);
    rejoinResponseFrame(&frame, JOIN_STRANGER_IEEE);

    Test_Expect(Nwk_JoinHandleCommand(&dev.nwk, &frame, payload, (uint32_t)sizeof payload, 100) == 1,
                "a 0x07 from a device that is not the parent the request went to is consumed all the same: the identifier is this layer's");

    Test_Expect(Nwk_JoinStateOf(&dev.nwk) == NWK_JOIN_REJOINING,
                "and the rejoin is still running: the countdown 3.6.1.6.1.2 loaded has not elapsed and no answer has been accepted");
    Test_Expect(Nwk_PollJoinConfirm(&dev.nwk, &confirm) == 0, "so no confirm is ready");
    Test_Expect(Mac_Pib(&dev.mac)->shortAddress == 0x2345,
                "and the PIB is untouched, exactly as it was before the frame arrived (3.6.1.6.1.2's discard is 'without further processing')");
    Test_Expect(neighborAt(&dev.nwk, 0x0000) == 0,
                "and no parent entry is recorded at the address the rejoin asked: 3.6.1.6.1.1's neighbour write is the accepted answer's act and nobody else's");
}

/*
 * 7. 3.6.1.6.1.2's success that names no usable address: SUCCESS with 0xffff (or a reserved address) is not a
 *    place on the network. The rejoin fails with Table 10-102's 0x0c, the status a countdown that elapsed would
 *    have given, and the PIB keeps the address it had.
 */
void caseRejoinResponseWithNoAddressFails(void)
{
    Test_BandA dev;
    Nwk_Frame frame;
    Nwk_JoinConfirmParameters confirm;
    static const uint8_t payload[JOIN_RESPONSE_OCTETS] = { 0x07, 0xff, 0xff, 0x00 };

    rejoinChildRig(&dev);
    rejoinResponseFrame(&frame, JOIN_PARENT_IEEE);

    Test_Expect(Nwk_JoinHandleCommand(&dev.nwk, &frame, payload, (uint32_t)sizeof payload, 100) == 1,
                "a SUCCESS whose address field is 0xffff is consumed as the answer it claims to be");

    Test_Expect(Nwk_JoinStateOf(&dev.nwk) == NWK_JOIN_FAILED, "and the rejoin has failed");
    Test_Expect(Nwk_PollJoinConfirm(&dev.nwk, &confirm) == 1, "with a confirm");
    Test_Expect(confirm.status == 0xeb,
                "whose status is 0xeb NO_DATA (802.15.4-2006 Table 78): 0xffff names no device, so an answer that grants no address is the same answer as an answer that never came");
    Test_Expect(confirm.networkAddress == JOIN_REJOIN_ADDRESS_NONE, "and the confirm's address field is 0xffff, the failure form");
    Test_Expect(Mac_Pib(&dev.mac)->shortAddress == 0x2345, "and the PIB is untouched: no address was granted");
    Test_Expect(neighborAt(&dev.nwk, 0x0000) == 0, "and no parent is recorded for a rejoin that never landed");
}

/*
 * 9. Table 3-75's SecurityTimer as the countdown it is: armed to a length, decremented once per second from the
 *    anchor it was armed at, never below zero, and off while it is zero. 3.6.1.6.1.1 and 3.6.1.6.1.3 both arm it
 *    with apsSecurityTimeOutPeriod; what this case pins is the arithmetic, which neither clause prints.
 */
void caseSecurityTimerCounts(void)
{
    Nwk_NeighborTableEntry entry;

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);

    Test_Expect(Nwk_NeighborSecurityTimerTick(&entry, 1000) == 0,
                "an entry with no countdown running answers nothing, whatever the clock says");

    Nwk_NeighborSecurityTimerArm(&entry, 3, 1000);

    Test_Expect(entry.securityTimer == 3, "armed to three seconds");
    Test_Expect(Nwk_NeighborSecurityTimerTick(&entry, 1999) == 0 && entry.securityTimer == 3,
                "and a tick inside the first second takes nothing off: the countdown is in whole seconds");
    Test_Expect(Nwk_NeighborSecurityTimerTick(&entry, 2000) == 0 && entry.securityTimer == 2,
                "a tick a second later takes one off, and three to two is not yet zero, which is what the answer reports");
    Test_Expect(Nwk_NeighborSecurityTimerTick(&entry, 5000) == 1 && entry.securityTimer == 0,
                "three seconds past the anchor takes the rest and reports the zero");
    Test_Expect(Nwk_NeighborSecurityTimerTick(&entry, 9000) == 0 && entry.securityTimer == 0,
                "and a countdown that has reached zero stays there rather than wrapping: it is not re-reported");
}

/*
 * 10. 3.6.1.6.1.1's NO_KEY: a device that joined and was given no network key within apsSecurityTimeOutPeriod gets
 *     a second NLME-JOIN.confirm, this one carrying Table 3-84's 0xcd. The join itself succeeded, which is why the
 *     first confirm was a SUCCESS and why the device is still joined afterwards.
 */
void caseJoinKeyWaitTimesOut(void)
{
    Test_BandA dev;
    Nwk_Frame frame;
    Nwk_JoinConfirmParameters confirm;
    Nwk_NeighborTableEntry *parent;
    static const uint8_t payload[JOIN_RESPONSE_OCTETS] = { 0x07, 0x45, 0x23, 0x00 };

    rejoinChildRig(&dev);
    rejoinResponseFrame(&frame, JOIN_PARENT_IEEE);

    Test_Expect(Nwk_JoinHandleCommand(&dev.nwk, &frame, payload, (uint32_t)sizeof payload, 100) == 1,
                "a rejoin response that succeeds, so the join is JOINED and its confirm is ready");
    Test_Expect(Nwk_PollJoinConfirm(&dev.nwk, &confirm) == 1 && confirm.status == NWK_JOIN_STATUS_SUCCESS,
                "the SUCCESS confirm 3.2.2.15 owes is taken");

    parent = neighborAt(&dev.nwk, 0x0000);
    Test_Expect(parent != 0 && parent->securityTimer == NWK_SECURITY_TIMEOUT_DEFAULT,
                "and the parent's entry carries Table 4-35's apsSecurityTimeOutPeriod, ten seconds by default");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + 9000), ZB_OK,
                      "nine seconds pass with no network key and no confirm is owed yet");
    Test_Expect(Nwk_PollJoinConfirm(&dev.nwk, &confirm) == 0 && Nwk_JoinKeyTimeouts(&dev.nwk) == 0,
                "nothing is reported: 3.6.1.6.1.1 gives the device apsSecurityTimeOutPeriod to be authorized in");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + 11000), ZB_OK, "and the period passes");

    Test_Expect(Nwk_JoinKeyTimeouts(&dev.nwk) == 1, "which is the NO_KEY outcome, counted once");
    Test_Expect(Nwk_PollJoinConfirm(&dev.nwk, &confirm) == 1, "a second NLME-JOIN.confirm is ready");
    Test_Expect(confirm.status == NWK_STATUS_NO_KEY,
                "with Table 3-84's 0xcd, the one code 3.6.1.6.1.1 names for a NIB that was not given the key");
    Test_Expect(confirm.networkAddress == 0x2345,
                "and the address the join had given, so the confirmation names the join it belongs to");
    Test_Expect(confirm.parentExtended == JOIN_PARENT_IEEE, "and the parent it waited on");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + 30000), ZB_OK, "and the timer does not fire again");
    Test_Expect(Nwk_JoinKeyTimeouts(&dev.nwk) == 1 && Nwk_PollJoinConfirm(&dev.nwk, &confirm) == 0,
                "one join, one NO_KEY: the countdown reported its zero once");
}

/*
 * 11. 3.6.1.6.1.3's deletion: the parent arms the same countdown on a child that has just associated, and a child
 *     that has shown no network-secured frame by the time it reaches zero is deleted from the neighbor table. The
 *     network-encrypted message the clause waits for is what stops it, which is 4.3.1.2 step 8's promotion.
 */
void caseParentDeletesUnauthorizedChild(void)
{
    Test_BandA dev;
    Nwk_NeighborTableEntry *child;
    Security_Result result;

    rig(&dev, OWN_SHORT, PAN_ID);

    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_END_DEVICE, 1, NWK_REL_UNAUTHENTICATED_CHILD);

    child = neighborAt(&dev.nwk, NEIGHBOR);
    Test_Expect(child != 0, "a child that associated and has not been heard from since");

    Nwk_NeighborSecurityTimerArm(child, 2, 1000);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 2000), ZB_OK, "a second passes");
    Test_Expect(Nwk_JoinChildrenExpired(&dev.nwk) == 0 && neighborAt(&dev.nwk, NEIGHBOR) != 0,
                "and the entry is still held: 3.6.1.6.1.3 gives the child the whole period to show itself authorized");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 4000), ZB_OK, "and the period runs out");
    Test_Expect(Nwk_JoinChildrenExpired(&dev.nwk) == 1, "the parent deletes the unauthorized child, once");
    Test_Expect(neighborAt(&dev.nwk, NEIGHBOR) == 0, "and the neighbor table no longer holds it");

    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_END_DEVICE, 1, NWK_REL_UNAUTHENTICATED_CHILD);

    child = neighborAt(&dev.nwk, NEIGHBOR);
    child->extendedAddress = 0x00212effff05a888;
    child->ieeeKnown = 1;
    Nwk_NeighborSecurityTimerArm(child, 2, 10000);

    Zb_memset(&result, 0, (uint32_t)sizeof result);
    result.senderIeee = child->extendedAddress;

    Nwk_RxAuthenticateHop(dev.nwk.neighbors, &result);

    Test_Expect(child->relationship == NWK_REL_CHILD && child->securityTimer == 0,
                "while a network-encrypted frame from the child promotes it to 0x01 and stops the countdown, which is the message 3.6.1.6.1.3 waits for");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 60000), ZB_OK, "however long the clock runs after that");
    Test_Expect(Nwk_JoinChildrenExpired(&dev.nwk) == 1 && neighborAt(&dev.nwk, NEIGHBOR) != 0,
                "the authorized child is not deleted");
}

/*
 * 3.6.1.6.1.3's last two sentences on the MAC's MLME-COMM-STATUS: an association answer that was delivered is a join
 * the next higher layer is told of, and one that was not ends the procedure, taking the unauthenticated child it
 * created with it. A TRÅDFRI bulb that never took its first answer was sent a network key anyway before this.
 */
void caseParentIndicatesOnlyADeliveredAnswer(void)
{
    Test_BandA dev;
    Nwk_NeighborTableEntry *child;
    Nwk_JoinIndicationParameters inds[2];
    Mac_CommStatusParameters status;
    Security security;
    Security_Config cfg;
    Security_KeyDescriptor key;
    Security_IncomingEntry stale;

    rig(&dev, OWN_SHORT, PAN_ID);

    Zb_memset(&key, 0, (uint32_t)sizeof key);
    key.inUse = 1;
    key.outgoingFrameCounter = 1;
    Zb_memset(&stale, 0, (uint32_t)sizeof stale);
    stale.senderIeee = JOIN_CHILD_IEEE;
    stale.frameCounter = 20484;    /* the bulb's counter before its factory reset */
    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = JOIN_OWN_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.authenticated = 1;
    cfg.keys = &key;
    cfg.keyCount = 1;
    cfg.incomingSeeds = &stale;
    cfg.incomingSeedCount = 1;
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_OK, "a parent that remembers the child's counter from before");
    Nwk_AttachSecurity(&dev.nwk, &security);

    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_UNAUTHENTICATED_CHILD);
    child = neighborAt(&dev.nwk, NEIGHBOR);
    Test_Expect(child != 0, "a child the parent has just answered");
    child->extendedAddress = JOIN_CHILD_IEEE;
    child->ieeeKnown = 1;

    Zb_memset(&dev.nwk.joinPending[0], 0, (uint32_t)sizeof dev.nwk.joinPending[0]);
    dev.nwk.joinPending[0].networkAddress = NEIGHBOR;
    dev.nwk.joinPending[0].extendedAddress = JOIN_CHILD_IEEE;
    dev.nwk.joinPendingInUse[0] = 1;

    Zb_memset(&status, 0, (uint32_t)sizeof status);
    status.destAddrMode = MAC_ADDR_EXTENDED;
    status.destExtended = JOIN_CHILD_IEEE;
    status.status = ZB_ERR_NO_ACK;

    Nwk_JoinCommStatus(&dev.nwk, &status);

    Test_Expect(Nwk_JoinResponsesUndelivered(&dev.nwk) == 1 && Nwk_JoinIndicationQueue(&dev.nwk) == 0,
                "an answer the child never acknowledged is no join: nothing is indicated");
    Test_Expect(neighborAt(&dev.nwk, NEIGHBOR) == 0, "and the child it created is gone with the procedure");

    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_UNAUTHENTICATED_CHILD);
    child = neighborAt(&dev.nwk, NEIGHBOR);
    child->extendedAddress = JOIN_CHILD_IEEE;
    child->ieeeKnown = 1;
    dev.nwk.joinPendingInUse[0] = 1;

    Nwk_JoinCommStatus(&dev.nwk, &status);
    status.status = ZB_OK;
    Nwk_JoinCommStatus(&dev.nwk, &status);

    Test_Expect(Nwk_JoinResponsesDelivered(&dev.nwk) == 0,
                "a second status for an answer already settled finds nothing waiting");

    seedNeighbor(&dev.nwk, NEIGHBOR, NWK_DEVICE_ROUTER, 1, NWK_REL_UNAUTHENTICATED_CHILD);
    child = neighborAt(&dev.nwk, NEIGHBOR);
    child->extendedAddress = JOIN_CHILD_IEEE;
    child->ieeeKnown = 1;
    dev.nwk.joinPendingInUse[0] = 1;

    Nwk_JoinCommStatus(&dev.nwk, &status);

    Test_Expect(Nwk_JoinResponsesDelivered(&dev.nwk) == 1 && Nwk_PollJoinIndications(&dev.nwk, inds, 2) == 1
                && inds[0].networkAddress == NEIGHBOR && inds[0].extendedAddress == JOIN_CHILD_IEEE,
                "and a delivered answer is indicated once, for the child it addressed");
    Test_Expect(neighborAt(&dev.nwk, NEIGHBOR) != 0, "which keeps its entry");
    Test_Expect(security.incoming[0].inUse == 0,
                "and the counter the parent held for the child is forgotten, so a device that restarted it at 0 is heard");
}

/* 3.6.1.6.1.1's next-parent rule: the joiner, an end device holding no address yet, whose Association Requests go
   unacknowledged (Table 10-107's NO_ACK, 0xe9), and the parents its discovery table holds. */
#define JOIN_NO_ACK 0xe9
#define JOIN_CHANNEL 15
#define JOIN_OTHER_CHANNEL 20

static void joinerRig(Test_BandA *rig, uint32_t attempts)
{
    rigAt(rig, 0xffff, 0xffff, NWK_DEVICE_END_DEVICE, 1);
    setOwnIeee(rig, JOIN_NEW_IEEE);
    rig->nwk.cfg.maxInitialJoinParentAttempts = attempts;
}

static void joinerParent(Test_BandA *rig, uint16_t shortAddress, uint32_t channel, int permit, uint64_t extendedPanId)
{
    Nwk_JoinParent row;
    uint32_t i;

    Zb_memset(&row, 0, (uint32_t)sizeof row);

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        row.extendedPanId[i] = (uint8_t)(extendedPanId >> (i * 8));

    row.panId = PAN_ID;
    row.shortAddress = shortAddress;
    row.shortKnown = 1;
    row.extendedAddress = JOIN_PARENT_IEEE + shortAddress;
    row.channel = channel;
    row.associationPermit = permit;
    row.deviceType = NWK_DEVICE_ROUTER;
    row.rxOnWhenIdle = 1;

    Test_ExpectStatus(Nwk_JoinParentAdd(&rig->nwk, &row), ZB_OK, "the discovery table takes the entry");
}

static Nwk_JoinRequestParameters joinerRequest(uint32_t scanChannels)
{
    Nwk_JoinRequestParameters req;
    uint32_t i;

    Zb_memset(&req, 0, (uint32_t)sizeof req);

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        req.extendedPanId[i] = (uint8_t)(JOIN_EXTENDED_PAN_ID >> (i * 8));

    req.scanChannels = scanChannels;
    req.capability.rxOnWhenIdle = 1;
    req.capability.allocateAddress = 1;

    return req;
}

static void joinerUnanswered(Test_BandA *rig, uint32_t count)
{
    Loopback_Outcome outcomes[LOOPBACK_TX_MAX];
    uint32_t i;

    Zb_memset(outcomes, 0, (uint32_t)sizeof outcomes);

    for (i = 0; i < count; i++)
        outcomes[i].isAcked = 0;

    LoopbackRadio_ScriptOutcomes(&rig->model, outcomes, count);
}

/* The short destination of the `index`th frame the air log holds: Figure 10-1's header, the address after the PAN */
static uint16_t joinerAirTo(const Air *air, uint32_t index, uint32_t count)
{
    if (index >= count || ((air[index].bytes[1] >> 2) & 0x03) != 0x02)
        return 0xffff;

    return (uint16_t)(air[index].bytes[5] | (air[index].bytes[6] << 8));
}

/* An attempt that fails moves to the next parent the request allows, and the bound ends the join: entries that
   do not permit, belong to another network or sit on a channel the request did not name are passed over. */
void caseJoinTriesTheNextParent(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    joinerRig(&dev, 2);
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0004, JOIN_CHANNEL, 0, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0005, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID + 1);
    joinerParent(&dev, 0x0006, JOIN_OTHER_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0002, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0003, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerUnanswered(&dev, 3);

    jr = joinerRequest((uint32_t)1 << JOIN_CHANNEL);

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 0), ZB_OK, "the join asks the first parent");
    harvestAir(&dev.model, air, &count);
    Test_Expect(joinerAirTo(air, 0, count) == 0x0001 && count == 1, "whose Association Request is on the air");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "the step collects its NO_ACK");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 0, "and owes no confirm while a parent is left to try");
    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_ASSOCIATING, "the join goes on");
    Test_Expect(joinerAirTo(air, 1, count) == 0x0002 && count == 2,
                "with the next parent the request allows, past one that refuses, one of another network and one off the channel named");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 2), ZB_OK, "the second attempt fails as well");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "and nwkMaxInitialJoinParentAttempts, 2 here, ends the join");
    Test_ExpectCount(jc.status, JOIN_NO_ACK, "with the last attempt's status");
    Test_Expect(jc.parentShort == 0x0002 && jc.parentExtended == JOIN_PARENT_IEEE + 0x0002,
                "naming the parent that attempt addressed");
    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_FAILED, "the join has failed");
    Test_ExpectCount(count, 2, "and the third parent was never asked");
}

/* nwkMaxInitialJoinParentAttempts' default is 1: a second parent in the table is not tried */
void caseJoinDefaultTriesOneParent(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    joinerRig(&dev, 0);
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0002, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerUnanswered(&dev, 2);

    jr = joinerRequest(0);

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 0), ZB_OK, "the join asks the first parent");
    harvestAir(&dev.model, air, &count);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "whose request goes unacknowledged");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "and a config that names 0 attempts takes the default, one");
    Test_Expect(jc.status == JOIN_NO_ACK && jc.parentShort == 0x0001, "the confirm is the first parent's NO_ACK");
    Test_ExpectCount(count, 1, "and the second parent was never asked");
}

/* The rule moves to the next parent, never back to the same one: one parent is one attempt, whatever the bound */
void caseJoinOneParentIsNotRetried(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    joinerRig(&dev, 3);
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerUnanswered(&dev, 3);

    jr = joinerRequest(0);

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 0), ZB_OK, "the join asks the one parent");
    harvestAir(&dev.model, air, &count);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "whose request goes unacknowledged");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "and with no potential parent left the join ends");
    Test_ExpectCount(jc.status, JOIN_NO_ACK, "on that attempt's status");
    Test_ExpectCount(count, 1, "after one attempt, though the bound allows three");
}

/* A next parent the MAC refuses ends the join at once with the failure before it; nothing is re-asked */
void caseJoinNextParentRefusedEndsTheJoin(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    joinerRig(&dev, 2);
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0002, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerUnanswered(&dev, 1);

    jr = joinerRequest(0);

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 0), ZB_OK, "the join asks the first parent");
    harvestAir(&dev.model, air, &count);
    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_DEVICE, 1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "its NO_ACK arrives and the radio refuses the next request");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(LoopbackRadio_Refusals(&dev.model), 1, "the second parent's request was offered and refused");
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "so the join ends there");
    Test_Expect(jc.status == JOIN_NO_ACK && jc.parentShort == 0x0001,
                "with the first parent's NO_ACK, the last attempt that went out");
    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_FAILED, "the join has failed");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 2), ZB_OK, "and a later step");
    harvestAir(&dev.model, air, &count);
    Test_Expect(count == 1 && Nwk_PollJoinConfirm(&dev.nwk, &jc) == 0, "sends nothing and confirms nothing more");
}

/* The rejoin's half of the rule, nwkMaxRejoinParentAttempts' default 3: a device on the network at 0x2345 whose
   rejoin requests go to the discovery entries of the network it names, and answers that come back or do not. */
#define JOIN_NO_DATA 0xeb

static void rejoinerRig(Test_BandA *rig, uint32_t attempts)
{
    rigAt(rig, 0x2345, PAN_ID, NWK_DEVICE_END_DEVICE, 1);
    setOwnIeee(rig, JOIN_OWN_IEEE);
    rig->nwk.cfg.maxRejoinParentAttempts = attempts;
}

static void rejoinerAnswer(Test_BandA *rig, uint64_t from, uint8_t status, uint32_t nowMs)
{
    Nwk_Frame frame;
    uint8_t payload[JOIN_RESPONSE_OCTETS] = { 0x07, 0x45, 0x23, 0x00 };

    payload[3] = status;
    rejoinResponseFrame(&frame, from);

    Test_Expect(Nwk_JoinHandleCommand(&rig->nwk, &frame, payload, (uint32_t)sizeof payload, nowMs) == 1,
                "the rejoin response is a command the layer consumes");
}


/* One MAC command `frame` describes, closed by its footer and put in front of the device's MAC. */
static void joinInjectCommand(Test_BandA *rig, Mac_Frame *frame, const uint8_t *content, uint32_t contentLen)
{
    Loopback_FrameSpec spec;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t len = 0;

    frame->frameType = MAC_FRAME_TYPE_COMMAND;

    Test_ExpectStatus(MacFrame_Compose(frame, content, contentLen, bytes, RADIO_MPDU_MAX, &len), ZB_OK,
                      "a MAC command this stack composes");
    Test_ExpectStatus(MacFrame_AppendFcs(bytes, len, RADIO_MPDU_MAX, &len), ZB_OK, "closed by its footer");

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = len;
    spec.bytes = bytes;
    spec.rssiDbm = -70;
    spec.lqi = 200;
    spec.stampTicks = 1;

    Test_ExpectStatus(LoopbackRadio_Inject(&rig->model, &spec, 1), ZB_OK, "put in front of the MAC");
}

/* 6101-6102 with 6168: RejoinNetwork 0x01 is the MAC's orphaning procedure, an Orphan Notification on the device's
   channel, and the coordinator's realignment joins it at the address it names, under that coordinator. */
void caseOrphanRejoinTakesTheRealignment(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters rr;
    Nwk_JoinConfirmParameters jc;
    Nwk_NeighborTableEntry *parent;
    Mac_Frame frame;
    Air air[AIR_LOG_MAX];
    uint8_t content[8] = { MAC_CMD_COORDINATOR_REALIGNMENT, PAN_ID & 0xff, PAN_ID >> 8, 0x00, 0x00, 0x00, 0x45, 0x23 };
    uint32_t count = 0;
    uint32_t nowMs;

    rigAt(&dev, 0x1fa1, PAN_ID, NWK_DEVICE_END_DEVICE, 1);
    setOwnIeee(&dev, JOIN_OWN_IEEE);
    content[5] = (uint8_t)Mac_Pib(&dev.mac)->channel;

    rr = joinerRequest(0);
    rr.rejoinNetwork = 0x01;

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &rr, 0), ZB_OK, "an orphan asks to rejoin, holding no parent");

    for (nowMs = 0; nowMs < 20 && count == 0; nowMs++)
    {
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, nowMs), ZB_OK, "a turn of the orphan scan");
        harvestAir(&dev.model, air, &count);
    }

    Test_Expect(count == 1 && air[0].len >= 16 && air[0].bytes[15] == MAC_CMD_ORPHAN_NOTIFICATION,
                "and an Orphan Notification is on the air (10.20.3.1)");

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.ackRequest = 1;
    frame.destAddrMode = MAC_ADDR_EXTENDED;
    frame.destPan = 0xffff;
    frame.destExtended = JOIN_OWN_IEEE;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.srcPan = PAN_ID;
    frame.srcExtended = JOIN_PARENT_IEEE;
    frame.seq = 0x61;
    joinInjectCommand(&dev, &frame, content, (uint32_t)sizeof content);

    for (; nowMs < 40 && Nwk_JoinStateOf(&dev.nwk) == NWK_JOIN_ORPHANING; nowMs++)
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, nowMs), ZB_OK, "a turn");

    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_JOINED, "the realignment joins the device");
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "with one confirm");
    Test_Expect(jc.status == NWK_JOIN_STATUS_SUCCESS && jc.networkAddress == 0x2345 && jc.parentShort == 0x0000
                    && jc.parentExtended == JOIN_PARENT_IEEE,
                "naming the address the realignment gave and the coordinator that sent it");
    Test_ExpectCount(Mac_Pib(&dev.mac)->shortAddress, 0x2345, "which the PIB holds (10.20.1)");
    parent = neighborAt(&dev.nwk, 0x0000);
    Test_Expect(parent != 0 && parent->relationship == NWK_REL_PARENT && parent->extendedAddress == JOIN_PARENT_IEEE,
                "and the neighbor table holds that coordinator as the parent");
}

/* An orphan scan nobody answers ends with the scan's NO_BEACON on the confirm (6163-6165). */
void caseOrphanRejoinUnanswered(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters rr;
    Nwk_JoinConfirmParameters jc;
    uint32_t nowMs;

    rigAt(&dev, 0x1fa1, PAN_ID, NWK_DEVICE_END_DEVICE, 1);
    setOwnIeee(&dev, JOIN_OWN_IEEE);

    rr = joinerRequest(0);
    rr.rejoinNetwork = 0x01;

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &rr, 0), ZB_OK, "an orphan asks to rejoin");

    for (nowMs = 0; nowMs < 2 * MAC_RESPONSE_WAIT_MS && Nwk_JoinStateOf(&dev.nwk) == NWK_JOIN_ORPHANING; nowMs++)
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, nowMs), ZB_OK, "a turn");

    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_FAILED, "nothing answers");
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "and the confirm is owed");
    Test_ExpectCount(jc.status, 0xea, "with the scan's NO_BEACON");
}

/* 5199-5205 and 5283: a parent realigns an orphan it holds as a child to the address it has, and sends nothing to
   one it does not hold (10.20.2.1). */
void caseParentRealignsItsOrphanedChild(void)
{
    Test_BandA dev;
    Nwk_NeighborTableEntry *child;
    Mac_Frame frame;
    Mac_Frame header;
    Mac_FrameRefusal refusal = MAC_FRAME_REFUSAL_NONE;
    Air air[AIR_LOG_MAX];
    const uint8_t *payload = 0;
    uint32_t payloadLen = 0;
    uint8_t content[1] = { MAC_CMD_ORPHAN_NOTIFICATION };
    uint32_t count = 0;

    rigAt(&dev, 0x0000, PAN_ID, NWK_DEVICE_COORDINATOR, 1);
    setOwnIeee(&dev, JOIN_PARENT_IEEE);
    joinPermit(&dev);
    Test_ExpectStatus(Nwk_SetBeaconInfo(&dev.nwk, &dev.nwk.beaconInfo, 0), ZB_OK, "its permit closed again");

    seedNeighbor(&dev.nwk, JOIN_CHILD, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);
    child = neighborAt(&dev.nwk, JOIN_CHILD);
    child->extendedAddress = JOIN_CHILD_IEEE;
    child->ieeeKnown = 1;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.panIdCompression = 1;
    frame.destAddrMode = MAC_ADDR_SHORT;
    frame.destPan = 0xffff;
    frame.destShort = 0xffff;
    frame.srcAddrMode = MAC_ADDR_EXTENDED;
    frame.srcExtended = JOIN_CHILD_IEEE + 1;
    frame.seq = 0x62;
    joinInjectCommand(&dev, &frame, content, (uint32_t)sizeof content);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "an orphan this parent does not hold");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "a turn");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, 0, "is sent nothing");
    Test_ExpectCount(dev.nwk.orphansUnknown, 1, "and counted");

    frame.srcExtended = JOIN_CHILD_IEEE;
    frame.seq = 0x63;
    joinInjectCommand(&dev, &frame, content, (uint32_t)sizeof content);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "its own child, orphaned");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 201), ZB_OK, "a turn");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, 1, "is sent one frame");
    Test_ExpectCount(dev.nwk.orphansRealigned, 1, "counted as a realignment");

    if (count != 1)
        return;

    Test_ExpectStatus(MacFrame_Parse(air[0].bytes, air[0].len, 1, &header, &payload, &payloadLen, &refusal), ZB_OK,
                      "a frame this MAC reads back");
    Test_Expect(header.destAddrMode == MAC_ADDR_EXTENDED && header.destExtended == JOIN_CHILD_IEEE && payloadLen == 8
                    && payload[0] == MAC_CMD_COORDINATOR_REALIGNMENT && payload[6] == (JOIN_CHILD & 0xff)
                    && payload[7] == (JOIN_CHILD >> 8),
                "the realignment to the child, naming the address it has");
}

/* 7935-7936 turn a joined router's parent into a sibling, and 8059-8060 still have a rejoin go to the most recent
   potential parent: a 0x02 rejoin naming no network finds it by the address it joined through. */
void caseRejoinRouterFindsTheSiblingItJoined(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters rr;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    rigAt(&dev, 0x2345, PAN_ID, NWK_DEVICE_ROUTER, 1);
    setOwnIeee(&dev, JOIN_OWN_IEEE);
    seedNeighbor(&dev.nwk, 0x0001, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    Nwk_NeighborOf(dev.nwk.neighbors, 0x0001)->extendedAddress = JOIN_PARENT_IEEE + 0x0001;
    Nwk_NeighborOf(dev.nwk.neighbors, 0x0001)->ieeeKnown = 1;
    dev.nwk.joinParentShort = 0x0001;
    dev.nwk.joinParentShortKnown = 1;

    rr = joinerRequest(0);
    rr.rejoinNetwork = 0x02;
    Zb_memset(rr.extendedPanId, 0, (uint32_t)sizeof rr.extendedPanId);

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &rr, 0), ZB_OK, "a joined router asks to rejoin");
    harvestAir(&dev.model, air, &count);
    Test_Expect(count == 1 && joinerAirTo(air, 0, count) == 0x0001, "and its request goes to the device it joined");
}

/* A timed-out request and a refusal each move the rejoin to the next parent, an answer from a parent it has left is
   dropped, and the bound ends it with the last attempt's NO_DATA */
void caseRejoinTriesTheNextParent(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters rr;
    Nwk_JoinConfirmParameters jc;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;
    uint32_t t1 = MAC_RESPONSE_WAIT_MS + 1;

    rejoinerRig(&dev, 0);
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0002, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0003, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0004, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);

    rr = joinerRequest(0);
    rr.rejoinNetwork = 0x02;

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &rr, 0), ZB_OK, "the rejoin asks the network's first parent");
    harvestAir(&dev.model, air, &count);
    Test_Expect(joinerAirTo(air, 0, count) == 0x0001 && count == 1, "whose request is on the air");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, t1), ZB_OK, "macResponseWaitTime passes with no answer");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 0, "and no confirm is owed while a parent is left");
    Test_Expect(joinerAirTo(air, 1, count) == 0x0002 && count == 2, "the request goes to the next parent");

    rejoinerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, NWK_JOIN_STATUS_SUCCESS, t1 + 5);
    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_REJOINING,
                     "an answer from the parent it left is not from the most recent potential parent, and is dropped");

    rejoinerAnswer(&dev, JOIN_PARENT_IEEE + 0x0002, 0x01, t1 + 10);
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 0, "the second parent's refusal owes no confirm either");
    Test_Expect(joinerAirTo(air, 2, count) == 0x0003 && count == 3, "and moves the rejoin to the third");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, t1 + 10 + MAC_RESPONSE_WAIT_MS + 1), ZB_OK, "the third stays silent");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "and nwkMaxRejoinParentAttempts' default, 3, ends the rejoin");
    Test_Expect(jc.status == JOIN_NO_DATA && jc.parentExtended == JOIN_PARENT_IEEE + 0x0003,
                "with the third attempt's NO_DATA, naming that parent");
    Test_ExpectCount(count, 3, "and the fourth parent was never asked");
}

/* The next parent's answer is the rejoin's: the confirm and the parent entry name the parent that answered */
void caseRejoinNextParentAnswers(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters rr;
    Nwk_JoinConfirmParameters jc;
    Nwk_NeighborTableEntry *parent;
    uint32_t t1 = MAC_RESPONSE_WAIT_MS + 1;

    rejoinerRig(&dev, 0);
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0002, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);

    rr = joinerRequest(0);
    rr.rejoinNetwork = 0x02;

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &rr, 0), ZB_OK, "the rejoin asks the first parent");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, t1), ZB_OK, "which does not answer, so the second is asked");

    rejoinerAnswer(&dev, JOIN_PARENT_IEEE + 0x0002, NWK_JOIN_STATUS_SUCCESS, t1 + 10);
    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_JOINED, "the second parent's answer rejoins the device");
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "and the one confirm is owed");
    Test_Expect(jc.status == NWK_JOIN_STATUS_SUCCESS && jc.parentShort == 0x0002
                && jc.parentExtended == JOIN_PARENT_IEEE + 0x0002, "naming the parent that answered");
    parent = neighborAt(&dev.nwk, 0x0002);
    Test_Expect(parent != 0 && parent->relationship == NWK_REL_PARENT, "which the neighbor table now holds as the parent");
}

/* A rejoin that names no network goes to the parent the device holds, the one candidate it has: one attempt */
void caseRejoinOfTheParentItHoldsIsOneAttempt(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters rr;
    Nwk_JoinConfirmParameters jc;
    Nwk_NeighborTableEntry *held;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;
    uint32_t i;

    rejoinerRig(&dev, 0);
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    seedNeighbor(&dev.nwk, 0x0000, NWK_DEVICE_COORDINATOR, 1, NWK_REL_PARENT);
    held = neighborAt(&dev.nwk, 0x0000);
    held->extendedAddress = JOIN_PARENT_IEEE;
    held->ieeeKnown = 1;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        dev.nwk.joinExtendedPanId[i] = (uint8_t)(JOIN_EXTENDED_PAN_ID >> (i * 8));

    rr = joinerRequest(0);
    rr.rejoinNetwork = 0x02;
    Zb_memset(rr.extendedPanId, 0, RADIO_ADDR_LEN);

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &rr, 0), ZB_OK, "the rejoin asks the parent the device holds");
    harvestAir(&dev.model, air, &count);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, MAC_RESPONSE_WAIT_MS + 1), ZB_OK, "which does not answer");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "and the rejoin ends at once");
    Test_Expect(jc.status == JOIN_NO_DATA && count == 1 && joinerAirTo(air, 0, count) == 0x0000,
                "with NO_DATA after the one request, though a discovery entry of the network is there");
}

/* A request the next parent cannot be sent ends the rejoin there, with the timeout of the attempt before it */
void caseRejoinNextParentRefusedEndsTheRejoin(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters rr;
    Nwk_JoinConfirmParameters jc;

    rejoinerRig(&dev, 0);
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0002, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);

    rr = joinerRequest(0);
    rr.rejoinNetwork = 0x02;

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &rr, 0), ZB_OK, "the rejoin asks the first parent");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "whose request is collected");
    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_DEVICE, 1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, MAC_RESPONSE_WAIT_MS + 1), ZB_OK,
                      "no answer comes, and the radio refuses the request to the second parent");
    Test_ExpectCount(LoopbackRadio_Refusals(&dev.model), 1, "that request was offered and refused");
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "so the rejoin ends there");
    Test_Expect(jc.status == JOIN_NO_DATA && jc.parentExtended == JOIN_PARENT_IEEE + 0x0001,
                "with the first parent's NO_DATA, the last attempt that went out");
    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_FAILED, "the rejoin has failed");
}

/* Each rejoin request goes out on its parent's channel, as the association does, and an entry on no channel this
   layer joins is passed over */
void caseRejoinFollowsTheParentsChannel(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters rr;
    Nwk_JoinConfirmParameters jc;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    rejoinerRig(&dev, 0);
    joinerParent(&dev, 0x0003, 0, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0002, JOIN_OTHER_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);

    rr = joinerRequest(0);
    rr.rejoinNetwork = 0x02;

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &rr, 0), ZB_OK, "the rejoin asks the first parent on a channel it joins");
    harvestAir(&dev.model, air, &count);
    Test_Expect(joinerAirTo(air, 0, count) == 0x0001 && Mac_Pib(&dev.mac)->channel == JOIN_CHANNEL,
                "past the entry on channel 0, and with the radio moved to that parent's channel");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, MAC_RESPONSE_WAIT_MS + 1), ZB_OK, "no answer comes");
    harvestAir(&dev.model, air, &count);
    Test_Expect(joinerAirTo(air, 1, count) == 0x0002 && Mac_Pib(&dev.mac)->channel == JOIN_OTHER_CHANNEL,
                "so the next parent is asked, on its own channel");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 2 * (MAC_RESPONSE_WAIT_MS + 1)), ZB_OK, "and it stays silent too");
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "the list has run out");
    Test_ExpectCount(jc.channel, JOIN_OTHER_CHANNEL, "and the confirm names the channel the last attempt ran on");
}

/* The commissioning request's capability octet is Table 3-71's, the association's own layout: a router on battery
   whose receiver stays on, asking for an address, is 0x8a */
void caseCommissioningRequestCapabilityOctet(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_Frame frame;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
    const uint8_t *npdu;

    joinerRig(&dev, 0);
    dev.nwk.cfg.attachMechanism = NWK_ATTACH_COMMISSIONING;
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);

    jr = joinerRequest(0);
    jr.capability.deviceType = 1;

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 0), ZB_OK, "the join goes out as a commissioning request");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, 1, "one frame on the air");

    npdu = air[0].bytes + NPDU_OFFSET;
    Test_ExpectStatus(NwkFrame_Parse(npdu, npduLenOf(&air[0]), &frame, &payloadOffset, &payloadLen), ZB_OK,
                      "with a network header");
    Test_Expect(payloadLen >= 3 && npdu[payloadOffset] == NWK_CMD_NETWORK_COMMISSIONING_REQUEST
                && npdu[payloadOffset + 1] == NWK_COMMISSIONING_INITIAL_JOIN,
                "carrying the commissioning request, an Initial Join");
    Test_ExpectCount(npdu[payloadOffset + 2], 0x8a,
                     "whose capability is bit 1 for the router, bit 3 for the receiver and bit 7 for the address");
}

/* 3.6.1.6.1.1's choice for an Initial Join when the configuration forces none: the parent whose beacon carried the R23
   appendix is asked by Network Commissioning, one without it by association, and a forced association overrides. */
static uint8_t attachCommandOf(int r23Appendix, uint32_t mechanism)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_Frame frame;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
    const uint8_t *npdu;

    joinerRig(&dev, 0);
    dev.nwk.cfg.attachMechanism = mechanism;
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    dev.nwk.joinParents[0].r23Appendix = r23Appendix;

    jr = joinerRequest(0);
    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 0), ZB_OK, "the join goes out");
    harvestAir(&dev.model, air, &count);

    if (count != 1)
        return 0;

    if ((air[0].bytes[0] & 0x07) == MAC_FRAME_TYPE_COMMAND)
        return MAC_CMD_ASSOCIATION_REQUEST;

    npdu = air[0].bytes + NPDU_OFFSET;

    if (NwkFrame_Parse(npdu, npduLenOf(&air[0]), &frame, &payloadOffset, &payloadLen) != ZB_OK || payloadLen == 0)
        return 0;

    return npdu[payloadOffset];
}

void caseTheBeaconChoosesTheAttachMechanism(void)
{
    Test_ExpectCount(attachCommandOf(1, NWK_ATTACH_BY_BEACON), NWK_CMD_NETWORK_COMMISSIONING_REQUEST,
                     "a parent whose beacon carried the R23 appendix is asked by Network Commissioning (rule 1)");
    Test_ExpectCount(attachCommandOf(0, NWK_ATTACH_BY_BEACON), MAC_CMD_ASSOCIATION_REQUEST,
                     "one without it by MAC association (rule 3)");
    Test_ExpectCount(attachCommandOf(1, NWK_ATTACH_ASSOCIATION), MAC_CMD_ASSOCIATION_REQUEST,
                     "and a configuration that forces association overrides the appendix");
    Test_ExpectCount(attachCommandOf(0, NWK_ATTACH_COMMISSIONING), NWK_CMD_NETWORK_COMMISSIONING_REQUEST,
                     "as one that forces commissioning overrides its absence");
}

/* The commissioning child, the joiner rig with 3.4.14's attach chosen, asking the one parent at 0x0001 */
static void commissionerRig(Test_BandA *rig, int rxOnWhenIdle, Nwk_JoinRequestParameters *jr)
{
    joinerRig(rig, 0);
    rig->nwk.cfg.attachMechanism = NWK_ATTACH_COMMISSIONING;
    joinerParent(rig, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);

    *jr = joinerRequest(0);
    jr->capability.rxOnWhenIdle = rxOnWhenIdle ? 1 : 0;

    Test_ExpectStatus(Nwk_JoinRequest(&rig->nwk, jr, 0), ZB_OK, "the join goes out as a commissioning request");
}

/* 3.4.15's answer as the child receives it, from `from` to `to`, naming `address` with `status` */
static void commissionerAnswer(Test_BandA *rig, uint64_t from, uint64_t to, uint16_t address, uint8_t status)
{
    Nwk_Frame frame;
    uint8_t payload[1 + NWK_COMMISSIONING_RESPONSE_OCTETS];

    payload[0] = NWK_CMD_NETWORK_COMMISSIONING_RESPONSE;
    payload[1] = (uint8_t)(address & 0xff);
    payload[2] = (uint8_t)(address >> 8);
    payload[3] = status;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = NWK_FRAME_TYPE_COMMAND;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.destAddr = Mac_Pib(&rig->mac)->shortAddress;
    frame.srcAddr = 0x0001;
    frame.radius = 1;
    frame.srcIeeePresent = 1;
    frame.srcIeee = from;
    frame.destIeeePresent = 1;
    frame.destIeee = to;

    Test_Expect(Nwk_JoinHandleCommand(&rig->nwk, &frame, payload, (uint32_t)sizeof payload, 50) == 1,
                "the commissioning response is a command the layer consumes");
}

/* The command the `index`th frame on the air carries, and the commissioning type behind it when it is one. */
static uint8_t rejoinCommandAt(const Air *air, uint32_t index, uint32_t count, uint8_t *type, uint16_t *source)
{
    Nwk_Frame frame;
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
    const uint8_t *npdu;

    if (index >= count)
        return 0;

    npdu = air[index].bytes + NPDU_OFFSET;

    if (NwkFrame_Parse(npdu, npduLenOf(&air[index]), &frame, &payloadOffset, &payloadLen) != ZB_OK || payloadLen < 2)
        return 0;

    *type = npdu[payloadOffset + 1];
    *source = frame.srcAddr;

    return npdu[payloadOffset];
}

/* Rule 1 and rule 2 of 7971-7984 for a rejoin: the parent's beacon chooses between Commissioning Type 0x01 and 0x06 */
static uint8_t rejoinCommandOf(int r23Appendix, uint32_t mechanism, uint8_t *type)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters rr;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;
    uint16_t source = 0;

    rejoinerRig(&dev, 0);
    dev.nwk.cfg.attachMechanism = mechanism;
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    dev.nwk.joinParents[0].r23Appendix = r23Appendix;

    rr = joinerRequest(0);
    rr.rejoinNetwork = 0x02;

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &rr, 0), ZB_OK, "the rejoin goes out");
    harvestAir(&dev.model, air, &count);

    *type = 0xff;

    return count == 1 ? rejoinCommandAt(air, 0, count, type, &source) : 0;
}

void caseTheBeaconChoosesTheRejoinMechanism(void)
{
    uint8_t type = 0;

    Test_ExpectCount(rejoinCommandOf(1, NWK_ATTACH_BY_BEACON, &type), NWK_CMD_NETWORK_COMMISSIONING_REQUEST,
                     "a parent whose beacon carried the R23 appendix is asked by Network Commissioning (7971-7979)");
    Test_ExpectCount(type, NWK_COMMISSIONING_REJOIN, "with Commission Type 0x01, Rejoin");
    Test_ExpectCount(rejoinCommandOf(0, NWK_ATTACH_BY_BEACON, &type), NWK_CMD_REJOIN_REQUEST,
                     "one without it by the NWK Rejoin Request (7980-7983)");
    Test_ExpectCount(rejoinCommandOf(1, NWK_ATTACH_ASSOCIATION, &type), NWK_CMD_REJOIN_REQUEST,
                     "and a configuration that forces the older mechanism overrides the appendix");
    Test_ExpectCount(rejoinCommandOf(0, NWK_ATTACH_COMMISSIONING, &type), NWK_CMD_NETWORK_COMMISSIONING_REQUEST,
                     "as one that forces commissioning overrides its absence");
}

/* The answer to a Commissioning Rejoin is the rejoin's: a refusal moves to the next parent by that parent's own
   mechanism, 0xF0 retries once at the address it names, and success rejoins the device at that address. */
void caseCommissioningRejoinIsAnswered(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters rr;
    Nwk_JoinConfirmParameters jc;
    Nwk_NeighborTableEntry *parent;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;
    uint16_t source = 0;
    uint8_t type = 0;

    rejoinerRig(&dev, 0);
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0002, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    dev.nwk.joinParents[0].r23Appendix = 1;
    dev.nwk.joinParents[1].r23Appendix = 0;

    rr = joinerRequest(0);
    rr.rejoinNetwork = 0x02;

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &rr, 0), ZB_OK, "the rejoin asks the first parent by commissioning");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(rejoinCommandAt(air, 0, count, &type, &source), NWK_CMD_NETWORK_COMMISSIONING_REQUEST,
                     "its request is a commissioning request");

    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0002, JOIN_OWN_IEEE, 0x2345, 0);
    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_REJOINING,
                     "an answer from a parent it did not ask is dropped (8056-8061)");

    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, JOIN_OWN_IEEE, 0x3456, NWK_COMMISSIONING_STATUS_ADDRESS_CONFLICT);
    harvestAir(&dev.model, air, &count);
    Test_Expect(rejoinCommandAt(air, 1, count, &type, &source) == NWK_CMD_NETWORK_COMMISSIONING_REQUEST
                    && source == 0x3456 && joinerAirTo(air, 1, count) == 0x0001,
                "0xF0 has the same parent asked again, from the address it named (7737-7738)");

    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, JOIN_OWN_IEEE, 0xffff, MAC_ASSOC_STATUS_PAN_AT_CAPACITY);
    harvestAir(&dev.model, air, &count);
    Test_Expect(rejoinCommandAt(air, 2, count, &type, &source) == NWK_CMD_REJOIN_REQUEST
                    && joinerAirTo(air, 2, count) == 0x0002,
                "a refusal moves the rejoin to the next parent, which has no appendix and is asked by 0x06");

    rejoinerAnswer(&dev, JOIN_PARENT_IEEE + 0x0002, NWK_JOIN_STATUS_SUCCESS, 100);
    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_JOINED, "whose answer rejoins the device");
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "with one confirm");
    Test_Expect(jc.status == NWK_JOIN_STATUS_SUCCESS && jc.parentShort == 0x0002, "naming the parent that answered");

    rejoinerRig(&dev, 0);
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    dev.nwk.joinParents[0].r23Appendix = 1;

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &rr, 200), ZB_OK, "a second rejoin, by commissioning");
    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, JOIN_OWN_IEEE, 0x2345, 0);
    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_JOINED, "is rejoined by the commissioning response");
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "with one confirm");
    Test_Expect(jc.status == NWK_JOIN_STATUS_SUCCESS && jc.networkAddress == 0x2345 && jc.parentShort == 0x0001,
                "naming its address and the parent");
    parent = neighborAt(&dev.nwk, 0x0001);
    Test_Expect(parent != 0 && parent->relationship == NWK_REL_PARENT, "which the neighbor table holds as the parent");
}

/* A parent heard only by a beacon from its short address has no IEEE address in its entry: the request carries no
   destination IEEE (3.4.6.2, 7666-7667), and the answer from that short address is the one 8059-8060 wait for, by
   0x06 and by commissioning alike, its own source IEEE then naming the parent. */
void caseRejoinToAParentKnownByItsShortAddress(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters rr;
    Nwk_JoinConfirmParameters jc;
    Nwk_Frame frame;
    Nwk_Frame parsed;
    Air air[AIR_LOG_MAX];
    uint8_t payload[JOIN_RESPONSE_OCTETS] = { 0x07, 0x45, 0x23, 0x00 };
    uint32_t count = 0;
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
    int appendix;

    for (appendix = 0; appendix <= 1; appendix++)
    {
        rejoinerRig(&dev, 0);
        joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
        dev.nwk.joinParents[0].extendedAddress = 0;
        dev.nwk.joinParents[0].r23Appendix = appendix;

        rr = joinerRequest(0);
        rr.rejoinNetwork = 0x02;
        count = 0;

        Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &rr, 0), ZB_OK, "the rejoin asks a parent it knows by address");
        harvestAir(&dev.model, air, &count);
        Test_Expect(count == 1
                        && NwkFrame_Parse(air[0].bytes + NPDU_OFFSET, npduLenOf(&air[0]), &parsed, &payloadOffset,
                                          &payloadLen) == ZB_OK
                        && parsed.destIeeePresent == 0,
                    "and its request names no destination IEEE it does not know");

        if (appendix)
            commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, JOIN_OWN_IEEE, 0x2345, 0);
        else
        {
            rejoinResponseFrame(&frame, JOIN_PARENT_IEEE + 0x0001);
            frame.srcAddr = 0x0001;
            Test_Expect(Nwk_JoinHandleCommand(&dev.nwk, &frame, payload, (uint32_t)sizeof payload, 50) == 1,
                        "the rejoin response is a command the layer consumes");
        }

        Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_JOINED, "the answer from that address rejoins the device");
        Test_Expect(Nwk_PollJoinConfirm(&dev.nwk, &jc) == 1 && jc.parentExtended == JOIN_PARENT_IEEE + 0x0001,
                    "and the confirm names the parent by the IEEE address its answer carried");
    }
}

/* The request borrows the parent's PAN and channel and a claimed address; with no answer in macResponseWaitTime the
   join ends with NO_DATA and the PIB is given back, so the device can ask again */
void caseCommissioningJoinTimesOut(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    const Radio_Pib *pib;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    commissionerRig(&dev, 1, &jr);
    harvestAir(&dev.model, air, &count);

    pib = Mac_Pib(&dev.mac);
    Test_Expect(pib->panId == PAN_ID && pib->channel == JOIN_CHANNEL && pib->shortAddress < 0xfff8,
                "the PIB holds the parent's PAN and channel and the address the request claims");
    Test_ExpectCount(Nwk_IsPartOfNetwork(&dev.nwk), 0, "which does not make the device a member");
    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 1), ZB_ERR_BUSY, "and a second join is busy, not refused as a member's");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, MAC_ASSOC_POLL_DELAY_MS + 1), ZB_OK, "a step inside the wait");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, 1, "sends no poll: the receiver is on, so the answer comes directly");
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 0, "and owes no confirm yet");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, MAC_RESPONSE_WAIT_MS + 1), ZB_OK, "macResponseWaitTime passes with no answer");
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "so the join ends");
    Test_Expect(jc.status == JOIN_NO_DATA && jc.networkAddress == 0xffff && jc.parentShort == 0x0001
                && jc.parentExtended == JOIN_PARENT_IEEE + 0x0001 && jc.channel == JOIN_CHANNEL,
                "with NO_DATA, no address, and the parent and channel it asked on");
    Test_Expect(pib->panId == 0xffff && pib->shortAddress == 0xffff, "and the PIB's PAN and address are given back");
    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_FAILED, "the join has failed");

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, MAC_RESPONSE_WAIT_MS + 10), ZB_OK,
                      "so a new request is not refused as a member's");
}

/* An answer is the join's only when it comes from the parent asked and names this device; the one that does is the
   join, and an address other than the one claimed is the one the PIB keeps */
void caseCommissioningAnswerMustNameBothEnds(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;

    commissionerRig(&dev, 1, &jr);

    commissionerAnswer(&dev, JOIN_STRANGER_IEEE, JOIN_NEW_IEEE, 0x4321, 0x00);
    Test_Expect(Nwk_JoinStateOf(&dev.nwk) == NWK_JOIN_COMMISSIONING && Nwk_JoinCommandsDropped(&dev.nwk) == 1,
                "an answer from a device that was not asked is dropped");

    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, JOIN_STRANGER_IEEE, 0x4321, 0x00);
    Test_Expect(Nwk_JoinStateOf(&dev.nwk) == NWK_JOIN_COMMISSIONING && Nwk_JoinCommandsDropped(&dev.nwk) == 2,
                "as is one the parent addressed to another device (3.6.1.6.1.2)");

    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, JOIN_NEW_IEEE, 0x4321, 0x00);
    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_JOINED, "the parent's answer to this device is the join");
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "with its confirm");
    Test_Expect(jc.status == 0x00 && jc.networkAddress == 0x4321 && Mac_Pib(&dev.mac)->shortAddress == 0x4321,
                "SUCCESS for the address the answer named, which the PIB now holds");
    Test_ExpectCount(Nwk_IsPartOfNetwork(&dev.nwk), 1, "and the device is a member");

    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, JOIN_NEW_IEEE, 0x5678, 0x00);
    Test_Expect(Nwk_JoinCommandsDropped(&dev.nwk) == 3 && Mac_Pib(&dev.mac)->shortAddress == 0x4321,
                "a second answer, which nothing asked for, is dropped (3.6.1.10.6)");
}

/* A refusal ends the join with the parent's status, and gives the PIB back */
void caseCommissioningRefusalGivesThePibBack(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;

    commissionerRig(&dev, 1, &jr);

    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, JOIN_NEW_IEEE, 0xffff, 0x02);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "the parent's refusal ends the join");
    Test_Expect(jc.status == 0x02 && jc.networkAddress == 0xffff, "with Table 10-102's PAN_ACCESS_DENIED and no address");
    Test_Expect(Mac_Pib(&dev.mac)->panId == 0xffff && Mac_Pib(&dev.mac)->shortAddress == 0xffff,
                "and the PIB's PAN and address given back");
}

/* A joiner whose receiver rests asks the parent for its answer while the countdown runs (3.6.1.6.1.2) */
void caseCommissioningSleepyJoinerPolls(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    commissionerRig(&dev, 0, &jr);
    harvestAir(&dev.model, air, &count);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, MAC_ASSOC_POLL_DELAY_MS + 1), ZB_OK, "a step inside the wait");
    harvestAir(&dev.model, air, &count);
    Test_Expect(count == 2 && (air[1].bytes[0] & 0x07) == 0x03 && joinerAirTo(air, 1, count) == 0x0001
                && air[1].bytes[9] == 0x04,
                "sends a Data Request (MAC command 0x04) to the parent");
}

/* The source the `index`th logged frame's network header names */
static uint16_t commissionerSourceOf(const Air *air, uint32_t index)
{
    Nwk_Frame frame;
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;

    if (NwkFrame_Parse(air[index].bytes + NPDU_OFFSET, npduLenOf(&air[index]), &frame, &payloadOffset,
                       &payloadLen) != ZB_OK)
        return 0xffff;

    return frame.srcAddr;
}

/* An address conflict (0xF0) is asked once more, of the same parent, from the address its answer gave; that is not a
   new parent, so the default bound of one still allows it, and the answer to it is the join */
void caseCommissioningConflictAsksAgain(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    commissionerRig(&dev, 1, &jr);
    harvestAir(&dev.model, air, &count);

    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, JOIN_NEW_IEEE, 0x4444, 0xf0);
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 0, "the conflict owes no confirm");
    Test_Expect(count == 2 && joinerAirTo(air, 1, count) == 0x0001 && commissionerSourceOf(air, 1) == 0x4444
                && Mac_Pib(&dev.mac)->shortAddress == 0x4444,
                "the request goes to the same parent again, from the address the answer gave (3.6.1.10.3)");

    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, JOIN_NEW_IEEE, 0x4444, 0x00);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "and its answer is the join");
    Test_Expect(jc.status == 0x00 && jc.networkAddress == 0x4444, "SUCCESS for that address");
}

/* A parent that conflicts twice has failed: with no other parent the join ends on 0xF0 and the PIB is given back */
void caseCommissioningSecondConflictFails(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;

    commissionerRig(&dev, 1, &jr);

    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, JOIN_NEW_IEEE, 0x4444, 0xf0);
    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, JOIN_NEW_IEEE, 0x5555, 0xf0);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "the second conflict ends the join");
    Test_Expect(jc.status == 0xf0 && jc.networkAddress == 0xffff, "with 0xF0 and no address");
    Test_Expect(Mac_Pib(&dev.mac)->panId == 0xffff && Mac_Pib(&dev.mac)->shortAddress == 0xffff,
                "and the PIB given back");
}

/* A commissioning attempt that fails moves to the next parent like an association does, on that parent's channel */
void caseCommissioningTriesTheNextParent(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    joinerRig(&dev, 2);
    dev.nwk.cfg.attachMechanism = NWK_ATTACH_COMMISSIONING;
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0002, JOIN_OTHER_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);

    jr = joinerRequest(0);
    jr.capability.rxOnWhenIdle = 1;

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 0), ZB_OK, "the join asks the first parent");
    harvestAir(&dev.model, air, &count);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, MAC_RESPONSE_WAIT_MS + 1), ZB_OK, "which does not answer");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 0, "so no confirm yet");
    Test_Expect(count == 2 && joinerAirTo(air, 1, count) == 0x0002 && Mac_Pib(&dev.mac)->channel == JOIN_OTHER_CHANNEL
                && commissionerSourceOf(air, 1) == commissionerSourceOf(air, 0),
                "the second parent is asked on its channel, from the same claimed address");

    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0002, JOIN_NEW_IEEE, 0xffff, 0x01);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "its refusal is the last attempt the bound allows");
    Test_Expect(jc.status == 0x01 && jc.parentShort == 0x0002 && Mac_Pib(&dev.mac)->shortAddress == 0xffff,
                "the confirm names that parent's status and the PIB is given back");
}

/* The conflict's re-send uses none of the bound: with two attempts allowed, a parent that conflicts and then refuses
   still leaves the second parent its attempt */
void caseCommissioningConflictIsNotAnAttempt(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    joinerRig(&dev, 2);
    dev.nwk.cfg.attachMechanism = NWK_ATTACH_COMMISSIONING;
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    joinerParent(&dev, 0x0002, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);

    jr = joinerRequest(0);
    jr.capability.rxOnWhenIdle = 1;

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 0), ZB_OK, "the join asks the first parent");
    harvestAir(&dev.model, air, &count);

    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, JOIN_NEW_IEEE, 0x4444, 0xf0);
    harvestAir(&dev.model, air, &count);
    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 0x0001, JOIN_NEW_IEEE, 0xffff, 0x01);
    harvestAir(&dev.model, air, &count);

    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 0, "the first parent's refusal after its conflict owes no confirm");
    Test_Expect(count == 3 && joinerAirTo(air, 2, count) == 0x0002,
                "and the second parent is asked: the conflict's re-send was not an attempt");
}

/* A request the transmit door has no room for is held and offered again each step, the PIB written once; the
   answer's countdown starts when the request goes out, not when it was asked for */
void caseCommissioningRequestHeldWhileTheDoorIsFull(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;
    uint32_t sentAt = 20;

    joinerRig(&dev, 0);
    dev.nwk.cfg.attachMechanism = NWK_ATTACH_COMMISSIONING;
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    jr = joinerRequest(0);
    jr.capability.rxOnWhenIdle = 1;
    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 2);

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 0), ZB_OK, "a request the door has no room for is taken");
    harvestAir(&dev.model, air, &count);
    Test_Expect(count == 0 && dev.nwk.joinOwedInUse == 1 && Nwk_JoinStateOf(&dev.nwk) == NWK_JOIN_COMMISSIONING
                && Mac_Pib(&dev.mac)->panId == PAN_ID, "and held, the join waiting with the PIB already written");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 10), ZB_OK, "the door refuses it once more");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, sentAt), ZB_OK, "and takes it");
    harvestAir(&dev.model, air, &count);
    Test_Expect(count == 1 && joinerAirTo(air, 0, count) == 0x0001 && dev.nwk.joinOwedInUse == 0,
                "so the request goes to the parent, once");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, MAC_RESPONSE_WAIT_MS + 5), ZB_OK, "macResponseWaitTime after the ask");
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 0, "is not the end: the countdown started when it went out");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, sentAt + MAC_RESPONSE_WAIT_MS + 1), ZB_OK, "macResponseWaitTime after the send");
    Test_Expect(Nwk_PollJoinConfirm(&dev.nwk, &jc) == 1 && jc.status == JOIN_NO_DATA, "is, with NO_DATA");
}

/* A held frame the door still refuses when the wait has passed is dropped and counted; the request's join then
   ends on its countdown and gives the PIB back */
void caseJoinFrameDroppedAfterTheWait(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    joinerRig(&dev, 0);
    dev.nwk.cfg.attachMechanism = NWK_ATTACH_COMMISSIONING;
    joinerParent(&dev, 0x0001, JOIN_CHANNEL, 1, JOIN_EXTENDED_PAN_ID);
    jr = joinerRequest(0);
    jr.capability.rxOnWhenIdle = 1;
    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 100);

    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 0), ZB_OK, "the request is held");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, MAC_ASSOC_SEND_WAIT_MS - 1), ZB_OK, "and kept while the wait runs");
    Test_ExpectCount(dev.nwk.joinOwedInUse, 1, "still held");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, MAC_ASSOC_SEND_WAIT_MS + 1), ZB_OK, "the wait has passed");
    harvestAir(&dev.model, air, &count);
    Test_Expect(count == 0 && dev.nwk.joinOwedInUse == 0 && Nwk_JoinSendsDropped(&dev.nwk) == 1,
                "so the frame is dropped and counted, never sent");
    Test_Expect(Nwk_PollJoinConfirm(&dev.nwk, &jc) == 1 && jc.status == JOIN_NO_DATA
                && Mac_Pib(&dev.mac)->shortAddress == 0xffff, "and the join ends on NO_DATA with the PIB given back");
}

/* A beacon as Table 3-74's entry: 3.6.1.5.1 discards one with no payload, another protocol version or another stack
   profile, and the entry keeps the channel, LQA, Update ID and the appendix's Router Information bitmap. */
void caseDiscoveryEntryFromABeacon(void)
{
    Mac_BeaconNotification beacon;
    Nwk_BeaconInfo info;
    Nwk_JoinParent entry;
    uint32_t len = 0;

    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    Test_ExpectStatus(Nwk_ParentFromBeacon(&beacon, &entry), ZB_ERR_BAD_FRAME, "a beacon with no payload (rule 1)");

    Zb_memset(&info, 0, (uint32_t)sizeof info);
    info.stackProfile = NWK_STACK_PROFILE_PRO;
    info.protocolVersion = NWK_BEACON_PROTOCOL_VERSION;
    info.routerCapacity = 1;
    info.endDeviceCapacity = 1;
    info.deviceDepth = 0;
    info.extendedPanId = JOIN_EXTENDED_PAN_ID;
    info.txOffset = NWK_BEACON_TX_OFFSET_NONE;
    info.updateId = 9;
    Test_ExpectStatus(Nwk_ComposeBeaconPayload(&info, beacon.payload, MAC_BEACON_PAYLOAD_MAX, &len), ZB_OK, "a payload");
    beacon.payload[17] = (uint8_t)NWK_ROUTER_INFO_HUB_CONNECTIVITY;
    beacon.payloadLen = len;
    beacon.coordAddrMode = MAC_ADDR_SHORT;
    beacon.coordShort = 0x1001;
    beacon.coordPanId = PAN_ID;
    beacon.channel = 20;
    beacon.lqi = 180;
    beacon.associationPermit = 1;

    Test_ExpectStatus(Nwk_ParentFromBeacon(&beacon, &entry), ZB_OK, "a Zigbee PRO router's beacon is an entry");
    Test_Expect(entry.channel == 20 && entry.lqa == 180 && entry.updateId == 9 && entry.depth == 0
                && entry.shortKnown && entry.shortAddress == 0x1001 && entry.extendedAddress == 0,
                "with its channel, LQA, Update ID, depth and the short address the beacon named");
    Test_Expect(entry.r23Appendix && entry.routerInformation == NWK_ROUTER_INFO_HUB_CONNECTIVITY,
                "and its appendix's Router Information bitmap");

    beacon.payload[1] = (uint8_t)((beacon.payload[1] & 0xf0) | 0x01);
    Test_ExpectStatus(Nwk_ParentFromBeacon(&beacon, &entry), ZB_ERR_BAD_FRAME, "another stack profile (rule 3)");
    beacon.payload[1] = (uint8_t)((beacon.payload[1] & 0xf0) | NWK_STACK_PROFILE_PRO);
    beacon.payload[1] = (uint8_t)((beacon.payload[1] & 0x0f) | 0x10);
    Test_ExpectStatus(Nwk_ParentFromBeacon(&beacon, &entry), ZB_ERR_BAD_FRAME, "another protocol version (rule 2)");
}

/* An entry of the network, on a channel, with an LQA and Router Information bitmap: the four things the ranking reads. */
static Nwk_JoinParent rankedParent(uint16_t shortAddress, uint32_t lqa, uint16_t routerInformation, uint32_t updateId)
{
    Nwk_JoinParent entry;
    uint32_t i;

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        entry.extendedPanId[i] = (uint8_t)(JOIN_EXTENDED_PAN_ID >> (i * 8));

    entry.inUse = 1;
    entry.panId = PAN_ID;
    entry.shortKnown = 1;
    entry.shortAddress = shortAddress;
    entry.channel = JOIN_CHANNEL;
    entry.associationPermit = 1;
    entry.deviceType = NWK_DEVICE_ROUTER;
    entry.rxOnWhenIdle = 1;
    entry.lqa = lqa;
    entry.routerInformation = routerInformation;
    entry.updateId = updateId;

    return entry;
}

/* 3.6.1.5.2's order: a good LQA above a marginal one whatever else, then hub connectivity, preferred parent and long
   uptime, then the newer Update ID with wrap; the table updates a parent heard twice and, full, gives its lowest row
   only to a newcomer ranked above it. */
void caseDiscoveryRanksTheParents(void)
{
    Nwk_JoinParent pool[NWK_JOIN_PARENT_MAX];
    Nwk_JoinParent a;
    Nwk_JoinParent b;
    uint32_t i;

    a = rankedParent(1, 200, 0, 0);
    b = rankedParent(2, 50, NWK_ROUTER_INFO_HUB_CONNECTIVITY | NWK_ROUTER_INFO_PREFERRED_PARENT, 0);
    Test_Expect(Nwk_ParentRanksAbove(&a, &b, NWK_GOOD_PARENT_LQA_DEFAULT), "a good LQA above a marginal one");
    b.lqa = 200;
    Test_Expect(Nwk_ParentRanksAbove(&b, &a, NWK_GOOD_PARENT_LQA_DEFAULT), "between two good, hub connectivity");
    a.routerInformation = NWK_ROUTER_INFO_HUB_CONNECTIVITY;
    Test_Expect(Nwk_ParentRanksAbove(&b, &a, NWK_GOOD_PARENT_LQA_DEFAULT), "then the preferred parent");
    a.routerInformation = NWK_ROUTER_INFO_HUB_CONNECTIVITY | NWK_ROUTER_INFO_PREFERRED_PARENT;
    a.routerInformation |= NWK_ROUTER_INFO_LONG_UPTIME;
    Test_Expect(Nwk_ParentRanksAbove(&a, &b, NWK_GOOD_PARENT_LQA_DEFAULT), "then long uptime");
    b.routerInformation = a.routerInformation;
    a.updateId = 0xfe;
    b.updateId = 0x02;
    Test_Expect(Nwk_ParentRanksAbove(&b, &a, NWK_GOOD_PARENT_LQA_DEFAULT), "then the newer Update ID, 0x02 past 0xfe");

    Zb_memset(pool, 0, (uint32_t)sizeof pool);
    a = rankedParent(1, 200, 0, 0);
    Test_ExpectStatus(Nwk_ParentAdmit(pool, &a, NWK_GOOD_PARENT_LQA_DEFAULT), ZB_OK, "a parent enters");
    a.lqa = 120;
    Test_ExpectStatus(Nwk_ParentAdmit(pool, &a, NWK_GOOD_PARENT_LQA_DEFAULT), ZB_OK, "and is heard again");
    Test_Expect(pool[0].lqa == 120 && !pool[1].inUse, "updating its row, not taking a second");

    for (i = 1; i < NWK_JOIN_PARENT_MAX; i++)
    {
        a = rankedParent((uint16_t)(1 + i), 100, 0, 0);
        Test_ExpectStatus(Nwk_ParentAdmit(pool, &a, NWK_GOOD_PARENT_LQA_DEFAULT), ZB_OK, "the table fills");
    }

    a = rankedParent(0x77, 10, 0, 0);
    Test_ExpectStatus(Nwk_ParentAdmit(pool, &a, NWK_GOOD_PARENT_LQA_DEFAULT), ZB_ERR_NO_SPACE,
                      "full, a marginal newcomer is refused");
    a = rankedParent(0x78, 100, NWK_ROUTER_INFO_HUB_CONNECTIVITY, 0);
    Test_ExpectStatus(Nwk_ParentAdmit(pool, &a, NWK_GOOD_PARENT_LQA_DEFAULT), ZB_OK,
                      "while one ranked above the lowest row takes it");
    Test_ExpectCount(Nwk_ParentBest(pool, ~(uint32_t)0, NWK_GOOD_PARENT_LQA_DEFAULT) < NWK_JOIN_PARENT_MAX
                     ? pool[Nwk_ParentBest(pool, ~(uint32_t)0, NWK_GOOD_PARENT_LQA_DEFAULT)].shortAddress : 0,
                     0x78, "and is the best-ranked row");
}

/* The join asks the best-ranked parent first, not the first one entered. */
void caseJoinAsksTheBestRankedParent(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinParent first;
    Nwk_JoinParent better;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;

    joinerRig(&dev, 0);
    dev.nwk.cfg.attachMechanism = NWK_ATTACH_ASSOCIATION;
    first = rankedParent(0x0001, 200, 0, 0);
    first.extendedAddress = JOIN_PARENT_IEEE + 1;
    better = rankedParent(0x0002, 200, NWK_ROUTER_INFO_HUB_CONNECTIVITY, 0);
    better.extendedAddress = JOIN_PARENT_IEEE + 2;
    Test_ExpectStatus(Nwk_JoinParentAdd(&dev.nwk, &first), ZB_OK, "a parent entered first");
    Test_ExpectStatus(Nwk_JoinParentAdd(&dev.nwk, &better), ZB_OK, "and one with hub connectivity after it");

    jr = joinerRequest(0);
    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 0), ZB_OK, "the join goes out");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(count, 1, "one Association Request");
    Test_ExpectCount(joinerAirTo(air, 0, count), 0x0002, "to the better-ranked parent");
}

/* A coordinator's beacon names it by short address alone, so the entry has no IEEE address: the commissioning request
   carries no destination IEEE field, the answer is taken from the parent's short address, and its source field
   teaches the parent's IEEE address, which the confirm then names. */
void caseCommissioningToAParentKnownByItsShortAddress(void)
{
    Test_BandA dev;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinConfirmParameters jc;
    Nwk_JoinParent parent;
    Nwk_Frame frame;
    Air air[AIR_LOG_MAX];
    uint32_t count = 0;
    uint32_t payloadOffset = 0;
    uint32_t payloadLen = 0;
    uint16_t own;

    joinerRig(&dev, 0);
    dev.nwk.cfg.attachMechanism = NWK_ATTACH_COMMISSIONING;
    parent = rankedParent(0x0001, 200, 0, 0);
    Test_ExpectStatus(Nwk_JoinParentAdd(&dev.nwk, &parent), ZB_OK, "an entry with a short address and no IEEE one");

    jr = joinerRequest(0);
    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 0), ZB_OK, "the commissioning join goes out");
    harvestAir(&dev.model, air, &count);
    Test_ExpectStatus(NwkFrame_Parse(air[0].bytes + NPDU_OFFSET, npduLenOf(&air[0]), &frame, &payloadOffset,
                                     &payloadLen), ZB_OK, "its network header parses");
    Test_Expect(frame.srcIeeePresent && !frame.destIeeePresent, "naming its own IEEE address and not the parent's");

    own = Mac_Pib(&dev.mac)->shortAddress;
    commissionerAnswer(&dev, JOIN_PARENT_IEEE + 7, JOIN_NEW_IEEE, own, 0x00);
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &jc), 1, "the parent's answer from its short address is taken");
    Test_Expect(jc.status == 0x00 && jc.parentExtended == JOIN_PARENT_IEEE + 7,
                "SUCCESS, with the parent's IEEE address learnt from the answer");
}

/* A router's beacon on `channel` for the extended PAN given, from short address `from`, its permit and stack profile
   as given: Table 3-83's octets and the appendix behind the MAC's superframe fields. */
static uint32_t discoveryBeacon(uint8_t *out, uint16_t from, uint64_t extendedPanId, int permit, uint32_t profile)
{
    Nwk_BeaconInfo info;
    MacFrame_Beacon beacon;
    Mac_Frame frame;
    uint8_t payload[NWK_BEACON_PAYLOAD_LEN];
    uint8_t body[64];
    uint32_t payloadLen = 0;
    uint32_t bodyLen = 0;
    uint32_t len = 0;

    Zb_memset(&info, 0, (uint32_t)sizeof info);
    info.stackProfile = profile;
    info.protocolVersion = NWK_BEACON_PROTOCOL_VERSION;
    info.routerCapacity = 1;
    info.endDeviceCapacity = 1;
    info.extendedPanId = extendedPanId;
    info.txOffset = NWK_BEACON_TX_OFFSET_NONE;
    Test_ExpectStatus(Nwk_ComposeBeaconPayload(&info, payload, (uint32_t)sizeof payload, &payloadLen), ZB_OK,
                      "a Zigbee beacon payload");

    Zb_memset(&beacon, 0, (uint32_t)sizeof beacon);
    beacon.beaconOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.superframeOrder = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.finalCapSlot = MAC_FRAME_BEACON_ORDER_NONE;
    beacon.associationPermit = permit;
    Test_ExpectStatus(MacFrame_ComposeBeaconPayload(&beacon, payload, payloadLen, body, (uint32_t)sizeof body,
                                                    &bodyLen), ZB_OK, "in a beacon body");

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = MAC_FRAME_TYPE_BEACON;
    frame.destAddrMode = MAC_ADDR_NONE;
    frame.srcAddrMode = MAC_ADDR_SHORT;
    frame.srcPan = PAN_ID;
    frame.srcShort = from;
    frame.seq = (uint8_t)from;
    Test_ExpectStatus(MacFrame_Compose(&frame, body, bodyLen, out, RADIO_MPDU_MAX, &len), ZB_OK, "a beacon frame");
    Test_ExpectStatus(MacFrame_AppendFcs(out, len, RADIO_MPDU_MAX, &len), ZB_OK, "closed by its footer");

    return len;
}

static void discoveryInject(Test_BandA *dev, const uint8_t *bytes, uint32_t len)
{
    Loopback_FrameSpec spec;

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = len;
    spec.bytes = bytes;
    spec.rssiDbm = -60;
    spec.lqi = 220;
    spec.stampTicks = 1;
    Test_ExpectStatus(LoopbackRadio_Inject(&dev->model, &spec, 1), ZB_OK, "a beacon arrives");
}

/* 3.2.2.3 end to end on the loopback: an active scan of channels 11 and 20, three beacons heard on 20 (a router of the
   network, one that permits no join while only permitting networks were asked for, one of another stack profile),
   one entry kept with its channel, 3.2.2.4's confirm, and the join that follows asks the entry discovered. */
void caseNetworkDiscoveryFillsTheTable(void)
{
    Test_BandA dev;
    Nwk_NetworkDiscoveryRequestParameters req;
    Nwk_NetworkDiscoveryConfirmParameters confirm;
    Nwk_JoinRequestParameters jr;
    Nwk_JoinParent entries[NWK_JOIN_PARENT_MAX];
    Nwk_JoinParent stale;
    Air air[AIR_LOG_MAX];
    uint8_t good[RADIO_MPDU_MAX];
    uint8_t closed[RADIO_MPDU_MAX];
    uint8_t other[RADIO_MPDU_MAX];
    uint32_t goodLen;
    uint32_t closedLen;
    uint32_t otherLen;
    uint32_t count = 0;
    uint32_t nowMs;
    int injected = 0;
    uint32_t listenedMs = 0;

    joinerRig(&dev, 0);
    dev.nwk.cfg.attachMechanism = NWK_ATTACH_ASSOCIATION;
    goodLen = discoveryBeacon(good, 0x1001, JOIN_EXTENDED_PAN_ID, 1, NWK_STACK_PROFILE_PRO);
    closedLen = discoveryBeacon(closed, 0x1002, JOIN_EXTENDED_PAN_ID, 0, NWK_STACK_PROFILE_PRO);
    otherLen = discoveryBeacon(other, 0x1003, JOIN_EXTENDED_PAN_ID, 1, 0x01);

    stale = rankedParent(0x0077, 200, 0, 0);
    Test_ExpectStatus(Nwk_JoinParentAdd(&dev.nwk, &stale), ZB_OK, "an entry left from an earlier discovery");

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.scanChannels = ((uint32_t)1 << 11) | ((uint32_t)1 << 20);
    req.scanDuration = 2;
    req.onlyPermitJoinNetworks = 1;
    Test_ExpectStatus(Nwk_NetworkDiscoveryRequest(&dev.nwk, &req, 0), ZB_OK, "a discovery of channels 11 and 20");
    Test_ExpectCount(dev.mac.scan.dwellMs, 77, "dwelling aBaseSuperframeDuration * (2^2 + 1), 4800 symbols, on each");
    Test_ExpectStatus(Nwk_NetworkDiscoveryRequest(&dev.nwk, &req, 0), ZB_ERR_BUSY, "one at a time");
    jr = joinerRequest(0);
    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 0), ZB_ERR_BUSY, "and no join while it runs");

    for (nowMs = 1; nowMs < 600; nowMs++)
    {
        if (dev.mac.scan.state == MAC_SCAN_LISTENING && dev.mac.scan.channel == 20 && injected < 3)
        {
            if (injected == 0)
                discoveryInject(&dev, good, goodLen);
            else if (injected == 1)
                discoveryInject(&dev, closed, closedLen);
            else
                discoveryInject(&dev, other, otherLen);

            injected++;
            listenedMs = nowMs;
        }

        Test_ExpectStatus(Test_NwkStep(&dev.nwk, nowMs), ZB_OK, "a turn");
        harvestAir(&dev.model, air, &count);

        if (Nwk_PollNetworkDiscoveryConfirm(&dev.nwk, &confirm) == 1)
            break;
    }

    Test_Expect(injected == 3 && listenedMs != 0 && nowMs < 600, "the discovery ends, three beacons heard on channel 20");
    Test_Expect(confirm.status == 0x00 && confirm.entries == 1, "SUCCESS, one potential parent kept");
    Test_ExpectCount(dev.nwk.discoveryBeaconsDiscarded, 2, "the closed network and the other profile discarded");
    Test_ExpectCount(Nwk_DiscoveryEntries(&dev.nwk, entries, NWK_JOIN_PARENT_MAX), 1,
                     "the table reads back, the earlier entry gone");
    Test_Expect(entries[0].channel == 20 && entries[0].shortAddress == 0x1001 && entries[0].lqa == 220,
                "the router on channel 20, at the LQA it was heard with");

    jr = joinerRequest(0);
    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, nowMs + 1), ZB_OK, "the join that follows");
    harvestAir(&dev.model, air, &count);
    Test_ExpectCount(joinerAirTo(air, count - 1, count), 0x1001, "asks the router discovered");
    Test_ExpectCount(Mac_Pib(&dev.mac)->channel, 20, "on its channel");
}

/* 5229-5231: a repeated scan is there to make the list more accurate, so what the earlier scans heard stays. */
void caseNetworkDiscoveryRepeatKeepsTheTable(void)
{
    Test_BandA dev;
    Nwk_NetworkDiscoveryRequestParameters req;
    Nwk_NetworkDiscoveryConfirmParameters confirm;
    Nwk_JoinParent entries[NWK_JOIN_PARENT_MAX];
    Nwk_JoinParent heard;
    uint32_t nowMs;

    joinerRig(&dev, 0);

    heard = rankedParent(0x0077, 200, 0, 0);
    Test_ExpectStatus(Nwk_JoinParentAdd(&dev.nwk, &heard), ZB_OK, "an entry an earlier scan heard");

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.scanChannels = (uint32_t)1 << 11;
    req.scanDuration = 2;
    req.keepTable = 1;
    Test_ExpectStatus(Nwk_NetworkDiscoveryRequest(&dev.nwk, &req, 0), ZB_OK, "a repeat that hears nothing");

    for (nowMs = 1; nowMs < 600; nowMs++)
    {
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, nowMs), ZB_OK, "a turn");

        if (Nwk_PollNetworkDiscoveryConfirm(&dev.nwk, &confirm) == 1)
            break;
    }

    Test_Expect(nowMs < 600, "the repeat ends");
    Test_ExpectCount(confirm.entries, 1, "and the confirm counts what the table still holds");
    Test_ExpectCount(Nwk_DiscoveryEntries(&dev.nwk, entries, NWK_JOIN_PARENT_MAX), 1, "the earlier entry stays");
    Test_ExpectCount(entries[0].shortAddress, 0x0077, "and it is that one");
}

/* A device off any network with a radio that measures: a router not yet joined. */
static void edScanRig(Test_BandA *dev, uint16_t own)
{
    Test_BandAConfig cfg;

    Test_BandADefaults(&cfg);
    cfg.caps.hasEnergyScan = 1;
    cfg.ownAddress = own;
    cfg.panId = 0xffff;
    Test_ExpectStatus(Test_BandABuild(dev, &cfg), ZB_OK, "a router whose radio measures");
}

/* 3.2.2.11 and 3.2.2.12 end to end on the loopback: the request's arguments judged, the MAC's ED scan of four
   channels at ScanDuration 3, and the confirm's EnergyDetectListStructure, one entry per channel lowest first in dBm,
   the channel nothing measured carrying no level. */
void caseEdScanReportsEachChannel(void)
{
    static const int32_t levels[16] = { -80, -94, -94, -94, -60, -94, -94, -94,
                                        -94, RADIO_SCAN_NO_LEVEL, -94, -94, -94, -94, -91, -94 };
    Test_BandA dev;
    Nwk_EdScanRequestParameters req;
    Nwk_EdScanConfirmParameters confirm;
    Nwk_NetworkDiscoveryRequestParameters discovery;
    uint32_t nowMs;
    uint32_t taken = 0;

    edScanRig(&dev, 0xffff);
    LoopbackRadio_ScriptEnergy(&dev.model, levels, 16);

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.scanChannels = (uint32_t)1 << 10;
    Test_ExpectStatus(Nwk_EdScanRequest(&dev.nwk, &req, 0), ZB_ERR_BAD_ARGUMENT, "channel 10, which this PHY lacks");
    req.scanChannels = 0;
    Test_ExpectStatus(Nwk_EdScanRequest(&dev.nwk, &req, 0), ZB_ERR_BAD_ARGUMENT, "no channel at all");
    req.scanChannels = ((uint32_t)1 << 11) | ((uint32_t)1 << 15) | ((uint32_t)1 << 20) | ((uint32_t)1 << 25);
    req.scanDuration = 15;
    Test_ExpectStatus(Nwk_EdScanRequest(&dev.nwk, &req, 0), ZB_ERR_BAD_ARGUMENT, "a ScanDuration past 14");

    req.scanDuration = 3;
    Test_ExpectStatus(Nwk_EdScanRequest(&dev.nwk, &req, 0), ZB_OK, "an ED scan of channels 11, 15, 20 and 25");
    Test_ExpectCount(dev.mac.scan.dwellMs, 139, "aBaseSuperframeDuration * (2^3 + 1), 8640 symbols, on each");
    Test_ExpectStatus(Nwk_EdScanRequest(&dev.nwk, &req, 0), ZB_ERR_BUSY, "one at a time");
    Zb_memset(&discovery, 0, (uint32_t)sizeof discovery);
    discovery.scanChannels = (uint32_t)1 << 11;
    Test_ExpectStatus(Nwk_NetworkDiscoveryRequest(&dev.nwk, &discovery, 0), ZB_ERR_BUSY, "and no discovery beside it");

    for (nowMs = 1; nowMs < 100 && taken == 0; nowMs++)
    {
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, nowMs), ZB_OK, "a turn");
        Test_ExpectStatus(LoopbackRadio_Pump(&dev.model, nowMs), ZB_OK, "and of the radio");
        taken = Nwk_PollEdScanConfirm(&dev.nwk, &confirm);
    }

    Test_ExpectCount(taken, 1, "the confirm is taken");
    Test_ExpectCount(Nwk_PollEdScanConfirm(&dev.nwk, &confirm), 0, "once");
    Test_ExpectCount(confirm.status, 0x00, "SUCCESS");
    Test_ExpectCount(confirm.channelCount, 4, "one entry per channel scanned");
    Test_Expect(confirm.channels[0].channelNumber == 11 && confirm.channels[1].channelNumber == 15
                && confirm.channels[2].channelNumber == 20 && confirm.channels[3].channelNumber == 25
                && confirm.channels[0].channelPage == 0, "lowest first, on page 0");
    Test_Expect(confirm.channels[0].measured && confirm.channels[0].energyDetected == -80
                && confirm.channels[1].energyDetected == -60 && confirm.channels[3].energyDetected == -91,
                "each level in the radio's dBm");
    Test_Expect(!confirm.channels[2].measured && confirm.channels[2].energyDetected == 0,
                "and channel 20, whose dwell measured nothing, carries no level");
}

/* A device on a network is refused: 3.2.2.11.3's pause in its operation is not built here. */
void caseEdScanRefusedOnANetwork(void)
{
    Test_BandA dev;
    Nwk_EdScanRequestParameters req;

    edScanRig(&dev, 0x1234);

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.scanChannels = (uint32_t)1 << 11;
    Test_ExpectStatus(Nwk_EdScanRequest(&dev.nwk, &req, 0), ZB_ERR_BAD_STATE, "a router at 0x1234 is on a network");
    Test_Expect(!Mac_Scanning(&dev.mac), "and no scan runs");
}

/* 3.2.2.3.3's INVALID_PARAMETER: no channel this PHY has, or a ScanDuration past 14. */
void caseNetworkDiscoveryRefusesBadRequests(void)
{
    Test_BandA dev;
    Nwk_NetworkDiscoveryRequestParameters req;

    joinerRig(&dev, 0);
    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.scanChannels = (uint32_t)1 << 5;
    Test_ExpectStatus(Nwk_NetworkDiscoveryRequest(&dev.nwk, &req, 0), ZB_ERR_BAD_ARGUMENT, "channel 5 only");
    req.scanChannels = (uint32_t)1 << 11;
    req.scanDuration = 15;
    Test_ExpectStatus(Nwk_NetworkDiscoveryRequest(&dev.nwk, &req, 0), ZB_ERR_BAD_ARGUMENT, "ScanDuration 15");
    Test_Expect(!Mac_Scanning(&dev.mac), "and no scan started");
}

/* Turns `from` to `until` of one rig, a millisecond apart. */
static void keepaliveSteps(Test_BandA *dev, uint32_t from, uint32_t until)
{
    uint32_t now;

    for (now = from; now <= until; now++)
        (void)Test_NwkStep(&dev->nwk, now);
}

/* A restored end device at OWN_SHORT whose parent NEIGHBOR said which keepalive it wants, its radio answering every
   transmit as `answered` says; the turns run to `until`, and the indications raised are read back into `out`. */
static uint32_t keepaliveRun(Test_BandA *dev, uint32_t parentInformation, int answered, uint32_t until,
                             Nwk_NwkStatusIndication *out)
{
    rigAt(dev, OWN_SHORT, PAN_ID, NWK_DEVICE_END_DEVICE, 1);
    dev->nwk.cfg.parentInformation = parentInformation;
    scriptOutcomes(&dev->model, LOOPBACK_TX_MAX, answered);
    Nwk_JoinResume(&dev->nwk, NEIGHBOR, JOIN_OWN_IEEE);

    keepaliveSteps(dev, 1, until);

    return Nwk_PollStatusIndications(&dev->nwk, out, 2);
}

void caseRestoredEndDeviceKeepalive(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_NwkStatusIndication inds[2];
    uint8_t payload[1 + NWK_TIMEOUT_RESPONSE_OCTETS];
    uint8_t npdu[64];
    uint32_t payloadLen = 0;
    uint32_t npduLen;
    uint32_t airCount = 0;

    Zb_memset(inds, 0, (uint32_t)sizeof inds);

    Test_ExpectCount(keepaliveRun(&dev, NWK_PARENT_INFORMATION_MAC_DATA_POLL, 0, 5, inds), 1,
                     "a restored end device whose parent named the MAC data poll polls it once, which no one acknowledges");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1 && (fcfOf(&air[0]) & 0x07) == MAC_FRAME_TYPE_COMMAND && airDestOf(&air[0]) == NEIGHBOR,
                "the keepalive is one MAC command to the parent (3.6.10.3, 3.6.10.8)");
    Test_Expect(inds[0].status == NWK_STATUS_CODE_PARENT_LINK_FAILURE && inds[0].shortAddr == NEIGHBOR,
                "and its NO_ACK is a failed link to the parent, raised as 0x09 (3.6.4.8.1)");
    Test_ExpectCount(Nwk_KeepalivesSent(&dev.nwk), 1, "one keepalive was sent");

    Test_ExpectCount(keepaliveRun(&dev, NWK_PARENT_INFORMATION_MAC_DATA_POLL, 1, 5, inds), 0,
                     "the same poll acknowledged raises nothing");
    Test_ExpectCount(keepaliveRun(&dev, 0, 1, 5, inds), 0,
                     "and a parent that named no method is polled too, since 3.6.10.4 has every parent answer a poll");
    Test_ExpectCount(Nwk_KeepalivesSent(&dev.nwk), 1, "with one keepalive");

    Test_ExpectCount(keepaliveRun(&dev, NWK_PARENT_INFORMATION_TIMEOUT_REQUEST, 1, NWK_KEEPALIVE_RESPONSE_WAIT_MS, inds),
                     0, "a parent that named only the timeout request is sent one, and its wait is not yet over");
    Test_ExpectCount(Nwk_TimeoutRequestsSent(&dev.nwk), 1, "the request went out");

    keepaliveSteps(&dev, NWK_KEEPALIVE_RESPONSE_WAIT_MS + 1, NWK_KEEPALIVE_RESPONSE_WAIT_MS + 4);
    Test_ExpectCount(Nwk_PollStatusIndications(&dev.nwk, inds, 2), 1, "and with no response once the wait is over");
    Test_Expect(inds[0].status == NWK_STATUS_CODE_PARENT_LINK_FAILURE && inds[0].shortAddr == NEIGHBOR,
                "the end device raises 0x09 (3.6.10.3)");

    Test_ExpectCount(keepaliveRun(&dev, NWK_PARENT_INFORMATION_TIMEOUT_REQUEST, 1, 5, inds), 0,
                     "the same request again");
    Test_ExpectStatus(Nwk_TimeoutResponseCompose(NWK_TIMEOUT_STATUS_SUCCESS, NWK_PARENT_INFORMATION_TIMEOUT_REQUEST,
                                                 payload + 1, (uint32_t)sizeof payload - 1, &payloadLen), ZB_OK,
                      "and the parent's SUCCESS composed");
    payload[0] = NWK_CMD_END_DEVICE_TIMEOUT_RESPONSE;
    npduLen = makeNpdu(npdu, OWN_SHORT, NEIGHBOR, 1, 0x40, NWK_FRAME_TYPE_COMMAND, 0, payload, payloadLen + 1);
    injectNpdu(&dev, npdu, npduLen, NEIGHBOR);

    keepaliveSteps(&dev, 6, NWK_KEEPALIVE_RESPONSE_WAIT_MS + 10);
    Test_ExpectCount(Nwk_PollStatusIndications(&dev.nwk, inds, 2), 0, "answered in time, nothing is raised");
    Test_ExpectCount(dev.nwk.keepalive, NWK_KEEPALIVE_NONE, "and the keepalive is over");
}
