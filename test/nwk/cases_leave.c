/* The `nwk` suite's leave: 3.6.1.11.1's own removal and its two arms, 3.6.1.11.2's parent removing a child,
   3.6.1.11.3's receipt of an announcement and 3.6.1.11.3.1's validation of a request. */

#include <stdint.h>

#include "nwk_addr.h"
#include "nwk_get.h"
#include "nwk_helpers.h"
#include "nwk_leave.h"
#include "nwk_frame.h"
#include "nwk_neighbor.h"
#include "loopback_radio.h"
#include "mac_frame.h"
#include "test_harness.h"
#include "zb_utils.h"

#define LEAVE_SHORT 0xdead
#define LEAVE_PAN 0xbeef
#define LEAVE_CHILD_SHORT 0x2001
#define LEAVE_CHILD_IEEE 0x00212effff05a888
#define LEAVE_STRANGER_IEEE 0x00212effff05a999

static Nwk_NeighborTableEntry *leaveSeed(Nwk_Nwk *nwk, uint16_t address, uint64_t ieee, uint32_t deviceType,
                                         uint32_t relationship)
{
    Nwk_NeighborTableEntry *entry = Nwk_NeighborFree(nwk->neighbors);

    Test_ExpectCount(entry != 0, 1, "the neighbour table has a row for the seeded device");

    entry->inUse = 1;
    entry->networkAddress = address;
    entry->extendedAddress = ieee;
    entry->ieeeKnown = 1;
    entry->deviceType = deviceType;
    entry->relationship = relationship;

    return entry;
}

static void leaveBeacon(Nwk_Nwk *nwk)
{
    Nwk_BeaconInfo info;

    Zb_memset(&info, 0, (uint32_t)sizeof info);

    info.stackProfile = 2;
    info.protocolVersion = 2;
    info.routerCapacity = 1;
    info.endDeviceCapacity = 1;
    info.extendedPanId = 0x0123456789abcdef;
    info.txOffset = 0xffffff;

    Test_ExpectStatus(Nwk_SetBeaconInfo(nwk, &info, 1), ZB_OK, "the application states its beacon");
}

/* Figure 3-15's options octet, composed and read back. */
void caseLeaveCommandCodec(void)
{
    Nwk_LeaveCommand command;
    Nwk_LeaveCommand readBack;
    uint8_t payload[NWK_LEAVE_COMMAND_OCTETS];

    Zb_memset(&command, 0, (uint32_t)sizeof command);
    Zb_memset(&readBack, 0, (uint32_t)sizeof readBack);

    command.rejoin = 1;
    command.request = 0;
    command.removeChildren = 1;

    payload[0] = 0;

    Test_ExpectStatus(Nwk_LeaveCommandCompose(&command, payload + 1, 1), ZB_OK, "the options octet composes");
    Test_ExpectCount(payload[1], NWK_LEAVE_OPTION_REJOIN | NWK_LEAVE_OPTION_REMOVE_CHILDREN,
                     "with the request sub-field clear and the five reserved bits below the three zero");

    Test_ExpectStatus(Nwk_LeaveCommandParse(payload, 2, &readBack), ZB_OK, "and the payload parses");
    Test_ExpectCount(readBack.rejoin, 1, "the rejoin sub-field");
    Test_ExpectCount(readBack.request, 0, "the request sub-field");
    Test_ExpectCount(readBack.removeChildren, 1, "and the remove children sub-field");

    payload[1] = 0x1f;      /* the five low bits, which the figure reserves */

    Test_ExpectStatus(Nwk_LeaveCommandParse(payload, 2, &readBack), ZB_OK, "reserved bits are read and not obeyed");
    Test_ExpectCount(readBack.rejoin, 0, "leaving every sub-field zero");
}

/* 3.6.1.11.1 and 3.6.1.11.4: a router that leaves announces itself and clears what it holds about the network. */
void caseLeaveOwnRemoval(void)
{
    Test_BandA dev;
    Nwk_LeaveIndication indication;

    rig(&dev, LEAVE_SHORT, LEAVE_PAN);
    leaveBeacon(&dev.nwk);
    leaveSeed(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, NWK_DEVICE_END_DEVICE, NWK_REL_CHILD);

    Test_ExpectCount(Nwk_LeaveRequest(&dev.nwk, NWK_LEAVE_ADDRESS_NULL, 0, 0, 1000), NWK_LEAVE_STATUS_SUCCESS,
                     "3.2.2.18.3: a NULL DeviceAddress removes this device");
    Test_ExpectCount(Nwk_LeaveCommandsSent(&dev.nwk), 1, "3.6.1.11.1 puts the announcement on the air");
    Test_ExpectCount(Nwk_LeavesTaken(&dev.nwk), 1, "and 3.6.1.11.4 is run");

    Test_ExpectCount(Nwk_NeighborTableEntries(&dev.nwk), 0, "the neighbour table is cleared");
    Test_ExpectCount(Nwk_RouteTableEntries(&dev.nwk), 0, "the routing table is cleared");
    Test_ExpectCount(Nwk_IsPartOfNetwork(&dev.nwk), 0, "and the device no longer holds an address on the network");

    Test_ExpectCount(Nwk_PollLeaveIndications(&dev.nwk, &indication, 1), 1, "3.2.2.19's indication arrives");
    Test_Expect(indication.deviceAddress == NWK_LEAVE_ADDRESS_NULL,
                 "with a NULL DeviceAddress, which Table 3-27 prints for the device that left");
    Test_ExpectCount(indication.rejoin, 0, "and the rejoin the request carried");
}

/* 3.6.1.11.4's first arm: a device that is asked to rejoin keeps its tables standing. */
void caseLeaveWithRejoinKeepsTheNetwork(void)
{
    Test_BandA dev;
    Nwk_LeaveIndication indication;

    rig(&dev, LEAVE_SHORT, LEAVE_PAN);
    leaveBeacon(&dev.nwk);
    leaveSeed(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, NWK_DEVICE_END_DEVICE, NWK_REL_CHILD);

    Test_ExpectCount(Nwk_LeaveRequest(&dev.nwk, NWK_LEAVE_ADDRESS_NULL, 0, 1, 1000), NWK_LEAVE_STATUS_SUCCESS,
                     "the request is answered as any other");
    Test_ExpectCount(Nwk_LeaveCommandsSent(&dev.nwk), 1, "the announcement goes out with its rejoin bit set");
    Test_ExpectCount(Nwk_LeavesTaken(&dev.nwk), 0, "and nothing is cleared");
    Test_ExpectCount(Nwk_NeighborTableEntries(&dev.nwk), 1, "the neighbour table stands");
    Test_ExpectCount(Nwk_IsPartOfNetwork(&dev.nwk), 1, "and so does the address");
    Test_ExpectCount(Nwk_PollLeaveIndications(&dev.nwk, &indication, 1), 1, "with the indication carrying rejoin");
    Test_ExpectCount(indication.rejoin, 1, "as the parameter said");
}

/* 3.2.2.18.3 and 3.6.1.11.2: a parent removing a child, and the three answers when it cannot. */
void caseLeaveRemovesAChild(void)
{
    Test_BandA dev;
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Nwk_NeighborTableEntry *child;

    rig(&dev, LEAVE_SHORT, LEAVE_PAN);
    leaveBeacon(&dev.nwk);
    child = leaveSeed(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, NWK_DEVICE_END_DEVICE, NWK_REL_CHILD);

    Test_ExpectCount(Nwk_LeaveRequest(&dev.nwk, LEAVE_CHILD_IEEE, 0, 0, 1000), NWK_LEAVE_STATUS_SUCCESS,
                     "3.6.1.11.2: a coordinator or router asks its child to leave");
    Test_ExpectCount(Nwk_LeaveCommandsSent(&dev.nwk), 1, "one command, addressed at the child");
    Test_ExpectCount(Mac_IndirectHeldFor(&dev.mac, LEAVE_CHILD_SHORT), 1,
                     "held for the child's poll, its receiver being off");
    Test_ExpectCount(LoopbackRadio_Sent(&dev.model, sent, LOOPBACK_TX_MAX), 0,
                     "and nothing sent direct to a receiver that is off");
    Test_ExpectCount(child->relationship, NWK_REL_PREVIOUS_CHILD,
                     "and 3.2.2.18.3's change of a child entry to previous child");
    Test_ExpectCount(Nwk_LeavesTaken(&dev.nwk), 0, "the parent does not leave with it");
    Test_ExpectCount(Nwk_IsPartOfNetwork(&dev.nwk), 1, "and stays on the network itself");

    Test_ExpectCount(Nwk_LeaveRequest(&dev.nwk, LEAVE_STRANGER_IEEE, 0, 0, 2000), NWK_LEAVE_STATUS_UNKNOWN_DEVICE,
                     "3.2.2.18.3: a device the neighbour table does not hold is UNKNOWN_DEVICE");
    Test_ExpectCount(Nwk_LeaveCommandsSent(&dev.nwk), 1, "and no frame is put on the air for it");

    Test_ExpectCount(Nwk_LeaveRequest(&dev.nwk, NWK_ADDR_ALL_DEVICES, 0, 0, 3000), NWK_LEAVE_STATUS_UNKNOWN_DEVICE,
                     "and so is a broadcast address, which is no device");
}

/* 3.6.1.11.3: an announced leave is noted, and the sender stops being the neighbour it was. */
void caseLeaveAnnouncementHeard(void)
{
    Test_BandA dev;
    Nwk_LeaveCommand command;
    Nwk_LeaveIndication indication;
    Nwk_NeighborTableEntry *child;

    Zb_memset(&command, 0, (uint32_t)sizeof command);

    rig(&dev, LEAVE_SHORT, LEAVE_PAN);
    leaveBeacon(&dev.nwk);
    child = leaveSeed(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, NWK_DEVICE_END_DEVICE, NWK_REL_CHILD);

    Nwk_LeaveRx(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, &command, 0, 1000);

    Test_ExpectCount(Nwk_LeaveCommandsHeard(&dev.nwk), 1, "the announcement was read");
    Test_ExpectCount(child->relationship, NWK_REL_PREVIOUS_CHILD, "and its entry no longer records a child");
    Test_ExpectCount(Nwk_PollLeaveIndications(&dev.nwk, &indication, 1), 1,
                     "3.6.1.11.3 issues the indication with the address the command came from");
    Test_Expect(indication.deviceAddress == LEAVE_CHILD_IEEE, "the sender's IEEE address");
    Test_ExpectCount(indication.networkAddress, LEAVE_CHILD_SHORT, "its network address");
    Test_ExpectCount(indication.child, 1, "and that it was this device's child when it left");

    Zb_memset(&indication, 0, (uint32_t)sizeof indication);

    Nwk_LeaveRx(&dev.nwk, 0x3002, 0x00212effff06b00b, &command, 0, 2000);

    Test_ExpectCount(Nwk_PollLeaveIndications(&dev.nwk, &indication, 1), 1,
                     "an announcement from a device this table never held is still noted");
    Test_ExpectCount(indication.child, 0, "as no child of this device");
    Test_ExpectCount(Nwk_IsPartOfNetwork(&dev.nwk), 1, "and the listener stays on its network");
}

/* 3.6.1.11.3.1: who carries out a leave request, and who drops it. */
void caseLeaveRequestValidation(void)
{
    Test_BandA dev;
    Nwk_LeaveCommand command;
    Nwk_NeighborTableEntry *entry;

    Zb_memset(&command, 0, (uint32_t)sizeof command);

    command.request = 1;

    rigAt(&dev, LEAVE_SHORT, LEAVE_PAN, NWK_DEVICE_COORDINATOR, 1);
    leaveBeacon(&dev.nwk);

    Nwk_LeaveRx(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, &command, 0, 1000);

    Test_ExpectCount(Nwk_LeavesTaken(&dev.nwk), 0,
                     "step 1: a coordinator drops a leave request and does nothing further");
    Test_ExpectCount(Nwk_LeaveCommandsSent(&dev.nwk), 0, "with no frame put on the air");

    rigAt(&dev, LEAVE_SHORT, LEAVE_PAN, NWK_DEVICE_ROUTER, 1);
    leaveBeacon(&dev.nwk);

    Test_ExpectCount(Nwk_LeaveRequestAllowed(&dev.nwk), 1,
                     "Table 3-66's own default for nwkLeaveRequestAllowed is TRUE");

    Nwk_SetLeaveRequestAllowed(&dev.nwk, 0);

    Nwk_LeaveRx(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, &command, 0, 2000);

    Test_ExpectCount(Nwk_LeavesTaken(&dev.nwk), 0,
                     "step 2 c: a router whose nwkLeaveRequestAllowed is FALSE does nothing");

    Nwk_SetLeaveRequestAllowed(&dev.nwk, 1);

    Test_ExpectCount(Nwk_LeaveRequestAllowed(&dev.nwk), 1, "the application turns it on again");

    Nwk_LeaveRx(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, &command, 0, 3000);

    Test_ExpectCount(Nwk_LeavesTaken(&dev.nwk), 1, "step 2 b: with TRUE the router carries out 3.6.1.11.1");
    Test_ExpectCount(Nwk_LeaveCommandsSent(&dev.nwk), 1, "announcing itself as that procedure says");

    rigAt(&dev, LEAVE_SHORT, LEAVE_PAN, NWK_DEVICE_END_DEVICE, 0);
    leaveBeacon(&dev.nwk);

    Nwk_LeaveRx(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, &command, 0, 4000);

    Test_ExpectCount(Nwk_LeavesTaken(&dev.nwk), 0,
                     "step 3 a i: an end device with no entry for the sender does nothing");

    entry = leaveSeed(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, NWK_DEVICE_ROUTER, NWK_REL_SIBLING);

    Nwk_LeaveRx(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, &command, 0, 5000);

    Test_ExpectCount(Nwk_LeavesTaken(&dev.nwk), 0,
                     "step 3 b: an entry that is not the parent is no reason to leave");

    entry->relationship = NWK_REL_PARENT;

    Nwk_LeaveRx(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, &command, 0, 6000);

    Test_ExpectCount(Nwk_LeavesTaken(&dev.nwk), 1,
                     "step 3 c: from the parent it leaves, and the footnote says it sends no frame of its own");
    Test_ExpectCount(Nwk_LeaveCommandsSent(&dev.nwk), 0, "which the count states plainly");
    Test_ExpectCount(Nwk_IsPartOfNetwork(&dev.nwk), 0, "and it is off the network");
}

/* 3.4.4.2 and 3.6.1.11.2: the child-directed request names the child it asks to leave, in the network header and at
   the MAC, and carries the child's IEEE address because this device knows it. */
void caseLeaveRequestNamesTheChild(void)
{
    Test_BandA dev;
    Loopback_Sent sent[LOOPBACK_TX_MAX + 1];
    Mac_Frame mac;
    Nwk_Frame frame;
    Nwk_LeaveCommand parsed;
    const uint8_t *payload;
    uint32_t payloadLen = 0;
    uint32_t npduOffset = 0;
    uint32_t npduLen = 0;

    rigAt(&dev, LEAVE_SHORT, LEAVE_PAN, NWK_DEVICE_ROUTER, 1);
    leaveBeacon(&dev.nwk);
    leaveSeed(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, NWK_DEVICE_END_DEVICE, NWK_REL_CHILD)->rxOnWhenIdle = 1;

    Test_ExpectCount(Nwk_LeaveRequest(&dev.nwk, LEAVE_CHILD_IEEE, 0, 0, 1000), NWK_LEAVE_STATUS_SUCCESS,
                     "a parent asking its child, whose receiver is on, to leave");

    Test_Expect(LoopbackRadio_Sent(&dev.model, sent, LOOPBACK_TX_MAX + 1) == 1, "one frame went on the air");
    Test_Expect(MacFrame_Parse(sent[0].bytes, sent[0].len, 1, &mac, &payload, &payloadLen, 0) == ZB_OK,
                "and it is a MAC data frame");
    Test_ExpectCount(mac.destShort, LEAVE_CHILD_SHORT, "addressed to the child and not to a broadcast address");
    Test_Expect(NwkFrame_Parse(payload, payloadLen, &frame, &npduOffset, &npduLen) == ZB_OK, "with a network header");
    Test_ExpectCount(frame.destAddr, LEAVE_CHILD_SHORT, "whose destination is the child");
    Test_ExpectCount(frame.destIeeePresent, 1, "and whose destination IEEE sub-field is present");
    Test_Expect(frame.destIeee == LEAVE_CHILD_IEEE, "holding the child's IEEE address");
    Test_ExpectCount(frame.radius, 1, "with the radius the clause fixes");
    Test_ExpectCount(frame.srcIeeePresent, 1, "and this device's own IEEE address in the source sub-field");

    Test_Expect(Nwk_LeaveCommandParse(payload + npduOffset, npduLen, &parsed) == ZB_OK, "and the command parses");
    Test_ExpectCount(parsed.request, 1, "with the request sub-field set");
    Test_ExpectCount(parsed.removeChildren, 0, "the rejoin and remove children sub-fields as the caller asked");
}

/* 3.6.1.11.3.1 step 1: a request that arrives as a broadcast is dropped, whoever the reader is. */
void caseLeaveBroadcastRequestIsDropped(void)
{
    Test_BandA dev;
    Nwk_LeaveCommand command;

    Zb_memset(&command, 0, (uint32_t)sizeof command);

    command.request = 1;

    rigAt(&dev, LEAVE_SHORT, LEAVE_PAN, NWK_DEVICE_ROUTER, 1);
    leaveBeacon(&dev.nwk);

    Nwk_LeaveRx(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, &command, 1, 1000);

    Test_ExpectCount(Nwk_LeavesTaken(&dev.nwk), 0, "a router with the NIB allowing a request still drops this one");
    Test_ExpectCount(Nwk_LeaveCommandsSent(&dev.nwk), 0, "and puts nothing on the air");
}

/* 3.6.1.11.3: a router whose parent announced a departure that takes its children repeats the announcement to its
   own subtree, forgets the network it was announced out of, and reports its own orphaning. */
void caseLeaveRouterRepeatsItsParentsAnnouncement(void)
{
    Test_BandA dev;
    Nwk_LeaveCommand command;
    Nwk_LeaveIndication indication[2];
    Nwk_NeighborTableEntry *parent;

    Zb_memset(&command, 0, (uint32_t)sizeof command);

    command.removeChildren = 1;

    rigAt(&dev, LEAVE_SHORT, LEAVE_PAN, NWK_DEVICE_ROUTER, 1);
    leaveBeacon(&dev.nwk);
    parent = leaveSeed(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, NWK_DEVICE_ROUTER, NWK_REL_PARENT);

    Test_ExpectCount(parent->relationship, NWK_REL_PARENT, "the table records the parent the announcement came from");

    Nwk_LeaveRx(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, &command, 0, 1000);

    Test_ExpectCount(Nwk_LeaveCommandsSent(&dev.nwk), 1, "the router repeats the announcement");
    Test_Expect(dev.nwk.beaconInfo.extendedPanId == 0, "and stops naming the network it was announced out of");
    Test_ExpectCount(Nwk_PollLeaveIndications(&dev.nwk, indication, 2), 2,
                     "once with the address the command came from and once with none");
    Test_Expect(indication[1].deviceAddress == NWK_LEAVE_ADDRESS_NULL, "the second names no device");
    Test_Expect(Nwk_NeighborOf(dev.nwk.neighbors, LEAVE_CHILD_SHORT) == 0, "and the former parent is no neighbour at all");
    Test_ExpectCount(Nwk_IsPartOfNetwork(&dev.nwk), 1, "while the router itself stays");
}

/* 8397-8398: a router that announces its leaving is no longer a neighbour, whichever way the rejoin flag points, so no
   link status lists it and nothing is sent to it, directly or through it. */
void caseLeaveRouterIsNoLongerANeighbour(void)
{
    Test_BandA dev;
    Nwk_LeaveCommand command;
    Nwk_LeaveIndication indication;
    Nwk_NeighborTableEntry *sibling;
    Nwk_RoutingTableEntry *route;
    uint32_t rejoin;

    for (rejoin = 0; rejoin < 2; rejoin++)
    {
        Zb_memset(&command, 0, (uint32_t)sizeof command);
        command.rejoin = rejoin;

        rig(&dev, LEAVE_SHORT, LEAVE_PAN);
        leaveBeacon(&dev.nwk);
        sibling = leaveSeed(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, NWK_DEVICE_ROUTER, NWK_REL_SIBLING);
        sibling->outgoingCost = 1;

        route = Nwk_RouteClaim(dev.nwk.routes);
        route->inUse = 1;
        route->destinationAddress = 0x4004;
        route->nextHopAddress = LEAVE_CHILD_SHORT;
        route->status = NWK_ROUTE_ACTIVE;

        Nwk_LeaveRx(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, &command, 0, 1000);

        Test_Expect(Nwk_NeighborOf(dev.nwk.neighbors, LEAVE_CHILD_SHORT) == 0, "the table no longer holds the sibling");
        Test_ExpectCount(route->status, NWK_ROUTE_INACTIVE, "and a route through it no longer stands");
        Test_ExpectCount(Nwk_PollLeaveIndications(&dev.nwk, &indication, 1), 1, "while the indication is still made");
        Test_Expect(indication.deviceAddress == LEAVE_CHILD_IEEE, "and names the device from its command frame");
        Test_ExpectCount(indication.rejoin, rejoin, "with the flag it carried");
    }
}

/* 7935-7936 over 8404 (D-256): a joined router has no parent, so the device it joined through announcing its departure
   with remove children takes nothing down with it, and that router leaving is no child's departure for 11973. */
void caseLeaveAJoinedRouterHasNoParentAndIsNoChild(void)
{
    Test_BandA dev;
    Nwk_LeaveCommand command;
    Nwk_LeaveIndication indication[2];

    Zb_memset(&command, 0, (uint32_t)sizeof command);

    command.removeChildren = 1;

    rigAt(&dev, LEAVE_SHORT, LEAVE_PAN, NWK_DEVICE_ROUTER, 1);
    leaveBeacon(&dev.nwk);
    (void)leaveSeed(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, NWK_DEVICE_ROUTER, NWK_REL_SIBLING);
    dev.nwk.joinParentShort = LEAVE_CHILD_SHORT;
    dev.nwk.joinParentShortKnown = 1;

    Nwk_LeaveRx(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, &command, 0, 1000);

    Test_ExpectCount(Nwk_LeaveCommandsSent(&dev.nwk), 0, "the announcement is not repeated");
    Test_Expect(dev.nwk.beaconInfo.extendedPanId != 0, "and this router keeps the network it names");
    Test_ExpectCount(Nwk_PollLeaveIndications(&dev.nwk, indication, 2), 1, "one indication, for the device that left");
    Test_ExpectCount(indication[0].child, 0, "which was no child, so 11973 owes the trust centre no report of it");
}

/* 3.6.1.11.3's closing paragraph: an end device whose parent announced clears the extended PAN id it was given and
   reports its own orphaning, without leaving on the parent's behalf. */
void caseLeaveEndDeviceHearsItsParentAnnounce(void)
{
    Test_BandA dev;
    Nwk_LeaveCommand command;
    Nwk_LeaveIndication indication[2];

    Zb_memset(&command, 0, (uint32_t)sizeof command);

    command.removeChildren = 1;

    rigAt(&dev, LEAVE_SHORT, LEAVE_PAN, NWK_DEVICE_END_DEVICE, 0);
    leaveBeacon(&dev.nwk);
    leaveSeed(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, NWK_DEVICE_ROUTER, NWK_REL_PARENT);

    Nwk_LeaveRx(&dev.nwk, LEAVE_CHILD_SHORT, LEAVE_CHILD_IEEE, &command, 0, 1000);

    Test_Expect(dev.nwk.beaconInfo.extendedPanId == 0, "the end device forgets the network its parent left");
    Test_ExpectCount(Nwk_PollLeaveIndications(&dev.nwk, indication, 2), 2,
                     "and reports the departure twice over: the announced leave and its own orphaning");
    Test_Expect(indication[1].deviceAddress == NWK_LEAVE_ADDRESS_NULL, "the second names no device");
    Test_ExpectCount(Nwk_LeaveCommandsSent(&dev.nwk), 0, "and sends no leave frame of its own here");
    Test_ExpectCount(Nwk_LeavesTaken(&dev.nwk), 0, "while its own departure is a procedure it has not run");
}
