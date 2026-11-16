/* The `zdo` suite's network management: 2.4.3.3.2, 2.4.3.3.3 and 2.4.3.3.4 ask for the three tables, and
   2.4.4.3.2, 2.4.4.3.3 and 2.4.4.3.4 report them from the index the request named. */

#include <stdint.h>

#include "nwk_get.h"
#include "nwk_leave.h"
#include "nwk_permit.h"
#include "nwk_neighbor.h"
#include "nwk_route.h"
#include "test_harness.h"
#include "zb_utils.h"
#include "zdo_helpers.h"

#define ZDO_EXT_PAN_ID 0x0123456789abcdef

static void zdoSeedNeighbor(Zdo_Rig *rig, uint16_t address, uint32_t deviceType, uint32_t relationship,
                            uint32_t lqi, int ieeeKnown)
{
    Nwk_NeighborTableEntry *entry = Nwk_NeighborFree(rig->stack.nwk.neighbors);

    Test_ExpectCount(entry != 0, 1, "the neighbour table has a row for the seeded device");

    entry->inUse = 1;
    entry->networkAddress = address;
    entry->extendedAddress = 0x00212effff000000 | address;
    entry->ieeeKnown = ieeeKnown;
    entry->deviceType = deviceType;
    entry->rxOnWhenIdle = 1;
    entry->relationship = relationship;
    entry->lqi = lqi;
}

/* 2.4.4.3.2.1 caps a neighbour report at two whole records, so a table with more is read by paging. */
void caseZdoNeighborReport(void)
{
    Zdo_Rig rig;
    uint8_t body[ZDO_ASDU_MAX];
    Zdo_TableReport head;
    Zdo_NeighborReport records[ZDO_REPORT_MAX];
    uint32_t length;
    uint8_t startIndex;

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, ZDO_EXT_PAN_ID);

    zdoSeedNeighbor(&rig, 0x1001, NWK_DEVICE_ROUTER, NWK_REL_PARENT, 180, 1);
    zdoSeedNeighbor(&rig, 0x1002, NWK_DEVICE_END_DEVICE, NWK_REL_BACKBONE_SIBLING, 96, 1);
    zdoSeedNeighbor(&rig, 0x1003, NWK_NEIGHBOR_TYPE_UNKNOWN, NWK_REL_NONE, 12, 0);

    Test_ExpectCount(Nwk_NeighborTableEntries(&rig.stack.nwk), 3, "the read 3.2.2.27 answers sees three entries");

    length = Zdo_NeighborReportCompose(&rig.zdo, 0, body, (uint32_t)sizeof body);

    Test_ExpectCount(length, ZDO_REPORT_HEADER_OCTETS + 2 * ZDO_NEIGHBOR_RECORD_OCTETS,
                     "Table 2-101 reports two of them, whole");

    Test_ExpectStatus(Zdo_NeighborReportParse(body, length, &head, records, ZDO_REPORT_MAX), ZB_OK,
                      "and the report reads back");

    Test_ExpectCount(head.status, ZDO_STATUS_SUCCESS, "with the status 2.4.4.3.2.1 gives a table it obtained");
    Test_ExpectCount(head.totalEntries, 3, "the total the table holds, not the number it printed");
    Test_ExpectCount(head.listCount, 2, "and the number it printed");

    Test_Expect(records[0].extendedPanId == ZDO_EXT_PAN_ID, "Table 2-102's extended PAN id of this network");
    Test_ExpectCount(records[0].networkAddress, 0x1001, "the neighbour's address");
    Test_ExpectCount(records[0].deviceType, NWK_DEVICE_ROUTER, "its device type");
    Test_ExpectCount(records[0].rxOnWhenIdle, 1, "its receiver duty");
    Test_ExpectCount(records[0].affinity, 0, "and 2.4.4.3.2.1's mapping of the relationship");
    Test_ExpectCount(records[0].permitJoining, ZDO_REPORT_UNKNOWN,
                     "with Table 2-102's unknown value for what this stack does not observe");
    Test_ExpectCount(records[0].depth, ZDO_REPORT_DEPTH_DEPRECATED, "and the depth 3.6.8 deprecated it to");
    Test_ExpectCount(records[0].lqa, 180, "and the link quality");

    Test_ExpectCount(records[1].affinity, 3,
                     "a relationship past 0x02 is 2.4.4.3.2.1's None of the Above");

    length = Zdo_NeighborReportCompose(&rig.zdo, 2, body, (uint32_t)sizeof body);
    Test_ExpectStatus(Zdo_NeighborReportParse(body, length, &head, records, ZDO_REPORT_MAX), ZB_OK,
                      "the page from index 2 reads back too");

    Test_ExpectCount(head.listCount, 1, "one record left");
    Test_ExpectCount(records[0].networkAddress, 0x1003, "the third neighbour");
    Test_ExpectCount(records[0].deviceType, ZDO_NEIGHBOR_TYPE_UNKNOWN,
                     "an entry made from an address heard states Table 2-102's unknown device type");
    Test_ExpectCount(records[0].rxOnWhenIdle, ZDO_REPORT_UNKNOWN, "and its unknown receiver duty");
    Test_Expect(records[0].extendedAddress == 0xffffffffffffffff, "and 2.4.4.3.2.1's all-ones IEEE address");

    startIndex = 2;
    zdoDeliverCommand(&rig, ZDO_MGMT_LQI_REQ, &startIndex, 1, 100);
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "2.4.3.3.2: a Mgmt_Lqi_req is answered");

    startIndex = 0;
    zdoDeliverCommand(&rig, ZDO_MGMT_RTG_REQ, &startIndex, 1, 200);
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 2, "and so is a Mgmt_Rtg_req");

    Zdo_SetNetwork(&rig.zdo, 0, 0, 0);

    Test_ExpectCount(Zdo_NeighborReportCompose(&rig.zdo, 0, body, (uint32_t)sizeof body), 0,
                     "a device object with no network layer to read composes nothing");
    Test_ExpectCount(Zdo_RouteReportCompose(&rig.zdo, 0, body, (uint32_t)sizeof body), 0,
                     "and nothing for the routing table either");

    zdoDeliverCommand(&rig, ZDO_MGMT_LQI_REQ, &startIndex, 1, 300);
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 3, "but the request is still answered, with NOT_SUPPORTED alone");
}

/* 2.4.4.3.3's RoutingTableList record: the two addresses and Table 3-77's flags in one packed octet. */
void caseZdoRouteReport(void)
{
    Zdo_Rig rig;
    Nwk_RoutingTableEntry *route;
    uint8_t body[ZDO_ASDU_MAX];
    Zdo_TableReport head;
    Zdo_RouteReport records[ZDO_REPORT_MAX];
    uint8_t startIndex = 0;
    uint32_t length;

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, ZDO_EXT_PAN_ID);

    route = Nwk_RouteClaim(rig.stack.nwk.routes);
    Test_ExpectCount(route != 0, 1, "the routing table has a row");

    route->inUse = 1;
    route->destinationAddress = 0x2001;
    route->status = NWK_ROUTE_ACTIVE;
    route->nextHopAddress = 0x3001;
    route->manyToOne = 1;
    route->noRouteCache = 1;
    route->routeRecordRequired = 1;

    route = Nwk_RouteClaim(rig.stack.nwk.routes);
    route->inUse = 1;
    route->destinationAddress = 0x2002;
    route->status = NWK_ROUTE_DISCOVERY_UNDERWAY;
    route->nextHopAddress = 0x0000;

    Test_ExpectCount(Nwk_RouteTableEntries(&rig.stack.nwk), 2, "two routes are in the table 3.2.2.27 reads");

    length = Zdo_RouteReportCompose(&rig.zdo, 0, body, (uint32_t)sizeof body);

    Test_ExpectCount(length, ZDO_REPORT_HEADER_OCTETS + 2 * ZDO_ROUTE_RECORD_OCTETS,
                     "Table 2-103 prints both records, five octets each");

    Test_ExpectStatus(Zdo_RouteReportParse(body, length, &head, records, ZDO_REPORT_MAX), ZB_OK,
                      "and the report reads back");

    Test_ExpectCount(head.totalEntries, 2, "with the total");
    Test_ExpectCount(records[0].destinationAddress, 0x2001, "the destination");
    Test_ExpectCount(records[0].nextHopAddress, 0x3001, "the next hop");
    Test_ExpectCount(records[0].status, NWK_ROUTE_ACTIVE, "Table 3-78's status");
    Test_ExpectCount(records[0].memoryConstrained, 1,
                     "the concentrator Table 2-104 calls memory constrained, which Table 3-55's many-to-one form "
                     "that asks for no route record names");
    Test_ExpectCount(records[0].manyToOne, 1, "the many-to-one flag");
    Test_ExpectCount(records[0].routeRecordRequired, 1, "and the route record flag");
    Test_ExpectCount(records[1].status, NWK_ROUTE_DISCOVERY_UNDERWAY, "and the second entry's status");

    zdoDeliverCommand(&rig, ZDO_MGMT_RTG_REQ, &startIndex, 1, 100);
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "2.4.3.3.3: a Mgmt_Rtg_req is answered");
}

/* 2.4.4.3.4's BindingTableList record, whose length turns on its destination mode, and 2.4.4.3.4.1's answer for an
   empty table. */
void caseZdoBindingReport(void)
{
    Zdo_Rig rig;
    Aps_Binding bindings[APS_BIND_MAX];
    Aps_Binding entry;
    uint8_t body[ZDO_ASDU_MAX];
    Zdo_TableReport head;
    Zdo_BindingReport records[ZDO_REPORT_MAX];
    Zdo_RouteReport routes[ZDO_REPORT_MAX];
    uint8_t startIndex = 0;
    uint32_t length;

    Zb_memset(bindings, 0, (uint32_t)sizeof bindings);
    Zb_memset(&entry, 0, (uint32_t)sizeof entry);

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, ZDO_EXT_PAN_ID);
    Aps_SetBindings(&rig.aps, bindings);

    Test_ExpectCount(Zdo_BindingReportCompose(&rig.zdo, 5, body, (uint32_t)sizeof body), ZDO_REPORT_HEADER_OCTETS,
                     "2.4.4.3.4.1: an empty table is answered with the status and three zero octets");
    Test_ExpectCount(body[2], 0, "the start index among them zero, whatever the request named");

    entry.srcIeee = ZDO_OWN_IEEE;
    entry.srcEndpoint = 1;
    entry.clusterId = 0x0006;
    entry.dstAddrMode = 0x01;
    entry.dstAddress = 0x0011;

    Test_ExpectCount(Aps_BindAdd(bindings, &entry), APS_BIND_ADDED, "a group entry");

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.srcIeee = ZDO_OWN_IEEE;
    entry.srcEndpoint = 2;
    entry.clusterId = 0x0000;
    entry.dstAddrMode = 0x03;
    entry.dstExtendedAddress = 0x00212effff05a888;
    entry.dstEndpoint = 3;

    Test_ExpectCount(Aps_BindAdd(bindings, &entry), APS_BIND_ADDED, "and an extended entry");

    length = Zdo_BindingReportCompose(&rig.zdo, 0, body, (uint32_t)sizeof body);

    Test_ExpectCount(length, ZDO_REPORT_HEADER_OCTETS + 14 + 21,
                     "Table 2-106 prints 14 octets for the group and 21 for the extended address");

    Test_ExpectStatus(Zdo_BindingReportParse(body, length, &head, records, ZDO_REPORT_MAX), ZB_OK,
                      "and the report reads back");

    Test_ExpectCount(head.totalEntries, 2, "with the total");

    Test_ExpectCount(records[0].dstAddrMode, 0x01, "the group entry");
    Test_ExpectCount(records[0].dstAddress, 0x0011, "its group address");
    Test_ExpectCount(records[0].dstEndpoint, 0, "and no endpoint, which Table 2-106 prints only for 0x03");
    Test_ExpectCount(records[1].srcEndpoint, 2, "the second entry's source endpoint");
    Test_Expect(records[1].dstExtendedAddress == 0x00212effff05a888, "the extended destination");
    Test_ExpectCount(records[1].dstEndpoint, 3, "and its endpoint");

    body[0] = ZDO_STATUS_NOT_SUPPORTED;

    Test_ExpectStatus(Zdo_RouteReportParse(body, 1, &head, routes, ZDO_REPORT_MAX), ZB_OK,
                      "2.4.4.3.3.1: a report whose status is not SUCCESS carries nothing after it, and that is "
                      "readable");
    Test_ExpectCount(head.status, ZDO_STATUS_NOT_SUPPORTED, "the status the report stated");
    Test_ExpectCount(head.listCount, 0, "and no list");

    body[0] = ZDO_STATUS_SUCCESS;
    body[1] = 1;
    body[2] = 0;
    body[3] = 1;
    body[4] = 0x12;
    body[5] = 0x8a;
    body[6] = 0x04;
    body[7] = 0xff;
    body[8] = 0xff;
    body[9] = 0x2e;
    body[10] = 0x21;
    body[11] = 0x00;
    body[12] = 1;
    body[13] = 0x06;
    body[14] = 0x00;
    body[15] = 0x02;
    body[16] = 0x11;
    body[17] = 0x00;

    Test_ExpectStatus(Zdo_BindingReportParse(body, 18, &head, records, ZDO_REPORT_MAX), ZB_ERR_BAD_ARGUMENT,
                      "Table 2-106 reserves every destination mode but 0x01 and 0x03, and a record carrying one "
                      "desynchronises the list, so it is refused");

    zdoDeliverCommand(&rig, ZDO_MGMT_BIND_REQ, &startIndex, 1, 100);
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "2.4.3.3.4: a Mgmt_Bind_req is answered");

    zdoDeliverBroadcast(&rig, ZDO_MGMT_BIND_REQ, &startIndex, 1, 200);
    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "2.4.3.3.4's addressing is unicast only, so a broadcast "
                     "Mgmt_Bind_req is dropped and answered by nothing");
    Test_ExpectCount(Zdo_CommandsDroppedBroadcast(&rig.zdo), 1, "which the device object counts");
}

/* 2.4.3.3.7 and 2.4.4.3.7: the request carries the duration 3.2.2.7 takes, Revision 21 and later read its 0xff as
   0xfe seconds, and a broadcast is carried out without an answer. */
void caseZdoPermitJoining(void)
{
    Zdo_Rig rig;
    Nwk_BeaconInfo info;
    uint8_t payload[3];

    Zb_memset(&info, 0, (uint32_t)sizeof info);
    info.stackProfile = 2;
    info.protocolVersion = 2;
    info.routerCapacity = 1;
    info.endDeviceCapacity = 1;
    info.extendedPanId = ZDO_EXT_PAN_ID;
    info.txOffset = 0xffffff;

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, ZDO_EXT_PAN_ID);

    Test_ExpectStatus(Nwk_SetBeaconInfo(&rig.stack.nwk, &info, 0), ZB_OK, "the application states its beacon");

    payload[0] = 30;
    payload[1] = 0x00;      /* the deprecated TC_Significance value, which is read as 1 anyway */
    payload[2] = 0x00;

    zdoDeliverCommand(&rig, ZDO_MGMT_PERMIT_JOINING_REQ, payload, 3, 1000);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "2.4.3.3.7: a Mgmt_Permit_Joining_req is answered");
    Test_ExpectCount(Nwk_PermitJoiningActive(&rig.stack.nwk), 1, "and 3.2.2.7 was issued for its duration");
    Test_ExpectCount(Nwk_PermitJoiningRequests(&rig.stack.nwk), 1, "once, counted");

    Test_ExpectStatus(Nwk_Step(&rig.stack.nwk, 40000), ZB_OK, "stepped past the 30 s");
    Test_ExpectCount(Nwk_PermitJoiningActive(&rig.stack.nwk), 0, "and the permit expired on its own clock");

    payload[0] = 0xff;

    zdoDeliverCommand(&rig, ZDO_MGMT_PERMIT_JOINING_REQ, payload, 3, 50000);

    Test_ExpectCount(Nwk_PermitJoiningActive(&rig.stack.nwk), 1, "2.4.3.3.7.2: 0xff in the command is a duration");
    Test_ExpectStatus(Nwk_Step(&rig.stack.nwk, 50000 + 0xfe * 1000 - 1), ZB_OK, "of 0xfe seconds, not 'forever'");
    Test_ExpectCount(Nwk_PermitJoiningActive(&rig.stack.nwk), 1, "which has not yet run out");
    Test_ExpectStatus(Nwk_Step(&rig.stack.nwk, 50000 + 0xfe * 1000), ZB_OK, "and then it does");
    Test_ExpectCount(Nwk_PermitJoiningActive(&rig.stack.nwk), 0, "with the permit set false again");

    payload[0] = 15;

    zdoDeliverBroadcast(&rig, ZDO_MGMT_PERMIT_JOINING_REQ, payload, 3, 200000);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 2,
                     "2.4.3.3.7.2: a broadcast Mgmt_Permit_Joining_req is carried out and answered by nothing");
    Test_ExpectCount(Nwk_PermitJoiningActive(&rig.stack.nwk), 1, "and the permit it asked for stands");
    Test_ExpectCount(Zdo_CommandsBroadcastUnanswered(&rig.zdo), 1, "which the device object counts apart");
}

/* 2.4.3.3.5 and 2.4.4.3.5: Figure 2-35's request naming a child removes that child, one naming nobody in the table
   leaves it alone, one sent as a broadcast is dropped, and one naming this device carries it out. */
void caseZdoLeaveRequest(void)
{
    Zdo_Rig rig;
    Nwk_NeighborTableEntry *child;
    uint8_t payload[NWK_LEAVE_ADDRESS_OCTETS + 1];
    uint32_t i;

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, ZDO_EXT_PAN_ID);

    child = Nwk_NeighborFree(rig.stack.nwk.neighbors);
    Test_ExpectCount(child != 0, 1, "the neighbour table has a row for the child");

    child->inUse = 1;
    child->networkAddress = 0x2001;
    child->extendedAddress = 0x00212effff05a888;
    child->ieeeKnown = 1;
    child->deviceType = NWK_DEVICE_END_DEVICE;
    child->relationship = NWK_REL_CHILD;

    for (i = 0; i < NWK_LEAVE_ADDRESS_OCTETS; i++)
        payload[i] = (uint8_t)((0x00212effff05a999 >> (8 * i)) & 0xff);

    payload[NWK_LEAVE_ADDRESS_OCTETS] = 0;

    zdoDeliverCommand(&rig, ZDO_MGMT_LEAVE_REQ, payload, NWK_LEAVE_ADDRESS_OCTETS + 1, 1000);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "a request naming a device the table does not hold is answered");
    Test_ExpectCount(Nwk_LeaveCommandsSent(&rig.stack.nwk), 0, "with no leave frame on the air");
    Test_ExpectCount(Nwk_LeavesTaken(&rig.stack.nwk), 0, "and this device still on the network");

    for (i = 0; i < NWK_LEAVE_ADDRESS_OCTETS; i++)
        payload[i] = (uint8_t)((0x00212effff05a888 >> (8 * i)) & 0xff);

    zdoDeliverCommand(&rig, ZDO_MGMT_LEAVE_REQ, payload, NWK_LEAVE_ADDRESS_OCTETS + 1, 2000);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 2, "a request naming the child is answered");
    Test_ExpectCount(Nwk_LeaveCommandsSent(&rig.stack.nwk), 1, "and the parent puts one leave frame on the air");
    Test_ExpectCount(child->relationship, NWK_REL_PREVIOUS_CHILD, "with its entry no longer recording a child");
    Test_ExpectCount(Nwk_LeavesTaken(&rig.stack.nwk), 0, "and the parent staying");
    Test_ExpectCount(Nwk_IsPartOfNetwork(&rig.stack.nwk), 1, "on the network itself");

    zdoDeliverBroadcast(&rig, ZDO_MGMT_LEAVE_REQ, payload, NWK_LEAVE_ADDRESS_OCTETS + 1, 3000);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 2, "3.6.1.11.3.1 step 1: the same request as a broadcast is dropped");
    Test_ExpectCount(Zdo_CommandsDroppedBroadcast(&rig.zdo), 1, "and counted as dropped");

    for (i = 0; i < NWK_LEAVE_ADDRESS_OCTETS; i++)
        payload[i] = (uint8_t)((ZDO_OWN_IEEE >> (8 * i)) & 0xff);

    payload[NWK_LEAVE_ADDRESS_OCTETS] = ZDO_LEAVE_OPTION_REJOIN;

    zdoDeliverCommand(&rig, ZDO_MGMT_LEAVE_REQ, payload, NWK_LEAVE_ADDRESS_OCTETS + 1, 4000);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 3, "2.4.3.3.5.2: a request naming this device is answered");
    Test_ExpectCount(Nwk_LeaveCommandsSent(&rig.stack.nwk), 2, "and this device announces its own departure");
    Test_ExpectCount(Nwk_LeavesTaken(&rig.stack.nwk), 1, "with 3.6.1.11.4 run: the clause fixes the rejoin parameter "
                     "to FALSE, so the bit the frame carried is not what the primitive was given");
    Test_ExpectCount(Nwk_IsPartOfNetwork(&rig.stack.nwk), 0, "and the device is no longer on the network");
}

/* 3.6.1.11.3.1 run on the management route as well: a request this device is not allowed to carry out is answered
   with a refusal and changes nothing. */
void caseZdoLeaveRequestRefused(void)
{
    Zdo_Rig rig;
    uint8_t payload[NWK_LEAVE_ADDRESS_OCTETS + 1];
    uint32_t i;

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, ZDO_EXT_PAN_ID);

    Test_ExpectCount(Nwk_LeaveRequestAllowed(&rig.stack.nwk), 1, "the NIB starts with the leave request allowed");

    Nwk_SetLeaveRequestAllowed(&rig.stack.nwk, 0);

    for (i = 0; i < NWK_LEAVE_ADDRESS_OCTETS; i++)
        payload[i] = (uint8_t)((ZDO_OWN_IEEE >> (8 * i)) & 0xff);

    payload[NWK_LEAVE_ADDRESS_OCTETS] = 0;

    zdoDeliverCommand(&rig, ZDO_MGMT_LEAVE_REQ, payload, NWK_LEAVE_ADDRESS_OCTETS + 1, 1000);

    Test_ExpectCount(Zdo_ResponsesSent(&rig.zdo), 1, "the request is answered");
    Test_ExpectCount(Nwk_LeavesTaken(&rig.stack.nwk), 0, "and nothing else happens");
    Test_ExpectCount(Nwk_IsPartOfNetwork(&rig.stack.nwk), 1, "the device stays where it was");

    Nwk_SetLeaveRequestAllowed(&rig.stack.nwk, 1);

    zdoDeliverCommand(&rig, ZDO_MGMT_LEAVE_REQ, payload, NWK_LEAVE_ADDRESS_OCTETS + 1, 2000);

    Test_ExpectCount(Nwk_LeavesTaken(&rig.stack.nwk), 1, "allowed again, the same request is carried out");
    Test_ExpectCount(Nwk_IsPartOfNetwork(&rig.stack.nwk), 0, "and the device is gone from the network");
}

/* An announcement as the framework hands it over: the transaction sequence number, the network address, the IEEE
   address and the capability octet of Figure 2-25. */
static void zdoAnnounce(Zdo_Rig *rig, uint16_t networkAddress, uint64_t ieee, uint32_t nowMs)
{
    uint8_t asdu[12];
    uint32_t i;

    asdu[0] = 0x31;
    asdu[1] = (uint8_t)(networkAddress & 0xff);
    asdu[2] = (uint8_t)(networkAddress >> 8);

    for (i = 0; i < 8; i++)
        asdu[3 + i] = (uint8_t)((ieee >> (8 * i)) & 0xff);

    asdu[11] = 0x8e;

    zdoDeliver(rig, ZDO_DEVICE_ANNCE, asdu, (uint32_t)sizeof asdu, nowMs);
}

/* 2.5.4.5.4.3: a device that hears an announcement takes the pair into its address map, a changed address moves the
   row of that IEEE address, and a pair that contradicts the map is a conflict. All ones, this device's own IEEE
   address and a device object with no network layer learn nothing. */
void caseZdoDeviceAnnceHeard(void)
{
    Zdo_Rig rig;
    Nwk_Nwk *nwk;
    uint64_t ieee = 0;
    uint16_t address = 0;
    uint32_t rows;

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, ZDO_EXT_PAN_ID);
    nwk = &rig.stack.nwk;

    zdoAnnounce(&rig, 0x1234, 0x00212effff000a01, 100);
    Test_ExpectCount(Zdo_AnnouncementsHeard(&rig.zdo), 1, "an announcement is heard");
    Test_Expect(Nwk_AddressOfIeee(nwk, 0x00212effff000a01, &address) && address == 0x1234,
                "and the map holds the pair it carried");

    zdoAnnounce(&rig, 0x1235, 0x00212effff000a01, 200);
    Test_Expect(Nwk_AddressOfIeee(nwk, 0x00212effff000a01, &address) && address == 0x1235,
                "a device that announces a new address has its row moved to it");
    Test_ExpectCount(Nwk_IeeeOfAddress(nwk, 0x1234, &ieee), 0, "and nothing answers for the old one");

    rows = Nwk_AddrMapCount(Nwk_AddrMapConst(nwk));
    zdoAnnounce(&rig, 0x1235, 0x00212effff000a02, 300);
    Test_ExpectCount(Nwk_AddressConflictsOther(nwk), 1, "another device announcing that address is a conflict");
    Test_Expect(Nwk_AddressOfIeee(nwk, 0x00212effff000a01, &address) && address == 0x1235
                && Nwk_AddrMapCount(Nwk_AddrMapConst(nwk)) == rows, "which changes no row");

    zdoAnnounce(&rig, 0x1300, 0xffffffffffffffff, 400);
    zdoAnnounce(&rig, 0x1301, 0, 450);
    zdoAnnounce(&rig, 0x1302, ZDO_OWN_IEEE, 500);
    Test_Expect(Nwk_AddrMapCount(Nwk_AddrMapConst(nwk)) == rows, "all ones, the null address and this device's own add no row");
    Test_ExpectCount(Nwk_IeeeOfAddress(nwk, 0x1302, &ieee), 0, "and none answers for the address announced with this device's");
    Test_ExpectCount(Zdo_AnnouncementsHeard(&rig.zdo), 6, "though each is heard");

    Zdo_SetNetwork(&rig.zdo, 0, 0, 0);
    zdoAnnounce(&rig, 0x1400, 0x00212effff000a03, 600);
    Test_ExpectCount(Zdo_AnnouncementsHeard(&rig.zdo), 7, "an object with no network layer still hears it");
}

/* One run of the conflict case: X holds `rowX` and Y holds 0x1235, in the order the caller seeds them, and X then
   announces 0x1235. */
static void zdoAnnounceHeldAddress(int yFirst)
{
    Zdo_Rig rig;
    Nwk_Nwk *nwk;
    uint16_t address = 0;
    uint64_t ieee = 0;
    uint32_t rows;

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, ZDO_EXT_PAN_ID);
    nwk = &rig.stack.nwk;

    if (yFirst)
        (void)Nwk_AddrMapLearn(Nwk_AddrMapOf(nwk), 0x1235, 0x00212effff000a02, ZDO_OWN_SHORT, 50);

    (void)Nwk_AddrMapLearn(Nwk_AddrMapOf(nwk), 0x1234, 0x00212effff000a01, ZDO_OWN_SHORT, 60);

    if (!yFirst)
        (void)Nwk_AddrMapLearn(Nwk_AddrMapOf(nwk), 0x1235, 0x00212effff000a02, ZDO_OWN_SHORT, 70);

    rows = Nwk_AddrMapCount(Nwk_AddrMapConst(nwk));

    zdoAnnounce(&rig, 0x1235, 0x00212effff000a01, 100);

    Test_ExpectCount(Nwk_AddressConflictsOther(nwk), 1, "a device announcing the address another holds is one conflict");
    Test_Expect(Nwk_AddressOfIeee(nwk, 0x00212effff000a01, &address) && address == 0x1234,
                "whichever row was seeded first, the announcing device's row does not move");
    Test_Expect(Nwk_IeeeOfAddress(nwk, 0x1235, &ieee) && ieee == 0x00212effff000a02
                && Nwk_AddrMapCount(Nwk_AddrMapConst(nwk)) == rows, "and the holder keeps its row, with no row added");
}

/* An announcement that names this device's own network address under another IEEE address is a local conflict, and
   one that contradicts the map is a conflict with no row moved, whatever order the rows were learned in. */
void caseZdoDeviceAnnceConflicts(void)
{
    Zdo_Rig rig;
    uint64_t ieee = 0;

    zdoRigBuild(&rig);
    Zdo_SetNetwork(&rig.zdo, &rig.stack.nwk, &rig.aps, ZDO_EXT_PAN_ID);

    zdoAnnounce(&rig, ZDO_OWN_SHORT, 0x00212effff000a09, 100);
    Test_ExpectCount(Nwk_AddressConflictsLocal(&rig.stack.nwk), 1, "this device's own address announced by another is a local conflict");
    Test_ExpectCount(Nwk_IeeeOfAddress(&rig.stack.nwk, ZDO_OWN_SHORT, &ieee), 0, "and is not learned as that device's");

    zdoAnnounceHeldAddress(1);
    zdoAnnounceHeldAddress(0);
}

/* The client's parsers refuse what runs past its frame: a node descriptor a field short, an endpoint list longer than
   the octets behind its count, an announcement without its capability octet, and table reports whose count names
   more records than the frame carries. */
void caseZdoParsersStayInsideTheFrame(void)
{
    static const uint8_t node[3 + 13] = { ZDO_STATUS_SUCCESS, 0x34, 0x12, 0x01, 0x40, 0x8e, 0x35, 0x11 };
    static const uint8_t endpoints[] = { ZDO_STATUS_SUCCESS, 0x34, 0x12, 0x03, 0x01, 0x02 };
    static const uint8_t announcement[] = { 0x01, 0x34, 0x12, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x8e };
    static const uint8_t neighbors[] = { ZDO_STATUS_SUCCESS, 0x02, 0x00, 0x01, 0x00 };
    static const uint8_t routes[] = { ZDO_STATUS_SUCCESS, 0x02, 0x00, 0x02, 0x34, 0x12, 0x00, 0x00, 0x00 };
    static const uint8_t bindings[] = { ZDO_STATUS_SUCCESS, 0x01, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                        0x77, 0x88, 0x01, 0x06, 0x00, 0x03, 0x01, 0x02 };
    Zdo_NodeDescriptor descriptor;
    Zdo_TableReport head;
    Zdo_NeighborReport neighborRecords[2];
    Zdo_RouteReport routeRecords[2];
    Zdo_BindingReport bindingRecords[1];
    uint8_t list[4];
    uint64_t ieee = 0;
    uint16_t address = 0;
    uint8_t capability = 0;

    Test_ExpectStatus(Zdo_NodeDescriptorParse(node, (uint32_t)sizeof node - 1, &descriptor), ZB_ERR_BAD_ARGUMENT,
                      "a node descriptor one octet short is refused");
    Test_ExpectStatus(Zdo_NodeDescriptorParse(node, (uint32_t)sizeof node, &descriptor), ZB_OK, "and read whole");
    Test_ExpectCount(descriptor.manufacturerCode, 0x1135, "its manufacturer code low octet first");

    Test_ExpectCount(Zdo_ActiveEndpointsParse(endpoints, (uint32_t)sizeof endpoints, list, 4), 0,
                     "a count of three over two endpoints reads nothing");
    Test_ExpectCount(Zdo_ActiveEndpointsParse(endpoints, (uint32_t)sizeof endpoints, list, 2), 0,
                     "nor does a count over the caller's room");

    Test_ExpectStatus(Zdo_DeviceAnnouncementParse(announcement, (uint32_t)sizeof announcement - 1, &ieee, &address,
                                                  &capability), ZB_ERR_BAD_FRAME,
                      "an announcement without its capability octet is refused");
    Test_ExpectStatus(Zdo_DeviceAnnouncementParse(announcement, (uint32_t)sizeof announcement, &ieee, &address,
                                                  &capability), ZB_OK, "and read whole");
    Test_Expect(address == 0x1234 && ieee == 0x1122334455667788 && capability == 0x8e,
                "the address, the extended address and the capability, low octet first");

    Test_ExpectStatus(Zdo_NeighborReportParse(neighbors, (uint32_t)sizeof neighbors, &head, neighborRecords, 2),
                      ZB_ERR_BAD_ARGUMENT, "a neighbour report naming a record it does not carry is refused");
    Test_ExpectStatus(Zdo_RouteReportParse(routes, (uint32_t)sizeof routes, &head, routeRecords, 2),
                      ZB_ERR_BAD_ARGUMENT, "a route report one record short is refused");
    Test_ExpectStatus(Zdo_BindingReportParse(bindings, (uint32_t)sizeof bindings, &head, bindingRecords, 1),
                      ZB_ERR_BAD_ARGUMENT, "an extended binding record cut before its endpoint is refused");
}
