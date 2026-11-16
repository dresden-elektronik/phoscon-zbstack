#include "nwk_leave.h"

#include "mac.h"
#include "nwk_addr.h"
#include "nwk_command.h"
#include "nwk_frame.h"
#include "nwk_neighbor.h"
#include "nwk_route.h"
#include "nwk_tx.h"
#include "security.h"
#include "zb_utils.h"

/* R23.1: 3.2.2.18, 3.2.2.18.3, 3.2.2.19, 3.4.4.2, 3.4.4.3.1, 3.6.1.11.1, 3.6.1.11.2, 3.6.1.11.3, 3.6.1.11.4,
   3.6.10.4.1, 4.6.3.6.3, Table 3-26, Table 3-27, Table 3-28 ok. */

static void nwkLeaveNote(Nwk_Nwk *self, uint64_t deviceAddress, uint16_t networkAddress, uint32_t child,
                         uint32_t rejoin)
{
    Nwk_LeaveIndication *slot;

    if (self->leaveIndicationCount >= NWK_LEAVE_INDICATION_MAX)
    {
        self->leaveIndicationsDropped++;

        return;
    }

    slot = &self->leaveIndications[(self->leaveIndicationHead + self->leaveIndicationCount)
                                   % NWK_LEAVE_INDICATION_MAX];

    slot->deviceAddress = deviceAddress;
    slot->networkAddress = networkAddress;
    slot->child = child;
    slot->rejoin = rejoin;

    self->leaveIndicationCount++;
}

/* Figure 3-15's options octet, with the five reserved bits below the three sub-fields left zero. */
ZbStatus Nwk_LeaveCommandCompose(const Nwk_LeaveCommand *command, uint8_t *out, uint32_t outCap)
{
    if (command == 0 || out == 0 || outCap < 1)
        return ZB_ERR_NO_SPACE;

    out[0] = (uint8_t)((command->rejoin ? NWK_LEAVE_OPTION_REJOIN : 0)
                       | (command->request ? NWK_LEAVE_OPTION_REQUEST : 0)
                       | (command->removeChildren ? NWK_LEAVE_OPTION_REMOVE_CHILDREN : 0));

    return ZB_OK;
}

ZbStatus Nwk_LeaveCommandParse(const uint8_t *payload, uint32_t length, Nwk_LeaveCommand *out)
{
    if (payload == 0 || out == 0 || length < 2)
        return ZB_ERR_BAD_FRAME;

    Zb_memset(out, 0, (uint32_t)sizeof *out);

    out->rejoin = (payload[1] & NWK_LEAVE_OPTION_REJOIN) ? 1 : 0;
    out->request = (payload[1] & NWK_LEAVE_OPTION_REQUEST) ? 1 : 0;
    out->removeChildren = (payload[1] & NWK_LEAVE_OPTION_REMOVE_CHILDREN) ? 1 : 0;

    return ZB_OK;
}

static int nwkLeaveOwnAddress(const Nwk_Nwk *self, uint16_t *out)
{
    if (self == 0 || self->mac == 0)
        return 0;

    return Nwk_AddrOwn(Mac_Pib(self->mac), out);
}

/* The neighbour entry that records this device's parent, or 0 when the table holds none. */
static Nwk_NeighborTableEntry *nwkLeaveParent(Nwk_Nwk *self)
{
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (self->neighbors[i].inUse && self->neighbors[i].relationship == NWK_REL_PARENT)
            return &self->neighbors[i];
    }

    return 0;
}

static Nwk_NeighborTableEntry *nwkLeaveEntryOfIeee(Nwk_Nwk *self, uint64_t ieee)
{
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (self->neighbors[i].inUse && self->neighbors[i].ieeeKnown
            && self->neighbors[i].extendedAddress == ieee)
            return &self->neighbors[i];
    }

    return 0;
}

/* One leave frame onto the air, or held for a child that does not listen: secured whenever this device runs network
   security, since a leave of any of the three kinds is sent secured or not at all. */
static ZbStatus nwkLeaveIssue(Nwk_Nwk *self, Nwk_Frame *header, const uint8_t *payload, uint16_t nextHop,
                              uint32_t isBroadcast, int held, uint32_t nowMs)
{
    Mac_DataRequestParameters request;
    const uint8_t *octets;
    uint32_t octetLen;
    uint32_t npduLen = 0;
    uint32_t securedLen = 0;
    ZbStatus status;

    header->securityEnabled = Nwk_TxSecurityRuns(self->security) ? 1 : 0;

    status = NwkFrame_Compose(header, payload, NWK_LEAVE_COMMAND_OCTETS, self->relayNpdu,
                              (uint32_t)sizeof self->relayNpdu, &npduLen);

    if (status != ZB_OK)
        return status;

    octets = self->relayNpdu;
    octetLen = npduLen;

    if (header->securityEnabled)
    {
        status = Nwk_TxProtect(self->security, self->relayNpdu, npduLen, NwkFrame_HeaderLen(header),
                               self->secureScratch, (uint32_t)sizeof self->secureScratch, &securedLen);

        if (status != ZB_OK)
            return status;

        octets = self->secureScratch;
        octetLen = securedLen;
    }

    if (!held)
        status = Nwk_TxIssueRaw(self->mac, octets, octetLen, nextHop, (int)isBroadcast, nowMs, 0);
    else
    {
        Zb_memset(&request, 0, (uint32_t)sizeof request);

        request.frameType = MAC_FRAME_TYPE_DATA;
        request.destAddrMode = MAC_ADDR_SHORT;
        request.srcAddrMode = MAC_ADDR_SHORT;
        request.destPan = Mac_Pib(self->mac)->panId;
        request.destShort = nextHop;
        request.ackRequest = 1;
        request.payload = octets;
        request.payloadLen = octetLen;

        status = Mac_IndirectRequest(self->mac, &request, nowMs);
    }

    if (status == ZB_OK)
        self->leaveCommandsSent++;

    return status;
}

/* The two destinations a leave command frame can have: a request goes to the child it names and is unicast at the MAC
   too, held for a child whose receiver is off; an announcement goes to the all-routers-and-c-hub address by MAC
   broadcast, except for an end device, whose own departure is unicast to the parent it holds. */
static int nwkLeaveAnnounce(Nwk_Nwk *self, const Nwk_LeaveCommand *command,
                            const Nwk_NeighborTableEntry *child, uint32_t nowMs)
{
    uint8_t payload[NWK_LEAVE_COMMAND_OCTETS];
    Nwk_Frame header;
    uint16_t own;
    uint16_t destination;
    uint16_t nextHop = MAC_FRAME_ADDR_BROADCAST;
    uint32_t isBroadcast = 1;
    int held = 0;

    if (!nwkLeaveOwnAddress(self, &own))
        return 0;

    payload[0] = NWK_CMD_LEAVE;

    if (Nwk_LeaveCommandCompose(command, payload + 1, (uint32_t)sizeof payload - 1) != ZB_OK)
        return 0;

    Zb_memset(&header, 0, (uint32_t)sizeof header);

    destination = NWK_ADDR_RX_ON_WHEN_IDLE;

    if (command->request != 0)
    {
        if (child == 0)
            return 0;

        destination = child->networkAddress;
        nextHop = child->networkAddress;
        isBroadcast = 0;
        held = child->rxOnWhenIdle ? 0 : 1;

        if (child->ieeeKnown)
        {
            header.destIeeePresent = 1;
            header.destIeee = child->extendedAddress;
        }
    }
    else if (self->cfg.deviceType == NWK_DEVICE_END_DEVICE)
    {
        Nwk_NeighborTableEntry *parent = nwkLeaveParent(self);

        if (parent == 0)
            return 0;

        nextHop = parent->networkAddress;
        isBroadcast = 0;
    }

    header.frameType = NWK_FRAME_TYPE_COMMAND;
    header.protocolVersion = NWK_PROTOCOL_VERSION;
    header.discoverRoute = NWK_DISCOVER_SUPPRESS;
    header.destAddr = destination;
    header.srcAddr = own;
    header.radius = NWK_LEAVE_RADIUS;
    header.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    header.srcIeeePresent = 1;
    header.srcIeee = Nwk_OwnExtendedAddress(self);

    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    return nwkLeaveIssue(self, &header, payload, nextHop, isBroadcast, held, nowMs) == ZB_OK;
}

static ZbStatus nwkLeaveAskRejoin(Nwk_Nwk *self, uint16_t address, int held, uint32_t nowMs)
{
    Nwk_LeaveCommand command;
    Nwk_Frame header;
    uint8_t payload[NWK_LEAVE_COMMAND_OCTETS];
    uint16_t own;

    if (self == 0 || self->mac == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (!nwkLeaveOwnAddress(self, &own))
        return ZB_ERR_NOT_READY;

    Zb_memset(&command, 0, (uint32_t)sizeof command);

    command.request = 1;
    command.rejoin = 1;
    payload[0] = NWK_CMD_LEAVE;

    if (Nwk_LeaveCommandCompose(&command, payload + 1, (uint32_t)sizeof payload - 1) != ZB_OK)
        return ZB_ERR_NO_SPACE;

    Zb_memset(&header, 0, (uint32_t)sizeof header);

    header.frameType = NWK_FRAME_TYPE_COMMAND;
    header.protocolVersion = NWK_PROTOCOL_VERSION;
    header.discoverRoute = NWK_DISCOVER_SUPPRESS;
    header.destAddr = address;
    header.srcAddr = own;
    header.radius = NWK_LEAVE_RADIUS;
    header.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    header.srcIeeePresent = 1;
    header.srcIeee = Nwk_OwnExtendedAddress(self);

    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    return nwkLeaveIssue(self, &header, payload, address, 0, held, nowMs);
}

ZbStatus Nwk_LeaveUnknownPoller(Nwk_Nwk *self, uint16_t address, uint32_t nowMs)
{
    return nwkLeaveAskRejoin(self, address, 1, nowMs);
}

ZbStatus Nwk_LeaveUnknownSender(Nwk_Nwk *self, uint16_t address, uint32_t nowMs)
{
    return nwkLeaveAskRejoin(self, address, 0, nowMs);
}

/* The rejoin arm leaves the tables standing, and the other arm clears what this layer holds about the network it is
   leaving. The clearing of the whole neighbour table is what the procedure orders; the marking of the former parent
   that the door clause asks for has no counterpart left in it, and the MAC offers no reset to issue. */
static void nwkLeaveDepart(Nwk_Nwk *self, uint32_t rejoin)
{
    Radio_Pib pib;

    if (rejoin != 0)
        return;

    Zb_memset(self->neighbors, 0, (uint32_t)sizeof self->neighbors);
    Zb_memset(self->routes, 0, (uint32_t)sizeof self->routes);
    Zb_memset(self->discoveries, 0, (uint32_t)sizeof self->discoveries);
    Zb_memset(self->addressMap, 0, (uint32_t)sizeof self->addressMap);
    Zb_memset(self->sourceRoutes, 0, (uint32_t)sizeof self->sourceRoutes);

    if (self->security != 0)
        Security_Reset(self->security);

    self->beaconInfo.extendedPanId = 0;
    self->beaconInfo.updateId = 0;
    self->cfg.parentInformation = 0;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);

    pib.present = RADIO_PIB_SHORT_ADDRESS | RADIO_PIB_PAN_ID;
    pib.shortAddress = NWK_ADDR_ALL_DEVICES;
    pib.panId = 0xffff;

    (void)Mac_SetPib(self->mac, &pib);

    self->leavesTaken++;
}

/* A device leaving on its own say, and a child told by its parent, which is the same departure with no frame sent
   back. */
static uint32_t nwkLeaveSelf(Nwk_Nwk *self, const Nwk_LeaveCommand *command, int announce, uint32_t nowMs)
{
    Nwk_LeaveCommand own;
    int sent;

    own = *command;
    own.request = 0;

    if (self->cfg.deviceType == NWK_DEVICE_END_DEVICE)
        own.removeChildren = 0;

    sent = announce ? nwkLeaveAnnounce(self, &own, 0, nowMs) : 1;

    if (self->cfg.deviceType == NWK_DEVICE_END_DEVICE)
        self->beaconInfo.extendedPanId = 0;

    nwkLeaveNote(self, NWK_LEAVE_ADDRESS_NULL, 0, 0, own.rejoin);

    nwkLeaveDepart(self, own.rejoin);

    return sent ? NWK_LEAVE_STATUS_SUCCESS : NWK_LEAVE_STATUS_FRAME_NOT_BUFFERED;
}

uint32_t Nwk_LeaveRequest(Nwk_Nwk *self, uint64_t deviceAddress, int removeChildren, int rejoin, uint32_t nowMs)
{
    Nwk_LeaveCommand command;
    Nwk_NeighborTableEntry *child;

    if (self == 0 || self->mac == 0)
        return NWK_LEAVE_STATUS_FRAME_NOT_BUFFERED;

    if (!Nwk_IsPartOfNetwork(self))
        return NWK_LEAVE_STATUS_INV_REQUESTTYPE;

    Zb_memset(&command, 0, (uint32_t)sizeof command);

    command.rejoin = rejoin ? 1 : 0;
    command.removeChildren = removeChildren ? 1 : 0;

    if (deviceAddress == NWK_LEAVE_ADDRESS_NULL || deviceAddress == Nwk_OwnExtendedAddress(self))
        return nwkLeaveSelf(self, &command, 1, nowMs);

    if (self->cfg.deviceType == NWK_DEVICE_END_DEVICE)
        return NWK_LEAVE_STATUS_INV_REQUESTTYPE;

    child = nwkLeaveEntryOfIeee(self, deviceAddress);

    if (child == 0 || child->deviceType != NWK_DEVICE_END_DEVICE)
        return NWK_LEAVE_STATUS_UNKNOWN_DEVICE;

    if (child->relationship == NWK_REL_UNAUTHENTICATED_CHILD)
    {
        child->relationship = NWK_REL_NONE;

        return NWK_LEAVE_STATUS_SUCCESS;
    }

    command.request = 1;

    if (!nwkLeaveAnnounce(self, &command, child, nowMs))
        return NWK_LEAVE_STATUS_FRAME_NOT_BUFFERED;

    if (child->relationship == NWK_REL_CHILD)
        child->relationship = NWK_REL_PREVIOUS_CHILD;

    if (child->relationship == NWK_REL_UNAUTHENTICATED_CHILD)
        child->relationship = NWK_REL_NONE;

    return NWK_LEAVE_STATUS_SUCCESS;
}

/* The validation a leave request passes, whether it came as a command frame or as a management request: a coordinator
   drops it, a router carries it out only when the NIB allows it, and an end device only when it came from the entry
   that records its parent. */
int Nwk_LeaveRequestAllowedFrom(Nwk_Nwk *self, uint16_t srcAddr, int arrivedAsBroadcast)
{
    Nwk_NeighborTableEntry *entry;

    if (self == 0)
        return 0;

    if (self->cfg.deviceType == NWK_DEVICE_COORDINATOR || arrivedAsBroadcast)
        return 0;

    if (self->cfg.deviceType == NWK_DEVICE_ROUTER)
        return self->leaveRequestAllowed;

    entry = Nwk_NeighborOf(self->neighbors, srcAddr);

    return entry != 0 && entry->relationship == NWK_REL_PARENT;
}

/* A coordinator drops a leave request, a router carries it out only when the NIB allows it, and an end device only
   when the request came from the entry that records its parent. */
static void nwkLeaveRequestRx(Nwk_Nwk *self, uint16_t srcAddr, const Nwk_LeaveCommand *command,
                              int arrivedAsBroadcast, uint32_t nowMs)
{
    if (!Nwk_LeaveRequestAllowedFrom(self, srcAddr, arrivedAsBroadcast))
        return;

    (void)nwkLeaveSelf(self, command, self->cfg.deviceType == NWK_DEVICE_ROUTER ? 1 : 0, nowMs);
}

/* An announced leave is noted for the next higher layer and stops making the sender a neighbour (8397-8398), whatever
   the rejoin flag says, so routes through it go as an aged entry's do. The entry is read before it is rewritten: the
   sender being this device's parent is what the router's own re-announcement and the end device's orphaning turn on. */
void Nwk_LeaveRx(Nwk_Nwk *self, uint16_t srcAddr, uint64_t srcIeee, const Nwk_LeaveCommand *command,
                 int arrivedAsBroadcast, uint32_t nowMs)
{
    Nwk_NeighborTableEntry *entry;
    uint32_t wasChild;
    int fromParent;

    if (self == 0 || command == 0)
        return;

    self->leaveCommandsHeard++;

    if (command->request != 0)
    {
        nwkLeaveRequestRx(self, srcAddr, command, arrivedAsBroadcast, nowMs);

        return;
    }

    entry = Nwk_NeighborOf(self->neighbors, srcAddr);
    fromParent = entry != 0 && entry->relationship == NWK_REL_PARENT;
    wasChild = entry != 0 && (entry->relationship == NWK_REL_CHILD
                              || entry->relationship == NWK_REL_UNAUTHENTICATED_CHILD);

    if (entry != 0)
    {
        if (entry->relationship == NWK_REL_CHILD)
            entry->relationship = NWK_REL_PREVIOUS_CHILD;
        else
        {
            Zb_memset(entry, 0, (uint32_t)sizeof *entry);
            self->routesInvalidated += Nwk_RouteInvalidate(self->routes, srcAddr);
        }
    }

    nwkLeaveNote(self, srcIeee, srcAddr, wasChild, command->rejoin);

    if (!fromParent || command->removeChildren == 0)
        return;

    if (self->cfg.deviceType == NWK_DEVICE_ROUTER)
    {
        (void)nwkLeaveAnnounce(self, command, 0, nowMs);

        self->beaconInfo.extendedPanId = 0;

        nwkLeaveNote(self, NWK_LEAVE_ADDRESS_NULL, 0, 0, command->rejoin);

        return;
    }

    if (self->cfg.deviceType == NWK_DEVICE_END_DEVICE)
    {
        self->beaconInfo.extendedPanId = 0;

        nwkLeaveNote(self, NWK_LEAVE_ADDRESS_NULL, 0, 0, command->rejoin);
    }
}

uint32_t Nwk_PollLeaveIndications(Nwk_Nwk *self, Nwk_LeaveIndication *out, uint32_t max)
{
    uint32_t taken = 0;

    if (self == 0 || out == 0)
        return 0;

    while (taken < max && self->leaveIndicationCount > 0)
    {
        out[taken++] = self->leaveIndications[self->leaveIndicationHead];

        self->leaveIndicationHead = (self->leaveIndicationHead + 1) % NWK_LEAVE_INDICATION_MAX;
        self->leaveIndicationCount--;
    }

    return taken;
}

void Nwk_SetLeaveRequestAllowed(Nwk_Nwk *self, int allowed)
{
    if (self == 0)
        return;

    self->leaveRequestAllowed = allowed ? 1 : 0;
}

int Nwk_LeaveRequestAllowed(const Nwk_Nwk *self)
{
    return self != 0 ? self->leaveRequestAllowed : 0;
}

uint32_t Nwk_LeaveCommandsSent(const Nwk_Nwk *self)
{
    return self != 0 ? self->leaveCommandsSent : 0;
}

uint32_t Nwk_LeaveCommandsHeard(const Nwk_Nwk *self)
{
    return self != 0 ? self->leaveCommandsHeard : 0;
}

uint32_t Nwk_LeavesTaken(const Nwk_Nwk *self)
{
    return self != 0 ? self->leavesTaken : 0;
}
