#include "nwk.h"

#include "mac.h"
#include "nwk_btt.h"
#include "nwk_command.h"
#include "nwk_discovery.h"
#include "nwk_frame.h"
#include "nwk_indirect.h"
#include "nwk_poll.h"
#include "nwk_join.h"
#include "nwk_leave.h"
#include "nwk_neighbor.h"
#include "nwk_parents.h"
#include "nwk_permit.h"
#include "nwk_relay.h"
#include "nwk_route.h"
#include "nwk_rrep.h"
#include "nwk_rreprx.h"
#include "nwk_rreq.h"
#include "nwk_rreqrelay.h"
#include "nwk_rreqrx.h"
#include "nwk_rreqtx.h"
#include "nwk_linkstatus.h"
#include "nwk_sourceroute.h"
#include "nwk_rx.h"
#include "nwk_status.h"
#include "nwk_timeout.h"
#include "nwk_tx.h"
#include "security.h"
#include "zb_time.h"
#include "zb_utils.h"

/* R23.1: 2.2.4.1.1, 2.2.4.1.3, 3.2.1.1.1, 3.3.1, 3.3.2.2.2, 3.4, 3.4.8.1, 3.4.8.2, 3.6.1.10.1, 3.6.1.10.2, 3.6.1.10.5, 3.6.2, 3.6.4.5, 3.6.4.3,
   3.6.4.3.2, 3.6.4.4.1, 3.6.4.4.2, 3.6.4.4.3, 3.6.4.4.3.1, 3.6.4.5.5, 3.6.4.8, 3.6.6, 3.6.7, 3.6.10, 3.6.10.1, 3.6.13, 4.2.2, 4.3.1, 4.3.2, 4.5.1.3
   ok; 3.2.1.1.3, 3.2.2.3, 3.2.2.4, 3.3.1.1.8, 3.6.1.5.1, 3.6.1.6.1, 3.6.1.6.1.1, 3.6.1.8, 3.6.4.4.4 elsewhere. */

/* The PIB's extended address as a payload carries it, defined below: 3.4.3.2 makes it mandatory in this header. */
static uint64_t nwkDoOwnIeee(const Mac_Mac *mac);

/* A route discovery started, defined below: an originator's frame and a relayed one both wait on it. */
static ZbStatus nwkDoDiscoverRoute(Nwk_Nwk *self, Nwk_Tx *tx, uint16_t dstAddr, uint8_t requestRadius, uint16_t ownAddr,
                                   uint32_t nowMs, uint32_t *nwkStatus);

/* 4.3.1.1's protection refused, one count whichever attempt owed it */
static void nwkDoProtectRefused(Nwk_Nwk *self, ZbStatus status)
{
        /* the crossing answered UNSUPPORTED: docs/internals/conformance.md §2 */
    if (status == ZB_ERR_UNSUPPORTED)
    {
        self->droppedUnsupported++;
        return;
    }

    self->txSecurityFailures++;
}

/* A taken-back request's answer: the confirmation ring, the slot released by the same act (docs/internals/coding-rules.md §4.3).
   A full ring refuses the answer and counts it, which is the one policy every pool here has. */
static void nwkDoConfirm(Nwk_Nwk *self, Nwk_Tx *tx, ZbStatus status, uint32_t nwkStatus)
{
    Nwk_DataConfirmParameters *confirm;

    if (tx->forwarded)
    {
        Zb_memset(tx, 0, (uint32_t)sizeof *tx);

        return;
    }

    if (self->confirmCount >= NWK_CONFIRM_MAX)
    {
        self->confirmsDropped++;
        Zb_memset(tx, 0, (uint32_t)sizeof *tx);

        return;
    }

    confirm = &self->confirms[(self->confirmHead + self->confirmCount) % NWK_CONFIRM_MAX];

    confirm->status = status;
    confirm->nwkStatus = nwkStatus;
    confirm->dstAddr = tx->dstAddr;
    confirm->seq = tx->seq;
    confirm->attempts = tx->attempts;
    confirm->handle = tx->lastHandle;   

    self->confirmCount++;

    Zb_memset(tx, 0, (uint32_t)sizeof *tx);
}

/* A request the pool had no room for: Table 3-3's FRAME_NOT_BUFFERED among the confirm's statuses, Table 3-84's own failure */
static void nwkDoNoRoomConfirm(Nwk_Nwk *self, uint16_t dstAddr)
{
    Nwk_DataConfirmParameters *confirm;

    if (self->confirmCount >= NWK_CONFIRM_MAX)
    {
        self->confirmsDropped++;

        return;
    }

    confirm = &self->confirms[(self->confirmHead + self->confirmCount) % NWK_CONFIRM_MAX];

    confirm->status = ZB_ERR_NO_SPACE;
    confirm->nwkStatus = NWK_STATUS_FRAME_NOT_BUFFERED;
    confirm->dstAddr = dstAddr;
    confirm->seq = 0;                   
    confirm->attempts = 0;
    confirm->handle = RADIO_HANDLE_NONE;   

    self->confirmCount++;
}

/* Table 3-84 prints no code for a refusal no delay cures: the seam's status, and the sentinel that says no code */
static void nwkDoAttemptFailed(Nwk_Nwk *self, Nwk_Tx *tx, ZbStatus status)
{
    nwkDoConfirm(self, tx, status, Nwk_TxConfirmStatus(status));
}

/* 8874-8877 for a frame this device composed for the network: the slot's retries run, and nobody is owed a confirm. */
static ZbStatus nwkDoForward(Nwk_Nwk *self, const uint8_t *npdu, uint32_t npduLen, uint32_t headerLen, int secured,
                             uint8_t seq, uint16_t nextHop, uint16_t dstAddr, uint32_t nowMs)
{
    int protectRefused;
    ZbStatus status;

    status = Nwk_TxForward(Nwk_TxFree(self->tx), self->mac, self->security, self->secureScratch,
                           (uint32_t)sizeof self->secureScratch, npdu, npduLen, headerLen, secured, seq, nextHop,
                           dstAddr, nowMs, &protectRefused);

    if (protectRefused)
        nwkDoProtectRefused(self, status);
    else if (status == ZB_ERR_NO_SPACE)
        self->forwardsRefused++;

    return status;
}

/* 3.6.4.8.1's Network Status frame, issued: 3.4.3.2's header, 3.4.3.3.2's two payload octets, K.4.1.1's sequence number */
static ZbStatus nwkDoStatusIssue(Nwk_Nwk *self, uint16_t nextHop, uint16_t destination, uint16_t failedDestination,
                                 int sequenceNumberValid, uint16_t routingSequenceNumber, uint16_t own,
                                 uint32_t statusCode, uint32_t nowMs)
{
    Nwk_Frame reply;
    const Nwk_NeighborTableEntry *neighbor;
    const uint8_t *octets;
    uint32_t len;
    uint32_t securedLen;
    uint32_t octetLen;
    ZbStatus status;

    neighbor = Nwk_NeighborOf(self->neighbors, destination);

    status = Nwk_CommandComposeStatus(&reply, own, nwkDoOwnIeee(self->mac), destination, neighbor,
                                      statusCode, failedDestination, sequenceNumberValid,
                                      routingSequenceNumber, Nwk_TxSecurityRuns(self->security) ? 1 : 0,
                                      &self->seq, self->relayNpdu, (uint32_t)sizeof self->relayNpdu, &len);

    if (status != ZB_OK)
        return status;

    if (!Nwk_NeighborRestsReceiver(self->neighbors, nextHop))
        return nwkDoForward(self, self->relayNpdu, len, NwkFrame_HeaderLen(&reply), reply.securityEnabled,
                            reply.sequenceNumber, nextHop, destination, nowMs);

    octets = self->relayNpdu;
    octetLen = len;

    if (reply.securityEnabled)
    {
        status = Nwk_TxProtect(self->security, self->relayNpdu, len, NwkFrame_HeaderLen(&reply),
                               self->secureScratch, (uint32_t)sizeof self->secureScratch, &securedLen);

        if (status != ZB_OK)
            return status;

        octets = self->secureScratch;
        octetLen = securedLen;
    }

    return Nwk_TxOfferRaw(self->mac, octets, octetLen, nextHop, 1, NWK_TX_HELD_UNTRACKED, nowMs, 0);
}

/* 8882-8884: a relayed frame's failure goes back to its source under Table 3-56's 0x02, the one code it prints for a frame that did not cross.
   3.6.4.8.1: a many-to-one route that breaks is reported with its own code, 0x0c, and the destination is the route's other end either way.
   Only a link seen failing also invalidates every entry through it. */
static void nwkDoDeliveryFailed(Nwk_Nwk *self, uint16_t brokenLink, uint16_t sourceAddr, uint16_t destAddr,
                                int linkFailed, int forwarded, uint32_t nowMs)
{
    Nwk_RoutingTableEntry *broken;
    uint16_t nextHop;
    uint16_t own;
    int sequenceNumberValid;
    uint16_t routingSequenceNumber;
    int manyToOne;

    broken = Nwk_RouteOf(self->routes, destAddr);
    sequenceNumberValid = (broken != 0 && broken->sequenceNumberValid) ? 1 : 0;
    routingSequenceNumber = (broken != 0) ? broken->sequenceNumber : 0;
    manyToOne = (broken != 0 && broken->manyToOne) ? 1 : 0;

    if (linkFailed)
    {
        self->routesInvalidated += Nwk_RouteInvalidate(self->routes, brokenLink);
        Nwk_JoinParentLinkFailed(self, brokenLink);
    }

    if (!forwarded)
        return;

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        return;

    if (!Nwk_RouteNextHop(self->routes, self->neighbors, sourceAddr, nowMs, &nextHop))
    {
        self->droppedNoRoute++;
        return;
    }

    if (nwkDoStatusIssue(self, nextHop, sourceAddr, destAddr, sequenceNumberValid, routingSequenceNumber, own,
                         manyToOne ? NWK_STATUS_CODE_MANY_TO_ONE_FAILURE : NWK_NETWORK_STATUS_LINK_FAILURE,
                         nowMs) == ZB_OK)
        self->linkFailuresReported++;
}

/* A router or coordinator broadcasts its link status once a period, jittered, with no neighbour yet too: one hop to the
   routers, naming its sender and secured like other commands, so it waits for the key. A list too long for one frame
   takes one a turn; a frame the door refuses is not retried, and the rest waits for the next period. */
static void nwkDoLinkStatusTx(Nwk_Nwk *self, uint32_t nowMs)
{
    Nwk_Frame frame;
    uint8_t payload[NWK_FRAME_NPDU_MAX];
    const uint8_t *octets;
    uint32_t room;
    uint32_t payloadLen = 0;
    uint32_t npduLen = 0;
    uint32_t octetLen;
    uint32_t securedLen = 0;
    uint32_t entries = 0;
    uint16_t own;
    uint16_t lastAddress = 0;
    int lastFrame = 1;
    int continuing = self->linkStatusContinues;
    ZbStatus status;

    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        return;

    self->linkStatusContinues = 0;

    if (self->linkStatusAtMs == 0)
    {
        self->linkStatusAtMs = nowMs + NWK_LINK_STATUS_PERIOD_MS;
        return;
    }

    if (!continuing)
    {
        if (!Zb_timeReached(nowMs, self->linkStatusAtMs))
            return;

        self->linkStatusAtMs = nowMs + NWK_LINK_STATUS_PERIOD_MS + Nwk_RelayJitterMs(&self->jitterState, &self->cfg);
    }

    if (self->security != 0 && Security_Level(self->security) != SECURITY_LEVEL_NONE
        && !Nwk_TxSecurityRuns(self->security))
        return;

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        return;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = NWK_FRAME_TYPE_COMMAND;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.destAddr = NWK_ADDR_ROUTERS;
    frame.srcAddr = own;
    frame.radius = NWK_LINK_STATUS_RADIUS;
    frame.srcIeeePresent = 1;
    frame.srcIeee = nwkDoOwnIeee(self->mac);
    frame.securityEnabled = Nwk_TxSecurityRuns(self->security) ? 1 : 0;

    room = NWK_FRAME_NPDU_MAX - NwkFrame_HeaderLen(&frame) - 1;

    if (frame.securityEnabled)
        room -= Security_NwkOverhead(self->security);

    if (Nwk_LinkStatusCompose(self->neighbors, !continuing, continuing ? self->linkStatusFromAddr : 0, payload + 1, room,
                              &payloadLen, &entries, &lastFrame, &lastAddress) != ZB_OK)
        return;

    if (continuing && entries == 0)
        return;

    payload[0] = NWK_CMD_LINK_STATUS;
    payloadLen++;

    frame.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    if (NwkFrame_Compose(&frame, payload, payloadLen, self->relayNpdu, (uint32_t)sizeof self->relayNpdu,
                         &npduLen) != ZB_OK)
        return;

    octets = self->relayNpdu;
    octetLen = npduLen;

    if (frame.securityEnabled)
    {
        status = Nwk_TxProtect(self->security, self->relayNpdu, npduLen, NwkFrame_HeaderLen(&frame),
                               self->secureScratch, (uint32_t)sizeof self->secureScratch, &securedLen);

        if (status != ZB_OK)
        {
            nwkDoProtectRefused(self, status);
            return;
        }

        octets = self->secureScratch;
        octetLen = securedLen;
    }

    if (Nwk_TxIssueRaw(self->mac, octets, octetLen, MAC_FRAME_ADDR_BROADCAST, 1, nowMs, 0) != ZB_OK)
    {
        self->linkStatusAtMs = nowMs + NWK_LINK_STATUS_RETRY_MS;
        self->linkStatusContinues = continuing;
        return;
    }

    self->linkStatusSent++;
    self->linkStatusContinues = !lastFrame;
    self->linkStatusFromAddr = lastAddress;
}

/* A child's Timeout counter is decremented by the real time that passed, and the entry goes when it reaches zero; a
   Timeout Request or a keepalive poll restarts it, and a counter restored without its clock starts on this turn. */
static void nwkDoChildTimeout(Nwk_Nwk *self, uint32_t nowMs)
{
    Nwk_NeighborTableEntry *entry;
    uint32_t elapsed;
    uint32_t i;

    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        return;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        entry = &self->neighbors[i];

        if (!entry->inUse || entry->deviceType != NWK_DEVICE_END_DEVICE || entry->timeoutCounter == 0)
            continue;

        if (!entry->timeoutStarted)
        {
            entry->timeoutMs = nowMs;
            entry->timeoutStarted = 1;

            continue;
        }

        elapsed = (nowMs - entry->timeoutMs) / 1000;

        if (elapsed == 0)
            continue;

        entry->timeoutMs += elapsed * 1000;

        if (elapsed >= entry->timeoutCounter)
        {
            Zb_memset(entry, 0, (uint32_t)sizeof *entry);
            self->childrenAgedOut++;

            continue;
        }

        entry->timeoutCounter -= elapsed;
    }
}

/* The two answers to a poll: a known end device's counter restarts, and a device polling with no entry, by a short
   address it can be sent to, is held a leave request, one at a time. */
static void nwkDoPolls(Nwk_Nwk *self, uint32_t nowMs)
{
    Nwk_NeighborTableEntry *entry;
    const Mac_PollArrival *poll;
    uint32_t taken;
    uint32_t i;
    uint32_t j;

    taken = Mac_PollArrivals(self->mac, self->macPolls, MAC_POLL_EVENT_MAX);

    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        return;

    for (i = 0; i < taken; i++)
    {
        poll = &self->macPolls[i];
        entry = 0;

        if (poll->addrMode == MAC_ADDR_SHORT)
            entry = Nwk_NeighborOf(self->neighbors, poll->shortAddress);

        for (j = 0; poll->addrMode == MAC_ADDR_EXTENDED && j < NWK_NEIGHBOR_MAX; j++)
        {
            if (self->neighbors[j].inUse && self->neighbors[j].ieeeKnown
                && self->neighbors[j].extendedAddress == poll->extendedAddress)
                entry = &self->neighbors[j];
        }

        if (entry != 0)
        {
            if (entry->deviceType == NWK_DEVICE_END_DEVICE)
            {
                Nwk_TimeoutRestart(entry, nowMs);
                entry->keepaliveReceived = 1;
                self->keepalivesReceived++;
            }

            continue;
        }

        if (poll->addrMode != MAC_ADDR_SHORT || Nwk_AddrIsBroadcast(poll->shortAddress)
            || Nwk_AddrIsReserved(poll->shortAddress)
            || Mac_IndirectHeldFor(self->mac, poll->shortAddress) != 0)
            continue;

        if (Nwk_LeaveUnknownPoller(self, poll->shortAddress, nowMs) == ZB_OK)
            self->unknownPollLeaves++;
    }
}

/* 3.6.4.4.4's sweep, 3.6.4.4.3.1's promotion over what it aged, and 3.6.4.8.1's invalidation of the routes through
   an entry it retired */
static void nwkDoNeighborAge(Nwk_Nwk *self, uint32_t nowMs)
{
    uint32_t retired;
    uint32_t i;

    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        return;

    if (self->activityDecayAtMs == 0)
        self->activityDecayAtMs = nowMs + NWK_LINK_STATUS_PERIOD_MS;
    else if (Zb_timeReached(nowMs, self->activityDecayAtMs))
    {
        Nwk_NeighborActivityDecay(self->neighbors);
        self->activityDecayAtMs += NWK_LINK_STATUS_PERIOD_MS;
    }

    retired = Nwk_NeighborAge(self->neighbors, nowMs);

    self->neighborsAgedOut += retired;

    self->backbonePromotions += Nwk_NeighborPromoteBackbone(self->neighbors,
                                                            NWK_LINK_STATUS_BACKBONE_FORMATION_TICKS,
                                                            NWK_LINK_STATUS_BACKBONE_NEIGHBORS);

    if (retired == 0)
        return;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!self->neighbors[i].inUse)
            continue;

        if (self->neighbors[i].age <= NWK_ROUTER_AGE_LIMIT)
            continue;

        if (self->neighbors[i].outgoingCost != 0)
            continue;

        self->routesInvalidated += Nwk_RouteInvalidate(self->routes, self->neighbors[i].networkAddress);
    }
}

/* 3.6.4.8.1's removal of the entry the status names is a deletion of it, not an invalidation */
static void nwkDoStatusRemoveRoute(Nwk_Nwk *self, const Nwk_NetworkStatusPayload *status)
{
    Nwk_RoutingTableEntry *route;

    if (!status->valid)
        return;

    route = Nwk_RouteOf(self->routes, status->targetAddress);

    if (route == 0)
        return;

    Zb_memset(route, 0, (uint32_t)sizeof *route);
    self->statusRoutesRemoved++;
}

/* One change of the source route table for the higher layer; a full ring counts what it lost. */
static void nwkDoSourceRouteNotice(Nwk_Nwk *self, uint16_t destination, uint32_t reason, const uint16_t *relays,
                                   uint32_t count)
{
    Nwk_SourceRouteNotice *notice;
    uint32_t i;

    if (self->sourceRouteNoticeCount >= NWK_SOURCE_ROUTE_NOTICE_MAX)
    {
        self->sourceRouteNoticesDropped++;
        return;
    }

    notice = &self->sourceRouteNotices[(self->sourceRouteNoticeHead + self->sourceRouteNoticeCount)
                                       % NWK_SOURCE_ROUTE_NOTICE_MAX];

    Zb_memset(notice, 0, (uint32_t)sizeof *notice);
    notice->destinationAddress = destination;
    notice->reason = reason;
    notice->relayCount = count;

    for (i = 0; i < count; i++)
        notice->relayList[i] = relays[i];

    self->sourceRouteNoticeCount++;
}

/* A record's relays stored for `destination`, told when they are new or differ from the row's. */
static void nwkDoSourceRouteLearn(Nwk_Nwk *self, uint16_t destination, const uint16_t *relays, uint32_t count,
                                  uint32_t nowMs)
{
    uint32_t verdict = Nwk_SourceRouteLearn(self->sourceRoutes, destination, relays, count, nowMs);

    if (verdict == NWK_SR_FULL)
        return;

    self->sourceRoutesLearned++;

    if (verdict == NWK_SR_LEARNED)
        nwkDoSourceRouteNotice(self, destination, NWK_SR_NOTICE_LEARNED, relays, count);
    else if (verdict == NWK_SR_UPDATED)
        nwkDoSourceRouteNotice(self, destination, NWK_SR_NOTICE_CHANGED, relays, count);
}

/* 3.6.4.5.5's last sentence: the record replaces the route to its originator, and the routes this device already
   holds to the relays on it, each relay's being the part of the list between it and this device. The relay next to
   this device is reached directly, so its row goes. */
static void nwkDoSourceRouteRecord(Nwk_Nwk *self, uint16_t originator, const uint16_t *relays, uint32_t count,
                                   uint32_t nowMs)
{
    uint32_t i;

    if (count == 0)
    {
        if (Nwk_SourceRouteForget(self->sourceRoutes, originator))
            nwkDoSourceRouteNotice(self, originator, NWK_SR_NOTICE_DIRECT, 0, 0);

        return;
    }

    nwkDoSourceRouteLearn(self, originator, relays, count, nowMs);

    for (i = 0; i < count; i++)
    {
        if (Nwk_SourceRouteOf(self->sourceRoutes, relays[i], nowMs) == 0)
            continue;

        if (i + 1 == count)
        {
            (void)Nwk_SourceRouteForget(self->sourceRoutes, relays[i]);
            nwkDoSourceRouteNotice(self, relays[i], NWK_SR_NOTICE_DIRECT, 0, 0);
        }
        else
        {
            nwkDoSourceRouteLearn(self, relays[i], relays + i + 1, count - 1 - i, nowMs);
        }
    }
}

/* 8826-8829 send to an end device child directly and 8835-8837 over an ACTIVE routing entry, and only a
   destination with neither is looked up in the source route table (8857-8860) */
static int nwkDoRoutesFirst(Nwk_Nwk *self, uint16_t destination)
{
    const Nwk_NeighborTableEntry *neighbor = Nwk_NeighborOf(self->neighbors, destination);
    const Nwk_RoutingTableEntry *route = Nwk_RouteOf(self->routes, destination);

    if (neighbor != 0 && neighbor->deviceType == NWK_DEVICE_END_DEVICE && neighbor->relationship == NWK_REL_CHILD)
        return 1;

    return route != 0 && route->status == NWK_ROUTE_ACTIVE;
}

/* 9403-9412's 0x0b removes the source route to the payload's destination, at the router the status is for and at
   the parent of the end device it is for */
static void nwkDoStatusRemoveSourceRoute(Nwk_Nwk *self, const Nwk_NetworkStatusPayload *status)
{
    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType) || !Nwk_StatusOwesSourceRouteRemoval(status))
        return;

    if (!Nwk_SourceRouteForget(self->sourceRoutes, status->targetAddress))
        return;

    self->statusSourceRoutesRemoved++;
    nwkDoSourceRouteNotice(self, status->targetAddress, NWK_SR_NOTICE_FAILED, 0, 0);
}

static void nwkDoStatusAtDestination(Nwk_Nwk *self, const uint8_t *payload, uint32_t payloadLen)
{
    Nwk_NetworkStatusPayload status;

    status = Nwk_StatusRead(payload, payloadLen);

    nwkDoStatusRemoveSourceRoute(self, &status);

    if (!Nwk_StatusRemovesAtDestination(&status, self->cfg.deviceType))
        return;

    nwkDoStatusRemoveRoute(self, &status);
}

/* 3.6.4.8.1's parent half: a status carried on to this device's end-device child removes the payload's entry first */
static void nwkDoStatusAtParent(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen)
{
    const Nwk_NeighborTableEntry *addressed;
    Nwk_NetworkStatusPayload status;

    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        return;

    status = Nwk_StatusRead(payload, payloadLen);
    addressed = Nwk_NeighborOf(self->neighbors, frame->destAddr);

    if (addressed != 0 && addressed->deviceType == NWK_DEVICE_END_DEVICE && addressed->relationship == NWK_REL_CHILD)
        nwkDoStatusRemoveSourceRoute(self, &status);

    if (!Nwk_StatusRemovesAtParent(&status, addressed))
        return;

    nwkDoStatusRemoveRoute(self, &status);
}

/* A status heard during the delay cancels the broadcast this device owes, and the offending address is what the
   identical payload means. */
static void nwkDoConflictStatusHeard(Nwk_Nwk *self, const uint8_t *payload, uint32_t payloadLen)
{
    Nwk_NetworkStatusPayload status;

    if (!self->conflictBroadcastPending)
        return;

    status = Nwk_StatusRead(payload, payloadLen);

    if (!status.valid || status.statusCode != NWK_NETWORK_STATUS_ADDRESS_CONFLICT)
        return;

    if (status.targetAddress != (uint16_t)self->conflictBroadcastAddress)
        return;

    self->conflictBroadcastPending = 0;
    self->conflictBroadcastsCancelled++;
}

/* The record a confirm answers: a held relay's by the MSDU handle it was queued under; 0 when it answers none. */
static Nwk_RelayTrack *nwkDoRelayTrackFor(Nwk_Nwk *self, const Mac_DataConfirmParameters *confirm, int *held)
{
    uint32_t slot;

    *held = confirm->msduHandle >= NWK_TX_HELD_RELAY_FIRST
            && confirm->msduHandle < NWK_TX_HELD_RELAY_FIRST + NWK_RELAY_HELD_MAX;

    if (!*held)
        return 0;

    slot = (uint32_t)confirm->msduHandle - NWK_TX_HELD_RELAY_FIRST;

    return self->heldRelays[slot].inUse ? &self->heldRelays[slot] : 0;
}

/* A relay held for a resting child has 3.6.4.8.1's frame and source in a record: a failed extraction leaves it queued,
   and its expiry is the failure. */
static int nwkDoRelayAnswered(Nwk_Nwk *self, const Mac_DataConfirmParameters *confirm, uint32_t nowMs)
{
    Nwk_RelayTrack *track;
    int held;

    track = nwkDoRelayTrackFor(self, confirm, &held);

    if (track == 0)
        return 0;

    if (held && confirm->status != ZB_OK && confirm->status != ZB_ERR_TRANSACTION_EXPIRED)
    {
        Nwk_NeighborTxFailure(self->neighbors, track->nextHop);
        return 1;
    }

    if (confirm->status == ZB_OK)
    {
        Nwk_NeighborTxSuccess(self->neighbors, track->nextHop);
        Zb_memset(track, 0, (uint32_t)sizeof *track);

        return 1;
    }

    Nwk_NeighborTxFailure(self->neighbors, track->nextHop);

    if (confirm->status == ZB_ERR_NO_ACK || confirm->status == ZB_ERR_DEVICE
        || confirm->status == ZB_ERR_TRANSACTION_EXPIRED)
        nwkDoDeliveryFailed(self, track->nextHop, track->sourceAddr, track->destAddr, 1, 1, nowMs);

    Zb_memset(track, 0, (uint32_t)sizeof *track);

    return 1;
}

/* A held relay's record is closed by its confirm, extraction or expiry; one whose confirm never came (a full confirm
   ring, a radio adopted again) is freed a second past the MAC's own persistence, so the pool cannot fill with them. */
static void nwkDoHeldRelayAge(Nwk_Nwk *self, uint32_t nowMs)
{
    uint32_t slot;

    for (slot = 0; slot < NWK_RELAY_HELD_MAX; slot++)
    {
        if (!self->heldRelays[slot].inUse
            || Zb_timeWithin(nowMs, self->heldRelays[slot].issuedMs, MAC_TRANSACTION_PERSISTENCE_MS + 1000))
            continue;

        Zb_memset(&self->heldRelays[slot], 0, (uint32_t)sizeof self->heldRelays[slot]);
        self->relaysHeldAgedOut++;
    }
}

/* The first free held-relay record, or -1 when every one waits on a child. */
static int nwkDoHeldRelayFree(const Nwk_Nwk *self)
{
    uint32_t slot;

    for (slot = 0; slot < NWK_RELAY_HELD_MAX; slot++)
    {
        if (!self->heldRelays[slot].inUse)
            return (int)slot;
    }

    return -1;
}

/* 3.2.1.1.3's retry law on the MAC's answer; 3.6.6 gives a broadcast's retransmission to the BTT instead */
/* The MAC's other primitive, drained so its ring does not fill: the outcome of a transaction an MLME response
   started. This stack has no NLME primitive to hand it to yet, so it is counted here. */
static void nwkDoDrainCommStatus(Nwk_Nwk *self)
{
    uint32_t got = Mac_PollCommStatus(self->mac, self->macCommStatus, MAC_COMM_STATUS_MAX);
    uint32_t i;

    self->commStatusSeen += got;

    for (i = 0; i < got; i++)
        Nwk_JoinCommStatus(self, &self->macCommStatus[i]);
}

static void nwkDoDrainConfirms(Nwk_Nwk *self, uint32_t nowMs)
{
    const Mac_DataConfirmParameters *confirm;
    Nwk_Tx *tx;
    uint32_t got;
    uint32_t i;
    uint32_t j;

    got = Mac_PollConfirms(self->mac, self->macConfirms, MAC_TX_TRACK_MAX);

    for (i = 0; i < got; i++)
    {
        confirm = &self->macConfirms[i];
        tx = 0;

        for (j = 0; j < NWK_TX_MAX; j++)
        {
            if (self->tx[j].state != NWK_TX_OUTSTANDING)
                continue;

            if (self->tx[j].indirect)
            {
                if (confirm->msduHandle != self->tx[j].msduHandle)
                    continue;
            }
            else if (self->tx[j].lastHandle != confirm->handle)
                continue;

            tx = &self->tx[j];
            break;
        }

        if (tx == 0)
        {
            if (Nwk_JoinKeepaliveAnswered(self, confirm) || nwkDoRelayAnswered(self, confirm, nowMs))
                continue;

            self->confirmsIgnored++;
            continue;
        }

        if (tx->indirect && confirm->status != ZB_OK && confirm->status != ZB_ERR_TRANSACTION_EXPIRED)
        {
            Nwk_NeighborTxFailure(self->neighbors, tx->nextHop);
            continue;
        }

        if (confirm->status == ZB_OK)
        {
            if (!tx->isBroadcast)
            {
                Nwk_NeighborTxSuccess(self->neighbors, tx->nextHop);
                Nwk_JoinParentLinkHeld(self, tx->nextHop);
            }

            nwkDoConfirm(self, tx, ZB_OK, NWK_STATUS_SUCCESS);
            continue;
        }

        if (!tx->isBroadcast && Nwk_TxBlamesNextHop(confirm->status))
            Nwk_NeighborTxFailure(self->neighbors, tx->nextHop);

        if (!tx->isBroadcast && tx->attempts < NWK_UNICAST_RETRIES + 1 && Nwk_TxRetryOwed(confirm->status))
        {
            tx->state = NWK_TX_AWAITING_RETRY;
            tx->nextRetryMs = nowMs + NWK_UNICAST_RETRY_DELAY_MS;
            continue;
        }

        if (tx->forwarded && Nwk_TxRefusedForRoom(confirm->status))
            self->forwardsGivenUp++;

        if (!tx->isBroadcast && (confirm->status == ZB_ERR_NO_ACK || confirm->status == ZB_ERR_DEVICE))
            nwkDoDeliveryFailed(self, tx->nextHop, tx->sourceAddr, tx->dstAddr, 1, tx->reportsFailure, nowMs);
        else if (tx->reportsFailure)
            nwkDoDeliveryFailed(self, tx->nextHop, tx->sourceAddr, tx->dstAddr, 0, 1, nowMs);

        nwkDoConfirm(self, tx, confirm->status, NWK_STATUS_LAST_MAC_STATUS);
    }
}

/* The broadcast table's record of a frame this device originates, found by the slot's sequence number. */
static Nwk_BroadcastTransactionRecord *nwkDoOwnBroadcastRecord(Nwk_Nwk *self, const Nwk_Tx *tx)
{
    Nwk_BroadcastTransactionRecord *record;
    uint16_t own;

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        return 0;

    record = Nwk_BttOf(self->btt, own, tx->seq);

    return record != 0 && record->inUse && record->originates ? record : 0;
}

/* The copies a broadcast owes its resting children, made once the frame itself is on its way. */
static void nwkDoBroadcastCopies(Nwk_Nwk *self, const Nwk_Tx *tx, uint32_t nowMs)
{
    uint16_t own;
    ZbStatus status;

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        return;

    status = Nwk_IndirectTransactionCopies(self->neighbors, self->cfg.deviceType, self->mac, self->security,
                                           tx->dstAddr, own, tx->npdu, tx->npduLen, tx->headerLen, tx->secured,
                                           self->secureScratch, (uint32_t)sizeof self->secureScratch, nowMs);

    if (status != ZB_OK)
        nwkDoProtectRefused(self, status);
}

/* A held broadcast sent at last: the passive-acknowledgment wait counts from now, and the children's copies follow. */
static void nwkDoBroadcastReleased(Nwk_Nwk *self, const Nwk_Tx *tx, uint32_t nowMs)
{
    Nwk_BroadcastTransactionRecord *record = nwkDoOwnBroadcastRecord(self, tx);

    if (record != 0)
        record->nextRelayMs = nowMs + NWK_PASSIVE_ACK_TIMEOUT_MS + Nwk_RelayJitterMs(&self->jitterState, &self->cfg);

    nwkDoBroadcastCopies(self, tx, nowMs);
}

/* A held broadcast that never reached the air is confirmed so, and its record goes, so nothing sends it after. */
static void nwkDoBroadcastAbandoned(Nwk_Nwk *self, const Nwk_Tx *tx)
{
    Nwk_BroadcastTransactionRecord *record = nwkDoOwnBroadcastRecord(self, tx);

    if (record != 0)
        Zb_memset(record, 0, (uint32_t)sizeof *record);
}

/* Whether a refused attempt is asked again: a unicast within its retry count, a broadcast within its hold. */
static int nwkDoRetryAllowed(const Nwk_Tx *tx, uint32_t nowMs)
{
    if (tx->isBroadcast)
        return Zb_timeWithin(nowMs, tx->heldSinceMs, NWK_BROADCAST_HOLD_MS);

    return tx->attempts < NWK_UNICAST_RETRIES + 1;
}

/* The next attempt's floor: a unicast waits out nwkcUnicastRetryDelay, a broadcast refused for room goes next turn. */
static uint32_t nwkDoRetryAt(const Nwk_Tx *tx, uint32_t nowMs)
{
    return tx->isBroadcast ? nowMs : nowMs + NWK_UNICAST_RETRY_DELAY_MS;
}

/* The retries whose floor has passed: 3.2.1.1.3 re-secures each attempt, 7.2.3 re-offers an unsecured slot as composed */
static void nwkDoRetries(Nwk_Nwk *self, uint32_t nowMs)
{
    Nwk_Tx *tx;
    uint32_t i;
    ZbStatus status;
    int retryable;
    int protectRefused;

    for (i = 0; i < NWK_TX_MAX; i++)
    {
        tx = &self->tx[i];

        if (tx->state != NWK_TX_AWAITING_RETRY)
            continue;

        if (!Zb_timeReached(nowMs, tx->nextRetryMs))
            continue;

        status = Nwk_TxIssueAttempt(tx, self->mac, self->security, self->secureScratch,
                                    (uint32_t)sizeof self->secureScratch, nowMs, &retryable, &protectRefused);

        if (protectRefused)
            nwkDoProtectRefused(self, status);

        if (status == ZB_OK)
        {
            self->lastRequestHandle = tx->lastHandle;

            if (tx->isBroadcast)
                nwkDoBroadcastReleased(self, tx, nowMs);

            continue;
        }

        if (retryable && nwkDoRetryAllowed(tx, nowMs))
        {
            tx->nextRetryMs = nwkDoRetryAt(tx, nowMs);
            continue;
        }

        if (tx->isBroadcast)
            nwkDoBroadcastAbandoned(self, tx);

        if (tx->forwarded)
            self->forwardsGivenUp++;

        if (tx->reportsFailure)
            nwkDoDeliveryFailed(self, tx->nextHop, tx->sourceAddr, tx->dstAddr, 0, 1, nowMs);

        nwkDoAttemptFailed(self, tx, status);
    }
}

/* Table 3-4's NsduLength ceiling of 108: an NSDU longer than that is refused whole, never truncated */
static void nwkDoIndicate(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *nsdu, uint32_t nsduLen,
                          uint32_t lqi, int wasBroadcast, int securityUsed)
{
    Nwk_DataIndicationParameters *slot;

    if (nsduLen > NWK_NSDU_MAX)
    {
        self->droppedIndications++;
        return;
    }

    slot = &self->indication;

    Zb_memset(slot, 0, (uint32_t)sizeof *slot);

    slot->dstAddr = frame->destAddr;
    slot->srcAddr = frame->srcAddr;
    slot->seq = frame->sequenceNumber;
    slot->radiusRemaining = frame->radius;
    slot->frameType = (uint32_t)frame->frameType;
    slot->lqi = lqi;
    slot->wasBroadcast = wasBroadcast;
    slot->securityUsed = securityUsed;
    slot->nsdu = nsdu;
    slot->nsduLength = nsduLen;

    if (frame->frameType == NWK_FRAME_TYPE_COMMAND && nsduLen != 0)
        slot->commandIdentifier = nsdu[0];

    self->indicationHeld = 1;
}

/* 3.6.13's answer to an unknown or unsupported command: aimed at the offender's NWK source per 3.4.3.1, acknowledgment asked */
static void nwkDoUnknownCommandReply(Nwk_Nwk *self, const Nwk_Frame *offender, uint32_t commandId,
                                     uint32_t nowMs)
{
    Nwk_Frame reply;
    const Nwk_NeighborTableEntry *neighbor;
    uint16_t own;
    uint16_t nextHop;
    uint32_t len;
    uint32_t securedLen;
    const uint8_t *octets;
    uint32_t octetLen;
    ZbStatus status;

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own))
    {
        self->droppedNotForMe++;
        return;
    }

    neighbor = Nwk_NeighborOf(self->neighbors, offender->srcAddr);

    status = Nwk_CommandComposeReply(&reply, offender, commandId, own, nwkDoOwnIeee(self->mac),
                                     neighbor, Nwk_TxSecurityRuns(self->security) ? 1 : 0, &self->seq,
                                     self->relayNpdu, (uint32_t)sizeof self->relayNpdu, &len);

    if (status != ZB_OK)
    {
        self->droppedUnsupported++;
        return;
    }

    if (!Nwk_RouteNextHop(self->routes, self->neighbors, offender->srcAddr, nowMs, &nextHop))
    {
        self->droppedNoRoute++;
        return;
    }

    if (!Nwk_NeighborRestsReceiver(self->neighbors, nextHop))
    {
        if (nwkDoForward(self, self->relayNpdu, len, NwkFrame_HeaderLen(&reply), reply.securityEnabled,
                         reply.sequenceNumber, nextHop, offender->srcAddr, nowMs) == ZB_OK)
            self->replyCommands++;

        return;
    }

    octets = self->relayNpdu;
    octetLen = len;

    if (reply.securityEnabled)
    {
        status = Nwk_TxProtect(self->security, self->relayNpdu, len, NwkFrame_HeaderLen(&reply),
                               self->secureScratch, (uint32_t)sizeof self->secureScratch, &securedLen);

        if (status != ZB_OK)
        {
            nwkDoProtectRefused(self, status);
            return;
        }

        octets = self->secureScratch;
        octetLen = securedLen;
    }

    if (Nwk_TxOfferRaw(self->mac, octets, octetLen, nextHop, 1, NWK_TX_HELD_UNTRACKED, nowMs, 0) != ZB_OK)
        return;

    self->replyCommands++;
}

/* 7.2.1.4's address octets, lowest first, laid in as they arrive: `mac` converts only its own frames (docs/internals/protocol.md §6) */
static uint64_t nwkDoOwnIeee(const Mac_Mac *mac)
{
    const Radio_Pib *pib = Mac_Pib(mac);
    uint64_t value;
    uint32_t i;

    value = 0;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        value = value | ((uint64_t)pib->extendedAddress[i] << (i * 8));

    return value;
}

/* 3.6.4.5.1.1's reply to a request naming this device or its end device child, who is the responder either way
   (7075-7076, 7085-7086): Table 3-79's sender address as next hop, that one link's cost (9102-9105) */
static void nwkDoRreqReply(Nwk_Nwk *self, const Nwk_Frame *frame, const Nwk_RouteRequestFields *fields,
                           const Nwk_RreqRxDecision *decision, uint16_t own, uint32_t nowMs)
{
    Nwk_NeighborTableEntry *sender;
    Nwk_NeighborTableEntry *originator;
    Nwk_NeighborTableEntry *child;
    Nwk_RouteReplyPayload reply;
    Nwk_Frame header;
    uint8_t payload[NWK_RREP_PAYLOAD_MAX];
    uint32_t payloadLen;
    uint32_t npduLen;
    uint64_t originatorIeee;
    ZbStatus status;

    sender = Nwk_NeighborOf(self->neighbors, decision->senderAddr);

    if (sender == 0)
    {
        self->rreqDroppedNoNeighbor++;
        return;
    }

    originatorIeee = 0;

    if (frame->srcIeeePresent)
        originatorIeee = frame->srcIeee;
    else
    {
        originator = Nwk_NeighborOf(self->neighbors, decision->sourceAddr);

        if (originator != 0 && originator->ieeeKnown)
            originatorIeee = originator->extendedAddress;
    }

    Zb_memset(&reply, 0, (uint32_t)sizeof reply);

    reply.requestId = fields->requestId;
    reply.originatorAddr = decision->sourceAddr;        
    reply.responderAddr = fields->destAddr;
    reply.pathCost = (uint8_t)Nwk_RreqRxLinkCost(sender);  
    reply.originatorIeee = originatorIeee;
    reply.responderIeee = nwkDoOwnIeee(self->mac);

    child = fields->destAddr != own ? Nwk_NeighborOf(self->neighbors, fields->destAddr) : 0;

    if (child != 0 && child->ieeeKnown)
        reply.responderIeee = child->extendedAddress;
    else if (fields->destAddr != own && fields->destIeeePresent)
        reply.responderIeee = fields->destIeee;

    status = Nwk_RrepCompose(&reply, &self->routingSequenceNumber, payload, (uint32_t)sizeof payload,
                             &payloadLen);

    if (status != ZB_OK)
    {
        self->droppedUnsupported++;
        return;
    }

    Zb_memset(&header, 0, (uint32_t)sizeof header);

    header.frameType = NWK_FRAME_TYPE_COMMAND;
    header.protocolVersion = NWK_PROTOCOL_VERSION;
    header.discoverRoute = NWK_DISCOVER_SUPPRESS;       
    header.destAddr = decision->senderAddr;             
    header.srcAddr = own;
    header.radius = NWK_RREP_RADIUS;                    
    header.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    header.srcIeeePresent = 1;                          
    header.srcIeee = nwkDoOwnIeee(self->mac);
    header.securityEnabled = Nwk_TxSecurityRuns(self->security) ? 1 : 0;
    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    status = NwkFrame_Compose(&header, payload, payloadLen, self->relayNpdu,
                              (uint32_t)sizeof self->relayNpdu, &npduLen);

    if (status != ZB_OK)
    {
        self->droppedUnsupported++;
        return;
    }

    if (nwkDoForward(self, self->relayNpdu, npduLen, NwkFrame_HeaderLen(&header), header.securityEnabled,
                     header.sequenceNumber, decision->senderAddr, decision->senderAddr, nowMs) != ZB_OK)
        return;

    self->routeRepliesSent++;
}

/* 9152-9155: the routing entry for the request's destination; a many-to-one request's is the one for its source (9125-9142) */
static void nwkDoRreqRelayMark(Nwk_Nwk *self, const Nwk_RouteRequestFields *fields, uint32_t nowMs)
{
    Nwk_RoutingTableEntry *route = Nwk_RouteOf(self->routes, fields->destAddr);

    if (route)
    {
        if (route->status == NWK_ROUTE_ACTIVE)
            return;             

        route->status = NWK_ROUTE_DISCOVERY_UNDERWAY;
        route->ageMs = nowMs;

        return;
    }

    if (fields->manyToOne != NWK_RREQ_MANY_TO_ONE_NONE)
        return;                 

    route = Nwk_RouteClaim(self->routes);

    if (route == 0)
        return;

    route->inUse = 1;
    route->destinationAddress = fields->destAddr;
    route->status = NWK_ROUTE_DISCOVERY_UNDERWAY;
    route->ageMs = nowMs;
}

/* 3.6.4.5.1.4's forwarded request: the received payload with 3.4.1.3.4's path cost replaced by 9109-9110's forward cost */
static void nwkDoRreqRelay(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                           const Nwk_RouteRequestFields *fields, const Nwk_RreqRxDecision *decision, uint32_t nowMs)
{
    uint8_t relayed[NWK_FRAME_NPDU_MAX];
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t relayedLen;
    uint32_t npduLen;
    ZbStatus status;

    nwkDoRreqRelayMark(self, fields, nowMs);

    status = Nwk_RreqComposeRelay(payload, payloadLen, decision->forwardCost, relayed,
                                  (uint32_t)sizeof relayed, &relayedLen);

    if (status != ZB_OK)
    {
        self->droppedUnsupported++;
        return;
    }

    status = NwkFrame_Compose(frame, relayed, relayedLen, npdu, (uint32_t)sizeof npdu, &npduLen);

    if (status != ZB_OK)
    {
        self->droppedUnsupported++;
        return;
    }

    status = Nwk_RreqTxStartRelay(self->rreqRelay, frame->srcAddr, fields->requestId, npdu, npduLen,
                                  NwkFrame_HeaderLen(frame), frame->securityEnabled,
                                  nowMs + Nwk_RreqRelayJitterMs(&self->jitterState, self->cfg.jitterSeed));

    if (status != ZB_OK)
        self->droppedUnsupported++;
}

/* 3.6.4.5.1's reception where a command frame lands: the payload parsed, the procedure run over this device's tables, its outcome acted on */
static void nwkDoRouteRequest(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload,
                              uint32_t payloadLen, uint16_t senderAddr, uint16_t own, uint32_t nowMs)
{
    Nwk_RouteRequestFields fields;
    Nwk_RreqRxDecision decision;
    Nwk_RouteDiscoveryTableEntry *entry;

    if (Nwk_RreqParse(payload, payloadLen, &fields) != ZB_OK)
    {
        self->droppedMalformed++;
        return;
    }

    (void)Nwk_RreqRx(&fields, frame, senderAddr, self->neighbors, self->routes, self->discoveries, own,
                     self->cfg.deviceType, nowMs, &decision);

    entry = Nwk_DiscoveryOf(self->discoveries, decision.sourceAddr, decision.requestId);

    if (entry != 0)
        entry->destAddr = decision.destination;


    switch (decision.outcome)
    {
        case NWK_RREQ_RX_DESTINATION_REPLY:
            nwkDoRreqReply(self, frame, &fields, &decision, own, nowMs);
            break;

        case NWK_RREQ_RX_FORWARD_RELAY:
            nwkDoRreqRelay(self, frame, payload, payloadLen, &fields, &decision, nowMs);
            break;

        case NWK_RREQ_RX_END_DEVICE:
            self->rreqDroppedEndDevice++;
            break;

        case NWK_RREQ_RX_NO_NEIGHBOR:
            self->rreqDroppedNoNeighbor++;
            break;

        case NWK_RREQ_RX_OUTGOING_COST_ZERO:
            self->rreqDroppedNoOutgoingCost++;
            break;

        case NWK_RREQ_RX_GREATER_FORWARD_COST:
            self->rreqDroppedGreaterCost++;
            break;

        case NWK_RREQ_RX_NO_DISCOVERY_SLOT:
            self->rreqDroppedNoDiscoverySlot++;
            break;

        case NWK_RREQ_RX_FORWARDER_REPLY:
            self->droppedUnsupported++;
            break;
    }
}

/* 3.6.4.5.2's originator half: the entry left ACTIVE, the frame that waited on it goes out over the hop 3.6.4.3 found, and 3.6.4.5.1.4's schedule for the discovery stops */
static void nwkDoDiscoveryRelease(Nwk_Nwk *self, uint16_t destAddr, uint8_t requestId, uint32_t nowMs)
{
    Nwk_RoutingTableEntry *route;
    uint32_t i;
    int retryable;
    int protectRefused;
    ZbStatus status;

    route = Nwk_RouteOf(self->routes, destAddr);

    if (route == 0 || route->status != NWK_ROUTE_ACTIVE)
        return;

    for (i = 0; i < NWK_TX_MAX; i++)
    {
        if (self->tx[i].state != NWK_TX_AWAITING_ROUTE)
            continue;

        if (self->tx[i].dstAddr != destAddr || self->tx[i].requestId != requestId)
            continue;

        if (!Nwk_RouteNextHop(self->routes, self->neighbors, destAddr, nowMs, &self->tx[i].nextHop))
        {
            nwkDoAttemptFailed(self, &self->tx[i], ZB_ERR_NO_ROUTE);

            continue;
        }

        status = Nwk_TxIssueAttempt(&self->tx[i], self->mac, self->security, self->secureScratch,
                                    (uint32_t)sizeof self->secureScratch, nowMs, &retryable, &protectRefused);

        if (protectRefused)
            nwkDoProtectRefused(self, status);

        if (status == ZB_OK)
            self->lastRequestHandle = self->tx[i].lastHandle;

        if (retryable)
        {
            self->tx[i].state = NWK_TX_AWAITING_RETRY;
            self->tx[i].nextRetryMs = nowMs + NWK_UNICAST_RETRY_DELAY_MS;

            continue;
        }

        if (status != ZB_OK)
            nwkDoAttemptFailed(self, &self->tx[i], status);
    }

    Nwk_RreqTxStop(self->rreqTx, destAddr, requestId);
}

/* 3.6.4.5.2.1: the reply carried on with 9225-9228's cost, unicast to Table 3-79's sender address for the originator (9266-9272) */
static void nwkDoRrepForward(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                             const Nwk_RouteReplyFields *fields, const Nwk_RrepRxDecision *decision, uint16_t own,
                             uint32_t nowMs)
{
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_Frame header;
    uint8_t forwarded[NWK_RREP_PAYLOAD_MAX];
    uint32_t forwardedLen;
    uint32_t npduLen;
    ZbStatus status;

    entry = Nwk_DiscoveryOf(self->discoveries, fields->originatorAddr, fields->requestId);

    if (entry == 0)
    {
        self->rrepDroppedNoDiscovery++;
        return;
    }

    status = Nwk_RrepForward(payload, payloadLen, decision->pathCost, forwarded, (uint32_t)sizeof forwarded,
                             &forwardedLen);

    if (status != ZB_OK)
    {
        self->droppedUnsupported++;
        return;
    }

    Zb_memset(&header, 0, (uint32_t)sizeof header);

    header.frameType = NWK_FRAME_TYPE_COMMAND;
    header.protocolVersion = NWK_PROTOCOL_VERSION;
    header.discoverRoute = NWK_DISCOVER_SUPPRESS;
    header.destAddr = entry->senderAddress;                
    header.srcAddr = own;
    header.radius = frame->radius;                      
    header.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    header.securityEnabled = Nwk_TxSecurityRuns(self->security) ? 1 : 0;
    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    status = NwkFrame_Compose(&header, forwarded, forwardedLen, self->relayNpdu,
                              (uint32_t)sizeof self->relayNpdu, &npduLen);

    if (status != ZB_OK)
    {
        self->droppedUnsupported++;
        return;
    }

    if (nwkDoForward(self, self->relayNpdu, npduLen, NwkFrame_HeaderLen(&header), header.securityEnabled,
                     header.sequenceNumber, entry->senderAddress, entry->senderAddress, nowMs) != ZB_OK)
        return;

    self->routeRepliesForwarded++;
}

/* 3.6.4.5.2's reception where a command frame lands: the payload parsed, `nwk_rreprx`'s procedure over this device's tables */
static void nwkDoRouteReply(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload,
                            uint32_t payloadLen, uint16_t own, uint32_t nowMs)
{
    Nwk_RouteReplyFields fields;
    Nwk_RrepRxDecision decision;
    Nwk_RouteDiscoveryTableEntry *entry;
    uint16_t discovered = 0;

    if (Nwk_RrepParse(payload, payloadLen, &fields) != ZB_OK)
    {
        self->droppedMalformed++;
        return;
    }

    entry = Nwk_DiscoveryOf(self->discoveries, fields.originatorAddr, fields.requestId);

    if (entry != 0)
        discovered = entry->destAddr;

    (void)Nwk_RrepRx(&fields, frame, own, self->cfg.deviceType, self->neighbors, self->routes,
                     self->discoveries, nowMs, &decision);

    switch (decision.outcome)
    {
        case NWK_RREP_RX_ORIGINATOR_ROUTE:
        case NWK_RREP_RX_ORIGINATOR_CHEAPER:
            nwkDoDiscoveryRelease(self, fields.responderAddr, fields.requestId, nowMs);
            break;

        case NWK_RREP_RX_FORWARDED:
            nwkDoRrepForward(self, frame, payload, payloadLen, &fields, &decision, own, nowMs);
            break;

        case NWK_RREP_RX_NO_DISCOVERY:
            self->rrepDroppedNoDiscovery++;
            break;

        case NWK_RREP_RX_NO_ROUTE_REMOVED:
            Nwk_RreqTxStop(self->rreqTx, discovered, fields.requestId);
            self->rrepDroppedNoRoute++;
            break;

        case NWK_RREP_RX_NO_ROUTE_DISCARDED:
            self->rrepDroppedNoReverseRoute++;
            break;

        case NWK_RREP_RX_COST_NOT_SMALLER:
            self->rrepDroppedNotSmaller++;
            break;

        case NWK_RREP_RX_UNSUITABLE:
            self->rrepDroppedUnsuitable++;
            break;

        case NWK_RREP_RX_NO_ROUTING_CAPACITY:
            self->rrepDroppedNoCapacity++;
            break;
    }
}

static void nwkDoRelayOutcome(Nwk_Nwk *self, Nwk_RelayOutcome outcome, ZbStatus status, int originates)
{
    switch (outcome)
    {
        case NWK_RELAY_ISSUED:

            if (originates != 0)
                self->broadcastRetransmissions++;
            else
                self->relaysSent++;

            break;

        case NWK_RELAY_NOT_FOR_ME:
            self->droppedNotForMe++;
            break;

        case NWK_RELAY_NO_ROUTE:
            self->droppedNoRoute++;
            break;

        case NWK_RELAY_FORWARD_COPY_FAILED:
            self->droppedUnsupported++;
            break;

        case NWK_RELAY_PROTECT_REFUSED:
            nwkDoProtectRefused(self, status);
            break;

        case NWK_RELAY_ISSUE_FAILED:
            self->forwardsRefused += status == ZB_ERR_NO_SPACE ? 1 : 0;
            break;
    }
}

static void nwkDoRelayBroadcast(Nwk_Nwk *self, Nwk_BroadcastTransactionRecord *record, uint32_t nowMs)
{
    Nwk_RelayOutcome outcome;
    ZbStatus copiesStatus;
    ZbStatus protectStatus;

    outcome = Nwk_RelayBroadcast(record, self->neighbors, &self->cfg, &self->jitterState, self->mac,
                                 self->security, self->secureScratch,
                                 (uint32_t)sizeof self->secureScratch, nowMs, &protectStatus,
                                 &copiesStatus);

    nwkDoRelayOutcome(self, outcome, protectStatus, record->originates);

    if (copiesStatus != ZB_OK)
        nwkDoProtectRefused(self, copiesStatus);
}

/* What a consumed frame says about the device that sent it, and the one refusal the neighbor table can answer */
static void nwkDoObserve(Nwk_Nwk *self, const Mac_DataIndicationParameters *ind, const Nwk_Frame *frame,
                         uint64_t hopIeee, int hopIeeeKnown, uint32_t nowMs)
{
    int addRefused;

    if (ind->header.srcAddrMode != MAC_ADDR_SHORT)
        return;

    Nwk_RxObserve(self->neighbors, frame, ind->header.srcShort, ind->lqi, hopIeee, hopIeeeKnown, nowMs, &addRefused);

    if (ind->header.destAddrMode == MAC_ADDR_SHORT && ind->header.destShort != MAC_FRAME_ADDR_BROADCAST)
        (void)Nwk_NeighborInboundActivity(self->neighbors, ind->header.srcShort);

    if (addRefused)
        self->neighborAddsRefused++;
}

/* The record of a broadcast this device sends without the data path's slot, so a neighbour's relay of it is dropped
   as a copy (9481) rather than taken for another holder of this address (8233); it holds no frame to retransmit. */
static void nwkDoRecordOwnBroadcast(Nwk_Nwk *self, uint16_t own, uint8_t seq, uint16_t dst, uint32_t nowMs)
{
    if (Nwk_AddrKeepsBtt(self->cfg.deviceType, Nwk_AddrOwnRxOnWhenIdle(Mac_Pib(self->mac))))
        (void)Nwk_BttOpen(self->btt, own, seq, dst, nowMs, nowMs + NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS);
}

/* A local conflict arms one broadcast, delayed by the jitter, and a second conflict found before it goes out replaces
   the address it names rather than queueing another. */
static void nwkDoAnnounceConflict(Nwk_Nwk *self, uint16_t offendingAddress, uint16_t own, uint32_t nowMs)
{
    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        return;

    if (offendingAddress != own)
        return;

    self->conflictBroadcastAddress = offendingAddress;
    self->conflictBroadcastAtMs = nowMs + Nwk_RelayJitterMs(&self->jitterState, &self->cfg);
    self->conflictBroadcastPending = 1;
}

/* The turn the delay runs out on: a Network Status with 0x0d and the offending address, broadcast to the devices
   whose receivers rest on. */
static void nwkDoConflictBroadcast(Nwk_Nwk *self, uint32_t nowMs)
{
    Nwk_Frame frame;
    uint16_t own;
    uint32_t len;
    uint32_t securedLen;
    const uint8_t *octets;
    uint32_t octetLen;
    ZbStatus status;

    if (!self->conflictBroadcastPending)
        return;

    if (!Zb_timeReached(nowMs, self->conflictBroadcastAtMs))
        return;

    self->conflictBroadcastPending = 0;

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        return;

    status = Nwk_CommandComposeStatus(&frame, own, nwkDoOwnIeee(self->mac), NWK_ADDR_RX_ON_WHEN_IDLE,
                                      0, NWK_NETWORK_STATUS_ADDRESS_CONFLICT,
                                      (uint16_t)self->conflictBroadcastAddress, 0, 0,
                                      Nwk_TxSecurityRuns(self->security) ? 1 : 0, &self->seq,
                                      self->relayNpdu, (uint32_t)sizeof self->relayNpdu, &len);

    if (status != ZB_OK)
        return;

    octets = self->relayNpdu;
    octetLen = len;

    if (frame.securityEnabled)
    {
        status = Nwk_TxProtect(self->security, self->relayNpdu, len, NwkFrame_HeaderLen(&frame),
                               self->secureScratch, (uint32_t)sizeof self->secureScratch, &securedLen);

        if (status != ZB_OK)
        {
            nwkDoProtectRefused(self, status);
            return;
        }

        octets = self->secureScratch;
        octetLen = securedLen;
    }

    if (Nwk_TxIssueRaw(self->mac, octets, octetLen, NWK_ADDR_RX_ON_WHEN_IDLE, 1, nowMs, 0) == ZB_OK)
    {
        nwkDoRecordOwnBroadcast(self, own, frame.sequenceNumber, NWK_ADDR_RX_ON_WHEN_IDLE, nowMs);
        self->conflictBroadcastsSent++;
    }
}

/* The frame to this device, straight on to the header's destination, on to the previous relay with the index
   decremented, or dropped; the relay is a direct MCPS-DATA.request, so the discovery sub-field is suppressed. */
static void nwkDoSourceRoute(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                             uint16_t own, int securityUsed, uint32_t nowMs)
{
    Nwk_SourceRouteVerdict verdict;
    Nwk_RoutingTableEntry *route;
    Nwk_Frame relay;
    const uint8_t *octets;
    uint32_t npduLen;
    uint32_t octetLen;
    uint32_t securedLen;
    uint16_t nextHop = 0;
    ZbStatus status;

    verdict = Nwk_RxSourceRoute(frame, own, self->cfg.deviceType, self->neighbors, &nextHop);

    if (verdict == NWK_SR_DROP)
    {
        self->droppedNotForMe++;
        return;
    }

    if (verdict == NWK_SR_DELIVER)
    {
        nwkDoIndicate(self, frame, payload, payloadLen, 0, 0, securityUsed);

        return;
    }

    route = Nwk_RouteOf(self->routes, frame->srcAddr);

    if (route != 0 && !route->noRouteCache)
        route->routeRecordRequired = 0;

    if (frame->radius == 0)
    {
        self->droppedNoRoute++;
        return;
    }

    Zb_memset(&relay, 0, (uint32_t)sizeof relay);

    relay = *frame;
    relay.destAddr = nextHop;
    relay.srcAddr = own;
    relay.discoverRoute = NWK_DISCOVER_SUPPRESS;
    relay.endDeviceInitiator = 0;
    relay.relayIndex = verdict == NWK_SR_RELAY_ONWARD ? (uint8_t)(frame->relayIndex - 1) : 0;
    relay.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    status = NwkFrame_ComposeRelay(&relay, payload, payloadLen, self->relayNpdu,
                                   (uint32_t)sizeof self->relayNpdu, &npduLen);

    if (status != ZB_OK)
    {
        self->droppedUnsupported++;
        return;
    }

    octets = self->relayNpdu;
    octetLen = npduLen;

    if (securityUsed && self->security != 0)
    {
        status = Nwk_TxProtect(self->security, self->relayNpdu, npduLen, NwkFrame_HeaderLen(&relay),
                               self->secureScratch, (uint32_t)sizeof self->secureScratch, &securedLen);

        if (status != ZB_OK)
        {
            nwkDoProtectRefused(self, status);
            return;
        }

        octets = self->secureScratch;
        octetLen = securedLen;
    }

    if (Nwk_TxOfferRaw(self->mac, octets, octetLen, nextHop, Nwk_NeighborRestsReceiver(self->neighbors, nextHop),
                       NWK_TX_HELD_UNTRACKED, nowMs, 0) == ZB_OK)
        self->relaysSent++;
}

/* The initiation's one case: a route entry that is many-to-one and owes a record gets one command sent to the
   destination before the data frame, so the concentrator can answer along the path it was reached by: the command's
   identifier and a relay count of 0, behind both 64-bit addresses, the destination's where it is known. */
static int nwkDoRouteRecordSend(Nwk_Nwk *self, uint16_t destination, uint32_t nowMs)
{
    Nwk_RoutingTableEntry *route;
    Nwk_Frame frame;
    uint8_t payload[2];
    uint32_t recordLen = 0;
    uint32_t npduLen = 0;
    uint16_t own;
    uint16_t nextHop = 0;

    route = Nwk_RouteOf(self->routes, destination);

    if (route == 0 || !route->manyToOne || !route->routeRecordRequired)
        return 0;

    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        return 0;

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        return 0;

    if (!Nwk_RouteNextHop(self->routes, self->neighbors, destination, nowMs, &nextHop))
        return 0;

    payload[0] = NWK_CMD_ROUTE_RECORD;

    if (Nwk_RouteRecordCompose(0, 0, payload + 1, (uint32_t)sizeof payload - 1, &recordLen) != ZB_OK)
        return 0;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = NWK_FRAME_TYPE_COMMAND;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.discoverRoute = NWK_DISCOVER_SUPPRESS;
    frame.destAddr = destination;
    frame.srcAddr = own;
    frame.radius = NWK_INITIAL_RADIUS;
    frame.srcIeeePresent = 1;
    frame.srcIeee = nwkDoOwnIeee(self->mac);
    frame.destIeeePresent = Nwk_AddrMapExtendedOf(self->addressMap, destination, &frame.destIeee) ? 1 : 0;
    frame.securityEnabled = Nwk_TxSecurityRuns(self->security) ? 1 : 0;
    frame.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    if (NwkFrame_Compose(&frame, payload, 1 + recordLen, self->relayNpdu, (uint32_t)sizeof self->relayNpdu,
                         &npduLen) != ZB_OK)
        return 0;

    if (nwkDoForward(self, self->relayNpdu, npduLen, NwkFrame_HeaderLen(&frame), frame.securityEnabled,
                     frame.sequenceNumber, nextHop, destination, nowMs) != ZB_OK)
        return 0;

    route->routeRecordRequired = 0;
    self->routeRecordsSent++;

    return 1;
}

/* The record's two halves: the destination stores the list it was handed, a neighbour's empty one letting go of the
   route it replaces, and every other device appends its own address and forwards the command, discarding it when
   the payload has no room. */
static void nwkDoRouteRecord(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                             uint16_t own, uint32_t nowMs)
{
    Nwk_Frame forward;
    uint8_t recordPayload[2 + NWK_MAX_RELAYS * NWK_FRAME_RELAY_OCTETS];
    uint16_t relays[NWK_MAX_RELAYS];
    uint32_t count = 0;
    uint32_t npduLen = 0;
    uint32_t octetLen = 0;
    uint32_t relayCount;
    uint16_t nextHop;
    ZbStatus status;

    if (Nwk_RouteRecordParse(payload, payloadLen, relays, NWK_MAX_RELAYS, &count) != ZB_OK)
    {
        self->droppedMalformed++;
        return;
    }

    if (frame->destAddr == own)
    {
        self->routeRecordsReceived++;
        nwkDoSourceRouteRecord(self, frame->srcAddr, relays, count, nowMs);

        return;
    }

    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
    {
        self->droppedNotForMe++;
        return;
    }

    if (count >= NWK_MAX_RELAYS || count >= NWK_MAX_SOURCE_ROUTE)
    {
        self->droppedNoRoute++;
        return;
    }

    relays[count++] = own;

    nextHop = frame->destAddr;

    if (!Nwk_RouteNextHop(self->routes, self->neighbors, frame->destAddr, nowMs, &nextHop))
    {
        self->droppedNoRoute++;
        return;
    }

    status = Nwk_RouteRecordCompose(relays, count, recordPayload + 1, (uint32_t)sizeof recordPayload - 1,
                                    &relayCount);

    if (status != ZB_OK)
    {
        self->droppedNoRoute++;
        return;
    }

    recordPayload[0] = NWK_CMD_ROUTE_RECORD;

    forward = *frame;
    forward.destAddr = frame->destAddr;
    forward.srcAddr = frame->srcAddr;
    forward.radius = frame->radius > 0 ? frame->radius - 1 : 0;
    forward.discoverRoute = NWK_DISCOVER_SUPPRESS;
    forward.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    forward.securityEnabled = Nwk_TxSecurityRuns(self->security) ? 1 : 0;

    status = NwkFrame_Compose(&forward, recordPayload, relayCount + 1, self->relayNpdu,
                              (uint32_t)sizeof self->relayNpdu, &npduLen);

    if (status != ZB_OK)
    {
        self->droppedNoRoute++;
        return;
    }

    octetLen = npduLen;

    if (nwkDoForward(self, self->relayNpdu, octetLen, NwkFrame_HeaderLen(&forward), forward.securityEnabled,
                     forward.sequenceNumber, nextHop, forward.destAddr, nowMs) == ZB_OK)
        self->routeRecordsRelayed++;
}

/* A link status frame is one hop's, so it is applied to the sender's entry and the two metrics it carries. A sender
   the observation had no slot for takes the place of the lowest-ranked sibling, and with no sibling to give way the
   frame is dropped (8990-9001). */
static void nwkDoLinkStatus(Nwk_Nwk *self, const Mac_DataIndicationParameters *ind, const Nwk_Frame *frame,
                            uint64_t hopIeee, int hopIeeeKnown, uint16_t senderAddr, uint16_t own,
                            const uint8_t *payload, uint32_t payloadLen, int senderWasKnown, uint32_t nowMs)
{
    Nwk_LinkStatus list;
    int room;
    uint32_t answerAtMs;

    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        return;

    if (Nwk_LinkStatusParse(payload, payloadLen, &list) != ZB_OK)
    {
        self->droppedMalformed++;
        return;
    }

    if (Nwk_NeighborOf(self->neighbors, senderAddr) == 0)
    {
        room = Nwk_NeighborMakeRoom(self->neighbors, NWK_LINK_STATUS_MIN_OBSERVATION_TICKS);

        if (room < 0)
            return;

        Zb_memset(&self->neighbors[room], 0, (uint32_t)sizeof self->neighbors[room]);
        nwkDoObserve(self, ind, frame, hopIeee, hopIeeeKnown, nowMs);
    }

    if (list.count == 0 && !senderWasKnown)
    {
        answerAtMs = nowMs + Nwk_RelayBootstrapJitterMs(&self->jitterState, &self->cfg);

        if (self->linkStatusAtMs == 0 || Zb_timeReached(self->linkStatusAtMs, answerAtMs))
            self->linkStatusAtMs = answerAtMs;
    }

    if (Nwk_LinkStatusApply(self->neighbors, senderAddr, own, &list, senderWasKnown, nowMs))
        self->linkStatusApplied++;
}

/* This device's parent in the neighbour table. */
static Nwk_NeighborTableEntry *nwkDoParentEntry(Nwk_Nwk *self)
{
    uint32_t i;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!self->neighbors[i].inUse || self->neighbors[i].relationship != NWK_REL_PARENT)
            continue;

        return &self->neighbors[i];
    }

    return 0;
}

/* A conflict on the address of one of this device's own end-device children is the parent's to resolve, so a new
   address is drawn and the unsolicited rejoin response carries it. */
static void nwkDoReaddressChild(Nwk_Nwk *self, uint16_t conflictedAddress, uint32_t nowMs)
{
    Nwk_NeighborTableEntry *child;

    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        return;

    child = Nwk_NeighborOf(self->neighbors, conflictedAddress);

    if (child == 0 || child->deviceType != NWK_DEVICE_END_DEVICE)
        return;

    if (child->relationship != NWK_REL_CHILD && child->relationship != NWK_REL_UNAUTHENTICATED_CHILD)
        return;

    (void)Nwk_JoinReaddressChild(self, child, nowMs);
}

/* Another device's IEEE address stated with this device's own short address is a local conflict, whether
   or not the map was seeded with the own row; an unsecured frame announces nothing. */
static int nwkDoOwnAddressClaimed(Nwk_Nwk *self, uint16_t networkAddress, uint64_t extendedAddress, int secured,
                                  uint16_t own, uint32_t nowMs)
{
    if (networkAddress != own)
        return 0;

    if (extendedAddress != Nwk_OwnExtendedAddress(self))
    {
        self->addressConflictsLocal++;

        if (secured)
            nwkDoAnnounceConflict(self, networkAddress, own, nowMs);
    }

    return 1;
}

/* One pair for the higher layer; a full ring counts what it lost. */
static void nwkDoAddressNotice(Nwk_Nwk *self, uint16_t networkAddress, uint64_t extendedAddress, uint32_t reason)
{
    Nwk_AddressNotice *notice;

    if (self->addressNoticeCount >= NWK_ADDRESS_NOTICE_MAX)
    {
        self->addressNoticesDropped++;
        return;
    }

    notice = &self->addressNotices[(self->addressNoticeHead + self->addressNoticeCount) % NWK_ADDRESS_NOTICE_MAX];
    notice->extendedAddress = extendedAddress;
    notice->networkAddress = networkAddress;
    notice->reason = reason;
    self->addressNoticeCount++;
}

/* 3.6.1.10.1 and 3.6.1.10.2 over one address pair: it is handed to Table 3-68's map, and the two conflicts are
   answered apart, the local one by 3.6.1.10.5's announcement and the other by a child's new address; an unsecured
   frame announces nothing, which `nwk_join.c`'s clause forbids. */
static void nwkDoLearnPair(Nwk_Nwk *self, uint16_t networkAddress, uint64_t extendedAddress, int secured,
                           uint16_t own, uint32_t nowMs)
{
    Nwk_AddrMapVerdict verdict;

    if (nwkDoOwnAddressClaimed(self, networkAddress, extendedAddress, secured, own, nowMs))
        return;

    verdict = Nwk_AddrMapLearn(self->addressMap, networkAddress, extendedAddress, own, nowMs);

    if (verdict == NWK_ADDRMAP_LEARNED || verdict == NWK_ADDRMAP_UPDATED)
    {
        self->addressMapLearned++;
        nwkDoAddressNotice(self, networkAddress, extendedAddress, verdict == NWK_ADDRMAP_LEARNED
                                                                  ? NWK_ADDRESS_NOTICE_LEARNED
                                                                  : NWK_ADDRESS_NOTICE_CHANGED);
    }
    else if (verdict == NWK_ADDRMAP_CONFLICT_LOCAL)
    {
        self->addressConflictsLocal++;

        if (secured)
            nwkDoAnnounceConflict(self, networkAddress, own, nowMs);
    }
    else if (verdict == NWK_ADDRMAP_CONFLICT_OTHER)
    {
        self->addressConflictsOther++;
        nwkDoAddressNotice(self, networkAddress, extendedAddress, NWK_ADDRESS_NOTICE_CONFLICT);
        nwkDoReaddressChild(self, networkAddress, nowMs);
    }
}

/* What the NWK header states of each end of the frame, one pair each. */
static void nwkDoLearnAddress(Nwk_Nwk *self, const Nwk_Frame *frame, uint16_t own, uint32_t nowMs)
{
    if (frame->srcIeeePresent)
        nwkDoLearnPair(self, frame->srcAddr, frame->srcIeee, frame->securityEnabled, own, nowMs);

    if (frame->destIeeePresent)
        nwkDoLearnPair(self, frame->destAddr, frame->destIeee, frame->securityEnabled, own, nowMs);
}

void Nwk_AddressAnnounced(Nwk_Nwk *self, uint16_t networkAddress, uint64_t extendedAddress, uint32_t nowMs)
{
    uint64_t holder = 0;
    uint16_t own;
    int secured;

    if (self == 0 || !Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        return;

    if (extendedAddress == 0xffffffffffffffff || extendedAddress == Nwk_OwnExtendedAddress(self))
        return;

    secured = Nwk_TxSecurityRuns(self->security);

    if (nwkDoOwnAddressClaimed(self, networkAddress, extendedAddress, secured, own, nowMs))
        return;

    if (Nwk_AddrMapExtendedOf(self->addressMap, networkAddress, &holder) && holder != 0 && holder != extendedAddress)
    {
        self->addressConflictsOther++;
        nwkDoAddressNotice(self, networkAddress, extendedAddress, NWK_ADDRESS_NOTICE_CONFLICT);
        nwkDoReaddressChild(self, networkAddress, nowMs);

        return;
    }

    nwkDoLearnPair(self, networkAddress, extendedAddress, secured, own, nowMs);
}

/* A relayed data frame that asks for discovery and whose NWK source is this device's end device child starts one
   (9037-9041), its copy held in a slot for the route when one is free (9060). 1 when it applied. */
static int nwkDoRelayDiscover(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                              Nwk_Tx *slot, uint16_t own, uint32_t nowMs)
{
    const Nwk_NeighborTableEntry *child;
    Nwk_RouteDiscoveryTableEntry *entry;
    uint32_t nwkStatus;
    uint32_t len;

    if (frame->frameType != NWK_FRAME_TYPE_DATA || frame->discoverRoute != NWK_DISCOVER_ENABLE || frame->radius == 0)
        return 0;

    child = Nwk_NeighborOf(self->neighbors, frame->srcAddr);

    if (child == 0 || child->relationship != NWK_REL_CHILD || child->deviceType != NWK_DEVICE_END_DEVICE)
        return 0;

    if (Nwk_RxForwardCopy(frame, payload, payloadLen, self->relayNpdu, (uint32_t)sizeof self->relayNpdu, &len) != ZB_OK
        || Nwk_TxHold(slot, self->relayNpdu, len, NwkFrame_HeaderLen(frame), frame->securityEnabled,
                      frame->sequenceNumber, frame->destAddr) != ZB_OK)
    {
        slot = 0;
        self->droppedNoRoute++;
    }
    else
    {
        slot->sourceAddr = frame->srcAddr;
        slot->reportsFailure = 1;
        self->childFramesHeld++;
    }

    self->childDiscoveries++;
    entry = Nwk_DiscoveryRunning(self->discoveries, own, frame->destAddr);

    if (entry != 0 && slot != 0)
    {
        slot->state = NWK_TX_AWAITING_ROUTE;
        slot->requestId = entry->routeRequestId;
    }

    if (entry != 0)
        return 1;

    if (nwkDoDiscoverRoute(self, slot, frame->destAddr, 0, own, nowMs, &nwkStatus) == ZB_OK)
        return 1;

    if (slot != 0)
    {
        Zb_memset(slot, 0, (uint32_t)sizeof *slot);
        self->droppedNoRoute++;
    }

    return 1;
}

/* 3.6.2.2's gates follow the unprotection 4.3.1.1 step 3d makes the first act of receipt; its two halves are one
   branch with the carve-outs docs/internals/conformance.md §2 names. The unjoined half accepts an unsecured 0x07 whatever
   state the rejoin was in, and a broadcast with this device's own source is marked before it is dropped. */
static void nwkDoReceive(Nwk_Nwk *self, const Mac_DataIndicationParameters *ind, uint32_t nowMs)
{
    Nwk_BroadcastTransactionRecord *record;
    Nwk_Frame frame;
    Nwk_NeighborTableEntry *neighbor;
    Nwk_RelayOutcome outcome;
    Nwk_RelayTrack *track;
    Nwk_Tx *slot;
    Security_Result hop;
    int heldSlot;
    uint16_t nextHop = 0;
    const uint8_t *npdu;
    const uint8_t *payload;
    uint16_t own;
    uint32_t headerLen;
    uint32_t payloadOffset;
    uint32_t payloadLen;
    uint32_t plainLen;
    uint32_t npduLen;
    uint16_t senderAddr;
    int forMe;
    int isBroadcast;
    int securityUsed;
    int unsecured;
    ZbStatus status;

    if (!ind->headerValid)
    {
        self->droppedMalformed++;
        return;
    }

    if (ind->frameType != (uint32_t)MAC_FRAME_TYPE_DATA)
    {
        self->carrierOther++;
        return;
    }

    if (ind->status != ZB_OK)
    {
        self->droppedMalformed++;
        return;
    }

    npdu = ind->bytes + ind->payloadOffset;
    npduLen = ind->payloadLen;

    status = NwkFrame_Parse(npdu, npduLen, &frame, &payloadOffset, &payloadLen);

    /* the crossing answered UNSUPPORTED: docs/internals/conformance.md §2 */
    if (status == ZB_ERR_UNSUPPORTED)
    {
        self->droppedUnsupported++;
        return;
    }

    if (status != ZB_OK)
    {
        self->droppedMalformed++;
        return;
    }

    if (frame.multicastDeprecated)
    {
        self->droppedMulticast++;
        return;
    }

    payload = npdu + payloadOffset;
    headerLen = payloadOffset;     
    securityUsed = frame.securityEnabled;
    unsecured = 0;

    if (frame.securityEnabled)
    {
        if (!Nwk_TxSecurityRuns(self->security))
        {
            self->droppedUnsupported++;
            return;
        }

        status = Security_Unprotect(self->security, npdu, npduLen, headerLen, self->plainScratch,
                                    (uint32_t)sizeof self->plainScratch, &plainLen, &hop);

    /* the crossing answered UNSUPPORTED: docs/internals/conformance.md §2 */
        if (status == ZB_ERR_UNSUPPORTED)
        {
            self->droppedUnsupported++;
            return;
        }

        if (status == ZB_ERR_AUTH || status == ZB_ERR_NO_SPACE)
        {
            self->rxSecurityFailures++;
            return;
        }

        if (status == ZB_ERR_BAD_FRAME_COUNTER)
        {
            self->rxFrameCounterRejects++;
            return;
        }

        if (status == ZB_ERR_BAD_ARGUMENT)
        {
            self->droppedMalformed++;
            return;
        }

        payload = self->plainScratch;
        payloadLen = plainLen;

        Nwk_RxAuthenticateHop(self->neighbors, &hop);      
    }
    else if (self->security != 0 && Security_Level(self->security) != SECURITY_LEVEL_NONE)
        unsecured = 1;     

    if (frame.radius > 0)
        frame.radius = (uint8_t)(frame.radius - 1);

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own))
    {
        self->droppedNotForMe++;
        return;
    }

    isBroadcast = Nwk_AddrIsBroadcast(frame.destAddr) ? 1 : 0;

    senderAddr = 0;

    if (ind->header.srcAddrMode == MAC_ADDR_SHORT)
        senderAddr = ind->header.srcShort;

    if (Nwk_AddrIsBroadcast(frame.srcAddr) || Nwk_AddrIsReserved(frame.srcAddr))
    {
        self->droppedBadSource++;
        return;
    }

    if (Nwk_AddrIsReserved(frame.destAddr))
    {
        self->droppedNotForMe++;
        return;
    }

    if (isBroadcast)
    {
        if (!Nwk_AddrClassAccepts(frame.destAddr, self->cfg.deviceType,
                                   Nwk_AddrOwnRxOnWhenIdle(Mac_Pib(self->mac))))
        {
            self->droppedNotForMe++;
            return;
        }

        forMe = 1;
    }
    else
        forMe = (frame.destAddr == own) ? 1 : 0;

    if (unsecured)
    {
        int command;
        int accepted;
        int joined;
        int rejoinRequest;
        int rejoinResponse;
        int commissioningRequest;
        int commissioningResponse;

        command = (frame.frameType == NWK_FRAME_TYPE_COMMAND && payloadLen != 0) ? 1 : 0;
        joined = Security_IsAuthenticated(self->security) ? 1 : 0;
        rejoinRequest = (command && payload[0] == NWK_CMD_REJOIN_REQUEST) ? 1 : 0;
        rejoinResponse = (command && payload[0] == NWK_CMD_REJOIN_RESPONSE) ? 1 : 0;
        commissioningRequest = (command && payload[0] == NWK_CMD_NETWORK_COMMISSIONING_REQUEST) ? 1 : 0;
        commissioningResponse = (command && payload[0] == NWK_CMD_NETWORK_COMMISSIONING_RESPONSE) ? 1 : 0;
        accepted = 0;

        if ((rejoinRequest || commissioningRequest) && joined)
            accepted = Nwk_RxUnsecuredAccepted(&frame, payload, payloadLen, (isBroadcast ? 0 : forMe));

        if ((rejoinResponse || commissioningResponse) && !joined && !isBroadcast && forMe)
            accepted = 1;

        if (!joined && !command && forMe && Nwk_RxCarriesTransportKey(payload, payloadLen))
            accepted = 1;

        if (!accepted)
        {
            self->droppedUnsecured++;
            return;
        }
    }

    if (frame.endDeviceInitiator)
    {
        if (self->cfg.deviceType == NWK_DEVICE_END_DEVICE)
        {
            self->droppedNotForMe++;
            return;
        }

        neighbor = Nwk_NeighborOf(self->neighbors, frame.srcAddr);

        if (neighbor == 0 || neighbor->deviceType != NWK_DEVICE_END_DEVICE)
        {
            self->droppedEndDeviceInitiator++;

            if (Nwk_LeaveUnknownSender(self, frame.srcAddr, nowMs) == ZB_OK)
                self->unknownSenderLeaves++;

            return;
        }
    }

    record = 0;

    if (frame.sourceRoute && frame.frameType == NWK_FRAME_TYPE_DATA)
    {
        nwkDoSourceRoute(self, &frame, payload, payloadLen, own, securityUsed, nowMs);
        return;
    }

    if (isBroadcast && frame.srcAddr == own)
    {
        record = Nwk_BttOf(self->btt, own, frame.sequenceNumber);

        if (record != 0 && Nwk_BttMarkRelayed(record))
            self->passiveAcksHeard++;

        if (record == 0 && Zb_timeReached(nowMs, self->operatingSinceMs + NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS)
            && frame.securityEnabled)
        {
            self->addressConflictsLocal++;
            nwkDoAnnounceConflict(self, own, own, nowMs);
        }

        self->droppedNotForMe++;
        return;
    }

    if ((forMe || isBroadcast) && frame.frameType == NWK_FRAME_TYPE_COMMAND && payloadLen != 0
        && payload[0] == NWK_CMD_ROUTE_REQUEST)
    {
        nwkDoObserve(self, ind, &frame, hop.senderIeee, securityUsed ? 1 : 0, nowMs);

        nwkDoRouteRequest(self, &frame, payload, payloadLen, senderAddr, own, nowMs);

        return;
    }

    if (frame.frameType == NWK_FRAME_TYPE_COMMAND && payloadLen != 0 && payload[0] == NWK_CMD_LINK_STATUS)
    {
        int senderWasKnown = Nwk_NeighborOf(self->neighbors, senderAddr) != 0;

        nwkDoObserve(self, ind, &frame, hop.senderIeee, securityUsed ? 1 : 0, nowMs);
        nwkDoLearnAddress(self, &frame, own, nowMs);
        nwkDoLinkStatus(self, ind, &frame, hop.senderIeee, securityUsed ? 1 : 0, senderAddr, own, payload + 1,
                        payloadLen - 1, senderWasKnown, nowMs);

        return;
    }

    if (frame.frameType == NWK_FRAME_TYPE_COMMAND && payloadLen >= NWK_LEAVE_COMMAND_OCTETS
        && payload[0] == NWK_CMD_LEAVE)
    {
        Nwk_LeaveCommand leave;

        if (Nwk_LeaveCommandParse(payload, payloadLen, &leave) == ZB_OK)
            Nwk_LeaveRx(self, senderAddr, frame.srcIeeePresent ? frame.srcIeee : hop.senderIeee, &leave,
                        Nwk_AddrIsBroadcast(frame.destAddr), nowMs);

        return;
    }

    if (frame.frameType == NWK_FRAME_TYPE_COMMAND && payloadLen != 0 && payload[0] == NWK_CMD_ROUTE_RECORD)
    {
        nwkDoObserve(self, ind, &frame, hop.senderIeee, securityUsed ? 1 : 0, nowMs);
        nwkDoRouteRecord(self, &frame, payload + 1, payloadLen - 1, own, nowMs);

        return;
    }

    if (forMe && !isBroadcast && frame.frameType == NWK_FRAME_TYPE_COMMAND && payloadLen != 0
        && payload[0] == NWK_CMD_ROUTE_REPLY)
    {
        nwkDoObserve(self, ind, &frame, hop.senderIeee, securityUsed ? 1 : 0, nowMs);

        nwkDoRouteReply(self, &frame, payload, payloadLen, own, nowMs);

        return;
    }

    if (isBroadcast
        && Nwk_AddrKeepsBtt(self->cfg.deviceType, Nwk_AddrOwnRxOnWhenIdle(Mac_Pib(self->mac))))
    {
        record = Nwk_BttOf(self->btt, frame.srcAddr, frame.sequenceNumber);

        if (record != 0)
        {
            if (!Zb_timeReached(nowMs, record->expiresAtMs))
            {
                if (senderAddr != 0 && senderAddr != frame.srcAddr)
                    (void)Nwk_BttMarkRelayed(record);

                self->droppedDuplicate++;
                return;
            }

            Zb_memset(record, 0, (uint32_t)sizeof *record);
        }
        else
            record = Nwk_BttClaim(self->btt, nowMs);

        if (record == 0)
        {
            self->bttFullDrops++;
            return;
        }

        record->inUse = 1;
        record->sourceAddress = frame.srcAddr;
        record->sequenceNumber = frame.sequenceNumber;
        record->dst = frame.destAddr;
        record->expiresAtMs = nowMs + NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS;

        frame.endDeviceInitiator = 0;
        Nwk_RxForwardCopy(&frame, payload, payloadLen, record->npdu,
                          (uint32_t)sizeof record->npdu, &record->npduLen);

        record->reprotect = frame.securityEnabled;
        record->headerLen = frame.securityEnabled ? headerLen : 0;
    }

    nwkDoObserve(self, ind, &frame, hop.senderIeee, securityUsed ? 1 : 0, nowMs);

    nwkDoLearnAddress(self, &frame, own, nowMs);

    Nwk_RxExamineParents(self->neighbors, self->cfg.deviceType, ind, &frame, nowMs);

    if (isBroadcast)
    {
        if (frame.frameType == NWK_FRAME_TYPE_COMMAND && payloadLen != 0 && Nwk_CommandIsKnown(payload[0]))
            self->recognizedCommands++;

        if (frame.frameType == NWK_FRAME_TYPE_COMMAND && payloadLen != 0 && payload[0] == NWK_CMD_NETWORK_STATUS)
            nwkDoConflictStatusHeard(self, payload, payloadLen);

        nwkDoIndicate(self, &frame, payload, payloadLen, ind->lqi, 1, securityUsed);

        if (record != 0 && Nwk_AddrHasRoutingDuty(self->cfg.deviceType) && frame.radius > 0)
            nwkDoRelayBroadcast(self, record, nowMs);

        return;
    }

    if (forMe)
    {
        if (frame.frameType == NWK_FRAME_TYPE_COMMAND)
        {
            if (payloadLen == 0)
            {
                self->droppedMalformed++;
                return;
            }

            if (Nwk_JoinHandleCommand(self, &frame, payload, payloadLen, nowMs))
            {
                self->recognizedCommands++;
                return;
            }

            if (!Nwk_CommandIsProcessed(payload[0]))
            {
                nwkDoUnknownCommandReply(self, &frame, payload[0], nowMs);
                return;
            }

            if (payload[0] == NWK_CMD_NETWORK_STATUS)
                nwkDoStatusAtDestination(self, payload, payloadLen);

            self->recognizedCommands++;
        }

        nwkDoIndicate(self, &frame, payload, payloadLen, ind->lqi, 0, securityUsed);
        return;
    }

    if (frame.frameType == NWK_FRAME_TYPE_COMMAND && payloadLen != 0 && payload[0] == NWK_CMD_NETWORK_STATUS)
    {
        nwkDoStatusAtParent(self, &frame, payload, payloadLen);
        nwkDoConflictStatusHeard(self, payload, payloadLen);
    }

    frame.endDeviceInitiator = 0;
    heldSlot = nwkDoHeldRelayFree(self);
    slot = Nwk_TxFree(self->tx);

    status = Nwk_RelayUnicast(&frame, payload, payloadLen, &self->cfg, self->routes, self->neighbors,
                              self->mac, self->security, self->secureScratch,
                              (uint32_t)sizeof self->secureScratch, self->relayNpdu, (uint32_t)sizeof self->relayNpdu,
                              heldSlot >= 0 ? (uint8_t)(NWK_TX_HELD_RELAY_FIRST + heldSlot) : NWK_TX_HELD_UNTRACKED,
                              slot, nowMs, &outcome, &nextHop);

    if (outcome == NWK_RELAY_NO_ROUTE && nwkDoRelayDiscover(self, &frame, payload, payloadLen, slot, own, nowMs))
        return;

    nwkDoRelayOutcome(self, outcome, status, 0);

    if (outcome != NWK_RELAY_ISSUED || !Nwk_NeighborRestsReceiver(self->neighbors, nextHop))
        return;

    if (heldSlot < 0)
    {
        self->relaysHeldUntracked++;
        return;
    }

    track = &self->heldRelays[heldSlot];
    track->inUse = 1;
    track->sourceAddr = frame.srcAddr;
    track->destAddr = frame.destAddr;
    track->nextHop = nextHop;
    track->issuedMs = nowMs;
}

/* Every carrier `mac` delivered, in order, each decided before the next is taken: the BTT dedup judges this
   turn's second copy against the record its first created. No decision steps the MAC, so the ring only empties
   here, bounded at its own size. */
/* The step's receive, one MAC frame at a time: it stops at a frame held for the layer above, and after one ring's worth */
static void nwkDoDrainIndications(Nwk_Nwk *self)
{
    while (!self->indicationHeld && self->stepReceived < MAC_INDICATION_QUEUE_MAX
           && Mac_PollIndications(self->mac, &self->macIndication, 1) == 1)
    {
        self->stepReceived++;
        nwkDoReceive(self, &self->macIndication, self->stepMs);
    }
}

/* 3.6.2.2's no-retransmission rule for a spent radius: a record this device never relayed is not scheduled at all */
static void nwkDoRetransmissions(Nwk_Nwk *self, uint32_t nowMs)
{
    Nwk_BroadcastTransactionRecord *record;
    uint32_t i;

    for (i = 0; i < NWK_BTT_MAX; i++)
    {
        record = &self->btt[i];

        if (!record->inUse)
            continue;

        if (record->npduLen == 0)
            continue;

        if (!record->originates && record->relayed == 0)
            continue;

        if (record->relayed >= NWK_MAX_BROADCAST_RETRIES)
            continue;

        if (!Zb_timeReached(nowMs, record->nextRelayMs))
            continue;

        if (record->relayedByNeighbor)
        {
            record->relayed = NWK_MAX_BROADCAST_RETRIES;
            self->passiveAckStops++;
            continue;
        }

        nwkDoRelayBroadcast(self, record, nowMs);
    }
}

/* The deletion 3.6.4.5.1.7 makes for the destination and the wider one this façade makes for the source, which agree
   on the one predicate they share (ACTIVE survives, every other Table 3-78 status does not), so no precedence is
   chosen between them. */
static void nwkDoForgetRoute(Nwk_Nwk *self, uint16_t destAddr)
{
    Nwk_RoutingTableEntry *route;

    route = Nwk_RouteOf(self->routes, destAddr);

    if (route == 0)
        return;

    if (route->status == NWK_ROUTE_ACTIVE)
        return;

    Zb_memset(route, 0, (uint32_t)sizeof *route);
}

/* 3.6.1.6.1.3's search of the routing table, which is the one deletion in the corpus printed without a status
   condition: an entry whose destination is a device that has just rejoined goes, ACTIVE or not. */
uint32_t Nwk_RouteDelete(Nwk_Nwk *self, uint16_t destAddr)
{
    Nwk_RoutingTableEntry *route;

    if (self == 0)
        return 0;

    route = Nwk_RouteOf(self->routes, destAddr);

    if (route == 0)
        return 0;

    Zb_memset(route, 0, (uint32_t)sizeof *route);

    return 1;
}

/* Table 3-78's status for an entry that exists and does not forward: the one word a failed attempt has. */
static void nwkDoMarkRoute(Nwk_Nwk *self, uint16_t destAddr, uint32_t status)
{
    Nwk_RoutingTableEntry *route;

    route = Nwk_RouteOf(self->routes, destAddr);

    if (route == 0 || route->status == NWK_ROUTE_ACTIVE)
        return;

    route->status = status;
}

/* A discovery that timed out: the request that started it, held in its slot, is confirmed with Table 3-84's
   ROUTE_ERROR, its frame never sent */
static void nwkDoRouteDiscoveryFailed(Nwk_Nwk *self, uint16_t destAddr, uint8_t requestId)
{
    uint32_t i;

    for (i = 0; i < NWK_TX_MAX; i++)
    {
        if (self->tx[i].state != NWK_TX_AWAITING_ROUTE)
            continue;

        if (self->tx[i].dstAddr != destAddr || self->tx[i].requestId != requestId)
            continue;

        nwkDoConfirm(self, &self->tx[i], ZB_ERR_NO_ROUTE, NWK_STATUS_ROUTE_ERROR);
    }

    Nwk_RreqTxStop(self->rreqTx, destAddr, requestId);
}

/* One transmission of a schedule, and the two outcomes it can cost: a protection refused, and one sent */
static void nwkDoRreqTxRun(Nwk_Nwk *self, Nwk_RreqTx *record, uint32_t nowMs)
{
    int sent;
    int protectRefused;
    ZbStatus status;

    status = Nwk_RreqTxRun(record, self->mac, self->security, self->secureScratch,
                           (uint32_t)sizeof self->secureScratch, nowMs, &sent, &protectRefused);

    if (protectRefused)
        nwkDoProtectRefused(self, status);

    if (sent)
        self->routeRequestsSent++;
}

/* The two schedules 3.6.4.5.1 arms, in the order the clause prints them: this device's discoveries, its relays */
static void nwkDoRreqTx(Nwk_Nwk *self, uint32_t nowMs)
{
    uint32_t i;

    for (i = 0; i < NWK_RREQ_TX_MAX; i++)
        nwkDoRreqTxRun(self, &self->rreqTx[i], nowMs);

    for (i = 0; i < NWK_RREQ_TX_MAX; i++)
        nwkDoRreqTxRun(self, &self->rreqRelay[i], nowMs);
}

/* 3.6.4.5.1.7's deletion over the routing table and this façade's wider one, and the request that waited answered with
   ROUTE_ERROR */
static void nwkDoDiscoveryExpiry(Nwk_Nwk *self, uint32_t nowMs)
{
    Nwk_RouteDiscoveryTableEntry *entry;
    uint32_t i;

    for (i = 0; i < NWK_DISCOVERY_MAX; i++)
    {
        entry = &self->discoveries[i];

        if (!entry->inUse)
            continue;

        if (!Zb_timeReached(nowMs, entry->expiresAtMs))
            continue;

        entry->inUse = 0;

        if (Nwk_DiscoveryHeldForDestination(self->discoveries, entry->destAddr) == 0)
            nwkDoForgetRoute(self, entry->destAddr);
        else
            nwkDoMarkRoute(self, entry->destAddr, NWK_ROUTE_DISCOVERY_FAILED);

        if (Nwk_DiscoveryHeldForSource(self->discoveries, entry->sourceAddress) == 0)
            nwkDoForgetRoute(self, entry->sourceAddress);

        nwkDoRouteDiscoveryFailed(self, entry->destAddr, entry->routeRequestId);
    }
}

/* 3.6.4.5.1's second initiation case, entered where 3.6.4.3's lookup failed: the routing entry, the two counters, Table 3-79's entry */
/* 3.4.1.3.1.2: the destination IEEE address SHOULD always be added if it is known, and Table 3-68's map is one of
   the two places a device's 64-bit address is known. */
static ZbStatus nwkDoDiscoverRoute(Nwk_Nwk *self, Nwk_Tx *tx, uint16_t dstAddr, uint8_t requestRadius, uint16_t ownAddr,
                                   uint32_t nowMs, uint32_t *nwkStatus)
{
    uint8_t payload[NWK_RREQ_PAYLOAD_MAX];
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    Nwk_RouteDiscoveryTableEntry *entry;
    Nwk_NeighborTableEntry *target;
    Nwk_RoutingTableEntry *route;
    Nwk_Frame frame;
    Nwk_RouteRequestPayload request;
    uint32_t payloadLen;
    uint32_t npduLen;
    uint8_t radius;
    ZbStatus status;

    entry = Nwk_DiscoveryClaim(self->discoveries, nowMs);

    if (entry == 0)
    {
        *nwkStatus = NWK_STATUS_ROUTE_DISCOVERY_FAILED;

        return ZB_ERR_NO_SPACE;
    }

    self->routeRequestId = (uint8_t)(self->routeRequestId + 1);     
    radius = requestRadius == 0 ? NWK_INITIAL_RADIUS : requestRadius;
    target = Nwk_NeighborOf(self->neighbors, dstAddr);

    Zb_memset(&request, 0, (uint32_t)sizeof request);

    request.requestId = self->routeRequestId;
    request.destAddr = dstAddr;
    request.pathCost = 0;                                       
    request.manyToOne = NWK_RREQ_MANY_TO_ONE_NONE;               

    if (target != 0 && target->ieeeKnown)
    {
        request.destIeeePresent = 1;
        request.destIeee = target->extendedAddress;
    }
    else if (Nwk_AddrMapExtendedOf(self->addressMap, dstAddr, &request.destIeee))
        request.destIeeePresent = 1;

    request.maxSourceRoute = NWK_MAX_SOURCE_ROUTE;

    status = Nwk_RreqCompose(&request, &self->routingSequenceNumber, radius, payload,
                             (uint32_t)sizeof payload, &payloadLen);

    if (status != ZB_OK)
    {
        *nwkStatus = NWK_STATUS_FRAME_NOT_BUFFERED;

        return status;
    }

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = NWK_FRAME_TYPE_COMMAND;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.discoverRoute = NWK_DISCOVER_SUPPRESS;    
    frame.destAddr = NWK_ADDR_ROUTERS;              
    frame.srcAddr = ownAddr;
    frame.radius = radius;                          
    frame.sequenceNumber = (uint8_t)(self->seq % NWK_SEQ_WRAP);
    frame.srcIeeePresent = 1;                       
    frame.srcIeee = nwkDoOwnIeee(self->mac);
    frame.securityEnabled = Nwk_TxSecurityRuns(self->security) ? 1 : 0;
    self->seq = (self->seq + 1) % NWK_SEQ_WRAP;

    status = NwkFrame_Compose(&frame, payload, payloadLen, npdu, (uint32_t)sizeof npdu, &npduLen);

    if (status != ZB_OK)
    {
        *nwkStatus = NWK_STATUS_FRAME_NOT_BUFFERED;

        return status;
    }

    status = Nwk_RreqTxStart(self->rreqTx, dstAddr, self->routeRequestId, NWK_RREQ_MANY_TO_ONE_NONE,
                             npdu, npduLen, NwkFrame_HeaderLen(&frame), frame.securityEnabled, nowMs);

    if (status != ZB_OK)
    {
        entry->inUse = 0;
        *nwkStatus = NWK_STATUS_FRAME_NOT_BUFFERED;

        return status;
    }

    nwkDoRecordOwnBroadcast(self, ownAddr, frame.sequenceNumber, NWK_ADDR_ROUTERS, nowMs);

    entry->inUse = 1;
    entry->routeRequestId = self->routeRequestId;
    entry->sourceAddress = ownAddr;
    entry->senderAddress = 0;              
    entry->forwardCost = 0;
    entry->residualCost = 0;
    entry->destAddr = dstAddr;
    entry->expiresAtMs = nowMs + NWK_ROUTE_DISCOVERY_TIME_MS;

    route = Nwk_RouteOf(self->routes, dstAddr);

    if (route == 0)
    {
        route = Nwk_RouteClaim(self->routes);

        if (route == 0)
        {
            entry->inUse = 0;
            *nwkStatus = NWK_STATUS_ROUTE_ERROR;

            return ZB_ERR_NO_ROUTE;
        }

        route->inUse = 1;
        route->destinationAddress = dstAddr;
        route->ageMs = nowMs;
        route->status = NWK_ROUTE_DISCOVERY_UNDERWAY;
    }
    else if (route->status != NWK_ROUTE_ACTIVE)
        route->status = NWK_ROUTE_DISCOVERY_UNDERWAY;    

    if (tx != 0)
    {
        tx->state = NWK_TX_AWAITING_ROUTE;
        tx->requestId = self->routeRequestId;
    }

    return ZB_OK;
}

ZbStatus Nwk_Init(Nwk_Nwk *self, Mac_Mac *mac, const Nwk_Config *cfg)
{
    uint16_t own;

    if (self == 0 || mac == 0 || cfg == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->deviceType != NWK_DEVICE_COORDINATOR
        && cfg->deviceType != NWK_DEVICE_ROUTER
        && cfg->deviceType != NWK_DEVICE_END_DEVICE)
        return ZB_ERR_BAD_ARGUMENT;

    if (cfg->seqStart >= NWK_SEQ_WRAP)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(self, 0, (uint32_t)sizeof *self);

    self->mac = mac;
    self->cfg = *cfg;

    self->seq = cfg->seqStart;

    self->jitterState = cfg->jitterSeed;

    self->joinSeedState = cfg->joinSeed != 0 ? cfg->joinSeed : NWK_JOIN_SEED_DEFAULT;

    self->trustCenterIeee = cfg->trustCenterIeee != 0 ? cfg->trustCenterIeee : NWK_TRUST_CENTER_NONE;

    self->pollRateMs = cfg->indirectPollRateMs;

    own = 0;
    self->joinState = Nwk_AddrOwn(Mac_Pib(self->mac), &own) ? NWK_JOIN_JOINED : NWK_JOIN_IDLE;

    self->operatingSinceMs = 0;
    self->leaveRequestAllowed = 1;

    return ZB_OK;
}

/* The scaffold: no `Security` attached, or one answering level 0x00, is no security call on either side (4.3.1.1, 4.3.1.2) */
void Nwk_AttachSecurity(Nwk_Nwk *self, Security *security)
{
    if (self == 0)
        return;

    self->security = security;
}

void Nwk_SetTrustCenter(Nwk_Nwk *self, uint64_t trustCenterIeee)
{
    if (self == 0)
        return;

    self->trustCenterIeee = trustCenterIeee != 0 ? trustCenterIeee : NWK_TRUST_CENTER_NONE;
}

int Nwk_UnauthenticatedChildOf(const Nwk_Nwk *self, uint64_t extendedAddress, uint16_t *outAddress)
{
    uint32_t i;

    if (self == 0 || outAddress == 0)
        return 0;

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (self->neighbors[i].inUse && self->neighbors[i].ieeeKnown
            && self->neighbors[i].extendedAddress == extendedAddress
            && self->neighbors[i].relationship == NWK_REL_UNAUTHENTICATED_CHILD)
        {
            *outAddress = self->neighbors[i].networkAddress;

            return 1;
        }
    }

    return 0;
}

const Security *Nwk_Security(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->security;
}

/* 3.6.6's schedule belongs to the device that broadcast the frame, so a broadcast this door sends keeps the octets
   it would repeat and `nwkDoRetransmissions` runs the count for them as it does for a relay. */
ZbStatus Nwk_DataRequest(Nwk_Nwk *self, const Nwk_DataRequestParameters *req, uint32_t nowMs)
{
    Nwk_BroadcastTransactionRecord *record;
    Nwk_Tx *tx;
    Nwk_RouteDiscoveryTableEntry *entry;
    const Nwk_SourceRouteEntry *sourceRoute;
    uint16_t own;
    uint32_t nwkStatus = NWK_STATUS_LAST_MAC_STATUS;   
    int retryable;
    int protectRefused;
    ZbStatus status;

    if (self == 0 || req == 0 || self->mac == 0)
        return ZB_ERR_BAD_ARGUMENT;


    if (req->securityEnable != 0 && !Nwk_TxSecurityRuns(self->security))
    {
        self->refusedRequests++;
        return ZB_ERR_UNSUPPORTED;    /* 4.2.2 forbids a secured send with no security attached: the printed refusal, docs/internals/conformance.md §2 */
    }

    if (req->discoverRoute > (uint32_t)NWK_DISCOVER_ENABLE)
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;     
    }

    if (req->nsdu == 0 && req->nsduLength != 0)
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;     
    }

    if (req->nsduLength > NWK_NSDU_MAX)
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;     
    }

    if (Nwk_AddrIsReserved(req->dstAddr))
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;     
    }

    if (!Nwk_AddrOwn(Mac_Pib(self->mac), &own) || self->joinState == NWK_JOIN_COMMISSIONING)
    {
        self->refusedRequests++;
        return ZB_ERR_NOT_READY;        
    }

    if (req->dstAddr == own)
    {
        self->refusedRequests++;
        return ZB_ERR_BAD_ARGUMENT;
    }

    if (self->confirmCount >= NWK_CONFIRM_MAX)
    {
        self->refusedRequests++;
        return ZB_ERR_NO_SPACE;
    }

    tx = Nwk_TxFree(self->tx);

    if (tx == 0 || Nwk_TxOccupied(self->tx) + self->confirmCount >= NWK_CONFIRM_MAX)
    {
        self->refusedRequests++;
        nwkDoNoRoomConfirm(self, req->dstAddr);

        return ZB_ERR_NO_SPACE;
    }

    tx->state = NWK_TX_OUTSTANDING;     
    tx->dstAddr = req->dstAddr;
    tx->isBroadcast = Nwk_AddrIsBroadcast(req->dstAddr) ? 1 : 0;

    self->lastRequestHandle = RADIO_HANDLE_NONE;

    sourceRoute = Nwk_AddrHasRoutingDuty(self->cfg.deviceType) && !tx->isBroadcast
                  && !nwkDoRoutesFirst(self, req->dstAddr)
                  ? Nwk_SourceRouteOf(self->sourceRoutes, req->dstAddr, nowMs)
                  : 0;

    status = Nwk_TxCompose(tx, req, own, &self->seq, self->cfg.deviceType == NWK_DEVICE_END_DEVICE
                                                        && self->cfg.parentInformation != 0, sourceRoute);

    if (status != ZB_OK)
    {
        Zb_memset(tx, 0, (uint32_t)sizeof *tx);
        self->refusedRequests++;
        return status;
    }

    self->lastRequestSeq = tx->seq;

    if (tx->isBroadcast && Nwk_AddrKeepsBtt(self->cfg.deviceType, Nwk_AddrOwnRxOnWhenIdle(Mac_Pib(self->mac))))
    {
        record = Nwk_BttOpen(self->btt, own, tx->seq, tx->dstAddr, nowMs,
                             nowMs + NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS);

        if (record == 0)
        {
            self->bttFullDrops++;
            nwkDoConfirm(self, tx, ZB_ERR_NO_SPACE, NWK_STATUS_BT_TABLE_FULL);

            return ZB_OK;
        }

        Zb_memcpy(record->npdu, tx->npdu, tx->npduLen);

        record->npduLen = tx->npduLen;
        record->headerLen = tx->headerLen;
        record->reprotect = tx->secured;
        record->originates = 1;
        record->nextRelayMs = nowMs + NWK_PASSIVE_ACK_TIMEOUT_MS + Nwk_RelayJitterMs(&self->jitterState, &self->cfg);
    }

    if (tx->isBroadcast)
    {
        tx->nextHop = req->dstAddr;

        if (self->cfg.deviceType == NWK_DEVICE_END_DEVICE)
        {
            Nwk_NeighborTableEntry *parent = nwkDoParentEntry(self);

            if (parent != 0)
            {
                tx->nextHop = parent->networkAddress;
                tx->toParent = 1;
            }
        }
    }
    else if (sourceRoute != 0)
        tx->nextHop = sourceRoute->relayList[sourceRoute->relayCount - 1];
    else if (self->cfg.deviceType == NWK_DEVICE_END_DEVICE)
    {
        Nwk_NeighborTableEntry *parent = nwkDoParentEntry(self);

        if (parent == 0)
        {
            self->droppedNoRoute++;
            nwkDoConfirm(self, tx, ZB_ERR_NO_ROUTE, NWK_STATUS_ROUTE_ERROR);

            return ZB_OK;
        }

        tx->nextHop = parent->networkAddress;
    }
    else if (!Nwk_RouteNextHop(self->routes, self->neighbors, req->dstAddr, nowMs, &tx->nextHop))
    {
        if (req->discoverRoute == (uint32_t)NWK_DISCOVER_ENABLE && Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        {
            entry = Nwk_DiscoveryRunning(self->discoveries, own, req->dstAddr);

            if (entry != 0)
            {
                tx->state = NWK_TX_AWAITING_ROUTE;
                tx->requestId = entry->routeRequestId;

                return ZB_OK;
            }

            status = nwkDoDiscoverRoute(self, tx, req->dstAddr, req->radius, own, nowMs, &nwkStatus);

            if (status == ZB_OK)
                return ZB_OK;           

            nwkDoConfirm(self, tx, status, nwkStatus);

            return ZB_OK;
        }

        self->droppedNoRoute++;
        nwkDoConfirm(self, tx, ZB_ERR_NO_ROUTE, NWK_STATUS_ROUTE_ERROR);

        return ZB_OK;
    }

    (void)nwkDoRouteRecordSend(self, req->dstAddr, nowMs);

    tx->indirect = Nwk_NeighborRestsReceiver(self->neighbors, tx->nextHop);
    tx->msduHandle = (uint8_t)(tx - self->tx + 1);

    status = Nwk_TxIssueAttempt(tx, self->mac, self->security, self->secureScratch,
                                (uint32_t)sizeof self->secureScratch, nowMs, &retryable, &protectRefused);

    if (protectRefused)
        nwkDoProtectRefused(self, status);

    if (status == ZB_OK)
        self->lastRequestHandle = tx->lastHandle;

    if (retryable)
    {
        tx->state = NWK_TX_AWAITING_RETRY;
        tx->heldSinceMs = nowMs;
        tx->nextRetryMs = nwkDoRetryAt(tx, nowMs);
    }
    else if (status != ZB_OK)
    {
        nwkDoAttemptFailed(self, tx, status);

        return ZB_OK;
    }

    if (tx->isBroadcast && !retryable)
        nwkDoBroadcastCopies(self, tx, nowMs);

    return ZB_OK;
}

ZbStatus Nwk_SetBeaconInfo(Nwk_Nwk *self, const Nwk_BeaconInfo *info, int associationPermit)
{
    Mac_BeaconConfig macBeacon;
    uint8_t payload[NWK_BEACON_PAYLOAD_LEN];
    uint32_t payloadLen = 0;
    ZbStatus status;

    if (self == 0 || info == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(&macBeacon, 0, (uint32_t)sizeof macBeacon);

    macBeacon.answer = (self->cfg.deviceType == NWK_DEVICE_COORDINATOR
                        || self->cfg.deviceType == NWK_DEVICE_ROUTER);
    macBeacon.panCoordinator = self->cfg.deviceType == NWK_DEVICE_COORDINATOR;
    macBeacon.associationPermit = associationPermit ? 1 : 0;
    macBeacon.payloadLen = 0;

    if (macBeacon.answer)
    {
        status = Nwk_ComposeBeaconPayload(info, payload, (uint32_t)sizeof payload, &payloadLen);

        if (status != ZB_OK)
            return status;

        macBeacon.payload = payload;
        macBeacon.payloadLen = payloadLen;
    }

    status = Mac_SetBeaconConfig(self->mac, &macBeacon);

    if (status == ZB_OK)
    {
        self->associationPermit = associationPermit ? 1 : 0;
        self->beaconInfo = *info;
        self->beaconInfoKnown = 1;
    }

    return status;
}

/* What a step runs after its receive, at the step's time, once nothing is held */
static void nwkDoStepRest(Nwk_Nwk *self)
{
    self->stepRestOwed = 0;

    nwkDoPolls(self, self->stepMs);

    nwkDoConflictBroadcast(self, self->stepMs);

    nwkDoDiscoveryExpiry(self, self->stepMs);
}

ZbStatus Nwk_Step(Nwk_Nwk *self, uint32_t nowMs)
{
    ZbStatus status;
    uint32_t i;

    if (self == 0 || self->mac == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->stepRestOwed)
        nwkDoStepRest(self);

    if (self->indicationHeld)
    {
        self->indicationHeld = 0;
        self->droppedIndications++;
    }

    self->stepMs = nowMs;
    self->stepReceived = 0;

    status = Mac_Step(self->mac, nowMs);

    nwkDoNeighborAge(self, nowMs);

    nwkDoChildTimeout(self, nowMs);

    nwkDoLinkStatusTx(self, nowMs);

    Nwk_PermitExpire(self, nowMs);

    nwkDoDrainConfirms(self, nowMs);

    nwkDoHeldRelayAge(self, nowMs);

    nwkDoDrainCommStatus(self);

    nwkDoRetries(self, nowMs);

    nwkDoRetransmissions(self, nowMs);

    for (i = 0; i < NWK_TX_MAX; i++)
    {
        if (self->tx[i].state == NWK_TX_AWAITING_ROUTE)
            nwkDoDiscoveryRelease(self, self->tx[i].dstAddr, self->tx[i].requestId, nowMs);
    }

    nwkDoRreqTx(self, nowMs);

    self->lostChildrenDeleted += Nwk_RxReleaseLostChildren(self->neighbors, nowMs);

    Nwk_ParentsStep(self, nowMs);

    Nwk_JoinStep(self, nowMs);

    Nwk_PollStep(self, nowMs);

    nwkDoDrainIndications(self);

    if (self->indicationHeld)
        self->stepRestOwed = 1;
    else
        nwkDoStepRest(self);

    return status;
}

uint32_t Nwk_PollConfirms(Nwk_Nwk *self, Nwk_DataConfirmParameters *out, uint32_t max)
{
    uint32_t taken = 0;

    if (self == 0 || out == 0 || max == 0)
        return 0;

    while (taken < max && self->confirmCount > 0)
    {
        out[taken] = self->confirms[self->confirmHead];
        self->confirmHead = (self->confirmHead + 1) % NWK_CONFIRM_MAX;
        self->confirmCount--;
        taken++;
    }

    return taken;
}

const Nwk_DataIndicationParameters *Nwk_Indication(const Nwk_Nwk *self)
{
    return self != 0 && self->indicationHeld ? &self->indication : 0;
}

void Nwk_IndicationDone(Nwk_Nwk *self)
{
    if (self == 0 || !self->indicationHeld)
        return;

    self->indicationHeld = 0;

    nwkDoDrainIndications(self);

    if (!self->indicationHeld && self->stepRestOwed)
        nwkDoStepRest(self);
}

uint32_t Nwk_ConfirmsWaiting(const Nwk_Nwk *self)
{
    return self != 0 ? self->confirmCount : 0;
}


uint32_t Nwk_TransmitQueue(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return Nwk_TxOccupied(self->tx);
}

/* 3.3.1.2: this device's own short address, which the same mirror carries. */
uint16_t Nwk_OwnAddress(const Nwk_Nwk *self)
{
    const Radio_Pib *pib;

    if (self == 0 || self->mac == 0)
        return 0;

    pib = Mac_Pib(self->mac);

    return pib != 0 ? pib->shortAddress : 0;
}

int Nwk_OwnAddressKnown(const Nwk_Nwk *self, uint16_t *outAddress)
{
    if (self == 0 || self->mac == 0)
        return 0;

    return Nwk_AddrOwn(Mac_Pib(self->mac), outAddress);
}

/* 3.3.1.2: the device's own extended address is the PIB the backend took, mirrored by the MAC. */
uint64_t Nwk_OwnExtendedAddress(const Nwk_Nwk *self)
{
    const Radio_Pib *pib;

    if (self == 0 || self->mac == 0)
        return 0;

    pib = Mac_Pib(self->mac);

    if (pib == 0)
        return 0;

    return ((uint64_t)pib->extendedAddress[7] << 56) | ((uint64_t)pib->extendedAddress[6] << 48)
        | ((uint64_t)pib->extendedAddress[5] << 40) | ((uint64_t)pib->extendedAddress[4] << 32)
        | ((uint64_t)pib->extendedAddress[3] << 24) | ((uint64_t)pib->extendedAddress[2] << 16)
        | ((uint64_t)pib->extendedAddress[1] << 8) | (uint64_t)pib->extendedAddress[0];
}

uint32_t Nwk_NeighborQueue(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return Nwk_NeighborCount(self->neighbors);
}

/* The two link-status counters, the promotion count, and the rank of one entry. */
uint32_t Nwk_LinkStatusSent(const Nwk_Nwk *self)
{
    return self != 0 ? self->linkStatusSent : 0;
}

uint32_t Nwk_LinkStatusApplied(const Nwk_Nwk *self)
{
    return self != 0 ? self->linkStatusApplied : 0;
}

uint32_t Nwk_BackbonePromotions(const Nwk_Nwk *self)
{
    return self != 0 ? self->backbonePromotions : 0;
}

uint32_t Nwk_NeighborRankOf(const Nwk_Nwk *self, uint16_t address)
{
    const Nwk_NeighborTableEntry *entry;

    if (self == 0)
        return 0;

    entry = Nwk_NeighborOf((Nwk_NeighborTableEntry *)self->neighbors, address);

    return entry != 0 ? Nwk_NeighborRank(entry) : 0;
}

/* 3.6.10's counters, which is how a caller sees the exchange and the aging it decides. */
uint32_t Nwk_TimeoutRequestsSent(const Nwk_Nwk *self)
{
    return self != 0 ? self->timeoutRequestsSent : 0;
}

uint32_t Nwk_TimeoutResponsesSent(const Nwk_Nwk *self)
{
    return self != 0 ? self->timeoutResponsesSent : 0;
}

uint32_t Nwk_ChildrenAgedOut(const Nwk_Nwk *self)
{
    return self != 0 ? self->childrenAgedOut : 0;
}

uint32_t Nwk_KeepalivesReceived(const Nwk_Nwk *self)
{
    return self != 0 ? self->keepalivesReceived : 0;
}

uint32_t Nwk_UnknownPollLeaves(const Nwk_Nwk *self)
{
    return self != 0 ? self->unknownPollLeaves : 0;
}

uint32_t Nwk_ParentLinkFailures(const Nwk_Nwk *self)
{
    return self != 0 ? self->parentLinkFailures : 0;
}

uint32_t Nwk_PollsSent(const Nwk_Nwk *self)
{
    return self != 0 ? self->pollsSent : 0;
}

uint32_t Nwk_ParentLinkHeld(const Nwk_Nwk *self)
{
    return self != 0 ? self->parentLinkHeld : 0;
}

uint32_t Nwk_KeepalivesSent(const Nwk_Nwk *self)
{
    return self != 0 ? self->keepalivesSent : 0;
}

uint32_t Nwk_UnknownSenderLeaves(const Nwk_Nwk *self)
{
    return self != 0 ? self->unknownSenderLeaves : 0;
}

/* 3.6.4.5.5's two counters, which is how a caller sees a record arrive or a command pass through. */
uint32_t Nwk_SourceRoutesLearned(const Nwk_Nwk *self)
{
    return self != 0 ? self->sourceRoutesLearned : 0;
}

ZbStatus Nwk_SetSourceRoute(Nwk_Nwk *self, uint16_t destination, const uint16_t *relays, uint32_t count, uint32_t nowMs)
{
    uint16_t own = 0;
    uint32_t i;

    if (self == 0 || (relays == 0 && count != 0) || count > NWK_MAX_SOURCE_ROUTE)
        return ZB_ERR_BAD_ARGUMENT;

    if (!Nwk_AddrHasRoutingDuty(self->cfg.deviceType))
        return ZB_ERR_BAD_STATE;

    (void)Nwk_AddrOwn(Mac_Pib(self->mac), &own);

    if (Nwk_AddrIsReserved(destination) || Nwk_AddrIsBroadcast(destination) || destination == own)
        return ZB_ERR_BAD_ARGUMENT;

    for (i = 0; i < count; i++)
    {
        if (Nwk_AddrIsReserved(relays[i]) || Nwk_AddrIsBroadcast(relays[i]) || relays[i] == own
            || relays[i] == destination)
            return ZB_ERR_BAD_ARGUMENT;
    }

    return Nwk_SourceRouteSeed(self->sourceRoutes, destination, relays, count, nowMs);
}

uint32_t Nwk_PollAddressNotices(Nwk_Nwk *self, Nwk_AddressNotice *out, uint32_t max)
{
    uint32_t taken = 0;

    if (self == 0 || out == 0)
        return 0;

    while (taken < max && self->addressNoticeCount > 0)
    {
        out[taken++] = self->addressNotices[self->addressNoticeHead];

        self->addressNoticeHead = (self->addressNoticeHead + 1) % NWK_ADDRESS_NOTICE_MAX;
        self->addressNoticeCount--;
    }

    return taken;
}

uint32_t Nwk_AddressNoticesDropped(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->addressNoticesDropped;
}

uint32_t Nwk_PollSourceRouteNotices(Nwk_Nwk *self, Nwk_SourceRouteNotice *out, uint32_t max)
{
    uint32_t taken = 0;

    if (self == 0 || out == 0)
        return 0;

    while (taken < max && self->sourceRouteNoticeCount > 0)
    {
        out[taken++] = self->sourceRouteNotices[self->sourceRouteNoticeHead];

        self->sourceRouteNoticeHead = (self->sourceRouteNoticeHead + 1) % NWK_SOURCE_ROUTE_NOTICE_MAX;
        self->sourceRouteNoticeCount--;
    }

    return taken;
}

uint32_t Nwk_SourceRouteNoticesDropped(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->sourceRouteNoticesDropped;
}

uint32_t Nwk_RouteRecordsReceived(const Nwk_Nwk *self)
{
    return self != 0 ? self->routeRecordsReceived : 0;
}

uint32_t Nwk_RouteRecordsSent(const Nwk_Nwk *self)
{
    return self != 0 ? self->routeRecordsSent : 0;
}

uint32_t Nwk_RouteRecordsRelayed(const Nwk_Nwk *self)
{
    return self != 0 ? self->routeRecordsRelayed : 0;
}

uint32_t Nwk_RouteQueue(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return Nwk_RouteCount(self->routes);
}

uint32_t Nwk_DiscoveryQueue(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return Nwk_DiscoveryCount(self->discoveries);
}

uint32_t Nwk_BttQueue(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return Nwk_BttCount(self->btt);
}

uint32_t Nwk_ConfirmQueue(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->confirmCount;
}

uint32_t Nwk_ConfirmsDropped(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->confirmsDropped;
}

uint32_t Nwk_IndicationQueue(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->indicationHeld ? 1 : 0;
}

Radio_Handle Nwk_LastRequestHandle(const Nwk_Nwk *self)
{
    if (self == 0)
        return RADIO_HANDLE_NONE;

    return self->lastRequestHandle;
}

uint8_t Nwk_LastRequestSeq(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->lastRequestSeq;
}

uint32_t Nwk_RefusedRequests(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->refusedRequests;
}

uint32_t Nwk_DroppedEndDeviceInitiator(const Nwk_Nwk *self)
{
    return self != 0 ? self->droppedEndDeviceInitiator : 0;
}

uint32_t Nwk_DroppedNoRoute(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->droppedNoRoute;
}

uint32_t Nwk_ConfirmsIgnored(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->confirmsIgnored;
}

uint32_t Nwk_CommStatusSeen(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->commStatusSeen;
}

uint32_t Nwk_DroppedMalformed(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->droppedMalformed;
}

uint32_t Nwk_DroppedUnsupported(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->droppedUnsupported;
}

uint32_t Nwk_DroppedDuplicate(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->droppedDuplicate;
}

uint32_t Nwk_DroppedNotForMe(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->droppedNotForMe;
}

uint32_t Nwk_DroppedMulticast(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->droppedMulticast;
}

uint32_t Nwk_DroppedBadSource(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->droppedBadSource;
}

uint32_t Nwk_LostChildrenDeleted(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->lostChildrenDeleted;
}

uint32_t Nwk_BttFullDrops(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->bttFullDrops;
}

uint32_t Nwk_DroppedIndications(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->droppedIndications;
}

uint32_t Nwk_RecognizedCommands(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->recognizedCommands;
}

uint32_t Nwk_ReplyCommands(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->replyCommands;
}

uint32_t Nwk_NeighborAddsRefused(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->neighborAddsRefused;
}

uint32_t Nwk_RelaysSent(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->relaysSent;
}

uint32_t Nwk_BroadcastRetransmissions(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->broadcastRetransmissions;
}

uint32_t Nwk_PassiveAcksHeard(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->passiveAcksHeard;
}

uint32_t Nwk_PassiveAckStops(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->passiveAckStops;
}

uint32_t Nwk_RxSecurityFailures(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->rxSecurityFailures;
}

uint32_t Nwk_RxFrameCounterRejects(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->rxFrameCounterRejects;
}

uint32_t Nwk_DroppedUnsecured(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->droppedUnsecured;
}

uint32_t Nwk_TxSecurityFailures(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->txSecurityFailures;
}

uint32_t Nwk_CarrierOther(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->carrierOther;
}

uint32_t Nwk_RouteRequestsSent(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->routeRequestsSent;
}

uint32_t Nwk_RouteRepliesSent(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->routeRepliesSent;
}

uint32_t Nwk_RouteRepliesForwarded(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->routeRepliesForwarded;
}

uint32_t Nwk_ChildDiscoveries(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->childDiscoveries;
}

uint32_t Nwk_ChildFramesHeld(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->childFramesHeld;
}

uint32_t Nwk_RrepDroppedNoDiscovery(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->rrepDroppedNoDiscovery;
}

uint32_t Nwk_RrepDroppedNoRoute(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->rrepDroppedNoRoute;
}

uint32_t Nwk_RrepDroppedNoReverseRoute(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->rrepDroppedNoReverseRoute;
}

uint32_t Nwk_RrepDroppedNotSmaller(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->rrepDroppedNotSmaller;
}

uint32_t Nwk_RrepDroppedUnsuitable(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->rrepDroppedUnsuitable;
}

uint32_t Nwk_RrepDroppedNoCapacity(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->rrepDroppedNoCapacity;
}

uint32_t Nwk_RreqDroppedEndDevice(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->rreqDroppedEndDevice;
}

uint32_t Nwk_RreqDroppedNoNeighbor(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->rreqDroppedNoNeighbor;
}

uint32_t Nwk_RreqDroppedNoOutgoingCost(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->rreqDroppedNoOutgoingCost;
}

uint32_t Nwk_RreqDroppedGreaterCost(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->rreqDroppedGreaterCost;
}

uint32_t Nwk_RreqDroppedNoDiscoverySlot(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->rreqDroppedNoDiscoverySlot;
}

uint32_t Nwk_NeighborsAgedOut(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->neighborsAgedOut;
}

uint32_t Nwk_RoutesInvalidated(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->routesInvalidated;
}

uint32_t Nwk_LinkFailuresReported(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->linkFailuresReported;
}

/* The routing entries and the source routes a received Network Status removed */
uint32_t Nwk_StatusRoutesRemoved(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->statusRoutesRemoved;
}

uint32_t Nwk_StatusSourceRoutesRemoved(const Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return self->statusSourceRoutesRemoved;
}

uint32_t Nwk_TestJitterMs(Nwk_Nwk *self)
{
    if (self == 0)
        return 0;

    return Nwk_RelayJitterMs(&self->jitterState, &self->cfg);
}

Nwk_AddressMapEntry *Nwk_AddrMapOf(Nwk_Nwk *self)
{
    return self != 0 ? self->addressMap : 0;
}

const Nwk_AddressMapEntry *Nwk_AddrMapConst(const Nwk_Nwk *self)
{
    return self != 0 ? self->addressMap : 0;
}

uint32_t Nwk_AddressMapLearned(const Nwk_Nwk *self)
{
    return self != 0 ? self->addressMapLearned : 0;
}

uint32_t Nwk_AddressConflictsLocal(const Nwk_Nwk *self)
{
    return self != 0 ? self->addressConflictsLocal : 0;
}

uint32_t Nwk_AddressConflictsOther(const Nwk_Nwk *self)
{
    return self != 0 ? self->addressConflictsOther : 0;
}

int Nwk_AddressOfIeee(const Nwk_Nwk *self, uint64_t extendedAddress, uint16_t *outAddress)
{
    if (self == 0)
        return 0;

    return Nwk_AddrMapShortOf(self->addressMap, extendedAddress, outAddress);
}

int Nwk_IsPartOfNetwork(const Nwk_Nwk *self)
{
    uint16_t own = 0;

    if (self == 0 || self->mac == 0 || self->joinState == NWK_JOIN_COMMISSIONING)
        return 0;

    return Nwk_AddrOwn(Mac_Pib(self->mac), &own) ? 1 : 0;
}

int Nwk_IeeeOfAddress(const Nwk_Nwk *self, uint16_t networkAddress, uint64_t *outExtended)
{
    if (self == 0)
        return 0;

    return Nwk_AddrMapExtendedOf(self->addressMap, networkAddress, outExtended);
}

uint32_t Nwk_JoinResponsesDelivered(const Nwk_Nwk *self)
{
    return self != 0 ? self->joinResponsesDelivered : 0;
}

uint32_t Nwk_JoinResponsesUndelivered(const Nwk_Nwk *self)
{
    return self != 0 ? self->joinResponsesUndelivered : 0;
}

uint32_t Nwk_ConflictBroadcastsSent(const Nwk_Nwk *self)
{
    return self != 0 ? self->conflictBroadcastsSent : 0;
}

uint32_t Nwk_ConflictBroadcastsCancelled(const Nwk_Nwk *self)
{
    return self != 0 ? self->conflictBroadcastsCancelled : 0;
}

uint32_t Nwk_PollStatusIndications(Nwk_Nwk *self, Nwk_NwkStatusIndication *out, uint32_t max)
{
    uint32_t taken;

    if (self == 0 || out == 0)
        return 0;

    for (taken = 0; taken < max && self->statusIndicationCount != 0; taken++)
    {
        out[taken] = self->statusIndications[self->statusIndicationHead];

        self->statusIndicationHead = (self->statusIndicationHead + 1) % NWK_STATUS_INDICATION_MAX;
        self->statusIndicationCount--;
    }

    return taken;
}

uint32_t Nwk_AddressUpdatesSent(const Nwk_Nwk *self)
{
    return self != 0 ? self->addressUpdatesSent : 0;
}

uint32_t Nwk_AddressUpdatesTaken(const Nwk_Nwk *self)
{
    return self != 0 ? self->addressUpdatesTaken : 0;
}
