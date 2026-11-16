#include "nwk_parents.h"

#include "nwk_addr.h"
#include "nwk_beacon.h"
#include "nwk_cost.h"
#include "zb_utils.h"

/* R23.1: 3.2.2.2.3, 3.2.2.3, 3.2.2.4, 3.2.2.12, 3.6.1.5, 3.6.1.5.1, 3.6.1.6.1.4 ok (one MAC interface, its scans, levels
   in dBm); 3.2.2.11 ok (but a joined device's pause, refused); 3.6.1.5.2 ok (but rule 5, the rejoin's current parent,
   and rule 6, a manufacturer's own features). */

ZbStatus Nwk_ParentFromBeacon(const Mac_BeaconNotification *beacon, Nwk_JoinParent *out)
{
    Nwk_BeaconInfo info;
    uint32_t i;

    if (beacon == 0 || out == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (beacon->payloadLen == 0 || Nwk_ParseBeaconInfo(beacon->payload, beacon->payloadLen, &info) != ZB_OK)
        return ZB_ERR_BAD_FRAME;

    if (info.protocolVersion != NWK_BEACON_PROTOCOL_VERSION || info.stackProfile != NWK_STACK_PROFILE_PRO)
        return ZB_ERR_BAD_FRAME;

    Zb_memset(out, 0, (uint32_t)sizeof *out);

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        out->extendedPanId[i] = (uint8_t)(info.extendedPanId >> (8 * i));

    out->panId = beacon->coordPanId;
    out->shortKnown = beacon->coordAddrMode == MAC_ADDR_SHORT ? 1 : 0;
    out->shortAddress = beacon->coordShort;
    out->extendedAddress = beacon->coordAddrMode == MAC_ADDR_EXTENDED ? beacon->coordExtended : 0;
    out->channel = beacon->channel;
    out->page = 0;
    out->associationPermit = beacon->associationPermit;
    out->deviceType = beacon->panCoordinator ? NWK_DEVICE_COORDINATOR : NWK_DEVICE_ROUTER;
    out->rxOnWhenIdle = 1;
    out->r23Appendix = Nwk_BeaconRouterInformation(beacon->payload, beacon->payloadLen, &out->routerInformation);
    out->lqa = beacon->lqi > NWK_LQA_MAX ? NWK_LQA_MAX : beacon->lqi;
    out->updateId = info.updateId;
    out->depth = info.deviceDepth;
    out->routerCapacity = info.routerCapacity;
    out->endDeviceCapacity = info.endDeviceCapacity;
    out->inUse = 1;

    return ZB_OK;
}

/* One of Table I-6's bits as a preference: 1 above 0, 0 when the two agree. */
static int nwkParentsBitOrder(const Nwk_JoinParent *a, const Nwk_JoinParent *b, uint16_t bit)
{
    return (int)((a->routerInformation & bit) != 0) - (int)((b->routerInformation & bit) != 0);
}

int Nwk_ParentRanksAbove(const Nwk_JoinParent *a, const Nwk_JoinParent *b, uint32_t goodLqa)
{
    int order;
    int aGood = a->lqa >= goodLqa;
    int bGood = b->lqa >= goodLqa;

    if (aGood != bGood)
        return aGood;

    order = nwkParentsBitOrder(a, b, NWK_ROUTER_INFO_HUB_CONNECTIVITY);

    if (order == 0)
        order = nwkParentsBitOrder(a, b, NWK_ROUTER_INFO_PREFERRED_PARENT);

    if (order == 0)
        order = nwkParentsBitOrder(a, b, NWK_ROUTER_INFO_LONG_UPTIME);

    if (order != 0)
        return order > 0;

    return (int8_t)(uint8_t)(a->updateId - b->updateId) > 0;
}

/* The same potential parent: one network, one channel, and the same short or extended address the beacon named. */
static int nwkParentsSame(const Nwk_JoinParent *row, const Nwk_JoinParent *entry)
{
    if (Zb_memcmp(row->extendedPanId, entry->extendedPanId, RADIO_ADDR_LEN) != 0 || row->channel != entry->channel)
        return 0;

    if (row->shortKnown && entry->shortKnown)
        return row->shortAddress == entry->shortAddress;

    return row->extendedAddress != 0 && row->extendedAddress == entry->extendedAddress;
}

ZbStatus Nwk_ParentAdmit(Nwk_JoinParent *pool, const Nwk_JoinParent *entry, uint32_t goodLqa)
{
    Nwk_JoinParent *slot = 0;
    uint32_t i;

    for (i = 0; i < NWK_JOIN_PARENT_MAX && slot == 0; i++)
    {
        if (pool[i].inUse && nwkParentsSame(&pool[i], entry))
            slot = &pool[i];
    }

    for (i = 0; i < NWK_JOIN_PARENT_MAX && slot == 0; i++)
    {
        if (!pool[i].inUse)
            slot = &pool[i];
    }

    if (slot == 0)
    {
        slot = &pool[0];

        for (i = 1; i < NWK_JOIN_PARENT_MAX; i++)
        {
            if (Nwk_ParentRanksAbove(slot, &pool[i], goodLqa))
                slot = &pool[i];
        }

        if (!Nwk_ParentRanksAbove(entry, slot, goodLqa))
            return ZB_ERR_NO_SPACE;
    }

    *slot = *entry;
    slot->inUse = 1;

    return ZB_OK;
}

uint32_t Nwk_ParentBest(const Nwk_JoinParent *pool, uint32_t eligible, uint32_t goodLqa)
{
    uint32_t best = NWK_JOIN_PARENT_MAX;
    uint32_t i;

    for (i = 0; i < NWK_JOIN_PARENT_MAX; i++)
    {
        if (!pool[i].inUse || (eligible & ((uint32_t)1 << i)) == 0)
            continue;

        if (best == NWK_JOIN_PARENT_MAX || Nwk_ParentRanksAbove(&pool[i], &pool[best], goodLqa))
            best = i;
    }

    return best;
}

uint32_t Nwk_ParentsGoodLqa(const Nwk_Nwk *self)
{
    return self->cfg.goodParentLqa != 0 ? self->cfg.goodParentLqa : (uint32_t)NWK_GOOD_PARENT_LQA_DEFAULT;
}

/* This device's nwkExtendedPanId as the NIB holds it, 0 when it names no network yet. */
static uint64_t nwkParentsOwnExtendedPan(const Nwk_Nwk *self)
{
    return self->beaconInfoKnown ? self->beaconInfo.extendedPanId : 0;
}

/* Rules 4 to 6, the request's and the NIB's: a beacon that permits no join where only permitting networks were
   asked for, one with no end device capacity where only those were, and another network than the NIB's own. */
static int nwkParentsWanted(const Nwk_Nwk *self, const Nwk_JoinParent *entry)
{
    uint64_t own = nwkParentsOwnExtendedPan(self);
    uint64_t heard = 0;
    uint32_t i;

    if (self->discoveryRequest.onlyPermitJoinNetworks && !entry->associationPermit)
        return 0;

    if (self->discoveryRequest.onlyEndDeviceCapacity && !entry->endDeviceCapacity)
        return 0;

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        heard |= (uint64_t)entry->extendedPanId[i] << (8 * i);

    return own == 0 || own == heard;
}

ZbStatus Nwk_NetworkDiscoveryRequest(Nwk_Nwk *self, const Nwk_NetworkDiscoveryRequestParameters *req, uint32_t nowMs)
{
    Mac_ScanRequestParameters scan;
    uint32_t supported = 0;
    uint32_t channel;
    ZbStatus status;

    if (self == 0 || req == 0 || self->mac == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (self->discoveryRunning || Mac_Scanning(self->mac))
        return ZB_ERR_BUSY;

    for (channel = MAC_SCAN_CHANNEL_FIRST; channel <= MAC_SCAN_CHANNEL_LAST; channel++)
        supported |= (uint32_t)1 << channel;

    if ((req->scanChannels & supported) == 0 || req->scanDuration > NWK_DISCOVERY_SCAN_DURATION_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(&scan, 0, (uint32_t)sizeof scan);
    scan.scanType = MAC_SCAN_ACTIVE;
    scan.scanChannels = req->scanChannels & supported;
    scan.scanDuration = NWK_DISCOVERY_SUPERFRAME_SYMBOLS * (((uint32_t)1 << req->scanDuration) + 1);

    status = Mac_ScanRequest(self->mac, &scan, nowMs);

    if (status != ZB_OK)
        return status;

    if (!req->keepTable)
        Zb_memset(self->joinParents, 0, (uint32_t)sizeof self->joinParents);

    self->discoveryRequest = *req;
    self->discoveryConfirmReady = 0;
    self->discoveryRunning = 1;

    return ZB_OK;
}

void Nwk_ParentsStep(Nwk_Nwk *self, uint32_t nowMs)
{
    Mac_BeaconNotification beacon;
    Mac_ScanConfirmParameters scan;
    Nwk_JoinParent entry;
    uint32_t i;

    (void)nowMs;

    if (!self->discoveryRunning)
        return;

    while (Mac_PollBeacons(self->mac, &beacon, 1) == 1)
    {
        if (Nwk_ParentFromBeacon(&beacon, &entry) != ZB_OK || !nwkParentsWanted(self, &entry)
            || Nwk_ParentAdmit(self->joinParents, &entry, Nwk_ParentsGoodLqa(self)) != ZB_OK)
        {
            self->discoveryBeaconsDiscarded++;
            continue;
        }

        self->discoveryBeaconsTaken++;
    }

    if (Mac_PollScanConfirm(self->mac, &scan) != 1)
        return;

    self->discoveryConfirm.status = scan.status;
    self->discoveryConfirm.entries = 0;

    for (i = 0; i < NWK_JOIN_PARENT_MAX; i++)
        self->discoveryConfirm.entries += self->joinParents[i].inUse ? 1 : 0;

    self->discoveryRunning = 0;
    self->discoveryConfirmReady = 1;
}

uint32_t Nwk_PollNetworkDiscoveryConfirm(Nwk_Nwk *self, Nwk_NetworkDiscoveryConfirmParameters *out)
{
    if (self == 0 || out == 0 || !self->discoveryConfirmReady)
        return 0;

    *out = self->discoveryConfirm;
    self->discoveryConfirmReady = 0;

    return 1;
}

ZbStatus Nwk_EdScanRequest(Nwk_Nwk *self, const Nwk_EdScanRequestParameters *req, uint32_t nowMs)
{
    Mac_ScanRequestParameters scan;
    uint32_t supported = 0;
    uint32_t channel;
    uint16_t own;
    ZbStatus status;

    if (self == 0 || req == 0 || self->mac == 0)
        return ZB_ERR_BAD_ARGUMENT;

    for (channel = MAC_SCAN_CHANNEL_FIRST; channel <= MAC_SCAN_CHANNEL_LAST; channel++)
        supported |= (uint32_t)1 << channel;

    if (req->scanChannels == 0 || (req->scanChannels & ~supported) != 0
        || req->scanDuration > NWK_DISCOVERY_SCAN_DURATION_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (Nwk_AddrOwn(Mac_Pib(self->mac), &own))
        return ZB_ERR_BAD_STATE;

    if (self->edScanRunning || self->discoveryRunning || self->joinState != NWK_JOIN_IDLE || Mac_Scanning(self->mac))
        return ZB_ERR_BUSY;

    Zb_memset(&scan, 0, (uint32_t)sizeof scan);
    scan.scanType = MAC_SCAN_ENERGY;
    scan.scanChannels = req->scanChannels;
    scan.scanDuration = NWK_DISCOVERY_SUPERFRAME_SYMBOLS * (((uint32_t)1 << req->scanDuration) + 1);

    status = Mac_ScanRequest(self->mac, &scan, nowMs);

    if (status != ZB_OK)
        return status;

    self->edScanRequest = *req;
    self->edScanRunning = 1;

    return ZB_OK;
}

uint32_t Nwk_PollEdScanConfirm(Nwk_Nwk *self, Nwk_EdScanConfirmParameters *out)
{
    Mac_ScanConfirmParameters scan;
    Nwk_EnergyDetectChannelInfo *info;
    uint32_t channel;

    if (self == 0 || out == 0 || !self->edScanRunning || Mac_PollScanConfirm(self->mac, &scan) != 1)
        return 0;

    Zb_memset(out, 0, (uint32_t)sizeof *out);
    out->status = scan.status;

    for (channel = MAC_SCAN_CHANNEL_FIRST; channel <= MAC_SCAN_CHANNEL_LAST; channel++)
    {
        if ((self->edScanRequest.scanChannels & ((uint32_t)1 << channel)) == 0)
            continue;

        info = &out->channels[out->channelCount++];
        info->channelPage = 0;
        info->channelNumber = (uint8_t)channel;
        info->measured = (scan.unscannedChannels & ((uint32_t)1 << channel)) == 0 ? 1 : 0;
        info->energyDetected = info->measured ? scan.energyDbm[channel - MAC_SCAN_CHANNEL_FIRST] : 0;
    }

    self->edScanRunning = 0;

    return 1;
}

uint32_t Nwk_DiscoveryEntries(const Nwk_Nwk *self, Nwk_JoinParent *out, uint32_t max)
{
    uint32_t taken = 0;
    uint32_t remaining = 0;
    uint32_t best;
    uint32_t i;

    if (self == 0 || out == 0)
        return 0;

    for (i = 0; i < NWK_JOIN_PARENT_MAX; i++)
        remaining |= self->joinParents[i].inUse ? (uint32_t)1 << i : 0;

    while (taken < max)
    {
        best = Nwk_ParentBest(self->joinParents, remaining, Nwk_ParentsGoodLqa(self));

        if (best >= NWK_JOIN_PARENT_MAX)
            break;

        out[taken] = self->joinParents[best];
        remaining &= ~((uint32_t)1 << best);
        taken++;
    }

    return taken;
}
