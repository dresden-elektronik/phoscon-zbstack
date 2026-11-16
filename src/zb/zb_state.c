/* R23.1: 3.6.9, 4.3, 4.3.1.2, 4.3.4, 4.4.1.1, 4.4.12.1, 4.6.3.8 ok (the SHOULD list, the child list, the banks,
   the octet counters, every key pair but its incoming counter); 4.3.4 deferred (no EPID is held with the counter,
   so a second network's copy cannot be kept apart; a restore rewinds a live octet counter, which the suite pins). */

#include "zb_state.h"

#include "nwk_addr.h"
#include "nwk_beacon.h"
#include "nwk_join.h"

#include "nwk_rreq.h"
#include "zb_utils.h"

/* One name twice is a set that selects nothing: a key by KeySeqNumber, a window by (sender, key),
   a pair by DeviceAddress (content identity). */
static int stateDoDuplicateKey(const Zb_State *in, uint32_t index)
{
    uint32_t other;

    for (other = 0; other < index; other++)
    {
        if (in->keys[index].keySeqNumber == in->keys[other].keySeqNumber)
            return 1;
    }

    return 0;
}

static int stateDoDuplicateWindow(const Zb_State *in, uint32_t index)
{
    uint32_t other;

    for (other = 0; other < index; other++)
    {
        if (in->windows[index].senderIeee == in->windows[other].senderIeee
            && in->windows[index].keySeqNumber == in->windows[other].keySeqNumber)
            return 1;
    }

    return 0;
}

static int stateDoDuplicatePair(const Zb_State *in, uint32_t index)
{
    uint32_t other;

    for (other = 0; other < index; other++)
    {
        if (in->pairs[index].deviceIeee == in->pairs[other].deviceIeee)
            return 1;
    }

    return 0;
}

/* The bank, over the larger of the stored value and the one this boot reached, so a second restore of the
   same state advances again. Carrying past 2^32-1 is refused, not saturated. */
static ZbStatus stateDoBank(uint32_t stored, uint32_t current, uint32_t *out)
{
    uint32_t base = stored > current ? stored : current;

    if (base > SECURITY_FRAME_COUNTER_LAST - ZB_STATE_COUNTER_BANK)
        return ZB_ERR_BAD_FRAME_COUNTER;

    *out = base + ZB_STATE_COUNTER_BANK;

    return ZB_OK;
}

/* The descriptor this boot holds under a key sequence number, and the key it was configured with
   (kept where `keyPresent` is 0); -1 when it holds none. */
static int stateDoFindKey(const Security *security, uint8_t keySeqNumber)
{
    uint32_t index;

    for (index = 0; index < SECURITY_KEY_SET_MAX; index++)
    {
        if (security->keys[index].inUse && security->keys[index].keySeqNumber == keySeqNumber)
            return (int)index;
    }

    return -1;
}

/* The key pair this boot holds for a Table 4-36 DeviceAddress, or -1. */
static int stateDoFindPair(const Security *security, uint64_t deviceIeee)
{
    uint32_t index;

    for (index = 0; index < security->keyPairCount && index < SECURITY_KEYPAIR_MAX; index++)
    {
        if (security->keyPairs[index].deviceIeee == deviceIeee)
            return (int)index;
    }

    return -1;
}

/* The counter this boot has already reached under a name, 0 for a name it holds nothing under: the second
   half of what a restore lands past. */
static uint32_t stateDoCurrentKey(const Security *security, uint8_t keySeqNumber)
{
    int found = stateDoFindKey(security, keySeqNumber);

    return found < 0 ? 0 : security->keys[found].outgoingFrameCounter;
}

static uint32_t stateDoCurrentPair(const Security *security, uint64_t deviceIeee)
{
    int found = stateDoFindPair(security, deviceIeee);

    return found < 0 ? 0 : security->keyPairs[found].outgoingFrameCounter;
}

/* Every rule a state is held to, judged before the first write: the schema, the bounds a count is not
   allowed to exceed, the three one-octet counters and the routing sequence number (each inside its own wrap),
   every entry's own shape and every name's uniqueness; a key pair names a device unless it holds the global key,
   which names none, since 4.4.12.1 backs up every entry. The rules a module would judge (a level Table 4-38
   prints, a KeyAttributes 4.4.1.1 will not use) are Security_Restore's, and the second half of this file hands it
   only states that passed here, so its refusals are reviews of a set this function could have refused already. */
static ZbStatus stateDoValidate(const Security *security, const Nwk_Nwk *nwk, const Zb_State *in)
{
    uint32_t index;
    uint32_t banked;

    if (in->version < ZB_STATE_VERSION_OLDEST || in->version > ZB_STATE_VERSION || in->deviceType != nwk->cfg.deviceType)
        return ZB_ERR_BAD_ARGUMENT;

    if (in->nwkUpdateId > 0xff
        || (in->channel != 0 && (in->channel < MAC_SCAN_CHANNEL_FIRST || in->channel > MAC_SCAN_CHANNEL_LAST)))
        return ZB_ERR_BAD_ARGUMENT;

    if (in->deviceType == NWK_DEVICE_END_DEVICE && (in->parentIeee == 0 || in->parentShort > NWK_ADDR_LAST_UNICAST))
        return ZB_ERR_BAD_ARGUMENT;

    if (in->nwkSecurityLevel > SECURITY_LEVEL_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (in->keyCount > SECURITY_KEY_SET_MAX || in->windowCount > SECURITY_INCOMING_MAX
        || in->pairCount > SECURITY_KEYPAIR_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    if (in->nwkSequenceNumber >= NWK_SEQ_WRAP || in->nwkRoutingSequenceNumber >= NWK_ROUTE_SEQUENCE_WRAP
        || in->macDsn >= MAC_DSN_WRAP || in->apsCounter >= APS_COUNTER_WRAP)
        return ZB_ERR_BAD_ARGUMENT;

    for (index = 0; index < in->keyCount; index++)
    {
        if (stateDoBank(in->keys[index].outgoingFrameCounter,
                        stateDoCurrentKey(security, in->keys[index].keySeqNumber), &banked) != ZB_OK)
            return ZB_ERR_BAD_FRAME_COUNTER;

        if (stateDoDuplicateKey(in, index))
            return ZB_ERR_BAD_ARGUMENT;
    }

    for (index = 0; index < in->windowCount; index++)
    {
        if (in->windows[index].senderIeee == 0)
            return ZB_ERR_BAD_ARGUMENT;

        if (stateDoDuplicateWindow(in, index))
            return ZB_ERR_BAD_ARGUMENT;
    }

    for (index = 0; index < in->pairCount; index++)
    {
        if (in->pairs[index].deviceIeee == 0 && in->pairs[index].linkKeyType != SECURITY_LINK_KEY_GLOBAL)
            return ZB_ERR_BAD_ARGUMENT;

        if (stateDoBank(in->pairs[index].outgoingFrameCounter,
                        stateDoCurrentPair(security, in->pairs[index].deviceIeee), &banked) != ZB_OK)
            return ZB_ERR_BAD_FRAME_COUNTER;

        if (stateDoDuplicatePair(in, index))
            return ZB_ERR_BAD_ARGUMENT;
    }

    return ZB_OK;
}

/* The device's own place in the network and the child list a parent keeps: the four fields go back where they were
   read from, and a stored child the live table does not hold is added, its timeout counter starting over. */
static void stateDoRestorePlace(Nwk_Nwk *nwk, Mac_Mac *mac, const Zb_State *in)
{
    Radio_Pib pib;
    Nwk_NeighborTableEntry *entry;
    uint32_t index;

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);

    pib.present = RADIO_PIB_PAN_ID | RADIO_PIB_SHORT_ADDRESS;
    pib.panId = in->panId;
    pib.shortAddress = in->networkAddress;

    (void)Mac_SetPib(mac, &pib);

    nwk->cfg.parentInformation = in->parentInformation;

    for (index = 0; index < 8; index++)
        nwk->joinExtendedPanId[index] = (uint8_t)((in->extendedPanId >> (8 * index)) & 0xff);

    for (index = 0; index < in->childCount && index < NWK_NEIGHBOR_MAX; index++)
    {
        entry = Nwk_NeighborOf(nwk->neighbors, in->children[index].networkAddress);

        if (entry == 0)
            entry = Nwk_NeighborFree(nwk->neighbors);

        if (entry == 0)
            return;

        Zb_memset(entry, 0, (uint32_t)sizeof *entry);

        entry->inUse = 1;
        entry->networkAddress = in->children[index].networkAddress;
        entry->extendedAddress = in->children[index].extendedAddress;
        entry->ieeeKnown = 1;
        entry->deviceType = NWK_DEVICE_END_DEVICE;
        entry->relationship = NWK_REL_UNAUTHENTICATED_CHILD;
        entry->routerOutboundActivity = NWK_ROUTER_AGE_LIMIT;
        entry->routerInboundActivity = NWK_ROUTER_AGE_LIMIT;
        entry->endDeviceConfiguration = in->children[index].endDeviceConfiguration;
        entry->deviceTimeout = in->children[index].deviceTimeout;
        entry->timeoutCounter = in->children[index].deviceTimeout;
    }
}

/* The network layer's own copy of the trust centre, which a joiner otherwise learns with its key, and the joined
   state with an end device's parent: the place a boot that did not join has to be given. */
static void stateDoRestoreJoin(Nwk_Nwk *nwk, const Zb_State *in)
{
    if (in->trustCenterIeee != APS_KEY_IEEE_UNSET && in->trustCenterIeee != APS_KEY_IEEE_ALL_F)
        Nwk_SetTrustCenter(nwk, in->trustCenterIeee);

    Nwk_JoinResume(nwk, in->parentShort, in->deviceType == NWK_DEVICE_END_DEVICE ? in->parentIeee : 0);
}

/* The address pairs the set already names go into the map a 64-bit destination is resolved through: a centralized
   network's trust centre at the coordinator's address, an end device's parent and each child. */
static void stateDoRestoreMap(Nwk_Nwk *nwk, const Zb_State *in)
{
    uint32_t index;

    if (in->trustCenterIeee != APS_KEY_IEEE_UNSET && in->trustCenterIeee != APS_KEY_IEEE_ALL_F)
        (void)Nwk_AddrMapLearn(nwk->addressMap, NWK_ADDR_COORDINATOR, in->trustCenterIeee, in->networkAddress, 0);

    if (in->deviceType == NWK_DEVICE_END_DEVICE)
        (void)Nwk_AddrMapLearn(nwk->addressMap, in->parentShort, in->parentIeee, in->networkAddress, 0);

    for (index = 0; index < in->childCount && index < NWK_NEIGHBOR_MAX; index++)
        (void)Nwk_AddrMapLearn(nwk->addressMap, in->children[index].networkAddress,
                               in->children[index].extendedAddress, in->networkAddress, 0);
}

/* The SHOULD list's four fields come from where each lives, the PAN and the address from the MAC's PIB and the
   extended PAN and the parent information from the NWK layer's; the child list is the neighbour table's end devices. */
ZbStatus Zb_StateCapture(const Security *security, const Nwk_Nwk *nwk, const Aps_Aps *aps, const Mac_Mac *mac,
                         int includeKeys, Zb_State *out)
{
    uint32_t index;

    if (!security || !nwk || !aps || !mac || !out)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(out, 0, (uint32_t)sizeof *out);

    out->version = ZB_STATE_VERSION;
    out->ownIeee = security->ownIeee;
    out->deviceType = nwk->cfg.deviceType;
    out->trustCenterIeee = security->trustCenterIeee;

    out->panId = Mac_Pib(mac)->panId;
    out->networkAddress = Mac_Pib(mac)->shortAddress;
    out->channel = Mac_Pib(mac)->channel;
    out->nwkUpdateId = nwk->beaconInfoKnown ? nwk->beaconInfo.updateId : 0;
    out->parentInformation = nwk->cfg.parentInformation;
    out->stackProfile = NWK_BEACON_STACK_PROFILE;

    if (nwk->cfg.deviceType == NWK_DEVICE_END_DEVICE)
    {
        out->parentShort = (uint16_t)nwk->joinParentShort;
        out->parentIeee = nwk->joinParentExtended;
    }

    for (index = 0; index < 8; index++)
        out->extendedPanId |= (uint64_t)nwk->joinExtendedPanId[index] << (8 * index);

    out->nwkSecurityLevel = security->nwkSecurityLevel;
    out->nwkActiveKeySeqNumber = security->nwkActiveKeySeqNumber;
    out->authenticated = security->authenticated ? 1 : 0;
    out->nwkAllFresh = security->nwkAllFresh ? 1 : 0;

    for (index = 0; index < SECURITY_KEY_SET_MAX; index++)
    {
        if (!security->keys[index].inUse)
            continue;

        out->keys[out->keyCount].keySeqNumber = security->keys[index].keySeqNumber;
        out->keys[out->keyCount].outgoingFrameCounter = security->keys[index].outgoingFrameCounter;
        out->keys[out->keyCount].keyPresent = includeKeys ? 1 : 0;

        if (includeKeys)
            Zb_memcpy(out->keys[out->keyCount].key, security->keys[index].key, SECURITY_KEY_OCTETS);

        out->keyCount++;
    }

    for (index = 0; index < SECURITY_INCOMING_MAX; index++)
    {
        if (!security->incoming[index].inUse)
            continue;

        out->windows[out->windowCount].senderIeee = security->incoming[index].senderIeee;
        out->windows[out->windowCount].keySeqNumber = security->incoming[index].keySeqNumber;
        out->windows[out->windowCount].frameCounter = security->incoming[index].frameCounter;
        out->windowCount++;
    }

    for (index = 0; index < security->keyPairCount && index < SECURITY_KEYPAIR_MAX; index++)
    {
        out->pairs[index].deviceIeee = security->keyPairs[index].deviceIeee;
        out->pairs[index].shortAddress = security->keyPairs[index].shortAddress;
        out->pairs[index].shortKnown = security->keyPairs[index].shortKnown ? 1 : 0;
        out->pairs[index].keyAttributes = security->keyPairs[index].keyAttributes;
        out->pairs[index].linkKeyType = security->keyPairs[index].linkKeyType;
        out->pairs[index].outgoingFrameCounter = security->keyPairs[index].outgoingFrameCounter;
        out->pairs[index].featuresCapabilities = security->keyPairs[index].featuresCapabilities;
        out->pairs[index].keyPresent = includeKeys ? 1 : 0;

        if (includeKeys)
            Zb_memcpy(out->pairs[index].linkKey, security->keyPairs[index].key, SECURITY_KEY_OCTETS);

        out->pairCount++;
    }

    for (index = 0; index < NWK_NEIGHBOR_MAX; index++)
    {
        const Nwk_NeighborTableEntry *entry = &nwk->neighbors[index];

        if (!entry->inUse || entry->deviceType != NWK_DEVICE_END_DEVICE)
            continue;

        out->children[out->childCount].extendedAddress = entry->extendedAddress;
        out->children[out->childCount].networkAddress = entry->networkAddress;
        out->children[out->childCount].endDeviceConfiguration = entry->endDeviceConfiguration;
        out->children[out->childCount].deviceTimeout = entry->deviceTimeout;
        out->childCount++;
    }

    out->nwkSequenceNumber = nwk->seq;
    out->nwkRoutingSequenceNumber = nwk->routingSequenceNumber;
    out->macDsn = mac->tx.dsn % MAC_DSN_WRAP;
    out->apsCounter = aps->apsCounter;

    return ZB_OK;
}

/* This boot's seed and transport-key policy go back in, the seed copied out first: the wipe clears the module's
   own copy. */
ZbStatus Zb_StateRestore(Security *security, Nwk_Nwk *nwk, Aps_Aps *aps, Mac_Mac *mac, const Zb_State *in)
{
    Security_Config cfg;
    Security_KeyDescriptor keys[SECURITY_KEY_SET_MAX];
    Security_IncomingEntry windows[SECURITY_INCOMING_MAX];
    Security_KeyPairEntry pairs[SECURITY_KEYPAIR_MAX];
    uint8_t linkKeySeed[SECURITY_KEY_OCTETS];
    uint32_t index;
    uint32_t base;
    int found;
    ZbStatus status;

    if (!security || !nwk || !aps || !mac || !in)
        return ZB_ERR_BAD_ARGUMENT;

    status = stateDoValidate(security, nwk, in);

    if (status != ZB_OK)
        return status;

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    Zb_memset(keys, 0, (uint32_t)sizeof keys);
    Zb_memset(windows, 0, (uint32_t)sizeof windows);
    Zb_memset(pairs, 0, (uint32_t)sizeof pairs);

    cfg.ownIeee = in->ownIeee;
    cfg.trustCenterIeee = in->trustCenterIeee;
    cfg.requireLinkKeyEncryption = security->requireLinkKeyEncryption;

    if (security->linkKeySeedKnown)
    {
        Zb_memcpy(linkKeySeed, security->linkKeySeed, SECURITY_KEY_OCTETS);
        cfg.linkKeySeed = linkKeySeed;
    }

    cfg.nwkSecurityLevel = (uint8_t)in->nwkSecurityLevel;
    cfg.nwkActiveKeySeqNumber = in->nwkActiveKeySeqNumber;
    cfg.authenticated = in->authenticated ? 1 : 0;
    cfg.nwkAllFresh = in->nwkAllFresh ? 1 : 0;
    cfg.keys = keys;
    cfg.keyCount = in->keyCount;
    cfg.incomingSeeds = windows;
    cfg.incomingSeedCount = in->windowCount;
    cfg.keyPairs = pairs;
    cfg.keyPairCount = in->pairCount;
    cfg.log = 0;                        

    for (index = 0; index < in->keyCount; index++)
    {
        keys[index].keySeqNumber = in->keys[index].keySeqNumber;
        keys[index].inUse = 1;

        if (stateDoBank(in->keys[index].outgoingFrameCounter,
                        stateDoCurrentKey(security, in->keys[index].keySeqNumber),
                        &keys[index].outgoingFrameCounter) != ZB_OK)
            return ZB_ERR_BAD_FRAME_COUNTER;     

        if (in->keys[index].keyPresent)
            Zb_memcpy(keys[index].key, in->keys[index].key, SECURITY_KEY_OCTETS);
        else
        {
            found = stateDoFindKey(security, in->keys[index].keySeqNumber);

            if (found < 0)
                return ZB_ERR_AUTH;

            Zb_memcpy(keys[index].key, security->keys[found].key, SECURITY_KEY_OCTETS);
        }
    }

    for (index = 0; index < in->windowCount; index++)
    {
        windows[index].senderIeee = in->windows[index].senderIeee;
        windows[index].keySeqNumber = in->windows[index].keySeqNumber;
        windows[index].inUse = 1;
        windows[index].frameCounter = in->windows[index].frameCounter;
    }

    for (index = 0; index < in->pairCount; index++)
    {
        pairs[index].deviceIeee = in->pairs[index].deviceIeee;
        pairs[index].shortAddress = in->pairs[index].shortAddress;
        pairs[index].shortKnown = in->pairs[index].shortKnown ? 1 : 0;
        pairs[index].keyAttributes = in->pairs[index].keyAttributes;
        pairs[index].linkKeyType = in->pairs[index].linkKeyType;
        pairs[index].featuresCapabilities = in->pairs[index].featuresCapabilities;

        if (stateDoBank(in->pairs[index].outgoingFrameCounter,
                        stateDoCurrentPair(security, in->pairs[index].deviceIeee),
                        &pairs[index].outgoingFrameCounter) != ZB_OK)
            return ZB_ERR_BAD_FRAME_COUNTER;

        if (in->pairs[index].keyPresent)
            Zb_memcpy(pairs[index].key, in->pairs[index].linkKey, SECURITY_KEY_OCTETS);
        else
        {
            found = stateDoFindPair(security, in->pairs[index].deviceIeee);

            if (found < 0)
                return ZB_ERR_AUTH;

            Zb_memcpy(pairs[index].key, security->keyPairs[found].key, SECURITY_KEY_OCTETS);
        }
    }

    status = Security_Restore(security, &cfg);

    if (status != ZB_OK)
        return status;

    nwk->seq = (in->nwkSequenceNumber + ZB_STATE_OCTET_STEP) % NWK_SEQ_WRAP;
    mac->tx.dsn = (in->macDsn + ZB_STATE_OCTET_STEP) % MAC_DSN_WRAP;
    aps->apsCounter = (in->apsCounter + ZB_STATE_OCTET_STEP) % APS_COUNTER_WRAP;

    base = in->nwkRoutingSequenceNumber > nwk->routingSequenceNumber ? in->nwkRoutingSequenceNumber
                                                                    : nwk->routingSequenceNumber;
    nwk->routingSequenceNumber = (base + ZB_STATE_SEQUENCE_STEP) % NWK_ROUTE_SEQUENCE_WRAP;

    stateDoRestorePlace(nwk, mac, in);
    stateDoRestoreJoin(nwk, in);
    stateDoRestoreMap(nwk, in);

    return ZB_OK;
}
