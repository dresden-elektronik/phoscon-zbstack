/* Suite for the four topic modules band A's APS directory holds (`aps_group`, `aps_dup`, `aps_tx` and
   `aps_ack`) driven through their own headers and nothing above them (docs/internals/coding-rules.md §4.5). Every pool is a plain array the suite owns, exactly the shape `Aps_Aps` embeds,
   and every call hands that array in: no `Aps_Aps` anywhere in the file, and no door validation, count or
   confirmation-ring arithmetic, all of which stay façade-side and are asserted in the `aps` suite.
   `Aps_TxResolveKeyPair` and `Aps_TxOutgoingOctets` need a `Security` seeded the way `test/aps/` seeds one,
   and `Aps_AckRespond` needs the layer it hands an answer down to, so the file builds one minimal
   `Nwk_Nwk` over `loopback_radio` for that one case: the air is what proves the three not-owed rows stopped
   before it.

   What is asserted is what each body answers: which slot a group lookup returns and what an unused slot
   carrying the same pair is worth, the order `Aps_GroupAdd`'s two questions are asked in, the status a remove
   gives for a pair the table does not hold and the status the remove-all gives when nothing matched, the
   eviction a full duplicate pool performs and what a hit writes, the delivery mode each Table 2-2 row derives
   to and the address a group send is aimed at, which octets a secured slot hands down and which an unsecured
   one hands down, which transaction a confirmation belongs to and by what it was recognized, the free slot
   and the occupied count of a transaction pool, the key pair a request names and the negative it names no
   entry with, and the four parts 2.2.8.4.4 matches an acknowledgement on.

   Two rules are pinned by mutation rather than by more cases, and both are named at the bottom of the file
   beside the change each one stands for. */

#include "aps.h"
#include "aps_ack.h"
#include "aps_admit.h"
#include "aps_transportkey.h"
#include "aps_dup.h"
#include "aps_frag.h"
#include "aps_frame.h"
#include "aps_group.h"
#include "aps_tx.h"
#include "loopback_radio.h"
#include "mac.h"
#include "nwk.h"
#include "radio.h"
#include "security.h"
#include "test_harness.h"
#include "zb_utils.h"

/* Two devices this suite aims at and a third that is neither of them, two group ids, and the endpoints a
   group table may hold. `EP_BROADCAST` is the broadcast endpoint: legal for a frame, out of range for an
   APSME parameter, and judged nowhere inside these modules. */
#define PEER_A 0x0011
#define PEER_B 0x0022
#define PEER_C 0x0033
#define UNSEEN 0x9999
#define GROUP_A 0x1234
#define GROUP_B 0x5678
#define GROUP_C 0x0001
#define EP_ONE 0x01
#define EP_TWO 0x02
#define EP_THREE 0x03
#define EP_UNUSED 0x07
#define EP_BROADCAST 0xff
#define EP_ZDO 0x00

#define PROFILE_ID 0x0104
#define CLUSTER_ID 0x0006
#define SRC_EP 0x01
#define DST_EP 0x02
#define APS_COUNTER 0x11
#define ASDU_LEN 6

#define SEEN_MS 1000
#define LATER_MS 2000

/* The eight-octet unicast data header `ApsFrame_Compose` writes for the shape this suite composes (Figure 2-3
   with Figure 2-7's columns), and the Frame Control Field of the acknowledgement `Aps_AckRespond` composes:
   frame type 0b10 in bits 0-1, delivery mode unicast, ACK format 0, security 0, ACK request 0, no extended
   header (2.2.5.1.1.3 with 2.2.8.4.3). */
#define APS_HEADER_UNICAST_OCTETS 8
#define APS_ACK_FCF 0x02

#define OWN_IEEE 0x0123456789abcdef
#define PARTNER_IEEE 0x1011121314151617
#define FOREIGN_IEEE 0x2222222222222222

static const uint8_t s_linkKey[SECURITY_KEY_OCTETS] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
};

static const uint8_t s_nwkKey[SECURITY_KEY_OCTETS] = {
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};

/* The octet pattern a caller's buffer is prefilled with so a refusal can be asserted to have written nothing
   in it, and the pattern the scratch of the outgoing-octet case carries so the two arms are distinguishable
   by content and not only by pointer. */
#define SENTINEL_OCTET 0x5a
#define SCRATCH_OCTET 0x6b

static const uint8_t s_asdu[ASDU_LEN] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

/* The three pools, as the suite owns them: plain arrays, cleared before every case, exactly the shape `Aps_Aps`
   embeds as a named member of its own struct. */
static Aps_Group s_groups[APS_GROUP_MAX];
static Aps_Dup s_dups[APS_DUP_MAX];
static Aps_Tx s_tx[APS_TX_MAX];

/* --- pool seeding and clearing ----------------------------------------------------------------- */

static void clearGroups(void)
{
    Zb_memset(s_groups, 0, (uint32_t)sizeof s_groups);
}

/* One membership written straight into the pool, the way the façade's own `Aps_Init` leaves none and the way
   a persisted table hands them back. */
static void seedGroup(uint32_t slot, uint16_t groupAddress, uint8_t endpoint)
{
    s_groups[slot].inUse = 1;
    s_groups[slot].groupAddress = groupAddress;
    s_groups[slot].endpoint = endpoint;
}

static void clearDups(void)
{
    Zb_memset(s_dups, 0, (uint32_t)sizeof s_dups);
}

static void seedDup(uint32_t slot, uint16_t srcAddr, uint8_t apsCounter, uint32_t seenMs)
{
    s_dups[slot].inUse = 1;
    s_dups[slot].srcAddress = srcAddr;
    s_dups[slot].apsCounter = apsCounter;
    s_dups[slot].seenMs = seenMs;
}

static void clearTx(void)
{
    Zb_memset(s_tx, 0, (uint32_t)sizeof s_tx);
}

static void seedTx(uint32_t slot, uint32_t state, uint16_t nwkDst, uint16_t dstAddress, uint8_t dstEndpoint,
                   uint16_t clusterId, uint8_t apsCounter, Radio_Handle lastHandle)
{
    s_tx[slot].state = state;
    s_tx[slot].nwkDst = nwkDst;
    s_tx[slot].dstAddress = dstAddress;
    s_tx[slot].dstEndpoint = dstEndpoint;
    s_tx[slot].clusterId = clusterId;
    s_tx[slot].apsCounter = apsCounter;
    s_tx[slot].lastHandle = lastHandle;
}

/* --- the shapes the operations are handed ------------------------------------------------------ */

static Aps_ApsdeReq reqAt(uint32_t dstAddrMode, uint16_t dstAddress)
{
    Aps_ApsdeReq req;

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.dstAddrMode = dstAddrMode;
    req.dstAddress = dstAddress;
    req.dstEndpoint = DST_EP;
    req.profileId = PROFILE_ID;
    req.clusterId = CLUSTER_ID;
    req.srcEndpoint = SRC_EP;

    return req;
}

/* An acknowledgement as the codec hands it to the module that matches transactions against it. The presence
   flags are what `ApsFrame_Parse` derives from the Frame Control Field, so a case that clears one is a case
   that read a frame which does not carry that field at all. */
static Aps_Frame ackFrameAt(int ackRequest, uint32_t deliveryMode, uint16_t clusterId, uint8_t apsCounter,
                            uint8_t srcEndpoint)
{
    Aps_Frame frame;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = APS_FRAME_TYPE_ACK;
    frame.deliveryMode = deliveryMode;
    frame.ackRequest = ackRequest;
    frame.clusterPresent = 1;
    frame.clusterId = clusterId;
    frame.profilePresent = 1;
    frame.profileId = PROFILE_ID;
    frame.srcEndpointPresent = 1;
    frame.srcEndpoint = srcEndpoint;
    frame.dstEndpointPresent = 1;
    frame.dstEndpoint = SRC_EP;
    frame.apsCounter = apsCounter;

    return frame;
}

/* The indication an acknowledgement arrived on: the one field `Aps_AckSlotForAck` and `Aps_AckRespond` read off
   it is `srcAddr`, the NWK originator Table 3-4 pins (the guard is band A's own). */
static Nwk_DataIndicationParameters indicationAt(uint16_t srcAddr, uint16_t dstAddr)
{
    Nwk_DataIndicationParameters ind;

    Zb_memset(&ind, 0, (uint32_t)sizeof ind);
    ind.srcAddr = srcAddr;
    ind.dstAddr = dstAddr;
    ind.frameType = NWK_FRAME_TYPE_DATA;
    ind.radiusRemaining = 30;
    ind.wasBroadcast = 0;

    return ind;
}

static Nwk_DataConfirmParameters confirmAt(uint16_t dstAddr, Radio_Handle handle, uint8_t seq, ZbStatus status)
{
    Nwk_DataConfirmParameters confirm;

    Zb_memset(&confirm, 0, (uint32_t)sizeof confirm);
    confirm.dstAddr = dstAddr;
    confirm.handle = handle;
    confirm.seq = seq;
    confirm.status = status;
    confirm.attempts = 1;

    return confirm;
}

/* One entry of `apsDeviceKeyPairSet` as an application seeds it: the partner, the alias this
   stack's own addressing gives that partner, the attribute 4.4.1.1 step 1a-ii requires, the link key, both
   counters, and no peer capability recorded. */
static Security_KeyPairEntry pairAt(uint64_t partner, uint16_t alias, int aliasKnown)
{
    Security_KeyPairEntry entry;

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.deviceIeee = partner;
    entry.shortAddress = alias;
    entry.shortKnown = aliasKnown;
    entry.keyAttributes = SECURITY_KEYPAIR_ATTR_VERIFIED;
    entry.outgoingFrameCounter = 4;
    entry.incomingFrameCounter = 1;
    entry.linkKeyType = SECURITY_LINK_KEY_UNIQUE;
    entry.featuresCapabilities = SECURITY_FEATURES_NONE;
    entry.verifiedFrameCounter = 1;
    Zb_memcpy(entry.key, s_linkKey, SECURITY_KEY_OCTETS);

    return entry;
}

/* The `Security` the two crossing operations are asked against: the descriptor 4.4.1.1 step 3 borrows a level
   from and the pairs it actually reads. */
static void securityAt(Security *security, const Security_KeyPairEntry *pairs, uint32_t pairCount)
{
    Security_KeyDescriptor key;
    Security_Config cfg;

    Zb_memset(&key, 0, (uint32_t)sizeof key);
    key.keySeqNumber = 0x00;
    key.inUse = 1;
    key.outgoingFrameCounter = 1;
    Zb_memcpy(key.key, s_nwkKey, SECURITY_KEY_OCTETS);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = OWN_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.nwkActiveKeySeqNumber = 0x00;
    cfg.authenticated = 1;
    cfg.nwkAllFresh = 1;
    cfg.keys = &key;
    cfg.keyCount = 1;
    cfg.keyPairs = pairs;
    cfg.keyPairCount = pairCount;

    Test_ExpectStatus(Security_Init(security, &cfg), ZB_OK,
                 "the key material this suite asks the crossing against is seeded the only way `Security` takes it");
}

/* The layer `Aps_AckRespond` hands its answer down: `test/aps/`'s stack, one floor up from the module under
   test, with a neighbor seeded so a unicast aimed at it really reaches the air, the reason the three not-owed
   rows can be asserted as an empty air instead of as a refusal this case never gave the module a chance to make. */
static void rigAt(Loopback_Radio *model, Mac_Mac *mac, Nwk_Nwk *nwk)
{
    Radio_Radio *seam;
    Radio_Caps caps;
    Radio_Pib pib;
    Nwk_Config cfg;
    uint32_t i;

    Zb_memset(&caps, 0, (uint32_t)sizeof caps);
    caps.radioCaps = 0x10d;
    caps.hasTransmit = 1;
    caps.psduIncludesFcs = 1;
    caps.handlesAckTimeout = 1;

    LoopbackRadio_Init(model, &caps);
    seam = LoopbackRadio_Seam(model);

    Test_ExpectStatus(Mac_Init(mac, seam, 0), ZB_OK, "the module under test is given a layer below that has a backend");

    Zb_memset(&pib, 0, (uint32_t)sizeof pib);
    pib.present = RADIO_PIB_SHORT_ADDRESS | RADIO_PIB_PAN_ID | RADIO_PIB_CHANNEL | RADIO_PIB_RX_ON_WHEN_IDLE;
    pib.shortAddress = PEER_C;
    pib.panId = 0xbeef;
    pib.channel = 26;
    pib.rxOnWhenIdle = 1;

    Test_ExpectStatus(Mac_SetPib(mac, &pib), ZB_OK, "whose PIB mirror carries an address, so `nwk` is not refusing for want of one");

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.deviceType = NWK_DEVICE_ROUTER;

    Test_ExpectStatus(Nwk_Init(nwk, mac, &cfg), ZB_OK, "and the network layer adopts that MAC by pointer");

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (!nwk->neighbors[i].inUse)
            break;
    }

    Test_Expect(i < NWK_NEIGHBOR_MAX, "the neighbor table has room for the entry this case seeds");

    nwk->neighbors[i].inUse = 1;
    nwk->neighbors[i].networkAddress = PEER_A;
    nwk->neighbors[i].ieeeKnown = 0;
    nwk->neighbors[i].deviceType = NWK_DEVICE_ROUTER;
    nwk->neighbors[i].rxOnWhenIdle = 1;
    nwk->neighbors[i].relationship = NWK_REL_SIBLING;
}

static uint32_t airCount(Loopback_Radio *model)
{
    Loopback_Sent sent[LOOPBACK_TX_MAX];

    return LoopbackRadio_Sent(model, sent, LOOPBACK_TX_MAX);
}

static int scratchUntouched(const uint8_t *scratch, uint32_t len)
{
    uint32_t i;

    for (i = 0; i < len; i++)
    {
        if (scratch[i] != SENTINEL_OCTET)
            return 0;
    }

    return 1;
}

/* --- aps_group: the pair the table keys on ----------------------------------------------------- */

/*
 * 2.2.4.5.1.3 and 2.2.4.5.3.3 both judge "an entry for the given GroupAddress and Endpoint", and the pool is
 * flat: `inUse` is what makes a slot an entry, so a cleared slot that still carries the octets of a pair it
 * held is not one.
 */
static void caseGroupFindAnswersThePairAndNotAClearedSlotCarryingIt(void)
{
    clearGroups();

    seedGroup(0, GROUP_A, EP_ONE);
    seedGroup(1, GROUP_B, EP_TWO);

    s_groups[2].groupAddress = GROUP_A;
    s_groups[2].endpoint = EP_ONE;

    Test_Expect(Aps_GroupFind(s_groups, GROUP_A, EP_ONE) == &s_groups[0],
           "the pair the table holds is answered by its own slot, so a caller can act on it (2.2.4.5.1.3's lookup)");
    Test_Expect(Aps_GroupFind(s_groups, GROUP_B, EP_TWO) == &s_groups[1],
           "a second group's pair is found in its own slot, and a group id is no key on its own");
    Test_Expect(Aps_GroupFind(s_groups, GROUP_A, EP_TWO) == 0,
           "the group is held and this endpoint is not a member of it: the two parameters are judged together");
    Test_Expect(Aps_GroupFind(s_groups, GROUP_C, EP_ONE) == 0,
           "a group the table holds nothing of is a miss and not a hole");
    Test_Expect(Aps_GroupFind(s_groups, GROUP_A, EP_UNUSED) == 0,
           "the same group with an endpoint it does not carry is a miss too");
    Test_Expect(Aps_GroupFind(s_groups, 0x0000, EP_ONE) == 0,
           "and no address is refused for its value here: Table 2-14 prints GroupAddress as 0x0000-0xffff, so a lookup judges nothing about a group id");
}

/*
 * APSME-ADD-GROUP's two questions in the order 2.2.4.5.1.3 asks them: is this pair
 * already a membership, and is there a slot for it. The second is never asked for a
 * pair the table already holds, which is why a full pool can still answer SUCCESS, and
 * why nothing is evicted to make room (docs/internals/coding-rules.md §4.3, the full policy for
 * `apsGroupTable`, which Table 2-24 prints as "Variable" and 2.2.8.3.1 prints no size for).
 */
static void caseGroupAddAnswersIdempotenceBeforeItAnswersTableFull(void)
{
    uint32_t i;

    clearGroups();

    for (i = 0; i < APS_GROUP_MAX; i++)
        seedGroup(i, GROUP_A, (uint8_t)(EP_ONE + i));

    Test_Expect(Aps_GroupCount(s_groups) == APS_GROUP_MAX, "the pool is full");
    Test_Expect(Aps_GroupFree(s_groups) == 0, "and no slot is on offer");

    Test_Expect(Aps_GroupAdd(s_groups, GROUP_B, EP_THREE) == APS_STATUS_TABLE_FULL,
           "Table 2-15's status for a pool with no free entry, and no eviction of an entry this device holds");
    Test_Expect(Aps_GroupCount(s_groups) == APS_GROUP_MAX, "the refusal took nothing back out to make room");
    Test_Expect(s_groups[0].groupAddress == GROUP_A && s_groups[0].endpoint == EP_ONE
           && s_groups[APS_GROUP_MAX - 1].groupAddress == GROUP_A
           && s_groups[APS_GROUP_MAX - 1].endpoint == (uint8_t)(EP_ONE + APS_GROUP_MAX - 1),
           "and the pairs the table held are the pairs it still holds, in the slots they were in");

    Test_Expect(Aps_GroupAdd(s_groups, GROUP_A, (uint8_t)(EP_ONE + 4)) == APS_STATUS_SUCCESS,
           "2.2.4.5.1.3: 'the APSME does not alter the group table' and answers SUCCESS, the find runs before the free, so a repeat is idempotent even in a full pool");
    Test_Expect(Aps_GroupCount(s_groups) == APS_GROUP_MAX, "and a full pool that was asked for a pair it holds changes nothing");

    clearGroups();

    Test_Expect(Aps_GroupAdd(s_groups, GROUP_A, EP_ONE) == APS_STATUS_SUCCESS, "a pair a cleared pool is asked for lands");
    Test_Expect(s_groups[0].inUse == 1 && s_groups[0].groupAddress == GROUP_A && s_groups[0].endpoint == EP_ONE,
           "in the first free slot of the pool, which is the pool order 2.2.8.3.1 licenses");
    Test_Expect(Aps_GroupAdd(s_groups, GROUP_A, EP_ONE) == APS_STATUS_SUCCESS, "the same pair asked for again answers SUCCESS");
    Test_Expect(Aps_GroupCount(s_groups) == 1, "and it is one membership and not two: the table is untouched (2.2.4.5.1.3)");
    Test_Expect(Aps_GroupFind(s_groups, GROUP_A, EP_ONE) == &s_groups[0], "still in the slot it first landed in");

    Test_Expect(Aps_GroupAdd(s_groups, GROUP_B, EP_BROADCAST) == APS_STATUS_SUCCESS
           && Aps_GroupAdd(s_groups, GROUP_B, EP_ZDO) == APS_STATUS_SUCCESS,
           "the module judges no parameter range: Tables 2-14's 0x01-0xfe is the façade's door, and an endpoint out of it reaches the pool unchanged");
    Test_Expect(Aps_GroupCount(s_groups) == 3, "three memberships, each one pair");
}

/*
 * APSME-REMOVE-GROUP takes out one pair and not one group, because Table 2-25's entry is a Group ID with an
 * Endpoint List; 2.2.4.5.3.3 answers a pair the table does not hold with INVALID_GROUP and changes nothing.
 */
static void caseGroupRemoveClearsOnePairAndAnswersINVALID_GROUPForNone(void)
{
    Aps_Group before[APS_GROUP_MAX];

    clearGroups();

    seedGroup(0, GROUP_A, EP_ONE);
    seedGroup(1, GROUP_A, EP_TWO);
    seedGroup(2, GROUP_B, EP_ONE);

    Test_Expect(Aps_GroupRemove(s_groups, GROUP_A, EP_ONE) == APS_STATUS_SUCCESS,
           "the pair named is the pair removed (2.2.4.5.3.3)");
    Test_Expect(s_groups[0].inUse == 0 && s_groups[0].groupAddress == 0 && s_groups[0].endpoint == 0,
           "and its slot is cleared and not merely unlinked: a cleared slot carries no pair, which is what the lookup above refuses to read as one");
    Test_Expect(s_groups[1].inUse == 1 && s_groups[1].groupAddress == GROUP_A && s_groups[1].endpoint == EP_TWO,
           "the same group's other endpoint stays a member: one pair per APSME-REMOVE-GROUP.request, not one group");
    Test_Expect(s_groups[2].inUse == 1 && s_groups[2].groupAddress == GROUP_B && s_groups[2].endpoint == EP_ONE,
           "and another group is not this primitive's business at all");
    Test_Expect(Aps_GroupCount(s_groups) == 2, "the count says so");

    Zb_memcpy(before, s_groups, (uint32_t)sizeof before);

    Test_Expect(Aps_GroupRemove(s_groups, GROUP_A, EP_THREE) == APS_STATUS_INVALID_GROUP,
           "0xa5, Table 2-29's own words: an APSME-REMOVE-GROUP.request for a group identifier that does not appear in the group table");
    Test_Expect(Zb_memcmp(s_groups, before, (uint32_t)sizeof s_groups) == 0,
           "and the refusal frees nothing: no slot is cleared to answer a question the table cannot affirm");
    Test_Expect(Aps_GroupRemove(s_groups, GROUP_B, EP_ONE) == APS_STATUS_SUCCESS, "the pair that is there is still removable");
    Test_Expect(Aps_GroupRemove(s_groups, GROUP_B, EP_ONE) == APS_STATUS_INVALID_GROUP,
           "and the second ask for it is the miss, because the first removed it");

    s_groups[0].groupAddress = GROUP_C;
    s_groups[0].endpoint = EP_UNUSED;

    Test_Expect(Aps_GroupRemove(s_groups, GROUP_C, EP_UNUSED) == APS_STATUS_INVALID_GROUP,
           "a cleared slot carrying the octets of a pair is not a membership the remove can answer for");
    Test_Expect(Aps_GroupFree(s_groups) == &s_groups[0], "and the slot the first remove freed is on offer again");
}

/*
 * APSME-REMOVE-ALL-GROUPS: one endpoint out of every group it belongs to. 2.2.4.5.5.3 asks for the endpoint's
 * memberships and not for a match, and Table 2-19 prints SUCCESS or INVALID_PARAMETER for its confirm and
 * nothing else, so an endpoint that belonged to nothing is removed from nothing and still answers SUCCESS.
 */
static void caseGroupRemoveAllSweepsAnEndpointAndAnswersSUCCESSOnNoMembership(void)
{
    Aps_Group before[APS_GROUP_MAX];

    clearGroups();

    seedGroup(0, GROUP_A, EP_ONE);
    seedGroup(1, GROUP_A, EP_TWO);
    seedGroup(2, GROUP_B, EP_ONE);
    seedGroup(3, GROUP_C, EP_THREE);

    Test_Expect(Aps_GroupRemoveAll(s_groups, EP_ONE) == APS_STATUS_SUCCESS,
           "the endpoint's memberships are cleared across groups (2.2.4.5.5.3)");
    Test_Expect(s_groups[0].inUse == 0 && s_groups[2].inUse == 0,
           "one endpoint, every group it belonged to: this is the primitive that takes a device out of a group set, and the only one that does not name a group");
    Test_Expect(s_groups[1].inUse == 1 && s_groups[1].groupAddress == GROUP_A && s_groups[1].endpoint == EP_TWO
           && s_groups[3].inUse == 1 && s_groups[3].groupAddress == GROUP_C && s_groups[3].endpoint == EP_THREE,
           "and every other membership is exactly where it was");
    Test_Expect(Aps_GroupCount(s_groups) == 2, "two pairs left of four");

    Zb_memcpy(before, s_groups, (uint32_t)sizeof before);

    Test_Expect(Aps_GroupRemoveAll(s_groups, EP_UNUSED) == APS_STATUS_SUCCESS,
           "an endpoint that belonged to nothing answers SUCCESS: the clause asks for memberships and Table 2-19 prints no INVALID_GROUP for this service");
    Test_Expect(Zb_memcmp(s_groups, before, (uint32_t)sizeof s_groups) == 0,
           "and the sweep that matched nothing wrote nothing");
    Test_Expect(Aps_GroupCount(s_groups) == 2, "the count is the one the first sweep left");
}

/*
 * 2.2.8.4.2's fan-out: the members of one group, in the pool's own order, walked from an index, the shape the
 * façade loops over to hand one indication to each member. `APS_NO_GROUP_MEMBER` is the end of that loop and is
 * deliberately a value no pool index can be.
 */
static void caseGroupMemberAtWalksOneGroupInPoolOrderAndCountWalksHoles(void)
{
    uint32_t first;
    uint32_t second;

    clearGroups();

    seedGroup(2, GROUP_A, EP_ONE);
    seedGroup(5, GROUP_B, EP_ONE);
    seedGroup(9, GROUP_A, EP_TWO);

    s_groups[7].groupAddress = GROUP_A;
    s_groups[7].endpoint = EP_THREE;

    Test_Expect(APS_NO_GROUP_MEMBER == APS_GROUP_MAX,
           "the end of the walk is an index one past the pool, which no entry can ever be");

    first = Aps_GroupMemberAt(s_groups, GROUP_A, 0);
    Test_Expect(first == 2, "the first member of the group is the lowest live slot that carries its id");
    second = Aps_GroupMemberAt(s_groups, GROUP_A, first + 1);
    Test_Expect(second == 9, "and the walk skips the holes: the unused slot carrying this group's id is not a member");
    Test_Expect(Aps_GroupMemberAt(s_groups, GROUP_A, second + 1) == APS_NO_GROUP_MEMBER,
           "past the last member the answer is the sentinel, which is what ends the façade's fan-out (2.2.8.4.2)");
    Test_Expect(Aps_GroupMemberAt(s_groups, GROUP_B, 0) == 5
           && Aps_GroupMemberAt(s_groups, GROUP_B, 6) == APS_NO_GROUP_MEMBER,
           "another group's single member is walked the same way, and starting past it is the sentinel and not another group's slot");
    Test_Expect(Aps_GroupMemberAt(s_groups, GROUP_C, 0) == APS_NO_GROUP_MEMBER,
           "a group the table holds nothing of has no first member");

    Test_Expect(Aps_GroupCount(s_groups) == 3, "the count walks the same holes: three live pairs among 16 slots");

    Test_Expect(Aps_GroupRemove(s_groups, GROUP_A, EP_ONE) == APS_STATUS_SUCCESS, "free a pair in the middle of the pool");
    Test_Expect(Aps_GroupCount(s_groups) == 2, "and the count follows it, with the freed slot a hole between two live ones");
    Test_Expect(Aps_GroupMemberAt(s_groups, GROUP_A, 0) == 9, "the walk no longer sees it");
}

/* --- aps_dup: the record 2.2.8.4.2 prints ----------------------------------------------------- */

/*
 * One read, one write, in one act: a miss makes the record and says not-seen; a hit says seen and writes
 * nothing at all, not the record it hit, not its `seenMs`, not a new record beside it (pinned at façade level
 * in A2 and re-pinned here at the module that owns the table).
 */
static void caseDupSeenRecordsAMissAndAnswersSeenWithoutWritingAnything(void)
{
    Aps_Dup before[APS_DUP_MAX];

    clearDups();

    Test_Expect(Aps_DupSeen(s_dups, PEER_A, APS_COUNTER, 0, SEEN_MS) == 0,
           "a frame no record names is not a duplicate, and its record now exists (2.2.8.4.2)");
    Test_Expect(s_dups[0].inUse == 1 && s_dups[0].srcAddress == PEER_A && s_dups[0].apsCounter == APS_COUNTER
           && s_dups[0].seenMs == SEEN_MS,
           "the record is the printed three parts: source address, APS counter, timing information");

    Zb_memcpy(before, s_dups, (uint32_t)sizeof before);

    Test_Expect(Aps_DupSeen(s_dups, PEER_A, APS_COUNTER, 0, LATER_MS) == 1,
           "the repeat is a duplicate and is answered before the pool is written to");
    Test_Expect(Zb_memcmp(s_dups, before, (uint32_t)sizeof s_dups) == 0,
           "and a hit refreshes nothing: the record it hit keeps the arrival time that made it, no second record is made, and the pool is byte-identical");
    Test_Expect(Aps_DupSeen(s_dups, PEER_A, APS_COUNTER, 0, SEEN_MS + APS_DUP_LIFETIME_MS - 1) == 1,
           "a copy is a repeat until the last moment one can still arrive: the sender's last retry or a broadcast's last copy");
    Test_Expect(s_dups[1].inUse == 0, "and the hit did not reach for the free slot beside the record it found");
    Test_Expect(Aps_DupSeen(s_dups, PEER_A, APS_COUNTER, 0, SEEN_MS + APS_DUP_LIFETIME_MS) == 0,
           "past it the same counter is a new frame, as from a device whose counter started over: 2.2.8.4.2's timing information");
    Test_Expect(s_dups[0].seenMs == SEEN_MS + APS_DUP_LIFETIME_MS && s_dups[1].inUse == 0,
           "recorded in the expired record's place, with the time it arrived");

    clearDups();
    Test_Expect(Aps_DupSeen(s_dups, PEER_A, APS_COUNTER, 0, 0xffffff00) == 0, "a frame just before the clock wraps");
    Test_Expect(Aps_DupSeen(s_dups, PEER_A, APS_COUNTER, 0, 0x00000100) == 1,
           "and its copy just after it is still a repeat: the record's age is a difference on the clock");
}

/*
 * The full-pool policy, band A's and stated as such: replace-oldest, the record with the smallest `seenMs`
 * giving way, and a tie going to the earlier slot because that is the only ordering these records have. A
 * free slot is preferred to a recycle, which is what the body does first.
 */
static void caseDupFullPoolEvictsTheOldestRecordAndNotTheFirstInOrder(void)
{
    uint32_t i;

    clearDups();

    for (i = 0; i < APS_DUP_MAX; i++)
        seedDup(i, PEER_A, (uint8_t)(0x10 + i), 100 * (APS_DUP_MAX - i));

    Test_Expect(Aps_DupSeen(s_dups, PEER_B, 0x20, 0, 100 * (APS_DUP_MAX + 1)) == 0,
           "a full pool still records a frame it has never seen: refusing to record would make a later copy a new delivery");
    Test_Expect(s_dups[APS_DUP_MAX - 1].srcAddress == PEER_B && s_dups[APS_DUP_MAX - 1].apsCounter == 0x20
           && s_dups[APS_DUP_MAX - 1].seenMs == 100 * (APS_DUP_MAX + 1) && s_dups[APS_DUP_MAX - 1].inUse == 1,
           "the newcomer took the record with the smallest `seenMs`, which is the last slot of the pool: the eviction is the oldest record and not the first slot in order");
    Test_Expect(s_dups[0].srcAddress == PEER_A && s_dups[0].apsCounter == 0x10 && s_dups[0].seenMs == 100 * APS_DUP_MAX,
           "and the newest record survives it");
    Test_Expect(s_dups[1].seenMs == 100 * (APS_DUP_MAX - 1) && s_dups[APS_DUP_MAX - 2].seenMs == 200,
           "and every other record is untouched");

    clearDups();

    for (i = 0; i < APS_DUP_MAX; i++)
        seedDup(i, PEER_A, (uint8_t)(0x10 + i), (i == 2 || i == 4) ? 100 : 200 + i);

    Test_Expect(Aps_DupSeen(s_dups, PEER_C, 0x21, 0, 1000) == 0, "the pool is full and one more key arrives");
    Test_Expect(s_dups[2].srcAddress == PEER_C && s_dups[2].apsCounter == 0x21 && s_dups[2].seenMs == 1000,
           "a tie at one `seenMs` evicts the earlier slot of the pool, which is the only ordering these records have");
    Test_Expect(s_dups[4].srcAddress == PEER_A && s_dups[4].seenMs == 100, "and the other tied record stays");

    clearDups();

    for (i = 0; i < APS_DUP_MAX; i++)
    {
        if (i != 3)
            seedDup(i, PEER_A, (uint8_t)(0x10 + i), 100 + i);
    }

    Test_Expect(Aps_DupSeen(s_dups, PEER_B, 0x22, 0, 1000) == 0, "a pool with a hole records its newcomer in the hole");
    Test_Expect(s_dups[3].inUse == 1 && s_dups[3].srcAddress == PEER_B && s_dups[3].seenMs == 1000,
           "the free slot is taken before any live record is recycled, however old that record is");
    Test_Expect(s_dups[0].seenMs == 100, "and the oldest live record survives a pool that had room");
}

/*
 * The key is the source address and the APS counter together, and only those two: 2.2.8.4.2 names "source
 * address, APS counter, and timing information", and the third part decides the eviction and nothing else.
 */
static void caseDupKeyIsTheSourceAndTheCounterTogether(void)
{
    clearDups();

    Test_Expect(Aps_DupSeen(s_dups, PEER_A, 0x10, 0, SEEN_MS) == 0, "the first frame records");
    Test_Expect(Aps_DupSeen(s_dups, PEER_B, 0x10, 0, SEEN_MS) == 0,
           "the same APS counter from another source is another frame: a counter alone is not a key, and the APS header carries no device address for a third part to be keyed on");
    Test_Expect(Aps_DupSeen(s_dups, PEER_A, 0x11, 0, SEEN_MS) == 0,
           "the same source at the next counter is another frame again: 2.2.5.1.7's number is what distinguishes one transmission from the next");
    Test_Expect(s_dups[0].srcAddress == PEER_A && s_dups[0].apsCounter == 0x10
           && s_dups[1].srcAddress == PEER_B && s_dups[1].apsCounter == 0x10
           && s_dups[2].srcAddress == PEER_A && s_dups[2].apsCounter == 0x11,
           "three records, one per frame, in the order they arrived");
    Test_Expect(s_dups[3].inUse == 0, "and nothing was recorded twice");

    Test_Expect(Aps_DupSeen(s_dups, PEER_A, 0x10, 0, LATER_MS) == 1, "the first frame's repeat is seen");
    Test_Expect(Aps_DupSeen(s_dups, PEER_B, 0x11, 0, LATER_MS) == 0,
           "and the crossed pair (the other source at the other counter) is a fourth frame and not a repeat of either");
    Test_Expect(s_dups[3].srcAddress == PEER_B && s_dups[3].apsCounter == 0x11,
           "the source and the counter are matched together, so no slot holding one half of each is ever a hit");
}

/* --- aps_tx: the request as Table 2-2 reads it ----------------------------------------------- */

/*
 * The delivery mode is derived, not carried: 2.2.5.1.1.2 makes a broadcast a fact about the destination
 * address ("all devices defined for the selected broadcast address in use as defined in section 3.6.6"), so
 * the mode row of Table 2-2 says what kind of address `dstAddress` is and Table 3-80 says whether that address
 * names a group of devices. The class predicate is `nwk_addr`'s and is called, not copied.
 */
static void caseDeliveryModeIsTheModeTableAsCoded(void)
{
    Aps_ApsdeReq req;

    req = reqAt(APS_ADDR_MODE_GROUP, GROUP_A);
    Test_Expect(Aps_TxDeliveryMode(&req) == APS_DELIVERY_GROUP,
           "mode 0x01 is group delivery (Table 2-21's 0b11), whatever the group id's value is");

    req = reqAt(APS_ADDR_MODE_GROUP, APS_NWK_BROADCAST_GROUP_DEFAULT);
    Test_Expect(Aps_TxDeliveryMode(&req) == APS_DELIVERY_GROUP,
           "and the mode is read first: a group id that happens to be one of Table 3-80's classes is still a group id, because Table 2-14 prints GroupAddress as 0x0000-0xffff and no class rule reaches it");

    req = reqAt(APS_ADDR_MODE_SHORT, 0x1234);
    Test_Expect(Aps_TxDeliveryMode(&req) == APS_DELIVERY_UNICAST, "mode 0x02 at an ordinary device address is unicast");

    req = reqAt(APS_ADDR_MODE_SHORT, NWK_ADDR_LAST_UNICAST);
    Test_Expect(Aps_TxDeliveryMode(&req) == APS_DELIVERY_UNICAST,
           "0xfff7, the last address Table 3-75 says a device may hold, is the last unicast this derivation answers");

    req = reqAt(APS_ADDR_MODE_SHORT, NWK_ADDR_LOW_POWER_ROUTERS);
    Test_Expect(Aps_TxDeliveryMode(&req) == APS_DELIVERY_BROADCAST,
           "0xfffb is Table 3-80's class of low-power routers, so the delivery is broadcast (3.6.6)");

    req = reqAt(APS_ADDR_MODE_SHORT, APS_BROADCAST_ADDRESS_MIN);
    Test_Expect(Aps_TxDeliveryMode(&req) == APS_DELIVERY_BROADCAST, "0xfffc is a class, and so broadcast");

    req = reqAt(APS_ADDR_MODE_SHORT, APS_NWK_BROADCAST_GROUP_DEFAULT);
    Test_Expect(Aps_TxDeliveryMode(&req) == APS_DELIVERY_BROADCAST, "0xfffd, all routers and coordinators");

    req = reqAt(APS_ADDR_MODE_SHORT, NWK_ADDR_RESERVED);
    Test_Expect(Aps_TxDeliveryMode(&req) == APS_DELIVERY_UNICAST,
           "0xfffe is printed Reserved by Table 3-80 and so is not a class: this derivation calls it unicast and the refusal is one layer up, at the door's reserved check and at `nwk`'s own");

    req = reqAt(APS_ADDR_MODE_SHORT, NWK_ADDR_ALL_DEVICES);
    Test_Expect(Aps_TxDeliveryMode(&req) == APS_DELIVERY_BROADCAST, "0xffff is a class, and so broadcast");

    req = reqAt(APS_ADDR_MODE_SHORT, NWK_ADDR_RESERVED_LOW);
    Test_Expect(Aps_TxDeliveryMode(&req) == APS_DELIVERY_UNICAST,
           "the reserved band below the classes is judged nowhere in this module either: 0xfff8 arrives as a destination the derivation cannot call a broadcast");

    req = reqAt(APS_ADDR_MODE_NONE, NWK_ADDR_ALL_DEVICES);
    Test_Expect(Aps_TxDeliveryMode(&req) == APS_DELIVERY_BROADCAST,
           "mode 0x00 is not group addressing, so the address decides: this module never consults a binding table, which the façade answers NOT_SUPPORTED for");

    req = reqAt(APS_ADDR_MODE_NONE, 0x0000);
    Test_Expect(Aps_TxDeliveryMode(&req) == APS_DELIVERY_UNICAST, "and no address is a class by default");

    req = reqAt(APS_ADDR_MODE_EXTENDED, 0x0000);
    Test_Expect(Aps_TxDeliveryMode(&req) == APS_DELIVERY_UNICAST,
           "mode 0x03 is not group addressing either: the 64-bit destination plays no part in this derivation, which is the shape the address-map deferral answers at the door");
}

/*
 * The address the NWK layer is asked to reach, which for a group send is not the address the request named:
 * 2.2.4.1.1.3 puts the group id in the APS header and the `nwkBroadcastAddress` in the NLDE request, and
 * 2.2.8.4.1 prints 0xfffd as the one to employ when the request stated none.
 */
static void caseNwkDestinationCarriesAGroupSendOnTheClassItNames(void)
{
    Aps_ApsdeReq req;

    req = reqAt(APS_ADDR_MODE_GROUP, GROUP_A);
    Test_Expect(Aps_TxNwkDestination(&req) == APS_NWK_BROADCAST_GROUP_DEFAULT,
           "a group send with no broadcast stated rides 0xfffd (2.2.8.4.1), and the group id never rides the NWK header");
    Test_Expect(APS_NWK_BROADCAST_GROUP_DEFAULT == 0xfffd, "the default is the printed address and not a house number");

    req = reqAt(APS_ADDR_MODE_GROUP, GROUP_A);
    req.nwkBroadcastAddress = APS_BROADCAST_ADDRESS_MIN;
    Test_Expect(Aps_TxNwkDestination(&req) == APS_BROADCAST_ADDRESS_MIN,
           "a group send that states its class is aimed at that class (Table 2-2's nwkBroadcastAddress)");

    req = reqAt(APS_ADDR_MODE_GROUP, GROUP_A);
    req.nwkBroadcastAddress = NWK_ADDR_ALL_DEVICES;
    Test_Expect(Aps_TxNwkDestination(&req) == NWK_ADDR_ALL_DEVICES, "including 0xffff");

    req = reqAt(APS_ADDR_MODE_GROUP, GROUP_A);
    req.nwkBroadcastAddress = APS_BROADCAST_ADDRESS_MAX;
    Test_Expect(Aps_TxNwkDestination(&req) == APS_BROADCAST_ADDRESS_MAX,
           "and the parameter is copied unchanged once it is non-zero: the range 0xfffc-0xffff is the door's judgement, not this one");

    req = reqAt(APS_ADDR_MODE_SHORT, PEER_A);
    Test_Expect(Aps_TxNwkDestination(&req) == PEER_A, "mode 0x02 is aimed at the address the request named");

    req = reqAt(APS_ADDR_MODE_SHORT, NWK_ADDR_ALL_DEVICES);
    Test_Expect(Aps_TxNwkDestination(&req) == NWK_ADDR_ALL_DEVICES, "a broadcast's own destination is its class");

    req = reqAt(APS_ADDR_MODE_NONE, PEER_B);
    Test_Expect(Aps_TxNwkDestination(&req) == PEER_B, "mode 0x00 is no different here");

    req = reqAt(APS_ADDR_MODE_EXTENDED, PEER_C);
    req.dstExtendedAddress = PARTNER_IEEE;
    Test_Expect(Aps_TxNwkDestination(&req) == PEER_C,
           "and mode 0x03 returns the 16-bit half of its own request: this module has no address map to consult");

    Test_Expect((uint64_t)Aps_TxNwkDestination(&req) != req.dstExtendedAddress, "no 64-bit address becomes a NWK destination here");
}

/*
 * The octets one issue hands down as its NSDU: the protected frame for a secured slot (which is only ever the
 * scratch's contents once `Aps_TxProtect` has filled it) and the stored APDU for every other transaction of
 * this module. Both arms, and the length each reports.
 */
static void caseOutgoingOctetsIsTheScratchForASecuredSlotAndTheStoredApduOtherwise(void)
{
    Aps_Tx tx;
    Aps_ApsdeReq req;
    uint8_t scratch[APS_FRAME_MAX];
    const uint8_t *octets;
    uint32_t len;

    Zb_memset(&tx, 0, (uint32_t)sizeof tx);
    Zb_memset(scratch, SCRATCH_OCTET, (uint32_t)sizeof scratch);

    tx.state = APS_TX_AWAITING_NLDE;
    tx.deliveryMode = APS_DELIVERY_UNICAST;
    tx.ackRequested = 1;
    tx.apsSecurity = 0;
    tx.apsCounter = APS_COUNTER;

    req = reqAt(APS_ADDR_MODE_SHORT, PEER_A);
    req.asdu = s_asdu;
    req.asduLength = ASDU_LEN;

    Test_ExpectStatus(Aps_TxCompose(&tx, &req), ZB_OK,
                 "the slot's APDU is the codec's composition and nothing else's");
    Test_Expect(tx.apduLen == APS_HEADER_UNICAST_OCTETS + ASDU_LEN && tx.apduHeaderLen == APS_HEADER_UNICAST_OCTETS,
           "header octets plus ASDU, with the payload offset beside it: that offset is where 4.4.10 puts the auxiliary header");
    Test_Expect(tx.apdu[0] == (uint8_t)(APS_DELIVERY_UNICAST | 0x40),
           "FCF 0x40: data frame, unicast delivery, the acknowledgement asked for (Figure 2-4)");

    Aps_TxOutgoingOctets(&tx, scratch, &octets, &len);
    Test_Expect(octets == tx.apdu && len == tx.apduLen,
           "an unsecured slot hands down its stored APDU and its own length: the unsecured path, unchanged");
    Test_Expect(Zb_memcmp(octets, tx.apdu, len) == 0 && octets != scratch,
           "the octets are the slot's, and the caller's scratch is not what goes on the wire for this transaction");

    tx.apsSecurity = 1;
    tx.securedLen = 30;

    Aps_TxOutgoingOctets(&tx, scratch, &octets, &len);
    Test_Expect(octets == scratch && len == tx.securedLen,
           "a secured slot hands down the scratch and the length `Aps_TxProtect` recorded in it (4.4.1.1 with 2.2.4.1.1.3)");
    Test_Expect(octets != tx.apdu && len != tx.apduLen,
           "and it is not the stored APDU: the authenticated octets are the transaction's, the protected frame belongs to the attempt (the same arrangement one layer up)");
    Test_Expect(octets[0] == SCRATCH_OCTET, "the buffer it names, octet for octet");

    tx.securedLen = 22;

    Aps_TxOutgoingOctets(&tx, scratch, &octets, &len);
    Test_Expect(len == 22 && tx.apduLen == APS_HEADER_UNICAST_OCTETS + ASDU_LEN,
           "the length is read from the slot at the call, so a shorter protected frame reports 22 and the stored APDU still reports 14");
    Test_Expect(tx.apdu[0] == (uint8_t)(APS_DELIVERY_UNICAST | 0x40),
           "and choosing the scratch form writes nothing into the stored APDU: a retransmission re-protects the same octets (2.2.8.4.4)");
}

/*
 * Which transaction a NLDE confirmation belongs to (3.2.1.1.3, 3.6.4.3): the handle its last issue ran on is
 * the key, and a confirm whose handle names no waiting issue (a routed-out discard, a re-issued attempt, a held
 * frame) is paired by destination and NWK sequence number. Only a slot awaiting the NLDE answer is searched.
 */
static void caseSlotForConfirmPairsOnTheHandleAndFallsBackToTheDestination(void)
{
    Nwk_DataConfirmParameters confirm;

    clearTx();

    seedTx(0, APS_TX_AWAITING_NLDE, PEER_A, PEER_A, DST_EP, CLUSTER_ID, APS_COUNTER, 5);
    seedTx(1, APS_TX_AWAITING_ACK, PEER_B, PEER_B, DST_EP, CLUSTER_ID, 0x12, 6);
    seedTx(2, APS_TX_AWAITING_NLDE, PEER_B, PEER_B, DST_EP, CLUSTER_ID, 0x13, RADIO_HANDLE_NONE);
    seedTx(3, APS_TX_AWAITING_NLDE, PEER_B, PEER_B, DST_EP, CLUSTER_ID, 0x14, RADIO_HANDLE_NONE);
    seedTx(4, APS_TX_AWAITING_NLDE, PEER_C, PEER_C, DST_EP, CLUSTER_ID, 0x15, 7);
    s_tx[1].lastNwkSeq = 41;
    s_tx[2].lastNwkSeq = 41;
    s_tx[3].lastNwkSeq = 42;
    s_tx[4].lastNwkSeq = 43;

    confirm = confirmAt(PEER_A, 5, 40, ZB_OK);
    Test_Expect(Aps_TxSlotForConfirm(s_tx, &confirm) == &s_tx[0],
           "the handle the issue recorded is the pairing, exactly as `mac` pairs its completions and `nwk` its NLDE answers (the same lineage)");

    confirm = confirmAt(PEER_A, 5, 255, ZB_ERR_DEVICE);
    Test_Expect(Aps_TxSlotForConfirm(s_tx, &confirm) == &s_tx[0],
           "a matching handle needs no sequence number, and the status the confirmation carries is not part of the pairing");

    confirm = confirmAt(PEER_B, 6, 41, ZB_OK);
    Test_Expect(Aps_TxSlotForConfirm(s_tx, &confirm) == &s_tx[2],
           "a handle no waiting slot holds falls to the destination and sequence number: the slot holding that handle is awaiting an acknowledgement, a later answer than this one");

    confirm = confirmAt(PEER_B, RADIO_HANDLE_NONE, 42, ZB_ERR_NO_ROUTE);
    Test_Expect(Aps_TxSlotForConfirm(s_tx, &confirm) == &s_tx[3],
           "of two slots awaiting an answer for one device, the sequence number names the one this confirm is for, not pool order");

    confirm = confirmAt(PEER_C, 99, 43, ZB_OK);
    Test_Expect(Aps_TxSlotForConfirm(s_tx, &confirm) == &s_tx[4],
           "a handle this module never recorded still reaches its transaction by destination and sequence number");

    confirm = confirmAt(PEER_C, 99, 50, ZB_OK);
    Test_Expect(Aps_TxSlotForConfirm(s_tx, &confirm) == 0,
           "and with a sequence number no slot for that device holds, it reaches none");

    confirm = confirmAt(UNSEEN, 99, 44, ZB_OK);
    Test_Expect(Aps_TxSlotForConfirm(s_tx, &confirm) == 0,
           "and a confirmation no transaction of this module's owes is the one the caller counts as ignored");

    clearTx();
    seedTx(0, APS_TX_FREE, PEER_A, PEER_A, DST_EP, CLUSTER_ID, APS_COUNTER, 5);
    seedTx(1, APS_TX_AWAITING_ACK, PEER_B, PEER_B, DST_EP, CLUSTER_ID, APS_COUNTER, 7);

    confirm = confirmAt(PEER_A, 5, 45, ZB_OK);
    Test_Expect(Aps_TxSlotForConfirm(s_tx, &confirm) == 0,
           "a freed slot carrying the handle is not a transaction, and a slot awaiting an acknowledgement is not awaiting this one (2.2.8.4.4's window)");

    confirm = confirmAt(PEER_B, 7, 46, ZB_OK);
    Test_Expect(Aps_TxSlotForConfirm(s_tx, &confirm) == 0,
           "an answer to a transmission already acknowledged matches nothing: a transaction that is already answered is the unmatched confirmation it is");
}

/* The transaction pool's own shapes: a slot is free by its state and not by the octets it still carries, and
 * the occupied count is the number the door adds to the confirmation ring's depth before it refuses. */
static void caseTxFreeHandsTheFirstIdleSlotAndOccupiedCountsEveryHeldOne(void)
{
    uint32_t i;

    clearTx();

    Test_Expect(Aps_TxFree(s_tx) == &s_tx[0], "a cleared pool offers its first slot");
    Test_Expect(Aps_TxOccupied(s_tx) == 0, "and holds none");

    seedTx(0, APS_TX_AWAITING_NLDE, PEER_A, PEER_A, DST_EP, CLUSTER_ID, APS_COUNTER, 1);
    seedTx(2, APS_TX_AWAITING_ACK, PEER_B, PEER_B, DST_EP, CLUSTER_ID, APS_COUNTER, 2);
    seedTx(5, APS_TX_AWAITING_NLDE, PEER_C, PEER_C, DST_EP, CLUSTER_ID, APS_COUNTER, RADIO_HANDLE_NONE);

    Test_Expect(Aps_TxFree(s_tx) == &s_tx[1], "the next free slot is the first one in pool order, not the last");
    Test_Expect(Aps_TxOccupied(s_tx) == 3, "and the count is of states, one for each of the two living ones");

    s_tx[1].apsCounter = APS_COUNTER;

    Test_Expect(Aps_TxFree(s_tx) == &s_tx[1],
           "a slot whose state says free is free whatever octets the transaction it held left behind: the state is the key (`Aps_TxState`)");

    for (i = 0; i < APS_TX_MAX; i++)
        seedTx(i, APS_TX_AWAITING_NLDE, PEER_A, PEER_A, DST_EP, CLUSTER_ID, APS_COUNTER, (Radio_Handle)(1 + i));

    Test_Expect(Aps_TxFree(s_tx) == 0, "a full pool offers nothing and evicts nothing to make room (§4.3)");
    Test_Expect(Aps_TxOccupied(s_tx) == APS_TX_MAX, "and the count says so, which is the number the door checks against the ring");

    Zb_memset(&s_tx[3], 0, (uint32_t)sizeof s_tx[3]);

    Test_Expect(Aps_TxFree(s_tx) == &s_tx[3] && Aps_TxOccupied(s_tx) == APS_TX_MAX - 1,
           "one released slot is enough to take the next transaction back");
}

/*
 * 4.4.1.1 step 1's selection read against a set keyed by Table 4-36's DeviceAddress:
 * mode 0x03 names the 64-bit address outright, mode 0x02 names the alias an application gave that partner,
 * and nothing names an entry that carries no alias.
 */
static void caseResolveKeyPairNamesTheEntryTheDestinationIs(void)
{
    Security security;
    Security aliasless;
    Security_KeyPairEntry pairs[1];
    Aps_ApsdeReq req;

    pairs[0] = pairAt(PARTNER_IEEE, PEER_A, 1);
    securityAt(&security, pairs, 1);

    pairs[0] = pairAt(PARTNER_IEEE, PEER_A, 0);
    securityAt(&aliasless, pairs, 1);

    req = reqAt(APS_ADDR_MODE_SHORT, PEER_A);
    Test_Expect(Aps_TxResolveKeyPair(&security, &req) == 0,
           "the 16-bit destination is matched by the alias the entry carries: the filler for the gap 4.4.1.1 leaves open");

    req = reqAt(APS_ADDR_MODE_EXTENDED, 0x0000);
    req.dstExtendedAddress = PARTNER_IEEE;
    Test_Expect(Aps_TxResolveKeyPair(&security, &req) == 0,
           "mode 0x03's leg is 4.4.1.1 step 1a-i read directly against DeviceAddress, reachable here because the module is asked and not the door");

    req = reqAt(APS_ADDR_MODE_EXTENDED, 0x0000);
    req.dstExtendedAddress = FOREIGN_IEEE;
    Test_Expect(Aps_TxResolveKeyPair(&security, &req) == -1,
           "a partner no entry is shared with answers the negative, which the door reports as NO_SHORT_ADDRESS 0xa9");

    req = reqAt(APS_ADDR_MODE_SHORT, UNSEEN);
    Test_Expect(Aps_TxResolveKeyPair(&security, &req) == -1, "an address no alias names answers the same negative");

    req = reqAt(APS_ADDR_MODE_SHORT, 0x0000);
    Test_Expect(Aps_TxResolveKeyPair(&security, &req) == -1,
           "and address 0x0000 is not an alias of anything: an unset entry names no short address, 0x0000 included");

    req = reqAt(APS_ADDR_MODE_SHORT, PEER_A);
    Test_Expect(Aps_TxResolveKeyPair(&aliasless, &req) == -1,
           "an entry with the right DeviceAddress and no recorded alias is no help to a 16-bit destination: the alias is the application's to supply");

    Test_Expect(Aps_TxResolveKeyPair(&aliasless, &req) == -1,
           "and a module with no provider attached answers the same negative the resolution answers for no entry: the refusal is one step earlier because there is nothing to ask (4.4.1.1 step 1)");

    Test_Expect(Aps_TxResolveKeyPair(0, &req) == -1,
           "with no `Security` attached at all there is no pool to search, and the answer is the same negative");

    Test_Expect(Security_KeyPairCount(&security) == 1 && Security_KeyPairAt(&security, 0) != 0,
           "the index the resolution returns names an entry the caller can read (Table 2-4's KeyIndex)");
}

/* --- aps_ack: the match, and the answer owed ------------------------------------------------- */

/*
 * The four parts 2.2.8.4.4 prints, in the order it prints them (cluster identifier, APS counter, and a source
 * endpoint equal to the destination endpoint the original frame went to) plus band A's guard that the frame
 * came from the device the transaction was aimed at. Only a slot awaiting an acknowledgement is searched, in
 * pool order. The profile identifier is deliberately not compared.
 */
static void caseAckSlotMatchesThePrintedPartsAndBandsAcksGuard(void)
{
    Nwk_DataIndicationParameters ind;
    Aps_Frame frame;

    clearTx();

    seedTx(0, APS_TX_AWAITING_ACK, PEER_A, PEER_A, DST_EP, CLUSTER_ID, APS_COUNTER, 3);
    seedTx(1, APS_TX_AWAITING_NLDE, PEER_B, PEER_B, DST_EP, CLUSTER_ID, APS_COUNTER, 4);

    ind = indicationAt(PEER_A, PEER_C);
    frame = ackFrameAt(0, APS_DELIVERY_UNICAST, CLUSTER_ID, APS_COUNTER, DST_EP);

    Test_Expect(Aps_AckSlotForAck(s_tx, &ind, &frame) == &s_tx[0],
           "cluster, counter, source endpoint and (band A's own guard) the NWK source the transaction was aimed at (2.2.8.4.4 with 2.2.8.4.3.2)");

    frame = ackFrameAt(0, APS_DELIVERY_UNICAST, CLUSTER_ID, (uint8_t)(APS_COUNTER + 1), DST_EP);
    Test_Expect(Aps_AckSlotForAck(s_tx, &ind, &frame) == 0, "a counter one off is not this transaction's answer");

    frame = ackFrameAt(0, APS_DELIVERY_UNICAST, (uint16_t)(CLUSTER_ID + 1), APS_COUNTER, DST_EP);
    Test_Expect(Aps_AckSlotForAck(s_tx, &ind, &frame) == 0, "another cluster is not this transaction's answer");

    frame = ackFrameAt(0, APS_DELIVERY_UNICAST, CLUSTER_ID, APS_COUNTER, SRC_EP);
    Test_Expect(Aps_AckSlotForAck(s_tx, &ind, &frame) == 0,
           "a source endpoint that is not the destination endpoint the original frame went to is not an answer to it (2.2.8.4.4's own wording)");

    ind = indicationAt(UNSEEN, PEER_C);
    frame = ackFrameAt(0, APS_DELIVERY_UNICAST, CLUSTER_ID, APS_COUNTER, DST_EP);
    Test_Expect(Aps_AckSlotForAck(s_tx, &ind, &frame) == 0,
           "a perfect acknowledgement from a device this transaction was not aimed at matches nothing: the guard, which 2.2.8.4.4 does not print");

    ind = indicationAt(PEER_A, PEER_C);

    frame = ackFrameAt(0, APS_DELIVERY_UNICAST, CLUSTER_ID, APS_COUNTER, DST_EP);
    frame.clusterPresent = 0;
    Test_Expect(Aps_AckSlotForAck(s_tx, &ind, &frame) == 0,
           "an ACK format 1 acknowledgement carries no cluster identifier at all (2.2.5.1.1.3) and answers no data transaction");

    frame = ackFrameAt(0, APS_DELIVERY_UNICAST, CLUSTER_ID, APS_COUNTER, DST_EP);
    frame.srcEndpointPresent = 0;
    Test_Expect(Aps_AckSlotForAck(s_tx, &ind, &frame) == 0, "and the same shape with no source endpoint to compare");

    frame = ackFrameAt(0, APS_DELIVERY_UNICAST, CLUSTER_ID, APS_COUNTER, DST_EP);
    frame.profileId = (uint16_t)(PROFILE_ID + 1);
    Test_Expect(Aps_AckSlotForAck(s_tx, &ind, &frame) == &s_tx[0],
           "the profile identifier is not compared: 2.2.5.2.3.1 requires an acknowledgement to repeat it and 2.2.8.4.4 does not include it in what a receiver matches on");

    s_tx[0].state = APS_TX_AWAITING_NLDE;
    frame = ackFrameAt(0, APS_DELIVERY_UNICAST, CLUSTER_ID, APS_COUNTER, DST_EP);
    Test_Expect(Aps_AckSlotForAck(s_tx, &ind, &frame) == 0,
           "a slot still awaiting the NLDE answer is not awaiting this one: an acknowledgement inside that window answers the previous transmission of the same number");

    s_tx[0].state = APS_TX_FREE;
    seedTx(1, APS_TX_AWAITING_ACK, PEER_B, PEER_B, DST_EP, CLUSTER_ID, APS_COUNTER, 4);
    frame = ackFrameAt(0, APS_DELIVERY_UNICAST, CLUSTER_ID, APS_COUNTER, DST_EP);
    Test_Expect(Aps_AckSlotForAck(s_tx, &ind, &frame) == 0,
           "and the guard is a guard: a slot aimed at another device is not matched by this frame's arrival, whichever slot the pool order would have offered first");
}

/*
 * The three rows that say no answer was owed, each answered before the layer below is asked anything: the AR
 * sub-field clear (2.2.5.1.1.5 forbids an answer), a delivery that is not a unicast (the same clause), and a
 * frame whose Status is not SUCCESS (2.2.5.1.1.5's "determining that the frame is valid"). The rig has a route
 * to the frame's source, so a gate that fell through would put a frame on the air and be seen.
 */
static void caseAckRespondAnswersItsThreeNotOwedRowsBeforeTheNetwork(void)
{
    Loopback_Radio model;
    Mac_Mac mac;
    Nwk_Nwk nwk;
    Nwk_DataIndicationParameters ind;
    Aps_Frame frame;
    uint8_t scratch[APS_FRAME_MAX];
    Aps_AckOutcome outcome;

    rigAt(&model, &mac, &nwk);

    ind = indicationAt(PEER_A, PEER_C);

    Zb_memset(scratch, SENTINEL_OCTET, (uint32_t)sizeof scratch);
    frame = ackFrameAt(0, APS_DELIVERY_UNICAST, CLUSTER_ID, APS_COUNTER, SRC_EP);
    outcome = Aps_AckRespond(&ind, &frame, APS_STATUS_SUCCESS, &nwk, scratch, (uint32_t)sizeof scratch, 100);
    Test_Expect(outcome == APS_ACK_NOT_REQUESTED,
           "2.2.5.1.1.5: an AR sub-field of 0 means no answer is owed, and this is the module's word for that and not a counter");
    Test_Expect(airCount(&model) == 0 && Nwk_TransmitQueue(&nwk) == 0 && Nwk_RefusedRequests(&nwk) == 0,
           "nothing was issued and nothing was asked for: the row is answered before the network is touched");
    Test_Expect(scratchUntouched(scratch, (uint32_t)sizeof scratch), "and no octet was composed into the caller's buffer");

    Zb_memset(scratch, SENTINEL_OCTET, (uint32_t)sizeof scratch);
    frame = ackFrameAt(1, APS_DELIVERY_GROUP, CLUSTER_ID, APS_COUNTER, SRC_EP);
    outcome = Aps_AckRespond(&ind, &frame, APS_STATUS_SUCCESS, &nwk, scratch, (uint32_t)sizeof scratch, 100);
    Test_Expect(outcome == APS_ACK_NOT_UNICAST,
           "an ask on a group delivery is refused by the same clause: 'This sub-field SHALL be set to 0 for all frames that are broadcast or multicast'");

    Zb_memset(scratch, SENTINEL_OCTET, (uint32_t)sizeof scratch);
    frame = ackFrameAt(1, APS_DELIVERY_BROADCAST, CLUSTER_ID, APS_COUNTER, SRC_EP);
    outcome = Aps_AckRespond(&ind, &frame, APS_STATUS_SUCCESS, &nwk, scratch, (uint32_t)sizeof scratch, 100);
    Test_Expect(outcome == APS_ACK_NOT_UNICAST, "and so is one on a broadcast");
    Test_Expect(airCount(&model) == 0 && Nwk_TransmitQueue(&nwk) == 0 && scratchUntouched(scratch, (uint32_t)sizeof scratch),
           "two rows, both answered before the codec was reached");

    Zb_memset(scratch, SENTINEL_OCTET, (uint32_t)sizeof scratch);
    frame = ackFrameAt(1, APS_DELIVERY_UNICAST, CLUSTER_ID, APS_COUNTER, SRC_EP);
    outcome = Aps_AckRespond(&ind, &frame, APS_STATUS_SECURITY_FAIL, &nwk, scratch,
                             (uint32_t)sizeof scratch, 100);
    Test_Expect(outcome == APS_ACK_NOT_ACCEPTED,
           "a frame this device did not judge valid owes nothing: the Status the frame carries at this moment is the one word that says it (2.2.5.1.1.5, 2.2.8.4.3.2)");
    Test_Expect(airCount(&model) == 0 && Nwk_TransmitQueue(&nwk) == 0 && Nwk_RefusedRequests(&nwk) == 0
           && scratchUntouched(scratch, (uint32_t)sizeof scratch),
           "and the refusal is decided before the composition and before the issue, which is the order the security gate sits in");

    Zb_memset(scratch, SENTINEL_OCTET, (uint32_t)sizeof scratch);
    frame = ackFrameAt(1, APS_DELIVERY_UNICAST, CLUSTER_ID, APS_COUNTER, SRC_EP);
    outcome = Aps_AckRespond(&ind, &frame, APS_STATUS_SUCCESS, &nwk, scratch, (uint32_t)sizeof scratch, 100);
    Test_Expect(outcome == APS_ACK_RESPONDED,
           "and the same rig with all three gates passed does put the answer on the air: the reason the three empty airs above are a proof and not an accident");
    Test_Expect(airCount(&model) == 1 && Nwk_TransmitQueue(&nwk) == 1, "one frame, aimed at the indication's source");
    Test_Expect(scratch[0] == APS_ACK_FCF,
           "composed as an acknowledgement frame: frame type 0b10 with ACK format 0, no security, no AR and no extended header (Figure 2-9 with 2.2.8.4.3)");
}

/* The sentences a descriptor's semantics rest on: 4.4.2.3 makes only the octet 1 true, 4.4.11.1.4.1's TLV is a tag and
 * a length that fill the tail, and a body that fails either leaves the caller's struct untouched rather than half
 * written. */
static void caseTransportKeyFieldRules(void)
{
    static const char *keyHex = "00112233445566778899aabbccddeeff";
    static const uint8_t badTlv[4] = { 0x00, 0x05, 0x01, 0x02 };   /* a length of five with two octets behind it */
    static const uint8_t shortTlv[1] = { 0x00 };                  /* a tag with no length */
    Aps_TransportKey tk;
    Aps_TransportKey read;
    uint8_t body[64];
    uint8_t before[64];
    uint8_t sentinel[sizeof(Aps_TransportKey)];
    uint32_t len = 0;

    Zb_memset(&tk, 0, (uint32_t)sizeof tk);
    Test_ParseHex(keyHex, tk.key, APS_TK_KEY_OCTETS);
    tk.standardKeyType = APS_TK_TYPE_APPLICATION_LINK_KEY;

    tk.initiator = 7;
    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_ERR_BAD_ARGUMENT,
                      "an initiator of 7 is refused: 4.4.11.1.3.3 gives the flag two values, and a third is a caller bug this module will not quietly round");

    tk.initiator = 0;
    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_OK, "one good body");
    body[APS_TK_TYPE_OCTETS + APS_TK_KEY_OCTETS + APS_TK_IEEE_OCTETS] = 0x02;

    Test_ExpectStatus(Aps_TransportKeyParse(body, len, &read), ZB_OK, "an initiator octet of 2 parses");
    Test_ExpectCount((uint32_t)read.initiator, 0,
                     "and is not true: 4.4.2.3 makes the Initiator parameter TRUE only when the field is 1, and 0 otherwise");

    tk.tlvs = badTlv;
    tk.tlvLen = (uint32_t)sizeof badTlv;
    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_ERR_BAD_ARGUMENT,
                      "a TLV whose length runs past the tail is refused when written");
    tk.tlvs = shortTlv;
    tk.tlvLen = (uint32_t)sizeof shortTlv;
    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_ERR_BAD_ARGUMENT,
                      "and so is a tag with no length behind it");

    tk.tlvs = badTlv;
    tk.tlvLen = (uint32_t)sizeof badTlv;
    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_ERR_BAD_ARGUMENT,
                      "both refusals leaving the buffer as it was");

    tk.tlvs = 0;
    tk.tlvLen = 0xffffffff;
    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_ERR_BAD_ARGUMENT,
                      "and a length with no buffer behind it, before any arithmetic adds the two together");

    tk.tlvLen = 0;
    tk.standardKeyType = APS_TK_TYPE_NETWORK_KEY;
    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_OK, "a network key body");
    Zb_memcpy(before, body, len);
    Zb_memset(&read, 0x5a, (uint32_t)sizeof read);
    Zb_memcpy(sentinel, &read, (uint32_t)sizeof sentinel);

    Test_ExpectStatus(Aps_TransportKeyParse(before, len - 1, &read), ZB_ERR_BAD_ARGUMENT,
                      "a body one octet short is refused");
    Test_ExpectOctets("and the caller's struct is untouched by the refusal", (const uint8_t *)&read,
                      (uint32_t)sizeof read, sentinel, (uint32_t)sizeof sentinel);
}

/* 4.4.11.1's three descriptors, each written and read back in its own figure's octet count: the network key is the one
 * the milestone exists for, Table 4-9's 0x01 with a sequence number and the two addresses that say who should use it
 * and who sent it. */
static void caseTransportKeyNetworkDescriptor(void)
{
    static const char *keyHex = "5a6967426565416c6c69616e63653039";
    Aps_TransportKey tk;
    Aps_TransportKey read;
    uint8_t body[APS_TK_NETWORK_BODY_OCTETS + 8];
    uint32_t len = 0;

    Zb_memset(&tk, 0, (uint32_t)sizeof tk);
    tk.standardKeyType = APS_TK_TYPE_NETWORK_KEY;
    Test_ParseHex(keyHex, tk.key, APS_TK_KEY_OCTETS);
    tk.keySeqNumber = 0x2a;
    tk.destinationIeee = 0x00212effff048a12;
    tk.sourceIeee = 0x00212effff05a888;

    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_OK,
                      "a network key descriptor is written");
    Test_ExpectCount(len, APS_TK_NETWORK_BODY_OCTETS,
                     "in Figure 4-8's type octet and Figure 4-10's 33: 16 of key, one of sequence number, two 8-octet addresses");
    Test_ExpectCount(body[0], APS_TK_TYPE_NETWORK_KEY, "the type octet first, which is 4.4.11.1.2's field order");
    Test_ExpectOctets("then the key", body + 1, APS_TK_KEY_OCTETS, tk.key, APS_TK_KEY_OCTETS);
    Test_ExpectCount(body[17], 0x2a, "and its sequence number straight after it");

    Test_ExpectOctets("then the destination address low octet first, the order every 64-bit address in this stack is written in on the air",
                      body + 18, 8, (const uint8_t *)"\x12\x8a\x04\xff\xff\x2e\x21\x00", 8);
    Test_ExpectOctets("and the source address after it",
                      body + 26, 8, (const uint8_t *)"\x88\xa8\x05\xff\xff\x2e\x21\x00", 8);

    Test_ExpectStatus(Aps_TransportKeyParse(body, len, &read), ZB_OK, "and it reads back");
    Test_ExpectCount(read.standardKeyType, APS_TK_TYPE_NETWORK_KEY, "as a network key");
    Test_ExpectCount(read.keySeqNumber, 0x2a, "with its sequence number");
    Test_Expect(read.destinationIeee == tk.destinationIeee && read.sourceIeee == tk.sourceIeee,
                "and both addresses as they went in");
    Test_ExpectOctets("and the key octet for octet", read.key, APS_TK_KEY_OCTETS, tk.key, APS_TK_KEY_OCTETS);
    Test_ExpectCount(read.tlvLen, 0, "with no TLV sub-field, which Figure 4-10 does not print");
}

/* The two forms that end in TLVs, and the network form that may not: 4.4.11.1.4's contents are carried, not read. */
static void caseTransportKeyLinkDescriptors(void)
{
    static const char *keyHex = "00112233445566778899aabbccddeeff";
    static const uint8_t tlv[3] = { 0x00, 0x01, 0x01 };   /* Table 4-32's local tag, its length, its one-octet value */
    Aps_TransportKey tk;
    Aps_TransportKey read;
    uint8_t body[64];
    uint32_t len = 0;

    Zb_memset(&tk, 0, (uint32_t)sizeof tk);
    tk.standardKeyType = APS_TK_TYPE_TC_LINK_KEY;
    Test_ParseHex(keyHex, tk.key, APS_TK_KEY_OCTETS);
    tk.destinationIeee = 0x0011223344556677;
    tk.sourceIeee = 0xffffffffffffffff;
    tk.tlvs = tlv;
    tk.tlvLen = (uint32_t)sizeof tlv;

    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_OK,
                      "a trust center link key descriptor is written");
    Test_ExpectCount(len, APS_TK_TC_LINK_BODY_OCTETS + (uint32_t)sizeof tlv,
                     "in Figure 4-9's 32 octets and its TLVs after them");
    Test_ExpectStatus(Aps_TransportKeyParse(body, len, &read), ZB_OK, "and reads back");
    Test_ExpectCount(read.tlvLen, (uint32_t)sizeof tlv, "with the TLVs carried verbatim");
    Test_ExpectOctets("octet for octet", read.tlvs, read.tlvLen, tlv, (uint32_t)sizeof tlv);
    Test_Expect(read.sourceIeee == 0xffffffffffffffff,
                "and the all-F source address of a distributed security network surviving the round trip (4.4.11.1.3.2)");

    tk.standardKeyType = APS_TK_TYPE_APPLICATION_LINK_KEY;
    tk.partnerIeee = 0x00212effff048a12;
    tk.initiator = 1;

    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_OK,
                      "an application link key descriptor is written");
    Test_ExpectCount(len, APS_TK_APP_LINK_BODY_OCTETS + (uint32_t)sizeof tlv,
                     "in Figure 4-11's 25 octets, the initiator flag included, and its TLVs");
    Test_ExpectStatus(Aps_TransportKeyParse(body, len, &read), ZB_OK, "and reads back");
    Test_Expect(read.partnerIeee == tk.partnerIeee && read.initiator == 1,
                "with the partner address and the initiator flag");

    tk.tlvs = 0;
    tk.tlvLen = 0;
    tk.standardKeyType = APS_TK_TYPE_NETWORK_KEY;

    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_OK,
                      "while a network key descriptor without TLVs is the ordinary case");

    tk.tlvs = tlv;
    tk.tlvLen = (uint32_t)sizeof tlv;

    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_ERR_BAD_ARGUMENT,
                      "and one with them is refused: Figure 4-10 prints no TLV sub-field for a network key");
}

/* What the two functions refuse, and that a refusal writes nothing. */
static void caseTransportKeyRefusals(void)
{
    static const char *keyHex = "00112233445566778899aabbccddeeff";
    Aps_TransportKey tk;
    Aps_TransportKey read;
    uint8_t body[64];
    uint8_t shortBody[20];
    uint8_t sentinel[64];
    uint32_t len = 0;

    Zb_memset(&tk, 0, (uint32_t)sizeof tk);
    Test_ParseHex(keyHex, tk.key, APS_TK_KEY_OCTETS);

    Zb_memset(sentinel, 0xa5, (uint32_t)sizeof sentinel);
    Zb_memcpy(body, sentinel, (uint32_t)sizeof body);

    tk.standardKeyType = 0x02;
    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_ERR_BAD_ARGUMENT,
                      "StandardKeyType 0x02 is refused: Table 4-9 reserves it, whatever 4.4.11.1.3.3 says about key types 2 and 3");
    tk.standardKeyType = 0x00;
    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_ERR_BAD_ARGUMENT,
                      "and so is 0x00, which Table 4-9 does not print");
    tk.standardKeyType = APS_TK_TYPE_NETWORK_KEY;
    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, APS_TK_NETWORK_BODY_OCTETS - 1, &len), ZB_ERR_NO_SPACE,
                      "a buffer one octet short is refused rather than filled part way");
    Test_ExpectOctets("and nothing was written into it", body, APS_TK_NETWORK_BODY_OCTETS, sentinel,
                      APS_TK_NETWORK_BODY_OCTETS);

    Test_ExpectStatus(Aps_TransportKeyCompose(0, body, (uint32_t)sizeof body, &len), ZB_ERR_BAD_ARGUMENT,
                      "no descriptor is an argument error");

    Zb_memset(shortBody, 0, (uint32_t)sizeof shortBody);
    shortBody[0] = APS_TK_TYPE_NETWORK_KEY;
    Test_ExpectStatus(Aps_TransportKeyParse(shortBody, APS_TK_NETWORK_BODY_OCTETS - 1, &read), ZB_ERR_BAD_ARGUMENT,
                      "a network key body one octet short of Figure 4-10 is refused, not truncated");
    Test_ExpectStatus(Aps_TransportKeyParse(shortBody, 0, &read), ZB_ERR_BAD_ARGUMENT,
                      "an empty body has no type to read");

    Zb_memset(shortBody, 0, (uint32_t)sizeof shortBody);
    shortBody[0] = 0x05;
    Test_ExpectStatus(Aps_TransportKeyParse(shortBody, (uint32_t)sizeof shortBody, &read), ZB_ERR_BAD_ARGUMENT,
                      "and a reserved type is refused before any length is trusted");

    Test_ExpectStatus(Aps_TransportKeyCompose(&tk, body, (uint32_t)sizeof body, &len), ZB_OK, "one good body");
    body[len] = 0x00;
    body[len + 1] = 0x01;
    body[len + 2] = 0x01;

    Test_ExpectStatus(Aps_TransportKeyParse(body, len + 3, &read), ZB_ERR_BAD_ARGUMENT,
                      "and a network key body followed by a well-formed TLV is refused: Figure 4-10 prints no TLV sub-field, so the refusal is the figure's and not the TLV run's");
}

/* Figure 4-13 written out by hand, both ways, with and without 4.4.11.2.5's JoinerTLVs, and what Table 4-14's ranges
   refuse on the way out. */
static void caseUpdateDeviceBody(void)
{
    static const uint8_t want[12] = { 0x06, 0x12, 0x8a, 0x04, 0xff, 0xff, 0x2e, 0x21, 0x00, 0x34, 0x12, 0x01 };
    static const uint8_t tlv[4] = { 0x42, 0x01, 0xaa, 0xbb };   /* a tag, its length minus one, two octets */
    Aps_UpdateDevice in;
    Aps_UpdateDevice read;
    uint8_t out[32];
    uint32_t len = 0;

    Zb_memset(&in, 0, (uint32_t)sizeof in);
    in.deviceIeee = 0x00212effff048a12;
    in.deviceShortAddress = 0x1234;
    in.status = APS_UPDATE_DEVICE_UNSECURED_JOIN;

    Test_ExpectStatus(Aps_UpdateDeviceCompose(&in, out, (uint32_t)sizeof out, &len), ZB_OK,
                      "an Update Device for an unsecured join is written");
    Test_ExpectOctets("as Figure 4-13 prints it: the identifier Table 4-31 gives 0x06, the device's 64-bit address and its short address low octet first (1.2.3), then 4.4.11.2.4's status",
                      out, len, want, (uint32_t)sizeof want);

    Test_ExpectStatus(Aps_UpdateDeviceParse(out + 1, len - 1, &read), ZB_OK, "and its body reads back");
    Test_Expect(read.deviceIeee == in.deviceIeee && read.deviceShortAddress == 0x1234
                    && read.status == APS_UPDATE_DEVICE_UNSECURED_JOIN,
                "with the address, the short address and the status as they went in");
    Test_Expect(read.joinerTlvs == 0 && read.joinerTlvLen == 0,
                "and no JoinerTLVs, which 4.4.11.2.5 makes absent where the joiner or its parent predates R23");

    in.joinerTlvs = tlv;
    in.joinerTlvLen = (uint32_t)sizeof tlv;

    Test_ExpectStatus(Aps_UpdateDeviceCompose(&in, out, (uint32_t)sizeof out, &len), ZB_OK,
                      "an Update Device carrying JoinerTLVs is written");
    Test_ExpectCount(len, (uint32_t)sizeof want + (uint32_t)sizeof tlv,
                     "the TLVs appended after the status, which 4.4.3.1.3 places at the end of the frame");
    Test_ExpectOctets("verbatim", out + sizeof want, (uint32_t)sizeof tlv, tlv, (uint32_t)sizeof tlv);
    Test_ExpectStatus(Aps_UpdateDeviceParse(out + 1, len - 1, &read), ZB_OK, "and it reads back");
    Test_ExpectOctets("with the TLVs handed over as the octets after the fixed fields", read.joinerTlvs,
                      read.joinerTlvLen, tlv, (uint32_t)sizeof tlv);

    Test_ExpectStatus(Aps_UpdateDeviceParse(want + 1, (uint32_t)sizeof want - 2, &read), ZB_ERR_BAD_FRAME,
                      "a body one octet short of Figure 4-13's fixed fields is refused");

    Zb_memcpy(out, want, (uint32_t)sizeof want);
    out[11] = 0x05;
    Test_ExpectStatus(Aps_UpdateDeviceParse(out + 1, (uint32_t)sizeof want - 1, &read), ZB_OK,
                      "a reserved status is read rather than refused");
    Test_ExpectCount(read.status, 0x05, "and returned as the octet said, Table 4-14's reservation being the trust centre's to judge");

    in.joinerTlvs = 0;
    in.joinerTlvLen = 0;
    in.status = 0x04;
    Test_ExpectStatus(Aps_UpdateDeviceCompose(&in, out, (uint32_t)sizeof out, &len), ZB_ERR_BAD_ARGUMENT,
                      "while composing the first reserved status, 0x04, is refused (Table 4-14)");
    in.status = APS_UPDATE_DEVICE_LEFT;
    in.deviceShortAddress = 0x0000;
    Test_ExpectStatus(Aps_UpdateDeviceCompose(&in, out, (uint32_t)sizeof out, &len), ZB_ERR_BAD_ARGUMENT,
                      "and so is a short address of 0x0000, below Table 4-14's 0x0001");
    in.deviceShortAddress = 0xfff8;
    Test_ExpectStatus(Aps_UpdateDeviceCompose(&in, out, (uint32_t)sizeof out, &len), ZB_ERR_BAD_ARGUMENT,
                      "and 0xfff8, above its 0xfff7");
    in.deviceShortAddress = 0xfff7;
    Test_ExpectStatus(Aps_UpdateDeviceCompose(&in, out, (uint32_t)sizeof want - 1, &len), ZB_ERR_NO_SPACE,
                      "and a buffer one octet short is refused rather than filled part way");
}

/* Figure 4-14 written out by hand, and the one length it prints. */
static void caseRemoveDeviceBody(void)
{
    static const uint8_t want[9] = { 0x07, 0x88, 0xa8, 0x05, 0xff, 0xff, 0x2e, 0x21, 0x00 };
    uint8_t out[16];
    uint64_t target = 0;
    uint32_t len = 0;

    Test_ExpectStatus(Aps_RemoveDeviceCompose(0x00212effff05a888, out, (uint32_t)sizeof out, &len), ZB_OK,
                      "a Remove Device is written");
    Test_ExpectOctets("as Figure 4-14 prints it: the identifier Table 4-31 gives 0x07 and the target's 64-bit address low octet first",
                      out, len, want, (uint32_t)sizeof want);
    Test_ExpectStatus(Aps_RemoveDeviceParse(out + 1, len - 1, &target), ZB_OK, "and its body reads back");
    Test_Expect(target == 0x00212effff05a888, "naming the target that went in (4.4.11.3.2)");

    Test_ExpectStatus(Aps_RemoveDeviceParse(want + 1, 7, &target), ZB_ERR_BAD_FRAME,
                      "a body of seven octets is refused");
    Test_ExpectStatus(Aps_RemoveDeviceParse(out, 9, &target), ZB_ERR_BAD_FRAME,
                      "and so is one of nine: Figure 4-14 prints the address alone");
    Test_ExpectStatus(Aps_RemoveDeviceCompose(1, out, 8, &len), ZB_ERR_NO_SPACE,
                      "and a buffer one octet short of the nine is refused");
}

/* Figure 4-17 around a secured command written out by hand, and each part of 4.4.11.6.3 and 4.6.3.7.1's shape the
   two functions refuse when it is missing. */
static void caseTunnelBody(void)
{
    /* Figure 2-8's header of a secured command (0x21) with its counter, an auxiliary frame naming the key-transport
       key with the extended nonce (0x30), its frame counter and the trust centre's address, two encrypted octets and
       the MIC */
    static const char *securedHex = "2117" "30" "01000000" "88a805ffff2e2100" "c3d4" "a1b2c3d4";
    uint8_t secured[32];
    uint8_t want[48];
    uint8_t out[48];
    uint8_t bad[32];
    Aps_Tunnel read;
    uint32_t securedLen;
    uint32_t len = 0;

    securedLen = Test_ParseHex(securedHex, secured, (uint32_t)sizeof secured);
    Test_ExpectCount(securedLen, APS_TUNNEL_SECURED_MIN + 1,
                     "the vector is a two-octet header, a thirteen-octet auxiliary frame, two octets and a MIC");

    Test_ExpectStatus(Aps_TunnelCompose(0x00212effff048a12, secured, securedLen, out, (uint32_t)sizeof out, &len), ZB_OK,
                      "a Tunnel is written around it");
    Test_ParseHex("0e" "128a04ffff2e2100", want, (uint32_t)sizeof want);
    Zb_memcpy(want + 9, secured, securedLen);
    Test_ExpectOctets("as Figure 4-17 prints it: the identifier Table 4-31 gives 0x0e, the destination low octet first, then the secured command whole",
                      out, len, want, 9 + securedLen);

    Test_ExpectStatus(Aps_TunnelParse(out + 1, len - 1, &read), ZB_OK, "and its body reads back");
    Test_Expect(read.destinationIeee == 0x00212effff048a12, "naming the destination (4.4.11.6.2)");
    Test_Expect(read.secured == out + 9 && read.securedLen == securedLen,
                "and handing over the octets after it, which 4.6.3.7.2 makes the extracted command's header, auxiliary frame and payload in that order");

    Zb_memcpy(bad, secured, securedLen);
    bad[2] = 0x10;
    Test_ExpectStatus(Aps_TunnelCompose(1, bad, securedLen, out, (uint32_t)sizeof out, &len), ZB_ERR_BAD_ARGUMENT,
                      "an auxiliary frame without the extended nonce is refused on the way out (4.4.11.6.3)");
    Test_ExpectStatus(Aps_TunnelParse(want + 1, 8 + securedLen, &read), ZB_OK, "the good body still parses");
    want[9 + 2] = 0x10;
    Test_ExpectStatus(Aps_TunnelParse(want + 1, 8 + securedLen, &read), ZB_ERR_BAD_FRAME,
                      "and the same frame without the extended nonce is refused on the way in");
    want[9 + 2] = 0x28;
    Test_ExpectStatus(Aps_TunnelParse(want + 1, 8 + securedLen, &read), ZB_ERR_BAD_FRAME,
                      "and so is one naming the network key, which 4.4.11.6.3's link key rules out");
    want[9 + 2] = 0x30;
    want[9] = 0x20;
    Test_ExpectStatus(Aps_TunnelParse(want + 1, 8 + securedLen, &read), ZB_ERR_BAD_FRAME,
                      "and a data frame, where 4.6.3.7.1 tunnels a command");
    want[9] = 0x01;
    Test_ExpectStatus(Aps_TunnelParse(want + 1, 8 + securedLen, &read), ZB_ERR_BAD_FRAME,
                      "and a command with security off, where 4.6.3.7.1 tunnels it secured");
    want[9] = 0xa1;
    Test_ExpectStatus(Aps_TunnelParse(want + 1, 8 + securedLen, &read), ZB_ERR_BAD_FRAME,
                      "and one with an extended header, which Figure 4-17's two header octets cannot hold");
    want[9] = 0x21;
    Test_ExpectStatus(Aps_TunnelParse(want + 1, 8 + APS_TUNNEL_SECURED_MIN, &read), ZB_OK,
                      "a carried frame of exactly a header, an auxiliary frame, one octet and a MIC is the shortest one taken");
    Test_ExpectStatus(Aps_TunnelParse(want + 1, 8 + APS_TUNNEL_SECURED_MIN - 1, &read), ZB_ERR_BAD_FRAME,
                      "and a carried frame one octet short of a header, an auxiliary frame, one octet and a MIC");
    Test_ExpectStatus(Aps_TunnelCompose(1, secured, securedLen, out, 9 + securedLen - 1, &len), ZB_ERR_NO_SPACE,
                      "and a buffer one octet short is refused rather than filled part way");
}

void caseFragmentationBlocks(void);
void caseFragmentAcknowledgement(void);

int main(void)
{
    Test_Begin("aps_modules");

    caseGroupFindAnswersThePairAndNotAClearedSlotCarryingIt();
    caseGroupAddAnswersIdempotenceBeforeItAnswersTableFull();
    caseGroupRemoveClearsOnePairAndAnswersINVALID_GROUPForNone();
    caseGroupRemoveAllSweepsAnEndpointAndAnswersSUCCESSOnNoMembership();
    caseGroupMemberAtWalksOneGroupInPoolOrderAndCountWalksHoles();
    caseDupSeenRecordsAMissAndAnswersSeenWithoutWritingAnything();
    caseDupFullPoolEvictsTheOldestRecordAndNotTheFirstInOrder();
    caseDupKeyIsTheSourceAndTheCounterTogether();
    caseDeliveryModeIsTheModeTableAsCoded();
    caseNwkDestinationCarriesAGroupSendOnTheClassItNames();
    caseOutgoingOctetsIsTheScratchForASecuredSlotAndTheStoredApduOtherwise();
    caseSlotForConfirmPairsOnTheHandleAndFallsBackToTheDestination();
    caseTxFreeHandsTheFirstIdleSlotAndOccupiedCountsEveryHeldOne();
    caseResolveKeyPairNamesTheEntryTheDestinationIs();
    caseAckSlotMatchesThePrintedPartsAndBandsAcksGuard();
    caseAckRespondAnswersItsThreeNotOwedRowsBeforeTheNetwork();
    caseTransportKeyNetworkDescriptor();
    caseTransportKeyLinkDescriptors();
    caseTransportKeyRefusals();
    caseTransportKeyFieldRules();
    caseFragmentationBlocks();
    caseFragmentAcknowledgement();
    caseUpdateDeviceBody();
    caseRemoveDeviceBody();
    caseTunnelBody();

    return Test_Report();
}

/*
 * The mutation this suite's Transport-Key cases are written to catch, and the one they cannot. Swap 4.4.2.3's
 * `initiatorOctet == 1` for `!= 0` in `aps_transportkey.c` and `caseTransportKeyFieldRules` reddens once, on the
 * octet 2 that would otherwise read as true. Remove the TLV walk's head guard, `if (tlvLen - at < 2)`, and no case
 * reddens: the guard stops a read past the tail, so what follows is undefined behaviour rather than a wrong answer,
 * and a case can only hold a defined one. It is asserted for the defined case it does produce, a run ending on a bare
 * tag, and its removal is not provable here.
 */

/*
 * The two mutations this suite is written to catch, run against this file and named here because a mutation
 * that is not stated is a claim and not a proof.
 *
 * 1. `aps_dup.c`, `Aps_DupSeen`: make the full-pool eviction pick the newest record instead of the oldest,
 * read `pool[i].seenMs > oldest->seenMs`. `caseDupFullPoolEvictsTheOldestRecordAndNotTheFirstInOrder`
 * reddens three times: the newcomer is found in the last slot of the pool instead of the first, the newest
 * record is no longer there to be found, and the tie at one `seenMs` lands elsewhere. The `aps` suite's
 * duplicate case reddens beside it, on four of its own assertions: the ordering is pinned at both gates, and
 * what only this file builds directly is a pool whose oldest record sits at the far end of it. The same
 * body's other half, `oldest = free` before any recycle, is caught by a mutation of its own: write `if (free
 * != 0 && oldest == 0)` and the hole-preference block reddens while the eviction block stays green, which is
 * why both blocks are asserted rather than one. 2. `aps_tx.c`, `Aps_TxOutgoingOctets`: swap the two arms,
 * `if (!tx->apsSecurity)`. Both arms of
 * `caseOutgoingOctetsIsTheScratchForASecuredSlotAndTheStoredApduOtherwise` redden at once, on six
 * assertions: which buffer each slot hands down, the length each reports, and the pointer identity between a
 * secured transaction's octets and its caller's scratch. The `aps` suite reddens with it on its secured legs
 * (four APDUs on the air where four differing ones belong) but the choice between two buffers is what this
 * case sees directly and a pipeline case cannot see at all: it is the assertion that a retransmission
 * re-protects rather than repeating a frame its peer has already counted (4.4.1.2 step 4, the same
 * arrangement one layer up).
 */

/*
 * 2.2.8.4.5's fragmentation at apscWindowSize 1: the block count, the block numbers 2.2.8.4.5.3 prints, the sub-field
 * a block carries, the octets each one hands down, and the reassembly pool that puts them back together.
 */
void caseFragmentationBlocks(void)
{
    Aps_FragAssembly pool[APS_FRAG_TRANSACTIONS];
    Aps_FragAssembly *assembly = 0;
    uint8_t asdu[APS_FRAG_MAX_ASDU];
    const uint8_t *block;
    uint8_t blockNumber = 0;
    uint8_t bitfield = 0;
    uint32_t blockLen;
    uint32_t i;

    Zb_memset(pool, 0, (uint32_t)sizeof pool);

    for (i = 0; i < (uint32_t)sizeof asdu; i++)
        asdu[i] = (uint8_t)(0x40 + i);

    Test_ExpectCount(Aps_FragBlockCount(96, 40), 3, "96 octets at 40 a block is three blocks, the last one short");
    Test_ExpectCount(Aps_FragBlockCount(40, 40), 1, "and an ASDU that fits one block is one block");
    Test_ExpectCount(Aps_FragBlockCount(0, 40), 0, "while nothing at all is no transaction");

    Test_ExpectCount(Aps_FragBlockNumber(0, 3), 3, "the first block states the total number of blocks, which 2.2.8.4.5.3 prints");
    Test_ExpectCount(Aps_FragBlockNumber(1, 3), 1, "the second states 0x01");
    Test_ExpectCount(Aps_FragBlockNumber(2, 3), 2, "and each after it is one more");
    Test_Expect(Aps_FragSubField(0) == APS_FRAG_FIRST && Aps_FragSubField(1) == APS_FRAG_SUBSEQUENT,
           "the sub-field is 0b01 for the first block and 0b10 for every subsequent one");

    block = Aps_FragBlock(asdu, 96, 40, 2, &blockLen);
    Test_Expect(block != 0 && blockLen == 16 && block[0] == asdu[80],
           "the third block is the sixteen octets from 80 to the end, and it starts where the second stopped");
    Test_Expect(Aps_FragBlock(asdu, 96, 40, 3, &blockLen) == 0 && blockLen == 0,
           "and a fourth block of a three-block transmission is no octets at all");

    Test_Expect(Aps_FragAccept(pool, 0x1234, 0x2a, APS_FRAG_SUBSEQUENT, 1, asdu, 40, 40, 100, &assembly)
                == APS_FRAG_DROP_OUT_OF_WINDOW,
           "a subsequent block with no transaction behind it is outside the window, which 2.2.8.4.5.4 refuses");

    block = Aps_FragBlock(asdu, 96, 40, 0, &blockLen);
    Test_Expect(Aps_FragAccept(pool, 0x1234, 0x2a, APS_FRAG_FIRST, 3, block, blockLen, 40, 110, &assembly)
                == APS_FRAG_ACCEPTED,
           "the first block opens the transaction, its block number being the total");
    Test_Expect(assembly != 0 && assembly->expected == 3 && assembly->have == 1,
           "so the record knows how many blocks to wait for and has one");

    Test_Expect(Aps_FragAckWindow(pool, 0x1234, 0x2a, &blockNumber, &bitfield) == 1,
           "an acknowledgement for the window is owed");
    Test_Expect(blockNumber == 1 && bitfield == 0xfe,
           "naming the lowest block of the window the first block moved on to, its own bit 0 because that block is not here yet and the remaining bits at 1, which 2.2.8.4.5.4 asks of a window smaller than eight");

    block = Aps_FragBlock(asdu, 96, 40, 1, &blockLen);
    Test_Expect(Aps_FragAccept(pool, 0x1234, 0x2a, APS_FRAG_SUBSEQUENT, 1, block, blockLen, 40, 120, &assembly)
                == APS_FRAG_ACCEPTED, "the second block is taken");
    Test_Expect(Aps_FragAccept(pool, 0x1234, 0x2a, APS_FRAG_SUBSEQUENT, 1, block, blockLen, 40, 130, &assembly)
                == APS_FRAG_ACCEPTED,
           "and the same one again is a block the window already passed, which keeps the transaction where it was");
    Test_Expect(Aps_FragAckWindow(pool, 0x1234, 0x2a, &blockNumber, &bitfield) == 1 && blockNumber == 1
           && bitfield == 0xff,
           "and repeats that block's acknowledgement, which is the persistence 2.2.8.4.5.4 encourages for a sender that did not hear the first one");

    block = Aps_FragBlock(asdu, 96, 40, 2, &blockLen);
    Test_Expect(Aps_FragAccept(pool, 0x1234, 0x2a, APS_FRAG_SUBSEQUENT, 2, block, blockLen, 40, 140, &assembly)
                == APS_FRAG_COMPLETE,
           "and the last block completes it");
    Test_Expect(assembly != 0 && assembly->asduLength == 96
           && Zb_memcmp(assembly->asdu, asdu, 96) == 0,
           "with the ASDU whole and in the order it was sent, which is the reassembly 2.2.8.4.5.4 asks for");

    Test_ExpectCount(Aps_FragReleaseIdle(pool, 200, 60), 1, "a transaction that has gone quiet gives its record back");
    Test_ExpectCount(Aps_FragCount(pool), 0, "leaving the pool empty");
}

/* 2.2.8.4.5.4's acknowledgement door: a frame that is not fragmented gets no window answer, and one that is goes
   down the one NLDE-DATA.request the answer always takes. */
void caseFragmentAcknowledgement(void)
{
    Aps_Frame frame;
    Nwk_DataIndicationParameters ind;
    uint8_t scratch[APS_FRAME_MAX];

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    Zb_memset(&ind, 0, (uint32_t)sizeof ind);

    frame.frameType = APS_FRAME_TYPE_DATA;
    frame.deliveryMode = APS_DELIVERY_UNICAST;
    frame.ackRequest = 1;
    frame.apsCounter = 0x2a;
    frame.srcEndpoint = 0x02;
    frame.dstEndpoint = 0x01;

    Test_Expect(Aps_AckRespondFragment(&ind, &frame, 1, 0xfe, 0, scratch, (uint32_t)sizeof scratch, 100)
                == APS_ACK_NOT_ACCEPTED,
           "a frame with no fragmentation sub-field is not a window this device answers, which 2.2.8.4.5.4 requires the fields for");

    frame.extendedHeaderPresent = 1;
    frame.extFrameControl = (uint8_t)APS_FRAG_FIRST;
    frame.fragmentation = APS_FRAG_FIRST;
    frame.blockNumberPresent = 1;
    frame.blockNumber = 3;

    Test_Expect(Aps_AckRespondFragment(&ind, &frame, 1, 0xfe, 0, scratch, (uint32_t)sizeof scratch, 100)
                == APS_ACK_ISSUE_REFUSED,
           "while a fragmented one reaches the issue, which a device with no network layer behind it cannot run");

    frame.ackRequest = 0;

    Test_Expect(Aps_AckRespondFragment(&ind, &frame, 1, 0xfe, 0, scratch, (uint32_t)sizeof scratch, 100)
                == APS_ACK_NOT_REQUESTED,
           "and one that asked for nothing is answered with nothing, as 2.2.8.4.3.1 prints for every frame");
}
