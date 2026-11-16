/*
 * -------------------------------------------------------------------------------------
 * Part C: the security crossing.
 *
 * The same two halves with a `Security` attached: what a request becomes when it asks for protection, what a
 * secured frame becomes when it is heard, and what a relay puts back on the air. The suites above are the
 * scaffold contract, and every one of them still runs untouched: a module with no `Security` attached, or with
 * one at level 0x00, behaves exactly as it did before the secured paths landed.
 *
 * Provenance of the octets this part compares against. `s1` is the byte-exact secured NWK frame
 * of the security suite, src/zb/security.c's first vector, computed from R23.1 4.3.1.1 by an
 * independent CPython implementation and cross-checked against the CCM* seam through the intermediates
 * Annex C.3 validates (no secured NWK vector is published anywhere in the corpus). It is quoted
 * here rather than recomputed, and it is the oracle of the end-to-end case: the NWK composition,
 * the protection and the MAC framing have to agree octet for octet with the security module's
 * own vector for the byte comparison to pass, which makes that case the strongest in this tree.
 *
 * The fixtures share Table 4-2's nwkSecurityMaterialSet key (sequence number 0x00), run Table 4-2's default
 * `nwkSecurityLevel` 0x05, and start from named outgoing counters. Devices: A at 0x0000 with the extended
 * address s1's auxiliary header carries, B at 0x0001, a third fixture for the device that only listens.
 * -------------------------------------------------------------------------------------
 *
 * This is where that crossing is asserted, attaching and detaching the
 * module included: the scaffold suites it re-runs are `cases_delivery.c`, `cases_broadcast.c` and
 * `cases_rx.c`. */

#include "loopback_radio.h"
#include "mac.h"
#include "nwk.h"
#include "nwk_commissioning.h"
#include "nwk_join.h"
#include "nwk_leave.h"
#include "nwk_status.h"
#include "nwk_timeout.h"
#include "nwk_cost.h"
#include "nwk_frame.h"
#include "nwk_helpers.h"
#include "rig_band_a.h"
#include "security.h"
#include "test_harness.h"
#include "zb_utils.h"

#define SEC_A_IEEE 0x0123456789abcdef
#define SEC_B_IEEE 0x1011121314151617
#define SEC_E_IEEE 0x2021222324252627

#define ADDR_COORD 0x0000           /* A, the coordinator-shaped source of every secured frame Part C sends */
#define ADDR_PEER 0x0001            /* B, the device Part C receives at */
#define ADDR_SLEEPY1 0x0101
#define ADDR_SLEEPY2 0x0102
#define ADDR_ELSEWHERE 0x0100

#define SEC_NSDU_LEN 7
#define SEC_HEADER_LEN 8            /* the minimal NWK header s1 carries: no IEEE address, no source route */
#define SEC_AUX_OCTETS 14           /* Figure 4-24 for the only auxiliary form band A reads */
#define SEC_MIC_OCTETS 4            /* Table 4-38 at level 0x05 */

/* The NSDU every secured case sends: s1's payload, octet for octet. */
static const uint8_t securedNsdu[SEC_NSDU_LEN] =
{
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46
};

/* The suite's network key, at sequence number 0x00: the key s1 was protected with. */
static const char *s_keyHex = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";

/* s1: level 0x05, key 0x00, outgoing counter 0x00000005, A's extended address in the auxiliary source field.
   8 + 14 + 7 + 4 = 33 octets, in 4.3.1.1 step 5's order. */
static const char *s_frame1Hex = "0802010000001e052805000000efcdab896745230100621e81731bba4c15db7c75";

/* s6: the same key, the same level and the same sender as s1, on a NWK *command* frame (Frame Control Field
   0x0209, frame type Command with nwkcProtocolVersion 0x02 and the security sub-field set), whose plaintext is
   empty. 8 + 14 + 0 + 4 = 26 octets, at counter 0x00000009. Computed the way s1 is computed above: no secured
   command frame is published anywhere in the corpus, still less an empty one,
   so it comes from the same independent CPython implementation assembled per R23.1 Annex A.2,
   at this part's own key and this part's own sender. */
static const char *s_frame6Hex = "0902010000001e052809000000efcdab896745230100080c5d11";

/* The vectors are runs of hex, as the standards write them; the same reader the security suite uses. */
static uint32_t octetsOf(const char *hex, uint8_t *out, uint32_t cap)
{
    uint32_t octet;
    uint32_t digit;
    uint8_t nibble;
    uint8_t value;

    for (octet = 0; octet < cap && hex[2 * octet] != 0; octet++)
    {
        value = 0;

        for (digit = 0; digit < 2; digit++)
        {
            nibble = 0;

            if (hex[2 * octet + digit] >= '0' && hex[2 * octet + digit] <= '9')
                nibble = (uint8_t)(hex[2 * octet + digit] - '0');

            if (hex[2 * octet + digit] >= 'a' && hex[2 * octet + digit] <= 'f')
                nibble = (uint8_t)(hex[2 * octet + digit] - 'a' + 10);

            value = (uint8_t)((value << 4) | nibble);
        }

        out[octet] = value;
    }

    return octet;
}

/* A network key descriptor and the one configuration every Part C fixture is seeded from (the key,
   the level, this device's extended address and the outgoing counter arrive as application configuration and
   from nowhere else). */
static void secSeed(Security *sec, uint64_t ownIeee, uint32_t outgoingCounter, int authenticated)
{
    Security_KeyDescriptor key;
    Security_Config cfg;

    Zb_memset(&key, 0, (uint32_t)sizeof key);
    key.keySeqNumber = 0x00;
    key.inUse = 1;
    key.outgoingFrameCounter = outgoingCounter;
    Test_Expect(octetsOf(s_keyHex, key.key, SECURITY_KEY_OCTETS) == SECURITY_KEY_OCTETS,
                "the suite's network key is the 16 octets Table 4-3 prints");

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = ownIeee;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;      /* Table 4-2's printed default 0x05, M = 4 per Table 4-38 */
    cfg.nwkActiveKeySeqNumber = 0x00;
    cfg.authenticated = authenticated;
    cfg.nwkAllFresh = 1;                                   /* nwkAllFresh defaults TRUE (Table 4-2, attribute 0xa3) */
    cfg.keys = &key;
    cfg.keyCount = 1;
    cfg.incomingSeeds = 0;
    cfg.incomingSeedCount = 0;
    cfg.log = 0;

    Test_ExpectStatus(Security_Init(sec, &cfg), ZB_OK, "a fixture the application could have configured");
    Test_Expect(Security_IsEnabled(sec) == 1 && Security_Level(sec) == SECURITY_LEVEL_ENC_MIC_32,
                "enabled at a level band A runs");
    Test_Expect(Security_IsAuthenticated(sec) == authenticated, "and carrying the joined flag it was told to carry");
}

/* A rig with the security module adopted, the way `mac` adopts a backend. */
static void securedRig(Test_BandA *rig, uint16_t own, uint32_t deviceType, int rxOnWhenIdle, Security *sec,
                       uint64_t ownIeee, uint32_t outgoingCounter, int authenticated)
{
    rigAt(rig, own, PAN_ID, deviceType, rxOnWhenIdle);
    secSeed(sec, ownIeee, outgoingCounter, authenticated);
    Nwk_AttachSecurity(&rig->nwk, sec);
    Test_Expect(rig->nwk.security == sec,
          "adopted by pointer and not copied: the keys, the counters and the joined flag stay in the caller's struct");
}

/* The frame counter field of an auxiliary header, read at the boundary the codec reports: Figure 4-24 puts the
   four octets after the one control octet, low octet first as 4.5 transmits every field longer than one octet. */
static uint32_t auxCounterOf(const uint8_t *npdu, uint32_t headerLen)
{
    return (uint32_t)npdu[headerLen + 1]
           | ((uint32_t)npdu[headerLen + 2] << 8)
           | ((uint32_t)npdu[headerLen + 3] << 16)
           | ((uint32_t)npdu[headerLen + 4] << 24);
}

/* The same field's neighbour: the eight-octet source address, which 4.5.1.3 pins to the device responsible for
   securing the frame. */
static uint64_t auxSourceOf(const uint8_t *npdu, uint32_t headerLen)
{
    uint64_t value = 0;
    uint32_t i;

    for (i = 0; i < 8; i++)
        value = value | ((uint64_t)npdu[headerLen + 5 + i] << (8 * i));

    return value;
}

/* The key sequence number octet, last of the fourteen. */
static uint8_t auxKeySeqOf(const uint8_t *npdu, uint32_t headerLen)
{
    return npdu[headerLen + SEC_AUX_OCTETS - 1];
}

/*
 * A secured NPDU built the honest way, for the cases that have to put a neighbor's secured frame on this
 * device's doorstep: this stack's own codec composes the header, a `Security` fixture stands for the device that
 * sent it and protects the frame with its own address and its own counter (3.2.1.1.3, 4.5.1.3), and what comes
 * back is what the receiving rig then has to authenticate. The header is the minimal eight-octet form here,
 * because `makeNpdu` composes no IEEE address and no source route, which is also what the header half of the
 * authenticated string counts for a frame of these fields.
 */
static uint32_t secureNpdu(Security *sender, uint16_t dst, uint16_t src, uint8_t radius, uint8_t seq,
                           uint32_t frameType, uint32_t endDeviceInitiator, const uint8_t *payload,
                           uint32_t payloadLen, uint8_t *out, uint32_t outCap)
{
    Nwk_Frame frame;
    uint8_t plain[NWK_FRAME_NPDU_MAX];
    uint32_t plainLen;
    uint32_t outLen = 0;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = (int)frameType;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.discoverRoute = NWK_DISCOVER_SUPPRESS;
    frame.securityEnabled = 1;        /* the bit is part of the header the frame is authenticated over: 4.3.2, "When security is applied to an NPDU frame, the security bit in the NWK frame control field SHALL be set to 1", and `Nwk_TxCompose` sets it before the frame is ever protected */
    frame.endDeviceInitiator = (int)endDeviceInitiator;
    frame.destAddr = dst;
    frame.srcAddr = src;
    frame.radius = radius;
    frame.sequenceNumber = seq;

    Test_ExpectStatus(NwkFrame_Compose(&frame, payload, payloadLen, plain,
                                  (uint32_t)sizeof plain, &plainLen), ZB_OK,
                  "the header the case injects is one this stack's own codec composes");
    Test_Expect(plainLen == NWK_MIN_HEADER_OVERHEAD + payloadLen,
          "and it is the minimal eight-octet form: no IEEE address, no source route");

    Test_ExpectStatus(Security_Protect(sender, plain, NWK_MIN_HEADER_OVERHEAD, plain + NWK_MIN_HEADER_OVERHEAD,
                                  plainLen - NWK_MIN_HEADER_OVERHEAD, out, outCap, &outLen), ZB_OK,
                  "then protected by the sender's own fixture, which is the only way a frame this stack did not send can be a frame this stack can read");
    Test_Expect(outLen == NWK_MIN_HEADER_OVERHEAD + SEC_AUX_OCTETS + payloadLen + SEC_MIC_OCTETS,
          "into the shape 4.3.1.1 step 5 prints for an encrypting level");

    return outLen;
}

/*
 * 1. A secured unicast, end to end, byte for byte.
 *
 * A composes, protects and issues; the radio answers; the same octets are put in front of B's MAC as a
 * neighbor's frame; B unprotects and indicates. The NPDU on A's side of the seam is compared against s1, the
 * security suite's vector: the NWK header `nwk_frame` wrote, the auxiliary header and ciphertext `security`
 * wrote and the MAC framing `mac` wrote all have to be the ones the vector says they are, or one octet of the
 * comparison fails. That is why this is the strongest case in the tree: it is the only one that pins the whole
 * stack against an outside computation rather than against itself.
 *
 * The order it pins on the receive side is the receive order: the radius the indication carries is 29, which is
 * 30 as s1's header states it minus the one decrement this device paid, and the decrement could only have read
 * the frame's own octet after the MIC verified, because the radius octet is inside the authenticated string
 * (4.3.1.1 step 3d).
 */
void caseSecuredUnicastEndToEnd(void)
{
    Test_BandA devA;
    Test_BandA devB;
    Security secA, secB;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[2];
    Nwk_DataIndicationParameters inds[2];
    Nwk_DataRequestParameters req;
    Security_KeyState state;
    uint8_t vector[64];
    uint32_t airCount = 0;
    uint32_t vectorLen;
    uint32_t got;

    vectorLen = octetsOf(s_frame1Hex, vector, (uint32_t)sizeof vector);
    Test_Expect(vectorLen == SEC_HEADER_LEN + SEC_AUX_OCTETS + SEC_NSDU_LEN + SEC_MIC_OCTETS,
          "s1 is 33 octets: NwkHeader || AuxiliaryHeader || c || MIC (4.3.1.1 step 5)");

    securedRig(&devA, ADDR_COORD, NWK_DEVICE_ROUTER, 1, &secA, SEC_A_IEEE, 5, 1);
    securedRig(&devB, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &secB, SEC_B_IEEE, 5, 1);

    devA.nwk.seq = 5;     /* the sequence octet s1 carries, so the header this module composes is the header the vector was computed over */
    seedNeighbor(&devA.nwk, ADDR_PEER, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    req = nldeReq(ADDR_PEER, securedNsdu, SEC_NSDU_LEN, 0);
    req.securityEnable = 1;

    Test_ExpectStatus(Nwk_DataRequest(&devA.nwk, &req, 100), ZB_OK,
                  "a secured unicast at a device that runs NWK security: 4.2.2 honours the request, and the radius the request left unstated is still the network default 3.2.1.1.3 derives");
    harvestAir(&devA.model, air, &airCount);

    Test_Expect(airCount == 1, "one frame on the air");
    Test_Expect(fcfOf(&air[0]) == AIR_UNICAST_FCF && air[0].ackRequest == 1,
          "on this PAN's acknowledged unicast: the ask is the NWK's decision (3.6.4.3) and security changes nothing about it");
    Test_Expect(npduLenOf(&air[0]) == vectorLen && Zb_memcmp(npduOf(&air[0]), vector, vectorLen) == 0,
          "and the NPDU the MAC carried is s1 octet for octet: NWK composition, protection and MAC framing pinned against a computation this stack did not make");
    Test_Expect(auxSourceOf(npduOf(&air[0]), SEC_HEADER_LEN) == SEC_A_IEEE,
          "the auxiliary source field is this device's own extended address (4.5.1.3, 3.2.1.1.3)");
    Test_Expect(auxCounterOf(npduOf(&air[0]), SEC_HEADER_LEN) == 5,
          "the auxiliary frame counter is the descriptor's outgoing counter as it stood (4.3.1.1 steps 1 and 2c)");
    Test_Expect(npduOf(&air[0])[SEC_HEADER_LEN] == 0x28 && auxKeySeqOf(npduOf(&air[0]), SEC_HEADER_LEN) == 0x00,
          "control octet 0x28 (the level sub-field overwritten by 4.3.1.1 step 8, the level travelling in the nonce only) and key sequence number 0x00");

    Test_ExpectStatus(Test_NwkStep(&devA.nwk, 101), ZB_OK, "answered");
    harvestAir(&devA.model, air, &airCount);
    Test_Expect(airCount == 1, "and one attempt was all it took");

    got = Nwk_PollConfirms(&devA.nwk, confirms, 2);
    Test_Expect(got == 1 && confirms[0].status == ZB_OK && confirms[0].nwkStatus == NWK_STATUS_SUCCESS,
          "SUCCESS in both vocabularies, exactly as an unsecured delivery answers (3.2.1.2.3)");
    Test_Expect(got == 1 && confirms[0].attempts == 1 && confirms[0].seq == 5 && confirms[0].dstAddr == ADDR_PEER,
          "for the one frame, numbered as the frame numbered itself");

    injectNpdu(&devB, npduOf(&air[0]), npduLenOf(&air[0]), ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&devB.nwk, 102), ZB_OK, "the same octets arrive at B as a neighbor's frame");

    got = Test_NwkPoll(&devB.nwk, inds, 2);
    Test_Expect(got == 1 && inds[0].securityUsed == 1,
          "Table 3-4's SecurityUse, 'Set to TRUE if security was applied to the received frame or FALSE if the received frame was unsecured'");
    Test_Expect(got == 1 && inds[0].nsduLength == SEC_NSDU_LEN
                && Zb_memcmp(inds[0].nsdu, securedNsdu, SEC_NSDU_LEN) == 0,
          "and the NSDU is the seven octets A asked to have sent: the auxiliary header and the MIC are gone, 4.3.1.2 step 5b handing back NwkHeader || m");
    Test_Expect(got == 1 && inds[0].radiusRemaining == 29 && inds[0].seq == 5,
          "radius 29 of the 30 s1's header states (the decrement receipt costs, paid after the frame was readable and before anything else decided) and the originator's own sequence number");
    Test_Expect(got == 1 && inds[0].srcAddr == ADDR_COORD && inds[0].dstAddr == ADDR_PEER && inds[0].wasBroadcast == 0,
          "the originator and this device's own address, on the unicast path (Table 3-4, 3.6.2.2)");

    Test_Expect(Nwk_RxSecurityFailures(&devB.nwk) == 0 && Nwk_RxFrameCounterRejects(&devB.nwk) == 0
                && Nwk_DroppedUnsupported(&devB.nwk) == 0 && Nwk_DroppedMalformed(&devB.nwk) == 0
                && Nwk_DroppedUnsecured(&devB.nwk) == 0 && Nwk_TxSecurityFailures(&devA.nwk) == 0
                && Nwk_RefusedRequests(&devA.nwk) == 0 && Nwk_RelaysSent(&devB.nwk) == 0
                && Nwk_BttQueue(&devB.nwk) == 0 && Nwk_DroppedDuplicate(&devB.nwk) == 0,
          "and a delivery that worked has nothing to count on either side");

    Security_Snapshot(&secA, &state);
    Test_Expect(state.keyCount == 1 && state.keySeqNumber[0] == 0x00 && state.outgoingFrameCounter[0] == 6,
          "the descriptor's counter moved once, for the one frame that became the secured frame (4.3.1.1 step 7): the snapshot is what the application persists");
}

/*
 * 2. A tampered frame authenticates nowhere.
 *
 * One octet of s1's ciphertext flipped. Nothing about the header, the counter or the key changed, so the frame
 * reaches the MIC and fails there: 4.3.1.2 step 5a, "If the CCM mode invoked in step 4 outputs 'invalid',
 * security processing SHALL indicate a failure to the next higher layer with a status of 'frame security failed'
 * and no further security processing shall be done on this frame". No status exists
 * in the corpus for an incoming security failure, so the counter is where it lives, and step 6 running after
 * step 5a is why the sender's window is untouched.
 */
void caseSecuredTamperRejected(void)
{
    Test_BandA dev;
    Security sec;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[2];
    uint8_t npdu[64];
    uint32_t airCount = 0;
    uint32_t npduLen;

    securedRig(&dev, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &sec, SEC_B_IEEE, 5, 1);

    npduLen = octetsOf(s_frame1Hex, npdu, (uint32_t)sizeof npdu);
    npdu[SEC_HEADER_LEN + SEC_AUX_OCTETS] = (uint8_t)(npdu[SEC_HEADER_LEN + SEC_AUX_OCTETS] ^ 0x01);

    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a secured unicast with one ciphertext octet changed");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_RxSecurityFailures(&dev.nwk) == 1, "is a security failure, counted as one");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 2) == 0, "and is not delivered: 4.3.1.2's failure is 'no further security processing', and 3.6.2.2 indicates a frame it processed");
    Test_Expect(Nwk_RxFrameCounterRejects(&dev.nwk) == 0 && Nwk_DroppedMalformed(&dev.nwk) == 0
                && Nwk_DroppedUnsupported(&dev.nwk) == 0 && Nwk_DroppedNotForMe(&dev.nwk) == 0,
          "counted under the name that says which gate refused it and not under any of the others");
    Test_Expect(airCount == 0 && Nwk_RelaysSent(&dev.nwk) == 0 && Nwk_BttQueue(&dev.nwk) == 0,
          "and nothing went out for it");
    Test_Expect(sec.incoming[0].inUse == 0,
          "the sender's incoming window holds nothing: 4.3.1.2 step 6 stores a count only for a frame that authenticated, so a forgery cannot spend a sender's window");
}

/*
 * 3. A replayed secured unicast is refused by the counter, not by a table.
 *
 * s1 twice, at a unicast, where band A keeps no duplicate record at all (no unicast replay table, the only
 * printed unicast identification is 3.3.1.5's MAY). What refuses the second copy is the anti-replay the
 * standard does print (4.3.1.2 step 3, "If there is an incoming frame count FrameCount corresponding to
 * SenderAddress … and if ReceivedFrameCount is less than FrameCount, security processing SHALL indicate a
 * failure … with a status of 'bad frame counter'") because step 6 stored ReceivedFrameCount + 1 for the first
 * copy. That is the whole of band A's unicast replay defence, and it is the security module's rather than a
 * table of its own.
 */
void caseSecuredUnicastReplayRefused(void)
{
    Test_BandA dev;
    Security sec;
    Nwk_DataIndicationParameters inds[2];
    uint8_t npdu[64];
    uint32_t npduLen;

    securedRig(&dev, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &sec, SEC_B_IEEE, 5, 1);

    npduLen = octetsOf(s_frame1Hex, npdu, (uint32_t)sizeof npdu);

    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "the first copy, counter 5");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 2) == 1 && inds[0].securityUsed == 1, "is delivered");
    Test_Expect(sec.incoming[0].inUse == 1 && sec.incoming[0].senderIeee == SEC_A_IEEE
                && sec.incoming[0].keySeqNumber == 0x00 && sec.incoming[0].frameCounter == 6,
          "and the window stored for that sender is ReceivedFrameCount + 1, keyed on the auxiliary address and the key (4.3.1.2 step 6, Table 4-4)");

    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "the identical frame again");

    Test_Expect(Nwk_RxFrameCounterRejects(&dev.nwk) == 1, "refused by the freshness window: 4.3.1.2 step 3's 'bad frame counter'");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 2) == 0, "and not delivered a second time");
    Test_Expect(Nwk_RxSecurityFailures(&dev.nwk) == 0 && Nwk_DroppedDuplicate(&dev.nwk) == 0,
          "counted as the counter refusal it is: no duplicate table is involved, because band A builds none for a unicast");
}

/*
 * 4. The duplicate a broadcast transaction table never gets to call.
 *
 * The same secured broadcast twice at a router that keeps a BTT. Under the unsecured suite the second copy is
 * `droppedDuplicate`; here it never reaches the record, because 4.3.1.2 step 3 refuses the replayed counter
 * before any policy gate runs (the receive order). It is the direct consequence of storing the unsecured copy: a
 * secured broadcast's copies are separate frames with separate counters, so the counters (and not a table keyed
 * on source and sequence) are what identifies a duplicate.
 */
void caseSecuredBroadcastDuplicateProof(void)
{
    Test_BandA dev;
    Security sec;
    Security secSender;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[2];
    uint8_t npdu[128];
    uint32_t airCount = 0;
    uint32_t npduLen;

    securedRig(&dev, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &sec, SEC_B_IEEE, 1, 1);

    secSeed(&secSender, SEC_A_IEEE, 5, 1);

    /* Radius 1, so the copy is recorded and not relayed: the point is which counter moves. */
    npduLen = secureNpdu(&secSender, NWK_ADDR_ALL_DEVICES, ADDR_COORD, 1, 0x40, NWK_FRAME_TYPE_DATA, 0,
                         securedNsdu, SEC_NSDU_LEN, npdu, (uint32_t)sizeof npdu);

    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a secured broadcast with one hop left");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 2) == 1 && inds[0].wasBroadcast == 1
                && inds[0].securityUsed == 1 && inds[0].radiusRemaining == 0,
          "delivered with the decrement paid, and not relayed: 3.6.2.2's 'SHALL NOT, under any circumstances'");
    Test_Expect(airCount == 0 && Nwk_BttQueue(&dev.nwk) == 1 && Nwk_RelaysSent(&dev.nwk) == 0,
          "and recorded, which is what makes the second copy a duplicate in the table's terms");

    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 101), ZB_OK, "the same secured broadcast again, same source, same sequence number");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_RxFrameCounterRejects(&dev.nwk) == 1,
          "the freshness window outruns the broadcast transaction table (4.3.1.2 step 3): the counter refuses the replay before the dedup can speak");
    Test_Expect(Nwk_DroppedDuplicate(&dev.nwk) == 0, "and the dedup counter does not move, because the frame never reached the record");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 2) == 0 && airCount == 0 && Nwk_BttQueue(&dev.nwk) == 1,
          "not delivered, not relayed, and the one record unchanged");
}

/*
 * 5. A secured retry is a new secured frame on every attempt.
 *
 * 3.2.1.1.3 says it and 3.6.4.3 repeats it for a relay: each additional attempt "SHALL be delayed by at least
 * nwkcUnicastRetryDelay and SHALL be re-encrypted with the newest network frame counter". The slot holds the
 * unsecured octets and the header it composed, so the four attempts differ in the auxiliary counter and
 * therefore in ciphertext and MIC, and are identical in everything the network layer chose: sequence number,
 * radius, addresses, payload. B decrypts each one with the same key and its window for A steps once per
 * attempt, which is what "a new frame counter" means from the receiving side.
 */
void caseSecuredRetryResecuresEveryAttempt(void)
{
    Test_BandA devA;
    Test_BandA devB;
    Security secA, secB;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[2];
    Nwk_DataIndicationParameters inds[2];
    Nwk_DataRequestParameters req;
    Security_KeyState state;
    uint32_t airCount = 0;
    uint32_t got;
    uint32_t i;

    securedRig(&devA, ADDR_COORD, NWK_DEVICE_ROUTER, 1, &secA, SEC_A_IEEE, 5, 1);
    securedRig(&devB, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &secB, SEC_B_IEEE, 9, 1);

    devA.nwk.seq = 5;
    seedNeighbor(&devA.nwk, ADDR_PEER, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    scriptOutcomes(&devA.model, LOOPBACK_TX_MAX, 0);        /* every attempt is a unicast nobody acknowledged */

    req = nldeReq(ADDR_PEER, securedNsdu, SEC_NSDU_LEN, 0);
    req.securityEnable = 1;

    Test_ExpectStatus(Nwk_DataRequest(&devA.nwk, &req, 0), ZB_OK, "the first attempt, issued at once");
    harvestAir(&devA.model, air, &airCount);
    Test_Expect(airCount == 1 && auxCounterOf(npduOf(&air[0]), SEC_HEADER_LEN) == 5,
          "one frame on the air, counter 5");

    Test_ExpectStatus(Test_NwkStep(&devA.nwk, 1), ZB_OK, "answered NO_ACK");
    Test_ExpectStatus(Test_NwkStep(&devA.nwk, 50), ZB_OK, "one millisecond short of the retry floor");
    harvestAir(&devA.model, air, &airCount);
    Test_Expect(airCount == 1, "and nothing issued");

    Test_ExpectStatus(Test_NwkStep(&devA.nwk, 51), ZB_OK, "the second attempt, at the floor");
    harvestAir(&devA.model, air, &airCount);
    Test_Expect(airCount == 2, "on the air");
    Test_ExpectStatus(Test_NwkStep(&devA.nwk, 52), ZB_OK, "answered NO_ACK again");
    Test_ExpectStatus(Test_NwkStep(&devA.nwk, 102), ZB_OK, "the third attempt");
    harvestAir(&devA.model, air, &airCount);
    Test_Expect(airCount == 3, "on the air");
    Test_ExpectStatus(Test_NwkStep(&devA.nwk, 103), ZB_OK, "answered NO_ACK again");
    Test_ExpectStatus(Test_NwkStep(&devA.nwk, 153), ZB_OK, "the fourth and last attempt");
    harvestAir(&devA.model, air, &airCount);
    Test_Expect(airCount == 1 + NWK_UNICAST_RETRIES, "1 + nwkcUnicastRetries frames, which is the bound 3.2.1.1.3 states");
    Test_ExpectStatus(Test_NwkStep(&devA.nwk, 154), ZB_OK, "answered NO_ACK for the fourth time");
    harvestAir(&devA.model, air, &airCount);
    Test_Expect(airCount == 1 + NWK_UNICAST_RETRIES, "and no fifth attempt");

    for (i = 0; i < airCount; i++)
    {
        Test_Expect(npduLenOf(&air[i]) == SEC_HEADER_LEN + SEC_AUX_OCTETS + SEC_NSDU_LEN + SEC_MIC_OCTETS,
                    "every attempt the same length: 8 + 14 + 7 + 4");
        Test_Expect(Zb_memcmp(npduOf(&air[i]), npduOf(&air[0]), SEC_HEADER_LEN) == 0,
                    "and the same NWK header octet for octet, security sub-field, sequence number and radius included: 3.6.4.3's rule that a replayed packet keeps the number the originator chose");
        Test_Expect(auxCounterOf(npduOf(&air[i]), SEC_HEADER_LEN) == 5 + i,
                    "with the auxiliary counter the only number the network layer moved: 5, 6, 7, 8 (4.3.1.1 step 7, 3.2.1.1.3's re-encryption rule)");
        Test_Expect(auxSourceOf(npduOf(&air[i]), SEC_HEADER_LEN) == SEC_A_IEEE,
                    "and always this device's own extended address (3.2.1.1.3)");

        if (i != 0)
            Test_Expect(npduDiffCount(npduOf(&air[i]), npduLenOf(&air[i]), npduOf(&air[0]),
                                 npduLenOf(&air[0])) > 0,
                        "so each attempt is a different NPDU on the wire, not the first one re-sent");
    }

    got = Nwk_PollConfirms(&devA.nwk, confirms, 2);
    Test_Expect(got == 1 && confirms[0].attempts == 1 + NWK_UNICAST_RETRIES,
          "the final confirmation counts every attempt the frame took");
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_DEVICE
                && confirms[0].nwkStatus == NWK_STATUS_LAST_MAC_STATUS,
          "with the MAC's own status and no NWK code of this module's: these attempts failed on the air and not at the security module (3.2.1.1.3)");
    Test_Expect(Nwk_TxSecurityFailures(&devA.nwk) == 0, "and no protection was refused on the way");

    /* The four frames as B reads them. */
    for (i = 0; i < airCount; i++)
    {
        injectNpdu(&devB, npduOf(&air[i]), npduLenOf(&air[i]), ADDR_COORD);
        Test_ExpectStatus(Test_NwkStep(&devB.nwk, 200 + i), ZB_OK, "the attempt arrives at B");

        got = Test_NwkPoll(&devB.nwk, inds, 2);
        Test_Expect(got == 1 && inds[0].securityUsed == 1
                    && inds[0].nsduLength == SEC_NSDU_LEN
                    && Zb_memcmp(inds[0].nsdu, securedNsdu, SEC_NSDU_LEN) == 0,
                    "decrypts at B with the shared key and delivers the same NSDU: four secured frames, one payload");
        Test_Expect(secB.incoming[0].frameCounter == 6 + i,
                    "and B's window for this sender steps once per attempt (4.3.1.2 step 6)");
    }

    Test_Expect(Nwk_RxSecurityFailures(&devB.nwk) == 0 && Nwk_RxFrameCounterRejects(&devB.nwk) == 0,
          "every one of them accepted: a fresh counter is what makes a retry pass the freshness window a replay fails");

    Security_Snapshot(&secA, &state);
    Test_Expect(state.outgoingFrameCounter[0] == 5 + 1 + NWK_UNICAST_RETRIES,
          "and A's descriptor moved once per attempt, four times for one frame (4.3.1.1 step 7)");
}

/*
 * 6. A secured broadcast relayed: unprotect, record the unsecured copy, re-secure on the way out.
 *
 * The stored record is the whole case. O secures the broadcast with its own address and its own counter; R reads
 * it, records the *unsecured* forwarded copy (the decremented radius, the cleared End Device Initiator, the
 * plaintext behind the header boundary, and the bit 9 that says the next copy has to be protected) and puts back
 * on the air a frame it secured with R's own extended address and R's own counter. E, which only listens,
 * authenticates R's frame and not O's, and its indication says security was applied. The two retransmissions R
 * owes are two secured frames with two counters, which is what §9.5's verbatim-carry rule no longer reaches.
 */
void caseSecuredBroadcastRelayResecures(void)
{
    Test_BandA devO;
    Test_BandA devR;
    Test_BandA devE;
    Security secO, secR, secE;
    Air airO[AIR_LOG_MAX];
    Air airR[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    Nwk_BroadcastTransactionRecord *record;
    Nwk_DataRequestParameters req;
    Security_KeyState state;
    uint8_t npdu[128];
    uint32_t airOCount = 0;
    uint32_t airRCount = 0;
    uint32_t seq = 0x42;

    securedRig(&devO, ADDR_COORD, NWK_DEVICE_ROUTER, 1, &secO, SEC_A_IEEE, 5, 1);
    securedRig(&devR, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &secR, SEC_B_IEEE, 1, 1);
    securedRig(&devE, ADDR_ELSEWHERE, NWK_DEVICE_END_DEVICE, 0, &secE, SEC_E_IEEE, 1, 1);

    devO.nwk.seq = (uint8_t)seq;     /* the sequence number the record is keyed on, fixed so the case can name it */

    req = nldeReq(NWK_ADDR_ALL_DEVICES, securedNsdu, SEC_NSDU_LEN, 2);
    req.securityEnable = 1;

    Test_ExpectStatus(Nwk_DataRequest(&devO.nwk, &req, 100), ZB_OK, "O broadcasts a secured frame with two hops left");
    harvestAir(&devO.model, airO, &airOCount);

    Test_Expect(airOCount == 1 && (nwkFcfOf(npduOf(&airO[0])) & NWK_FCF_SECURITY_BIT) != 0,
          "on the air with the security sub-field set (4.3.2: 'the security bit in the NWK frame control field SHALL be set to 1 to indicate the presence of the auxiliary frame header')");
    Test_Expect(auxSourceOf(npduOf(&airO[0]), SEC_HEADER_LEN) == SEC_A_IEEE
                && auxCounterOf(npduOf(&airO[0]), SEC_HEADER_LEN) == 5,
          "secured by O: O's address, O's counter");

    injectNpdu(&devR, npduOf(&airO[0]), npduLenOf(&airO[0]), ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&devR.nwk, 101), ZB_OK, "R receives it as a broadcast with one hop left");
    harvestAir(&devR.model, airR, &airRCount);

    Test_Expect(airRCount == 1, "and relays it once on receipt (3.6.6)");

    record = bttFor(&devR.nwk, ADDR_COORD, (uint8_t)seq);
    Test_Expect(record != 0 && record->reprotect == 1 && record->headerLen == SEC_HEADER_LEN,
          "the broadcast transaction record is a secured one, and it says so alongside the header boundary");
    Test_Expect(record != 0 && record->npduLen == SEC_HEADER_LEN + SEC_NSDU_LEN
                && (nwkFcfOf(record->npdu) & NWK_FCF_SECURITY_BIT) != 0
                && record->npdu[6] == 1 && Zb_memcmp(record->npdu + SEC_HEADER_LEN, securedNsdu, SEC_NSDU_LEN) == 0,
          "and what it stores is the unsecured forwarded copy: bit 9 kept, radius as R read it, the plaintext behind the header, the record holds the material and not a finished frame");

    Test_Expect(auxSourceOf(npduOf(&airR[0]), SEC_HEADER_LEN) == SEC_B_IEEE,
          "the copy on the air carries R's extended address in its auxiliary source field: 4.5.1.3, 'the extended 64-bit address of the device responsible for securing the frame'");
    Test_Expect(auxCounterOf(npduOf(&airR[0]), SEC_HEADER_LEN) == 1,
          "and R's own counter, from R's own descriptor: not O's 5, which is what a verbatim re-offer would have put on the air a second time");
    Test_Expect(npduLenOf(&airR[0]) == npduLenOf(&airO[0])
                && npduDiffCount(npduOf(&airR[0]), npduLenOf(&airR[0]), npduOf(&airO[0]),
                            npduLenOf(&airO[0])) > 0,
          "the same length and a different frame: everything the hop that secured it says is different");
    Test_Expect(nwkFcfOf(npduOf(&airR[0])) == NWK_FCF_DATA_SECURED && npduOf(&airR[0])[6] == 1,
          "the NWK half of the copy is the originator's frame with only the decrement and the cleared initiator to show it was relayed (3.3.1.4, 3.3.1.1.8, 3.6.4.3)");

    Security_Snapshot(&secR, &state);
    Test_Expect(state.outgoingFrameCounter[0] == 2, "R spent one counter for the one copy it issued");

    /* The device that only listens. */
    injectNpdu(&devE, npduOf(&airR[0]), npduLenOf(&airR[0]), ADDR_PEER);
    Test_ExpectStatus(Test_NwkStep(&devE.nwk, 102), ZB_OK, "and E hears R's copy");

    Test_Expect(Test_NwkPoll(&devE.nwk, inds, 4) == 1 && inds[0].securityUsed == 1
                && inds[0].nsduLength == SEC_NSDU_LEN
                && Zb_memcmp(inds[0].nsdu, securedNsdu, SEC_NSDU_LEN) == 0
                && inds[0].radiusRemaining == 0 && inds[0].srcAddr == ADDR_COORD,
          "E's indication carries the plaintext, security applied, and the originator's own address: the NWK header is O's and the security is R's, which is hop-by-hop seen from the end of the path");
    Test_Expect(Nwk_RxSecurityFailures(&devE.nwk) == 0,
          "and E verified the MIC: the assertion that the relay secured the copy correctly is made by the device that had to read it");

    Test_Expect(npduLenOf(&airR[0]) == npduLenOf(&airO[0])
                && auxSourceOf(npduOf(&airR[0]), SEC_HEADER_LEN) != auxSourceOf(npduOf(&airO[0]), SEC_HEADER_LEN)
                && auxCounterOf(npduOf(&airR[0]), SEC_HEADER_LEN) != auxCounterOf(npduOf(&airO[0]), SEC_HEADER_LEN),
          "what E heard is not what O put on the air, in both of the fields 4.5.1.3 says identify who secured it");

    Test_Expect(Nwk_RelaysSent(&devE.nwk) == 0 && Nwk_BttQueue(&devE.nwk) == 0
                && Nwk_RecognizedCommands(&devE.nwk) == 0 && Nwk_DroppedDuplicate(&devE.nwk) == 0,
          "and E relays nothing and keeps no record: 3.6.6 gives neither duty to an end device with macRxOnWhenIdle FALSE, and it needs no BTT to know that");

    /* The scheduled second retransmission, and the same listener reading it: two copies are two frames with
       two counters, and they reach the end of the path in the order they were sent, which is the only order a
       freshness window accepts. */
    Test_ExpectStatus(Test_NwkStep(&devR.nwk, 101 + NWK_PASSIVE_ACK_TIMEOUT_MS), ZB_OK, "the second retransmission, at nwkPassiveAckTimeout");
    harvestAir(&devR.model, airR, &airRCount);
    Test_Expect(airRCount == 2 && auxCounterOf(npduOf(&airR[1]), SEC_HEADER_LEN) == 2,
          "re-protected with the next counter the descriptor holds, and with the record's stored unsecured copy unchanged by it");

    Zb_memcpy(npdu, npduOf(&airR[1]), npduLenOf(&airR[1]));
    injectNpdu(&devE, npdu, npduLenOf(&airR[1]), ADDR_PEER);
    Test_ExpectStatus(Test_NwkStep(&devE.nwk, 103), ZB_OK, "and E hears the second retransmission as well");
    Test_Expect(Test_NwkPoll(&devE.nwk, inds, 4) == 1
                && inds[0].nsduLength == SEC_NSDU_LEN
                && Zb_memcmp(inds[0].nsdu, securedNsdu, SEC_NSDU_LEN) == 0
                && Nwk_RxFrameCounterRejects(&devE.nwk) == 0 && Nwk_RxSecurityFailures(&devE.nwk) == 0,
          "the second copy decrypts at its own counter: two scheduled copies are two secured frames, and a listener with no BTT is the device that shows they were never the same frame twice");

    record = bttFor(&devR.nwk, ADDR_COORD, (uint8_t)seq);
    Test_Expect(record != 0 && record->npduLen == SEC_HEADER_LEN + SEC_NSDU_LEN
                && Zb_memcmp(record->npdu + SEC_HEADER_LEN, securedNsdu, SEC_NSDU_LEN) == 0,
          "and the record still holds the unsecured copy it was made from after both retransmissions: a slot that stored protected octets would have been spent by the first one");

    Security_Snapshot(&secR, &state);
    Test_Expect(state.outgoingFrameCounter[0] == 3,
          "R's descriptor moved once per scheduled copy, which is what 4.3.1.1 step 7 counts");
}

/*
 * 7. Each indirect copy of a protected broadcast is a protected frame of its own.
 *
 * 3.2.1.1.3 item 7 and 3.6.6 step 1 make a coordinator copy a 0xffff broadcast to every sleepy end device it
 * holds an entry for, and 3.2.1.1.3 makes the security processing of any frame it sends use this device's own
 * extended address and outgoing counter. A copy is not a copy of the octets that went out on the air: it is a
 * frame this device originates for one recipient, so two children get two secured frames, each with its own
 * counter, and both differ from the broadcast they were copied from. The three are decrypted at a fixture that
 * stands for the neighbour that heard them, in issue order, which is what "each copy consumed a counter of its
 * own" means when the only evidence is the octets.
 */
void caseSecuredSleepyCopiesEachProtected(void)
{
    Test_BandA dev;
    Security sec;
    Security secPeer;
    Air air[AIR_LOG_MAX];
    Mac_Transaction *copy[2];
    Nwk_DataRequestParameters req;
    Security_Result result;
    Security_KeyState state;
    uint8_t plain[NWK_FRAME_NPDU_MAX];
    uint32_t airCount = 0;
    uint32_t plainLen = 0;
    uint32_t counters[3];
    uint32_t queued = 0;
    uint32_t i;
    Mac_Counters macCounters;

    copy[0] = 0;
    copy[1] = 0;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_COORDINATOR, 1, &sec, SEC_A_IEEE, 5, 1);
    secSeed(&secPeer, SEC_B_IEEE, 1, 1);

    seedNeighbor(&dev.nwk, ADDR_SLEEPY1, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    seedNeighbor(&dev.nwk, ADDR_SLEEPY2, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);

    req = nldeReq(NWK_ADDR_ALL_DEVICES, securedNsdu, SEC_NSDU_LEN, 2);
    req.securityEnable = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK,
                  "a coordinator's secured broadcast to 0xffff, with two sleepy children to copy it to");
    harvestAir(&dev.model, air, &airCount);

    macCounters = Mac_CountersOf(&dev.mac);
    Test_Expect(airCount == 1 && macCounters.transactionQueue == 2,
          "one copy on the air and two held as indirect transactions (3.6.6 step 1a: each is 'relay[ed] as a unicast at the MAC layer')");

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (!dev.mac.indirect.transactions[i].used)
            continue;

        if (queued < 2)
            copy[queued] = &dev.mac.indirect.transactions[i];

        queued++;
    }

    Test_Expect(queued == 2 && copy[0] != 0 && copy[1] != 0, "two queued copies to read");

    counters[0] = auxCounterOf(npduOf(&air[0]), SEC_HEADER_LEN);
    counters[1] = auxCounterOf(copy[0]->payload, SEC_HEADER_LEN);
    counters[2] = auxCounterOf(copy[1]->payload, SEC_HEADER_LEN);

    Test_Expect((nwkFcfOf(copy[0]->payload) & NWK_FCF_SECURITY_BIT) != 0
                && (nwkFcfOf(copy[1]->payload) & NWK_FCF_SECURITY_BIT) != 0,
          "each queued copy carries the security sub-field: it is a secured frame and not the broadcast with its octets reused");
    Test_Expect(copy[0]->payloadLen == SEC_HEADER_LEN + SEC_AUX_OCTETS + SEC_NSDU_LEN + SEC_MIC_OCTETS
                && copy[1]->payloadLen == copy[0]->payloadLen,
          "and each is the full secured length, 33 octets");
    Test_Expect(counters[0] != counters[1] && counters[1] != counters[2] && counters[0] != counters[2],
          "three frames, three counters: no copy reused another one's auxiliary header");

    Test_Expect(counters[0] == 5 && counters[1] != counters[2],
          "the broadcast consumed one counter and the two copies consumed two more: 5, then 6 and 7 in issue order (3.2.1.1.3)");

    Test_Expect(auxSourceOf(copy[0]->payload, SEC_HEADER_LEN) == SEC_A_IEEE
                && auxSourceOf(copy[1]->payload, SEC_HEADER_LEN) == SEC_A_IEEE,
          "every one of them secured by this device's own extended address, the coordinator's and not the child's");

    /* Decrypted in issue order, which is the order a neighbour's window is judged in. */
    Test_ExpectStatus(Security_Unprotect(&secPeer, npduOf(&air[0]), npduLenOf(&air[0]), SEC_HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "the broadcast decrypts at the peer fixture");
    Test_Expect(plainLen == SEC_NSDU_LEN && Zb_memcmp(plain, securedNsdu, SEC_NSDU_LEN) == 0
                && result.senderIeee == SEC_A_IEEE, "to the NSDU, from A");

    for (i = 0; i < 2; i++)
    {
        plainLen = 0;

        Test_ExpectStatus(Security_Unprotect(&secPeer, copy[i]->payload, copy[i]->payloadLen, SEC_HEADER_LEN,
                                        plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                      "and each queued copy decrypts with the same key, at a counter the previous one had not used");
        Test_Expect(plainLen == SEC_NSDU_LEN && Zb_memcmp(plain, securedNsdu, SEC_NSDU_LEN) == 0,
                    "to the same plaintext: two copies of one broadcast, differing in the counter alone");
    }

    Security_Snapshot(&sec, &state);
    Test_Expect(state.outgoingFrameCounter[0] == 8,
          "and the coordinator's descriptor moved three times for one request: the air copy and the two copies this module owes");
    Test_Expect(Nwk_TxSecurityFailures(&dev.nwk) == 0 && Nwk_RelaysSent(&dev.nwk) == 0,
          "no protection refused, and a queued copy is not a relay: 3.6.6's retransmission and 3.6.6 step 1's copy are different acts");
}

/*
 * 8. The reply 3.6.13 requires is this device's own frame, and this device secures it.
 *
 * An unknown command identifier, secured, addressed to this device. The frame is unprotected before anything
 * decides about it, the identifier is outside Table 3-54, and 3.6.13 answers with a Network
 * Status frame carrying 0x13. What the case pins is the reply's security: 3.6.13 step 5 hands the frame to
 * NLDE-DATA.request with no SecurityEnable printed, 4.2.2 secures a frame originating at the NWK layer unless
 * that parameter says otherwise, and 3.2.1.1.3 makes the protection use this device's own address and counter.
 * So the reply is authenticated by the device the offender came from, and its five payload octets are what
 * 3.6.13 steps 2 to 4 print.
 */
void caseSecuredUnknownCommandReply(void)
{
    Test_BandA devB;
    Security secB;
    Security secA;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[2];
    uint8_t cmd[1];
    uint8_t npdu[128];
    uint8_t plain[NWK_FRAME_NPDU_MAX];
    Security_Result result;
    uint32_t airCount = 0;
    uint32_t plainLen = 0;
    uint32_t npduLen;

    securedRig(&devB, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &secB, SEC_B_IEEE, 1, 1);
    secSeed(&secA, SEC_A_IEEE, 5, 1);
    seedNeighbor(&devB.nwk, ADDR_COORD, NWK_DEVICE_ROUTER, 1, NWK_REL_PARENT);

    cmd[0] = 0x10;     /* the first identifier Table 3-54 prints as Reserved */
    npduLen = secureNpdu(&secA, ADDR_PEER, ADDR_COORD, 2, 0x43, NWK_FRAME_TYPE_COMMAND, 0, cmd, 1,
                         npdu, (uint32_t)sizeof npdu);

    injectNpdu(&devB, npdu, npduLen, ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&devB.nwk, 100), ZB_OK, "a secured command frame with an unknown identifier, addressed to this device");
    harvestAir(&devB.model, air, &airCount);

    Test_Expect(Test_NwkPoll(&devB.nwk, inds, 2) == 0 && Nwk_ReplyCommands(&devB.nwk) == 1,
          "is answered at this layer and not passed up (3.6.13)");
    Test_Expect(airCount == 1 && airDestOf(&air[0]) == ADDR_COORD && air[0].ackRequest == 1,
          "one frame back out, aimed at the offender's address and asked to be acknowledged (3.6.13 step 5, 3.4.3.1)");

    Test_Expect((nwkFcfOf(npduOf(&air[0])) & NWK_FCF_SECURITY_BIT) != 0,
          "and the reply is secured: 4.2.2 with 3.6.13 step 5, a frame this module composed for itself");
    Test_Expect(auxSourceOf(npduOf(&air[0]), SEC_HEADER_LEN + 2 * NWK_IEEE_ADDR_OCTETS) == SEC_B_IEEE
                && auxCounterOf(npduOf(&air[0]), SEC_HEADER_LEN + 2 * NWK_IEEE_ADDR_OCTETS) == 1,
          "by this device, with its own address and its own next counter (3.2.1.1.3), behind the two IEEE address fields 3.4.3.2 requires of a status command");

    Test_ExpectStatus(Security_Unprotect(&secA, npduOf(&air[0]), npduLenOf(&air[0]),
                                    SEC_HEADER_LEN + 2 * NWK_IEEE_ADDR_OCTETS, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "the reply authenticates at the fixture of the device it was sent to");
    Test_Expect(result.senderIeee == SEC_B_IEEE,
          "and the auxiliary source names the hop that secured it: 4.5.1.3, the device responsible");
    Test_Expect(plainLen == 3 && plain[0] == NWK_CMD_NETWORK_STATUS && plain[1] == NWK_NETWORK_STATUS_UNKNOWN_COMMAND
                && plain[2] == 0x10,
          "three payload octets as 3.4.3.3.2 prints them: the identifier, 0x13 Unknown Command, and the octet it did not support");
    Test_Expect(Nwk_RxSecurityFailures(&devB.nwk) == 0 && Nwk_RxFrameCounterRejects(&devB.nwk) == 0
                && Nwk_DroppedUnsupported(&devB.nwk) == 0 && Nwk_TxSecurityFailures(&devB.nwk) == 0,
          "and nothing about that exchange was a refusal");
}

/*
 * 9. 3.6.2.2's unsecured discard, at a device that is joined and authenticated.
 *
 * The clause is quoted in src/zb/nwk/nwk_rx.c at `Nwk_RxUnsecuredAccepted`; what it decides here is four frames and one
 * carve-out. An unsecured unicast data frame and an unsecured broadcast data frame are both discarded: the sentence
 * names "a NWK data frame" and does not narrow it. The carve-out is the rejoin request, and only for the device it is
 * destined to. Everything else the same paragraph prints is "dropped and no further processing SHALL be done", which
 * band A reads as closing the command-frame sentence too: an unknown identifier at a joined device draws no 3.6.13
 * reply, because the frame never reached the point where a reply is decided.
 *
 * The scaffold beside it is the point of level 0: the same four frames at a device with no
 * `Security` attached are delivered and answered exactly as the suites above deliver and answer them. The
 * clause's other half is the opposite reading of the same sentence: a device that is not joined and
 * authenticated drops every unsecured frame but 0x07, so even 0x06 draws nothing there.
 */
void caseUnsecuredDiscardWhileAuthenticated(void)
{
    Test_BandA devAuth;
    Test_BandA devScaffold;
    Test_BandA devUnjoined;
    Security secAuth, secUnjoined;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    uint8_t cmd[1];
    uint8_t npdu[128];
    uint32_t npduLen;
    uint32_t airCount = 0;

    securedRig(&devAuth, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &secAuth, SEC_B_IEEE, 1, 1);

    rigAt(&devScaffold, ADDR_PEER, PAN_ID, NWK_DEVICE_ROUTER, 1);
    seedNeighbor(&devScaffold.nwk, ADDR_COORD, NWK_DEVICE_ROUTER, 1, NWK_REL_PARENT);

    securedRig(&devUnjoined, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &secUnjoined, SEC_B_IEEE, 1, 0);

    npduLen = makeNpdu(npdu, ADDR_PEER, ADDR_COORD, 2, 0x50, NWK_FRAME_TYPE_DATA, 0, securedNsdu, SEC_NSDU_LEN);
    injectNpdu(&devAuth, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&devAuth.nwk, 100), ZB_OK, "an unsecured unicast data frame at a joined, authenticated router");
    harvestAir(&devAuth.model, air, &airCount);
    Test_Expect(Nwk_DroppedUnsecured(&devAuth.nwk) == 1 && Test_NwkPoll(&devAuth.nwk, inds, 4) == 0,
          "is discarded with the reason 3.6.2.2 prints ('the device is currently joined and authenticated, and the incoming frame is a NWK data frame, the NLDE SHALL discard the frame') and not indicated");

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, ADDR_COORD, 1, 0x51, NWK_FRAME_TYPE_DATA, 0, securedNsdu, SEC_NSDU_LEN);
    injectNpdu(&devAuth, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&devAuth.nwk, 101), ZB_OK, "and an unsecured broadcast data frame");
    harvestAir(&devAuth.model, air, &airCount);
    Test_Expect(Nwk_DroppedUnsecured(&devAuth.nwk) == 2 && Test_NwkPoll(&devAuth.nwk, inds, 4) == 0
                && Nwk_BttQueue(&devAuth.nwk) == 0 && airCount == 0 && Nwk_RelaysSent(&devAuth.nwk) == 0,
          "is discarded the same way, with no record and no retransmission: 'no further processing SHALL be done' is the whole of what the discard costs");

    /* The carve-out the clause prints, and the destination condition attached to it. */
    cmd[0] = NWK_CMD_REJOIN_REQUEST;
    npduLen = makeNpdu(npdu, ADDR_PEER, ADDR_COORD, 2, 0x52, NWK_FRAME_TYPE_COMMAND, 0, cmd, 1);
    injectNpdu(&devAuth, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&devAuth.nwk, 102), ZB_OK, "an unsecured rejoin request addressed to this device");
    harvestAir(&devAuth.model, air, &airCount);

    Test_Expect(Nwk_DroppedUnsecured(&devAuth.nwk) == 2 && Test_NwkPoll(&devAuth.nwk, inds, 4) == 0
                && Nwk_ReplyCommands(&devAuth.nwk) == 1 && airCount == 1 && Nwk_DroppedNoRoute(&devAuth.nwk) == 0,
          "rides on: 3.6.2.2's carve-out admits a command destined to this device, and 3.6.13's answer goes out because 3.6.1.7 observed the coordinator the request came from");

    cmd[0] = NWK_CMD_REJOIN_REQUEST;
    npduLen = makeNpdu(npdu, ADDR_ELSEWHERE, ADDR_COORD, 2, 0x53, NWK_FRAME_TYPE_COMMAND, 0, cmd, 1);
    injectNpdu(&devAuth, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&devAuth.nwk, 103), ZB_OK, "and the same identifier addressed to another device");
    Test_Expect(Nwk_DroppedUnsecured(&devAuth.nwk) == 3 && Test_NwkPoll(&devAuth.nwk, inds, 4) == 0
                && Nwk_RelaysSent(&devAuth.nwk) == 0 && Nwk_ReplyCommands(&devAuth.nwk) == 1,
          "is dropped: the carve-out is for the device the rejoin is asking, and a frame this device would only forward is not destined to it");

    cmd[0] = 0x10;
    npduLen = makeNpdu(npdu, ADDR_PEER, ADDR_COORD, 2, 0x54, NWK_FRAME_TYPE_COMMAND, 0, cmd, 1);
    injectNpdu(&devAuth, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&devAuth.nwk, 104), ZB_OK, "and an unsecured identifier from the Reserved band");
    harvestAir(&devAuth.model, air, &airCount);
    Test_Expect(Nwk_DroppedUnsecured(&devAuth.nwk) == 4 && Nwk_ReplyCommands(&devAuth.nwk) == 1 && airCount == 1,
          "draws no 3.6.13 reply: the unsecured discard closes the frame before a reply is decided, and the one frame on the air is the rejoin request's answer, drawn a step earlier");

    Test_Expect(Nwk_RxSecurityFailures(&devAuth.nwk) == 0 && Nwk_RxFrameCounterRejects(&devAuth.nwk) == 0
                && Nwk_DroppedNotForMe(&devAuth.nwk) == 0 && Nwk_DroppedMalformed(&devAuth.nwk) == 0
                && Nwk_DroppedUnsupported(&devAuth.nwk) == 0 && Nwk_RefusedRequests(&devAuth.nwk) == 0,
          "and none of it was counted under another name");

    /* The scaffold: no `Security`, no policy, every frame as the suites above read it. */
    npduLen = makeNpdu(npdu, ADDR_PEER, ADDR_COORD, 2, 0x50, NWK_FRAME_TYPE_DATA, 0, securedNsdu, SEC_NSDU_LEN);
    injectNpdu(&devScaffold, npdu, npduLen, ADDR_COORD);

    npduLen = makeNpdu(npdu, NWK_ADDR_ALL_DEVICES, ADDR_COORD, 1, 0x51, NWK_FRAME_TYPE_DATA, 0, securedNsdu, SEC_NSDU_LEN);
    injectNpdu(&devScaffold, npdu, npduLen, ADDR_COORD);

    cmd[0] = 0x10;
    npduLen = makeNpdu(npdu, ADDR_PEER, ADDR_COORD, 2, 0x54, NWK_FRAME_TYPE_COMMAND, 0, cmd, 1);
    injectNpdu(&devScaffold, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&devScaffold.nwk, 105), ZB_OK, "the same three frames at a scaffold router with no security attached");
    harvestAir(&devScaffold.model, air, &airCount);

    Test_Expect(Test_NwkPoll(&devScaffold.nwk, inds, 4) == 2 && Nwk_DroppedUnsecured(&devScaffold.nwk) == 0
                && Nwk_ReplyCommands(&devScaffold.nwk) == 1 && airCount == 2 && Nwk_BttQueue(&devScaffold.nwk) == 1,
          "are delivered, recorded and answered as they always were, the two frames on the air being the broadcast's relay and 3.6.13's reply: 3.6.2.2's discard is conditioned on a non-zero nwkSecurityLevel");

    /* And the clause's own other half: a device that is not joined and authenticated drops everything but 0x07, so
       the joined half's 0x06 carve-out does not reach it. */
    npduLen = makeNpdu(npdu, ADDR_PEER, ADDR_COORD, 2, 0x50, NWK_FRAME_TYPE_DATA, 0, securedNsdu, SEC_NSDU_LEN);
    injectNpdu(&devUnjoined, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&devUnjoined.nwk, 106), ZB_OK, "the unsecured unicast at a device with keys but no join");
    Test_Expect(Test_NwkPoll(&devUnjoined.nwk, inds, 4) == 0 && Nwk_DroppedUnsecured(&devUnjoined.nwk) == 1,
          "is discarded: 3.6.2.2's other half drops every unsecured frame at a device that is not joined and authenticated, whatever its type");

    cmd[0] = NWK_CMD_REJOIN_REQUEST;
    npduLen = makeNpdu(npdu, ADDR_PEER, ADDR_COORD, 2, 0x55, NWK_FRAME_TYPE_COMMAND, 0, cmd, 1);
    injectNpdu(&devUnjoined, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&devUnjoined.nwk, 107), ZB_OK, "and an unsecured rejoin request at the same device");
    Test_Expect(Test_NwkPoll(&devUnjoined.nwk, inds, 4) == 0 && Nwk_DroppedUnsecured(&devUnjoined.nwk) == 2,
          "is discarded too: 0x06 is the joined device's carve-out, and the unjoined half admits 0x07 alone");
}

/*
 * 10. 4.3.1.2 step 8: the hop a frame authenticates is the entry the neighbour table promotes.
 *
 * "If there is an entry in nwkNeighborTable in the NIB whose extended address matches SenderAddress and whose
 * relationship field has value 0x05 (unauthenticated child), then set relationship field in that entry to the
 * value 0x01 (child)". SenderAddress is the auxiliary source field, which 4.5.1.3 pins to the device that
 * secured the frame, and Security_Unprotect hands it up for exactly this act: the NWK's duty and not the
 * security module's. The entry has to be one somebody seeded: band A learns an IEEE address only from a frame
 * that carries one, and association is ZDO work that is deferred.
 */
void caseAuthenticatedHopPromotion(void)
{
    Test_BandA dev;
    Security sec;
    Nwk_NeighborTableEntry *neighbor;
    Nwk_DataIndicationParameters inds[2];
    uint8_t npdu[64];
    uint32_t npduLen;

    securedRig(&dev, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &sec, SEC_B_IEEE, 1, 1);

    seedNeighbor(&dev.nwk, ADDR_COORD, NWK_DEVICE_END_DEVICE, 1, NWK_REL_UNAUTHENTICATED_CHILD);
    neighbor = neighborAt(&dev.nwk, ADDR_COORD);
    Test_Expect(neighbor != 0 && neighbor->relationship == NWK_REL_UNAUTHENTICATED_CHILD,
          "an entry Table 3-75 says 0x05, unauthenticated child, which is the relationship 4.3.1.2 step 8 exists to change");

    if (neighbor != 0)
    {
        neighbor->extendedAddress = SEC_A_IEEE;
        neighbor->ieeeKnown = 1;
    }

    npduLen = octetsOf(s_frame1Hex, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a secured frame whose auxiliary source address is that device's");

    neighbor = neighborAt(&dev.nwk, ADDR_COORD);
    Test_Expect(neighbor != 0 && neighbor->relationship == NWK_REL_CHILD,
          "step 8 fires on the IEEE match and the relationship reads 0x01: the hop that secured the frame is authenticated now, and it is the NWK that records it (4.3.1.2 step 8, 4.5.1.3)");
    Test_Expect(neighbor != 0 && neighbor->deviceType == NWK_DEVICE_END_DEVICE,
          "and nothing else about the entry moved: a frame says an address, not what kind of device lives there");
    Test_Expect(Test_NwkPoll(&dev.nwk, inds, 2) == 1 && inds[0].securityUsed == 1
                && Nwk_RxSecurityFailures(&dev.nwk) == 0 && Nwk_NeighborQueue(&dev.nwk) == 1,
          "the frame was delivered, and the promotion created no entry and cost no refusal");
}

/*
 * 11. A protection that cannot happen, answered through the confirm ring.
 *
 * 4.3.1.1 step 1: "If the outgoing frame counter is equal to 2^32-1 … security processing SHALL fail and no
 * further security processing SHALL be done on this frame." The request is still accepted, because protection is
 * an act of the attempt and not of the door, and an accepted request answers through the confirm ring, which is
 * where this failure surfaces: the seam's own status beside Table 3-84's 0xcc MAX_FRM_COUNTER,
 * `Nwk_TxConfirmStatus`-named mapping aside, nothing on the air, no attempt counted, and the descriptor's
 * counter untouched because step 7 runs only for a frame that became the secured frame.
 *
 * The second half is the other refusal the module can answer with and Table 3-84 prints no code for: a secured
 * frame longer than the band's own 127-octet ceiling (4.3.1.1 step 6). It is reported as
 * the seam named it.
 */
void caseProtectionRefusedIsAConfirm(void)
{
    Test_BandA dev;
    Security sec;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[4];
    Nwk_DataRequestParameters req;
    Security_KeyState state;
    uint8_t big[NWK_NSDU_MAX];
    uint32_t airCount = 0;
    uint32_t got;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_ROUTER, 1, &sec, SEC_A_IEEE, 5, 1);
    seedNeighbor(&dev.nwk, ADDR_PEER, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    Zb_memset(big, 0xa5, (uint32_t)sizeof big);

    /* First the length: 8 octets of header plus 108 of NSDU is a legal unsecured NPDU and an impossible
       secured one (8 + 14 + 108 + 4 = 134 over a 127-octet ceiling). */
    req = nldeReq(ADDR_PEER, big, NWK_NSDU_MAX, 0);
    req.securityEnable = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK,
                  "a secured request at Table 3-2's NSDU ceiling is accepted: the door composes the unsecured frame and never runs protection, so the length is not the door's to judge (3.2.1.1.3)");
    harvestAir(&dev.model, air, &airCount);

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_NO_SPACE
                && confirms[0].nwkStatus == NWK_STATUS_LAST_MAC_STATUS && confirms[0].attempts == 0,
          "and the attempt refuses it: ZB_ERR_NO_SPACE from 4.3.1.1 step 6's ceiling, with no Table 3-84 code for a length");
    Test_Expect(airCount == 0 && Nwk_TransmitQueue(&dev.nwk) == 0 && Nwk_TxSecurityFailures(&dev.nwk) == 1,
          "nothing on the air, the slot released by its own answer, and the failure counted as a protection refused on an attempt this module owed");

    Security_Snapshot(&sec, &state);
    Test_Expect(state.outgoingFrameCounter[0] == 5,
          "and the descriptor's counter unmoved: 4.3.1.1 step 7 updates the counter of a frame that became the secured frame, and this one never did");

    /* Now the exhausted counter, seeded by a fresh Security_Init over the same struct: the reseed the
       application makes, used here to reach the value step 1 names. */
    secSeed(&sec, SEC_A_IEEE, SECURITY_FRAME_COUNTER_LAST, 1);

    req = nldeReq(ADDR_PEER, securedNsdu, SEC_NSDU_LEN, 0);
    req.securityEnable = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 200), ZB_OK,
                  "a request at a device whose outgoing counter is 2^32-1: accepted, because 4.3.1.1 step 1 is the attempt's test and not the door's");
    harvestAir(&dev.model, air, &airCount);

    got = Nwk_PollConfirms(&dev.nwk, confirms, 4);
    Test_Expect(got == 1 && confirms[0].status == ZB_ERR_BAD_FRAME_COUNTER,
          "answered with the seam's own word for the refusal");
    Test_Expect(got == 1 && confirms[0].nwkStatus == NWK_STATUS_MAX_FRM_COUNTER,
          "and Table 3-84's 0xcc beside it: the frame counter has reached its maximum value");
    Test_Expect(got == 1 && confirms[0].attempts == 0 && confirms[0].seq == 1,
          "no attempt was made, and the confirmation still names the frame composed and numbered (3.3.1.5, 3.6.2.2)");
    Test_Expect(airCount == 0 && Nwk_TransmitQueue(&dev.nwk) == 0 && Nwk_TxSecurityFailures(&dev.nwk) == 2,
          "nothing on the air and no retry scheduled: 3.2.1.1.3 discards the frame a failed security processing");

    Security_Snapshot(&sec, &state);
    Test_Expect(state.outgoingFrameCounter[0] == SECURITY_FRAME_COUNTER_LAST,
          "and the exhausted counter stayed exhausted: 4.3.1.1 step 1 fails before step 7, and nothing here wraps it or resets it (4.3.4's reset duties are the application's over the snapshot)");
    Test_Expect(Nwk_RefusedRequests(&dev.nwk) == 0 && Nwk_DroppedNoRoute(&dev.nwk) == 0,
          "and neither request was a refusal at the door or a routing discard: both were taken back and answered");
}

/*
 * 12. Attached and detached, and what each state means.
 *
 * `Nwk_AttachSecurity` is the whole of the crossing's wiring: a `Security` adopted by pointer, and a 0 that
 * puts the module back where the suites above left it. Detaching is not a subtle state: a secured request is
 * refused again, a secured frame received is counted as unreadable, and an unsecured request flows with no
 * security call anywhere in its path.
 */
void caseAttachAndDetach(void)
{
    Test_BandA dev;
    Security sec;
    Air air[AIR_LOG_MAX];
    Nwk_DataConfirmParameters confirms[2];
    Nwk_DataIndicationParameters inds[2];
    Nwk_DataRequestParameters req;
    uint8_t npdu[64];
    uint32_t airCount = 0;
    uint32_t npduLen;
    uint32_t got;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_ROUTER, 1, &sec, SEC_A_IEEE, 5, 1);
    seedNeighbor(&dev.nwk, ADDR_PEER, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    req = nldeReq(ADDR_PEER, securedNsdu, SEC_NSDU_LEN, 0);
    req.securityEnable = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 100), ZB_OK, "attached: a secured request is honoured");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1 && (nwkFcfOf(npduOf(&air[0])) & NWK_FCF_SECURITY_BIT) != 0, "and secured on the air");

    Nwk_AttachSecurity(&dev.nwk, 0);
    Test_Expect(dev.nwk.security == 0, "detached");

    req = nldeReq(ADDR_PEER, securedNsdu, SEC_NSDU_LEN, 0);
    req.securityEnable = 1;
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 200), ZB_ERR_UNSUPPORTED,
                  "and the same request is refused with the reason 4.2.2 gives it: no procedure to run at a device with no `Security`, counted as a refusal at the door");

    npduLen = secureNpdu(&sec, ADDR_COORD, ADDR_PEER, 2, 0x44, NWK_FRAME_TYPE_DATA, 0, securedNsdu,
                         SEC_NSDU_LEN, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_PEER);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 201), ZB_OK, "a secured frame from a neighbor arrives, and the first transmission is answered");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(Nwk_DroppedUnsupported(&dev.nwk) == 1 && Nwk_RxSecurityFailures(&dev.nwk) == 0
                && Test_NwkPoll(&dev.nwk, inds, 2) == 0,
          "the secured frame is unreadable and counted as unsupported: the codec reads the bit, this module has no key behind it");

    got = Nwk_PollConfirms(&dev.nwk, confirms, 2);
    Test_Expect(got == 1 && confirms[0].status == ZB_OK && confirms[0].nwkStatus == NWK_STATUS_SUCCESS,
          "and the frame that was sent while security was attached is answered as the secured delivery it was");

    req = nldeReq(ADDR_PEER, securedNsdu, SEC_NSDU_LEN, 0);
    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, 300), ZB_OK, "and an unsecured request flows, because that is the scaffold contract");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect((nwkFcfOf(npduOf(&air[1])) & NWK_FCF_SECURITY_BIT) == 0
                && npduLenOf(&air[1]) == SEC_HEADER_LEN + SEC_NSDU_LEN,
          "the plain eight-octet header and the NSDU, with no auxiliary header and no refusal counted for asking");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 301), ZB_OK, "answered");
    got = Nwk_PollConfirms(&dev.nwk, confirms, 2);
    Test_Expect(got == 1 && confirms[0].status == ZB_OK && confirms[0].nwkStatus == NWK_STATUS_SUCCESS,
          "SUCCESS in both vocabularies, as an unsecured delivery always answered");
    Test_Expect(Nwk_RefusedRequests(&dev.nwk) == 1 && Nwk_TxSecurityFailures(&dev.nwk) == 0
                && Nwk_RxSecurityFailures(&dev.nwk) == 0 && Nwk_DroppedUnsecured(&dev.nwk) == 0,
          "one refusal counted, the one the door made, and no security act anywhere else in the case");
}

/*
 * 13. A secured command frame with nothing inside it is damage, and damage only.
 *
 * s6, the 26 octets quoted above: a level 0x05 protected NWK command frame whose plaintext is empty, 8 of NWK
 * header, 14 of auxiliary header, 4 of MIC, and no ciphertext octet between the header and the MIC. Its
 * provenance is the same as every other vector here and in the `security` suite: the corpus publishes no secured
 * NWK frame of any shape, still less an empty one, so this one was computed from 4.3.1.1 by the independent
 * CPython implementation that produced s1 and s5, at this part's own key and this part's own
 * sender, and quoted here rather than recomputed. That oracle reproduces s1 and s5 octet for octet before it
 * produced this frame, and the frame it produced then authenticates at this stack's own `Security_Unprotect` in
 * the second block below: those two computations, and not this module talking to itself, are what stand behind
 * every assertion in the case.
 *
 * Two rules are in force on these octets at once, and they are not rules about the same thing. 3.3.2.2.2 with
 * Figure 3-8 make a command frame a frame that carries a payload (one octet of Table 3-54 identifier is what
 * makes it a command) and `nwk_frame` enforces that on the NPDU it is handed, where a secured frame's payload
 * region is everything past the header fields: 18 octets here, the auxiliary header and the MIC, and the codec is
 * right to read the frame. 4.3.1.2 step 5b then hands this layer `NwkHeader || m`, and this frame's m is zero
 * octets long. Satisfying the codec's payload rule and satisfying the command path's need for an identifier are
 * separate facts about separate octets, and the first is no evidence for the second.
 *
 * What is therefore decided here is what the command path may read. After an empty unprotection `payload` points
 * at a scratch buffer this frame never wrote, and `payload[0]` is whatever the previous frame left there: an
 * identifier this device invented, which would decide recognition, a 3.6.13 answer and an indication on the
 * strength of octets that name nothing. A command frame with no identifier octet is not a command frame (that is
 * 3.3.2.2.2 with Figure 3-8, the same rule `nwk_frame` enforces on transmitted frames) and a frame whose
 * plaintext names nothing is a frame this stack cannot act on, which is what `droppedMalformed` is for (3.6.2.2,
 * 3.6.6). So it is counted as damage and the delivery machinery is not entered, while the security half (which
 * did its work correctly and first) keeps its verdict: the MIC verified, the counter was fresh, and the sender's
 * window moved. That is why the counters of this case read the way they do, and why the second copy of the frame
 * is refused by the counter rather than by the guard.
 *
 * The scaffold half is the same 26 octets at a router with no `Security` attached. There the frame is unreadable
 * before it is anything else (no key behind the bit, so no plaintext, empty or otherwise) and it is counted
 * `droppedUnsupported` and never `droppedMalformed`: the crossing is what turns this shape into
 * readable-but-empty damage at all. Case 12 pins the same counter for a detached device's secured *data* frame;
 * what this half adds is that the frame's shape changes nothing about it.
 */
void caseSecuredCommandEmptyPlaintextIsDamage(void)
{
    Test_BandA devB;
    Test_BandA devScaffold;
    Security secB, secRead;
    Air airB[AIR_LOG_MAX];
    Air airScaffold[AIR_LOG_MAX];
    Nwk_Frame frame;
    Security_KeyState state;
    Security_Result hop;
    Nwk_DataIndicationParameters inds[2];
    uint8_t vector[64];
    uint8_t plain[NWK_FRAME_NPDU_MAX];
    uint32_t airBCount = 0;
    uint32_t airScaffoldCount = 0;
    uint32_t vectorLen;
    uint32_t codecHeaderLen = 0;
    uint32_t codecPayloadRegion = 0;
    uint32_t plainLen = 0;

    vectorLen = octetsOf(s_frame6Hex, vector, (uint32_t)sizeof vector);
    Test_Expect(vectorLen == SEC_HEADER_LEN + SEC_AUX_OCTETS + SEC_MIC_OCTETS,
          "s6 is 26 octets: NwkHeader || AuxiliaryHeader || c || MIC, with c empty, 8 + 14 + 0 + 4 (4.3.1.1 step 5)");
    Test_Expect((nwkFcfOf(vector) & NWK_FRAME_FCF_TYPE_MASK) == NWK_FRAME_TYPE_COMMAND
                && (nwkFcfOf(vector) & NWK_FCF_SECURITY_BIT) != 0,
          "its Frame Control Field is 0x0209: frame type Command, nwkcProtocolVersion 0x02, the security sub-field set (3.3.1.1.4, 4.3.2)");
    Test_Expect(auxCounterOf(vector, SEC_HEADER_LEN) == 9
                && auxSourceOf(vector, SEC_HEADER_LEN) == SEC_A_IEEE
                && auxKeySeqOf(vector, SEC_HEADER_LEN) == 0x00,
          "and the auxiliary header carries A's counter 0x00000009, A's extended address and key sequence number 0x00: the same sender and the same key as s1, further along the counter (4.5.1.3)");

    /* The two halves of the sentence, measured on the same octets: what the codec sees, and what the security
       module hands up. */
    Test_ExpectStatus(NwkFrame_Parse(vector, vectorLen, &frame, &codecHeaderLen, &codecPayloadRegion), ZB_OK,
                  "the codec reads it, because 3.3.2.2.2's demand that a command frame carry a payload is a demand about the NPDU, and this NPDU has octets past its header fields");
    Test_Expect(frame.frameType == NWK_FRAME_TYPE_COMMAND && frame.securityEnabled == 1
                && codecHeaderLen == SEC_HEADER_LEN && codecPayloadRegion == SEC_AUX_OCTETS + SEC_MIC_OCTETS,
          "a command frame, secured, with an 18-octet payload region: the auxiliary header and the MIC, which is every octet the frame has and none of it plaintext");

    secSeed(&secRead, SEC_B_IEEE, 1, 1);

    Test_ExpectStatus(Security_Unprotect(&secRead, vector, vectorLen, SEC_HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &hop), ZB_OK,
                  "the frame authenticates at a fixture of B's shape: the MIC over a ciphertext of nothing verifies, so this is a protected frame and not a forgery (4.3.1.2 steps 4 and 5a)");
    Test_Expect(plainLen == 0,
          "and step 5b hands back NwkHeader || m with m empty: there is no octet left that could name a command");
    Test_Expect(hop.senderIeee == SEC_A_IEEE && hop.keySeqNumber == 0x00 && hop.frameCounter == 9,
          "the hop it names is A, the key is 0x00 and the count the frame carried is 9");

    /* And now through the whole receive path, at B, which is where the two halves meet. */
    securedRig(&devB, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &secB, SEC_B_IEEE, 1, 1);
    Test_Expect(secB.incoming[0].inUse == 0, "the fixture holds no window for any sender before the frame arrives");

    injectNpdu(&devB, vector, vectorLen, ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&devB.nwk, 100), ZB_OK,
                  "s6 delivered to B as a neighbor's MAC data frame: destination B's own short address, NWK source 0x0000 (not B's) and A's extended address behind the security bit");
    harvestAir(&devB.model, airB, &airBCount);

    Test_Expect(Nwk_RxSecurityFailures(&devB.nwk) == 0 && Nwk_RxFrameCounterRejects(&devB.nwk) == 0
                && Nwk_TxSecurityFailures(&devB.nwk) == 0,
          "the unprotection succeeded: no security failure and no counter refusal is counted, because nothing about the frame's security was wrong (4.3.1.2 steps 3, 5a)");
    Test_Expect(secB.incoming[0].inUse == 1 && secB.incoming[0].senderIeee == SEC_A_IEEE
                && secB.incoming[0].keySeqNumber == 0x00 && secB.incoming[0].frameCounter == 10,
          "and the sender's window moved to ReceivedFrameCount + 1, 10, under A's auxiliary address and key 0x00 (4.3.1.2 step 6)");

    Test_Expect(Nwk_DroppedMalformed(&devB.nwk) == 1,
          "the network layer counted the frame as the damage it is: a command frame with no identifier octet in its plaintext is not a command frame, whatever it was that satisfied the codec");
    Test_Expect(Nwk_DroppedUnsupported(&devB.nwk) == 0 && Nwk_DroppedUnsecured(&devB.nwk) == 0
                && Nwk_DroppedNotForMe(&devB.nwk) == 0 && Nwk_DroppedDuplicate(&devB.nwk) == 0
                && Nwk_DroppedNoRoute(&devB.nwk) == 0 && Nwk_RefusedRequests(&devB.nwk) == 0,
          "and under that name alone: not a form this device declines to read, not the unsecured discard, not a destination gate, not a dedup, not a routing refusal");
    Test_Expect(Test_NwkPoll(&devB.nwk, inds, 2) == 0 && Nwk_IndicationQueue(&devB.nwk) == 0
                && Nwk_DroppedIndications(&devB.nwk) == 0,
          "nothing is indicated upward, and nothing was thrown away to make room for an indication: there was no command to hand up");
    Test_Expect(Nwk_RecognizedCommands(&devB.nwk) == 0 && Nwk_ReplyCommands(&devB.nwk) == 0
                && airBCount == 0 && Nwk_TransmitQueue(&devB.nwk) == 0,
          "no identifier was recognized and no 3.6.13 answer was decided, with nothing on the air and nothing queued");
    Test_Expect(Nwk_RelaysSent(&devB.nwk) == 0 && Nwk_BttQueue(&devB.nwk) == 0 && Nwk_NeighborQueue(&devB.nwk) == 1,
          "no relay and no broadcast record, which a unicast keeps neither of, and one neighbor entry: the NWK source these octets name is 0x0000, and 3.6.1.7 observes the coordinator before the payload is read");

    Security_Snapshot(&secB, &state);
    Test_Expect(state.keyCount == 1 && state.keySeqNumber[0] == 0x00 && state.outgoingFrameCounter[0] == 1,
          "and B's own descriptor is where it started: a frame this device threw away spent none of its counters, and it secured nothing it could have answered with (4.3.1.1 step 7)");

    /* The window the accepted frame stored is what refuses the same 26 octets a second time, which is the proof
       that the damage is counted after the security half rather than instead of it. */
    injectNpdu(&devB, vector, vectorLen, ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&devB.nwk, 101), ZB_OK, "the identical frame again");
    harvestAir(&devB.model, airB, &airBCount);

    Test_Expect(Nwk_RxFrameCounterRejects(&devB.nwk) == 1 && Nwk_DroppedMalformed(&devB.nwk) == 1
                && Test_NwkPoll(&devB.nwk, inds, 2) == 0 && airBCount == 0,
          "refused by the freshness window and not by the guard: the first copy moved A's window to 10 (4.3.1.2 step 3)");

    /* The scaffold: the same octets at a device the crossing has not been built into. */
    rigAt(&devScaffold, ADDR_PEER, PAN_ID, NWK_DEVICE_ROUTER, 1);

    injectNpdu(&devScaffold, vector, vectorLen, ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&devScaffold.nwk, 102), ZB_OK, "s6 at a router with no `Security` attached");
    harvestAir(&devScaffold.model, airScaffold, &airScaffoldCount);

    Test_Expect(Nwk_DroppedUnsupported(&devScaffold.nwk) == 1 && Nwk_DroppedMalformed(&devScaffold.nwk) == 0,
          "is an unreadable form and not damage: with no key behind the bit there is no plaintext at all, empty or otherwise, so the emptiness this guard names is never reached");
    Test_Expect(Test_NwkPoll(&devScaffold.nwk, inds, 2) == 0 && Nwk_ReplyCommands(&devScaffold.nwk) == 0
                && Nwk_RecognizedCommands(&devScaffold.nwk) == 0 && airScaffoldCount == 0
                && Nwk_RxSecurityFailures(&devScaffold.nwk) == 0 && Nwk_RxFrameCounterRejects(&devScaffold.nwk) == 0,
          "and the scaffold discards it just as completely: nothing indicated, nothing answered, nothing on the air, and no security counter moved at a device that ran no security");
}

/*
 * 3.6.2.2's carve-out, judged as the clause prints it: "If the security sub-field is set to 0, the
 * nwkSecurityLevel attribute in the NIB is non-zero, and the incoming frame is a NWK command frame and the
 * command ID is 0x06 (rejoin request), the NLDE SHALL only accept the frame if it is destined to itself, that
 * is, if it does not need to be forwarded to another device. Otherwise the frame SHALL be dropped and no further
 * processing SHALL be done."
 *
 * A rejoin request on a Table 3-80 class is the one unsecured command the clause lets a single device accept,
 * and a broadcast address is by definition a frame other devices were meant to hear: judging the carve-out on
 * the destination *class* makes it the one frame the whole mesh would accept, record, indicate and relay.
 */
void caseUnsecuredRejoinOnABroadcastIsDropped(void)
{
    Test_BandA dev;
    Air air[AIR_LOG_MAX];
    Nwk_DataIndicationParameters inds[4];
    Security sec;
    uint8_t cmd[1];
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    securedRig(&dev, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &sec, SEC_B_IEEE, 1, 1);

    cmd[0] = NWK_CMD_REJOIN_REQUEST;

    npduLen = makeNpdu(npdu, NWK_ADDR_ROUTERS, ADDR_COORD, 4, 0x61, NWK_FRAME_TYPE_COMMAND, 0, cmd, 1);
    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK,
                      "an unsecured rejoin request addressed to the routers' class, at a device that is joined and authenticated");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_DroppedUnsecured(&dev.nwk), 1,
                     "is dropped: the class is not 'destined to itself', and the clause's carve-out is the only way an unsecured command frame gets past the discard");
    Test_ExpectCount(Nwk_BttQueue(&dev.nwk), 0, "no broadcast transaction record is claimed for it");
    Test_ExpectCount(Nwk_RelaysSent(&dev.nwk), 0, "nothing is relayed: 'no further processing SHALL be done'");
    Test_ExpectCount(Test_NwkPoll(&dev.nwk, inds, 4), 0, "and nothing is handed up");
    Test_ExpectCount(airCount, 0, "with nothing on the air at all");

    /* The same frame addressed to this device is the case the carve-out is written for, and it is admitted. */
    npduLen = makeNpdu(npdu, ADDR_PEER, ADDR_COORD, 4, 0x62, NWK_FRAME_TYPE_COMMAND, 0, cmd, 1);
    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "and the same unsecured request addressed to this device itself");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_DroppedUnsecured(&dev.nwk), 1,
                     "is not dropped: it needs no forwarding to another device, which is the condition the clause prints");
}

/*
 * 3.6.2.2's second half, printed for a device that is not joined and authenticated: an unsecured NWK data frame is
 * accepted only if the APDU behind it is Table 4-31's Transport Key command. This is the reader the clause asks the
 * network layer for, and the reason 4.6.3.2.1 forbids the sender to secure that frame: the joiner has no key to
 * unprotect it with.
 */
void caseUnsecuredTransportKeyAccepted(void)
{
    Test_BandA dev;
    uint8_t payload[8];

    rig(&dev, OWN_SHORT, PAN_ID);

    Zb_memset(payload, 0, (uint32_t)sizeof payload);

    payload[0] = 0x41;             /* Figure 2-4: frame type 0x01 command, unicast, AR set, security clear */
    payload[1] = 0x2b;             /* the APS counter */
    payload[2] = 0x05;             /* Table 4-31's Transport Key, the payload's first octet (Figure 2-8) */

    Test_Expect(Nwk_RxCarriesTransportKey(payload, (uint32_t)sizeof payload) == 1,
          "an APS command whose identifier is 0x05 is the one unsecured data frame 3.6.2.2 lets a joining device see");

    payload[2] = 0x06;
    Test_Expect(Nwk_RxCarriesTransportKey(payload, (uint32_t)sizeof payload) == 0,
          "0x06, Table 4-31's Update Device, is not: the clause names 0x05 and nothing else");

    payload[0] = 0x61;             /* the same command with APS security set */
    payload[2] = 0x30;             /* 4.4.10's security control where the identifier was, as a trust centre sends it */
    Test_Expect(Nwk_RxCarriesTransportKey(payload, (uint32_t)sizeof payload) == 1,
          "an APS-secured command is passed whatever octet 2 holds: the auxiliary header sits there and the identifier is encrypted behind it, so `aps` judges it after unsecuring");

    payload[2] = 0x05;
    payload[0] = 0x20;
    Test_Expect(Nwk_RxCarriesTransportKey(payload, (uint32_t)sizeof payload) == 0,
          "and an APS *data* frame that happens to carry 0x05 in that octet is not either, because the frame control says data");

    payload[0] = 0x61;
    Test_Expect(Nwk_RxCarriesTransportKey(payload, 2) == 0,
          "a payload too short to hold the identifier is refused rather than read past");
    Test_Expect(Nwk_RxCarriesTransportKey(0, 8) == 0, "as is a null payload");
}

/* A secured NPDU carrying both IEEE address fields, which `secureNpdu` does not compose and 3.6.1.10.2's conflict
   needs: the header is built with them present, then protected whole, exactly as `Nwk_TxProtect` does for a frame
   this stack sends. */
static uint32_t secureNpduWithIeee(Security *sender, uint16_t dst, uint16_t src, uint8_t radius, uint8_t seq,
                                   const uint8_t *payload, uint32_t payloadLen, uint64_t srcIeee,
                                   uint64_t dstIeee, uint8_t *out, uint32_t outCap)
{
    Nwk_Frame frame;
    uint8_t plain[NWK_FRAME_NPDU_MAX];
    uint32_t plainLen;
    uint32_t headerLen;
    uint32_t outLen = 0;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = NWK_FRAME_TYPE_COMMAND;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.discoverRoute = NWK_DISCOVER_SUPPRESS;
    frame.securityEnabled = 1;
    frame.destAddr = dst;
    frame.srcAddr = src;
    frame.radius = radius;
    frame.sequenceNumber = seq;
    frame.srcIeeePresent = 1;
    frame.srcIeee = srcIeee;
    frame.destIeeePresent = 1;
    frame.destIeee = dstIeee;

    Test_ExpectStatus(NwkFrame_Compose(&frame, payload, payloadLen, plain, (uint32_t)sizeof plain, &plainLen), ZB_OK,
                  "a command frame with both IEEE address fields, which 3.6.1.10.1 says a command always carries");

    headerLen = NwkFrame_HeaderLen(&frame);

    Test_ExpectStatus(Security_Protect(sender, plain, headerLen, plain + headerLen, plainLen - headerLen, out, outCap,
                                  &outLen), ZB_OK,
                  "protected whole, as this stack protects a frame it sends");

    return outLen;
}

/* The same conflict with the map holding no own row, as in production: the header pair alone raises it. */
void caseLocalConflictNeedsNoOwnRow(void)
{
    Test_BandA dev;
    Security sec;
    Air air[AIR_LOG_MAX];
    const Air *announce = 0;
    const uint8_t *header;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint8_t payload[4];
    uint32_t airCount = 0;
    uint32_t npduLen;
    uint32_t i;

    securedRig(&dev, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &sec, SEC_B_IEEE, 5, 1);

    Zb_memset(payload, 0, (uint32_t)sizeof payload);
    payload[0] = NWK_CMD_LINK_STATUS;

    npduLen = secureNpduWithIeee(&sec, ADDR_PEER, ADDR_COORD, NWK_INITIAL_RADIUS, 0x31, payload, 3,
                                 0x00212effff060000, 0x00212effff060000, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 20), ZB_OK, "a secured frame naming this device's address and another IEEE");
    Test_ExpectCount(Nwk_AddressConflictsLocal(&dev.nwk), 1, "is a local conflict although the map holds no own row");

    for (i = 0; i < 8; i++)
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, 30 + (i * 40)), ZB_OK, "the turns that carry the clause's delay");

    Test_ExpectCount(Nwk_ConflictBroadcastsSent(&dev.nwk), 1, "and it is announced");
    harvestAir(&dev.model, air, &airCount);

    for (i = 0; i < airCount; i++)
    {
        header = npduOf(&air[i]);

        if (((uint32_t)header[2] | ((uint32_t)header[3] << 8)) == NWK_ADDR_RX_ON_WHEN_IDLE)
            announce = &air[i];
    }

    Test_Expect(announce != 0 && airDestOf(announce) == MAC_FRAME_ADDR_BROADCAST && announce->ackRequest == 0,
                "3.2.1.1.3: to 0xfffd in the NWK header, on the MAC's broadcast address with no acknowledgment asked");
    Test_Expect(announce != 0 && Nwk_BttOf(dev.nwk.btt, ADDR_PEER, npduOf(announce)[7]) != 0,
                "and with a record of its own, so a neighbour's relay of it is a copy and no conflict (8233)");

    npduLen = secureNpduWithIeee(&sec, ADDR_PEER, ADDR_COORD, NWK_INITIAL_RADIUS, 0x32, payload, 3,
                                 0x00212effff060000, 0xffffffffffffffff, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 400), ZB_OK, "a destination IEEE address of all ones at this device's address");
    Test_ExpectCount(Nwk_AddressConflictsLocal(&dev.nwk), 2, "is a conflict too, the clause saying so of that value");
}

/*
 * 3.6.1.10.2 and 3.6.1.10.5 on the secured path: a frame naming this device's own short address and somebody else's
 * IEEE address is a local conflict, and it arms one Network Status with 0x0d after the clause's jitter. 3.6.1.10.3
 * forbids announcing a conflict found in an unsecured frame, which the second half pins.
 */
void caseLocalConflictIsAnnounced(void)
{
    Test_BandA dev;
    Security sec;
    Nwk_NetworkStatusPayload status;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint8_t payload[4];
    uint32_t npduLen;
    uint32_t i;

    securedRig(&dev, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &sec, SEC_B_IEEE, 5, 1);

    Test_ExpectStatus(Nwk_AddrMapSeedOwn(Nwk_AddrMapOf(&dev.nwk), ADDR_PEER, SEC_B_IEEE, 10), ZB_OK,
                  "this device's own row is in the map");

    Zb_memset(payload, 0, (uint32_t)sizeof payload);
    payload[0] = NWK_CMD_LINK_STATUS;

    npduLen = secureNpduWithIeee(&sec, ADDR_PEER, ADDR_COORD, NWK_INITIAL_RADIUS, 0x31, payload, 3,
                                 0x00212effff060000, 0x00212effff060000, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 20), ZB_OK,
                  "a secured frame naming this device's own address and somebody else's");

    Test_ExpectCount(Nwk_AddressConflictsLocal(&dev.nwk), 1, "is 3.6.1.10.2's local conflict");

    for (i = 0; i < 8; i++)
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, 30 + (i * 40)), ZB_OK, "the turns that carry the clause's delay");

    Test_ExpectCount(Nwk_ConflictBroadcastsSent(&dev.nwk), 1,
                     "and one Network Status goes out, once: a second conflict replaces the address rather than queueing another");

    /* The cancel half: the same conflict found again, and a neighbour's own 0x0d heard in the same turn. */
    Zb_memset(payload, 0, (uint32_t)sizeof payload);
    payload[0] = NWK_CMD_LINK_STATUS;

    npduLen = secureNpduWithIeee(&sec, ADDR_PEER, ADDR_COORD, NWK_INITIAL_RADIUS, 0x32, payload, 3,
                                 0x00212effff060000, 0x00212effff060000, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);

    Zb_memset(payload, 0, (uint32_t)sizeof payload);
    payload[0] = NWK_CMD_NETWORK_STATUS;
    payload[1] = NWK_NETWORK_STATUS_ADDRESS_CONFLICT;
    payload[2] = (uint8_t)(ADDR_PEER & 0xff);
    payload[3] = (uint8_t)(ADDR_PEER >> 8);

    status = Nwk_StatusRead(payload, (uint32_t)sizeof payload);
    Test_Expect(status.valid == 1 && status.statusCode == NWK_NETWORK_STATUS_ADDRESS_CONFLICT
           && status.targetAddress == ADDR_PEER,
           "a Network Status 0x0d naming this device's address reads as the identical payload");

    npduLen = secureNpdu(&sec, NWK_ADDR_ALL_DEVICES, ADDR_COORD, NWK_INITIAL_RADIUS, 0x33, NWK_FRAME_TYPE_COMMAND, 0,
                         payload, (uint32_t)sizeof payload, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 500), ZB_OK,
                  "one turn that reads the conflict and then the neighbour's announcement of it");

    Test_ExpectCount(Nwk_AddressConflictsLocal(&dev.nwk), 2, "the conflict is counted again");
    Test_ExpectCount(Nwk_ConflictBroadcastsCancelled(&dev.nwk), 1, "and the announcement this device owed is withdrawn");
    Test_ExpectCount(Nwk_ConflictBroadcastsSent(&dev.nwk), 1, "with nothing further sent");

    /* 3.6.1.10.3: an unsecured frame SHALL NOT generate a Network Status message. */
    Zb_memset(payload, 0, (uint32_t)sizeof payload);
    payload[0] = NWK_CMD_LINK_STATUS;

    npduLen = makeNpdu(npdu, ADDR_PEER, ADDR_COORD, NWK_INITIAL_RADIUS, 0x34, NWK_FRAME_TYPE_COMMAND, 0, payload, 3);
    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 600), ZB_OK, "an unsecured command, which carries no IEEE address at all");
    Test_ExpectCount(Nwk_ConflictBroadcastsSent(&dev.nwk), 1,
                     "announces nothing: the clause forbids a network-wide notification from an unsecured message");
}

/*
 * 3.6.1.10.5's re-address: the parent draws a new address for its own end-device child and tells it with an
 * unsolicited rejoin response, which 3.6.1.10.6 requires to be network encrypted; the child changes to it and
 * reports Table 3-25's NLME-NWK-STATUS.indication.
 */
void caseReaddressChild(void)
{
    Test_BandA dev;
    Security sec;
    Nwk_NeighborTableEntry *child;
    Nwk_NwkStatusIndication inds[2];
    Nwk_Frame frame;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint8_t payload[4];
    uint32_t npduLen;
    uint16_t newAddress;

    securedRig(&dev, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &sec, SEC_B_IEEE, 5, 1);

    seedNeighbor(&dev.nwk, ADDR_COORD, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);

    child = neighborAt(&dev.nwk, ADDR_COORD);
    Test_Expect(child != 0 && child->deviceType == NWK_DEVICE_END_DEVICE,
                "an end-device child of this device, which 3.6.1.10.5 gives the parent the duty to re-address");

    child->extendedAddress = 0x00212effff060000;
    child->ieeeKnown = 1;

    newAddress = Nwk_JoinReaddressChild(&dev.nwk, child, 100);

    Test_Expect(newAddress != 0 && newAddress != ADDR_COORD,
           "a new address is drawn, and it is not the one the child had");
    Test_ExpectCount(child->networkAddress, newAddress, "which the neighbour entry carries");
    Test_ExpectCount(Nwk_AddressUpdatesSent(&dev.nwk), 1, "and the unsolicited response is sent once");

    /* The child's half: the same frame, at the device that is joined and being told a new address. */
    payload[0] = NWK_CMD_REJOIN_RESPONSE;
    payload[1] = (uint8_t)(0x2b2b & 0xff);
    payload[2] = (uint8_t)(0x2b2b >> 8);
    payload[3] = MAC_ASSOC_STATUS_SUCCESS;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);

    frame.frameType = NWK_FRAME_TYPE_COMMAND;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.securityEnabled = 1;
    frame.destAddr = ADDR_PEER;
    frame.srcAddr = ADDR_COORD;
    frame.radius = 1;
    frame.sequenceNumber = 0x41;
    frame.srcIeeePresent = 1;
    frame.srcIeee = SEC_B_IEEE;

    Test_ExpectStatus(NwkFrame_Compose(&frame, payload, (uint32_t)sizeof payload, npdu,
                                       (uint32_t)sizeof npdu, &npduLen), ZB_OK,
                  "an unsolicited rejoin response, network encrypted as 3.6.1.10.6 requires");

    dev.nwk.joinState = NWK_JOIN_JOINED;
    dev.nwk.joinParentExtended = SEC_B_IEEE;

    Test_ExpectCount(Nwk_JoinHandleCommand(&dev.nwk, &frame, payload, (uint32_t)sizeof payload, 110), 1,
                     "is a command the joined device consumes");

    Test_ExpectCount(Nwk_AddressUpdatesTaken(&dev.nwk), 1, "and it takes the new address");
    Test_ExpectCount(Mac_Pib(&dev.mac)->shortAddress, 0x2b2b, "which the PIB now carries");

    Test_ExpectCount(Nwk_PollStatusIndications(&dev.nwk, inds, 2), 1,
                     "and the change is reported upward as Table 3-25's indication");
    Test_Expect(inds[0].status == NWK_STATUS_CODE_NETWORK_ADDRESS_UPDATE && inds[0].shortAddr == 0x2b2b,
           "with the address-update status and the new address as ShortAddr, which is 3.6.1.10.5's own sentence");

    /* 3.6.1.10.6: an unencrypted unsolicited response is dropped. */
    frame.securityEnabled = 0;
    dev.nwk.joinState = NWK_JOIN_JOINED;

    Test_ExpectCount(Nwk_JoinHandleCommand(&dev.nwk, &frame, payload, (uint32_t)sizeof payload, 120), 1,
                     "an unencrypted one is consumed and dropped");
    Test_ExpectCount(Nwk_AddressUpdatesTaken(&dev.nwk), 1, "with nothing taken from it");
}

/* 4.6.3.6.3: a leave of any kind is sent secured in a secured network. The request to a sleeping child is held for its
   poll and decrypts at the child, and the parent's own announcement goes out secured. */
void caseSecuredLeaveRequestHeld(void)
{
    Test_BandA dev;
    Security sec;
    Security secPeer;
    Air air[AIR_LOG_MAX];
    Nwk_BeaconInfo info;
    Nwk_NeighborTableEntry *child;
    Mac_Transaction *held = 0;
    Nwk_Frame frame;
    Security_Result result;
    uint8_t plain[NWK_FRAME_NPDU_MAX];
    uint32_t airCount = 0;
    uint32_t plainLen = 0;
    uint32_t npduOffset = 0;
    uint32_t npduLen = 0;
    uint32_t i;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_ROUTER, 1, &sec, SEC_A_IEEE, 5, 1);
    secSeed(&secPeer, SEC_E_IEEE, 1, 1);

    Zb_memset(&info, 0, (uint32_t)sizeof info);
    info.stackProfile = 2;
    info.protocolVersion = 2;
    info.extendedPanId = 0x0123456789abcdef;
    info.txOffset = 0xffffff;
    Test_ExpectStatus(Nwk_SetBeaconInfo(&dev.nwk, &info, 1), ZB_OK, "the router is on a network");

    seedNeighbor(&dev.nwk, ADDR_SLEEPY1, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    child = neighborAt(&dev.nwk, ADDR_SLEEPY1);
    child->extendedAddress = SEC_E_IEEE;
    child->ieeeKnown = 1;

    Test_ExpectCount(Nwk_LeaveRequest(&dev.nwk, SEC_E_IEEE, 0, 0, 100), NWK_LEAVE_STATUS_SUCCESS,
                     "the parent asks its sleeping child to leave");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "nothing goes on the air direct");

    for (i = 0; i < MAC_TRANSACTION_MAX; i++)
    {
        if (dev.mac.indirect.transactions[i].used)
            held = &dev.mac.indirect.transactions[i];
    }

    Test_Expect(held != 0 && Mac_IndirectHeldFor(&dev.mac, ADDR_SLEEPY1) == 1, "the request is held for the child");
    Test_Expect((nwkFcfOf(held->payload) & NWK_FCF_SECURITY_BIT) != 0, "with the security sub-field set");
    Test_ExpectStatus(NwkFrame_Parse(held->payload, held->payloadLen, &frame, &npduOffset, &npduLen), ZB_OK,
                      "its network header parses");
    Test_ExpectStatus(Security_Unprotect(&secPeer, held->payload, held->payloadLen, NwkFrame_HeaderLen(&frame), plain,
                                         (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                      "and the child decrypts it with the network key");
    Test_Expect(plainLen == NWK_LEAVE_COMMAND_OCTETS && plain[0] == NWK_CMD_LEAVE
                && (plain[1] & NWK_LEAVE_OPTION_REQUEST) != 0, "to a leave request");

    Test_ExpectCount(Nwk_LeaveRequest(&dev.nwk, NWK_LEAVE_ADDRESS_NULL, 0, 0, 200), NWK_LEAVE_STATUS_SUCCESS,
                     "then the router leaves itself");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1 && (nwkFcfOf(npduOf(&air[0])) & NWK_FCF_SECURITY_BIT) != 0,
                "and its announcement goes on the air secured");
}

/* 3.6.2.2: a joined device discards a command that arrives unsecured, so a parent answers a timeout request
   secured, and the answer decrypts at the child. */
void caseSecuredTimeoutResponse(void)
{
    Test_BandA dev;
    Security sec;
    Security secPeer;
    Air air[AIR_LOG_MAX];
    Nwk_Frame frame;
    Security_Result result;
    uint8_t request[3];
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint8_t plain[NWK_FRAME_NPDU_MAX];
    uint32_t airCount = 0;
    uint32_t plainLen = 0;
    uint32_t npduOffset = 0;
    uint32_t npduLen = 0;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_ROUTER, 1, &sec, SEC_A_IEEE, 5, 1);
    secSeed(&secPeer, SEC_E_IEEE, 1, 1);
    seedNeighbor(&dev.nwk, ADDR_SLEEPY1, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);

    request[0] = NWK_CMD_END_DEVICE_TIMEOUT_REQUEST;
    request[1] = 2;
    request[2] = 0;

    npduLen = secureNpdu(&secPeer, ADDR_COORD, ADDR_SLEEPY1, 1, 7, NWK_FRAME_TYPE_COMMAND, 0, request,
                         (uint32_t)sizeof request, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "the parent takes a secured timeout request");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_TimeoutResponsesSent(&dev.nwk), 1, "and answers it");
    Test_Expect(airCount == 0 && Mac_CountersOf(&dev.mac).transactionQueue == 1,
                "held for the child's poll, since its receiver rests (10.22.2)");

    composePollTo(&dev.model, 0x5a, ADDR_SLEEPY1, ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "the child's poll extracts it");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1 && (nwkFcfOf(npduOf(&air[0])) & NWK_FCF_SECURITY_BIT) != 0,
                "with the security sub-field set");
    Test_ExpectStatus(NwkFrame_Parse(npduOf(&air[0]), npduLenOf(&air[0]), &frame, &npduOffset, &npduLen), ZB_OK,
                      "its network header parses");
    Test_ExpectStatus(Security_Unprotect(&secPeer, npduOf(&air[0]), npduLenOf(&air[0]), NwkFrame_HeaderLen(&frame),
                                         plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                      "and the child decrypts it with the network key");
    Test_Expect(plainLen == 3 && plain[0] == NWK_CMD_END_DEVICE_TIMEOUT_RESPONSE
                && plain[1] == NWK_TIMEOUT_STATUS_SUCCESS, "to a SUCCESS response");
}

/* 3.6.10.2 and 3.6.2.2: the timeout request a child owes after joining waits until it holds the network key, and
   then goes out secured, since its parent discards it otherwise. */
void caseSecuredTimeoutRequest(void)
{
    Nwk_JoinRequestParameters jr;
    Nwk_Frame response;
    Nwk_JoinConfirmParameters confirm;
    uint8_t answer[4] = { NWK_CMD_REJOIN_RESPONSE, 0, 0, 0x00 };
    Test_BandA dev;
    Security sec;
    Security secPeer;
    Air air[AIR_LOG_MAX];
    Nwk_NeighborTableEntry *parent;
    Nwk_Frame frame;
    Security_Result result;
    uint8_t plain[NWK_FRAME_NPDU_MAX];
    uint32_t airCount = 0;
    uint32_t base;
    uint8_t key[SECURITY_KEY_OCTETS];
    uint32_t plainLen = 0;
    uint32_t npduOffset = 0;
    uint32_t npduLen = 0;

    securedRig(&dev, ADDR_SLEEPY1, NWK_DEVICE_END_DEVICE, 0, &sec, SEC_E_IEEE, 1, 1);
    secSeed(&secPeer, SEC_A_IEEE, 1, 1);

    seedNeighbor(&dev.nwk, ADDR_COORD, NWK_DEVICE_ROUTER, 1, NWK_REL_PARENT);
    parent = neighborAt(&dev.nwk, ADDR_COORD);
    parent->extendedAddress = SEC_A_IEEE;
    parent->ieeeKnown = 1;
    sec.nwkActiveKeySeqNumber = 0x07;
    setOwnIeee(&dev, SEC_E_IEEE);

    Zb_memset(&jr, 0, (uint32_t)sizeof jr);
    jr.rejoinNetwork = 0x02;
    jr.capability.allocateAddress = 1;
    Test_ExpectStatus(Nwk_JoinRequest(&dev.nwk, &jr, 0), ZB_OK, "the child asks its parent to rejoin it, holding no key");
    harvestAir(&dev.model, air, &airCount);

    Zb_memset(&response, 0, (uint32_t)sizeof response);
    response.frameType = NWK_FRAME_TYPE_COMMAND;
    response.protocolVersion = NWK_PROTOCOL_VERSION;
    response.destAddr = ADDR_SLEEPY1;
    response.srcAddr = ADDR_COORD;
    response.radius = 1;
    response.destIeeePresent = 1;
    response.destIeee = SEC_E_IEEE;
    response.srcIeeePresent = 1;
    response.srcIeee = SEC_A_IEEE;
    answer[1] = (uint8_t)(ADDR_SLEEPY1 & 0xff);
    answer[2] = (uint8_t)(ADDR_SLEEPY1 >> 8);
    Test_Expect(Nwk_JoinHandleCommand(&dev.nwk, &response, answer, (uint32_t)sizeof answer, 50) == 1,
                "and the parent's rejoin response, SUCCESS, is taken");
    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_JOINED, "so the child is joined");
    Test_ExpectCount(Nwk_PollJoinConfirm(&dev.nwk, &confirm), 1, "and the layer above reads the NLME-JOIN.confirm");
    Test_Expect(dev.nwk.timeoutRequestPending == 1, "and owes its parent the timeout request (3.6.10.2)");
    base = airCount;

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a child that joined a secured network, its key not here yet");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == base + Nwk_PollsSent(&dev.nwk) && Nwk_TimeoutRequestsSent(&dev.nwk) == 0,
                "sends nothing but the polls 3.6.1.15 asks of a resting child while it attaches");
    Test_Expect(dev.nwk.timeoutRequestPending == 1, "and still owes the request");
    base = airCount;

    Zb_memcpy(key, sec.keys[0].key, SECURITY_KEY_OCTETS);
    Test_ExpectStatus(Security_InstallNetworkKey(&sec, key, 0x00, 0, 1), ZB_OK,
                      "the trust centre's network key is installed, as its Transport Key installs it");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "once the key is installed its next turn sends it");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(Nwk_TimeoutRequestsSent(&dev.nwk), 1, "once");
    Test_Expect(airCount == base + 1 && (nwkFcfOf(npduOf(&air[base])) & NWK_FCF_SECURITY_BIT) != 0,
                "with the security sub-field set");
    Test_ExpectStatus(NwkFrame_Parse(npduOf(&air[base]), npduLenOf(&air[base]), &frame, &npduOffset, &npduLen), ZB_OK,
                      "its network header parses");
    Test_ExpectStatus(Security_Unprotect(&secPeer, npduOf(&air[base]), npduLenOf(&air[base]), NwkFrame_HeaderLen(&frame),
                                         plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                      "and the parent decrypts it with the network key");
    Test_Expect(plainLen == 3 && plain[0] == NWK_CMD_END_DEVICE_TIMEOUT_REQUEST, "to a timeout request");
    Test_Expect(dev.nwk.timeoutRequestPending == 0, "which the child no longer owes");
}

/* 3.4.14's request from the device at ADDR_SLEEPY1, secured by `sender` or plain when it is 0, with the source IEEE
   address 3.4.14.2 puts in the header and `secureNpdu`'s minimal header has not. */
static uint32_t commissioningRequestNpduFrom(Security *sender, uint32_t type, uint8_t capability, uint16_t source,
                                             uint8_t *out, uint32_t outCap)
{
    Nwk_CommissioningRequest request;
    Nwk_Frame frame;
    uint8_t payload[1 + 2 + 2 + 2 + NWK_TLV_FRAGMENTATION_OCTETS + 2 + NWK_TLV_KEY_NEGOTIATION_OCTETS];
    uint8_t plain[NWK_FRAME_NPDU_MAX];
    uint32_t payloadLen = 0;
    uint32_t plainLen = 0;
    uint32_t outLen = 0;

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    request.type = type;
    request.capability = capability;
    request.nodeId = source;
    request.fragmentationOptions = NWK_TLV_FRAGMENTATION_APS_BIT;
    request.maxIncomingTransferUnit = 128;

    Test_ExpectStatus(Nwk_CommissioningRequestCompose(&request, payload + 1, (uint32_t)sizeof payload - 1,
                                                     &payloadLen), ZB_OK, "a commissioning request");
    payload[0] = NWK_CMD_NETWORK_COMMISSIONING_REQUEST;
    payloadLen++;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = NWK_FRAME_TYPE_COMMAND;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.discoverRoute = NWK_DISCOVER_SUPPRESS;
    frame.securityEnabled = sender != 0;
    frame.destAddr = ADDR_COORD;
    frame.srcAddr = source;
    frame.radius = 1;
    frame.sequenceNumber = 9;
    frame.srcIeeePresent = 1;
    frame.srcIeee = SEC_E_IEEE;

    Test_ExpectStatus(NwkFrame_Compose(&frame, payload, payloadLen, plain, (uint32_t)sizeof plain, &plainLen), ZB_OK,
                      "composed with its source address");

    if (sender == 0)
    {
        Zb_memcpy(out, plain, plainLen);

        return plainLen;
    }

    Test_ExpectStatus(Security_Protect(sender, plain, NwkFrame_HeaderLen(&frame), plain + NwkFrame_HeaderLen(&frame),
                                       plainLen - NwkFrame_HeaderLen(&frame), out, outCap, &outLen), ZB_OK,
                      "and protected by the requester");

    return outLen;
}

/* The same request from the address the rest of this file's joiner holds. */
static uint32_t commissioningRequestNpdu(Security *sender, uint32_t type, uint8_t capability, uint8_t *out,
                                         uint32_t outCap)
{
    return commissioningRequestNpduFrom(sender, type, capability, ADDR_SLEEPY1, out, outCap);
}

/* 3.4.15.2: the commissioning response takes the security level of the request, so a request that arrived
   secured is answered secured. */
void caseSecuredCommissioningResponse(void)
{
    Test_BandA dev;
    Security sec;
    Security secPeer;
    Air air[AIR_LOG_MAX];
    Nwk_Frame frame;
    Security_Result result;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint8_t plain[NWK_FRAME_NPDU_MAX];
    uint32_t plainLen = 0;
    uint32_t npduOffset = 0;
    uint32_t npduLen;
    uint32_t airCount = 0;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_COORDINATOR, 1, &sec, SEC_A_IEEE, 5, 1);
    secSeed(&secPeer, SEC_E_IEEE, 1, 1);

    npduLen = commissioningRequestNpdu(&secPeer, NWK_COMMISSIONING_REJOIN, 0x08, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "the parent takes a secured rejoin, whether or not it permits joining");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1 && (nwkFcfOf(npduOf(&air[0])) & NWK_FCF_SECURITY_BIT) != 0,
                "and answers with the security sub-field set");
    Test_ExpectStatus(NwkFrame_Parse(npduOf(&air[0]), npduLenOf(&air[0]), &frame, &npduOffset, &npduLen), ZB_OK,
                      "its network header parses");
    Test_ExpectStatus(Security_Unprotect(&secPeer, npduOf(&air[0]), npduLenOf(&air[0]), NwkFrame_HeaderLen(&frame),
                                         plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                      "and the requester decrypts it with the network key");
    Test_Expect(plainLen == 1 + NWK_COMMISSIONING_RESPONSE_OCTETS && plain[0] == NWK_CMD_NETWORK_COMMISSIONING_RESPONSE,
                "to a commissioning response");
}

/* 3.6.1.10.3: the request may be unsecured, since the device that sends it holds no key yet, so a parent on a secured
   network takes it and answers at the request's level, which is unsecured. */
void caseUnsecuredCommissioningRequest(void)
{
    Test_BandA dev;
    Security sec;
    Air air[AIR_LOG_MAX];
    Nwk_JoinIndicationParameters indication;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_COORDINATOR, 1, &sec, SEC_A_IEEE, 5, 1);

    dev.nwk.associationPermit = 1;
    npduLen = commissioningRequestNpdu(0, NWK_COMMISSIONING_INITIAL_JOIN, 0x08, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a joined parent takes an unsecured commissioning request");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(Nwk_DroppedUnsecured(&dev.nwk), 0, "it is not dropped for being unsecured");
    Test_ExpectCount(Nwk_PollJoinIndications(&dev.nwk, &indication, 1), 1, "the join is indicated");
    Test_Expect(airCount == 1 && (nwkFcfOf(npduOf(&air[0])) & NWK_FCF_SECURITY_BIT) == 0,
                "and the response goes out unsecured, as the request came");
}

/* What 3.6.1.6.1.3 protects of an entry: who it is, what it is, how it stands and its timers; the age and the link
   measurement a frame's arrival updates are not among them. */
static int sameDevice(const Nwk_NeighborTableEntry *a, const Nwk_NeighborTableEntry *b)
{
    return a->networkAddress == b->networkAddress && a->extendedAddress == b->extendedAddress
           && a->ieeeKnown == b->ieeeKnown && a->deviceType == b->deviceType && a->rxOnWhenIdle == b->rxOnWhenIdle
           && a->relationship == b->relationship && a->securityTimer == b->securityTimer
           && a->deviceTimeout == b->deviceTimeout;
}

/* Whether the table keeps a child under `address`. */
static int keepsAChild(Nwk_Nwk *nwk, uint16_t address)
{
    Nwk_NeighborTableEntry *entry = Nwk_NeighborOf(nwk->neighbors, address);

    return entry != 0 && (entry->relationship == NWK_REL_CHILD || entry->relationship == NWK_REL_UNAUTHENTICATED_CHILD);
}

/* The answer on the air, read out of an unsecured response: its address and its status. */
static int commissioningAnswerOf(const Air *air, uint16_t *address, uint8_t *status)
{
    Nwk_Frame frame;
    uint32_t offset = 0;
    uint32_t len = 0;
    const uint8_t *npdu = npduOf(air);

    if (NwkFrame_Parse(npdu, npduLenOf(air), &frame, &offset, &len) != ZB_OK)
        return 0;

    if (npduLenOf(air) <= NwkFrame_HeaderLen(&frame) || npdu[NwkFrame_HeaderLen(&frame)] != NWK_CMD_NETWORK_COMMISSIONING_RESPONSE)
        return 0;

    return Nwk_CommissioningResponseParse(npdu + NwkFrame_HeaderLen(&frame) + 1,
                                          npduLenOf(air) - NwkFrame_HeaderLen(&frame) - 1, address, status) == ZB_OK;
}

/* 3.6.1.6.1.3: an Initial Join while joining is not permitted is answered with PAN_ACCESS_DENIED and goes no
   further: no entry, no indication. */
void caseCommissioningInitialJoinRefused(void)
{
    Test_BandA dev;
    Security sec;
    Air air[AIR_LOG_MAX];
    Nwk_JoinIndicationParameters indication;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint16_t address = 0;
    uint8_t status = 0;
    uint32_t npduLen;
    uint32_t airCount = 0;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_COORDINATOR, 1, &sec, SEC_A_IEEE, 5, 1);
    dev.nwk.associationPermit = 0;

    npduLen = commissioningRequestNpdu(0, NWK_COMMISSIONING_INITIAL_JOIN, 0x08, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a parent that does not permit joining takes an Initial Join");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1 && commissioningAnswerOf(&air[0], &address, &status), "and answers it");
    Test_Expect(address == 0xffff && status == MAC_ASSOC_STATUS_PAN_ACCESS_DENIED,
                "with no address and PAN_ACCESS_DENIED");
    Test_ExpectCount(Nwk_PollJoinIndications(&dev.nwk, &indication, 1), 0, "indicating no join");
    Test_Expect(!keepsAChild(&dev.nwk, ADDR_SLEEPY1), "and keeping no child");
}

/* 8136-8139: a rejoin without NWK security leaves an unauthenticated child whose SecurityTimer runs, so a device the
   trust centre never authorizes is deleted rather than held for good. */
void caseUnsecuredRejoinChildExpires(void)
{
    Test_BandA dev;
    Security sec;
    uint8_t npdu[RADIO_MPDU_MAX];
    uint32_t npduLen;
    uint32_t seconds;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_COORDINATOR, 1, &sec, SEC_A_IEEE, 5, 1);
    dev.nwk.trustCenterIeee = SEC_A_IEEE;

    npduLen = makeRejoinNpdu(npdu, ADDR_COORD, ADDR_SLEEPY1, SEC_E_IEEE, SEC_A_IEEE, 0x88);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a parent takes an unsecured rejoin");
    Test_Expect(keepsAChild(&dev.nwk, ADDR_SLEEPY1), "and holds the device as a child");

    seconds = dev.nwk.cfg.apsSecurityTimeOutPeriod != 0 ? dev.nwk.cfg.apsSecurityTimeOutPeriod : NWK_SECURITY_TIMEOUT_DEFAULT;
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100 + (seconds + 1) * 1000), ZB_OK, "no secured frame follows in the period");
    Test_Expect(!keepsAChild(&dev.nwk, ADDR_SLEEPY1), "so the unauthenticated child is deleted");
    Test_ExpectCount(Nwk_JoinChildrenExpired(&dev.nwk), 1, "once");
}

/* 12474-12475: a network without a trust centre refuses a rejoin without NWK security, by commissioning as by 0x06. */
void caseUnsecuredCommissioningRejoinRefusedWithoutATrustCentre(void)
{
    Test_BandA dev;
    Security sec;
    Air air[AIR_LOG_MAX];
    Nwk_JoinIndicationParameters indication;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint16_t address = 0;
    uint8_t status = 0;
    uint32_t npduLen;
    uint32_t airCount = 0;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_COORDINATOR, 1, &sec, SEC_A_IEEE, 5, 1);
    dev.nwk.trustCenterIeee = NWK_TRUST_CENTER_NONE;

    npduLen = commissioningRequestNpdu(0, NWK_COMMISSIONING_REJOIN, 0x88, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a parent of a network without a trust centre takes it");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1 && commissioningAnswerOf(&air[0], &address, &status), "and answers it");
    Test_Expect(address == 0xffff && status == MAC_ASSOC_STATUS_PAN_ACCESS_DENIED,
                "with no address and PAN_ACCESS_DENIED");
    Test_ExpectCount(Nwk_PollJoinIndications(&dev.nwk, &indication, 1), 0, "indicating no rejoin");
    Test_Expect(!keepsAChild(&dev.nwk, ADDR_SLEEPY1), "and keeping no child");
}

/* 3.6.1.6.1.3: an Initial Join that arrives network-encrypted is dropped, with no answer. */
void caseSecuredInitialJoinDropped(void)
{
    Test_BandA dev;
    Security sec;
    Security secPeer;
    Air air[AIR_LOG_MAX];
    Nwk_JoinIndicationParameters indication;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_COORDINATOR, 1, &sec, SEC_A_IEEE, 5, 1);
    secSeed(&secPeer, SEC_E_IEEE, 1, 1);
    dev.nwk.associationPermit = 1;

    npduLen = commissioningRequestNpdu(&secPeer, NWK_COMMISSIONING_INITIAL_JOIN, 0x08, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a parent that permits joining takes a secured Initial Join");
    harvestAir(&dev.model, air, &airCount);

    Test_ExpectCount(airCount, 0, "and answers nothing");
    Test_ExpectCount(Nwk_JoinCommandsDropped(&dev.nwk), 1, "counting the drop");
    Test_ExpectCount(Nwk_PollJoinIndications(&dev.nwk, &indication, 1), 0, "indicating no join");
    Test_Expect(!keepsAChild(&dev.nwk, ADDR_SLEEPY1), "and keeping no child");
}

/* 3.6.1.6.1.3's matching rules: a device already in the table is found by its IEEE address; an unsecured rejoin that
   differs from the entry is refused with the entry untouched (8106-8110), one that agrees leaves it as it was, and an
   Initial Join from it while joining is open is a join again at the address it held, as a factory-reset product makes. */
void caseCommissioningMatchesAKnownDevice(void)
{
    Test_BandA dev;
    Security sec;
    Security secPeer;
    Air air[AIR_LOG_MAX];
    Nwk_JoinIndicationParameters indication;
    Nwk_NeighborTableEntry *entry;
    Nwk_NeighborTableEntry before;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint16_t address = 0;
    uint8_t status = 0;
    uint32_t npduLen;
    uint32_t airCount = 0;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_COORDINATOR, 1, &sec, SEC_A_IEEE, 5, 1);
    secSeed(&secPeer, SEC_E_IEEE, 1, 1);
    dev.nwk.associationPermit = 1;
    dev.nwk.trustCenterIeee = SEC_A_IEEE;

    seedNeighbor(&dev.nwk, ADDR_SLEEPY1, NWK_DEVICE_END_DEVICE, 0, NWK_REL_CHILD);
    entry = neighborAt(&dev.nwk, ADDR_SLEEPY1);
    entry->extendedAddress = SEC_E_IEEE;
    entry->ieeeKnown = 1;
    before = *entry;

    npduLen = commissioningRequestNpdu(0, NWK_COMMISSIONING_REJOIN, 0x08, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "an unsecured rejoin says the child listens, which the entry denies");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1 && commissioningAnswerOf(&air[0], &address, &status)
                && status == MAC_ASSOC_STATUS_PAN_ACCESS_DENIED, "and is refused");
    Test_Expect(sameDevice(entry, &before), "with the entry as it was");
    Test_ExpectCount(Nwk_PollJoinIndications(&dev.nwk, &indication, 1), 0, "and no join indicated");

    entry->rxOnWhenIdle = 1;
    before = *entry;

    npduLen = commissioningRequestNpdu(0, NWK_COMMISSIONING_REJOIN, 0x08, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "an unsecured rejoin that agrees with the entry");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 2 && commissioningAnswerOf(&air[1], &address, &status) && status == 0
                && address == ADDR_SLEEPY1, "is answered with the child's own address");
    Test_Expect(entry->relationship == NWK_REL_CHILD, "and does not demote the child to unauthenticated");
    Test_Expect(entry->securityTimer == before.securityTimer, "nor arm its security timer");

    npduLen = commissioningRequestNpdu(&secPeer, NWK_COMMISSIONING_REJOIN, 0x00, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 300), ZB_OK, "a secured request that says the child no longer listens");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 2 && entry->rxOnWhenIdle == 0 && entry->relationship == NWK_REL_CHILD,
                "updates the entry it names, which stays a child");
    Test_ExpectCount(Mac_CountersOf(&dev.mac).transactionQueue, 1,
                     "and its answer is held for the poll of a child that no longer listens (3.4.15.1)");

    (void)Nwk_PollJoinIndications(&dev.nwk, &indication, 1);
    entry->relationship = NWK_REL_SIBLING;
    entry->deviceType = NWK_DEVICE_ROUTER;
    entry->rxOnWhenIdle = 1;

    sec.incoming[0].inUse = 1;
    sec.incoming[0].senderIeee = SEC_E_IEEE;
    sec.incoming[0].frameCounter = 5000;

    npduLen = commissioningRequestNpduFrom(0, NWK_COMMISSIONING_INITIAL_JOIN, 0x8e, ADDR_SLEEPY2, npdu,
                                           (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY2);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 400), ZB_OK,
                      "an unsecured Initial Join from the same device, from another address, while joining is open");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 3 && commissioningAnswerOf(&air[2], &address, &status) && status == 0
                && address == ADDR_SLEEPY1, "is admitted at the address its entry holds, as an association is");
    Test_Expect(entry->relationship == NWK_REL_UNAUTHENTICATED_CHILD && entry->networkAddress == ADDR_SLEEPY1,
                "the entry made again as an unauthenticated child (8117-8119)");
    Test_Expect(neighborAt(&dev.nwk, ADDR_SLEEPY2) == 0, "and nothing kept at the address the request came from");
    Test_ExpectCount(Nwk_PollJoinIndications(&dev.nwk, &indication, 1), 1, "and the join is indicated");
    Test_Expect(!sec.incoming[0].inUse,
                "with the device's old frame counter forgotten, since a reset product starts its counter again");
}

/* 3.4.15.2.1.2: a new device whose address another holds is answered 0xF0 and a new address, and gets an entry of
   its own: the other device's is not touched. */
void caseCommissioningAddressHeldByAnother(void)
{
    Test_BandA dev;
    Security sec;
    Air air[AIR_LOG_MAX];
    Nwk_NeighborTableEntry *holder;
    Nwk_NeighborTableEntry *joiner;
    Nwk_NeighborTableEntry before;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint16_t address = 0;
    uint8_t status = 0;
    uint32_t npduLen;
    uint32_t airCount = 0;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_COORDINATOR, 1, &sec, SEC_A_IEEE, 5, 1);
    dev.nwk.associationPermit = 1;

    seedNeighbor(&dev.nwk, ADDR_SLEEPY1, NWK_DEVICE_END_DEVICE, 1, NWK_REL_CHILD);
    holder = neighborAt(&dev.nwk, ADDR_SLEEPY1);
    holder->extendedAddress = SEC_B_IEEE;
    holder->ieeeKnown = 1;
    before = *holder;

    npduLen = commissioningRequestNpdu(0, NWK_COMMISSIONING_INITIAL_JOIN, 0x08, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a device asks for the address a child holds");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1 && commissioningAnswerOf(&air[0], &address, &status)
                && status == NWK_COMMISSIONING_STATUS_ADDRESS_CONFLICT && address != ADDR_SLEEPY1,
                "and is told 0xF0 with another address");
    Test_Expect(sameDevice(holder, &before), "the child's entry is as it was");

    joiner = neighborAt(&dev.nwk, address);
    Test_Expect(joiner != 0 && joiner != holder && joiner->extendedAddress == SEC_E_IEEE
                && joiner->relationship == NWK_REL_UNAUTHENTICATED_CHILD, "and the device has an entry of its own");
}

/* An end device that joined owes its parent a timeout request; when the radio refuses it for want of room the
   request stays owed and goes out on a later turn, once, instead of being forgotten. */
void caseTimeoutRequestSurvivesARefusal(void)
{
    Test_BandA dev;
    Nwk_NeighborTableEntry *parent;
    Air air[AIR_LOG_MAX];
    uint32_t airCount = 0;
    uint32_t i;

    rigAt(&dev, ADDR_SLEEPY1, PAN_ID, NWK_DEVICE_END_DEVICE, 0);
    seedNeighbor(&dev.nwk, ADDR_COORD, NWK_DEVICE_ROUTER, 1, NWK_REL_PARENT);
    parent = neighborAt(&dev.nwk, ADDR_COORD);
    parent->extendedAddress = SEC_A_IEEE;
    parent->ieeeKnown = 1;

    dev.nwk.joinState = NWK_JOIN_JOINED;
    dev.nwk.timeoutRequestPending = 1;
    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "a turn on which the radio has no room");
    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 0, "sends no request");
    Test_ExpectCount(dev.nwk.joinOwedInUse, 1, "and holds the one it composed");

    for (i = 0; i < 5; i++)
        Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200 + 50 * i), ZB_OK, "later turns");

    harvestAir(&dev.model, air, &airCount);
    Test_ExpectCount(airCount, 1, "send it once the radio has room, and once");
    Test_ExpectCount(Nwk_TimeoutRequestsSent(&dev.nwk), 1, "counted once");
    Test_ExpectCount(dev.nwk.timeoutRequestPending, 0, "and it is no longer owed");
}

/* A device that is not yet joined, at a secured level, takes an unsecured commissioning response as it takes a rejoin
   response: the parent answers at the level the request came at, and the joiner holds no key yet (3.4.15.2) */
void caseUnsecuredCommissioningResponseAccepted(void)
{
    Test_BandA dev;
    Security sec;
    Nwk_Frame frame;
    uint8_t payload[4] = { NWK_CMD_NETWORK_COMMISSIONING_RESPONSE, 0x01, 0x00, 0x00 };
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t npduLen = 0;

    securedRig(&dev, ADDR_PEER, NWK_DEVICE_END_DEVICE, 1, &sec, SEC_B_IEEE, 0, 0);
    setOwnIeee(&dev, SEC_B_IEEE);

    dev.nwk.joinState = NWK_JOIN_COMMISSIONING;
    dev.nwk.joinParentShort = ADDR_COORD;
    dev.nwk.joinParentShortKnown = 1;
    dev.nwk.joinParentExtended = SEC_A_IEEE;

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = NWK_FRAME_TYPE_COMMAND;
    frame.protocolVersion = NWK_PROTOCOL_VERSION;
    frame.destAddr = ADDR_PEER;
    frame.srcAddr = ADDR_COORD;
    frame.radius = 1;
    frame.srcIeeePresent = 1;
    frame.srcIeee = SEC_A_IEEE;
    frame.destIeeePresent = 1;
    frame.destIeee = SEC_B_IEEE;

    Test_ExpectStatus(NwkFrame_Compose(&frame, payload, (uint32_t)sizeof payload, npdu, (uint32_t)sizeof npdu, &npduLen),
                      ZB_OK, "3.4.15's answer, unsecured as the Initial Join it answers");
    injectNpdu(&dev, npdu, npduLen, ADDR_COORD);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "the joiner's turn reads it");
    Test_ExpectCount(Nwk_DroppedUnsecured(&dev.nwk), 0, "it is not dropped for being unsecured");
    Test_ExpectCount(Nwk_JoinStateOf(&dev.nwk), NWK_JOIN_JOINED, "and it is the join");
}

/* 3.4.15.1: the answer to a joiner whose capability says its receiver rests is held for its poll, a refusal as
   much as a grant; the joiner's Data Request takes it off the transaction queue */
void caseCommissioningAnswerHeldForASleepyJoiner(void)
{
    Test_BandA dev;
    Security sec;
    Air air[AIR_LOG_MAX];
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint16_t address = 0;
    uint8_t status = 0xff;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_COORDINATOR, 1, &sec, SEC_A_IEEE, 5, 1);

    npduLen = commissioningRequestNpdu(0, NWK_COMMISSIONING_INITIAL_JOIN, 0x80, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "joining is not permitted, so the request is refused");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 0 && Mac_IndirectHeldFor(&dev.mac, ADDR_SLEEPY1) == 1,
                "and the refusal is held: the request said the joiner's receiver rests");

    composePollTo(&dev.model, 0x61, ADDR_SLEEPY1, ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 150), ZB_OK, "the joiner polls");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1 && commissioningAnswerOf(&air[0], &address, &status)
                && status == MAC_ASSOC_STATUS_PAN_ACCESS_DENIED, "and the refusal goes out to it");

    dev.nwk.associationPermit = 1;
    npduLen = commissioningRequestNpdu(0, NWK_COMMISSIONING_INITIAL_JOIN, 0x80, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 200), ZB_OK, "with joining permitted the request is granted");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1 && Mac_IndirectHeldFor(&dev.mac, ADDR_SLEEPY1) == 1, "and the grant is held as well");

    composePollTo(&dev.model, 0x62, ADDR_SLEEPY1, ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 250), ZB_OK, "until the joiner polls");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 2 && commissioningAnswerOf(&air[1], &address, &status) && status == 0
                && address == ADDR_SLEEPY1, "and it goes out with the joiner's address");
}

/* The parent's answer the door has no room for is held and goes out on the next turn, not lost */
void caseCommissioningAnswerHeldWhileTheDoorIsFull(void)
{
    Test_BandA dev;
    Security sec;
    Air air[AIR_LOG_MAX];
    Nwk_JoinIndicationParameters indication;
    uint8_t npdu[NWK_FRAME_NPDU_MAX];
    uint32_t npduLen;
    uint32_t airCount = 0;
    uint16_t address = 0;
    uint8_t status = 0xff;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_COORDINATOR, 1, &sec, SEC_A_IEEE, 5, 1);
    dev.nwk.associationPermit = 1;

    npduLen = commissioningRequestNpdu(0, NWK_COMMISSIONING_INITIAL_JOIN, 0x88, npdu, (uint32_t)sizeof npdu);
    injectNpdu(&dev, npdu, npduLen, ADDR_SLEEPY1);
    LoopbackRadio_RefuseTx(&dev.model, ZB_ERR_NO_SPACE, 1);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 100), ZB_OK, "the parent answers on a turn the door has no room");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 0 && dev.nwk.joinOwedInUse == 1, "so the answer is held");
    Test_ExpectCount(Nwk_PollJoinIndications(&dev.nwk, &indication, 1), 1, "and the join indicated");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 110), ZB_OK, "the next turn");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1 && commissioningAnswerOf(&air[0], &address, &status) && status == 0
                && address == ADDR_SLEEPY1, "sends it");
}

/* The NWK Frame Control Field of a logged frame, low octet first. */
static uint32_t fcfNwkOf(const Air *air)
{
    return (uint32_t)npduOf(air)[0] | ((uint32_t)npduOf(air)[1] << 8);
}

/* 8233 makes a broadcast that opens a new record with this device's own source a local conflict, so a route request
   this device sent must hold a record of its own: a neighbour's relay of it is a copy (9481), not another holder. */
void caseOwnRouteRequestRelayedBackIsNoConflict(void)
{
    Test_BandA dev;
    Security sec;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    uint32_t airCount = 0;
    uint32_t startMs = NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS + 100;

    securedRig(&dev, ADDR_COORD, NWK_DEVICE_ROUTER, 1, &sec, SEC_A_IEEE, 5, 1);
    setOwnIeee(&dev, SEC_A_IEEE);
    scriptOutcomes(&dev.model, LOOPBACK_TX_MAX, 1);

    req = nldeReq(ADDR_ELSEWHERE, securedNsdu, SEC_NSDU_LEN, 0);
    req.discoverRoute = 1;

    Test_ExpectStatus(Nwk_DataRequest(&dev.nwk, &req, startMs), ZB_OK,
                      "a request for an address with no route, once the device has operated past the delivery time");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, startMs), ZB_OK, "and the step that broadcasts its route request");
    harvestAir(&dev.model, air, &airCount);
    Test_Expect(airCount == 1 && npduOf(&air[0])[2] == 0xfc && npduOf(&air[0])[3] == 0xff,
                "one route request on the air, to 0xfffc");

    injectNpdu(&dev, npduOf(&air[0]), npduLenOf(&air[0]), ADDR_PEER);
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, startMs + 50), ZB_OK, "a neighbour relays it back unchanged");

    Test_ExpectCount(Nwk_AddressConflictsLocal(&dev.nwk), 0, "9481: which is a copy, found in the table");
    Test_ExpectCount(Nwk_ConflictBroadcastsSent(&dev.nwk), 0, "so no conflict is announced on this device's address");
}

/* 3.4.8.2's header, 3.4.8.1's MAC frame and 3.6.2.2's gate, across two devices on one key: the frame a router states
   its links in has to be one the other router reads. */
void caseLinkStatusFrameOnTheAir(void)
{
    Test_BandA devA;
    Test_BandA devB;
    Security secA;
    Security secB;
    Air air[AIR_LOG_MAX];
    Nwk_NeighborTableEntry *sender;
    const uint8_t *npdu;
    uint32_t airCount = 0;
    uint32_t i;
    uint64_t srcIeee = 0;

    securedRig(&devA, ADDR_COORD, NWK_DEVICE_ROUTER, 1, &secA, SEC_A_IEEE, 5, 1);
    setOwnIeee(&devA, SEC_A_IEEE);
    securedRig(&devB, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &secB, SEC_B_IEEE, 5, 1);

    seedNeighbor(&devA.nwk, ADDR_PEER, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);
    Nwk_NeighborOf(devA.nwk.neighbors, ADDR_PEER)->lqi = 100;
    seedNeighbor(&devB.nwk, ADDR_COORD, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    Test_ExpectStatus(Test_NwkStep(&devA.nwk, 1), ZB_OK, "the turn that arms 3.6.4.4.1's period");
    Test_ExpectStatus(Test_NwkStep(&devA.nwk, 1 + NWK_LINK_STATUS_PERIOD_MS), ZB_OK, "and the turn it runs out on");
    harvestAir(&devA.model, air, &airCount);

    Test_Expect(airCount == 1 && Nwk_LinkStatusSent(&devA.nwk) == 1, "one link status on the air");
    Test_Expect(airDestOf(&air[0]) == 0xffff && air[0].ackRequest == 0,
                "3.4.8.1: the MAC destination is the broadcast address and no acknowledgment is asked");

    npdu = npduOf(&air[0]);

    Test_ExpectCount((uint32_t)npdu[2] | ((uint32_t)npdu[3] << 8), NWK_ADDR_ROUTERS,
                     "3.4.8.2: the NWK destination is the router-only broadcast address");
    Test_ExpectCount(npdu[NPDU_RADIUS_OCTET], 1, "3.4.8.2: the radius is 1");
    Test_Expect((npdu[1] & (1 << (NWK_FRAME_FCF_SRC_IEEE_SHIFT - 8))) != 0, "3.4.8.2: the source IEEE sub-field is 1");
    Test_Expect((npdu[1] & (1 << (NWK_FRAME_FCF_DEST_IEEE_SHIFT - 8))) == 0, "and the destination IEEE sub-field 0");

    for (i = 0; i < 8; i++)
        srcIeee = srcIeee | ((uint64_t)npdu[SEC_HEADER_LEN + i] << (8 * i));

    Test_Expect(srcIeee == SEC_A_IEEE, "3.4.8.2: the source IEEE field is the originator's address");
    Test_Expect((fcfNwkOf(&air[0]) & NWK_FCF_SECURITY_BIT) != 0, "and a network that runs NWK security secures it");

    injectNpdu(&devB, npdu, npduLenOf(&air[0]), ADDR_COORD);
    Test_ExpectStatus(Test_NwkStep(&devB.nwk, 2 + NWK_LINK_STATUS_PERIOD_MS), ZB_OK, "the same octets at the other router");

    sender = Nwk_NeighborOf(devB.nwk.neighbors, ADDR_COORD);

    Test_ExpectCount(Nwk_DroppedUnsecured(&devB.nwk), 0, "are not refused as an unsecured command");
    Test_ExpectCount(Nwk_RxSecurityFailures(&devB.nwk), 0, "and authenticate");
    Test_ExpectCount(Nwk_LinkStatusApplied(&devB.nwk), 1, "and 3.6.4.4.2 applies them");
    Test_Expect(sender != 0 && sender->outgoingCost == Nwk_CostFromLqa(100),
                "so the receiver learns the cost the sender stated for it");
}

/* A router that joined and is still waiting for the network key has nothing to secure the frame with, and a joined
   receiver would refuse it unsecured; the same waiting device on a network with no NWK security sends. */
void caseLinkStatusWaitsForTheKey(void)
{
    Test_BandA dev;
    Security sec;
    Security_Config cfg;
    Air air[AIR_LOG_MAX];
    uint32_t airCount = 0;

    rigAt(&dev, ADDR_PEER, PAN_ID, NWK_DEVICE_ROUTER, 1);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = SEC_B_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.nwkAllFresh = 1;

    Test_ExpectStatus(Security_Init(&sec, &cfg), ZB_OK, "a secured network's device with no key yet");
    Test_Expect(!Security_IsEnabled(&sec), "which cannot secure a frame");

    Nwk_AttachSecurity(&dev.nwk, &sec);
    seedNeighbor(&dev.nwk, ADDR_COORD, NWK_DEVICE_ROUTER, 1, NWK_REL_PARENT);

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1), ZB_OK, "the turn that arms the period");
    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 1 + NWK_LINK_STATUS_PERIOD_MS), ZB_OK, "and the turn it runs out on");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 0 && Nwk_LinkStatusSent(&dev.nwk) == 0, "nothing goes out before the key is held");

    cfg.nwkSecurityLevel = SECURITY_LEVEL_NONE;
    Test_ExpectStatus(Security_Init(&sec, &cfg), ZB_OK, "and at level 0, a network with no NWK security");

    Test_ExpectStatus(Test_NwkStep(&dev.nwk, 2 + 2 * NWK_LINK_STATUS_PERIOD_MS), ZB_OK, "the next period");
    harvestAir(&dev.model, air, &airCount);

    Test_Expect(airCount == 1 && Nwk_LinkStatusSent(&dev.nwk) == 1, "the frame goes out unsecured");
    Test_Expect((fcfNwkOf(&air[0]) & NWK_FCF_SECURITY_BIT) == 0, "with the security sub-field clear");
}

/*
 * The route record on a secured network: 4.3.1.1 secures every NWK frame this layer sends, and 3.4.5 is no
 * exception, so the record a router owes a concentrator goes out secured, and so does one it relays with its own
 * address appended. An unsecured one is discarded at a joined receiver (3.6.2.2).
 */
void caseSecuredRouteRecord(void)
{
    Test_BandA devB;
    Security secB;
    Security secE;
    Air air[AIR_LOG_MAX];
    Nwk_DataRequestParameters req;
    uint8_t record[2];
    uint8_t npdu[128];
    uint32_t airCount = 0;
    uint32_t npduLen;

    securedRig(&devB, ADDR_PEER, NWK_DEVICE_ROUTER, 1, &secB, SEC_B_IEEE, 1, 1);
    secSeed(&secE, SEC_E_IEEE, 9, 1);
    seedNeighbor(&devB.nwk, ADDR_COORD, NWK_DEVICE_ROUTER, 1, NWK_REL_PARENT);
    seedNeighbor(&devB.nwk, ADDR_ELSEWHERE, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    devB.nwk.routes[0].inUse = 1;
    devB.nwk.routes[0].destinationAddress = ADDR_COORD;
    devB.nwk.routes[0].status = NWK_ROUTE_ACTIVE;
    devB.nwk.routes[0].nextHopAddress = ADDR_COORD;
    devB.nwk.routes[0].manyToOne = 1;
    devB.nwk.routes[0].routeRecordRequired = 1;

    req = nldeReq(ADDR_COORD, nsdu, NSDU_LEN, 0);
    req.securityEnable = 1;
    Test_ExpectStatus(Nwk_DataRequest(&devB.nwk, &req, 100), ZB_OK, "a frame to a concentrator that owes a record");
    harvestAir(&devB.model, air, &airCount);
    Test_Expect(airCount == 2 && Nwk_RouteRecordsSent(&devB.nwk) == 1, "goes behind the record");
    Test_Expect(airCount == 2 && (nwkFcfOf(npduOf(&air[0])) & NWK_FCF_SECURITY_BIT) != 0,
                "and the record is secured, as 4.3.1.1 secures every frame this layer sends");

    record[0] = NWK_CMD_ROUTE_RECORD;
    record[1] = 0;
    npduLen = secureNpdu(&secE, ADDR_COORD, ADDR_ELSEWHERE, 5, 0x61, NWK_FRAME_TYPE_COMMAND, 0, record, 2,
                         npdu, (uint32_t)sizeof npdu);
    injectNpdu(&devB, npdu, npduLen, ADDR_ELSEWHERE);
    Test_ExpectStatus(Test_NwkStep(&devB.nwk, 200), ZB_OK, "a neighbour's secured record for the concentrator");
    harvestAir(&devB.model, air, &airCount);
    Test_Expect(airCount == 3 && Nwk_RouteRecordsRelayed(&devB.nwk) == 1 && airDestOf(&air[2]) == ADDR_COORD,
                "is relayed on with this device's address appended");
    Test_Expect(airCount == 3 && (nwkFcfOf(npduOf(&air[2])) & NWK_FCF_SECURITY_BIT) != 0,
                "secured again by this device on the way");
}
