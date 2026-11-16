/* The `aps` suite's security crossing: the nine cases this crossing wires, a
   `Security` attached to `aps` and the `nwk` underneath left unsecured on purpose, so the octets compared are the
   APSDU and nothing else. */

#include "aps.h"
#include "aps_frame.h"
#include "aps_helpers.h"
#include "loopback_radio.h"
#include "nwk.h"
#include "rig_band_a.h"
#include "security.h"
#include "test_harness.h"
#include "zb_utils.h"

/* The four APS vectors of the `security` suite, quoted here rather than recomputed: a1-a4 are the computed
   link-key frames this crossing is pinned against, produced by an independent CPython implementation of
   4.4.1.1 assembled per Annex A.2 and reproduced octet for octet in test/security/cases_aps.c cases 18-22. What a case here
   asks of them is different from what that suite asks: there the module produced the octets, here the *service*
   must produce them (composition, protection and the NLDE hand-off in one act) and the byte-equality is what
   proves the service handed the right octets down and not merely some octets. Same link key, same addresses, same
   counters, same APS header fields: dstEndpoint 0x01, cluster 0x0006, profile 0x0104, source endpoint 0x03 and APS
   counter 0x11, the header the vectors were computed over (4.4.1.1 step 5d authenticates it as written). */
#define APS_OWN_IEEE 0x0123456789abcdef        /* A: the device a1 and a2 were protected by */
#define APS_PARTNER_IEEE 0x1011121314151617    /* B: the entity the link key is shared with, and a3's sender */

#define APS_VECTOR_SRC_EP 0x03
#define APS_VECTOR_DST_EP 0x01
#define APS_VECTOR_COUNTER 0x11                /* the octet a1, a2 and a4 carry */
#define APS_VECTOR_PAYLOAD_LEN 5
#define APS_REPLY_PAYLOAD_LEN 3

#define APS_OUTGOING_SEED 4                   /* the pair's OutgoingFrameCounter a1 was produced at; a2 takes 5 */
#define APS_REPLY_COUNTER 7                   /* the counter a3 carries, protected by the partner */

static const char *s_linkKeyHex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
static const char *s_nwkKeyHex = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
static const char *s_apsPayloadHex = "aabbccddee";
static const char *s_apsReplyPayloadHex = "102030";

/* a1: level 0x05, extended nonce 1, 8 + 13 + 5 + 4 = 30 octets, auxiliary control 0x60 with the level
   sub-field cleared by 4.4.1.1 step 10 and this device's own extended address in the source field. */
static const char *s_apsFrame1Hex = "20010600040103116004000000efcdab89674523019bc46c1a856adc703e";

/* a2: the same pair, the next counter, extended nonce 0, 8 + 5 + 5 + 4 = 22 octets and no address anywhere in
   its octets, which is why reading it back is the hint's test and not the auxiliary's. */
static const char *s_apsFrame2Hex = "20010600040103114005000000bd76748a2cc9c8f562";

/* a3: the partner's reply, its own extended address in the auxiliary source field, counter 7, 3 payload
   octets: 8 + 13 + 3 + 4 = 28 octets. Its APS counter is 0x21 and its endpoints are the reply's own. */
static const char *s_apsFrame3Hex = "2001060004010321600700000017161514131211102373abb7c81fd3";

/* One entry of `apsDeviceKeyPairSet`, seeded the way an application seeds it: the partner the
   key pair is shared with, the 16-bit alias this stack's own addressing gives that partner, the attribute the gate
   of 4.4.1.1 step 1a-ii requires, the link key, both counters, and no peer capability recorded, band A carries no
   `Features & Capabilities` bit, which is what makes 4.4.1.2 step 8 unreachable, and this crossing says so. */
static Security_KeyPairEntry apsPairAt(uint64_t partner, uint16_t alias, int aliasKnown,
                                       uint32_t outgoing, uint32_t incoming)
{
    Security_KeyPairEntry entry;

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.deviceIeee = partner;
    entry.shortAddress = alias;
    entry.shortKnown = aliasKnown;
    entry.keyAttributes = SECURITY_KEYPAIR_ATTR_VERIFIED;
    entry.outgoingFrameCounter = outgoing;
    entry.incomingFrameCounter = incoming;
    entry.linkKeyType = SECURITY_LINK_KEY_UNIQUE;
    entry.featuresCapabilities = SECURITY_FEATURES_NONE;
    entry.verifiedFrameCounter = 1;
    Test_ParseHex(s_linkKeyHex, entry.key, SECURITY_KEY_OCTETS);

    return entry;
}

/* A device of this suite with the crossing's material attached: the stack `rigBuild` builds, plus the
   application's `Security` at the NIB default level, with the one network descriptor `Security_Init` requires of
   any non-zero level and no APS procedure ever reads (4.4.1.1 step 3 borrows the level and nothing else; the key
   pairs are the crossing's own material), this device's extended address, which is the nonce's address half on
   every frame it protects (4.4.1.1 step 5c with 4.5.2.2), and the pairs as config. `Aps_AttachSecurity` adopts it
   by pointer exactly as `Nwk_AttachSecurity` does one layer down.

   The `nwk` underneath is deliberately left with no `Security` attached, and that is the suite stating which layer
   it is pinning: an APS-secured APDU travelling inside an unsecured NWK data frame is the octet string a1 names
   (the whole APSDU) and putting 4.3.1.1's 14 auxiliary octets and its MIC around it would compare a1 against a
   frame a1 is not. Attaching the same module to `nwk` as well is what an application does (TxOptions 0x02 then
   selects the NWK crossing too, and the NWK slot re-protects the NPDU per attempt); what these cases assert is the
   APS half, and nwk/ in test/'s Part C already asserts the NWK half on the same rigs. */
static void securedRigBuild(Rig *rig, Security *security, const Security_KeyPairEntry *pairs,
                            uint32_t pairCount, uint64_t ownIeee, uint16_t ownShort)
{
    Security_Config cfg;
    Security_KeyDescriptor key;

    rigBuild(rig, ownShort);

    Zb_memset(&key, 0, (uint32_t)sizeof key);
    key.keySeqNumber = 0x00;
    key.inUse = 1;
    key.outgoingFrameCounter = 1;
    Test_ParseHex(s_nwkKeyHex, key.key, SECURITY_KEY_OCTETS);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = ownIeee;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.nwkActiveKeySeqNumber = 0x00;
    cfg.authenticated = 1;
    cfg.nwkAllFresh = 1;
    cfg.keys = &key;
    cfg.keyCount = 1;
    cfg.keyPairs = pairs;
    cfg.keyPairCount = pairCount;

    Test_ExpectStatus(Security_Init(security, &cfg), ZB_OK,
                  "the application's key material arrives at `Security_Init` and nowhere else");

    Aps_AttachSecurity(&rig->aps, security);
    Test_Expect(rig->aps.security == security,
          "and the service adopts it by pointer, the same act's shape `nwk` uses: the keys, the pairs and both counters stay the application's");
}

/* The outgoing counter of one entry, read the only way an application is allowed to read it: out of
   `Security_Snapshot`, which is the per-partner bank. */
static uint32_t pairOutgoing(const Security *security, uint32_t index)
{
    Security_KeyState state;

    Security_Snapshot(security, &state);

    if (index >= state.keyPairCount)
        return 0xffffffff;

    return state.keyPairOutgoingFrameCounter[index];
}

/* One secured APDU this suite's own sender stack produced, captured off its side of the seam and copied out. The
   frame under test is then a frame this stack actually transmitted (its own key pair, its own header fields, its
   own protection), which is what lets a case change exactly one octet of it and say which octet it changed.
   `txOptions` is the ask, and the counter the entry holds at this moment is the counter the frame carries. */
static uint32_t securedFrameOut(Rig *sender, Air *air, uint32_t *airCount, const uint8_t *asdu,
                                uint32_t asduLength, uint32_t txOptions, uint8_t *out)
{
    Aps_ApsdeReq req;
    uint32_t len;
    uint32_t i;

    req = sapReq(APS_ADDR_MODE_SHORT, OWN_SHORT, DST_EP, CLUSTER_ID, asdu, asduLength, txOptions);

    Test_ExpectStatus(Aps_DataRequest(&sender->aps, &req, 100), ZB_OK,
                  "the sender's own service composes, protects and issues it (2.2.4.1.1.3 with 4.4.1.1)");

    harvestAir(&sender->stack.model, air, airCount);
    Test_Expect(*airCount == 1, "and exactly one frame went on its side of the seam");

    len = apduLenOf(&air[0]);

    for (i = 0; i < len; i++)
        out[i] = apduOf(&air[0])[i];

    return len;
}

/*
 * 25. A secured unicast out: the service produces a1 and a2 octet for octet (4.4.1.1).
 *
 * The claim is the one this crossing is pinned with, and it is the strongest form the suite has: the module under
 * test composes the APDU through its own codec, protects it through the crossing of the module it adopts, and hands
 * one NSDU down, and the octets that come out of the model's air are the vector an independent CPython
 * implementation of 4.4.1.1 computed, same link key, same local extended address, same counter, same APS header.
 * Nothing in this case knows the ciphertext: it is quoted. That is what makes it a test of the wiring and not of
 * the arithmetic, and it is why the two legs are the two auxiliary shapes: TxOptions 0x10 sets the extended nonce
 * and 4.5.1.3 turns it into a 13-octet auxiliary header, and TxOptions 0x10 clear turns it into a 5-octet one over
 * the same key and the next counter.
 */
void caseSecuredUnicastOut(void)
{
    Rig rig;
    Security security;
    Security_KeyPairEntry pairs[1];
    Air air[AIR_LOG_MAX];
    Aps_ApsdeReq req;
    Aps_Confirm confirms[2];
    uint8_t asdu[APS_VECTOR_PAYLOAD_LEN];
    uint32_t airCount = 0;
    uint32_t got;

    pairs[0] = apsPairAt(APS_PARTNER_IEEE, ADDR_PEER, 1, APS_OUTGOING_SEED, 0);
    securedRigBuild(&rig, &security, pairs, 1, APS_OWN_IEEE, OWN_SHORT);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);

    Test_ParseHex(s_apsPayloadHex, asdu, (uint32_t)sizeof asdu);

    rig.aps.apsCounter = APS_VECTOR_COUNTER;
    Test_Expect(rig.aps.apsCounter == APS_VECTOR_COUNTER,
          "the suite seeds the module's APS counter at the octet the vectors carry, the way case 4 seeds it to reach the top of the range: a vector is computed over an APS header, and 4.4.1.1 step 5d authenticates that header as written, so the counter octet has to be the one a1 names (2.2.5.1.7)");

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, APS_VECTOR_DST_EP, CLUSTER_ID, asdu, APS_VECTOR_PAYLOAD_LEN,
                 APS_TX_OPTION_SECURITY | APS_TX_OPTION_EXTENDED_NONCE);
    req.srcEndpoint = APS_VECTOR_SRC_EP;

    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK,
                  "a TxOptions 0x01|0x10 unicast is taken back, which is the whole of the door's answer now that the crossing exists: the pair was found by the alias lookup and the request was not refused for asking");

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 1, "and one frame went on the air, inside the request itself (2.2.8.4.1)");
    Test_Expect(apduLenOf(&air[0]) == APS_HEADER_UNICAST_FORM + 13 + APS_VECTOR_PAYLOAD_LEN + 4,
          "8 octets of APS header, 13 of auxiliary, 5 of ciphertext and a 4-octet MIC: 4.4.1.1 step 7's `ApsHeader || AuxiliaryHeader || c` at level 0x05 (Table 4-38's M = 4) with the 13-octet auxiliary 4.5.1.3 gives key identifier '00' with the extended nonce set");
    Test_ExpectHex("case 25: the APDU the service put on the air is the a1 vector octet for octet",
                 apduOf(&air[0]), apduLenOf(&air[0]), s_apsFrame1Hex);
    Test_Expect(apduOf(&air[0])[0] == 0x20,
          "FCF 0x20: frame type Data, delivery mode Unicast, ACK format 0, Security 1, ACK request 0, extended header absent. Bit 5 is the sub-field 2.2.5.1.1.4 hands to the provider, and this transaction is the first frame in this suite that ever sets it");
    Test_Expect(apduOf(&air[0])[APS_HEADER_UNICAST_FORM] == 0x60,
          "the auxiliary control 0x60: key identifier '00' in bits 3-4 (4.4.1.1 step 1a-i), the extended nonce in bit 5 (step 4a-ii, from TxOptions 0x10), the Require Verified Frame Counter in bit 6 (step 4a-iii with Table 4-41: 1 for an APS Datagram) and the level sub-field in bits 0-2 *cleared*, 4.4.1.1 step 10, the same mechanism one layer down: 0x28 on air against 0x2d in the nonce");
    Test_Expect(apduOf(&air[0])[APS_HEADER_UNICAST_FORM + 1] == APS_OUTGOING_SEED
           && apduOf(&air[0])[APS_HEADER_UNICAST_FORM + 2] == 0
           && apduOf(&air[0])[APS_HEADER_UNICAST_FORM + 3] == 0
           && apduOf(&air[0])[APS_HEADER_UNICAST_FORM + 4] == 0,
          "and the frame counter 0x00000004 low-octet first: the entry's OutgoingFrameCounter as the application seeded it, which is Table 4-36's counter and not the module's own number anywhere else");
    Test_Expect(npduOf(&air[0])[0] == NWK_FCF_DATA_DISCOVERING && npduOf(&air[0])[1] == 0x00,
          "carried in an unsecured minimal NWK data frame: TxOptions 0x02 was not asked for, so the layer below is the scaffold and bit 9 is 0 while APS bit 5 is 1, the two crossings are independent, which is what `Security_IsEnabled` says outright and this frame is the proof in one octet pair (3.3.1.1.4's \"implemented at another layer or disabled entirely\" is the other layer saying the same thing about its own bit)");

    Test_Expect(pairOutgoing(&security, 0) == APS_OUTGOING_SEED + 1,
          "4.4.1.1 step 9 moved the entry's counter, and `Security_Snapshot` exports it as the per-partner bank: the counter that moved is this partner's and not a device-wide one");
    Test_Expect(rig.aps.tx[0].apsSecurity == 1 && rig.aps.tx[0].extendedNonce == 1 && rig.aps.tx[0].keyPairIndex == 0,
          "the slot carries the crossing's three facts (that this transaction is secured, which nonce shape it asked for, and which entry the door resolved) and the module re-reads that index at every attempt rather than trusting the door");
    Test_Expect(rig.aps.tx[0].securedLen == apduLenOf(&air[0]),
          "and the length of the protected octets it handed down, which is the field `Aps_TxOutgoingOctets` reads to know the slot's stored APDU is not what goes on the wire");
    Test_Expect(Aps_TxSecuredFailures(&rig.aps) == 0 && Aps_TxNoKeyPair(&rig.aps) == 0,
          "neither transmit counter moved: the pair was there and the protection ran");
    Test_Expect(rig.aps.apsCounter == APS_VECTOR_COUNTER + 1,
          "and the transaction spent one APS counter, as any other transaction of this module does (2.2.5.1.7): the number a2's own header carries is the suite's re-seeding, said out loud at the second leg because a vector is a fact about one header");

    stepAt(&rig, air, &airCount, 101);

    got = Aps_PollConfirms(&rig.aps, confirms, 2);
    Test_Expect(got == 1 && confirms[0].status == ZB_OK && confirms[0].apsStatus == APS_STATUS_SUCCESS,
          "answered SUCCESS in both vocabularies with the delivery and ack machinery untouched: no AR was asked, so 2.2.8.4.3.1's \"the originating device SHALL assume that the transmission of the frame was successful\" is the whole of it, secured frame or not");
    Test_Expect(confirms[0].attempts == 1 && confirms[0].apsCounter == APS_VECTOR_COUNTER,
          "one NLDE transaction, and the APS counter the confirm reports is the one the frame travelled with: the crossing changes nothing about 2.2.5.2.3.1's match");

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, APS_VECTOR_DST_EP, CLUSTER_ID, asdu, APS_VECTOR_PAYLOAD_LEN,
                 APS_TX_OPTION_SECURITY);
    req.srcEndpoint = APS_VECTOR_SRC_EP;

    /* The module's APS counter is re-seeded to the octet a2 names, and that is the suite stating what it did:
       a1 and a2 are two protections of the *same* APS header (the same counter octet 0x11 with the link-frame
       counter stepping from 4 to 5) and a2 is only comparable with the header held equal. A transaction of this
       module would have taken 0x12 here, which is 2.2.5.1.7 doing its job and not a defect the vector can judge. */
    rig.aps.apsCounter = APS_VECTOR_COUNTER;

    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 102), ZB_OK,
                  "the same destination and the same ASDU with TxOptions 0x10 clear");

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 2, "and a second frame on the air");
    Test_Expect(apduLenOf(&air[1]) == APS_HEADER_UNICAST_FORM + 5 + APS_VECTOR_PAYLOAD_LEN + 4,
          "22 octets: the auxiliary header is 1 + 4 with no source address field, because 4.5.1.3 makes the source field the extended nonce and the extended nonce is TxOptions 0x10, the bit recorded as accepted and ignored is now the selector it is");
    Test_ExpectHex("case 25: the second frame is the a2 vector octet for octet",
                 apduOf(&air[1]), apduLenOf(&air[1]), s_apsFrame2Hex);
    Test_Expect(apduOf(&air[1])[APS_HEADER_UNICAST_FORM] == 0x40,
          "control 0x40: the same key identifier and the same RVFC bit with the extended nonce cleared");
    Test_Expect(apduOf(&air[1])[APS_HEADER_UNICAST_FORM + 1] == APS_OUTGOING_SEED + 1,
          "and the counter stepped to 5: the pair's counter moves per protection (4.4.1.1 step 9), which is the same rule one layer up and the reason this module protects afresh at each issue instead of storing the secured octets in the slot");
    Test_Expect(pairOutgoing(&security, 0) == APS_OUTGOING_SEED + 2, "and the entry now holds 6");

    stepAt(&rig, air, &airCount, 103);

    Test_Expect(Aps_PollConfirms(&rig.aps, confirms, 2) == 1 && confirms[0].apsStatus == APS_STATUS_SUCCESS,
          "answered the same way");
    Test_Expect(Aps_TransmitQueue(&rig.aps) == 0 && Aps_RxSecuredDeferred(&rig.aps) == 0
           && Aps_RxSecuredFailuresAuth(&rig.aps) == 0 && Aps_RxSecuredFailuresCounters(&rig.aps) == 0
           && Aps_AcksGenerated(&rig.aps) == 0 && Aps_DroppedIndications(&rig.aps) == 0,
          "and nothing else moved: this is a transmit-only case, and the reception family (including the crossing's own failure counters) is what stays at zero because nothing arrived (2.2.8.4.2 had no frame to decide)");
}

/*
 * 26. Secured frames in: the three ways a receiver can find out who sent one (4.4.1.2 step 2).
 *
 * a1 arrives at a device that holds the pair its auxiliary header names, and authenticates. a2 arrives
 * at the same device naming no address anywhere in its 22 octets, and authenticates because *this
 * layer* named the partner: the source address of the NLDE indication is the only address band A has,
 * `Security_FindKeyPairByShort` is the only map-shaped thing it has, and this layer takes exactly that
 * half of 4.4.1.2 step 2 to `aps`. a2 also shows the duplicate table sitting under the crossing: a1 and a2
 * are two protections of one APS header (the same source address and the same APS counter, which is the
 * key 2.2.8.4.2 prints), so the second is authenticated, spends its counter, and is then dropped as the
 * duplicate it is. That is the shape the vectors have and the case states it rather than arranging around it,
 * and the proof that a2 authenticated is the window it moved, which no refusal moves (case 30 asserts that
 * half directly). a3 is delivered at a second device (the other end of the same link key, because a3 is the
 * reply its partner sent) from a peer whose 16-bit address names nothing at all, and it authenticates on the
 * address the frame carries. A hint is not a check of a frame; it is the address the map could not supply.
 */
void caseSecuredInVectors(void)
{
    Rig b;
    Rig a;
    Security bSec;
    Security aSec;
    Security_KeyPairEntry bPairs[1];
    Security_KeyPairEntry aPairs[1];
    Test_BandA peer;
    Test_BandA other;
    Air air[AIR_LOG_MAX];
    Aps_Indication inds[2];
    uint8_t apdu[APS_FRAME_MAX];
    uint8_t wantPayload[APS_VECTOR_PAYLOAD_LEN];
    uint8_t wantReply[APS_REPLY_PAYLOAD_LEN];
    uint32_t airCount = 0;
    uint32_t len;

    Test_ParseHex(s_apsPayloadHex, wantPayload, (uint32_t)sizeof wantPayload);
    Test_ParseHex(s_apsReplyPayloadHex, wantReply, (uint32_t)sizeof wantReply);

    bPairs[0] = apsPairAt(APS_OWN_IEEE, ADDR_PEER, 1, 0, 0);
    aPairs[0] = apsPairAt(APS_PARTNER_IEEE, ADDR_PEER, 1, 0, 0);

    securedRigBuild(&b, &bSec, bPairs, 1, APS_PARTNER_IEEE, OWN_SHORT);
    securedRigBuild(&a, &aSec, aPairs, 1, APS_OWN_IEEE, OWN_SHORT);

    peerBuild(&peer, ADDR_PEER);
    peerBuild(&other, UNSEEN);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    seedNeighbor(&other.nwk, OWN_SHORT);
    scriptOutcomes(&b.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&a.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&other.model, LOOPBACK_TX_MAX, 1);

    len = Test_ParseHex(s_apsFrame1Hex, apdu, (uint32_t)sizeof apdu);
    Test_Expect(len == 30, "a1 is the 30 octets it is quoted as before any of it is handed over");

    peerDelivers(&peer, &b.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&b, air, &airCount, 101);

    Test_Expect(Aps_RxSecuredDeferred(&b.aps) == 0 && Aps_RxSecuredFailuresAuth(&b.aps) == 0
           && Aps_RxSecuredFailuresCounters(&b.aps) == 0 && Aps_RxMalformed(&b.aps) == 0,
          "none of the reception family moved: this secured frame is not a deferral, not a failure and not damage");
    Test_Expect(Aps_IndicationQueue(&b.aps) == 1, "one Table 2-4 indication");

    Zb_memset(inds, 0xa5, (uint32_t)sizeof inds);
    Test_Expect(Aps_PollIndications(&b.aps, inds, 2) == 1, "polled into a buffer full of the suite's own sentinel");
    Test_Expect(inds[0].status == APS_STATUS_SUCCESS,
          "Status SUCCESS: 2.2.4.1.3.2's \"Under all other circumstances, the APSDE sets the Status parameter to SUCCESS\", and the other circumstance of that same sentence (\"any status returned from the security processing of the frame\") is what cases 29 to 33 reach");
    Test_Expect(inds[0].securityStatus == APS_SECURITY_LINK_KEY,
          "SecurityStatus SECURED_LINK_KEY 0xab, which is Table 2-4's own word for it: \"SECURED_LINK_KEY if the ASDU was secured with a link key\". This field is one of the two the crossing reports, and an authenticated frame is the one case where the table's enumeration can be stated and not hedged");
    Test_Expect(inds[0].keyIndex == 0 && inds[0].keyStatus == SECURITY_KEYPAIR_ATTR_VERIFIED,
          "KeyIndex 0 (the index in `apsDeviceKeyPairSet` the module reported) and the key status that entry's Table 4-36 KeyAttributes carry, read through `Security_KeyPairAt`. Table 2-4 prints KeyIndex as a number and the entry itself only as a `DeviceKeyPairEntry` handle kept omitted here; an index plus the attribute behind it is what the table's own KeyIndex row invites: \"the application may use this index to obtain all the details about the key\"");
    Test_Expect(inds[0].asduLength == APS_VECTOR_PAYLOAD_LEN
           && Zb_memcmp(inds[0].asdu, wantPayload, APS_VECTOR_PAYLOAD_LEN) == 0,
          "and the ASDU is the 5 plaintext octets a1 carried, not the ciphertext and not the auxiliary header: 4.4.1.2 step 7b's `m` handed up as the ASDU, which is the whole point of the crossing existing");
    Test_Expect(inds[0].dstAddrMode == APS_ADDR_MODE_SHORT && inds[0].dstAddress == OWN_SHORT
           && inds[0].srcAddrMode == APS_ADDR_MODE_SHORT && inds[0].srcAddress == ADDR_PEER
           && inds[0].srcEndpoint == APS_VECTOR_SRC_EP && inds[0].dstEndpoint == APS_VECTOR_DST_EP
           && inds[0].clusterId == CLUSTER_ID && inds[0].profileId == PROFILE_ID,
          "and every other parameter of Table 2-4 is the one the authenticated header carried: a secured frame's addressing is judged by the layer below from octets that are now known not to have been tampered with");
    Test_Expect(bSec.keyPairs[0].incomingFrameCounter == APS_OUTGOING_SEED + 1,
          "4.4.1.2 step 9 stored the window as ReceivedFrameCount + 1 after the CCM verified, and it is the entry's own window and not a device-wide one");
    Test_Expect(Aps_AcksGenerated(&b.aps) == 0 && airCount == 0,
          "no acknowledgement was owed and nothing went back out: a1's FCF is 0x20, so its AR sub-field is 0 and 2.2.8.4.3.1 answers that with silence, exactly as it does for an unsecured frame");

    len = Test_ParseHex(s_apsFrame2Hex, apdu, (uint32_t)sizeof apdu);
    Test_Expect(len == 22, "a2: 8 + 5 + 5 + 4");

    peerDelivers(&peer, &b.stack.model, OWN_SHORT, apdu, len, 102);
    stepAt(&b, air, &airCount, 103);

    Test_Expect(Aps_RxSecuredFailuresAuth(&b.aps) == 0 && Aps_RxSecuredDeferred(&b.aps) == 0
           && Aps_RxSecuredFailuresCounters(&b.aps) == 0,
          "no failure and no deferral is counted for a2, although the frame names no sender anywhere in its 22 octets: this device resolved the 16-bit source of the NLDE indication to the entry that carries it as an alias and handed the EUI64 in as step 2's SourceAddress, because 4.4.1.2 puts the address map above the security procedure and `aps` holds the only map-shaped thing band A has. A hint that was not consulted (or an alias lookup that ignored the address the frame arrived from) lands this frame in `rxSecuredFailuresAuth` instead, which is the mutation this case exists to catch; case 33 is the frame whose hint resolves nothing at all");
    Test_Expect(bSec.keyPairs[0].incomingFrameCounter == APS_OUTGOING_SEED + 2,
          "and the proof it authenticated is the window: 6, the counter a2 carried plus one. A frame refused at step 3, step 4 or step 7a stores nothing, so a window that moved is a tag that verified (4.4.1.2 steps 4, 7a and 9)");
    Test_Expect(Aps_RxDuplicateDrops(&b.aps) == 1 && Aps_IndicationQueue(&b.aps) == 0,
          "and a2 is dropped as a duplicate, which is what the two vectors actually are: a1 and a2 are two protections of the *same* APS header (same source address, same APS counter 0x11, the link-frame counter stepping from 4 to 5) and 2.2.8.4.2's key is exactly those two fields, so the second copy is \"identified as a duplicate\" and not delivered twice. The security decision ran first and is counted where it belongs; the delivery decision ran after and is counted where it belongs. A suite that wanted an indication for a2 would have had to change a header octet the authentication covers, and this suite does not change authenticated octets to make a delivery appear");
    Test_Expect(Aps_AcksGenerated(&b.aps) == 0 && airCount == 0,
          "and nothing went out for it: a2's AR bit is 0 like a1's, and a deduplicated frame owes nothing in any case (2.2.8.4.2)");

    len = Test_ParseHex(s_apsFrame3Hex, apdu, (uint32_t)sizeof apdu);
    Test_Expect(len == 28, "a3: 8 + 13 + 3 + 4, the partner's own reply with its own extended address in the auxiliary source field and counter 7");

    peerDelivers(&other, &a.stack.model, OWN_SHORT, apdu, len, 104);
    stepAt(&a, air, &airCount, 105);

    Test_Expect(Aps_IndicationQueue(&a.aps) == 1 && Aps_RxSecuredFailuresAuth(&a.aps) == 0
           && Aps_RxSecuredDeferred(&a.aps) == 0,
          "and a3 arrives at the device it was sent to (the other end of the same link key) from a peer whose short address, 0x9999, names no alias on any entry of the set: this layer handed in no hint at all, and the frame still authenticated, because when the extended nonce sub-field is 1 the auxiliary header carries the sender's own extended address and 4.4.1.2 step 2 reads *that*. The nonce's address half is the partner the entry names, which is the same number the auxiliary carried: \"the nonce's source octets are always an EUI64, never an accident\", seen from the receiving side");

    Zb_memset(inds, 0xa5, (uint32_t)sizeof inds);
    Test_Expect(Aps_PollIndications(&a.aps, inds, 2) == 1, "one indication for a3");
    Test_Expect(inds[0].status == APS_STATUS_SUCCESS && inds[0].securityStatus == APS_SECURITY_LINK_KEY
           && inds[0].keyIndex == 0 && inds[0].keyStatus == SECURITY_KEYPAIR_ATTR_VERIFIED,
          "SECURED_LINK_KEY, index 0, VERIFIED: the entry the air named is the entry this device holds the key with");
    Test_Expect(inds[0].srcEndpoint == APS_VECTOR_SRC_EP && inds[0].dstEndpoint == APS_VECTOR_DST_EP
           && inds[0].srcAddress == UNSEEN && inds[0].clusterId == CLUSTER_ID,
          "with a3's own header fields, and `srcAddress` still the 16-bit address the NWK layer carried, because the address map that would have upgraded it to Table 2-4's 0x03 is a deferral and knowing a partner for the purpose of decrypting is not the map the indication parameter needs");
    Test_Expect(inds[0].asduLength == APS_REPLY_PAYLOAD_LEN
           && Zb_memcmp(inds[0].asdu, wantReply, APS_REPLY_PAYLOAD_LEN) == 0
           && inds[0].asdu[APS_REPLY_PAYLOAD_LEN] == 0,
          "and a3's ASDU is the 3 octets a3 carried and nothing after them: the ring slot is cleared before it is filled, so what lies past `asduLength` is zero and not a fragment of the frame's ciphertext, a delivery of 3 octets, reported as 3 octets, with nothing half-written behind it");
    Test_Expect(aSec.keyPairs[0].incomingFrameCounter == APS_REPLY_COUNTER + 1,
          "and the window at this end is 8: a3 carried counter 7 and step 9 stores one more (4.4.1.2 step 9)");
    Test_Expect(Aps_RxDuplicateDrops(&a.aps) == 0 && Aps_AcksGenerated(&a.aps) == 0 && airCount == 0,
          "nothing was deduplicated at this device, nothing was answered and nothing was put on the air: one frame from one peer, one delivery, no ask on it");
}

/*
 * 27. The pair of full stacks this case is built on: a secured unicast with AR set, answered and matched
 * (4.4.1.1, 4.4.1.2, 2.2.8.4.3.2, 2.2.8.4.4).
 *
 * Two devices of this stack, one key pair seeded twice (the same 16 link-key octets with the partner's address on
 * each side, which is what "shared" means in Table 4-36's DeviceAddress row), each with its own `mac`, `nwk`,
 * `aps` and its own `Security`. What the case pins is that the crossing did not disturb the acknowledgement
 * machine it was dropped into: the answer B owes is composed by the same code as every other owed answer, carries
 * the same APS counter as the frame it answers, travels unsecured, and matches A's slot on exactly the four parts
 * 2.2.8.4.4 prints plus band A's own source guard.
 */
void caseSecuredEndToEndPair(void)
{
    Rig a;
    Rig b;
    Security aSec;
    Security bSec;
    Security_KeyPairEntry aPairs[1];
    Security_KeyPairEntry bPairs[1];
    Air aAir[AIR_LOG_MAX];
    Air bAir[AIR_LOG_MAX];
    Aps_Confirm confirms[2];
    Aps_Indication inds[2];
    Aps_ApsdeReq req;
    uint32_t aAirCount = 0;
    uint32_t bAirCount = 0;
    static const uint8_t pairAsdu[ASDU_LEN] = { 0x70, 0x61, 0x69, 0x72, 0x65, 0x64 };

    aPairs[0] = apsPairAt(APS_PARTNER_IEEE, ADDR_PEER, 1, APS_OUTGOING_SEED, 0);
    bPairs[0] = apsPairAt(APS_OWN_IEEE, OWN_SHORT, 1, APS_OUTGOING_SEED, 0);

    securedRigBuild(&a, &aSec, aPairs, 1, APS_OWN_IEEE, OWN_SHORT);
    securedRigBuild(&b, &bSec, bPairs, 1, APS_PARTNER_IEEE, ADDR_PEER);

    seedNeighbor(&a.stack.nwk, ADDR_PEER);
    seedNeighbor(&b.stack.nwk, OWN_SHORT);
    scriptOutcomes(&a.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&b.stack.model, LOOPBACK_TX_MAX, 1);

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, pairAsdu, ASDU_LEN,
                 APS_TX_OPTION_SECURITY | APS_TX_OPTION_EXTENDED_NONCE | APS_TX_OPTION_ACK);

    Test_ExpectStatus(Aps_DataRequest(&a.aps, &req, 100), ZB_OK,
                  "A sends a secured acknowledged unicast to B: 0x01 selects the link key, 0x10 the 13-octet auxiliary, 0x04 the acknowledgement ask");

    harvestAir(&a.stack.model, aAir, &aAirCount);
    Test_Expect(aAirCount == 1 && apduOf(&aAir[0])[0] == 0x60,
          "one frame out, its APS Frame Control Field 0x60: data, unicast, security set and AR set (Figure 2-4)");

    handOver(&a.stack.model, &b.stack.model);

    stepAt(&a, aAir, &aAirCount, 101);
    Test_Expect(a.aps.tx[0].state == APS_TX_AWAITING_ACK && a.aps.tx[0].ackDeadlineMs == 1701,
          "and A is in the state 2.2.8.4.4 puts it in: the NLDE confirmed, so the acknowledgement is what is outstanding, waited for a full `apscAckWaitDuration`, the secured transaction waits exactly like any other");

    stepAt(&b, bAir, &bAirCount, 101);

    Test_Expect(bAirCount == 1 && apduLenOf(&bAir[0]) == APS_HEADER_UNICAST_FORM,
          "B answered: eight octets and nothing after them, Figure 2-9's ACK format 0 acknowledgement of 2.2.5.2.3.1");
    Test_Expect(apduOf(&bAir[0])[0] == APS_FCF_ACK,
          "FCF 0x02: frame type Acknowledgement, delivery mode unicast, ACK format 0, Security 0, ACK request 0 (2.2.8.4.3). The acknowledgement of an APS-secured data frame is itself unsecured, and band A states that as its reading rather than as a quote: 4.4.1.1 protects the `Payload` of an APS data frame and a Figure 2-9 acknowledgement prints no payload field to protect, while 2.2.5.2.3.1 fixes only what the answer must repeat, the cluster, the profile, the extended header and the APS counter. A secured acknowledgement is a form Table 4-41 prints, and this stack reads one (case 34) without sending one");
    Test_Expect(apduOf(&bAir[0])[APS_COUNTER_OCTET_UNICAST] == apduOf(&aAir[0])[APS_COUNTER_OCTET_UNICAST],
          "and it carries the same APS counter as the frame it answers (2.2.5.2.3.1): the octet inside the authenticated header, and the one A's match reads");
    Test_Expect(apduOf(&bAir[0])[1] == SRC_EP && apduOf(&bAir[0])[6] == DST_EP,
          "with the endpoint swap 2.2.5.2.3.1 states: the acknowledgement's source endpoint is the destination endpoint A sent to and its destination endpoint is A's source endpoint, checked against a composition this case did not make, in the column order Figure 2-9 shares with Figure 2-7 (frame control, destination endpoint, cluster, profile, source endpoint, APS counter)");
    Test_Expect(npduOf(&bAir[0])[0] == NWK_FCF_DATA_DISCOVERING && npduOf(&bAir[0])[1] == 0x00 && airDestOf(&bAir[0]) == OWN_SHORT,
          "in an unsecured minimal NWK data frame aimed back at A");

    Zb_memset(inds, 0xa5, (uint32_t)sizeof inds);
    Test_Expect(Aps_PollIndications(&b.aps, inds, 2) == 1,
          "and B delivered one indication: the delivery and the answer are two obligations and neither waits for the other (2.2.8.4.2, 2.2.8.4.3.2)");
    Test_Expect(inds[0].status == APS_STATUS_SUCCESS && inds[0].securityStatus == APS_SECURITY_LINK_KEY
           && inds[0].keyIndex == 0 && inds[0].keyStatus == SECURITY_KEYPAIR_ATTR_VERIFIED
           && inds[0].asduLength == ASDU_LEN && Zb_memcmp(inds[0].asdu, pairAsdu, ASDU_LEN) == 0,
          "SUCCESS at B, SECURED_LINK_KEY with index 0 and the VERIFIED attribute behind it, and the 6 octets A's application asked to have sent: end to end through two stacks of this tree and one key pair");
    Test_Expect(inds[0].srcAddress == OWN_SHORT && inds[0].dstAddress == ADDR_PEER
           && inds[0].srcEndpoint == SRC_EP && inds[0].dstEndpoint == DST_EP,
          "with the addressing the NWK layer carried (A at 0xdead sent to B at 0x0011, Table 3-4's originator in `srcAddress` and this device's own address in `dstAddress`) and the endpoints the authenticated header carried");
    Test_Expect(bSec.keyPairs[0].incomingFrameCounter == APS_OUTGOING_SEED + 1
           && pairOutgoing(&bSec, 0) == APS_OUTGOING_SEED,
          "B's entry stored the window and did *not* move its outgoing counter: 4.4.1.2 step 9 against 4.4.1.1 step 9, one entry, two counters, and receiving is not sending");
    Test_Expect(pairOutgoing(&aSec, 0) == APS_OUTGOING_SEED + 1 && Aps_TxSecuredFailures(&a.aps) == 0,
          "while A's entry moved once for the frame it produced");

    handOver(&b.stack.model, &a.stack.model);

    stepAt(&a, aAir, &aAirCount, 102);

    Test_Expect(Aps_PollConfirms(&a.aps, confirms, 2) == 1
           && confirms[0].status == ZB_OK && confirms[0].apsStatus == APS_STATUS_SUCCESS,
          "and A's transaction was released by that answer, SUCCESS in both vocabularies: the match machinery of 2.2.8.4.4 unchanged by the crossing, matching on cluster, counter, source endpoint and band A's own guard that the frame came from the device the transaction addressed");
    Test_Expect(confirms[0].attempts == 1
           && confirms[0].apsCounter == apduOf(&aAir[0])[APS_COUNTER_OCTET_UNICAST],
          "one NLDE transaction, and the counter the confirm reports is the one the secured frame carried: read off the air, because the slot that held the transaction is cleared by the act that answers it");

    stepAt(&b, bAir, &bAirCount, 102);

    Test_Expect(Aps_ConfirmationsIgnored(&b.aps) == 1 && Aps_UnmatchedAcks(&a.aps) == 0
           && Aps_AcksGenerated(&b.aps) == 1 && Aps_RxSecuredDeferred(&b.aps) == 0
           && Aps_RxSecuredFailuresAuth(&b.aps) == 0 && Aps_RxSecuredFailuresCounters(&b.aps) == 0
           && Aps_RxDuplicateDrops(&b.aps) == 0,
          "and the bookkeeping is the bookkeeping this module already did for an unsecured owed answer: the ack's own NLDE confirmation matches no transaction of B's and is counted as ignored, nothing at A went unmatched, and nothing anywhere was deferred or refused");
}

/*
 * 28. A secured transaction's four attempts are four protections (4.4.1.1 step 9 and 4.4.1.2 step 4).
 *
 * The design decision the crossing had to make, stated where it can be seen: the slot stores the *unsecured* `APS
 * header ‖ ASDU` and each issue protects afresh, because 4.4.1.1 step 9 moves the key pair's OutgoingFrameCounter
 * for every frame this device produces and 4.4.1.2 step 4 refuses a ReceivedFrameCount below the
 * `IncomingFrameCounter` the peer stores as ReceivedFrameCount + 1, so a retransmission that re-offered the same
 * secured octets would be a frame its peer refuses as a replay, and an acknowledged transaction that is
 * retransmitted is a frame the peer is expected to accept more than once. What the transaction holds constant is
 * its APS counter (2.2.5.1.7 with 2.2.8.4.4), which is a header field, inside the authenticated string, and the
 * field the acknowledgement matches on. Four attempts at A, four frames at B, and the pair of assertions that
 * prove both halves: A's four APDUs differ where the auxiliary counter is and agree everywhere the transaction
 * chose; B authenticates all four and delivers one.
 */
void caseSecuredRetransmissionReprotects(void)
{
    Rig a;
    Rig b;
    Security aSec;
    Security bSec;
    Security_KeyPairEntry aPairs[1];
    Security_KeyPairEntry bPairs[1];
    Air aAir[AIR_LOG_MAX];
    Air bAir[AIR_LOG_MAX];
    Aps_Confirm confirms[2];
    Aps_ApsdeReq req;
    uint32_t aAirCount = 0;
    uint32_t bAirCount = 0;
    uint32_t i;
    static const uint32_t retryAt[] = { 1701, 3302, 4903 };
    static const uint8_t againAsdu[ASDU_LEN] = { 0x61, 0x67, 0x61, 0x69, 0x6e, 0x34 };

    aPairs[0] = apsPairAt(APS_PARTNER_IEEE, ADDR_PEER, 1, APS_OUTGOING_SEED, 0);
    bPairs[0] = apsPairAt(APS_OWN_IEEE, OWN_SHORT, 1, 0, 0);

    securedRigBuild(&a, &aSec, aPairs, 1, APS_OWN_IEEE, OWN_SHORT);
    securedRigBuild(&b, &bSec, bPairs, 1, APS_PARTNER_IEEE, ADDR_PEER);

    seedNeighbor(&a.stack.nwk, ADDR_PEER);
    seedNeighbor(&b.stack.nwk, OWN_SHORT);
    scriptOutcomes(&a.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&b.stack.model, LOOPBACK_TX_MAX, 1);

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, againAsdu, ASDU_LEN,
                 APS_TX_OPTION_SECURITY | APS_TX_OPTION_EXTENDED_NONCE | APS_TX_OPTION_ACK);

    Test_ExpectStatus(Aps_DataRequest(&a.aps, &req, 100), ZB_OK, "a secured acknowledged unicast that B will answer once and A will retry");

    harvestAir(&a.stack.model, aAir, &aAirCount);
    handOver(&a.stack.model, &b.stack.model);

    stepAt(&a, aAir, &aAirCount, 101);
    stepAt(&b, bAir, &bAirCount, 101);

    for (i = 0; i < 3; i++)
    {
        stepAt(&a, aAir, &aAirCount, retryAt[i]);
        Test_Expect(aAirCount == i + 2, "and the retry one full wait after the attempt it belongs to is another frame on the air (2.2.8.4.4)");
        handOver(&a.stack.model, &b.stack.model);

        stepAt(&a, aAir, &aAirCount, retryAt[i] + 1);
        stepAt(&b, bAir, &bAirCount, retryAt[i] + 1);
    }

    Test_Expect(aAirCount == 1 + APS_MAX_FRAME_RETRIES,
          "four attempts, which is 1 + apscMaxFrameRetries and the end of the loop (Table 2-23)");

    for (i = 0; i < 1 + APS_MAX_FRAME_RETRIES; i++)
    {
        Test_Expect(apduLenOf(&aAir[i]) == APS_HEADER_UNICAST_FORM + 13 + ASDU_LEN + 4,
              "each one the same length: the same APS header, the same 13-octet auxiliary, the same 6 ASDU octets and a 4-octet MIC");
        Test_Expect(Zb_memcmp(apduOf(&aAir[i]), apduOf(&aAir[0]), APS_HEADER_UNICAST_FORM) == 0,
              "and the same eight header octets, frame control included: the transaction's delivery mode, its security bit, its AR bit, its endpoints, its cluster, its profile and its APS counter did not change across the retries (2.2.5.1.7)");
        Test_Expect(apduOf(&aAir[i])[APS_HEADER_UNICAST_FORM + 1] == (uint8_t)(APS_OUTGOING_SEED + i),
              "with the auxiliary frame counter stepped: 4, 5, 6, 7. The link-frame counter belongs to the protection and the protection belongs to the attempt (4.4.1.1 step 9), which is the arrangement one layer down in the NWK slot");
        Test_Expect(i == 0 || Zb_memcmp(apduOf(&aAir[i]), apduOf(&aAir[0]), apduLenOf(&aAir[i])) != 0,
              "and the frames are not the same frame: the second, third and fourth differ from the first, which is what this design refuses to do (re-offering identical secured octets is re-offering a count the peer has used). The four distinct entries in this suite's own air log already say the same thing, since the log keys on the octets it captured: four APDUs that were byte-identical would have been one entry with a note that nothing new appeared");
    }

    stepAt(&a, aAir, &aAirCount, 6504);

    Test_Expect(Aps_PollConfirms(&a.aps, confirms, 2) == 1
           && confirms[0].apsStatus == APS_STATUS_NO_ACK && confirms[0].attempts == 1 + APS_MAX_FRAME_RETRIES,
          "answered NO_ACK 0xa7 with four NLDE transactions behind it, the same answer an unsecured transaction gets when its acknowledgement never arrives: the crossing added nothing to the retry loop and took nothing away");
    Test_Expect(pairOutgoing(&aSec, 0) == APS_OUTGOING_SEED + 1 + APS_MAX_FRAME_RETRIES
           && Aps_TxSecuredFailures(&a.aps) == 0 && Aps_RetransmitRefusals(&a.aps) == 0,
          "the entry's counter moved four times, once per frame this device produced, and no attempt failed at the crossing (4.4.1.1 step 9 runs only for a frame that became the secured frame, and four frames did)");

    Test_Expect(Aps_RxSecuredFailuresCounters(&b.aps) == 0 && Aps_RxSecuredFailuresAuth(&b.aps) == 0,
          "and at B not one of the four failed the freshness rule of 4.4.1.2 step 4, which is the whole point of re-protecting per attempt: a peer that stores `ReceivedFrameCount + 1` refuses a repeat of the count, and four counts is four acceptances");
    Test_Expect(bSec.keyPairs[0].incomingFrameCounter == APS_OUTGOING_SEED + 1 + APS_MAX_FRAME_RETRIES,
          "the window B stored is 8, the last count plus one (4.4.1.2 step 9)");
    Test_Expect(Aps_RxDuplicateDrops(&b.aps) == 3,
          "and three of the four were dropped as duplicates after they authenticated: the crossing sits above the duplicate gate of 2.2.8.4.2 on purpose, so the security decision is taken for every secured frame this device hears and the dedup then decides what is delivered once. A frame this stack authenticates twice has spent two counters and earns one delivery, and the two counters say so separately");
    Test_Expect(Aps_IndicationQueue(&b.aps) == 1 && Aps_AcksGenerated(&b.aps) == 4 && bAirCount == 4,
          "one delivery and four acknowledgements at B: the duplicate gate suppresses the delivery alone, and 2.2.8.4.3.2 answers every copy that asked, which is what lets A's retry end on a lost acknowledgement");
}

/*
 * 29. A replay of a secured frame: the counter refusal, and the Table 2-4 failure indication the crossing
 * mandates (4.4.1.2 steps 1, 4 and 9, 2.2.4.1.3.2, Table 2-4).
 *
 * The frame is the one case 27's sender produced, AR bit set, captured off A's own air and delivered twice. The
 * second arrival is the point of the case: this stack does not silently drop a secured frame it could not accept.
 * 2.2.4.1.3.2 says what it does instead (the Status parameter carries the security error, the ASDULength is set to
 * 0 and the ASDU to the null set of bytes) and the failure is *not* an unauthenticated frame's licence to be
 * answered: the acknowledgement the first copy owed is not owed again, because the gate that decides validity sits
 * behind the authentication.
 */
void caseSecuredReplayRefused(void)
{
    Rig sender;
    Rig rig;
    Security senderSec;
    Security rigSec;
    Security_KeyPairEntry senderPairs[1];
    Security_KeyPairEntry rigPairs[1];
    Test_BandA peer;
    Air senderAir[AIR_LOG_MAX];
    Air air[AIR_LOG_MAX];
    Aps_Indication inds[2];
    uint8_t frame[APS_FRAME_MAX];
    uint32_t senderAirCount = 0;
    uint32_t airCount = 0;
    uint32_t len;
    uint32_t zeroed;
    uint32_t i;
    static const uint8_t replayAsdu[ASDU_LEN] = { 0x72, 0x65, 0x70, 0x6c, 0x61, 0x79 };

    senderPairs[0] = apsPairAt(APS_PARTNER_IEEE, OWN_SHORT, 1, APS_OUTGOING_SEED, 0);
    rigPairs[0] = apsPairAt(APS_OWN_IEEE, ADDR_PEER, 1, 0, 0);

    securedRigBuild(&sender, &senderSec, senderPairs, 1, APS_OWN_IEEE, ADDR_THIRD);
    securedRigBuild(&rig, &rigSec, rigPairs, 1, APS_PARTNER_IEEE, OWN_SHORT);

    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&sender.stack.nwk, OWN_SHORT);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&sender.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);

    len = securedFrameOut(&sender, senderAir, &senderAirCount, replayAsdu, ASDU_LEN,
                          APS_TX_OPTION_SECURITY | APS_TX_OPTION_EXTENDED_NONCE | APS_TX_OPTION_ACK,
                          frame);

    Test_Expect(len == APS_HEADER_UNICAST_FORM + 13 + ASDU_LEN + 4 && frame[0] == 0x60,
          "the frame under test is one this stack transmitted: 30 octets, FCF 0x60 with its acknowledgement ask set. Its NWK and MAC dress is not part of it: what is handed to the receiver below is the APDU, and the peer that carries it dresses it afresh, which is the fact that an APS header carries no device address at all");

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, frame, len, 100);
    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_IndicationQueue(&rig.aps) == 1 && Aps_AcksGenerated(&rig.aps) == 1 && airCount == 1,
          "the first copy authenticated, was delivered and was answered: the AR bit and 2.2.8.4.3.2, exactly as for an unsecured frame");

    Zb_memset(inds, 0xa5, (uint32_t)sizeof inds);
    Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1
           && inds[0].status == APS_STATUS_SUCCESS && inds[0].securityStatus == APS_SECURITY_LINK_KEY
           && inds[0].keyIndex == 0 && inds[0].asduLength == ASDU_LEN
           && Zb_memcmp(inds[0].asdu, replayAsdu, ASDU_LEN) == 0,
          "and what was delivered was the plaintext: SUCCESS, SECURED_LINK_KEY, index 0, the 6 octets the sender's application handed down");

    Test_Expect(Aps_RxSecuredFailuresCounters(&rig.aps) == 0 && Aps_RxSecuredFailuresAuth(&rig.aps) == 0
           && rigSec.keyPairs[0].incomingFrameCounter == APS_OUTGOING_SEED + 1,
          "and the window moved to 5, which is what makes the next arrival the replay it is");

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, frame, len, 102);
    stepAt(&rig, air, &airCount, 103);

    Test_Expect(Aps_RxSecuredFailuresCounters(&rig.aps) == 1,
          "the second copy is 4.4.1.2 step 4's refusal (ReceivedFrameCount 4 is below the stored IncomingFrameCounter 5) counted under its own reason word and under no other");
    Test_Expect(Aps_RxSecuredFailuresAuth(&rig.aps) == 0 && Aps_RxSecuredDeferred(&rig.aps) == 0
           && Aps_RxMalformed(&rig.aps) == 0 && Aps_RxDuplicateDrops(&rig.aps) == 0,
          "and not as a key failure, not as a deferral, not as damage and not as a duplicate: the counters distinguish the reasons, which is why they are counted per reason, and the crossing's gate sitting above 2.2.8.4.2's is what keeps this frame out of the duplicate counter");

    Zb_memset(inds, 0xa5, (uint32_t)sizeof inds);
    Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1,
          "and the frame is indicated, not dropped: \"a frame whose processing fails is not silently dropped\", which is the difference between this crossing and the deferral it replaced");
    Test_Expect(inds[0].status == APS_STATUS_SECURITY_FAIL,
          "Status SECURITY_FAIL 0xad: 2.2.4.1.3.2's \"the APSDE sets the Status parameter to the security error code returned from the security processing\", and Table 2-29's only member of that vocabulary. UNVERIFIED_FRAME_COUNTER is unenumerated there and a finer code here would be this stack inventing one");
    Test_Expect(inds[0].asduLength == 0,
          "asduLength 0, quoted: \"the APSDE sets the ASDULength parameter to 0 and the ASDU parameter to the null set of bytes\"");

    zeroed = 1;

    for (i = 0; i < (uint32_t)sizeof inds[0].asdu; i++)
    {
        if (inds[0].asdu[i] != 0)
            zeroed = 0;
    }

    Test_Expect(zeroed,
          "and every octet of the ASDU is zero: the caller's sentinel is gone and no octet of the frame's ciphertext was copied into the indication, which is what separates the standard's null set from a truncated delivery reported as one");
    Test_Expect(inds[0].securityStatus == APS_SECURITY_LINK_KEY && inds[0].keyIndex == 0
           && inds[0].keyStatus == SECURITY_KEYPAIR_ATTR_VERIFIED,
          "and the security parameters carry what this layer can honestly name: the frame was secured with a link key this device holds (the shape gate let it through, the source resolved to the pair) so KeyIndex names that pair and the key status names its attribute. `Security_UnprotectAps` reports its result only for a frame it accepted, so on a refusal these fields are this layer's own resolution and the comment at `Aps_RxSecureReceive` says so. Case 33 is the leg where this layer resolved nothing and all three carry the sentinels");
    Test_Expect(inds[0].clusterId == CLUSTER_ID && inds[0].profileId == PROFILE_ID
           && inds[0].srcAddress == ADDR_PEER && inds[0].dstEndpoint == DST_EP,
          "with the header fields of the refused frame intact: the header is authenticated even when the payload is refused, and an indication that named nothing about the frame it was refusing would be a less useful indication than the standard asks for");

    Test_Expect(Aps_AcksGenerated(&rig.aps) == 1 && airCount == 1,
          "and no second acknowledgement went out, although this frame asked for one: the AR gate of 2.2.5.1.1.5 is conditional on \"determining that the frame is valid\" and this frame failed the gate that decides validity. Answering an unauthenticated frame is trusting the exact octets 4.4.1 exists to make trustworthy, which is the reason the ordering in `apsDoReceive` has the crossing above the acknowledgement decision and not beside it");
    Test_Expect(rigSec.keyPairs[0].incomingFrameCounter == APS_OUTGOING_SEED + 1
           && pairOutgoing(&rigSec, 0) == 0
           && pairOutgoing(&senderSec, 0) == APS_OUTGOING_SEED + 1,
          "and the refusal consumed nothing: B's window stayed at 5, B's own outgoing counter stayed at the 0 the application seeded it with (receiving is not sending) and A's moved once for the one frame it produced (4.4.1.2 step 9 is not reached, 4.4.1.1 step 9 ran once)");
}

/*
 * 30. A tampered secured frame: the authentication refusal, nothing committed, and no answer owed
 * (4.4.1.2 steps 7a and 9, 2.2.8.4.3.2).
 *
 * One octet of the MIC, flipped in a frame this stack itself produced. The two things the case pins are the two
 * halves of commit-after-verify at this crossing (the refusal arrives at the seam and stores no window) and the
 * acknowledgement gate: this frame has its AR bit set, this device is its intended recipient, the header parses,
 * and still nothing goes back out. Then the pristine frame arrives and authenticates, which is the proof that the
 * tamper left nothing behind.
 */
void caseSecuredTamperRefused(void)
{
    Rig sender;
    Rig rig;
    Security senderSec;
    Security rigSec;
    Security_KeyPairEntry senderPairs[1];
    Security_KeyPairEntry rigPairs[1];
    Test_BandA peer;
    Air senderAir[AIR_LOG_MAX];
    Air air[AIR_LOG_MAX];
    Aps_Indication inds[2];
    uint8_t frame[APS_FRAME_MAX];
    uint32_t senderAirCount = 0;
    uint32_t airCount = 0;
    uint32_t len;
    uint32_t zeroed;
    uint32_t i;
    static const uint8_t tamperAsdu[ASDU_LEN] = { 0x74, 0x61, 0x6d, 0x70, 0x65, 0x72 };

    senderPairs[0] = apsPairAt(APS_PARTNER_IEEE, OWN_SHORT, 1, APS_OUTGOING_SEED, 0);
    rigPairs[0] = apsPairAt(APS_OWN_IEEE, ADDR_PEER, 1, 0, 0);

    securedRigBuild(&sender, &senderSec, senderPairs, 1, APS_OWN_IEEE, ADDR_THIRD);
    securedRigBuild(&rig, &rigSec, rigPairs, 1, APS_PARTNER_IEEE, OWN_SHORT);

    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&sender.stack.nwk, OWN_SHORT);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&sender.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);

    len = securedFrameOut(&sender, senderAir, &senderAirCount, tamperAsdu, ASDU_LEN,
                          APS_TX_OPTION_SECURITY | APS_TX_OPTION_EXTENDED_NONCE | APS_TX_OPTION_ACK,
                          frame);

    frame[len - 1] = (uint8_t)(frame[len - 1] ^ 0x01);

    Test_Expect(len == APS_HEADER_UNICAST_FORM + 13 + ASDU_LEN + 4,
          "the last octet of a 30-octet secured frame is the last octet of its MIC, and that is the one this case changes");

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, frame, len, 100);
    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_RxSecuredFailuresAuth(&rig.aps) == 1 && Aps_RxSecuredFailuresCounters(&rig.aps) == 0,
          "4.4.1.2 step 7a's \"invalid\" from the CCM operation, counted as an authentication failure and not as a counter one: the count was fine and the tag was not");
    Test_Expect(Aps_RxMalformed(&rig.aps) == 0 && Aps_RxSecuredDeferred(&rig.aps) == 0
           && Aps_RxDuplicateDrops(&rig.aps) == 0,
          "neither damage nor a deferral nor a duplicate: the frame is a well-formed secured frame whose contents were changed, which is the family the *authentication* counters are for");
    Test_Expect(Aps_AcksGenerated(&rig.aps) == 0 && airCount == 0,
          "and nothing went back out. This frame carries its AR bit, this device is the destination its NWK header names, its APS header parses, and no acknowledgement is composed: the validity gate sits behind 4.4.1.2, and this is the case that proves the gate moved, with the acknowledgement decision in front of the crossing, as the first slice had it, this assertion is where it fails");

    Zb_memset(inds, 0xa5, (uint32_t)sizeof inds);
    Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1 && inds[0].status == APS_STATUS_SECURITY_FAIL
           && inds[0].asduLength == 0,
          "and the failure indication the crossing reports, with the null ASDU");

    zeroed = 1;

    for (i = 0; i < (uint32_t)sizeof inds[0].asdu; i++)
    {
        if (inds[0].asdu[i] != 0)
            zeroed = 0;
    }

    Test_Expect(zeroed && inds[0].securityStatus == APS_SECURITY_LINK_KEY && inds[0].keyIndex == 0,
          "no octet of the tampered frame's ciphertext travels upward as an ASDU, and the pair this layer resolved is still named: the frame is refused, not unreadable");
    Test_Expect(rigSec.keyPairs[0].incomingFrameCounter == 0 && pairOutgoing(&rigSec, 0) == 0,
          "and nothing was committed: 4.4.1.2 step 9 stores a window only for a frame that authenticated, so the entry still holds the seed the application gave it and this device's own outgoing counter is untouched (a frame this module did not produce consumed nothing)");

    frame[len - 1] = (uint8_t)(frame[len - 1] ^ 0x01);

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, frame, len, 102);
    stepAt(&rig, air, &airCount, 103);

    Test_Expect(Aps_IndicationQueue(&rig.aps) == 1 && Aps_RxSecuredFailuresAuth(&rig.aps) == 1
           && rigSec.keyPairs[0].incomingFrameCounter == APS_OUTGOING_SEED + 1,
          "and the same octets with the same counter, unflipped, authenticate afterwards at the same entry: the tamper left no window behind and no verdict of its own, which is the difference between commit-after-verify and a stack that counted the frame before it checked it");
    Test_Expect(Aps_AcksGenerated(&rig.aps) == 1 && airCount == 1,
          "and now the acknowledgement this frame owed is composed and issued: the gate that refused the tamper is the same gate that answers the authentic frame, once");
}

/*
 * 31. A secured send with no key pair: NO_SHORT_ADDRESS, with nothing on the air.
 *
 * The two refusals a secured transmit can meet before anything runs are kept apart, because they are different facts
 * about the world: this device holds no pair for that destination, versus this device holds no key material at all
 * (case 2). And the mode 0x03 leg is the one this stack cannot honour whatever the key pair says: the
 * 64-bit-to-16-bit mapping 2.2.4.1.1.3 requires of `nwkAddressMap` is a deferral, so a mode-0x03 request is answered
 * NO_SHORT_ADDRESS at the door for the addressing reason and the pair is never consulted, which is also the reason
 * `Aps_TxResolveKeyPair`'s extended-address leg is written for the day the map lands and is asserted here as
 * unreachable today rather than quietly left unmentioned.
 */
void caseSecuredNoKeyPair(void)
{
    Rig rig;
    Security security;
    Security_KeyPairEntry pairs[1];
    Air air[AIR_LOG_MAX];
    Aps_Confirm confirms[2];
    Aps_ApsdeReq req;
    uint32_t airCount = 0;
    uint32_t counterBefore;
    static const uint8_t noneAsdu[ASDU_LEN] = { 0x6e, 0x6f, 0x70, 0x61, 0x69, 0x72 };

    pairs[0] = apsPairAt(APS_PARTNER_IEEE, ADDR_PEER, 1, APS_OUTGOING_SEED, 0);
    securedRigBuild(&rig, &security, pairs, 1, APS_OWN_IEEE, OWN_SHORT);
    seedNeighbor(&rig.stack.nwk, ADDR_PEER);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);

    counterBefore = rig.aps.apsCounter;

    req = sapReq(APS_ADDR_MODE_SHORT, UNSEEN, DST_EP, CLUSTER_ID, noneAsdu, ASDU_LEN,
                 APS_TX_OPTION_SECURITY | APS_TX_OPTION_EXTENDED_NONCE);

    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 100), ZB_OK,
                  "a secured unicast to a destination that names no entry: the call is taken back, because 2.2.4.1.1.3 answers this through the confirm and not through a return code");

    Test_Expect(Aps_PollConfirms(&rig.aps, confirms, 2) == 1
           && confirms[0].apsStatus == APS_STATUS_SECURITY_FAIL && confirms[0].status == ZB_OK,
          "answered SECURITY_FAIL 0xa5: 2.2.4.1.1.3 says the security service is used for a request that asks for protection and that \"if the security processing fails, the APSDE SHALL issue the APSDE-DATA.confirm primitive with a status of SECURITY_FAIL\", and a set with no entry for the destination is a processing that cannot be performed; NO_SHORT_ADDRESS is Table 2-29's words for a miss in the address map and belongs to the mode-0x03 door");
    Test_Expect(confirms[0].attempts == 0 && confirms[0].dstAddress == UNSEEN,
          "no attempt, and the destination the request named travels back in the confirm so the answer names the request that was made");
    Test_Expect(Aps_TxNoKeyPair(&rig.aps) == 1 && Aps_TxSecuredFailures(&rig.aps) == 0,
          "counted as a missing pair and not as a security failure: the two transmit counters exist precisely so a reader can tell \"no such partner\" from \"the protection failed\"");

    harvestAir(&rig.stack.model, air, &airCount);
    Test_Expect(airCount == 0 && Aps_TransmitQueue(&rig.aps) == 0 && Aps_ConfirmQueue(&rig.aps) == 0,
          "and no seam write at all: nothing was composed, nothing was handed down, no slot was taken, and the counter the entry holds is still the seed it was given");
    Test_Expect(rig.aps.apsCounter == counterBefore && pairOutgoing(&security, 0) == APS_OUTGOING_SEED,
          "no APS counter spent (a refusal transmits nothing (2.2.5.1.7)) and no link-frame counter moved, which is 4.4.1.1 step 9 refusing to run for a frame that was never produced");

    req = sapReq(APS_ADDR_MODE_EXTENDED, 0, DST_EP, CLUSTER_ID, noneAsdu, ASDU_LEN,
                 APS_TX_OPTION_SECURITY);
    req.dstExtendedAddress = APS_PARTNER_IEEE;

    Test_ExpectStatus(Aps_DataRequest(&rig.aps, &req, 101), ZB_OK,
                  "and a mode 0x03 secured request naming the very extended address this device *does* hold a pair with");
    Test_Expect(Aps_PollConfirms(&rig.aps, confirms, 2) == 1
           && confirms[0].apsStatus == APS_STATUS_NO_SHORT_ADDRESS,
          "still answered NO_SHORT_ADDRESS, and by the address map's door rather than by the key-pair set: a 64-bit destination has to become a 16-bit NWK address before any frame can be aimed at it, `nwkAddressMap` is Table 3-66's \"Null Set\" in this stack, and a key pair is not a route. The pair is never consulted for a request the addressing cannot carry, which is why the extended-address leg of the resolution is written and named and not reachable today");
    Test_Expect(Aps_TxNoKeyPair(&rig.aps) == 1 && Aps_TxSecuredFailures(&rig.aps) == 0 && airCount == 0,
          "and neither transmit counter moved for it: the answer was given before the key-pair question was asked, and the counts say so");
}

/*
 * 32. The secured shapes kept deferred, and the ordering that keeps a command out of the crossing
 * (the deferrals, 2.2.6 with 4.4.11).
 *
 * Two gates and one fact each. The command gate runs *below* the security gate, because which command a secured
 * frame carries is inside its protected region: 4.4.2.3's first act is security processing and only then the key
 * type. So a secured APS command whose auxiliary header is shorter than its control octet asks for is refused as
 * damage by the crossing, and a command that cannot be unprotected never reaches the key door at all. The
 * key-identifier gate is the module's, reached only for a data frame: '01' is refused as a shape and counted with
 * the deferral, because 4.4.1.2 prints no branch for a network key; '10' and '11' are not shapes any more, 4.4.1.2
 * step 3 b and c naming them, so those frames reach the crossing and are accounted for there.
 */
void caseSecuredShapesDeferred(void)
{
    Rig rig;
    Security security;
    Security_KeyPairEntry pairs[1];
    Test_BandA peer;
    Air air[AIR_LOG_MAX];
    Aps_Frame frame;
    uint8_t aux[13];
    uint8_t apdu[APS_FRAME_MAX];
    Aps_Indication inds[2];
    uint32_t airCount = 0;
    uint32_t len;
    static const uint8_t controlIds[] = { 0x28, 0x30, 0x38 };
    uint32_t i;

    pairs[0] = apsPairAt(APS_OWN_IEEE, ADDR_PEER, 1, APS_OUTGOING_SEED, 0);
    securedRigBuild(&rig, &security, pairs, 1, APS_PARTNER_IEEE, OWN_SHORT);
    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    aux[0] = 0x60;                 /* key identifier '00', extended nonce 1, RVFC 1, level cleared */
    aux[1] = APS_OUTGOING_SEED;
    aux[2] = 0;
    aux[3] = 0;
    aux[4] = 0;
    Test_ParseHex("efcdab8967452301", aux + 5, 8);

    Zb_memset(&frame, 0, (uint32_t)sizeof frame);
    frame.frameType = APS_FRAME_TYPE_COMMAND;
    frame.deliveryMode = APS_DELIVERY_UNICAST;
    frame.securityEnabled = 1;
    frame.ackRequest = 1;
    frame.apsCounter = 0x2a;

    len = composeApdu(&frame, aux, (uint32_t)sizeof aux, apdu);
    Test_Expect(len == 2 + (uint32_t)sizeof aux,
          "a secured APS command frame in Figure 2-8's shape (frame control and APS counter, the auxiliary header after them and the command identifier inside the protected payload) with a 13-octet auxiliary and a data-key identifier in its control octet, which is what 4.4.1.1 step 4a-ii prints for a command (extended nonce always 1) and 4.4.11 hands to the joining machinery, which is deferred");

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_RxMalformed(&rig.aps) == 1 && Aps_RxCommandDeferred(&rig.aps) == 0,
          "refused as damage by the crossing and never counted as a deferred command: 4.4.2.3's first act is security processing and the command identifier is inside the protected region, so the crossing runs first and this frame's thirteen octets are four short of the auxiliary header its control octet asks for plus a MIC");
    Test_Expect(Aps_RxSecuredDeferred(&rig.aps) == 0 && Aps_RxSecuredFailuresAuth(&rig.aps) == 0
           && Aps_RxSecuredFailuresCounters(&rig.aps) == 0,
          "and the failure family is untouched: a frame refused on its own length never reached the MIC, so no key pair's window was read and none was written");
    Test_Expect(security.keyPairs[0].incomingFrameCounter == 0
           && pairOutgoing(&security, 0) == APS_OUTGOING_SEED,
          "proved on the module's own numbers: the entry's window is still its seed and its outgoing counter is still its seed");
    Test_Expect(Aps_IndicationQueue(&rig.aps) == 0 && Aps_AcksGenerated(&rig.aps) == 0 && airCount == 0,
          "nothing indicated and nothing answered, whatever its AR bit");

    for (i = 0; i < (uint32_t)sizeof controlIds; i++)
    {
        dataHeader(&frame, APS_DELIVERY_UNICAST, 1, (uint8_t)(0x30 + i), DST_EP, CLUSTER_ID);
        frame.securityEnabled = 1;

        aux[0] = controlIds[i];
        len = composeApdu(&frame, aux, 9, apdu);
        Test_Expect(len == APS_HEADER_UNICAST_FORM + 9,
              "a secured data unicast with 5 octets of auxiliary header and 4 octets after them, which is long enough to be a frame and not the shape this crossing reads");

        peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 102 + i);
        stepAt(&rig, air, &airCount, 105 + i);

        /* '01' is a shape this slice does not process. '10' and '11' are not: 4.4.1.2 step 3 b and c derive their
           material by 4.5.3, so those frames reach the crossing and fail there on their own length. */
        if (i == 0)
        {
            Test_Expect(Aps_RxSecuredDeferred(&rig.aps) == 1,
                    "a control octet naming '01' is refused as a shape and counted in the deferral family: 4.4.1.1 steps 2 and 4d name it, never select it, and 4.4.1.2 has no branch for it");
            Test_Expect(Aps_RxSecuredFailuresAuth(&rig.aps) == 0 && Aps_RxSecuredFailuresCounters(&rig.aps) == 0
                   && Aps_RxMalformed(&rig.aps) == 1 && Aps_RxCommandDeferred(&rig.aps) == 0
                   && Aps_IndicationQueue(&rig.aps) == 0 && Aps_AcksGenerated(&rig.aps) == 0,
                   "and not in the failure family, not as fresh damage, not indicated and not answered: the deferral counts are kept for out-of-scope shapes and the failure counters are reserved for frames that reached the procedure and failed inside it, the one malformed frame being the command this case opened with");
        }
        else
        {
            Test_Expect(Aps_RxSecuredDeferred(&rig.aps) == 1,
                    "while '10' and '11' are no longer deferred: 4.4.1.2 step 3 b and c name them, so the frame is handed to the crossing");
            Test_ExpectCount(Aps_RxMalformed(&rig.aps), i + 1,
                    "and it is refused there as malformed, which is the shape's own fault and not the identifier's: this frame's control octet asks for the extended nonce and carries five octets of auxiliary header where thirteen are owed");
        }

        Test_Expect(security.keyPairs[0].incomingFrameCounter == 0
               && pairOutgoing(&security, 0) == APS_OUTGOING_SEED,
              "with the module's counters still untouched: a deferred shape never reaches them, and a frame that fails its MIC returns before the window is stored");
    }

    /* A frame whose auxiliary header is the length its control octet asks for, under '10': this one gets all the
       way to the MIC and fails there, which is what proves the identifier no longer stops it at the shape gate. */
    {
        uint8_t derivedAsdu[SECURITY_APS_AUX_MAX + 1 + SECURITY_MIC_32_OCTETS];

        Zb_memset(derivedAsdu, 0, (uint32_t)sizeof derivedAsdu);
        derivedAsdu[0] = 0x70;             /* '10', extended nonce 1, RVFC 1, level cleared: 4.4.1.1 step 4 a */
        derivedAsdu[1] = 0x30;
        Test_ParseHex("efcdab8967452301", derivedAsdu + 5, 8);
        derivedAsdu[SECURITY_APS_AUX_MAX] = 0x5a;

        dataHeader(&frame, APS_DELIVERY_UNICAST, 1, 0x3a, DST_EP, CLUSTER_ID);
        frame.securityEnabled = 1;

        len = composeApdu(&frame, derivedAsdu, (uint32_t)sizeof derivedAsdu, apdu);
        peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 200);
        stepAt(&rig, air, &airCount, 201);

        Test_ExpectCount(Aps_RxSecuredFailuresAuth(&rig.aps), 1,
                         "a frame of the right length under '10' reaches the CCM check and fails it, its tag being nothing this key produces");
        Test_Expect(security.keyPairs[0].incomingFrameCounter == 0
               && pairOutgoing(&security, 0) == APS_OUTGOING_SEED,
              "and the module's window and outgoing counter are still their seeds: 4.4.1.2 step 7 a fails before step 6's count is stored");
        Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1 && inds[0].status == APS_STATUS_SECURITY_FAIL,
              "and the frame is indicated with the security status, which 2.2.4.1.3.1 says the APSDE sets when security processing fails (\"the APSDE sets the Status parameter to the security error code returned from the security processing\"), not silently dropped");
        Test_Expect(Aps_AcksGenerated(&rig.aps) == 0,
              "and nothing acknowledged it: a frame that did not authenticate is not a frame this device answers for");
    }

    Test_Expect(airCount == 0,
          "and nothing this case put on the air: every one of these frames was refused before the point where an answer could be owed, and the four counters that name the four reasons (deferred, command deferred, authentication failure, counter failure) are the only account of them");
    Test_Expect(Aps_RxShapeRefused(&rig.aps) == 0 && Aps_UnmatchedAcks(&rig.aps) == 0
           && Aps_DroppedGroupMiss(&rig.aps) == 0 && Aps_DroppedIndications(&rig.aps) == 0,
          "and nothing landed in any other family: these are APS frames the codec read, aimed at this device, and refused by the service, not shapes, not damage, not duplicates and not lost for want of a ring slot");
}

/*
 * 33. A secured frame whose sender this layer cannot name: the hint is not a check of the frame
 * (4.4.1.2 steps 2, 3 and 4).
 *
 * The same two vectors a2 and a1, both delivered by a peer whose 16-bit address names no alias on any entry of the
 * set. a2 (the frame that carries no address anywhere) is refused for want of material, indicated with the failure
 * Status and the sentinels Table 2-4 leaves room for, and counted as an authentication failure and not a counter
 * one. a1 (the frame whose auxiliary names the sender outright) authenticates from the very same peer. Between the
 * two legs is the whole of the receiving half: the hint is the address the address map could not supply, and where
 * the frame supplies its own address the hint is not consulted at all.
 */
void caseSecuredNoPartnerNamed(void)
{
    Rig rig;
    Security security;
    Security_KeyPairEntry pairs[1];
    Test_BandA peer;
    Air air[AIR_LOG_MAX];
    Aps_Indication inds[2];
    uint8_t apdu[APS_FRAME_MAX];
    uint32_t airCount = 0;
    uint32_t len;
    uint32_t zeroed;
    uint32_t i;

    pairs[0] = apsPairAt(APS_OWN_IEEE, ADDR_PEER, 1, 0, 0);
    securedRigBuild(&rig, &security, pairs, 1, APS_PARTNER_IEEE, OWN_SHORT);
    peerBuild(&peer, UNSEEN);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&rig.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    len = Test_ParseHex(s_apsFrame2Hex, apdu, (uint32_t)sizeof apdu);

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&rig, air, &airCount, 101);

    Test_Expect(Aps_RxSecuredFailuresAuth(&rig.aps) == 1 && Aps_RxSecuredFailuresCounters(&rig.aps) == 0
           && Aps_RxSecuredDeferred(&rig.aps) == 0,
          "the frame is refused for want of material and counted as an authentication failure: its control octet is a shape this crossing reads, its count is inside any window, and the only thing missing is the address, 4.4.1.2 step 2's SourceAddress with nothing in `nwkAddressMap` to answer it and no auxiliary source field to answer it instead. There is no pre-installed-key fallback here either: step 2's \"joined and unauthorized\" branch is the joining machinery, deferred");

    Zb_memset(inds, 0xa5, (uint32_t)sizeof inds);
    Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1 && inds[0].status == APS_STATUS_SECURITY_FAIL
           && inds[0].asduLength == 0,
          "indicated as a failure with the null ASDU, the same shape case 29 asserts");

    zeroed = 1;

    for (i = 0; i < (uint32_t)sizeof inds[0].asdu; i++)
    {
        if (inds[0].asdu[i] != 0)
            zeroed = 0;
    }

    Test_Expect(zeroed && inds[0].securityStatus == APS_SECURITY_NONE
           && inds[0].keyIndex == APS_KEY_INDEX_NONE && inds[0].keyStatus == APS_KEY_STATUS_NONE,
          "and the security parameters carry the sentinels, because this layer can name no key: Table 2-4 bounds KeyIndex with \"This value is only valid when SecurityStatus is set to SECURED_LINK_KEY\", and a frame this device could not tie to any entry of `apsDeviceKeyPairSet` is not a frame it can say was secured with a link key. APS_SECURITY_NONE 0xff is band A's own value, named as the sentinel it is: the printed enumeration offers UNSECURED, SECURED_NWK_KEY and SECURED_LINK_KEY and none of them describes a frame that claimed security and produced no verdict");
    Test_Expect(security.keyPairs[0].incomingFrameCounter == 0 && pairOutgoing(&security, 0) == 0,
          "and the entry this device does hold is untouched: no material was selected, so no window was judged and none was stored");

    len = Test_ParseHex(s_apsFrame1Hex, apdu, (uint32_t)sizeof apdu);

    peerDelivers(&peer, &rig.stack.model, OWN_SHORT, apdu, len, 102);
    stepAt(&rig, air, &airCount, 103);

    Test_Expect(Aps_IndicationQueue(&rig.aps) == 1 && Aps_RxSecuredFailuresAuth(&rig.aps) == 1,
          "and a1 arrives from that same unnameable peer and is delivered, with no further failure counted: the auxiliary header named the sender, `Security_FindKeyPairByIeee` found the pair, and the hint this layer could not supply was never consulted (4.4.1.2 step 2 with step 3a)");

    Zb_memset(inds, 0xa5, (uint32_t)sizeof inds);
    Test_Expect(Aps_PollIndications(&rig.aps, inds, 2) == 1 && inds[0].status == APS_STATUS_SUCCESS
           && inds[0].securityStatus == APS_SECURITY_LINK_KEY && inds[0].keyIndex == 0
           && inds[0].keyStatus == SECURITY_KEYPAIR_ATTR_VERIFIED && inds[0].srcAddress == UNSEEN,
          "SECURED_LINK_KEY with the index and the attribute named, while `srcAddress` in the same indication is still the address this stack has no map for, which is the asymmetry stated rather than smoothed: the key pair was found from the air and the Table 2-4 source parameter still waits for `nwkAddressMap`");
    Test_Expect(security.keyPairs[0].incomingFrameCounter == APS_OUTGOING_SEED + 1 && airCount == 0,
          "the window moved once, for the frame that authenticated, and nothing went back out: a1's AR bit is 0");
}

/* One APDU the joiner's own module protects with its link key: the header as composed, `extendedNonce` deciding
   whether the auxiliary names the joiner, the length of what came out returned. */
static uint32_t joinerProtects(Security *joiner, const uint8_t *plain, uint32_t headerLen, uint32_t plainLen,
                               int extendedNonce, uint8_t *out)
{
    uint32_t securedLen = 0;

    Test_ExpectStatus(Security_ProtectAps(joiner, 0, SECURITY_KEY_ID_DATA, plain, headerLen, plain + headerLen,
                                          plainLen - headerLen, extendedNonce, out, APS_FRAME_MAX, &securedLen),
                      ZB_OK, "the joiner's module protects it with the data key of its pair (4.4.1.1)");

    return securedLen;
}

/*
 * 34. A sender only the global pair answers: the nonce's address is the sender's, never the pair's
 * (4.4.1.2 step 2, Table 4-41).
 *
 * A trust centre holds one pair for every joiner, the global link key with no device address in it, and learns the
 * joiner's 64-bit address from the network layer's map. Four frames from that joiner: data with the extended nonce
 * clear, which only the map can name; data with it set, which names itself; and a secured acknowledgement of a
 * secured transaction, the form a TRÅDFRI bulb answered the Transport Key with, once with its MIC broken and once
 * whole. The pair's own device address, 0, is the address none of them was protected with.
 */
void caseSecuredGlobalPairSender(void)
{
    Rig tc;
    Rig joinerRig;
    Security tcSec;
    Security joinerSec;
    Security_KeyPairEntry tcPairs[1];
    Security_KeyPairEntry joinerPairs[1];
    Test_BandA peer;
    Air air[AIR_LOG_MAX];
    Aps_Frame frame;
    Aps_Confirm confirms[2];
    Aps_Indication inds[2];
    Aps_ApsdeReq req;
    uint8_t plain[APS_FRAME_MAX];
    uint8_t apdu[APS_FRAME_MAX];
    uint8_t counter;
    uint32_t airCount = 0;
    uint32_t plainLen;
    uint32_t len;
    static const uint8_t asdu[ASDU_LEN] = { 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c };

    tcPairs[0] = apsPairAt(0, 0, 0, APS_OUTGOING_SEED, 0);
    tcPairs[0].linkKeyType = SECURITY_LINK_KEY_GLOBAL;
    joinerPairs[0] = apsPairAt(APS_OWN_IEEE, OWN_SHORT, 1, 1, 0);

    securedRigBuild(&tc, &tcSec, tcPairs, 1, APS_OWN_IEEE, OWN_SHORT);
    securedRigBuild(&joinerRig, &joinerSec, joinerPairs, 1, APS_PARTNER_IEEE, ADDR_PEER);

    peerBuild(&peer, ADDR_PEER);
    seedNeighbor(&tc.stack.nwk, ADDR_PEER);
    seedNeighbor(&peer.nwk, OWN_SHORT);
    scriptOutcomes(&tc.stack.model, LOOPBACK_TX_MAX, 1);
    scriptOutcomes(&peer.model, LOOPBACK_TX_MAX, 1);

    Test_Expect(Nwk_AddrMapLearn(Nwk_AddrMapOf(&tc.stack.nwk), ADDR_PEER, APS_PARTNER_IEEE, OWN_SHORT, 90)
                == NWK_ADDRMAP_LEARNED,
                "the trust centre's map holds the joiner, as the joiner's own NWK headers teach it (3.6.1.10.1)");

    dataHeader(&frame, APS_DELIVERY_UNICAST, 0, 0x31, DST_EP, CLUSTER_ID);
    frame.securityEnabled = 1;
    plainLen = composeApdu(&frame, asdu, ASDU_LEN, plain);
    len = joinerProtects(&joinerSec, plain, APS_HEADER_UNICAST_FORM, plainLen, 0, apdu);

    peerDelivers(&peer, &tc.stack.model, OWN_SHORT, apdu, len, 100);
    stepAt(&tc, air, &airCount, 101);

    Zb_memset(inds, 0xa5, (uint32_t)sizeof inds);
    Test_Expect(Aps_RxSecuredFailuresAuth(&tc.aps) == 0 && Aps_PollIndications(&tc.aps, inds, 2) == 1
           && inds[0].securityStatus == APS_SECURITY_LINK_KEY && inds[0].asduLength == ASDU_LEN
           && Zb_memcmp(inds[0].asdu, asdu, ASDU_LEN) == 0,
          "data with the extended nonce clear authenticates: the global pair names no device, so the nonce's address is the one the map holds for the frame's NWK source");

    dataHeader(&frame, APS_DELIVERY_UNICAST, 0, 0x32, DST_EP, CLUSTER_ID);
    frame.securityEnabled = 1;
    plainLen = composeApdu(&frame, asdu, ASDU_LEN, plain);
    len = joinerProtects(&joinerSec, plain, APS_HEADER_UNICAST_FORM, plainLen, 1, apdu);

    peerDelivers(&peer, &tc.stack.model, OWN_SHORT, apdu, len, 102);
    stepAt(&tc, air, &airCount, 103);

    Test_Expect(Aps_RxSecuredFailuresAuth(&tc.aps) == 0 && Aps_PollIndications(&tc.aps, inds, 2) == 1
           && inds[0].securityStatus == APS_SECURITY_LINK_KEY,
          "and data with it set authenticates too: the auxiliary's source is the joiner, which is what the map said, and the pair's address 0 is never compared against it");

    req = sapReq(APS_ADDR_MODE_SHORT, ADDR_PEER, DST_EP, CLUSTER_ID, asdu, ASDU_LEN,
                 APS_TX_OPTION_SECURITY | APS_TX_OPTION_ACK);
    Test_ExpectStatus(Aps_DataRequest(&tc.aps, &req, 110), ZB_OK,
                  "the trust centre sends the joiner a secured, acknowledged unicast under the global pair");
    harvestAir(&tc.stack.model, air, &airCount);
    Test_Expect(airCount == 1, "one frame out");
    counter = apduOf(&air[0])[APS_COUNTER_OCTET_UNICAST];
    stepAt(&tc, air, &airCount, 111);

    plainLen = ackApdu(plain, counter, DST_EP, SRC_EP, CLUSTER_ID);
    plain[0] = (uint8_t)(plain[0] | 0x20);
    len = joinerProtects(&joinerSec, plain, plainLen, plainLen, 0, apdu);
    apdu[len - 1] = (uint8_t)(apdu[len - 1] ^ 0x01);

    peerDelivers(&peer, &tc.stack.model, OWN_SHORT, apdu, len, 120);
    stepAt(&tc, air, &airCount, 121);

    Test_Expect(Aps_RxSecuredFailuresAuth(&tc.aps) == 1 && Aps_ConfirmQueue(&tc.aps) == 0
           && tc.aps.tx[0].state == APS_TX_AWAITING_ACK,
          "a secured acknowledgement whose MIC does not verify is a failure and answers nothing: the transaction still waits");

    apdu[len - 1] = (uint8_t)(apdu[len - 1] ^ 0x01);
    len = joinerProtects(&joinerSec, plain, plainLen, plainLen, 0, apdu);

    peerDelivers(&peer, &tc.stack.model, OWN_SHORT, apdu, len, 130);
    stepAt(&tc, air, &airCount, 131);

    Test_Expect(Aps_RxSecuredDeferred(&tc.aps) == 0 && Aps_UnmatchedAcks(&tc.aps) == 0
           && Aps_PollConfirms(&tc.aps, confirms, 2) == 1 && confirms[0].apsStatus == APS_STATUS_SUCCESS
           && confirms[0].attempts == 1,
          "and the whole one, Table 4-41's ACK to Datagram with the extended nonce clear, is unsecured and matched on the first attempt: no retry follows an answer that arrived");
}
