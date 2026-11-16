/* The `security` suite's APS crossing: cases 18-33, the two procedures of
   4.4.1.1 and 4.4.1.2 against the a1-a4 vectors and against the key-pair pool, what a
   protection writes, what an unprotection verifies, the auxiliary shapes and key identifiers this slice refuses,
   and the pool's own bounds. Every vector these cases quote is here, with its comment. */

#include "log.h"
#include "security.h"
#include "security_helpers.h"
#include "test_harness.h"
#include "zb_utils.h"

/* The APS vectors' partner: the entity the key pair A→B is shared with, whose extended address is what
   a3's auxiliary source field carries when that frame is the reply it is. */
#define APS_PARTNER_IEEE 0x1011121314151617

const char *s_apsHeaderHex = "2001060004010311";

const char *s_apsReplyHeaderHex = "2001060004010321";

const char *s_apsPayloadHex = "aabbccddee";

const char *s_apsReplyPayloadHex = "102030";

/* a1: 4.4.1.1 at level 0x05, extended nonce 1, the pair's OutgoingFrameCounter 0x00000004. The APSDU is
   ApsHeader || AuxiliaryHeader || c || MIC (4.4.1.1 step 7 with Figure 4-7): 8 + 13 + 5 + 4 = 30 octets.
   The auxiliary header is 0x60 (control with the level sub-field cleared by step 10, bit 5 the extended
   nonce and bit 6 the Require Verified Frame Counter Table 4-41 requires of a datagram), then 04000000
   (the counter, low octet first) then efcdab8967452301 (this device's own extended address, step 4b). */
const char *s_apsFrame1Hex = "20010600040103116004000000efcdab89674523019bc46c1a856adc703e";

/* a2: the same key pair and the same counter stepping to 0x00000005, with the extended nonce sub-field 0.
   The auxiliary header is 5 octets, 0x40 and the counter, no source address (4.5.1.3), and the frame is
   8 + 5 + 5 + 4 = 22 octets. What the frame does not carry, the nonce does: the same local extended
   address, which is what lets the peer authenticate it. */
const char *s_apsFrame2Hex = "20010600040103114005000000bd76748a2cc9c8f562";

/* a3: the reply, protected by the partner, its own extended address in the auxiliary source field
   (1716151413121110 is APS_PARTNER_IEEE low octet first), counter 0x00000007, extended nonce 1, over
   3 payload octets: 8 + 13 + 3 + 4 = 28 octets. */
const char *s_apsFrame3Hex = "2001060004010321600700000017161514131211102373abb7c81fd3";

/* a4: the frame sent with the Require Verified Frame Counter sub-field clear (0x20 on air, 0x25 in the
   nonce), which this module composes only by hand today (4.4.1.1 step 4a-iii sets the bit for a datagram)
   and 4.4.1.2 reads without judging it. */
const char *s_apsFrame4Hex = "20010600040103112006000000efcdab8967452301ccc6e7014e01e3b715";

/* A protect/unprotect pair at one APS level, between the two holders of one link key: this device's own
   extended address and its entry's outgoing counter on the way out, the partner's local level, its own entry
   and its stored window on the way in. No hex vector is quoted for the levels other than 0x05 because none
   exists in the corpus; a round trip proves this module's two APS halves agree on the nonce,
   the authenticated string and the M split of 4.4.1.2 step 6iii at the level under test, which is all a suite
   can prove about a level no published frame covers: the same argument cases 10, 12 and 13 make at NWK. */
void apsRoundTripAt(uint32_t level, uint32_t micLen, int extendedNonce, const char *which)
{
    Fixture sender;
    Fixture receiver;
    Security_KeyPairEntry senderPairs[1];
    Security_KeyPairEntry receiverPairs[1];
    Security_ApsResult result;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t auxLen;
    uint32_t frameLen;
    uint32_t headerLen;
    uint32_t payloadLen;
    uint32_t plainLen;
    uint32_t index;

    senderPairs[0] = apsPair(APS_PARTNER_IEEE, 1, 0);
    receiverPairs[0] = apsPair(OWN_IEEE, 1, 0);
    fixtureAps(&sender, level, OWN_IEEE, senderPairs, 1);
    fixtureAps(&receiver, level, APS_PARTNER_IEEE, receiverPairs, 1);

    headerLen = copyVector(header, s_apsHeaderHex);
    auxLen = extendedNonce ? SECURITY_APS_AUX_MAX : SECURITY_APS_AUX_MIN;

    for (index = 0; index < APS_PAYLOAD_LEN; index++)
        payload[index] = (uint8_t)(0xa0 + index);

    payloadLen = APS_PAYLOAD_LEN;

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    plainLen = 0;

    Test_ExpectStatus(Security_ProtectAps(&sender.security, 0, SECURITY_KEY_ID_DATA, header, headerLen, payload, payloadLen,
                                     extendedNonce, frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK, which);
    Test_Expect(frameLen == headerLen + auxLen + payloadLen + micLen,
           "the auxiliary shape this frame asked for and the M this level buys, added up (Figure 4-7 with Table 4-38)");
    Test_Expect(frame[headerLen] == (extendedNonce ? 0x60 : 0x40),
           "and the on-air security control carries no level at any level (4.4.1.1 step 10): M is decided locally in both directions here too, as it is one layer down");

    if (!(level & 0x04))
        Test_Expect(Zb_memcmp(frame + headerLen + auxLen, payload, payloadLen) == 0,
               "and the payload is right there in the frame's own octets: Table 4-38's Encryption Off column, read through 4.4.1.1 step 5d and step 7");

    Test_ExpectStatus(Security_UnprotectAps(&receiver.security, frame, frameLen, headerLen, OWN_IEEE, 1,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and the partner holding the same link key recovers it at the same level");
    Test_Expect(plainLen == payloadLen && Zb_memcmp(plain, payload, payloadLen) == 0,
           "with the payload octet for octet and the auxiliary header and the MIC gone (4.4.1.2 step 7b)");
    Test_Expect(result.keyPairIndex == 0 && result.partnerIeee == OWN_IEEE,
           "the entry the frame named, whether it named it on the air or in the hint");
    Test_Expect(result.frameCounter == 1 && result.rvfcSeen == 1,
           "with the count the frame carried and the bit this module always sets for a datagram");
}

/* Case 18, 4.4.1.1 end to end: the a1 vector, octet for octet, the snapshot bank, and the two
   Table 4-38 extremes no vector covers at this crossing. */
void caseProtectApsVector(void)
{
    Fixture fixture;
    Security_KeyPairEntry pairs[1];
    Security_KeyState state;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t headerLen;
    uint32_t payloadLen;

    pairs[0] = apsPair(APS_PARTNER_IEEE, 4, 0);
    fixtureAps5(&fixture, OWN_IEEE, pairs, 1);

    headerLen = copyVector(header, s_apsHeaderHex);
    payloadLen = copyVector(payload, s_apsPayloadHex);

    Test_Expect(headerLen == APS_HEADER_LEN && payloadLen == APS_PAYLOAD_LEN,
           "case 18: the a1 fixture is an 8-octet APS data header and a 5-octet ASDU");
    Test_Expect(Security_KeyPairCount(&fixture.security) == 1, "and this device holds one key pair");

    Test_ExpectStatus(Security_ProtectAps(&fixture.security, 0, SECURITY_KEY_ID_DATA, header, headerLen, payload, payloadLen, 1,
                                     frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "case 18: ProtectAps at level 0x05, extended nonce 1, entry 0 with OutgoingFrameCounter 0x00000004");
    Test_Expect(frameLen == APS_HEADER_LEN + SECURITY_APS_AUX_MAX + APS_PAYLOAD_LEN + 4,
           "the APSDU is 8 header + 13 auxiliary + 5 secured payload + 4 MIC = 30 octets (4.4.1.1 step 7 with Figure 4-7 and Table 4-38)");
    Test_ExpectHex("case 18: the frame is the a1 vector octet for octet", frame, frameLen, s_apsFrame1Hex);
    Test_Expect(frame[APS_HEADER_LEN] == 0x60,
           "and the auxiliary header begins with 0x60: key identifier '00' in bits 3-4, extended nonce 1 in bit 5, Require Verified Frame Counter 1 in bit 6 (Table 4-41, one datagram) and no level at all, 0x65 in the computation, 0x60 on air (4.4.1.1 steps 4 and 10)");
    Test_Expect(frame[APS_HEADER_LEN + 5] == 0xef && frame[APS_HEADER_LEN + 12] == 0x01,
           "and the eight octets after the counter are this device's own extended address, low octet first (4.4.1.1 step 4b with 4.5.1.3)");

    Security_Snapshot(&fixture.security, &state);

    Test_Expect(state.keyPairCount == 1 && state.keyPairDeviceIeee[0] == APS_PARTNER_IEEE
           && state.keyPairOutgoingFrameCounter[0] == 5,
           "4.4.1.1 step 9 with the export: the bank names the partner this device sent to and that entry's counter, 4 to 5");
    Test_Expect(state.keyCount == 1 && state.outgoingFrameCounter[0] == 1,
           "and the network descriptor did not move: the two crossings consume their own counters");

    /* Table 4-38's other two ends of this crossing: 0x01 authenticates and encrypts nothing, 0x07 encrypts
       and authenticates with the largest M the table prints. The clauses they exercise (step 5d's choice of
       what travels in a and what travels in c, step 7's two frame shapes, 4.4.1.2 step 6iii's split of the
       SecuredPayload) are the ones the a1 vector cannot speak for, because a1 is a level-0x05 frame. */
    apsRoundTripAt(SECURITY_LEVEL_MIC_32, 4, 1,
                   "case 18: the same pair protected at the authentication-only level 0x01, extended nonce 1");
    apsRoundTripAt(SECURITY_LEVEL_ENC_MIC_128, 16, 0,
                   "case 18: and at level 0x07 with M = 16 in the 5-octet auxiliary shape");
}

/* Case 19, the 5-octet auxiliary: the same pair one counter later with the extended nonce sub-field clear. */
void caseProtectApsShortAux(void)
{
    Fixture fixture;
    Security_KeyPairEntry pairs[1];
    Security_KeyState state;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t headerLen;
    uint32_t payloadLen;

    pairs[0] = apsPair(APS_PARTNER_IEEE, 5, 0);
    fixtureAps5(&fixture, OWN_IEEE, pairs, 1);

    headerLen = copyVector(header, s_apsHeaderHex);
    payloadLen = copyVector(payload, s_apsPayloadHex);

    Test_ExpectStatus(Security_ProtectAps(&fixture.security, 0, SECURITY_KEY_ID_DATA, header, headerLen, payload, payloadLen, 0,
                                     frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "case 19: the same entry at counter 0x00000005 with the extended nonce sub-field 0, TxOptions 0x10 not set");
    Test_Expect(frameLen == APS_HEADER_LEN + SECURITY_APS_AUX_MIN + APS_PAYLOAD_LEN + 4,
           "the frame is 8 + 5 + 5 + 4 = 22 octets: the auxiliary header is 1 + 4 with no source address field (4.5.1.3)");
    Test_ExpectHex("case 19: the frame is the a2 vector octet for octet", frame, frameLen, s_apsFrame2Hex);
    Test_Expect(frame[APS_HEADER_LEN] == 0x40,
           "with 0x40 as the control octet: bit 5 clear is what took the address off the air, and bit 6 still set");
    Test_Expect(frame[APS_HEADER_LEN + SECURITY_APS_AUX_MIN] == 0xbd,
           "and the octet straight after the 5 auxiliary octets is already the first octet of c: this frame names no address anywhere in its octets, and it still authenticates at the peer in case 21, because the nonce carried this device's own address (4.4.1.1 step 5c with 4.5.2.2)");

    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.keyPairCount == 1 && state.keyPairOutgoingFrameCounter[0] == 6,
           "and the entry moved to 6 whichever auxiliary shape it moved with");
}

/* Case 20, 4.4.1.2 against a1 at a fixture shaped like the partner, and a3 as the reply that partner sends
   back: the two directions of one key pair, both byte-exact. */
void caseUnprotectApsVectorAndReply(void)
{
    Fixture receiver;
    Fixture responder;
    Fixture originator;
    Security_KeyPairEntry pairs[1];
    Security_ApsResult result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t reply[SECURITY_FRAME_MAX];
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t replyLen;
    uint32_t headerLen;
    uint32_t payloadLen;
    uint32_t plainLen;

    pairs[0] = apsPair(OWN_IEEE, 1, 0);
    fixtureAps5(&receiver, APS_PARTNER_IEEE, pairs, 1);

    frameLen = copyVector(frame, s_apsFrame1Hex);
    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    plainLen = 0;

    Test_ExpectStatus(Security_UnprotectAps(&receiver.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "case 20: a1, unprotected by the partner it was sent to, with no hint at all, the extended nonce put the sender's own extended address on the air and that is what selects the entry (4.4.1.2 step 2 with step 3a)");
    Test_ExpectHex("and the payload is the five octets it was (4.4.1.2 step 7b)", plain, plainLen, s_apsPayloadHex);
    Test_Expect(plainLen == APS_PAYLOAD_LEN, "with the auxiliary header and the MIC gone");
    Test_Expect(result.keyPairIndex == 0,
           "the result names the pool entry that was used, which is what Table 2-4's KeyIndex reports");
    Test_Expect(result.partnerIeee == OWN_IEEE, "the partner it resolved is the auxiliary source address");
    Test_Expect(result.frameCounter == 4, "and the count as the frame carried it, not the +1 the entry stores");
    Test_Expect(result.rvfcSeen == 1,
           "with the Require Verified Frame Counter bit carried transparently for the layers' records: 4.4.1.2 reads no verdict off it");
    Test_Expect(receiver.security.keyPairs[0].incomingFrameCounter == 5,
           "4.4.1.2 step 9 stored ReceivedFrameCount + 1 = 5, and only after step 7a verified the tag");

    /* The return leg, protected by the partner: its own counter and its own extended address. */
    pairs[0] = apsPair(OWN_IEEE, 7, 5);
    fixtureAps5(&responder, APS_PARTNER_IEEE, pairs, 1);

    headerLen = copyVector(header, s_apsReplyHeaderHex);
    payloadLen = copyVector(payload, s_apsReplyPayloadHex);

    Test_ExpectStatus(Security_ProtectAps(&responder.security, 0, SECURITY_KEY_ID_DATA, header, headerLen, payload, payloadLen, 1,
                                     reply, SECURITY_FRAME_MAX, &replyLen), ZB_OK,
                  "case 20: and the reply, protected by the partner at its own counter 0x00000007");
    Test_Expect(replyLen == APS_REPLY_HEADER_LEN + SECURITY_APS_AUX_MAX + APS_REPLY_PAYLOAD_LEN + 4,
           "28 octets: 8 + 13 + 3 + 4");
    Test_ExpectHex("is the a3 vector octet for octet", reply, replyLen, s_apsFrame3Hex);
    Test_Expect(reply[APS_REPLY_HEADER_LEN + 5] == 0x17 && reply[APS_REPLY_HEADER_LEN + 12] == 0x10,
           "with 1716151413121110 in the auxiliary source field: the protecting device's own extended address, not the one it is answering (4.4.1.1 step 4b)");

    pairs[0] = apsPair(APS_PARTNER_IEEE, 0, 0);
    fixtureAps5(&originator, OWN_IEEE, pairs, 1);

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    plainLen = 0;

    Test_ExpectStatus(Security_UnprotectAps(&originator.security, reply, replyLen, APS_REPLY_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and the device the reply came from accepts it, on the same pair seen from the other side");
    Test_ExpectHex("with the three octets a3 carried", plain, plainLen, s_apsReplyPayloadHex);
    Test_Expect(result.keyPairIndex == 0 && result.partnerIeee == APS_PARTNER_IEEE
           && result.frameCounter == 7 && result.rvfcSeen == 1,
           "naming the partner, the count and the bit the frame carried");
    Test_Expect(originator.security.keyPairs[0].incomingFrameCounter == 8, "and storing 8 as that entry's window");
}

/* Case 21, the a2 shape where the auxiliary header names no address at all: the hint selects the entry, the
   entry names the nonce, and a wrong entry is a failed tag rather than a different error. */
void caseUnprotectApsNoAuxAddress(void)
{
    Fixture fixture;
    Security_KeyPairEntry pairs[2];
    Security_ApsResult result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    pairs[0] = apsPair(OWN_IEEE, 1, 0);
    pairs[1] = apsPair(PEER_IEEE, 1, 0);     /* a second partner, the same link key: only the address differs */
    fixtureAps5(&fixture, APS_PARTNER_IEEE, pairs, 2);

    frameLen = copyVector(frame, s_apsFrame2Hex);
    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    plainLen = 0;

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen, APS_HEADER_LEN, PEER_IEEE, 1,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_AUTH,
                  "case 21: hinted at the other entry, which exists, so the procedure runs, and puts that entry's DeviceAddress into the nonce where a2 was computed with the sender's. 4.4.1.2 step 6a-ii takes the nonce's address from step 2's SourceAddress and nothing else, so the tag simply does not verify");
    Test_Expect(plain[0] == 0x00 && plainLen == 0,
           "and no plaintext was released for it: what did not verify is destroyed (Annex A.4)");

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_AUTH,
                  "and with no hint at all it is 4.4.1.2 step 3's 'If the security material cannot be obtained': the address map sits above this module, so `aps` resolves the source (by nwkAddressMap, or by Security_FindKeyPairByShort for a 16-bit one) and hands the EUI in");
    Test_Expect(fixture.security.keyPairs[0].incomingFrameCounter == 0
           && fixture.security.keyPairs[1].incomingFrameCounter == 0,
           "and neither entry stored a counter: step 9 is after step 7a (4.4.1.2), and a frame this device cannot attribute burns nobody's window");

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen, APS_HEADER_LEN, OWN_IEEE, 1,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and with the hint that names the entry a2 was sent to, the same 22 octets verify: with no address on the air to verify against");
    Test_ExpectHex("case 21: the payload is the five octets a2 carried", plain, plainLen, s_apsPayloadHex);
    Test_Expect(result.keyPairIndex == 0 && result.partnerIeee == OWN_IEEE,
           "the resolved entry named the nonce's source octets");
    Test_Expect(result.frameCounter == 5 && result.rvfcSeen == 1, "with the count and the bit the frame carried");
    Test_Expect(fixture.security.keyPairs[0].incomingFrameCounter == 6,
           "and the entry now holds 5 + 1 (4.4.1.2 step 9)");

    drainLog(&fixture.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_UNPROTECT_FAILED, LOG_REASON_ERROR, (uint32_t)ZB_ERR_AUTH) == 1,
           "and both refusals are records in the caller's pool (docs/internals/coding-rules.md §5)");
}

/* Case 22, the transparency case: a frame sent with the Require Verified Frame Counter bit clear is read by
   a device whose own transmit rule would never have cleared it, and the bit is reported and not judged. */
void caseUnprotectApsRvfcTransparent(void)
{
    Fixture fixture;
    Security_KeyPairEntry pairs[1];
    Security_ApsResult result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    pairs[0] = apsPair(OWN_IEEE, 1, 0);
    fixtureAps5(&fixture, APS_PARTNER_IEEE, pairs, 1);

    frameLen = copyVector(frame, s_apsFrame4Hex);
    Test_Expect(frame[APS_HEADER_LEN] == 0x20,
           "case 22: a4's control octet is 0x20, key identifier '00', extended nonce 1, bit 6 clear, which 4.4.1.1 step 4a-iii would never print for a datagram");

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    plainLen = 0;

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and it verifies: the bit travels inside the authenticated string, and this module does not judge it (4.4.1.2 reading no verdict off bit 6)");
    Test_ExpectHex("with the payload intact", plain, plainLen, s_apsPayloadHex);
    Test_Expect(result.rvfcSeen == 0,
           "and the result says the bit was clear, which is the transparency measured: the only thing this crossing does with bit 6 is hand it up");
    Test_Expect(result.frameCounter == 6 && result.keyPairIndex == 0, "with the count and the entry a4 names");
    Test_Expect(fixture.security.keyPairs[0].incomingFrameCounter == 7, "and the window stored 7");
}

/* Case 23, 4.4.1.2 step 4 against a replay of a1: the same frame a second time is the freshness refusal,
   and the refusal stores nothing. */
void caseUnprotectApsReplay(void)
{
    Fixture fixture;
    Security_KeyPairEntry pairs[1];
    Security_ApsResult result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    pairs[0] = apsPair(OWN_IEEE, 1, 0);
    fixtureAps5(&fixture, APS_PARTNER_IEEE, pairs, 1);

    frameLen = copyVector(frame, s_apsFrame1Hex);

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    plainLen = 0;

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "case 23: a1 accepted once, storing the window 5");

    frameLen = copyVector(frame, s_apsFrame1Hex);
    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_BAD_FRAME_COUNTER,
                  "and the identical frame again is step 4's refusal: 4 is less than the stored 5, so no CCM is attempted for it (4.4.1.2 runs step 4 before step 6)");
    Test_Expect(plain[0] == 0xa5, "and no plaintext was written for it");
    Test_Expect(fixture.security.keyPairs[0].incomingFrameCounter == 5,
           "and the stored value did not move: the refusal consumed nothing, which is what keeps a replay from damaging the window it is trying to defeat");

    drainLog(&fixture.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_UNPROTECT_FAILED, LOG_REASON_ERROR, (uint32_t)ZB_ERR_BAD_FRAME_COUNTER) == 1,
           "and the refusal is recorded with the status the caller was given");
}

/* Case 24, the equal-counter acceptance the NWK crossing records, measured at APS: the store is
   ReceivedFrameCount + 1, so the same count again is not "less than" the window. */
void caseUnprotectApsEqualCounter(void)
{
    Fixture sender;
    Fixture receiver;
    Security_KeyPairEntry pairs[1];
    Security_ApsResult result;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t headerLen;
    uint32_t payloadLen;
    uint32_t plainLen;

    pairs[0] = apsPair(APS_PARTNER_IEEE, 5, 0);
    fixtureAps5(&sender, OWN_IEEE, pairs, 1);

    headerLen = copyVector(header, s_apsHeaderHex);
    payloadLen = copyVector(payload, s_apsPayloadHex);

    Test_ExpectStatus(Security_ProtectAps(&sender.security, 0, SECURITY_KEY_ID_DATA, header, headerLen, payload, payloadLen,
                                     1, frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "case 24: a frame protected at counter 0x00000005, which is the count the receiver already holds in its window");
    Test_Expect(frame[APS_HEADER_LEN + 1] == 0x05 && frame[APS_HEADER_LEN + 4] == 0x00,
           "the counter the frame carries, read back out of it");

    pairs[0] = apsPair(OWN_IEEE, 1, 5);
    fixtureAps5(&receiver, APS_PARTNER_IEEE, pairs, 1);

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    plainLen = 0;

    Test_ExpectStatus(Security_UnprotectAps(&receiver.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and the receiver whose IncomingFrameCounter is already 5 accepts a frame carrying 5: step 4 refuses only a count strictly less than the stored one, exactly as printed (the replay weakness, restated for APS and not repaired)");
    Test_ExpectHex("with the payload handed up", plain, plainLen, s_apsPayloadHex);
    Test_Expect(result.frameCounter == 5, "and the result naming the count as the frame carried it");
    Test_Expect(receiver.security.keyPairs[0].incomingFrameCounter == 6,
           "and the window moved to 5 + 1, so the weakness is one frame wide and not open");

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);

    Test_ExpectStatus(Security_UnprotectAps(&receiver.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_BAD_FRAME_COUNTER,
                  "and the same frame a second time is refused, which is what says the store really happened");
}

/* Case 25, commit-after-verify at the APS crossing: a tampered a1 fails, stores nothing, and costs the
   sender nothing. */
void caseUnprotectApsTampered(void)
{
    Fixture fixture;
    Security_KeyPairEntry pairs[1];
    Security_ApsResult result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    pairs[0] = apsPair(OWN_IEEE, 1, 0);
    fixtureAps5(&fixture, APS_PARTNER_IEEE, pairs, 1);

    frameLen = copyVector(frame, s_apsFrame1Hex);
    frame[frameLen - 1] = (uint8_t)(frame[frameLen - 1] ^ 0xff);

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    plainLen = 0;

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_AUTH,
                  "case 25: a1 with its last octet flipped is 4.4.1.2 step 7a's 'invalid' output of the CCM operation");
    Test_Expect(plain[0] == 0x00 && plainLen == 0,
           "and no plaintext was released: what did not verify is destroyed (Annex A.4)");
    Test_Expect(fixture.security.keyPairs[0].incomingFrameCounter == 0,
           "and the entry stored nothing for it: step 9 is not reached");

    drainLog(&fixture.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_UNPROTECT_FAILED, LOG_REASON_ERROR, (uint32_t)ZB_ERR_AUTH) == 1,
           "and the failure is a record in the caller's pool");

    frameLen = copyVector(frame, s_apsFrame1Hex);
    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and the pristine a1 still succeeds afterwards at the same count: a frame that did not authenticate left no window (4.4.1.2 steps 7 and 9)");
    Test_Expect(fixture.security.keyPairs[0].incomingFrameCounter == 5, "which stored 5 this time");
}

/* Case 26, 4.4.1.1 step 2's outgoing exhaustion, per entry. */
void caseProtectApsCounterExhausted(void)
{
    Fixture fixture;
    Security_KeyPairEntry pairs[2];
    Security_KeyState state;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t headerLen;
    uint32_t payloadLen;

    pairs[0] = apsPair(APS_PARTNER_IEEE, 0xffffffff, 0);
    pairs[1] = apsPair(PEER_IEEE, 3, 0);
    fixtureAps5(&fixture, OWN_IEEE, pairs, 2);

    headerLen = copyVector(header, s_apsHeaderHex);
    payloadLen = copyVector(payload, s_apsPayloadHex);
    Zb_memset(frame, 0x5a, (uint32_t)sizeof frame);

    Test_ExpectStatus(Security_ProtectAps(&fixture.security, 0, SECURITY_KEY_ID_DATA, header, headerLen, payload, payloadLen,
                                     1, frame, SECURITY_FRAME_MAX, &frameLen),
                  ZB_ERR_BAD_FRAME_COUNTER,
                  "case 26: the entry at 2^32-1 is refused (4.4.1.1 step 2), the same boundary 4.3.1.1 step 1 prints and the same reason word the mapping gives it");
    Test_Expect(frame[0] == 0x5a, "and nothing was written for it");

    Test_ExpectStatus(Security_ProtectAps(&fixture.security, 1, SECURITY_KEY_ID_DATA, header, headerLen, payload, payloadLen,
                                     1, frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "while the other entry of the same pool is untouched by that refusal and composes its frame");

    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.keyPairCount == 2 && state.keyPairOutgoingFrameCounter[0] == 0xffffffff
           && state.keyPairOutgoingFrameCounter[1] == 4,
           "and the bank shows it: the exhausted counter stayed exhausted, the other moved 3 to 4");

    drainLog(&fixture.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_PROTECT_REFUSED, LOG_REASON_ERROR, (uint32_t)ZB_ERR_BAD_FRAME_COUNTER) == 1,
           "and the refusal is recorded");
}

/* Case 27, 4.4.1.2 step 1's incoming exhaustion, which names no status in the clause and is given the
   outgoing one. The frame is a1 with its counter octets replaced, so it could not authenticate in any
   case: the point is which refusal answers first. */
void caseUnprotectApsCounterMaximum(void)
{
    Fixture fixture;
    Security_KeyPairEntry pairs[1];
    Security_ApsResult result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    pairs[0] = apsPair(OWN_IEEE, 1, 0);
    fixtureAps5(&fixture, APS_PARTNER_IEEE, pairs, 1);

    frameLen = copyVector(frame, s_apsFrame1Hex);
    rewriteCounter(frame, APS_HEADER_LEN, 0xffffffff);

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    plainLen = 0;

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_BAD_FRAME_COUNTER,
                  "case 27: a frame carrying ReceivedFrameCount 2^32-1 is refused by step 1, before its entry is resolved, before its window is judged and before the seam runs, so the answer is the counter word and never AUTH even though the tag cannot verify (4.4.1.2 step 1: \"no further security processing shall be done on this frame\")");
    Test_Expect(fixture.security.keyPairs[0].incomingFrameCounter == 0, "and nothing was stored");

    drainLog(&fixture.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_UNPROTECT_FAILED, LOG_REASON_ERROR, (uint32_t)ZB_ERR_BAD_FRAME_COUNTER) == 1,
           "and the refusal is recorded as an unprotect failure");
}

/* Case 28, the key identifier shapes 4.4.1 prints for APS and this slice does not read.
   Every frame here is a1 with one octet changed at the auxiliary header. */
void caseApsUnsupportedKeyIdentifiers(void)
{
    Fixture sender;
    Fixture receiver;
    Security_KeyPairEntry senderPairs[1];
    Security_KeyPairEntry receiverPairs[1];
    Security_ApsResult result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint8_t header[SECURITY_APS_HEADER_MAX];
    uint8_t payload[PAYLOAD_LEN];
    uint32_t headerLen;
    uint32_t frameLen;
    uint32_t plainLen;
    uint32_t index;

    senderPairs[0] = apsPair(APS_PARTNER_IEEE, 1, 0);
    receiverPairs[0] = apsPair(OWN_IEEE, 1, 0);
    fixtureAps5(&sender, OWN_IEEE, senderPairs, 1);
    fixtureAps5(&receiver, APS_PARTNER_IEEE, receiverPairs, 1);

    headerLen = copyVector(header, s_apsHeaderHex);

    for (index = 0; index < PAYLOAD_LEN; index++)
        payload[index] = (uint8_t)(0x40 + index);

    frameLen = copyVector(frame, s_apsFrame1Hex);
    frame[headerLen] = 0x68;     /* 0x60 with the key identifier sub-field '01': a network key at the APS crossing */

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    plainLen = 0;

    Test_ExpectStatus(Security_UnprotectAps(&receiver.security, frame, frameLen, headerLen, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_UNSUPPORTED,
                  "case 28: '01' is refused, 4.4.1.1 step 1 never selects it for an APS frame and 4.4.1.2 has no branch for it");

    Test_Expect(plain[0] == 0xa5 && plainLen == 0,
           "and it wrote nothing, and it is not a bad key or a bad tag: the shape is the refusal");

    Test_ExpectStatus(Security_ProtectAps(&sender.security, 0, SECURITY_KEY_ID_KEY_TRANSPORT, header, headerLen,
                                          payload, PAYLOAD_LEN, 1, frame, SECURITY_FRAME_MAX, &frameLen),
                      ZB_ERR_BAD_ARGUMENT,
                      "'10' on a data frame is refused: 4.4.1.1 step 1 a i sets '00' for every frame of an APSDE-DATA.request, and '10' belongs to a transport-key command");

    /* A Transport Key command's header (4.4.11.1, Figure 4-8): frame type command with the security bit, the APS
       counter, then the command identifier 0x05 */
    header[0] = 0x21;
    header[1] = 0x11;
    header[2] = 0x05;
    headerLen = 3;

    Test_ExpectStatus(Security_ProtectAps(&sender.security, 0, SECURITY_KEY_ID_KEY_TRANSPORT, header, headerLen,
                                          payload, PAYLOAD_LEN, 0, frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "on a command '10' protects: the key-transport key is the keyed hash of 0x00 under the pair's link key");
    Test_Expect(((frame[headerLen] >> SECURITY_CONTROL_KEY_ID_SHIFT) & SECURITY_CONTROL_KEY_ID_MASK)
                == SECURITY_KEY_ID_KEY_TRANSPORT,
                "and the auxiliary header says '10', which 4.4.1.1 step 4 a i sets and step 3 b of the receive half reads back");
    Test_Expect(((frame[headerLen] >> SECURITY_CONTROL_EXTENDED_NONCE_SHIFT) & SECURITY_CONTROL_EXTENDED_NONCE_MASK) == 1,
                "with the extended nonce set although the caller asked for none: step 4 a ii sets it for every APS command");
    Test_Expect(((frame[headerLen] >> SECURITY_CONTROL_RVFC_SHIFT) & SECURITY_CONTROL_RVFC_MASK) == 0,
                "and Require Verified Frame Counter clear, which Table 4-41 gives a command");

    Test_ExpectStatus(Security_UnprotectAps(&receiver.security, frame, frameLen, headerLen, OWN_IEEE, 1,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and the partner opens it under the same identifier");
    Test_ExpectOctets("with the payload it was given", plain, PAYLOAD_LEN, payload, PAYLOAD_LEN);

    Test_ExpectStatus(Security_ProtectAps(&sender.security, 0, SECURITY_KEY_ID_KEY_LOAD, header, headerLen,
                                          payload, PAYLOAD_LEN, 0, frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "'11' protects a command too: the key-load key is the keyed hash of 0x02 under the same link key");
    Test_ExpectStatus(Security_UnprotectAps(&receiver.security, frame, frameLen, headerLen, OWN_IEEE, 1,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and that one opens as well");

    headerLen = copyVector(header, s_apsHeaderHex);

    frameLen = copyVector(frame, s_apsFrame1Hex);
    rewriteCounter(frame, headerLen, 0xffffffff);
    frame[headerLen] = 0x68;

    Test_ExpectStatus(Security_UnprotectAps(&receiver.security, frame, frameLen, headerLen, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_UNSUPPORTED,
                  "and a frame that is both an unreadable shape and an exhausted counter answers UNSUPPORTED: the identifier is read off the control octet first, before any counter work (4.4.1.2 step 1 determines the sequence number, key identifier and counter together, and the shape gate is what band A adds)");

    drainLog(&receiver.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_UNPROTECT_FAILED, LOG_REASON_ERROR, (uint32_t)ZB_ERR_UNSUPPORTED) == 1,
           "and the '01' refusal is recorded with the status the caller was given");
}

/* Table 4-41, which "Sending devices SHALL use": the Require Verified Frame Counter bit by APS frame type, the ACK
   format field telling an ACK to a datagram from an ACK to a command. 4.4.1.1 step 4 a iii names only the datagram;
   the table is the narrower rule and the sender's own, so it decides the two ACK rows. */
void caseApsRvfcFollowsFrameType(void)
{
    Fixture sender;
    Security_KeyPairEntry pairs[1];
    uint8_t header[3];
    uint8_t payload[PAYLOAD_LEN];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t row;

    static const uint8_t frameControl[4] = { 0x20, 0x21, 0x22, 0x32 };
    static const uint8_t wantedRvfc[4] = { 1, 0, 1, 0 };
    static const char *what[4] = {
        "a datagram carries the bit",
        "a command does not",
        "an ACK to a datagram does, ACK format 0",
        "and an ACK to a command does not, ACK format 1"
    };

    pairs[0] = apsPair(APS_PARTNER_IEEE, 1, 0);
    fixtureAps5(&sender, OWN_IEEE, pairs, 1);
    Zb_memset(payload, 0x5a, (uint32_t)sizeof payload);

    for (row = 0; row < 4; row++)
    {
        header[0] = frameControl[row];
        header[1] = 0x11;
        header[2] = 0x05;

        Test_ExpectStatus(Security_ProtectAps(&sender.security, 0, SECURITY_KEY_ID_DATA, header, 3, payload,
                                              PAYLOAD_LEN, 1, frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                          "one frame of this row of Table 4-41 protected");
        Test_ExpectCount((uint32_t)((frame[3] >> SECURITY_CONTROL_RVFC_SHIFT) & SECURITY_CONTROL_RVFC_MASK),
                         wantedRvfc[row], what[row]);
    }
}

/* 4.4.1.2 step 2 (10284-10288): SourceAddress is determined "from the address-map table in the NIB, using the source
   address in the APS frame as the index", and the nonce of step 6 is built from it. A frame whose auxiliary header
   names a different device than the one the NWK source maps to is not that sender's frame, even when this device
   also shares a key with the device the auxiliary header names. */
void caseUnprotectApsSourceMustMatchTheMap(void)
{
    Fixture receiver;
    Security_KeyPairEntry pairs[2];
    Security_ApsResult result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    pairs[0] = apsPair(OWN_IEEE, 1, 0);
    pairs[1] = apsPair(PEER_IEEE, 1, 0);
    fixtureAps5(&receiver, APS_PARTNER_IEEE, pairs, 2);

    frameLen = copyVector(frame, s_apsFrame1Hex);

    Test_ExpectStatus(Security_UnprotectAps(&receiver.security, frame, frameLen, APS_HEADER_LEN, PEER_IEEE, 1,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_AUTH,
                  "a1 names its sender in the auxiliary header, while the NWK source it arrived from maps to another device this receiver holds a key with: refused");
    Test_Expect(receiver.security.keyPairs[0].incomingFrameCounter == 0
                && receiver.security.keyPairs[1].incomingFrameCounter == 0,
                "and neither pair's window moved, so a frame aimed through the wrong address cannot advance anyone's counter");

    Test_ExpectStatus(Security_UnprotectAps(&receiver.security, frame, frameLen, APS_HEADER_LEN, OWN_IEEE, 1,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "while the same frame from the source that maps to its own sender opens as before");
}

/* 4.4.1.2 step 2's other half: a device joined and not yet authorized "SHALL use the apsDeviceKeyPairSet that
   corresponds to its pre-installed link key", which is how the trust centre's key reaches it through its parent
   (4.6.3.7.2): the auxiliary header names the trust centre while the NWK source is the parent. */
void caseUnprotectApsUnauthorizedTakesARelayedFrame(void)
{
    Fixture receiver;
    Security_KeyPairEntry pairs[2];
    Security_ApsResult result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    pairs[0] = apsPair(OWN_IEEE, 1, 0);
    pairs[1] = apsPair(PEER_IEEE, 1, 0);
    fixtureAps5(&receiver, APS_PARTNER_IEEE, pairs, 2);
    receiver.security.authenticated = 0;

    frameLen = copyVector(frame, s_apsFrame1Hex);

    Test_ExpectStatus(Security_UnprotectAps(&receiver.security, frame, frameLen, APS_HEADER_LEN, PEER_IEEE, 1,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "the frame a1 relayed by a device the NWK source maps to, at a receiver not yet authorized: taken");
    Test_Expect(result.partnerIeee == OWN_IEEE, "from the sender its auxiliary header names");
}

/* Case 29, what Security_Init refuses a key pair for, each leaving a module that holds nothing. */
void caseApsInitRefusals(void)
{
    Security security;
    Security_Config cfg;
    Security_KeyDescriptor keys[1];
    Security_KeyPairEntry pairs[SECURITY_KEYPAIR_MAX + 1];
    Security expected;
    uint32_t index;

    keys[0] = keyAt(0x00, s_keyAHex, 1);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = OWN_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.nwkActiveKeySeqNumber = 0x00;
    cfg.authenticated = 1;
    cfg.nwkAllFresh = 1;
    cfg.keys = keys;
    cfg.keyCount = 1;
    cfg.keyPairs = pairs;
    cfg.keyPairCount = 1;

    for (index = 0; index < SECURITY_KEYPAIR_MAX + 1; index++)
        pairs[index] = apsPair(APS_PARTNER_IEEE + index, 1, 0);

    pairs[0] = keyPairAt(APS_PARTNER_IEEE, 0x0000, 0, SECURITY_KEYPAIR_ATTR_UNVERIFIED, s_linkKeyHex,
                         1, 0, SECURITY_LINK_KEY_UNIQUE, SECURITY_FEATURES_NONE, 1);
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_OK,
                  "case 29: a KeyAttributes of UNVERIFIED is held at configuration: 4.4.12.1 backs up every entry, and 4.4.1.1 step 1a-ii only keeps it from encrypting");
    Test_Expect(Security_KeyPairCount(&security) == 1, "and the module holds the pair");

    pairs[0] = keyPairAt(APS_PARTNER_IEEE, 0x0000, 0, SECURITY_KEYPAIR_ATTR_VERIFIED, s_linkKeyHex,
                         1, 0, SECURITY_LINK_KEY_GLOBAL, SECURITY_FEATURES_NONE, 1);
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_OK,
                  "while apsLinkKeyType 0x01 is a key a pair may hold: 4.4.1.2 step 4 prints its replay check for a unique key only, so a global one has nothing to run, and 4.4.1.5 needs such a key held");
    Test_Expect(Security_KeyPairCount(&security) == 1, "and the global key is held");

    pairs[0] = keyPairAt(APS_PARTNER_IEEE, 0x0000, 0, SECURITY_KEYPAIR_ATTR_VERIFIED, s_linkKeyHex,
                         1, 0, 0x02, SECURITY_FEATURES_NONE, 1);
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_ERR_BAD_ARGUMENT,
                  "and a third apsLinkKeyType is refused: Table 4-36 prints its range as 0x00 - 0x01");

    pairs[0] = keyPairAt(APS_PARTNER_IEEE, 0x0000, 0, SECURITY_KEYPAIR_ATTR_PROVISIONAL, s_linkKeyHex,
                         1, 0, SECURITY_LINK_KEY_UNIQUE, 0x02, 1);
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_ERR_BAD_ARGUMENT,
                  "and Features & Capabilities 0x02 is refused: Table 4-36 prints the range \"0x00, 0x01\" and says bits #1..#7 \"SHALL be set to '0'\", which is a set of two values and not a mask");

    pairs[0] = keyPairAt(APS_PARTNER_IEEE, 0x0000, 0, SECURITY_KEYPAIR_ATTR_PROVISIONAL, s_linkKeyHex,
                         1, 0, SECURITY_LINK_KEY_UNIQUE, SECURITY_FEATURES_FRAME_COUNTER_SYNC, 0);
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_OK,
                  "while 0x01 with VerifiedFrameCounter clear is a legal configuration: the pair is usable, and 4.4.1.2 step 8 is what case 31 reaches through it");
    Test_Expect(Security_KeyPairCount(&security) == 1, "and it is held");

    cfg.keyPairCount = 2;
    pairs[0] = apsPair(APS_PARTNER_IEEE, 1, 0);
    pairs[1] = apsPair(APS_PARTNER_IEEE, 2, 0);
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_ERR_BAD_ARGUMENT,
                  "and two entries sharing one DeviceAddress are refused: DeviceAddress is the name 4.4.1.1 step 1a-i and 4.4.1.2 step 3a select with, and one partner would have two counter windows");

    pairs[0] = keyPairAt(APS_PARTNER_IEEE, 0x1234, 1, SECURITY_KEYPAIR_ATTR_VERIFIED, s_linkKeyHex,
                         1, 0, SECURITY_LINK_KEY_UNIQUE, SECURITY_FEATURES_NONE, 1);
    pairs[1] = keyPairAt(PEER_IEEE, 0x1234, 1, SECURITY_KEYPAIR_ATTR_VERIFIED, s_linkKeyHex,
                         1, 0, SECURITY_LINK_KEY_UNIQUE, SECURITY_FEATURES_NONE, 1);
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_ERR_BAD_ARGUMENT,
                  "and two known short aliases naming the same 16-bit address are refused too, for the same reason through the same alias");

    cfg.keyPairCount = SECURITY_KEYPAIR_MAX + 1;
    pairs[SECURITY_KEYPAIR_MAX] = apsPair(SEEDED_IEEE, 1, 0);
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_ERR_BAD_ARGUMENT,
                  "and nine pairs are more than the named pool: Table 4-35 prints no cardinality for apsDeviceKeyPairSet, so 8 is band A's bound and a ninth is a refusal, not a truncation");

    cfg.keyPairCount = 1;
    cfg.keys = 0;
    cfg.keyCount = 0;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_NONE;
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_ERR_BAD_ARGUMENT,
                  "and a key pair at level 0x00 is refused: 4.4.1.1 step 3 takes the APS security level from nwkSecurityLevel, so a device with no level has no APS security to run either");

    cfg.keyPairs = 0;
    cfg.keyPairCount = 1;
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_ERR_BAD_ARGUMENT,
                  "and a count with no list behind it is the same class of caller error it is for the two NWK pools");

    Zb_memset(&expected, 0, (uint32_t)sizeof expected);
    expected.trustCenterIeee = 0xffffffffffffffff;
    Test_Expect(Zb_memcmp(&security, &expected, (uint32_t)sizeof expected) == 0,
           "and every one of those refusals left the module zeroed but for apsTrustCenterAddress, which 4.6.3.1 starts all-F: no level, no descriptor, no pair, no link key, no counter and no scratch");
}

/* Case 30, the two lookups `aps` selects an entry with, and what they refuse to match. */
void caseKeyPairLookups(void)
{
    Fixture fixture;
    Security_KeyPairEntry pairs[3];

    pairs[0] = keyPairAt(APS_PARTNER_IEEE, 0x1234, 1, SECURITY_KEYPAIR_ATTR_VERIFIED, s_linkKeyHex,
                         1, 0, SECURITY_LINK_KEY_UNIQUE, SECURITY_FEATURES_NONE, 1);
    pairs[1] = keyPairAt(PEER_IEEE, 0x0002, 1, SECURITY_KEYPAIR_ATTR_PROVISIONAL, s_linkKeyHex,
                         1, 0, SECURITY_LINK_KEY_UNIQUE, SECURITY_FEATURES_NONE, 1);
    pairs[2] = keyPairAt(SEEDED_IEEE, 0x0003, 0, SECURITY_KEYPAIR_ATTR_VERIFIED, s_linkKeyHex,
                         1, 0, SECURITY_LINK_KEY_UNIQUE, SECURITY_FEATURES_NONE, 1);
    fixtureAps5(&fixture, OWN_IEEE, pairs, 3);

    Test_Expect(Security_KeyPairCount(&fixture.security) == 3,
           "case 30: three pairs, held dense from index 0, which is what makes an index a name for Table 2-4's KeyIndex");
    Test_Expect(Security_FindKeyPairByIeee(&fixture.security, APS_PARTNER_IEEE) == 0,
           "Security_FindKeyPairByIeee finds the entry whose DeviceAddress it is");
    Test_Expect(Security_FindKeyPairByIeee(&fixture.security, PEER_IEEE) == 1, "and the second one");
    Test_Expect(Security_FindKeyPairByIeee(&fixture.security, SEEDED_IEEE) == 2, "and the third");
    Test_Expect(Security_FindKeyPairByIeee(&fixture.security, OWN_IEEE) == -1,
           "and no entry is shared with this device itself, which is the answer 4.4.1.1 step 1 gives before it says security processing SHALL fail");

    Test_Expect(Security_FindKeyPairByShort(&fixture.security, 0x1234) == 0,
           "Security_FindKeyPairByShort resolves the alias, which is how a 16-bit destination or source reaches the set at all");
    Test_Expect(Security_FindKeyPairByShort(&fixture.security, 0x0002) == 1, "for either entry that carries one");
    Test_Expect(Security_FindKeyPairByShort(&fixture.security, 0x0003) == -1,
           "and the third entry carries shortAddress 0x0003 with shortKnown 0, which names no address: it is never a hit");
    Test_Expect(Security_FindKeyPairByShort(&fixture.security, 0x0000) == -1,
           "not even for 0x0000, which is an unset alias here and not an address a frame could ask for");

    Security_Reset(&fixture.security);

    Test_Expect(Security_KeyPairCount(&fixture.security) == 0, "and Security_Reset leaves a module holding no pairs");
    Test_Expect(Security_FindKeyPairByIeee(&fixture.security, APS_PARTNER_IEEE) == -1,
           "in which both lookups answer -1 and Security_IsEnabled answers 0: the two crossings are separate questions");
    Test_Expect(Security_IsEnabled(&fixture.security) == 0, "and the wiped module does neither");
}

/* Case 31, 4.4.1.2 step 8 as a reachable leg: the pair says the peer supports frame counter
   synchronisation, this device has never verified this window through a challenge, and the frame is
   refused although its tag verified. */
void caseApsUnverifiedFrameCounter(void)
{
    Fixture unverified;
    Fixture verified;
    Fixture noCapability;
    Security_KeyPairEntry pairs[1];
    Security_ApsResult result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    pairs[0] = keyPairAt(OWN_IEEE, 0x0000, 0, SECURITY_KEYPAIR_ATTR_VERIFIED, s_linkKeyHex,
                         1, 0, SECURITY_LINK_KEY_UNIQUE, SECURITY_FEATURES_FRAME_COUNTER_SYNC, 0);
    fixtureAps5(&unverified, APS_PARTNER_IEEE, pairs, 1);

    pairs[0] = keyPairAt(OWN_IEEE, 0x0000, 0, SECURITY_KEYPAIR_ATTR_VERIFIED, s_linkKeyHex,
                         1, 0, SECURITY_LINK_KEY_UNIQUE, SECURITY_FEATURES_FRAME_COUNTER_SYNC, 1);
    fixtureAps5(&verified, APS_PARTNER_IEEE, pairs, 1);

    frameLen = copyVector(frame, s_apsFrame1Hex);
    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    plainLen = 0;

    Test_ExpectStatus(Security_UnprotectAps(&unverified.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_UNVERIFIED_FRAME_COUNTER,
                  "case 31: Features & Capabilities bit #0 set and VerifiedFrameCounter clear is step 8's failure, \"The result of the failure SHALL be UNVERIFIED_FRAME_COUNTER\", which is the word this module now answers with. It fires after step 6 verified the tag and before step 9 stored the window");
    Test_Expect(plain[0] == 0xaa && plainLen == 0,
           "and the plaintext the seam had already verified sits in the caller's buffer while the reported length stays 0: exactly as at 4.3.1.2 step 6 with nwkAllFresh TRUE, a frame that is authentic and still refused is refused by its status, and `aps` delivers nothing to it");
    Test_Expect(unverified.security.keyPairs[0].incomingFrameCounter == 0,
           "and the window stayed unverified and unstored: step 8's failure means no further security processing, which is where a challenge response would have started (4.6.3.8 with 4.5.1.1.4) and defers with the rest of the deferred list");
    Test_Expect(unverified.security.keyPairs[0].featuresCapabilities == SECURITY_FEATURES_FRAME_COUNTER_SYNC
           && unverified.security.keyPairs[0].verifiedFrameCounter == 0,
           "and the state that refused is the state the application seeded: this module can refuse on this ground and cannot clear it");

    drainLog(&unverified.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_UNPROTECT_FAILED, LOG_REASON_ERROR, (uint32_t)ZB_ERR_UNVERIFIED_FRAME_COUNTER) == 1,
           "and the refusal is recorded");

    frameLen = copyVector(frame, s_apsFrame1Hex);
    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);

    Test_ExpectStatus(Security_UnprotectAps(&verified.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "while the identical frame at the identical pair, with VerifiedFrameCounter set, passes step 8 and is accepted, which is what makes the refusal above step 8's and not the tag's");
    Test_ExpectHex("with its payload handed up", plain, plainLen, s_apsPayloadHex);
    Test_Expect(verified.security.keyPairs[0].incomingFrameCounter == 5, "and step 9 ran for it");
    Test_Expect(result.rvfcSeen == 1,
           "and the received Require Verified Frame Counter bit was 1 in both runs: step 8 judged neither, which is the gap recorded here");

    pairs[0] = keyPairAt(OWN_IEEE, 0x0000, 0, SECURITY_KEYPAIR_ATTR_VERIFIED, s_linkKeyHex,
                         1, 0, SECURITY_LINK_KEY_UNIQUE, SECURITY_FEATURES_NONE, 0);
    fixtureAps5(&noCapability, APS_PARTNER_IEEE, pairs, 1);

    frameLen = copyVector(frame, s_apsFrame1Hex);
    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    plainLen = 0;

    Test_ExpectStatus(Security_UnprotectAps(&noCapability.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and the same frame at a pair that records no peer capability and an unverified window is accepted: step 8 fires on the Features & Capabilities bit and on nothing else, which is the reading that separates it from 4.5.1.1.4's demand that a receiver which has not verified the frame counter accept only a frame whose Require Verified Frame Counter bit is set, that bit is 1 in this frame too and is judged nowhere (the digest's gap 4)");
    Test_Expect(noCapability.security.keyPairs[0].incomingFrameCounter == 5,
           "and the window was stored, unverified: the state the deferred challenge machinery of 4.6.3.8 exists to clear");
}

/* Case 32, the wipe duty over the new pool: case 16's byte-for-byte assertion, with the key pairs
   and both of their counters in the struct that is compared. */
void caseResetWipesApsMaterial(void)
{
    Fixture sender;
    Fixture receiver;
    Security_KeyPairEntry pairs[1];
    Security_ApsResult result;
    Security expected;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t headerLen;
    uint32_t payloadLen;
    uint32_t plainLen;

    pairs[0] = apsPair(APS_PARTNER_IEEE, 4, 0);
    fixtureAps5(&sender, OWN_IEEE, pairs, 1);

    headerLen = copyVector(header, s_apsHeaderHex);
    payloadLen = copyVector(payload, s_apsPayloadHex);

    Test_ExpectStatus(Security_ProtectAps(&sender.security, 0, SECURITY_KEY_ID_DATA, header, headerLen, payload, payloadLen,
                                     1, frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "case 32: a protection first, so the module holds a link key, a moved outgoing counter and a frame in its scratch");

    pairs[0] = apsPair(OWN_IEEE, 1, 0);
    fixtureAps5(&receiver, APS_PARTNER_IEEE, pairs, 1);

    Test_ExpectStatus(Security_UnprotectAps(&receiver.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and an unprotect on the other side, so a second module holds a stored incoming window");

    Security_Reset(&sender.security);
    Zb_memset(&expected, 0, (uint32_t)sizeof expected);
    expected.trustCenterIeee = 0xffffffffffffffff;

    Test_Expect(Zb_memcmp(&sender.security, &expected, (uint32_t)sizeof expected) == 0,
           "and every octet of the wiped struct is zero but for apsTrustCenterAddress's all-F start (4.6.3.1): the network descriptor and its 16 octets of key, the key-pair entry with its LinkKey and both of its counters, its attributes, its type and its capability byte, the level, the identity and both scratch buffers (the wipe duty restated over the key-pair material)");
    Test_Expect(Security_KeyPairCount(&sender.security) == 0, "which says so through the APS side of the module's own surface");

    Test_ExpectStatus(Security_ProtectAps(&sender.security, 0, SECURITY_KEY_ID_DATA, header, headerLen, payload, payloadLen,
                                     1, frame, SECURITY_FRAME_MAX, &frameLen), ZB_ERR_UNSUPPORTED,
                  "and a wiped module refuses rather than running on a zeroed link key at a zeroed level");

    Test_ExpectStatus(Security_UnprotectAps(&sender.security, frame, frameLen, APS_HEADER_LEN, OWN_IEEE, 1,
                                       plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_UNSUPPORTED,
                  "in both directions, with no pool to resolve a partner in");

    Security_Reset(&receiver.security);
    Test_Expect(Zb_memcmp(&receiver.security, &expected, (uint32_t)sizeof expected) == 0,
           "and the same for the module that had stored a window, the same one field aside");
}

/* Case 33, the two capacity refusals at the APS crossing, and what neither of them consumes. */
void caseApsCapacityRefusals(void)
{
    Fixture fixture;
    Security_KeyPairEntry pairs[2];
    Security_ApsResult result;
    Security_KeyState state;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t out[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t headerLen;
    uint32_t payloadLen;
    uint32_t index;
    uint32_t plainLen;

    pairs[0] = apsPair(APS_PARTNER_IEEE, 4, 0);
    pairs[1] = apsPair(OWN_IEEE, 1, 0);     /* the same module seen from the other side of one link key, so a1 resolves here and the room gate can be judged against a stored window */
    fixtureAps5(&fixture, OWN_IEEE, pairs, 2);

    headerLen = copyVector(header, s_apsHeaderHex);
    payloadLen = copyVector(payload, s_apsPayloadHex);
    Zb_memset(out, 0x5a, (uint32_t)sizeof out);

    Test_ExpectStatus(Security_ProtectAps(&fixture.security, 0, SECURITY_KEY_ID_DATA, header, headerLen, payload, payloadLen,
                                     1, out, APS_HEADER_LEN + SECURITY_APS_AUX_MAX + APS_PAYLOAD_LEN
                                     + 4 - 1, &frameLen), ZB_ERR_NO_SPACE,
                  "case 33: a caller with one octet too little room gets NO_SPACE and no frame, 4.4.1.1 step 8 bounds the frame, `outMax` bounds the caller, and both are decided before anything is consumed");
    Test_Expect(out[0] == 0x5a, "and its buffer was not half-written into");

    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.keyPairCount == 2 && state.keyPairOutgoingFrameCounter[0] == 4,
           "and the entry's counter did not move: 4.4.1.1 step 9 runs for a frame that became the secured frame");

    frameLen = copyVector(frame, s_apsFrame1Hex);

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen - 8, APS_HEADER_LEN,
                                       APS_PARTNER_IEEE, 1, out, (uint32_t)sizeof out, &plainLen, &result),
                  ZB_ERR_BAD_ARGUMENT,
                  "a secured APSDU truncated by eight octets is 22 long, shorter than 8 + 13 + 4, so 4.4.1.2 step 6iii has nothing to split: the bounds gate is a bad argument, before any entry, window or tag is consulted");

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen, APS_HEADER_LEN + 9,
                                       APS_PARTNER_IEEE, 1, out, (uint32_t)sizeof out, &plainLen, &result),
                  ZB_ERR_BAD_ARGUMENT,
                  "and a header length the frame cannot carry (17 named header octets inside 30, with a 13-octet auxiliary header and a 4-octet tag still to fit) is the same refusal");

    Test_ExpectStatus(Security_ProtectAps(&fixture.security, 5, SECURITY_KEY_ID_DATA, header, headerLen, payload, payloadLen,
                                     1, out, SECURITY_FRAME_MAX, &frameLen), ZB_ERR_AUTH,
                  "and an entry index outside the pool is 4.4.1.1 step 1's failure word and not an argument error: index 5 in a pool of 2");

    Test_Expect(out[0] == 0x5a, "and none of the three wrote anything into the caller's buffer");

    frameLen = copyVector(frame, s_apsFrame1Hex);
    Zb_memset(out, 0x5a, (uint32_t)sizeof out);
    plainLen = 0;

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       out, APS_PAYLOAD_LEN - 1, &plainLen, &result), ZB_ERR_NO_SPACE,
                  "and on the receive side a caller with four octets for a five-octet payload gets NO_SPACE: with nothing committed, because a frame this module cannot hand over must not burn the window of the partner that sent it");
    Test_Expect(fixture.security.keyPairs[1].incomingFrameCounter == 0,
           "which the refusal is proved by asking about the same frame with room afterwards: the window is still 0, so 4 is not \"less than\" it and this second answer cannot be a counter refusal wearing a room refusal");
    Test_Expect(plainLen == 0, "and no payload length was reported for the frame that had no room");

    frameLen = copyVector(frame, s_apsFrame1Hex);
    Zb_memset(out, 0x5a, (uint32_t)sizeof out);

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       out, SECURITY_FRAME_MAX, &plainLen, &result), ZB_OK,
                  "while the same a1 with room for it is accepted here, in the module that sent it: the extended nonce named the partner, and the entry it named holds the same link key from the other side");
    Test_ExpectHex("with its payload intact", out, plainLen, s_apsPayloadHex);
    Test_Expect(result.keyPairIndex == 1, "naming the entry the auxiliary source address resolved to");
    Test_Expect(fixture.security.keyPairs[1].incomingFrameCounter == 5, "and the window stored then");

    for (index = 0; index < 103; index++)
        payload[index] = (uint8_t)(0x80 + index);

    Test_ExpectStatus(Security_ProtectAps(&fixture.security, 0, SECURITY_KEY_ID_DATA, header, headerLen, payload, 94,
                                     1, out, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "and a long ASDU in the 13-octet-auxiliary shape composes up to the MSDU ceiling: 8 + 13 + 94 + 4 = 119");
    Test_Expect(frameLen == SECURITY_APS_MSDU_MAX,
          "119 octets, which is aMaxMACFrameSize: Annex D.5's aMaxPHYPacketSize less Table 3-65's nwkcMinHeaderOverhead of 8, the bound 4.4.1.1 step 8 puts on the secured outgoing frame");

    Test_ExpectStatus(Security_ProtectAps(&fixture.security, 0, SECURITY_KEY_ID_DATA, header, headerLen, payload, 95,
                                     1, out, SECURITY_FRAME_MAX, &frameLen), ZB_ERR_NO_SPACE,
                  "while 8 + 13 + 95 + 4 = 120 is refused at composition, which is step 8 read as it prints: the secured frame is the MSDU the network layer carries, so its ceiling is the MAC payload less that overhead and not the MAC payload itself");

    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.keyPairOutgoingFrameCounter[0] == 5 && state.keyPairOutgoingFrameCounter[1] == 1,
           "and only the frame that was produced moved a counter: entry 0 from 4 to 5, entry 1 not at all, the refusal consuming nothing");

    drainLog(&fixture.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_FRAME_TOO_LONG, LOG_REASON_DROPPED, 120) == 1,
           "and the length refusal is recorded with the length it would have been");
}

/*
 * 4.6.3.8's last paragraph: "After a device initially joins a network by receiving an APS Encrypted Transport Key
 * command, it SHALL set the VerifiedFrameCounter to TRUE and the IncomingFrameCounter field to the frame counter
 * value for the received APS Transport Key Command."
 */
void caseVerifyKeyPair(void)
{
    Fixture fixture;
    Security_KeyPairEntry pairs[1];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    pairs[0] = keyPairAt(OWN_IEEE, 0x0000, 0, SECURITY_KEYPAIR_ATTR_VERIFIED, s_linkKeyHex,
                         1, 0, SECURITY_LINK_KEY_UNIQUE, SECURITY_FEATURES_FRAME_COUNTER_SYNC, 0);
    fixtureAps5(&fixture, APS_PARTNER_IEEE, pairs, 1);

    frameLen = copyVector(frame, s_apsFrame1Hex);

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, 0), ZB_ERR_UNVERIFIED_FRAME_COUNTER,
                  "the frame a transport key would arrive in is refused while the pair is unverified");

    Test_ExpectStatus(Security_VerifyKeyPair(&fixture.security, 0, 4), ZB_OK,
                  "and the transport key that arrived verifies the pair it came from, with the counter that command carried");

    Test_ExpectCount(fixture.security.keyPairs[0].verifiedFrameCounter, 1, "which sets VerifiedFrameCounter");
    Test_ExpectCount(fixture.security.keyPairs[0].incomingFrameCounter, 5,
                     "and the window past that command's own counter, 4, so a replay of it is refused and the next frame is not");

    frameLen = copyVector(frame, s_apsFrame1Hex);
    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);

    Test_ExpectStatus(Security_UnprotectAps(&fixture.security, frame, frameLen, APS_HEADER_LEN, 0, 0,
                                       plain, (uint32_t)sizeof plain, &plainLen, 0), ZB_ERR_BAD_FRAME_COUNTER,
                  "so the same frame, whose counter is now behind the window, is refused as a replay rather than as unverified");

    Test_ExpectStatus(Security_VerifyKeyPair(&fixture.security, 3, 4), ZB_ERR_NOT_FOUND,
                  "and a pair the pool does not hold is refused by name");
    Test_ExpectStatus(Security_VerifyKeyPair(0, 0, 4), ZB_ERR_NOT_FOUND, "as is a call with no module");
}

/* 4.4.1.1 step 1a-ii: an UNVERIFIED pair encrypts nothing. A frame asked under one goes out under the global pair, the
   key the partner still holds while the new one awaits its Verify-Key, and its counter is the global pair's. */
void caseUnverifiedPairEncryptsNothing(void)
{
    Fixture sender;
    Fixture receiver;
    Security_KeyPairEntry senderPairs[2];
    Security_KeyPairEntry receiverPairs[1];
    Security_ApsResult result;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[4] = { 0x01, 0x02, 0x03, 0x04 };
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen = 0;
    uint32_t headerLen;
    uint32_t plainLen = 0;

    senderPairs[0] = apsPair(0, 1, 0);
    senderPairs[0].linkKeyType = SECURITY_LINK_KEY_GLOBAL;
    senderPairs[1] = apsPair(APS_PARTNER_IEEE, 1, 0);
    senderPairs[1].keyAttributes = SECURITY_KEYPAIR_ATTR_UNVERIFIED;
    senderPairs[1].key[0] ^= 0xff;
    receiverPairs[0] = apsPair(OWN_IEEE, 1, 0);
    fixtureAps(&sender, SECURITY_LEVEL_ENC_MIC_32, OWN_IEEE, senderPairs, 2);
    fixtureAps(&receiver, SECURITY_LEVEL_ENC_MIC_32, APS_PARTNER_IEEE, receiverPairs, 1);

    headerLen = copyVector(header, s_apsHeaderHex);

    Test_ExpectStatus(Security_ProtectAps(&sender.security, 1, SECURITY_KEY_ID_DATA, header, headerLen, payload, 4, 1,
                                          frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                      "a frame asked under the partner's UNVERIFIED pair is secured");
    Test_ExpectStatus(Security_UnprotectAps(&receiver.security, frame, frameLen, headerLen, OWN_IEEE, 1, plain,
                                            (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                      "under the global key, which the partner still holds, and not under the new one");
    Test_Expect(Security_KeyPairAt(&sender.security, 0)->outgoingFrameCounter == 2
                && Security_KeyPairAt(&sender.security, 1)->outgoingFrameCounter == 1,
                "and the global pair's counter is the one used");
}
