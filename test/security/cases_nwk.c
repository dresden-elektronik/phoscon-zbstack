/* The `security` suite's NWK crossing: cases 1-17, the two procedures of
   R23.1 4.3.1.1 and 4.3.1.2 as vectors and as refusals, what a protection puts on the air octet for octet, what
   an unprotection accepts, refuses and stores, the shape of the material set, and the module's own bounds. Every
   vector these cases quote is here, with the comment that says what it is and where it comes from. */

#include "log.h"
#include "security.h"
#include "security_helpers.h"
#include "test_harness.h"
#include "zb_utils.h"

/* The NWK header of every vector but s4: FCF 0x0208, frame type Data, nwkcProtocolVersion 0x02, the
   security sub-field set (3.3.1.1.4) and nothing else, then destination 0x0001, source 0x0000,
   radius 0x1e, sequence number 0x05, in Figure 3-4's order. */
const char *s_headerHex = "0802010000001e05";

/* s4's header, the same frame with the source route subframe of 3.3.1.8: relay count 3, relay index
   2, relays 0x0001 0x0002 0x0003. Sixteen octets, which is what sits ahead of the
   auxiliary header. */
const char *s_routeHeaderHex = "0806010000001e090302010002000300";

const char *s_payloadHex = "40414243444546";

/* s1: level 0x05, key A at sequence number 0x00, outgoing counter 0x00000005. The frame is
   NwkHeader || AuxiliaryHeader || c || MIC (4.3.1.1 step 5), 8 + 14 + 7 + 4 = 33 octets. The
   auxiliary header reads 0x28 (control, level sub-field cleared by step 8), 05000000 (frame counter,
   low octet first), efcdab8967452301 (this device's extended address, low octet first), 00 (key
   sequence number). */
const char *s_frame1Hex = "0802010000001e052805000000efcdab896745230100621e81731bba4c15db7c75";

/* s5: the same key, the same level, the next counter, 0x00000006. The pair is the per-issue rule: a
   retry of a frame is a new protection with the counter the descriptor holds at that moment. */
const char *s_frame5Hex = "0802010000001e052806000000efcdab8967452301004ab8a663d8e761756f6f84";

/* s2: key B at sequence number 0x01, counter 0x00000006. The only vector whose key sequence number
   is not the active one, which is what 4.3.1.2 step 7 is about. */
const char *s_frame2Hex = "0802010000001e052806000000efcdab896745230101c1553aae53922b720f9006";

/* s3: level 0x01, which Table 4-38 gives authentication and no encryption (M = 4). The payload
   travels in the clear and the frame is NwkHeader || AuxiliaryHeader || Payload || MIC. */
const char *s_frame3Hex = "0802010000001e052807000000efcdab89674523010040414243444546d420072d";

/* s4: the source-routed frame, counter 0x00000008, 16 + 14 + 7 + 4 = 41 octets. The route subframe
   is inside the authenticated string, which is that claim in vector form. */
const char *s_frame4Hex = "0806010000001e0903020100020003002808000000efcdab896745230100ff6816b475489467dd6b48";

/* The auxiliary header of s4's counter and key sequence number with the level sub-field cleared:
   what case 5 asserts octet by octet, because no published vector covers a frame protected under an
   adopted key. */
const char *s_auxCounter7Hex = "2807000000efcdab896745230101";

const char *s_auxCounter6Hex = "2806000000efcdab896745230101";

/* A frame whose security control is 0x35: level 0x05 in bits 0-2 as transmitted, key identifier '10'
   in bits 3-4 (Table 4-39's key-transport key) and extended nonce 1. Band A does not read key
   transport at the NWK, so this is refused as a shape and not as a bad key. */
const char *s_badControlHex = "0802010000001e053505000000efcdab896745230100621e81731bba4c15db7c75";

/* A frame whose security control is 0x25: key identifier '01' and extended nonce 0, so the source
   address field is absent and the auxiliary header is 1 + 4 + 1 = 6 octets (4.5.1.3). That is the
   802.15.4-2024 shape, whose control bit 5 means frame counter suppression; this stack refuses to
   read it as a Zigbee NPDU. */
const char *s_shortAuxHex = "0802010000001e0525050000000040414243444546d420072d";

/* Case 1, 4.3.1.1 end to end: the s1 vector, octet for octet, and the counter step 7 left behind. */
void caseProtectVector(void)
{
    Fixture fixture;
    Security_KeyDescriptor keys[1];
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    Security_KeyState state;
    uint32_t frameLen;
    uint32_t headerLen;
    uint32_t payloadLen;

    keys[0] = keyAt(0x00, s_keyAHex, 5);
    fixture5(&fixture, keys, 1, 0x00);

    headerLen = copyVector(header, s_headerHex);
    payloadLen = copyVector(payload, s_payloadHex);

    Test_Expect(headerLen == HEADER_LEN && payloadLen == PAYLOAD_LEN,
           "the s1 fixture is an 8-octet NWK header and a 7-octet payload");
    Test_Expect(Security_IsEnabled(&fixture.security) == 1, "a device at level 0x05 with key 0x00 live does run security");
    Test_Expect(Security_Level(&fixture.security) == SECURITY_LEVEL_ENC_MIC_32, "and says which level it runs");

    Test_ExpectStatus(Security_Protect(&fixture.security, header, headerLen, payload, payloadLen,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "case 1: protect at level 0x05, key sequence number 0x00, outgoing counter 0x00000005");
    Test_Expect(frameLen == HEADER_LEN + SECURITY_AUX_LEN + PAYLOAD_LEN + 4,
           "the secured NPDU is 8 header + 14 auxiliary + 7 payload + 4 MIC octets (4.3.1.1 step 5 with Table 4-38)");
    Test_ExpectHex("case 1: the frame is the s1 vector octet for octet", frame, frameLen, s_frame1Hex);

    /* The intermediate forms of s1 (the 13-octet nonce efcdab8967452301 05000000 2d and the 22-octet
       authenticated string 0802010000001e05 2d05000000efcdab896745230100) are never emitted: the
       frame carries 0x28 where the computation used 0x2D (4.3.1.1 step 8). Byte-exactness of the whole
       frame is what says they were the ones the vector was computed from, and both are quoted in main,
       where their lengths and octets are checked. */
    Test_Expect(frame[HEADER_LEN] == 0x28,
           "and the auxiliary header's first octet is the nonce's control octet with its three level bits cleared: 0x2D in the computation, 0x28 on air (4.3.1.1 step 8)");

    Security_Snapshot(&fixture.security, &state);

    Test_Expect(state.keyCount == 1 && state.keySeqNumber[0] == 0x00 && state.outgoingFrameCounter[0] == 6,
           "4.3.1.1 step 7: the descriptor that was used now holds 6, and the snapshot is what exposes it");
    Test_Expect(state.nwkActiveKeySeqNumber == 0x00, "and the active key sequence number did not move");
}

/* Case 2, the foundation: the next protection is the next counter, and the frame
   changes completely. */
void caseProtectSecondFrameUsesNextCounter(void)
{
    Fixture fixture;
    Security_KeyDescriptor keys[1];
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    Security_KeyState state;
    uint32_t frameLen;
    uint32_t headerLen;

    keys[0] = keyAt(0x00, s_keyAHex, 5);
    fixture5(&fixture, keys, 1, 0x00);

    headerLen = copyVector(header, s_headerHex);
    copyVector(payload, s_payloadHex);

    Test_ExpectStatus(Security_Protect(&fixture.security, header, headerLen, payload, PAYLOAD_LEN,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "case 2: the first protection with counter 0x00000005");
    Test_ExpectHex("case 2: the first frame is s1", frame, frameLen, s_frame1Hex);

    Test_ExpectStatus(Security_Protect(&fixture.security, header, headerLen, payload, PAYLOAD_LEN,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "and the second protection of the same header and payload is a fresh 4.3.1.1 run, not a repeat");
    Test_ExpectHex("case 2: the second frame is s5, the vector at counter 0x00000006", frame, frameLen, s_frame5Hex);

    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.outgoingFrameCounter[0] == 7, "and the descriptor now holds 7");
}

/* Case 3, 4.3.1.2 against s1 and s5: the plaintext, the hop identity, and the freshness rule as
   printed, a strictly smaller count is refused, an equal one is accepted, and step 6 stores
   ReceivedFrameCount + 1. */
void caseUnprotectAndFreshness(void)
{
    Fixture fixture;
    Security_KeyDescriptor keys[1];
    Security_Result result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    keys[0] = keyAt(0x00, s_keyAHex, 5);
    fixture5(&fixture, keys, 1, 0x00);

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    frameLen = copyVector(frame, s_frame1Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "case 3: s1 unprotected at level 0x05 with key 0x00 in the set");
    Test_ExpectHex("case 3: the payload is the seven octets it was (4.3.1.2 step 5b)", plain, plainLen, s_payloadHex);
    Test_Expect(plainLen == PAYLOAD_LEN, "and the auxiliary header and the MIC are not part of it");
    Test_Expect(result.senderIeee == OWN_IEEE, "the hop identity is the auxiliary source address, which is the previous hop's own extended address (4.5.1.3)");
    Test_Expect(result.keySeqNumber == 0x00 && result.frameCounter == 5, "and the result names the key and the count as the frame carried them");
    Test_Expect(result.activeKeyAdopted == 0, "with no key change: 0x00 is the active sequence number already");

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_BAD_FRAME_COUNTER,
                  "and the same frame again is the 'bad frame counter' failure of 4.3.1.2 step 3: 5 is less than the stored 6");
    Test_Expect(plain[0] == 0xa5, "and nothing was written for it");

    frameLen = copyVector(frame, s_frame5Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "then counter 0x00000006 from the same sender is accepted: the rule as printed refuses only a strictly smaller count, so an equal one passes, the spec's own replay weakness, recorded and not repaired");
    Test_Expect(result.frameCounter == 6 && plainLen == PAYLOAD_LEN, "and the accepted frame is handed up with its own count");

    frameLen = copyVector(frame, s_frame5Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_BAD_FRAME_COUNTER,
                  "which proves step 6 stored 7, not 6: the frame at 0x00000006 is now refused as smaller than the stored window");
}

/* Case 4, commit-after-verify: a tampered MIC fails, stores nothing, and costs the sender nothing. */
void caseTamperedMic(void)
{
    Fixture fixture;
    Security_KeyDescriptor keys[1];
    Security_Result result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    keys[0] = keyAt(0x00, s_keyAHex, 5);
    fixture5(&fixture, keys, 1, 0x00);

    frameLen = copyVector(frame, s_frame1Hex);
    frame[frameLen - 1] = (uint8_t)(frame[frameLen - 1] ^ 0xff);

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_AUTH,
                  "case 4: s1 with its last octet flipped is 4.3.1.2 step 5a's 'frame security failed'");
    Test_Expect(plain[0] == 0x00 && plain[PAYLOAD_LEN - 1] == 0x00,
           "and no plaintext was released: what did not verify is destroyed, first octet to last (Annex A.4)");

    drainLog(&fixture.log);

    Test_Expect(logHas(LOG_COMP_SECURITY_UNPROTECT_FAILED, LOG_REASON_ERROR, (uint32_t)ZB_ERR_AUTH) == 1,
           "and the failure is a record in the caller's pool (docs/internals/coding-rules.md §5)");

    frameLen = copyVector(frame, s_frame1Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and the pristine s1 frame still succeeds afterwards: a frame that did not authenticate never stored a counter, so 4.3.1.2 step 6 never ran");
}

/* Case 5, 4.3.1.2 step 7: a received key sequence number that is in the material
   set and is not the active one becomes the active one, and the next frame this device protects is
   secured under it, with that descriptor's own counter and its own sequence number in the auxiliary
   header. */
void caseKeyAdoption(void)
{
    Fixture fixture;
    Fixture peer;
    Security_KeyDescriptor keys[2];
    Security_Result result;
    Security_KeyState state;
    uint8_t adopted[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t headerLen;
    uint32_t plainLen;

    keys[0] = keyAt(0x00, s_keyAHex, 5);
    keys[1] = keyAt(0x01, s_keyBHex, 6);
    fixture5(&fixture, keys, 2, 0x00);

    frameLen = copyVector(frame, s_frame2Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "case 5: s2, secured with key 0x01, unprotected by a device whose active key is 0x00, step 2 matches the received sequence number to the set");
    Test_Expect(result.activeKeyAdopted == 1, "and step 7 fires: 0x01 is in nwkSecurityMaterialSet and is not the active sequence number");
    Test_Expect(result.keySeqNumber == 0x01 && result.frameCounter == 6, "with the key and the count the frame named");

    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.nwkActiveKeySeqNumber == 0x01, "and the module holds the adopted sequence number");
    Test_Expect(state.keyCount == 2 && state.keySeqNumber[0] == 0x00 && state.keySeqNumber[1] == 0x01,
           "with both descriptors of the set exposed, each with its own counter");

    drainLog(&fixture.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_KEY_ADOPTED, LOG_REASON_STATE, 1) == 1,
           "and the adoption is a record naming the sequence number it moved to");

    headerLen = copyVector(header, s_headerHex);
    copyVector(payload, s_payloadHex);

    Test_ExpectStatus(Security_Protect(&fixture.security, header, headerLen, payload, PAYLOAD_LEN,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "and the next frame this device protects is protected under the adopted key, with that descriptor's own counter");
    Test_Expect(frameLen == HEADER_LEN + SECURITY_AUX_LEN + PAYLOAD_LEN + 4, "of the usual 33 octets");
    Test_ExpectHex("whose auxiliary header is the level-0x05 form at counter 0x00000006 under key 0x01",
                frame + HEADER_LEN, SECURITY_AUX_LEN, s_auxCounter6Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_BAD_FRAME_COUNTER,
                  "and this device does not accept its own frame back: the window it stored for its own address under key 0x01 is 7 and 6 is smaller, the same rule of 4.3.1.2 step 3 that makes hop-by-hop re-securing mean anything");

    Zb_memcpy(adopted, frame, frameLen);

    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.outgoingFrameCounter[1] == 7 && state.outgoingFrameCounter[0] == 5,
           "and the refusal consumed nothing: the descriptor that was used moved from 6 to 7, key 0x00 is still at 5 (the per-descriptor counter)");

    Test_ExpectStatus(Security_Protect(&fixture.security, header, headerLen, payload, PAYLOAD_LEN,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "and the next protection carries the counter it moved to");
    Test_ExpectHex("at counter 0x00000007 under key 0x01",
                frame + HEADER_LEN, SECURITY_AUX_LEN, s_auxCounter7Hex);

    /* No published vector covers a frame protected under an adopted key, so the ciphertext and MIC of
       that frame are checked the way a transform is checked without one: handed to a second device
       with the same key material and no memory of the first, which must recover the payload. */
    keys[0] = keyAt(0x00, s_keyAHex, 1);
    keys[1] = keyAt(0x01, s_keyBHex, 1);
    fixture5(&peer, keys, 2, 0x00);

    Zb_memset(plain, 0x5a, (uint32_t)sizeof plain);

    Test_ExpectStatus(Security_Unprotect(&peer.security, adopted, HEADER_LEN + SECURITY_AUX_LEN + PAYLOAD_LEN + 4,
                                    HEADER_LEN, plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "which a peer holding the same two keys and no stored windows accepts, whatever ciphertext the seam produced");
    Test_ExpectHex("and the payload it hands up is the octets that went in", plain, plainLen, s_payloadHex);
    Test_Expect(result.senderIeee == OWN_IEEE && result.keySeqNumber == 0x01 && result.frameCounter == 6,
           "with the hop, the key and the count the frame named: the peer sees this device as its previous hop (4.5.1.3)");

    Test_ExpectStatus(Security_Unprotect(&peer.security, adopted, HEADER_LEN + SECURITY_AUX_LEN + PAYLOAD_LEN + 4,
                                    HEADER_LEN, plain, (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_BAD_FRAME_COUNTER,
                  "and the peer stored a window for it, so the same frame is refused a second time");

    Security_Snapshot(&peer.security, &state);
    Test_Expect(state.nwkActiveKeySeqNumber == 0x01, "and the peer adopted the key too, from the same frame");
}

/* Case 5b, 4.3.1.2 step 7's "newer": Table 4-3 prints KeySeqNumber as an octet that wraps at 0x100 and the
   material set is an unordered pool searched by equality, so "newer" is the octet's own signed distance, a
   received number in the forward half of the circle moves the active one, an older copy leaves it where it was. */
void caseKeyAdoptionNeedsANewerSequenceNumber(void)
{
    Fixture fixture;
    Security_KeyDescriptor keys[2];
    Security_Result result;
    Security_KeyState state;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    /* s1 is key A at sequence number 0x00; this device's active key is 0x01, so the frame is older than it */
    keys[0] = keyAt(0x00, s_keyAHex, 5);
    keys[1] = keyAt(0x01, s_keyBHex, 6);
    fixture5(&fixture, keys, 2, 0x01);

    frameLen = copyVector(frame, s_frame1Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "case 5b: a frame that authenticates under the retired key of the set is still read");
    Test_Expect(result.keySeqNumber == 0x00 && result.activeKeyAdopted == 0,
           "and step 7 does not fire: 0x00 belongs to an entry that is not newer than the active 0x01");

    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.nwkActiveKeySeqNumber == 0x01,
           "so nwkActiveKeySeqNumber stays where it was: a late frame under the old key never moves it back");

    /* the same claim across the wrap: 0x00 is one step ahead of 0xff, which is a newer key and no smaller number */
    keys[0] = keyAt(0xff, s_keyBHex, 6);
    keys[1] = keyAt(0x00, s_keyAHex, 5);
    fixture5(&fixture, keys, 2, 0xff);

    frameLen = copyVector(frame, s_frame1Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and s1 read by a device whose active key is 0xff");
    Test_Expect(result.activeKeyAdopted == 1, "0x00 lies one step ahead of 0xff in the octet's own arithmetic, so it is newer");

    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.nwkActiveKeySeqNumber == 0x00, "and the active sequence number follows it across the wrap");

    /* and the half-way point: two entries 0x80 apart have no order, the forward half is open at its far end */
    keys[0] = keyAt(0x80, s_keyBHex, 6);
    keys[1] = keyAt(0x00, s_keyAHex, 5);
    fixture5(&fixture, keys, 2, 0x80);

    frameLen = copyVector(frame, s_frame1Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and s1 read by a device whose active key is exactly 0x80 away from it");
    Test_Expect(result.activeKeyAdopted == 0, "0x80 is half the circle in either direction: no order is defined there, so nothing is adopted");

    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.nwkActiveKeySeqNumber == 0x80, "and the active sequence number stands");
}

/* Case 6, 4.3.1.1 step 1's outgoing exhaustion: the refusal, and a counter that did not move. */
/* 4.6.3.4.2 (11816-11824) as one rule: in the normal operating state only a trust center key is accepted and it replaces
 * the alternate; outside it, at the join, the key replaces the active one; either way that key's counters go to zero. */
void caseNetworkKeyInstall(void)
{
    Fixture fixture;
    Security_KeyState state;
    Security_KeyDescriptor keys[2];
    uint8_t fresh[SECURITY_KEY_OCTETS];
    uint8_t activeKey[SECURITY_KEY_OCTETS];

    keys[0] = keyAt(0x00, s_keyAHex, 5);
    keys[1] = keyAt(0x01, s_keyBHex, 9);
    fixtureAt(&fixture, SECURITY_LEVEL_ENC_MIC_32, OWN_IEEE, 0x00, keys, 2, 0, 0, 1);

    Zb_memset(fresh, 0x77, (uint32_t)sizeof fresh);
    (void)copyVector(activeKey, s_keyAHex);

    Test_ExpectStatus(Security_InstallNetworkKey(&fixture.security, fresh, 0x03, 1, 0), ZB_ERR_AUTH,
                      "in the normal operating state a key that did not come from the trust center is refused: 4.6.3.4.2 'SHALL accept ... only if the SrcAddress parameter is the same as the Trust Center's address'");
    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.nwkActiveKeySeqNumber == 0x00 && state.keySeqNumber[0] == 0x00 && state.keySeqNumber[1] == 0x01
                && state.outgoingFrameCounter[0] == 5 && state.outgoingFrameCounter[1] == 9,
                "and nothing moved: the refused key is not the 'Otherwise' that replaces the active one, which would install the key the sentence before it has refused");

    Test_ExpectStatus(Security_InstallNetworkKey(&fixture.security, fresh, 0x02, 1, 1), ZB_OK,
                      "a trust center key in the normal operating state is accepted");
    Security_Snapshot(&fixture.security, &state);
    Test_ExpectCount(state.nwkActiveKeySeqNumber, 0x00,
                     "and it is the alternate: the active number stays until 4.6.3.4.3's switch-key makes it current");
    Test_Expect(state.keyCount == 2 && state.keySeqNumber[0] == 0x00 && state.keySeqNumber[1] == 0x02,
                "written over the alternate descriptor, which is the one 'If accepted ... SHALL replace'");
    Test_Expect(state.outgoingFrameCounter[0] == 5 && state.outgoingFrameCounter[1] == 0,
                "the active key keeps its counter, and the installed key's goes to zero as the clause's last sentence requires");

    Test_ExpectStatus(Security_InstallNetworkKey(&fixture.security, activeKey, 0x00, 1, 1), ZB_OK,
                      "the trust center re-sending the active key under its own number");
    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.keySeqNumber[0] == 0x00 && state.outgoingFrameCounter[0] == 5 && state.keySeqNumber[1] == 0x02,
                "changes nothing: written to the alternate it would leave two descriptors for one number, and zeroing the active key's counter would reset the one 4.3.4 says only APSME-SWITCH-KEY may reset");

    Test_ExpectStatus(Security_InstallNetworkKey(&fixture.security, fresh, 0x00, 1, 1), ZB_ERR_BAD_STATE,
                      "while other octets under the active number are refused: the set cannot hold two keys under one sequence number, and nothing in the clause says which of them the number would mean");

    Test_ExpectStatus(Security_InstallNetworkKey(&fixture.security, fresh, 0x04, 0, 1), ZB_OK,
                      "outside the normal operating state, which is the join, a key replaces the active one");
    Security_Snapshot(&fixture.security, &state);
    Test_ExpectCount(state.nwkActiveKeySeqNumber, 0x04,
                     "and the active number moves with it: a pointer naming no descriptor would leave the device with no network key");
    Test_Expect(state.keySeqNumber[0] == 0x04 && state.outgoingFrameCounter[0] == 0 && state.keySeqNumber[1] == 0x02,
                "in the descriptor the active key held, at zero, with the alternate untouched");

    Test_ExpectStatus(Security_InstallNetworkKey(0, fresh, 0x05, 1, 1), ZB_ERR_BAD_ARGUMENT,
                      "a module that is not there is an argument error");
    Test_ExpectStatus(Security_InstallNetworkKey(&fixture.security, 0, 0x05, 1, 1), ZB_ERR_BAD_ARGUMENT,
                      "and so is a key that is not there");
}

/* The join, where nothing is held: the first key a device receives becomes its active key, whatever number the trust
   center gave it (4.6.3.2.2.3 sends the active key, 4.6.3.2.3 makes the device authorized on it). */
void caseNetworkKeyInstallAtJoin(void)
{
    Fixture fixture;
    Security_KeyState state;
    Security_KeyDescriptor keys[1];
    uint8_t fresh[SECURITY_KEY_OCTETS];

    keys[0] = keyAt(0x00, s_keyAHex, 5);
    fixtureAt(&fixture, SECURITY_LEVEL_ENC_MIC_32, OWN_IEEE, 0x00, keys, 1, 0, 0, 1);

    Zb_memset(fresh, 0x66, (uint32_t)sizeof fresh);

    Test_ExpectStatus(Security_InstallNetworkKey(&fixture.security, fresh, 0x2a, 0, 1), ZB_OK,
                      "a key with a number other than the default, received at the join");
    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.nwkActiveKeySeqNumber == 0x2a && state.keyCount == 1 && state.keySeqNumber[0] == 0x2a,
                "is the active key under its own number: the default 0x00 does not stay behind naming nothing");
}

/* The counters 4.6.3.4.2 zeroes belong to the key installed, and a key replaced takes its windows with it: 4.3.1.2 step 6
   bounds the store by the material set, so windows for a number the set no longer holds have no key to answer to. */
void caseNetworkKeyInstallDropsItsWindows(void)
{
    Fixture fixture;
    Security_KeyDescriptor keys[2];
    Security_IncomingEntry windows[2];
    Security_Result result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;
    uint8_t fresh[SECURITY_KEY_OCTETS];

    keys[0] = keyAt(0x00, s_keyAHex, 5);
    keys[1] = keyAt(0x01, s_keyBHex, 9);

    windows[0] = windowAt(OWN_IEEE, 0x00, 11);
    windows[1] = windowAt(OWN_IEEE, 0x01, 13);

    fixtureAt(&fixture, SECURITY_LEVEL_ENC_MIC_32, OWN_IEEE, 0x00, keys, 2, windows, 2, 1);

    (void)copyVector(fresh, s_keyBHex);

    frameLen = copyVector(frame, s_frame2Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_BAD_FRAME_COUNTER,
                  "the s2 vector carries counter 6 under key 0x01 where this device has stored 13 for that sender, so 4.3.1.2 step 3 refuses it");

    Test_ExpectStatus(Security_InstallNetworkKey(&fixture.security, fresh, 0x01, 1, 1), ZB_OK,
                  "the trust center installs key 0x01 again, over the alternate");

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and the same frame is accepted: the window that refused it went to zero with the key it belonged to");
    Test_Expect(result.keySeqNumber == 0x01 && result.frameCounter == 6,
           "under the key and the count the frame names");

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_BAD_FRAME_COUNTER,
                  "and the window is live again from that frame: the same octets are refused the second time");

    {
        Security_KeyState state;

        Security_Snapshot(&fixture.security, &state);
        Test_ExpectCount(state.nwkActiveKeySeqNumber, 0x01,
                         "the earlier acceptance adopted 0x01 as the active key (4.3.1.2 step 7), so 0x00 is now the alternate");
    }


    Test_ExpectStatus(Security_InstallNetworkKey(&fixture.security, fresh, 0x05, 1, 1), ZB_OK,
                  "a new number from the trust center goes over that alternate, 0x00");
    Test_ExpectStatus(Security_InstallNetworkKey(&fixture.security, fresh, 0x01, 1, 1), ZB_OK,
                  "and the trust center re-sending the active 0x01 with the same octets");
    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_BAD_FRAME_COUNTER,
                  "changes nothing, the window included: a re-sent active key that zeroed its windows would reopen every frame it has already refused");
}

void caseOutgoingCounterExhausted(void)
{
    Fixture fixture;
    Security_KeyDescriptor keys[1];
    Security_KeyState state;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t headerLen;

    keys[0] = keyAt(0x00, s_keyAHex, 0xffffffff);
    fixture5(&fixture, keys, 1, 0x00);

    headerLen = copyVector(header, s_headerHex);
    copyVector(payload, s_payloadHex);
    Zb_memset(frame, 0x5a, (uint32_t)sizeof frame);

    Test_ExpectStatus(Security_Protect(&fixture.security, header, headerLen, payload, PAYLOAD_LEN,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_ERR_BAD_FRAME_COUNTER,
                  "case 6: a descriptor at 2^32-1 is refused (4.3.1.1 step 1), which the NWK crossing reports as MAX_FRM_COUNTER 0xcc");
    Test_Expect(frame[0] == 0x5a, "and nothing was written for it");

    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.outgoingFrameCounter[0] == 0xffffffff, "and the counter is unchanged: no further security processing, and no increment");

    drainLog(&fixture.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_PROTECT_REFUSED, LOG_REASON_ERROR, (uint32_t)ZB_ERR_BAD_FRAME_COUNTER) == 1,
           "and the refusal is recorded");
}

/* Case 7, 4.3.1.2 step 1's incoming exhaustion. The clause names no status for it; the reason word it
   is given is the outgoing one's. */
void caseIncomingCounterMaximum(void)
{
    Fixture fixture;
    Security_KeyDescriptor keys[1];
    Security_Result result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    keys[0] = keyAt(0x00, s_keyAHex, 5);
    fixture5(&fixture, keys, 1, 0x00);

    frameLen = copyVector(frame, s_frame1Hex);
    rewriteCounter(frame, HEADER_LEN, 0xffffffff);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_BAD_FRAME_COUNTER,
                  "case 7: a frame carrying ReceivedFrameCount 2^32-1 is refused before its key, its window or its MIC is looked at");

    drainLog(&fixture.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_UNPROTECT_FAILED, LOG_REASON_ERROR, (uint32_t)ZB_ERR_BAD_FRAME_COUNTER) == 1,
           "and the refusal is recorded as an unprotect failure");
}

/* Case 8, 4.3.1.2 step 2: a key sequence number that is not in the material set. */
void caseUnknownKeySeqNumber(void)
{
    Fixture fixture;
    Security_KeyDescriptor keys[2];
    Security_Result result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    keys[0] = keyAt(0x00, s_keyAHex, 5);
    keys[1] = keyAt(0x01, s_keyBHex, 5);
    fixture5(&fixture, keys, 2, 0x00);

    frameLen = copyVector(frame, s_frame1Hex);
    frame[HEADER_LEN + SECURITY_AUX_LEN - 1] = 0x02;     /* the key sequence number field, set to a number the set does not hold */

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_AUTH,
                  "case 8: no descriptor carries 0x02, which is 'frame security failed' with no key obtained");

    Test_Expect(fixture.security.nwkActiveKeySeqNumber == 0x00,
           "and nothing moved: an unmatched frame neither adopts a key nor stores a window");
}

/* Case 9, the auxiliary shapes band A does not read. Both frames are otherwise the s1
   vector, and both are refused as shapes rather than as bad keys or bad MICs. */
void caseUnsupportedAuxiliaryShapes(void)
{
    Fixture fixture;
    Security_KeyDescriptor keys[1];
    Security_Result result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    keys[0] = keyAt(0x00, s_keyAHex, 5);
    fixture5(&fixture, keys, 1, 0x00);

    frameLen = copyVector(frame, s_badControlHex);
    Test_Expect(frameLen == HEADER_LEN + SECURITY_AUX_LEN + PAYLOAD_LEN + 4,
           "case 9: the key-transport-shaped frame is as long as s1 and differs in one octet");

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_UNSUPPORTED,
                  "and it is refused: key identifier '10' (Table 4-39) is a key-transport key, and the NWK security procedure only ever runs the network key (4.3.1.1 step 2a)");

    frameLen = copyVector(frame, s_shortAuxHex);
    Test_Expect(frameLen == HEADER_LEN + 6 + PAYLOAD_LEN + 4,
           "the extended-nonce-0 frame carries 1 + 4 + 1 octets of auxiliary header: 6, not 14 (4.5.1.3)");

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_UNSUPPORTED,
                  "and it is refused too: without the source address there is no 13-octet nonce (4.5.2.2), and the shape is the IEEE 802.15.4-2024 one whose control bit 5 suppresses the frame counter, which is not transferable to a Zigbee NPDU");

    drainLog(&fixture.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_UNPROTECT_FAILED, LOG_REASON_ERROR, (uint32_t)ZB_ERR_UNSUPPORTED) == 1,
           "and each refusal is recorded with the status the caller was given");
}

/* Case 10, Table 4-38's authentication-only level 0x01 against s3: the payload travels in the clear,
   the MIC is the only thing the transform produced, and the MIC still gates everything. */
void caseMicOnlyLevel(void)
{
    Fixture fixture;
    Fixture untouched;
    Security_KeyDescriptor keys[1];
    Security_Result result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;

    keys[0] = keyAt(0x00, s_keyAHex, 7);
    fixtureAt(&fixture, SECURITY_LEVEL_MIC_32, OWN_IEEE, 0x00, keys, 1, 0, 0, 1);
    fixtureAt(&untouched, SECURITY_LEVEL_MIC_32, OWN_IEEE, 0x00, keys, 1, 0, 0, 1);

    Test_Expect(Security_IsEnabled(&fixture.security) == 1, "case 10: level 0x01 is a level this stack runs");

    frameLen = copyVector(frame, s_frame3Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "s3 unprotected at level 0x01: the payload is authenticated, not decrypted (4.3.1.2 step 4e, step 5b)");
    Test_ExpectHex("and the payload the module hands up is the frame's own octets, unchanged", plain, plainLen, s_payloadHex);
    Test_Expect(result.frameCounter == 7, "with the count the frame carried");

    frame[frameLen - 1] = (uint8_t)(frame[frameLen - 1] ^ 0x01);
    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);

    /* The tamper is offered to a second device of the same configuration, because 4.3.1.2 runs step 3's
       freshness before step 4's CCM: offered to the device above, the frame that this device has already
       accepted would be refused as a counter problem and the MIC would never be reached. */
    Test_ExpectStatus(Security_Unprotect(&untouched.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_AUTH,
                  "and a tampered MIC is refused as 'frame security failed': the payload of a MIC-only frame is right there in the octets, and it is not copied out when the 4-octet tag does not verify");
    Test_Expect(plain[0] == 0xa5, "the payload was not copied");
}

/* Case 11, the authenticated string in vector form: the auxiliary header sits after every NWK header field
   including a source route subframe, so a source-routed secured frame authenticates its route, and
   the same 16-octet header produces the s4 vector when the counter is the one s4 carried. */
void caseSourceRouteInsideTheAuthenticatedString(void)
{
    Fixture fixture;
    Security_KeyDescriptor keys[1];
    Security_Result result;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t headerLen;
    uint32_t plainLen;

    keys[0] = keyAt(0x00, s_keyAHex, 8);
    fixture5(&fixture, keys, 1, 0x00);

    headerLen = copyVector(header, s_routeHeaderHex);
    Test_Expect(headerLen == ROUTE_HEADER_LEN,
           "case 11: s4's NWK header is the eight always-present octets of 3.3.1.2 … 3.3.1.5 plus the source route subframe of 3.3.1.8, two octets of relay control and three two-octet relay addresses, 16 in all");

    frameLen = copyVector(frame, s_frame4Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, ROUTE_HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "s4 unprotected with headerLen 16: the route is inside NwkHeader and therefore inside the authenticated string");
    Test_ExpectHex("and its payload is the seven octets s4 carried", plain, plainLen, s_payloadHex);
    Test_Expect(result.frameCounter == 8 && result.senderIeee == OWN_IEEE, "with the count and the hop s4 names");

    copyVector(payload, s_payloadHex);

    Test_ExpectStatus(Security_Protect(&fixture.security, header, headerLen, payload, PAYLOAD_LEN,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "and composing the same header and payload with counter 0x00000008 gives the s4 frame");
    Test_Expect(frameLen == ROUTE_HEADER_LEN + SECURITY_AUX_LEN + PAYLOAD_LEN + 4,
           "41 octets: 16 header + 14 auxiliary + 7 payload + 4 MIC");
    Test_ExpectHex("case 11: the frame is the s4 vector octet for octet", frame, frameLen, s_frame4Hex);
}

/* A protect/unprotect pair at one level, between two devices of this PAN: the sender's own extended
   address and counter on the way out, the receiver's local level and stored window on the way in.
   No hex vector is quoted for levels 0x02, 0x06 and 0x07 because none exists in the corpus; a round
   trip proves the two halves of this module agree on the nonce, the authenticated string and the M
   split of 4.3.1.2 step 4d at those levels, which is all a suite can prove about a level no published
   frame covers: it is not a claim about what another vendor's device puts on the air. */
void roundTripAt(uint32_t level, uint32_t micLen, uint32_t payloadLen, const char *which)
{
    Fixture sender;
    Fixture receiver;
    Security_KeyDescriptor keys[1];
    Security_Result result;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t headerLen;
    uint32_t plainLen;
    uint32_t index;

    keys[0] = keyAt(0x00, s_keyAHex, 1);
    fixtureAt(&sender, level, OWN_IEEE, 0x00, keys, 1, 0, 0, 1);
    fixtureAt(&receiver, level, PEER_IEEE, 0x00, keys, 1, 0, 0, 1);

    headerLen = copyVector(header, s_headerHex);

    for (index = 0; index < payloadLen; index++)
        payload[index] = (uint8_t)(0x40 + index);

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);

    Test_ExpectStatus(Security_Protect(&sender.security, header, headerLen, payload, payloadLen,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "case 12: the frame protected at the level under test");
    Test_Expect(frameLen == headerLen + SECURITY_AUX_LEN + payloadLen + micLen,
           which);
    Test_Expect(frame[headerLen] == 0x28,
           "and the on-air security control carries no level at any level (4.3.1.1 step 8): M is decided locally in both directions");
    Test_Expect(frame[headerLen + SECURITY_AUX_LEN - 1] == 0x00,
           "with the key sequence number field of the active descriptor");

    Test_ExpectStatus(Security_Unprotect(&receiver.security, frame, frameLen, headerLen, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and the peer at the same level recovers it");
    Test_Expect(plainLen == payloadLen, "with the payload length the request asked for");
    Test_Expect(Zb_memcmp(plain, payload, payloadLen) == 0, "and the payload octet for octet");
    Test_Expect(result.senderIeee == OWN_IEEE, "and the hop identity the receiver recorded is the sender's extended address, not the peer's own (4.5.1.3)");
    Test_Expect(result.frameCounter == 1 && result.activeKeyAdopted == 0, "with the count and no key change");
}

/* Case 12, the other levels Table 4-38 offers, and the one thing the local level decides: a frame
   secured at level 0x06 does not verify at level 0x07, because M and the MIC split are what the
   receiving device's own nwkSecurityLevel says (4.3.1.2 step 1, step 4a, step 4d). */
void caseLevelsAndCrossLevel(void)
{
    Fixture sender;
    Fixture otherLevel;
    Security_KeyDescriptor keys[1];
    Security_Result result;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t headerLen;
    uint32_t plainLen;
    uint32_t index;

    roundTripAt(SECURITY_LEVEL_MIC_64, 8, PAYLOAD_LEN, "case 12: level 0x02 authenticates with M = 8, so the frame is 8 + 14 + 7 + 8 = 37 octets");
    roundTripAt(SECURITY_LEVEL_ENC_MIC_64, 8, PAYLOAD_LEN, "case 12: level 0x06 encrypts and authenticates with M = 8, the same length");
    roundTripAt(SECURITY_LEVEL_ENC_MIC_128, 16, PAYLOAD_LEN, "case 12: level 0x07 with M = 16, 45 octets");

    keys[0] = keyAt(0x00, s_keyAHex, 2);
    fixtureAt(&sender, SECURITY_LEVEL_ENC_MIC_64, OWN_IEEE, 0x00, keys, 1, 0, 0, 1);
    fixtureAt(&otherLevel, SECURITY_LEVEL_ENC_MIC_128, PEER_IEEE, 0x00, keys, 1, 0, 0, 1);

    headerLen = copyVector(header, s_headerHex);

    for (index = 0; index < LONG_PAYLOAD_LEN; index++)
        payload[index] = (uint8_t)(0x60 + index);

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    plainLen = 0;

    Test_ExpectStatus(Security_Protect(&sender.security, header, headerLen, payload, LONG_PAYLOAD_LEN,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "case 12: 32 octets protected at level 0x06");
    Test_Expect(frameLen == HEADER_LEN + SECURITY_AUX_LEN + LONG_PAYLOAD_LEN + 8,
           "the SecuredPayload region is 40 octets: 32 of ciphertext and an 8-octet MIC");

    Test_ExpectStatus(Security_Unprotect(&otherLevel.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_AUTH,
                  "the level-0x07 device that is handed it passes its own bounds (8 + 14 + 16 fits inside 62) splits the region as 24 octets plus a 16-octet tag and verifies nothing: the level is local, and a frame secured at another level is simply a frame this device cannot authenticate");
    Test_Expect(plainLen == 0, "and no plaintext length is reported");

    Test_ExpectStatus(Security_Unprotect(&otherLevel.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_AUTH,
                  "again, the same refusal and not a frame-counter one: the failed frame stored no window (4.3.1.2 step 6 after step 5a)");
}

/* Case 13, Table 4-38's third authentication-only level: 0x03 is MIC-128, the M = 16 the encrypting
   level 0x07 pays for as well, and the one honoured level this suite had no case of its own for. No hex
   vector is quoted because the corpus prints no secured NWK frame at any level: what a round trip proves
   here is that this module's two halves agree on the Encryption-Off column of Table 4-38 and on the M
   split of 4.3.1.2 step 4d at 0x03, which is all a suite can prove about a level no published frame
   covers. */
void caseMic128Level(void)
{
    Fixture fixture;
    Fixture untouched;
    Security_KeyDescriptor keys[1];
    Security_Result result;
    Security_KeyState state;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t pristine[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t headerLen;
    uint32_t plainLen;

    keys[0] = keyAt(0x00, s_keyAHex, 1);
    fixtureAt(&fixture, SECURITY_LEVEL_MIC_128, OWN_IEEE, 0x00, keys, 1, 0, 0, 1);
    fixtureAt(&untouched, SECURITY_LEVEL_MIC_128, PEER_IEEE, 0x00, keys, 1, 0, 0, 1);

    Test_Expect(Security_IsEnabled(&fixture.security) == 1, "case 13: level 0x03 is a level this stack runs (Table 4-38)");
    Test_Expect(Security_Level(&fixture.security) == SECURITY_LEVEL_MIC_128, "and the module says which level it is running");

    headerLen = copyVector(header, s_headerHex);
    copyVector(payload, s_payloadHex);

    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);
    plainLen = 0;

    Test_ExpectStatus(Security_Protect(&fixture.security, header, headerLen, payload, PAYLOAD_LEN,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "case 13: the seven octets s3's payload carries, protected at level 0x03");
    Test_Expect(frameLen == HEADER_LEN + SECURITY_AUX_LEN + PAYLOAD_LEN + SECURITY_MIC_MAX,
           "the frame is 8 + 14 + 7 + 16 = 45 octets, the same total level 0x07 makes with an encrypting level");
    Test_Expect(Zb_memcmp(frame, header, HEADER_LEN) == 0, "the NWK header is the octets it was composed as");
    Test_Expect(frame[HEADER_LEN] == 0x28,
           "and the on-air security control carries no level at this level either (4.3.1.1 step 8): a MIC-128 frame is told from a MIC-32 one by what closes it, never by the octets it begins with");
    Test_Expect(frame[HEADER_LEN + SECURITY_AUX_LEN - 1] == 0x00,
           "with the key sequence number field of the active descriptor");
    Test_Expect(Zb_memcmp(frame + HEADER_LEN + SECURITY_AUX_LEN, payload, PAYLOAD_LEN) == 0,
           "and the payload is right there in the frame's octets, unencrypted: Table 4-38 sets Encryption Off for level 0x03, so the payload travels inside the authenticated string (4.3.1.1 step 3d, step 5)");
    Test_Expect(frameLen - (HEADER_LEN + SECURITY_AUX_LEN + PAYLOAD_LEN) == SECURITY_MIC_MAX,
           "and what follows it is a 16-octet MIC: the M Table 4-38 gives this level");

    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.outgoingFrameCounter[0] == 2,
           "and the descriptor moved from 1 to 2 for the frame it produced (4.3.1.1 step 7)");

    Zb_memcpy(pristine, frame, frameLen);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and the device that sent it reads it back: M and the split of the SecuredPayload region come from its own nwkSecurityLevel (4.3.1.2 step 1, step 4a)");
    Test_ExpectHex("case 13: the payload it hands up is the same seven octets", plain, plainLen, s_payloadHex);
    Test_Expect(plainLen == PAYLOAD_LEN, "with the auxiliary header and the tag gone (4.3.1.2 step 5b)");
    Test_Expect(result.senderIeee == OWN_IEEE,
           "and the hop identity is this device's own extended address, because this device is the one that secured the frame (4.5.1.3)");
    Test_Expect(result.frameCounter == 1 && result.activeKeyAdopted == 0, "with the count the frame carried and no key change");

    frame[frameLen - 1] = (uint8_t)(frame[frameLen - 1] ^ 0xff);
    Zb_memset(plain, 0xa5, (uint32_t)sizeof plain);

    /* The tamper goes to a second device of the same configuration that has stored no window yet: 4.3.1.2
       runs step 3's freshness before step 4's CCM, and the device above now holds a window of 2 for this
       sender, so a repeat of count 1 there would be a frame-counter refusal that never reaches the tag. */
    Test_ExpectStatus(Security_Unprotect(&untouched.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_AUTH,
                  "case 13: the frame with one tag octet flipped is 4.3.1.2 step 5a's 'frame security failed', at a level whose whole answer is that tag; the tamper is the failure itself");
    Test_Expect(plain[0] == 0xa5,
           "and nothing was written for it, although the plaintext is sitting in the frame's own octets for the whole world to read (Annex A.4)");

    Zb_memcpy(frame, pristine, frameLen);

    Test_ExpectStatus(Security_Unprotect(&untouched.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "which is known because the pristine frame at the same count authenticates there: a frame that did not authenticate stored no counter, so step 6 never ran for it");
    Test_Expect(result.senderIeee == OWN_IEEE && result.frameCounter == 1,
           "with the hop, the key and the count the frame named to a device that is not the one that wrote it");

    Test_ExpectStatus(Security_Unprotect(&untouched.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_BAD_FRAME_COUNTER,
                  "and the same frame a third time is the freshness refusal rather than the tag one: the copy that authenticated stored 2, so 1 is now smaller (4.3.1.2 steps 3 and 6)");

    drainLog(&untouched.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_UNPROTECT_FAILED, LOG_REASON_ERROR, (uint32_t)ZB_ERR_AUTH) == 1,
           "and the tag refusal is a record in that device's pool (docs/internals/coding-rules.md §5)");
}

/* Case 14, what Security_Init refuses, and what a level-0x00 device is. */
void caseInitRefusals(void)
{
    Security security;
    Security_Config cfg;
    Security_KeyDescriptor keys[3];
    Security_IncomingEntry windows[SECURITY_INCOMING_MAX + 1];
    Security_KeyState state;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint32_t headerLen;
    uint32_t index;
    uint32_t frameLen;
    uint32_t plainLen;

    keys[0] = keyAt(0x00, s_keyAHex, 1);
    keys[1] = keyAt(0x01, s_keyBHex, 1);
    keys[2] = keyAt(0x02, s_keyBHex, 1);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = OWN_IEEE;
    cfg.nwkActiveKeySeqNumber = 0x00;
    cfg.authenticated = 1;
    cfg.nwkAllFresh = 1;
    cfg.keys = keys;
    cfg.keyCount = 1;

    Test_ExpectStatus(Security_Init(0, &cfg), ZB_ERR_BAD_ARGUMENT, "case 14: a 0 module is a bad argument");

    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC;
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_ERR_BAD_ARGUMENT,
                  "and level 0x04 is refused: M = 0 is inexpressible at the CCM* seam (802.15.4-2024 9.4.2.2)");

    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.nwkActiveKeySeqNumber = 0x07;
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_ERR_BAD_ARGUMENT,
                  "and a level that runs with no descriptor under the active key sequence number is a configuration error, not the runtime 'no key' of 4.3.1.1 step 1");

    cfg.nwkActiveKeySeqNumber = 0x00;
    cfg.keyCount = 3;
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_ERR_BAD_ARGUMENT,
                  "and three descriptors are more than the set of 2 Table 4-2 prints");

    cfg.keyCount = 2;
    keys[1] = keyAt(0x00, s_keyBHex, 1);
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_ERR_BAD_ARGUMENT,
                  "and two descriptors naming the same key sequence number are refused too: nwkActiveKeySeqNumber would select neither");

    keys[1] = keyAt(0x01, s_keyBHex, 1);
    cfg.incomingSeedCount = SECURITY_INCOMING_MAX + 1;
    cfg.incomingSeeds = windows;

    for (index = 0; index < SECURITY_INCOMING_MAX + 1; index++)
        windows[index] = windowAt(SEEDED_IEEE + index, 0x00, 1);

    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_ERR_BAD_ARGUMENT,
                  "and 33 incoming windows do not fit the pool 4.3.1.2 step 6 bounds at M × N = 2 × 16 = 32");

    cfg.incomingSeedCount = 2;
    windows[0] = windowAt(SEEDED_IEEE, 0x00, 1);
    windows[1] = windowAt(SEEDED_IEEE, 0x00, 2);
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_ERR_BAD_ARGUMENT,
                  "and a seed list that names one (sender, key) pair twice is refused rather than given to this sender twice");

    cfg.incomingSeedCount = 0;
    cfg.incomingSeeds = 0;
    cfg.keyCount = 0;
    cfg.keys = 0;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_NONE;
    Test_ExpectStatus(Security_Init(&security, &cfg), ZB_OK,
                  "case 14: level 0x00 with no keys at all is the scaffold `nwk` runs on today, and it initialises");
    Test_Expect(Security_IsEnabled(&security) == 0, "which says so");
    Test_Expect(Security_Level(&security) == 0, "with no level to name");
    Test_Expect(Security_IsAuthenticated(&security) == 1, "and still states the joined flag the 3.6.2.2 policy reads");

    headerLen = copyVector(header, s_headerHex);
    copyVector(payload, s_payloadHex);

    Test_ExpectStatus(Security_Protect(&security, header, headerLen, payload, PAYLOAD_LEN,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_ERR_UNSUPPORTED,
                  "and there is no protection to run at level 0x00: the NWK composes an unsecured NPDU and never calls here");

    frameLen = copyVector(frame, s_frame1Hex);

    Test_ExpectStatus(Security_Unprotect(&security, frame, frameLen, HEADER_LEN, payload,
                                    (uint32_t)sizeof payload, &plainLen, 0), ZB_ERR_UNSUPPORTED,
                  "and there is no unprotect to run either");

    Security_Snapshot(&security, &state);
    Test_Expect(state.keyCount == 0 && state.nwkActiveKeySeqNumber == 0, "and a module with no keys snapshots as nothing");
}

/* Case 15, the incoming store at its bound and the two answers 4.3.1.2 step 6 gives. */
void caseIncomingPoolFull(void)
{
    Fixture full;
    Fixture inPlace;
    Fixture notAllFresh;
    Security_KeyDescriptor keys[1];
    Security_IncomingEntry windows[SECURITY_INCOMING_MAX];
    Security_Result result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t plain[SECURITY_FRAME_MAX];
    uint32_t frameLen;
    uint32_t plainLen;
    uint32_t index;

    keys[0] = keyAt(0x00, s_keyAHex, 5);

    for (index = 0; index < SECURITY_INCOMING_MAX; index++)
        windows[index] = windowAt(SEEDED_IEEE + index, 0x00, 1);

    fixtureAt(&full, SECURITY_LEVEL_ENC_MIC_32, OWN_IEEE, 0x00, keys, 1, windows, SECURITY_INCOMING_MAX, 1);

    frameLen = copyVector(frame, s_frame1Hex);

    Test_ExpectStatus(Security_Unprotect(&full.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_NO_SPACE,
                  "case 15: 32 windows held and a 33rd sender's frame authenticates, the store cannot take it, nwkAllFresh is TRUE, so 4.3.1.2 step 6 fails the frame after its MIC verified");

    drainLog(&full.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_INCOMING_FULL, LOG_REASON_DROPPED, SECURITY_INCOMING_MAX) == 1,
           "and the pool refusal is recorded with the bound it hit");

    windows[SECURITY_INCOMING_MAX - 1] = windowAt(OWN_IEEE, 0x00, 4);
    fixtureAt(&inPlace, SECURITY_LEVEL_ENC_MIC_32, OWN_IEEE, 0x00, keys, 1, windows, SECURITY_INCOMING_MAX, 1);

    frameLen = copyVector(frame, s_frame1Hex);

    Test_ExpectStatus(Security_Unprotect(&inPlace.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "an existing sender's window in a full pool still updates in place, which is all step 6 asks of a full pool");
    Test_Expect(plainLen == PAYLOAD_LEN, "with the payload handed up");

    frameLen = copyVector(frame, s_frame1Hex);

    Test_ExpectStatus(Security_Unprotect(&inPlace.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_ERR_BAD_FRAME_COUNTER,
                  "and the in-place update really happened: the stored window is 6 now, so 5 is smaller and refused");

    windows[SECURITY_INCOMING_MAX - 1] = windowAt(SEEDED_IEEE + SECURITY_INCOMING_MAX - 1, 0x00, 1);
    fixtureAt(&notAllFresh, SECURITY_LEVEL_ENC_MIC_32, OWN_IEEE, 0x00, keys, 1, windows, SECURITY_INCOMING_MAX, 0);

    frameLen = copyVector(frame, s_frame1Hex);

    Test_ExpectStatus(Security_Unprotect(&notAllFresh.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "with nwkAllFresh FALSE the same frame is accepted out of a full pool and simply not recorded: no clause states an eviction policy and this stack makes no eviction the rule");

    frameLen = copyVector(frame, s_frame1Hex);

    Test_ExpectStatus(Security_Unprotect(&notAllFresh.security, frame, frameLen, HEADER_LEN, plain,
                                    (uint32_t)sizeof plain, &plainLen, &result), ZB_OK,
                  "and the identical frame again: an unrecorded frame left no window, which is what makes 'not recorded' a fact a suite can read rather than a claim");
}

/* Case 16, the wipe duty: Security_Reset leaves no key octet, no counter and no scratch. */
void caseResetWipesEverything(void)
{
    Fixture fixture;
    Security_KeyDescriptor keys[2];
    Security expected;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint32_t headerLen;
    uint32_t frameLen;

    keys[0] = keyAt(0x00, s_keyAHex, 5);
    keys[1] = keyAt(0x01, s_keyBHex, 5);
    fixture5(&fixture, keys, 2, 0x00);

    headerLen = copyVector(header, s_headerHex);
    copyVector(payload, s_payloadHex);

    Test_ExpectStatus(Security_Protect(&fixture.security, header, headerLen, payload, PAYLOAD_LEN,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "case 16: a protection first, so the module holds round keys, a moved counter and a frame in its scratch");

    Security_Reset(&fixture.security);

    Zb_memset(&expected, 0, (uint32_t)sizeof expected);
    expected.trustCenterIeee = 0xffffffffffffffff;

    Test_Expect(Zb_memcmp(&fixture.security, &expected, (uint32_t)sizeof expected) == 0,
           "and every octet of the struct is zero after Security_Reset but for apsTrustCenterAddress, which 4.6.3.1 starts all-F: both key descriptors including their 16-octet keys, both counters, the incoming store, the level, the identity and the scratch buffers");
    Test_Expect(Security_IsEnabled(&fixture.security) == 0, "which leaves a module that does no security at all");

    Test_ExpectStatus(Security_Protect(&fixture.security, header, headerLen, payload, PAYLOAD_LEN,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_ERR_UNSUPPORTED,
                  "and a wiped module refuses rather than running on zeroed keys");
}

/* Case 17, the two capacity refusals, and what neither of them consumes. */
void caseCapacityRefusals(void)
{
    Fixture fixture;
    Security_KeyDescriptor keys[1];
    Security_IncomingEntry windows[1];
    Security_Result result;
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t out[SECURITY_FRAME_MAX];
    Security_KeyState state;
    uint32_t frameLen;
    uint32_t headerLen;
    uint32_t index;
    uint32_t plainLen;

    keys[0] = keyAt(0x00, s_keyAHex, 5);
    windows[0] = windowAt(OWN_IEEE, 0x00, 1);
    fixtureAt(&fixture, SECURITY_LEVEL_ENC_MIC_32, OWN_IEEE, 0x00, keys, 1, windows, 1, 1);

    headerLen = copyVector(header, s_headerHex);
    copyVector(payload, s_payloadHex);
    Zb_memset(out, 0x5a, (uint32_t)sizeof out);

    plainLen = 0;

    Test_ExpectStatus(Security_Protect(&fixture.security, header, headerLen, payload, PAYLOAD_LEN,
                                  out, HEADER_LEN + SECURITY_AUX_LEN + PAYLOAD_LEN + 4 - 1, &frameLen), ZB_ERR_NO_SPACE,
                  "case 17: a caller with one octet too little room gets NO_SPACE and no frame");
    Test_Expect(out[0] == 0x5a, "and its buffer was not half-written into");

    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.outgoingFrameCounter[0] == 5, "and the counter did not move: 4.3.1.1 step 7 runs for a frame that became the secured frame");

    frameLen = copyVector(frame, s_frame1Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen - 8, HEADER_LEN, out,
                                    (uint32_t)sizeof out, &plainLen, &result), ZB_ERR_BAD_ARGUMENT,
                  "case 17: a secured frame truncated by eight octets is 25 long, shorter than 8 + 14 + 4, so 4.3.1.2 step 4d has nothing to split, the bounds gate is a bad argument, before any key, window or MIC is consulted");

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN + 12, out,
                                    (uint32_t)sizeof out, &plainLen, &result), ZB_ERR_BAD_ARGUMENT,
                  "and a header length the frame cannot carry (20 named header octets inside 33 with 14 auxiliary octets to fit) is the same refusal");

    frameLen = copyVector(frame, s_frame1Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, out,
                                    PAYLOAD_LEN - 1, &plainLen, &result), ZB_ERR_NO_SPACE,
                  "and a caller with too little room for the payload gets NO_SPACE: with nothing committed, because a frame this module cannot hand over must not burn the window of the sender that sent it");

    Test_Expect(plainLen == 0, "and no payload length was reported for the frame that had no room");

    frameLen = copyVector(frame, s_frame1Hex);
    rewriteCounter(frame, HEADER_LEN, 1);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, out,
                                    (uint32_t)sizeof out, &plainLen, &result), ZB_ERR_AUTH,
                  "which the refusal is proved by asking about a smaller count: the stored window is still the seeded 1, so a count of 1 is not 'bad' and the frame reaches the MIC, which it cannot pass. A window burned to 6 by the refused frame would have answered BAD_FRAME_COUNTER here");

    frameLen = copyVector(frame, s_frame1Hex);

    Test_ExpectStatus(Security_Unprotect(&fixture.security, frame, frameLen, HEADER_LEN, out,
                                    (uint32_t)sizeof out, &plainLen, &result), ZB_OK,
                  "and the s1 frame that was refused for want of room is acceptable with room for it, at 5 against a stored window of 1");
    Test_ExpectHex("with its payload intact", out, plainLen, s_payloadHex);

    for (index = 0; index < LONG_PAYLOAD_LEN; index++)
        payload[index] = (uint8_t)(0x80 + index);

    Test_ExpectStatus(Security_Protect(&fixture.security, header, headerLen, payload, LONG_PAYLOAD_LEN,
                                  out, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                  "and a long payload at level 0x05 still composes: 8 + 14 + 32 + 4 = 58 octets, inside the band's ceiling");

    Test_ExpectStatus(Security_Protect(&fixture.security, header, headerLen, payload, 106,
                                  out, SECURITY_FRAME_MAX, &frameLen), ZB_ERR_NO_SPACE,
                  "while 8 + 14 + 106 + 4 = 132 octets is refused at composition (4.3.1.1 step 6 with its ceiling)");

    Security_Snapshot(&fixture.security, &state);
    Test_Expect(state.outgoingFrameCounter[0] == 6, "and only the frame that fitted moved the counter: 5 to 6, the refused one not at all");

    drainLog(&fixture.log);
    Test_Expect(logHas(LOG_COMP_SECURITY_FRAME_TOO_LONG, LOG_REASON_DROPPED, 132) == 1,
           "recorded with the length it would have been");
}
