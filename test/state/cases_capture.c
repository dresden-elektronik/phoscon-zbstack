/* The `state` suite's capture half: cases 1-5, the object a stack fills and what its counts and tails mean.
   See `state_cases.h` for the case list and `state_helpers.h` for the machinery. */

#include "state_cases.h"
#include "state_helpers.h"

#include "zb_utils.h"

/* The NWK header and payload of the s1 frame this suite's `security` vector is quoted with: FCF 0x0208
   (frame type Data, protocol version 0x02 and the security sub-field), destination 0x0001, source 0x0000,
   radius 0x1e, sequence number 0x05, and a 7-octet NSDU. */
static const char *s_header1Hex = "0802010000001e05";
static const char *s_payloadHex = "40414243444546";

void caseCaptureFresh(void)
{
    StateDevice dev;
    Zb_State state;
    Zb_State withKeys;
    uint8_t key[SECURITY_KEY_OCTETS];
    uint32_t keyLen;

    stateBuild(&dev);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 1: a freshly initialised stack is captured with includeKeys 0, the default a state is taken with");

    Test_ExpectCount(state.version, ZB_STATE_VERSION, "and the object names the schema it was made by");
    Test_Expect(state.ownIeee == STATE_OWN_IEEE,
                "with this device's extended address, which every auxiliary header it composes carries (3.2.1.1.3)");
    Test_Expect(state.nwkSecurityLevel == SECURITY_LEVEL_ENC_MIC_32,
                "and nwkSecurityLevel as the module holds it, Table 4-2's default 0x05");
    Test_Expect(state.nwkActiveKeySeqNumber == 0x00, "and nwkActiveKeySeqNumber");
    Test_Expect(state.authenticated == 1 && state.nwkAllFresh == 1,
                "and the two flags as the application set them: the joined bit and nwkAllFresh are configuration, never inferred from traffic");

    Test_ExpectCount(state.keyCount, 1, "one descriptor, which is the whole of the material set this device holds");
    Test_Expect(state.keys[0].keySeqNumber == 0x00 && state.keys[0].outgoingFrameCounter == 5,
                "naming Table 4-3's KeySeqNumber and the counter 4.3.1.1 step 7 moves");
    Test_Expect(state.keys[0].keyPresent == 0,
                "and no key: includeKeys 0 is the harmless artefact, the one that may sit in plain flash");
    Test_Expect(stateIsZero(state.keys[0].key, SECURITY_KEY_OCTETS),
                "with its 16 octets zero rather than unset or left as whatever the caller's object held");
    Test_ExpectCount(state.windowCount, 0, "no incoming window on a module that has heard nothing");
    Test_ExpectCount(state.pairCount, 0, "and no key pair: this device runs NWK security and no link-key crossing");

    Test_ExpectCount(state.nwkSequenceNumber, 0, "nwkSequenceNumber is the seed the application gave the rig (Table 3-66)");
    Test_ExpectCount(state.macDsn, 0, "and so is the MAC's DSN (Mac_Config.dsnStart)");
    Test_ExpectCount(state.apsCounter, 0, "and the APS counter is at APS_COUNTER_START, no transaction having run");
    Test_ExpectCount(state.panId, STATE_PAN_ID, "3.6.9's SHOULD list: the PAN identifier the MAC's PIB holds");
    Test_ExpectCount(state.networkAddress, STATE_OWN_SHORT, "and this device's own network address");
    Test_ExpectCount(state.parentInformation, 0, "and the parent information a device with no parent carries at 0");
    Test_ExpectCount(state.childCount, 0, "3.6.9's child list is empty: this device has no end device under it");

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 1, &withKeys), ZB_OK,
                      "the same stack captured with includeKeys 1");
    Test_Expect(withKeys.keys[0].keyPresent == 1, "carries the key it was configured with");

    keyLen = stateKeyOf(s_keyAHex, key);

    Test_ExpectOctets("and its 16 octets are key A: with keyPresent 1 the key travels in the object and protecting it is the application's duty",
                      withKeys.keys[0].key, SECURITY_KEY_OCTETS, key, keyLen);

    stateSend(&dev);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "and once one frame has gone out through the NLDE");
    Test_ExpectCount(state.nwkSequenceNumber, 1, "the NWK sequence number the capture reports is the one the next frame will carry: traffic, not a seed");
    Test_ExpectCount(state.macDsn, 1, "and the MAC's DSN moved with the frame that carried it");
    Test_ExpectCount(state.apsCounter, 0, "while the APS counter, which no APS transaction has moved, is still where it started");
}

void caseCaptureCounts(void)
{
    StateDevice dev;
    Security_KeyDescriptor keys[1];
    Security_IncomingEntry windows[2];
    Security_KeyPairEntry pairs[1];
    Zb_State state;

    keys[0] = stateKeyAt(0x00, s_keyAHex, 5);
    windows[0] = stateWindowAt(STATE_SECOND_IEEE, 0x00, 7);
    windows[1] = stateWindowAt(STATE_THIRD_IEEE, 0x00, 9);
    pairs[0] = statePairAt(STATE_PEER_IEEE, s_linkKeyHex, 0x10, 0x20);

    stateBuildWith(&dev, keys, 1, windows, 2, pairs, 1);

    /* The object arrives full of something that is not a state, which is what a caller's buffer may hold. */
    Zb_memset(&state, 0xff, (uint32_t)sizeof state);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 2: a device holding one descriptor, two windows and one key pair is captured over an object prefilled with 0xff");

    Test_ExpectCount(state.keyCount, 1, "the count is the content: one descriptor");
    Test_ExpectCount(state.windowCount, 2, "two windows");
    Test_ExpectCount(state.pairCount, 1, "one key pair");

    Test_Expect(state.keys[1].keySeqNumber == 0 && state.keys[1].outgoingFrameCounter == 0
                && state.keys[1].keyPresent == 0 && stateIsZero(state.keys[1].key, SECURITY_KEY_OCTETS),
                "and every entry past a count is zero rather than the caller's 0xff: capture zeroes the whole object first, so a whole-array round trip is garbage-free");
    Test_Expect(state.windows[2].senderIeee == 0 && state.windows[2].frameCounter == 0
                && state.windows[SECURITY_INCOMING_MAX - 1].senderIeee == 0,
                "the window tail down to the last slot of the 32-entry pool is zero");
    Test_Expect(state.pairs[1].deviceIeee == 0 && state.pairs[1].outgoingFrameCounter == 0
                && stateIsZero(state.pairs[1].linkKey, SECURITY_KEY_OCTETS),
                "and so is the key-pair tail, link key included");

    Test_Expect(state.windows[0].senderIeee == STATE_SECOND_IEEE && state.windows[0].frameCounter == 7
                && state.windows[1].senderIeee == STATE_THIRD_IEEE && state.windows[1].frameCounter == 9,
                "with the two windows in pool order, each carrying ReceivedFrameCount + 1 as 4.3.1.2 step 6 stores it");
    Test_Expect(state.pairs[0].deviceIeee == STATE_PEER_IEEE
                && state.pairs[0].linkKeyType == SECURITY_LINK_KEY_UNIQUE
                && state.pairs[0].keyAttributes == SECURITY_KEYPAIR_ATTR_VERIFIED
                && state.pairs[0].keyPresent == 0,
                "and the pair's Table 4-36 fields, its outgoing counter and no link key: 4.4.12.1 persists no incoming one");
}

void caseArgumentRefusals(void)
{
    StateDevice dev;
    Zb_State state;
    uint8_t image[sizeof(Security)];

    stateBuild(&dev);
    Zb_memset(&state, 0xff, (uint32_t)sizeof state);

    Test_ExpectStatus(Zb_StateCapture(0, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_ERR_BAD_ARGUMENT,
                      "case 3: a capture with no security module is refused");
    Test_ExpectStatus(Zb_StateCapture(&dev.security, 0, &dev.aps, &dev.rig.mac, 0, &state), ZB_ERR_BAD_ARGUMENT,
                      "and one with no network layer: the four layers are the whole of what a state is made of, so a missing one is not a partial state");
    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, 0, &dev.rig.mac, 0, &state), ZB_ERR_BAD_ARGUMENT,
                      "and one with no APS service");
    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, 0, 0, &state), ZB_ERR_BAD_ARGUMENT,
                      "and one with no MAC");
    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, 0), ZB_ERR_BAD_ARGUMENT,
                      "and one with nowhere to write the object");
    Test_ExpectCount(state.version, 0xffffffff,
                     "and a refused capture writes nothing at all: the object is still the caller's 0xff, not a half-filled state");

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "a state captured to drive the other half");

    stateImage(&dev.security, image);

    Test_ExpectStatus(Zb_StateRestore(0, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and a restore with no security module is refused");
    Test_ExpectStatus(Zb_StateRestore(&dev.security, 0, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and one with no network layer");
    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, 0, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and one with no APS service");
    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, 0, &state), ZB_ERR_BAD_ARGUMENT,
                      "and one with no MAC");
    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0), ZB_ERR_BAD_ARGUMENT,
                      "and one with no state to read");
    Test_Expect(stateImageHeld(&dev.security, image),
                "and not one of those refusals wrote a byte into the security module, nor into the three counters of the layers beside it");
}

void caseRoundTrip(void)
{
    StateDevice dev;
    Security_KeyDescriptor keys[1];
    Security_IncomingEntry windows[1];
    Security_KeyPairEntry pairs[1];
    Security_KeyState snapshot;
    Zb_State captured;
    Zb_State after;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t key[SECURITY_KEY_OCTETS];
    uint8_t linkKey[SECURITY_KEY_OCTETS];
    uint32_t headerLen;
    uint32_t payloadLen;
    uint32_t frameLen;
    uint32_t plainLen;
    uint32_t keyLen;
    uint32_t linkKeyLen;

    keys[0] = stateKeyAt(0x00, s_keyAHex, 5);
    windows[0] = stateWindowAt(STATE_SECOND_IEEE, 0x00, 7);
    pairs[0] = statePairAt(STATE_PEER_IEEE, s_linkKeyHex, 0x10, 0x20);

    stateBuildWith(&dev, keys, 1, windows, 1, pairs, 1);
    stateSend(&dev);
    dev.aps.apsCounter = 0x11;

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &captured), ZB_OK,
                      "case 4: a device that holds a descriptor, a window and a key pair, has sent a frame and numbered an APS transaction is captured");

    headerLen = Test_ParseHex(s_header1Hex, header, SECURITY_FRAME_MAX);
    payloadLen = Test_ParseHex(s_payloadHex, payload, SECURITY_FRAME_MAX);

    Test_ExpectStatus(Security_Protect(&dev.security, header, headerLen, payload, payloadLen,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_OK,
                      "then the stack is disturbed: a protection moves the descriptor's outgoing counter (4.3.1.1 step 7)");

    frameLen = Test_ParseHex(s_frame1Hex, frame, SECURITY_FRAME_MAX);

    Test_ExpectStatus(Security_Unprotect(&dev.security, frame, frameLen, headerLen, payload,
                                    SECURITY_FRAME_MAX, &plainLen, 0), ZB_OK,
                      "and an accepted s1 frame stores an incoming window under the auxiliary source address it carried (4.3.1.2 step 6)");
    stateSend(&dev);

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &captured), ZB_OK,
                      "case 4: and the captured state is restored over that device");

    Security_Snapshot(&dev.security, &snapshot);

    Test_Expect(snapshot.keyCount == 1 && snapshot.keySeqNumber[0] == 0x00,
                "the material set is the one the state named, and the descriptor the disturbed boot's protection used is gone");
    Test_ExpectCount(snapshot.outgoingFrameCounter[0], 6 + ZB_STATE_COUNTER_BANK,
                     "with its counter past both the 5 the state stored and the 6 the disturbing protection left behind, by the bank: 9.2.4 refuses a smaller counter and forbids the reuse");

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &after), ZB_OK,
                      "and the module answers a capture again");
    Test_ExpectCount(after.windowCount, 1,
                     "with exactly the windows the state carried: the one the disturbed boot gathered is not there, because a restore wipes before it fills");
    Test_Expect(after.windows[0].senderIeee == STATE_SECOND_IEEE && after.windows[0].frameCounter == 7,
                "and it is the window the state named, at the counter it named: a receiver's window is not a nonce this device transmits with, so it is restored as it stands");
    Test_ExpectCount(after.pairCount, 1, "and the key pair came back");
    Test_Expect(after.pairs[0].deviceIeee == STATE_PEER_IEEE && dev.security.keyPairs[0].incomingFrameCounter == 0,
                "with its IncomingFrameCounter at 0, the value a reboot sets (4.6.3.8): 4.4.12.1 does not persist it");

    Test_ExpectCount(after.nwkSequenceNumber, (captured.nwkSequenceNumber + 1) % NWK_SEQ_WRAP,
                     "nwkSequenceNumber lands one past the stored octet: 256 modulo the wrap is 0, so one is the whole of what an octet can be advanced by");
    Test_ExpectCount(after.macDsn, (captured.macDsn + 1) % MAC_DSN_WRAP, "and the MAC's DSN the same way");
    Test_ExpectCount(after.apsCounter, (captured.apsCounter + 1) % APS_COUNTER_WRAP, "and the APS counter, which wraps at 256 too");

    keyLen = stateKeyOf(s_keyAHex, key);
    linkKeyLen = stateKeyOf(s_linkKeyHex, linkKey);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 1, &after), ZB_OK,
                      "and a capture that asks for the keys proves what the counters-only state left in place");
    Test_ExpectOctets("the key is the one this boot was configured with, although the state carried none (the opt-in)",
                      after.keys[0].key, SECURITY_KEY_OCTETS, key, keyLen);
    Test_ExpectOctets("and so is the link key of the pair it did not carry",
                      after.pairs[0].linkKey, SECURITY_KEY_OCTETS, linkKey, linkKeyLen);
}

void caseCountsAuthoritative(void)
{
    StateDevice dev;
    Zb_State state;
    uint8_t image[sizeof(Security)];
    uint32_t index;

    stateBuild(&dev);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 5: a state captured from a device holding one descriptor and no window");

    stateImage(&dev.security, image);

    state.keyCount = SECURITY_KEY_SET_MAX + 1;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and a keyCount above the compile-time set is refused rather than truncated: a state from a build with larger pools must fail loudly instead of silently dropping a descriptor");
    Test_Expect(stateImageHeld(&dev.security, image),
                "with the module byte-identical (pools, counters, scratch, level, identity and record pool) because the count is judged before the first write");

    state.keyCount = 1;
    state.windowCount = SECURITY_INCOMING_MAX + 1;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and a windowCount above the 32-entry store is the same refusal: a silently dropped replay window is the one failure this boundary exists to prevent");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    state.windowCount = 0;
    state.pairCount = SECURITY_KEYPAIR_MAX + 1;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and a pairCount above the key-pair pool");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched either");

    state.pairCount = 0;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "and the same state with its counts back inside the bounds restores: what was refused was the count, not the state");

    /* A state from a build with a larger store, as the format allows it: the 32-entry store is full and
       one more window is named, so the count is the only thing that can stop the 33rd entry from being read
       at all. Everything else about this state is well formed, which is what makes the count the claim. */
    Zb_memset(&state, 0, (uint32_t)sizeof state);
    state.version = ZB_STATE_VERSION;
    state.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    state.keys[0].keySeqNumber = 0x00;
    state.keys[0].outgoingFrameCounter = 5;
    state.keyCount = 1;

    for (index = 0; index < SECURITY_INCOMING_MAX; index++)
    {
        state.windows[index].senderIeee = STATE_SECOND_IEEE + index;
        state.windows[index].keySeqNumber = 0x00;
        state.windows[index].frameCounter = index + 1;
    }

    state.windowCount = SECURITY_INCOMING_MAX + 1;
    state.pairs[0].deviceIeee = STATE_PEER_IEEE;
    state.pairs[0].keyAttributes = SECURITY_KEYPAIR_ATTR_VERIFIED;
    state.pairs[0].linkKeyType = SECURITY_LINK_KEY_UNIQUE;
    state.pairCount = 1;

    stateImage(&dev.security, image);

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and a state whose store is full at 32 and names one window more is refused, with every one of its 32 entries well formed: the bound is the count's and not the entries'");
    Test_Expect(stateImageHeld(&dev.security, image),
                "with the module byte-identical, and with the 33rd entry never read: a state from a build with a larger pool fails at the count");
}
