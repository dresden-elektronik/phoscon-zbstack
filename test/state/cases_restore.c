/* The `state` suite's restore half: cases 6-14 and 16-18, the rules binding on the way back in,
   content-addressing, validation before the first write, the counter bank, the opt-in on key material, and
   what a restore deliberately leaves alone. See `state_cases.h` for the case list. */

#include "state_cases.h"
#include "state_helpers.h"

#include "nwk_rreq.h"
#include "zb_utils.h"

/* The NWK header and payload of the `security` suite's s1 frame: what a protection in this half of the suite
   runs over when the claim is about the key rather than about the frame. */
static const char *s_header1Hex = "0802010000001e05";
static const char *s_payloadHex = "40414243444546";

void caseIdentityNotIndex(void)
{
    StateDevice dev;
    Security_KeyDescriptor keys[2];
    Security_IncomingEntry windows[2];
    Security_KeyState snapshot;
    Zb_State state;
    Zb_State after;
    Zb_StateKey keySwap;
    Zb_StateWindow windowSwap;

    keys[0] = stateKeyAt(0x00, s_keyAHex, 5);
    keys[1] = stateKeyAt(0x01, s_keyBHex, 11);
    windows[0] = stateWindowAt(STATE_SECOND_IEEE, 0x00, 7);
    windows[1] = stateWindowAt(STATE_THIRD_IEEE, 0x00, 9);
    stateBuildWith(&dev, keys, 2, windows, 2, 0, 0);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 6: two descriptors and two windows are captured");

    /* An application that keeps its own lists is free to hand them back in another order. */
    keySwap = state.keys[0];
    state.keys[0] = state.keys[1];
    state.keys[1] = keySwap;

    windowSwap = state.windows[0];
    state.windows[0] = state.windows[1];
    state.windows[1] = windowSwap;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "and a state whose descriptor and window lists are permuted is accepted: an entry is identified by its content (a key by its KeySeqNumber, a window by its SenderAddress) never by its index");

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &after), ZB_OK,
                      "and the module holds both windows again");
    Test_ExpectCount(after.windowCount, 2, "two of them, not one twice");
    Test_Expect(after.windows[0].senderIeee == STATE_THIRD_IEEE && after.windows[0].frameCounter == 9
                && after.windows[1].senderIeee == STATE_SECOND_IEEE && after.windows[1].frameCounter == 7,
                "each at its own counter: the window followed its sender through the permutation and took nothing of its neighbour's, and the pool order it is written in is the order the state listed");

    Security_Snapshot(&dev.security, &snapshot);

    Test_Expect(snapshot.keyCount == 2 && snapshot.keySeqNumber[0] == 0x01 && snapshot.keySeqNumber[1] == 0x00,
                "and both descriptors are back, in the order the permuted state listed them");
    Test_Expect(snapshot.outgoingFrameCounter[0] == 11 + ZB_STATE_COUNTER_BANK
                && snapshot.outgoingFrameCounter[1] == 5 + ZB_STATE_COUNTER_BANK,
                "each with its own counter banked: 5 and 11 travelled with their sequence numbers and did not swap places with the entries");
}

void caseVersionRefused(void)
{
    StateDevice dev;
    Zb_State state;
    uint8_t image[sizeof(Security)];

    stateBuild(&dev);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 7: a state captured from this build");

    stateImage(&dev.security, image);

    state.version = ZB_STATE_VERSION + 1;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and a schema this build does not know is refused: `version` names the object for the application's own format, and a restore refuses one it does not read");
    Test_Expect(stateImageHeld(&dev.security, image), "with the module byte-identical");

    state.version = 0;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and so is version 0, which no capture writes");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched either");

    state.version = ZB_STATE_VERSION;
    state.channel = 27;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "a channel outside 11-26 is refused");
    state.channel = 0;
    state.nwkUpdateId = 0x100;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and an nwkUpdateId wider than its octet");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    state.nwkUpdateId = 0;
    state.version = ZB_STATE_VERSION_OLDEST;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "the first schema, which holds no channel, is still restored");
}

void caseDuplicatesRefused(void)
{
    StateDevice dev;
    Security_KeyDescriptor keys[2];
    Security_IncomingEntry windows[2];
    Security_KeyPairEntry pairs[2];
    Zb_State base;
    Zb_State state;
    uint8_t image[sizeof(Security)];

    keys[0] = stateKeyAt(0x00, s_keyAHex, 5);
    keys[1] = stateKeyAt(0x01, s_keyBHex, 11);
    windows[0] = stateWindowAt(STATE_SECOND_IEEE, 0x00, 7);
    windows[1] = stateWindowAt(STATE_THIRD_IEEE, 0x00, 9);
    pairs[0] = statePairAt(STATE_PEER_IEEE, s_linkKeyHex, 0x10, 0x20);
    pairs[1] = statePairAt(STATE_SECOND_IEEE, s_linkKeyHex, 0x30, 0x40);
    stateBuildWith(&dev, keys, 2, windows, 2, pairs, 2);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &base), ZB_OK,
                      "case 8: a full state (two keys, two windows, two pairs) captured");

    stateImage(&dev.security, image);

    state = base;
    state.keys[1].keySeqNumber = state.keys[0].keySeqNumber;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and two descriptors naming one KeySeqNumber are refused: nwkActiveKeySeqNumber and 4.3.1.2 step 2 would select neither");
    Test_Expect(stateImageHeld(&dev.security, image), "with the module byte-identical");

    state = base;
    state.windows[1].senderIeee = state.windows[0].senderIeee;
    state.windows[1].keySeqNumber = state.windows[0].keySeqNumber;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and two windows for one (sender, key) pair: the store keeps one window per pair, and two would give this sender two to be judged against");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    state = base;
    state.pairs[1].deviceIeee = state.pairs[0].deviceIeee;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and two key pairs for one Table 4-36 DeviceAddress: 4.4.1.1 step 1's selection would be ambiguous");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched either");

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &base), ZB_OK,
                      "and the state as it was captured is accepted, so it was the duplicate and not the state that was refused");
}

void caseZeroNamesRefused(void)
{
    StateDevice dev;
    Security_KeyDescriptor keys[1];
    Security_IncomingEntry windows[1];
    Security_KeyPairEntry pairs[1];
    Zb_State state;
    uint8_t image[sizeof(Security)];

    keys[0] = stateKeyAt(0x00, s_keyAHex, 5);
    windows[0] = stateWindowAt(STATE_SECOND_IEEE, 0x00, 7);
    pairs[0] = statePairAt(STATE_PEER_IEEE, s_linkKeyHex, 0x10, 0x20);
    stateBuildWith(&dev, keys, 1, windows, 1, pairs, 1);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 9: a state with one window and one pair");

    stateImage(&dev.security, image);

    state.windows[0].senderIeee = 0;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and a window whose sender address is 0 is malformed rather than an entry for address 0: no auxiliary source address is ever zero (4.5.1.3, 3.2.1.1.3)");
    Test_Expect(stateImageHeld(&dev.security, image), "with the module byte-identical");

    state.windows[0].senderIeee = STATE_SECOND_IEEE;
    state.pairs[0].deviceIeee = 0;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and a unique key pair whose DeviceAddress is 0 is the same: Table 4-36's \"any valid 64-bit address\" excludes it");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched either");
}

void caseCountersMoveForward(void)
{
    StateDevice dev;
    Security_KeyDescriptor keys[1];
    Security_IncomingEntry windows[1];
    Security_KeyPairEntry pairs[1];
    Security_KeyState snapshot;
    Zb_State state;
    Zb_State after;

    keys[0] = stateKeyAt(0x00, s_keyAHex, 5);
    windows[0] = stateWindowAt(STATE_SECOND_IEEE, 0x00, 7);
    pairs[0] = statePairAt(STATE_PEER_IEEE, s_linkKeyHex, 0x10, 0x20);
    pairs[0].verifiedFrameCounter = 1;
    stateBuildWith(&dev, keys, 1, windows, 1, pairs, 1);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 10: a state captured at descriptor counter 5 and key-pair counter 0x10");

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "and restored");

    Security_Snapshot(&dev.security, &snapshot);

    Test_ExpectCount(snapshot.outgoingFrameCounter[0], 5 + ZB_STATE_COUNTER_BANK,
                     "the descriptor's outgoing counter is the stored one plus ZB_STATE_COUNTER_BANK, so a stale backup advances past everything it could have used");
    Test_ExpectCount(snapshot.keyPairOutgoingFrameCounter[0], 0x10 + ZB_STATE_COUNTER_BANK,
                     "and the key pair's outgoing counter is banked the same way: 4.4.1.1 step 2's nonce has the same constraint");

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &after), ZB_OK,
                      "and the two counters a bank does not touch are the values the state carried");

    Test_ExpectCount(after.windows[0].frameCounter, 7,
                     "the incoming window stands as it was stored: it is the count this device refuses next, not one it transmits with");
    Test_Expect(dev.security.keyPairs[0].incomingFrameCounter == 0 && dev.security.keyPairs[0].verifiedFrameCounter == 0,
                "while the key pair's IncomingFrameCounter starts at 0 and VerifiedFrameCounter FALSE: 4.4.12.1 persists neither, and 4.6.3.8 clears the second after a reboot");

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "and restoring the very same state a second time is accepted");

    Security_Snapshot(&dev.security, &snapshot);

    Test_ExpectCount(snapshot.outgoingFrameCounter[0], 5 + ZB_STATE_COUNTER_BANK + ZB_STATE_COUNTER_BANK,
                     "and advances again: a backup can never rewind a counter, however often it is read (9.2.4)");
    Test_ExpectCount(snapshot.keyPairOutgoingFrameCounter[0], 0x10 + ZB_STATE_COUNTER_BANK + ZB_STATE_COUNTER_BANK,
                     "which is the rule and not a single step: twice the bank after two restores");
}

void caseKeysOptIn(void)
{
    StateDevice devA;
    StateDevice devB;
    StateDevice devC;
    Security_KeyDescriptor keysA[1];
    Security_KeyDescriptor keysB[1];
    Security_KeyDescriptor keysC[1];
    Zb_State state;
    Zb_State after;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frameB[SECURITY_FRAME_MAX];
    uint8_t frameC[SECURITY_FRAME_MAX];
    uint8_t key[SECURITY_KEY_OCTETS];
    uint32_t headerLen;
    uint32_t payloadLen;
    uint32_t frameBLen;
    uint32_t frameCLen;
    uint32_t keyLen;

    keysA[0] = stateKeyAt(0x00, s_keyAHex, 5);
    keysB[0] = stateKeyAt(0x00, s_keyBHex, 5);
    keysC[0] = stateKeyAt(0x00, s_keyBHex, 5 + ZB_STATE_COUNTER_BANK);

    stateBuildWith(&devA, keysA, 1, 0, 0, 0, 0);
    stateBuildWith(&devB, keysB, 1, 0, 0, 0, 0);
    stateBuildWith(&devC, keysC, 1, 0, 0, 0, 0);

    Test_ExpectStatus(Zb_StateCapture(&devA.security, &devA.rig.nwk, &devA.aps, &devA.rig.mac, 0, &state), ZB_OK,
                      "case 11: a device holding key A captures a state that carries no key");
    Test_Expect(state.keys[0].keyPresent == 0, "which says so in the entry");

    Test_ExpectStatus(Zb_StateRestore(&devB.security, &devB.rig.nwk, &devB.aps, &devB.rig.mac, &state), ZB_OK,
                      "and a device configured with key B restores it: the counters travel, the key does not");

    Test_ExpectStatus(Zb_StateCapture(&devB.security, &devB.rig.nwk, &devB.aps, &devB.rig.mac, 1, &after), ZB_OK,
                      "and a capture of that device which does ask for the keys");

    keyLen = stateKeyOf(s_keyBHex, key);

    Test_ExpectOctets("answers key B: a keyPresent of 0 left the key Security_Init configured in place (the opt-in, the artefact that may sit in plain flash)",
                      after.keys[0].key, SECURITY_KEY_OCTETS, key, keyLen);
    Test_ExpectCount(after.keys[0].outgoingFrameCounter, 5 + ZB_STATE_COUNTER_BANK, "with the counter the state carried, banked");

    /* The key is not merely unchanged but *used*: the same header and payload protected by devB and by devC
       (which was configured with key B at the banked counter) are one frame, octet for octet. */
    headerLen = Test_ParseHex(s_header1Hex, header, SECURITY_FRAME_MAX);
    payloadLen = Test_ParseHex(s_payloadHex, payload, SECURITY_FRAME_MAX);

    Test_ExpectStatus(Security_Protect(&devB.security, header, headerLen, payload, payloadLen,
                                  frameB, SECURITY_FRAME_MAX, &frameBLen), ZB_OK,
                      "and a protection on that device runs, which needs a key");
    Test_ExpectStatus(Security_Protect(&devC.security, header, headerLen, payload, payloadLen,
                                  frameC, SECURITY_FRAME_MAX, &frameCLen), ZB_OK,
                      "as it does on a device seeded by hand with that same key and counter");

    Test_ExpectOctets("and the two frames are identical, so the key that was kept is the key that was configured and not merely a key present",
                      frameB, frameBLen, frameC, frameCLen);

    Test_ExpectStatus(Zb_StateCapture(&devB.security, &devB.rig.nwk, &devB.aps, &devB.rig.mac, 0, &after), ZB_OK,
                      "and the protection moved that device's counter to the next one, as any protection does");
    Test_ExpectCount(after.keys[0].outgoingFrameCounter, 5 + ZB_STATE_COUNTER_BANK + 1,
                     "which is the frame just protected and not a restored value");
}

void caseKeyWithoutDescriptorRefused(void)
{
    StateDevice dev;
    Security_KeyDescriptor keys[1];
    Security_KeyPairEntry pairs[1];
    Zb_State state;
    uint8_t image[sizeof(Security)];

    keys[0] = stateKeyAt(0x00, s_keyAHex, 5);
    pairs[0] = statePairAt(STATE_PEER_IEEE, s_linkKeyHex, 0x10, 0x20);
    stateBuildWith(&dev, keys, 1, 0, 0, pairs, 1);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 12: a state captured from a device holding key 0x00 and one key pair");

    stateImage(&dev.security, image);

    state.keys[0].keySeqNumber = 0x05;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_AUTH,
                      "and an entry that carries no key and names a sequence number this boot holds nothing under is refused with ZB_ERR_AUTH: there is no key to keep, and a restore that wiped first would leave a module holding no material at all (4.3.1.1 step 1)");
    Test_Expect(stateImageHeld(&dev.security, image), "with the module byte-identical, which is only possible because the lookup happens before the wipe");

    state.keys[0].keyPresent = 1;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and now the key travels but nwkActiveKeySeqNumber still names 0x00, which no descriptor the state carries holds: an unseeded active key is a configuration error, not the runtime 'no key' (Security_Init's rule, 4.3.1.1 step 1)");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    state.keys[0].keySeqNumber = 0x00;
    state.pairs[0].deviceIeee = STATE_THIRD_IEEE;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_AUTH,
                      "and a key pair whose link key did not travel and whose partner this boot shares no pair with is the same refusal: no link key to keep");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched either");
}

void caseCounterBankOverflow(void)
{
    StateDevice dev;
    Security_KeyDescriptor keys[1];
    Security_KeyPairEntry pairs[1];
    Security_KeyState snapshot;
    Zb_State state;
    uint8_t header[SECURITY_FRAME_MAX];
    uint8_t payload[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
    uint8_t image[sizeof(Security)];
    uint32_t headerLen;
    uint32_t payloadLen;
    uint32_t frameLen;

    keys[0] = stateKeyAt(0x00, s_keyAHex, 5);
    pairs[0] = statePairAt(STATE_PEER_IEEE, s_linkKeyHex, 0x10, 0x20);
    stateBuildWith(&dev, keys, 1, 0, 0, pairs, 1);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 13: a state captured from a device holding one descriptor at counter 5");

    stateImage(&dev.security, image);

    state.keys[0].outgoingFrameCounter = 0xffffffff - ZB_STATE_COUNTER_BANK + 1;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_FRAME_COUNTER,
                      "and a stored counter whose bank would carry past 2^32-1 is refused rather than wrapped: saturating would land 2^32-1, which 4.3.1.1 step 1 refuses for every later send, so both readings are refusals and this one names the cause here");
    Test_Expect(stateImageHeld(&dev.security, image), "with the module byte-identical");

    state.keys[0].outgoingFrameCounter = 5;
    state.pairs[0].outgoingFrameCounter = 0xffffffff - ZB_STATE_COUNTER_BANK + 1;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_FRAME_COUNTER,
                      "and a key pair's outgoing counter is judged by the same arithmetic");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    state.pairs[0].outgoingFrameCounter = 0x10;
    state.keys[0].outgoingFrameCounter = 0xffffffff - ZB_STATE_COUNTER_BANK;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "while a stored counter one below that boundary restores: its banked value is exactly 2^32-1");

    Security_Snapshot(&dev.security, &snapshot);

    Test_ExpectCount(snapshot.outgoingFrameCounter[0], 0xffffffff,
                     "which is the largest counter this module can hold, and the one 4.3.1.1 step 1 will not transmit with");

    headerLen = Test_ParseHex(s_header1Hex, header, SECURITY_FRAME_MAX);
    payloadLen = Test_ParseHex(s_payloadHex, payload, SECURITY_FRAME_MAX);

    Test_ExpectStatus(Security_Protect(&dev.security, header, headerLen, payload, payloadLen,
                                  frame, SECURITY_FRAME_MAX, &frameLen), ZB_ERR_BAD_FRAME_COUNTER,
                      "so the very next protection is refused there: the state was restored honestly and the exhaustion is now a fact of the descriptor, not a wrapped counter");
}

void caseTablesNotWiped(void)
{
    StateDevice dev;
    Zb_State state;
    uint32_t neighbours;
    uint32_t groups;

    stateBuild(&dev);
    stateSend(&dev);

    Test_Expect(Aps_AddGroup(&dev.aps, 0x0001, 0x03) == APS_STATUS_SUCCESS,
                "the device is given a group, which is left to the application's own APSME-ADD-GROUP (2.2.4.5.1)");

    neighbours = Nwk_NeighborQueue(&dev.rig.nwk);
    groups = Aps_GroupQueue(&dev.aps);

    Test_Expect(neighbours == 1 && groups == 1, "so it holds one neighbour from the frame it sent and one group it was given");

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 14: a state is captured from it");

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "and restored");

    Test_ExpectCount(Nwk_NeighborQueue(&dev.rig.nwk), neighbours,
                     "the neighbour table is still there: it is traffic-derived state the object does not hold, and a restore wipes and fills the security module only");
    Test_ExpectCount(Aps_GroupQueue(&dev.aps), groups,
                     "and so is group membership, which the object does not hold because it is application config re-added through Aps_AddGroup");

    Test_ExpectCount(dev.rig.nwk.seq, (state.nwkSequenceNumber + 1) % NWK_SEQ_WRAP,
                     "while the NWK sequence number, which the object does hold, was written: a public member of the caller's own struct (§4.3)");
    Test_ExpectCount(dev.rig.mac.tx.dsn, (state.macDsn + 1) % MAC_DSN_WRAP, "and the MAC's DSN");
    Test_ExpectCount(dev.aps.apsCounter, (state.apsCounter + 1) % APS_COUNTER_WRAP, "and the APS counter");
}

/* 3.6.10.8: a restored child is given its full Device Timeout from the parent's first turn, whatever its clock reads,
   and ages out a whole period after that turn. */
void caseChildRestoredWithAFullPeriod(void)
{
    StateDevice dev;
    Zb_State state;
    const uint32_t firstTurnMs = 5000000;

    stateBuild(&dev);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "a router's state is captured");

    state.childCount = 1;
    state.children[0].extendedAddress = 0x00212effff048a12;
    state.children[0].networkAddress = 0x4c2a;
    state.children[0].deviceTimeout = 120;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "and restored with one end device child of 3.6.9's SHALL list, its Device Timeout 120 seconds");

    Test_ExpectStatus(Nwk_Step(&dev.rig.nwk, firstTurnMs), ZB_OK, "the first turn after the reboot comes late in the clock");
    Test_ExpectCount(Nwk_ChildrenAgedOut(&dev.rig.nwk), 0,
                     "and does not age the child: 3.6.10.8 sets its counter to the Device Timeout, a full period");

    Test_ExpectStatus(Nwk_Step(&dev.rig.nwk, firstTurnMs + 119 * 1000), ZB_OK, "a turn 119 seconds on");
    Test_ExpectCount(Nwk_ChildrenAgedOut(&dev.rig.nwk), 0, "still holds it");

    Test_ExpectStatus(Nwk_Step(&dev.rig.nwk, firstTurnMs + 120 * 1000), ZB_OK, "and the turn 120 seconds on");
    Test_ExpectCount(Nwk_ChildrenAgedOut(&dev.rig.nwk), 1, "ages it out, the period counted from that first turn");
}

void caseRoutingSequenceRoundTrip(void)
{
    StateDevice dev;
    Zb_State state;
    Zb_State after;

    stateBuild(&dev);
    dev.rig.nwk.routingSequenceNumber = 0x1234;

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 16: a device holding routing sequence number 0x1234 is captured");

    Test_ExpectCount(state.nwkRoutingSequenceNumber, 0x1234,
                     "and NIB 0xBE's value is in the object: Table 3-66 marks it as persisting, so a reboot that did not carry it would restart the number the Route Requests are dated by");

    dev.rig.nwk.routingSequenceNumber = 0;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "and a module that came up at 0 restores that state");

    Test_ExpectCount(dev.rig.nwk.routingSequenceNumber, 0x1235,
                     "holding the stored number one step on, which is all a carried number owes: the slot was free to be used, so the restore does not hand it back");

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &after), ZB_OK,
                      "a capture of the restored device");

    Test_ExpectCount(after.nwkRoutingSequenceNumber, 0x1235,
                     "reports the restored number, so what the round trip carried is the object's value and not the module's");
}

void caseRoutingSequenceForwardOnly(void)
{
    StateDevice dev;
    Zb_State state;

    stateBuild(&dev);
    dev.rig.nwk.routingSequenceNumber = 0x0100;

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 17: a state captured at routing sequence number 0x0100");

    dev.rig.nwk.routingSequenceNumber = 0x5000;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "and restored over a boot that had already reached 0x5000");

    Test_ExpectCount(dev.rig.nwk.routingSequenceNumber, 0x5001,
                     "the lower stored number does not lower the live one: the one step lands past the larger of the two, so a stale backup can never make a peer's route look older than it is (3.6.4.5.1)");

    dev.rig.nwk.routingSequenceNumber = 0xffff;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "and the same state restored over a boot holding the top of Table 3-66's range");

    Test_ExpectCount(dev.rig.nwk.routingSequenceNumber, 0x0000,
                     "takes the 0x10000 wrap the module's own increment takes rather than stalling at the top of it");
}

void caseRoutingSequenceRefused(void)
{
    StateDevice dev;
    Zb_State state;
    uint8_t image[sizeof(Security)];

    stateBuild(&dev);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 18: a state captured from this build");

    stateImage(&dev.security, image);

    state.nwkRoutingSequenceNumber = NWK_ROUTE_SEQUENCE_WRAP;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and a routing sequence number at the wrap is refused: Table 3-66 prints 0-0xffff for NIB 0xBE, so 0x10000 is not a value this boundary can produce");
    Test_Expect(stateImageHeld(&dev.security, image), "with the security module byte-identical");
    Test_ExpectCount(dev.rig.nwk.routingSequenceNumber, 0, "and the module's own number untouched, because the judgement is before the first write");

    state.nwkRoutingSequenceNumber = 0xffffffff;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_ERR_BAD_ARGUMENT,
                      "and so is a value no 16-bit field could have carried");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched either");

    state.nwkRoutingSequenceNumber = 0xffff;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "while the top of the printed range restores, so it was the wrap and not the number that was refused");

    Test_ExpectCount(dev.rig.nwk.routingSequenceNumber, 0x0000,
                     "and one step past the top of the printed range is the wrap");
}

void caseGlobalPairRoundTrip(void)
{
    static const uint8_t seed[SECURITY_KEY_OCTETS] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    StateDevice dev;
    Zb_State state;
    Zb_State after;

    stateBuildTrustCentre(&dev, STATE_OWN_IEEE, seed);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 1, &state), ZB_OK,
                      "case 20: a trust centre holding the global link key beside a device's own is captured");
    Test_Expect(state.pairCount == 2 && state.pairs[0].deviceIeee == 0
                && state.pairs[0].linkKeyType == SECURITY_LINK_KEY_GLOBAL,
                "with the global key's entry, which names no device, among its pairs");

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "and its own capture is restored: 4.4.12.1 backs up every apsDeviceKeyPairSet entry");

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 1, &after), ZB_OK,
                      "and captured again");
    Test_Expect(after.pairCount == 2 && after.pairs[0].deviceIeee == 0
                && after.pairs[0].linkKeyType == SECURITY_LINK_KEY_GLOBAL
                && Zb_memcmp(after.pairs[0].linkKey, state.pairs[0].linkKey, SECURITY_KEY_OCTETS) == 0,
                "with the global entry and its key where they were");

    state.pairs[1].deviceIeee = 0;
    state.pairs[1].linkKeyType = SECURITY_LINK_KEY_GLOBAL;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state),
                      ZB_ERR_BAD_ARGUMENT, "while two entries naming no device are one name twice");
}

void caseTrustCentreConfigurationKept(void)
{
    static const uint8_t seed[SECURITY_KEY_OCTETS] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    StateDevice dev;
    Zb_State state;
    uint8_t before[SECURITY_KEY_OCTETS];
    uint8_t after[SECURITY_KEY_OCTETS];

    stateBuildTrustCentre(&dev, STATE_OWN_IEEE, seed);

    Test_ExpectStatus(Security_DeriveLinkKey(&dev.security, STATE_THIRD_IEEE, before), ZB_OK,
                      "case 21: a trust centre derives a joiner's link key from its seed (4.7.3.8.1)");
    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 1, &state), ZB_OK,
                      "and is captured");
    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "and restored");

    Test_Expect(dev.security.trustCenterIeee == STATE_OWN_IEEE,
                "it is still the trust centre: apsTrustCenterAddress came back with the state (4.4.12.1)");
    Test_Expect(dev.security.requireLinkKeyEncryption == 1,
                "and it still requires a transported key under the link key (4.4.2.3), which is configuration too");
    Test_ExpectStatus(Security_DeriveLinkKey(&dev.security, STATE_THIRD_IEEE, after), ZB_OK,
                      "and it still holds a seed");
    Test_Expect(Zb_memcmp(before, after, SECURITY_KEY_OCTETS) == 0,
                "the same one, so a joiner that asks again is given the key it was given before");
}

void caseTrustCentreAddressPersisted(void)
{
    StateDevice dev;
    Zb_State state;

    stateBuildTrustCentre(&dev, STATE_PEER_IEEE, 0);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 1, &state), ZB_OK,
                      "case 22: a device whose trust centre is another device is captured");
    Test_Expect(state.trustCenterIeee == STATE_PEER_IEEE, "and the object carries apsTrustCenterAddress (4.4.12.1)");

    stateBuildTrustCentre(&dev, 0xffffffffffffffff, 0);

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "and restored on a boot that has not learnt its trust centre yet, the address still all-F");
    Test_Expect(dev.security.trustCenterIeee == STATE_PEER_IEEE, "which then names the stored trust centre");
}

void caseExtendedPanOctetOrder(void)
{
    static const uint8_t joined[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    StateDevice dev;
    Zb_State state;

    stateBuild(&dev);
    Zb_memcpy(dev.rig.nwk.joinExtendedPanId, joined, (uint32_t)sizeof joined);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 23: a device that joined the network whose extended PAN is 0x8877665544332211 is captured");
    Test_Expect(state.extendedPanId == 0x8877665544332211,
                "and the object holds that value: the join keeps it least significant octet first, as the beacon carries it");

    state.extendedPanId = 0x0102030405060708;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "a state naming 0x0102030405060708 is restored");
    Test_Expect(dev.rig.nwk.joinExtendedPanId[0] == 0x08 && dev.rig.nwk.joinExtendedPanId[7] == 0x01,
                "and the join's field holds it in the same order");
}

void caseRoleMustMatch(void)
{
    StateDevice dev;
    Zb_State state;
    uint8_t image[sizeof(Security)];

    stateBuild(&dev);
    dev.rig.nwk.joinParentShort = STATE_NEIGHBOR_SHORT;
    dev.rig.nwk.joinParentExtended = STATE_PEER_IEEE;

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "case 24: a router that joined through a parent is captured");
    Test_ExpectCount(state.deviceType, NWK_DEVICE_ROUTER, "and the object names the role that captured it");
    Test_Expect(state.parentShort == 0 && state.parentIeee == 0,
                "but no parent, which 3.6.9 keeps for an end device alone, so a restore and a capture agree");

    stateImage(&dev.security, image);
    state.deviceType = NWK_DEVICE_END_DEVICE;
    state.parentIeee = STATE_PEER_IEEE;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state),
                      ZB_ERR_BAD_ARGUMENT, "an end device's state is refused on a boot configured as a router");
    Test_Expect(stateImageHeld(&dev.security, image), "and the refusal touched nothing");

    stateBuildEndDevice(&dev, STATE_OWN_SHORT);
    state.parentIeee = 0;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state),
                      ZB_ERR_BAD_ARGUMENT, "and on an end device, one that names no parent is refused too");
}

void caseEndDeviceComesBackJoined(void)
{
    StateDevice dev;
    Zb_State state;
    const Nwk_NeighborTableEntry *parent = 0;
    uint32_t i;

    stateBuildEndDevice(&dev, STATE_OWN_SHORT);
    dev.rig.nwk.joinParentShort = STATE_NEIGHBOR_SHORT;
    dev.rig.nwk.joinParentShortKnown = 1;
    dev.rig.nwk.joinParentExtended = STATE_PEER_IEEE;
    dev.security.trustCenterIeee = STATE_SECOND_IEEE;

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 1, &state), ZB_OK,
                      "case 25: an end device joined through 0x0002 is captured");
    Test_Expect(state.parentShort == STATE_NEIGHBOR_SHORT && state.parentIeee == STATE_PEER_IEEE,
                "with its parent by both addresses");

    stateBuildEndDevice(&dev, 0xffff);

    Test_Expect(!Nwk_IsPartOfNetwork(&dev.rig.nwk), "a boot with no address is on no network");
    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "and the state is restored on it");
    Test_Expect(Nwk_IsPartOfNetwork(&dev.rig.nwk) && dev.rig.nwk.joinState == NWK_JOIN_JOINED
                && Mac_Pib(&dev.rig.mac)->shortAddress == STATE_OWN_SHORT,
                "which puts it back at its address, joined (3.6.9)");

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        if (dev.rig.nwk.neighbors[i].inUse && dev.rig.nwk.neighbors[i].relationship == NWK_REL_PARENT)
            parent = &dev.rig.nwk.neighbors[i];
    }

    Test_Expect(parent != 0 && parent->networkAddress == STATE_NEIGHBOR_SHORT && parent->ieeeKnown
                && parent->extendedAddress == STATE_PEER_IEEE && parent->deviceType == NWK_DEVICE_ROUTER,
                "with its parent in the neighbour table, a router by its address");
    Test_Expect(dev.rig.nwk.joinParentShortKnown && dev.rig.nwk.joinParentShort == STATE_NEIGHBOR_SHORT
                && dev.rig.nwk.joinParentExtended == STATE_PEER_IEEE,
                "and named as the parent the join would have recorded");
    Test_Expect(dev.rig.nwk.trustCenterIeee == STATE_SECOND_IEEE,
                "and the network layer checks rejoins against the stored trust centre, which it learns with a key otherwise");
}

void caseAddressMapSeededFromTheState(void)
{
    StateDevice dev;
    Zb_State state;
    uint16_t found = 0xffff;
    uint64_t holder = 0;

    stateBuildEndDevice(&dev, STATE_OWN_SHORT);
    dev.rig.nwk.joinParentShort = STATE_NEIGHBOR_SHORT;
    dev.rig.nwk.joinParentShortKnown = 1;
    dev.rig.nwk.joinParentExtended = STATE_PEER_IEEE;
    dev.security.trustCenterIeee = STATE_SECOND_IEEE;

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 1, &state), ZB_OK,
                      "case 26: an end device whose trust centre is another device is captured");

    stateBuildEndDevice(&dev, 0xffff);

    Test_Expect(!Nwk_AddressOfIeee(&dev.rig.nwk, STATE_SECOND_IEEE, &found), "a boot whose map names nobody");
    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "has the state restored on it");
    Test_Expect(Nwk_AddressOfIeee(&dev.rig.nwk, STATE_SECOND_IEEE, &found) && found == 0x0000,
                "and maps the trust centre to the coordinator's address, where a centralized network keeps it (4.6.2.2)");
    Test_Expect(Nwk_AddressOfIeee(&dev.rig.nwk, STATE_PEER_IEEE, &found) && found == STATE_NEIGHBOR_SHORT,
                "and its parent to the address 3.6.9 stored: a bound 64-bit destination resolves (2.2.4.1.1.3)");

    stateBuild(&dev);

    Test_ExpectStatus(Zb_StateCapture(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, 0, &state), ZB_OK,
                      "a router with no trust centre is captured");

    state.trustCenterIeee = 0xffffffffffffffff;
    state.childCount = 1;
    state.children[0].extendedAddress = 0x00212effff048a12;
    state.children[0].networkAddress = 0x4c2a;
    state.children[0].deviceTimeout = 120;

    Test_ExpectStatus(Zb_StateRestore(&dev.security, &dev.rig.nwk, &dev.aps, &dev.rig.mac, &state), ZB_OK,
                      "and restored with one end device child and a distributed network's all-F trust centre");
    Test_Expect(Nwk_AddressOfIeee(&dev.rig.nwk, 0x00212effff048a12, &found) && found == 0x4c2a,
                "which maps the child");
    Test_Expect(!Nwk_AddrMapExtendedOf(Nwk_AddrMapConst(&dev.rig.nwk), 0x0000, &holder),
                "and puts no trust centre at the coordinator's address");
}
