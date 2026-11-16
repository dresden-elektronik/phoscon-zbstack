/* The `state` suite's module-level case: Security_Restore judged on its own, without a state object in the way
   (the second half of the persistence boundary). See `state_cases.h` for the case list. */

#include "state_cases.h"
#include "state_helpers.h"

#include "zb_utils.h"

void caseSecurityRestoreRefusals(void)
{
    StateDevice dev;
    Security_Config cfg;
    Security_KeyDescriptor keys[SECURITY_KEY_SET_MAX + 1];
    Security_IncomingEntry windows[SECURITY_INCOMING_MAX + 1];
    Security_KeyPairEntry pairs[SECURITY_KEYPAIR_MAX + 1];
    Security_KeyState snapshot;
    uint8_t image[sizeof(Security)];
    uint32_t index;

    stateBuild(&dev);
    stateImage(&dev.security, image);

    keys[0] = stateKeyAt(0x00, s_keyAHex, 5);
    keys[1] = stateKeyAt(0x01, s_keyBHex, 6);

    for (index = 0; index < SECURITY_INCOMING_MAX + 1; index++)
        windows[index] = stateWindowAt(STATE_SECOND_IEEE + index, 0x00, index + 1);

    for (index = 0; index < SECURITY_KEYPAIR_MAX + 1; index++)
        pairs[index] = statePairAt(STATE_PEER_IEEE + index, s_linkKeyHex, 1, 1);

    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);
    cfg.ownIeee = STATE_OWN_IEEE;
    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.nwkActiveKeySeqNumber = 0x00;
    cfg.authenticated = 1;
    cfg.nwkAllFresh = 1;
    cfg.keys = keys;
    cfg.keyCount = 1;
    cfg.log = 0;                        /* not read: the module keeps the pool it already reports into */

    Test_ExpectStatus(Security_Restore(0, &cfg), ZB_ERR_BAD_ARGUMENT, "case 15: a 0 module is a bad argument");
    Test_ExpectStatus(Security_Restore(&dev.security, 0), ZB_ERR_BAD_ARGUMENT, "and a 0 configuration");
    Test_Expect(stateImageHeld(&dev.security, image), "and neither refusal touched the module: validate-then-commit is this call's whole difference from Security_Init, which zeroes first");

    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC;

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "level 0x04 is refused as a config error (M = 0 is inexpressible at the CCM* seam)");
    Test_Expect(stateImageHeld(&dev.security, image), "with the module byte-identical");

    cfg.nwkSecurityLevel = SECURITY_LEVEL_MAX + 1;

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and a level above 0x07, Table 4-2's range");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    cfg.nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;
    cfg.keyCount = SECURITY_KEY_SET_MAX + 1;

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and three descriptors are more than the set of 2 Table 4-2 prints, at the module's door as well as at the object's");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    cfg.keyCount = 2;
    keys[1] = stateKeyAt(0x00, s_keyBHex, 6);

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and one sequence number named twice");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    keys[1] = stateKeyAt(0x01, s_keyBHex, 6);
    cfg.nwkActiveKeySeqNumber = 0x07;

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and an active sequence number no descriptor names, at a level that runs security");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    cfg.nwkActiveKeySeqNumber = 0x00;
    cfg.incomingSeeds = windows;
    cfg.incomingSeedCount = SECURITY_INCOMING_MAX + 1;

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and 33 windows do not fit the store 4.3.1.2 step 6 bounds at M × N = 2 × 16 = 32");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    cfg.incomingSeedCount = 2;
    windows[1] = stateWindowAt(STATE_SECOND_IEEE, 0x00, 9);

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and one (sender, key) pair named twice");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    cfg.incomingSeeds = 0;
    cfg.incomingSeedCount = 0;
    cfg.keyPairs = pairs;
    cfg.keyPairCount = SECURITY_KEYPAIR_MAX + 1;

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and nine key pairs do not fit the pool Table 4-35 prints no bound for, which is band A's own named bound");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    cfg.keyPairCount = 2;
    pairs[1] = statePairAt(STATE_PEER_IEEE, s_linkKeyHex, 1, 1);

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and two entries for one DeviceAddress make 4.4.1.1 step 1's selection ambiguous");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    pairs[1] = statePairAt(STATE_SECOND_IEEE, s_linkKeyHex, 1, 1);
    pairs[0].shortKnown = 1;
    pairs[0].shortAddress = 0x0005;
    pairs[1].shortKnown = 1;
    pairs[1].shortAddress = 0x0005;

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and so does one known short alias twice, the 16-bit handle on an entry");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    pairs[0].shortKnown = 0;
    pairs[1].shortKnown = 0;
    pairs[1].keyAttributes = SECURITY_KEYPAIR_ATTR_UNVERIFIED;

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_OK,
                      "and an entry awaiting its Verify-Key restores: 4.4.12.1 backs up every entry of apsDeviceKeyPairSet");
    Test_Expect(Security_KeyPairCount(&dev.security) == 2
                && Security_KeyPairAt(&dev.security, 1)->keyAttributes == SECURITY_KEYPAIR_ATTR_UNVERIFIED,
                "with both pairs held, the second still unverified");
    pairs[1].keyAttributes = SECURITY_KEYPAIR_ATTR_PROVISIONAL + 3;

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and a KeyAttributes Table 4-36 does not print is refused");

    pairs[1].keyAttributes = SECURITY_KEYPAIR_ATTR_VERIFIED;
    pairs[1].linkKeyType = SECURITY_LINK_KEY_GLOBAL;

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_OK,
                      "and a global link key restores: 4.4.1.2 step 4 prints its freshness check for a unique key only, so a global one has nothing to run, and 4.4.1.5 needs such a key held");
    Test_Expect(Security_KeyPairCount(&dev.security) == 2, "with both pairs held");

    stateImage(&dev.security, image);

    pairs[1].linkKeyType = SECURITY_LINK_KEY_UNIQUE;
    pairs[1].featuresCapabilities = SECURITY_FEATURES_FRAME_COUNTER_SYNC + 1;

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and a Features & Capabilities outside Table 4-36's printed {0x00, 0x01}, whose bits 1-7 \"SHALL be set to '0'\"");
    Test_Expect(stateImageHeld(&dev.security, image), "with nothing touched");

    pairs[1].featuresCapabilities = SECURITY_FEATURES_NONE;
    cfg.keyCount = 1;

    Test_ExpectStatus(Security_Restore(&dev.security, &cfg), ZB_OK,
                      "and every rule passed, so the restore runs");

    Security_Snapshot(&dev.security, &snapshot);

    Test_Expect(snapshot.keyCount == 1 && snapshot.keySeqNumber[0] == 0x00 && snapshot.outgoingFrameCounter[0] == 5,
                "installing the counters exactly as they arrived: the bank is zb_state's arithmetic, because advancing a counter is a persistence rule this module knows nothing about");
    Test_Expect(dev.security.log == &dev.log,
                "and keeping the record pool the module already had, although the configuration named none: the pool is the application's and not persisted state");
    Test_ExpectCount(dev.security.keyPairCount, 2, "with the key pairs in the dense pool Table 2-4's KeyIndex is an index into");
    Test_Expect(Security_IsAuthenticated(&dev.security) == 1
                && Security_Level(&dev.security) == SECURITY_LEVEL_ENC_MIC_32,
                "and the flags and the level the configuration named");
}
