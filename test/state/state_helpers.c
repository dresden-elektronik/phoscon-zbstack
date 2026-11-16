/* The `state` suite's shared machinery: the bodies. See `state_helpers.h` for what this file is and why it
   is here. */

#include "state_helpers.h"

#include "zb_utils.h"

const char *s_frame1Hex = "0802010000001e052805000000efcdab896745230100621e81731bba4c15db7c75";
const char *s_keyAHex = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
const char *s_keyBHex = "101112131415161718191a1b1c1d1e1f";
const char *s_linkKeyHex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
const char *s_globalLinkKeyHex = "5a6967426565416c6c69616e63653039";

Security_KeyDescriptor stateKeyAt(uint8_t keySeqNumber, const char *keyHex, uint32_t outgoing)
{
    Security_KeyDescriptor descriptor;

    Zb_memset(&descriptor, 0, (uint32_t)sizeof descriptor);
    descriptor.keySeqNumber = keySeqNumber;
    descriptor.outgoingFrameCounter = outgoing;
    stateKeyOf(keyHex, descriptor.key);

    return descriptor;
}

Security_IncomingEntry stateWindowAt(uint64_t senderIeee, uint8_t keySeqNumber, uint32_t counter)
{
    Security_IncomingEntry entry;

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.senderIeee = senderIeee;
    entry.keySeqNumber = keySeqNumber;
    entry.frameCounter = counter;

    return entry;
}

Security_KeyPairEntry statePairAt(uint64_t deviceIeee, const char *linkKeyHex,
                                  uint32_t outgoing, uint32_t incoming)
{
    Security_KeyPairEntry entry;

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.deviceIeee = deviceIeee;
    entry.keyAttributes = SECURITY_KEYPAIR_ATTR_VERIFIED;
    entry.linkKeyType = SECURITY_LINK_KEY_UNIQUE;
    entry.outgoingFrameCounter = outgoing;
    entry.incomingFrameCounter = incoming;
    stateKeyOf(linkKeyHex, entry.key);

    return entry;
}

/* The configuration every builder starts from, the sets as the caller names them */
static void stateConfigAt(Security_Config *cfg, StateDevice *dev, const Security_KeyDescriptor *keys,
                          uint32_t keyCount, const Security_IncomingEntry *windows, uint32_t windowCount,
                          const Security_KeyPairEntry *pairs, uint32_t pairCount)
{
    Zb_memset(cfg, 0, (uint32_t)sizeof *cfg);
    cfg->ownIeee = STATE_OWN_IEEE;
    cfg->nwkSecurityLevel = SECURITY_LEVEL_ENC_MIC_32;      /* the NIB default, Table 4-2 */
    cfg->nwkActiveKeySeqNumber = 0x00;
    cfg->authenticated = 1;
    cfg->nwkAllFresh = 1;
    cfg->keys = keys;
    cfg->keyCount = keyCount;
    cfg->incomingSeeds = windows;
    cfg->incomingSeedCount = windowCount;
    cfg->keyPairs = pairs;
    cfg->keyPairCount = pairCount;
    cfg->log = &dev->log;
}

static void stateBuildOnAs(StateDevice *dev, const Security_Config *cfg, uint32_t deviceType, uint16_t ownShort)
{
    Test_BandAConfig rigCfg;

    Test_BandADefaults(&rigCfg);
    rigCfg.deviceType = deviceType;
    rigCfg.ownAddress = ownShort;
    rigCfg.panId = STATE_PAN_ID;

    Test_ExpectStatus(Test_BandABuild(&dev->rig, &rigCfg), ZB_OK,
                      "the device this case captures stands on a MAC that already has its backend");

    Test_ExpectStatus(Security_Init(&dev->security, cfg), ZB_OK,
                      "and it holds the material this case seeded, as the application configures it");

    Test_ExpectStatus(Aps_Init(&dev->aps, &dev->rig.nwk), ZB_OK,
                      "with an APS service on the same network layer");

    Nwk_AttachSecurity(&dev->rig.nwk, &dev->security);
    Aps_AttachSecurity(&dev->aps, &dev->security);

    Test_Expect(dev->rig.nwk.security == &dev->security && dev->aps.security == &dev->security,
                "and one security module adopted by pointer by both crossings: the state object's `security` pointer is that object and not a copy of it");
}

static void stateBuildOn(StateDevice *dev, const Security_Config *cfg)
{
    stateBuildOnAs(dev, cfg, NWK_DEVICE_ROUTER, STATE_OWN_SHORT);
}

void stateBuildWith(StateDevice *dev, const Security_KeyDescriptor *keys, uint32_t keyCount,
                    const Security_IncomingEntry *windows, uint32_t windowCount,
                    const Security_KeyPairEntry *pairs, uint32_t pairCount)
{
    Security_Config cfg;

    stateConfigAt(&cfg, dev, keys, keyCount, windows, windowCount, pairs, pairCount);
    stateBuildOn(dev, &cfg);
}

void stateBuildTrustCentre(StateDevice *dev, uint64_t trustCenterIeee, const uint8_t *linkKeySeed)
{
    Security_KeyDescriptor keys[1];
    Security_KeyPairEntry pairs[2];
    Security_Config cfg;

    keys[0] = stateKeyAt(0x00, s_keyAHex, 5);
    pairs[0] = statePairAt(0, s_globalLinkKeyHex, 1, 0);
    pairs[0].linkKeyType = SECURITY_LINK_KEY_GLOBAL;
    pairs[1] = statePairAt(STATE_PEER_IEEE, s_linkKeyHex, 0x10, 0x20);

    stateConfigAt(&cfg, dev, keys, 1, 0, 0, pairs, 2);
    cfg.trustCenterIeee = trustCenterIeee;
    cfg.requireLinkKeyEncryption = 1;
    cfg.linkKeySeed = linkKeySeed;
    stateBuildOn(dev, &cfg);
}

void stateBuildEndDevice(StateDevice *dev, uint16_t ownShort)
{
    Security_KeyDescriptor keys[1];
    Security_Config cfg;

    keys[0] = stateKeyAt(0x00, s_keyAHex, 5);
    stateConfigAt(&cfg, dev, keys, 1, 0, 0, 0, 0);
    stateBuildOnAs(dev, &cfg, NWK_DEVICE_END_DEVICE, ownShort);
}

void stateBuild(StateDevice *dev)
{
    Security_KeyDescriptor keys[1];

    keys[0] = stateKeyAt(0x00, s_keyAHex, 5);
    stateBuildWith(dev, keys, 1, 0, 0, 0, 0);
}

void stateSend(StateDevice *dev)
{
    static const uint8_t nsdu[2] = { 0xaa, 0x55 };
    Nwk_DataRequestParameters req;

    Test_BandASeedNeighbor(&dev->rig.nwk, STATE_NEIGHBOR_SHORT, NWK_DEVICE_ROUTER, 1, NWK_REL_SIBLING);

    Zb_memset(&req, 0, (uint32_t)sizeof req);
    req.dstAddr = STATE_NEIGHBOR_SHORT;
    req.nsdu = nsdu;
    req.nsduLength = 2;

    Test_ExpectStatus(Nwk_DataRequest(&dev->rig.nwk, &req, 100), ZB_OK,
                      "one unicast leaves through the NLDE, so the sequence numbers this case captures moved by traffic and not by assignment");
}

void stateImage(const Security *security, uint8_t *out)
{
    Zb_memcpy(out, security, (uint32_t)sizeof *security);
}

int stateImageHeld(const Security *security, const uint8_t *image)
{
    return Zb_memcmp(security, image, (uint32_t)sizeof *security) == 0;
}

int stateIsZero(const uint8_t *octets, uint32_t len)
{
    uint32_t index;

    for (index = 0; index < len; index++)
    {
        if (octets[index] != 0)
            return 0;
    }

    return 1;
}

uint32_t stateKeyOf(const char *hex, uint8_t *out)
{
    return Test_ParseHex(hex, out, SECURITY_KEY_OCTETS);
}
