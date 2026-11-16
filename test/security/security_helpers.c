/* The `security` suite's shared machinery: the bodies. See `security_helpers.h` for what this file is and why
   it is here. */

#include "log.h"
#include "security.h"
#include "security_helpers.h"
#include "test_harness.h"
#include "zb_utils.h"

const char *s_keyAHex = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
const char *s_keyBHex = "101112131415161718191a1b1c1d1e1f";
const char *s_linkKeyHex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
const char *s_apsNonce1Hex = "efcdab89674523010400000065";
const char *s_apsNonce2Hex = "efcdab89674523010500000045";
const char *s_apsAdata1Hex = "20010600040103116504000000efcdab8967452301";
const char *s_nonce1Hex = "efcdab8967452301050000002d";
const char *s_adata1Hex = "0802010000001e052d05000000efcdab896745230100";

/* The memory sink: the records this module made, collected so a case can name one. The same few
   lines `test_log.c` uses for the pool itself. */
static Log_Record s_sink[LOG_RING_MAX];
static uint32_t s_sinkCount;

static void memSinkWrite(void *context, const Log_Record *record)
{
    (void)context;

    if (s_sinkCount < LOG_RING_MAX)
        s_sink[s_sinkCount] = *record;

    s_sinkCount++;
}

void drainLog(Log_Log *log)
{
    Log_Sink sink;

    s_sinkCount = 0;
    sink.context = 0;
    sink.write = memSinkWrite;
    Log_Drain(log, &sink);
}

int logHas(uint16_t component, uint16_t reason, uint32_t argument)
{
    uint32_t index;

    for (index = 0; index < s_sinkCount; index++)
    {
        if (s_sink[index].component == component && s_sink[index].reason == reason
            && s_sink[index].argument == argument)
            return 1;
    }

    return 0;
}

/* One descriptor of the material set, with the counter this device would transmit with under it. */
Security_KeyDescriptor keyAt(uint8_t keySeqNumber, const char *keyHex, uint32_t outgoing)
{
    Security_KeyDescriptor descriptor;

    Zb_memset(&descriptor, 0, (uint32_t)sizeof descriptor);
    descriptor.keySeqNumber = keySeqNumber;
    descriptor.inUse = 1;
    descriptor.outgoingFrameCounter = outgoing;
    Test_ParseHex(keyHex, descriptor.key, SECURITY_KEY_OCTETS);

    return descriptor;
}

/* One persisted incoming window: the sender's extended address as the auxiliary header named it, the
   key it belongs to, and the next count the module will refuse (4.3.1.2 step 6 stores
   ReceivedFrameCount + 1). */
Security_IncomingEntry windowAt(uint64_t senderIeee, uint8_t keySeqNumber, uint32_t counter)
{
    Security_IncomingEntry entry;

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.senderIeee = senderIeee;
    entry.keySeqNumber = keySeqNumber;
    entry.inUse = 1;
    entry.frameCounter = counter;

    return entry;
}

void fixtureAt(Fixture *fixture, uint32_t level, uint64_t ownIeee, uint8_t activeSeq,
               const Security_KeyDescriptor *keys, uint32_t keyCount,
               const Security_IncomingEntry *windows, uint32_t windowCount, int nwkAllFresh)
{
    Security_Config cfg;

    Zb_memset(fixture, 0, (uint32_t)sizeof *fixture);
    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);

    Log_Init(&fixture->log);

    cfg.ownIeee = ownIeee;
    cfg.nwkSecurityLevel = (uint8_t)level;
    cfg.nwkActiveKeySeqNumber = activeSeq;
    cfg.authenticated = 1;
    cfg.nwkAllFresh = nwkAllFresh;
    cfg.keys = keys;
    cfg.keyCount = keyCount;
    cfg.incomingSeeds = windows;
    cfg.incomingSeedCount = windowCount;
    cfg.log = &fixture->log;

    Test_ExpectStatus(Security_Init(&fixture->security, &cfg), ZB_OK, "the fixture's security module initialised");
}

void fixture5(Fixture *fixture, const Security_KeyDescriptor *keys, uint32_t keyCount,
              uint8_t activeSeq)
{
    fixtureAt(fixture, SECURITY_LEVEL_ENC_MIC_32, OWN_IEEE, activeSeq, keys, keyCount, 0, 0, 1);
}

/* One entry of apsDeviceKeyPairSet, seeded the way an application seeds it: the partner
   the key pair is shared with (Table 4-36's DeviceAddress), an optional 16-bit alias, an attribute from the
   gate of 4.4.1.1 step 1a-ii, the link key, both counters, and the peer's Features & Capabilities bit. */
Security_KeyPairEntry keyPairAt(uint64_t deviceIeee, uint16_t shortAddress, int shortKnown,
                                uint32_t keyAttributes, const char *linkKeyHex,
                                uint32_t outgoing, uint32_t incoming,
                                uint32_t linkKeyType, uint8_t features, int verified)
{
    Security_KeyPairEntry entry;

    Zb_memset(&entry, 0, (uint32_t)sizeof entry);
    entry.deviceIeee = deviceIeee;
    entry.shortAddress = shortAddress;
    entry.shortKnown = shortKnown;
    entry.keyAttributes = keyAttributes;
    entry.outgoingFrameCounter = outgoing;
    entry.incomingFrameCounter = incoming;
    entry.linkKeyType = linkKeyType;
    entry.featuresCapabilities = features;
    entry.verifiedFrameCounter = verified;
    Test_ParseHex(linkKeyHex, entry.key, SECURITY_KEY_OCTETS);

    return entry;
}

/* The pair the APS vectors are shared with, as this device (ownIeee) holds it: VERIFIED, unique, no peer
   capability recorded (the config band A carries) with both counters where the case
   wants them and no short alias unless the case names one. */
Security_KeyPairEntry apsPair(uint64_t partner, uint32_t outgoing, uint32_t incoming)
{
    return keyPairAt(partner, 0x0000, 0, SECURITY_KEYPAIR_ATTR_VERIFIED, s_linkKeyHex,
                     outgoing, incoming, SECURITY_LINK_KEY_UNIQUE, SECURITY_FEATURES_NONE, 1);
}

/* A device of this stack that also holds link keys. The one network descriptor is not decoration:
   Security_Init refuses a non-zero level with no descriptor under the active sequence number, so an APS fixture at the NIB default level is seeded with network material it never uses,
   Security_ProtectAps and Security_UnprotectAps work off the pair pool and never read a descriptor, which
   is what the snapshot assertions in these cases read back as an untouched network counter. */
void fixtureAps(Fixture *fixture, uint32_t level, uint64_t ownIeee,
                const Security_KeyPairEntry *pairs, uint32_t pairCount)
{
    Security_Config cfg;
    Security_KeyDescriptor keys[1];

    keys[0] = keyAt(0x00, s_keyAHex, 1);

    Zb_memset(fixture, 0, (uint32_t)sizeof *fixture);
    Zb_memset(&cfg, 0, (uint32_t)sizeof cfg);

    Log_Init(&fixture->log);

    cfg.ownIeee = ownIeee;
    cfg.nwkSecurityLevel = (uint8_t)level;
    cfg.nwkActiveKeySeqNumber = 0x00;
    cfg.authenticated = 1;
    cfg.nwkAllFresh = 1;
    cfg.keys = keys;
    cfg.keyCount = 1;
    cfg.keyPairs = pairs;
    cfg.keyPairCount = pairCount;
    cfg.log = &fixture->log;

    Test_ExpectStatus(Security_Init(&fixture->security, &cfg), ZB_OK, "the APS fixture's security module initialised");
}

/* The same fixture at the NIB default level, as the device whose address is `ownIeee`. */
void fixtureAps5(Fixture *fixture, uint64_t ownIeee, const Security_KeyPairEntry *pairs,
                 uint32_t pairCount)
{
    fixtureAps(fixture, SECURITY_LEVEL_ENC_MIC_32, ownIeee, pairs, pairCount);
}

/* A copy of a vector, so a case can patch one field of it and hand the module a frame that is the
   vector except for the one thing the case is about. */
uint32_t copyVector(uint8_t *out, const char *hex)
{
    return Test_ParseHex(hex, out, SECURITY_FRAME_MAX);
}

/* The frame counter of a copied vector, rewritten in place at its auxiliary-header offset. The MIC
   of the frame is now wrong by construction: these cases are about the refusal that fires before the
   MIC is ever looked at. */
void rewriteCounter(uint8_t *frame, uint32_t headerLen, uint32_t counter)
{
    frame[headerLen + 1] = (uint8_t)(counter & 0xff);
    frame[headerLen + 2] = (uint8_t)((counter >> 8) & 0xff);
    frame[headerLen + 3] = (uint8_t)((counter >> 16) & 0xff);
    frame[headerLen + 4] = (uint8_t)((counter >> 24) & 0xff);
}
