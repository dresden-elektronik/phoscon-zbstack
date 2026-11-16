/* The `state` suite's shared machinery.

   What more than one case needs: a band-A device with a `Security` and an `Aps_Aps` on it (the four layers
   `Zb_StateCapture` reads and `Zb_StateRestore` writes) the builders for one Table 4-3 descriptor, one
   incoming window and one Table 4-36 pair, the one frame that moves the counters through real traffic, and
   the byte image a refusal is judged against.

   The keys and the s1 frame are the `security` suite's own fixtures, quoted again here because a suite's
   vectors are its own: the point of the second copy is that this suite protects a frame and
   compares it to the vector that suite pins, so the two suites cannot drift apart silently. */

#ifndef STATE_HELPERS_H
#define STATE_HELPERS_H

#include <stdint.h>

#include "aps.h"
#include "log.h"
#include "mac.h"
#include "nwk.h"
#include "rig_band_a.h"
#include "security.h"
#include "test_harness.h"
#include "zb_state.h"

/* This device's extended address (the one 3.2.1.1.3 puts in the auxiliary header of every frame it
   protects) and the three peer addresses the incoming store and the key-pair pool are keyed by. */
#define STATE_OWN_IEEE 0x0123456789abcdef
#define STATE_PEER_IEEE 0x0011223344556677
#define STATE_SECOND_IEEE 0x1000000000000000
#define STATE_THIRD_IEEE 0x2000000000000000

/* This device's address and PAN on the air, and the two addresses a send needs: a neighbour of this
   suite's own and one that is not. */
#define STATE_OWN_SHORT 0x0001
#define STATE_PAN_ID 0x1234
#define STATE_NEIGHBOR_SHORT 0x0002

/* The frame s1 of the `security` suite: 8-octet NWK header, the auxiliary header of counter 0x00000005 under
   key A at sequence number 0x00, the 7-octet payload and the 4-octet MIC. This suite protects a frame and
   compares it to this, which is how a restore that kept the right key is told from one that kept a key. */
extern const char *s_frame1Hex;

/* The two network keys and the link key (Table 4-3's Key, Table 4-36's LinkKey). */
extern const char *s_keyAHex;
extern const char *s_keyBHex;
extern const char *s_linkKeyHex;
extern const char *s_globalLinkKeyHex;   /* "ZigBeeAlliance09", the key a pair names no device under */

/* A band-A device as this suite builds it: the hardware-free backend, a MAC, the network layer on it, a
   security module the network layer and the APS service are attached to, and the record pool the module
   reports into, all of it caller-owned storage on the case's stack (§4.3). */
typedef struct StateDevice
{
    Test_BandA rig;
    Security security;
    Aps_Aps aps;
    Log_Log log;
} StateDevice;

/* The device a case starts from: a router at level 0x05 holding key A at sequence number 0x00 with outgoing
   counter 5 (the fixture every `security` vector is quoted at) joined and all-fresh, with no window and no
   key pair, and an APS service on the same `nwk` and `Security`. Nothing is sent, so the three sequence
   numbers are the rig's two zero seeds and APS_COUNTER_START. */
void stateBuild(StateDevice *dev);

/* The same device with a material set, windows and key pairs, as the application would have configured them
   at Security_Init; the counts are the sets, as Security_Config states them. */
void stateBuildWith(StateDevice *dev, const Security_KeyDescriptor *keys, uint32_t keyCount,
                    const Security_IncomingEntry *windows, uint32_t windowCount,
                    const Security_KeyPairEntry *pairs, uint32_t pairCount);

/* The device as a trust centre configures it: key A, the global link key in a pair that names no device beside a
   unique pair for the peer, the trust centre's address, link-key encryption required for a transported key, and
   the seed 4.7.3.8.1 lets a trust centre derive each device's link key from. */
void stateBuildTrustCentre(StateDevice *dev, uint64_t trustCenterIeee, const uint8_t *linkKeySeed);

/* The device as an end device, holding key A, at `ownShort`: 0xffff is one that booted with no address yet. */
void stateBuildEndDevice(StateDevice *dev, uint16_t ownShort);

/* One descriptor, one window and one pair. */
Security_KeyDescriptor stateKeyAt(uint8_t keySeqNumber, const char *keyHex, uint32_t outgoing);
Security_IncomingEntry stateWindowAt(uint64_t senderIeee, uint8_t keySeqNumber, uint32_t counter);
Security_KeyPairEntry statePairAt(uint64_t deviceIeee, const char *linkKeyHex,
                                  uint32_t outgoing, uint32_t incoming);

/* One NLDE unicast to a seeded neighbour, so the NWK sequence number and the MAC DSN move the way traffic
   moves them rather than by assignment: 3.3.1.5 and the MAC's own numbering, driven through the stack. */
void stateSend(StateDevice *dev);

/* The security module as bytes, and whether it is still those bytes: what a refused restore is judged
   against, because "nothing was touched" is a claim about the whole struct (pools, counters, scratch, the
   level, the identity and the record pool) and not about the fields a case thought to name. */
void stateImage(const Security *security, uint8_t *out);
int stateImageHeld(const Security *security, const uint8_t *image);

/* Whether a 16-octet field is all zero. */
int stateIsZero(const uint8_t *octets, uint32_t len);

/* The key octets a hex vector names, for a comparison against what a capture carried. */
uint32_t stateKeyOf(const char *hex, uint8_t *out);

#endif /* STATE_HELPERS_H */
