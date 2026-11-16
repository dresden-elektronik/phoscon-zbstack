/* The `security` suite's shared machinery.

   What two or more of the suite's cases use, once: the fixtures a case drives the module
   with (this device, the peer it protects for, the descriptors of the material set, the
   persisted windows and the key pairs) the few builders that make one descriptor, one window
   or one entry out of octets, the copy a case patches to make a frame that is a vector
   except for the one thing it is about, and the log sink the refusals are read back through.

   The constants here are the ones both halves of the suite read or `main` evaluates: this device's extended
   address, the peer's and the senders', the frame lengths every vector is quoted in, the two keys of the material
   set, and the intermediates `main` checks against Figure 4-26. A vector only one half's cases quote lives in
   that half's own case file, with the comment that says what it is. */

#ifndef SECURITY_HELPERS_H
#define SECURITY_HELPERS_H

#include <stdint.h>

#include "log.h"
#include "security.h"
#include "test_harness.h"

/* This device, the peer the round-trip cases send to, and the senders the incoming-pool case seeds.
   The extended address is the one the auxiliary source field of every frame this device protects
   carries (3.2.1.1.3, 4.5.1.3), and it is the same number in the nonce. */
#define OWN_IEEE 0x0123456789abcdef
#define PEER_IEEE 0x0011223344556677
#define SEEDED_IEEE 0x1000000000000000

/* The lengths every vector in this suite is quoted in: the NWK header, the source-routed one, the payload
   the cases protect and the long payload two of them go up to. */
#define HEADER_LEN 8
#define ROUTE_HEADER_LEN 16
#define PAYLOAD_LEN 7
#define LONG_PAYLOAD_LEN 32

/* The APS data header of a1, a2 and a4: FCF 0x20, frame type Data and delivery mode unicast
   (Table 2-20, Table 2-21), ACK format 0, the security sub-field set (bit 5, which is what 4.4.10 reads
   to place the auxiliary header), ACK request 0, no extended header, then destination endpoint 0x01,
   cluster identifier 0x0006, profile identifier 0x0104, source endpoint 0x03 and APS counter 0x11: the
   always-present fields of Figure 2-7 with the group address column absent, 8 octets. */
#define APS_HEADER_LEN 8
#define APS_REPLY_HEADER_LEN 8
#define APS_PAYLOAD_LEN 5
#define APS_REPLY_PAYLOAD_LEN 3

/* The two keys of this suite. Key A is the network key of vectors s1, s3, s4 and s5 at key sequence
   number 0x00; key B is the key s2 was secured with at 0x01: the pair Table 4-2's
   nwkSecurityMaterialSet is a set of. */
extern const char *s_keyAHex;
extern const char *s_keyBHex;

/* The link key of the APS vectors: Table 4-36's LinkKey, "the actual value of the link key", shared by
   this device (OWN_IEEE) and APS_PARTNER_IEEE. */
extern const char *s_linkKeyHex;

/* a1's 13 octets of CCM* nonce and the 21 octets its authenticated string is: ApsHeader || AuxiliaryHeader
   with the pre-overwrite control octet, the string 4.4.1.1 step 5d names for an encrypting level. */
extern const char *s_apsNonce1Hex;
extern const char *s_apsNonce2Hex;
extern const char *s_apsAdata1Hex;

/* The 13 octets the CCM* nonce of s1 is built from, quoted so a reader can check it
   against Figure 4-26 without the module at hand: source address, frame counter, security control
   before step 8. */
extern const char *s_nonce1Hex;

/* The 22 octets s1's authenticated string begins with: NwkHeader || AuxiliaryHeader. */
extern const char *s_adata1Hex;

/* A device of this stack, seeded the way an application seeds one, with its own log
   pool so the records a case asserts are the records that case made. */
typedef struct Fixture
{
    Log_Log log;
    Security security;
} Fixture;

/* The log sink: what the module recorded, drained so a case can name one of the records. */
void drainLog(Log_Log *log);
int logHas(uint16_t component, uint16_t reason, uint32_t argument);

/* One descriptor of the material set, one persisted incoming window, and the devices a case drives. */
Security_KeyDescriptor keyAt(uint8_t keySeqNumber, const char *keyHex, uint32_t outgoing);
Security_IncomingEntry windowAt(uint64_t senderIeee, uint8_t keySeqNumber, uint32_t counter);
void fixtureAt(Fixture *fixture, uint32_t level, uint64_t ownIeee, uint8_t activeSeq,
               const Security_KeyDescriptor *keys, uint32_t keyCount,
               const Security_IncomingEntry *windows, uint32_t windowCount, int nwkAllFresh);
void fixture5(Fixture *fixture, const Security_KeyDescriptor *keys, uint32_t keyCount, uint8_t activeSeq);

/* One entry of apsDeviceKeyPairSet, the pair the APS vectors are shared with, and the device that holds one. */
Security_KeyPairEntry keyPairAt(uint64_t deviceIeee, uint16_t shortAddress, int shortKnown,
                                uint32_t keyAttributes, const char *linkKeyHex,
                                uint32_t outgoing, uint32_t incoming,
                                uint32_t linkKeyType, uint8_t features, int verified);
Security_KeyPairEntry apsPair(uint64_t partner, uint32_t outgoing, uint32_t incoming);
void fixtureAps(Fixture *fixture, uint32_t level, uint64_t ownIeee,
                const Security_KeyPairEntry *pairs, uint32_t pairCount);
void fixtureAps5(Fixture *fixture, uint64_t ownIeee, const Security_KeyPairEntry *pairs, uint32_t pairCount);

/* A copy of a vector, and the counter of a copied vector rewritten in place. */
uint32_t copyVector(uint8_t *out, const char *hex);
void rewriteCounter(uint8_t *frame, uint32_t headerLen, uint32_t counter);

#endif /* SECURITY_HELPERS_H */
