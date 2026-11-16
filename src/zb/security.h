#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>

#include "log.h"
#include "zb_limits.h"
#include "zb_status.h"

enum
{
    SECURITY_KEY_SET_MAX = 2,
    SECURITY_KEY_OCTETS = 16,
    SECURITY_INCOMING_MAX = ZB_LIMIT_SECURITY_INCOMING,
    SECURITY_AUX_LEN = 14,
    SECURITY_NONCE_LEN = 13,
    SECURITY_FRAME_MAX = 127,
    SECURITY_HEADER_MAX = 112,

    /* 4.4.1.1 step 8's bound on the secured APSDU, which is the MSDU the network layer carries: aMaxMACFrameSize,
       Annex D.5's aMaxPHYPacketSize less nwkcMinHeaderOverhead (Table 3-65's 0x08) */
    SECURITY_APS_MSDU_MAX = 127 - 8,

    SECURITY_KEYPAIR_MAX = ZB_LIMIT_SECURITY_KEYPAIR,
    SECURITY_APS_AUX_MIN = 5,
    SECURITY_APS_AUX_MAX = 13,
    SECURITY_APS_HEADER_MAX = 13,

    SECURITY_CONTROL_LEVEL_SHIFT = 0,
    SECURITY_CONTROL_KEY_ID_SHIFT = 3,
    SECURITY_CONTROL_EXTENDED_NONCE_SHIFT = 5,
    SECURITY_CONTROL_RVFC_SHIFT = 6,
    SECURITY_CONTROL_LEVEL_MASK = 0x07,
    SECURITY_CONTROL_KEY_ID_MASK = 0x03,
    SECURITY_CONTROL_EXTENDED_NONCE_MASK = 0x01,
    SECURITY_CONTROL_RVFC_MASK = 0x01,
    SECURITY_CONTROL_MAX = 0xFF,

    SECURITY_KEY_ID_DATA = 0x00,          /* Table 4-39: a data key, which 4.5.3 makes the link key itself */
    SECURITY_KEY_ID_NETWORK = 0x01,       /* Table 4-39: a network key, which 4.4.1.1 never selects and 4.4.1.2 has no branch for */
    SECURITY_KEY_ID_KEY_TRANSPORT = 0x02, /* Table 4-39: the key-transport key, selected for a transported network key (4.4.1.1 step 1 b ii) */
    SECURITY_KEY_ID_KEY_LOAD = 0x03,      /* Table 4-39: the key-load key, selected for a transported link key */

    /* 4.5.3's hash inputs, and the trap in them: the identifier and the octet hashed are not the same number.
       The key-transport key (identifier 02) is the keyed hash of 0x00 and the key-load key (identifier 03) that
       of 0x02, each under the link key. */
    SECURITY_KEY_HASH_TRANSPORT_INPUT = 0x00,
    SECURITY_KEY_HASH_LOAD_INPUT = 0x02,
    SECURITY_KEY_HASH_VERIFY_INPUT = 0x03, /* 4.4.11.7.4: the Initiator Verify-Key Hash Value's one-octet input */

    /* The two APS frame control fields 4.4.1.1 step 4 a reads off ApsHeader (Figure 2-4) */
    SECURITY_APS_FRAME_TYPE_MASK = 0x03,
    SECURITY_APS_FRAME_TYPE_DATA = 0x00,
    SECURITY_APS_FRAME_TYPE_COMMAND = 0x01,
    SECURITY_APS_FRAME_TYPE_ACK = 0x02,
    SECURITY_APS_ACK_FORMAT_SHIFT = 4,

    SECURITY_KEYPAIR_ATTR_PROVISIONAL = 0x00,
    SECURITY_KEYPAIR_ATTR_UNVERIFIED = 0x01,
    SECURITY_KEYPAIR_ATTR_VERIFIED = 0x02,

    SECURITY_LINK_KEY_UNIQUE = 0x00,
    SECURITY_LINK_KEY_GLOBAL = 0x01,

    SECURITY_FEATURES_NONE = 0x00,
    SECURITY_FEATURES_FRAME_COUNTER_SYNC = 0x01,

    SECURITY_LEVEL_NONE = 0x00,
    SECURITY_LEVEL_MIC_32 = 0x01,
    SECURITY_LEVEL_MIC_64 = 0x02,
    SECURITY_LEVEL_MIC_128 = 0x03,
    SECURITY_LEVEL_ENC = 0x04,
    SECURITY_LEVEL_ENC_MIC_32 = 0x05,
    SECURITY_LEVEL_ENC_MIC_64 = 0x06,
    SECURITY_LEVEL_ENC_MIC_128 = 0x07,
    SECURITY_LEVEL_MAX = 0x07,

    SECURITY_LEVEL_ENCRYPTED_MASK = 0x04,

    SECURITY_MIC_32_OCTETS = 4,
    SECURITY_MIC_64_OCTETS = 8,
    SECURITY_MIC_128_OCTETS = 16,
    SECURITY_MIC_MAX = 16,

    /* Half of Table 4-3's KeySeqNumber octet: the distance a number may lie ahead of the active one and still be
       the newer of the two (4.3.1.2 step 7). */
    SECURITY_KEY_SEQ_HALF = 0x80
};

#define SECURITY_FRAME_COUNTER_LAST 0xffffffff

typedef struct Security_KeyDescriptor
{
    uint8_t keySeqNumber;
    int inUse;
    uint8_t key[SECURITY_KEY_OCTETS];
    uint32_t outgoingFrameCounter;
} Security_KeyDescriptor;

typedef struct Security_IncomingEntry
{
    uint64_t senderIeee;
    uint8_t keySeqNumber;
    int inUse;
    uint32_t frameCounter;
} Security_IncomingEntry;

typedef struct Security_KeyPairEntry
{
    uint64_t deviceIeee;
    uint16_t shortAddress;
    int shortKnown;
    uint32_t keyAttributes;
    uint8_t key[SECURITY_KEY_OCTETS];
    uint32_t outgoingFrameCounter;
    uint32_t incomingFrameCounter;
    uint32_t linkKeyType;
    uint8_t featuresCapabilities;
    int verifiedFrameCounter;
} Security_KeyPairEntry;

typedef struct Security_Config
{
    uint64_t ownIeee;
    uint64_t trustCenterIeee;      /* apsTrustCenterAddress (4.6.3.1), whose initial value is all-F: a distributed
                                      security network, where 4.4.1.3's trust-centre test does not apply */
    int requireLinkKeyEncryption;  /* requireLinkKeyEncryptionForApsTransportKey (4.4.2.3) */
    uint8_t nwkSecurityLevel;
    uint8_t nwkActiveKeySeqNumber;
    int authenticated;
    int nwkAllFresh;
    const Security_KeyDescriptor *keys;
    uint32_t keyCount;
    const Security_IncomingEntry *incomingSeeds;
    uint32_t incomingSeedCount;
    const Security_KeyPairEntry *keyPairs;
    uint32_t keyPairCount;
    const uint8_t *linkKeySeed;    /* 16 octets a trust centre derives each device's link key from (D-218), or 0 */
    Log_Log *log;
} Security_Config;

typedef struct Security_KeyState
{
    uint8_t nwkActiveKeySeqNumber;
    uint32_t keyCount;
    uint8_t keySeqNumber[SECURITY_KEY_SET_MAX];
    uint32_t outgoingFrameCounter[SECURITY_KEY_SET_MAX];
    uint32_t keyPairCount;
    uint64_t keyPairDeviceIeee[SECURITY_KEYPAIR_MAX];
    uint32_t keyPairOutgoingFrameCounter[SECURITY_KEYPAIR_MAX];
} Security_KeyState;

typedef struct Security_Result
{
    uint64_t senderIeee;
    uint8_t keySeqNumber;
    uint32_t frameCounter;
    int activeKeyAdopted;
} Security_Result;

typedef struct Security_ApsResult
{
    int keyPairIndex;
    uint64_t partnerIeee;
    uint32_t frameCounter;
    int rvfcSeen;
} Security_ApsResult;

typedef struct Security
{
    uint64_t ownIeee;
    uint64_t trustCenterIeee;
    int requireLinkKeyEncryption;
    uint32_t nwkSecurityLevel;
    uint8_t nwkActiveKeySeqNumber;
    int authenticated;
    int nwkAllFresh;
    Log_Log *log;

    Security_KeyDescriptor keys[SECURITY_KEY_SET_MAX];
    Security_IncomingEntry incoming[SECURITY_INCOMING_MAX];
    Security_KeyPairEntry keyPairs[SECURITY_KEYPAIR_MAX];
    uint32_t keyPairCount;
    uint8_t linkKeySeed[SECURITY_KEY_OCTETS];
    int linkKeySeedKnown;

    uint8_t adata[SECURITY_FRAME_MAX];
    uint8_t frame[SECURITY_FRAME_MAX];
} Security;

ZbStatus Security_Init(Security *self, const Security_Config *cfg);

void Security_Reset(Security *self);

ZbStatus Security_Restore(Security *self, const Security_Config *cfg);

int Security_IsEnabled(const Security *self);

/* A level with no key in the set is the joining device of 4.6.3.2.4: it can do security and has not been given the
   network key yet, so a transmit asking for it fails NO_KEY rather than being refused at configuration. */

/* Install a network key as 4.6.3.4.2 prints it. In the normal operating state only a key from the trust center is
   accepted and it replaces the alternate; outside it (the join) the key replaces the active one. ZB_OK, ZB_ERR_AUTH
   for a key refused, ZB_ERR_BAD_STATE for the active number re-sent with other octets, ZB_ERR_BAD_ARGUMENT for 0. */
ZbStatus Security_InstallNetworkKey(Security *self, const uint8_t key[SECURITY_KEY_OCTETS],
                                    uint8_t keySeqNumber, int normalOperating, int fromTrustCenter);

/* A trust-centre key is what 4.6.3.2.3 makes a joining device authorized with, so the install above sets the state
   this reads: the join's wait for the key ends there and the network layer's unsecured discard begins. */

/* 4.6.3.8's last paragraph: the pair the transport key arrived from is verified, and its counter is the one that
   command carried, because no earlier message can be replayed to a device that has just joined. ZB_ERR_NOT_FOUND
   for an index the pool does not hold. */
ZbStatus Security_VerifyKeyPair(Security *self, int index, uint32_t frameCounter);

/* 4.7.3.8.1 step 1's key, derived as D-56 asks: the keyed hash of the device's address under the configured seed, so a
   device that asks twice is given the same key (D-218). ZB_ERR_UNSUPPORTED with no seed. */
ZbStatus Security_DeriveLinkKey(const Security *self, uint64_t deviceIeee, uint8_t out[SECURITY_KEY_OCTETS]);

/* 4.7.3.8.1 step 2: the device's own entry, unique and unverified, written over an earlier one for the same device or
   appended. The index, or -1 when the set is full (step 3). */
int Security_SetUnverifiedPair(Security *self, uint64_t deviceIeee, uint16_t shortAddress,
                               const uint8_t key[SECURITY_KEY_OCTETS]);

/* 4.7.3.1's entry for a device joining with no key of its own (12443-12449), written over the device's own entry in
   its place: the global key, PROVISIONAL, its outgoing counter kept. For an operator who removed the device, since a
   Device Left takes no security action (10591-10593). The index, or -1 for a device with no entry of its own. */
int Security_ForgetLinkKey(Security *self, uint64_t deviceIeee);

/* 4.4.7.2.3 step 9 with 4.4.8.1 step 7: the entry verified and its incoming counter back to 0. */
ZbStatus Security_ConfirmKeyPair(Security *self, int index);

/* 4.4.11.7.4: B.1.4's keyed hash of 0x03 under the entry's link key. */
ZbStatus Security_VerifyKeyHash(const Security_KeyPairEntry *entry, uint8_t out[SECURITY_KEY_OCTETS]);

/* Every NWK incoming window kept for one sender goes, under every key: a device that has just associated anew starts
   from whatever counter it sends, which a device that restarted its counter at a factory reset needs (D-219). */
void Security_ForgetSender(Security *self, uint64_t senderIeee);

int Security_IsAuthenticated(const Security *self);

/* What NWK protection adds to a frame at this level: the auxiliary header and the MIC (4.3.1.1 step 5). */
uint32_t Security_NwkOverhead(const Security *self);

uint8_t Security_Level(const Security *self);

ZbStatus Security_Protect(Security *self, const uint8_t *header, uint32_t headerLen,
                          const uint8_t *payload, uint32_t payloadLen,
                          uint8_t *outNpdu, uint32_t outMax, uint32_t *outLen);

ZbStatus Security_Unprotect(Security *self, const uint8_t *npdu, uint32_t npduLen, uint32_t headerLen,
                            uint8_t *plainOut, uint32_t plainMax, uint32_t *plainLen,
                            Security_Result *resultOut);

int Security_KeyPairCount(const Security *self);

/* The network key nwkActiveKeySeqNumber names, or 0 when the set holds none: what a trust centre sends a joiner. */
const Security_KeyDescriptor *Security_ActiveNetworkKey(const Security *self);

int Security_FindKeyPairByIeee(const Security *self, uint64_t ieee);

int Security_FindKeyPairByShort(const Security *self, uint16_t shortAddress);

const Security_KeyPairEntry *Security_KeyPairAt(const Security *self, int index);

/* The material an auxiliary key identifier selects out of one pair: the link key for 00, and for 02 and 03 the two
   derivatives of 4.5.3. ZB_OK, or ZB_ERR_BAD_ARGUMENT for a 0 pointer or an identifier outside Table 4-39, 01 among
   them because 4.4.1.2 prints no branch for a network key. */
ZbStatus Security_KeyForIdentifier(const Security_KeyPairEntry *entry, uint32_t keyIdentifier,
                                   uint8_t out[SECURITY_KEY_OCTETS]);

/* 4.4.1.1 over one APDU. The frame type in header[0] decides three things the caller does not: a command always carries
   the extended nonce (step 4 a ii), the Require Verified Frame Counter bit follows Table 4-41, and an identifier other
   than 00 is refused on anything but a command (step 1); an UNVERIFIED pair encrypts nothing, so the global one does. */
ZbStatus Security_ProtectAps(Security *self, int keyPairIndex, uint32_t keyIdentifier, const uint8_t *header, uint32_t headerLen,
                             const uint8_t *payload, uint32_t payloadLen, int extendedNonce,
                             uint8_t *outSecured, uint32_t outMax, uint32_t *outLen);

ZbStatus Security_UnprotectAps(Security *self, const uint8_t *apsdu, uint32_t apsduLen, uint32_t headerLen,
                               uint64_t partnerHint, int hintKnown,
                               uint8_t *plainOut, uint32_t plainMax, uint32_t *plainLen,
                               Security_ApsResult *resultOut);

void Security_Snapshot(const Security *self, Security_KeyState *out);

#endif
