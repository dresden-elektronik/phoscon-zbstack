#ifndef ZB_STATE_H
#define ZB_STATE_H

/*
 * The persistence boundary: a plain C state object in and out, serialised by the application. No
 * pointer, no clock, no storage call. Every array carries its count, entries are keyed by content rather
 * than index, a restore validates before it wipes, and counters only move forward.
 */

#include <stdint.h>

#include "aps.h"
#include "mac.h"
#include "nwk.h"
#include "security.h"
#include "zb_status.h"

/* The schema number the application records for this object, and the oldest one a restore still takes: version 1
   has no channel, which the config then names. Any other is refused. */
#define ZB_STATE_VERSION 2
#define ZB_STATE_VERSION_OLDEST 1

enum
{
    /* What a restored outgoing counter is advanced by: a state from an earlier boot must not rewind one
       (9.2.4). One octet's whole bank is a single step. */
    ZB_STATE_COUNTER_BANK = 256,
    ZB_STATE_OCTET_STEP = 1,
    /* One step, not the bank: a sequence number is incremented before it is carried, a counter is not. */
    ZB_STATE_SEQUENCE_STEP = 1
};

/* One entry of Table 4-2's nwkSecurityMaterialSet: Table 4-3's KeySeqNumber and OutgoingFrameCounter with
   the key behind the `keyPresent` opt-in. `keyPresent` 0 leaves `key` zero and asks a restore to keep the key
   this boot was configured with. */
typedef struct Zb_StateKey
{
    uint8_t keySeqNumber;
    uint32_t outgoingFrameCounter;
    int keyPresent;                   /* the per-entry opt-in */
    uint8_t key[SECURITY_KEY_OCTETS];
} Zb_StateKey;

/* One window of the incoming store 4.3.1.2 steps 3 and 6 keep. */
typedef struct Zb_StateWindow
{
    uint64_t senderIeee;              /* the previous hop that secured the frame, not the originator */
    uint8_t keySeqNumber;
    uint32_t frameCounter;            /* ReceivedFrameCount + 1, the value step 6 stores */
} Zb_StateWindow;

/* One entry of `apsDeviceKeyPairSet`, the Table 4-36 core the application configures. 4.4.12.1 persists neither
   IncomingFrameCounter nor VerifiedFrameCounter: a restore starts the first at 0 and the second FALSE (4.6.3.8). */
typedef struct Zb_StatePair
{
    uint64_t deviceIeee;
    uint16_t shortAddress;            /* the optional alias, meaningful only when shortKnown is 1 */
    int shortKnown;
    uint32_t keyAttributes;
    uint32_t linkKeyType;
    uint32_t outgoingFrameCounter;
    uint8_t featuresCapabilities;
    int keyPresent;                   /* the per-entry opt-in */
    uint8_t linkKey[SECURITY_KEY_OCTETS];
} Zb_StatePair;

/* 3.6.9's per-child list: what a parent must keep for each of its end devices. */
typedef struct Zb_StateChild
{
    uint64_t extendedAddress;
    uint16_t networkAddress;
    uint32_t endDeviceConfiguration;
    uint32_t deviceTimeout;
} Zb_StateChild;

typedef struct Zb_State
{
    uint32_t version;                 /* ZB_STATE_VERSION */
    uint64_t ownIeee;
    uint32_t deviceType;              /* NWK_DEVICE_*: a restore takes only the role that captured it */
    uint64_t trustCenterIeee;         /* apsTrustCenterAddress, which 4.4.12.1 persists */

    /* 3.6.9's SHOULD list and the device's own place in the network */
    uint16_t panId;
    uint64_t extendedPanId;
    uint16_t networkAddress;
    uint32_t nwkUpdateId;
    uint32_t channel;                 /* the MAC interface's, which the SHOULD list keeps; 0: the config names it */
    uint32_t parentInformation;
    uint16_t parentShort;             /* an end device's, which 3.6.9 lists for an end device alone; 0 for the others */
    uint64_t parentIeee;              /* beside it, for the end device's timeout request */
    uint32_t stackProfile;

    /* 3.6.9's SHALL list for a parent: one row per end device in its neighbour table */
    uint32_t childCount;
    Zb_StateChild children[NWK_NEIGHBOR_MAX];
    uint32_t nwkSecurityLevel;
    uint8_t nwkActiveKeySeqNumber;
    int authenticated;                /* the joined flag 3.6.2.2's policy reads */
    int nwkAllFresh;                  /* the incoming pool's full policy */

    uint32_t keyCount;
    Zb_StateKey keys[SECURITY_KEY_SET_MAX];

    uint32_t windowCount;
    Zb_StateWindow windows[SECURITY_INCOMING_MAX];

    uint32_t pairCount;
    Zb_StatePair pairs[SECURITY_KEYPAIR_MAX];

    uint32_t nwkSequenceNumber;       /* one octet's worth (3.3.1.5) */
    uint32_t nwkRoutingSequenceNumber; /* NIB 0xBE: Table 3-66's 0-0xffff, persisted */
    uint32_t macDsn;
    uint32_t apsCounter;
} Zb_State;

/* Capture: the object is zeroed first, so a count bounds the content. `includeKeys` 0 leaves both
   key fields zero and every `keyPresent` 0. ZB_ERR_BAD_ARGUMENT for a 0 pointer. */
ZbStatus Zb_StateCapture(const Security *security, const Nwk_Nwk *nwk, const Aps_Aps *aps, const Mac_Mac *mac,
                         int includeKeys, Zb_State *out);

/* Restore in one order: validate the whole set (version, role, an end device's parent, bounds, duplicate names,
   counters a bank short of 2^32-1, and what `Security_Init` would refuse) before anything is touched; then wipe the
   security module and fill it, keeping the key this boot holds where `keyPresent` is 0 (ZB_ERR_AUTH first if there
   is none) and this boot's link-key seed and transport-key policy, which are configuration and not state; then move
   the outgoing counters forward by the bank, the three octet counters by one step and the routing sequence number
   by the bank; then put the device back in its place: the PAN, the address, the extended PAN, the parent
   information, the children, the trust centre the network layer checks, and the joined state with an end device's
   parent. The routing and address tables are not written. A refusal changes nothing. */
ZbStatus Zb_StateRestore(Security *security, Nwk_Nwk *nwk, Aps_Aps *aps, Mac_Mac *mac, const Zb_State *in);

#endif /* ZB_STATE_H */
