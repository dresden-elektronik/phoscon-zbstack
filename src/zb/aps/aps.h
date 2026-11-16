#ifndef APS_H
#define APS_H

/*
 * Band A's APS data service: the APSDE-DATA request, confirm and indication of 2.2.4.1, spoken over the NLDE
 * pair of 3.2.1 through the `aps_frame` codec, with the one crossing into chapter 4 that 2.2.5.1.1.4 names,
 * 4.4.1.1 out, 4.4.1.2 in, over the `Security` this module adopts as `nwk` adopts it. What the slice
 * enforces and what it defers is docs/internals/conformance.md §3.
 *
 * Decided here and nowhere else: the APS counter, the delivery mode a request implies, the acknowledgement
 * ask, the wait charged to each transmission, the order an answer is given in (2.2.4.1.1.3), the order a
 * received frame is decided in (2.2.8.4.2), group membership, what a duplicate is, which key pair a secured
 * frame uses and who it came from. A transaction is answered through the confirmation
 * ring and only there; a delivery leaves through the indication ring and only there; an acknowledgement this
 * device owes is composed into scratch and issued straight down the seam, as `nwk` issues a relay.
 *
 * Core module: no allocation, no wall clock, no device call, every pool in the caller's `Aps_Aps`, time as
 * `nowMs` (docs/internals/coding-rules.md §4.1-§4.3). `nwk` and `security` are adopted by pointer and never owned.
 */

#include <stdint.h>

#include "aps_dup.h"
#include "aps_bind.h"
#include "aps_frame.h"
#include "aps_group.h"
#include "nwk.h"
#include "nwk_relay.h"
#include "radio.h"
#include "zb_status.h"

/*
 * Table 2-29 "APS Sub-layer Status Values", every row the table prints, in the table's order and words. Six
 * are answers this module gives now; the rest are named so a later slice cannot invent a number for them
 * (Tables 2-3, 2-4, 2-15, 2-17). 0xa0 starts the band because 0x00 is SUCCESS, and the gaps at
 * 0xab-0xac and 0xb0-0xb2 are the table's own.
 */
enum
{
    APS_STATUS_SUCCESS = 0x00,
    APS_STATUS_ASDU_TOO_LONG = 0xa0,
    APS_STATUS_DEFRAG_DEFERRED = 0xa1,
    APS_STATUS_DEFRAG_UNSUPPORTED = 0xa2,
    APS_STATUS_ILLEGAL_REQUEST = 0xa3,
    APS_STATUS_INVALID_BINDING = 0xa4,
    APS_STATUS_INVALID_GROUP = 0xa5,
    APS_STATUS_INVALID_PARAMETER = 0xa6,
    APS_STATUS_NO_ACK = 0xa7,
    APS_STATUS_NO_BOUND_DEVICE = 0xa8,
    APS_STATUS_NO_SHORT_ADDRESS = 0xa9,
    APS_STATUS_NOT_SUPPORTED = 0xaa,
    APS_STATUS_SECURED_LINK_KEY = 0xab,
    APS_STATUS_SECURED_NWK_KEY = 0xac,
    APS_STATUS_SECURITY_FAIL = 0xad,
    APS_STATUS_TABLE_FULL = 0xae,
    APS_STATUS_UNSECURED = 0xaf,
    APS_STATUS_UNSUPPORTED_ATTRIBUTE = 0xb0,
    APS_STATUS_PEER_CANNOT_FRAGMENT = 0xb1,
    APS_STATUS_UNKNOWN_FRAGMENT_SUPPORT = 0xb2,

    /* Not a printed code: an NLDE request the NWK layer refused at its own door left no confirmation to copy
       (Table 2-3; the honesty of `NWK_STATUS_LAST_MAC_STATUS` one layer down) */
    APS_STATUS_LAST_SEAM_STATUS = 0xff
};

/*
 * Table 2-2's `TxOptions` bitmap, one named bit per printed value, split as this slice splits them with
 * the APS security crossing wired in: 0x01 honoured for a unicast and refused as an argument error for anything
 * else (4.4.1 prints no key-selection rule for a group- or broadcast-addressed send), 0x02 and 0x04 honoured,
 * 0x08 accepted and ignored, 0x10 honoured as the extended nonce where 0x01 is set (4.4.1.1 step 4a-ii).
 */
enum
{
    APS_TX_OPTION_SECURITY = 0x01,
    APS_TX_OPTION_NWK_KEY = 0x02,
    APS_TX_OPTION_ACK = 0x04,
    APS_TX_OPTION_FRAGMENT = 0x08,
    APS_TX_OPTION_EXTENDED_NONCE = 0x10,

    APS_TX_OPTIONS_MAX = 0x1f               /* Table 2-2 prints the range as "0000 0000 – 0001 1111" */
};

/*
 * Table 2-4's SecurityStatus and KeyIndex, spelled apart from the Status values above because the table prints
 * them as different fields with different vocabularies. The two 0xff sentinels are band A's own: Table 2-4
 * prints no fourth SecurityStatus and Table 4-36's KeyAttributes has no "no key" member, so a frame that
 * claimed security without this layer being able to say with what, and a delivery that involved no key pair,
 * name the sentinel instead of a printed code. An *unsecured* indication keeps the
 * printed word, APS_STATUS_UNSECURED 0xaf. There is no `APS_SECURED_NWK_KEY` row: an APDU secured with the
 * network key is 4.4.5's and 4.4.12's, deferred with joining.
 */
enum
{
    APS_SECURITY_NONE = 0xff,               /* band A's sentinel: no security verdict for this frame */
    APS_SECURITY_LINK_KEY = 0xab,           /* Table 2-4's SECURED_LINK_KEY, Table 2-29's 0xab */

    APS_KEY_STATUS_NONE = 0xff,             /* band A's sentinel: no key pair involved */
    APS_KEY_STATUS_PROVISIONAL = 0x00,      /* Table 4-36's KeyAttributes, PROVISIONAL */
    APS_KEY_STATUS_VERIFIED = 0x02          /* Table 4-36's KeyAttributes, VERIFIED */
};

enum
{
    /* R23.1 prints no size for any APS pool: each here follows §4.3's rule (bounded, named, full is
       refusal and count. The slot pool is named by `aps_tx.h` and the rings follow that include. */

    /* An indication is somebody else's frame, so this ring's full policy is refusal and count at the moment
       of production, not overwrite (`nwk`'s reasoning one layer down) */
    APS_INDICATION_MAX = NWK_INDICATION_MAX,

    /* everything past the shortest header the codec validates, inside the NSDU the layer below delivers */
    APS_INDICATION_ASDU_MAX = APS_FRAME_MAX - APS_FRAME_HEADER_MIN,

    /* Table 2-23, the two constants 2.2.8.4.4 runs the acknowledgement machine on */
    APS_MAX_FRAME_RETRIES = 3, /* apscMaxFrameRetries (Table 2-23): additional attempts on top of the first (3.2.1.1.3) */
    APS_ACK_WAIT_DURATION_MS = 1600, /* apscAckWaitDuration: 1.6 s (Table 2-23), re-armed per transmission (2.2.8.4.4, §9.6) */

    /* 2.2.5.1.7's octet, one per new transaction and held constant across its retransmissions
       (2.2.8.4.4, 2.2.8.4.5.3) */
    APS_COUNTER_WRAP = 256,

    /* Table 2-2's nwkBroadcastAddress range, "0xFFFC - 0xFFFF": band A's own band, deliberately wider than
       Table 3-80's four classes, a destination in that table's Reserved rows being refused at the door */
    APS_BROADCAST_ADDRESS_MIN = 0xfffc,
    APS_BROADCAST_ADDRESS_MAX = 0xffff,

    /* 2.2.8.4.1's printed group broadcast address, Table 3-80's macRxOnWhenIdle class; Table 2-2's own
       parameter still wins when the request states one (2.2.4.1.1.3) */
    APS_NWK_BROADCAST_GROUP_DEFAULT = 0xfffd,

    /* Table 2-2's ASDULength range, 256 blocks of the printed per-frame ceiling; inside it but above one
       frame's payload the answer is ASDU_TOO_LONG because fragmentation is deferred */
    APS_ASDU_LENGTH_MAX = 256 * APS_ASDU_MAX,

    /* Table 2-2's `DstAddrMode`, 0x04-0xff being the table's own reserved band */
    APS_ADDR_MODE_NONE = 0x00,              /* the binding-table mode */
    APS_ADDR_MODE_GROUP = 0x01,             /* group address, no DstEndpoint */

    /* 2.2.8.4.2 delivers to the endpoints the group table associates and to nothing else. The other two values are
       this repository's departures: with no member the frame is delivered once, at the broadcast endpoint, and the
       application filters; or the device delivers it to each of its endpoints whose profile is the frame's. */
    APS_GROUP_DELIVERY_MEMBERS = 0,
    APS_GROUP_DELIVERY_UNFILTERED = 1,
    APS_GROUP_DELIVERY_ENDPOINTS = 2,
    APS_ENDPOINT_BROADCAST = 0xff,
    APS_ADDR_MODE_SHORT = 0x02,             /* 16-bit DstAddress, DstEndpoint present */
    APS_ADDR_MODE_EXTENDED = 0x03,          /* 64-bit DstAddress: the address map gives its NWK address, or NO_SHORT_ADDRESS */
    APS_ADDR_MODE_MAX = 0x03,

    /* Table 2-2 prints SrcEndpoint "0x00 – 0xfe", and 2.2.5.1.6 makes 0xff a destination value alone */
    APS_SRC_ENDPOINT_MAX = 0xfe,

    /* No clause prints a start value (2.2.5.1.7 states only the increment, Table 2-24 has no apsCounter),
       so this is named as the house choice it is: the reasoning `NWK_SEQ_START` records one layer down */
    APS_COUNTER_START = 0
};

enum
{
    /* 2.2.8.4.2's timing information prints no interval: a duplicate record lasts as long as a copy of its frame can
       trail it, the sender's last retry or a broadcast's last copy, so a new frame that reuses a counter is no repeat */
    APS_DUP_RETRY_SPAN_MS = (1 + APS_MAX_FRAME_RETRIES) * APS_ACK_WAIT_DURATION_MS,
    APS_DUP_LIFETIME_MS = APS_DUP_RETRY_SPAN_MS > NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS
                          ? APS_DUP_RETRY_SPAN_MS : NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS
};

/* Table 2-4's KeyIndex "0 – 255", valid only for SECURED_LINK_KEY, carried as a pair's index into a table that may hold
   more (ZB_LIMIT_SECURITY_KEYPAIR), so "no pair resolved" is a value no index reaches */
#define APS_KEY_INDEX_NONE ((uint32_t)0xffffffff)

/*
 * APSDE-DATA.request (2.2.4.1.1, Table 2-2) at the house's widths. `dstAddress` is 16-bit because the first
 * slice acts on 16-bit destinations only, mode 0x03 travelling in `dstExtendedAddress` to the refusal that
 * answers it; `dstEndpoint` is present or absent by the mode exactly as the table states it, so no presence
 * flag rides with it; the caller's `asdu` is not retained because a retransmission outlives this call.
 */
typedef struct Aps_ApsdeReq
{
    uint32_t dstAddrMode;               /* Table 2-2, 0x04-0xff reserved */
    uint16_t dstAddress;                /* DstAddress as the mode says it */
    uint64_t dstExtendedAddress;        /* DstAddress for mode 0x03, carried for the refusal */
    uint8_t dstEndpoint;                /* DstEndpoint, for mode 0x02 and 0x03 */
    uint16_t profileId;                 /* ProfileId, 0x0000-0xffff */
    uint16_t clusterId;                 /* ClusterId, 0x0000-0xffff */
    uint8_t srcEndpoint;                /* SrcEndpoint, 0x00-0xfe */
    const uint8_t *asdu;                /* ASDU */
    uint32_t asduLength;                /* ASDULength */
    uint32_t txOptions;                 /* TxOptions */
    int useAlias;                       /* UseAlias */
    uint16_t aliasSrcAddr;              /* AliasSrcAddr */
    uint32_t aliasSeqNumb;              /* Table 2-2's spelling */
    uint8_t radiusCounter;              /* 0x00-0xff; zero is the network default */
    uint16_t nwkBroadcastAddress;       /* mode 0x01's NWK destination; 0 is the default above */
    uint16_t tag;                       /* the caller's name for this request, given back in its confirm; never on the air */
} Aps_ApsdeReq;

/* `Aps_TxCompose`, `Aps_TxDeliveryMode` and `Aps_TxNwkDestination` name `Aps_ApsdeReq`: the SAP types come first. */

#include "aps_tx.h"

enum
{
    /* sized to the pool that answers it: a transaction is in a slot or in the ring, never both (§4.3) */
    APS_CONFIRM_MAX = APS_TX_MAX,

    /* R23.1 prints no size for this pool either: bounded, named, and full is refusal and count (§4.3) */
    APS_KEY_INDICATION_MAX = 4,

    /* nor for this one, which a router's two copies of one Update Device share */
    APS_UPDATE_DEVICE_INDICATION_MAX = 4,

    /* nor for this one, which a router drains on the turn after the command */
    APS_REMOVE_DEVICE_INDICATION_MAX = 2
};

/*
 * APSDE-DATA.confirm (2.2.4.1.2, Table 2-3) with the two facts that say which transaction it answers.
 * The Status travels in both vocabularies this stack has, exactly as `Nwk_DataConfirmParameters`
 * carries its own two: 2.2.4.1.1.3 makes a failed NLDE confirmation's code the APS Status, and
 * `status` is the seam's name for the same outcome. `TxTime` is absent (no wall clock at a SAP) and a
 * mode-0x01 confirm echoes the group id, which is what Table 2-2 says DstAddress *is* for that mode.
 */
typedef struct Aps_Confirm
{
    ZbStatus status;
    uint32_t apsStatus;               /* an APS_STATUS_*, a Table 3-84 code copied up, or the sentinel saying none exists */
    uint32_t dstAddrMode;
    uint16_t dstAddress;
    uint64_t dstExtendedAddress;      /* mode 0x03's address, echoed back */
    uint8_t dstEndpoint;
    uint8_t srcEndpoint;
    uint16_t profileId;
    uint16_t clusterId;
    uint8_t apsCounter;               /* what an acknowledgement this module matched repeated (2.2.5.2.3.1) */
    uint32_t attempts;                /* NLDE transactions this transaction went through: this module's loop, not the NWK's */
    uint16_t tag;                     /* the request's own tag, which tells two requests to one destination apart */
} Aps_Confirm;

/*
 * APSDE-DATA.indication (2.2.4.1.3, Table 2-4), one per delivery this module decided. `status` is the frame
 * Status parameter of that table and a different field from `securityStatus` and from a confirm's Status;
 * `dstAddrMode` is 0x01 for a group with the group id the APS header carried and 0x02 for a unicast or a
 * broadcast with the NWK destination it arrived on, 0x03 and 0x04 waiting for the address map. `RxTime` and
 * `DeviceKeyPairEntry` are absent; the pair is named by its index and attributes.
 */
typedef struct Aps_Indication
{
    uint32_t dstAddrMode;         /* Table 2-4: 0x01 group, 0x02 short; 0x03 / 0x04 wait for the address map */
    uint16_t dstAddress;          /* the group id, or the NWK destination it arrived on */
    uint8_t dstEndpoint;          /* the member endpoint, or the endpoint the frame carried */
    uint32_t srcAddrMode;         /* Table 2-4: 0x02, or 0x03 when the map holds the source's 64-bit address */
    uint16_t srcAddress;          /* the NWK originator (Table 3-4), always filled */
    uint64_t srcExtendedAddress;  /* 2.2.4.1.3.2's 64-bit source, read only when `srcAddrMode` is 0x03 */
    uint8_t srcEndpoint;          /* SrcEndpoint, as the frame carried it */
    uint16_t profileId;
    uint16_t clusterId;
    uint32_t asduLength;          /* 0 whenever `status` is not SUCCESS (2.2.4.1.3.2's null ASDU) */
    uint8_t asdu[APS_INDICATION_ASDU_MAX];
    uint32_t status;              /* Table 2-4's Status: SUCCESS, DEFRAG_UNSUPPORTED or SECURITY_FAIL here */
    uint32_t securityStatus;      /* written with the delivery, at `apsDoIndicate` */
    uint32_t linkQuality;         /* Table 2-4's LinkQuality, `Nwk_DataIndicationParameters.lqi` carried up unchanged */
    uint32_t keyIndex;            /* the pair the delivery used, or APS_KEY_INDEX_NONE; a §1 index in Table 2-4's range */
    uint32_t keyStatus;           /* that entry's Table 4-36 KeyAttributes, or APS_KEY_STATUS_NONE */
} Aps_Indication;

/*
 * One delivery being decided, in the parts a Table 2-4 indication is made of. The unsecured path fills it from
 * the payload region the codec reported; the secured path refills it from what 4.4.1.2 answered: the
 * plaintext, or SECURITY_FAIL with the null ASDU. It lives inside one pass of `apsDoReceive`.
 */
/*
 * APSME-TRANSPORT-KEY.indication (Table 4-13), one per command this module kept. `srcIeee` is the SrcAddress the
 * clause names for that key type, the command's own source field for 0x01 and 0x04 and the NWK source for 0x03;
 * `status` is this module's own verdict, Table 4-13 printing none. `ChangeOfTrustCenterEUI64` and `TunnelCommand`
 * are absent: 4.4.2.2.3's trust-centre swap and 4.6.3.7's tunnel are not built.
 */
typedef struct Aps_KeyIndication
{
    uint64_t srcIeee;
    uint32_t standardKeyType;
    uint8_t key[16];
    uint8_t keySeqNumber;
    uint64_t partnerIeee;
    int initiator;
    uint32_t status;              /* APS_STATUS_SUCCESS, or the refusal the install answered */
} Aps_KeyIndication;

/* APSME-UPDATE-DEVICE.request (Table 4-14). */
typedef struct Aps_UpdateDeviceReq
{
    uint64_t destIeee;
    uint64_t deviceIeee;
    uint8_t status;
    uint16_t deviceShortAddress;
    const uint8_t *joinerTlvs;
    uint32_t joinerTlvLen;
} Aps_UpdateDeviceReq;

/* APSME-UPDATE-DEVICE.indication (Table 4-15). `srcAddress` is the originator's network address, which is not the
   table's: it is where a key owed the device is tunnelled. JoiningDeviceTLVs are not kept. */
typedef struct Aps_UpdateDeviceIndication
{
    uint64_t srcIeee;
    uint16_t srcAddress;
    uint64_t deviceIeee;
    uint16_t deviceShortAddress;
    uint8_t status;
} Aps_UpdateDeviceIndication;

/* APSME-REMOVE-DEVICE.request (Table 4-16), with the parent's network address beside it: where the command goes, as
   a Transport-Key's `nwkDst` is. A router is removed with the target as its own parent (4.4.4.1.2). */
typedef struct Aps_RemoveDeviceReq
{
    uint64_t parentIeee;
    uint16_t parentNwk;
    uint64_t targetIeee;
} Aps_RemoveDeviceReq;

/* APSME-REMOVE-DEVICE.indication (Table 4-17). */
typedef struct Aps_RemoveDeviceIndication
{
    uint64_t srcIeee;
    uint64_t targetIeee;
} Aps_RemoveDeviceIndication;

typedef struct Aps_Delivery
{
    const uint8_t *asdu;
    uint32_t asduLength;
    uint32_t status;              /* Table 2-4's Status */
    uint32_t securityStatus;      /* Table 2-4's SecurityStatus */
    uint32_t keyStatus;           /* Table 4-36's KeyAttributes */
    uint32_t keyIndex;            /* the key pair index */
    uint32_t frameCounter;        /* the auxiliary header's counter, which 4.6.3.8 stores when the pair is verified */
    uint64_t srcIeee;             /* the sender the crossing authenticated, the nonce's address */
} Aps_Delivery;

/* `Aps_RxSecureReceive` writes `Aps_Delivery` and `Aps_AckRespond` is gated by the Status in it: the SAP
   types come first. */

#include "aps_ack.h"
#include "aps_admit.h"
#include "aps_frag.h"
#include "aps_keydoor.h"
#include "aps_rx.h"
#include "aps_tclink.h"

/*
 * The module's whole state, all of it the caller's (§4.3). `nwk` and `security` are adopted by pointer and
 * never owned; a null `security` is the unsecured device, and `apsCounter` moves once per transaction that
 * transmits (2.2.5.1.7 with 2.2.8.4.4). The arrays
 * named scratch hold what one drain or one call took and are overwritten by the next; nothing a caller can
 * poll lives in them. The counters are the module's account of what it refused, one per gate.
 */
typedef struct Aps_Aps
{
    Nwk_Nwk *nwk;                     /* adopted, never owned */
    Security *security;               /* adopted, never owned: 2.2.5.1.1.4's provider, the key pairs' owner */
    uint32_t apsCounter;

    Aps_Tx tx[APS_TX_MAX];

    Aps_Group groups[APS_GROUP_MAX];      /* in no particular order, which 2.2.8.3.1 licenses outright
                                             ("any manner that is convenient and efficient"); what the clause
                                             fixes is one indication per member, so the fan-out walks pool order */
    Aps_Dup dups[APS_DUP_MAX];            /* oldest by `seenMs` for the eviction, otherwise unordered */

    Aps_Binding *bindings;                /* Table 2-24's binding table, adopted: 0 when this device keeps none */

    /* Confirmation ring, oldest first: the only way an answer leaves the module */
    Aps_Confirm confirms[APS_CONFIRM_MAX];
    uint32_t confirmHead;
    uint32_t confirmCount;

    /* Indication ring, oldest first: full is refusal and count at production (`APS_INDICATION_MAX`) */
    Aps_Indication indications[APS_INDICATION_MAX];
    uint32_t indicationHead;
    uint32_t indicationCount;

    Nwk_DataConfirmParameters nwkConfirm;         /* scratch, not a pool: the one confirmation being decided */

    uint8_t ackApdu[APS_FRAME_MAX];       /* scratch, not a pool: composed and issued inside the one call */

    uint8_t secureScratch[APS_FRAME_MAX]; /* scratch, not a pool: `Security_ProtectAps`'s output for the last issue */
    uint8_t plainScratch[APS_FRAME_MAX];  /* scratch, not a pool: the unprotect output, copied out before it is reused */

    uint32_t refusedRequests;         /* declined at the door, each reason named */
    uint32_t unmatchedAcks;           /* read and not matched to a transaction that owed one (2.2.8.4.4) */
    uint32_t confirmsIgnored;         /* answers to frames this module issued on its own initiative, or already answered */
    uint32_t retransmitRefusals;      /* a retransmission the layer below would not take: the one refusal a later turn cures */

    /* The reception family, one counter per gate of `apsDoReceive`'s sequence, the codec's two families kept
       apart as `nwk` keeps them (`droppedUnsupported` against `droppedMalformed`), deferrals and
       readings counted at the gate each one reaches */
    uint32_t rxShapeRefused;
    uint32_t rxMalformed;
    uint32_t rxSecuredDeferred;
    uint32_t rxCommandDeferred;
    uint32_t rxDuplicateDrops;
    uint32_t droppedGroupMiss;
    uint32_t groupDeliveredUnfiltered;  /* the no-member arm D-213 delivers instead of dropping */
    uint32_t groupDelivery;             /* APS_GROUP_DELIVERY_*, MEMBERS until the application asks */
    uint32_t droppedBoundEntries;     /* an entry the fan-out refused for its own fields */
    uint32_t acksGenerated;
    uint32_t acksRefused;
    uint32_t droppedIndications;
    uint32_t loopbacks;               /* requests to this device's own address, indicated here and never sent */

    /* The security family: two transmit reasons and two receive reasons, each reaching the
       Table 2-4 indication a failure produces */
    uint32_t txNoKeyPair;
    uint32_t txSecuredFailures;
    uint32_t rxSecuredFailuresAuth;
    uint32_t rxSecuredFailuresCounters;

    /* Indications of 4.4.2.2: a transport key this module kept, oldest first */
    Aps_KeyIndication keyIndications[APS_KEY_INDICATION_MAX];
    uint32_t keyIndicationHead;
    uint32_t keyIndicationCount;

    /* Indications of 4.4.3.2 at a trust centre, a local join's and a router's report alike, oldest first */
    Aps_UpdateDeviceIndication updateDevices[APS_UPDATE_DEVICE_INDICATION_MAX];
    uint32_t updateDeviceHead;
    uint32_t updateDeviceCount;

    /* Indications of 4.4.4.2 at a router, each a trust centre's order to remove the target, oldest first */
    Aps_RemoveDeviceIndication removeDevices[APS_REMOVE_DEVICE_INDICATION_MAX];
    uint32_t removeDeviceHead;
    uint32_t removeDeviceCount;

    /* The command family: a transaction a command door opened is answered by no primitive (4.4.2), so its
       outcome is counted where the request that opened it can be read against it */
#if ZB_APS_FRAGMENTATION
    Aps_FragAssembly frag[APS_FRAG_TRANSACTIONS];   /* 2.2.8.4.5's reassembly pool */
#endif

    uint32_t commandAnswers;
    uint32_t commandFailures;

    /* The fragmentation family: what the reassembly pool refused, and what it put back together */
    uint32_t rxFragmentDrops;
    uint32_t fragmentsReassembled;

    /* The transport-key door's account, one counter per verdict 4.4.2.3 prints and two for what it kept */
    uint32_t keyDroppedNotTrustCenter;
    uint32_t keyDroppedPolicy;
    uint32_t keyDroppedUnsecured;
    uint32_t keyDroppedDistributed;
    uint32_t keyForwardDeferred;
    uint32_t keyInstalled;
    uint32_t keyInstallFailed;
    uint32_t keyLinkKeyDeferred;

    /* 4.7.3.8's exchange at a trust centre: allowTrustCenterLinkKeyRequests (0, 1 or 2) and what became of the
       Request-Key and Verify-Key commands it read (D-218) */
    uint32_t allowTcLinkKeyRequests;
    uint32_t tcLinkKeysSent;
    uint32_t tcLinkKeyRequestsDropped;
    uint32_t verifyKeysConfirmed;
    uint32_t verifyKeysRefused;

    /* The same exchange at a joiner: whether it takes a trust centre link key at all, where its own update stands, and
       its account of the keys installed, verified and given up */
    int tcLinkKeyUpdate;
    uint32_t tcLinkKeyState;
    uint32_t tcLinkKeyRequestsSent;
    uint32_t tcLinkKeysInstalled;
    uint32_t tcLinkKeysVerified;
    uint32_t tcLinkKeysAbandoned;

    /* 4.4.3's account: indications made, commands ignored away from a trust centre, refused by Table 4-6, and
       dropped as a repeat of one still queued or for want of room */
    uint32_t updateDevicesIndicated;
    uint32_t updateDevicesIgnored;
    uint32_t updateDevicesRefused;
    uint32_t updateDevicesRepeated;
    uint32_t updateDevicesDropped;

    /* and at a router: the reports it sent its trust centre, and the Tunnels it relayed to a child or refused */
    uint32_t updateDevicesSent;
    uint32_t tunnelsRelayed;
    uint32_t tunnelsDropped;

    /* 4.4.4's account: the commands sent, and those received that were indicated, refused, or dropped for want of room */
    uint32_t removeDevicesSent;
    uint32_t removeDevicesIndicated;
    uint32_t removeDevicesRefused;
    uint32_t removeDevicesDropped;

    /* The group pool's own account: refusals of the APSME services of 2.2.4.5, counted here because their
       caller is holding a return value and not a confirmation it might never read */
    uint32_t groupRefusals;
} Aps_Aps;

/*
 * Adopt the network layer, which is already through `Nwk_Init`; a null `self` or `nwk` is refused and the
 * struct is cleared before it is filled. There is no configuration to pass (see the module doc), and the
 * security half arrives separately, at `Aps_AttachSecurity`, because key material is configuration.
 */
ZbStatus Aps_Init(Aps_Aps *self, Nwk_Nwk *nwk);

/* The binding table a destination mode of 0x00 searches (2.2.4.1.1.3); 0 leaves that mode answering NOT_SUPPORTED. */
void Aps_SetBindings(Aps_Aps *self, Aps_Binding *bindings);

/* The installed table, which the device object reports, or 0 when this device keeps none. */
const Aps_Binding *Aps_BindingPool(const Aps_Aps *self);

/* APSME-BIND.request and APSME-UNBIND.request, `add` naming which. */
uint32_t Aps_BindRequest(Aps_Aps *self, const Aps_Binding *entry, int add);

/* A binding entry the fan-out could not use because its own fields are out of Table 2-6's ranges. */
uint32_t Aps_DroppedBoundEntries(const Aps_Aps *self);

/*
 * Adopt the security module, or drop it: `Nwk_AttachSecurity`'s shape one layer up, often the very same
 * object. A 0 puts the unsecured device back: nothing protected, every secured arrival a deferral, a
 * 0x01 ask answered SECURITY_FAIL. This module never consults `Security_IsEnabled`: the two crossings
 * are seeded independently and the attempt answers what it was told.
 */
void Aps_AttachSecurity(Aps_Aps *self, Security *security);

/*
 * One APSDE-DATA.request. The door answers whatever is decidable without putting a frame on the air, names
 * its reason, counts it and produces no confirmation; everything the standard answers with a Status is
 * answered through the confirmation ring and still returns ZB_OK (§9.6). A full pool is refused at the door.
 */
ZbStatus Aps_DataRequest(Aps_Aps *self, const Aps_ApsdeReq *req, uint32_t nowMs);

/*
 * Service the sub-layer once: `Nwk_Step` first, then the NLDE answers, then the NLDE indications, then the answers
 * those and the network layer's later tasks gave, then the expired waits; last, so an acknowledgement that arrived
 * in this turn is a fact before the same turn concludes a timeout. Each pass is safe against a layer that refused.
 */
ZbStatus Aps_Step(Aps_Aps *self, uint32_t nowMs);

/*
 * Take what this module has answered, oldest first, at most `max`. A confirmation is produced when the
 * transaction it answers is finished with, so a caller that never polls fills the ring and is refused at the
 * door rather than losing an answer.
 */
uint32_t Aps_PollConfirms(Aps_Aps *self, Aps_Confirm *out, uint32_t max);

/*
 * Take what this module has delivered upward, oldest first, at most `max`. The ring's full policy is refusal
 * and count at the moment of production, and a group frame with several members is several indications and
 * can fill it by itself (2.2.8.4.2).
 */
uint32_t Aps_PollIndications(Aps_Aps *self, Aps_Indication *out, uint32_t max);

/*
 * APSME-ADD-GROUP / APSME-REMOVE-GROUP / APSME-REMOVE-ALL-GROUPS (2.2.4.5.1, 2.2.4.5.3, 2.2.4.5.5), answered
 * in place: the return value *is* the Status parameter of Tables 2-15, 2-17 and 2-19, in Table 2-29's codes.
 * Only the printed endpoint range is judged; an endpoint "not implemented on the current device" needs the
 * endpoint registry of the layer above, which band A has not built.
 */
uint32_t Aps_AddGroup(Aps_Aps *self, uint16_t groupAddress, uint8_t endpoint);
uint32_t Aps_RemoveGroup(Aps_Aps *self, uint16_t groupAddress, uint8_t endpoint);
uint32_t Aps_RemoveAllGroups(Aps_Aps *self, uint8_t endpoint);

/* What the module holds and what it has done: the depth of each pool, and the counters. */
uint32_t Aps_TransmitQueue(const Aps_Aps *self);
uint32_t Aps_ConfirmQueue(const Aps_Aps *self);
uint32_t Aps_IndicationQueue(const Aps_Aps *self);
uint32_t Aps_GroupQueue(const Aps_Aps *self);

uint32_t Aps_RefusedRequests(const Aps_Aps *self);
uint32_t Aps_UnmatchedAcks(const Aps_Aps *self);
uint32_t Aps_ConfirmationsIgnored(const Aps_Aps *self);
uint32_t Aps_RetransmitRefusals(const Aps_Aps *self);

uint32_t Aps_RxShapeRefused(const Aps_Aps *self);
uint32_t Aps_RxMalformed(const Aps_Aps *self);
uint32_t Aps_RxSecuredDeferred(const Aps_Aps *self);
uint32_t Aps_RxCommandDeferred(const Aps_Aps *self);
uint32_t Aps_RxDuplicateDrops(const Aps_Aps *self);
uint32_t Aps_DroppedGroupMiss(const Aps_Aps *self);
uint32_t Aps_GroupDeliveredUnfiltered(const Aps_Aps *self);

/* Which arm a group frame with no member takes; `APS_GROUP_DELIVERY_MEMBERS` is the clause and the default. */
void Aps_SetGroupDelivery(Aps_Aps *self, uint32_t mode);
uint32_t Aps_GroupDelivery(const Aps_Aps *self);
uint32_t Aps_AcksGenerated(const Aps_Aps *self);
uint32_t Aps_AcksRefused(const Aps_Aps *self);
uint32_t Aps_DroppedIndications(const Aps_Aps *self);
uint32_t Aps_Loopbacks(const Aps_Aps *self);
uint32_t Aps_GroupRefusals(const Aps_Aps *self);

/* The security family, each one reached by a different clause of 4.4.1 */
uint32_t Aps_TxNoKeyPair(const Aps_Aps *self);
uint32_t Aps_TxSecuredFailures(const Aps_Aps *self);
uint32_t Aps_RxSecuredFailuresAuth(const Aps_Aps *self);
uint32_t Aps_RxSecuredFailuresCounters(const Aps_Aps *self);

/* The command transactions that reached an outcome, and how many of those failed: 4.4.2 prints no confirm for a
   command, so this is where the sender of one reads what became of it. */
uint32_t Aps_CommandAnswers(const Aps_Aps *self);
uint32_t Aps_CommandFailures(const Aps_Aps *self);

/* Where a joiner's trust centre link key update stands. */
enum
{
    APS_TCLK_NONE = 0,          /* nothing asked */
    APS_TCLK_REQUESTED = 1,     /* a Request-Key went out, its Transport-Key awaited */
    APS_TCLK_VERIFYING = 2,     /* the key is held unverified, its Verify-Key sent, the Confirm-Key awaited */
    APS_TCLK_VERIFIED = 3,      /* a Confirm-Key said SUCCESS: the entry is verified */
    APS_TCLK_ABANDONED = 4      /* given up: the unverified entry forgotten, the global key kept */
};

/* 1: a joiner takes a trust centre link key its trust centre sends, holds it unverified and asks Verify-Key; 0, as
   after `Aps_Init`, it keeps the key it joined with, as an older device does. */
void Aps_SetTcLinkKeyUpdate(Aps_Aps *self, int update);

/* 4.4.5.1's APSME-REQUEST-KEY.request for the trust centre link key, to the trust centre under the key the device
   holds now. ZB_ERR_BAD_STATE with no trust centre known or on the trust centre itself. */
ZbStatus Aps_RequestTcLinkKey(Aps_Aps *self, uint32_t nowMs);

/* The update given up: an unverified entry for the trust centre becomes the global key again. */
void Aps_TcLinkKeyAbandon(Aps_Aps *self);

/* APS_TCLK_*, and the joiner's account. */
uint32_t Aps_TcLinkKeyState(const Aps_Aps *self);
uint32_t Aps_TcLinkKeyRequestsSent(const Aps_Aps *self);
uint32_t Aps_TcLinkKeysVerified(const Aps_Aps *self);
uint32_t Aps_TcLinkKeysAbandoned(const Aps_Aps *self);

/* allowTrustCenterLinkKeyRequests (4.7.3.8 step 4): 0 drops every request, 1 answers it, 2 answers a device whose
   pair is still provisional. 1 after `Aps_Init`; a trust centre with no link key seed answers none (D-218). */
void Aps_SetAllowTcLinkKeyRequests(Aps_Aps *self, uint32_t allow);

/* 4.7.3.8's account: keys sent for a Request-Key, requests dropped, Verify-Keys confirmed and refused. */
uint32_t Aps_TcLinkKeysSent(const Aps_Aps *self);
uint32_t Aps_TcLinkKeyRequestsDropped(const Aps_Aps *self);
uint32_t Aps_VerifyKeysConfirmed(const Aps_Aps *self);
uint32_t Aps_VerifyKeysRefused(const Aps_Aps *self);

/*
 * APSME-TRANSPORT-KEY.request (4.4.2.1.3): compose Figure 4-8's command, protect it with the key 4.4.1.1 step 1 b ii
 * names, and issue it to `nwkDst` as one transaction. ZB_ERR_AUTH with no security adopted, ZB_ERR_NOT_FOUND for a
 * destination this device holds no key pair for (there is no key to protect it with), ZB_ERR_BAD_ARGUMENT for a type
 * Table 4-9 does not give, ZB_ERR_NO_SPACE for a full transaction pool, and whatever the protection or the issue
 * answered. The outcome of the transmission itself is `Aps_CommandAnswers`' to report: 4.4.2 prints no confirm.
 * A network key goes out unsecured at the network layer, which `aps_tx`'s mark names; a link key goes to a device
 * that already holds the network key, so the network layer protects it. With `tunnel` the secured command goes inside
 * a Tunnel to the parent `tunnelNwk` names, which the network layer protects (4.6.3.7.1).
 */
ZbStatus Aps_TransportKeyRequest(Aps_Aps *self, const Aps_TransportKeyReq *req, uint32_t nowMs);

/* Drain the transport-key indications of 4.4.2.2, oldest first, at most `max`. */
uint32_t Aps_PollKeyIndications(Aps_Aps *self, Aps_KeyIndication *out, uint32_t max);

uint32_t Aps_KeyIndicationQueue(const Aps_Aps *self);

uint32_t Aps_KeyDroppedNotTrustCenter(const Aps_Aps *self);
uint32_t Aps_KeyDroppedPolicy(const Aps_Aps *self);
uint32_t Aps_KeyDroppedUnsecured(const Aps_Aps *self);
uint32_t Aps_KeyDroppedDistributed(const Aps_Aps *self);
uint32_t Aps_KeyForwardDeferred(const Aps_Aps *self);
uint32_t Aps_KeyInstalled(const Aps_Aps *self);
uint32_t Aps_KeyInstallFailed(const Aps_Aps *self);
uint32_t Aps_KeyLinkKeyDeferred(const Aps_Aps *self);

/* APSME-UPDATE-DEVICE.request (4.4.3.1.3): at a trust centre the indication with this device as its source, elsewhere
   the command to the trust centre, ZB_ERR_NOT_READY while that is unknown and ZB_ERR_BAD_STATE in a distributed
   network. ZB_ERR_BAD_ARGUMENT for a status Table 4-14 reserves, ZB_ERR_NO_SPACE for a full ring or pool. */
ZbStatus Aps_UpdateDeviceRequest(Aps_Aps *self, const Aps_UpdateDeviceReq *req, uint32_t nowMs);

/* Drain the update-device indications of 4.4.3.2, oldest first, at most `max`. */
uint32_t Aps_PollUpdateDeviceIndications(Aps_Aps *self, Aps_UpdateDeviceIndication *out, uint32_t max);

uint32_t Aps_UpdateDevicesIndicated(const Aps_Aps *self);
uint32_t Aps_UpdateDevicesIgnored(const Aps_Aps *self);
uint32_t Aps_UpdateDevicesRefused(const Aps_Aps *self);
uint32_t Aps_UpdateDevicesRepeated(const Aps_Aps *self);
uint32_t Aps_UpdateDevicesDropped(const Aps_Aps *self);
uint32_t Aps_UpdateDevicesSent(const Aps_Aps *self);
uint32_t Aps_TunnelsRelayed(const Aps_Aps *self);
uint32_t Aps_TunnelsDropped(const Aps_Aps *self);

/* APSME-REMOVE-DEVICE.request (4.4.4.1.3): the command naming the target, APS encrypted under the pair held for the
   parent and sent to it. ZB_ERR_NOT_FOUND when this device holds no pair for the parent, ZB_ERR_NO_SPACE for a full
   pool. */
ZbStatus Aps_RemoveDeviceRequest(Aps_Aps *self, const Aps_RemoveDeviceReq *req, uint32_t nowMs);

/* Drain the remove-device indications of 4.4.4.2, oldest first, at most `max`: each one came APS encrypted from the
   trust centre, and what the target is to this device is the caller's to decide. */
uint32_t Aps_PollRemoveDeviceIndications(Aps_Aps *self, Aps_RemoveDeviceIndication *out, uint32_t max);

uint32_t Aps_RemoveDevicesSent(const Aps_Aps *self);
uint32_t Aps_RemoveDevicesIndicated(const Aps_Aps *self);
uint32_t Aps_RemoveDevicesRefused(const Aps_Aps *self);
uint32_t Aps_RemoveDevicesDropped(const Aps_Aps *self);

/* 2.2.8.4.5's reassembly: the blocks it refused and the ASDU it put back together. */
uint32_t Aps_RxFragmentDrops(const Aps_Aps *self);
uint32_t Aps_FragmentsReassembled(const Aps_Aps *self);

/* 1 while a fragmented ASDU is being put back together, which a resting end device polls faster for. */
int Aps_Reassembling(const Aps_Aps *self);

#endif /* APS_H */
