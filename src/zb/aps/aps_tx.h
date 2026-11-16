#ifndef APS_TX_H
#define APS_TX_H

/*
 * The transmit machinery of band A's APS sub-layer: the transaction slot, its three states and their pool
 * bound, and the acts one transaction is made of, free slot and occupancy, the delivery mode and NWK
 * destination a request implies, composition, key-pair resolution, protection, the issue and its octets.
 *
 * Everything it acts on arrives from the caller: the pool, the adopted `Security`, the scratch, the adopted
 * `Nwk_Nwk`. Nothing here owns a pool, writes a confirmation or counts an outcome: the door, the ring and the
 * wait pass stay façade-side, and the composition keeps the unsecured APDU, each issue protecting afresh.
 */

#include <stdint.h>

#include "aps_frag.h"
#include "aps_frame.h"
#include "nwk.h"
#include "radio.h"
#include "security.h"
#include "zb_limits.h"
#include "zb_status.h"

enum
{
    /* no apscMaxTransactions exists: bounded, named, full is refusal and count (§4.3) */
    APS_TX_MAX = ZB_LIMIT_APS_TX /* transactions taken back and not yet answered */
};

/*
 * Three modes, because a transaction with more than two modes is a state machine (§3). Retrying is not a
 * fourth: 2.2.8.4.4's loop re-issues the stored APDU and returns the slot to AWAITING_NLDE, the same
 * obligation run again with a larger attempt count and the same APS counter.
 */
typedef enum Aps_TxState
{
    APS_TX_FREE = 0,            /* no transaction in this slot */
    APS_TX_AWAITING_NLDE = 1,   /* its NLDE-DATA.confirm is outstanding */
    APS_TX_AWAITING_ACK = 2     /* the APS acknowledgement is what is outstanding */
} Aps_TxState;

/*
 * One transaction this module has taken back. `apdu` is the composed `APS header ‖ ASDU`
 * stored byte for byte: a retransmission is that APDU re-offered and its acknowledgement
 * matches on the counter it carries (2.2.8.4.4), and the NWK slot one level down holds the
 * NPDU around it. `nwkDst` is where every issue is aimed: a Table 3-80 class for a group send,
 * the group id riding the APS header. `lastHandle` pairs a confirmation with the transaction
 * that owes it, NONE being an issue that ran no transmit, and `lastNwkSeq` pairs one that carries
 * no handle: a held frame, a retry, a discard. The secured octets are never
 * stored: each issue protects afresh, 4.4.1.2 step 4 refusing a count the peer already used.
 */
typedef struct Aps_Tx
{
    uint32_t state;                   /* Aps_TxState */
    uint32_t dstAddrMode;
    uint16_t dstAddress;
    uint64_t dstExtendedAddress;
    uint8_t dstEndpoint;
    uint8_t srcEndpoint;
    uint16_t profileId;
    uint16_t clusterId;
    uint8_t apsCounter;
    uint16_t tag;                     /* the caller's, carried to the confirm */
    uint32_t deliveryMode;            /* derived from the request (Table 2-21, 3-80) */
    uint16_t nwkDst;                  /* where each issue is aimed */
    int ackRequested;                 /* the AR sub-field: 1 for an acknowledged unicast, 0 otherwise (2.2.5.1.1.5) */
    int apsSecurity;                  /* FCF bit 5 as this transaction writes it: TxOptions 0x01, the APS crossing */
    int extendedNonce;                /* TxOptions 0x10: 4.4.1.1 step 4a-ii's sub-field */
    int keyPairIndex;                 /* the pair the door resolved, re-read at every issue */
    uint32_t keyIdentifier;           /* Table 4-39's identifier the protection names: 00 for a datagram, 02 or 03 for a
                                         transport-key command (4.4.1.1 step 1 b ii) */
    int confirmOwed;                  /* 1 for an APSDE-DATA transaction, whose answer is Table 2-3's confirm; 0 for a
                                         command, which 4.4.2 prints no confirm primitive for */
    int nwkSecurity;                  /* 1 when the network layer may protect this frame, 0 when a transport key says not */
    uint8_t radiusCounter;            /* RadiusCounter, carried down unchanged */
    int useAlias;                     /* Table 2-2's UseAlias, with the two rows it names (3.2.1.1.1) */
    uint16_t aliasSrcAddr;
    uint32_t aliasSeqNumb;
    uint32_t apduLen;
    uint32_t apduHeaderLen;           /* the codec's payload offset: where the auxiliary goes (4.4.10) */
    uint32_t securedLen;              /* the protected octets of the last issue, 0 before the first protection */
    uint8_t apdu[APS_FRAME_MAX];
#if ZB_APS_FRAGMENTATION
    /* 2.2.8.4.5's fragmented transmission, at the one window size R23.1 makes interoperable: the ASDU itself, which
       no single frame holds, and where in it the block being sent lies. A transaction that is not fragmented leaves
       all of this at zero. */
    int fragmented;
    uint8_t fragTotal;                /* the block count, which the first block's own number states */
    uint8_t fragIndex;                /* the block being transmitted, zero-based */
    uint8_t fragCapacity;             /* the octets one block carries */
    uint32_t fragAsduLength;
    uint8_t fragAsdu[APS_FRAG_MAX_ASDU];
#endif

    uint32_t attempts;                /* NLDE transactions issued: ceiling 1 + APS_MAX_FRAME_RETRIES */
    uint32_t ackDeadlineMs;           /* armed after each transmission (2.2.8.4.4) */
    Radio_Handle lastHandle;
    uint8_t lastNwkSeq;
} Aps_Tx;

/* The slot that is free, in pool order. */
Aps_Tx *Aps_TxFree(Aps_Tx *pool);

/* How many slots hold a transaction: the number the door adds to the confirmation ring's depth before it
   refuses, a transaction being in one of the two and never both (docs/internals/coding-rules.md §4.3). */
uint32_t Aps_TxOccupied(const Aps_Tx *pool);

/*
 * The delivery mode and the NWK destination the request implies, derived from it and not handed to it:
 * group for mode 0x01, broadcast for a Table 3-80 class, unicast otherwise (2.2.5.1.1.2 with 3.6.6); the group id
 * riding the APS header while the frame is aimed at `nwkBroadcastAddress`, 0xfffd stated or defaulted
 * (2.2.8.4.1).
 */
uint32_t Aps_TxDeliveryMode(const Aps_ApsdeReq *req);
uint16_t Aps_TxNwkDestination(const Aps_ApsdeReq *req);

/* The `APS header ‖ ASDU` the slot stores, written by `aps_frame` and by nothing else, kept
   unsecured because protection is an act of the attempt (4.4.10). */
ZbStatus Aps_TxCompose(Aps_Tx *tx, const Aps_ApsdeReq *req);

#if ZB_APS_FRAGMENTATION
/* 2.2.8.4.5.3's block of the fragmented ASDU the slot holds: the extended header present, the sub-field the block's
   place gives it, and its number. ZB_ERR_BAD_ARGUMENT for a slot that is not fragmented, ZB_ERR_NO_SPACE for one whose
   ASDU does not fit the block capacity it was given. */
ZbStatus Aps_TxComposeBlock(Aps_Tx *tx);

/* The octets one block can carry in this slot's frame shape: the frame ceiling less the header the frame writes. */
uint32_t Aps_TxBlockCapacity(const Aps_Tx *tx);
#endif

/* The `apsDeviceKeyPairSet` index the destination names (0x03 by its EUI64, 0x02 by the short alias an entry
   carries) or -1 for none (4.4.1.1 step 1). */
int Aps_TxResolveKeyPair(const Security *security, const Aps_ApsdeReq *req);

/* 4.4.1.1 over the stored APDU, into the caller's buffer: `securedLen` records what came back, and a refusal
   moves no frame counter and costs the call site its count (2.2.4.1.1.3, 4.4.1.1 step 9). */
ZbStatus Aps_TxProtect(Security *security, Aps_Tx *tx, uint8_t *scratch, uint32_t scratchMax);

/* The octets one issue hands down as its NSDU: the protected frame for a secured transaction (only after
   `Aps_TxProtect` filled the buffer) and the stored APDU for every other one. */
void Aps_TxOutgoingOctets(const Aps_Tx *tx, const uint8_t *scratch,
                          const uint8_t **octets, uint32_t *len);

/*
 * One transmission of the transaction as one NLDE-DATA.request (2.2.8.4.1, 2.2.4.1.1.3): the attempt records
 * its own count, handle and state in the slot, `DiscoverRoute` travels 0x00 while route
 * discovery defers, and every refusal comes back for the call site to answer.
 */
ZbStatus Aps_TxIssue(Aps_Tx *tx, Nwk_Nwk *nwk, const uint8_t *scratch, uint32_t nowMs);

/* The slot a NLDE confirmation belongs to: by the handle its last issue ran on, and for the two cases with
   no handle (a routed-out discard and a transmit the MAC's pool never ran) by the destination, in pool
   order (3.2.1.1.3, 3.6.4.3). */
Aps_Tx *Aps_TxSlotForConfirm(Aps_Tx *pool, const Nwk_DataConfirmParameters *confirm);

#endif /* APS_TX_H */
