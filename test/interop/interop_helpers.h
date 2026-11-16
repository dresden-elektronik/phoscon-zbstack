/* The `interop` suite's shared machinery.

   What two or more of the four phases use, once: the capture tables and the loader that fills them, the
   deny-tx shim and its ops table, the device this suite assembles for itself, the three drives and the ledger
   they are read into. The cast the suite names (the two fixtures' line counts, the address this device
   answers to, the PAN, the channel, the key octets and their sequence numbers, and the cadence every replay
   runs at) is here for the same reason: it is this suite's own reading of the captured network, and every
   phase reads it. */

#ifndef INTEROP_HELPERS_H
#define INTEROP_HELPERS_H

#include <stdint.h>

#include "aps.h"
#include "fixtures_frames.h"
#include "loopback_radio.h"
#include "mac.h"
#include "nwk.h"
#include "radio.h"
#include "rig_band_a.h"
#include "security.h"

#ifndef ZB_SAMPLES_DIR
#define ZB_SAMPLES_DIR "."
#endif

#define PRIMARY_PATH ZB_SAMPLES_DIR "/" "conbee2_ch15_nwksec_hex.txt"
#define SECONDARY_PATH ZB_SAMPLES_DIR "/" "conbee2_ch15_hex.txt"

/* The channel-15 test network, as a device that only ever reads it is configured. ownIeee is a
   sentinel: no captured auxiliary source address and no captured NWK source IEEE equals it, so nothing this
   replay hears can be mistaken for this device's own traffic. */
#define OWN_IEEE 0x0011223344556677

enum
{
    PRIMARY_LINES = 135,            /* the primary fixture's raw-PSDU line count */
    SECONDARY_LINES = 55,
    CAPTURE_MAX = PRIMARY_LINES,

    OWN_SHORT = 0xfff0,             /* Nwk_Config / PIB identity the replay pins */
    PAN_ID = 0xde20,
    CHANNEL = 15,
    SENDER_SHORT = 0x1111,          /* the composed legs: an unsecured 0xde20 frame needs a source that is not this device */

    KEY_OCTET = 0xcc,               /* the test network's key: sixteen of these octets, application config */
    FOREIGN_KEY_OCTET = 0x11,       /* the composed legs: the same frame at a stack holding a different key */
    KEY_SEQ = 0x00,                 /* the sequence every captured auxiliary header carries */
    OTHER_KEY_SEQ = 0x05,           /* the key-sequence leg: a descriptor under a number the frames do not carry */
    KEY_LEVEL = 0x05,               /* nwkSecurityLevel's printed default (Table 4-2), the level these frames are secured at */
    KEY_OUTGOING_START = 0,         /* 4.3.1.1 step 7 starts this device's counter where the application seeds it */

    MS_PER_FRAME = 1,               /* the replay's cadence, stated by the capture inventory: one step per batch of at most RADIO_FRAME_BATCH_MAX, the clock advanced 1 ms per frame */
    FIXTURE_RSSI_DBM = -100,        /* the loader reads octets only (the annotation lines are a decoder's output), so the metadata is a fixed stand-in and no counter here reads it */
    FIXTURE_LQI = 0,
    FIXTURE_STAMP_BASE = 1          /* device ticks, arrival-ordered, never compared against a host clock */
};

typedef struct Capture
{
    uint32_t count;
    uint32_t len[CAPTURE_MAX];
    uint8_t bytes[CAPTURE_MAX][RADIO_MPDU_MAX];
} Capture;

/* The two captures, read once by the entry point's loader and replayed by the phases. They are the fixtures,
   not state a case carries: phase A and phase D drive the primary, phase B the secondary. */
extern Capture s_primary;
extern Capture s_secondary;

/*
 * The wrapper around the seam: every operation forwarded to the `loopback_radio` backend unchanged, and `tx`
 * refused with ZB_ERR_UNSUPPORTED at the shim before it reaches the backend, counted there. The receive
 * semantics run unmodified (the crossing decrypts, the windows commit, the parsers parse), so the shim's
 * count is the machine-readable proof that this device never put a octet on the air.
 */
typedef struct DenyTx
{
    Radio_Radio *backend;         /* the seam the shim wraps, called with its own provider */
    Radio_Radio seam;             /* the seam band A is handed */
    uint32_t txRefusals;
} DenyTx;

typedef struct Rig
{
    Loopback_Radio model;
    DenyTx deny;
    Security security;
    Mac_Mac mac;
    Nwk_Nwk nwk;
    Aps_Aps aps;
    int shimmied;
    int secured;
} Rig;

/*
 * What one replay did, as the drive saw it: the rings it drained and the refusals its own step answered.
 * The model answers every transmit the moment it is asked (no scripted pending pump), so no `LoopbackRadio_Pump`
 * is owed between steps.
 */
typedef struct Driven
{
    uint32_t steps;
    uint32_t stepsRefusingTx;     /* steps whose Aps_Step answered the shim's ZB_ERR_UNSUPPORTED: a poll answer that was refused */
    uint32_t apsIndications;      /* the APSDE indications this drive took off the ring: the NHLE's share */
    uint32_t apsConfirms;
    uint32_t macPollEvents;
} Driven;

/*
 * The MAC row measured at the MAC: the same capture driven through `mac` alone, with its own rings drained,
 * so "frames delivered upward" is a number this drive counted rather than one inferred from the layer above.
 * The 22 acknowledgements and the non-poll commands are consumed at the carrier that read the header,
 * which is exactly what this view cannot see in its queue and can see in its counters.
 */
typedef struct MacView
{
    uint32_t delivered;
    uint32_t verdictFailing;      /* delivered with a status that is not ZB_OK: the parser's refusal, or the radio's
                                     own report of a duplicate or a receive error; a footer that does not compute
                                     is discarded at the MAC and never delivered (6.6.2, 7.2.11) */
    uint32_t headerUnread;        /* delivered without a parsed header at all: 0 by construction, since a frame
                                     the parse refuses is now discarded and counted in `refused` below */
    uint32_t footerRefused;       /* discarded at the MAC because the footer did not compute (6.6.2, 7.2.11) */
    uint32_t refused;             /* discarded at the MAC before any duty: a reserved type or version, a malformed
                                     header, or a form this build has no header for (6.6.2 a), b)) */
    uint32_t acksHeard;
    uint32_t commandsHeard;
    uint32_t pollEvents;
    uint32_t confirms;
} MacView;

typedef struct Ledger
{
    /* mac */
    uint32_t macAcksHeard;
    uint32_t macCommandsHeard;
    uint32_t macRefusedRequests;
    uint32_t macPollsSkipped;
    uint32_t macPollsUnanswered;
    uint32_t macPollArrivalsDropped;
    uint32_t macTransactionsExpired;
    uint32_t macTimeouts;
    uint32_t macOutstanding;
    uint32_t macTransactionQueue;

    /* nwk, receive family */
    uint32_t nwkCarrierOther;
    uint32_t nwkDroppedMalformed;
    uint32_t nwkDroppedUnsupported;
    uint32_t nwkDroppedDuplicate;
    uint32_t nwkDroppedNotForMe;
    uint32_t nwkDroppedNoRoute;
    uint32_t nwkDroppedEndDeviceInitiator;
    uint32_t nwkDroppedIndications;
    uint32_t nwkBttFullDrops;
    uint32_t nwkRecognizedCommands;
    uint32_t nwkRxSecurityFailures;
    uint32_t nwkRxFrameCounterRejects;
    uint32_t nwkDroppedUnsecured;
    uint32_t nwkNeighborAddsRefused;
    uint32_t nwkIndicationsAccounted;    /* every NLDE indication, counted by what the APS gate made of it */

    /* 3.6.4.5.1's reception: the requests the capture carries, and the five drops that clause prints */
    uint32_t nwkRouteRequestsSent;
    uint32_t nwkRouteRepliesSent;
    uint32_t nwkRreqDroppedEndDevice;
    uint32_t nwkRreqDroppedNoNeighbor;
    uint32_t nwkRreqDroppedNoOutgoingCost;
    uint32_t nwkRreqDroppedGreaterCost;
    uint32_t nwkRreqDroppedNoDiscoverySlot;

    /* nwk, send family */
    uint32_t nwkRefusedRequests;
    uint32_t nwkConfirmsIgnored;
    uint32_t nwkRelaysSent;
    uint32_t nwkReplyCommands;
    uint32_t nwkTxSecurityFailures;
    uint32_t nwkConfirmQueue;
    uint32_t nwkTransmitQueue;
    uint32_t nwkBttQueue;
    uint32_t nwkNeighborQueue;
    uint32_t nwkRouteQueue;
    uint32_t nwkIndicationQueue;

    /* security */
    uint32_t securityWindows;
    uint32_t securityOutgoing;

    /* aps */
    uint32_t apsRefusedRequests;
    uint32_t apsUnmatchedAcks;
    uint32_t apsConfirmsIgnored;
    uint32_t apsRetransmitRefusals;
    uint32_t apsRxShapeRefused;
    uint32_t apsRxMalformed;
    uint32_t apsRxSecuredDeferred;
    uint32_t apsRxCommandDeferred;
    uint32_t apsRxDuplicateDrops;
    uint32_t apsDroppedGroupMiss;
    uint32_t apsAcksGenerated;
    uint32_t apsAcksRefused;
    uint32_t apsDroppedIndications;
    uint32_t apsGroupRefusals;
    uint32_t apsTxNoKeyPair;
    uint32_t apsTxSecuredFailures;
    uint32_t apsRxSecuredFailuresAuth;
    uint32_t apsRxSecuredFailuresCounters;
    uint32_t apsConfirmQueue;
    uint32_t apsTransmitQueue;
    uint32_t apsGroupQueue;
    uint32_t apsIndicationQueue;

    /* drive and backend */
    uint32_t steps;
    uint32_t stepsRefusingTx;
    uint32_t apsIndications;
    uint32_t apsConfirms;
    uint32_t macPollEvents;
    uint32_t backendIssued;
    uint32_t backendSent;
    uint32_t shimRefusals;
} Ledger;

/* Phase A's run, kept for phase D: the same capture's ledger without a shim, compared counter by counter
   against the run that had one. */
extern Ledger s_plainPrimary;

/* One capture, read by the shared annotated-fixture loader into this suite's own fixed-width table. */
void loadCapture(const char *path, Capture *cap, uint32_t wanted, const char *what);

/* The device, assembled from scratch and read back before any frame is driven through it. */
void bringMacUp(Mac_Mac *mac, uint16_t ownShort);
void rigBuild(Rig *rig, uint16_t ownShort, int wantSecurity, uint8_t keyOctet, uint8_t keySeq, int wantDeny);
void rigAssert(const Rig *rig, uint16_t ownShort);

/* The drives that read a capture: the replay every phase runs, and the same capture through `mac` alone. */
void driveReset(Driven *out);
void driveReplay(Rig *rig, const Capture *cap, Driven *out);
void measureMacRow(const Capture *cap, MacView *out);

/* What the three layers and the shim reported after a replay. */
void readLedger(const Rig *rig, const Driven *driven, Ledger *out);

#endif /* INTEROP_HELPERS_H */
