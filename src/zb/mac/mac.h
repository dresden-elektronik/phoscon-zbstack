#ifndef MAC_H
#define MAC_H

/* Band A's own 802.15.4 MAC: docs/internals/architecture.md places it and its §5.1 names the SAP pair it speaks, and
   docs/internals/conformance.md §1 states the coordinator's queue rules it implements. */

#include <stdint.h>
#include "log.h"
#include "mac_frame.h"
#include "radio.h"
#include "zb_limits.h"
#include "zb_status.h"

enum
{
    MAC_TX_TRACK_MAX = ZB_LIMIT_MAC_TX_TRACK, /* transmits issued, and the confirmations their answers produced */

    /* 8.3.5/8.3.6's `Timestamp` field: the unit is the device's, not a millisecond and not a microsecond, so it travels as ticks and is never converted here. */
    MAC_NO_STAMP = 0,

    /* docs/internals/protocol.md §8.3: a completion that never arrives means the radio is stuck or the RCP reset, and
       re-arming is the only honest next step. 1000 ms is band A's own number, open. */
    MAC_COMPLETION_TIMEOUT_MS = 1000,

    MAC_DSN_WRAP = 256,

    /* Table 8-36's macMaxFrameRetries default, the budget a direct frame carries until band A sets the field. */
    MAC_MAX_FRAME_RETRIES_DEFAULT = 3,

    /* 10.22.2, Transaction handling, gives a floor and no cap for the transaction store, so the coordinator's
       queue is this module's own pool: full is refusal-and-count where the SAP would say TRANSACTION_OVERFLOW
       (docs/internals/coding-rules.md §4.3). */
    MAC_TRANSACTION_MAX = ZB_LIMIT_MAC_TRANSACTION,

    /* 8.3.2's MsduHandle names one MSDU a caller handed down; this module's own frames (a beacon, a poll's
       zero-length answer, an extraction) carry none and owe the caller no confirm (8.3.5). */
    MAC_MSDU_HANDLE_NONE = 0xff,

    /* 10.22.2's confirmations for the transactions the indirect queue finishes, drained beside the transmit
       confirms because 8.3.5's primitive is one: full is a refusal of the newest and a count. */
    MAC_INDIRECT_CONFIRM_MAX = 4,

    /* The same pool for the other primitive: a transaction an MLME response instigated is reported through
       MLME-COMM-STATUS.indication, not as an MCPS confirm a caller's handle could be matched to. */
    MAC_COMM_STATUS_MAX = 4,

    /* 10.22.2's persistence limit: Table 8-36, macTransactionPersistenceTime, keys that unit to macBeaconOrder
       and defines it for this PAN, the arithmetic in docs/internals/conformance.md §1. 30000 ms is band A's own number
       against it, open. */
    MAC_TRANSACTION_PERSISTENCE_MS = 30000,

    /* Table 8-36, macResponseWaitTime: 32 aBaseSuperframeDurations of 960 symbols at 62.5 ksymbol/s is 491.52 ms,
       rounded up, open as a number. 10.21.2 attempts the extraction "after macResponseWaitTime" and concludes
       NO_DATA "within macResponseWaitTime" of that attempt, so the deadline is two of these (docs/internals/conformance.md). */
    MAC_RESPONSE_WAIT_MS = 492,

    /* R23.1 3.6.1.6.1.2, the extraction: one MLME-POLL.request is owed before macResponseWaitTime elapses and more
       than one is permitted. 123 ms is band A's own interval between them inside the window the first one opens,
       open as a number: a quarter of the window, so four attempts fit before the deadline. */
    MAC_ASSOC_POLL_DELAY_MS = 123,

    /* 10.22.3's "expected time" after an Ack with Frame Pending one: macMaxFrameTotalWaitTime, 2006 Equation 14, is
       1986 symbols or 32 ms at the default PIB, and both ends here are hosts behind a serial link whose completions
       arrive 14 to 21 ms after the request (docs/internals/protocol.md §8.3). Band A's own number, open. */
    MAC_POLL_WAIT_MS = 100,

    /* How long an Association Request the transmit door had no room for is held and re-asked: band A's own number,
       one macResponseWaitTime, after which the exchange fails with TRANSACTION_OVERFLOW (docs/internals/decisions.md). */
    MAC_ASSOC_SEND_WAIT_MS = MAC_RESPONSE_WAIT_MS,

    /* MLME-SCAN.request's ScanDuration is symbol periods (Table 8-18), 16 us each on the O-QPSK PHY at 2450 MHz, taken up
       to the longest dwell a Zigbee discovery asks for (aBaseSuperframeDuration * (2^14 + 1)); the channels an active
       scan visits (11 to 26 of page 0), and how long a channel write or Beacon Request is re-asked for want of room. */
    MAC_SYMBOL_US = 16,
    MAC_SCAN_SYMBOLS_MAX = 960 * 16385,
    MAC_SCAN_CHANNEL_FIRST = 11,
    MAC_SCAN_CHANNEL_LAST = 26,
    MAC_SCAN_HOLD_MS = MAC_RESPONSE_WAIT_MS,

    /* How long a beacon reply the transmit door had no room for is re-asked before it is counted refused: band A's
       own number, open, short because the scanner listens on the channel only for a dwell this device cannot know. */
    MAC_BEACON_HOLD_MS = 100,

    /* A poll is an event for the layer above, and one batch can deliver at most RADIO_FRAME_BATCH_MAX of
       them; R23.1 D.10.2 says nothing about how many may wait. Same full-pool policy as the queue below
       it: the newest arrival is refused and counted. */
    MAC_POLL_EVENT_MAX = 8,

    /* 10.21.5.1: an Association Request is an event for the layer above, the parent's decision to make. The
       ring is the poll ring's shape and the same full-pool policy: the newest arrival is refused and counted. */
    MAC_ASSOCIATION_MAX = 8,

    /* Table 7-11's command frame: the one identifier octet, and the Content the clause after it describes. */
    MAC_CMD_FRAME_OCTETS = 1,

    /* Table 7-11's association pair: 10.21.5.1 sends the request from an unassociated device, 10.21.5.2 sends
       the response from the coordinator, and the two bodies are mac_frame's. */
    MAC_CMD_ASSOCIATION_REQUEST = 0x01,
    MAC_CMD_ASSOCIATION_RESPONSE = 0x02,

    /* Table 7-11's 0x04 Data Request command: 10.22.4.1 pins its Frame Pending field to zero, and 10.22.5.2
       makes the poll the asking device's own act, which is why it is never a transaction queued here. */
    MAC_CMD_POLL = 0x04,

    /* 10.21.5.1's request as it arrives: Table 7-11's identifier octet and Figure 10-151's capability octet. */
    MAC_ASSOC_REQUEST_PAYLOAD_OCTETS = 2,

    /* Table 7-11's orphan pair: 10.20.3.1's notification, which has no Content, and 7.5.4's realignment, whose
       Content is the PAN ID, the coordinator's short address, the channel and the orphan's short address. */
    MAC_CMD_ORPHAN_NOTIFICATION = 0x06,
    MAC_CMD_COORDINATOR_REALIGNMENT = 0x08,
    MAC_REALIGNMENT_OCTETS = 8,

    /* 10.20.4.2's indications waiting for the layer above: full is a refusal and a count. */
    MAC_ORPHAN_MAX = 4,

    /* Table 7-11's 0x07 Beacon Request. R23.1 3.6.5 owes it an answer and D.11.1.5 obliges every coordinator and
       router to give one; 7.5.2 pins the request's own shape, which macBeaconRequestShape checks. */
    MAC_CMD_BEACON_REQUEST = 0x07,

    /* Table 7-11's reserved range: from 0x2b nothing is a command */
    MAC_CMD_RESERVED_FIRST = 0x2b,

    /* R23.1 3.6.8.2 hands the beacon payload down as opaque octets (macBeaconPayload, written by the network
       layer), so band A carries it and does not read it. The pool is this module's own and its policy is the
       usual one: a payload that does not fit is refused and counted, never truncated. */
    MAC_BEACON_PAYLOAD_MAX = 40,

    /* The beacons waiting for the layer above: 8.2.4.3's primitive is an event of its own, and two is the ring a
       caller that reads its notifications every step needs. */
    MAC_BEACON_NOTIFY_MAX = 2,

    /* 7.3.1, Figure 7-5's MAC payload at its widest for this module: the Superframe Specification, the GTS
       fields, the Pending Address Specification, seven short and seven extended pending addresses, and the
       beacon payload. A beacon larger than this is a beacon this module does not compose. */
    MAC_BEACON_BODY_MAX = 4 + (7 * 8) + MAC_BEACON_PAYLOAD_MAX,   /* 7.3.1.6: seven addresses, the widest 8 octets */

    /* 10.22.4.1: "If macShortAddress is less than 0xfffe, short addressing shall be used", 0xfffe being what
       a coordinator's unknown short address carries. A source field this module sets applies the same test. */
    MAC_SHORT_ADDRESS_LAST_USABLE = 0xfffe,

    /* Two of Table 3-80's classes, named where the layer that reads them is: R23.1 3.2.1.1.3 item 6, the DstAddr
       mapping, turns a NWK destination of 0xFFFD or 0xFFFC into a MAC `DstAddr` of 0xFFFF, so neither reaches
       this module as a broadcast; Table 10-101, the short-address ranges, puts both inside "0x0000-0xfffd". */
    MAC_ZB_ADDR_ALL_RX_ON = 0xfffd,
    MAC_ZB_ADDR_ALL_ROUTERS = 0xfffc,

    /* Table 7-4's frame versions, as the Version field carries them: 0b10 is the 2015 revision's, the one value
       10.21.5.1 lets omit an Association Request's Source PAN ID field ("If the Version field is set to 0b10, the
       Source PAN ID field is omitted"). This stack writes version 0 (R23.1 Annex D.6) and reads both. */
    MAC_FRAME_VERSION_2015 = 2
};

/* Table 10-102's valid Association Status values. 0x03, 0x80 and 0x81 are the table's other named values
   (hopping-sequence duplication, fast association, suspendable CSMA-CA) and this stack's association procedure
   produces none of them: the codec carries the octet and the procedure judges it. */
typedef enum Mac_AssociationStatus
{
    MAC_ASSOC_STATUS_SUCCESS = 0x00,
    MAC_ASSOC_STATUS_PAN_AT_CAPACITY = 0x01,
    MAC_ASSOC_STATUS_PAN_ACCESS_DENIED = 0x02
} Mac_AssociationStatus;

/* What the application supplies that the seam cannot: the seed 6.6.1's macDsn starts from, and Table 8-36's
   default for macDsn prints "Random value from within the range", taken as a seed and never drawn, since what
   random means is the application's duty. A `0` config is that same default, stated rather than assumed. */
typedef struct Mac_Config
{
    uint8_t dsnStart;             /* the initial macDsn, held unwrapped: the first frame issued carries it,
                                     and every octet on the air is that value modulo MAC_DSN_WRAP */
    uint8_t bsnStart;             /* the initial macBSN, the beacon's own number (7.3.1.2): a separate
                                     counter from the DSN, seeded the same way and drawn the same way */
    int macPromiscuousMode;       /* Table 10-114's Boolean, default FALSE: TRUE is 10.23.1's receive-all
                                     mode, which delivers every correctly received frame upward */
    int hearsWhileAsleep;         /* 1: a device with macRxOnWhenIdle FALSE keeps what its radio heard between
                                     polls; 0, the default, discards it as a sleeping radio never heard it */

    /* The diagnostics pool this module reports through, or 0 for none: the caller owns it and drains it, the
       way it does for every other module that logs (docs/internals/coding-rules.md §5). A 0 sink costs no report. */
    Log_Log *log;
} Mac_Config;

/* One tracked transmit's lifecycle, docs/internals/coding-rules.md §3's explicit states: "answered" and "gave up on"
   are different facts, and only the second sets `needsRearm`. */
typedef enum Mac_TxState
{
    MAC_TX_FREE = 0,        /* no transmit in this slot */
    MAC_TX_OUTSTANDING = 1, /* issued; the seam has not answered */
    MAC_TX_ANSWERED = 2,    /* the seam answered; its confirmation is waiting to be polled */
    MAC_TX_TIMED_OUT = 3    /* nobody answered in time; this is what sets `needsRearm` */
} Mac_TxState;

/* The associating device's half of 10.21.2 (Figure 10-152): the request goes out and is acknowledged, the
   coordinator's decision waits in its transaction queue, and a Data Request extracts it (10.22.3). One machine owns
   the sequence; the layer above reads the outcome through the confirm and the state. */
typedef enum Mac_AssocState
{
    MAC_ASSOC_IDLE = 0,
    MAC_ASSOC_REQUESTING = 1,
    MAC_ASSOC_WAITING = 2,
    MAC_ASSOC_POLLING = 3,
    MAC_ASSOC_DONE = 4,
    MAC_ASSOC_FAILED = 5,
    MAC_ASSOC_SENDING = 6       /* the PIB is written and the request waits for room at the transmit door */
} Mac_AssocState;

/* Table 8-30, the MCPS-DATA.request parameters: `frameType` and `ackRequest` are what Table 8-29's SendMultipurpose
   and AckTx decide, `framePending` is the Frame Pending bit 10.22.2 sets and no request parameter, the Msdu is
   `payload` with its `payloadLen`, and DstPanId and DstAddr are `destPan` and `destShort`/`destExtended`. */
typedef struct Mac_DataRequestParameters
{
    uint8_t msduHandle;
    uint32_t frameType;
    Mac_AddrMode destAddrMode;
    Mac_AddrMode srcAddrMode;
    uint16_t destPan;
    uint16_t destShort;
    uint64_t destExtended;
    int ackRequest;
    int framePending;
    const uint8_t *payload;
    uint32_t payloadLen;
} Mac_DataRequestParameters;

/* Table 8-31, the MCPS-DATA.confirm parameters: `handle` is its MsduHandle at the seam's width; `dsn`, `frameType`
   and `acked` are not the table's; they say which frame was confirmed (7.2.3's sequence number, Table 7-1's type)
   and whether the radio heard it acknowledged. */
typedef struct Mac_DataConfirmParameters
{
    uint8_t msduHandle;
    Radio_Handle handle;
    uint32_t dsn;
    int frameType;
    ZbStatus status;
    int acked;
    uint32_t numBackoffs;
    int framePending;
} Mac_DataConfirmParameters;

/* Table 8-10's MLME-COMM-STATUS.indication: the status a transaction's completion carries, the destination the
   frame named, which is what relates it to the response primitive, the PAN it was on, and whether the radio heard
   the acknowledgment. */
typedef struct Mac_CommStatusParameters
{
    ZbStatus status;
    Mac_AddrMode destAddrMode;
    uint16_t destPan;
    uint16_t destShort;
    uint64_t destExtended;
    int acked;
} Mac_CommStatusParameters;

/* Table 8-4's MLME-BEACON-NOTIFY.indication: 8.2.4.3's Sn and Table 8-3's PanDescriptor (ChannelNumber the radio's
   channel), plus 7.3.1.6's Address List which 10.22.3 reads and Table 8-3 does not carry, and R23.1 3.6.8.2's
   macBeaconPayload as the received beacon carried it, copied because the frame is not handed up. */
typedef struct Mac_BeaconNotification
{
    uint8_t sn;
    Mac_AddrMode coordAddrMode;
    uint16_t coordPanId;
    uint16_t coordShort;
    uint64_t coordExtended;
    int32_t rssiDbm;
    uint32_t lqi;
    uint64_t stampTicks;
    uint32_t beaconOrder;
    uint32_t superframeOrder;
    uint32_t finalCapSlot;
    int batteryLifeExtension;
    int panCoordinator;
    int associationPermit;
    int gtsPermit;

    uint16_t pendingShort[MAC_FRAME_PENDING_MAX];
    uint32_t pendingShortCount;
    uint64_t pendingExtended[MAC_FRAME_PENDING_MAX];
    uint32_t pendingExtendedCount;

    uint32_t payloadLen;
    uint8_t payload[MAC_BEACON_PAYLOAD_MAX];
    uint32_t channel;
} Mac_BeaconNotification;

/* Table 8-32's MCPS-DATA.indication: Dsn, FramePending and DataFrameVersion are `header`, the Msdu is
   `payloadOffset`/`payloadLen` inside `len`/`bytes`, `lqi`/`stampTicks`/`rssiDbm` are the link, and `len` is the
   carrier delivered, so 10.23.1's Msdu is `[0, payloadOffset + payloadLen)`; `ackedWithFramePending` is ours. */
typedef struct Mac_DataIndicationParameters
{
    int headerValid;
    Mac_Frame header;
    uint32_t frameType;
    uint32_t len;
    uint8_t bytes[RADIO_MPDU_MAX];
    uint32_t payloadOffset;
    uint32_t payloadLen;
    int32_t rssiDbm;
    uint32_t lqi;
    uint64_t stampTicks;
    ZbStatus status;
    int ackedWithFramePending;
} Mac_DataIndicationParameters;

/* One transmit and what became of it: the confirmation *is* this slot, so there is one pool and not two, and
   a band A that never collects its confirmations is told ZB_ERR_NO_SPACE rather than having one
   overwritten (docs/internals/coding-rules.md §4.3). */
typedef struct Mac_Track
{
    uint8_t msduHandle;
    int confirmOwed;
    Radio_Handle handle;
    uint32_t dsn;
    uint32_t issuedMs;
    int frameType;
    int ackRequest;
    Mac_TxState state;

    ZbStatus status;
    int acked;
    uint32_t numBackoffs;
    int framePending;
    int framePendingReported;
    int isExtraction;
} Mac_Track;

/* 10.22.2's transaction, an indirect transmission request held in the queue: Table 8-30's addressing parameters, the
   frame type and the Msdu as `payload`/`payloadLen`, the `dsn` 6.6.3.4 re-extracts, the queue's own `used`,
   `arrivedMs`, `attemptPending` and `attemptHandle`, and whether a response primitive or a request started it. */
/* 6.6.3.4's AR=0 limb needs the ask the request carried, which is `ackRequest` below and is no table's row. */
typedef struct Mac_Transaction
{
    int used;

    uint32_t dsn;

    uint8_t msduHandle;

    uint32_t arrivedMs;

    int attemptPending;
    Radio_Handle attemptHandle;

    uint32_t frameType;

    Mac_AddrMode destAddrMode;
    Mac_AddrMode srcAddrMode;
    uint16_t destPan;
    uint16_t destShort;
    uint64_t destExtended;

    uint32_t payloadLen;
    uint8_t payload[MAC_FRAME_MPDU_MAX];

    int ackRequest;

    int isMlmeInstigated;
} Mac_Transaction;

/* A Data Request this coordinator received, as R23.1 Annex D.10.2 names its event, MLME-Poll.indication
   {AddrMode, DeviceAddress}, the two fields below. The poll's `dsn` and `stampTicks` are house fields: which
   of the polls this device sent an arrival was. The raw command frame stays in the indication queue. */
typedef struct Mac_PollArrival
{
    Mac_AddrMode addrMode;
    uint16_t shortAddress;
    uint64_t extendedAddress;
    uint32_t dsn;
    uint64_t stampTicks;
} Mac_PollArrival;

/* R23.1 D.10.2's events as the band holds them: the ring the receive classification queues into and the layer
   above drains, with the number it could not report. */
typedef struct Mac_PollEvents
{
    Mac_PollArrival arrival[MAC_POLL_EVENT_MAX];
    uint32_t head;
    uint32_t count;
    uint32_t dropped;
} Mac_PollEvents;

/* 10.21.5.1's Association Request as the parent reports it: the child's extended address (the clause fixes the
   source addressing mode to extended), the PAN the request names, the Capability Information field, and the
   device's stamp. The short address the child is given is the layer above's decision and not part of this. */
typedef struct Mac_AssociationIndication
{
    uint64_t extendedAddress;
    uint16_t destPan;
    MacFrame_Capability capability;
    uint64_t stampTicks;
} Mac_AssociationIndication;

/* 10.21.5.2's answer: the request the answer is for (the child's extended address and the capability that
   decides 10.21.2's Allocate Address rule), the short address (0xfffe on a success with no allocation, 0xffff
   on a failure) and Table 10-102's status. The destination PAN is the PIB's and the source this device's. */
typedef struct Mac_AssociationResponse
{
    Mac_AssociationIndication request;
    uint16_t shortAddress;
    uint8_t status;
} Mac_AssociationResponse;

/* Table 10-104, the MLME-ASSOCIATE.request parameters this stack carries: CoordPanId is `destPan`, CoordAddress is
   the parent's and `parentShortKnown` says which form of it the beacon named, ChannelInfo is `channel` (0 leaves
   the radio's channel alone) and CapabilityInformation is `capability`. */
typedef struct Mac_AssociateRequestParameters
{
    uint16_t destPan;
    int parentShortKnown;
    uint16_t parentShort;
    uint64_t parentExtended;
    uint32_t channel;
    MacFrame_Capability capability;
} Mac_AssociateRequestParameters;

/* Table 10-107, the MLME-ASSOCIATE.confirm parameters this stack carries, the GTS and hopping rows of the table
   having no PAN here: Status is `status`, AssociationStatus the response's octet and AssocShortAddress
   `shortAddress`, and the parent is this record's own, 10.21.2 storing that identity where the table prints none. */
typedef struct Mac_AssociateConfirmParameters
{
    uint8_t status;
    uint8_t associationStatus;
    uint16_t shortAddress;
    int parentShortKnown;
    uint16_t parentShort;
    uint64_t parentExtended;
} Mac_AssociateConfirmParameters;

/* MLME-SCAN.request's ScanType values this module takes: the ED scan, which a Zigbee NLME-ED-SCAN asks for, the
   active scan 10.19 describes, which a Zigbee network discovery asks for, and 10.20's orphan scan, which a Zigbee
   orphan rejoin asks for; any other is an argument error. */
typedef enum Mac_ScanType
{
    MAC_SCAN_ENERGY = 0,
    MAC_SCAN_ACTIVE = 1,
    MAC_SCAN_ORPHAN = 3
} Mac_ScanType;

/* The parameters of MLME-SCAN.request (8.2.8.2) this module carries: ScanType, ScanChannels as a mask of page 0's
   channels (bit n for channel n) and ScanDuration in symbol periods. */
typedef struct Mac_ScanRequestParameters
{
    uint32_t scanType;
    uint32_t scanChannels;
    uint32_t scanDuration;
} Mac_ScanRequestParameters;

/* MLME-SCAN.confirm (8.2.8.3): Status, ScanType, UnscannedChannels, an active scan's beacons counted as they went up,
   an orphan scan's realignment (7.5.4's fields 10.20.1 writes, and its source), and an ED scan's EnergyDetectList as
   channel 11 + i's peak in the radio's dBm, not the octet; a channel no dwell measured is left unscanned. */
typedef struct Mac_ScanConfirmParameters
{
    uint8_t status;
    uint32_t scanType;
    uint32_t unscannedChannels;
    int8_t energyDbm[MAC_SCAN_CHANNEL_LAST - MAC_SCAN_CHANNEL_FIRST + 1];
    uint32_t beaconsHeard;
    int realigned;
    uint16_t panId;
    uint16_t coordShort;
    uint64_t coordExtended;
    uint32_t channel;
    uint16_t shortAddress;
} Mac_ScanConfirmParameters;

/* Table 10-112's MLME-POLL.request: the coordinator the Data Request goes to. SecurityParams is absent, as on every
   MAC command this stack sends (R23.1 Annex D.6). */
typedef struct Mac_PollRequestParameters
{
    Mac_AddrMode coordAddrMode;
    uint16_t coordPanId;
    uint16_t coordShort;
    uint64_t coordExtended;
} Mac_PollRequestParameters;

/* Table 10-113's MLME-POLL.confirm: SUCCESS, NO_DATA, or the transmit's failure. `framePending` is ours: the
   delivered frame's Frame Pending bit, which 10.22.3 says means more is held. */
typedef struct Mac_PollConfirmParameters
{
    ZbStatus status;
    int framePending;
} Mac_PollConfirmParameters;

/* 10.20.4.2's MLME-ORPHAN.indication: the extended address an Orphan Notification came from. */
typedef struct Mac_OrphanIndication
{
    uint64_t orphanAddress;
} Mac_OrphanIndication;

/* 10.20.4.3's MLME-ORPHAN.response: the orphan, the short address it was allocated, and whether it is a member. */
typedef struct Mac_OrphanResponseParameters
{
    uint64_t orphanAddress;
    uint16_t shortAddress;
    int associatedMember;
} Mac_OrphanResponseParameters;

/* What the module has counted and what its pools held at the instant of the call, so the numbers a suite
   compares are numbers about one moment and not about the order of two calls (docs/internals/coding-rules.md §4.3). */
typedef struct Mac_Counters
{
    uint32_t refusedRequests;
    uint32_t ackAskCleared;
    uint32_t indirectIgnored;
    uint32_t pollsSkipped;
    uint32_t confirmQueue;
    uint32_t indicationQueue;
    uint32_t outstanding;
    uint32_t transactionQueue;
    uint32_t pollArrivalQueue;
    uint32_t transactionsExpired;
    uint32_t commStatusQueue;
    uint32_t commStatusRefused;
    uint32_t pollsUnanswered;
    uint32_t pibReapplications;
    uint32_t acksHeard;
    uint32_t commandsHeard;
    uint32_t selfEchoes;
    uint32_t fcsFailures;
    uint32_t reservedTypeFrames;
    uint32_t reservedVersionFrames;
    uint32_t malformedFrames;
    uint32_t unbuiltForms;
    uint32_t panMismatches;
    uint32_t destinationMismatches;
    uint32_t beaconPanMismatches;
    uint32_t sourcePanMismatches;
    uint32_t promiscuousDelivered;
    uint32_t beaconRequestsHeard;
    uint32_t beaconReplies;
    uint32_t beaconIgnored;
    uint32_t beaconRefused;
    uint32_t beaconPendingDropped;
    uint32_t beaconsNotified;
    uint32_t beaconsNoPayload;
    uint32_t beaconsNotifyDropped;
    uint32_t beaconsUnreadable;
    uint32_t enhancedBeaconsUnbuilt;
    uint32_t beaconsPayloadOverflow;
    uint32_t associationQueue;
    uint32_t associationsDropped;
    uint32_t assocDroppedNotAsked;
    uint32_t assocDroppedNotOurs;
    uint32_t assocDroppedSource;
    uint32_t assocDroppedParent;
    uint32_t assocDroppedMalformed;
    uint32_t assocDroppedAddress;
    uint32_t assocRequestDroppedSource;
    uint32_t assocRequestDroppedContent;
    uint32_t assocRequestDroppedNotOurs;
    uint32_t assocRequestDroppedFast;
    uint32_t assocRequestDroppedUnparsable;
    uint32_t pollsRequested;
    uint32_t pollsWithData;
    uint32_t pollsNoData;
    uint32_t heardAsleep;
    int needsRearm;
} Mac_Counters;

/* The topic records' types are named over the SAP's: `Mac_Tx` names `Mac_Track`, `Mac_Indirect` names
   `Mac_Transaction`, `Mac_Rx` names `Mac_DataIndicationParameters` in its ring, `Mac_Beacon` the payload and body
   pools and `Mac_Assoc` the association records; `mac_assoc.h` names this record, so it comes first. */

typedef struct Mac_Mac Mac_Mac;

#include "mac_beacon.h"
#include "mac_indirect.h"
#include "mac_tx.h"
#include "mac_assoc.h"
#include "mac_rx.h"
#include "mac_scan.h"

struct Mac_Mac
{
    /* Band A holds this only to call through `ops`: reading or casting `provider` is the violation
       docs/internals/coding-rules.md §4.6 names, and nothing in this module does either. */
    Radio_Radio *radio;
    Radio_Caps caps;
    Radio_Pib pib;

    /* Band A's own record of what it asked this device to hold: the mask every accepted `Mac_SetPib` named, with
       the values it named with it. It is not a copy of `pib` (that one is the report the device gave, and it
       carries the factory address no call above the seam may write) and it is what a re-application hands back. */
    Radio_Pib applied;

    /* 3.6.2.2's classification and the indication ring: the frames this device heard and delivered, the eight
       numbers a heard carrier is counted by, and the batch a step's delivery is classified out of. */
    Mac_Rx rx;

    /* The coordinator half of the poll: what is queued for a device that cannot receive, and the polls that
       come to take it. */
    Mac_Indirect indirect;

    /* The device half: the poll this device sent its own coordinator, and the window it listens in after it. */
    Mac_ChildPoll childPoll;
    int hearsWhileAsleep;

    /* D.10.2's poll events waiting for the layer above, written by the classification in `mac_rx`. */
    Mac_PollEvents polls;

    /* 10.21.5's parent door beside 10.21.2's child sequence: the association subject's own state. */
    Mac_Assoc assoc;
    Mac_Scan scan;

    uint8_t mpdu[RADIO_MPDU_MAX];

    /* The diagnostics pool the receive classification reports through (6.6.2's refusals), or 0 for none. */
    Log_Log *log;

    uint32_t bsn;                   /* the BSN the next beacon will carry (7.3.1.2), counted apart from the DSN */
    int macPromiscuousMode;         /* Table 10-114: 10.23.1's receive-all mode, the MAC's own Boolean */
    uint32_t refusedRequests;       /* requests this module declined, with the reason it named */
    uint32_t ackAskCleared;         /* frames 6.6.3.1 sends asking nothing, the caller having asked */
    uint32_t indirectIgnored;       /* indirect requests 8.3.4 sends directly, the option ignored */
    int coordinatorKnown;           /* whether the layer above has said what this device's role is */
    int coordinatorIs;              /* and what it said */
    uint32_t pollsSkipped;          /* polls it did not make because it had nowhere to put the answer, or a scan's beacon */
    uint32_t timeouts;

    /* The on-demand beacon (7.5.2, R23.1 3.6.5): what this device answers with, and what it has counted. */
    Mac_Beacon beacon;

    /* What a backend seen lost leaves behind: `lostEpisode` while the last sighting was a device that was not
       there, and `reapplyPending`, what band A applied owed to a device that came back from its own defaults
       (docs/internals/protocol.md §7.2); `pibReapplications` counts the re-applications it accepted. */
    int lostEpisode;
    int reapplyPending;
    uint32_t pibReapplications;

    /* The delivery mode band A stated, owed again with the pending table to a device back from its defaults,
       which an RCP re-arms promiscuous and so acknowledging nothing (10.23.1). */
    int filterStated;
    int restatePending;

    int needsRearm;

    /* The transmit subject's state: the track pool the confirmations are read out of, and the DSN it issues at. */
    Mac_Tx tx;
};

/* Adopt a backend: read its capabilities and its PIB and start from what it says rather than from what this
   module would like. A backend not brought up answers ZB_ERR_NOT_READY here (the host brings the radio up,
   then band A takes it) and `config` is the seed of 6.6.1's macDsn, supplied and never drawn. */
ZbStatus Mac_Init(Mac_Mac *self, Radio_Radio *radio, const Mac_Config *config);

/* Change the PIB through the seam and mirror only what the backend accepted: a refused field, the
   acknowledgment wait both builds lack a property for, leaves the mirror standing, so
   band A never believes a value the radio never took. What it accepted is kept as band A's applied record. */
ZbStatus Mac_SetPib(Mac_Mac *self, const Radio_Pib *pib);
const Radio_Caps *Mac_Caps(const Mac_Mac *self);
const Radio_Pib *Mac_Pib(const Mac_Mac *self);

/* Table 10-114's macPromiscuousMode, the MAC's own Boolean and not a radio PIB field: TRUE is 10.23.1's
   receive-all mode, FALSE the first-level filter of 6.6.2 as usual. The default a fresh MAC holds is FALSE. */
ZbStatus Mac_SetPromiscuousMode(Mac_Mac *self, int on);
int Mac_PromiscuousModeOf(const Mac_Mac *self);

/* One MCPS-DATA.request: the MHR from this module's PIB and the caller's destination, the version field
   pinned to 0 as R23.1 Annex D.6 requires, the footer `mac_frame`'s, and one DSN per frame issued rather
   than per confirmation. Refused before anything is composed when the request contradicts itself. */
ZbStatus Mac_DataRequest(Mac_Mac *self, const Mac_DataRequestParameters *req, uint32_t nowMs, Radio_Handle *outHandle);

/* MCPS-DATA.request with the indirect option set: hold this for a device that cannot receive and send it when
   that device asks (10.22.2, Transaction handling); nothing goes out here. Three shapes are refused: a
   broadcast, no destination (8.3.4, MCPS-DATA.request), and a Data Request command 10.22.5.2 leaves to the child. */
ZbStatus Mac_IndirectRequest(Mac_Mac *self, const Mac_DataRequestParameters *req, uint32_t nowMs);

/* The transactions held for a device by its short address, which 10.22.2 sends when that device polls. */
uint32_t Mac_IndirectHeldFor(const Mac_Mac *self, uint16_t shortAddress);

/* 8.3.4 asks the role before a transaction may be held; the layer above answers it. */
ZbStatus Mac_SetCoordinator(Mac_Mac *self, int known, int isCoordinator);

/* Service the radio once: ask whether the device is there and, while it is not, mark and do nothing else that
   turn; once it answers again, ask for every field band A applied before composing anything from the mirror; then
   collect completions, deliver, expire, answer the polls, and stop on a full indication queue. */
ZbStatus Mac_Step(Mac_Mac *self, uint32_t nowMs);

/* Take what band A has produced, oldest first. Both return how many were copied. */
uint32_t Mac_PollConfirms(Mac_Mac *self, Mac_DataConfirmParameters *out, uint32_t max);
uint32_t Mac_PollIndications(Mac_Mac *self, Mac_DataIndicationParameters *out, uint32_t max);
uint32_t Mac_PollArrivals(Mac_Mac *self, Mac_PollArrival *out, uint32_t max);

/* The MLME's own primitive: what became of a transaction an MLME response started, oldest first, related to that
   response by the destination address it carries. The association answer is the one transaction this stack has. */
uint32_t Mac_PollCommStatus(Mac_Mac *self, Mac_CommStatusParameters *out, uint32_t max);

/* The parent's association traffic, oldest first. A request the radio delivered and this device was addressed
   by becomes an indication here; `Mac_AssociateResponse` answers it as 10.21.5.2's indirect transaction, which
   the child extracts with a Data Request (10.22.2). */
uint32_t Mac_PollAssociations(Mac_Mac *self, Mac_AssociationIndication *out, uint32_t max);

/* The beacons this device heard, oldest first, taken the way the other rings are taken (8.2.4.3). */
uint32_t Mac_PollBeacons(Mac_Mac *self, Mac_BeaconNotification *out, uint32_t max);
ZbStatus Mac_AssociateResponse(Mac_Mac *self, const Mac_AssociationResponse *response, uint32_t nowMs);

/* Table 10-104, MLME-ASSOCIATE.request written where 10.21.2 puts it, then 10.21.5.1's request. A door with no
   room for it holds the request and re-asks each step (docs/internals/decisions.md); one that refuses it otherwise leaves no PAN written,
   no address and a failed confirm carrying TRANSACTION_OVERFLOW, while the caller keeps the door's own status. */
ZbStatus Mac_AssociateRequest(Mac_Mac *self, const Mac_AssociateRequestParameters *req, uint32_t nowMs);

/* 1 when the association's outcome was taken: 10.21.6.1.5's confirm, holding Table 10-102's octet on a response,
   0xeb NO_DATA (Table 78) on the one window that saw none, and 0xe9 NO_ACK on a request that never went out, and
   the short address 10.21.2 stores into macShortAddress. */
uint32_t Mac_PollAssociateConfirm(Mac_Mac *self, Mac_AssociateConfirmParameters *out);

/* What the exchange is doing, for an owner that reads the state and not only the confirm. */
Mac_AssocState Mac_AssocStateOf(const Mac_Mac *self);

/* MLME-SCAN.request: every channel the mask names, lowest first. An active scan gives each a Beacon Request and
   ScanDuration's dwell under the broadcast PAN (6.6.2), an ED scan the radio's dwells, every channel unscanned on a
   radio with none. ZB_ERR_BAD_STATE while a scan runs. */
ZbStatus Mac_ScanRequest(Mac_Mac *self, const Mac_ScanRequestParameters *req, uint32_t nowMs);

/* 1 when the scan's confirm was taken: SUCCESS when a beacon was heard or an ED scan ended, NO_BEACON when none was
   though a Beacon Request went out, CHANNEL_ACCESS_FAILURE when none could be sent, and the channels left unscanned. */
uint32_t Mac_PollScanConfirm(Mac_Mac *self, Mac_ScanConfirmParameters *out);

/* 10.20.4.2's indications, oldest first. */
uint32_t Mac_PollOrphans(Mac_Mac *self, Mac_OrphanIndication *out, uint32_t max);

/* 10.20.4.3: a member is sent 7.5.4's realignment, directed and acknowledged; a response naming no member sends
   nothing. ZB_ERR_BAD_STATE at a device that is no coordinator. */
ZbStatus Mac_OrphanResponse(Mac_Mac *self, const Mac_OrphanResponseParameters *response, uint32_t nowMs);

/* MLME-POLL.request (10.22.5.2): a Data Request to the coordinator, answered by Mac_PollRequestConfirm. ZB_ERR_BUSY
   while an earlier poll's confirm is owed. */
ZbStatus Mac_PollRequest(Mac_Mac *self, const Mac_PollRequestParameters *req, uint32_t nowMs);

/* 1 when MLME-POLL.confirm was taken (10.22.5.3). */
uint32_t Mac_PollRequestConfirm(Mac_Mac *self, Mac_PollConfirmParameters *out);

/* Whether this device hears now: always with macRxOnWhenIdle TRUE, and otherwise only while a poll's window, a scan
   or an association is open, unless the configuration keeps what a powered radio heard between polls. */
int Mac_Hears(const Mac_Mac *self);

/* Whether a scan is running, which takes the radio off the channel the device works on. */
int Mac_Scanning(const Mac_Mac *self);

/* Every number this module reports, read at one instant: the stored counters as they are and the six queue
   depths from the pools' own head and count, so the record has no second copy to drift. A null `self` answers
   a record of zeros. */
Mac_Counters Mac_CountersOf(const Mac_Mac *self);

/* What the on-demand beacon is answered with, the record and its rules being mac_beacon.h's: the payload is
   copied and never read, and one past MAC_BEACON_PAYLOAD_MAX is ZB_ERR_NO_SPACE with nothing changed. */
ZbStatus Mac_SetBeaconConfig(Mac_Mac *self, const Mac_BeaconConfig *config);

#endif /* MAC_H */
