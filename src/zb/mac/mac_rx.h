#ifndef MAC_RX_H
#define MAC_RX_H

/*
 * The receive classification and the indication ring; docs/internals/protocol.md §9.2 and §9.3 own its contract.
 */

#include <stdint.h>

#include "mac_beacon.h"
#include "mac_assoc.h"
#include "radio.h"
#include "zb_limits.h"
#include "zb_status.h"

enum
{
    MAC_INDICATION_QUEUE_MAX = ZB_LIMIT_MAC_INDICATION, /* received frames waiting for the layer above to take */

    /* The two claims that refuse a frame's footer, as bits of the log record 6.6.2's discard writes: the
       radio's bad-FCS flag on the frame it delivered, and 7.2.11's recomputation over the delivered octets. A
       radio report that names neither (a duplicate, a receive error) refuses nothing. */
    MAC_RX_FCS_RADIO = 1,
    MAC_RX_FCS_CHECKSUM = 2
};

/* The log record's argument for a refused frame: 6.6.2 a) and b)'s two refusals, a malformed header, and a
   defined form this build has no header for. */
typedef enum Mac_RxRefusal
{
    MAC_RX_REFUSED_RESERVED_TYPE = 1,
    MAC_RX_REFUSED_RESERVED_VERSION = 2,
    MAC_RX_REFUSED_MALFORMED = 3,
    MAC_RX_REFUSED_UNBUILT = 4
} Mac_RxRefusal;

/* The receive subject's own state: the ring the classification delivers through, the polls one step's batch
   detected in the order their answers are extracted, the eight numbers a heard carrier is counted by, and the
   caller's batch the step delivered. */
typedef struct Mac_Rx
{
    Mac_DataIndicationParameters indications[MAC_INDICATION_QUEUE_MAX];
    uint32_t indicationHead;
    uint32_t indicationCount;

    Mac_PollArrival stepPolls[RADIO_FRAME_BATCH_MAX];
    uint32_t stepPollCount;

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

    Radio_Frame batch[RADIO_FRAME_BATCH_MAX];
} Mac_Rx;

/* One delivered PSDU, classified once by the header this module read, then queued or consumed: 3.6.2.2's order over
   the caller's pools. `pib` with `ownExtendedKnown`/`ownExtended` (6.2) and the two 7.3.1.4's bits are the caller's
   facts, and `beacon`, `polls`, `assoc` and `tx` the subjects the findings go to: `mac`, only the doors they walk. */
void MacRx_QueueFrame(Mac_Rx *rx, const Radio_Frame *frame, const Radio_Pib *pib, const Radio_Caps *caps,
                      int ownExtendedKnown, uint64_t ownExtended, int beaconAnswers, int beaconPanCoordinator,
                      int promiscuous, Mac_Beacon *beacon, Mac_PollEvents *polls, Mac_Assoc *assoc,
                      Mac_Tx *tx, Mac_Mac *mac);

/* How many frames the ring the classification delivers through still has room for. */
uint32_t MacRx_Room(const Mac_Rx *rx);

/* The frames the classification queued, oldest first, taken the way the confirmations are taken. */
uint32_t MacRx_PollIndications(Mac_Rx *rx, Mac_DataIndicationParameters *out, uint32_t max);

/* R23.1 D.10.2's poll events, oldest first, out of the ring the caller holds. */
uint32_t MacRx_PollArrivals(Mac_PollEvents *polls, Mac_PollArrival *out, uint32_t max);

#endif /* MAC_RX_H */
