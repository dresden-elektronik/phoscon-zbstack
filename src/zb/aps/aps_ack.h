#ifndef APS_ACK_H
#define APS_ACK_H

/*
 * The acknowledgement machine of band A's APS sub-layer: the match that answers a transaction when an
 * acknowledgement arrives, and the answer this device owes a frame it accepted, composed by `aps_frame` and
 * handed down the adopted `nwk` outside the transaction pool, as `nwk` puts a relay or a 3.6.13 answer on the
 * air. Nothing is owned and no count moved here: the pool, the scratch and the `nwk` arrive from the caller,
 * and the wait `apscAckWaitDuration` arms stays façade-side with its retransmissions.
 */

/* `Aps_Tx` is `aps_tx`'s slot type: `aps.h` includes this header after `aps_tx.h`, as it does `aps_tx.h`
   itself after the SAP types. */

#include <stdint.h>

#include "aps_frame.h"
#include "nwk.h"

/*
 * What owing an answer ended as, named as what it is rather than as the counter each moves,
 * the shape `Nwk_RelayOutcome` states one layer down: the first three say none was owed, the last two say one
 * was owed and did not reach the seam, and both of those are `acksRefused`.
 */
typedef enum Aps_AckOutcome
{
    APS_ACK_RESPONDED = 0,      /* composed and handed down as one NLDE-DATA.request */
    APS_ACK_NOT_REQUESTED,      /* AR 0: 2.2.8.4.3.1 forbids an answer */
    APS_ACK_NOT_UNICAST,        /* an ask on a group or broadcast delivery (2.2.5.1.1.5) */
    APS_ACK_NOT_ACCEPTED,       /* a Status other than SUCCESS: not a frame this device judged valid */
    APS_ACK_COMPOSE_REFUSED,    /* the codec would not write the shape */
    APS_ACK_ISSUE_REFUSED       /* the layer below would not take the answer */
} Aps_AckOutcome;

/*
 * The transaction an incoming acknowledgement answers: the four parts 2.2.8.4.4 prints, in the order it
 * prints them, plus band A's guard that the frame came from the device the transaction was aimed at.
 * Only a slot waiting for an acknowledgement is searched, in pool order; 0 is the unmatched frame.
 */
Aps_Tx *Aps_AckSlotForAck(Aps_Tx *txPool, const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame);

/*
 * The acknowledgement this device owes a frame it accepted, from "this frame wants an answer" to "the answer
 * is on its way out": the ask read off the parsed frame and the Status the façade decided for it, the
 * composition of Figure 2-9 with 2.2.5.2.3.1's field rules, and one NLDE-DATA.request at the indication's
 * NWK source. No slot is taken and no wait opened for the answer.
 */
Aps_AckOutcome Aps_AckRespond(const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame, uint32_t deliveryStatus,
                              Nwk_Nwk *nwk, uint8_t *scratch, uint32_t scratchMax, uint32_t nowMs);

/*
 * 2.2.8.4.5.4's acknowledgement for a fragmented frame: the extended APS header carrying the lowest block number of
 * the current receive window and that window's bitfield, which the caller reads off `aps_frag`. The APS counter is
 * the frame's, as the clause prints, and the answer goes down the same one NLDE-DATA.request.
 */
Aps_AckOutcome Aps_AckRespondFragment(const Nwk_DataIndicationParameters *ind, const Aps_Frame *frame,
                                      uint8_t windowBlockNumber, uint8_t windowBitfield,
                                      Nwk_Nwk *nwk, uint8_t *scratch, uint32_t scratchMax, uint32_t nowMs);

#endif /* APS_ACK_H */
