#ifndef NWK_JOIN_H
#define NWK_JOIN_H

/*
 * 3.6.1.6.1's two halves of joining; docs/internals/conformance.md §2 owns the façade's contract.
 */

#include <stdint.h>

#include "nwk.h"

/* One pass: the child's MLME-ASSOCIATE.confirm while it waits for one, then the parent's answer to every
   request the MAC holds. `Nwk_Step` calls this after `Mac_Step` and after its own drains, so an answer composed
   here is taken on the next turn and no frame this turn owes is held behind it. */
void Nwk_JoinStep(Nwk_Nwk *self, uint32_t nowMs);

/* One MLME-COMM-STATUS.indication: the outcome of an association answer this device is waiting on, or nothing. */
void Nwk_JoinCommStatus(Nwk_Nwk *self, const Mac_CommStatusParameters *status);

/* 3.6.9's restart: a device whose PIB a restore gave back its address is joined again, and an end device's parent
   goes back into the neighbour table, owed the keepalive 3.6.10.8 recommends and 3.6.10.3 chooses. */
void Nwk_JoinResume(Nwk_Nwk *self, uint16_t parentShort, uint64_t parentIeee);

/* 3.6.4.8.1's last rule: an end device whose frame to its parent `hop` failed tells the layer above with 0x09
   (Parent Link Failure); a frame to any other hop, or a device that is not a joined end device, raises nothing. */
void Nwk_JoinParentLinkFailed(Nwk_Nwk *self, uint16_t hop);

/* The other half: an end device's frame or keepalive its parent `hop` answered, counted so the layer above can end a
   run of failures, which it counts consecutively. */
void Nwk_JoinParentLinkHeld(Nwk_Nwk *self, uint16_t hop);

/* One more keepalive to the parent, for an end device that is joined and has none under way: the further attempt
   the layer above may make before it rejoins. */
void Nwk_JoinKeepaliveOwe(Nwk_Nwk *self);

/* The MAC's answer to a keepalive poll: 1 when `confirm` was the poll's, a NO_ACK being a failed link to the parent
   (3.6.4.8.1); 0 for any other transmit's. */
int Nwk_JoinKeepaliveAnswered(Nwk_Nwk *self, const Mac_DataConfirmParameters *confirm);

/* 3.6.1.10.5: the parent picks a new address for one of its own end-device children and tells it with an unsolicited
   rejoin response, network-encrypted as 3.6.1.10.6 requires. The new address, or 0 when the pool refused one. */
uint16_t Nwk_JoinReaddressChild(Nwk_Nwk *self, Nwk_NeighborTableEntry *child, uint32_t nowMs);

/* 3.4.6 and 3.4.7, the NWK rejoin's command pair as 3.6.1.6.1.2 and 3.6.1.6.1.3 run it: 1 when the frame was a
   rejoin command this device consumed, and 0 when it was not one it handles, which leaves the frame to 3.6.13. */
int Nwk_JoinHandleCommand(Nwk_Nwk *self, const Nwk_Frame *frame, const uint8_t *payload, uint32_t payloadLen,
                          uint32_t nowMs);

#endif /* NWK_JOIN_H */
