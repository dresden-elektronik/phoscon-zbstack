#ifndef NWK_LEAVE_H
#define NWK_LEAVE_H

/* 3.4.4's leave command and 3.6.1.11's four procedures: a device leaving, a parent removing a child, a device
   hearing that someone left, and what a device clears when it is gone. docs/internals/conformance.md §2 owns the clause marks. */

#include <stdint.h>

#include "nwk.h"

/* Table 3-26's request: `deviceAddress` NULL or this device's own address removes it, any other address asks a
   parent to remove that child. */
uint32_t Nwk_LeaveRequest(Nwk_Nwk *self, uint64_t deviceAddress, int removeChildren, int rejoin, uint32_t nowMs);

/* 3.6.10.4.1's leave request to a device that polled with no neighbour entry: request and rejoin set, no destination
   IEEE address, secured as 4.6.3.6.3 asks and held for the device's next poll. ZB_OK when queued. */
ZbStatus Nwk_LeaveUnknownPoller(Nwk_Nwk *self, uint16_t address, uint32_t nowMs);

/* 8678-8680's to the sender of an end device's marked frame with no entry: the same request, sent at once, not held. */
ZbStatus Nwk_LeaveUnknownSender(Nwk_Nwk *self, uint16_t address, uint32_t nowMs);

/* Figure 3-14's payload, in both directions. */
ZbStatus Nwk_LeaveCommandCompose(const Nwk_LeaveCommand *command, uint8_t *out, uint32_t outCap);
ZbStatus Nwk_LeaveCommandParse(const uint8_t *payload, uint32_t length, Nwk_LeaveCommand *out);

/* 3.6.1.11.3 and its validation, run on a command the receive pipeline read; `arrivedAsBroadcast` is how the frame
   was addressed, which step 1 of the validation turns on. */
void Nwk_LeaveRx(Nwk_Nwk *self, uint16_t srcAddr, uint64_t srcIeee, const Nwk_LeaveCommand *command,
                 int arrivedAsBroadcast, uint32_t nowMs);

int Nwk_LeaveRequestAllowedFrom(Nwk_Nwk *self, uint16_t srcAddr, int arrivedAsBroadcast);

uint32_t Nwk_PollLeaveIndications(Nwk_Nwk *self, Nwk_LeaveIndication *out, uint32_t max);

/* nwkLeaveRequestAllowed, which 3.6.1.11.3.1 step 2 reads and the application sets. */
void Nwk_SetLeaveRequestAllowed(Nwk_Nwk *self, int allowed);
int Nwk_LeaveRequestAllowed(const Nwk_Nwk *self);

uint32_t Nwk_LeaveCommandsSent(const Nwk_Nwk *self);
uint32_t Nwk_LeaveCommandsHeard(const Nwk_Nwk *self);
uint32_t Nwk_LeavesTaken(const Nwk_Nwk *self);

#endif
