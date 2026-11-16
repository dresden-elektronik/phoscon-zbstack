#ifndef NWK_PERMIT_H
#define NWK_PERMIT_H

/* 3.2.2.7's NLME-PERMIT-JOINING and 3.2.2.8's confirm: the association permit stated for a fixed period, the
   period counted out by `Nwk_Step`, and the answer a device that cannot state one gets.
   docs/internals/conformance.md §2 owns the clause marks. */

#include <stdint.h>

#include "nwk.h"

/* Table 3-15's two named PermitDuration values. */
enum
{
    NWK_PERMIT_OFF = 0x00,
    NWK_PERMIT_UNLIMITED = 0xff,
    NWK_PERMIT_SECONDS_MAX = 0xfe
};

/* Table 3-16's Status, narrowed to the three this stack can answer. */
enum
{
    NWK_PERMIT_SUCCESS = 0,
    NWK_PERMIT_INV_REQUESTTYPE = 1
};

/* The door, `permitDuration` in seconds, and whether the permit stands now. */
uint32_t Nwk_PermitJoining(Nwk_Nwk *self, uint32_t permitDuration, uint32_t nowMs);
int Nwk_PermitJoiningActive(const Nwk_Nwk *self);

/* The countdown's leg, run from the module's turn. */
void Nwk_PermitExpire(Nwk_Nwk *self, uint32_t nowMs);

uint32_t Nwk_PermitJoiningRequests(const Nwk_Nwk *self);
uint32_t Nwk_PermitJoiningExpiries(const Nwk_Nwk *self);

#endif
