#ifndef NWK_POLL_H
#define NWK_POLL_H

/*
 * A resting end device's polls of its parent and NLME-SYNC; docs/internals/conformance.md §2 owns their contract.
 */

#include <stdint.h>

#include "nwk.h"

/* One pass, after `Nwk_JoinStep`: the MLME-POLL.confirm taken and reported to the parent link, then the next poll
   when NLME-SYNC asked for one, a frame said more is held, or the interval passed with the receiver resting. */
void Nwk_PollStep(Nwk_Nwk *self, uint32_t nowMs);

#endif /* NWK_POLL_H */
