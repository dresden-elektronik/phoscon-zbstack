#ifndef APS_RX_H
#define APS_RX_H

/*
 * The secured-receive stage of band A's APS data service: 4.4.1.2 run on a frame the caller's
 * parse stopped at, with the adopted `Security` and the caller's plaintext scratch arriving as parameters,
 * the partner hint this layer owes the crossing resolved inside the stage, and everything the crossing
 * decided written into the caller's `Aps_Delivery`. No counter moves here and no gate around the stage is
 * decided here: the order of the reception sequence is the façade's, and so is one counter per gate of it.
 */

#include <stdint.h>

#include "aps_frame.h"
#include "nwk.h"
#include "security.h"
#include "zb_status.h"

/*
 * 4.4.1.2 on one secured frame, answered in the module's vocabulary and counted by the call site in the order
 * the gates are met: ZB_ERR_UNSUPPORTED is the deferral family and writes nothing into `delivery`;
 * ZB_ERR_BAD_ARGUMENT is the codec's family; every other refusal is the failure this stage reports
 * indicating; ZB_OK is an authenticated frame, its ASDU the plaintext this stage wrote into the scratch.
 */
ZbStatus Aps_RxSecureReceive(Security *security, const Nwk_Nwk *nwk, const Nwk_DataIndicationParameters *ind,
                             const Aps_Frame *frame, uint32_t headerLen, uint32_t apsduLen, Aps_Delivery *delivery,
                             uint8_t *plainScratch, uint32_t scratchMax);

#endif /* APS_RX_H */
