#include "aps.h"

#include "aps_rx.h"

#include "aps_frame.h"
#include "nwk.h"
#include "security.h"

/* R23.1 2.2.5.1.1 4.4.1.2 4.4.10 ok; a command frame is read here too, its payload region being the command body,
   and 4.4.1.2's three identifiers 00, 02 and 03 are the ones security.c derives. docs/internals/conformance.md pages 86, 426, 461. */

/*
 * 4.4.1.2 on the frame `apsDoReceive` stopped at, handed the whole APDU rather than the codec's payload region
 * because the module splits that region itself (4.4.10's boundary). The partner hint is this layer's half of
 * the crossing: a pair's own device address, or for a sender only the global pair answers, the 64-bit address
 * the network layer's map holds for its source. A source neither names is refused
 * at step 3 for want of material, not papered over. An acknowledgement is unsecured here like any other frame.
 */
ZbStatus Aps_RxSecureReceive(Security *security, const Nwk_Nwk *nwk, const Nwk_DataIndicationParameters *ind,
                             const Aps_Frame *frame, uint32_t headerLen, uint32_t apsduLen, Aps_Delivery *delivery,
                             uint8_t *plainScratch, uint32_t scratchMax)
{
    const Security_KeyPairEntry *entry;
    Security_ApsResult result;
    uint64_t hint;
    uint64_t mapped;
    uint32_t plainLen;
    int hintKnown;
    int pairIndex;
    ZbStatus status;

    if (frame->frameType != APS_FRAME_TYPE_DATA && frame->frameType != APS_FRAME_TYPE_COMMAND
        && frame->frameType != APS_FRAME_TYPE_ACK)
        return ZB_ERR_UNSUPPORTED;

    if (security == 0)
    {
        return ZB_ERR_UNSUPPORTED;
    }

    hint = 0;
    hintKnown = 0;

    pairIndex = Security_FindKeyPairByShort(security, ind->srcAddr);
    entry = Security_KeyPairAt(security, pairIndex);

    if (entry != 0)
    {
        delivery->keyIndex = (uint32_t)pairIndex;
        delivery->keyStatus = entry->keyAttributes;
    }

    if (entry != 0 && entry->linkKeyType != SECURITY_LINK_KEY_GLOBAL)
    {
        hint = entry->deviceIeee;
        hintKnown = 1;
    }
    else if (nwk != 0 && Nwk_IeeeOfAddress(nwk, ind->srcAddr, &mapped))
    {
        hint = mapped;
        hintKnown = 1;
    }

    status = Security_UnprotectAps(security, ind->nsdu, apsduLen, headerLen,
                                   hint, hintKnown, plainScratch,
                                   scratchMax, &plainLen, &result);

    if (status == ZB_ERR_UNSUPPORTED)
        return ZB_ERR_UNSUPPORTED;

    if (status == ZB_ERR_BAD_ARGUMENT)
        return ZB_ERR_BAD_ARGUMENT;

    if (status != ZB_OK)
    {
        delivery->status = APS_STATUS_SECURITY_FAIL;
        delivery->asdu = 0;
        delivery->asduLength = 0;

        if (delivery->keyIndex == APS_KEY_INDEX_NONE)
            delivery->securityStatus = APS_SECURITY_NONE;
        else
            delivery->securityStatus = APS_SECURITY_LINK_KEY;

        return status;
    }

    entry = Security_KeyPairAt(security, result.keyPairIndex);

    delivery->asdu = plainScratch;
    delivery->asduLength = plainLen;
    delivery->status = APS_STATUS_SUCCESS;
    delivery->securityStatus = APS_SECURITY_LINK_KEY;
    delivery->keyIndex = (uint32_t)result.keyPairIndex;
    delivery->frameCounter = result.frameCounter;
    delivery->srcIeee = result.partnerIeee;
    delivery->keyStatus = entry != 0 ? entry->keyAttributes : APS_KEY_STATUS_NONE;

    return ZB_OK;
}
