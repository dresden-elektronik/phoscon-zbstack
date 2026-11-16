#include "nwk.h"

#include "nwk_indirect.h"

#include "mac.h"
#include "nwk_addr.h"
#include "nwk_frame.h"
#include "nwk_neighbor.h"
#include "nwk_tx.h"
#include "security.h"
#include "zb_utils.h"

/* R23.1: 3.2.1.1.3, 3.6.6 ok (the sleepy copy over the MAC's own transaction queue, one per non-listening child, the
   MAC's acknowledgement asked of it); the Trusted-Link single send is a companion specification's and unbuilt. */

/* 3.2.1.1.3 items 6-7 with 3.6.6 step 1 in the clause's own order: the routing duty, a destination of 0xffff, entries of type 0x02 with the receiver off, and the broadcast's own source skipped (docs/internals/conformance.md §2) */
ZbStatus Nwk_IndirectTransactionCopies(const Nwk_NeighborTableEntry *neighbors, uint32_t deviceType, Mac_Mac *mac,
                                         Security *security, uint16_t dstAddr, uint16_t srcAddr,
                                         const uint8_t *npdu, uint32_t npduLen, uint32_t headerLen,
                                         int secured, uint8_t *scratch, uint32_t scratchMax, uint32_t nowMs)
{
    Mac_DataRequestParameters req;
    const Nwk_NeighborTableEntry *neighbor;
    const Radio_Pib *pib;
    const uint8_t *octets;
    uint16_t own;
    uint32_t octetLen;
    uint32_t securedLen;
    uint32_t i;
    ZbStatus status;

    if (dstAddr != NWK_ADDR_ALL_DEVICES)
        return ZB_OK;

    if (!Nwk_AddrHasRoutingDuty(deviceType))
        return ZB_OK;

    if (!Nwk_AddrOwn(Mac_Pib(mac), &own))
        return ZB_OK;

    pib = Mac_Pib(mac);

    for (i = 0; i < NWK_NEIGHBOR_MAX; i++)
    {
        neighbor = &neighbors[i];

        if (!neighbor->inUse)
            continue;

        if (neighbor->deviceType != NWK_DEVICE_END_DEVICE)
            continue;

        if (neighbor->rxOnWhenIdle)
            continue;

        if (neighbor->networkAddress == srcAddr)
            continue;

        if (Nwk_AddrIsReserved(neighbor->networkAddress) || Nwk_AddrIsBroadcast(neighbor->networkAddress))
            continue;

        octets = npdu;
        octetLen = npduLen;

        if (secured)
        {
            status = Nwk_TxProtect(security, npdu, npduLen, headerLen, scratch, scratchMax, &securedLen);

            if (status != ZB_OK)
                return status;

            octets = scratch;
            octetLen = securedLen;
        }

        Zb_memset(&req, 0, (uint32_t)sizeof req);

        req.frameType = MAC_FRAME_TYPE_DATA;
        req.destAddrMode = MAC_ADDR_SHORT;
        req.srcAddrMode = MAC_ADDR_SHORT;
        req.destPan = pib->panId;
        req.destShort = neighbor->networkAddress;

        req.ackRequest = 1;
        req.payload = octets;
        req.payloadLen = octetLen;

        Mac_IndirectRequest(mac, &req, nowMs);
    }

    return ZB_OK;
}
