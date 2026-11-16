#include "nwk.h"

#include "nwk_status.h"

#include "nwk_addr.h"
#include "nwk_command.h"
#include "zb_bstream.h"

/* R23.1: 3.4.3.3, 3.4.3.3.1, 3.4.3.3.2, 3.6.4.8.1, 3.6.13 ok (the payload's code and its conditional destination, the
   three removal predicates, the 0x0b removal it owes, and the 0x0c a broken many-to-one route is reported with). */

/* Whether a status code's frame carries a destination address: Table 3-56's routing failures and the address
   conflict do, and an unknown-command answer does not. */
/* The codes Table 3-56 prints, which are the ones a receiver acts on: a reserved or a deprecated code is ignored */
static int nwkStatusIsPrintedCode(uint32_t statusCode)
{
    if (statusCode <= NWK_STATUS_CODE_LINK_FAILURE)
        return 1;

    if (statusCode == NWK_STATUS_CODE_PARENT_LINK_FAILURE)
        return 1;

    if (statusCode >= NWK_STATUS_CODE_SOURCE_ROUTE_FAILURE && statusCode <= NWK_STATUS_CODE_ADDRESS_CONFLICT)
        return 1;

    return statusCode == NWK_STATUS_CODE_PAN_ID_UPDATE || statusCode == NWK_STATUS_CODE_NETWORK_ADDRESS_UPDATE
           || statusCode == NWK_STATUS_CODE_UNKNOWN_COMMAND;
}

static int nwkStatusCodeCarriesTarget(uint32_t statusCode)
{
    if (statusCode == NWK_STATUS_CODE_LEGACY_NO_ROUTE || statusCode == NWK_STATUS_CODE_LEGACY_LINK_FAILURE)
        return 1;

    if (statusCode == NWK_NETWORK_STATUS_LINK_FAILURE || statusCode == NWK_STATUS_CODE_SOURCE_ROUTE_FAILURE)
        return 1;

    return statusCode == NWK_STATUS_CODE_MANY_TO_ONE_FAILURE || statusCode == NWK_STATUS_CODE_ADDRESS_CONFLICT;
}

/* Figure 3-13 with 3.4.3.3.1 and 3.4.3.3.2: Table 3-56's status code, then the two-octet destination address where
   that clause prints one. A code the table does not print is ignored as 7130 asks, and a frame that should carry a
   target and does not is no frame this module reads. */
Nwk_NetworkStatusPayload Nwk_StatusRead(const uint8_t *payload, uint32_t payloadLen)
{
    Nwk_NetworkStatusPayload status;
    U_BStream stream;

    status.valid = 0;
    status.statusCode = 0;
    status.targetAddress = 0;

    if (payloadLen < 2)
        return status;

    Zb_bstream_init_const(&stream, payload, payloadLen);
    U_bstream_advance(&stream, 1);
    status.statusCode = U_bstream_get_u8(&stream);
    status.valid = nwkStatusIsPrintedCode(status.statusCode);

    if (!nwkStatusCodeCarriesTarget(status.statusCode))
        return status;

    if (payloadLen < NWK_STATUS_PAYLOAD_MIN)
    {
        status.valid = 0;
        return status;
    }

    status.targetAddress = U_bstream_get_u16_le(&stream);

    return status;
}

/* 3.6.4.8.1's removal for the intended destination, and for 0x01 and 0x02 alone: 0x00 is the payload code the
   parent paragraph adds, not this one, and a 0x13 answer names no routing failure at all. */
int Nwk_StatusRemovesAtDestination(const Nwk_NetworkStatusPayload *status, uint32_t deviceType)
{
    if (!status->valid)
        return 0;

    if (!Nwk_AddrHasRoutingDuty(deviceType))
        return 0;

    if (status->statusCode != NWK_STATUS_CODE_LEGACY_LINK_FAILURE && status->statusCode != NWK_NETWORK_STATUS_LINK_FAILURE)
        return 0;

    return 1;
}

/* The parent's removal, whose codes are 0x00, 0x01 and 0x02 (Table 3-56's legacy pair beside the current code)
   and whose subject is a neighbour held as this device's own end-device child (Table 3-75's 0x01). */
int Nwk_StatusRemovesAtParent(const Nwk_NetworkStatusPayload *status, const Nwk_NeighborTableEntry *addressed)
{
    if (!status->valid || addressed == 0)
        return 0;

    if (addressed->deviceType != NWK_DEVICE_END_DEVICE || addressed->relationship != NWK_REL_CHILD)
        return 0;

    if (status->statusCode == NWK_NETWORK_STATUS_LINK_FAILURE)
        return 1;

    if (status->statusCode == NWK_STATUS_CODE_LEGACY_NO_ROUTE || status->statusCode == NWK_STATUS_CODE_LEGACY_LINK_FAILURE)
        return 1;

    return 0;
}

/* The 0x0b half: the façade removes the source route the payload names from its own table */
int Nwk_StatusOwesSourceRouteRemoval(const Nwk_NetworkStatusPayload *status)
{
    if (!status->valid)
        return 0;

    return status->statusCode == NWK_STATUS_CODE_SOURCE_ROUTE_FAILURE ? 1 : 0;
}
