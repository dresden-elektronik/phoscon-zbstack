#include "nwk.h"

#include "nwk_command.h"

#include "nwk_frame.h"
#include "nwk_neighbor.h"
#include "nwk_tlv.h"
#include "zb_bstream.h"
#include "zb_utils.h"

/* R23.1: 3.3.2.2.2, 3.4.3.2, 3.4.3.3.1, 3.4.3.3.2, 3.6.1.10.5, 3.6.13, 4.2.2 ok (the 0x13 answer carries the source
   IEEE address the clause makes mandatory); 3.6.2.2 elsewhere (nwk.c's unsecured gate); 3.6.4.5.1, 3.6.4.5.2, 3.6.4.8.1
   elsewhere (nwk_rreq*.c, nwk_rrep*.c, nwk.c). */

/* Table 3-54's identifiers and only those (0x01-0x0f named, 0x10-0xff Reserved beneath them), so a range check is the table's shape (3.3.2.2.2); recognition is not support (3.6.13) */
int Nwk_CommandIsKnown(uint32_t id)
{
    if (id < NWK_CMD_ROUTE_REQUEST)
        return 0;

    if (id > NWK_CMD_NETWORK_COMMISSIONING_RESPONSE)
        return 0;

    return 1;
}

/* 3.6.13 answers "an unknown or unsupported unicast NWK command", and the second word is the wide one: only
   the three identifiers this layer acts on are supported, Table 3-54's other twelve being machinery this stack
   has deferred. */
int Nwk_CommandIsProcessed(uint32_t id)
{
    if (id == NWK_CMD_ROUTE_REQUEST || id == NWK_CMD_ROUTE_REPLY)
        return 1;

    return id == NWK_CMD_NETWORK_STATUS ? 1 : 0;
}

/* 3.6.13's answer in the order its steps print: Network Status, Table 3-56's 0x13, 3.6.13 step 3's destination and Figure 3-61's one payload octet carrying the received identifier */
ZbStatus Nwk_CommandComposeReply(Nwk_Frame *replyOut, const Nwk_Frame *offender, uint32_t commandId,
                                 uint16_t ownAddr, uint64_t ownIeee,
                                 const Nwk_NeighborTableEntry *offenderEntry, int securityEnabled,
                                 uint32_t *seq, uint8_t *npdu, uint32_t npduMax, uint32_t *npduLen)
{
    U_BStream stream;
    uint8_t payload[NWK_COMMAND_REPLY_PAYLOAD_MAX];

    U_bstream_init(&stream, payload, (unsigned long)sizeof payload);

    U_bstream_put_u8(&stream, NWK_CMD_NETWORK_STATUS);
    U_bstream_put_u8(&stream, NWK_NETWORK_STATUS_UNKNOWN_COMMAND);
    U_bstream_put_u8(&stream, (uint8_t)(commandId & 0xff));

    if (!Zb_bstream_ok(&stream) || Zb_bstream_pos(&stream) != (uint32_t)sizeof payload)
        return ZB_ERR_NO_SPACE;

    Zb_memset(replyOut, 0, (uint32_t)sizeof *replyOut);

    replyOut->frameType = NWK_FRAME_TYPE_COMMAND;
    replyOut->protocolVersion = NWK_PROTOCOL_VERSION;
    replyOut->discoverRoute = NWK_DISCOVER_SUPPRESS;
    replyOut->destAddr = offender->srcAddr;      
    replyOut->srcAddr = ownAddr;
    replyOut->radius = NWK_INITIAL_RADIUS;
    replyOut->sequenceNumber = (uint8_t)(*seq % NWK_SEQ_WRAP);
    replyOut->securityEnabled = securityEnabled ? 1 : 0;

    *seq = (*seq + 1) % NWK_SEQ_WRAP;

    replyOut->srcIeeePresent = 1;
    replyOut->srcIeee = ownIeee;

    if (offenderEntry != 0 && offenderEntry->ieeeKnown)
    {
        replyOut->destIeeePresent = 1;
        replyOut->destIeee = offenderEntry->extendedAddress;
    }

    return NwkFrame_Compose(replyOut, payload, (uint32_t)sizeof payload, npdu, npduMax, npduLen);
}

/* 3.6.4.8.1's frame in its clauses' order: 3.4.3.2's header, 3.4.3.3.2's two octets naming the destination *of the frame that failed*, and K.4.1.1's sequence number while the entry's flag carries one */
ZbStatus Nwk_CommandComposeStatus(Nwk_Frame *replyOut, uint16_t ownAddr, uint64_t ownIeee,
                                  uint16_t destination, const Nwk_NeighborTableEntry *destinationEntry, uint16_t status,
                                  uint16_t failedDestination, int sequenceNumberValid,
                                  uint16_t routingSequenceNumber, int securityEnabled, uint32_t *seq,
                                  uint8_t *npdu, uint32_t npduMax, uint32_t *npduLen)
{
    U_BStream stream;
    uint8_t payload[NWK_COMMAND_STATUS_PAYLOAD_MAX];

    U_bstream_init(&stream, payload, (unsigned long)sizeof payload);

    U_bstream_put_u8(&stream, NWK_CMD_NETWORK_STATUS);
    U_bstream_put_u8(&stream, (uint8_t)(status & 0xff));
    U_bstream_put_u16_le(&stream, failedDestination);

    if (sequenceNumberValid)
        Nwk_TlvPutRoutingSequenceNumber(&stream, routingSequenceNumber);

    if (!Zb_bstream_ok(&stream))
        return ZB_ERR_NO_SPACE;

    Zb_memset(replyOut, 0, (uint32_t)sizeof *replyOut);

    replyOut->frameType = NWK_FRAME_TYPE_COMMAND;
    replyOut->protocolVersion = NWK_PROTOCOL_VERSION;
    replyOut->discoverRoute = NWK_DISCOVER_SUPPRESS;
    replyOut->destAddr = destination;
    replyOut->srcAddr = ownAddr;
    replyOut->radius = NWK_INITIAL_RADIUS;
    replyOut->sequenceNumber = (uint8_t)(*seq % NWK_SEQ_WRAP);
    replyOut->securityEnabled = securityEnabled ? 1 : 0;
    replyOut->srcIeeePresent = 1;      
    replyOut->srcIeee = ownIeee;

    *seq = (*seq + 1) % NWK_SEQ_WRAP;

    if (destinationEntry != 0 && destinationEntry->ieeeKnown)
    {
        replyOut->destIeeePresent = 1;
        replyOut->destIeee = destinationEntry->extendedAddress;
    }

    return NwkFrame_Compose(replyOut, payload, Zb_bstream_pos(&stream), npdu, npduMax, npduLen);
}
