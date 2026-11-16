#include "nwk_tlv.h"

#include "nwk_command.h"
#include "zb_utils.h"

/* R23.1: 3.3 ok (Figure 3-13's TLV set: the extended route information, the routing sequence number, the unknown
   tag skipped); the beacon appendix is nwk_beacon.c's, and 3.4.14's joiner TLVs are nwk_commissioning.c's. */

/* I.2.5 and I.2.1 drop the whole message: no record of it is reported, the ones before the offender included */
static Nwk_TlvOutcome nwkTlvDrop(Nwk_TlvSet *set, Nwk_TlvOutcome outcome)
{
    Zb_memset(set, 0, (uint32_t)sizeof *set);

    return outcome;
}

/* I.2.7 step 2: one bit per id the message has carried so far, the Manufacturer Specific id recorded nowhere */
static int nwkTlvSeenAlready(uint64_t *seen, uint8_t tag)
{
    uint32_t word;
    uint64_t bit;

    if (tag == NWK_TLV_TAG_MANUFACTURER_SPECIFIC)
        return 0;                   

    word = (uint32_t)tag / NWK_TLV_SEEN_BITS;
    bit = (uint64_t)1 << ((uint32_t)tag % NWK_TLV_SEEN_BITS);

    if (seen[word] & bit)
        return 1;

    seen[word] = seen[word] | bit;

    return 0;
}

/* The local ids one command defines and the shortest value its figure prints: K.2.1's three for a request
   (Figures K-1 to K-3), tag 0 alone for the reply and the network status (K.3.1.1, K.4.1.1). An id the command
   does not define is I.2.3's Unknown Tag: ignored, whatever length it carries. */
static Nwk_TlvOutcome nwkTlvDoLocal(Nwk_TlvSet *set, uint32_t command, uint8_t tag, uint32_t valueLen,
                                    U_BStream *stream)
{
    if (tag == NWK_TLV_TAG_EXTENDED_ROUTE)
    {
        if (valueLen < NWK_TLV_ROUTING_SEQUENCE_OCTETS)
            return NWK_TLV_MALFORMED;   

        set->extendedRouteInfo = 1;
        set->routingSequenceNumber = U_bstream_get_u16_le(stream);

        if (valueLen >= NWK_TLV_EXTENDED_ROUTE_OCTETS)
        {
            set->initialRadius = U_bstream_get_u8(stream);
            set->initialRadiusPresent = 1;
        }

        return NWK_TLV_OK;
    }

    if (command != NWK_CMD_ROUTE_REQUEST)
        return NWK_TLV_OK;              

    if (tag == NWK_TLV_TAG_CONCENTRATOR)
    {
        if (valueLen < NWK_TLV_CONCENTRATOR_OCTETS)
            return NWK_TLV_MALFORMED;   

        set->concentratorInfo = 1;

        return NWK_TLV_OK;
    }

    if (tag == NWK_TLV_TAG_SOURCE_ROUTE_SOLICITATION)
    {
        if (valueLen < NWK_TLV_SOLICITATION_OCTETS)
            return NWK_TLV_MALFORMED;

        if ((valueLen % NWK_TLV_SOLICITATION_OCTETS) != 0)
            return NWK_TLV_MALFORMED;   

        set->sourceRouteSolicitation = 1;

        return NWK_TLV_OK;
    }

    return NWK_TLV_OK;                  
}

/* I.2.1's order-independence is the walk: each record is read where it stands and none is looked up by position */
Nwk_TlvOutcome Nwk_TlvRead(uint32_t command, const uint8_t *tlvs, uint32_t tlvsLen, Nwk_TlvSet *set)
{
    U_BStream stream;
    U_BStream value;
    uint64_t seen[NWK_TLV_SEEN_WORDS];
    uint32_t valueLen;
    uint8_t tag;
    uint8_t lengthField;
    Nwk_TlvOutcome outcome;

    Zb_memset(set, 0, (uint32_t)sizeof *set);
    Zb_memset(seen, 0, (uint32_t)sizeof seen);

    if (tlvsLen == 0)
        return NWK_TLV_ABSENT;

    Zb_bstream_init_const(&stream, tlvs, tlvsLen);

    while (Zb_bstream_remaining(&stream) > 0)
    {
        if (Zb_bstream_remaining(&stream) < NWK_TLV_HEADER_OCTETS)
            return nwkTlvDrop(set, NWK_TLV_MALFORMED);   

        tag = U_bstream_get_u8(&stream);
        lengthField = U_bstream_get_u8(&stream);
        valueLen = (uint32_t)lengthField + NWK_TLV_LENGTH_BIAS;

        if (valueLen > Zb_bstream_remaining(&stream))
            return nwkTlvDrop(set, NWK_TLV_MALFORMED);   

        Zb_bstream_sub(&stream, &value, valueLen);

        if (nwkTlvSeenAlready(seen, tag))
            return nwkTlvDrop(set, NWK_TLV_DUPLICATE);

        if (tag <= NWK_TLV_LOCAL_MAX)
        {
            outcome = nwkTlvDoLocal(set, command, tag, valueLen, &value);

            if (outcome != NWK_TLV_OK)
                return nwkTlvDrop(set, outcome);
        }
    }

    return NWK_TLV_OK;
}

/* Table I-1's tag and length, then Figure K-1's three octets: the length field is the value less one */
void Nwk_TlvPutExtendedRouteInformation(U_BStream *stream, uint16_t routingSequenceNumber, uint8_t initialRadius)
{
    U_bstream_put_u8(stream, NWK_TLV_TAG_EXTENDED_ROUTE);
    U_bstream_put_u8(stream, (unsigned char)(NWK_TLV_EXTENDED_ROUTE_OCTETS - NWK_TLV_LENGTH_BIAS));
    U_bstream_put_u16_le(stream, routingSequenceNumber);
    U_bstream_put_u8(stream, initialRadius);
}

/* Table I-1's tag and length, then Figure K-4's two octets and no radius (K.3.1.1.1) */
void Nwk_TlvPutRoutingSequenceNumber(U_BStream *stream, uint16_t routingSequenceNumber)
{
    U_bstream_put_u8(stream, NWK_TLV_TAG_EXTENDED_ROUTE);
    U_bstream_put_u8(stream, (unsigned char)(NWK_TLV_ROUTING_SEQUENCE_OCTETS - NWK_TLV_LENGTH_BIAS));
    U_bstream_put_u16_le(stream, routingSequenceNumber);
}
