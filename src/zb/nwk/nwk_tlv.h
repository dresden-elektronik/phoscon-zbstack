#ifndef NWK_TLV_H
#define NWK_TLV_H

/*
 * Annex I's tag-length-value walk; docs/internals/conformance.md §2 owns its contract.
 */

#include <stdint.h>

#include "zb_bstream.h"

enum
{
    NWK_TLV_TAG_OCTETS = 1,         /* Table I-1's Tag field */
    NWK_TLV_LENGTH_OCTETS = 1,      /* Table I-1's Length field */
    NWK_TLV_HEADER_OCTETS = 2,      /* both, ahead of every value */
    NWK_TLV_LENGTH_BIAS = 1,        /* Table I-1: the value is the Length field + 1 octets */

    NWK_TLV_LOCAL_MAX = 63,         /* Table I-2: 0-63 local, 64-255 global */

    /* I.2.1's duplicate rule covers every id a message carries, so the walk remembers all 256 that Table I-2
       prints, one bit each; the Manufacturer Specific Global TLV is the one id it MAY carry twice (I.4.1). */
    NWK_TLV_ID_COUNT = 256,
    NWK_TLV_SEEN_WORDS = NWK_TLV_ID_COUNT / 64,
    NWK_TLV_SEEN_BITS = 64,
    NWK_TLV_TAG_MANUFACTURER_SPECIFIC = 64,

    NWK_TLV_TAG_EXTENDED_ROUTE = 0, /* the Extended Route Information tag, K.2.1.1's and K.3.1.1's */
    NWK_TLV_TAG_CONCENTRATOR = 1,   /* K.2.1.2's Concentrator Information tag */
    NWK_TLV_TAG_SOURCE_ROUTE_SOLICITATION = 2, /* K.2.1.3's Source Route Solicitation tag */

    NWK_TLV_EXTENDED_ROUTE_OCTETS = 3, /* Figure K-1: Routing Sequence Number 2, Initial Radius 1 */
    NWK_TLV_ROUTING_SEQUENCE_OCTETS = 2, /* Figures K-4 and K-5: the Routing Sequence Number alone */
    NWK_TLV_CONCENTRATOR_OCTETS = 2,   /* Figure K-2: Concentrator Discovery Time 1, Max Source Route Length 1 */
    NWK_TLV_SOLICITATION_OCTETS = 2    /* Figure K-3: one nwkAddressOfInterest is the shortest list it prints */
};

/* What the walk answered: `NWK_TLV_MALFORMED` and `NWK_TLV_DUPLICATE` both drop the whole message (I.2.5, I.2.1). */
typedef enum Nwk_TlvOutcome
{
    NWK_TLV_ABSENT = 0,             /* the tail was empty: K.2.1.1's earlier revisions, tolerated on receipt */
    NWK_TLV_OK = 1,                 /* every record was read, an unknown one skipped (I.2.3) */
    NWK_TLV_MALFORMED = 2,          /* shorter than its minimum, or truncated at its length field (I.2.5) */
    NWK_TLV_DUPLICATE = 3           /* one local tag id twice in a message (I.2.1) */
} Nwk_TlvOutcome;

/* The records of one message: the Extended Route Information as far as the two octets every figure prints, and the
   request's two by presence alone (K.2.1.2, K.2.1.3). */
typedef struct Nwk_TlvSet
{
    int extendedRouteInfo;          /* 1 when tag 0 was read; its absence is not a refusal (K.2.1.1) */
    int initialRadiusPresent;       /* 1 when the record carried Figure K-1's third octet as well (I.2.4) */
    uint16_t routingSequenceNumber; /* Figures K-1, K-4 and K-5's two octets, low octet first (3.3) */
    uint8_t initialRadius;          /* Figure K-1's third octet: the header radius of the original request */
    int concentratorInfo;           /* 1 when the request's tag 1 was present (K.2.1.2) */
    int sourceRouteSolicitation;    /* 1 when the request's tag 2 was present (K.2.1.3) */
} Nwk_TlvSet;

/* Walk a payload tail (I.2) over the ids its command defines (I.1.2), remembering every id for I.2.1's duplicate test. */
Nwk_TlvOutcome Nwk_TlvRead(uint32_t command, const uint8_t *tlvs, uint32_t tlvsLen, Nwk_TlvSet *set);

/*
 * Write Figure K-1's three-octet value at the stream's position: the request's record (K.2.1.1.1, K.2.1.1.2).
 */
void Nwk_TlvPutExtendedRouteInformation(U_BStream *stream, uint16_t routingSequenceNumber, uint8_t initialRadius);

/*
 * Write Figure K-4's two-octet value at the stream's position: the reply's record (K.3.1.1.1).
 */
void Nwk_TlvPutRoutingSequenceNumber(U_BStream *stream, uint16_t routingSequenceNumber);

#endif /* NWK_TLV_H */
