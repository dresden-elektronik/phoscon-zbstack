#ifndef SPINEL_H
#define SPINEL_H

/*
 * Band B: the Spinel frame codec (docs/internals/protocol.md §3, §4, §8). The header octet, packed
 * uints, and the typed values a property argument carries. Which property means what is the
 * property table's business; how a frame is framed on a wire is hdlc.h's. This module knows
 * neither: it turns a payload buffer into argument octets and back.
 *
 * Both directions run over vendor/u_bstream, the one bounded byte stream in this tree
 * (docs/internals/coding-rules.md §1). A field read past the end, or
 * an argument that cannot be a value, puts the stream into a stated failure status and yields
 * zero; a frame is judged by one Spinel_StreamFailed check after its fields have been read,
 * not by a check per field. The caller owns the buffer in both directions.
 */

#include <stdint.h>
#include "zb_bstream.h"

enum
{
    SPINEL_HEADER_FLAGS_SHIFT = 6,
    SPINEL_HEADER_FLAGS_MASK = 0xc0,
    SPINEL_HEADER_FLAG = 0x80,        /* bits 7:6 are 0b10 on every frame measured here */
    SPINEL_HEADER_IID_MASK = 0x30,
    SPINEL_HEADER_IID_SHIFT = 4,
    SPINEL_HEADER_IID_MAX = 3,
    SPINEL_HEADER_TID_MASK = 0x0f,
    SPINEL_TID_NONE = 0,              /* unsolicited: a notification carries no transaction */
    SPINEL_TID_MIN = 1,
    SPINEL_TID_MAX = 15,
    SPINEL_HEADER_BYTES = 1,
    SPINEL_PACKED_UINT_MAX_BYTES = 5, /* 7 bits x 5 groups covers a 32-bit value */
    SPINEL_LEN_PREFIX_BYTES = 2,
    SPINEL_LEN_MAX = 65535,
    SPINEL_BOOL_BYTES = 1,
    SPINEL_BOOL_FALSE = 0,
    SPINEL_BOOL_TRUE = 1,
    SPINEL_STRING_TERM_BYTES = 1,
    SPINEL_STRING_TERM = 0
};

/* The MD_FLAG bits of a framed radio value (docs/internals/protocol.md §8.1). Named here because this is
   the layer that reads the field; what they mean for a MAC is band A's decision. */
enum
{
    /* Measured on the AT86RF233 build, asserted by the codec suite: every MD_PHY timestamp in a
       transcript shares one residue modulo this quantum. It is a property of that silicon's
       clock, not of the protocol, and nothing in this stack may depend on it. */
    SPINEL_STAMP_QUANTUM = 1000,
    SPINEL_MD_TX = 0x0001,
    SPINEL_MD_BAD_FCS = 0x0004,
    SPINEL_MD_DUPE = 0x0008,

    /* Upstream's SPINEL_MD_FLAG_ACKED_FP: the acknowledgment this radio sent for the frame carried the Frame
       Pending bit. Measured on the AT86RF233 build, which composes the Ack itself and has no other way to tell a
       host what it said (docs/internals/protocol.md §8.1). */
    SPINEL_MD_ACKED_FP = 0x0010
};

/* CONFIG-class commands (docs/internals/protocol.md §3). A reply carries the TID of the command it
   answers, so these names say what a frame *is*, not who sent it: direction is not encoded. */
enum
{
    SPINEL_CMD_NOOP = 0,
    SPINEL_CMD_RESET = 1,
    SPINEL_CMD_PROP_VALUE_GET = 2,
    SPINEL_CMD_PROP_VALUE_SET = 3,

    /* What a host writes to `MAC_SCAN_STATE` to start a dwell, and what the property reads back once the dwell
     * is over: 2 put one on the air here and 0 is what the RCP reported afterwards (docs/internals/protocol.md §7.4.1). The upstream enum names two other states, a beacon scan and a discover, which
     * this stack does not run. */
    SPINEL_SCAN_STATE_IDLE = 0,
    SPINEL_SCAN_STATE_ENERGY = 2,
    SPINEL_CMD_PROP_VALUE_INSERT = 4,
    SPINEL_CMD_PROP_VALUE_REMOVE = 5,
    SPINEL_CMD_PROP_VALUE_IS = 6,
    SPINEL_CMD_PROP_VALUE_INSERTED = 7,
    SPINEL_CMD_PROP_VALUE_REMOVED = 8
};

typedef struct SpinelHeader
{
    uint8_t flags;
    uint8_t iid;
    uint8_t tid;
} Spinel_Header;

/*
 * The header octet of a frame on this family: bits 7:6 are 0b10, IID zero, transaction id in the
 * low nibble (docs/internals/protocol.md §3). A tid outside SPINEL_TID_MIN..SPINEL_TID_MAX is a caller
 * error; masking it is how that error becomes a frame the RCP answers with a TID the session
 * matcher then refuses. Spinel_TidValid is what a driver checks before formatting.
 *
 * The IID field is written as zero because that is all a measured host has ever put on the wire, and
 * Spinel_ReadHeader reports the bits it found: a peer that uses a non-zero IID is legible here
 * rather than silently folded into IID 0.
 */
int Spinel_HeaderValid(uint8_t octet);
uint8_t Spinel_HeaderByte(uint8_t tid);
int Spinel_TidValid(uint8_t tid);
void Spinel_WriteHeader(U_BStream *stream, uint8_t tid);
void Spinel_ReadHeader(uint8_t octet, Spinel_Header *out);
int Spinel_IsNotification(const Spinel_Header *header);
int Spinel_IidValid(const Spinel_Header *header);

/*
 * Packed uint: 7-bit groups, least significant group first, bit 7 means another group follows
 * (docs/internals/protocol.md §4), which is the vendored unsigned 32-bit varint. The type is 32 bits,
 * so a fifth group carrying bits above 31 is a parse failure and not a value: the reference
 * truncates it silently, which is a defect this stack does not inherit. A redundant continuation
 * byte is accepted: the value it decodes to is unambiguous, and a decoder that rejects it would
 * reject frames the RCPs accept. A value that does not fit is not written at all.
 *
 * Spinel_PackedUintBytes is the sizing half: a caller that must not emit a partial frame
 * computes the length first and checks the buffer once.
 */
uint32_t Spinel_PackedUintBytes(uint32_t value);
void Spinel_WritePackedUint(U_BStream *stream, uint32_t value);
uint32_t Spinel_ReadPackedUint(U_BStream *stream);

/* Fixed-width typed values, all little-endian (docs/internals/protocol.md §4: C c S s L l X x). */
void Spinel_WriteUint8(U_BStream *stream, uint8_t value);
uint8_t Spinel_ReadUint8(U_BStream *stream);
void Spinel_WriteInt8(U_BStream *stream, int8_t value);
int8_t Spinel_ReadInt8(U_BStream *stream);
void Spinel_WriteUint16(U_BStream *stream, uint16_t value);
uint16_t Spinel_ReadUint16(U_BStream *stream);
void Spinel_WriteInt16(U_BStream *stream, int16_t value);
int16_t Spinel_ReadInt16(U_BStream *stream);
void Spinel_WriteUint32(U_BStream *stream, uint32_t value);
uint32_t Spinel_ReadUint32(U_BStream *stream);
void Spinel_WriteInt32(U_BStream *stream, int32_t value);
int32_t Spinel_ReadInt32(U_BStream *stream);
void Spinel_WriteUint64(U_BStream *stream, uint64_t value);
uint64_t Spinel_ReadUint64(U_BStream *stream);

/*
 * The same widths the other way round, on the vendored big-endian writers and readers
 * (docs/internals/coding-rules.md §1). docs/internals/hardware.md §5 records a property that is big-endian on the wire.
 * An EUI-64 is eight octets in address order, which is why the address pair takes a byte array
 * instead of a 64-bit integer: this stack never holds an address as a number.
 */
void Spinel_WriteUint16Be(U_BStream *stream, uint16_t value);
uint16_t Spinel_ReadUint16Be(U_BStream *stream);
void Spinel_WriteUint32Be(U_BStream *stream, uint32_t value);
uint32_t Spinel_ReadUint32Be(U_BStream *stream);
void Spinel_WriteUint64Be(U_BStream *stream, uint64_t value);
uint64_t Spinel_ReadUint64Be(U_BStream *stream);
void Spinel_WriteAddrBe(U_BStream *stream, const uint8_t *addr, uint32_t len);
const uint8_t *Spinel_ReadAddrBe(U_BStream *stream, uint8_t *out, uint32_t len);

/* A Spinel bool is one octet (docs/internals/protocol.md §8.2). Any non-zero octet reads as true, which
   is the only coercion this codec is allowed. */
void Spinel_WriteBool(U_BStream *stream, int value);
int Spinel_ReadBool(U_BStream *stream);

/*
 * Data and struct fields are the same shape here: u16 LE length, then that many octets
 * (docs/internals/protocol.md §8.1). The length prefix is what makes a field this stack does not
   understand skippable instead of fatal.
 *
 * Spinel_ReadPrefixed returns a span inside the stream's own buffer, valid until that stream
   is written to again: a decoder hands the next layer a view, it does not copy. 0 with
   *outLen == 0 when the declared length runs past the end of the frame. Spinel_WritePrefixed
 * either writes the whole field or nothing at all.
 */
uint32_t Spinel_PrefixedBytes(uint32_t len);
void Spinel_WritePrefixed(U_BStream *stream, const uint8_t *bytes, uint32_t len);
const uint8_t *Spinel_ReadPrefixed(U_BStream *stream, uint32_t *outLen);

/* A `U` argument: octets up to a NUL, terminator consumed. Unterminated inside the frame is a
   decode error, not a string that happens to be short. */
const uint8_t *Spinel_ReadString(U_BStream *stream, uint32_t *outLen);

/* The two questions a frame's reader asks of a const stream: whether it failed, and how many octets are left, 0 once
   it has. */
int Spinel_StreamFailed(const U_BStream *stream);
uint32_t Spinel_Remaining(const U_BStream *stream);

#endif /* SPINEL_H */
