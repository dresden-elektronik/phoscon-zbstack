#include "spinel.h"

/*
 * Two halves of one rule keep this codec honest: a writer never tests the buffer it is given,
 * and a reader never decides on its own that a frame is finished. Sizing is done before
 * composing (Spinel_PackedUintBytes, Spinel_PrefixedBytes), validity is decided once afterwards
 * (Spinel_StreamFailed). A frame is therefore either whole or not sent at all.
 */

int Spinel_HeaderValid(uint8_t octet)
{
    return (octet & SPINEL_HEADER_FLAGS_MASK) == SPINEL_HEADER_FLAG;
}

uint8_t Spinel_HeaderByte(uint8_t tid)
{
    return (uint8_t)(SPINEL_HEADER_FLAG | (tid & SPINEL_HEADER_TID_MASK));
}

int Spinel_TidValid(uint8_t tid)
{
    return tid >= SPINEL_TID_MIN && tid <= SPINEL_TID_MAX;
}

void Spinel_WriteHeader(U_BStream *stream, uint8_t tid)
{
    U_bstream_put_u8(stream, Spinel_HeaderByte(tid));
}

void Spinel_ReadHeader(uint8_t octet, Spinel_Header *out)
{
    if (out == 0)
        return;

    out->flags = (uint8_t)((octet & SPINEL_HEADER_FLAGS_MASK) >> SPINEL_HEADER_FLAGS_SHIFT);
    out->iid = (uint8_t)((octet & SPINEL_HEADER_IID_MASK) >> SPINEL_HEADER_IID_SHIFT);
    out->tid = (uint8_t)(octet & SPINEL_HEADER_TID_MASK);
}

int Spinel_IsNotification(const Spinel_Header *header)
{
    return header != 0 && header->tid == SPINEL_TID_NONE;
}

int Spinel_IidValid(const Spinel_Header *header)
{
    return header != 0 && header->iid <= SPINEL_HEADER_IID_MAX;
}

uint32_t Spinel_PackedUintBytes(uint32_t value)
{
    return (uint32_t)U_bstream_leb128_u32_size((unsigned long)value);
}

void Spinel_WritePackedUint(U_BStream *stream, uint32_t value)
{
    U_bstream_put_leb128_u32(stream, (unsigned long)value);
}

uint32_t Spinel_ReadPackedUint(U_BStream *stream)
{
    return (uint32_t)U_bstream_get_leb128_u32(stream);
}

void Spinel_WriteUint8(U_BStream *stream, uint8_t value)
{
    U_bstream_put_u8(stream, value);
}

uint8_t Spinel_ReadUint8(U_BStream *stream)
{
    return U_bstream_get_u8(stream);
}

void Spinel_WriteInt8(U_BStream *stream, int8_t value)
{
    U_bstream_put_s8(stream, (signed char)value);
}

int8_t Spinel_ReadInt8(U_BStream *stream)
{
    return (int8_t)U_bstream_get_s8(stream);
}

void Spinel_WriteUint16(U_BStream *stream, uint16_t value)
{
    U_bstream_put_u16_le(stream, value);
}

uint16_t Spinel_ReadUint16(U_BStream *stream)
{
    return U_bstream_get_u16_le(stream);
}

void Spinel_WriteInt16(U_BStream *stream, int16_t value)
{
    U_bstream_put_s16_le(stream, value);
}

int16_t Spinel_ReadInt16(U_BStream *stream)
{
    return U_bstream_get_s16_le(stream);
}

void Spinel_WriteUint32(U_BStream *stream, uint32_t value)
{
    U_bstream_put_u32_le(stream, value);
}

uint32_t Spinel_ReadUint32(U_BStream *stream)
{
    return U_bstream_get_u32_le(stream);
}

void Spinel_WriteInt32(U_BStream *stream, int32_t value)
{
    U_bstream_put_s32_le(stream, value);
}

int32_t Spinel_ReadInt32(U_BStream *stream)
{
    return U_bstream_get_s32_le(stream);
}

void Spinel_WriteUint64(U_BStream *stream, uint64_t value)
{
    U_bstream_put_u64_le(stream, value);
}

uint64_t Spinel_ReadUint64(U_BStream *stream)
{
    return U_bstream_get_u64_le(stream);
}

void Spinel_WriteUint16Be(U_BStream *stream, uint16_t value)
{
    U_bstream_put_u16_be(stream, value);
}

uint16_t Spinel_ReadUint16Be(U_BStream *stream)
{
    return U_bstream_get_u16_be(stream);
}

void Spinel_WriteUint32Be(U_BStream *stream, uint32_t value)
{
    U_bstream_put_u32_be(stream, (unsigned long)value);
}

uint32_t Spinel_ReadUint32Be(U_BStream *stream)
{
    return (uint32_t)U_bstream_get_u32_be(stream);
}

void Spinel_WriteUint64Be(U_BStream *stream, uint64_t value)
{
    U_bstream_put_u64_be(stream, value);
}

uint64_t Spinel_ReadUint64Be(U_BStream *stream)
{
    return U_bstream_get_u64_be(stream);
}

void Spinel_WriteAddrBe(U_BStream *stream, const uint8_t *addr, uint32_t len)
{
    if (addr == 0)
    {
        Zb_bstream_fail(stream, U_BSTREAM_WRITE_PAST_END);
        return;
    }

    U_bstream_put_bytes(stream, addr, (unsigned long)len);
}

const uint8_t *Spinel_ReadAddrBe(U_BStream *stream, uint8_t *out, uint32_t len)
{
    if (out == 0 || !Zb_bstream_fits(stream, len))
    {
        Zb_bstream_fail(stream, U_BSTREAM_DECODE_ERROR);
        return 0;
    }

    U_bstream_get_bytes(stream, out, (unsigned long)len);

    return Zb_bstream_ok(stream) ? out : 0;
}

void Spinel_WriteBool(U_BStream *stream, int value)
{
    U_bstream_put_u8(stream, value ? SPINEL_BOOL_TRUE : SPINEL_BOOL_FALSE);
}

int Spinel_ReadBool(U_BStream *stream)
{
    return U_bstream_get_u8(stream) != SPINEL_BOOL_FALSE;
}

uint32_t Spinel_PrefixedBytes(uint32_t len)
{
    return SPINEL_LEN_PREFIX_BYTES + len;
}

void Spinel_WritePrefixed(U_BStream *stream, const uint8_t *bytes, uint32_t len)
{
    if (bytes == 0 || len > SPINEL_LEN_MAX || !Zb_bstream_fits(stream, Spinel_PrefixedBytes(len)))
    {
        Zb_bstream_fail(stream, U_BSTREAM_WRITE_PAST_END);
        return;
    }

    U_bstream_put_u16_le(stream, (uint16_t)len);
    U_bstream_put_bytes(stream, bytes, (unsigned long)len);
}

const uint8_t *Spinel_ReadPrefixed(U_BStream *stream, uint32_t *outLen)
{
    uint32_t len;
    const uint8_t *bytes;

    if (outLen != 0)
        *outLen = 0;

    len = (uint32_t)U_bstream_get_u16_le(stream);

    if (!Zb_bstream_fits(stream, len))
    {
        Zb_bstream_fail(stream, U_BSTREAM_DECODE_ERROR);
        return 0;
    }

    bytes = Zb_bstream_get_span(stream, len);

    if (outLen != 0)
        *outLen = len;

    return bytes;
}

const uint8_t *Spinel_ReadString(U_BStream *stream, uint32_t *outLen)
{
    U_BStream probe;
    uint32_t scan = 0;
    int terminated = 0;

    if (outLen != 0)
        *outLen = 0;

    probe = *stream;

    while (Zb_bstream_fits(&probe, 1))
    {
        if (U_bstream_get_u8(&probe) == SPINEL_STRING_TERM)
        {
            terminated = 1;
            break;
        }

        scan++;
    }

    if (!terminated)
    {
        Zb_bstream_fail(stream, U_BSTREAM_DECODE_ERROR);
        return 0;
    }

    if (outLen != 0)
        *outLen = scan;

    return Zb_bstream_get_span(stream, scan + SPINEL_STRING_TERM_BYTES);
}

int Spinel_StreamFailed(const U_BStream *stream)
{
    return stream == 0 || !Zb_bstream_ok(stream);
}

uint32_t Spinel_Remaining(const U_BStream *stream)
{
    if (stream == 0)
        return 0;

    return Zb_bstream_remaining(stream);
}
