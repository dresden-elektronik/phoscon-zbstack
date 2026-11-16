#include "zb_bstream.h"

/* The additions read and move the vendored stream's own fields under the vendored rule for each failure: a failed
   stream is left as it is, one with no buffer becomes U_BSTREAM_NOT_INITIALISED, one too short the past-end status. */

/* Whether n more octets may be taken, failing the stream with `pastEnd` where they may not */
static int exTake(U_BStream *bs, uint32_t n, U_BStreamStatus pastEnd)
{
    if (bs->status != U_BSTREAM_OK)
        return 0;

    if (bs->data == 0)
    {
        bs->status = U_BSTREAM_NOT_INITIALISED;
        return 0;
    }

    if ((unsigned long)n > bs->size - bs->pos)
    {
        bs->status = pastEnd;
        return 0;
    }

    return 1;
}

void Zb_bstream_init_const(U_BStream *bs, const uint8_t *data, uint32_t size)
{
    U_bstream_init(bs, (uint8_t *)data, (unsigned long)size);
}

void Zb_bstream_fail(U_BStream *bs, U_BStreamStatus status)
{
    if (bs->status == U_BSTREAM_OK)
        bs->status = status;
}

int Zb_bstream_ok(const U_BStream *bs)
{
    return bs->data != 0 && bs->status == U_BSTREAM_OK;
}

uint32_t Zb_bstream_remaining(const U_BStream *bs)
{
    if (!Zb_bstream_ok(bs))
        return 0;

    return (uint32_t)(bs->size - bs->pos);
}

uint32_t Zb_bstream_pos(const U_BStream *bs)
{
    return (uint32_t)bs->pos;
}

uint32_t Zb_bstream_size(const U_BStream *bs)
{
    return (uint32_t)bs->size;
}

int Zb_bstream_fits(const U_BStream *bs, uint32_t n)
{
    return n <= Zb_bstream_remaining(bs);
}

const uint8_t *Zb_bstream_get_span(U_BStream *bs, uint32_t n)
{
    const uint8_t *span;

    if (!exTake(bs, n, U_BSTREAM_READ_PAST_END))
        return 0;

    span = bs->data + bs->pos;
    bs->pos += n;

    return span;
}

void Zb_bstream_sub(U_BStream *bs, U_BStream *sub, uint32_t n)
{
    const uint8_t *span;

    span = Zb_bstream_get_span(bs, n);

    if (span != 0)
    {
        Zb_bstream_init_const(sub, span, n);
        return;
    }

    U_bstream_init(sub, 0, 0);
    sub->status = bs->status;
}

uint8_t Zb_bstream_peek_u8(const U_BStream *bs)
{
    if (!Zb_bstream_fits(bs, 1))
        return 0;

    return bs->data[bs->pos];
}

void Zb_bstream_put_u24_le(U_BStream *bs, uint32_t value)
{
    if (!exTake(bs, 3, U_BSTREAM_WRITE_PAST_END))
        return;

    U_bstream_put_u8(bs, (unsigned char)(value & 0xff));
    U_bstream_put_u8(bs, (unsigned char)((value >> 8) & 0xff));
    U_bstream_put_u8(bs, (unsigned char)((value >> 16) & 0xff));
}

uint32_t Zb_bstream_get_u24_le(U_BStream *bs)
{
    uint32_t value;

    if (!exTake(bs, 3, U_BSTREAM_READ_PAST_END))
        return 0;

    value = (uint32_t)U_bstream_get_u8(bs);
    value |= (uint32_t)U_bstream_get_u8(bs) << 8;
    value |= (uint32_t)U_bstream_get_u8(bs) << 16;

    return value;
}

void Zb_bstream_put_u8_at(U_BStream *bs, uint32_t offset, uint8_t value)
{
    if (bs->status != U_BSTREAM_OK)
        return;

    if (bs->data == 0)
    {
        bs->status = U_BSTREAM_NOT_INITIALISED;
        return;
    }

    if ((unsigned long)offset >= bs->size)
    {
        bs->status = U_BSTREAM_WRITE_PAST_END;
        return;
    }

    bs->data[offset] = value;
}
