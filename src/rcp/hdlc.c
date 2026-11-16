#include "hdlc.h"
#include "zb_bstream.h"
#include "zb_utils.h"

/*
 * The CRC is computed bit by bit. A 512-byte lookup table would be the other option; frames
 * here are at most 256 octets on a 115200 link, and read-only state that a WASM or MCU target
 * has to carry is a worse trade than a few hundred shifts.
 */

static uint16_t hdlcRegister(const uint8_t *bytes, uint32_t len)
{
    uint16_t fcs;
    uint16_t mixed;
    uint32_t i;
    uint32_t bit;

    fcs = 0xffff;

    for (i = 0; i < len; i++)
    {
        mixed = (uint16_t)(fcs ^ (uint16_t)bytes[i]);

        for (bit = 0; bit < 8; bit++)
        {
            if ((mixed & 1) != 0)
                mixed = (uint16_t)((mixed >> 1) ^ 0x8408);
            else
                mixed = (uint16_t)(mixed >> 1);
        }

        fcs = mixed;
    }

    return fcs;
}

uint16_t Hdlc_Fcs(const uint8_t *bytes, uint32_t len)
{
    return (uint16_t)(hdlcRegister(bytes, len) ^ 0xffff);
}

int Hdlc_ResidueValid(const uint8_t *bytes, uint32_t len)
{
    return hdlcRegister(bytes, len) == HDLC_FCS_RESIDUE;
}

int Hdlc_NeedsEscape(uint8_t octet)
{
    return octet == 0x11 || octet == 0x13 || octet == 0xf8
        || octet == HDLC_ESCAPE || octet == HDLC_FLAG;
}

static void hdlcPut(U_BStream *stream, uint8_t octet)
{
    if (Hdlc_NeedsEscape(octet))
    {
        U_bstream_put_u8(stream, HDLC_ESCAPE);
        U_bstream_put_u8(stream, (uint8_t)(octet ^ HDLC_ESCAPE_MASK));
        return;
    }

    U_bstream_put_u8(stream, octet);
}

ZbStatus Hdlc_Encode(const uint8_t *payload, uint32_t len,
                     uint8_t *out, uint32_t cap, uint32_t *outLen)
{
    U_BStream stream;
    uint32_t i;
    uint16_t fcs;

    if (payload == 0 || out == 0 || outLen == 0)
        return ZB_ERR_BAD_ARGUMENT;

    if (len > HDLC_PAYLOAD_MAX)
        return ZB_ERR_BAD_ARGUMENT;

    U_bstream_init(&stream, out, (unsigned long)cap);
    U_bstream_put_u8(&stream, HDLC_FLAG);

    for (i = 0; i < len; i++)
        hdlcPut(&stream, payload[i]);

    fcs = Hdlc_Fcs(payload, len);
    hdlcPut(&stream, (uint8_t)(fcs & 0xff));
    hdlcPut(&stream, (uint8_t)(fcs >> 8));

    U_bstream_put_u8(&stream, HDLC_FLAG);

    if (!Zb_bstream_ok(&stream))
    {
        *outLen = 0;
        return ZB_ERR_NO_SPACE;
    }

    *outLen = Zb_bstream_pos(&stream);
    return ZB_OK;
}

ZbStatus Hdlc_Init(Hdlc_Decoder *decoder)
{
    if (decoder == 0)
        return ZB_ERR_BAD_ARGUMENT;

    Zb_memset(decoder, 0, (uint32_t)sizeof *decoder);
    decoder->state = HDLC_STATE_IDLE;
    decoder->opened = 0;
    return ZB_OK;
}

/* Closes the frame that the flag ended and opens the next one in the same breath. */
static int hdlcEmpty(const Hdlc_Decoder *decoder)
{
    return decoder->len == 0 && decoder->overflow == 0;
}
static HdlcEvent hdlcClose(Hdlc_Decoder *decoder, uint8_t *outPayload, uint32_t *outLen)
{
    uint32_t body;
    uint16_t want;
    uint16_t got;
    HdlcEvent event;

    if (decoder->overflow != 0)
    {
        event = HDLC_EVENT_DROP_LONG;
        decoder->drops++;
    }
    else if (decoder->len < HDLC_FCS_LEN + 1)
    {
        event = HDLC_EVENT_DROP_SHORT;
        decoder->drops++;
    }
    else
    {
        body = decoder->len - HDLC_FCS_LEN;
        want = Hdlc_Fcs(decoder->payload, body);
        got = (uint16_t)(decoder->payload[body] | ((uint16_t)decoder->payload[body + 1] << 8));

        if (want == got)
        {
            event = HDLC_EVENT_FRAME;
            decoder->framesOk++;

            if (outPayload != 0)
                Zb_memcpy(outPayload, decoder->payload, body);

            if (outLen != 0)
                *outLen = body;
        }
        else
        {
            event = HDLC_EVENT_DROP_FCS;
            decoder->drops++;
        }
    }

    decoder->len = 0;
    decoder->overflow = 0;
    decoder->state = HDLC_STATE_BODY;
    return event;
}

HdlcEvent Hdlc_Feed(Hdlc_Decoder *decoder, uint8_t octet, uint8_t *outPayload, uint32_t *outLen)
{
    if (octet == HDLC_FLAG)
    {
        if (!decoder->opened || hdlcEmpty(decoder))
        {
            decoder->opened = 1;
            decoder->state = HDLC_STATE_BODY;
            decoder->len = 0;
            decoder->overflow = 0;
            return HDLC_EVENT_NONE;
        }

        return hdlcClose(decoder, outPayload, outLen);
    }

    if (!decoder->opened)
        return HDLC_EVENT_NONE;

    if (decoder->state == HDLC_STATE_ESCAPE)
    {
        octet = (uint8_t)(octet ^ HDLC_ESCAPE_MASK);
        decoder->state = HDLC_STATE_BODY;

        if (decoder->len < HDLC_PAYLOAD_MAX)
        {
            decoder->payload[decoder->len] = octet;
            decoder->len++;
        }
        else
        {
            decoder->overflow = 1;
        }

        return HDLC_EVENT_NONE;
    }

    if (octet == HDLC_ESCAPE)
    {
        if (decoder->state == HDLC_STATE_IDLE)
            decoder->state = HDLC_STATE_BODY;

        decoder->state = HDLC_STATE_ESCAPE;
        return HDLC_EVENT_NONE;
    }

    if (decoder->state == HDLC_STATE_IDLE)
        decoder->state = HDLC_STATE_BODY;

    if (decoder->len < HDLC_PAYLOAD_MAX)
    {
        decoder->payload[decoder->len] = octet;
        decoder->len++;
    }
    else
    {
        decoder->overflow = 1;
    }

    return HDLC_EVENT_NONE;
}

uint32_t Hdlc_FramesOk(const Hdlc_Decoder *decoder)
{
    if (decoder == 0)
        return 0;

    return decoder->framesOk;
}

uint32_t Hdlc_Drops(const Hdlc_Decoder *decoder)
{
    if (decoder == 0)
        return 0;

    return decoder->drops;
}
