#ifndef HDLC_H
#define HDLC_H

/*
 * Band B: the HDLC-lite framing every Spinel frame travels in (docs/internals/protocol.md §2).
 * Written from the contract and the measured wire; no reference implementation was
 * transcribed. It knows nothing of Spinel commands, properties or dialects: it turns
 * octets in and octets out.
 */

#include <stdint.h>
#include "zb_status.h"

enum
{
    HDLC_FLAG = 0x7e,
    HDLC_ESCAPE = 0x7d,
    HDLC_ESCAPE_MASK = 0x20,
    HDLC_FCS_LEN = 2,
    HDLC_FRAME_MAX = 256,       /* the whole frame, both FCS bytes included */
    HDLC_PAYLOAD_MAX = 254,
    HDLC_FCS_RESIDUE = 0xf0b8   /* CRC over payload+FCS leaves this constant */
};

/*
 * The escape set is not just the two framing octets: the RCP escapes 0x11 and 0x13
 * (XON/XOFF, which a terminal would otherwise eat) and 0xF8 as well. 0x13 arriving as
 * `7d 33` is measured (docs/internals/protocol.md §2).
 */
int Hdlc_NeedsEscape(uint8_t octet);

/* CRC-16/X.25 as the RCP computes it: poly 0x8408 reflected, init 0xFFFF, xorout 0xFFFF. */
uint16_t Hdlc_Fcs(const uint8_t *bytes, uint32_t len);

/*
 * The other way the same check is written: run the register over payload+FCS and compare
 * against HDLC_FCS_RESIDUE before the final inversion. 1 when a framed run is self-consistent
 * without splitting the FCS off first.
 */
int Hdlc_ResidueValid(const uint8_t *bytes, uint32_t len);

/*
 * Framed form in `out`: flag, escaped payload, escaped FCS low byte first, flag. A flag both
 * closes a frame and opens the next, so consecutive frames share one. ZB_ERR_BAD_ARGUMENT
 * for a payload that cannot fit a frame, ZB_ERR_NO_SPACE when `cap` is too small for the
 * escaped form: an encoder never writes a partial frame.
 */
ZbStatus Hdlc_Encode(const uint8_t *payload, uint32_t len,
                     uint8_t *out, uint32_t cap, uint32_t *outLen);

typedef enum HdlcState
{
    HDLC_STATE_IDLE = 0,    /* between frames */
    HDLC_STATE_BODY = 1,    /* collecting payload octets */
    HDLC_STATE_ESCAPE = 2   /* next octet is the escaped half of a byte */
} HdlcState;

typedef enum HdlcEvent
{
    HDLC_EVENT_NONE = 0,
    HDLC_EVENT_FRAME = 1,       /* a complete frame with a matching FCS */
    HDLC_EVENT_DROP_SHORT = 2,  /* closed with less than a payload plus FCS */
    HDLC_EVENT_DROP_LONG = 3,   /* outgrew the frame maximum; the whole frame is discarded */
    HDLC_EVENT_DROP_FCS = 4     /* full length, FCS disagrees: corrupt on air, kept as a count */
} HdlcEvent;

/*
 * One decoder per link, caller-owned storage. A frame longer than HDLC_PAYLOAD_MAX is not
 * truncated and kept: the overflow is remembered and the whole frame is dropped at its flag,
 * because a silently shortened frame is worse than a missing one. Drops are counted, never
 * silent (docs/internals/coding-rules.md §7).
 *
 * A frame is only a frame if a flag opened it: octets before the first flag are ignored rather
 * than treated as a corrupt frame, which is what a transcript captured mid-frame actually is.
 * Two flags in a row close nothing and open nothing, so frames that each carry their own flag
 * do not manufacture a drop between them.
 */
typedef struct Hdlc_Decoder
{
    uint32_t state;
    uint32_t len;
    int overflow;
    int opened;
    uint32_t framesOk;
    uint32_t drops;
    uint8_t payload[HDLC_PAYLOAD_MAX];
} Hdlc_Decoder;

ZbStatus Hdlc_Init(Hdlc_Decoder *decoder);

/*
 * Feed one received octet. When a frame closes, the payload (FCS stripped) is copied to
 * `outPayload`, its length to `outLen`, and the event says what happened. `outPayload` may be
 * 0 when the caller only wants the events; a frame is then still counted and dropped frames
 * still reported.
 */
HdlcEvent Hdlc_Feed(Hdlc_Decoder *decoder, uint8_t octet, uint8_t *outPayload, uint32_t *outLen);

uint32_t Hdlc_FramesOk(const Hdlc_Decoder *decoder);
uint32_t Hdlc_Drops(const Hdlc_Decoder *decoder);

#endif /* HDLC_H */
