#ifndef ZB_BSTREAM_H
#define ZB_BSTREAM_H

/* Zb_bstream: what this stack adds beside the vendored U_BStream (docs/internals/refs.md §6), whose header it
   includes so a source needs only this one. Counts are uint32_t; a failed stream stays failed and reads as zero, as
   the vendored calls do; an addition upstream comes to carry is deleted here and its callers renamed. */

#include <stdint.h>

#include "u_bstream.h"

/* A stream over a buffer the caller holds read-only: the vendored init takes a writable pointer, so the cast is here
   and nowhere else. The stream has no read-only flag, and a write through it is the caller's defect. */
void Zb_bstream_init_const(U_BStream *bs, const uint8_t *data, uint32_t size);

/* Fails a stream that has not failed yet, the vendored rule for a fault found by the caller's own check: the first
   failure is the one a stream reports. */
void Zb_bstream_fail(U_BStream *bs, U_BStreamStatus status);

/* The queries on a const stream, with no side effect: the vendored ones take a writable stream, and its pos marks an
   uninitialised stream failed. */
int Zb_bstream_ok(const U_BStream *bs);                   /* initialised and U_BSTREAM_OK */
uint32_t Zb_bstream_remaining(const U_BStream *bs);       /* octets after the cursor, 0 on a failed stream */
uint32_t Zb_bstream_pos(const U_BStream *bs);             /* the cursor, what was committed even after a failure */
uint32_t Zb_bstream_size(const U_BStream *bs);            /* the octets the stream was opened over */
int Zb_bstream_fits(const U_BStream *bs, uint32_t n);     /* n octets can still be read or written */

/* The next n octets taken in place: a pointer at the cursor, which then moves past them. A stream too short for n
   octets is failed U_BSTREAM_READ_PAST_END and the answer is 0. */
const uint8_t *Zb_bstream_get_span(U_BStream *bs, uint32_t n);

/* A stream of its own over the next n octets, which the parent moves past, so a record read through it never reads
   past its own length. A parent short of n octets fails as get_span does, and the child opens with its status. */
void Zb_bstream_sub(U_BStream *bs, U_BStream *sub, uint32_t n);

/* The octet at the cursor without moving it, 0 where there is none; a caller that must tell a 0 from no octet asks
   Zb_bstream_fits first. */
uint8_t Zb_bstream_peek_u8(const U_BStream *bs);

/* A 24-bit value, least significant octet first: the whole value or none of it. */
void Zb_bstream_put_u24_le(U_BStream *bs, uint32_t value);
uint32_t Zb_bstream_get_u24_le(U_BStream *bs);

/* One octet written at an absolute offset without moving the cursor: a count known only once what it counts is
   written. An offset at or past the end fails the stream U_BSTREAM_WRITE_PAST_END. */
void Zb_bstream_put_u8_at(U_BStream *bs, uint32_t offset, uint8_t value);

#endif /* ZB_BSTREAM_H */
