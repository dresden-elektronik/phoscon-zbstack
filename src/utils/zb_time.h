#ifndef ZB_TIME_H
#define ZB_TIME_H

#include <stdint.h>

/*
 * Zb_time: the deadline arithmetic of a `uint32_t` millisecond counter, so that no band above C compares a
 * deadline as two numbers (docs/internals/coding-rules.md §4.1). Time arrives as the caller's `nowMs`: no clock, no
 * state, no allocation.
 *
 * The subtraction is the comparison. The counter is free-running and wraps once every 2^32 ms (49.7 days), so
 * a difference is read as a distance: `nowMs - deadlineMs` as a signed 32-bit number is negative while the
 * deadline is ahead and non-negative once it has passed, and `nowMs - startMs` as an unsigned one is the
 * milliseconds elapsed since a start. A span shorter than 2^31 ms (24.8 days) is therefore measured correctly
 * across the wrap in either direction; a span of 2^31 ms or more is not, and a caller holding a deadline that
 * far away has a design error rather than a comparison problem.
 */

/* 1 once nowMs has reached deadlineMs, 0 while the deadline is still ahead. now == deadline is reached. */
int Zb_timeReached(uint32_t nowMs, uint32_t deadlineMs);

/* 1 while nowMs lies inside the window opened at startMs, 0 from the millisecond windowMs has passed. */
int Zb_timeWithin(uint32_t nowMs, uint32_t startMs, uint32_t windowMs);

#endif /* ZB_TIME_H */
