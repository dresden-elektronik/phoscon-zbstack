#include "zb_time.h"

/*
 * The two deadline comparisons: the subtraction is the comparison, read at the width that gives it a
 * direction (docs/internals/coding-rules.md §4.1, the span rule stated in zb_time.h).
 */

int Zb_timeReached(uint32_t nowMs, uint32_t deadlineMs)
{
    return (int32_t)(nowMs - deadlineMs) >= 0;
}

int Zb_timeWithin(uint32_t nowMs, uint32_t startMs, uint32_t windowMs)
{
    return (uint32_t)(nowMs - startMs) < windowMs;
}
