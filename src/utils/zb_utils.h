#ifndef ZB_UTILS_H
#define ZB_UTILS_H

/*
 * Zb_ utils: the stack's own byte and text primitives, so that no file under src/ includes
 * <string.h> or a similar hosted header (docs/internals/coding-rules.md §1). Bands A and B and the
 * target-independent port code are compiled for every target, including the WASM and MCU
 * ports where <string.h> is not promised at all (C99 §4: a freestanding implementation
 * need not provide the hosted headers). These are substrate below the bands like the
 * vendored libraries: any band may include them, they include nothing.
 *
 * Counts are uint32_t, as everywhere in this stack, not size_t. The prefix is the stack's own
 * Zb_, since U_ belongs to the u_* libraries an application may link beside it (docs/internals/coding-rules.md §2); the
 * snake_case names keep the C library's, so a reader knows each one at a glance.
 *
 * No function here reads or writes past the bound stated at the call, and none of them
 * handles overlapping ranges: a copy whose regions overlap is a programming error in this
 * stack, and there is no memmove equivalent to paper over it.
 */

#include <stdint.h>

/* Copies n bytes. n == 0 does nothing. Ranges must not overlap. */
void Zb_memcpy(void *dst, const void *src, uint32_t n);

/* Sets n bytes to value. n == 0 does nothing. */
void Zb_memset(void *dst, unsigned char value, uint32_t n);

/*
 * Compares n bytes. Zero when every byte matches; otherwise the
 * difference of the first pair that differs, each interpreted as an
 * unsigned char: the sign is that of (a[i] - b[i]), which is what
 * makes ordering of opaque buffers meaningful. n == 0 compares equal.
 */
int Zb_memcmp(const void *a, const void *b, uint32_t n);

/*
 * Length of the string at s, scanning at most cap bytes. Returns the number of bytes
 * before the first '\0', or cap when no '\0' appears within cap: a caller that needs to
 * tell a truncated scan from a full buffer compares against cap. Never reads past cap.
 */
uint32_t Zb_strlen(const char *s, uint32_t cap);

#endif /* ZB_UTILS_H */
