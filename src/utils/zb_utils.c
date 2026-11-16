#include "zb_utils.h"

/*
 * Byte-at-a-time on purpose. The ranges these move are frames and ring slices (tens to
 * hundreds of bytes) and a loop over unsigned char is the only form that is both valid
 * C99 everywhere and honest about what it may alias. A word-at-a-time copy would need
 * either misaligned access or a union trick, and both are the kind of thing this stack
 * keeps out of the tree. A target that wants the libc internals can wrap them in its own
 * band-C backend; nothing above the seam will notice.
 */

void Zb_memcpy(void *dst, const void *src, uint32_t n)
{
    unsigned char *to;
    const unsigned char *from;
    uint32_t i;

    if (n == 0)
        return;

    to = (unsigned char *)dst;
    from = (const unsigned char *)src;

    for (i = 0; i < n; i++)
        to[i] = from[i];
}

void Zb_memset(void *dst, unsigned char value, uint32_t n)
{
    unsigned char *to;
    uint32_t i;

    if (n == 0)
        return;

    to = (unsigned char *)dst;

    for (i = 0; i < n; i++)
        to[i] = value;
}

int Zb_memcmp(const void *a, const void *b, uint32_t n)
{
    const unsigned char *x;
    const unsigned char *y;
    uint32_t i;

    if (n == 0)
        return 0;

    x = (const unsigned char *)a;
    y = (const unsigned char *)b;

    for (i = 0; i < n; i++)
    {
        if (x[i] != y[i])
            return (int)x[i] - (int)y[i];
    }

    return 0;
}

uint32_t Zb_strlen(const char *s, uint32_t cap)
{
    uint32_t i;

    for (i = 0; i < cap; i++)
    {
        if (s[i] == 0)
            return i;
    }

    return cap;
}
