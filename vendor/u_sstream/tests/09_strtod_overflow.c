#include <assert.h>
#include <stdio.h>
#include <string.h>

#define U_SSTREAM_NO_DEPRECATED
#define U_ASSERT(c) assert(c)

#include "../u_sstream.h"
#include "../u_sstream.c"


int main(void)
{
    const char *endptr;
    int err;
    double result;
    char buf[400];

    result = U_strtod("123.456", 7, &endptr, &err);
    assert(err == 0);
    printf("U_strtod(\"123.456\"): result=%g, err=%d (expected 0)\n", result, err);

    result = U_strtod("", 0, &endptr, &err);
    assert(err == 0x01);
    printf("U_strtod(\"\"): result=%g, err=%d (expected 1 = invalid input)\n", result, err);

    result = U_strtod("abc", 3, &endptr, &err);
    assert(err == 0x01);
    printf("U_strtod(\"abc\"): result=%g, err=%d (expected 1 = invalid input)\n", result, err);

    memset(buf, '9', 310);
    buf[310] = '\0';
    result = U_strtod(buf, 310, &endptr, &err);
    assert(err == 0x02);
    printf("U_strtod(\"310x9\"): result=%g, err=%d (expected 2 = overflow)\n", result, err);

    memset(buf, '9', 50);
    buf[50] = '\0';
    result = U_strtod(buf, 50, &endptr, &err);
    assert(err == 0);
    printf("U_strtod(\"50x9\"): result=%g, err=%d (expected 0 = valid)\n", result, err);

    printf("\nall tests passed\n");
    return 0;
}
