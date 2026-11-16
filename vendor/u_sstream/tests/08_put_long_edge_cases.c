#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#define U_SSTREAM_NO_DEPRECATED
#define U_ASSERT(c) assert(c)

#include "../u_sstream.h"
#include "../u_sstream.c"


int main(void)
{
    char buf[64];
    U_SStream ss;

#if __SIZEOF_LONG__ == 8
    const char *expected_min = "-9223372036854775808";
    const char *expected_max = "9223372036854775807";
#else
    const char *expected_min = "-2147483648";
    const char *expected_max = "2147483647";
#endif

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_long(&ss, 0);
    assert(ss.status == U_SSTREAM_OK);
    assert(strcmp(buf, "0") == 0);
    printf("put_long(0): \"%s\" (expected \"0\")\n", buf);

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_long(&ss, -1);
    assert(ss.status == U_SSTREAM_OK);
    assert(strcmp(buf, "-1") == 0);
    printf("put_long(-1): \"%s\" (expected \"-1\")\n", buf);

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_long(&ss, LONG_MAX);
    assert(ss.status == U_SSTREAM_OK);
    assert(strcmp(buf, expected_max) == 0);
    printf("put_long(LONG_MAX): \"%s\" (expected \"%s\")\n", buf, expected_max);

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_long(&ss, LONG_MIN);
    assert(ss.status == U_SSTREAM_OK);
    assert(strcmp(buf, expected_min) == 0);
    printf("put_long(LONG_MIN): \"%s\" (expected \"%s\")\n", buf, expected_min);

    printf("\nall tests passed\n");
    return 0;
}
