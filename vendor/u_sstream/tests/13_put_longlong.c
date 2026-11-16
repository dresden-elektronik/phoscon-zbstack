#include <assert.h>
#include <stdio.h>
#include <string.h>

#define U_SSTREAM_NO_DEPRECATED
#define U_ASSERT(c) assert(c)

#include "../u_sstream.h"
#include "../u_sstream.c"


static int test_put_longlong_zero(void)
{
    char buf[64];
    U_SStream ss;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_longlong(&ss, 0);

    if (ss.status != U_SSTREAM_OK)
        return 0;
    if (ss.pos != 1)
        return 0;
    if (memcmp(buf, "0", 1) != 0)
        return 0;
    return 1;
}


static int test_put_longlong_positive(void)
{
    char buf[64];
    U_SStream ss;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_longlong(&ss, 12345);

    if (ss.status != U_SSTREAM_OK)
        return 0;
    if (ss.pos != 5)
        return 0;
    if (memcmp(buf, "12345", 5) != 0)
        return 0;
    return 1;
}


static int test_put_longlong_negative(void)
{
    char buf[64];
    U_SStream ss;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_longlong(&ss, -12345);

    if (ss.status != U_SSTREAM_OK)
        return 0;
    if (ss.pos != 6)
        return 0;
    if (memcmp(buf, "-12345", 6) != 0)
        return 0;
    return 1;
}


static int test_put_longlong_max(void)
{
    char buf[64];
    U_SStream ss;
    const char *expected = "9223372036854775807";
    unsigned expected_len = 19;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_longlong(&ss, 9223372036854775807LL);

    if (ss.status != U_SSTREAM_OK)
        return 0;
    if (ss.pos != expected_len)
        return 0;
    if (memcmp(buf, expected, expected_len) != 0)
        return 0;
    return 1;
}


static int test_put_longlong_min(void)
{
    char buf[64];
    U_SStream ss;
    const char *expected = "-9223372036854775808";
    unsigned expected_len = 20;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_longlong(&ss, -9223372036854775807LL - 1);

    if (ss.status != U_SSTREAM_OK)
        return 0;
    if (ss.pos != expected_len)
        return 0;
    if (memcmp(buf, expected, expected_len) != 0)
        return 0;
    return 1;
}


static int test_put_longlong_minus_one(void)
{
    char buf[64];
    U_SStream ss;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_longlong(&ss, -1);

    if (ss.status != U_SSTREAM_OK)
        return 0;
    if (ss.pos != 2)
        return 0;
    if (memcmp(buf, "-1", 2) != 0)
        return 0;
    return 1;
}


static int test_put_longlong_overflow_positive(void)
{
    char buf[19];
    U_SStream ss;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_longlong(&ss, 9223372036854775807LL);

    if (ss.status != U_SSTREAM_ERR_NO_SPACE)
        return 0;
    return 1;
}


static int test_put_longlong_overflow_negative(void)
{
    char buf[20];
    U_SStream ss;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_longlong(&ss, -9223372036854775807LL - 1);

    if (ss.status != U_SSTREAM_ERR_NO_SPACE)
        return 0;
    return 1;
}


static int test_put_longlong_exact_fit_positive(void)
{
    char buf[20];
    U_SStream ss;
    const char *expected = "9223372036854775807";
    unsigned expected_len = 19;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_longlong(&ss, 9223372036854775807LL);

    if (ss.status != U_SSTREAM_OK)
        return 0;
    if (ss.pos != expected_len)
        return 0;
    if (memcmp(buf, expected, expected_len) != 0)
        return 0;
    return 1;
}


static int test_put_longlong_exact_fit_negative(void)
{
    char buf[21];
    U_SStream ss;
    const char *expected = "-9223372036854775808";
    unsigned expected_len = 20;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_longlong(&ss, -9223372036854775807LL - 1);

    if (ss.status != U_SSTREAM_OK)
        return 0;
    if (ss.pos != expected_len)
        return 0;
    if (memcmp(buf, expected, expected_len) != 0)
        return 0;
    return 1;
}


static int test_put_longlong_single_byte_buffer(void)
{
    char buf[2];
    U_SStream ss;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_longlong(&ss, 0);

    if (ss.status != U_SSTREAM_OK)
        return 0;
    if (ss.pos != 1)
        return 0;
    if (memcmp(buf, "0", 1) != 0)
        return 0;
    return 1;
}


static int test_put_longlong_single_byte_overflow(void)
{
    char buf[2];
    U_SStream ss;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_longlong(&ss, 100);

    if (ss.status != U_SSTREAM_ERR_NO_SPACE)
        return 0;
    return 1;
}


static int test_put_longlong_error_propagation(void)
{
    char buf[64];
    U_SStream ss;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    ss.status = U_SSTREAM_ERR_NO_SPACE;

    U_sstream_put_longlong(&ss, 12345);

    if (ss.status != U_SSTREAM_ERR_NO_SPACE)
        return 0;
    return 1;
}


static int test_put_longlong_sequential(void)
{
    char buf[64];
    U_SStream ss;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_longlong(&ss, 123);
    U_sstream_put_longlong(&ss, 456);

    if (ss.status != U_SSTREAM_OK)
        return 0;
    if (ss.pos != 6)
        return 0;
    if (memcmp(buf, "123456", 6) != 0)
        return 0;
    return 1;
}


static int test_put_longlong_small_negative_overflow(void)
{
    char buf[3];
    U_SStream ss;

    memset(buf, 0xFF, sizeof(buf));
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_longlong(&ss, -10);

    if (ss.status != U_SSTREAM_ERR_NO_SPACE)
        return 0;
    return 1;
}


int main(void)
{
    int tests[] = {
        test_put_longlong_zero(),
        test_put_longlong_positive(),
        test_put_longlong_negative(),
        test_put_longlong_max(),
        test_put_longlong_min(),
        test_put_longlong_minus_one(),
        test_put_longlong_overflow_positive(),
        test_put_longlong_overflow_negative(),
        test_put_longlong_exact_fit_positive(),
        test_put_longlong_exact_fit_negative(),
        test_put_longlong_single_byte_buffer(),
        test_put_longlong_single_byte_overflow(),
        test_put_longlong_error_propagation(),
        test_put_longlong_sequential(),
        test_put_longlong_small_negative_overflow()
    };
    unsigned i;

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
    {
        if (tests[i] == 0)
            return i + 1;
    }

    printf("all tests passed\n");
    return 0;
}
