#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "../u_sstream.h"
#include "../u_sstream.c"

union u64real
{
    double f;
    unsigned long long i;
};

int main(void)
{
    U_SStream ss;
    char str[512];
    union u64real nan1;
    union u64real inf1;
    union u64real inf2;
    unsigned long long i;

    nan1.i = (0x7ffULL << 52) | 1;
    inf1.i = (0x7ffULL << 52) | 0;
    inf2.i = (0x7ffULL << 52) | (1ULL << 63) | 0;

    const double values[] = {
        nan1.f,
        inf1.f,
        inf2.f,
        1,
        0,
        -0,
        1000,
        12345.0012345,
        3372036854775807.08888,
        -9007199254740991.0 /* Javascript 2^53-1 miniumum safe value */,
        9007199254740991.0 /* Javascript 2^53-1 maxiumum safe value */,
        9007199254740990.0,
        -0.5,
        -0.25,
        -0.1,
        -0.99,
        -1.5
    };

    const char *expected_result[] = {
        "null",
        "1e99999",
        "-1e99999",
        "1",
        "0",
        "0",
        "1000",
        "12345.001234",
        "3372036854775807",
        "-9007199254740991",
        "9007199254740991",
        "9007199254740990",
        "-0.5",
        "-0.25",
        "-0.1",
        "-0.99",
        "-1.5"
    };

    for (i = 0; i < sizeof(values) / sizeof(values[0]); i++)
    {
        const char *exp = expected_result[i];

        U_sstream_init(&ss, str, sizeof(str));
        U_sstream_put_double(&ss, values[i], 6);

        if (ss.status != U_SSTREAM_OK)
        {
            printf("error: %f --> %s\n", values[i], ss.str);
            return 1;
        }

        if (ss.pos != strlen(exp))
        {
            printf("wrong length: %s vs %s (%f)\n", ss.str, exp, values[i]);
            return 2;
        }

        if (memcmp(ss.str, exp, ss.pos) != 0)
        {
            printf("not equal: %s vs %s (%f)\n", ss.str, exp, values[i]);
            return 3;
        }
    }

    i = 9007199254740980ULL;
    for (; i < 9007199254741000ULL; i++)
    {
        U_sstream_init(&ss, str, sizeof(str));
        U_sstream_put_double(&ss, (double)i, 6);

        if (ss.status != U_SSTREAM_OK)
        {
            if (i < 9007199254740991ULL)
            {
                printf("error (status: %d): %f (%llu)\n", ss.status, (double)i, i);
                return 4;
            }
        }
    }

    return 0;
}
