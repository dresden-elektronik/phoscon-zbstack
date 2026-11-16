#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#define U_SSTREAM_NO_DEPRECATED
#define U_ASSERT(c) assert(c)

#include "../u_sstream.h"
#include "../u_sstream.c"

struct entry
{
    const char *str;
    U_sstream_status status;
};


static int test_long(struct entry e)
{
    double num;
    U_SStream ss;
    unsigned len;
    char buf[128];

    for (len = 0; e.str[len]; len++)
        buf[len] = e.str[len];

    buf[len] = '\0';

    U_sstream_init(&ss, buf, len);

    num = U_sstream_get_double(&ss);

    if (ss.status == e.status)
    {
        printf("parsed: %s -> %g, ss.status: %d\n", e.str, num, (int)ss.status);
        if (U_sstream_at_end(&ss) == 0 && ss.status == U_SSTREAM_OK)
            return 0;

        return 1;
    }

    printf("failed to parse: %s, ss.pos: %u, ss.len: %u, ss.status: %d\n", e.str, ss.pos, ss.len, (int)ss.status);
    return 0;
}


int main(void)
{
    const struct entry numbers[] =
    {
        { "1", U_SSTREAM_OK },
        { "1.0625", U_SSTREAM_OK },
        { ".0625", U_SSTREAM_OK },
        { "1e3", U_SSTREAM_OK },
        { ".0e1", U_SSTREAM_OK },
        { "0.4e3", U_SSTREAM_OK },
        { "0.5e-3", U_SSTREAM_OK },
        { "0.5e-23", U_SSTREAM_OK },
        { "2e+24", U_SSTREAM_OK },
        { "    123.456", U_SSTREAM_OK },
        { "999999191919199199999999999", U_SSTREAM_OK },
        { "not_a_number", U_SSTREAM_ERR_INVALID },
        { "e", U_SSTREAM_ERR_INVALID },
        { "e1", U_SSTREAM_ERR_INVALID },
        { "e+23", U_SSTREAM_ERR_INVALID },
        { "e-4", U_SSTREAM_ERR_INVALID },
        { ".e-4", U_SSTREAM_ERR_INVALID }
    };

    for (unsigned i = 0; i < sizeof(numbers) / sizeof(numbers[0]); i++)
    {
        if (test_long(numbers[i]) == 0)
            return i + 1;
    }

    return 0;
}
