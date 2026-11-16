#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#define U_SSTREAM_NO_DEPRECATED
#define U_ASSERT(c) assert(c)

#include "../u_sstream.h"
#include "../u_sstream.c"

static int test_long(long num)
{
    char buf[256];
    U_SStream ss;

    snprintf(buf, sizeof(buf), "%ld", num);

    U_sstream_init(&ss, buf, strlen(buf));
    if (U_sstream_get_long(&ss) == num)
        return 1;

    printf("failed to parse: %ld, ss.pos: %u, ss.len: %u\n", num, ss.pos, ss.len);
    return 0;
}


int main(void)
{
    const long numbers[] = { LONG_MIN, LONG_MAX, 0, -1, 1, 0 };

    for (unsigned i = 0; i < sizeof(numbers) / sizeof(numbers[0]); i++)
    {
        if (test_long(numbers[i]) == 0)
            return i + 1;
    }

    return 0;
}
