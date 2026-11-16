#include <assert.h>
#include <stdio.h>
#include <string.h>

#define U_SSTREAM_NO_DEPRECATED
#define U_ASSERT(c) assert(c)

#include "../u_sstream.h"
#include "../u_sstream.c"

static int test_find(const char *str, const char *needle)
{
    int result;
    int our_result;
    unsigned len;
    char buf[256];
    U_SStream ss;

    for (len = 0; str[len]; len++)
        buf[len] = str[len];

    buf[len] = '\0';

    U_sstream_init(&ss, buf, len);

    result = strstr(str, needle) == NULL ? 0 : 1;
    our_result = U_sstream_find(&ss, needle);

    printf("find str: '%s', needle: '%s', results: %d (strstr) | %d (sstream), pos: %u\n", str, needle, result, our_result, ss.pos);

    if (our_result == result)
        return 1;

    printf("failed find str: '%s', needle: '%s'\n", str, needle);
    return 0;
}


int main(void)
{
    if (test_find("", "1") == 0)
        return 1;

    if (test_find("0 1234", "123") == 0)
        return 2;

    if (test_find("0 1234", "abcgzsdghgshd") == 0)
        return 3;

    if (test_find("0 1234 abc", "abc") == 0)
        return 4;

    return 0;
}
