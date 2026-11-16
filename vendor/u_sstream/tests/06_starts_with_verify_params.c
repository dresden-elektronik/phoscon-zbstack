#include <assert.h>
#include <stdio.h>
#include <string.h>

#define U_SSTREAM_NO_DEPRECATED
#define U_ASSERT(c) assert(c)

#include "../u_sstream.h"
#include "../u_sstream.c"


int main(void)
{
    char buf[32] = "abcdef";
    U_SStream ss;
    int result;

    U_sstream_init(&ss, buf, sizeof(buf));
    result = U_sstream_starts_with(&ss, "abc");
    assert(result == 1);
    printf("starts_with 'abc' on 'abcdef': %d (expected 1)\n", result);

    U_sstream_init(&ss, buf, sizeof(buf));
    result = U_sstream_starts_with(&ss, "xyz");
    assert(result == 0);
    printf("starts_with 'xyz' on 'abcdef': %d (expected 0)\n", result);

    U_sstream_init(&ss, buf, sizeof(buf));
    result = U_sstream_starts_with(&ss, "");
    assert(result == 0);
    printf("starts_with '' on 'abcdef': %d (expected 0)\n", result);

    U_sstream_init(&ss, buf, sizeof(buf));
    result = U_sstream_starts_with(&ss, "abcdefgh");
    assert(result == 0);
    printf("starts_with 'abcdefgh' on 'abcdef': %d (expected 0)\n", result);

    U_sstream_init(&ss, buf, sizeof(buf));
    result = U_sstream_starts_with(&ss, NULL);
    assert(result == 0);
    printf("starts_with NULL: %d (expected 0)\n", result);

    printf("\nall tests passed\n");
    return 0;
}
