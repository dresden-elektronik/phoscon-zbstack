#include <assert.h>
#include <stdio.h>
#include <string.h>

#define U_SSTREAM_NO_DEPRECATED
#define U_ASSERT(c) assert(c)

#include "../u_sstream.h"
#include "../u_sstream.c"


int main(void)
{
    U_SStream ss;
    int result;

    U_sstream_init(&ss, "xxabcyy", 8);
    result = U_sstream_find(&ss, "abc");
    assert(result == 1);
    printf("find 'abc' in 'xxabcyy': %d (expected 1)\n", result);

    U_sstream_init(&ss, "xxabcyy", 8);
    result = U_sstream_find(&ss, "xyz");
    assert(result == 0);
    printf("find 'xyz' in 'xxabcyy': %d (expected 0)\n", result);

    U_sstream_init(&ss, "xxabcyy", 8);
    result = U_sstream_find(&ss, "");
    assert(result == 0);
    printf("find '' in 'xxabcyy': %d (expected 0)\n", result);

    U_sstream_init(&ss, "xxabcyy", 8);
    result = U_sstream_find(&ss, NULL);
    assert(result == 0);
    printf("find NULL: %d (expected 0)\n", result);

    printf("\nall tests passed\n");
    return 0;
}
