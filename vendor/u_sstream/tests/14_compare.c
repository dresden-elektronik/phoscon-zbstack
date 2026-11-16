#include <assert.h>
#include <stdio.h>
#include <string.h>

#define U_SSTREAM_NO_DEPRECATED
#define U_ASSERT(c) assert(c)

#include "../u_sstream.h"
#include "../u_sstream.c"


int main(void)
{
    char buf[32];
    U_SStream ss;
    int result;

    /* Test equal strings */
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_str(&ss, "abcdef");
    result = U_sstream_compare(&ss, "abcdef");
    assert(result == 0);
    printf("compare 'abcdef' vs 'abcdef': %d (expected 0)\n", result);

    /* Test stream less than str */
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_str(&ss, "abcdef");
    result = U_sstream_compare(&ss, "abcdez");
    assert(result < 0);
    printf("compare 'abcdef' vs 'abcdez': %d (expected <0)\n", result);

    /* Test stream greater than str */
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_str(&ss, "abcdef");
    result = U_sstream_compare(&ss, "abcde");
    assert(result > 0);
    printf("compare 'abcdef' vs 'abcde': %d (expected >0)\n", result);

    /* Test prefix - stream is prefix of str */
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_str(&ss, "abcdef");
    result = U_sstream_compare(&ss, "abcdefgh");
    assert(result < 0);
    printf("compare 'abcdef' vs 'abcdefgh': %d (expected <0)\n", result);

    /* Test prefix - str is prefix of stream */
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_str(&ss, "abcdef");
    result = U_sstream_compare(&ss, "abc");
    assert(result > 0);
    printf("compare 'abcdef' vs 'abc': %d (expected >0)\n", result);

    /* Test NULL str */
    U_sstream_init(&ss, buf, sizeof(buf));
    U_sstream_put_str(&ss, "abcdef");
    result = U_sstream_compare(&ss, NULL);
    assert(result == 0);
    printf("compare 'abcdef' vs NULL: %d (expected 0)\n", result);

    printf("\nall tests passed\n");
    return 0;
}
