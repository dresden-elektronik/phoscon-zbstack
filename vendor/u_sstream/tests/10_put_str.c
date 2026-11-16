#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#define U_SSTREAM_NO_DEPRECATED
#define U_ASSERT(c) assert(c)

#include "../u_sstream.h"
#include "../u_sstream.c"

static int test_put_str_basic(void)
{
    char buf[256];
    U_SStream ss;
    U_sstream_init(&ss, buf, sizeof(buf));
    
    U_sstream_put_str(&ss, "test");
    // Verify the string was actually written using strncmp
    if (strncmp(buf, "test", 4) != 0)
        return 0;
    // Verify null termination
    if (buf[4] != '\0')
        return 0;
    return 1;
}

static int test_put_str_empty(void)
{
    char buf[256];
    U_SStream ss;
    U_sstream_init(&ss, buf, sizeof(buf));
    
    U_sstream_put_str(&ss, "");
    // Verify empty string
    if (buf[0] != '\0')
        return 0;
    return 1;
}

static int test_put_str_null(void)
{
    char buf[256];
    U_SStream ss;
    buf[0] = 0;
    U_sstream_init(&ss, buf, sizeof(buf));
    
    U_sstream_put_str(&ss, 0);
    // Should not crash, buffer should remain unchanged
    if (buf[0] != '\0')
        return 0;
    return 1;
}

static int test_put_str_overflow(void)
{
    char buf[10];
    U_SStream ss;
    U_sstream_init(&ss, buf, sizeof(buf));
    
    // Try to write a string that would overflow
    U_sstream_put_str(&ss, "this string is too long");
    
    // Verify status is set to error
    return (ss.status == U_SSTREAM_ERR_NO_SPACE) ? 1 : 0;
}

static int test_put_str_boundary(void)
{
    char buf[10];
    U_SStream ss;
    U_sstream_init(&ss, buf, sizeof(buf));
    
    // Write string that fits exactly (plus null terminator)
    U_sstream_put_str(&ss, "12345678");
    
    // Verify the string was written correctly
    if (strncmp(buf, "12345678", 8) != 0)
        return 0;
    
    // Verify null termination
    if (buf[8] != '\0')
        return 0;
        
    return 1;
}

int main(void)
{
    int tests[] = {
        test_put_str_basic(),
        test_put_str_empty(),
        test_put_str_null(),
        test_put_str_overflow(),
        test_put_str_boundary()
    };
    
    for (unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
    {
        if (tests[i] == 0)
            return i + 1;
    }

    return 0;
}