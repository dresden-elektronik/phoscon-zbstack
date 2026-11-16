#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#define U_SSTREAM_NO_DEPRECATED
#define U_ASSERT(c) assert(c)

#include "../u_sstream.h"
#include "../u_sstream.c"

static int test_strtol_basic_overflow(void)
{
    char buf[256];
    const char *endp;
    int err;
    long result;
    
#if __SIZEOF_LONG__ == 8
    // 64-bit system - test with 64-bit overflow values
    // Test case 1: Input that should overflow (LONG_MAX + 1)
    snprintf(buf, sizeof(buf), "9223372036854775808"); // LONG_MAX + 1
#else
    // 32-bit system - test with 32-bit overflow values
    // On 32-bit systems LONG_MAX is 2147483647
    snprintf(buf, sizeof(buf), "2147483648"); // 32-bit LONG_MAX + 1
#endif
    result = U_strtol(buf, strlen(buf), &endp, &err);
    
    // Should detect overflow and return 0
    if (result != 0 || !(err & 2))
        return 0;
        
    return 1;
}

static int test_strtol_boundary_overflow(void)
{
    char buf[256];
    const char *endp;
    int err;
    long result;
    
#if __SIZEOF_LONG__ == 8
    // 64-bit system - test with 64-bit boundary value
    snprintf(buf, sizeof(buf), "9223372036854775807"); // LONG_MAX
#else
    // 32-bit system - test with 32-bit boundary value
    snprintf(buf, sizeof(buf), "2147483647"); // 32-bit LONG_MAX
#endif
    result = U_strtol(buf, strlen(buf), &endp, &err);
    
    // Should succeed and return LONG_MAX
    if (result != LONG_MAX || err != 0)
        return 0;
        
    return 1;
}

static int test_strtol_negative_overflow(void)
{
    char buf[256];
    const char *endp;
    int err;
    long result;
    
#if __SIZEOF_LONG__ == 8
    // 64-bit system - test with 64-bit negative overflow values
    // Test case 3: Negative overflow case
    snprintf(buf, sizeof(buf), "-9223372036854775809"); // LONG_MIN - 1
#else
    // 32-bit system - test with 32-bit negative overflow values
    // On 32-bit systems LONG_MIN is -2147483648
    snprintf(buf, sizeof(buf), "-2147483649"); // 32-bit LONG_MIN - 1
#endif
    result = U_strtol(buf, strlen(buf), &endp, &err);
    
    // Should detect overflow and return 0
    if (result != 0 || !(err & 2))
        return 0;
        
    return 1;
}

static int test_strtol_overflow_with_whitespace(void)
{
    char buf[256];
    const char *endp;
    int err;
    long result;
    
#if __SIZEOF_LONG__ == 8
    // 64-bit system - test with 64-bit overflow values
    snprintf(buf, sizeof(buf), "  9223372036854775808  ");
#else
    // 32-bit system - test with 32-bit overflow values
    snprintf(buf, sizeof(buf), "  2147483648  ");
#endif
    result = U_strtol(buf, strlen(buf), &endp, &err);
    
    // Should detect overflow and return 0
    if (result != 0 || !(err & 2))
        return 0;
        
    return 1;
}

static int test_strtol_overflow_with_digits(void)
{
    char buf[256];
    const char *endp;
    int err;
    long result;
    
#if __SIZEOF_LONG__ == 8
    // 64-bit system - test with 64-bit overflow values
    snprintf(buf, sizeof(buf), "922337203685477580712345"); // LONG_MAX + large number
#else
    // 32-bit system - test with 32-bit overflow values
    snprintf(buf, sizeof(buf), "214748364712345"); // 32-bit LONG_MAX + large number
#endif
    result = U_strtol(buf, strlen(buf), &endp, &err);
    
    // Should detect overflow and return 0
    if (result != 0 || !(err & 2))
        return 0;
        
    return 1;
}

int main(void)
{
    int tests[] = {
        test_strtol_basic_overflow(),
        test_strtol_boundary_overflow(),
        test_strtol_negative_overflow(),
        test_strtol_overflow_with_whitespace(),
        test_strtol_overflow_with_digits()
    };
    
    for (unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
    {
        if (tests[i] == 0)
            return i + 1;
    }

    return 0;
}