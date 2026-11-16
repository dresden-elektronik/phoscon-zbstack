#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#define U_SSTREAM_NO_DEPRECATED
#define U_ASSERT(c) assert(c)

#include "../u_sstream.h"
#include "../u_sstream.c"

static int test_put_hex_basic(void)
{
    char buf[256];
    U_SStream ss;
    U_sstream_init(&ss, buf, sizeof(buf));
    
    unsigned char data = 0xAB;
    U_sstream_put_hex(&ss, &data, 1);
    
    if (strncmp(buf, "AB", 2) != 0)
        return 0;
    if (buf[2] != '\0')
        return 0;
    return 1;
}

static int test_put_hex_multiple(void)
{
    char buf[256];
    U_SStream ss;
    U_sstream_init(&ss, buf, sizeof(buf));
    
    unsigned char data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    U_sstream_put_hex(&ss, data, 4);
    
    if (strncmp(buf, "DEADBEEF", 8) != 0)
        return 0;
    if (buf[8] != '\0')
        return 0;
    return 1;
}

static int test_put_hex_empty(void)
{
    char buf[256];
    U_SStream ss;
    U_sstream_init(&ss, buf, sizeof(buf));
    
    U_sstream_put_hex(&ss, "", 0);
    
    if (buf[0] != '\0')
        return 0;
    return 1;
}

static int test_put_hex_overflow(void)
{
    char buf[5];
    U_SStream ss;
    U_sstream_init(&ss, buf, sizeof(buf));
    
    unsigned char data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    U_sstream_put_hex(&ss, data, 4);
    
    return (ss.status == U_SSTREAM_ERR_NO_SPACE) ? 1 : 0;
}

static int test_put_hex_boundary(void)
{
    char buf[9];
    U_SStream ss;
    U_sstream_init(&ss, buf, sizeof(buf));
    
    unsigned char data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    U_sstream_put_hex(&ss, data, 4);
    
    if (strncmp(buf, "DEADBEEF", 8) != 0)
        return 0;
    if (buf[8] != '\0')
        return 0;
    return 1;
}

static int test_put_hex_edges(void)
{
    char buf[256];
    U_SStream ss;
    int passed = 1;
    
    U_sstream_init(&ss, buf, sizeof(buf));
    unsigned char zero = 0x00;
    U_sstream_put_hex(&ss, &zero, 1);
    if (strncmp(buf, "00", 2) != 0 || buf[2] != '\0')
        passed = 0;
    
    U_sstream_init(&ss, buf, sizeof(buf));
    unsigned char ff = 0xFF;
    U_sstream_put_hex(&ss, &ff, 1);
    if (strncmp(buf, "FF", 2) != 0 || buf[2] != '\0')
        passed = 0;
    
    U_sstream_init(&ss, buf, sizeof(buf));
    unsigned char of = 0x0F;
    U_sstream_put_hex(&ss, &of, 1);
    if (strncmp(buf, "0F", 2) != 0 || buf[2] != '\0')
        passed = 0;
    
    U_sstream_init(&ss, buf, sizeof(buf));
    unsigned char fo = 0xF0;
    U_sstream_put_hex(&ss, &fo, 1);
    if (strncmp(buf, "F0", 2) != 0 || buf[2] != '\0')
        passed = 0;
    
    return passed;
}

int main(void)
{
    int tests[] = {
        test_put_hex_basic(),
        test_put_hex_multiple(),
        test_put_hex_empty(),
        test_put_hex_overflow(),
        test_put_hex_boundary(),
        test_put_hex_edges()
    };
    
    for (unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
    {
        if (tests[i] == 0)
            return i + 1;
    }

    return 0;
}
