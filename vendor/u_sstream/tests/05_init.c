#include <assert.h>
#include <stdio.h>
#include <string.h>

#define U_SSTREAM_NO_DEPRECATED
#define U_ASSERT(c) assert(c)

#include "../u_sstream.h"
#include "../u_sstream.c"


int main(void)
{
    char buf[16] = "test";
    U_SStream ss;

    U_sstream_init(&ss, buf, sizeof(buf));
    assert(ss.status == U_SSTREAM_OK);
    printf("valid ptr + valid size: OK\n");

    U_sstream_init(&ss, buf, 0);
    assert(ss.status == U_SSTREAM_ERR_INVALID);
    printf("valid ptr + size 0: ERR_INVALID\n");

    U_sstream_init(&ss, NULL, sizeof(buf));
    assert(ss.status == U_SSTREAM_ERR_INVALID);
    printf("NULL ptr + valid size: ERR_INVALID\n");

    U_sstream_init(&ss, NULL, 0);
    assert(ss.status == U_SSTREAM_ERR_INVALID);
    printf("NULL ptr + size 0: ERR_INVALID\n");

    printf("all init tests passed\n");
    return 0;
}
