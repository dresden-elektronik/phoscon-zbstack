/* The shared assertion family of the host suites:
   the counters, the failure lines and the one hex-vector parser. See test_harness.h for the contract. */

#include <stdio.h>

#include "test_harness.h"
#include "zb_utils.h"

static const char *s_suiteName = "";
static const char *s_caseName;
static int s_failures;

/* The head of every failure line: `FAIL: <what>` for a suite that names no case, `FAIL: <case>: <what>` for
   one that does. What follows the head is the printer's own tail: a status, a count, a length, a dump. */
static void testFailureHead(const char *what)
{
    if (s_caseName)
    {
        printf("FAIL: %s: %s", s_caseName, what);
        return;
    }

    printf("FAIL: %s", what);
}

void Test_Begin(const char *suiteName)
{
    s_suiteName = suiteName;
    s_caseName = 0;
    s_failures = 0;
}

void Test_Case(const char *caseName)
{
    s_caseName = caseName;
}

int Test_Failures(void)
{
    return s_failures;
}

int Test_Report(void)
{
    if (s_failures != 0)
    {
        printf("%s: %d failures\n", s_suiteName, s_failures);
        return 1;
    }

    printf("%s: ok\n", s_suiteName);

    return 0;
}

void Test_Fault(const char *what)
{
    testFailureHead(what);
    printf("\n");
    s_failures++;
}

void Test_Expect(int condition, const char *what)
{
    if (condition)
        return;

    Test_Fault(what);
}

void Test_ExpectStatus(ZbStatus actual, ZbStatus wanted, const char *what)
{
    if (actual == wanted)
        return;

    testFailureHead(what);
    printf(" (status %u, wanted %u)\n", (uint32_t)actual, (uint32_t)wanted);
    s_failures++;
}

void Test_ExpectCount(uint32_t actual, uint32_t wanted, const char *what)
{
    if (actual == wanted)
        return;

    testFailureHead(what);
    printf(" (got %u, wanted %u)\n", actual, wanted);
    s_failures++;
}

void Test_ExpectPassive(uint32_t shims, uint32_t plain, const char *what)
{
    if (shims == plain)
        return;

    testFailureHead(what);
    printf(" (%u through the deny-tx shim, %u without it)\n", shims, plain);
    s_failures++;
}

void Test_PrintOctets(const uint8_t *octets, uint32_t len)
{
    uint32_t index;

    for (index = 0; index < len; index++)
        printf("%02x", octets[index]);
}

void Test_ExpectOctets(const char *what, const uint8_t *got, uint32_t gotLen,
                       const uint8_t *want, uint32_t wantLen)
{
    if (gotLen == wantLen && (gotLen == 0 || Zb_memcmp(got, want, gotLen) == 0))
        return;

    testFailureHead(what);
    printf("\n  got  ");
    Test_PrintOctets(got, gotLen);
    printf("\n  want ");
    Test_PrintOctets(want, wantLen);
    printf("\n");
    s_failures++;
}

uint32_t Test_ParseHex(const char *hex, uint8_t *out, uint32_t cap)
{
    uint32_t octet;
    uint32_t digit;
    uint8_t nibble;
    uint8_t value;

    for (octet = 0; octet < cap && hex[2 * octet] != 0; octet++)
    {
        value = 0;

        for (digit = 0; digit < 2; digit++)
        {
            nibble = 0;

            if (hex[2 * octet + digit] >= '0' && hex[2 * octet + digit] <= '9')
                nibble = (uint8_t)(hex[2 * octet + digit] - '0');

            if (hex[2 * octet + digit] >= 'a' && hex[2 * octet + digit] <= 'f')
                nibble = (uint8_t)(hex[2 * octet + digit] - 'a' + 10);

            value = (uint8_t)((value << 4) | nibble);
        }

        out[octet] = value;
    }

    return octet;
}

void Test_ExpectHex(const char *what, const uint8_t *got, uint32_t gotLen, const char *wantHex)
{
    uint8_t want[TEST_HARNESS_HEX_MAX];
    uint32_t wantLen;

    wantLen = Test_ParseHex(wantHex, want, (uint32_t)sizeof want);

    if (gotLen != wantLen)
    {
        testFailureHead(what);
        printf(" (length %u, the vector is %u)\n", gotLen, wantLen);
        s_failures++;
        return;
    }

    Test_ExpectOctets(what, got, gotLen, want, wantLen);
}
