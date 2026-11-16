#include "test_fixture.h"

#include <stdio.h>
#include <string.h>

static int hexDigit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    return -1;
}

uint32_t fixtureReadHex(const char *path, uint8_t *buf, uint32_t cap)
{
    FILE *file;
    uint32_t count;
    int high;
    int c;

    count = 0;
    high = -1;
    file = fopen(path, "rb");

    if (!file)
        return 0;

    c = fgetc(file);

    while (c != EOF)
    {
        if (c == '\n' || c == '\r')
        {
            high = -1;
            c = fgetc(file);
            continue;
        }

        if (high < 0 && (c == '#' || c == ';'))
        {
            while (c != EOF && c != '\n')
                c = fgetc(file);

            continue;
        }

        if (c == ' ' || c == '\t' || c == ',' || c == ':')
        {
            c = fgetc(file);
            continue;
        }

        {
            int digit = hexDigit((char)c);

            if (digit < 0)
            {
                c = fgetc(file);
                continue;
            }

            if (high < 0)
            {
                high = digit;
            }
            else
            {
                if (count < cap)
                    buf[count++] = (uint8_t)((high << 4) | digit);

                high = -1;
            }
        }

        c = fgetc(file);
    }

    fclose(file);
    return count;
}
