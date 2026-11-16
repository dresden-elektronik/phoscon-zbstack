/* The annotated fixture reader of the host suites (docs/internals/testing.md §4).
   See fixtures_frames.h for the contract. */

#include "fixtures_frames.h"

#include <stdio.h>

#include "zb_utils.h"

static int fixtureNibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    return -1;
}

uint32_t Test_FixturePsdu(const char *line, uint8_t *out, uint32_t cap)
{
    uint32_t i;
    uint32_t count;
    uint32_t indent;
    int high;
    int low;

    i = 0;
    count = 0;
    indent = 0;

    while (line[i] == ' ' || line[i] == '\t')
    {
        i++;
        indent++;
    }

    if (indent < TEST_FIXTURE_INDENT_MIN)
        return 0;

    for (;;)
    {
        high = fixtureNibble(line[i]);

        if (high < 0)
            return 0;

        low = fixtureNibble(line[i + 1]);

        if (low < 0)
            return 0;

        i = i + 2;

        if (count < cap)
            out[count] = (uint8_t)((high << 4) | low);

        count++;

        if (line[i] != ' ')
        {
            while (line[i] == ' ' || line[i] == '\t' || line[i] == '\r')
                i++;

            if (line[i] != 0 && line[i] != '\n')
                return 0;

            break;
        }

        i++;

        if (line[i] == 0 || line[i] == '\n' || line[i] == '\r')
            break;
    }

    if (count == 0 || count > cap)
        return 0;

    return count;
}

ZbStatus Test_FixtureLoad(const char *path, uint8_t *bytes, uint32_t *lengths, uint32_t cap,
                          uint32_t stride, uint32_t wanted, uint32_t *countOut)
{
    FILE *file;
    char line[TEST_FIXTURE_LINE_MAX];
    uint8_t scratch[TEST_FIXTURE_LINE_MAX / 2];   /* a line of this length holds fewer octets than this */
    uint32_t count;
    uint32_t len;

    count = 0;
    *countOut = 0;

    file = fopen(path, "rb");

    if (!file)
        return ZB_ERR_NOT_OPEN;

    while (fgets(line, (int)sizeof line, file) != 0)
    {
        if (count == cap)
        {
            /* A frame where the table is full is the caller's pool refusing, and it is not read into it:
               one annotation after the last frame is not a frame. */
            if (Test_FixturePsdu(line, scratch, (uint32_t)sizeof scratch) == 0)
                continue;

            fclose(file);
            *countOut = count;

            return ZB_ERR_NO_SPACE;
        }

        len = Test_FixturePsdu(line, bytes + count * stride, stride);

        if (len == 0)
            continue;

        /* A row is `stride` octets of the caller's table: the octets past this PSDU's own are zero, so a
           shorter frame after a longer one never carries a tail nobody read. */
        Zb_memset(bytes + count * stride + len, 0, stride - len);
        lengths[count] = len;
        count++;
    }

    fclose(file);
    *countOut = count;

    if (count != wanted)
        return ZB_ERR_BAD_FRAME;

    return ZB_OK;
}
