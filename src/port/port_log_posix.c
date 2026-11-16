#include "port_log_posix.h"

#include <stdint.h>
#include <unistd.h>

#include "log_names.h"
#include "zb_utils.h"

/* The port band may not include a byte/text header (docs/internals/coding-rules.md §1), so the sink
   turns the four integers of a record into ASCII itself and hands the line to write(2).
   The component is hex (its canonical display) and the rest decimal; a line is short enough
   to build in one bounded buffer. */

#define SINK_LINE_MAX 96

static uint32_t sinkPutDec(char *at, uint32_t value)
{
    char tmp[10];
    uint32_t n = 0;
    uint32_t i;

    if (value == 0)
    {
        *at = '0';
        return 1;
    }

    while (value != 0)
    {
        tmp[n] = (char)('0' + (value % 10));
        value /= 10;
        n++;
    }

    for (i = 0; i < n; i++)
        *at++ = tmp[n - 1 - i];

    return n;
}

static uint32_t sinkPutHex4(char *at, uint16_t value)
{
    static const char nibbles[] = "0123456789ABCDEF";
    uint32_t i;

    for (i = 0; i < 4; i++)
        *at++ = nibbles[(value >> (12 - 4 * i)) & 0x0F];

    return 4;
}

static void sinkPutLit(char **at, const char *text)
{
    uint32_t i = 0;

    while (text[i] != '\0')
    {
        **at = text[i];
        (*at)++;
        i++;
    }
}

void PortLogPosix_Write(void *context, const Log_Record *record)
{
    char line[SINK_LINE_MAX];
    char *at = line;
    char *end;
    uint32_t written;

    (void)context;

    sinkPutLit(&at, "LOG ");
    sinkPutLit(&at, "0x");
    at += sinkPutHex4(at, record->component);
    sinkPutLit(&at, " ");
    sinkPutLit(&at, LogNames_SectionName(record->component >> 8));
    sinkPutLit(&at, "/");
    sinkPutLit(&at, LogNames_TopicName(record->component));
    sinkPutLit(&at, " ");
    sinkPutLit(&at, LogNames_ReasonName(record->reason));
    sinkPutLit(&at, " line=");
    at += sinkPutDec(at, record->line);
    sinkPutLit(&at, " arg=");
    at += sinkPutDec(at, record->argument);
    sinkPutLit(&at, "\n");
    end = at;

    written = (uint32_t)(end - line);
    (void)write(STDERR_FILENO, line, written);
}

void PortLogPosix_Sink(Log_Sink *sink)
{
    if (!sink)
        return;

    sink->context = 0;
    sink->write = PortLogPosix_Write;
}
