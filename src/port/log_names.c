#include "log_names.h"

#include "log.h"

const char *LogNames_SectionName(uint16_t section)
{
    switch (section)
    {
        case LOG_SECTION_NONE:
            return "none";
        case LOG_SECTION_PORT:
            return "port";
        case LOG_SECTION_HDLC:
            return "hdlc";
        case LOG_SECTION_SPINEL:
            return "spinel";
        case LOG_SECTION_RCP:
            return "rcp";
        case LOG_SECTION_LOOPBACK:
            return "loopback";
        case LOG_SECTION_MAC:
            return "mac";
        case LOG_SECTION_NWK:
            return "nwk";
        case LOG_SECTION_APS:
            return "aps";
        case LOG_SECTION_ZDO:
            return "zdo";
        case LOG_SECTION_SECURITY:
            return "security";
        case LOG_SECTION_APP:
            return "app";
    }

    return "unknown";
}

const char *LogNames_TopicName(uint16_t component)
{
    switch (component)
    {
        case LOG_COMP_PORT_CORE:
            return "core";
        case LOG_COMP_PORT_POSIX:
            return "posix";
        case LOG_COMP_PORT_NULL:
            return "null";
        case LOG_COMP_PORT_WIN32:
            return "win32";
        case LOG_COMP_PORT_LOG:
            return "log";
        case LOG_COMP_HDLC:
            return "hdlc";
        case LOG_COMP_SPINEL_CODEC:
            return "codec";
        case LOG_COMP_SPINEL_SESSION:
            return "session";
        case LOG_COMP_RCP_RADIO:
            return "radio";
        case LOG_COMP_RCP_PROPS:
            return "props";
        case LOG_COMP_LOOPBACK:
            return "loopback";
        case LOG_COMP_MAC_FRAME:
            return "mac_frame";
        case LOG_COMP_MAC:
            return "mac";
        case LOG_COMP_MAC_RX:
            return "mac_rx";
        case LOG_COMP_NWK:
            return "nwk";
        case LOG_COMP_APS:
            return "aps";
        case LOG_COMP_ZDO:
            return "zdo";
        case LOG_COMP_SECURITY:
            return "security";
        case LOG_COMP_SECURITY_PROTECT_REFUSED:
            return "protect_refused";
        case LOG_COMP_SECURITY_UNPROTECT_FAILED:
            return "unprotect_failed";
        case LOG_COMP_SECURITY_KEY_ADOPTED:
            return "key_adopted";
        case LOG_COMP_SECURITY_INCOMING_FULL:
            return "incoming_full";
        case LOG_COMP_SECURITY_FRAME_TOO_LONG:
            return "frame_too_long";
        case LOG_COMP_APP:
            return "app";
    }

    return "unknown";
}

const char *LogNames_ReasonName(uint32_t reason)
{
    switch (reason)
    {
        case LOG_REASON_NONE:
            return "none";
        case LOG_REASON_ERROR:
            return "error";
        case LOG_REASON_TIMEOUT:
            return "timeout";
        case LOG_REASON_DROPPED:
            return "dropped";
        case LOG_REASON_STATE:
            return "state";
        case LOG_REASON_RESET:
            return "reset";
        case LOG_REASON_CONFIG:
            return "config";
        case LOG_REASON_ASSERT:
            return "assert";
        case LOG_REASON_FCS:
            return "fcs";
        case LOG_REASON_REFUSED:
            return "refused";
    }

    return "unknown";
}

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

uint32_t LogNames_Line(char *line, const Log_Record *record)
{
    char *at = line;

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

    return (uint32_t)(at - line);
}
