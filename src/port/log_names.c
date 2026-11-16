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
