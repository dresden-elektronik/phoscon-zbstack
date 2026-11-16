/*
 * log_probe, runs the log substrate end to end on this host: a few integer reports go
 * through the portable pool, one of them overfills it so the stated full policy shows, and
 * the platform sink (src/port) is what turns the records into lines on standard error.
 * Nothing between the reports and the sink is a string (docs/internals/coding-rules.md §5); the
 * summary on standard out is this tool's own, and tools may print.
 */

#include <stdio.h>

#include "log.h"
#include "port_log_posix.h"

int main(void)
{
    Log_Log log;
    Log_Sink sink;
    uint32_t i;
    uint32_t toFill;
    ZbStatus status;

    Log_Init(&log);
    PortLogPosix_Sink(&sink);

    Log_Report(&log, LOG_COMP_PORT_CORE, __LINE__, LOG_REASON_CONFIG, 0x03);
    Log_Report(&log, LOG_COMP_SPINEL_SESSION, __LINE__, LOG_REASON_STATE, 2);
    Log_Report(&log, LOG_COMP_RCP_RADIO, __LINE__, LOG_REASON_ERROR, ZB_ERR_TIMEOUT);
    Log_Report(&log, LOG_COMP_MAC, __LINE__, LOG_REASON_DROPPED, 1);

    /* Fill the pool and overfill it by one, so the refusal and its count are part of the
       demonstration rather than an assumption. */
    toFill = LOG_RING_MAX - Log_Count(&log) + 1;

    for (i = 0; i < toFill; i++)
    {
        status = Log_Report(&log, LOG_COMP_LOOPBACK, __LINE__, LOG_REASON_STATE, i);

        if (status != ZB_OK)
            break;
    }

    Log_Drain(&log, &sink);

    printf("log_probe: reported %u, drained %u, refused %u, waiting %u\n",
           Log_Drained(&log) + Log_Refused(&log), Log_Drained(&log), Log_Refused(&log),
           Log_Count(&log));
    return 0;
}
