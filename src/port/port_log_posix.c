#include "port_log_posix.h"

#include <stdint.h>
#include <unistd.h>

#include "log_names.h"

void PortLogPosix_Write(void *context, const Log_Record *record)
{
    char line[LOG_NAMES_LINE_MAX];

    (void)context;
    (void)write(STDERR_FILENO, line, LogNames_Line(line, record));
}

void PortLogPosix_Sink(Log_Sink *sink)
{
    if (!sink)
        return;

    sink->context = 0;
    sink->write = PortLogPosix_Write;
}
