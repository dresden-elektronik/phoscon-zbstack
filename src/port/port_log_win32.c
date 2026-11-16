#include "port_log_win32.h"

void PortLogWin32_Write(void *context, const Log_Record *record)
{
    (void)context;
    (void)record;
}

void PortLogWin32_Sink(Log_Sink *sink)
{
    if (!sink)
        return;

    sink->context = 0;
    sink->write = PortLogWin32_Write;
}
