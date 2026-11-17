/* Before any include: the smallest <windows.h> that still declares the console handles */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#include "port_log_win32.h"

#include <windows.h>

#include "log_names.h"

/* The POSIX sink's line, written to the process's standard error handle: a console, a pipe or a file alike. */
void PortLogWin32_Write(void *context, const Log_Record *record)
{
    char line[LOG_NAMES_LINE_MAX];
    DWORD written;

    (void)context;
    (void)WriteFile(GetStdHandle(STD_ERROR_HANDLE), line, (DWORD)LogNames_Line(line, record), &written, 0);
}

void PortLogWin32_Sink(Log_Sink *sink)
{
    if (!sink)
        return;

    sink->context = 0;
    sink->write = PortLogWin32_Write;
}
