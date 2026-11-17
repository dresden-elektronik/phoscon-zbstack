#ifndef PORT_LOG_WIN32_H
#define PORT_LOG_WIN32_H

/*
 * The Windows platform sink for the log records (docs/internals/coding-rules.md §5): one line per record, on the
 * process's standard error, built from the host-side name table as the POSIX sink's is.
 */

#include "log.h"

/* The sink's write function, for a Log_Sink whose context is 0. */
void PortLogWin32_Write(void *context, const Log_Record *record);

/* Fills a Log_Sink for this platform. */
void PortLogWin32_Sink(Log_Sink *sink);

#endif /* PORT_LOG_WIN32_H */
