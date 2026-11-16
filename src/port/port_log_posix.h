#ifndef PORT_LOG_POSIX_H
#define PORT_LOG_POSIX_H

/*
 * The POSIX platform sink for the log records (docs/internals/coding-rules.md §5): one line per
 * record, on the process's standard error, built from the host-side name table. It is the
 * host-side half of logging: the only place in the path from a record to a line where a
 * string is built. The record itself, from the call site to this door, is four integers.
 */

#include "log.h"

/* The sink's write function, for a Log_Sink whose context is 0. */
void PortLogPosix_Write(void *context, const Log_Record *record);

/* Fills a Log_Sink for this platform. */
void PortLogPosix_Sink(Log_Sink *sink);

#endif /* PORT_LOG_POSIX_H */
