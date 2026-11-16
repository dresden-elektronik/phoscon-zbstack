#ifndef PORT_LOG_WIN32_H
#define PORT_LOG_WIN32_H

/*
 * The Win32 platform sink for the log records (docs/internals/coding-rules.md §5). Stub on this
 * bench, as the port's own Win32 backend is: no Windows host is attached (docs/porting.md
 * §10.3), so the sink that a Windows target links must be written against a real console,
 * the win32 API (OutputDebugString for the debugger, the console for the terminal) is
 * where that output goes, and the line is built from the same host-side name table as the
 * POSIX sink. Until a Windows host lands, this sink discards the record and the absence
 * is stated, not faked.
 */

#include "log.h"

/* The sink's write function; a no-op until a Windows host is measured (see above). */
void PortLogWin32_Write(void *context, const Log_Record *record);

/* Fills a Log_Sink for this platform. */
void PortLogWin32_Sink(Log_Sink *sink);

#endif /* PORT_LOG_WIN32_H */
