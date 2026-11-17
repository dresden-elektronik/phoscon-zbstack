#ifndef LOG_NAMES_H
#define LOG_NAMES_H

/*
 * The host-side name table for the log records (docs/internals/coding-rules.md §5): section, topic
 * and reason ids to the words a human line is built from. The component code is two
 * levels deep (the section in the top byte, the topic in the low byte), so one code names
 * two rows here, the section and the topic within it. It lives in src/port because the
 * core in src/log must stay string-free; a platform sink, a suite or a tool builds a line
 * from it. It takes and returns only integers and static strings (no hosted header, no
 * platform call), so it compiles for every host target unchanged.
 */

#include <stdint.h>

#include "log.h"

/* The longest line LogNames_Line builds, its newline included. */
#define LOG_NAMES_LINE_MAX 96

/* The name of a section (section = component >> 8); "none" for LOG_SECTION_NONE,
   "unknown" for a section the table has no row for (a new section is still a valid
   report, docs/internals/coding-rules.md §5). */
const char *LogNames_SectionName(uint16_t section);

/* The name of the topic within the section a component code carries (topic =
   component & 0xFF); "unknown" for a topic the table has no row for. */
const char *LogNames_TopicName(uint16_t component);

/* The name of a reason code; "none" for LOG_REASON_NONE, "unknown" otherwise for a code
   the table has no row for. */
const char *LogNames_ReasonName(uint32_t reason);

/* The human line of one record, newline-terminated and not NUL-terminated, into `line` of LOG_NAMES_LINE_MAX octets;
   its length. The component is hex, its canonical display, and the rest decimal: every platform sink writes this line,
   so a log reads the same on every host. */
uint32_t LogNames_Line(char *line, const Log_Record *record);

#endif /* LOG_NAMES_H */
