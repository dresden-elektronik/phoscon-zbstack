/* The annotated fixture reader of the host suites (docs/internals/testing.md §4).

   A capture in `test/fixtures/` is two kinds of line: an indented run of hex octets, which is a PSDU as it
   was on the air, and everything else, which is a decoder's annotation written at capture time. Reading a
   fixture means reading the first kind and *ignoring* the second: a loader that took hex out of an
   annotation would invent frames out of a decoder's remarks. `Test_FixturePsdu` is that reading for one
   line, and `Test_FixtureLoad` is the file's worth of it, into a caller-owned table of fixed-width rows.

   `test_fixture.h`'s `fixtureReadHex` is a different reader for a different shape of file: it takes a
   fixture that *is* hex, whitespace and comments, and it has no notion of a line that is prose. Both are
   suite-band; neither asserts anything, so a suite says what it expected of the file it read. */

#ifndef FIXTURES_FRAMES_H
#define FIXTURES_FRAMES_H

#include <stdint.h>

#include "zb_status.h"

/* Longer than any PSDU line either capture carries (127 octets, three characters each, plus the indent), so
   a line is never split by the reader. */
#define TEST_FIXTURE_LINE_MAX 512

/* harness/check_samples.py's PSDU_LINE: the raw octets are indented eight blanks or more, and an annotation
   never is. */
#define TEST_FIXTURE_INDENT_MIN 8

/* One line of an annotated capture as the PSDU it carries: at least `TEST_FIXTURE_INDENT_MIN` leading
   blanks, two lowercase hex digits per octet separated by one space, then nothing but blanks to the end of
   the line. Any other line is an annotation and answers 0: as does a line whose octets do not fit `cap`. */
uint32_t Test_FixturePsdu(const char *line, uint8_t *out, uint32_t cap);

/* Every PSDU in `path`, into a caller-owned table of `cap` rows: row `n` lands at `bytes + n * stride`, its
   length in `lengths[n]`, and the number of rows read in `*countOut`. `wanted` is the count the caller pins,
   which is what makes an inventory of a capture an assertion instead of a hope.

   The status is about the read: ZB_ERR_NOT_OPEN when the file cannot be read, ZB_ERR_NO_SPACE when a PSDU
   arrives with the table full, ZB_ERR_BAD_FRAME when the file did not hold `wanted` frames, ZB_OK otherwise. */
ZbStatus Test_FixtureLoad(const char *path, uint8_t *bytes, uint32_t *lengths, uint32_t cap,
                          uint32_t stride, uint32_t wanted, uint32_t *countOut);

#endif /* FIXTURES_FRAMES_H */
