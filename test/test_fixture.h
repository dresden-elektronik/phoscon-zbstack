/* Host-side helpers for suites: reading a fixture is not stack code. */
#ifndef TEST_FIXTURE_H
#define TEST_FIXTURE_H

#include <stdint.h>

/* Parses whitespace-separated hex bytes, ignoring lines beginning with '#' or ';'.
   Returns the number of bytes stored, or 0 when the file is unreadable. */
uint32_t fixtureReadHex(const char *path, uint8_t *buf, uint32_t cap);

#endif /* TEST_FIXTURE_H */
