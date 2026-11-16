/* The shared assertion family of the host suites.

   A suite is a name and a ledger, not a file: the ctest names and the case order are the contract, and the
   machinery two suites both need lives once, here. This module carries the assertions and nothing else: no
   rig, no fixture, no clock. No state is shared between suites: the counters are per-process and
   `Test_Begin` resets them, so a suite that begins first owes nothing to the suite that ran before it.

   A failure line keeps the shape the suites printed for themselves before this file existed, so a failing
   run still reads `FAIL: <what>`, `FAIL: <what> (status N, wanted M)`, `FAIL: <what> (got N, wanted M)` or
   `FAIL: <what> (length N, the vector is M)`, and an octet comparison still ends in the `got  `/`want `
   dump. A suite that names the case it is running gets that name between the two; one that names none
   prints exactly what it printed before.

   The suite band runs on the host, so the hosted library is allowed here (docs/internals/coding-rules.md §1): a
   failure line is `printf`, and every octet compared or copied travels through `src/utils` as it does
   everywhere else in the tree. */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <stdint.h>

#include "zb_status.h"

/* The hex vectors the suites compare against are frames: a 127-octet NPDU is the longest this tree holds
   (src/zb/nwk/nwk_frame.h), and `SECURITY_FRAME_MAX` states the same ceiling for a secured one. */
#define TEST_HARNESS_HEX_MAX 160

/* Name the run and reset the counters, printing nothing. */
void Test_Begin(const char *suiteName);

/* Record the case now running, so a failure line names it. Optional: a suite that never calls it prints
   the failure lines it always printed. */
void Test_Case(const char *caseName);

/* The assertions that have failed since `Test_Begin`. */
int Test_Failures(void);

/* 0 when the run is clean, after printing `<suite>: ok`; otherwise `<suite>: <n> failures` and 1. */
int Test_Report(void);

/* `condition` is false: `FAIL: <what>`. */
void Test_Expect(int condition, const char *what);

/* `actual` is not `wanted`: `FAIL: <what> (status N, wanted M)`, the status as its 32-bit value. */
void Test_ExpectStatus(ZbStatus actual, ZbStatus wanted, const char *what);

/* `actual` is not `wanted`: `FAIL: <what> (got N, wanted M)`. */
void Test_ExpectCount(uint32_t actual, uint32_t wanted, const char *what);

/* The two runs differ: the failure line and the pair in the order the caller passes them, what came through
   the shimmed path and what came through the plain one. A move that claims to be passive compares two runs of
   the same capture, and both numbers belong in the line that says they disagreed. */
void Test_ExpectPassive(uint32_t shims, uint32_t plain, const char *what);

/* The two runs differ in length or in any octet: the failure line and both runs beneath it. */
void Test_ExpectOctets(const char *what, const uint8_t *got, uint32_t gotLen,
                       const uint8_t *want, uint32_t wantLen);

/* The same against a vector written as a run of hex, the way the standards print one. A run of the wrong
   length is named as a length before any octet is compared. */
void Test_ExpectHex(const char *what, const uint8_t *got, uint32_t gotLen, const char *wantHex);

/* Decode a run of hex into `out`, the one hex-vector parser in the tree: the number of octets decoded, so a
   case can assert a vector is the length it is quoted as before any of it is compared. */
uint32_t Test_ParseHex(const char *hex, uint8_t *out, uint32_t cap);

/* One run of octets as lowercase hex, for a failure line of a suite's own. */
void Test_PrintOctets(const uint8_t *octets, uint32_t len);

/* Record a failure that is no assertion (a rig that could not answer the case it was asked for) in the
   same `FAIL: <what>` shape, because a red run is a red run either way. It is deliberately not spelled
   `Test_Expect*`: the ledger counts the assertion family, and these sites were never assertions. */
void Test_Fault(const char *what);

#endif /* TEST_HARNESS_H */
