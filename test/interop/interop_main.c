/* The `interop` suite's entry point: a suite is a name and a ledger, not a
   file, so this file names the run, reads the two
   fixtures the phases replay and drives the four phases in the one order `test/suite_ledger.json` records.
   What each of them proves lives in the phase file beside it (`phase_a.c`, `phase_b.c`, `phase_c.c`,
   `phase_d.c`) and the machinery they share in `interop_helpers.c`. Nothing here asserts anything: what the
   phases prove, they assert. */

#include "interop_cases.h"
#include "interop_helpers.h"
#include "test_harness.h"

int main(void)
{
    Test_Begin("interop");

    loadCapture(PRIMARY_PATH, &s_primary, PRIMARY_LINES,
                "the primary fixture carries the 135 PSDU lines the capture counts");
    loadCapture(SECONDARY_PATH, &s_secondary, SECONDARY_LINES,
                "the secondary fixture carries the 55 PSDU lines the capture counts");

    phaseA();
    phaseB();
    phaseC();
    phaseD();

    return Test_Report();
}
