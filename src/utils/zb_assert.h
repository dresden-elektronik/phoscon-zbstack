#ifndef ZB_ASSERT_H
#define ZB_ASSERT_H

/*
 * The invariant macro. A band states an invariant it relies on; ZB_ASSERT(cond, component,
 * argument) checks it, and the check always compiles. On a false condition the macro
 * calls Zb_AssertHandler(component, line, argument) with integers only: component and line
 * from the site, argument what the site passed.
 *
 * The executable that uses the macro links exactly one Zb_AssertHandler, called once per
 * failure and not expected to return. How the host stops then (trap, halt, or
 * log-and-stop) is the glue's call; the portable band never traps on its own.
 *
 * (upstream) the reference u_assert (dresden elektronik's deconz-lib) elides the check in release builds; here it always compiles, a compiled-out check is what an assert exists to catch.
 *
 * (upstream) it traps via a compiler intrinsic under MSVC/GNUC #ifdefs; here the failure flows to the handler the executable links, so it can reach the record stream and a sink, and no platform guard appears outside src/port/.
 */

#include <stdint.h>

/*
 * The handler the executable links. component and line come from the site that failed,
 * argument is what the site passed, 0 when the invariant has no value to name. It is
 * called once per failure and is not expected to return.
 */
void Zb_AssertHandler(uint16_t component, uint16_t line, uint32_t argument);

/* The statement idiom: each argument is evaluated at most once. */
#define ZB_ASSERT(cond, component, argument) \
    do \
    { \
        if (!(cond)) \
        { \
            Zb_AssertHandler((component), (uint16_t)__LINE__, (uint32_t)(argument)); \
        } \
    } while (0)

#endif /* ZB_ASSERT_H */
