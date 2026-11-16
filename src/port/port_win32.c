#include "port_win32.h"

static ZbStatus win32Unsupported(Port *port, const char *path, const PortConfig *config)
{
    (void)path;
    (void)config;
    port->fault = PORT_FAULT_OPEN;
    port->platformErrno = 0;
    return ZB_ERR_UNSUPPORTED;
}

/* Entropy is refused here as the rest of this stub is: this target has no getentropy(2) and a stub does
   not answer with something it has not implemented (docs/internals/coding-rules.md §1). The clock is absent for the
   same reason, so this file defines no Port_NowMs: a stub that answered wall-clock time would hand the stack a
   counter that steps backwards. */
static ZbStatus win32Entropy(Port *port, uint8_t *out, uint32_t len)
{
    (void)port;
    (void)out;
    (void)len;
    return ZB_ERR_UNSUPPORTED;    /* Entropy is refused here as the rest of this stub is: this target has no getentropy(2) and a stub doe */
}

static const PortDeviceOps s_ops = {
    "win32-stub",
    win32Unsupported,
    0,
    0,
    0,
    0,
    win32Entropy,
    0
};

const PortDeviceOps *PortWin32StubOps(void)
{
    return &s_ops;
}
