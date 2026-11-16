#ifndef PORT_WIN32_H
#define PORT_WIN32_H

#include "port.h"

/* Stub target: no Windows host has been measured (docs/porting.md §3). Every
   call answers ZB_ERR_UNSUPPORTED and no conformance gate counts it as passing. */
const PortDeviceOps *PortWin32StubOps(void);

#endif /* PORT_WIN32_H */
