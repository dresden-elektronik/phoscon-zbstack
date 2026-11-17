#ifndef PORT_WIN32_H
#define PORT_WIN32_H

#include "port.h"

/* Windows: a COM port through CreateFile, a DCB and COMMTIMEOUTS, CNG's generator for entropy and the performance
   counter for Port_NowMs (docs/porting.md §3). */
const PortDeviceOps *PortWin32Ops(void);

#endif /* PORT_WIN32_H */
