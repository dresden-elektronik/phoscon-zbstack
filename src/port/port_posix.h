#ifndef PORT_POSIX_H
#define PORT_POSIX_H

#include <stdint.h>

#include "port.h"

const PortDeviceOps *PortPosixOps(void);

/* Suite helpers: a pseudo-terminal pair, and its master side, so a
   suite exercises the port against a real device node without a platform call of its own. */
ZbStatus PortPosix_PtyOpen(int *masterFd, char *slaveName, uint32_t nameCapacity);
ZbStatus PortPosix_PtyWrite(int masterFd, const uint8_t *bytes, uint32_t len);
void     PortPosix_PtyClose(int masterFd);
ZbStatus PortPosix_PtyRead(int masterFd, uint8_t *buf, uint32_t cap, uint32_t *got);

/* A link at `linkPath` to a terminal's slave name, replacing any link there; 0 for `slaveName` removes it. A suite
   names its RCP by a path that stays while the terminal behind it changes, as a serial-number device name does. */
ZbStatus PortPosix_PtyLink(const char *linkPath, const char *slaveName);

#endif /* PORT_POSIX_H */
