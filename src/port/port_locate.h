#ifndef PORT_LOCATE_H
#define PORT_LOCATE_H

#include <stdint.h>

#include "port.h"
#include "zb_status.h"

/* A stick named by what it is rather than where the system put it: `usb-serial:<serial>` names the USB device whose
   serial number is <serial>, exactly, and the platform finds the node it has now, at every open (D-282). */
#define PORT_LOCATE_PREFIX "usb-serial:"

enum
{
    PORT_LOCATE_TEXT_MAX = 64       /* a USB string descriptor as read: serial number, product */
};

typedef struct PortLocate_Candidate
{
    char device[PORT_LOCATED_MAX];
    char serial[PORT_LOCATE_TEXT_MAX];
    char product[PORT_LOCATE_TEXT_MAX];
    uint16_t vendorId;
    uint16_t productId;
    int present;                    /* the node exists here; in a container a match can name one never mapped in */
} PortLocate_Candidate;

typedef void (*PortLocate_Visit)(void *context, const PortLocate_Candidate *candidate);

int PortLocate_IsSelector(const char *path);

/* Every serial device with a USB device above it, handed to `visit`; the count. `root` 0 asks the platform (IOKit on
   macOS, /sys and /dev on Linux); a root names a directory holding a sysfs-shaped `sys` and a `dev`, as a suite's is. */
uint32_t PortLocate_Each(const char *root, PortLocate_Visit visit, void *context);

/* The sysfs walk itself (port_locate_sysfs.c), under `root` ("" for the system's own): Linux's platform half, and a
   fixture's on any POSIX host. */
uint32_t PortLocate_EachSysfs(const char *root, PortLocate_Visit visit, void *context);

/* The platform's own enumeration, one per target: IOKit on macOS, the sysfs walk at "" on Linux. */
uint32_t PortLocate_EachPlatform(PortLocate_Visit visit, void *context);

/* The node a selector names now, copied to `device`: NO_DEVICE when nothing matches or the match has no node here,
   BAD_ARGUMENT when two devices carry the serial. `matches` says how many did. */
ZbStatus PortLocate_Resolve(const char *root, const char *selector, char *device, uint32_t capacity,
                            uint32_t *matches);

#endif /* PORT_LOCATE_H */
