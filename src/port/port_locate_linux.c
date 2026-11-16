#include "port_locate.h"

/* Linux names a USB serial device's serial number in sysfs, which a container mounts with no udev behind it. */
uint32_t PortLocate_EachPlatform(PortLocate_Visit visit, void *context)
{
    return PortLocate_EachSysfs("", visit, context);
}
