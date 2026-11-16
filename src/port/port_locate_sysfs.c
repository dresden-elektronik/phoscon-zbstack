#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1          /* realpath(3) and the dirent calls, which glibc hides under -std=c99 */
#endif

#include "port_locate.h"
#include "zb_utils.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

/* Linux's sysfs layout, walked with POSIX calls only: built on every POSIX host, so the port_locate suite reads its
   fixture tree on macOS as well, and the Linux build hands it the system's own root. */

#define SYSFS_PATH_MAX PATH_MAX

/* `a`, `b` and `c` end to end in `out`; 0 when that does not fit. */
static int sysfsJoin(char *out, uint32_t capacity, const char *a, const char *b, const char *c)
{
    const char *parts[3];
    uint32_t used = 0;
    uint32_t len;
    uint32_t i;

    parts[0] = a;
    parts[1] = b;
    parts[2] = c;

    for (i = 0; i < 3; i++)
    {
        len = Zb_strlen(parts[i], capacity);

        if (used + len + 1 > capacity)
            return 0;

        Zb_memcpy(out + used, parts[i], len);
        used += len;
    }

    out[used] = 0;
    return 1;
}

/* One attribute of a sysfs device, its trailing newline cut; 0 when the file is not there. */
static int sysfsRead(const char *dir, const char *name, char *out, uint32_t capacity)
{
    char path[SYSFS_PATH_MAX];
    ssize_t got;
    uint32_t len;
    int fd;

    out[0] = 0;

    if (!sysfsJoin(path, (uint32_t)sizeof path, dir, "/", name))
        return 0;

    fd = open(path, O_RDONLY);

    if (fd < 0)
        return 0;

    got = read(fd, out, (size_t)(capacity - 1));
    close(fd);
    len = got > 0 ? (uint32_t)got : 0;
    out[len] = 0;

    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r'))
        out[--len] = 0;

    return 1;
}

static uint16_t sysfsHex16(const char *text)
{
    uint32_t value = 0;
    uint32_t i;
    char c;

    for (i = 0; i < 4 && text[i] != 0; i++)
    {
        c = text[i];

        if (c >= '0' && c <= '9')
            value = value * 16 + (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f')
            value = value * 16 + (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            value = value * 16 + (uint32_t)(c - 'A' + 10);
        else
            break;
    }

    return (uint16_t)value;
}

/* Up from the tty's device to the first directory naming a vendor: the USB device itself. A hub above it has a
   serial number of its own, so the walk stops at the first; it never leaves the tree's own `sys`. */
static int sysfsUsbDevice(char *path, const char *sysReal)
{
    char probe[SYSFS_PATH_MAX];
    uint32_t floor = Zb_strlen(sysReal, SYSFS_PATH_MAX);
    uint32_t len = Zb_strlen(path, SYSFS_PATH_MAX);

    if (len <= floor || Zb_memcmp(path, sysReal, floor) != 0)
        return 0;

    while (len > floor)
    {
        if (sysfsJoin(probe, (uint32_t)sizeof probe, path, "/idVendor", "") && access(probe, F_OK) == 0)
            return 1;

        while (len > floor && path[len - 1] != '/')
            len--;

        if (len > 0)
            len--;

        path[len] = 0;
    }

    return 0;
}

uint32_t PortLocate_EachSysfs(const char *root, PortLocate_Visit visit, void *context)
{
    char sys[SYSFS_PATH_MAX];
    char sysReal[SYSFS_PATH_MAX];
    char link[SYSFS_PATH_MAX];
    char usb[SYSFS_PATH_MAX];
    char text[PORT_LOCATE_TEXT_MAX];
    PortLocate_Candidate candidate;
    struct dirent *entry;
    DIR *dir;
    uint32_t count = 0;

    if (root == 0 || visit == 0)
        return 0;

    if (!sysfsJoin(sys, (uint32_t)sizeof sys, root, "/sys", "") || realpath(sys, sysReal) == 0)
        return 0;

    if (!sysfsJoin(link, (uint32_t)sizeof link, sysReal, "/class/tty", ""))
        return 0;

    dir = opendir(link);

    if (dir == 0)
        return 0;

    while ((entry = readdir(dir)) != 0)
    {
        if (entry->d_name[0] == '.')
            continue;

        if (!sysfsJoin(link, (uint32_t)sizeof link, sysReal, "/class/tty/", entry->d_name)
                || !sysfsJoin(link, (uint32_t)sizeof link, link, "/device", ""))
            continue;

        if (realpath(link, usb) == 0 || !sysfsUsbDevice(usb, sysReal))
            continue;

        Zb_memset(&candidate, 0, (uint32_t)sizeof candidate);

        if (!sysfsRead(usb, "serial", candidate.serial, (uint32_t)sizeof candidate.serial))
            continue;

        (void)sysfsRead(usb, "product", candidate.product, (uint32_t)sizeof candidate.product);
        (void)sysfsRead(usb, "idVendor", text, (uint32_t)sizeof text);
        candidate.vendorId = sysfsHex16(text);
        (void)sysfsRead(usb, "idProduct", text, (uint32_t)sizeof text);
        candidate.productId = sysfsHex16(text);

        if (!sysfsJoin(candidate.device, (uint32_t)sizeof candidate.device, root, "/dev/", entry->d_name))
            continue;

        candidate.present = access(candidate.device, F_OK) == 0;
        visit(context, &candidate);
        count++;
    }

    closedir(dir);
    return count;
}
