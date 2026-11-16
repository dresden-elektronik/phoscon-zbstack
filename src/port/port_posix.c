/* Before any include: glibc fixes its feature set at the first system header, which port_posix.h reaches */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700          /* termios and the pty calls are POSIX, C99 does not imply them */
#endif

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1          /* glibc keeps getentropy(2) in <unistd.h> behind __USE_MISC, which _XOPEN_SOURCE alone does not turn on (docs/internals/coding-rules.md §1: the target facts are stated where the target lives) */
#endif

#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1         /* macOS hides B57600 and above under _XOPEN_SOURCE alone */
#endif

#include "port_posix.h"
#include "port_locate.h"
#include "zb_utils.h"

#include <stdlib.h>                   /* POSIX declares the pty calls here, not in a byte/text header */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>                   /* PATH_MAX, held against PORT_PATH_MAX below */
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/random.h>               /* macOS and the BSDs declare getentropy here; glibc declares it in <unistd.h> below. Both are included, so the one call this file makes is declared wherever this backend is built */
#include <termios.h>
#include <time.h>                     /* CLOCK_MONOTONIC: POSIX, which is what this backend is chosen for */
#include <unistd.h>

#if defined(PATH_MAX) && PATH_MAX > PORT_PATH_MAX
#error "PORT_PATH_MAX is shorter than this host's PATH_MAX"
#endif

#define POSIX_READ_CHUNK 256

static speed_t posixSpeed(uint32_t baud, int *known)
{
    *known = 1;

    switch (baud)
    {
        case 9600:   return B9600;
        case 19200:  return B19200;
        case 38400:  return B38400;
        case 57600:  return B57600;
        case 115200: return B115200;
#if defined(B230400)
        case 230400: return B230400;
#endif
#if defined(B460800)
        case 460800: return B460800;
#endif
#if defined(B921600)
        case 921600: return B921600;
#endif
        default:
            *known = 0;
            return B115200;
    }
}

/* Raw 8N1 without cfmakeraw: it is not POSIX and the two systems spell it
   differently (docs/internals/hardware.md §2). */
static void posixMakeRaw(struct termios *attr)
{
    attr->c_iflag &= ~(uint32_t)(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR |
                                 IGNCR | ICRNL | IXON);
    attr->c_oflag &= ~(uint32_t)OPOST;
    attr->c_lflag &= ~(uint32_t)(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    attr->c_cflag &= ~(uint32_t)(CSIZE | PARENB | CSTOPB);
#if defined(CRTSCTS)
    attr->c_cflag &= ~(uint32_t)CRTSCTS;
#endif
    attr->c_cflag |= (uint32_t)(CS8 | CLOCAL | CREAD);
    attr->c_cc[VMIN] = 0;
    attr->c_cc[VTIME] = 0;
}

static ZbStatus posixOpen(Port *port, const char *path, const PortConfig *config)
{
    struct termios attr;
    speed_t speed;
    ZbStatus status;
    int known;
    int fd;
    int flags;

    port->fault = PORT_FAULT_NONE;
    port->platformErrno = 0;

    speed = posixSpeed(config->baud, &known);

    if (!known)
        return ZB_ERR_BAD_ARGUMENT;

    port->located[0] = 0;

    if (PortLocate_IsSelector(path))
    {
        status = PortLocate_Resolve(0, path, port->located, (uint32_t)sizeof port->located, 0);

        if (status != ZB_OK)
        {
            port->fault = status == ZB_ERR_NO_DEVICE ? PORT_FAULT_DEVICE_GONE : PORT_FAULT_OPEN;
            return status;
        }

        path = port->located;
    }

    flags = O_RDWR | O_NOCTTY | O_NONBLOCK;
    fd = open(path, flags);

    if (fd < 0)
    {
        port->platformErrno = (uint32_t)errno;
        port->fault = (errno == ENOENT || errno == ENXIO || errno == ENODEV)
                          ? PORT_FAULT_DEVICE_GONE : PORT_FAULT_OPEN;
        return (errno == EACCES) ? ZB_ERR_UNSUPPORTED : ZB_ERR_NO_DEVICE;
    }

    if (config->exclusive)
    {
        if (ioctl(fd, TIOCEXCL) < 0 && errno == EBUSY)
        {
            port->platformErrno = (uint32_t)errno;
            port->fault = PORT_FAULT_OPEN;
            close(fd);
            return ZB_ERR_BUSY;
        }
    }

    if (tcgetattr(fd, &attr) < 0)
    {
        port->platformErrno = (uint32_t)errno;
        port->fault = PORT_FAULT_OPEN;
        close(fd);
        return ZB_ERR_NO_DEVICE;
    }

    posixMakeRaw(&attr);
    cfsetispeed(&attr, speed);
    cfsetospeed(&attr, speed);

    if (tcsetattr(fd, TCSANOW, &attr) < 0)
    {
        port->platformErrno = (uint32_t)errno;
        port->fault = PORT_FAULT_OPEN;
        close(fd);
        return ZB_ERR_NO_DEVICE;
    }

    port->device = (uintptr_t)fd;
    return ZB_OK;
}

static void posixClose(Port *port)
{
    int fd;

    if (port->device == 0)
        return;

    fd = (int)port->device;
    port->device = 0;
    close(fd);
}

static int posixPump(Port *port)
{
    uint8_t chunk[POSIX_READ_CHUNK];
    uint32_t want;
    ssize_t got;
    int fd = (int)port->device;

    want = Port_RxRingSize(port) - Port_RxPending(port);

    if (want == 0)
        return 0;

    if (want > POSIX_READ_CHUNK)
        want = POSIX_READ_CHUNK;

    got = read(fd, chunk, (size_t)want);

    if (got > 0)
        return (int)Port_PushRx(port, chunk, (uint32_t)got);

    if (got == 0)
        return 0;

    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return 0;

    port->platformErrno = (uint32_t)errno;
    port->fault = (errno == EIO || errno == ENXIO || errno == EBADF || errno == ENODEV)
                      ? PORT_FAULT_DEVICE_GONE : PORT_FAULT_READ;
    return -1;
}

static ZbStatus posixDrain(Port *port)
{
    const uint8_t *bytes;
    uint32_t run;
    uint32_t sent;
    ssize_t wrote;
    int fd = (int)port->device;

    for (;;)
    {
        bytes = Port_TxHead(port, &run);

        if (!bytes)
            return ZB_OK;

        sent = 0;

        while (sent < run)
        {
            wrote = write(fd, bytes + sent, (size_t)(run - sent));

            if (wrote > 0)
            {
                sent += (uint32_t)wrote;
                continue;
            }

            if (wrote < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            {
                Port_ConsumeTx(port, sent);
                return ZB_OK;
            }

            port->platformErrno = (uint32_t)errno;
            port->fault = (errno == EIO || errno == ENXIO || errno == EBADF || errno == ENODEV)
                              ? PORT_FAULT_DEVICE_GONE : PORT_FAULT_WRITE;
            Port_ConsumeTx(port, sent);
            return ZB_ERR_DEVICE_LOST;
        }

        Port_ConsumeTx(port, sent);
    }
}

static ZbStatus posixLastFault(const Port *port)
{
    (void)port;
    return ZB_ERR_DEVICE_LOST;
}

/*
 * The host's own entropy source: getentropy(2), the one call this contract exists for.
 * The octets are read into this function's own stage buffer (sized to PORT_ENTROPY_MAX,
 * which the contract door has already checked the request against) and copied out only if
 * the read filled it, so "no partial fill" is a property of this code and not a promise
 * about how a platform behaves when it fails. A failed read is the host's, not this port's
 * device: the platform error is carried out and nothing else about the port changes.
 */
static ZbStatus posixEntropy(Port *port, uint8_t *out, uint32_t len)
{
    uint8_t stage[PORT_ENTROPY_MAX];

    if (getentropy(stage, (size_t)len) != 0)
    {
        port->platformErrno = (uint32_t)errno;
        return ZB_ERR_INTERNAL;
    }

    Zb_memcpy(out, stage, len);
    return ZB_OK;
}

/*
 * The host's monotonic clock: clock_gettime(CLOCK_MONOTONIC), read as milliseconds since an epoch this file
 * never names. POSIX fails that call only for a clock the host does not have, and a host this backend builds for
 * has CLOCK_MONOTONIC, so there is no failure to carry out.
 */
uint32_t Port_NowMs(void)
{
    struct timespec now;

    (void)clock_gettime(CLOCK_MONOTONIC, &now);

    return (uint32_t)((uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000);
}

/* nanosleep(2), resumed with what is left when a signal cuts it short, so the caller sleeps the whole time. */
void Port_SleepMs(uint32_t ms)
{
    struct timespec wait;
    struct timespec left;

    wait.tv_sec = (time_t)(ms / 1000);
    wait.tv_nsec = (long)(ms % 1000) * 1000000;

    while (nanosleep(&wait, &left) != 0 && errno == EINTR)
        wait = left;
}

/* poll(2) for input, and for room to write while the transmit ring holds something, so a frame the last write left
   half-sent goes out as soon as the device takes it. An interrupted wait is a short one, not a fault; a hung-up line
   is a device gone, which macOS reports this way and through no read error. */
static ZbStatus posixWait(Port *port, uint32_t maxMs)
{
    struct pollfd watch;
    const uint32_t longest = 0x7fffffff;
    int timeout = maxMs > longest ? (int)longest : (int)maxMs;

    watch.fd = (int)port->device;
    watch.events = POLLIN;
    watch.revents = 0;

    if (Port_TxPending(port) != 0)
        watch.events |= POLLOUT;

    if (poll(&watch, 1, timeout) < 0 && errno != EINTR)
    {
        port->platformErrno = (uint32_t)errno;
        return ZB_ERR_INTERNAL;
    }

    if ((watch.revents & (POLLHUP | POLLNVAL)) != 0)
    {
        port->fault = PORT_FAULT_DEVICE_GONE;
        return ZB_OK;
    }

    if ((watch.revents & POLLOUT) != 0)
        (void)posixDrain(port);

    return ZB_OK;
}

static const PortDeviceOps s_ops = {
    "posix",
    posixOpen,
    posixClose,
    posixPump,
    posixDrain,
    posixLastFault,
    posixEntropy,
    posixWait
};

/* Suite helper: a pseudo-terminal pair, so the port contract is exercised against a
   real device node with no radio attached. It lives here because
   this file is the only one allowed to know what a descriptor is. */
ZbStatus PortPosix_PtyOpen(int *masterFd, char *slaveName, uint32_t nameCapacity)
{
    int master;
    char *name;

    if (!masterFd || !slaveName || nameCapacity == 0)
        return ZB_ERR_BAD_ARGUMENT;

    master = posix_openpt(O_RDWR | O_NOCTTY);

    if (master < 0)
        return ZB_ERR_NO_DEVICE;

    if (grantpt(master) < 0 || unlockpt(master) < 0)
    {
        close(master);
        return ZB_ERR_NO_DEVICE;
    }

    name = ptsname(master);

    if (!name || Zb_strlen(name, nameCapacity) >= nameCapacity)
    {
        close(master);
        return ZB_ERR_NO_DEVICE;
    }

    fcntl(master, F_SETFL, O_NONBLOCK);
    *masterFd = master;
    Zb_memcpy(slaveName, name, Zb_strlen(name, nameCapacity) + 1);
    return ZB_OK;
}

/* Suite helpers: the master side of the pseudo-terminal, so a test never needs a
   descriptor of its own. */
ZbStatus PortPosix_PtyWrite(int masterFd, const uint8_t *bytes, uint32_t len)
{
    uint32_t sent;
    ssize_t wrote;

    sent = 0;

    while (sent < len)
    {
        wrote = write(masterFd, bytes + sent, (size_t)(len - sent));

        if (wrote > 0)
        {
            sent += (uint32_t)wrote;
            continue;
        }

        if (wrote < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            continue;

        return ZB_ERR_DEVICE_LOST;
    }

    return ZB_OK;
}

void PortPosix_PtyClose(int masterFd)
{
    close(masterFd);
}

ZbStatus PortPosix_PtyRead(int masterFd, uint8_t *buf, uint32_t cap, uint32_t *got)
{
    ssize_t read_;

    *got = 0;
    read_ = read(masterFd, buf, (size_t)cap);

    if (read_ > 0)
    {
        *got = (uint32_t)read_;
        return ZB_OK;
    }

    if (read_ == 0)
        return ZB_OK;

    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return ZB_OK;

    return ZB_ERR_DEVICE_LOST;
}

ZbStatus PortPosix_PtyLink(const char *linkPath, const char *slaveName)
{
    if (unlink(linkPath) != 0 && errno != ENOENT)
        return ZB_ERR_INTERNAL;

    if (slaveName == 0)
        return ZB_OK;

    return symlink(slaveName, linkPath) == 0 ? ZB_OK : ZB_ERR_INTERNAL;
}

const PortDeviceOps *PortPosixOps(void)
{
    return &s_ops;
}

const PortDeviceOps *Port_DefaultOps(void)
{
    return &s_ops;
}
