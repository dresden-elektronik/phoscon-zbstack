/* Before any include: the smallest <windows.h> that still declares the communications and the CNG calls */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#include "port_win32.h"
#include "port_locate.h"
#include "zb_utils.h"

#include <windows.h>
#include <bcrypt.h>                   /* BCryptGenRandom: the system's preferred generator, no provider to open */

#define WIN32_READ_CHUNK      256
#define WIN32_WRITE_BOUND_MS  100     /* the longest one WriteFile may hold the caller before it answers what went out */
#define WIN32_DEVICE_PREFIX   "\\\\.\\"

/* COM1 to COM9 open by their bare names and COM10 up only as \\.\COM10, and the prefixed form opens every one of
   them, so a bare name is prefixed and a name already in the device namespace is kept as written. */
static int win32DeviceName(const char *path, char *name, uint32_t capacity)
{
    uint32_t prefix = 0;
    uint32_t len = Zb_strlen(path, PORT_PATH_MAX);

    if (!(path[0] == '\\' && path[1] == '\\'))
        prefix = (uint32_t)sizeof WIN32_DEVICE_PREFIX - 1;

    if (prefix + len + 1 > capacity)
        return 0;

    Zb_memcpy(name, WIN32_DEVICE_PREFIX, prefix);
    Zb_memcpy(name + prefix, path, len + 1);
    return 1;
}

static int win32KnownBaud(uint32_t baud)
{
    switch (baud)
    {
        case 9600:
        case 19200:
        case 38400:
        case 57600:
        case 115200:
        case 230400:
        case 460800:
        case 921600:
            return 1;
        default:
            return 0;
    }
}

/* The errors a removed USB device answers with: which one depends on the driver (usbser for the CDC sticks, the FTDI
   VCP for the bridged ones), and every one of them means the handle will never carry a byte again. */
static int win32DeviceGone(DWORD error)
{
    switch (error)
    {
        case ERROR_ACCESS_DENIED:
        case ERROR_BAD_COMMAND:
        case ERROR_DEVICE_NOT_CONNECTED:
        case ERROR_DEVICE_REMOVED:
        case ERROR_FILE_NOT_FOUND:
        case ERROR_GEN_FAILURE:
        case ERROR_INVALID_HANDLE:
        case ERROR_OPERATION_ABORTED:
            return 1;
        default:
            return 0;
    }
}

/* A read that returns at once with what the driver holds, and a write bounded so a stalled line cannot hold the
   caller: COMMTIMEOUTS is the whole of Windows' non-blocking mode for a COM port. */
static BOOL win32Immediate(HANDLE handle)
{
    COMMTIMEOUTS timeouts;

    timeouts.ReadIntervalTimeout = MAXDWORD;
    timeouts.ReadTotalTimeoutMultiplier = 0;
    timeouts.ReadTotalTimeoutConstant = 0;
    timeouts.WriteTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = WIN32_WRITE_BOUND_MS;

    return SetCommTimeouts(handle, &timeouts);
}

static ZbStatus win32OpenFailed(Port *port, HANDLE handle, ZbStatus status)
{
    port->platformErrno = (uint32_t)GetLastError();
    port->fault = PORT_FAULT_OPEN;
    CloseHandle(handle);
    return status;
}

static ZbStatus win32Open(Port *port, const char *path, const PortConfig *config)
{
    char name[PORT_PATH_MAX + sizeof WIN32_DEVICE_PREFIX];
    ZbStatus status;
    HANDLE handle;
    DCB dcb;
    DWORD error;

    port->fault = PORT_FAULT_NONE;
    port->platformErrno = 0;
    port->located[0] = 0;

    if (!win32KnownBaud(config->baud))
        return ZB_ERR_BAD_ARGUMENT;

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

    if (!win32DeviceName(path, name, (uint32_t)sizeof name))
        return ZB_ERR_BAD_ARGUMENT;

    /* No sharing: a COM port has one opener at a time whatever `exclusive` asks, so a second one is refused here. */
    handle = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);

    if (handle == INVALID_HANDLE_VALUE)
    {
        error = GetLastError();
        port->platformErrno = (uint32_t)error;

        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
        {
            port->fault = PORT_FAULT_DEVICE_GONE;
            return ZB_ERR_NO_DEVICE;
        }

        port->fault = PORT_FAULT_OPEN;
        return (error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION) ? ZB_ERR_BUSY : ZB_ERR_NO_DEVICE;
    }

    Zb_memset(&dcb, 0, sizeof dcb);
    dcb.DCBlength = sizeof dcb;

    if (!GetCommState(handle, &dcb))
        return win32OpenFailed(port, handle, ZB_ERR_NO_DEVICE);

    /* 8N1, binary, no flow control in either direction, and DTR and RTS raised as a POSIX open leaves them. An error
       on the line does not stop the port until it is cleared: the HDLC framing above finds the next frame. */
    dcb.BaudRate = (DWORD)config->baud;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fBinary = TRUE;
    dcb.fParity = FALSE;
    dcb.fOutxCtsFlow = FALSE;
    dcb.fOutxDsrFlow = FALSE;
    dcb.fDtrControl = DTR_CONTROL_ENABLE;
    dcb.fDsrSensitivity = FALSE;
    dcb.fTXContinueOnXoff = TRUE;
    dcb.fOutX = FALSE;
    dcb.fInX = FALSE;
    dcb.fErrorChar = FALSE;
    dcb.fNull = FALSE;
    dcb.fRtsControl = RTS_CONTROL_ENABLE;
    dcb.fAbortOnError = FALSE;

    if (!SetCommState(handle, &dcb))
        return win32OpenFailed(port, handle, ZB_ERR_NO_DEVICE);

    if (!win32Immediate(handle))
        return win32OpenFailed(port, handle, ZB_ERR_NO_DEVICE);

    port->device = (uintptr_t)handle;
    return ZB_OK;
}

static void win32Close(Port *port)
{
    HANDLE handle;

    if (port->device == 0)
        return;

    handle = (HANDLE)port->device;
    port->device = 0;
    CloseHandle(handle);
}

static void win32Fault(Port *port, PortFault otherwise)
{
    DWORD error = GetLastError();

    port->platformErrno = (uint32_t)error;
    port->fault = win32DeviceGone(error) ? PORT_FAULT_DEVICE_GONE : otherwise;
}

/* What the driver holds now, which also clears a line error so the next read is not refused for it; a removed device
   fails this call before any read does. */
static int win32Queued(Port *port, DWORD *queued)
{
    COMSTAT stat;
    DWORD errors;

    if (!ClearCommError((HANDLE)port->device, &errors, &stat))
    {
        win32Fault(port, PORT_FAULT_READ);
        return 0;
    }

    *queued = stat.cbInQue;
    return 1;
}

/* One ReadFile of up to `want` octets into the ring, under whichever timeouts are set. */
static int win32ReadInto(Port *port, uint32_t want)
{
    uint8_t chunk[WIN32_READ_CHUNK];
    DWORD got = 0;

    if (want > WIN32_READ_CHUNK)
        want = WIN32_READ_CHUNK;

    if (!ReadFile((HANDLE)port->device, chunk, (DWORD)want, &got, 0))
    {
        win32Fault(port, PORT_FAULT_READ);
        return -1;
    }

    return got > 0 ? (int)Port_PushRx(port, chunk, (uint32_t)got) : 0;
}

static int win32Pump(Port *port)
{
    uint32_t want;
    DWORD queued;

    want = Port_RxRingSize(port) - Port_RxPending(port);

    if (want == 0)
        return 0;

    if (!win32Queued(port, &queued))
        return -1;

    if (queued == 0)
        return 0;

    if (want > (uint32_t)queued)
        want = (uint32_t)queued;

    return win32ReadInto(port, want);
}

static ZbStatus win32Drain(Port *port)
{
    const uint8_t *bytes;
    uint32_t run;
    DWORD wrote;

    for (;;)
    {
        bytes = Port_TxHead(port, &run);

        if (!bytes)
            return ZB_OK;

        wrote = 0;

        if (!WriteFile((HANDLE)port->device, bytes, (DWORD)run, &wrote, 0))
        {
            Port_ConsumeTx(port, (uint32_t)wrote);
            win32Fault(port, PORT_FAULT_WRITE);
            return ZB_ERR_DEVICE_LOST;
        }

        Port_ConsumeTx(port, (uint32_t)wrote);

        /* The write bound passed with the run half out: the rest waits on the ring, as a POSIX EAGAIN leaves it. */
        if ((uint32_t)wrote < run)
            return ZB_OK;
    }
}

static ZbStatus win32LastFault(const Port *port)
{
    (void)port;
    return ZB_ERR_DEVICE_LOST;
}

/*
 * The system's preferred generator through CNG, staged as the POSIX backend stages getentropy(2), so a failed call
 * writes nothing into `out`. The NTSTATUS of a failure is the platform's error here.
 */
static ZbStatus win32Entropy(Port *port, uint8_t *out, uint32_t len)
{
    uint8_t stage[PORT_ENTROPY_MAX];
    NTSTATUS status;

    status = BCryptGenRandom(0, stage, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (status != 0)
    {
        port->platformErrno = (uint32_t)status;
        return ZB_ERR_INTERNAL;
    }

    Zb_memcpy(out, stage, len);
    return ZB_OK;
}

/*
 * The performance counter, monotonic since boot and never adjusted, read as milliseconds. The whole seconds and the
 * remainder are scaled apart so the product cannot overflow 64 bits at any uptime. Windows documents both calls as
 * never failing from Windows XP on, so there is no failure to carry out.
 */
uint32_t Port_NowMs(void)
{
    LARGE_INTEGER count;
    LARGE_INTEGER frequency;
    uint64_t ticks;
    uint64_t perSecond;

    (void)QueryPerformanceCounter(&count);
    (void)QueryPerformanceFrequency(&frequency);

    ticks = (uint64_t)count.QuadPart;
    perSecond = (uint64_t)frequency.QuadPart;

    return (uint32_t)((ticks / perSecond) * 1000 + (ticks % perSecond) * 1000 / perSecond);
}

void Port_SleepMs(uint32_t ms)
{
    Sleep((DWORD)ms);
}

/*
 * A wait with no overlapped I/O: timeouts of MAXDWORD, MAXDWORD and `maxMs` make one ReadFile return as soon as a
 * byte arrives, or empty when `maxMs` has passed (the COMMTIMEOUTS documentation's own case), and the octets it
 * brings go onto the ring as a pump's would. The immediate timeouts are set back before the call returns.
 */
static ZbStatus win32Wait(Port *port, uint32_t maxMs)
{
    HANDLE handle = (HANDLE)port->device;
    COMMTIMEOUTS timeouts;
    uint32_t want;
    DWORD queued;
    int read_;

    want = Port_RxRingSize(port) - Port_RxPending(port);

    if (!win32Queued(port, &queued))
        return ZB_OK;

    if (queued != 0 || maxMs == 0 || want == 0)
        return ZB_OK;

    if (maxMs >= MAXDWORD)
        maxMs = MAXDWORD - 1;

    timeouts.ReadIntervalTimeout = MAXDWORD;
    timeouts.ReadTotalTimeoutMultiplier = MAXDWORD;
    timeouts.ReadTotalTimeoutConstant = (DWORD)maxMs;
    timeouts.WriteTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = WIN32_WRITE_BOUND_MS;

    if (!SetCommTimeouts(handle, &timeouts))
    {
        win32Fault(port, PORT_FAULT_READ);
        return ZB_OK;
    }

    read_ = win32ReadInto(port, want);

    if (!win32Immediate(handle) && read_ >= 0)
        win32Fault(port, PORT_FAULT_READ);

    return ZB_OK;
}

static const PortDeviceOps s_ops = {
    "win32",
    win32Open,
    win32Close,
    win32Pump,
    win32Drain,
    win32LastFault,
    win32Entropy,
    win32Wait
};

const PortDeviceOps *PortWin32Ops(void)
{
    return &s_ops;
}

const PortDeviceOps *Port_DefaultOps(void)
{
    return &s_ops;
}
