/* Before any include: the smallest <windows.h> that still declares the registry and configuration-manager calls */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#include "port_locate.h"
#include "zb_utils.h"

#include <windows.h>
#include <initguid.h>                 /* before the two below, so the class GUID and the property key are defined here */
#include <devguid.h>
#include <devpkey.h>
#include <setupapi.h>
#include <cfgmgr32.h>

#define WIN32_USB_PREFIX     "USB\\VID_"
#define WIN32_PARENTS_MAX    4        /* a COM port, its USB interface or the FTDI bus, then the USB device */

static int win32HexDigit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    return -1;
}

static uint16_t win32Hex4(const char *at)
{
    uint16_t value = 0;
    int digit;
    uint32_t i;

    for (i = 0; i < 4; i++)
    {
        digit = win32HexDigit(at[i]);

        if (digit < 0)
            return 0;

        value = (uint16_t)(value * 16 + (uint16_t)digit);
    }

    return value;
}

/*
 * A USB device's instance id, USB\VID_vvvv&PID_pppp\<serial>, read into the candidate. An interface of a composite
 * device carries &MI_ in its hardware part and is not the device, and a device with no serial number gets an
 * instance id the system made up, which holds an '&'; neither names a serial.
 */
static int win32UsbDevice(const char *id, PortLocate_Candidate *candidate)
{
    uint32_t prefix = (uint32_t)sizeof WIN32_USB_PREFIX - 1;
    const char *serial = 0;
    uint32_t len;
    uint32_t i;

    len = Zb_strlen(id, MAX_DEVICE_ID_LEN);

    if (len <= prefix || Zb_memcmp(id, WIN32_USB_PREFIX, prefix) != 0)
        return 0;

    for (i = prefix; i < len; i++)
    {
        if (id[i] == '\\')
        {
            serial = id + i + 1;
            break;
        }

        if (id[i] == '&' && id[i + 1] == 'M' && id[i + 2] == 'I' && id[i + 3] == '_')
            return 0;
    }

    if (serial == 0 || serial[0] == 0)
        return 0;

    for (i = 0; serial[i] != 0; i++)
    {
        if (serial[i] == '&' || i + 1 >= (uint32_t)sizeof candidate->serial)
            return 0;
    }

    Zb_memcpy(candidate->serial, serial, i + 1);
    candidate->vendorId = win32Hex4(id + prefix);
    candidate->productId = len >= prefix + 9 ? win32Hex4(id + prefix + 9) : 0;
    return 1;
}

/* The product string the device reported on the bus, kept to ASCII: a USB string descriptor is UTF-16 and the
   candidate's text is a C string. */
static void win32Product(DEVINST node, char *out, uint32_t capacity)
{
    WCHAR text[PORT_LOCATE_TEXT_MAX];
    DEVPROPTYPE type;
    ULONG size = (ULONG)sizeof text;
    uint32_t i;

    out[0] = 0;

    if (CM_Get_DevNode_PropertyW(node, &DEVPKEY_Device_BusReportedDeviceDesc, &type, (PBYTE)text, &size, 0)
            != CR_SUCCESS || type != DEVPROP_TYPE_STRING)
        return;

    for (i = 0; i + 1 < capacity && i < PORT_LOCATE_TEXT_MAX && text[i] != 0; i++)
        out[i] = text[i] < 0x80 ? (char)text[i] : '?';

    out[i] = 0;
}

/* The COM name the Ports class keeps in the device's own registry key. */
static int win32PortName(HDEVINFO set, SP_DEVINFO_DATA *info, char *out, uint32_t capacity)
{
    HKEY key;
    DWORD type;
    DWORD size = (DWORD)capacity - 1;
    LONG status;

    key = SetupDiOpenDevRegKey(set, info, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);

    if (key == INVALID_HANDLE_VALUE)
        return 0;

    status = RegQueryValueExA(key, "PortName", 0, &type, (LPBYTE)out, &size);
    RegCloseKey(key);

    if (status != ERROR_SUCCESS || type != REG_SZ || size == 0)
        return 0;

    out[size] = 0;
    return out[0] == 'C' && out[1] == 'O' && out[2] == 'M';
}

/* Every present COM port with a USB device above it that has a serial number: the CDC sticks hang from it directly or
   through an interface, the FTDI bridge through the FTDI bus. */
uint32_t PortLocate_EachPlatform(PortLocate_Visit visit, void *context)
{
    PortLocate_Candidate candidate;
    char id[MAX_DEVICE_ID_LEN];
    SP_DEVINFO_DATA info;
    HDEVINFO set;
    DEVINST node;
    uint32_t count = 0;
    DWORD index;
    uint32_t up;

    if (visit == 0)
        return 0;

    set = SetupDiGetClassDevsA(&GUID_DEVCLASS_PORTS, 0, 0, DIGCF_PRESENT);

    if (set == INVALID_HANDLE_VALUE)
        return 0;

    info.cbSize = sizeof info;

    for (index = 0; SetupDiEnumDeviceInfo(set, index, &info); index++)
    {
        Zb_memset(&candidate, 0, (uint32_t)sizeof candidate);

        if (!win32PortName(set, &info, candidate.device, (uint32_t)sizeof candidate.device))
            continue;

        node = info.DevInst;

        for (up = 0; up < WIN32_PARENTS_MAX; up++)
        {
            if (up > 0 && CM_Get_Parent(&node, node, 0) != CR_SUCCESS)
                break;

            if (CM_Get_Device_IDA(node, id, (ULONG)sizeof id, 0) != CR_SUCCESS)
                break;

            if (win32UsbDevice(id, &candidate))
            {
                win32Product(node, candidate.product, (uint32_t)sizeof candidate.product);
                candidate.present = 1;
                visit(context, &candidate);
                count++;
                break;
            }
        }
    }

    SetupDiDestroyDeviceInfoList(set);
    return count;
}

/* Windows has no sysfs, so a root names a tree this target cannot read: nothing is found under it. */
uint32_t PortLocate_EachSysfs(const char *root, PortLocate_Visit visit, void *context)
{
    (void)root;
    (void)visit;
    (void)context;
    return 0;
}
