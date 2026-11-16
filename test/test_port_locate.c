#include <stdio.h>
#include <string.h>

#include "port.h"
#include "port_locate.h"
#include "port_posix.h"
#include "test_harness.h"

/* A stick found by its USB serial number (D-282), read from a sysfs-shaped tree CMake makes for this suite
   (test/port_locate_fixture.cmake), and from the platform's own enumeration, which this suite only reads. */

/* ctest runs the suite inside the fixture, which it names ".", so a node path is as short as a real one wherever
   the build tree lies: PORT_LOCATED_MAX holds `/dev/` and a name, not a deep build directory. */
#define LOCATE_ROOT "."

typedef struct Seen
{
    uint32_t count;
    PortLocate_Candidate last[8];
} Seen;

static void seenAdd(void *context, const PortLocate_Candidate *candidate)
{
    Seen *seen = (Seen *)context;

    if (seen->count < 8)
        seen->last[seen->count] = *candidate;

    seen->count++;
}

static int endsWith(const char *text, const char *tail);

static const PortLocate_Candidate *seenDevice(const Seen *seen, const char *tail)
{
    uint32_t i;

    for (i = 0; i < seen->count && i < 8; i++)
    {
        if (endsWith(seen->last[i].device, tail))
            return &seen->last[i];
    }

    return 0;
}

static void caseSelectorIsItsPrefix(void)
{
    Test_Case("caseSelectorIsItsPrefix");
    Test_Expect(PortLocate_IsSelector("usb-serial:DE1000000"), "a usb-serial: path is a selector");
    Test_Expect(!PortLocate_IsSelector("/dev/ttyACM0"), "a device path is not");
    Test_Expect(!PortLocate_IsSelector("usb-serial"), "nor the bare word");
    Test_Expect(!PortLocate_IsSelector(0), "nor nothing");
}

static void caseOnlyUsbTerminalsAreListed(void)
{
    Seen seen;

    Test_Case("caseOnlyUsbTerminalsAreListed");
    memset(&seen, 0, sizeof seen);
    Test_ExpectCount(PortLocate_Each(LOCATE_ROOT, seenAdd, &seen), 5,
                     "five terminals have a USB device above them; the UART, the dangling link and tty0 do not");
    Test_ExpectCount(seen.count, 5, "and each is handed over once");
    Test_Expect(seenDevice(&seen, "/dev/ttyAMA0") == 0, "a header UART is never a candidate");
}

static void caseBothLayoutsReadTheirDevice(void)
{
    const PortLocate_Candidate *acm;
    const PortLocate_Candidate *ftdi;
    Seen seen;

    Test_Case("caseBothLayoutsReadTheirDevice");
    memset(&seen, 0, sizeof seen);
    (void)PortLocate_Each(LOCATE_ROOT, seenAdd, &seen);
    acm = seenDevice(&seen, "/dev/ttyACM0");
    ftdi = seenDevice(&seen, "/dev/ttyUSB0");

    Test_Expect(acm != 0 && strcmp(acm->serial, "DE1000000") == 0, "a CDC terminal reads the device above its interface");
    Test_Expect(acm != 0 && acm->vendorId == 0x1cf1 && acm->productId == 0x0030 && strcmp(acm->product, "ConBee II") == 0,
                "with its vendor, product and name, and not the root hub's serial above it");
    Test_Expect(ftdi != 0 && strcmp(ftdi->serial, "DEDEADAFFE") == 0 && ftdi->vendorId == 0x0403,
                "an FTDI terminal sits one level deeper and reads the same way");
    Test_Expect(ftdi != 0 && ftdi->present, "and its node is there");
}

static int endsWith(const char *text, const char *tail)
{
    size_t len = strlen(text);
    size_t tailLen = strlen(tail);

    return len >= tailLen && strcmp(text + len - tailLen, tail) == 0;
}

static void caseSelectorResolvesToItsNode(void)
{
    char device[PORT_LOCATED_MAX];
    uint32_t matches = 0;

    Test_Case("caseSelectorResolvesToItsNode");
    Test_ExpectStatus(PortLocate_Resolve(LOCATE_ROOT, "usb-serial:DEDEADAFFE", device, (uint32_t)sizeof device, &matches),
                      ZB_OK, "a serial one device carries resolves");
    Test_Expect(endsWith(device, "/dev/ttyUSB0"), "to the node that device has now");
    Test_ExpectCount(matches, 1, "one match");
}

static void caseMatchIsExact(void)
{
    char device[PORT_LOCATED_MAX];
    uint32_t matches = 7;

    Test_Case("caseMatchIsExact");
    Test_ExpectStatus(PortLocate_Resolve(LOCATE_ROOT, "usb-serial:DE100000", device, (uint32_t)sizeof device, &matches),
                      ZB_ERR_NO_DEVICE, "a serial's prefix names nothing");
    Test_ExpectCount(matches, 0, "and matches nothing");
    Test_ExpectStatus(PortLocate_Resolve(LOCATE_ROOT, "usb-serial:DE10000001", device, (uint32_t)sizeof device, &matches),
                      ZB_ERR_NO_DEVICE, "nor does macOS's device name for it, the serial with a digit appended");
    Test_ExpectStatus(PortLocate_Resolve(LOCATE_ROOT, "usb-serial:", device, (uint32_t)sizeof device, &matches),
                      ZB_ERR_BAD_ARGUMENT, "an empty serial is refused");
}

static void caseMatchWithNoNodeIsNoDevice(void)
{
    char device[PORT_LOCATED_MAX];
    uint32_t matches = 0;

    Test_Case("caseMatchWithNoNodeIsNoDevice");
    Test_ExpectStatus(PortLocate_Resolve(LOCATE_ROOT, "usb-serial:DM00F7D1", device, (uint32_t)sizeof device, &matches),
                      ZB_ERR_NO_DEVICE, "a device attached whose node this system does not have is not opened");
    Test_ExpectCount(matches, 1, "though it matched, which is how a container that mapped one name reads");
}

static void caseTwoMatchesNameNeither(void)
{
    char device[PORT_LOCATED_MAX];
    uint32_t matches = 0;

    Test_Case("caseTwoMatchesNameNeither");
    Test_ExpectStatus(PortLocate_Resolve(LOCATE_ROOT, "usb-serial:0001", device, (uint32_t)sizeof device, &matches),
                      ZB_ERR_BAD_ARGUMENT, "a serial two adapters share is refused rather than guessed");
    Test_ExpectCount(matches, 2, "and says how many carried it");
}

static void caseMissingTreeListsNothing(void)
{
    Seen seen;

    Test_Case("caseMissingTreeListsNothing");
    memset(&seen, 0, sizeof seen);
    Test_ExpectCount(PortLocate_Each(LOCATE_ROOT "/absent", seenAdd, &seen), 0, "a root with no sys lists nothing");
}

/* The platform's own list: read only, and whatever this host has plugged in. */
static void casePlatformListIsUsable(void)
{
    Seen seen;
    uint32_t i;
    int named = 1;

    Test_Case("casePlatformListIsUsable");
    memset(&seen, 0, sizeof seen);
    (void)PortLocate_Each(0, seenAdd, &seen);

    for (i = 0; i < seen.count && i < 8; i++)
    {
        if (seen.last[i].device[0] == 0 || seen.last[i].serial[0] == 0)
            named = 0;
    }

    Test_Expect(named, "every device this host lists has a node and a serial");
    printf("port_locate: this host lists %u USB serial device(s)\n", (unsigned)seen.count);
}

static void caseOpenOfAnAbsentSerialIsAGonePort(void)
{
    Port port;

    Test_Case("caseOpenOfAnAbsentSerialIsAGonePort");
    Port_Init(&port, PortPosixOps());
    Test_ExpectStatus(Port_Open(&port, "usb-serial:no-such-serial-anywhere", 0), ZB_ERR_NO_DEVICE,
                      "a selector nothing carries opens nothing");
    Test_Expect(Port_Fault(&port) == PORT_FAULT_DEVICE_GONE, "and the port reads as gone, which the stack opens again");
    Test_Expect(strcmp(Port_Path(&port), "usb-serial:no-such-serial-anywhere") == 0, "keeping the selector as its path");
    Port_Close(&port);
}

int main(void)
{
    Test_Begin("port_locate");

    caseSelectorIsItsPrefix();
    caseOnlyUsbTerminalsAreListed();
    caseBothLayoutsReadTheirDevice();
    caseSelectorResolvesToItsNode();
    caseMatchIsExact();
    caseMatchWithNoNodeIsNoDevice();
    caseTwoMatchesNameNeither();
    caseMissingTreeListsNothing();
    casePlatformListIsUsable();
    caseOpenOfAnAbsentSerialIsAGonePort();

    return Test_Report();
}
