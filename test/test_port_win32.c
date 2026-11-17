#include <string.h>

#include "port.h"
#include "port_locate.h"
#include "port_win32.h"
#include "test_harness.h"
#include "zb_time.h"

/* The Windows backend where no RCP is attached: the names it opens, what an absent device answers, the entropy, the
   clock and the files. The byte stream itself needs a COM port, and a stick on one is the bench's (docs/porting.md
   §3); Windows has no pseudo-terminal to stand in for it as the POSIX suite's does. */

static void caseAbsentDevice(void)
{
    Port port;
    uint32_t got;
    uint8_t buf[8];

    Port_Init(&port, PortWin32Ops());
    Test_Expect(Port_Open(&port, "COM199", 0) == ZB_ERR_NO_DEVICE, "an absent COM port reports ZB_ERR_NO_DEVICE");
    Test_Expect(Port_State(&port) == PORT_STATE_FAULT, "an absent device is a fault, not a silence");
    Test_Expect(Port_Fault(&port) == PORT_FAULT_DEVICE_GONE, "the reason is a gone device");
    Test_Expect(Port_PlatformErrno(&port) != 0, "the platform error is carried out");
    Test_Expect(Port_Read(&port, buf, sizeof buf, &got) == ZB_ERR_DEVICE_LOST,
           "a read after a failed open reports the loss");
    Port_Close(&port);

    Port_Init(&port, PortWin32Ops());
    Test_Expect(Port_Open(&port, "\\\\.\\COM199", 0) == ZB_ERR_NO_DEVICE,
           "a name already in the device namespace is opened as written, and answers the same");
    Test_Expect(Port_Fault(&port) == PORT_FAULT_DEVICE_GONE, "with the same reason");
    Port_Close(&port);
}

static void caseUnsupportedBaud(void)
{
    Port port;
    PortConfig config;

    memset(&config, 0, sizeof config);
    config.baud = 12345;
    Port_Init(&port, PortWin32Ops());
    Test_Expect(Port_Open(&port, "COM199", &config) == ZB_ERR_BAD_ARGUMENT,
           "a rate the POSIX backend cannot set is refused here too, before a device is touched");
    Test_Expect(Port_PlatformErrno(&port) == 0, "no platform call was made");
    Port_Close(&port);
}

/* A selector no device carries finds nothing; the enumeration it walks is the system's own and is only read. */
static void caseSelectorWithNoMatch(void)
{
    Port port;

    Port_Init(&port, PortWin32Ops());
    Test_Expect(Port_Open(&port, "usb-serial:NO-SUCH-SERIAL-0000", 0) == ZB_ERR_NO_DEVICE,
           "a serial number no USB device carries opens nothing");
    Test_Expect(Port_Fault(&port) == PORT_FAULT_DEVICE_GONE, "and is a gone device, as an absent name is");
    Port_Close(&port);
}

static void caseEntropyFillsAndRefusesWithoutWriting(void)
{
    Port port;
    uint8_t first[32];
    uint8_t second[32];
    uint8_t big[PORT_ENTROPY_MAX + 1];
    uint32_t i;

    memset(first, 0xa5, sizeof first);
    memset(second, 0xa5, sizeof second);
    memset(big, 0x5a, sizeof big);

    Port_Init(&port, PortWin32Ops());
    Test_Expect(Port_Entropy(&port, first, (uint32_t)sizeof first) == ZB_OK, "the system's generator answers");
    Test_Expect(Port_Entropy(&port, second, (uint32_t)sizeof second) == ZB_OK, "and answers again");
    Test_Expect(memcmp(first, second, sizeof first) != 0, "with other octets the second time");
    Test_Expect(Port_Entropy(&port, big, (uint32_t)sizeof big) == ZB_ERR_BAD_ARGUMENT,
           "a request above PORT_ENTROPY_MAX is refused at the door");

    for (i = 0; i < sizeof big && big[i] == 0x5a; i++)
        ;

    Test_Expect(i == sizeof big, "and nothing was written");
    Test_Expect(Port_Entropy(&port, big, PORT_ENTROPY_MAX) == ZB_OK, "the largest request is filled");
    Port_Close(&port);
}

static void caseSleepTakesItsTime(void)
{
    uint32_t before;

    before = Port_NowMs();
    Port_SleepMs(30);
    Test_Expect(Port_NowMs() - before >= 30, "a sleep of 30 ms takes at least 30 ms");
}

static void caseMonotonicClockAnswers(void)
{
    uint32_t first;
    uint32_t second;

    first = Port_NowMs();
    second = Port_NowMs();
    Test_Expect(Zb_timeReached(second, first) == 1,
           "the clock never reads earlier than the draw before it: the performance counter's own promise");
}

static void caseDefaultOpsAreThisTargets(void)
{
    Test_Expect(Port_DefaultOps() == PortWin32Ops(), "a Windows build's default ops are the Windows backend's");
    Test_Expect(strcmp(PortWin32Ops()->name, "win32") == 0, "and it names itself");
}

/* The files, shared with the POSIX suite (port_file_cases.c). */
void caseFileRoundTrip(void);

int main(void)
{
    Test_Begin("port_win32");

    caseAbsentDevice();
    caseUnsupportedBaud();
    caseSelectorWithNoMatch();
    caseEntropyFillsAndRefusesWithoutWriting();
    caseSleepTakesItsTime();
    caseMonotonicClockAnswers();
    caseDefaultOpsAreThisTargets();
    caseFileRoundTrip();

    return Test_Report();
}
