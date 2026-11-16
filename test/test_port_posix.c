#include <stdio.h>
#include <string.h>

#include "port.h"
#include "port_file.h"
#include "port_posix.h"
#include "test_harness.h"
#include "zb_time.h"

/* The bytes a Spinel link actually carries: flags, escapes, control octets and the
   802.15.4 values that a line discipline likes to translate (docs/internals/protocol.md §2). */
static const uint8_t s_wire[] = {
    0x7e, 0x80, 0x01, 0x02, 0x92, 0x7e,
    0x7d, 0x33, 0x11, 0x13, 0xf8, 0x00, 0xff,
    0x0d, 0x0a, 0x09, 0x04, 0x1c, 0x88, 0xde, 0x20, 0x27, 0x9e
};

static void caseAbsentDevice(void)
{
    Port port;
    uint32_t got;
    uint8_t buf[8];

    Port_Init(&port, PortPosixOps());
    Test_Expect(Port_Open(&port, "/dev/definitely-not-on-this-machine", 0) == ZB_ERR_NO_DEVICE,
           "an absent device reports ZB_ERR_NO_DEVICE");
    Test_Expect(Port_State(&port) == PORT_STATE_FAULT, "an absent device is a fault, not a silence");
    Test_Expect(Port_Fault(&port) == PORT_FAULT_DEVICE_GONE, "the reason is a gone device");
    Test_Expect(Port_PlatformErrno(&port) != 0, "the platform error is carried out");
    Test_Expect(Port_Read(&port, buf, sizeof buf, &got) == ZB_ERR_DEVICE_LOST,
           "a faulted port reports the loss on read");
    Port_Close(&port);
}

static void caseUnsupportedBaud(void)
{
    Port port;
    PortConfig config;

    config.baud = 12345;
    config.rxRingSize = 0;
    config.txRingSize = 0;
    config.exclusive = 1;

    Port_Init(&port, PortPosixOps());
    Test_Expect(Port_Open(&port, "/dev/port-posix", &config) == ZB_ERR_BAD_ARGUMENT,
           "a baud the platform cannot name is a bad argument");
    Port_Close(&port);
}

static void casePtyRawRoundTrip(void)
{
    Port port;
    int master;
    char slave[PORT_PATH_MAX];
    uint8_t buf[64];
    uint32_t got;
    uint32_t written;

    master = -1;
    memset(slave, 0, sizeof slave);

    if (PortPosix_PtyOpen(&master, slave, (uint32_t)sizeof slave) != ZB_OK)
    {
        printf("port_posix: no pseudo-terminal available, round-trip case skipped\n");
        return;
    }

    Port_Init(&port, PortPosixOps());
    Test_Expect(Port_Open(&port, slave, 0) == ZB_OK, "the slave side opens");
    Test_Expect(Port_IsOpen(&port), "the port is usable");
    Test_Expect(strcmp(Port_TargetName(&port), "posix") == 0, "the target names itself");
    Test_Expect(strcmp(Port_Path(&port), slave) == 0, "the path is the one supplied");

    /* A read with nothing pending is a normal empty answer, not a block and not an error. */
    Test_Expect(Port_Read(&port, buf, sizeof buf, &got) == ZB_OK, "an empty read answers ZB_OK");
    Test_Expect(got == 0, "an empty read transfers nothing");

    Test_Expect(Port_Write(&port, s_wire, (uint32_t)sizeof s_wire, &written) == ZB_OK,
           "the port writes to the device");
    Test_Expect(Port_TxPending(&port) == 0, "the write drained out of the ring");

    got = 0;

    while (got < (uint32_t)sizeof s_wire)
    {
        uint32_t chunk;

        if (PortPosix_PtyRead(master, &buf[got], (uint32_t)sizeof buf - got, &chunk) != ZB_OK)
            break;

        if (chunk == 0)
            break;

        got += chunk;
    }

    Test_Expect(got == (uint32_t)sizeof s_wire, "no octet was added or dropped on the way out");
    Test_Expect(memcmp(buf, s_wire, got) == 0, "raw 8N1: no translation of 7e 7d 11 13 f8 0d 0a");

    Test_Expect(PortPosix_PtyWrite(master, s_wire, (uint32_t)sizeof s_wire) == ZB_OK,
           "the master can write");

    got = 0;

    {
        uint32_t total;
        total = 0;

        while (total < (uint32_t)sizeof s_wire)
        {
            uint32_t chunk;

            if (Port_Read(&port, &buf[total], (uint32_t)sizeof buf - total, &chunk) != ZB_OK)
                break;

            if (chunk == 0)
                break;

            total += chunk;
        }

        Test_Expect(total == (uint32_t)sizeof s_wire, "every octet arrived on the inbound ring");
        Test_Expect(memcmp(buf, s_wire, total) == 0, "raw 8N1: no translation on the way in");
    }

    Port_Close(&port);
    PortPosix_PtyClose(master);
}

/* Port_Wait sleeps on the device rather than on a clock: nothing pending, it returns once its limit has passed,
   and a device that sent something wakes it at once, the octets then on the ring. */
static void caseWaitWakesOnInput(void)
{
    Port port;
    int master;
    char slave[PORT_PATH_MAX];
    uint8_t buf[16];
    uint32_t before;
    uint32_t after;
    uint32_t got;

    master = -1;
    memset(slave, 0, sizeof slave);

    if (PortPosix_PtyOpen(&master, slave, (uint32_t)sizeof slave) != ZB_OK)
    {
        printf("port_posix: no pseudo-terminal available, wait case skipped\n");
        return;
    }

    Port_Init(&port, PortPosixOps());
    Test_Expect(Port_Open(&port, slave, 0) == ZB_OK, "the slave side opens");

    before = Port_NowMs();
    Test_Expect(Port_Wait(&port, 40) == ZB_OK, "a wait with nothing pending answers ZB_OK");
    after = Port_NowMs();
    Test_Expect(after - before >= 30, "and returns once its limit has passed, not at once");

    Test_Expect(PortPosix_PtyWrite(master, s_wire, (uint32_t)sizeof s_wire) == ZB_OK, "the device sends");
    before = Port_NowMs();
    Test_Expect(Port_Wait(&port, 5000) == ZB_OK, "a wait with input pending answers ZB_OK");
    after = Port_NowMs();
    Test_Expect(after - before < 1000, "and returns long before its limit");
    Test_Expect(Port_Read(&port, buf, (uint32_t)sizeof buf, &got) == ZB_OK && got > 0, "with the octets to read");

    Port_Close(&port);
    PortPosix_PtyClose(master);

    Test_Expect(Port_Wait(&port, 10) == ZB_ERR_NOT_OPEN, "a closed port has nothing to wait on");
}

static void caseExclusiveOpen(void)
{
    Port first;
    Port second;
    PortConfig config;
    int master;
    char slave[PORT_PATH_MAX];
    ZbStatus refused;

    master = -1;
    memset(slave, 0, sizeof slave);

    if (PortPosix_PtyOpen(&master, slave, (uint32_t)sizeof slave) != ZB_OK)
    {
        printf("port_posix: no pseudo-terminal available, exclusivity case skipped\n");
        return;
    }

    config.baud = 0;
    config.rxRingSize = 0;
    config.txRingSize = 0;
    config.exclusive = 1;

    Port_Init(&first, PortPosixOps());
    Port_Init(&second, PortPosixOps());

    Test_Expect(Port_Open(&first, slave, &config) == ZB_OK, "the first open succeeds");
    refused = Port_Open(&second, slave, &config);
    printf("  observed: a second exclusive open of the same device answered status %d, "
           "fault %d, errno %u\n", (int)refused, (int)Port_Fault(&second),
           Port_PlatformErrno(&second));
    printf("  (not asserted here: what the platform enforces is the platform's)");

    Port_Close(&first);
    Port_Close(&second);
    PortPosix_PtyClose(master);
}

static void caseTwoPortsOnTwoDevices(void)
{
    Port a;
    Port b;
    int masterA;
    int masterB;
    char slaveA[PORT_PATH_MAX];
    char slaveB[PORT_PATH_MAX];
    uint8_t bytesA[16];
    uint8_t bytesB[24];
    uint8_t buf[64];
    uint32_t got;
    uint32_t written;
    uint32_t i;

    masterA = -1;
    masterB = -1;
    memset(slaveA, 0, sizeof slaveA);
    memset(slaveB, 0, sizeof slaveB);

    if (PortPosix_PtyOpen(&masterA, slaveA, (uint32_t)sizeof slaveA) != ZB_OK ||
        PortPosix_PtyOpen(&masterB, slaveB, (uint32_t)sizeof slaveB) != ZB_OK)
    {
        printf("port_posix: no pseudo-terminal available, two-port case skipped\n");
        return;
    }

    for (i = 0; i < sizeof bytesA; i++)
        bytesA[i] = (uint8_t)(0x40 + i);

    for (i = 0; i < sizeof bytesB; i++)
        bytesB[i] = (uint8_t)(0x90 + i);

    Port_Init(&a, PortPosixOps());
    Port_Init(&b, PortPosixOps());
    Test_Expect(Port_Open(&a, slaveA, 0) == ZB_OK, "first device opens");
    Test_Expect(Port_Open(&b, slaveB, 0) == ZB_OK, "second device opens");

    Test_Expect(Port_Write(&a, bytesA, sizeof bytesA, &written) == ZB_OK, "port a writes");
    Test_Expect(Port_Write(&b, bytesB, sizeof bytesB, &written) == ZB_OK, "port b writes");

    got = 0;
    Test_Expect(PortPosix_PtyRead(masterA, buf, sizeof buf, &got) == ZB_OK && got == sizeof bytesA,
           "port a reached only its own device");
    Test_Expect(got == sizeof bytesA && memcmp(buf, bytesA, got) == 0, "port a's bytes are intact");

    got = 0;
    Test_Expect(PortPosix_PtyRead(masterB, buf, sizeof buf, &got) == ZB_OK && got == sizeof bytesB,
           "port b reached only its own device");
    Test_Expect(got == sizeof bytesB && memcmp(buf, bytesB, got) == 0, "port b's bytes are intact");

    Port_Close(&a);
    Port_Close(&b);
    PortPosix_PtyClose(masterA);
    PortPosix_PtyClose(masterB);
}

/*
 * The host's entropy source, through the one contract entry here. Three things are
 * asserted: octets arrive, the sentinels that were in the buffer beforehand are gone, and a request the
 * contract cannot answer writes nothing at all.
 *
 * Two successive 32-octet draws are compared because two independent draws from the host's source landing on
 * all 256 bits of the same pattern is 2^-256: a collision this suite could not manufacture and does not need
 * to repeat to rule out. The sentinel test is stated the same way: each of 32 prefilled octets has a
 * 1-in-256 chance of surviving unchanged, so requiring 24 of them to move leaves a flake probability under
 * 1e-11 rather than a coin flip on one octet.
 */
static void caseEntropyFillsAndRefusesWithoutWriting(void)
{
    Port port;
    uint8_t first[32];
    uint8_t second[32];
    uint8_t sentinel[32];
    uint32_t i;
    uint32_t changed;
    uint32_t moved;

    for (i = 0; i < sizeof first; i++)
    {
        first[i] = 0xa5;
        second[i] = 0xa5;
        sentinel[i] = 0x5a;
    }

    Port_Init(&port, PortPosixOps());

    Test_Expect(Port_IsOpen(&port) == 0, "no device is open: entropy is not the byte stream and the contract does not ask for one");
    Test_Expect(Port_Entropy(&port, first, (uint32_t)sizeof first) == ZB_OK, "the host's entropy source answers");

    changed = 0;

    for (i = 0; i < sizeof first; i++)
    {
        if (first[i] != 0xa5)
            changed++;
    }

    Test_Expect(changed >= 24, "and the buffer was really written: 24 of 32 sentinel octets moved");

    Test_Expect(Port_Entropy(&port, second, (uint32_t)sizeof second) == ZB_OK, "a second draw answers too");
    Test_Expect(memcmp(first, second, sizeof first) != 0,
           "and two successive draws differ, which no scripted fixture would have to be told is not a repeat");

    Test_Expect(Port_Entropy(&port, sentinel, 0) == ZB_OK, "a request for nothing is answered ZB_OK");

    moved = 0;

    for (i = 0; i < sizeof sentinel; i++)
    {
        if (sentinel[i] != 0x5a)
            moved++;
    }

    Test_Expect(moved == 0, "and it wrote nothing: every sentinel octet is where it was");

    Test_Expect(Port_Entropy(&port, sentinel, 1048576) == ZB_ERR_BAD_ARGUMENT,
           "a length above PORT_ENTROPY_MAX is refused at the door, before the platform is asked");
    Test_Expect(Port_Entropy(&port, 0, 8) == ZB_ERR_BAD_ARGUMENT, "and a buffer that is not there is refused outright");

    moved = 0;

    for (i = 0; i < sizeof sentinel; i++)
    {
        if (sentinel[i] != 0x5a)
            moved++;
    }

    Test_Expect(moved == 0, "and neither refusal touched the caller's buffer: a refusal here is a refusal, not a partial fill");
    Test_Expect(Port_Fault(&port) == PORT_FAULT_NONE && Port_State(&port) == PORT_STATE_CLOSED,
           "and an entropy refusal leaves the port exactly as it was: no fault record, no state change");
    Test_Expect(Port_Refusals(&port) == 0 && Port_Drops(&port) == 0,
           "and it is not counted as a write that found the device busy: the two counters stay clear");
}

/*
 * The host's own monotonic clock (docs/porting.md §4, D-277): clock_gettime(CLOCK_MONOTONIC) read as milliseconds.
 * What it answers is the host's business (the epoch is arbitrary and no assertion here reads a number out of it), so
 * what is asserted is the contract's own promise: no port is needed, and it never reads earlier than the draw before it.
 */
/* A device whose other end went away, as a pulled RCP's does: the wait says so, with no write to find it out. */
static void caseWaitSeesAHungUpLine(void)
{
    Port port;
    int master;
    char slave[PORT_PATH_MAX];
    uint8_t buf[16];
    uint32_t got;

    master = -1;
    memset(slave, 0, sizeof slave);

    if (PortPosix_PtyOpen(&master, slave, (uint32_t)sizeof slave) != ZB_OK)
    {
        printf("port_posix: no pseudo-terminal available, hang-up case skipped\n");
        return;
    }

    Port_Init(&port, PortPosixOps());
    Test_Expect(Port_Open(&port, slave, 0) == ZB_OK, "the slave side opens");
    Test_Expect(PortPosix_PtyWrite(master, s_wire, (uint32_t)sizeof s_wire) == ZB_OK, "the device sends");
    PortPosix_PtyClose(master);

    (void)Port_Wait(&port, 100);
    (void)Port_Wait(&port, 100);
    Test_Expect(Port_Fault(&port) == PORT_FAULT_DEVICE_GONE, "a wait on a hung-up line finds the device gone");
    Test_Expect(Port_Read(&port, buf, (uint32_t)sizeof buf, &got) == ZB_ERR_DEVICE_LOST || got > 0,
                "and a read answers what it last sent, or that it is lost");

    Port_Close(&port);
}

/* The platform's sleep, for a loop with no port to wait on. */
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
           "the clock never reads earlier than the draw before it: CLOCK_MONOTONIC's own promise, and the reason a deadline may be a subtraction");
}

/* A POSIX build's default ops are the POSIX backend's, so a host program reaches them with no platform header. */
static void caseDefaultOpsAreThisTargets(void)
{
    Test_Expect(Port_DefaultOps() == PortPosixOps(), "a POSIX build's default ops are the POSIX backend's");
}

#define SCRATCH_FILE ZB_SCRATCH_DIR "/port_posix_scratch.bin"
#define SCRATCH_MISSING ZB_SCRATCH_DIR "/port_posix_missing.bin"
#define SCRATCH_RENAMED ZB_SCRATCH_DIR "/port_posix_renamed.bin"

/* The POSIX files (docs/porting.md §3): a missing file does not open for reading, a write creates and empties, what was written
   reads back from any position, a mode refuses the direction it does not allow, and a rename replaces in one step. */
static void caseFileRoundTrip(void)
{
    static const uint8_t first[] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
    static const uint8_t second[] = { 0xaa, 0xbb };
    PortFile file;
    uint8_t buf[16];
    uint32_t got = 0;
    uint32_t size = 0;

    (void)Port_FileDelete(SCRATCH_MISSING);
    Test_Expect(Port_FileOpen(&file, SCRATCH_MISSING, PORT_FILE_READ) == 0, "a missing file does not open for reading");
    Test_Expect(file.mode == 0 && file.platformErrno != 0, "and is left closed, the platform's error kept");
    Test_Expect(Port_FileExists(SCRATCH_MISSING) == 0, "nor is it there");

    Test_Expect(Port_FileOpen(&file, SCRATCH_FILE, PORT_FILE_WRITE) == 1, "write mode creates the file");
    Test_Expect(Port_FileWrite(&file, first, (uint32_t)sizeof first, &got) == 1 && got == sizeof first,
                "every octet is written");
    Test_Expect(Port_FileRead(&file, buf, (uint32_t)sizeof buf, &got) == 0 && got == 0,
                "write mode refuses a read");
    Port_FileClose(&file);
    Port_FileClose(&file);
    Test_Expect(file.mode == 0, "a closed file is closed, and closing it again does nothing");
    Test_Expect(Port_FileExists(SCRATCH_FILE) == 1, "the file is there");

    Test_Expect(Port_FileOpen(&file, SCRATCH_FILE, PORT_FILE_READ) == 1, "it opens for reading");
    Test_Expect(Port_FileSize(&file, &size) == 1 && size == sizeof first, "with the size written");
    Test_Expect(Port_FileRead(&file, buf, (uint32_t)sizeof buf, &got) == 1 && got == sizeof first
                && memcmp(buf, first, sizeof first) == 0, "and the octets read back");
    Test_Expect(Port_FileRead(&file, buf, (uint32_t)sizeof buf, &got) == 1 && got == 0,
                "at the end a read succeeds with nothing");
    Test_Expect(Port_FileSeek(&file, 4) == 1 && Port_FileRead(&file, buf, 1, &got) == 1 && got == 1 && buf[0] == 0x50,
                "a seek moves the position from the start");
    Test_Expect(Port_FileWrite(&file, second, (uint32_t)sizeof second, &got) == 0 && got == 0,
                "read mode refuses a write");
    Port_FileClose(&file);

    Test_Expect(Port_FileOpen(&file, SCRATCH_FILE, PORT_FILE_READ_WRITE) == 1, "read-write keeps the file");
    Test_Expect(Port_FileSeek(&file, 2) == 1 && Port_FileWrite(&file, second, (uint32_t)sizeof second, &got) == 1,
                "and writes in place");
    Test_Expect(Port_FileSeek(&file, 0) == 1 && Port_FileRead(&file, buf, (uint32_t)sizeof buf, &got) == 1
                && got == sizeof first && buf[1] == 0x20 && buf[2] == 0xaa && buf[3] == 0xbb && buf[4] == 0x50,
                "what it wrote replaces those octets and leaves the rest");
    Port_FileClose(&file);

    Test_Expect(Port_FileOpen(&file, SCRATCH_FILE, PORT_FILE_WRITE) == 1 && Port_FileSize(&file, &size) == 1 && size == 0,
                "write mode empties an existing file");
    Port_FileClose(&file);
    Test_Expect(Port_FileSeek(&file, 0) == 0 && Port_FileSize(&file, &size) == 0, "a closed file answers nothing");
    Test_Expect(Port_FileOpen(&file, SCRATCH_FILE, 4) == 0, "an unknown mode does not open");

    Test_Expect(Port_FileOpen(&file, SCRATCH_RENAMED, PORT_FILE_WRITE) == 1
                && Port_FileWrite(&file, second, (uint32_t)sizeof second, &got) == 1, "a second file is written");
    Test_Expect(Port_FileSync(&file) == 1, "and synced through to its storage");
    Port_FileClose(&file);
    Test_Expect(Port_FileSync(&file) == 0, "a closed file has nothing to sync");
    Test_Expect(Port_FileOpen(&file, SCRATCH_RENAMED, PORT_FILE_READ) == 1 && Port_FileSync(&file) == 0,
                "and a file opened to read is not one this call writes through");
    Port_FileClose(&file);
    Test_Expect(Port_FileRename(SCRATCH_RENAMED, SCRATCH_FILE) == 1 && Port_FileExists(SCRATCH_RENAMED) == 0,
                "a rename moves it to the first one's name");
    Test_Expect(Port_FileOpen(&file, SCRATCH_FILE, PORT_FILE_READ) == 1 && Port_FileSize(&file, &size) == 1
                && size == sizeof second, "and replaces the file that was there");
    Port_FileClose(&file);
    Test_Expect(Port_FileRename(SCRATCH_MISSING, SCRATCH_FILE) == 0 && Port_FileExists(SCRATCH_FILE) == 1,
                "a rename from a missing file fails and leaves the target alone");

    Test_Expect(Port_FileDelete(SCRATCH_FILE) == 1 && Port_FileExists(SCRATCH_FILE) == 0, "a delete removes the file");
    Test_Expect(Port_FileDelete(SCRATCH_FILE) == 0, "and a second delete finds nothing to remove");
    Test_Expect(Port_FileExists(ZB_SCRATCH_DIR) == 0, "a directory is not a file");
}

int main(void)
{
    Test_Begin("port_posix");

    caseAbsentDevice();
    caseUnsupportedBaud();
    casePtyRawRoundTrip();
    caseWaitWakesOnInput();
    caseWaitSeesAHungUpLine();
    caseSleepTakesItsTime();
    caseExclusiveOpen();
    caseTwoPortsOnTwoDevices();
    caseEntropyFillsAndRefusesWithoutWriting();
    caseMonotonicClockAnswers();
    caseDefaultOpsAreThisTargets();
    caseFileRoundTrip();

    return Test_Report();
}
