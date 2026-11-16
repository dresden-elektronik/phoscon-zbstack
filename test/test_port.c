#include <string.h>

#include "port.h"
#include "port_null.h"
#include "port_win32.h"
#include "test_harness.h"

#define TRANSCRIPT_LEN 900
#define NO_INJECTION   0xffffffff

static void buildTranscript(uint8_t *out, uint32_t len)
{
    uint32_t i;

    for (i = 0; i < len; i++)
        out[i] = (uint8_t)((i * 37 + 11) & 0xff);
}

static void scriptDefaults(PortNullScript *script, const uint8_t *bytes, uint32_t len)
{
    memset(script, 0, sizeof *script);
    script->rxBytes = bytes;
    script->rxLen = len;
    script->failPumpAfter = NO_INJECTION;
    script->failDrainAfter = NO_INJECTION;
}

static void openPort(Port *port, PortNullScript *script, const char *path,
                     uint32_t rxSize, uint32_t txSize)
{
    PortConfig config;
    config.baud = 0;
    config.rxRingSize = rxSize;
    config.txRingSize = txSize;
    config.exclusive = 1;

    Port_Init(port, PortNullOps());
    PortNull_Attach(port, script);
    Test_Expect(Port_Open(port, path, &config) == ZB_OK, "open succeeds");
    Test_Expect(Port_IsOpen(port), "port reports open");
}

static uint32_t drainPort(Port *port, uint8_t *out, uint32_t cap)
{
    uint8_t buf[256];
    uint32_t total;
    uint32_t got;

    total = 0;

    for (;;)
    {
        if (Port_Read(port, buf, sizeof buf, &got) != ZB_OK)
            break;

        if (got == 0)
            break;

        if (total + got > cap)
            break;

        memcpy(&out[total], buf, got);
        total += got;
    }

    return total;
}

static void caseInitDefaults(void)
{
    Port port;

    Test_Expect(Port_Init(&port, PortNullOps()) == ZB_OK, "init ok");
    Test_Expect(Port_Init(&port, 0) == ZB_ERR_BAD_ARGUMENT, "init needs an ops table");
    Test_Expect(Port_State(&port) == PORT_STATE_CLOSED, "a fresh port is closed");
    Test_Expect(Port_RxRingSize(&port) == PORT_RX_RING_DEFAULT, "default rx ring");
    Test_Expect(Port_TxRingSize(&port) == PORT_TX_RING_DEFAULT, "default tx ring");
    Test_Expect(Port_Drops(&port) == 0 && Port_Refusals(&port) == 0, "counters start clear");
}

static void config_baud(Port *port, PortNullScript *script, uint32_t baud,
                        uint32_t rxSize, uint32_t txSize, int exclusive)
{
    PortConfig config;
    config.baud = baud;
    config.rxRingSize = rxSize;
    config.txRingSize = txSize;
    config.exclusive = exclusive;
    Port_Init(port, PortNullOps());
    PortNull_Attach(port, script);
    Test_Expect(Port_Open(port, "/dev/port-null", &config) == ZB_OK, "explicit config opens");
}

static void caseNoDefaultPath(void)
{
    static char longPath[PORT_PATH_MAX + 1];
    Port port;
    PortNullScript script;
    uint8_t buf[16];
    uint32_t got;

    scriptDefaults(&script, 0, 0);
    Port_Init(&port, PortNullOps());
    PortNull_Attach(&port, &script);

    Test_Expect(Port_Open(&port, 0, 0) == ZB_ERR_BAD_ARGUMENT, "a null path is refused");
    Test_Expect(Port_Open(&port, "", 0) == ZB_ERR_BAD_ARGUMENT, "an empty path is refused");
    memset(longPath, 'a', sizeof longPath - 1);
    longPath[sizeof longPath - 1] = '\0';
    Test_Expect(Port_Open(&port, longPath, 0) == ZB_ERR_BAD_ARGUMENT, "an over-long path is refused");
    Test_Expect(Port_Path(&port)[0] == '\0', "no path is invented");
    Test_Expect(Port_State(&port) == PORT_STATE_CLOSED, "refused opens leave the port closed");
    Test_Expect(Port_Read(&port, buf, sizeof buf, &got) == ZB_ERR_NOT_OPEN, "closed port refuses reads");
}

static void caseRingArguments(void)
{
    Port port;
    PortNullScript script;
    PortConfig config;

    config.baud = 0;
    config.exclusive = 1;
    scriptDefaults(&script, 0, 0);

    config.rxRingSize = 300;
    config.txRingSize = 0;
    Port_Init(&port, PortNullOps());
    PortNull_Attach(&port, &script);
    Test_Expect(Port_Open(&port, "/dev/port-null", &config) == ZB_ERR_BAD_ARGUMENT,
           "a non power-of-two ring is refused");

    config.rxRingSize = 0;
    config.txRingSize = PORT_TX_RING_MAX * 2;
    Port_Init(&port, PortNullOps());
    PortNull_Attach(&port, &script);
    Test_Expect(Port_Open(&port, "/dev/port-null", &config) == ZB_ERR_BAD_ARGUMENT,
           "a ring larger than the fixed pool is refused");

    Test_Expect(PORT_TX_RING_DEFAULT >= PORT_FRAME_MAX * 2,
           "the default transmit ring holds a frame whose every octet had to be escaped");

    config.rxRingSize = 128;
    config.txRingSize = 64;
    openPort(&port, &script, "/dev/port-null", 128, 64);
    Test_Expect(Port_RxRingSize(&port) == 128, "a ring may shrink");
    Test_Expect(Port_TxRingSize(&port) == 64, "the tx ring may shrink");
    Port_Close(&port);
}

/* A Linux by-id name is the stable one and runs past 64 characters; a ConBee II's is 88. */
static void caseByIdPathOpens(void)
{
    static const char byId[] = "/dev/serial/by-id/usb-dresden_elektronik_ingenieurtechnik_GmbH_ConBee_II_DE1000001-if00";
    Port port;
    PortNullScript script;

    scriptDefaults(&script, 0, 0);
    Port_Init(&port, PortNullOps());
    PortNull_Attach(&port, &script);
    Test_Expect(Port_Open(&port, byId, 0) == ZB_OK, "a by-id path opens");
    Test_Expect(strcmp(Port_Path(&port), byId) == 0, "and is kept whole");
    Port_Close(&port);
}

static void caseDefaultsReachTheDevice(void)
{
    Port port;
    PortNullScript script;

    scriptDefaults(&script, 0, 0);
    Port_Init(&port, PortNullOps());
    PortNull_Attach(&port, &script);
    Test_Expect(Port_Open(&port, "/dev/port-null", 0) == ZB_OK, "open with no config succeeds");
    Test_Expect(script.seenBaud == PORT_BAUD_LINK, "no config means the measured link baud");
    Test_Expect(script.seenExclusive == 1, "exclusivity is requested unless told otherwise");
    Test_Expect(script.seenRxRing == PORT_RX_RING_DEFAULT, "the default rx ring is passed down");
    Test_Expect(script.seenTxRing == PORT_TX_RING_DEFAULT, "the default tx ring is passed down");
    Port_Close(&port);

    config_baud(&port, &script, 9600, 0, 0, 0);
    Test_Expect(script.seenBaud == 9600, "an explicit baud is passed through");
    Test_Expect(script.seenExclusive == 0, "an explicit non-exclusive open is honoured");
    Port_Close(&port);
}

static void caseEmptyReadIsNotAnError(void)
{
    Port port;
    PortNullScript script;
    uint8_t buf[32];
    uint32_t got;

    scriptDefaults(&script, 0, 0);
    openPort(&port, &script, "/dev/port-null", 0, 0);
    Test_Expect(Port_Read(&port, buf, sizeof buf, &got) == ZB_OK, "an empty read is ZB_OK");
    Test_Expect(got == 0, "an empty read transfers zero bytes");
    Port_Close(&port);
}

static void caseSplitInvariance(const uint8_t *transcript, uint32_t len)
{
    static const uint32_t chunks[] = { 1, 3, 7, 13, 256, 0 };
    static uint8_t collected[TRANSCRIPT_LEN];
    uint32_t c;

    for (c = 0; c < sizeof chunks / sizeof chunks[0]; c++)
    {
        Port port;
        PortNullScript script;
        uint32_t total;

        scriptDefaults(&script, transcript, len);
        script.rxChunk = chunks[c];
        openPort(&port, &script, "/dev/port-null", 0, 0);

        total = drainPort(&port, collected, sizeof collected);
        Test_Expect(total == len, "every split delivers the whole transcript");
        Test_Expect(memcmp(collected, transcript, len) == 0, "byte order preserved across splits");
        Test_Expect(Port_Drops(&port) == 0, "a drained transcript loses nothing");
        Port_Close(&port);
    }
}

static void caseOverflowKeepsOldest(void)
{
    Port port;
    PortNullScript script;
    static uint8_t transcript[TRANSCRIPT_LEN];
    static uint8_t collected[TRANSCRIPT_LEN];
    uint32_t accepted;
    uint32_t total;

    buildTranscript(transcript, TRANSCRIPT_LEN);
    scriptDefaults(&script, 0, 0);
    openPort(&port, &script, "/dev/port-null", 256, 0);

    /* A device that hands over more than the ring holds. */
    accepted = Port_PushRx(&port, transcript, TRANSCRIPT_LEN);
    Test_Expect(accepted == 256, "only a ring-full is accepted");
    Test_Expect(Port_RxPending(&port) == 256, "the ring is full");
    Test_Expect(Port_Drops(&port) == TRANSCRIPT_LEN - 256, "the newest bytes are the ones lost");

    total = drainPort(&port, collected, sizeof collected);
    Test_Expect(total == 256, "the ring hands over what it kept");
    Test_Expect(memcmp(collected, transcript, 256) == 0, "the oldest bytes survived");

    Test_Expect(Port_PushRx(&port, transcript, 8) == 8, "a freed ring accepts again");
    Port_Close(&port);
    Test_Expect(Port_Drops(&port) == 0 && Port_Refusals(&port) == 0, "close resets the counters");
}

static void caseIndexWrap(void)
{
    Port port;
    PortNullScript script;
    static uint8_t transcript[300];
    static uint8_t collected[300];
    uint32_t accepted;
    uint32_t total;

    buildTranscript(transcript, sizeof transcript);
    scriptDefaults(&script, 0, 0);
    openPort(&port, &script, "/dev/port-null", 256, 0);

    Port_TestPrimeRing(&port, 0xfffffff0, 0xfffffff0);

    accepted = Port_PushRx(&port, transcript, 300);
    Test_Expect(accepted == 256, "push works across the counter wrap");
    Test_Expect(Port_RxPending(&port) == 256, "occupancy is right across the wrap");
    total = drainPort(&port, collected, sizeof collected);
    Test_Expect(total == 256, "pop works across the counter wrap");
    Test_Expect(memcmp(collected, transcript, 256) == 0, "bytes are right across the wrap");
    Port_Close(&port);
}

static void caseWriteIsAtomic(void)
{
    Port port;
    PortNullScript script;
    static uint8_t payload[PORT_FRAME_MAX];
    static uint8_t captured[PORT_FRAME_MAX * 2];
    uint32_t written;
    uint32_t pendingBefore;

    buildTranscript(payload, sizeof payload);
    scriptDefaults(&script, 0, 0);
    script.txCapture = captured;
    script.txCapacity = sizeof captured;
    script.txRateLimit = 64;     /* a device that takes 64 bytes per drain */

    openPort(&port, &script, "/dev/port-null", 0, 128);

    Test_Expect(Port_Write(&port, payload, 128, &written) == ZB_OK && written == 128,
           "a whole write is accepted");
    Test_Expect(PortNull_Captured(&port) == 64, "a slow device drained its share");
    Test_Expect(Port_TxPending(&port) == 64, "the rest waits in the ring");

    pendingBefore = Port_TxPending(&port);
    Test_Expect(Port_Write(&port, payload, 128, &written) == ZB_ERR_BUSY,
           "a write that does not fit entirely is refused");
    Test_Expect(written == 0, "a refusal transfers nothing");
    Test_Expect(Port_TxPending(&port) == pendingBefore, "a refusal leaves the ring untouched");
    Test_Expect(Port_Refusals(&port) == 1, "a refusal is counted");

    Test_Expect(Port_Write(&port, payload, 129, &written) == ZB_ERR_BAD_ARGUMENT,
           "a frame larger than the tx ring is refused outright");
    Test_Expect(Port_Write(&port, payload, 0, &written) == ZB_ERR_BAD_ARGUMENT,
           "a zero-length write is a bad argument");
    Test_Expect(Port_Write(&port, 0, 8, &written) == ZB_ERR_BAD_ARGUMENT, "a null buffer is refused");
    Test_Expect(PortNull_Overflow(&port) == 0, "nothing was silently discarded");

    Port_Close(&port);
    Test_Expect(Port_Write(&port, payload, 16, &written) == ZB_ERR_NOT_OPEN,
           "a closed port refuses writes");
}

static void caseReadFaultAndLost(void)
{
    Port port;
    PortNullScript script;
    static uint8_t transcript[32];
    uint8_t buf[64];
    uint32_t got;

    buildTranscript(transcript, sizeof transcript);
    scriptDefaults(&script, transcript, sizeof transcript);
    script.failPumpAfter = 1;
    script.platformErrno = 5;
    openPort(&port, &script, "/dev/port-null", 0, 0);

    Test_Expect(Port_Read(&port, buf, sizeof buf, &got) == ZB_OK && got == 32,
           "the first pump succeeds");
    Test_Expect(Port_Read(&port, buf, sizeof buf, &got) == ZB_ERR_DEVICE_LOST,
           "a failing pump reports the loss");
    Test_Expect(Port_State(&port) == PORT_STATE_FAULT, "a read fault enters the fault state");
    Test_Expect(Port_Fault(&port) == PORT_FAULT_READ, "the fault reason is read");
    Test_Expect(Port_PlatformErrno(&port) == 5, "the platform error is carried out");
    Test_Expect(Port_Read(&port, buf, sizeof buf, &got) == ZB_ERR_DEVICE_LOST,
           "a faulted port stays faulted until it is closed");
    Port_Close(&port);
}

static void caseBufferedBytesSurviveAFault(void)
{
    Port port;
    PortNullScript script;
    static uint8_t pushed[40];
    static uint8_t collected[64];
    uint32_t got;
    uint32_t total;

    buildTranscript(pushed, sizeof pushed);
    scriptDefaults(&script, 0, 0);
    script.failPumpAfter = 0;      /* the very first pump fails */
    openPort(&port, &script, "/dev/port-null", 0, 0);

    Port_PushRx(&port, pushed, sizeof pushed);
    Test_Expect(Port_Read(&port, collected, sizeof collected, &got) == ZB_OK,
           "buffered bytes are handed over even after the device faults");
    total = got;
    Test_Expect(total == sizeof pushed, "the buffered bytes are complete");
    Test_Expect(memcmp(collected, pushed, total) == 0, "the buffered bytes are intact");
    Test_Expect(Port_State(&port) == PORT_STATE_FAULT, "the fault was still recorded");
    Port_Close(&port);
}

static void caseWriteFault(void)
{
    Port port;
    PortNullScript script;
    static uint8_t payload[16];
    uint32_t written;

    buildTranscript(payload, sizeof payload);
    scriptDefaults(&script, 0, 0);
    script.failDrainAfter = 0;     /* the device refuses to take anything */
    script.platformErrno = 5;
    openPort(&port, &script, "/dev/port-null", 0, 0);

    Test_Expect(Port_Write(&port, payload, sizeof payload, &written) == ZB_ERR_DEVICE_LOST,
           "a failing drain is reported to the caller");
    Test_Expect(written == sizeof payload, "the bytes were accepted into the ring first");
    Test_Expect(Port_State(&port) == PORT_STATE_FAULT, "a write fault enters the fault state");
    Test_Expect(Port_Fault(&port) == PORT_FAULT_WRITE, "the fault reason is write");
    Port_Close(&port);
}

/*
 * Scripted entropy on the null port: the bytes are the suite's, consumed in call order, and running out is
 * a refusal with a count rather than a short fill (docs/internals/coding-rules.md §4.3). Nothing here is drawn from a
 * host, which is the point of the scripted backend: a suite can name the octets a caller got.
 */
static void caseScriptedEntropyIsConsumedInOrder(void)
{
    static const uint8_t entropyScript[10] =
    {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
    };
    Port port;
    PortNullScript script;
    static uint8_t transcript[16];
    static uint8_t collected[32];
    uint8_t out[8];
    uint32_t i;
    uint32_t got;
    uint32_t total;

    buildTranscript(transcript, sizeof transcript);
    scriptDefaults(&script, transcript, sizeof transcript);
    script.entropyBytes = entropyScript;
    script.entropyLen = (uint32_t)sizeof entropyScript;
    openPort(&port, &script, "/dev/port-null", 0, 0);

    for (i = 0; i < sizeof out; i++)
        out[i] = 0xa5;

    Test_Expect(Port_Entropy(&port, out, 3) == ZB_OK, "the scripted entropy answers");
    Test_Expect(out[0] == 0x10 && out[1] == 0x11 && out[2] == 0x12, "exactly as it was scripted, in script order");
    Test_Expect(out[3] == 0xa5, "and only as far as the request went: the rest of the caller's buffer is the caller's");

    Test_Expect(Port_Entropy(&port, out, 2) == ZB_OK, "the next call continues where the last one stopped");
    Test_Expect(out[0] == 0x13 && out[1] == 0x14, "consumed per call, not restarted per call");

    out[0] = 0x5a;
    Test_Expect(Port_Entropy(&port, out, 6) == ZB_ERR_NO_SPACE,
           "a request past the remaining script is refused with the house refusal-and-count");
    Test_Expect(out[0] == 0x5a, "and the caller's buffer is untouched by the refusal");
    Test_Expect(script.entropyRefused == 1 && script.entropyPos == 5,
           "the refusal is counted and consumed nothing");

    Test_Expect(Port_Entropy(&port, out, 0) == ZB_OK, "a zero length is a no-op ZB_OK");
    Test_Expect(script.entropyPos == 5 && script.entropyRefused == 1, "and it moved neither the script nor the count");

    Test_Expect(Port_Entropy(&port, out, 4) == ZB_OK && out[0] == 0x15 && out[3] == 0x18,
           "the rest of the script is still there, in order");
    Test_Expect(Port_Entropy(&port, out, 1) == ZB_OK && out[0] == 0x19, "to the last scripted octet");
    Test_Expect(Port_Entropy(&port, out, 1) == ZB_ERR_NO_SPACE && script.entropyRefused == 2,
           "and one past it is out of script");

    total = drainPort(&port, collected, sizeof collected);
    Test_Expect(total == sizeof transcript && memcmp(collected, transcript, total) == 0,
           "the transcript is a separate script: entropy consumption took nothing off it");
    got = Port_Drops(&port);
    Test_Expect(got == 0, "and nothing was lost to make room for either");
    Port_Close(&port);

    scriptDefaults(&script, 0, 0);
    openPort(&port, &script, "/dev/port-null", 0, 0);
    out[0] = 0x5a;
    Test_Expect(Port_Entropy(&port, out, 1) == ZB_ERR_NO_SPACE,
           "a null port with no entropy scripted says it has none, in the same vocabulary");
    Test_Expect(out[0] == 0x5a, "and it did not write a byte to make the answer look like success");
    Port_Close(&port);
}

static void caseStubTargetFailsLoudly(void)
{
    Port port;
    static uint8_t payload[8];
    uint32_t written;

    buildTranscript(payload, sizeof payload);
    Port_Init(&port, PortWin32StubOps());
    Test_Expect(Port_Open(&port, "COM9", 0) == ZB_ERR_UNSUPPORTED,
           "a stub answers ZB_ERR_UNSUPPORTED, never silence");
    Test_Expect(Port_State(&port) == PORT_STATE_FAULT, "a stub is never treated as open");
    Test_Expect(Port_Fault(&port) == PORT_FAULT_OPEN, "the stub names an open fault");
    Test_Expect(Port_Write(&port, payload, sizeof payload, &written) == ZB_ERR_DEVICE_LOST,
           "a stub cannot carry traffic");
    Test_Expect(strcmp(Port_TargetName(&port), "win32-stub") == 0, "a stub names itself");
    Test_Expect(Port_Entropy(&port, payload, sizeof payload) == ZB_ERR_UNSUPPORTED,
           "and it refuses entropy the way it refuses everything else: ZB_ERR_UNSUPPORTED is a contract answer, not a failure");
    Port_Close(&port);
}

static void caseTwoPortsCoexist(void)
{
    Port a;
    Port b;
    PortNullScript scriptA;
    PortNullScript scriptB;
    static uint8_t bytesA[200];
    static uint8_t bytesB[100];
    static uint8_t collectedA[256];
    static uint8_t collectedB[256];
    uint8_t buf[64];
    uint32_t got;
    uint32_t totalA;
    uint32_t totalB;

    buildTranscript(bytesA, sizeof bytesA);
    buildTranscript(bytesB, sizeof bytesB);
    scriptDefaults(&scriptA, bytesA, sizeof bytesA);
    scriptDefaults(&scriptB, bytesB, sizeof bytesB);
    scriptA.rxChunk = 7;
    scriptB.rxChunk = 3;

    openPort(&a, &scriptA, "/dev/port-a", 0, 0);
    openPort(&b, &scriptB, "/dev/port-b", 0, 0);

    /* Interleaved: two sessions in one process, each with its own device. */
    totalA = 0;
    totalB = 0;

    while (Port_Read(&a, buf, sizeof buf, &got) == ZB_OK && got > 0)
    {
        memcpy(&collectedA[totalA], buf, got);
        totalA += got;

        if (Port_Read(&b, buf, sizeof buf, &got) == ZB_OK && got > 0)
        {
            memcpy(&collectedB[totalB], buf, got);
            totalB += got;
        }
    }

    while (Port_Read(&b, buf, sizeof buf, &got) == ZB_OK && got > 0)
    {
        memcpy(&collectedB[totalB], buf, got);
        totalB += got;
    }

    Test_Expect(totalA == sizeof bytesA && memcmp(collectedA, bytesA, totalA) == 0,
           "port a delivered only its own transcript");
    Test_Expect(totalB == sizeof bytesB && memcmp(collectedB, bytesB, totalB) == 0,
           "port b delivered only its own transcript");
    Test_Expect(strcmp(Port_Path(&a), "/dev/port-a") == 0, "port a keeps its own path");
    Test_Expect(strcmp(Port_Path(&b), "/dev/port-b") == 0, "port b keeps its own path");

    Port_Close(&a);
    Test_Expect(Port_IsOpen(&b), "closing one port leaves the other usable");
    Test_Expect(Port_Read(&a, buf, sizeof buf, &got) == ZB_ERR_NOT_OPEN,
           "a closed port refuses reads");
    Port_Close(&b);
}

int main(void)
{
    static uint8_t transcript[TRANSCRIPT_LEN];

    Test_Begin("port_contract");

    buildTranscript(transcript, TRANSCRIPT_LEN);

    caseInitDefaults();
    caseNoDefaultPath();
    caseByIdPathOpens();
    caseDefaultsReachTheDevice();
    caseRingArguments();
    caseEmptyReadIsNotAnError();
    caseSplitInvariance(transcript, TRANSCRIPT_LEN);
    caseOverflowKeepsOldest();
    caseIndexWrap();
    caseWriteIsAtomic();
    caseReadFaultAndLost();
    caseBufferedBytesSurviveAFault();
    caseWriteFault();
    caseScriptedEntropyIsConsumedInOrder();
    caseStubTargetFailsLoudly();
    caseTwoPortsCoexist();

    return Test_Report();
}
