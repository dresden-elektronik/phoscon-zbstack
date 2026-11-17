#include <stdio.h>
#include <string.h>

#include "port.h"
#include "port_null.h"
#include "test_fixture.h"
#include "test_harness.h"

#ifndef ZB_SAMPLES_DIR
#define ZB_SAMPLES_DIR "."
#endif

#define FIXTURE_NAME "port_conb2_raw.hex"
#define FIXTURE_PATH ZB_SAMPLES_DIR "/" FIXTURE_NAME

#define SCRATCH_CAP 8192
#define BURST_CAP   512

/* One port, one chunk pattern, and optionally one entropy script beside the transcript: what comes out of
   the ring must be the transcript either way (the entropy entry is on this
   contract, and a byte source that belongs to a caller must not reach into the byte source that belongs to
   the fixture). `entropy == 0` scripts none, which is what every replay here already did. */
static uint32_t replayScripted(const uint8_t *transcript, uint32_t len, uint32_t chunk,
                               const uint8_t *entropy, uint32_t entropyLen,
                               uint8_t *out, uint32_t outCap, uint32_t *drops,
                               uint8_t *drawn, uint32_t *drawnLen)
{
    Port port;
    PortNullScript script;
    uint8_t buf[256];
    uint32_t total;
    uint32_t got;

    total = 0;
    memset(&script, 0, sizeof script);
    script.rxBytes = transcript;
    script.rxLen = len;
    script.rxChunk = chunk;
    script.failPumpAfter = 0xffffffff;
    script.failDrainAfter = 0xffffffff;
    script.entropyBytes = entropy;
    script.entropyLen = entropyLen;

    Port_Init(&port, PortNullOps());
    PortNull_Attach(&port, &script);
    Test_Expect(Port_Open(&port, FIXTURE_NAME, 0) == ZB_OK, "fixture replay opens a port");

    if (drawn && drawnLen)
    {
        *drawnLen = 0;

        if (entropy && entropyLen <= PORT_ENTROPY_MAX
            && Port_Entropy(&port, drawn, entropyLen) == ZB_OK)
            *drawnLen = entropyLen;
    }

    for (;;)
    {
        if (Port_Read(&port, buf, sizeof buf, &got) != ZB_OK)
            break;

        if (got == 0)
            break;

        if (total + got > outCap)
            break;

        memcpy(&out[total], buf, got);
        total += got;
    }

    *drops = Port_Drops(&port);
    Port_Close(&port);
    return total;
}

static uint32_t replay(const uint8_t *transcript, uint32_t len, uint32_t chunk,
                       uint8_t *out, uint32_t outCap, uint32_t *drops)
{
    return replayScripted(transcript, len, chunk, 0, 0, out, outCap, drops, 0, 0);
}

int main(void)
{
    Test_Begin("port_conformance");

    static const uint32_t chunks[] = { 1, 3, 7, 13, 64, 255, 256, 0 };
    static uint8_t transcript[SCRATCH_CAP];
    static uint8_t collected[SCRATCH_CAP];
    static uint8_t reference[SCRATCH_CAP];
    uint32_t len;
    uint32_t c;
    uint32_t drops;
    uint32_t total;
    uint32_t flags;
    uint32_t escapes;
    uint32_t i;

    len = fixtureReadHex(FIXTURE_PATH, transcript, sizeof transcript);

    if (len == 0)
    {
        printf("FAIL: fixture %s unreadable\n", FIXTURE_PATH);
        return 1;
    }

    memcpy(reference, transcript, len);

    flags = 0;
    escapes = 0;

    for (i = 0; i < len; i++)
    {
        if (transcript[i] == 0x7e)
            flags++;

        if (transcript[i] == 0x7d)
            escapes++;
    }

    printf("port_conformance: fixture %u bytes, %u HDLC flags, %u escapes\n",
           len, flags, escapes);
    Test_Expect(flags > 0, "the transcript carries framing");
    Test_Expect(escapes > 0, "the transcript carries escaped octets");

    for (c = 0; c < sizeof chunks / sizeof chunks[0]; c++)
    {
        total = replay(transcript, len, chunks[c], collected, sizeof collected, &drops);
        Test_Expect(total == len, "every split delivers the whole transcript");
        Test_Expect(memcmp(collected, reference, len) == 0, "byte order preserved across splits");
        Test_Expect(drops == 0, "a drained transcript loses nothing");
    }

    /* A ring deliberately one frame too small, fed in bursts: identical prefix,
       counted loss, oldest kept (docs/porting.md §2). */

    {
        Port port;
        PortNullScript script;
        PortConfig config;
        uint8_t buf[512];
        uint32_t burst;
        uint32_t pushed;
        uint32_t got;

        memset(&script, 0, sizeof script);
        script.failPumpAfter = 0xffffffff;
        script.failDrainAfter = 0xffffffff;

        config.baud = 0;
        config.rxRingSize = 256;
        config.txRingSize = 0;
        config.exclusive = 1;

        Port_Init(&port, PortNullOps());
        PortNull_Attach(&port, &script);
        Test_Expect(Port_Open(&port, FIXTURE_NAME, &config) == ZB_OK, "undersized port opens");
        Test_Expect(Port_RxRingSize(&port) == 256, "the ring is one frame too small for this stream");

        pushed = 0;

        while (pushed < len)
        {
            burst = len - pushed;

            if (burst > BURST_CAP)
                burst = BURST_CAP;

            Port_PushRx(&port, &transcript[pushed], burst);
            pushed += burst;
        }

        Test_Expect(Port_RxPending(&port) == 256, "the ring stayed at its capacity");
        Test_Expect(Port_Drops(&port) == len - 256, "the loss is counted, not silent");

        total = 0;

        while (Port_Read(&port, buf, sizeof buf, &got) == ZB_OK && got > 0)
        {
            if (total + got > sizeof collected)
                break;

            memcpy(&collected[total], buf, got);
            total += got;
        }

        Test_Expect(total == 256, "the surviving bytes are one ring-full");
        Test_Expect(memcmp(collected, reference, total) == 0, "the surviving bytes are the oldest");
        Port_Close(&port);
    }

    /* Two ports in one process, different split patterns, same transcript. */
    {
        Port a;
        Port b;
        PortNullScript scriptA;
        PortNullScript scriptB;
        static uint8_t collectedB[SCRATCH_CAP];
        uint8_t buf[128];
        uint32_t got;
        uint32_t totalA;
        uint32_t totalB;

        memset(&scriptA, 0, sizeof scriptA);
        memset(&scriptB, 0, sizeof scriptB);
        scriptA.rxBytes = transcript;
        scriptA.rxLen = len;
        scriptA.rxChunk = 1;
        scriptA.failPumpAfter = 0xffffffff;
        scriptA.failDrainAfter = 0xffffffff;
        scriptB.rxBytes = transcript;
        scriptB.rxLen = len;
        scriptB.rxChunk = 255;
        scriptB.failPumpAfter = 0xffffffff;
        scriptB.failDrainAfter = 0xffffffff;

        Port_Init(&a, PortNullOps());
        PortNull_Attach(&a, &scriptA);
        Port_Init(&b, PortNullOps());
        PortNull_Attach(&b, &scriptB);
        Test_Expect(Port_Open(&a, FIXTURE_NAME, 0) == ZB_OK, "port a opens");
        Test_Expect(Port_Open(&b, FIXTURE_NAME, 0) == ZB_OK, "port b opens");

        totalA = 0;
        totalB = 0;

        while (Port_Read(&a, buf, sizeof buf, &got) == ZB_OK && got > 0)
        {
            memcpy(&collected[totalA], buf, got);
            totalA += got;

            if (Port_Read(&b, buf, sizeof buf, &got) == ZB_OK && got > 0)
            {
                memcpy(&collectedB[totalB], buf, got);
                totalB += got;
            }
        }

        while (Port_Read(&b, buf, sizeof buf, &got) == ZB_OK && got > 0)
        {
            if (totalB + got > sizeof collectedB)
                break;

            memcpy(&collectedB[totalB], buf, got);
            totalB += got;
        }

        Test_Expect(totalA == len && memcmp(collected, transcript, len) == 0,
               "port a reassembled the transcript byte for byte");
        Test_Expect(totalB == len && memcmp(collectedB, transcript, len) == 0,
               "port b reassembled the same transcript from a different split");
        Test_Expect(Port_Drops(&a) == 0 && Port_Drops(&b) == 0, "neither port lost anything");
        Port_Close(&a);
        Port_Close(&b);
    }

    /* Entropy is on this contract and is not part of a transcript: a
       port that carries both scripts replays the fixture exactly as a port that carries one does, and the
       two byte sources never meet. The honest per-port line, in the suite that owns each backend:
       `null` scripts it (asserted here, since this binary links the null port; `posix` answers it from the
       host's own source), asserted in the port_posix suite, the only binary that links that backend; a target
       that cannot answer it refuses it, asserted in port_contract, and no part of this conformance result rests
       on that refusal. */
    {
        Port port;
        static uint8_t entropyScript[8] = { 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
        static uint8_t drawn[8];
        uint32_t drawnLen;

        for (i = 0; i < sizeof drawn; i++)
            drawn[i] = 0xa5;

        total = replayScripted(transcript, len, 7, entropyScript, (uint32_t)sizeof entropyScript,
                               collected, sizeof collected, &drops, drawn, &drawnLen);

        Test_Expect(total == len && memcmp(collected, reference, len) == 0,
               "the same transcript, byte for byte, through a port that was also asked for entropy");
        Test_Expect(drops == 0, "and nothing was taken from the transcript to answer it");
        Test_Expect(drawnLen == 8 && drawn[0] == 0xd0 && drawn[7] == 0xd7,
               "and the scripted entropy came out of its own script, as scripted");

        Port_Init(&port, PortNullOps());
        Test_Expect(Port_Entropy(&port, 0, 8) == ZB_ERR_BAD_ARGUMENT,
               "a request with no buffer is refused on every target before any target is asked");
        Port_Close(&port);
    }

    return Test_Report();
}
