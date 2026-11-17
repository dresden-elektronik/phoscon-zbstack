/* A radio co-processor that goes quiet, read as an application reads it: Zb_Stack opens a pseudo-terminal as its serial
   port, a ConBee's USB one or a RaspBee's UART alike, and this file answers on the other end in the RCP's dialect until
   a case tells it to stop. */

#if STACK_RCP_CASES      /* the pseudo-terminal is POSIX's: on another host this file is empty (stack_main.c) */

#define _POSIX_C_SOURCE 200809

#include <time.h>

#include "hdlc.h"
#include "port_posix.h"
#include "props.h"
#include "rcp_radio.h"
#include "spinel.h"
#include "spinel_session.h"
#include "test_harness.h"
#include "zb_utils.h"
#include "zb_stack.h"

#define MOCK_RCP_VERSION "DSPINEL/1.0; AT86RF233"
#define MOCK_RCP_RADIO_CAPS 0x10f
#define MOCK_RCP_API_VERSION 4
#define MOCK_RCP_NAME_MAX 128
#define MOCK_RCP_CHANNEL 12
#define MOCK_RCP_PAN_ID 0xbeef
#define MOCK_RCP_NETWORK_KEY_HEX "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
#define MOCK_RCP_TURN_MS 10
#define MOCK_RCP_REAL_WAIT_NS 500000
#define MOCK_RCP_ENDPOINT 0x01
#define MOCK_RCP_PROFILE 0x0104
#define MOCK_RCP_CLUSTER 0x0006
#define MOCK_RCP_LINK "stack_rcp_unplugged.lnk"
#define MOCK_RCP_WAIT_ASKED_MS 50

static const uint8_t rcpAddress[RADIO_ADDR_LEN] = { 0x00, 0x21, 0x2e, 0xff, 0xff, 0x01, 0x02, 0x03 };

typedef struct MockRcp
{
    int master;
    Hdlc_Decoder decoder;
    int silent;
    uint32_t resetsToIgnore;
    uint32_t resets;
    uint32_t panWrites;
    uint32_t transmits;
} MockRcp;

static MockRcp s_mock;
static Zb_Stack s_stack;
static ZbStatus s_heardStatus;

static void mockSend(const uint8_t *payload, uint32_t len)
{
    uint8_t wire[PORT_TX_RING_MAX];
    uint32_t wireLen = 0;

    Test_ExpectStatus(Hdlc_Encode(payload, len, wire, (uint32_t)sizeof wire, &wireLen), ZB_OK, "an answer fits a frame");
    Test_ExpectStatus(PortPosix_PtyWrite(s_mock.master, wire, wireLen), ZB_OK, "and the terminal");
}

static void mockAnswerStatus(uint8_t tid, uint32_t status)
{
    uint8_t stage[16];
    U_BStream out;

    U_bstream_init(&out, stage, (unsigned long)sizeof stage);
    Spinel_WriteHeader(&out, tid);
    Spinel_WritePackedUint(&out, SPINEL_CMD_PROP_VALUE_IS);
    Spinel_WritePackedUint(&out, PROP_LAST_STATUS);
    Spinel_WritePackedUint(&out, status);
    mockSend(stage, (uint32_t)sizeof stage - Spinel_Remaining(&out));
}

/* A read answered with a value of the property's own shape, zero where nothing here depends on it. */
static void mockAnswerGet(uint8_t tid, uint32_t propId)
{
    uint8_t stage[64];
    U_BStream out;
    const Prop_Entry *entry = Props_Find(PROPS_DIALECT_DSPINEL, propId);
    uint32_t i;

    if (entry == 0 && propId != PROP_NCP_VERSION)
    {
        mockAnswerStatus(tid, SPINEL_STATUS_PROP_NOT_FOUND);
        return;
    }

    U_bstream_init(&out, stage, (unsigned long)sizeof stage);
    Spinel_WriteHeader(&out, tid);
    Spinel_WritePackedUint(&out, SPINEL_CMD_PROP_VALUE_IS);
    Spinel_WritePackedUint(&out, propId);

    if (propId == PROP_NCP_VERSION)
    {
        for (i = 0; MOCK_RCP_VERSION[i] != 0; i++)
            Spinel_WriteUint8(&out, (uint8_t)MOCK_RCP_VERSION[i]);

        Spinel_WriteUint8(&out, SPINEL_STRING_TERM);
    }
    else if (propId == PROP_HWADDR)
        Spinel_WriteAddrBe(&out, rcpAddress, RADIO_ADDR_LEN);
    else if (propId == PROP_RADIO_CAPS)
        Spinel_WritePackedUint(&out, MOCK_RCP_RADIO_CAPS);
    else if (propId == PROP_RCP_API_VERSION || propId == PROP_RCP_MIN_HOST_API_VERSION)
        Spinel_WritePackedUint(&out, MOCK_RCP_API_VERSION);
    else if (entry->kind == PROP_KIND_U16_LE)
        Spinel_WriteUint16(&out, 0);
    else if (entry->kind == PROP_KIND_ADDR_BE)
    {
        for (i = 0; i < RADIO_ADDR_LEN; i++)
            Spinel_WriteUint8(&out, 0);
    }
    else if (entry->kind == PROP_KIND_PACKED_U)
        Spinel_WritePackedUint(&out, 0);
    else if (entry->kind != PROP_KIND_ARRAY_U16_LE && entry->kind != PROP_KIND_ARRAY_ADDR_BE)
        Spinel_WriteUint8(&out, 0);

    mockSend(stage, (uint32_t)sizeof stage - Spinel_Remaining(&out));
}

/* A write answered with what was written, which needs no knowledge of its shape. */
static void mockAnswerSet(uint8_t tid, uint32_t propId, const uint8_t *value, uint32_t valueLen)
{
    uint8_t stage[HDLC_PAYLOAD_MAX];
    U_BStream out;
    uint32_t i;

    U_bstream_init(&out, stage, (unsigned long)sizeof stage);
    Spinel_WriteHeader(&out, tid);
    Spinel_WritePackedUint(&out, SPINEL_CMD_PROP_VALUE_IS);
    Spinel_WritePackedUint(&out, propId);

    for (i = 0; i < valueLen; i++)
        Spinel_WriteUint8(&out, value[i]);

    mockSend(stage, (uint32_t)sizeof stage - Spinel_Remaining(&out));
}

static void mockRequest(uint8_t *payload, uint32_t len)
{
    Spinel_Header header;
    U_BStream in;
    uint32_t command;
    uint32_t propId;
    uint32_t left;

    U_bstream_init(&in, payload, (unsigned long)len);
    Spinel_ReadHeader(Spinel_ReadUint8(&in), &header);
    command = Spinel_ReadPackedUint(&in);
    propId = Spinel_ReadPackedUint(&in);
    left = Spinel_Remaining(&in);

    if (command == SPINEL_CMD_RESET)
    {
        s_mock.resets++;

        if (s_mock.resetsToIgnore > 0)
            s_mock.resetsToIgnore--;
        else if (!s_mock.silent)
            mockAnswerStatus(SPINEL_TID_NONE, SPINEL_STATUS_RESET_SOFTWARE);

        return;
    }

    if (s_mock.silent)
        return;

    if (command == SPINEL_CMD_PROP_VALUE_GET)
    {
        mockAnswerGet(header.tid, propId);
        return;
    }

    if (propId == PROP_STREAM_RAW)
    {
        s_mock.transmits++;
        mockAnswerStatus(header.tid, SPINEL_STATUS_OK);
        return;
    }

    if (propId == PROP_MAC_15_4_PANID)
        s_mock.panWrites++;

    mockAnswerSet(header.tid, propId, payload + len - left, left);
}

static void mockServe(void)
{
    uint8_t chunk[256];
    uint8_t payload[HDLC_PAYLOAD_MAX];
    uint32_t got = 0;
    uint32_t frameLen = 0;
    uint32_t i;

    while (PortPosix_PtyRead(s_mock.master, chunk, (uint32_t)sizeof chunk, &got) == ZB_OK && got > 0)
    {
        for (i = 0; i < got; i++)
        {
            if (Hdlc_Feed(&s_mock.decoder, chunk[i], payload, &frameLen) == HDLC_EVENT_FRAME)
                mockRequest(payload, frameLen);
        }
    }
}

static void rcpRealWait(void)
{
    struct timespec wait;

    wait.tv_sec = 0;
    wait.tv_nsec = MOCK_RCP_REAL_WAIT_NS;
    (void)nanosleep(&wait, 0);
}

/* Turns under the case's clock, which runs far ahead of the wall's: a terminal's answer has a real moment to arrive
   before the clock moves, so a wait the stack measures is one the case asked for. Ends when `type` is heard;
   ZB_EVENT_NONE is never heard, so it asks for the whole time. */
static int rcpTurnUntil(Zb_StackEventType type, uint32_t *nowMs, uint32_t forMs, uint32_t *failed)
{
    Zb_StackEvent event;
    uint32_t end = *nowMs + forMs;
    int heard = 0;

    while (*nowMs < end && !heard)
    {
        Zb_StackTurn(&s_stack, *nowMs);
        rcpRealWait();
        mockServe();
        rcpRealWait();

        while (Zb_StackPollEvent(&s_stack, &event))
        {
            if (event.type == ZB_EVENT_NETWORK_FAILED && failed != 0)
                (*failed)++;

            if (event.type == type)
            {
                heard = 1;
                s_heardStatus = event.status;
            }
        }

        *nowMs += MOCK_RCP_TURN_MS;
    }

    return heard;
}

static int rcpStart(char *name, uint32_t nameMax, uint32_t *nowMs)
{
    Zb_StackConfig cfg;

    Zb_memset(&s_mock, 0, (uint32_t)sizeof s_mock);
    Hdlc_Init(&s_mock.decoder);

    if (PortPosix_PtyOpen(&s_mock.master, name, nameMax) != ZB_OK)
    {
        Test_Fault("this host gives the suite no pseudo-terminal");
        return 0;
    }

    Zb_StackCoordinatorDefaults(&cfg);
    cfg.path = name;
    cfg.channel = MOCK_RCP_CHANNEL;
    cfg.panId = MOCK_RCP_PAN_ID;
    Test_ParseHex(MOCK_RCP_NETWORK_KEY_HEX, cfg.networkKey, ZB_STACK_KEY_OCTETS);
    Zb_memset(&cfg.endpoints[0], 0, (uint32_t)sizeof cfg.endpoints[0]);
    cfg.endpoints[0].endpoint = MOCK_RCP_ENDPOINT;
    cfg.endpoints[0].profileId = MOCK_RCP_PROFILE;
    cfg.endpointCount = 1;
    Test_ExpectStatus(Zb_StackStart(&s_stack, &cfg), ZB_OK, "the stack opens the terminal as its RCP");
    *nowMs = 100;
    return 1;
}

static void rcpEnd(uint32_t *nowMs)
{
    s_mock.silent = 0;
    (void)Zb_StackStop(&s_stack);
    (void)rcpTurnUntil(ZB_EVENT_STOPPED, nowMs, 2000, 0);
    PortPosix_PtyClose(s_mock.master);
}

void caseStackRcpThatMissesAResetStillComesUp(void)
{
    char name[MOCK_RCP_NAME_MAX];
    uint32_t nowMs = 0;
    uint32_t failed = 0;

    Test_Case("caseStackRcpThatMissesAResetStillComesUp");

    if (!rcpStart(name, MOCK_RCP_NAME_MAX, &nowMs))
        return;

    s_mock.resetsToIgnore = 1;

    Test_Expect(rcpTurnUntil(ZB_EVENT_NETWORK_UP, &nowMs, 2 * RCP_RADIO_REPLY_TIMEOUT_MS, &failed),
                "a RESET lost to an RCP not yet listening is sent again, and the network comes up");
    Test_ExpectCount(failed, 0, "with no failure reported on the way");
    Test_Expect(s_mock.resets >= 2, "and it took another RESET to ask for it");

    rcpEnd(&nowMs);
}

void caseStackRcpThatNeverAnswersFailsItsStart(void)
{
    char name[MOCK_RCP_NAME_MAX];
    uint32_t nowMs = 0;

    Test_Case("caseStackRcpThatNeverAnswersFailsItsStart");

    if (!rcpStart(name, MOCK_RCP_NAME_MAX, &nowMs))
        return;

    s_mock.silent = 1;

    Test_Expect(rcpTurnUntil(ZB_EVENT_NETWORK_FAILED, &nowMs, 4000, 0), "an RCP that never answers ends the start, once the deadline passes");
    Test_Expect(s_mock.resets >= 2, "after being asked more than once");

    rcpEnd(&nowMs);
}

void caseStackRcpGoneQuietIsLostAndComesBack(void)
{
    char name[MOCK_RCP_NAME_MAX];
    Aps_ApsdeReq request;
    uint32_t nowMs = 0;
    uint32_t panWrites;
    uint32_t transmits;
    uint8_t payload[1] = { 0x5a };

    Test_Case("caseStackRcpGoneQuietIsLostAndComesBack");

    if (!rcpStart(name, MOCK_RCP_NAME_MAX, &nowMs))
        return;

    Test_Expect(rcpTurnUntil(ZB_EVENT_NETWORK_UP, &nowMs, 2000, 0), "the network comes up");
    (void)rcpTurnUntil(ZB_EVENT_NONE, &nowMs, 100, 0);

    panWrites = s_mock.panWrites;
    Test_Expect(panWrites != 0, "and the RCP was told its PAN");

    s_mock.silent = 1;

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    request.dstAddrMode = APS_ADDR_MODE_SHORT;
    request.dstAddress = 0xfffc;
    request.dstEndpoint = MOCK_RCP_ENDPOINT;
    request.profileId = MOCK_RCP_PROFILE;
    request.clusterId = MOCK_RCP_CLUSTER;
    request.srcEndpoint = MOCK_RCP_ENDPOINT;
    request.asdu = payload;
    request.asduLength = (uint32_t)sizeof payload;

    Test_ExpectStatus(Zb_StackApsRequest(&s_stack, &request), ZB_OK, "a frame goes to an RCP that has stopped answering");
    Test_Expect(rcpTurnUntil(ZB_EVENT_RCP_LOST, &nowMs, 2 * RCP_RADIO_REPLY_TIMEOUT_MS, 0),
                "and the application hears the RCP is lost");

    s_mock.silent = 0;
    Test_Expect(rcpTurnUntil(ZB_EVENT_RCP_BACK, &nowMs, 2 * RCP_RADIO_REPLY_TIMEOUT_MS, 0),
                "the same RCP answers the next RESET, and the application hears it is back");
    (void)rcpTurnUntil(ZB_EVENT_NONE, &nowMs, 100, 0);
    Test_Expect(s_mock.panWrites > panWrites, "holding what the stack told it");

    transmits = s_mock.transmits;
    Test_ExpectStatus(Zb_StackApsRequest(&s_stack, &request), ZB_OK, "and it sends again");
    (void)rcpTurnUntil(ZB_EVENT_NONE, &nowMs, 1000, 0);
    Test_Expect(s_mock.transmits > transmits, "the frame reaches the RCP");

    rcpEnd(&nowMs);
}

/* An RCP pulled from its socket and put back, at the path the stack was given: a link to a terminal, its other end
   closed to unplug it and a new terminal linked to replug it, as a serial-number device name returns. */
void caseStackRcpUnpluggedIsLostAndComesBack(void)
{
    char name[MOCK_RCP_NAME_MAX];
    Zb_StackConfig cfg;
    Zb_StackEvent event;
    Aps_ApsdeReq request;
    uint32_t nowMs = 100;
    uint32_t panWrites;
    uint32_t startMs;
    uint8_t payload[1] = { 0x5a };

    Test_Case("caseStackRcpUnpluggedIsLostAndComesBack");

    Zb_memset(&s_mock, 0, (uint32_t)sizeof s_mock);
    Hdlc_Init(&s_mock.decoder);

    if (PortPosix_PtyOpen(&s_mock.master, name, MOCK_RCP_NAME_MAX) != ZB_OK || PortPosix_PtyLink(MOCK_RCP_LINK, name) != ZB_OK)
    {
        Test_Fault("this host gives the suite no linked pseudo-terminal");
        return;
    }

    Zb_StackCoordinatorDefaults(&cfg);
    cfg.path = MOCK_RCP_LINK;
    cfg.channel = MOCK_RCP_CHANNEL;
    cfg.panId = MOCK_RCP_PAN_ID;
    Test_ParseHex(MOCK_RCP_NETWORK_KEY_HEX, cfg.networkKey, ZB_STACK_KEY_OCTETS);
    Zb_memset(&cfg.endpoints[0], 0, (uint32_t)sizeof cfg.endpoints[0]);
    cfg.endpoints[0].endpoint = MOCK_RCP_ENDPOINT;
    cfg.endpoints[0].profileId = MOCK_RCP_PROFILE;
    cfg.endpointCount = 1;
    Test_ExpectStatus(Zb_StackStart(&s_stack, &cfg), ZB_OK, "the stack opens the linked terminal as its RCP");
    Test_Expect(rcpTurnUntil(ZB_EVENT_NETWORK_UP, &nowMs, 2000, 0), "the network comes up");
    (void)rcpTurnUntil(ZB_EVENT_NONE, &nowMs, 100, 0);

    PortPosix_PtyClose(s_mock.master);
    (void)PortPosix_PtyLink(MOCK_RCP_LINK, 0);

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    request.dstAddrMode = APS_ADDR_MODE_SHORT;
    request.dstAddress = 0xfffc;
    request.dstEndpoint = MOCK_RCP_ENDPOINT;
    request.profileId = MOCK_RCP_PROFILE;
    request.clusterId = MOCK_RCP_CLUSTER;
    request.srcEndpoint = MOCK_RCP_ENDPOINT;
    request.asdu = payload;
    request.asduLength = (uint32_t)sizeof payload;

    (void)Zb_StackApsRequest(&s_stack, &request);
    Test_Expect(rcpTurnUntil(ZB_EVENT_RCP_LOST, &nowMs, 2 * RCP_RADIO_REPLY_TIMEOUT_MS, 0),
                "an unplugged RCP is lost");
    Test_ExpectStatus(s_heardStatus, ZB_ERR_NO_DEVICE, "and the loss is the port's, not a reset of the RCP");

    Zb_memset(&s_mock, 0, (uint32_t)sizeof s_mock);
    Hdlc_Init(&s_mock.decoder);

    if (PortPosix_PtyOpen(&s_mock.master, name, MOCK_RCP_NAME_MAX) != ZB_OK || PortPosix_PtyLink(MOCK_RCP_LINK, name) != ZB_OK)
    {
        Test_Fault("this host gives the suite no second linked pseudo-terminal");
        return;
    }

    Test_Expect(rcpTurnUntil(ZB_EVENT_RCP_BACK, &nowMs, 10000, 0),
                "the RCP put back at the same path is opened again, and the application hears it is back");
    (void)rcpTurnUntil(ZB_EVENT_NONE, &nowMs, 100, 0);
    panWrites = s_mock.panWrites;
    Test_Expect(panWrites != 0, "holding the PAN the stack told the one before it");
    Test_ExpectStatus(Zb_StackApsRequest(&s_stack, &request), ZB_OK, "and it sends again");
    (void)rcpTurnUntil(ZB_EVENT_NONE, &nowMs, 1000, 0);
    Test_Expect(s_mock.transmits > 0, "the frame reaches the RCP put back");

    PortPosix_PtyClose(s_mock.master);
    (void)PortPosix_PtyLink(MOCK_RCP_LINK, 0);
    (void)Zb_StackApsRequest(&s_stack, &request);
    (void)rcpTurnUntil(ZB_EVENT_RCP_LOST, &nowMs, 2 * RCP_RADIO_REPLY_TIMEOUT_MS, 0);

    startMs = Port_NowMs();

    while (Zb_StackPollEvent(&s_stack, &event))
        ;

    (void)Zb_StackNextEvent(&s_stack, &event, MOCK_RCP_WAIT_ASKED_MS);
    Test_Expect(Port_NowMs() - startMs >= MOCK_RCP_WAIT_ASKED_MS / 2,
                "and while it is away, a wait for the next event waits rather than returning at once");

    (void)Zb_StackStop(&s_stack);
    nowMs = Port_NowMs();
    (void)rcpTurnUntil(ZB_EVENT_STOPPED, &nowMs, 2000, 0);
    (void)PortPosix_PtyLink(MOCK_RCP_LINK, 0);
}

#else

typedef int CasesRcpNeedAPseudoTerminal;   /* C99 6.9: a translation unit holds at least one declaration */

#endif
