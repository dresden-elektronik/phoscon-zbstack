/* What Zb_Stack reports, read as an application reads it: a config in, one event at a time out. Each stack runs over a
   loopback model with a factory address, and two models are joined by an air the case carries between turns. */

#include "aes_hash.h"
#include "loopback_radio.h"
#include "nwk_leave.h"
#include "rig_band_a.h"
#include "test_harness.h"
#include "zb_utils.h"
#include "zb_stack.h"
#if ZB_ZDO_CLIENT
#include "zdo_client.h"
#endif

#define STACK_CHANNEL 26
#define STACK_PAN_ID 0x1a2b
#define STACK_COORDINATOR_IEEE 0x2021222324252627
#define STACK_ROUTER_IEEE 0x3031323334353637
#define STACK_END_DEVICE_IEEE 0x4041424344454647
#define STACK_NETWORK_KEY_HEX "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
#define STACK_LINK_KEY_SEED_HEX "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
#define STACK_ENDPOINT 0x01
#define STACK_PROFILE 0x0104
#define STACK_CLUSTER 0x0006
#define STACK_TURN_MS 10
#define STACK_LOG_MAX 32

typedef struct StackSide
{
    Loopback_Radio model;
    Zb_Stack stack;
    Zb_StackConfig cfg;
    Radio_Handle seen;
    Zb_StackEvent log[STACK_LOG_MAX];
    uint32_t logged;
    Zb_StackEvent childPoll;        /* the last ZB_EVENT_CHILD_POLL, which every poll repeats and the log leaves out */
    uint32_t childPolls;
    uint32_t childPollsPending;
} StackSide;

/* Two stacks, which a static keeps off the case's own frame: each holds a whole library. */
static StackSide s_coordinator;
static StackSide s_router;

static void stackModel(Loopback_Radio *model, uint64_t ieee)
{
    uint8_t octets[RADIO_ADDR_LEN];
    Radio_Caps caps;
    uint32_t i;

    Test_BandACapsAcks(&caps);
    LoopbackRadio_Init(model, &caps);

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        octets[i] = (uint8_t)(ieee >> (8 * i));

    LoopbackRadio_SetFactoryAddress(model, octets);
}

static void stackEndpoint(Zb_StackConfig *cfg)
{
    Af_SimpleDescriptor *endpoint = &cfg->endpoints[0];

    Zb_memset(endpoint, 0, (uint32_t)sizeof *endpoint);
    endpoint->endpoint = STACK_ENDPOINT;
    endpoint->profileId = STACK_PROFILE;
    endpoint->deviceId = 0x0005;
    endpoint->inputClusterCount = 1;
    endpoint->inputClusters[0] = STACK_CLUSTER;
    cfg->endpointCount = 1;
}

static void stackCoordinator(StackSide *side)
{
    Zb_memset(side, 0, (uint32_t)sizeof *side);
    stackModel(&side->model, STACK_COORDINATOR_IEEE);

    Zb_StackCoordinatorDefaults(&side->cfg);
    side->cfg.channel = STACK_CHANNEL;
    side->cfg.panId = STACK_PAN_ID;
    Test_ParseHex(STACK_NETWORK_KEY_HEX, side->cfg.networkKey, ZB_STACK_KEY_OCTETS);
    Test_ParseHex(STACK_LINK_KEY_SEED_HEX, side->cfg.linkKeySeed, ZB_STACK_KEY_OCTETS);
    side->cfg.radio = LoopbackRadio_Seam(&side->model);
    stackEndpoint(&side->cfg);
}

static void stackRouter(StackSide *side)
{
    Zb_memset(side, 0, (uint32_t)sizeof *side);
    stackModel(&side->model, STACK_ROUTER_IEEE);

    Zb_StackRouterDefaults(&side->cfg);
    side->cfg.channelMask = (uint32_t)1 << STACK_CHANNEL;
    side->cfg.radio = LoopbackRadio_Seam(&side->model);
    stackEndpoint(&side->cfg);
}

static void stackEndDevice(StackSide *side)
{
    Zb_memset(side, 0, (uint32_t)sizeof *side);
    stackModel(&side->model, STACK_END_DEVICE_IEEE);

    Zb_StackEndDeviceDefaults(&side->cfg);
    side->cfg.channelMask = (uint32_t)1 << STACK_CHANNEL;
    side->cfg.radio = LoopbackRadio_Seam(&side->model);
    stackEndpoint(&side->cfg);
}

/* What one model put on the air arrives in front of the other, before either stack turns. */
static void stackCross(StackSide *from, StackSide *to)
{
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    Loopback_FrameSpec spec[LOOPBACK_TX_MAX];
    Radio_Handle newest = from->seen;
    uint32_t got;
    uint32_t count = 0;
    uint32_t i;

    got = LoopbackRadio_Sent(&from->model, sent, LOOPBACK_TX_MAX);

    for (i = 0; i < got; i++)
    {
        if (sent[i].handle == RADIO_HANDLE_NONE || sent[i].handle <= from->seen)
            continue;

        Zb_memset(&spec[count], 0, (uint32_t)sizeof spec[count]);
        spec[count].len = sent[i].len;
        spec[count].bytes = sent[i].bytes;
        spec[count].rssiDbm = -60;
        spec[count].lqi = 200;
        spec[count].stampTicks = 2;
        count++;

        if (sent[i].handle > newest)
            newest = sent[i].handle;
    }

    if (count != 0)
        (void)LoopbackRadio_Inject(&to->model, spec, count);

    from->seen = newest;
}

/* One turn and every event it left, kept in the side's log in the order an application would have read them. */
static void stackTurn(StackSide *side, uint32_t nowMs)
{
    Zb_StackEvent event;

    Zb_StackTurn(&side->stack, nowMs);

    while (Zb_StackPollEvent(&side->stack, &event))
    {
        if (event.type == ZB_EVENT_CHILD_POLL)
        {
            side->childPoll = event;
            side->childPolls++;
            side->childPollsPending += event.childPoll.framePending != 0;
        }
        else if (side->logged < STACK_LOG_MAX)
            side->log[side->logged++] = event;
    }
}

static const Zb_StackEvent *stackFirst(const StackSide *side, Zb_StackEventType type)
{
    uint32_t i;

    for (i = 0; i < side->logged; i++)
    {
        if (side->log[i].type == type)
            return &side->log[i];
    }

    return 0;
}

/* One version part in decimal at `out`, answering its length. */
static uint32_t versionPart(uint32_t value, char *out)
{
    char digits[10];
    uint32_t count = 0;
    uint32_t i;

    do
    {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);

    for (i = 0; i < count; i++)
        out[i] = digits[count - 1 - i];

    return count;
}

/* The version an application reads is one number, spelt twice: the string is the three parts, and nothing else. */
void caseStackVersionStringIsItsNumbers(void)
{
    char expected[40];
    uint32_t len = 0;

    len += versionPart(ZB_VERSION_MAJOR, expected + len);
    expected[len++] = '.';
    len += versionPart(ZB_VERSION_MINOR, expected + len);
    expected[len++] = '.';
    len += versionPart(ZB_VERSION_PATCH, expected + len);

    Test_Expect(Zb_strlen(ZB_VERSION_STRING, 40) == len && Zb_memcmp(ZB_VERSION_STRING, expected, len) == 0,
                "ZB_VERSION_STRING spells ZB_VERSION_MAJOR, _MINOR and _PATCH, dot separated");
}

void caseStackStartRefusesWhatItCannotStartFrom(void)
{
    Zb_StackConfig cfg;

    Test_Case("caseStackStartRefusesWhatItCannotStartFrom");

    stackCoordinator(&s_coordinator);

    cfg = s_coordinator.cfg;
    cfg.channel = 0;
    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "a coordinator names its channel: nothing picks one for it");

    cfg = s_coordinator.cfg;
    cfg.channel = 27;
    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and a channel the 2.4 GHz PHY has, 11 to 26");

    cfg = s_coordinator.cfg;
    cfg.radio = 0;
    cfg.path = 0;
    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "a stack with no radio of its own needs the RCP's path: no port is ever defaulted");

    cfg = s_coordinator.cfg;
    cfg.endpointCount = ZB_STACK_ENDPOINT_MAX + 1;
    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and no more endpoints than the registry holds");

    stackRouter(&s_router);

    cfg = s_router.cfg;
    cfg.channelMask = 0;
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "a router names its channels, because the discovery transmits on every one");
}

void caseStackCoordinatorComesUp(void)
{
    const Zb_StackEvent *up;
    Zb_StackEvent event;
    Aps_ApsdeReq request;
    uint32_t nowMs;

    Test_Case("caseStackCoordinatorComesUp");

    stackCoordinator(&s_coordinator);

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "a coordinator starts");
    Test_Expect(Zb_StackPollEvent(&s_coordinator.stack, &event) == 0, "and has nothing to report before it turns");

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    Test_ExpectStatus(Zb_StackApsRequest(&s_coordinator.stack, &request), ZB_ERR_NOT_READY,
                      "a send before the network is up is refused, not held");

    for (nowMs = 100; nowMs < 2000 && stackFirst(&s_coordinator, ZB_EVENT_NETWORK_UP) == 0; nowMs += STACK_TURN_MS)
        stackTurn(&s_coordinator, nowMs);

    up = stackFirst(&s_coordinator, ZB_EVENT_NETWORK_UP);

    Test_Expect(up != 0, "the network comes up without the application asking whether it did");
    Test_Expect(s_coordinator.logged != 0 && s_coordinator.log[0].type == ZB_EVENT_NETWORK_UP,
                "and that is the first thing it hears");
    Test_ExpectCount(up ? up->network.networkAddress : 0xffff, 0x0000, "a coordinator is 0x0000");
    Test_ExpectCount(up ? up->network.panId : 0, STACK_PAN_ID, "on the PAN it named");
    Test_ExpectCount(up ? up->network.channel : 0, STACK_CHANNEL, "and the channel it named");
    Test_Expect(up != 0 && up->network.ieee == STACK_COORDINATOR_IEEE,
                "its address is the radio's factory address, read by the stack");
    Test_Expect(up != 0 && up->network.extendedPanId == STACK_COORDINATOR_IEEE,
                "and with none named its extended PAN identifier is that address");

    Test_ExpectStatus(Zb_StackStop(&s_coordinator.stack), ZB_OK, "the application stops it");
    stackTurn(&s_coordinator, nowMs);
    Test_Expect(stackFirst(&s_coordinator, ZB_EVENT_STOPPED) != 0, "and hears that it stopped");
}

void caseStackCoordinatorWithoutEntropyNamesItsKey(void)
{
    const Zb_StackEvent *failed;
    uint32_t nowMs;

    Test_Case("caseStackCoordinatorWithoutEntropyNamesItsKey");

    stackCoordinator(&s_coordinator);
    Zb_memset(s_coordinator.cfg.networkKey, 0, ZB_STACK_KEY_OCTETS);

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK,
                      "a coordinator over a radio of its own starts");

    for (nowMs = 100; nowMs < 500; nowMs += STACK_TURN_MS)
        stackTurn(&s_coordinator, nowMs);

    failed = stackFirst(&s_coordinator, ZB_EVENT_NETWORK_FAILED);

    Test_Expect(failed != 0 && stackFirst(&s_coordinator, ZB_EVENT_NETWORK_UP) == 0,
                "but with no port there is no entropy, and a network key is never made up: the network fails");
    Test_ExpectStatus(failed ? failed->status : ZB_OK, ZB_ERR_UNSUPPORTED, "saying why");
}

void caseStackRouterJoinsAndTheyTalk(void)
{
    const Zb_StackEvent *coordinatorUp;
    const Zb_StackEvent *routerUp;
    const Zb_StackEvent *joined;
    const Zb_StackEvent *data;
    const Zb_StackEvent *sent;
    Aps_ApsdeReq request;
    uint8_t asdu[3] = { 0x01, 0x2a, 0x02 };
    uint32_t nowMs;
    uint32_t step;

    Test_Case("caseStackRouterJoinsAndTheyTalk");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &s_router.cfg), ZB_OK, "and the router");

    for (nowMs = 100; nowMs < 60000; nowMs += STACK_TURN_MS)
    {
        stackCross(&s_coordinator, &s_router);
        stackCross(&s_router, &s_coordinator);
        stackTurn(&s_coordinator, nowMs);
        stackTurn(&s_router, nowMs);

        if (stackFirst(&s_router, ZB_EVENT_NETWORK_UP) != 0 && stackFirst(&s_coordinator, ZB_EVENT_DEVICE_JOINED) != 0)
            break;
    }

    /* two seconds more, so whatever the device objects sent on their own has its outcome back */
    for (step = 0; step < 200; step++, nowMs += STACK_TURN_MS)
    {
        stackCross(&s_coordinator, &s_router);
        stackCross(&s_router, &s_coordinator);
        stackTurn(&s_coordinator, nowMs);
        stackTurn(&s_router, nowMs);
    }

    coordinatorUp = stackFirst(&s_coordinator, ZB_EVENT_NETWORK_UP);
    routerUp = stackFirst(&s_router, ZB_EVENT_NETWORK_UP);
    joined = stackFirst(&s_coordinator, ZB_EVENT_DEVICE_JOINED);

    Test_Expect(coordinatorUp != 0, "the coordinator's network comes up");
    Test_Expect(routerUp != 0 && stackFirst(&s_router, ZB_EVENT_NETWORK_FAILED) == 0,
                "the router's comes up too: it found the network, joined it and holds the key");
    Test_ExpectCount(routerUp ? routerUp->network.panId : 0, STACK_PAN_ID, "on the coordinator's PAN");
    Test_Expect(routerUp != 0 && routerUp->network.networkAddress != 0xffff && routerUp->network.networkAddress != 0,
                "with an address of its own");
    Test_Expect(routerUp != 0 && coordinatorUp != 0
                && routerUp->network.extendedPanId == coordinatorUp->network.extendedPanId,
                "on the network the coordinator formed");
    Test_Expect(joined != 0 && joined->joined.ieee == STACK_ROUTER_IEEE,
                "and the coordinator hears it join, by its extended address");
    Test_Expect(joined != 0 && routerUp != 0 && joined->joined.networkAddress == routerUp->network.networkAddress,
                "at the address it was given");
    Test_Expect(joined != 0 && joined->joined.receiverOn == 1, "a router keeps its receiver on");
    Test_Expect(joined != 0 && (joined->joined.capability & 0x02) != 0, "and says it is a full-function device");
    Test_Expect(joined != 0 && joined->data.profileId == 0x0000 && joined->data.clusterId == 0x0013
                && joined->data.asduLength == 12 && joined->data.asdu[11] == joined->joined.capability,
                "the announcement itself rides in data, its capability octet last");
    Test_Expect(stackFirst(&s_router, ZB_EVENT_SENT) == 0 && stackFirst(&s_coordinator, ZB_EVENT_SENT) == 0,
                "and neither application hears of a send it did not make: the device object's announcement is its own");

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    request.dstAddrMode = APS_ADDR_MODE_SHORT;
    request.dstAddress = 0x0000;
    request.dstEndpoint = STACK_ENDPOINT;
    request.profileId = STACK_PROFILE;
    request.clusterId = STACK_CLUSTER;
    request.srcEndpoint = STACK_ENDPOINT;
    request.asdu = asdu;
    request.asduLength = (uint32_t)sizeof asdu;
    request.txOptions = APS_TX_OPTION_ACK;
    request.tag = 0x0a17;

    Test_ExpectStatus(Zb_StackApsRequest(&s_router.stack, &request), ZB_OK, "the router sends to the coordinator's endpoint");

    for (; nowMs < 70000; nowMs += STACK_TURN_MS)
    {
        stackCross(&s_coordinator, &s_router);
        stackCross(&s_router, &s_coordinator);
        stackTurn(&s_coordinator, nowMs);
        stackTurn(&s_router, nowMs);

        if (stackFirst(&s_router, ZB_EVENT_SENT) != 0 && stackFirst(&s_coordinator, ZB_EVENT_DATA) != 0)
            break;
    }

    data = stackFirst(&s_coordinator, ZB_EVENT_DATA);
    sent = stackFirst(&s_router, ZB_EVENT_SENT);

    Test_Expect(data != 0 && data->data.clusterId == STACK_CLUSTER && data->data.asduLength == (uint32_t)sizeof asdu,
                "the coordinator's application gets the frame as data");
    Test_Expect(data != 0 && Zb_memcmp(data->data.asdu, asdu, (uint32_t)sizeof asdu) == 0, "octet for octet");
    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK,
                      "and the router's application hears the send succeeded, acknowledged end to end");
    Test_ExpectCount(sent ? sent->sent.tag : 0, 0x0a17, "under the tag it gave the request, which is how it knows which one");
}

/* Both sides turned until `side` has an event of `type` or `untilMs` passes, the air carried between them each turn. */
static uint32_t stackRunUntil(StackSide *a, StackSide *b, StackSide *side, Zb_StackEventType type, uint32_t nowMs,
                              uint32_t untilMs)
{
    for (; nowMs < untilMs && stackFirst(side, type) == 0; nowMs += STACK_TURN_MS)
    {
        stackCross(a, b);
        stackCross(b, a);
        stackTurn(a, nowMs);
        stackTurn(b, nowMs);
    }

    return nowMs;
}

/* Both sides turned for `forMs`, so what either sent on its own has its outcome back. */
static uint32_t stackRunFor(StackSide *a, StackSide *b, uint32_t nowMs, uint32_t forMs)
{
    uint32_t untilMs = nowMs + forMs;

    for (; nowMs < untilMs; nowMs += STACK_TURN_MS)
    {
        stackCross(a, b);
        stackCross(b, a);
        stackTurn(a, nowMs);
        stackTurn(b, nowMs);
    }

    return nowMs;
}

/* An application frame with an acknowledgement asked for, to `dst`'s endpoint under `tag`. */
static Aps_ApsdeReq stackRequest(uint16_t dst, const uint8_t *asdu, uint32_t asduLength, uint16_t tag)
{
    Aps_ApsdeReq request;

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    request.dstAddrMode = APS_ADDR_MODE_SHORT;
    request.dstAddress = dst;
    request.dstEndpoint = STACK_ENDPOINT;
    request.profileId = STACK_PROFILE;
    request.clusterId = STACK_CLUSTER;
    request.srcEndpoint = STACK_ENDPOINT;
    request.asdu = asdu;
    request.asduLength = asduLength;
    request.txOptions = APS_TX_OPTION_ACK;
    request.tag = tag;

    return request;
}

/* An end device joins with its receiver on and joins no one to itself, and the two exchange an acknowledged frame
   each way. */
void caseStackEndDeviceJoinsAndTheyTalk(void)
{
    static StackSide endDevice;
    const Zb_StackEvent *up;
    const Zb_StackEvent *joined;
    const Zb_StackEvent *sent;
    Aps_ApsdeReq request;
    uint8_t asdu[3] = { 0x01, 0x2b, 0x02 };
    uint32_t nowMs;

    Test_Case("caseStackEndDeviceJoinsAndTheyTalk");

    stackCoordinator(&s_coordinator);
    stackEndDevice(&endDevice);

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&endDevice.stack, &endDevice.cfg), ZB_OK, "and the end device");

    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_NETWORK_UP, 100, 60000);
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &s_coordinator, ZB_EVENT_DEVICE_JOINED, nowMs, nowMs + 2000);
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 15000);

    up = stackFirst(&endDevice, ZB_EVENT_NETWORK_UP);
    joined = stackFirst(&s_coordinator, ZB_EVENT_DEVICE_JOINED);

    Test_Expect(up != 0 && stackFirst(&endDevice, ZB_EVENT_NETWORK_FAILED) == 0, "the end device's network comes up");
    Test_Expect(joined != 0 && joined->joined.ieee == STACK_END_DEVICE_IEEE, "and the coordinator hears it join");
    Test_Expect(joined != 0 && joined->joined.receiverOn == 1, "with its receiver on");
    Test_Expect(joined != 0 && up != 0 && joined->joined.networkAddress == up->network.networkAddress,
                "at the address it was given");
    Test_ExpectCount((uint32_t)Zb_CoreNwk(Zb_StackCore(&endDevice.stack))->associationPermit, 0,
                     "and it opens no permit of its own");
    Test_Expect(joined != 0 && Nwk_NeighborOf(Zb_CoreNwk(Zb_StackCore(&s_coordinator.stack))->neighbors,
                                              joined->joined.networkAddress) != 0,
                "and fifteen seconds on its parent still holds it: Table 3-58's ten seconds are not what it asked for");

    request = stackRequest(0x0000, asdu, (uint32_t)sizeof asdu, 0x0e01);
    Test_ExpectStatus(Zb_StackApsRequest(&endDevice.stack, &request), ZB_OK, "the end device sends to the coordinator");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_SENT, nowMs, nowMs + 10000);
    sent = stackFirst(&endDevice, ZB_EVENT_SENT);

    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "acknowledged end to end");
    Test_Expect(stackFirst(&s_coordinator, ZB_EVENT_DATA) != 0, "and the coordinator's application has it");

    request = stackRequest(up ? up->network.networkAddress : 0xffff, asdu, (uint32_t)sizeof asdu, 0x0e02);
    Test_ExpectStatus(Zb_StackApsRequest(&s_coordinator.stack, &request), ZB_OK, "the coordinator answers in kind");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &s_coordinator, ZB_EVENT_SENT, nowMs, nowMs + 10000);
    sent = stackFirst(&s_coordinator, ZB_EVENT_SENT);

    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "acknowledged end to end");
    Test_Expect(stackFirst(&endDevice, ZB_EVENT_DATA) != 0, "and the end device's application has it");
}

/* A sleepy end device joins with its receiver resting, polls its parent at 250 ms through Transport-Key and the link
   key exchange (R23.1 3.6.1.15), then at its own rate; a frame each way arrives, the parent's by the child's poll. */
void caseStackSleepyEndDeviceJoinsAndTheyTalk(void)
{
    static StackSide endDevice;
    const Zb_StackEvent *up;
    const Zb_StackEvent *joined;
    const Zb_StackEvent *sent;
    const Zb_StackEvent *polled;
    const Nwk_NeighborTableEntry *child;
    Aps_ApsdeReq request;
    uint8_t asdu[3] = { 0x01, 0x2f, 0x02 };
    uint32_t pollsBefore;
    uint32_t nowMs;

    Test_Case("caseStackSleepyEndDeviceJoinsAndTheyTalk");

    stackCoordinator(&s_coordinator);
    stackEndDevice(&endDevice);
    endDevice.cfg.sleepy = 1;

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&endDevice.stack, &endDevice.cfg), ZB_OK, "and a sleepy end device");

    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_NETWORK_UP, 100, 60000);
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 2000);
    Test_ExpectCount(Aps_TcLinkKeyState(&Zb_CoreLayers(Zb_StackCore(&endDevice.stack))->aps), APS_TCLK_VERIFIED,
                     "within two seconds of holding the network key its link key is verified: it polled at 250 ms");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &s_coordinator, ZB_EVENT_DEVICE_JOINED, nowMs, nowMs + 5000);
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 15000);

    up = stackFirst(&endDevice, ZB_EVENT_NETWORK_UP);
    joined = stackFirst(&s_coordinator, ZB_EVENT_DEVICE_JOINED);
    child = joined != 0 ? Nwk_NeighborOf(Zb_CoreNwk(Zb_StackCore(&s_coordinator.stack))->neighbors,
                                         joined->joined.networkAddress) : 0;

    Test_Expect(up != 0 && joined != 0 && joined->joined.receiverOn == 0,
                "the network comes up, and the coordinator hears a device whose receiver rests");
    Test_Expect(child != 0 && child->rxOnWhenIdle == 0, "and holds it as a child to keep frames for");
    Test_ExpectCount(Zb_StackCore(&endDevice.stack)->zdo.node.macCapabilityFlags, 0x84,
                     "its node descriptor says so too (2.3.2.3.6)");
    Test_Expect(Mac_CountersOf(Zb_CoreMac(Zb_StackCore(&endDevice.stack))).heardAsleep != 0,
                "and it discarded what its RCP heard between polls");

    pollsBefore = Nwk_PollsSent(Zb_CoreNwk(Zb_StackCore(&endDevice.stack)));
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 30000);
    Test_Expect(Nwk_PollsSent(Zb_CoreNwk(Zb_StackCore(&endDevice.stack))) - pollsBefore <= 30000 / 7500 + 1,
                "attached, it polls at its own rate, 7.5 s by default");

    request = stackRequest(0x0000, asdu, (uint32_t)sizeof asdu, 0x0e11);
    Test_ExpectStatus(Zb_StackApsRequest(&endDevice.stack, &request), ZB_OK, "the end device sends to the coordinator");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_SENT, nowMs, nowMs + 20000);
    sent = stackFirst(&endDevice, ZB_EVENT_SENT);
    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "acknowledged end to end, the ack by its poll");

    Test_ExpectStatus(Zb_StackSetPollInterval(&endDevice.stack, 1000), ZB_OK, "the application polls every second");
    request = stackRequest(up ? up->network.networkAddress : 0xffff, asdu, (uint32_t)sizeof asdu, 0x0e12);
    Test_ExpectStatus(Zb_StackApsRequest(&s_coordinator.stack, &request), ZB_OK, "the coordinator answers in kind");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &s_coordinator, ZB_EVENT_SENT, nowMs, nowMs + 20000);
    sent = stackFirst(&s_coordinator, ZB_EVENT_SENT);
    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "held for the child's poll and acknowledged");
    Test_Expect(stackFirst(&endDevice, ZB_EVENT_DATA) != 0, "and the end device's application has it");

    Test_ExpectStatus(Zb_StackPoll(&endDevice.stack), ZB_OK, "the application asks for one poll more");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_POLLED, nowMs, nowMs + 1000);
    polled = stackFirst(&endDevice, ZB_EVENT_POLLED);
    Test_ExpectStatus(polled ? polled->status : ZB_ERR_INTERNAL, ZB_ERR_NO_DATA, "and hears the parent held nothing");
    Test_ExpectStatus(Zb_StackPoll(&s_coordinator.stack), ZB_ERR_BAD_STATE, "a coordinator has no parent to poll");
}

/* A sleepy child's Data Requests told to its parent's application, one event per poll, with the child's addresses:
   nothing held for the polls it makes on its own schedule, and the frame held for it on the poll that takes it. */
void caseStackChildPollsAreTold(void)
{
    static StackSide endDevice;
    const Zb_StackEvent *up;
    const Zb_StackEvent *sent;
    Aps_ApsdeReq request;
    uint8_t asdu[3] = { 0x01, 0x30, 0x02 };
    uint32_t pollsBefore;
    uint32_t nowMs;

    Test_Case("caseStackChildPollsAreTold");

    stackCoordinator(&s_coordinator);
    stackEndDevice(&endDevice);
    endDevice.cfg.sleepy = 1;

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&endDevice.stack, &endDevice.cfg), ZB_OK, "and a sleepy end device");

    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_NETWORK_UP, 100, 60000);
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &s_coordinator, ZB_EVENT_DEVICE_JOINED, nowMs, nowMs + 5000);
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 2000);
    up = stackFirst(&endDevice, ZB_EVENT_NETWORK_UP);
    Test_Expect(up != 0 && s_coordinator.childPolls != 0, "the child is up, and its parent was told of its polls");

    s_coordinator.childPolls = 0;
    s_coordinator.childPollsPending = 0;
    pollsBefore = Nwk_PollsSent(Zb_CoreNwk(Zb_StackCore(&endDevice.stack)));
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 30000);

    Test_ExpectCount(s_coordinator.childPolls, Nwk_PollsSent(Zb_CoreNwk(Zb_StackCore(&endDevice.stack))) - pollsBefore,
                     "one event for each Data Request the child sent at its own rate");
    Test_Expect(s_coordinator.childPolls != 0 && s_coordinator.childPoll.childPoll.networkAddress
                                                     == (up != 0 ? up->network.networkAddress : 0xffff),
                "naming the child by its network address");
    Test_Expect(s_coordinator.childPoll.childPoll.ieeeKnown
                    && s_coordinator.childPoll.childPoll.ieee == STACK_END_DEVICE_IEEE,
                "and by the extended address its association gave the parent");
    Test_ExpectCount(s_coordinator.childPollsPending, 0, "the parent held nothing for any of them");

    request = stackRequest(up != 0 ? up->network.networkAddress : 0xffff, asdu, (uint32_t)sizeof asdu, 0x0e13);
    Test_ExpectStatus(Zb_StackApsRequest(&s_coordinator.stack, &request), ZB_OK, "the coordinator sends to the child");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &s_coordinator, ZB_EVENT_SENT, nowMs, nowMs + 20000);
    sent = stackFirst(&s_coordinator, ZB_EVENT_SENT);
    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "held for the child's poll and acknowledged");
    Test_Expect(s_coordinator.childPollsPending != 0, "and the poll that took it was told with a frame pending");
    Test_ExpectCount(Nwk_ChildPollNoticesDropped(Zb_CoreNwk(Zb_StackCore(&s_coordinator.stack))), 0,
                     "an application that reads its events loses none");
}

/* A parent that has forgotten its child, as one that aged it out or restarted has: the child's next marked frame is
   dropped and answered with a Leave asking it to rejoin (8670-8680), the child discovers its network's parents and
   rejoins, the permit closed as a network's usually is (8077-8082, 8090), and the APS retry of the frame arrives. */
void caseStackForgottenEndDeviceRejoins(void)
{
    static StackSide endDevice;
    const Zb_StackEvent *up;
    const Zb_StackEvent *sent;
    Nwk_NeighborTableEntry *entry;
    Aps_ApsdeReq request;
    uint8_t asdu[3] = { 0x01, 0x2c, 0x02 };
    uint32_t beaconsBefore;
    uint32_t commissioningBefore;
    uint32_t nowMs;

    Test_Case("caseStackForgottenEndDeviceRejoins");

    stackCoordinator(&s_coordinator);
    stackEndDevice(&endDevice);

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&endDevice.stack, &endDevice.cfg), ZB_OK, "and the end device");

    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_NETWORK_UP, 100, 60000);
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 2000);
    up = stackFirst(&endDevice, ZB_EVENT_NETWORK_UP);

    Test_Expect(up != 0, "the end device is up");
    Test_Expect(Zb_CoreNwk(Zb_StackCore(&endDevice.stack))->cfg.parentInformation != 0,
                "and its parent's timeout answer has it mark its frames as an end device's");

    entry = up != 0 ? Nwk_NeighborOf(Zb_CoreNwk(Zb_StackCore(&s_coordinator.stack))->neighbors,
                                     up->network.networkAddress) : 0;
    Test_Expect(entry != 0, "the coordinator holds its child");

    Test_ExpectStatus(Zb_StackPermitJoining(&s_coordinator.stack, 0), ZB_OK, "the coordinator closes its permit");
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 200);
    Test_ExpectCount((uint32_t)Zb_CoreNwk(Zb_StackCore(&s_coordinator.stack))->associationPermit, 0,
                     "and admits no new device");

    if (entry != 0)
        Zb_memset(entry, 0, (uint32_t)sizeof *entry);

    Zb_StackCore(&endDevice.stack)->joinParams.scanDuration = 0;
    beaconsBefore = Zb_CoreNwk(Zb_StackCore(&endDevice.stack))->discoveryBeaconsTaken;
    commissioningBefore = Zb_CoreNwk(Zb_StackCore(&s_coordinator.stack))->commissioningJoins;

    request = stackRequest(0x0000, asdu, (uint32_t)sizeof asdu, 0x0e03);
    Test_ExpectStatus(Zb_StackApsRequest(&endDevice.stack, &request), ZB_OK, "the forgotten child sends to its parent");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_SENT, nowMs, nowMs + 10000);
    sent = stackFirst(&endDevice, ZB_EVENT_SENT);

    Test_Expect(Nwk_DroppedEndDeviceInitiator(Zb_CoreNwk(Zb_StackCore(&s_coordinator.stack))) > 0,
                "the parent drops the marked frame of a child it does not hold");
    Test_Expect(Nwk_UnknownSenderLeaves(Zb_CoreNwk(Zb_StackCore(&s_coordinator.stack))) > 0,
                "and sends it a Leave that asks it to rejoin");
    Test_ExpectCount(Zb_CoreRejoins(Zb_StackCore(&endDevice.stack)), 1, "the child is told to rejoin, and does");
    Test_Expect(Zb_CoreNwk(Zb_StackCore(&endDevice.stack))->discoveryBeaconsTaken > beaconsBefore,
                "after a discovery of its network's parents (7950-7952)");
    Test_ExpectCount(Zb_CoreNwk(Zb_StackCore(&endDevice.stack))->discoveryRequest.scanDuration, 3,
                     "for D.9's ScanDuration of 3 when no join named one, as after a restore");
    Test_ExpectCount(Zb_CoreNwk(Zb_StackCore(&s_coordinator.stack))->commissioningJoins, commissioningBefore + 1,
                     "and by a Commissioning Rejoin, the parent's beacon carrying the R23 appendix (7971-7979)");
    Test_Expect(up != 0 && Nwk_NeighborOf(Zb_CoreNwk(Zb_StackCore(&s_coordinator.stack))->neighbors,
                                          up->network.networkAddress) != 0,
                "the parent holds it again");
    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "and the frame arrives on its APS retry");
    Test_Expect(stackFirst(&s_coordinator, ZB_EVENT_DATA) != 0, "in the coordinator's application");
}

/* As many sends as the APS holds in flight, made in one turn: each is taken, and each outcome comes back under its own
   tag, in whatever order the confirms arrive. */
void caseStackParallelSendsComeBackByTag(void)
{
    Aps_ApsdeReq request;
    uint8_t asdu[3] = { 0x01, 0x2b, 0x02 };
    uint8_t seen[APS_TX_MAX];
    uint32_t sentCount = 0;
    uint32_t sentOk = 0;
    uint32_t dataCount = 0;
    uint32_t nowMs;
    uint32_t step;
    uint32_t i;

    Test_Case("caseStackParallelSendsComeBackByTag");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &s_router.cfg), ZB_OK, "and the router");

    for (nowMs = 100; nowMs < 60000; nowMs += STACK_TURN_MS)
    {
        stackCross(&s_coordinator, &s_router);
        stackCross(&s_router, &s_coordinator);
        stackTurn(&s_coordinator, nowMs);
        stackTurn(&s_router, nowMs);

        if (stackFirst(&s_router, ZB_EVENT_NETWORK_UP) != 0 && stackFirst(&s_coordinator, ZB_EVENT_DEVICE_JOINED) != 0)
            break;
    }

    /* two seconds more, so the device objects' own sends are done and the logs start empty */
    for (step = 0; step < 200; step++, nowMs += STACK_TURN_MS)
    {
        stackCross(&s_coordinator, &s_router);
        stackCross(&s_router, &s_coordinator);
        stackTurn(&s_coordinator, nowMs);
        stackTurn(&s_router, nowMs);
    }

    Test_Expect(stackFirst(&s_router, ZB_EVENT_NETWORK_UP) != 0, "the router joined the coordinator's network");
    s_router.logged = 0;
    s_coordinator.logged = 0;

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    request.dstAddrMode = APS_ADDR_MODE_SHORT;
    request.dstAddress = 0x0000;
    request.dstEndpoint = STACK_ENDPOINT;
    request.profileId = STACK_PROFILE;
    request.clusterId = STACK_CLUSTER;
    request.srcEndpoint = STACK_ENDPOINT;
    request.asdu = asdu;
    request.asduLength = (uint32_t)sizeof asdu;
    request.txOptions = APS_TX_OPTION_ACK;

    for (i = 0; i < APS_TX_MAX; i++)
    {
        request.tag = (uint16_t)(0x0100 + i);
        Test_ExpectStatus(Zb_StackApsRequest(&s_router.stack, &request), ZB_OK, "each send of the burst is taken");
    }

    request.tag = 0x01ff;
    Test_ExpectStatus(Zb_StackApsRequest(&s_router.stack, &request), ZB_ERR_NO_SPACE,
                      "and one more is refused at once, with no event to follow");

    for (; nowMs < 80000; nowMs += STACK_TURN_MS)
    {
        stackCross(&s_coordinator, &s_router);
        stackCross(&s_router, &s_coordinator);
        stackTurn(&s_coordinator, nowMs);
        stackTurn(&s_router, nowMs);
    }

    Zb_memset(seen, 0, (uint32_t)sizeof seen);

    for (i = 0; i < s_router.logged; i++)
    {
        const Zb_StackEvent *event = &s_router.log[i];

        if (event->type != ZB_EVENT_SENT)
            continue;

        sentCount++;

        if (event->status == ZB_OK && event->sent.tag >= 0x0100 && event->sent.tag < 0x0100 + APS_TX_MAX
            && seen[event->sent.tag - 0x0100] == 0)
        {
            seen[event->sent.tag - 0x0100] = 1;
            sentOk++;
        }
    }

    for (i = 0; i < s_coordinator.logged; i++)
    {
        if (s_coordinator.log[i].type == ZB_EVENT_DATA)
            dataCount++;
    }

    Test_ExpectCount(sentCount, APS_TX_MAX, "the router's application hears one outcome per send");
    Test_ExpectCount(sentOk, APS_TX_MAX, "each acknowledged, and each under a tag of its own");
    Test_ExpectCount(dataCount, APS_TX_MAX, "and the coordinator's application gets every frame");
}

/* `side`'s events of `type`, and the last of them. */
static uint32_t stackCount(const StackSide *side, Zb_StackEventType type, const Zb_StackEvent **last)
{
    uint32_t count = 0;
    uint32_t i;

    for (i = 0; i < side->logged; i++)
    {
        if (side->log[i].type != type)
            continue;

        count++;

        if (last != 0)
            *last = &side->log[i];
    }

    return count;
}

/* A Node_Desc_req from `side`'s application to `destination`, from endpoint 0 under `tag`. */
static ZbStatus stackSendNodeDescReq(StackSide *side, uint16_t destination, uint8_t tsn, uint16_t tag)
{
    Aps_ApsdeReq request;
    uint8_t asdu[3];

    asdu[0] = tsn;
    asdu[1] = (uint8_t)(destination & 0xff);
    asdu[2] = (uint8_t)(destination >> 8);

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    request.dstAddrMode = APS_ADDR_MODE_SHORT;
    request.dstAddress = destination;
    request.dstEndpoint = ZDO_ENDPOINT;
    request.profileId = ZDO_PROFILE_ID;
    request.clusterId = ZDO_NODE_DESC_REQ;
    request.srcEndpoint = ZDO_ENDPOINT;
    request.asdu = asdu;
    request.asduLength = (uint32_t)sizeof asdu;
    request.txOptions = APS_TX_OPTION_ACK;
    request.tag = tag;

    return Zb_StackApsRequest(&side->stack, &request);
}

void caseStackDeviceObjectSendsAreItsOwn(void)
{
    const Zb_StackEvent *routerUp;
    const Zb_StackEvent *sent = 0;
    const Zb_StackEvent *data = 0;
    uint16_t routerAddress;
    uint32_t answered;
    uint32_t nowMs;
    uint32_t step;

    Test_Case("caseStackDeviceObjectSendsAreItsOwn");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &s_router.cfg), ZB_OK, "and the router");

    for (nowMs = 100; nowMs < 60000; nowMs += STACK_TURN_MS)
    {
        stackCross(&s_coordinator, &s_router);
        stackCross(&s_router, &s_coordinator);
        stackTurn(&s_coordinator, nowMs);
        stackTurn(&s_router, nowMs);

        if (stackFirst(&s_router, ZB_EVENT_NETWORK_UP) != 0 && stackFirst(&s_coordinator, ZB_EVENT_DEVICE_JOINED) != 0)
            break;
    }

    for (step = 0; step < 200; step++, nowMs += STACK_TURN_MS)
    {
        stackCross(&s_coordinator, &s_router);
        stackCross(&s_router, &s_coordinator);
        stackTurn(&s_coordinator, nowMs);
        stackTurn(&s_router, nowMs);
    }

    routerUp = stackFirst(&s_router, ZB_EVENT_NETWORK_UP);
    Test_Expect(routerUp != 0, "the router joined the coordinator's network");
    routerAddress = routerUp != 0 ? routerUp->network.networkAddress : 0xffff;
    s_router.logged = 0;
    s_coordinator.logged = 0;

    Test_ExpectStatus(stackSendNodeDescReq(&s_coordinator, routerAddress, 0x41, ZB_STACK_TAG_DEVICE_OBJECT),
                      ZB_ERR_BAD_ARGUMENT, "an application may not send under the device object's own tag");
    answered = Zdo_ResponsesSent(&Zb_StackCore(&s_coordinator.stack)->zdo);
    Test_ExpectStatus(stackSendNodeDescReq(&s_router, 0x0000, 0x52, 0x0b02), ZB_OK,
                      "the router's application asks the coordinator for its node descriptor");

    /* turned until the coordinator's device object has sent its answer, whose acknowledgement is still to come */
    for (step = 0; step < 100 && Zdo_ResponsesSent(&Zb_StackCore(&s_coordinator.stack)->zdo) == answered; step++)
    {
        nowMs += STACK_TURN_MS;
        stackCross(&s_coordinator, &s_router);
        stackCross(&s_router, &s_coordinator);
        stackTurn(&s_coordinator, nowMs);
        stackTurn(&s_router, nowMs);
    }

    Test_ExpectStatus(stackSendNodeDescReq(&s_coordinator, routerAddress, 0x41, 0x0b01), ZB_OK,
                      "and while that answer waits on its acknowledgement, the coordinator's application asks the router");

    for (; nowMs < 90000; nowMs += STACK_TURN_MS)
    {
        stackCross(&s_coordinator, &s_router);
        stackCross(&s_router, &s_coordinator);
        stackTurn(&s_coordinator, nowMs);
        stackTurn(&s_router, nowMs);
    }

    Test_ExpectCount(stackCount(&s_coordinator, ZB_EVENT_SENT, &sent), 1,
                     "the coordinator's application hears one outcome, its device object's answer being none of its own");
    Test_ExpectCount(sent ? sent->sent.tag : 0, 0x0b01, "under the tag it gave");
    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "acknowledged (2.4.2.8.4)");
    Test_ExpectCount(stackCount(&s_coordinator, ZB_EVENT_DATA, &data), 1, "and the router's answer comes as data");
    Test_Expect(data != 0 && data->data.profileId == ZDO_PROFILE_ID
                && data->data.clusterId == (ZDO_NODE_DESC_REQ | ZDO_RESPONSE_BIT) && data->data.asduLength != 0
                && data->data.asdu[0] == 0x41,
                "2.4.2.8.1: the Node_Desc_rsp, carrying the request's transaction sequence number");

    sent = 0;
    data = 0;
    Test_ExpectCount(stackCount(&s_router, ZB_EVENT_SENT, &sent), 1, "the router's application likewise hears one");
    Test_ExpectCount(sent ? sent->sent.tag : 0, 0x0b02, "under its own tag");
    Test_ExpectCount(stackCount(&s_router, ZB_EVENT_DATA, &data), 1, "and gets the coordinator's answer");
    Test_Expect(data != 0 && data->data.clusterId == (ZDO_NODE_DESC_REQ | ZDO_RESPONSE_BIT) && data->data.asdu[0] == 0x52,
                "2.4.2.8.1: numbered as the router's request was");
}

/* A ZDP request of `len` octets, its transaction sequence number first, from `side`'s endpoint 0 to `destination`. */
static ZbStatus stackSendZdp(StackSide *side, uint16_t destination, uint16_t cluster, const uint8_t *asdu, uint32_t len)
{
    Aps_ApsdeReq request;

    Zb_memset(&request, 0, (uint32_t)sizeof request);
    request.dstAddrMode = APS_ADDR_MODE_SHORT;
    request.dstAddress = destination;
    request.dstEndpoint = ZDO_ENDPOINT;
    request.profileId = ZDO_PROFILE_ID;
    request.clusterId = cluster;
    request.srcEndpoint = ZDO_ENDPOINT;
    request.asdu = asdu;
    request.asduLength = len;
    request.txOptions = APS_TX_OPTION_ACK;
    request.tag = 0x0c00;

    return Zb_StackApsRequest(&side->stack, &request);
}

/* Both sides turned with the air between them for `turns` turns. */
static uint32_t stackRun(uint32_t nowMs, uint32_t turns)
{
    uint32_t step;

    for (step = 0; step < turns; step++, nowMs += STACK_TURN_MS)
    {
        stackCross(&s_coordinator, &s_router);
        stackCross(&s_router, &s_coordinator);
        stackTurn(&s_coordinator, nowMs);
        stackTurn(&s_router, nowMs);
    }

    return nowMs;
}

/* The two sides started, the router joined and two seconds more turned, the logs cleared: the time reached. */
static uint32_t stackJoinRouter(void)
{
    uint32_t nowMs;

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &s_router.cfg), ZB_OK, "and the router");

    for (nowMs = 100; nowMs < 60000; nowMs += STACK_TURN_MS)
    {
        nowMs = stackRun(nowMs, 1) - STACK_TURN_MS;

        if (stackFirst(&s_router, ZB_EVENT_NETWORK_UP) != 0 && stackFirst(&s_coordinator, ZB_EVENT_DEVICE_JOINED) != 0)
            break;
    }

    Test_Expect(stackFirst(&s_router, ZB_EVENT_NETWORK_UP) != 0, "the router joined the coordinator's network");
    nowMs = stackRun(nowMs, 200);
    s_router.logged = 0;
    s_coordinator.logged = 0;

    return nowMs;
}

/* The router's application's first ZDP answer on `cluster`, or 0. */
static const Zb_StackEvent *stackAnswer(uint16_t cluster)
{
    uint32_t i;

    for (i = 0; i < s_router.logged; i++)
    {
        if (s_router.log[i].type == ZB_EVENT_DATA && s_router.log[i].data.profileId == ZDO_PROFILE_ID
            && s_router.log[i].data.clusterId == (uint16_t)(cluster | ZDO_RESPONSE_BIT))
            return &s_router.log[i];
    }

    return 0;
}

void caseStackDeviceObjectAnswersMatchAndUnsupported(void)
{
    /* TSN, NWKAddrOfInterest 0x0000, profile 0x0104, one input cluster, no output clusters (Figure 2-24) */
    static const uint8_t match[] = { 0x61, 0x00, 0x00, 0x04, 0x01, 0x01, 0x06, 0x00, 0x00 };
    static const uint8_t elsewhere[] = { 0x62, 0x00, 0x00, 0x04, 0x01, 0x01, 0x08, 0x00, 0x00 };
    static const uint8_t stranger[] = { 0x63, 0x34, 0x12, 0xff, 0xff, 0x01, 0x06, 0x00, 0x00 };
    static const uint8_t unsupported[] = { 0x64, 0x00 };
    const Zb_StackEvent *answer;
    const Zb_StackEvent *data = 0;
    uint32_t nowMs;

    Test_Case("caseStackDeviceObjectAnswersMatchAndUnsupported");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);
    nowMs = stackJoinRouter();

    Test_ExpectStatus(stackSendZdp(&s_router, 0x0000, ZDO_MATCH_DESC_REQ, match, (uint32_t)sizeof match), ZB_OK,
                      "the router's application asks the coordinator which endpoints serve On/Off");
    nowMs = stackRun(nowMs, 100);
    answer = stackAnswer(ZDO_MATCH_DESC_REQ);
    Test_Expect(answer != 0 && answer->data.asduLength == 6 && answer->data.asdu[0] == 0x61
                && answer->data.asdu[1] == ZDO_STATUS_SUCCESS && answer->data.asdu[2] == 0x00
                && answer->data.asdu[3] == 0x00 && answer->data.asdu[4] == 1 && answer->data.asdu[5] == STACK_ENDPOINT,
                "2.4.4.2.7: SUCCESS, the address of interest, and the one endpoint whose input clusters hold it");

    s_router.logged = 0;
    Test_ExpectStatus(stackSendZdp(&s_router, 0x0000, ZDO_MATCH_DESC_REQ, elsewhere, (uint32_t)sizeof elsewhere),
                      ZB_OK, "then for a cluster no endpoint has");
    nowMs = stackRun(nowMs, 100);
    answer = stackAnswer(ZDO_MATCH_DESC_REQ);
    Test_Expect(answer != 0 && answer->data.asduLength == 5 && answer->data.asdu[1] == ZDO_STATUS_SUCCESS
                && answer->data.asdu[4] == 0,
                "step 7: a unicast that matches nothing is still SUCCESS, with an empty list");

    s_router.logged = 0;
    Test_ExpectStatus(stackSendZdp(&s_router, 0x0000, ZDO_MATCH_DESC_REQ, stranger, (uint32_t)sizeof stranger),
                      ZB_OK, "then about an address the coordinator does not know");
    nowMs = stackRun(nowMs, 100);
    answer = stackAnswer(ZDO_MATCH_DESC_REQ);
    Test_Expect(answer != 0 && answer->data.asduLength == 5 && answer->data.asdu[1] == ZDO_STATUS_DEVICE_NOT_FOUND
                && answer->data.asdu[2] == 0x34 && answer->data.asdu[3] == 0x12 && answer->data.asdu[4] == 0,
                "step 4b: DEVICE_NOT_FOUND, the address echoed and no list");

    s_router.logged = 0;
    Test_ExpectStatus(stackSendZdp(&s_router, 0x0000, 0x0030, unsupported, (uint32_t)sizeof unsupported), ZB_OK,
                      "a request the coordinator does not support");
    nowMs = stackRun(nowMs, 100);
    answer = stackAnswer(0x0030);
    Test_Expect(answer != 0 && answer->data.asduLength == 2 && answer->data.asdu[0] == 0x64
                && answer->data.asdu[1] == ZDO_STATUS_NOT_SUPPORTED,
                "2.4.4.1: is answered on its response cluster with NOT_SUPPORTED alone");
    Test_ExpectCount(stackCount(&s_coordinator, ZB_EVENT_DATA, 0), 0, "and the coordinator's application never sees it");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);
    s_coordinator.cfg.zdpUnsupportedToApplication = 1;
    nowMs = stackJoinRouter();

    Test_ExpectStatus(stackSendZdp(&s_router, 0x0000, 0x0030, unsupported, (uint32_t)sizeof unsupported), ZB_OK,
                      "with zdpUnsupportedToApplication the same request");
    nowMs = stackRun(nowMs, 100);
    Test_ExpectCount(stackCount(&s_coordinator, ZB_EVENT_DATA, &data), 1, "reaches the coordinator's application");
    Test_Expect(data != 0 && data->data.profileId == ZDO_PROFILE_ID && data->data.clusterId == 0x0030
                && data->data.dstEndpoint == ZDO_ENDPOINT && data->data.asduLength == 2 && data->data.asdu[0] == 0x64,
                "as it arrived, on endpoint 0");
    Test_Expect(stackAnswer(0x0030) == 0, "and the device object leaves the answer to it");
}

/* The coordinator's application's events of `type` on `cluster`, and the last of them. */
static uint32_t stackOwnCount(Zb_StackEventType type, uint16_t cluster, const Zb_StackEvent **last)
{
    uint32_t count = 0;
    uint32_t i;

    for (i = 0; i < s_coordinator.logged; i++)
    {
        if (s_coordinator.log[i].type != type || (type == ZB_EVENT_DATA && s_coordinator.log[i].data.clusterId != cluster))
            continue;

        count++;
        *last = &s_coordinator.log[i];
    }

    return count;
}

void caseStackRequestsToItselfAreLoopedBack(void)
{
    static const uint8_t lqi[] = { 0x72, 0x00 };
    static const uint8_t frame[] = { 0x5a };
    const Zb_StackEvent *data = 0;
    const Zb_StackEvent *sent = 0;
    Aps_ApsdeReq request;
    uint32_t nowMs;

    Test_Case("caseStackRequestsToItselfAreLoopedBack");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);
    nowMs = stackJoinRouter();

    Test_ExpectStatus(stackSendNodeDescReq(&s_coordinator, 0x0000, 0x71, 0x0d01), ZB_OK,
                      "the coordinator's application asks its own address for the node descriptor");
    nowMs = stackRun(nowMs, 4);
    Test_ExpectCount(stackOwnCount(ZB_EVENT_DATA, ZDO_NODE_DESC_REQ | ZDO_RESPONSE_BIT, &data), 1,
                     "the device object answers it, and the answer comes back to the application");
    Test_Expect(data != 0 && data->data.srcAddress == 0x0000 && data->data.dstEndpoint == ZDO_ENDPOINT
                && data->data.asduLength > 4 && data->data.asdu[0] == 0x71 && data->data.asdu[1] == ZDO_STATUS_SUCCESS,
                "from the device's own address, under the request's number, SUCCESS");
    Test_Expect(stackOwnCount(ZB_EVENT_SENT, 0, &sent) == 1 && sent->sent.tag == 0x0d01 && sent->sent.status == ZB_OK
                && sent->sent.apsStatus == APS_STATUS_SUCCESS, "the request is confirmed SUCCESS under its tag");

    s_coordinator.logged = 0;
    Zb_memset(&request, 0, (uint32_t)sizeof request);
    request.dstAddrMode = APS_ADDR_MODE_EXTENDED;
    request.dstExtendedAddress = s_coordinator.stack.ieee;
    request.dstEndpoint = ZDO_ENDPOINT;
    request.profileId = ZDO_PROFILE_ID;
    request.clusterId = ZDO_MGMT_LQI_REQ;
    request.srcEndpoint = ZDO_ENDPOINT;
    request.asdu = lqi;
    request.asduLength = (uint32_t)sizeof lqi;
    request.txOptions = APS_TX_OPTION_ACK | APS_TX_OPTION_SECURITY;
    request.tag = 0x0d02;
    Test_ExpectStatus(Zb_StackApsRequest(&s_coordinator.stack, &request), ZB_OK,
                      "then by its own extended address for its neighbours, APS-secured as a Mgmt request may be");
    nowMs = stackRun(nowMs, 4);
    Test_ExpectCount(stackOwnCount(ZB_EVENT_DATA, ZDO_MGMT_LQI_REQ | ZDO_RESPONSE_BIT, &data), 1,
                     "the Mgmt_Lqi_rsp comes back the same way");
    Test_Expect(data != 0 && data->data.asduLength > 4 && data->data.asdu[0] == 0x72
                && data->data.asdu[1] == ZDO_STATUS_SUCCESS && data->data.asdu[2] == 1 && data->data.asdu[4] == 1,
                "SUCCESS, one neighbour, the router, in one record");

    s_coordinator.logged = 0;
    request = stackRequest(0x0000, frame, (uint32_t)sizeof frame, 0x0d03);
    Test_ExpectStatus(Zb_StackApsRequest(&s_coordinator.stack, &request), ZB_OK,
                      "a frame from the application's endpoint to its own address and endpoint");
    nowMs = stackRun(nowMs, 4);
    Test_ExpectCount(stackOwnCount(ZB_EVENT_DATA, STACK_CLUSTER, &data), 1, "is the application's own frame back");
    Test_Expect(data != 0 && data->data.dstEndpoint == STACK_ENDPOINT && data->data.srcEndpoint == STACK_ENDPOINT
                && data->data.asduLength == 1 && data->data.asdu[0] == 0x5a, "on the endpoint it named, as it was sent");

    Test_ExpectCount(Aps_Loopbacks(&Zb_StackCore(&s_coordinator.stack)->layers.aps), 5,
                     "three requests and the device object's two answers were looped back, none put on the air");
    (void)nowMs;
}

/* The application's entropy source: every octet 0x5c, and the calls counted. */
static ZbStatus stackEntropy(void *context, uint8_t *out, uint32_t len)
{
    (*(uint32_t *)context)++;
    Zb_memset(out, 0x5c, len);

    return ZB_OK;
}

void caseStackDrawsFromTheApplicationsEntropy(void)
{
    static Zb_State saved;
    uint32_t draws = 0;
    uint32_t i;

    Test_Case("caseStackDrawsFromTheApplicationsEntropy");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);
    Zb_memset(s_coordinator.cfg.networkKey, 0, ZB_STACK_KEY_OCTETS);
    Zb_memset(s_coordinator.cfg.linkKeySeed, 0, ZB_STACK_KEY_OCTETS);
    s_coordinator.cfg.entropy = stackEntropy;
    s_coordinator.cfg.entropyContext = &draws;

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK,
                      "a coordinator over a radio of its own, with no network key and an entropy source of the application's");
    (void)stackRunUntil(&s_coordinator, &s_router, &s_coordinator, ZB_EVENT_NETWORK_UP, 100, 3000);
    Test_Expect(stackFirst(&s_coordinator, ZB_EVENT_NETWORK_UP) != 0, "forms its network");
    Test_ExpectCount(draws, 3, "having drawn its seeds, its network key and its link key seed from the source");
    Test_ExpectStatus(Zb_StackCapture(&s_coordinator.stack, 1, &saved), ZB_OK, "and is captured");

    for (i = 0; i < ZB_STACK_KEY_OCTETS && saved.keys[0].key[i] == 0x5c; i++)
        ;

    Test_ExpectCount(i, ZB_STACK_KEY_OCTETS, "its network key being what the source gave");
}

#if ZB_ZDO_CLIENT
void caseStackZdoRequestsAreNumberedByTheDeviceObject(void)
{
    const Zb_StackEvent *routerUp;
    const Zb_StackEvent *sent = 0;
    const Zb_StackEvent *data = 0;
    uint8_t payload[2];
    uint8_t nodeReq[16];
    uint8_t first = 0;
    uint8_t second = 0;
    uint8_t third = 0;
    uint8_t counter;
    uint32_t nodeLen;
    uint32_t answered = 0;
    uint16_t routerAddress;
    uint32_t nowMs;
    uint32_t step;

    Test_Case("caseStackZdoRequestsAreNumberedByTheDeviceObject");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackZdoRequest(&s_coordinator.stack, 0x0001, ZDO_ACTIVE_EP_REQ, payload, 2, 0x0c01, &first),
                      ZB_ERR_NOT_READY, "a request before the network is up is refused");
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &s_router.cfg), ZB_OK, "and the router");

    for (nowMs = 100; nowMs < 60000; nowMs += STACK_TURN_MS)
    {
        stackCross(&s_coordinator, &s_router);
        stackCross(&s_router, &s_coordinator);
        stackTurn(&s_coordinator, nowMs);
        stackTurn(&s_router, nowMs);

        if (stackFirst(&s_router, ZB_EVENT_NETWORK_UP) != 0 && stackFirst(&s_coordinator, ZB_EVENT_DEVICE_JOINED) != 0)
            break;
    }

    for (step = 0; step < 200; step++, nowMs += STACK_TURN_MS)
    {
        stackCross(&s_coordinator, &s_router);
        stackCross(&s_router, &s_coordinator);
        stackTurn(&s_coordinator, nowMs);
        stackTurn(&s_router, nowMs);
    }

    routerUp = stackFirst(&s_router, ZB_EVENT_NETWORK_UP);
    routerAddress = routerUp != 0 ? routerUp->network.networkAddress : 0xffff;
    s_router.logged = 0;
    s_coordinator.logged = 0;
    payload[0] = (uint8_t)(routerAddress & 0xff);
    payload[1] = (uint8_t)(routerAddress >> 8);

    Test_ExpectStatus(Zb_StackZdoRequest(&s_coordinator.stack, routerAddress, ZDO_NODE_DESC_REQ | ZDO_RESPONSE_BIT,
                                      payload, 2, 0x0c01, &first), ZB_ERR_BAD_ARGUMENT,
                      "a response's cluster is the device object's to send, not a request");
    Test_ExpectStatus(Zb_StackZdoRequest(&s_coordinator.stack, routerAddress, ZDO_ACTIVE_EP_REQ, payload, 2,
                                      ZB_STACK_TAG_DEVICE_OBJECT, &first), ZB_ERR_BAD_ARGUMENT,
                      "and the device object's own tag is refused");

    counter = Zdo_TransactionSequenceNumber(&Zb_StackCore(&s_coordinator.stack)->zdo);
    Test_ExpectStatus(Zb_StackZdoRequest(&s_coordinator.stack, routerAddress, ZDO_ACTIVE_EP_REQ, payload, 2, 0x0c01,
                                      &first), ZB_OK, "an Active_EP_req goes to the router");
    Test_ExpectStatus(Zb_StackZdoRequest(&s_coordinator.stack, routerAddress, ZDO_ACTIVE_EP_REQ, payload, 2, 0x0c02,
                                      &second), ZB_OK, "and a second one behind it");
    Test_Expect(first == counter && second == (uint8_t)(counter + 1)
                && Zdo_TransactionSequenceNumber(&Zb_StackCore(&s_coordinator.stack)->zdo) == (uint8_t)(counter + 2),
                "2.4.2.8.1: numbered from the device object's own counter, one apart, and the counter moved past both");

    nodeLen = ZdoClient_NodeDescReq(&Zb_StackCore(&s_coordinator.stack)->zdo, routerAddress, nodeReq,
                                    (uint32_t)sizeof nodeReq);
    Test_ExpectStatus(Zb_StackZdoRequest(&s_coordinator.stack, routerAddress, ZDO_NODE_DESC_REQ, nodeReq, nodeLen, 0x0c03,
                                      &third), ZB_OK, "2.4.3.1.3.1: a Node_Desc_req with its fragmentation TLV goes too");

    for (; nowMs < 90000; nowMs += STACK_TURN_MS)
    {
        stackCross(&s_coordinator, &s_router);
        stackCross(&s_router, &s_coordinator);
        stackTurn(&s_coordinator, nowMs);
        stackTurn(&s_router, nowMs);
    }

    Test_ExpectCount(stackCount(&s_coordinator, ZB_EVENT_SENT, &sent), 3, "each request has its outcome");
    Test_Expect(sent != 0 && sent->status == ZB_OK && sent->sent.tag >= 0x0c01 && sent->sent.tag <= 0x0c03,
                "2.4.2.8.4: acknowledged, under the request's tag");
    Test_ExpectCount(stackCount(&s_coordinator, ZB_EVENT_DATA, 0), 3, "and each its response");

    for (step = 0; step < s_coordinator.logged; step++)
    {
        data = &s_coordinator.log[step];

        if (data->type == ZB_EVENT_DATA && data->data.clusterId == (ZDO_ACTIVE_EP_REQ | ZDO_RESPONSE_BIT))
            answered++;

        if (data->type == ZB_EVENT_DATA && data->data.clusterId == (ZDO_NODE_DESC_REQ | ZDO_RESPONSE_BIT)
            && data->data.asduLength > 1 && data->data.asdu[0] == third && data->data.asdu[1] == ZDO_STATUS_SUCCESS)
            answered += 0x10;
    }

    Test_ExpectCount(answered, 0x12, "2.4.2.8.1: two Active_EP_rsp, and a Node_Desc_rsp of success under its number");
}
#endif

/* A coordinator saved, stopped and started again from its state: the router that stayed up never notices. The network
   is the one it joined, and the coordinator's outgoing counter starts past every one it had sent, so the router hears
   it and is heard (4.3.4). */
void caseStackCoordinatorComesBackFromItsState(void)
{
    static Zb_State saved;
    static Zb_State after;
    const Zb_StackEvent *up;
    const Zb_StackEvent *sent;
    Zb_StackConfig cfg;
    Aps_ApsdeReq request;
    uint8_t asdu[3] = { 0x01, 0x2c, 0x02 };
    uint64_t extendedPanId;
    uint32_t nowMs;

    Test_Case("caseStackCoordinatorComesBackFromItsState");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackCapture(&s_coordinator.stack, 1, &saved), ZB_ERR_NOT_READY,
                      "and has no network to capture before it is up");
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &s_router.cfg), ZB_OK, "the router starts");

    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_router, ZB_EVENT_NETWORK_UP, 100, 60000);
    nowMs = stackRunFor(&s_coordinator, &s_router, nowMs, 2000);
    up = stackFirst(&s_coordinator, ZB_EVENT_NETWORK_UP);
    extendedPanId = up != 0 ? up->network.extendedPanId : 0;

    Test_Expect(stackFirst(&s_router, ZB_EVENT_NETWORK_UP) != 0, "the router joins");
    Test_ExpectStatus(Zb_StackCapture(&s_coordinator.stack, 1, &saved), ZB_OK, "the coordinator's network is captured");
    Test_Expect(saved.keyCount == 1 && saved.keys[0].keyPresent && saved.trustCenterIeee == STACK_COORDINATOR_IEEE,
                "with its network key and its trust centre address");
    Test_Expect(saved.extendedPanId == extendedPanId && extendedPanId == STACK_COORDINATOR_IEEE,
                "and the extended PAN it formed, which a coordinator states and never joins");
    Test_Expect(saved.version == ZB_STATE_VERSION && saved.channel == STACK_CHANNEL && saved.nwkUpdateId == 0,
                "and 3.6.9's channel and nwkUpdateId, 0 on a network that never moved");
    saved.nwkUpdateId = 7;

    Test_ExpectStatus(Zb_StackStop(&s_coordinator.stack), ZB_OK, "and it stops");
    stackTurn(&s_coordinator, nowMs);
    Test_Expect(stackFirst(&s_coordinator, ZB_EVENT_STOPPED) != 0, "and has stopped");

    cfg = s_coordinator.cfg;
    Zb_memset(cfg.networkKey, 0, ZB_STACK_KEY_OCTETS);
    cfg.panId = 0;
    cfg.state = &saved;
    cfg.role = ZB_STACK_ROUTER;
    cfg.channelMask = (uint32_t)1 << STACK_CHANNEL;
    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "a coordinator's state is refused to a router: the state names the role that saved it");
    cfg.role = ZB_STACK_COORDINATOR;
    cfg.panId = STACK_PAN_ID + 1;
    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and a config naming another PAN than the state's contradicts it");
    cfg.panId = 0;
    cfg.channel = STACK_CHANNEL + 1;
    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and so does a config naming another channel");
    cfg.channel = 0;

    s_coordinator.logged = 0;
    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &cfg), ZB_OK,
                      "it starts from the state, naming neither its key, its PAN nor its channel");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_coordinator, ZB_EVENT_NETWORK_UP, nowMs, nowMs + 2000);
    up = stackFirst(&s_coordinator, ZB_EVENT_NETWORK_UP);

    Test_ExpectCount(up ? up->network.panId : 0, STACK_PAN_ID, "the network comes up on the state's PAN");
    Test_Expect(up != 0 && up->network.extendedPanId == extendedPanId, "and its extended PAN");
    Test_Expect(up != 0 && up->network.channel == STACK_CHANNEL, "on the state's channel");
    Test_ExpectCount(Zb_CoreNwk(Zb_StackCore(&s_coordinator.stack))->beaconInfo.updateId, 7,
                     "and its beacon carries the state's nwkUpdateId");
    Test_ExpectStatus(Zb_StackCapture(&s_coordinator.stack, 1, &after), ZB_OK, "and is captured again");
    Test_Expect(after.keyCount == 1 && Zb_memcmp(after.keys[0].key, saved.keys[0].key, ZB_STACK_KEY_OCTETS) == 0,
                "holding the network key it ran on");
    Test_Expect(after.keys[0].outgoingFrameCounter >= saved.keys[0].outgoingFrameCounter + ZB_STATE_COUNTER_BANK,
                "with its outgoing counter a bank past the saved one");
    Test_Expect(after.trustCenterIeee == STACK_COORDINATOR_IEEE, "and still its own trust centre");
    Test_Expect(after.channel == STACK_CHANNEL && after.nwkUpdateId == 7, "on the channel and update id it came back with");

    request = stackRequest(0x0000, asdu, (uint32_t)sizeof asdu, 0x0c05);
    Test_ExpectStatus(Zb_StackApsRequest(&s_router.stack, &request), ZB_OK, "the router, which stayed up, sends to it");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_router, ZB_EVENT_SENT, nowMs, nowMs + 10000);
    sent = stackFirst(&s_router, ZB_EVENT_SENT);

    Test_Expect(stackFirst(&s_coordinator, ZB_EVENT_DATA) != 0, "the coordinator's application gets the frame");
    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "and acknowledges it");
    Test_ExpectCount(sent ? sent->sent.attempts : 0, 1,
                     "on the first attempt: the router's window for it is behind the restored counter, so no retry was needed");
}

/* One side stopped, and started again from `state` on the network's channel: a joiner that comes back with no join. */
static ZbStatus stackRestart(StackSide *side, const Zb_State *state, uint32_t nowMs)
{
    side->cfg.state = state;
    side->cfg.channel = STACK_CHANNEL;

    (void)Zb_StackStop(&side->stack);
    stackTurn(side, nowMs);
    side->logged = 0;

    return Zb_StackStart(&side->stack, &side->cfg);
}

/* A router captured once it joined comes back from its state: no join, the same address, and both directions of
   traffic acknowledged on the first attempt once link status has measured the link again, since 3.6.9 keeps no
   neighbour table and a route request over a link of no outgoing cost is dropped (9121). */
void caseStackRouterComesBackFromItsState(void)
{
    static Zb_State saved;
    static Zb_State keyless;
    const Zb_StackEvent *up;
    const Zb_StackEvent *sent;
    Zb_StackConfig cfg;
    Aps_ApsdeReq request;
    uint8_t asdu[3] = { 0x01, 0x2c, 0x02 };
    uint16_t address;
    uint32_t joinsHeard;
    uint32_t nowMs;

    Test_Case("caseStackRouterComesBackFromItsState");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &s_router.cfg), ZB_OK, "and the router");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_router, ZB_EVENT_NETWORK_UP, 100, 60000);
    nowMs = stackRunFor(&s_coordinator, &s_router, nowMs, 2000);
    up = stackFirst(&s_router, ZB_EVENT_NETWORK_UP);
    address = up != 0 ? up->network.networkAddress : 0xffff;

    Test_Expect(up != 0, "the router joins");
    Test_ExpectStatus(Zb_StackCapture(&s_router.stack, 1, &saved), ZB_OK, "and is captured");
    Test_ExpectStatus(Zb_StackCapture(&s_router.stack, 0, &keyless), ZB_OK, "once more without its keys");
    Test_ExpectCount(saved.deviceType, NWK_DEVICE_ROUTER, "the state names a router");

    joinsHeard = Zb_CoreJoinsHeard(Zb_StackCore(&s_coordinator.stack));

    cfg = s_router.cfg;
    cfg.state = &saved;
    cfg.channel = STACK_CHANNEL + 1;
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "a joiner coming back on another channel than its state's is refused");
    saved.version = ZB_STATE_VERSION_OLDEST;
    saved.channel = 0;
    cfg.channel = 0;
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and one whose state is of the first schema, which holds no channel, names it");
    saved.version = ZB_STATE_VERSION;
    saved.channel = STACK_CHANNEL;
    cfg.channel = STACK_CHANNEL;
    cfg.channelMask = (uint32_t)1 << (STACK_CHANNEL - 1);
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "inside the channels it names, when it names any");
    cfg.channelMask = (uint32_t)1 << STACK_CHANNEL;
    cfg.role = ZB_STACK_END_DEVICE;
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &cfg), ZB_ERR_BAD_ARGUMENT, "as the role that saved the state");
    cfg.role = ZB_STACK_ROUTER;
    cfg.state = &keyless;
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &cfg), ZB_ERR_BAD_ARGUMENT,
                      "and with the network key it was sent, which a joiner's boot does not hold");

    Test_ExpectStatus(stackRestart(&s_router, &saved, nowMs), ZB_OK, "the router starts again from its state");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_router, ZB_EVENT_NETWORK_UP, nowMs, nowMs + 2000);
    up = stackFirst(&s_router, ZB_EVENT_NETWORK_UP);

    Test_Expect(up != 0 && up->network.networkAddress == address && up->network.panId == STACK_PAN_ID
                && up->network.extendedPanId == STACK_COORDINATOR_IEEE,
                "and is up at the address, PAN and extended PAN it had (3.6.9)");
    Test_ExpectCount(Zb_CoreJoinsHeard(Zb_StackCore(&s_coordinator.stack)), joinsHeard,
                     "without a join: the coordinator heard none");
    Test_Expect(Zb_CoreNwk(Zb_StackCore(&s_router.stack))->beaconInfo.extendedPanId == STACK_COORDINATOR_IEEE
                && Zb_CoreNwk(Zb_StackCore(&s_router.stack))->associationPermit,
                "and it beacons for its network with its door open, as a router that joined does");

    nowMs = stackRunFor(&s_coordinator, &s_router, nowMs, 2 * NWK_LINK_STATUS_PERIOD_MS + NWK_ROUTER_BOOTSTRAP_JITTER_MAX_MS);
    Test_Expect(Nwk_NeighborOf(Zb_CoreNwk(Zb_StackCore(&s_router.stack))->neighbors, 0x0000) != 0,
                "two link status periods on, it holds the coordinator as a neighbour again");

    request = stackRequest(0x0000, asdu, (uint32_t)sizeof asdu, 0x0d01);
    Test_ExpectStatus(Zb_StackApsRequest(&s_router.stack, &request), ZB_OK, "the router sends to the coordinator");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_router, ZB_EVENT_SENT, nowMs, nowMs + 10000);
    sent = stackFirst(&s_router, ZB_EVENT_SENT);
    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "which acknowledges it");
    Test_ExpectCount(sent ? sent->sent.attempts : 0, 1, "on the first attempt");

    s_coordinator.logged = 0;
    request = stackRequest(address, asdu, (uint32_t)sizeof asdu, 0x0d02);
    Test_ExpectStatus(Zb_StackApsRequest(&s_coordinator.stack, &request), ZB_OK, "and the coordinator to the router");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_coordinator, ZB_EVENT_SENT, nowMs, nowMs + 10000);
    sent = stackFirst(&s_coordinator, ZB_EVENT_SENT);
    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "which the restored router acknowledges");
    Test_Expect(stackFirst(&s_router, ZB_EVENT_DATA) != 0, "in its application");
}

/* An end device captured once it joined comes back from its state: no join and no rejoin, its parent sent the
   keepalive 3.6.10.8 recommends, no announcement unless the config asks for one, and its frames acknowledged. */
void caseStackEndDeviceComesBackFromItsState(void)
{
    static StackSide endDevice;
    static Zb_State saved;
    const Zb_StackEvent *up;
    const Zb_StackEvent *sent;
    Aps_ApsdeReq request;
    uint8_t asdu[3] = { 0x01, 0x2c, 0x02 };
    uint16_t address;
    uint32_t consumed;
    uint32_t nowMs;

    Test_Case("caseStackEndDeviceComesBackFromItsState");

    stackCoordinator(&s_coordinator);
    stackEndDevice(&endDevice);

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&endDevice.stack, &endDevice.cfg), ZB_OK, "and the end device");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_NETWORK_UP, 100, 60000);
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 2000);
    up = stackFirst(&endDevice, ZB_EVENT_NETWORK_UP);
    address = up != 0 ? up->network.networkAddress : 0xffff;

    Test_ExpectStatus(Zb_StackCapture(&endDevice.stack, 1, &saved), ZB_OK, "the end device joins and is captured");
    Test_Expect(saved.deviceType == NWK_DEVICE_END_DEVICE && saved.parentShort == 0x0000
                && saved.parentIeee == STACK_COORDINATOR_IEEE,
                "the state names an end device and its parent by both addresses");

    consumed = Zb_CoreZdpFramesConsumed(Zb_StackCore(&s_coordinator.stack));

    Test_ExpectStatus(stackRestart(&endDevice, &saved, nowMs), ZB_OK, "it starts again from its state");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_NETWORK_UP, nowMs, nowMs + 2000);
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 1000);
    up = stackFirst(&endDevice, ZB_EVENT_NETWORK_UP);

    Test_Expect(up != 0 && up->network.networkAddress == address, "and is up at the address it had (3.6.9)");
    Test_ExpectCount(Nwk_KeepalivesSent(Zb_CoreNwk(Zb_StackCore(&endDevice.stack))), 1,
                     "its parent sent one keepalive (3.6.10.8)");
    Test_ExpectCount(Zb_CoreParentLinkFailures(Zb_StackCore(&endDevice.stack)), 0, "which was acknowledged");
    Test_ExpectCount(Zb_CoreRejoins(Zb_StackCore(&endDevice.stack)), 0, "so nothing rejoined");
    Test_ExpectCount(Zb_CoreZdpFramesConsumed(Zb_StackCore(&s_coordinator.stack)), consumed,
                     "and no Device_annce reached the coordinator: no join or rejoin happened (2.4.3.1.11.1)");

    request = stackRequest(0x0000, asdu, (uint32_t)sizeof asdu, 0x0e01);
    Test_ExpectStatus(Zb_StackApsRequest(&endDevice.stack, &request), ZB_OK, "the end device sends to its parent");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_SENT, nowMs, nowMs + 10000);
    sent = stackFirst(&endDevice, ZB_EVENT_SENT);
    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "which acknowledges it");
    Test_ExpectCount(sent ? sent->sent.attempts : 0, 1, "on the first attempt");

    Test_ExpectStatus(Zb_StackCapture(&endDevice.stack, 1, &saved), ZB_OK,
                      "captured again, as an application saves before it stops: an older state repeats sequence numbers the parent's duplicate filters have seen");
    consumed = Zb_CoreZdpFramesConsumed(Zb_StackCore(&s_coordinator.stack));
    endDevice.cfg.announceAfterRestore = 1;
    Test_ExpectStatus(stackRestart(&endDevice, &saved, nowMs), ZB_OK, "restored again with the announcement asked for");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_NETWORK_UP, nowMs, nowMs + 2000);
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 1000);
    Test_Expect(Zb_CoreZdpFramesConsumed(Zb_StackCore(&s_coordinator.stack)) > consumed
                && Zb_CoreLastZdpCluster(Zb_StackCore(&s_coordinator.stack)) == 0x0013,
                "it sends a Device_annce, which the coordinator takes");
}

/* A restored end device whose parent does not answer: its first keepalives go unacknowledged, and past the threshold
   it rejoins, through the same parent once that one answers again, keeping its address (3.6.1.12). */
void caseStackRestoredEndDeviceRejoinsWhenItsParentIsGone(void)
{
    static StackSide endDevice;
    static Zb_State saved;
    Loopback_Outcome lost[ZB_CORE_PARENT_LINK_RETRY_THRESHOLD_DEFAULT + 1];
    const Zb_StackEvent *up;
    uint16_t address;
    uint32_t nowMs;
    uint32_t i;

    Test_Case("caseStackRestoredEndDeviceRejoinsWhenItsParentIsGone");

    stackCoordinator(&s_coordinator);
    stackEndDevice(&endDevice);

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&endDevice.stack, &endDevice.cfg), ZB_OK, "and the end device");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_NETWORK_UP, 100, 60000);
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 2000);
    up = stackFirst(&endDevice, ZB_EVENT_NETWORK_UP);
    address = up != 0 ? up->network.networkAddress : 0xffff;
    Test_ExpectStatus(Zb_StackCapture(&endDevice.stack, 1, &saved), ZB_OK, "the end device joins and is captured");

    Zb_memset(lost, 0, (uint32_t)sizeof lost);

    for (i = 0; i < ZB_CORE_PARENT_LINK_RETRY_THRESHOLD_DEFAULT + 1; i++)
        lost[i].status = ZB_ERR_DEVICE;

    Test_ExpectStatus(stackRestart(&endDevice, &saved, nowMs), ZB_OK, "it starts again from its state");
    LoopbackRadio_ScriptOutcomes(&endDevice.model, lost, ZB_CORE_PARENT_LINK_RETRY_THRESHOLD_DEFAULT + 1);
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_NETWORK_UP, nowMs, nowMs + 2000);

    for (i = 0; i < 1000 && Zb_CoreRejoins(Zb_StackCore(&endDevice.stack)) == 0; i++)
        nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, STACK_TURN_MS);

    Test_ExpectCount(Nwk_KeepalivesSent(Zb_CoreNwk(Zb_StackCore(&endDevice.stack))),
                     ZB_CORE_PARENT_LINK_RETRY_THRESHOLD_DEFAULT + 1,
                     "its keepalive and the ones up to the threshold went unacknowledged (5403-5405)");
    Test_ExpectCount(Zb_CoreRejoins(Zb_StackCore(&endDevice.stack)), 1, "and past it, it rejoined (5405-5407)");
    Test_ExpectCount(Zb_CoreParentLinkFailures(Zb_StackCore(&endDevice.stack)), 0,
                     "which clears the failure counter (5427)");
    Test_ExpectCount(Mac_Pib(Zb_CoreMac(Zb_StackCore(&endDevice.stack)))->shortAddress, address,
                     "at the address it had");
}

/* A sleepy end device captured and started again from its state polls its parent as before and takes the parent's
   frame through its poll; when its polls then go unacknowledged past the threshold, it rejoins (2.5.4.5.5.1), the
   rejoin's answer coming through the rejoin's own Data Request. */
void caseStackSleepyEndDeviceRestoresAndRejoins(void)
{
    static StackSide endDevice;
    static Zb_State saved;
    Loopback_Outcome lost[ZB_CORE_PARENT_LINK_RETRY_THRESHOLD_DEFAULT + 1];
    const Zb_StackEvent *up;
    const Zb_StackEvent *sent;
    Aps_ApsdeReq request;
    uint8_t asdu[3] = { 0x01, 0x30, 0x02 };
    uint32_t pollsBefore;
    uint16_t address;
    uint32_t nowMs;
    uint32_t i;

    Test_Case("caseStackSleepyEndDeviceRestoresAndRejoins");

    stackCoordinator(&s_coordinator);
    stackEndDevice(&endDevice);
    endDevice.cfg.sleepy = 1;
    endDevice.cfg.pollIntervalMs = 1000;

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&endDevice.stack, &endDevice.cfg), ZB_OK, "and a sleepy end device");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_NETWORK_UP, 100, 60000);
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 3000);
    up = stackFirst(&endDevice, ZB_EVENT_NETWORK_UP);
    address = up != 0 ? up->network.networkAddress : 0xffff;
    Test_ExpectStatus(Zb_StackCapture(&endDevice.stack, 1, &saved), ZB_OK, "it joins and is captured");

    Test_ExpectStatus(stackRestart(&endDevice, &saved, nowMs), ZB_OK, "and starts again from its state, still sleepy");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &endDevice, ZB_EVENT_NETWORK_UP, nowMs, nowMs + 2000);
    pollsBefore = Nwk_PollsSent(Zb_CoreNwk(Zb_StackCore(&endDevice.stack)));
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 3000);
    Test_Expect(Nwk_PollsSent(Zb_CoreNwk(Zb_StackCore(&endDevice.stack))) > pollsBefore,
                "the restored device polls the parent its state named");

    request = stackRequest(address, asdu, (uint32_t)sizeof asdu, 0x0e13);
    Test_ExpectStatus(Zb_StackApsRequest(&s_coordinator.stack, &request), ZB_OK, "the coordinator sends to it");
    nowMs = stackRunUntil(&s_coordinator, &endDevice, &s_coordinator, ZB_EVENT_SENT, nowMs, nowMs + 20000);
    sent = stackFirst(&s_coordinator, ZB_EVENT_SENT);
    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "and the frame is taken by its poll");
    Test_Expect(stackFirst(&endDevice, ZB_EVENT_DATA) != 0, "and delivered");

    Zb_memset(lost, 0, (uint32_t)sizeof lost);

    for (i = 0; i < ZB_CORE_PARENT_LINK_RETRY_THRESHOLD_DEFAULT + 1; i++)
        lost[i].status = ZB_ERR_NO_ACK;

    LoopbackRadio_ScriptOutcomes(&endDevice.model, lost, ZB_CORE_PARENT_LINK_RETRY_THRESHOLD_DEFAULT + 1);

    for (i = 0; i < 3000 && Zb_CoreRejoins(Zb_StackCore(&endDevice.stack)) == 0; i++)
        nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, STACK_TURN_MS);

    Test_ExpectCount(Zb_CoreRejoins(Zb_StackCore(&endDevice.stack)), 1,
                     "polls its parent never acknowledged, past the threshold, start a rejoin");
    nowMs = stackRunFor(&s_coordinator, &endDevice, nowMs, 3000);
    Test_ExpectCount(Nwk_JoinStateOf(Zb_CoreNwk(Zb_StackCore(&endDevice.stack))), NWK_JOIN_JOINED,
                     "which the parent answers");
    Test_ExpectCount(Mac_Pib(Zb_CoreMac(Zb_StackCore(&endDevice.stack)))->shortAddress, address,
                     "and it keeps the address it had");
}

/* The library's records reach the application's own pool: a malformed frame the coordinator hears is reported by the
   MAC, and the security module reports into the same pool. */
void caseStackRecordsReachTheApplicationsLog(void)
{
    static Log_Log pool;
    static const uint8_t malformed[3] = { 0x41, 0x88, 0x01 };
    Loopback_FrameSpec spec;
    uint32_t nowMs;

    Test_Case("caseStackRecordsReachTheApplicationsLog");

    Test_ExpectStatus(Log_Init(&pool), ZB_OK, "the application holds a record pool");
    stackCoordinator(&s_coordinator);
    s_coordinator.cfg.log = &pool;

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "a coordinator starts with it");

    for (nowMs = 100; nowMs < 2000 && stackFirst(&s_coordinator, ZB_EVENT_NETWORK_UP) == 0; nowMs += STACK_TURN_MS)
        stackTurn(&s_coordinator, nowMs);

    Test_Expect(Zb_CoreLayers(Zb_StackCore(&s_coordinator.stack))->security.log == &pool,
                "and its security module reports into that pool");

    Zb_memset(&spec, 0, (uint32_t)sizeof spec);
    spec.len = (uint32_t)sizeof malformed;
    spec.bytes = malformed;
    spec.rssiDbm = -60;
    spec.lqi = 200;
    (void)LoopbackRadio_Inject(&s_coordinator.model, &spec, 1);
    stackTurn(&s_coordinator, nowMs);
    stackTurn(&s_coordinator, nowMs + STACK_TURN_MS);

    Test_Expect(Log_Count(&pool) > 0 && pool.ring[pool.head].component == LOG_COMP_MAC_RX,
                "a malformed frame it hears is a MAC record in the application's pool");
}

/* A router that joined, forgot its network (a factory reset) and joins again with joining open is admitted again, at the
   address it had: an unsecured Initial Join from a device the parent knows is rejected only for an unsecured NWK
   rejoin (3.6.1.6.1.3, 8106-8110), and the trust centre admits a known device's unsecured join (12433-12449). */
void caseStackRouterJoinsAgainAfterAReset(void)
{
    const Zb_StackEvent *up;
    uint16_t address;
    uint32_t joinsHeard;
    uint32_t nowMs;

    Test_Case("caseStackRouterJoinsAgainAfterAReset");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &s_router.cfg), ZB_OK, "and the router");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_router, ZB_EVENT_NETWORK_UP, 100, 60000);
    nowMs = stackRunFor(&s_coordinator, &s_router, nowMs, 2000);
    up = stackFirst(&s_router, ZB_EVENT_NETWORK_UP);
    address = up != 0 ? up->network.networkAddress : 0xffff;
    joinsHeard = Zb_CoreJoinsHeard(Zb_StackCore(&s_coordinator.stack));

    Test_Expect(up != 0, "the router joins");

    (void)Zb_StackStop(&s_router.stack);
    stackTurn(&s_router, nowMs);
    s_router.logged = 0;
    Test_ExpectStatus(Zb_CoreForgetLinkKey(Zb_StackCore(&s_coordinator.stack), STACK_ROUTER_IEEE), ZB_OK,
                      "the coordinator's application forgets the trust centre link key the router took");

    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &s_router.cfg), ZB_OK,
                      "it starts again with no state, as a product does after a factory reset");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_router, ZB_EVENT_NETWORK_UP, nowMs, nowMs + 60000);
    up = stackFirst(&s_router, ZB_EVENT_NETWORK_UP);

    Test_Expect(up != 0 && stackFirst(&s_router, ZB_EVENT_NETWORK_FAILED) == 0,
                "and joins again while the coordinator's door is open");
    Test_ExpectCount(up != 0 ? up->network.networkAddress : 0xffff, address, "at the address the parent holds for it");
    Test_ExpectCount(Zb_CoreJoinsHeard(Zb_StackCore(&s_coordinator.stack)), joinsHeard + 1,
                     "the trust centre heard the second join");
}

/* The application's source route, held until the device's own route record says otherwise, which is then told. */
void caseStackSourceRoutesAreSeededAndTold(void)
{
    static const uint8_t frame[] = { 0x5b };
    Nwk_RoutingTableEntry *route = 0;
    const Zb_StackEvent *told = 0;
    Aps_ApsdeReq request;
    Nwk_Nwk *routerNwk;
    uint16_t routerAddress;
    uint16_t relays[2];
    uint32_t nowMs;
    uint32_t i;

    Test_Case("caseStackSourceRoutesAreSeededAndTold");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);

    relays[0] = 0x4444;
    Test_ExpectStatus(Zb_StackSetSourceRoute(&s_coordinator.stack, 0x1234, relays, 1), ZB_ERR_NOT_READY,
                      "no source route before the network is up");

    nowMs = stackJoinRouter();
    routerNwk = &Zb_StackCore(&s_router.stack)->layers.nwk;
    routerAddress = Mac_Pib(Zb_CoreMac(Zb_StackCore(&s_router.stack)))->shortAddress;

    Test_ExpectStatus(Zb_StackSetSourceRoute(&s_coordinator.stack, routerAddress, relays, 1), ZB_OK,
                      "the coordinator's application seeds a route to the router through a relay it kept");
    Test_ExpectStatus(Zb_StackSetSourceRoute(&s_coordinator.stack, 0xfffc, relays, 1), ZB_ERR_BAD_ARGUMENT,
                      "and none to a broadcast address");
    nowMs = stackRun(nowMs, 4);
    Test_ExpectCount(stackOwnCount(ZB_EVENT_ROUTE, 0, &told), 0, "its own seed is not told back");

    for (i = 0; i < NWK_ROUTE_MAX && route == 0; i++)
    {
        if (!routerNwk->routes[i].inUse || routerNwk->routes[i].destinationAddress == 0x0000)
            route = &routerNwk->routes[i];
    }

    Test_Expect(route != 0, "a row of the router's routing table");

    if (route == 0)
        return;

    Zb_memset(route, 0, (uint32_t)sizeof *route);
    route->inUse = 1;
    route->destinationAddress = 0x0000;
    route->status = NWK_ROUTE_ACTIVE;
    route->nextHopAddress = 0x0000;
    route->manyToOne = 1;
    route->routeRecordRequired = 1;

    request = stackRequest(0x0000, frame, (uint32_t)sizeof frame, 0x0e01);
    Test_ExpectStatus(Zb_StackApsRequest(&s_router.stack, &request), ZB_OK,
                      "the router, owing the concentrator a route record, sends it a frame");
    nowMs = stackRun(nowMs, 6);

    Test_ExpectCount(stackOwnCount(ZB_EVENT_ROUTE, 0, &told), 1, "the record reaches the coordinator and is told");
    Test_Expect(told != 0 && told->route.destination == routerAddress && told->route.reason == ZB_ROUTE_DIRECT
                && told->route.relayCount == 0, "as the router's route, now direct, and the seed gone");
    Test_Expect(Nwk_SourceRouteOf(Zb_StackCore(&s_coordinator.stack)->layers.nwk.sourceRoutes, routerAddress, nowMs)
                == 0, "from the coordinator's table");
}

/* A device that leaves is told to the application with its extended address and whether it said it rejoins. */
void caseStackDeparturesAreTold(void)
{
    const Zb_StackEvent *left = 0;
    uint16_t routerAddress;
    uint32_t nowMs;

    Test_Case("caseStackDeparturesAreTold");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);
    nowMs = stackJoinRouter();
    routerAddress = Mac_Pib(Zb_CoreMac(Zb_StackCore(&s_router.stack)))->shortAddress;

    Test_ExpectCount(Nwk_LeaveRequest(&Zb_StackCore(&s_router.stack)->layers.nwk, NWK_LEAVE_ADDRESS_NULL, 0, 0, nowMs),
                     NWK_LEAVE_STATUS_SUCCESS, "the router leaves the network, not to rejoin");
    nowMs = stackRun(nowMs, 6);

    Test_ExpectCount(stackOwnCount(ZB_EVENT_DEVICE_LEFT, 0, &left), 1, "the coordinator hears it and tells it once");
    Test_Expect(left != 0 && left->left.ieee == STACK_ROUTER_IEEE && left->left.networkAddress == routerAddress
                && left->left.rejoin == 0, "with the router's addresses, and no rejoin");
    Test_ExpectCount(Zb_CoreDeparturesDropped(Zb_StackCore(&s_coordinator.stack)), 0, "and nothing lost");
}

/* A device's address learned by the coordinator's map is told to the application, beside its announcement. */
void caseStackAddressesAreTold(void)
{
    const Zb_StackEvent *address = 0;
    uint32_t nowMs;
    uint32_t i;

    Test_Case("caseStackAddressesAreTold");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);
    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &s_router.cfg), ZB_OK, "and the router");

    for (nowMs = 100; nowMs < 60000 && stackFirst(&s_coordinator, ZB_EVENT_DEVICE_JOINED) == 0; )
        nowMs = stackRun(nowMs, 1);

    for (i = 0; i < s_coordinator.logged && address == 0; i++)
    {
        if (s_coordinator.log[i].type == ZB_EVENT_ADDRESS && s_coordinator.log[i].address.ieee == STACK_ROUTER_IEEE)
            address = &s_coordinator.log[i];
    }

    Test_Expect(address != 0 && address->address.reason == ZB_ADDRESS_LEARNED
                && address->address.networkAddress
                   == Mac_Pib(Zb_CoreMac(Zb_StackCore(&s_router.stack)))->shortAddress,
                "the router's pair is told as learned, at the address it joined with");
    (void)nowMs;
}

/* A coordinator's side whose radio measures when `measures` is 1, before any network is formed. */
static void stackScanner(StackSide *side, int measures)
{
    uint8_t octets[RADIO_ADDR_LEN];
    Radio_Caps caps;
    uint32_t i;

    Zb_memset(side, 0, (uint32_t)sizeof *side);
    Test_BandACapsAcks(&caps);
    caps.hasEnergyScan = measures;
    LoopbackRadio_Init(&side->model, &caps);

    for (i = 0; i < RADIO_ADDR_LEN; i++)
        octets[i] = (uint8_t)(STACK_COORDINATOR_IEEE >> (8 * i));

    LoopbackRadio_SetFactoryAddress(&side->model, octets);
    Zb_StackCoordinatorDefaults(&side->cfg);
    side->cfg.radio = LoopbackRadio_Seam(&side->model);
    stackEndpoint(&side->cfg);
}

/* The scan run to its stop, the radio pumped as a host loop pumps its backend. */
static uint32_t stackScanToStop(StackSide *side, uint32_t nowMs, uint32_t untilMs)
{
    for (; nowMs < untilMs && stackFirst(side, ZB_EVENT_STOPPED) == 0; nowMs += STACK_TURN_MS)
    {
        stackTurn(side, nowMs);
        (void)LoopbackRadio_Pump(&side->model, nowMs);
    }

    return nowMs;
}

/* NLME-ED-SCAN through the stack before a network is formed: its arguments judged, four channels measured with
   nothing sent, one level each in the radio's dBm and none for the channel nothing measured, the stop that follows,
   and the coordinator then started on the channel the application chose. */
void caseStackEnergyScanReportsEachChannel(void)
{
    static const int32_t levels[16] = { -70, -94, -94, -94, -85, -94, -94, -94,
                                        -94, RADIO_SCAN_NO_LEVEL, -94, -94, -94, -94, -92, -94 };
    const uint32_t mask = ((uint32_t)1 << 11) | ((uint32_t)1 << 15) | ((uint32_t)1 << 20) | ((uint32_t)1 << 25);
    Loopback_Sent sent[LOOPBACK_TX_MAX];
    const Zb_StackEvent *scan;
    const Zb_StackEvent *up;
    uint32_t scanAt = 0;
    uint32_t stopAt = 0;
    uint32_t nowMs;
    uint32_t i;

    Test_Case("caseStackEnergyScanReportsEachChannel");

    stackScanner(&s_coordinator, 1);
    LoopbackRadio_ScriptEnergy(&s_coordinator.model, levels, 16);

    Test_ExpectStatus(Zb_StackEnergyScan(&s_coordinator.stack, &s_coordinator.cfg, 0, 3), ZB_ERR_BAD_ARGUMENT,
                      "a scan of no channel is refused");
    Test_ExpectStatus(Zb_StackEnergyScan(&s_coordinator.stack, &s_coordinator.cfg, (uint32_t)1 << 10, 3),
                      ZB_ERR_BAD_ARGUMENT, "and of channel 10");
    Test_ExpectStatus(Zb_StackEnergyScan(&s_coordinator.stack, &s_coordinator.cfg, mask, 15), ZB_ERR_BAD_ARGUMENT,
                      "and a ScanDuration past 14");
    Test_ExpectStatus(Zb_StackEnergyScan(&s_coordinator.stack, &s_coordinator.cfg, mask, 3), ZB_OK,
                      "a scan of channels 11, 15, 20 and 25 starts");
    Test_ExpectStatus(Zb_StackEnergyScan(&s_coordinator.stack, &s_coordinator.cfg, mask, 3), ZB_ERR_BUSY,
                      "and no second one while it runs");

    nowMs = stackScanToStop(&s_coordinator, 100, 5000);
    scan = stackFirst(&s_coordinator, ZB_EVENT_ENERGY_SCAN);

    for (i = 0; i < s_coordinator.logged; i++)
    {
        scanAt = s_coordinator.log[i].type == ZB_EVENT_ENERGY_SCAN ? i + 1 : scanAt;
        stopAt = s_coordinator.log[i].type == ZB_EVENT_STOPPED ? i + 1 : stopAt;
    }

    Test_ExpectStatus(scan ? scan->status : ZB_ERR_INTERNAL, ZB_OK, "the scan is reported");
    Test_Expect(scanAt != 0 && stopAt > scanAt, "and ZB_EVENT_STOPPED follows it");
    Test_Expect(stackFirst(&s_coordinator, ZB_EVENT_NETWORK_UP) == 0, "with no network formed");
    Test_ExpectCount(LoopbackRadio_Sent(&s_coordinator.model, sent, LOOPBACK_TX_MAX), 0, "and nothing sent");
    Test_ExpectCount(scan ? scan->energy.count : 0, 4, "one level per channel asked");
    Test_Expect(scan != 0 && scan->energy.levels[0].channel == 11 && scan->energy.levels[0].measured
                && scan->energy.levels[0].dbm == -70 && scan->energy.levels[1].dbm == -85
                && scan->energy.levels[3].channel == 25 && scan->energy.levels[3].dbm == -92,
                "lowest first, each in the radio's dBm");
    Test_Expect(scan != 0 && scan->energy.levels[2].channel == 20 && !scan->energy.levels[2].measured
                && scan->energy.levels[2].dbm == 0, "and channel 20, which nothing measured, has no level");

    s_coordinator.logged = 0;
    s_coordinator.cfg.channel = 11;
    s_coordinator.cfg.panId = STACK_PAN_ID;
    Test_ParseHex(STACK_NETWORK_KEY_HEX, s_coordinator.cfg.networkKey, ZB_STACK_KEY_OCTETS);
    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK,
                      "the coordinator then starts on the channel the application chose");

    for (i = 0; i < 200 && stackFirst(&s_coordinator, ZB_EVENT_NETWORK_UP) == 0; i++, nowMs += STACK_TURN_MS)
        stackTurn(&s_coordinator, nowMs);

    up = stackFirst(&s_coordinator, ZB_EVENT_NETWORK_UP);
    Test_ExpectCount(up ? up->network.channel : 0, 11, "and forms its network there");
}

/* A radio with no energy scan: the scan is reported ZB_ERR_UNSUPPORTED with no level, and the stack stops. */
void caseStackEnergyScanNeedsARadioThatMeasures(void)
{
    const Zb_StackEvent *scan;

    Test_Case("caseStackEnergyScanNeedsARadioThatMeasures");

    stackScanner(&s_coordinator, 0);

    Test_ExpectStatus(Zb_StackEnergyScan(&s_coordinator.stack, &s_coordinator.cfg, (uint32_t)1 << 11, 0), ZB_OK,
                      "a scan on a radio that measures nothing starts");
    (void)stackScanToStop(&s_coordinator, 100, 1000);
    scan = stackFirst(&s_coordinator, ZB_EVENT_ENERGY_SCAN);

    Test_ExpectStatus(scan ? scan->status : ZB_ERR_INTERNAL, ZB_ERR_UNSUPPORTED, "and is reported unsupported");
    Test_ExpectCount(scan ? scan->energy.count : 1, 0, "with no level");
    Test_Expect(stackFirst(&s_coordinator, ZB_EVENT_STOPPED) != 0, "and the stack stops");
}

/* The security module of one side's library. */
static Security *stackSecurity(StackSide *side)
{
    return &Zb_CoreLayers(Zb_StackCore(&side->stack))->security;
}

/* The unique entry `security` holds for `ieee`, or 0. */
static const Security_KeyPairEntry *stackUniquePair(Security *security, uint64_t ieee)
{
    const Security_KeyPairEntry *entry = Security_KeyPairAt(security, Security_FindKeyPairByIeee(security, ieee));

    return entry != 0 && entry->deviceIeee == ieee && entry->linkKeyType == SECURITY_LINK_KEY_UNIQUE ? entry : 0;
}

/* R23.1 4.7.3.8 at the joiner: once it holds the network key, a router asks for its own trust centre link key, takes
   the key derived from the coordinator's seed unverified, sends Verify-Key, and is confirmed. Both ends then hold it
   verified, a capture keeps it, and the router comes back from that state on the same key. */
void caseStackJoinerTakesItsOwnLinkKey(void)
{
    static Zb_State saved;
    const Security_KeyPairEntry *joiner;
    const Security_KeyPairEntry *centre;
    const Zb_StackEvent *sent;
    Aps_ApsdeReq request;
    uint8_t asdu[3] = { 0x01, 0x2d, 0x02 };
    uint8_t seed[ZB_STACK_KEY_OCTETS];
    uint8_t address[8];
    uint8_t derived[16];
    uint32_t nowMs;
    uint32_t i;

    Test_Case("caseStackJoinerTakesItsOwnLinkKey");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);
    Test_ParseHex(STACK_LINK_KEY_SEED_HEX, seed, ZB_STACK_KEY_OCTETS);

    for (i = 0; i < 8; i++)
        address[i] = (uint8_t)(STACK_ROUTER_IEEE >> (8 * i));

    Test_ExpectStatus(Aes_MmoHmac(seed, ZB_STACK_KEY_OCTETS, address, 8, derived), ZB_OK,
                      "the key the router should end with: B.1.4's keyed hash of its address under the seed");

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &s_router.cfg), ZB_OK, "and the router");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_router, ZB_EVENT_NETWORK_UP, 100, 60000);
    nowMs = stackRunFor(&s_coordinator, &s_router, nowMs, 2000);

    joiner = stackUniquePair(stackSecurity(&s_router), STACK_COORDINATOR_IEEE);
    centre = stackUniquePair(stackSecurity(&s_coordinator), STACK_ROUTER_IEEE);

    Test_ExpectCount(Aps_TcLinkKeyRequestsSent(&Zb_CoreLayers(Zb_StackCore(&s_router.stack))->aps), 1,
                     "the router asked once");
    Test_ExpectCount(Aps_TcLinkKeyState(&Zb_CoreLayers(Zb_StackCore(&s_router.stack))->aps), APS_TCLK_VERIFIED,
                     "and its update is verified");
    Test_Expect(joiner != 0 && joiner->keyAttributes == SECURITY_KEYPAIR_ATTR_VERIFIED
                && Zb_memcmp(joiner->key, derived, 16) == 0,
                "the router holds the derived key for its trust centre, verified");
    Test_Expect(centre != 0 && centre->keyAttributes == SECURITY_KEYPAIR_ATTR_VERIFIED
                && Zb_memcmp(centre->key, derived, 16) == 0,
                "and the coordinator holds the same key for the router, verified (4.4.7.2.3 step 9)");

    request = stackRequest(0x0000, asdu, (uint32_t)sizeof asdu, 0x0c07);
    request.txOptions |= APS_TX_OPTION_SECURITY;
    Test_ExpectStatus(Zb_StackApsRequest(&s_router.stack, &request), ZB_OK, "an APS-secured frame to the coordinator");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_router, ZB_EVENT_SENT, nowMs, nowMs + 5000);
    sent = stackFirst(&s_router, ZB_EVENT_SENT);
    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "is acknowledged under the new key");

    Test_ExpectStatus(Zb_StackCapture(&s_router.stack, 1, &saved), ZB_OK, "the router is captured");
    Test_ExpectStatus(stackRestart(&s_router, &saved, nowMs), ZB_OK, "and starts again from that state");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_router, ZB_EVENT_NETWORK_UP, nowMs, nowMs + 2000);
    nowMs = stackRunFor(&s_coordinator, &s_router, nowMs, 1000);
    joiner = stackUniquePair(stackSecurity(&s_router), STACK_COORDINATOR_IEEE);

    Test_Expect(joiner != 0 && joiner->keyAttributes == SECURITY_KEYPAIR_ATTR_VERIFIED
                && Zb_memcmp(joiner->key, derived, 16) == 0, "holding the verified key again (4.4.12.1)");
    Test_ExpectCount(Aps_TcLinkKeyRequestsSent(&Zb_CoreLayers(Zb_StackCore(&s_router.stack))->aps), 0,
                     "and asking for none: a restored device keeps the key it saved");
}

/* A joiner told to keep the key it joined with, as an older device does, asks for none; the trust centre serves it on
   the global key as before. */
void caseStackJoinerKeepsItsJoinedKey(void)
{
    const Zb_StackEvent *sent;
    Aps_ApsdeReq request;
    uint8_t asdu[3] = { 0x01, 0x2e, 0x02 };
    uint32_t nowMs;

    Test_Case("caseStackJoinerKeepsItsJoinedKey");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);
    s_router.cfg.keepJoinedLinkKey = 1;

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK, "the coordinator starts");
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &s_router.cfg), ZB_OK, "and a router that keeps its joined key");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_router, ZB_EVENT_NETWORK_UP, 100, 60000);
    nowMs = stackRunFor(&s_coordinator, &s_router, nowMs, 2000);

    Test_ExpectCount(Aps_TcLinkKeyRequestsSent(&Zb_CoreLayers(Zb_StackCore(&s_router.stack))->aps), 0,
                     "the router asks for no key");
    Test_Expect(stackUniquePair(stackSecurity(&s_router), STACK_COORDINATOR_IEEE) == 0
                && stackUniquePair(stackSecurity(&s_coordinator), STACK_ROUTER_IEEE) == 0,
                "and neither end holds a unique key for the other");

    request = stackRequest(0x0000, asdu, (uint32_t)sizeof asdu, 0x0c08);
    request.txOptions |= APS_TX_OPTION_SECURITY;
    Test_ExpectStatus(Zb_StackApsRequest(&s_router.stack, &request), ZB_OK, "an APS-secured frame to the coordinator");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_router, ZB_EVENT_SENT, nowMs, nowMs + 5000);
    sent = stackFirst(&s_router, ZB_EVENT_SENT);
    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "is acknowledged under the global key");
}

/* A trust centre that answers no Request-Key, here one without a link key seed: the joiner asks three times, five
   seconds apart, then gives up and keeps the key it joined with, and still talks. */
void caseStackJoinerGivesUpOnASilentTrustCentre(void)
{
    const Zb_StackEvent *sent;
    Aps_ApsdeReq request;
    uint8_t asdu[3] = { 0x01, 0x2f, 0x02 };
    uint32_t nowMs;

    Test_Case("caseStackJoinerGivesUpOnASilentTrustCentre");

    stackCoordinator(&s_coordinator);
    stackRouter(&s_router);
    Zb_memset(s_coordinator.cfg.linkKeySeed, 0, ZB_STACK_KEY_OCTETS);

    Test_ExpectStatus(Zb_StackStart(&s_coordinator.stack, &s_coordinator.cfg), ZB_OK,
                      "a coordinator with no link key seed, which answers no Request-Key");
    Test_ExpectStatus(Zb_StackStart(&s_router.stack, &s_router.cfg), ZB_OK, "and a router");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_router, ZB_EVENT_NETWORK_UP, 100, 60000);
    nowMs = stackRunFor(&s_coordinator, &s_router, nowMs, 3 * ZB_CORE_TC_LINK_KEY_WAIT_MS + 1000);

    Test_ExpectCount(Aps_TcLinkKeyRequestsSent(&Zb_CoreLayers(Zb_StackCore(&s_router.stack))->aps),
                     ZB_CORE_TC_LINK_KEY_ATTEMPTS, "the router asks three times");
    Test_ExpectCount(Aps_TcLinkKeyState(&Zb_CoreLayers(Zb_StackCore(&s_router.stack))->aps), APS_TCLK_ABANDONED,
                     "then gives the update up");
    Test_Expect(stackUniquePair(stackSecurity(&s_router), STACK_COORDINATOR_IEEE) == 0,
                "holding no unique key, only the one it joined with");

    s_router.logged = 0;
    request = stackRequest(0x0000, asdu, (uint32_t)sizeof asdu, 0x0c09);
    Test_ExpectStatus(Zb_StackApsRequest(&s_router.stack, &request), ZB_OK, "a frame to the coordinator");
    nowMs = stackRunUntil(&s_coordinator, &s_router, &s_router, ZB_EVENT_SENT, nowMs, nowMs + 5000);
    sent = stackFirst(&s_router, ZB_EVENT_SENT);
    Test_ExpectStatus(sent ? sent->status : ZB_ERR_INTERNAL, ZB_OK, "is still acknowledged");
}
