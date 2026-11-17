/*
 * The third example: a Zigbee coordinator that forms a network, lets devices join, and asks every device that joins
 * what it is: its node descriptor, its active endpoints, each endpoint's simple descriptor, and the Basic cluster's
 * manufacturer name and model.
 *
 * The application is two kinds of state machine over the stack's events: its own, from starting through serving to
 * stopping, as the first example's; and one per device in `interview.c`, which asks one step at a time and moves on
 * when the answer comes. The ZDP requests go through the device object's client half, so this example is built only
 * with ZB_ZDO_CLIENT; the ZCL read is written with the Cluster Library's codecs and sent as an APS request.
 *
 *   ./example_interview --path <port> --channel 25
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "interview.h"
#include "port.h"
#include "zb_time.h"
#include "zb_utils.h"
#include "zb_stack.h"
#include "zcl.h"

/* The endpoint this coordinator advertises: the Home Automation profile, a client of the Basic cluster, which is the
   endpoint its reads go from and their answers come to. */
#define APP_ENDPOINT 0x01
#define APP_PROFILE 0x0104
#define APP_DEVICE_ID 0x0005          /* Configuration Tool, Table 2-48's device identifiers */

#define EVENT_WAIT_MS 100
#define APP_SECONDS_MAX 2147483       /* Zb_timeWithin measures a span under 2^31 ms */

/* The application's own states: waiting for its network, serving it, and stopping. */
typedef enum AppState
{
    APP_STARTING,
    APP_SERVING,
    APP_STOPPING,
    APP_DONE
} AppState;

typedef struct Options
{
    const char *path;
    uint32_t channel;
    uint16_t panId;
    uint64_t extendedPanId;
    uint32_t permitSeconds;
    uint32_t baud;
    uint64_t ieee;
    uint32_t seconds;
} Options;

/* The stack and the interviews are the application's memory and large ones, so they are static rather than on main's
   frame. */
static Zb_Stack s_stack;
static Interview s_interview;
static volatile sig_atomic_t s_signal = 0;

static void onSignal(int number)
{
    (void)number;

    s_signal = 1;
}

static void usage(void)
{
    printf("usage: example_interview --path <serial device>\n"
           "                         [--channel 25] [--pan beef] [--extended-pan hex]\n"
           "                         [--permit seconds] [--baud n] [--ieee hex] [--seconds n]\n"
           "  --path      the RCP's device node: /dev/cu.usbmodem* on macOS, /dev/ttyACM* on Linux, COM<n> on Windows\n"
           "  --channel   defaults to 25, and is the one your network should be alone on\n"
           "  --permit    how long joining stays open, 180 s by default, 0 to keep it closed\n"
           "  --baud      the link's rate: 57600 for a ConBee I or a RaspBee I, the port's default otherwise\n"
           "  --ieee      this device's extended address, for a unit taking over another's identity; the RCP's own\n"
           "              address otherwise\n"
           "  --seconds   0, the default, runs until Ctrl-C\n");
}

static int parseOptions(int argc, char **argv, Options *out)
{
    int i;

    memset(out, 0, sizeof *out);

    out->channel = 25;
    out->panId = 0xbeef;
    out->permitSeconds = 180;

    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--path") == 0 && i + 1 < argc)
            out->path = argv[++i];
        else if (strcmp(argv[i], "--channel") == 0 && i + 1 < argc)
            out->channel = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--pan") == 0 && i + 1 < argc)
            out->panId = (uint16_t)strtoul(argv[++i], 0, 16);
        else if (strcmp(argv[i], "--extended-pan") == 0 && i + 1 < argc)
            out->extendedPanId = strtoull(argv[++i], 0, 16);
        else if (strcmp(argv[i], "--permit") == 0 && i + 1 < argc)
            out->permitSeconds = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--baud") == 0 && i + 1 < argc)
            out->baud = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--seconds") == 0 && i + 1 < argc)
            out->seconds = (uint32_t)strtoul(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--ieee") == 0 && i + 1 < argc)
            out->ieee = strtoull(argv[++i], 0, 16);
        else
        {
            usage();
            return 0;
        }
    }

    if (out->path == 0)
    {
        printf("no port is ever defaulted: --path names one\n");
        return 0;
    }

    if (out->permitSeconds > 254)
    {
        printf("--permit takes 0 to 254 seconds\n");
        return 0;
    }

    if (out->seconds > APP_SECONDS_MAX)
    {
        printf("--seconds takes 0 to %u\n", (unsigned)APP_SECONDS_MAX);
        return 0;
    }

    return 1;
}

/* The network, stated once: the stack fills in the rest, the network key included, drawn at random. */
static void configure(Zb_StackConfig *cfg, const Options *options)
{
    Af_SimpleDescriptor *endpoint = &cfg->endpoints[0];

    Zb_StackCoordinatorDefaults(cfg);
    cfg->path = options->path;
    cfg->baud = options->baud;
    cfg->channel = options->channel;
    cfg->panId = options->panId;
    cfg->extendedPanId = options->extendedPanId;
    cfg->ieee = options->ieee;
    cfg->permitSeconds = (uint8_t)options->permitSeconds;

    endpoint->endpoint = APP_ENDPOINT;
    endpoint->profileId = APP_PROFILE;
    endpoint->deviceId = APP_DEVICE_ID;
    endpoint->deviceVersion = 0;
    endpoint->outputClusterCount = 1;
    endpoint->outputClusters[0] = ZCL_CLUSTER_BASIC;
    cfg->endpointCount = 1;
}

static const char *statusName(ZbStatus status)
{
    switch (status)
    {
    case ZB_OK:
        return "ok";

    case ZB_ERR_NO_ROUTE:
        return "no route";

    case ZB_ERR_NO_ACK:
        return "no acknowledgement";

    case ZB_ERR_NO_SPACE:
        return "no room";

    case ZB_ERR_TIMEOUT:
        return "timed out";

    default:
        return "refused";
    }
}

static void printData(const Aps_Indication *data)
{
    uint32_t i;

    printf("aps        from 0x%04x endpoint %02x to %02x, cluster 0x%04x profile 0x%04x, %u octet(s): ",
           data->srcAddress, data->srcEndpoint, data->dstEndpoint, data->clusterId, data->profileId,
           data->asduLength);

    for (i = 0; i < data->asduLength; i++)
        printf("%02x", data->asdu[i]);

    printf("\n");
}

/* The application as a state machine over the stack's events; the interviews take the answers and outcomes that are
   theirs, and what is left is printed. */
static AppState onEvent(AppState state, const Zb_StackEvent *event, const Options *options)
{
    uint32_t nowMs = Port_NowMs();
    int taken;

    switch (event->type)
    {
    case ZB_EVENT_NETWORK_UP:
        printf("network    coordinator 0x%04x, PAN 0x%04x, channel %u, extended PAN %016llx, ieee %016llx\n",
               event->network.networkAddress, event->network.panId, event->network.channel,
               (unsigned long long)event->network.extendedPanId, (unsigned long long)event->network.ieee);
        printf("network    permit open %u s; every device that joins is interviewed; Ctrl-C ends the run\n",
               options->permitSeconds);
        return APP_SERVING;

    case ZB_EVENT_NETWORK_FAILED:
        printf("network    did not come up (%s, status %d)\n", statusName(event->status), (int)event->status);
        (void)Zb_StackStop(&s_stack);
        return APP_STOPPING;

    case ZB_EVENT_DEVICE_JOINED:
        printf("joined     0x%04x  %016llx  %s\n", event->joined.networkAddress,
               (unsigned long long)event->joined.ieee, event->joined.receiverOn ? "receiver-on" : "sleepy");
        Interview_Joined(&s_interview, &event->joined, nowMs);
        return state;

    case ZB_EVENT_DATA:
        taken = Interview_Data(&s_interview, &event->data, nowMs);

        if (!taken)
            printData(&event->data);

        return state;

    case ZB_EVENT_SENT:
        taken = Interview_Sent(&s_interview, event->status, &event->sent, nowMs);

        if (!taken)
            printf("confirm    %s for 0x%04x cluster 0x%04x, %u attempt(s)\n", statusName(event->status),
                   event->sent.dstAddress, event->sent.clusterId, event->sent.attempts);

        return state;

    case ZB_EVENT_RCP_LOST:
        printf("rcp        lost; the stack is bringing it back\n");
        return state;

    case ZB_EVENT_RCP_BACK:
        printf("rcp        back, holding the network again\n");
        return state;

    case ZB_EVENT_STOPPED:
        printf("reset      the RCP was reset and closed, and is left unarmed\n");
        return APP_DONE;

    default:
        return state;
    }
}

/* Whether --seconds has run out, on the platform's monotonic clock. */
static int timeIsUp(uint32_t startedMs, uint32_t seconds)
{
    return seconds != 0 && !Zb_timeWithin(Port_NowMs(), startedMs, seconds * 1000);
}

int main(int argc, char **argv)
{
    Options options;
    Zb_StackConfig cfg;
    Zb_StackEvent event;
    AppState state = APP_STARTING;
    uint32_t startedMs;
    ZbStatus status;

    /* Each printf straight out, into a pipe or a file as onto a terminal. Not a line buffer: MSVC's C library refuses
       one of size 0 and buffers _IOLBF in full, so lines would wait in a pipe there. */
    setvbuf(stdout, 0, _IONBF, 0);

    if (!parseOptions(argc, argv, &options))
        return 2;

    startedMs = Port_NowMs();

    configure(&cfg, &options);
    Interview_Init(&s_interview, &s_stack, APP_ENDPOINT);

    printf("stack      Phoscon Zigbee Stack %s\n", ZB_VERSION_STRING);
    status = Zb_StackStart(&s_stack, &cfg);

    if (status != ZB_OK)
    {
        printf("%s: the stack did not start (status %d)\n", options.path, (int)status);
        return 1;
    }

    printf("coordinator forming a network on channel %u; Ctrl-C ends the run\n", options.channel);
    signal(SIGINT, onSignal);

    while (state != APP_DONE)
    {
        if (Zb_StackNextEvent(&s_stack, &event, EVENT_WAIT_MS))
            state = onEvent(state, &event, &options);

        if (state == APP_SERVING)
            Interview_Turn(&s_interview, Port_NowMs());

        if (state != APP_STOPPING && state != APP_DONE && (s_signal || timeIsUp(startedMs, options.seconds)))
        {
            (void)Zb_StackStop(&s_stack);
            state = APP_STOPPING;
        }
    }

    return 0;
}
