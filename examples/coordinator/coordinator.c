/*
 * The first example: a Zigbee coordinator that forms a network, lets devices join, and prints what it receives.
 *
 * It is an application, not an instrument: it states its network once, then reacts to what the stack reports. The
 * beacon, the radio, the network key and the device object's answers are the stack's; what is left here is three
 * states and what to print.
 *
 *   ./example_coordinator --path <port> --channel 25
 *   ./example_coordinator --path <port> --channel 25 --config coordinator.txt
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ex_config.h"
#include "port.h"
#include "port_file.h"
#include "zb_time.h"
#include "zb_utils.h"
#include "zb_stack.h"

/* The endpoint this coordinator advertises: the Home Automation profile, and the two clusters an On/Off light answers
   on. The stack's device object answers every discovery request about it. */
#define APP_ENDPOINT 0x01
#define APP_PROFILE 0x0104
#define APP_DEVICE_ID 0x0005          /* On/Off Light, Table 2-48's device identifiers */
#define CLUSTER_ON_OFF 0x0006
#define CLUSTER_LEVEL 0x0008

#define EVENT_WAIT_MS 100
#define APP_SECONDS_MAX 2147483       /* Zb_timeWithin measures a span under 2^31 ms */
#define APP_SAVE_MS 30000             /* a capture is saved this often if it changed, well inside 256 secured frames */

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
    const char *config;
    int identityGiven;                /* --channel, --pan, --extended-pan or --ieee, which a saved network refuses */
} Options;

/* The stack is the application's memory and a large one, so it is static rather than on main's frame. */
static Zb_Stack s_stack;
static volatile sig_atomic_t s_signal = 0;

/* The saved network, which the stack reads at bring-up, and the capture compared against it before each save. */
static Ex_Config s_saved;
static Zb_State s_capture;
static uint32_t s_savedMs;

static void onSignal(int number)
{
    (void)number;

    s_signal = 1;
}

static void usage(void)
{
    printf("usage: example_coordinator --path <serial device>\n"
           "                            [--channel 25] [--pan beef] [--extended-pan hex]\n"
           "                            [--permit seconds] [--baud n] [--ieee hex] [--seconds n] [--config file]\n"
           "  --path      the RCP's device node: /dev/cu.usbmodem* on macOS, /dev/ttyACM* on Linux\n"
           "  --channel   defaults to 25, and is the one your network should be alone on\n"
           "  --permit    how long joining stays open, 180 s by default, 0 to keep it closed\n"
           "  --baud      the link's rate: 57600 for a ConBee I or a RaspBee I, the port's default otherwise\n"
           "  --ieee      this device's extended address, for a unit taking over another's identity; the RCP's own\n"
           "              address otherwise\n"
           "  --seconds   0, the default, runs until Ctrl-C\n"
           "  --config    a file the network is saved to and comes back from; once it exists, it names the channel,\n"
           "              PAN, extended PAN and address, and refuses the options that would name another\n");
}

/* The options that name the network, which a saved one already names. */
static int namesTheNetwork(const char *option)
{
    return strcmp(option, "--channel") == 0 || strcmp(option, "--pan") == 0 || strcmp(option, "--extended-pan") == 0
           || strcmp(option, "--ieee") == 0;
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
        if (namesTheNetwork(argv[i]))
            out->identityGiven = 1;

        if (strcmp(argv[i], "--path") == 0 && i + 1 < argc)
            out->path = argv[++i];
        else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            out->config = argv[++i];
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

    if (out->config != 0 && out->identityGiven && Port_FileExists(out->config))
    {
        printf("%s holds the network: it names the channel, PAN and addresses, so delete it to form another\n",
               out->config);
        return 0;
    }

    return 1;
}

/* The network a config file brings back, or for a file not written yet the seed the first run saves into it: a seed
   drawn by the stack could not be read back, so the example draws it from the port's entropy itself. */
static int loadConfig(const Options *options, Zb_StackConfig *cfg)
{
    Port port;

    if (Port_FileExists(options->config))
    {
        if (!Ex_ConfigLoad(&s_saved, options->config))
        {
            printf("%s: not a config this example wrote, or one of another version\n", options->config);
            return 0;
        }

        cfg->panId = 0;
        cfg->extendedPanId = 0;
        cfg->ieee = 0;
        Ex_ConfigToStack(&s_saved, cfg);
        printf("config     %s: the network saved there, on channel %u\n", options->config, s_saved.channel);

        return 1;
    }

    if (Port_Init(&port, Port_DefaultOps()) != ZB_OK
        || Port_Entropy(&port, s_saved.linkKeySeed, ZB_STACK_KEY_OCTETS) != ZB_OK)
    {
        printf("%s: the port has no entropy for the link-key seed\n", options->config);
        return 0;
    }

    Zb_memcpy(cfg->linkKeySeed, s_saved.linkKeySeed, ZB_STACK_KEY_OCTETS);
    printf("config     %s: a new network, saved there once it is up\n", options->config);

    return 1;
}

/* The network as it stands, written to the config file when it moved since the last save or when `force` asks. */
static void saveConfig(const Options *options, uint32_t channel, int force)
{
    if (options->config == 0 || Zb_StackCapture(&s_stack, 1, &s_capture) != ZB_OK)
        return;

    s_savedMs = Port_NowMs();

    if (!force && Zb_memcmp(&s_capture, &s_saved.state, (uint32_t)sizeof s_capture) == 0)
        return;

    s_saved.channel = channel;
    s_saved.state = s_capture;

    if (!Ex_ConfigSave(&s_saved, options->config))
        printf("config     %s: not saved\n", options->config);
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
    endpoint->deviceVersion = 2;
    endpoint->inputClusterCount = 2;
    endpoint->inputClusters[0] = CLUSTER_ON_OFF;
    endpoint->inputClusters[1] = CLUSTER_LEVEL;
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

/* The application as a state machine over the stack's events. */
static AppState onEvent(AppState state, const Zb_StackEvent *event, const Options *options)
{
    switch (event->type)
    {
    case ZB_EVENT_NETWORK_UP:
        printf("network    coordinator 0x%04x, PAN 0x%04x, channel %u, extended PAN %016llx, ieee %016llx\n",
               event->network.networkAddress, event->network.panId, event->network.channel,
               (unsigned long long)event->network.extendedPanId, (unsigned long long)event->network.ieee);
        printf("network    endpoint 0x%02x, profile 0x%04x, clusters 0x%04x and 0x%04x; permit open %u s\n",
               APP_ENDPOINT, APP_PROFILE, CLUSTER_ON_OFF, CLUSTER_LEVEL, options->permitSeconds);
        printf("network    waiting for a device to join; Ctrl-C ends the run\n");
        saveConfig(options, event->network.channel, 1);
        return APP_SERVING;

    case ZB_EVENT_NETWORK_FAILED:
        printf("network    did not come up (%s, status %d)\n", statusName(event->status), (int)event->status);
        (void)Zb_StackStop(&s_stack);
        return APP_STOPPING;

    case ZB_EVENT_DEVICE_JOINED:
        printf("joined     0x%04x  %016llx  %s\n", event->joined.networkAddress,
               (unsigned long long)event->joined.ieee, event->joined.receiverOn ? "receiver-on" : "sleepy");
        saveConfig(options, s_saved.channel, 0);
        return state;

    case ZB_EVENT_DATA:
        printData(&event->data);
        return state;

    case ZB_EVENT_SENT:
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

    setvbuf(stdout, 0, _IOLBF, 0);          /* one line at a time, into a pipe or a file as onto a terminal */

    if (!parseOptions(argc, argv, &options))
        return 2;

    startedMs = Port_NowMs();

    configure(&cfg, &options);

    if (options.config != 0 && !loadConfig(&options, &cfg))
        return 1;

    status = Zb_StackStart(&s_stack, &cfg);

    if (status != ZB_OK)
    {
        printf("%s: the stack did not start (status %d)\n", options.path, (int)status);
        return 1;
    }

    signal(SIGINT, onSignal);

    while (state != APP_DONE)
    {
        if (Zb_StackNextEvent(&s_stack, &event, EVENT_WAIT_MS))
            state = onEvent(state, &event, &options);

        if (state == APP_SERVING && !Zb_timeWithin(Port_NowMs(), s_savedMs, APP_SAVE_MS))
            saveConfig(&options, s_saved.channel, 0);

        if (state != APP_STOPPING && state != APP_DONE && (s_signal || timeIsUp(startedMs, options.seconds)))
        {
            if (state == APP_SERVING)
                saveConfig(&options, s_saved.channel, 0);

            (void)Zb_StackStop(&s_stack);
            state = APP_STOPPING;
        }
    }

    return 0;
}
