/*
 * The second example: a Zigbee router that finds a network on the channels it is given, joins it, then lets other
 * devices join through it and prints what it receives. Its endpoint serves the Basic cluster, so a coordinator can
 * read what it is: its manufacturer's name and its model.
 *
 * It is an application, not an instrument: it states where it may look once, then reacts to what the stack reports.
 * The discovery, the choice of parent, the network key and reporting a joiner to the trust centre are the stack's.
 *
 *   ./example_router --path <port> --channels 11,12
 *   ./example_router --path <port> --channels 11,12 --config router.txt
 *
 * The channels are named every time and never defaulted: the discovery sends a Beacon Request on each channel it
 * visits, so the list is a list of channels you may transmit on.
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
#include "zcl.h"

#define CHANNEL_FIRST 11
#define CHANNEL_LAST 26

/* The endpoint this router advertises: a mains-powered dimmable light, the commonest router there is. */
#define APP_ENDPOINT 0x01
#define APP_PROFILE 0x0104
#define APP_DEVICE_ID 0x0100          /* Dimmable Light, Table 2-48's device identifiers */
#define CLUSTER_ON_OFF 0x0006
#define CLUSTER_LEVEL 0x0008
#define APP_MANUFACTURER "Phoscon"    /* the Basic cluster's ManufacturerName and ModelIdentifier, Table 3-7 */
#define APP_MODEL "example_router"
#define APP_POWER_MAINS 0x01          /* Table 3-8's PowerSource: mains, single phase */
#define APP_TAG_BASIC 1               /* the tag on the Basic cluster's answers */

#define EVENT_WAIT_MS 100
#define APP_SECONDS_MAX 2147483       /* Zb_timeWithin measures a span under 2^31 ms */
#define APP_SAVE_MS 30000             /* a capture is saved this often if it changed, well inside 256 secured frames */

/* The application's own states: waiting to be on a network, serving it, and stopping. */
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
    uint32_t channels;
    uint64_t extendedPanId;
    uint32_t permitSeconds;
    uint32_t baud;
    uint64_t ieee;
    uint32_t seconds;
    const char *config;
    int identityGiven;                /* --extended-pan or --ieee, which a saved network refuses */
} Options;

/* The stack is the application's memory and a large one, so it is static rather than on main's frame. */
static Zb_Stack s_stack;
static Zcl_Cluster s_basic;
static Ex_Config s_saved;
static Zb_State s_capture;
static uint32_t s_savedMs;
static volatile sig_atomic_t s_signal = 0;

static void onSignal(int number)
{
    (void)number;

    s_signal = 1;
}

static void usage(void)
{
    printf("usage: example_router --path <serial device> --channels <list>\n"
           "                       [--extended-pan hex] [--permit seconds] [--baud n] [--ieee hex] [--seconds n]\n"
           "                       [--config file]\n"
           "  --path           the RCP's device node: /dev/cu.usbmodem* on macOS, /dev/ttyACM* on Linux,\n"
           "                   COM<n> on Windows\n"
           "  --channels       a comma list of 11 to 26; a Beacon Request goes out on each, so nothing is defaulted\n"
           "  --extended-pan   join only this network; the best one heard otherwise\n"
           "  --permit         how long devices may join through this router, 180 s by default, 0 to keep it closed\n"
           "  --baud           the link's rate: 57600 for a ConBee I or a RaspBee I, the port's default otherwise\n"
           "  --ieee           this device's extended address; the RCP's own address otherwise\n"
           "  --seconds        0, the default, runs until Ctrl-C\n"
           "  --config         a file the network is saved to and comes back from; once it exists, the router comes\n"
           "                   back at its address with no join, on the saved channel, which --channels must list\n");
}

/* The options that name the network or this device, which a saved network already names. */
static int namesTheNetwork(const char *option)
{
    return strcmp(option, "--extended-pan") == 0 || strcmp(option, "--ieee") == 0;
}

static uint32_t parseChannels(const char *text)
{
    uint32_t mask = 0;
    char *end;
    unsigned long channel;

    while (*text != '\0')
    {
        channel = strtoul(text, &end, 10);

        if (end == text || channel < CHANNEL_FIRST || channel > CHANNEL_LAST)
            return 0;

        mask |= (uint32_t)1 << channel;
        text = *end == ',' ? end + 1 : end;

        if (*end != ',' && *end != '\0')
            return 0;
    }

    return mask;
}

static int parseOptions(int argc, char **argv, Options *out)
{
    int i;

    memset(out, 0, sizeof *out);

    out->permitSeconds = 180;

    for (i = 1; i < argc; i++)
    {
        if (namesTheNetwork(argv[i]))
            out->identityGiven = 1;

        if (strcmp(argv[i], "--path") == 0 && i + 1 < argc)
            out->path = argv[++i];
        else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            out->config = argv[++i];
        else if (strcmp(argv[i], "--channels") == 0 && i + 1 < argc)
            out->channels = parseChannels(argv[++i]);
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

    if (out->channels == 0)
    {
        printf("no channel is ever defaulted: --channels names the ones, 11 to 26, this run may transmit on\n");
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
        printf("%s holds the network: it names the extended PAN and this device, so delete it to join another\n",
               out->config);
        return 0;
    }

    return 1;
}

/* The network a config file brings back, on its own channel, which has to be one this run may transmit on; a file
   not written yet is the router joining, and saving once it is up. */
static int loadConfig(const Options *options, Zb_StackConfig *cfg)
{
    if (!Port_FileExists(options->config))
    {
        printf("config     %s: joining a network, saved there once it is up\n", options->config);
        return 1;
    }

    if (!Ex_ConfigLoad(&s_saved, options->config) || s_saved.state.deviceType != NWK_DEVICE_ROUTER)
    {
        printf("%s: not a router's config this example wrote, or one of another version\n", options->config);
        return 0;
    }

    if ((options->channels & ((uint32_t)1 << s_saved.channel)) == 0)
    {
        printf("%s: the network is on channel %u, which --channels does not list\n", options->config, s_saved.channel);
        return 0;
    }

    cfg->extendedPanId = 0;
    cfg->ieee = 0;
    Ex_ConfigToStack(&s_saved, cfg);
    printf("config     %s: the network saved there, on channel %u\n", options->config, s_saved.channel);

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

/* Where the router may look, stated once: the stack discovers, joins, waits for the key and opens the permit. */
static void configure(Zb_StackConfig *cfg, const Options *options)
{
    Af_SimpleDescriptor *endpoint = &cfg->endpoints[0];

    Zb_StackRouterDefaults(cfg);
    cfg->path = options->path;
    cfg->baud = options->baud;
    cfg->channelMask = options->channels;
    cfg->extendedPanId = options->extendedPanId;
    cfg->ieee = options->ieee;
    cfg->permitSeconds = (uint8_t)options->permitSeconds;

    endpoint->endpoint = APP_ENDPOINT;
    endpoint->profileId = APP_PROFILE;
    endpoint->deviceId = APP_DEVICE_ID;
    endpoint->deviceVersion = 1;
    endpoint->inputClusterCount = 3;
    endpoint->inputClusters[0] = ZCL_CLUSTER_BASIC;
    endpoint->inputClusters[1] = CLUSTER_ON_OFF;
    endpoint->inputClusters[2] = CLUSTER_LEVEL;
    cfg->endpointCount = 1;

    Zcl_BasicDefaults(&s_basic, APP_POWER_MAINS, APP_MANUFACTURER, APP_MODEL);
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

    case ZB_ERR_NOT_FOUND:
        return "no network";

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

/* The Basic cluster's server on the endpoint (ZCL R8 2.5.1, 2.5.2, 2.5.12.2): a Read Attributes is answered record
   by record, and any other command draws a Default Response saying it is not supported, but only when it came by
   unicast and is not a Default Response itself. */
static void serveBasic(const Aps_Indication *data)
{
    Zcl_Header request;
    Zcl_Header answer;
    Aps_ApsdeReq reply;
    uint8_t payload[ZCL_PAYLOAD_MAX];
    uint8_t asdu[ZCL_HEADER_MAX + ZCL_PAYLOAD_MAX];
    uint32_t payloadLen;
    uint32_t asduLen = 0;
    uint32_t offset = 0;
    int unicast;

    if (data->dstEndpoint != APP_ENDPOINT || data->profileId != APP_PROFILE || data->clusterId != ZCL_CLUSTER_BASIC)
        return;

    if (Zcl_FrameParse(data->asdu, data->asduLength, &request, &offset) != ZB_OK)
        return;

    unicast = data->dstAddrMode == APS_ADDR_MODE_SHORT && data->dstAddress < 0xfff8;

    Zb_memset(&answer, 0, (uint32_t)sizeof answer);
    answer.frameControl = (uint8_t)(ZCL_FRAME_TYPE_GLOBAL | ZCL_FC_DISABLE_DEFAULT_RESPONSE
                                    | ((request.frameControl & ZCL_FC_DIRECTION) ^ ZCL_FC_DIRECTION));
    answer.transactionSequenceNumber = request.transactionSequenceNumber;

    if ((request.frameControl & (ZCL_FC_TYPE_MASK | ZCL_FC_DIRECTION | ZCL_FC_MANUFACTURER)) == ZCL_FRAME_TYPE_GLOBAL
        && request.commandIdentifier == ZCL_CMD_READ_ATTRIBUTES)
    {
        answer.commandIdentifier = ZCL_CMD_READ_ATTRIBUTES_RESPONSE;
        payloadLen = Zcl_ReadAttributesAnswer(&s_basic, data->asdu + offset, data->asduLength - offset, payload,
                                              (uint32_t)sizeof payload, 0, 0);
    }
    else if (unicast && !((request.frameControl & ZCL_FC_TYPE_MASK) == ZCL_FRAME_TYPE_GLOBAL
                          && request.commandIdentifier == ZCL_CMD_DEFAULT_RESPONSE))
    {
        answer.commandIdentifier = ZCL_CMD_DEFAULT_RESPONSE;
        payload[0] = request.commandIdentifier;
        payload[1] = ZCL_STATUS_UNSUP_CLUSTER_COMMAND;
        payloadLen = 2;
    }
    else
        return;

    if (Zcl_FrameCompose(&answer, payload, payloadLen, asdu, (uint32_t)sizeof asdu, &asduLen) != ZB_OK)
        return;

    Zb_memset(&reply, 0, (uint32_t)sizeof reply);
    reply.dstAddrMode = APS_ADDR_MODE_SHORT;
    reply.dstAddress = data->srcAddress;
    reply.dstEndpoint = data->srcEndpoint;
    reply.profileId = APP_PROFILE;
    reply.clusterId = ZCL_CLUSTER_BASIC;
    reply.srcEndpoint = APP_ENDPOINT;
    reply.asdu = asdu;
    reply.asduLength = asduLen;
    reply.txOptions = APS_TX_OPTION_ACK;
    reply.tag = APP_TAG_BASIC;

    if (Zb_StackApsRequest(&s_stack, &reply) != ZB_OK)
        printf("basic      the answer to 0x%04x was not taken\n", data->srcAddress);
}

/* The application as a state machine over the stack's events. */
static AppState onEvent(AppState state, const Zb_StackEvent *event, const Options *options)
{
    switch (event->type)
    {
    case ZB_EVENT_NETWORK_UP:
        printf("network    router 0x%04x, channel %u, extended PAN %016llx, ieee %016llx, holding the network key\n",
               event->network.networkAddress, event->network.channel,
               (unsigned long long)event->network.extendedPanId, (unsigned long long)event->network.ieee);
        printf("network    serving; Ctrl-C ends the run\n");
        saveConfig(options, event->network.channel, 1);
        return APP_SERVING;

    case ZB_EVENT_NETWORK_FAILED:
        printf("join       ended without a network (%s, status %d)\n", statusName(event->status), (int)event->status);
        (void)Zb_StackStop(&s_stack);
        return APP_STOPPING;

    case ZB_EVENT_DEVICE_JOINED:
        printf("joined     0x%04x  %016llx  %s\n", event->joined.networkAddress,
               (unsigned long long)event->joined.ieee, event->joined.receiverOn ? "receiver-on" : "sleepy");
        saveConfig(options, s_saved.channel, 0);
        return state;

    case ZB_EVENT_DATA:
        printData(&event->data);
        serveBasic(&event->data);
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

    /* Each printf straight out, into a pipe or a file as onto a terminal. Not a line buffer: MSVC's C library refuses
       one of size 0 and buffers _IOLBF in full, so lines would wait in a pipe there. */
    setvbuf(stdout, 0, _IONBF, 0);

    if (!parseOptions(argc, argv, &options))
        return 2;

    startedMs = Port_NowMs();

    configure(&cfg, &options);

    if (options.config != 0 && !loadConfig(&options, &cfg))
        return 1;

    printf("stack      Phoscon Zigbee Stack %s\n", ZB_VERSION_STRING);
    status = Zb_StackStart(&s_stack, &cfg);

    if (status != ZB_OK)
    {
        printf("%s: the stack did not start (status %d)\n", options.path, (int)status);
        return 1;
    }

    printf("router     %s; Ctrl-C ends the run\n", cfg.state != 0 ? "coming back on its network" : "looking for a network");
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
