# Using the stack

How an application is built on the Phoscon Zigbee Stack: one object, started with one config, reporting what happens as events.
**After reading** you can write a coordinator or a router of your own; `examples/coordinator/coordinator.c` and `examples/router/router.c` are complete programs that do each of the things below, and `examples/interview/` a coordinator that asks every device that joins for its descriptors and its Basic cluster, over ZDP and ZCL requests and the events that answer them.

## 1. One object

An application includes `zb_stack.h`, and the codecs beside it (`zcl.h`, `zdo.h`) when it builds or reads frames.
`Zb_Stack` is the whole stack: the RCP and its protocol, the serial port, the clock, entropy, and the library that runs the Zigbee layers.
With CMake, an application links `zb_stack`, as the examples do.

The application never sees the stack's internal states.
It states its network once, starts the stack, and from then on takes events: the network came up, a device joined, a frame arrived, a send finished.
Its own logic is a small state machine over those events.

The library under the stack, `Zb_Core`, is there for an integration that runs its own loop or its own radio; `docs/porting.md` describes it.

## 2. The event loop

```c
static Zb_Stack zb;                          /* large: static storage, never a small stack frame */

Zb_StackConfig cfg;
Zb_StackEvent event;

Zb_StackCoordinatorDefaults(&cfg);
cfg.path = "/dev/ttyACM0";
cfg.channel = 25;
cfg.panId = 0xbeef;
/* ... endpoints, see §4 */

if (Zb_StackStart(&zb, &cfg) != ZB_OK)
    return 1;

while (app.state != APP_DONE)
{
    if (Zb_StackNextEvent(&zb, &event, 100))   /* 0: nothing happened within 100 ms */
        onEvent(&app, &event);
}
```

`Zb_StackNextEvent` turns the stack and sleeps on the RCP until an event happens or the timeout passes (Figure 1).
Nothing calls the application back, and there is no thread: every bit of the stack's work happens inside that call.
A timeout of 0 turns the stack once without waiting, for an application whose loop has other work to do.

![A sequence diagram of one call to Zb_StackNextEvent, with five columns: your application; Zb_Stack, the object it calls; and three parts held inside it: Zb_Core with the APS, NWK and MAC, Rcp_Radio for the RCP, and Port with the clock and serial device. The application calls Zb_StackNextEvent. The stack first hands back any event already waiting, then reads the clock with Port_NowMs and loops until an event or the timeout. Each turn, Zb_StackTurn, pumps the RCP with RcpRadio_Pump, which reads the bytes with Port_Read, checks with RcpRadio_Mode whether the RCP was lost or came back, and calls Zb_CoreStep, in amber; inside the step the MAC uses the radio's tx, rxPoll and completion, a frame to send goes onto the port's ring with Port_Write, and received Radio_Frames come back. Before the network is up, the turn brings the RCP up, joins, or opens the permit instead. After each turn, Zb_StackPollEvent reads one confirm or indication from Zb_Core with Zb_CorePollConfirms or Zb_CorePollIndications, straight into the event, and returns 1 if the turn left one; otherwise the stack returns 0 once the timeout is spent, or sleeps in Port_Wait, which first drains pending writes, until the RCP sends bytes or 5 ms pass, and turns again. The application handles the event in its own state machine, onEvent, and calls again.](images/turn.png)

*Figure 1: one `Zb_StackNextEvent` call.*
It turns the stack until it has an event to hand back or the timeout passes; the network moves only inside `Zb_CoreStep`, in amber, and the application's part is one call and its own state machine.
Source: `tools/diagrams/turn.py`.

## 3. The config

`Zb_StackCoordinatorDefaults` and `Zb_StackRouterDefaults` fill a config with the defaults every Zigbee 3.0 device shares; an application then names only what is its own.
`Zb_StackEndDeviceDefaults` fills one for an end device, which takes a router's fields, routes nothing and opens no permit; it keeps its receiver on unless `sleepy` says it rests (D-301).

| Field | Coordinator | Router |
| --- | --- | --- |
| `path` | the RCP's serial device node: `/dev/cu.usbmodem*` on macOS, `/dev/ttyACM*` on Linux; or `usb-serial:<serial>`, the USB stick with that serial number wherever the system put it (D-282, `tools/port_find` lists them); never defaulted | the same |
| `baud` | 0: 115 200 | 57 600 for a ConBee I or a RaspBee I |
| `channel` | the network's channel, 11 to 26; required | with `state`, the saved network's channel; required then |
| `channelMask` | unused | the channels to look on, bit n for channel n; required, since a scan transmits on each |
| `scanAttempts` | unused | the scans before choosing a network, 1 to 255; 0 is the standard's 5, about 1.2 s on one channel and 11 s on all sixteen |
| `scanGapMs` | unused | the time between those scans; 0 is the standard's 100 ms |
| `panId` | the network's PAN identifier; 0 draws one | unused |
| `extendedPanId` | 0: the coordinator's own address | 0: join the best network heard; otherwise only this one |
| `ieee` | 0: the RCP's own address | the same |
| `permitSeconds` | how long devices may join once the network is up; 180 by default, 0 keeps it closed | how long devices may join through it |
| `networkKey` | all zero: a random key, drawn from the port | unused: the trust centre hands it over |
| `trustCentreLinkKey` | all zero: Zigbee 3.0's global key, "ZigBeeAlliance09" | the same |
| `linkKeySeed` | all zero: a random seed, from which each joiner's own link key is derived | unused |
| `state` | 0 forms a new network; a saved `Zb_State` brings the old one back (§8) | 0 joins one; a saved `Zb_State` comes back on it without a join (§8) |
| `announceAfterRestore` | unused | restored from `state`, it sends a Device_annce; 0 sends none, since it did not join |
| `keepJoinedLinkKey` | unused | 0: once joined, it asks the trust centre for a link key of its own and verifies it, as R23.1 4.7.3.8 asks, keeping the joined key if no answer comes after three tries; 1: it keeps the key it joined with, as an older device does (D-299) |
| `sleepy` | unused | an end device's: 1 rests its receiver and polls its parent for what it holds, at 250 ms while it attaches (R23.1 3.6.1.15) and at `pollIntervalMs` once attached; 0 keeps the receiver on (D-301) |
| `pollIntervalMs` | unused | a sleepy device's interval between polls once attached; 0 is 7.5 s, below the 30 s a parent holds a frame |
| `hearsWhileAsleep` | unused | a sleepy device's: 0 discards what the RCP heard between polls, as a sleeping radio would not have heard it; 1 keeps it, for debugging (D-300) |
| `manufacturerCode` | the node descriptor's; dresden elektronik's by default | the same |
| `zdpUnsupportedToApplication` | 0: a ZDP request the device object does not answer is answered NOT_SUPPORTED, or dropped when broadcast; 1: it arrives as `ZB_EVENT_DATA` on endpoint 0, and the application answers it | the same |
| `endpoints`, `endpointCount` | the application's endpoints (§4) | the same |
| `log` | 0 records nothing; a `Log_Log` the application drains, which the MAC and the security module report into | the same |

A coordinator is the network's trust centre: every device that joins is sent the network key, and a Zigbee 3.0 device that asks for its own trust-centre link key is given one.
A fixed network key is a visible choice: write it into `networkKey`, and the same network comes back on the next run.

A coordinator about to form a new network can measure its candidate channels first.
`Zb_StackEnergyScan(&zb, &cfg, mask, scanDuration)` brings up the RCP `cfg` names, measures each channel in `mask` for ScanDuration's 15.36 ms × (2ⁿ + 1), sends nothing, and reports `ZB_EVENT_ENERGY_SCAN`, then `ZB_EVENT_STOPPED`.
Each level is the radio's peak in dBm, and a channel nothing measured is flagged rather than given a level (D-298); the application picks the channel and starts with it in `cfg.channel`.

## 4. Endpoints

An endpoint is described once, in the config: its number, profile, device identifier, and the clusters it serves and uses.

```c
Af_SimpleDescriptor *endpoint = &cfg.endpoints[0];

endpoint->endpoint = 0x01;
endpoint->profileId = 0x0104;               /* Home Automation */
endpoint->deviceId = 0x0005;
endpoint->inputClusterCount = 2;
endpoint->inputClusters[0] = 0x0006;        /* On/Off */
endpoint->inputClusters[1] = 0x0008;        /* Level Control */
cfg.endpointCount = 1;
```

The stack's device object answers every discovery request about the device out of these descriptors, and a request for endpoint 0 is its own: none reaches the application.
A response is the application's: one that asks another device from endpoint 0 gets the answer as `ZB_EVENT_DATA` on profile 0, the request's cluster with bit 15 set, and matches it by the request's transaction sequence number: the one it wrote, or with `ZB_ZDO_CLIENT` the one `Zb_StackZdoRequest` handed back.

## 5. The events

| Event | Carries | Means |
| --- | --- | --- |
| `ZB_EVENT_NETWORK_UP` | `network`: address, PAN, channel, extended PAN, this device's address | a coordinator formed its network, or a router joined one and holds the network key; joining is open for `permitSeconds` |
| `ZB_EVENT_NETWORK_FAILED` | `status` | the RCP did not come up, or a router found no network to join |
| `ZB_EVENT_DEVICE_JOINED` | `joined`: network address, extended address, whether its receiver stays on, the capability octet; `data`: the Device_annce as it arrived | a device joined and announced itself |
| `ZB_EVENT_DATA` | `data`, an `Aps_Indication` | a frame for one of the application's endpoints (§7) |
| `ZB_EVENT_SENT` | `status`, `sent`, an `Aps_Confirm` carrying the request's `tag` | what became of a `Zb_StackApsRequest` (§6) |
| `ZB_EVENT_RCP_LOST` | `status` | `ZB_ERR_DEVICE_LOST`: the RCP reset or went quiet, and the stack arms it again; `ZB_ERR_NO_DEVICE`: its port went away, and the stack opens the same path again every second until an RCP is there (D-281) |
| `ZB_EVENT_RCP_BACK` | | the RCP runs again, holding what the stack told it |
| `ZB_EVENT_STOPPED` | | the RCP was reset and the port closed, after `Zb_StackStop` or an energy scan |
| `ZB_EVENT_ENERGY_SCAN` | `status`, `energy`: per channel asked, lowest first, the channel, `dbm` and `measured` | a `Zb_StackEnergyScan` ended (§3); `ZB_ERR_UNSUPPORTED` on a radio that has no energy scan |
| `ZB_EVENT_POLLED` | `status` | a `Zb_StackPoll` ended: `ZB_OK` when the parent sent a frame, `ZB_ERR_NO_DATA` when it held none, or why the poll failed (§8) |
| `ZB_EVENT_DEVICE_LEFT` | `left`: network address, extended address, `rejoin`, `reported` | another device left: its leave command was heard, `rejoin` 1 when it said it comes back with its key; or `reported` 1, its parent's Device Left, which R23.1 makes informative, so no key is dropped on it; the two may both tell one departure |
| `ZB_EVENT_ADDRESS` | `address`: network address, extended address, `reason` | the address map learned a device (`ZB_ADDRESS_LEARNED`), found it at another network address (`ZB_ADDRESS_CHANGED`), or heard a second device claim one (`ZB_ADDRESS_CONFLICT`, the map keeping the first) (D-296) |
| `ZB_EVENT_ROUTE` | `route`: destination, `reason`, the relays, `relays[0]` next to the destination | a route record or a network status 0x0b changed a source route: `ZB_ROUTE_LEARNED`, `ZB_ROUTE_CHANGED`, or gone as `ZB_ROUTE_DIRECT` or `ZB_ROUTE_FAILED` (§8, D-295) |

Both examples are the same three states over these events:

```c
static AppState onEvent(AppState state, const Zb_StackEvent *event)
{
    switch (event->type)
    {
    case ZB_EVENT_NETWORK_UP:
        return APP_SERVING;

    case ZB_EVENT_NETWORK_FAILED:
        Zb_StackStop(&zb);
        return APP_STOPPING;

    case ZB_EVENT_DATA:
        handleFrame(&event->data);               /* may call Zb_StackApsRequest */
        return state;

    case ZB_EVENT_STOPPED:
        return APP_DONE;

    default:
        return state;                            /* joined, sent, RCP lost and back: printed */  
    }
}
```

The application stops by calling `Zb_StackStop` and going to its own STOPPING state; `ZB_EVENT_STOPPED` follows.

## 6. Sending

A frame goes out as an APS data request from one of the configured endpoints; the ZCL codec writes its payload:

```c
uint8_t asdu[8];
uint32_t asduLength;
Zcl_Header header = { ZCL_FRAME_TYPE_CLUSTER, 0, 0x01, 0x02 };   /* cluster command, sequence 1, Toggle */
Aps_ApsdeReq request;

Zcl_FrameCompose(&header, 0, 0, asdu, sizeof asdu, &asduLength);

memset(&request, 0, sizeof request);
request.dstAddrMode = APS_ADDR_MODE_SHORT;
request.dstAddress = 0x9304;
request.dstEndpoint = 0x01;
request.profileId = 0x0104;
request.clusterId = 0x0006;                  /* On/Off */
request.srcEndpoint = 0x01;                  /* one of the configured endpoints */
request.asdu = asdu;
request.asduLength = asduLength;
request.txOptions = APS_TX_OPTION_ACK;
request.tag = 7;                             /* the application's own name for this send */

status = Zb_StackApsRequest(&zb, &request);
```

The call answers at once whether the request was taken, and `ZB_ERR_NOT_READY` before the network is up.
What became of it arrives later as `ZB_EVENT_SENT`, with a `status` (`ZB_OK`, `ZB_ERR_NO_ACK`, `ZB_ERR_NO_ROUTE`, …) and the number of `attempts`.
Several sends may be in flight at once, and their outcomes need not arrive in the order they were sent: `sent.tag` is the tag the request carried, which is how the application tells them apart.
The tag is the application's to choose and never goes on the air; the stack does not check that two are different, and refuses only `ZB_STACK_TAG_DEVICE_OBJECT`, the device object's own.
8 sends may be in flight by default, and one more is refused at once with `ZB_ERR_NO_SPACE`, no event to follow; `docs/configuration.md` sizes that and every other table the stack keeps.
Routes are found, frames are secured and retries run inside the turns in between.
A request to the device's own network or extended address never goes on the air: it comes back as `ZB_EVENT_DATA`, a ZDP request answered by the device object first, and is confirmed `ZB_OK` (D-292).

## 7. Receiving

A `ZB_EVENT_DATA` carries an `Aps_Indication`: the source's network address and endpoint, the profile and cluster, the payload (`asdu`, `asduLength`) and its link quality.
`Zcl_FrameParse` reads a ZCL payload's header, and `Zcl_ReadResponseParse` the records of a Read Attributes Response behind it; `Zcl_ReadAttributesCompose` writes the read's identifiers, and `Zcl_ReadAttributesAnswer` the answer a `Zcl_Cluster` such as `Zcl_BasicDefaults`'s gives, for an application that serves the Basic cluster on its own endpoint.
A device's announcement does not arrive as `ZB_EVENT_DATA`: the stack reads it and reports `ZB_EVENT_DEVICE_JOINED`, whose `data` holds the frame for an application that reads it whole.

## 8. Joining later, stopping

`Zb_StackPermitJoining(&zb, seconds)` opens joining again once the network is up, and 0 closes it.
A sleepy end device asks its parent for what it holds with `Zb_StackPoll(&zb)` beside its own schedule, and `ZB_EVENT_POLLED` follows; `Zb_StackSetPollInterval(&zb, ms)` changes the schedule, shorter while it expects answers and back to 0, the default, after.
`Zb_StackStop(&zb)` resets the RCP and closes the port, and `ZB_EVENT_STOPPED` follows.

A device keeps its network across restarts with `Zb_StackCapture(&zb, 1, &state)` once it is up, and `state` handed back as `cfg.state` at the next start.
The state names the role, the network's address, PAN, extended PAN, channel, update id and keys, so the config needs nothing more; one it contradicts is refused, and a state saved before the channel was kept takes the config's (D-294).
A restored device can send to its trust centre, its parent and its children by IEEE address at once, as a binding to the coordinator does; any other IEEE destination waits until a frame from it has been heard.
A restored end device polls its parent once, and rejoins if the parent stays silent; it comes back sleepy when its config says so, since the state does not.
A restored router or coordinator reaches its routers again once link status has measured the links, about two periods of 15 s: until then a first unicast to a router not yet heard can fail after its 10 s route discovery, so wait or retry.
The outgoing counters restart 256 past the saved ones, so capture again before that many secured frames have gone out.
`linkKeySeed` is worth keeping beside it: a device that asks for its link key again is then given the same one.

Source routes are not in the state: an application that keeps them stores each `ZB_EVENT_ROUTE` and hands the routes back with `Zb_StackSetSourceRoute(&zb, destination, relays, count)` once the network is up.
A route handed back holds until a route record or a 0x0b replaces it, and no relays remove it: the stack removes none for a device that left, so the application does (D-295).

## 9. What the stack does not wrap

`Zb_StackCore(&zb)` hands out the library under the stack for what has no call of its own yet:

| To | Call |
| --- | --- |
| leave the network | `Zb_CoreLeave(core, rejoin, nowMs)` |
| remove another device, at the trust centre | `Zb_CoreRemove(core, ieee, nowMs)` |
| forget a device's own link key at the trust centre, so the device can join again after a factory reset, which every joiner that updated its key needs (D-299) | `Zb_CoreForgetLinkKey(core, ieee)` |
| bind, and read the counters | `Zb_CoreBindings`, `Zb_CoreJoinsHeard` and the other `Zb_Core` accessors |
| show the RCP's firmware | `RcpRadio_VersionText(&zb.rcp, out, cap)` once the network is up: its NCP_VERSION, such as `DSPINEL/1.0; AT86RF233; phoscon-rcp 0.2.0`, which names the radio and the release and no board (`docs/internals/hardware.md`) |
| count what an event ring lost | `Nwk_SourceRouteNoticesDropped(&core->layers.nwk)`, `Nwk_AddressNoticesDropped(&core->layers.nwk)`, `Zb_CoreDeparturesDropped(core)` |
| hear group frames for groups no endpoint is a member of | `Aps_SetGroupDelivery(&core->layers.aps, mode)` after each `ZB_EVENT_NETWORK_UP`: `APS_GROUP_DELIVERY_UNFILTERED` delivers one at endpoint 0xff, `APS_GROUP_DELIVERY_ENDPOINTS` one to each endpoint of the frame's profile (D-213, D-293) |

A device that was factory reset comes back to a trust centre still holding the link key it updated to, which it no longer has, so its join times out.
`Zb_CoreForgetLinkKey` turns that entry back into the global key a new device is given, and the next join under an open permit goes as the first one did, its link key asked for again (4.7.3.1, D-299).
Forget before the device joins again: a join heard first is answered under the old key and times out, and the next attempt succeeds; a device that first joined with an install code needs that key entered again.

`example_coordinator --config` and `example_router --config` keep their network in a file through `Zb_StackCapture` (`examples/README.md`).

## 10. A loop or a radio of your own

`Zb_StackTurn(&zb, nowMs)` and `Zb_StackPollEvent(&zb, &event)` are what `Zb_StackNextEvent` does with the port's clock and wait: an application whose loop already owns a clock calls them itself.
A config whose `radio` names a radio of the caller's own runs the stack over it instead of an RCP, which is how the suites run two stacks with no hardware; such a stack has no port to draw entropy from, so it is given its network key, or an `entropy` source of the application's own, which then replaces the port's for every stack.
The caller pumps its own radio as the stack pumps an RCP: the loopback answers an energy dwell on the next `LoopbackRadio_Pump`.

## 11. What is not there yet

The Cluster Library has its frame and the Basic cluster, and no other cluster; the application writes other clusters' payloads itself, as §6 does.
The APS commands beyond key exchange, and some device-object requests, are not built.
The Windows port is a stub.
`docs/status.md` keeps the list, with what each gap waits on.
