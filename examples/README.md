# Examples

Three applications built on `Zb_Stack`, each in a directory of its own with its `CMakeLists.txt`, with no test rig and no bench instrument.
A new example is a new directory and one `add_subdirectory` line in `examples/CMakeLists.txt`.
They are here to be read, run against an RCP, and copied; `docs/getting-started.md` runs them, and `docs/guide.md` explains every call they make.

| Example | What it does |
| --- | --- |
| `coordinator/` | forms a network, lets devices join and hands them the network key, and prints what it receives |
| `router/` | finds a network on the channels it is given, joins it, then lets devices join through it; its endpoint serves the Basic cluster |
| `interview/` | a coordinator that asks every device that joins what it is: its descriptors, then the Basic cluster's manufacturer name and model; built with `ZB_ZDO_CLIENT` |

The first two state their network once and are then three states over the stack's events: `APP_STARTING` until the network is up, `APP_SERVING` until it is told to stop, and `APP_STOPPING` until the stack says it stopped (Figure 1).
The two differ in their config, a coordinator naming its channel and PAN and a router the channels it may look on, and in the router answering a read of its Basic cluster.
`example_interview` runs the same three states with an interview per device beside them.

![A state diagram of the application both examples share. Zb_StackStart returns ZB_OK with the RCP open, and the application enters APP_STARTING, where the stack brings the RCP up and forms or joins a network. On ZB_EVENT_NETWORK_UP it moves to APP_SERVING, in amber, where ZB_EVENT_DEVICE_JOINED, ZB_EVENT_DATA, ZB_EVENT_SENT, ZB_EVENT_RCP_LOST and ZB_EVENT_RCP_BACK are printed and the state stays. On Ctrl-C, or when --seconds runs out, the application calls Zb_StackStop and moves to APP_STOPPING; a rail on the left takes APP_STARTING there the same way, on ZB_EVENT_NETWORK_FAILED, Ctrl-C or --seconds. On ZB_EVENT_STOPPED the application reaches APP_DONE and main returns. A note says the coordinator and the router differ only in their Zb_StackConfig: Zb_StackCoordinatorDefaults with the channel and PAN it forms, Zb_StackRouterDefaults with a channel mask the stack scans.](../docs/images/appstates.png)

*Figure 1: the examples' shared state machine.*
It moves on the events `Zb_StackNextEvent` hands back and on its own decision to stop, and spends its life in `APP_SERVING`, in amber.
Source: `tools/diagrams/appstates.py`.

An example includes `zb_stack.h`, the codecs beside it (`zcl.h`, `zdo.h`, and `zdo_client.h` where `ZB_ZDO_CLIENT` builds it), its own directory's headers, `src/utils/`, the port's contract `port.h` and its files `port_file.h`, the shared modules of `common/` and the vendored `u_sstream.h`, and nothing under them; `test/bands_audit.py` holds that, because a header from below would mean the stack is missing something.

## The saved network: `common/ex_config`

`common/` holds what more than one example pulls in, built as the `example_config` library that an example links beside `zb_stack`.
`ex_config` keeps a device's network in a text file, through three calls.

- `Ex_ConfigSave` builds each line with U_SStream, writes `<path>.tmp` through `port_file.h` and renames it over the file, so a failed save leaves the old one.
- `Ex_ConfigLoad` refuses any line it did not write, leaving the caller's config untouched, and skips `#` lines and blank ones.
- `Ex_ConfigToStack` points a `Zb_StackConfig` at what it read: the channel, the link-key seed and the state.

The file holds one field per line: `version`, the channel, the link-key seed, then every field of the `Zb_State` that `Zb_StackCapture` returns, ids and keys in hex and the rest in decimal.
A `key`, `window`, `pair` or `child` line is one entry, its values in the order `ex_config.c` writes them, and `-` stands for a key or a short address the entry does not hold.
It carries the network key and every link key in clear.

`config/` holds a sample for each role, `coordinator.txt`, `router.txt` and `end_device.txt`, with a comment on what that role keeps.
No example reads them; the `ex_config` suite holds them readable.

## `example_coordinator`

```sh
./build/host/example_coordinator --path <port> --channel 25
```

| Option | Means |
| --- | --- |
| `--path` | the RCP's serial device node; none is ever defaulted |
| `--channel` | the network's channel, 25 by default: one no other network uses where you are |
| `--pan` | the network's PAN identifier, `0xbeef` by default |
| `--extended-pan` | the network's extended PAN identifier; the coordinator's own address by default |
| `--permit` | how long joining stays open, 180 s by default, 0 to keep it closed |
| `--baud` | 57600 for a ConBee I or a RaspBee I, whose links run at that rate |
| `--ieee` | the device's extended address, for a unit taking over another's identity (D-242); the RCP's own otherwise |
| `--seconds` | how long to run; 0, the default, runs until Ctrl-C |
| `--config` | a file the network is kept in (`common/ex_config` above); once it exists, it names the channel, PAN, extended PAN and address, and `--channel`, `--pan`, `--extended-pan` and `--ieee` are refused beside it |

Its network key is drawn at random on every run, and a device joins with Zigbee 3.0's global trust-centre link key, "ZigBeeAlliance09".
With `--config`, the first run draws the key and a link-key seed and saves the network once it is up; a later run brings it back, its outgoing counters 256 past the saved ones, so a device that joined before is still heard.
The file is saved when the network comes up, when a device joins, every 30 s if anything changed, and before the stack stops.
It does not serve a cluster, so an On/Off command from a remote arrives as an `aps` line and is not acted on.

## `example_router`

```sh
./build/host/example_router --path <port> --channels 25
```

| Option | Means |
| --- | --- |
| `--channels` | the channels the discovery visits; required, because it sends a Beacon Request on every one |
| `--extended-pan` | join only this network; without it, the best-ranked network that permits joining |
| `--permit` | how long devices may join through it once it has joined, 180 s by default, 0 to keep it closed |
| `--path`, `--baud`, `--ieee`, `--seconds` | as for the coordinator |
| `--config` | a file the network is kept in; once it exists, the router comes back at its address with no join, on the saved channel, which `--channels` must list, and `--extended-pan` and `--ieee` are refused beside it |

Its endpoint 0x01 is a dimmable light that serves the Basic cluster: a Read Attributes is answered with ZCLVersion, PowerSource (mains), ManufacturerName `Phoscon` and ModelIdentifier `example_router`, and any other command sent to that cluster by unicast draws a Default Response, `UNSUP_COMMAND` (ZCL R8 2.5.12.2); it serves On/Off and Level Control in its descriptor only.

It brings one key, the global trust-centre link key; without `--config` it keeps nothing across runs, so each run joins again.
With `--config` it saves its network as the coordinator does, and a later run reaches the coordinator again once link status has measured the link, about 30 s.

Both print the same lines: `network` when the network is up, `joined` for a device that joined, `aps` for a frame that reached the application, `confirm` for a send's outcome, `rcp` when the RCP reset and came back, and `reset` once the RCP was reset and closed.

## `example_interview`

```sh
cmake -S . -B build/zdo -DZB_ZDO_CLIENT=ON && cmake --build build/zdo
./build/zdo/example_interview --path <port> --channel 25
```

It takes the coordinator's options but `--config`, and forms a new network on every run.
Every device that announces itself is interviewed, one request at a time, by a state machine of its own in `interview.c`:

| Step | Request | Moves on when |
| --- | --- | --- |
| node descriptor | `Node_Desc_req` through `Zb_StackZdoRequest` | the `Node_Desc_rsp` with the request's transaction sequence number comes |
| active endpoints | `Active_EP_req` | the `Active_EP_rsp` comes; with no endpoint the interview ends |
| simple descriptor | `Simple_Desc_req`, once per endpoint | each `Simple_Desc_rsp` comes |
| basic cluster | a ZCL Read Attributes of ManufacturerName (0x0004) and ModelIdentifier (0x0005) through `Zb_StackApsRequest`, to the first endpoint whose input clusters name Basic | the Read Attributes Response, or a Default Response refusing it, with the read's ZCL sequence number comes; with no such endpoint the interview ends |

A step's answer may come before its request's `ZB_EVENT_SENT`, as some products send it, and moves the step on all the same.
A request not delivered, or not answered within 10 s, is asked again 2 s later, three times in all, and the interview stops at that step after the third.
A status other than SUCCESS leaves that part out and moves on.
Four devices are asked at once, which keeps their requests inside the eight the stack takes in flight; the others wait their turn.
An `interview` line follows every request, and a summary once a device is complete: its logical type, its manufacturer code, each endpoint's profile, device and clusters, its manufacturer name and its model.
`example_router` on a second RCP answers every step.
