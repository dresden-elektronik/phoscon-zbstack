# Phoscon Zigbee Stack

A Zigbee stack in portable C99 for dresden elektronik's ConBee and RaspBee.
It runs on the host: the 802.15.4 MAC, the network layer, application support and the application layer are one library, and the ConBee or RaspBee, running the Phoscon RCP firmware as a radio co-processor (RCP), is only a radio driven over Spinel.
A device built on it takes any of the three Zigbee roles: coordinator, router or end device, sleepy or not.
The router and end device roles are what deCONZ's coming refactor uses to simulate existing products on a real Zigbee network.
The current version is 0.6.0: usable, with the API still allowed to change before 1.0.0 (`src/zb/zb_version.h`).

![What runs where, read downwards. On the host: your application, such as a coordinator, a router or a gateway; then the Zigbee stack in amber, four layers: ZDO, ZCL and AF, the application layer; APS, delivery, acknowledgements, binding, groups and keys; NWK, joining, routing, relaying and network security; and the MAC, frames, retries, association and indirect delivery; then the port, the serial device, a millisecond clock and entropy. A rule marked Spinel, HDLC frames over USB or a UART, separates the host from the RCP, which holds Phoscon RCP, the radio firmware doing CSMA, the Ack, the address filter and the energy scan, and the PHY. Under them the five RCPs, ConBee I, II and III and RaspBee I and II; a rule marked 802.15.4, the air at 2.4 GHz; and the Zigbee devices: lights, sensors, plugs and other routers.](docs/images/where.png)

*Figure: what runs where.*
Everything Zigbee runs on the host, the MAC included; the RCP acknowledges, backs off and filters in radio time and does nothing else.

The library allocates nothing and has no thread, clock or file of its own.
The application turns it, passes the time in milliseconds and lends every buffer, so the same code builds for a desktop host, for WASM, or for a microcontroller beside a co-processor.

## What works

| Part | State |
| --- | --- |
| MAC | done: data and command frames, acknowledgements, polls, the indirect queue, association, beacons |
| Network layer | done: joining and rejoining, network security, broadcasts, relaying, route discovery, source routes |
| End devices | done: an end device joins, polls its parent and rejoins when the parent goes silent; a sleepy one listens only after its polls |
| The network key | done: a joining device receives it from the trust centre under the Zigbee 3.0 global link key |
| Application support | in part: unicast, acknowledgements, groups, fragmentation, binding and APS security; not the APS commands |
| Application layer | in part: endpoints, device discovery, binding, permit and leave management, the Basic cluster; not the other clusters |
| Hosts | macOS, and Linux on a Raspberry Pi (with a RaspBee on its header) or x86_64; and Windows, measured with a ConBee II and a ConBee III |

A Zigbee 3.0 bulb joins a coordinator built on the library and has its trust-centre link key updated, and a second RCP joins as a router and lets devices join through it.
`docs/status.md` holds what is next, and what each gap waits on.

## Hardware

| Device | Host link |
| --- | --- |
| ConBee II | USB |
| RaspBee II | Raspberry Pi header UART, 115 200 baud |
| ConBee III | USB serial bridge |
| ConBee I | USB serial bridge, 57 600 baud |
| RaspBee I | Raspberry Pi header UART, 57 600 baud |

Each runs [Phoscon RCP](https://github.com/dresden-elektronik/phoscon-rcp), released separately; `docs/internals/hardware.md` has what each one reports.

## Try it

```sh
git clone https://github.com/dresden-elektronik/phoscon-zbstack && cd phoscon-zbstack
cmake -S . -B build/host -DCMAKE_BUILD_TYPE=Debug && cmake --build build/host
ctest --test-dir build/host --output-on-failure    # every suite and audit; no RCP needed

# a coordinator on channel 25 that hands the network key to every device that joins
./build/host/example_coordinator --path <port> --channel 25
```

`<port>` is the RCP's serial device node: `/dev/cu.usbmodem*` on macOS, `/dev/ttyACM*` on Linux, `COM<n>` on Windows.
On Windows the same commands run in a Developer Command Prompt for Visual Studio, with `-G Ninja` on the first, and the programs are `build\host\example_coordinator.exe` and the like.
`examples/README.md` walks through the three examples and what they print.

## Documentation

For using the stack:

| Document | Read it to |
| --- | --- |
| `docs/getting-started.md` | build the stack, start a coordinator on an RCP, and join a light to it |
| `docs/guide.md` | write an application: the loop, setting up a device, joining, sending, receiving, saving state |
| `docs/configuration.md` | choose the build options and size the stack's tables, from a gateway to a small target |
| `docs/memory.md` | see where memory goes |
| `examples/README.md` | read the two example programs and their options |
| `docs/status.md` | see what works, what does not, and what comes next |
| `docs/porting.md` | bring the stack to another platform |

For changing it, or finding your way inside it:

| Document | Read it to |
| --- | --- |
| `docs/internals/README.md` | start: the vocabulary, the source map, and which document answers what |
| `docs/internals/architecture.md` | see the bands, the seam, and why the MAC runs on the host |
| `docs/internals/protocol.md` | read the bytes on the wire: Spinel, HDLC, 802.15.4 and Zigbee framing |
| `docs/internals/conformance.md` | find the clauses each source file implements |
| `docs/internals/testing.md` | see what each suite proves, and the bench instruments |
| `docs/internals/coding-rules.md`, `AGENTS.md` | change the code |
| `docs/internals/decisions.md` | look a decision up by its D-id |

## License

BSD-3-Clause, copyright dresden elektronik ingenieurtechnik gmbh, see `LICENSE`.
`vendor/` holds two pinned libraries under their own BSD licences (`docs/internals/refs.md` §6).
