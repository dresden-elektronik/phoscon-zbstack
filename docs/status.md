# Status

What the stack can do, what it cannot yet, and what comes next.
**After reading** you know what works today, what each gap is, and what would close it.

| Part | State | What is true |
| --- | --- | --- |
| Talking to the radio | **done** | An RCP is identified, armed and reset over Spinel, and a recorded stream replays byte for byte. |
| The MAC | **done** | Data and command frames, sequence numbers, acknowledgements, polls, the indirect queue, association, beacons and scans. |
| Network data | **done** | Frames cross with network security, are retried, broadcast, relayed and delivered by the printed rules. |
| Routing | **done** | Discovery, replies, relays, ageing, source routes, many-to-one failure reporting and the neighbour ranking; a broken route is reported to its originator and discovered again on the next send. |
| Joining | **done** | A device joins by association or by the commissioning pair, is given a stochastic address, rejoins, and asks its parent for a timeout. |
| The network key | **done** | A joined device receives it from the trust centre under the global link key, and a Zigbee 3.0 device is given its own trust-centre link key when it asks; a joiner built on the stack asks for its own, unless told to keep the one it joined with. |
| Application support | **in part** | Unicast, acknowledgements, groups, duplicate rejection, fragmentation, binding and APS security; the APS commands beyond key exchange are not built. |
| The application layer | **in part** | The device door and its join, the endpoint registry, the device object's discovery, table reports, permit and leave management, binding, and the Basic cluster; not the other clusters. |
| Hosts | **in part** | The suites pass on macOS, on Linux (Debian on a Raspberry Pi 5, Ubuntu and Debian containers on x86_64) and on Windows 11 with MSVC; the examples run on Linux on a Raspberry Pi, and on Windows over a ConBee II and a ConBee III. |
| Cross-platform CI | **not started** | Nothing yet; the goal is one local command that builds, tests and audits the tree on Windows, Linux and macOS, with no hosted service. |
| Fuzzing | **not started** | Nothing yet; the goal is libFuzzer targets over the MAC and NWK decoders, and a sanitizer run that reports no fault. |
| A microcontroller target | **parked** | The library measures 33 KiB of flash and no RAM of its own on a Cortex-M0+; no target is chosen. |

## What works today

A Zigbee 3.0 light joins a coordinator built on the library, receives the network key, and has its trust-centre link key updated.
A second RCP joins that network as a router and lets devices join through it.
Two RCPs with no route between them discover one and carry an acknowledged frame over it.
Six RCPs made to hear only their two sides route across five hops.
An end device with its receiver on reaches every router of that line through its parent, and each answers it.
A sleepy end device joins, takes its link key and is interviewed through its polls, on loopback radios and on an ESP32-C6 development board running Phoscon RCP under a ConBee II parent.
A capture of a test network replays through all four layers with no RCP attached.
An application registers its endpoint, the device object answers and asks discovery, and the Basic cluster answers a read.

## What is next

| Gap | What closes it |
| --- | --- |
| clusters beyond Basic | the Cluster Library's other clusters, starting with On/Off and Level Control, so an example can act on a command |
| device-object requests | the management and binding requests in `ZB_ZDO_CLIENT` beside its discovery requests, and the network-update commands |
| APS commands | the commands beyond key exchange |
| Green Power | the proxy and sink of the Green Power specification, so battery-free switches reach the network through a router or the coordinator |
| Touchlink | Inter-PAN frames, which the network layer refuses today, then Touchlink commissioning over them, so a light can be paired by proximity |
| a sleepy end device under another stack's parent | a bench run measuring the poll window against a parent that is not this stack, which fixes `MAC_POLL_WAIT_MS` (D-300), and the Ack's Frame Pending bit measured on the ConBee III and the ESP32-C6 board, where only the ConBee II's is |

The network layer is closed against the standard, except two optional features (power negotiation, multiple MAC interfaces) and the NIST randomness regimen.
The mesh backbone's algorithm is printed in the standard, but its parameters are not.

Every RCP runs Phoscon RCP firmware; `docs/internals/hardware.md` lists them.
