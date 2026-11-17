# Getting started

From a clone to a Zigbee network with a device in it: build the stack, run its suites, start a coordinator on an RCP, and join a light to it.
**After reading** you have a running network, you know what each line the coordinator prints means, and you know where to go to write your own application.

## 1. What you need

| | |
| --- | --- |
| an RCP | any of the five running the Phoscon RCP firmware: ConBee I, II or III, RaspBee I or II; to either example, a ConBee I or a RaspBee I adds `--baud 57600` |
| a host | macOS or Linux, with CMake, a C99 compiler and Python 3 |
| a device to join | any Zigbee 3.0 device, factory reset: a light is the easiest, since it starts looking for a network as soon as it is powered |
| a channel | one that no other network uses where you are; the examples default to 25 |

The RCP's firmware is [Phoscon RCP](https://github.com/dresden-elektronik/phoscon-rcp), released separately with its own flashing guide; this stack never flashes an RCP.
`docs/internals/hardware.md` lists what each one reports.

## 2. Build and test

```sh
git clone https://github.com/dresden-elektronik/phoscon-zbstack
cd phoscon-zbstack
cmake -S . -B build/host -DCMAKE_BUILD_TYPE=Debug
cmake --build build/host
ctest --test-dir build/host --output-on-failure
```

The suites need no RCP: each layer runs against a scripted radio, and the audits check the tree's own rules.
Every one of them passes on macOS, where they are run; Linux is expected to pass and has not been measured.

## 3. Find the RCP's port

| Host | Device | Port |
| --- | --- | --- |
| macOS | ConBee II | `/dev/cu.usbmodem*` |
| macOS | ConBee III | `/dev/cu.usbserial-*` |
| Linux | ConBee II | `/dev/ttyACM*` |
| Linux | ConBee III | `/dev/ttyUSB*` |
| Raspberry Pi 5 | RaspBee II | `/dev/ttyAMA0`, never `/dev/serial0` |

The Linux names are the kernel's usual ones; Linux has run here only on a Raspberry Pi.
No program here ever picks a port for you: several devices of one kind share a name prefix, and the wrong one would be armed.
One program at a time may have a port open.

## 4. Start a coordinator

```sh
./build/host/example_coordinator --path <port> --channel 12
```

The coordinator forms the network, opens it to joining for 180 seconds (`--permit` changes that), and waits; its network key is drawn at random, and its extended PAN identifier is its own address unless `--extended-pan` names one:

```
stack      Phoscon Zigbee Stack 0.6.0
network    coordinator 0x0000, PAN 0xbeef, channel 12, extended PAN 00212effff048a12, ieee 00212effff048a12
network    endpoint 0x01, profile 0x0104, clusters 0x0006 and 0x0008; permit open 180 s
network    waiting for a device to join; Ctrl-C ends the run
```

## 5. Join a device

Power the factory-reset light while the permit is open.
It finds the network, associates, receives the network key from the coordinator, and announces itself; in this run the device was a second RCP running the router example (§7):

```
joined     0x5e8f  00212effff05a888  receiver-on
```

| Line | Means |
| --- | --- |
| `joined` | a device joined and announced itself: its network address, its extended address, whether its receiver stays on |
| `aps` | a frame reached the application's endpoint, with its source, cluster and payload |
| `confirm` | a frame the application sent was answered, with its outcome |
| `rcp` | the RCP reset or came back; the stack brings it back by itself |

The application did none of this; it stated its network and reads what the stack reports (Figure 1).
The beacon, the association, the key and the device object's answers are the library's, and a Zigbee 3.0 device that asks for its own trust-centre link key is given one too.

![A sequence diagram with three lifelines: the joining device, a Zigbee 3.0 bulb, on the left; the coordinator, the trust centre this stack runs, in the middle; your application on the right. The application's config opened joining when the network came up. To find a network, the device broadcasts a Beacon Request and the coordinator answers with a Beacon saying it is the PAN coordinator, permits association and has router capacity. To associate, the device sends an Association Request and then a Data Request poll, and the coordinator answers with an Association Response giving the short address 0x1fa1. To get the network key, the coordinator sends an APS Transport Key carrying the network key, sealed with a key derived from ZigBeeAlliance09; this step is amber, the moment the device becomes a member. The device broadcasts its Device_annce, which the stack reports to the application as ZB_EVENT_DEVICE_JOINED. For the Zigbee 3.0 link key, the device asks for the coordinator's node descriptor, sends an APS Request Key, receives its own trust-centre link key in an APS Transport Key, proves it holds the key with an APS Verify Key, and receives an APS Confirm Key under the new key. A note says the APS acknowledgements are not drawn.](images/join.png)

*Figure 1: how a device joins.*
The network key arriving, in amber, is the moment the device becomes a member; after it, a Zigbee 3.0 device trades the global link key for one of its own.
The application states its permit in the config and hears the join as one event.
Drawn from a real light's join; source: `tools/diagrams/join.py`.

## 6. Stop

Ctrl-C ends the run.
The coordinator stops the stack, which resets the RCP and closes the port, so the RCP is left unarmed:

```
reset      the RCP was reset and closed, and is left unarmed
```

The example keeps nothing between runs: no device table, no frame counters, no keys a device was given.
A product saves that state and restores it at start (`docs/guide.md` §9).

## 7. A second RCP as a router

```sh
./build/host/example_router --path <second port> --channels 12
```

The router discovers the network on the channels named, joins it, waits for the network key, and then lets devices join through it:

```
router     looking for a network; Ctrl-C ends the run
stack      Phoscon Zigbee Stack 0.6.0
network    router 0x5e8f, channel 12, extended PAN 00212effff048a12, ieee 00212effff05a888, holding the network key
network    serving; Ctrl-C ends the run
```

Every transcript on this page is one run, shortened.
`--channels` has no default, because a discovery sends a Beacon Request on every channel it visits.
A ConBee I or a RaspBee I adds `--baud 57600`.

## Next

| To | Read |
| --- | --- |
| see how the examples are built, and what they print | `examples/README.md` |
| know what works and what does not yet | `docs/status.md` |
| bring the stack to a platform other than macOS or Linux | `docs/porting.md` |
