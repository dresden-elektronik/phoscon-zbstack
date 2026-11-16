# Hardware

The RCPs: what each one is, what it reports, and the rules a run against one obeys.
**After reading** you can identify an RCP, predict what it will answer, and know which actions a run may take.
Claims are marked **measured** (on Phoscon RCP, through this harness), **upstream** (from a named reference source), **spec** (a clause of a published specification, `docs/internals/refs.md` §1) or **open**.
Wire-level behaviour is in `docs/internals/protocol.md`; the shape of the stack is in `docs/internals/architecture.md`.

## 1. Supported devices

Every device runs Phoscon RCP, the Spinel radio co-processor firmware for this family, released separately (`docs/internals/refs.md` §1); this stack has never been measured against a vendor build.

| Device | Silicon | Host link | `NCP_VERSION` | Notes |
| --- | --- | --- | --- | --- |
| ConBee II | ATSAMR21E18A (Cortex-M0+) with an AT86RF233 | native USB CDC | `DSPINEL/1.0; AT86RF233; phoscon-rcp 0.2.0` | the reference device |
| RaspBee II | the same | the Raspberry Pi header UART at 115 200 8N1: `/dev/ttyAMA0` on a Pi 5, never `/dev/serial0` | the same | its bootloader stays at 38 400 |
| ConBee III | EFR32MG21 (Cortex-M33) | an FTDI USB-serial bridge at 115 200 | `DSPINEL/1.0; EFR32MG21; phoscon-rcp 0.2.0` | an early unit reports an extended address that is not its own, so a run names one (`--own-ieee`, D-242) |
| ConBee I | ATmega256RFR2 | an FTDI USB-serial bridge at 57 600 | `DSPINEL/1.0; ATmega256RFR2; phoscon-rcp 0.2.0` | before 0.2.0 an energy dwell reported a level on channels 11 to 15 only |
| RaspBee I | the same | the Raspberry Pi header UART at 57 600: the mini UART `/dev/ttyS0` on a Pi 3, `/dev/ttyAMA0` on a Pi 5 | the same | under-voltage on the Pi silences it for a whole bring-up |

macOS enumerates a CDC stick as `/dev/cu.usbmodem*` and a bridged one as `/dev/cu.usbserial-*`, and sticks of one kind share a prefix, so a port is always named.
A stick on a USB extension cable reads a noise floor 8 to 14 dB lower than one in a hub or the host's own port, and a floor near the -71 dBm CCA threshold fails CCA however good the RCP is.

**Which build a ConBee II carries, without opening its port:** both firmwares enumerate as `idVendor:idProduct` `0x1cf1:0x0030` with product string `ConBee II`; `bcdDevice` `0x0101` is Phoscon RCP (**measured**) and `0x0100` the vendor build it replaces, which is that project's naming and not a measured fact.
Reading `ioreg -p IOUSB -l -w0` is a host-side question and touches no device.

Every ConBee II reading in this document and in `docs/internals/protocol.md` §7 is a reading of Phoscon RCP at some revision, and what separates two of its revisions is `RADIO_CAPS` and the scan group (§3).

## 2. Link parameters

| Parameter | Value | Basis |
| --- | --- | --- |
| Baud | 115 200 for the ConBee II, the ConBee III and the RaspBee II; 57 600 for the ConBee I and the RaspBee I | measured |
| Framing | 8N1, raw, no flow control, no DCD requirement | measured |
| Open behaviour | responds immediately; a leading bare `0x7E` flush is documented bring-up and is sent on open | upstream, measured-compatible |
| CDC line coding | host-set; set via termios on open (`CREAD\|CLOCAL`, clear `CSTOPB`/`PARENB`) | measured |
| Host reach of the stage-1 harness | POSIX only (`termios` + `select`): macOS measured, Linux expected, Windows unsupported | measured, open |
| Port naming outside macOS | Linux `/dev/ttyACM*` for a ConBee II, and `/dev/ttyUSB*` for a bridged stick; Windows `COM<n>` | both Linux names measured; Windows **open**: `docs/porting.md` §3 |

## 3. Dialect identity

Every supported device speaks Spinel over HDLC under one dialect, `DSPINEL/1.0`, which band B detects from the prefix of `NCP_VERSION`.
An RCP that answers `SL-OPENTHREAD` is read with the OpenThread dialect of `docs/internals/protocol.md` §7.1, which no supported device runs.

| Property | ConBee II on Phoscon RCP |
| --- | --- |
| `PROTOCOL_VERSION` | `04 03` (4.3) |
| `INTERFACE_TYPE` | `03` |
| `CAPS` | 34 CONFIG_RADIO, 64 RCP_API_VERSION, 65 RCP_MIN_HOST_API_VERSION, 67 RCP_LOG_CRASH_DUMP, 513 MAC_RAW |
| `RCP_API_VERSION`, `RCP_MIN_HOST_API_VERSION` | 4, 4 |
| `RADIO_CAPS` (`0x120B`) | `0x16f` (§4) |
| `VENDOR_ID` (4), `INTERFACE_COUNT` (6) | `PROP_NOT_FOUND` |
| `PHY_CHAN_SUPPORTED` (`0x22`) | the channels 11 to 26 |
| `PHY_ENABLED` (0x20), `PHY_CHAN` (0x21) after a reset | `0`, `0`: the channel must be set, and it stays set |
| `MAC_RAW_STREAM_ENABLED` (0x37), `MAC_PROMISCUOUS_MODE` (0x38), `MAC_RX_ON_WHEN_IDLE` (0x3B) | GET-answerable; all read `0` after a reset |
| `PHY_CCA_THRESHOLD` (0x24) | −71 dBm (`b9`) |
| `PHY_TX_POWER` (0x25) after a reset | `fd`, -3 dBm: the board's cap, which the firmware reads back in place of the host's value |
| `PHY_RSSI` (0x26) | `−128` dBm: an "unknown" sentinel on an idle radio, not a measurement |
| `PHY_RX_SENSITIVITY` (0x27) | `−96` dBm, the AT86RF233 figure |
| `MAC_15_4_SADDR` (`0x35`) after a reset | `fe ff` = `0xFFFE`, the unassigned short address |
| Scan properties `0x30`..`0x32` | answered: state, mask, period (`docs/internals/protocol.md` §7.4.1) |
| `0x33`, `0x39` | `PROP_NOT_FOUND` on GET, `0x39` arriving as a notification |
| `RCP_LOG_CRASH_DUMP` (`0xB2`) after a reset | `00`, with no record stream until a host writes `01` |
| `0x1303`..`0x1305` | answered: the source-match enable bit and the two address lists (`docs/internals/protocol.md` §7.4.5) |
| `PHY_FREQ` (`0x23`), `MAC_DATA_POLL_PERIOD` (`0x3A`), `UNSOL_UPDATE_FILTER` (`0x1008`), `UNSOL_UPDATE_LIST` (`0x1009`), `RCP_TIMESTAMP` (`0x802`), `RCP_CSL_ACCURACY` (`0x804`) | `PROP_NOT_FOUND` |
| the transmit PSDU's length | the caller's, footer included |

Every row is **measured**.
`PHY_CCA_THRESHOLD`, `PHY_RSSI`, `PHY_RX_SENSITIVITY` and the after-reset reads of `0x20`, `0x21`, `0x37`, `0x38` and `0x3B` were read at an earlier revision (`docs/internals/protocol.md` §7.2) and are not known to have moved; the other rows are Phoscon RCP 0.2.0's.
Two ConBee IIs answer **byte-identically**, with `HWADDR` the only differing field: per-device data, not a dialect difference.

**The name is not the revision.**
The same `NCP_VERSION` name, `PROTOCOL_VERSION`, `INTERFACE_TYPE`, API levels and five `CAPS` numbers answered at every revision read, while `RADIO_CAPS`, the scan group, `0x22`, `0xB2`'s default, the transmit power read back and the source-match family moved under them (`docs/internals/protocol.md` §7.4).
A feature is therefore chosen from what the device answers, never from the version string or from what was measured last: `docs/internals/decisions.md` D-123.

The last row is the contract this stack's own transmissions depend on: the length the host gives counts the two FCS octets the radio fills in, as upstream OpenThread's SAMR21 driver and zigbee-on-host do, and a 12-octet PSDU arrives as twelve.
Band B sets it from the dialect (`psduIncludesFcs`, `docs/internals/protocol.md` §8.2).

## 4. Radio capabilities (`RADIO_CAPS`, `0x120B`)

| Device | Value | Decoded (`OT_RADIO_CAPS_*`) |
| --- | --- | --- |
| Every device on Phoscon RCP 0.1.0 and 0.2.0 | `0x16f` | ACK_TIMEOUT, ENERGY_SCAN, TRANSMIT_RETRIES, CSMA_BACKOFF, **TRANSMIT_SEC**, **TRANSMIT_TIMING**, RX_ON_WHEN_IDLE |

A capability bit is a claim about the silicon, not a contract about how to ask: band B gates a scan on the answers of `0x30`..`0x32` rather than on the bitmap or the version string, and an earlier revision answered a bitmap without ENERGY_SCAN under the same name (`docs/internals/decisions.md` D-123).
A stack must read this property rather than assume it.
Phoscon RCP claims TRANSMIT_SEC and TRANSMIT_TIMING; this stack secures in the host and uses neither, so APS and NWK crypto is entirely host-side.

The DSPINEL dialect delivers the FCS inside the PSDU, and the radio's own verdict corroborates it on the wire: in one 49-frame capture the 11 frames carrying `MD_FLAG` `0x0004` (BAD_FCS) are exactly the frames whose trailing two octets are not the CRC of the preceding body.

The bitmap above is OpenThread's `otRadioCaps` enum, taken straight from the wire: the host driver casts the value rather than translating it, so a firmware that is not OpenThread still reports OpenThread's bit positions here, and `0x16f` decodes as it does only under that enum.
Decoding the same octets as some other capability table reports capabilities the device does not have.

## 5. Addressing identities

| Identity | Where | Order | Notes |
| --- | --- | --- | --- |
| `HWADDR` (`0x08`) | factory EUI-64 | MSB-first (display order) | the dresden OUI `00:21:2e` in front; on an early ConBee III unit the reported address is not its identity (§1, `--own-ieee`). Read-only; on the AT86RF233 build an erased NVM user row answers `INVALID_STATE` rather than zeros **upstream** |
| `MAC_15_4_LADDR` (`0x34`) | host-set operational address | **big-endian** on the wire: **upstream**, **measured** on a ConBee II | what the radio's address filter uses; all zeros after every reset, i.e. set it before expecting unicast or ACK delivery |
| `MAC_15_4_SADDR` (`0x35`) | host-set | `u16` LE | default `0xfffe` |
| `MAC_15_4_PANID` (`0x36`) | host-set | `u16` LE | default `0xffff` (match-any) |

## 6. Measured device behaviour

The delivery selection (`MAC_PROMISCUOUS_MODE`) is a third state with its own consequences: a promiscuous RCP hands up every frame it hears and **acknowledges none of them**, and a filtered one hands up what names it.
A filtered RCP must hand up a frame addressed to its own **extended** address, which is where 10.21.5.2's Association Response goes while a joining device has no short one; an early Phoscon RCP revision did not, and every revision since does.

## 7. Channels

A run that transmits does so on a quiet channel and a private PAN, `0xbeef` by default.
Nothing is protected by default: `--protect-channel <n>` and `--protect-pan <id>`, each repeatable, name a network of the user's own that shares the air.
A protected channel is refused even for a run that sends nothing, because an armed RCP acknowledges frames addressed to it.
`tools/rcp_probe` and `tools/zb_join` arm on a protected channel only with `--allow-live-channel`; `tools/rcp_probe` needs the same flag to transmit to a protected PAN, `tools/zb_join` refuses one, and `tools/rcp_send` lifts neither protection.
`tools/zb_mesh` and its driver `tools/zb_mesh_bench.py` take the same two options, and refuse a run whose channel or fixed PAN is protected.
A quiet channel reads about -94 dBm on a USB stick on a cable; 12 (`tools/rcp_probe`) and 26 (`tools/rcp_send`) are the ones the tools default to.
A channel is only as quiet as its last listen, so a run listens first.

## 8. Rules for a run

| Rule | Reason |
| --- | --- |
| Pass the device explicitly, always | RCPs of one kind share a port-name prefix, and no tool defaults a port |
| End a session with a reset | armed state survives the close, so a closed port is not an unarmed RCP |
| A dwell is a receive-only action | an energy scan transmits nothing, so it may run even on a protected channel; it does take the RCP off the host's channel for its length and delivers no frame while it runs, and a session that armed the radio for it ends with a reset like any other |
| One session per port | a second writer corrupts measurements and can reset the RCP mid-run, and a second *reader* steals its traffic; the platform enforces neither |
| A tool that transmits takes `--tx` and `--allow-tx`, and runs on a quiet channel with a private PAN | an accidental run arms nothing; the examples are applications and take no gate, like any application (D-273) |
| A protected channel is armed on only with `--allow-live-channel`, where the tool offers it, and a protected PAN is not composed for | a network of the user's own is never disturbed by accident (§7) |
| An active scan transmits on every channel it visits | each channel gets a Beacon Request, five times on a router's join by default, so a scan's channel list is a transmit authorisation channel by channel, and `example_router --channels` has no default for this reason |
| No reflashing from this repository | the firmware's flash path ends in a bootloader trap, and flashing is the firmware project's procedure |
| Energy-scan the channel before counting a CCA failure | an RCP whose floor reads near or above the host's -71 dBm threshold fails CCA because of where it is plugged in, and the run measures the port (§1) |
| Verify an RCP's identity (`GET NCP_VERSION`) before believing a firmware fault | a fault is a fact about one build, and the firmware on a port may have changed since the last run |
| A run that expects acknowledgments arms the radio with promiscuity off (`--no-promisc`) | a promiscuous receiver does not hardware-acknowledge, so every acknowledged frame comes back `17 NO_ACK` and the exchange looks broken |
