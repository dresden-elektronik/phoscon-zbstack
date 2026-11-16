# Protocol

The Spinel-over-HDLC contract as implemented and measured on Phoscon RCP, plus the 802.15.4/Zigbee framing facts the harness has to interpret.
What a layer does with those bytes is `docs/internals/conformance.md`; device-specific values (capabilities, identity, quirks) are in `docs/internals/hardware.md`.
**After reading** you can read an octet on the wire as the field, the property or the answer it is.
Claims are marked **spec** (a named clause of a published specification, which outranks any implementation: `docs/internals/refs.md` §1.1), **measured** (on Phoscon RCP), **upstream** (a reference implementation) or **open**; a claim that is this repository's own binding decision (`docs/internals/decisions.md`) carries **mandate**.
Section numbers are frozen: never renumber, never reuse, and a section is filed where its number says it belongs.

## 1. Transport

Byte-transparent serial link, 115200 8N1 raw (`docs/internals/hardware.md` §2).
An RCP is a Spinel *NCP*: it answers commands and emits unsolicited notifications on the same byte stream.

## 2. HDLC framing

![The host-to-RCP serial framing as byte strips. An HDLC frame is a 0x7E flag, the Spinel frame (at most 254 octets before escaping), a 2-octet CRC-16/X.25 FCS sent low octet first, and a closing 0x7E; a bracket notes that 0x11, 0x13, 0x7D, 0x7E and 0xF8 in the frame and the FCS go out as 0x7D followed by the octet XOR 0x20. The Spinel frame is a header octet (flag 0b10, IID 0, a 4-bit TID), a command and a property id as packed unsigned integers, and a value. The TX request is header 0x80 with a TID, command 3 SET, property 0x71 STREAM_RAW, a 2-octet length, the PSDU in amber, and a 16-octet trailer, magnified: channel 0, max CSMA backoffs from the PIB, max frame retries per frame, CSMA-CA enabled 1, three flags at 0, two 4-octet delays at 0 and an RX channel after TX of 0. The RX notification is header 0x80 with TID 0, command 6 VALUE_IS, property 0x71, length, the PSDU in amber and 26 octets of metadata, magnified: RSSI, noise floor, MD_FLAG, then MD_PHY (length, channel, LQI, an 8-octet timestamp), MD_VEND (length, RX error) and MD_MAC (length, ack key id, a 4-octet ack frame counter), each labelled with whether the host keeps, drops or only counts it. Whether the PSDU carries its FCS depends on the firmware's dialect.](../images/wire.png)

*Figure 1: what crosses the serial line.*
HDLC around Spinel, and the two `STREAM_RAW` values that carry an 802.15.4 frame each way, the PSDU in amber; the trailer's and the metadata's octets are drawn to scale, with what this stack writes or does with each.
The generator reads every width and the escape set from `src/rcp/`; source: `tools/diagrams/wire.py`.

| Item | Value | Basis |
| --- | --- | --- |
| Flag | `0x7E` (`FEND`), both ends; a flag both closes the previous frame and opens the next | upstream, measured |
| Escape | `0x7D` + `(byte ^ 0x20)` | upstream, measured |
| Bytes that require escaping | `0x11`, `0x13`, `0x7D`, `0x7E`, `0xF8` | upstream, measured (`0x13` observed as `7D 33`) |
| FCS | reflected CRC-16/X.25: poly `0x8408`, shift right, init `0xFFFF`, on the wire `crc ^ 0xFFFF`, **low byte first** | upstream, measured |
| FCS residue check | running the register over payload+FCS leaves the constant `0xF0B8`: a validity test without splitting the FCS off first. It is the register **before** the final inversion: an implementation that applies `^ 0xFFFF` first reads the same four octets as `0x0F47`, so the two forms differ by exactly the inversion and a check written against the wrong one fails on good frames | upstream, measured |
| Frame maximum | 256 bytes including the 2 FCS bytes | upstream |
| Resync | an unescaped flag discards a partial frame; a frame shorter than the FCS is discarded | upstream |
| Endianness of the HDLC FCS | little-endian; the *Spinel* payload's own multi-byte fields are little-endian except where a property type says otherwise (e.g. `E` addresses are big-endian on some firmwares: `docs/internals/hardware.md` §5) | measured |

Older Spinel prose describes an unreflected FCS; implementations here use the reflected one.

Two things a decoder has to decide that the framing table does not say:

| Case | Behaviour a decoder needs | Basis |
| --- | --- | --- |
| The same mid-frame tail arriving after a completed frame | a flag had already opened the next frame, so the run is a partial frame and closing it is one counted drop. `port_conb2_raw.hex` decoded alone discards nothing; the same bytes arriving behind an answer frame discard one. Both readings are asserted, each in the suite that produces them | measured |
| A stream that begins mid-frame | ignore octets before the first flag: they are the tail of a frame whose opening flag was missed, not a corrupt frame. `port_conb2_raw.hex` begins with 19 such octets; treating them as a frame reports a bad FCS that never happened | measured |
| Two flags in a row, or a closing flag followed by the opening flag of the next frame | close nothing and open nothing: a frame is only a frame if it collected something between flags, otherwise every well-formed stream manufactures one discard per frame | measured |

Both are visible in the recorded transcripts: decoded with these rules the three raw transcripts yield 39, 7 and 49 frames with **zero** discards, which is what the harness reports from the same bytes.

## 3. Spinel frame header

```
byte 0  bit 7    flag            always 1 on this firmware family
        bit 6    reserved        0
        bits 5-4 IID             0 in use
        bits 3-0 TID             transaction id
byte 1  command                 packed uint
byte 2+ property id + value     packed uints and typed values
```

- **Direction is not encoded in the header.**
  A command, a reply and an unsolicited notification all use flag byte `0x80`.
  Branch on the command byte.
- `PROP_VALUE_IS` (`6`) carries notifications *and* GET responses; `PROP_VALUE_INSERTED` (`7`) / `PROP_VALUE_REMOVED` (`8`) are the replies to INSERT/REMOVE.
- Bits 7:6 are one field and carry `0b10` on this family, so a legal header octet is `0x80`..`0xBF`.
  A header outside that range is not a frame from these firmwares and is rejected before a command byte is looked at.

## 4. Integers

Every command id, property id and list element ≥ `0x80` is a **packed uint**: 7-bit groups, least-significant group first, bit 7 = continuation.
`128 → 80 01`, `0xB0 → B0 01`, `0x1008 → 88 20`, `0x120B → 8B 24`.

Sending such an id as a single raw byte is a wire error, not an unsupported property: the decoder sees a continuation bit, runs off the end of the frame and answers `LAST_STATUS(PARSE_ERROR)`.

Typed values follow the Spinel type letters (`C` u8, `c` i8, `S` u16 LE, `s` i16, `L` u32, `l` i32, `X` u64, `x` i64, `i` packed uint, `U` zero-terminated utf8, `b` bool one octet, `E` EUI-64, `D` data and `@` struct: both **uint16 LE length prefix then fields**), little-endian except where a property says otherwise (`docs/internals/hardware.md` §5).

A packed uint covers a **32-bit** value: at most five groups.
A sixth group, or a fifth group that would need bits above 31 (`ff ff ff ff 10`), is not a value and is a parse failure: the reference truncates that case silently, which is a defect this stack does not inherit.
A *redundant* continuation byte (`80 00` for zero) decodes to an unambiguous value and is accepted, because a decoder that rejects it rejects frames the RCPs accept.
**upstream**; see §10 for what is still unknown about what firmwares emit.

## 5. TID discipline and reset reporting

| Rule | Effect | Basis |
| --- | --- | --- |
| TID 0 on a GET/SET | the command is processed, **no response is queued** | upstream, measured |
| TIDs are expected in increasing order | an out-of-order TID marks the previous queued reply as superseded | upstream |
| Repeating one TID across several commands | replies overwrite each other; only the last is delivered | measured (a harness bug that looked like missing property support) |
| TID wraps 15 → 1 on this family | none | upstream |
| `RESET` may carry a reset-type payload (e.g. `2` = "stack") | accepted; OpenThread treats it as a stack reset, DSPINEL parses and ignores it | upstream |
| A `RESET` that carries a TID | the answer is still the unsolicited `LAST_STATUS` with `TID 0`: the TID is not echoed. A host that wants a silent RCP to be distinguishable from a rearming one therefore has to bound the wait itself | measured |
| Post-reset notification | OpenThread-family firmware sends `LAST_STATUS 112 RESET_POWER_ON`; DSPINEL sends `114 RESET_SOFTWARE` **only** in response to `RESET` and sends nothing at power-on | measured, upstream |

A TID-bearing frame is the only way to get a reply: `0x80 | tid`, `tid` in 1..15.

## 6. Bring-up and arming

```
flush:      write a single 0x7E
probe:      GET PROTOCOL_VERSION, NCP_VERSION, INTERFACE_TYPE,
            RCP_API_VERSION, RCP_MIN_HOST_API_VERSION, CAPS, RADIO_CAPS,
            HWADDR                       (the factory EUI-64, read and never written)
reset:      RESET (TID 0)                      -> unsolicited LAST_STATUS
radio on:   SET PHY_ENABLED = 1               -> installs the receive callback
channel:    SET PHY_CHAN = <11..26>
mode:       SET MAC_PROMISCUOUS_MODE = 2      (0 off, 1 network, 2 full)
identity:   SET MAC_15_4_SADDR, MAC_15_4_PANID, MAC_15_4_LADDR
arm rx:     SET MAC_RAW_STREAM_ENABLED = 1    -> starts receive
verify:     GET PHY_CHAN / MAC_PROMISCUOUS_MODE / PHY_ENABLED
```

Sniffer variant: `PHY_ENABLED → PHY_CHAN → MAC_PROMISCUOUS_MODE → MAC_RX_ON_WHEN_IDLE → MAC_RAW_STREAM_ENABLED`.
Coordinator variant additionally sets `LADDR`/`SADDR`/`PANID` before arming, and reads `PHY_TX_POWER`, `PHY_RSSI`, `PHY_RX_SENSITIVITY`, `PHY_CCA_THRESHOLD` for telemetry.

`LADDR` is the operational long address and eight octets in **address order** (most significant octet first, the order `HWADDR` answers in) while `Radio_Pib.extendedAddress` is the MAC's own LSB-first order (octet *i* is bits *i*×8).
Every `'E'` field therefore crosses the seam reversed, in both directions, and the adapter does the reversing: the PIB stays LSB-first and the wire stays MSB-first.
The family accepts the write with no guard and no persistence, so the address is written every session, and the factory EUI-64 is `HWADDR` (`0x08`), read-only and never written.

The two are one duty with two halves, and a host owes both: `HWADDR` is *read* (the device's own, never written) and `LADDR` is *written* from it, because the family has no persistence and an RCP that was given neither transmits nothing but a source field of eight zero octets.
A host that reads the first and skips the second has a device whose frames name an address nobody was given, and a receiver with no long address of its own then cannot tell such a frame from its own echo.
Band B's report names the operational address only after this host wrote it, on the same rule as the CCA threshold.

**Teardown order matters**: clear `MAC_PROMISCUOUS_MODE`, then `PHY_ENABLED`, then `MAC_RAW_STREAM_ENABLED`.
Turning the raw stream off first answers `BUSY` on some firmware.

On the build that carries `MAC_RX_ON_WHEN_IDLE` those three leave it set, so that dialect's sequence clears it second (while the phy is still on) and keeps the raw stream last: a close that wrote only the three left an RCP with its radio off and still idling.

Promiscuous mode bypasses destination-address filtering; it does not make the RCP inert: the radio ACKs frames addressed to its own `SADDR` (`docs/internals/hardware.md` §5), so a sniffer holds an unused short address.

## 7. Properties

### 7.1 Implemented by the OpenThread 2.3.2 radio build (a ConBee III's former firmware)

Base/PHY/MAC/STREAM properties of the radio build, plus `RCP_API_VERSION (0xB0)`, `RCP_MIN_HOST_API_VERSION (0xB1)`, `RCP_TIMESTAMP (0x802)`, `RCP_CSL_ACCURACY (0x804)`, `RADIO_CAPS (0x120B)`, `PHY_CHAN_SUPPORTED (0x22)`, scan properties `0x30..0x33`.
`UNSOL_UPDATE_FILTER (0x1008)` exists as a property but its **GET and SET handlers are compiled only for MTD/FTD builds**: on a radio build they answer `PROP_NOT_FOUND`, while **INSERT and REMOVE are compiled and work**.
Filtering is therefore reachable only as `INSERT 0x1008: <filterable prop ids>` / `REMOVE 0x1008: …`, and only for properties marked filterable in the NCP's changed-props table.

### 7.2 Implemented by DSPINEL (ConBee II)

A GET sweep on a ConBee II after a plain reset.
Every request was answered; none timed out.
The sweep read Phoscon RCP at the revision that predates the scan family; §7.4 reads the current one.

| GET answers a value | Reply | Value as read |
| --- | --- | --- |
| `0x00 LAST_STATUS` | value | reached by notification, not by GET, on this build |
| `0x02 NCP_VERSION` | value | version string, zero-terminated |
| `0x08 HWADDR` | 8 octets | the dresden OUI `00 21 2e` first, address order |
| `0x21 PHY_CHAN` | value | `0` after a reset: the channel **must** be written before receive works |
| `0x24 PHY_CCA_THRESHOLD` | value | −71 dBm default |
| `0x25 PHY_TX_POWER` | value | `0` dBm |
| `0x26 PHY_RSSI` | value | `0x80` = −128 dBm: the "unknown" sentinel, not a measurement |
| `0x27 PHY_RX_SENSITIVITY` | value | `0xa0` = −96 dBm, the AT86RF233 figure read off the RCP |
| `0x34 MAC_15_4_LADDR` | 8 octets | `00 00 00 00 00 00 00 00` after a reset: the operational long address, writable and never persisted, so a host writes it every session |
| `0x3B MAC_RX_ON_WHEN_IDLE` | value | `0` after a reset |
| `0xB0 RCP_API_VERSION` | packed uint | `4` |
| `0xB1 RCP_MIN_HOST_API_VERSION` | packed uint | `4` |
| `0xB3` | value | `0`; upstream defines nothing at this id (its RCP group ends at `0xB2 RCP_LOG_CRASH_DUMP`), so this id belonged to the firmware on this RCP, and Phoscon RCP 0.1.0 refuses it (§7.4) |
| `0x120B RADIO_CAPS` | packed uint | `0x10d`, OpenThread's bit positions (`docs/internals/hardware.md` §4) |

| GET answers `PROP_NOT_FOUND` | What that removes |
| --- | --- |
| `0x04`, `0x06` | no vendor id, no interface count |
| `0x22 PHY_CHAN_SUPPORTED` | the supported-channel list is **not** discoverable on this build; band B takes it from the 802.15.4 OIB instead (`docs/internals/decisions.md` decision 29) |
| `0x23 PHY_FREQ` | no frequency read-out, channel only |
| `0x30`..`0x33`, `0x39` | no scan state, mask, period, beacon result or energy-scan result |
| `0x3A MAC_DATA_POLL_PERIOD` | a sleepy host's poll period is the host's own business |
| `0x1008`, `0x1009` | no unsolicited-update filter or list: every notification this build sends, it sends |
| `0x802`, `0x804` | no RCP timestamp or CSL accuracy |

`GET 0x71 STREAM_RAW` answers `PROP_NOT_FOUND`: the raw stream is not a table property on this build, it is handled specially, the value arrives as a notification and is written as a SET.

The ids `0x01` `0x03` `0x05` `0x20` `0x34` `0x35` `0x36` `0x37` `0x38` are answered as well (`docs/internals/hardware.md` §3); the sweep above lists only what was re-read for this table.

### 7.3 Unanswered-by-design responses

| Reply | Meaning |
| --- | --- |
| `LAST_STATUS(PROP_NOT_FOUND)` (13) | the property is not in this build's table |
| `LAST_STATUS(PARSE_ERROR)` (9) | malformed frame or a bad packed-uint: a *host* error |
| `LAST_STATUS(INVALID_ARGUMENT)` (3) | well-formed but rejected (e.g. filtering a non-filterable property) |
| `LAST_STATUS(INVALID_STATE)` (4) | valid command in the wrong radio state (e.g. TX with the raw stream off) |
| `LAST_STATUS(BUSY)` (12) | an operation is already running (e.g. TX in flight, or wrong teardown order) |
| a refusal band B causes itself | no room for another transaction at the seam call: the write queue is full or the transmit track is full. A frame does not refuse for the one Spinel request outstanding (§5) or for a PIB write ahead of it; it waits its turn (D-263). It answers `ZB_ERR_NO_SPACE`, this seam's name for IEEE 7.2.4's `TRANSACTION_OVERFLOW`, and band A re-asks a unicast refused that way (D-167), holds a broadcast (D-243) and holds an association request (D-222). `ZB_ERR_BUSY` is kept for what the device answered **spec, decision** |
| a frame the wire never took | the frame was accepted and waited `RCP_RADIO_TX_WAIT_MS` in line, so `ZB_ERR_NO_SPACE` arrives in its completion, not at the seam call (D-263). Band A retries a unicast and charges no neighbour; it confirms a broadcast and fails an association request at once, because neither of the holds above sees a completion. A broadcast's passive-acknowledgment wait starts when the frame is accepted, so a frame in line spends part of it there **decision** |
| `LAST_STATUS(NO_ACK)` (17) | a transmit that asked to be acknowledged was not: measured on a rig transmit whose peer was armed promiscuous rather than addressed |
| `LAST_STATUS(CCA_FAILURE)` (18) | the radio's CCA found the channel busy and sent nothing. Band B names it `ZB_ERR_CHANNEL_ACCESS_FAILURE`, 8.2.2's status, and 3.2.1.1.3 owes a unicast the same retries as a NO_ACK (D-167). Seen on a ConBee II whose firmware ran the CCA at the reset threshold |
| `ZB_ERR_NO_ROUTE` (14) | band A's name for R23.1 3.6.4.3's `ROUTE_ERROR`, a status of this stack's own with no radio reply behind it: the answer a device gives when it has no path, discarded at a relay, confirmed to its own originator. `Nwk_DataConfirmParameters` carries both vocabularies of the same outcome: the seam status a caller matches on, and Table 3-84's `ROUTE_ERROR` value `0xd1` in `nwkStatus`. A relay with no entry discards this way unless the frame asks for discovery from its own end device child (D-265); an APS unicast no longer reaches it, because 2.2.8.4.1 makes the sub-layer ask for a route and 3.6.4.5.1 runs instead (R23.1 2.2.8.4.1, D-165) **spec, mandate** |
| `ZB_ERR_BAD_FRAME_COUNTER` (15) | a status with no radio reply behind it as well, and the reason word band A uses for all three frame-counter refusals: 4.3.1.1 step 1 (the outgoing counter of the active descriptor at `2^32-1`), 4.3.1.2 step 1 (a received count of `2^32-1`, the one failure in that procedure the corpus gives no status for) and 4.3.1.2 step 3 (a count the sender's stored window has already used, 'bad frame counter'). Outgoing, it reaches its originator with Table 3-84's `MAX_FRM_COUNTER` `0xcc` beside the seam status on `Nwk_DataConfirmParameters.nwkStatus`; `NO_KEY` `0xcd` and `BAD_CCM_OUTPUT` `0xce` travel from the same crossing for the other two refusals `Security_Protect` answers with, while a `NO_SPACE` for a secured frame over the band's ceiling deliberately carries no NWK code, the mapping being the one helper `Nwk_TxConfirmStatus` in `src/zb/nwk/nwk_tx.c` (`docs/internals/decisions.md` decision 53(ix)). Incoming, it names a discard with nothing above it: no `NLDE-DATA.indication`, no confirmation, a counter only **decision, spec** |
| `ZB_ERR_NOT_FOUND` (16) | the discovery table holds no parent for the extended PAN a join asked for: R23.1 3.6.1.6.1.1's NOT_PERMITTED as a status of this stack's own, with no radio reply behind it. The application fills Table 3-74's pool through `Nwk_JoinParentAdd`; a join naming a network nobody put there is refused at the door and no exchange starts (`docs/internals/decisions.md` R23.1 3.6.1.6.1) **spec, mandate** |
| `ZB_ERR_BAD_STATE` (17) | the request is not one this device may make now: 3.6.1.6.1.1's INV_REQUESTTYPE for a join by a device that already holds a short address, and for the coordinator, which has no parent. The number coincides with the Spinel reply `17` above and is a different namespace: the seam's `ZbStatus` is the one the parameter carries, the Spinel code is the device's (`docs/internals/decisions.md` R23.1 3.6.1.6.1) **spec, mandate** |

Status codes measured: `0 OK`, `3`, `4`, `9`, `12`, `13`, `17`, `18`, `112`, `114`.
17 is `SPINEL_STATUS_NO_ACK` upstream and 18 is `CCA_FAILURE`; band B names both (`ZB_ERR_NO_ACK`, `ZB_ERR_CHANNEL_ACCESS_FAILURE`) and folds every other code into `ZB_ERR_DEVICE`, keeping the code readable, because a run that cannot tell "not acknowledged" from "failed" has measured nothing.

### 7.4 Implemented by the current revision of Phoscon RCP (`DSPINEL` 1.0)

Every supported device runs Phoscon RCP, driven over this repository's own Spinel codec (`docs/internals/hardware.md` §1).
`GET NCP_VERSION` answers `DSPINEL/1.0; AT86RF233`, `RCP_API_VERSION` and `RCP_MIN_HOST_API_VERSION` answer `4`, and `CAPS` lists 34, 64, 65, 67, 513: **octet for octet what the same build answered at the revision §7.2 read**.
The name carries no revision, and the table moved under it: `RADIO_CAPS` gained a bit and the scan group went from refused to answered.
Nothing about a build's surface may therefore be inferred from its name or from what was measured last.

| GET | the revision §7.2 read | the current revision |
| --- | --- | --- |
| `0x30 MAC_SCAN_STATE` | `PROP_NOT_FOUND` | `c`: `00` idle, `02` while a dwell runs |
| `0x31 MAC_SCAN_MASK` | `PROP_NOT_FOUND` | count + `c`… list: `10 0b 0c … 1a` after a reset; a write of `01 0c` reads back `01 0c` |
| `0x32 MAC_SCAN_PERIOD` | `PROP_NOT_FOUND` | `S` little-endian: `c8 00` (200) after a reset, `e8 03` after that write |
| `0x33 MAC_SCAN_BEACON` | `PROP_NOT_FOUND` | `PROP_NOT_FOUND`: an event id, not a property |
| `0x39 MAC_ENERGY_SCAN_RESULT` | `PROP_NOT_FOUND` | `PROP_NOT_FOUND` on GET; arrives only as a notification (§7.4.1) |
| `0x3C MAC_15_4_ALT_SADDR` | not probed | `PROP_NOT_FOUND`: no alternate short address is offered; the address a peer aims at is `0x35 MAC_15_4_SADDR` and nothing else |
| `0x3D MAC_RX_AT` | not probed | `PROP_NOT_FOUND`: no scheduled receive window, so a timed RX is not reachable on this build, whose `RADIO_CAPS` carries no RECEIVE_TIMING bit (`docs/internals/hardware.md` §4) |
| `0x3E`, `0x3F` | not probed | `PROP_NOT_FOUND`: the upstream MAC group ends at `0x3D`, and this build answers nothing in the gap before `0x40`. No id in that gap reports an acknowledgment either: nothing this build answers carries a received Ack's octets (§10 question 11) |
| `0xB2 RCP_LOG_CRASH_DUMP` | not probed | `u8`: `00` after a reset on Phoscon RCP 0.2.0, the stream off until a host writes `01`; `01` on an earlier revision, the stream on by default |
| `0x1303` `MAC_SRC_MATCH_ENABLED` | `PROP_NOT_FOUND` | `b`: `00` after a reset, and a write reads back (§7.4.5) |
| `0x1304` `MAC_SRC_MATCH_SHORT_ADDRESSES` | `PROP_NOT_FOUND` | `A(S)`: empty after a reset, replaced whole by a write, and patchable by INSERT and REMOVE (§7.4.5) |
| `0x1305` `MAC_SRC_MATCH_EXTENDED_ADDRESSES` | `PROP_NOT_FOUND` | `A(E)`: the same shape for the eight-octet forms, in `MAC_15_4_LADDR`'s byte order (§7.4.5) |
| `0xB3` | value `0` | `PROP_NOT_FOUND` since Phoscon RCP 0.1.0, value `0` before it: a diagnostic gate at an id upstream leaves undefined, which the stack never read |
| `RADIO_CAPS` (`0x120B`) | `0x10d` | `0x10f`, ENERGY_SCAN (bit 1) added, then `0x16f` since Phoscon RCP 0.1.0 (`docs/internals/hardware.md` §4) |

Every refusal §7.2 lists stays refused on this build (`0x04`, `0x06`, `0x23`, `0x3A`, `0x1008`, `0x1009` and a GET of `0x71`) as do `0x33` and `0x39`; `0x22` answers the channels 11 to 26 on Phoscon RCP 0.2.0, and band B still takes the list from the OIB (D-29).
The four ids probed since, `0x3C`..`0x3F`, are refused too.
Band B therefore asks the device instead of reading the name: the scan surface is known by whether `0x30` answers (`docs/internals/decisions.md` D-123).
**measured, and re-read at this revision**

#### 7.4.1 The energy dwell

One channel per dwell, one level per dwell, no transmission anywhere in the dialog.
Armed as §6 arms (`PHY_ENABLED` 1, `PHY_CHAN` 12, `MAC_RAW_STREAM_ENABLED` 1), narrowed to one channel, period 200:

| host writes | RCP answers | host-clock delay |
| --- | --- | --- |
| `SET 0x31 = 01 0c` | `81 06 31 01 0c`: the write echoed | +11 ms |
| `SET 0x32 = c8 00` | `82 06 32 c8 00` | +11 ms |
| `SET 0x30 = 02` | `81 06 30 02`: accepted, with the request's own TID | +11 ms |
| | `80 06 39 0c a2`, unsolicited TID 0: channel `0x0c`, level `0xa2` = −94 dBm | +343 ms |
| | `80 06 30 00`, unsolicited TID 0: the dwell is over | +343 ms |

`0x39` carries two `c`: the channel number, then the level as a signed octet.
`+127` is the marker for "nothing usable was measured here", and a disarm reports it rather than leaving a host in its own timeout.
A quiet channel reports −94, the floor `docs/internals/hardware.md` §7 already names.

**A dwell is refused before anything is asked of the radio.**
`SET 0x30 = 02` with `PHY_ENABLED` 0 answers `LAST_STATUS 4 INVALID_STATE`, and answers it ahead of any judgement of the mask: the same refusal came back for a stored 16-channel mask the RCP had accepted and echoed verbatim, so a write that stored says nothing about whether a dwell will start on what was stored.

**A dwell outlives the period it was asked for, in the host's clock.**
The 200 ms period produced its result at +343, +501 and +505 ms over three runs on channels 12, 26 and 15; a 1000 ms period produced its result at +2128 ms.
The board's millisecond is not the host's, so a host that budgets `period + slack` budgets less than the dwell takes.

#### 7.4.2 Notifications are dispatched by id, not by assumption

On a revision whose `0xB2` stream is on after a reset, unsolicited record notifications arrive from the moment the port opens (before the first command is written) one or two riding in the chunk with each scan frame, and once as a 400-octet batch whose payload carries the RCP's own EUI-64 and its serial as record words.
On Phoscon RCP 0.2.0 they arrive only once a host writes `01` (§7.4).
A `VALUE_IS` on an id that is not `0x71` is never a PSDU: band B routes by property id and discards what it does not consume, and a reader that treats any notification as traffic loses frames to it.

#### 7.4.3 What each write answers (the current revision)

Every accepted write is confirmed by a `PROP_VALUE_IS` carrying the request's TID and the value written; every refusal is a `PROP_VALUE_IS LAST_STATUS <code>` carrying that TID, and in every refusal the property reads unchanged afterwards.

| the host writes | the RCP answers | what that establishes |
| --- | --- | --- |
| `SET PHY_CHAN = 0a`, `SET PHY_CHAN = 1b` | `3 INVALID_ARG` | the channel is range-checked **at the write**, and `0x21` keeps its old value |
| `SET PHY_CCA_THRESHOLD = b0`, `= 7f` | the value echoed; `+127` accepted | the threshold is writable, and is **not** range-checked: a dBm figure no radio can hold is stored |
| `SET PHY_TX_POWER = 02` | the value echoed | transmit power is writable on this build |
| `SET MAC_PROMISCUOUS_MODE = 03` | `3 INVALID_ARG` | the mode is range-checked |
| `SET MAC_SCAN_STATE = 01`, `= 03` | `2 UNIMPLEMENTED` | the beacon and network kinds are refused as §7.4.1 says |
| `SET MAC_SCAN_MASK = 02 0c 0d` | the value echoed | a mask naming **two** channels stores |
| then `SET MAC_SCAN_STATE = 02` | `3 INVALID_ARG`, no `0x39`, no completion | a dwell is refused for that mask at the start, so storage is not permission |
| `SET MAC_SCAN_MASK = 01 1b` then a start | echoed, then `3 INVALID_ARG` | a channel outside 11..26 stores and is refused only when a dwell is asked to begin on it |
| `SET MAC_SCAN_MASK = 03 0c` | `3 INVALID_ARG`, mask reads back unchanged | a count byte that does not match its list is refused whole |
| `SET MAC_SCAN_PERIOD = 0000`, then a dwell | `0x39` with `7f` at +16 ms, `0x30 00` at +21 ms | a zero period ends the dwell with **no reading**, and reports that as `+127` rather than as a refusal |
| `SET MAC_SCAN_PERIOD = 1027` (10000) stored, then a dwell | stored verbatim; `0x39` at +2239 ms, `0x30 00` at +2243 ms | the period is bounded **where it is used**, not where it is written, and the bound is about 1000 board milliseconds (§7.4.1) |
| `SET MAC_SCAN_STATE = 00` while a dwell runs | `VALUE_IS 0x30 = 02`: the state, not the value written | a disarm is accepted, answers "still running", and the dwell finishes on its own schedule with its own level |


#### 7.4.4 What an answer says about a property

A dialect's table records what a build may be asked about, measured at one revision of it.
What the device on the port answered is a separate record, because only one answer speaks about the device: `PROP_NOT_FOUND` says the id is not in this build.
A refusal of another kind (`INVALID_STATE`, `INVALID_ARGS`) says something about the ask, not about whether the device knows the property, and recording it as absence would turn a bad request into a statement about the hardware.
A property nobody asked about has no answer, and "no answer" is not "absent": a table that lists a property and a session that never asked about it leave the question open, which is the state band B must report rather than resolve by guessing.
**spec (§8.8.19), measured**

#### 7.4.5 The source-match family and the Ack's Frame Pending bit

The three ids are upstream's `SPINEL_PROP_MAC_EXT__BEGIN` + 3, + 4 and + 5, and their wire shapes are upstream's: a `b` that says whether the table decides the answer, and two lists of concatenated addresses with no count prefix, `A(S)` little-endian and `A(E)` in the byte order `MAC_15_4_LADDR` uses.
A list is replaced whole and refused whole: a list that does not fit answers `NOMEM` and leaves the table as it was, because a partial list claims "nothing queued" for the addresses a host believes it wrote.
`INSERT` and `REMOVE` carry one entry and answer `VALUE_INSERTED`/`VALUE_REMOVED`; a `REMOVE` of an absent entry answers `ITEM_NOT_FOUND`.
`RESET` clears both lists and the enable bit.
**measured at this revision**

What the radio does with it is the firmware's own table, and it is not restated here: Phoscon RCP's `docs/protocol.md` §10.2 states the table's semantics, and Phoscon RCP's `docs/ack-pending-frame.md` prints the Frame Pending decision for every received frame and how each radio composes the Ack (§5 on the AT86RF233 and ATmega256RFR2, §7 on the ConBee III).
The one sentence this stack depends on: with the enable bit clear, every Ack to a Data Request carries Frame Pending one, which is 802.15.4-2024 10.22.3's fallback for a coordinator that cannot know.

Band B states the table as one three-write statement, in this order and one write per pump: `0x1303`, then `0x1304`, then `0x1305` (`docs/internals/conformance.md` §1, `docs/internals/decisions.md` D-157).
It writes the statement at adoption, on every move of band A's transaction queue, and again after a reset, because the device forgot it.
`MD_FLAG` bit 4 (`SPINEL_MD_FLAG_ACKED_FP`, `0x0010`) is set on a delivered frame whose Ack this radio sent with Frame Pending one: it is the only report a host gets of an Ack it never sees, and it is what a coordinator reads to know a child was told more is held.

## 8. `STREAM_RAW`: the data path

### 8.1 RCP → host: RX notification

Unsolicited `VALUE_IS` on property `0x71`, header TID 0.
Layout after the property id (identical on both firmwares; OpenThread calls it `PackRadioFrame`):

```
u16 LE  psdu length            (0 for an RX error)
..      PSDU
i8      RSSI dBm
i8      noise floor (always -128; unused)
u16 LE  MD_FLAG
struct  MD_PHY   (u16 LE length = 10): u8 channel, u8 LQI, u64 LE timestamp (device ticks)
struct  MD_VEND  (u16 LE length = 1):  packed uint RX error
struct  MD_MAC   (u16 LE length = 5):  u8 ack key id, u32 LE ack frame counter
```

After the PSDU the fixed part is **26** octets: RSSI, noise, MD_FLAG and the three length-prefixed groups (2+10, 2+1, 2+5).
Counting the length prefix in front of the PSDU, the value is 28 octets of framing around the frame itself.
The value ends at MD_MAC: nothing follows it in any captured frame.

`MD_FLAG` bits: `0x0001` TX (never set in an RX notification), `0x0004` **BAD_FCS**, the AT86RF233 build flags FCS-invalid frames rather than silently passing them, `0x0008` DUPE (defined, never set here).

Every field of the three raw transcripts (`test/fixtures/port_conb2*_raw.hex`), read through the codec:

| Field | What the captured notifications carry | Basis |
| --- | --- | --- |
| header | TID 0 (unsolicited), IID 0, flag bits `0b10`, command `6`, property `0x71` on all 39 / 7 / 49 frames | measured |
| noise floor | `-128` in every frame: the field is present and unused | measured |
| LQI | 0..255, with 255 dominant (34/39, 6/7, 31/49) | measured |
| RSSI | −94..−76 across these captures | measured |
| MD_VEND payload | the packed uint `0`: no RX error recorded | measured |
| MD_MAC payload | all five octets zero: the radio records no acknowledgment on receive, and it records none on the transmission it hands back either | measured |
| MD_PHY timestamp | the device's own clock in the device's own unit: named microseconds upstream, measured at ≈2.37 µs per tick on the AT86RF233 build; quantised to 1000-tick steps (≈2.4 ms), never decreasing, equal values possible | measured |
| MD_FLAG | `0` or `0x0004` only; `0x0004` on 11 of the 49 frames of one transcript and on none of the others | measured |

### 8.2 Host → RCP: TX request

`SET 0x71` value: `u16 LE psdu length | PSDU | u8 channel (0 = keep) | u8 maxCsmaBackoffs | u8 maxFrameRetries | b csmaCaEnabled | b isHeaderUpdated | b isRetransmission | b isSecurityProcessed | u32 LE txDelay | u32 LE txDelayBase | u8 rxChannelAfterTx`.

| Point | OpenThread build | DSPINEL build |
| --- | --- | --- |
| fields after the channel | optional; absent fields take defaults | **mandatory**: a short value answers `PARSE_ERROR`. The trailer is exactly 16 bytes |
| FCS inside the PSDU | host supplies the frame without FCS; the radio validates and strips it on RX | **the PSDU carries its own 2 FCS octets in both directions, and the radio regenerates them rather than appending**, so the length includes them (the normative MPDU includes its footer: §9.3; `docs/internals/hardware.md` §3) |
| acceptance | no immediate answer; completion is deferred | same |
| refusal | `INVALID_STATE` (raw stream off), `NO_BUFS` | `INVALID_STATE`, `BUSY`, `PARSE_ERROR` |

Consequence: one TX encoder, always emitting the full 16-byte trailer, with a per-device "psdu includes FCS" flag.
`maxFrameRetries` is the frame's own count from the seam: macMaxFrameRetries for a direct frame that asks for an acknowledgment, 0 for any other; `maxCsmaBackoffs` 0 is the firmware's default (D-232).
Both are encoded in the harness and both are asserted by its regression checks.
The DSPINEL row is what that flag means, and band B sets it from the dialect `NCP_VERSION` names (`psduIncludesFcs`).

"Carries its own FCS" is a statement about length, not about authorship.
A transmit whose footer octets were corrupted reached the peer with the footer the frame computes for itself, not the one the host wrote, and the peer's own check called it valid: this build recomputes the footer rather than using the host's octets, while still requiring a PSDU long enough to contain one.

### 8.3 TX completion

Asynchronous `VALUE_IS LAST_STATUS` whose header carries **the requesting TID**:

```
packed uint status
bool framePending
bool headerUpdated
[ the ACK frame, in §8.1 form ]          when status is OK
[u8 key id, u32 frame counter]            when the frame was secured and headerUpdated
```

A completion that never arrives means the radio is stuck or the RCP reset; a session must time it out and re-arm (§5).
`Zb_Stack` allows 1000 ms for any request, then resets the RCP and ends every frame in its track with `ZB_ERR_TIMEOUT` (D-264).

Measured on the AT86RF233 build: the completion arrives carrying **the requesting TID** (a bring-up plus one transmit is thirteen transactions, twelve of them answered by TID) 14 to 21 ms after the request, with `0 OK` when the radio's own acknowledgment exchange succeeded and `17 NO_ACK` when it did not.
No acknowledgment frame is delivered (§10 question 11), but `framePending` is the Frame Pending bit of the acknowledgment the radio heard: a poller's completion read one whenever the parent's Ack said pending and zero when it did not.
The seam carries it as `Radio_TxResult.framePending`, with `framePendingReported` saying the completion had the two bits at all.

## 9. 802.15.4 / Zigbee framing

![One secured Zigbee data frame as five nested byte strips, each row the magnified payload of the row above. The PHY row has the radio's own SHR and PHR, hatched, never sent over the serial line, then the PSDU of at most 127 octets. The MAC row has frame control (2), sequence (1), destination PAN (2), destination and source short addresses (2 each), no source PAN because of PAN ID compression, the NPDU and a 2-octet FCS. The NWK row has frame control (2), destination (2), source (2), radius (1), sequence (1) and optional IEEE addresses and source route; then the 14-octet auxiliary security header: control (1, its level bits zero on the air), frame counter (4), sender EUI-64 (8) and key sequence (1); then the encrypted payload in amber and a 4-octet MIC. Brackets mark the headers as authenticated but sent in clear, the CCM* a-data with the control octet's level put back, the payload as encrypted, and the MIC as the tag. The payload in clear is an APS frame: frame control (1), destination endpoint (1), cluster (2), profile (2), source endpoint (1), APS counter (1) and the ASDU. One form of the ASDU is a ZCL frame: frame control (1), an optional manufacturer code (2), transaction sequence (1), command (1, here 0x00, read attributes) and attribute identifiers.](../images/nesting.png)

*Figure 2: one Zigbee frame, layer inside layer.*
The NWK layer encrypts its payload, in amber, and authenticates it together with the headers in front of it; the security level is restored for the a-data but sent as 0 on the air.
The generator reads every width from `src/zb/`; source: `tools/diagrams/nesting.py`.

### 9.1 Frame Control layout

The layout is confirmed by the active standard: IEEE 802.15.4-2024 7.2.2, Figure 7-2 (subfields 7.2.2.2 … 7.2.2.11) is **bit-for-bit the 802.15.4-2006 Figure 42 layout** that Zigbee inherited, with bits 8 and 9 named.
802.15.4-2024 is the compilation of 802.15.4-2020, the revision Zigbee R23.1 references normatively, so it is the citation of record here; the 802.15.4-2006 clause numbers are kept where they are the only source of a fact.

```
bits 0-2   frame type        0 beacon, 1 data, 2 ack (Imm-Ack/Enh-Ack), 3 MAC command
                            4 reserved, 5 Multipurpose, 6 Fragment, 7 Extended (Table 7-1)
bit  3     security enabled  the auxiliary security header is present iff set
bit  4     frame pending
bit  5     ack requested (AR)
bit  6     PAN id compression
bit  7     reserved          4.6: zero on transmission, ignored on reception
bit  8     sequence number suppression   must be 0 when the version field is 0 or 1
bit  9     IE present                    must be 0 when the version field is 0 or 1
bits 10-11 destination addressing mode   0 none, 2 16-bit, 3 64-bit, 1 reserved (Table 7-3)
bits 12-13 frame version     0 = 802.15.4-2003, 1 = 802.15.4-2006, 2 = this standard, 3 reserved (Table 7-4)
bits 14-15 source addressing mode
```

There is **no AIE bit and no PAN-ID-present field** in this FCF: 802.15.4-2024 defines those names only inside the Multipurpose frame's own MHR (7.3.5, Figure 7-19), a frame type no Zigbee device sends.
A stack that treats bits 8-9 as writable is inventing a field; on every frame captured on the channel-15 test network (version 0) they are zero, as 7.2.2.7 and 7.2.2.8 require.

Field presence (7.2.4 … 7.2.7, the same rules as 802.15.4-2006 7.2.1.3..7.2.1.6): the destination PAN identifier and the destination address exist only if the destination addressing mode is nonzero; the source address only if the source mode is nonzero; the source PAN identifier only if the source mode is nonzero **and** compression is 0.
Security level and key identifier are not FCF fields: they live in the auxiliary security header, Security Control (1 octet: level bits 0-2, key identifier mode bits 3-4), Frame Counter (4 octets), Key Identifier (0/1/5/9 octets).
A frame whose version field is 0 **cannot be MAC-secured at all**: 7.3.2.2 sets Security Enabled only "if security is enabled and the Frame Version field is not zero", and 9.2.4 answers an attempt to unsecure such a frame with `UNSUPPORTED_LEGACY`.
That is the normative reason every frame on the channel-15 test network is unsecured at the MAC layer while encrypted end to end.

That header (7.2.8's field, whose format 9.4 prints; 802.15.4-2006 drew the same header as 7.2.1.7 and 7.6.2) is not modelled in band A: Security Enabled is a flag the codec judges and nothing this stack composes sets, so composition with it set is refused and every frame written is unsecured by construction.
A received frame carrying it is refused as a form this stack has no header for, counted apart from the standard's own refusals and written to the log, rather than parsed as though the auxiliary header were absent.
**spec, measured, open**: MAC-level security is deferred, not dispensed with.

**Zigbee overrides the version field.**
802.15.4-2006 7.2.2 required Frame Version 0b01 whenever the frame was secured **or** the payload exceeded `aMaxMACSafePayloadSize` (102 octets, Table 85), and 7.2.3 named a long unsecured frame as one of only two 802.15.4-2003 incompatibilities.
R23.1 Annex D.6 cancels that for this stack: "When used in a Zigbee platform, the MAC implementation SHALL always set the Frame Version field in unsecured MAC data packets to zero.
The reason for this is to ensure backwards compatibility with existing deployed Zigbee devices".
802.15.4-2024 dropped the whole `aMaxMACPayloadSize` / `aMaxMACSafePayloadSize` constant pair from its MAC constants table, so the IEEE rule it replaced is no longer visible there at all.
Every frame captured on the channel-15 test network carries version 0 with Security Enabled 0: D.6, not an old-firmware artifact.
A provider that follows IEEE's version rule here breaks interoperation with the devices on the network.

**Zigbee also widens the destination form of one command.**
R23.1 Annex D.4 (Table D-1) lists among the options a device "SHALL be recognized" by: the destination PAN and address fields are omitted when the destination is the PAN coordinator.
The standard's filtering is not directly applicable: 6.6.2 d)(3) requires `macImplicitBroadcast` (default FALSE, Table 8-1), and d)(4)'s source-PAN rule fits the poll, whose source PAN is `macPanId` (10.22.5.2), but not the Association Request, whose source PAN is the broadcast 0xffff (10.21.5.1).
R23.1 Annex D.4's Table D-1/D-2 is therefore the form recognized for the Association Request: the source PAN is the broadcast PAN and the source address extended (10.21.5.1), and the MAC's association door accepts it where the device is the PAN coordinator.
The poll's destination-less form is 10.22.5.2's and 6.6.2 d)4's, and the MAC's poll door accepts it only at the PAN coordinator.

Frame forms: data 7.3.2 (Figure 7-14) and MAC command 7.3.4 (Figure 7-17) as `FCF seq [dstPAN] dst [srcPAN] src [aux] payload`; and a Beacon frame (7.3.1, Figure 7-5) at version 0b00/0b01 as `FCF seq(= macBsn) srcPAN src [aux] superframe-spec(2) GTS-info pending-address [beacon payload] FCS`, a beacon addresses *from* itself: the source addressing modes are set, the destination fields are absent, and "all other fields in the Frame Control field shall be set to zero and ignored on reception".
The superframe specification is 16 octet-bits with the final CAP slot inside it (Figure 7-7), not a separate octet as 802.15.4-2006 drew it.
The checked-in channel-15 captures hold data, acknowledgment and command frames only, so a beacon's shape on that network is open question 7; `test/fixtures/conb2_beacon_reply.txt` holds this stack's own.

What Zigbee puts in the beacon payload **is** specified: R23.1 3.6.8 makes the IEEE Beacon Payload a **Zigbee Beacon Info Field of 15 octets** (Protocol ID (always 0, 0xff reserved to the Alliance), stack profile, nwkcProtocolVersion, router capacity, end-device capacity, nwkExtendedPANId, TxOffset, … (Table 3-83)) plus a variable **Beacon Appendix** of TLVs from R23 devices onward, and in an **Enhanced** beacon the Beacon Info Field leaves the payload entirely and travels as a Payload IE (Annex D, Zigbee Payload IE).
That is the structure to confirm against a real capture, and it is what a join-capable stack must read: `nwkExtendedPANId` is how a device tells your network from the neighbour's.

**A discrepancy in R23.1 itself, named rather than inherited.**
Its worked beacon in Annex D (Figure D-3) prints the third octet of the Zigbee Beacon Info Field as `0x88` beside a tabulated Router Capacity 1, Device Depth 0 and End Device Capacity 1; Figure 3-53's bit positions encode that triple as `0x84`.
This stack emits `0x84`, the figure's reading, and `nwk`'s suite pins it; the worked example's byte is not followed.

**Acknowledgment: 7.3.3, and the name matters.**
An **Imm-Ack** (version 0b00 or 0b01, Figure 7-15) is `Frame Control | Sequence Number | FCS` and nothing else, "In an Imm-Ack frame, all other fields in the Frame Control field shall be set to zero", and the AR field of any Ack is zero.
An **Enh-Ack** (version 0b10, Figure 7-16) *does* carry addressing fields, an auxiliary security header and IEs; no frame on the channel-15 test network is one.
Frame Pending on a poll answer is governed by 10.22.3 (a coordinator that cannot immediately answer a Data Request "shall set the Frame Pending field of the Ack frame to one", which is what the measured `0x0012` acknowledgments are) while 7.3.3's general rule for other cases sets it to zero; the two clauses are in tension and 10.22.3 is the one that matches the captures.

The 802.15.4-2003 layout (security enabled bit 4, pending 5, ack 6, PAN compression 7, security level 8-10, key id 11, one-bit addressing modes 12/13, PAN suppression 14/15) is what earlier decoders, zigbee-on-host among them, and this harness used until the captures were checked against IEEE 802.15.4-2024.
For the channel-15 test network's data frames it lands the addressing fields in the right places by coincidence (the mode and suppression bits carry the same values in both readings) while naming them wrongly and failing outright elsewhere: it reads Ack Request one bit high; reports an acknowledgment carrying Frame Pending (`fcf 0x0012`) as a *secured* frame, which five octets cannot hold since an auxiliary security header needs at least five octets of its own; expects a destination PAN in an acknowledgment that has none; and reads Ack Request onto broadcast data frames (`0x8841`, dst `0xffff`) that demonstrably go unacknowledged.
The captures decide it: `0x0002` and `0x0012` are five octets `FCF seq FCS` with exactly the computed CRC in the tail, and the `0x8861` frames that carry bit 5 are the ones followed by an acknowledgment with the matching sequence number.

Zigbee data frames carry MAC security off because encryption happens at the APS sub-layer; the version field is 0 on every frame captured on the channel-15 test network.

### 9.2 Command identity tables

| 802.15.4 MAC command (frame type 3) | Id | Source (Table 7-11 = 802.15.4-2006 Table 82 for 0x01-0x09) |
| --- | --- | --- |
| Association request | 0x01 | 802.15.4-2006 Table 82 |
| Association response | 0x02 | ditto |
| Disassociation notification | 0x03 | ditto |
| **Data request: the beacon-less poll** | **0x04** | ditto |
| PAN id conflict notification | 0x05 | ditto |
| Orphan notification | 0x06 | ditto |
| Beacon request | 0x07 | ditto |
| Coordinator realignment | 0x08 | ditto |
| GTS request | 0x09 | ditto |

`0x0a-0xff` is not simply reserved, and a stack that forwards an unknown command id blindly will collide with IEEE-defined space: 0x0a/0x0b TRLE management request and response, 0x0c-0x12 reserved, 0x13-0x1c DSME (association, GTS, information, beacon allocation and collision, link report), 0x1d-0x1f reserved, 0x20 RIT data request, 0x21/0x22 DBS request and response, 0x23 RIT data response, **0x24 vendor specific** (7.5.5), 0x25-0x28 SRM request/response/report/information, 0x29 ranging verifier, 0x2a ranging prover, 0x2b-0xff reserved.
The only mandatory transceiver coverage is "all MAC commands with Command ID field of values 0x07-0x08" (beacon request, coordinator realignment).
Data Request 0x04 has "a zero-length Content field" (10.22.4.1), which is why a poll on the channel-15 test network is exactly twelve octets.

The association pair's content fields are 10.21.5.1's Figure 10-156 (one octet, the Capability Information field of Figure 10-157) and 10.21.5.2's Figure 10-158 (two octets of short address, least significant first, then Table 10-102's Association Status).
The Capability Information octet is 802.15.4-2024's eight bits: bit 0 reserved, bit 1 Device Type, bit 2 Power Source, bit 3 Receiver On When Idle, bit 4 Association Type, bit 5 Suspendable CSMA-CA, bit 6 Security Capability, bit 7 Allocate Address.
802.15.4-2006's Figure 56 drew the same octet with bit 0 as Alternate PAN Coordinator and bits 4-5 reserved; a frame that sets bit 0 is read as 2024's reserved bit, and a stack that writes an alternate-PAN-coordinator bit there writes a field the citation of record does not have.
Table 10-102's status values are 0x00 association successful, 0x01 PAN at capacity, 0x02 PAN access denied, 0x03 hopping sequence offset duplication, 0x80 fast association successful and 0x81 suspendable CSMA-CA association successful, the rest reserved.
The table contradicts itself at 0x81: it names "Suspendable CSMA-CA association successful" and then prints a reserved band beginning at 0x81; the enumeration is read as naming 0x80 and 0x81 and reserving 0x82-0xff, and this stack's association procedure produces only 0x00-0x02 and refuses the other three.
The transmit door refuses the three capability bits this stack cannot honour (Association Type, Suspendable CSMA-CA, Security Capability), so a request that names them never reaches the air; the codec refuses them too.

Zigbee NWK command frame identifiers (R23.1 Table 3-54): route request `0x01`, route reply `0x02`, network status `0x03`, leave `0x04`, route record `0x05`, rejoin request `0x06`, rejoin response `0x07`, link status `0x08`, network report `0x09`, network update `0x0a`, end device timeout request `0x0b`, end device timeout response `0x0c`, link power delta `0x0d`, network commissioning request `0x0e`, network commissioning response `0x0f`, `0x10-0xff` reserved.

NWK frame types: data `0`, NWK command `1`, inter-PAN `3` (R23.1 3.3.2).

The most frequent frame class on the channel-15 test network (MAC command, payload `0x04`, unsecured, ack-requested, ~every 5 s, destined for `0x0000`) is a **Data Request**: a sleepy end device polling its parent.

MAC status codes sent over the air keep the numeric values of IEEE 802.15.4-2006, and **only 802.15.4-2006 supplies them**: 8.2.2 lists status values symbolically (SUCCESS, CHANNEL_ACCESS_FAILURE, NO_ACK, TRANSACTION_EXPIRED, INVALID_PARAMETER, UNAVAILABLE_KEY, UNSUPPORTED_LEGACY, …) with no numeric table, and Zigbee R23.1 Annex D.2 says the OTA codes "SHALL use the numeric values provided in IEEE Std 802.15.4-2006", that is 802.15.4-2006 Table 78 (7.1.17), where 0x01-0xda is one reserved block for command status and reason codes and 0xdb-0xdf holds the security codes, which is exactly the band Zigbee's `0xA0-0xD0` NWK status values sit inside.
Note one drift: Table 10-102 (association status) and 10-103 (disassociation reason) now occupy `0x80` and `0x81` where 802.15.4-2006 Tables 83/84 reserved `0x80-0xff` for MAC primitive enumeration.

### 9.3 FCS in delivered PSDUs

Normatively there is no ambiguity about where the FCS belongs: it is the MAC footer (MFR) inside the MAC frame (7.2.1, Figures 7-1 and 7-14: MHR | MAC payload | MFR), and "The MAC frames are passed to the PHY as the PSDU" (5.6.3); on the 2.4 GHz O-QPSK PHY that these radios use, the Frame Length field "specifies the total number of octets contained in the PSDU" (13.1.3.2) and the PHY adds no FCS of its own.
A build that delivers "PSDU without FCS" delivers the MPDU minus its footer.

The FCS itself: 7.2.11, "The 2-octet FCS shall be calculated using the following standard generator polynomial: G16(x) = x^16 + x^12 + x^5 + 1" over the MHR and payload ("the calculation field"), remainder initialised to zero, appended so that r0 goes to the PHY first; the clause's worked example is literally a three-octet acknowledgment MHR.
A 4-octet FCS (G32) exists only through `macFcsType` on HRP-UWB HPRF, SUN, TVWS, LECIM and MSK-2000 PHYs: never on the mandatory Clause 13 PHY, so a Zigbee stack transmitting on 2.4 GHz has exactly one FCS form.
A received frame whose FCS fails "shall be discarded" (6.6.2).

The clause's own worked example is a test vector that needs no capture: an Ack MHR with no payload, bit string `0100 0000 0000 0000 0101 0110` with `b0` passed to the PHY first, and FCS bits `0010 0111 1001 1110` with `r0` passed first.
Reading a transmitted bit string as octets with the first transmitted bit as the least significant bit of each octet (the convention every 802.15.4 frame follows) turns that into MHR `02 00 6a` and FCS `e4 79`, which is what the harness asserts against the CRC helper.

What the two dialects deliver (`docs/internals/hardware.md` §3, §8.2 above): the AT86RF233 build hands over the complete MPDU, 53 of 55 captured frames have a valid FCS tail, and **all 27 acknowledgments are exactly `FCF seq FCS`**, each trailing pair equal to the computed CRC of the first three octets (`02 00 1c` → `55 6f`, `02 00 1d` → `dc 7e`).
The two that fail validation are candidates for on-air corruption; the radio's own `BAD_FCS` flag (§8.1) is the cross-check, and the frames are kept as captured.
The OpenThread build a ConBee III once carried handed over frames whose tail was never a valid FCS (0 of 16), including its seven acknowledgments, where the two octets after the sequence number hold values such as `00 00` or `20 de`.
Its delivered **lengths** were the normative ones (a five-octet acknowledgment, a twelve-octet poll (`FCF seq dstPAN dst src cmd FCS`)) so the wrong octets sat exactly where the FCS belongs rather than being absent.

Consequences: one TX encoder with a per-dialect `psduIncludesFcs` flag (§8.2), and a sniffer that never trusts the frame tail of the OpenThread dialect.

### 9.4 The rules each layer implements

The poll queue, the NWK and APS delivery rules, the security crossing and the size bounds this stack keeps are `docs/internals/conformance.md` §1–§9.9: what a layer does with a frame is a claim about the code, and this document prints only what a party on the wire can see (`docs/internals/coding-rules.md` §10).

## 10. Open questions (append-only)

| # | Question | How it gets settled |
| --- | --- | --- |
| 1 | **Moot.** It asked about the OpenThread build a ConBee III once carried; every supported device runs Phoscon RCP (`docs/internals/hardware.md` §1) | moot |
| 2 | **Moot.** It asked about the OpenThread build a ConBee III once carried; every supported device runs Phoscon RCP (`docs/internals/hardware.md` §1) | moot |
| 3 | **Moot.** It asked about the OpenThread build a ConBee III once carried; every supported device runs Phoscon RCP (`docs/internals/hardware.md` §1) | moot |
| 4 | Whether either build carries the FCF bits 802.15.4-2015 and 802.15.4-2020 introduced (sequence number suppression, IE list present) or Information Elements at all | capture an Enhanced Beacon Request on a rig channel (R23.1 Annex D.11). The **spec** half is settled by 802.15.4-2024: the IE framework (7.4.1, Tables 7-6 … 7-10), the Enhanced Beacon Request command (7.5.3) and the Enhanced Beacon Filter IE (7.4.4.2, Figure 7-28, Nested IE short Sub-ID 0x1e) are fully defined; what is open is only whether these two firmwares implement them |
| 5 | **Moot.** It asked about the OpenThread build a ConBee III once carried; every supported device runs Phoscon RCP (`docs/internals/hardware.md` §1) | moot |
| 6 | RSSI fidelity on the AT86RF233 build | a fixed-distance two-RCP measurement on a quiet channel |
| 7 | **Half settled: the classic form is built and measured, the channel-15 test network's beacons are not.** This stack answers a Beacon Request with a classic IEEE beacon (7.3.1's Figure 7-5 order, Superframe Specification 0xCFFF, GTS fields zero, pending lists from the queue, then R23.1 Table 3-83's fifteen octets in Figure 3-53's order) and a ConBee II puts exactly that on channel 12 in answer to 7.5.2's request. Open: whether the devices of the channel-15 test network beacon at all, whether those beacons are classic or Enhanced (question 4's IE form), and what their payload carries, since no beacon from that network has been captured | a passive capture on channel 15 long enough to catch one; and, if that network answers requests at all, one Beacon Request on a quiet channel against a device authorised to answer |
| 9 | Whether any firmware ever emits a non-canonical packed uint (a redundant continuation byte) or a value that needs more than 32 bits. This stack accepts the first and rejects the second, which is a decision rather than an observation | a property read that answers `PARSE_ERROR` where a value was intended, or a capture showing such an encoding |
| 12 | **Settled.** A `RESET` carrying a TID is answered by the unsolicited `LAST_STATUS` with `TID 0`: the TID is not echoed. Band B still sends the TID, because a request with no answer must be distinguishable from a silent RCP, and it accepts either shape | measured on a ConBee II by `tools/rcp_probe` |
| 11 | **Settled for the AT86RF233 build at the revision it was measured at: it returns no acknowledged frame.** The rig measured an ack-requested transmit answered `0 OK` when the peer was filtered to the addressed short address and `17 NO_ACK` when the peer was merely promiscuous, and the RCP whose completion said *acknowledged* received nothing in a listen window afterwards. Band A gets the outcome of the exchange, never its contents. The settlement is unaffected by the echo an RCP hands back of its own transmission: that frame is the sender's own transmission, `MD_MAC` is zero in it, and band A consumes it rather than reading it as an answer. | settled at the revision measured |
| 10 | **Half settled.** The quantum is an AT86RF233 trait, not a Spinel convention: the tick is ≈2.37 µs on this build, where Spinel and upstream both name the field in microseconds. Still open: whether the two RCPs' residues differ because of boot offset, and what unit the other build reports | half settled: the quantum is the radio's, the unit is open |
| 8 | Whether either firmware lets the host compose the acknowledgment to a Data Request, which is what Zigbee R23.1 Annex D.10.2.3 needs in order to set the Frame Pending bit from the higher layer's queue (`docs/internals/architecture.md` §4) | **Settled: it does not.** The radio answers a Data Request addressed to its own short address by itself and delivers that Ack to no host (D-47); the host states the Ack's Frame Pending bit through the source-match table (§7.4.5), and a poller's completion reports the bit its parent's Ack carried (§8.3) |
| 13 | Whether band A accepts an APS data frame broadcast to destination endpoint `0x00`, which devices on the channel-15 test network send: seven such APDUs across the two channel-15 fixtures, each FCS-valid, authenticated at the NWK and carried by an NPDU destined to `0xfffd`, against 2.2.5.1.2's range of 0x01-0xfe or 0xff for a broadcast | **Settled by D-217: accepted, in both directions.** 2.4.3.1.11.1 broadcasts Device_annce to the ZDO, so 2.2.5.1.2's range sentence cannot be read literally; a TRÅDFRI bulb's announcements were the same frames, and the `interop` suite counts 0 refusals and delivers them |
| 14 | Partly answered, and not by a transmit: a dwell reads its channel, not a constant. Eight dwells through band B's own dialogue read −94 dBm on 11, 12, 13, 14, 20, 25 and 26 and **−91 on 15**, the test network's own channel, and a run an hour earlier read **−73 on 26** where the later one read its floor. What is still open is the *scale*: no dwell has yet been measured against a peer transmitting at a named power and distance, so the figures above are observed differences rather than a calibration. §7.4.1's measurements of the dialog (that it happens, ends, and carries a signed octet) stand | an A/B sweep of one channel: measured silent, then measured while an authorised peer transmits at a named power and distance, and the difference printed per channel |
| 16 | **Settled.** On Phoscon RCP 0.2.0 a `RESET` returns `RCP_LOG_CRASH_DUMP` (`0xB2`) to `00`, the stream off until a host writes `01` (§7.4); an earlier revision returned it to `01` | measured at 0.2.0 |
| 17 | **Settled: the acknowledgment belongs to the exchange and not to the frame's shape.** No frame type, ask, payload length, source address, PIB write, page, long address or `rxOnWhenIdle` changed whether a filtered peer acknowledged. Four consequences follow: a delivered frame whose source is this device is an echo of its own transmission and band A consumes it (D-125); `MD_MAC` carries nothing for such an echo; a session that reports no completion for a frame the peer delivered has reported an expired host wait, not an unanswered frame; and an APS-level `radio-error` beside a MAC `acked 1` is the peer's silence at the APS layer | settled |
