# Testing

What is tested, by which instrument, and what each one is allowed to prove.
**After reading** you can name the suite that holds a module to its contract, say what only the rig can prove, and find where a vector or a fixture comes from.
`docs/internals/coding-rules.md` §4.5 makes a host suite part of the definition of done.

## 1. Two layers of testing

- **Host suites** need a C99 compiler, and Python 3 for the audits and the fixture reader; they prove codecs, bounds, state machines, error handling and fixture replay, and cannot show what a radio puts on the air.
- **The two-RCP rig** needs two RCPs, a quiet channel and authorisation, and proves that TX reaches the air, completions, acknowledgment round trips and per-dialect differences; it proves nothing about a live network.

A host suite is the default place to find a bug.
The rig discovers behaviour, and what it discovers is frozen into a fixture or a vector so that a host suite defends it from then on.
The Python harness is the third instrument (§7).

![A table of the evidence that tests the stack, one row per layer, from what needs nothing to what needs real hardware; each row shows what it stands on, the ctest names that run on it with a line saying what they prove, and what it needs. The audits read the tree's source and documents as text. The codecs and pools of the substrate, band A, band B and the examples' saved network run on input written in the case, with no radio. The crypto suites check published vectors from FIPS-197, NIST SP 800-38 and R23.1 Annex C. Every band-A layer, from mac to stack, runs over loopback_radio, in amber, the seam's scripted implementation with no RCP and no clock. The Spinel backend and the port run over port_null's scripted bytes, and port_posix over a pseudo-terminal. All of these need nothing. The fixtures in test/fixtures/ are re-read by samples, replayed by interop, and read by several other suites; they need a capture. Outside ctest, the two-RCP rig drives real RCPs on a quiet channel with the tools and harness instruments, and an arrow shows what it finds frozen into a capture.](../images/testing.png)

*Figure 1: what proves what.*
Everything above the rig runs in `ctest` with no RCP, every band-A layer over the scripted `loopback_radio`, in amber; what the rig finds on the air comes back as a capture in `test/fixtures/`.
The generator refuses to draw when a registered suite is missing from the figure.
Source: `tools/diagrams/testing.py`.

## 2. Host suites

A suite is a C99 program, or a Python audit, built by CMake and run by `ctest`, with no device, no clock and no network.
`ctest -N` lists the suites and `ctest --test-dir build/host -R <name>` runs one.
A suite is a name and a ledger, not a file: `test/suite_ledger.py --check` pins each suite's case order and assertion count in `test/suite_ledger.json`, so a suite can be split across files without changing what it proves.

**A case cites the clause it enforces**, in its assertion message (`docs/internals/coding-rules.md` §6).
A passing suite proves only what its cases say, and a case written against the code instead of the clause passes together with the defect it should catch.
A case that can name no clause asserts this repository's own choice and says so.
A case is proof only after it has been run against the code from before the fix, and that step is `docs/internals/conformance.md`'s, "How a file is audited".

### The suites

Each entry names the subject the suite owns and the document or clause that defines it; the cases themselves are the detail.
An entry marked **not built** specifies a suite whose module does not exist yet.

#### Substrate

- **`utils_contract`** (**built**): the `Zb_*` primitives, `ZB_ASSERT`, the deadline arithmetic (D-41 and D-277) and the `Zb_bstream_` additions to the vendored stream.
- **`u_bstream`** (**built**): the bounded reader and writer, each call the Spinel codec forwards to (`docs/internals/coding-rules.md` §1).
- **`u_sstream/*`** (**built**): the vendored library's own tests, run unchanged.
- **`crypto_aes`** (**built**): the `aes.h` contract, against the published vectors of §2.1 (decisions 42, 43).
- **`crypto_hash`** (**built**): `Aes_MmoHash` and `Aes_MmoHmac`, against the vectors R23.1 Annex C prints for them (§2.1).
- **`vendor`** (**built**): every file under `vendor/` against its hash in `vendor/MANIFEST`.

#### Band C: the port

- **`port_contract`** (**built**): rings, entropy and the clock, `docs/porting.md` §1.
- **`port_posix`** (**built**): the POSIX byte stream, including raw 8N1 over a pseudo-terminal, `docs/porting.md` §1, and the POSIX file calls on a scratch file (D-278).
- **`port_locate`** (**built**): an RCP found by its USB serial number (D-282) on a sysfs-shaped tree made at configure time: both USB layouts, the hub above a device, a match with no node, two devices with one serial; and the host's own list, read only.
- **`ex_config`** (**built**): the examples' saved network, `examples/README.md`: a full `Zb_State` written and read back on a scratch file, every kind of file the module did not write refused with the caller's config untouched, a failed save leaving the old file, and the samples in `examples/config/` read.
- **`port_conformance`** (**built**): one recorded transcript replayed through every implemented port, `docs/porting.md` §2.

#### Band B: the radio backends

- **`hdlc`** (**built**): framing, escaping and FCS, `docs/internals/protocol.md` §2.
- **`spinel_codec`** (**built**): the Spinel header, packed integers and typed values, `docs/internals/protocol.md` §3, §4 and §8.1.
- **`spinel_session`** (**built**): TID discipline and the reset episode, `docs/internals/protocol.md` §5.
- **`props`** (**built**): the property table and what each dialect answered, `docs/internals/protocol.md` §7.
- **`rcp_radio`** (**built**): the radio service over a scripted RCP, `docs/internals/protocol.md`.
- **`loopback_radio`** (**built**): the radio service with no hardware, `docs/internals/architecture.md` §4.
- **`seam`** (**built**): the seam contract in `src/seam/radio.h`.

#### Band A: the library

- **`mac_frame`** (**built**): the 802.15.4 frame codec, `docs/internals/protocol.md` §9.1 and §9.2.
- **`mac`** (**built**): the MAC over a model backend, `docs/internals/conformance.md` §1 and `docs/internals/conformance.md` §1.
- **`nwk_frame`** (**built**): the NWK frame codec, R23.1 Figures 3-4 and 3-5.
- **`nwk`** (**built**): the NWK data service and the join, `docs/internals/conformance.md` §2 and `docs/internals/conformance.md` §2.
- **`nwk_tables`** (**built**): the NWK pools and their full-pool policies, `docs/internals/architecture.md` §5.
- **`nwk_modules`** (**built**): the NWK topic modules, `docs/internals/architecture.md` §5.
- **`nwk_routedisc`** (**built**): the Route Request and its Annex K records.
- **`nwk_routeflow`** (**built**): route discovery end to end, 3.4.2.3.5, and across a gap on `test/support/mesh_air`, an air where a case says who cannot hear whom, and a relay's discovery for its end device child's frame and for no other (D-265).
- **`security`** (**built**): the NWK and APS security crossings, `docs/internals/conformance.md` §4.
- **`aps_frame`** (**built**): the APS frame codec.
- **`aps`** (**built**): the APS data service, `docs/internals/conformance.md` §3 and `docs/internals/conformance.md` §3.
- **`aps_modules`** (**built**): the APS topic modules, `docs/internals/architecture.md` §5.
- **`af`** (**built**): the application framework's endpoint table and ASDU path, `docs/internals/conformance.md` §7.
- **`zdo`** (**built**): the device object's server half, 2.4.4.2's descriptors and addresses, `docs/internals/conformance.md` §7.
- **`zdo_client`** (**built** with `ZB_ZDO_CLIENT`): the client half, 2.4.3.1's requests as their figures frame them and the address and match responses read whole, short and overrunning.
- **`core`** (**built**): the surface an application stands on, `docs/internals/architecture.md` §5.2 and `docs/internals/decisions.md` D-210.
- **`zcl`** (**built**): the Cluster Library's foundation frame and the Basic cluster's read path, ZCL R8, `docs/internals/conformance.md` §7.
- **`state`** (**built**): the persistence boundary, `docs/internals/architecture.md` §5.2.
- **`log`** (**built**): the diagnostics record and its pool, `docs/internals/coding-rules.md` §5.

#### End to end

- **`layers`** (**built**): `Zb_Layers` through its public operations, one stack and two, `docs/internals/architecture.md` §5.2.
- **`stack`** (**built**): `Zb_Stack` read only through its events, over loopback models: what `Zb_StackStart` refuses, a coordinator coming up, a network key never made up without entropy, a router joining a coordinator, the two exchanging an acknowledged frame (D-251), an end device doing the same both ways (D-301), a sleepy one too, its parent's frame taken by its poll and its link key verified at the attach rate (D-301), and a child its parent forgot rejoining, the permit closed (D-268, D-269); and over a pseudo-terminal it answers as an RCP does, an RCP that misses a RESET, never answers, or goes quiet and comes back (D-264).
- **`interop`** (**built**): a test network on channel 15, captured and replayed offline.
- **`hearing`** (**built**): the shim in `src/stack` that `tools/zb_mesh` stands on: it judges the hop rather than the originator and reports a cut unicast as NO_ACK (D-260).

#### Audits and the oracle

- **`bands`** (**built**): the band rules, `docs/internals/coding-rules.md` §1, §4.6 and §6.
- **`freestanding`** (**built**): the portable set compiled freestanding and as `wasm32` (`docs/internals/coding-rules.md` §1).
- **`parent_streams`** (**built**): a parent project that names its own `u_bstream` and `u_sstream` builds the stack with no source of `vendor/`, and one whose header is another revision does not configure (D-290).
- **`namespace_audit`** (**built** where the toolchain has `nm`): no library of the tree's own defines a `U_` symbol, which belongs to the u_* libraries (`docs/internals/coding-rules.md` §2).
- **`comment_audit`** (**built**): the comment and assertion-message rules, `docs/internals/coding-rules.md` §6.
- **`docs_audit`** (**built**): the documentation rules, and this page's suite and fixture lists against `ctest` and `test/fixtures/`.
- **`conformance_audit`** (**built**): `docs/internals/conformance.md`'s rows against the clause marks in the files they name, both directions, with the unmarked files and the defect marks held at their measured count.
- **`samples`** (**built**): every fixture under `test/fixtures/`, dissected by `harness/ieee802154.py`.
- **`band_a_size`** (**built**): band A compiled for the ConBee II's Cortex-M0+, over the source set `CMakeLists.txt` names, `docs/memory.md`.
- **`mem_size`** (**built**): the RAM of every object, member by member, on the Cortex-M0+ and on the host, and the deepest call chain from each public entry point on the Cortex-M0+, which `docs/memory.md` cites; a cycle it does not know to end fails it.

#### Not built

- **`deadlines`** (**not built**): `Zb_NextDeadline`, the earliest pending item across every layer's timers.

### 2.1 Known-answer vectors

A vector is never both the thing under test and the source of the implementation, and its octets live only in the case files.
Each entry names the vector and where it comes from.

Measured on Phoscon RCP:

- the `RESET` request `7e 80 01 02 92 7e`.
- the post-reset notifications `7e 80 06 00 70 ee 74 7e` (112) and `… 72 fc 57` (114).
- the GET frames `7e 81 02 02 5e 80 7e` and `7e 81 02 b0 01 54 53 7e`, also asserted on import by the harness.
- the escaped payload `89 06 25 13` → `… 7d 33 9b …`.
- the `STREAM_RAW` metadata groups of 10, 1 and 5 octets (`docs/internals/protocol.md` §8.1).
- the acknowledgment `02 00 1c | 55 6f`, whose FCS is a capture (7.3.3, Figure 7-15).
- the acknowledgment with queued data `12 00 …` (10.22.3).
- the Matyas-Meyer-Oseas digests `C0` → `AE 3A 10 2A …` and `C0 … CF` → `A7 97 7E 88 …`, the two sides of B.4's padding threshold at 8191 and 8192 octets (`24 EC 2F E7 …` and `DC 6B 06 87 …`), and the two-block tail of C.5.6 (`BC 98 28 D5 …`): R23.1 Annex C.5.
- the keyed hashes `40 41 … 4F` over `C0` → `45 12 80 7B …` and the same over a 32-octet key → `A3 B0 07 99 …`, which is the hashed-down key C.6.2 prints first: R23.1 Annex C.6.
- the key-transport and key-load derivatives of the global Trust Center link key `5A 69 67 42 65 65 41 6C 6C 69 61 6E 63 65 30 39` (4.2.1.2.1) as `4B AB 0F 17 …` and `C5 A4 70 35 …`, derived here from 4.5.3's rule and quoted as the values the upstream stacks publish for the same key.
- the broadcast data frame `41 88 … 0xffff` with AR clear (Figure 7-2).
- the poll `63 88 …` with content `04` (Table 7-11).

From the specifications and published references:

- the FCS of the MHR `02 00 6a`, `e4 79` (802.15.4 7.2.11).
- the Imm-Ack shape, `FCF + seq + FCS` with every other field zero (7.3.3, Figure 7-15).
- the frame-control layout and presence rules of `docs/internals/protocol.md` §9.1 (Figure 7-2, 7.2.4 to 7.2.7).
- the CRC-16 check value of `"123456789"`, `0x2189`.
- FIPS-197 C.1: key `000102030405060708090a0b0c0d0e0f`, plaintext `00112233445566778899aabbccddeeff`, ciphertext `69c4e0d8…c55a`.
- CMAC of the empty message, `bb1d6929…6746` (SP 800-38B D.1).
- the CCM tag `b4ac6bec…bcea5b` (SP 800-38C C.4).
- the CCM* tag of the secured beacon, `223bc1ec841ab553` (IEEE C.3.2.2).
- the Zigbee CCM* pair, a 23-octet payload and an 8-octet tag (R23.1 C.3, C.4).

From upstream implementations:

- the HDLC FCS residue `0xF0B8`.
- the packed uints `0x120B → 8b 24`, `0x1008 → 88 20` and `0xFFFFFFFF → ff ff ff ff 0f`, also measured.

Computed by hand, where the corpus prints no worked example:

- the NWK vectors: the unicast `08 00 01 00 00 00 1e 05`, the Route Request form and the source-route subframe (R23.1 Figures 3-4, 3-5, 3-6).
- the secured NWK frames s1 to s6 (decision 53); **no secured vector exists in the corpus**.
- the APS frames v1 to v9; **the corpus prints no worked APS frame**.

## 3. Two-RCP rig

The rig is two RCPs on one quiet channel, a private PAN, and a destination address that belongs to neither RCP's network.
The quiet channels are **12 and 26** (`docs/internals/hardware.md` §7), and transmitting needs `--allow-tx` in each session under the rules for a run of `docs/internals/hardware.md` §8; the destination PAN defaults to the inert `0xbeef`.
An RCP stays armed after its host closes the port, so every session ends with a reset.

What only the rig proves, with the record behind each:

- A frame transmitted by one RCP is captured byte for byte by the other in promiscuous mode, and a frame band A composed arrives octet for octet on both quiet channels.
- A completion carries the request's TID; an acknowledgment request with no peer completes as `17 NO_ACK`.
- A data frame, a Data Request and the 33-octet APS carrier are each acknowledged by a filtered peer.
- The Ack's Frame Pending bit follows the table band A writes: complete and empty answers zero, a named short or extended form answers one, a complete table naming another device answers zero, and a statement band A cannot complete answers one for everyone.
- A reset mid-session re-arms the RCP and capture resumes, and two sessions on two RCPs coexist.
- A frame this stack transmits arrives as composed, its length counting the footer the radio fills in (`docs/internals/hardware.md` §3), and the pending-table cells and the indirect exchange are read with the stack on both ends.
- `tools/rcp_probe` brings a real RCP up from C and re-arms it after a host reset.
- `tools/interop_sniff` reads a live network through the whole stack behind a deny-tx shim and makes **0 backend tx calls**.

Still open:

- The OpenThread half of the per-dialect FCS rule has no device to run on, because every supported device runs Phoscon RCP (`docs/internals/hardware.md` §1).
- The acknowledgment frame inside a completion is delivered by neither measured build (`docs/internals/protocol.md` §10, question 11).
- `INVALID_STATE` and `BUSY` are asserted against a scripted RCP only, because provoking them on hardware leaves the RCP in a state this rig avoids.

A rig run that discovers something ends with the finding in `docs/internals/protocol.md` or `docs/internals/hardware.md` **and** a fixture or a vector here.

## 4. Fixtures

`test/fixtures/` holds the real captures the suites read, each checked in with the gate that reads it.
A capture's octets are never edited; its header names the run, with the run's port names replaced by neutral ones (`/dev/ttyACM0`, `conbee2-a`).
`harness/check_samples.py` re-dissects every file in the directory, so no fixture goes unread.
The channel-15 captures come from a test network and hold headers and ciphertext only.
A rig transcript carries the test network key it transmitted with, because a transmission that cannot be compared octet for octet witnesses nothing.

Port captures, raw bytes from an RCP:

- `port_conb2a_raw.hex`, `port_conb2b_raw.hex`: `hdlc`, `spinel_codec` (and its FCS-error path), `rcp_radio`.
- `port_conb2_raw.hex`: the same three, and `port_conformance`.

Air captures, PSDUs from a test network on channel 15:

- `conbee2_ch15_hex.txt`: the `interop` replay's second capture.
- `conbee2_ch15_nwksec_hex.txt`: the `interop` replay, and the on-air evidence for the secured NWK vectors.

Rig transcripts, what one RCP was asked to send and what its peer delivered:

- `loopback_ch26_tx_*.txt`, `loopback_ch26_rx_*.txt`: the §3 gates and the `mac` suite's on-air cases.
- `loopback_ch26_tx_nsdu_*_discovery.txt`, `loopback_ch26_rx_nsdu_discovery.txt`: an NSDU unsecured and secured, every attempt delivered, read by the `layers` suite.
- `conb2_beacon_reply.txt`: the on-demand beacon, both ends, read by the `mac` suite.

## 5. Conventions

- A case that asserts what a protocol requires cites the clause; one that asserts what a device does cites the capture (`docs/internals/refs.md` §1.1).
- A case asserts a status or a bounded drop, never only that nothing crashed (`docs/internals/coding-rules.md` §4.4).
- The same frame decodes to the same fields whichever RCP produced it; cross-firmware parity is a test.
- A vendored library's tests are vendored with it; where upstream ships none, this repository writes the gate.
- Harness self-checks run on import, so a broken encoder fails before it touches a port.
- A refactor is witnessed by `test/refactor_gate.py`, not by green suites: its comment mode proves a comment-only change left the code identical, and its probe mode diffs `test/layer_probe.c` against a reference revision.
- Determinism, the three-host matrix and the stub-target rule are `docs/internals/coding-rules.md` §4.1, §8 and §1.

## 6. Current state

What the tree contains is `docs/status.md`; the suite list is `ctest -N`.
`freestanding`, `band_a_size` and `mem_size` are the suites that compile for a second target.

### 6.1 Band C: what each target is

The target contract is `docs/porting.md` §3.

- macOS, **implemented, primary**: every rig gate runs on macOS.
- Linux, **implemented, measured**: the build and every suite pass on a Raspberry Pi 5 (aarch64) and on x86_64 Ubuntu and Debian, and a RaspBee II on a Pi 5's UART joins a network (`docs/porting.md` §3).
- Windows, **stub**: `port_win32` answers `ZB_ERR_UNSUPPORTED` to every call, and no gate passes because of it.
- WASM, deferred to stage 3.
- MCU, parked (decision 18).

## 7. The two instruments

The C side is the suites and the tools; the Python harness is the other side.
The harness carries the one thing the C side cannot: a decoder that has never read this tree's code.
A capability belongs to exactly one side, a C tool never writes a fixture, and the harness never grows a stack.

Python harness, POSIX only; `--device <name>` reads the name from the file `ZB_DEVICE_MAP` names, as the C tools do:

- `harness/spinel_probe.py`: asks an RCP for any property.
- `harness/rcp_sniffer.py`: captures and dissects a stream.
- `harness/port_dump.py`: captures raw bytes for a fixture.
- `harness/ieee802154.py`: the independent 802.15.4 dissector.
- `harness/check_samples.py`: re-reads every fixture; `ctest` runs it as `samples`.

C tools; one that opens a port names it by `--path`, and every one but `tools/zb_mesh` also by `--device <name>`, from the file the environment variable `ZB_DEVICE_MAP` names, one `name path` pair per line:

- `tools/rcp_probe`, `tools/rcp_send`: the stack on the air.
- `tools/zb_join`: the join, one RCP the parent and one the child.
- `tools/interop_sniff`: the stack on a live network, with no transmit path.
- `tools/port_probe`: what the port delivers, read-only.
- `tools/port_find`: which node a `usb-serial:<serial>` selector names, opening nothing (D-282).
- `tools/log_probe`: what the diagnostics path produces.
- `tools/zb_mesh`: several nodes that have to route, on RCPs that all hear each other.

`tools/zb_mesh_bench.py` starts a `tools/zb_mesh` run, and `tools/band_a_size.py` and `tools/mem_size.py` are the size suites' readers (§2).
`tools/rcp_probe`, `tools/rcp_send` and `tools/zb_join` take the channels and PANs a run may not use as `--protect-channel` and `--protect-pan`, and nothing is protected by default; `tools/zb_mesh` takes only the channels named below (`docs/internals/hardware.md` §7).

The two sides read the same fixtures, so a frame count or an FCS verdict always has a second reading; the harness's decoder is what caught the frame-control error `docs/internals/protocol.md` §9.1 records.

`tools/zb_mesh` is one node of a mesh, over the `hearing` shim in `src/stack` (D-260), and its suite is `hearing`.
RCPs in one room hear each other, so a run that has to route names what each node may not hear: `--ignore <eui64>` for each device that is not next to it in the topology, at both ends of every cut, and `--ignore-short 0` as well for the coordinator, whose beacon names only that address.
A beacon names no extended address, so a line C, R1, R2 is built by opening one parent at a time: start C with a `--permit` that ends before R2 starts, start R1, and start R2 once R1 has sent a link status and C's permit has closed.
Leave a router 30 s or more after it joins before anything joins through it, because 9120-9122 refuse its route requests until its link status has named the next device.
`--trace` prints one line a frame, and `route` lines at the end of a run show the path each node chose.
With `--lockstep` a node keeps one unicast out at a time and sends the next only after its confirm, which `line --lockstep` gives to the coordinator alone, with nobody broadcasting.
`line --child` adds an end device, `--role e`, that hears only the coordinator, its parent, and with `--lockstep` it is the only sender; `--forget-at` has the coordinator forget it partway.
`--sleepy` makes that end device rest its receiver and poll its parent, every `--poll-ms` once attached (7.5 s when it names none), and `--hears-while-asleep` keeps what the RCP heard between polls; each `nwkstat` line counts the polls, those that brought a frame, and the frames discarded between polls (D-301).
At its end `tools/zb_mesh` prints how long the RCP took to answer each request, by a transmit's result and for the rest, how long a frame waited in line, and the length of its own turns.
`tools/zb_mesh_bench.py` starts every node of such a run from a run file the user writes outside the tree, naming each node's host, port, baud and EUI-64 (`--bench`): `line` builds that topology, `mesh` lets all hear each other, and `report --against` holds a run's totals against an earlier one.
Its defaults are fixed, on channel 12, so runs compare; `--channel` moves a run to another channel when 12 is loud, and `--protect-channel` and `--protect-pan` pass to every node, so no run arms on a network the bench must leave alone.
Without `--tx --allow-tx` it only prints what it would start.

`tools/zb_join` is the rig's join driver: `--parent` runs the coordinator's half and `--join` the child's.
`--own-ieee` names the device's extended address over the one the RCP reports, for early ConBee III units whose reported address is not yet theirs (`docs/internals/hardware.md` §1).
The child makes up to four Beacon Request tries, and up to three joins from the discovery table when its own transmission failed (0xe1, 0xe9, 0xeb, 0xee); a parent's refusal ends the run.
The child attaches as 3.6.1.6.1.1 chooses (D-236): by 3.4.14's Network Commissioning to a parent whose beacon carries the R23 appendix, which this stack's parent always sends, so its default join is a commissioning one; `--commission` and `--associate` force either mechanism.
A commissioning join shows method 3 in the parent's summary, and both sides print the End Device Timeout exchange.
A disagreement between the sides is a bug in one of them, never a tolerance to adjust.
