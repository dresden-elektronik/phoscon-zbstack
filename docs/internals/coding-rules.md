# Coding Rules

Binding conventions for every C source here (`src/`, `tools/`, `test/`), with the sibling project's shape as a reference and any deliberate difference marked **differs**.
A rule is binding; one marked *default* is this tree's present choice and may be revised by a decision.
**After reading** you can write C here without an audit telling you afterwards what the tree requires.

Status: **in force**.
The `bands` and `freestanding` audits check the rules for the modules that exist, and `test/comment_audit.py` checks §6's: the comment rules, the assertion message's four and the deferral pointer a `ZB_ERR_UNSUPPORTED` owes (decision 135).
The audit fails on the migrated areas (`mac` and `nwk`) and reports the rest as a per-rule backlog; §2's naming rule is enforced by review.

## 1. Language and build

- **C99 hosted**: `-std=c99 -Wall -Wextra -pedantic`; no C++, no GNU extensions, no VLAs.
- **Portable by construction.**
  One module may touch a platform API (`src/port/`): the only place `termios`, file descriptors, timers or WASM imports appear, and the only place libc is allowed.
  Everywhere below it, pure C99 with no POSIX header, no `pthread`, no `mmap`.
- **No hosted C library header in the portable set**: `<stdint.h>` and project headers only, with byte and text primitives ours (`Zb_memcpy`, `Zb_memset`, `Zb_memcmp`, `Zb_strlen`), and `<stdlib.h>` confined to `src/port/` and not a licence to allocate (§7).
  Measured: the portable set compiles `-ffreestanding` and as `wasm32` under `-nostdlib` (`test/freestanding_audit.py`).
- **No `bool`/`_Bool`.**
  Booleans are `int` (0/1), named accordingly (`int isReady;`).
- **No `NULL`**: test with `if (!ptr)`, produce a null pointer as `0` (C99 §6.3.2.3) and keep the cast where one is needed.
  `src/` includes no `<stddef.h>` unless a file uses `offsetof`.
- **All binary framing goes through one bounded writer and reader**: `U_BStream` (`docs/internals/refs.md` §6), with an explicit capacity and a status for every past-end read, write, seek and decode.
  A source includes `zb_bstream.h` and asks a stream through its calls: only `src/utils/` and the vendored code name a stream's fields, which the `bands` audit checks.
  No ad-hoc pointer arithmetic, no `sprintf`, no second codec.
- **No verbatim reuse of reference code.**
  `src/` is written from scratch: reading an encoder to learn the protocol is expected, transcribing it is not (`docs/internals/refs.md` §5).
- **`vendor/` is the one exception**: third-party code as it is, pinned in `vendor/MANIFEST`, exempt from §1's language rules and §6 but not from the include graph, the no-allocation rule or the libc ban.
  Nothing there is edited; where it lacks something, our function adapts above it (`docs/internals/refs.md` §6).
- **Vendor widths are crossed, not harmonised**: cast at the call, bounded by a named constant first; a vendored signature is never changed.
- **An unimplemented target is a stub that answers `ZB_ERR_UNSUPPORTED`**, is listed as unimplemented, and passes no conformance gate (`docs/porting.md` §3).
- **CMake only**; approved build dirs `build/host` and `build/wasm` (later stage).
- **A target is chosen by which files the build links**: `#if defined(PL_…)` appears in `src/port/` and `tools/` only, and no band carries a platform conditional or a platform type name (`docs/porting.md` §3).
- **Counts, lengths, offsets and indices are `uint32_t`, never `size_t`**: a `sizeof` result enters an interface as `uint32_t`, and a platform API insisting on `size_t` is satisfied inside the port module.
- **No platform type crosses `src/port/port.h`**: shared headers use `uint8_t`, `uint16_t`, `uint32_t` and `ZbStatus`, not `size_t`, `speed_t`, `ssize_t`, `socklen_t`, `mode_t`, `struct timespec` or a handle.

## 2. Naming

| Thing | Case | Example |
| --- | --- | --- |
| Public function (module header) | UpperCamel, `Module_Operation` | `Hdlc_Encode`, `Spinel_ReadProp`, `Nwk_Decode` |
| Private / static function | lowerCamel, `moduleOperation` | `hdlcUnescape`, `spinelQueueReply` |
| Types (struct/union/enum) the specification defines | UpperCamel, the specification's noun | `Nwk_Frame`, `Nwk_RouteRequest`, `Mac_Frame` |
| A type that is a row of a specification table | that noun + `Entry` | `Nwk_RouteDiscoveryTableEntry` (Table 3-79), `Nwk_NeighborTableEntry` (Table 3-75) |
| Types we invent | UpperCamel, named for the job | `Nwk_Config`, `Aps_Delivery`, `Port_DeviceOps` |
| Enum constants, macros, constants | UPPER_SNAKE | `HDLC_FRAME_MAX`, `SPINEL_CMD_RESET` |
| File-scope variables (avoid) | `s_` module prefix | `s_pool_rx` |
| Files | snake_case, one module per `.c`/`.h` | `hdlc.c` / `hdlc.h`, `mac_frame.c` / `.h` |

- The module prefix is the lower/upper-cased module name and is always on public symbols, so headers may be included in any order.
- **Length after the namespace is free; abbreviation there is not**: anything the specification names is spelled out (`Nwk_RouteRequestPayload`), and the acronyms it writes (`TLV`, `NLDE`, `APS`, `CCM*`) stay as it writes them.
- `Entry` marks a **row** of a table and nothing else: a frame or payload takes the specification's noun bare, and a primitive's parameter record that noun with `Parameters`.
- **A record that mirrors the specification is named after it, and its fields carry the table's or figure's row labels with no notes**: §6 states that silence and the one exception it allows.
- Protocol constants keep the spelling of the source that defines the wire value (`SPINEL_PROP_STREAM_RAW`, `MAC_CMD_DATA_REQUEST`), so a comparison against a clause or a hexdump stays readable.
  *default*
- **The radio co-processor is the RCP**, in a name and in prose (`rcp`, `Rcp_`, `RCP_`): a RaspBee is no stick, so "stick" names only a USB device as such.
- One public header per module: declarations and types only.
  *default*
- **A layer may be a directory**: a façade keeping the public API, the SAP rings and the composition, beside topic modules holding the pools and pipeline stages, each a full pair under these rules.
  Operations take caller-supplied pools, and a module reaches another's state through public operations only.
- The primitives in `src/utils/` take the stack's own `Zb_` prefix with the C library's snake_case names (`Zb_memcpy`, `Zb_strlen`, `Zb_bstream_fits`): `U_` belongs to the u_* libraries, vendored here or linked by an application beside the stack, and no name of ours may meet one of theirs.
  They are our implementations at our widths (`uint32_t` counts), not a borrowed interface.
  *default*

## 3. State machines everywhere

Any component with more than two meaningful modes is an explicit state machine:

- A named enum whose members name what it *is doing* (`RADIO_STATE_*`, `HDLC_STATE_*`, `NWK_JOIN_*`, `APS_KEY_*`).
- One `…_Step()` / `…_Poll()` entry point advances it; transitions are an explicit `switch` or a table, never scattered flags.
- One machine owns the state; others observe or command it through the public interface, never poke fields.

Applied at minimum to: the HDLC decoder (flag/escape/FCS/resync), the Spinel session (command, TID, pending-response, re-arm after a reset notification), the radio interface (sleep / rx / promiscuous-rx / tx / tx-wait-done), and (later) joining and route discovery.

Resynchronisation is a state, not an error: a decoder that sees garbage recovers to its idle state and counts the drop (§4.3).

## 4. Structure: core / platform split (testability)

Every non-trivial module splits into:

- **core**, pure C99: state machines, parsers, serializers and checks on plain buffers, with no file descriptor, no `termios`, no time syscall and no global, so it runs on the desktop and in WASM unchanged.
- **platform**, thin: open, close, read and write a serial device, monotonic time, later WASM interop, and no logic beyond mapping a core decision onto the platform.

### 4.1 Dependency direction

**Core never calls out**: no `Host_*`, no file descriptor and no `time()` inside a pure module.
Time is a parameter (`uint32_t nowMs`), and every deadline comparison goes through `Zb_timeReached`/`Zb_timeWithin` (`src/utils/zb_time.h`), which read the difference as a distance across the 49.7-day wrap.
A constant that is a time states its unit in its name (`_MS`, `_US`).

### 4.2 State is caller-owned

Module state lives in a caller-provided struct or behind one explicit reset function, never a hidden file-scope variable: two instances must coexist in one process, and a test must reset a module without restarting it.

### 4.3 Every pool states and tests its full-pool policy

A module that owns buffers says what happens when they are full and counts it, never blocking and never overwriting a slot in flight, with the counter readable.

### 4.4 Fault injection is part of the suite

For every boundary, feed truncated, oversized, escape-heavy and malformed input and assert the *bounded* response rather than "no crash", plus one deterministic pseudo-random stream per byte parser.

### 4.5 A module without a suite is not finished

Definition of done for a core module: host-clean under `-std=c99 -Wall -Wextra -pedantic`, registered in `test/CMakeLists.txt`, green in `ctest`, bounds and error paths covered.
The platform module is exempt by construction (§4.1) and is covered by `docs/internals/testing.md` §2's band C suites.

### 4.6 Bands: the library does not know a serial port exists

The protocol band (the 802.15.4 MAC and the Zigbee layers above it, `docs/internals/architecture.md` §1) may include only its own headers and the seam header.
No Spinel, HDLC, property, dialect or device name appears in it, and it contains no knowledge of a serial link, an RCP API level, a trailer, or whether a delivered PSDU carries its own FCS: those are stated to it as capability flags and dialect rules through the seam.
A radio backend may not include a protocol header.
The seam header is the only file both sides may include, and it contains types and function pointers, not code.
The MAC builds and parses 802.15.4 frames: that is the library's job, not the backend's.

Two things are substrate below the bands rather than a band: the vendored code (`vendor/`, `docs/internals/refs.md` §6) and `src/utils/`.
Any band may include either; neither may include a band; neither uses a hosted or platform header.
`src/utils/` may include a vendored header, so `zb_bstream.h` brings `U_BStream` and this stack's additions in one include.
That is what keeps a shared primitive from becoming a back door around §1, the audit knows both as substrate and checks them differently: vendored files for byte-identical pinning, `src/utils/` for our own language rules.

The rule is checked mechanically in `test/` by an include-graph audit, and the audit fails the build: band membership that depends on review is band membership that erodes.

### 4.7 One execution context for the protocol band

Band B's byte pump is allowed to run where the platform puts it (a UART/SPI interrupt, a poll loop, a WASM callback) and may only decode into band B's own caller-owned ring.
All protocol processing happens inside the single step function, with `nowMs` supplied by the caller.
No band-A function is ever called from interrupt context, no inbound path calls band A directly, and nothing in the protocol band re-enters itself.
Every queue crossing the seam is therefore a ring with a stated full-pool policy under §4.3.

## 5. Diagnostics

- **No printf in the stack**: diagnostics are fixed-size binary records with a component id and a numeric reason code, written through an injectable sink, and the human-readable table lives host-side.
- The record is 12 bytes (component 16, line 16, reason 16, argument 32), integers from the reporting call to the sink: `src/log/` holds no string literal, no hosted header and no platform call, and a human-readable line is built only by a platform sink or a tool.
  The `bands` audit checks the section ranges and value uniqueness.
- The pool is fixed at `LOG_RING_MAX`, and a report into a full one is refused with `ZB_ERR_NO_SPACE` and counted rather than overwriting.
- Reason codes are plain enums in one header, never reused or renumbered; adding a code is one line.
- A band states its invariants with `ZB_ASSERT` (`src/utils/zb_assert.h`), a false condition calling the executable's handler once with integers only, and a portable module never traps on its own.
- A decode failure names the byte offset that broke it, so a hexdump and a diagnostic line describe the same event.
  *default*

## 6. Style

**Applied by hand (there is no formatter and no second style authority) and the layout rules below are checked by the `bands` audit.**

- Braces on their own line (Allman).
  *default*
- **A single-statement body takes no braces and goes on the next line**, the control header alone on its line; never `if (cond) continue;` and never a brace on the control line.
  Anything longer keeps its braces, and a `do` body is always a block.
- **A blank line separates a conditional, a loop, a `switch` or a braced statement from the code above and below it**, the unit being one statement with its body or a whole chain, at every nesting level.
  No blank line where the line above opens a block or the line below closes one, and none between a header and its body.
  A brace carrying only declarations is a statement here; one opening a function, `struct` or `enum` is not.
- **A comment is a pointer, a deviation or an ownership mark, one line, three at most.**
  The pointer is the clause, table or figure the code obeys **with the noun it governs**: a number without its noun is not a pointer.
  The deviation says what the code does where the cited clause prints nothing; the ownership mark says the specification is silent and the choice is this stack's.
  Nothing else: no restatement of the code, no quotation, no narrative, no internal decision id.
  **A clause number is written bare; `§` belongs to our own documents, cited by name.**
- **A clause is named once per rule, where the rule is decided, and the file's mark block reports it.**
  A module states its clauses in the three-line block at its top, which `docs/internals/conformance.md` holds against its own row.
  An entry point may carry the clause it answers, one line as above.
  A helper called from one place does not: its caller already names the rule, and a second copy is a second version of it, which is how a comment comes to describe a function that no longer exists.
  A helper's comment therefore says what it does, in words, and cites nothing.
  D-150.
- **An assertion message is a pointer too, of the same shape**: the message argument of `test/support/test_harness.h` carries the pointer, the deviation or the ownership mark, in one literal of at most three source lines and 200 characters.
  `comment_audit` checks the four rules.
- **A record that mirrors the specification takes the specification's name, and its fields are silent**: the field list is the index and the table is the text, with one line above naming the table and any field it lacks.
  A field note survives only for a deviation, the name taking it first where it can.
  Exempt: the caller's state (`Nwk_Nwk`, `Aps_Aps`), the seam, the port, the diagnostics pool.
- Declarations at the top of a function; early returns for errors; no `goto` except one cleanup jump.
  *default*
- Errors are explicit status returns; no silent coercion and no `assert()` in shipped paths, a violated invariant entering a stated panic path with a diagnostic record.
- Sizes, offsets and bit positions are named constants, never raw magic numbers in logic.
- **No integer-literal suffixes**: the width that matters is the one in the declaration the literal lands in, and a conversion gets a cast there instead.
  A value needing the top bit of a 32-bit field is written `0x80000000`, not `1 << 31`.
- **Indentation is 4 spaces.**

## 7. Memory

- **No dynamic allocation of any kind**: every path has a fixed bound and every buffer is statically sized from a named constant.
- A build-time assertion (negative-size array typedef) fails the build if a frame or path exceeds its buffer; unit tests cover the same bounds at runtime.
- Buffer ownership is explicit and single-writer: a slot is free, filled, or in flight.
- 802.15.4 frames are bounded by `127` PSDU bytes and a Spinel/HDLC frame by `256` including its FCS (`docs/internals/protocol.md` §2), and buffer sizes derive from those constants rather than round numbers.
- Stack usage is bounded; no recursion in protocol parsing.

## 8. Portability contract (the WASM stage)

- No file paths, no environment variables, no threads, no filesystem, no sockets below the platform module.
- One protocol band for three host systems and later for WASM: the platform files of `src/port/` (`port_posix.c` and its siblings for macOS and Linux, `port_win32.c`) are the only files that know an operating system exists, and the same suites must build and pass on each.
- No reliance on `char` signedness, pointer subtraction across unrelated objects, or struct layout beyond same-type assignment.
- Byte-order conversion is explicit (`zb_le16`, `zb_le32`, `zb_le64`), never implicit through a cast.
- Endianness-agnostic tests: every codec suite round-trips, so a big-endian host compile is a supported check, not an aspiration.
  *default*
- The protocol band compiles from one source list into a host object, an MCU object and a WASM object; a target needs a port module and a provider, never a protocol change (§4.6, `docs/internals/architecture.md` §7).

## 9. Where the rules and the facts come from

| fact | source | owned by |
| --- | --- | --- |
| Protocol truth | Zigbee R23.1 (05-3474-23) and IEEE 802.15.4-2024, with 802.15.4-2006 beside it: the clause first, an implementation never | `docs/internals/refs.md` §1.1 |
| Style and section shape | Phoscon RCP's coding rules, a shape reference, not a code donor | none |
| RCP behaviour | OpenThread, BSD-3/Apache-2.0 | `docs/internals/refs.md` §2 |
| Measured device behaviour | measurements on Phoscon RCP | `docs/internals/hardware.md`, `docs/internals/protocol.md` |
| Port contract | none | `docs/porting.md` |
| Layer map and feature decomposition | zigbee-on-host, GPL-3.0, no code import | `docs/internals/refs.md` §1 |

## 10. Writing the documentation

These rules bind every document here.
The claim marks are `docs/internals/protocol.md`'s legend and the figure conventions `docs/internals/figures.md`'s.

- **A document is about its filename, and it states conclusions**: the evidence behind one is a suite or a fixture in `test/fixtures/` it cites.
- **Impersonal present tense; no dates, no `file:line`, no narrative of how a conclusion was reached.**
  A document states what is true and where the evidence lives; git history carries the rest.
- **Section numbers follow the document**: a document is renumbered when it is cut, and every citation to it is rewritten in the same commit.
  Code cites a document rather than a section unless the section matters.
- **One purpose per document; tables over prose.**
  A section that has grown into a second subject moves to the document that names it, and keeps its numbers.
- **A superseded claim is replaced, not shelved**: the row in the document that owns the subject is rewritten, and a claim that survives only for one build revision says which.
- **A design decision belongs in `docs/internals/decisions.md`**, as its own id-bearing entry with its status, never as a rule in another document.
- **A claim mark lives in a table, a register entry or `docs/internals/conformance.md`**, never alone after a paragraph: **spec** (a named clause of a standard), **measured** (on Phoscon RCP), **upstream** (a reference implementation), **mandate** (this repository's own binding decision, recorded in `docs/internals/decisions.md`) or **open**.
- **Two doors**: a document for someone using the library lives in `docs/`, one for someone changing it in `docs/internals/`.
- **Public sources only**: a tracked document cites standards and upstream projects by name and version, never a bench port, a serial, a local path or a path into `refs/`; those live in the untracked `AGENTS.local.md`.
- **Findings go into the document that owns the subject**: no diary, no session notes, and git history the archive.
- **No em-dash**: a comma, colon, semicolon or bracket says what it stood in for, and `docs_audit` fails one in a document or comment.
  A capture under `test/fixtures/` is exempt, its octets never being hand-edited.
- **One sentence per line.**
  A line never ends inside a sentence, so a diff is a diff of sentences rather than of a reflowed paragraph.
  The `docs_audit` layout check reads it: a line ends at a sentence end or the paragraph does.
