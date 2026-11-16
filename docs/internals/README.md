# Inside the stack

**Start here** if you are changing the stack or finding your way in it; someone building on it starts at `docs/getting-started.md` instead.
This page is the vocabulary, the map of the source tree, and which document answers the question you came with.

## The shape

The 802.15.4 MAC and the Zigbee layers above it are one **library** with no dynamic allocation, whose bottom edge is a **radio service**: a pipe that hands over an assembled frame and a report of what the radio can do.
Everything above that edge is the same code on a host, in WASM, or on a microcontroller beside a co-processor, because nothing above it may touch a platform.
There is no thread, no clock and no file: the caller turns the state machines, passes the time in milliseconds and lends every buffer.

![The stack read downwards: the application over the doors zb_stack.h and zb_core.h; band A in amber, the library's application layer, APS, NWK and MAC; the seam, seam/radio.h; band B, the radio backends; port/port.h; band C, the port; and the RCPs running Phoscon RCP at the bottom, with the substrate beside every band.](../images/bands.png)

*The bands and the seam, as `docs/internals/architecture.md` §1 draws them.*
Amber is the library; everything below the seam is what a target chooses, and not one line of the library knows a serial port exists.

## The words this repository uses

| Word | What it means |
| --- | --- |
| **band** | where code sits. Band A is the library; band B a radio backend, `rcp_radio` for an RCP and `loopback_radio` for none; band C the port, the platform's bytes and clock. The `bands` audit fails a build that leaks across them. |
| **seam** | the library's bottom edge, `src/seam/radio.h`: one PSDU pipe and a capability report, deliberately below the MAC, so the MAC is the library's on every target |
| **door** | the top edge: `zb_stack.h` for an application, one object reporting events; `zb_core.h`, the library under it, for a loop or a radio of its own |
| **port** | the small per-platform module that reads and writes a device node, and nothing else; its contract is `docs/porting.md` |
| **RCP** | the radio co-processor: a ConBee or RaspBee running Phoscon RCP, spoken to over Spinel; never called a stick, since a RaspBee is a board on a UART |
| **D-id** | an address in the decision register; permanent, never reused, and cited from code: `D-47` in a comment points at the reasoning |
| **claim mark** | where a statement comes from: **spec** (a clause of a standard, which outranks everything), **measured** (on Phoscon RCP), **upstream** (a reference implementation), **mandate** (this repository's decision), **open** |

Attribute names such as `nwkc*`, `nwk*` and `mac*` are the standards' own, so a reader can search for the clause they come from.

## The source tree

| Directory | Band | What it holds | Read |
| --- | --- | --- | --- |
| `src/stack/` | above A | `Zb_Stack`: the library, the backend and the port composed, reporting events | `docs/guide.md` |
| `src/zb/` | A | the library: `mac/`, `nwk/`, `aps/`, `af/`, `zdo/`, `zcl/`, the security crossing, `zb_core` and `zb_layers` | `docs/internals/architecture.md` |
| `src/seam/` | the seam | the radio service and the status codes every band shares | `docs/internals/architecture.md` §1 |
| `src/rcp/`, `src/loopback/` | B | the Spinel backend for an RCP, and the scripted one the suites use | `docs/internals/protocol.md` |
| `src/port/` | C | the serial device, the clock, entropy and an application's files, per platform | `docs/porting.md` |
| `src/utils/`, `src/log/`, `src/crypto/`, `vendor/` | substrate | what any band may include: bounded memory and text, the log pool, AES | `docs/internals/coding-rules.md` §4.6 |
| `test/`, `tools/`, `harness/` | none | the suites and audits, the bench instruments, the Python probe | `docs/internals/testing.md` |
| `examples/` | none | three applications on the door | `examples/README.md` |

## Which document answers what

| To | Read |
| --- | --- |
| know why the code is shaped this way | `docs/internals/architecture.md` |
| know what the bytes on the wire are | `docs/internals/protocol.md` |
| know what the RCPs are and what they report | `docs/internals/hardware.md` |
| know what a suite proves | `docs/internals/testing.md` |
| write C here, or write a document | `docs/internals/coding-rules.md` |
| see what works and what is next | `docs/status.md` |

Three documents are references, looked up rather than read front to back:

| Reference | Look up |
| --- | --- |
| `docs/internals/decisions.md` | a decision by its D-id: what was decided and what follows from it |
| `docs/internals/conformance.md` | the clauses of the standards each source file implements, with the pages to read them on |
| `docs/internals/refs.md` | the standards, the reference implementations, their licences, and what may be a code donor |

A statement that contradicts a cited clause of the standard is a defect, not a difference of opinion (`docs/internals/refs.md` §1.1).
