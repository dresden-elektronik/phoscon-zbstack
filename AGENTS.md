# AGENTS.md: agent contract for the Phoscon Zigbee Stack

Read this first.
A router, not a manual: every rule's text lives in the document that owns its subject.
It states only what no document owns, and never restates a rule; point at it.
**If `AGENTS.local.md` exists, read it next**: maintainers keep their bench, its ports and their local tool paths there, outside the tracked tree; a contributor without one works from the tracked docs alone.

## What this project is

A **Zigbee stack in portable C99** running on the host, against an **RCP**, a radio co-processor that owns the PHY silicon and whatever MAC primitives it reports.
The MAC and the Zigbee layers are one **library** whose bottom edge is a radio-service seam (`docs/internals/architecture.md`); every band is built, and the application layer has its first slice.
Where it stands is `docs/status.md`, how the modules fit is `docs/internals/architecture.md`, what each suite proves is `docs/internals/testing.md`.

## Read in this order

| Before you… | Read |
| --- | --- |
| arrive, or explain the project | `docs/internals/README.md` |
| change code | `docs/internals/coding-rules.md` |
| touch an RCP | `docs/internals/hardware.md`, then `AGENTS.local.md` where a maintainer keeps one |
| add or change a module | `docs/internals/architecture.md`, then the module's own header |
| find out what is built | `docs/status.md` |
| decide anything | `docs/internals/decisions.md` |
| write or move a document | `docs/internals/coding-rules.md` §10 |
| add or change a suite | `docs/internals/testing.md` |
| answer a protocol question | `docs/internals/protocol.md`, then `docs/internals/refs.md` |
| find out what a layer does with a frame | `docs/internals/conformance.md` |
| ask how a measured fact is known | `docs/internals/testing.md` and `test/fixtures/` |
| port to another target | `docs/porting.md` |
| use or donate code | `docs/internals/refs.md` |

`docs/` is the door for someone using the stack and `docs/internals/` for someone changing it (`docs/internals/coding-rules.md` §10).

**Do not open a port without reading `docs/internals/hardware.md`.**

## Commands

README's "Try it" owns the build and a first run, and `docs/internals/testing.md` §7 the instruments.
The rules a run obeys and the transmit gate (`--tx` with `--allow-tx`) are `docs/internals/hardware.md` §8's.
Before a commit that touches a figure, or a module a figure names, run `python3 tools/diagrams/all.py --check` (`docs/internals/figures.md`).

## How work is dispatched here

These rules have no other owner; each is stated here because no document states it.

- A delegated task does one thing; the parent chains the steps and keeps the decisions and the documentation.
- Small descriptive commits, one concern each, doc updates committed with the code they describe.
- A decision, a test, a fix or a reading is checked against the specification before it is acted on: the clause read in full with the sections that narrow it, and the clauses it touches read for what it could break (`docs/internals/coding-rules.md` §9 names the text).
- A clause that seems to contradict another is a reading not yet finished: the answer is often spread across chapters (the procedure, the command, the security chapter, the Trust Center's policy, the figures), so every clause on the subject is gathered before a contradiction is named.
