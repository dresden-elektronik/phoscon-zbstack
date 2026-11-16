# Figures

What the figures under `docs/images/` are, which document owns each one, and how they are rebuilt.
A figure is a program's output, never a drawing: every label is a string in a script under `tools/diagrams/`, so a change to a figure shows up in a diff.

## 1. Figures

| Figure | Owned by | Source |
| --- | --- | --- |
| `docs/images/where.png` | `README.md` | `tools/diagrams/where.py` |
| `docs/images/join.png` | `docs/getting-started.md` §5 | `tools/diagrams/join.py` |
| `docs/images/turn.png` | `docs/guide.md` §2 | `tools/diagrams/turn.py` |
| `docs/images/appstates.png` | `examples/README.md` | `tools/diagrams/appstates.py` |
| `docs/images/testing.png` | `docs/internals/testing.md` §1 | `tools/diagrams/testing.py` |
| `docs/images/wire.png` | `docs/internals/protocol.md` §2 | `tools/diagrams/wire.py` |
| `docs/images/nesting.png` | `docs/internals/protocol.md` §9 | `tools/diagrams/nesting.py` |
| `docs/images/port.png` | `docs/porting.md` §2 | `tools/diagrams/port.py` |
| `docs/images/indirect.png` | `docs/internals/conformance.md` §1 | `tools/diagrams/indirect.py` |
| `docs/images/routing.png` | `docs/internals/conformance.md` §2 | `tools/diagrams/routing.py` |
| `docs/images/bands.png` | `docs/internals/architecture.md` §1 | `tools/diagrams/bands.py` |
| `docs/images/macsplit.png` | `docs/internals/architecture.md` §3 | `tools/diagrams/macsplit.py` |
| `docs/images/seam.png` | `docs/internals/architecture.md` §4 | `tools/diagrams/seam.py` |
| `docs/images/txpath.png` | `docs/internals/architecture.md` §6 | `tools/diagrams/txpath.py` |
| `docs/images/rxpath.png` | `docs/internals/architecture.md` §6 | `tools/diagrams/rxpath.py` |
| `docs/images/memmap.png` | `docs/memory.md` §1 | `tools/diagrams/memmap.py` |
| `docs/images/memlife.png` | `docs/memory.md` §2 | `tools/diagrams/memlife.py` |
| `docs/images/memrxframe.png` | `docs/memory.md` §3 | `tools/diagrams/memrxframe.py` |
| `docs/images/memtxframe.png` | `docs/memory.md` §4 | `tools/diagrams/memtxframe.py` |

A figure has one owner, the section that states what it shows; that section carries its caption and its alt text, and another document may show it with a pointer back.

## 2. Rebuilding

```sh
python3 tools/diagrams/all.py              # rebuild every figure
python3 tools/diagrams/all.py --check      # is every committed figure current?
python3 tools/diagrams/all.py --names      # the tree checks alone, no renderer
python3 tools/diagrams/bands.py            # one figure
```

`--check` is run before a commit that touches a figure, a script or a module a figure names.
It is a lint rather than a suite, because it needs Chrome and poppler (`pdftoppm`); the scripts need Python 3 and nothing else, and find Chrome through `$CHROME`, its macOS install, or `google-chrome` or `chromium` on the `PATH`.
The pipeline is SVG, an HTML page sized to the figure, Chrome printing it to PDF, and `pdftoppm` at twice the size to a lossless PNG; the output is deterministic, which is what `--check` compares.

## 3. Conventions

Figures follow the Phoscon design language on its paper tokens: `tools/diagrams/phoscon.css` is the design language's figure classes, and `tools/diagrams/figure.py` the shared primitives, layouts and checks.

| Convention | Why |
| --- | --- |
| amber marks the one subject of a figure | a reader knows where to look before reading a label |
| solid is a call or what the tree holds; dashed is an answer or what is owed; hatched is what the tree does not own | the state reads in grayscale, never by colour alone |
| identifiers in the mono face, one plain line in the sans face under each | a module name is code and is set as code |
| every figure has a legend | a figure explains its own marks |
| the caption and the alt text live in the Markdown; no prose, dates, versions or counts inside the image | the words that age stay where they are maintained |
| a figure is sized to its content | nothing is letterboxed or squeezed to fit a frame |
| a figure drawn to scale reads its sizes from the table its owning section prints (`figure.docTable`) | a changed number is a stale figure, which `--check` reports |

## 4. What a figure checks before it draws

A figure that names the tree is refused when the tree disagrees, so a stale figure cannot be built:

- every source path a block stands for exists, and a block drawn owed over a path that is only a stub says so in its words;
- every identifier it prints is named in `src/`;
- every label fits its box, measured in Chrome's own fonts;
- the band figure also runs `test/bands_audit.py`, the one statement of the rule it draws.
