#!/usr/bin/env python3
r"""The documentation's own gates (docs/internals/testing.md §2, §4).

A suite is a name and an entry. `ctest` is the fact and §2's list is the claim, and the two have drifted
before: a suite registered with no entry (`seam`), an entry named for a suite `ctest` does not have (`utils`
against `utils_contract`), and thirteen built entries that said nothing about their state. §4's fixture list
is the directory's inventory, and it had stopped at the fixtures a suite reads while thirteen
harness-produced captures were cited only from `docs/internals/hardware.md`.

  docs_audit.py [root]     default root: this script's tree

Nine checks, in the order the code runs them.

The first two read §2's list and §4's list in both directions, because either can drift alone: every
`add_test` name must have an entry, every entry must carry exactly one state marker that agrees with
whether `ctest` registers it, and every file in `test/fixtures/` must be named in §4. The fixture check
enumerates the directory rather than a list written into the tool, so a capture that arrives without an
entry fails rather than passing silently (§4's own rule).

The third check is layout (docs/internals/coding-rules.md §10): one sentence per line, in every Markdown document. Both
shapes the rule forbids render the same as the correct source and differ only in it, so only a gate
reads them: a line that stops inside a sentence fails by name, and so does a line that carries two. A
list item's continuation line must be indented or it renders as a paragraph of its own. Fenced code,
tables and headings are not prose and are never touched.

The fourth check is the count gate (decision 132): a count a tool prints is the tool's claim and never
the document's, so a `\d+ cases` or a `\d+ tests` in `docs/` fails, and a `\d+ assertions` fails unless
it follows "reddens", the shape a mutation's measured depth is attested with. The line is provenance
and not length: a number a run produced (a capture's frames, the counter ledger `interop` pins, the
assertions a mutation reddens) is the document's and is not read here.

The fifth check is that no document and no comment carries an em-dash (docs/internals/coding-rules.md §10). The dash stands
in for a relation the sentence has not decided, and it reads as a bar in the middle of a line where
this prose is read most. A capture under `test/fixtures/` is exempt, being a real run that is never
hand-edited.

The sixth check is that a `D-id` cited anywhere in the tree names an entry the register holds, or a
tombstone that keeps its number. What a citation points at is checked; what the entry is supposed to
say about it is not, and no anchor check reads whether the section a citation names carries the claim
it is cited for (docs/internals/coding-rules.md §10). The same holds for a document: a `docs/...md` path cited anywhere
must exist, and a `§N` written right after it must be a section that document has, because a
document is renumbered when it is cut and its citations with it (docs/internals/coding-rules.md §10). That is a guard
against a pointer that leads nowhere, not a reading of the claim.

The seventh check is that a document's own numbering holds together: a section number is greater than
the one before it at the same depth and under the same parent, and a numbered record lies under the
heading whose number it carries. Appending a section at the end of a file because renumbering was
forbidden is what this catches.

The eighth check is the register's index and its entries: every entry has a row, every row has an entry
unless it is a tombstone, the count in each of the index's two headings is the number of rows under it,
and an entry from decision 139 on is capped, so a decision stays a decision instead of growing into an
argument.

The ninth check is the word budget, named rather than failed: a document over its own limit is listed,
because "is this worth its length?" is a question a warning asks and nobody asks it unprompted.
"""

import fnmatch
import glob
import os
import re
import sys

SECTION_SUITES = ("## 2. Host suites", "### 2.1")
SECTION_FIXTURES = ("## 4. Fixtures", "## 5.")

ROW_RE = re.compile(r"^\| `([^`]+)`")
ENTRY_RE_ROW = re.compile(r"^- \*\*`([^`]+)`\*\*")

# A suite is built or not. The marks are read case-insensitively so that a row saying
# "**Built and passing**" and an entry saying "**built**" are the same claim.
BUILT_MARK = "**built"
NOT_BUILT_MARK = "**not built"
ADD_TEST_RE = re.compile(r"add_test\(\s*NAME\s+([^\s)]+)")
FIXTURE_RE = re.compile(r"`([A-Za-z0-9_.*\-]+\.(?:txt|hex|pcap))`")


MARK_RE = re.compile(r"^([-*+]|\d+\.)\s")

# A citation this gate reads is a decision id: the register holds the ids, and a citation to one the
# register lacks is a failure. Whether the entry cited carries the claim it is cited for is not readable
# mechanically, and docs/internals/coding-rules.md §10 dropped the section half of the check with that reasoning.
# Annex D of R23.1 numbers its own figures and tables "D-n" (Figure D-3, Table D-1/D-2): those are not ids.
DECISION_RE = re.compile(r"(?<!Figure )(?<!Table )(?<!Tables )(?<![D0-9]-\d/)(?<!/)\bD-(\d+)\b")
HEADING_RE = re.compile(r"^(#{1,6}) (\d+(?:\.\d+)*)[. ]")
RECORD_RE = re.compile(r"^(\d+(?:\.\d+)+) \*\*")
ENTRY_RE = re.compile(r"^## (D-\d+) · ", re.M)
INDEX_ROW_RE = re.compile(r"^\| (D-\d+) \|([^|]*)\|([^|]*)\|")
INDEX_HEAD_RE = re.compile(r"^### (?:Agenda|Settled)[^(]*\((\d+)\)", re.M)

# A document's word budget (D-183). Two kinds of document, and the budget means something different for each.
#
# A *derived* document has one entry per thing in the tree: a decision per decision, a run per measurement, a module
# per module, a section per measured property, a row per source. Its length follows from the tree, so its budget is
# derived the same way and the derivation is written beside the number. Exceeding a derived budget means the tree grew.
#
# A *chosen* document is narrative: an argument, a rule set, a map. Its budget is an editorial limit, and exceeding it
# is the prompt to ask whether the content has another owner before cutting a word of it.
BUDGETS = {
    # chosen: a router, an overview, a page of milestones; README is the front page of both doors (docs/internals/coding-rules.md §10):
    # what the stack is, what works, the sticks, a first run, and each door's map
    "README.md": 700,
    "AGENTS.md": 500,
    "docs/internals/README.md": 800,
    "docs/status.md": 700,
    "docs/internals/figures.md": 800,
    "docs/porting.md": 2700,
    # chosen, and §2's design argument alone is 1673 words: why the seam sits below the MAC is in no clause and no
    # source file, so the page is as long as the argument is
    "docs/internals/architecture.md": 3400,
    # chosen, one line per binding rule: a rule trimmed is a rule lost
    "docs/internals/coding-rules.md": 3400,
    # derived: 59 modules at a contract each (zb_stack the 59th, D-251), plus the sections that frame them
    # derived: a section per measured property of the stick, which no clause and no source file carries
    "docs/internals/protocol.md": 10500,
    # derived: a row per source, and a licence notice is not a candidate for trimming
    "docs/internals/refs.md": 3400,
    # derived: a record per run, 30 of them (6.88 to 6.117) at the size a run's record is; the budget follows the count (D-183)
    # derived: a row per source file and per suite entry
    "docs/internals/conformance.md": 9000,
    "docs/internals/testing.md": 5000,
    # derived: the run record's own cast of devices and rules
    "docs/internals/hardware.md": 4650,
    # D-183: the budget follows the cap and the entry count. The register's index carries 268 rows, and at decision
    # 139's 150 words each that is 40 200 before headings, so a budget below that would fail a register that obeys its
    # own cap; the entries that run over the cap are listed apart, not paid for here.
    "docs/internals/decisions.md": 40200,
}

# Decision 139: an entry's cap, the first id it binds, and the ones it counts instead of rewriting. The count this
# prints is a prompt and not a failure (D-183): the entries over it were read, and they are the ones that enumerate
# (D-186 lists three missing features with a clause each) or that carry a consequences list. A decided entry with one
# ruling, its clauses and no enumeration is the shape the cap is for, and those are inside it.
ENTRY_CAP = 150
ENTRY_CAP_FROM = 139

CODE_AREAS = ("src", "tools", "test", "harness")
CODE_SUFFIXES = (".c", ".h", ".py")
SENTENCE_END_RE = re.compile(r"[.!?][)\]'\"*_\u201d\u2019]*$")

# The em-dash (U+2014), which no document and no comment may carry (docs/internals/coding-rules.md §10). A fixture is
# exempt: `test/fixtures/` is a real capture and is never hand-edited.
EM_DASH = "\u2014"

# Where a sentence ends inside a line: the punctuation, its closing marks, whitespace, and a token a
# sentence may open with. A period that ends an abbreviation is not a sentence end, so the word before
# it is read too.
SENTENCE_BREAK_RE = re.compile(r"[.!?][)\]}'\"*_\u201d\u2019]*\s+"
                            r"(?=[A-Z0-9`*_\"'(\[\u00a7\u201c\u2013\u2014])")
ABBREVIATIONS = ("e.g", "i.e", "cf", "vs", "al", "No", "Fig", "vol", "approx")

# The counts decision 132 leaves to the tool that prints them, the source that prints each, and the one
# attested shape that keeps a number in a document: `reddens 24 assertions` is a mutation run's depth.
COUNTED = (
    (re.compile(r"\b\d+ cases\b"), "a case count", None, "the suite ledger"),
    (re.compile(r"\b\d+ assertions\b"), "an assertion count", "reddens ", "the suite ledger"),
    (re.compile(r"\b\d+ tests\b"), "a vendored suite's test count", None, "`ctest -N`"),
)


def markdownFiles(root):
    """The documents this repository writes for a reader."""
    files = [os.path.join(root, "README.md"), os.path.join(root, "AGENTS.md")]
    # the run log is kept untracked beside the tree and is not one of its documents
    files.extend(sorted(path for path in glob.glob(os.path.join(root, "docs", "*.md"))
                        if os.path.basename(path) != "bench-log.md"))
    files.extend(sorted(glob.glob(os.path.join(root, "docs", "internals", "*.md"))))
    files.append(os.path.join(root, "examples", "README.md"))
    return files


def proseBlocks(text):
    """Every blank-line-delimited block of prose: (first line number, the lines).

    Fenced code, tables, headings and images are not prose and never appear here: an image's alt
    text is the figure described for a reader who cannot see it, an attribute and not a paragraph
    (docs/internals/figures.md §3).
    """
    fence = False
    block = []
    start = 0

    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()

        if stripped.startswith("```") or stripped.startswith("~~~"):
            if block:
                yield (start, block)
                block = []
            fence = not fence
            continue

        if fence:
            continue

        if (not line.strip() or stripped.startswith("#") or stripped.startswith("|")
                or stripped.startswith("![")):
            if block:
                yield (start, block)
                block = []
            continue

        if not block:
            start = number

        block.append(line)

    if block:
        yield (start, block)


def sentenceBreaks(line):
    """How many sentences a line carries beyond its first."""
    breaks = 0

    for match in SENTENCE_BREAK_RE.finditer(line):
        if line[:match.start()].rsplit(" ", 1)[-1] in ABBREVIATIONS:
            continue

        breaks += 1

    return breaks


def layoutProblems(relative, first, block):
    """The lines of a prose block that break docs/internals/coding-rules.md §10's rule.

    A paragraph is a run of sentences and a list item is a run of indented ones, so a line is one
    sentence: it never stops inside one, and it never carries two. Both shapes render the same as the
    correct source, which is why only a gate reads them.
    """
    problems = []

    for offset, lines in groups(block):
        listed = MARK_RE.match(lines[0]) is not None

        for index, line in enumerate(lines):
            number = first + offset + index
            carried = sentenceBreaks(line)

            if carried:
                problems.append(f"{relative}:{number}: a line carries {carried + 1} sentences; "
                                f"one sentence is one line (docs/internals/coding-rules.md §10)")

            if index < len(lines) - 1 and not SENTENCE_END_RE.search(line.rstrip()):
                problems.append(f"{relative}:{number}: a line ends inside a sentence; "
                                f"one sentence is one line (docs/internals/coding-rules.md §10)")

            if listed and index and not line[:1].isspace():
                problems.append(f"{relative}:{number}: a list item's continuation line is not "
                                f"indented, so it renders as a new paragraph")

    return problems


def groups(block):
    """The paragraph or the list items a block is made of, each as (offset, lines)."""
    if MARK_RE.match(block[0]) is None:
        return [(0, block)]

    items = []
    start = 0
    current = None
    expected = None

    for index, line in enumerate(block):
        marker = MARK_RE.match(line)
        starts = False

        if marker:
            if current is None:
                starts = True
            elif marker.group(1) in ("-", "*", "+"):
                starts = True
            elif (expected is not None and marker.group(1).endswith(".")
                  and int(marker.group(1).rstrip(".")) == expected):
                starts = True

        if starts:
            if current is not None:
                items.append((start, current))
            current = [line]
            start = index
            expected = (int(marker.group(1).rstrip(".")) + 1
                        if marker.group(1).endswith(".") else None)
        elif current is None:
            current = [line]
            start = index
        else:
            current.append(line)

    if current is not None:
        items.append((start, current))

    return items


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def statedCounts(root):
    """The counts `docs/` may not state: (the problems, how many attested depths were read).

    The scope is `docs/*.md`, the documents that carry a claim about a suite's size. A problem names
    its file, its line and the matched text, because the fix is at that spot and a reader has to find
    it; the second number is what keeps this check visibly non-vacuous, since the sanctioned shape is
    read and passed rather than skipped.
    """
    problems = []
    attested = 0

    for path in markdownFiles(root)[2:]:
        for number, line in enumerate(read(path).splitlines(), 1):
            for pattern, what, follows, source in COUNTED:
                for match in pattern.finditer(line):
                    if follows is not None and line[:match.start()].endswith(follows):
                        attested += 1
                        continue

                    problems.append(f"{os.path.relpath(path, root)}:{number}: {what} "
                                    f"{match.group(0)!r} is a tool's to print, not the document's; "
                                    f"{source} prints it (decision 132)")

    return problems, attested


def ctestNames(root):
    """The names `add_test` registers, with the generated sstream family folded to its glob.

    Full-line comments are dropped first: a commented-out `add_test` is not a registered suite, and a
    gate that counted one would pass a suite the build had dropped.
    """
    text = read(os.path.join(root, "test", "CMakeLists.txt"))
    text = "\n".join(line for line in text.splitlines()
                      if not line.lstrip().startswith("#"))
    names = []

    for name in ADD_TEST_RE.findall(text):
        names.append("u_sstream/*" if name.startswith("u_sstream/") else name)

    return names


def section(text, bounds):
    start, end = bounds

    if start not in text or end not in text:
        return None

    return text.split(start, 1)[1].split(end, 1)[0]


def suiteRows(table):
    """§2's rows or entries: the name, whether the built marker is there, whether the not-built one is.

    A suite is a name and a state, and which shape states it is the document's choice: a table row
    when the entries are one line, a list entry when each one needs a paragraph under it.
    """
    rows = []
    entry = []
    name = None

    def marks(text):
        state = text.lower()
        return (BUILT_MARK in state and NOT_BUILT_MARK not in state,
                NOT_BUILT_MARK in state)

    def flush():
        if name is not None:
            built, notBuilt = marks("\n".join(entry))
            rows.append((name, built, notBuilt))

    for line in table.splitlines():
        row = ROW_RE.match(line)
        opened = ENTRY_RE_ROW.match(line)

        if row is not None:
            flush()
            name, entry = None, []
            built, notBuilt = marks(line)
            rows.append((row.group(1), built, notBuilt))
            continue

        if opened is not None:
            flush()
            name, entry = opened.group(1), [line]
            continue

        if name is None:
            continue

        if line.strip() and (line[:1].isspace() or line.startswith("  ")):
            entry.append(line)
            continue

        flush()
        name, entry = None, []

    flush()

    return rows



def codeFiles(root):
    """The files outside `docs/` this gate reads: their comments are pointers and carry citations."""
    paths = []

    for area in CODE_AREAS:
        for suffix in CODE_SUFFIXES:
            paths.extend(glob.glob(os.path.join(root, area, "**", "*" + suffix), recursive=True))

    return sorted(paths)


def decisionIds(root):
    """Every id the register answers to: an entry, or a tombstone that keeps the number."""
    text = read(os.path.join(root, "docs", "internals", "decisions.md"))
    known = {match.group(1) for match in ENTRY_RE.finditer(text)}

    for line in text.splitlines():
        row = INDEX_ROW_RE.match(line)
        if row and row.group(3).strip().startswith("Retired"):
            known.add(row.group(1))

    return known


def dashProblems(root, documents):
    """Every em-dash in a document or in a comment of the tree (docs/internals/coding-rules.md §10)."""
    problems = []

    for path in documents + codeFiles(root):
        relative = os.path.relpath(path, root)

        for number, line in enumerate(read(path).splitlines(), 1):
            if EM_DASH not in line:
                continue

            problems.append(f"{relative}:{number}: an em-dash; a comma, a colon, a semicolon or a "
                            f"bracket says what it stood in for (docs/internals/coding-rules.md §10)")

    return problems


def decisionProblems(root, documents):
    """Every `D-id` the tree cites that the register does not hold (docs/internals/coding-rules.md §10)."""
    problems = []
    ids = decisionIds(root)

    for path in documents + codeFiles(root):
        relative = os.path.relpath(path, root)

        for number, line in enumerate(read(path).splitlines(), 1):
            for match in DECISION_RE.finditer(line):
                if match.group(0) not in ids:
                    problems.append(f"{relative}:{number}: cites {match.group(0)}, "
                                    f"which the register does not hold")

    return problems


# A document cited by path, and the section written right after it. Another repository's document
# is named as that repository's ("Phoscon RCP's `docs/protocol.md`", "`docs/x.md` there", a
# row of the reference index naming the repository) and is not this tree's to resolve; the untracked docs/tmp/ is not this tree's either (docs/internals/coding-rules.md §10).
CITED_DOC_RE = re.compile(r"(?<![A-Za-z0-9_./-])(docs/[A-Za-z0-9_/-]+\.md)`?((?:,? |\s)§(\d+(?:\.\d+)*))?")
FOREIGN_DOC_RE = re.compile(r"(?:spinel`?|RCP)'s `docs/|`docs/[A-Za-z0-9_/-]+\.md` there\b|`docs/x\.md|"
                            r"phoscon_analyzer`.*?`docs/")


def sectionNumbers(text):
    """Every section number a document answers to: its numbered headings and its numbered records."""
    numbers = set()

    for line in text.splitlines():
        match = HEADING_RE.match(line) or RECORD_RE.match(line)
        if match:
            numbers.add(match.group(match.lastindex))

    return numbers


def citationProblems(root, documents):
    """Every cited document that does not exist, and every cited section it does not have (docs/internals/coding-rules.md §10)."""
    problems = []
    sections = {}

    for path in documents + codeFiles(root):
        relative = os.path.relpath(path, root)

        for number, line in enumerate(read(path).splitlines(), 1):
            foreign = [match.span() for match in FOREIGN_DOC_RE.finditer(line)]

            for match in CITED_DOC_RE.finditer(line):
                cited = match.group(1)
                if cited.startswith("docs/tmp/") or any(a <= match.start() < b for a, b in foreign):
                    continue

                target = os.path.join(root, cited)
                if not os.path.isfile(target):
                    problems.append(f"{relative}:{number}: cites {cited}, which does not exist")
                    continue

                section = match.group(3)
                if section is None:
                    continue

                if cited not in sections:
                    sections[cited] = sectionNumbers(read(target))
                if section not in sections[cited]:
                    problems.append(f"{relative}:{number}: cites {cited} §{section}, "
                                    f"which that document does not have")

    return problems


def orderProblems(relative, text):
    """A document whose numbers do not increase where they should, and a record filed under the wrong one."""
    problems = []
    headings = []

    for number, line in enumerate(text.splitlines(), 1):
        heading = HEADING_RE.match(line)
        if heading:
            headings.append((number, heading.group(2), len(heading.group(1))))

        record = RECORD_RE.match(line)
        if record:
            headings.append((number, None, None, record.group(1)))

    numbers = [entry[1] for entry in headings if entry[1] is not None]
    orphans = set()

    if headings and headings[0][1] is not None:
        parts = headings[0][1].split(".")
        for cut in range(1, len(parts)):
            prefix = ".".join(parts[:cut])
            if prefix not in numbers:
                orphans.add(prefix)

    seen = set()
    sibling = {}
    section = None

    for entry in headings:
        if len(entry) == 4:
            number, record = entry[0], entry[3]
            if section is not None and record.split(".")[0] != section:
                problems.append(f"{relative}:{number}: the record {record} sits under §{section}")
            continue

        number, heading, depth = entry
        parts = heading.split(".")

        if len(parts) > 1:
            parent = ".".join(parts[:-1])
            if parent not in seen and parent not in orphans:
                problems.append(f"{relative}:{number}: §{heading} has no §{parent} above it")

        key = (depth, tuple(parts[:-1]))
        if key in sibling and int(parts[-1]) <= sibling[key]:
            problems.append(f"{relative}:{number}: §{heading} follows a higher number at the same depth, "
                            f"so a section is filed out of order")
        sibling[key] = int(parts[-1])
        seen.add(heading)

        if len(parts) == 1:
            section = parts[0]

    return problems


def registerProblems(root):
    """The register's index against its entries, and each of the two counts against the rows under it."""
    text = read(os.path.join(root, "docs", "internals", "decisions.md"))
    entries = {match.group(1) for match in ENTRY_RE.finditer(text)}
    problems = []
    rows = {}

    for number, line in enumerate(text.splitlines(), 1):
        row = INDEX_ROW_RE.match(line)
        if row:
            rows[row.group(1)] = (number, row.group(3).strip())

    for entry in sorted(entries, key=lambda name: int(name[2:])):
        if entry not in rows:
            problems.append(f"docs/internals/decisions.md: {entry} has an entry and no index row")

    for name, (number, status) in sorted(rows.items(), key=lambda item: int(item[0][2:])):
        if name not in entries and not status.startswith("Retired"):
            problems.append(f"docs/internals/decisions.md:{number}: the {name} row has no entry and is no tombstone")

    for heading in INDEX_HEAD_RE.finditer(text):
        stated = int(heading.group(1))
        start = text.index(heading.group(0))
        rest = text[start + len(heading.group(0)):]
        counted = 0

        for line in rest.splitlines():
            if line.startswith("### ") or line.startswith("## "):
                break
            counted += 1 if INDEX_ROW_RE.match(line) else 0

        if counted != stated:
            problems.append(f"docs/internals/decisions.md: the heading says ({stated}) and {counted} rows are under it")

    return problems


def budgetProblems(root, documents):
    """The documents over the length they were given, as a warning: the pass that shortens them is the fix."""
    over = []

    for path in documents:
        relative = os.path.relpath(path, root)
        limit = BUDGETS.get(relative)

        if limit is None:
            continue

        # an image's alt text is the figure's description, not the document's length (docs/internals/figures.md §3)
        words = sum(len(line.split()) for line in read(path).splitlines()
                    if not line.lstrip().startswith("!["))

        if words > limit:
            over.append(f"{relative}: {words} words against a budget of {limit}")

    return over



def entryProblems(root):
    """The entries over decision 139's cap: a failure from the first id it binds, a count before it."""
    text = read(os.path.join(root, "docs", "internals", "decisions.md"))
    problems = []
    counted = 0

    for match in ENTRY_RE.finditer(text):
        end = text.find("\n## ", match.end())
        body = text[match.end():end if end > 0 else len(text)]
        words = len(body.split())

        if words <= ENTRY_CAP:
            continue

        counted += 1

        if int(match.group(1)[2:]) >= ENTRY_CAP_FROM:
            problems.append(f"docs/internals/decisions.md: {match.group(1)} runs to {words} words against the "
                            f"cap of {ENTRY_CAP} (decision 139)")

    return problems, counted


# Rows of docs/internals/conformance.md's tables that do not yet carry a locator: the clause number alone is a
# paraphrase waiting to happen (decision 150). Frozen here so the number can only fall.
CONFORMANCE_ROWS_WITHOUT_LOCATOR = 0

LOCATOR_RE = re.compile(r"PDFPAGE|ZIGBEE PDFPAGE|\(p\.\d|M2024 pages|R23\.1 pages?")


def locatorProblems(root):
    """Every row of the clause index names where its rule is printed.

    Sections 4 to 6 are this stack's own surface, its measured check and its bounds, not a
    clause index, and their second column is a value rather than a locator.
    """
    text = read(os.path.join(root, "docs", "internals", "conformance.md"))
    inIndex = False
    missing = 0

    for line in text.splitlines():
        stripped = line.strip()

        if stripped.startswith(("## ", "### ")):
            inIndex = stripped.startswith(("## 1.", "## 2.", "## 3.", "### 3.1"))
            continue

        if not inIndex or not stripped.startswith("|") or stripped.startswith("| ---"):
            continue

        cells = [cell.strip() for cell in stripped.strip("|").split("|")]

        if not cells or cells[0].startswith(("What this stack does", "Source file")):
            continue

        if len(cells) < 2 or not LOCATOR_RE.search(cells[1]):
            missing += 1

    if missing > CONFORMANCE_ROWS_WITHOUT_LOCATOR:
        return [f"docs/internals/conformance.md has {missing} index rows without a locator, up from "
                f"{CONFORMANCE_ROWS_WITHOUT_LOCATOR} (decision 150)"]

    return []


def main():
    root = (sys.argv[1] if len(sys.argv) > 1
            else os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    doc = read(os.path.join(root, "docs", "internals", "testing.md"))
    suites = section(doc, SECTION_SUITES)
    fixtures = section(doc, SECTION_FIXTURES)

    if suites is None or fixtures is None:
        for bounds in (SECTION_SUITES, SECTION_FIXTURES):
            if section(doc, bounds) is None:
                print(f"DOCS VIOLATION: docs/internals/testing.md has no {bounds[0]!r} heading")
        print("docs_audit: a section this audit reads was renamed or removed")
        return 1

    names = ctestNames(root)
    rows = suiteRows(suites)
    rowNames = { name for name, _, _ in rows }
    problems = []

    for name in names:
        if name not in rowNames:
            problems.append(f"ctest registers {name!r} and docs/internals/testing.md §2 has no entry for it")

    for name, built, notBuilt in rows:
        if built == notBuilt:
            problems.append(f"the {name!r} entry carries no single state marker (docs/internals/testing.md §2)")
            continue

        registered = name in names

        if built and not registered:
            problems.append(f"the {name!r} entry says built; no add_test registers it")
        if notBuilt and registered:
            problems.append(f"the {name!r} entry says not built; add_test registers it")

    cited = set(FIXTURE_RE.findall(fixtures))
    globs = [name for name in cited if "*" in name]
    files = sorted(os.path.basename(path)
                   for path in glob.glob(os.path.join(root, "test", "fixtures", "*")))

    for name in files:
        if name in cited or any(fnmatch.fnmatch(name, pattern) for pattern in globs):
            continue

        problems.append(f"test/fixtures/{name} has no entry in docs/internals/testing.md §4")

    for name in sorted(cited):
        if "*" in name or name in files:
            continue

        problems.append(f"docs/internals/testing.md §4 names {name!r} and test/fixtures/ has no such file")

    documents = markdownFiles(root)

    for path in documents:
        relative = os.path.relpath(path, root)

        for first, block in proseBlocks(read(path)):
            problems.extend(layoutProblems(relative, first, block))

    counted, attested = statedCounts(root)
    problems.extend(counted)
    problems.extend(dashProblems(root, documents))
    problems.extend(decisionProblems(root, documents))
    problems.extend(citationProblems(root, documents))

    for path in documents:
        problems.extend(orderProblems(os.path.relpath(path, root), read(path)))

    problems.extend(registerProblems(root))

    entries, entriesOver = entryProblems(root)
    problems.extend(entries)

    problems.extend(locatorProblems(root))

    over = budgetProblems(root, documents)

    for problem in problems:
        print(f"DOCS VIOLATION: {problem}")

    if problems:
        print(f"docs_audit: {len(problems)} problem(s)")
        return 1

    measurements = "measurement" if attested == 1 else "measurements"

    print(f"docs_audit: ok ({len(names)} ctest names, {len(rows)} suite entries, "
          f"{len(files)} fixtures, {len(documents)} documents, "
          f"{len(counted)} printed counts, {attested} attested {measurements}, "
          f"{len(over)} over budget, {entriesOver} entries over the cap)")

    for line in over:
        print(f"docs_audit: budget: {line}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
