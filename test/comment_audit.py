#!/usr/bin/env python3
"""Comment gate: the comment rules of docs/internals/coding-rules.md §6, checked mechanically, and
scoped by area so it can be trusted while the tree is still being migrated; and, by docs/internals/coding-rules.md §6,
the same shape on the assertion family's message strings.

A comment is a pointer, a deviation or an ownership mark: one line, three at most; a section
mark belongs to our own documents and names one; and a record that mirrors the specification
carries its fields silently. Those are the four rules a machine can read:

  1. a comment block (`/* ... */`) of more than three lines;
  2. a `§` with no `docs/...md` name before it in the same block: a wrap that carries the
     name into the block above is a failure like any other;
  3. an internal decision id (`D-99`, `decision 47`): a decision is not a clause;
  4. a `/*` between `typedef struct` and its closing `};`, unless the record does not mirror
     the specification (§6 exempts the caller's state, the seam, the port, the diagnostics
     pool, and this stack's own machinery is the same kind of record).

A message is the message argument of the assertion family in test/support/test_harness.h
(Test_Expect, Test_ExpectStatus, Test_ExpectCount, Test_ExpectPassive, Test_ExpectOctets,
Test_ExpectHex, Test_Fault: the last argument of the first four, the first of the last
three), and it takes the same shape (docs/internals/coding-rules.md §6). Its unit is one literal, or a wrapped,
implicitly-concatenated one, read as one:

  5. a message unit over three source lines;
  6. a message unit over 200 characters after escape decoding: 200 is the mechanical form
     of three lines at the tree's line length;
  7. a `§` with no `docs/...md` name before it in the same unit: a wrap that carries the
     name into the unit above is a failure like any other;
  8. an internal decision id in a unit: a decision is not a clause.

The record's field rule does not reach a message. The message rules read call sites and apply
to files under test/ only, where the family is invoked: test/<dir> is the area the AREAS
table names for <dir> (test/mac is mac, test/nwk is nwk), a file at test/'s root or under a
directory the table does not name is `suites`, and a migrated area's check therefore holds
its suite files to the message rules as well (mac's sources plus test/mac, nwk's plus
test/nwk). A call site outside test/ is reported and not failed; a message that is a
variable carries no measurable string and is not read.

A deferral is stated where it is returned (D-135): a function that answers
`ZB_ERR_UNSUPPORTED` says why in the same breath, and names the document that owns the
deferral, so a reader learns whether this stack has not built that form or the standard makes
the refusal the right answer. The ninth rule reads that:

  9. a `ZB_ERR_UNSUPPORTED` that names no document.

"The comment block that introduces it" is the nearest `/* ... */` above the refusal, provided
nothing but blank lines and code of the same body separates the two: a block above the `if`
that returns is the block that introduces the return, one guard chain carries one pointer
above the chain, and a block above a function's own opening brace introduces nothing here. A
pointer on the refusal's own line serves too, since that is where the reader meets it. The
rule reads band A's refusals and therefore the `.c` files under `src/zb/` alone: a header
declares a status, it answers none, and the seam, the provider band and the suites under
test/ answer no refusal of band A's. `src/zb/mac_frame.c` is `mac`'s by the AREAS table and
is swept with it, so the three areas a refusal can stand in are `mac` and `nwk` (failed) and
the rest of `src/zb/` (counted as backlog); `src/seam`, `src/rcp`, `src/port` and `test/`
contribute nothing to it, not even to the count.

Scope: the tree is not migrated, so a gate that failed everywhere on day one would be switched
off. The AREAS table below names an area and the files it owns; only an area marked migrated
fails the build, and every other area is counted and reported so the backlog is visible and
shrinks as areas migrate. `mac` was the first migrated area (the four files the M0-M4b sweep
took through §6) and `nwk` the second, the forty-two files of `src/zb/nwk/` that N0-N4 took
through it; the two are the model the areas after them are held to. The security crossing,
`src/zb/security.c` and `src/zb/security.h`, is an area of its own rather than one of the layer's
topics (it is the module band A's NWK layer leans on and it migrates with its own sweep) so
naming it separately is what keeps this row exactly the layer's files.

Usage: comment_audit.py [repo-root]
"""

import os
import re
import sys

SCANNED = (".c", ".h")
# vendor/ is third-party code, exempt from §6 by docs/internals/coding-rules.md §1; the reference
# trees under refs/ are not this repository's source and build/ is generated.
NOT_SCANNED = {".git", "build", "refs", "vendor"}

# --- the areas table ------------------------------------------------------------------
# area -> (migrated, the files it owns). A file is owned by the one area whose entry matches
# it: a directory ending in os.sep owns everything below it. A file no area names is
# reported as `unassigned`, so a stale table shows up as a line in the report instead of
# quietly shrinking what this gate looks at.
MIGRATED = True
BACKLOG = False
AREAS = (
    ("mac", MIGRATED,
     ("src/zb/mac" + os.sep, "src/zb/mac_frame.c", "src/zb/mac_frame.h")),
    ("nwk", MIGRATED, ("src/zb/nwk" + os.sep,)),
    ("stack", MIGRATED, ("src/stack" + os.sep,)),
    ("security", BACKLOG, ("src/zb/security.c", "src/zb/security.h")),
    ("aps", BACKLOG, ("src/zb/aps" + os.sep,)),
    ("layers", BACKLOG,
     ("src/zb/zb_layers.c", "src/zb/zb_layers.h", "src/zb/zb_state.c", "src/zb/zb_state.h", "src/zb/zb_core.c",
      "src/zb/zb_core.h")),
    ("seam", BACKLOG, ("src/seam" + os.sep,)),
    ("port", BACKLOG, ("src/port" + os.sep,)),
    ("provider", BACKLOG, ("src/rcp" + os.sep, "src/loopback" + os.sep)),
    ("substrate", BACKLOG, ("src/utils" + os.sep, "src/log" + os.sep, "src/crypto" + os.sep)),
    ("suites", BACKLOG, ("test" + os.sep,)),
    ("tools", BACKLOG, ("tools" + os.sep,)),
)

# --- the record exemption of §6 --------------------------------------------------------
# §6: "Exempt, judged by their own rules: the caller's state (`Nwk_Nwk`, `Aps_Aps`), the
# seam, the port, the diagnostics pool." A record named for this stack's own machinery is not
# a record that mirrors a table the specification prints, so the exemption is written as the
# classes a name can be recognised by rather than as a list of every such record:
#   - the module's own state, spelled `<Module>_<Module>`: Mac_Mac, Nwk_Nwk, Aps_Aps, Log_Log;
#   - what the application supplies, `..._Config`, which §6 judges by the caller's rules too;
#   - the seam (`Radio_...`), the port (`Port...`) and the diagnostics pool (`Log_...`),
#     named one and all in §6's sentence.
EXEMPT_PREFIXES = ("Radio_", "Port", "Log_")
EXEMPT_SUFFIXES = ("_Config",)
MODULE_STATE_RE = re.compile(r"^([A-Z][A-Za-z0-9]*)_\1$")
# The machinery this tree builds around the specification and around the bands under test:
# pools, decisions, dialects and the suites' own rigs. A name joins this list only when it
# names something we invented rather than a table, figure or primitive the standard prints:
# `Nwk_RoutingTableEntry` (Table 3-77) and `Aps_Frame` (Figure 2-9) stay out of it and stay counted.
EXEMPT_MACHINERY = {
    # band A's and band B's own plumbing: a pool, a decision, a rig, a dialect; never a table, a
    # figure or a primitive the standard prints
    "Aps_Aps", "Aps_Tx", "Aps_Delivery", "Nwk_Tx", "Nwk_RelayTrack", "Nwk_RreqTx", "Nwk_TlvSet",
    "Nwk_RreqRxDecision", "Nwk_RrepRxDecision",
    "Zb_State", "Zb_StateKey", "Zb_StatePair", "Zb_StateWindow",
    # the façade, the provider bands and their dialects
    "Zb_Layers", "Zb_Stack", "Zb_StackConfig", "Zb_StackEvent", "Zb_StackNetwork", "Zb_StackJoined", "RcpRadio", "SpinelSession", "Loopback_Radio", "PibJudgement", "PropEntry",
    "PropStep", "PortNullScript",
    # the suites' and tools' own scaffolding
    "Rig", "MacView", "Ledger", "Driven", "Deviation", "DenyTx",
}

DOC_NAME_RE = re.compile(r"docs/[A-Za-z0-9_./-]*\.md")
# `D-99` is an internal decision id, `TID-0` is Spinel's field and not one: the boundary is
# what separates them, so the `D` must start a token.
DECISION_RE = re.compile(r"\bD-[0-9]+|\b[Dd]ecision [0-9]+")
STRUCT_START_RE = re.compile(r"typedef\s+struct\b")
# §6's Allman braces make a record's end its own line; the name is the tag or the typedef.
STRUCT_END_RE = re.compile(r"\n\}\s*([A-Za-z_][A-Za-z0-9_]*)?\s*;")
RECORD_NAME_RE = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_]*)")

# rule -> the one line a reader is given when it fires
RULES = (
    ("block", "a comment block over three lines"),
    ("section", "a section mark with no document name before it in its block"),
    ("decision", "an internal decision id"),
    ("field", "a field note inside a record that mirrors the specification"),
    ("msg_lines", "a message unit over three source lines"),
    ("msg_chars", "a message unit over 200 characters after escape decoding: the mechanical "
                  "form of three lines at the tree's line length"),
    ("msg_section", "a section mark with no document name before it in its message unit"),
    ("msg_decision", "an internal decision id in a message unit"),
    ("unsupported", "a ZB_ERR_UNSUPPORTED that names no document"),
)
RULE_TEXT = dict(RULES)
# The authority a violation is reported against: the comment rules and the message family's
# are §6's, and the deferral rule is the decision that made it a rule (D-135).
RULE_AUTHORITY = {rule: "docs/internals/coding-rules.md §6" for rule, _ in RULES}
RULE_AUTHORITY["unsupported"] = "decision 135"


def isExemptRecord(name):
    if not name or MODULE_STATE_RE.match(name):
        return True
    if name.startswith(EXEMPT_PREFIXES) or name.endswith(EXEMPT_SUFFIXES):
        return True
    return name in EXEMPT_MACHINERY


def commentBlocks(text):
    """Every `/* ... */` in `text`, as (first line, last line, the block's own text)."""
    blocks = []
    at = 0
    while True:
        start = text.find("/*", at)
        if start == -1:
            return blocks
        end = text.find("*/", start + 2)
        if end == -1:
            end = len(text) - 2
        firstLine = text.count("\n", 0, start) + 1
        lastLine = text.count("\n", 0, end) + 1
        blocks.append((firstLine, lastLine, text[start:end + 2]))
        at = end + 2


def records(text):
    """Every `typedef struct ... };` in `text`, as (line, name, body)."""
    found = []
    for start in STRUCT_START_RE.finditer(text):
        end = STRUCT_END_RE.search(text, start.end())
        if not end:
            continue
        line = text.count("\n", 0, start.start()) + 1
        tag = RECORD_NAME_RE.match(text, start.end()).group(1)
        name = tag if tag != "{" else (end.group(1) or "")
        found.append((line, name, text[start.end():end.start()]))
    return found


def checkText(text):
    """The four rules over one file's text, as (rule, line, detail)."""
    found = []
    for first, last, block in commentBlocks(text):
        if last - first + 1 > 3:
            found.append(("block", first, f"{last - first + 1} lines, at most 3"))
        for mark in [m.start() for m in re.finditer("§", block)]:
            if not DOC_NAME_RE.search(block[:mark]):
                found.append(("section", first + block.count("\n", 0, mark),
                              "no docs/...md name before the mark in its block"))
        decision = DECISION_RE.search(block)
        if decision:
            found.append(("decision", first + block.count("\n", 0, decision.start()),
                          f"{decision.group(0)} names a decision, not a clause"))
    for line, name, body in records(text):
        if "/*" in body and not isExemptRecord(name):
            found.append(("field", line,
                          f"`{name or 'anonymous record'}` mirrors the specification, so its fields are silent"))
    return found


# --- the message rules of docs/internals/coding-rules.md §6 ---------------------------------------------------------
# The message argument of the assertion family (test/support/test_harness.h): the last
# argument of the first four of these, the first of the last three.
MESSAGE_HELPERS = {
    "Test_Expect": -1,
    "Test_ExpectStatus": -1,
    "Test_ExpectCount": -1,
    "Test_ExpectPassive": -1,
    "Test_ExpectOctets": 0,
    "Test_ExpectHex": 0,
    "Test_Fault": 0,
}

# The C escapes a message literal may carry, decoded before the unit is measured.
MESSAGE_ESCAPES = {
    "\\n": "\n", "\\t": "\t", "\\r": "\r", "\\0": "\0",
    '\\"': '"', "\\\\": "\\", "\\'": "'",
}


def unescape(text):
    """A literal's content, its C escapes decoded."""
    out, i = [], 0
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text):
            two = text[i:i + 2]
            if two in MESSAGE_ESCAPES:
                out.append(MESSAGE_ESCAPES[two])
                i += 2
                continue
            if two == "\\x" and i + 3 < len(text):
                out.append(chr(int(text[i + 2:i + 4], 16)))
                i += 4
                continue
            out.append(text[i + 1])
            i += 2
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def tokenize(src):
    """The tokens of `src` (string, char, id, punct), each with its source lines: comments
    are dropped, a string literal is one token, and a literal's lines run from its opening
    quote to its closing one, so a wrapped literal keeps its shape."""
    i, n, line = 0, len(src), 1
    toks = []
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r\f\v":
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j < 0:
                j = n
            line += src.count("\n", i, j)
            i = j + 2
        elif c == '"':
            start = line
            parts = []
            i += 1
            while i < n:
                ch = src[i]
                if ch == "\\":
                    parts.append(src[i:i + 2])
                    i += 2
                elif ch == '"':
                    i += 1
                    break
                else:
                    if ch == "\n":
                        line += 1
                    parts.append(ch)
                    i += 1
            toks.append(("str", "".join(parts), start, line))
        elif c == "'":
            start = line
            parts = []
            i += 1
            while i < n:
                ch = src[i]
                if ch == "\\":
                    parts.append(src[i:i + 2])
                    i += 2
                elif ch == "'":
                    i += 1
                    break
                else:
                    if ch == "\n":
                        line += 1
                    parts.append(ch)
                    i += 1
            toks.append(("chr", "".join(parts), start, line))
        elif c.isalpha() or c == "_":
            j = i
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            toks.append(("id", src[i:j], line, line))
            i = j
        else:
            toks.append(("punct", c, line, line))
            i += 1
    return toks


def parseCall(toks, k):
    """`toks[k]` is the helper's id and `toks[k+1]` its `(`: the call's arguments, each a
    run of tokens, and the index of the closing `)`."""
    depth = 0
    args = [[]]
    j = k + 1
    while j < len(toks):
        kind, text, _l0, _l1 = toks[j]
        if depth == 0:
            if kind == "punct" and text == "(":
                depth = 1
                j += 1
                continue
            break
        if kind == "punct":
            if text in "([{":
                depth += 1
            elif text in ")]}":
                depth -= 1
                if depth == 0:
                    return args, j
            elif text == "," and depth == 1:
                args.append([])
                j += 1
                continue
        args[-1].append(toks[j])
        j += 1
    return args, j


def familySites(text):
    """Every call site of the assertion family in `text`, as (helper, the site's line,
    the call's arguments). The site's line is the helper's; a call that wraps its message
    onto its own lines keeps it, and the message's tokens carry their own lines."""
    found = []
    toks = tokenize(text)
    for k, tok in enumerate(toks):
        if tok[0] != "id" or tok[1] not in MESSAGE_HELPERS:
            continue
        nxt = toks[k + 1] if k + 1 < len(toks) else None
        if not nxt or nxt[1] != "(":
            continue
        args, _end = parseCall(toks, k)
        found.append((tok[1], tok[2], args))
    return found


def messageUnits(sites):
    """The literal messages of `sites`, as (first line, the unit's source lines, the
    unit's characters after escape decoding, the unit's text). The message's argument is
    one unit, a wrapped, implicitly-concatenated literal as one; a message that is a
    variable carries no measurable string and is not read."""
    found = []
    for helper, _line, args in sites:
        idx = MESSAGE_HELPERS[helper]
        if idx < 0:
            idx += len(args)
        if idx >= len(args) or not args[idx]:
            continue
        arg = args[idx]
        if any(t[0] != "str" for t in arg):
            continue
        text = "".join(unescape(t[1]) for t in arg)
        line0 = arg[0][2]
        line1 = arg[-1][3]
        found.append((line0, line1 - line0 + 1, len(text), text))
    return found


def checkMessage(line0, lines, chars, text):
    """The four message rules over one unit, as (rule, line, detail); the unit's first
    line names the site."""
    found = []
    if lines > 3:
        found.append(("msg_lines", line0, f"{lines} source lines, at most 3"))
    if chars > 200:
        found.append(("msg_chars", line0, f"{chars} characters after escape decoding, "
                                             f"at most 200"))
    for mark in [m.start() for m in re.finditer("§", text)]:
        if not DOC_NAME_RE.search(text[:mark]):
            found.append(("msg_section", line0, "no docs/...md name before the mark in its unit"))
    decision = DECISION_RE.search(text)
    if decision:
        found.append(("msg_decision", line0, f"{decision.group(0)} names a decision, not a clause"))
    return found


# --- the deferral rule of D-135 ---------------------------------------------------------
# A refusal says why where it is returned: `/* 10.21.2's fast association asks for a direct
# response; not built, docs/internals/conformance.md §1 */` names the clause it rests on, the kind of
# refusal it is and the document that owns the deferral, so `grep -B2 ZB_ERR_UNSUPPORTED
# src/zb` is the inventory of what this stack does not do rather than a prose list a reviewer
# has to trust. Two refusals of one form at two places are two pointers; a guard chain carries
# one, above the chain, because that is where a reader meets it.
UNSUPPORTED_TOKEN_RE = re.compile(r"\bZB_ERR_UNSUPPORTED\b")
# The rule reads band A's refusals, in the C files under src/zb/ alone: a header declares a
# status where a body answers one. `src/zb/mac_frame.c` is mac's by the AREAS table and is
# swept with it; src/seam, src/rcp, src/port and test/ are read by no part of this rule.
REFUSAL_ROOT = "src" + os.sep + "zb" + os.sep


def blanked(text):
    """`text` with every comment and literal replaced by spaces and its newlines kept: the
    shape a brace is counted in, so no comment or string can move a body's depth."""
    out = list(text)
    n = len(text)
    i = 0
    while i < n:
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            for k in range(i, end):
                if out[k] != "\n":
                    out[k] = " "
            i = end
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            for k in range(i, end):
                out[k] = " "
            i = end
        elif text[i] in "\"'":
            quote = text[i]
            k = i + 1
            while k < n:
                if text[k] == "\\":
                    k += 2
                    continue
                k += 1
                if text[k - 1] == quote or text[k - 1] == "\n":
                    break
            for j in range(i, min(k, n)):
                if out[j] != "\n":
                    out[j] = " "
            i = k
        else:
            i += 1
    return "".join(out)


def lineDepths(blank):
    """The brace depth at the start of each line of `blank`, one entry per line."""
    depths, depth = [], 0
    for line in blank.split("\n"):
        depths.append(depth)
        depth += line.count("{") - line.count("}")
    return depths


def refusalSites(text):
    """Every line a `ZB_ERR_UNSUPPORTED` stands on in code, as its number: an occurrence a
    comment mentions is prose about a refusal, not one."""
    blank = blanked(text)
    return sorted({blank.count("\n", 0, match.start()) + 1
                   for match in UNSUPPORTED_TOKEN_RE.finditer(blank)})


def checkUnsupported(text):
    """The deferral rule over one file's text, as (rule, line, detail). The pointer is the
    refusal's own line or the block that introduces it: the nearest `/* ... */` above, where
    nothing but blank lines and code of the same body separates the two; a body opened at
    file scope in between is another function's, so the block introduces that body instead."""
    found = []
    lines = text.split("\n")
    depths = lineDepths(blanked(text))
    blocks = commentBlocks(text)
    for line in refusalSites(text):
        if DOC_NAME_RE.search(lines[line - 1]):
            continue
        above = [block for block in blocks if block[1] < line]
        if not above:
            found.append(("unsupported", line, "no comment above it, and no document on the line"))
            continue
        _first, last, block = above[-1]
        if any(depths[k - 1] == 0 and depths[k] > 0 for k in range(last + 1, line)):
            found.append(("unsupported", line,
                          "the comment above it introduces another function, and names no document"))
            continue
        if not DOC_NAME_RE.search(block):
            found.append(("unsupported", line, "the comment above it names no document"))
    return found


def sourceFiles(root):
    """Every `.c` and `.h` under src/, test/ and tools/, relative to `root`."""
    found = []
    for base in ("src", "test", "tools"):
        for directory, subdirs, names in os.walk(os.path.join(root, base)):
            subdirs[:] = sorted(d for d in subdirs if d not in NOT_SCANNED)
            for name in sorted(names):
                if name.endswith(SCANNED):
                    found.append(os.path.relpath(os.path.join(directory, name), root))
    return sorted(set(found))


def areaOf(rel):
    for area, _, owned in AREAS:
        for entry in owned:
            if rel == entry or (entry.endswith(os.sep) and rel.startswith(entry)):
                return area
    return "unassigned"


# The area names the table knows, for the message rules' mapping of a suite directory onto
# the area it tests.
AREA_NAMES = {name for name, _, _ in AREAS}


def messageAreaOf(rel):
    """The area a message in a file under test/ belongs to: test/<dir> is the area the
    table names for <dir> (test/mac is mac, test/nwk is nwk); a file at test/'s root or
    under a directory the table does not name is `suites`."""
    parts = rel.split(os.sep)
    if len(parts) >= 3 and parts[1] in AREA_NAMES:
        return parts[1]
    return "suites"


MIGRATED_AREAS = {name for name, migrated, _ in AREAS if migrated}


def report(counts):
    """One line per rule: what remains outside the migrated areas, and how much of it."""
    total = 0
    for rule, text in RULES:
        total += counts[rule]
        print(f"comment_audit: backlog elsewhere, {text}: {counts[rule]}")
    return total


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    files = sourceFiles(root)
    if not files:
        print("comment_audit: FAIL, no C source found under src/, test/ or tools/")
        return 1

    violations = []
    counts = {rule: 0 for rule, _ in RULES}
    perArea = {area: 0 for area, _, _ in AREAS}
    perArea["unassigned"] = 0
    suiteFiles = {area: 0 for area, _, _ in AREAS}
    notes = []
    for rel in files:
        area = areaOf(rel)
        perArea[area] += 1
        try:
            with open(os.path.join(root, rel), "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError as error:
            violations.append(f"{rel}:0: unreadable: {error}")
            continue
        found = checkText(text)
        if area in MIGRATED_AREAS:
            for rule, line, detail in found:
                violations.append(f"{rel}:{line}: {RULE_TEXT[rule]} ({detail}), "
                                  f"{RULE_AUTHORITY[rule]}")
        else:
            for rule, _, _ in found:
                counts[rule] += 1

        # The deferral rule reads band A's own refusals, in the C files under src/zb/ alone.
        if rel.startswith(REFUSAL_ROOT) and rel.endswith(".c"):
            for rule, line, detail in checkUnsupported(text):
                if area in MIGRATED_AREAS:
                    violations.append(f"{rel}:{line}: {RULE_TEXT[rule]} ({detail}), "
                                      f"{RULE_AUTHORITY[rule]}")
                else:
                    counts[rule] += 1

        # The message rules read test/ only, the ground the family is called on; a migrated
        # area holds its suite files to the same shape, and a call site anywhere else is
        # reported and not failed.
        if rel.startswith("test" + os.sep):
            suiteFiles[messageAreaOf(rel)] += 1
        if any(helper in text for helper in MESSAGE_HELPERS):
            sites = familySites(text)
            if rel.startswith("test" + os.sep):
                marea = messageAreaOf(rel)
                for line0, lines, chars, unit in messageUnits(sites):
                    for rule, line, detail in checkMessage(line0, lines, chars, unit):
                        if marea in MIGRATED_AREAS:
                            violations.append(f"{rel}:{line}: {RULE_TEXT[rule]} ({detail}), "
                                              f"{RULE_AUTHORITY[rule]}")
                        else:
                            counts[rule] += 1
            elif sites:
                plural = "" if len(sites) == 1 else "s"
                notes.append(f"{len(sites)} assertion-family call site{plural} in {rel} "
                             f"outside test/: reported, not failed")

    for violation in violations:
        print(f"COMMENT VIOLATION: {violation}")
    for note in notes:
        print(f"comment_audit: {note}")
    if violations:
        plural = "" if len(violations) == 1 else "s"
        print(f"comment_audit: {len(violations)} violation{plural} in the migrated area(s): "
              f"{', '.join(sorted(MIGRATED_AREAS))}")
        report(counts)
        return 1

    for name in sorted(MIGRATED_AREAS):
        print(f"comment_audit: {name} ok ({perArea[name] + suiteFiles[name]} files, "
              f"{len(RULES)} rules)")
    backlog = report(counts)
    if perArea["unassigned"]:
        print(f"comment_audit: {perArea['unassigned']} file(s) the areas table does not name, "
              f"counted as backlog")
    print(f"comment_audit: ok ({', '.join(sorted(MIGRATED_AREAS))} migrated and clean over "
          f"{len(files)} files; {backlog} violations elsewhere, reported and not failed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
