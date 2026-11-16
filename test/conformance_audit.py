#!/usr/bin/env python3
r"""The conformance map's own gate (docs/internals/conformance.md §1 to §3 and §7, decision 150).

The map says which standard clauses a source file answers to, and the file says what it makes of each
one. Neither is worth much alone: a row that names a page and a file that says nothing is a claim nobody
checked, which is the failure this branch was opened for. So each row's clause list and the file's own
marks are held together here, mechanically, in both directions.

  conformance_audit.py [root]      default root: this script's tree

A row is `| `path` phrase | M2024 pages a-b (clause, clause), c (clause); R23.1 pages d (clause) |`, and
its clause list is what that file answers to. A file's marks are a block in its first comment:

  /* M2024: 7.3.1.2, 7.3.1.6 ok; 7.3.1.4 constructed; 7.3.1.5 unbuilt; 8.2.4.3 deferred D-149;
     7.3.1.1, 7.3.1.7 defect (a name for each). */

Five checks.

The first is coverage: every clause its row names is marked by the file, so a clause cannot be cited in
the map and left unread in the code. The second is the reverse: no file marks a clause its rows do not
give it, because a mark for a clause nobody assigned is a claim about somebody else's rule. The third is
the vocabulary, five marks and no others, because `ok` and `constructed` and `unbuilt` are different
answers and a sixth would be a way of not answering. The fourth is that `deferred` names a decision and
`defect` names what is wrong, since a mark that names nothing is a shrug.

The fifth is the ratchet. A tree where most files carry no marks is where this starts, and the count of
such files may only fall: `FILES_WITHOUT_MARKS` and `DEFECT_MARKS` are the numbers measured when the
mechanism was built, and a change that raises either has added a file nobody enumerated or a defect
nobody named.
"""

import os
import re
import sys

# Measured when the mechanism was built: 38 rows, every file mapped, 197 clauses still to be judged.
FILES_WITHOUT_MARKS = 0
DEFECT_MARKS = 7
TODO_MARKS = 283
UNCITED_CLAUSES = 56
HELPER_CITATIONS = 88
# 28 of the 29 are D-135's own document pointers, which the rule requires inside the body; the 29th is
# `nwk_join.c`'s 3.2.2.13 channel change, where the radio's refusal is a form this stack does not build.
BODY_COMMENTS = 29

MARKS = ("ok", "constructed", "unbuilt", "deferred", "delegated", "elsewhere", "defect", "todo")
STANDARDS = ("M2024", "R23.1", "ZCL")
CLAUSE_RE = re.compile(r"^\d+\.\d+(?:\.\d+)*$")
CITE_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+){0,3})\b")
ROW_RE = re.compile(r"^\|\s*`([^`]+)`[^|]*\|(.*)\|\s*$")
MARK_WORD = r"\b(" + "|".join(MARKS) + r")\b"
MARK_RE = re.compile(r"\b(M2024|R23\.1|ZCL)\b([^;]*?)\b(ok|constructed|unbuilt|deferred|defect|todo)\b")


# An annex or appendix id is not a clause: D.4, D.10.2, I.2.5 and K.3.1.1 all read as clause numbers.
ANNEX_RE = re.compile(r"(?:\b[A-Z]|Annex [A-Z]|Appendix [A-Z])\.\d+(?:\.\d+)*")


def read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def mapRows(root):
    """Every row of the clause-index sections, 1, 2, 3 and 7: path -> {(standard, clause)}."""
    rows = {}
    inIndex = False

    for line in read(os.path.join(root, "docs", "internals", "conformance.md")).splitlines():
        stripped = line.strip()

        if stripped.startswith(("## ", "### ")):
            inIndex = stripped.startswith(("## 1.", "## 2.", "## 3.", "### 3.1", "## 7."))
            continue

        if not inIndex:
            continue

        match = ROW_RE.match(stripped)

        if match is None or match.group(1).startswith("Source file"):
            continue

        clauses = set()
        segment = None
        locator = ANNEX_RE.sub("", match.group(2))

        for piece in re.split(r"\b(M2024|R23\.1|ZCL)\b", locator)[1:]:
            if piece in STANDARDS:
                segment = piece
                continue

            if segment is None:
                continue

            for group in re.findall(r"\(([^)]*)\)", piece):
                for token in group.split(","):
                    token = token.strip()

                    if CLAUSE_RE.match(token):
                        clauses.add((segment, token))

        rows[match.group(1)] = clauses

    return rows


def fileMarks(text):
    """The first comment block's marks: (standard, clause) -> mark, and the block itself.

    The block names a standard once and stays in it until another one is named, so a line reads
    `M2024: 7.3.1.2 ok; 7.3.1.5 unbuilt; R23.1 3.6.2.2 ok`. Only the clauses written before a mark word
    belong to it: what follows is the reason, and a reason may name a clause of its own.
    """
    start = text.find("/*")

    if start < 0:
        return {}, ""

    block = ANNEX_RE.sub("", re.sub(r"\s+", " ", text[start:text.find("*/", start)]))
    marks = {}
    standard = None

    for piece in block.split(";"):
        piece = piece.strip().lstrip("/* ").strip()
        named = re.match(r"^(M2024|R23\.1|ZCL)\b(.*)$", piece)

        if named is not None:
            standard = named.group(1)
            piece = named.group(2)

        if standard is None:
            continue

        word = re.search(MARK_WORD, piece)

        if word is None:
            continue

        head = piece.split(word.group(1))[0]

        for token in re.findall(r"\b(\d+\.\d+(?:\.\d+)*)\b", head):
            marks[(standard, token)] = word.group(1)

    return marks, block


def citedClauses(text):
    """Every clause a file's comments name outside its marks block, house refs and tables aside."""
    blocks = list(re.finditer(r"/\*.*?\*/", text, re.S))

    if not blocks:
        return set()

    rest = text[:blocks[0].start()] + text[blocks[0].end():]
    comments = "\n".join(re.findall(r"/\*.*?\*/", rest, re.S))
    # a clause is not a quantity and not the standard's own name
    cleaned = re.sub(r"\d+\.\d+(?=\s*(?:ms|us|µs|ksymbol|octets|symbols|kbit|dBm))", " ", comments)
    cleaned = re.sub(r"802\.15\.4", " ", cleaned)
    cleaned = ANNEX_RE.sub(" ", re.sub(r"§\s*\d+(?:\.\d+)*", " ",
                                       re.sub(r"(?:Table|Figure)\s+[0-9A-Z]+.-?[0-9]+", " ", cleaned)))

    return set(CITE_RE.findall(cleaned))


FUNC_RE = re.compile(r"^static\s[^;{]*?\b(\w+)\s*\(", re.M)


def helperCitations(text):
    """The helper functions whose own comment cites a clause, and the clause it cites.

    A helper stands inside its caller's rule, so the caller names the clause and the helper says what it does.
    Two comments naming one clause are two versions of it, and the older one outlives the code it described.
    """
    body = text.split("*/", 1)[1] if "*/" in text else text
    found = []

    for match in FUNC_RE.finditer(body):
        before = body[:match.start()].rstrip()

        if not before.endswith("*/"):
            continue

        start = before.rfind("/*")

        if start < 0:
            continue

        comment = before[start:]
        cleaned = re.sub(r"802\.15\.4", " ", ANNEX_RE.sub(" ", re.sub(r"§\s*\d+(?:\.\d+)*", " ", comment)))

        if CITE_RE.search(cleaned):
            found.append(match.group(1))

    return found


def bodyComments(text):
    """The comments left inside function bodies.

    The code explains itself: a body comment survives only where a refusal is a form this stack does not build
    and therefore names the document that says so, which decision 135 requires of `ZB_ERR_UNSUPPORTED`.
    """
    out = []
    i, depth, n = 0, 0, len(text)

    while i < n:
        if text.startswith("/*", i):
            end = text.index("*/", i) + 2

            if depth >= 1:
                out.append(" ".join(text[i:end].split()))

            i = end
            continue

        if text[i] in "\"'":
            quote = text[i]
            j = i + 1

            while j < n and text[j] != quote:
                j += 2 if text[j] == "\\" else 1

            i = j + 1
            continue

        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1

        i += 1

    return out


def sourcePath(root, row):
    """Where a row's file lives: the row names it as the tree names it under src/zb."""
    return os.path.join(root, "src", "zb", row)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    rows = mapRows(root)
    problems = []
    unmarked = 0
    defects = 0
    todos = 0
    marked = 0

    uncited = 0
    helpers = 0
    bodies = 0

    for row, wanted in sorted(rows.items()):
        path = sourcePath(root, row)

        if not os.path.exists(path):
            problems.append(f"docs/internals/conformance.md names `{row}` and there is no such file")
            continue

        marks, block = fileMarks(read(path))

        if not marks:
            if "M2024:" not in block and "R23.1:" not in block:
                unmarked += 1
            else:
                marked += 1
            continue

        marked += 1

        for key in sorted(wanted):
            if key not in marks:
                problems.append(f"`{row}` answers {key[0]} {key[1]} and does not mark it")

        for key in sorted(marks):
            if key not in wanted:
                problems.append(f"`{row}` marks {key[0]} {key[1]}, which no row gives that file")

        module = os.path.join(root, "src", "zb", os.path.splitext(row)[0])
        # a row that names 7.2.2 answers 7.2.2.6 as well: a parent covers its children
        named = {(standard, clause) for standard, clause in wanted}

        def covered(standard, clause):
            return any((standard, parent) in named and (clause == parent or clause.startswith(parent + "."))
                       for _, parent in ((standard, p) for _, p in named if _ == standard))

        for suffix in (".c", ".h"):
            if not os.path.exists(module + suffix):
                continue

            # A file that marks one standard and one only answers to that standard: the Cluster Library's numbers
            # look like the Core's, so the clause's own shape cannot tell the two apart.
            marked_standards = {standard for standard, _ in fileMarks(read(module + suffix))[0]}

            for clause in sorted(citedClauses(read(module + suffix))):
                if len(marked_standards) == 1:
                    standard = next(iter(marked_standards))
                else:
                    standard = "M2024" if clause.startswith(("6.", "7.", "8.", "9.", "10.", "11.", "13.")) else "R23.1"

                if not covered(standard, clause):
                    uncited += 1

        for suffix in (".c",):
            module_text = read(module + suffix) if os.path.exists(module + suffix) else ""
            helpers += len(helperCitations(module_text))
            bodies += len(bodyComments(module_text))

        for mark in marks.values():
            if mark in ("deferred", "delegated") and not re.search(mark + r"\s*\(", block):
                problems.append(f"`{row}` marks a clause {mark} and gives no reason in words")

            if mark == "defect" and not re.search(r"defect\s*\(", block):
                problems.append(f"`{row}` marks a defect and names nothing wrong")

            if mark == "defect":
                defects += 1

            if mark == "todo":
                todos += 1

    if unmarked > FILES_WITHOUT_MARKS:
        problems.append(f"{unmarked} files carry no clause marks, up from {FILES_WITHOUT_MARKS}")

    if defects > DEFECT_MARKS:
        problems.append(f"{defects} clause marks say defect, up from {DEFECT_MARKS}")

    if bodies > BODY_COMMENTS:
        problems.append(f"{bodies} comments sit inside function bodies, up from {BODY_COMMENTS}")

    if helpers > HELPER_CITATIONS:
        problems.append(f"{helpers} helpers cite a clause their caller already names, up from {HELPER_CITATIONS}")

    if uncited > UNCITED_CLAUSES:
        problems.append(f"{uncited} clause references in the sources answer to no row, up from {UNCITED_CLAUSES}")

    if todos > TODO_MARKS:
        problems.append(f"{todos} clause marks are still todo, up from {TODO_MARKS}")

    if problems:
        for problem in problems:
            print(f"CONFORMANCE VIOLATION: {problem}")
        return 1

    print(f"conformance_audit: ok ({len(rows)} rows, {marked} file{'' if marked == 1 else 's'} marked, "
          f"{unmarked} unmarked, {defects} defect marks, {todos} todo, {uncited} uncited, "
          f"{helpers} helpers citing, {bodies} in bodies)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
