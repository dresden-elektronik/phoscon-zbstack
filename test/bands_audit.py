#!/usr/bin/env python3
"""Band audit: the include graph and the language rules of docs/internals/coding-rules.md §4.6,
checked mechanically so band membership cannot erode.

Usage: bands_audit.py [repo-root]
"""

import os
import re
import sys

BAND_OF_DIR = {
    "src/zb": "protocol",
    "src/stack": "stack",
    "src/seam": "seam",
    "src/rcp": "provider",
    "src/loopback": "provider",
    "src/port": "port",
    "src/utils": "utils",
    "src/log": "log",
    "src/crypto": "crypto",
    "tools": "glue",
    # What several examples share, ahead of `examples` so the longer prefix is matched first: a suite tests it.
    "examples/common": "example",
    "examples": "glue",
    "test": "suite",
    "vendor": "vendor",
}

# band -> bands it may include; a band may always include itself
# Vendored code is substrate below the bands: any band may use it, it may use nothing
# of ours (docs/internals/refs.md §6).
# `utils` and `vendor` are substrate below the bands: any band may include them, they may
# include nothing of ours (docs/internals/coding-rules.md §4.6, docs/internals/refs.md §6).
ALLOWED = {
    # The security crossing calls the crypto contract from
    # the protocol band: the crypto band is a header and the implementations behind it, no platform, no
    # Spinel and no knowledge of a link (docs/internals/coding-rules.md §4.6).
    "protocol": {"seam", "vendor", "utils", "log", "crypto"},
    "seam": {"vendor", "utils"},
    "provider": {"seam", "port", "vendor", "utils", "log"},
    "port": {"seam", "vendor", "utils", "log"},
    # `utils` may include the vendored headers, so `zb_bstream.h` extends U_BStream in one include.
    "utils": {"vendor"},
    "log": {"seam"},
    # The crypto band is a contract header and the implementations behind it: the seam status
    # header is the only thing of ours it touches besides its own.
    "crypto": {"seam"},
    # The stack an application meets: the library composed with a backend and a port, and nothing of its own below.
    "stack": {"protocol", "seam", "provider", "port", "vendor", "utils", "log"},
    "glue": {"stack", "protocol", "seam", "provider", "port", "vendor", "utils", "log", "example"},
    # The examples' shared modules stand on what an example may include and nothing more.
    "example": {"stack", "protocol", "seam", "provider", "port", "vendor", "utils", "log"},
    # A host suite is where every band gets asserted, so it may include any band's header,
    # the crypto contract included.
    "suite": {"stack", "protocol", "seam", "provider", "port", "vendor", "utils", "log", "crypto", "example"},
    "vendor": set(),
}

# Vendored code is verbatim upstream: our naming and literal rules do not apply to it,
# the platform-header, allocation and include-graph rules do.
STYLE_EXEMPT_BANDS = {"vendor"}
# Band C is the OS-facing band, but its byte and text work still comes from src/utils.
BYTE_TEXT_BANDS = {"protocol", "seam", "provider", "utils", "port", "vendor", "log"}

PLATFORM_HEADERS = {
    "termios.h", "unistd.h", "fcntl.h", "errno.h", "sys/ioctl.h", "sys/socket.h",
    "netinet/in.h", "arpa/inet.h", "pthread.h", "poll.h", "select.h", "sys/select.h",
    "windows.h", "winbase.h", "setupapi.h", "mman.h", "sys/mman.h", "dlfcn.h",
    "sys/random.h", "dirent.h",
    "CoreFoundation/CoreFoundation.h", "IOKit/IOKitLib.h", "IOKit/serial/IOSerialKeys.h",
}

# The port files that are per-target backends and may include a platform header: the device
# link, the log sink that writes the host's line (docs/internals/coding-rules.md §5), and the lookup of a stick by its
# USB serial number (D-282). Every other file in the tree may include only a freestanding header and project headers.
PLATFORM_HEADER_FILES = {"src/port/port_posix.c", "src/port/port_log_posix.c", "src/port/port_file_posix.c",
                         "src/port/port_locate_sysfs.c", "src/port/port_locate_darwin.c"}

# The bands that must compile against a freestanding C implementation: only the headers
# C99 §4 promises without a hosted library, plus project headers (docs/internals/coding-rules.md §1).
# Byte and text movement goes through src/utils instead.
FREESTANDING_HEADERS = {"stdint.h", "stddef.h", "limits.h", "stdarg.h", "float.h"}
STRICT_BANDS = {"protocol", "seam", "provider", "utils", "log", "crypto"}
# Byte and text movement never comes from the hosted library in any band: src/utils is the
# only source of it. <stdlib.h> is not on this list because POSIX declares syscalls there;
# allocation itself is rejected everywhere by ALLOC_RE.
BYTE_TEXT_HEADERS = {"string.h", "stdio.h", "wchar.h", "ctype.h"}
PLATFORM_INCLUDE_DIRS = {"src/port", "tools", "test"}
# Vendored code is verbatim upstream, so its own portability conditionals
# (__cplusplus, __STDC_VERSION__, _WIN32, __SIZEOF_LONG__) are expected; its headers
# are still held to the no-libc rule below.
CONDITION_EXEMPT_BANDS = {"vendor"}

INCLUDE_RE = re.compile(r'^\s*#\s*include\s*(["<])([^">]+)[">]')
COND_RE = re.compile(r'^\s*#\s*(if|ifdef|ifndef)\b')
GUARD_IFDEF_RE = re.compile(r'^\s*#\s*ifndef\s+([A-Za-z_][A-Za-z0-9_]*)\s*$')
GUARD_DEFINE_RE = re.compile(r'^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s*$')
SIZE_T_RE = re.compile(r'\bsize_t\b')
BOOL_RE = re.compile(r'\b(bool|_Bool)\b')
# NULL is not used anywhere in this tree: a pointer is tested with !ptr / ptr, and a null
# pointer constant is written 0 (docs/internals/coding-rules.md §1). That also removes the need for
# <stddef.h>, which is therefore only tolerated where offsetof is actually used.
NULL_RE = re.compile(r'\bNULL\b')
ALLOC_RE = re.compile(r'\b(malloc|calloc|realloc|free|alloca)\s*\(')
LITERAL_SUFFIX_RE = re.compile(r'\b(0[xX][0-9a-fA-F]+|\d+)[uUlL]+\b')
PLATFORM_MACRO_RE = re.compile(r'^__|^_WIN32$|^PL_|^_XOPEN_SOURCE$|^_POSIX_C_SOURCE$')

violations = []


# --- layout rules of docs/internals/coding-rules.md §6 -------------------------------------------
# Every control statement at every nesting level is checked: a control header carries no body
# and no brace on its line, and the statement, chain or run it belongs to is separated from
# what surrounds it by blank lines.

CONTROL_HEAD_RE = re.compile(r'^\s*(if|for|while|switch|do)\b')
CONTROL_ANY_RE = re.compile(r'^\s*(if|for|while|switch|do|else)\b')
# `else` and `else if` are control headers too. A reader that knows only `if` reads the brace
# of an else-if as a statement of its own and begins separating a header from its own body.
HEADER_RE = re.compile(r'^\s*else\b|^\s*(if|for|while|switch|do)\b')
ELSE_RE = re.compile(r'^\s*else\b')


def indentOf(line):
    return len(line) - len(line.lstrip(" \t"))


def stripCode(line):
    text = re.sub(r'/\*.*?\*/', ' ', line)
    text = re.sub(r'//.*', '', text)
    return text.strip()


def isComment(line):
    # A line that is only prose: whole-line or block-continuation comment. `*known = 1;` is
    # a statement, not a comment, which an earlier version of this helper got wrong.
    text = line.strip()
    return text.startswith("//") or text.startswith("/*") or text.startswith("*/") \
        or text.startswith("* ") or text == "*"


def scanParens(text, start, depth):
    i = start
    while i < len(text):
        c = text[i]
        if c in "\"'":
            quote = c
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    break
                i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i, depth
        i += 1
    return None, depth


def headerEnd(lines, i):
    """Last line of the control header starting at lines[i], plus whatever follows its
    closing parenthesis on that line (a body, or a brace, or nothing)."""
    text = lines[i]
    if re.match(r'^\s*do\b', text):
        return i, ""
    start = 0
    prefix = re.match(r'^\s*else\b', text)
    if prefix:
        start = prefix.end()
    keyword = re.compile(r'(if|for|while|switch)\b').search(text, start)
    if not keyword:
        return i, ""
    openAt = text.find("(", keyword.end())
    if openAt < 0:
        return i, ""
    closeAt, depth = scanParens(text, openAt, 0)
    if closeAt is not None:
        return i, text[closeAt + 1:].strip()
    j = i + 1
    _, depth = scanParens(text, openAt, 0)
    while j < len(lines) and depth > 0:
        _, depth = scanParens(stripCode(lines[j]), 0, depth)
        j += 1
    return j - 1, ""


def blockEnd(lines, i):
    """Index of the line that closes the brace block opened at or after lines[i]."""
    depth = 0
    j = i
    while j < len(lines):
        inner = stripCode(lines[j])
        depth += inner.count("{") - inner.count("}")
        if depth <= 0:
            return j
        j += 1
    return len(lines) - 1


def statementEnd(lines, i):
    text = stripCode(lines[i])
    if not text or isComment(lines[i]):
        return i + 1
    if text.endswith("{") or text == "{":
        return blockEnd(lines, i) + 1
    last, trailing = headerEnd(lines, i)
    if HEADER_RE.match(lines[i]) and not trailing:
        j = last + 1
        while j < len(lines) and not lines[j].strip():
            j += 1
        return statementEnd(lines, j)
    if last == i:
        return wrappedEnd(lines, i)
    return last + 1


def lineParenDepth(text, depth):
    """The parenthesis depth left at the end of a whole line.

    scanParens stops at the closing parenthesis it was looking for, which answers a control header
    and misreads a wrapped statement: `mixed[row][col] = (uint8_t)(aesDoGmul(state[row][col], 2)`
    closes the cast before it opens the parenthesis that stays open, so a scan that stops at the
    first close puts the end of the statement inside the call.
    """
    i = 0

    while i < len(text):
        c = text[i]

        if c in "\"'":
            quote = c
            i += 1

            while i < len(text):
                if text[i] == "\\":
                    i += 2
                    continue

                if text[i] == quote:
                    break

                i += 1

        elif c == "(":
            depth += 1

        elif c == ")":
            depth -= 1

        i += 1

    return depth


def wrappedEnd(lines, i):
    """The line after a statement whose parentheses are still open.

    A call written across three lines is one statement: the blank-line rule applies once, after
    the closing parenthesis, and a reader that stops at the first line demands a blank in the
    middle of a call.
    """
    depth = 0
    j = i

    while j < len(lines):
        depth = lineParenDepth(stripCode(lines[j]), depth)
        if depth <= 0:
            return j + 1
        j += 1

    return len(lines)


def chainEnd(lines, i):
    """A control statement, its else clauses, and a consecutive run of control statements
    at the same indentation, which is one block."""
    indent = indentOf(lines[i])
    j = statementEnd(lines, i)
    while True:
        while j < len(lines) and stripCode(lines[j]).startswith("else"):
            j = statementEnd(lines, j)
        if j < len(lines) and stripCode(lines[j]) and indentOf(lines[j]) == indent \
                and CONTROL_HEAD_RE.match(lines[j]):
            j = statementEnd(lines, j)
            continue
        break
    return j


def blankLine(raw, depth):
    """Blank comment content and the inside of string and character literals, in one pass.

    A comment wins over a quote: a quote inside a comment is not a literal, so an apostrophe in
    prose cannot swallow the closing marker that ends the comment, and a slash sequence inside a
    literal cannot open one. Returns the blanked line, the depth to carry into the next line, and
    whether any comment appeared on the line.
    """
    out = []
    sawComment = depth > 0
    i = 0

    while i < len(raw):
        if depth > 0:
            closeAt = raw.find("*/", i)

            if closeAt < 0:
                out.append(" " * (len(raw) - i))
                break

            out.append(" " * (closeAt + 2 - i))
            i = closeAt + 2
            depth = 0
            continue

        ch = raw[i]

        if ch == "/" and i + 1 < len(raw) and raw[i + 1] == "/":
            out.append(" " * (len(raw) - i))
            sawComment = True
            break

        if ch == "/" and i + 1 < len(raw) and raw[i + 1] == "*":
            out.append("  ")
            i += 2
            depth = 1
            sawComment = True
            continue

        if ch == '"' or ch == "'":
            quote = ch
            i += 1

            while i < len(raw):
                if raw[i] == "\\":
                    i += 2
                    continue

                if raw[i] == quote:
                    i += 1
                    break

                i += 1

            out.append(" ")
            continue

        out.append(ch)
        i += 1

    return "".join(out), depth, sawComment


def commentScan(lines):
    """Which lines sit inside a block comment, and which of them carry no code of their own.

    A comment whose closing marker shares a line with its last sentence is still prose. Reading that
    line as code makes a conditional look unseparated from the prose that introduces it, when the
    rule is about the run of prose and the statement as one unit.
    """
    marks = [False] * len(lines)
    prose = [False] * len(lines)
    depth = 0

    for i, raw in enumerate(lines):
        text, depth, sawComment = blankLine(raw, depth)
        marks[i] = sawComment
        prose[i] = sawComment and text.strip() == ""

    return marks, prose



def isProse(lines, prose, i):
    if i < 0 or i >= len(lines):
        return False

    if prose[i]:
        return True

    return isComment(lines[i]) and stripCode(lines[i]) == ""


def commentRunTop(lines, prose, i):
    """The first line of the comment run that introduces the statement at lines[i]."""
    top = i

    while True:
        previous = prevMeaningful(lines, top)

        if not isProse(lines, prose, previous):
            return top

        top = previous


def prevMeaningful(lines, i):
    j = i - 1
    while j >= 0 and not lines[j].strip():
        j -= 1
    return j


def isScopeBlock(lines, i):
    """A brace that is a statement rather than a definition or an initialiser."""
    if indentOf(lines[i]) == 0 or lines[i].strip() != "{":
        return False
    j = prevMeaningful(lines, i)
    if j < 0:
        return False
    previous = lines[j].strip()
    if CONTROL_ANY_RE.match(previous) or previous == "{" or previous.endswith(("{", ")", "=", ",")):
        return False
    return True


def checkBodyNotSeparated(rel, lines, i):
    """A control header and the statement or block that is its body belong together."""
    last, _ = headerEnd(lines, i)
    j = last + 1
    while j < len(lines) and not lines[j].strip():
        j += 1
    if j > last + 1 and j < len(lines) and not isComment(lines[j]):
        violations.append(f"{rel}:{last + 1}: blank line between a control header and its body "
                          f"(docs/internals/coding-rules.md §6)")


def checkSeparators(rel, lines, i, end, prose):
    top = commentRunTop(lines, prose, i)
    above = prevMeaningful(lines, top)
    if above >= 0:
        previous = lines[above].strip()
        excused = (previous == "{" or previous.endswith("{") or previous.startswith("#")
                   or isComment(lines[above]) or CONTROL_ANY_RE.match(previous))
        if previous and above == top - 1 and not excused:
            what = "a comment that introduces a conditional or block" if top != i \
                   else "a conditional or block"
            violations.append(f"{rel}:{top + 1}: no blank line above {what} "
                              f"(docs/internals/coding-rules.md §6)")

    below = end
    if below < len(lines):
        following = stripCode(lines[below])
        if following and following != "}" and not following.startswith("else") \
                and not following.startswith("} while"):
            violations.append(f"{rel}:{below + 1}: no blank line below a conditional or block "
                              f"(docs/internals/coding-rules.md §6)")


def checkLayout(rel, lines):
    _, prose = commentScan(lines)

    # A line spliced on by a backslash-ended line is part of a directive (a
    # multi-line #define), not code: the layout rules do not reach it.
    continuation = [False] * len(lines)
    for i in range(1, len(lines)):
        if lines[i].strip() and lines[i - 1].rstrip().endswith("\\"):
            continuation[i] = True

    for i in range(len(lines)):
        if not stripCode(lines[i]) or isComment(lines[i]):
            continue

        if continuation[i]:
            continue

        if isScopeBlock(lines, i):
            close = blockEnd(lines, i)
            checkSeparators(rel, lines, i, close + 1, prose)
            continue

        if not HEADER_RE.match(lines[i]):
            continue

        checkBodyNotSeparated(rel, lines, i)

        if ELSE_RE.match(lines[i]):
            continue          # a chain member: the chain start already judged the spacing

        last, trailing = headerEnd(lines, i)
        if trailing.startswith("//"):
            trailing = ""
        if trailing == "{":
            violations.append(f"{rel}:{i + 1}: brace on the control line (docs/internals/coding-rules.md §6)")
        elif trailing:
            violations.append(f"{rel}:{i + 1}: single-line conditional, the body goes on the "
                              f"next line (docs/internals/coding-rules.md §6)")
            continue

        if not re.match(r'^\s*(if|for|while|switch)\b', lines[i]):
            continue                      # `do` carries a block, which the brace rule covers
        if stripCode(lines[last]) != "" and last != i and stripCode(lines[last]).endswith(";"):
            violations.append(f"{rel}:{last + 1}: conditional body belongs on the next line "
                              f"(docs/internals/coding-rules.md §6)")

        checkSeparators(rel, lines, i, chainEnd(lines, i), prose)


def band_of(path):
    for prefix, band in BAND_OF_DIR.items():
        if path.startswith(prefix + os.sep) or path == prefix:
            return band
    return None


SOURCE_ROOTS = ("src", "tools", "test", "examples", "vendor")

# An example is an application: it may include the façade it stands on, the codecs beside it, the substrate and the
# port's contract, and nothing below them. The band says what a host program may reach and this says what an example
# may, which is narrower because an example is documentation: a layer header here would mean the façade is missing a
# door (D-216), and a platform header would tie the example to one target (D-276). The examples' own modules under
# examples/common/ and the vendored U_SStream they write their files with are theirs too, and so is a header in the
# example's own directory. `zdo_client.h` is the ZDP client's codecs, which ZB_ZDO_CLIENT builds.
EXAMPLE_INCLUDES = {
    "zb_stack.h", "zcl.h", "zdo.h", "zdo_client.h", "zb_status.h",
    "zb_utils.h", "zb_time.h", "zb_bstream.h", "zb_assert.h",
    "port.h", "port_file.h",
    "ex_config.h", "u_sstream.h",
}


def sourceFiles(root, only=None):
    for rootName in (only or SOURCE_ROOTS):
        base = os.path.join(root, rootName)
        if not os.path.isdir(base):
            continue
        for directory, dirs, files in os.walk(base):
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))
            for name in sorted(files):
                if name.endswith((".c", ".h")):
                    yield os.path.relpath(os.path.join(directory, name), root)


def checkExampleIncludes(root, rel, lines):
    """An example reaches for the façade and not for the layers under it."""
    if not rel.startswith("examples" + os.sep):
        return

    for number, line in enumerate(lines, 1):
        match = re.match(r'\s*#\s*include\s+"([^"]+)"', line)

        if match is None:
            continue

        if match.group(1) in EXAMPLE_INCLUDES or os.path.isfile(os.path.join(root, os.path.dirname(rel),
                                                                             match.group(1))):
            continue

        violations.append(f"{rel}:{number}: an example includes {match.group(1)}, which is under the surface it "
                              f"stands on")


def guardMacros(lines):
    guards = set()
    for line in lines:
        match = GUARD_IFDEF_RE.match(line)
        if match:
            guards.add(match.group(1))
    for line in lines:
        match = GUARD_DEFINE_RE.match(line)
        if match and match.group(1) in guards:
            guards.add(match.group(1))
    return guards


def isPlatformConditional(line, guards):
    if not COND_RE.match(line):
        return False
    names = [n for n in re.findall(r'[A-Za-z_][A-Za-z0-9_]*', line)
             if n not in ("if", "ifdef", "ifndef", "defined") and n not in guards]
    return any(PLATFORM_MACRO_RE.match(n) for n in names)


def resolveInclude(root, rel, target):
    found = []
    for prefix in BAND_OF_DIR:
        base = os.path.join(root, prefix)
        if not os.path.isdir(base):
            continue
        for directory, dirs, files in os.walk(base):
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))
            hit = os.path.relpath(os.path.join(directory, target), root)
            # A directory with a band of its own inside another band's is walked from both prefixes
            if target in files and hit not in found:
                found.append(hit)
    candRel = os.path.relpath(os.path.join(os.path.dirname(os.path.join(root, rel)), target), root)
    if os.path.exists(os.path.join(root, candRel)) and candRel not in found:
        found.append(candRel)
    if not found:
        return None
    if len(found) > 1:
        violations.append(f"{rel}: include '{target}' resolves to more than one module header "
                          f"({', '.join(found)})")
        return None
    return found[0]


def isHostTestFile(rel):
    # Programs that run on the host and are not part of the shipped library: our own suites
    # and tools, and the test programs that came with a vendored library. They may use the
    # hosted C library; the bands and the vendored library code may not.
    if rel.startswith("test/") or rel.startswith("tools/"):
        return True
    return rel.startswith("vendor/") and os.sep + "tests" + os.sep in rel


def codeLines(lines):
    """The file with C comments removed, block comments tracked across lines.

    A keyword rule about C usage that also reads prose reports a documentation sentence as a
    violation: `A Spinel bool is one octet` is a statement about the protocol, not the C type.
    """
    out = []
    inBlock = False

    for line in lines:
        text = line

        if inBlock:
            end = text.find("*/")
            if end == -1:
                out.append("")
                continue
            text = text[end + 2:]
            inBlock = False

        parts = []
        i = 0

        while i < len(text):
            block = text.find("/*", i)
            lineComment = text.find("//", i)

            if lineComment != -1 and (block == -1 or lineComment < block):
                parts.append(text[i:lineComment])
                i = len(text)
                break

            if block == -1:
                parts.append(text[i:])
                i = len(text)
                break

            parts.append(text[i:block])
            close = text.find("*/", block + 2)
            if close == -1:
                inBlock = True
                i = len(text)
                break
            i = close + 2

        out.append(stripLiterals("".join(parts)))

    return out


def stripLiterals(text):
    """Blank out string and character literals.

    A diagnostic message that names the protocol's bool datatype is not a use of the C type, and
    a rule that reports one teaches a reader to distrust the rule.
    """
    out = []
    i = 0

    while i < len(text):
        ch = text[i]

        if ch == '"' or ch == "'":
            quote = ch
            i += 1

            while i < len(text):
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1

            out.append(" ")
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def checkFile(root, rel):
    band = band_of(rel)
    if band is None:
        violations.append(f"{rel}: not inside a known band directory")
        return

    path = os.path.join(root, rel)
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        lines = handle.read().split("\n")
    guards = guardMacros(lines)
    codes = codeLines(lines)

    for number, line in enumerate(lines, 1):
        code = codes[number - 1]
        match = INCLUDE_RE.match(line)
        if match:
            form, target = match.group(1), match.group(2)
            if form == "<":
                if target in PLATFORM_HEADERS and rel not in PLATFORM_HEADER_FILES \
                        and band not in PLATFORM_INCLUDE_DIRS:
                    violations.append(f"{rel}:{number}: platform header <{target}> outside the port module")
                if not isHostTestFile(rel) and band in BYTE_TEXT_BANDS and target in BYTE_TEXT_HEADERS:
                    violations.append(f"{rel}:{number}: <{target}>, byte and text primitives come "
                                      f"from src/utils (docs/internals/coding-rules.md §1)")
                elif target == "stddef.h" and band in STRICT_BANDS.union({"port"}) \
                        and not isHostTestFile(rel):
                    if not any("offsetof" in line for line in lines):
                        violations.append(f"{rel}:{number}: <stddef.h> with no offsetof, a null pointer "
                                          f"constant is written 0, not NULL (docs/internals/coding-rules.md §1)")
                elif not isHostTestFile(rel) and band in STRICT_BANDS \
                        and target not in FREESTANDING_HEADERS and target not in PLATFORM_HEADERS:
                    violations.append(f"{rel}:{number}: <{target}> in a band that must compile "
                                      f"freestanding (C99 §4)")
            else:
                target_rel = resolveInclude(root, rel, target)
                if target_rel is None:
                    violations.append(f'{rel}:{number}: quoted include "{target}" resolves to no module')
                else:
                    target_band = band_of(target_rel)
                    if target_band is not None and target_band != band \
                            and target_band not in ALLOWED[band]:
                        violations.append(
                            f'{rel}:{number}: {band} includes {target_band} header "{target}"')

        if not rel.startswith(tuple(PLATFORM_INCLUDE_DIRS)) and band not in CONDITION_EXEMPT_BANDS \
                and isPlatformConditional(line, guards):
            violations.append(f"{rel}:{number}: platform conditional outside src/port/ and tools/")

        if band in STYLE_EXEMPT_BANDS:
            continue

        if band in ("protocol", "seam", "provider") and SIZE_T_RE.search(code):
            violations.append(f"{rel}:{number}: size_t outside the port boundary")
        if band == "port" and rel.endswith(".h") and SIZE_T_RE.search(code):
            violations.append(f"{rel}:{number}: size_t in a public port header")

        if BOOL_RE.search(code):
            violations.append(f"{rel}:{number}: bool/_Bool; booleans are int 0/1")
        if band != "vendor" and NULL_RE.search(code):
            violations.append(f"{rel}:{number}: NULL, test a pointer with !ptr / ptr and write a "
                              f"null pointer constant as 0 (docs/internals/coding-rules.md §1)")
        if ALLOC_RE.search(code):
            violations.append(f"{rel}:{number}: dynamic allocation")

        match = LITERAL_SUFFIX_RE.search(code)
        if match:
            violations.append(f"{rel}:{number}: integer literal suffix ({match.group(0)}); "
                              f"width comes from the declaration")


    if band != "vendor":
        checkLayout(rel, lines)


# The component table of src/log/log.h, parsed as `#define NAME 0xHEX` lines:
# sections are one byte, components are section in the top byte and topic in the low byte
# (docs/internals/coding-rules.md §5).
LOG_CODE_RE = re.compile(r'^\s*#\s*define\s+(LOG_(?:SECTION|COMP)_[A-Za-z0-9_]+)\s+(0[xX][0-9a-fA-F]+)\s*$')


# The .c files of the crypto band that carry no header of their own: one contract header
# (src/crypto/aes.h) serves the modes module and the candidate block implementations, of which
# exactly one is linked per build (the CMake option ZB_AES_IMPLEMENTATION), the table candidate
# joining the exemption. The port's file calls are the same shape: one contract header (src/port/port_file.h) and one
# backend per target, linked by the build (D-278), and so is the stick lookup's platform half (D-282).
SEAM_IMPLS = {"src/crypto/aes_modes", "src/crypto/aes_scalar", "src/crypto/aes_table", "src/port/port_file_posix",
              "src/port/port_locate_sysfs", "src/port/port_locate_darwin", "src/port/port_locate_linux"}


def checkModulePairs(root):
    names = set()
    for rel in sourceFiles(root, only=("src",)):
        base, ext = os.path.splitext(rel)
        names.add((base, ext))
    for base, ext in sorted(names):
        if base in SEAM_IMPLS:
            continue
        if ext == ".c" and (base, ".h") not in names:
            violations.append(f"{base}.c: no matching {base}.h (one module per .c/.h pair)")


STREAM_DECL_RE = re.compile(r"\bU_BStream\s*\*?\s*(\w+)")


def checkStreamFields(root):
    """A U_BStream's fields belong to the vendored code and src/utils/zb_bstream: every other source in src/
    asks through the calls (docs/internals/coding-rules.md §1). A stream is known by the names a file declares
    with the type, and by the struct members and parameters src/ headers declare with it."""
    sources = [rel for rel in sourceFiles(root, ("src",)) if not rel.startswith(os.path.join("src", "utils") + os.sep)]
    shared = set()
    texts = {}

    for rel in sources:
        with open(os.path.join(root, rel), "r", encoding="utf-8", errors="replace") as handle:
            texts[rel] = codeLines(handle.read().split("\n"))

        if rel.endswith(".h"):
            shared.update(m.group(1) for line in texts[rel] for m in STREAM_DECL_RE.finditer(line))

    for rel in sources:
        names = set(shared)
        names.update(m.group(1) for line in texts[rel] for m in STREAM_DECL_RE.finditer(line))
        names.discard("U_BStream")

        if not names:
            continue

        field = re.compile(r"\b(" + "|".join(sorted(names)) + r")(\.|->)(data|pos|size|status)\b")

        for number, line in enumerate(texts[rel], 1):
            if field.search(line):
                violations.append(f"{rel}:{number}: a U_BStream field read outside src/utils/, ask through "
                                  f"zb_bstream (docs/internals/coding-rules.md §1)")


def checkLogCodes(root):
    """The component table of src/log/log.h: sections distinct, every component inside one
    declared section's range, and no value twice (docs/internals/coding-rules.md §5)."""
    rel = "src/log/log.h"
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        return

    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        lines = handle.read().split("\n")

    sections = []
    components = []

    for line in lines:
        match = LOG_CODE_RE.match(line)
        if not match:
            continue
        value = int(match.group(2), 16)
        if match.group(1).startswith("LOG_SECTION_"):
            sections.append((match.group(1), value))
        else:
            components.append((match.group(1), value))

    for i, (name, value) in enumerate(sections):
        for other in sections[i + 1:]:
            if other[1] == value:
                violations.append(f"{rel}: section {name} and {other[0]} share value {value:#04x} "
                                  f"(docs/internals/coding-rules.md §5)")

    declared = {value for _, value in sections}
    for name, value in components:
        if value != 0x0000 and value >> 8 not in declared:
            violations.append(f"{rel}: component {name} = {value:#06x} is not inside any declared "
                              f"section's range (docs/internals/coding-rules.md §5)")

    for i, (name, value) in enumerate(components):
        for other in components[i + 1:]:
            if other[1] == value:
                violations.append(f"{rel}: components {name} and {other[0]} share value {value:#06x} "
                                  f"(docs/internals/coding-rules.md §5)")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    checked = 0
    for rel in sourceFiles(root):
        checked += 1
        checkFile(root, rel)
        checkExampleIncludes(root, rel, open(os.path.join(root, rel)).read().splitlines())
    checkModulePairs(root)
    checkLogCodes(root)
    checkStreamFields(root)

    for violation in violations:
        print(f"BAND VIOLATION: {violation}")
    if violations:
        print(f"bands: {len(violations)} violations over {checked} files")
        return 1
    print(f"bands: ok ({checked} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
