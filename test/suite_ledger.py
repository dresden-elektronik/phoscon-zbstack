#!/usr/bin/env python3
"""The suite ledger (docs/internals/testing.md §2).

A suite is a name and a ledger, not a file. Renaming or splitting a suite's source files
must not change what the suite proves, so this records, per ctest name, the ordered list of
case functions its executable drives and the number of assertions it makes, summed over
every source file the executable is built from.

  suite_ledger.py            print the ledger
  suite_ledger.py --write    write test/suite_ledger.json (the committed baseline)
  suite_ledger.py --check    compare against the baseline, exit 1 on any difference
"""

import json
import os
import re
import sys

def ledgerRoot():
    """The tree to read: this script's tree, or ZB_LEDGER_ROOT for a captured baseline."""
    return os.environ.get("ZB_LEDGER_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


ROOT = ledgerRoot()
LEDGER = os.path.join(ROOT, "test", "suite_ledger.json")

EXEC_RE = re.compile(r"^\s*add_executable\(\s*([A-Za-z0-9_]+)\s+([^)]*)\)", re.M)
TEST_RE = re.compile(r"^\s*add_test\(\s*NAME\s+([A-Za-z0-9_/.]+)\s+COMMAND\s+([A-Za-z0-9_]+)(?:\s+[^)]*)?\)", re.M)
MAIN_CALL_RE = re.compile(r"^\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*;", re.M)
CASE_DEF_RE = re.compile(r"^(?:static\s+)?void\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*void\s*\)", re.M)
# The assertion family, by the name it is spelled with: a suite that carries its own `expect`/`expectStatus`
# and one that calls the shared `Test_Expect*` family in test/support make
# the same assertion, so moving a suite onto the harness leaves this count where it was. The harness's own
# definitions are not counted: test/support is built into each suite through the `zb_test_support` interface
# target rather than listed in an `add_executable`, so no suite's source set contains them.
ASSERT_RE = re.compile(r"\b(?:Test_)?[Ee]xpect[A-Za-z]*\s*\(")
# A definition is not an assertion: the harness bodies and any suite-local helper body are excluded,
# so a suite's number is its CALL SITES and moving a helper into test/support is invisible to the ledger.
ASSERT_DEF_RE = re.compile(r"^(?:static\s+)?(?:void|int|uint32_t)\s+(?:Test_)?[Ee]xpect[A-Za-z]*\s*\(", re.M)


def readText(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def sourceSet(raw):
    names = []
    for token in raw.split():
        if token.endswith(".c"):
            names.append(token)
    return names


def stripComments(src):
    out, i = [], 0
    while i < len(src):
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = len(src) if j == -1 else j + 2
            out.append(" ")
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = len(src) if j == -1 else j
            continue
        if src[i] in "\"'":
            quote = src[i]
            i += 1
            while i < len(src):
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == quote:
                    i += 1
                    break
                i += 1
            out.append(" ")
            continue
        out.append(src[i])
        i += 1
    return "".join(out)


def definedCases(sources):
    """The functions the suite defines itself: `void name(void)`. A case call names one of these."""
    names = set()
    for path in sources:
        names.update(CASE_DEF_RE.findall(stripComments(readText(path))))
    names.discard("main")
    return names


def caseOrder(sources):
    """The ordered list of case calls inside the executable's main().

    A call counts only when the suite defines it as `void name(void)`: an empty-paren `printf( )`
    left behind by literal blanking is not a case, and a suite that calls a helper in main says so
    by defining it the same way.
    """
    cases = definedCases(sources)
    for path in sources:
        code = stripComments(readText(path))
        start = code.find("int main(")
        if start == -1:
            continue
        end = code.find("\n}", start)
        body = code[start:end] if end != -1 else code[start:]
        return [name for name in MAIN_CALL_RE.findall(body) if name in cases]
    return []


def assertionCount(sources):
    total = 0
    for path in sources:
        code = stripComments(readText(path))
        total += len(ASSERT_RE.findall(code)) - len(ASSERT_DEF_RE.findall(code))
    return total


def buildLedger():
    cmake = readText(os.path.join(ROOT, "test", "CMakeLists.txt"))
    executables = {}
    for name, raw in EXEC_RE.findall(cmake):
        executables[name] = sourceSet(raw)
    ledger = {}
    for suite, exe in TEST_RE.findall(cmake):
        if suite.startswith("u_sstream/"):
            continue  # vendored, not ours to shape
        sources = [os.path.join(ROOT, "test", rel) for rel in executables.get(exe, [])]
        sources = [path for path in sources if os.path.exists(path)]
        if not sources:
            continue
        cases = caseOrder(sources)
        ledger[suite] = {
            "executable": exe,
            "assertions": assertionCount(sources),
            "cases": len(cases),
            "caseOrder": cases,
        }
    return dict(sorted(ledger.items()))


def render(ledger):
    lines = [f"{len(ledger)} suites",
             f"{sum(entry['assertions'] for entry in ledger.values())} assertions",
             f"{sum(entry['cases'] for entry in ledger.values())} cases", ""]
    for suite, entry in ledger.items():
        lines.append(f"{suite:16s} {entry['cases']:3d} cases {entry['assertions']:4d} assertions")
    return "\n".join(lines)


def compare(baseline, current):
    problems = []
    for suite in sorted(set(baseline) | set(current)):
        if suite not in current:
            problems.append(f"{suite}: missing (was {baseline[suite]['cases']} cases)")
            continue
        if suite not in baseline:
            problems.append(f"{suite}: new suite, no baseline row")
            continue
        old, new = baseline[suite], current[suite]
        if old["assertions"] != new["assertions"]:
            problems.append(f"{suite}: assertions {old['assertions']} -> {new['assertions']}")
        if old["caseOrder"] != new["caseOrder"]:
            if sorted(old["caseOrder"]) == sorted(new["caseOrder"]):
                problems.append(f"{suite}: case ORDER changed, same set")
            else:
                lost = [c for c in old["caseOrder"] if c not in new["caseOrder"]]
                gained = [c for c in new["caseOrder"] if c not in old["caseOrder"]]
                problems.append(f"{suite}: cases changed (lost {lost or 'none'}, gained {gained or 'none'})")
    return problems


def main():
    ledger = buildLedger()
    if "--write" in sys.argv:
        with open(LEDGER, "w", encoding="utf-8") as handle:
            json.dump(ledger, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"suite ledger written: {len(ledger)} suites, "
              f"{sum(e['assertions'] for e in ledger.values())} assertions -> {LEDGER}")
        return 0
    if "--check" in sys.argv:
        if not os.path.exists(LEDGER):
            sys.exit("suite ledger: no baseline; run --write first")
        baseline = json.load(open(LEDGER, "r", encoding="utf-8"))
        problems = compare(baseline, ledger)
        if problems:
            print("suite ledger: FAILED")
            for line in problems:
                print(f"  {line}")
            return 1
        print(f"suite ledger: unchanged across {len(ledger)} suites, "
              f"{sum(e['assertions'] for e in ledger.values())} assertions, "
              f"{sum(e['cases'] for e in ledger.values())} cases")
        return 0
    print(render(ledger))
    return 0


if __name__ == "__main__":
    sys.exit(main())
