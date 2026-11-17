#!/usr/bin/env python3
"""Freestanding gate: the code that is not a per-target
backend must compile with no hosted C library at all, and (when the compiler can target
WebAssembly) as a wasm object. This is what makes "portable C99, WASM later" a measured
property instead of an intention.

Usage: freestanding_audit.py [repo-root] [compiler]
"""

import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bands_audit  # one definition of what a platform header is, shared with the band audit

CFLAGS = ["-std=c99", "-ffreestanding", "-Wall", "-Wextra", "-pedantic"]
# Derived, not listed: every directory under src/ and each vendored library's own
# directory. A gate that has to be told about a new module is a gate that misses it.
PER_TARGET_ROOT = "src/port"


def firstLines(text, count=3):
    lines = [line for line in text.strip().splitlines() if line.strip()]
    return " | ".join(lines[:count]) if lines else "compiled with diagnostics"


def run(command):
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True)


def platformBackends(root):
    """Files under src/port/ that include a platform header are per-target backends: they
    are excluded from the gate because they are the code the gate exists to isolate."""
    backends = []
    for rel in bands_audit.sourceFiles(root, only=("src",)):
        if not rel.endswith(".c") or not rel.startswith(PER_TARGET_ROOT + "/"):
            continue
        with open(os.path.join(root, rel), "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                match = bands_audit.INCLUDE_RE.match(line)
                if match and match.group(1) == "<" and match.group(2) in bands_audit.PLATFORM_HEADERS:
                    backends.append(rel)
                    break
    return backends


def includeDirs(root):
    dirs = []
    for base in ("src", "vendor"):
        for directory, subdirs, files in os.walk(os.path.join(root, base)):
            dirs.append("-I" + directory)          # absolute: ctest runs suites from build/
            if base == "vendor" and directory != os.path.join(root, base):
                subdirs[:] = []
    return dirs


def portableSources(root):
    excluded = set(platformBackends(root))
    return [rel for rel in bands_audit.sourceFiles(root, only=("src",))
            if rel.endswith(".c") and rel not in excluded], excluded


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    compiler = sys.argv[2] if len(sys.argv) > 2 else (shutil.which("clang") or shutil.which("cc"))
    if not compiler:
        print("freestanding: skipped, no C compiler found")
        return 0

    sources, backends = portableSources(root)
    if not sources:
        print("freestanding: FAIL, no portable source found under src/")
        return 1

    outDir = os.path.join(root, "build", "freestanding")
    os.makedirs(outDir, exist_ok=True)
    includes = includeDirs(root)

    failures = []

    # The gate is two things: no hosted header in the portable set, and a compile that needs
    # no hosted library. A compile alone would still pass with <string.h> present.
    for rel in sources:
        with open(os.path.join(root, rel), "r", encoding="utf-8", errors="replace") as handle:
            for number, line in enumerate(handle, 1):
                match = bands_audit.INCLUDE_RE.match(line)
                if match and match.group(1) == "<" \
                        and match.group(2) not in bands_audit.FREESTANDING_HEADERS:
                    failures.append(f"{rel}:{number}: <{match.group(2)}> is not a freestanding header")

    for rel in sources:
        obj = os.path.join(outDir, rel.replace("/", "_") + ".o")
        result = run([compiler] + CFLAGS + includes + ["-c", os.path.join(root, rel), "-o", obj])
        if result.returncode != 0 or result.stdout.strip():
            failures.append(f"{rel}: {firstLines(result.stdout)}")

    wasmNote = ""
    probe = run([compiler, "-print-targets"])
    if probe.returncode == 0 and "wasm32" in probe.stdout:
        wasmSources = sources          # per-target backends are already out of `sources`
        for rel in wasmSources:
            obj = os.path.join(outDir, rel.replace("/", "_") + ".wasm")
            result = run([compiler] + CFLAGS + ["-nostdlib", "-target", "wasm32", "-O2"]
                         + includes + ["-c", os.path.join(root, rel), "-o", obj])
            if result.returncode != 0 or result.stdout.strip():
                failures.append(f"{rel} (wasm32): {firstLines(result.stdout)}")
        wasmNote = f", {len(wasmSources)} as wasm32 objects"
    else:
        wasmNote = ", wasm32 target not offered by this compiler"

    for failure in failures:
        print(f"FREESTANDING FAIL: {failure}")
    if failures:
        print(f"freestanding: {len(failures)} failures")
        return 1

    print(f"freestanding: ok ({len(sources)} sources compiled with -ffreestanding and no "
          f"hosted header{wasmNote}; {len(backends)} per-target backend(s) excluded)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
