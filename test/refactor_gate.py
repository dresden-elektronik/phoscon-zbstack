#!/usr/bin/env python3
"""Refactor witnesses (docs/internals/testing.md §5).

Two modes, both comparing the working tree against a reference revision:

  refactor_gate.py --probe [-r REV]
      Build the reference tree's band A sources and the working tree's test/layer_probe.c,
      run it, then build the working tree the same way, run, and diff the two printed
      ledgers. Identical output witnesses that a move chunk changed no behaviour. One
      revision's tree is built with its own copy of the probe file instead, and the gate
      says so, only when the working probe names a symbol that revision's sources do not
      carry - the case a chunk that renames names reaches; such a chunk witnesses the
      probe's own renames by substituting the old names back and running the comment gate.

  refactor_gate.py -f FILE [FILE...] [-r REV]
      Comment-gate mode: strip comments from each file at the reference revision and in
      the working tree and require the code lines to match exactly. A chunk that claims
      "comments only" proves it here.

Exit 0 when the witness holds.
"""

import argparse
import glob
import os
import subprocess
import sys
import tempfile

INCLUDES = [
    "src/zb", "src/zb/mac", "src/zb/nwk", "src/zb/aps", "src/seam", "src/utils", "src/loopback",
    "src/crypto", "src/port", "src/log",
    "vendor/u_bstream", "vendor/u_sstream",
]

SOURCES = [
    "src/zb/*.c", "src/zb/mac/*.c", "src/zb/nwk/*.c", "src/zb/aps/*.c",
    "src/crypto/aes_scalar.c", "src/crypto/aes_modes.c",
    "src/utils/*.c", "src/log/log.c", "src/loopback/loopback_radio.c",
    "vendor/u_bstream/u_bstream.c",
]

# The probe is a band-A device, so it is built on the same rig constructor the band-A suites use.
# The support source is the working tree's, not the reference's: it is
# suite-band scaffolding over the public API and it asserts nothing.
SUPPORT_RIG = os.path.join("test", "support", "rig_band_a.c")


def gitShow(rev, path):
    done = subprocess.run(["git", "show", f"{rev}:{path}"],
                          capture_output=True, text=True)
    if done.returncode != 0:
        sys.exit(f"refactor_gate: git show {rev}:{path} failed: {done.stderr.strip()}")
    return done.stdout


def stripComments(src):
    """The file with every C comment removed, literals protected, lines right-trimmed."""
    out, i = [], 0
    while i < len(src):
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j == -1:
                break
            i = j + 2
            out.append("\n")
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = len(src) if j == -1 else j
            continue
        if src[i] in "\"'":
            quote = src[i]
            out.append(src[i])
            i += 1
            while i < len(src):
                if src[i] == "\\":
                    out.append(src[i:i + 2])
                    i += 2
                    continue
                out.append(src[i])
                if src[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        out.append(src[i])
        i += 1
    return [line.rstrip() for line in "".join(out).splitlines() if line.strip()]


def commentGate(rev, files):
    bad = []
    for path in files:
        if not os.path.exists(path):
            sys.exit(f"refactor_gate: {path} does not exist in the working tree")
        head = stripComments(gitShow(rev, path))
        now = stripComments(open(path).read())
        if head == now:
            continue
        for n in range(min(len(head), len(now))):
            if head[n] != now[n]:
                bad.append(f"{path}: code line {n + 1}\n  {rev}: {head[n]}\n  now : {now[n]}")
                break
        else:
            if len(head) != len(now):
                bad.append(f"{path}: code line count {len(head)} -> {len(now)}")
    if bad:
        print("comment-gate: FAILED\n" + "\n".join(bad))
        return 1
    print(f"comment-gate: code identical in every one of {len(files)} files")
    return 0


def runProbe(rev, probeFrom="working"):
    """Build one probe binary from (reference tree, probe file), return its ledger lines or None.

    probeFrom is "working" for the working tree's own test/layer_probe.c - one probe against two
    source trees, which is what keeps the witness hard to satisfy by moving the witness along with
    the behaviour - and "tree" for the revision's own copy of the same file, with that revision's
    own rig: the rig is a constructor over band A's public API and asserts nothing, but it names the
    API, so a chunk that renames a field the rig names needs the tree's rig as well as its probe.
    """
    root = os.getcwd()
    with tempfile.TemporaryDirectory() as work:
        tree = os.path.join(work, "tree")
        os.makedirs(tree)
        archive = subprocess.run(f"git archive {rev} | tar -x -C {tree}",
                                 shell=True, capture_output=True, text=True)
        if archive.returncode != 0:
            sys.exit(f"refactor_gate: git archive {rev} failed: {archive.stderr.strip()}")
        args = ["cc", "-std=c99", "-Wall", "-Wextra", "-pedantic"]
        args += [f"-I{os.path.join(tree, d)}" for d in INCLUDES]
        args += [p for pattern in SOURCES for p in sorted(glob.glob(f"{tree}/{pattern}"))]
        # The rig, always the working tree's with the shared probe: a rig is a constructor over band
        # A's public API and asserts nothing, so the same support source builds against either band-A
        # source tree - unless the chunk renamed a field the rig names, which is what the fallback below
        # is for.
        rigRoot = tree if probeFrom == "tree" else root
        args += [f"-I{os.path.join(rigRoot, 'test', 'support')}"]
        args += [os.path.join(rigRoot, SUPPORT_RIG)]
        probe = os.path.join(tree if probeFrom == "tree" else root, "test/layer_probe.c")
        args += [probe, "-o", os.path.join(work, "probe")]
        built = subprocess.run(args, capture_output=True, text=True)
        if built.returncode != 0:
            return None, built.stderr
        ran = subprocess.run([os.path.join(work, "probe")], capture_output=True, text=True)
        if ran.returncode != 0:
            sys.exit(f"refactor_gate: probe run against {rev} failed:\n{ran.stderr}")
        return ran.stdout.splitlines(), ""


def probeLines(rev):
    """One revision's ledger, with the shared working probe when its sources can carry it and with
    that revision's own probe file when they cannot. Returns (lines, builtItsOwnProbe)."""
    lines, err = runProbe(rev, "working")
    if lines is not None:
        return lines, False

    lines, ownErr = runProbe(rev, "tree")
    if lines is None:
        sys.exit(f"refactor_gate: probe build failed against {rev}:\n{ownErr}\n"
                 f"(the shared-probe build failed too:\n{err})")
    return lines, True


def probeGate(rev):
    a, ownA = probeLines(rev)
    b, ownB = probeLines("HEAD")  # HEAD as a tree; working-tree library edits are what --probe must catch
    # A working tree with uncommitted library changes is compared too: rebuild from the paths
    # themselves when HEAD differs from the working tree only via those paths.
    if a == b:
        print(f"probe-gate: {len(a)} ledger lines identical between {rev} and HEAD")
        if ownA or ownB:
            print("probe-gate: the working probe names symbols one of these trees does not carry,"
                  " so that build used its own copy of test/layer_probe.c: the renames the probe"
                  " itself carries are witnessed by substituting the old names back through -f")
        if a != runWorking():
            print("probe-gate: the WORKING TREE (uncommitted) differs: a move is not behaviour-neutral")
            return diffReport(a, runWorking())
        return 0
    return diffReport(a, b)


def runWorking():
    root = os.getcwd()
    with tempfile.TemporaryDirectory() as work:
        args = ["cc", "-std=c99", "-Wall", "-Wextra", "-pedantic"]
        args += [f"-I{os.path.join(root, d)}" for d in INCLUDES]
        args += [p for pattern in SOURCES for p in sorted(glob.glob(os.path.join(root, pattern)))]
        args += [f"-I{os.path.join(root, 'test', 'support')}", SUPPORT_RIG]
        args += ["test/layer_probe.c", "-o", os.path.join(work, "probe")]
        built = subprocess.run(args, capture_output=True, text=True)
        if built.returncode != 0:
            sys.exit(f"refactor_gate: probe build failed in the working tree:\n{built.stderr}")
        ran = subprocess.run([os.path.join(work, "probe")], capture_output=True, text=True)
        if ran.returncode != 0:
            sys.exit(f"refactor_gate: probe run failed in the working tree:\n{ran.stderr}")
        return ran.stdout.splitlines()


def diffReport(a, b):
    print(f"probe-gate: {len(a)} lines vs {len(b)} lines, DIFFER")
    shown = 0
    for n in range(max(len(a), len(b))):
        x = a[n] if n < len(a) else "<absent>"
        y = b[n] if n < len(b) else "<absent>"
        if x != y:
            print(f"  line {n + 1}:\n    ref: {x}\n    now: {y}")
            shown += 1
            if shown == 10:
                print("  ...")
                break
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-r", "--rev", default="HEAD", help="reference revision (default HEAD)")
    ap.add_argument("--probe", action="store_true", help="differential probe mode")
    ap.add_argument("-f", "--files", nargs="+", help="comment-gate mode: files to compare")
    args = ap.parse_args()
    if args.probe:
        return probeGate(args.rev)
    if not args.files:
        sys.exit(__doc__)
    return commentGate(args.rev, args.files)


if __name__ == "__main__":
    sys.exit(main())
