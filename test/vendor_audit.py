#!/usr/bin/env python3
"""Vendor integrity gate (docs/internals/refs.md §6): every file under vendor/ must be
byte-identical to the revision recorded in vendor/MANIFEST.

This is what makes vendoring honest: the copy is verbatim, drift is a build failure,
and a capability the library lacks is an upstream change, not a local patch.

Usage: vendor_audit.py [repo-root]
"""

import hashlib
import os
import sys

INCLUDE_RE = __import__("re").compile(r'^\s*#\s*include\s*[<"]([^">]+)[">]')
ALLOC_RE = __import__("re").compile(r'\b(malloc|calloc|realloc|free|alloca)\s*\(')
LIBC_HEADERS = {
    "stdio.h", "stdlib.h", "string.h", "assert.h", "math.h", "time.h", "errno.h",
    "unistd.h", "termios.h", "fcntl.h", "ctype.h", "stdint.h", "stddef.h",
}
LIBRARY_LIBC_ALLOWED = {"stdint.h", "stddef.h"}


def fail(violations, text):
    violations.append(text)


def parseManifest(root):
    libraries = []
    current = None
    with open(os.path.join(root, "vendor", "MANIFEST"), "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            if line == "[library]":
                current = {"files": {}}
                libraries.append(current)
                continue
            if line == "[files]":
                continue
            if "=" not in line or current is None:
                continue
            key, value = line.split("=", 1)
            if key == "name":
                current["name"] = value
            elif key in ("upstream", "commit", "latest_tag", "license"):
                current[key] = value
            else:
                current["files"][key] = value
    return libraries


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checkLibrary(root, library, violations):
    name = library.get("name")
    if not name:
        fail(violations, "MANIFEST: a [library] block has no name")
        return
    base = os.path.join(root, "vendor", name)
    if not os.path.isdir(base):
        fail(violations, f"vendor/{name}: pinned upstream {library.get('upstream')} is not vendored")
        return

    licenseFile = os.path.join(base, "LICENSE.txt")
    if not os.path.isfile(licenseFile):
        fail(violations, f"vendor/{name}: no LICENSE.txt alongside the vendored code")

    listed = library["files"]
    for rel, expected in sorted(listed.items()):
        path = os.path.join(base, rel)
        if not os.path.isfile(path):
            fail(violations, f"vendor/{name}/{rel}: listed in MANIFEST but missing from the tree")
            continue
        actual = sha256(path)
        if actual != expected:
            fail(violations, f"vendor/{name}/{rel}: modified locally ({actual[:12]} != {expected[:12]})")

    for directory, dirs, files in os.walk(base):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for fileName in sorted(files):
            rel = os.path.relpath(os.path.join(directory, fileName), base)
            if rel not in listed:
                fail(violations, f"vendor/{name}/{rel}: present in the tree but not pinned in MANIFEST")

    for rel in listed:
        if not rel.endswith((".c", ".h")):
            continue
        path = os.path.join(base, rel)
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for number, line in enumerate(handle, 1):
                if ALLOC_RE.search(line):
                    fail(violations, f"vendor/{name}/{rel}:{number}: dynamic allocation in vendored code")
                match = INCLUDE_RE.match(line)
                isTestFile = rel.startswith("tests/")
                if match and not isTestFile and match.group(1) in LIBC_HEADERS \
                        and match.group(1) not in LIBRARY_LIBC_ALLOWED:
                    fail(violations,
                         f"vendor/{name}/{rel}:{number}: vendored library code includes <{match.group(1)}>, "
                         f"so it is not usable by a libc-free band")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    manifest = os.path.join(root, "vendor", "MANIFEST")
    if not os.path.isfile(manifest):
        print("VENDOR VIOLATION: vendor/MANIFEST missing")
        return 1

    violations = []
    libraries = parseManifest(root)
    if not libraries:
        print("VENDOR VIOLATION: vendor/MANIFEST pins no library")
        return 1
    for library in libraries:
        checkLibrary(root, library, violations)

    for violation in violations:
        print(f"VENDOR VIOLATION: {violation}")
    if violations:
        print(f"vendor: {len(violations)} violations")
        return 1

    for library in libraries:
        print(f"vendor: {library['name']} pinned to {library['commit'][:12]} "
              f"({library['upstream']}), {len(library['files'])} files verified, {library['license']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
