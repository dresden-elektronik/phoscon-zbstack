#!/usr/bin/env python3
"""Compiled size estimate of band A for the ConBee II MCU (ATSAMR21E18A,
Cortex-M0+ Thumb). The source set is read from CMakeLists.txt: the
targets band A links (zb_mac, zb_utils, zb_log, zb_crypto at its default scalar
AES implementation, and the vendored u_bstream), so the figure cannot drift
from the build. The flags are the
sibling project's toolchain description (docs/internals/hardware.md §1 owns the silicon)
plus the freestanding gate's: -mcpu=cortex-m0plus -mthumb -Os -std=c99
-ffunction-sections -fdata-sections -fno-common -ffreestanding -Wall -Wextra
-pedantic.

The image is linked three times: once with every section kept (upper bound),
and twice with --gc-sections rooting a public surface, because the library has
two tiers (docs/internals/decisions.md D-210): `zb_layers`, the transport an application
composes over, and `zb_core`, the surface an application uses, which carries
the endpoint registry, the device object and the binding table with it. The
library's own RAM shows as the image's data/bss: the pools are caller-owned
state, so it stays zero. Two extras are reported, not part of band A: libgcc
(Cortex-M0+ has no 64-bit arithmetic or divide) and a memcpy/memset provider
(the compiler lowers struct copies to memcpy calls; a real target satisfies
them from newlib(-nano)).

Usage: band_a_size.py [repo-root] [compiler-prefix]
"""

import os
import re
import shutil
import subprocess
import sys


def run(command):
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True)


def firstLines(text, count=3):
    lines = [line for line in text.strip().splitlines() if line.strip()]
    return " | ".join(lines[:count]) if lines else ""


def includeDirs(root):
    dirs = []
    for base in ("src", "vendor"):
        for directory, subdirs, _ in os.walk(os.path.join(root, base)):
            dirs.append("-I" + directory)
            if base == "vendor" and directory != os.path.join(root, base):
                subdirs[:] = []
    return dirs


# The ConBee II's compile, which tools/mem_size.py measures the structs with too.
M0_FLAGS = ["-mcpu=cortex-m0plus", "-mthumb", "-Os", "-std=c99",
            "-ffunction-sections", "-fdata-sections", "-fno-common",
            "-ffreestanding", "-Wall", "-Wextra", "-pedantic"]

# The targets band A links, in CMake's own names: the walk that used to stand here drifted from the build once
# already, and a size figure measured over a source set the build does not link is not a figure.
LIBRARY_TARGETS = ("zb_mac", "zb_utils", "zb_log", "zb_crypto", "u_bstream")


def librarySources(root):
    """The `.c` files CMake compiles into the targets band A links, read from CMakeLists.txt itself."""
    text = open(os.path.join(root, "CMakeLists.txt")).read()
    out = []

    for target in LIBRARY_TARGETS:
        match = re.search(r"add_library\(" + re.escape(target) + r"\b([^)]*)\)", text, re.S)

        if not match:
            raise SystemExit(f"band_a_size: CMakeLists.txt has no add_library({target})")

        body = match.group(1)
        body = body.replace("${ZB_AES_IMPLEMENTATION}", "scalar")

        for name in re.findall(r"[\w./${}-]+\.c\b", body):
            if name.startswith(("src/", "vendor/")):
                out.append(name)

    return sorted(set(out))


def sizeOf(executable, path):
    result = run([executable, path])
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if line.strip().endswith(os.path.basename(path)):
            fields = line.split()
            if len(fields) >= 4 and fields[0].isdigit():
                return (int(fields[0]), int(fields[1]), int(fields[2]))  # text, data, bss
    return None


def mapTaggedSizes(path, marker="Linker script and memory map"):
    """The contribution lines after the memory-map marker: (addr, size, source)."""
    live = False
    for line in open(path):
        if marker in line:
            live = True
            continue
        if not live:
            continue
        match = re.match(r"^\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)\s+(\S+)\s*$", line)
        if match:
            yield int(match.group(1), 16), match.group(2)


def libgccFromMap(path):
    total = 0
    for size, source in mapTaggedSizes(path):
        if "libgcc.a" in source and size > 0:
            total += size
    return total


SHIM = """
/* probe-only provider: what a real target supplies from newlib(-nano).
   Byte-at-a-time, the same shape as src/utils/zb_utils.c. Not part of the tree. */
#include <stddef.h>
void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    size_t i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}
void *memset(void *dst, int value, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    size_t i;
    for (i = 0; i < n; i++) d[i] = (unsigned char)value;
    return dst;
}
"""

# the two public surfaces, src/zb/zb_layers.h and src/zb/zb_core.h: the roots an application pulls
STUB_TRANSPORT = """
/* probe entry: reference the transport facade so --gc-sections keeps what an application composing over it pulls
   and drops what it would not. The element reads are real: a pointer-to-array test optimizes away. */
#include "zb_layers.h"
void *facade[] = {
    (void *)&Zb_LayersInit, (void *)&Zb_LayersStep, (void *)&Zb_LayersPollConfirms,
    (void *)&Zb_LayersPollIndications, (void *)&Zb_LayersDataRequest, (void *)&Zb_LayersMac,
    (void *)&Zb_LayersNwk, (void *)&Zb_LayersAps, (void *)&Zb_LayersSecurity,
    (void *)&Zb_LayersExtendedPanId, (void *)&Zb_LayersCapture, (void *)&Zb_LayersRestore,
};
int main(void) { return facade[0] == 0 && facade[11] == 0; }
"""

STUB_DEVICE = """
/* probe entry: the same, rooted on the surface an application actually stands on, which is the device facade and
   everything it composes: the stack, the endpoint registry, the device object and the binding table. */
#include "zb_core.h"
void *facade[] = {
    (void *)&Zb_CoreInit, (void *)&Zb_CoreStep, (void *)&Zb_CoreRegisterEndpoint,
    (void *)&Zb_CoreSendRequest, (void *)&Zb_CorePollIndications, (void *)&Zb_CorePollConfirms,
    (void *)&Zb_CoreAnnounce, (void *)&Zb_CorePermitJoining, (void *)&Zb_CoreLeave,
    (void *)&Zb_CoreLayers, (void *)&Zb_CoreAps, (void *)&Zb_CoreNwk,
    (void *)&Zb_CoreMac, (void *)&Zb_CoreBindings, (void *)&Zb_CoreEndpointCount,
    (void *)&Zb_CoreZdpFramesConsumed, (void *)&Zb_CoreAnnouncementsRepublished,
    (void *)&Zb_CoreIndicationsDropped, (void *)&Zb_CoreIsRunning,
    (void *)&Zb_CoreLastZdpCluster, (void *)&Zb_CoreLastZdpProfile, (void *)&Zb_CoreLastZdpEndpoint,
};
int main(void) { return facade[0] == 0 && facade[21] == 0; }
"""


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    if root.startswith("-") or not os.path.isfile(os.path.join(root, "CMakeLists.txt")):
        print("usage: band_a_size.py [repo-root] [compiler-prefix]: the root is this tree, which holds CMakeLists.txt")
        return 2

    prefix = sys.argv[2] if len(sys.argv) > 2 else "arm-none-eabi-"
    cc = shutil.which(prefix + "gcc")
    if not cc:
        print(f"band_a_size: skipped, no {prefix}gcc on PATH")
        return 0

    size = prefix + "size"
    outDir = os.path.join(root, "build", "band_a_size")
    os.makedirs(outDir, exist_ok=True)
    includes = includeDirs(root)
    flags = M0_FLAGS

    sources = librarySources(root)
    errors = []
    notes = []
    perObject = []
    for rel in sources:
        obj = os.path.join(outDir, rel.replace(os.sep, "_") + ".o")
        result = run([cc] + flags + includes + ["-c", os.path.join(root, rel), "-o", obj])
        if result.returncode != 0:
            errors.append(f"{rel}: {firstLines(result.stdout)}")
            continue
        if result.stdout.strip():
            lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            message = next((line for line in lines if "warning" in line or "error" in line), lines[0])
            notes.append(f"{rel}: {message.replace(root + os.sep, '')}")
        measured = sizeOf(size, obj)
        if measured:
            perObject.append((measured[0], os.path.basename(rel)))

    if errors:
        for error in errors:
            print(f"band_a_size: {error}")
        print(f"band_a_size: {len(errors)} failure(s)")
        return 1

    for name, body in (("shim.c", SHIM), ("stub_transport.c", STUB_TRANSPORT), ("stub_device.c", STUB_DEVICE)):
        with open(os.path.join(outDir, name), "w") as handle:
            handle.write(body)
        result = run([cc, "-mcpu=cortex-m0plus", "-mthumb", "-Os", "-std=c99",
                      "-ffunction-sections", "-fdata-sections", "-ffreestanding"]
                     + includes + ["-c", os.path.join(outDir, name),
                                   "-o", os.path.join(outDir, name.replace(".c", ".o"))])
        if result.returncode != 0:
            print(f"band_a_size: probe {name} failed: {firstLines(result.stdout)}")
            return 1

    objects = [os.path.join(outDir, rel.replace(os.sep, "_") + ".o") for rel in sources]
    shimObj = os.path.join(outDir, "shim.o")
    stubObjects = {"transport": os.path.join(outDir, "stub_transport.o"),
                   "device": os.path.join(outDir, "stub_device.o")}

    linkSpecs = [
        ("upper bound, every section", "size_all", "transport", None, False),
        ("gc'd, transport facade", "size_gc_transport", "transport", "map_gc_transport.map", True),
        ("gc'd, device facade", "size_gc_device", "device", "map_gc_device.map", True),
    ]
    results = {}
    for label, name, tier, mapFile, gc in linkSpecs:
        out = os.path.join(outDir, name)
        command = [cc, "-mcpu=cortex-m0plus", "-mthumb", "-Os", "-nostdlib",
                   "-Wl,--entry=main"]
        if gc:
            command = [cc, "-mcpu=cortex-m0plus", "-mthumb", "-Os", "-nostdlib",
                       "-Wl,--gc-sections,--entry=main"]
        if mapFile:
            command.append("-Wl,-Map=" + os.path.join(outDir, mapFile))
        result = run(command + [shimObj, stubObjects[tier]] + objects + ["-o", out, "-lgcc"])
        if result.returncode != 0:
            print(f"band_a_size: link ({label}) failed: {firstLines(result.stdout)}")
            return 1
        measured = sizeOf(size, out)
        if not measured:
            print(f"band_a_size: could not read size of {name}")
            return 1
        libgcc = libgccFromMap(os.path.join(outDir, mapFile)) if mapFile else 0
        results[label] = (measured, libgcc)

    shimSize = sizeOf(size, shimObj)
    transportStub = sizeOf(size, stubObjects["transport"])
    deviceStub = sizeOf(size, stubObjects["device"])
    (upperText, upperData, upperBss), _ = results["upper bound, every section"]
    (gcText, gcData, gcBss), gcLibgcc = results["gc'd, transport facade"]
    (deviceText, deviceData, deviceBss), deviceLibgcc = results["gc'd, device facade"]
    provider = shimSize[0] + transportStub[0]
    project = gcText - gcLibgcc - provider
    deviceProject = deviceText - deviceLibgcc - shimSize[0] - deviceStub[0]
    libraryRam = deviceBss + max(deviceData - deviceStub[1], 0)

    top = sorted(perObject, reverse=True)[:5]
    print("band_a_size: band A, Cortex-M0+ Thumb -Os (ConBee II, ATSAMR21E18A)")
    print(f"  {len(sources)} objects compiled; "
          f"object sum {sum(t for t, _ in perObject)} B text")
    print(f"  flash, gc'd device facade    {deviceText:6d} B   "
          f"(project {deviceProject} + libgcc {deviceLibgcc} + probe {shimSize[0] + deviceStub[0]})")
    print(f"  flash, gc'd transport facade {gcText:6d} B   "
          f"(project {project} + libgcc {gcLibgcc} + probe {provider})")
    print(f"  flash, upper bound           {upperText:6d} B   (data {upperData} B)")
    print(f"  RAM, library's own           {libraryRam:6d} B   "
          f"(state is caller-owned; the image's {deviceData} B data is the probe's reference array)")
    print("  top objects: " + "  ".join(f"{name} {text}" for text, name in top))
    print("  chip: 215 KiB flash, 32 KiB RAM (the vendor's linker-script regions)")
    for note in notes:
        print(f"  diagnostic, {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
