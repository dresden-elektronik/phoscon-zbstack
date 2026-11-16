#!/usr/bin/env python3
"""Raw port capture: opens a stick's serial link, writes nothing to it, and records
the bytes the operating system delivers. The output is a fixture for the C99 port
suites (docs/internals/testing.md §4), so the transcript is exactly what a port must survive:
arbitrary splits of a byte stream that carries HDLC frames.

Read-only by construction: this tool never issues a byte to the device.
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from spinel_probe import DEFAULT_BAUD, open_port, resolve_port  # noqa: E402


def capture(path, baud, seconds, max_bytes):
    import select

    fd = open_port(path, baud)
    collected = bytearray()
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline and len(collected) < max_bytes:
            remaining = max_bytes - len(collected)
            if remaining > 4096:
                remaining = 4096
            try:
                ready, _, _ = select.select([fd], [], [], 0.25)
            except OSError:
                break
            if not ready:
                continue
            try:
                chunk = os.read(fd, remaining)
            except BlockingIOError:
                continue
            except OSError:
                break
            if not chunk:
                continue
            collected += chunk
    finally:
        os.close(fd)
    return bytes(collected)


def main():
    ap = argparse.ArgumentParser(description="raw port byte capture (never transmits)")
    ap.add_argument("--device", default=None,
                    help="a name the file ZB_DEVICE_MAP maps to a port; --port wins")
    ap.add_argument("--port", help="explicit device path; overrides --device")
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--seconds", type=float, default=10.0)
    ap.add_argument("--bytes", type=int, default=4096)
    ap.add_argument("--out", required=True, help="fixture file to write")
    args = ap.parse_args()

    path = resolve_port(args.port, args.device)

    data = capture(path, args.baud, args.seconds, args.bytes)
    if not data:
        print("no bytes delivered; nothing written", file=sys.stderr)
        return 1

    with open(args.out, "wb") as handle:
        handle.write(b"# raw byte transcript, captured without writing to the device\n")
        handle.write(f"# source {path} baud {args.baud}\n".encode())
        for start in range(0, len(data), 16):
            handle.write(b" ".join(b"%02x" % b for b in data[start:start + 16]) + b"\n")

    print(f"{args.out}: {len(data)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
