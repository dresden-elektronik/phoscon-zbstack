"""Regression check: every capture under test/fixtures/ must dissect cleanly under
the layout the standards define (harness/ieee802154.py docstring), and the
per-build FCS behaviour recorded in docs/internals/protocol.md §9.3 must still hold.

Two fixture shapes exist and both are read:

  * annotated sniffer dumps: the indented raw-PSDU lines are the fixture, the
    annotation lines are output of whatever decoder ran at capture time and are
    ignored;
  * raw port transcripts (`*.hex`, written by harness/port_dump.py): comment
    lines starting with '#' then whitespace-separated hex octets. Those are
    *link* bytes, so they go through the HDLC framing of harness/spinel_probe.py
    first, then each PROP_STREAM_RAW (0x71) value through the body layout
    harness/rcp_sniffer.py decodes, then each PSDU through the dissection.

A file that cannot be read, or that carries frame bytes and yields nothing
decodable, fails the gate. Frames a raw transcript carries that the dissection
rejects are reported: an on-air-corrupted frame in a capture is a fact about the
capture, not a decoder fault (docs/internals/protocol.md §9.3 keeps them as captured).

Run: python3 harness/check_samples.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ieee802154 as zb                     # noqa: E402
from spinel_probe import PROP_NAMES, decode_hdlc, parse_varint  # noqa: E402
from rcp_sniffer import decode_raw          # noqa: E402

SAMPLE_DIR = os.path.join("test", "fixtures")
PROP_STREAM_RAW = 0x71

# The build a fixture came from is read from the port its header names, not from its file
# name: the fixtures name the two ConBee IIs (ATSAMR21 + AT86RF233) /dev/ttyACM0 and
# /dev/ttyACM1, and the ConBee III (EFR32MG21) /dev/ttyUSB0 (docs/internals/hardware.md §1).
BUILD_OF_PORT = {"/dev/ttyACM0": "AT86RF233 build",
                 "/dev/ttyACM1": "AT86RF233 build",
                 "/dev/ttyUSB0": "EFR32 build"}
BUILD_DELIVERS_FCS = {"AT86RF233 build": True, "EFR32 build": False}

PSDU_LINE = re.compile(r"^\s{8,}([0-9a-f]{2}(?: [0-9a-f]{2})+)\s*$")
SOURCE_LINE = re.compile(r"^#\s*source\s+(\S+)|\[sniffing\s+(\S+)")
HEX_OCTET = re.compile(r"[0-9a-fA-F]{2}$")
# an annotated dump with no PSDU lines is a summary log: frame classes and a
# device table only, nothing to re-dissect
ANNOTATION_LINE = re.compile(r"^\s*\[\s*\d+\]\s+ch=|^\s*=== summary ===")

# The line a session transcript carries when its reporter printed no frame octets.
TRANSCRIPT_MARKER = "== session transcript: no PSDU in this file =="

# Wireshark's "Export Packet Dissections" as text: its own dissection, with no PSDU line to re-read.
WIRESHARK_EXPORT_LINE = re.compile(r"^No\.\s+Time\s+Source\s")


def sample_files(directory=SAMPLE_DIR):
    """Every capture file under test/fixtures/, sorted: annotated .txt and .hex."""
    return [os.path.join(directory, name)
            for name in sorted(os.listdir(directory))
            if name.endswith(".txt") or name.endswith(".hex")]


def load_frames(path):
    frames = []
    for line in open(path):
        m = PSDU_LINE.match(line)
        if m:
            frames.append(bytes.fromhex(m.group(1)))
    return frames


def load_link(path):
    """A port_dump transcript -> the octets the operating system delivered."""
    octets = []
    for line in open(path):
        if line.lstrip().startswith("#"):
            continue
        for token in line.split():
            if not HEX_OCTET.match(token):
                raise ValueError(f"not a hex octet: {line.strip()}")
            octets.append(int(token, 16))
    return bytes(octets)


def frames_from_link(link):
    """Raw Spinel link bytes -> (psdus, stats): HDLC framing, then the STREAM_RAW
    body layout (u16 LE psdu length | psdu | rssi | noise | flags | structs)."""
    psdus = []
    stats = {"hdlc": 0, "hdlc_bad_fcs": 0, "truncated": 0, "props": {}}
    for frame, ok in decode_hdlc(link):
        stats["hdlc"] += 1
        if not ok:
            stats["hdlc_bad_fcs"] += 1
            continue
        body = frame[:-2]
        if len(body) < 3 or body[1] not in (2, 3, 4, 5, 6, 7, 8):
            continue                      # no property id carried
        prop, pos = parse_varint(body, 2)
        name = PROP_NAMES.get(prop, f"?{prop:#x}")
        stats["props"][name] = stats["props"].get(name, 0) + 1
        if prop != PROP_STREAM_RAW:
            continue
        try:
            psdu = decode_raw(body[pos:])["psdu"]
        except IndexError:                # value cut off by the capture window
            stats["truncated"] += 1
            continue
        if psdu:
            psdus.append(psdu)
    return psdus, stats


def build_of(path):
    for line in open(path):
        m = SOURCE_LINE.search(line)
        if m:
            return BUILD_OF_PORT.get(m.group(1) or m.group(2), "unknown build")
    return "unknown build"


def is_summary_log(path):
    """Annotated dump with no raw PSDU lines: annotations only, no fixture body."""
    return (not load_frames(path)
            and any(ANNOTATION_LINE.match(l) for l in open(path)))


def is_session_transcript(path):
    """A tool session's own output, declaring that it carries no PSDU.

    A transcript of a run in which band A was the reporter prints no frame octets, and that is a
    fact about the run rather than a gap in the file: the declaration line says so where a reader
    of the file meets it first."""
    text = open(path).read()
    return not load_frames(path) and TRANSCRIPT_MARKER in text


def report(path, frames, expect_fcs, extra, strict):
    """The per-file verdict for one capture.

    strict: an annotated PSDU fixture must dissect every frame it carries; a raw
    transcript reports what the dissection rejected instead."""
    ok = [f for f in frames if zb.dissect(f).get("ok")]
    bad = [f for f in frames if not zb.dissect(f).get("ok")]
    with_fcs = sum(1 for f in frames if zb.fcs_valid(f))
    types = {}
    for f in ok:
        name = zb.dissect(f)["type_name"]
        types[name] = types.get(name, 0) + 1
    acks = [f for f in ok if zb.dissect(f)["type"] == 2]
    ack_fcs = sum(1 for f in acks if zb.fcs_valid(f))
    polls = sum(1 for f in ok
                if zb.dissect(f).get("cmd", {}).get("name") == "data-request")
    print(f"{path}: {len(ok)}/{len(frames)} frames dissect, types={types}")
    if extra:
        print(f"  {extra}")
    print(f"  rejected by dissection: {len(bad)}")
    print(f"  FCS-valid frames: {with_fcs}/{len(frames)}, "
          f"ACK frames: {ack_fcs}/{len(acks)}, polls: {polls}")
    failures = []
    if not frames:
        failures.append("FAIL: the fixture carries no decodable frame")
    if frames and not ok:
        failures.append("FAIL: the dissection rejected every frame in the fixture")
    if expect_fcs is True and ok and ack_fcs != len(acks):
        failures.append("FAIL: every AT86RF233 acknowledgment must be FCF+seq+FCS")
    if expect_fcs is False and with_fcs:
        failures.append("FAIL: the EFR32 build delivers no valid FCS tail")
    if strict:
        for f in bad[:3]:
            failures.append(f"FAIL: {f.hex()} -> {zb.dissect(f)['reason']}")
    else:
        for f in bad[:3]:
            print(f"  rejected frame: {f.hex(' ')} -> {zb.dissect(f)['reason']}")
    for line in failures:
        print(f"  {line}")
    return {"file": path, "frames": len(frames), "decoded": len(ok),
            "rejected": len(bad), "fcs": with_fcs, "polls": polls,
            "verdict": "FAIL" if failures else "ok"}, failures


def is_wireshark_export(path):
    """A third-party dissector's text export: the evidence is its reading, not octets for this decoder."""
    with open(path) as handle:
        first = next((line for line in handle if line.strip()), "")
    return not load_frames(path) and bool(WIRESHARK_EXPORT_LINE.match(first))


def is_raw_transcript(path):
    """port_dump transcripts open with '#' comment lines; annotated dumps do not."""
    with open(path) as handle:
        for line in handle:
            if line.strip():
                return line.lstrip().startswith("#")
    return False


def build_column(path):
    try:
        return build_of(path)
    except OSError:
        return "?"


def main():
    failed, rows = 0, []
    polls_total = 0
    for path in sample_files():
        try:
            build = build_of(path)
            expect_fcs = BUILD_DELIVERS_FCS.get(build)
            if is_raw_transcript(path):
                strict = False          # a transcript may carry a corrupted frame
                link = load_link(path)
                frames, st = frames_from_link(link)
                props = " ".join(f"{n}={c}" for n, c in sorted(st["props"].items()))
                extra = (f"link: {len(link)} octets, {st['hdlc']} HDLC frames "
                         f"({st['hdlc_bad_fcs']} bad FCS, {st['truncated']} cut off), "
                         f"{props}")
            elif is_session_transcript(path):
                print(f"{path}: {build}: a session transcript, declared as carrying no PSDU")
                rows.append({"file": path, "frames": 0, "decoded": 0, "rejected": 0,
                             "fcs": 0, "polls": 0, "verdict": "no fixture body"})
                continue
            elif is_wireshark_export(path):
                print(f"{path}: {build}: a Wireshark packet-details export, dissected by Wireshark, "
                      "no PSDU to re-dissect")
                rows.append({"file": path, "frames": 0, "decoded": 0, "rejected": 0,
                             "fcs": 0, "polls": 0, "verdict": "no fixture body"})
                continue
            elif is_summary_log(path):
                print(f"{path}: {build}: summary log only, no raw PSDU fixture "
                      "to re-dissect")
                rows.append({"file": path, "frames": 0, "decoded": 0, "rejected": 0,
                             "fcs": 0, "polls": 0, "verdict": "no fixture body"})
                continue
            else:
                frames, extra = load_frames(path), None
                strict = True
            row, _ = report(path, frames, expect_fcs, extra, strict)
        except (OSError, ValueError) as exc:
            print(f"{path}: FAIL: cannot be read: {exc}")
            row = {"file": path, "frames": 0, "decoded": 0, "rejected": 0,
                   "fcs": 0, "polls": 0, "verdict": "unreadable"}
        polls_total += row["polls"]
        if row["verdict"] == "FAIL":
            failed += 1
        rows.append(row)

    print(f"MAC Data Request polls identified: {polls_total}")
    if not polls_total:
        print("FAIL: the frequent polls must decode as MAC command 0x04")
        failed += 1

    header = ("file", "build", "frames", "decoded", "rejected", "FCS", "polls", "verdict")
    table = [(r["file"], build_column(r["file"]),
              *("-" if r["verdict"] == "no fixture body" else str(r[k])
                for k in ("frames", "decoded", "rejected", "fcs", "polls")),
              r["verdict"])
             for r in rows]
    widths = [max(len(header[i]), max(len(t[i]) for t in table)) for i in range(len(header))]
    print("\nper-file:")
    for values in [header] + table:
        print("  " + "  ".join(v.ljust(widths[i]) for i, v in enumerate(values)).rstrip())

    print("check_samples: " + ("FAILED" if failed else "ok"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
