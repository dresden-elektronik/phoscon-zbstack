#!/usr/bin/env python3
"""Minimal Spinel-over-HDLC probe for the ConBee III (R21, RCP firmware).

Stage-1 seed harness for phoscon_zbstack. Python 3 stdlib only.

Protocol constants verified against OpenThread:
  - src/lib/hdlc/hdlc.cpp          (HDLC-lite: flag 0x7E, escape 0x7D^0x20,
                                     CRC-16/CCITT-X25, FCS little-endian)
  - src/lib/spinel/spinel.h        (SPINEL_CMD_*, SPINEL_PROP_*)
  - src/lib/spinel/spinel_interface.hpp (reset frame = [0x80, 0x01])

Usage:
  spinel_probe.py [--port <path>] [--baud 115200]
  spinel_probe.py --listen [seconds]
"""

import argparse
import os
import select
import sys

# The port calls are POSIX; the decoders below are not, so a host without termios (Windows) still imports them.
try:
    import termios
    import tty
except ImportError:
    termios = tty = None

DEFAULT_PORT = None  # no port is ever defaulted: several RCPs of one kind share a name prefix


def load_devices():
    """A bench's RCPs by the names its user gives them, from the file ZB_DEVICE_MAP names:
    one `name path` pair per line, `#` starting a comment. Nothing is built in."""
    devices = {}
    path = os.environ.get("ZB_DEVICE_MAP")
    if not path:
        return devices
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) >= 2 and not fields[0].startswith("#"):
                    devices[fields[0]] = fields[1]
    except OSError:
        pass
    return devices


def resolve_port(port, device):
    """The --port given, else the path --device names in ZB_DEVICE_MAP; exit when neither names one."""
    if port:
        return port
    if device and device in DEVICES:
        return DEVICES[device]
    sys.exit("name the RCP's port with --port, or a --device that the file ZB_DEVICE_MAP names")


DEVICES = load_devices()
DEFAULT_BAUD = 115200

# Known-answer: HDLC-encoded Spinel Reset (payload [0x80, 0x01]).
# Verified against the FCS table in src/lib/hdlc/hdlc.cpp.
SPINEL_RESET_PAYLOAD = bytes([0x80, 0x01])
KNOWN_ANSWER_RESET = b"\x7e\x80\x01\x02\x92\x7e"  # host->RCP Spinel reset

# Property IDs (src/lib/spinel/spinel.h, verified): 0=LAST_STATUS, 1=PROTOCOL_VERSION,
# 2=NCP_VERSION (string), 3=NCP_TYPE. GET frame = [0x80, 0x02, prop-as-varint].
SPINEL_CMD_RESET = 1
SPINEL_CMD_PROP_VALUE_GET = 2
SPINEL_CMD_PROP_VALUE_SET = 3

# --- HDLC (per src/lib/hdlc/hdlc.cpp) ---
FLAG = 0x7E
ESCAPE = 0x7D
NEEDS_ESCAPE = {0x11, 0x13, 0x7D, 0x7E, 0xF8}


def crc16(data: bytes) -> int:
    """CRC-16/CCITT-X25: poly 0x8408, init 0xFFFF, xorout 0xFFFF."""
    fcs = 0xFFFF
    for b in data:
        fcs ^= b
        for _ in range(8):
            fcs = (fcs >> 1) ^ (0x8408 if fcs & 1 else 0)
    return fcs ^ 0xFFFF


def encode_hdlc(payload: bytes) -> bytes:
    body = bytearray()

    def put(b: int) -> None:
        if b in NEEDS_ESCAPE:
            body.append(ESCAPE)
            body.append(b ^ 0x20)
        else:
            body.append(b)

    for b in payload:
        put(b)
    fcs = crc16(payload)
    put(fcs & 0xFF)
    put(fcs >> 8)
    return bytes([FLAG]) + bytes(body) + bytes([FLAG])


assert encode_hdlc(SPINEL_RESET_PAYLOAD) == KNOWN_ANSWER_RESET, "encoder regression"


class HdlcStream:
    """A decoder that keeps what a read cut in half.

    A stick's frames arrive wherever the USB serial layer chose to end a read, so one frame is often
    split across two reads and a fresh frame can begin in the same buffer that ends another. A decoder
    that starts over at every read therefore drops the first half of one frame and misreads the second
    half as garbage. This one carries the partial frame, and the escape it was in the middle of, to the
    next call (the C side carries the same state in Hdlc_Decoder).

    A run with no flag in it is not a frame: after HDLC_STREAM_MAX octets of it the partial is dropped
    and the search resumes at the next flag, so noise on a link cannot grow the buffer without bound.
    """

    def __init__(self):
        self.cur = None
        self.escaped = False
        self.since_flag = 0

    def feed(self, data: bytes):
        cur = self.cur
        escaped = self.escaped
        since_flag = self.since_flag

        for b in data:
            if b == FLAG:
                if cur is not None and len(cur) >= 3:
                    ok = crc16(cur[:-2]) == int.from_bytes(cur[-2:], "little")
                    yield bytes(cur), ok
                cur = []
                escaped = False
                since_flag = 0
                continue

            if cur is None:
                continue

            since_flag += 1

            if since_flag > HDLC_STREAM_MAX:
                cur = []
                escaped = False
                since_flag = 0
                continue

            if b == ESCAPE:
                escaped = True
                continue

            if escaped:
                cur.append(b ^ 0x20)
                escaped = False
            else:
                cur.append(b)

        self.cur = cur
        self.escaped = escaped
        self.since_flag = since_flag


HDLC_STREAM_MAX = 4096


def decode_hdlc(data: bytes):
    """One buffer at a time: the whole stream is in hand, nothing carries over."""
    yield from HdlcStream().feed(data)


def _selfcheck_hdlc_stream():
    """Every split of one frame must yield that frame once, and no half of it."""
    frame = encode_hdlc(SPINEL_RESET_PAYLOAD)
    wanted = (SPINEL_RESET_PAYLOAD + crc16(SPINEL_RESET_PAYLOAD).to_bytes(2, "little"), True)

    for cut in range(1, len(frame)):
        stream = HdlcStream()
        got = list(stream.feed(frame[:cut])) + list(stream.feed(frame[cut:]))
        assert got == [wanted], f"frame split at {cut} decoded as {got}"

    # A frame that begins in the buffer that ends another is not lost, and neither is an escape at the cut.
    both = encode_hdlc(SPINEL_RESET_PAYLOAD) + encode_hdlc(SPINEL_RESET_PAYLOAD)
    stream = HdlcStream()
    assert len(list(stream.feed(both))) == 2, "two frames in one buffer"

    escaped = encode_hdlc(bytes([FLAG, ESCAPE, 0x7e, 0x01]))
    cut = len(escaped) - 3
    stream = HdlcStream()
    assert len(list(stream.feed(escaped[:cut])) + list(stream.feed(escaped[cut:]))) == 1, "escape split"

    stream = HdlcStream()
    junk = bytes([0x01] * (HDLC_STREAM_MAX + 500))
    got = list(stream.feed(junk)) + list(stream.feed(encode_hdlc(SPINEL_RESET_PAYLOAD)))
    assert got == [wanted], f"noise longer than the cap must not swallow the frame after it: {got}"


_selfcheck_hdlc_stream()


# --- Spinel decoding (per src/lib/spinel/spinel.h) ---
FRAME_TYPE_NAMES = {0: "notification", 1: "response", 2: "command"}
CMD_NAMES = {
    0: "NOOP", 1: "RESET", 2: "PROP_VALUE_GET", 3: "PROP_VALUE_SET",
    4: "PROP_VALUE_INSERT", 5: "PROP_VALUE_REMOVE", 6: "PROP_VALUE_IS",
    7: "PROP_VALUE_INSERTED", 8: "PROP_VALUE_REMOVED",
}
PROP_NAMES = {
    0: "LAST_STATUS", 1: "PROTOCOL_VERSION", 2: "NCP_VERSION", 3: "INTERFACE_TYPE",
    4: "VENDOR_ID", 5: "CAPS", 6: "INTERFACE_COUNT",
    0x07: "POWER_STATE", 0x08: "HWADDR",
    0x20: "PHY_ENABLED", 0x21: "PHY_CHAN", 0x22: "PHY_CHAN_SUPPORTED",
    0x23: "PHY_FREQ", 0x24: "PHY_CCA_THRESHOLD", 0x25: "PHY_TX_POWER",
    0x26: "PHY_RSSI", 0x27: "PHY_RX_SENSITIVITY",
    0x30: "MAC_SCAN_STATE", 0x31: "MAC_SCAN_MASK", 0x32: "MAC_SCAN_PERIOD",
    0x33: "MAC_SCAN_BEACON", 0x39: "MAC_ENERGY_SCAN_RESULT",
    0x3A: "MAC_DATA_POLL_PERIOD",
    0x34: "MAC_15_4_LADDR", 0x35: "MAC_15_4_SADDR", 0x36: "MAC_15_4_PANID",
    0x37: "MAC_RAW_STREAM_ENABLED", 0x38: "MAC_PROMISCUOUS_MODE",
    0x3B: "MAC_RX_ON_WHEN_IDLE", 0x41: "MAC_SRC_MATCH_ENABLED",
    0x70: "STREAM_NET", 0x71: "STREAM_RAW",
    0xB0: "RCP_API_VERSION", 0xB1: "RCP_MIN_HOST_API_VERSION",
    0xB2: "RCP_LOG_CRASH_DUMP",
    0x802: "RCP_TIMESTAMP", 0x804: "RCP_CSL_ACCURACY", 0x805: "RCP_CSL_UNCERTAINTY",
    0x1008: "UNSOL_UPDATE_FILTER", 0x1009: "UNSOL_UPDATE_LIST",
    0x120B: "RADIO_CAPS",
}

# from SPINEL_CAP_* in OpenThread's src/lib/spinel/spinel.h
CAP_NAMES = {
    1: "LOCK", 2: "NET_SAVE", 3: "HBO", 4: "POWER_SAVE", 5: "COUNTERS",
    6: "JAM_DETECT", 7: "PEEK_POKE", 8: "WRITABLE_RAW_STREAM", 9: "GPIO",
    10: "TRNG", 11: "CMD_MULTI", 12: "UNSOL_UPDATE_FILTER", 13: "MCU_POWER_STATE",
    14: "PCAP", 16: "802_15_4__BEGIN", 24: "802_15_4_2450MHZ_OQPSK",
    32: "CONFIG_FTD", 33: "CONFIG_MTD", 34: "CONFIG_RADIO",
    48: "ROLE_ROUTER", 49: "ROLE_SLEEPY", 52: "NET_THREAD_1_0",
    53: "NET_THREAD_1_1", 54: "NET_THREAD_1_2",
    64: "RCP_API_VERSION", 65: "RCP_MIN_HOST_API_VERSION", 67: "RCP_LOG_CRASH_DUMP",
    512: "OPENTHREAD__BEGIN", 513: "MAC_RAW",
}

# OT_RADIO_CAPS_* bit positions (RADIO_CAPS value is a packed-uint bitfield).
# OpenThread's src/lib/spinel/spinel.h defines no SPINEL_RADIO_CAPS_* bits at all and
# radio_spinel.cpp casts the wire value straight to otRadioCaps, so the wire
# numbering IS otRadioCaps: docs/internals/hardware.md §4 decodes the measured 0x10d as
# ACK_TIMEOUT/TRANSMIT_RETRIES/CSMA_BACKOFF/RX_ON_WHEN_IDLE, which only this
# numbering reproduces (RX_ON_WHEN_IDLE is bit 8 of the newer enum).
RADIO_CAP_BITS = {0: "ACK_TIMEOUT", 1: "ENERGY_SCAN", 2: "TRANSMIT_RETRIES",
                  3: "CSMA_BACKOFF", 4: "SLEEP_TO_TX", 5: "TRANSMIT_SEC",
                  6: "TRANSMIT_TIMING", 7: "RECEIVE_TIMING", 8: "RX_ON_WHEN_IDLE"}
STATUS_NAMES = {
    0: "OK", 1: "FAILURE", 2: "UNIMPLEMENTED", 3: "INVALID_ARGUMENT",
    4: "INVALID_STATE", 5: "INVALID_COMMAND", 6: "INVALID_INTERFACE",
    7: "INTERNAL_ERROR", 8: "SECURITY_ERROR", 9: "PARSE_ERROR",
    10: "IN_PROGRESS", 11: "NOMEM", 12: "BUSY", 13: "PROP_NOT_FOUND",
    14: "DROPPED", 15: "EMPTY", 112: "RESET_POWER_ON", 114: "RESET_SOFTWARE",
    # names above only as far as docs/internals/protocol.md §5 states them (112, 114); 113/115
    # are seen on no measured RCP and are not named by any doc here.
}


def decode_radio_caps(value: int) -> str:
    """Name the OT_RADIO_CAPS_* bits of a RADIO_CAPS value (docs/internals/hardware.md §4)."""
    names = [RADIO_CAP_BITS[b] for b in sorted(RADIO_CAP_BITS) if value >> b & 1]
    names += [f"bit{b}" for b in range(32)
              if b not in RADIO_CAP_BITS and value >> b & 1]
    return " ".join(names) if names else "NONE"


# known-answer regression: docs/internals/hardware.md §4 decodes the measured ConBee II value
# 0x10d as ACK_TIMEOUT, TRANSMIT_RETRIES, CSMA_BACKOFF, RX_ON_WHEN_IDLE.
assert decode_radio_caps(0x10d) == "ACK_TIMEOUT TRANSMIT_RETRIES CSMA_BACKOFF " \
                                   "RX_ON_WHEN_IDLE"
assert decode_radio_caps(0) == "NONE"
assert decode_radio_caps(0x1000) == "bit12"  # unnamed bits stay explicit


def parse_varint(buf: bytes, pos: int):
    val = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
    return val, pos


def parse_spinel(frame: bytes, fcs_ok: bool) -> str:
    """frame = payload only (FCS bytes already stripped)."""
    if not fcs_ok:
        return "  !! FCS MISMATCH"
    if len(frame) < 2:
        return "  (short frame)"
    b0 = frame[0]
    ftype = (b0 >> 6) & 3
    iid = (b0 >> 4) & 3
    tid = b0 & 0x0F
    cmd = frame[1]
    out = (f"  type={FRAME_TYPE_NAMES.get(ftype, ftype)} iid={iid} tid={tid} "
           f"cmd={CMD_NAMES.get(cmd, f'?{cmd}')}")
    rest = frame[2:]
    if cmd in (2, 3, 4, 5, 6, 7, 8):  # property commands carry a property id
        if rest:
            prop, pos = parse_varint(rest, 0)
            out += f" prop={PROP_NAMES.get(prop, f'?{prop}')}"
            val = rest[pos:]
            if prop == 0x120B and val:  # RADIO_CAPS: packed-uint bitfield, GET or VALUE_IS
                radio_caps, used = parse_varint(val, 0)
                out += (f" value={val[:used].hex(' ')} = {radio_caps:#05x} "
                        f"[{decode_radio_caps(radio_caps)}]")
            elif cmd == 6 and val:  # PROP_VALUE_IS
                if prop == 5:  # CAPS is a list of packed uints
                    caps, pos = [], 0
                    while pos < len(val):
                        c, pos = parse_varint(val, pos)
                        caps.append(f"{c} ({CAP_NAMES.get(c, '?')})")
                    out += " caps=" + " ".join(caps)
                elif prop == 0 and len(val) == 1:  # LAST_STATUS is a status code
                    out += f" value={val[0]} ({STATUS_NAMES.get(val[0], '?')})"
                else:
                    printable = False
                    try:
                        s = val.rstrip(b"\x00").decode("utf-8")
                        if len(s) >= 4 and s.isprintable():
                            printable = True
                            out += f" value=\"{s}\""
                    except UnicodeDecodeError:
                        pass
                    if not printable:
                        out += f" value={val.hex(' ')}"
            elif cmd == 1:  # reset response carries status
                out += f" status={val[0] if val else '?'}"
    elif cmd == 1:  # RESET response: status byte
        out += f" status={rest[0] if rest else '?'}"
    else:
        if rest:
            out += f" payload={rest.hex(' ')}"
    return out


# --- port handling (macOS/BSD termios, raw, non-blocking reads via select) ---
def open_port(path: str, baud: int) -> int:
    if termios is None:
        sys.exit("the harness opens a port through termios, which this host does not have")
    bconst = getattr(termios, f"B{baud}", None)
    if bconst is None:
        sys.exit(f"unsupported baud {baud}")
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(fd)
    attrs = termios.tcgetattr(fd)
    attrs[2] |= termios.CREAD | termios.CLOCAL
    attrs[2] &= ~termios.CSTOPB
    attrs[2] &= ~termios.PARENB
    attrs[4] = bconst  # ispeed
    attrs[5] = bconst  # ospeed
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    return fd


def read_until_quiet(fd: int, total: float, quiet: float = 0.25):
    """Read with select; stop after `total` s or `quiet` s of silence (if data seen)."""
    import time
    deadline = time.monotonic() + total
    last_rx = None
    chunks = []
    while time.monotonic() < deadline:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                break
            if not chunk:
                break
            last_rx = time.monotonic()
            chunks.append(chunk)
            print("  rx: " + chunk.hex(" "), flush=True)
        elif chunks and time.monotonic() - last_rx > quiet:
            break
    return b"".join(chunks)


def pack_uint(value: int) -> bytes:
    """Spinel packed uint (7-bit groups, LSB first, 0x80 = continuation).

    Mirrors spinel_packed_uint_encode() in OpenThread's src/lib/spinel/spinel.c.
    Any value >= 0x80 needs more than one byte: sending a single raw byte for
    e.g. 0xB0 is a parse error, not an unsupported property.
    """
    if value < 0:
        raise ValueError("negative value")
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)


def spinel_get_frame(prop: int, tid: int = 1) -> bytes:
    """HDLC-encoded PROP_VALUE_GET for a property id (read-only query).

    TID must be non-zero or the NCP suppresses the response (EnqueueResponse
    drops responses for TID 0). TID occupies bits 0-3 of the header byte.
    """
    if not 1 <= tid <= 15:
        raise ValueError("tid must be 1-15 for a response")
    header = 0x80 | (tid & 0x0F)
    return encode_hdlc(bytes([header, SPINEL_CMD_PROP_VALUE_GET]) + pack_uint(prop))


# packed-uint regression: ids >= 0x80 are multi-byte; sending a raw single byte
# is a genuine parse error on the NCP side (observed: PARSE_ERROR, 0x09)
assert pack_uint(0) == b"\x00"
assert pack_uint(127) == b"\x7f"
assert pack_uint(128) == b"\x80\x01"
assert pack_uint(0xB0) == b"\xb0\x01"
assert pack_uint(0x120B) == b"\x8b\x24"
assert spinel_get_frame(2, 1) == bytes([0x7E, 0x81, 0x02, 0x02, 0x5E, 0x80, 0x7E])
assert spinel_get_frame(0xB0, 1) == bytes([0x7E, 0x81, 0x02, 0xB0, 0x01, 0x54, 0x53, 0x7E])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--device", default=None,
                    help="a name the file ZB_DEVICE_MAP maps to a port; --port wins")
    ap.add_argument("--port", default=None)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--listen", nargs="?", const=3.0, type=float, default=None,
                    metavar="SECONDS", help="just open and capture incoming traffic")
    ap.add_argument("--get", type=lambda x: int(x, 0), nargs="+", default=None,
                    metavar="PROP",
                    help="after reset, PROP_VALUE_GET for one or more property ids "
                         "(dec or 0x hex); TIDs are assigned 1..15 in sequence")
    ap.add_argument("--set", action="append", metavar="PROP:HEX",
                    help="PROP_VALUE_SET with a raw value given as hex octets in the order "
                         "they appear on the wire (sets are sent before --get)")
    ap.add_argument("--insert", action="append", metavar="PROP:V1,V2,...",
                    help="PROP_VALUE_INSERT (used to add UNSOL_UPDATE_FILTER entries)")
    ap.add_argument("--remove", action="append", metavar="PROP:V1,V2,...",
                    help="PROP_VALUE_REMOVE")
    ap.add_argument("--hold", type=float, default=None, metavar="SECONDS",
                    help="read window after a SET: read the whole window instead of stopping at "
                         "a quiet gap (a scan's result arrives a period after its echo)")
    ap.add_argument("--tid", type=int, default=1, metavar="TID",
                    help="transaction id for --get (1-15; 0 = NCP will not respond)")
    ap.add_argument("--no-reset", action="store_true",
                    help="skip the reset (used with --get once link is known up)")
    args = ap.parse_args()
    port = resolve_port(args.port, args.device)

    try:
        fd = open_port(port, args.baud)
    except OSError as e:
        sys.exit(f"cannot open {port}: {e}")

    # One decoder for the whole session: a stick's frames end wherever the serial layer ended a read,
    # and a decoder per read drops the first half of a frame split across two.
    link = HdlcStream()

    try:
        if args.listen is not None:
            print(f"[listen] {port} @ {args.baud} for {args.listen}s")
            read_until_quiet(fd, args.listen, quiet=0.2)
            return

        # drain any pending data
        read_until_quiet(fd, 0.3, quiet=0.1)
        if args.no_reset:
            if not (args.get or args.set or args.insert or args.remove):
                sys.exit("--no-reset is only useful with --get/--set/--insert/--remove")
        else:
            frame = encode_hdlc(SPINEL_RESET_PAYLOAD)
            print(f"[reset] sending: {frame.hex(' ')}")
            os.write(fd, frame)
            data = read_until_quiet(fd, 3.0)
            print(f"[reset] total received: {len(data)} bytes")
            for frame_bytes, ok in link.feed(data):
                print(f"frame: {frame_bytes.hex(' ')} (fcs {'ok' if ok else 'BAD'})")
                print(parse_spinel(frame_bytes[:-2], ok))
            if not data:
                print("[reset] no response: firmware silent (wrong baud? not RCP? needs wake?)")
                return

        tid = args.tid
        setWindow = args.hold if args.hold is not None else 3.0
        setQuiet = setWindow if args.hold is not None else 0.25
        for item in (args.set or []):
            prop_s, _, hex_s = item.partition(":")
            prop = int(prop_s, 0)
            value = bytes.fromhex(hex_s)
            payload = bytes([0x80 | (tid & 0x0F), SPINEL_CMD_PROP_VALUE_SET])
            payload += pack_uint(prop) + value
            sframe = encode_hdlc(payload)
            print(f"\n[set {prop:#x} tid {tid}] sending: {sframe.hex(' ')}")
            os.write(fd, sframe)
            sdata = read_until_quiet(fd, setWindow, quiet=setQuiet)
            print(f"[set {prop:#x} tid {tid}] total received: {len(sdata)} bytes")
            for frame_bytes, ok in link.feed(sdata):
                print(f"  frame: {frame_bytes.hex(' ')} (fcs {'ok' if ok else 'BAD'})")
                print("  " + parse_spinel(frame_bytes[:-2], ok))
            tid = 1 if tid == 15 else tid + 1

        for prop in (args.get or []):
            gframe = spinel_get_frame(prop, tid)
            print(f"\n[get {prop:#x} tid {tid}] sending: {gframe.hex(' ')}")
            os.write(fd, gframe)
            gdata = read_until_quiet(fd, 3.0)
            print(f"[get {prop:#x} tid {tid}] total received: {len(gdata)} bytes")
            for frame_bytes, ok in link.feed(gdata):
                print(f"  frame: {frame_bytes.hex(' ')} (fcs {'ok' if ok else 'BAD'})")
                print("  " + parse_spinel(frame_bytes[:-2], ok))
            tid = 1 if tid == 15 else tid + 1

        for spec, command in ((args.insert, 4), (args.remove, 5)):
            for item in spec or []:
                prop_s, _, vals_s = item.partition(":")
                prop = int(prop_s, 0)
                payload = bytearray([0x80 | (tid & 0x0F), command])
                payload += pack_uint(prop)
                for v in filter(None, vals_s.split(",")):
                    payload += pack_uint(int(v, 0))
                frame = encode_hdlc(bytes(payload))
                print(f"\n[{('insert' if command == 4 else 'remove')} {prop:#x} tid {tid}] "
                      f"sending: {frame.hex(' ')}")
                os.write(fd, frame)
                rdata = read_until_quiet(fd, 3.0)
                for frame_bytes, ok in link.feed(rdata):
                    print(f"  frame: {frame_bytes.hex(' ')} (fcs {'ok' if ok else 'BAD'})")
                    print("  " + parse_spinel(frame_bytes[:-2], ok))
                tid = 1 if tid == 15 else tid + 1
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
