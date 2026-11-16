#!/usr/bin/env python3
"""ConBee III (RCP) 802.15.4 sniffer: Spinel over HDLC, stdlib only.

Arms the raw receive path on the RCP and prints disassembled frames.

Receive-path facts (from the OpenThread RCP firmware source):
  * SET PHY_ENABLED (0x20) true  -> otLinkRawSetReceiveDone(LinkRawReceiveDone)
    installs the callback; this is what makes otLinkRawIsEnabled() true.
  * SET MAC_RAW_STREAM_ENABLED (0x37) true -> otLinkRawReceive() arms the radio.
  * SET MAC_PROMISCUOUS_MODE (0x38) 0/1/2 = OFF/NETWORK/FULL.
  * SET PHY_CHAN (0x21) -> channel; re-arms receive if the raw stream is on.
  * Frames arrive unsolicited as PROP_VALUE_IS prop 0x71 (STREAM_RAW):
      uint16 LE psdu length, psdu, int8 rssi, int8 noise(-128), uint16 flags,
      struct{ u8 channel, u8 lqi, u64 timestamp us },
      struct{ packed-uint rx error },
      struct{ u8 ack key id, u32 ack frame counter }
    OpenThread structs are uint16-LE length prefixed. The psdu carries no FCS.

Usage:
    python3 harness/rcp_sniffer.py --channel 15 --duration 20
    python3 harness/rcp_sniffer.py --channel 15 --promisc network --duration 60
    python3 harness/rcp_sniffer.py --quiet      # summary only, no frame dump
"""

import argparse
import os
import select
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from spinel_probe import (  # noqa: E402
    DEFAULT_BAUD, DEFAULT_PORT, resolve_port, HdlcStream, PROP_NAMES, decode_hdlc, encode_hdlc,
    open_port, pack_uint, parse_varint,
)
import ieee802154 as zb  # noqa: E402

CMD_SET, CMD_GET = 3, 2
PROP_PHY_ENABLED, PROP_PHY_CHAN = 0x20, 0x21
PROP_RAW_STREAM, PROP_PROMISC, PROP_STREAM_RAW = 0x37, 0x38, 0x71
PROP_LADDR, PROP_SADDR, PROP_PANID, PROP_HWADDR = 0x34, 0x35, 0x36, 8
PROP_RX_ON_WHEN_IDLE = 0x3B  # MAC_RX_ON_WHEN_IDLE_MODE (upstream OT; ConBee II supports it)

PROMISC = {"off": 0, "network": 1, "full": 2}
# SPINEL_STATUS_RESET_* : the NCP emits one unsolicited after (re)boot, which
# wipes everything we configured.
RESET_STATUSES = {112, 113, 114, 115}


def set_frame(prop, value, tid):
    return encode_hdlc(bytes([0x80 | (tid & 0x0F), CMD_SET]) + pack_uint(prop) + value)


def get_frame(prop, tid):
    return encode_hdlc(bytes([0x80 | (tid & 0x0F), CMD_GET]) + pack_uint(prop))


def tx_frame(psdu, channel, tid, csma_backoffs=3, retries=0, csma=True):
    """SET PROP_STREAM_RAW = raw transmit request.

    Value layout (identical on both sticks; the difference is strictness):
      u16 LE psdu length | psdu | u8 channel | u8 maxCsmaBackoffs
      u8 maxFrameRetries | b csmaCaEnabled | b isHeaderUpdated | b isARetx
      b isSecurityProcessed | u32LE txDelay | u32LE txDelayBase | u8 rxChannelAfterTx

    OpenThread (ConBee III) treats everything after the channel as optional
    (NcpBase::DecodeStreamRawTxRequest). DSPINEL (ConBee II) requires the whole
    16-byte trailer and answers PARSE_ERROR for a short value, so we always send
    all 16 bytes: one shape works on both.

    The reply is asynchronous: on transmit-done the RCP emits
    PROP_VALUE_IS(LAST_STATUS) with *our* TID:
      status(packed u) | bool framePending | bool headerUpdated |
      [ack frame] [u8 keyId u32 frameCounter if secured + header updated]
    """
    p = bytearray([0x80 | (tid & 0x0F), CMD_SET]) + pack_uint(PROP_STREAM_RAW)
    p += bytes([len(psdu) & 0xFF, (len(psdu) >> 8) & 0xFF]) + psdu
    p += bytes([channel, csma_backoffs, retries, 1 if csma else 0, 0, 0, 0])
    p += b"\x00\x00\x00\x00"   # txDelay
    p += b"\x00\x00\x00\x00"   # txDelayBase
    p += bytes([0])              # rxChannelAfterTx: keep current
    return encode_hdlc(bytes(p))


# regression: header+cmd+prop(1)+len(2)+psdu(5)+trailer(16) = 25 value+header bytes
_probe_frame, _probe_ok = next(iter(decode_hdlc(tx_frame(b"\x02\x00\x00\x00\x00", 15, 1))))
assert _probe_ok
_body = _probe_frame[:-2]                      # drop the HDLC FCS
assert _body[0] == 0x81 and _body[1] == CMD_SET and _body[2] == PROP_STREAM_RAW
_psdu_len = _body[3] | (_body[4] << 8)
assert _psdu_len == 5
# header(1) + cmd(1) + prop(1) + length field(2) + psdu + trailer == whole body
_trailer = len(_body) - 3 - 2 - _psdu_len
assert _trailer == 16, f"TX trailer must be 16 bytes, got {_trailer}"


def decode_tx_done(body, pos):
    """TX-done LAST_STATUS body -> (status, frame_pending, header_updated, ack_psdu)."""
    status, pos = parse_varint(body, pos)
    fp = body[pos] if pos < len(body) else 0
    hu = body[pos + 1] if pos + 1 < len(body) else 0
    pos += 2
    ack = None
    if pos + 2 <= len(body):
        n = u16(body, pos)
        if n:
            ack = body[pos + 2:pos + 2 + n]
    return status, bool(fp), bool(hu), ack


def u16(b, i):
    return b[i] | (b[i + 1] << 8)


def s8(b):
    return b - 256 if b > 127 else b


def decode_raw(payload):
    """Body after header+cmd+prop for prop 0x71 -> dict."""
    p = 0
    plen = u16(payload, p)
    p += 2
    psdu = payload[p:p + plen]
    p += plen
    out = {"psdu": psdu, "rssi": s8(payload[p]), "noise": s8(payload[p + 1]),
           "flags": u16(payload, p + 2)}
    p += 4
    for name in ("phy", "vendor", "mac"):
        if p + 2 > len(payload):
            break
        slen = u16(payload, p)
        body = payload[p + 2:p + 2 + slen]
        p += 2 + slen
        if name == "phy" and len(body) >= 10:
            out["channel"] = body[0]
            out["lqi"] = body[1]
            out["timestamp"] = int.from_bytes(body[2:10], "little")
        elif name == "vendor" and body:
            out["rx_error"], _ = parse_varint(body, 0)
        elif name == "mac" and len(body) >= 5:
            out["ack_key_id"] = body[0]
            out["ack_frame_counter"] = int.from_bytes(body[1:5], "little")
    return out


def drain(fd, total, quiet=0.25):
    deadline, last, chunks = time.monotonic() + total, None, []
    while time.monotonic() < deadline:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                c = os.read(fd, 4096)
            except (BlockingIOError, InterruptedError):
                continue
            if c:
                chunks.append(c)
                last = time.monotonic()
        elif last and time.monotonic() - last > quiet:
            break
    return b"".join(chunks)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--device", default=None,
                    help="a name the file ZB_DEVICE_MAP maps to a port; --port wins")
    ap.add_argument("--port", default=None)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--channel", type=int, default=15)
    ap.add_argument("--promisc", choices=PROMISC, default="full")
    ap.add_argument("--duration", type=float, default=15.0)
    ap.add_argument("--no-reset", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="summary only")
    ap.add_argument("--hex", action="store_true", help="dump raw psdu hex per frame")
    ap.add_argument("--own-pan", type=lambda x: int(x, 0), default=0xFFFF,
                    help="PAN the RCP filters on. Keep 0xffff (match-any): measured "
                         "that setting a specific PAN silences RX even in promiscuous "
                         "FULL mode: the radio's PAN filter still applies")
    ap.add_argument("--own-addr", type=lambda x: int(x, 0), default=0x4242,
                    help="short address given to the RCP / used as our TX src")
    ap.add_argument("--dst-pan", type=lambda x: int(x, 0), default=0xBEEF,
                    help="dst PAN for transmitted frames. Default 0xbeef: no device on "
                         "air matches it, so every receiver PAN-filters it away")
    ap.add_argument("--dst-addr", type=lambda x: int(x, 0), default=0xFFFF,
                    help="dst short address for --tx")
    ap.add_argument("--skip-saddr", action="store_true", help="do not SET MAC_15_4_SADDR")
    ap.add_argument("--skip-panid", action="store_true", help="do not SET MAC_15_4_PANID")
    ap.add_argument("--rx-on-when-idle", action="store_true",
                    help="SET MAC_RX_ON_WHEN_IDLE_MODE(0x3B)=1 after arming")
    ap.add_argument("--skip-hwaddr", action="store_true",
                    help="do not GET PROP_HWADDR")
    ap.add_argument("--allow-tx", action="store_true",
                    help="required for --tx. Transmitting puts energy on a shared "
                         "channel; make it a deliberate choice")
    ap.add_argument("--no-ack", action="store_true",
                    help="transmit without the ack-request bit")
    ap.add_argument("--tx-psdu-fcs", choices=("append", "none"), default="append",
                    help="append the 2 FCS bytes to the PSDU before transmitting. "
                         "DSPINEL (ConBee II) requires the PSDU to carry its own FCS "
                         "(the radio regenerates the bytes); OpenThread builds take "
                         "the frame without it. Default append")
    ap.add_argument("--seq", type=int, default=0, help="seq number for --tx frames")
    ap.add_argument("--tx", action="append", default=[], metavar="SPEC",
                    help="transmit: 'poll' | 'data:<hex payload>' | 'raw:<hex psdu>'; "
                         "repeatable")
    args = ap.parse_args()
    port = resolve_port(args.port, args.device)

    if args.tx and not args.allow_tx:
        sys.exit("--tx requires --allow-tx: transmitting is audible to every device "
                 "on this channel. Open a channel-15 network to TX only on purpose.")

    fd = open_port(port, args.baud)
    # a bare flag flushes the transport: DSPINEL's documented bring-up does this
    # first, and an RCP mid-frame otherwise drops our first command
    os.write(fd, b"\x7e")
    tid = 1
    stats = Counter()
    peers = defaultdict(Counter)      # src short -> Counter(dst short)
    votes = defaultdict(Counter)      # src short -> Counter(EUI)
    seen = Counter()                  # src short -> frames
    rssi = defaultdict(lambda: [127, -128])
    pans = Counter()
    tx_tids = set()
    rearm = [False]
    in_config = [False]   # a reset notification caused by OUR reset is not a fault

    link = HdlcStream()   # one decoder for the session: a frame split across two reads is carried, not lost

    def feed(data):
        """Decode HDLC frames; classify Spinel responses vs raw-frame notifications."""
        for fb, ok in link.feed(data):
            body = fb[:-2]
            if len(body) < 3:
                continue
            prop, pos = parse_varint(body, 2)
            if prop == PROP_STREAM_RAW:
                fr = decode_raw(body[pos:])
                d = zb.dissect(fr["psdu"])
                stats[d["type_name"] if d["ok"] else "bad"] += 1
                if not d["ok"]:
                    if not args.quiet:
                        print(f"  !! {d['reason']}: {fr['psdu'].hex(' ')}")
                    continue
                src = d["src"]["short"] if d.get("src") else None
                if src is not None:
                    seen[src] += 1
                    r = rssi[src]
                    r[0] = min(r[0], fr["rssi"])
                    r[1] = max(r[1], fr["rssi"])
                    for e in zb.mac_candidates(d["payload"]):
                        votes[src][e] += 1
                    if d.get("dst") and d["dst"]["short"] is not None:
                        peers[src][d["dst"]["short"]] += 1
                for pan in (d.get("dst_pan"), d.get("src_pan")):
                    if pan is not None:
                        pans[pan] += 1
                if d.get("beacon"):
                    votes[0][d["beacon"]["coord_ext"]] += 10  # authoritative
                if not args.quiet:
                    flags = []
                    if d["secured"]:
                        flags.append("secured")
                    if d["ack_req"]:
                        flags.append("ackreq")
                    if d["pending"]:
                        flags.append("pending")
                    if d["type"] == 2:
                        who = "fcs-ok" if d["fcs_valid"] else "fcs-stripped"
                    else:
                        who = (zb.key_of(d.get("src")) or "?") + " -> " + \
                              (zb.key_of(d.get("dst")) or "?")
                    extra = ""
                    if d["type"] == 3 and d.get("cmd"):
                        extra = f" cmd={d['cmd']['name']} params={d['cmd']['params'].hex(' ')}"
                    elif d["type"] == 0 and d.get("beacon"):
                        b = d["beacon"]
                        extra = (f" beacon: coord={b['coord_ext']} pan={b['pan_id']:#06x}"
                                 f" src={b['src_short']:#06x} cap={d['capability']:#04x}")
                    elif d["type"] == 1:
                        n = zb.nwk_view(d["payload"])
                        if n:
                            extra = (f" nwkfcf={n['nwk_fcf']:#04x} nwk {n['nwk_src']:#06x}"
                                     f"->{n['nwk_dst']:#06x} seq={n['nwk_seq']}")
                    print(f"[{sum(stats.values()):4d}] ch={fr['channel']} rssi={fr['rssi']:4d} "
                          f"len={len(fr['psdu']):3d} {d['type_name']} {who} seq={d['seq']} "
                          f"{' '.join(flags)}{extra}")
                    if args.hex:
                        print(f"        {fr['psdu'].hex(' ')}")
            elif prop == 0:
                stats["status"] += 1
                st0, _ = parse_varint(body, pos)
                if st0 in RESET_STATUSES and (body[0] & 0x0F) == 0 and not in_config[0]:
                    rearm[0] = True  # unsolicited reset: our config is gone
                if args.quiet:
                    continue
                my_tid = body[0] & 0x0F
                if my_tid in tx_tids:
                    tx_tids.discard(my_tid)
                    st, fp, hu, ack = decode_tx_done(body, pos)
                    line = f"  [tx-done tid {my_tid}] status={st} " + \
                           ("OK" if st == 0 else f"(see SPINEL_STATUS_{st})") + \
                           f" frame_pending={int(fp)} header_updated={int(hu)}"
                    if ack is not None:
                        ad = zb.dissect(ack)
                        line += f"\n        ack: {ack.hex(' ')}  -> " + \
                                (f"{ad['type_name']} seq={ad.get('seq')} "
                                 f"pending={int(ad.get('pending', 0))}"
                                 if ad["ok"] else ad["reason"])
                    print(line)
                else:
                    st, _ = parse_varint(body, pos)
                    print(f"  [status tid {my_tid}] {st} raw={body.hex(' ')}")
            else:
                stats["spinel"] += 1
                if not args.quiet:
                    print(f"  [spinel tid {body[0] & 0x0F} {PROP_NAMES.get(prop, prop)}] "
                          f"{body[pos:].hex(' ')}")

    try:
        drain(fd, 0.3, quiet=0.1)
        # Build each frame with its OWN tid at send time: a constant TID makes the
        # NCP treat every command as out-of-sequence and overwrite the queued reply.
        def apply_config():
            """Send the arming sequence; return True if every GET was answered."""
            nonlocal tid
            in_config[0] = True
            steps = []
            if not args.no_reset:
                # the verified known-answer frame: reset goes out as TID 0
                steps.append((lambda t: encode_hdlc(bytes([0x80, 0x01])), "reset"))
            steps += [
                (lambda t: set_frame(PROP_PHY_ENABLED, b"\x01", t), "PHY_ENABLED=true"),
                (lambda t: set_frame(PROP_PHY_CHAN, pack_uint(args.channel), t),
                 f"PHY_CHAN={args.channel}"),
                (lambda t: set_frame(PROP_PROMISC, pack_uint(PROMISC[args.promisc]), t),
                 f"PROMISC={args.promisc}"),
            ]
            if not args.skip_saddr:
                steps.append((lambda t: set_frame(
                    PROP_SADDR, bytes([args.own_addr & 0xFF, (args.own_addr >> 8) & 0xFF]), t),
                    f"SADDR={args.own_addr:#06x}"))
            if not args.skip_panid:
                steps.append((lambda t: set_frame(
                    PROP_PANID, bytes([args.own_pan & 0xFF, (args.own_pan >> 8) & 0xFF]), t),
                    f"PANID={args.own_pan:#06x}"))
            steps.append((lambda t: set_frame(PROP_RAW_STREAM, b"\x01", t),
                          "RAW_STREAM=true"))
            if args.rx_on_when_idle:
                steps.append((lambda t: set_frame(PROP_RX_ON_WHEN_IDLE, b"\x01", t),
                              "RX_ON_WHEN_IDLE=true"))
            checks = [PROP_PHY_CHAN, PROP_PROMISC, PROP_PHY_ENABLED]
            if not args.skip_hwaddr:
                checks.append(PROP_HWADDR)
            for prop in checks:
                steps.append((lambda t, p=prop: get_frame(p, t),
                              f"verify {PROP_NAMES.get(prop, prop)}"))

            answered = 0
            for build, label in steps:
                os.write(fd, build(tid))
                tid = 1 if tid == 15 else tid + 1
                data = drain(fd, 0.6)
                if not args.quiet:
                    print(f"  -> {label}")
                before = stats["spinel"]
                feed(data)
                if label.startswith("verify") and stats["spinel"] > before:
                    answered += 1
            want = sum(1 for _, l in steps if l.startswith("verify"))
            in_config[0] = False
            return answered == want

        for attempt in (1, 2, 3):
            if apply_config():
                break
            print(f"  [warn] RCP did not answer the verify GETs "
                  f"(attempt {attempt}); re-arming")
            time.sleep(1.0)
        else:
            print("  [warn] RCP still unresponsive: frames may not arrive")

        for spec in args.tx:
            kind, _, arg = spec.partition(":")
            if kind == "poll":
                psdu = zb.poll_frame(args.dst_pan, args.dst_addr, args.own_addr,
                                     seq=args.seq)
            elif kind == "data":
                psdu = zb.data_frame(args.dst_pan, args.dst_addr, args.own_addr,
                                     bytes.fromhex(arg.replace(":", " ")), seq=args.seq,
                                     ack_req=not args.no_ack)
            elif kind == "raw":
                psdu = bytes.fromhex(arg.replace(":", " "))
            else:
                sys.exit(f"unknown --tx spec: {spec}")
            if args.tx_psdu_fcs == "append":
                psdu += zb.fcs_802154(psdu)
            print(f"\n[tx {spec}] {len(psdu)} B dst_pan={args.dst_pan:#06x} "
                  f"dst={args.dst_addr:#06x} src={args.own_addr:#06x} "
                  f"psdu={psdu.hex(' ')}")
            os.write(fd, tx_frame(psdu, args.channel, tid))
            tx_tids.add(tid)
            tid = 1 if tid == 15 else tid + 1
            feed(drain(fd, 1.2))

        print(f"\n[sniffing {port} ch={args.channel} "
              f"promisc={args.promisc} for {args.duration}s]")
        deadline = time.monotonic() + args.duration
        while time.monotonic() < deadline:
            r, _, _ = select.select([fd], [], [], 0.5)
            if not r:
                continue
            try:
                feed(os.read(fd, 4096))
            except (BlockingIOError, InterruptedError):
                continue
            if rearm[0]:
                rearm[0] = False
                print("  [notice] RCP reported a reset (LAST_STATUS 112-115): "
                      "re-applying the arming sequence")
                apply_config()

        # Two-pass EUI resolution: drop candidates that belong to a peer we
        # already resolved.
        resolved = zb.resolve_macs(votes)
        known = set(v for v in resolved.values() if v)
        if known:
            for src, counts in votes.items():
                for eui in known - {resolved.get(src)}:
                    counts[eui] = 0
            resolved = zb.resolve_macs(votes)

        print("\n=== summary ===")
        print("frame classes:", dict(stats))
        print("PAN ids seen:", {f"0x{p:04x}": n for p, n in pans.items()})
        print(f"{'src':>8} {'frames':>6} {'rssi':>13}  resolved EUI-64 / peers")
        for src, n in seen.most_common():
            lo, hi = rssi[src]
            eui = resolved.get(src) or "-"
            pr = ", ".join(f"0x{p:04x}×{c}" for p, c in peers[src].most_common(4))
            print(f"{src:#08x} {n:>6} {lo:>5}..{hi:<6}  {eui:<25} {pr}")
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
