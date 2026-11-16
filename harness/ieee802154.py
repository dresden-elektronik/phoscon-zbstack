"""802.15.4 / Zigbee MAC dissection for captured PSDUs: pure, stdlib only.

The Frame Control layout is the one the standards define:

  FCF (16-bit LE), IEEE 802.15.4-2006 Figure 42: bit 3 (Security Enabled) and bits
  12-13 (Frame Version) are also given in its Table 81; Zigbee R23.1 Annex D lists
  the same field and fills bits 8 (sequence number suppression) and 9 (IE list
  present), which 802.15.4-2015 and 802.15.4-2020 added and 802.15.4-2006 reserved:

    0-2   frame type          0=beacon 1=data 2=ack 3=MAC command
    3     security enabled    the auxiliary security header is present iff set
    4     frame pending
    5     ack requested
    6     PAN ID compression
    7     reserved (802.15.4-2006)
    8     sequence number suppression (802.15.4-2015, 802.15.4-2020)
    9     IE list present (802.15.4-2015, 802.15.4-2020)
    10-11 destination addressing mode   0=none 2=16-bit 3=64-bit
    12-13 frame version       0=compatible with 802.15.4-2003, 1=this standard
    14-15 source addressing mode

  Field presence (802.15.4-2006 7.2.1.3..7.2.1.6):
    destination PAN and address  only if destination addressing mode is nonzero
    source address               only if source addressing mode is nonzero
    source PAN                   only if source mode is nonzero AND compression is 0
  Security level and key identifier are not in the FCF: they are in the auxiliary
  security header, Security Control(1: level bits 0-2, key identifier mode bits
  3-4) + Frame Counter(4) + Key Identifier(0/1/5/9).
  Acknowledgment frame (802.15.4-2006 7.2.2.3): Frame Control, Sequence Number, FCS and
  nothing else: 5 octets, no addressing fields; Frame Pending is set when
  acknowledging a data request for which the parent has data queued.
  MAC command identifiers: 802.15.4-2006 Table 82. Zigbee NWK command identifiers:
  R23.1 Table 3-54.

Superseded reading, kept because docs/internals/protocol.md §9.1 records why it is wrong: the
802.15.4-2003 layout (security enabled 4, pending 5, ack 6, PAN compression 7,
security level 8-10, key id 11, one-bit addressing modes 12/13, PAN suppression
14/15) is what earlier decoders and this harness used until the captured
frames were checked against IEEE 802.15.4-2024. For this PAN's data frames it lands the
addressing modes and PAN suppression on bits that happen to decode the same fields,
so its offsets looked verified; it mislabels the flags (Ack Request read one bit
high, Frame Pending read as Security Enabled) and cannot account for a 5-octet
acknowledgment frame at all.

Frame tails: the AT86RF233 build delivers the MAC frame with its FCS (53/55
frames in test/fixtures/conbee2_ch15_hex.txt verify), the EFR32 build delivers
frames whose trailing octets are not a valid FCS (0/16 in
conbee3_ch15_hex.txt). The payload of a secured Zigbee frame is AES-CCM ciphertext
with the network key: opaque; the NWK/APS headers in front of it are plaintext.
"""

FRAME_TYPES = {0: "beacon", 1: "data", 2: "ack", 3: "cmd"}

FCF_TYPE_MASK = 0x0007
FCF_SECURITY = 0x0008
FCF_PENDING = 0x0010
FCF_ACK_REQ = 0x0020
FCF_PAN_COMP = 0x0040
FCF_SEQ_SUP = 0x0100
FCF_IE_LIST = 0x0200
FCF_DST_MODE = 0x0C00
FCF_VERSION = 0x3000
FCF_SRC_MODE = 0xC000

ADDR_MODES = {0: "none", 1: "reserved", 2: "16-bit", 3: "64-bit"}
ADDR_NONE, ADDR_SHORT, ADDR_LONG = 0, 2, 3

# IEEE 802.15.4-2006 Table 82 (MAC command frames).
MAC_COMMANDS = {
    0x01: "assoc-request", 0x02: "assoc-response", 0x03: "disassoc-notify",
    0x04: "data-request", 0x05: "pan-id-conflict", 0x06: "orphan-notify",
    0x07: "beacon-request", 0x08: "coordinator-realign", 0x09: "gts-request",
}

# Zigbee R23.1 Table 3-54 (NWK command frames, carried in a MAC data frame's NPDU).
NWK_COMMANDS = {
    0x01: "route-request", 0x02: "route-reply", 0x03: "network-status",
    0x04: "leave", 0x05: "route-record", 0x06: "rejoin-request",
    0x07: "rejoin-response", 0x08: "link-status", 0x09: "network-report",
    0x0a: "network-update", 0x0b: "ed-timeout-request",
    0x0c: "ed-timeout-response", 0x0d: "link-power-delta",
    0x0e: "commissioning-request", 0x0f: "commissioning-response",
}

SEC_LEVELS = {0: "none", 1: "MIC-32", 2: "MIC-64", 3: "MIC-128",
              4: "ENC", 5: "ENC-MIC-32", 6: "ENC-MIC-64", 7: "ENC-MIC-128"}
KEY_ID_MODES = {0: "implicit", 1: "source-addr+key-index", 2: "3-octet-source+index",
                3: "4-octet-source+index"}
KEY_ID_OCTETS = {0: 0, 1: 1, 2: 5, 3: 9}


def fcs_802154(psdu: bytes) -> bytes:
    """802.15.4 FCS: CRC-16, reflected poly 0x8408, init 0x0000, no final XOR,
    appended little-endian (the CRC-16/CCITT arithmetic).
    Returns the two wire bytes."""
    crc = 0
    for b in psdu:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])


# known answer: published CRC-16/40215 check value for "123456789" is 0x2189
assert fcs_802154(b"123456789") == bytes([0x89, 0x21])

# known answer from the standard itself: 7.2.11 works out the FCS of an Ack frame
# with no payload, giving the MHR bit string 0100 0000 0000 0000 0101 0110 (b0 passed to
# the PHY first) and the FCS bit string 0010 0111 1001 1110 (r0 passed first). Read as
# octets with the first transmitted bit as the least significant bit of each octet, that
# is MHR 02 00 6a and FCS e4 79.
assert fcs_802154(bytes.fromhex("02006a")) == bytes.fromhex("e479")


def le16(b, o):
    return b[o] | (b[o + 1] << 8)


def eui_str(raw8):
    """Wire-order 8 bytes -> Zigbee display form (byte-reversed, colon groups)."""
    return ":".join(f"{raw8[i]:02x}" for i in range(7, -1, -1))


def _addr(b, o, ext):
    if ext:
        raw = b[o:o + 8]
        return {"short": None, "ext": eui_str(raw), "raw": raw}
    return {"short": le16(b, o), "ext": None, "raw": None}


def key_of(a):
    if not a:
        return None
    return a["ext"] if a["ext"] is not None else f"0x{a['short']:04x}"


def fcs_valid(psdu: bytes) -> bool:
    """True if the trailing two octets are the FCS of everything before them."""
    return len(psdu) >= 3 and psdu[-2:] == fcs_802154(psdu[:-2])


def dissect(psdu: bytes) -> dict:
    if len(psdu) < 2:
        return {"ok": False, "reason": "too short for FCF"}
    fcf = le16(psdu, 0)
    dst_mode = (fcf & FCF_DST_MODE) >> 10
    src_mode = (fcf & FCF_SRC_MODE) >> 14
    base = {
        "ok": True,
        "fcf": fcf,
        "type": fcf & FCF_TYPE_MASK,
        "secured": bool(fcf & FCF_SECURITY),
        "pending": bool(fcf & FCF_PENDING),
        "ack_req": bool(fcf & FCF_ACK_REQ),
        "pan_comp": bool(fcf & FCF_PAN_COMP),
        "seq_sup": bool(fcf & FCF_SEQ_SUP),
        "ie_list": bool(fcf & FCF_IE_LIST),
        "dst_mode": dst_mode,
        "src_mode": src_mode,
        "version": (fcf & FCF_VERSION) >> 12,
        "fcs_valid": fcs_valid(psdu),
    }
    base["type_name"] = FRAME_TYPES.get(base["type"], f"type{base['type']}")
    base["addr"] = f"{ADDR_MODES[dst_mode]}->{ADDR_MODES[src_mode]}"

    if base["type"] == 0:  # beacon: FCF seq GS(2) Pending(2) Capability(1) payload
        if len(psdu) < 7:
            return {**base, "ok": False, "reason": "beacon too short"}
        cap = psdu[6]
        out = {**base, "gs": le16(psdu, 2), "capability": cap,
               "beacon_order": psdu[2] & 0x0F, "superframe": (psdu[2] >> 4) & 0x0F,
               "is_coordinator": bool(cap & 0x40), "isFFD": bool(cap & 0x04),
               "payload": psdu[7:]}
        p = out["payload"]
        if len(p) >= 12:
            out["beacon"] = {"coord_ext": _addr(p, 0, True)["ext"],
                             "pan_id": le16(p, 8), "src_short": le16(p, 10)}
        return out

    if len(psdu) < 3:
        return {**base, "ok": False, "reason": "too short for seq"}
    out = {**base, "seq": psdu[2]}
    off = 3

    if base["type"] == 2:
        # 7.2.2.3: an acknowledgment MHR is Frame Control + Sequence Number only.
        out["ack_tail"] = psdu[3:]
        if dst_mode:
            dl = 8 if dst_mode == ADDR_LONG else 2
            if off + dl > len(psdu):
                return {**out, "ok": False, "reason": "truncated ack dst"}
            out["dst"] = _addr(psdu, off, dst_mode == ADDR_LONG)
            off += dl
        out["payload"] = psdu[off:]
        return out

    if base["type"] not in (1, 3):
        return {**base, "ok": False, "reason": f"unsupported type {base['type']}"}

    if dst_mode:
        if off + 2 + (8 if dst_mode == ADDR_LONG else 2) > len(psdu):
            return {**out, "ok": False, "reason": "truncated dstPAN/dst"}
        out["dst_pan"] = le16(psdu, off)
        off += 2
        out["dst"] = _addr(psdu, off, dst_mode == ADDR_LONG)
        off += 8 if dst_mode == ADDR_LONG else 2
    else:
        out["dst_pan"], out["dst"] = None, None

    if src_mode:
        out["src_pan"] = None
        if not base["pan_comp"]:
            if off + 2 > len(psdu):
                return {**out, "ok": False, "reason": "truncated srcPAN"}
            out["src_pan"] = le16(psdu, off)
            off += 2
        sl = 8 if src_mode == ADDR_LONG else 2
        if off + sl > len(psdu):
            return {**out, "ok": False, "reason": "truncated src"}
        out["src"] = _addr(psdu, off, src_mode == ADDR_LONG)
        off += sl
    else:
        out["src"], out["src_pan"] = None, None

    if base["secured"]:
        if off + 5 > len(psdu):
            return {**out, "ok": False, "reason": "truncated aux security header"}
        ctrl = psdu[off]
        key_mode = (ctrl >> 3) & 3
        n = 1 + 4 + KEY_ID_OCTETS[key_mode]
        if off + n > len(psdu):
            return {**out, "ok": False, "reason": "truncated key identifier"}
        out["aux"] = {"control": ctrl, "level": SEC_LEVELS[ctrl & 7],
                      "key_mode": KEY_ID_MODES[key_mode],
                      "frame_counter": le16(psdu, off + 1) | (le16(psdu, off + 3) << 16),
                      "len": n}
        off += n

    out["payload"] = psdu[off:]

    if base["type"] == 3 and out["payload"]:
        cid = out["payload"][0]
        out["cmd"] = {"id": cid, "name": MAC_COMMANDS.get(cid, f"cmd0x{cid:02x}"),
                      "params": out["payload"][1:]}
    return out


# --- NWK / APS plaintext windows (empirical) ---
# Offsets counted from the start of the MAC payload (i.e. after the MAC header).
OFF_NONBACKUP = 8    # broadcast / extended non-backup route (NWK FCF bit0 set, e.g. 0x09)
OFF_UNICAST = 13     # classic short-address unicast (0x48 / 0x58 / 0x72)
OFF_APS_SRC = 21     # extended-addressing unicast (NWK FCF 0x08): source's own EUI-64


def _window(payload, off):
    if len(payload) < off + 8:
        return None
    return eui_str(payload[off:off + 8])


def mac_candidates(payload: bytes):
    """Candidate source EUI-64s for this frame (0-2). Which one is the source's
    own is resolved by recurrence across frames: see resolve_macs()."""
    if len(payload) < 8:
        return []
    classic = OFF_NONBACKUP if payload[0] & 0x01 else OFF_UNICAST
    out = []
    for off in (classic, OFF_APS_SRC):
        # The offset-8 window carries the PEER's EUI-64 in the 0x08 class.
        if off == OFF_NONBACKUP and payload[0] == 0x08:
            continue
        w = _window(payload, off)
        if w and w not in out:
            out.append(w)
    return out


def nwk_view(payload: bytes) -> dict:
    """Best-effort NWK header view for data frames. Empirical, FCF-dependent."""
    if len(payload) < 8:
        return {}
    fcf = payload[0]
    v = {"nwk_fcf": fcf}
    # dst/src short addresses sit at 2-3 / 4-5 in the classes observed here
    v["nwk_dst"] = le16(payload, 2)
    v["nwk_src"] = le16(payload, 4)
    v["nwk_seq"] = payload[7]
    return v


# --- frame construction (the mirror image of dissect) ---

def build_fcf(ftype, ack_req=True, pan_comp=True, sec=False, pending=False,
              dst_mode=ADDR_SHORT, src_mode=ADDR_SHORT, version=0,
              seq_sup=False, ie_list=False):
    """FCF in the layout of the module docstring."""
    f = ftype & FCF_TYPE_MASK
    f |= (1 if sec else 0) << 3
    f |= (1 if pending else 0) << 4
    f |= (1 if ack_req else 0) << 5
    f |= (1 if pan_comp else 0) << 6
    f |= (1 if seq_sup else 0) << 8
    f |= (1 if ie_list else 0) << 9
    f |= (dst_mode & 3) << 10
    f |= (version & 3) << 12
    f |= (src_mode & 3) << 14
    return f


def _le16_bytes(v):
    return bytes([v & 0xFF, (v >> 8) & 0xFF])


def _addr_bytes(a, mode):
    if mode != ADDR_LONG:
        return _le16_bytes(a)
    if isinstance(a, str):  # display form "00:11:22:..." -> wire order
        return bytes(int(x, 16) for x in reversed(a.split(":")))
    return bytes(a)


def frame(ftype, dst_pan, dst, src, payload, seq=0, src_pan=None, **fcf_kw):
    """Assemble a PSDU following the field-presence rules. No FCS is appended:
    whether the radio expects one is a per-device decision (docs/internals/protocol.md §8.2)."""
    fcf = build_fcf(ftype, **fcf_kw)
    dst_mode = (fcf & FCF_DST_MODE) >> 10
    src_mode = (fcf & FCF_SRC_MODE) >> 14
    out = bytearray([fcf & 0xFF, (fcf >> 8) & 0xFF, seq & 0xFF])
    if dst_mode:
        out += _le16_bytes(dst_pan)
        out += _addr_bytes(dst, dst_mode)
    if src_mode:
        if not fcf & FCF_PAN_COMP:
            out += _le16_bytes(dst_pan if src_pan is None else src_pan)
        out += _addr_bytes(src, src_mode)
    out += payload
    return bytes(out)


def ack_frame(seq, pending=False, with_fcs=True):
    """802.15.4-2006 7.2.2.3: Frame Control + Sequence Number + FCS, no addressing."""
    psdu = bytearray([0x02, 0x00, seq & 0xFF])
    if pending:
        psdu[0] |= FCF_PENDING & 0xFF
    if with_fcs:
        psdu += fcs_802154(psdu)
    return bytes(psdu)


def poll_frame(dst_pan, dst, src, seq=0):
    """802.15.4 Data Request (the beacon-less poll): command id 0x04, Table 82."""
    return frame(3, dst_pan, dst, src, bytes([0x04]), seq=seq)


def data_frame(dst_pan, dst, src, payload, seq=0, ack_req=True):
    return frame(1, dst_pan, dst, src, payload, seq=seq, ack_req=ack_req)


# regression: built frames dissect back to themselves, and captured frames are
# known answers (docs/internals/testing.md §2.1)
_p = poll_frame(0xde20, 0x0000, 0x4242, seq=7)
_d = dissect(_p)
assert _d["ok"] and _d["type"] == 3 and _d["seq"] == 7
assert _d["dst_mode"] == 2 and _d["src_mode"] == 2 and _d["version"] == 0
assert _d["ack_req"] and _d["pan_comp"] and not _d["secured"] and not _d["pending"]
assert _d["dst_pan"] == 0xde20 and _d["dst"]["short"] == 0x0000
assert _d["src"]["short"] == 0x4242 and _d["src_pan"] is None
assert _d["cmd"]["id"] == 0x04 and _d["cmd"]["name"] == "data-request"
assert len(_p) == 10  # FCF seq dstPAN dst src cmd

_a = dissect(bytes.fromhex("02001c556f"))  # captured on the AT86RF233 build
assert _a["ok"] and _a["type"] == 2 and _a["seq"] == 0x1C
assert _a["dst_mode"] == 0 and not _a["secured"] and not _a["pending"]
assert _a["fcs_valid"]
assert ack_frame(0x1C).hex() == "02001c556f"

_pend = dissect(bytes.fromhex("12007d20de"))  # ACK carrying Frame Pending
assert _pend["ok"] and _pend["type"] == 2 and _pend["pending"] and not _pend["secured"]

_b = dissect(bytes.fromhex("41880720deffff a705".replace(" ", "") + "00" * 10))
assert _b["ok"] and _b["type"] == 1 and not _b["ack_req"] and _b["pan_comp"]
assert _b["dst"]["short"] == 0xFFFF and _b["src"]["short"] == 0x05A7
assert _b["dst_pan"] == 0xDE20 and _b["src_pan"] is None


def resolve_macs(votes: dict, min_conf: int = 3):
    """Resolve each short address's own EUI-64 by recurrence vote.
    votes: {short_addr: {eui: count}} -> {short_addr: eui or None}
    A value must reach min_conf frames and strictly beat the runner-up."""
    out = {}
    for short, counts in votes.items():
        ranked = sorted(counts.items(), key=lambda kv: -kv[1])
        if not ranked:
            out[short] = None
        elif ranked[0][1] >= min_conf and (len(ranked) == 1 or
                                           ranked[0][1] > ranked[1][1]):
            out[short] = ranked[0][0]
        else:
            out[short] = None
    return out
