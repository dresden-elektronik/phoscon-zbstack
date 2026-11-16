#!/usr/bin/env python3
"""What crosses the serial line between the host and the RCP, for the internals documentation.

Content only: the style, the renderer and the checks are in figure.py. The HDLC frame on the wire, the
Spinel frame it carries, and then the two STREAM_RAW values the data path is made of: the transmit
request this stack writes and the receive notification it reads, each with its fixed block magnified
octet to scale. Amber is the PSDU, the 802.15.4 frame the whole exchange exists to carry; everything
else on the figure is framing round it.

Every constant printed and every block size drawn is read out of src/rcp before the figure is drawn,
so a framing change in the tree refuses the figure rather than leaving it stale.

    python3 tools/diagrams/wire.py            # docs/images/wire.png
    python3 tools/diagrams/wire.py --check    # is the committed raster still this figure?
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import D, MX, S1, S2, S4  # noqa: E402

W = 1040
FW = W - 2 * MX
BH = 48                         # a field of a coarse row
ZH = 36                         # a field of a magnified block
ZOOM = 58                       # from a row's bottom to the next row's caption
CAP = 30                        # a row's caption and the air under it, down to its offsets
TIER = 30                       # one tier of extent brackets over a row

PATHS = ['src/rcp/hdlc.c', 'src/rcp/hdlc.h', 'src/rcp/spinel.c', 'src/rcp/spinel.h',
         'src/rcp/spinel_session.c', 'src/rcp/props.c', 'src/rcp/props.h', 'src/rcp/rcp_radio.c']
SYMBOLS = ['Hdlc_Encode', 'HDLC_FLAG', 'HDLC_ESCAPE', 'SpinelSession_Compose', 'PROP_STREAM_RAW',
           'radioOpTx', 'radioReadStreamRaw', 'psduIncludesFcs', 'RCP_RADIO_TX_TRAILER_LEN']

# The TX trailer as radioOpTx writes it, in order: (type letter, octets, name and what this stack writes)
TRAILER = [('C', 1, 'channel: 0, keep the current'), ('C', 1, 'maxCsmaBackoffs: the PIB\'s'),
           ('C', 1, 'maxFrameRetries: per frame'), ('b', 1, 'csmaCaEnabled: 1'),
           ('b', 1, 'isHeaderUpdated: 0'), ('b', 1, 'isRetransmission: 0'),
           ('b', 1, 'isSecurityProcessed: 0'), ('L', 4, 'txDelay: 0'), ('L', 4, 'txDelayBase: 0'),
           ('C', 1, 'rxChannelAfterTx: 0')]
# The RX metadata as radioReadStreamRaw reads it: (type letter, octets, kind, name and what is done)
METADATA = [('c', 1, 'blk', 'RSSI, dBm: kept'), ('c', 1, 'blk', 'noise floor: read, dropped'),
            ('S', 2, 'blk', 'MD_FLAG: bad FCS, dupe, acked FP'),
            ('S', 2, 'tag', 'MD_PHY length'), ('C', 1, 'blk', 'channel: read, dropped'),
            ('C', 1, 'blk', 'LQI: kept'), ('X', 8, 'blk', 'timestamp, device ticks: kept'),
            ('S', 2, 'tag', 'MD_VEND length'), ('i', 1, 'blk', 'RX error: packed uint'),
            ('S', 2, 'tag', 'MD_MAC length'), ('C', 1, 'blk', 'ack key id: counted only'),
            ('L', 4, 'blk', 'ack frame counter: counted only')]


def src(rel):
    with open(os.path.join(figure.ROOT, rel)) as f:
        return f.read()


def const(rel, name):
    """An enumerator's value as the source states it."""
    m = re.search(r'\b%s\s*=\s*(0x[0-9a-fA-F]+|\d+)' % re.escape(name), src(rel))
    if not m:
        raise SystemExit('wire: %s no longer states %s' % (rel, name))
    return int(m.group(1), 0)


def facts():
    c = {
        'flag': const('src/rcp/hdlc.h', 'HDLC_FLAG'), 'esc': const('src/rcp/hdlc.h', 'HDLC_ESCAPE'),
        'mask': const('src/rcp/hdlc.h', 'HDLC_ESCAPE_MASK'), 'fcs': const('src/rcp/hdlc.h', 'HDLC_FCS_LEN'),
        'max': const('src/rcp/hdlc.h', 'HDLC_PAYLOAD_MAX'),
        'hflag': const('src/rcp/spinel.h', 'SPINEL_HEADER_FLAG'),
        'set': const('src/rcp/spinel.h', 'SPINEL_CMD_PROP_VALUE_SET'),
        'is': const('src/rcp/spinel.h', 'SPINEL_CMD_PROP_VALUE_IS'),
        'tidmax': const('src/rcp/spinel.h', 'SPINEL_TID_MAX'),
        'uintmax': const('src/rcp/spinel.h', 'SPINEL_PACKED_UINT_MAX_BYTES'),
        'raw': const('src/rcp/props.h', 'PROP_STREAM_RAW'),
        'trailer': const('src/rcp/rcp_radio.c', 'RCP_RADIO_TX_TRAILER_LEN'),
        'phy': const('src/rcp/rcp_radio.c', 'RCP_RADIO_MD_PHY_LEN'),
        'vend': const('src/rcp/rcp_radio.c', 'RCP_RADIO_MD_VEND_LEN'),
        'mac': const('src/rcp/rcp_radio.c', 'RCP_RADIO_MD_MAC_LEN'),
    }
    # the octets Hdlc_NeedsEscape names besides the escape and the flag
    body = re.search(r'int Hdlc_NeedsEscape\(uint8_t octet\)\s*\{(.*?)\}', src('src/rcp/hdlc.c'), re.S)
    c['escaped'] = sorted(set(int(v, 16) for v in re.findall(r'0x([0-9a-fA-F]{2})', body.group(1)))
                          | {c['esc'], c['flag']})
    have = sum(n for _t, n, _w in TRAILER)
    if have != c['trailer']:
        raise SystemExit('wire: the trailer is drawn as %d octets, rcp_radio.c says %d' % (have, c['trailer']))
    want = 1 + 1 + 2 + (2 + c['phy']) + (2 + c['vend']) + (2 + c['mac'])
    have = sum(n for _t, n, _k, _w in METADATA)
    if have != want:
        raise SystemExit('wire: the metadata is drawn as %d octets, rcp_radio.c reads %d' % (have, want))
    groups = [sum(n for _t, n, _k, _w in METADATA[4:7]), METADATA[8][1], sum(n for _t, n, _k, _w in METADATA[10:])]
    if groups != [c['phy'], c['vend'], c['mac']]:
        raise SystemExit('wire: the metadata groups are drawn as %r, rcp_radio.c reads %r'
                         % (groups, [c['phy'], c['vend'], c['mac']]))
    return c


def row(f, y, fields, h=BH):
    """One run of fields left to right at their drawn widths, each offset above it; the spans."""
    x, spans = MX, []
    for name, sub, w, kind, off in fields:
        f.block(x, y, w, h, name, sub, kind, center=True)
        if off is not None:
            f.text(x + 2, y - S1, off, 'f-bit')
        spans.append((x, x + w))
        x += w
    if abs(x - (MX + FW)) > 0.5:
        raise SystemExit('wire: a row is %g px, the figure %g' % (x - MX, FW))
    return spans


def caption(f, y, cap, ident=None, line=None):
    """A row's name in caps, the code that writes or reads it in mono, and one plain line."""
    f.text(MX, y, cap, 'f-cap')
    x = MX + figure.textW(cap, 'f-cap') + S4
    if ident:
        f.text(x, y, ident, 'f-lab')
        x += figure.textW(ident, 'f-lab') + S2
    if line:
        f.fits(line, 'f-sub', MX + FW - x, 'the caption %r' % cap)
        f.text(x, y, line, 'f-sub')


def zoom(f, x0, x1, y, Y):
    f.line([(x0, y), (MX, Y)], 'f-rule')
    f.line([(x1, y), (MX + FW, Y)], 'f-rule')


def magnified(f, y, fields, start):
    """A fixed block octet to scale: its type letter inside, its name turned under it; the bottom."""
    n = sum(fld[1] for fld in fields)
    unit = FW / float(n)
    x, off = MX, 0
    for fld in fields:
        letter, octs, words = fld[0], fld[1], fld[-1]
        kind = fld[2] if len(fld) == 4 else 'blk'
        w = octs * unit
        f.block(x, y, w, ZH, letter, None, kind, center=True)
        f.text(x + 2, y - S1, '+%d' % off if off else start, 'f-bit')
        f.text(x + w / 2.0 + 4, y + ZH + S2, words, 'f-sub', 'end', rotate=-90)
        x += w
        off += octs
    return y + ZH + S2 + max(figure.textW(fld[-1], 'f-sub') for fld in fields)


def value(f, y, cap, ident, line, header, command, trailer_name, trailer_sub, c):
    """One STREAM_RAW value in its Spinel frame: the coarse row, then where its fixed block begins."""
    caption(f, y, cap, ident, line)
    y += CAP
    fixed = [150, 130, 110, 130, 250]
    spans = row(f, y, [
        ('header', header, fixed[0], 'blk', '0'),
        ('command', command, fixed[1], 'blk', '1'),
        ('property', '0x%02x' % c['raw'], fixed[2], 'blk', '2'),
        ('length', '2 %s the PSDU\'s, n' % D, fixed[3], 'tag', '3'),
        ('PSDU', 'the MPDU, its FCS as the dialect says', fixed[4], 'amb', '5'),
        (trailer_name, trailer_sub, FW - sum(fixed), 'blk', '5+n'),
    ])
    return y, spans


def build():
    c = facts()
    f = figure.Fig(W, 1600, 'WHAT CROSSES THE SERIAL LINE',
                   'HDLC frames carry Spinel frames; on the data path a Spinel frame carries one '
                   '802.15.4 frame and the radio\'s words about it')
    y = f.top + 10

    # ---- HDLC
    caption(f, y, 'HDLC, ON THE WIRE', 'Hdlc_Encode', 'the FCS is computed before escaping')
    y += CAP + TIER
    fixed = [110, 230, 110]
    hd = row(f, y, [
        ('HDLC_FLAG', '0x%02X' % c['flag'], fixed[0], 'tag', None),
        ('Spinel frame', 'at most %d octets before escaping' % c['max'], FW - sum(fixed), 'blk', None),
        ('FCS', '%d %s CRC-16/X.25, low octet first' % (c['fcs'], D), fixed[1], 'blk', None),
        ('HDLC_FLAG', '0x%02X' % c['flag'], fixed[2], 'tag', None),
    ])
    esc = ' '.join('0x%02X' % v for v in c['escaped'])
    words = '%s go out as 0x%02X, octet ^ 0x%02X' % (esc, c['esc'], c['mask'])
    f.hbracket(hd[1][0] + 2, hd[2][1] - 2, y - 10)
    lw = figure.textW('HDLC_ESCAPE', 'f-num') + S2 + figure.textW(words, 'f-sub')
    lx = (hd[1][0] + hd[2][1]) / 2.0 - lw / 2.0
    f.text(lx, y - 20, 'HDLC_ESCAPE', 'f-num')
    f.text(lx + figure.textW('HDLC_ESCAPE', 'f-num') + S2, y - 20, words, 'f-sub')
    f.fits('HDLC_ESCAPE  ' + words, 'f-sub', hd[2][1] - hd[1][0], 'the escape extent')
    y2 = y + BH + ZOOM
    zoom(f, hd[1][0], hd[1][1], y + BH, y2 - 18)

    # ---- Spinel
    y = y2
    caption(f, y, 'SPINEL FRAME', 'SpinelSession_Compose', 'direction is not in the header: the command says it')
    y += CAP
    fixed = [250, 210, 210]
    row(f, y, [
        ('header', 'flag 0b10 %s IID 0 %s TID 0 to %d' % (D, D, c['tidmax']), fixed[0], 'blk', '0'),
        ('command', 'packed uint, 1 to %d octets' % c['uintmax'], fixed[1], 'blk', '1'),
        ('property id', 'packed uint, 1 to %d octets' % c['uintmax'], fixed[2], 'blk', None),
        ('value', 'as the property\'s type says', FW - sum(fixed), 'blk', None),
    ])
    y += BH + ZOOM - 10

    # ---- the TX request
    y, sp = value(f, y, 'HOST TO RCP: THE TX REQUEST', 'radioOpTx', 'answered later by a completion',
                  '0x%02X %s TID' % (c['hflag'], D), '%d %s SET' % (c['set'], D),
                  'trailer', '%d octets' % c['trailer'], c)
    y2 = y + BH + 44
    zoom(f, sp[5][0], sp[5][1], y + BH, y2 - 14)
    y = magnified(f, y2, TRAILER, '5+n') + 56

    # ---- the RX notification
    y, sp = value(f, y, 'RCP TO HOST: THE RX NOTIFICATION', 'radioReadStreamRaw', 'unsolicited',
                  '0x%02X %s TID 0' % (c['hflag'], D), '%d %s VALUE_IS' % (c['is'], D),
                  'metadata', '%d octets' % sum(n for _t, n, _k, _w in METADATA), c)
    y2 = y + BH + 44
    zoom(f, sp[5][0], sp[5][1], y + BH, y2 - 14)
    y = magnified(f, y2, METADATA, '5+n')

    ly = f.legend(y + 56, [('amb', 'the PSDU, the 802.15.4 frame carried'), ('blk', 'a field'),
                           ('tag', 'framing: a flag or a length prefix')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    sys.exit(figure.main('wire', build, paths=PATHS, symbols=SYMBOLS))
