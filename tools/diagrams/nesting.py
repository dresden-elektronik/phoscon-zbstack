#!/usr/bin/env python3
"""One secured Zigbee data frame, layer inside layer, for the internals documentation.

Content only: the style, the renderer and the checks are in figure.py. Each row is the payload of the
row above, magnified: the PHY packet, the MAC frame, the NWK frame with its auxiliary security header,
and then what the encrypted payload is in clear, the APS frame and one form of its ASDU, a ZCL frame.
Field widths are not to scale; the offsets above each row are octets from that layer's first octet.

Amber is the encrypted NWK payload: it is the one field the security crossing changes, the line
between what any receiver reads (every row above it, and the headers beside it) and what only a holder
of the network key reads (the two rows under it). The brackets over the NWK row are CCM*'s two inputs:
the header and the auxiliary header authenticated in clear as the a-data, the payload encrypted as the
m-data, and the MIC after it. Every octet width drawn is read out of the codec headers before the figure
is drawn, so a width that moves in the tree refuses the figure.

    python3 tools/diagrams/nesting.py            # docs/images/nesting.png
    python3 tools/diagrams/nesting.py --check    # is the committed raster still this figure?
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import D, MX, S1, S2, S4  # noqa: E402

W = 1240
FW = W - 2 * MX
BH = 48                         # a field
ZOOM = 58                       # from a row's bottom to the next row's caption
CAP = 30                        # a row's caption and the air under it, down to its offsets
TIER = 30                       # one tier of extent brackets over a row

PATHS = ['src/zb/mac_frame.c', 'src/zb/mac_frame.h', 'src/zb/nwk/nwk_frame.c', 'src/zb/nwk/nwk_frame.h',
         'src/zb/security.c', 'src/zb/security.h', 'src/zb/aps/aps_frame.c', 'src/zb/aps/aps_frame.h',
         'src/zb/zcl/zcl.c', 'src/zb/zcl/zcl.h']
SYMBOLS = ['MacFrame_Compose', 'MacFrame_AppendFcs', 'NwkFrame_Compose', 'Security_Protect',
           'Security_Unprotect', 'ApsFrame_Compose', 'Zcl_FrameCompose', 'ZCL_CMD_READ_ATTRIBUTES',
           'SECURITY_LEVEL_ENC_MIC_32']


def octets(rel, name):
    """An enumerator's value as the header states it, so a width drawn is a width the codec has."""
    with open(os.path.join(figure.ROOT, rel)) as f:
        m = re.search(r'\b%s\s*=\s*(0x[0-9a-fA-F]+|\d+)' % re.escape(name), f.read())
    if not m:
        raise SystemExit('nesting: %s no longer states %s' % (rel, name))
    return int(m.group(1), 0)


def widths():
    mac, nwk, sec, aps = 'src/zb/mac_frame.h', 'src/zb/nwk/nwk_frame.h', 'src/zb/security.h', \
        'src/zb/aps/aps_frame.h'
    w = {
        'mac.fcf': octets(mac, 'MAC_FRAME_FCF_OCTETS'), 'mac.seq': octets(mac, 'MAC_FRAME_SEQ_OCTETS'),
        'mac.pan': octets(mac, 'MAC_FRAME_PAN_OCTETS'), 'mac.short': octets(mac, 'MAC_FRAME_SHORT_OCTETS'),
        'mac.fcs': octets(mac, 'MAC_FRAME_FCS_OCTETS'), 'mac.max': octets(mac, 'MAC_FRAME_MPDU_MAX'),
        'nwk.fcf': octets(nwk, 'NWK_FRAME_FCF_OCTETS'), 'nwk.addr': octets(nwk, 'NWK_FRAME_ADDR_OCTETS'),
        'nwk.radius': octets(nwk, 'NWK_FRAME_RADIUS_OCTETS'), 'nwk.seq': octets(nwk, 'NWK_FRAME_SEQ_OCTETS'),
        'nwk.ieee': octets(nwk, 'NWK_IEEE_ADDR_OCTETS'), 'nwk.min': octets(nwk, 'NWK_MIN_HEADER_OVERHEAD'),
        'sec.aux': octets(sec, 'SECURITY_AUX_LEN'), 'sec.mic': octets(sec, 'SECURITY_MIC_32_OCTETS'),
        'sec.level': octets(sec, 'SECURITY_LEVEL_ENC_MIC_32'),
        'aps.fcf': octets(aps, 'APS_FRAME_FCF_OCTETS'), 'aps.ep': octets(aps, 'APS_FRAME_ENDPOINT_OCTETS'),
        'aps.cluster': octets(aps, 'APS_FRAME_CLUSTER_OCTETS'),
        'aps.profile': octets(aps, 'APS_FRAME_PROFILE_OCTETS'),
        'aps.counter': octets(aps, 'APS_FRAME_COUNTER_OCTETS'),
        'zcl.read': octets('src/zb/zcl/zcl.h', 'ZCL_CMD_READ_ATTRIBUTES'),
    }
    # the auxiliary header as securityDoWriteAux writes it: control, counter, source, key sequence
    w['aux'] = [1, 4, 8, 1]
    if sum(w['aux']) != w['sec.aux']:
        raise SystemExit('nesting: the auxiliary header is drawn as %d octets, security.h says %d'
                         % (sum(w['aux']), w['sec.aux']))
    if w['nwk.fcf'] + 2 * w['nwk.addr'] + w['nwk.radius'] + w['nwk.seq'] != w['nwk.min']:
        raise SystemExit('nesting: the NWK header\'s fixed fields no longer sum to NWK_MIN_HEADER_OVERHEAD')
    # Figure 2-2's header as Zcl_FrameCompose sizes it: three octets, two more with a manufacturer code
    if not re.search(r'total = 3 \+ payloadLen \+ \(\(header->frameControl & ZCL_FC_MANUFACTURER\) != 0 \? 2 : 0\)',
                     open(os.path.join(figure.ROOT, 'src/zb/zcl/zcl.c')).read()):
        raise SystemExit('nesting: Zcl_FrameCompose no longer sizes the header drawn')
    return w


def row(f, y, fields):
    """One layer: the fields left to right at their drawn widths, each offset above it; the spans."""
    x, spans = MX, []
    for name, sub, w, kind, off in fields:
        f.block(x, y, w, BH, name, sub, kind, center=True)
        if off is not None:
            f.text(x + 2, y - S1, off, 'f-bit')
        spans.append((x, x + w))
        x += w
    if abs(x - (MX + FW)) > 0.5:
        raise SystemExit('nesting: a row is %g px, the figure %g' % (x - MX, FW))
    return spans


def caption(f, y, cap, ident=None, line=None):
    """A row's name in caps, the code that writes it in mono, and one plain line."""
    f.text(MX, y, cap, 'f-cap')
    x = MX + figure.textW(cap, 'f-cap') + S4
    if ident:
        f.text(x, y, ident, 'f-lab')
        x += figure.textW(ident, 'f-lab') + S2
    if line:
        f.text(x, y, line, 'f-sub')


def zoom(f, x0, x1, y, Y):
    """The two lines that say: the field above, drawn larger below."""
    f.line([(x0, y), (MX, Y)], 'f-rule')
    f.line([(x1, y), (MX + FW, Y)], 'f-rule')


def extent(f, x0, x1, y, name, line=None):
    """A bracket over a run of fields: its name in the number voice, an optional plain line after it."""
    f.hbracket(x0 + 2, x1 - 2, y)
    if line:
        tw = figure.textW(name, 'f-num') + S2 + figure.textW(line, 'f-sub')
        cx = (x0 + x1) / 2.0 - tw / 2.0
        f.text(cx, y - 6 - S1, name, 'f-num')
        f.text(cx + figure.textW(name, 'f-num') + S2, y - 6 - S1, line, 'f-sub')
        f.fits(name + '  ' + line, 'f-sub', x1 - x0, 'the extent %r' % name)
    else:
        f.text((x0 + x1) / 2.0, y - 6 - S1, name, 'f-num', 'middle')
        f.fits(name, 'f-num', x1 - x0, 'the extent %r' % name)


def build():
    w = widths()
    f = figure.Fig(W, 1000, 'ONE ZIGBEE FRAME, LAYER INSIDE LAYER',
                   'each row is the payload of the row above; the NWK layer encrypts its payload '
                   'and authenticates it together with the headers in front of it')
    y = f.top + 10

    # ---- PHY: what the radio puts round the MPDU; the RCP's own, never on the serial line
    caption(f, y, 'PHY PACKET', None, 'built and stripped by the RCP\'s radio')
    y += CAP - 10
    phy = row(f, y, [
        ('SHR', 'preamble %s start-of-frame delimiter' % D, 240, 'keep', None),
        ('PHR', 'frame length, bits 0-6', 200, 'keep', None),
        ('PSDU', 'the MPDU, at most %d octets' % w['mac.max'], FW - 440, 'blk', None),
    ])
    y2 = y + BH + ZOOM
    zoom(f, phy[2][0], phy[2][1], y + BH, y2 - 18)

    # ---- MAC: PAN ID compression on, both addresses short, so no source PAN field
    y = y2
    caption(f, y, 'MAC FRAME', 'MacFrame_Compose %s MacFrame_AppendFcs' % D,
            'PAN ID compression, so no source PAN')
    y += CAP
    o = [0]
    for k in ('mac.fcf', 'mac.seq', 'mac.pan', 'mac.short', 'mac.short'):
        o.append(o[-1] + w[k])
    fixed = [150, 110, 150, 150, 150, 120]
    mac = row(f, y, [
        ('frame control', '%d octets' % w['mac.fcf'], fixed[0], 'blk', str(o[0])),
        ('seq', '%d octet' % w['mac.seq'], fixed[1], 'blk', str(o[1])),
        ('dest PAN', '%d octets' % w['mac.pan'], fixed[2], 'blk', str(o[2])),
        ('dest', '%d octets %s short' % (w['mac.short'], D), fixed[3], 'blk', str(o[3])),
        ('src', '%d octets %s short' % (w['mac.short'], D), fixed[4], 'blk', str(o[4])),
        ('payload', 'the NPDU, n octets', FW - sum(fixed), 'gap', str(o[5])),
        ('FCS', '%d octets' % w['mac.fcs'], fixed[5], 'blk', '%d+n' % o[5]),
    ])
    y2 = y + BH + ZOOM
    zoom(f, mac[5][0], mac[5][1], y + BH, y2 - 18)

    # ---- NWK: header, auxiliary security header, encrypted payload, MIC
    y = y2
    caption(f, y, 'NWK FRAME, SECURED', 'NwkFrame_Compose %s Security_Protect' % D,
            'level %d: encrypted, %d-octet MIC' % (w['sec.level'], w['sec.mic']))
    y += CAP + 2 * TIER
    h = w['nwk.min']
    o = [0]
    for k in ('nwk.fcf', 'nwk.addr', 'nwk.addr', 'nwk.radius'):
        o.append(o[-1] + w[k])
    a = ['h']
    for n in w['aux']:
        a.append('h+%d' % (int(a[-1][2:] or 0) + n))
    nwk = row(f, y, [
        ('frame control', '%d octets' % w['nwk.fcf'], 118, 'blk', str(o[0])),
        ('dest', '%d %s short' % (w['nwk.addr'], D), 74, 'blk', str(o[1])),
        ('src', '%d %s short' % (w['nwk.addr'], D), 74, 'blk', str(o[2])),
        ('radius', '%d' % w['nwk.radius'], 66, 'blk', str(o[3])),
        ('seq', '%d' % w['nwk.seq'], 56, 'blk', str(o[4])),
        ('IEEE %s route' % D, 'only when flagged', 132, 'gap', str(h)),
        ('control', '%d %s level 0 on air' % (w['aux'][0], D), 116, 'blk', a[0]),
        ('counter', '%d %s frame counter' % (w['aux'][1], D), 120, 'blk', a[1]),
        ('source', '%d %s sender EUI-64' % (w['aux'][2], D), 120, 'blk', a[2]),
        ('key seq', '%d' % w['aux'][3], 72, 'blk', a[3]),
        ('payload', 'the APDU, encrypted', 180, 'amb', a[4]),
        ('MIC', '%d octets' % w['sec.mic'], FW - 1128, 'blk', a[4] + '+p'),
    ])
    hdr0, hdr1 = nwk[0][0], nwk[5][1]
    aux0, aux1 = nwk[6][0], nwk[9][1]
    pay0, pay1 = nwk[10]
    mic0, mic1 = nwk[11]
    # tier 1: what each run is; tier 2: what CCM* does with it
    t1 = y - 18
    extent(f, hdr0, hdr1, t1, 'NWK header', 'h octets: %d, more when flagged' % h)
    extent(f, aux0, aux1, t1, 'auxiliary security header', '%d octets' % w['sec.aux'])
    extent(f, pay0, pay1, t1, 'p octets')
    t2 = t1 - TIER
    extent(f, hdr0, aux1, t2, 'authenticated, sent in clear',
           'CCM* a-data, the control octet with its level put back')
    extent(f, pay0, pay1, t2, 'encrypted', 'm-data')
    extent(f, mic0, mic1, t2, 'tag')
    y2 = y + BH + ZOOM
    zoom(f, pay0, pay1, y + BH, y2 - 18)

    # ---- APS: the encrypted payload, in clear
    y = y2
    caption(f, y, 'APS FRAME, THE PAYLOAD IN CLEAR', 'ApsFrame_Compose %s Security_Unprotect' % D,
            'never on the air in clear')
    y += CAP
    o = [0]
    for k in ('aps.fcf', 'aps.ep', 'aps.cluster', 'aps.profile', 'aps.ep', 'aps.counter'):
        o.append(o[-1] + w[k])
    fixed = [150, 130, 150, 150, 130, 130]
    aps = row(f, y, [
        ('frame control', '%d octet' % w['aps.fcf'], fixed[0], 'blk', str(o[0])),
        ('dst endpoint', '%d octet' % w['aps.ep'], fixed[1], 'blk', str(o[1])),
        ('cluster', '%d octets' % w['aps.cluster'], fixed[2], 'blk', str(o[2])),
        ('profile', '%d octets' % w['aps.profile'], fixed[3], 'blk', str(o[3])),
        ('src endpoint', '%d octet' % w['aps.ep'], fixed[4], 'blk', str(o[4])),
        ('APS counter', '%d octet' % w['aps.counter'], fixed[5], 'blk', str(o[5])),
        ('ASDU', 'the application\'s octets', FW - sum(fixed), 'gap', str(o[6])),
    ])
    y2 = y + BH + ZOOM
    zoom(f, aps[6][0], aps[6][1], y + BH, y2 - 18)

    # ---- ZCL: one form an ASDU takes, as Zcl_FrameCompose writes it
    y = y2
    caption(f, y, 'ZCL FRAME, ONE FORM OF THE ASDU', 'Zcl_FrameCompose',
            'here a read attributes request')
    y += CAP
    fixed = [150, 190, 150, 210]
    row(f, y, [
        ('frame control', '1 octet', fixed[0], 'blk', '0'),
        ('manufacturer', '0 or 2 octets, if flagged', fixed[1], 'gap', '1'),
        ('TSN', '1 %s transaction seq' % D, fixed[2], 'blk', '1 or 3'),
        ('command', '1 %s 0x%02x, read attributes' % (D, w['zcl.read']), fixed[3], 'blk', '2 or 4'),
        ('payload', 'attribute identifiers, 2 octets each', FW - sum(fixed), 'gap', '3 or 5'),
    ])
    y += BH

    ly = f.legend(y + 40, [('amb', 'the encrypted NWK payload'), ('blk', 'a field'),
                           ('gap', 'variable, or present only when flagged'),
                           ('keep', 'the radio\'s own: never crosses the serial line'),
                           ('br', 'an extent')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    sys.exit(figure.main('nesting', build, paths=PATHS, symbols=SYMBOLS))
