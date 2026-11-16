#!/usr/bin/env python3
"""The bands and the seam, owned by docs/internals/architecture.md section 2.

Content only: the style, the renderer and the checks are in figure.py. Every block names the
sources it stands for, and the generator refuses to draw when one of them is gone, or when
test/bands_audit.py no longer holds the rule the figure draws.

The figure is a stack read downwards. Amber goes to band A only, because that is what the figure
is about: the library, the same code on every target, which never touches a platform. The two
contracts are the rules between bands; the substrate stands beside every band, because any band
may include it and it includes none.

    python3 tools/diagrams/bands.py            # docs/images/bands.png
    python3 tools/diagrams/bands.py --check    # is the committed raster still this figure?
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import D, MX, S1, S2, S3, S5  # noqa: E402

W = 1240
X0, X1 = 176, 1056             # where blocks start and end; the gutter names each band
BH = 46
CONTRACT = 56                  # a contract: the air, the rule with its chips, the air
BAND_GAP = 28                 # the air between two bands that meet without a contract

Z, N, A, M = 'src/zb/', 'src/zb/nwk/', 'src/zb/aps/', 'src/zb/mac/'


def mods(base, *names):
    return [base + n + '.c' for n in names]


APP = [
    [('examples/', 'a coordinator %s a router' % D, 'tag',
      ['examples/coordinator/coordinator.c', 'examples/router/router.c']),
     ('your application', 'zb_stack.h, and nothing below it', 'tag', [])],
]
# (name, plain line, kind, the sources the block stands for)
LIBRARY = [
    ('application', [
        ('af', 'endpoints %s the ASDU' % D, 'amb', mods(Z + 'af/', 'af')),
        ('zdo', 'the device object', 'amb', mods(Z + 'zdo/', 'zdo')),
        ('zcl', 'clusters, both ways', 'amb', mods(Z + 'zcl/', 'zcl')),
        ('zb_state', 'the persistence snapshot', 'amb', mods(Z, 'zb_state')),
    ]),
    ('APS', [
        ('aps', 'the data service', 'amb', mods(A, 'aps', 'aps_rx', 'aps_tx', 'aps_frame')),
        ('aps_ack', 'acks %s duplicates' % D, 'amb', mods(A, 'aps_ack', 'aps_dup')),
        ('aps_frag', 'fragmentation', 'amb', mods(A, 'aps_frag')),
        ('aps_bind', 'binding %s groups' % D, 'amb', mods(A, 'aps_bind', 'aps_group')),
        ('aps_tclink', 'keys %s who may join' % D, 'amb',
         mods(A, 'aps_tclink', 'aps_transportkey', 'aps_keydoor', 'aps_admit')),
    ]),
    ('NWK', [
        ('nwk', 'the data service', 'amb',
         mods(N, 'nwk', 'nwk_tx', 'nwk_rx', 'nwk_get', 'nwk_frame', 'nwk_tlv')),
        ('security', 'the frame crossing', 'amb', mods(Z, 'security')),
        ('nwk_join', 'join %s rejoin %s leave' % (D, D), 'amb',
         mods(N, 'nwk_join', 'nwk_discovery', 'nwk_commissioning', 'nwk_permit', 'nwk_leave',
              'nwk_parents', 'nwk_beacon', 'nwk_addr', 'nwk_poll')),
        ('nwk_command', 'commands %s status' % D, 'amb', mods(N, 'nwk_command', 'nwk_status')),
        ('nwk_btt', 'broadcasts', 'amb', mods(N, 'nwk_btt')),
    ]),
    ('', [
        ('nwk_route', 'routes %s source routes' % D, 'amb', mods(N, 'nwk_route', 'nwk_sourceroute')),
        ('nwk_rreq', 'route discovery', 'amb',
         mods(N, 'nwk_rreq', 'nwk_rreqtx', 'nwk_rreqrx', 'nwk_rreqrelay', 'nwk_rrep', 'nwk_rreprx')),
        ('nwk_relay', 'relaying', 'amb', mods(N, 'nwk_relay')),
        ('nwk_neighbor', 'neighbours %s link status' % D, 'amb',
         mods(N, 'nwk_neighbor', 'nwk_linkstatus', 'nwk_cost', 'nwk_timeout')),
        ('nwk_indirect', 'sleeping children', 'amb', mods(N, 'nwk_indirect')),
    ]),
    ('MAC', [
        ('mac', 'MLME %s MCPS' % D, 'amb', mods(M, 'mac') + mods(Z, 'mac_frame')),
        ('mac_tx', 'transmit %s retries' % D, 'amb', mods(M, 'mac_tx')),
        ('mac_rx', 'receive %s filter' % D, 'amb', mods(M, 'mac_rx')),
        ('mac_assoc', 'association', 'amb', mods(M, 'mac_assoc')),
        ('mac_scan', 'scans %s beacons' % D, 'amb', mods(M, 'mac_scan', 'mac_beacon')),
        ('mac_indirect', 'the indirect queue', 'amb', mods(M, 'mac_indirect')),
    ]),
]
BACKENDS = [
    [('rcp_radio', 'a radio co-processor', 'blk', ['src/rcp/rcp_radio.c']),
     ('spinel_session', 'one request at a time', 'blk', ['src/rcp/spinel_session.c']),
     ('spinel', 'typed fields', 'blk', ['src/rcp/spinel.c']),
     ('props', 'the dialect', 'blk', ['src/rcp/props.c']),
     ('hdlc', 'the byte framing', 'blk', ['src/rcp/hdlc.c']),
     ('loopback_radio', 'no hardware', 'blk', ['src/loopback/loopback_radio.c'])],
]
PORTS = [
    [('port_posix', 'Linux %s macOS %s BSD' % (D, D), 'blk', ['src/port/port_posix.c']),
     ('port_win32', 'Windows, a stub', 'owe', ['src/port/port_win32.c']),
     ('port_null', 'scripted, no device', 'blk', ['src/port/port_null.c']),
     ('port_log', 'a line per record', 'blk',
      ['src/port/port_log_posix.c', 'src/port/port_log_win32.c', 'src/port/log_names.c'])],
]
DOORS = (['zb_stack.h', 'zb_core.h'],
         'Zb_Stack: one object reporting events; Zb_Core under it, for a loop of its own',
         ['src/stack/zb_stack.c', 'src/stack/zb_stack.h', 'src/zb/zb_core.c', 'src/zb/zb_core.h'])
SEAM = (['seam/radio.h'], 'the seam: a PSDU pipe and a report of what the radio can do',
        ['src/seam/radio.h'])
PORT = (['port/port.h'], 'bytes in and out, a millisecond clock, entropy',
        ['src/port/port.h', 'src/port/port.c'])
STICKS = [('ConBee II  %s  RaspBee II' % D, 'ATSAMR21, running Phoscon RCP'),
          ('ConBee III', 'EFR32MG21, running Phoscon RCP')]
SIDE = ('substrate', 'utils %s log %s crypto %s vendor/' % (D, D, D),
        ['src/utils/zb_utils.c', 'src/log/log.c', 'src/crypto/aes.h', 'vendor/u_bstream',
         'vendor/u_sstream'])
SYMBOLS = ['tx', 'completion', 'rxPoll', 'Port_Read', 'Port_Write', 'Port_NowMs', 'Port_Entropy']


def paths():
    out = []
    for rows in (APP, BACKENDS, PORTS):
        for row in rows:
            for b in row:
                out += b[3]
    for _label, row in LIBRARY:
        for b in row:
            out += b[3]
    for c in (DOORS, SEAM, PORT, SIDE):
        out += c[2]
    return out


def gutter(f, y, name, sub):
    f.text(MX, y + 18, name, 'f-lab')
    for k, ln in enumerate(sub):
        f.text(MX, y + 34 + 14 * k, ln, 'f-sub')


def row(f, y, blocks, x0=X0):
    n = len(blocks)
    w = (X1 - x0 - (n - 1) * S2) / float(n)
    for j, (bn, bs, kind, _p) in enumerate(blocks):
        f.block(x0 + j * (w + S2), y, w, BH, bn, bs, kind)
    return y + BH


def contract(f, y, chips, detail):
    mid = y + CONTRACT / 2.0
    x = X0
    for c in chips:
        x += f.chip(x, mid - 12, c) + S1
    f.line([(x + S1, mid), (X1, mid)], 'f-rule')
    f.fits(detail, 'f-sub', X1 - x - S5, 'the contract %r' % chips[0])
    f.text(X1, mid - S2, detail, 'f-sub', 'end')
    return y + CONTRACT


def build():
    f = figure.Fig(W, 1000, 'BANDS: ONE LIBRARY, TWO CONTRACTS BELOW IT',
                   'band A never touches a platform: what it needs crosses the seam, or the caller '
                   'lends it')
    y = top = f.top + S2

    gutter(f, y, 'application', ['built on the doors'])
    y = row(f, y, APP[0])
    y = contract(f, y, *DOORS[:2])

    gutter(f, y, 'band A', ['the library:', 'MAC, NWK, APS and', 'the application layer'])
    lx = X0 + 96
    for label, blocks in LIBRARY:
        if label:
            f.text(X0, y + BH / 2.0 + 4, label, 'f-cap')
        y = row(f, y, blocks, lx) + S2
    y -= S2
    y = contract(f, y, *SEAM[:2])

    gutter(f, y, 'band B', ['a radio backend:', 'an RCP, its dialect,', 'its framing'])
    y = row(f, y, BACKENDS[0])
    y = contract(f, y, *PORT[:2])

    gutter(f, y, 'band C', ['the port: the only', 'code that knows a', 'serial device'])
    y = row(f, y, PORTS[0]) + BAND_GAP

    sw = (X1 - X0 - S2) / 2.0
    for k, (name, sub) in enumerate(STICKS):
        f.block(X0 + k * (sw + S2), y, sw, BH, name, sub, 'brt')
    f.text(MX, y + 18, 'the RCP', 'f-lab')
    f.text(MX, y + 34, 'outside the tree', 'f-sub')
    bottom = y + BH

    # the substrate stands beside every band, because every band may include it
    sx = X1 + S5
    f.rect(sx, top, 40, bottom - BH - BAND_GAP - top, 'f-blk')
    mid = (top + bottom - BH - BAND_GAP) / 2.0
    f.text(sx + 25, mid, '%s:  %s' % SIDE[:2], 'f-id', 'middle', rotate=-90)
    ax = sx + 40 + S5
    f.line([(ax, top), (ax, bottom)], 'f-out', 'ink')
    f.text(ax + S2, (top + bottom) / 2.0, 'CALLS GO DOWN', 'f-cap', 'middle', rotate=90)
    ax += 36
    f.line([(ax, bottom), (ax, top)], 'f-back', 'line')
    f.text(ax + S2, (top + bottom) / 2.0, 'RESULTS ARE POLLED, NOTHING CALLS UP', 'f-cap',
           'middle', rotate=90)
    if ax + S2 + 12 > W - MX:
        raise SystemExit('bands: the arrows run past the page')

    ly = f.legend(bottom + 36, [('amb', 'band A: the library, the same on every target'),
                                ('blk', 'a module'), ('owe', 'owed'),
                                ('tag', 'a contract, or code outside the library'),
                                ('brd', 'hardware')])
    f.h = ly + 16
    return f


if __name__ == '__main__':
    sys.exit(figure.main('bands', build, paths=paths(), symbols=SYMBOLS, bands=True))
