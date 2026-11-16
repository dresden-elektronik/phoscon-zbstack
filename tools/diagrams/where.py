#!/usr/bin/env python3
"""What runs where, owned by README.md.

Content only: the style, the renderer and the checks are in figure.py. The figure is for someone
deciding whether to use the stack, so it names layers, not modules: the whole Zigbee stack, MAC
included, runs on the host, and the RCP is a radio behind Spinel. Amber is that stack, the
subject; every layer drawn as the host's names the source directory it stands for, and the
generator refuses to draw when one of them is gone.

    python3 tools/diagrams/where.py            # docs/images/where.png
    python3 tools/diagrams/where.py --check    # is the committed raster still this figure?
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import D, MX, S2, S4  # noqa: E402

W = 760
BW = W - 2 * MX
BH, BG = 44, 8                 # a block and the air between two
LABEL = 26                     # a group's caps label and the air under it
RULE = 64                      # a boundary: the air, the rule with its chip, the air

HOST = [
    ('your application', 'a coordinator %s a router %s a gateway' % (D, D), 'tag',
     ['examples/coordinator/coordinator.c', 'examples/router/router.c']),
    ('ZDO %s ZCL %s AF' % (D, D), 'the application layer: endpoints, discovery, clusters', 'amb',
     ['src/zb/zdo', 'src/zb/zcl', 'src/zb/af']),
    ('APS', 'delivery %s acknowledgements %s binding %s groups %s keys' % (D, D, D, D), 'amb',
     ['src/zb/aps']),
    ('NWK', 'joining %s routing %s relaying %s network security' % (D, D, D), 'amb',
     ['src/zb/nwk', 'src/zb/security.c']),
    ('MAC', 'frames %s retries %s association %s indirect delivery' % (D, D, D), 'amb',
     ['src/zb/mac']),
    ('port', 'the serial device, a millisecond clock, entropy', 'blk', ['src/port/port.h']),
]
STICK = [
    ('Phoscon RCP', 'the radio firmware: CSMA %s Ack %s address filter %s energy scan' % (D, D, D),
     'blk'),
    ('PHY', 'the RCP\'s 802.15.4 radio', 'blk'),
]
BOARDS = ['ConBee I', 'ConBee II', 'ConBee III', 'RaspBee I', 'RaspBee II']


def paths():
    out = []
    for b in HOST:
        out += b[3]
    return out


def stack(f, y, blocks):
    for b in blocks:
        f.block(MX, y, BW, BH, b[0], b[1], b[2])
        y += BH + BG
    return y - BG


def boundary(f, y, chip, wire):
    """A boundary: a rule across the page, broken by the chip that names what crosses it."""
    mid = y + RULE / 2.0
    w = f.chip(MX, mid - 12, chip)
    f.line([(MX + w, mid), (MX + BW, mid)], 'f-out')
    f.fits(wire, 'f-sub', BW - w - S4, 'the boundary %r' % chip)
    f.text(MX + BW, mid - S2, wire, 'f-sub', 'end')
    return y + RULE


def build():
    f = figure.Fig(W, 1000, 'WHAT RUNS WHERE',
                   'the whole Zigbee stack runs on the host; the RCP is a radio')
    y = f.top + S2
    f.text(MX, y + 14, 'HOST', 'f-cap')
    y = stack(f, y + LABEL, HOST)
    y = boundary(f, y, 'Spinel', 'HDLC frames over USB or a UART')
    f.text(MX, y + 14, 'RCP', 'f-cap')
    y = stack(f, y + LABEL, STICK) + S4
    f.block(MX, y, BW, 52, ('  %s  ' % D).join(BOARDS), 'one 802.15.4 radio each', 'brt')
    y = boundary(f, y + 52, '802.15.4', 'the air, 2.4 GHz')
    f.block(MX, y, BW, BH, 'Zigbee devices', 'lights %s sensors %s plugs %s other routers' % (D, D, D),
            'tag')
    y += BH
    ly = f.legend(y + 36, [('amb', 'the Zigbee stack: one library, the same on every host'), ('blk', 'a layer'),
                           ('tag', 'outside it'), ('brd', 'the RCP')])
    f.h = ly + 16
    return f


if __name__ == '__main__':
    sys.exit(figure.main('where', build, paths=paths()))
