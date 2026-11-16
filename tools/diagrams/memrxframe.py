#!/usr/bin/env python3
"""One frame received: every buffer a full frame is copied into, from the MAC to the application.

Content only: the style, the renderer and the checks are in figure.py. One row per buffer in the
order the frame climbs; an outline is as wide as the buffer, its amber fill as wide as the frame's
octets in it, and a buffer on the call stack is hatched. Under the rows, the payload the
application gets is set against every buffer it passed through, end to end. The rows are
docs/memory.md §3.2's table, read here; memtxframe.py draws §4.1 with the same function.

    python3 tools/diagrams/memrxframe.py            # docs/images/memrxframe.png
    python3 tools/diagrams/memrxframe.py --check    # is the committed raster still this figure?
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import MX, S2, S4  # noqa: E402

DOC = 'docs/memory.md'
PX = 0.3                       # px per byte, every bar
NW = 300                       # the buffer names
X0 = MX + NW + S4              # the bars
RH, RG = 24, 8                 # a row's height, the air between rows
ASDU = 82                      # the payload delivered: AF_ASDU_MAX, the APS ceiling less its header
SPAN = 1850                    # the bytes the widest figure needs: both share one scale and width
W = X0 + int(SPAN * PX) + MX

SYMBOLS = ['batch', 'indications', 'macIndication', 'adata', 'frame',
           'plainScratch', 'Zb_CoreStep', 'indication', 'AF_ASDU_MAX']
PATHS = ['src/zb/mac/mac_rx.h', 'src/zb/nwk/nwk.h', 'src/zb/security.h',
         'src/zb/aps/aps.h', 'src/zb/zb_core.c']


def name(buf):
    """`rx.batch, one entry` -> `rx.batch`; `Zb_CoreStep's indication` -> `Zb_CoreStep · indication`."""
    return buf.split(', ')[0].replace("'s ", ' %s ' % figure.D)


def draw(title, lead, section, payload_words):
    rows = figure.docTable(DOC, section)
    f = figure.Fig(W, 1200, title, lead)
    y = f.top + S2
    for layer, buf, size, octets, held, where in rows:
        b, o = figure.bytesOf(size), figure.bytesOf(octets)
        label = '%s %s %s' % (layer, figure.D, name(buf))
        f.fits(label, 'f-lab', NW, 'the buffer names')
        f.text(MX + NW, y + RH / 2.0 + 4, label, 'f-lab', 'end')
        f.rect(X0, y, b * PX, RH, 'f-keep' if where == 'stack' else 'f-blk')
        f.rect(X0 + 2, y + 5, o * PX - 4, RH - 10, 'f-amb', rx=1)
        f.text(X0 + b * PX + S2, y + RH / 2.0 + 4, 'held until ' + held, 'f-sub')
        y += RH + RG

    # the payload against everything it passed through, end to end
    y += S4
    f.text(MX + NW, y + RH / 2.0 + 4, payload_words, 'f-lab', 'end')
    f.rect(X0, y, ASDU * PX, RH, 'f-amb')
    y += RH + RG
    f.text(MX + NW, y + RH / 2.0 + 4, 'the buffers it passed through', 'f-lab', 'end')
    x = X0
    for layer, buf, size, _octets, _held, where in rows:
        b = figure.bytesOf(size) * PX
        f.rect(x, y, b, RH, 'f-keep' if where == 'stack' else 'f-blk', rx=0)
        x += b
    bottom = y + RH

    keys = [('blk', 'a buffer in the object')]
    if any(r[5] == 'stack' for r in rows):
        keys.append(('keep', 'a buffer on the call stack'))
    ly = f.legend(bottom + 40, keys + [('amb', 'the frame\'s octets in it')])
    f.h = ly + S4
    return f


def build():
    return draw('MEMORY: ONE FRAME RECEIVED',
                'a full frame climbing from the MAC to the application\'s ring, every buffer '
                'it is copied into', '3.2', 'the payload delivered')


if __name__ == '__main__':
    sys.exit(figure.main('memrxframe', build, paths=PATHS, symbols=SYMBOLS))
