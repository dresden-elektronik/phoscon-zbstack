#!/usr/bin/env python3
"""Where the bytes are: Zb_Stack on a host at the defaults, a network of 200 devices.

Content only: the style, the renderer and the checks are in figure.py. One memory map read
downwards, every block as tall as its bytes, a bracket per layer; the sizes are docs/memory.md
§1's tables, read here, so the figure and the tables cannot disagree. Amber is the subject: the
tables that grow with the network, §1.1's.

    python3 tools/diagrams/memmap.py            # docs/images/memmap.png
    python3 tools/diagrams/memmap.py --check    # is the committed raster still this figure?
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import MX, S2, S4  # noqa: E402

DOC = 'docs/memory.md'
PX = 0.0225                    # px per byte
LINE = 16                      # the least height a block's name is set in
CW = 300                       # the map's width
LAB = 96                       # the air left of the map for its layer brackets
RAB = 120                      # the air right of it for Zb_Core's bracket
X1 = MX + LAB
W = X1 + CW + RAB + MX

# docs/memory.md §1's sections, one per layer of Zb_Core, then what Zb_Stack adds
LAYERS = [('1.2', 'mac'), ('1.3', 'nwk'), ('1.4', 'aps'), ('1.5', 'security'), ('1.6', 'af'), ('1.7', 'zdo'),
          ('1.8', 'core')]
STACK = ('1.9', 'stack')

SYMBOLS = ['Zb_Core', 'Zb_Stack', 'sourceRoutes', 'addressMap', 'keyPairs', 'joiners', 'neighbors', 'routes',
           'incoming', 'transactions', 'btt', 'dups', 'rxQueue', 'lifecycle']
PATHS = ['src/zb/zb_core.h', 'src/zb/zb_layers.h', 'src/zb/mac/mac.h', 'src/zb/nwk/nwk.h',
         'src/zb/aps/aps.h', 'src/zb/security.h', 'src/stack/zb_stack.h', 'src/rcp/rcp_radio.h']


def member(f, y, h, name, kind):
    if h >= LINE:
        f.block(X1, y, CW, h, name, None, kind)
    else:
        f.rect(X1, y, CW, h, figure.KIND[kind][0])


def build():
    f = figure.Fig(W, 2400, 'MEMORY: WHERE THE BYTES ARE',
                   'Zb_Stack on a host at the defaults, a network of 200 devices, every block as tall as '
                   'its bytes')
    top = f.top + S4
    grows = set(row[1] for row in figure.docTable(DOC, '1.1'))

    # per section its tables as blocks, those the network sizes in amber, then its smaller ones as one
    def section(y, sec, layer):
        y0, small = y, 0.0
        for row in figure.docTable(DOC, sec):
            h = figure.bytesOf(row[2]) * PX
            big = row[0].split('.')[-1] in grows
            if row[0] == 'the rest' or (h < LINE and not big):
                small += h
                continue
            member(f, y, h, row[0], 'amb' if big else 'blk')
            y += h
        member(f, y, small, 'the rest', 'gap')
        y += small
        f.bracket(X1 - S2, y0 + 1, y - 1, layer, 'left', 'f-lab')
        return y

    y = top
    for sec, layer in LAYERS:
        y = section(y, sec, layer)
    f.bracket(X1 + CW + S2, top + 1, y - 1, 'Zb_Core', 'right', 'f-lab')
    bottom = section(y, *STACK)

    ly = f.legend(bottom + 40,
                  [('amb', 'a table the number of devices sizes'), ('blk', 'a table'),
                   ('gap', 'the smaller members, together')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    sys.exit(figure.main('memmap', build, paths=PATHS, symbols=SYMBOLS))
