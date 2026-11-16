#!/usr/bin/env python3
"""How long each part is used: four lanes over three steps of the application's loop.

Content only: the style, the renderer and the checks are in figure.py. A lane is as tall as the
bytes that live that long (docs/memory.md §2's table, read here), and its whole width is reserved,
because every table is a fixed array; what is drawn solid is when it is used. Amber is the
subject: what is used only inside a step or a call, reserved for the device's life all the same.
The call frames are the caller's, on its stack, and not to scale.

    python3 tools/diagrams/memlife.py            # docs/images/memlife.png
    python3 tools/diagrams/memlife.py --check    # is the committed raster still this figure?
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import MX, S2, S3, S4  # noqa: E402

DOC = 'docs/memory.md'
PX = 0.008                     # px per byte, every lane
LW = 190                       # the lane names
X0 = MX + LW + S4              # the timeline
TW = 760
W = X0 + TW + MX
LG = 14                        # the air between lanes
STACK_H = 20                   # the call-frame lane, not to scale
STEPS = [(0.06, 0.26), (0.40, 0.60), (0.76, 0.96)]   # a turn's window, as fractions of the timeline

# when each lane is in use: an illustration of the pattern, not a trace (a quiet step uses less)
ACROSS = [(0.10, 0.70, 0.30), (0.45, 1.00, 0.25), (0.00, 0.50, 0.20), (0.62, 1.00, 0.15)]
WITHIN = [0.85, 0.35, 0.55]
CALLS = [(0.10, 0.17), (0.48, 0.52, 0.56), (0.82, 0.90)]

SYMBOLS = ['Zb_StackTurn', 'Zb_StackNextEvent']
PATHS = ['src/stack/zb_stack.c']


def build():
    rows = [r for r in figure.docTable(DOC, 2) if r[2]]
    f = figure.Fig(W, 800, 'MEMORY: HOW LONG EACH PART IS USED',
                   'every lane is reserved all along, as tall as its bytes; when each is in use is an '
                   'illustration, not a trace')
    top = f.top + 40
    lanes = []
    y = top
    for lifetime, _what, size in rows:
        h = figure.bytesOf(size) * PX
        lanes.append((lifetime, y, h))
        y += h + LG
    lanes.append(('on the caller\'s stack', y, STACK_H))
    bottom = y + STACK_H

    # the steps: a band behind every lane, named at the top
    for i, (a, b) in enumerate(STEPS):
        f.band(X0 + a * TW, top - 30, (b - a) * TW, bottom - top + 38, 'Zb_StackTurn')
    f.text(X0 + (STEPS[0][1] + STEPS[1][0]) / 2.0 * TW, top - 12, 'waiting', 'f-sub', 'middle')
    f.text(X0 + (STEPS[1][1] + STEPS[2][0]) / 2.0 * TW, top - 12, 'waiting', 'f-sub', 'middle')

    for n, (lifetime, ly, h) in enumerate(lanes):
        f.fits(lifetime, 'f-lab', LW, 'the lane names')
        f.text(MX + LW, ly + h / 2.0 + 4, lifetime, 'f-lab', 'end')
        if n == len(lanes) - 1:
            # the call frames: the caller's, not to scale
            f.rect(X0, ly, TW, h, 'f-keep')
            continue
        f.rect(X0 + 0.75, ly + 0.75, TW - 1.5, h - 1.5, 'f-owe')
        if n == 0:
            f.rect(X0, ly, TW, h, 'f-blk')
        elif n == 1:
            yy = ly
            for a, b, share in ACROSS:
                f.rect(X0 + a * TW, yy, (b - a) * TW, share * h, 'f-blk')
                yy += share * h
        elif n == 2:
            for (a, b), share in zip(STEPS, WITHIN):
                f.rect(X0 + a * TW, ly + (1 - share) * h, (b - a) * TW, share * h, 'f-amb')
        else:
            for marks in CALLS:
                for m in marks:
                    f.rect(X0 + m * TW, ly, 6, h, 'f-amb', rx=0)

    ly = f.legend(bottom + 40, [('blk', 'in use'), ('amb', 'in use only inside a step or a call'),
                                ('owe', 'reserved, not in use'),
                                ('keep', 'the caller\'s stack, not to scale'),
                                ('band', 'a step of the application\'s loop')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    sys.exit(figure.main('memlife', build, paths=PATHS, symbols=SYMBOLS))
