#!/usr/bin/env python3
"""An application's life: the state machine both examples share.

Content only: the style, the renderer and the checks are in figure.py. The figure is for someone
writing an application on Zb_Stack: the stack reports, the application moves on what it is told.
examples/coordinator/coordinator.c and examples/router/router.c have the same four states and the same transitions,
so one column draws both; what differs is the config each states before Zb_StackStart, which the
note beside the column says. Amber is the serving state, where an application spends its life.
Every transition drawn is one onEvent or main takes: NETWORK_UP and STOPPED move the state,
NETWORK_FAILED and the stop main reads (Ctrl-C, or --seconds ran out, in any state before
STOPPING) call Zb_StackStop, and every other event in SERVING is printed and leaves it where it is.

Every state name and identifier printed is checked against src/, or against the examples for the
names only an example has, before the figure draws.

    python3 tools/diagrams/appstates.py            # docs/images/appstates.png
    python3 tools/diagrams/appstates.py --check    # is the committed raster still this figure?
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import MX, S2, S3, S4, S5  # noqa: E402

EXAMPLES = ['examples/coordinator/coordinator.c', 'examples/router/router.c']

ROWS = ['STARTING', 'SERVING', 'STOPPING', 'DONE']
SUB = {
    'STARTING': 'the stack brings the RCP up, forms or joins',
    'SERVING': 'the network is up; what happens is printed',
    'STOPPING': 'the stack resets the RCP',
    'DONE': 'the loop ends, main returns',
}
STAYS = ['ZB_EVENT_DEVICE_JOINED', 'ZB_EVENT_DATA', 'ZB_EVENT_SENT', 'ZB_EVENT_RCP_LOST',
         'ZB_EVENT_RCP_BACK']

SYMBOLS = ['Zb_StackStart', 'Zb_StackNextEvent', 'Zb_StackStop', 'ZB_OK', 'ZB_EVENT_NETWORK_UP',
           'ZB_EVENT_NETWORK_FAILED', 'ZB_EVENT_STOPPED', 'Zb_StackConfig',
           'Zb_StackCoordinatorDefaults', 'Zb_StackRouterDefaults', 'channel', 'panId',
           'channelMask'] + STAYS
# what only an example names: its states, its handler and the stop it reads
APP_SYMBOLS = ['APP_' + s for s in ROWS] + ['onEvent', 'Ctrl-C', '--seconds']

BW, BH = 300, 56                # a state
RG = 80                         # the air between two rows, where a transition is named
LOOP = 26                       # a self-loop's reach right of its state
LANE = 330                      # the room right of the column for the loop's lines and the note
RAIL = 28                       # the stop rail, left of the states
SIDE = 250                      # the room left of the rail for its lines
SX = MX + SIDE + RAIL           # the states' left edge
W = SX + BW + LOOP + S2 + LANE + MX


def checkExamples(names):
    blob = ''
    for p in EXAMPLES:
        with open(os.path.join(figure.ROOT, p)) as f:
            blob += f.read()
    return ['%s is drawn, but no example names it' % s for s in names
            if not re.search(r'(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])' % re.escape(s), blob)]


def lines(f, x, ymid, rows, room, where, anchor='start'):
    """Mono and plain lines, one under another, centred on ymid."""
    top = ymid - (len(rows) - 1) * 7.5 + 4
    for i, (text, cls) in enumerate(rows):
        f.fits(text, cls, room, where)
        f.text(x, top + i * 15, text, cls, anchor)


class Column(object):
    """The application's machine, its states one under another."""

    def __init__(self, f, x, y0):
        self.f, self.x, self.y0 = f, x, y0
        self.cx = x + BW / 2.0
        self.rail = x - RAIL
        for s in ROWS:
            f.block(x, self.y(s), BW, BH, 'APP_' + s, SUB[s], 'amb' if s == 'SERVING' else 'blk')

    def y(self, state):
        return self.y0 + ROWS.index(state) * (BH + RG)

    def mid(self, state):
        return self.y(state) + BH / 2.0

    def down(self, a, b, rows):
        """A transition down the column, named right of its arrow: a trigger, then the call it makes."""
        f = self.f
        y0, y1 = self.y(a) + BH + 2, self.y(b) - 2
        f.arrow([(self.cx, y0), (self.cx, y1)])
        tx = self.cx + S3
        lines(f, tx, (y0 + y1) / 2.0, rows, self.x + BW + LOOP + S2 + LANE - tx,
              'the transition %s to %s' % (a, b))

    def loop(self, state, rows):
        """A state that stays: out of its right edge and back, named in the lane beside it."""
        f = self.f
        y, x = self.y(state), self.x + BW
        f.line([(x + 2, y + 16), (x + LOOP, y + 16), (x + LOOP, y + BH - 16), (x + 4, y + BH - 16)],
               'f-out', 'ink')
        lines(f, x + LOOP + S2, y + BH / 2.0, rows, LANE, 'the loop on %s' % state)

    def bypass(self, a, b, rows):
        """A transition that passes the states between: a rail on the column's left, named left of it."""
        f = self.f
        f.line([(self.x - 2, self.mid(a)), (self.rail, self.mid(a)), (self.rail, self.mid(b)),
                (self.x - 2, self.mid(b))], 'f-out', 'ink')
        between = ROWS[ROWS.index(a) + 1]
        lines(f, self.rail - S2, self.mid(between), rows, SIDE - S2,
              'the transition %s to %s' % (a, b), anchor='end')


def build():
    f = figure.Fig(W, 1100, 'AN APPLICATION\'S LIFE',
                   'the stack reports events from Zb_StackNextEvent; the application moves on what it is '
                   'told, and stops when it decides to')
    y = f.top + S2

    # the way in: Zb_StackStart, which either opens the RCP or returns before any state
    c_y0 = y + 66
    cx = SX + BW / 2.0
    f.arrow([(cx, y), (cx, c_y0 - 2)])
    lines(f, cx + S3, (y + c_y0) / 2.0, [('Zb_StackStart', 'f-msg'), ('ZB_OK: the RCP is open', 'f-sub')],
          BW / 2.0 + LOOP + S2 + LANE - S3, 'the way in')

    c = Column(f, SX, c_y0)
    c.down('STARTING', 'SERVING', [('ZB_EVENT_NETWORK_UP', 'f-msg'),
                                   ('formed, or joined with the key', 'f-sub')])
    c.loop('SERVING', [(s, 'f-msg') for s in STAYS] + [('printed; the state stays', 'f-sub')])
    c.down('SERVING', 'STOPPING', [('Ctrl-C, or --seconds ran out:', 'f-sub'), ('Zb_StackStop', 'f-msg')])
    c.down('STOPPING', 'DONE', [('ZB_EVENT_STOPPED', 'f-msg'), ('the RCP reset, the port closed', 'f-sub')])
    c.bypass('STARTING', 'STOPPING', [('ZB_EVENT_NETWORK_FAILED', 'f-msg'),
                                      ('or Ctrl-C, or --seconds ran out:', 'f-sub'),
                                      ('Zb_StackStop', 'f-msg')])

    # what differs between the two examples: only the config each states, beside STARTING
    nx = SX + BW + LOOP + S2
    ny = c.y('STARTING') - 4
    f.group(nx, ny, LANE, 'Zb_StackConfig', 'the only difference')
    note = [('Zb_StackCoordinatorDefaults', 'f-msg'), ('coordinator.c: the channel and panId it forms', 'f-sub'),
            ('Zb_StackRouterDefaults', 'f-msg'), ('router.c: a channelMask the stack scans', 'f-sub')]
    for i, (text, cls) in enumerate(note):
        f.fits(text, cls, LANE, 'the config note')
        f.text(nx, ny + 26 + i * 15 + (S2 if i >= 2 else 0), text, cls)

    end = c.y('DONE') + BH
    ly = f.legend(end + S5 + S4, [('amb', 'where the application spends its life'),
                                  ('blk', 'an application state'),
                                  ('out', 'a transition: the event, or the application\'s own stop')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    bad = checkExamples(APP_SYMBOLS)
    if bad:
        raise SystemExit('appstates: the figure no longer matches the tree:\n  %s' % '\n  '.join(bad))
    sys.exit(figure.main('appstates', build, paths=EXAMPLES + ['src/stack/zb_stack.h'],
                         symbols=SYMBOLS))
