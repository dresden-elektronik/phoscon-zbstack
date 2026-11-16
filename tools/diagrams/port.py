#!/usr/bin/env python3
"""The port: rings, bursts, deadlines, owned by docs/porting.md sections 10.1, 10.2 and 10.4.

Content only: the style, the renderer and the checks are in figure.py. The figure is what a port is
to the rest of the stack. Amber is the two rings, because they are where the target and the stack
meet: the target's half fills the receive ring and empties the transmit ring, band B does the
other two. Below them are the port's two other services, read by the application and handed down
as parameters, and the deadline rule that follows from that: the library holds deadlines and never
a timer. Every identifier is checked against src/, and the two ring sizes the figure prints are
read out of src/port/port.h, so the generator refuses to draw when either drifts.

    python3 tools/diagrams/port.py            # docs/images/port.png
    python3 tools/diagrams/port.py --check    # is the committed raster still this figure?
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import D, MX, S1, S2, S3, S4, S5  # noqa: E402

BH = 50                        # a block
ARROW_ROOM = 2                 # an arrow stops this short of what it points at

# the columns, left to right: the device, the target's ops, the rings, band B, the application's reach
DEV = (MX, 120)
TGT = (DEV[0] + 120 + 88, 220)
RING = (TGT[0] + 220 + 140, 260)
BANDB = (RING[0] + 260 + 120, 200)
FAR = (BANDB[0] + 200 + 96, 196)
W = FAR[0] + FAR[1] + MX

RX_SIZE, TX_SIZE = 512, 1024   # what the rings are drawn as; facts() holds them to port.h

SYMBOLS = ['posixPump', 'posixDrain', 'clock_gettime', 'posixEntropy',
           'rxRing', 'txRing', 'Port_PushRx', 'Port_Read', 'Port_Write', 'Port_TxHead',
           'Port_ConsumeTx', 'Port_Drops', 'Port_Refusals', 'ZB_ERR_BUSY', 'PortConfig',
           'Port_NowMs', 'Port_Entropy', 'RcpRadio_Pump', 'Zb_CoreStep', 'Zb_CoreConfig',
           'nowMs', 'deadlineMs', 'startMs', 'windowMs', 'CLOCK_MONOTONIC', 'getentropy', 'read',
           'write',
           'Zb_timeReached', 'Zb_timeWithin']
PATHS = ['src/port/port.h', 'src/port/port.c', 'src/port/port_posix.c', 'src/rcp/rcp_radio.c',
         'src/zb/zb_core.h', 'src/utils/zb_time.h', 'src/utils/zb_time.c']


def facts():
    """The sizes printed on the rings are port.h's, and the transmit default is the pool's maximum."""
    with open(os.path.join(figure.ROOT, 'src', 'port', 'port.h')) as f:
        src = f.read()
    defs = dict(re.findall(r'#define\s+(PORT_\w+)\s+(\w+)', src))
    bad = []
    if defs.get('PORT_RX_RING_DEFAULT') != str(RX_SIZE):
        bad.append('PORT_RX_RING_DEFAULT is %s, the figure draws %d'
                   % (defs.get('PORT_RX_RING_DEFAULT'), RX_SIZE))
    tx = defs.get('PORT_TX_RING_DEFAULT')
    tx = defs.get(tx, tx)
    if tx != str(TX_SIZE):
        bad.append('PORT_TX_RING_DEFAULT is %s, the figure draws %d' % (tx, TX_SIZE))
    if bad:
        raise SystemExit('port: the figure no longer matches the tree:\n  ' + '\n  '.join(bad))


def x1(c):
    return c[0] + c[1]


def label(f, xa, xb, y, above, below=None):
    """An arrow's words: an identifier above the line, a second one under it, centred in the gap."""
    mid = (xa + xb) / 2.0
    room = abs(xb - xa) - 2 * S1
    f.fits(above, 'f-msg', room, 'the arrow %r' % above)
    f.text(mid, y - 6, above, 'f-msg', 'middle')
    if below:
        f.fits(below, 'f-msg', room, 'the arrow %r' % above)
        f.text(mid, y + 16, below, 'f-msg', 'middle')


def note(f, x, y, name, sub, room):
    """A counter or a rule under a block: its identifier, one plain line under it."""
    f.fits(name, 'f-msg', room, 'the note %r' % name)
    f.text(x, y, name, 'f-msg')
    f.fits(sub, 'f-sub', room, 'the note %r' % name)
    f.text(x, y + 15, sub, 'f-sub')


def build():
    f = figure.Fig(W, 1000, 'THE PORT: RINGS, BURSTS, DEADLINES',
                   'two fixed rings take up the bursts between two turns; the clock is read above '
                   'the library and handed down')
    top = f.top + S2

    # ------------------------------------------------------------ the byte stream
    r0 = top + 30                       # the owed producer
    r1 = r0 + BH + 34                   # receive
    r2 = r1 + BH + 70                   # transmit
    s1_bottom = r2 + BH + 74
    r3 = s1_bottom + 44                 # the clock
    r4 = r3 + BH + 26                   # entropy
    s2_bottom = r4 + BH + S5

    f.band(TGT[0] - S4, top, TGT[1] + 2 * S4, s2_bottom - top, 'THE TARGET %s port_posix.c' % D)
    f.band(BANDB[0] - S4, top, BANDB[1] + 2 * S4, s1_bottom - top, 'BAND B')

    f.block(DEV[0], r1, DEV[1], r2 + BH - r1, 'device', 'USB or UART', 'brt')

    f.block(TGT[0], r0, TGT[1], BH, 'an interrupt', 'recommended: into this ring', 'owe')
    f.block(TGT[0], r1, TGT[1], BH, 'posixPump', 'inside Port_Read: only what fits')
    f.block(TGT[0], r2, TGT[1], BH, 'posixDrain', 'inside Port_Write: until it blocks')

    f.block(RING[0], r1, RING[1], BH, 'rxRing', '%d B %s full: the newest dropped' % (RX_SIZE, D),
            'amb')
    f.block(RING[0], r2, RING[1], BH, 'txRing', '%d B %s full: the write refused whole'
            % (TX_SIZE, D), 'amb')
    note(f, RING[0], r1 + BH + 20, 'Port_Drops', 'every byte a full ring turned away', RING[1])
    note(f, RING[0], r2 + BH + 20, 'Port_Refusals', 'ZB_ERR_BUSY, and the ring untouched',
         RING[1])
    rule = 'either ring: a power of two, shrunk by PortConfig'
    f.fits(rule, 'f-sub', RING[1], 'the ring rule')
    f.text(RING[0], r2 + BH + 62, rule, 'f-sub')

    f.block(BANDB[0], r1, BANDB[1], r2 + BH - r1, 'RcpRadio_Pump',
            'reads %s decodes %s writes' % (D, D))

    m0, m1, m2 = r0 + BH / 2.0, r1 + BH / 2.0, r2 + BH / 2.0
    # receive: device -> pump -> ring -> band B
    f.arrow([(x1(DEV) + ARROW_ROOM, m1), (TGT[0] - ARROW_ROOM, m1)])
    label(f, x1(DEV), TGT[0], m1, 'read()')
    f.arrow([(x1(TGT) + ARROW_ROOM, m1), (RING[0] - ARROW_ROOM, m1)])
    label(f, x1(TGT), RING[0], m1, 'Port_PushRx')
    f.arrow([(x1(RING) + ARROW_ROOM, m1), (BANDB[0] - ARROW_ROOM, m1)])
    label(f, x1(RING), BANDB[0], m1, 'Port_Read')
    # the owed producer: the device raises it, it pushes into the same ring
    dx = DEV[0] + DEV[1] / 2.0
    f.line([(dx, r1 - ARROW_ROOM), (dx, m0), (TGT[0] - ARROW_ROOM, m0)], 'f-back', 'line')
    dropx = RING[0] + 64
    f.line([(x1(TGT) + ARROW_ROOM, m0), (dropx, m0), (dropx, r1 - ARROW_ROOM)], 'f-back', 'line')
    f.fits('Port_PushRx', 'f-msg', dropx - x1(TGT) - S3, 'the owed arrow')
    f.text(x1(TGT) + S3, m0 - 6, 'Port_PushRx', 'f-msg')
    # transmit: band B -> ring -> drain -> device
    f.arrow([(BANDB[0] - ARROW_ROOM, m2), (x1(RING) + ARROW_ROOM, m2)])
    label(f, x1(RING), BANDB[0], m2, 'Port_Write')
    f.arrow([(RING[0] - ARROW_ROOM, m2), (x1(TGT) + ARROW_ROOM, m2)])
    label(f, x1(TGT), RING[0], m2, 'Port_TxHead', 'Port_ConsumeTx')
    f.arrow([(TGT[0] - ARROW_ROOM, m2), (x1(DEV) + ARROW_ROOM, m2)])
    label(f, x1(DEV), TGT[0], m2, 'write()')

    # ------------------------------------------------------------ the two services
    f.block(TGT[0], r3, TGT[1], BH, 'clock_gettime()', 'CLOCK_MONOTONIC, as ms')
    f.block(TGT[0], r4, TGT[1], BH, 'posixEntropy', 'getentropy()')
    f.block(RING[0], r3, RING[1], BH, 'Port_NowMs', 'monotonic %s one wrap every 2^32 ms' % D)
    f.block(RING[0], r4, RING[1], BH, 'Port_Entropy', 'the whole request, or nothing')
    f.block(BANDB[0], r3, BANDB[1], r4 + BH - r3, 'your application',
            'reads both; no band ever does', 'tag')
    f.block(FAR[0], r3, FAR[1], BH, 'Zb_CoreStep', 'band A: nowMs, a parameter')
    f.block(FAR[0], r4, FAR[1], BH, 'Zb_CoreConfig', 'a seed, at init')

    m3, m4 = r3 + BH / 2.0, r4 + BH / 2.0
    for m in (m3, m4):
        f.arrow([(x1(TGT) + ARROW_ROOM, m), (RING[0] - ARROW_ROOM, m)])
        f.arrow([(x1(RING) + ARROW_ROOM, m), (BANDB[0] - ARROW_ROOM, m)])
        f.arrow([(x1(BANDB) + ARROW_ROOM, m), (FAR[0] - ARROW_ROOM, m)])
    label(f, x1(RING), BANDB[0], m3, 'nowMs')
    label(f, x1(BANDB), FAR[0], m3, 'nowMs')
    label(f, x1(RING), BANDB[0], m4, 'octets')
    label(f, x1(BANDB), FAR[0], m4, 'a seed')
    # the same nowMs goes up to band B's turn
    ux = BANDB[0] + BANDB[1] / 2.0
    f.arrow([(ux, r3 - ARROW_ROOM), (ux, r2 + BH + ARROW_ROOM)])
    f.text(ux + S2, (s1_bottom + r3) / 2.0 + 4, 'nowMs', 'f-msg')

    # ------------------------------------------------------------ the deadline rule
    y = s2_bottom + 44
    f.group(MX, y, W - 2 * MX, 'DEADLINES, NOT TIMERS',
            'nothing below the application sleeps or arms a timer: a wait is a deadline, '
            'compared on each turn')
    ys = y + 70                          # the counter's scale
    sx0, sx1 = MX + 8, MX + 560
    f.line([(sx0, ys), (sx1, ys)], 'f-rule')
    for x in (sx0, sx1):
        f.line([(x, ys - 5), (x, ys + 5)], 'f-tickm')
    f.text(sx0, ys + 20, '0', 'f-axl', 'middle')
    f.text(sx1, ys + 20, '2^32 - 1', 'f-axl', 'middle')

    def at(p):
        return sx0 + p * (sx1 - sx0)

    start, now, deadline = at(0.70), at(0.90), at(0.14)
    for x, name in ((start, 'startMs'), (now, 'nowMs'), (deadline, 'deadlineMs')):
        f.line([(x, ys - 9), (x, ys + 9)], 'f-out')
        f.text(x, ys - 14, name, 'f-num', 'middle')
    # the window from the start runs off the end and on from zero: one span, read across the wrap
    f.hbracket(start, sx1, ys + 30, 'windowMs runs off the end', below=True, cls='f-sub')
    f.hbracket(sx0, deadline, ys + 30, 'and on from 0', below=True, cls='f-sub')
    gist = 'nowMs is the larger number, and the deadline is still ahead'
    f.fits(gist, 'f-sub', sx1 - sx0, 'the scale')
    f.text(sx0, ys + 76, gist, 'f-sub')

    tx = sx1 + 72
    room = W - MX - tx
    note(f, tx, ys - 30, 'Zb_timeReached(nowMs, deadlineMs)',
         'reached once nowMs - deadlineMs, read signed, is not negative', room)
    note(f, tx, ys + 12, 'Zb_timeWithin(nowMs, startMs, windowMs)',
         'inside while nowMs - startMs, read unsigned, is under windowMs', room)
    f.fits('so a span under 2^31 ms reads right across the wrap', 'f-sub', room, 'the wrap')
    f.text(tx, ys + 54, 'so a span under 2^31 ms reads right across the wrap', 'f-sub')

    ly = f.legend(ys + 116, [('amb', 'a ring: where the target and the stack meet'),
                             ('blk', 'a function or a type'), ('owe', 'owed: an interrupt-driven target'),
                             ('tag', 'the application'), ('brd', 'the device'),
                             ('band', 'who runs it'), ('out', 'bytes or a value, handed on'),
                             ('back', 'the owed path')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    facts()
    sys.exit(figure.main('port', build, paths=PATHS, symbols=SYMBOLS))
