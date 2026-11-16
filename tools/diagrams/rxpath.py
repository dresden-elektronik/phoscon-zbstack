#!/usr/bin/env python3
"""A frame coming in: the receive path, from the port's bytes to the application's poll.

Content only: the style, the renderer and the checks are in figure.py. The frame climbs the left
column, pulled one poll at a time; on the way a layer may send something back down (a relay, an
answer, an ack), drawn as the transmit path taking over. Only a unicast relay leaves the climb. Amber is the subject: the two security crossings, where
a received frame is trusted or not before any layer decides what to do with it. The network
crossing drops a failure; the APS crossing hands it up as a status. Every identifier printed is
checked against src/ and every file the blocks stand for against the tree before the figure draws.

    python3 tools/diagrams/rxpath.py            # docs/images/rxpath.png
    python3 tools/diagrams/rxpath.py --check    # is the committed raster still this figure?
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import D, MX, S2, S4  # noqa: E402

LW, BW = 444, 372              # the frame's column, the column of turns back down
G = 64                         # the air a turn's arrow crosses
X0 = MX
BX = X0 + LW + G
W = BX + BW + MX
BH = 48
GAP = 64                       # the air between two layers: an arrow, its name and its line
TIGHT = 24                     # the air between a crossing and the layer it belongs to
AX = 28                        # the arrow's offset into the column

SYMBOLS = [
    'Port_Read', 'Hdlc_Feed', 'RcpRadio_Pump', 'Radio_Frame', 'rxPoll', 'Mac_PollIndications',
    'MacIndirect_DoPollAnswer', 'Security_Unprotect', 'Nwk_Indication', 'Nwk_RelayUnicast',
    'Nwk_RelayBroadcast',
    'Aps_RxSecureReceive', 'Aps_AckRespond', 'Aps_PollIndications', 'Zb_CoreStep',
    'Zdo_HandleIndication', 'ZB_EVENT_DATA', 'Zb_StackNextEvent',
]
Z = 'src/zb/'
PATHS = [
    'src/port/port.h', 'src/rcp/hdlc.c', 'src/rcp/spinel_session.c', 'src/rcp/rcp_radio.c',
    'src/seam/radio.h', Z + 'mac/mac.c', Z + 'mac/mac_rx.c', Z + 'mac/mac_indirect.c',
    Z + 'mac_frame.c', Z + 'security.c', Z + 'nwk/nwk.c', Z + 'nwk/nwk_rx.c', Z + 'nwk/nwk_btt.c',
    Z + 'nwk/nwk_relay.c', Z + 'aps/aps.c', Z + 'aps/aps_rx.c', Z + 'aps/aps_dup.c',
    Z + 'aps/aps_ack.c', Z + 'aps/aps_frag.c', Z + 'zb_core.c', Z + 'zdo/zdo.c',
    Z + 'af/af.c',
]

# bottom to top: (name, plain line, kind, the air above it, the arrow into the next, a turn back down)
STEPS = [
    ('the RCP', 'Phoscon RCP: address filter %s the Ack, sent already' % D, 'brt', GAP,
     ('Port_Read %s Hdlc_Feed' % D, 'bytes read by RcpRadio_Pump, the application\'s call'), None),
    ('rcp_radio', 'a STREAM_RAW notification becomes a Radio_Frame, queued', 'blk', GAP,
     ('rxPoll', 'the seam: the MAC pulls a batch each step'), None),
    ('mac', 'FCS %s header %s own echo %s filter %s beacon, association, poll' % (D, D, D, D), 'blk',
     GAP, ('Mac_PollIndications', None),
     ('MacIndirect_DoPollAnswer', 'a child\'s poll: the frame held for it goes out')),
    ('Security_Unprotect', 'a NWK-secured frame: MIC and frame counter; a failure is dropped',
     'amb', TIGHT, None, None),
    ('nwk', 'radius %s commands %s broadcast table %s for this device, or relayed' % (D, D, D), 'blk',
     GAP, ('Nwk_Indication', 'held, read in place until APS is done'),
     ('Nwk_RelayUnicast %s Nwk_RelayBroadcast' % D,
      'not this device\'s, or a broadcast too: re-secured, sent on')),
    ('Aps_RxSecureReceive', 'an APS-secured frame: a failure goes up as a status, its ASDU empty',
     'amb', TIGHT, None, None),
    ('aps', 'an ack ends a send\'s wait %s duplicates %s fragments %s groups' % (D, D, D), 'blk',
     GAP, ('Aps_PollIndications', 'in Zb_CoreStep'),
     ('Aps_AckRespond', 'the APS ack the frame asked for, sent back')),
    ('zb_core', 'a ZDP request is the device object\'s; the rest wait for the application', 'blk',
     GAP, ('ZB_EVENT_DATA', 'the application\'s own, as an event from Zb_StackNextEvent'),
     ('Zdo_HandleIndication', 'the device object answers; its answer is a send')),
    ('your application', 'takes what is its own as events', 'tag', 0, None, None),
]


def build():
    f = figure.Fig(W, 1400, 'RX PATH: A FRAME COMING IN',
                   'pulled up one poll at a time; on the way, a layer may send something back down')
    x = X0 + AX
    room = LW - AX - 2 * S2

    # lay the column out top-down: the application first, the RCP last
    order = list(reversed(STEPS))
    y = f.top + S2
    tops = []
    for i, step in enumerate(order):
        tops.append(y)
        y += BH
        if i + 1 < len(order):
            y += order[i + 1][3]
    bottom = y

    for step, top in zip(order, tops):
        name, sub, kind, _air, _up, turn = step
        f.block(X0, top, LW, BH, name, sub, kind)
        if turn:
            f.block(BX, top, BW, BH, turn[0], turn[1], 'gap')
            f.arrow([(X0 + LW + 2, top + BH / 2.0), (BX - 2, top + BH / 2.0)])

    # the arrows up, each from a step to the one above it
    for i in range(len(order) - 1, 0, -1):
        step, top, above = order[i], tops[i], tops[i - 1]
        up = step[4]
        y0, y1 = top - 2, above + BH + 2
        f.arrow([(x, y0), (x, y1)])
        if not up:
            continue
        name, sub = up
        mid = (y0 + y1) / 2.0
        f.fits(name, 'f-msg', room, 'the arrow %r' % name)
        f.text(x + S2 + 2, mid - (2 if sub else -4), name, 'f-msg')
        if sub:
            f.fits(sub, 'f-sub', room, 'the arrow %r' % name)
            f.text(x + S2 + 2, mid + 13, sub, 'f-sub')

    ly = f.legend(bottom + 40, [('out', 'a frame handed on'),
                                ('amb', 'a security crossing'),
                                ('blk', 'a layer'), ('gap', 'sent back down: the transmit path'),
                                ('tag', 'the application'), ('brd', 'the RCP')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    sys.exit(figure.main('rxpath', build, paths=PATHS, symbols=SYMBOLS))
