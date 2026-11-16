#!/usr/bin/env python3
"""A frame going out: the transmit path, request down and confirm up.

Content only: the style, the renderer and the checks are in figure.py. The request goes down the
left column in the caller's own call; the confirm comes up the right column, polled, through the
slots that wait for it. Amber is the subject: where a frame waits, held or sent again. The refusal
for room those holds answer starts in rcp_radio's one outstanding TID, which is why that row says
so. Every identifier printed is checked against src/ and every file the blocks stand for against
the tree before the figure draws.

    python3 tools/diagrams/txpath.py            # docs/images/txpath.png
    python3 tools/diagrams/txpath.py --check    # is the committed raster still this figure?
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import D, MX, S2, S3, S4  # noqa: E402

LW, HW, RW = 424, 384, 228     # the request column, the hold column, the receive-path block
G = 44                         # the air between two columns
X0 = MX
HX = X0 + LW + G
RX = HX + HW + G
W = RX + RW + MX
BH = 48                        # one block, or one entry of a hold
GAP = 64                       # the air between two rows: an arrow, its name and its line
AX = 28                        # an arrow's offset into its column

SYMBOLS = [
    'Zb_StackApsRequest', 'ZB_EVENT_SENT', 'Aps_DataRequest', 'Nwk_PollConfirms',
    'Nwk_DataRequest', 'Mac_PollConfirms', 'Mac_DataRequest', 'Mac_IndirectRequest',
    'Hdlc_Encode', 'Port_Write', 'Hdlc_Feed', 'RcpRadio_Pump', 'PROP_LAST_STATUS',
    'APS_TX_AWAITING_ACK', 'NWK_TX_AWAITING_ROUTE', 'NWK_TX_AWAITING_RETRY', 'MAC_TX_OUTSTANDING',
    'Aps_AckSlotForAck', 'tx', 'completion',
]
Z = 'src/zb/'
PATHS = [
    Z + 'zb_core.c', Z + 'zb_layers.c', Z + 'aps/aps.c', Z + 'aps/aps_tx.c', Z + 'aps/aps_ack.c',
    Z + 'nwk/nwk.c', Z + 'nwk/nwk_tx.c', Z + 'security.c', Z + 'mac/mac.c', Z + 'mac/mac_tx.c',
    Z + 'mac/mac_indirect.c', Z + 'mac_frame.c', 'src/seam/radio.h', 'src/rcp/rcp_radio.c',
    'src/rcp/spinel_session.c', 'src/rcp/hdlc.c', 'src/port/port.h',
]


def hold(f, x, y, w, entries, kind='amb'):
    """One layer's waiting slots: one fill, an entry per state, a rule between two."""
    box, tn, ts = figure.KIND[kind]
    f.rect(x, y, w, BH * len(entries), box)
    for i, (name, sub) in enumerate(entries):
        top = y + i * BH
        if i:
            f.line([(x + S3, top), (x + w - S3, top)], 'f-rule')
        f.fits(name, tn, w - 2 * S3, 'its hold')
        f.fits(sub, ts, w - 2 * S3, 'the hold %r' % name)
        f.text(x + S3, top + BH / 2.0 - 3, name, tn)
        f.text(x + S3, top + BH / 2.0 + 13, sub, ts)
    return y + BH * len(entries)


def vlink(f, x, y0, y1, name, sub=None, back=False, room=300, at=None):
    """A vertical arrow from y0 to y1, its name and one plain line to its right."""
    f.arrow([(x, y0), (x, y1)], back)
    mid = (y0 + y1) / 2.0 if at is None else at
    f.fits(name, 'f-msg', room, 'the arrow %r' % name)
    f.text(x + S2 + 2, mid - (2 if sub else -4), name, 'f-msg')
    if sub:
        f.fits(sub, 'f-sub', room, 'the arrow %r' % name)
        f.text(x + S2 + 2, mid + 13, sub, 'f-sub')


def build():
    f = figure.Fig(W, 1200, 'TX PATH: A FRAME GOING OUT',
                   'the request goes down in the caller\'s call; its confirm comes up, polled, '
                   'through the slots that wait for it')
    span = HX + HW - X0
    down, up = X0 + AX, HX + AX
    droom, uroom = LW - AX - 2 * S2, HW - AX - 2 * S2

    y = f.top + S2
    f.text(X0, y + 10, 'THE REQUEST, DOWN', 'f-cap')
    f.text(HX, y + 10, 'WHERE IT WAITS, AND THE CONFIRM, UP', 'f-cap')
    y += 22

    y_app = y
    f.block(X0, y, span, BH, 'your application', 'sends through Zb_Stack; hears the outcome as an event',
            'tag')
    y += BH + GAP

    y_dev = y
    f.block(X0, y, LW, BH, 'zb_core', 'the door: a source endpoint other than 0 must be registered')
    y += BH + GAP

    y_aps = y
    f.block(X0, y, LW, BH, 'aps', 'a slot %s the frame and its counter %s APS security if asked'
            % (D, D))
    hold(f, HX, y, HW, [('APS_TX_AWAITING_ACK', 'no APS ack by the deadline: sent again, then NO_ACK')])
    f.block(RX, y, RW, BH, 'Aps_AckSlotForAck', 'the peer\'s ack, up the receive path', 'gap')
    f.arrow([(RX - 2, y + BH / 2.0), (HX + HW + 2, y + BH / 2.0)], back=True)
    y += BH + GAP

    y_nwk = y
    f.block(X0, y, LW, 2 * BH, 'nwk', 'route or discovery %s broadcast table %s header %s '
            'NWK security' % (D, D, D))
    hold(f, HX, y, HW, [('NWK_TX_AWAITING_ROUTE', 'no route yet: held while discovery runs'),
                        ('NWK_TX_AWAITING_RETRY', 'a unicast retried; a broadcast held '
                         'for room')])
    y += 2 * BH + GAP

    y_mac = y
    f.block(X0, y, LW, 2 * BH, 'mac', 'MHR %s sequence number %s FCS %s a retry count for the radio'
            % (D, D, D))
    hold(f, HX, y, HW, [('MAC_TX_OUTSTANDING', 'waits for the radio\'s completion, or times out'),
                        ('Mac_IndirectRequest', 'a resting child\'s frame: kept until it polls')])
    y += 2 * BH + GAP

    y_rcp = y
    f.block(X0, y, LW, BH, 'rcp_radio', 'SET STREAM_RAW; while a reply or a write is owed: no room')
    f.block(HX, y, HW, BH, 'PROP_LAST_STATUS', 'the answer that carries the transmit\'s TID')
    y += BH + GAP

    y_stick = y
    f.block(X0, y, span, BH, 'the RCP', 'Phoscon RCP: CSMA %s retries %s the Ack' % (D, D), 'brt')
    y += BH

    # the request, down: one call from the door to the port, unless a layer holds it
    vlink(f, down, y_app + BH + 2, y_dev - 2, 'Zb_StackApsRequest',
          'all the way down in this call, unless a layer holds it', room=droom)
    vlink(f, down, y_dev + BH + 2, y_aps - 2, 'Aps_DataRequest', room=droom)
    vlink(f, down, y_aps + BH + 2, y_nwk - 2, 'Nwk_DataRequest', 'held frames go later, in a step',
          room=droom)
    vlink(f, down, y_nwk + 2 * BH + 2, y_mac - 2, 'Mac_DataRequest', room=droom)
    vlink(f, down, y_mac + 2 * BH + 2, y_rcp - 2, 'tx', 'the seam: one whole MPDU, a handle back',
          room=droom)
    vlink(f, down, y_rcp + BH + 2, y_stick - 2, 'Hdlc_Encode %s Port_Write' % D, room=droom)

    # the confirm, up: each layer's slot pairs it, then the layer above polls for it
    vlink(f, up, y_stick - 2, y_rcp + BH + 2, 'Hdlc_Feed', 'bytes read by RcpRadio_Pump',
          back=True, room=uroom)
    vlink(f, up, y_rcp - 2, y_mac + 2 * BH + 2, 'completion', 'the seam: asked per handle, each step',
          back=True, room=uroom)
    vlink(f, up, y_mac - 2, y_nwk + 2 * BH + 2, 'Mac_PollConfirms', back=True, room=uroom)
    vlink(f, up, y_nwk - 2, y_aps + BH + 2, 'Nwk_PollConfirms', 'success with no ack asked ends '
          'the APS slot', back=True, room=uroom)
    vlink(f, up, y_aps - 2, y_app + BH + 2, 'ZB_EVENT_SENT',
          'the confirm, as an event', back=True, room=uroom, at=y_dev + BH / 2.0)

    ly = f.legend(y + 40, [('out', 'a call, handed down'), ('back', 'an answer, polled up'),
                           ('amb', 'where a frame waits: held, or sent again'),
                           ('blk', 'a layer, or what it reads'), ('gap', 'the receive path'),
                           ('tag', 'the application'), ('brd', 'the RCP')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    sys.exit(figure.main('txpath', build, paths=PATHS, symbols=SYMBOLS))
