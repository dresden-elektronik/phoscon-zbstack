#!/usr/bin/env python3
"""A frame for a sleeping child: indirect delivery, and the Ack bit the host has to state in advance.

Content only: the style, the renderer and the checks are in figure.py. The parent is this stack, a
coordinator or router, whose next hop is an end device with its receiver off
(Nwk_NeighborRestsReceiver), so the network layer hands the frame to Mac_IndirectRequest instead of
sending it. The MAC queues it and states its pending table, which band B writes as Spinel's
source-match family; when the child polls, the RCP acknowledges from that table before the host
has seen the poll, and only then hands the Data Request up with the Ack's bit reported. The MAC
answers the poll with the held frame, and the transaction leaves on the child's Ack. Amber is the
Frame Pending bit in the RCP's Ack: the one decision the host cannot make in time and has to have
written down already.

    python3 tools/diagrams/indirect.py            # docs/images/indirect.png
    python3 tools/diagrams/indirect.py --check    # is the committed raster still this figure?
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import S2, S3, S4  # noqa: E402

XN, XM, XR, XC = 240, 570, 910, 1270
W = XC + 85 + 40
AX0, AX1 = 40, W - 40          # an alternative's frame, its condition left of the first lifeline

# what does each step, so a step whose module is gone stops the figure
PATHS = [
    'src/zb/nwk/nwk.c',            # the next hop is a resting child: the slot is marked indirect
    'src/zb/nwk/nwk_neighbor.c',   # which neighbour rests its receiver
    'src/zb/nwk/nwk_tx.c',         # the indirect issue, Mac_IndirectRequest
    'src/zb/mac/mac.c',            # the pending table stated, the poll answered, the step's ageing
    'src/zb/mac/mac_indirect.c',   # the queue, the extraction, the persistence
    'src/zb/mac/mac_rx.c',         # the Data Request recorded as a poll
    'src/seam/radio.h',            # pendingTable, ackedWithFramePending
    'src/rcp/rcp_radio.c',         # the table as Spinel source match, MD_FLAG's ACKED_FP
]

SYMBOLS = [
    'Nwk_NeighborRestsReceiver', 'Mac_IndirectRequest', 'MacIndirect_Queue', 'macStatePendingTable',
    'pendingTable', 'Radio_Pending', 'isComplete', 'PROP_MAC_SRC_MATCH_ENABLED',
    'PROP_MAC_SRC_MATCH_SHORT_ADDRESSES', 'PROP_MAC_SRC_MATCH_EXTENDED_ADDRESSES', 'SPINEL_MD_ACKED_FP',
    'ackedWithFramePending', 'MacIndirect_DoPollAnswer', 'MacIndirect_ReleaseAttempt',
    'MacIndirect_AgeTransactions', 'MAC_TRANSACTION_PERSISTENCE_MS', 'ZB_ERR_TRANSACTION_EXPIRED',
]


def selfm(f, seq, a, name, sub, side, room):
    """seq.self_msg with its two lines measured against the gap it is drawn into."""
    f.fits(name, 'f-msg', room, 'the step %r' % name)
    f.fits(sub, 'f-sub', room, 'the step %r' % name)
    seq.self_msg(a, name, sub, side=side)


def alt(f, seq, y0, label):
    """An alternative framed across the whole figure, its condition set clear of the first lifeline."""
    f.fits(label, 'f-cap', XN - S2 - (AX0 + S2), 'the frame %r' % label)
    f.rect(AX0, y0, AX1 - AX0, seq.y - y0, 'f-alt', rx=2)
    f.text(AX0 + S2, y0 + 14, label, 'f-cap')
    seq.y += S2


def build():
    f = figure.Fig(W, 1500, 'A FRAME FOR A SLEEPING CHILD',
                   'the parent holds the frame until the child asks, and tells the RCP beforehand '
                   'what to answer when it does')
    seq = figure.Seq(f, {'nwk': (XN, 'network layer', 'this stack, the parent'),
                         'mac': (XM, 'MAC', 'this stack, on the host'),
                         'rcp': (XR, 'RCP', 'Phoscon RCP'),
                         'child': (XC, 'child', 'an end device, receiver off')},
                     f.top + S2, head_w=170)
    gap_m = XR - XM - 28 - S2 - S3
    gap_r = XC - XR - 28 - S2 - S3

    seq.label('HOLD THE FRAME')
    seq.msg('nwk', 'mac', 'Mac_IndirectRequest', 'the next hop is a child that sleeps')
    selfm(f, seq, 'mac', 'MacIndirect_Queue', 'held, not sent, for at most its persistence time',
          'right', gap_m)
    seq.msg('mac', 'rcp', 'pendingTable', "the child's short and extended address")
    selfm(f, seq, 'rcp', 'PROP_MAC_SRC_MATCH_ENABLED', 'then both lists; left clear, every Ack says pending',
          'right', gap_r)

    seq.label('THE CHILD POLLS')
    seq.msg('child', 'rcp', 'Data Request', 'it wakes and asks: a MAC command')
    seq.msg('rcp', 'child', 'Ack: Frame Pending 1', 'from the table, at once: the host is not asked',
            back=True, amber=True)
    seq.msg('rcp', 'mac', 'Data Request', 'handed up after the Ack, ackedWithFramePending set',
            back=True)
    selfm(f, seq, 'mac', 'MacIndirect_DoPollAnswer', 'the oldest frame for the child; the table drops it',
          'right', gap_m)
    seq.msg('mac', 'rcp', 'held frame', 'its Frame Pending bit: whether more is held')
    seq.msg('rcp', 'child', 'held frame', 'never retried: a lost Ack waits for the next poll')
    seq.msg('child', 'rcp', 'Ack', back=True)
    seq.msg('rcp', 'mac', 'completion', 'acknowledged', back=True)
    selfm(f, seq, 'mac', 'MacIndirect_ReleaseAttempt', 'acknowledged: the frame leaves the queue','right', gap_m)
    seq.msg('mac', 'nwk', 'confirm', 'success', back=True)

    seq.skip(S4)
    y0 = seq.y
    seq.skip(20)
    selfm(f, seq, 'mac', 'MacIndirect_AgeTransactions', 'past its persistence time: discarded',
          'right', gap_m)
    seq.msg('mac', 'rcp', 'pendingTable', 'restated without the child')
    seq.msg('mac', 'nwk', 'ZB_ERR_TRANSACTION_EXPIRED', 'the confirm: the frame never left',
            back=True)
    alt(f, seq, y0, 'IF THE CHILD NEVER POLLS')
    end = seq.end()

    ly = f.legend(end + 30, [('out', 'a frame sent, or a call'),
                             ('back', 'an answer, or a frame handed up'),
                             ('now', 'Frame Pending, set by the RCP from the table'),
                             ('alt', 'an alternative')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    sys.exit(figure.main('indirect', build, paths=PATHS, symbols=SYMBOLS))
