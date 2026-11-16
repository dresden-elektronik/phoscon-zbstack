#!/usr/bin/env python3
"""The MAC split line, owned by docs/internals/architecture.md section 2.2.

Content only: the style, the renderer and the checks are in figure.py. The MAC is split between
the host and the RCP, and the line between them is a time: each duty is drawn on one log time
scale at the deadline its next step must meet. A transmit's completion is measured coming back
14 to 21 ms after the request (docs/internals/protocol.md §8.3); every duty whose deadline falls
before that is the RCP's, every one after it the host's. That measured band is the split, and
the figure's subject, in amber.

The host's windows are read from src/zb/mac/mac.h and src/zb/nwk/nwk.h when the figure is built,
so a changed constant moves its block and --check reports the figure stale. The RCP's deadlines
are the standard's (802.15.4-2024 Table 12-1, the macUnitBackoffPeriod row of Table 8-36, and
802.15.4-2006 Equation 13) at the 2.4 GHz O-QPSK symbol of 16 µs.

    python3 tools/diagrams/macsplit.py            # docs/images/macsplit.png
    python3 tools/diagrams/macsplit.py --check    # is the committed raster still this figure?
"""

import math
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import MX, S2, S3, S4, S5  # noqa: E402

W = 968
AX = 112                       # the time axis
HX, SX, CW = 150, 556, 364     # the host column, the RCP column, their width
BH, BG = 40, 6                 # a block and the air between two
DEC = 110                      # px a decade
T0, T1 = -4, 2                 # the axis runs 10^T0 s to 10^T1 s

MAC_H = os.path.join(figure.ROOT, 'src', 'zb', 'mac', 'mac.h')
NWK_H = os.path.join(figure.ROOT, 'src', 'zb', 'nwk', 'nwk.h')

# the completion's measured return over the link, docs/internals/protocol.md §8.3
LINK = (0.014, 0.021)

PATHS = ['src/zb/mac/mac.h', 'src/zb/mac/mac_tx.c', 'src/zb/mac/mac_rx.c', 'src/zb/mac/mac_scan.c',
         'src/zb/mac/mac_indirect.c', 'src/zb/mac/mac.c', 'src/zb/mac_frame.c', 'src/zb/nwk/nwk.h',
         'src/seam/radio.h', 'src/rcp/rcp_radio.c']


def const(path, name):
    """A constant's value as the tree states it, so the figure moves when the number does."""
    with open(path) as f:
        m = re.search(r'\b%s\s*=\s*(\d+)\s*,' % name, f.read())
    if not m:
        raise SystemExit('macsplit: %s no longer states %s' % (os.path.relpath(path, figure.ROOT),
                                                                name))
    return int(m.group(1))


SYMBOL_US = 16                 # 2.4 GHz O-QPSK: 62.5 ksymbol/s, 802.15.4-2024 Table 11-1

# The RCP: (seconds, name, plain line), each at the deadline the step after it must meet.
STICK = [
    (8 * SYMBOL_US * 1e-6, 'CCA', 'phyCcaDuration, 8 symbols: 128 µs'),
    (12 * SYMBOL_US * 1e-6, 'the Ack', 'address match, Frame Pending: 192 µs turnaround'),
    (20 * SYMBOL_US * 1e-6, 'CSMA-CA', 'each backoff step a unit of 20 symbols: 320 µs'),
    (54 * SYMBOL_US * 1e-6, 'retransmission', 'when the Ack wait ends, 54 symbols: 864 µs'),
]


def hostItems():
    sym = const(MAC_H, 'MAC_SYMBOL_US')
    superframe = const(NWK_H, 'NWK_DISCOVERY_SUPERFRAME_SYMBOLS')
    scan_ms = superframe * 2 * sym / 1000.0          # ScanDuration 0: (2^0 + 1) superframes
    out = [(scan_ms / 1000.0, 'mac_scan', 'an active scan\'s dwell a channel: %g ms at least'
            % scan_ms)]
    for name, what in (('MAC_BEACON_HOLD_MS', 'a beacon answer re-asked for room'),
                       ('MAC_ASSOC_POLL_DELAY_MS', 'the association\'s polls'),
                       ('MAC_RESPONSE_WAIT_MS', 'macResponseWaitTime'),
                       ('MAC_COMPLETION_TIMEOUT_MS', 'a completion that never came: re-arm'),
                       ('MAC_TRANSACTION_PERSISTENCE_MS', 'the indirect queue\'s expiry')):
        ms = const(MAC_H, name)
        out.append((ms / 1000.0, name, '%s ms: %s' % ('{:,}'.format(ms).replace(',', ' '), what)))
    return out


# What has no air deadline at all: done whenever Mac_Step runs.
ANYTIME = [
    ('MacFrame_Compose', 'the MHR: frame control, addresses, PAN-id compression'),
    ('sequence numbers', 'the DSN and the BSN, band A\'s own'),
    ('ackRequest', 'asked only where one device can answer'),
    ('macTxFrameRetries', 'the PIB\'s count for a direct frame asking an Ack, else 0'),
    ('MacRx_QueueFrame', '6.6.2\'s filter in software, on every delivered frame'),
    ('the indirect queue', 'frames held for a poll, and the table they make'),
]

SYMBOLS = ['MAC_BEACON_HOLD_MS', 'MAC_ASSOC_POLL_DELAY_MS', 'MAC_RESPONSE_WAIT_MS',
           'MAC_COMPLETION_TIMEOUT_MS', 'MAC_TRANSACTION_PERSISTENCE_MS', 'MAC_SYMBOL_US',
           'NWK_DISCOVERY_SUPERFRAME_SYMBOLS', 'MacFrame_Compose', 'MacRx_QueueFrame',
           'macTxFrameRetries', 'ackRequest', 'pendingTable', 'Mac_Step', 'macResponseWaitTime']


def build():
    f = figure.Fig(W, 1400, 'THE MAC SPLIT LINE',
                   'each duty sits at the deadline its next step must meet; what falls before an '
                   'answer can cross the link is the RCP\'s')
    top = f.top + S2
    f.block(HX, top, CW, 40, 'HOST MAC', 'band A, src/zb/mac/: library code', 'hd', center=True)
    f.block(SX, top, CW, 40, 'RCP', 'Phoscon RCP, behind the seam', 'hd', center=True)
    y0 = top + 40 + S5 + 10
    y1 = y0 + DEC * (T1 - T0)

    def y(t):
        return y0 + DEC * (math.log10(t) - T0)

    # the scale
    f.line([(AX, y0), (AX, y1)], 'f-rule')
    labels = {-4: '100 µs', -3: '1 ms', -2: '10 ms', -1: '100 ms', 0: '1 s', 1: '10 s', 2: '100 s'}
    for d in range(T0, T1 + 1):
        f.line([(AX - 7, y(10.0 ** d)), (AX, y(10.0 ** d))], 'f-tickm')
        f.text(AX - 10, y(10.0 ** d) + 4, labels[d], 'f-axl', 'end')
        if d < T1:
            for k in range(2, 10):
                f.line([(AX - 4, y(k * 10.0 ** d)), (AX, y(k * 10.0 ** d))], 'f-tick')
    f.text(AX, y0 - 12, 'TIME', 'f-cap', 'middle')

    # the split: the completion's measured return, across both columns
    sy0, sy1 = y(LINK[0]), y(LINK[1])
    f.rect(AX - 7, sy0, SX + CW - AX + 7, sy1 - sy0, 'f-amb', rx=1)
    split = 'a transmit\'s completion, as measured coming back over the link'
    f.fits(split, 'f-asub', SX + CW - HX - S3, 'the split band')
    f.text(HX + S3, (sy0 + sy1) / 2.0 + 4, split, 'f-asub')

    def column(x, items, floor, edge):
        """Blocks in time order, each as near its deadline as the one above it allows."""
        out = {}
        prev = floor - BH / 2.0 - BG
        for t, name, sub in items:
            mid = max(y(t), prev + BH + BG, floor + BH / 2.0)
            f.block(x, mid - BH / 2.0, CW, BH, name, sub, 'blk')
            yt = y(t)
            # the leader: from the scale at the deadline, to the block's edge
            # two straight runs, never one polyline: the lifeline class has no fill of its own
            f.line([(AX + 2, yt), (edge - 14, yt)], 'f-life')
            f.line([(edge - 14, yt), (edge, mid)], 'f-life')
            f.line([(AX - 3, yt), (AX + 3, yt)], 'f-tickm')
            out[name] = mid
            prev = mid
        return out

    smid = column(SX, STICK, y0 - 6, SX)
    column(HX, hostItems(), sy1 + S2, HX)

    # what has no deadline on the air
    gy = y1 + S5 + 6
    f.group(HX, gy, CW, 'NO AIR DEADLINE', 'whenever Mac_Step runs')
    by = gy + S4 + 2
    last = None
    for name, sub in ANYTIME:
        f.block(HX, by, CW, BH, name, sub, 'blk')
        last = by
        by += BH + BG
    bottom = by - BG

    # the crossing: the queue is written in milliseconds, the Ack reads it in microseconds
    ack = smid['the Ack']
    gx = SX + CW + S4
    qy = last + BH / 2.0
    f.line([(HX + CW, qy), (gx, qy), (gx, ack), (SX + CW + 2, ack)], 'f-out', 'ink')
    f.text(HX + CW + S3, qy - S2, 'pendingTable', 'f-msg')
    f.fits('written as the queue moves, read inside the turnaround', 'f-sub',
           gx - (HX + CW) - S3, 'the pendingTable arrow')
    f.text(HX + CW + S3, qy + 15, 'written as the queue moves,', 'f-sub')
    f.text(HX + CW + S3, qy + 29, 'read inside the turnaround', 'f-sub')

    ly = f.legend(bottom + 36, [('amb', 'the split: a completion\'s measured return'),
                                ('blk', 'a duty'),
                                ('out', 'what crosses it: the pending table')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    sys.exit(figure.main('macsplit', build, paths=PATHS, symbols=SYMBOLS))
