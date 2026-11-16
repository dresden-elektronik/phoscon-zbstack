#!/usr/bin/env python3
"""The seam, call by call, owned by docs/internals/architecture.md section 2.4.

Content only: the style, the renderer and the checks are in figure.py. A sequence between band A's
MAC, the backend behind src/seam/radio.h and the RCP, for each operation the seam carries. The
subject is the transmit's handle and its completion, in amber: `tx` hands back a handle at once and
the MAC later asks `completion` for it, which is what makes the seam a pipe rather than a MAC data
service. The table beside the transmit is how rcp_radio turns the RCP's LAST_STATUS into the one
status band A branches on.

What the backend does on its own clock is drawn as its own: a write the seam took is only queued,
and the caller's loop (RcpRadio_Pump) is what puts it on the wire, while `tx` writes its frame inside
the call. An RCP that resets while it runs fails the open handles and is reported through isLost
until it runs again, and band A then re-applies its PIB, its delivery mode and its pending table.

    python3 tools/diagrams/seam.py            # docs/images/seam.png
    python3 tools/diagrams/seam.py --check    # is the committed raster still this figure?
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import D, MX, S1, S2, S3, S4  # noqa: E402

W = 1260
X_MAC, X_RCP, X_STICK = 214, 544, 864
HEAD_W = 170
TX0 = 1002                      # the status table's left edge
TX_W = W - MX - TX0

PATHS = ['src/seam/radio.h', 'src/zb/mac/mac.c', 'src/zb/mac/mac_tx.c', 'src/rcp/rcp_radio.c',
         'src/rcp/spinel_session.c', 'src/rcp/props.c', 'src/rcp/hdlc.c', 'tools/rcp_probe.c']

SYMBOLS = [
    # the seam
    'caps', 'pibSet', 'filter', 'tx', 'completion', 'rxPoll', 'isLost', 'scanStart', 'scanCollect',
    'pendingTable', 'Radio_Caps', 'Radio_Pib', 'Radio_TxResult', 'Radio_Frame', 'Radio_Pending',
    'handlesAckTimeout', 'hasPendingTable', 'isAcked', 'retries', 'isPromiscuous', 'ackRequest',
    'dwellUnits', 'rssiDbm', 'lqi', 'deviceStampTicks', 'RADIO_SCAN_NO_LEVEL',
    # statuses
    'ZB_OK', 'ZB_ERR_NOT_READY', 'ZB_ERR_NO_ACK', 'ZB_ERR_CHANNEL_ACCESS_FAILURE',
    'ZB_ERR_DEVICE_LOST', 'ZB_ERR_TIMEOUT', 'SpinelSession_StatusToZb',
    'SPINEL_STATUS_OK', 'SPINEL_STATUS_NO_ACK', 'SPINEL_STATUS_CCA_FAILURE',
    # the code either side
    'Mac_Init', 'Mac_SetPib', 'Mac_Step', 'RcpRadio_Pump', 'radioTxComplete', 'radioHandleReset',
    'rxQueue', 'needsRearm', 'maxFrameRetries',
    # the wire
    'STREAM_RAW', 'LAST_STATUS', 'NCP_VERSION', 'RADIO_CAPS', 'HWADDR', 'PHY_CHAN',
    'MAC_15_4_PANID', 'MAC_PROMISCUOUS_MODE', 'MAC_SRC_MATCH_ENABLED', 'MAC_SCAN_MASK',
    'MAC_ENERGY_SCAN_RESULT',
]

# How radioTxComplete and the session turn what the RCP said into Radio_TxResult.status:
# (what arrived, what band A gets, the condition on it)
STATUS = [
    ('SPINEL_STATUS_OK', 'ZB_OK', 'isAcked when an Ack was asked for'),
    ('SPINEL_STATUS_NO_ACK', 'ZB_ERR_NO_ACK', 'when an Ack was asked for'),
    ('SPINEL_STATUS_CCA_FAILURE', 'ZB_ERR_CHANNEL_ACCESS_FAILURE', 'nothing was sent'),
    ('a reset notification', 'ZB_ERR_DEVICE_LOST', 'every handle still open'),
    ('no answer in time', 'ZB_ERR_TIMEOUT', 'the session expired the request'),
    ('any other code', 'SpinelSession_StatusToZb', 'BUSY, INVALID_STATE, PARSE_ERROR …'),
]


def statusTable(f, y):
    """The translation, beside the completion it explains: one row per outcome."""
    f.group(TX0, y, TX_W, 'LAST_STATUS', 'becomes status')
    y += S4 + S2
    for code, zb, cond in STATUS:
        mono = code.isupper() or '_' in code
        f.fits(code, 'f-msg' if mono else 'f-sub', TX_W, 'the status table')
        f.text(TX0, y + 10, code, 'f-msg' if mono else 'f-sub')
        f.fits('→ ' + zb, 'f-msg', TX_W, 'the status table')
        f.text(TX0, y + 26, '→ ' + zb, 'f-msg')
        f.fits(cond, 'f-sub', TX_W - S4, 'the status table')
        f.text(TX0 + S4, y + 41, cond, 'f-sub')
        y += 52
    return y


def selfMsg(seq, a, name, sub, side='right', room=272):
    """Seq.self_msg, with its two lines measured like every other label."""
    seq.f.fits(name, 'f-msg', room, 'the step %r' % name)
    if sub:
        seq.f.fits(sub, 'f-sub', room, 'the step %r' % name)
    return seq.self_msg(a, name, sub, side)


def build():
    f = figure.Fig(W, 2000, 'THE SEAM, CALL BY CALL',
                   'a PSDU pipe and a capability report: band A calls down and pulls every answer; '
                   'the RCP is reached only through the backend')
    top = f.top + S2
    seq = figure.Seq(f, {
        'mac': (X_MAC, 'band A: the MAC', 'src/zb/mac/'),
        'rcp': (X_RCP, 'rcp_radio', 'band B: the backend'),
        'stick': (X_STICK, 'Phoscon RCP', 'the RCP'),
    }, top, head_w=HEAD_W)
    # what crosses each gap, named between the heads
    for xa, xb, name in ((X_MAC, X_RCP, 'seam/radio.h'), (X_RCP, X_STICK, 'Spinel %s HDLC' % D)):
        cw = figure.textW(name, 'f-id') + 2 * S2
        f.chip((xa + xb) / 2.0 - cw / 2.0, top + 8, name)

    # ---- bring-up
    seq.label('BRING-UP')
    selfMsg(seq, 'rcp', 'RcpRadio_Pump', 'the caller\'s loop moves the bytes, not the seam')
    seq.note('rcp', 'stick', 'RESET %s GET NCP_VERSION, RADIO_CAPS, HWADDR %s the arm writes' % (D, D),
             kind='band', pad=40)
    seq.msg('mac', 'rcp', 'caps', 'Mac_Init asks, then pibGet')
    seq.msg('rcp', 'mac', 'Radio_Caps', 'read at discovery: handlesAckTimeout, hasPendingTable',
            back=True)
    seq.msg('mac', 'rcp', 'pibSet(Radio_Pib)', 'Mac_SetPib: channel, PAN id, addresses …')
    seq.msg('rcp', 'mac', 'ZB_OK', 'queued: nothing has reached the RCP yet', back=True)
    seq.msg('mac', 'rcp', 'filter(isPromiscuous)', 'the delivery mode; the identity is pibSet\'s')
    seq.msg('rcp', 'stick', 'SET PHY_CHAN, MAC_15_4_PANID …',
            'then MAC_PROMISCUOUS_MODE: one write a pump')
    seq.msg('stick', 'rcp', 'VALUE_IS', 'the echo moves the write queue on', back=True)

    # ---- transmit: the subject
    seq.skip(S2)
    seq.label('TRANSMIT')
    tx0 = seq.msg('mac', 'rcp', 'tx(mpdu, ackRequest, maxFrameRetries)',
                  'the whole MPDU, its FCS included')
    seq.msg('rcp', 'stick', 'SET STREAM_RAW, tid n', 'written inside the call: PSDU and trailer')
    t0 = seq.msg('rcp', 'mac', 'handle', 'at once, before the frame is on the air', back=True,
                 amber=True)
    seq.note('stick', 'stick', 'CSMA-CA %s CCA %s the Ack wait %s retries' % (D, D, D), kind='band',
             pad=116)
    seq.msg('mac', 'rcp', 'completion(handle)', 'Mac_Step asks for every open handle')
    seq.msg('rcp', 'mac', 'ZB_ERR_NOT_READY', 'not answered yet: asked again next step', back=True)
    seq.msg('stick', 'rcp', 'LAST_STATUS, tid n', 'the outcome code, then two flags',
                 back=True)
    selfMsg(seq, 'rcp', 'radioTxComplete', 'matched by tid; the code mapped as at the right')
    seq.msg('mac', 'rcp', 'completion(handle)', 'the next step asks again')
    t1 = seq.msg('rcp', 'mac', 'Radio_TxResult', 'status and isAcked; retries stays 0', back=True,
                 amber=True)
    table_end = statusTable(f, tx0 - 12)

    # ---- receive
    seq.skip(S2)
    seq.label('RECEIVE')
    seq.msg('stick', 'rcp', 'VALUE_IS STREAM_RAW, tid 0', 'unsolicited, whenever a frame is heard')
    selfMsg(seq, 'rcp', 'rxQueue', 'a copy of each frame, held until band A asks')
    seq.msg('mac', 'rcp', 'rxPoll', 'a batch at most, each step')
    seq.msg('rcp', 'mac', 'Radio_Frame[ ]', 'bytes, rssiDbm, lqi, deviceStampTicks, error',
            back=True)

    # ---- the RCP resets; the radio is lost
    seq.skip(S2)
    seq.label('A RESET, A LOSS')
    seq.msg('stick', 'rcp', 'LAST_STATUS RESET_*', 'the RCP reset itself')
    selfMsg(seq, 'rcp', 'radioHandleReset', 'arms again, and owes the loss')
    seq.msg('mac', 'rcp', 'completion(handle)', 'an open handle')
    seq.msg('rcp', 'mac', 'ZB_ERR_DEVICE_LOST', 'the frame never left', back=True)
    seq.msg('mac', 'rcp', 'isLost', 'asked first, every Mac_Step')
    ya = seq.msg('rcp', 'mac', '1', 'until the RCP runs again, and once after: the MAC holds,',
                 back=True)
    f.text(X_RCP - S3, ya + 28, 'then re-applies its PIB, mode and pending table', 'f-sub', 'end')
    seq.skip(10)

    # ---- the pending table
    seq.skip(S2)
    seq.label('THE INDIRECT QUEUE MOVES')
    ya = seq.msg('mac', 'rcp', 'pendingTable(Radio_Pending)', 'who has a frame waiting, written')
    f.text(X_MAC + S3, ya + 28, 'only when the RCP reported hasPendingTable', 'f-sub')
    seq.skip(10)
    seq.msg('rcp', 'stick', 'SET MAC_SRC_MATCH_ENABLED …', 'and the two address lists, a pump each')
    seq.note('stick', 'stick', 'sets the Ack\'s Frame Pending from the table', kind='band',
             pad=150)

    # ---- the energy scan
    seq.skip(S2)
    y0 = seq.y
    seq.skip(32)
    seq.msg('mac', 'rcp', 'scanStart(channel, dwellUnits)', 'issued, not waited for')
    seq.msg('rcp', 'mac', 'ZB_OK', 'queued', back=True)
    seq.msg('rcp', 'stick', 'SET MAC_SCAN_MASK …', 'then the period, then the state')
    seq.msg('mac', 'rcp', 'scanCollect', 'while the dwell runs')
    seq.msg('rcp', 'mac', 'ZB_ERR_NOT_READY', 'ask again later', back=True)
    seq.msg('stick', 'rcp', 'MAC_ENERGY_SCAN_RESULT', 'the channel and a signed level', back=True)
    seq.msg('mac', 'rcp', 'scanCollect', 'collected once')
    seq.msg('rcp', 'mac', 'ZB_OK, channel, dBm', 'or RADIO_SCAN_NO_LEVEL: nothing was measured',
            back=True)
    seq.frame('mac', 'stick', y0, 'ENERGY SCAN', pad=100)
    owed = 'called by the MAC\'s ED scan and by tools/rcp_probe.c'
    f.fits(owed, 'f-sub', X_RCP - X_MAC - 2 * S3, 'the energy scan frame')
    f.text(X_MAC + S3, y0 + 14, owed, 'f-sub')

    end = seq.end()
    f.bracket(X_MAC - 60, t0, t1, ['the handle', 'is out:', 'nothing', 'waits on it'],
              side='left', cls='f-sub')

    bottom = max(end, table_end)
    ly = f.legend(bottom + 30, [('out', 'a call, or a frame sent'), ('back', 'an answer'),
                                ('now', 'the handle and its completion'),
                                ('band', 'what the RCP does meanwhile'),
                                ('alt', 'not yet band A\'s'), ('br', 'the deferred interval'),
                                ('tag', 'what crosses a gap')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    sys.exit(figure.main('seam', build, paths=PATHS, symbols=SYMBOLS))
