#!/usr/bin/env python3
"""The event loop: what one Zb_StackNextEvent call does under an application.

Content only: the style, the renderer and the checks are in figure.py. The figure is for someone
writing an application on Zb_Stack. The application's loop is one call and its own state machine;
the call turns the stack until an event or the timeout. The order drawn is src/stack/zb_stack.c's:
Zb_StackNextEvent hands back a waiting event without a turn, reads the clock, then loops - one turn
(Zb_StackTurn: pump the RCP, watch it, step the library), the next event if the turn left one,
read from the library's rings one entry at a time, the timeout test, Port_Wait on the RCP, the clock again. The turn drawn
is the one once the network is up; before it the turn brings the RCP up, joins or opens the
permit, which a plain line under the turn says. Amber is Zb_CoreStep: the network moves only there,
everything else in the call is carrying bytes and handing out what the step left.

Every identifier printed is checked against src/, or against the examples for the names only an
example has, before the figure draws.

    python3 tools/diagrams/turn.py            # docs/images/turn.png
    python3 tools/diagrams/turn.py --check    # is the committed raster still this figure?
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import D, MX, S2, S3, S4, S5  # noqa: E402

EXAMPLES = ['examples/coordinator/coordinator.c', 'examples/router/router.c']

SYMBOLS = ['Zb_Stack', 'Zb_Core', 'Rcp_Radio', 'Port', 'Zb_StackNextEvent', 'Zb_StackPollEvent',
           'Zb_StackTurn', 'Port_NowMs', 'RcpRadio_Pump', 'Port_Read', 'RcpRadio_Mode',
           'Zb_CoreStep', 'tx', 'rxPoll', 'completion', 'Radio_Ops', 'Port_Write', 'Radio_Frame',
           'Zb_CorePollConfirms', 'Zb_CorePollIndications', 'Aps_Confirm', 'Aps_Indication',
           'Port_Wait', 'nowMs', 'ZB_STACK_WAIT_MS']
# what only an example names: the application's own state machine and its wait
APP_SYMBOLS = ['s_stack', 'EVENT_WAIT_MS', 'onEvent', 'state', 'event']

W = 1280
HEAD_W, HEAD_H = 190, 42
X = {'app': 160, 'stack': 470, 'core': 730, 'rcp': 950, 'port': 1160}
BAR = 8                         # the amber activation's width
LOOP_X = MX + 30                # the application's way back to its call, left of everything
FRAME_L = 230                   # the stack's loop frame, left of its lifeline: room for the returns' lines
FRAME_R = 44                    # and right of the port's


def waitMs():
    """The longest sleep between two turns, as src/stack/zb_stack.c sets it, so the image never copies it."""
    with open(os.path.join(figure.ROOT, 'src', 'stack', 'zb_stack.c')) as f:
        m = re.search(r'ZB_STACK_WAIT_MS\s*=\s*(\d+)', f.read())
    if not m:
        raise SystemExit('turn: src/stack/zb_stack.c sets no ZB_STACK_WAIT_MS')
    return int(m.group(1))


def checkExamples(names):
    blob = ''
    for p in EXAMPLES:
        with open(os.path.join(figure.ROOT, p)) as f:
            blob += f.read()
    return ['%s is drawn, but no example names it' % s for s in names
            if not re.search(r'(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])' % re.escape(s), blob)]


def head(f, y, key, name, sub, kind):
    x = X[key]
    f.block(x - HEAD_W / 2.0, y, HEAD_W, HEAD_H, name, sub, kind, center=True)


def selfMsg(f, seq, a, name, sub, until):
    """A step inside one participant, on its right, its labels measured against the room up to `until`."""
    room = X[until] - S3 - (seq.x[a] + 28 + S2)
    f.fits(name, 'f-msg', room, 'the step %r' % name)
    f.fits(sub, 'f-sub', room, 'the step %r' % name)
    return seq.self_msg(a, name, sub, side='right')


def build():
    f = figure.Fig(W, 1600, 'THE EVENT LOOP',
                   'your loop is one call and your own state machine; the stack moves only inside the call')

    # the object the application holds, and what it drives: one label and rule over the four columns
    gx0, gx1 = X['stack'] - HEAD_W / 2.0, X['port'] + HEAD_W / 2.0
    gy = f.top + 6
    f.group(gx0, gy, gx1 - gx0, 'static Zb_Stack s_stack;', 'one object in your memory, and all it drives')
    hy = gy + 20
    head(f, hy, 'app', 'your application', 'the loop, in main', 'hd')
    head(f, hy, 'stack', 'Zb_Stack', 'the object you call', 'tag')
    head(f, hy, 'core', 'Zb_Core', 'APS %s NWK %s MAC' % (D, D), 'tag')
    head(f, hy, 'rcp', 'Rcp_Radio', 'the RCP\'s backend', 'tag')
    head(f, hy, 'port', 'Port', 'its clock and serial device', 'tag')

    seq = figure.Seq(f, {}, hy)
    seq.x = dict(X)
    seq.top = hy + HEAD_H + 2
    seq.y = hy + HEAD_H + S5

    first = seq.msg('app', 'stack', 'Zb_StackNextEvent', 'waits at most EVENT_WAIT_MS for one event')
    selfMsg(f, seq, 'stack', 'Zb_StackPollEvent', 'one already waiting returns at once', 'core')
    seq.msg('stack', 'port', 'Port_NowMs', 'when the call began')

    # the stack's own loop: a dashed frame from the stack's lifeline to the port's
    loop_top = seq.y
    seq.skip(26)

    # one turn: a band behind it, from the stack's lifeline to the port's
    band_top = seq.y
    seq.skip(30)
    seq.msg('stack', 'rcp', 'RcpRadio_Pump(&rcp, nowMs)', 'the bytes the RCP sent, decoded')
    seq.msg('rcp', 'port', 'Port_Read', 'what the RCP sent')
    selfMsg(f, seq, 'stack', 'RcpRadio_Mode', 'an RCP lost or back is an event', 'core')

    step_y = seq.msg('stack', 'core', 'Zb_CoreStep(&core, nowMs)', 'every layer advances once')
    bar_at = len(f.parts)
    # while the library is turning, its arrows leave from the edge of the amber bar, not its middle
    seq.x['core'] = X['core'] + BAR / 2.0
    seq.msg('core', 'rcp', 'tx %s rxPoll %s completion' % (D, D), 'through Radio_Ops, never blocking')
    seq.msg('rcp', 'port', 'Port_Write', 'framed onto the port\'s ring')
    seq.msg('rcp', 'core', 'Radio_Frame', 'a frame the RCP received', back=True)
    bar_end = seq.y - 6
    seq.x['core'] = X['core']

    seq.skip(S2)
    band_end = seq.y

    seq.skip(S2)
    selfMsg(f, seq, 'stack', 'Zb_StackPollEvent', 'the next event, if the turn left one', 'core')
    seq.msg('stack', 'core', 'Zb_CorePollConfirms', 'or Zb_CorePollIndications, one entry')
    seq.msg('core', 'stack', 'Aps_Confirm %s Aps_Indication' % D, 'straight into the event', back=True)
    seq.msg('stack', 'app', '1', 'an event: the call returns it', back=True)
    seq.msg('stack', 'port', 'Port_NowMs', 'is the timeout spent?')
    seq.msg('stack', 'app', '0', 'the timeout spent: no event', back=True)
    seq.msg('stack', 'port', 'Port_Wait', 'drains, then sleeps for bytes, at most %d ms' % waitMs())
    seq.msg('stack', 'port', 'Port_NowMs', 'the next turn\'s nowMs')
    loop_end = seq.y + S2
    seq.skip(S4 + S2)

    selfMsg(f, seq, 'app', 'onEvent(state, &event)', 'your state machine, then call again', 'stack')
    end = seq.end(pad=S4)

    # the amber step: an activation on the library's lifeline, under the arrows that touch it
    lx = X['core']
    f.parts.insert(bar_at, '<rect class="f-now" x="%g" y="%g" width="%g" height="%g" rx="1"/>'
                   % (lx - BAR / 2.0, step_y + 6, BAR, bar_end - step_y - 6))

    # the turn's band and the loop's frame, behind everything, the lifelines included
    fx0, fx1 = X['stack'] - FRAME_L, X['port'] + FRAME_R
    bx0, bx1 = fx0 + S3, fx1 - S3
    f.parts.insert(0, '<rect class="f-band" x="%g" y="%g" width="%g" height="%g" rx="3"/>'
                   % (bx0, band_top, bx1 - bx0, band_end - band_top))
    band_label = 'ONE TURN, Zb_StackTurn'
    f.fits(band_label, 'f-cap', bx1 - bx0 - 2 * S2, 'the turn\'s band')
    f.text(bx0 + S2, band_top + 14, band_label, 'f-cap')
    # which turn is drawn: plain lines in the band's empty corner, left of the stack's lifeline
    phase = ['the turn once the network is up;', 'before it, the turn brings the',
             'RCP up, joins, or opens the', 'permit instead']
    py = (step_y + bar_end) / 2.0 - (len(phase) - 1) * 7.5 + 4
    for i, ln in enumerate(phase):
        f.fits(ln, 'f-sub', X['stack'] - S3 - (bx0 + S2), 'the turn\'s phase lines')
        f.text(bx0 + S2, py + i * 15, ln, 'f-sub')
    f.rect(fx0, loop_top, fx1 - fx0, loop_end - loop_top, 'f-alt', rx=2)
    loop_label = 'UNTIL AN EVENT OR THE TIMEOUT'
    f.fits(loop_label, 'f-cap', fx1 - fx0 - 2 * S2, 'the loop\'s frame')
    f.text(fx0 + S2, loop_top + 14, loop_label, 'f-cap')

    # and round again: from the application's state machine back to its call
    ax = X['app'] - 2
    f.line([(ax, end - S2), (LOOP_X, end - S2), (LOOP_X, first), (ax - 2, first)], 'f-out', 'ink')
    label = 'AND ROUND AGAIN'
    f.fits(label, 'f-cap', end - first - 40, 'the way back')
    f.text(LOOP_X - 8, (first + end) / 2.0, label, 'f-cap', 'middle', rotate=-90)

    ly = f.legend(end + S5 + S3, [
        ('now', 'the subject: the network moves only inside Zb_CoreStep'),
        ('out', 'a call'), ('back', 'what comes back'),
        ('band', 'one turn'), ('alt', 'repeated until an event or the timeout')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    bad = checkExamples(APP_SYMBOLS)
    if bad:
        raise SystemExit('turn: the figure no longer matches the tree:\n  %s' % '\n  '.join(bad))
    sys.exit(figure.main('turn', build,
                         paths=EXAMPLES + ['src/stack/zb_stack.h', 'src/stack/zb_stack.c',
                                           'src/zb/zb_core.h', 'src/rcp/rcp_radio.h',
                                           'src/seam/radio.h', 'src/port/port.h'],
                         symbols=SYMBOLS))
