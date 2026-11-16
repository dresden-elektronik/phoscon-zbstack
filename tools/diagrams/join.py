#!/usr/bin/env python3
"""How a Zigbee 3.0 device joins a network this stack formed.

Content only: the style, the renderer and the checks are in figure.py. The figure is for someone
using the stack, so it draws what crosses the air and the one thing the application sees: the
frames in the order the trust centre exchanged them with a real bulb, and the announcement the
device object hands up. Amber is the network key arriving, the step after which the device is a
member. Every module the figure stands for is named in paths(), every identifier it prints in
symbols(), and the generator refuses to draw when one of them is gone.

    python3 tools/diagrams/join.py            # docs/images/join.png
    python3 tools/diagrams/join.py --check    # is the committed raster still this figure?
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import D, S2, S4  # noqa: E402

W = 1080

# what does each step, so a step whose module is gone stops the figure
PATHS = [
    'examples/coordinator/coordinator.c',      # the joined line
    'src/stack/zb_stack.c',        # the permit from the config, the announcement as an event
    'src/zb/zb_core.c',          # the key owed to a joiner, the announcement handed up
    'src/zb/mac/mac_beacon.c',     # the beacon answer
    'src/zb/mac/mac_assoc.c',      # the association response, held for the poll
    'src/zb/nwk/nwk_join.c',       # the address, the join indication
    'src/zb/aps/aps.c',            # Request Key, Verify Key, Confirm Key, the key door
    'src/zb/aps/aps_keydoor.c',    # which key a Transport Key is sealed with
    'src/zb/aps/aps_tclink.c',     # the link-key commands' bodies
    'src/zb/zdo/zdo.c',            # the Node Descriptor answer
]

SYMBOLS = ['permitSeconds', 'ZB_EVENT_DEVICE_JOINED']


def build():
    f = figure.Fig(W, 1400, 'HOW A DEVICE JOINS',
                   'a Zigbee 3.0 device associates, takes the network key, then trades the '
                   'global link key for one of its own')
    seq = figure.Seq(f, {'dev': (220, 'joining device', 'a Zigbee 3.0 bulb'),
                         'tc': (680, 'coordinator', 'trust centre: this stack'),
                         'app': (960, 'your application', 'on Zb_Stack')},
                     f.top + S2, head_w=170)

    seq.label('OPEN THE NETWORK')
    seq.msg('app', 'tc', 'permitSeconds', 'in the config: joining opens with the network')

    seq.label('FIND A NETWORK')
    seq.msg('dev', 'tc', 'Beacon Request', 'broadcast, on each channel it scans')
    seq.msg('tc', 'dev', 'Beacon', 'PAN coordinator %s association permit %s router capacity' % (D, D),
            back=True)

    seq.label('ASSOCIATE')
    seq.msg('dev', 'tc', 'Association Request', 'asks for a short address')
    seq.msg('dev', 'tc', 'Data Request', 'the poll that collects the answer')
    seq.msg('tc', 'dev', 'Association Response', 'success, short address 0x1fa1', back=True)

    seq.label('GET THE NETWORK KEY')
    seq.msg('tc', 'dev', 'APS Transport Key',
            'the network key, sealed with a key from ZigBeeAlliance09', amber=True)
    seq.msg('dev', 'tc', 'Device_annce', 'broadcast: its short and IEEE address, to the network')
    seq.msg('tc', 'app', 'ZB_EVENT_DEVICE_JOINED', 'the announcement, reported as one event', back=True)

    seq.label('ZIGBEE 3.0 LINK KEY')
    seq.msg('dev', 'tc', 'Node_Desc_req', 'asks what the trust centre is')
    seq.msg('tc', 'dev', 'Node_Desc_rsp', 'answered by the device object', back=True)
    seq.msg('dev', 'tc', 'APS Request Key', 'for a trust-centre link key of its own')
    seq.msg('tc', 'dev', 'APS Transport Key', 'its own link key, sealed with the global one',
            back=True)
    seq.msg('dev', 'tc', 'APS Verify Key', 'a hash that proves it holds the new key')
    seq.msg('tc', 'dev', 'APS Confirm Key', 'success, under the new key: the pair is verified',
            back=True)
    seq.note('dev', 'tc', 'the APS acknowledgements are not drawn',
             pad=60)
    end = seq.end()

    ly = f.legend(end + 30, [('out', 'a frame sent, or a call'), ('back', 'an answer'),
                             ('now', 'the network key arrives: the device is a member'),
                             ('gap', 'not drawn')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    sys.exit(figure.main('join', build, paths=PATHS, symbols=SYMBOLS))
