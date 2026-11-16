#!/usr/bin/env python3
"""Finding a route: Zigbee route discovery as this stack runs it, over one relay.

Content only: the style, the renderer and the checks are in figure.py. Three routers, the
originator S out of the destination D's range and one relay R between them. S holds the frame in
its transmit slot, broadcasts a Route Request, R records a discovery entry and a reverse route and
rebroadcasts after a jitter, D answers with a Route Reply readdressed hop by hop back along the
reverse routes, and the held frame goes out over the hop the reply named. Amber is the reply
reaching S: the moment the originator's routing entry turns ACTIVE and the frame is released
(nwk_rreprx.c's originator branch, nwk.c's nwkDoDiscoveryRelease).

R's forward entry is drawn with its next hop and no status: the relay branch of Nwk_RrepRx sets
the next hop and leaves the DISCOVERY_UNDERWAY the request set, and the relayed frame finds D as a
neighbour. The two failures are the two the code has: no reply before the discovery entry expires,
and a link that breaks after the route stood.

    python3 tools/diagrams/routing.py            # docs/images/routing.png
    python3 tools/diagrams/routing.py --check    # is the committed raster still this figure?
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import S2, S3, S4  # noqa: E402

W = 1140
XS, XR, XD = 240, 620, 1000
AX0, AX1 = 40, W - 40          # an alternative's frame, its condition left of S's lifeline

# what does each step, so a step whose module is gone stops the figure
PATHS = [
    'src/zb/nwk/nwk.c',            # the held slot, the discovery started, released, expired; the replies sent
    'src/zb/nwk/nwk_rreq.c',       # the Route Request composed and relayed
    'src/zb/nwk/nwk_rreqtx.c',     # the request's broadcast schedule
    'src/zb/nwk/nwk_rreqrelay.c',  # the relay's jitter
    'src/zb/nwk/nwk_rreqrx.c',     # the discovery entry and the reverse route
    'src/zb/nwk/nwk_rrep.c',       # the Route Reply composed and forwarded
    'src/zb/nwk/nwk_rreprx.c',     # the reply received: the originator's ACTIVE, the relay's next hop
    'src/zb/nwk/nwk_route.c',      # the routing table, the next hop, the invalidation
    'src/zb/nwk/nwk_cost.c',       # the link cost the path cost accumulates
    'src/zb/nwk/nwk_relay.c',      # the unicast relay
    'src/zb/nwk/nwk_status.c',     # the network status and the route it removes
    'src/zb/nwk/nwk_tx.c',         # the held frame's issue
]

SYMBOLS = [
    'NWK_TX_AWAITING_ROUTE', 'NWK_ROUTE_DISCOVERY_UNDERWAY', 'NWK_ROUTE_ACTIVE', 'NWK_ROUTE_INACTIVE',
    'NWK_ADDR_ROUTERS', 'NWK_STATUS_ROUTE_ERROR', 'NWK_NETWORK_STATUS_LINK_FAILURE',
    'Nwk_RouteInvalidate', 'Nwk_RreqRelayJitterMs', 'Nwk_RrepRx', 'Nwk_RreqRx', 'nwkDoDiscoveryRelease',
    'nwkDoDiscoveryExpiry', 'nwkDoDeliveryFailed',
]


def selfm(f, seq, a, name, sub, side, room):
    """seq.self_msg with its two lines measured against the gap it is drawn into."""
    f.fits(name, 'f-msg', room, 'the step %r' % name)
    f.fits(sub, 'f-sub', room, 'the step %r' % name)
    seq.self_msg(a, name, sub, side=side)


def alt(f, seq, y0, label):
    """An alternative framed across the whole figure, its condition set clear of S's lifeline."""
    f.fits(label, 'f-cap', XS - S2 - (AX0 + S2), 'the frame %r' % label)
    f.rect(AX0, y0, AX1 - AX0, seq.y - y0, 'f-alt', rx=2)
    f.text(AX0 + S2, y0 + 14, label, 'f-cap')
    seq.y += S2


def build():
    f = figure.Fig(W, 1600, 'FINDING A ROUTE',
                   'a router with a frame and no route asks the network, and the reply lays the '
                   'route down hop by hop')
    seq = figure.Seq(f, {'s': (XS, 'originator S', 'this stack, a router'),
                         'r': (XR, 'relay R', 'a router between'),
                         'd': (XD, 'destination D', "out of S's range")},
                     f.top + S2, head_w=170)
    gap = XR - XS - 28 - S2 - S3

    seq.label('NO ROUTE TO D')
    selfm(f, seq, 's', 'NWK_TX_AWAITING_ROUTE', 'the frame is held in its slot, not sent', 'right', gap)
    selfm(f, seq, 's', 'NWK_ROUTE_DISCOVERY_UNDERWAY', 'a routing entry for D, and a discovery entry',
          'right', gap)

    seq.label('ASK')
    seq.msg('s', 'r', 'Route Request', 'broadcast to every router: request id, path cost 0')
    selfm(f, seq, 'r', 'discovery entry, reverse route',
          'to S: next hop S, ACTIVE; to D: DISCOVERY_UNDERWAY', 'right', gap)
    seq.msg('r', 'd', 'Route Request', 'rebroadcast after a jitter, path cost plus the S-R link')
    selfm(f, seq, 'd', 'the request is for D', 'discovery entry; to S: next hop R, ACTIVE', 'left',
          gap)

    seq.label('ANSWER')
    seq.msg('d', 'r', 'Route Reply', 'unicast to R, path cost the R-D link', back=True)
    selfm(f, seq, 'r', 'route to D: next hop D, ACTIVE', 'path cost plus the S-R link, readdressed to S',
          'right', gap)
    seq.msg('r', 's', 'Route Reply', 'the route to D turns ACTIVE via R; the requests stop',
            back=True, amber=True)

    seq.label('SEND')
    seq.msg('s', 'r', 'held frame', 'released: NWK destination D, MAC destination R')
    seq.msg('r', 's', 'Ack', 'MAC, one hop', back=True)
    seq.msg('r', 'd', 'relayed frame', 'over R\'s route to D')
    seq.msg('d', 'r', 'Ack', 'MAC, one hop', back=True)
    seq.msg('d', 's', 'APS Ack', 'end to end, when the request asked for one', back=True)

    seq.skip(S4)
    y0 = seq.y
    seq.skip(20)
    selfm(f, seq, 's', 'NWK_STATUS_ROUTE_ERROR', 'the discovery entry expired: the frame never left',
          'right', gap)
    alt(f, seq, y0, 'IF NO REPLY COMES')

    seq.skip(S2)
    y0 = seq.y
    seq.skip(20)
    seq.msg('r', 'd', 'relayed frame', 'no MAC Ack, its retries spent')
    selfm(f, seq, 'r', 'Nwk_RouteInvalidate', 'every route through D turns INACTIVE', 'right', gap)
    seq.msg('r', 's', 'Network Status', 'link failure, naming D')
    selfm(f, seq, 's', 'route to D removed', 'the next frame for D starts a new discovery', 'right',
          gap)
    alt(f, seq, y0, 'IF A LINK BREAKS LATER')
    end = seq.end()

    ly = f.legend(end + 30, [('out', 'a frame sent'), ('back', 'an answer'),
                             ('now', 'the reply reaches S: the route exists'),
                             ('alt', 'an alternative')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    sys.exit(figure.main('routing', build, paths=PATHS, symbols=SYMBOLS))
