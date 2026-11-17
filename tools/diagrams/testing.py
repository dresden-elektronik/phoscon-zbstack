#!/usr/bin/env python3
"""What proves what, owned by docs/internals/testing.md section 1.

Content only: the style, the renderer and the checks are in figure.py. One row per layer of
evidence, ordered by what it needs, from nothing to two RCPs: what the row stands on at the left,
the ctest names that run on it in the middle with one plain line of what they prove, and what the
row needs at the right. Amber is `loopback_radio`, the seam's scripted implementation, because it is
what lets every band-A layer run with no RCP at all; the arrow is section 1's loop, what the rig
discovers frozen into a capture that the suites above defend from then on.

Every ctest name drawn is read out of test/CMakeLists.txt before anything is drawn, and so is each
row's claim about it: a suite drawn over `loopback_radio` links it, one drawn with no radio links no
backend, one drawn over `port_null` includes it, one drawn reading a capture is given the samples
directory, and every suite ctest registers is somewhere on the figure.

    python3 tools/diagrams/testing.py            # docs/images/testing.png
    python3 tools/diagrams/testing.py --check    # is the committed raster still this figure?
"""

import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
from figure import D, MX, S2, S3, S4, ROOT, textW  # noqa: E402

W = 1180
CA = 248                       # the column a row stands on
GX = MX + CA + 32              # where the ctest names start
NW = 104                       # the needs column, right-aligned at the margin
CB = W - MX - NW - 24 - GX     # the room for the names and the lines under them
CH, CG, CL = 24, 6, 30         # a chip's height, the air between two, a line of chips
PAD = 16                       # the air above and below a row's content
RIG_GAP = 44                   # the air the arrow from the rig crosses

# A row: (caps label, (stands-on name, plain line, kind), [segments], [proof lines], needs, claim).
# A segment is (prefix or None, [names], chip kind); a 'gap' chip is a bench instrument, not ctest.
SUB = 'substrate'
ROWS = [
    ('AUDITS', ('the tree', 'its source and documents, read as text', 'blk'),
     [(None, ['bands', 'vendor', 'freestanding', 'comment_audit', 'conformance_audit',
              'docs_audit', 'band_a_size', 'mem_size', 'namespace_audit', 'parent_streams'], 'tag')],
     ['the band, vendoring, comment, conformance-map, document and symbol-name rules hold; no behaviour runs',
      'band_a_size and mem_size compile for the ConBee II\'s Cortex-M0+, and skip it without '
      'that toolchain',
      'parent_streams builds the stack over an application\'s own u_bstream and u_sstream'],
     'nothing', 'python'),
    ('CODECS AND POOLS, NO RADIO', ('hand-built input', 'octets and pools written in the case',
                                    'blk'),
     [('substrate', ['utils_contract', 'u_bstream', 'u_sstream/*', 'log'], 'tag'),
      ('band A', ['mac_frame', 'nwk_frame', 'aps_frame', 'nwk_tables', 'nwk_modules',
                  'nwk_routedisc', 'security'], 'tag'),
      ('band B', ['hdlc', 'spinel_codec', 'spinel_session', 'props'], 'tag'),
      ('examples', ['ex_config'], 'tag')],
     ['codecs, bounds and pools field for field, against vectors computed by hand where the '
      'corpus prints none'],
     'nothing', 'noradio'),
    ('KNOWN ANSWERS', ('published vectors', 'FIPS-197 %s SP 800-38 %s R23.1 Annex C' % (D, D),
                       'blk'),
     [(None, ['crypto_aes', 'crypto_hash'], 'tag')],
     ['the cipher, CCM* and the Annex B hashes give the octets the specifications print'],
     'nothing', None),
    ('BAND A, EVERY LAYER', ('loopback_radio', 'the seam, scripted: no RCP, no clock', 'amb'),
     [(None, ['mac', 'nwk', 'nwk_routeflow', 'aps', 'aps_modules', 'af', 'zdo', 'zdo_client', 'zcl', 'core',
              'state', 'layers', 'stack'], 'tag'),
      ('the seam, and the model held to it', ['seam', 'loopback_radio', 'hearing'], 'tag')],
     ['every layer\'s state machines, one stack and two; what the air answered is the script\'s '
      'choice, never a device\'s'],
     'nothing', 'loopback'),
    ('BANDS B AND C, SCRIPTED BYTES', ('port_null', 'a scripted port: bytes in, bytes captured',
                                       'blk'),
     [(None, ['rcp_radio', 'port_contract', 'port_conformance'], 'tag'),
      ('over a pseudo-terminal or a sysfs-shaped tree instead', ['port_posix', 'port_locate'], 'tag'),
      ('on Windows, with no device', ['port_win32'], 'tag')],
     ['the Spinel backend and the port byte for byte, with every split and failure the script '
      'names'],
     'nothing', 'portnull'),
    ('FIXTURES', ('test/fixtures/', 'real captures, octets never edited', 'blk'),
     [(None, ['samples', 'interop'], 'tag'),
      ('also read by', ['hdlc', 'spinel_codec', 'rcp_radio', 'port_conformance', 'mac', 'layers'],
       'tag')],
     ['samples re-reads every fixture with a decoder that never read this tree; interop '
      'replays a test network offline'],
     'a capture', 'samples'),
    ('OUTSIDE CTEST: THE TWO-RCP RIG', ('the air', 'two RCPs on a quiet channel %s --allow-tx' % D, 'brd'),
     [(None, ['tools/rcp_probe', 'tools/rcp_send', 'tools/zb_join', 'tools/zb_mesh', 'tools/interop_sniff',
              'harness/rcp_sniffer.py', 'harness/port_dump.py'], 'gap')],
     ['what reaches the air: completions, Ack round trips, per-dialect differences; nothing '
      'about a live network'],
     'two RCPs', None),
]

PATHS = [
    'src/loopback/loopback_radio.c', 'src/port/port_null.c', 'test/support/rig_band_a.c',
    'test/CMakeLists.txt', 'harness/check_samples.py', 'test/fixtures',
    'test/bands_audit.py', 'test/vendor_audit.py', 'test/freestanding_audit.py',
    'test/comment_audit.py', 'test/conformance_audit.py', 'test/docs_audit.py', 'test/namespace_audit.py', 'test/parent_streams.py',
    'tools/band_a_size.py', 'tools/mem_size.py', 'vendor/u_sstream/tests',
    'tools/rcp_probe.c', 'tools/rcp_send.c', 'tools/zb_join.c', 'tools/interop_sniff.c',
    'harness/rcp_sniffer.py', 'harness/port_dump.py',
]


# ------------------------------------------------------------------ the tree's ctest

def ctest():
    """test/CMakeLists.txt read as {test name: (command, sources, link libraries, definitions)}."""
    with open(os.path.join(ROOT, 'test', 'CMakeLists.txt')) as f:
        text = f.read()

    def calls(fn):
        return [(m.group(1), m.group(2).split()) for m in
                re.finditer(r'%s\(\s*(\S+)\s+([^)]*)\)' % fn, text)]

    srcs = dict(calls('add_executable'))
    libs, defs = {}, {}
    for exe, rest in calls('target_link_libraries'):
        libs.setdefault(exe, []).extend(rest)
    for exe, rest in calls('target_compile_definitions'):
        defs.setdefault(exe, []).extend(rest)
    tests = {}
    for m in re.finditer(r'add_test\(\s*NAME\s+(\S+)\s+COMMAND\s+([^\s)]+)', text):
        name, cmd = m.group(1), m.group(2)
        tests[name] = (cmd, srcs.get(cmd, []), libs.get(cmd, []), ' '.join(defs.get(cmd, [])))
    return tests


def includes(sources, header):
    for s in sources:
        p = os.path.join(ROOT, 'test', s)
        if os.path.exists(p) and ('"%s"' % header) in open(p, errors='replace').read():
            return True
    return False


def checkRows():
    """Each name drawn is an add_test name, and each row's claim about its names holds."""
    tests = ctest()
    bad, drawn = [], set()
    vendored = glob.glob(os.path.join(ROOT, 'vendor', 'u_sstream', 'tests', '*.c'))
    for label, _stand, segs, _proof, _needs, claim in ROWS:
        for prefix, names, kind in segs:
            if kind == 'gap':
                continue
            for n in names:
                drawn.add(n)
                if n == 'u_sstream/*':
                    if not vendored or 'u_sstream/${testName}' not in open(
                            os.path.join(ROOT, 'test', 'CMakeLists.txt')).read():
                        bad.append('u_sstream/* is drawn, but ctest registers no vendored test')
                    continue
                if n not in tests:
                    bad.append('%s is drawn as a ctest name, but test/CMakeLists.txt has no '
                               'add_test of it' % n)
                    continue
                cmd, srcs, libs, defs = tests[n]
                if prefix == 'also read by' or (claim == 'samples' and n == 'interop'):
                    if 'ZB_SAMPLES_DIR' not in defs:
                        bad.append('%s is drawn reading test/fixtures/, but is not given it' % n)
                elif claim == 'python' and cmd != '${ZB_PYTHON}':
                    bad.append('%s is drawn as an audit, but it is not a Python script' % n)
                elif claim == 'loopback' and prefix is None and \
                        not set(libs) & {'zb_test_rig_band_a', 'zb_loopback'}:
                    bad.append('%s is drawn over loopback_radio, but does not link it' % n)
                elif claim == 'noradio' and (set(libs) & {'zb_test_rig_band_a', 'zb_loopback'} or
                                             includes(srcs, 'port_null.h')):
                    bad.append('%s is drawn with no radio, but links a backend' % n)
                elif claim == 'portnull' and prefix is None and not includes(srcs, 'port_null.h'):
                    bad.append('%s is drawn over port_null, but never includes it' % n)
    # the fixture row's list is the whole of who reads a capture
    readers = set(n for n, t in tests.items() if 'ZB_SAMPLES_DIR' in t[3])
    shown = set(ROWS[5][2][0][1] + ROWS[5][2][1][1]) - {'samples'}
    if readers != shown:
        bad.append('the suites given test/fixtures/ are %s, the figure draws %s'
                   % (sorted(readers), sorted(shown)))
    for n in sorted(tests):
        if n.startswith('u_sstream/'):
            continue
        if n not in drawn:
            bad.append('ctest registers %s, but the figure does not draw it' % n)
    return bad


# ------------------------------------------------------------------ drawing

def chipW(name):
    return textW(name, 'f-id') + 2 * S2


def chip(f, x, y, name, kind):
    w = chipW(name)
    f.rect(x, y, w, CH, figure.KIND[kind][0], rx=1)
    f.text(x + S2, y + CH / 2.0 + 4.5, name, 'f-id')
    return w


def layout(segs):
    """Where each chip of a row goes: [(x, y, name, kind)], prefixes [(x, y, words)], height."""
    chips, words, y = [], [], 0
    for prefix, names, kind in segs:
        x = GX
        if prefix:
            words.append((x, y + CH / 2.0 + 4, prefix + ':'))
            x += textW(prefix + ':', 'f-sub') + S3
        x0 = x
        for n in names:
            w = chipW(n)
            if x + w > GX + CB and x > x0:
                x, y = x0, y + CL
            chips.append((x, y, n, kind))
            x += w + CG
        y += CL
    return chips, words, y - CG


def build():
    f = figure.Fig(W, 1400, 'WHAT PROVES WHAT',
                   'each layer of evidence, what it stands on and what it needs; everything above '
                   'the rig runs in ctest with no RCP')
    y = f.top + S2
    f.text(MX, y + 10, 'STANDS ON', 'f-cap')
    f.text(GX, y + 10, 'RUNS IN CTEST, AND WHAT IT PROVES', 'f-cap')
    f.text(W - MX, y + 10, 'NEEDS', 'f-cap', 'end')
    y += 18
    f.line([(MX, y), (W - MX, y)], 'f-rule')
    boxes = []
    for i, (label, stand, segs, proof, needs, _claim) in enumerate(ROWS):
        top = y + (RIG_GAP if i == len(ROWS) - 1 else PAD)
        cy = top + 14
        f.text(GX, cy, label, 'f-cap')
        chips, words, ch = layout(segs)
        cy += S3
        for x, yy, n, kind in chips:
            chip(f, x, cy + yy, n, kind)
        for x, yy, w in words:
            f.fits(w, 'f-sub', CB, 'the row %r' % label)
            f.text(x, cy + yy, w, 'f-sub')
        py = cy + ch + 18
        for ln in proof:
            f.fits(ln, 'f-sub', CB, 'the row %r' % label)
            f.text(GX, py, ln, 'f-sub')
            py += 15
        bottom = py - 15 + 5
        h = max(bottom - top, 52)
        f.block(MX, top, CA, h, stand[0], stand[1], stand[2])
        f.fits(needs, 'f-lab', NW, 'the needs column')
        f.text(W - MX, top + h / 2.0 + 4, needs, 'f-lab', 'end')
        boxes.append((top, top + h))
        y = top + h + PAD
        if i < len(ROWS) - 1:
            f.line([(GX, y), (W - MX, y)], 'f-rule')

    # section 1's loop: what the rig discovers is frozen into a capture the suites defend
    ax = MX + 36
    f.arrow([(ax, boxes[-1][0] - 2), (ax, boxes[-2][1] + 3)])
    f.text(ax + S2 + 2, (boxes[-1][0] + boxes[-2][1]) / 2.0 + 4, 'what it finds, frozen into a capture',
           'f-sub')
    f.fits('what it finds, frozen into a capture', 'f-sub', CA - 48, 'the rig arrow')

    ly = f.legend(y + 30, [
        ('amb', 'the subject: the scripted radio every band-A layer stands on'),
        ('tag', 'a ctest name'), ('gap', 'a bench instrument, run by hand'),
        ('brd', 'real RCPs'), ('out', 'what the rig finds, handed on')])
    f.h = ly + S4
    return f


if __name__ == '__main__':
    bad = checkRows()
    if bad:
        raise SystemExit('testing: the figure no longer matches the tree:\n  %s' % '\n  '.join(bad))
    sys.exit(figure.main('testing', build, paths=PATHS))
