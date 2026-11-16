#!/usr/bin/env python3
"""Where the RAM goes: the stack's objects broken down by member, on the ConBee II's MCU and on this host.

docs/memory.md cites what this prints. The members are read from the structs as the compiler sees them, after
`-E`, so a member under `#if` is there exactly when the build has it, and every `sizeof` is the compiler's: the
M0+ side is compiled with band_a_size.py's flags and read back with `nm -S`, the host side is compiled and run.
A member the parser cannot read stops the tool; what the members do not add up to is printed as padding.
After the objects, the deepest call chain from each public entry point on the M0+, from gcc's -fcallgraph-info.

Usage: mem_size.py [repo-root] [--conbee2] [-D NAME=VALUE ...] [--all] [--min BYTES]

    --conbee2       a 32 KB profile for the ConBee II's MCU, which runs no coordinator yet
    -D NAME=VALUE   any other ZB_LIMIT_* or build option, as CMake would pass it
    --all           every member, not only those of --min bytes or more (default 100, so a frame's buffer shows)

Skips the M0+ column without arm-none-eabi-gcc, as band_a_size.py does.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import band_a_size  # noqa: E402

HEADERS = ['zb_stack.h', 'zb_core.h', 'rcp_radio.h']

# The ConBee II's MCU, 32 KB: 4 APS and NWK sends, NWK indications and route discoveries, 8 routes, neighbours,
# broadcast-table entries and sleepy-child frames, 16 frame counters, 24 duplicates, fragmentation off, and 34 devices
CONBEE2 = ['ZB_APS_FRAGMENTATION=0', 'ZB_LIMIT_APS_TX=4', 'ZB_LIMIT_NWK_TX=4', 'ZB_LIMIT_NWK_INDICATION=4',
           'ZB_LIMIT_NWK_DISCOVERY=4', 'ZB_LIMIT_NWK_ROUTE=8', 'ZB_LIMIT_NWK_NEIGHBOR=8', 'ZB_LIMIT_NWK_BTT=8',
           'ZB_LIMIT_SECURITY_INCOMING=16', 'ZB_LIMIT_MAC_TRANSACTION=8', 'ZB_LIMIT_APS_DUP=24',
           'ZB_LIMIT_NWK_ADDR_MAP=34', 'ZB_LIMIT_SECURITY_KEYPAIR=34', 'ZB_LIMIT_CORE_JOINER=34',
           'ZB_LIMIT_NWK_SOURCE_ROUTE=34']

# The tree printed: an object's member of these types is broken down in its turn.
EXPAND = {
    ('Zb_Stack', 'rcp'): 'Rcp_Radio',
    ('Zb_Stack', 'core'): 'Zb_Core',
    ('Rcp_Radio', 'port'): 'Port',
    ('Rcp_Radio', 'decoder'): 'Hdlc_Decoder',
    ('Zb_Core', 'layers'): 'Zb_Layers',
    ('Zb_Core', 'af'): 'Af_Af',
    ('Zb_Core', 'zdo'): 'Zdo_Zdo',
    ('Zb_Layers', 'mac'): 'Mac_Mac',
    ('Zb_Layers', 'nwk'): 'Nwk_Nwk',
    ('Zb_Layers', 'aps'): 'Aps_Aps',
    ('Zb_Layers', 'security'): 'Security',
    ('Mac_Mac', 'rx'): 'Mac_Rx',
    ('Mac_Mac', 'indirect'): 'Mac_Indirect',
}
ROOTS = ['Zb_Stack']

# The public entry points whose deepest call chain on the M0+ is printed: what an application calls, and so the call
# stack it has to leave room for.
CHAIN_ROOTS = ['Zb_CoreInit', 'Zb_CoreStep', 'Zb_CoreSendRequest', 'Zb_StateCapture', 'Zb_StateRestore']
CHAIN_FRAMES = 8               # the largest single frames, printed after the chains

# The cycles known to end, each with the most times its function is on one chain and why; any other cycle stops
# the tool.
BOUNDED = [
    (('Aps_DataRequest', 'apsDoRequest'), 2,
     'an extended destination resolved to a short one is asked once more, as a short one'),
]
BOUND = dict((name, times) for names, times, _ in BOUNDED for name in names)

# One entry of the tables a frame is held in, broken down: docs/memory.md §4 cites their insides.
SLOTS = ['Aps_Tx', 'Nwk_Tx', 'Nwk_BroadcastTransactionRecord', 'Mac_Transaction']
SLOT_MIN = 16                  # a slot's members of this many bytes or more are printed


def run(command, **kw):
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, **kw)


def fail(message):
    raise SystemExit('mem_size: ' + message)


def revision(root):
    head = run(['git', '-C', root, 'rev-parse', '--short', 'HEAD'])
    if head.returncode != 0:
        return 'unknown revision'
    dirty = run(['git', '-C', root, 'status', '--porcelain', '--', 'src', 'vendor'])
    return head.stdout.strip() + (', src changed' if dirty.stdout.strip() else '')


def preprocess(cc, flags, root, work):
    src = os.path.join(work, 'all.c')
    with open(src, 'w') as f:
        f.write(''.join('#include "%s"\n' % h for h in HEADERS))
    res = run([cc] + flags + band_a_size.includeDirs(root) + ['-E', '-P', src])
    if res.returncode != 0:
        fail('%s -E failed: %s' % (cc, band_a_size.firstLines(res.stdout)))
    return res.stdout


def structBody(text, name):
    """The member text of `struct name { ... }`, or of `typedef struct tag { ... } name;`, from preprocessed
    source."""
    m = re.search(r'\bstruct\s+%s\s*\{' % re.escape(name), text)
    if m:
        depth, i = 1, m.end()
        while depth:
            depth += {'{': 1, '}': -1}.get(text[i], 0)
            i += 1
        return text[m.end():i - 1]
    m = re.search(r'\}\s*%s\s*;' % re.escape(name), text)
    if not m:
        fail('no struct %s in the preprocessed headers' % name)
    depth, i = 1, m.start() - 1
    while depth:
        depth += {'}': 1, '{': -1}.get(text[i], 0)
        i -= 1
    return text[i + 2:m.start()]


def members(text, name):
    """(member, is_array) in declaration order; a declaration this cannot read stops the tool."""
    out = []
    body = structBody(text, name)
    if '{' in body:
        fail('struct %s nests a struct or union body, which the parser does not read' % name)
    for decl in body.split(';'):
        decl = ' '.join(decl.split())
        if not decl:
            continue
        if '(' in decl:
            fn = re.search(r'\(\s*\*\s*(\w+)\s*\)', decl)
            if not fn:
                fail('struct %s: cannot read "%s"' % (name, decl))
            out.append((fn.group(1), False))
            continue
        if ':' in decl:
            fail('struct %s: a bit-field has no sizeof: "%s"' % (name, decl))
        parts = decl.split(',')
        first = re.match(r'^(.*?)(\**\s*\w+\s*(\[[^\]]*\]\s*)*)$', parts[0])
        if not first:
            fail('struct %s: cannot read "%s"' % (name, decl))
        for part in [first.group(2)] + parts[1:]:
            d = re.match(r'^\s*\**\s*(\w+)\s*((\[[^\]]*\]\s*)*)$', part)
            if not d:
                fail('struct %s: cannot read "%s"' % (name, decl))
            out.append((d.group(1), bool(d.group(2))))
    return out


def entries(text):
    """Every (type, member, is_array) measured, a member '' standing for the type itself."""
    out, todo, seen = [], list(ROOTS) + SLOTS, set()
    while todo:
        t = todo.pop(0)
        if t in seen:
            continue
        seen.add(t)
        out.append((t, '', False))
        for m, arr in members(text, t):
            out.append((t, m, arr))
            if (t, m) in EXPAND:
                todo.append(EXPAND[(t, m)])
    return out


def probeHost(cc, flags, root, work, ents):
    lines = ['#include <stdio.h>'] + ['#include "%s"' % h for h in HEADERS] + ['int main(void)', '{']
    for t, m, arr in ents:
        size = 'sizeof(%s)' % t if not m else 'sizeof(((%s *)0)->%s)' % (t, m)
        elem = 'sizeof(((%s *)0)->%s[0])' % (t, m) if arr else '0'
        lines.append('    printf("%s %s %%zu %%zu\\n", (size_t)%s, (size_t)%s);' % (t, m or '-', size, elem))
    lines += ['    return 0;', '}']
    src, exe = os.path.join(work, 'host.c'), os.path.join(work, 'host')
    with open(src, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    res = run([cc] + flags + band_a_size.includeDirs(root) + [src, '-o', exe])
    if res.returncode != 0:
        fail('host probe failed: %s' % band_a_size.firstLines(res.stdout))
    res = run([exe])
    sizes = {}
    for line in res.stdout.splitlines():
        t, m, size, elem = line.split()
        sizes[(t, '' if m == '-' else m)] = (int(size), int(elem))
    return sizes


def probeM0(prefix, defines, root, work, ents):
    """The same sizes from the cross-compiler, as char arrays whose size `nm -S` reads back."""
    lines = ['#include "%s"' % h for h in HEADERS]
    for i, (t, m, arr) in enumerate(ents):
        size = 'sizeof(%s)' % t if not m else 'sizeof(((%s *)0)->%s)' % (t, m)
        lines.append('char s%d[%s];' % (i, size))
        if arr:
            lines.append('char e%d[sizeof(((%s *)0)->%s[0])];' % (i, t, m))
    src, obj = os.path.join(work, 'm0.c'), os.path.join(work, 'm0.o')
    with open(src, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    res = run([prefix + 'gcc'] + band_a_size.M0_FLAGS + defines + band_a_size.includeDirs(root)
              + ['-c', src, '-o', obj])
    if res.returncode != 0:
        fail('M0+ probe failed: %s' % band_a_size.firstLines(res.stdout))
    res = run([prefix + 'nm', '-S', '--defined-only', obj])
    got = {}
    for line in res.stdout.splitlines():
        f = line.split()
        if len(f) == 4 and re.match(r'^[se]\d+$', f[3]):
            got[f[3]] = int(f[1], 16)
    sizes = {}
    for i, (t, m, arr) in enumerate(ents):
        sizes[(t, m)] = (got['s%d' % i], got.get('e%d' % i, 0))
    return sizes


def callGraph(prefix, defines, root, work):
    """Band A compiled for the M0+ with gcc's -fcallgraph-info: every function's frame and every call it makes, an
    indirect call (the radio seam's operations, the log sink) an edge to `__indirect_call`."""
    frames, calls = {}, {}
    for rel in band_a_size.librarySources(root):
        obj = os.path.join(work, rel.replace(os.sep, '_') + '.o')
        res = run([prefix + 'gcc'] + band_a_size.M0_FLAGS + defines + band_a_size.includeDirs(root)
                  + ['-fcallgraph-info=su', '-c', os.path.join(root, rel), '-o', obj])
        if res.returncode != 0:
            fail('%s: %s' % (rel, band_a_size.firstLines(res.stdout)))
        for line in open(obj[:-2] + '.ci'):
            node = re.match(r'node: \{ title: "([^"]+)" label: "([^"\\]*)\\n[^"]*?\\n(\d+) bytes \((\w[\w,]*)\)', line)
            if node:
                if node.group(4) != 'static':
                    fail('%s has a %s frame, which a chain cannot bound' % (node.group(2), node.group(4)))
                frames[node.group(1)] = (node.group(2), int(node.group(3)))
                continue
            edge = re.match(r'edge: \{ sourcename: "([^"]+)" targetname: "([^"]+)"', line)
            if edge:
                calls.setdefault(edge.group(1), set()).add(edge.group(2))
    return frames, calls


def deepest(frames, calls, fn, path=()):
    """(bytes, chain) of the deepest chain from `fn`. A function met again on its own chain is a cycle: one
    BOUNDED names is walked that many times, any other stops the tool, coding-rules §7 bounding the stack."""
    name = frames.get(fn, (fn,))[0]
    if path.count(fn) >= BOUND.get(name, 1):
        if name in BOUND:
            return 0, []
        fail('%s calls itself through %s' % (name, ' > '.join(frames.get(p, (p,))[0] for p in path)))
    best = (0, [])
    for callee in sorted(calls.get(fn, ())):
        if callee != '__indirect_call':
            d = deepest(frames, calls, callee, path + (fn,))
            if d[0] > best[0]:
                best = d
    return frames.get(fn, (fn, 0))[1] + best[0], [fn] + best[1]


def indirect(calls, fn):
    """The functions reachable from `fn` that call through a pointer, whose callee no chain can count."""
    seen, todo, out = set(), [fn], set()
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        for c in calls.get(f, ()):
            if c == '__indirect_call':
                out.add(f)
            else:
                todo.append(c)
    return out


def reportChains(frames, calls):
    print('call stack on the M0+, the deepest chain from each entry point (bytes, frame by frame)')
    for fn in CHAIN_ROOTS:
        if fn not in frames:
            fail('%s is not in band A' % fn)
        total, chain = deepest(frames, calls, fn)
        through = indirect(calls, fn)
        print('%-44s %10d' % (fn, total))
        print('    ' + ' > '.join('%s %d' % frames.get(c, (c, 0)) for c in chain))
        if through:
            print('    a lower bound: %d function%s on its reach call%s through a pointer, the callee not counted'
                  % (len(through), '' if len(through) == 1 else 's', 's' if len(through) == 1 else ''))
    for names, times, why in BOUNDED:
        print('    %s walked up to %d times on a chain: %s' % (' and '.join(names), times, why))
    print()
    print('largest frames on the M0+')
    for name, size in sorted(frames.values(), key=lambda f: (-f[1], f[0]))[:CHAIN_FRAMES]:
        print('%-44s %10d' % (name, size))


def shape(size, elem):
    return '%d x %d' % (size // elem, elem) if elem > 1 else ''


def report(text, columns, minimum):
    """The tree from the roots, then the slots; each member's bytes in every column."""
    names = [c for c, _ in columns]
    head = '%-44s %-12s' % ('', 'entries') + ''.join('%10s' % n for n in names)
    print(head)

    def row(label, ents, size_of):
        print('%-44s %-12s' % (label, ents) + ''.join('%10s' % size_of(c) for c in columns))

    def walk(t, indent, label, minimum=minimum):
        own = [(m, arr) for m, arr in members(text, t)]
        row(indent + label, '', lambda c: c[1][(t, '')][0])
        shown, rest, restCount = [], {n: 0 for n in names}, 0
        for m, arr in own:
            key = (t, m)
            big = any(c[1][key][0] >= minimum for c in columns)
            if big or (t, m) in EXPAND:
                shown.append(m)
            else:
                restCount += 1
                for n, s in columns:
                    rest[n] += s[key][0]
        for m in shown:
            key = (t, m)
            if key in EXPAND:
                walk(EXPAND[key], indent + '  ', m)
            else:
                first = columns[0][1][key]
                row(indent + '  ' + m, shape(*first), lambda c, k=key: c[1][k][0])
        if restCount:
            row(indent + '  the rest, %d members' % restCount, '', lambda c: rest[c[0]])
        pad = {n: s[(t, '')][0] - sum(s[(t, m)][0] for m, _ in own) for n, s in columns}
        if any(pad.values()):
            row(indent + '  padding', '', lambda c: pad[c[0]])

    for t in ROOTS:
        walk(t, '', t)
    print()
    for t in SLOTS:
        walk(t, '', t + ', one entry', min(minimum, SLOT_MIN))
        print()


def main(argv):
    args = list(argv)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    defines, minimum, prefix = [], 100, 'arm-none-eabi-'
    i = 0
    while i < len(args):
        a = args[i]
        if a == '--conbee2':
            defines += ['-D' + d for d in CONBEE2]
        elif a == '-D':
            i += 1
            defines.append('-D' + args[i])
        elif a.startswith('-D'):
            defines.append(a)
        elif a == '--all':
            minimum = 0
        elif a == '--min':
            i += 1
            minimum = int(args[i])
        elif not a.startswith('-'):
            root = a
        else:
            print(__doc__)
            return 2
        i += 1
    if not os.path.isfile(os.path.join(root, 'CMakeLists.txt')):
        fail('%s is not this tree: it holds no CMakeLists.txt' % root)

    with tempfile.TemporaryDirectory() as work:
        hostCc = os.environ.get('CC', 'cc')
        hostFlags = ['-std=c99'] + defines
        text = preprocess(hostCc, hostFlags, root, work)
        ents = entries(text)
        columns, graph = [], None
        if shutil.which(prefix + 'gcc'):
            m0text = preprocess(prefix + 'gcc', band_a_size.M0_FLAGS + defines, root, work)
            if [(t, m) for t, m, _ in entries(m0text)] != [(t, m) for t, m, _ in ents]:
                fail('the M0+ and the host see different members')
            columns.append(('M0+', probeM0(prefix, defines, root, work, ents)))
            graph = callGraph(prefix, defines, root, work)
        else:
            print('mem_size: M0+ column skipped, no %sgcc on PATH' % prefix)
        columns.append(('host', probeHost(hostCc, hostFlags, root, work, ents)))

    print('mem_size: bytes at %s%s; M0+ is %s' % (
        revision(root), (', ' + ' '.join(d[2:] for d in defines)) if defines else ', the default limits',
        ' '.join(band_a_size.M0_FLAGS[:3])))
    print()
    report(text, columns, minimum)
    if graph:
        reportChains(*graph)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
