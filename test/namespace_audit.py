#!/usr/bin/env python3
"""No library of the tree's own defines a U_ symbol: U_ belongs to the u_* libraries, vendored here or the
application's own, and the tree's helpers are Zb_ (docs/internals/coding-rules.md §2).

    namespace_audit.py <nm> <archive>...

It fails with the names it finds.
"""

import re
import subprocess
import sys

DEFINED = re.compile(r'^[0-9a-fA-F]+ [TDBS] _?(U_\w+)$')


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    found = set()
    for archive in argv[2:]:
        out = subprocess.run([argv[1], '-g', archive], capture_output=True, text=True)
        if out.returncode != 0:
            print('namespace_audit: %s could not read %s' % (argv[1], archive))
            return 1
        for line in out.stdout.splitlines():
            m = DEFINED.match(line.strip())
            if m:
                found.add(m.group(1))
    if found:
        print('NAMESPACE VIOLATION: the tree defines U_ names, which belong to the u_* libraries: '
              + ' '.join(sorted(found)))
        return 1
    print('namespace_audit: no U_ symbol in %d archive(s) of the tree\'s own' % (len(argv) - 2))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
