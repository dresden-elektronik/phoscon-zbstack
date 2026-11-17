#!/usr/bin/env python3
"""An application that names its own u_bstream and u_sstream builds the stack over them, and vendor/ is not
compiled; a copy whose header is not the revision vendor/MANIFEST pins stops the configure (D-290).

    parent_streams.py <cmake> <tree> <work directory> [<generator>]

It configures and builds test/parent_streams/ twice under the work directory: once as written, which must link with
no source of vendor/ in its compile commands and the application's include directory on none of the tree's, and once
with a header of another revision, which must not configure.
"""

import json
import os
import shutil
import subprocess
import sys


def run(argv):
    return subprocess.run(argv, capture_output=True, text=True)


def configure(cmake, generator, tree, build, extra):
    shutil.rmtree(build, ignore_errors=True)
    # The build tree's own generator, so compile_commands.json is written: Visual Studio's, the default on Windows,
    # writes none.
    return run([cmake, '-S', os.path.join(tree, 'test', 'parent_streams'), '-B', build] + generator + [
                '-DZB_TREE=' + tree, '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-DCMAKE_BUILD_TYPE=Release'] + extra)


def main(argv):
    if len(argv) not in (4, 5):
        print(__doc__)
        return 2
    cmake, tree, work = argv[1], os.path.realpath(argv[2]), os.path.realpath(argv[3])
    generator = ['-G', argv[4]] if len(argv) == 5 else []
    vendor = os.path.join(tree, 'vendor') + os.sep

    build = os.path.join(work, 'pinned')
    out = configure(cmake, generator, tree, build, [])
    if out.returncode != 0:
        print('parent_streams: the pinned copy did not configure\n' + out.stdout + out.stderr)
        return 1
    out = run([cmake, '--build', build, '--target', 'parent_app'])
    if out.returncode != 0:
        print('parent_streams: the stack did not build over the application\'s copy\n' + out.stdout + out.stderr)
        return 1
    with open(os.path.join(build, 'compile_commands.json')) as f:
        entries = json.load(f)
    compiled = [os.path.realpath(entry['file']) for entry in entries]
    vendored = [path for path in compiled if path.startswith(vendor)]
    if vendored:
        print('PARENT STREAMS VIOLATION: vendor/ compiled beside the application\'s copy: ' + ' '.join(vendored))
        return 1
    ulib = os.path.join(build, 'ulib')
    reached = [os.path.realpath(entry['file']) for entry in entries
               if os.path.realpath(entry['file']).startswith(os.path.join(tree, 'src') + os.sep) and ulib in entry.get('command', '')]
    if reached:
        print('PARENT STREAMS VIOLATION: the application\'s include directory is on the path of the tree\'s own '
              'sources, where a header of its own could stand in for one of ours: ' + ' '.join(reached[:3]))
        return 1

    other = os.path.join(work, 'other')
    os.makedirs(other, exist_ok=True)
    with open(os.path.join(tree, 'vendor', 'u_bstream', 'u_bstream.h')) as f:
        header = f.read()
    with open(os.path.join(other, 'u_bstream.h'), 'w') as f:
        f.write(header + '\n/* another revision */\n')
    out = configure(cmake, generator, tree, os.path.join(work, 'unpinned'), ['-DPARENT_HEADER_SOURCE=' + other])
    if out.returncode == 0 or 'is not the revision vendor/MANIFEST pins' not in out.stdout + out.stderr:
        print('PARENT STREAMS VIOLATION: a u_bstream.h of another revision configured\n' + out.stdout + out.stderr)
        return 1

    print('parent_streams: %d sources over the application\'s copy, none from vendor/; another revision refused'
          % len(compiled))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
