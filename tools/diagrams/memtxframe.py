#!/usr/bin/env python3
"""One frame sent: every buffer a full frame is copied into, from the application to the MAC.

Content only: the style, the renderer and the checks are in figure.py, and the drawing is
memrxframe.py's, on docs/memory.md §4.1's table. An outline is as wide as the buffer, its amber
fill as wide as the frame's octets in it; under the rows, the payload sent is set against every
buffer it passed through.

    python3 tools/diagrams/memtxframe.py            # docs/images/memtxframe.png
    python3 tools/diagrams/memtxframe.py --check    # is the committed raster still this figure?
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import figure  # noqa: E402
import memrxframe  # noqa: E402

SYMBOLS = ['tx', 'adata', 'frame', 'secureScratch', 'mpdu', 'Zb_StackApsRequest']
PATHS = ['src/zb/aps/aps.h', 'src/zb/nwk/nwk.h', 'src/zb/security.h', 'src/zb/mac/mac.h']


def build():
    return memrxframe.draw('MEMORY: ONE FRAME SENT',
                           'a full frame going down from Zb_StackApsRequest to the MAC, every buffer it '
                           'is copied into', '4.1', 'the payload sent')


if __name__ == '__main__':
    sys.exit(figure.main('memtxframe', build, paths=PATHS, symbols=SYMBOLS))
