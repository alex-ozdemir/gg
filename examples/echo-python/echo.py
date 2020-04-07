#!/usr/bin/env python3

import sys
with open(sys.argv[1], 'r') as f:
    s = f.read()
    with open(sys.argv[2], 'w') as fout:
        fout.write(s)
    with open(sys.argv[3], 'w') as fout:
        fout.write(s)

