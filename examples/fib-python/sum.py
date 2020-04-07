#!/usr/bin/env python3
import sys

with open(sys.argv[1], 'r') as f:
    x = int(f.read().strip())

with open(sys.argv[2], 'r') as f:
    y = int(f.read().strip())

with open(sys.argv[3], 'w') as f:
    f.write(str(x + y) + '\n')
