#!/usr/bin/env python3
import sys
import os
import shutil
import subprocess as sub

n = int(sys.argv[1].strip())
create_thunk_path = sys.argv[2].strip()

def placeholder(t):
    return '@{GGHASH:%s}' % t

def write_fib_thunk(n, path):
    fib_hash = os.environ['fib_hash']
    sum_hash = os.environ['sum_hash']
    create_thunk_hash = os.environ['create_thunk_hash']
    args = [
        create_thunk_path,
        '--output', 'out',
        '--output', 'out1',
        '--output', 'out2',
        '--executable', fib_hash,
        '--executable', create_thunk_hash,
        '--envar', 'fib_hash=%s' % fib_hash,
        '--envar', 'sum_hash=%s' % sum_hash,
        '--envar', 'create_thunk_hash=%s' % create_thunk_hash,
        '--output-path', path,
        '--',
        fib_hash,
        'fib.py',
        str(n),
        placeholder(create_thunk_hash),
    ]
    r = sub.run(args, check = True, stderr = sub.PIPE)
    return r.stderr.decode().strip()

def write_sum_thunk(a_hash, b_hash, path):
    sum_hash = os.environ['sum_hash']
    args = [
        create_thunk_path,
        '--output', 'out',
        '--executable', sum_hash,
        '--thunk', a_hash,
        '--thunk', b_hash,
        '--output-path', path,
        '--',
        sum_hash,
        'sum.py',
        placeholder(a_hash),
        placeholder(b_hash),
        'out',
    ]
    sub.run(args, check = True, stderr = sub.PIPE)

if n < 2:
    with open('out', 'w') as f:
        f.write(str(n) + '\n')
    for i in range(1, 3):
        with open('out%s' % i, 'w') as f:
            f.write("\n")
else:
    n1_hash = write_fib_thunk(n - 1, 'out1')
    n2_hash = write_fib_thunk(n - 2, 'out2')
    write_sum_thunk(n1_hash, n2_hash, 'out')
