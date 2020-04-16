#!/usr/bin/env python3.7
# ARGS: fib 5
# RESULT: 5
import pygg
import subprocess as sub

@pygg.thunk_fn()
def fib(gg: pygg.GG, n: int) -> pygg.Output:
    if n < 2:
        return gg.str_value(str(n))
    else:
        a = gg.thunk(fib, [n - 1])
        b = gg.thunk(fib, [n - 2])
        return gg.thunk(add_str, [a, b])

pygg.install("add_str")

@pygg.thunk_fn()
def add_str(gg: pygg.GG, a: pygg.Value, b: pygg.Value) -> pygg.Output:
    ap = a.path()
    bp = b.path()
    assert ap is not None
    assert bp is not None
    sub.check_call([gg.bin("add_str").path(), ap, bp])
    return gg.file_value("out")


pygg.main()
