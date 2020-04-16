#!/usr/bin/env python3.7
# ARGS: trib 5
# RESULT: 11
import pygg

@pygg.thunk_fn()
def trib(gg: pygg.GG, n: int) -> pygg.Output:
    if n < 3:
        return gg.str_value(str(n))
    else:
        a = gg.thunk(trib, [n - 1])
        b = gg.thunk(trib, [n - 2])
        c = gg.thunk(trib, [n - 3])
        return gg.thunk(add_str, [gg.thunk(add_str, [a, b]), c])


@pygg.thunk_fn()
def add_str(gg: pygg.GG, a: pygg.Value, b: pygg.Value) -> pygg.Output:
    ai = int(a.as_str())
    bi = int(b.as_str())
    return gg.str_value(str(ai + bi))


pygg.main()
