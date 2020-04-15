#! /usr/bin/python3.7
# ARGS: fib 5
# RESULT: 5
# Copied
import os, sys
from importlib.util import spec_from_loader, module_from_spec
from importlib.machinery import SourceFileLoader

if not os.path.exists(sys.argv[1]):
    import pygg
else:
    spec = spec_from_loader("pygg", SourceFileLoader("pygg", os.path.realpath(sys.argv[1])))
    pygg = module_from_spec(spec)
    spec.loader.exec_module(pygg)  # type: ignore
    del sys.argv[1]

# End copy
from typing import List

@pygg.thunk_fn()
def fib(gg: pygg.GG, n: int) -> pygg.Output:
    return gg.thunk(fib_, [gg.str_value(str(n))])

@pygg.thunk_fn()
def fib_(gg: pygg.GG, n: pygg.Value) -> pygg.Output:
    i = int(n.as_str())
    if i < 2:
        return gg.str_value(str(i))
    else:
        s = gg.thunk(split, [n])
        a = gg.thunk(fib_, [s])
        b = gg.thunk(fib_, [s["n2"]])
        return gg.thunk(add_str, [a, b])

def split_outputs(gg: pygg.GG, _n: pygg.Value) -> List[str]:
    return ["n1", "n2"]

@pygg.thunk_fn(outputs = split_outputs)
def split(gg: pygg.GG, n: pygg.Value) -> pygg.MultiOutput:
    i = int(n.as_str())
    return {
        "n1": gg.str_value(str(i - 1)),
        "n2": gg.str_value(str(i - 2)),
    }


@pygg.thunk_fn()
def add_str(gg: pygg.GG, a: pygg.Value, b: pygg.Value) -> pygg.Output:
    ai = int(a.as_str())
    bi = int(b.as_str())
    return gg.str_value(str(ai + bi))


pygg.main()
