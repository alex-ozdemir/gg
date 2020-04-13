#! /usr/bin/python3.7
import os, sys
from importlib.util import spec_from_loader, module_from_spec
from importlib.machinery import SourceFileLoader

if not os.path.exists(sys.argv[1]):
    import pygg
else:
    spec = spec_from_loader(
        "pygg", SourceFileLoader("pygg", os.path.realpath(sys.argv[1]))
    )
    pygg = module_from_spec(spec)
    spec.loader.exec_module(pygg) # type: ignore
    del sys.argv[1]


@pygg.thunk_fn
def fib(gg: pygg.GG, n: int) -> pygg.Term:
    if n < 2:
        return gg.str_value(str(n))
    else:
        a = gg.thunk(fib, [n - 1])
        b = gg.thunk(fib, [n - 2])
        return gg.thunk(add_str, [a, b])


@pygg.thunk_fn
def add_str(gg: pygg.GG, a: pygg.Value, b: pygg.Value) -> pygg.Term:
    ai = int(a.as_str())
    bi = int(b.as_str())
    return gg.str_value(str(ai + bi))


pygg.main()
