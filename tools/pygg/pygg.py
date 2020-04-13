#! /usr/bin/python3.7

from typing import (
    Union,
    List,
    Optional,
    Callable,
    NamedTuple,
    Dict,
    Iterable,
    BinaryIO,
    TypeVar,
)
import subprocess as sub
import shutil as sh
import hashlib
import base64
import sys
import pprint
import os
import inspect
import functools as ft
import pathlib
import tempfile
import itertools as it

MAX_FANOUT = 10

Hash = str

script_path = os.path.realpath(sys.argv[0])
lib_path = os.path.realpath(__file__)

T = TypeVar("T")


def unwrap(t: Optional[T]) -> T:
    if t is None:
        raise ValueError("Unwrapped empty Optional")
    return t


def unreachable():
    raise Exception("This location should be unreachable")


def which(cmd: str) -> str:
    t = sh.which(cmd)
    if t is None:
        raise ValueError(f"which: {cmd} is not present/executable")
    return t


def gg_hash(data: bytes, tag: str) -> Hash:
    sha = hashlib.sha256()
    sha.update(data)
    h = (
        base64.urlsafe_b64encode(sha.digest())
        .decode("ascii")
        .replace("-", ".")
        .rstrip("=")
    )
    return f"{tag}{h}{len(data):08x}"


class Value:
    _gg: "GG"
    _path: Optional[str]
    _hash: Optional[str]
    _bytes: Optional[bytes]
    saved: bool

    def __init__(
        self,
        gg: "GG",
        path: Optional[str],
        hash_: Optional[str],
        bytes_: Optional[bytes],
        saved: bool,
    ):
        self._gg = gg
        self._path = path
        self._hash = hash_
        self._bytes = bytes_
        self.saved = saved

    def as_bytes(self) -> bytes:
        if self._bytes is None:
            assert self._path is not None, "No bytes nor path for this value..."
            with open(self._path, "rb") as f:
                self._bytes = f.read()
        return self._bytes

    def as_str(self) -> str:
        return self.as_bytes().decode()

    def path(self) -> Optional[str]:
        return self._path

    def hash(self) -> str:
        if self._hash is None:
            if self._path is not None:
                self._hash = self._gg.hash_file(self._path)
            else:
                assert (
                    self._bytes is not None
                ), "No bytes nor hash nor path for this value..."
                self._hash = gg_hash(self._bytes, "V")
        return self._hash

    def force(self, gg) -> "Value":
        return self

    def _check(self):
        """ Invariant that must always be satisfied """
        assert (
            self.path is not None or self._bytes is not None or self._hash is not None
        )


GG_TERM_TYS = ["Thunk", Value]
Term = Union["Thunk", Value]

GG_PRIM_TYS = [str, int, float]
Prim = Union[str, int, float]

Arg = Union["Thunk", Value, str, int, float]


class Thunk:
    f: Callable
    args: List  # TODO: articulate
    executable: bool

    def __init__(self, f: Callable, args: List, dec_from_str: bool, gg: "GG"):
        self.f = f  # type: ignore
        self.args = []
        self.executable = True
        n = f.__name__

        def e(msg: str, note: Optional[str] = None):
            inv = f"{n}({', '.join(str(a) for a in args)})"
            m = f"Since\n\t{msg}\n, the thunk invocation\n\t{inv}\nis invalid\n"
            if note is not None:
                m += f"\nNote: {note}\n"
            raise ValueError(m)

        if n not in GG_STATE.thunk_functions:
            raise e(f"{n} is not a registered thunk function")
        fargs = inspect.getfullargspec(f).args
        tys = f.__annotations__
        if len(fargs) != 1 + len(args):
            raise e(f"The number of arguments is incorrect")
        for farg, arg in zip(fargs[1:], args):
            ex_type = tys[farg]
            if dec_from_str and type(arg) in GG_PRIM_TYS:
                if ex_type == Value and isinstance(arg, str):
                    arg = Value(gg, arg, None, None, True)
                else:
                    arg = prim_dec(arg, ex_type)
            if type(arg) != ex_type:
                if isinstance(arg, Thunk) and ex_type == Value:
                    self.executable = False
                else:
                    raise e(
                        f"The actual argument {arg} should have type {tys[farg]} but has type {type(arg)}"
                    )
            self.args.append(arg)

    def exec(self, gg: "GG") -> Term:
        assert self.executable
        return self.f(gg, *self.args)

    def force(self, gg: "GG") -> Value:
        args = []
        for a in self.args:
            while isinstance(a, Thunk):
                a = a.force(gg)
            args.append(a)
        return self.f(gg, *args)

    def __repr__(self):
        return f"Thunk {pprint.pformat(self.__dict__)}"


def gg_arg_placeholder(h: Hash) -> str:
    return "@{GGHASH:%s}" % h


def prim_enc(prim: Prim) -> str:
    t = type(prim)
    if t not in GG_PRIM_TYS:
        raise ValueError(
            f"prim_end: Unacceptable type {t}. Acceptable types: {GG_PRIM_TYS}"
        )
    return str(prim)


def prim_dec(data: str, ex_type: type) -> Prim:
    if ex_type not in GG_PRIM_TYS:
        raise ValueError(
            f"prim_dec: Unacceptable type {ex_type}. Acceptable types: {GG_PRIM_TYS}"
        )
    return ex_type(data)


class GG:
    lib: Value
    script: Value
    gg_hash_bin: Value
    gg_create_thunk_bin: Value

    def __init__(
        self, lib: Value, script: Value, gg_create_thunk_bin: Value, gg_hash_bin: Value
    ):
        self.lib = lib
        self.script = script
        self.gg_create_thunk_bin = gg_create_thunk_bin
        self.gg_hash_bin = gg_hash_bin

    def hash_file(self, path: str) -> Hash:
        return (
            sub.check_output([unwrap(self.gg_hash_bin.path()), path]).decode().strip()
        )

    def str_value(self, string: str) -> Value:
        return self.bytes_value(string.encode())

    def bytes_value(self, bytes_: bytes) -> Value:
        return Value(self, None, None, bytes_, False)

    def file_value(self, path: str, saved: bool = False) -> Value:
        return Value(self, path, None, None, saved)

    def thunk(self, f: Callable, args: List) -> "Thunk":
        return Thunk(f, args, False, self)

    def save(self, term: Term, dest_path: Optional[str] = None) -> Hash:
        def e(msg: str):
            raise ValueError(f"save: {msg}")

        if isinstance(term, Value):
            p = term.path()
            if term.saved:
                return term.hash()
            if p is None:
                ret = self._save_bytes(term.as_bytes(), dest_path)
            else:
                ret = self._save_path(p, dest_path)
            term.saved = True
            return ret
        elif isinstance(term, Thunk):
            return self.save_thunk(term, dest_path)
        else:
            raise e(f"Unknown type {type(term)}")

    def _save_bytes(self, data: bytes, dest_path: Optional[str]) -> Hash:
        raise Exception("NYI")

    def _save_path(self, path: str, dest_path: Optional[str]) -> Hash:
        raise Exception("NYI")

    def _thunk_location_args(self, dest_path: Optional[str]) -> List[str]:
        raise Exception("NYI")

    def save_thunk(self, t: Thunk, dest_path: Optional[str]) -> Hash:
        f = t.f
        name = f.__name__
        args = t.args

        def e(msg: str):
            raise ValueError(f"save_thunk: `{name}`: {msg}")

        cmd = [
            os.path.basename(script_path),
            gg_arg_placeholder(self.lib.hash()),
            "exec",
            gg_arg_placeholder(self.gg_create_thunk_bin.hash()),
            gg_arg_placeholder(self.gg_hash_bin.hash()),
            name,
        ]
        executables = [
            self.script.hash(),
            self.gg_create_thunk_bin.hash(),
            self.gg_hash_bin.hash(),
        ]
        thunks = []
        values = [
            self.lib.hash(),
        ]
        fparams = inspect.getfullargspec(f).args
        if len(args) + 1 != len(fparams):
            raise e("The number of formal and actual params are not equal")
        for fp, ap in zip(fparams[1:], args):
            ex_type = f.__annotations__[fp]
            if ex_type in GG_PRIM_TYS:
                cmd.append(prim_enc(ap))  # type: ignore
            elif ex_type == Value:
                h = self.save(ap)
                cmd.append(gg_arg_placeholder(h))
                if isinstance(ap, Value):
                    values.append(h)
                elif isinstance(ap, Thunk):
                    thunks.append(h)
                else:
                    unreachable()
            else:
                unreachable()
        outputs = ["out"] + list(f"{i:03d}" for i in range(MAX_FANOUT))
        value_args = it.chain.from_iterable(["--value", v] for v in values)
        thunk_args = it.chain.from_iterable(["--thunk", v] for v in thunks)
        output_args = it.chain.from_iterable(["--output", v] for v in outputs)
        exec_args = it.chain.from_iterable(["--executable", v] for v in executables)
        env_args = ["--envar", "PYTHONDONTWRITEBYTECODE=1"]
        loc_args = self._thunk_location_args(dest_path)
        args = list(
            it.chain(
                [unwrap(self.gg_create_thunk_bin.path())],
                value_args,
                thunk_args,
                output_args,
                exec_args,
                loc_args,
                env_args,
                ["--", self.script.hash()],
                cmd,
            )
        )
        result = sub.run(args, stderr=sub.PIPE, stdout=sub.PIPE,)
        if result.returncode != 0:
            print(
                f"Non-zero return {result.returncode} for command:\n\t{' '.join(args)}"
            )
            print("STDOUT:", result.stdout.decode(), file=sys.stderr, sep="\n")
            print("STDERR:", result.stderr.decode(), file=sys.stdout, sep="\n")
            sys.exit(1)
        return result.stderr.decode().strip()


class GGWorker(GG):
    nextOutput: int
    nOuputs: int

    def __init__(self, gg_create_thunk_bin: str, gg_hash_bin: str):
        script = Value(self, script_path, None, None, True)
        lib = Value(self, lib_path, None, None, True)
        a = Value(self, gg_create_thunk_bin, None, None, True)
        b = Value(self, gg_hash_bin, None, None, True)
        super().__init__(lib, script, a, b)
        self.nextOutput = 0
        self.nOuputs = MAX_FANOUT

    def _next_output_file(self) -> str:
        self.nextOutput += 1
        assert self.nextOutput <= self.nOuputs
        return f"{self.nextOutput - 1:03d}"

    def _save_bytes(self, data: bytes, dest_path: Optional[str]) -> Hash:
        if dest_path is None:
            dest_path = self._next_output_file()
        f = open(dest_path, "wb")
        f.write(data)
        f.close()
        return self.hash_file(dest_path)

    def _save_path(self, path: str, dest_path: Optional[str]) -> Hash:
        if dest_path is None:
            dest_path = self._next_output_file()
        sh.move(path, dest_path)
        return self.hash_file(dest_path)

    def _thunk_location_args(self, dest_path: Optional[str]) -> List[str]:
        if dest_path is None:
            dest_path = self._next_output_file()
        return ["--output-path", dest_path]

    def unused_outputs(self) -> Iterable[str]:
        return (f"{i:03}" for i in range(self.nextOutput, self.nOuputs))


class GGCoordinator(GG):
    def __init__(self):
        script = Value(self, script_path, None, None, True)
        lib = Value(self, lib_path, None, None, True)
        a = Value(self, which("gg-create-thunk-static"), None, None, True)
        b = Value(self, which("gg-hash-static"), None, None, True)
        self.init()
        self.collect(script.path())
        self.collect(lib.path())
        self.collect(a.path())
        self.collect(b.path())
        super().__init__(lib, script, a, b)

    def collect(self, path: str) -> Hash:
        return sub.check_output([which("gg-collect"), path]).decode().strip()

    def init(self):
        sub.check_call(["rm -rf .gg",], shell=True)
        sub.check_call([which("gg-init")])

    def _save_bytes(self, data: bytes, dest_path: Optional[str]) -> Hash:
        if dest_path is None:
            f = tempfile.NamedTemporaryFile(mode="wb")
        else:
            f = open(dest_path, "wb")
        f.write(data)
        a = self.collect(f.name)
        f.close()
        return a

    def _save_path(self, path: str, dest_path: Optional[str]) -> Hash:
        if dest_path is not None:
            sh.copy(path, dest_path)
            path = dest_path
        return self.collect(path)

    def _thunk_location_args(self, dest_path: Optional[str]) -> List[str]:
        if dest_path is None:
            return []
        else:
            return ["--placeholder", dest_path]


class GGState(NamedTuple):
    thunk_functions: Dict[str, Callable]


GG_STATE = GGState({})


def thunk_fn(func):
    def e(msg: str, note: Optional[str] = None):
        m = f"In function `{func.__name__}`,\n\t{msg}\n, so `{func.__name__}` cannot be a thunk."
        if note is not None:
            m += f"\n\nNote: {note}"
        raise ValueError(m)

    if "return" not in func.__annotations__:
        raise e("there is no annotated return")
    ret = func.__annotations__["return"]
    if ret not in [Term, Value, Thunk]:  # type: ignore
        raise e("the return is not annotated as a value or thunk")
    argspec = inspect.getfullargspec(func)
    if argspec.varargs is not None:
        raise e("there are varargs")
    if argspec.varkw is not None:
        raise e("there are keyword args")
    if argspec.defaults is not None:
        raise e("there are default arg values")
    params = argspec.args
    if func.__annotations__[params[0]] != GG:
        raise e("the first argument is not a GG")

    for p in params[1:]:
        if p not in func.__annotations__:
            raise e(f"the parameter `{p}` is not annotated")
        if func.__annotations__[p] not in [str, Value, int, float]:
            raise e(
                f"the parameter `{p}` has unacceptable type",
                "the acceptable types are: [str, Value, int, float]",
            )
    name = func.__name__
    assert name not in GG_STATE.thunk_functions
    GG_STATE.thunk_functions[name] = func
    return func


def gg_root(args: List[str]):
    gg = GGCoordinator()

    def e(msg: str):
        raise ValueError(f"gg_root: {msg}")

    if len(args) == 0:
        raise e("Must include the thunk name")
    if args[0] not in GG_STATE.thunk_functions:
        raise e(f"`{args[0]}` is not a known thunk")
    f = GG_STATE.thunk_functions[args[0]]
    t = Thunk(f, args[1:], True, gg)
    gg.save(t, "out")


def gg_exec(args: List[str]):
    def e(msg: str):
        raise ValueError(f"gg_exec: {msg}")

    if len(args) < 3:
        raise e(
            "There must be at least 3 argumets (gg-create-thunk, gg-hash, and the thunk name"
        )
    gg = GGWorker(args[0], args[1])
    t_name = args[2]
    if t_name not in GG_STATE.thunk_functions:
        raise e(f"`{t_name}` is not a known thunk")
    f = GG_STATE.thunk_functions[t_name]
    t = Thunk(f, args[3:], True, gg)
    result = t.exec(gg)
    gg.save(result, "out")
    for path in gg.unused_outputs():
        pathlib.Path(path).touch(exist_ok=False)


def main():
    def e(msg: str):
        raise ValueError(f"pygg: {msg}")

    if len(sys.argv) < 2:
        raise e("There must be at least one argument: (init or run)")
    if sys.argv[1] == "init":
        gg_root(sys.argv[2:])
    elif sys.argv[1] == "exec":
        gg_exec(sys.argv[2:])
    else:
        raise e(f"The first argument must be (init|run), not {sys.argv[1]}")
