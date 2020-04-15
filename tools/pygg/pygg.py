#! /usr/bin/env python3.7

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
    Sequence,
    NoReturn,
    Tuple,
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


def unreachable() -> NoReturn:
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
    _hash: Optional[Hash]
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


Prim = Union[str, int, float]
GG_PRIM_TYS = [str, int, float]

FormalArg = Union[Prim, Value]
FORMAL_ARG_TYS = [str, int, float, Value]

ActualArg = Union[Prim, Value, "Thunk"]
ACTUAL_ARG_TYS = [str, int, float, Value, "Thunk", "ThunkOutput"]

Output = Union[Value, "Thunk"]
MultiOutput = Union[Value, "Thunk", Dict[str, Union["Thunk", Value]]]


class ThunkFn(NamedTuple):
    f: Callable[..., MultiOutput]
    outputs: Optional[Callable[..., List[str]]]
    bins: List[str] = []

    def sig(self) -> inspect.FullArgSpec:
        return inspect.getfullargspec(self.f)

    def named_outputs(self, gg: "GG", args: List[ActualArg]) -> Optional[List[str]]:
        if self.outputs is not None:
            op = self.outputs(gg, *args)
            if len(op) == 0:
                raise ValueError(
                    f"The output profile {self.outputs.__name__} returned an empty list. Thunks must have at least one output.\nReturn:\n\t{op}"
                )
            return op
        return None

    def _check(self) -> None:
        def ty_sig(s: inspect.FullArgSpec) -> List[type]:
            return [s.annotations[fa] for fa in s.args]

        """ Check signature agreement """

        def e(m: str) -> NoReturn:
            raise ValueError(f"ThunkFn consistency: {m}")

        f_sig = ty_sig(self.sig())
        if self.outputs is None:
            return
        o_sig = inspect.getfullargspec(self.outputs)
        o_args = ty_sig(o_sig)
        if f_sig != o_args:
            e(
                f"The functions {self.f.__name__} and {self.outputs.__name__} should take the same arguments, since the latter is an output profile function for the former, but\n\t{f_sig}\nis not equal to\n\t{o_args}\n"
            )
        if (
            "return" not in o_sig.annotations
            or o_sig.annotations["return"] != List[str]
        ):
            e(f"The output profile, {self.outputs.__name__} must return a List[str]")


def arg_decode(gg: "GG", arg: str, ex_type: type) -> FormalArg:
    """ Interprets the thunk argument `arg` as `ex_type`.
    For primitives, this is just a parse.
    For a value, this interprets `arg` as a path """
    if ex_type in GG_PRIM_TYS:
        return ex_type(arg)
    elif ex_type == Value:
        return Value(gg, arg, None, None, True)
    else:
        raise ValueError(
            f"prim_dec: Unacceptable type {ex_type}. Acceptable types: {FORMAL_ARG_TYS}"
        )


class Thunk:
    gg: "GG"
    f: ThunkFn
    args: List[ActualArg]
    executable: bool

    @classmethod
    def from_pgm_args(cls, gg: "GG", f: ThunkFn, str_args: List[str]) -> "Thunk":
        tys = f.f.__annotations__
        fargs = f.sig().args
        args = []
        for farg, str_arg in zip(fargs[1:], str_args):
            ex_type = tys[farg]
            args.append(arg_decode(gg, str_arg, ex_type))
        return cls(f, args, gg)

    def __init__(self, f: ThunkFn, args: Sequence[ActualArg], gg: "GG"):
        self.f = f  # type: ignore
        self.args = []
        self.executable = True
        self.gg = gg
        n = f.f.__name__

        def e(msg: str, note: Optional[str] = None) -> NoReturn:
            inv = f"{n}({', '.join(str(a) for a in args)})"
            m = f"Since\n\t{msg}\n, the thunk invocation\n\t{inv}\nis invalid\n"
            if note is not None:
                m += f"\nNote: {note}\n"
            raise ValueError(m)

        if n not in GG_STATE.thunk_functions:
            e(f"{n} is not a registered thunk function")
        if not isinstance(args, list):
            e(f"{args} is not a list")
        fargs = f.sig().args
        tys = f.f.__annotations__
        if len(fargs) != 1 + len(args):
            e(f"The number of arguments is incorrect")
        for farg, arg in zip(fargs[1:], args):
            ex_type = tys[farg]
            if not isinstance(arg, ex_type):
                if (
                    isinstance(arg, Thunk) or isinstance(arg, ThunkOutput)
                ) and ex_type == Value:
                    self.executable = False
                else:
                    e(
                        f"The actual argument {arg} should have type {tys[farg]} but has type {type(arg)}"
                    )
            self.args.append(arg)

    def exec(self, gg: "GG") -> MultiOutput:
        assert self.executable
        return self.f.f(gg, *self.args)

    def __repr__(self) -> str:
        return f"Thunk {pprint.pformat(self.__dict__)}"

    def default_output(self) -> "ThunkOutput":
        return ThunkOutput(thunk=self, filename=None)

    def __getitem__(self, filename: str) -> "ThunkOutput":
        op = self.f.named_outputs(self.gg, self.args)
        if op is not None and op[0] == filename:
            return ThunkOutput(thunk=self, filename=None)
        else:
            return ThunkOutput(thunk=self, filename=filename)


class ThunkOutput(NamedTuple):
    thunk: Thunk
    # If there is no filename, this is the default output
    filename: Optional[str]


def hash_deref(h: Hash) -> str:
    return "@{GGHASH:%s}" % h


def hash_tag(h: Hash, filename: Optional[str]) -> str:
    return h if filename is None else f"{h}#{filename}"


def prim_enc(prim: Prim) -> str:
    t = type(prim)
    if t not in GG_PRIM_TYS:
        raise ValueError(
            f"prim_end: Unacceptable type {t}. Acceptable types: {GG_PRIM_TYS}"
        )
    return str(prim)


class GG:
    lib: Value
    script: Value
    bins: Dict[str, Value]

    def __init__(
            self, lib: Value, script: Value, bins: Dict[str, Value]
    ):
        self.lib = lib
        self.script = script
        self.bins = bins

    def hash_file(self, path: str) -> Hash:
        return (
            sub.check_output([unwrap(self.bin("gg-hash-static").path()), path]).decode().strip()
        )

    def str_value(self, string: str) -> Value:
        return self.bytes_value(string.encode())

    def bytes_value(self, bytes_: bytes) -> Value:
        return Value(self, None, None, bytes_, False)

    def file_value(self, path: str, saved: bool = False) -> Value:
        return Value(self, path, None, None, saved)

    def thunk(self, f: ThunkFn, args: List[ActualArg]) -> Thunk:
        return Thunk(f, args, self)

    def _save_output(
        self, output: MultiOutput, dest_path: Optional[str] = None
    ) -> None:
        if isinstance(output, dict):
            for name, t in output.items():
                if not isinstance(name, str):
                    raise ValueError(f"The key {name} of {output} is not a string")
                self._save(t, name)
        else:
            self._save(output, dest_path)

    def _save(self, term: ActualArg, dest_path: Optional[str] = None) -> Hash:
        def e(msg: str) -> NoReturn:
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
        elif isinstance(term, ThunkOutput):
            return hash_tag(self.save_thunk(term.thunk, dest_path), term.filename)
        else:
            e(f"Unknown type {type(term)}")

    def bin(self, name: str) -> Value:
        if name not in self.bins:
            raise ValueError(f"Unknown bin: {name}")
        return self.bins[name]

    def _save_bytes(self, data: bytes, dest_path: Optional[str]) -> Hash:
        raise Exception("NYI")

    def _save_path(self, path: str, dest_path: Optional[str]) -> Hash:
        raise Exception("NYI")

    def _thunk_location_args(self, dest_path: Optional[str]) -> List[str]:
        raise Exception("NYI")

    def save_thunk(self, t: Thunk, dest_path: Optional[str]) -> Hash:
        name = t.f.f.__name__

        def e(msg: str) -> NoReturn:
            raise ValueError(f"save_thunk: `{name}`: {msg}")

        bin_hashes = []
        for bin_name in GG_STATE.bins:
            if bin_name not in self.bins:
                e(f"The binary {bin_name} is unknown")
            bin_hashes.append(self.bins[bin_name].hash())

        cmd = [
            os.path.basename(script_path),
            hash_deref(self.lib.hash()),
            "exec",
            name,
        ] + list(map(hash_deref, bin_hashes))
        executables = [
            self.script.hash(),
        ] + bin_hashes
        thunks = []
        values = [
            self.lib.hash(),
        ]
        fparams = t.f.sig().args
        if len(t.args) + 1 != len(fparams):
            e("The number of formal and actual params are not equal")
        for fp, ap in zip(fparams[1:], t.args):
            ex_type = t.f.f.__annotations__[fp]
            if ex_type in GG_PRIM_TYS:
                cmd.append(prim_enc(ap))  # type: ignore
            elif ex_type == Value:
                h = self._save(ap)
                cmd.append(hash_deref(h))
                if isinstance(ap, Value):
                    values.append(h)
                elif isinstance(ap, Thunk) or isinstance(ap, ThunkOutput):
                    thunks.append(h)
                else:
                    unreachable()
            else:
                unreachable()
        outputs = []
        op = t.f.named_outputs(self, t.args)
        if op is None:
            outputs.append("out")
        else:
            outputs.extend(op)
        outputs += list(f"{i:03d}" for i in range(MAX_FANOUT))
        value_args = it.chain.from_iterable(["--value", v] for v in values)
        thunk_args = it.chain.from_iterable(["--thunk", v] for v in thunks)
        output_args = it.chain.from_iterable(["--output", v] for v in outputs)
        exec_args = it.chain.from_iterable(["--executable", v] for v in executables)
        env_args = ["--envar", "PYTHONDONTWRITEBYTECODE=1"]
        loc_args = self._thunk_location_args(dest_path)
        cmd_args = list(
            it.chain(
                [unwrap(self.bin("gg-create-thunk-static").path())],
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
        result = sub.run(cmd_args, stderr=sub.PIPE, stdout=sub.PIPE,)
        if result.returncode != 0:
            print(
                f"Non-zero return {result.returncode} for command:\n\t{' '.join(cmd_args)}"
            )
            print("STDOUT:", result.stdout.decode(), file=sys.stderr, sep="\n")
            print("STDERR:", result.stderr.decode(), file=sys.stdout, sep="\n")
            sys.exit(1)
        return result.stderr.decode().strip()


class GGWorker(GG):
    nextOutput: int
    nOuputs: int

    def __init__(self, bins: List[Tuple[str,str]]) -> None:
        script = Value(self, script_path, None, None, True)
        lib = Value(self, lib_path, None, None, True)
        bdict = {bin_: Value(self, path, None, None, True) for bin_, path in bins}
        super().__init__(lib, script, bdict)
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

    def __init__(self, bins: List[str]) -> None:
        script = Value(self, script_path, None, None, True)
        lib = Value(self, lib_path, None, None, True)
        bdict = {bin_: Value(self, which(bin_), None, None, True) for bin_ in bins}
        self.init()
        self.collect(unwrap(script.path()))
        self.collect(unwrap(lib.path()))
        for _, bin_value in bdict.items():
            self.collect(unwrap(bin_value.path()))
        super().__init__(lib, script, bdict)

    def collect(self, path: str) -> Hash:
        return sub.check_output([which("gg-collect"), path]).decode().strip()

    def init(self) -> None:
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
    thunk_functions: Dict[str, ThunkFn]
    bins: List[str]


GG_STATE = GGState(thunk_functions={}, bins=[])

REQUIRED_BINS = ["gg-create-thunk-static", "gg-hash-static"]

def thunk_fn(
    outputs: Optional[Callable[..., List[str]]] = None, bins: List[str] = []
) -> Callable[[Callable], ThunkFn]:
    def decorator_thunk_fn(func: Callable) -> ThunkFn:
        def e(msg: str, note: Optional[str] = None) -> NoReturn:
            m = f"In function `{func.__name__}`,\n\t{msg}\n, so `{func.__name__}` cannot be a thunk."
            if note is not None:
                m += f"\n\nNote: {note}"
            raise ValueError(m)

        if "return" not in func.__annotations__:
            e("there is no annotated return")
        ret = func.__annotations__["return"]
        if ret not in [MultiOutput, Output, Value, Thunk]:  # type: ignore
            e("the return is not annotated as a value or thunk")
        if ret == MultiOutput and outputs is None:  # type: ignore
            e("the return is a MultiOutput, but there is no outputs")
        for b in bins:
            install(b)
        tf = ThunkFn(f=func, outputs=outputs, bins=REQUIRED_BINS + bins)
        argspec = tf.sig()
        if argspec.varargs is not None:
            e("there are varargs")
        if argspec.varkw is not None:
            e("there are keyword args")
        if argspec.defaults is not None:
            e("there are default arg values")
        params = argspec.args
        if func.__annotations__[params[0]] != GG:
            e("the first argument is not a GG")

        for p in params[1:]:
            if p not in func.__annotations__:
                e(f"the parameter `{p}` is not annotated")
            if func.__annotations__[p] not in [str, Value, int, float]:
                e(
                    f"the parameter `{p}` has unacceptable type",
                    "the acceptable types are: [str, Value, int, float]",
                )
        name = func.__name__
        assert name not in GG_STATE.thunk_functions
        GG_STATE.thunk_functions[name] = tf
        tf._check()
        return tf

    return decorator_thunk_fn


def install(bin_: str) -> None:
    if bin_ not in GG_STATE.bins:
        GG_STATE.bins.append(bin_)


def gg_root(args: List[str]) -> None:
    gg = GGCoordinator(GG_STATE.bins)

    def e(msg: str) -> NoReturn:
        raise ValueError(f"gg_root: {msg}")

    if len(args) == 0:
        e("Must include the thunk name")
    if args[0] not in GG_STATE.thunk_functions:
        e(f"`{args[0]}` is not a known thunk")
    f = GG_STATE.thunk_functions[args[0]]
    t = Thunk.from_pgm_args(gg, f, args[1:])
    gg._save_output(t, "out")


def gg_exec(args: List[str]) -> None:
    def e(msg: str) -> NoReturn:
        raise ValueError(f"gg_exec: {msg}")

    if len(args) < 1:
        e(
            "There must >= 1 argument (the thunk name)"
        )
    t_name = args[0]
    args = args[1:]
    if t_name not in GG_STATE.thunk_functions:
        e(f"`{t_name}` is not a known thunk")
    f = GG_STATE.thunk_functions[t_name]
    bins = GG_STATE.bins
    if len(args) < len(bins):
        e(
                f"There must be an argument for each required binary:\n\tArgs: {args}\n\tBins: {bins}\n"
        )
    gg = GGWorker(list(zip(bins,args[:len(bins)])))
    args = args[len(bins):]
    t = Thunk.from_pgm_args(gg, f, args)
    result = t.exec(gg)
    gg._save_output(result, "out")
    for path in gg.unused_outputs():
        pathlib.Path(path).touch(exist_ok=False)


def main() -> None:
    def e(msg: str) -> NoReturn:
        raise ValueError(f"pygg: {msg}")

    if not os.access(sys.argv[0], os.X_OK):
        e(f"The script {sys.argv[0]} is not executable. It must be.")
    for b in REQUIRED_BINS:
        install(b)
    if len(sys.argv) < 2:
        e("There must be at least one argument: (init or run)")
    if sys.argv[1] == "init":
        gg_root(sys.argv[2:])
    elif sys.argv[1] == "exec":
        gg_exec(sys.argv[2:])
    else:
        e(f"The first argument must be (init|run), not {sys.argv[1]}")
