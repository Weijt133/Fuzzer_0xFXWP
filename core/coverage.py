#!/usr/bin/env python3
import argparse
import ctypes
import fcntl
import os
import re
import signal
import struct
import subprocess
import threading
import time
import lief
from ctypes import CDLL, Structure, c_long, c_ulonglong, c_uint, c_void_p
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union


PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_POKETEXT = 4
PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13

LIBC = CDLL("libc.so.6", use_errno=True)
WORD_SIZE = struct.calcsize("l")


class user_regs_struct(Structure):
    _fields_ = [
        ("r15", c_ulonglong), ("r14", c_ulonglong), ("r13", c_ulonglong),
        ("r12", c_ulonglong), ("rbp", c_ulonglong), ("rbx", c_ulonglong),
        ("r11", c_ulonglong), ("r10", c_ulonglong), ("r9", c_ulonglong),
        ("r8", c_ulonglong), ("rax", c_ulonglong), ("rcx", c_ulonglong),
        ("rdx", c_ulonglong), ("rsi", c_ulonglong), ("rdi", c_ulonglong),
        ("orig_rax", c_ulonglong), ("rip", c_ulonglong), ("cs", c_ulonglong),
        ("eflags", c_ulonglong), ("rsp", c_ulonglong), ("ss", c_ulonglong),
        ("fs_base", c_ulonglong), ("gs_base", c_ulonglong), ("ds", c_ulonglong),
        ("es", c_ulonglong), ("fs", c_ulonglong), ("gs", c_ulonglong),
    ]


def ptrace(req: int, pid: int, addr=0, data=0) -> int:
    LIBC.ptrace.restype = c_long
    res = LIBC.ptrace(c_uint(req), c_uint(pid), c_void_p(addr), c_void_p(data))
    if res == -1:
        err = ctypes.get_errno()
        raise OSError(err, f"ptrace {req} failed (errno {err})")
    return res


def read_word(pid: int, addr: int) -> int:
    return ptrace(PTRACE_PEEKTEXT, pid, addr, 0)


def write_word(pid: int, addr: int, value: int) -> None:
    ptrace(PTRACE_POKETEXT, pid, addr, value)


def read_byte(pid: int, addr: int) -> int:
    base = addr & ~(WORD_SIZE - 1)
    word = read_word(pid, base)
    shift = (addr - base) * 8
    return (word >> shift) & 0xFF


def write_byte(pid: int, addr: int, byte: int) -> None:
    base = addr & ~(WORD_SIZE - 1)
    word = read_word(pid, base)
    shift = (addr - base) * 8
    mask = ~(0xFF << shift) & (2**64 - 1)
    write_word(pid, base, (word & mask) | (byte << shift))


def get_regs(pid: int) -> user_regs_struct:
    regs = user_regs_struct()
    ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
    return regs


def set_regs(pid: int, regs: user_regs_struct) -> None:
    ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))


class BreakpointManager:

    def __init__(self, pid: int):
        self.pid = pid
        self.saved: Dict[int, int] = {}
        self.offsets: Dict[int, set] = {}

    def _aligned(self, addr: int) -> Tuple[int, int]:
        base = addr & ~(WORD_SIZE - 1)
        shift = (addr - base) * 8
        return base, shift

    def _write(self, base: int) -> None:
        word = self.saved[base]
        for shift in self.offsets.get(base, set()):
            word = (word & ~(0xFF << shift)) | (0xCC << shift)
        write_word(self.pid, base, word)

    def enable(self, addr: int) -> None:
        base, shift = self._aligned(addr)
        if base not in self.saved:
            self.saved[base] = read_word(self.pid, base)
        self.offsets.setdefault(base, set()).add(shift)
        self._write(base)

    def disable(self, addr: int) -> None:
        base, shift = self._aligned(addr)
        if shift in self.offsets.get(base, set()):
            self.offsets[base].remove(shift)
            if not self.offsets[base]:
                del self.offsets[base]
        self._write(base)


class Coverage:
    func_re = re.compile(r"^([0-9a-f]+) <([^>]+)>:$")
    insn_re = re.compile(
        r"^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+([a-z.]+)(?:\s+([0-9a-fx]+) <)?"
    )

    def __init__(self, target: str, args: Optional[List[str]] = None):
        self.binary = os.path.realpath(target)
        self.argv = [self.binary] + (args or [])
        self.blocks: Dict[int, str] = {}

    @staticmethod
    def _coerce_stdin(payload: Optional[Union[str, bytes]]) -> Optional[bytes]:
        if payload is None:
            return None
        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, bytearray):
            return bytes(payload)
        if isinstance(payload, str):
            return payload.encode()
        raise TypeError("stdin_data must be bytes, bytearray, str or None")

    @staticmethod
    def _start_stdin_writer(fd: int, data: bytes) -> threading.Thread:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        def _pump() -> None:
            view = memoryview(data)
            try:
                while len(view):
                    try:
                        written = os.write(fd, view)
                        view = view[written:]
                    except BlockingIOError:
                        time.sleep(0.001)
            except BrokenPipeError:
                pass
            finally:
                os.close(fd)

        writer = threading.Thread(target=_pump, daemon=True)
        writer.start()
        return writer


    def discover(self):
        disasm = subprocess.check_output(["objdump", "-d", self.binary], text=True)
        functions: Dict[str, List[Tuple[int, str, Optional[int], bool]]] = {}
        cur: Optional[str] = None

        for line in disasm.splitlines():
            fm = self.func_re.match(line)
            if fm:
                cur = fm.group(2)
                functions[cur] = []
                continue
            if not cur:
                continue
            im = self.insn_re.match(line)
            if not im:
                continue
            addr = int(im.group(1), 16)
            mnem = im.group(2)
            tgt = im.group(3)
            target = int(tgt, 16) if tgt else None
            is_jump = mnem.startswith("j")
            is_uncond = mnem in {"jmp", "jmpq"}
            functions[cur].append((addr, mnem, target, is_jump and not is_uncond))

        blocks: Dict[int, str] = {}
        for name, insns in functions.items():
            if not insns or name.endswith("@plt"):
                continue
            blocks[insns[0][0]] = name
            for idx, (addr, mnem, target, is_cond) in enumerate(insns):
                if mnem.startswith("j"):
                    if target is not None:
                        blocks[target] = name
                    if is_cond and idx + 1 < len(insns):
                        blocks[insns[idx + 1][0]] = name
        if not blocks:
            raise RuntimeError("No blocks found")
        self.blocks = blocks
        return blocks

    def _load_bias(self, pid, imagebase):
        real = self.binary
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 6:
                    continue
                path = os.path.realpath(parts[-1])
                if path != real:
                    continue
                start = int(parts[0].split("-")[0], 16)
                return start - imagebase
        return 0

    def run(self, stdin_data = None, test = None):
            
        imagebase = lief.parse(self.binary).imagebase

        rfd, wfd = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(wfd)
                os.dup2(rfd, 0) 
                os.close(rfd)
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, 1)
                os.dup2(devnull, 2)
                os.close(devnull)
                ptrace(PTRACE_TRACEME, 0, 0, 0)
                os.execv(self.binary, self.argv)
            except Exception as exc:
                print(f"[child error] {exc}", flush=True)
            os._exit(1)

        wpid, status = os.waitpid(pid, 0)
        if wpid != pid or os.WIFEXITED(status) or os.WIFSIGNALED(status):
            raise RuntimeError("tracee died early")

        os.close(rfd)

        bias = self._load_bias(pid, imagebase)
        runtime_blocks = {addr + bias: name for addr, name in self.blocks.items()}
        counters = {addr: 0 for addr in runtime_blocks}
        bps = BreakpointManager(pid)
        for addr in runtime_blocks:
            bps.enable(addr)

        writer_thread: Optional[threading.Thread] = None
        payload = self._coerce_stdin(stdin_data)
        if payload:
            writer_thread = self._start_stdin_writer(wfd, payload)
        else:
            os.close(wfd)

        ptrace(PTRACE_CONT, pid, 0, 0)

        while True:
            wpid, status = os.waitpid(pid, 0)
            if wpid != pid:
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                break
            if not os.WIFSTOPPED(status):
                continue

            sig = os.WSTOPSIG(status)
            if sig != signal.SIGTRAP:
                ptrace(PTRACE_CONT, pid, 0, sig)
                continue

            regs = get_regs(pid)
            hit = regs.rip - 1
            if hit not in runtime_blocks:
                ptrace(PTRACE_CONT, pid, 0, 0)
                continue

            counters[hit] += 1
            bps.disable(hit)
            regs.rip = hit
            set_regs(pid, regs)

            ptrace(PTRACE_SINGLESTEP, pid, 0, 0)
            wpid2, st2 = os.waitpid(pid, 0)
            if wpid2 != pid or os.WIFEXITED(st2) or os.WIFSIGNALED(st2):
                break

            ptrace(PTRACE_CONT, pid, 0, 0)

        if writer_thread:
            writer_thread.join()

        if test:
            return counters, runtime_blocks, bias

        total_blocks = len(runtime_blocks)
        covered_blocks = sum(1 for hits in counters.values() if hits > 0)
        coverage = covered_blocks / total_blocks if total_blocks else 0.0
        return coverage



if __name__ == "__main__":

    cov = Coverage('./test/binaries/csv1')
    blocks = cov.discover()
    print(f"[+] Instrumenting {len(blocks)} basic blocks", flush=True)
    inputs = [b'123',b'456']
    results = cov.run(inputs[0], test=True) if len(inputs) == 1 else [cov.run(inp, test=True) for inp in inputs]
    
    for counters, runtime_blocks, bias in results:
        print(f"[+] Bias: {bias:#x}")
        covered_blocks = sum(1 for hits in counters.values() if hits > 0)
        total_blocks = len(runtime_blocks)
        coverage = covered_blocks / total_blocks if total_blocks else 0.0
        print(f"[+] Coverage: {coverage:.2%}")
