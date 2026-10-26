"""Agents that attach to `Sim.serve()` over the real pipe / Unix socket.

`PipeAgent` is a minimal agent in Python, so a script can exercise the served
endpoint (and the tee) without Go. `start_kext_tester` launches the Go test
agent against it.
"""
from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

from ._native import Event, EventStream, verdict_command

# The repository root when running from a checkout (sim/python/zfsim/agents.py).
REPO = Path(__file__).resolve().parents[3]


def _connect(endpoint: str, timeout: float) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        try:
            if sys.platform == "win32":
                return open(endpoint, "r+b", buffering=0)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(endpoint)
            return sock
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


class PipeAgent:
    """Connects to `endpoint` (as returned by `Sim.serve()`) and answers every
    event with `policy(event)` on a background thread; a returned verdict is
    sent back for `"connection"` events. Events it saw are in `events`. Ends
    when the sim closes the endpoint or on `stop()`; `join()` re-raises a
    `policy` exception."""

    def __init__(
        self,
        endpoint: str,
        policy: Callable[[Event], int | None] = lambda event: None,
        timeout: float = 5.0,
    ) -> None:
        self.events: list[Event] = []
        self._policy = policy
        self._error: Exception | None = None
        self._conn = _connect(endpoint, timeout)
        self._thread = threading.Thread(target=self._run, name="PipeAgent", daemon=True)
        self._thread.start()

    def _read(self) -> bytes:
        if sys.platform == "win32":
            return self._conn.read(4096)
        return self._conn.recv(4096)

    def _write(self, command: bytes) -> None:
        # One write is one command message on the Windows message pipe; the
        # Unix socket is a stream, so commands carry a u32 length prefix there.
        if sys.platform == "win32":
            self._conn.write(command)
        else:
            self._conn.sendall(struct.pack("<I", len(command)) + command)

    def _run(self) -> None:
        stream = EventStream()
        try:
            while True:
                try:
                    data = self._read()
                except OSError:
                    break
                if not data:
                    break
                for event in stream.feed(data):
                    self.events.append(event)
                    verdict = self._policy(event)
                    if verdict is not None and event.id is not None:
                        self._write(verdict_command(event.id, int(verdict)))
        except Exception as err:
            self._error = err
        finally:
            self._conn.close()

    def stop(self) -> None:
        """Hang up, as an agent that exits would."""
        if sys.platform == "win32":
            import ctypes
            import msvcrt

            # The reader is blocked in a synchronous ReadFile on this handle:
            # cancel it, and the thread closes the handle on its way out.
            handle = msvcrt.get_osfhandle(self._conn.fileno())
            ctypes.windll.kernel32.CancelIoEx(ctypes.c_void_p(handle), None)
        else:
            self._conn.shutdown(socket.SHUT_RDWR)
        self.join()

    def join(self, timeout: float = 5.0) -> None:
        self._thread.join(timeout)
        if self._thread.is_alive():
            raise TimeoutError("PipeAgent did not finish")
        if self._error is not None:
            raise self._error


def kext_tester_path() -> Path | None:
    """The built Go test agent (`just sim-build-agent`): `$ZF_KEXT_TESTER`, else
    the repo's build output, else `kext_tester` on PATH; None if none is found."""
    if os.environ.get("ZF_KEXT_TESTER"):
        return Path(os.environ["ZF_KEXT_TESTER"])
    name = "kext_tester.exe" if sys.platform == "win32" else "kext_tester/kext_tester"
    path = REPO / name
    if path.is_file():
        return path
    found = shutil.which("kext_tester")
    return Path(found) if found else None


def start_kext_tester(name: str, path: Path | str | None = None, **popen_args: Any) -> subprocess.Popen:
    """Start the Go test agent attached to the endpoint `Sim.serve(name)`
    opened (`name` is the logical name). Its policy: outbound to 1.1.1.1 is
    PERMANENT_BLOCK, everything else PERMANENT_ACCEPT. It exits on its own once
    the sim closes the endpoint."""
    path = path or kext_tester_path()
    if path is None:
        raise FileNotFoundError("kext_tester is not built (just sim-build-agent)")
    env = dict(os.environ, ZF_SIM_PIPE=name)
    return subprocess.Popen([str(path)], env=env, **popen_args)
