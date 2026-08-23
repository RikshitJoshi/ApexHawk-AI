"""CommandExecutor - safe, cached subprocess execution with telemetry.

All tool wrappers funnel through here. Responsibilities:
  * normalise list/str commands (list => shell=False, safer)
  * enforce the destructive-command guard
  * cache successful results (SmartCache)
  * register live processes (ProcessManager)
  * enforce timeouts and record telemetry
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import List, Optional, Union

from .cache import SmartCache, make_key
from .config import (
    DEFAULT_COMMAND_TIMEOUT,
    MAX_COMMAND_TIMEOUT,
    is_dangerous_command,
)
from .process_manager import ProcessManager

CommandLike = Union[str, List[str]]


@dataclass
class CommandResult:
    command: str
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    success: bool = False
    duration: float = 0.0
    cached: bool = False
    timed_out: bool = False
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


class CommandExecutor:
    def __init__(self, cache: Optional[SmartCache] = None,
                 process_manager: Optional[ProcessManager] = None) -> None:
        self.cache = cache or SmartCache()
        self.processes = process_manager or ProcessManager()
        self._lock = threading.Lock()
        self._telemetry = {
            "total": 0,
            "successful": 0,
            "failed": 0,
            "timed_out": 0,
            "blocked": 0,
            "cache_served": 0,
            "total_runtime": 0.0,
            "started_at": time.time(),
        }

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def check_tool(binary: str) -> bool:
        """Is the given binary present on PATH?"""
        return shutil.which(binary) is not None

    @staticmethod
    def _display(command: CommandLike) -> str:
        if isinstance(command, (list, tuple)):
            return " ".join(shlex.quote(str(c)) for c in command)
        return str(command)

    def _record(self, result: CommandResult) -> None:
        with self._lock:
            self._telemetry["total"] += 1
            self._telemetry["total_runtime"] += result.duration
            if result.cached:
                self._telemetry["cache_served"] += 1
            if result.timed_out:
                self._telemetry["timed_out"] += 1
            if result.success:
                self._telemetry["successful"] += 1
            else:
                self._telemetry["failed"] += 1

    # -- main entry point ------------------------------------------------
    def run(self, command: CommandLike, timeout: Optional[int] = None,
            use_cache: bool = True, tool_name: str = "command") -> CommandResult:
        display = self._display(command)
        timeout = min(timeout or DEFAULT_COMMAND_TIMEOUT, MAX_COMMAND_TIMEOUT)

        # 1) destructive-command guard
        reason = is_dangerous_command(display)
        if reason:
            with self._lock:
                self._telemetry["blocked"] += 1
            return CommandResult(command=display, success=False,
                                 error=reason, returncode=None)

        # 2) cache lookup
        cache_key = make_key(display)
        if use_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                result = CommandResult(**{**cached, "cached": True})
                self._record(result)
                return result

        # 3) execute
        use_shell = isinstance(command, str)
        start = time.time()
        proc = None
        try:
            proc = subprocess.Popen(
                command,
                shell=use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
            )
            self.processes.register(proc.pid, display, tool=tool_name, handle=proc)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                rc = proc.returncode
                self.processes.mark_done(proc.pid, rc)
                result = CommandResult(
                    command=display,
                    returncode=rc,
                    stdout=stdout or "",
                    stderr=stderr or "",
                    success=(rc == 0),
                    duration=round(time.time() - start, 3),
                )
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                self.processes.mark_done(proc.pid, None)
                result = CommandResult(
                    command=display,
                    returncode=None,
                    stdout=stdout or "",
                    stderr=stderr or "",
                    success=False,
                    duration=round(time.time() - start, 3),
                    timed_out=True,
                    error=f"timed out after {timeout}s",
                )
        except FileNotFoundError:
            result = CommandResult(
                command=display, success=False,
                error="executable not found (is the tool installed and on PATH?)",
                duration=round(time.time() - start, 3),
            )
        except Exception as exc:  # pragma: no cover - defensive
            result = CommandResult(
                command=display, success=False, error=str(exc),
                duration=round(time.time() - start, 3),
            )

        # 4) cache + telemetry
        if use_cache and result.success:
            self.cache.set(cache_key, result.to_dict())
        self._record(result)
        return result

    def telemetry(self) -> dict:
        with self._lock:
            t = dict(self._telemetry)
        uptime = time.time() - t["started_at"]
        t["uptime_seconds"] = round(uptime, 1)
        t["avg_runtime"] = round(t["total_runtime"] / t["total"], 3) if t["total"] else 0.0
        return t
