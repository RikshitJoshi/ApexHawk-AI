"""ProcessManager - registry and live control of running tool subprocesses."""

from __future__ import annotations

import signal
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:  # psutil enriches telemetry but is optional
    import psutil  # type: ignore

    _HAS_PSUTIL = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore
    _HAS_PSUTIL = False


@dataclass
class ManagedProcess:
    pid: int
    command: str
    tool: str = "command"
    started_at: float = field(default_factory=time.time)
    status: str = "running"  # running | done | failed | terminated
    returncode: Optional[int] = None
    handle: object = None  # subprocess.Popen, not serialised

    def runtime(self) -> float:
        return round(time.time() - self.started_at, 3)

    def to_dict(self) -> dict:
        info = {
            "pid": self.pid,
            "tool": self.tool,
            "command": self.command,
            "status": self.status,
            "returncode": self.returncode,
            "runtime_seconds": self.runtime(),
        }
        if _HAS_PSUTIL and self.status == "running":
            try:
                proc = psutil.Process(self.pid)
                with proc.oneshot():
                    info["cpu_percent"] = proc.cpu_percent(interval=0.0)
                    info["memory_mb"] = round(proc.memory_info().rss / 1_048_576, 2)
            except Exception:
                pass
        return info


class ProcessManager:
    """Tracks subprocesses spawned by the executor and allows live control."""

    def __init__(self) -> None:
        self._procs: Dict[int, ManagedProcess] = {}
        self._lock = threading.RLock()

    def register(self, pid: int, command: str, tool: str = "command", handle=None) -> ManagedProcess:
        with self._lock:
            mp = ManagedProcess(pid=pid, command=command, tool=tool, handle=handle)
            self._procs[pid] = mp
            return mp

    def mark_done(self, pid: int, returncode: Optional[int]) -> None:
        with self._lock:
            mp = self._procs.get(pid)
            if mp:
                mp.returncode = returncode
                mp.status = "done" if returncode == 0 else "failed"

    def list(self) -> List[dict]:
        with self._lock:
            return [mp.to_dict() for mp in self._procs.values()]

    def status(self, pid: int) -> Optional[dict]:
        with self._lock:
            mp = self._procs.get(pid)
            return mp.to_dict() if mp else None

    def terminate(self, pid: int, force: bool = False) -> dict:
        with self._lock:
            mp = self._procs.get(pid)
        if not mp:
            return {"success": False, "error": f"no managed process with pid {pid}"}
        try:
            if mp.handle is not None and hasattr(mp.handle, "poll"):
                if mp.handle.poll() is None:
                    mp.handle.kill() if force else mp.handle.terminate()
            elif _HAS_PSUTIL:
                proc = psutil.Process(pid)
                proc.kill() if force else proc.terminate()
            else:  # last resort
                import os

                os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
            mp.status = "terminated"
            return {"success": True, "pid": pid, "forced": force}
        except Exception as exc:
            return {"success": False, "pid": pid, "error": str(exc)}

    def prune(self, older_than: float = 3600.0) -> int:
        """Drop finished entries older than ``older_than`` seconds."""
        with self._lock:
            now = time.time()
            stale = [
                pid
                for pid, mp in self._procs.items()
                if mp.status != "running" and (now - mp.started_at) > older_than
            ]
            for pid in stale:
                self._procs.pop(pid, None)
            return len(stale)

    def dashboard(self) -> dict:
        procs = self.list()
        running = [p for p in procs if p["status"] == "running"]
        return {
            "total_tracked": len(procs),
            "running": len(running),
            "completed": len([p for p in procs if p["status"] == "done"]),
            "failed": len([p for p in procs if p["status"] in ("failed", "terminated")]),
            "psutil_available": _HAS_PSUTIL,
            "processes": procs,
        }
