"""Resilience helpers: rate-limit detection, recovery, degradation, monitoring."""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

try:
    import psutil  # type: ignore
    _HAS_PSUTIL = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore
    _HAS_PSUTIL = False


class RateLimitDetector:
    """Spots rate limiting in tool output and recommends a backoff."""

    SIGNALS = [
        re.compile(r"\b429\b"),
        re.compile(r"too many requests", re.I),
        re.compile(r"rate.?limit", re.I),
        re.compile(r"\bthrottl", re.I),
        re.compile(r"captcha", re.I),
    ]

    def __init__(self) -> None:
        self.consecutive = 0

    def inspect(self, text: str) -> Dict[str, Any]:
        hit = any(p.search(text or "") for p in self.SIGNALS)
        self.consecutive = self.consecutive + 1 if hit else 0
        backoff = min(2 ** self.consecutive, 120) if hit else 0
        return {
            "rate_limited": hit,
            "consecutive_hits": self.consecutive,
            "recommended_backoff_seconds": backoff,
            "recommendation": (
                f"back off ~{backoff}s, reduce concurrency/threads, or add jitter"
                if hit else "no rate limiting detected"
            ),
        }


class GracefulDegradation:
    """Suggests an alternative when the preferred tool is unavailable."""

    ALTERNATIVES = {
        "gobuster_scan": ["feroxbuster_scan", "ffuf_scan"],
        "feroxbuster_scan": ["gobuster_scan", "ffuf_scan"],
        "ffuf_scan": ["gobuster_scan", "feroxbuster_scan"],
        "rustscan_scan": ["nmap_scan", "masscan_scan"],
        "masscan_scan": ["rustscan_scan", "nmap_scan"],
        "nmap_scan": ["rustscan_scan"],
        "subfinder_enum": ["amass_enum"],
        "amass_enum": ["subfinder_enum"],
    }

    def __init__(self, registry=None, executor=None) -> None:
        self.registry = registry
        self.executor = executor

    def _available(self, tool_name: str) -> bool:
        if self.registry is None or self.executor is None:
            return True
        tool = self.registry.get(tool_name)
        return bool(tool and self.executor.check_tool(tool.binary))

    def fallback(self, tool_name: str) -> Dict[str, Any]:
        if self._available(tool_name):
            return {"tool": tool_name, "degraded": False, "use": tool_name}
        for alt in self.ALTERNATIVES.get(tool_name, []):
            if self._available(alt):
                return {"tool": tool_name, "degraded": True, "use": alt,
                        "reason": f"{tool_name} unavailable, substituting {alt}"}
        return {"tool": tool_name, "degraded": True, "use": None,
                "reason": f"{tool_name} and all known alternatives are unavailable"}


class FailureRecoverySystem:
    """Classifies a failed run and recommends the next action."""

    def classify(self, result: Dict[str, Any]) -> str:
        if result.get("timed_out"):
            return "timeout"
        if result.get("available") is False:
            return "tool_missing"
        if result.get("authorized") is False:
            return "out_of_scope"
        err = (result.get("error") or "").lower()
        if "not found" in err:
            return "tool_missing"
        if result.get("returncode") not in (0, None):
            return "nonzero_exit"
        return "unknown"

    def recommend(self, result: Dict[str, Any]) -> Dict[str, Any]:
        category = self.classify(result)
        actions = {
            "timeout": "increase the timeout or narrow the scan scope, then retry",
            "tool_missing": "install the tool or let GracefulDegradation pick an alternative",
            "out_of_scope": "do not retry - target is outside authorized scope",
            "nonzero_exit": "inspect stderr; adjust parameters and retry once",
            "unknown": "review stdout/stderr manually",
        }
        return {
            "category": category,
            "retryable": category in ("timeout", "nonzero_exit"),
            "action": actions.get(category, "review manually"),
        }


class PerformanceMonitor:
    """System + executor telemetry snapshot."""

    def __init__(self, executor=None) -> None:
        self.executor = executor
        self.started_at = time.time()

    def snapshot(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "psutil_available": _HAS_PSUTIL,
        }
        if _HAS_PSUTIL:
            try:
                data["cpu_percent"] = psutil.cpu_percent(interval=0.0)
                vm = psutil.virtual_memory()
                data["memory_percent"] = vm.percent
                data["memory_used_mb"] = round(vm.used / 1_048_576, 1)
            except Exception:
                pass
        if self.executor is not None:
            data["executor"] = self.executor.telemetry()
        return data
