"""SmartCache - thread-safe LRU cache with TTL for command results."""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from typing import Any, Optional

from .config import CACHE_MAX_ENTRIES, CACHE_TTL_SECONDS


def make_key(*parts: Any) -> str:
    """Deterministic cache key from arbitrary parts (e.g. a command line)."""
    raw = "\x1f".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


class SmartCache:
    """LRU + TTL cache.

    - Least-recently-used eviction once ``max_entries`` is exceeded.
    - Per-entry expiry after ``ttl`` seconds.
    - Tracks hit/miss/eviction stats for the /api/cache/stats endpoint.
    """

    def __init__(self, max_entries: int = CACHE_MAX_ENTRIES, ttl: int = CACHE_TTL_SECONDS):
        self.max_entries = max_entries
        self.ttl = ttl
        self._store: "OrderedDict[str, tuple[float, Any]]" = OrderedDict()
        self._lock = threading.RLock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            item = self._store.get(key)
            if item is None:
                self.misses += 1
                return None
            ts, value = item
            if self.ttl and (time.time() - ts) > self.ttl:
                # expired
                self._store.pop(key, None)
                self.misses += 1
                return None
            self._store.move_to_end(key)
            self.hits += 1
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (time.time(), value)
            while len(self._store) > self.max_entries:
                self._store.popitem(last=False)
                self.evictions += 1

    def clear(self) -> int:
        with self._lock:
            n = len(self._store)
            self._store.clear()
            return n

    def stats(self) -> dict:
        with self._lock:
            total = self.hits + self.misses
            hit_rate = (self.hits / total) if total else 0.0
            return {
                "entries": len(self._store),
                "max_entries": self.max_entries,
                "ttl_seconds": self.ttl,
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "hit_rate": round(hit_rate, 4),
            }
