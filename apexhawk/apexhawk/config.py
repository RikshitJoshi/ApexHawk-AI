"""Central configuration, versioning, and the authorized-testing scope model.

The scope model is what keeps ApexHawk on the right side of "authorized testing
only": any tool that takes a ``target`` validates it against the configured
scope before a single packet is sent. Loosen it only for lab environments.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

VERSION = "6.0.0"
PRODUCT_NAME = "ApexHawk AI"
TAGLINE = "AI-Powered MCP Cybersecurity Automation Platform"

# ---------------------------------------------------------------------------
# Server defaults
# ---------------------------------------------------------------------------
# Bind to loopback by default. This server can execute security tools, so it
# should never be exposed on 0.0.0.0 without an explicit, deliberate choice.
DEFAULT_HOST = os.environ.get("APEXHAWK_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("APEXHAWK_PORT", "8888"))

# Optional bearer token. If set (env APEXHAWK_API_TOKEN), every /api/* request
# must send `Authorization: Bearer <token>`.
API_TOKEN = os.environ.get("APEXHAWK_API_TOKEN") or None

# ---------------------------------------------------------------------------
# Execution / caching
# ---------------------------------------------------------------------------
DEFAULT_COMMAND_TIMEOUT = int(os.environ.get("APEXHAWK_TIMEOUT", "300"))
MAX_COMMAND_TIMEOUT = 3600
CACHE_MAX_ENTRIES = int(os.environ.get("APEXHAWK_CACHE_ENTRIES", "512"))
CACHE_TTL_SECONDS = int(os.environ.get("APEXHAWK_CACHE_TTL", "3600"))

# The raw /api/command endpoint is powerful (arbitrary shell). It is disabled
# unless the operator explicitly opts in.
ALLOW_ARBITRARY_COMMANDS = os.environ.get("APEXHAWK_ALLOW_CMD", "0") == "1"

# ---------------------------------------------------------------------------
# Destructive-command guard
# ---------------------------------------------------------------------------
# Defense-in-depth against accidents and prompt-injection reaching the shell.
# Not a security boundary on its own, but blocks the obvious footguns.
DANGEROUS_PATTERNS: List[re.Pattern] = [
    re.compile(r"\brm\s+-[a-z]*r[a-z]*f?\s+(/|~|\$HOME)"),
    re.compile(r"\bmkfs(\.\w+)?\b"),
    re.compile(r"\bdd\b[^\n]*\bof=/dev/(sd|nvme|vd|mmcblk)"),
    re.compile(r">\s*/dev/(sd|nvme|vd|mmcblk)"),
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),  # fork bomb
    re.compile(r"\b(shutdown|reboot|halt|poweroff|init\s+0)\b"),
    re.compile(r"\bchmod\s+-[a-z]*R[a-z]*\s+0*00?0?\s+/"),
    re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b"),  # curl|sh
]


def is_dangerous_command(command: str) -> Optional[str]:
    """Return a human-readable reason if the command looks destructive, else None."""
    for pattern in DANGEROUS_PATTERNS:
        if pattern.search(command):
            return f"blocked by destructive-command guard (matched: {pattern.pattern})"
    return None


# ---------------------------------------------------------------------------
# Authorized-testing scope
# ---------------------------------------------------------------------------
@dataclass
class ScopeConfig:
    """Defines which targets ApexHawk is permitted to test.

    A target is authorized if it matches a domain (suffix match), an exact
    host, or falls inside one of the CIDR ranges. ``allow_any`` disables the
    check entirely and should only be used in an isolated lab.
    """

    domains: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    cidrs: List[str] = field(default_factory=list)
    allow_any: bool = False

    @staticmethod
    def _extract_host(target: str) -> str:
        target = (target or "").strip()
        if not target:
            return ""
        if "://" in target:
            parsed = urlparse(target)
            return (parsed.hostname or "").lower()
        # strip any path / port fragments from a bare host:port or host/path
        host = target.split("/")[0].split("\\")[0]
        host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        return host.strip().lower()

    def is_authorized(self, target: str) -> bool:
        if self.allow_any:
            return True
        host = self._extract_host(target)
        if not host:
            return False

        # Exact host match
        if host in {h.lower() for h in self.hosts}:
            return True

        # Domain suffix match (example.com authorizes api.example.com)
        for domain in self.domains:
            domain = domain.lower().lstrip(".")
            if host == domain or host.endswith("." + domain):
                return True

        # CIDR membership (only meaningful when the host is an IP literal)
        try:
            ip = ipaddress.ip_address(host)
            for cidr in self.cidrs:
                try:
                    if ip in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    continue
        except ValueError:
            pass

        return False

    def summary(self) -> dict:
        return {
            "domains": self.domains,
            "hosts": self.hosts,
            "cidrs": self.cidrs,
            "allow_any": self.allow_any,
        }


def load_scope(path: Optional[str] = None) -> ScopeConfig:
    """Load scope from a JSON file.

    Resolution order: explicit ``path`` -> ``$APEXHAWK_SCOPE`` -> ./scope.json.
    If nothing is found, returns an empty scope (nothing authorized) unless
    ``$APEXHAWK_ALLOW_ANY=1`` is set for lab use.
    """
    allow_any_env = os.environ.get("APEXHAWK_ALLOW_ANY", "0") == "1"

    candidates = []
    if path:
        candidates.append(Path(path))
    if os.environ.get("APEXHAWK_SCOPE"):
        candidates.append(Path(os.environ["APEXHAWK_SCOPE"]))
    candidates.append(Path.cwd() / "scope.json")

    for candidate in candidates:
        try:
            if candidate and candidate.is_file():
                data = json.loads(candidate.read_text(encoding="utf-8"))
                return ScopeConfig(
                    domains=data.get("domains", []),
                    hosts=data.get("hosts", []),
                    cidrs=data.get("cidrs", []),
                    allow_any=bool(data.get("allow_any", False)) or allow_any_env,
                )
        except (OSError, json.JSONDecodeError, TypeError):
            continue

    return ScopeConfig(allow_any=allow_any_env)
