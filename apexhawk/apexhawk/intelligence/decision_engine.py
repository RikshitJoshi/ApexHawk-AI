"""The intelligence layer: target profiling, tool selection, parameter tuning.

These are heuristic 'agents' - deterministic decision helpers that let an AI
agent (or the CLI) pick sensible tools and parameters for a target. They do not
perform any network activity themselves; they only reason about a target.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")


class TechnologyDetector:
    """Best-effort technology fingerprinting from response evidence."""

    SIGNATURES = {
        "wordpress": ["wp-content", "wp-includes", "x-pingback"],
        "nginx": ["server: nginx"],
        "apache": ["server: apache"],
        "iis": ["server: microsoft-iis", "x-aspnet-version"],
        "php": ["x-powered-by: php", ".php"],
        "django": ["csrftoken", "x-frame-options: deny"],
        "react": ["react", "__next_data__"],
        "cloudflare": ["server: cloudflare", "cf-ray"],
    }

    def detect(self, evidence: str = "", headers: Optional[Dict[str, str]] = None) -> List[str]:
        blob = (evidence or "").lower()
        if headers:
            blob += "\n" + "\n".join(f"{k.lower()}: {str(v).lower()}" for k, v in headers.items())
        found = [tech for tech, sigs in self.SIGNATURES.items()
                 if any(s in blob for s in sigs)]
        return sorted(set(found))


class IntelligentDecisionEngine:
    """Profiles targets and recommends an ordered tool chain."""

    def __init__(self, registry=None) -> None:
        self.registry = registry
        self.tech_detector = TechnologyDetector()

    # -- profiling -------------------------------------------------------
    def analyze_target(self, target: str) -> Dict[str, Any]:
        target = (target or "").strip()
        profile: Dict[str, Any] = {
            "target": target,
            "type": "unknown",
            "host": target,
            "scheme": None,
            "is_web": False,
            "notes": [],
        }
        if not target:
            profile["notes"].append("empty target")
            return profile

        # URL?
        if "://" in target:
            parsed = urlparse(target)
            profile.update(type="url", host=parsed.hostname or target,
                           scheme=parsed.scheme, is_web=parsed.scheme in ("http", "https"))
            return profile

        # CIDR?
        if "/" in target:
            try:
                ipaddress.ip_network(target, strict=False)
                profile.update(type="cidr")
                return profile
            except ValueError:
                pass

        # IP?
        try:
            ipaddress.ip_address(target)
            profile.update(type="ip")
            return profile
        except ValueError:
            pass

        # Domain?
        if _DOMAIN_RE.match(target):
            profile.update(type="domain")
            return profile

        profile["notes"].append("could not classify target")
        return profile

    # -- selection -------------------------------------------------------
    def select_tools(self, target: str, objective: str = "full") -> Dict[str, Any]:
        profile = self.analyze_target(target)
        ttype = profile["type"]
        objective = (objective or "full").lower()

        recon = ["subfinder_enum", "amass_enum", "dnsenum_scan", "theharvester_scan"]
        network = ["nmap_scan", "rustscan_scan"]
        web = ["httpx_probe", "wafw00f_scan", "nuclei_scan", "gobuster_scan"]

        chain: List[str] = []
        if objective in ("subdomain", "osint", "recon") and ttype in ("domain",):
            chain = recon
        elif objective == "network" or ttype in ("ip", "cidr"):
            chain = network + (["nuclei_scan"] if objective == "full" else [])
        elif objective == "web" or profile["is_web"]:
            chain = web
        elif ttype == "domain":  # full on a bare domain
            chain = recon + ["httpx_probe", "nuclei_scan"]
        else:
            chain = network

        if objective == "full" and ttype == "domain":
            chain = recon + web

        # keep only tools that actually exist in the registry, if provided
        if self.registry is not None:
            known = set(self.registry.names())
            chain = [t for t in chain if t in known]

        return {"target": target, "objective": objective, "profile": profile,
                "recommended_tools": chain}


class ParameterOptimizer:
    """Context-aware default parameters for a tool given a target profile."""

    def optimize(self, tool_name: str, profile: Dict[str, Any]) -> Dict[str, Any]:
        ttype = profile.get("type", "unknown")
        params: Dict[str, Any] = {"target": profile.get("target")}

        if tool_name == "nmap_scan":
            # small ranges scan everything; large/unknown -> top ports & faster
            params["ports"] = "1-1000" if ttype in ("ip",) else None
            params["scripts"] = "default,vuln" if ttype == "ip" else None
        elif tool_name in ("gobuster_scan", "ffuf_scan", "feroxbuster_scan"):
            params["wordlist"] = "/usr/share/wordlists/dirb/common.txt"
        elif tool_name == "nuclei_scan":
            params["severity"] = "critical,high,medium"
        elif tool_name == "masscan_scan":
            params["ports"] = "1-65535"
            params["rate"] = 1000

        return {k: v for k, v in params.items() if v is not None}
