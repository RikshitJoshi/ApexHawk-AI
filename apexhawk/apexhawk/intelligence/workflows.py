"""Workflow managers - phased playbooks for bug bounty and CTF work.

A manager produces an ordered plan of (tool, params) steps. Execution is
optional and, when requested, runs each step through the shared executor with
the same scope enforcement every tool uses.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .decision_engine import IntelligentDecisionEngine, ParameterOptimizer


class BugBountyWorkflowManager:
    """Recon -> enumeration -> vulnerability-scan playbook."""

    PHASES = ("recon", "enumeration", "vulnerability_scan")

    def __init__(self, registry=None) -> None:
        self.registry = registry
        self.engine = IntelligentDecisionEngine(registry=registry)
        self.optimizer = ParameterOptimizer()

    def plan(self, target: str) -> Dict[str, Any]:
        profile = self.engine.analyze_target(target)
        phase_tools = {
            "recon": ["subfinder_enum", "amass_enum", "theharvester_scan"],
            "enumeration": ["httpx_probe", "wafw00f_scan", "gobuster_scan"],
            "vulnerability_scan": ["nuclei_scan", "sqlmap_scan"],
        }
        if profile["type"] in ("ip", "cidr"):
            phase_tools["recon"] = ["nmap_scan", "rustscan_scan"]

        known = set(self.registry.names()) if self.registry else None
        phases = []
        for name in self.PHASES:
            steps = []
            for tool in phase_tools[name]:
                if known is not None and tool not in known:
                    continue
                params = self.optimizer.optimize(tool, profile)
                params.setdefault("target", target)
                steps.append({"tool": tool, "params": params})
            phases.append({"phase": name, "steps": steps})

        return {"target": target, "profile": profile, "phases": phases}

    def execute(self, target: str, executor, scope) -> Dict[str, Any]:
        """Run the plan sequentially. Requires registry, executor and scope."""
        if self.registry is None:
            raise RuntimeError("execute() needs a tool registry")
        plan = self.plan(target)
        for phase in plan["phases"]:
            for step in phase["steps"]:
                tool = self.registry.get(step["tool"])
                if not tool:
                    step["result"] = {"error": "unknown tool"}
                    continue
                step["result"] = tool.run(step["params"], executor, scope)
        return plan


class CTFWorkflowManager:
    """Classifies a CTF challenge and suggests a starting tool set."""

    KEYWORDS = {
        "web": ["http", "cookie", "sql", "xss", "login", "flask", "php", "jwt"],
        "crypto": ["cipher", "rsa", "aes", "hash", "encode", "xor", "key"],
        "pwn": ["overflow", "binary", "shellcode", "rop", "libc", "heap", "stack"],
        "reverse": ["reverse", "disassemble", "decompile", "obfuscated", "crackme"],
        "forensics": ["pcap", "memory", "disk", "image", "steg", "carve", "dump"],
        "osint": ["find the person", "username", "social", "geolocate"],
    }

    SUGGESTIONS = {
        "web": ["httpx_probe", "gobuster_scan", "sqlmap_scan", "nuclei_scan"],
        "crypto": ["(offline analysis - RsaCtfTool, CyberChef, sage)"],
        "pwn": ["strings_extract", "(gdb/pwntools/checksec)"],
        "reverse": ["strings_extract", "binwalk_scan", "(ghidra/radare2)"],
        "forensics": ["binwalk_scan", "exiftool_scan", "(volatility3/foremost/zsteg)"],
        "osint": ["theharvester_scan", "(sherlock/spiderfoot)"],
    }

    def categorize(self, description: str) -> Dict[str, Any]:
        blob = (description or "").lower()
        scores = {cat: sum(1 for kw in kws if kw in blob)
                  for cat, kws in self.KEYWORDS.items()}
        best = max(scores, key=scores.get)
        if scores[best] == 0:
            best = "unknown"
        return {
            "category": best,
            "confidence": scores.get(best, 0),
            "all_scores": scores,
            "suggested_tools": self.SUGGESTIONS.get(best, []),
        }
