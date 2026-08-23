"""Web application security testing tool wrappers (priority category)."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import BaseTool
from .registry import REGISTRY
from ..executor import CommandResult

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


class GobusterScan(BaseTool):
    name = "gobuster_scan"
    binary = "gobuster"
    category = "web"
    description = "Directory/file brute-forcing with Gobuster."
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        wordlist = params.get("wordlist", DEFAULT_WORDLIST)
        cmd = ["gobuster", "dir", "-u", params["target"], "-w", wordlist, "-q"]
        if params.get("extensions"):
            cmd += ["-x", str(params["extensions"])]
        cmd += self._extra_args(params)
        return cmd


class FfufScan(BaseTool):
    name = "ffuf_scan"
    binary = "ffuf"
    category = "web"
    description = "Fast web fuzzing with ffuf (use FUZZ in the target URL)."
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        target = params["target"]
        url = target if "FUZZ" in target else target.rstrip("/") + "/FUZZ"
        wordlist = params.get("wordlist", DEFAULT_WORDLIST)
        cmd = ["ffuf", "-u", url, "-w", wordlist, "-s"]
        if params.get("match_codes"):
            cmd += ["-mc", str(params["match_codes"])]
        cmd += self._extra_args(params)
        return cmd


class FeroxbusterScan(BaseTool):
    name = "feroxbuster_scan"
    binary = "feroxbuster"
    category = "web"
    description = "Recursive content discovery with feroxbuster."
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        wordlist = params.get("wordlist", DEFAULT_WORDLIST)
        cmd = ["feroxbuster", "-u", params["target"], "-w", wordlist, "--silent"]
        cmd += self._extra_args(params)
        return cmd


class NucleiScan(BaseTool):
    name = "nuclei_scan"
    binary = "nuclei"
    category = "web"
    description = "Template-based vulnerability scanning with Nuclei."
    default_timeout = 1200

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        cmd = ["nuclei", "-u", params["target"], "-jsonl", "-silent"]
        if params.get("severity"):
            cmd += ["-severity", str(params["severity"])]
        if params.get("tags"):
            cmd += ["-tags", str(params["tags"])]
        cmd += self._extra_args(params)
        return cmd

    def parse_output(self, result: CommandResult, params: Dict[str, Any]) -> List[dict]:
        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info", {})
            findings.append({
                "severity": info.get("severity", "info"),
                "title": info.get("name", obj.get("template-id", "nuclei match")),
                "target": obj.get("matched-at", params.get("target")),
                "tool": self.name,
                "description": (info.get("description") or "")[:180],
                "reference": (info.get("reference") or [""])[0]
                if isinstance(info.get("reference"), list) else info.get("reference", ""),
            })
        return findings


class SqlmapScan(BaseTool):
    name = "sqlmap_scan"
    binary = "sqlmap"
    category = "web"
    description = "Automated SQL injection detection with sqlmap (--batch)."
    default_timeout = 1200

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        cmd = ["sqlmap", "-u", params["target"], "--batch"]
        if params.get("data"):
            cmd += ["--data", str(params["data"])]
        level = params.get("level")
        risk = params.get("risk")
        if level:
            cmd += ["--level", str(level)]
        if risk:
            cmd += ["--risk", str(risk)]
        cmd += self._extra_args(params)
        return cmd

    def parse_output(self, result: CommandResult, params: Dict[str, Any]) -> List[dict]:
        text = result.stdout
        if re.search(r"is vulnerable|appears to be.*injectable|Parameter:.*\n.*Type:", text):
            return [{
                "severity": "high",
                "title": "Potential SQL injection detected",
                "target": params.get("target"),
                "tool": self.name,
                "description": "sqlmap reported an injectable parameter; review output.",
            }]
        return []


class NiktoScan(BaseTool):
    name = "nikto_scan"
    binary = "nikto"
    category = "web"
    description = "Web server misconfiguration scanning with Nikto."
    default_timeout = 900

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        cmd = ["nikto", "-h", params["target"], "-ask", "no"]
        cmd += self._extra_args(params)
        return cmd


class HttpxProbe(BaseTool):
    name = "httpx_probe"
    binary = "httpx"
    category = "web"
    description = "HTTP probing and tech detection with httpx."
    default_timeout = 300

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        cmd = ["httpx", "-u", params["target"], "-sc", "-title", "-td", "-silent", "-json"]
        cmd += self._extra_args(params)
        return cmd


class WpscanScan(BaseTool):
    name = "wpscan_scan"
    binary = "wpscan"
    category = "web"
    description = "WordPress security scanning with WPScan."
    default_timeout = 900

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        cmd = ["wpscan", "--url", params["target"], "--no-banner"]
        if params.get("api_token"):
            cmd += ["--api-token", str(params["api_token"])]
        cmd += self._extra_args(params)
        return cmd


class DalfoxScan(BaseTool):
    name = "dalfox_scan"
    binary = "dalfox"
    category = "web"
    description = "XSS scanning with Dalfox."
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        cmd = ["dalfox", "url", params["target"]]
        cmd += self._extra_args(params)
        return cmd


class Wafw00fScan(BaseTool):
    name = "wafw00f_scan"
    binary = "wafw00f"
    category = "web"
    description = "Web application firewall fingerprinting."
    default_timeout = 180

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        cmd = ["wafw00f", params["target"]]
        cmd += self._extra_args(params)
        return cmd


for _t in (
    GobusterScan(), FfufScan(), FeroxbusterScan(), NucleiScan(), SqlmapScan(),
    NiktoScan(), HttpxProbe(), WpscanScan(), DalfoxScan(), Wafw00fScan(),
):
    REGISTRY.register(_t)
