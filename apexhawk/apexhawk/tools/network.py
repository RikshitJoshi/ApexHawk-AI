"""Network reconnaissance & scanning tool wrappers."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import BaseTool
from .registry import REGISTRY
from ..executor import CommandResult

_PORT_RE = re.compile(r"^(\d{1,5})/(tcp|udp)\s+(open|open\|filtered)\s+(\S+)", re.M)


class NmapScan(BaseTool):
    name = "nmap_scan"
    binary = "nmap"
    category = "network"
    description = "Service/version detection and port scanning with Nmap."
    default_timeout = 900

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        target = params["target"]
        cmd = ["nmap", "-sV", "-T4", "--open"]
        ports = params.get("ports")
        if ports:
            cmd += ["-p", str(ports)]
        if params.get("scripts"):
            cmd += ["--script", str(params["scripts"])]
        cmd += self._extra_args(params)
        cmd.append(target)
        return cmd

    def parse_output(self, result: CommandResult, params: Dict[str, Any]) -> List[dict]:
        findings = []
        for port, proto, state, service in _PORT_RE.findall(result.stdout):
            findings.append({
                "severity": "info",
                "title": f"Open port {port}/{proto} ({service})",
                "target": params.get("target"),
                "tool": self.name,
                "description": f"state={state} service={service}",
            })
        return findings


class RustscanScan(BaseTool):
    name = "rustscan_scan"
    binary = "rustscan"
    category = "network"
    description = "Ultra-fast port sweep with Rustscan."
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        cmd = ["rustscan", "-a", params["target"], "--accessible"]
        if params.get("ports"):
            cmd += ["-p", str(params["ports"])]
        cmd += self._extra_args(params)
        return cmd


class MasscanScan(BaseTool):
    name = "masscan_scan"
    binary = "masscan"
    category = "network"
    description = "High-speed port scan with Masscan (usually needs root)."
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        ports = str(params.get("ports", "1-1000"))
        rate = str(params.get("rate", 1000))
        cmd = ["masscan", params["target"], "-p", ports, "--rate", rate]
        cmd += self._extra_args(params)
        return cmd


for _t in (NmapScan(), RustscanScan(), MasscanScan()):
    REGISTRY.register(_t)
