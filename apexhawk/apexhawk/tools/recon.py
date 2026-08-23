"""Subdomain enumeration & OSINT tool wrappers (priority category)."""

from __future__ import annotations

from typing import Any, Dict, List

from .base import BaseTool
from .registry import REGISTRY
from ..executor import CommandResult


class SubfinderEnum(BaseTool):
    name = "subfinder_enum"
    binary = "subfinder"
    category = "recon"
    description = "Passive subdomain discovery with Subfinder."
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        cmd = ["subfinder", "-d", params["target"], "-silent"]
        cmd += self._extra_args(params)
        return cmd

    def parse_output(self, result: CommandResult, params: Dict[str, Any]) -> List[dict]:
        subs = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
        if not subs:
            return []
        return [{
            "severity": "info",
            "title": f"{len(subs)} subdomain(s) discovered",
            "target": params.get("target"),
            "tool": self.name,
            "description": ", ".join(subs[:15]) + (" ..." if len(subs) > 15 else ""),
        }]


class AmassEnum(BaseTool):
    name = "amass_enum"
    binary = "amass"
    category = "recon"
    description = "Subdomain enumeration and OSINT with Amass."
    default_timeout = 1200

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        mode = "-passive" if params.get("passive", True) else "-active"
        cmd = ["amass", "enum", mode, "-d", params["target"]]
        cmd += self._extra_args(params)
        return cmd


class DnsenumScan(BaseTool):
    name = "dnsenum_scan"
    binary = "dnsenum"
    category = "recon"
    description = "DNS enumeration and zone-transfer checks with dnsenum."
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        cmd = ["dnsenum", "--nocolor", params["target"]]
        cmd += self._extra_args(params)
        return cmd


class TheHarvesterScan(BaseTool):
    name = "theharvester_scan"
    binary = "theHarvester"
    category = "recon"
    description = "Email/subdomain harvesting from public sources."
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        sources = str(params.get("sources", "all"))
        cmd = ["theHarvester", "-d", params["target"], "-b", sources]
        cmd += self._extra_args(params)
        return cmd


class GauScan(BaseTool):
    name = "gau_scan"
    binary = "gau"
    category = "recon"
    description = "Fetch known URLs from Wayback/Common Crawl/OTX with gau."
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        cmd = ["gau", params["target"]]
        cmd += self._extra_args(params)
        return cmd


for _t in (
    SubfinderEnum(), AmassEnum(), DnsenumScan(), TheHarvesterScan(), GauScan(),
):
    REGISTRY.register(_t)
