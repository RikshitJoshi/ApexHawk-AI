#!/usr/bin/env python3
"""ApexHawk AI - MCP bridge.

Exposes ApexHawk's capabilities as MCP tools so an MCP-compatible agent
(Claude Desktop, Cursor, VS Code Copilot, ...) can drive them. This process is
a thin client: every tool call is forwarded to the ApexHawk HTTP server, which
is where scope enforcement, caching and execution actually happen.

    python3 apexhawk_mcp.py --server http://localhost:8888
"""

from __future__ import annotations

import argparse
import os
from typing import Any, Dict, Optional

import requests

# FastMCP ships both as the standalone 'fastmcp' package and inside the MCP SDK.
try:
    from fastmcp import FastMCP  # type: ignore
except Exception:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP  # type: ignore

mcp = FastMCP("ApexHawk AI")

SERVER = os.environ.get("APEXHAWK_SERVER", "http://localhost:8888")
API_TOKEN = os.environ.get("APEXHAWK_API_TOKEN") or None
TIMEOUT = int(os.environ.get("APEXHAWK_MCP_TIMEOUT", "600"))


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------
def _headers() -> Dict[str, str]:
    h = {"Content-Type": "application/json"}
    if API_TOKEN:
        h["Authorization"] = f"Bearer {API_TOKEN}"
    return h


def _post(path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    try:
        r = requests.post(f"{SERVER}{path}", json=payload or {},
                          headers=_headers(), timeout=TIMEOUT)
        return r.json()
    except Exception as exc:
        return {"error": f"request to {path} failed: {exc}",
                "hint": "is apexhawk_server.py running and --server correct?"}


def _get(path: str) -> Dict[str, Any]:
    try:
        r = requests.get(f"{SERVER}{path}", headers=_headers(), timeout=TIMEOUT)
        return r.json()
    except Exception as exc:
        return {"error": f"request to {path} failed: {exc}"}


def _run_tool(name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    return _post(f"/api/tools/{name}/run", {k: v for k, v in params.items() if v not in (None, "")})


# --------------------------------------------------------------------------
# Meta / intelligence tools
# --------------------------------------------------------------------------
@mcp.tool()
def health() -> Dict[str, Any]:
    """Server health, version, and which security tools are installed."""
    return _get("/health")


@mcp.tool()
def list_tools() -> Dict[str, Any]:
    """List every wrapped tool, grouped by category, with availability."""
    return _get("/api/tools/list")


@mcp.tool()
def analyze_target(target: str) -> Dict[str, Any]:
    """Profile a target (classify as ip/domain/url/cidr, detect web, etc.)."""
    return _post("/api/intelligence/analyze-target", {"target": target})


@mcp.tool()
def select_tools(target: str, objective: str = "full") -> Dict[str, Any]:
    """Recommend an ordered tool chain for a target and objective
    (recon | subdomain | network | web | full)."""
    return _post("/api/intelligence/select-tools",
                 {"target": target, "objective": objective})


@mcp.tool()
def optimize_parameters(tool: str, target: str) -> Dict[str, Any]:
    """Suggest tuned parameters for a tool given a target profile."""
    return _post("/api/intelligence/optimize-parameters",
                 {"tool": tool, "target": target})


@mcp.tool()
def run_tool(name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Run any registered tool by name with an arbitrary parameter dict."""
    return _run_tool(name, params or {})


# --------------------------------------------------------------------------
# Representative per-tool wrappers (all forward to the server)
# --------------------------------------------------------------------------
@mcp.tool()
def nmap_scan(target: str, ports: str = "", scripts: str = "", extra_args: str = "") -> Dict[str, Any]:
    """Nmap service/version scan of an in-scope target."""
    return _run_tool("nmap_scan", {"target": target, "ports": ports,
                                   "scripts": scripts, "extra_args": extra_args})


@mcp.tool()
def rustscan_scan(target: str, ports: str = "", extra_args: str = "") -> Dict[str, Any]:
    """Fast Rustscan port sweep of an in-scope target."""
    return _run_tool("rustscan_scan", {"target": target, "ports": ports, "extra_args": extra_args})


@mcp.tool()
def nuclei_scan(target: str, severity: str = "", tags: str = "") -> Dict[str, Any]:
    """Nuclei template-based vulnerability scan of an in-scope target."""
    return _run_tool("nuclei_scan", {"target": target, "severity": severity, "tags": tags})


@mcp.tool()
def gobuster_scan(target: str, wordlist: str = "", extensions: str = "") -> Dict[str, Any]:
    """Gobuster directory/file brute-force of an in-scope web target."""
    return _run_tool("gobuster_scan", {"target": target, "wordlist": wordlist,
                                       "extensions": extensions})


@mcp.tool()
def ffuf_scan(target: str, wordlist: str = "", match_codes: str = "") -> Dict[str, Any]:
    """ffuf fuzzing of an in-scope web target (put FUZZ in the URL)."""
    return _run_tool("ffuf_scan", {"target": target, "wordlist": wordlist,
                                   "match_codes": match_codes})


@mcp.tool()
def httpx_probe(target: str, extra_args: str = "") -> Dict[str, Any]:
    """httpx probe: status, title and tech detection for an in-scope target."""
    return _run_tool("httpx_probe", {"target": target, "extra_args": extra_args})


@mcp.tool()
def sqlmap_scan(target: str, data: str = "", level: str = "", risk: str = "") -> Dict[str, Any]:
    """sqlmap SQL-injection detection against an in-scope URL (--batch)."""
    return _run_tool("sqlmap_scan", {"target": target, "data": data,
                                     "level": level, "risk": risk})


@mcp.tool()
def wpscan_scan(target: str, api_token: str = "") -> Dict[str, Any]:
    """WPScan WordPress assessment of an in-scope target."""
    return _run_tool("wpscan_scan", {"target": target, "api_token": api_token})


@mcp.tool()
def subfinder_enum(target: str) -> Dict[str, Any]:
    """Passive subdomain discovery for an in-scope domain."""
    return _run_tool("subfinder_enum", {"target": target})


@mcp.tool()
def amass_enum(target: str, passive: bool = True) -> Dict[str, Any]:
    """Amass subdomain enumeration for an in-scope domain."""
    return _run_tool("amass_enum", {"target": target, "passive": passive})


@mcp.tool()
def trivy_scan(target_ref: str, mode: str = "image") -> Dict[str, Any]:
    """Trivy scan of a container image, filesystem path, or repo (mode)."""
    return _run_tool("trivy_scan", {"target_ref": target_ref, "mode": mode})


# --------------------------------------------------------------------------
# Workflows / CVE / advisor
# --------------------------------------------------------------------------
@mcp.tool()
def bugbounty_plan(target: str) -> Dict[str, Any]:
    """Build a phased recon->enum->scan plan for an in-scope target."""
    return _post("/api/workflows/bugbounty", {"target": target})


@mcp.tool()
def ctf_categorize(description: str) -> Dict[str, Any]:
    """Classify a CTF challenge and suggest a starting tool set."""
    return _post("/api/ctf/categorize", {"description": description})


@mcp.tool()
def cve_search(keyword: str, limit: int = 10) -> Dict[str, Any]:
    """Search public CVE data (NVD) by keyword. Read-only OSINT."""
    return _post("/api/cve/search", {"keyword": keyword, "limit": limit})


@mcp.tool()
def cve_get(cve_id: str) -> Dict[str, Any]:
    """Fetch metadata for a specific CVE id from NVD. Read-only OSINT."""
    return _get(f"/api/cve/{cve_id}")


@mcp.tool()
def exploit_advise(query: str) -> Dict[str, Any]:
    """Triage advice for a CVE/finding: public references + remediation.
    Does NOT generate exploit code."""
    return _post("/api/exploit/advise", {"query": query})


# --------------------------------------------------------------------------
# Process management
# --------------------------------------------------------------------------
@mcp.tool()
def list_processes() -> Dict[str, Any]:
    """List processes ApexHawk is currently tracking."""
    return _get("/api/processes/list")


@mcp.tool()
def terminate_process(pid: int, force: bool = False) -> Dict[str, Any]:
    """Terminate a tracked process by PID."""
    return _post(f"/api/processes/terminate/{pid}", {"force": force})


def main() -> None:
    global SERVER
    parser = argparse.ArgumentParser(description="ApexHawk AI MCP bridge")
    parser.add_argument("--server", default=SERVER, help="ApexHawk HTTP server URL")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    SERVER = args.server.rstrip("/")
    mcp.run()


if __name__ == "__main__":
    main()
