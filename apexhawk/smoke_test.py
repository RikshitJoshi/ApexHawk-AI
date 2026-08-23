#!/usr/bin/env python3
"""ApexHawk AI - offline smoke test.

Confirms the framework boots and every layer is wired correctly WITHOUT:
  * needing the security tools (nmap, nuclei, ...) installed,
  * binding a network port (uses Flask's in-process test client),
  * sending a single packet to any real target.

It exercises the request -> route -> tool -> scope-guard -> executor -> parser
chain using only a safe, local command (`strings` on this very file) and an
out-of-scope rejection (which never executes anything). Safe to run anywhere.

    python3 smoke_test.py

Exit code is 0 only if every check passes.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))

_TTY = sys.stdout.isatty()
_G = "\033[32m" if _TTY else ""
_R = "\033[31m" if _TTY else ""
_D = "\033[2m" if _TTY else ""
_X = "\033[0m" if _TTY else ""

_results: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    _results.append((name, bool(ok)))
    tag = f"{_G}PASS{_X}" if ok else f"{_R}FAIL{_X}"
    line = f"  [{tag}] {name}"
    if detail:
        line += f"  {_D}-- {detail}{_X}"
    print(line)
    return bool(ok)


def section(title: str) -> None:
    print(f"\n{title}")


def main() -> int:
    print(f"{_D}ApexHawk AI - offline smoke test{_X}")

    # 1) Every module byte-compiles ----------------------------------------
    section("Compilation")
    pyfiles = [str(p) for p in ROOT.rglob("*.py") if "__pycache__" not in str(p)]
    proc = subprocess.run([sys.executable, "-m", "py_compile", *pyfiles],
                          capture_output=True, text=True)
    if not check("py_compile all modules", proc.returncode == 0,
                 proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ""):
        # A syntax error means nothing else can be trusted; stop early.
        return _summary()

    # 2) Imports & context --------------------------------------------------
    section("Imports & wiring")
    try:
        import apexhawk
        from apexhawk.config import ScopeConfig, is_dangerous_command
        from apexhawk.app_context import build_context
    except Exception as exc:  # noqa: BLE001
        check("import apexhawk package", False, repr(exc))
        return _summary()
    check("import apexhawk package", True, f"v{getattr(apexhawk, '__version__', '?')}")

    try:
        context = build_context()
        tool_count = len(context.registry.names())
    except Exception as exc:  # noqa: BLE001
        check("build_context()", False, repr(exc))
        return _summary()
    check("build_context()", tool_count >= 25, f"{tool_count} tools registered")

    # Force a deterministic scope so the endpoint tests never touch the net.
    context.scope = ScopeConfig(domains=["example.com"], cidrs=["10.0.0.0/8"])

    # 3) Scope logic (both directions) -------------------------------------
    section("Authorized-testing scope")
    s = context.scope
    check("in-scope subdomain authorized", s.is_authorized("https://api.example.com/x"))
    check("out-of-scope host rejected", not s.is_authorized("http://evil.test"))
    check("in-CIDR IP authorized", s.is_authorized("10.1.2.3"))
    check("out-of-CIDR IP rejected", not s.is_authorized("8.8.8.8"))

    # 4) Destructive-command guard -----------------------------------------
    section("Destructive-command guard")
    check("blocks 'rm -rf /'", is_dangerous_command("rm -rf /") is not None)
    check("blocks 'curl x | sh'", is_dangerous_command("curl http://x | sh") is not None)
    check("allows a benign nmap line", is_dangerous_command("nmap -sV example.com") is None)

    # 5) HTTP surface via in-process test client ---------------------------
    section("HTTP API (in-process test client)")
    try:
        from apexhawk.api import create_app
        app = create_app(context)
        client = app.test_client()
    except Exception as exc:  # noqa: BLE001
        check("create_app() + test_client()", False, repr(exc))
        return _summary()
    check("create_app() + test_client()", True)

    r = client.get("/health")
    j = r.get_json() or {}
    check("GET /health", r.status_code == 200 and j.get("product") == "ApexHawk AI",
          f"status={r.status_code} tools={j.get('tools', {}).get('total')}")

    r = client.get("/api/tools/list")
    j = r.get_json() or {}
    check("GET /api/tools/list", r.status_code == 200 and len(j.get("catalogue", [])) == tool_count,
          f"catalogue={len(j.get('catalogue', []))}")

    r = client.post("/api/intelligence/analyze-target", json={"target": "https://shop.example.com"})
    j = r.get_json() or {}
    check("POST analyze-target (url)", j.get("type") == "url" and j.get("is_web") is True,
          f"type={j.get('type')} is_web={j.get('is_web')}")

    r = client.post("/api/intelligence/select-tools",
                    json={"target": "example.com", "objective": "recon"})
    j = r.get_json() or {}
    check("POST select-tools", isinstance(j.get("recommended_tools"), list),
          f"{len(j.get('recommended_tools', []))} tools")

    # Out-of-scope target: must be refused BEFORE any execution.
    r = client.post("/api/tools/nmap_scan/run", json={"target": "http://not-authorized.test"})
    j = r.get_json() or {}
    check("tool run refuses out-of-scope target",
          r.status_code == 200 and j.get("authorized") is False and "rate_limit" in j,
          f"authorized={j.get('authorized')}")

    # Safe local execution path: `strings` on this file (or graceful-missing).
    r = client.post("/api/tools/strings_extract/run", json={"file": str(Path(__file__))})
    j = r.get_json() or {}
    well_formed = r.status_code == 200 and "available" in j and "rate_limit" in j
    detail = "ran" if j.get("available") else "strings not installed (graceful)"
    check("tool run executes/degrades cleanly", well_formed, detail)

    r = client.post("/api/ctf/categorize",
                    json={"description": "http login page with a sql error and a jwt cookie"})
    j = r.get_json() or {}
    check("POST ctf/categorize", j.get("category") == "web", f"category={j.get('category')}")

    # Non-weaponizing boundary must be present in the advisor's output.
    r = client.post("/api/exploit/advise", json={"query": "SQL injection in login form"})
    j = r.get_json() or {}
    check("exploit advisor stays non-weaponizing",
          "disclaimer" in j and "remediation" in j and "does not generate" in j.get("disclaimer", ""),
          "disclaimer + remediation present")

    r = client.get("/api/processes/dashboard")
    check("GET /api/processes/dashboard", r.status_code == 200)

    r = client.get("/api/unknown/route")
    check("unknown route -> 404 JSON", r.status_code == 404 and (r.get_json() or {}).get("error"))

    return _summary()


def _summary() -> int:
    passed = sum(1 for _, ok in _results if ok)
    total = len(_results)
    ok = passed == total
    color = _G if ok else _R
    print(f"\n{color}{passed}/{total} checks passed{_X}")
    if not ok:
        print("Failing checks:")
        for name, res in _results:
            if not res:
                print(f"  - {name}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
