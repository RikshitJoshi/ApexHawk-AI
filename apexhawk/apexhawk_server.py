#!/usr/bin/env python3
"""ApexHawk AI - HTTP API server entry point.

Starts the Flask API that wraps the security-tool arsenal and the intelligence
layer. Binds to loopback by default; exposing it more widely is an explicit,
deliberate choice because this server can execute security tools.

    python3 apexhawk_server.py                 # 127.0.0.1:8888
    python3 apexhawk_server.py --port 9000 --debug
    APEXHAWK_ALLOW_CMD=1 python3 apexhawk_server.py --allow-command
"""

from __future__ import annotations

import argparse
import sys

from apexhawk import config
from apexhawk.app_context import build_context
from apexhawk.api import create_app
from apexhawk.visual import C, ModernVisualEngine


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="ApexHawk AI MCP server")
    p.add_argument("--host", default=config.DEFAULT_HOST,
                   help="bind address (default 127.0.0.1; use 0.0.0.0 with care)")
    p.add_argument("--port", type=int, default=config.DEFAULT_PORT)
    p.add_argument("--scope", default=None, help="path to scope.json")
    p.add_argument("--allow-command", action="store_true",
                   help="enable the raw /api/command endpoint (localhost only)")
    p.add_argument("--debug", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    if args.allow_command:
        config.ALLOW_ARBITRARY_COMMANDS = True

    context = build_context(scope_path=args.scope)

    print(ModernVisualEngine.banner())
    avail = context.registry.availability_report(context.executor)
    print(ModernVisualEngine.info(
        f"Registered tools: {avail['total']}  "
        f"(available: {avail['available']}, missing: {avail['missing']})"))
    if context.scope.allow_any:
        print(ModernVisualEngine.warn(
            "scope.allow_any is TRUE - every target is authorized. Use only in a lab."))
    elif not (context.scope.domains or context.scope.hosts or context.scope.cidrs):
        print(ModernVisualEngine.warn(
            "No authorized scope configured - target-bearing tools will refuse to "
            "run. Create scope.json (see scope.json.example)."))
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(ModernVisualEngine.warn(
            f"Binding to {args.host} - the tool-execution API will be reachable off-host."))
    if config.ALLOW_ARBITRARY_COMMANDS:
        print(ModernVisualEngine.warn(
            "Raw /api/command endpoint is ENABLED."))
    print(ModernVisualEngine.success(
        f"ApexHawk API listening on http://{args.host}:{args.port}"))
    print(f"{C.DIM}Press Ctrl+C to stop.{C.RESET}\n")

    app = create_app(context)
    try:
        app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)
    except KeyboardInterrupt:
        print("\n" + ModernVisualEngine.info("Shutting down. Bye."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
