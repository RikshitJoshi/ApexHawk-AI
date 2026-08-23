"""Flask HTTP API - every endpoint documented in the README's API Reference."""

from __future__ import annotations

from typing import Any, Dict

from flask import Flask, jsonify, request

from .. import config
from ..app_context import AppContext


def _want_json() -> Dict[str, Any]:
    return request.get_json(silent=True) or {}


def create_app(context: AppContext) -> Flask:
    app = Flask("apexhawk")

    # -- optional bearer-token auth on /api/* ----------------------------
    @app.before_request
    def _auth_gate():
        if config.API_TOKEN and request.path.startswith("/api/"):
            sent = request.headers.get("Authorization", "")
            if sent != f"Bearer {config.API_TOKEN}":
                return jsonify({"error": "unauthorized"}), 401
        return None

    # -- health ----------------------------------------------------------
    @app.get("/health")
    def health():
        avail = context.registry.availability_report(context.executor)
        return jsonify({
            "status": "ok",
            "product": config.PRODUCT_NAME,
            "version": config.VERSION,
            "tools": avail,
            "scope": context.scope.summary(),
            "arbitrary_commands_enabled": config.ALLOW_ARBITRARY_COMMANDS,
        })

    # -- arbitrary command (gated) --------------------------------------
    @app.post("/api/command")
    def run_command():
        if not config.ALLOW_ARBITRARY_COMMANDS:
            return jsonify({
                "error": "arbitrary command execution is disabled; start the server "
                         "with APEXHAWK_ALLOW_CMD=1 to enable it (localhost only)."
            }), 403
        body = _want_json()
        command = body.get("command")
        if not command:
            return jsonify({"error": "missing 'command'"}), 400
        result = context.executor.run(command, timeout=body.get("timeout"),
                                      use_cache=body.get("use_cache", True))
        return jsonify(result.to_dict())

    # -- telemetry / cache ----------------------------------------------
    @app.get("/api/telemetry")
    def telemetry():
        return jsonify(context.perfmon.snapshot())

    @app.get("/api/cache/stats")
    def cache_stats():
        return jsonify(context.cache.stats())

    @app.post("/api/cache/clear")
    def cache_clear():
        return jsonify({"cleared_entries": context.cache.clear()})

    # -- intelligence ----------------------------------------------------
    @app.post("/api/intelligence/analyze-target")
    def analyze_target():
        body = _want_json()
        target = body.get("target", "")
        return jsonify(context.decision_engine.analyze_target(target))

    @app.post("/api/intelligence/select-tools")
    def select_tools():
        body = _want_json()
        return jsonify(context.decision_engine.select_tools(
            body.get("target", ""), body.get("objective", "full")))

    @app.post("/api/intelligence/optimize-parameters")
    def optimize_parameters():
        body = _want_json()
        tool = body.get("tool", "")
        profile = context.decision_engine.analyze_target(body.get("target", ""))
        return jsonify({"tool": tool, "profile": profile,
                        "parameters": context.optimizer.optimize(tool, profile)})

    # -- tools -----------------------------------------------------------
    @app.get("/api/tools/list")
    def tools_list():
        return jsonify({
            "catalogue": context.registry.catalogue(),
            "by_category": context.registry.by_category(),
            "availability": context.registry.availability_report(context.executor),
        })

    @app.post("/api/tools/<name>/run")
    def tool_run(name: str):
        tool = context.registry.get(name)
        if not tool:
            return jsonify({"error": f"unknown tool '{name}'"}), 404
        params = _want_json()
        result = tool.run(params, context.executor, context.scope)
        # enrich with rate-limit + recovery advice
        blob = (result.get("stdout", "") + result.get("stderr", ""))
        result["rate_limit"] = context.rate_limiter.inspect(blob)
        if not result.get("success"):
            result["recovery"] = context.recovery.recommend(result)
        return jsonify(result)

    # -- workflows / CTF / CVE / advisor --------------------------------
    @app.post("/api/workflows/bugbounty")
    def bugbounty_plan():
        body = _want_json()
        return jsonify(context.bugbounty.plan(body.get("target", "")))

    @app.post("/api/ctf/categorize")
    def ctf_categorize():
        body = _want_json()
        return jsonify(context.ctf.categorize(body.get("description", "")))

    @app.post("/api/cve/search")
    def cve_search():
        body = _want_json()
        return jsonify(context.cve_intel.search(body.get("keyword", ""),
                                                body.get("limit", 10)))

    @app.get("/api/cve/<cve_id>")
    def cve_get(cve_id: str):
        return jsonify(context.cve_intel.get(cve_id))

    @app.post("/api/exploit/advise")
    def exploit_advise():
        body = _want_json()
        return jsonify(context.exploit_advisor.advise(body.get("query", "")))

    # -- process management ---------------------------------------------
    @app.get("/api/processes/list")
    def processes_list():
        return jsonify({"processes": context.processes.list()})

    @app.get("/api/processes/status/<int:pid>")
    def process_status(pid: int):
        status = context.processes.status(pid)
        if status is None:
            return jsonify({"error": f"no managed process with pid {pid}"}), 404
        return jsonify(status)

    @app.post("/api/processes/terminate/<int:pid>")
    def process_terminate(pid: int):
        body = _want_json()
        return jsonify(context.processes.terminate(pid, force=bool(body.get("force"))))

    @app.get("/api/processes/dashboard")
    def process_dashboard():
        return jsonify(context.processes.dashboard())

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "not found"}), 404

    return app
