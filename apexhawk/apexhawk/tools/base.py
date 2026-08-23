"""BaseTool - common contract for every wrapped security tool.

Each wrapper declares its binary, category and how to build an argv list from a
parameter dict. ``run`` handles the cross-cutting concerns every tool needs:

  1. scope enforcement  - refuse targets outside the authorized scope
  2. availability check  - degrade gracefully if the binary is not installed
  3. execution           - via the shared CommandExecutor (cache + telemetry)
  4. parsing             - optional per-tool extraction of structured findings
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..config import ScopeConfig
from ..executor import CommandExecutor, CommandResult


class BaseTool:
    name: str = "base"
    binary: str = ""
    category: str = "misc"
    description: str = ""
    #: whether params must include an in-scope ``target``
    requires_target: bool = True
    #: default per-run timeout (seconds); None -> executor default
    default_timeout: Optional[int] = None

    # -- to be overridden ------------------------------------------------
    def build_command(self, params: Dict[str, Any]) -> List[str]:
        raise NotImplementedError

    def parse_output(self, result: CommandResult, params: Dict[str, Any]) -> List[dict]:
        """Return a list of structured findings. Default: none."""
        return []

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _extra_args(params: Dict[str, Any]) -> List[str]:
        """Whitelisted pass-through of additional argv items (never shell)."""
        extra = params.get("extra_args") or []
        if isinstance(extra, str):
            import shlex

            extra = shlex.split(extra)
        return [str(a) for a in extra]

    def _base_response(self, params: Dict[str, Any]) -> dict:
        return {
            "tool": self.name,
            "category": self.category,
            "target": params.get("target"),
            "available": None,
            "authorized": None,
            "success": False,
            "command": None,
            "returncode": None,
            "duration": 0.0,
            "cached": False,
            "timed_out": False,
            "stdout": "",
            "stderr": "",
            "findings": [],
            "error": None,
        }

    # -- orchestration ---------------------------------------------------
    def run(self, params: Dict[str, Any], executor: CommandExecutor,
            scope: ScopeConfig) -> dict:
        response = self._base_response(params)

        # 1) scope enforcement
        if self.requires_target:
            target = params.get("target")
            if not target:
                response["error"] = "missing required parameter: target"
                response["authorized"] = False
                return response
            if not scope.is_authorized(target):
                response["authorized"] = False
                response["error"] = (
                    f"target '{target}' is outside the authorized testing scope; "
                    "add it to scope.json or set allow_any for lab use"
                )
                return response
            response["authorized"] = True

        # 2) availability
        if self.binary and not executor.check_tool(self.binary):
            response["available"] = False
            response["error"] = (
                f"'{self.binary}' is not installed / not on PATH - skipping "
                "(install it from its official source to enable this tool)"
            )
            return response
        response["available"] = True

        # 3) build + execute
        try:
            argv = self.build_command(params)
        except Exception as exc:
            response["error"] = f"failed to build command: {exc}"
            return response

        result = executor.run(
            argv,
            timeout=params.get("timeout", self.default_timeout),
            use_cache=params.get("use_cache", True),
            tool_name=self.name,
        )
        response.update(
            command=result.command,
            success=result.success,
            returncode=result.returncode,
            duration=result.duration,
            cached=result.cached,
            timed_out=result.timed_out,
            stdout=result.stdout,
            stderr=result.stderr,
            error=result.error,
        )

        # 4) parse
        try:
            response["findings"] = self.parse_output(result, params) or []
        except Exception as exc:  # parsing must never crash a run
            response["findings"] = []
            response["parse_error"] = str(exc)

        return response
