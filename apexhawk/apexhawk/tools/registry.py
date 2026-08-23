"""ToolRegistry - central catalogue of all wrapped tools."""

from __future__ import annotations

from typing import Dict, List, Optional

from .base import BaseTool


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> BaseTool:
        self._tools[tool.name] = tool
        return tool

    def get(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def all(self) -> List[BaseTool]:
        return list(self._tools.values())

    def names(self) -> List[str]:
        return sorted(self._tools.keys())

    def by_category(self) -> Dict[str, List[str]]:
        grouped: Dict[str, List[str]] = {}
        for tool in self._tools.values():
            grouped.setdefault(tool.category, []).append(tool.name)
        for names in grouped.values():
            names.sort()
        return grouped

    def catalogue(self) -> List[dict]:
        return [
            {
                "name": t.name,
                "binary": t.binary,
                "category": t.category,
                "description": t.description,
                "requires_target": t.requires_target,
            }
            for t in sorted(self._tools.values(), key=lambda x: (x.category, x.name))
        ]

    def availability_report(self, executor) -> dict:
        report: Dict[str, bool] = {}
        for tool in self._tools.values():
            report[tool.name] = bool(tool.binary) and executor.check_tool(tool.binary)
        available = sum(1 for v in report.values() if v)
        return {
            "total": len(report),
            "available": available,
            "missing": len(report) - available,
            "tools": report,
        }


#: process-wide registry; tool modules register into this on import
REGISTRY = ToolRegistry()
