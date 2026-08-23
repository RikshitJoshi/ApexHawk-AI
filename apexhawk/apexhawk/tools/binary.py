"""Binary analysis, CTF & forensics tool wrappers (scaffold category).

These operate on local files you provide (``file`` parameter), so no network
scope check applies.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .base import BaseTool
from .registry import REGISTRY


class StringsExtract(BaseTool):
    name = "strings_extract"
    binary = "strings"
    category = "binary"
    description = "Extract printable strings from a file."
    requires_target = False
    default_timeout = 120

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        path = params.get("file")
        if not path:
            raise ValueError("strings requires a 'file' parameter")
        min_len = str(params.get("min_len", 6))
        cmd = ["strings", "-n", min_len, str(path)]
        cmd += self._extra_args(params)
        return cmd


class BinwalkScan(BaseTool):
    name = "binwalk_scan"
    binary = "binwalk"
    category = "binary"
    description = "Firmware/embedded-file analysis with binwalk."
    requires_target = False
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        path = params.get("file")
        if not path:
            raise ValueError("binwalk requires a 'file' parameter")
        cmd = ["binwalk"]
        if params.get("extract"):
            cmd.append("-e")
        cmd += self._extra_args(params)
        cmd.append(str(path))
        return cmd


class ExiftoolScan(BaseTool):
    name = "exiftool_scan"
    binary = "exiftool"
    category = "binary"
    description = "Read file metadata with ExifTool."
    requires_target = False
    default_timeout = 120

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        path = params.get("file")
        if not path:
            raise ValueError("exiftool requires a 'file' parameter")
        cmd = ["exiftool", str(path)]
        cmd += self._extra_args(params)
        return cmd


for _t in (StringsExtract(), BinwalkScan(), ExiftoolScan()):
    REGISTRY.register(_t)
