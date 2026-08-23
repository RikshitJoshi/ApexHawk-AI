"""ModernVisualEngine - terminal output styling for ApexHawk.

Dependency-free ANSI styling: banner, section headers, severity-coloured
vulnerability cards, progress bars and tool-status lines. Colours auto-disable
when stdout is not a TTY or when NO_COLOR / APEXHAWK_NO_COLOR is set.
"""

from __future__ import annotations

import os
import sys
import shutil
from typing import Iterable, Optional

from .config import PRODUCT_NAME, TAGLINE, VERSION


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("APEXHAWK_NO_COLOR"):
        return False
    return sys.stdout.isatty()


class C:
    """ANSI colour codes (blanked out when colour is disabled)."""

    _on = _color_enabled()

    RESET = "\033[0m" if _on else ""
    BOLD = "\033[1m" if _on else ""
    DIM = "\033[2m" if _on else ""

    RED = "\033[38;5;196m" if _on else ""
    CRIMSON = "\033[38;5;160m" if _on else ""
    ROSE = "\033[38;5;210m" if _on else ""
    ORANGE = "\033[38;5;208m" if _on else ""
    YELLOW = "\033[38;5;220m" if _on else ""
    GREEN = "\033[38;5;46m" if _on else ""
    CYAN = "\033[38;5;51m" if _on else ""
    BLUE = "\033[38;5;39m" if _on else ""
    GREY = "\033[38;5;245m" if _on else ""
    WHITE = "\033[38;5;231m" if _on else ""


SEVERITY_COLORS = {
    "critical": C.CRIMSON,
    "high": C.RED,
    "medium": C.ORANGE,
    "low": C.YELLOW,
    "info": C.CYAN,
    "unknown": C.GREY,
}


class ModernVisualEngine:
    """Renders ApexHawk's real-time visual output."""

    @staticmethod
    def banner() -> str:
        art = r"""
    _                      _   _                _
   / \   _ __   _____  __ | | | | __ ___      _| | __
  / _ \ | '_ \ / _ \ \/ / | |_| |/ _` \ \ /\ / / |/ /
 / ___ \| |_) |  __/>  <  |  _  | (_| |\ V  V /|   <
/_/   \_\ .__/ \___/_/\_\ |_| |_|\__,_| \_/\_/ |_|\_\
        |_|
"""
        return (
            f"{C.RED}{C.BOLD}{art}{C.RESET}\n"
            f"  {C.WHITE}{C.BOLD}{PRODUCT_NAME}{C.RESET} "
            f"{C.GREY}v{VERSION}{C.RESET} - {C.ROSE}{TAGLINE}{C.RESET}\n"
            f"  {C.DIM}Authorized security testing only. You are responsible for "
            f"staying in scope.{C.RESET}\n"
        )

    @staticmethod
    def section(title: str) -> str:
        line = "-" * max(8, 60 - len(title))
        return f"\n{C.RED}{C.BOLD}[ {title} ]{C.RESET} {C.DIM}{line}{C.RESET}"

    @staticmethod
    def info(msg: str) -> str:
        return f"{C.CYAN}[*]{C.RESET} {msg}"

    @staticmethod
    def success(msg: str) -> str:
        return f"{C.GREEN}[+]{C.RESET} {msg}"

    @staticmethod
    def warn(msg: str) -> str:
        return f"{C.YELLOW}[!]{C.RESET} {msg}"

    @staticmethod
    def error(msg: str) -> str:
        return f"{C.RED}[x]{C.RESET} {msg}"

    @staticmethod
    def tool_status(name: str, state: str, detail: str = "") -> str:
        icons = {
            "running": (C.YELLOW, "RUN"),
            "done": (C.GREEN, "OK "),
            "failed": (C.RED, "ERR"),
            "skipped": (C.GREY, "SKIP"),
            "missing": (C.ORANGE, "N/A"),
        }
        color, tag = icons.get(state, (C.GREY, "?"))
        detail = f" {C.DIM}{detail}{C.RESET}" if detail else ""
        return f"  {color}[{tag}]{C.RESET} {C.BOLD}{name}{C.RESET}{detail}"

    @staticmethod
    def progress_bar(current: int, total: int, width: int = 30, label: str = "") -> str:
        total = max(total, 1)
        frac = max(0.0, min(1.0, current / total))
        filled = int(frac * width)
        bar = "#" * filled + "-" * (width - filled)
        pct = int(frac * 100)
        label = f" {label}" if label else ""
        return f"{C.RED}[{bar}]{C.RESET} {C.BOLD}{pct:3d}%{C.RESET}{label}"

    @staticmethod
    def vulnerability_card(finding: dict) -> str:
        sev = str(finding.get("severity", "unknown")).lower()
        color = SEVERITY_COLORS.get(sev, C.GREY)
        title = finding.get("title", "Unnamed finding")
        target = finding.get("target", "-")
        tool = finding.get("tool", "-")
        desc = finding.get("description", "")
        ref = finding.get("reference", "")

        width = min(shutil.get_terminal_size((80, 20)).columns, 88)
        top = "+" + "-" * (width - 2) + "+"

        def row(text: str) -> str:
            text = text[: width - 4]
            return f"| {text:<{width - 4}} |"

        lines = [
            f"{color}{top}",
            row(f"[{sev.upper()}] {title}"),
            f"{C.RESET}{color}" + "+" + "-" * (width - 2) + "+",
            f"{C.RESET}" + row(f"target : {target}"),
            row(f"tool   : {tool}"),
        ]
        if desc:
            lines.append(row(f"detail : {desc}"))
        if ref:
            lines.append(row(f"ref    : {ref}"))
        lines.append(f"{color}{top}{C.RESET}")
        return "\n".join(lines)

    @staticmethod
    def render_findings(findings: Iterable[dict]) -> str:
        cards = [ModernVisualEngine.vulnerability_card(f) for f in findings]
        return "\n".join(cards) if cards else ModernVisualEngine.info("No findings.")
