"""ApexHawk AI - AI-powered MCP cybersecurity automation platform.

A framework that orchestrates standard, publicly available security tools
(nmap, nuclei, ffuf, subfinder, ...) and exposes them to MCP-compatible AI
agents. Intended strictly for authorized penetration testing, bug bounty
programs (within scope), CTFs, and security research on systems you own or
are explicitly permitted to test.
"""

from .config import VERSION

__version__ = VERSION
__all__ = ["__version__", "VERSION"]
