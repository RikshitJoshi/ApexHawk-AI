"""Authentication & password security tool wrappers (scaffold category).

Network credential attacks (hydra) are scope-enforced like any other
target-bearing tool. Offline hash tools (john, hashcat) operate on local files
you supply and are commonly used against authorized/CTF hashes.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .base import BaseTool
from .registry import REGISTRY


class HydraBruteforce(BaseTool):
    name = "hydra_bruteforce"
    binary = "hydra"
    category = "auth"
    description = "Network login testing with Hydra (scope-enforced target)."
    default_timeout = 1800

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        service = params.get("service")
        if not service:
            raise ValueError("hydra requires a 'service' parameter (e.g. ssh, ftp)")
        cmd = ["hydra"]
        if params.get("username"):
            cmd += ["-l", str(params["username"])]
        elif params.get("userlist"):
            cmd += ["-L", str(params["userlist"])]
        if params.get("password"):
            cmd += ["-p", str(params["password"])]
        elif params.get("passlist"):
            cmd += ["-P", str(params["passlist"])]
        if params.get("port"):
            cmd += ["-s", str(params["port"])]
        cmd += self._extra_args(params)
        cmd += [params["target"], str(service)]
        return cmd


class JohnCrack(BaseTool):
    name = "john_crack"
    binary = "john"
    category = "auth"
    description = "Offline hash cracking with John the Ripper (local hash file)."
    requires_target = False
    default_timeout = 1800

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        hashfile = params.get("hashfile")
        if not hashfile:
            raise ValueError("john requires a 'hashfile' parameter")
        cmd = ["john"]
        if params.get("wordlist"):
            cmd.append(f"--wordlist={params['wordlist']}")
        if params.get("format"):
            cmd.append(f"--format={params['format']}")
        cmd += self._extra_args(params)
        cmd.append(str(hashfile))
        return cmd


class HashcatCrack(BaseTool):
    name = "hashcat_crack"
    binary = "hashcat"
    category = "auth"
    description = "GPU-accelerated hash cracking with hashcat (local hash file)."
    requires_target = False
    default_timeout = 3600

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        hashfile = params.get("hashfile")
        mode = params.get("mode")
        wordlist = params.get("wordlist")
        if not (hashfile and mode is not None and wordlist):
            raise ValueError("hashcat requires 'hashfile', 'mode', and 'wordlist'")
        cmd = ["hashcat", "-m", str(mode), "-a", "0", str(hashfile), str(wordlist)]
        cmd += self._extra_args(params)
        return cmd


for _t in (HydraBruteforce(), JohnCrack(), HashcatCrack()):
    REGISTRY.register(_t)
