"""Cloud & container security tool wrappers (priority category).

These assess cloud accounts (via your configured credentials), container
images, or a local Kubernetes cluster, so they are not network-target tools
and are not scope-checked.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .base import BaseTool
from .registry import REGISTRY


class ProwlerAssess(BaseTool):
    name = "prowler_assess"
    binary = "prowler"
    category = "cloud"
    description = "AWS/Azure/GCP posture assessment with Prowler."
    requires_target = False
    default_timeout = 1800

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        provider = str(params.get("provider", "aws"))
        cmd = ["prowler", provider]
        cmd += self._extra_args(params)
        return cmd


class ScoutSuiteAudit(BaseTool):
    name = "scout_suite_audit"
    binary = "scout"
    category = "cloud"
    description = "Multi-cloud security auditing with Scout Suite."
    requires_target = False
    default_timeout = 1800

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        provider = str(params.get("provider", "aws"))
        cmd = ["scout", provider]
        cmd += self._extra_args(params)
        return cmd


class TrivyScan(BaseTool):
    name = "trivy_scan"
    binary = "trivy"
    category = "cloud"
    description = "Vulnerability/IaC scanning of images, filesystems or repos."
    requires_target = False
    default_timeout = 900

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        mode = str(params.get("mode", "image"))  # image | fs | repo | config
        ref = params.get("target_ref")
        if not ref:
            raise ValueError("trivy requires a 'target_ref' (image name, path, or repo)")
        cmd = ["trivy", mode, str(ref)]
        cmd += self._extra_args(params)
        return cmd


class KubeHunterScan(BaseTool):
    name = "kube_hunter_scan"
    binary = "kube-hunter"
    category = "cloud"
    description = "Kubernetes weakness discovery with kube-hunter."
    requires_target = False
    default_timeout = 900

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        cmd = ["kube-hunter"]
        # default to the least intrusive mode unless the operator overrides
        if not self._extra_args(params):
            cmd += ["--pod"] if params.get("pod") else ["--list"]
        cmd += self._extra_args(params)
        return cmd


class KubeBenchCheck(BaseTool):
    name = "kube_bench_check"
    binary = "kube-bench"
    category = "cloud"
    description = "CIS Kubernetes benchmark checks with kube-bench."
    requires_target = False
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> List[str]:
        cmd = ["kube-bench"]
        cmd += self._extra_args(params)
        return cmd


for _t in (
    ProwlerAssess(), ScoutSuiteAudit(), TrivyScan(), KubeHunterScan(), KubeBenchCheck(),
):
    REGISTRY.register(_t)
