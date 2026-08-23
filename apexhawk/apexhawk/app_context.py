"""AppContext - wires together the shared singletons used across the server.

One context is built at startup and shared by every request handler and the
CLI, so caches, telemetry and the process registry are consistent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .cache import SmartCache
from .config import ScopeConfig, load_scope
from .executor import CommandExecutor
from .process_manager import ProcessManager
from .tools import REGISTRY
from .intelligence import (
    BugBountyWorkflowManager,
    CTFWorkflowManager,
    CVEIntelligenceManager,
    ExploitAdvisor,
    FailureRecoverySystem,
    GracefulDegradation,
    IntelligentDecisionEngine,
    ParameterOptimizer,
    PerformanceMonitor,
    RateLimitDetector,
)


@dataclass
class AppContext:
    cache: SmartCache
    processes: ProcessManager
    executor: CommandExecutor
    registry: object
    scope: ScopeConfig
    decision_engine: IntelligentDecisionEngine
    optimizer: ParameterOptimizer
    bugbounty: BugBountyWorkflowManager
    ctf: CTFWorkflowManager
    cve_intel: CVEIntelligenceManager
    exploit_advisor: ExploitAdvisor
    rate_limiter: RateLimitDetector
    degradation: GracefulDegradation
    recovery: FailureRecoverySystem
    perfmon: PerformanceMonitor


def build_context(scope_path: Optional[str] = None) -> AppContext:
    cache = SmartCache()
    processes = ProcessManager()
    executor = CommandExecutor(cache=cache, process_manager=processes)
    scope = load_scope(scope_path)
    registry = REGISTRY

    cve_intel = CVEIntelligenceManager()
    return AppContext(
        cache=cache,
        processes=processes,
        executor=executor,
        registry=registry,
        scope=scope,
        decision_engine=IntelligentDecisionEngine(registry=registry),
        optimizer=ParameterOptimizer(),
        bugbounty=BugBountyWorkflowManager(registry=registry),
        ctf=CTFWorkflowManager(),
        cve_intel=cve_intel,
        exploit_advisor=ExploitAdvisor(executor=executor, cve_intel=cve_intel),
        rate_limiter=RateLimitDetector(),
        degradation=GracefulDegradation(registry=registry, executor=executor),
        recovery=FailureRecoverySystem(),
        perfmon=PerformanceMonitor(executor=executor),
    )
