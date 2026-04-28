"""Phase registry for Counterscarp Engine scan pipeline."""

from __future__ import annotations

from scan_phase import ScanContext, ScanPhase  # noqa: F401 — re-export for consumers

from phases.static_analysis import AderynPhase, SlitherPhase, SupplyChainPhase
from phases.fuzzing import FoundryFuzzPhase, MedusaFuzzPhase
from phases.heuristic import FingerprintPhase, HeuristicPhase, PluginPhase, SymbolicPhase
from phases.analysis import SolanaPhase, UpgradeDiffPhase
from phases.enrichment import ExploitGenPhase, HistoryPhase, RagEnrichPhase
from phases.reporting import ReportPhase

__all__ = [
    "ScanContext",
    "ScanPhase",
    "SupplyChainPhase",
    "SlitherPhase",
    "AderynPhase",
    "FoundryFuzzPhase",
    "MedusaFuzzPhase",
    "HeuristicPhase",
    "PluginPhase",
    "FingerprintPhase",
    "SymbolicPhase",
    "SolanaPhase",
    "UpgradeDiffPhase",
    "RagEnrichPhase",
    "ExploitGenPhase",
    "HistoryPhase",
    "ReportPhase",
    "PHASE_REGISTRY",
]

#: Ordered list of all scan phases. The orchestrator iterates this list.
#: Phase execution order MUST be preserved — some phases depend on results
#: from earlier phases (e.g. ExploitGen needs heuristic_results + static_issues).
PHASE_REGISTRY: list[ScanPhase] = [
    SupplyChainPhase(group=0),                          # Phase 1
    SlitherPhase(group=1, parallel=True),               # Phase 2
    AderynPhase(group=1, parallel=True),                # Phase 2B
    FoundryFuzzPhase(group=2, parallel=True),           # Phase 3
    MedusaFuzzPhase(group=2, parallel=True),            # Phase 3B
    HeuristicPhase(group=3, parallel=True),             # Phase 4
    PluginPhase(group=4),                               # Phase 4C
    FingerprintPhase(group=3, parallel=True),           # Phase 4B
    SymbolicPhase(group=5),                             # Phase 5
    SolanaPhase(group=6, parallel=True),                # Phase 6
    UpgradeDiffPhase(group=6, parallel=True),           # Phase 7
    RagEnrichPhase(group=7),                            # Phase 7.5
    ExploitGenPhase(group=8, parallel=True),            # Phase 8
    HistoryPhase(group=8, parallel=True),               # Phase 8B
    ReportPhase(group=9),                               # Phase 9
]
