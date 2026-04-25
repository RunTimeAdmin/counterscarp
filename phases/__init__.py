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
    SupplyChainPhase(),    # Phase 1
    SlitherPhase(),        # Phase 2
    AderynPhase(),         # Phase 2B
    FoundryFuzzPhase(),    # Phase 3
    MedusaFuzzPhase(),     # Phase 3B
    HeuristicPhase(),      # Phase 4
    PluginPhase(),         # Phase 4C
    FingerprintPhase(),    # Phase 4B
    SymbolicPhase(),       # Phase 5
    SolanaPhase(),         # Phase 6
    UpgradeDiffPhase(),    # Phase 7
    RagEnrichPhase(),      # Phase 7.5
    ExploitGenPhase(),     # Phase 8
    HistoryPhase(),        # Phase 8B
    ReportPhase(),         # Phase 9
]
