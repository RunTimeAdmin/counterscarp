from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class EngineConfig:
    """Engine-wide settings."""
    name: str
    version: str
    fail_on_severity: str
    max_findings: int


@dataclass
class HeuristicConfig:
    """Heuristic scanning configuration."""
    enabled: bool
    severity_overrides: Dict[str, str]
    disabled_rules: Dict[str, bool]

    def is_rule_enabled(self, rule_id: str) -> bool: ...
    def get_rule_severity(self, rule_id: str, default_severity: str) -> str: ...


@dataclass
class Suppression:
    """Represents a single suppression rule."""
    rule_id: str
    file: Optional[str]
    line: Optional[int]
    reason: str
    expires: Optional[str]

    def matches(self, rule_id: str, file_path: str, line_no: int) -> bool: ...
    def _file_matches(self, suppression_file: str, target_file: str) -> bool: ...


@dataclass
class StaticAnalysisConfig:
    """Static analyzer settings."""
    slither_enabled: bool
    slither_exclude_detectors: str
    slither_include_impact: str
    aderyn_enabled: bool
    aderyn_scope: str


@dataclass
class FuzzingConfig:
    """Fuzzing configuration."""
    foundry_enabled: bool
    foundry_runs: int
    foundry_max_test_rejects: int
    medusa_enabled: bool
    medusa_test_limit: int
    medusa_timeout: int
    medusa_workers: int


@dataclass
class SolanaIDLConfig:
    """Solana IDL validation settings."""
    idl_path: str
    validate_constraints: bool
    trace_cpi: bool


@dataclass
class ChainConfig:
    """Chain-specific settings."""
    solana_enabled: bool
    solana_project_root: str
    solana_idl: SolanaIDLConfig
    evm_solc_version: str
    evm_trusted_contracts: List[str]


@dataclass
class UpgradeDiffConfig:
    """Upgrade safety settings."""
    old_implementation_path: str
    new_implementation_path: str
    ignore_new_view_functions: bool
    ignore_comment_changes: bool


@dataclass
class ReportingConfig:
    """Reporting settings."""
    format: str
    executive_summary: bool
    supply_chain: bool
    static_analysis: bool
    heuristic_scan: bool
    fuzzing: bool
    threat_intel: bool
    access_matrix: bool
    verbosity: str
    group_by: str


@dataclass
class CIGeneratorConfig:
    """CI/CD pipeline generator settings."""
    platform: str
    triggers: List[str]
    notifications: List[str]
    custom_steps: List[str]


@dataclass
class CIConfig:
    """CI/CD integration settings."""
    fail_on_findings: bool
    post_pr_comment: bool
    upload_sarif: bool
    exclude_paths: List[str]
    generator: Optional[CIGeneratorConfig]


@dataclass
class RedTeamConfig:
    """Red team scan configuration."""
    severity_allowlist: List[str]
    ignore_checks: List[str]


@dataclass
class ExternalToolsConfig:
    """External tool timeouts and settings."""
    aderyn_timeout: int
    mythril_timeout: int
    foundry_fuzz_runs: int


@dataclass
class SupplyChainConfig:
    """Supply chain security configuration."""
    ecosystem: str
    osv_timeout: int
    osv_max_retries: int
    osv_rate_limit: int


@dataclass
class ThreatIntelConfig:
    """Threat intelligence configuration."""
    c4_timeout: int
    immunefi_timeout: int
    solana_github_timeout: int
    api_rate_limit: int


@dataclass
class HttpConfig:
    """HTTP client configuration."""
    default_timeout: int
    max_retries: int
    base_delay: float
    max_delay: float
    backoff_factor: float


@dataclass
class ExploitGenerationConfig:
    """Exploit PoC auto-generation configuration."""
    auto_generate: bool
    min_severity: str
    validate_compilation: bool
    output_dir: str
    llm_backend: str
    template_dir: str


@dataclass
class FingerprintConfig:
    """Protocol fingerprint scanner configuration."""
    enabled: bool
    min_similarity: float
    database_path: str
    include_risk_assessment: bool


@dataclass
class VisualizationConfig:
    """Attack graph visualization configuration."""
    enabled: bool
    include_source_analysis: bool
    trace_attack_paths: bool
    output_format: str
    max_path_depth: int


@dataclass
class HistoryConfig:
    """History scanning configuration."""
    max_commits: int
    scan_branches: List[str]
    include_fixed: bool
    output_dir: str


@dataclass
class AIConfig:
    """AI and RAG configuration."""
    embedding_backend: str
    llm_backend: str
    openai_model: str
    rag_index_path: str
    top_k: int
    auto_enrich: bool


@dataclass
class PluginsConfig:
    """Plugin system configuration."""
    enabled: bool
    dirs: List[str]


@dataclass
class GarrisonConfig:
    """Root configuration object."""
    engine: EngineConfig
    heuristics: HeuristicConfig
    suppressions: List[Suppression]
    static_analysis: StaticAnalysisConfig
    fuzzing: FuzzingConfig
    chains: ChainConfig
    upgrade_diff: UpgradeDiffConfig
    reporting: ReportingConfig
    ci: CIConfig
    red_team: RedTeamConfig
    external_tools: ExternalToolsConfig
    supply_chain: SupplyChainConfig
    threat_intel: ThreatIntelConfig
    http: HttpConfig
    exploit_generation: ExploitGenerationConfig
    history: HistoryConfig
    visualization: VisualizationConfig
    fingerprint: FingerprintConfig
    ai: AIConfig
    plugins: PluginsConfig

    def is_finding_suppressed(
        self, rule_id: str, file_path: str, line_no: int
    ) -> Optional[Suppression]: ...


def load_config(config_path: Optional[str] = None) -> GarrisonConfig: ...
def find_config_file() -> Optional[str]: ...
def validate_config(config: dict) -> list[str]: ...
def print_config_summary(config: GarrisonConfig) -> None: ...
