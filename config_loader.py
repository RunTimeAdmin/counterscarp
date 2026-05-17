#!/usr/bin/env python3
"""
Configuration Loader for Counterscarp Engine.

Parses project TOML configuration and provides typed config access.
Supports `scarpshield.toml` (preferred) and `counterscarp.toml` (legacy).
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, Callable, ClassVar, Dict, List, Optional, Any, Type
from logging import Logger
from dataclasses import dataclass, field
from pathlib import Path

# Import exceptions (core module — must always be available)
from exceptions import CounterscarpValidationError, CounterscarpConfigError


CONFIG_FILE_CANDIDATES: tuple[str, ...] = (
    "scarpshield.toml",
    "counterscarp.toml",
)

LEGACY_PROFILE_PREFIX = "counterscarp-"
PREFERRED_PROFILE_PREFIX = "scarpshield-"

# Import logger with fallback
get_logger: Optional[Callable[[str], Logger]] = None
try:
    from logger import get_logger
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False

# Initialize logger
if LOGGER_AVAILABLE and get_logger is not None:
    logger = get_logger(__name__)
else:
    import logging
    logger = logging.getLogger(__name__)

# Try to import toml parser
try:
    import tomli as toml  # Python 3.11+ stdlib tomllib, or pip install tomli
except ImportError:
    try:
        import tomllib as toml  # Python 3.11+
    except ImportError:
        try:
            import toml  # type: ignore[import-untyped]  # Fallback to older toml package
        except ImportError:
            logger.error(
                "TOML parser not available. Install: pip install tomli"
            )
            toml = None


@dataclass
class EngineConfig:
    """Engine-wide settings.

    Attributes:
        name: Name of the security engine.
        version: Version string of the engine.
        fail_on_severity: Minimum severity level to fail on.
        max_findings: Maximum number of findings to report (0 = unlimited).
    """
    name: str = "Counterscarp Security Engine"
    version: str = "5.0.0"
    fail_on_severity: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    max_findings: int = 0  # 0 = unlimited


@dataclass
class HeuristicConfig:
    """Heuristic scanning configuration.

    Attributes:
        enabled: Whether heuristic scanning is enabled.
        severity_overrides: Dict mapping rule IDs to custom severity levels.
        disabled_rules: Dict mapping rule IDs to disabled status.
        min_confidence: Minimum confidence score (1-10) to include; 0 = show all.
        min_severity: Minimum severity level to include; INFO = show all.
    """
    enabled: bool = True
    severity_overrides: Dict[str, str] = field(default_factory=dict)
    disabled_rules: Dict[str, bool] = field(default_factory=dict)
    min_confidence: int = 0      # 0 = show all
    min_severity: str = "INFO"   # INFO = show all

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check if a rule is enabled.

        Args:
            rule_id: The ID of the rule to check.

        Returns:
            True if the rule is enabled, False otherwise.
        """
        return not self.disabled_rules.get(rule_id, False)

    def get_rule_severity(self, rule_id: str, default_severity: str) -> str:
        """Get effective severity for a rule (considering overrides).

        Args:
            rule_id: The ID of the rule.
            default_severity: Default severity if no override exists.

        Returns:
            The effective severity level.
        """
        return self.severity_overrides.get(rule_id, default_severity)


@dataclass
class Suppression:
    """Represents a single suppression rule.

    Attributes:
        rule_id: The ID of the rule to suppress.
        file: Optional file path to limit suppression scope.
        line: Optional line number to limit suppression scope.
        reason: Explanation for the suppression.
        expires: Optional ISO date string for expiration.
    """
    rule_id: str
    file: Optional[str] = None
    line: Optional[int] = None
    reason: str = ""
    expires: Optional[str] = None  # ISO date string

    def matches(self, rule_id: str, file_path: str, line_no: int) -> bool:
        """Check if this suppression applies to a finding.

        Args:
            rule_id: The ID of the rule that triggered the finding.
            file_path: Path to the file where the finding occurred.
            line_no: Line number where the finding occurred.

        Returns:
            True if this suppression applies to the finding.
        """
        # Rule ID must match
        if self.rule_id != rule_id:
            return False

        # If suppression specifies a file, it must match
        if self.file:
            # Use proper path normalization to avoid false positives
            # e.g., Oracle.sol should NOT match MyOracle.sol
            if not self._file_matches(self.file, file_path):
                return False

        # If suppression specifies a line, it must match
        if self.line is not None and self.line != line_no:
            return False

        # Check if suppression has expired
        if self.expires:
            from datetime import datetime
            try:
                expiry_date = datetime.fromisoformat(self.expires)
                if datetime.now() > expiry_date:
                    return False
            except ValueError as e:
                logger.warning(
                    f"Invalid expiry date format in suppression: {self.expires}. "
                    f"Error: {e}. Ignoring expiry check."
                )

        return True

    def _file_matches(self, suppression_file: str, target_file: str) -> bool:
        """Check if suppression_file matches target_file using proper path normalization.

        Uses exact basename matching or full path matching to avoid
        false positives (e.g., Oracle.sol matching MyOracle.sol).

        Args:
            suppression_file: The file pattern from the suppression rule.
            target_file: The actual file path being checked.

        Returns:
            True if the files match according to suppression rules.
        """
        # Normalize both paths
        norm_target = str(Path(target_file))
        norm_suppression = str(Path(suppression_file))

        # On Windows, make comparison case-insensitive
        if os.name == 'nt':
            norm_target = norm_target.lower()
            norm_suppression = norm_suppression.lower()

        # Get basenames for comparison
        target_basename = Path(norm_target).name
        suppression_basename = Path(norm_suppression).name

        # Exact basename match
        if target_basename == suppression_basename:
            return True

        # Full path match (for relative paths in config)
        if norm_target.endswith(norm_suppression):
            return True
        if norm_suppression in norm_target:
            # Additional check: ensure the match is at a path boundary
            # to avoid partial matches like 'Oracle' in 'MyOracle'
            idx = norm_target.find(norm_suppression)
            if idx != -1:
                # Check character before match is a path separator
                # or we're at the start
                if idx == 0 or norm_target[idx - 1] in ('/', '\\'):
                    return True

        return False


@dataclass
class StaticAnalysisConfig:
    """Static analyzer settings.

    Attributes:
        slither_enabled: Whether Slither analysis is enabled.
        slither_exclude_detectors: Comma-separated list of detectors to exclude.
        slither_include_impact: Severity levels to include in results.
        aderyn_enabled: Whether Aderyn analysis is enabled.
        aderyn_scope: Optional scope for Aderyn analysis.
    """
    slither_enabled: bool = True
    slither_exclude_detectors: str = ""
    slither_include_impact: str = "High,Medium"
    aderyn_enabled: bool = False
    aderyn_scope: str = ""


@dataclass
class FuzzingConfig:
    """Fuzzing configuration.

    Attributes:
        foundry_enabled: Whether Foundry fuzzing is enabled.
        foundry_runs: Number of fuzz runs to execute.
        foundry_max_test_rejects: Maximum rejected tests before stopping.
        medusa_enabled: Whether Medusa fuzzing is enabled.
        medusa_test_limit: Maximum number of test sequences.
        medusa_timeout: Timeout in seconds for Medusa fuzzing.
        medusa_workers: Number of parallel workers for Medusa.
    """
    foundry_enabled: bool = False
    foundry_runs: int = 10000
    foundry_max_test_rejects: int = 100000
    medusa_enabled: bool = False
    medusa_test_limit: int = 100000
    medusa_timeout: int = 300
    medusa_workers: int = 10


@dataclass
class SolanaIDLConfig:
    """Solana IDL validation settings.

    Attributes:
        idl_path: Path to IDL files.
        validate_constraints: Whether to validate IDL constraints.
        trace_cpi: Whether to trace CPI calls in IDL.
    """
    idl_path: str = "target/idl"
    validate_constraints: bool = True
    trace_cpi: bool = True


@dataclass
class ChainConfig:
    """Chain-specific settings.

    Attributes:
        solana_enabled: Whether Solana analysis is enabled.
        solana_project_root: Path to Solana program root directory.
        solana_idl: IDL validation configuration.
        evm_solc_version: Required Solidity compiler version.
        evm_trusted_contracts: List of trusted contract addresses.
    """
    solana_enabled: bool = False
    solana_project_root: str = "./programs"
    solana_idl: SolanaIDLConfig = field(default_factory=SolanaIDLConfig)
    evm_solc_version: str = ">=0.8.0"
    evm_trusted_contracts: List[str] = field(default_factory=list)


@dataclass
class UpgradeDiffConfig:
    """Upgrade safety settings.

    Attributes:
        old_implementation_path: Path to old contract implementation.
        new_implementation_path: Path to new contract implementation.
        ignore_new_view_functions: Whether to ignore new view functions.
        ignore_comment_changes: Whether to ignore comment-only changes.
    """
    old_implementation_path: str = ""
    new_implementation_path: str = ""
    ignore_new_view_functions: bool = True
    ignore_comment_changes: bool = True


@dataclass
class ReportingConfig:
    """Reporting settings.

    Attributes:
        format: Output format (markdown, json, html, sarif, pdf).
        executive_summary: Whether to include executive summary.
        supply_chain: Whether to include supply chain analysis.
        static_analysis: Whether to include static analysis results.
        heuristic_scan: Whether to include heuristic scan results.
        fuzzing: Whether to include fuzzing results.
        threat_intel: Whether to include threat intelligence.
        access_matrix: Whether to include access control matrix.
        verbosity: Report verbosity level (minimal, standard, verbose).
        group_by: How to group findings (severity, category, file).
    """
    format: str = "markdown"
    executive_summary: bool = True
    supply_chain: bool = True
    static_analysis: bool = True
    heuristic_scan: bool = True
    fuzzing: bool = False
    threat_intel: bool = False
    access_matrix: bool = True
    verbosity: str = "standard"
    group_by: str = "severity"

    # Valid output formats (used for validation)
    VALID_FORMATS: ClassVar[List[str]] = ["markdown", "json", "html", "sarif", "pdf"]


@dataclass
class CIGeneratorConfig:
    """CI/CD pipeline generator settings.

    Attributes:
        platform: Target platform for pipeline generation.
        triggers: List of pipeline triggers.
        notifications: List of notification channels.
        custom_steps: List of custom steps to add.
    """
    platform: str = "github"
    triggers: List[str] = field(
        default_factory=lambda: ["push", "pull_request"]
    )
    notifications: List[str] = field(default_factory=list)
    custom_steps: List[str] = field(default_factory=list)


@dataclass
class CIConfig:
    """CI/CD integration settings.

    Attributes:
        fail_on_findings: Whether to fail CI on findings.
        post_pr_comment: Whether to post findings as PR comments.
        upload_sarif: Whether to upload SARIF results.
        exclude_paths: List of path patterns to exclude from analysis.
        generator: Pipeline generator settings.
    """
    fail_on_findings: bool = True
    post_pr_comment: bool = True
    upload_sarif: bool = False
    exclude_paths: List[str] = field(default_factory=lambda: [
        "test/**", "script/**", "node_modules/**", ".git/**", "lib/**"
    ])
    generator: Optional[CIGeneratorConfig] = None


@dataclass
class RedTeamConfig:
    """Red team scan configuration.

    Attributes:
        severity_allowlist: List of severity levels to include in findings.
        ignore_checks: List of check IDs to ignore (noise filtering).
    """
    severity_allowlist: List[str] = field(default_factory=lambda: ["High", "Medium"])
    ignore_checks: List[str] = field(default_factory=lambda: [
        "solc-version",
        "naming-convention",
        "assembly",
        "redundant-statements"
    ])


@dataclass
class ExternalToolsConfig:
    """External tool timeouts and settings.

    Attributes:
        aderyn_timeout: Aderyn static analyzer timeout in seconds.
        mythril_timeout: Mythril symbolic execution timeout in seconds.
        foundry_fuzz_runs: Foundry fuzzing default runs.
    """
    aderyn_timeout: int = 120
    mythril_timeout: int = 600
    foundry_fuzz_runs: int = 1000


@dataclass
class SupplyChainConfig:
    """Supply chain security configuration.

    Attributes:
        ecosystem: Package ecosystem to check (npm, pypi, etc.).
        osv_timeout: OSV API timeout in seconds.
        osv_max_retries: OSV API max retries.
        osv_rate_limit: OSV API rate limit (requests per second).
    """
    ecosystem: str = "npm"
    osv_timeout: int = 10
    osv_max_retries: int = 3
    osv_rate_limit: int = 10


@dataclass
class ThreatIntelConfig:
    """Threat intelligence configuration.

    Attributes:
        c4_timeout: Code4rena GitHub API timeout in seconds.
        immunefi_timeout: Immunefi RSS feed timeout in seconds.
        solana_github_timeout: Solana intelligence GitHub API timeout in seconds.
        api_rate_limit: Default API rate limit (requests per second).
        offline_mode: Force offline mode (skip all network calls).
        bundled_db_path: Path to bundled threat intel database JSON file.
    """
    c4_timeout: int = 10
    immunefi_timeout: int = 10
    solana_github_timeout: int = 10
    api_rate_limit: int = 5
    offline_mode: bool = False      # Force offline mode (skip all network calls)
    bundled_db_path: str = "data/threat_intel_db.json"


@dataclass
class HttpConfig:
    """HTTP client configuration.

    Attributes:
        default_timeout: Default timeout for HTTP requests in seconds.
        max_retries: Default max retries for failed requests.
        base_delay: Base delay for exponential backoff in seconds.
        max_delay: Maximum delay cap for exponential backoff in seconds.
        backoff_factor: Backoff multiplier for exponential backoff.
    """
    default_timeout: int = 30
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    backoff_factor: float = 2.0


@dataclass
class ExploitGenerationConfig:
    """Exploit PoC auto-generation configuration.

    Attributes:
        auto_generate: Whether to automatically generate exploit PoCs.
        min_severity: Minimum severity level to generate exploits for.
        validate_compilation: Whether to validate generated exploits compile.
        output_dir: Directory to save generated exploit files.
        llm_backend: LLM backend to use ("none", "openai", "anthropic").
        template_dir: Directory containing exploit templates.
    """
    auto_generate: bool = False
    min_severity: str = "HIGH"
    validate_compilation: bool = True
    output_dir: str = "exploits/"
    llm_backend: str = "none"
    template_dir: str = "exploit_templates/"


@dataclass
class SafePattern:
    """A known-safe library/framework pattern that downgrades finding severity.

    Attributes:
        library: Human-readable library name (e.g., "OpenZeppelin.UUPS").
        rule_id: Rule ID to match against.
        pattern: Regex to match in import/inheritance lines.
        downgrade_to: Target severity (INFO, LOW, etc.).
        reason: Human-readable explanation.
    """
    library: str
    rule_id: str
    pattern: str
    downgrade_to: str
    reason: str


DEFAULT_SAFE_PATTERNS: List[SafePattern] = [
    SafePattern(
        "OpenZeppelin.UUPS", "STORAGE_COLLISION_RISK",
        r"import\s+.*@openzeppelin.*UUPSUpgradeable|is\s+UUPSUpgradeable",
        "INFO", "OpenZeppelin UUPS proxy follows audited standard storage layout"
    ),
    SafePattern(
        "OpenZeppelin.ReentrancyGuard", "REENTRANCY_PATTERN",
        r"import\s+.*@openzeppelin.*ReentrancyGuard|nonReentrant",
        "INFO", "Protected by OpenZeppelin ReentrancyGuard mutex"
    ),
    SafePattern(
        "Uniswap.Currency", "UNCHECKED_EXTERNAL_CALL",
        r"Currency\.transfer|CurrencyLibrary|import.*Currency",
        "INFO", "Uniswap Currency library wrapper, not a raw ETH transfer"
    ),
    SafePattern(
        "Uniswap.Permit2", "UNCHECKED_EXTERNAL_CALL",
        r"IAllowanceTransfer|ISignatureTransfer|import.*[Pp]ermit2",
        "INFO", "Uniswap Permit2 standard approval pattern"
    ),
    SafePattern(
        "OpenZeppelin.SafeERC20", "UNCHECKED_EXTERNAL_CALL",
        r"import\s+.*SafeERC20|using\s+SafeERC20|safeTransfer\(|safeTransferFrom\(",
        "INFO", "OpenZeppelin SafeERC20 handles return value checking"
    ),
    SafePattern(
        "OpenZeppelin.Initializable", "STORAGE_COLLISION_RISK",
        r"import\s+.*@openzeppelin.*Initializable|modifier\s+initializer",
        "LOW", "OpenZeppelin Initializable follows audited standard pattern"
    ),
    SafePattern(
        "OpenZeppelin.AccessControl", "MISSING_ACCESS_CONTROL",
        r"import\s+.*@openzeppelin.*AccessControl|hasRole\(|onlyRole\(",
        "INFO", "Protected by OpenZeppelin role-based AccessControl"
    ),
    SafePattern(
        "OpenZeppelin.Ownable", "MISSING_ACCESS_CONTROL",
        r"import\s+.*@openzeppelin.*Ownable|onlyOwner",
        "INFO", "Protected by OpenZeppelin Ownable modifier"
    ),
]


@dataclass
class SafePatternConfig:
    """Configuration for the context-aware severity whitelist.

    Attributes:
        enabled: Whether safe pattern matching is enabled.
        patterns: List of safe patterns to apply.
    """
    enabled: bool = True
    patterns: List[SafePattern] = field(
        default_factory=lambda: list(DEFAULT_SAFE_PATTERNS)
    )


@dataclass
class FingerprintConfig:
    """Protocol fingerprint scanner configuration.

    Attributes:
        enabled: Whether fingerprint scanning is enabled.
        min_similarity: Minimum similarity threshold (0.0-1.0).
        database_path: Path to custom fingerprint database JSON.
        include_risk_assessment: Whether to include risk assessment in results.
    """
    enabled: bool = False
    min_similarity: float = 0.7
    database_path: str = "data/protocol_fingerprints.json"
    include_risk_assessment: bool = True


@dataclass
class VisualizationConfig:
    """Attack graph visualization configuration.

    Attributes:
        enabled: Whether to generate attack graph visualizations.
        include_source_analysis: Whether to parse source files for
            contract structure.
        trace_attack_paths: Whether to trace attack paths through
            external calls.
        output_format: Output format ("html", "json", or "both").
        max_path_depth: Maximum depth for attack path tracing.
    """
    enabled: bool = False
    include_source_analysis: bool = True
    trace_attack_paths: bool = True
    output_format: str = "html"
    max_path_depth: int = 10


@dataclass
class HistoryConfig:
    """History scanning configuration.

    Attributes:
        max_commits: Maximum number of commits to scan.
        scan_branches: List of branches to scan.
        include_fixed: Whether to include fixed vulnerabilities in reports.
        output_dir: Directory to save history scan reports.
    """
    max_commits: int = 50
    scan_branches: List[str] = field(default_factory=lambda: ["main"])
    include_fixed: bool = True
    output_dir: str = "."


@dataclass
class AIConfig:
    """AI and RAG configuration.

    Attributes:
        embedding_backend: Backend for embeddings (local, openai, anthropic).
        llm_backend: LLM provider for generation ("none", "openai", "ollama").
        llm_model: Model name used for both OpenAI and Ollama.
        ollama_url: Ollama API base URL (only used when llm_backend="ollama").
        openai_model: Deprecated alias kept for backward compatibility.
        rag_index_path: Path to the RAG vector index.
        top_k: Number of similar findings to retrieve.
        auto_enrich: Whether to auto-enrich findings with RAG.
        llm_enrichment: Whether to enable LLM-powered finding analysis.
    """
    embedding_backend: str = "local"
    llm_backend: str = "none"
    llm_model: str = "gpt-4o-mini"
    ollama_url: str = "http://localhost:11434"
    openai_model: str = "gpt-4-turbo-preview"  # kept for backward compat
    rag_index_path: str = ".scarpshield/rag_index.json"
    top_k: int = 5
    auto_enrich: bool = False
    llm_enrichment: bool = False


@dataclass
class PluginsConfig:
    """Plugin system configuration.

    Attributes:
        enabled: Whether plugin system is enabled.
        dirs: List of directories to scan for plugins.
    """
    enabled: bool = True
    dirs: List[str] = field(default_factory=lambda: [".scarpshield/plugins"])


@dataclass
class LicenseConfig:
    """License configuration for Pro features.

    Attributes:
        key: Pro license key for unlocking premium features.
    """
    key: str = ""


@dataclass
class CounterscarpConfig:
    """Root configuration object.

    Attributes:
        engine: Engine-wide settings.
        heuristics: Heuristic scanning configuration.
        suppressions: List of active suppression rules.
        static_analysis: Static analyzer settings.
        fuzzing: Fuzzing configuration.
        chains: Chain-specific settings.
        upgrade_diff: Upgrade safety settings.
        reporting: Reporting settings.
        ci: CI/CD integration settings.
        red_team: Red team scan configuration.
        external_tools: External tool timeouts and settings.
        supply_chain: Supply chain security configuration.
        threat_intel: Threat intelligence configuration.
        http: HTTP client configuration.
        exploit_generation: Exploit PoC auto-generation settings.
        history: History scanning configuration.
        fingerprint: Protocol fingerprint scanner settings.
        ai: AI and RAG configuration.
        plugins: Plugin system configuration.
        license: License configuration for Pro features.
    """
    engine: EngineConfig = field(default_factory=EngineConfig)
    heuristics: HeuristicConfig = field(default_factory=HeuristicConfig)
    suppressions: List[Suppression] = field(default_factory=list)
    static_analysis: StaticAnalysisConfig = field(default_factory=StaticAnalysisConfig)
    fuzzing: FuzzingConfig = field(default_factory=FuzzingConfig)
    chains: ChainConfig = field(default_factory=ChainConfig)
    upgrade_diff: UpgradeDiffConfig = field(default_factory=UpgradeDiffConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    ci: CIConfig = field(default_factory=CIConfig)
    red_team: RedTeamConfig = field(default_factory=RedTeamConfig)
    external_tools: ExternalToolsConfig = field(default_factory=ExternalToolsConfig)
    supply_chain: SupplyChainConfig = field(default_factory=SupplyChainConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    http: HttpConfig = field(default_factory=HttpConfig)
    exploit_generation: ExploitGenerationConfig = field(
        default_factory=ExploitGenerationConfig
    )
    history: HistoryConfig = field(default_factory=HistoryConfig)
    visualization: VisualizationConfig = field(
        default_factory=VisualizationConfig
    )
    fingerprint: FingerprintConfig = field(default_factory=FingerprintConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    plugins: PluginsConfig = field(default_factory=PluginsConfig)
    license: LicenseConfig = field(default_factory=LicenseConfig)

    def is_finding_suppressed(
        self, rule_id: str, file_path: str, line_no: int
    ) -> Optional[Suppression]:
        """Check if a finding should be suppressed.

        Args:
            rule_id: The ID of the rule that triggered the finding.
            file_path: Path to the file where the finding occurred.
            line_no: Line number where the finding occurred.

        Returns:
            The matching Suppression object if suppressed, None otherwise.
        """
        for suppression in self.suppressions:
            if suppression.matches(rule_id, file_path, line_no):
                return suppression
        return None


def load_config(config_path: Optional[str] = None) -> CounterscarpConfig:
    """
    Load configuration from project TOML config.

    Args:
        config_path: Path to config file. If None, searches current dir and
            parent directories.

    Returns:
        CounterscarpConfig object with loaded settings.
    """
    if toml is None:
        logger.error("TOML parser not available, using default config")
        return CounterscarpConfig()

    # Find config file
    if config_path is None:
        config_path = find_config_file()

    if config_path:
        resolved = _resolve_legacy_config_alias(config_path)
        if resolved:
            config_path = resolved

    if not config_path or not Path(config_path).exists():
        names = ", ".join(CONFIG_FILE_CANDIDATES)
        logger.info(
            "No config file found (%s), using default configuration",
            names,
        )
        return CounterscarpConfig()

    logger.info(f"Loading configuration from: {config_path}")

    # Determine the TOML parse error class for whichever library was loaded
    _toml_decode_error: type = Exception  # fallback: catch-all
    try:
        _toml_decode_error = toml.TOMLDecodeError  # tomllib / tomli
    except AttributeError:
        try:
            _toml_decode_error = toml.TomlDecodeError  # older toml package
        except AttributeError:
            pass  # keep generic Exception fallback

    try:
        with open(config_path, 'rb') as f:
            data = toml.load(f)
    except FileNotFoundError:
        logger.warning("Config file not found (skipping): %s", config_path)
        return CounterscarpConfig()
    except (PermissionError, IOError) as e:
        logger.error("Cannot read config file '%s': %s", config_path, e)
        return CounterscarpConfig()
    except _toml_decode_error as e:  # type: ignore[misc]
        logger.error(
            "TOML syntax error in config file '%s': %s",
            config_path,
            e,
        )
        if CounterscarpConfigError is not None:
            raise CounterscarpConfigError(
                "Failed to parse configuration file",
                details={"path": config_path, "error": str(e)}
            ) from e
        return CounterscarpConfig()
    except Exception as e:
        logger.error("Unexpected error reading config '%s' (%s): %s", config_path, type(e).__name__, e)
        if CounterscarpConfigError is not None:
            raise CounterscarpConfigError(
                "Failed to read configuration file",
                details={"path": config_path, "error": str(e)}
            ) from e
        return CounterscarpConfig()

    # Validate config schema and log warnings
    validation_warnings = validate_config(data)
    if validation_warnings:
        logger.warning("Configuration validation warnings:")
        for warning in validation_warnings:
            logger.warning(f"  - {warning}")

    config = CounterscarpConfig()

    # Parse engine config
    if 'engine' in data:
        eng = data['engine']
        config.engine = EngineConfig(
            name=eng.get('name', 'Counterscarp Security Engine'),
            version=eng.get('version', '5.0.0'),
            fail_on_severity=eng.get('fail_on_severity', 'HIGH'),
            max_findings=eng.get('max_findings', 0)
        )

    # Parse heuristics config
    if 'heuristics' in data:
        heur = data['heuristics']
        config.heuristics = HeuristicConfig(
            enabled=heur.get('enabled', True),
            severity_overrides=heur.get('severity_overrides', {}),
            disabled_rules=heur.get('disabled_rules', {}),
            min_confidence=heur.get('min_confidence', 0),
            min_severity=heur.get('min_severity', 'INFO')
        )

    # Parse suppressions
    if 'suppressions' in data:
        for supp_data in data['suppressions']:
            config.suppressions.append(Suppression(
                rule_id=supp_data['rule_id'],
                file=supp_data.get('file'),
                line=supp_data.get('line'),
                reason=supp_data.get('reason', ''),
                expires=supp_data.get('expires')
            ))

    # Parse static analysis config
    if 'static_analysis' in data:
        sa = data['static_analysis']
        slither = sa.get('slither', {})
        aderyn = sa.get('aderyn', {})
        config.static_analysis = StaticAnalysisConfig(
            slither_enabled=slither.get('enabled', True),
            slither_exclude_detectors=slither.get(
                'exclude_detectors', ''
            ),
            slither_include_impact=slither.get(
                'include_impact', 'High,Medium'
            ),
            aderyn_enabled=aderyn.get('enabled', False),
            aderyn_scope=aderyn.get('scope', '')
        )

    # Parse fuzzing config
    if 'fuzzing' in data:
        fuzz = data['fuzzing']
        foundry = fuzz.get('foundry', {})
        medusa = fuzz.get('medusa', {})
        config.fuzzing = FuzzingConfig(
            foundry_enabled=foundry.get('enabled', False),
            foundry_runs=foundry.get('runs', 10000),
            foundry_max_test_rejects=foundry.get('max_test_rejects', 100000),
            medusa_enabled=medusa.get('enabled', False),
            medusa_test_limit=medusa.get('test_limit', 100000),
            medusa_timeout=medusa.get('timeout', 300),
            medusa_workers=medusa.get('workers', 10)
        )

    # Parse chain config
    if 'chains' in data:
        chains = data['chains']
        solana = chains.get('solana', {})
        evm = chains.get('evm', {})

        # Parse IDL config
        idl_config = SolanaIDLConfig()
        if 'idl' in solana:
            idl = solana['idl']
            idl_config = SolanaIDLConfig(
                idl_path=idl.get('idl_path', 'target/idl'),
                validate_constraints=idl.get('validate_constraints', True),
                trace_cpi=idl.get('trace_cpi', True)
            )

        config.chains = ChainConfig(
            solana_enabled=solana.get('enabled', False),
            solana_project_root=solana.get('project_root', './programs'),
            solana_idl=idl_config,
            evm_solc_version=evm.get('solc_version', '>=0.8.0'),
            evm_trusted_contracts=evm.get('trusted_contracts', [])
        )

    # Parse upgrade diff config
    if 'upgrade_diff' in data:
        upg = data['upgrade_diff']
        ignore_patterns = upg.get('ignore_patterns', {})
        config.upgrade_diff = UpgradeDiffConfig(
            old_implementation_path=upg.get(
                'old_implementation_path', ''
            ),
            new_implementation_path=upg.get(
                'new_implementation_path', ''
            ),
            ignore_new_view_functions=ignore_patterns.get(
                'ignore_new_view_functions', True
            ),
            ignore_comment_changes=ignore_patterns.get(
                'ignore_comment_changes', True
            )
        )

    # Parse reporting config
    if 'reporting' in data:
        rep = data['reporting']
        sections = rep.get('sections', {})
        config.reporting = ReportingConfig(
            format=rep.get('format', 'markdown'),
            executive_summary=sections.get('executive_summary', True),
            supply_chain=sections.get('supply_chain', True),
            static_analysis=sections.get('static_analysis', True),
            heuristic_scan=sections.get('heuristic_scan', True),
            fuzzing=sections.get('fuzzing', False),
            threat_intel=sections.get('threat_intel', False),
            access_matrix=sections.get('access_matrix', True),
            verbosity=rep.get('verbosity', 'standard'),
            group_by=rep.get('group_by', 'severity')
        )

    # Parse CI config
    if 'ci' in data:
        ci = data['ci']
        
        # Parse generator config if present
        generator_config = None
        if 'generator' in ci:
            gen = ci['generator']
            generator_config = CIGeneratorConfig(
                platform=gen.get('platform', 'github'),
                triggers=gen.get('triggers', ['push', 'pull_request']),
                notifications=gen.get('notifications', []),
                custom_steps=gen.get('custom_steps', [])
            )
        
        config.ci = CIConfig(
            fail_on_findings=ci.get('fail_on_findings', True),
            post_pr_comment=ci.get('post_pr_comment', True),
            upload_sarif=ci.get('upload_sarif', False),
            exclude_paths=ci.get('exclude_paths', [
                "test/**", "script/**", "node_modules/**", ".git/**"
            ]),
            generator=generator_config
        )

    # Parse red team config
    if 'red_team' in data:
        rt = data['red_team']
        config.red_team = RedTeamConfig(
            severity_allowlist=rt.get(
                'severity_allowlist', ["High", "Medium"]
            ),
            ignore_checks=rt.get('ignore_checks', [
                "solc-version",
                "naming-convention",
                "assembly",
                "redundant-statements"
            ])
        )

    # Parse external tools config
    if 'external_tools' in data:
        et = data['external_tools']
        config.external_tools = ExternalToolsConfig(
            aderyn_timeout=et.get('aderyn_timeout', 120),
            mythril_timeout=et.get('mythril_timeout', 600),
            foundry_fuzz_runs=et.get('foundry_fuzz_runs', 1000)
        )

    # Parse supply chain config
    if 'supply_chain' in data:
        sc = data['supply_chain']
        config.supply_chain = SupplyChainConfig(
            ecosystem=sc.get('ecosystem', 'npm'),
            osv_timeout=sc.get('osv_timeout', 10),
            osv_max_retries=sc.get('osv_max_retries', 3),
            osv_rate_limit=sc.get('osv_rate_limit', 10)
        )

    # Parse threat intel config
    if 'threat_intel' in data:
        ti = data['threat_intel']
        config.threat_intel = ThreatIntelConfig(
            c4_timeout=ti.get('c4_timeout', 10),
            immunefi_timeout=ti.get('immunefi_timeout', 10),
            solana_github_timeout=ti.get('solana_github_timeout', 10),
            api_rate_limit=ti.get('api_rate_limit', 5),
            offline_mode=ti.get('offline_mode', False),
            bundled_db_path=ti.get('bundled_db_path', 'data/threat_intel_db.json')
        )

    # Parse HTTP config
    if 'http' in data:
        http = data['http']
        config.http = HttpConfig(
            default_timeout=http.get('default_timeout', 30),
            max_retries=http.get('max_retries', 3),
            base_delay=http.get('base_delay', 1.0),
            max_delay=http.get('max_delay', 30.0),
            backoff_factor=http.get('backoff_factor', 2.0)
        )

    # Parse exploit generation config
    if 'exploit_generation' in data:
        eg = data['exploit_generation']
        config.exploit_generation = ExploitGenerationConfig(
            auto_generate=eg.get('auto_generate', False),
            min_severity=eg.get('min_severity', 'HIGH'),
            validate_compilation=eg.get('validate_compilation', True),
            output_dir=eg.get('output_dir', 'exploits/'),
            llm_backend=eg.get('llm_backend', 'none'),
            template_dir=eg.get('template_dir', 'exploit_templates/')
        )

    # Parse history config
    if 'history' in data:
        hist = data['history']
        config.history = HistoryConfig(
            max_commits=hist.get('max_commits', 50),
            scan_branches=hist.get('scan_branches', ["main"]),
            include_fixed=hist.get('include_fixed', True),
            output_dir=hist.get('output_dir', '.')
        )

    # Parse visualization config
    if 'visualization' in data:
        vis = data['visualization']
        config.visualization = VisualizationConfig(
            enabled=vis.get('enabled', False),
            include_source_analysis=vis.get('include_source_analysis', True),
            trace_attack_paths=vis.get('trace_attack_paths', True),
            output_format=vis.get('output_format', 'html'),
            max_path_depth=vis.get('max_path_depth', 10)
        )

    # Parse fingerprint config
    if 'fingerprint' in data:
        fp = data['fingerprint']
        config.fingerprint = FingerprintConfig(
            enabled=fp.get('enabled', False),
            min_similarity=fp.get('min_similarity', 0.7),
            database_path=fp.get(
                'database_path', 'data/protocol_fingerprints.json'
            ),
            include_risk_assessment=fp.get(
                'include_risk_assessment', True
            )
        )

    # Parse AI config
    if 'ai' in data:
        ai = data['ai']
        config.ai = AIConfig(
            embedding_backend=ai.get('embedding_backend', 'local'),
            llm_backend=ai.get('llm_backend', 'none'),
            llm_model=ai.get('llm_model', 'gpt-4o-mini'),
            ollama_url=ai.get('ollama_url', 'http://localhost:11434'),
            openai_model=ai.get('openai_model', 'gpt-4-turbo-preview'),
            rag_index_path=ai.get(
                'rag_index_path', '.scarpshield/rag_index.json'
            ),
            top_k=ai.get('top_k', 5),
            auto_enrich=ai.get('auto_enrich', False),
            llm_enrichment=ai.get('llm_enrichment', False)
        )

    # Parse plugins config
    if 'plugins' in data:
        plug = data['plugins']
        config.plugins = PluginsConfig(
            enabled=plug.get('enabled', True),
            dirs=plug.get('dirs', ['.scarpshield/plugins'])
        )

    # Parse license config
    if 'license' in data:
        lic = data['license']
        config.license = LicenseConfig(
            key=lic.get('key', '')
        )

    logger.info("Configuration loaded successfully")
    heur_status = 'enabled' if config.heuristics.enabled else 'disabled'
    logger.info(
        f"Heuristics: {heur_status}, "
        f"Disabled rules: {len(config.heuristics.disabled_rules)}, "
        f"Suppressions: {len(config.suppressions)}, "
        f"Fail on: {config.engine.fail_on_severity}+"
    )

    return config


def _resolve_legacy_config_alias(config_path: str) -> Optional[str]:
    """Resolve preferred/legacy profile aliases when explicit path is missing."""
    candidate = Path(config_path)
    if candidate.exists():
        return str(candidate)

    name = candidate.name
    alias_name: Optional[str] = None
    if name.startswith(PREFERRED_PROFILE_PREFIX):
        alias_name = LEGACY_PROFILE_PREFIX + name[len(PREFERRED_PROFILE_PREFIX):]
    elif name.startswith(LEGACY_PROFILE_PREFIX):
        alias_name = PREFERRED_PROFILE_PREFIX + name[len(LEGACY_PROFILE_PREFIX):]

    if not alias_name:
        return None

    alias_path = candidate.with_name(alias_name)
    if alias_path.exists():
        logger.info("Config alias fallback: %s -> %s", candidate.name, alias_name)
        return str(alias_path)
    return None


def find_config_file() -> Optional[str]:
    """
    Search for config file in current directory and parent directories.

    Preference order:
      1) scarpshield.toml
      2) counterscarp.toml (legacy fallback)
    """
    current_dir = Path.cwd()

    # Search up to 5 levels up
    for _ in range(5):
        for config_name in CONFIG_FILE_CANDIDATES:
            config_path = current_dir / config_name
            if config_path.exists():
                return str(config_path)
        current_dir = current_dir.parent
        if current_dir == current_dir.parent:  # Reached filesystem root
            break

    return None


def validate_config(config: dict) -> list[str]:
    """Validate TOML configuration schema and return warnings.

    Checks:
    - Required keys exist
    - Types are correct
    - Values are within expected ranges

    Args:
        config: The loaded TOML configuration dictionary.

    Returns:
        List of validation warning strings.
    """
    warnings: list[str] = []

    if not isinstance(config, dict):
        warnings.append("Config must be a dictionary")
        return warnings

    # Validate engine section
    if 'engine' in config:
        eng = config['engine']
        if not isinstance(eng, dict):
            warnings.append("'engine' must be a dictionary")
        else:
            # Validate fail_on_severity
            valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            fail_on = eng.get('fail_on_severity')
            if fail_on and fail_on not in valid_severities:
                warnings.append(
                    f"engine.fail_on_severity must be one of "
                    f"{valid_severities}, got '{fail_on}'"
                )

            # Validate max_findings
            max_findings = eng.get('max_findings')
            if max_findings is not None:
                if not isinstance(max_findings, int) or max_findings < 0:
                    warnings.append(
                        f"engine.max_findings must be a non-negative integer, "
                        f"got {max_findings}"
                    )

    # Validate heuristics section
    if 'heuristics' in config:
        heur = config['heuristics']
        if not isinstance(heur, dict):
            warnings.append("'heuristics' must be a dictionary")
        else:
            # Validate enabled is boolean
            enabled = heur.get('enabled')
            if enabled is not None and not isinstance(enabled, bool):
                warnings.append(
                    f"heuristics.enabled must be a boolean, "
                    f"got {type(enabled)}"
                )

            # Validate severity_overrides is a dict
            overrides = heur.get('severity_overrides')
            if overrides is not None and not isinstance(overrides, dict):
                warnings.append(
                    "heuristics.severity_overrides must be a dictionary"
                )
            elif isinstance(overrides, dict):
                valid_severities = [
                    'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
                ]
                for rule_id, sev in overrides.items():
                    if sev not in valid_severities:
                        warnings.append(
                            f"heuristics.severity_overrides['{rule_id}'] "
                            f"must be one of {valid_severities}, got '{sev}'"
                        )

            # Validate disabled_rules is a dict
            disabled = heur.get('disabled_rules')
            if disabled is not None and not isinstance(disabled, dict):
                warnings.append(
                    "heuristics.disabled_rules must be a dictionary"
                )

    # Validate suppressions section
    if 'suppressions' in config:
        suppressions = config['suppressions']
        if not isinstance(suppressions, list):
            warnings.append("'suppressions' must be a list")
        else:
            for i, supp in enumerate(suppressions):
                if not isinstance(supp, dict):
                    warnings.append(f"suppressions[{i}] must be a dictionary")
                    continue

                # Check required field
                if 'rule_id' not in supp:
                    warnings.append(
                        f"suppressions[{i}] missing required 'rule_id'"
                    )

                # Validate line is an integer if present
                line = supp.get('line')
                if line is not None and not isinstance(line, int):
                    warnings.append(
                        f"suppressions[{i}].line must be an integer, "
                        f"got {type(line)}"
                    )

                # Validate expires is a valid date string if present
                expires = supp.get('expires')
                if expires:
                    from datetime import datetime
                    try:
                        datetime.fromisoformat(expires)
                    except ValueError:
                        warnings.append(
                            f"suppressions[{i}].expires must be a valid "
                            f"ISO date string, got '{expires}'"
                        )

    # Validate fuzzing section
    if 'fuzzing' in config:
        fuzz = config['fuzzing']
        if not isinstance(fuzz, dict):
            warnings.append("'fuzzing' must be a dictionary")
        else:
            # Validate foundry runs
            foundry = fuzz.get('foundry', {})
            runs = foundry.get('runs')
            if runs is not None:
                if not isinstance(runs, int) or runs < 1:
                    warnings.append(
                        "fuzzing.foundry.runs must be a positive integer"
                    )

            # Validate medusa settings
            medusa = fuzz.get('medusa', {})
            test_limit = medusa.get('test_limit')
            if test_limit is not None:
                if not isinstance(test_limit, int) or test_limit < 1:
                    warnings.append(
                        "fuzzing.medusa.test_limit must be a positive integer"
                    )

            timeout = medusa.get('timeout')
            if timeout is not None:
                if not isinstance(timeout, int) or timeout < 1:
                    warnings.append(
                        "fuzzing.medusa.timeout must be a positive integer"
                    )

            workers = medusa.get('workers')
            if workers is not None:
                if not isinstance(workers, int) or workers < 1:
                    warnings.append(
                        "fuzzing.medusa.workers must be a positive integer"
                    )

    # Validate reporting section
    if 'reporting' in config:
        rep = config['reporting']
        if not isinstance(rep, dict):
            warnings.append("'reporting' must be a dictionary")
        else:
            valid_formats = ['markdown', 'json', 'html', 'sarif', 'pdf']
            fmt = rep.get('format')
            if fmt and fmt not in valid_formats:
                warnings.append(
                    f"reporting.format must be one of {valid_formats}, "
                    f"got '{fmt}'"
                )

            valid_verbosity = ['minimal', 'standard', 'verbose']
            verbosity = rep.get('verbosity')
            if verbosity and verbosity not in valid_verbosity:
                warnings.append(
                    f"reporting.verbosity must be one of {valid_verbosity}, "
                    f"got '{verbosity}'"
                )

            valid_group_by = ['severity', 'category', 'file']
            group_by = rep.get('group_by')
            if group_by and group_by not in valid_group_by:
                warnings.append(
                    f"reporting.group_by must be one of {valid_group_by}, "
                    f"got '{group_by}'"
                )

    return warnings


def print_config_summary(config: CounterscarpConfig) -> None:
    """Pretty-print configuration summary."""
    logger.debug("Printing configuration summary")
    print("\n" + "="*60)
    print(f" {config.engine.name} v{config.engine.version}")
    print("="*60)

    print("\n[Engine]")
    print(f"  Fail on severity: {config.engine.fail_on_severity}+")
    max_f = config.engine.max_findings
    print(f"  Max findings: {max_f if max_f > 0 else 'unlimited'}")

    print("\n[Heuristics]")
    status = '✓ enabled' if config.heuristics.enabled else '✗ disabled'
    print(f"  Status: {status}")
    print(f"  Disabled rules: {len(config.heuristics.disabled_rules)}")
    if config.heuristics.disabled_rules:
        for rule_id in list(config.heuristics.disabled_rules.keys())[:5]:
            print(f"    - {rule_id}")
        dr_count = len(config.heuristics.disabled_rules)
        if dr_count > 5:
            print(f"    ... and {dr_count - 5} more")

    print(f"  Severity overrides: {len(config.heuristics.severity_overrides)}")

    print("\n[Suppressions]")
    print(f"  Total: {len(config.suppressions)}")
    for supp in config.suppressions[:3]:
        if supp.file and supp.line:
            location = f"{supp.file}:{supp.line}"
        else:
            location = supp.file or "global"
        print(f"    - {supp.rule_id} @ {location}")
    if len(config.suppressions) > 3:
        print(f"    ... and {len(config.suppressions) - 3} more")

    print("\n" + "="*60 + "\n")


# CLI for testing config loader
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Test Counterscarp configuration loader"
    )
    parser.add_argument("--config", help="Path to counterscarp.toml")
    args = parser.parse_args()

    config = load_config(args.config)
    print_config_summary(config)

    # Test suppression matching
    if config.suppressions:
        print("\n[Suppression Test]")
        print("Testing suppression matching:")
        test_rule = config.suppressions[0].rule_id
        test_file = config.suppressions[0].file or "test.sol"
        test_line = config.suppressions[0].line or 1
        matched = config.is_finding_suppressed(test_rule, test_file, test_line)
        if matched:
            print(f"  ✓ Suppression matched: {matched.reason}")
        else:
            print("  ✗ No suppression matched")
