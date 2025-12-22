#!/usr/bin/env python3
"""
Configuration Loader for Sentinel Engine
Parses sentinel.toml and provides typed config access
"""

import os
import sys
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path

# Try to import toml parser
try:
    import tomli as toml  # Python 3.11+ stdlib tomllib, or pip install tomli
except ImportError:
    try:
        import tomllib as toml  # Python 3.11+
    except ImportError:
        try:
            import toml  # Fallback to older toml package
        except ImportError:
            print("[!] TOML parser not available. Install: pip install tomli")
            toml = None


@dataclass
class EngineConfig:
    """Engine-wide settings."""
    name: str = "Sentinel Security Engine"
    version: str = "2.2"
    fail_on_severity: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    max_findings: int = 0  # 0 = unlimited


@dataclass
class HeuristicConfig:
    """Heuristic scanning configuration."""
    enabled: bool = True
    severity_overrides: Dict[str, str] = field(default_factory=dict)
    disabled_rules: Dict[str, bool] = field(default_factory=dict)

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check if a rule is enabled."""
        return not self.disabled_rules.get(rule_id, False)

    def get_rule_severity(self, rule_id: str, default_severity: str) -> str:
        """Get effective severity for a rule (considering overrides)."""
        return self.severity_overrides.get(rule_id, default_severity)


@dataclass
class Suppression:
    """Represents a single suppression rule."""
    rule_id: str
    file: Optional[str] = None
    line: Optional[int] = None
    reason: str = ""
    expires: Optional[str] = None  # ISO date string

    def matches(self, rule_id: str, file_path: str, line_no: int) -> bool:
        """Check if this suppression applies to a finding."""
        # Rule ID must match
        if self.rule_id != rule_id:
            return False

        # If suppression specifies a file, it must match
        if self.file:
            # Normalize paths for comparison
            file_normalized = Path(file_path).as_posix()
            suppression_file = Path(self.file).as_posix()
            if suppression_file not in file_normalized:
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
            except ValueError:
                pass  # Invalid date format, ignore expiry check

        return True


@dataclass
class StaticAnalysisConfig:
    """Static analyzer settings."""
    slither_enabled: bool = True
    slither_exclude_detectors: str = ""
    slither_include_impact: str = "High,Medium"
    aderyn_enabled: bool = False
    aderyn_scope: str = ""


@dataclass
class FuzzingConfig:
    """Fuzzing configuration."""
    foundry_enabled: bool = False
    foundry_runs: int = 10000
    foundry_max_test_rejects: int = 100000
    medusa_enabled: bool = False
    medusa_test_limit: int = 100000
    medusa_timeout: int = 300
    medusa_workers: int = 10


@dataclass
class ChainConfig:
    """Chain-specific settings."""
    solana_enabled: bool = False
    solana_project_root: str = "./programs"
    evm_solc_version: str = ">=0.8.0"
    evm_trusted_contracts: List[str] = field(default_factory=list)


@dataclass
class UpgradeDiffConfig:
    """Upgrade safety settings."""
    old_implementation_path: str = ""
    new_implementation_path: str = ""
    ignore_new_view_functions: bool = True
    ignore_comment_changes: bool = True


@dataclass
class ReportingConfig:
    """Reporting settings."""
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


@dataclass
class CIConfig:
    """CI/CD integration settings."""
    fail_on_findings: bool = True
    post_pr_comment: bool = True
    upload_sarif: bool = False
    exclude_paths: List[str] = field(default_factory=lambda: [
        "test/**", "script/**", "node_modules/**", ".git/**"
    ])


@dataclass
class SentinelConfig:
    """Root configuration object."""
    engine: EngineConfig = field(default_factory=EngineConfig)
    heuristics: HeuristicConfig = field(default_factory=HeuristicConfig)
    suppressions: List[Suppression] = field(default_factory=list)
    static_analysis: StaticAnalysisConfig = field(default_factory=StaticAnalysisConfig)
    fuzzing: FuzzingConfig = field(default_factory=FuzzingConfig)
    chains: ChainConfig = field(default_factory=ChainConfig)
    upgrade_diff: UpgradeDiffConfig = field(default_factory=UpgradeDiffConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    ci: CIConfig = field(default_factory=CIConfig)

    def is_finding_suppressed(self, rule_id: str, file_path: str, line_no: int) -> Optional[Suppression]:
        """
        Check if a finding should be suppressed.
        Returns the matching Suppression object if suppressed, None otherwise.
        """
        for suppression in self.suppressions:
            if suppression.matches(rule_id, file_path, line_no):
                return suppression
        return None


def load_config(config_path: Optional[str] = None) -> SentinelConfig:
    """
    Load configuration from sentinel.toml.

    Args:
        config_path: Path to config file. If None, searches current dir and parent dirs.

    Returns:
        SentinelConfig object with loaded settings.
    """
    if toml is None:
        print("[!] TOML parser not available, using default config")
        return SentinelConfig()

    # Find config file
    if config_path is None:
        config_path = find_config_file()

    if not config_path or not os.path.exists(config_path):
        print(f"[*] No sentinel.toml found, using default configuration")
        return SentinelConfig()

    print(f"[*] Loading configuration from: {config_path}")

    try:
        with open(config_path, 'rb') as f:
            data = toml.load(f)
    except Exception as e:
        print(f"[!] Error loading config: {e}")
        return SentinelConfig()

    config = SentinelConfig()

    # Parse engine config
    if 'engine' in data:
        eng = data['engine']
        config.engine = EngineConfig(
            name=eng.get('name', 'Sentinel Security Engine'),
            version=eng.get('version', '2.2'),
            fail_on_severity=eng.get('fail_on_severity', 'HIGH'),
            max_findings=eng.get('max_findings', 0)
        )

    # Parse heuristics config
    if 'heuristics' in data:
        heur = data['heuristics']
        config.heuristics = HeuristicConfig(
            enabled=heur.get('enabled', True),
            severity_overrides=heur.get('severity_overrides', {}),
            disabled_rules=heur.get('disabled_rules', {})
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
            slither_exclude_detectors=slither.get('exclude_detectors', ''),
            slither_include_impact=slither.get('include_impact', 'High,Medium'),
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
        config.chains = ChainConfig(
            solana_enabled=solana.get('enabled', False),
            solana_project_root=solana.get('project_root', './programs'),
            evm_solc_version=evm.get('solc_version', '>=0.8.0'),
            evm_trusted_contracts=evm.get('trusted_contracts', [])
        )

    # Parse upgrade diff config
    if 'upgrade_diff' in data:
        upg = data['upgrade_diff']
        ignore_patterns = upg.get('ignore_patterns', {})
        config.upgrade_diff = UpgradeDiffConfig(
            old_implementation_path=upg.get('old_implementation_path', ''),
            new_implementation_path=upg.get('new_implementation_path', ''),
            ignore_new_view_functions=ignore_patterns.get('ignore_new_view_functions', True),
            ignore_comment_changes=ignore_patterns.get('ignore_comment_changes', True)
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
        config.ci = CIConfig(
            fail_on_findings=ci.get('fail_on_findings', True),
            post_pr_comment=ci.get('post_pr_comment', True),
            upload_sarif=ci.get('upload_sarif', False),
            exclude_paths=ci.get('exclude_paths', [
                "test/**", "script/**", "node_modules/**", ".git/**"
            ])
        )

    print(f"[+] Configuration loaded successfully")
    print(f"    - Heuristics: {'enabled' if config.heuristics.enabled else 'disabled'}")
    print(f"    - Disabled rules: {len(config.heuristics.disabled_rules)}")
    print(f"    - Suppressions: {len(config.suppressions)}")
    print(f"    - Fail on: {config.engine.fail_on_severity}+")

    return config


def find_config_file() -> Optional[str]:
    """
    Search for sentinel.toml in current directory and parent directories.
    """
    current_dir = Path.cwd()

    # Search up to 5 levels up
    for _ in range(5):
        config_path = current_dir / "sentinel.toml"
        if config_path.exists():
            return str(config_path)
        current_dir = current_dir.parent
        if current_dir == current_dir.parent:  # Reached filesystem root
            break

    return None


def print_config_summary(config: SentinelConfig) -> None:
    """Pretty-print configuration summary."""
    print("\n" + "="*60)
    print(f" {config.engine.name} v{config.engine.version}")
    print("="*60)

    print("\n[Engine]")
    print(f"  Fail on severity: {config.engine.fail_on_severity}+")
    print(f"  Max findings: {config.engine.max_findings if config.engine.max_findings > 0 else 'unlimited'}")

    print("\n[Heuristics]")
    print(f"  Status: {'✓ enabled' if config.heuristics.enabled else '✗ disabled'}")
    print(f"  Disabled rules: {len(config.heuristics.disabled_rules)}")
    if config.heuristics.disabled_rules:
        for rule_id in list(config.heuristics.disabled_rules.keys())[:5]:
            print(f"    - {rule_id}")
        if len(config.heuristics.disabled_rules) > 5:
            print(f"    ... and {len(config.heuristics.disabled_rules) - 5} more")

    print(f"  Severity overrides: {len(config.heuristics.severity_overrides)}")

    print(f"\n[Suppressions]")
    print(f"  Total: {len(config.suppressions)}")
    for supp in config.suppressions[:3]:
        location = f"{supp.file}:{supp.line}" if supp.file and supp.line else (supp.file or "global")
        print(f"    - {supp.rule_id} @ {location}")
    if len(config.suppressions) > 3:
        print(f"    ... and {len(config.suppressions) - 3} more")

    print("\n" + "="*60 + "\n")


# CLI for testing config loader
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test Sentinel configuration loader")
    parser.add_argument("--config", help="Path to sentinel.toml")
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
            print(f"  ✗ No suppression matched")
