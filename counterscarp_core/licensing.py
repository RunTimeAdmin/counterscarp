"""License gating that works with or without the private license module.

``license_manager`` (key validation, Pro feature gates) is private and is not
shipped in the public repository. When it is installed next to the engine,
this module re-exports it unchanged. Without it, the engine runs at the
Community tier: every gated feature reports as unavailable, the same answer
the private module gives when no license key is set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

try:
    from license_manager import (
        AI_COPILOT,
        ATTACK_GRAPH,
        BRANDED_REPORTS,
        COMMUNITY,
        EXPLOIT_GEN,
        FEATURE_NAMES,
        FEATURE_TIERS,
        FINGERPRINT,
        GRACE_PERIOD_DAYS,
        LICENSE_PREFIXES,
        SOLANA,
        TIER_HIERARCHY,
        TIME_TRAVEL,
        WEB_APP,
        LicenseInfo,
        LicenseManager,
    )

    LICENSING_AVAILABLE = True
except ModuleNotFoundError as _exc:
    # Only fall back when the private module itself is absent. A missing
    # dependency *inside* it is a real error and must surface.
    if _exc.name != "license_manager":
        raise

    LICENSING_AVAILABLE = False

    AI_COPILOT = "ai_copilot"
    ATTACK_GRAPH = "attack_graph"
    EXPLOIT_GEN = "exploit_gen"
    TIME_TRAVEL = "time_travel"
    FINGERPRINT = "fingerprint"
    SOLANA = "solana"
    BRANDED_REPORTS = "branded_reports"
    WEB_APP = "web_app"

    COMMUNITY = "community"
    TIER_HIERARCHY = [COMMUNITY, "payg", "developer", "pro", "team", "enterprise"]
    LICENSE_PREFIXES = ("SE-PAYG-", "SE-DEV-", "SE-PRO-", "SE-TEAM-", "SE-ENT-")
    GRACE_PERIOD_DAYS = 3

    FEATURE_TIERS = {
        SOLANA: "developer",
        BRANDED_REPORTS: "developer",
        WEB_APP: "developer",
        AI_COPILOT: "pro",
        ATTACK_GRAPH: "pro",
        EXPLOIT_GEN: "pro",
        TIME_TRAVEL: "pro",
        FINGERPRINT: "pro",
    }
    FEATURE_NAMES = {
        AI_COPILOT: "AI Audit Copilot",
        ATTACK_GRAPH: "Attack Graph Visualization",
        EXPLOIT_GEN: "Exploit PoC Generator",
        TIME_TRAVEL: "Time-Travel Scanner",
        FINGERPRINT: "Protocol Fingerprinting",
        SOLANA: "Solana Analyzer",
        BRANDED_REPORTS: "Branded HTML/SARIF Reports",
        WEB_APP: "Web Application",
    }

    @dataclass
    class LicenseInfo:  # type: ignore[no-redef]
        valid: bool
        tier: str
        expires_at: Optional[datetime]
        features: list = field(default_factory=list)
        max_activations: int = 0
        current_activations: int = 0

    class LicenseManager:  # type: ignore[no-redef]
        """Community-tier stand-in for the private license manager."""

        def clear_cache(self) -> None:
            return None

        def get_tier(self) -> str:
            return str(COMMUNITY)

        def get_license_info(self) -> LicenseInfo:
            return LicenseInfo(valid=False, tier=COMMUNITY, expires_at=None)

        def check_pro_feature(self, feature: str) -> bool:
            return feature not in FEATURE_TIERS

        @staticmethod
        def get_upgrade_message(feature: str) -> str:
            name = FEATURE_NAMES.get(feature, feature)
            return f"{name} needs the licensed build of Counterscarp Engine."


__all__ = [
    "AI_COPILOT",
    "ATTACK_GRAPH",
    "BRANDED_REPORTS",
    "COMMUNITY",
    "EXPLOIT_GEN",
    "FEATURE_NAMES",
    "FEATURE_TIERS",
    "FINGERPRINT",
    "GRACE_PERIOD_DAYS",
    "LICENSE_PREFIXES",
    "LICENSING_AVAILABLE",
    "SOLANA",
    "TIER_HIERARCHY",
    "TIME_TRAVEL",
    "WEB_APP",
    "LicenseInfo",
    "LicenseManager",
]
