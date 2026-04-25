"""
License Management Module for Counterscarp Engine.

Handles Pro feature gating, license validation, and machine fingerprinting.
"""

from typing import Optional, Dict, List, Any, Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Pro feature gate constants
AI_COPILOT: str
ATTACK_GRAPH: str
EXPLOIT_GEN: str
TIME_TRAVEL: str
FINGERPRINT: str
SOLANA: str
BRANDED_REPORTS: str
WEB_APP: str

# Tier level constants
COMMUNITY: str
DEVELOPER: str
PRO: str
TEAM: str
ENTERPRISE: str

# Tier hierarchy list (ascending privilege order)
TIER_HIERARCHY: List[str]

# Tier key prefixes mapping tier -> key prefix string
TIER_PREFIXES: Dict[str, str]

# Canonical tuple of valid license key prefixes
LICENSE_PREFIXES: tuple[str, ...]

# Default max activations per tier
TIER_DEFAULT_ACTIVATIONS: Dict[str, int]

# All pro features list
ALL_PRO_FEATURES: List[str]

# Feature-to-minimum-tier mapping
FEATURE_TIERS: Dict[str, str]

# Human-readable feature names mapping
FEATURE_NAMES: Dict[str, str]

# License server URLs
LICENSE_SERVER_URL: str
LICENSE_DEACTIVATE_URL: str

# Cache and grace period settings
CACHE_TTL_HOURS: int
GRACE_PERIOD_DAYS: int

# Product version string
PRODUCT_VERSION: str


class LicenseError(Exception):
    """Raised when a gated feature is used without a sufficient license tier."""
    feature: str
    def __init__(self, feature: str, message: str = "") -> None: ...


@dataclass
class LicenseInfo:
    """Holds the result of a license validation."""
    valid: bool
    tier: str  # "community", "developer", "pro", "team", "enterprise"
    expires_at: Optional[datetime]
    features: List[str]
    max_activations: int
    current_activations: int


def get_machine_fingerprint() -> str:
    """Generate a stable machine fingerprint using SHA-256."""
    ...


class LicenseManager:
    """Singleton license manager for Counterscarp Engine."""

    _instance: "LicenseManager | None"
    _initialized: bool

    def __new__(cls) -> "LicenseManager": ...
    def __init__(self) -> None: ...

    def clear_cache(self) -> None:
        """Public method to clear the license cache and reload license key."""
        ...

    def check_pro_feature(self, feature: str) -> bool:
        """Check if the current license tier grants access to a feature."""
        ...

    def require_pro_feature(self, feature: str) -> None:
        """Check if a pro feature is available. Raises LicenseError if not."""
        ...

    def get_license_info(self) -> LicenseInfo:
        """Get current license info. Returns free-tier info if no license."""
        ...

    def get_tier(self) -> str:
        """Get current tier: 'community', 'developer', 'pro', 'team', or 'enterprise'."""
        ...

    @staticmethod
    def get_upgrade_message(feature: str) -> str:
        """Get a formatted upgrade message for CLI output."""
        ...


def check_pro_feature(feature: str) -> bool:
    """Convenience function to check if a pro feature is available."""
    ...


def require_pro(feature: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to gate a function behind a pro license check."""
    ...


def generate_license_key(
    tier: str,
    email: str,
    expires: str,
    max_activations: Optional[int] = ...,
) -> Dict[str, Any]:
    """Generate a new license key entry for the licenses.json database."""
    ...
