"""
License Management Module for Sentinel Engine.

Handles Pro feature gating, license validation, and machine fingerprinting.
"""

import argparse
import functools
import hashlib
import hmac
import json
import os
import platform
import secrets
import sys
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests

# Pro feature gates
AI_COPILOT = "ai_copilot"
ATTACK_GRAPH = "attack_graph"
EXPLOIT_GEN = "exploit_gen"
TIME_TRAVEL = "time_travel"
FINGERPRINT = "fingerprint"
SOLANA = "solana"
BRANDED_REPORTS = "branded_reports"
WEB_APP = "web_app"

ALL_PRO_FEATURES = [
    AI_COPILOT,
    ATTACK_GRAPH,
    EXPLOIT_GEN,
    TIME_TRAVEL,
    FINGERPRINT,
    SOLANA,
    BRANDED_REPORTS,
    WEB_APP,
]

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

LICENSE_SERVER_URL = "https://api.sentinel-engine.io/license/validate"
CACHE_TTL_HOURS = 24
GRACE_PERIOD_DAYS = 7
PRODUCT_VERSION = "3.0.0"


class LicenseError(Exception):
    """Raised when a pro feature is used without a valid license."""

    def __init__(self, feature: str, message: str = ""):
        self.feature = feature
        default = f"Feature '{feature}' requires Pro license"
        super().__init__(message or default)


@dataclass
class LicenseInfo:
    valid: bool
    tier: str  # "free", "pro", "enterprise"
    expires_at: Optional[datetime]
    features: list
    max_activations: int
    current_activations: int


def get_machine_fingerprint() -> str:
    """Generate a stable machine fingerprint using SHA-256."""
    hostname = platform.node()
    mac = uuid.getnode()
    system_info = f"{platform.system()}_{platform.machine()}"

    fingerprint_data = f"{hostname}:{mac}:{system_info}"
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()


def _get_cache_dir() -> Path:
    """Get the cache directory path."""
    cache_dir = Path.home() / ".sentinel"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _get_cache_path() -> Path:
    """Get the license cache file path."""
    return _get_cache_dir() / "license_cache.json"


def _load_toml_license_key() -> str:
    """Load license key from sentinel.toml config file."""
    config_paths = [
        Path.cwd() / "sentinel.toml",
        Path.home() / ".sentinel" / "sentinel.toml",
    ]

    for config_path in config_paths:
        if config_path.exists():
            try:
                # Use tomllib for Python 3.11+, fallback to tomli
                if sys.version_info >= (3, 11):
                    import tomllib

                    with open(config_path, "rb") as f:
                        config = tomllib.load(f)
                else:
                    import tomli

                    with open(config_path, "rb") as f:
                        config = tomli.load(f)

                license_section = config.get("license", {})
                key = license_section.get("key", "")
                if key:
                    return key
            except Exception:
                continue

    return ""


def _get_license_key() -> str:
    """Get license key from environment or config file."""
    # Priority 1: Environment variable
    env_key = os.environ.get("SENTINEL_PRO_LICENSE", "").strip()
    if env_key:
        return env_key

    # Priority 2: Config file
    return _load_toml_license_key()


class LicenseManager:
    """Singleton license manager for Sentinel Engine."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        with self._lock:
            if self._initialized:
                return

            self._license_key = _get_license_key()
            self._machine_id = get_machine_fingerprint()
            self._cache_lock = threading.Lock()
            self._cached_result: Optional[LicenseInfo] = None
            self._cache_valid = False

            self._initialized = True

    def _compute_cache_signature(
        self, key_hash: str, machine_id: str, cached_at: str
    ) -> str:
        """Compute HMAC-SHA256 signature for cache validation."""
        message = f"{key_hash}{machine_id}{cached_at}"
        return hmac.new(
            self._license_key.encode(), message.encode(), hashlib.sha256
        ).hexdigest()

    def _load_cached_result(self) -> Optional[LicenseInfo]:
        """Load and validate cached license result."""
        if not self._license_key:
            return None

        cache_path = _get_cache_path()
        if not cache_path.exists():
            return None

        try:
            with open(cache_path, "r") as f:
                cache = json.load(f)

            # Validate signature
            stored_signature = cache.get("signature", "")
            computed_signature = self._compute_cache_signature(
                cache.get("key_hash", ""),
                cache.get("machine_id", ""),
                cache.get("cached_at", ""),
            )

            if not hmac.compare_digest(stored_signature, computed_signature):
                print("License cache signature mismatch")
                return None

            # Check machine ID
            if cache.get("machine_id") != self._machine_id:
                print("License cache machine ID mismatch")
                return None

            # Check key hash
            key_hash = hashlib.sha256(self._license_key.encode()).hexdigest()
            if cache.get("key_hash") != key_hash:
                return None

            cached_at = datetime.fromisoformat(cache.get("cached_at", ""))
            now = datetime.now(timezone.utc)

            # Check if cache is still fresh (< 24 hours)
            cache_age = now - cached_at
            if cache_age > timedelta(hours=CACHE_TTL_HOURS):
                return None

            result = cache.get("validation_result", {})
            return LicenseInfo(
                valid=result.get("valid", False),
                tier=result.get("tier", "free"),
                expires_at=(
                    datetime.fromisoformat(result.get("expires_at"))
                    if result.get("expires_at")
                    else None
                ),
                features=result.get("features", []),
                max_activations=result.get("max_activations", 0),
                current_activations=result.get("current_activations", 0),
            )

        except Exception:
            return None

    def _load_grace_period_cache(self) -> Optional[LicenseInfo]:
        """Load cached result during grace period (network failure)."""
        cache_path = _get_cache_path()
        if not cache_path.exists():
            return None

        try:
            with open(cache_path, "r") as f:
                cache = json.load(f)

            # Validate signature
            stored_signature = cache.get("signature", "")
            computed_signature = self._compute_cache_signature(
                cache.get("key_hash", ""),
                cache.get("machine_id", ""),
                cache.get("cached_at", ""),
            )

            if not hmac.compare_digest(stored_signature, computed_signature):
                return None

            # Check machine ID
            if cache.get("machine_id") != self._machine_id:
                return None

            cached_at = datetime.fromisoformat(cache.get("cached_at", ""))
            now = datetime.now(timezone.utc)

            # Grace period: up to 7 days
            cache_age = now - cached_at
            if cache_age > timedelta(days=GRACE_PERIOD_DAYS):
                return None

            result = cache.get("validation_result", {})
            days = cache_age.days
            print(f"Using cached license (grace period: {days} days)")
            return LicenseInfo(
                valid=result.get("valid", False),
                tier=result.get("tier", "free"),
                expires_at=(
                    datetime.fromisoformat(result.get("expires_at"))
                    if result.get("expires_at")
                    else None
                ),
                features=result.get("features", []),
                max_activations=result.get("max_activations", 0),
                current_activations=result.get("current_activations", 0),
            )

        except Exception:
            return None

    def _save_cached_result(self, result: LicenseInfo):
        """Save license validation result to cache."""
        if not self._license_key:
            return

        key_hash = hashlib.sha256(self._license_key.encode()).hexdigest()
        cached_at = datetime.now(timezone.utc).isoformat()

        validation_result = {
            "valid": result.valid,
            "tier": result.tier,
            "expires_at": (
                result.expires_at.isoformat() if result.expires_at else None
            ),
            "features": result.features,
            "max_activations": result.max_activations,
            "current_activations": result.current_activations,
        }

        signature = self._compute_cache_signature(
            key_hash, self._machine_id, cached_at
        )

        cache = {
            "key_hash": key_hash,
            "machine_id": self._machine_id,
            "validation_result": validation_result,
            "cached_at": cached_at,
            "signature": signature,
        }

        try:
            with self._cache_lock:
                with open(_get_cache_path(), "w") as f:
                    json.dump(cache, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save license cache: {e}")

    def _clear_cache(self):
        """Clear the license cache."""
        cache_path = _get_cache_path()
        if cache_path.exists():
            try:
                cache_path.unlink()
            except Exception:
                pass

    def _validate_license(self) -> Optional[LicenseInfo]:
        """Validate license with server or cache."""
        if not self._license_key:
            return None

        # Check local cache first
        cached = self._load_cached_result()
        if cached:
            with self._cache_lock:
                self._cached_result = cached
                self._cache_valid = True
            return cached

        # Prepare validation request
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = {
            "license_key": self._license_key,
            "machine_id": self._machine_id,
            "product_version": PRODUCT_VERSION,
            "timestamp": timestamp,
        }

        try:
            response = requests.post(
                LICENSE_SERVER_URL,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            data = response.json()

            if not data.get("valid", False):
                self._clear_cache()
                return None

            result = LicenseInfo(
                valid=data.get("valid", False),
                tier=data.get("tier", "free"),
                expires_at=(
                    datetime.fromisoformat(
                        data.get("expires_at").replace("Z", "+00:00")
                    )
                    if data.get("expires_at")
                    else None
                ),
                features=data.get("features", []),
                max_activations=data.get("max_activations", 0),
                current_activations=data.get("current_activations", 0),
            )

            # Save to cache
            self._save_cached_result(result)

            with self._cache_lock:
                self._cached_result = result
                self._cache_valid = True

            return result

        except requests.exceptions.RequestException:
            # Network error: try grace period cache
            grace_result = self._load_grace_period_cache()
            if grace_result:
                with self._cache_lock:
                    self._cached_result = grace_result
                    self._cache_valid = True
                return grace_result

            # No valid cache available
            return None

        except Exception:
            return None

    def _get_or_validate_license(self) -> LicenseInfo:
        """Get cached license or validate new one."""
        with self._cache_lock:
            if self._cache_valid and self._cached_result:
                return self._cached_result

        result = self._validate_license()
        if result:
            return result

        # Return free tier info
        return LicenseInfo(
            valid=False,
            tier="free",
            expires_at=None,
            features=[],
            max_activations=0,
            current_activations=0,
        )

    def check_pro_feature(self, feature: str) -> bool:
        """Check if a pro feature is available."""
        if feature not in ALL_PRO_FEATURES:
            return True  # Unknown features are allowed

        license_info = self._get_or_validate_license()
        if not license_info.valid:
            return False

        if license_info.tier == "enterprise":
            return True

        return feature in license_info.features

    def require_pro_feature(self, feature: str) -> None:
        """Check if a pro feature is available. Raises LicenseError if not."""
        if not self.check_pro_feature(feature):
            raise LicenseError(feature)

    def get_license_info(self) -> LicenseInfo:
        """Get current license info. Returns free-tier info if no license."""
        return self._get_or_validate_license()

    def get_tier(self) -> str:
        """Get current tier: 'free', 'pro', or 'enterprise'."""
        license_info = self._get_or_validate_license()
        return license_info.tier

    @staticmethod
    def get_upgrade_message(feature: str) -> str:
        """Get a formatted upgrade message for CLI output."""
        name = FEATURE_NAMES.get(feature, feature)
        return f"""
┌──────────────────────────────────────────────────────────────┐
│  ⚡ {name} requires Sentinel Engine Pro                      
│                                                              
│  Upgrade to unlock:                                          
│  • All 21 analyzers            • AI Audit Copilot           
│  • Attack Graph Visualization  • Exploit PoC Generator      
│  • Time-Travel Scanner         • Protocol Fingerprinting    
│  • Branded HTML/SARIF Reports  • Solana Analyzer            
│                                                              
│  → https://sentinel-engine.io/pricing                       
│  Set SENTINEL_PRO_LICENSE=your-key to activate              
└──────────────────────────────────────────────────────────────┘
"""


def check_pro_feature(feature: str) -> bool:
    """Convenience function to check if a pro feature is available."""
    return LicenseManager().check_pro_feature(feature)


def require_pro(feature: str):
    """Decorator to gate a function behind a pro license check."""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            mgr = LicenseManager()
            if not mgr.check_pro_feature(feature):
                print(mgr.get_upgrade_message(feature))
                return None
            return func(*args, **kwargs)

        return wrapper

    return decorator


def generate_license_key(
    tier: str, email: str, expires: str, max_activations: int
) -> dict:
    """Generate a new license key entry for the licenses.json database."""
    key = f"SE-{tier.upper()}-{secrets.token_hex(16)}"
    return {
        "key": key,
        "customer_email": email,
        "tier": tier,
        "expires_at": expires,
        "max_activations": max_activations,
        "activated_machines": [],
        "revoked": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def _save_license_to_db(entry: dict) -> None:
    """Append a license entry to data/licenses.json."""
    db_path = Path(__file__).parent / "data" / "licenses.json"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if db_path.exists():
        with open(db_path, "r", encoding="utf-8") as f:
            db = json.load(f)
    else:
        db = {"licenses": [], "version": 1}

    db["licenses"].append(entry)

    with open(db_path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)

    print(f"License saved to {db_path}")


def main_generate(args):
    """Handle the generate subcommand."""
    result = generate_license_key(
        tier=args.tier,
        email=args.email,
        expires=args.expires,
        max_activations=args.max_activations,
    )
    print(json.dumps(result, indent=2))

    if args.save:
        _save_license_to_db(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="License CLI")
    subparsers = parser.add_subparsers(
        dest="command", help="Available commands"
    )

    # Generate subcommand
    gen_parser = subparsers.add_parser(
        "generate", help="Generate a new license key (admin use)"
    )
    gen_parser.add_argument(
        "--tier", required=True,
        choices=["pro", "enterprise"],
        help="License tier"
    )
    gen_parser.add_argument("--email", required=True, help="Customer email")
    gen_parser.add_argument(
        "--expires", required=True, help="Expiration date (ISO format)"
    )
    gen_parser.add_argument(
        "--max-activations",
        type=int,
        default=2,
        help="Maximum number of machine activations",
    )
    gen_parser.add_argument(
        "--save",
        action="store_true",
        help="Save the generated license to data/licenses.json",
    )

    args = parser.parse_args()

    if args.command == "generate":
        main_generate(args)
    else:
        parser.print_help()
