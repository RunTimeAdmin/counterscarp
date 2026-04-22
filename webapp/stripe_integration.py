"""
Stripe integration for Counterscarp Engine — payment processing and license provisioning.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import stripe  # noqa: F401
except ImportError:
    stripe = None  # type: ignore

# ---------------------------------------------------------------------------
# Product catalogue
# ---------------------------------------------------------------------------

PRODUCTS: Dict[str, Dict[str, Any]] = {
    "dev_monthly": {
        "name": "Counterscarp Developer",
        "description": "Developer tier – monthly billing",
        "price_cents": 4900,
        "interval": "month",
        "tier": "developer",
        "max_activations": 1,
    },
    "dev_annual": {
        "name": "Counterscarp Developer (Annual)",
        "description": "Developer tier – annual billing",
        "price_cents": 49900,
        "interval": "year",
        "tier": "developer",
        "max_activations": 1,
    },
    "pro_monthly": {
        "name": "Counterscarp Pro",
        "description": "Pro tier – monthly billing",
        "price_cents": 14900,
        "interval": "month",
        "tier": "pro",
        "max_activations": 3,
    },
    "pro_annual": {
        "name": "Counterscarp Pro (Annual)",
        "description": "Pro tier – annual billing",
        "price_cents": 149900,
        "interval": "year",
        "tier": "pro",
        "max_activations": 3,
    },
    "team_monthly": {
        "name": "Counterscarp Team",
        "description": "Team tier – monthly billing",
        "price_cents": 39900,
        "interval": "month",
        "tier": "team",
        "max_activations": 10,
    },
    "team_annual": {
        "name": "Counterscarp Team (Annual)",
        "description": "Team tier – annual billing",
        "price_cents": 399900,
        "interval": "year",
        "tier": "team",
        "max_activations": 10,
    },
}

# ---------------------------------------------------------------------------
# File paths
# ---------------------------------------------------------------------------

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_LICENSES_PATH = _DATA_DIR / "licenses.json"
_SESSION_MAP_PATH = _DATA_DIR / "session_license_map.json"

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_session_map() -> Dict[str, Any]:
    """Load the session → license key mapping from disk."""
    if not _SESSION_MAP_PATH.exists():
        return {}
    try:
        return json.loads(_SESSION_MAP_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_session_map(data: Dict[str, Any]) -> None:
    """Persist the session → license key mapping to disk."""
    _SESSION_MAP_PATH.parent.mkdir(parents=True, exist_ok=True)
    _SESSION_MAP_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# License DB helpers
# ---------------------------------------------------------------------------


def find_license_by_subscription(subscription_id: str) -> Optional[Dict[str, Any]]:
    """Return the license entry matching *subscription_id*, or None."""
    if not _LICENSES_PATH.exists():
        return None
    try:
        with open(_LICENSES_PATH, "r", encoding="utf-8") as fh:
            db = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None
    for entry in db.get("licenses", []):
        if entry.get("stripe_subscription_id") == subscription_id:
            return entry
    return None


def update_license_in_db(key: str, updates: Dict[str, Any]) -> bool:
    """Apply *updates* to the license identified by *key*.  Returns True on success."""
    if not _LICENSES_PATH.exists():
        return False
    try:
        with open(_LICENSES_PATH, "r", encoding="utf-8") as fh:
            db = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return False

    for entry in db.get("licenses", []):
        if entry.get("key") == key:
            entry.update(updates)
            with open(_LICENSES_PATH, "w", encoding="utf-8") as fh:
                json.dump(db, fh, indent=2)
            return True
    return False


# ---------------------------------------------------------------------------
# Stripe event handlers
# ---------------------------------------------------------------------------


def handle_checkout_completed(session: Dict[str, Any]) -> Dict[str, Any]:
    """Handle a Stripe ``checkout.session.completed`` event.

    Generates a license key, stores it in the DB and session map, and
    returns the new license entry dict.
    """
    import license_manager  # local import to avoid circular deps

    product_key: str = (session.get("metadata") or {}).get("product_key", "")
    product_info = PRODUCTS.get(product_key, PRODUCTS["pro_monthly"])

    email: str = (
        (session.get("customer_details") or {}).get("email")
        or session.get("customer_email")
        or ""
    )

    entry: Dict[str, Any] = license_manager.generate_license_key(
        tier=product_info["tier"],
        email=email,
        max_activations=product_info["max_activations"],
    )

    # Attach Stripe-specific metadata
    entry["stripe_subscription_id"] = session.get("subscription", "")
    entry["stripe_customer_id"] = session.get("customer", "")
    entry["billing_interval"] = product_info["interval"]

    # Persist to license DB
    license_manager._save_license_to_db(entry)

    # Update session map
    session_map = _load_session_map()
    session_id: str = session.get("id", "")
    if session_id:
        session_map[session_id] = {
            "key": entry["key"],
            "tier": entry.get("tier", ""),
            "customer_email": entry.get("customer_email", ""),
            "expires_at": entry.get("expires_at", ""),
        }
        _save_session_map(session_map)

    return entry


def get_session_license_key(session_id: str) -> Optional[Dict[str, Any]]:
    """Return the license info stored for *session_id*, or None."""
    session_map = _load_session_map()
    return session_map.get(session_id)
