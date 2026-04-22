"""
Stripe integration for Counterscarp Engine — payment processing and license provisioning.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import stripe  # noqa: F401
except ImportError:
    stripe = None  # type: ignore

from webapp.user_manager import user_manager

# ---------------------------------------------------------------------------
# Stripe configuration — loaded from environment variables
# ---------------------------------------------------------------------------

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

logger = logging.getLogger("counterscarp.security")
if not STRIPE_SECRET_KEY:
    logger.warning("STRIPE_SECRET_KEY not set — payment features will be unavailable")
if not STRIPE_WEBHOOK_SECRET:
    logger.warning("STRIPE_WEBHOOK_SECRET not set — webhook signature verification will fail")

if stripe and STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

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
        result: Dict[str, Any] = json.loads(_SESSION_MAP_PATH.read_text(encoding="utf-8"))
        return result
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
            return dict(entry)
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
# Price cache (avoids redundant Stripe API calls)
# ---------------------------------------------------------------------------

_price_cache: Dict[str, str] = {}
_price_cache_lock = threading.Lock()


def get_or_create_price(product_key: str) -> str:
    """Return a Stripe Price ID for *product_key*, creating it if necessary."""
    with _price_cache_lock:
        if product_key in _price_cache:
            return _price_cache[product_key]

    if stripe is None:
        raise RuntimeError("stripe package is not installed")

    product_info = PRODUCTS[product_key]

    # Check if the product already exists in Stripe
    existing = stripe.Product.search(
        query=f"metadata['product_key']:'{product_key}'"
    )

    if existing.data:
        product = existing.data[0]
        prices = stripe.Price.list(product=product.id, active=True, limit=1)
        if prices.data:
            price_id = prices.data[0].id
            with _price_cache_lock:
                _price_cache[product_key] = price_id
            return price_id

    # Create a new Product + Price
    product = stripe.Product.create(
        name=product_info["name"],
        description=product_info["description"],
        metadata={"product_key": product_key},
    )

    price = stripe.Price.create(
        product=product.id,
        unit_amount=product_info["price_cents"],
        currency="usd",
        recurring={"interval": product_info["interval"]},
        metadata={"product_key": product_key},
    )

    price_id = price.id
    with _price_cache_lock:
        _price_cache[product_key] = price_id
    return price_id


# ---------------------------------------------------------------------------
# Checkout session creation
# ---------------------------------------------------------------------------


def create_checkout_session(
    product_key: str,
    success_url: str,
    cancel_url: str,
) -> Any:
    """Create a Stripe Checkout Session and return the session object.

    *success_url* should contain the literal ``{CHECKOUT_SESSION_ID}``
    placeholder — Stripe replaces it after payment.
    """
    if stripe is None:
        raise RuntimeError("stripe package is not installed")

    price_id = get_or_create_price(product_key)

    session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        payment_method_types=["card"],
        metadata={"product_key": product_key},
    )
    return session


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

    from datetime import datetime, timedelta, timezone as _tz
    _interval = product_info.get("interval", "month")
    _now = datetime.now(_tz.utc)
    _expires = (_now + timedelta(days=365 if _interval == "year" else 30)).strftime("%Y-%m-%d")

    entry: Dict[str, Any] = license_manager.generate_license_key(
        tier=product_info["tier"],
        email=email,
        expires=_expires,
        max_activations=product_info["max_activations"],
    )

    # Attach Stripe-specific metadata
    entry["stripe_subscription_id"] = session.get("subscription", "")
    entry["stripe_customer_id"] = session.get("customer", "")
    entry["billing_interval"] = product_info["interval"]

    # Auto-link license to user account if registered
    customer_email = entry.get("customer_email", "").lower()
    if customer_email:
        existing_user = user_manager.get_by_email(customer_email)
        if existing_user:
            entry["user_id"] = existing_user["id"]
            user_manager.set_license_key(
                existing_user["id"],
                entry["key"],
                stripe_customer_id=str(entry.get("stripe_customer_id") or ""),
                stripe_subscription_id=str(entry.get("stripe_subscription_id") or "")
            )

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
    val = session_map.get(session_id)
    if val is None:
        return None
    return dict(val)
