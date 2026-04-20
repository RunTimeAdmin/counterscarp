"""Stripe Checkout integration for Sentinel Engine Pro licensing."""

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import stripe

# Stripe configuration — from environment variables
# Set STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, STRIPE_WEBHOOK_SECRET in your environment
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

stripe.api_key = STRIPE_SECRET_KEY

# Product definitions (prices created via Stripe API on first use)
PRODUCTS = {
    "pro_monthly": {
        "name": "Sentinel Engine Pro - Monthly",
        "description": (
            "Full access to all 21 analyzers,"
            " AI Copilot, Attack Graphs, and more."
        ),
        "price_cents": 9900,  # $99
        "interval": "month",
        "tier": "pro",
        "max_activations": 2,
    },
    "pro_annual": {
        "name": "Sentinel Engine Pro - Annual",
        "description": (
            "Full access to all 21 analyzers,"
            " AI Copilot, Attack Graphs, and more."
            " Save $189/year!"
        ),
        "price_cents": 99900,  # $999
        "interval": "year",
        "tier": "pro",
        "max_activations": 2,
    },
}

# In-memory cache of Stripe Price IDs keyed by product_key
_price_cache: dict[str, str] = {}
_price_cache_lock = threading.Lock()

# Session-to-license mapping file
_SESSION_MAP_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "session_license_map.json"
)
_session_map_lock = threading.Lock()


def _load_session_map() -> dict:
    """Load the session_id -> license mapping from disk."""
    if _SESSION_MAP_PATH.exists():
        try:
            with open(_SESSION_MAP_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_session_map(data: dict) -> None:
    """Persist the session_id -> license mapping to disk."""
    _SESSION_MAP_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _session_map_lock:
        with open(_SESSION_MAP_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


def get_or_create_price(product_key: str) -> str:
    """Create a Stripe Product + Price if they don't exist yet.

    Uses product metadata to track which product_key a Stripe Product
    belongs to.  Caches the resulting Price ID in memory for speed.
    Returns the Stripe Price ID (``price_…``).
    """
    with _price_cache_lock:
        if product_key in _price_cache:
            return _price_cache[product_key]

    product_info = PRODUCTS[product_key]

    # Search for an existing product with matching metadata
    existing = stripe.Product.search(
        query=f"metadata['product_key']:'{product_key}'",
        limit=1,
    )

    if existing.data:
        product = existing.data[0]
        # Get the active price for this product
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


def create_checkout_session(
    product_key: str,
    success_url: str,
    cancel_url: str,
) -> str:
    """Create a Stripe Checkout Session and return the URL to redirect to.

    *success_url* should contain the literal ``{CHECKOUT_SESSION_ID}``
    placeholder — Stripe replaces it after payment.
    """
    price_id = get_or_create_price(product_key)

    session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        payment_method_types=["card"],
        metadata={"product_key": product_key},
    )
    return session.url


def handle_checkout_completed(session: dict) -> dict:
    """Process a completed checkout session (called by webhook).

    1. Extracts customer email & product info from the session.
    2. Generates a license key via ``license_manager.generate_license_key``.
    3. Saves it to ``data/licenses.json`` via ``_save_license_to_db``.
    4. Stores a ``session_id -> license`` mapping so the success page
       can display the key.

    Returns the license entry dict.
    """
    from license_manager import generate_license_key, _save_license_to_db

    session_id = session.get("id", "")
    customer_email = (
        session.get("customer_details", {}).get("email")
        or session.get("customer_email", "")
        or ""
    )
    product_key = session.get("metadata", {}).get("product_key", "pro_monthly")
    product_info = PRODUCTS.get(product_key, PRODUCTS["pro_monthly"])

    # Compute expiry based on billing interval
    now = datetime.now(timezone.utc)
    if product_info["interval"] == "year":
        expires_at = (now + timedelta(days=365)).strftime("%Y-%m-%d")
    else:
        expires_at = (now + timedelta(days=30)).strftime("%Y-%m-%d")

    # Generate and persist the license key
    license_entry = generate_license_key(
        tier=product_info["tier"],
        email=customer_email,
        expires=expires_at,
        max_activations=product_info["max_activations"],
    )
    _save_license_to_db(license_entry)

    # Map session_id -> license so the success page can look it up
    session_map = _load_session_map()
    session_map[session_id] = {
        "key": license_entry["key"],
        "tier": license_entry["tier"],
        "customer_email": customer_email,
        "expires_at": license_entry["expires_at"],
    }
    _save_session_map(session_map)

    return license_entry


def get_session_license_key(session_id: str) -> Optional[dict]:
    """Look up the license information associated with a checkout session.

    Returns ``None`` if the session hasn't been completed yet or is unknown.
    """
    session_map = _load_session_map()
    return session_map.get(session_id)
