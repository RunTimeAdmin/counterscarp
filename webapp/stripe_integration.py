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
    import stripe
except ImportError:
    stripe = None  # type: ignore[assignment,unused-ignore]

try:
    import redis as redis_lib
except ImportError:
    redis_lib = None  # type: ignore[assignment,unused-ignore]

from webapp.user_manager import user_manager
from webapp.license_api import append_audit_log

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
        "price_cents": 46800,
        "interval": "year",
        "tier": "developer",
        "max_activations": 1,
    },
    "pro_monthly": {
        "name": "Counterscarp Pro",
        "description": "Pro tier – monthly billing",
        "price_cents": 19900,
        "interval": "month",
        "tier": "pro",
        "max_activations": 3,
    },
    "pro_annual": {
        "name": "Counterscarp Pro (Annual)",
        "description": "Pro tier – annual billing",
        "price_cents": 190800,
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
        "max_activations": 5,
    },
    "team_annual": {
        "name": "Counterscarp Team (Annual)",
        "description": "Team tier – annual billing",
        "price_cents": 382800,
        "interval": "year",
        "tier": "team",
        "max_activations": 5,
    },
}

# Pay-As-You-Go scan credit packs (one-time purchases, not subscriptions)
PAYG_PACKS: Dict[str, Dict[str, Any]] = {
    "payg_starter": {
        "name": "Counterscarp Starter Pack",
        "description": "1 smart contract audit scan",
        "credits": 1,
        "price_cents": 999,
        "price_id_env": "STRIPE_PAYG_STARTER_PRICE_ID",
    },
    "payg_standard": {
        "name": "Counterscarp Standard Pack",
        "description": "5 smart contract audit scans",
        "credits": 5,
        "price_cents": 2999,
        "price_id_env": "STRIPE_PAYG_STANDARD_PRICE_ID",
    },
    "payg_pro_pack": {
        "name": "Counterscarp Pro Pack",
        "description": "15 smart contract audit scans",
        "credits": 15,
        "price_cents": 6999,
        "price_id_env": "STRIPE_PAYG_PRO_PACK_PRICE_ID",
    },
}

# ---------------------------------------------------------------------------
# File paths
# ---------------------------------------------------------------------------

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_LICENSES_PATH = _DATA_DIR / "licenses.json"
_SESSION_MAP_PATH = _DATA_DIR / "session_license_map.json"
_PROCESSED_EVENTS_PATH = _DATA_DIR / "processed_webhook_events.json"

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


_session_map_lock = threading.Lock()


def _load_session_map() -> Dict[str, Any]:
    """Load the session → license key mapping from disk."""
    with _session_map_lock:
        if not _SESSION_MAP_PATH.exists():
            return {}
        try:
            result: Dict[str, Any] = json.loads(_SESSION_MAP_PATH.read_text(encoding="utf-8"))
            return result
        except (json.JSONDecodeError, OSError):
            return {}


def _save_session_map(data: Dict[str, Any]) -> None:
    """Persist the session → license key mapping to disk."""
    with _session_map_lock:
        _SESSION_MAP_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _SESSION_MAP_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(str(tmp), str(_SESSION_MAP_PATH))


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


_licenses_file_lock = threading.Lock()


def update_license_in_db(key: str, updates: Dict[str, Any]) -> bool:
    """Apply *updates* to the license identified by *key*.  Returns True on success."""
    with _licenses_file_lock:
        if not _LICENSES_PATH.exists():
            return False
        try:
            with open(_LICENSES_PATH, "r", encoding="utf-8") as fh:
                db = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return False

        for entry in db.get("licenses", []):
            if entry.get("key") == key:
                old_tier = entry.get("tier")
                entry.update(updates)
                tmp = _LICENSES_PATH.with_suffix(".tmp")
                try:
                    with open(tmp, "w", encoding="utf-8") as fh:
                        json.dump(db, fh, indent=2)
                    tmp.replace(_LICENSES_PATH)
                except OSError:
                    # Fallback: direct write if atomic rename fails
                    with open(_LICENSES_PATH, "w", encoding="utf-8") as fh:
                        json.dump(db, fh, indent=2)
                # Log tier change if tier was updated
                if "tier" in updates and updates["tier"] != old_tier:
                    append_audit_log(
                        "tier_changed", key, "system", "system",
                        {"old_tier": old_tier, "new_tier": updates["tier"]},
                    )
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
            return str(price_id)

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
    return str(price_id)


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


def create_payg_checkout(
    pack_key: str,
    user_email: str,
    user_id: str,
    success_url: str,
    cancel_url: str,
) -> Any:
    """Create a Stripe Checkout session for a one-time PAYG credit pack purchase."""
    if not stripe:
        raise RuntimeError("Stripe SDK not available")

    pack = PAYG_PACKS.get(pack_key)
    if not pack:
        raise ValueError(f"Unknown PAYG pack: {pack_key}")

    price_id = os.environ.get(pack["price_id_env"], "")
    if not price_id:
        raise ValueError(f"Stripe Price ID not configured for {pack_key}")

    session = stripe.checkout.Session.create(
        mode="payment",  # One-time payment, NOT subscription
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        customer_email=user_email,
        payment_method_types=["card"],
        metadata={
            "purchase_type": "payg",
            "pack_key": pack_key,
            "user_id": user_id,
            "credits": str(pack["credits"]),
        },
    )
    return session


def link_payg_credits_to_user(user_id: str, pack_key: str, ip: str = "") -> int:
    """Grant scan credits to a user after PAYG pack purchase. Returns new balance."""
    from webapp.user_manager import user_manager as _um

    pack = PAYG_PACKS.get(pack_key)
    if not pack:
        logger.error("Unknown PAYG pack key in webhook: %s", pack_key)
        return 0

    credits = pack["credits"]
    new_balance = _um.add_scan_credits(user_id, credits)

    append_audit_log(
        event_type="payg_credits_granted",
        key=pack_key,
        actor=user_id,
        ip=ip,
        changes={"pack": pack_key, "credits_added": credits, "new_balance": new_balance},
    )

    logger.info("PAYG credits granted: user=%s pack=%s credits=%d balance=%d", user_id, pack_key, credits, new_balance)
    return new_balance


# ---------------------------------------------------------------------------
# Stripe event handlers
# ---------------------------------------------------------------------------


def handle_checkout_completed(session: Dict[str, Any]) -> Dict[str, Any]:
    """Handle a Stripe ``checkout.session.completed`` event.

    Generates a license key, stores it in the DB and session map, and
    returns the new license entry dict.
    """
    # Check if this is a PAYG purchase
    purchase_type = session.get("metadata", {}).get("purchase_type", "")
    if purchase_type == "payg":
        pack_key = session["metadata"].get("pack_key", "")
        user_id_val = session["metadata"].get("user_id", "")
        if pack_key and user_id_val:
            link_payg_credits_to_user(user_id_val, pack_key)
            # Store in session map for success page
            session_map = _load_session_map()
            sid: str = session.get("id", "")
            if sid:
                session_map[sid] = {
                    "purchase_type": "payg",
                    "pack_key": pack_key,
                    "user_id": user_id_val,
                    "credits": PAYG_PACKS.get(pack_key, {}).get("credits", 0),
                }
                _save_session_map(session_map)
        return {}  # Don't process as subscription

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

    append_audit_log(
        "license_activated", entry["key"], "stripe_webhook", "system",
        {"tier": entry.get("tier", ""), "email": email},
    )

    return entry


def get_session_license_key(session_id: str) -> Optional[Dict[str, Any]]:
    """Return the license info stored for *session_id*, or None."""
    session_map = _load_session_map()
    val = session_map.get(session_id)
    if val is None:
        return None
    return dict(val)


# ---------------------------------------------------------------------------
# Webhook event idempotency
# ---------------------------------------------------------------------------

_REDIS_WEBHOOK_TTL = 259200  # 72 hours
_REDIS_KEY_PREFIX = "counterscarp:webhook_events"
_MAX_FILE_EVENTS = 1000

_events_file_lock = threading.Lock()


_redis_client: Any = None
_redis_client_checked: bool = False


def _get_redis_client() -> Any:
    """Return a cached Redis client connected via REDIS_URL, or None.

    Uses a module-level singleton so at most ONE connection is created per
    worker process, reused across all calls.  If the cached client loses
    its connection, falls back gracefully (returns None).
    """
    global _redis_client, _redis_client_checked

    if redis_lib is None:
        return None

    # Fast path: already attempted connection (result may be None)
    if _redis_client_checked:
        # Verify cached client is still alive
        if _redis_client is not None:
            try:
                _redis_client.ping()
                return _redis_client
            except Exception:
                logger.debug("Cached Redis connection lost, returning None")
                _redis_client = None
        return _redis_client

    # First call: try to connect once, cache the result (even if None)
    url = os.environ.get("REDIS_URL")
    if not url:
        _redis_client = None
        _redis_client_checked = True
        return None

    try:
        _redis_client = redis_lib.from_url(url, decode_responses=True, socket_timeout=2)
        _redis_client.ping()  # verify connection
    except Exception:
        _redis_client = None

    _redis_client_checked = True
    return _redis_client


def is_event_processed(event_id: str) -> bool:
    """Check if a Stripe webhook event has already been processed."""
    # Try Redis first
    try:
        client = _get_redis_client()
        if client is not None:
            return bool(client.exists(f"{_REDIS_KEY_PREFIX}:{event_id}"))
    except Exception:
        logger.debug("Redis unavailable for idempotency check, falling back to file")

    # File fallback
    try:
        with _events_file_lock:
            if not _PROCESSED_EVENTS_PATH.exists():
                return False
            data = json.loads(_PROCESSED_EVENTS_PATH.read_text(encoding="utf-8"))
            return event_id in data
    except Exception:
        logger.warning("Failed to check processed events file: %s", event_id)
        return False


def mark_event_processed(event_id: str) -> None:
    """Mark a Stripe webhook event as processed."""
    # Try Redis first
    try:
        client = _get_redis_client()
        if client is not None:
            client.set(
                f"{_REDIS_KEY_PREFIX}:{event_id}", "1",
                nx=True, ex=_REDIS_WEBHOOK_TTL,
            )
    except Exception:
        logger.debug("Redis unavailable for marking event, falling back to file")

    # Always persist to file as well (durable fallback)
    _file_mark_event(event_id)


def unmark_event_processed(event_id: str) -> None:
    """Remove event mark so Stripe retries can be processed after failures."""
    try:
        client = _get_redis_client()
        if client is not None:
            client.delete(f"{_REDIS_KEY_PREFIX}:{event_id}")
    except Exception:
        logger.debug("Redis unavailable while unmarking event: %s", event_id)

    try:
        with _events_file_lock:
            if not _PROCESSED_EVENTS_PATH.exists():
                return
            try:
                data = json.loads(_PROCESSED_EVENTS_PATH.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return
            if event_id not in data:
                return
            data = [eid for eid in data if eid != event_id]
            tmp = _PROCESSED_EVENTS_PATH.with_suffix(".tmp")
            try:
                tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
                tmp.replace(_PROCESSED_EVENTS_PATH)
            except OSError:
                _PROCESSED_EVENTS_PATH.write_text(
                    json.dumps(data, indent=2),
                    encoding="utf-8",
                )
    except Exception:
        logger.warning("Failed to unmark processed event: %s", event_id)


def _file_mark_event(event_id: str) -> None:
    """Persist event_id to the file fallback (caller may or may not hold lock)."""
    try:
        _PROCESSED_EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        if _PROCESSED_EVENTS_PATH.exists():
            try:
                data = json.loads(
                    _PROCESSED_EVENTS_PATH.read_text(encoding="utf-8")
                )
            except (json.JSONDecodeError, OSError):
                data = []
        else:
            data = []

        if event_id not in data:
            data.append(event_id)

        # Prune to last N entries
        if len(data) > _MAX_FILE_EVENTS:
            data = data[-_MAX_FILE_EVENTS:]

        tmp = _PROCESSED_EVENTS_PATH.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(_PROCESSED_EVENTS_PATH)
        except OSError:
            _PROCESSED_EVENTS_PATH.write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )
    except Exception:
        logger.warning("Failed to persist processed event to file: %s", event_id)


def check_and_mark_event(event_id: str) -> bool:
    """Atomically check if event was processed and mark it if not.

    Returns True if the event was ALREADY processed (duplicate).
    Returns False if the event is new and has now been marked as processed.

    This eliminates the TOCTOU race between is_event_processed() and
    mark_event_processed() in the file fallback path.
    """
    # Try Redis first — SETNX is inherently atomic
    try:
        client = _get_redis_client()
        if client is not None:
            # SET with NX returns True if set (new), None/False if already exists
            was_set = client.set(
                f"{_REDIS_KEY_PREFIX}:{event_id}", "1",
                nx=True, ex=_REDIS_WEBHOOK_TTL,
            )
            if not was_set:
                return True  # Already processed
            # Also persist to file for durability
            with _events_file_lock:
                _file_mark_event(event_id)
            return False  # Newly marked
    except Exception:
        logger.debug("Redis unavailable for atomic check-and-mark, falling back to file")

    # File fallback — single lock acquisition for check + mark
    try:
        with _events_file_lock:
            _PROCESSED_EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
            if _PROCESSED_EVENTS_PATH.exists():
                try:
                    data = json.loads(
                        _PROCESSED_EVENTS_PATH.read_text(encoding="utf-8")
                    )
                except (json.JSONDecodeError, OSError):
                    data = []
            else:
                data = []

            if event_id in data:
                return True  # Already processed

            # Mark as processed
            data.append(event_id)
            if len(data) > _MAX_FILE_EVENTS:
                data = data[-_MAX_FILE_EVENTS:]

            tmp = _PROCESSED_EVENTS_PATH.with_suffix(".tmp")
            try:
                tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
                tmp.replace(_PROCESSED_EVENTS_PATH)
            except OSError:
                _PROCESSED_EVENTS_PATH.write_text(
                    json.dumps(data, indent=2), encoding="utf-8"
                )
            return False  # Newly marked
    except Exception:
        logger.warning("Failed atomic check-and-mark for event: %s", event_id)
        return False  # Fail open — allow processing
