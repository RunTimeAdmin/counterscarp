"""Stripe webhook event handlers — registry pattern.

Splits the 243-line ``stripe_webhook`` route into:
  - ``WebhookDeps``: a plain dataclass that bundles collaborators
    (callable injections, not module globals) so each handler is
    independently unit-testable by passing fakes.
  - One function per Stripe event type.
  - ``dispatch_webhook_event``: routes an event dict to the right handler.

The route itself shrinks to ~40 lines of transport logic (free-mode guard,
rate-limit, signature verify, idempotency check) and a single
``dispatch_webhook_event(event, deps)`` call.

Behaviour preserved verbatim from the original inline code:
  - Yearly-interval detection: {"year", "annual", "yearly"}.
  - Renewal / resume expiry: 365 days (yearly) or 30 days (monthly).
  - Tier map and max-activations map are module constants here, not
    two anonymous dicts repeated in the same branch.
  - Idempotency rollback (``unmark_event_processed``) happens in the
    route's except block — not inside handlers — so the caller controls it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants (hoisted from inside the old inline function)
# ---------------------------------------------------------------------------

_TIER_MAP: dict[str, str] = {
    "dev_monthly": "developer",
    "dev_annual": "developer",
    "pro_monthly": "pro",
    "pro_annual": "pro",
    "team_monthly": "team",
    "team_annual": "team",
}

_MAX_ACTIVATIONS_MAP: dict[str, int] = {
    "developer": 1,
    "pro": 3,
    "team": 5,
}


# ---------------------------------------------------------------------------
# Dependency bundle
# ---------------------------------------------------------------------------


@dataclass
class WebhookDeps:
    """Collaborators injected by the route — enables testing without globals."""

    find_license_by_subscription: Callable[[str], dict[str, Any] | None]  # noqa: E501
    update_license_in_db: Callable[[str, dict[str, Any]], None]
    handle_checkout_completed: Callable[[dict[str, Any]], None]
    append_audit_log: Callable[..., None]
    logger: logging.Logger = field(
        default_factory=lambda: logging.getLogger(__name__)
    )
    ip: str = "unknown"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_yearly_interval(interval: str) -> bool:
    return str(interval or "").strip().lower() in {"year", "annual", "yearly"}


def _extend_expiry(interval: str, now: datetime) -> datetime:
    days = 365 if _is_yearly_interval(interval) else 30
    return now + timedelta(days=days)


# ---------------------------------------------------------------------------
# Per-event handlers
# ---------------------------------------------------------------------------


def _handle_checkout_completed(
    event: dict[str, Any],
    deps: WebhookDeps,
) -> None:
    session = event["data"]["object"]
    deps.handle_checkout_completed(session)


def _handle_invoice_paid(
    event: dict[str, Any],
    deps: WebhookDeps,
) -> None:
    invoice = event["data"]["object"]
    subscription_id = invoice.get("subscription", "")
    if not subscription_id:
        return
    license_entry = deps.find_license_by_subscription(subscription_id)
    if not license_entry:
        return

    interval = license_entry.get("billing_interval", "month")
    now = datetime.now(timezone.utc)
    new_expiry = _extend_expiry(interval, now)

    deps.update_license_in_db(
        license_entry["key"],
        {
            "expires_at": new_expiry.strftime("%Y-%m-%d"),
            "payment_failed_at": None,
        },
    )
    deps.logger.info(
        "License renewed: %s... extended to %s",
        license_entry["key"][:12],
        new_expiry.strftime("%Y-%m-%d"),
    )
    deps.append_audit_log(
        "subscription_renewed",
        license_entry["key"],
        "stripe_webhook",
        deps.ip,
        {"new_expiry": new_expiry.strftime("%Y-%m-%d")},
    )


def _handle_subscription_deleted(
    event: dict[str, Any],
    deps: WebhookDeps,
) -> None:
    subscription = event["data"]["object"]
    subscription_id = subscription.get("id", "")
    if not subscription_id:
        return
    license_entry = deps.find_license_by_subscription(subscription_id)
    if not license_entry:
        return

    deps.update_license_in_db(
        license_entry["key"],
        {
            "revoked": True,
            "revoked_at": datetime.now(timezone.utc).isoformat(),
            "revoke_reason": "subscription_cancelled",
        },
    )
    deps.logger.info(
        "License revoked (subscription cancelled): %s...",
        license_entry["key"][:12],
    )
    deps.append_audit_log(
        "subscription_cancelled",
        license_entry["key"],
        "stripe_webhook",
        deps.ip,
        {"reason": "subscription_cancelled"},
    )


def _handle_payment_failed(
    event: dict[str, Any],
    deps: WebhookDeps,
) -> None:
    invoice = event["data"]["object"]
    subscription_id = invoice.get("subscription", "")
    if not subscription_id:
        return
    license_entry = deps.find_license_by_subscription(subscription_id)
    if not license_entry:
        return

    deps.update_license_in_db(
        license_entry["key"],
        {"payment_failed_at": datetime.now(timezone.utc).isoformat()},
    )
    deps.logger.info(
        "Payment failed for license: %s... (grace period active)",
        license_entry["key"][:12],
    )
    deps.append_audit_log(
        "payment_failed",
        license_entry["key"],
        "stripe_webhook",
        deps.ip,
        {"subscription_id": subscription_id},
    )


def _handle_subscription_created(
    event: dict[str, Any],
    deps: WebhookDeps,
) -> None:
    subscription = event["data"]["object"]
    subscription_id = subscription.get("id", "")
    customer_email = (
        subscription.get("customer_email") or subscription.get("customer", "")
    )
    deps.logger.info("Subscription created: %s for %s", subscription_id, customer_email)


def _handle_subscription_updated(
    event: dict[str, Any],
    deps: WebhookDeps,
) -> None:
    subscription = event["data"]["object"]
    subscription_id = subscription.get("id", "")
    if not subscription_id:
        return
    license_entry = deps.find_license_by_subscription(subscription_id)
    if not license_entry:
        return

    product_key = (
        subscription.get("items", {})
        .get("data", [{}])[0]
        .get("price", {})
        .get("metadata", {})
        .get("product_key", "")
    )
    new_tier = _TIER_MAP.get(
        product_key, license_entry.get("tier", "developer")
    )
    new_max_activations = _MAX_ACTIVATIONS_MAP.get(new_tier, 1)
    new_billing_interval = "year" if product_key.endswith("_annual") else "month"

    license_key = license_entry["key"]
    deps.update_license_in_db(
        license_key,
        {
            "tier": new_tier,
            "max_activations": new_max_activations,
            "billing_interval": new_billing_interval,
        },
    )
    deps.logger.info(
        "Subscription updated: %s... tier changed to %s",
        license_key[:12],
        new_tier,
    )


def _handle_subscription_resumed(
    event: dict[str, Any],
    deps: WebhookDeps,
) -> None:
    subscription = event["data"]["object"]
    subscription_id = subscription.get("id", "")
    if not subscription_id:
        return
    license_entry = deps.find_license_by_subscription(subscription_id)
    if not license_entry:
        return

    license_key = license_entry["key"]
    interval = license_entry.get("billing_interval", "month")
    now = datetime.now(timezone.utc)
    new_expiry = _extend_expiry(interval, now)

    deps.update_license_in_db(
        license_key,
        {
            "revoked": False,
            "revoked_at": None,
            "revoke_reason": None,
            "expires_at": new_expiry.strftime("%Y-%m-%d"),
        },
    )
    deps.logger.info("Subscription resumed: %s...", license_key[:12])


# ---------------------------------------------------------------------------
# Dispatch registry
# ---------------------------------------------------------------------------

_HANDLERS: dict[str, Callable[[dict[str, Any], WebhookDeps], None]] = {
    "checkout.session.completed": _handle_checkout_completed,
    "invoice.paid": _handle_invoice_paid,
    "customer.subscription.deleted": _handle_subscription_deleted,
    "invoice.payment_failed": _handle_payment_failed,
    "customer.subscription.created": _handle_subscription_created,
    "customer.subscription.updated": _handle_subscription_updated,
    "customer.subscription.resumed": _handle_subscription_resumed,
}


def dispatch_webhook_event(event: dict[str, Any], deps: WebhookDeps) -> None:
    """Route *event* to the appropriate handler.

    Unknown event types are silently ignored (Stripe sends many event types
    the app does not care about; logging every one is noise).
    """
    event_type = event.get("type", "")
    handler = _HANDLERS.get(event_type)
    if handler is None:
        deps.logger.debug("Unhandled Stripe event type: %s", event_type)
        return
    handler(event, deps)
