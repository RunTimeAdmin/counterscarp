"""Stripe webhook event handlers (refactored out of webapp/main.py).

BEFORE: the ``stripe_webhook`` route was a single 243-line function. The first
~55 lines were transport concerns (free-mode short-circuit, rate limit,
signature verification, idempotency). The remaining ~190 lines were a flat
if/elif chain over 7 event types, each block reaching into module-level
collaborators (find_license_by_subscription, update_license_in_db,
append_audit_log) and repeating the same "look up license, mutate, log" shape.

AFTER: each event type becomes a small named handler with a uniform signature.
A registry dict maps event type -> handler. The route keeps only transport
concerns and a one-line dispatch. New event types are added by writing a
handler and registering it — no edits to a growing if/elif ladder.

Behaviour is preserved: the handlers below are the original blocks moved
verbatim, only reshaped into functions. The renewal/resume expiry math, the
audit-log calls, and the field names are unchanged.

This module is import-light and side-effect free at import time, so it is unit
testable by passing fakes for the collaborator callables via WebhookDeps.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional

_YEARLY_INTERVALS = {"year", "annual", "yearly"}

# Maps a Stripe price product_key -> tier. Hoisted out of the
# subscription.updated block where it was two inline dict literals.
_PRODUCT_TIER_MAP: Dict[str, str] = {
    "dev_monthly": "developer",
    "dev_annual": "developer",
    "pro_monthly": "pro",
    "pro_annual": "pro",
    "team_monthly": "team",
    "team_annual": "team",
}
_TIER_MAX_ACTIVATIONS: Dict[str, int] = {"developer": 1, "pro": 3, "team": 5}


def _is_yearly(interval: str | None) -> bool:
    return str(interval or "").strip().lower() in _YEARLY_INTERVALS


def _renewal_expiry(
    interval: str | None, now: Optional[datetime] = None
) -> datetime:
    """Compute a new expiry date from the billing interval (365d vs 30d)."""
    now = now or datetime.now(timezone.utc)
    return now + timedelta(days=365 if _is_yearly(interval) else 30)


@dataclass(frozen=True)
class WebhookDeps:
    """Collaborators the handlers need, injected rather than imported globally.

    In production these are the same functions main.py already calls; in tests
    they can be fakes. This is what makes the handlers unit-testable.
    """

    find_license_by_subscription: Callable[[str], Optional[dict]]
    update_license_in_db: Callable[[str, dict], Any]
    handle_checkout_completed: Callable[[dict], Any]
    append_audit_log: Callable[..., Any]
    logger: Any
    ip: str


# --- Individual handlers. Each takes (event, deps) and returns None. ---------

def _on_checkout_completed(event: dict, deps: WebhookDeps) -> None:
    deps.handle_checkout_completed(event["data"]["object"])


def _on_invoice_paid(event: dict, deps: WebhookDeps) -> None:
    invoice = event["data"]["object"]
    subscription_id = invoice.get("subscription", "")
    if not subscription_id:
        return
    entry = deps.find_license_by_subscription(subscription_id)
    if not entry:
        return
    new_expiry = _renewal_expiry(entry.get("billing_interval", "month"))
    deps.update_license_in_db(
        entry["key"],
        {
            "expires_at": new_expiry.strftime("%Y-%m-%d"),
            "payment_failed_at": None,
        },
    )
    deps.logger.info(
        "License renewed: %s... extended to %s",
        entry["key"][:12],
        new_expiry.strftime("%Y-%m-%d"),
    )
    deps.append_audit_log(
        "subscription_renewed", entry["key"], "stripe_webhook", deps.ip,
        {"new_expiry": new_expiry.strftime("%Y-%m-%d")},
    )


def _on_subscription_deleted(event: dict, deps: WebhookDeps) -> None:
    subscription_id = event["data"]["object"].get("id", "")
    if not subscription_id:
        return
    entry = deps.find_license_by_subscription(subscription_id)
    if not entry:
        return
    deps.update_license_in_db(
        entry["key"],
        {
            "revoked": True,
            "revoked_at": datetime.now(timezone.utc).isoformat(),
            "revoke_reason": "subscription_cancelled",
        },
    )
    deps.append_audit_log(
        "subscription_cancelled", entry["key"], "stripe_webhook", deps.ip,
        {"reason": "subscription_cancelled"},
    )


def _on_payment_failed(event: dict, deps: WebhookDeps) -> None:
    subscription_id = event["data"]["object"].get("subscription", "")
    if not subscription_id:
        return
    entry = deps.find_license_by_subscription(subscription_id)
    if not entry:
        return
    deps.update_license_in_db(
        entry["key"],
        {"payment_failed_at": datetime.now(timezone.utc).isoformat()},
    )
    deps.append_audit_log(
        "payment_failed", entry["key"], "stripe_webhook", deps.ip,
        {"subscription_id": subscription_id},
    )


def _on_subscription_created(event: dict, deps: WebhookDeps) -> None:
    sub = event["data"]["object"]
    deps.logger.info(
        "Subscription created: %s for %s",
        sub.get("id", ""),
        sub.get("customer_email") or sub.get("customer", ""),
    )


def _on_subscription_updated(event: dict, deps: WebhookDeps) -> None:
    sub = event["data"]["object"]
    subscription_id = sub.get("id", "")
    if not subscription_id:
        return
    entry = deps.find_license_by_subscription(subscription_id)
    if not entry:
        return
    product_key = (
        sub.get("items", {}).get("data", [{}])[0]
        .get("price", {}).get("metadata", {}).get("product_key", "")
    )
    new_tier = _PRODUCT_TIER_MAP.get(
        product_key, entry.get("tier", "developer")
    )
    deps.update_license_in_db(
        entry["key"],
        {
            "tier": new_tier,
            "max_activations": _TIER_MAX_ACTIVATIONS.get(new_tier, 1),
            "billing_interval": (
                "year" if product_key.endswith("_annual") else "month"
            ),
        },
    )
    deps.logger.info(
        "Subscription updated: %s... tier changed to %s",
        entry["key"][:12],
        new_tier,
    )


def _on_subscription_resumed(event: dict, deps: WebhookDeps) -> None:
    subscription_id = event["data"]["object"].get("id", "")
    if not subscription_id:
        return
    entry = deps.find_license_by_subscription(subscription_id)
    if not entry:
        return
    new_expiry = _renewal_expiry(entry.get("billing_interval", "month"))
    deps.update_license_in_db(
        entry["key"],
        {
            "revoked": False,
            "revoked_at": None,
            "revoke_reason": None,
            "expires_at": new_expiry.strftime("%Y-%m-%d"),
        },
    )
    deps.logger.info("Subscription resumed: %s...", entry["key"][:12])


#: Event type -> handler. Adding an event type = one new function + one line.
WEBHOOK_HANDLERS: Dict[str, Callable[[dict, WebhookDeps], None]] = {
    "checkout.session.completed": _on_checkout_completed,
    "invoice.paid": _on_invoice_paid,
    "customer.subscription.deleted": _on_subscription_deleted,
    "invoice.payment_failed": _on_payment_failed,
    "customer.subscription.created": _on_subscription_created,
    "customer.subscription.updated": _on_subscription_updated,
    "customer.subscription.resumed": _on_subscription_resumed,
}


def dispatch_webhook_event(event: dict, deps: WebhookDeps) -> None:
    """Route a verified Stripe event to its handler.

    No-op for unknown event types.
    """
    handler = WEBHOOK_HANDLERS.get(str(event.get("type", "")))
    if handler is not None:
        handler(event, deps)
