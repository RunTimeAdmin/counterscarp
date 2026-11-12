"""Billing hooks for the web app, with or without the private billing modules.

Stripe checkout, PAYG credits and license-key storage live in
``webapp.license_api``, ``webapp.stripe_integration`` and
``webapp.stripe_webhook_handlers``. They are private and not shipped in the
public repository. With them installed this module re-exports them. Without
them ``webapp.config`` forces FREE_TOOL_MODE on, so every billing route
returns before it reaches the stand-ins below.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter

from webapp.config import BASE_DIR, BILLING_AVAILABLE

logger = logging.getLogger("counterscarp.billing")

if BILLING_AVAILABLE:
    from webapp.license_api import (  # type: ignore[import-not-found]
        append_audit_log,
        find_license_in_db,
        license_router,
        link_license_to_user,
    )
    from webapp.stripe_integration import (  # type: ignore[import-not-found]
        PAYG_PACKS,
        PRODUCTS,
        STRIPE_PUBLISHABLE_KEY,
        STRIPE_WEBHOOK_SECRET,
        check_and_mark_event,
        create_checkout_session,
        create_payg_checkout,
        find_license_by_subscription,
        get_session_license_key,
        handle_checkout_completed,
        unmark_event_processed,
        update_license_in_db,
    )
    from webapp.stripe_webhook_handlers import (  # type: ignore[import-not-found]
        WebhookDeps,
        dispatch_webhook_event,
    )
else:
    logger.info("Billing modules not installed; running as a free tool")

    license_router = APIRouter()
    PAYG_PACKS: dict = {}
    PRODUCTS: dict = {}
    STRIPE_PUBLISHABLE_KEY = ""
    STRIPE_WEBHOOK_SECRET = ""

    _AUDIT_LOG_PATH = BASE_DIR / "data" / "audit_log.jsonl"
    _audit_log_lock = threading.Lock()

    def append_audit_log(
        event_type: str, key: str, actor: str, ip: str, changes: dict
    ) -> None:
        """Append one JSON line to the audit log, same format as the private module."""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "key": key[:12] + "..." if key else "",
            "actor": actor,
            "ip": ip,
            "changes": changes,
        }
        with _audit_log_lock:
            _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(_AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")

    def find_license_in_db(license_key: str) -> Optional[dict[str, Any]]:
        return None

    def link_license_to_user(email: str, user_id: str) -> Optional[str]:
        return None

    def _billing_unavailable(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("Billing is not available in this build")

    check_and_mark_event = _billing_unavailable
    create_checkout_session = _billing_unavailable
    create_payg_checkout = _billing_unavailable
    find_license_by_subscription = _billing_unavailable
    get_session_license_key = _billing_unavailable
    handle_checkout_completed = _billing_unavailable
    unmark_event_processed = _billing_unavailable
    update_license_in_db = _billing_unavailable
    dispatch_webhook_event = _billing_unavailable
    WebhookDeps = _billing_unavailable
