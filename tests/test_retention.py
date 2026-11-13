"""Scan data was kept forever while the privacy page said it was deleted."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from webapp import audit_index
from webapp.retention import purge_expired


def _aged(path: Path, days: float) -> Path:
    path.mkdir(parents=True)
    old = time.time() - days * 86400
    os.utime(path, (old, old))
    return path


def test_expired_results_and_uploads_are_deleted(tmp_path: Path) -> None:
    results, uploads = tmp_path / "results", tmp_path / "uploads"
    audit_index.configure(tmp_path / "index")
    old_id, new_id = "11111111-0000-4000-8000-000000000001", "11111111-0000-4000-8000-000000000002"
    for aid in (old_id, new_id):
        audit_index.append("user-1", {"audit_id": aid})

    old = results / old_id
    old.mkdir(parents=True)
    (old / "scan_meta.json").write_text(json.dumps({"owner_user_id": "user-1"}))
    stamp = time.time() - 31 * 86400
    os.utime(old, (stamp, stamp))
    _aged(results / new_id, 29)
    _aged(uploads / old_id, 1.5)
    _aged(uploads / new_id, 0.5)

    assert purge_expired(results, uploads, result_days=30) == (1, 1)
    assert sorted(p.name for p in results.iterdir()) == [new_id]
    assert sorted(p.name for p in uploads.iterdir()) == [new_id]
    assert [e["audit_id"] for e in audit_index.list_audits("user-1")] == [new_id]


def test_privacy_page_states_the_real_retention() -> None:
    from fastapi.testclient import TestClient

    import webapp.main as main

    text = TestClient(main.app).get("/privacy").text
    assert "in-memory" not in text and "deleted afterward" not in text
    assert f"{main.RESULT_RETENTION_DAYS} days" in text
    assert "encrypted environment file" not in text


def test_web_startup_leaves_retention_to_the_queue_worker(monkeypatch) -> None:
    """Each uvicorn worker ran the purge at the same moment (44 removals logged
    for 38 folders). With a queue, only the arq worker purges."""
    import asyncio
    from unittest.mock import patch

    import webapp.main as main

    with patch("webapp.retention.purge_expired") as purge:
        monkeypatch.setattr(main.app.state, "arq_pool", object(), raising=False)
        asyncio.run(main.startup_cleanup())
        purge.assert_not_called()
        monkeypatch.setattr(main.app.state, "arq_pool", None, raising=False)
        asyncio.run(main.startup_cleanup())
        purge.assert_called_once()

    from webapp.worker import WorkerSettings
    assert [c.run_at_startup for c in WorkerSettings.cron_jobs] == [True]
