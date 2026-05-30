"""HTTP client for the Counterscarp /api/v1/scan endpoints."""

from __future__ import annotations

import os
import time
from typing import Any

import requests


class CounterscarpClient:
    """Submit scans and poll until complete."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        poll_interval: float | None = None,
        timeout: float | None = None,
    ) -> None:
        self.base_url = (
            base_url or os.environ.get("COUNTERSCARP_API_URL", "http://localhost:8001")
        ).rstrip("/")
        self.api_key = api_key or os.environ.get("COUNTERSCARP_API_KEY", "")
        if not self.api_key:
            raise ValueError("COUNTERSCARP_API_KEY is required")

        self.poll_interval = float(
            poll_interval or os.environ.get("COUNTERSCARP_POLL_INTERVAL", "5")
        )
        self.timeout = float(
            timeout or os.environ.get("COUNTERSCARP_SCAN_TIMEOUT", "600")
        )
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
        )

    def submit_scan(
        self,
        filename: str,
        content: str,
        project_name: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "project_name": project_name or filename,
            "files": [{"filename": filename, "content": content}],
        }
        response = self.session.post(
            f"{self.base_url}/api/v1/scan",
            json=payload,
            timeout=60,
        )
        response.raise_for_status()
        return response.json()

    def get_scan(
        self,
        audit_id: str,
        *,
        include_findings: bool = False,
    ) -> dict[str, Any]:
        params = {"include_findings": "true"} if include_findings else {}
        response = self.session.get(
            f"{self.base_url}/api/v1/scan/{audit_id}",
            params=params,
            timeout=60,
        )
        response.raise_for_status()
        return response.json()

    def wait_for_scan(self, audit_id: str) -> dict[str, Any]:
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            data = self.get_scan(audit_id)
            status = data.get("status")
            if status == "complete":
                return self.get_scan(audit_id, include_findings=True)
            if status == "failed":
                raise RuntimeError(data.get("progress", "Scan failed"))
            time.sleep(self.poll_interval)
        raise TimeoutError(
            f"Scan {audit_id} did not complete within {self.timeout:.0f}s"
        )

    def scan_contract(
        self,
        filename: str,
        content: str,
        project_name: str | None = None,
    ) -> dict[str, Any]:
        submitted = self.submit_scan(filename, content, project_name)
        return self.wait_for_scan(submitted["audit_id"])
