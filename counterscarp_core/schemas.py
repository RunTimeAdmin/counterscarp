"""Shared Pydantic schemas for license operations."""

from typing import Annotated

from pydantic import BaseModel, StringConstraints


class ValidateRequest(BaseModel):
    license_key: Annotated[
        str,
        StringConstraints(pattern=r"^SE-(DEV|PRO|TEAM|ENT)-[0-9a-f]{32}$"),
    ]
    machine_id: Annotated[
        str,
        StringConstraints(max_length=255, pattern=r"^[a-zA-Z0-9\-_:.]{1,255}$"),
    ]
    product_version: Annotated[
        str,
        StringConstraints(pattern=r"^\d+\.\d+\.\d+.*$", max_length=20),
    ]
    timestamp: Annotated[
        str,
        StringConstraints(
            pattern=r"^\d{4}-\d{2}-\d{2}T[\d:.]+[Z+\-\d:]*$",
            max_length=40,
        ),
    ]


class ValidateResponse(BaseModel):
    valid: bool
    error: str | None = None
    tier: str | None = None
    expires_at: str | None = None
    features: list[str] | None = None
    max_activations: int | None = None
    current_activations: int | None = None


class DeactivateRequest(BaseModel):
    license_key: Annotated[
        str,
        StringConstraints(pattern=r"^SE-(DEV|PRO|TEAM|ENT)-[0-9a-f]{32}$"),
    ]
    machine_id: Annotated[
        str,
        StringConstraints(max_length=255, pattern=r"^[a-zA-Z0-9\-_:.]{1,255}$"),
    ]


class DeactivateResponse(BaseModel):
    success: bool
    remaining_activations: int


class LicenseInfoResponse(BaseModel):
    key_masked: str
    tier: str
    customer_email: str
    expires_at: str
    max_activations: int
    current_activations: int
    revoked: bool
    created_at: str
