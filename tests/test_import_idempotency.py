"""Tests for duplicate import prevention and idempotency."""

import pytest
import sqlite3
from cloud_security_case import imports


def test_import_is_idempotent(db_conn):
    """Verify that importing the same wearable workout twice resolves to the same resource."""
    payload = {
        "user_id": "usr_alice",
        "distance_m": 5000.0,
        "duration_seconds": 1200.0,
        "occurred_at": "2026-07-03",
        "source_provider": "apple_health",
        "external_workout_id": "uuid_apple_watch_run_123",
    }

    # First import
    id1 = imports.secure_import(db_conn, payload)
    assert id1 is not None

    # Second import - raises DuplicateImportError and provides the existing ID
    with pytest.raises(imports.DuplicateImportError) as exc_info:
        imports.secure_import(db_conn, payload)

    assert exc_info.value.existing_id == id1
    assert "already imported" in str(exc_info.value)


def test_validation_rejects_malformed_runs():
    """Verify that validation flags unreasonable or invalid run values."""
    malformed = {
        "user_id": "usr_alice",
        "distance_m": -100.0,  # Negative distance
        "duration_seconds": 1200.0,
        "occurred_at": "2026-07-03",
        "source_provider": "apple_health",
        "external_workout_id": "uuid_bad_run",
    }
    with pytest.raises(imports.ValidationError) as exc_info:
        imports.validate_import_payload(malformed)
    assert "cannot be negative" in str(exc_info.value)
