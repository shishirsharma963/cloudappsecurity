"""Tests verifying transactional atomic rollback behavior."""

import pytest
import sqlite3
from cloud_security_case import database, imports


def test_transaction_rollback_on_failure(db_conn):
    """Verify that a database transaction rolls back all changes if a failure occurs mid-operation."""
    # First insert is valid, second one is invalid and throws. Both are in the same transaction block.
    valid_payload = {
        "user_id": "usr_alice",
        "distance_m": 3000.0,
        "duration_seconds": 900.0,
        "occurred_at": "2026-07-03",
        "source_provider": "apple_health",
        "external_workout_id": "uuid_valid_123",
    }
    invalid_payload = {
        "user_id": "usr_alice",
        "distance_m": -50.0,  # Fails validation
        "duration_seconds": 200.0,
        "occurred_at": "2026-07-03",
        "source_provider": "apple_health",
        "external_workout_id": "uuid_invalid_456",
    }

    try:
        with database.transaction() as tx_conn:
            # First write succeeds (locally in transaction)
            imports.secure_import(tx_conn, valid_payload)
            # Second write throws ValidationError, aborting and triggering rollback
            imports.secure_import(tx_conn, invalid_payload)
    except imports.ValidationError:
        pass

    # Verify that the first write was rolled back and does not exist in the database
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM runs WHERE external_workout_id = ?",
        ("uuid_valid_123",),
    )
    count = cursor.fetchone()[0]
    conn.close()

    assert count == 0, "The first write was not rolled back despite transaction failure!"
