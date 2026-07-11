"""Tests verifying correct classification of post-commit failures."""

import pytest
import sqlite3
from cloud_security_case import database, imports, scenarios


def test_post_commit_presentation_failure_handling(db_conn):
    """Verify that a presentation-layer failure does not falsely mask a successful DB write."""
    payload = {
        "user_id": "usr_alice",
        "distance_m": 5000.0,
        "duration_seconds": 1200.0,
        "occurred_at": "2026-07-03",
        "source_provider": "apple_health",
        "external_workout_id": "uuid_post_commit_test_123",
    }

    # Execute secure pathway representing separate transaction & presentation scopes
    status = None
    workout_id = None

    try:
        # Step 1: Database transaction commits successfully
        with database.transaction() as tx_conn:
            workout_id = imports.secure_import(tx_conn, payload)

        # Step 2: Post-commit presentation error occurs (e.g. navigation/view refresh fails)
        imports.run_post_commit_step(throw_error=True)
        status = "SUCCESS"
    except RuntimeError as e:
        status = f"PERSISTED_WITH_PRESENTATION_ERROR (workout_id={workout_id}): {e}"

    # Assert database actually persisted the run row
    cursor = db_conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM runs WHERE external_workout_id = ?",
        ("uuid_post_commit_test_123",),
    )
    count = cursor.fetchone()[0]

    assert count == 1
    assert "PERSISTED_WITH_PRESENTATION_ERROR" in status
    assert workout_id is not None
