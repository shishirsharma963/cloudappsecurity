"""Tests for duplicate import prevention and idempotency."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
import sqlite3
from cloud_security_case import database, imports


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


def test_true_concurrent_duplicate_imports(db_conn):
    """10 threads race to insert the SAME payload at the same instant.

    This is a real interleaving, not sequential theater: a barrier releases
    all threads simultaneously, each opens its own connection and transaction.
    The UNIQUE constraint must admit exactly one row; every loser must recover
    into DuplicateImportError (idempotent 200), and nothing may deadlock or
    surface a raw SQLITE_BUSY/IntegrityError to the caller.
    """
    n_threads = 10
    payload = {
        "user_id": "usr_alice",
        "distance_m": 5000.0,
        "duration_seconds": 1200.0,
        "occurred_at": "2026-07-03",
        "source_provider": "apple_health",
        "external_workout_id": "uuid_race_contended_run",
    }

    barrier = threading.Barrier(n_threads)
    results = []
    results_lock = threading.Lock()

    def worker():
        barrier.wait()  # align all threads at the same release instant
        try:
            with database.transaction() as tx_conn:
                new_id = imports.secure_import(tx_conn, payload)
            outcome = ("created", new_id)
        except imports.DuplicateImportError as e:
            outcome = ("duplicate", e.existing_id)
        except Exception as e:  # any other error is a failure of the invariant
            outcome = ("error", f"{type(e).__name__}: {e}")
        with results_lock:
            results.append(outcome)

    with ThreadPoolExecutor(max_workers=n_threads) as pool:
        for _ in range(n_threads):
            pool.submit(worker)

    created = [r for r in results if r[0] == "created"]
    duplicates = [r for r in results if r[0] == "duplicate"]
    errors = [r for r in results if r[0] == "error"]

    assert errors == [], f"unexpected raw errors under contention: {errors}"
    assert len(created) == 1, f"expected exactly one winner, got {len(created)}"
    assert len(duplicates) == n_threads - 1

    # Every loser recovered the winner's ID — idempotency held under the race
    winner_id = created[0][1]
    assert all(d[1] == winner_id for d in duplicates)

    # And the database holds exactly one physical row
    count = db_conn.execute(
        "SELECT COUNT(*) FROM runs WHERE external_workout_id = ?",
        ("uuid_race_contended_run",),
    ).fetchone()[0]
    assert count == 1


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
