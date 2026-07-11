"""Imports module handling wearable workout import pipeline, idempotency, and racing.

Enforces structural validations, handles duplicate check races, and separates
database transaction boundaries from presentation-layer outcomes.
"""

import sqlite3
import uuid
from datetime import datetime
from cloud_security_case import database


class ValidationError(Exception):
    pass


class DuplicateImportError(Exception):
    def __init__(self, message: str, existing_id: str):
        super().__init__(message)
        self.existing_id = existing_id


def validate_import_payload(payload: dict):
    """Enforces validation invariants: distances/durations must be positive, reasonable numbers."""
    required = {
        "user_id",
        "distance_m",
        "duration_seconds",
        "occurred_at",
        "source_provider",
        "external_workout_id",
    }
    missing = required - set(payload.keys())
    if missing:
        raise ValidationError(f"Missing required fields: {', '.join(missing)}")

    # Type validation
    if not isinstance(payload["distance_m"], (int, float)):
        raise ValidationError("distance_m must be a number.")
    if not isinstance(payload["duration_seconds"], (int, float)):
        raise ValidationError("duration_seconds must be a number.")

    # Invariant validation
    if payload["distance_m"] < 0:
        raise ValidationError("distance_m cannot be negative.")
    if payload["duration_seconds"] <= 0:
        raise ValidationError("duration_seconds must be positive.")

    # High-risk / unreasonable boundary validation
    if payload["distance_m"] > 100000:  # 100km
        raise ValidationError(
            f"distance_m '{payload['distance_m']}' exceeds reasonable single-run limit."
        )


def insecure_import(conn: sqlite3.Connection, payload: dict) -> str:
    """VULNERABLE PATH: Import wearable workout.

    - Fails to use explicit transactions for database operations.
    - Uses manual application-level check for duplicate detection before write,
      which creates a race condition window.
    - Misinterprets post-commit presentation failures as database persistence failures.
    """
    validate_import_payload(payload)

    # 1. Manual check (Bypasses atomic unique constraint check at query time)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id FROM runs
        WHERE user_id = ? AND source_provider = ? AND external_workout_id = ?
        """,
        (
            payload["user_id"],
            payload["source_provider"],
            payload["external_workout_id"],
        ),
    )
    row = cursor.fetchone()
    if row:
        # If we see it, return it. But in a multi-threaded race, two threads
        # could both pass this check before either inserts, causing a crash or double insert.
        return row[0]

    # Simulating a race condition pause where another thread could run and write first
    # (in the demo we will simulate this explicitly)

    workout_id = str(uuid.uuid4())
    now_str = datetime.now().isoformat()

    # 2. Raw insert without transaction context
    cursor.execute(
        """
        INSERT INTO runs (
            id, user_id, distance_m, duration_seconds, occurred_at,
            source_provider, external_workout_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            workout_id,
            payload["user_id"],
            payload.get("distance_m"),
            payload.get("duration_seconds"),
            payload.get("occurred_at"),
            payload.get("source_provider"),
            payload.get("external_workout_id"),
            now_str,
        ),
    )

    return workout_id


def secure_import(conn: sqlite3.Connection, payload: dict) -> str:
    """SECURE PATH: Import wearable workout.

    - Relies on database unique constraints for atomic duplicate checks.
    - Recovers gracefully from unique constraint violations to maintain idempotency.
    - Must be wrapped in a transaction at the caller layer.
    """
    validate_import_payload(payload)

    workout_id = str(uuid.uuid4())
    now_str = datetime.now().isoformat()

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO runs (
                id, user_id, distance_m, duration_seconds, occurred_at,
                source_provider, external_workout_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                workout_id,
                payload["user_id"],
                payload["distance_m"],
                payload["duration_seconds"],
                payload["occurred_at"],
                payload["source_provider"],
                payload["external_workout_id"],
                now_str,
            ),
        )
        return workout_id
    except sqlite3.IntegrityError as e:
        # Gracefully handle the uniqueness conflict to ensure idempotency.
        # Fetch the existing ID to return it to the caller.
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id FROM runs
            WHERE user_id = ? AND source_provider = ? AND external_workout_id = ?
            """,
            (
                payload["user_id"],
                payload["source_provider"],
                payload["external_workout_id"],
            ),
        )
        existing_row = cursor.fetchone()
        if existing_row:
            existing_id = existing_row[0]
            raise DuplicateImportError(
                f"Idempotency Guard: workout '{payload['external_workout_id']}' already imported.",
                existing_id,
            )
        raise e


def run_post_commit_step(throw_error: bool = False):
    """Simulates a secondary step (e.g. rendering UI, refreshing view) that runs post-commit."""
    if throw_error:
        raise RuntimeError("UI navigation render failure (post-commit).")
