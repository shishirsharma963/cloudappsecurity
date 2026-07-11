"""Database module for managing connection, schema, transactions, and index creation.

Uses SQLite in-memory or on disk with strict PRAGMAs and transaction control.
"""

import sqlite3
from contextlib import contextmanager

_DB_PATH = ":memory:"


def set_db_path(path: str):
    global _DB_PATH
    _DB_PATH = path


def get_connection() -> sqlite3.Connection:
    """Create a connection with foreign keys and WAL mode enabled in autocommit mode."""
    conn = sqlite3.connect(_DB_PATH, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def transaction():
    """Context manager for managing transaction boundaries (commit/rollback)."""
    conn = get_connection()
    try:
        conn.execute("BEGIN TRANSACTION;")
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def init_db(conn: sqlite3.Connection):
    """Initialize the schema with tables, constraints, and indexes."""
    # 1. Users
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )

    # 2. Workouts (Strength / Hybrid shell)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS workouts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            source_name TEXT NOT NULL DEFAULT 'manual',
            hybrid_workout_id TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )

    # 3. Runs (wearable or manual, with unique constraint for duplicate prevention)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            distance_m REAL NOT NULL,
            duration_seconds REAL NOT NULL,
            occurred_at TEXT NOT NULL,
            source_provider TEXT,
            external_workout_id TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, source_provider, external_workout_id)
        );
        """
    )

    # 4. Body Metrics
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS body_metrics (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            metric_type TEXT NOT NULL CHECK(metric_type IN ('weight', 'waist')),
            value REAL NOT NULL,
            occurred_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )

    # 5. Race Goals
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS race_goals (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            target_distance_m REAL NOT NULL,
            target_duration_seconds REAL NOT NULL,
            race_date TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )

    # 6. Audit Logs (structured, redacted logs stored inside the database for compliance)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor_id TEXT,
            resource_id TEXT,
            action TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL,
            detail TEXT NOT NULL
        );
        """
    )

    # Indexes for performance and multi-tenant lookup speed
    conn.execute("CREATE INDEX IF NOT EXISTS idx_workouts_user ON workouts(user_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_user ON runs(user_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_body_metrics_user ON body_metrics(user_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_race_goals_user ON race_goals(user_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_external ON runs(source_provider, external_workout_id);")
