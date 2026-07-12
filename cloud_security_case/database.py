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
    """Create a connection with foreign keys and WAL mode enabled in autocommit mode.

    timeout=5.0 sets SQLite's busy handler: a writer blocked by another writer
    waits up to 5s for the lock instead of failing immediately with
    SQLITE_BUSY. Required for correctness under concurrent write contention.
    """
    conn = sqlite3.connect(_DB_PATH, isolation_level=None, timeout=5.0)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def transaction():
    """Context manager for managing transaction boundaries (commit/rollback).

    Uses BEGIN IMMEDIATE, not deferred BEGIN: the write lock is acquired up
    front, so concurrent transactions serialize at entry. A deferred BEGIN
    takes a read snapshot first and upgrades to a write lock at the first
    write — under WAL, if another writer committed in between, that upgrade
    fails immediately with SQLITE_BUSY (snapshot too old) rather than waiting,
    turning benign contention into spurious 500s.
    """
    if _DB_PATH == ":memory:":
        # Each sqlite3 connection to ":memory:" is its own private database.
        # A transaction opened here would commit to a throwaway DB and vanish,
        # silently diverging from connections used elsewhere. Fail loudly.
        raise RuntimeError(
            "transaction() requires a file-backed database: call set_db_path() first "
            "(':memory:' would give this transaction its own private, invisible database)"
        )
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE TRANSACTION;")
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

    # 3b. Workout Sets — CHILD of workouts. Deliberately normalized: no user_id
    # column. Ownership is derivable only through the parent workout, which is
    # exactly the shape that produces nested-BOLA bugs when an endpoint fetches
    # a child by ID without joining to the parent's owner.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS workout_sets (
            id TEXT PRIMARY KEY,
            workout_id TEXT NOT NULL,
            exercise_name TEXT NOT NULL,
            set_number INTEGER NOT NULL,
            weight_kg REAL NOT NULL,
            reps INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (workout_id) REFERENCES workouts(id) ON DELETE CASCADE
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

    # 6. Sessions (server-side session records enabling revocation of stateless JWTs;
    #    stands in for Cognito's GlobalSignOut / RevokeToken plane)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_jti TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked')),
            created_at TEXT NOT NULL,
            revoked_at TEXT,
            revoked_reason TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )

    # 7. Audit Logs (structured, redacted logs stored inside the database for compliance)
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
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_workout_sets_workout ON workout_sets(workout_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);")
