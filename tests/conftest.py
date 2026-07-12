"""Shared pytest configuration and fixtures for cloudappsecurity."""

import os
import sys
import pytest

# Ensure our library is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cloud_security_case import database, scenarios


@pytest.fixture
def db_conn(tmp_path):
    """Provides a seeded database connection for a single test.

    Each test gets its own database file under pytest's tmp_path: a single
    shared path would make tests stomp on each other under pytest-xdist and
    leave stray artifacts in the repo on a crashed run.
    """
    db_file = str(tmp_path / "test_db.sqlite")
    database.set_db_path(db_file)
    conn = database.get_connection()
    database.init_db(conn)
    scenarios.seed_database(conn)
    yield conn
    conn.close()
