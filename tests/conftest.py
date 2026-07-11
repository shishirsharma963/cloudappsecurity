"""Shared pytest configuration and fixtures for cloudappsecurity."""

import os
import sys
import pytest

# Ensure our library is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cloud_security_case import database, scenarios


@pytest.fixture
def db_conn():
    """Provides a seeded database connection for a single test."""
    db_file = "/Users/shishir/cloudappsecurity/test_db.sqlite"
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except OSError:
            pass
    database.set_db_path(db_file)
    conn = database.get_connection()
    database.init_db(conn)
    scenarios.seed_database(conn)
    yield conn
    conn.close()
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except OSError:
            pass
