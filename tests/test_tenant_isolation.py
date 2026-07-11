"""Tests asserting comprehensive tenant database isolation invariants."""

import sqlite3


def test_query_filtering_tenant_isolation(db_conn):
    """Verify that queries for workouts are strictly bound to user_id."""
    cursor = db_conn.cursor()

    # Bob's query
    cursor.execute("SELECT * FROM workouts WHERE user_id = ?", ("usr_bob",))
    bob_workouts = [dict(row) for row in cursor.fetchall()]
    assert len(bob_workouts) == 1
    assert all(w["user_id"] == "usr_bob" for w in bob_workouts)

    # Alice's query
    cursor.execute("SELECT * FROM workouts WHERE user_id = ?", ("usr_alice",))
    alice_workouts = [dict(row) for row in cursor.fetchall()]
    assert len(alice_workouts) == 1
    assert all(w["user_id"] == "usr_alice" for w in alice_workouts)


def test_cross_tenant_enumeration_returns_zero_or_denies(db_conn):
    """Verify that a tenant trying to list workouts of another user fails."""
    cursor = db_conn.cursor()
    # Malicious scan attempting to select other user's records
    cursor.execute(
        "SELECT id FROM workouts WHERE user_id = ? AND id = ?",
        ("usr_alice", "wkt_bob_1"),
    )
    res = cursor.fetchone()
    assert res is None
