"""Tests for object-level authorization (IDOR/BOLA prevention)."""

import pytest
from cloud_security_case import authorization


def test_insecure_fetch_leaks_other_tenant_workout(db_conn):
    """Verify that insecure_fetch allows BOLA / IDOR leak (vulnerable)."""
    # Bob's workout (wkt_bob_1) can be fetched by anyone without ownership check
    workout = authorization.insecure_fetch(db_conn, "workouts", "wkt_bob_1")
    assert workout["id"] == "wkt_bob_1"
    assert workout["user_id"] == "usr_bob"


def test_secure_fetch_enforces_tenant_boundary(db_conn):
    """Verify that secure_fetch successfully blocks cross-tenant access."""
    # Alice requests Bob's workout
    claims_alice = {"sub": "usr_alice", "email": "alice@gmail.com"}
    with pytest.raises(authorization.AuthorizationError) as exc_info:
        authorization.secure_fetch(db_conn, claims_alice, "workouts", "wkt_bob_1")
    assert "Tenant isolation violation" in str(exc_info.value)


def test_secure_fetch_allows_owner_access(db_conn):
    """Verify that secure_fetch permits owner access to own workout."""
    claims_alice = {"sub": "usr_alice", "email": "alice@gmail.com"}
    workout = authorization.secure_fetch(db_conn, claims_alice, "workouts", "wkt_alice_1")
    assert workout["id"] == "wkt_alice_1"
    assert workout["user_id"] == "usr_alice"


def test_secure_delete_enforces_tenant_boundary(db_conn):
    """Verify that secure_delete blocks cross-tenant deletion."""
    claims_alice = {"sub": "usr_alice", "email": "alice@gmail.com"}
    with pytest.raises(authorization.AuthorizationError) as exc_info:
        authorization.secure_delete(db_conn, claims_alice, "workouts", "wkt_bob_1")
    assert "Tenant isolation violation" in str(exc_info.value)
