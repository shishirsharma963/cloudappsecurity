"""Tests for hierarchical (nested) resource authorization.

Child rows (workout_sets) carry no user_id. Protecting only the parent route
is not tenant isolation: authorization must follow the ownership chain to its
root when a child is queried directly by ID.
"""

import pytest
from cloud_security_case import authorization


def test_insecure_child_fetch_leaks_across_tenants(db_conn):
    """The vulnerable direct-by-ID child endpoint leaks Bob's set to anyone."""
    row = authorization.insecure_fetch_child(db_conn, "workout_sets", "wst_bob_1")
    assert row["id"] == "wst_bob_1"
    assert row["workout_id"] == "wkt_bob_1"  # nested BOLA: no ownership check possible


def test_secure_child_fetch_blocks_cross_tenant(db_conn):
    """Alice cannot fetch Bob's set even though the set row has no user_id."""
    claims_alice = {"sub": "usr_alice", "email": "alice@gmail.com"}
    with pytest.raises(authorization.AuthorizationError) as exc_info:
        authorization.secure_fetch_child(db_conn, claims_alice, "workout_sets", "wst_bob_1")
    assert "Tenant isolation violation" in str(exc_info.value)
    # The denial must not disclose the actual owner's identity
    assert "usr_bob" not in str(exc_info.value)


def test_secure_child_fetch_allows_owner(db_conn):
    """The owner reaches their own child record through the parent join."""
    claims_alice = {"sub": "usr_alice", "email": "alice@gmail.com"}
    row = authorization.secure_fetch_child(db_conn, claims_alice, "workout_sets", "wst_alice_1")
    assert row["id"] == "wst_alice_1"
    assert row["exercise_name"] == "Back Squat"


def test_secure_child_fetch_unknown_id_raises_not_found(db_conn):
    claims_alice = {"sub": "usr_alice", "email": "alice@gmail.com"}
    with pytest.raises(authorization.ResourceNotFoundError):
        authorization.secure_fetch_child(db_conn, claims_alice, "workout_sets", "wst_ghost")


def test_invalid_child_type_rejected(db_conn):
    """Unknown child tables are refused before any SQL is built."""
    claims_alice = {"sub": "usr_alice", "email": "alice@gmail.com"}
    with pytest.raises(ValueError, match="Invalid child resource type"):
        authorization.secure_fetch_child(db_conn, claims_alice, "credit_cards", "c1")


def test_parent_denial_messages_do_not_disclose_owner(db_conn):
    """Existence-oracle hardening: denials never name the victim tenant."""
    claims_alice = {"sub": "usr_alice", "email": "alice@gmail.com"}
    with pytest.raises(authorization.AuthorizationError) as exc_info:
        authorization.secure_fetch(db_conn, claims_alice, "workouts", "wkt_bob_1")
    assert "usr_bob" not in str(exc_info.value)
