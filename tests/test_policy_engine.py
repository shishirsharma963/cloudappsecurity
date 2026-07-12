"""Tests for the OPA-style policy engine (policy-as-code authorization)."""

import pytest
from cloud_security_case import authorization


def test_owner_read_allowed_by_policy(db_conn):
    """The owner-full-access policy permits a tenant reading their own resource."""
    claims_alice = {"sub": "usr_alice", "email": "alice@gmail.com"}
    result = authorization.policy_fetch(db_conn, claims_alice, "workouts", "wkt_alice_1")
    assert result["resource"]["id"] == "wkt_alice_1"
    assert result["decision"]["allow"] is True
    assert result["decision"]["policy_id"] == "owner-full-access"


def test_cross_tenant_read_hits_default_deny(db_conn):
    """No policy matches a cross-tenant read, so the engine default-denies."""
    claims_alice = {"sub": "usr_alice", "email": "alice@gmail.com"}
    with pytest.raises(authorization.AuthorizationError, match="default deny"):
        authorization.policy_fetch(db_conn, claims_alice, "workouts", "wkt_bob_1")


def test_cross_tenant_delete_hits_explicit_deny(db_conn):
    """Cross-tenant writes match the explicit deny policy, which overrides."""
    claims_alice = {"sub": "usr_alice", "email": "alice@gmail.com"}
    with pytest.raises(authorization.AuthorizationError, match="deny-cross-tenant-write"):
        authorization.policy_fetch(
            db_conn, claims_alice, "workouts", "wkt_bob_1", action="delete"
        )


def test_deny_overrides_allow():
    """When both an allow and a deny policy match, the deny wins (Rego/IAM semantics)."""
    engine = authorization.PolicyEngine(
        policies=[
            {
                "id": "allow-everything",
                "description": "overly broad allow",
                "effect": "allow",
                "actions": ["read"],
                "resource_types": ["workouts"],
                "condition": {},
            },
            {
                "id": "deny-cross-tenant",
                "description": "cross-tenant deny",
                "effect": "deny",
                "actions": ["read"],
                "resource_types": ["workouts"],
                "condition": {"resource.user_id": {"not_equals": "input.subject"}},
            },
        ]
    )
    decision = engine.evaluate(
        {
            "subject": "usr_alice",
            "action": "read",
            "resource": {"type": "workouts", "id": "wkt_bob_1", "user_id": "usr_bob"},
        }
    )
    assert decision["allow"] is False
    assert decision["policy_id"] == "deny-cross-tenant"


def test_empty_policy_set_denies_everything():
    """An engine with no policies must default-deny, never default-allow."""
    engine = authorization.PolicyEngine(policies=[])
    decision = engine.evaluate(
        {
            "subject": "usr_alice",
            "action": "read",
            "resource": {"type": "workouts", "id": "wkt_alice_1", "user_id": "usr_alice"},
        }
    )
    assert decision["allow"] is False
    assert decision["policy_id"] is None


def test_policy_fetch_unknown_resource_raises_not_found(db_conn):
    """Nonexistent resources surface as not-found before any policy evaluation."""
    claims_alice = {"sub": "usr_alice", "email": "alice@gmail.com"}
    with pytest.raises(authorization.ResourceNotFoundError):
        authorization.policy_fetch(db_conn, claims_alice, "workouts", "wkt_ghost")
