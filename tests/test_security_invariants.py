"""Tests mapping directly to our defined security invariants and SOC 2 / NIST rules."""

import pytest
from cloud_security_case import auth, authorization, scenarios


def test_authn_does_not_imply_authz(db_conn):
    """Invariant 4: Authentication does not imply authorization.

    An authenticated user has zero permissions to access another user's resources
    without explicit ownership validation.
    """
    # 1. Authenticate Alice successfully (Authentication check)
    token = scenarios.cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="fitness_api",
    )
    claims = scenarios.cognito.verify_token(token, expected_audience="fitness_api")
    assert claims is not None

    # 2. Assert authorization check blocks Alice from fetching Bob's data (Authorization check)
    with pytest.raises(authorization.AuthorizationError) as exc_info:
        authorization.secure_fetch(db_conn, claims, "workouts", "wkt_bob_1")
    assert "Tenant isolation violation" in str(exc_info.value)


def test_invalid_resource_type_denied_by_default(db_conn):
    """Invariant 10: Unknown/high-risk actions deny by default where appropriate."""
    claims = {"sub": "usr_alice", "email": "alice@gmail.com"}
    with pytest.raises(ValueError) as exc_info:
        authorization.secure_fetch(db_conn, claims, "credit_cards", "card_1")
    assert "Invalid resource type" in str(exc_info.value)


def test_audit_logs_record_required_metadata(db_conn):
    """Invariant 11: Audit records identify actor, action, resource, decision, and reason.

    Ensures all audit records capture necessary metadata for traceability.
    """
    scenarios.execute_flow_1_legit_read(db_conn)

    cursor = db_conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY rowid DESC LIMIT 1")
    row = dict(cursor.fetchone())

    assert row["actor_id"] is not None
    assert row["action"] == "READ"
    assert row["resource_id"] == "wkt_alice_1"
    assert row["decision"] == "ALLOW"
    assert row["reason"] is not None
    assert row["timestamp"] is not None
