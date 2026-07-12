"""Tests for automated incident-response containment (session revocation)."""

import json

import pytest
from cloud_security_case import auth, containment, detection


@pytest.fixture
def alice_claims(db_conn):
    """Mint a valid token for Alice and register its session."""
    cognito = auth.CognitoProvider()
    token = cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="fitness_api",
    )
    claims = cognito.verify_token(token, expected_audience="fitness_api")
    containment.create_session(db_conn, user_id="usr_alice", token_jti=claims["jti"])
    return claims


def test_active_session_passes_gate(db_conn, alice_claims):
    """A registered, unrevoked session passes the request-time gate."""
    containment.require_active_session(db_conn, alice_claims)  # must not raise


def test_unknown_jti_is_rejected(db_conn):
    """A token whose jti has no session record is rejected (no implicit trust)."""
    with pytest.raises(containment.SessionRevokedError, match="jti unknown"):
        containment.require_active_session(db_conn, {"jti": "jti_never_issued"})


def test_revocation_blocks_still_valid_token(db_conn, alice_claims):
    """After revocation, a cryptographically valid JWT is rejected server-side."""
    revoked = containment.revoke_user_sessions(
        db_conn, user_id="usr_alice", reason="manual containment"
    )
    assert revoked == 1
    with pytest.raises(containment.SessionRevokedError, match="session revoked"):
        containment.require_active_session(db_conn, alice_claims)


def test_exfiltration_alert_triggers_containment(db_conn, alice_claims):
    """A CRITICAL bulk-exfiltration alert auto-revokes the user's sessions."""
    detector = detection.AnomalyDetector(
        alert_hooks=[containment.build_containment_hook(db_conn)]
    )

    alert = None
    for _ in range(6):
        result = detector.log_event("usr_alice", allowed=True)
        if result:
            alert = result
            break

    assert alert is not None
    assert alert["alert"] == "BULK_EXFILTRATION_WARNING"
    assert alert["containment_actions"][0]["sessions_revoked"] == 1

    # The attacker's token is now dead at the session gate
    with pytest.raises(containment.SessionRevokedError):
        containment.require_active_session(db_conn, alice_claims)


def test_containment_writes_redacted_audit_event(db_conn, alice_claims):
    """The containment action itself is audit-logged for the incident timeline."""
    detector = detection.AnomalyDetector(
        alert_hooks=[containment.build_containment_hook(db_conn)]
    )
    for _ in range(6):
        if detector.log_event("usr_alice", allowed=True):
            break

    row = db_conn.execute(
        "SELECT * FROM audit_logs WHERE event_type = 'AUTO_CONTAINMENT'"
    ).fetchone()
    assert row is not None
    assert row["action"] == "REVOKE_SESSIONS"
    assert row["decision"] == "ENFORCED"
    detail = json.loads(row["detail"])
    assert detail["sessions_revoked"] == 1


def test_high_severity_alert_does_not_revoke(db_conn, alice_claims):
    """BOLA-scan (HIGH) alerts flag but do not auto-revoke; only CRITICAL contains."""
    detector = detection.AnomalyDetector(
        alert_hooks=[containment.build_containment_hook(db_conn)]
    )
    alert = None
    for _ in range(3):
        result = detector.log_event("usr_alice", allowed=False)
        if result:
            alert = result

    assert alert is not None
    assert alert["severity"] == "HIGH"
    assert "containment_actions" not in alert
    containment.require_active_session(db_conn, alice_claims)  # still active
