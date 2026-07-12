"""Tests verifying structured audit log redaction controls."""

import json
import pytest
from cloud_security_case import audit


def test_audit_log_pii_redaction(db_conn):
    """Verify that secure logging successfully redacts emails, tokens, and weight metrics."""
    detail = {
        "email": "alice@gmail.com",
        "weight": 70.2,
        "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfYWxpY2UiLCJhdWQiOiJmaXRuZXNzX2FwaSJ9.signature_value",
        "device": "WatchOS",
    }

    # Insecure logging
    audit.insecure_log(
        db_conn,
        event_type="ACCESS",
        actor_id="alice@gmail.com",
        resource_id="w123",
        action="READ",
        decision="ALLOW",
        reason="Owner read",
        detail=detail,
    )

    # Secure logging
    audit.secure_log(
        db_conn,
        event_type="ACCESS",
        actor_id="alice@gmail.com",
        resource_id="w123",
        action="READ",
        decision="ALLOW",
        reason="Owner read",
        detail=detail,
    )

    # Fetch logs from DB
    cursor = db_conn.cursor()
    cursor.execute("SELECT actor_id, detail FROM audit_logs ORDER BY rowid ASC")
    logs = cursor.fetchall()

    insecure_log_row = logs[0]
    secure_log_row = logs[1]

    # Verify insecure leak
    insecure_detail = json.loads(insecure_log_row["detail"])
    assert insecure_log_row["actor_id"] == "alice@gmail.com"
    assert insecure_detail["email"] == "alice@gmail.com"
    assert "eyJhbGciOi" in insecure_detail["token"]
    assert insecure_detail["weight"] == 70.2

    # Verify secure redaction
    secure_detail = json.loads(secure_log_row["detail"])
    assert secure_log_row["actor_id"] == "[REDACTED_EMAIL]"
    assert secure_detail["email"] == "[REDACTED_SENSITIVE_DATA]"
    assert secure_detail["token"] == "[REDACTED_SENSITIVE_DATA]"
    assert secure_detail["weight"] == "[REDACTED_SENSITIVE_DATA]"
    assert secure_detail["device"] == "WatchOS"  # Unchanged


def test_camel_and_snake_case_health_keys_redacted():
    """A new metric added in any naming convention must not leak.

    This was the original scrubber's exact failure mode: it matched only
    lowercase exact keys, so `bodyFatPercentage` sailed straight through.
    """
    payload = {
        "bodyFatPercentage": 24.1,
        "heartRateMax": 182,
        "heart_rate_max": 182,
        "body_fat_pct": 24.1,
        "resting-heart-rate": 51,
    }
    cleaned = audit.redact_structure(payload)
    for key in payload:
        assert cleaned[key] == "[REDACTED_SENSITIVE_DATA]", f"{key} leaked"


def test_credential_and_contact_key_variants_redacted():
    payload = {
        "apiKey": "sk_live_abc",
        "refreshToken": "rt_xyz",
        "userContactString": "call me",
        "phoneNumber": "+1 555 0100",
    }
    cleaned = audit.redact_structure(payload)
    for key in payload:
        assert cleaned[key] == "[REDACTED_SENSITIVE_DATA]", f"{key} leaked"


def test_nested_email_in_free_text_redacted():
    """Emails inside nested string values are caught by the text scrubber."""
    payload = {"metadata": {"note": "escalate to alice@gmail.com by Friday"}}
    cleaned = audit.redact_structure(payload)
    assert "alice@gmail.com" not in json.dumps(cleaned)
    assert "[REDACTED_EMAIL]" in cleaned["metadata"]["note"]


def test_unrecognized_numerics_in_health_context_fail_closed():
    """Numbers the scrubber cannot classify inside a health container are
    redacted by default — under-redaction is a breach, over-redaction is
    merely a less useful log line."""
    payload = {"biometrics": {"recoveryIndex": 33.5, "strainScore": 18.2, "id": "b1", "setNumber": 3}}
    cleaned = audit.redact_structure(payload)
    assert cleaned["biometrics"]["recoveryIndex"] == "[REDACTED_SENSITIVE_DATA]"
    assert cleaned["biometrics"]["strainScore"] == "[REDACTED_SENSITIVE_DATA]"
    # Structural fields survive so logs remain correlatable
    assert cleaned["biometrics"]["id"] == "b1"
    assert cleaned["biometrics"]["setNumber"] == 3


def test_non_health_numerics_are_preserved():
    """The fail-closed rule must not destroy log utility outside health context."""
    payload = {"workout": {"distance_m": 5000.0, "duration_seconds": 1200.0}, "retries": 2}
    cleaned = audit.redact_structure(payload)
    assert cleaned["workout"]["distance_m"] == 5000.0
    assert cleaned["workout"]["duration_seconds"] == 1200.0
    assert cleaned["retries"] == 2


def test_secure_log_scrubs_reason_field(db_conn):
    """Denial reasons are exception text and can echo user input — scrub them."""
    audit.secure_log(
        db_conn,
        event_type="DATA_ACCESS",
        actor_id="usr_alice",
        resource_id="w1",
        action="READ",
        decision="DENY",
        reason="denied request from alice@gmail.com with token eyJhbGciOi.eyJzdWIi.sig",
        detail={},
    )
    row = db_conn.execute("SELECT reason FROM audit_logs ORDER BY rowid DESC LIMIT 1").fetchone()
    assert "alice@gmail.com" not in row["reason"]
    assert "[REDACTED_EMAIL]" in row["reason"]
    assert "[REDACTED_JWT]" in row["reason"]
