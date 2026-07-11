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
