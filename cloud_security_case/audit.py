"""Audit module handling structured auditing and sensitive data redaction.

Scans audit details for credentials (JWTs) and PII (emails, body metrics) and
redacts them before they enter the database or log files.
"""

import datetime
import json
import re
import sqlite3
import uuid

JWT_REGEX = re.compile(r"ey[a-zA-Z0-9-_=]+\.[a-zA-Z0-9-_=]+\.?[a-zA-Z0-9-_.+/=]*")
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

SENSITIVE_KEYS = {
    "email",
    "weight",
    "waist",
    "value",
    "authorization",
    "token",
    "password",
    "secret",
}


def redact_text(text: str) -> str:
    """Scrub raw text lines of visible JWT signatures and email structures."""
    if not isinstance(text, str):
        return str(text)
    text = JWT_REGEX.sub("[REDACTED_JWT]", text)
    text = EMAIL_REGEX.sub("[REDACTED_EMAIL]", text)
    return text


def redact_structure(data: dict | list) -> dict | list:
    """Recursively traverses dictionary or list structure, redacting sensitive keys and texts."""
    if isinstance(data, list):
        return [
            redact_structure(item)
            if isinstance(item, (dict, list))
            else (redact_text(item) if isinstance(item, str) else item)
            for item in data
        ]

    if not isinstance(data, dict):
        return data

    cleaned = {}
    for k, v in data.items():
        k_lower = k.lower()
        if k_lower in SENSITIVE_KEYS:
            cleaned[k] = "[REDACTED_SENSITIVE_DATA]"
        elif isinstance(v, (dict, list)):
            cleaned[k] = redact_structure(v)
        elif isinstance(v, str):
            cleaned[k] = redact_text(v)
        else:
            cleaned[k] = v
    return cleaned


def insecure_log(
    conn: sqlite3.Connection,
    *,
    event_type: str,
    actor_id: str | None,
    resource_id: str | None,
    action: str,
    decision: str,
    reason: str,
    detail: dict,
):
    """VULNERABLE PATH: Log event directly with raw dictionary payload.

    Allows PII and credentials to leak into persistent logs.
    """
    cursor = conn.cursor()
    log_id = str(uuid.uuid4())
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    cursor.execute(
        """
        INSERT INTO audit_logs (id, timestamp, event_type, actor_id, resource_id, action, decision, reason, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            log_id,
            timestamp,
            event_type,
            actor_id,
            resource_id,
            action,
            decision,
            reason,
            json.dumps(detail),
        ),
    )


def secure_log(
    conn: sqlite3.Connection,
    *,
    event_type: str,
    actor_id: str | None,
    resource_id: str | None,
    action: str,
    decision: str,
    reason: str,
    detail: dict,
):
    """SECURE PATH: Logs event after scrubbing actor_id and details of PII/JWTs."""
    cursor = conn.cursor()
    log_id = str(uuid.uuid4())
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Redact email from actor_id if it's formatted as one
    clean_actor = redact_text(actor_id) if actor_id else "anonymous"
    clean_detail = redact_structure(detail)

    cursor.execute(
        """
        INSERT INTO audit_logs (id, timestamp, event_type, actor_id, resource_id, action, decision, reason, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            log_id,
            timestamp,
            event_type,
            clean_actor,
            resource_id,
            action,
            decision,
            reason,
            json.dumps(clean_detail),
        ),
    )
