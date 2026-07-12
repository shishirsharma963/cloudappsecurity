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

# ---------------------------------------------------------------------------
# Classification-driven redaction
#
# A hardcoded exact-match key list is brittle: `weight` is caught while
# `bodyFatPercentage`, `heartRateMax`, or `body_fat_pct` sail through the
# moment a developer adds a new metric. Keys are therefore normalized
# (lowercased, separators stripped, so camelCase / snake_case / kebab-case
# all collapse to one token) and matched against *classification markers* by
# substring. Unknown numeric values inside a health-context container are
# redacted by default: the scrubber fails closed on data it cannot classify,
# because the failure mode of over-redaction is a less useful log line, while
# the failure mode of under-redaction is a PII breach in every log sink.
# ---------------------------------------------------------------------------

# Marker substrings matched against normalized keys.
CREDENTIAL_MARKERS = (
    "token", "secret", "password", "credential", "apikey",
    "authorization", "jwt", "bearer", "privatekey",
)
CONTACT_MARKERS = ("email", "phone", "contact", "ssn", "passport", "birth")
HEALTH_MARKERS = (
    "weight", "waist", "bodyfat", "heartrate", "pulse", "hrv", "bmi",
    "bloodpressure", "glucose", "vo2", "calorie", "bodymass", "menstrual",
)
# Exact normalized keys that are sensitive only as a whole word ("value" is
# the generic body_metrics column; matching it as a substring would nuke
# harmless keys like "value_type").
EXACT_SENSITIVE_KEYS = ("value",)

# Container keys that place their entire subtree in health context.
HEALTH_CONTEXT_MARKERS = (
    "biometric", "bodymetric", "health", "vitals", "measurement",
    "wellness", "metrics",
)
# Numeric values under these normalized keys survive inside health context —
# structural fields, not measurements.
STRUCTURAL_NUMERIC_ALLOWLIST = (
    "id", "count", "timestamp", "epoch", "version", "page", "offset",
    "limit", "setnumber", "reps",
)

_NORMALIZE_RE = re.compile(r"[^a-z0-9]")


def _normalize_key(key: str) -> str:
    """Collapse camelCase / snake_case / kebab-case to one comparable token."""
    return _NORMALIZE_RE.sub("", key.lower())


def _key_is_sensitive(norm_key: str) -> bool:
    if norm_key in EXACT_SENSITIVE_KEYS:
        return True
    return any(
        marker in norm_key
        for markers in (CREDENTIAL_MARKERS, CONTACT_MARKERS, HEALTH_MARKERS)
        for marker in markers
    )


def redact_text(text: str) -> str:
    """Scrub raw text lines of visible JWT signatures and email structures."""
    if not isinstance(text, str):
        return str(text)
    text = JWT_REGEX.sub("[REDACTED_JWT]", text)
    text = EMAIL_REGEX.sub("[REDACTED_EMAIL]", text)
    return text


def _redact(data, in_health_context: bool, parent_key: str = ""):
    if isinstance(data, list):
        return [_redact(item, in_health_context) for item in data]

    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            norm = _normalize_key(k)
            if _key_is_sensitive(norm):
                cleaned[k] = "[REDACTED_SENSITIVE_DATA]"
            else:
                child_context = in_health_context or any(
                    marker in norm for marker in HEALTH_CONTEXT_MARKERS
                )
                cleaned[k] = _redact(v, child_context, parent_key=norm)
        return cleaned

    if isinstance(data, str):
        return redact_text(data)

    # Fail-safe: an unclassified number inside a health-context subtree is
    # assumed to be a body measurement unless its key is structural.
    if (
        in_health_context
        and isinstance(data, (int, float))
        and not isinstance(data, bool)
        and parent_key not in STRUCTURAL_NUMERIC_ALLOWLIST
    ):
        return "[REDACTED_SENSITIVE_DATA]"

    return data


def redact_structure(data: dict | list) -> dict | list:
    """Recursively redact sensitive keys, texts, and health-context numerics."""
    return _redact(data, in_health_context=False)


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
    # Denial reasons are built from exception text and can echo user input
    # (emails, tokens) — scrub them like any other free-text field.
    clean_reason = redact_text(reason)

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
            clean_reason,
            json.dumps(clean_detail),
        ),
    )
