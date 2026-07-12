"""Containment module for automated incident response.

Stateless JWTs cannot be un-signed: a stolen or abused token stays
cryptographically valid until it expires. Revocation therefore requires a
server-side check — a session record keyed by the token's `jti` claim that the
API consults on every request (Cognito exposes this as GlobalSignOut /
RevokeToken). This module provides that session plane plus a containment hook
the anomaly detector can invoke to disable a user's active sessions the moment
an exfiltration alert fires.
"""

import datetime
import sqlite3
import uuid

from cloud_security_case import audit


class SessionRevokedError(Exception):
    pass


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def create_session(conn: sqlite3.Connection, *, user_id: str, token_jti: str) -> str:
    """Record an active session for a minted token (login time)."""
    session_id = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO sessions (id, user_id, token_jti, status, created_at)
        VALUES (?, ?, ?, 'active', ?)
        """,
        (session_id, user_id, token_jti, _now_iso()),
    )
    return session_id


def revoke_user_sessions(conn: sqlite3.Connection, *, user_id: str, reason: str) -> int:
    """Revoke every active session for a user. Returns the number revoked.

    Production equivalent: cognito-idp AdminUserGlobalSignOut, which invalidates
    all refresh tokens and marks access tokens for rejection at the API layer.
    """
    cursor = conn.execute(
        """
        UPDATE sessions
        SET status = 'revoked', revoked_at = ?, revoked_reason = ?
        WHERE user_id = ? AND status = 'active'
        """,
        (_now_iso(), reason, user_id),
    )
    return cursor.rowcount


def require_active_session(conn: sqlite3.Connection, claims: dict):
    """Request-time gate: a cryptographically valid token is still rejected
    if its session has been revoked. Raises SessionRevokedError on revocation."""
    row = conn.execute(
        "SELECT status, revoked_reason FROM sessions WHERE token_jti = ?",
        (claims.get("jti"),),
    ).fetchone()
    if row is None:
        raise SessionRevokedError("no session on record for this token (jti unknown)")
    if row["status"] != "active":
        raise SessionRevokedError(
            f"session revoked: {row['revoked_reason'] or 'no reason recorded'}"
        )


def build_containment_hook(conn: sqlite3.Connection, revocation_list=None):
    """Build an alert hook for the AnomalyDetector.

    When a CRITICAL alert fires, the hook revokes the offending user's active
    sessions and writes a redacted audit event, then returns a summary of the
    containment action so the caller (SOC dashboard, demo) can display it.

    If an `auth.RevocationList` is supplied, the user's subject is also
    tombstoned on the edge deny-list, so the token dies at the *gateway*
    (verify_token) as well as at the app-layer session gate — the same event
    feeding both revocation planes.
    """

    def on_alert(alert: dict) -> dict | None:
        if alert.get("severity") != "CRITICAL":
            return None
        reason = f"auto-containment: {alert['alert']} ({alert['count']} events in {alert['window_seconds']}s)"
        revoked = revoke_user_sessions(conn, user_id=alert["user_id"], reason=reason)
        if revocation_list is not None:
            revocation_list.revoke_subject(alert["user_id"])
        audit.secure_log(
            conn,
            event_type="AUTO_CONTAINMENT",
            actor_id="anomaly-detector",
            resource_id=alert["user_id"],
            action="REVOKE_SESSIONS",
            decision="ENFORCED",
            reason=reason,
            detail={"alert": alert, "sessions_revoked": revoked},
        )
        return {"action": "REVOKE_SESSIONS", "user_id": alert["user_id"], "sessions_revoked": revoked}

    return on_alert
