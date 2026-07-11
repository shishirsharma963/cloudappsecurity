"""Authorization module enforcing tenant isolation and object-level permissions.

Contrasts the vulnerable (BOLA/IDOR) resource access patterns with the secure,
tenant-bound patterns.
"""

import sqlite3

VALID_RESOURCES = {"workouts", "runs", "body_metrics", "race_goals"}


class AuthorizationError(Exception):
    pass


class ResourceNotFoundError(Exception):
    pass


def _validate_resource_type(resource_type: str):
    if resource_type not in VALID_RESOURCES:
        raise ValueError(f"Invalid resource type: '{resource_type}'")


def insecure_fetch(conn: sqlite3.Connection, resource_type: str, resource_id: str) -> dict:
    """VULNERABLE PATH: Query resource by ID only.

    Fails to check resource ownership, allowing BOLA / IDOR.
    """
    _validate_resource_type(resource_type)
    cursor = conn.cursor()
    # Query using raw ID only, neglecting tenant boundaries
    cursor.execute(
        f"SELECT * FROM {resource_type} WHERE id = ?",  # safe from SQL Injection via placeholder, but not BOLA
        (resource_id,),
    )
    row = cursor.fetchone()
    if not row:
        raise ResourceNotFoundError(f"Resource '{resource_id}' not found.")
    return dict(row)


def secure_fetch(
    conn: sqlite3.Connection, claims: dict, resource_type: str, resource_id: str
) -> dict:
    """SECURE PATH: Query bound to the authenticated subject (user_id).

    Prevents BOLA / IDOR by enforcing the tenant boundary.
    """
    _validate_resource_type(resource_type)
    user_id = claims.get("sub")
    if not user_id:
        raise AuthorizationError("Missing subject (user_id) in verified token.")

    cursor = conn.cursor()
    # Check if the resource exists at all (for audit/detection purposes)
    cursor.execute(f"SELECT user_id FROM {resource_type} WHERE id = ?", (resource_id,))
    row = cursor.fetchone()

    if not row:
        raise ResourceNotFoundError(f"Resource '{resource_id}' not found.")

    actual_owner = row[0]
    if actual_owner != user_id:
        raise AuthorizationError(
            f"Tenant isolation violation: user '{user_id}' requested access to "
            f"resource '{resource_id}' owned by user '{actual_owner}'."
        )

    # Secure query binding both resource ID and owner
    cursor.execute(
        f"SELECT * FROM {resource_type} WHERE id = ? AND user_id = ?",
        (resource_id, user_id),
    )
    res_row = cursor.fetchone()
    return dict(res_row)


def secure_delete(
    conn: sqlite3.Connection, claims: dict, resource_type: str, resource_id: str
) -> bool:
    """SECURE PATH: Delete resource bound to the tenant."""
    _validate_resource_type(resource_type)
    user_id = claims.get("sub")
    if not user_id:
        raise AuthorizationError("Missing subject (user_id) in verified token.")

    cursor = conn.cursor()
    # Check ownership first
    cursor.execute(f"SELECT user_id FROM {resource_type} WHERE id = ?", (resource_id,))
    row = cursor.fetchone()

    if not row:
        raise ResourceNotFoundError(f"Resource '{resource_id}' not found.")

    actual_owner = row[0]
    if actual_owner != user_id:
        raise AuthorizationError(
            f"Tenant isolation violation: user '{user_id}' attempted to delete "
            f"resource '{resource_id}' owned by user '{actual_owner}'."
        )

    # Enforce isolation at execution
    cursor.execute(
        f"DELETE FROM {resource_type} WHERE id = ? AND user_id = ?",
        (resource_id, user_id),
    )
    return True
