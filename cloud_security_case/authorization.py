"""Authorization module enforcing tenant isolation and object-level permissions.

Contrasts the vulnerable (BOLA/IDOR) resource access patterns with the secure,
tenant-bound patterns.
"""

import sqlite3

VALID_RESOURCES = {"workouts", "runs", "body_metrics", "race_goals"}

# Child resources carry no user_id of their own; ownership is derived through
# the parent row. Maps child table -> (parent table, FK column on the child).
CHILD_RESOURCES = {"workout_sets": ("workouts", "workout_id")}


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
        # Do NOT name the actual owner: the denial text flows into API errors
        # and audit reasons, and disclosing the victim's user ID would hand an
        # enumerator exactly the tenant mapping they are probing for.
        raise AuthorizationError(
            f"Tenant isolation violation: user '{user_id}' requested access to "
            f"resource '{resource_id}' they do not own."
        )

    # Secure query binding both resource ID and owner
    cursor.execute(
        f"SELECT * FROM {resource_type} WHERE id = ? AND user_id = ?",
        (resource_id, user_id),
    )
    res_row = cursor.fetchone()
    return dict(res_row)


def _validate_child_type(child_type: str):
    if child_type not in CHILD_RESOURCES:
        raise ValueError(f"Invalid child resource type: '{child_type}'")


def insecure_fetch_child(conn: sqlite3.Connection, child_type: str, child_id: str) -> dict:
    """VULNERABLE PATH: fetch a child record by its own ID only.

    The parent workout may be perfectly tenant-bound, but this endpoint
    queries the child directly. Because the child row has no user_id, there
    is nothing to check against — a nested BOLA: /workouts/{id} is protected
    while /sets/{id} leaks any tenant's data.
    """
    _validate_child_type(child_type)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {child_type} WHERE id = ?", (child_id,))
    row = cursor.fetchone()
    if not row:
        raise ResourceNotFoundError(f"Resource '{child_id}' not found.")
    return dict(row)


def secure_fetch_child(
    conn: sqlite3.Connection, claims: dict, child_type: str, child_id: str
) -> dict:
    """SECURE PATH: fetch a child record with ownership derived via the parent.

    Joins the child to its parent table and binds the parent's user_id to the
    authenticated subject. Authorization must follow the ownership chain to
    its root for every level of nesting — protecting only the top-level
    route is not tenant isolation.
    """
    _validate_child_type(child_type)
    user_id = claims.get("sub")
    if not user_id:
        raise AuthorizationError("Missing subject (user_id) in verified token.")

    parent_table, fk_column = CHILD_RESOURCES[child_type]
    cursor = conn.cursor()

    # Resolve the owner through the parent chain (for 404-vs-deny and audit)
    cursor.execute(
        f"""
        SELECT p.user_id FROM {child_type} c
        JOIN {parent_table} p ON c.{fk_column} = p.id
        WHERE c.id = ?
        """,
        (child_id,),
    )
    row = cursor.fetchone()
    if not row:
        raise ResourceNotFoundError(f"Resource '{child_id}' not found.")
    if row[0] != user_id:
        raise AuthorizationError(
            f"Tenant isolation violation: user '{user_id}' requested access to "
            f"child resource '{child_id}' they do not own."
        )

    # Secure query: child bound to the authenticated owner through the join
    cursor.execute(
        f"""
        SELECT c.* FROM {child_type} c
        JOIN {parent_table} p ON c.{fk_column} = p.id
        WHERE c.id = ? AND p.user_id = ?
        """,
        (child_id, user_id),
    )
    return dict(cursor.fetchone())


# ---------------------------------------------------------------------------
# Policy-as-code plane (OPA / Rego style)
#
# secure_fetch above hard-codes the ownership rule in Python. That works for
# one rule, but production authorization accumulates conditions (admin roles,
# sharing grants, support-access windows) and hand-rolled conditionals drift
# apart across services. The production pattern is a policy engine (e.g. Open
# Policy Agent): the service builds a structured *input document* describing
# the request, the engine evaluates declarative policies against it, and the
# service enforces the returned decision. Policies become reviewable,
# testable data instead of scattered code.
# ---------------------------------------------------------------------------

DEFAULT_POLICIES = [
    {
        "id": "owner-full-access",
        "description": "A tenant may read, update, and delete resources they own.",
        "effect": "allow",
        "actions": ["read", "update", "delete"],
        "resource_types": sorted(VALID_RESOURCES),
        "condition": {"resource.user_id": "input.subject"},
    },
    {
        "id": "deny-cross-tenant-write",
        "description": "Explicitly deny any write to another tenant's resource.",
        "effect": "deny",
        "actions": ["update", "delete"],
        "resource_types": sorted(VALID_RESOURCES),
        "condition": {"resource.user_id": {"not_equals": "input.subject"}},
    },
]


class PolicyEngine:
    """Local mock of an OPA-style policy evaluation call.

    Evaluates structured JSON policies against an input document of the shape:

        {"subject": "usr_alice", "action": "read",
         "resource": {"type": "workouts", "id": "wkt_1", "user_id": "usr_alice"}}

    Semantics mirror Rego defaults: explicit deny overrides allow, and if no
    policy matches, the decision is DENY (default-deny, never default-allow).
    """

    def __init__(self, policies: list | None = None):
        self.policies = policies if policies is not None else DEFAULT_POLICIES

    @staticmethod
    def _resolve(reference: str, input_doc: dict):
        """Resolve a dotted reference like 'resource.user_id' against the input document."""
        node = {"input": {"subject": input_doc.get("subject")}, "resource": input_doc.get("resource", {})}
        for part in reference.split("."):
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    def _condition_holds(self, condition: dict, input_doc: dict) -> bool:
        for reference, expected in condition.items():
            actual = self._resolve(reference, input_doc)
            if isinstance(expected, dict) and "not_equals" in expected:
                other = self._resolve(expected["not_equals"], input_doc)
                if actual == other:
                    return False
            else:
                other = self._resolve(expected, input_doc) if isinstance(expected, str) and "." in expected else expected
                if actual != other:
                    return False
        return True

    def evaluate(self, input_doc: dict) -> dict:
        """Return a structured decision: {allow, policy_id, reason}."""
        action = input_doc.get("action")
        resource_type = input_doc.get("resource", {}).get("type")

        matched_allow = None
        for policy in self.policies:
            if action not in policy["actions"]:
                continue
            if resource_type not in policy["resource_types"]:
                continue
            if not self._condition_holds(policy.get("condition", {}), input_doc):
                continue
            if policy["effect"] == "deny":
                # Deny overrides: stop immediately, mirroring Rego/IAM semantics.
                return {
                    "allow": False,
                    "policy_id": policy["id"],
                    "reason": f"explicit deny by policy '{policy['id']}': {policy['description']}",
                }
            matched_allow = policy

        if matched_allow:
            return {
                "allow": True,
                "policy_id": matched_allow["id"],
                "reason": f"allowed by policy '{matched_allow['id']}': {matched_allow['description']}",
            }
        return {
            "allow": False,
            "policy_id": None,
            "reason": "default deny: no policy matched the request",
        }


def policy_fetch(
    conn: sqlite3.Connection,
    claims: dict,
    resource_type: str,
    resource_id: str,
    *,
    action: str = "read",
    engine: PolicyEngine | None = None,
) -> dict:
    """SECURE PATH (policy-as-code): fetch gated by a policy engine decision.

    Same guarantee as secure_fetch, but the authorization rule lives in
    declarative policy data evaluated by the engine, not in inline Python.
    Returns the resource with the structured decision attached for auditing.
    """
    _validate_resource_type(resource_type)
    user_id = claims.get("sub")
    if not user_id:
        raise AuthorizationError("Missing subject (user_id) in verified token.")

    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {resource_type} WHERE id = ?", (resource_id,))
    row = cursor.fetchone()
    if not row:
        raise ResourceNotFoundError(f"Resource '{resource_id}' not found.")

    resource = dict(row)
    input_doc = {
        "subject": user_id,
        "action": action,
        "resource": {"type": resource_type, **resource},
    }
    decision = (engine or PolicyEngine()).evaluate(input_doc)
    if not decision["allow"]:
        raise AuthorizationError(
            f"Policy engine denied '{action}' on '{resource_id}' for user '{user_id}': "
            f"{decision['reason']}"
        )
    return {"resource": resource, "decision": decision}


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
            f"resource '{resource_id}' they do not own."
        )

    # Enforce isolation at execution
    cursor.execute(
        f"DELETE FROM {resource_type} WHERE id = ? AND user_id = ?",
        (resource_id, user_id),
    )
    return True
