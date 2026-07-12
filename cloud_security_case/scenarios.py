"""Scenarios module orchestrating the security scenarios for the demo and tests.

Seeds an in-memory database and executes the security verification flows.
"""

import sqlite3
from datetime import datetime
from cloud_security_case import auth, authorization, containment, database, imports, audit, detection

# Instantiate singletons for the provider and detector
cognito = auth.CognitoProvider()
detector = detection.AnomalyDetector()


def seed_database(conn: sqlite3.Connection):
    """Seed test users and workouts."""
    # Seed Users
    conn.execute(
        "INSERT INTO users (id, email, created_at) VALUES (?, ?, ?)",
        ("usr_alice", "alice@gmail.com", datetime.now().isoformat()),
    )
    conn.execute(
        "INSERT INTO users (id, email, created_at) VALUES (?, ?, ?)",
        ("usr_bob", "bob@gmail.com", datetime.now().isoformat()),
    )

    # Seed Workouts
    conn.execute(
        """
        INSERT INTO workouts (id, user_id, name, occurred_at, created_at, source_name)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "wkt_alice_1",
            "usr_alice",
            "Heavy Squats",
            "2026-07-01",
            datetime.now().isoformat(),
            "manual",
        ),
    )
    conn.execute(
        """
        INSERT INTO workouts (id, user_id, name, occurred_at, created_at, source_name)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "wkt_bob_1",
            "usr_bob",
            "5k Tempo Run",
            "2026-07-02",
            datetime.now().isoformat(),
            "manual",
        ),
    )

    # Seed Workout Sets (child rows — ownership only derivable via the parent)
    conn.execute(
        """
        INSERT INTO workout_sets (id, workout_id, exercise_name, set_number, weight_kg, reps, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        ("wst_alice_1", "wkt_alice_1", "Back Squat", 1, 120.0, 5, datetime.now().isoformat()),
    )
    conn.execute(
        """
        INSERT INTO workout_sets (id, workout_id, exercise_name, set_number, weight_kg, reps, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        ("wst_bob_1", "wkt_bob_1", "Sled Push", 1, 90.0, 10, datetime.now().isoformat()),
    )


def execute_flow_1_legit_read(conn: sqlite3.Connection) -> dict:
    """Flow 1: Alice reads her own workout using a valid token."""
    # Mint token for Alice
    token = cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="fitness_api",
    )

    # Verify token (e.g. at API Gateway boundary)
    claims = cognito.verify_token(token, expected_audience="fitness_api")

    # Fetch workout securely
    workout = authorization.secure_fetch(conn, claims, "workouts", "wkt_alice_1")

    # Log audit event
    audit.secure_log(
        conn,
        event_type="DATA_ACCESS",
        actor_id=claims.get("email"),
        resource_id="wkt_alice_1",
        action="READ",
        decision="ALLOW",
        reason="Owner read workout",
        detail={"workout": workout},
    )

    return {"claims": claims, "workout": workout}


def execute_attack_1_bola(conn: sqlite3.Connection) -> dict:
    """Attack 1: Alice tries to access Bob's workout (wkt_bob_1)."""
    token = cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="fitness_api",
    )
    claims = cognito.verify_token(token, expected_audience="fitness_api")

    insecure_result = None
    secure_error = None

    # Insecure path: BOLA succeeds
    try:
        insecure_result = authorization.insecure_fetch(conn, "workouts", "wkt_bob_1")
        audit.insecure_log(
            conn,
            event_type="DATA_ACCESS",
            actor_id=claims.get("email"),
            resource_id="wkt_bob_1",
            action="READ",
            decision="ALLOW",
            reason="Unchecked query by ID",
            detail={"workout": insecure_result},
        )
    except Exception as e:
        insecure_result = f"Error: {e}"

    # Secure path: BOLA is blocked
    try:
        authorization.secure_fetch(conn, claims, "workouts", "wkt_bob_1")
    except authorization.AuthorizationError as e:
        secure_error = str(e)
        audit.secure_log(
            conn,
            event_type="DATA_ACCESS",
            actor_id=claims.get("email"),
            resource_id="wkt_bob_1",
            action="READ",
            decision="DENY",
            reason=secure_error,
            detail={"resource_type": "workouts"},
        )
        # Log to anomaly detector
        detector.log_event(claims["sub"], allowed=False)

    return {
        "claims": claims,
        "insecure_result": insecure_result,
        "secure_error": secure_error,
    }


def execute_attack_2_forged_token() -> str:
    """Attack 2: Attacker sends a token signed with a different key."""
    attacker_provider = auth.CognitoProvider()  # holds different RSA key pair
    forged_token = attacker_provider.mint_token(
        user_id="usr_attacker",
        email="attacker@evil.com",
        client_id="client_mobile_app",
        audience="fitness_api",
    )
    try:
        cognito.verify_token(forged_token, expected_audience="fitness_api")
        return "ALLOWED"
    except auth.AuthenticationError as e:
        return f"DENIED: {e}"


def execute_attack_3_wrong_audience() -> str:
    """Attack 3: A valid token intended for another audience is replayed."""
    wrong_aud_token = cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="some_other_api",
    )
    try:
        cognito.verify_token(wrong_aud_token, expected_audience="fitness_api")
        return "ALLOWED"
    except auth.AuthenticationError as e:
        return f"DENIED: {e}"


def execute_attack_4_expired_token() -> str:
    """Attack 4: Token is expired."""
    expired_token = cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="fitness_api",
        ttl_seconds=-10,  # expired 10s ago
    )
    try:
        cognito.verify_token(expired_token, expected_audience="fitness_api")
        return "ALLOWED"
    except auth.AuthenticationError as e:
        return f"DENIED: {e}"


def execute_flow_2_legit_import(conn: sqlite3.Connection) -> dict:
    """Flow 2: Legitimate wearable import succeeds."""
    payload = {
        "user_id": "usr_alice",
        "distance_m": 5000.0,
        "duration_seconds": 1200.0,
        "occurred_at": "2026-07-03",
        "source_provider": "apple_health",
        "external_workout_id": "uuid_apple_watch_run_999",
    }

    # Secure import within transactional boundary
    with database.transaction() as tx_conn:
        workout_id = imports.secure_import(tx_conn, payload)

    return {"workout_id": workout_id, "payload": payload}


def execute_attack_5_duplicate_import(conn: sqlite3.Connection) -> dict:
    """Attack 5: Duplicate import arrives twice."""
    payload = {
        "user_id": "usr_alice",
        "distance_m": 5000.0,
        "duration_seconds": 1200.0,
        "occurred_at": "2026-07-03",
        "source_provider": "apple_health",
        "external_workout_id": "uuid_apple_watch_run_999",
    }

    insecure_results = []
    secure_results = []

    # Seed first run
    try:
        with database.transaction() as tx_conn:
            imports.secure_import(tx_conn, payload)
    except Exception:
        pass  # already seeded

    # Second arrival - Insecure path crashes or duplicate database state if constraint bypassed.
    # In our database we have the unique constraint, so the insecure path (no try-except recovery)
    # throws a raw SQLite IntegrityError, crashing the API.
    try:
        # Insecure path tries to run check and insert
        imports.insecure_import(conn, payload)
        insecure_results.append("SUCCESS_MUTATED")
    except sqlite3.IntegrityError as e:
        insecure_results.append(f"CRASH_500: Raw DB Error ({e})")

    # Second arrival - Secure path recovers gracefully and returns the existing workout ID, maintaining idempotency (200 OK)
    try:
        with database.transaction() as tx_conn:
            imports.secure_import(tx_conn, payload)
    except imports.DuplicateImportError as e:
        secure_results.append(
            f"IDEMPOTENT_OK: Returns existing ID '{e.existing_id}' with clean recovery msg: {e}"
        )

    return {"insecure": insecure_results, "secure": secure_results}


def execute_attack_6_racing_imports(conn: sqlite3.Connection) -> dict:
    """Attack 6: Race condition simulation of background sync vs manual save.

    We simulate a race where two execution flows run concurrently.
    """
    payload = {
        "user_id": "usr_alice",
        "distance_m": 8000.0,
        "duration_seconds": 2100.0,
        "occurred_at": "2026-07-04",
        "source_provider": "fitbit",
        "external_workout_id": "uuid_fitbit_run_456",
    }

    # Simulate race: both threads check the database at the same time in insecure mode.
    # Because there is no transactional locks/isolation, both threads see 0 runs and proceed to write.
    # SQLite unique constraint will block the second insert, but the insecure path throws a 500.
    # Let's show how secure path recovers gracefully from concurrent attempts.
    results = []
    # Attempt 1 (Thread 1)
    with database.transaction() as tx_conn1:
        id1 = imports.secure_import(tx_conn1, payload)
        results.append(f"Flow A: Saved Run '{id1}'")

    # Attempt 2 (Thread 2 - Concurrent race)
    try:
        with database.transaction() as tx_conn2:
            imports.secure_import(tx_conn2, payload)
    except imports.DuplicateImportError as e:
        results.append(
            f"Flow B: Caught concurrent collision. Idempotently returned ID '{e.existing_id}'"
        )

    return {"results": results}


def execute_attack_7_validation_failure(conn: sqlite3.Connection) -> dict:
    """Attack 7: Validation failure occurs (negative distance).

    The transaction must roll back entirely, leaving zero records.
    """
    payload = {
        "user_id": "usr_alice",
        "distance_m": -1500.0,  # Invariant violation!
        "duration_seconds": 600.0,
        "occurred_at": "2026-07-05",
        "source_provider": "apple_health",
        "external_workout_id": "uuid_apple_watch_run_invalid",
    }

    try:
        with database.transaction() as tx_conn:
            imports.secure_import(tx_conn, payload)
    except Exception as e:
        error_msg = str(e)

    # Verify that nothing was persisted
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM runs WHERE external_workout_id = ?",
        ("uuid_apple_watch_run_invalid",),
    )
    count = cursor.fetchone()[0]

    return {"error": error_msg, "count": count}


def execute_attack_8_post_commit_failure(conn: sqlite3.Connection) -> dict:
    """Attack 8: Post-commit presentation failure occurs.

    Ensure DB remains committed, and application reports success but notes the presentation failure.
    """
    payload = {
        "user_id": "usr_alice",
        "distance_m": 4200.0,
        "duration_seconds": 1000.0,
        "occurred_at": "2026-07-06",
        "source_provider": "apple_health",
        "external_workout_id": "uuid_post_commit_789",
    }

    # Insecure implementation catches all errors together, reporting database save failure
    insecure_status = None
    try:
        # Insecure path inserts
        imports.insecure_import(conn, payload)
        # Post-commit presentation fails (e.g. UI throws render error)
        imports.run_post_commit_step(throw_error=True)
    except Exception:
        # DB actually committed the row! But caller gets reported failure.
        insecure_status = "Run could not be saved (500)"

    # Check database to see if it was persisted anyway in the insecure path
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM runs WHERE external_workout_id = ?",
        ("uuid_post_commit_789",),
    )
    insecure_db_count = cursor.fetchone()[0]

    # Secure path runs DB in transactional boundary, then handles post-commit errors separately
    # Delete the run from the insecure path to avoid unique constraint clash
    cursor.execute("DELETE FROM runs WHERE external_workout_id = ?", ("uuid_post_commit_789",))
    secure_status = None
    workout_id = None
    try:
        # 1. Transaction commits
        with database.transaction() as tx_conn:
            workout_id = imports.secure_import(tx_conn, payload)
        # 2. Downstream presentation runs outside transaction
        imports.run_post_commit_step(throw_error=True)
        secure_status = "SUCCESS"
    except RuntimeError as e:
        secure_status = f"PERSISTED_WITH_PRESENTATION_ERROR (workout_id={workout_id}): {e}"

    return {
        "insecure_status": insecure_status,
        "insecure_db_count": insecure_db_count,
        "secure_status": secure_status,
    }


def execute_attack_9_sensitive_logging(conn: sqlite3.Connection) -> dict:
    """Attack 9: Sensitive data in logs.

    Verify that tokens and PII (body metrics/emails) are redacted in secure logs.
    """
    token = cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="fitness_api",
    )

    detail = {
        "email": "alice@gmail.com",
        "token": token,
        "weight": 68.5,
        "device": "iPhone14,2",
    }

    # Log in insecure path
    audit.insecure_log(
        conn,
        event_type="USER_LOGIN",
        actor_id="alice@gmail.com",
        resource_id=None,
        action="LOGIN",
        decision="ALLOW",
        reason="Valid credentials",
        detail=detail,
    )

    # Log in secure path
    audit.secure_log(
        conn,
        event_type="USER_LOGIN",
        actor_id="alice@gmail.com",
        resource_id=None,
        action="LOGIN",
        decision="ALLOW",
        reason="Valid credentials",
        detail=detail,
    )

    # Fetch log entries
    cursor = conn.cursor()
    cursor.execute("SELECT detail, actor_id FROM audit_logs ORDER BY rowid DESC LIMIT 2")
    rows = cursor.fetchall()

    secure_row = dict(rows[0])
    insecure_row = dict(rows[1])

    return {"insecure": insecure_row, "secure": secure_row}


def execute_attack_10_bulk_exfiltration() -> list:
    """Attack 10: Bulk access anomaly detection.

    Trigger multiple successful requests to simulate exfiltration.
    """
    alerts = []
    # Alice requests her own data repeatedly in a tight loop
    for i in range(6):
        alert = detector.log_event("usr_alice", allowed=True)
        if alert:
            alerts.append(alert)

    return alerts


def execute_flow_3_workload_identity() -> dict:
    """Flow 3: Service-to-service calls verified via workload identity exchange.

    The import worker attests to the broker (STS AssumeRole / SPIFFE style),
    receives a short-lived scoped service token, and the internal API verifies
    provenance. Contrast paths: an unregistered workload, a scope-escalation
    attempt, and a stolen *user* token replayed on the service channel.
    """
    broker = auth.WorkloadIdentityBroker()
    broker.register_workload(
        "wearable-import-worker",
        attestation_secret="platform-attest-import-worker",
        scopes=["runs:write", "queue:consume"],
    )

    # Legit exchange and callee-side verification
    service_token = broker.exchange_token(
        "wearable-import-worker",
        "platform-attest-import-worker",
        audience="internal_runs_api",
        requested_scopes=["runs:write"],
    )
    claims = broker.verify_service_call(
        service_token, expected_audience="internal_runs_api", required_scope="runs:write"
    )
    legit = f"VERIFIED provenance: {claims['sub']} (scope: {claims['scope']})"

    # Attack A: unregistered workload requests a token
    try:
        broker.exchange_token(
            "rogue-cryptominer",
            "guessed-secret",
            audience="internal_runs_api",
            requested_scopes=["runs:write"],
        )
        unregistered = "ALLOWED"
    except auth.WorkloadIdentityError as e:
        unregistered = f"DENIED: {e}"

    # Attack B: registered workload tries to escalate beyond its granted scopes
    try:
        broker.exchange_token(
            "wearable-import-worker",
            "platform-attest-import-worker",
            audience="internal_runs_api",
            requested_scopes=["runs:write", "users:delete"],
        )
        escalation = "ALLOWED"
    except auth.WorkloadIdentityError as e:
        escalation = f"DENIED: {e}"

    # Attack C: a stolen mobile *user* token is replayed on the service channel
    user_token = cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="internal_runs_api",
    )
    try:
        broker.verify_service_call(
            user_token, expected_audience="internal_runs_api", required_scope="runs:write"
        )
        confused_deputy = "ALLOWED"
    except auth.WorkloadIdentityError as e:
        confused_deputy = f"DENIED: {e}"

    return {
        "legit": legit,
        "unregistered": unregistered,
        "escalation": escalation,
        "confused_deputy": confused_deputy,
    }


def execute_flow_4_policy_engine(conn: sqlite3.Connection) -> dict:
    """Flow 4: Authorization decided by an OPA-style policy engine.

    The service builds a structured input document and enforces the engine's
    decision instead of hand-rolled conditionals. Shows an owner allow, a
    cross-tenant default-deny, and the structured decision object for audit.
    """
    engine = authorization.PolicyEngine()

    # Owner read: allowed by the 'owner-full-access' policy
    claims_alice = {"sub": "usr_alice", "email": "alice@gmail.com"}
    allowed = authorization.policy_fetch(
        conn, claims_alice, "workouts", "wkt_alice_1", action="read", engine=engine
    )

    # Cross-tenant read: no policy matches -> Rego-style default deny
    try:
        authorization.policy_fetch(
            conn, claims_alice, "workouts", "wkt_bob_1", action="read", engine=engine
        )
        denied = "ALLOWED"
    except authorization.AuthorizationError as e:
        denied = f"DENIED: {e}"

    # Cross-tenant delete: matches the explicit 'deny-cross-tenant-write' policy
    try:
        authorization.policy_fetch(
            conn, claims_alice, "workouts", "wkt_bob_1", action="delete", engine=engine
        )
        denied_write = "ALLOWED"
    except authorization.AuthorizationError as e:
        denied_write = f"DENIED: {e}"

    return {
        "allowed_decision": allowed["decision"],
        "denied_read": denied,
        "denied_write": denied_write,
    }


def execute_attack_11_containment(conn: sqlite3.Connection) -> dict:
    """Attack 11: Automated incident response containment.

    The anomaly engine detects bulk exfiltration and fires a containment hook
    that revokes the user's active sessions AND tombstones the subject on the
    edge deny-list. The attacker's still-valid JWT is then rejected at both
    layers: the gateway verify step and the app-layer session gate.
    """
    # Wire a dedicated detector with the containment hook (EventBridge -> Lambda analogue)
    deny_list = auth.RevocationList()
    ir_detector = detection.AnomalyDetector(
        alert_hooks=[containment.build_containment_hook(conn, revocation_list=deny_list)]
    )

    # Alice's account is compromised; the attacker logs in and a session is recorded
    token = cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="fitness_api",
    )
    claims = cognito.verify_token(token, expected_audience="fitness_api", revocation_list=deny_list)
    containment.create_session(conn, user_id="usr_alice", token_jti=claims["jti"])

    # Before containment: the session gate passes
    containment.require_active_session(conn, claims)
    pre_status = "ALLOWED (token valid, session active)"

    # Attacker bulk-exports data; the 5th read in the window trips the alert
    alert = None
    for _ in range(6):
        result = ir_detector.log_event("usr_alice", allowed=True)
        if result:
            alert = result
            break  # containment fired; the session is already dead

    # After containment layer 1: the gateway deny-list rejects the token outright
    try:
        cognito.verify_token(token, expected_audience="fitness_api", revocation_list=deny_list)
        gateway_status = "ALLOWED"
    except auth.TokenRevokedError as e:
        gateway_status = f"DENIED: {e}"

    # After containment layer 2: even past the gateway, the session gate blocks
    try:
        containment.require_active_session(conn, claims)
        post_status = "ALLOWED"
    except containment.SessionRevokedError as e:
        post_status = f"DENIED: {e}"

    return {
        "pre_status": pre_status,
        "alert": alert,
        "gateway_status": gateway_status,
        "post_status": post_status,
    }


def execute_attack_12_nested_bola(conn: sqlite3.Connection) -> dict:
    """Attack 12: Nested BOLA — the parent is protected, the child is probed.

    Alice is blocked from /workouts/wkt_bob_1, so she requests the child
    directly: /sets/wst_bob_1. The child row has no user_id column; only a
    join to the parent's owner can authorize it.
    """
    token = cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="fitness_api",
    )
    claims = cognito.verify_token(token, expected_audience="fitness_api")

    # Vulnerable child endpoint: fetch by ID only — leaks Bob's set
    insecure_result = authorization.insecure_fetch_child(conn, "workout_sets", "wst_bob_1")

    # Hardened child endpoint: ownership derived through the parent join
    try:
        authorization.secure_fetch_child(conn, claims, "workout_sets", "wst_bob_1")
        secure_error = "ALLOWED"
    except authorization.AuthorizationError as e:
        secure_error = f"DENIED: {e}"

    # Owner path still works
    own_set = authorization.secure_fetch_child(conn, claims, "workout_sets", "wst_alice_1")

    return {
        "insecure_result": insecure_result,
        "secure_error": secure_error,
        "own_set": own_set,
    }
