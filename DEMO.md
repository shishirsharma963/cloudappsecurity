# Demo Walkthrough (`DEMO.md`)

This document details the scenarios executed by `demo.py`. For each scenario, we define the threat modeled, why it matters, the control that handles it, and the AWS production equivalent.

---

## Phase 1: Cryptographic User Identity & Token Security

### Flow 1: Legitimate User Reads Own Workout
*   **What Happens:** User `usr_alice` sends a request with a valid Cognito OIDC token to read her own workout `wkt_alice_1`.
*   **Expected Decision:** `ALLOWED`
*   **Threat Modeled:** Unauthorized endpoint access / Data loss.
*   **Why It Matters:** Legitimate clients must access their own data with minimal latency and high reliability.
*   **Local Control:** `auth.CognitoProvider` verifies signature, expiry, and audience. `authorization.secure_fetch` validates that `wkt_alice_1.user_id == usr_alice`.
*   **AWS Production Equivalent:** Amazon API Gateway validates Cognito JWT signature using JWKS (JSON Web Key Set). Lambda/ECS compute executes SQL with a tenant parameter.

---

### Attack 1: Broken Object-Level Authorization (BOLA / IDOR)
*   **What Happens:** Alice attempts to fetch Bob's workout `wkt_bob_1` by swapping the ID in the request parameters.
*   **Expected Decision:** `DENIED`
*   **Threat Modeled:** BOLA / IDOR (OWASP API Security Top 10 - API1:2023).
*   **Why It Matters:** Most data breaches occur not because attackers bypassed login prompts, but because they modified resource IDs in API queries to fetch other users' records.
*   **Local Control:** `authorization.secure_fetch` checks resource ownership before querying the database, raising `AuthorizationError` when a mismatch is detected.
*   **AWS Production Equivalent:** Application code on Lambda/ECS queries DynamoDB or RDS with user ID query conditions (`WHERE id = :id AND user_id = :authenticated_user_id`).

---

### Attack 2: Forged Token Signature
*   **What Happens:** Attacker generates a token using a self-signed RSA key pair and sends it to the API.
*   **Expected Decision:** `DENIED`
*   **Threat Modeled:** Token spoofing / Authentication bypass.
*   **Why It Matters:** Trust must be established cryptographically. If the verifier does not check signatures against the trusted identity provider's public keys, attackers can impersonate any user.
*   **Local Control:** `auth.CognitoProvider.verify_token` raises `AuthenticationError` because the signature does not match the provider's public key.
*   **AWS Production Equivalent:** API Gateway JWT Authorizer rejects the token at the edge before invoking the backend.

---

### Attack 3: Wrong Audience Token Replay
*   **What Happens:** Attacker intercepts a token minted for a different microservice and replays it against the fitness API.
*   **Expected Decision:** `DENIED`
*   **Threat Modeled:** Token replay / Auditing bypass.
*   **Why It Matters:** Tokens must be audience-scoped. A token for "Microservice A" must never grant access to "Microservice B" to prevent compromised components from executing actions elsewhere.
*   **Local Control:** JWT audience check (`aud`) fails verification, raising an audience exception.
*   **AWS Production Equivalent:** API Gateway checks the `aud` claim against the configured Client ID.

---

### Attack 4: Expired Token Replay
*   **What Happens:** Attacker replays a valid token that expired in the past.
*   **Expected Decision:** `DENIED`
*   **Threat Modeled:** Replay attack.
*   **Why It Matters:** Stolen bearer tokens are valid until they expire. A short TTL (Time to Live) limits the blast radius of token theft.
*   **Local Control:** JWT expiry check (`exp`) fails verification, raising an expired signature exception.
*   **AWS Production Equivalent:** API Gateway automatically discards expired tokens based on clock time.

---

## Phase 2: Wearable Ingestion & Transaction Integrity

### Flow 2: Legitimate Wearable Ingestion
*   **What Happens:** A wearable run import is submitted containing valid distance, duration, and external UUID.
*   **Expected Decision:** `PERSISTED`
*   **Threat Modeled:** Data loss / Out-of-sync state.
*   **Why It Matters:** Health integration imports must be recorded accurately.
*   **Local Control:** `imports.validate_import_payload` verifies parameters. The database commits the new record.
*   **AWS Production Equivalent:** API Gateway routes to SQS, processed by an import worker writing to RDS PostgreSQL.

---

### Attack 5: Duplicate Ingestion Replay (Idempotency Guard)
*   **What Happens:** The client sends the same wearable run UUID twice due to a network timeout retry.
*   **Expected Decision:** `IDEMPOTENT_OK` (recovers the existing record ID, prevents duplicates).
*   **Threat Modeled:** Replayed imports / Double-crediting workouts.
*   **Why It Matters:** Network failures cause retries. Without idempotency, duplicate runs appear, distorting progress analytics.
*   **Local Control:** The database enforces a `UNIQUE(user_id, source_provider, external_workout_id)` constraint. `imports.secure_import` catches the `IntegrityError` and returns the existing workout ID.
*   **AWS Production Equivalent:** PostgreSQL unique constraint + transaction + Lambda catching duplicate errors and returning `200 OK` with the existing ID.

---

### Attack 6: Background Sync vs Manual Save (Race Condition)
*   **What Happens:** Two threads attempt to import the same external workout concurrently.
*   **Expected Decision:** `DEDUPED` (one thread inserts, the second catches collision and returns existing ID).
*   **Threat Modeled:** Race condition / State corruption.
*   **Why It Matters:** Concurrent background sync and manual saving can race. Relying only on application-level "select-before-insert" checks results in race conditions. Database-level constraints are mandatory.
*   **Local Control:** SQLite unique constraint forces one to fail. The failing thread catches the conflict and recovers.
*   **AWS Production Equivalent:** RDS PostgreSQL transaction isolation (`READ COMMITTED` or `SERIALIZABLE`) and unique indexes.

---

### Attack 7: Validation Failure Rollback
*   **What Happens:** An import containing a negative distance is sent.
*   **Expected Decision:** `ROLLED_BACK` (zero records persisted).
*   **Threat Modeled:** Corrupted database state / Integrity loss.
*   **Why It Matters:** Invariants must be enforced. If multiple writes are executed in sequence and one fails validation, previous writes must roll back to avoid partial state.
*   **Local Control:** `imports.validate_import_payload` raises `ValidationError`. The transaction block (`with database.transaction()`) catches the error and executes `conn.rollback()`.
*   **AWS Production Equivalent:** ACID transactions in RDS PostgreSQL.

---

### Attack 8: Post-Commit Presentation Failure Ambiguity
*   **What Happens:** The database commit succeeds, but a downstream UI update throws an error.
*   **Expected Decision:** `PERSISTED_WITH_PRESENTATION_ERROR`
*   **Threat Modeled:** API error taxonomy distortion / Unnecessary retries.
*   **Why It Matters:** If the API returns a `500 Server Error` on a presentation failure, the mobile client believes the save failed and retries, creating duplicate data. 
*   **Local Control:** Separate scopes. The transaction block closes and commits first. The presentation logic runs *after* commit in a separate `try-except` block, ensuring correct error reporting.
*   **AWS Production Equivalent:** Separate database persistence from downstream notifications (like SNS/SQS push notifications).

---

## Phase 3: Auditing & Behavioral Detection

### Attack 9: Sensitive Data Leak in Logs
*   **What Happens:** A user login event occurs. The system logs details of the request containing email addresses and JWT tokens.
*   **Expected Decision:** `REDACTED`
*   **Threat Modeled:** Log injection / Credential leakage (OWASP Top 10 - Cryptographic Failures).
*   **Why It Matters:** Developers and support engineers inspect logs. If logs contain plain tokens or PII, a log compromise translates directly to account takeover or compliance breaches.
*   **Local Control:** `audit.secure_log` recursively scrubs dictionaries and redacts JWT signatures and email formats.
*   **AWS Production Equivalent:** AWS CloudWatch log scrubbing rules / KMS-encrypted CloudWatch log groups.

---

### Attack 10: Bulk Authenticated Data Exfiltration
*   **What Happens:** An authenticated user rapidly requests multiple resources in a tight window.
*   **Expected Decision:** `ALERTVOLUME` (anomaly alarm triggered).
*   **Threat Modeled:** Bulk data exfiltration / Account scraping.
*   **Why It Matters:** Even if authorization succeeds, bulk scanning represents abnormal behavior (e.g. scraper script or compromised token).
*   **Local Control:** `detection.AnomalyDetector` tracks access rates in-memory and triggers a `BULK_EXFILTRATION_WARNING` alert.
*   **AWS Production Equivalent:** Application sends telemetry events to CloudWatch. CloudWatch Metric Filters trigger EventBridge alerts to disable the Cognito user session.

---

## Representative Terminal Output

Running `python3 demo.py` produces the following output:

```
======================================================================
  Cloud Application Security Demo: Multi-Tenant Mobile Backend on AWS
  Case Study Vehicle: Synthetic Fitness Log Application
======================================================================

======================================================================
PHASE 1: CRYPTOGRAPHIC USER IDENTITY & TOKEN SECURITY
======================================================================

----------------------------------------------------------------------
FLOW 1 — Legitimate user reads own workout
----------------------------------------------------------------------
  Authenticated Subject   : usr_alice (alice@gmail.com)
  Requested Resource ID   : wkt_alice_1
  Workout Details         : Heavy Squats on 2026-07-01
  Ownership Authorization : AUTHORIZED (User owns resource)
  HARDENED   (GOOD) | Access Decision         : ALLOWED

----------------------------------------------------------------------
ATTACK 1 — Broken Object-Level Authorization (BOLA / IDOR)
----------------------------------------------------------------------
  Alice attempts to read Bob's workout (wkt_bob_1) by changing the resource ID in the URL.
  VULNERABLE (BAD)  | Insecure Query Result   : Leaked workout: {'id': 'wkt_bob_1', 'user_id': 'usr_bob', 'name': '5k Tempo Run', ...}
  HARDENED   (GOOD) | Secure Query Result     : Blocked with message: Tenant isolation violation: user 'usr_alice' requested access to resource 'wkt_bob_1' owned by user 'usr_bob'.

----------------------------------------------------------------------
ATTACK 2 — Forged Token Signature
----------------------------------------------------------------------
  Attacker creates a JWT using their own RSA key pair and claims it came from Cognito.
  HARDENED   (GOOD) | Verification Result     : DENIED: invalid token signature: Signature verification failed

----------------------------------------------------------------------
ATTACK 3 — Wrong Audience Token Replay
----------------------------------------------------------------------
  Attacker attempts to replay a token minted for a different microservice API.
  HARDENED   (GOOD) | Verification Result     : DENIED: wrong audience: token not minted for 'fitness_api'

----------------------------------------------------------------------
ATTACK 4 — Expired Token Replay
----------------------------------------------------------------------
  Attacker replays a previously captured expired OIDC token.
  HARDENED   (GOOD) | Verification Result     : DENIED: token expired

======================================================================
PHASE 2: WEARABLE DATA INGESTION & TRANSACTION INTEGRITY
======================================================================

----------------------------------------------------------------------
FLOW 2 — Legitimate Wearable Workout Ingestion
----------------------------------------------------------------------
  Synchronizing run from Apple Health/Apple Watch.
  Source Provider         : apple_health
  External UUID           : uuid_apple_watch_run_999
  HARDENED   (GOOD) | Ingestion Outcome       : PERSISTED with ID '0cd295ff-c221-4570-be78-d68d35d3cd5c'

----------------------------------------------------------------------
ATTACK 5 — Duplicate Ingestion Replay (Idempotency Guard)
----------------------------------------------------------------------
  Network timeout causes client to resend same wearable run UUID.
  VULNERABLE (BAD)  | Insecure Ingest Response: SUCCESS_MUTATED
  HARDENED   (GOOD) | Secure Ingest Response  : IDEMPOTENT_OK: Returns existing ID '0cd295ff-c221-4570-be78-d68d35d3cd5c' with clean recovery msg: Idempotency Guard: workout 'uuid_apple_watch_run_999' already imported.

----------------------------------------------------------------------
ATTACK 6 — Background Sync vs Manual Save (Race Condition)
----------------------------------------------------------------------
  Simulated race: concurrent threads execute writes for the same run.
  HARDENED   (GOOD) | Execution thread log    : Flow A: Saved Run '7eed73bf-9f15-470c-b7b5-d48ebb276e66'
  HARDENED   (GOOD) | Execution thread log    : Flow B: Caught concurrent collision. Idempotently returned ID '7eed73bf-9f15-470c-b7b5-d48ebb276e66'

----------------------------------------------------------------------
ATTACK 7 — Invariant Validation Failure Rollback
----------------------------------------------------------------------
  Payload contains validation error (negative distance value).
  Validation Exception    : distance_m cannot be negative.
  HARDENED   (GOOD) | DB Persisted Count      : Saved records = 0 (Rollback successful)

----------------------------------------------------------------------
ATTACK 8 — Post-Commit Presentation Failure Ambiguity
----------------------------------------------------------------------
  Database write succeeds, but a downstream UI update throws an error.
  VULNERABLE (BAD)  | Insecure App Report     : Run could not be saved (500) (DB Count: 1)
  HARDENED   (GOOD) | Secure App Report       : PERSISTED_WITH_PRESENTATION_ERROR (workout_id=19f7fba4-0300-40dc-9c96-ff0b8ec89826): UI navigation render failure (post-commit).

======================================================================
PHASE 3: STRUCTURED AUDITING & BEHAVIORAL DETECTION
======================================================================

----------------------------------------------------------------------
ATTACK 9 — Sensitive Data Leak in Logs
----------------------------------------------------------------------
  Application logs user login event containing emails and credentials.
  VULNERABLE (BAD)  | Insecure Log Entry      : {"email": "alice@gmail.com", "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
  HARDENED   (GOOD) | Secure Log Entry        : {"email": "[REDACTED_SENSITIVE_DATA]", "token": "[REDACTED_SENSITIVE_DATA]", "weight": "[REDACTED_SENSITIVE_DATA]", "device": "iPhone14,2"}

----------------------------------------------------------------------
ATTACK 10 — Bulk Authenticated Data Exfiltration
----------------------------------------------------------------------
  Alice rapidly requests multiple workouts within a short time window.
  HARDENED   (GOOD) | Anomaly Engine Alert    : [BULK_EXFILTRATION_WARNING] Severity: CRITICAL -> Enforce captcha or revoke OIDC/Cognito session
  HARDENED   (GOOD) | Anomaly Engine Alert    : [BULK_EXFILTRATION_WARNING] Severity: CRITICAL -> Enforce captcha or revoke OIDC/Cognito session
======================================================================
  Demo Complete.
======================================================================
```
