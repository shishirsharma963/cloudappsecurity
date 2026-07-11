# System Architecture (`ARCHITECTURE.md`)

This document outlines the architectural boundaries, module structures, and request lifecycles for the multi-tenant fitness application.

---

## 1. System Components & Module Ownership

The application logic is partitioned into dedicated modules, each managing a specific security boundary:

```
                  ┌────────────────────────────────────────┐
                  │              iOS Client                │
                  └───────────────────┬────────────────────┘
                                      │ OAuth JWT (PKCE)
                                      v
                  ┌────────────────────────────────────────┐
                  │              API Gateway               │
                  │        (Asymmetric AuthN Gate)         │
                  └───────────────────┬────────────────────┘
                                      │ Verified Claims
                                      v
                  ┌────────────────────────────────────────┐
                  │              App Services              │
                  │    (Tenant AuthZ & validation gate)    │
                  └───────────────────┬────────────────────┘
                                      │ SQL Queries
                                      v
                  ┌────────────────────────────────────────┐
                  │            Database (RDS)              │
                  │      (Constraints & Transactions)      │
                  └────────────────────────────────────────┘
```

*   **`auth.py` (Identity Gate):** Represents the Cognito Authentication Provider. Generates asymmetric RSA keys, mints signed RS256 JWT tokens, and validates incoming tokens.
*   **`authorization.py` (Authorization Gate):** Enforces object-level tenant boundaries. Resolves ownership checks by ensuring every fetch or write query is bound to the authenticated subject ID (`sub`).
*   **`imports.py` (Data Pipeline Gate):** Manages wearable ingestion logic, enforces schema validation, handles unique constraint conflicts (for idempotency), and separates transaction commits from presentation renders.
*   **`database.py` (Persistence Gate):** Seeds tables, configures SQLite WAL (Write-Ahead Logging) mode, and exposes transaction helpers.
*   **`audit.py` (Telemetry Gate):** Formats structured logs and recursively redacts PII and token variables before persistence.
*   **`detection.py` (Behavioral Gate):** Monitors traffic anomalies (such as repeated access denials or bulk reads) to detect scrapers or BOLA scans.

---

## 2. Trust Boundaries

Three distinct trust boundaries separate components:

1.  **Hostile Client Boundary:** The iOS client is treated as completely untrusted. All parameters, claims, and data objects sent from the mobile application must undergo validation on the cloud backend.
2.  **API Gateway Boundary:** The API Gateway acts as the outer authentication gate. It decrypts and verifies the asymmetric JWT signature, audience, and expiry before the request is allowed to call internal services.
3.  **Application Tenant Boundary:** Internal application compute is responsible for tenant resource validation. Every query must bind both the resource ID and the user's OIDC ID. The database layer reinforces this boundary using unique indexes and transaction rollbacks.

---

## 3. Data Integrity & State Invariants

### State Ownership
*   **The Database is the Source of Truth:** No client-side state is trusted. The database defines the active state of users, workouts, runs, metrics, and goals.
*   **Uniqueness Invariant:** A wearable sync payload must map to exactly one database row. The database enforces `UNIQUE(user_id, source_provider, external_workout_id)`.
*   **Tenant Separation Invariant:** User A must never access User B's resources. Checked at the service query builder layer.

### Verification of Correctness
*   Correctness is asserted via a modular test suite (`tests/`) verifying that:
    1.  BOLA queries raise authorization exceptions.
    2.  Duplicate inputs result in a single logical database entry.
    3.  Validation failures trigger total rollback of active transactions.
    4.  Auditing strips out JWT tokens.

---

## 4. Ingestion Lifecycle & Race Handlers

The wearable sync pipeline follows a strict state transition flow to prevent races:

```
[ Sync Request ] ──> [ RECEIVED ] ──> [ VALIDATED ] ──> [ NORMALIZED ] ──> [ DEDUPED ] ──> [ PERSISTED ]
```

1.  **RECEIVED:** Ingests raw JSON payload.
2.  **VALIDATED:** Confirms numeric types and boundaries (e.g. positive distance, distance under 100km).
3.  **NORMALIZED:** Standardizes fields to consistent database entities.
4.  **DEDUPED:** Resolves duplicate records. If the unique index matches a row already in the database, the transaction aborts with a uniqueness conflict. The application catches this conflict, rolls back the sub-transaction, and returns the ID of the existing record to the caller. This keeps the API idempotent and prevents duplicate workout records.
5.  **PERSISTED:** DB transaction commits.

---

## 5. Audit & Telemetry Architecture

Every security action emits structured logs to a designated telemetry pipeline:

```
[ App Action ] ──> [ Scrubber (PII Redactor) ] ──> [ Structured JSON Event ] ──> [ CloudWatch / Audit DB ]
```

*   **Log Scrubbing:** The logging utility parses all detail dictionaries and redacts values matching email addresses, weight/waist metrics, or JWT signatures, mapping them to `[REDACTED_SENSITIVE_DATA]`.
*   **Telemetry Structure:** Logs include:
    *   `timestamp`: ISO UTC time.
    *   `event_type`: Category of action.
    *   `actor_id`: Masked/redacted identifier of the caller.
    *   `action`: HTTP/SQL method.
    *   `decision`: `ALLOW` or `DENY`.
    *   `reason`: Clear reason for the decision (e.g. `Owner read workout` or `Tenant isolation violation`).
