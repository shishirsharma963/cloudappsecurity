# Threat Model (`THREAT_MODEL.md`)

This threat model outlines the primary assets, threat actors, and attack vectors for the multi-tenant fitness application, mapped according to the **STRIDE** methodology.

---

## 1. Asset Inventory & Classification

We classify data based on sensitivity and business risk:

| Asset | Description | Sensitivity | Risk of Exposure |
|---|---|---|---|
| **Access Tokens** | OIDC/Cognito bearer tokens. | **CRITICAL (Secret)** | Complete account takeover. |
| **Email Address** | User login identity. | **HIGH (PII)** | Targeted phishing, identity leak. |
| **Body Weight / Waist** | Personal body metrics. | **HIGH (PII)** | User embarrassment, health compliance breach. |
| **Workout History** | Exercises, sets, reps. | **MEDIUM (Private)** | User privacy violation. |
| **Race Goals** | Distances and target times. | **MEDIUM (Private)** | User privacy violation. |
| **Audit Logs** | Security trails. | **HIGH (Compliance)** | Security posture exposure, tampering. |

---

## 2. Threat Actors & Agent Vectors

*   **External Unauthenticated Attacker:** Tries to bypass login gates, spoof JWT tokens, or replay old credentials.
*   **Malicious Authenticated User:** Attempts to access or modify other users' workouts, weight metrics, or race goals by changing resource IDs (BOLA/IDOR).
*   **Compromised Client Device:** Attacker gains access to a user's mobile device, looking to extract stored tokens or spoof Apple Health sync records.
*   **Insider Threat / Overprivileged Workload:** Compromised application server or administrator attempting to download databases or intercept telemetry streams.

---

## 3. STRIDE Threat Mapping

The following matrix maps threat descriptions to application-level controls, test cases, and AWS production mitigations:

| STRIDE | Threat Description | Local App Control | Automated Test | AWS Production Control |
|---|---|---|---|---|
| **Spoofing** | Attacker signs their own tokens to gain user privileges. | `auth.CognitoProvider` validates JWT signatures. | `test_forged_signature_raises_error` | Cognito User Pools + API Gateway JWT Validation (JWKS verification). |
| **Tampering** | User modifies request parameters to view other tenants' data. | `authorization.secure_fetch` binds queries to user IDs. | `test_secure_fetch_enforces_boundary` | DynamoDB/RDS PostgreSQL queries structured with user parameter filters. |
| **Repudiation** | Malicious actor denies performing an action due to lack of trail. | `audit.secure_log` writes structured logs containing actor and action. | `test_audit_logs_record_metadata` | CloudTrail enabled (log validation active) + CloudWatch logs. |
| **Info Leak** | Telemetry logs contain plaintext email addresses or JWTs. | `audit.redact_structure` strips email and token formats. | `test_audit_log_pii_redaction` | CloudWatch log groups encrypted using KMS keys with automatic scrubbing. |
| **Info Leak** | Bob's workouts are exposed to Alice via BOLA. | `authorization.secure_fetch` raises `AuthorizationError`. | `test_insecure_fetch_leaks_workout` | Private RDS subnet isolation + user-bound API queries. |
| **Denial of Svc** | Duplicate sync storms overwhelm db connection pools. | `imports.secure_import` catches DB errors for clean idempotency. | `test_import_is_idempotent` | SQS queue buffers import jobs, Lambda limits concurrency. |
| **Elevation of Priv** | Attacker accesses administrative db queries. | Enforced type validation at gate (`insecure_fetch` restricted). | `test_invalid_type_denied` | Least-privilege IAM policies, separate IAM workload roles. |

---

## 4. Attack Surfaces & Boundaries

```
[ Hostile Client Device ]
        │  (Attack Surface: Stolen Tokens, Mock GPS, Replayed Apple Health payload)
        ▼
   [ WAF / Edge ]
        │  (Attack Surface: DDoS, SQL Injection scans, Rate limit bypass)
        ▼
 [ API Gateway / Auth ]
        │  (Attack Surface: Expired token replays, signature forgery)
        ▼
[ Application Compute ]
        │  (Attack Surface: IDOR/BOLA scans, race conditions, parameter injection)
        ▼
   [ Database (RDS) ]
```

### Mitigation Priority Focus
1.  **BOLA / IDOR Verification:** We treat this as the P0 invariant. Edge controls (like WAF) cannot determine database row ownership; authorization must be verified inside the compute layer.
2.  **Idempotency & Rollbacks:** Asynchronous pipelines require database-level constraints. A failure must roll back the transaction completely, and retries must gracefully resolve to the existing ID to prevent double-crediting.
3.  **Credential Scarcity in Logs:** Redacting logs at the application source guarantees that credentials never touch log processors or indices.
