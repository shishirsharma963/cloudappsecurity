# Security Control Matrix (`CONTROLS.md`)

This control matrix maps the core application and architectural risks to specific security controls, their type, prototype implementation, AWS production service mapping, verification evidence, and residual risk.

---

## Control Mapping Matrix

| Risk / Threat | Control Name | Type | Local Prototype Mechanism | AWS Production Service | Verification Evidence | Automated Test | Residual Risk | NIST CSF 2.0 / SOC 2 |
|---|---|---|---|---|---|---|---|---|
| **Forged Tokens / Impersonation** | Asymmetric JWT Validation | Prevent | `auth.CognitoProvider.verify_token` checks RS256 signature. | Amazon API Gateway JWT Authorizer | API Gateway configuration log | `test_forged_signature_raises_error` | Vulnerabilities in Cognito or key management systems. | PR.AT-01 / CC6.1 |
| **Expired Token Replays** | Token TTL Enforcement | Prevent | JWT verifier asserts `exp` claim. | API Gateway Token validation | Request audit logs (status 401) | `test_expired_token_raises_error` | Token intercepted and replayed within the valid TTL window. | PR.DS-02 / CC6.3 |
| **Wrong Audience Token Replay** | Audience Claim Restriction | Prevent | JWT verifier asserts `aud` matches API identifier. | API Gateway + Cognito Config | API Gateway config audit | `test_wrong_audience_raises_error` | Attacker intercepts a token for a related service that shares audience definitions. | PR.DS-02 / CC6.3 |
| **BOLA / IDOR Data Leak** | Tenant Isolated Queries | Prevent | `authorization.secure_fetch` queries resource ID AND subject sub. | ECS/Lambda query parameter binding | Database query logs / trace metrics | `test_secure_fetch_enforces_boundary` | Direct SQL execution or developer failing to apply query bindings in new endpoints. | PR.AC-03 / CC6.3 |
| **Duplicate Sync Records** | Idempotency Constraints | Prevent | SQLite unique constraint on source and external UUID. | RDS PostgreSQL Unique Constraints + transaction | Database schema description | `test_import_is_idempotent` | Client changes UUID on retry, bypassing unique check. | PR.DS-01 / CC6.8 |
| **Import Race Conditions** | Transaction Isolation | Prevent | Database writes wrapped in transactional commit blocks. | RDS Postgres isolation level (Read Committed) | Transaction log commits | `test_transaction_rollback_on_failure` | Thread lock timeouts leading to transaction failures and client errors. | PR.DS-01 / CC6.8 |
| **Partial State Corruption** | Atomic Database Rollbacks | Prevent | Transaction blocks execution rollback on validation check error. | Aurora Postgres engine rollbacks | Application error logs showing ROLLED_BACK | `test_transaction_rollback_on_failure` | System crash during rollback execution before disk flush. | PR.DS-01 / CC6.8 |
| **Distorted Saving Status** | Commit/Presentation Split | Prevent | Separates db transaction commits from presentation error scopes. | Explicit controller code flow separation | Verification logs | `test_post_commit_presentation_failure_handling` | Complex multi-stage external integrations that fail post-commit. | PR.DS-01 / CC6.8 |
| **Sensitive Data in Telemetry** | Recursive Log Redaction | Prevent | `audit.redact_structure` scrubs keys like email, token, weight. | CloudWatch Logs subscription filter + KMS | JSON structured logs in database | `test_audit_log_pii_redaction` | Custom keys introduced by developers not added to redactor lists. | PR.DS-01 / CC6.1 |
| **IDOR / BOLA Enumeration Scan** | Auth Failure Monitoring | Detect | `detection.AnomalyDetector` tracks sequential denials. | CloudWatch Metric Filters + Alarm | JSON anomaly alert events | `test_bola_scan_detection` | Low-and-slow scans designed to bypass rate-based thresholds. | DE.AE-02 / CC7.2 |
| **Bulk Data Exfiltration** | Access Velocity Alerting | Detect | `detection.AnomalyDetector` tracks successful read volumes. | CloudWatch Metrics + EventBridge Alarm | Anomaly alert generated | `test_bulk_exfiltration_detection` | Malicious user spreading downloads across multiple days or IP locations. | DE.AE-02 / CC7.2 |
| **AWS Account/Network Access** | Least-Privilege Compute Roles | Prevent | Illustrated via `security.tf` import worker execution role. | IAM Workload Identity roles | IAM Access Analyzer report | Verified in Terraform | Hardcoded credentials or IAM policy modifications by overprivileged administrators. | PR.AC-04 / CC6.3 |
