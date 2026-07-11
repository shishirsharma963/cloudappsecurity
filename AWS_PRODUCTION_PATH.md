# Transition Path to AWS Production (`AWS_PRODUCTION_PATH.md`)

This document bridges the local prototype mechanisms to their AWS-native equivalents, defining the migration patterns and integration interfaces.

---

## Service Migration Mapping

| Local Component | Local Mechanism | AWS Production Service | Production Integration Pattern |
|---|---|---|---|
| **Identity Provider** | `auth.CognitoProvider` mints RS256 JWTs using in-process RSA. | **Amazon Cognito User Pools** | Client authenticates via Cognito SDK (OAuth 2.0 PKCE flow) and receives OIDC ID/Access Tokens. |
| **Authentication Edge** | JWT signature, audience, and expiry validated in `CognitoProvider`. | **Amazon API Gateway** (v2 HTTP API) | API Gateway configured with a JWT Authorizer pointing to the Cognito User Pool issuer URL. Signature validated against Cognito JWKS (`/.well-known/jwks.json`). |
| **Edge Protection** | Simulated rate limits and signature validations. | **AWS WAF v2** | Regional WAF associated with API Gateway stage. Rules: rate-limiting (aggregate key = IP), AWS Core Managed Rule Set. |
| **Database Plane** | In-memory SQLite with constraints and transactions. | **Amazon Aurora PostgreSQL** (Serverless v2) | Database instances hosted in isolated private subnets. Master credentials managed via **AWS Secrets Manager** with automatic rotation. |
| **Asynchronous Ingestion** | Local thread processing and SQLite checks. | **Amazon SQS + Lambda / ECS** | Ingest API writes raw payloads to SQS. SQS triggers Lambda Worker. Poison messages route to SQS Dead-Letter Queue (DLQ). |
| **Encryption at Rest** | SQLite unencrypted storage in memory/disk. | **AWS Key Management Service (KMS)** | Aurora storage encrypted with Customer Managed Key. S3 buckets encrypted using S3 Bucket Keys with KMS SSE. |
| **Telemetry & Log Scrubbing** | `audit.secure_log` recursively scrubs PII and writes JSON to database. | **Amazon CloudWatch Logs** | App compute writes JSON to stdout/stderr. CloudWatch log group associated with KMS key. Subscription filter triggers Lambda for real-time log scanning/masking. |
| **Behavioral Detection** | `detection.AnomalyDetector` tracks rates in memory. | **Amazon CloudWatch + EventBridge** | App pushes metric filters (e.g. `DenialCount`). CloudWatch Alarm triggers EventBridge rule, running Lambda to block the Cognito user. |
| **Workload Security** | Simulated in code. | **AWS IAM (Identity &amp; Access Management)** | ECS Task or Lambda Execution Roles configured with least-privilege resource policies, verified by IAM Access Analyzer. |

---

## Step-by-Step Transition Guide

### 1. Migrating Customer Identity (Cognito Setup)
*   **Local:** We generate a transient key pair in-memory.
*   **Production:** Deploy `infra/terraform/identity.tf`. Configure the client application using OAuth 2.0 PKCE. Point the client app to the Cognito user pool domain.

### 2. Establishing the Database Network Boundary
*   **Local:** SQLite connects to a local file or in-memory instance.
*   **Production:** Deploy `infra/terraform/database.tf`.
    1.  Create a VPC with private subnets across multiple Availability Zones.
    2.  Provision an Aurora Serverless v2 PostgreSQL cluster. Disable public accessibility (`publicly_accessible = false`).
    3.  Create a database security group allowing ingress on port 5432 *only* from the security group of the API compute tasks.

### 3. Implementing Tenant-Bound ORM Scope
*   **Local:** Explicitly querying `id` and `user_id` in `authorization.py`.
*   **Production:** When writing backend service code (e.g., Node.js/Sequelize, Python/SQLAlchemy, Go/GORM), implement a global query middleware or scope that automatically binds the tenant query filter:
    ```python
    # Example SQLAlchemy query filter injection
    db.query(Workout).filter(
        Workout.id == workout_id,
        Workout.user_id == current_user_id
    ).first()
    ```
    This mirrors the local prototype's secure query structure.

### 4. Asynchronous Ingestion & Idempotency
*   **Local:** SQLite constraint prevents duplicate rows; application catches error and returns existing ID.
*   **Production:** SQS queue receives Apple Health sync payload. Lambda processes SQS messages. The target table in Aurora has a `UNIQUE(user_id, source_provider, external_workout_id)` constraint. 
    1.  If SQS retries a message, Aurora unique constraint fails.
    2.  Lambda catches PostgreSQL `unique_violation` exception (Error Code `23505`), queries the database for the existing ID, and returns a successful response code.
    3.  Message is marked complete and removed from SQS, preventing infinite retry loops.

### 5. Audit Logging to CloudWatch
*   **Local:** Structured JSON logs are saved to the SQLite `audit_logs` table.
*   **Production:** Log events are structured as JSON and written to standard output. AWS CloudWatch Agent captures stdout and forwards it to a CloudWatch Log Group. CloudWatch Metrics scan for `Anomaly` patterns and alert security operations.
