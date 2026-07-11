# Architecture Decisions Log (`DECISIONS.md`)

This log documents the key architectural choices, rejected alternatives, and security trade-offs made during the design of the multi-tenant cloud backend.

---

## ADR 1: Relational Database (RDS PostgreSQL) vs. Key-Value NoSQL (DynamoDB)

*   **Decision:** Select relational database modeling (Amazon RDS or Aurora PostgreSQL) rather than DynamoDB.
*   **Context:** The fitness domain contains highly relational objects: Users have Workouts, Workouts have Exercise Sets, Users have Runs, and Users have Body Metrics. Queries frequently require aggregations, range queries (e.g. progressive overload charts), and multi-table integrity.
*   **Why Not DynamoDB:** While DynamoDB scales horizontally, it requires defining access patterns upfront (Single-Table Design). Complex relational queries, join aggregations, and changing query patterns for analytics (e.g. progressive overload over arbitrary exercises) create significant index bloat and expensive scan operations in DynamoDB.
*   **Trade-off:** Relational databases require managing connection pools (e.g., RDS Proxy) and scaling database instances vertically or via read replicas, whereas DynamoDB scales transparently. We accept this scaling management cost to ensure clean relational integrity and rich query capability.

---

## ADR 2: Asymmetric Token Verification (RS256) vs. Symmetric Verification (HS256)

*   **Decision:** Use asymmetric RS256 JWT tokens (simulating Cognito) rather than symmetric HS256.
*   **Context:** The identity issuer (Cognito) must sign tokens with a private key, and verifying endpoints (API Gateway, application services) must validate tokens using only the public key.
*   **Why Not HS256:** HS256 relies on a shared secret. If a shared secret is compromised on any verifying microservice, the attacker can use it to mint valid tokens for any user. Under RS256, verifying endpoints hold only the public key; key compromise on a service does not grant token-minting privileges.
*   **Trade-off:** Asymmetric signature verification requires slightly higher CPU overhead than symmetric hashing. We accept this minor latency cost (sub-millisecond) for superior security boundary isolation.

---

## ADR 3: Tenant-Bound Database Queries vs. Application-Level Resource Verification

*   **Decision:** Bind database queries to both resource ID and authenticated user ID (`SELECT * FROM runs WHERE id = :id AND user_id = :user_id`) rather than querying by resource ID first and then verifying ownership in application code.
*   **Context:** Prevent Broken Object-Level Authorization (BOLA).
*   **Why Not Application Checks:** Querying by ID only (`SELECT * FROM runs WHERE id = :id`) and checking `run.user_id == user_id` in application memory exposes a dangerous vulnerability window. If a developer forgets to add the ownership check in a new controller endpoint, the endpoint is immediately vulnerable to BOLA. Forcing user ID parameters at the query level ensures that even if developers forget to check ownership in code, the database query simply returns no results.
*   **Trade-off:** Requires writing query parameters consistently across all endpoints, which is resolved by utilizing standard ORM scopes or repository patterns.

---

## ADR 4: Database-Level Uniqueness Constraints vs. Application-Level Existence Queries

*   **Decision:** Enforce duplicate import prevention using database unique constraints (`UNIQUE(user_id, source_provider, external_workout_id)`) rather than checking existence via application queries before insert.
*   **Context:** A network retry or concurrent background sync must not create duplicate workout rows.
*   **Why Not Application Checks:** Doing a `SELECT COUNT(*)` check before executing an `INSERT` creates a classic race condition (Time-of-Check to Time-of-Use - TOCTOU). In high-concurrency environments, two threads can run the count check simultaneously, see 0 records, and both execute write operations, resulting in duplicate records or primary key collisions. Enforcing unique indexes ensures the database handles serialization atomically.
*   **Trade-off:** The application must handle database Integrity/Constraint errors and convert them to clean idempotent outcomes (e.g., catching `IntegrityError` and returning the existing row ID), rather than returning raw 500 errors to the client.

---

## ADR 5: Separation of Database Transactions from Presentation / Notification Scopes

*   **Decision:** Close and commit database transactions before invoking presentation renders, client navigation, or external notification updates.
*   **Context:** Distinguishing database persistence outcomes from UI rendering or message push errors.
*   **Why Not a Unified Scope:** If database commits and UI updates are wrapped in a single execution block, a presentation-layer failure (like a view refresh exception) will raise an exception, causing the system to report "Save failed" to the client. However, the database transaction has already succeeded, leaving a row in the database. When the client retries, it causes duplicate imports or unique index conflicts. Separating the transaction scope guarantees that once a write is committed, it is reported as persisted, regardless of presentation errors.
*   **Trade-off:** Requires writing separate exception handling blocks for the database write and post-commit presentation phases.

---

## ADR 6: Edge WAF vs. Application Authorization

*   **Decision:** WAF is a perimeter shield, not an authorization layer.
*   **Context:** AWS WAF inspects IP rates and request formats.
*   **Why Not Rely on WAF:** WAF cannot check database row ownership. WAF does not know whether Alice is authorized to access Bob's runs. WAF is critical for blocking SQL injection, scraping blocklists, and rate-limiting DDoS attempts, but resource-level authorization remains an application-layer invariant.
*   **Trade-off:** Application development teams must maintain and test their own authorization matrices rather than offloading access safety to infrastructure firewalls.
