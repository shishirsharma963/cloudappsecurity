# Adversarial Security Audit (`SECURITY_AUDIT.md`)

**Reviewer role:** Principal Security Architect
**Subject:** `cloudappsecurity` prototype (multi-tenant fitness backend)
**Verdict:** Strong foundation, five real gaps. All five are now closed in code; this document records what was wrong, why it mattered, and how it was fixed — plus the questions the junior engineer should be able to answer before the next review.

The prototype's core thesis — *application-layer authorization is the real perimeter, not infrastructure theater* — is correct and well-executed. But several controls were demonstrated rather than proven, and the audit surfaced three additional defects the challenge prompts did not name. Findings are ordered by severity.

---

## Severity Summary

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Nested BOLA: child resources had no ownership path | **High** | Fixed |
| 2 | Log redaction was exact-match/allowlist — leaked on any new key | **High** | Fixed |
| 3 | No token revocation — stolen JWT valid until TTL | **High** | Fixed |
| 4 | "Race condition" test was sequential, proving nothing | Medium | Fixed |
| 5 | Private subnets with no PrivateLink/NAT — wouldn't run; no RDS Proxy | Medium | Fixed |
| 6 | Denial messages disclosed the victim's `user_id` (existence oracle) | Medium | Fixed |
| 7 | `reason` field written to audit log unredacted | Medium | Fixed |
| 8 | `db_sg` egress comment said "deny all" over an allow-all rule | Low | Fixed |
| 9 | `transaction()` on `:memory:` silently wrote to a throwaway DB | Low | Fixed |

Findings 6–9 were not in the handoff brief; they were found during the audit.

---

## Finding 1 — Nested BOLA: the parent was guarded, the children were open

**Challenge:** *"Did you protect the parent but leave the children exposed?"*

**Confirmed.** The original schema had no child tables at all, so `secure_fetch` looked airtight — every protected resource happened to carry its own `user_id`. That is the trap. In a real fitness app a workout owns sets, exercises, and metrics linked by foreign key, and those child rows do **not** carry a `user_id`. An endpoint like `GET /sets/{id}` that queries the child directly has *nothing to bind the tenant to* — `WHERE id = ? AND user_id = ?` cannot even be written, because the column doesn't exist. Alice, blocked from `/workouts/wkt_bob_1`, simply pivots to `/sets/wst_bob_1` and reads Bob's data.

**Fix:**
- Added a `workout_sets` child table ([database.py](cloud_security_case/database.py)) **deliberately normalized with no `user_id`** — the realistic shape that produces the bug.
- Added `CHILD_RESOURCES` mapping and `secure_fetch_child` / `insecure_fetch_child` ([authorization.py](cloud_security_case/authorization.py)). The secure path derives ownership by **joining the child to its parent and binding the parent's `user_id`** to the token subject.
- Demo **Attack 12** and [test_nested_authorization.py](tests/test_nested_authorization.py) prove the insecure path leaks and the secure path denies while still allowing the owner.

**Question for the engineer:** Your app has two levels of nesting today. What is your plan for three (workout → set → set_annotation)? A per-endpoint join does not scale. The production answer is a **query scope / row-level security policy applied globally**, so a developer *cannot* write an unscoped child query. Where does that live — ORM middleware, Postgres RLS, or both?

---

## Finding 2 — Log redaction was a hardcoded allowlist; it leaks the day someone adds a field

**Challenge:** *"Will a simple camelCase key leak your PII?"*

**Confirmed — and worse than stated.** The original `SENSITIVE_KEYS` was an exact-match set of lowercased keys. Empirically, before the fix:

```
{"bodyFatPercentage": 24.1, "heartRateMax": 182}  ->  UNCHANGED (leaked)
{"heart_rate_max": 182, "body_fat_pct": 24.1}     ->  UNCHANGED (leaked)
{"biometrics": {"recoveryIndex": 33.5}}           ->  UNCHANGED (leaked)
```

Every new metric a developer adds is a silent PII leak into every log sink, discovered only in a breach post-mortem. This is a classic **denylist-by-enumeration** failure: it defends only against the exact strings someone remembered to type.

**Fix ([audit.py](cloud_security_case/audit.py)) — classification-driven, fail-closed:**
- Keys are **normalized** (lowercased, separators stripped) so `bodyFatPercentage`, `body_fat_pct`, and `body-fat-pct` collapse to one token, then matched against **classification markers** (credential / contact / health) by substring.
- **Fail-closed rule:** an unrecognized *numeric* value inside a health-context container (`biometrics`, `vitals`, `metrics`, …) is redacted **by default**. Over-redaction costs a less useful log line; under-redaction is a breach. A short structural allowlist (`id`, `setNumber`, `reps`, timestamps) keeps logs correlatable.
- Booleans and non-health numerics are preserved so the logs stay useful.

**Verified** across camelCase/snake_case/kebab-case, nested contact keys, nested emails in free text, and health-context numerics ([test_audit_redaction.py](tests/test_audit_redaction.py)).

**Question for the engineer:** Substring classification will over-match eventually (a field named `token_count` is not a credential). The real production control is **typed log schemas** — a struct where each field is annotated `@Sensitive` at definition time, so classification is a compile-time property, not a runtime guess. This regex layer is a safety net under that, not a substitute. Do you agree, and is the schema work on the roadmap?

---

## Finding 3 — No revocation: a stolen token is valid until it expires

**Challenge:** *"How do you block a stolen token?"*

**Confirmed.** The prototype validated signature/audience/expiry and stopped. That is correct *authentication* but leaves a gaping *revocation* hole: a token lifted from a jailbroken device or a proxy is cryptographically perfect until `exp`. "Stateless validation at the gateway" was being sold as a pure win when it is actually a **trade-off** — statelessness buys latency and availability at the cost of revocability.

**Fix ([auth.py](cloud_security_case/auth.py)):**
- Added `RevocationList`: an edge deny-list keyed by `jti` (single token) and by `sub` with an `iat` cutoff (**GlobalSignOut** semantics — kill everything issued before the sign-out instant, honor post-reauth tokens).
- `verify_token` consults it **after** signature validation (so an attacker can't probe revocation state with unsigned garbage).
- Tombstones **self-expire** at the token's original `exp`, keeping the structure bounded — the same reason a production cache uses a TTL.
- Wired into containment: one exfiltration alert now tombstones the subject on the **gateway deny-list** *and* revokes the **app-layer session** ([containment.py](cloud_security_case/containment.py)). Demo Attack 11 shows the token dying at **both** layers.

This resolves the trade-off honestly: the hot path stays a local cache lookup; only revocation *events* (rare) touch shared state. In production the deny-list is ElastiCache/DynamoDB fed by the same events that drive Cognito `AdminUserGlobalSignOut`.

**Question for the engineer:** A deny-list is fail-open if the cache is unreachable — do you fail closed (reject all) or open (allow all) on a cache miss/outage, and how does that interact with your availability SLO? The honest answer usually involves **short token TTLs (5–15 min) as the backstop**, so the deny-list only has to cover the window. What TTL did you pick, and does the deny-list retention match it?

---

## Finding 4 — The "race condition" was sequential theater

**Challenge:** *"Is this a real race or just sequential theater?"*

**Confirmed.** `execute_attack_6_racing_imports` ran two `with database.transaction()` blocks **one after the other**. That proves the UNIQUE constraint rejects a second insert; it proves **nothing** about concurrency, interleaving, lock contention, or `SQLITE_BUSY` under real thread pressure. Calling it a race was hand-waving.

**Fix ([test_import_idempotency.py](tests/test_import_idempotency.py)):**
`test_true_concurrent_duplicate_imports` spawns **10 threads on a `threading.Barrier`**, so they all fire the same insert at the same released instant, each on its own connection/transaction. Asserted invariants:
- **exactly one** `created`, **nine** `duplicate` recoveries, **zero** raw errors,
- every loser recovers the **winner's** ID (idempotency held under the race),
- the table holds **exactly one** physical row.

This also forced two real correctness fixes in [database.py](cloud_security_case/database.py) that the sequential test would never have caught:
- `BEGIN IMMEDIATE` instead of a deferred `BEGIN` — under WAL a deferred begin takes a read snapshot and fails on write-upgrade if another writer committed in between (`SQLITE_BUSY: snapshot too old`), turning benign contention into spurious 500s.
- `timeout=5.0` on the connection so a blocked writer **waits** for the lock instead of erroring immediately.

**Question for the engineer:** SQLite serializes writers, so this test proves the *logic* but not the *scale*. Aurora Postgres does not serialize writers the same way — under true concurrency you can still get two transactions past a pre-check. Your idempotency therefore **must** rest on the DB constraint catching `23505`, never on an application-level `SELECT`-then-`INSERT`. Confirm no code path relies on the read-check for correctness (the `insecure_import` path, which does, is retained only as the contrast example — correct).

---

## Finding 5 — Private subnets that can't reach AWS, and no connection pooling

**Challenge:** *"Where is the VPC Endpoint?"*

**Confirmed.** `database.tf` put the cluster in private subnets with `publicly_accessible = false` — good — but there was **no NAT Gateway, no VPC endpoints, and no route table** wiring egress. A Lambda in those subnets calling Secrets Manager, KMS, SQS, or CloudWatch would **hang and time out**. The infra as written could not actually run. Separately, there was **no RDS Proxy**: Lambda's horizontal scaling (hundreds of concurrent executions) against Postgres's bounded `max_connections` is a self-inflicted DoS waiting for a traffic spike.

**Fix ([networking.tf](infra/terraform/networking.tf)):**
- **Interface (PrivateLink) endpoints** for `secretsmanager`, `kms`, `logs`, `sqs`, `sts`, `events`, plus a **Gateway endpoint for S3** — traffic stays on the AWS backbone, no NAT needed.
- Explicit **private route table with no `0.0.0.0/0`** — egress control by construction; workloads reach the VPC and the endpoints and nothing else. (I chose PrivateLink over a NAT Gateway deliberately: a NAT opens a generic outbound path an exfiltrating attacker would love.)
- **RDS Proxy** with IAM auth and Secrets Manager integration, so app code never handles the DB password; `db_sg` now admits **only** the proxy SG (plus the rotation lambda).

**Question for the engineer:** Interface endpoints cost money per-AZ per-hour and are easy to over-provision. Did you scope endpoints to services actually called from *private* subnets, or copy a boilerplate list? (I scoped to the six the workloads use.) Also: your endpoints currently have no **endpoint policies** — a compromised workload could call any Secrets Manager secret in the account through them. Adding resource policies to the endpoints is the next hardening step.

---

## Findings 6–9 — Defects found during the audit (not in the brief)

**6 — Existence oracle in denial messages (Medium).** `secure_fetch`/`secure_delete` raised `"...owned by user 'usr_bob'."` That text flows into API errors and audit `reason` fields, handing an enumerator the exact tenant→resource mapping they're probing for. **Fixed:** denials now say *"they do not own"* and never name the owner. Regression asserted in [test_nested_authorization.py](tests/test_nested_authorization.py).

**7 — Unredacted `reason` in audit log (Medium).** `secure_log` scrubbed `actor_id` and `detail` but wrote `reason` raw — and `reason` is often exception text built from user input (emails, tokens). **Fixed:** `reason` now runs through `redact_text`. Asserted in [test_audit_redaction.py](tests/test_audit_redaction.py).

**8 — Lying comment in `db_sg` (Low).** The egress block was commented *"Deny all outbound from database by default"* above a rule allowing `-1` to `0.0.0.0/0`. A reviewer skimming comments would be actively misled. **Fixed:** removed the egress rule entirely (no rule = deny all; the DB initiates nothing).

**9 — `transaction()` on `:memory:` (Low).** Each new `sqlite3` connection to `:memory:` is a *separate* database. `transaction()` opened its own connection, so a transaction against the default in-memory path would commit to a throwaway DB and silently vanish. **Fixed:** `transaction()` now raises if the path is `:memory:`, forcing a file-backed DB.

---

## What was already right (credit where due)

- Object-level tenant binding on the parent (`WHERE id = ? AND user_id = ?`) — the actual point, done correctly.
- Idempotency resting on the DB UNIQUE constraint and catching the violation, not on a bare read-check, in the *secure* path.
- Asymmetric RS256 with public-key-only verification; audience and expiry enforced.
- Structured audit records with actor/action/resource/decision/reason.
- Honest `SECURITY_REVIEW.md` cataloguing what's simulated — rare and valuable.

---

## Test posture

`pytest -v` — **41 → 58 tests**, all green. New coverage: true multi-threaded concurrency, nested-BOLA (leak + block + owner-allow), redaction across naming conventions and health-context fail-closed, token revocation (jti + subject + post-reauth survival + tombstone eviction), reason-field scrubbing, and existence-oracle hardening.

Fixtures were also isolated per-test via pytest's `tmp_path` — the previous shared hardcoded DB path would collide under parallel test execution.
