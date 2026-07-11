#!/usr/bin/env python3
"""Interactive demo runner for cloudappsecurity.

Contrasts insecure vs secure designs, demonstrates BOLA/IDOR blocking, JWT checks,
idempotent import flows, transaction rollbacks, log redactions, and exfiltration alerts.
"""

import sys
import os
import sqlite3

# Ensure current folder is in python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from cloud_security_case import database, scenarios

BAR = "=" * 70
SUB = "-" * 70


def heading(title: str):
    print(f"\n{BAR}\n{title}\n{BAR}")


def section(name: str):
    print(f"\n{SUB}\n{name}\n{SUB}")


def item_bad(label: str, val: str):
    print(f"  VULNERABLE (BAD)  | {label:24}: {val}")


def item_good(label: str, val: str):
    print(f"  HARDENED   (GOOD) | {label:24}: {val}")


def main():
    print(BAR)
    print("  Cloud Application Security Demo: Multi-Tenant Mobile Backend on AWS")
    print("  Case Study Vehicle: Synthetic Fitness Log Application")
    print(BAR)

    # Setup database connection
    db_file = "/Users/shishir/cloudappsecurity/demo_db.sqlite"
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except OSError:
            pass
    database.set_db_path(db_file)
    conn = database.get_connection()
    database.init_db(conn)
    scenarios.seed_database(conn)

    # -------------------------------------------------------------------------
    heading("PHASE 1: CRYPTOGRAPHIC USER IDENTITY & TOKEN SECURITY")

    # 1. Legit User Read
    section("FLOW 1 — Legitimate user reads own workout")
    f1 = scenarios.execute_flow_1_legit_read(conn)
    print(f"  Authenticated Subject   : {f1['claims']['sub']} ({f1['claims']['email']})")
    print(f"  Requested Resource ID   : {f1['workout']['id']}")
    print(f"  Workout Details         : {f1['workout']['name']} on {f1['workout']['occurred_at']}")
    print(f"  Ownership Authorization : AUTHORIZED (User owns resource)")
    item_good("Access Decision", "ALLOWED")

    # 2. BOLA Attack
    section("ATTACK 1 — Broken Object-Level Authorization (BOLA / IDOR)")
    print("  Alice attempts to read Bob's workout (wkt_bob_1) by changing the resource ID in the URL.")
    f2 = scenarios.execute_attack_1_bola(conn)
    item_bad("Insecure Query Result", f"Leaked workout: {f2['insecure_result']}")
    item_good("Secure Query Result", f"Blocked with message: {f2['secure_error']}")

    # 3. Forged Token
    section("ATTACK 2 — Forged Token Signature")
    print("  Attacker creates a JWT using their own RSA key pair and claims it came from Cognito.")
    a2 = scenarios.execute_attack_2_forged_token()
    item_good("Verification Result", a2)

    # 4. Wrong Audience
    section("ATTACK 3 — Wrong Audience Token Replay")
    print("  Attacker attempts to replay a token minted for a different microservice API.")
    a3 = scenarios.execute_attack_3_wrong_audience()
    item_good("Verification Result", a3)

    # 5. Expired Token
    section("ATTACK 4 — Expired Token Replay")
    print("  Attacker replays a previously captured expired OIDC token.")
    a4 = scenarios.execute_attack_4_expired_token()
    item_good("Verification Result", a4)

    # -------------------------------------------------------------------------
    heading("PHASE 2: WEARABLE DATA INGESTION & TRANSACTION INTEGRITY")

    # 6. Legit Import
    section("FLOW 2 — Legitimate Wearable Workout Ingestion")
    print("  Synchronizing run from Apple Health/Apple Watch.")
    f6 = scenarios.execute_flow_2_legit_import(conn)
    print(f"  Source Provider         : {f6['payload']['source_provider']}")
    print(f"  External UUID           : {f6['payload']['external_workout_id']}")
    item_good("Ingestion Outcome", f"PERSISTED with ID '{f6['workout_id']}'")

    # 7. Duplicate Import Replay
    section("ATTACK 5 — Duplicate Ingestion Replay (Idempotency Guard)")
    print("  Network timeout causes client to resend same wearable run UUID.")
    f7 = scenarios.execute_attack_5_duplicate_import(conn)
    item_bad("Insecure Ingest Response", f7["insecure"][0])
    item_good("Secure Ingest Response", f7["secure"][0])

    # 8. Concurrent Race Ingestion
    section("ATTACK 6 — Background Sync vs Manual Save (Race Condition)")
    print("  Simulated race: concurrent threads execute writes for the same run.")
    f8 = scenarios.execute_attack_6_racing_imports(conn)
    for r in f8["results"]:
        item_good("Execution thread log", r)

    # 9. Validation Failure Rollback
    section("ATTACK 7 — Invariant Validation Failure Rollback")
    print("  Payload contains validation error (negative distance value).")
    f9 = scenarios.execute_attack_7_validation_failure(conn)
    print(f"  Validation Exception    : {f9['error']}")
    item_good("DB Persisted Count", f"Saved records = {f9['count']} (Rollback successful)")

    # 10. Post-Commit presentation ambiguity
    section("ATTACK 8 — Post-Commit Presentation Failure Ambiguity")
    print("  Database write succeeds, but a downstream UI update throws an error.")
    f10 = scenarios.execute_attack_8_post_commit_failure(conn)
    item_bad("Insecure App Report", f"{f10['insecure_status']} (DB Count: {f10['insecure_db_count']})")
    item_good("Secure App Report", f10["secure_status"])

    # -------------------------------------------------------------------------
    heading("PHASE 3: STRUCTURED AUDITING & BEHAVIORAL DETECTION")

    # 11. Redacted Logs
    section("ATTACK 9 — Sensitive Data Leak in Logs")
    print("  Application logs user login event containing emails and credentials.")
    f11 = scenarios.execute_attack_9_sensitive_logging(conn)
    item_bad("Insecure Log Entry", f11["insecure"]["detail"][:140] + "...")
    item_good("Secure Log Entry", f11["secure"]["detail"])

    # 12. Bulk exfiltration
    section("ATTACK 10 — Bulk Authenticated Data Exfiltration")
    print("  Alice rapidly requests multiple workouts within a short time window.")
    a10 = scenarios.execute_attack_10_bulk_exfiltration()
    for alert in a10:
        item_good("Anomaly Engine Alert", f"[{alert['alert']}] Severity: {alert['severity']} -> {alert['recommendation']}")

    conn.close()
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except OSError:
            pass
    print(BAR)
    print("  Demo Complete.")
    print(BAR)


if __name__ == "__main__":
    main()
