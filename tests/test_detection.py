"""Tests verifying application-level anomaly detection behavior."""

import pytest
from cloud_security_case import detection


def test_bola_scan_detection():
    """Verify that multiple sequential authorization failures trigger an anomaly alert."""
    # Instantiating a fresh detector for isolated test state
    detector = detection.AnomalyDetector(denial_threshold=3, window_seconds=2.0)

    # First two denials do not alert
    alert1 = detector.log_event("usr_alice", allowed=False)
    alert2 = detector.log_event("usr_alice", allowed=False)
    assert alert1 is None
    assert alert2 is None

    # Third denial triggers a BOLA scan alert
    alert3 = detector.log_event("usr_alice", allowed=False)
    assert alert3 is not None
    assert alert3["alert"] == "BOLA_SCAN_DETECTED"
    assert alert3["user_id"] == "usr_alice"
    assert alert3["severity"] == "HIGH"


def test_bulk_exfiltration_detection():
    """Verify that excessive successful reads trigger a bulk exfiltration warning."""
    detector = detection.AnomalyDetector(export_threshold=5, window_seconds=2.0)

    # First four reads do not alert
    for _ in range(4):
        alert = detector.log_event("usr_alice", allowed=True)
        assert alert is None

    # Fifth read triggers the alert
    alert = detector.log_event("usr_alice", allowed=True)
    assert alert is not None
    assert alert["alert"] == "BULK_EXFILTRATION_WARNING"
    assert alert["user_id"] == "usr_alice"
    assert alert["severity"] == "CRITICAL"
