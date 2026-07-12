"""Detection module for application-level security metrics and threat alerts.

Identifies semantic abuse (BOLA scans and bulk exports) that cloud-level
infrastructure detection (e.g. AWS GuardDuty) cannot natively see.
"""

import time


class AnomalyDetector:
    def __init__(
        self,
        denial_threshold: int = 3,
        export_threshold: int = 5,
        window_seconds: float = 5.0,
        alert_hooks: list | None = None,
    ):
        self.denial_threshold = denial_threshold
        self.export_threshold = export_threshold
        self.window_seconds = window_seconds

        # Containment callbacks invoked with each alert (e.g. session revocation).
        # Production equivalent: EventBridge rule -> response Lambda.
        self.alert_hooks = alert_hooks or []

        # In-memory tracking lists: user_id -> [timestamps]
        self._denials = {}
        self._accesses = {}

    def _prune(self, history: list, now: float) -> list:
        return [t for t in history if now - t <= self.window_seconds]

    def _dispatch(self, alert: dict) -> dict:
        """Run containment hooks and attach their actions to the alert."""
        actions = []
        for hook in self.alert_hooks:
            result = hook(alert)
            if result:
                actions.append(result)
        if actions:
            alert["containment_actions"] = actions
        return alert

    def log_event(self, user_id: str, allowed: bool) -> dict | None:
        """Process access result and check for anomalies."""
        now = time.time()

        if not allowed:
            # Track authorization failure rate
            history = self._denials.setdefault(user_id, [])
            history.append(now)
            history[:] = self._prune(history, now)

            if len(history) >= self.denial_threshold:
                return self._dispatch({
                    "alert": "BOLA_SCAN_DETECTED",
                    "user_id": user_id,
                    "count": len(history),
                    "window_seconds": self.window_seconds,
                    "severity": "HIGH",
                    "recommendation": "Block IP / Temp disable User Cognito Session",
                    "evidence_for": ["SOC2_CC7.2", "NIST_DE.AE"],
                })
        else:
            # Track volume of successful reads (bulk export attempt)
            history = self._accesses.setdefault(user_id, [])
            history.append(now)
            history[:] = self._prune(history, now)

            if len(history) >= self.export_threshold:
                return self._dispatch({
                    "alert": "BULK_EXFILTRATION_WARNING",
                    "user_id": user_id,
                    "count": len(history),
                    "window_seconds": self.window_seconds,
                    "severity": "CRITICAL",
                    "recommendation": "Enforce captcha or revoke OIDC/Cognito session",
                    "evidence_for": ["SOC2_CC7.2", "NIST_DE.AE"],
                })

        return None
