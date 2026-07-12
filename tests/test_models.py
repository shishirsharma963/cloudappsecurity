"""Regression test: the models module must import and construct cleanly.

Nothing else imported models, so a dataclass field-ordering error
(non-default argument after default arguments) shipped undetected.
"""

from datetime import datetime

from cloud_security_case import models


def test_run_model_constructs():
    run = models.Run(
        id="run_1",
        user_id="usr_alice",
        distance_m=5000.0,
        duration_seconds=1200.0,
        occurred_at="2026-07-03",
        created_at=datetime.now(),
        source_provider="apple_health",
        external_workout_id="uuid_1",
    )
    assert run.user_id == "usr_alice"


def test_all_models_construct():
    now = datetime.now()
    models.User(id="u", email="e@example.com", created_at=now)
    models.Workout(id="w", user_id="u", name="n", occurred_at="2026-07-01", created_at=now)
    models.BodyMetric(id="b", user_id="u", metric_type="weight", value=70.0, occurred_at="2026-07-01", created_at=now)
    models.RaceGoal(
        id="r", user_id="u", name="race", target_distance_m=8000.0,
        target_duration_seconds=3600.0, race_date="2026-09-01", created_at=now,
    )
