"""Domain models for the fitness application.

Represents the core data structures used in both the database and application layer.
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class User:
    id: str
    email: str
    created_at: datetime


@dataclass
class Workout:
    id: str
    user_id: str
    name: str
    occurred_at: str  # local ISO date format YYYY-MM-DD
    created_at: datetime
    source_name: str | None = "manual"
    hybrid_workout_id: str | None = None


@dataclass
class Run:
    id: str
    user_id: str
    distance_m: float
    duration_seconds: float
    occurred_at: str  # YYYY-MM-DD
    source_provider: str | None = None
    external_workout_id: str | None = None
    created_at: datetime


@dataclass
class BodyMetric:
    id: str
    user_id: str
    metric_type: str  # "weight" or "waist"
    value: float
    occurred_at: str  # YYYY-MM-DD
    created_at: datetime


@dataclass
class RaceGoal:
    id: str
    user_id: str
    name: str
    target_distance_m: float
    target_duration_seconds: float
    race_date: str  # YYYY-MM-DD
    created_at: datetime
