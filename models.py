from sqlalchemy import String, Text, Integer, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime, timezone

from database import Base

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(200), unique=True)
    password_hash: Mapped[str] = mapped_column(String(225))


class SurveyResponse(Base):
    """
    Stores one completed Security Assessment.

    Kept separate from User (spec section 20: "Survey responses should
    be separated from authentication data"). user_id is nullable
    because the assessment can be taken before logging in.
    """
    __tablename__ = "survey_responses"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )

    # Raw answers and per-question breakdown, stored as JSON text so the
    # scoring is auditable later without adding a column per question.
    raw_answers_json: Mapped[str] = mapped_column(Text)
    breakdown_json: Mapped[str] = mapped_column(Text)

    category_scores_json: Mapped[str] = mapped_column(Text)
    overall_score: Mapped[int] = mapped_column(Integer)
    profile_name: Mapped[str] = mapped_column(String(100))

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )


class ExperimentResult(Base):
    """
    One row per benchmark run or real attack outcome (spec section 20).
    configuration is a short label like "classical" / "ml_kem"; result
    is the real, measured outcome — never a value we made up.
    """
    __tablename__ = "experiment_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    experiment_type: Mapped[str] = mapped_column(String(50))     # "HANDSHAKE_BENCHMARK", "MESSAGE_TAMPERING", ...
    configuration: Mapped[str] = mapped_column(String(50))       # "classical", "ml_kem", etc.
    attack_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    result: Mapped[str] = mapped_column(String(20))              # "BLOCKED", "VULNERABLE", "MEASURED"
    latency_ms: Mapped[float | None] = mapped_column(nullable=True)
    detail_json: Mapped[str] = mapped_column(Text)               # sizes, algorithm names, etc.
    session_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Set when this row was recorded during an active benchmark window
    # (see main.py ACTIVE_BENCHMARK_SESSION) — lets a benchmark run
    # pull in real /ws handshakes and real chat latency that happened
    # organically during the same ~60s, not just synthetic iterations.

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )