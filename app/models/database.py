from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all database models."""

    pass


class Analysis(Base):
    """Stores analysis history and results."""

    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ciphertext_hash: Mapped[str] = mapped_column(String(64), index=True)
    ciphertext: Mapped[str] = mapped_column(Text)

    # Analysis profile
    statistics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    detected_language: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Classification result (new)
    classification: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Cipher detection results (legacy, kept for backward compatibility)
    suspected_ciphers: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    # Decryption results
    plaintext_candidates: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    best_plaintext: Mapped[str | None] = mapped_column(Text, nullable=True)
    best_formatted_plaintext: Mapped[str | None] = mapped_column(Text, nullable=True)
    best_cipher_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    best_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    best_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    best_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Visual data for frontend
    visual_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Analysis info (performance metrics)
    analysis_info: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Metadata
    parameters_used: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    explanations: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )


class User(Base):
    """User model for API access and history tracking."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
