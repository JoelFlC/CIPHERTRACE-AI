"""SQLAlchemy engine and session configuration supporting PostgreSQL and SQLite fallback."""

from __future__ import annotations

import os
import time
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ciphertrace.db")
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
SQLALCHEMY_DATABASE_URL = DATABASE_URL

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Declarative base for SQLAlchemy ORM models."""


def init_db(max_retries: int = 5, retry_delay: float = 2.0) -> None:
    """Create all database tables with startup retries for PostgreSQL readiness."""
    from app.db import models  # noqa: F401

    for attempt in range(1, max_retries + 1):
        try:
            Base.metadata.create_all(bind=engine)
            return
        except (OperationalError, SQLAlchemyError) as exc:
            if attempt >= max_retries:
                raise
            print(
                f"[CIPHERTRACE DB] Esperando base de datos (intento {attempt}/{max_retries}): {exc}"
            )
            time.sleep(retry_delay)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a scoped SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
