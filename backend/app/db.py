"""SQLite store so investigators can open the same file in DBeaver."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "intel.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    risk: Mapped[str] = mapped_column(String(16))
    subject: Mapped[str | None] = mapped_column(String(512), nullable=True)
    sender: Mapped[str | None] = mapped_column(String(512), nullable=True)
    payload_json: Mapped[str] = mapped_column(Text)


def init_db() -> None:
    Base.metadata.create_all(engine)


def save_analysis(result: dict) -> dict:
    with SessionLocal() as session:
        row = Analysis(
            risk=result["risk"],
            subject=result.get("subject"),
            sender=result.get("from"),
            payload_json=json.dumps(result),
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return _to_dict(row)


def list_analyses(limit: int = 50) -> list[dict]:
    with SessionLocal() as session:
        rows = session.scalars(select(Analysis).order_by(Analysis.id.desc()).limit(limit)).all()
        return [_to_dict(row) for row in rows]


def get_analysis(analysis_id: int) -> dict | None:
    with SessionLocal() as session:
        row = session.get(Analysis, analysis_id)
        return _to_dict(row) if row else None


def _to_dict(row: Analysis) -> dict:
    data = json.loads(row.payload_json)
    data["id"] = row.id
    data["created_at"] = row.created_at.isoformat()
    return data
