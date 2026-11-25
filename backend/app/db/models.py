"""SQLAlchemy ORM models for analyzed network flows and security alerts."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship

from app.db.database import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AnalyzedFlow(Base):
    """Persisted passive flow evaluation record."""

    __tablename__ = "analyzed_flows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    flow_id: Mapped[str] = mapped_column(String(128), index=True)
    timestamp_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, index=True
    )
    source: Mapped[str] = mapped_column(String(64), default="api")
    src_ip: Mapped[str] = mapped_column(String(64), default="0.0.0.0")
    dst_ip: Mapped[str] = mapped_column(String(64), default="0.0.0.0")
    src_port: Mapped[int] = mapped_column(Integer, default=0)
    dst_port: Mapped[int] = mapped_column(Integer, default=443)
    protocol: Mapped[str] = mapped_column(String(16), default="TCP")
    sni: Mapped[str] = mapped_column(String(255), default="")

    prob_mlp: Mapped[float] = mapped_column(Float, nullable=False)
    anomaly_ae: Mapped[float] = mapped_column(Float, nullable=False)
    prob_rf: Mapped[float] = mapped_column(Float, nullable=False)
    anomaly_iforest: Mapped[float] = mapped_column(Float, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), index=True)
    predicted_threat: Mapped[str] = mapped_column(String(32), index=True)
    inference_latency_ms: Mapped[float] = mapped_column(Float, nullable=False)

    features_json: Mapped[str] = mapped_column(Text, nullable=False)
    explainability_json: Mapped[str] = mapped_column(Text, nullable=False)

    alert: Mapped["SecurityAlert | None"] = relationship(
        back_populates="flow", uselist=False, cascade="all, delete-orphan"
    )

    def to_dict(self) -> dict[str, Any]:
        ts = self.timestamp_utc
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return {
            "id": int(self.id),
            "flow_id": self.flow_id,
            "timestamp_utc": ts.isoformat(),
            "source": self.source,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": int(self.src_port),
            "dst_port": int(self.dst_port),
            "protocol": self.protocol,
            "sni": self.sni,
            "prob_mlp": float(self.prob_mlp),
            "anomaly_ae": float(self.anomaly_ae),
            "prob_rf": float(self.prob_rf),
            "anomaly_iforest": float(self.anomaly_iforest),
            "risk_score": float(self.risk_score),
            "risk_level": self.risk_level,
            "predicted_threat": self.predicted_threat,
            "inference_latency_ms": float(self.inference_latency_ms),
            "features": json.loads(self.features_json),
            "top_contributing_features": json.loads(self.explainability_json),
        }


class SecurityAlert(Base):
    """Persisted SOC security alert generated when risk_level is MEDIO or ALTO."""

    __tablename__ = "security_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    flow_db_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyzed_flows.id"), nullable=False, unique=True
    )
    flow_id: Mapped[str] = mapped_column(String(128), index=True)
    timestamp_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, index=True
    )
    src_ip: Mapped[str] = mapped_column(String(64), default="0.0.0.0")
    dst_ip: Mapped[str] = mapped_column(String(64), default="0.0.0.0")
    dst_port: Mapped[int] = mapped_column(Integer, default=443)
    protocol: Mapped[str] = mapped_column(String(16), default="TCP")

    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), index=True)
    predicted_threat: Mapped[str] = mapped_column(String(32), index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    explainability_json: Mapped[str] = mapped_column(Text, nullable=False)

    flow: Mapped[AnalyzedFlow] = relationship(back_populates="alert")

    def to_dict(self) -> dict[str, Any]:
        ts = self.timestamp_utc
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return {
            "id": int(self.id),
            "flow_db_id": int(self.flow_db_id),
            "flow_id": self.flow_id,
            "timestamp_utc": ts.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": int(self.dst_port),
            "protocol": self.protocol,
            "risk_score": float(self.risk_score),
            "risk_level": self.risk_level,
            "predicted_threat": self.predicted_threat,
            "summary": self.summary,
            "top_contributing_features": json.loads(self.explainability_json),
        }


def persist_evaluation(
    db: Session,
    evaluation: dict[str, Any],
    source: str = "api",
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Persist an evaluated flow and, if risk is MEDIO/ALTO, create a SecurityAlert."""
    now = _utc_now()
    features_json = json.dumps(evaluation["features"])
    explain_json = json.dumps(evaluation["top_contributing_features"], ensure_ascii=False)

    flow_row = AnalyzedFlow(
        flow_id=str(evaluation["flow_id"]),
        timestamp_utc=now,
        source=str(source),
        src_ip=str(evaluation["src_ip"]),
        dst_ip=str(evaluation["dst_ip"]),
        src_port=int(evaluation.get("src_port", 0)),
        dst_port=int(evaluation.get("dst_port", 443)),
        protocol=str(evaluation.get("protocol", "TCP")),
        sni=str(evaluation.get("sni", "")),
        prob_mlp=float(evaluation["prob_mlp"]),
        anomaly_ae=float(evaluation["anomaly_ae"]),
        prob_rf=float(evaluation["prob_rf"]),
        anomaly_iforest=float(evaluation["anomaly_iforest"]),
        risk_score=float(evaluation["risk_score"]),
        risk_level=str(evaluation["risk_level"]),
        predicted_threat=str(evaluation["predicted_threat"]),
        inference_latency_ms=float(evaluation["inference_latency_ms"]),
        features_json=features_json,
        explainability_json=explain_json,
    )
    db.add(flow_row)
    db.flush()

    alert_dict: dict[str, Any] | None = None
    if evaluation["risk_level"] in ("MEDIO", "ALTO"):
        top_reasons = [
            item["explanation"]
            for item in evaluation["top_contributing_features"][:2]
        ]
        summary = " | ".join(top_reasons) if top_reasons else evaluation["predicted_threat"]
        alert_row = SecurityAlert(
            flow_db_id=flow_row.id,
            flow_id=flow_row.flow_id,
            timestamp_utc=now,
            src_ip=flow_row.src_ip,
            dst_ip=flow_row.dst_ip,
            dst_port=flow_row.dst_port,
            protocol=flow_row.protocol,
            risk_score=flow_row.risk_score,
            risk_level=flow_row.risk_level,
            predicted_threat=flow_row.predicted_threat,
            summary=summary,
            explainability_json=explain_json,
        )
        db.add(alert_row)
        db.flush()
        alert_dict = alert_row.to_dict()

    db.commit()
    db.refresh(flow_row)
    return flow_row.to_dict(), alert_dict
