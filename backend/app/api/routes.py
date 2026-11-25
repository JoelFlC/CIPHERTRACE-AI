"""REST and WebSocket API routes for CIPHERTRACE AI."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from pydantic import BaseModel, Field
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.core.config import (
    FEATURE_COLUMNS,
    GA_CONFIG_PATH,
    LABEL_CLASSES,
    MODEL_METRICS_PATH,
)
from app.db.database import get_db
from app.db.models import AnalyzedFlow, SecurityAlert, persist_evaluation
from app.ml.dataset_builder import _map_external_dataframe
from app.ml.pcap_extractor import extract_flows_from_pcap
from app.services.inference_engine import engine
from app.services.threat_simulator import generate_simulated_flows
from app.services.ws_manager import ws_manager

router = APIRouter(prefix="/api", tags=["CIPHERTRACE API"])


class SimulateRequest(BaseModel):
    """Payload for real-time threat simulation."""

    scenario: str = Field(
        default="PHISHING_AITM",
        description="One of BENIGN, C2_BEACONING, DOH_TUNNEL, EXFILTRATION, PHISHING_AITM",
    )
    count: int = Field(default=5, ge=1, le=50)
    delay_ms: int = Field(default=100, ge=0, le=2000)


@router.get("/health")
async def get_health() -> dict[str, Any]:
    """Return system status and verification of loaded ML/DL artifacts."""
    engine.ensure_loaded()
    return {
        "status": "ok",
        "service": "CIPHERTRACE AI Backend",
        "models_loaded": engine.loaded,
        "loaded_artifacts": {
            "scaler": engine.scaler is not None,
            "mlp_model": engine.mlp_model is not None,
            "autoencoder": engine.autoencoder is not None,
            "rf_model": engine.rf_model is not None,
            "iforest_model": engine.iforest_model is not None,
        },
        "selected_features": engine.ga_config.get("selected_features", []),
        "hybrid_weights": {
            "w_mlp": engine.w_mlp,
            "w_ae": engine.w_ae,
            "threshold": engine.threshold,
        },
        "ws_connections": len(ws_manager.active_connections),
    }


@router.get("/dashboard/summary")
async def get_dashboard_summary(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Return aggregated SOC KPIs from SQLite."""
    total_flows = int(db.query(func.count(AnalyzedFlow.id)).scalar() or 0)
    active_alerts = int(db.query(func.count(SecurityAlert.id)).scalar() or 0)
    critical_alerts = int(
        db.query(func.count(SecurityAlert.id))
        .filter(SecurityAlert.risk_level == "ALTO")
        .scalar()
        or 0
    )
    medium_alerts = int(
        db.query(func.count(SecurityAlert.id))
        .filter(SecurityAlert.risk_level == "MEDIO")
        .scalar()
        or 0
    )
    avg_latency = float(
        db.query(func.avg(AnalyzedFlow.inference_latency_ms)).scalar() or 0.0
    )

    threat_rows = (
        db.query(AnalyzedFlow.predicted_threat, func.count(AnalyzedFlow.id))
        .group_by(AnalyzedFlow.predicted_threat)
        .all()
    )
    threat_distribution = {label: 0 for label in LABEL_CLASSES}
    for threat, count in threat_rows:
        threat_distribution[str(threat)] = int(count)

    risk_rows = (
        db.query(AnalyzedFlow.risk_level, func.count(AnalyzedFlow.id))
        .group_by(AnalyzedFlow.risk_level)
        .all()
    )
    risk_distribution = {"BAJO": 0, "MEDIO": 0, "ALTO": 0}
    for level, count in risk_rows:
        risk_distribution[str(level)] = int(count)

    anomaly_rate = round(
        (active_alerts / total_flows) * 100.0, 2
    ) if total_flows > 0 else 0.0

    return {
        "total_flows": total_flows,
        "active_alerts": active_alerts,
        "critical_alerts": critical_alerts,
        "medium_alerts": medium_alerts,
        "avg_inference_latency_ms": round(avg_latency, 4),
        "anomaly_rate_pct": anomaly_rate,
        "threat_distribution": threat_distribution,
        "risk_distribution": risk_distribution,
    }


@router.get("/flows")
async def get_recent_flows(
    limit: int = Query(default=50, ge=1, le=500),
    risk_level: str = Query(default="ALL"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Fetch recent analyzed flows and alerts filtered optionally by risk_level."""
    normalized_risk = risk_level.strip().upper()
    flow_query = db.query(AnalyzedFlow).order_by(desc(AnalyzedFlow.id))
    alert_query = db.query(SecurityAlert).order_by(desc(SecurityAlert.id))

    if normalized_risk in ("BAJO", "MEDIO", "ALTO"):
        flow_query = flow_query.filter(AnalyzedFlow.risk_level == normalized_risk)
        alert_query = alert_query.filter(SecurityAlert.risk_level == normalized_risk)

    flows = [row.to_dict() for row in flow_query.limit(limit).all()]
    alerts = [row.to_dict() for row in alert_query.limit(limit).all()]
    return {
        "count": len(flows),
        "risk_level_filter": normalized_risk,
        "flows": flows,
        "alerts": alerts,
    }


@router.get("/ml/metrics")
async def get_ml_metrics() -> dict[str, Any]:
    """Return Phase 1 cross-validation model metrics and GA evolution config."""
    engine.ensure_loaded()
    metrics = engine.model_metrics
    ga_cfg = engine.ga_config

    if not metrics and MODEL_METRICS_PATH.exists():
        with open(MODEL_METRICS_PATH, encoding="utf-8") as fh:
            metrics = json.load(fh)
    if not ga_cfg and GA_CONFIG_PATH.exists():
        with open(GA_CONFIG_PATH, encoding="utf-8") as fh:
            ga_cfg = json.load(fh)

    return {
        "model_metrics": metrics,
        "ga_config": ga_cfg,
    }


@router.post("/analyze/file")
async def analyze_uploaded_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Passively extract flows from .pcap/.csv upload, evaluate, persist, and broadcast."""
    engine.ensure_loaded()
    filename = file.filename or "upload.bin"
    suffix = Path(filename).suffix.lower()
    if suffix not in (".pcap", ".pcapng", ".csv"):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Upload a .pcap, .pcapng, or .csv file.",
        )

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_fh:
            tmp_fh.write(content)
            tmp_path = tmp_fh.name

        if suffix in (".pcap", ".pcapng"):
            raw_flows = extract_flows_from_pcap(tmp_path)
        else:
            raw_df = pd.read_csv(tmp_path, low_memory=False)
            mapped_df = _map_external_dataframe(raw_df, source_idx=0)
            raw_flows = []
            for idx in range(len(mapped_df)):
                row = mapped_df.iloc[idx]
                raw_flows.append(
                    {
                        "flow_id": str(row["flow_id"]),
                        "src_ip": str(row["src_ip"]),
                        "dst_ip": str(row["dst_ip"]),
                        "src_port": int(row["src_port"]),
                        "dst_port": int(row["dst_port"]),
                        "protocol": str(row["protocol"]),
                        "sni": "",
                        "features": {col: float(row[col]) for col in FEATURE_COLUMNS},
                    }
                )
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

    evaluated_flows: list[dict[str, Any]] = []
    alerts_generated: list[dict[str, Any]] = []

    for raw_flow in raw_flows:
        evaluation = engine.evaluate_flow(raw_flow)
        flow_dict, alert_dict = persist_evaluation(
            db, evaluation, source=f"file:{filename}"
        )
        evaluated_flows.append(flow_dict)
        if alert_dict is not None:
            alerts_generated.append(alert_dict)

        await ws_manager.broadcast(
            {
                "event": "flow_evaluated",
                "source": f"file:{filename}",
                "flow": flow_dict,
                "alert": alert_dict,
            }
        )

    threat_counts: dict[str, int] = {}
    risk_counts: dict[str, int] = {"BAJO": 0, "MEDIO": 0, "ALTO": 0}
    for item in evaluated_flows:
        threat_counts[item["predicted_threat"]] = (
            threat_counts.get(item["predicted_threat"], 0) + 1
        )
        risk_counts[item["risk_level"]] = risk_counts.get(item["risk_level"], 0) + 1

    return {
        "filename": filename,
        "total_flows_analyzed": len(evaluated_flows),
        "alerts_triggered": len(alerts_generated),
        "risk_summary": risk_counts,
        "threat_summary": threat_counts,
        "flows": evaluated_flows,
        "alerts": alerts_generated,
    }


@router.post("/lab/simulate")
async def simulate_threat_flows(
    payload: SimulateRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Generate simulated flows, evaluate with CipherTraceEngine, persist, and stream via WS."""
    engine.ensure_loaded()
    try:
        simulated = generate_simulated_flows(
            scenario=payload.scenario, count=payload.count
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    evaluated_flows: list[dict[str, Any]] = []
    alerts_generated: list[dict[str, Any]] = []

    for idx, flow_meta in enumerate(simulated):
        if idx > 0 and payload.delay_ms > 0:
            await asyncio.sleep(payload.delay_ms / 1000.0)

        evaluation = engine.evaluate_flow(flow_meta)
        flow_dict, alert_dict = persist_evaluation(
            db, evaluation, source=f"sim:{payload.scenario.upper()}"
        )
        evaluated_flows.append(flow_dict)
        if alert_dict is not None:
            alerts_generated.append(alert_dict)

        await ws_manager.broadcast(
            {
                "event": "flow_evaluated",
                "source": f"sim:{payload.scenario.upper()}",
                "flow": flow_dict,
                "alert": alert_dict,
            }
        )

    return {
        "scenario": payload.scenario.upper(),
        "count": len(evaluated_flows),
        "alerts_triggered": len(alerts_generated),
        "flows": evaluated_flows,
        "alerts": alerts_generated,
    }


ws_router = APIRouter(tags=["CIPHERTRACE WebSocket"])


@ws_router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket) -> None:
    """Real-time WebSocket stream for SOC alerts and evaluated flows."""
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json(
            {
                "event": "connected",
                "message": "CIPHERTRACE AI SOC WebSocket conectado",
            }
        )
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
