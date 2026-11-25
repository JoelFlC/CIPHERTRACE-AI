"""End-to-End API and passive inference verification suite for CIPHERTRACE AI."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

TEST_PATH = Path(__file__).resolve()
BACKEND_DIR = TEST_PATH.parent.parent
PROJECT_ROOT = BACKEND_DIR.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Use an isolated temporary SQLite database unless DATABASE_URL is explicitly provided
_TEMP_DB_DIR: str | None = None
if "DATABASE_URL" not in os.environ:
    _TEMP_DB_DIR = tempfile.mkdtemp(prefix="ciphertrace_e2e_")
    os.environ["DATABASE_URL"] = f"sqlite:///{_TEMP_DB_DIR}/e2e_test.db"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from scripts.generate_demo_files import generate_all  # noqa: E402


def _ensure_demo_samples() -> tuple[Path, Path]:
    demo_dir = PROJECT_ROOT / "demo_samples"
    csv_path = demo_dir / "mixed_traffic_demo.csv"
    pcap_path = demo_dir / "sample_capture.pcap"
    if not csv_path.exists() or not pcap_path.exists():
        csv_path, pcap_path = generate_all(demo_dir)
    return csv_path, pcap_path


def run_all_tests() -> None:
    """Execute the complete End-to-End verification against FastAPI TestClient."""
    csv_path, pcap_path = _ensure_demo_samples()

    with TestClient(app) as client:
        # 1. Health check & ML artifacts verification
        resp = client.get("/api/health")
        assert resp.status_code == 200, f"/api/health failed: {resp.text}"
        health = resp.json()
        assert health["status"] == "ok"
        assert health["models_loaded"] is True
        assert all(health["loaded_artifacts"].values()), (
            f"Missing artifacts: {health['loaded_artifacts']}"
        )
        print("[PASS] GET /api/health")

        # 2. ML & GA metrics endpoint
        resp = client.get("/api/ml/metrics")
        assert resp.status_code == 200, f"/api/ml/metrics failed: {resp.text}"
        ml = resp.json()
        assert "random_forest" in ml["model_metrics"]["models"]
        assert "mlp" in ml["model_metrics"]["models"]
        assert "autoencoder" in ml["model_metrics"]["models"]
        assert "isolation_forest" in ml["model_metrics"]["models"]
        assert "hybrid_ensemble" in ml["model_metrics"]
        assert len(ml["ga_config"]["feature_columns"]) == 18
        assert len(ml["ga_config"]["selected_features"]) > 0
        print("[PASS] GET /api/ml/metrics")

        # 3. Initial dashboard summary
        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200, f"/api/dashboard/summary failed: {resp.text}"
        summary = resp.json()
        for key in (
            "total_flows",
            "active_alerts",
            "critical_alerts",
            "medium_alerts",
            "avg_inference_latency_ms",
            "anomaly_rate_pct",
            "threat_distribution",
            "risk_distribution",
        ):
            assert key in summary, f"Missing summary key: {key}"
        print("[PASS] GET /api/dashboard/summary (initial)")

        # 4. Controlled threat simulations (AiTM + C2)
        for scenario in ("PHISHING_AITM", "C2_BEACONING"):
            resp = client.post(
                "/api/lab/simulate",
                json={"scenario": scenario, "count": 3, "delay_ms": 0},
            )
            assert resp.status_code == 200, f"simulate {scenario} failed: {resp.text}"
            sim = resp.json()
            assert sim["scenario"] == scenario
            assert sim["count"] == 3
            assert sim["alerts_triggered"] >= 1
            assert len(sim["flows"][0]["top_contributing_features"]) == 3
        print("[PASS] POST /api/lab/simulate (PHISHING_AITM & C2_BEACONING)")

        # 5. Passive file upload analysis (.csv & .pcap)
        with open(csv_path, "rb") as csv_fh:
            resp = client.post(
                "/api/analyze/file",
                files={"file": (csv_path.name, csv_fh, "text/csv")},
            )
        assert resp.status_code == 200, f"analyze CSV failed: {resp.text}"
        csv_res = resp.json()
        assert csv_res["total_flows_analyzed"] == 40
        assert csv_res["alerts_triggered"] > 0
        print("[PASS] POST /api/analyze/file (mixed_traffic_demo.csv)")

        with open(pcap_path, "rb") as pcap_fh:
            resp = client.post(
                "/api/analyze/file",
                files={"file": (pcap_path.name, pcap_fh, "application/vnd.tcpdump.pcap")},
            )
        assert resp.status_code == 200, f"analyze PCAP failed: {resp.text}"
        pcap_res = resp.json()
        assert pcap_res["total_flows_analyzed"] >= 5
        assert len(pcap_res["flows"]) >= 5
        print("[PASS] POST /api/analyze/file (sample_capture.pcap)")

        # 6. Local AiTM reverse-proxy login endpoint
        resp = client.post(
            "/lab/aitm-proxy/login",
            json={"username": "estudiante.e2e@universidad.local"},
            headers={"Accept": "application/json"},
        )
        assert resp.status_code == 200, f"/lab/aitm-proxy/login failed: {resp.text}"
        aitm_res = resp.json()
        assert aitm_res["mode"] == "AITM_REVERSE_PROXY"
        assert aitm_res["captured_session_token"].startswith("session_token_demo_")
        assert aitm_res["measured_double_hop_latency_ms"] >= 150.0
        assert aitm_res["risk_level"] in ("MEDIO", "ALTO")
        assert len(aitm_res["top_contributing_features"]) == 3
        print("[PASS] POST /lab/aitm-proxy/login")

        # 7. Final dashboard summary & flows verification
        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200
        final_summary = resp.json()
        assert final_summary["total_flows"] >= 52
        assert final_summary["active_alerts"] > 0

        resp = client.get("/api/flows?limit=20&risk_level=ALTO")
        assert resp.status_code == 200
        flows_payload = resp.json()
        assert flows_payload["count"] > 0
        print("[PASS] GET /api/dashboard/summary & /api/flows (post-ingestion)")

    print("\nALL E2E TESTS PASSED (7/7)")


def test_e2e_suite() -> None:
    """Pytest-compatible wrapper."""
    run_all_tests()


if __name__ == "__main__":
    try:
        run_all_tests()
    finally:
        if _TEMP_DB_DIR and os.path.exists(_TEMP_DB_DIR):
            shutil.rmtree(_TEMP_DB_DIR, ignore_errors=True)
