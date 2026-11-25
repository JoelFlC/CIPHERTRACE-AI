"""Real-time passive flow simulator for SOC threat scenarios."""

from __future__ import annotations

import uuid
from typing import Any

import numpy as np

from app.core.config import FEATURE_COLUMNS, LABEL_CLASSES
from app.ml.dataset_builder import _build_class_block

SCENARIO_SNIS: dict[str, list[str]] = {
    "BENIGN": [
        "api.github.com",
        "cdn.cloudflare.com",
        "login.microsoftonline.com",
        "outlook.office365.com",
    ],
    "C2_BEACONING": [
        "cdn-telemetry-sync.cloud-ops.net",
        "update-agent-v2.net-edge.io",
        "static-heartbeat.sync-node.org",
    ],
    "DOH_TUNNEL": [
        "a8f4c912d0e3b76a55f19c8e4d2a1b0f9e8c.doh-relay.net",
        "7c91e3a04b2f8d65e109a3c7f5b2d4e8901a.dns-tunnel.xyz",
    ],
    "EXFILTRATION": [
        "backup-mirror-upload.object-store.io",
        "archive-sync-east.cloud-bucket.net",
    ],
    "PHISHING_AITM": [
        "login-verify-session-a9f82c1e.cloud-auth.site",
        "sso-account-check-7b4d90e2.auth-portal.online",
    ],
}


def generate_simulated_flows(
    scenario: str,
    count: int = 5,
    seed: int | None = None,
) -> list[dict[str, Any]]:
    """Generate realistic passive metadata flows for the requested threat scenario."""
    normalized = scenario.strip().upper()
    if normalized not in LABEL_CLASSES:
        raise ValueError(
            f"Invalid scenario '{scenario}'. Must be one of {LABEL_CLASSES}"
        )

    rng = np.random.default_rng(seed)
    block = _build_class_block(rng, normalized, count)
    sni_pool = SCENARIO_SNIS[normalized]

    flows: list[dict[str, Any]] = []
    for idx in range(len(block)):
        row = block.iloc[idx]
        sni = str(rng.choice(sni_pool))
        features = {col: float(row[col]) for col in FEATURE_COLUMNS}
        flows.append(
            {
                "flow_id": f"sim-{normalized.lower()}-{uuid.uuid4().hex[:8]}",
                "src_ip": str(row["src_ip"]),
                "dst_ip": str(row["dst_ip"]),
                "src_port": int(row["src_port"]),
                "dst_port": int(row["dst_port"]),
                "protocol": str(row["protocol"]),
                "sni": sni,
                "features": features,
            }
        )
    return flows
