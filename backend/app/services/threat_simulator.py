"""Real-time passive flow simulator aligned with processed real/lab dataset."""

from __future__ import annotations

import uuid
from functools import lru_cache
from typing import Any

import numpy as np
import pandas as pd

from app.core.config import (
    FEATURE_COLUMNS,
    LABEL_CLASSES,
    PROCESSED_DATASET_PATH,
    TARGET_CLASS_COL,
)
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

DISCRETE_FEATURES = {"tls_version_num", "cipher_suite_count", "sni_length", "redirect_count"}


@lru_cache(maxsize=1)
def _load_processed_dataset_cached(mtime: float) -> pd.DataFrame:
    _ = mtime
    return pd.read_csv(PROCESSED_DATASET_PATH)


def generate_simulated_flows(
    scenario: str,
    count: int = 5,
    seed: int | None = None,
) -> list[dict[str, Any]]:
    """Generate realistic passive metadata flows sampled from real/lab distributions."""
    normalized = scenario.strip().upper()
    if normalized not in LABEL_CLASSES:
        raise ValueError(
            f"Invalid scenario '{scenario}'. Must be one of {LABEL_CLASSES}"
        )

    rng = np.random.default_rng(seed)
    block: pd.DataFrame | None = None

    if PROCESSED_DATASET_PATH.exists():
        df = _load_processed_dataset_cached(PROCESSED_DATASET_PATH.stat().st_mtime)
        subset = df[df[TARGET_CLASS_COL] == normalized]
        if not subset.empty:
            replace = len(subset) < count
            chosen_idx = rng.choice(len(subset), size=count, replace=replace)
            block = subset.iloc[chosen_idx].reset_index(drop=True)

    if block is None:
        block = _build_class_block(rng, normalized, count)

    sni_pool = SCENARIO_SNIS[normalized]
    flows: list[dict[str, Any]] = []
    for idx in range(len(block)):
        row = block.iloc[idx]
        sni = str(rng.choice(sni_pool))
        features: dict[str, float] = {}
        for col in FEATURE_COLUMNS:
            val = float(row[col])
            if col not in DISCRETE_FEATURES and col != "byte_asymmetry_ratio" and val > 0:
                val = round(val * float(rng.uniform(0.98, 1.02)), 4)
            features[col] = val

        features["byte_asymmetry_ratio"] = round(
            (features["bytes_sent"] - features["bytes_recv"])
            / (features["bytes_sent"] + features["bytes_recv"] + 1.0),
            4,
        )

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
