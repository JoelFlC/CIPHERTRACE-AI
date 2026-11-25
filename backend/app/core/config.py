"""Central configuration, standard passive feature schema, and artifact paths."""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

# Directory paths
CORE_DIR = Path(__file__).resolve().parent
APP_DIR = CORE_DIR.parent
BACKEND_DIR = APP_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent

DATA_DIR = BACKEND_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
PROCESSED_DATASET_PATH = PROCESSED_DATA_DIR / "ciphertrace_dataset.csv"

ARTIFACTS_DIR = BACKEND_DIR / "artifacts"
SCALER_PATH = ARTIFACTS_DIR / "scaler.joblib"
RF_MODEL_PATH = ARTIFACTS_DIR / "rf_model.joblib"
MLP_MODEL_PATH = ARTIFACTS_DIR / "mlp_model.joblib"
IFOREST_MODEL_PATH = ARTIFACTS_DIR / "iforest_model.joblib"
AUTOENCODER_PATH = ARTIFACTS_DIR / "autoencoder.pt"
GA_CONFIG_PATH = ARTIFACTS_DIR / "ga_config.json"
MODEL_METRICS_PATH = ARTIFACTS_DIR / "model_metrics.json"

RANDOM_SEED = 42

# 18 standard passive metadata features observable without payload decryption
FEATURE_COLUMNS: list[str] = [
    "duration_ms",
    "bytes_sent",
    "bytes_recv",
    "byte_asymmetry_ratio",
    "packets_sent",
    "packets_recv",
    "iat_mean_ms",
    "iat_std_ms",
    "pkt_size_mean",
    "pkt_size_std",
    "pkt_size_max",
    "tls_version_num",
    "cipher_suite_count",
    "sni_entropy",
    "sni_length",
    "dns_query_rate",
    "double_hop_latency_ms",
    "redirect_count",
]

METADATA_COLUMNS: list[str] = [
    "flow_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
]

LABEL_CLASSES: list[str] = [
    "BENIGN",
    "C2_BEACONING",
    "DOH_TUNNEL",
    "EXFILTRATION",
    "PHISHING_AITM",
]

LABEL_TO_ID: dict[str, int] = {label: idx for idx, label in enumerate(LABEL_CLASSES)}
ID_TO_LABEL: dict[int, str] = {idx: label for idx, label in enumerate(LABEL_CLASSES)}

TARGET_CLASS_COL = "label_type"
TARGET_BINARY_COL = "is_malicious"


def ensure_directories() -> None:
    """Create required data and artifact directories if they do not exist."""
    for directory in (RAW_DATA_DIR, PROCESSED_DATA_DIR, ARTIFACTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def shannon_entropy(text: str) -> float:
    """Compute Shannon entropy in bits per character for an SNI/domain string."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return float(
        -sum((count / length) * math.log2(count / length) for count in counts.values())
    )
