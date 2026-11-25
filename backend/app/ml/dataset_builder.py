"""Dataset loader (CIC-IDS2017 / CTU-13 / DoHBrw-2020) and realistic synthetic traffic generator."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from app.core.config import (
    FEATURE_COLUMNS,
    LABEL_CLASSES,
    METADATA_COLUMNS,
    PROCESSED_DATASET_PATH,
    RANDOM_SEED,
    RAW_DATA_DIR,
    TARGET_BINARY_COL,
    TARGET_CLASS_COL,
    ensure_directories,
    shannon_entropy,
)

# Column aliases across CIC-IDS2017, CTU-13, and DoHBrw-2020 exports
EXTERNAL_COLUMN_ALIASES: dict[str, list[str]] = {
    "duration_ms": ["duration_ms", "Flow Duration", "Duration", "Dur", "duration"],
    "bytes_sent": [
        "bytes_sent",
        "Total Length of Fwd Packets",
        "FlowBytesSent",
        "SrcBytes",
        "fwd_bytes",
    ],
    "bytes_recv": [
        "bytes_recv",
        "Total Length of Bwd Packets",
        "FlowBytesReceived",
        "DstBytes",
        "bwd_bytes",
    ],
    "packets_sent": [
        "packets_sent",
        "Total Fwd Packets",
        "FlowPacketsSent",
        "SrcPkts",
    ],
    "packets_recv": [
        "packets_recv",
        "Total Backward Packets",
        "FlowPacketsReceived",
        "DstPkts",
    ],
    "iat_mean_ms": ["iat_mean_ms", "Flow IAT Mean", "PacketTimeMean", "iat_mean"],
    "iat_std_ms": [
        "iat_std_ms",
        "Flow IAT Std",
        "PacketTimeStandardDeviation",
        "iat_std",
    ],
    "pkt_size_mean": [
        "pkt_size_mean",
        "Average Packet Size",
        "PacketLengthMean",
        "pkt_len_mean",
    ],
    "pkt_size_std": [
        "pkt_size_std",
        "Packet Length Std",
        "PacketLengthStandardDeviation",
        "pkt_len_std",
    ],
    "pkt_size_max": ["pkt_size_max", "Max Packet Length", "PacketLengthMax"],
    "tls_version_num": ["tls_version_num", "tls_version"],
    "cipher_suite_count": ["cipher_suite_count", "cipher_suites"],
    "sni_entropy": ["sni_entropy", "domain_entropy"],
    "sni_length": ["sni_length", "domain_length"],
    "dns_query_rate": ["dns_query_rate", "DoHQueryRate", "PacketRate"],
    "double_hop_latency_ms": ["double_hop_latency_ms", "ResponseTimeTimeMean"],
    "redirect_count": ["redirect_count"],
}

LABEL_COLUMN_CANDIDATES = ["label_type", "Label", "label", "Attack", "Class", "TrafficType"]


def _normalize_label(raw_label: Any) -> str:
    text = str(raw_label).strip().upper()
    if text in LABEL_CLASSES:
        return text
    if any(tok in text for tok in ("BENIGN", "NORMAL", "NONDOH", "NON-DOH")):
        return "BENIGN"
    if any(tok in text for tok in ("BEACON", "BOTNET", "C2", "COMMAND")):
        return "C2_BEACONING"
    if any(tok in text for tok in ("DOH", "DNS", "TUNNEL")):
        return "DOH_TUNNEL"
    if any(tok in text for tok in ("EXFIL", "DATA_THEFT", "UPLOAD")):
        return "EXFILTRATION"
    if any(tok in text for tok in ("PHISH", "AITM", "PROXY", "MITM")):
        return "PHISHING_AITM"
    return "C2_BEACONING"


def _find_first_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    lower_map = {col.strip().lower(): col for col in df.columns}
    for cand in candidates:
        if cand in df.columns:
            return cand
        matched = lower_map.get(cand.strip().lower())
        if matched is not None:
            return matched
    return None


def _map_external_dataframe(df: pd.DataFrame, source_idx: int) -> pd.DataFrame:
    """Normalize an external CIC-IDS2017 / CTU-13 / DoHBrw-2020 DataFrame."""
    n = len(df)
    out = pd.DataFrame(index=df.index)

    for col in FEATURE_COLUMNS:
        if col == "byte_asymmetry_ratio":
            continue
        matched = _find_first_column(df, EXTERNAL_COLUMN_ALIASES.get(col, [col]))
        if matched is not None:
            series = pd.to_numeric(df[matched], errors="coerce").fillna(0.0)
            # CIC-IDS2017 reports Flow Duration and IAT in microseconds
            if matched in ("Flow Duration", "Flow IAT Mean", "Flow IAT Std"):
                series = series / 1000.0
            elif matched == "Dur":
                series = series * 1000.0
            out[col] = series.astype(float)
        else:
            if col == "tls_version_num":
                out[col] = 1.2
            elif col == "cipher_suite_count":
                out[col] = 12.0
            else:
                out[col] = 0.0

    # Handle CTU-13 TotBytes / TotPkts when DstBytes or bwd packets are missing
    if "bytes_recv" in out and (out["bytes_recv"] == 0).all():
        tot_bytes_col = _find_first_column(df, ["TotBytes"])
        if tot_bytes_col is not None:
            tot_bytes = pd.to_numeric(df[tot_bytes_col], errors="coerce").fillna(0.0)
            out["bytes_recv"] = np.maximum(0.0, tot_bytes - out["bytes_sent"])

    out["byte_asymmetry_ratio"] = (
        (out["bytes_sent"] - out["bytes_recv"])
        / (out["bytes_sent"] + out["bytes_recv"] + 1.0)
    )

    label_col = _find_first_column(df, LABEL_COLUMN_CANDIDATES)
    if label_col is not None:
        labels = df[label_col].map(_normalize_label)
    else:
        labels = pd.Series(["BENIGN"] * n, index=df.index)

    out[TARGET_CLASS_COL] = labels
    out[TARGET_BINARY_COL] = (out[TARGET_CLASS_COL] != "BENIGN").astype(int)

    # Metadata columns
    out["flow_id"] = [f"ext-{source_idx}-{i:06d}" for i in range(n)]
    out["src_ip"] = (
        df[_find_first_column(df, ["src_ip", "SrcAddr", "Source IP"]) or ""]
        if _find_first_column(df, ["src_ip", "SrcAddr", "Source IP"])
        else "10.0.0.10"
    )
    out["dst_ip"] = (
        df[_find_first_column(df, ["dst_ip", "DstAddr", "Destination IP"]) or ""]
        if _find_first_column(df, ["dst_ip", "DstAddr", "Destination IP"])
        else "198.51.100.10"
    )
    src_port_col = _find_first_column(df, ["src_port", "Sport", "Source Port"])
    dst_port_col = _find_first_column(df, ["dst_port", "Dport", "Destination Port"])
    proto_col = _find_first_column(df, ["protocol", "Proto", "Protocol"])

    out["src_port"] = (
        pd.to_numeric(df[src_port_col], errors="coerce").fillna(50000).astype(int)
        if src_port_col
        else 50000
    )
    out["dst_port"] = (
        pd.to_numeric(df[dst_port_col], errors="coerce").fillna(443).astype(int)
        if dst_port_col
        else 443
    )
    out["protocol"] = df[proto_col].astype(str) if proto_col else "TCP"

    out = out.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    ordered_cols = METADATA_COLUMNS + FEATURE_COLUMNS + [TARGET_CLASS_COL, TARGET_BINARY_COL]
    return out[ordered_cols]


def load_external_csvs(raw_dir: Path = RAW_DATA_DIR) -> pd.DataFrame | None:
    """Load and standardize any CSV files present in data/raw/."""
    csv_files = sorted(raw_dir.glob("*.csv"))
    if not csv_files:
        return None

    frames = []
    for idx, csv_path in enumerate(csv_files):
        raw_df = pd.read_csv(csv_path, low_memory=False)
        if not raw_df.empty:
            frames.append(_map_external_dataframe(raw_df, idx))

    if not frames:
        return None

    combined = pd.concat(frames, ignore_index=True)
    return combined


def _generate_random_sni_strings(
    rng: np.random.Generator,
    count: int,
    high_entropy: bool = False,
    medium_entropy: bool = False,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate realistic SNI strings and compute exact Shannon entropy and length."""
    benign_domains = [
        "api.github.com",
        "cdn.cloudflare.com",
        "fonts.googleapis.com",
        "login.microsoftonline.com",
        "s3.amazonaws.com",
        "slack.com",
        "pypi.org",
        "outlook.office365.com",
        "dns.google",
        "mozilla.cloudflare-dns.com",
        "registry.npmjs.org",
        "update.googleapis.com",
    ]
    phish_templates = [
        "login-verify-session",
        "secure-oauth-portal",
        "sso-account-check",
        "auth-token-gateway",
        "mfa-confirm-device",
    ]
    alphabet = np.array(list("abcdefghijklmnopqrstuvwxyz0123456789"))

    entropies = np.empty(count, dtype=float)
    lengths = np.empty(count, dtype=float)

    for i in range(count):
        if high_entropy:
            # Base32/hex-like encoded DNS/DoH tunnel subdomain
            sub_len = int(rng.integers(24, 62))
            label = "".join(rng.choice(alphabet, size=sub_len))
            domain = f"{label}.doh-relay.net"
        elif medium_entropy:
            prefix = rng.choice(phish_templates)
            suffix = "".join(rng.choice(alphabet, size=int(rng.integers(6, 16))))
            domain = f"{prefix}-{suffix}.cloud-auth.site"
        else:
            base = str(rng.choice(benign_domains))
            if rng.random() < 0.25:
                sub = "".join(rng.choice(alphabet[:26], size=int(rng.integers(3, 7))))
                domain = f"{sub}.{base}"
            else:
                domain = base

        entropies[i] = round(shannon_entropy(domain), 4)
        lengths[i] = float(len(domain))

    return entropies, lengths


def _build_class_block(
    rng: np.random.Generator,
    label: str,
    n: int,
) -> pd.DataFrame:
    """Create a statistically coherent block of passive metadata flows for one class."""
    data: dict[str, np.ndarray] = {}

    if label == "BENIGN":
        # 94% standard TLS/HTTPS/DoH traffic + 6% realistic edge cases (cloud upload, VPN)
        is_edge = rng.random(n) < 0.06
        data["duration_ms"] = np.where(
            is_edge,
            rng.uniform(12_000.0, 95_000.0, n),
            rng.lognormal(mean=7.7, sigma=0.95, size=n).clip(120.0, 45_000.0),
        )
        data["bytes_sent"] = np.where(
            is_edge,
            rng.uniform(45_000.0, 320_000.0, n),
            rng.lognormal(mean=8.1, sigma=0.8, size=n).clip(400.0, 28_000.0),
        )
        data["bytes_recv"] = np.where(
            is_edge,
            rng.uniform(18_000.0, 140_000.0, n),
            rng.lognormal(mean=9.8, sigma=1.0, size=n).clip(1_500.0, 350_000.0),
        )
        data["packets_sent"] = np.clip(
            np.round(data["bytes_sent"] / rng.uniform(220.0, 650.0, n)), 3, 900
        )
        data["packets_recv"] = np.clip(
            np.round(data["bytes_recv"] / rng.uniform(550.0, 1_150.0, n)), 3, 1_400
        )
        data["iat_mean_ms"] = rng.uniform(12.0, 320.0, n)
        data["iat_std_ms"] = np.where(
            is_edge,
            rng.uniform(14.0, 55.0, n),
            rng.uniform(32.0, 420.0, n),
        )
        data["pkt_size_mean"] = rng.uniform(280.0, 980.0, n)
        data["pkt_size_std"] = rng.uniform(110.0, 440.0, n)
        data["pkt_size_max"] = np.clip(
            data["pkt_size_mean"] + rng.uniform(220.0, 620.0, n), 480.0, 1_500.0
        )
        data["tls_version_num"] = rng.choice([1.2, 1.3], size=n, p=[0.35, 0.65])
        data["cipher_suite_count"] = rng.integers(10, 26, size=n).astype(float)
        sni_ent, sni_len = _generate_random_sni_strings(rng, n)
        data["sni_entropy"] = sni_ent
        data["sni_length"] = sni_len
        data["dns_query_rate"] = np.where(
            rng.random(n) < 0.12,
            rng.uniform(0.5, 4.2, n),
            rng.uniform(0.0, 1.2, n),
        )
        data["double_hop_latency_ms"] = np.where(
            is_edge,
            rng.uniform(85.0, 195.0, n),
            rng.uniform(10.0, 75.0, n),
        )
        data["redirect_count"] = rng.choice([0, 1, 2], size=n, p=[0.65, 0.27, 0.08]).astype(float)
        dst_ports = rng.choice([443, 8443], size=n, p=[0.95, 0.05])

    elif label == "C2_BEACONING":
        # Long-lived periodic callbacks with ultra-low IAT jitter and small uniform payloads
        data["duration_ms"] = rng.uniform(45_000.0, 320_000.0, n)
        data["bytes_sent"] = rng.uniform(1_800.0, 14_000.0, n)
        data["bytes_recv"] = rng.uniform(1_500.0, 16_000.0, n)
        data["packets_sent"] = rng.integers(18, 95, size=n).astype(float)
        data["packets_recv"] = rng.integers(16, 90, size=n).astype(float)
        data["iat_mean_ms"] = rng.uniform(800.0, 5_000.0, n)
        data["iat_std_ms"] = rng.uniform(0.5, 19.0, n)
        data["pkt_size_mean"] = rng.uniform(85.0, 265.0, n)
        data["pkt_size_std"] = rng.uniform(6.0, 48.0, n)
        data["pkt_size_max"] = np.clip(
            data["pkt_size_mean"] + rng.uniform(25.0, 110.0, n), 120.0, 420.0
        )
        data["tls_version_num"] = rng.choice([1.2, 1.3], size=n, p=[0.72, 0.28])
        data["cipher_suite_count"] = rng.integers(4, 12, size=n).astype(float)
        sni_ent, sni_len = _generate_random_sni_strings(rng, n, medium_entropy=True)
        data["sni_entropy"] = np.clip(sni_ent + rng.uniform(-0.3, 0.2, n), 2.7, 4.1)
        data["sni_length"] = sni_len
        data["dns_query_rate"] = rng.uniform(0.0, 1.8, n)
        data["double_hop_latency_ms"] = rng.uniform(25.0, 115.0, n)
        data["redirect_count"] = rng.choice([0, 1], size=n, p=[0.85, 0.15]).astype(float)
        dst_ports = rng.choice([443, 8443, 8080], size=n, p=[0.75, 0.15, 0.10])

    elif label == "DOH_TUNNEL":
        # High-entropy encoded subdomains and high DNS-over-HTTPS query rates
        data["duration_ms"] = rng.uniform(8_000.0, 95_000.0, n)
        data["bytes_sent"] = rng.uniform(12_000.0, 110_000.0, n)
        data["bytes_recv"] = rng.uniform(14_000.0, 130_000.0, n)
        data["packets_sent"] = rng.integers(55, 340, size=n).astype(float)
        data["packets_recv"] = rng.integers(55, 340, size=n).astype(float)
        data["iat_mean_ms"] = rng.uniform(25.0, 180.0, n)
        data["iat_std_ms"] = rng.uniform(12.0, 85.0, n)
        data["pkt_size_mean"] = rng.uniform(175.0, 430.0, n)
        data["pkt_size_std"] = rng.uniform(22.0, 95.0, n)
        data["pkt_size_max"] = np.clip(
            data["pkt_size_mean"] + rng.uniform(90.0, 260.0, n), 280.0, 780.0
        )
        data["tls_version_num"] = rng.choice([1.2, 1.3], size=n, p=[0.25, 0.75])
        data["cipher_suite_count"] = rng.integers(9, 19, size=n).astype(float)
        sni_ent, sni_len = _generate_random_sni_strings(rng, n, high_entropy=True)
        data["sni_entropy"] = sni_ent
        data["sni_length"] = sni_len
        data["dns_query_rate"] = rng.uniform(6.5, 38.0, n)
        data["double_hop_latency_ms"] = rng.uniform(18.0, 90.0, n)
        data["redirect_count"] = rng.choice([0, 1], size=n, p=[0.90, 0.10]).astype(float)
        dst_ports = np.full(n, 443)

    elif label == "EXFILTRATION":
        # Massive outbound upload with minimal server response -> high positive byte asymmetry
        data["duration_ms"] = rng.uniform(4_000.0, 85_000.0, n)
        data["bytes_sent"] = rng.uniform(140_000.0, 2_400_000.0, n)
        data["bytes_recv"] = rng.uniform(1_800.0, 32_000.0, n)
        data["packets_sent"] = np.clip(
            np.round(data["bytes_sent"] / rng.uniform(1_050.0, 1_420.0, n)), 95, 2_400
        )
        data["packets_recv"] = rng.integers(14, 95, size=n).astype(float)
        data["iat_mean_ms"] = rng.uniform(8.0, 95.0, n)
        data["iat_std_ms"] = rng.uniform(15.0, 125.0, n)
        data["pkt_size_mean"] = rng.uniform(1_020.0, 1_410.0, n)
        data["pkt_size_std"] = rng.uniform(65.0, 240.0, n)
        data["pkt_size_max"] = rng.uniform(1_380.0, 1_500.0, n)
        data["tls_version_num"] = rng.choice([1.2, 1.3], size=n, p=[0.45, 0.55])
        data["cipher_suite_count"] = rng.integers(8, 18, size=n).astype(float)
        sni_ent, sni_len = _generate_random_sni_strings(rng, n)
        data["sni_entropy"] = np.clip(sni_ent + rng.uniform(0.1, 0.6, n), 2.6, 4.1)
        data["sni_length"] = sni_len
        data["dns_query_rate"] = rng.uniform(0.0, 1.5, n)
        data["double_hop_latency_ms"] = rng.uniform(20.0, 110.0, n)
        data["redirect_count"] = rng.choice([0, 1], size=n, p=[0.8, 0.2]).astype(float)
        dst_ports = np.full(n, 443)

    else:  # PHISHING_AITM
        # Reverse-proxy double-hop latency, multi-step credential redirects, lookalike SNI
        data["duration_ms"] = rng.uniform(3_500.0, 48_000.0, n)
        data["bytes_sent"] = rng.uniform(4_500.0, 38_000.0, n)
        data["bytes_recv"] = rng.uniform(18_000.0, 165_000.0, n)
        data["packets_sent"] = rng.integers(14, 90, size=n).astype(float)
        data["packets_recv"] = rng.integers(22, 160, size=n).astype(float)
        data["iat_mean_ms"] = rng.uniform(65.0, 480.0, n)
        data["iat_std_ms"] = rng.uniform(45.0, 290.0, n)
        data["pkt_size_mean"] = rng.uniform(340.0, 860.0, n)
        data["pkt_size_std"] = rng.uniform(140.0, 420.0, n)
        data["pkt_size_max"] = rng.uniform(900.0, 1_480.0, n)
        data["tls_version_num"] = rng.choice([1.2, 1.3], size=n, p=[0.55, 0.45])
        data["cipher_suite_count"] = rng.integers(8, 17, size=n).astype(float)
        sni_ent, sni_len = _generate_random_sni_strings(rng, n, medium_entropy=True)
        data["sni_entropy"] = sni_ent
        data["sni_length"] = sni_len
        data["dns_query_rate"] = rng.uniform(0.2, 3.2, n)
        data["double_hop_latency_ms"] = rng.uniform(185.0, 620.0, n)
        data["redirect_count"] = rng.integers(3, 10, size=n).astype(float)
        dst_ports = rng.choice([443, 8443], size=n, p=[0.90, 0.10])

    # Derived ratio directly from sent/recv byte counts
    data["byte_asymmetry_ratio"] = (
        (data["bytes_sent"] - data["bytes_recv"])
        / (data["bytes_sent"] + data["bytes_recv"] + 1.0)
    )

    frame = pd.DataFrame({col: np.round(data[col], 4) for col in FEATURE_COLUMNS})
    frame[TARGET_CLASS_COL] = label
    frame[TARGET_BINARY_COL] = 0 if label == "BENIGN" else 1

    # Realistic passive metadata columns
    src_last_octet = rng.integers(10, 240, size=n)
    dst_pool = (
        ["142.250.74.14", "104.16.132.229", "13.107.42.14", "1.1.1.1", "8.8.8.8"]
        if label == "BENIGN"
        else ["185.220.101.45", "91.214.124.78", "45.142.212.61", "194.26.135.120"]
    )
    frame["src_ip"] = [f"192.168.10.{o}" for o in src_last_octet]
    frame["dst_ip"] = rng.choice(dst_pool, size=n)
    frame["src_port"] = rng.integers(32768, 61000, size=n)
    frame["dst_port"] = dst_ports
    frame["protocol"] = "TCP"
    frame["flow_id"] = ""

    return frame


def generate_synthetic_dataset(
    n_samples: int = 6000,
    seed: int = RANDOM_SEED,
) -> pd.DataFrame:
    """Generate a balanced, statistically coherent synthetic dataset of passive encrypted flows."""
    rng = np.random.default_rng(seed)

    # 50% BENIGN, 50% malicious balanced equally across the 4 attack families
    n_benign = n_samples // 2
    n_per_attack = (n_samples - n_benign) // 4
    remainder = (n_samples - n_benign) - (n_per_attack * 4)

    class_counts = {
        "BENIGN": n_benign,
        "C2_BEACONING": n_per_attack + (1 if remainder > 0 else 0),
        "DOH_TUNNEL": n_per_attack + (1 if remainder > 1 else 0),
        "EXFILTRATION": n_per_attack + (1 if remainder > 2 else 0),
        "PHISHING_AITM": n_per_attack,
    }

    blocks = [
        _build_class_block(rng, label, count)
        for label, count in class_counts.items()
    ]
    dataset = pd.concat(blocks, ignore_index=True)
    dataset = dataset.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    dataset["flow_id"] = [f"flow-{i:06d}" for i in range(len(dataset))]

    ordered_cols = METADATA_COLUMNS + FEATURE_COLUMNS + [TARGET_CLASS_COL, TARGET_BINARY_COL]
    return dataset[ordered_cols]


def build_or_load_dataset(
    force_rebuild: bool = False,
    n_samples: int = 6000,
    seed: int = RANDOM_SEED,
    save_path: Path = PROCESSED_DATASET_PATH,
) -> pd.DataFrame:
    """Load external CSVs from data/raw/ if available, else generate synthetic dataset."""
    ensure_directories()

    external = load_external_csvs(RAW_DATA_DIR)
    if external is not None:
        external.to_csv(save_path, index=False)
        return external

    if not force_rebuild and save_path.exists():
        return pd.read_csv(save_path)

    synthetic = generate_synthetic_dataset(n_samples=n_samples, seed=seed)
    synthetic.to_csv(save_path, index=False)
    return synthetic
