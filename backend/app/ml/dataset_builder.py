"""Dataset loader (CIC-IDS2017 / CTU-13 / DoHBrw-2020) and controlled lab fallback generator."""

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

MAX_TOTAL_TRAINING_ROWS = 20_000
CSV_CHUNK_SIZE = 100_000

# Column aliases across CIC-IDS2017, CTU-13 (CSV/Parquet), and DoHBrw-2020 exports
EXTERNAL_COLUMN_ALIASES: dict[str, list[str]] = {
    "duration_ms": ["duration_ms", "Flow Duration", "Duration", "Dur", "dur", "duration"],
    "bytes_sent": [
        "bytes_sent",
        "Total Length of Fwd Packets",
        "FlowBytesSent",
        "SrcBytes",
        "src_bytes",
        "fwd_bytes",
    ],
    "bytes_recv": [
        "bytes_recv",
        "Total Length of Bwd Packets",
        "FlowBytesReceived",
        "DstBytes",
        "dst_bytes",
        "bwd_bytes",
    ],
    "packets_sent": [
        "packets_sent",
        "Total Fwd Packets",
        "FlowPacketsSent",
        "SrcPkts",
        "src_pkts",
    ],
    "packets_recv": [
        "packets_recv",
        "Total Backward Packets",
        "FlowPacketsReceived",
        "DstPkts",
        "dst_pkts",
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
        "Packet Length Mean",
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

LABEL_COLUMN_CANDIDATES = [
    "label_type",
    "Attack Type",
    "Label",
    "label",
    "Attack",
    "Class",
    "TrafficType",
]


def _normalize_label(raw_label: Any, source_name: str = "") -> str:
    text = str(raw_label).strip().upper()
    if text in LABEL_CLASSES:
        return text

    src_lower = source_name.lower()

    # Dataset-specific mappings for DoHBrw-2020, CIC-IDS2017, and CTU-13
    if "doh" in src_lower:
        if "BENIGN" in text or "NONDOH" in text or "NON-DOH" in text:
            return "BENIGN"
        return "DOH_TUNNEL"

    if "virut" in src_lower or "binetflow" in src_lower or "ctu" in src_lower:
        if "BOTNET" in text:
            return "C2_BEACONING"
        if "NORMAL" in text or "BENIGN" in text:
            return "BENIGN"
        if "BACKGROUND" in text:
            return "BACKGROUND"
        return "C2_BEACONING"

    if "cicids" in src_lower:
        if "NORMAL" in text or "BENIGN" in text:
            return "BENIGN"
        if "BOT" in text:
            return "C2_BEACONING"
        if any(tok in text for tok in ("WEB ATTACK", "BRUTE FORCE", "INFILTRATION", "EXFIL")):
            return "EXFILTRATION"
        if any(tok in text for tok in ("PORT SCAN", "DOS", "DDOS")):
            return "EXFILTRATION"
        return "C2_BEACONING"

    # Generic fallback for uploaded CSVs
    if any(tok in text for tok in ("BENIGN", "NORMAL", "NONDOH", "NON-DOH")):
        return "BENIGN"
    if any(tok in text for tok in ("BEACON", "BOTNET", "BOT", "C2", "COMMAND")):
        return "C2_BEACONING"
    if any(tok in text for tok in ("DOH", "DNS", "TUNNEL")):
        return "DOH_TUNNEL"
    if any(tok in text for tok in ("EXFIL", "DATA_THEFT", "UPLOAD", "WEB ATTACK", "BRUTE")):
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


def _map_external_dataframe(
    df: pd.DataFrame,
    source_idx: int,
    source_name: str = "",
) -> pd.DataFrame:
    """Normalize an external CIC-IDS2017 / CTU-13 / DoHBrw-2020 DataFrame."""
    n = len(df)
    out = pd.DataFrame(index=df.index)
    src_lower = source_name.lower()

    for col in FEATURE_COLUMNS:
        if col == "byte_asymmetry_ratio":
            continue
        matched = _find_first_column(df, EXTERNAL_COLUMN_ALIASES.get(col, [col]))
        if matched is not None:
            series = pd.to_numeric(df[matched], errors="coerce").fillna(0.0)
            # Unit normalization: CIC-IDS2017 uses microseconds; DoHBrw & CTU-13 use seconds
            if matched in ("Flow Duration", "Flow IAT Mean", "Flow IAT Std"):
                series = series / 1000.0
            elif matched in (
                "Dur",
                "dur",
                "PacketTimeMean",
                "PacketTimeStandardDeviation",
                "ResponseTimeTimeMean",
            ):
                series = series * 1000.0
            out[col] = series.astype(float)
        else:
            if col == "tls_version_num":
                out[col] = 1.2
            elif col == "cipher_suite_count":
                out[col] = 12.0
            else:
                out[col] = 0.0

    # Derive duration_ms when missing (e.g., BCCC-CIRA-CIC-DoHBrw-2020)
    if (out["duration_ms"] == 0).all():
        sent_rate_col = _find_first_column(df, ["FlowSentRate"])
        recv_rate_col = _find_first_column(df, ["FlowReceivedRate"])
        if sent_rate_col is not None or recv_rate_col is not None:
            s_rate = (
                pd.to_numeric(df[sent_rate_col], errors="coerce").fillna(0.0)
                if sent_rate_col
                else pd.Series(0.0, index=df.index)
            )
            r_rate = (
                pd.to_numeric(df[recv_rate_col], errors="coerce").fillna(0.0)
                if recv_rate_col
                else pd.Series(0.0, index=df.index)
            )
            dur_s = np.where(s_rate > 0, out["bytes_sent"] / np.maximum(s_rate, 1e-6), 0.0)
            dur_r = np.where(r_rate > 0, out["bytes_recv"] / np.maximum(r_rate, 1e-6), 0.0)
            out["duration_ms"] = np.clip(np.maximum(dur_s, dur_r) * 1000.0, 0.0, 600_000.0)

    # Derive bytes_recv from CTU-13 TotBytes/tot_bytes OR CIC-IDS2017 Flow Bytes/s
    tot_bytes_col = _find_first_column(df, ["TotBytes", "tot_bytes"])
    if (out["bytes_recv"] == 0).all():
        if tot_bytes_col is not None:
            tot_bytes = pd.to_numeric(df[tot_bytes_col], errors="coerce").fillna(0.0)
            out["bytes_recv"] = np.maximum(0.0, tot_bytes - out["bytes_sent"])
        else:
            flow_bps_col = _find_first_column(df, ["Flow Bytes/s"])
            if flow_bps_col is not None:
                flow_bps = pd.to_numeric(df[flow_bps_col], errors="coerce").fillna(0.0)
                est_total_bytes = np.maximum(0.0, flow_bps * (out["duration_ms"] / 1000.0))
                out["bytes_recv"] = np.maximum(0.0, est_total_bytes - out["bytes_sent"])

    # Derive packet counts when missing (CTU-13 tot_pkts, DoHBrw-2020, or CIC-IDS2017 Flow Packets/s)
    tot_pkts_col = _find_first_column(df, ["TotPkts", "tot_pkts"])
    if (out["packets_sent"] == 0).all() and (out["packets_recv"] == 0).all():
        if tot_pkts_col is not None:
            tot_pkts = np.maximum(
                1.0, pd.to_numeric(df[tot_pkts_col], errors="coerce").fillna(1.0)
            )
            total_b = np.maximum(out["bytes_sent"] + out["bytes_recv"], 1.0)
            sent_ratio = np.clip(out["bytes_sent"] / total_b, 0.05, 0.95)
            out["packets_sent"] = np.maximum(1.0, np.round(tot_pkts * sent_ratio))
            out["packets_recv"] = np.maximum(0.0, tot_pkts - out["packets_sent"])
        else:
            mean_sz = np.maximum(out["pkt_size_mean"], 40.0)
            out["packets_sent"] = np.maximum(1.0, np.round(out["bytes_sent"] / mean_sz))
            out["packets_recv"] = np.maximum(0.0, np.round(out["bytes_recv"] / mean_sz))
    elif (out["packets_recv"] == 0).all():
        flow_pps_col = _find_first_column(df, ["Flow Packets/s"])
        if flow_pps_col is not None:
            flow_pps = pd.to_numeric(df[flow_pps_col], errors="coerce").fillna(0.0)
            est_total_pkts = np.maximum(0.0, flow_pps * (out["duration_ms"] / 1000.0))
            out["packets_recv"] = np.maximum(0.0, np.round(est_total_pkts - out["packets_sent"]))

    # Derive pkt_size_mean / pkt_size_max / iat_mean_ms when missing (e.g., CTU-13 or DoHBrw)
    if (out["pkt_size_mean"] == 0).all():
        total_pkts = np.maximum(out["packets_sent"] + out["packets_recv"], 1.0)
        out["pkt_size_mean"] = (out["bytes_sent"] + out["bytes_recv"]) / total_pkts

    if (out["pkt_size_max"] == 0).all():
        out["pkt_size_max"] = np.clip(
            out["pkt_size_mean"] + 2.0 * out["pkt_size_std"], 60.0, 1500.0
        )

    if (out["iat_mean_ms"] == 0).all():
        total_pkts = np.maximum(out["packets_sent"] + out["packets_recv"] - 1.0, 1.0)
        out["iat_mean_ms"] = out["duration_ms"] / total_pkts

    if "doh" in src_lower and (out["dns_query_rate"] == 0).all():
        out["dns_query_rate"] = out["packets_sent"] / np.maximum(out["duration_ms"] / 1000.0, 1.0)

    out["byte_asymmetry_ratio"] = (
        (out["bytes_sent"] - out["bytes_recv"])
        / (out["bytes_sent"] + out["bytes_recv"] + 1.0)
    )

    label_col = _find_first_column(df, LABEL_COLUMN_CANDIDATES)
    if label_col is not None:
        labels = df[label_col].map(lambda val: _normalize_label(val, source_name))
    else:
        labels = pd.Series(["BENIGN"] * n, index=df.index)

    out[TARGET_CLASS_COL] = labels
    out[TARGET_BINARY_COL] = (out[TARGET_CLASS_COL] != "BENIGN").astype(int)

    # Metadata columns
    out["flow_id"] = [f"ext-{source_idx}-{i:06d}" for i in range(n)]
    src_ip_col = _find_first_column(df, ["src_ip", "SrcAddr", "Source IP"])
    dst_ip_col = _find_first_column(df, ["dst_ip", "DstAddr", "Destination IP"])
    out["src_ip"] = df[src_ip_col].astype(str) if src_ip_col else "10.0.0.10"
    out["dst_ip"] = df[dst_ip_col].astype(str) if dst_ip_col else "198.51.100.10"

    src_port_col = _find_first_column(df, ["src_port", "Sport", "Source Port"])
    dst_port_col = _find_first_column(
        df, ["dst_port", "Dport", "Destination Port"]
    )
    proto_col = _find_first_column(df, ["protocol", "Proto", "proto", "Protocol"])

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
    out["protocol"] = df[proto_col].astype(str).str.upper() if proto_col else "TCP"

    out = out.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    ordered_cols = METADATA_COLUMNS + FEATURE_COLUMNS + [TARGET_CLASS_COL, TARGET_BINARY_COL]
    return out[ordered_cols]


def _list_raw_dataset_files(raw_dir: Path) -> list[Path]:
    if not raw_dir.exists():
        return []
    return sorted(
        p
        for p in raw_dir.iterdir()
        if p.is_file() and p.suffix.lower() in (".csv", ".parquet")
    )


def _sample_from_raw_file(
    file_path: Path,
    source_idx: int,
    quotas: dict[str, int],
    seed: int,
) -> pd.DataFrame:
    """Stream CSV chunks (or read Parquet) and take bounded stratified samples per class."""
    suffix = file_path.suffix.lower()
    rng = np.random.default_rng(seed + source_idx)
    collected: dict[str, list[pd.DataFrame]] = {lbl: [] for lbl in quotas}
    collected_counts: dict[str, int] = {lbl: 0 for lbl in quotas}
    buffer_cap = 3  # keep up to 3x quota before final exact downsampling

    def _consume_chunk(raw_chunk: pd.DataFrame) -> bool:
        if raw_chunk.empty:
            return False

        # For CTU-13, keep only verified Normal / Botnet flows (skip Background noise)
        if any(tok in file_path.name.lower() for tok in ("virut", "binetflow", "ctu")):
            lbl_col = _find_first_column(raw_chunk, LABEL_COLUMN_CANDIDATES)
            if lbl_col is not None:
                lbl_str = raw_chunk[lbl_col].astype(str)
                keep_mask = lbl_str.str.contains("Botnet|Normal", case=False, regex=True)
                raw_chunk = raw_chunk[keep_mask]
                if raw_chunk.empty:
                    return False

        # For CIC-IDS2017, normalize labels before mapping to prioritize target classes efficiently
        lbl_col = _find_first_column(raw_chunk, LABEL_COLUMN_CANDIDATES)
        if lbl_col is not None:
            norm_labels = raw_chunk[lbl_col].map(
                lambda val: _normalize_label(val, file_path.name)
            )
        else:
            norm_labels = pd.Series(["BENIGN"] * len(raw_chunk), index=raw_chunk.index)

        # In CIC-IDS2017, prioritize real data-transferring flows (Web Attacks / Brute Force) for EXFILTRATION
        is_cicids = "cicids" in file_path.name.lower() and lbl_col is not None
        if is_cicids:
            raw_text = raw_chunk[lbl_col].astype(str).str.upper()
            fwd_col = _find_first_column(raw_chunk, ["Total Length of Fwd Packets"])
            dur_col = _find_first_column(raw_chunk, ["Flow Duration"])
            if fwd_col and dur_col:
                data_flow_mask = (
                    pd.to_numeric(raw_chunk[fwd_col], errors="coerce").fillna(0.0) >= 200.0
                ) & (
                    pd.to_numeric(raw_chunk[dur_col], errors="coerce").fillna(0.0) > 0.0
                )
            else:
                data_flow_mask = pd.Series(True, index=raw_chunk.index)

        selected_indices: list[pd.Index] = []
        for target_cls, q in quotas.items():
            if q <= 0 or collected_counts[target_cls] >= q * buffer_cap:
                continue
            cls_mask = norm_labels == target_cls
            if is_cicids and target_cls == "EXFILTRATION":
                preferred = cls_mask & data_flow_mask & raw_text.str.contains("WEB ATTACK|BRUTE FORCE")
                fallback_data = cls_mask & data_flow_mask
                if preferred.any():
                    cls_rows = raw_chunk[preferred]
                elif fallback_data.any():
                    cls_rows = raw_chunk[fallback_data]
                else:
                    cls_rows = raw_chunk[cls_mask]
            else:
                cls_rows = raw_chunk[cls_mask]

            if cls_rows.empty:
                continue

            take_n = min(len(cls_rows), q * buffer_cap - collected_counts[target_cls])
            if take_n < len(cls_rows):
                chosen_pos = rng.choice(len(cls_rows), size=take_n, replace=False)
                cls_rows = cls_rows.iloc[chosen_pos]

            selected_indices.append(cls_rows.index)
            collected_counts[target_cls] += len(cls_rows)

        if selected_indices:
            merged_idx = selected_indices[0]
            for extra_idx in selected_indices[1:]:
                merged_idx = merged_idx.union(extra_idx)
            mapped_chunk = _map_external_dataframe(
                raw_chunk.loc[merged_idx], source_idx=source_idx, source_name=file_path.name
            )
            for target_cls in quotas:
                sub = mapped_chunk[mapped_chunk[TARGET_CLASS_COL] == target_cls]
                if not sub.empty:
                    collected[target_cls].append(sub)

        return all(collected_counts[c] >= q * buffer_cap for c, q in quotas.items() if q > 0)

    if suffix == ".parquet":
        df_pq = pd.read_parquet(file_path)
        _consume_chunk(df_pq)
    else:
        for chunk in pd.read_csv(file_path, chunksize=CSV_CHUNK_SIZE, low_memory=False):
            done = _consume_chunk(chunk)
            if done:
                break

    sampled_parts: list[pd.DataFrame] = []
    for target_cls, q in quotas.items():
        if q <= 0 or not collected[target_cls]:
            continue
        cls_df = pd.concat(collected[target_cls], ignore_index=True)
        if len(cls_df) > q:
            cls_df = cls_df.sample(n=q, random_state=seed + source_idx)
        sampled_parts.append(cls_df)

    if not sampled_parts:
        return pd.DataFrame(
            columns=METADATA_COLUMNS + FEATURE_COLUMNS + [TARGET_CLASS_COL, TARGET_BINARY_COL]
        )

    return pd.concat(sampled_parts, ignore_index=True)


def load_external_csvs(
    raw_dir: Path = RAW_DATA_DIR,
    max_total_rows: int = MAX_TOTAL_TRAINING_ROWS,
    seed: int = RANDOM_SEED,
) -> pd.DataFrame | None:
    """Load and standardize public CSV/Parquet files in data/raw/ with bounded sampling."""
    files = _list_raw_dataset_files(raw_dir)
    if not files:
        return None

    per_file_cap = max(1000, max_total_rows // len(files))
    default_quotas = {
        "BENIGN": per_file_cap // 2,
        "C2_BEACONING": per_file_cap // 4,
        "DOH_TUNNEL": per_file_cap // 4,
        "EXFILTRATION": per_file_cap // 4,
    }
    frames = []
    for idx, fpath in enumerate(files):
        sampled = _sample_from_raw_file(fpath, idx, default_quotas, seed=seed)
        if not sampled.empty:
            frames.append(sampled)

    if not frames:
        return None
    return pd.concat(frames, ignore_index=True)


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


def _default_file_quotas(filename: str, max_total_rows: int) -> dict[str, int]:
    """Allocate balanced per-file quotas summing up to 20,000 rows (with margin for balancing)."""
    lower = filename.lower()
    scale = max_total_rows / float(MAX_TOTAL_TRAINING_ROWS)
    if "virut" in lower or "binetflow" in lower or "ctu" in lower:
        return {
            "BENIGN": int(round(3000 * scale)),
            "C2_BEACONING": int(round(1200 * scale)),
        }
    if "doh" in lower:
        return {
            "BENIGN": int(round(3500 * scale)),
            "DOH_TUNNEL": int(round(2500 * scale)),
        }
    if "cicids" in lower:
        return {
            "BENIGN": int(round(3500 * scale)),
            "C2_BEACONING": int(round(1620 * scale)),
            "EXFILTRATION": int(round(2500 * scale)),
        }
    # Generic CSV/Parquet file placed in raw/
    return {
        "BENIGN": int(round(3000 * scale)),
        "C2_BEACONING": int(round(1250 * scale)),
        "DOH_TUNNEL": int(round(1250 * scale)),
        "EXFILTRATION": int(round(1250 * scale)),
        "PHISHING_AITM": int(round(1250 * scale)),
    }


def build_or_load_dataset_with_metadata(
    force_rebuild: bool = False,
    n_samples: int = MAX_TOTAL_TRAINING_ROWS,
    seed: int = RANDOM_SEED,
    save_path: Path = PROCESSED_DATASET_PATH,
    raw_dir: Path = RAW_DATA_DIR,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Auto-ingest public CSV/Parquet datasets from data/raw/ with 20,000-row stratified cap."""
    ensure_directories()

    max_rows = min(int(n_samples), MAX_TOTAL_TRAINING_ROWS)
    raw_files = _list_raw_dataset_files(raw_dir)
    raw_filenames = [path.name for path in raw_files]

    if raw_files:
        rng = np.random.default_rng(seed)
        target_per_class = {
            "BENIGN": max_rows // 2,  # 10,000
            "C2_BEACONING": max_rows // 8,  # 2,500
            "DOH_TUNNEL": max_rows // 8,  # 2,500
            "EXFILTRATION": max_rows // 8,  # 2,500
            "PHISHING_AITM": max_rows - (max_rows // 2) - 3 * (max_rows // 8),  # 2,500
        }

        per_file_frames: list[tuple[str, pd.DataFrame]] = []
        for idx, file_path in enumerate(raw_files):
            quotas = _default_file_quotas(file_path.name, max_rows)
            sampled_df = _sample_from_raw_file(file_path, idx, quotas, seed=seed)
            if not sampled_df.empty:
                sampled_df = sampled_df.copy()
                sampled_df["_source_file"] = file_path.name
                per_file_frames.append((file_path.name, sampled_df))

        if per_file_frames:
            all_public = pd.concat([df for _, df in per_file_frames], ignore_index=True)

            # Enforce exact global class cap (50% BENIGN, 50% across 4 attack families <= 20,000)
            selected_public_parts: list[pd.DataFrame] = []
            by_class: dict[str, dict[str, int]] = {}
            public_total = 0
            fallback_total = 0

            for label in LABEL_CLASSES:
                target_n = target_per_class[label]
                subset = all_public[all_public[TARGET_CLASS_COL] == label]
                if len(subset) > target_n:
                    subset = subset.sample(n=target_n, random_state=seed)

                pub_count = int(len(subset))
                if pub_count > 0:
                    selected_public_parts.append(subset)
                    public_total += pub_count

                missing = max(0, target_n - pub_count)
                if missing > 0:
                    lab_block = _build_class_block(rng, label, missing)
                    lab_block["_source_file"] = "controlled_lab_generator"
                    selected_public_parts.append(lab_block)
                    fallback_total += missing

                by_class[label] = {
                    "public_raw": pub_count,
                    "fallback_or_lab": missing,
                }

            combined_with_src = pd.concat(selected_public_parts, ignore_index=True)

            # Compute exact per-file counts retained in the final 20,000-row stratified training set
            by_file: dict[str, dict[str, Any]] = {}
            for fname in raw_filenames:
                file_slice = combined_with_src[combined_with_src["_source_file"] == fname]
                cls_counts = file_slice[TARGET_CLASS_COL].value_counts().to_dict()
                by_file[fname] = {
                    "total_loaded": int(len(file_slice)),
                    "by_class": {str(k): int(v) for k, v in cls_counts.items()},
                }

            combined = combined_with_src.drop(columns=["_source_file"])
            combined = combined.sample(frac=1.0, random_state=seed).reset_index(drop=True)
            combined["flow_id"] = [f"flow-{i:06d}" for i in range(len(combined))]
            ordered_cols = METADATA_COLUMNS + FEATURE_COLUMNS + [TARGET_CLASS_COL, TARGET_BINARY_COL]
            combined = combined[ordered_cols]
            combined.to_csv(save_path, index=False)

            mode = "public_only" if fallback_total == 0 else "public_plus_lab"
            return combined, {
                "mode": mode,
                "max_samples_cap": max_rows,
                "raw_files_detected": raw_filenames,
                "by_file": by_file,
                "public_raw_flows": public_total,
                "fallback_or_lab_flows": fallback_total,
                "by_class": by_class,
            }

    if not force_rebuild and save_path.exists():
        cached = pd.read_csv(save_path)
        counts = cached[TARGET_CLASS_COL].value_counts().to_dict()
        by_class = {
            label: {"public_raw": 0, "fallback_or_lab": int(counts.get(label, 0))}
            for label in LABEL_CLASSES
        }
        return cached, {
            "mode": "statistical_fallback",
            "max_samples_cap": max_rows,
            "raw_files_detected": raw_filenames,
            "by_file": {},
            "public_raw_flows": 0,
            "fallback_or_lab_flows": int(len(cached)),
            "by_class": by_class,
        }

    fallback_n = min(6000, max_rows)
    synthetic = generate_synthetic_dataset(n_samples=fallback_n, seed=seed)
    synthetic.to_csv(save_path, index=False)
    counts = synthetic[TARGET_CLASS_COL].value_counts().to_dict()
    by_class = {
        label: {"public_raw": 0, "fallback_or_lab": int(counts.get(label, 0))}
        for label in LABEL_CLASSES
    }
    return synthetic, {
        "mode": "statistical_fallback",
        "max_samples_cap": max_rows,
        "raw_files_detected": raw_filenames,
        "by_file": {},
        "public_raw_flows": 0,
        "fallback_or_lab_flows": int(len(synthetic)),
        "by_class": by_class,
    }


def build_or_load_dataset(
    force_rebuild: bool = False,
    n_samples: int = MAX_TOTAL_TRAINING_ROWS,
    seed: int = RANDOM_SEED,
    save_path: Path = PROCESSED_DATASET_PATH,
) -> pd.DataFrame:
    """Load external CSV/Parquet datasets from data/raw/ if available, else synthetic fallback."""
    df, _ = build_or_load_dataset_with_metadata(
        force_rebuild=force_rebuild,
        n_samples=n_samples,
        seed=seed,
        save_path=save_path,
    )
    return df
