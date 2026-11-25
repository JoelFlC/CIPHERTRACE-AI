"""Generate realistic mixed CSV and Scapy PCAP demo files in demo_samples/."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, wrpcap  # type: ignore

SCRIPT_PATH = Path(__file__).resolve()
BACKEND_DIR = SCRIPT_PATH.parent.parent
PROJECT_ROOT = BACKEND_DIR.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import (  # noqa: E402
    FEATURE_COLUMNS,
    METADATA_COLUMNS,
    TARGET_BINARY_COL,
    TARGET_CLASS_COL,
)
from app.ml.dataset_builder import _build_class_block  # noqa: E402


def _build_tls_client_hello(
    sni: str,
    cipher_count: int = 16,
    tls13: bool = True,
) -> bytes:
    """Construct a valid unencrypted TLS ClientHello payload for passive header parsing."""
    sni_bytes = sni.encode("ascii", errors="ignore")
    sni_entry = b"\x00" + len(sni_bytes).to_bytes(2, "big") + sni_bytes
    sni_ext_data = len(sni_entry).to_bytes(2, "big") + sni_entry
    extensions = (
        b"\x00\x00" + len(sni_ext_data).to_bytes(2, "big") + sni_ext_data
    )

    if tls13:
        # supported_versions extension (0x002B) advertising TLS 1.3 (0x0304)
        sv_data = b"\x02\x03\x04"
        extensions += b"\x00\x2b" + len(sv_data).to_bytes(2, "big") + sv_data

    cipher_suites = b"\x13\x01" * max(1, cipher_count)
    body = (
        b"\x03\x03"  # ClientHello version TLS 1.2
        + os.urandom(32)  # Random
        + b"\x00"  # Session ID length = 0
        + len(cipher_suites).to_bytes(2, "big")
        + cipher_suites
        + b"\x01\x00"  # Compression methods: null
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
    return record


def _build_tls_server_hello(tls13: bool = True) -> bytes:
    """Construct a minimal TLS ServerHello header."""
    ver = b"\x03\x04" if tls13 else b"\x03\x03"
    body = ver + os.urandom(32) + b"\x00\x13\x01\x00"
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def generate_mixed_csv(output_path: Path, seed: int = 2025) -> Path:
    """Generate 40 mixed benign and malicious passive flows into a CSV file."""
    rng = np.random.default_rng(seed)
    counts = {
        "BENIGN": 16,
        "C2_BEACONING": 6,
        "DOH_TUNNEL": 6,
        "EXFILTRATION": 6,
        "PHISHING_AITM": 6,
    }
    frames = [_build_class_block(rng, label, count) for label, count in counts.items()]
    df = pd.concat(frames, ignore_index=True)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    df["flow_id"] = [f"demo-csv-{idx + 1:04d}" for idx in range(len(df))]

    ordered_cols = METADATA_COLUMNS + FEATURE_COLUMNS + [TARGET_CLASS_COL, TARGET_BINARY_COL]
    df = df[ordered_cols]
    df.to_csv(output_path, index=False)
    return output_path


def generate_sample_pcap(output_path: Path) -> Path:
    """Generate a multi-flow .pcap capture with TCP/TLS and DNS traffic via Scapy."""
    packets = []
    base_ts = 1732500000.0

    def add_pkt(pkt: object, ts: float) -> None:
        pkt.time = ts  # type: ignore[attr-defined]
        packets.append(pkt)

    # 1) Benign HTTPS flow (TLS 1.3, api.github.com, fast RTT ~22 ms)
    t = base_ts
    src_ip, dst_ip, sport, dport = "192.168.10.25", "140.82.121.6", 51240, 443
    add_pkt(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S", seq=100), t)
    add_pkt(IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=200, ack=101), t + 0.022)
    add_pkt(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A", seq=101, ack=201), t + 0.024)
    add_pkt(
        IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags="PA", seq=101, ack=201)
        / Raw(load=_build_tls_client_hello("api.github.com", cipher_count=18, tls13=True)),
        t + 0.028,
    )
    add_pkt(
        IP(src=dst_ip, dst=src_ip)
        / TCP(sport=dport, dport=sport, flags="PA", seq=201, ack=200)
        / Raw(load=_build_tls_server_hello(tls13=True)),
        t + 0.052,
    )
    for idx in range(5):
        add_pkt(
            IP(src=dst_ip, dst=src_ip)
            / TCP(sport=dport, dport=sport, flags="PA", seq=400 + idx * 1100, ack=250)
            / Raw(load=b"\x17\x03\x03" + b"A" * 1050),
            t + 0.090 + idx * 0.045,
        )

    # 2) C2 Beaconing flow (TLS 1.2, 6 cipher suites, low IAT jitter every ~500 ms)
    t = base_ts + 5.0
    src_ip, dst_ip, sport, dport = "192.168.10.42", "198.51.100.77", 52110, 443
    add_pkt(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S", seq=100), t)
    add_pkt(IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=200, ack=101), t + 0.045)
    add_pkt(
        IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags="PA", seq=101, ack=201)
        / Raw(load=_build_tls_client_hello("update-agent-v2.net-edge.io", cipher_count=6, tls13=False)),
        t + 0.055,
    )
    for idx in range(10):
        beacon_t = t + 0.500 * (idx + 1)
        add_pkt(
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=dport, flags="PA", seq=200 + idx * 64, ack=201)
            / Raw(load=b"\x17\x03\x03" + b"B" * 64),
            beacon_t,
        )
        add_pkt(
            IP(src=dst_ip, dst=src_ip)
            / TCP(sport=dport, dport=sport, flags="PA", seq=201 + idx * 48, ack=264 + idx * 64)
            / Raw(load=b"\x17\x03\x03" + b"C" * 48),
            beacon_t + 0.025,
        )

    # 3) High-entropy DNS / DoH Tunneling flow (UDP/53 rapid queries)
    t = base_ts + 15.0
    src_ip, dst_ip, sport, dport = "192.168.10.63", "1.1.1.1", 54880, 53
    tunnel_qname = "a8f4c912d0e3b76a55f19c8e4d2a1b0f9e8c.doh-relay.net"
    for idx in range(14):
        add_pkt(
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=sport, dport=dport)
            / DNS(rd=1, qd=DNSQR(qname=tunnel_qname)),
            t + idx * 0.06,
        )

    # 4) Data Exfiltration flow (massive outbound MTU-sized payloads, minimal inbound)
    t = base_ts + 20.0
    src_ip, dst_ip, sport, dport = "192.168.10.88", "203.0.113.99", 55400, 443
    add_pkt(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S", seq=100), t)
    add_pkt(IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=200, ack=101), t + 0.030)
    add_pkt(
        IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags="PA", seq=101, ack=201)
        / Raw(load=_build_tls_client_hello("backup-mirror-upload.object-store.io", cipher_count=12, tls13=False)),
        t + 0.040,
    )
    for idx in range(18):
        add_pkt(
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=dport, flags="PA", seq=300 + idx * 1360, ack=201)
            / Raw(load=b"\x17\x03\x03" + b"X" * 1340),
            t + 0.080 + idx * 0.015,
        )

    # 5) Phishing AiTM Reverse Proxy flow (double-hop RTT ~290 ms + multiple ClientHellos)
    t = base_ts + 26.0
    src_ip, dst_ip, sport, dport = "192.168.10.91", "185.220.101.45", 56320, 443
    aitm_sni = "login-verify-session-a9f82c1e.cloud-auth.site"
    add_pkt(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S", seq=100), t)
    add_pkt(IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=200, ack=101), t + 0.290)
    for idx in range(4):
        add_pkt(
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=dport, flags="PA", seq=101 + idx * 150, ack=201)
            / Raw(load=_build_tls_client_hello(aitm_sni, cipher_count=12, tls13=False)),
            t + 0.310 + idx * 0.220,
        )
        add_pkt(
            IP(src=dst_ip, dst=src_ip)
            / TCP(sport=dport, dport=sport, flags="PA", seq=201 + idx * 120, ack=251 + idx * 150)
            / Raw(load=_build_tls_server_hello(tls13=False)),
            t + 0.420 + idx * 0.220,
        )

    packets.sort(key=lambda pkt: float(pkt.time))
    wrpcap(str(output_path), packets)
    return output_path


def generate_all(output_dir: Path | None = None) -> tuple[Path, Path]:
    """Generate both demo CSV and PCAP files inside demo_samples/."""
    target_dir = output_dir or (PROJECT_ROOT / "demo_samples")
    target_dir.mkdir(parents=True, exist_ok=True)

    csv_path = generate_mixed_csv(target_dir / "mixed_traffic_demo.csv")
    pcap_path = generate_sample_pcap(target_dir / "sample_capture.pcap")
    return csv_path, pcap_path


if __name__ == "__main__":
    csv_out, pcap_out = generate_all()
    print(f"[CIPHERTRACE DEMO] CSV generado : {csv_out} ({csv_out.stat().st_size} bytes)")
    print(f"[CIPHERTRACE DEMO] PCAP generado: {pcap_out} ({pcap_out.stat().st_size} bytes)")
