"""Passive PCAP metadata extractor using Scapy without decrypting any payload."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from scapy.all import DNS, IP, TCP, UDP, IPv6, Raw, rdpcap  # type: ignore

from app.core.config import FEATURE_COLUMNS, shannon_entropy

TLS_VERSION_MAP: dict[int, float] = {
    0x0300: 1.0,  # SSL 3.0 mapped safely
    0x0301: 1.0,  # TLS 1.0
    0x0302: 1.1,  # TLS 1.1
    0x0303: 1.2,  # TLS 1.2
    0x0304: 1.3,  # TLS 1.3
}


def _parse_tls_client_hello(payload: bytes) -> dict[str, Any]:
    """Parse unencrypted TLS ClientHello/ServerHello handshake headers only."""
    info: dict[str, Any] = {
        "is_tls": False,
        "is_client_hello": False,
        "tls_version_num": 0.0,
        "cipher_suite_count": 0,
        "sni": "",
    }
    if len(payload) < 9:
        return info

    # TLS Record Layer: ContentType=0x16 (Handshake), Major=0x03
    content_type = payload[0]
    record_ver = int.from_bytes(payload[1:3], "big")
    if content_type != 0x16 or (record_ver >> 8) != 0x03:
        return info

    info["is_tls"] = True
    info["tls_version_num"] = TLS_VERSION_MAP.get(record_ver, 1.2)

    handshake_type = payload[5]
    if handshake_type == 0x02 and len(payload) >= 11:
        # ServerHello handshake version
        server_ver = int.from_bytes(payload[9:11], "big")
        info["tls_version_num"] = max(
            info["tls_version_num"], TLS_VERSION_MAP.get(server_ver, 1.2)
        )
        return info

    if handshake_type != 0x01 or len(payload) < 44:
        return info

    info["is_client_hello"] = True
    try:
        # Handshake header (4B at offset 5) + ClientVersion (2B) + Random (32B)
        client_ver = int.from_bytes(payload[9:11], "big")
        info["tls_version_num"] = max(
            info["tls_version_num"], TLS_VERSION_MAP.get(client_ver, 1.2)
        )

        pos = 43  # offset of SessionID length
        if pos >= len(payload):
            return info
        session_id_len = payload[pos]
        pos += 1 + session_id_len

        if pos + 2 > len(payload):
            return info
        cipher_suites_len = int.from_bytes(payload[pos : pos + 2], "big")
        info["cipher_suite_count"] = max(0, cipher_suites_len // 2)
        pos += 2 + cipher_suites_len

        if pos + 1 > len(payload):
            return info
        compression_len = payload[pos]
        pos += 1 + compression_len

        if pos + 2 > len(payload):
            return info
        extensions_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2
        ext_end = min(len(payload), pos + extensions_len)

        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(payload[pos : pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2 : pos + 4], "big")
            ext_data = payload[pos + 4 : pos + 4 + ext_len]
            pos += 4 + ext_len

            if ext_type == 0x0000 and len(ext_data) >= 5:
                # Server Name Indication (SNI) extension
                name_type = ext_data[2]
                name_len = int.from_bytes(ext_data[3:5], "big")
                if name_type == 0x00 and 5 + name_len <= len(ext_data):
                    info["sni"] = ext_data[5 : 5 + name_len].decode(
                        "utf-8", errors="ignore"
                    )
            elif ext_type == 0x002B and len(ext_data) >= 3:
                # supported_versions extension: check for TLS 1.3 (0x0304)
                list_len = ext_data[0]
                versions_bytes = ext_data[1 : 1 + list_len]
                for idx in range(0, len(versions_bytes) - 1, 2):
                    ver = int.from_bytes(versions_bytes[idx : idx + 2], "big")
                    if ver == 0x0304:
                        info["tls_version_num"] = 1.3
    except Exception:
        return info

    return info


def _canonical_flow_key(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str
) -> tuple[tuple[str, int], tuple[str, int], str]:
    ep_a = (src_ip, src_port)
    ep_b = (dst_ip, dst_port)
    if ep_a <= ep_b:
        return (ep_a, ep_b, proto)
    return (ep_b, ep_a, proto)


def extract_flows_from_pcap(pcap_path: str | Path) -> list[dict[str, Any]]:
    """Read a .pcap/.pcapng file passively and extract 18 standard metadata features per flow."""
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    packets = rdpcap(str(path))
    grouped: dict[tuple[tuple[str, int], tuple[str, int], str], list[dict[str, Any]]] = (
        defaultdict(list)
    )
    flow_origins: dict[
        tuple[tuple[str, int], tuple[str, int], str], tuple[str, str, int, int, str]
    ] = {}

    for pkt in packets:
        if IP in pkt:
            src_ip = str(pkt[IP].src)
            dst_ip = str(pkt[IP].dst)
        elif IPv6 in pkt:
            src_ip = str(pkt[IPv6].src)
            dst_ip = str(pkt[IPv6].dst)
        else:
            continue

        if TCP in pkt:
            proto = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            tcp_flags = int(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
            tcp_flags = 0
        else:
            continue

        key = _canonical_flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        if key not in flow_origins:
            flow_origins[key] = (src_ip, dst_ip, src_port, dst_port, proto)

        raw_bytes = bytes(pkt[Raw].load) if Raw in pkt else b""
        dns_qname = ""
        is_dns_query = False
        if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd is not None:
            is_dns_query = True
            qname = getattr(pkt[DNS].qd, "qname", b"")
            if isinstance(qname, bytes):
                dns_qname = qname.decode("utf-8", errors="ignore").rstrip(".")
            else:
                dns_qname = str(qname).rstrip(".")

        grouped[key].append(
            {
                "time": float(pkt.time),
                "size": float(len(pkt)),
                "src_ip": src_ip,
                "src_port": src_port,
                "tcp_flags": tcp_flags,
                "raw": raw_bytes,
                "dns_qname": dns_qname,
                "is_dns_query": is_dns_query,
            }
        )

    extracted: list[dict[str, Any]] = []
    for flow_idx, (key, pkts) in enumerate(grouped.items()):
        pkts.sort(key=lambda item: item["time"])
        orig_src_ip, orig_dst_ip, orig_src_port, orig_dst_port, proto = flow_origins[key]

        times = np.array([p["time"] for p in pkts], dtype=float)
        sizes = np.array([p["size"] for p in pkts], dtype=float)

        duration_s = max(float(times[-1] - times[0]), 0.0)
        duration_ms = duration_s * 1000.0

        sent_sizes = [
            p["size"]
            for p in pkts
            if p["src_ip"] == orig_src_ip and p["src_port"] == orig_src_port
        ]
        recv_sizes = [
            p["size"]
            for p in pkts
            if not (p["src_ip"] == orig_src_ip and p["src_port"] == orig_src_port)
        ]

        bytes_sent = float(sum(sent_sizes))
        bytes_recv = float(sum(recv_sizes))
        byte_asymmetry_ratio = (bytes_sent - bytes_recv) / (
            bytes_sent + bytes_recv + 1.0
        )

        packets_sent = float(len(sent_sizes))
        packets_recv = float(len(recv_sizes))

        if len(times) > 1:
            iats_ms = np.diff(times) * 1000.0
            iat_mean_ms = float(np.mean(iats_ms))
            iat_std_ms = float(np.std(iats_ms))
        else:
            iat_mean_ms = 0.0
            iat_std_ms = 0.0

        pkt_size_mean = float(np.mean(sizes))
        pkt_size_std = float(np.std(sizes))
        pkt_size_max = float(np.max(sizes))

        tls_version_num = 0.0
        cipher_suite_count = 0.0
        sni = ""
        client_hello_count = 0
        dns_queries = 0

        # Measure passive SYN->SYN/ACK or first client->server response RTT
        syn_time: float | None = None
        first_client_time: float | None = None
        double_hop_latency_ms = 0.0

        for p in pkts:
            is_client = (
                p["src_ip"] == orig_src_ip and p["src_port"] == orig_src_port
            )
            if is_client and first_client_time is None:
                first_client_time = p["time"]
            if proto == "TCP":
                if is_client and (p["tcp_flags"] & 0x02) and syn_time is None:
                    syn_time = p["time"]
                elif (
                    not is_client
                    and (p["tcp_flags"] & 0x12) == 0x12
                    and syn_time is not None
                    and double_hop_latency_ms == 0.0
                ):
                    double_hop_latency_ms = max(0.0, (p["time"] - syn_time) * 1000.0)

            if not is_client and double_hop_latency_ms == 0.0 and first_client_time is not None:
                double_hop_latency_ms = max(0.0, (p["time"] - first_client_time) * 1000.0)

            if p["is_dns_query"]:
                dns_queries += 1
                if not sni and p["dns_qname"]:
                    sni = p["dns_qname"]

            if p["raw"]:
                tls_info = _parse_tls_client_hello(p["raw"])
                if tls_info["is_tls"]:
                    tls_version_num = max(tls_version_num, float(tls_info["tls_version_num"]))
                    if tls_info["is_client_hello"]:
                        client_hello_count += 1
                        cipher_suite_count = max(
                            cipher_suite_count, float(tls_info["cipher_suite_count"])
                        )
                    if not sni and tls_info["sni"]:
                        sni = str(tls_info["sni"])

        # Safe fallback estimate for encrypted DoH flows on port 443/853 with no plain DNS layer
        if dns_queries > 0:
            dns_query_rate = dns_queries / max(duration_s, 1.0)
        elif orig_dst_port in (53, 853) or (
            orig_dst_port == 443 and packets_sent >= 10 and pkt_size_mean < 450.0
        ):
            dns_query_rate = packets_sent / max(duration_s, 1.0)
        else:
            dns_query_rate = 0.0

        sni_entropy = shannon_entropy(sni) if sni else 0.0
        sni_length = float(len(sni))

        # Observable redirect proxy heuristic: multiple ClientHellos or rapid direction shifts
        redirect_count = float(max(0, client_hello_count - 1))

        features = {
            "duration_ms": round(duration_ms, 4),
            "bytes_sent": round(bytes_sent, 4),
            "bytes_recv": round(bytes_recv, 4),
            "byte_asymmetry_ratio": round(byte_asymmetry_ratio, 6),
            "packets_sent": round(packets_sent, 4),
            "packets_recv": round(packets_recv, 4),
            "iat_mean_ms": round(iat_mean_ms, 4),
            "iat_std_ms": round(iat_std_ms, 4),
            "pkt_size_mean": round(pkt_size_mean, 4),
            "pkt_size_std": round(pkt_size_std, 4),
            "pkt_size_max": round(pkt_size_max, 4),
            "tls_version_num": round(tls_version_num, 2),
            "cipher_suite_count": round(cipher_suite_count, 4),
            "sni_entropy": round(sni_entropy, 4),
            "sni_length": round(sni_length, 4),
            "dns_query_rate": round(dns_query_rate, 4),
            "double_hop_latency_ms": round(double_hop_latency_ms, 4),
            "redirect_count": round(redirect_count, 4),
        }

        extracted.append(
            {
                "flow_id": f"{path.stem}-flow-{flow_idx:05d}",
                "src_ip": orig_src_ip,
                "dst_ip": orig_dst_ip,
                "src_port": orig_src_port,
                "dst_port": orig_dst_port,
                "protocol": proto,
                "sni": sni,
                "features": {col: features[col] for col in FEATURE_COLUMNS},
            }
        )

    return extracted


def flows_to_dataframe(flows: list[dict[str, Any]]) -> pd.DataFrame:
    """Convert extracted passive flow dictionaries into a standardized DataFrame."""
    if not flows:
        return pd.DataFrame(columns=["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", *FEATURE_COLUMNS])

    rows = []
    for flow in flows:
        row = {
            "flow_id": flow["flow_id"],
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],
            "src_port": flow["src_port"],
            "dst_port": flow["dst_port"],
            "protocol": flow["protocol"],
        }
        row.update(flow["features"])
        rows.append(row)
    return pd.DataFrame(rows)
