"""Live passive network sniffer service using Scapy without payload decryption."""

from __future__ import annotations

import asyncio
import os
import threading
from datetime import datetime, timezone
from typing import Any

from scapy.all import get_if_list, sniff  # type: ignore

from app.db.database import SessionLocal
from app.db.models import persist_evaluation
from app.ml.pcap_extractor import extract_flows_from_packets
from app.services.inference_engine import engine
from app.services.ws_manager import ws_manager

DEFAULT_BPF_FILTER = "tcp port 443 or tcp port 8443 or udp port 53 or tcp port 8000"


def has_capture_privileges() -> bool:
    """Return True if process is root or holds CAP_NET_RAW effective capability."""
    if os.geteuid() == 0:
        return True
    try:
        with open("/proc/self/status", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    cap_eff = int(line.split(":", 1)[1].strip(), 16)
                    # CAP_NET_RAW is capability bit 13
                    return bool(cap_eff & (1 << 13))
    except OSError:
        return False
    return False


def list_network_interfaces() -> list[str]:
    """Return available network interfaces ordered with 'any' and physical NICs first."""
    try:
        ifaces = [str(name) for name in get_if_list() if str(name).strip()]
    except Exception:
        ifaces = []

    ordered: list[str] = ["any"]
    non_loopback = [i for i in ifaces if i not in ("any", "lo")]
    ordered.extend(non_loopback)
    if "lo" in ifaces or not non_loopback:
        ordered.append("lo")

    # Deduplicate preserving order
    seen: set[str] = set()
    return [i for i in ordered if not (i in seen or seen.add(i))]


class LivePassiveSniffer:
    """Thread-safe windowed passive Scapy sniffer feeding CipherTraceEngine and WebSockets."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

        self._running: bool = False
        self._interface: str = "any"
        self._bpf_filter: str = DEFAULT_BPF_FILTER
        self._window_seconds: int = 4
        self._packets_captured: int = 0
        self._flows_evaluated: int = 0
        self._alerts_triggered: int = 0
        self._started_at: str | None = None
        self._last_window_at: str | None = None
        self._last_error: str | None = None

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def status(self) -> dict[str, Any]:
        """Return a thread-safe snapshot of live capture status and counters."""
        with self._lock:
            return {
                "running": self._running,
                "can_capture": has_capture_privileges(),
                "interface": self._interface,
                "bpf_filter": self._bpf_filter,
                "window_seconds": self._window_seconds,
                "packets_captured": self._packets_captured,
                "flows_evaluated": self._flows_evaluated,
                "alerts_triggered": self._alerts_triggered,
                "started_at": self._started_at,
                "last_window_at": self._last_window_at,
                "last_error": self._last_error,
            }

    def start(
        self,
        interface: str,
        bpf_filter: str,
        window_seconds: int,
        loop: asyncio.AbstractEventLoop,
    ) -> dict[str, Any]:
        """Start background windowed passive capture on the selected interface."""
        available = list_network_interfaces()
        target_iface = interface.strip() or "any"
        if target_iface != "any" and target_iface not in available:
            raise ValueError(
                f"Interfaz '{target_iface}' no disponible. Opciones: {available}"
            )

        if not has_capture_privileges():
            raise PermissionError(
                "Permisos insuficientes para captura pasiva (requiere CAP_NET_RAW o ejecutar con Docker/root)."
            )

        with self._lock:
            if self._running:
                return {
                    "running": self._running,
                    "can_capture": True,
                    "interface": self._interface,
                    "bpf_filter": self._bpf_filter,
                    "window_seconds": self._window_seconds,
                    "packets_captured": self._packets_captured,
                    "flows_evaluated": self._flows_evaluated,
                    "alerts_triggered": self._alerts_triggered,
                    "started_at": self._started_at,
                    "last_window_at": self._last_window_at,
                    "last_error": self._last_error,
                }

            self._stop_event.clear()
            self._loop = loop
            self._interface = target_iface
            self._bpf_filter = bpf_filter.strip()
            self._window_seconds = max(1, min(int(window_seconds), 30))
            self._packets_captured = 0
            self._flows_evaluated = 0
            self._alerts_triggered = 0
            self._started_at = datetime.now(timezone.utc).isoformat()
            self._last_window_at = None
            self._last_error = None
            self._running = True

            self._thread = threading.Thread(
                target=self._capture_loop,
                name=f"ciphertrace-sniffer-{target_iface}",
                daemon=True,
            )
            self._thread.start()

        return self.status()

    def stop(self) -> dict[str, Any]:
        """Signal the capture loop to stop and wait briefly for clean shutdown."""
        self._stop_event.set()
        thread = self._thread
        wait_timeout = float(self._window_seconds) + 2.0
        if thread and thread.is_alive() and threading.current_thread() is not thread:
            thread.join(timeout=wait_timeout)

        with self._lock:
            self._running = False
            self._thread = None

        return self.status()

    def _broadcast_async(self, payload: dict[str, Any]) -> None:
        loop = self._loop
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(ws_manager.broadcast(payload), loop)

    def _process_batch(self, packets: list[Any], iface: str) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        pkt_count = len(packets)
        if pkt_count == 0:
            with self._lock:
                self._last_window_at = now_iso
            return

        engine.ensure_loaded()
        raw_flows = extract_flows_from_packets(packets, flow_prefix=f"live-{iface}")
        if not raw_flows:
            with self._lock:
                self._packets_captured += pkt_count
                self._last_window_at = now_iso
            return

        source_label = f"live:{iface}"
        alerts_in_batch = 0
        evaluated_pairs: list[tuple[dict[str, Any], dict[str, Any] | None]] = []

        db = SessionLocal()
        try:
            for raw_flow in raw_flows:
                evaluation = engine.evaluate_flow(raw_flow)
                flow_dict, alert_dict = persist_evaluation(
                    db, evaluation, source=source_label
                )
                if alert_dict is not None:
                    alerts_in_batch += 1
                evaluated_pairs.append((flow_dict, alert_dict))
        finally:
            db.close()

        with self._lock:
            self._packets_captured += pkt_count
            self._flows_evaluated += len(evaluated_pairs)
            self._alerts_triggered += alerts_in_batch
            self._last_window_at = now_iso

        for flow_dict, alert_dict in evaluated_pairs:
            self._broadcast_async(
                {
                    "event": "flow_evaluated",
                    "source": source_label,
                    "flow": flow_dict,
                    "alert": alert_dict,
                }
            )

    def _capture_loop(self) -> None:
        iface = self._interface
        sniff_iface: str | None = None if iface == "any" else iface
        bpf = self._bpf_filter or None
        window = self._window_seconds

        try:
            while not self._stop_event.is_set():
                packets = sniff(
                    iface=sniff_iface,
                    filter=bpf,
                    timeout=window,
                    store=True,
                    stop_filter=lambda _: self._stop_event.is_set(),
                )
                self._process_batch(list(packets), iface)
        except Exception as exc:
            with self._lock:
                self._last_error = f"Error en captura pasiva ({iface}): {exc}"
        finally:
            with self._lock:
                self._running = False


live_sniffer = LivePassiveSniffer()
