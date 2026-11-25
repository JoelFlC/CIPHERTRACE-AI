"""Explainable real-time hybrid inference engine for CIPHERTRACE AI."""

from __future__ import annotations

import json
import math
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import joblib
import numpy as np
import pandas as pd

from app.core.config import (
    AUTOENCODER_PATH,
    FEATURE_COLUMNS,
    GA_CONFIG_PATH,
    ID_TO_LABEL,
    IFOREST_MODEL_PATH,
    LABEL_TO_ID,
    MLP_MODEL_PATH,
    MODEL_METRICS_PATH,
    PROCESSED_DATASET_PATH,
    RF_MODEL_PATH,
    SCALER_PATH,
    TARGET_CLASS_COL,
)
from app.ml.autoencoder import TabularAutoencoderDetector

# Fallback benign baseline if processed CSV is unavailable at runtime
DEFAULT_BENIGN_STATS: dict[str, tuple[float, float]] = {
    "duration_ms": (6510.131, 13845.895),
    "bytes_sent": (14902.675, 45745.576),
    "bytes_recv": (34175.774, 39731.670),
    "byte_asymmetry_ratio": (-0.524, 0.429),
    "packets_sent": (37.171, 117.272),
    "packets_recv": (42.101, 51.532),
    "iat_mean_ms": (166.845, 88.357),
    "iat_std_ms": (213.828, 117.841),
    "pkt_size_mean": (634.059, 203.274),
    "pkt_size_std": (278.019, 95.958),
    "pkt_size_max": (1052.127, 229.889),
    "tls_version_num": (1.265, 0.048),
    "cipher_suite_count": (17.575, 4.595),
    "sni_entropy": (3.447, 0.325),
    "sni_length": (18.456, 6.075),
    "dns_query_rate": (0.807, 0.731),
    "double_hop_latency_ms": (48.335, 29.894),
    "redirect_count": (0.425, 0.629),
}


def _explain_feature(
    feature: str,
    value: float,
    benign_mean: float,
    z_score: float,
    predicted_threat: str,
) -> str:
    """Build a human-readable Spanish explanation for a contributing passive feature."""
    high = value >= benign_mean
    explanations: dict[str, str] = {
        "double_hop_latency_ms": (
            f"Latencia de doble salto elevada ({value:.1f} ms vs {benign_mean:.1f} ms basal) compatible con Proxy Inverso AiTM"
            if high
            else f"Latencia de handshake baja ({value:.1f} ms), dentro de rango directo"
        ),
        "redirect_count": (
            f"Cadena anómala de redirecciones TLS/HTTP ({int(round(value))} saltos) típica de captura de sesión AiTM"
            if high
            else f"Conteo mínimo de redirecciones ({int(round(value))})"
        ),
        "sni_entropy": (
            f"Entropía Shannon elevada en SNI/dominio ({value:.2f} bits) sugestiva de subdominios codificados o DGA"
            if high
            else f"Entropía nominal en SNI ({value:.2f} bits)"
        ),
        "sni_length": (
            f"Longitud inusual de SNI/dominio ({int(round(value))} caracteres vs {benign_mean:.1f} basal) asociada a {predicted_threat}"
            if high
            else f"Longitud compacta de SNI ({int(round(value))} caracteres)"
        ),
        "dns_query_rate": (
            f"Tasa alta de consultas DNS/DoH ({value:.1f} req/s) indicativa de tunelización DoH"
            if high
            else f"Tasa baja de consultas DNS/DoH ({value:.2f} req/s)"
        ),
        "byte_asymmetry_ratio": (
            f"Asimetría saliente marcada ({value:+.2f}) con predominio de envío sobre recepción, compatible con exfiltración"
            if high
            else f"Asimetría entrante normal ({value:+.2f})"
        ),
        "bytes_sent": (
            f"Volumen elevado de bytes salientes ({value:,.0f} B) respecto al patrón benigno ({benign_mean:,.0f} B)"
            if high
            else f"Volumen saliente reducido ({value:,.0f} B)"
        ),
        "bytes_recv": (
            f"Alto volumen recibido ({value:,.0f} B) frente a la media basal ({benign_mean:,.0f} B)"
            if high
            else f"Respuesta del servidor mínima ({value:,.0f} B frente a {benign_mean:,.0f} B basal)"
        ),
        "iat_std_ms": (
            f"Variabilidad temporal elevada entre paquetes (IAT std={value:.1f} ms)"
            if high
            else f"Desviación IAT muy baja ({value:.1f} ms vs {benign_mean:.1f} ms basal), patrón periódico compatible con beaconing C2"
        ),
        "iat_mean_ms": (
            f"Intervalo medio entre paquetes prolongado ({value:.1f} ms) coherente con callbacks periódicos C2"
            if high
            else f"Intervalo medio corto entre paquetes ({value:.1f} ms)"
        ),
        "duration_ms": (
            f"Sesión de larga duración ({value / 1000.0:.1f} s) típica de canales persistentes o beaconing"
            if high
            else f"Duración breve de flujo ({value:.1f} ms)"
        ),
        "pkt_size_mean": (
            f"Tamaño medio de paquete elevado ({value:.1f} B) asociado a transferencia masiva de datos"
            if high
            else f"Paquetes pequeños uniformes ({value:.1f} B vs {benign_mean:.1f} B basal) frecuentes en comandos C2"
        ),
        "pkt_size_std": (
            f"Alta dispersión en tamaños de paquete ({value:.1f} B)"
            if high
            else f"Baja varianza en tamaño de paquete ({value:.1f} B), tráfico altamente estructurado"
        ),
        "pkt_size_max": (
            f"Paquetes cercanos al MTU máximo ({value:.0f} B) compatibles con exfiltración en ráfaga"
            if high
            else f"Tamaño máximo acotado ({value:.0f} B vs {benign_mean:.0f} B basal)"
        ),
        "packets_sent": (
            f"Cantidad elevada de paquetes salientes ({int(round(value))})"
            if high
            else f"Pocos paquetes salientes ({int(round(value))})"
        ),
        "packets_recv": (
            f"Cantidad elevada de paquetes entrantes ({int(round(value))})"
            if high
            else f"Pocos paquetes entrantes ({int(round(value))})"
        ),
        "tls_version_num": (
            f"Negociación TLS {value:.1f} observada en cabecera ClientHello/ServerHello"
        ),
        "cipher_suite_count": (
            f"Lista extensa de cipher suites ({int(round(value))}) en ClientHello"
            if high
            else f"Conteo reducido de cipher suites ({int(round(value))} vs {benign_mean:.1f} basal) típico de clientes C2 personalizados"
        ),
    }
    base_msg = explanations.get(
        feature,
        f"Desviación significativa en {feature} ({value:.2f}, z={z_score:+.2f})",
    )
    return base_msg


class CipherTraceEngine:
    """Singleton inference engine combining MLP, Autoencoder, RF, and Isolation Forest."""

    def __init__(self) -> None:
        self.loaded: bool = False
        self.scaler: Any = None
        self.rf_model: Any = None
        self.mlp_model: Any = None
        self.iforest_model: Any = None
        self.autoencoder: TabularAutoencoderDetector | None = None
        self.ga_config: dict[str, Any] = {}
        self.model_metrics: dict[str, Any] = {}
        self.ga_mask: np.ndarray = np.ones(len(FEATURE_COLUMNS), dtype=bool)
        self.w_mlp: float = 0.75
        self.w_ae: float = 0.25
        self.threshold: float = 0.50
        self.benign_means: dict[str, float] = {
            k: v[0] for k, v in DEFAULT_BENIGN_STATS.items()
        }
        self.benign_stds: dict[str, float] = {
            k: v[1] for k, v in DEFAULT_BENIGN_STATS.items()
        }

    def load_artifacts(self) -> None:
        """Load trained Phase 1 models, scaler, GA config, metrics, and benign baseline."""
        self.scaler = joblib.load(SCALER_PATH)
        self.rf_model = joblib.load(RF_MODEL_PATH)
        self.mlp_model = joblib.load(MLP_MODEL_PATH)
        self.iforest_model = joblib.load(IFOREST_MODEL_PATH)
        self.autoencoder = TabularAutoencoderDetector.load(AUTOENCODER_PATH)

        with open(GA_CONFIG_PATH, encoding="utf-8") as fh:
            self.ga_config = json.load(fh)
        with open(MODEL_METRICS_PATH, encoding="utf-8") as fh:
            self.model_metrics = json.load(fh)

        self.ga_mask = np.array(self.ga_config["ga_mask"], dtype=bool)
        weights = self.ga_config.get("weights", {})
        self.w_mlp = float(weights.get("w_mlp", 0.75))
        self.w_ae = float(weights.get("w_ae", 0.25))
        self.threshold = float(self.ga_config.get("threshold", 0.50))

        if PROCESSED_DATASET_PATH.exists():
            df = pd.read_csv(PROCESSED_DATASET_PATH)
            benign_df = df[df[TARGET_CLASS_COL] == "BENIGN"]
            if not benign_df.empty:
                for col in FEATURE_COLUMNS:
                    self.benign_means[col] = float(benign_df[col].mean())
                    self.benign_stds[col] = max(float(benign_df[col].std()), 1e-3)

        self.loaded = True

    def ensure_loaded(self) -> None:
        if not self.loaded:
            self.load_artifacts()

    def _extract_feature_vector(self, flow_metadata: dict[str, Any]) -> tuple[dict[str, float], np.ndarray]:
        source = flow_metadata.get("features", flow_metadata)
        clean_features: dict[str, float] = {}
        values: list[float] = []
        for col in FEATURE_COLUMNS:
            raw_val = source.get(col, 0.0)
            try:
                val = float(raw_val)
            except (TypeError, ValueError):
                val = 0.0
            if not math.isfinite(val):
                val = 0.0
            clean_features[col] = round(val, 4)
            values.append(val)
        return clean_features, np.array(values, dtype=np.float64).reshape(1, -1)

    def evaluate_flow(self, flow_metadata: dict[str, Any]) -> dict[str, Any]:
        """Evaluate a single passive encrypted flow with hybrid scoring & XAI explanation."""
        self.ensure_loaded()
        assert self.autoencoder is not None

        t0 = time.perf_counter()
        clean_features, X_raw = self._extract_feature_vector(flow_metadata)

        X_scaled = self.scaler.transform(X_raw)
        X_sel = X_scaled[:, self.ga_mask]

        benign_id = LABEL_TO_ID["BENIGN"]

        # 1) MLP multiclass probabilities
        mlp_probs_vec = self.mlp_model.predict_proba(X_sel)[0]
        prob_mlp = float(1.0 - mlp_probs_vec[benign_id])

        # 2) Autoencoder normalized reconstruction MSE in [0, 1]
        anomaly_ae = float(self.autoencoder.predict_scores(X_sel)[0])

        # 3) Random Forest multiclass probabilities
        rf_probs_vec = self.rf_model.predict_proba(X_sel)[0]
        prob_rf = float(1.0 - rf_probs_vec[benign_id])

        # 4) Isolation Forest normalized anomaly score in [0, 1]
        if_decision = float(self.iforest_model.decision_function(X_sel)[0])
        anomaly_iforest = float(1.0 / (1.0 + math.exp(5.0 * if_decision)))

        # GA-weighted hybrid risk score
        risk_score = float(
            np.clip(self.w_mlp * prob_mlp + self.w_ae * anomaly_ae, 0.0, 1.0)
        )

        if risk_score >= self.threshold:
            risk_level = "ALTO"
        elif risk_score >= 0.45:
            risk_level = "MEDIO"
        else:
            risk_level = "BAJO"

        # Combine supervised class probabilities to determine the most probable threat vector
        combined_class_probs = 0.55 * mlp_probs_vec + 0.45 * rf_probs_vec
        class_prob_map = {
            ID_TO_LABEL[idx]: round(float(combined_class_probs[idx]), 4)
            for idx in range(len(combined_class_probs))
        }

        if risk_level == "BAJO":
            predicted_threat = "BENIGN"
        else:
            non_benign_indices = [idx for idx in range(len(combined_class_probs)) if idx != benign_id]
            best_idx = int(np.argmax(combined_class_probs))
            if best_idx == benign_id:
                best_idx = max(non_benign_indices, key=lambda idx: float(combined_class_probs[idx]))
            predicted_threat = ID_TO_LABEL[best_idx]

        # Explainable AI: top 3 features by |z-score| relative to BENIGN baseline
        z_entries: list[dict[str, Any]] = []
        for col in FEATURE_COLUMNS:
            val = clean_features[col]
            mean = self.benign_means[col]
            std = max(self.benign_stds[col], 1e-3)
            z = (val - mean) / std
            z_entries.append(
                {
                    "feature": col,
                    "value": round(val, 4),
                    "benign_mean": round(mean, 4),
                    "z_score": round(float(z), 2),
                    "abs_z": abs(float(z)),
                    "direction": "elevado" if z >= 0 else "bajo",
                    "explanation": _explain_feature(col, val, mean, z, predicted_threat),
                }
            )
        z_entries.sort(key=lambda item: item["abs_z"], reverse=True)
        top_contributing = [
            {k: v for k, v in entry.items() if k != "abs_z"}
            for entry in z_entries[:3]
        ]

        latency_ms = round((time.perf_counter() - t0) * 1000.0, 4)

        return {
            "flow_id": str(flow_metadata.get("flow_id") or f"flow-{uuid.uuid4().hex[:10]}"),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "src_ip": str(flow_metadata.get("src_ip", "192.168.10.50")),
            "dst_ip": str(flow_metadata.get("dst_ip", "93.184.216.34")),
            "src_port": int(flow_metadata.get("src_port", 51420)),
            "dst_port": int(flow_metadata.get("dst_port", 443)),
            "protocol": str(flow_metadata.get("protocol", "TCP")),
            "sni": str(flow_metadata.get("sni", "")),
            "prob_mlp": round(prob_mlp, 4),
            "anomaly_ae": round(anomaly_ae, 4),
            "prob_rf": round(prob_rf, 4),
            "anomaly_iforest": round(anomaly_iforest, 4),
            "risk_score": round(risk_score, 4),
            "risk_level": risk_level,
            "predicted_threat": predicted_threat,
            "class_probabilities": class_prob_map,
            "top_contributing_features": top_contributing,
            "inference_latency_ms": latency_ms,
            "features": clean_features,
        }


engine = CipherTraceEngine()
