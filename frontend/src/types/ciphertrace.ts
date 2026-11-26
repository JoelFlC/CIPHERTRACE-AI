export type RiskLevel = 'ALTO' | 'MEDIO' | 'BAJO';

export type RiskFilter = 'TODOS' | RiskLevel;

export type ThreatVector =
  | 'BENIGN'
  | 'C2_BEACONING'
  | 'DOH_TUNNEL'
  | 'EXFILTRATION'
  | 'PHISHING_AITM';

export type NavView = 'overview' | 'threat-lab' | 'model-analytics' | 'file-inspector';

export type WsConnectionStatus = 'connected' | 'connecting' | 'disconnected';

export interface TopContributingFeature {
  feature: string;
  value: number;
  benign_mean: number;
  z_score: number;
  direction: 'elevado' | 'bajo' | string;
  explanation: string;
}

export interface AnalyzedFlow {
  id: number;
  flow_id: string;
  timestamp_utc: string;
  source: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  sni: string;
  prob_mlp: number;
  anomaly_ae: number;
  prob_rf: number;
  anomaly_iforest: number;
  risk_score: number;
  risk_level: RiskLevel;
  predicted_threat: ThreatVector | string;
  inference_latency_ms: number;
  features: Record<string, number>;
  top_contributing_features: TopContributingFeature[];
}

export interface SecurityAlert {
  id: number;
  flow_db_id: number;
  flow_id: string;
  timestamp_utc: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  risk_score: number;
  risk_level: RiskLevel;
  predicted_threat: ThreatVector | string;
  summary: string;
  top_contributing_features: TopContributingFeature[];
}

export interface DashboardSummary {
  total_flows: number;
  active_alerts: number;
  critical_alerts: number;
  medium_alerts: number;
  avg_inference_latency_ms: number;
  anomaly_rate_pct: number;
  threat_distribution: Record<string, number>;
  risk_distribution: Record<RiskLevel, number>;
}

export interface FlowsResponse {
  count: number;
  risk_level_filter: string;
  flows: AnalyzedFlow[];
  alerts: SecurityAlert[];
}

export interface HealthResponse {
  status: string;
  service: string;
  models_loaded: boolean;
  loaded_artifacts: {
    scaler: boolean;
    mlp_model: boolean;
    autoencoder: boolean;
    rf_model: boolean;
    iforest_model: boolean;
  };
  selected_features: string[];
  hybrid_weights: {
    w_mlp: number;
    w_ae: number;
    threshold: number;
  };
  ws_connections: number;
  live_capture_running?: boolean;
}

export interface CaptureInterfacesResponse {
  interfaces: string[];
  can_capture: boolean;
  default_bpf_filter: string;
}

export interface CaptureStatus {
  running: boolean;
  can_capture: boolean;
  interface: string;
  bpf_filter: string;
  window_seconds: number;
  packets_captured: number;
  flows_evaluated: number;
  alerts_triggered: number;
  started_at: string | null;
  last_window_at: string | null;
  last_error: string | null;
}

export interface CaptureStartRequest {
  interface: string;
  bpf_filter: string;
  window_seconds: number;
}

export interface DatasetSourceBreakdown {
  mode: 'public_only' | 'public_plus_lab' | 'statistical_fallback' | string;
  max_samples_cap?: number;
  raw_files_detected: string[];
  by_file?: Record<
    string,
    { total_loaded: number; by_class: Record<string, number> }
  >;
  public_raw_flows: number;
  fallback_or_lab_flows: number;
  by_class: Record<string, { public_raw: number; fallback_or_lab: number }>;
}

export interface ModelMetricEntry {
  precision: number;
  recall: number;
  f1_score: number;
  avg_latency_ms: number;
  display_name: string;
  paradigm: string;
  multiclass_f1_macro?: number;
}

export interface ConfusionMatrixData {
  labels: string[];
  matrix: number[][];
  tn: number;
  fp: number;
  fn: number;
  tp: number;
}

export interface HybridEnsembleMetrics {
  precision: number;
  recall: number;
  f1_score: number;
  avg_latency_ms: number;
  display_name: string;
  w_mlp: number;
  w_ae: number;
  threshold: number;
  confusion_matrix: ConfusionMatrixData;
}

export interface ModelMetrics {
  dataset: {
    path: string;
    total_flows: number;
    total_features: number;
    selected_features_count: number;
    classes: string[];
    cv_folds: number;
    source_breakdown?: DatasetSourceBreakdown;
  };
  models: {
    random_forest: ModelMetricEntry;
    mlp: ModelMetricEntry;
    autoencoder: ModelMetricEntry;
    isolation_forest: ModelMetricEntry;
  };
  hybrid_ensemble: HybridEnsembleMetrics;
}

export interface GAPhase1Generation {
  generation: number;
  best_fitness: number;
  avg_fitness: number;
  best_f1: number;
  avg_f1: number;
  num_selected_features: number;
  selected_features: string[];
}

export interface GAPhase2Generation {
  generation: number;
  best_f1: number;
  avg_f1: number;
  best_w_mlp: number;
  best_w_ae: number;
  best_threshold: number;
}

export interface GAConfig {
  feature_columns: string[];
  ga_mask: boolean[];
  selected_features: string[];
  discarded_features: string[];
  weights: {
    w_mlp: number;
    w_ae: number;
  };
  threshold: number;
  phase1_feature_selection: {
    best_fitness: number;
    best_f1: number;
    history: GAPhase1Generation[];
  };
  phase2_weight_optimization: {
    best_f1: number;
    history: GAPhase2Generation[];
  };
}

export interface MLMetricsResponse {
  model_metrics: ModelMetrics;
  ga_config: GAConfig;
}

export interface SimulateRequest {
  scenario: ThreatVector;
  count?: number;
  delay_ms?: number;
}

export interface SimulateResponse {
  scenario: string;
  count: number;
  alerts_triggered: number;
  flows: AnalyzedFlow[];
  alerts: SecurityAlert[];
}

export interface FileAnalysisResponse {
  filename: string;
  total_flows_analyzed: number;
  alerts_triggered: number;
  risk_summary: Record<RiskLevel, number>;
  threat_summary: Record<string, number>;
  flows: AnalyzedFlow[];
  alerts: SecurityAlert[];
}

export interface WsConnectedEvent {
  event: 'connected';
  message: string;
}

export interface WsFlowEvaluatedEvent {
  event: 'flow_evaluated';
  source: string;
  flow: AnalyzedFlow;
  alert: SecurityAlert | null;
  captured_demo_token?: string;
}

export type WsAlertMessage = WsConnectedEvent | WsFlowEvaluatedEvent;

export interface LiveFeedItem {
  flow: AnalyzedFlow;
  source: string;
  capturedDemoToken?: string;
}

export const THREAT_VECTORS: ThreatVector[] = [
  'BENIGN',
  'C2_BEACONING',
  'DOH_TUNNEL',
  'EXFILTRATION',
  'PHISHING_AITM',
];

export const THREAT_LABELS: Record<string, string> = {
  BENIGN: 'Tráfico Benigno',
  C2_BEACONING: 'Beaconing C2',
  DOH_TUNNEL: 'Túnel DoH',
  EXFILTRATION: 'Exfiltración',
  PHISHING_AITM: 'Phishing AiTM',
};

export const THREAT_COLORS: Record<string, string> = {
  BENIGN: '#36C995',
  C2_BEACONING: '#E56B6F',
  DOH_TUNNEL: '#5795F2',
  EXFILTRATION: '#F2A544',
  PHISHING_AITM: '#9D8CF5',
};

export const FEATURE_LABELS: Record<string, string> = {
  duration_ms: 'Duración del flujo (ms)',
  bytes_sent: 'Bytes salientes',
  bytes_recv: 'Bytes entrantes',
  byte_asymmetry_ratio: 'Asimetría de bytes',
  packets_sent: 'Paquetes salientes',
  packets_recv: 'Paquetes entrantes',
  iat_mean_ms: 'IAT medio (ms)',
  iat_std_ms: 'Desviación IAT (ms)',
  pkt_size_mean: 'Tamaño medio paquete (B)',
  pkt_size_std: 'Desviación tamaño paquete (B)',
  pkt_size_max: 'Tamaño máximo paquete (B)',
  tls_version_num: 'Versión TLS negociada',
  cipher_suite_count: 'Conteo Cipher Suites',
  sni_entropy: 'Entropía Shannon SNI',
  sni_length: 'Longitud SNI',
  dns_query_rate: 'Tasa consultas DNS/DoH',
  double_hop_latency_ms: 'Latencia doble salto (ms)',
  redirect_count: 'Conteo de redirecciones',
};
