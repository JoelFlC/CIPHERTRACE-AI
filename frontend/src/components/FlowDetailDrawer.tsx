import { useEffect, useState } from 'react';
import {
  ArrowDownRight,
  ArrowUpRight,
  ChevronDown,
  ChevronRight,
  Lock,
  ShieldCheck,
  X,
} from 'lucide-react';
import {
  FEATURE_LABELS,
  THREAT_COLORS,
  THREAT_LABELS,
  type AnalyzedFlow,
} from '../types/ciphertrace';
import { RiskBadge } from './RiskBadge';

interface FlowDetailDrawerProps {
  flow: AnalyzedFlow | null;
  threshold?: number;
  onClose: () => void;
}

interface ScoreRow {
  label: string;
  subtitle: string;
  value: number;
  accentColor: string;
}

function formatUtcTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString('es-ES', {
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function getScoreBarColor(score: number, threshold: number): string {
  if (score >= threshold) return '#EF4444';
  if (score >= 0.45) return '#F59E0B';
  return '#10B981';
}

export function FlowDetailDrawer({
  flow,
  threshold = 0.5,
  onClose,
}: FlowDetailDrawerProps) {
  const [showAllFeatures, setShowAllFeatures] = useState(false);

  useEffect(() => {
    setShowAllFeatures(false);
  }, [flow?.flow_id]);

  useEffect(() => {
    if (!flow) return;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [flow, onClose]);

  if (!flow) return null;

  const subModelScores: ScoreRow[] = [
    {
      label: 'Red Neuronal MLP',
      subtitle: 'Probabilidad multiclase supervisada',
      value: flow.prob_mlp,
      accentColor: '#06B6D4',
    },
    {
      label: 'PyTorch Autoencoder',
      subtitle: 'Error de reconstrucción (Zero-Day)',
      value: flow.anomaly_ae,
      accentColor: '#38BDF8',
    },
    {
      label: 'Random Forest',
      subtitle: 'Consenso de árboles supervisados',
      value: flow.prob_rf,
      accentColor: '#10B981',
    },
    {
      label: 'Isolation Forest',
      subtitle: 'Aislamiento no supervisado',
      value: flow.anomaly_iforest,
      accentColor: '#F59E0B',
    },
  ];

  const threatColor = THREAT_COLORS[flow.predicted_threat] ?? '#06B6D4';
  const threatLabel =
    THREAT_LABELS[flow.predicted_threat] ?? flow.predicted_threat;
  const featureEntries = Object.entries(flow.features ?? {});

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/65 backdrop-blur-[1px]"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="flow-drawer-title"
    >
      <div
        className="flex h-full w-full max-w-xl flex-col border-l border-[#1F2937] bg-[#111827] shadow-2xl"
        onClick={(event) => event.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="flex items-start justify-between gap-3 border-b border-[#1F2937] bg-[#0D1321] px-5 py-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2
                id="flow-drawer-title"
                className="mono-num truncate text-sm font-semibold text-gray-100"
              >
                {flow.flow_id}
              </h2>
              <RiskBadge level={flow.risk_level} size="sm" />
              <span
                className="mono-num rounded border px-2 py-0.5 text-[11px] font-medium"
                style={{
                  color: threatColor,
                  borderColor: `${threatColor}4D`,
                  backgroundColor: `${threatColor}18`,
                }}
              >
                {flow.predicted_threat} · {threatLabel}
              </span>
            </div>
            <div className="mono-num mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-gray-400">
              <span>{formatUtcTimestamp(flow.timestamp_utc)}</span>
              <span className="text-gray-600">|</span>
              <span>Origen de ingesta: {flow.source}</span>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-[#1F2937] bg-[#111827] p-1.5 text-gray-400 transition-colors hover:border-gray-600 hover:text-gray-100"
            aria-label="Cerrar panel de detalle"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5">
          {/* Passive Verification Badge */}
          <div className="flex items-center gap-3 rounded-md border border-cyan-500/30 bg-cyan-500/10 px-3.5 py-2.5">
            <ShieldCheck className="h-4 w-4 shrink-0 text-[#06B6D4]" />
            <div className="flex-1 text-xs text-cyan-100">
              <span className="font-medium">
                Payload sin descifrar verificado:
              </span>{' '}
              evaluación ejecutada exclusivamente sobre metadatos TLS,
              tamaños de paquete y temporización inter-paquete.
            </div>
            <Lock className="h-3.5 w-3.5 shrink-0 text-cyan-400" />
          </div>

          {/* Flow Metadata Grid */}
          <div className="grid grid-cols-2 gap-3 rounded-md border border-[#1F2937] bg-[#0B0F19] p-3.5 text-xs">
            <div>
              <div className="text-gray-500">Origen</div>
              <div className="mono-num mt-0.5 font-medium text-gray-200">
                {flow.src_ip}:{flow.src_port}
              </div>
            </div>
            <div>
              <div className="text-gray-500">Destino</div>
              <div className="mono-num mt-0.5 font-medium text-gray-200">
                {flow.dst_ip}:{flow.dst_port}
              </div>
            </div>
            <div>
              <div className="text-gray-500">Protocolo / Latencia</div>
              <div className="mono-num mt-0.5 font-medium text-gray-200">
                {flow.protocol} ·{' '}
                <span className="text-[#06B6D4]">
                  {flow.inference_latency_ms.toFixed(2)} ms
                </span>
              </div>
            </div>
            <div>
              <div className="text-gray-500">SNI observado</div>
              <div className="mono-num mt-0.5 truncate font-medium text-gray-200">
                {flow.sni || '— (sin SNI expuesto)'}
              </div>
            </div>
          </div>

          {/* Model Score Breakdown */}
          <section className="rounded-md border border-[#1F2937] bg-[#0B0F19] p-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-300">
                Desglose de Scores por Modelo
              </h3>
              <span className="mono-num text-[11px] text-gray-400">
                Umbral alerta ALTO: {threshold.toFixed(2)}
              </span>
            </div>

            {/* Hybrid Final Score */}
            <div className="mt-3 rounded-md border border-[#1F2937] bg-[#111827] p-3">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-gray-100">
                  Score Híbrido (AG: MLP + Autoencoder)
                </span>
                <span
                  className="mono-num text-sm font-semibold"
                  style={{
                    color: getScoreBarColor(flow.risk_score, threshold),
                  }}
                >
                  {flow.risk_score.toFixed(4)}
                </span>
              </div>
              <div className="relative mt-2 h-2.5 w-full overflow-hidden rounded-sm bg-[#0B0F19]">
                <div
                  className="h-full transition-all duration-300"
                  style={{
                    width: `${Math.min(100, Math.max(2, flow.risk_score * 100))}%`,
                    backgroundColor: getScoreBarColor(
                      flow.risk_score,
                      threshold,
                    ),
                  }}
                />
                <div
                  className="absolute inset-y-0 w-0.5 bg-gray-100/80"
                  style={{ left: `${threshold * 100}%` }}
                  title={`Umbral ${threshold.toFixed(2)}`}
                />
              </div>
            </div>

            {/* Individual Models */}
            <div className="mt-3 space-y-3">
              {subModelScores.map((model) => (
                <div key={model.label}>
                  <div className="flex items-baseline justify-between text-xs">
                    <div>
                      <span className="font-medium text-gray-200">
                        {model.label}
                      </span>
                      <span className="ml-2 text-[11px] text-gray-500">
                        {model.subtitle}
                      </span>
                    </div>
                    <span className="mono-num font-medium text-gray-200">
                      {model.value.toFixed(4)}
                    </span>
                  </div>
                  <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-sm bg-[#111827]">
                    <div
                      className="h-full rounded-sm transition-all duration-300"
                      style={{
                        width: `${Math.min(100, Math.max(1.5, model.value * 100))}%`,
                        backgroundColor: model.accentColor,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Explainable AI (XAI) Section */}
          <section className="rounded-md border border-[#1F2937] bg-[#0B0F19] p-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-300">
                Explicabilidad (XAI) — Factores Determinantes
              </h3>
              <span className="mono-num text-[11px] text-[#06B6D4]">
                Top {flow.top_contributing_features.length} desviaciones
              </span>
            </div>

            <div className="mt-3 space-y-2.5">
              {flow.top_contributing_features.map((item) => {
                const isHigh = item.direction === 'elevado';
                return (
                  <div
                    key={item.feature}
                    className="rounded-md border border-[#1F2937] bg-[#111827] p-3"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="mono-num text-xs font-semibold text-cyan-300">
                          {item.feature}
                        </span>
                        <span className="text-[11px] text-gray-400">
                          ({FEATURE_LABELS[item.feature] ?? item.feature})
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5">
                        <span
                          className={`inline-flex items-center gap-0.5 rounded border px-1.5 py-0.5 text-[10px] font-medium ${
                            isHigh
                              ? 'border-red-500/30 bg-red-500/10 text-red-400'
                              : 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                          }`}
                        >
                          {isHigh ? (
                            <ArrowUpRight className="h-3 w-3" />
                          ) : (
                            <ArrowDownRight className="h-3 w-3" />
                          )}
                          {item.direction}
                        </span>
                        <span className="mono-num rounded border border-[#1F2937] bg-[#0B0F19] px-1.5 py-0.5 text-[11px] text-gray-300">
                          z = {item.z_score >= 0 ? '+' : ''}
                          {item.z_score.toFixed(2)}
                        </span>
                      </div>
                    </div>

                    <p className="mt-2 text-xs leading-relaxed text-gray-300">
                      {item.explanation}
                    </p>

                    <div className="mono-num mt-2 flex items-center gap-4 border-t border-[#1F2937] pt-2 text-[11px] text-gray-400">
                      <span>
                        Observado:{' '}
                        <strong className="text-gray-100">
                          {item.value.toLocaleString('es-ES', {
                            maximumFractionDigits: 4,
                          })}
                        </strong>
                      </span>
                      <span>
                        Media benigna:{' '}
                        <strong className="text-gray-300">
                          {item.benign_mean.toLocaleString('es-ES', {
                            maximumFractionDigits: 4,
                          })}
                        </strong>
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Collapsible 18 Passive Features */}
          {featureEntries.length > 0 && (
            <section className="rounded-md border border-[#1F2937] bg-[#0B0F19]">
              <button
                type="button"
                onClick={() => setShowAllFeatures((prev) => !prev)}
                className="flex w-full items-center justify-between px-4 py-3 text-left text-xs font-medium text-gray-300 transition-colors hover:bg-[#111827]"
              >
                <span>
                  Vector Completo de Metadatos Pasivos ({featureEntries.length}{' '}
                  atributos)
                </span>
                {showAllFeatures ? (
                  <ChevronDown className="h-4 w-4 text-gray-400" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-gray-400" />
                )}
              </button>

              {showAllFeatures && (
                <div className="grid grid-cols-2 gap-2 border-t border-[#1F2937] p-3.5 text-xs">
                  {featureEntries.map(([key, val]) => (
                    <div
                      key={key}
                      className="flex items-center justify-between rounded border border-[#1F2937] bg-[#111827] px-2.5 py-1.5"
                    >
                      <span className="mono-num truncate text-[11px] text-gray-400">
                        {key}
                      </span>
                      <span className="mono-num ml-2 text-[11px] font-medium text-gray-200">
                        {Number(val).toLocaleString('es-ES', {
                          maximumFractionDigits: 4,
                        })}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
