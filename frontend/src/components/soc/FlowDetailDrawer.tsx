import { useCallback, useEffect, useRef, useState } from 'react';
import {
  ArrowDownRight,
  ArrowUpRight,
  ChevronDown,
  ChevronRight,
  Lock,
  X,
} from 'lucide-react';
import {
  FEATURE_LABELS,
  type AnalyzedFlow,
} from '../../types/ciphertrace';
import { AlertBanner } from '../ui/AlertBanner';
import { RiskBadge } from './RiskBadge';
import { ThreatBadge } from './ThreatBadge';

interface FlowDetailDrawerProps {
  flow: AnalyzedFlow | null;
  threshold?: number;
  onClose: () => void;
}

interface ScoreRow {
  label: string;
  subtitle: string;
  value: number;
  barColor: string;
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
  if (score >= threshold) return '#E56B6F';
  if (score >= 0.45) return '#F2A544';
  return '#36C995';
}

function getScoreTextColor(score: number, threshold: number): string {
  if (score >= threshold) return '#F08A8D';
  if (score >= 0.45) return '#F2A544';
  return '#36C995';
}

/**
 * Slide-over XAI inspection panel with Emil Kowalski drawer timing and focus restoration.
 */
export function FlowDetailDrawer({
  flow,
  threshold = 0.5,
  onClose,
}: FlowDetailDrawerProps) {
  const [renderedFlow, setRenderedFlow] = useState<AnalyzedFlow | null>(flow);
  const [isVisible, setIsVisible] = useState<boolean>(false);
  const [showAllFeatures, setShowAllFeatures] = useState(false);

  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (flow) {
      if (!returnFocusRef.current && document.activeElement instanceof HTMLElement) {
        returnFocusRef.current = document.activeElement;
      }
      setRenderedFlow(flow);
      setShowAllFeatures(false);
      const raf = window.requestAnimationFrame(() => setIsVisible(true));
      return () => window.cancelAnimationFrame(raf);
    } else if (renderedFlow) {
      setIsVisible(false);
      const timer = window.setTimeout(() => {
        setRenderedFlow(null);
        returnFocusRef.current?.focus();
        returnFocusRef.current = null;
      }, 210);
      return () => window.clearTimeout(timer);
    }
  }, [flow, renderedFlow]);

  const requestClose = useCallback(() => {
    onClose();
  }, [onClose]);

  useEffect(() => {
    if (isVisible && closeButtonRef.current) {
      closeButtonRef.current.focus();
    }
  }, [isVisible]);

  useEffect(() => {
    if (!renderedFlow) return;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        requestClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [renderedFlow, requestClose]);

  if (!renderedFlow) return null;

  const subModelScores: ScoreRow[] = [
    {
      label: 'Red Neuronal MLP',
      subtitle: 'Probabilidad multiclase supervisada',
      value: renderedFlow.prob_mlp,
      barColor: '#5795F2',
    },
    {
      label: 'PyTorch Autoencoder',
      subtitle: 'Error de reconstrucción (Zero-Day)',
      value: renderedFlow.anomaly_ae,
      barColor: '#79ABFF',
    },
    {
      label: 'Random Forest',
      subtitle: 'Consenso de árboles supervisados',
      value: renderedFlow.prob_rf,
      barColor: '#36C995',
    },
    {
      label: 'Isolation Forest',
      subtitle: 'Aislamiento no supervisado',
      value: renderedFlow.anomaly_iforest,
      barColor: '#F2A544',
    },
  ];

  const featureEntries = Object.entries(renderedFlow.features ?? {});

  return (
    <div
      className={`drawer-backdrop fixed inset-0 z-50 flex justify-end bg-black/65 ${
        isVisible ? 'opacity-100' : 'pointer-events-none opacity-0'
      }`}
      onClick={requestClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="flow-drawer-title"
    >
      <div
        data-state={isVisible ? 'open' : 'closing'}
        className={`drawer-panel flex h-full w-full max-w-xl flex-col rounded-l-[20px] border-l border-[#343D43] bg-[#1C2226] shadow-[0_16px_48px_rgba(0,0,0,0.55)] ${
          isVisible ? 'translate-x-0' : 'translate-x-full'
        }`}
        onClick={(event) => event.stopPropagation()}
      >
        {/* Fixed Header */}
        <div className="flex items-start justify-between gap-3 border-b border-[#343D43]/70 bg-[#151A1E] px-6 py-4 rounded-tl-[20px]">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2
                id="flow-drawer-title"
                className="tech-mono truncate text-sm font-semibold text-[#F2F4F5]"
              >
                {renderedFlow.flow_id}
              </h2>
              <RiskBadge level={renderedFlow.risk_level} size="sm" />
              <ThreatBadge vector={renderedFlow.predicted_threat} />
            </div>
            <div className="tabular-nums mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[#A1ABB3]">
              <span>{formatUtcTimestamp(renderedFlow.timestamp_utc)}</span>
              <span className="text-[#8E99A2]">·</span>
              <span>
                Origen:{' '}
                <span className="tech-mono text-[#F2F4F5]">
                  {renderedFlow.source}
                </span>
              </span>
            </div>
          </div>

          <button
            ref={closeButtonRef}
            type="button"
            onClick={requestClose}
            className="pressable rounded-[10px] border border-[#343D43] bg-[#272F35] p-1.5 text-[#A1ABB3] hover:text-[#F2F4F5] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#5795F2]/75"
            aria-label="Cerrar panel de detalle"
          >
            <X className="h-4 w-4" strokeWidth={1.75} />
          </button>
        </div>

        {/* Scrollable Content separated by clean hairlines */}
        <div className="flex-1 divide-y divide-[#343D43]/60 overflow-y-auto px-6">
          <div className="py-4">
            <AlertBanner variant="info">
              <div className="flex items-center justify-between gap-2">
                <span>
                  <strong className="font-semibold">
                    Payload sin descifrar verificado:
                  </strong>{' '}
                  evaluación sobre metadatos TLS, tamaños de paquete y
                  temporización inter-paquete.
                </span>
                <Lock className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              </div>
            </AlertBanner>
          </div>

          {/* Network Metadata */}
          <section className="grid grid-cols-2 gap-x-4 gap-y-3 py-4 text-xs">
            <div>
              <div className="text-[#A1ABB3]">Origen</div>
              <div className="tech-mono mt-0.5 font-medium text-[#F2F4F5]">
                {renderedFlow.src_ip}:{renderedFlow.src_port}
              </div>
            </div>
            <div>
              <div className="text-[#A1ABB3]">Destino</div>
              <div className="tech-mono mt-0.5 font-medium text-[#F2F4F5]">
                {renderedFlow.dst_ip}:{renderedFlow.dst_port}
              </div>
            </div>
            <div>
              <div className="text-[#A1ABB3]">Protocolo / Latencia</div>
              <div className="tabular-nums mt-0.5 font-medium text-[#F2F4F5]">
                {renderedFlow.protocol} ·{' '}
                <span className="text-[#79ABFF]">
                  {renderedFlow.inference_latency_ms.toFixed(2)} ms
                </span>
              </div>
            </div>
            <div>
              <div className="text-[#A1ABB3]">SNI observado</div>
              <div className="tech-mono mt-0.5 truncate font-medium text-[#F2F4F5]">
                {renderedFlow.sni || '— (sin SNI expuesto)'}
              </div>
            </div>
          </section>

          {/* Model Scores Breakdown */}
          <section className="py-5">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-[#F2F4F5]">
                Desglose de scores por modelo
              </h3>
              <span className="tabular-nums text-xs text-[#A1ABB3]">
                Umbral ALTO: {threshold.toFixed(2)}
              </span>
            </div>

            <div className="mt-3 rounded-[10px] bg-[#272F35] p-3.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-[#F2F4F5]">
                  Score Híbrido (AG: MLP + Autoencoder)
                </span>
                <span
                  className="tabular-nums text-sm font-semibold"
                  style={{
                    color: getScoreTextColor(renderedFlow.risk_score, threshold),
                  }}
                >
                  {renderedFlow.risk_score.toFixed(4)}
                </span>
              </div>
              <div className="relative mt-2.5 h-2 w-full overflow-hidden rounded-full bg-[#101416]">
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${Math.min(
                      100,
                      Math.max(2, renderedFlow.risk_score * 100),
                    )}%`,
                    backgroundColor: getScoreBarColor(
                      renderedFlow.risk_score,
                      threshold,
                    ),
                  }}
                />
                <div
                  className="absolute inset-y-0 w-0.5 bg-[#F2F4F5]/80"
                  style={{ left: `${threshold * 100}%` }}
                  title={`Umbral ${threshold.toFixed(2)}`}
                />
              </div>
            </div>

            <div className="mt-4 space-y-3">
              {subModelScores.map((model) => (
                <div key={model.label}>
                  <div className="flex items-baseline justify-between gap-2 text-xs">
                    <div className="min-w-0">
                      <span className="font-medium text-[#F2F4F5]">
                        {model.label}
                      </span>
                      <span className="ml-2 text-[#A1ABB3]">
                        {model.subtitle}
                      </span>
                    </div>
                    <span className="tabular-nums shrink-0 font-medium text-[#F2F4F5]">
                      {model.value.toFixed(4)}
                    </span>
                  </div>
                  <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-[#272F35]">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${Math.min(
                          100,
                          Math.max(1.5, model.value * 100),
                        )}%`,
                        backgroundColor: model.barColor,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* XAI Section */}
          <section className="py-5">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-[#F2F4F5]">
                Explicabilidad (XAI) — Factores determinantes
              </h3>
              <span className="tabular-nums text-xs text-[#79ABFF]">
                Top {renderedFlow.top_contributing_features.length} desviaciones
              </span>
            </div>

            <div className="mt-3 divide-y divide-[#343D43]/50">
              {renderedFlow.top_contributing_features.map((item) => {
                const isHigh = item.direction === 'elevado';
                return (
                  <div key={item.feature} className="py-3.5 first:pt-1 last:pb-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="min-w-0">
                        <span className="text-xs font-semibold text-[#F2F4F5]">
                          {FEATURE_LABELS[item.feature] ?? item.feature}
                        </span>
                        <span className="tech-mono ml-2 text-[11px] text-[#8E99A2]">
                          {item.feature}
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5">
                        <span
                          className={`inline-flex items-center gap-0.5 rounded-md border px-2 py-0.5 text-[11px] font-medium ${
                            isHigh
                              ? 'border-[#E56B6F]/30 bg-[#E56B6F]/14 text-[#F08A8D]'
                              : 'border-[#F2A544]/30 bg-[#F2A544]/14 text-[#F2A544]'
                          }`}
                        >
                          {isHigh ? (
                            <ArrowUpRight className="h-3 w-3" aria-hidden="true" />
                          ) : (
                            <ArrowDownRight className="h-3 w-3" aria-hidden="true" />
                          )}
                          {item.direction}
                        </span>
                        <span className="tabular-nums rounded-md border border-[#343D43] bg-[#272F35] px-2 py-0.5 text-[11px] font-medium text-[#F2F4F5]">
                          z = {item.z_score >= 0 ? '+' : ''}
                          {item.z_score.toFixed(2)}
                        </span>
                      </div>
                    </div>

                    <p className="mt-1.5 max-w-[65ch] text-xs leading-relaxed text-[#A1ABB3]">
                      {item.explanation}
                    </p>

                    <div className="tabular-nums mt-2 flex flex-wrap items-center gap-4 text-xs text-[#A1ABB3]">
                      <span>
                        Observado:{' '}
                        <strong className="font-semibold text-[#F2F4F5]">
                          {item.value.toLocaleString('es-ES', {
                            maximumFractionDigits: 4,
                          })}
                        </strong>
                      </span>
                      <span>
                        Media benigna:{' '}
                        <strong className="font-medium text-[#F2F4F5]">
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
            <section className="py-4">
              <button
                type="button"
                aria-expanded={showAllFeatures}
                onClick={() => setShowAllFeatures((prev) => !prev)}
                className="flex w-full items-center justify-between rounded-[10px] py-1.5 text-left text-xs font-medium text-[#F2F4F5] hover:text-[#79ABFF] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#5795F2]/75"
              >
                <span>
                  Vector completo de metadatos pasivos ({featureEntries.length}{' '}
                  atributos)
                </span>
                {showAllFeatures ? (
                  <ChevronDown className="h-4 w-4 text-[#A1ABB3]" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-[#A1ABB3]" />
                )}
              </button>

              {showAllFeatures && (
                <div className="mt-3 grid grid-cols-1 gap-x-4 gap-y-2 rounded-[10px] bg-[#272F35]/60 p-3.5 text-xs sm:grid-cols-2">
                  {featureEntries.map(([key, val]) => (
                    <div
                      key={key}
                      className="flex items-center justify-between border-b border-[#343D43]/40 py-1 last:border-b-0"
                    >
                      <span className="tech-mono truncate text-[11px] text-[#A1ABB3]">
                        {key}
                      </span>
                      <span className="tabular-nums ml-2 font-medium text-[#F2F4F5]">
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
