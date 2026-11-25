import { useState } from 'react';
import {
  CheckCircle2,
  ExternalLink,
  GlobeLock,
  Loader2,
  Play,
  Radio,
  ServerCrash,
  ShieldAlert,
  ShieldCheck,
  UploadCloud,
  Wifi,
} from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import { BACKEND_ORIGIN, simulateThreat } from '../services/api';
import {
  THREAT_COLORS,
  type AnalyzedFlow,
  type LiveFeedItem,
  type ThreatVector,
} from '../types/ciphertrace';

interface ThreatLabPageProps {
  liveFeed: LiveFeedItem[];
  onSelectFlow: (flow: AnalyzedFlow) => void;
  onSimulationComplete?: () => void;
}

interface ScenarioCardConfig {
  scenario: ThreatVector;
  title: string;
  subtitle: string;
  telemetryHint: string;
  accentColor: string;
  icon: typeof ShieldCheck;
}

const SCENARIO_CARDS: ScenarioCardConfig[] = [
  {
    scenario: 'BENIGN',
    title: 'Tráfico HTTPS Benigno',
    subtitle: 'Navegación TLS 1.3 directa hacia servicios legítimos.',
    telemetryHint: 'Baja entropía SNI · 0 redirecciones',
    accentColor: '#10B981',
    icon: ShieldCheck,
  },
  {
    scenario: 'C2_BEACONING',
    title: 'Beaconing C2',
    subtitle: 'Callbacks periódicos automatizados hacia Command & Control.',
    telemetryHint: 'IAT std muy bajo · paquetes pequeños',
    accentColor: '#EF4444',
    icon: Radio,
  },
  {
    scenario: 'DOH_TUNNEL',
    title: 'Túnel DNS-over-HTTPS',
    subtitle: 'Exfiltración y canal encubierto sobre consultas DoH cifradas.',
    telemetryHint: 'Alta entropía SNI · tasa DNS elevada',
    accentColor: '#06B6D4',
    icon: Wifi,
  },
  {
    scenario: 'EXFILTRATION',
    title: 'Exfiltración de Datos',
    subtitle: 'Transferencia masiva saliente en ráfagas cercanas al MTU.',
    telemetryHint: 'Asimetría saliente positiva marcada',
    accentColor: '#F59E0B',
    icon: UploadCloud,
  },
  {
    scenario: 'PHISHING_AITM',
    title: 'Phishing Proxy Inverso AiTM',
    subtitle: 'Interceptación de credenciales y cookies MFA mediante doble salto.',
    telemetryHint: 'Doble salto >200 ms · múltiples redirects',
    accentColor: '#F43F5E',
    icon: ShieldAlert,
  },
];

function formatClock(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString('es-ES', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function ThreatLabPage({
  liveFeed,
  onSelectFlow,
  onSimulationComplete,
}: ThreatLabPageProps) {
  const [flowCount, setFlowCount] = useState<number>(5);
  const [runningScenario, setRunningScenario] = useState<ThreatVector | null>(
    null,
  );
  const [scenarioResults, setScenarioResults] = useState<
    Partial<Record<ThreatVector, { count: number; alerts: number }>>
  >({});
  const [simError, setSimError] = useState<string | null>(null);

  const handleRunSimulation = async (scenario: ThreatVector) => {
    setSimError(null);
    setRunningScenario(scenario);
    try {
      const response = await simulateThreat({
        scenario,
        count: flowCount,
        delay_ms: 120,
      });
      setScenarioResults((prev) => ({
        ...prev,
        [scenario]: {
          count: response.count,
          alerts: response.alerts_triggered,
        },
      }));
      onSimulationComplete?.();
    } catch (err) {
      setSimError(
        err instanceof Error
          ? err.message
          : 'Error al ejecutar la simulación en el backend.',
      );
    } finally {
      setRunningScenario(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Section 1: Controlled Threat Injection */}
      <section className="rounded-lg border border-[#1F2937] bg-[#111827] p-5">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#1F2937] pb-4">
          <div>
            <h2 className="text-sm font-semibold text-gray-100">
              Panel de Inyección Controlada de Tráfico
            </h2>
            <p className="mt-0.5 text-xs text-gray-400">
              Genera flujos sintéticos evaluados en vivo por el motor híbrido
              sin descifrar payload (<span className="mono-num">POST /api/lab/simulate</span>)
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="text-gray-400">Flujos por lote:</span>
            <div className="inline-flex rounded-md border border-[#1F2937] bg-[#0B0F19] p-0.5">
              {[1, 3, 5, 10].map((qty) => (
                <button
                  key={qty}
                  type="button"
                  onClick={() => setFlowCount(qty)}
                  className={`mono-num rounded px-2.5 py-1 text-xs transition-colors ${
                    flowCount === qty
                      ? 'bg-[#1F2937] text-cyan-300'
                      : 'text-gray-400 hover:text-gray-200'
                  }`}
                >
                  {qty}
                </button>
              ))}
            </div>
          </div>
        </div>

        {simError && (
          <div className="mt-4 flex items-center gap-2 rounded-md border border-red-500/30 bg-red-500/10 px-3.5 py-2.5 text-xs text-red-300">
            <ServerCrash className="h-4 w-4 shrink-0" />
            <span>{simError}</span>
          </div>
        )}

        <div className="mt-4 grid grid-cols-1 gap-3.5 md:grid-cols-2 xl:grid-cols-5">
          {SCENARIO_CARDS.map((card) => {
            const Icon = card.icon;
            const isRunning = runningScenario === card.scenario;
            const lastRun = scenarioResults[card.scenario];

            return (
              <div
                key={card.scenario}
                className="flex flex-col justify-between rounded-md border border-[#1F2937] bg-[#0B0F19] p-4"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span
                      className="flex h-8 w-8 items-center justify-center rounded border"
                      style={{
                        color: card.accentColor,
                        borderColor: `${card.accentColor}40`,
                        backgroundColor: `${card.accentColor}14`,
                      }}
                    >
                      <Icon className="h-4 w-4" />
                    </span>
                    <span className="mono-num text-[10px] text-gray-500">
                      {card.scenario}
                    </span>
                  </div>

                  <h3 className="mt-3 text-sm font-semibold text-gray-100">
                    {card.title}
                  </h3>
                  <p className="mt-1 text-xs leading-relaxed text-gray-400">
                    {card.subtitle}
                  </p>
                  <div className="mono-num mt-2.5 rounded border border-[#1F2937] bg-[#111827] px-2 py-1 text-[10px] text-gray-400">
                    {card.telemetryHint}
                  </div>
                </div>

                <div className="mt-4 space-y-2">
                  <button
                    type="button"
                    disabled={runningScenario !== null}
                    onClick={() => void handleRunSimulation(card.scenario)}
                    className="flex w-full items-center justify-center gap-2 rounded-md border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-xs font-medium text-cyan-200 transition-colors hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {isRunning ? (
                      <>
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        <span>Inyectando...</span>
                      </>
                    ) : (
                      <>
                        <Play className="h-3.5 w-3.5" />
                        <span>Ejecutar Simulación</span>
                      </>
                    )}
                  </button>

                  {lastRun && (
                    <div className="mono-num flex items-center justify-center gap-1.5 text-[11px] text-emerald-400">
                      <CheckCircle2 className="h-3 w-3" />
                      <span>
                        {lastRun.count} flujos · {lastRun.alerts} alertas
                      </span>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Section 2: Local AiTM Web Lab & 3-Step Guide */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        {/* Portal Comparison Cards */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:col-span-7">
          <div className="flex flex-col justify-between rounded-lg border border-emerald-500/30 bg-[#111827] p-5">
            <div>
              <div className="flex items-center justify-between">
                <span className="inline-flex items-center gap-1.5 rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-400">
                  <GlobeLock className="h-3 w-3" />
                  Línea Base Segura
                </span>
                <span className="mono-num text-[11px] text-gray-500">
                  /lab/legit-portal
                </span>
              </div>
              <h3 className="mt-3 text-base font-semibold text-gray-100">
                Portal Legítimo Ficticio
              </h3>
              <p className="mt-1.5 text-xs leading-relaxed text-gray-400">
                Simula un inicio de sesión TLS 1.3 directo al servidor
                institucional sin intermediarios. Registra latencia nominal (~25
                ms) y cero redirecciones.
              </p>
            </div>

            <a
              href={`${BACKEND_ORIGIN}/lab/legit-portal`}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-5 inline-flex items-center justify-center gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-4 py-2.5 text-xs font-semibold text-emerald-300 transition-colors hover:bg-emerald-500/20"
            >
              <span>Abrir Portal Legítimo</span>
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          </div>

          <div className="flex flex-col justify-between rounded-lg border border-red-500/30 bg-[#111827] p-5">
            <div>
              <div className="flex items-center justify-between">
                <span className="inline-flex items-center gap-1.5 rounded border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[11px] font-medium text-red-400">
                  <ShieldAlert className="h-3 w-3" />
                  Proxy Adversary-in-the-Middle
                </span>
                <span className="mono-num text-[11px] text-gray-500">
                  /lab/aitm-proxy
                </span>
              </div>
              <h3 className="mt-3 text-base font-semibold text-gray-100">
                Proxy Inverso AiTM (Demo)
              </h3>
              <p className="mt-1.5 text-xs leading-relaxed text-gray-400">
                Simula un proxy inverso clonado que retransmite autenticación MFA
                en doble salto (~280 ms, 5 redirecciones y SNI anómalo) para
                capturar un token ficticio.
              </p>
            </div>

            <a
              href={`${BACKEND_ORIGIN}/lab/aitm-proxy`}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-5 inline-flex items-center justify-center gap-2 rounded-md border border-red-500/40 bg-red-500/10 px-4 py-2.5 text-xs font-semibold text-red-300 transition-colors hover:bg-red-500/20"
            >
              <span>Abrir Proxy AiTM (Demo)</span>
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          </div>
        </div>

        {/* 3-Step Visual Guide */}
        <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-5 xl:col-span-5">
          <h3 className="text-sm font-semibold text-gray-100">
            Guía de Demostración AiTM en 3 Pasos
          </h3>
          <p className="mt-0.5 text-xs text-gray-400">
            Flujo seguro sin almacenamiento de contraseñas reales
          </p>

          <ol className="mt-4 space-y-3">
            <li className="flex gap-3 rounded-md border border-[#1F2937] bg-[#0B0F19] p-3">
              <span className="mono-num flex h-6 w-6 shrink-0 items-center justify-center rounded border border-cyan-500/30 bg-cyan-500/10 text-xs font-semibold text-cyan-300">
                1
              </span>
              <div className="text-xs">
                <div className="font-medium text-gray-100">
                  Abre el Proxy Inverso AiTM en una nueva pestaña
                </div>
                <div className="mt-0.5 text-gray-400">
                  Pulsa <span className="text-red-300">Abrir Proxy AiTM</span>{' '}
                  y mantén esta consola SOC visible para observar el WebSocket.
                </div>
              </div>
            </li>

            <li className="flex gap-3 rounded-md border border-[#1F2937] bg-[#0B0F19] p-3">
              <span className="mono-num flex h-6 w-6 shrink-0 items-center justify-center rounded border border-cyan-500/30 bg-cyan-500/10 text-xs font-semibold text-cyan-300">
                2
              </span>
              <div className="text-xs">
                <div className="font-medium text-gray-100">
                  Inicia sesión con credenciales y MFA ficticios
                </div>
                <div className="mt-0.5 text-gray-400">
                  Envía el formulario precargado. El proxy mide únicamente el
                  retardo de doble salto, redirecciones y SNI.
                </div>
              </div>
            </li>

            <li className="flex gap-3 rounded-md border border-[#1F2937] bg-[#0B0F19] p-3">
              <span className="mono-num flex h-6 w-6 shrink-0 items-center justify-center rounded border border-cyan-500/30 bg-cyan-500/10 text-xs font-semibold text-cyan-300">
                3
              </span>
              <div className="text-xs">
                <div className="font-medium text-gray-100">
                  Inspecciona la alerta en vivo en el feed inferior
                </div>
                <div className="mt-0.5 text-gray-400">
                  La detección{' '}
                  <span className="mono-num text-red-400">PHISHING_AITM</span>{' '}
                  aparece al instante; haz clic en la fila para ver su XAI.
                </div>
              </div>
            </li>
          </ol>
        </div>
      </section>

      {/* Section 3: Live Lab Feed */}
      <section className="rounded-lg border border-[#1F2937] bg-[#111827]">
        <div className="flex items-center justify-between border-b border-[#1F2937] px-4 py-3">
          <div>
            <h2 className="text-sm font-semibold text-gray-100">
              Feed en Tiempo Real del Laboratorio y WebSocket
            </h2>
            <p className="text-xs text-gray-400">
              Eventos recibidos desde <span className="mono-num">/ws/alerts</span>{' '}
              y simulaciones recientes
            </p>
          </div>
          <span className="mono-num rounded border border-[#1F2937] bg-[#0B0F19] px-2.5 py-1 text-xs text-gray-300">
            {liveFeed.length} eventos
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[860px] border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-[#1F2937] bg-[#0D1321] text-[11px] font-medium uppercase tracking-wider text-gray-400">
                <th className="px-4 py-2.5">Hora</th>
                <th className="px-4 py-2.5">Origen Evento</th>
                <th className="px-4 py-2.5">Flujo</th>
                <th className="px-4 py-2.5">Vector</th>
                <th className="px-4 py-2.5 text-right">Doble Salto</th>
                <th className="px-4 py-2.5 text-right">Riesgo</th>
                <th className="px-4 py-2.5">Nivel</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2937]">
              {liveFeed.length === 0 ? (
                <tr>
                  <td
                    colSpan={7}
                    className="px-4 py-10 text-center text-xs text-gray-500"
                  >
                    Esperando eventos del laboratorio. Ejecuta una simulación o
                    prueba el Proxy AiTM local.
                  </td>
                </tr>
              ) : (
                liveFeed.map((item) => {
                  const { flow, source, capturedDemoToken } = item;
                  const doubleHop = flow.features?.double_hop_latency_ms ?? 0;
                  const vecColor =
                    THREAT_COLORS[flow.predicted_threat] ?? '#9CA3AF';

                  return (
                    <tr
                      key={`${flow.id}-${flow.flow_id}`}
                      onClick={() => onSelectFlow(flow)}
                      className="cursor-pointer transition-colors hover:bg-[#1F2937]/45"
                    >
                      <td className="mono-num whitespace-nowrap px-4 py-2.5 text-gray-400">
                        {formatClock(flow.timestamp_utc)}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="mono-num rounded border border-[#1F2937] bg-[#0B0F19] px-2 py-0.5 text-[11px] text-gray-300">
                          {source}
                        </span>
                        {capturedDemoToken && (
                          <div className="mono-num mt-1 text-[10px] text-red-400">
                            Token demo capturado: {capturedDemoToken}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="mono-num text-gray-200">
                          {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:
                          {flow.dst_port}
                        </div>
                        {flow.sni && (
                          <div className="mono-num max-w-xs truncate text-[11px] text-gray-500">
                            {flow.sni}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className="mono-num rounded border px-2 py-0.5 text-[11px]"
                          style={{
                            color: vecColor,
                            borderColor: `${vecColor}40`,
                            backgroundColor: `${vecColor}14`,
                          }}
                        >
                          {flow.predicted_threat}
                        </span>
                      </td>
                      <td className="mono-num px-4 py-2.5 text-right text-gray-300">
                        {doubleHop.toFixed(1)} ms
                      </td>
                      <td className="mono-num px-4 py-2.5 text-right font-semibold text-gray-100">
                        {flow.risk_score.toFixed(3)}
                      </td>
                      <td className="px-4 py-2.5">
                        <RiskBadge level={flow.risk_level} />
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
