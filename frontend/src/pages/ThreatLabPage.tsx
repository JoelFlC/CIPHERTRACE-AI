import { useState, type KeyboardEvent } from 'react';
import {
  Activity,
  CheckCircle2,
  ExternalLink,
  GlobeLock,
  Play,
  Radio,
  ShieldAlert,
  ShieldCheck,
  UploadCloud,
  Wifi,
} from 'lucide-react';
import { RiskBadge } from '../components/soc/RiskBadge';
import { ThreatBadge } from '../components/soc/ThreatBadge';
import { AlertBanner } from '../components/ui/AlertBanner';
import { BentoCard } from '../components/ui/BentoCard';
import { Button } from '../components/ui/Button';
import { EmptyState } from '../components/ui/EmptyState';
import { SegmentedControl } from '../components/ui/SegmentedControl';
import { BACKEND_ORIGIN, simulateThreat } from '../services/api';
import {
  THREAT_COLORS,
  type AnalyzedFlow,
  type LiveFeedItem,
  type ThreatVector,
} from '../types/ciphertrace';

interface ThreatLabPageProps {
  liveFeed: LiveFeedItem[];
  selectedFlowId?: string | null;
  onSelectFlow: (flow: AnalyzedFlow) => void;
  onSimulationComplete?: () => void;
}

interface ScenarioConfig {
  scenario: ThreatVector;
  title: string;
  subtitle: string;
  telemetryHint: string;
  icon: typeof ShieldCheck;
}

const SCENARIOS: ScenarioConfig[] = [
  {
    scenario: 'BENIGN',
    title: 'Tráfico HTTPS Benigno',
    subtitle: 'Navegación TLS 1.3 directa hacia servicios legítimos.',
    telemetryHint: 'Baja entropía SNI · 0 redirecciones',
    icon: ShieldCheck,
  },
  {
    scenario: 'C2_BEACONING',
    title: 'Beaconing C2',
    subtitle: 'Callbacks periódicos automatizados hacia Command & Control.',
    telemetryHint: 'IAT std muy bajo · paquetes pequeños',
    icon: Radio,
  },
  {
    scenario: 'DOH_TUNNEL',
    title: 'Túnel DNS-over-HTTPS',
    subtitle: 'Canal encubierto sobre consultas DoH cifradas.',
    telemetryHint: 'Alta entropía SNI · tasa DNS elevada',
    icon: Wifi,
  },
  {
    scenario: 'EXFILTRATION',
    title: 'Exfiltración de Datos',
    subtitle: 'Transferencia masiva saliente en ráfagas cercanas al MTU.',
    telemetryHint: 'Asimetría saliente positiva marcada',
    icon: UploadCloud,
  },
  {
    scenario: 'PHISHING_AITM',
    title: 'Phishing Proxy Inverso AiTM',
    subtitle: 'Interceptación de credenciales y cookies MFA en doble salto.',
    telemetryHint: 'Doble salto >200 ms · múltiples redirects',
    icon: ShieldAlert,
  },
];

const BATCH_OPTIONS = [
  { value: 1, label: '1' },
  { value: 3, label: '3' },
  { value: 5, label: '5' },
  { value: 10, label: '10' },
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
  selectedFlowId = null,
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

  const handleRowKeyDown = (
    event: KeyboardEvent<HTMLTableRowElement>,
    flow: AnalyzedFlow,
  ) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onSelectFlow(flow);
    }
  };

  return (
    <div className="space-y-6">
      {/* Row 1: Controlled Traffic Injection */}
      <BentoCard
        title="Panel de inyección controlada de tráfico"
        subtitle={
          <span>
            Genera flujos sintéticos evaluados en vivo sin descifrar payload (
            <span className="tech-mono text-[#F2F4F5]">POST /api/lab/simulate</span>)
          </span>
        }
        action={
          <div className="flex items-center gap-2.5 text-xs">
            <span className="text-[#A1ABB3]">Flujos por lote</span>
            <SegmentedControl
              options={BATCH_OPTIONS}
              value={flowCount}
              onChange={setFlowCount}
              ariaLabel="Cantidad de flujos por lote"
              tabular
            />
          </div>
        }
        headerDivider
      >
        {simError && (
          <AlertBanner variant="error" className="mb-4">
            {simError}
          </AlertBanner>
        )}

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-5">
          {SCENARIOS.map((item) => {
            const Icon = item.icon;
            const isRunning = runningScenario === item.scenario;
            const lastRun = scenarioResults[item.scenario];
            const dotColor = THREAT_COLORS[item.scenario] ?? '#5795F2';

            return (
              <div
                key={item.scenario}
                className="flex flex-col justify-between rounded-xl bg-[#272F35]/65 p-4"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="flex h-8 w-8 items-center justify-center rounded-[10px] bg-[#1C2226] text-[#F2F4F5]">
                      <Icon
                        className="h-4 w-4"
                        style={{ color: dotColor }}
                        strokeWidth={1.75}
                        aria-hidden="true"
                      />
                    </span>
                    <span className="tech-mono text-[11px] text-[#8E99A2]">
                      {item.scenario}
                    </span>
                  </div>

                  <h3 className="mt-3 text-sm font-semibold text-[#F2F4F5]">
                    {item.title}
                  </h3>
                  <p className="mt-1 text-xs leading-relaxed text-[#A1ABB3]">
                    {item.subtitle}
                  </p>
                  <p className="mt-2.5 text-[11px] text-[#8E99A2]">
                    {item.telemetryHint}
                  </p>
                </div>

                <div className="mt-4 space-y-2">
                  <Button
                    variant="secondary"
                    size="sm"
                    loading={isRunning}
                    disabled={runningScenario !== null && !isRunning}
                    onClick={() => void handleRunSimulation(item.scenario)}
                    icon={<Play className="h-3.5 w-3.5 text-[#79ABFF]" strokeWidth={1.75} />}
                    className="w-full"
                  >
                    {isRunning ? 'Inyectando...' : 'Ejecutar simulación'}
                  </Button>

                  {lastRun && (
                    <div className="tabular-nums flex items-center justify-center gap-1.5 text-[11px] font-medium text-[#36C995]">
                      <CheckCircle2 className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
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
      </BentoCard>

      {/* Row 2: Asymmetric Bento — Portal Comparison (7) + 3-Step Guide (5) */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <BentoCard
          noPadding
          title="Portales locales comparativos (AiTM Lab)"
          subtitle="Comparativa controlada entre acceso TLS directo y proxy inverso de doble salto"
          className="xl:col-span-7"
        >
          <div className="grid grid-cols-1 divide-y divide-[#343D43]/60 md:grid-cols-2 md:divide-x md:divide-y-0">
            {/* Legit Portal */}
            <div className="flex flex-col justify-between p-5">
              <div>
                <div className="flex items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 rounded-md border border-[#36C995]/30 bg-[#36C995]/14 px-2 py-0.5 text-[11px] font-medium text-[#36C995]">
                    <GlobeLock className="h-3 w-3" strokeWidth={1.75} aria-hidden="true" />
                    Línea base segura
                  </span>
                  <span className="tech-mono text-[11px] text-[#8E99A2]">
                    /lab/legit-portal
                  </span>
                </div>

                <h3 className="mt-3 text-base font-semibold text-[#F2F4F5]">
                  Portal Legítimo Ficticio
                </h3>
                <p className="mt-1.5 max-w-[65ch] text-xs leading-relaxed text-[#A1ABB3]">
                  Simula un inicio de sesión TLS 1.3 directo al servidor
                  institucional sin intermediarios. Registra latencia nominal
                  (~25 ms) y cero redirecciones.
                </p>
              </div>

              <a
                href={`${BACKEND_ORIGIN}/lab/legit-portal`}
                target="_blank"
                rel="noopener noreferrer"
                className="pressable mt-5 inline-flex h-9 items-center justify-center gap-2 rounded-[10px] border border-[#343D43] bg-[#272F35] px-4 text-xs font-medium text-[#F2F4F5] hover:bg-[#2E383F] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#5795F2]/75"
              >
                <span>Abrir Portal Legítimo</span>
                <ExternalLink className="h-3.5 w-3.5 text-[#36C995]" strokeWidth={1.75} aria-hidden="true" />
              </a>
            </div>

            {/* AiTM Proxy */}
            <div className="flex flex-col justify-between p-5">
              <div>
                <div className="flex items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 rounded-md border border-[#E56B6F]/30 bg-[#E56B6F]/14 px-2 py-0.5 text-[11px] font-medium text-[#F08A8D]">
                    <ShieldAlert className="h-3 w-3" strokeWidth={1.75} aria-hidden="true" />
                    Proxy Adversary-in-the-Middle
                  </span>
                  <span className="tech-mono text-[11px] text-[#8E99A2]">
                    /lab/aitm-proxy
                  </span>
                </div>

                <h3 className="mt-3 text-base font-semibold text-[#F2F4F5]">
                  Proxy Inverso AiTM (Demo)
                </h3>
                <p className="mt-1.5 max-w-[65ch] text-xs leading-relaxed text-[#A1ABB3]">
                  Simula un proxy inverso clonado que retransmite autenticación
                  MFA en doble salto (~280 ms, 5 redirecciones y SNI anómalo)
                  para capturar un token ficticio.
                </p>
              </div>

              <a
                href={`${BACKEND_ORIGIN}/lab/aitm-proxy`}
                target="_blank"
                rel="noopener noreferrer"
                className="pressable mt-5 inline-flex h-9 items-center justify-center gap-2 rounded-[10px] border border-[#E56B6F]/30 bg-[#E56B6F]/14 px-4 text-xs font-semibold text-[#F08A8D] hover:bg-[#E56B6F]/22 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#5795F2]/75"
              >
                <span>Abrir Proxy AiTM (Demo)</span>
                <ExternalLink className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
              </a>
            </div>
          </div>
        </BentoCard>

        <BentoCard
          title="Guía de demostración AiTM"
          subtitle="Secuencia segura sin almacenamiento de credenciales reales"
          className="xl:col-span-5"
          headerDivider
        >
          <ol className="divide-y divide-[#343D43]/55">
            <li className="flex gap-3 py-3 first:pt-0 last:pb-0">
              <span className="tabular-nums flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-[#5795F2]/14 text-xs font-semibold text-[#79ABFF]">
                1
              </span>
              <div className="text-xs">
                <div className="font-medium text-[#F2F4F5]">
                  Abre el Proxy Inverso AiTM en una nueva pestaña
                </div>
                <p className="mt-0.5 leading-relaxed text-[#A1ABB3]">
                  Pulsa <span className="font-medium text-[#F08A8D]">Abrir Proxy AiTM</span>{' '}
                  y mantén esta consola visible para observar el WebSocket.
                </p>
              </div>
            </li>

            <li className="flex gap-3 py-3 first:pt-0 last:pb-0">
              <span className="tabular-nums flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-[#5795F2]/14 text-xs font-semibold text-[#79ABFF]">
                2
              </span>
              <div className="text-xs">
                <div className="font-medium text-[#F2F4F5]">
                  Inicia sesión con credenciales y MFA ficticios
                </div>
                <p className="mt-0.5 leading-relaxed text-[#A1ABB3]">
                  Envía el formulario precargado. El proxy mide únicamente el
                  retardo de doble salto, redirecciones y SNI.
                </p>
              </div>
            </li>

            <li className="flex gap-3 py-3 first:pt-0 last:pb-0">
              <span className="tabular-nums flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-[#5795F2]/14 text-xs font-semibold text-[#79ABFF]">
                3
              </span>
              <div className="text-xs">
                <div className="font-medium text-[#F2F4F5]">
                  Inspecciona la alerta en vivo en el feed inferior
                </div>
                <p className="mt-0.5 leading-relaxed text-[#A1ABB3]">
                  La detección{' '}
                  <span className="tech-mono text-[#B0A1F8]">PHISHING_AITM</span>{' '}
                  aparece al instante; selecciona la fila para abrir su XAI.
                </p>
              </div>
            </li>
          </ol>
        </BentoCard>
      </section>

      {/* Row 3: Live Lab & WebSocket Feed */}
      <BentoCard
        noPadding
        title="Feed en tiempo real del laboratorio y WebSocket"
        subtitle={
          <span>
            Eventos recibidos desde{' '}
            <span className="tech-mono text-[#F2F4F5]">/ws/alerts</span> y
            simulaciones recientes
          </span>
        }
        action={
          <span className="tabular-nums rounded-md border border-[#343D43] bg-[#272F35] px-2.5 py-1 text-xs font-medium text-[#F2F4F5]">
            {liveFeed.length} eventos
          </span>
        }
      >
        {liveFeed.length === 0 ? (
          <EmptyState
            icon={Activity}
            title="Esperando eventos del laboratorio"
            description="Ejecuta una simulación arriba o prueba el Proxy AiTM local para ver los flujos evaluados aquí."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] border-collapse text-left text-[13px]">
              <thead>
                <tr className="border-b border-[#343D43]/60 bg-[#151A1E]/60 text-xs font-medium text-[#A1ABB3]">
                  <th className="px-5 py-3">Hora</th>
                  <th className="px-4 py-3">Origen evento</th>
                  <th className="px-4 py-3">Flujo</th>
                  <th className="px-4 py-3">Vector</th>
                  <th className="px-4 py-3 text-right">Doble salto</th>
                  <th className="px-4 py-3 text-right">Riesgo</th>
                  <th className="px-5 py-3">Nivel</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#343D43]/50">
                {liveFeed.map((item) => {
                  const { flow, source, capturedDemoToken } = item;
                  const doubleHop = flow.features?.double_hop_latency_ms ?? 0;
                  const isSelected = selectedFlowId === flow.flow_id;

                  return (
                    <tr
                      key={`${flow.id}-${flow.flow_id}`}
                      tabIndex={0}
                      role="button"
                      aria-label={`Inspeccionar evento ${flow.flow_id}, vector ${flow.predicted_threat}`}
                      onClick={() => onSelectFlow(flow)}
                      onKeyDown={(e) => handleRowKeyDown(e, flow)}
                      className={`cursor-pointer transition-colors duration-150 focus-visible:bg-[#272F35] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[#5795F2]/75 ${
                        isSelected
                          ? 'bg-[#5795F2]/12'
                          : 'hover:bg-[#272F35]/55'
                      }`}
                    >
                      <td className="tabular-nums whitespace-nowrap px-5 py-3 text-xs text-[#A1ABB3]">
                        {formatClock(flow.timestamp_utc)}
                      </td>
                      <td className="px-4 py-3">
                        <span className="tech-mono rounded-md border border-[#343D43] bg-[#272F35] px-2 py-0.5 text-[11px] text-[#F2F4F5]">
                          {source}
                        </span>
                        {capturedDemoToken && (
                          <div className="tech-mono mt-1 text-[11px] text-[#F08A8D]">
                            Token demo capturado: {capturedDemoToken}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="tech-mono text-xs text-[#F2F4F5]">
                          {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:
                          {flow.dst_port}
                        </div>
                        {flow.sni && (
                          <div className="tech-mono mt-0.5 max-w-xs truncate text-[11px] text-[#8E99A2]">
                            {flow.sni}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <ThreatBadge vector={flow.predicted_threat} />
                      </td>
                      <td className="tabular-nums px-4 py-3 text-right text-[#A1ABB3]">
                        {doubleHop.toFixed(1)} ms
                      </td>
                      <td className="tabular-nums px-4 py-3 text-right font-semibold text-[#F2F4F5]">
                        {flow.risk_score.toFixed(3)}
                      </td>
                      <td className="px-5 py-3">
                        <RiskBadge level={flow.risk_level} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </BentoCard>
    </div>
  );
}
