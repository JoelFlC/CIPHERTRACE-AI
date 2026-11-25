import { useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Clock,
  ShieldAlert,
  TrendingUp,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { RiskBadge } from '../components/RiskBadge';
import {
  THREAT_COLORS,
  THREAT_LABELS,
  THREAT_VECTORS,
  type AnalyzedFlow,
  type DashboardSummary,
  type RiskFilter,
} from '../types/ciphertrace';

interface OverviewPageProps {
  summary: DashboardSummary | null;
  flows: AnalyzedFlow[];
  loading: boolean;
  error: string | null;
  threshold: number;
  onSelectFlow: (flow: AnalyzedFlow) => void;
}

interface TimelinePoint {
  timeLabel: string;
  risk_score: number;
  flow_id: string;
  predicted_threat: string;
  risk_level: string;
  route: string;
}

interface RiskTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: TimelinePoint }>;
}

interface ThreatSlice {
  name: string;
  label: string;
  value: number;
  color: string;
}

interface ThreatTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: ThreatSlice }>;
}

function formatClockTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString('es-ES', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function RiskAreaTooltip({ active, payload }: RiskTooltipProps) {
  if (!active || !payload || payload.length === 0) return null;
  const pt = payload[0].payload;
  return (
    <div className="rounded-md border border-[#1F2937] bg-[#0B0F19] px-3 py-2 text-xs shadow-lg">
      <div className="mono-num font-semibold text-cyan-300">
        Risk Score: {pt.risk_score.toFixed(4)} ({pt.risk_level})
      </div>
      <div className="mono-num mt-1 text-gray-300">{pt.route}</div>
      <div className="mt-0.5 text-gray-400">
        Vector:{' '}
        <span className="mono-num text-gray-200">{pt.predicted_threat}</span>
      </div>
      <div className="mono-num mt-0.5 text-[11px] text-gray-500">
        {pt.timeLabel} · {pt.flow_id}
      </div>
    </div>
  );
}

function ThreatPieTooltip({ active, payload }: ThreatTooltipProps) {
  if (!active || !payload || payload.length === 0) return null;
  const slice = payload[0].payload;
  return (
    <div className="rounded-md border border-[#1F2937] bg-[#0B0F19] px-3 py-2 text-xs shadow-lg">
      <div className="flex items-center gap-2 font-medium text-gray-100">
        <span
          className="h-2 w-2 rounded-full"
          style={{ backgroundColor: slice.color }}
        />
        <span>{slice.label}</span>
      </div>
      <div className="mono-num mt-1 text-gray-300">
        {slice.value.toLocaleString('es-ES')} flujos ({slice.name})
      </div>
    </div>
  );
}

const FILTER_OPTIONS: RiskFilter[] = ['TODOS', 'ALTO', 'MEDIO', 'BAJO'];

export function OverviewPage({
  summary,
  flows,
  loading,
  error,
  threshold,
  onSelectFlow,
}: OverviewPageProps) {
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('TODOS');

  const timelineData = useMemo<TimelinePoint[]>(() => {
    return [...flows]
      .slice(0, 40)
      .reverse()
      .map((flow) => ({
        timeLabel: formatClockTime(flow.timestamp_utc),
        risk_score: Number(flow.risk_score.toFixed(4)),
        flow_id: flow.flow_id,
        predicted_threat: flow.predicted_threat,
        risk_level: flow.risk_level,
        route: `${flow.src_ip}:${flow.src_port} -> ${flow.dst_ip}:${flow.dst_port}`,
      }));
  }, [flows]);

  const threatDistribution = useMemo<ThreatSlice[]>(() => {
    const counts: Record<string, number> = {};
    for (const vec of THREAT_VECTORS) {
      counts[vec] = summary?.threat_distribution?.[vec] ?? 0;
    }
    if (!summary) {
      for (const f of flows) {
        counts[f.predicted_threat] = (counts[f.predicted_threat] ?? 0) + 1;
      }
    }
    return THREAT_VECTORS.map((vec) => ({
      name: vec,
      label: THREAT_LABELS[vec] ?? vec,
      value: counts[vec] ?? 0,
      color: THREAT_COLORS[vec] ?? '#6B7280',
    }));
  }, [summary, flows]);

  const totalThreatFlows = useMemo(
    () => threatDistribution.reduce((acc, item) => acc + item.value, 0),
    [threatDistribution],
  );

  const filteredFlows = useMemo(() => {
    if (riskFilter === 'TODOS') return flows;
    return flows.filter((f) => f.risk_level === riskFilter);
  }, [flows, riskFilter]);

  const totalFlows = summary?.total_flows ?? flows.length;
  const activeAlerts =
    summary?.active_alerts ??
    flows.filter((f) => f.risk_level === 'ALTO' || f.risk_level === 'MEDIO')
      .length;
  const criticalAlerts =
    summary?.critical_alerts ??
    flows.filter((f) => f.risk_level === 'ALTO').length;
  const mediumAlerts =
    summary?.medium_alerts ??
    flows.filter((f) => f.risk_level === 'MEDIO').length;
  const avgLatency =
    summary?.avg_inference_latency_ms ??
    (flows.length > 0
      ? flows.reduce((acc, f) => acc + f.inference_latency_ms, 0) / flows.length
      : 0);
  const anomalyRate =
    summary?.anomaly_rate_pct ??
    (totalFlows > 0 ? (activeAlerts / totalFlows) * 100 : 0);

  return (
    <div className="space-y-5">
      {error && (
        <div className="rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-xs text-red-300">
          No se pudo sincronizar completamente con el backend: {error}
        </div>
      )}

      {/* Row 1: 4 KPI Cards */}
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>Flujos Analizados</span>
            <Activity className="h-4 w-4 text-[#06B6D4]" />
          </div>
          <div className="mono-num mt-2 text-2xl font-semibold text-gray-100">
            {totalFlows.toLocaleString('es-ES')}
          </div>
          <div className="mono-num mt-1.5 text-[11px] text-gray-400">
            Benignos (BAJO):{' '}
            <span className="text-emerald-400">
              {(summary?.risk_distribution?.BAJO ??
                Math.max(0, totalFlows - activeAlerts)
              ).toLocaleString('es-ES')}
            </span>
          </div>
        </div>

        <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>Alertas Activas (Medio/Alto)</span>
            <ShieldAlert className="h-4 w-4 text-[#EF4444]" />
          </div>
          <div className="mono-num mt-2 text-2xl font-semibold text-gray-100">
            {activeAlerts.toLocaleString('es-ES')}
          </div>
          <div className="mono-num mt-1.5 flex items-center gap-3 text-[11px]">
            <span className="text-red-400">ALTO: {criticalAlerts}</span>
            <span className="text-amber-400">MEDIO: {mediumAlerts}</span>
          </div>
        </div>

        <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>Latencia Media de Inferencia</span>
            <Clock className="h-4 w-4 text-[#06B6D4]" />
          </div>
          <div className="mono-num mt-2 text-2xl font-semibold text-cyan-300">
            {avgLatency.toFixed(2)}{' '}
            <span className="text-sm font-normal text-gray-400">ms</span>
          </div>
          <div className="mt-1.5 text-[11px] text-gray-400">
            Evaluación híbrida MLP + Autoencoder
          </div>
        </div>

        <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>Tasa de Anomalía</span>
            <AlertTriangle className="h-4 w-4 text-[#F59E0B]" />
          </div>
          <div className="mono-num mt-2 text-2xl font-semibold text-gray-100">
            {anomalyRate.toFixed(2)}
            <span className="text-sm font-normal text-gray-400">%</span>
          </div>
          <div className="mt-2 h-1.5 w-full overflow-hidden rounded-sm bg-[#0B0F19]">
            <div
              className="h-full transition-all duration-300"
              style={{
                width: `${Math.min(100, Math.max(anomalyRate > 0 ? 3 : 0, anomalyRate))}%`,
                backgroundColor:
                  anomalyRate >= 35
                    ? '#EF4444'
                    : anomalyRate >= 15
                      ? '#F59E0B'
                      : '#10B981',
              }}
            />
          </div>
        </div>
      </section>

      {/* Row 2: Live Charts */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        {/* Risk Score Evolution */}
        <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4 xl:col-span-7">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="flex items-center gap-2 text-sm font-semibold text-gray-100">
                <TrendingUp className="h-4 w-4 text-[#06B6D4]" />
                Evolución Temporal del Risk Score
              </h2>
              <p className="text-xs text-gray-400">
                Últimos {timelineData.length} flujos evaluados en tiempo real
                (umbral crítico {threshold.toFixed(2)})
              </p>
            </div>
            <span className="mono-num rounded border border-[#1F2937] bg-[#0B0F19] px-2 py-0.5 text-[11px] text-gray-400">
              WebSocket Live
            </span>
          </div>

          {timelineData.length === 0 ? (
            <div className="flex h-64 items-center justify-center rounded border border-dashed border-[#1F2937] bg-[#0B0F19] text-xs text-gray-500">
              {loading
                ? 'Cargando telemetría de flujos...'
                : 'Sin flujos aún. Ejecuta una simulación en Laboratorio AiTM o carga un archivo PCAP/CSV.'}
            </div>
          ) : (
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height={256}>
                <AreaChart
                  data={timelineData}
                  margin={{ top: 8, right: 12, left: -16, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.32} />
                      <stop offset="95%" stopColor="#06B6D4" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid
                    stroke="#1F2937"
                    strokeDasharray="3 3"
                    vertical={false}
                  />
                  <XAxis
                    dataKey="timeLabel"
                    stroke="#6B7280"
                    tick={{ fontSize: 11, fill: '#9CA3AF', fontFamily: 'JetBrains Mono' }}
                    minTickGap={28}
                  />
                  <YAxis
                    domain={[0, 1]}
                    ticks={[0, 0.25, 0.5, 0.75, 1]}
                    stroke="#6B7280"
                    tick={{ fontSize: 11, fill: '#9CA3AF', fontFamily: 'JetBrains Mono' }}
                  />
                  <Tooltip content={<RiskAreaTooltip />} />
                  <ReferenceLine
                    y={threshold}
                    stroke="#EF4444"
                    strokeDasharray="4 4"
                    strokeOpacity={0.75}
                  />
                  <Area
                    type="monotone"
                    dataKey="risk_score"
                    stroke="#06B6D4"
                    strokeWidth={2}
                    fill="url(#riskFill)"
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Threat Vector Distribution */}
        <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4 xl:col-span-5">
          <div className="mb-3">
            <h2 className="text-sm font-semibold text-gray-100">
              Distribución por Vector de Amenaza
            </h2>
            <p className="text-xs text-gray-400">
              Clasificación pasiva multiclase (MLP + Random Forest)
            </p>
          </div>

          {totalThreatFlows === 0 ? (
            <div className="flex h-64 items-center justify-center rounded border border-dashed border-[#1F2937] bg-[#0B0F19] text-xs text-gray-500">
              Sin registros clasificados todavía.
            </div>
          ) : (
            <div className="grid grid-cols-1 items-center gap-3 sm:grid-cols-12">
              <div className="h-56 sm:col-span-6">
                <ResponsiveContainer width="100%" height={224}>
                  <PieChart>
                    <Pie
                      data={threatDistribution.filter((d) => d.value > 0)}
                      dataKey="value"
                      nameKey="label"
                      cx="50%"
                      cy="50%"
                      innerRadius={52}
                      outerRadius={80}
                      paddingAngle={2}
                      stroke="#111827"
                      strokeWidth={2}
                      isAnimationActive={false}
                    >
                      {threatDistribution
                        .filter((d) => d.value > 0)
                        .map((entry) => (
                          <Cell key={entry.name} fill={entry.color} />
                        ))}
                    </Pie>
                    <Tooltip content={<ThreatPieTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="space-y-2 sm:col-span-6">
                {threatDistribution.map((item) => {
                  const pct =
                    totalThreatFlows > 0
                      ? (item.value / totalThreatFlows) * 100
                      : 0;
                  return (
                    <div
                      key={item.name}
                      className="flex items-center justify-between rounded border border-[#1F2937] bg-[#0B0F19] px-2.5 py-1.5 text-xs"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className="h-2.5 w-2.5 shrink-0 rounded-sm"
                          style={{ backgroundColor: item.color }}
                        />
                        <span className="truncate text-gray-200">
                          {item.label}
                        </span>
                      </div>
                      <div className="mono-num ml-2 shrink-0 text-gray-300">
                        {item.value}{' '}
                        <span className="text-[11px] text-gray-500">
                          ({pct.toFixed(0)}%)
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Row 3: Real-Time Flows & Alerts Table */}
      <section className="rounded-lg border border-[#1F2937] bg-[#111827]">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#1F2937] px-4 py-3">
          <div>
            <h2 className="text-sm font-semibold text-gray-100">
              Flujos y Alertas en Tiempo Real
            </h2>
            <p className="text-xs text-gray-400">
              Haz clic en cualquier fila para abrir el panel de explicabilidad
              (XAI)
            </p>
          </div>

          <div
            className="inline-flex rounded-md border border-[#1F2937] bg-[#0B0F19] p-0.5"
            role="group"
            aria-label="Filtrar por nivel de riesgo"
          >
            {FILTER_OPTIONS.map((option) => {
              const active = riskFilter === option;
              return (
                <button
                  key={option}
                  type="button"
                  onClick={() => setRiskFilter(option)}
                  className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                    active
                      ? 'bg-[#1F2937] text-cyan-300'
                      : 'text-gray-400 hover:text-gray-200'
                  }`}
                >
                  {option}
                </button>
              );
            })}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[920px] border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-[#1F2937] bg-[#0D1321] text-[11px] font-medium uppercase tracking-wider text-gray-400">
                <th className="px-4 py-2.5">Timestamp</th>
                <th className="px-4 py-2.5">Origen → Destino</th>
                <th className="px-4 py-2.5">Vector Detectado</th>
                <th className="px-4 py-2.5 text-right">Score MLP</th>
                <th className="px-4 py-2.5 text-right">Anomalía AE</th>
                <th className="px-4 py-2.5 text-right">Riesgo Final</th>
                <th className="px-4 py-2.5">Nivel</th>
                <th className="px-4 py-2.5 text-right">Latencia</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2937]">
              {filteredFlows.length === 0 ? (
                <tr>
                  <td
                    colSpan={8}
                    className="px-4 py-10 text-center text-xs text-gray-500"
                  >
                    No hay flujos que coincidan con el filtro seleccionado (
                    {riskFilter}).
                  </td>
                </tr>
              ) : (
                filteredFlows.map((flow) => {
                  const vecColor =
                    THREAT_COLORS[flow.predicted_threat] ?? '#9CA3AF';
                  return (
                    <tr
                      key={`${flow.id}-${flow.flow_id}`}
                      onClick={() => onSelectFlow(flow)}
                      className="cursor-pointer transition-colors hover:bg-[#1F2937]/45"
                    >
                      <td className="mono-num whitespace-nowrap px-4 py-2.5 text-gray-400">
                        {formatClockTime(flow.timestamp_utc)}
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="mono-num text-gray-200">
                          {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:
                          {flow.dst_port}
                        </div>
                        {flow.sni && (
                          <div className="mono-num max-w-xs truncate text-[11px] text-gray-500">
                            SNI: {flow.sni}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className="mono-num inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px]"
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
                        {flow.prob_mlp.toFixed(3)}
                      </td>
                      <td className="mono-num px-4 py-2.5 text-right text-gray-300">
                        {flow.anomaly_ae.toFixed(3)}
                      </td>
                      <td className="mono-num px-4 py-2.5 text-right font-semibold text-gray-100">
                        {flow.risk_score.toFixed(3)}
                      </td>
                      <td className="px-4 py-2.5">
                        <RiskBadge level={flow.risk_level} />
                      </td>
                      <td className="mono-num whitespace-nowrap px-4 py-2.5 text-right text-cyan-300">
                        {flow.inference_latency_ms.toFixed(2)} ms
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
