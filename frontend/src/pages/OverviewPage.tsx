import { useMemo, useState } from 'react';
import { Activity, PieChart as PieChartIcon } from 'lucide-react';
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
import { FlowsTable } from '../components/soc/FlowsTable';
import { MetricStrip, type MetricItem } from '../components/soc/MetricStrip';
import { SensorControlBar } from '../components/soc/SensorControlBar';
import { AlertBanner } from '../components/ui/AlertBanner';
import { BentoCard } from '../components/ui/BentoCard';
import { ChartTooltip } from '../components/ui/ChartTooltip';
import { EmptyState } from '../components/ui/EmptyState';
import { SegmentedControl } from '../components/ui/SegmentedControl';
import { SkeletonBlock, SkeletonMetricStrip } from '../components/ui/Skeleton';
import {
  THREAT_COLORS,
  THREAT_LABELS,
  THREAT_VECTORS,
  type AnalyzedFlow,
  type CaptureInterfacesResponse,
  type CaptureStatus,
  type DashboardSummary,
  type RiskFilter,
} from '../types/ciphertrace';

interface OverviewPageProps {
  summary: DashboardSummary | null;
  flows: AnalyzedFlow[];
  loading: boolean;
  error: string | null;
  threshold: number;
  captureStatus: CaptureStatus | null;
  captureInterfaces: CaptureInterfacesResponse | null;
  captureBusy: boolean;
  captureError: string | null;
  selectedFlowId?: string | null;
  onStartCapture: (iface: string, bpf: string, windowSeconds: number) => void;
  onStopCapture: () => void;
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
    <ChartTooltip>
      <div className="tabular-nums font-semibold text-[#79ABFF]">
        Risk Score: {pt.risk_score.toFixed(4)} ({pt.risk_level})
      </div>
      <div className="tech-mono mt-1 text-[#F2F4F5]">{pt.route}</div>
      <div className="mt-1 text-[#A1ABB3]">
        Vector:{' '}
        <span className="font-medium text-[#F2F4F5]">
          {THREAT_LABELS[pt.predicted_threat] ?? pt.predicted_threat}
        </span>
      </div>
      <div className="tabular-nums mt-0.5 text-[11px] text-[#8E99A2]">
        {pt.timeLabel} · <span className="tech-mono">{pt.flow_id}</span>
      </div>
    </ChartTooltip>
  );
}

function ThreatPieTooltip({ active, payload }: ThreatTooltipProps) {
  if (!active || !payload || payload.length === 0) return null;
  const slice = payload[0].payload;
  return (
    <ChartTooltip>
      <div className="flex items-center gap-2 font-medium text-[#F2F4F5]">
        <span
          className="h-2 w-2 rounded-full"
          style={{ backgroundColor: slice.color }}
        />
        <span>{slice.label}</span>
      </div>
      <div className="tabular-nums mt-1 text-[#A1ABB3]">
        {slice.value.toLocaleString('es-ES')} flujos ({slice.name})
      </div>
    </ChartTooltip>
  );
}

const FILTER_OPTIONS: Array<{ value: RiskFilter; label: string }> = [
  { value: 'TODOS', label: 'Todos' },
  { value: 'ALTO', label: 'Alto' },
  { value: 'MEDIO', label: 'Medio' },
  { value: 'BAJO', label: 'Bajo' },
];

export function OverviewPage({
  summary,
  flows,
  loading,
  error,
  threshold,
  captureStatus,
  captureInterfaces,
  captureBusy,
  captureError,
  selectedFlowId = null,
  onStartCapture,
  onStopCapture,
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
      color: THREAT_COLORS[vec] ?? '#8E99A2',
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

  const benignFlowsCount =
    summary?.risk_distribution?.BAJO ?? Math.max(0, totalFlows - activeAlerts);

  const metricItems: MetricItem[] = [
    {
      id: 'total-flows',
      label: 'Flujos analizados',
      value: totalFlows.toLocaleString('es-ES'),
      detail: (
        <span>
          Benignos (BAJO):{' '}
          <span className="font-medium text-[#36C995]">
            {benignFlowsCount.toLocaleString('es-ES')}
          </span>
        </span>
      ),
    },
    {
      id: 'active-alerts',
      label: 'Alertas activas (Medio/Alto)',
      value: activeAlerts.toLocaleString('es-ES'),
      tone: criticalAlerts > 0 ? 'danger' : 'default',
      detail: (
        <span className="flex items-center gap-3">
          <span className="text-[#F08A8D]">ALTO: {criticalAlerts}</span>
          <span className="text-[#F2A544]">MEDIO: {mediumAlerts}</span>
        </span>
      ),
    },
    {
      id: 'avg-latency',
      label: 'Latencia media de inferencia',
      value: avgLatency.toFixed(2),
      unit: 'ms',
      tone: 'accent',
      detail: 'Evaluación híbrida MLP + Autoencoder',
    },
    {
      id: 'anomaly-rate',
      label: 'Tasa de anomalía',
      value: anomalyRate.toFixed(2),
      unit: '%',
      progress: {
        pct: anomalyRate,
        color:
          anomalyRate >= 35
            ? '#E56B6F'
            : anomalyRate >= 15
              ? '#F2A544'
              : '#36C995',
      },
    },
  ];

  return (
    <div className="space-y-6">
      {error && (
        <AlertBanner variant="error">
          No se pudo sincronizar completamente con el backend: {error}
        </AlertBanner>
      )}

      {/* Row 1: Unified KPI Strip */}
      {loading && !summary && flows.length === 0 ? (
        <SkeletonMetricStrip />
      ) : (
        <MetricStrip items={metricItems} />
      )}

      {/* Row 2: Asymmetric Bento Charts (7 : 5) */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <BentoCard
          className="xl:col-span-7"
          title="Evolución temporal del Risk Score"
          subtitle={`Últimos ${timelineData.length} flujos evaluados en tiempo real (umbral crítico ${threshold.toFixed(2)})`}
          action={
            <span className="inline-flex items-center gap-1.5 rounded-md border border-[#343D43] bg-[#272F35] px-2.5 py-1 text-[11px] font-medium text-[#A1ABB3]">
              WebSocket Live
            </span>
          }
        >
          {loading && timelineData.length === 0 ? (
            <SkeletonBlock className="h-64 w-full rounded-xl" />
          ) : timelineData.length === 0 ? (
            <EmptyState
              icon={Activity}
              title="Sin flujos evaluados todavía"
              description="Inicia una captura en vivo abajo, simula tráfico en Laboratorio AiTM o carga una captura PCAP/CSV."
            />
          ) : (
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height={256}>
                <AreaChart
                  data={timelineData}
                  margin={{ top: 10, right: 20, left: -12, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="riskFillBlue" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#5795F2" stopOpacity={0.26} />
                      <stop offset="95%" stopColor="#5795F2" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid
                    stroke="rgba(52, 61, 67, 0.45)"
                    strokeDasharray="3 3"
                    vertical={false}
                  />
                  <XAxis
                    dataKey="timeLabel"
                    axisLine={false}
                    tickLine={false}
                    tick={{ fontSize: 11, fill: '#8E99A2' }}
                    minTickGap={32}
                  />
                  <YAxis
                    domain={[0, 1]}
                    ticks={[0, 0.25, 0.5, 0.75, 1]}
                    axisLine={false}
                    tickLine={false}
                    tick={{ fontSize: 11, fill: '#8E99A2' }}
                  />
                  <Tooltip content={<RiskAreaTooltip />} />
                  <ReferenceLine
                    y={threshold}
                    stroke="#E56B6F"
                    strokeDasharray="4 4"
                    strokeOpacity={0.75}
                  />
                  <Area
                    type="monotone"
                    dataKey="risk_score"
                    stroke="#5795F2"
                    strokeWidth={2}
                    fill="url(#riskFillBlue)"
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </BentoCard>

        <BentoCard
          className="xl:col-span-5"
          title="Distribución por vector de amenaza"
          subtitle="Clasificación pasiva multiclase (MLP + Random Forest)"
        >
          {loading && totalThreatFlows === 0 ? (
            <SkeletonBlock className="h-64 w-full rounded-xl" />
          ) : totalThreatFlows === 0 ? (
            <EmptyState
              icon={PieChartIcon}
              title="Sin registros clasificados"
              description="La distribución multiclase aparecerá conforme se evalúen los primeros flujos."
            />
          ) : (
            <div className="grid grid-cols-1 items-center gap-4 sm:grid-cols-12">
              <div className="h-56 sm:col-span-5">
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
                      stroke="#1C2226"
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

              <div className="space-y-3 sm:col-span-7">
                {threatDistribution.map((item) => {
                  const pct =
                    totalThreatFlows > 0
                      ? (item.value / totalThreatFlows) * 100
                      : 0;
                  return (
                    <div key={item.name} className="space-y-1">
                      <div className="flex items-center justify-between gap-2 text-xs">
                        <div className="flex min-w-0 items-center gap-2">
                          <span
                            className="h-2 w-2 shrink-0 rounded-full"
                            style={{ backgroundColor: item.color }}
                            aria-hidden="true"
                          />
                          <span className="truncate text-[#F2F4F5]">
                            {item.label}
                          </span>
                        </div>
                        <div className="tabular-nums shrink-0 text-[#A1ABB3]">
                          <strong className="font-medium text-[#F2F4F5]">
                            {item.value.toLocaleString('es-ES')}
                          </strong>{' '}
                          <span className="text-[11px] text-[#8E99A2]">
                            ({pct.toFixed(0)}%)
                          </span>
                        </div>
                      </div>
                      <div className="h-1.5 w-full overflow-hidden rounded-full bg-[#272F35]">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${pct > 0 ? Math.max(2, pct) : 0}%`,
                            backgroundColor: item.color,
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </BentoCard>
      </section>

      {/* Row 3: Direct-Access Hybrid Capture Bar */}
      <SensorControlBar
        captureStatus={captureStatus}
        captureInterfaces={captureInterfaces}
        captureBusy={captureBusy}
        captureError={captureError}
        onStartCapture={onStartCapture}
        onStopCapture={onStopCapture}
      />

      {/* Row 4: Real-Time Flows & Alerts Table */}
      <BentoCard
        noPadding
        title="Flujos y alertas en tiempo real"
        subtitle="Selecciona cualquier fila (clic o Enter) para abrir el panel de explicabilidad XAI"
        action={
          <SegmentedControl
            options={FILTER_OPTIONS}
            value={riskFilter}
            onChange={setRiskFilter}
            ariaLabel="Filtrar flujos por nivel de riesgo"
          />
        }
      >
        <FlowsTable
          flows={filteredFlows}
          onSelectFlow={onSelectFlow}
          selectedFlowId={selectedFlowId}
          loading={loading}
          emptyTitle="Sin flujos para el filtro actual"
          emptyDescription={`No hay flujos clasificados con nivel ${riskFilter}.`}
        />
      </BentoCard>
    </div>
  );
}
