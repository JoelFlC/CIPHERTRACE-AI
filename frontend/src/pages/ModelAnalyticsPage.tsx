import { useEffect, useMemo, useState } from 'react';
import { CheckCircle2, FileSpreadsheet, MinusCircle } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { MetricStrip, type MetricItem } from '../components/soc/MetricStrip';
import { AlertBanner } from '../components/ui/AlertBanner';
import { BentoCard } from '../components/ui/BentoCard';
import { ChartTooltip } from '../components/ui/ChartTooltip';
import { SegmentedControl } from '../components/ui/SegmentedControl';
import { SkeletonBlock, SkeletonMetricStrip } from '../components/ui/Skeleton';
import { fetchMLMetrics } from '../services/api';
import {
  FEATURE_LABELS,
  THREAT_LABELS,
  type MLMetricsResponse,
} from '../types/ciphertrace';

interface ModelAnalyticsPageProps {
  refreshTrigger: number;
}

type GAPhaseTab = 'phase1' | 'phase2';

interface ConvergencePoint {
  generation: number;
  best: number;
  avg: number;
  extraLabel: string;
}

interface ConvergenceTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: ConvergencePoint }>;
}

interface BarTooltipProps {
  active?: boolean;
  label?: string;
  payload?: Array<{
    name?: string;
    value?: number;
    color?: string;
  }>;
}

interface ModelComparisonRow {
  key: string;
  displayName: string;
  paradigm: string;
  precision: number;
  recall: number;
  f1_score: number;
  avg_latency_ms: number;
  isHybrid?: boolean;
}

const PHASE_OPTIONS: Array<{ value: GAPhaseTab; label: string }> = [
  { value: 'phase1', label: 'Fase 1: Atributos' },
  { value: 'phase2', label: 'Fase 2: Pesos (F1)' },
];

function ConvergenceTooltip({ active, payload }: ConvergenceTooltipProps) {
  if (!active || !payload || payload.length === 0) return null;
  const pt = payload[0].payload;
  return (
    <ChartTooltip>
      <div className="tabular-nums font-semibold text-[#F2F4F5]">
        Generación {pt.generation}
      </div>
      <div className="tabular-nums mt-1 text-[#79ABFF]">
        Mejor: {pt.best.toFixed(4)}
      </div>
      <div className="tabular-nums text-[#A1ABB3]">
        Promedio: {pt.avg.toFixed(4)}
      </div>
      <div className="tech-mono mt-1 text-[11px] text-[#8E99A2]">
        {pt.extraLabel}
      </div>
    </ChartTooltip>
  );
}

function ModelBarTooltip({ active, label, payload }: BarTooltipProps) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <ChartTooltip>
      <div className="font-semibold text-[#F2F4F5]">{label}</div>
      <div className="mt-1.5 space-y-1">
        {payload.map((entry) => (
          <div
            key={entry.name}
            className="tabular-nums flex items-center justify-between gap-4 text-xs"
          >
            <span className="flex items-center gap-1.5 text-[#A1ABB3]">
              <span
                className="h-2 w-2 rounded-full"
                style={{ backgroundColor: entry.color }}
              />
              {entry.name}
            </span>
            <span className="font-medium text-[#F2F4F5]">
              {Number(entry.value ?? 0).toFixed(2)}%
            </span>
          </div>
        ))}
      </div>
    </ChartTooltip>
  );
}

export function ModelAnalyticsPage({ refreshTrigger }: ModelAnalyticsPageProps) {
  const [data, setData] = useState<MLMetricsResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activePhase, setActivePhase] = useState<GAPhaseTab>('phase1');

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);

    fetchMLMetrics()
      .then((res) => {
        if (!active) return;
        setData(res);
      })
      .catch((err) => {
        if (!active) return;
        setError(
          err instanceof Error
            ? err.message
            : 'No se pudieron cargar las métricas ML y del Algoritmo Genético.',
        );
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [refreshTrigger]);

  const convergenceData = useMemo<ConvergencePoint[]>(() => {
    if (!data) return [];
    if (activePhase === 'phase1') {
      return data.ga_config.phase1_feature_selection.history.map((gen) => ({
        generation: gen.generation,
        best: gen.best_fitness,
        avg: gen.avg_fitness,
        extraLabel: `F1=${gen.best_f1.toFixed(4)} · ${gen.num_selected_features} atributos`,
      }));
    }
    return data.ga_config.phase2_weight_optimization.history.map((gen) => ({
      generation: gen.generation,
      best: gen.best_f1,
      avg: gen.avg_f1,
      extraLabel: `w_mlp=${gen.best_w_mlp.toFixed(2)} · w_ae=${gen.best_w_ae.toFixed(2)} · thr=${gen.best_threshold.toFixed(2)}`,
    }));
  }, [data, activePhase]);

  const yDomain = useMemo<[number, number]>(() => {
    if (convergenceData.length === 0) return [0.95, 1.0];
    const values = convergenceData.flatMap((p) => [p.best, p.avg]);
    const minVal = Math.min(...values);
    const maxVal = Math.max(...values);
    const span = Math.max(maxVal - minVal, 0.002);
    const lower = Math.max(0, Number((minVal - span * 0.25).toFixed(4)));
    const upper = Math.min(1, Number((maxVal + span * 0.15).toFixed(4)));
    return [lower, upper <= lower ? 1 : upper];
  }, [convergenceData]);

  const modelRows = useMemo<ModelComparisonRow[]>(() => {
    if (!data) return [];
    const { models, hybrid_ensemble } = data.model_metrics;
    return [
      {
        key: 'random_forest',
        displayName: models.random_forest.display_name,
        paradigm: models.random_forest.paradigm,
        precision: models.random_forest.precision,
        recall: models.random_forest.recall,
        f1_score: models.random_forest.f1_score,
        avg_latency_ms: models.random_forest.avg_latency_ms,
      },
      {
        key: 'mlp',
        displayName: models.mlp.display_name,
        paradigm: models.mlp.paradigm,
        precision: models.mlp.precision,
        recall: models.mlp.recall,
        f1_score: models.mlp.f1_score,
        avg_latency_ms: models.mlp.avg_latency_ms,
      },
      {
        key: 'autoencoder',
        displayName: models.autoencoder.display_name,
        paradigm: models.autoencoder.paradigm,
        precision: models.autoencoder.precision,
        recall: models.autoencoder.recall,
        f1_score: models.autoencoder.f1_score,
        avg_latency_ms: models.autoencoder.avg_latency_ms,
      },
      {
        key: 'isolation_forest',
        displayName: models.isolation_forest.display_name,
        paradigm: models.isolation_forest.paradigm,
        precision: models.isolation_forest.precision,
        recall: models.isolation_forest.recall,
        f1_score: models.isolation_forest.f1_score,
        avg_latency_ms: models.isolation_forest.avg_latency_ms,
      },
      {
        key: 'hybrid',
        displayName: hybrid_ensemble.display_name,
        paradigm: 'Ensamble Ponderado por AG',
        precision: hybrid_ensemble.precision,
        recall: hybrid_ensemble.recall,
        f1_score: hybrid_ensemble.f1_score,
        avg_latency_ms: hybrid_ensemble.avg_latency_ms,
        isHybrid: true,
      },
    ];
  }, [data]);

  const barChartData = useMemo(() => {
    return modelRows
      .filter((row) => !row.isHybrid)
      .map((row) => ({
        name: row.displayName
          .replace('PyTorch ', '')
          .replace(' Neural Network', ''),
        Precisión: Number((row.precision * 100).toFixed(2)),
        Recall: Number((row.recall * 100).toFixed(2)),
        'F1-Score': Number((row.f1_score * 100).toFixed(2)),
      }));
  }, [modelRows]);

  if (loading && !data) {
    return (
      <div className="space-y-6">
        <SkeletonMetricStrip />
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <SkeletonBlock className="h-80 rounded-2xl xl:col-span-6" />
          <SkeletonBlock className="h-80 rounded-2xl xl:col-span-6" />
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <AlertBanner variant="error">
        {error ?? 'No hay datos de métricas disponibles.'}
      </AlertBanner>
    );
  }

  const { model_metrics, ga_config } = data;
  const selectedSet = new Set(ga_config.selected_features);
  const cm = model_metrics.hybrid_ensemble.confusion_matrix;
  const sourceBreakdown = model_metrics.dataset.source_breakdown;
  const reductionPct = (
    (1 - ga_config.selected_features.length / ga_config.feature_columns.length) *
    100
  ).toFixed(1);

  const metricItems: MetricItem[] = [
    {
      id: 'dataset',
      label: 'Dataset y validación',
      value: model_metrics.dataset.total_flows.toLocaleString('es-ES'),
      unit: 'flujos',
      detail: `Validación cruzada k=${model_metrics.dataset.cv_folds}`,
    },
    {
      id: 'ga-reduction',
      label: 'Reducción dimensional AG',
      value: `${ga_config.selected_features.length} / ${ga_config.feature_columns.length}`,
      unit: 'atributos',
      tone: 'success',
      detail: `${reductionPct}% menos dimensionalidad`,
    },
    {
      id: 'hybrid-f1',
      label: 'F1-Score Híbrido (AG)',
      value: model_metrics.hybrid_ensemble.f1_score.toFixed(4),
      tone: 'accent',
      detail: `Precisión ${model_metrics.hybrid_ensemble.precision.toFixed(4)} · Recall ${model_metrics.hybrid_ensemble.recall.toFixed(4)}`,
    },
    {
      id: 'hybrid-weights',
      label: 'Función de riesgo híbrido',
      value: `${ga_config.weights.w_mlp.toFixed(2)} / ${ga_config.weights.w_ae.toFixed(2)}`,
      detail: (
        <span className="tech-mono text-[11px] text-[#F2A544]">
          R={ga_config.weights.w_mlp.toFixed(2)}·MLP +{' '}
          {ga_config.weights.w_ae.toFixed(2)}·AE · thr=
          {ga_config.threshold.toFixed(2)}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Row 1: Summary Strip */}
      <MetricStrip items={metricItems} />

      {/* Row 2: GA Convergence (6) + Feature Selection & Confusion Matrix (6) */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <BentoCard
          className="xl:col-span-6"
          title="Convergencia del Algoritmo Genético"
          subtitle="Evolución generacional de mejor aptitud frente a aptitud promedio"
          action={
            <SegmentedControl
              options={PHASE_OPTIONS}
              value={activePhase}
              onChange={setActivePhase}
              ariaLabel="Fase del algoritmo genético"
            />
          }
        >
          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height={288}>
              <LineChart
                data={convergenceData}
                margin={{ top: 10, right: 16, left: 0, bottom: 8 }}
              >
                <CartesianGrid
                  stroke="rgba(52, 61, 67, 0.45)"
                  strokeDasharray="3 3"
                  vertical={false}
                />
                <XAxis
                  dataKey="generation"
                  axisLine={false}
                  tickLine={false}
                  tick={{ fontSize: 11, fill: '#8E99A2' }}
                  label={{
                    value: 'Generaciones',
                    position: 'insideBottomRight',
                    offset: -4,
                    fill: '#8E99A2',
                    fontSize: 11,
                  }}
                />
                <YAxis
                  domain={yDomain}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(val: number) => val.toFixed(4)}
                  width={56}
                  tick={{ fontSize: 11, fill: '#8E99A2' }}
                />
                <Tooltip content={<ConvergenceTooltip />} />
                <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '8px' }} />
                <Line
                  type="monotone"
                  dataKey="best"
                  name={
                    activePhase === 'phase1'
                      ? 'Mejor Aptitud (Fitness)'
                      : 'Mejor F1-Score'
                  }
                  stroke="#5795F2"
                  strokeWidth={2.2}
                  dot={{ r: 3, fill: '#5795F2' }}
                  activeDot={{ r: 5 }}
                />
                <Line
                  type="monotone"
                  dataKey="avg"
                  name={
                    activePhase === 'phase1'
                      ? 'Aptitud Promedio'
                      : 'F1-Score Promedio'
                  }
                  stroke="#79ABFF"
                  strokeWidth={1.7}
                  strokeDasharray="4 4"
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </BentoCard>

        <BentoCard
          className="flex flex-col justify-between xl:col-span-6"
          title="Mapa de selección de atributos (18 características)"
          subtitle="Máscara genética aplicada antes del entrenamiento e inferencia"
          action={
            <div className="tabular-nums flex items-center gap-3 text-xs">
              <span className="inline-flex items-center gap-1 text-[#36C995]">
                <CheckCircle2 className="h-3.5 w-3.5" strokeWidth={1.75} />
                {ga_config.selected_features.length} sel.
              </span>
              <span className="inline-flex items-center gap-1 text-[#8E99A2]">
                <MinusCircle className="h-3.5 w-3.5" strokeWidth={1.75} />
                {ga_config.discarded_features.length} desc.
              </span>
            </div>
          }
        >
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {ga_config.feature_columns.map((feat) => {
              const isSelected = selectedSet.has(feat);
              return (
                <div
                  key={feat}
                  title={FEATURE_LABELS[feat] ?? feat}
                  className={`flex items-center justify-between gap-2 rounded-md border px-2.5 py-1.5 text-xs ${
                    isSelected
                      ? 'border-[#5795F2]/30 bg-[#5795F2]/14 text-[#79ABFF]'
                      : 'border-transparent bg-[#272F35]/45 text-[#8E99A2]'
                  }`}
                >
                  <span className="tech-mono truncate text-[11px]">{feat}</span>
                  {isSelected ? (
                    <CheckCircle2
                      className="h-3.5 w-3.5 shrink-0 text-[#36C995]"
                      strokeWidth={1.75}
                      aria-label="Seleccionado"
                    />
                  ) : (
                    <MinusCircle
                      className="h-3.5 w-3.5 shrink-0 text-[#8E99A2]"
                      strokeWidth={1.75}
                      aria-label="Descartado"
                    />
                  )}
                </div>
              );
            })}
          </div>

          {/* 2x2 Confusion Matrix */}
          <div className="mt-5 border-t border-[#343D43]/60 pt-4">
            <div className="mb-2.5 flex items-center justify-between text-xs">
              <span className="font-semibold text-[#F2F4F5]">
                Matriz de confusión del ensamble (k={model_metrics.dataset.cv_folds})
              </span>
              <span className="tabular-nums text-[#A1ABB3]">
                Total:{' '}
                {(cm.tn + cm.fp + cm.fn + cm.tp).toLocaleString('es-ES')} flujos
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="flex items-center justify-between rounded-[10px] border border-[#36C995]/25 bg-[#36C995]/12 px-3 py-2">
                <span className="text-[#A1ABB3]">Verdadero Negativo (TN)</span>
                <span className="tabular-nums font-semibold text-[#36C995]">
                  {cm.tn.toLocaleString('es-ES')}
                </span>
              </div>
              <div className="flex items-center justify-between rounded-[10px] border border-[#F2A544]/25 bg-[#F2A544]/12 px-3 py-2">
                <span className="text-[#A1ABB3]">Falso Positivo (FP)</span>
                <span className="tabular-nums font-semibold text-[#F2A544]">
                  {cm.fp.toLocaleString('es-ES')}
                </span>
              </div>
              <div className="flex items-center justify-between rounded-[10px] border border-[#F2A544]/25 bg-[#F2A544]/12 px-3 py-2">
                <span className="text-[#A1ABB3]">Falso Negativo (FN)</span>
                <span className="tabular-nums font-semibold text-[#F2A544]">
                  {cm.fn.toLocaleString('es-ES')}
                </span>
              </div>
              <div className="flex items-center justify-between rounded-[10px] border border-[#36C995]/25 bg-[#36C995]/12 px-3 py-2">
                <span className="text-[#A1ABB3]">Verdadero Positivo (TP)</span>
                <span className="tabular-nums font-semibold text-[#36C995]">
                  {cm.tp.toLocaleString('es-ES')}
                </span>
              </div>
            </div>
          </div>
        </BentoCard>
      </section>

      {/* Row 3: Model Comparison Table (7) + Full 0-100% BarChart (5) */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <BentoCard
          noPadding
          className="xl:col-span-7"
          title={`Comparativa de modelos (Validación cruzada k=${model_metrics.dataset.cv_folds})`}
          subtitle={`Evaluación sobre los ${ga_config.selected_features.length} atributos óptimos seleccionados por el AG`}
        >
          <div className="overflow-x-auto">
            <table className="w-full min-w-[600px] border-collapse text-left text-[13px]">
              <thead>
                <tr className="border-b border-[#343D43]/60 bg-[#151A1E]/60 text-xs font-medium text-[#A1ABB3]">
                  <th className="px-5 py-3">Modelo</th>
                  <th className="px-4 py-3">Paradigma</th>
                  <th className="px-4 py-3 text-right">Precisión</th>
                  <th className="px-4 py-3 text-right">Recall</th>
                  <th className="px-4 py-3 text-right">F1-Score</th>
                  <th className="px-5 py-3 text-right">Latencia</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#343D43]/50">
                {modelRows.map((row) => (
                  <tr
                    key={row.key}
                    className={
                      row.isHybrid
                        ? 'bg-[#5795F2]/10 font-medium text-[#F2F4F5]'
                        : 'text-[#F2F4F5]'
                    }
                  >
                    <td className="px-5 py-3 font-medium">{row.displayName}</td>
                    <td className="px-4 py-3 text-xs text-[#A1ABB3]">
                      {row.paradigm}
                    </td>
                    <td className="tabular-nums px-4 py-3 text-right">
                      {(row.precision * 100).toFixed(2)}%
                    </td>
                    <td className="tabular-nums px-4 py-3 text-right">
                      {(row.recall * 100).toFixed(2)}%
                    </td>
                    <td className="tabular-nums px-4 py-3 text-right font-semibold text-[#79ABFF]">
                      {(row.f1_score * 100).toFixed(2)}%
                    </td>
                    <td className="tabular-nums px-5 py-3 text-right text-[#A1ABB3]">
                      {row.avg_latency_ms.toFixed(4)} ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </BentoCard>

        <BentoCard
          className="xl:col-span-5"
          title="Rendimiento comparativo (%)"
          subtitle="Escala íntegra 0–100% por arquitectura evaluada"
        >
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height={256}>
              <BarChart
                data={barChartData}
                margin={{ top: 8, right: 12, left: -12, bottom: 0 }}
              >
                <CartesianGrid
                  stroke="rgba(52, 61, 67, 0.45)"
                  strokeDasharray="3 3"
                  vertical={false}
                />
                <XAxis
                  dataKey="name"
                  axisLine={false}
                  tickLine={false}
                  tick={{ fontSize: 11, fill: '#8E99A2' }}
                />
                <YAxis
                  domain={[0, 100]}
                  ticks={[0, 25, 50, 75, 100]}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(v: number) => `${v}%`}
                  tick={{ fontSize: 11, fill: '#8E99A2' }}
                />
                <Tooltip content={<ModelBarTooltip />} cursor={{ fill: 'rgba(52, 61, 67, 0.25)' }} />
                <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '6px' }} />
                <Bar dataKey="Precisión" fill="#5795F2" radius={[4, 4, 0, 0]} />
                <Bar dataKey="Recall" fill="#79ABFF" radius={[4, 4, 0, 0]} />
                <Bar dataKey="F1-Score" fill="#36C995" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="mt-2 text-[11px] leading-relaxed text-[#8E99A2]">
            Autoencoder e Isolation Forest se entrenan únicamente con tráfico
            benigno para detección Zero-Day; el ensamble ponderado los combina
            con la red MLP.
          </p>
        </BentoCard>
      </section>

      {/* Row 4: Unified Dataset Provenance */}
      {sourceBreakdown && (
        <BentoCard
          title="Procedencia y trazabilidad del dataset de entrenamiento"
          subtitle={
            <span>
              Ingesta desde{' '}
              <span className="tech-mono text-[#F2F4F5]">backend/data/raw/</span>{' '}
              con respaldo estadístico y laboratorio controlado
            </span>
          }
          action={
            <span
              className={`rounded-md border px-2.5 py-1 text-xs font-medium ${
                sourceBreakdown.mode === 'public_only'
                  ? 'border-[#36C995]/30 bg-[#36C995]/14 text-[#36C995]'
                  : sourceBreakdown.mode === 'public_plus_lab'
                    ? 'border-[#5795F2]/30 bg-[#5795F2]/14 text-[#79ABFF]'
                    : 'border-[#F2A544]/30 bg-[#F2A544]/14 text-[#F2A544]'
              }`}
            >
              {sourceBreakdown.mode === 'public_only'
                ? '100% Datasets Públicos'
                : sourceBreakdown.mode === 'public_plus_lab'
                  ? 'Datasets Públicos + Laboratorio'
                  : 'Respaldo Estadístico (data/raw/ vacía)'}
            </span>
          }
          headerDivider
        >
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
            {/* By Class Proportional Bars */}
            <div className="space-y-3 lg:col-span-7">
              <div className="flex items-center justify-between text-xs text-[#A1ABB3]">
                <span className="font-medium text-[#F2F4F5]">
                  Composición por clase ({sourceBreakdown.public_raw_flows.toLocaleString('es-ES')} públicos · {sourceBreakdown.fallback_or_lab_flows.toLocaleString('es-ES')} lab/respaldo)
                </span>
                <div className="flex items-center gap-3 text-[11px]">
                  <span className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-[#5795F2]" />
                    Público
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-[#F2A544]" />
                    Lab / Resp.
                  </span>
                </div>
              </div>

              <div className="space-y-2.5">
                {Object.entries(sourceBreakdown.by_class).map(([cls, counts]) => {
                  const total = counts.public_raw + counts.fallback_or_lab;
                  const pubPct = total > 0 ? (counts.public_raw / total) * 100 : 0;
                  const labPct = total > 0 ? (counts.fallback_or_lab / total) * 100 : 0;

                  return (
                    <div key={cls} className="space-y-1">
                      <div className="flex items-center justify-between gap-2 text-xs">
                        <div className="min-w-0">
                          <span className="font-medium text-[#F2F4F5]">
                            {THREAT_LABELS[cls] ?? cls}
                          </span>
                          <span className="tech-mono ml-2 text-[11px] text-[#8E99A2]">
                            {cls}
                          </span>
                        </div>
                        <div className="tabular-nums shrink-0 text-[11px] text-[#A1ABB3]">
                          Público:{' '}
                          <strong className="text-[#F2F4F5]">
                            {counts.public_raw.toLocaleString('es-ES')}
                          </strong>{' '}
                          · Lab:{' '}
                          <strong className="text-[#F2F4F5]">
                            {counts.fallback_or_lab.toLocaleString('es-ES')}
                          </strong>
                        </div>
                      </div>
                      <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-[#272F35]">
                        {pubPct > 0 && (
                          <div
                            className="h-full bg-[#5795F2]"
                            style={{ width: `${pubPct}%` }}
                          />
                        )}
                        {labPct > 0 && (
                          <div
                            className="h-full bg-[#F2A544]"
                            style={{ width: `${labPct}%` }}
                          />
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Source Files List */}
            {sourceBreakdown.by_file &&
              Object.keys(sourceBreakdown.by_file).length > 0 && (
                <div className="border-t border-[#343D43]/60 pt-4 lg:col-span-5 lg:border-l lg:border-t-0 lg:pl-6 lg:pt-0">
                  <div className="mb-3 text-xs font-medium text-[#F2F4F5]">
                    Archivos públicos muestreados
                  </div>
                  <div className="divide-y divide-[#343D43]/55">
                    {Object.entries(sourceBreakdown.by_file).map(
                      ([fname, fileStats]) => (
                        <div
                          key={fname}
                          className="flex items-center justify-between gap-3 py-2.5 first:pt-0 last:pb-0 text-xs"
                        >
                          <div className="flex min-w-0 items-center gap-2">
                            <FileSpreadsheet
                              className="h-4 w-4 shrink-0 text-[#79ABFF]"
                              strokeWidth={1.75}
                              aria-hidden="true"
                            />
                            <span className="tech-mono truncate text-[#F2F4F5]">
                              {fname}
                            </span>
                          </div>
                          <span className="tabular-nums shrink-0 text-[#A1ABB3]">
                            {fileStats.total_loaded.toLocaleString('es-ES')} filas
                          </span>
                        </div>
                      ),
                    )}
                  </div>
                </div>
              )}
          </div>
        </BentoCard>
      )}
    </div>
  );
}
