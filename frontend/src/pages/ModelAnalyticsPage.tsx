import { useEffect, useMemo, useState } from 'react';
import {
  CheckCircle2,
  Cpu,
  Database,
  Dna,
  GitCompare,
  Loader2,
  MinusCircle,
} from 'lucide-react';
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
import { fetchMLMetrics } from '../services/api';
import {
  FEATURE_LABELS,
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

function ConvergenceTooltip({ active, payload }: ConvergenceTooltipProps) {
  if (!active || !payload || payload.length === 0) return null;
  const pt = payload[0].payload;
  return (
    <div className="rounded-md border border-[#1F2937] bg-[#0B0F19] px-3 py-2 text-xs shadow-lg">
      <div className="mono-num font-semibold text-gray-100">
        Generación {pt.generation}
      </div>
      <div className="mono-num mt-1 text-cyan-300">
        Mejor: {pt.best.toFixed(4)}
      </div>
      <div className="mono-num text-amber-300">
        Promedio: {pt.avg.toFixed(4)}
      </div>
      <div className="mono-num mt-1 text-[11px] text-gray-400">
        {pt.extraLabel}
      </div>
    </div>
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
      <div className="flex h-64 items-center justify-center rounded-lg border border-[#1F2937] bg-[#111827] text-xs text-gray-400">
        <Loader2 className="mr-2 h-4 w-4 animate-spin text-[#06B6D4]" />
        Cargando métricas de validación cruzada y evolución genética...
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-5 text-xs text-red-300">
        {error ?? 'No hay datos de métricas disponibles.'}
      </div>
    );
  }

  const { model_metrics, ga_config } = data;
  const selectedSet = new Set(ga_config.selected_features);
  const cm = model_metrics.hybrid_ensemble.confusion_matrix;
  const sourceBreakdown = model_metrics.dataset.source_breakdown;

  return (
    <div className="space-y-5">
      {/* Summary Strip */}
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4">
          <div className="text-xs text-gray-400">Dataset y Validación</div>
          <div className="mono-num mt-1.5 text-xl font-semibold text-gray-100">
            {model_metrics.dataset.total_flows.toLocaleString('es-ES')} flujos
          </div>
          <div className="mono-num mt-1 text-[11px] text-cyan-300">
            Validación Cruzada k={model_metrics.dataset.cv_folds}
          </div>
        </div>

        <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4">
          <div className="text-xs text-gray-400">Reducción Dimensional AG</div>
          <div className="mono-num mt-1.5 text-xl font-semibold text-emerald-400">
            {ga_config.selected_features.length} /{' '}
            {ga_config.feature_columns.length} atributos
          </div>
          <div className="mono-num mt-1 text-[11px] text-gray-400">
            {(
              (1 -
                ga_config.selected_features.length /
                  ga_config.feature_columns.length) *
              100
            ).toFixed(1)}
            % menos dimensionalidad
          </div>
        </div>

        <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4">
          <div className="text-xs text-gray-400">F1-Score Híbrido (AG)</div>
          <div className="mono-num mt-1.5 text-xl font-semibold text-cyan-300">
            {model_metrics.hybrid_ensemble.f1_score.toFixed(4)}
          </div>
          <div className="mono-num mt-1 text-[11px] text-gray-400">
            Precisión {model_metrics.hybrid_ensemble.precision.toFixed(4)} ·
            Recall {model_metrics.hybrid_ensemble.recall.toFixed(4)}
          </div>
        </div>

        <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4">
          <div className="text-xs text-gray-400">Pesos Óptimos y Umbral</div>
          <div className="mono-num mt-1.5 text-xl font-semibold text-gray-100">
            {ga_config.weights.w_mlp.toFixed(2)} /{' '}
            {ga_config.weights.w_ae.toFixed(2)}
          </div>
          <div className="mono-num mt-1 text-[11px] text-amber-300">
            w_mlp={ga_config.weights.w_mlp.toFixed(2)} · w_ae=
            {ga_config.weights.w_ae.toFixed(2)} · thr=
            {ga_config.threshold.toFixed(2)}
          </div>
        </div>
      </section>

      {/* Dataset Provenance & Auto-Ingestion Traceability */}
      {sourceBreakdown && (
        <section className="rounded-lg border border-[#1F2937] bg-[#111827] p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Database className="h-4 w-4 text-[#06B6D4]" />
              <div>
                <h2 className="text-sm font-semibold text-gray-100">
                  Procedencia del Dataset de Entrenamiento (Trazabilidad)
                </h2>
                <p className="text-xs text-gray-400">
                  Ingesta automática desde{' '}
                  <span className="mono-num">backend/data/raw/</span> con
                  respaldo estadístico controlado
                </p>
              </div>
            </div>

            <span
              className={`mono-num rounded border px-2.5 py-1 text-xs font-medium ${
                sourceBreakdown.mode === 'public_only'
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                  : sourceBreakdown.mode === 'public_plus_lab'
                    ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300'
                    : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
              }`}
            >
              {sourceBreakdown.mode === 'public_only'
                ? '100% Datasets Públicos'
                : sourceBreakdown.mode === 'public_plus_lab'
                  ? 'Datasets Públicos + Laboratorio'
                  : 'Respaldo Estadístico (data/raw/ vacía)'}
            </span>
          </div>

          <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-5">
            {Object.entries(sourceBreakdown.by_class).map(([cls, counts]) => (
              <div
                key={cls}
                className="rounded border border-[#1F2937] bg-[#0B0F19] px-3 py-2 text-xs"
              >
                <div className="mono-num font-medium text-gray-200">{cls}</div>
                <div className="mono-num mt-1 flex items-center justify-between text-[11px] text-gray-400">
                  <span>Público: {counts.public_raw}</span>
                  <span>Lab/Resp: {counts.fallback_or_lab}</span>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Row 2: GA Convergence Chart + Feature Selection & Optimal Weights */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        {/* Convergence LineChart */}
        <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4 xl:col-span-6">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="flex items-center gap-2 text-sm font-semibold text-gray-100">
                <Dna className="h-4 w-4 text-[#06B6D4]" />
                Convergencia del Algoritmo Genético
              </h2>
              <p className="text-xs text-gray-400">
                Evolución generacional de Mejor Aptitud vs. Aptitud Promedio
              </p>
            </div>

            <div className="inline-flex rounded-md border border-[#1F2937] bg-[#0B0F19] p-0.5 text-xs">
              <button
                type="button"
                onClick={() => setActivePhase('phase1')}
                className={`rounded px-2.5 py-1 transition-colors ${
                  activePhase === 'phase1'
                    ? 'bg-[#1F2937] text-cyan-300'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                Fase 1: Atributos
              </button>
              <button
                type="button"
                onClick={() => setActivePhase('phase2')}
                className={`rounded px-2.5 py-1 transition-colors ${
                  activePhase === 'phase2'
                    ? 'bg-[#1F2937] text-cyan-300'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                Fase 2: Pesos (F1)
              </button>
            </div>
          </div>

          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height={288}>
              <LineChart
                data={convergenceData}
                margin={{ top: 10, right: 16, left: 0, bottom: 4 }}
              >
                <CartesianGrid
                  stroke="#1F2937"
                  strokeDasharray="3 3"
                  vertical={false}
                />
                <XAxis
                  dataKey="generation"
                  stroke="#6B7280"
                  tick={{ fontSize: 11, fill: '#9CA3AF', fontFamily: 'JetBrains Mono' }}
                  label={{
                    value: 'Generaciones',
                    position: 'insideBottomRight',
                    offset: -4,
                    fill: '#6B7280',
                    fontSize: 11,
                  }}
                />
                <YAxis
                  domain={yDomain}
                  stroke="#6B7280"
                  tickFormatter={(val: number) => val.toFixed(4)}
                  width={56}
                  tick={{ fontSize: 11, fill: '#9CA3AF', fontFamily: 'JetBrains Mono' }}
                />
                <Tooltip content={<ConvergenceTooltip />} />
                <Legend
                  wrapperStyle={{ fontSize: '12px', paddingTop: '8px' }}
                />
                <Line
                  type="monotone"
                  dataKey="best"
                  name={
                    activePhase === 'phase1'
                      ? 'Mejor Aptitud (Fitness)'
                      : 'Mejor F1-Score'
                  }
                  stroke="#06B6D4"
                  strokeWidth={2.2}
                  dot={{ r: 3, fill: '#06B6D4' }}
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
                  stroke="#F59E0B"
                  strokeWidth={1.8}
                  strokeDasharray="4 4"
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* 18-Feature GA Selection Map + Weights + Confusion Matrix */}
        <div className="flex flex-col justify-between rounded-lg border border-[#1F2937] bg-[#111827] p-4 xl:col-span-6">
          <div>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="flex items-center gap-2 text-sm font-semibold text-gray-100">
                  <Cpu className="h-4 w-4 text-[#10B981]" />
                  Mapa de Selección de Atributos (18 Características)
                </h2>
                <p className="text-xs text-gray-400">
                  Comparación de características seleccionadas por el AG vs.
                  descartadas
                </p>
              </div>
              <div className="flex items-center gap-2 text-[11px]">
                <span className="inline-flex items-center gap-1 text-emerald-400">
                  <CheckCircle2 className="h-3 w-3" /> Seleccionadas (
                  {ga_config.selected_features.length})
                </span>
                <span className="inline-flex items-center gap-1 text-gray-500">
                  <MinusCircle className="h-3 w-3" /> Descartadas (
                  {ga_config.discarded_features.length})
                </span>
              </div>
            </div>

            <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {ga_config.feature_columns.map((feat) => {
                const isSelected = selectedSet.has(feat);
                return (
                  <div
                    key={feat}
                    title={FEATURE_LABELS[feat] ?? feat}
                    className={`flex items-center justify-between gap-2 rounded border px-2.5 py-1.5 text-xs ${
                      isSelected
                        ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-200'
                        : 'border-[#1F2937] bg-[#0B0F19] text-gray-500'
                    }`}
                  >
                    <span className="mono-num truncate text-[11px]">
                      {feat}
                    </span>
                    {isSelected ? (
                      <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-400" />
                    ) : (
                      <MinusCircle className="h-3.5 w-3.5 shrink-0 text-gray-600" />
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Optimal Weights & Confusion Matrix */}
          <div className="mt-4 grid grid-cols-1 gap-3 border-t border-[#1F2937] pt-3 sm:grid-cols-2">
            <div className="rounded-md border border-[#1F2937] bg-[#0B0F19] p-3">
              <div className="text-[11px] font-medium uppercase tracking-wider text-gray-400">
                Función de Riesgo Híbrido
              </div>
              <div className="mono-num mt-1.5 text-xs text-cyan-300">
                R = {ga_config.weights.w_mlp.toFixed(2)}·MLP +{' '}
                {ga_config.weights.w_ae.toFixed(2)}·AE
              </div>
              <div className="mono-num mt-1 text-[11px] text-gray-400">
                Umbral de alerta ALTO: thr = {ga_config.threshold.toFixed(2)}
              </div>
            </div>

            <div className="rounded-md border border-[#1F2937] bg-[#0B0F19] p-3">
              <div className="text-[11px] font-medium uppercase tracking-wider text-gray-400">
                Matriz de Confusión (Ensamble)
              </div>
              <div className="mono-num mt-1.5 grid grid-cols-2 gap-1.5 text-[11px]">
                <div className="rounded bg-emerald-500/10 px-2 py-1 text-emerald-400">
                  TN: {cm.tn}
                </div>
                <div className="rounded bg-amber-500/10 px-2 py-1 text-amber-400">
                  FP: {cm.fp}
                </div>
                <div className="rounded bg-amber-500/10 px-2 py-1 text-amber-400">
                  FN: {cm.fn}
                </div>
                <div className="rounded bg-emerald-500/10 px-2 py-1 text-emerald-400">
                  TP: {cm.tp}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Row 3: Model Comparison Table + Grouped BarChart */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="rounded-lg border border-[#1F2937] bg-[#111827] xl:col-span-7">
          <div className="border-b border-[#1F2937] px-4 py-3">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-gray-100">
              <GitCompare className="h-4 w-4 text-[#06B6D4]" />
              Comparativa de Modelos (Validación Cruzada k=
              {model_metrics.dataset.cv_folds})
            </h2>
            <p className="text-xs text-gray-400">
              Evaluación sobre los {ga_config.selected_features.length} atributos
              óptimos seleccionados por el AG
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full min-w-[600px] border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-[#1F2937] bg-[#0D1321] text-[11px] font-medium uppercase tracking-wider text-gray-400">
                  <th className="px-4 py-2.5">Modelo</th>
                  <th className="px-4 py-2.5">Paradigma</th>
                  <th className="px-4 py-2.5 text-right">Precisión</th>
                  <th className="px-4 py-2.5 text-right">Recall</th>
                  <th className="px-4 py-2.5 text-right">F1-Score</th>
                  <th className="px-4 py-2.5 text-right">Latencia (ms)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2937]">
                {modelRows.map((row) => (
                  <tr
                    key={row.key}
                    className={
                      row.isHybrid
                        ? 'bg-cyan-500/5 font-medium text-cyan-100'
                        : 'text-gray-200'
                    }
                  >
                    <td className="px-4 py-3">
                      <div className="font-medium">{row.displayName}</div>
                    </td>
                    <td className="px-4 py-3 text-gray-400">{row.paradigm}</td>
                    <td className="mono-num px-4 py-3 text-right">
                      {(row.precision * 100).toFixed(2)}%
                    </td>
                    <td className="mono-num px-4 py-3 text-right">
                      {(row.recall * 100).toFixed(2)}%
                    </td>
                    <td className="mono-num px-4 py-3 text-right font-semibold text-cyan-300">
                      {(row.f1_score * 100).toFixed(2)}%
                    </td>
                    <td className="mono-num px-4 py-3 text-right text-gray-300">
                      {row.avg_latency_ms.toFixed(4)} ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4 xl:col-span-5">
          <div className="mb-3">
            <h2 className="text-sm font-semibold text-gray-100">
              Rendimiento Comparativo (%)
            </h2>
            <p className="text-xs text-gray-400">
              Precisión, Recall y F1-Score por arquitectura evaluada
            </p>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height={256}>
              <BarChart
                data={barChartData}
                margin={{ top: 8, right: 12, left: -12, bottom: 0 }}
              >
                <CartesianGrid
                  stroke="#1F2937"
                  strokeDasharray="3 3"
                  vertical={false}
                />
                <XAxis
                  dataKey="name"
                  stroke="#6B7280"
                  tick={{ fontSize: 11, fill: '#9CA3AF' }}
                />
                <YAxis
                  domain={[80, 100]}
                  stroke="#6B7280"
                  tickFormatter={(v: number) => `${v}%`}
                  tick={{ fontSize: 11, fill: '#9CA3AF', fontFamily: 'JetBrains Mono' }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0B0F19',
                    borderColor: '#1F2937',
                    borderRadius: '6px',
                    fontSize: '12px',
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '6px' }} />
                <Bar dataKey="Precisión" fill="#06B6D4" radius={[3, 3, 0, 0]} />
                <Bar dataKey="Recall" fill="#10B981" radius={[3, 3, 0, 0]} />
                <Bar dataKey="F1-Score" fill="#F59E0B" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>
    </div>
  );
}
