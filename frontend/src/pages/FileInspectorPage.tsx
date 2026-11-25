import { useMemo, useRef, useState, type DragEvent } from 'react';
import {
  AlertCircle,
  FileCode2,
  FileUp,
  Loader2,
  ShieldCheck,
} from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import { analyzeFile } from '../services/api';
import {
  THREAT_COLORS,
  type AnalyzedFlow,
  type FileAnalysisResponse,
  type RiskFilter,
} from '../types/ciphertrace';

interface FileInspectorPageProps {
  onSelectFlow: (flow: AnalyzedFlow) => void;
  onAnalysisComplete?: () => void;
}

const ACCEPTED_EXTENSIONS = ['.pcap', '.pcapng', '.csv'];
const FILTER_OPTIONS: RiskFilter[] = ['TODOS', 'ALTO', 'MEDIO', 'BAJO'];

function isValidCaptureFile(filename: string): boolean {
  const lower = filename.toLowerCase();
  return ACCEPTED_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function FileInspectorPage({
  onSelectFlow,
  onAnalysisComplete,
}: FileInspectorPageProps) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<FileAnalysisResponse | null>(null);
  const [elapsedMs, setElapsedMs] = useState<number>(0);
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('TODOS');

  const processUpload = async (file: File) => {
    if (!isValidCaptureFile(file.name)) {
      setError(
        'Formato no soportado. Selecciona un archivo .pcap, .pcapng o .csv.',
      );
      return;
    }

    setSelectedFile(file);
    setError(null);
    setIsAnalyzing(true);
    const t0 = performance.now();

    try {
      const response = await analyzeFile(file);
      setElapsedMs(performance.now() - t0);
      setResult(response);
      setRiskFilter('TODOS');
      onAnalysisComplete?.();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Error analizando el archivo en el servidor.',
      );
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
    const dropped = event.dataTransfer.files?.[0];
    if (dropped) {
      void processUpload(dropped);
    }
  };

  const filteredFlows = useMemo(() => {
    if (!result) return [];
    if (riskFilter === 'TODOS') return result.flows;
    return result.flows.filter((f) => f.risk_level === riskFilter);
  }, [result, riskFilter]);

  const maliciousCount = result
    ? (result.risk_summary?.ALTO ?? 0) + (result.risk_summary?.MEDIO ?? 0)
    : 0;
  const maliciousRate =
    result && result.total_flows_analyzed > 0
      ? (maliciousCount / result.total_flows_analyzed) * 100
      : 0;

  return (
    <div className="space-y-5">
      {/* Drag & Drop Upload Zone */}
      <section className="rounded-lg border border-[#1F2937] bg-[#111827] p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-gray-100">
              Inspector Pasivo de Capturas PCAP / CSV
            </h2>
            <p className="text-xs text-gray-400">
              Extracción de flujos TLS y evaluación sin descifrado mediante{' '}
              <span className="mono-num">POST /api/analyze/file</span>
            </p>
          </div>
          <span className="inline-flex items-center gap-1.5 rounded border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-1 text-[11px] text-cyan-300">
            <ShieldCheck className="h-3.5 w-3.5" />
            Formatos: .pcap, .pcapng, .csv
          </span>
        </div>

        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng,.csv"
          className="hidden"
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) {
              void processUpload(file);
            }
            event.target.value = '';
          }}
        />

        <div
          onDragOver={(event) => {
            event.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          onClick={() => {
            if (!isAnalyzing) fileInputRef.current?.click();
          }}
          role="button"
          tabIndex={0}
          onKeyDown={(event) => {
            if ((event.key === 'Enter' || event.key === ' ') && !isAnalyzing) {
              event.preventDefault();
              fileInputRef.current?.click();
            }
          }}
          className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors ${
            isDragging
              ? 'border-[#06B6D4] bg-cyan-500/10'
              : 'border-[#1F2937] bg-[#0B0F19] hover:border-gray-600'
          } ${isAnalyzing ? 'pointer-events-none opacity-80' : ''}`}
        >
          {isAnalyzing ? (
            <>
              <Loader2 className="h-9 w-9 animate-spin text-[#06B6D4]" />
              <div className="mt-3 text-sm font-medium text-gray-100">
                Analizando{' '}
                <span className="mono-num text-cyan-300">
                  {selectedFile?.name}
                </span>
              </div>
              <p className="mt-1 text-xs text-gray-400">
                Extrayendo metadatos pasivos y ejecutando inferencia híbrida
                MLP + Autoencoder...
              </p>
            </>
          ) : (
            <>
              <div className="flex h-11 w-11 items-center justify-center rounded-full border border-cyan-500/30 bg-cyan-500/10 text-[#06B6D4]">
                <FileUp className="h-5 w-5" />
              </div>
              <div className="mt-3 text-sm font-medium text-gray-100">
                Arrastra tu captura <span className="mono-num">.pcap</span> o{' '}
                <span className="mono-num">.csv</span> aquí, o haz clic para
                seleccionarla
              </div>
              <p className="mt-1 text-xs text-gray-400">
                El backend evalúa cada flujo extraído y emite alertas en vivo
                hacia el SOC.
              </p>
              {selectedFile && (
                <div className="mono-num mt-3 inline-flex items-center gap-2 rounded border border-[#1F2937] bg-[#111827] px-3 py-1 text-xs text-gray-300">
                  <FileCode2 className="h-3.5 w-3.5 text-[#06B6D4]" />
                  <span>
                    Último archivo: {selectedFile.name} (
                    {formatBytes(selectedFile.size)})
                  </span>
                </div>
              )}
            </>
          )}
        </div>

        {error && (
          <div className="mt-4 flex items-center gap-2 rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-xs text-red-300">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </section>

      {/* Analysis Summary + Results Table */}
      {result && (
        <>
          <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4">
              <div className="text-xs text-gray-400">Archivo Procesado</div>
              <div className="mono-num mt-1.5 truncate text-sm font-semibold text-gray-100">
                {result.filename}
              </div>
              <div className="mono-num mt-1 text-xs text-cyan-300">
                {result.total_flows_analyzed.toLocaleString('es-ES')} flujos
                extraídos
              </div>
            </div>

            <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4">
              <div className="text-xs text-gray-400">
                Maliciosos / Sospechosos
              </div>
              <div className="mono-num mt-1.5 text-2xl font-semibold text-red-400">
                {maliciousCount.toLocaleString('es-ES')}
              </div>
              <div className="mono-num mt-1 flex items-center gap-3 text-[11px]">
                <span className="text-red-400">
                  ALTO: {result.risk_summary?.ALTO ?? 0}
                </span>
                <span className="text-amber-400">
                  MEDIO: {result.risk_summary?.MEDIO ?? 0}
                </span>
              </div>
            </div>

            <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4">
              <div className="text-xs text-gray-400">
                Tiempo Total de Análisis
              </div>
              <div className="mono-num mt-1.5 text-2xl font-semibold text-cyan-300">
                {elapsedMs.toFixed(0)}{' '}
                <span className="text-sm font-normal text-gray-400">ms</span>
              </div>
              <div className="mono-num mt-1 text-[11px] text-gray-400">
                {result.alerts_triggered} alertas persistidas
              </div>
            </div>

            <div className="rounded-lg border border-[#1F2937] bg-[#111827] p-4">
              <div className="text-xs text-gray-400">
                Proporción de Amenaza
              </div>
              <div className="mono-num mt-1.5 text-2xl font-semibold text-gray-100">
                {maliciousRate.toFixed(1)}
                <span className="text-sm font-normal text-gray-400">%</span>
              </div>
              <div className="mono-num mt-1 text-[11px] text-emerald-400">
                Benignos (BAJO): {result.risk_summary?.BAJO ?? 0}
              </div>
            </div>
          </section>

          <section className="rounded-lg border border-[#1F2937] bg-[#111827]">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#1F2937] px-4 py-3">
              <div>
                <h3 className="text-sm font-semibold text-gray-100">
                  Resultados Flujo por Flujo ({filteredFlows.length})
                </h3>
                <p className="text-xs text-gray-400">
                  Haz clic en cualquier flujo para revisar scores por modelo y
                  explicabilidad XAI
                </p>
              </div>

              <div className="inline-flex rounded-md border border-[#1F2937] bg-[#0B0F19] p-0.5">
                {FILTER_OPTIONS.map((option) => (
                  <button
                    key={option}
                    type="button"
                    onClick={() => setRiskFilter(option)}
                    className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                      riskFilter === option
                        ? 'bg-[#1F2937] text-cyan-300'
                        : 'text-gray-400 hover:text-gray-200'
                    }`}
                  >
                    {option}
                  </button>
                ))}
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full min-w-[880px] border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-[#1F2937] bg-[#0D1321] text-[11px] font-medium uppercase tracking-wider text-gray-400">
                    <th className="px-4 py-2.5">Flow ID</th>
                    <th className="px-4 py-2.5">Origen → Destino</th>
                    <th className="px-4 py-2.5">Vector</th>
                    <th className="px-4 py-2.5 text-right">MLP</th>
                    <th className="px-4 py-2.5 text-right">Autoencoder</th>
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
                        className="px-4 py-8 text-center text-xs text-gray-500"
                      >
                        No hay flujos en este archivo para el filtro{' '}
                        {riskFilter}.
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
                          <td className="mono-num px-4 py-2.5 text-gray-300">
                            {flow.flow_id}
                          </td>
                          <td className="mono-num px-4 py-2.5 text-gray-200">
                            {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:
                            {flow.dst_port}
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
                          <td className="mono-num px-4 py-2.5 text-right text-cyan-300">
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
        </>
      )}
    </div>
  );
}
