import { useMemo, useRef, useState, type DragEvent } from 'react';
import {
  FileCode2,
  FileUp,
  FolderOpen,
  Loader2,
  Lock,
  ShieldCheck,
} from 'lucide-react';
import { FlowsTable } from '../components/soc/FlowsTable';
import { MetricStrip, type MetricItem } from '../components/soc/MetricStrip';
import { AlertBanner } from '../components/ui/AlertBanner';
import { BentoCard } from '../components/ui/BentoCard';
import { SegmentedControl } from '../components/ui/SegmentedControl';
import { analyzeFile } from '../services/api';
import type {
  AnalyzedFlow,
  FileAnalysisResponse,
  RiskFilter,
} from '../types/ciphertrace';

interface FileInspectorPageProps {
  selectedFlowId?: string | null;
  onSelectFlow: (flow: AnalyzedFlow) => void;
  onAnalysisComplete?: () => void;
}

const ACCEPTED_EXTENSIONS = ['.pcap', '.pcapng', '.csv'];
const FILTER_OPTIONS: Array<{ value: RiskFilter; label: string }> = [
  { value: 'TODOS', label: 'Todos' },
  { value: 'ALTO', label: 'Alto' },
  { value: 'MEDIO', label: 'Medio' },
  { value: 'BAJO', label: 'Bajo' },
];

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
  selectedFlowId = null,
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

  const metricItems: MetricItem[] = result
    ? [
        {
          id: 'file-name',
          label: 'Archivo procesado',
          value: result.total_flows_analyzed.toLocaleString('es-ES'),
          unit: 'flujos',
          detail: (
            <span className="tech-mono block truncate text-[#79ABFF]">
              {result.filename}
            </span>
          ),
        },
        {
          id: 'malicious-count',
          label: 'Maliciosos / Sospechosos',
          value: maliciousCount.toLocaleString('es-ES'),
          tone: maliciousCount > 0 ? 'danger' : 'success',
          detail: (
            <span className="flex items-center gap-3">
              <span className="text-[#F08A8D]">
                ALTO: {result.risk_summary?.ALTO ?? 0}
              </span>
              <span className="text-[#F2A544]">
                MEDIO: {result.risk_summary?.MEDIO ?? 0}
              </span>
            </span>
          ),
        },
        {
          id: 'analysis-time',
          label: 'Tiempo total de análisis',
          value: elapsedMs.toFixed(0),
          unit: 'ms',
          tone: 'accent',
          detail: `${result.alerts_triggered} alertas persistidas`,
        },
        {
          id: 'threat-rate',
          label: 'Proporción de amenaza',
          value: maliciousRate.toFixed(1),
          unit: '%',
          detail: (
            <span className="text-[#36C995]">
              Benignos (BAJO): {result.risk_summary?.BAJO ?? 0}
            </span>
          ),
        },
      ]
    : [];

  return (
    <div className="space-y-6">
      {/* Row 1: Asymmetric Bento Upload (8) + Passive Scope Reference (4) */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <BentoCard
          className="xl:col-span-8"
          title="Inspector pasivo de capturas PCAP / CSV"
          subtitle={
            <span>
              Extracción de flujos TLS y evaluación sin descifrado mediante{' '}
              <span className="tech-mono text-[#F2F4F5]">
                POST /api/analyze/file
              </span>
            </span>
          }
          action={
            <span className="inline-flex items-center gap-1.5 rounded-md border border-[#5795F2]/30 bg-[#5795F2]/14 px-2.5 py-1 text-xs font-medium text-[#79ABFF]">
              <ShieldCheck className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
              .pcap · .pcapng · .csv
            </span>
          }
        >
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
            aria-label="Seleccionar o arrastrar captura PCAP o CSV para analizar"
            onKeyDown={(event) => {
              if (
                (event.key === 'Enter' || event.key === ' ') &&
                !isAnalyzing
              ) {
                event.preventDefault();
                fileInputRef.current?.click();
              }
            }}
            className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed px-6 py-10 text-center transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#5795F2]/75 ${
              isDragging
                ? 'border-[#5795F2] bg-[#5795F2]/12'
                : 'border-[#343D43] bg-[#101416]/55 hover:border-[#5795F2]/50 hover:bg-[#272F35]/40'
            } ${isAnalyzing ? 'pointer-events-none opacity-80' : ''}`}
          >
            {isAnalyzing ? (
              <>
                <Loader2
                  className="h-8 w-8 animate-spin text-[#5795F2]"
                  strokeWidth={1.75}
                  aria-hidden="true"
                />
                <div className="mt-3 text-sm font-medium text-[#F2F4F5]">
                  Analizando{' '}
                  <span className="tech-mono text-[#79ABFF]">
                    {selectedFile?.name}
                  </span>
                </div>
                <p className="mt-1 text-xs text-[#A1ABB3]">
                  Extrayendo metadatos pasivos y ejecutando inferencia híbrida
                  MLP + Autoencoder...
                </p>
              </>
            ) : (
              <>
                <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-[#5795F2]/30 bg-[#5795F2]/14 text-[#79ABFF]">
                  <FileUp className="h-5 w-5" strokeWidth={1.75} aria-hidden="true" />
                </div>
                <div className="mt-3 text-sm font-medium text-[#F2F4F5]">
                  Arrastra tu captura{' '}
                  <span className="tech-mono text-[#79ABFF]">.pcap</span> o{' '}
                  <span className="tech-mono text-[#79ABFF]">.csv</span> aquí, o
                  haz clic para seleccionarla
                </div>
                <p className="mt-1 text-xs text-[#A1ABB3]">
                  El backend evalúa cada flujo extraído y emite alertas en vivo
                  hacia la consola SOC.
                </p>
                {selectedFile && (
                  <div className="tech-mono mt-4 inline-flex items-center gap-2 rounded-[10px] border border-[#343D43] bg-[#272F35] px-3 py-1.5 text-xs text-[#F2F4F5]">
                    <FileCode2
                      className="h-3.5 w-3.5 text-[#79ABFF]"
                      strokeWidth={1.75}
                      aria-hidden="true"
                    />
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
            <AlertBanner variant="error" className="mt-4">
              {error}
            </AlertBanner>
          )}
        </BentoCard>

        <BentoCard
          className="flex flex-col justify-between xl:col-span-4"
          title="Alcance del análisis offline"
          subtitle="Inspección forense sin claves privadas ni proxy TLS"
          headerDivider
        >
          <div className="divide-y divide-[#343D43]/55 text-xs">
            <div className="flex gap-3 pb-3">
              <Lock
                className="mt-0.5 h-4 w-4 shrink-0 text-[#79ABFF]"
                strokeWidth={1.75}
                aria-hidden="true"
              />
              <div>
                <div className="font-medium text-[#F2F4F5]">
                  18 atributos pasivos observables
                </div>
                <p className="mt-0.5 leading-relaxed text-[#A1ABB3]">
                  Calcula IAT, tamaños de paquete, asimetría, entropía SNI y
                  latencia sin descifrar el payload.
                </p>
              </div>
            </div>

            <div className="flex gap-3 py-3">
              <ShieldCheck
                className="mt-0.5 h-4 w-4 shrink-0 text-[#36C995]"
                strokeWidth={1.75}
                aria-hidden="true"
              />
              <div>
                <div className="font-medium text-[#F2F4F5]">
                  Evaluación con ensamble AG
                </div>
                <p className="mt-0.5 leading-relaxed text-[#A1ABB3]">
                  Aplica la máscara óptima de 8 atributos y pondera MLP +
                  Autoencoder para cada flujo.
                </p>
              </div>
            </div>

            <div className="flex gap-3 pt-3">
              <FolderOpen
                className="mt-0.5 h-4 w-4 shrink-0 text-[#A1ABB3]"
                strokeWidth={1.75}
                aria-hidden="true"
              />
              <div className="min-w-0">
                <div className="font-medium text-[#F2F4F5]">
                  Muestras disponibles en el proyecto
                </div>
                <div className="tech-mono mt-1 space-y-1 text-[11px] text-[#8E99A2]">
                  <div className="truncate">demo_samples/sample_capture.pcap</div>
                  <div className="truncate">
                    demo_samples/mixed_traffic_demo.csv
                  </div>
                </div>
              </div>
            </div>
          </div>
        </BentoCard>
      </section>

      {/* Row 2: Analysis Summary & Results Table */}
      {result && (
        <>
          <MetricStrip items={metricItems} />

          <BentoCard
            noPadding
            title={`Resultados flujo por flujo (${filteredFlows.length})`}
            subtitle="Selecciona cualquier flujo (clic o Enter) para revisar scores por modelo y explicabilidad XAI"
            action={
              <SegmentedControl
                options={FILTER_OPTIONS}
                value={riskFilter}
                onChange={setRiskFilter}
                ariaLabel="Filtrar resultados por nivel de riesgo"
              />
            }
          >
            <FlowsTable
              flows={filteredFlows}
              firstColumn="flow_id"
              selectedFlowId={selectedFlowId}
              onSelectFlow={onSelectFlow}
              emptyTitle="Sin flujos para el filtro actual"
              emptyDescription={`No hay flujos en este archivo con nivel ${riskFilter}.`}
            />
          </BentoCard>
        </>
      )}
    </div>
  );
}
