import type { KeyboardEvent } from 'react';
import { Activity } from 'lucide-react';
import type { AnalyzedFlow } from '../../types/ciphertrace';
import { EmptyState } from '../ui/EmptyState';
import { SkeletonTable } from '../ui/Skeleton';
import { RiskBadge } from './RiskBadge';
import { ThreatBadge } from './ThreatBadge';

interface FlowsTableProps {
  flows: AnalyzedFlow[];
  onSelectFlow: (flow: AnalyzedFlow) => void;
  selectedFlowId?: string | null;
  firstColumn?: 'timestamp' | 'flow_id';
  loading?: boolean;
  emptyTitle?: string;
  emptyDescription?: string;
}

function formatClockTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleTimeString('es-ES', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/**
 * Unified, keyboard-accessible operational table for analyzed encrypted flows.
 */
export function FlowsTable({
  flows,
  onSelectFlow,
  selectedFlowId = null,
  firstColumn = 'timestamp',
  loading = false,
  emptyTitle = 'Sin flujos registrados',
  emptyDescription = 'No hay flujos que coincidan con el filtro seleccionado.',
}: FlowsTableProps) {
  const handleRowKeyDown = (
    event: KeyboardEvent<HTMLTableRowElement>,
    flow: AnalyzedFlow,
  ) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onSelectFlow(flow);
    }
  };

  if (loading && flows.length === 0) {
    return <SkeletonTable rows={6} />;
  }

  if (flows.length === 0) {
    return (
      <EmptyState
        icon={Activity}
        title={emptyTitle}
        description={emptyDescription}
      />
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[900px] border-collapse text-left text-[13px]">
        <thead>
          <tr className="border-b border-[#343D43]/60 bg-[#151A1E]/60 text-xs font-medium text-[#A1ABB3]">
            <th className="px-5 py-3">
              {firstColumn === 'flow_id' ? 'Flow ID' : 'Hora'}
            </th>
            <th className="px-4 py-3">Origen → Destino</th>
            <th className="px-4 py-3">Vector detectado</th>
            <th className="px-4 py-3 text-right">Score MLP</th>
            <th className="px-4 py-3 text-right">Anomalía AE</th>
            <th className="px-4 py-3 text-right">Riesgo final</th>
            <th className="px-4 py-3">Nivel</th>
            <th className="px-5 py-3 text-right">Latencia</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[#343D43]/50">
          {flows.map((flow) => {
            const isSelected = selectedFlowId === flow.flow_id;
            return (
              <tr
                key={`${flow.id}-${flow.flow_id}`}
                tabIndex={0}
                role="button"
                aria-label={`Inspeccionar flujo ${flow.flow_id}, riesgo ${flow.risk_level}`}
                onClick={() => onSelectFlow(flow)}
                onKeyDown={(e) => handleRowKeyDown(e, flow)}
                className={`cursor-pointer transition-colors duration-150 focus-visible:bg-[#272F35] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[#5795F2]/75 ${
                  isSelected
                    ? 'bg-[#5795F2]/12'
                    : 'hover:bg-[#272F35]/55'
                }`}
              >
                <td className="whitespace-nowrap px-5 py-3 text-xs text-[#A1ABB3]">
                  {firstColumn === 'flow_id' ? (
                    <span className="tech-mono text-[#F2F4F5]">
                      {flow.flow_id}
                    </span>
                  ) : (
                    <span className="tabular-nums">
                      {formatClockTime(flow.timestamp_utc)}
                    </span>
                  )}
                </td>

                <td className="px-4 py-3">
                  <div className="tech-mono text-xs text-[#F2F4F5]">
                    {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}
                  </div>
                  {flow.sni && (
                    <div className="tech-mono mt-0.5 max-w-xs truncate text-[11px] text-[#8E99A2]">
                      SNI: {flow.sni}
                    </div>
                  )}
                </td>

                <td className="px-4 py-3">
                  <ThreatBadge vector={flow.predicted_threat} />
                </td>

                <td className="tabular-nums px-4 py-3 text-right text-[#A1ABB3]">
                  {flow.prob_mlp.toFixed(3)}
                </td>

                <td className="tabular-nums px-4 py-3 text-right text-[#A1ABB3]">
                  {flow.anomaly_ae.toFixed(3)}
                </td>

                <td className="tabular-nums px-4 py-3 text-right font-semibold text-[#F2F4F5]">
                  {flow.risk_score.toFixed(3)}
                </td>

                <td className="px-4 py-3">
                  <RiskBadge level={flow.risk_level} />
                </td>

                <td className="tabular-nums whitespace-nowrap px-5 py-3 text-right text-[#79ABFF]">
                  {flow.inference_latency_ms.toFixed(2)} ms
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
