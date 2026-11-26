import { THREAT_COLORS, THREAT_LABELS } from '../../types/ciphertrace';

interface ThreatBadgeProps {
  vector: string;
  showCode?: boolean;
}

/**
 * Neutral threat classification pill with a categorical color dot.
 */
export function ThreatBadge({ vector, showCode = false }: ThreatBadgeProps) {
  const dotColor = THREAT_COLORS[vector] ?? '#8E99A2';
  const label = THREAT_LABELS[vector] ?? vector;

  return (
    <span
      title={vector}
      className="inline-flex items-center gap-1.5 rounded-md border border-[#343D43] bg-[#272F35] px-2 py-0.5 text-[11px] font-medium text-[#F2F4F5]"
    >
      <span
        className="h-1.5 w-1.5 shrink-0 rounded-full"
        style={{ backgroundColor: dotColor }}
        aria-hidden="true"
      />
      <span>{showCode ? vector : label}</span>
    </span>
  );
}
