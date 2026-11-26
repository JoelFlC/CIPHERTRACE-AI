import type { RiskLevel } from '../../types/ciphertrace';

interface RiskBadgeProps {
  level: RiskLevel;
  score?: number;
  size?: 'sm' | 'md';
}

const LEVEL_STYLES: Record<
  RiskLevel,
  { badge: string; dot: string; label: string }
> = {
  ALTO: {
    badge: 'bg-[#E56B6F]/14 border-[#E56B6F]/30 text-[#F08A8D]',
    dot: 'bg-[#E56B6F]',
    label: 'ALTO',
  },
  MEDIO: {
    badge: 'bg-[#F2A544]/14 border-[#F2A544]/30 text-[#F2A544]',
    dot: 'bg-[#F2A544]',
    label: 'MEDIO',
  },
  BAJO: {
    badge: 'bg-[#36C995]/14 border-[#36C995]/30 text-[#36C995]',
    dot: 'bg-[#36C995]',
    label: 'BAJO',
  },
};

/**
 * Semantic risk severity pill with dot indicator, text label, and WCAG AA contrast.
 */
export function RiskBadge({ level, score, size = 'sm' }: RiskBadgeProps) {
  const style = LEVEL_STYLES[level] ?? LEVEL_STYLES.BAJO;
  const paddingClass =
    size === 'md' ? 'px-2.5 py-1 text-xs' : 'px-2 py-0.5 text-[11px]';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border font-medium ${paddingClass} ${style.badge}`}
    >
      <span
        className={`h-1.5 w-1.5 shrink-0 rounded-full ${style.dot}`}
        aria-hidden="true"
      />
      <span>{style.label}</span>
      {typeof score === 'number' && (
        <span className="tabular-nums opacity-90">({score.toFixed(2)})</span>
      )}
    </span>
  );
}
