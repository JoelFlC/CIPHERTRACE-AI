import type { RiskLevel } from '../types/ciphertrace';

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
    badge: 'bg-red-500/10 border-red-500/30 text-red-400',
    dot: 'bg-[#EF4444]',
    label: 'ALTO',
  },
  MEDIO: {
    badge: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
    dot: 'bg-[#F59E0B]',
    label: 'MEDIO',
  },
  BAJO: {
    badge: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    dot: 'bg-[#10B981]',
    label: 'BAJO',
  },
};

export function RiskBadge({ level, score, size = 'sm' }: RiskBadgeProps) {
  const style = LEVEL_STYLES[level] ?? LEVEL_STYLES.BAJO;
  const paddingClass =
    size === 'md' ? 'px-2.5 py-1 text-xs' : 'px-2 py-0.5 text-[11px]';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border font-medium tracking-wide ${paddingClass} ${style.badge}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} aria-hidden="true" />
      <span>{style.label}</span>
      {typeof score === 'number' && (
        <span className="mono-num opacity-85">({score.toFixed(2)})</span>
      )}
    </span>
  );
}
