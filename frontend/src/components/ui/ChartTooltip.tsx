import type { ReactNode } from 'react';

interface ChartTooltipProps {
  children: ReactNode;
  className?: string;
}

/**
 * Shared floating tooltip surface for Recharts visualizations.
 */
export function ChartTooltip({ children, className = '' }: ChartTooltipProps) {
  return (
    <div
      className={`rounded-[10px] border border-[#343D43] bg-[#272F35] px-3 py-2.5 text-xs text-[#F2F4F5] shadow-[0_16px_40px_rgba(0,0,0,0.45)] ${className}`}
    >
      {children}
    </div>
  );
}
