import type { ReactNode } from 'react';

export interface MetricItem {
  id: string;
  label: string;
  value: string;
  unit?: string;
  tone?: 'default' | 'accent' | 'danger' | 'success';
  detail?: ReactNode;
  progress?: {
    pct: number;
    color: string;
  };
}

interface MetricStripProps {
  items: MetricItem[];
  className?: string;
}

const VALUE_TONE_CLASSES: Record<NonNullable<MetricItem['tone']>, string> = {
  default: 'text-[#F2F4F5]',
  accent: 'text-[#79ABFF]',
  danger: 'text-[#F08A8D]',
  success: 'text-[#36C995]',
};

/**
 * Shared Bento KPI surface separating related metrics with subtle hairlines.
 */
export function MetricStrip({ items, className = '' }: MetricStripProps) {
  return (
    <section
      className={`grid grid-cols-1 divide-y divide-[#343D43]/60 rounded-2xl border border-[#343D43]/70 bg-[#1C2226] sm:grid-cols-2 sm:divide-y-0 xl:grid-cols-4 xl:divide-x ${className}`}
    >
      {items.map((item, idx) => {
        const tone = item.tone ?? 'default';
        const smTopBorder =
          idx >= 2 ? 'sm:border-t sm:border-[#343D43]/60 xl:border-t-0' : '';
        const smRightBorder =
          idx % 2 === 0 ? 'sm:border-r sm:border-[#343D43]/60 xl:border-r-0' : '';

        return (
          <div
            key={item.id}
            className={`flex flex-col justify-between p-5 ${smTopBorder} ${smRightBorder}`}
          >
            <div className="text-xs font-medium text-[#A1ABB3]">{item.label}</div>

            <div
              className={`tabular-nums mt-2 text-[26px] font-semibold leading-tight tracking-[-0.02em] ${VALUE_TONE_CLASSES[tone]}`}
            >
              {item.value}
              {item.unit && (
                <span className="ml-1 text-sm font-normal text-[#A1ABB3]">
                  {item.unit}
                </span>
              )}
            </div>

            {item.progress ? (
              <div className="mt-3">
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-[#272F35]">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${Math.min(
                        100,
                        Math.max(item.progress.pct > 0 ? 3 : 0, item.progress.pct),
                      )}%`,
                      backgroundColor: item.progress.color,
                    }}
                  />
                </div>
                {item.detail && (
                  <div className="mt-1.5 text-xs text-[#A1ABB3]">
                    {item.detail}
                  </div>
                )}
              </div>
            ) : (
              item.detail && (
                <div className="tabular-nums mt-2 text-xs text-[#A1ABB3]">
                  {item.detail}
                </div>
              )
            )}
          </div>
        );
      })}
    </section>
  );
}
