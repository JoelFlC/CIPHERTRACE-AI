import type { ReactNode } from 'react';

interface BentoCardProps {
  title?: ReactNode;
  subtitle?: ReactNode;
  action?: ReactNode;
  noPadding?: boolean;
  headerDivider?: boolean;
  className?: string;
  children: ReactNode;
}

/**
 * Base Dark Bento Grid container (#1C2226) with hairline border (#343D43) and 16px radius.
 */
export function BentoCard({
  title,
  subtitle,
  action,
  noPadding = false,
  headerDivider = false,
  className = '',
  children,
}: BentoCardProps) {
  const hasHeader = Boolean(title || subtitle || action);

  return (
    <section
      className={`rounded-2xl border border-[#343D43]/70 bg-[#1C2226] ${
        noPadding ? 'overflow-hidden' : 'p-5'
      } ${className}`}
    >
      {hasHeader && (
        <div
          className={`flex flex-wrap items-start justify-between gap-3 ${
            noPadding ? 'px-5 py-4' : 'mb-4'
          } ${
            headerDivider || noPadding
              ? 'border-b border-[#343D43]/60'
              : ''
          } ${!noPadding && headerDivider ? 'pb-4' : ''}`}
        >
          <div className="min-w-0">
            {title && (
              <h2 className="text-sm font-semibold tracking-[-0.005em] text-[#F2F4F5]">
                {title}
              </h2>
            )}
            {subtitle && (
              <p className="mt-0.5 text-xs leading-relaxed text-[#A1ABB3]">
                {subtitle}
              </p>
            )}
          </div>
          {action && <div className="shrink-0">{action}</div>}
        </div>
      )}
      {children}
    </section>
  );
}
