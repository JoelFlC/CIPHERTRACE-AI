import type { ReactNode } from 'react';
import { AlertCircle, AlertTriangle, CheckCircle2, Info } from 'lucide-react';

type AlertVariant = 'error' | 'warning' | 'info' | 'success';

interface AlertBannerProps {
  variant?: AlertVariant;
  children: ReactNode;
  className?: string;
}

const VARIANT_CONFIG: Record<
  AlertVariant,
  { container: string; icon: typeof Info }
> = {
  error: {
    container: 'border-[#E56B6F]/30 bg-[#E56B6F]/14 text-[#F08A8D]',
    icon: AlertCircle,
  },
  warning: {
    container: 'border-[#F2A544]/30 bg-[#F2A544]/14 text-[#F2A544]',
    icon: AlertTriangle,
  },
  info: {
    container: 'border-[#5795F2]/30 bg-[#5795F2]/14 text-[#79ABFF]',
    icon: Info,
  },
  success: {
    container: 'border-[#36C995]/30 bg-[#36C995]/14 text-[#36C995]',
    icon: CheckCircle2,
  },
};

/**
 * Semantic inline notification banner with WCAG AA verified contrast.
 */
export function AlertBanner({
  variant = 'info',
  children,
  className = '',
}: AlertBannerProps) {
  const { container, icon: Icon } = VARIANT_CONFIG[variant];

  return (
    <div
      role={variant === 'error' || variant === 'warning' ? 'alert' : 'status'}
      className={`flex items-start gap-2.5 rounded-[10px] border px-3.5 py-2.5 text-xs leading-relaxed ${container} ${className}`}
    >
      <Icon className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.75} aria-hidden="true" />
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}
