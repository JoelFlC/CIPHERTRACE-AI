import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}

/**
 * Actionable empty state without noisy dashed boxes.
 */
export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  className = '',
}: EmptyStateProps) {
  return (
    <div
      className={`flex flex-col items-center justify-center px-6 py-10 text-center ${className}`}
    >
      <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#272F35] text-[#8E99A2]">
        <Icon className="h-5 w-5" strokeWidth={1.75} aria-hidden="true" />
      </div>
      <p className="mt-3 text-sm font-medium text-[#F2F4F5]">{title}</p>
      {description && (
        <p className="mt-1 max-w-md text-xs leading-relaxed text-[#A1ABB3]">
          {description}
        </p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
