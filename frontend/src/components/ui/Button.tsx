import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { Loader2 } from 'lucide-react';

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger-subtle';
type ButtonSize = 'sm' | 'md';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  icon?: ReactNode;
  children: ReactNode;
}

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  primary:
    'bg-[#5795F2] text-[#101416] font-semibold hover:bg-[#79ABFF] border border-transparent',
  secondary:
    'bg-[#272F35] text-[#F2F4F5] font-medium border border-[#343D43] hover:bg-[#2E383F] hover:border-[#465159]',
  ghost:
    'bg-transparent text-[#A1ABB3] font-medium border border-transparent hover:bg-[#272F35] hover:text-[#F2F4F5]',
  'danger-subtle':
    'bg-[#E56B6F]/15 text-[#F08A8D] font-medium border border-[#E56B6F]/30 hover:bg-[#E56B6F]/25',
};

const SIZE_CLASSES: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-xs gap-1.5 rounded-[10px]',
  md: 'h-9 px-3.5 text-xs gap-2 rounded-[10px]',
};

/**
 * Accessible action button with Emil Kowalski press feedback and WCAG AA contrast.
 */
export function Button({
  variant = 'secondary',
  size = 'md',
  loading = false,
  icon,
  disabled,
  type = 'button',
  className = '',
  children,
  ...rest
}: ButtonProps) {
  const isDisabled = Boolean(disabled || loading);

  return (
    <button
      type={type}
      disabled={isDisabled}
      className={`pressable inline-flex items-center justify-center whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#5795F2]/75 focus-visible:ring-offset-2 focus-visible:ring-offset-[#101416] disabled:cursor-not-allowed disabled:opacity-50 ${VARIANT_CLASSES[variant]} ${SIZE_CLASSES[size]} ${className}`}
      {...rest}
    >
      {loading ? (
        <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" aria-hidden="true" />
      ) : (
        icon && <span className="shrink-0">{icon}</span>
      )}
      <span>{children}</span>
    </button>
  );
}
