export interface SegmentedOption<T extends string | number> {
  value: T;
  label: string;
}

interface SegmentedControlProps<T extends string | number> {
  options: Array<SegmentedOption<T>>;
  value: T;
  onChange: (value: T) => void;
  ariaLabel: string;
  tabular?: boolean;
  className?: string;
}

/**
 * Compact mutually exclusive segmented selector with instant state feedback.
 */
export function SegmentedControl<T extends string | number>({
  options,
  value,
  onChange,
  ariaLabel,
  tabular = false,
  className = '',
}: SegmentedControlProps<T>) {
  return (
    <div
      role="group"
      aria-label={ariaLabel}
      className={`inline-flex items-center rounded-[10px] border border-[#343D43]/75 bg-[#101416] p-0.5 ${className}`}
    >
      {options.map((opt) => {
        const active = opt.value === value;
        return (
          <button
            key={String(opt.value)}
            type="button"
            aria-pressed={active}
            onClick={() => onChange(opt.value)}
            className={`pressable rounded-md px-2.5 py-1 text-xs font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#5795F2]/75 ${
              tabular ? 'tabular-nums' : ''
            } ${
              active
                ? 'bg-[#272F35] text-[#F2F4F5]'
                : 'text-[#A1ABB3] hover:text-[#F2F4F5]'
            }`}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}
