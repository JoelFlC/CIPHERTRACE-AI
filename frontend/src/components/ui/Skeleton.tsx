interface SkeletonBlockProps {
  className?: string;
}

export function SkeletonBlock({ className = '' }: SkeletonBlockProps) {
  return (
    <div
      aria-hidden="true"
      className={`animate-pulse rounded-md bg-[#272F35] ${className}`}
    />
  );
}

/**
 * Structural skeleton matching the 4-column MetricStrip container.
 */
export function SkeletonMetricStrip() {
  return (
    <div
      aria-label="Cargando métricas"
      className="grid grid-cols-1 divide-y divide-[#343D43]/60 rounded-2xl border border-[#343D43]/70 bg-[#1C2226] sm:grid-cols-2 sm:divide-y-0 xl:grid-cols-4 xl:divide-x"
    >
      {[0, 1, 2, 3].map((idx) => (
        <div key={idx} className="space-y-2.5 p-5">
          <SkeletonBlock className="h-3.5 w-28" />
          <SkeletonBlock className="h-7 w-24" />
          <SkeletonBlock className="h-3 w-36" />
        </div>
      ))}
    </div>
  );
}

/**
 * Structural skeleton for flow tables while initial telemetry loads.
 */
export function SkeletonTable({ rows = 5 }: { rows?: number }) {
  return (
    <div aria-label="Cargando registros" className="divide-y divide-[#343D43]/50">
      {Array.from({ length: rows }).map((_, idx) => (
        <div key={idx} className="flex items-center justify-between gap-4 px-5 py-3.5">
          <SkeletonBlock className="h-3.5 w-16" />
          <SkeletonBlock className="h-3.5 w-48" />
          <SkeletonBlock className="h-5 w-28 rounded-full" />
          <SkeletonBlock className="h-3.5 w-14" />
          <SkeletonBlock className="h-5 w-16" />
        </div>
      ))}
    </div>
  );
}
