import { Lock, Menu, RefreshCw } from 'lucide-react';
import { Button } from '../ui/Button';

interface HeaderProps {
  title: string;
  subtitle: string;
  isRefreshing: boolean;
  onRefresh: () => void;
  onOpenMobileSidebar: () => void;
}

/**
 * Compact sticky SOC top bar matching the sidebar neutral surface.
 */
export function Header({
  title,
  subtitle,
  isRefreshing,
  onRefresh,
  onOpenMobileSidebar,
}: HeaderProps) {
  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-3 border-b border-[#343D43]/65 bg-[#151A1E]/90 px-4 backdrop-blur-md sm:px-6">
      <div className="flex min-w-0 items-center gap-3">
        <button
          type="button"
          onClick={onOpenMobileSidebar}
          className="pressable rounded-[10px] border border-[#343D43] bg-[#272F35] p-1.5 text-[#A1ABB3] hover:text-[#F2F4F5] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#5795F2]/75 lg:hidden"
          aria-label="Abrir menú de navegación"
        >
          <Menu className="h-4 w-4" strokeWidth={1.75} />
        </button>

        <div className="min-w-0">
          <h1 className="truncate text-base font-semibold tracking-[-0.015em] text-[#F2F4F5] sm:text-[18px]">
            {title}
          </h1>
          <p className="hidden truncate text-xs text-[#A1ABB3] sm:block">
            {subtitle}
          </p>
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-2.5">
        <span className="hidden items-center gap-1.5 rounded-[10px] border border-[#5795F2]/30 bg-[#5795F2]/12 px-2.5 py-1.5 text-xs font-medium text-[#79ABFF] md:inline-flex">
          <Lock className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
          <span>Análisis pasivo · Sin descifrado</span>
        </span>

        <Button
          variant="secondary"
          size="sm"
          onClick={onRefresh}
          disabled={isRefreshing}
          title="Actualizar telemetría"
          icon={
            <RefreshCw
              className={`h-3.5 w-3.5 text-[#79ABFF] ${
                isRefreshing ? 'animate-spin' : ''
              }`}
              strokeWidth={1.75}
            />
          }
        >
          <span className="hidden sm:inline">Actualizar</span>
        </Button>
      </div>
    </header>
  );
}
