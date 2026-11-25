import {
  Activity,
  Cpu,
  Crosshair,
  FileSearch,
  RefreshCw,
  X,
} from 'lucide-react';
import type {
  CaptureStatus,
  HealthResponse,
  NavView,
  WsConnectionStatus,
} from '../types/ciphertrace';

interface SidebarProps {
  activeView: NavView;
  onSelectView: (view: NavView) => void;
  wsStatus: WsConnectionStatus;
  onReconnectWs: () => void;
  activeAlertsCount: number;
  health: HealthResponse | null;
  captureStatus: CaptureStatus | null;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

interface NavItem {
  id: NavView;
  label: string;
  description: string;
  icon: typeof Activity;
}

const NAV_ITEMS: NavItem[] = [
  {
    id: 'overview',
    label: 'Live SOC Overview',
    description: 'Telemetría y alertas en vivo',
    icon: Activity,
  },
  {
    id: 'threat-lab',
    label: 'Laboratorio AiTM',
    description: 'Inyección y proxy inverso',
    icon: Crosshair,
  },
  {
    id: 'model-analytics',
    label: 'Motor IA & AG',
    description: 'Convergencia y métricas k-fold',
    icon: Cpu,
  },
  {
    id: 'file-inspector',
    label: 'Inspector PCAP / CSV',
    description: 'Análisis pasivo offline',
    icon: FileSearch,
  },
];

export function Sidebar({
  activeView,
  onSelectView,
  wsStatus,
  onReconnectWs,
  activeAlertsCount,
  health,
  captureStatus,
  mobileOpen,
  onCloseMobile,
}: SidebarProps) {
  const handleSelect = (view: NavView) => {
    onSelectView(view);
    onCloseMobile();
  };

  return (
    <>
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/70 lg:hidden"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-50 flex w-60 flex-col border-r border-[#1F2937] bg-[#0D1321] transition-transform duration-200 lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
        aria-label="Navegación principal"
      >
        {/* Brand Header */}
        <div className="flex h-14 items-center justify-between border-b border-[#1F2937] px-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-md border border-cyan-500/30 bg-cyan-500/10">
              <svg
                viewBox="0 0 24 24"
                className="h-4 w-4 text-[#06B6D4]"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.9"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M12 2.5 4.5 5.8v5.7c0 5.1 3.2 9.4 7.5 10.7 4.3-1.3 7.5-5.6 7.5-10.7V5.8L12 2.5Z" />
                <path d="M7.5 12h2.2l1.3-2.6 2 5.2 1.3-2.6h2.2" />
              </svg>
            </div>
            <div>
              <div className="text-sm font-semibold tracking-tight text-gray-100">
                CIPHERTRACE <span className="text-[#06B6D4]">AI</span>
              </div>
              <div className="text-[11px] text-gray-400">
                SOC Pasivo TLS · ML/DL
              </div>
            </div>
          </div>

          <button
            type="button"
            onClick={onCloseMobile}
            className="rounded p-1 text-gray-400 hover:bg-gray-800 hover:text-gray-200 lg:hidden"
            aria-label="Cerrar menú lateral"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Live WebSocket Status */}
        <div className="border-b border-[#1F2937] px-4 py-3">
          <div
            className={`flex items-center justify-between rounded-md border px-2.5 py-2 ${
              wsStatus === 'connected'
                ? 'border-emerald-500/30 bg-emerald-500/10'
                : wsStatus === 'connecting'
                  ? 'border-amber-500/30 bg-amber-500/10'
                  : 'border-red-500/30 bg-red-500/10'
            }`}
          >
            <div className="flex items-center gap-2">
              {wsStatus === 'connected' ? (
                <span className="relative flex h-2.5 w-2.5" aria-hidden="true">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-[#10B981]" />
                </span>
              ) : wsStatus === 'connecting' ? (
                <span className="h-2.5 w-2.5 rounded-full bg-[#F59E0B]" aria-hidden="true" />
              ) : (
                <span className="h-2.5 w-2.5 rounded-full bg-[#EF4444]" aria-hidden="true" />
              )}
              <div>
                <div
                  className={`mono-num text-xs font-semibold tracking-wider ${
                    wsStatus === 'connected'
                      ? 'text-emerald-400'
                      : wsStatus === 'connecting'
                        ? 'text-amber-400'
                        : 'text-red-400'
                  }`}
                >
                  {wsStatus === 'connected'
                    ? 'LIVE'
                    : wsStatus === 'connecting'
                      ? 'CONECTANDO'
                      : 'OFFLINE'}
                </div>
                <div className="text-[10px] text-gray-400">
                  Stream /ws/alerts
                </div>
              </div>
            </div>

            {wsStatus === 'disconnected' && (
              <button
                type="button"
                onClick={onReconnectWs}
                className="rounded border border-red-500/30 bg-red-500/15 p-1 text-red-300 transition-colors hover:bg-red-500/25"
                title="Reconectar WebSocket"
                aria-label="Reconectar WebSocket"
              >
                <RefreshCw className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="flex-1 space-y-1 px-2.5 py-3">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeView === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => handleSelect(item.id)}
                className={`group flex w-full items-center justify-between rounded-r-md border-l-2 px-3 py-2.5 text-left transition-colors ${
                  isActive
                    ? 'border-[#06B6D4] bg-cyan-500/10 text-gray-100'
                    : 'border-transparent text-gray-400 hover:bg-[#111827] hover:text-gray-200'
                }`}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <Icon
                    className={`h-4 w-4 shrink-0 ${
                      isActive
                        ? 'text-[#06B6D4]'
                        : 'text-gray-500 group-hover:text-gray-300'
                    }`}
                  />
                  <div className="min-w-0">
                    <div className="truncate text-[13px] font-medium">
                      {item.label}
                    </div>
                    <div className="truncate text-[11px] text-gray-500">
                      {item.description}
                    </div>
                  </div>
                </div>

                {item.id === 'overview' && activeAlertsCount > 0 && (
                  <span className="mono-num ml-2 rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-[10px] font-medium text-red-400">
                    {activeAlertsCount}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Footer Engine Status */}
        <div className="border-t border-[#1F2937] p-3 space-y-2">
          <div className="rounded-md border border-[#1F2937] bg-[#111827] px-3 py-2 text-[11px]">
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Sensor Híbrido</span>
              <span
                className={`mono-num font-semibold ${
                  captureStatus?.running ? 'text-emerald-400' : 'text-cyan-300'
                }`}
              >
                {captureStatus?.running
                  ? `EN VIVO (${captureStatus.interface})`
                  : 'OFFLINE / LAB'}
              </span>
            </div>
          </div>

          <div className="rounded-md border border-[#1F2937] bg-[#111827] p-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-gray-300">Motor Híbrido</span>
              <span
                className={`mono-num text-[11px] ${
                  health?.models_loaded ? 'text-emerald-400' : 'text-gray-500'
                }`}
              >
                {health?.models_loaded ? 'ACTIVO' : 'SIN DATOS'}
              </span>
            </div>
            {health ? (
              <div className="mt-2 grid grid-cols-3 gap-1.5 border-t border-[#1F2937] pt-2 text-[11px]">
                <div>
                  <div className="text-gray-500">w_mlp</div>
                  <div className="mono-num text-cyan-300">
                    {health.hybrid_weights.w_mlp.toFixed(2)}
                  </div>
                </div>
                <div>
                  <div className="text-gray-500">w_ae</div>
                  <div className="mono-num text-cyan-300">
                    {health.hybrid_weights.w_ae.toFixed(2)}
                  </div>
                </div>
                <div>
                  <div className="text-gray-500">Umbral</div>
                  <div className="mono-num text-amber-300">
                    {health.hybrid_weights.threshold.toFixed(2)}
                  </div>
                </div>
              </div>
            ) : (
              <p className="mt-1.5 text-[11px] text-gray-500">
                Esperando respuesta de API en puerto 8000.
              </p>
            )}
          </div>
        </div>
      </aside>
    </>
  );
}
