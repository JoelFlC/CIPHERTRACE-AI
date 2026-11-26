import {
  Activity,
  Cpu,
  Crosshair,
  FileSearch,
  RefreshCw,
  X,
} from 'lucide-react';
import logoUrl from '../../assets/logo.png';
import type {
  HealthResponse,
  NavView,
  WsConnectionStatus,
} from '../../types/ciphertrace';

interface SidebarProps {
  activeView: NavView;
  onSelectView: (view: NavView) => void;
  wsStatus: WsConnectionStatus;
  onReconnectWs: () => void;
  activeAlertsCount: number;
  health: HealthResponse | null;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

interface NavItem {
  id: NavView;
  label: string;
  icon: typeof Activity;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'overview', label: 'Live SOC Overview', icon: Activity },
  { id: 'threat-lab', label: 'Laboratorio AiTM', icon: Crosshair },
  { id: 'model-analytics', label: 'Motor IA & AG', icon: Cpu },
  { id: 'file-inspector', label: 'Inspector PCAP / CSV', icon: FileSearch },
];

/**
 * Restrained SOC navigation sidebar on intermediate neutral layer (#151A1E).
 */
export function Sidebar({
  activeView,
  onSelectView,
  wsStatus,
  onReconnectWs,
  activeAlertsCount,
  health,
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
          className="drawer-backdrop fixed inset-0 z-40 bg-black/65 lg:hidden"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      <aside
        className={`drawer-panel fixed inset-y-0 left-0 z-50 flex w-[248px] flex-col border-r border-[#343D43]/65 bg-[#151A1E] lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
        aria-label="Navegación principal"
      >
        {/* Brand Header */}
        <div className="flex h-14 items-center justify-between gap-2 border-b border-[#343D43]/60 px-4">
          <img
            src={logoUrl}
            alt="CIPHERTRACE AI"
            className="h-11 w-full max-w-[180px] select-none object-contain object-left lg:max-w-[216px]"
          />

          <button
            type="button"
            onClick={onCloseMobile}
            className="pressable rounded-[10px] p-1.5 text-[#A1ABB3] hover:bg-[#272F35] hover:text-[#F2F4F5] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#5795F2]/75 lg:hidden"
            aria-label="Cerrar menú lateral"
          >
            <X className="h-4 w-4" strokeWidth={1.75} />
          </button>
        </div>

        {/* Calm Live Stream Indicator */}
        <div className="border-b border-[#343D43]/60 px-4 py-3">
          <div className="flex items-center justify-between rounded-[10px] bg-[#1C2226] px-3 py-2">
            <div className="flex items-center gap-2.5">
              <span
                className={`h-2 w-2 shrink-0 rounded-full ${
                  wsStatus === 'connected'
                    ? 'bg-[#36C995] ring-4 ring-[#36C995]/15'
                    : wsStatus === 'connecting'
                      ? 'bg-[#F2A544] ring-4 ring-[#F2A544]/15'
                      : 'bg-[#E56B6F] ring-4 ring-[#E56B6F]/15'
                }`}
                aria-hidden="true"
              />
              <div>
                <div
                  className={`text-xs font-semibold ${
                    wsStatus === 'connected'
                      ? 'text-[#36C995]'
                      : wsStatus === 'connecting'
                        ? 'text-[#F2A544]'
                        : 'text-[#F08A8D]'
                  }`}
                >
                  {wsStatus === 'connected'
                    ? 'Stream en vivo'
                    : wsStatus === 'connecting'
                      ? 'Conectando'
                      : 'Sin conexión'}
                </div>
                <div className="tech-mono text-[11px] text-[#8E99A2]">
                  /ws/alerts
                </div>
              </div>
            </div>

            {wsStatus === 'disconnected' && (
              <button
                type="button"
                onClick={onReconnectWs}
                className="pressable rounded-md border border-[#E56B6F]/30 bg-[#E56B6F]/14 p-1.5 text-[#F08A8D] hover:bg-[#E56B6F]/22 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#5795F2]/75"
                title="Reconectar WebSocket"
                aria-label="Reconectar WebSocket"
              >
                <RefreshCw className="h-3.5 w-3.5" strokeWidth={1.75} />
              </button>
            )}
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="flex-1 space-y-1 px-3 py-4">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeView === item.id;
            return (
              <button
                key={item.id}
                type="button"
                aria-current={isActive ? 'page' : undefined}
                onClick={() => handleSelect(item.id)}
                className={`pressable group flex w-full items-center justify-between rounded-[10px] px-3 py-2.5 text-left text-[13px] font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#5795F2]/75 ${
                  isActive
                    ? 'bg-[#5795F2]/14 text-[#F2F4F5]'
                    : 'text-[#A1ABB3] hover:bg-[#272F35]/65 hover:text-[#F2F4F5]'
                }`}
              >
                <span className="flex min-w-0 items-center gap-2.5">
                  <Icon
                    className={`h-4 w-4 shrink-0 ${
                      isActive
                        ? 'text-[#79ABFF]'
                        : 'text-[#8E99A2] group-hover:text-[#F2F4F5]'
                    }`}
                    strokeWidth={1.75}
                    aria-hidden="true"
                  />
                  <span className="truncate">{item.label}</span>
                </span>

                {item.id === 'overview' && activeAlertsCount > 0 && (
                  <span className="tabular-nums ml-2 rounded-md border border-[#E56B6F]/30 bg-[#E56B6F]/14 px-1.5 py-0.5 text-[11px] font-medium text-[#F08A8D]">
                    {activeAlertsCount}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Consolidated Hybrid Engine Status */}
        <div className="border-t border-[#343D43]/60 p-3">
          <div className="rounded-[12px] bg-[#1C2226] p-3.5">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-[#F2F4F5]">Motor Híbrido</span>
              <span
                className={`text-[11px] font-medium ${
                  health?.models_loaded ? 'text-[#36C995]' : 'text-[#8E99A2]'
                }`}
              >
                {health?.models_loaded ? 'Activo' : 'Sin datos'}
              </span>
            </div>

            {health ? (
              <div className="mt-2.5 grid grid-cols-3 gap-2 border-t border-[#343D43]/55 pt-2.5 text-xs">
                <div>
                  <div className="text-[11px] text-[#A1ABB3]">w_mlp</div>
                  <div className="tabular-nums mt-0.5 font-semibold text-[#79ABFF]">
                    {health.hybrid_weights.w_mlp.toFixed(2)}
                  </div>
                </div>
                <div>
                  <div className="text-[11px] text-[#A1ABB3]">w_ae</div>
                  <div className="tabular-nums mt-0.5 font-semibold text-[#79ABFF]">
                    {health.hybrid_weights.w_ae.toFixed(2)}
                  </div>
                </div>
                <div>
                  <div className="text-[11px] text-[#A1ABB3]">Umbral</div>
                  <div className="tabular-nums mt-0.5 font-semibold text-[#F2A544]">
                    {health.hybrid_weights.threshold.toFixed(2)}
                  </div>
                </div>
              </div>
            ) : (
              <p className="mt-2 text-[11px] leading-relaxed text-[#8E99A2]">
                Esperando respuesta de API en puerto 8000.
              </p>
            )}
          </div>
        </div>
      </aside>
    </>
  );
}
