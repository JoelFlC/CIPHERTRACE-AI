import { useCallback, useEffect, useState } from 'react';
import { Lock, Menu, RefreshCw } from 'lucide-react';
import { FlowDetailDrawer } from './components/FlowDetailDrawer';
import { Sidebar } from './components/Sidebar';
import { FileInspectorPage } from './pages/FileInspectorPage';
import { ModelAnalyticsPage } from './pages/ModelAnalyticsPage';
import { OverviewPage } from './pages/OverviewPage';
import { ThreatLabPage } from './pages/ThreatLabPage';
import {
  fetchDashboardSummary,
  fetchFlows,
  fetchHealth,
  useAlertWebSocket,
} from './services/api';
import type {
  AnalyzedFlow,
  DashboardSummary,
  HealthResponse,
  LiveFeedItem,
  NavView,
  WsFlowEvaluatedEvent,
} from './types/ciphertrace';

const VIEW_HEADERS: Record<NavView, { title: string; subtitle: string }> = {
  overview: {
    title: 'Live SOC Overview',
    subtitle: 'Monitorización en tiempo real de tráfico cifrado y anomalías',
  },
  'threat-lab': {
    title: 'Laboratorio AiTM & Inyección',
    subtitle: 'Simulación controlada de amenazas y proxy inverso local',
  },
  'model-analytics': {
    title: 'Motor IA & Algoritmo Genético',
    subtitle: 'Convergencia evolutiva, atributos seleccionados y métricas k=5',
  },
  'file-inspector': {
    title: 'Inspector Pasivo PCAP / CSV',
    subtitle: 'Análisis forense de capturas sin descifrado de payload',
  },
};

export function App() {
  const [activeView, setActiveView] = useState<NavView>('overview');
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [flows, setFlows] = useState<AnalyzedFlow[]>([]);
  const [labFeed, setLabFeed] = useState<LiveFeedItem[]>([]);
  const [health, setHealth] = useState<HealthResponse | null>(null);

  const [selectedFlow, setSelectedFlow] = useState<AnalyzedFlow | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [refreshTick, setRefreshTick] = useState<number>(0);

  const loadDashboardData = useCallback(async (isManualRefresh = false) => {
    if (isManualRefresh) {
      setIsRefreshing(true);
    } else {
      setLoading(true);
    }

    try {
      const [healthRes, summaryRes, flowsRes] = await Promise.all([
        fetchHealth(),
        fetchDashboardSummary(),
        fetchFlows(100, 'ALL'),
      ]);

      setHealth(healthRes);
      setSummary(summaryRes);
      setFlows(flowsRes.flows);
      setLabFeed((prev) => {
        if (prev.length > 0) return prev;
        return flowsRes.flows.slice(0, 30).map((flow) => ({
          flow,
          source: flow.source,
        }));
      });
      setApiError(null);
    } catch (err) {
      setApiError(
        err instanceof Error
          ? err.message
          : 'No se pudo conectar con http://localhost:8000',
      );
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void loadDashboardData(false);
  }, [loadDashboardData]);

  const handleFlowEvaluated = useCallback((event: WsFlowEvaluatedEvent) => {
    const incoming = event.flow;

    setFlows((prev) => {
      const deduped = prev.filter((item) => item.id !== incoming.id);
      return [incoming, ...deduped].slice(0, 200);
    });

    setLabFeed((prev) => {
      const deduped = prev.filter((item) => item.flow.id !== incoming.id);
      return [
        {
          flow: incoming,
          source: event.source || incoming.source,
          capturedDemoToken: event.captured_demo_token,
        },
        ...deduped,
      ].slice(0, 60);
    });

    // Update KPI summary optimistically, then resync exact aggregates
    setSummary((prev) => {
      if (!prev) return prev;
      const isAlert =
        incoming.risk_level === 'ALTO' || incoming.risk_level === 'MEDIO';
      const nextTotal = prev.total_flows + 1;
      const nextActiveAlerts = prev.active_alerts + (isAlert ? 1 : 0);
      const nextAvgLatency =
        (prev.avg_inference_latency_ms * prev.total_flows +
          incoming.inference_latency_ms) /
        nextTotal;

      return {
        ...prev,
        total_flows: nextTotal,
        active_alerts: nextActiveAlerts,
        critical_alerts:
          prev.critical_alerts + (incoming.risk_level === 'ALTO' ? 1 : 0),
        medium_alerts:
          prev.medium_alerts + (incoming.risk_level === 'MEDIO' ? 1 : 0),
        avg_inference_latency_ms: Number(nextAvgLatency.toFixed(4)),
        anomaly_rate_pct: Number(
          ((nextActiveAlerts / nextTotal) * 100).toFixed(2),
        ),
        threat_distribution: {
          ...prev.threat_distribution,
          [incoming.predicted_threat]:
            (prev.threat_distribution[incoming.predicted_threat] ?? 0) + 1,
        },
        risk_distribution: {
          ...prev.risk_distribution,
          [incoming.risk_level]:
            (prev.risk_distribution[incoming.risk_level] ?? 0) + 1,
        },
      };
    });
  }, []);

  const { status: wsStatus, reconnect: reconnectWs } = useAlertWebSocket({
    onFlowEvaluated: handleFlowEvaluated,
  });

  const handleGlobalRefresh = () => {
    setRefreshTick((prev) => prev + 1);
    void loadDashboardData(true);
  };

  const syncSummaryFromServer = useCallback(() => {
    void fetchDashboardSummary()
      .then((res) => setSummary(res))
      .catch(() => {
        // Keep current summary if transient error occurs
      });
  }, []);

  const headerMeta = VIEW_HEADERS[activeView];
  const threshold = health?.hybrid_weights.threshold ?? 0.5;

  return (
    <div className="min-h-screen bg-[#0B0F19] text-gray-100">
      <Sidebar
        activeView={activeView}
        onSelectView={setActiveView}
        wsStatus={wsStatus}
        onReconnectWs={reconnectWs}
        activeAlertsCount={summary?.active_alerts ?? 0}
        health={health}
        mobileOpen={mobileSidebarOpen}
        onCloseMobile={() => setMobileSidebarOpen(false)}
      />

      <div className="flex min-h-screen flex-col lg:pl-60">
        {/* Compact Top Header */}
        <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-3 border-b border-[#1F2937] bg-[#0B0F19]/95 px-4 backdrop-blur-sm sm:px-6">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileSidebarOpen(true)}
              className="rounded-md border border-[#1F2937] bg-[#111827] p-1.5 text-gray-300 hover:text-white lg:hidden"
              aria-label="Abrir menú de navegación"
            >
              <Menu className="h-4 w-4" />
            </button>

            <div className="min-w-0">
              <h1 className="truncate text-sm font-semibold text-gray-100 sm:text-base">
                {headerMeta.title}
              </h1>
              <p className="hidden truncate text-[11px] text-gray-400 sm:block">
                {headerMeta.subtitle}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <span className="hidden items-center gap-1.5 rounded-md border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-1 text-xs font-medium text-cyan-300 md:inline-flex">
              <Lock className="h-3.5 w-3.5" />
              Análisis Pasivo (Sin Descifrado)
            </span>

            <button
              type="button"
              onClick={handleGlobalRefresh}
              disabled={isRefreshing}
              className="inline-flex items-center gap-1.5 rounded-md border border-[#1F2937] bg-[#111827] px-3 py-1.5 text-xs font-medium text-gray-200 transition-colors hover:border-gray-600 hover:bg-[#1F2937] disabled:opacity-60"
              title="Actualizar telemetría"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 text-[#06B6D4] ${
                  isRefreshing ? 'animate-spin' : ''
                }`}
              />
              <span className="hidden sm:inline">Actualizar</span>
            </button>
          </div>
        </header>

        {/* Active View Content */}
        <main className="flex-1 p-4 sm:p-6">
          {activeView === 'overview' && (
            <OverviewPage
              summary={summary}
              flows={flows}
              loading={loading}
              error={apiError}
              threshold={threshold}
              onSelectFlow={setSelectedFlow}
            />
          )}

          {activeView === 'threat-lab' && (
            <ThreatLabPage
              liveFeed={labFeed}
              onSelectFlow={setSelectedFlow}
              onSimulationComplete={syncSummaryFromServer}
            />
          )}

          {activeView === 'model-analytics' && (
            <ModelAnalyticsPage refreshTrigger={refreshTick} />
          )}

          {activeView === 'file-inspector' && (
            <FileInspectorPage
              onSelectFlow={setSelectedFlow}
              onAnalysisComplete={syncSummaryFromServer}
            />
          )}
        </main>
      </div>

      <FlowDetailDrawer
        flow={selectedFlow}
        threshold={threshold}
        onClose={() => setSelectedFlow(null)}
      />
    </div>
  );
}

export default App;
