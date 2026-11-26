import { useCallback, useEffect, useState } from 'react';
import { FlowDetailDrawer } from './components/soc/FlowDetailDrawer';
import { Header } from './components/soc/Header';
import { Sidebar } from './components/soc/Sidebar';
import { FileInspectorPage } from './pages/FileInspectorPage';
import { ModelAnalyticsPage } from './pages/ModelAnalyticsPage';
import { OverviewPage } from './pages/OverviewPage';
import { ThreatLabPage } from './pages/ThreatLabPage';
import {
  fetchCaptureInterfaces,
  fetchCaptureStatus,
  fetchDashboardSummary,
  fetchFlows,
  fetchHealth,
  startLiveCapture,
  stopLiveCapture,
  useAlertWebSocket,
} from './services/api';
import type {
  AnalyzedFlow,
  CaptureInterfacesResponse,
  CaptureStatus,
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
  const [captureStatus, setCaptureStatus] = useState<CaptureStatus | null>(null);
  const [captureInterfaces, setCaptureInterfaces] =
    useState<CaptureInterfacesResponse | null>(null);
  const [captureBusy, setCaptureBusy] = useState<boolean>(false);
  const [captureError, setCaptureError] = useState<string | null>(null);

  const [selectedFlow, setSelectedFlow] = useState<AnalyzedFlow | null>(null);
  const [liveAnnouncement, setLiveAnnouncement] = useState<string>('');
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
      const [healthRes, summaryRes, flowsRes, capIfacesRes, capStatusRes] =
        await Promise.all([
          fetchHealth(),
          fetchDashboardSummary(),
          fetchFlows(100, 'ALL'),
          fetchCaptureInterfaces(),
          fetchCaptureStatus(),
        ]);

      setHealth(healthRes);
      setSummary(summaryRes);
      setFlows(flowsRes.flows);
      setCaptureInterfaces(capIfacesRes);
      setCaptureStatus(capStatusRes);
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

    if (incoming.risk_level === 'ALTO') {
      setLiveAnnouncement(
        `Alerta crítica detectada: ${incoming.predicted_threat} desde ${incoming.src_ip} hacia ${incoming.dst_ip}.`,
      );
    }

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

  useEffect(() => {
    if (!captureStatus?.running) return;
    const timer = window.setInterval(() => {
      void fetchCaptureStatus()
        .then((res) => setCaptureStatus(res))
        .catch(() => {});
    }, 3000);
    return () => window.clearInterval(timer);
  }, [captureStatus?.running]);

  const handleStartCapture = async (
    iface: string,
    bpf: string,
    windowSeconds: number,
  ) => {
    setCaptureBusy(true);
    setCaptureError(null);
    try {
      const statusRes = await startLiveCapture({
        interface: iface,
        bpf_filter: bpf,
        window_seconds: windowSeconds,
      });
      setCaptureStatus(statusRes);
    } catch (err) {
      setCaptureError(
        err instanceof Error
          ? err.message
          : 'No se pudo iniciar la captura pasiva en vivo.',
      );
    } finally {
      setCaptureBusy(false);
    }
  };

  const handleStopCapture = async () => {
    setCaptureBusy(true);
    setCaptureError(null);
    try {
      const statusRes = await stopLiveCapture();
      setCaptureStatus(statusRes);
      syncSummaryFromServer();
    } catch (err) {
      setCaptureError(
        err instanceof Error
          ? err.message
          : 'No se pudo detener la captura en vivo.',
      );
    } finally {
      setCaptureBusy(false);
    }
  };

  const headerMeta = VIEW_HEADERS[activeView];
  const threshold = health?.hybrid_weights.threshold ?? 0.5;

  return (
    <div className="min-h-screen bg-[#101416] text-[#F2F4F5]">
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {liveAnnouncement}
      </div>

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

      <div className="flex min-h-screen flex-col lg:pl-[248px]">
        <Header
          title={headerMeta.title}
          subtitle={headerMeta.subtitle}
          isRefreshing={isRefreshing}
          onRefresh={handleGlobalRefresh}
          onOpenMobileSidebar={() => setMobileSidebarOpen(true)}
        />

        <main className="flex-1 p-4 sm:p-6">
          {activeView === 'overview' && (
            <OverviewPage
              summary={summary}
              flows={flows}
              loading={loading}
              error={apiError}
              threshold={threshold}
              captureStatus={captureStatus}
              captureInterfaces={captureInterfaces}
              captureBusy={captureBusy}
              captureError={captureError}
              selectedFlowId={selectedFlow?.flow_id ?? null}
              onStartCapture={(iface, bpf, win) =>
                void handleStartCapture(iface, bpf, win)
              }
              onStopCapture={() => void handleStopCapture()}
              onSelectFlow={setSelectedFlow}
            />
          )}

          {activeView === 'threat-lab' && (
            <ThreatLabPage
              liveFeed={labFeed}
              selectedFlowId={selectedFlow?.flow_id ?? null}
              onSelectFlow={setSelectedFlow}
              onSimulationComplete={syncSummaryFromServer}
            />
          )}

          {activeView === 'model-analytics' && (
            <ModelAnalyticsPage refreshTrigger={refreshTick} />
          )}

          {activeView === 'file-inspector' && (
            <FileInspectorPage
              selectedFlowId={selectedFlow?.flow_id ?? null}
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
