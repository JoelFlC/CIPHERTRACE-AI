import { useCallback, useEffect, useRef, useState } from 'react';
import type {
  CaptureInterfacesResponse,
  CaptureStartRequest,
  CaptureStatus,
  DashboardSummary,
  FileAnalysisResponse,
  FlowsResponse,
  HealthResponse,
  MLMetricsResponse,
  SimulateRequest,
  SimulateResponse,
  WsAlertMessage,
  WsConnectionStatus,
  WsFlowEvaluatedEvent,
} from '../types/ciphertrace';

const rawApiOrigin =
  import.meta.env.VITE_API_URL ??
  import.meta.env.VITE_API_ORIGIN ??
  'http://localhost:8000';

export const BACKEND_ORIGIN = rawApiOrigin.replace(/\/+$/, '');
export const API_BASE_URL = `${BACKEND_ORIGIN}/api`;
export const WS_ALERTS_URL =
  import.meta.env.VITE_WS_URL ??
  `${BACKEND_ORIGIN.replace(/^http/i, 'ws')}/ws/alerts`;

interface FastApiErrorBody {
  detail?: string;
}

async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, init);

  if (!response.ok) {
    let errorMessage = `Error HTTP ${response.status}`;
    try {
      const body = (await response.json()) as FastApiErrorBody;
      if (body?.detail) {
        errorMessage = body.detail;
      }
    } catch {
      // Fallback to HTTP status text when error body is not JSON
      if (response.statusText) {
        errorMessage = `${response.status} ${response.statusText}`;
      }
    }
    throw new Error(errorMessage);
  }

  return (await response.json()) as T;
}

export function fetchHealth(): Promise<HealthResponse> {
  return apiRequest<HealthResponse>('/health');
}

export function fetchDashboardSummary(): Promise<DashboardSummary> {
  return apiRequest<DashboardSummary>('/dashboard/summary');
}

export function fetchFlows(
  limit = 50,
  riskLevel: 'ALL' | 'ALTO' | 'MEDIO' | 'BAJO' = 'ALL',
): Promise<FlowsResponse> {
  const params = new URLSearchParams({
    limit: String(limit),
    risk_level: riskLevel,
  });
  return apiRequest<FlowsResponse>(`/flows?${params.toString()}`);
}

export function fetchMLMetrics(): Promise<MLMetricsResponse> {
  return apiRequest<MLMetricsResponse>('/ml/metrics');
}

export function simulateThreat(
  payload: SimulateRequest,
): Promise<SimulateResponse> {
  return apiRequest<SimulateResponse>('/lab/simulate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export function analyzeFile(file: File): Promise<FileAnalysisResponse> {
  const formData = new FormData();
  formData.append('file', file);
  return apiRequest<FileAnalysisResponse>('/analyze/file', {
    method: 'POST',
    body: formData,
  });
}

export function fetchCaptureInterfaces(): Promise<CaptureInterfacesResponse> {
  return apiRequest<CaptureInterfacesResponse>('/capture/interfaces');
}

export function fetchCaptureStatus(): Promise<CaptureStatus> {
  return apiRequest<CaptureStatus>('/capture/status');
}

export function startLiveCapture(
  payload: CaptureStartRequest,
): Promise<CaptureStatus> {
  return apiRequest<CaptureStatus>('/capture/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export function stopLiveCapture(): Promise<CaptureStatus> {
  return apiRequest<CaptureStatus>('/capture/stop', {
    method: 'POST',
  });
}

interface UseAlertWebSocketOptions {
  onFlowEvaluated?: (event: WsFlowEvaluatedEvent) => void;
  enabled?: boolean;
}

export function useAlertWebSocket({
  onFlowEvaluated,
  enabled = true,
}: UseAlertWebSocketOptions) {
  const [status, setStatus] = useState<WsConnectionStatus>('connecting');
  const [lastMessageAt, setLastMessageAt] = useState<string | null>(null);
  const [connectAttempt, setConnectAttempt] = useState(0);

  const callbackRef = useRef(onFlowEvaluated);
  callbackRef.current = onFlowEvaluated;

  const reconnect = useCallback(() => {
    setConnectAttempt((prev) => prev + 1);
  }, []);

  useEffect(() => {
    if (!enabled) {
      setStatus('disconnected');
      return;
    }

    let isActive = true;
    let socket: WebSocket | null = null;
    let retryTimer: number | null = null;
    let retryDelayMs = 1500;

    const connect = () => {
      if (!isActive) return;
      setStatus('connecting');

      try {
        socket = new WebSocket(WS_ALERTS_URL);
      } catch {
        setStatus('disconnected');
        if (isActive) {
          retryTimer = window.setTimeout(connect, retryDelayMs);
          retryDelayMs = Math.min(retryDelayMs * 1.5, 5000);
        }
        return;
      }

      socket.onopen = () => {
        if (!isActive) {
          socket?.close();
          return;
        }
        retryDelayMs = 1500;
        setStatus('connected');
      };

      socket.onmessage = (event: MessageEvent<string>) => {
        if (!isActive) return;
        try {
          const parsed = JSON.parse(event.data) as WsAlertMessage;
          setLastMessageAt(new Date().toISOString());
          if (parsed.event === 'flow_evaluated') {
            callbackRef.current?.(parsed);
          }
        } catch {
          // Ignore malformed payloads
        }
      };

      socket.onerror = () => {
        if (!isActive) return;
        setStatus('disconnected');
      };

      socket.onclose = () => {
        if (!isActive) return;
        setStatus('disconnected');
        retryTimer = window.setTimeout(connect, retryDelayMs);
        retryDelayMs = Math.min(retryDelayMs * 1.5, 5000);
      };
    };

    connect();

    return () => {
      isActive = false;
      if (retryTimer !== null) {
        window.clearTimeout(retryTimer);
      }
      if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
        socket.close();
      }
    };
  }, [enabled, connectAttempt]);

  return {
    status,
    lastMessageAt,
    reconnect,
  };
}
