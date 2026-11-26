import { useEffect, useState } from 'react';
import { Play, Radio, Square } from 'lucide-react';
import type {
  CaptureInterfacesResponse,
  CaptureStatus,
} from '../../types/ciphertrace';
import { AlertBanner } from '../ui/AlertBanner';
import { BentoCard } from '../ui/BentoCard';
import { Button } from '../ui/Button';

interface SensorControlBarProps {
  captureStatus: CaptureStatus | null;
  captureInterfaces: CaptureInterfacesResponse | null;
  captureBusy: boolean;
  captureError: string | null;
  onStartCapture: (iface: string, bpf: string, windowSeconds: number) => void;
  onStopCapture: () => void;
}

/**
 * Direct-access Hybrid Passive Capture bar keeping Start/Stop and BPF controls visible in 1 click.
 */
export function SensorControlBar({
  captureStatus,
  captureInterfaces,
  captureBusy,
  captureError,
  onStartCapture,
  onStopCapture,
}: SensorControlBarProps) {
  const [selectedIface, setSelectedIface] = useState<string>('any');
  const [bpfFilter, setBpfFilter] = useState<string>(
    'tcp port 443 or tcp port 8443 or udp port 53 or tcp port 8000',
  );
  const [windowSeconds, setWindowSeconds] = useState<number>(4);

  useEffect(() => {
    if (captureInterfaces?.default_bpf_filter) {
      setBpfFilter((prev) => prev || captureInterfaces.default_bpf_filter);
    }
    if (
      captureInterfaces?.interfaces?.length &&
      !captureInterfaces.interfaces.includes(selectedIface)
    ) {
      setSelectedIface(captureInterfaces.interfaces[0]);
    }
  }, [captureInterfaces, selectedIface]);

  const isRunning = Boolean(captureStatus?.running);
  const disabledInputs = isRunning || captureBusy;
  const noPrivilegeWarning = captureInterfaces?.can_capture === false;

  return (
    <BentoCard
      title={
        <span className="flex items-center gap-2">
          <Radio
            className={`h-4 w-4 ${
              isRunning ? 'text-[#36C995]' : 'text-[#5795F2]'
            }`}
            strokeWidth={1.75}
            aria-hidden="true"
          />
          <span>Sensor Híbrido (Captura Pasiva En Vivo / Offline)</span>
          <span
            className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium ${
              isRunning
                ? 'border-[#36C995]/30 bg-[#36C995]/14 text-[#36C995]'
                : 'border-[#343D43] bg-[#272F35] text-[#A1ABB3]'
            }`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                isRunning ? 'bg-[#36C995]' : 'bg-[#8E99A2]'
              }`}
              aria-hidden="true"
            />
            {isRunning ? 'En vivo activo' : 'En espera / Offline'}
          </span>
        </span>
      }
      subtitle="Sniffer pasivo por ventanas sin descifrar carga útil, complementario al Inspector PCAP/CSV"
      action={
        captureStatus && (
          <div className="tabular-nums flex flex-wrap items-center gap-4 text-xs text-[#A1ABB3]">
            <span>
              Paquetes:{' '}
              <strong className="font-semibold text-[#F2F4F5]">
                {captureStatus.packets_captured.toLocaleString('es-ES')}
              </strong>
            </span>
            <span>
              Flujos:{' '}
              <strong className="font-semibold text-[#79ABFF]">
                {captureStatus.flows_evaluated.toLocaleString('es-ES')}
              </strong>
            </span>
            <span>
              Alertas:{' '}
              <strong className="font-semibold text-[#F08A8D]">
                {captureStatus.alerts_triggered.toLocaleString('es-ES')}
              </strong>
            </span>
          </div>
        )
      }
      headerDivider
    >
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
        <div className="lg:col-span-3">
          <label
            htmlFor="capture-iface"
            className="mb-1.5 block text-xs font-medium text-[#A1ABB3]"
          >
            Interfaz de red
          </label>
          <select
            id="capture-iface"
            disabled={disabledInputs}
            value={selectedIface}
            onChange={(e) => setSelectedIface(e.target.value)}
            className="tech-mono h-9 w-full rounded-[10px] border border-[#343D43] bg-[#272F35] px-3 text-xs text-[#F2F4F5] focus-visible:border-[#5795F2] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#5795F2]/50 disabled:cursor-not-allowed disabled:opacity-55"
          >
            {(captureInterfaces?.interfaces ?? ['any', 'lo']).map((iface) => (
              <option key={iface} value={iface}>
                {iface}
              </option>
            ))}
          </select>
        </div>

        <div className="lg:col-span-5">
          <label
            htmlFor="capture-bpf"
            className="mb-1.5 block text-xs font-medium text-[#A1ABB3]"
          >
            Filtro BPF (solo puertos TLS/DNS/Lab)
          </label>
          <input
            id="capture-bpf"
            type="text"
            disabled={disabledInputs}
            value={bpfFilter}
            onChange={(e) => setBpfFilter(e.target.value)}
            className="tech-mono h-9 w-full rounded-[10px] border border-[#343D43] bg-[#272F35] px-3 text-xs text-[#F2F4F5] focus-visible:border-[#5795F2] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#5795F2]/50 disabled:cursor-not-allowed disabled:opacity-55"
          />
        </div>

        <div className="lg:col-span-2">
          <label
            htmlFor="capture-window"
            className="mb-1.5 block text-xs font-medium text-[#A1ABB3]"
          >
            Ventana (s)
          </label>
          <select
            id="capture-window"
            disabled={disabledInputs}
            value={windowSeconds}
            onChange={(e) => setWindowSeconds(Number(e.target.value))}
            className="tabular-nums h-9 w-full rounded-[10px] border border-[#343D43] bg-[#272F35] px-3 text-xs text-[#F2F4F5] focus-visible:border-[#5795F2] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#5795F2]/50 disabled:cursor-not-allowed disabled:opacity-55"
          >
            <option value={3}>3 s</option>
            <option value={4}>4 s</option>
            <option value={5}>5 s</option>
            <option value={10}>10 s</option>
          </select>
        </div>

        <div className="flex items-end lg:col-span-2">
          {isRunning ? (
            <Button
              variant="danger-subtle"
              loading={captureBusy}
              onClick={onStopCapture}
              icon={<Square className="h-3.5 w-3.5" strokeWidth={1.75} />}
              className="w-full"
            >
              Detener En Vivo
            </Button>
          ) : (
            <Button
              variant="primary"
              loading={captureBusy}
              disabled={noPrivilegeWarning}
              onClick={() =>
                onStartCapture(selectedIface, bpfFilter, windowSeconds)
              }
              icon={<Play className="h-3.5 w-3.5" strokeWidth={1.75} />}
              className="w-full"
            >
              Iniciar En Vivo
            </Button>
          )}
        </div>
      </div>

      {(captureError || captureStatus?.last_error || noPrivilegeWarning) && (
        <AlertBanner variant="warning" className="mt-3">
          {captureError ??
            captureStatus?.last_error ??
            'Captura en vivo deshabilitada en este proceso (requiere CAP_NET_RAW / Docker Compose). El modo offline PCAP/CSV y el laboratorio AiTM siguen operativos.'}
        </AlertBanner>
      )}
    </BentoCard>
  );
}
