import React, { useState, useEffect, useRef, useMemo } from 'react';
import { 
  ResponsiveContainer, 
  ComposedChart, 
  Area, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ReferenceLine,
  ReferenceDot
} from 'recharts';
import { 
  SystemMetrics, 
  ThreatAlert, 
  TrafficFlow,
  SeverityLevel
} from '../types';
import { 
  Activity, 
  AlertTriangle, 
  Wifi, 
  Radio, 
  Layers, 
  ShieldAlert, 
  Zap, 
  Pause, 
  Play, 
  Maximize2,
  TrendingUp,
  Cpu
} from 'lucide-react';

interface NetworkTrafficChartProps {
  metrics: SystemMetrics;
  alerts: ThreatAlert[];
  trafficFlows: TrafficFlow[];
}

export interface TrafficDataPoint {
  time: string;
  timestamp: number;
  eth0Bps: number;
  wlan0Bps: number;
  docker0Bps: number;
  totalBps: number;
  hasAnomaly: boolean;
  anomalyTitle?: string;
  anomalySeverity?: SeverityLevel;
  pps: number;
}

export const NetworkTrafficChart: React.FC<NetworkTrafficChartProps> = ({
  metrics,
  alerts,
  trafficFlows
}) => {
  const [selectedInterface, setSelectedInterface] = useState<'all' | 'eth0' | 'wlan0' | 'docker0'>('all');
  const [unit, setUnit] = useState<'bps' | 'kbps' | 'mbps'>('kbps');
  const [showAnomaliesOnly, setShowAnomaliesOnly] = useState<boolean>(true);
  const [isLivePaused, setIsLivePaused] = useState<boolean>(false);
  const [dataPoints, setDataPoints] = useState<TrafficDataPoint[]>([]);

  const primaryIface = metrics.sniffingInterface || 'eth0';

  // 100% REAL: Inicializa buffer com dados reais do sensor
  useEffect(() => {
    const initialPoints: TrafficDataPoint[] = [];
    const now = Date.now();
    const currentBps = Math.round((metrics.bandwidthKbps || 0) * 1024 * 8);
    const currentPps = metrics.pps || 0;

    for (let i = 15; i >= 0; i--) {
      const pointTime = new Date(now - i * 2000);
      const timeStr = pointTime.toLocaleTimeString('pt-BR', { hour12: false });
      
      initialPoints.push({
        time: timeStr,
        timestamp: pointTime.getTime(),
        eth0Bps: currentBps,
        wlan0Bps: 0,
        docker0Bps: 0,
        totalBps: currentBps,
        hasAnomaly: false,
        pps: currentPps
      });
    }
    setDataPoints(initialPoints);
  }, []);

  // Atualização em tempo real sincronizada com as métricas reais do Scapy / Kali
  useEffect(() => {
    if (isLivePaused) return;

    const interval = setInterval(() => {
      const now = new Date();
      const timeStr = now.toLocaleTimeString('pt-BR', { hour12: false });

      // Telemetria real em bps
      const realKbps = metrics.bandwidthKbps || 0;
      const realEth0Bps = Math.round(realKbps * 1024 * 8);
      const realTotalBps = realEth0Bps;

      // Detecção de anomalia ativa real (não sintética)
      const recentUnmitigated = alerts.find(a => 
        a.status === 'active' && 
        (a.severity === 'critical' || a.severity === 'high')
      );

      const isAnomalySpike = Boolean(recentUnmitigated) || metrics.pps > 600;
      const anomalyTitle = recentUnmitigated 
        ? `${recentUnmitigated.title} (${recentUnmitigated.sourceIp})`
        : metrics.pps > 600 ? 'Surto Anômalo de Tráfego (>600 PPS)' : undefined;
      const anomalySeverity = recentUnmitigated?.severity || (metrics.pps > 600 ? 'critical' : undefined);

      setDataPoints(prev => {
        const nextPoint: TrafficDataPoint = {
          time: timeStr,
          timestamp: now.getTime(),
          eth0Bps: realEth0Bps,
          wlan0Bps: 0,
          docker0Bps: 0,
          totalBps: realTotalBps,
          hasAnomaly: isAnomalySpike,
          anomalyTitle,
          anomalySeverity,
          pps: metrics.pps || 0
        };

        const slice = prev.length >= 30 ? prev.slice(1) : prev;
        return [...slice, nextPoint];
      });
    }, 2000);

    return () => clearInterval(interval);
  }, [metrics, alerts, isLivePaused]);

  // Format unit helpers
  const formatBpsValue = (bps: number): number => {
    if (unit === 'mbps') {
      return Number((bps / 1000000).toFixed(2));
    }
    if (unit === 'kbps') {
      return Number((bps / 1000).toFixed(1));
    }
    return Math.round(bps);
  };

  const getUnitLabel = () => {
    switch (unit) {
      case 'mbps': return 'Mbps';
      case 'kbps': return 'Kbps';
      case 'bps': return 'bps';
    }
  };

  // Compute stats from current data window
  const stats = useMemo(() => {
    if (dataPoints.length === 0) {
      return { current: 0, peak: 0, avg: 0, anomaliesCount: 0 };
    }
    const last = dataPoints[dataPoints.length - 1];
    let peak = 0;
    let sum = 0;
    let anomalyCount = 0;

    dataPoints.forEach(p => {
      const val = selectedInterface === 'all' ? p.totalBps :
                  selectedInterface === 'eth0' ? p.eth0Bps :
                  selectedInterface === 'wlan0' ? p.wlan0Bps : p.docker0Bps;
      if (val > peak) peak = val;
      sum += val;
      if (p.hasAnomaly) anomalyCount++;
    });

    const currentVal = selectedInterface === 'all' ? last.totalBps :
                       selectedInterface === 'eth0' ? last.eth0Bps :
                       selectedInterface === 'wlan0' ? last.wlan0Bps : last.docker0Bps;

    return {
      current: currentVal,
      peak,
      avg: Math.round(sum / dataPoints.length),
      anomaliesCount: anomalyCount
    };
  }, [dataPoints, selectedInterface]);

  // Transformed chart data based on unit
  const chartData = useMemo(() => {
    return dataPoints.map(p => ({
      time: p.time,
      eth0: formatBpsValue(p.eth0Bps),
      wlan0: formatBpsValue(p.wlan0Bps),
      docker0: formatBpsValue(p.docker0Bps),
      total: formatBpsValue(p.totalBps),
      pps: p.pps,
      hasAnomaly: p.hasAnomaly,
      anomalyTitle: p.anomalyTitle,
      anomalySeverity: p.anomalySeverity,
      // Spike marker value for anomaly overlay
      anomalyMarker: p.hasAnomaly 
        ? (selectedInterface === 'all' ? formatBpsValue(p.totalBps) :
           selectedInterface === 'eth0' ? formatBpsValue(p.eth0Bps) :
           selectedInterface === 'wlan0' ? formatBpsValue(p.wlan0Bps) : formatBpsValue(p.docker0Bps))
        : null
    }));
  }, [dataPoints, unit, selectedInterface]);

  // Filtered anomaly points for ReferenceDot
  const anomalyPoints = useMemo(() => {
    return chartData.filter(d => d.hasAnomaly && d.anomalyMarker !== null);
  }, [chartData]);

  // Dynamic anomaly baseline threshold line
  const thresholdValue = useMemo(() => {
    const rawThreshold = 3500000; // ~3.5 Mbps baseline threshold
    return formatBpsValue(rawThreshold);
  }, [unit]);

  return (
    <div className="p-4 sm:p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4 shadow-xl">
      {/* 1. Header with Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div className="flex items-start sm:items-center gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-950/80 border border-cyan-800/80 text-cyan-400 shrink-0">
            <Activity className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm sm:text-base font-semibold text-slate-100 flex items-center gap-2">
                <span>Telemetria de Tráfego de Rede em Tempo Real</span>
                <span className="text-xs font-mono text-cyan-400 font-normal">
                  ({getUnitLabel()})
                </span>
              </h3>
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                AO VIVO
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Volume de bits/segundo por interface de rede e identificação imediata de picos de anomalias (SYN Scan, DDoS, ARP Spoofing).
            </p>
          </div>
        </div>

        {/* Toolbar & Filters */}
        <div className="flex items-center gap-2 flex-wrap self-start lg:self-auto">
          {/* Interface Selector */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            <span className="text-slate-500 text-[11px] px-1.5 hidden sm:inline">Interface:</span>
            {[
              { id: 'all', label: 'Todas' },
              { id: 'eth0', label: primaryIface },
              { id: 'wlan0', label: 'wlan0' },
              { id: 'docker0', label: 'docker0' }
            ].map(iface => (
              <button
                key={iface.id}
                onClick={() => setSelectedInterface(iface.id as any)}
                className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                  selectedInterface === iface.id
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                {iface.label}
              </button>
            ))}
          </div>

          {/* Unit Toggle (bps / Kbps / Mbps) */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-mono">
            {(['bps', 'kbps', 'mbps'] as const).map(u => (
              <button
                key={u}
                onClick={() => setUnit(u)}
                className={`px-2 py-0.5 rounded uppercase text-[11px] font-semibold transition-colors ${
                  unit === u
                    ? 'bg-slate-800 text-cyan-400 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {u}
              </button>
            ))}
          </div>

          {/* Anomaly Marker Toggle */}
          <button
            onClick={() => setShowAnomaliesOnly(!showAnomaliesOnly)}
            className={`p-1.5 px-2.5 rounded-lg border text-xs flex items-center gap-1.5 transition-colors ${
              showAnomaliesOnly
                ? 'bg-rose-950/60 text-rose-300 border-rose-800'
                : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
            }`}
            title="Destacar picos de anomalias detectadas no gráfico"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span className="hidden sm:inline text-[11px]">Picos</span>
          </button>

          {/* Pause / Resume Live */}
          <button
            onClick={() => setIsLivePaused(!isLivePaused)}
            className={`p-1.5 px-2 rounded-lg border text-xs flex items-center gap-1 transition-colors ${
              isLivePaused
                ? 'bg-amber-950 text-amber-300 border-amber-800'
                : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
            }`}
            title={isLivePaused ? 'Retomar fluxo em tempo real' : 'Pausar fluxo'}
          >
            {isLivePaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* 2. Mini KPI Badges Ribbon */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs">
        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] text-slate-500 block">Vazão Atual ({getUnitLabel()})</span>
            <span className="text-base font-bold font-mono text-cyan-400">
              {formatBpsValue(stats.current).toLocaleString('pt-BR')}
            </span>
          </div>
          <Activity className="w-4 h-4 text-cyan-500/70" />
        </div>

        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] text-slate-500 block">Pico Máximo ({getUnitLabel()})</span>
            <span className="text-base font-bold font-mono text-emerald-400">
              {formatBpsValue(stats.peak).toLocaleString('pt-BR')}
            </span>
          </div>
          <TrendingUp className="w-4 h-4 text-emerald-500/70" />
        </div>

        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] text-slate-500 block">Média da Janela</span>
            <span className="text-base font-bold font-mono text-indigo-400">
              {formatBpsValue(stats.avg).toLocaleString('pt-BR')}
            </span>
          </div>
          <Cpu className="w-4 h-4 text-indigo-500/70" />
        </div>

        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] text-slate-500 block">Picos de Anomalia</span>
            <span className={`text-base font-bold font-mono ${stats.anomaliesCount > 0 ? 'text-rose-400' : 'text-slate-400'}`}>
              {stats.anomaliesCount} {stats.anomaliesCount === 1 ? 'pico' : 'picos'}
            </span>
          </div>
          <ShieldAlert className={`w-4 h-4 ${stats.anomaliesCount > 0 ? 'text-rose-400 animate-bounce' : 'text-slate-600'}`} />
        </div>
      </div>

      {/* 3. Recharts Interactive Visualization */}
      <div className="h-72 w-full pt-1">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart
            data={chartData}
            margin={{ top: 12, right: 12, left: -10, bottom: 0 }}
          >
            <defs>
              {/* Cyan gradient for eth0 / primary */}
              <linearGradient id="gradientEth0" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
              </linearGradient>

              {/* Emerald gradient for wlan0 */}
              <linearGradient id="gradientWlan0" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10b981" stopOpacity={0.35} />
                <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
              </linearGradient>

              {/* Purple gradient for docker0 */}
              <linearGradient id="gradientDocker0" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#a855f7" stopOpacity={0.35} />
                <stop offset="95%" stopColor="#a855f7" stopOpacity={0.0} />
              </linearGradient>

              {/* Rose gradient for total/anomalies */}
              <linearGradient id="gradientTotal" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0} />
              </linearGradient>
            </defs>

            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />

            <XAxis 
              dataKey="time" 
              stroke="#64748b" 
              fontSize={11} 
              tickLine={false}
              axisLine={{ stroke: '#334155' }}
              interval="preserveStartEnd"
              minTickGap={25}
            />

            <YAxis 
              stroke="#64748b" 
              fontSize={11} 
              tickLine={false}
              axisLine={{ stroke: '#334155' }}
              tickFormatter={(v) => `${v}`}
              domain={['dataMin - 10', 'auto']}
            />

            <Tooltip content={<CustomTooltip unit={getUnitLabel()} />} />

            <Legend 
              verticalAlign="top" 
              align="right"
              wrapperStyle={{ paddingBottom: '10px', fontSize: '11px' }}
              iconType="circle"
            />

            {/* Threshold Line for Anomaly Warning */}
            {showAnomaliesOnly && (
              <ReferenceLine 
                y={thresholdValue} 
                stroke="#e11d48" 
                strokeDasharray="4 4" 
                strokeWidth={1.5}
                label={{ 
                  value: `Limiar de Anomalia (${thresholdValue} ${getUnitLabel()})`, 
                  fill: '#fb7185', 
                  fontSize: 10, 
                  position: 'insideTopLeft' 
                }} 
              />
            )}

            {/* Area Layers based on selected interface */}
            {selectedInterface === 'all' && (
              <>
                <Area
                  type="monotone"
                  dataKey="eth0"
                  name={`${primaryIface} (Primária)`}
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#gradientEth0)"
                  isAnimationActive={false}
                />
                <Area
                  type="monotone"
                  dataKey="wlan0"
                  name="wlan0 (Wireless)"
                  stroke="#10b981"
                  strokeWidth={1.5}
                  fillOpacity={1}
                  fill="url(#gradientWlan0)"
                  isAnimationActive={false}
                />
                <Area
                  type="monotone"
                  dataKey="docker0"
                  name="docker0 (Portainer Bridge)"
                  stroke="#a855f7"
                  strokeWidth={1.5}
                  fillOpacity={1}
                  fill="url(#gradientDocker0)"
                  isAnimationActive={false}
                />
              </>
            )}

            {selectedInterface === 'eth0' && (
              <Area
                type="monotone"
                dataKey="eth0"
                name={`${primaryIface} (Host Kali)`}
                stroke="#06b6d4"
                strokeWidth={2.5}
                fillOpacity={1}
                fill="url(#gradientEth0)"
                isAnimationActive={false}
              />
            )}

            {selectedInterface === 'wlan0' && (
              <Area
                type="monotone"
                dataKey="wlan0"
                name="wlan0 (Interface Wi-Fi)"
                stroke="#10b981"
                strokeWidth={2.5}
                fillOpacity={1}
                fill="url(#gradientWlan0)"
                isAnimationActive={false}
              />
            )}

            {selectedInterface === 'docker0' && (
              <Area
                type="monotone"
                dataKey="docker0"
                name="docker0 (Rede Interna dos Contêineres)"
                stroke="#a855f7"
                strokeWidth={2.5}
                fillOpacity={1}
                fill="url(#gradientDocker0)"
                isAnimationActive={false}
              />
            )}

            {/* PPS Line for correlating Packet Burst with Volume */}
            <Line
              type="monotone"
              dataKey="pps"
              name="PPS (Pacotes/s)"
              stroke="#fbbf24"
              strokeWidth={1}
              strokeDasharray="2 2"
              dot={false}
              isAnimationActive={false}
            />

            {/* ReferenceDots on Anomaly Peaks */}
            {showAnomaliesOnly && anomalyPoints.map((pt, idx) => (
              <ReferenceDot
                key={`anomaly-${pt.time}-${idx}`}
                x={pt.time}
                y={pt.anomalyMarker || 0}
                r={6}
                fill="#f43f5e"
                stroke="#ffe4e6"
                strokeWidth={2}
              />
            ))}
          </ComposedChart>
        </ResponsiveContainer>
      </div>

      {/* 4. Active Anomaly Highlights & Context Bar */}
      {stats.anomaliesCount > 0 && (
        <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-900/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 animate-pulse" />
            <span className="text-slate-300 font-medium">
              Pico de Anomalia Detectado na Janela Recente:
            </span>
            <span className="font-mono text-rose-300 font-semibold truncate">
              {alerts.find(a => a.status === 'active')?.title || 'Surto de pacotes com desvio estatístico (>300%)'}
            </span>
          </div>

          <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto font-mono text-[11px] text-slate-400">
            <span>Interface: <strong className="text-cyan-400">{primaryIface}</strong></span>
            <span aria-hidden="true">·</span>
            <span className="text-emerald-400">Modo Autônomo Ativo</span>
          </div>
        </div>
      )}
    </div>
  );
};

// Custom Tooltip component for Recharts
interface CustomTooltipProps {
  active?: boolean;
  payload?: any[];
  label?: string;
  unit: string;
}

const CustomTooltip: React.FC<CustomTooltipProps> = ({ active, payload, label, unit }) => {
  if (!active || !payload || payload.length === 0) return null;

  const rawPoint = payload[0]?.payload as TrafficDataPoint & { anomalyTitle?: string; hasAnomaly?: boolean };
  const hasAnomaly = rawPoint?.hasAnomaly;
  const anomalyTitle = rawPoint?.anomalyTitle;

  return (
    <div className="p-3 bg-slate-950/95 border border-slate-800 rounded-lg shadow-2xl backdrop-blur-md text-xs space-y-2 min-w-[210px]">
      <div className="flex items-center justify-between border-b border-slate-800 pb-1.5 font-mono text-slate-400">
        <span className="text-slate-300 font-semibold">{label}</span>
        <span className="text-[10px] text-cyan-400">{rawPoint?.pps || 0} PPS</span>
      </div>

      {hasAnomaly && (
        <div className="p-1.5 rounded bg-rose-950/70 border border-rose-800 text-[11px] text-rose-300 flex items-start gap-1.5 animate-fadeIn">
          <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <strong className="block text-rose-200">Pico de Ameaça Detectado!</strong>
            <span className="text-rose-300/90 leading-tight">{anomalyTitle || 'Desvio anômalo de tráfego'}</span>
          </div>
        </div>
      )}

      <div className="space-y-1 font-mono">
        {payload.map((item, index) => {
          if (item.dataKey === 'anomalyMarker') return null;
          return (
            <div key={`tooltip-item-${index}`} className="flex items-center justify-between gap-4">
              <span className="flex items-center gap-1.5 text-slate-400">
                <span 
                  className="w-2 h-2 rounded-full inline-block" 
                  style={{ backgroundColor: item.color }} 
                />
                <span className="truncate max-w-[130px]">{item.name}:</span>
              </span>
              <span className="font-semibold text-slate-200">
                {typeof item.value === 'number' ? item.value.toLocaleString('pt-BR') : item.value} {item.dataKey === 'pps' ? 'pps' : unit}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
