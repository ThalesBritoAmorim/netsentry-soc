import React, { useMemo, useState, useEffect } from 'react';
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  Cell 
} from 'recharts';
import { SystemMetrics, TrafficFlow, ThreatAlert } from '../types';
import { 
  Activity, 
  Wifi, 
  Layers, 
  ArrowUpRight, 
  ShieldCheck, 
  Radio, 
  BarChart3, 
  PieChart as PieIcon,
  Server
} from 'lucide-react';

interface RealtimeTrafficOverviewProps {
  metrics: SystemMetrics;
  trafficFlows: TrafficFlow[];
  alerts: ThreatAlert[];
}

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: '#06b6d4',  // Cyan
  UDP: '#10b981',  // Emerald
  ARP: '#f59e0b',  // Amber
  DNS: '#a855f7',  // Purple
  ICMP: '#ec4899', // Pink
  TLS: '#3b82f6',  // Blue
  OUTROS: '#64748b' // Slate
};

export const RealtimeTrafficOverview: React.FC<RealtimeTrafficOverviewProps> = ({
  metrics,
  trafficFlows,
  alerts
}) => {
  const [viewMode, setViewMode] = useState<'protocols' | 'bandwidth'>('protocols');
  const [liveHistory, setLiveHistory] = useState<Array<{
    time: string;
    pps: number;
    kbps: number;
  }>>([]);

  // Collect live rolling timeline from real networkEngine state
  useEffect(() => {
    const now = new Date();
    const timeStr = now.toLocaleTimeString('pt-BR', { hour12: false });
    const newPoint = {
      time: timeStr,
      pps: metrics.pps || 0,
      kbps: metrics.bandwidthKbps || 0
    };

    setLiveHistory(prev => {
      const slice = prev.length >= 20 ? prev.slice(1) : prev;
      return [...slice, newPoint];
    });
  }, [metrics.pps, metrics.bandwidthKbps]);

  // Aggregate protocol distribution from real traffic flows
  const protocolData = useMemo(() => {
    const counts: Record<string, { packets: number; bytes: number }> = {
      TCP: { packets: 0, bytes: 0 },
      UDP: { packets: 0, bytes: 0 },
      ARP: { packets: 0, bytes: 0 },
      DNS: { packets: 0, bytes: 0 },
      ICMP: { packets: 0, bytes: 0 },
      TLS: { packets: 0, bytes: 0 }
    };

    if (trafficFlows.length === 0) {
      // If no flows captured yet, show nominal baseline based on interface
      return [
        { protocol: 'TCP', packets: Math.max(metrics.totalPackets > 0 ? Math.round(metrics.totalPackets * 0.6) : 0, 0), bytes: 0, color: PROTOCOL_COLORS.TCP },
        { protocol: 'UDP', packets: Math.max(metrics.totalPackets > 0 ? Math.round(metrics.totalPackets * 0.25) : 0, 0), bytes: 0, color: PROTOCOL_COLORS.UDP },
        { protocol: 'ARP', packets: Math.max(metrics.totalPackets > 0 ? Math.round(metrics.totalPackets * 0.1) : 0, 0), bytes: 0, color: PROTOCOL_COLORS.ARP },
        { protocol: 'DNS', packets: Math.max(metrics.totalPackets > 0 ? Math.round(metrics.totalPackets * 0.05) : 0, 0), bytes: 0, color: PROTOCOL_COLORS.DNS }
      ];
    }

    trafficFlows.forEach(flow => {
      const proto = flow.protocol || 'TCP';
      if (!counts[proto]) {
        counts[proto] = { packets: 0, bytes: 0 };
      }
      counts[proto].packets += 1;
      counts[proto].bytes += flow.packetLength || 64;
    });

    return Object.entries(counts)
      .filter(([_, data]) => data.packets > 0)
      .map(([protocol, data]) => ({
        protocol,
        packets: data.packets,
        bytes: Math.round(data.bytes / 1024), // KB
        color: PROTOCOL_COLORS[protocol] || '#64748b'
      }));
  }, [trafficFlows, metrics.totalPackets]);

  const totalBufferPackets = trafficFlows.length;
  const suspiciousCount = trafficFlows.filter(f => f.isSuspicious).length;

  return (
    <div className="p-4 sm:p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4 shadow-xl">
      {/* 1. Header with Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-950/90 border border-cyan-800 text-cyan-400 shrink-0">
            <BarChart3 className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm sm:text-base font-bold text-slate-100">
                Subseção de Tráfego de Rede em Tempo Real
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-800 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Telemetria Direta da networkEngine
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Análise em tempo real de vazão, taxa de pacotes e distribuição de protocolos inspecionados pelo sniffer Scapy.
            </p>
          </div>
        </div>

        {/* View Toggle */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs self-start sm:self-auto">
          <button
            onClick={() => setViewMode('protocols')}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded font-medium transition-colors ${
              viewMode === 'protocols'
                ? 'bg-slate-800 text-cyan-300 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>Por Protocolo</span>
          </button>
          <button
            onClick={() => setViewMode('bandwidth')}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded font-medium transition-colors ${
              viewMode === 'bandwidth'
                ? 'bg-slate-800 text-emerald-300 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5 text-emerald-400" />
            <span>Vazão KB/s & PPS</span>
          </button>
        </div>
      </div>

      {/* 2. Real-Time Telemetry Stats Ribbon */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
          <span className="text-[11px] text-slate-500 block">Interface Ativa</span>
          <span className="text-sm font-bold font-mono text-cyan-300 truncate block mt-0.5">
            {metrics.sniffingInterface}
          </span>
          <span className="text-[10px] text-slate-400">Modo Promíscuo</span>
        </div>

        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
          <span className="text-[11px] text-slate-500 block">Vazão Instantânea</span>
          <span className="text-sm font-bold font-mono text-emerald-400 block mt-0.5">
            {metrics.bandwidthKbps.toLocaleString('pt-BR')} <span className="text-[10px] font-normal text-slate-400">KB/s</span>
          </span>
          <span className="text-[10px] text-slate-400">~{((metrics.bandwidthKbps * 8) / 1000).toFixed(2)} Mbps</span>
        </div>

        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
          <span className="text-[11px] text-slate-500 block">Taxa de Pacotes (PPS)</span>
          <span className="text-sm font-bold font-mono text-indigo-400 block mt-0.5">
            {metrics.pps} <span className="text-[10px] font-normal text-slate-400">PPS</span>
          </span>
          <span className="text-[10px] text-slate-400">{metrics.totalPackets.toLocaleString('pt-BR')} auditados</span>
        </div>

        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
          <span className="text-[11px] text-slate-500 block">Fluxos no Buffer</span>
          <span className={`text-sm font-bold font-mono block mt-0.5 ${suspiciousCount > 0 ? 'text-rose-400' : 'text-slate-200'}`}>
            {totalBufferPackets} <span className="text-[10px] font-normal text-slate-400">({suspiciousCount} suspeitos)</span>
          </span>
          <span className="text-[10px] text-slate-400">{alerts.length} alertas correlacionados</span>
        </div>
      </div>

      {/* 3. Recharts Dynamic Visualizer */}
      <div className="h-64 w-full pt-2">
        <ResponsiveContainer width="100%" height="100%">
          {viewMode === 'protocols' ? (
            <BarChart
              data={protocolData}
              margin={{ top: 10, right: 15, left: -10, bottom: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis 
                dataKey="protocol" 
                stroke="#64748b" 
                fontSize={11} 
                tickLine={false} 
                axisLine={{ stroke: '#334155' }} 
              />
              <YAxis 
                stroke="#64748b" 
                fontSize={11} 
                tickLine={false} 
                axisLine={{ stroke: '#334155' }} 
              />
              <Tooltip 
                content={({ active, payload, label }) => {
                  if (!active || !payload || payload.length === 0) return null;
                  const data = payload[0].payload;
                  return (
                    <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg shadow-xl text-xs space-y-1 font-mono">
                      <div className="font-bold text-slate-200 border-b border-slate-800 pb-1">
                        Protocolo: {label}
                      </div>
                      <div className="text-cyan-400">Pacotes: {data.packets}</div>
                      {data.bytes > 0 && <div className="text-emerald-400">Volume: {data.bytes} KB</div>}
                    </div>
                  );
                }} 
              />
              <Bar dataKey="packets" name="Pacotes Capturados" radius={[4, 4, 0, 0]}>
                {protocolData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          ) : (
            <AreaChart
              data={liveHistory}
              margin={{ top: 10, right: 15, left: -10, bottom: 0 }}
            >
              <defs>
                <linearGradient id="areaKbps" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="areaPps" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis 
                dataKey="time" 
                stroke="#64748b" 
                fontSize={11} 
                tickLine={false} 
                axisLine={{ stroke: '#334155' }} 
                minTickGap={20}
              />
              <YAxis 
                stroke="#64748b" 
                fontSize={11} 
                tickLine={false} 
                axisLine={{ stroke: '#334155' }} 
              />
              <Tooltip 
                content={({ active, payload, label }) => {
                  if (!active || !payload || payload.length === 0) return null;
                  return (
                    <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg shadow-xl text-xs space-y-1 font-mono">
                      <div className="font-bold text-slate-200 border-b border-slate-800 pb-1">{label}</div>
                      <div className="text-emerald-400">Vazão: {payload[0]?.value} KB/s</div>
                      <div className="text-cyan-400">PPS: {payload[1]?.value} pacotes/s</div>
                    </div>
                  );
                }} 
              />
              <Legend verticalAlign="top" align="right" wrapperStyle={{ fontSize: '11px', paddingBottom: '8px' }} />
              <Area
                type="monotone"
                dataKey="kbps"
                name="Vazão (KB/s)"
                stroke="#10b981"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#areaKbps)"
                isAnimationActive={false}
              />
              <Area
                type="monotone"
                dataKey="pps"
                name="Taxa (PPS)"
                stroke="#06b6d4"
                strokeWidth={1.5}
                fillOpacity={1}
                fill="url(#areaPps)"
                isAnimationActive={false}
              />
            </AreaChart>
          )}
        </ResponsiveContainer>
      </div>
    </div>
  );
};
