import React, { useState } from 'react';
import { 
  NetworkDevice, 
  ThreatAlert, 
  TrafficFlow, 
  SystemMetrics, 
  ThreatCategory 
} from '../types';
import { 
  ShieldAlert, 
  Activity, 
  Wifi, 
  Database, 
  Zap, 
  Terminal, 
  ArrowUpRight, 
  ShieldCheck, 
  AlertTriangle,
  Play,
  RotateCcw,
  CheckCircle2,
  Server,
  Cpu,
  Layers,
  ExternalLink,
  Split,
  Maximize2,
  BarChart2,
  Radio,
  Sparkles,
  Volume2,
  VolumeX
} from 'lucide-react';
import { soundAlertService } from '../services/soundAlertService';
import { D3LiveThroughputChart } from './D3LiveThroughputChart';
import { NetworkTrafficChart } from './NetworkTrafficChart';
import { IncidentHeatmapChart } from './IncidentHeatmapChart';
import { RealtimeTrafficOverview } from './RealtimeTrafficOverview';

interface DashboardViewProps {
  metrics: SystemMetrics;
  devices: NetworkDevice[];
  alerts: ThreatAlert[];
  trafficFlows: TrafficFlow[];
  onOpenPlaybook: (alert: ThreatAlert) => void;
  onApplyMitigation: (alertId: string) => void;
  onRollbackMitigation: (alertId: string) => void;
  onSimulateAttack: (category: ThreatCategory) => void;
  onNavigateToDevices: () => void;
  onNavigateToDeploy: () => void;
  onOpenKaliTerminal?: (cmd: string) => void;
  onUnblockHost?: (ip: string) => void;
  onOpenAIForensic?: (type: 'threat' | 'device' | 'flow' | 'spike' | 'posture', data?: any) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  metrics,
  devices,
  alerts,
  trafficFlows,
  onOpenPlaybook,
  onApplyMitigation,
  onRollbackMitigation,
  onSimulateAttack,
  onNavigateToDevices,
  onNavigateToDeploy,
  onOpenKaliTerminal,
  onUnblockHost,
  onOpenAIForensic
}) => {
  const [soundMuted, setSoundMuted] = useState(soundAlertService.isMuted());

  React.useEffect(() => {
    return soundAlertService.onMuteChange(setSoundMuted);
  }, []);
  const [filterSeverity, setFilterSeverity] = useState<'all' | 'critical' | 'high' | 'active'>('all');
  const [analyticsLayout, setAnalyticsLayout] = useState<'split' | 'd3' | 'traffic' | 'heatmap'>('split');

  const activeAlerts = alerts.filter(a => a.status === 'active' || a.status === 'investigating');
  const criticalCount = alerts.filter(a => a.severity === 'critical' && a.status === 'active').length;
  const highCount = alerts.filter(a => a.severity === 'high' && a.status === 'active').length;

  // Detecta se o Kali Linux (192.168.0.156) ou host local sofreu auto-bloqueio
  const selfBlockedAlerts = alerts.filter(a => 
    (a.sourceIp === '192.168.0.156' || a.sourceIp === '127.0.0.1' || a.sourceIp === 'localhost') && 
    (a.playbook?.applied || a.status === 'mitigated' || a.category === 'port_scan')
  );
  const isKaliSelfBlocked = selfBlockedAlerts.length > 0;

  const filteredAlerts = alerts.filter(a => {
    if (filterSeverity === 'critical') return a.severity === 'critical';
    if (filterSeverity === 'high') return a.severity === 'high';
    if (filterSeverity === 'active') return a.status === 'active' || a.status === 'investigating';
    return true;
  });

  const highRiskDevices = devices.filter(d => d.threatScore > 50 || d.trustLevel === 'quarantined');

  return (
    <div className="space-y-6">
      {/* Auto-Bloqueio Emergency Notice Banner */}
      {isKaliSelfBlocked && (
        <div className="p-4 rounded-xl bg-amber-950/40 border-2 border-amber-500/80 shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4 animate-in fade-in">
          <div className="flex items-start sm:items-center gap-3">
            <div className="p-2.5 rounded-lg bg-amber-500/20 text-amber-400 shrink-0">
              <AlertTriangle className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-amber-300 flex items-center gap-2">
                <span>⚠️ Auto-Bloqueio Detectado: Host Kali Linux Bloqueado no Kernel</span>
                <span className="text-xs px-2 py-0.5 rounded bg-amber-900/80 text-amber-100 border border-amber-600 font-mono">192.168.0.156</span>
              </h4>
              <p className="text-xs text-amber-200/90 mt-1 leading-relaxed">
                O sniffer Scapy interpretou os pacotes de varredura do seu próprio Kali como um ataque externo e aplicou regras <code className="bg-amber-900/40 px-1 py-0.5 rounded font-mono text-amber-200">DROP</code> no iptables. Comandos estão bloqueados pelo firewall.
              </p>
            </div>
          </div>
          <button
            onClick={() => onUnblockHost?.('192.168.0.156')}
            className="px-4 py-2.5 rounded-lg bg-amber-400 hover:bg-amber-300 text-slate-950 font-bold text-xs transition-all shrink-0 flex items-center gap-2 shadow-lg cursor-pointer transform hover:scale-[1.02]"
          >
            <Zap className="w-4 h-4 fill-slate-950" />
            <span>⚡ Desbloquear Meu Kali Linux (Remover DROP)</span>
          </button>
        </div>
      )}

      {/* 1. Telemetry KPI Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3.5">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Taxa de Pacotes (PPS)</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-100">
            {metrics.pps}
          </div>
          <div className="mt-1 text-xs text-slate-500 font-mono">
            {metrics.totalPackets.toLocaleString('pt-BR')} total
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Vazão de Tráfego</span>
            <ArrowUpRight className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-100">
            {metrics.bandwidthKbps} <span className="text-xs text-slate-400 font-normal">KB/s</span>
          </div>
          <div className="mt-1 text-xs text-slate-500">
            {metrics.sniffingInterface}
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Dispositivos na Rede</span>
            <Wifi className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-100">
            {devices.length}
          </div>
          <div className="mt-1 text-xs text-slate-500">
            {devices.filter(d => d.isOnline).length} online agora
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Ameaças Ativas</span>
            <ShieldAlert className={`w-4 h-4 ${criticalCount > 0 ? 'text-rose-400' : 'text-amber-400'}`} />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-rose-400">
            {activeAlerts.length}
          </div>
          <div className="mt-1 text-xs text-slate-500">
            {criticalCount} críticas · {highCount} altas
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Mitigações Executadas</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-emerald-400">
            {metrics.totalThreatsNeutralized}
          </div>
          <div className="mt-1 text-xs text-slate-500">
            Netfilter / Iptables no Kernel
          </div>
        </div>
      </div>

      {/* 2. System Architecture & Autonomous Engine Ribbon */}
      <div className={`p-4 rounded-xl border flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all ${
        metrics.isLiveKaliConnected
          ? 'bg-emerald-950/20 border-emerald-800/80 shadow-sm shadow-emerald-950/50'
          : 'bg-slate-900/80 border-slate-800'
      }`}>
        <div className="flex items-center gap-3">
          <div className={`p-2.5 rounded-lg border shrink-0 ${
            metrics.isLiveKaliConnected
              ? 'bg-emerald-950 text-emerald-400 border-emerald-700'
              : 'bg-cyan-950/70 border-cyan-800/80 text-cyan-400'
          }`}>
            {metrics.isLiveKaliConnected ? <Server className="w-5 h-5" /> : <Cpu className="w-5 h-5" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-slate-100">
                {metrics.isLiveKaliConnected ? 'Dados Reais em Tempo Real do Kali Linux' : 'NetSentry Daemon Autônomo & Portainer Stack'}
              </h2>
              <span className={`text-xs font-mono font-semibold ${metrics.isLiveKaliConnected ? 'text-emerald-400' : 'text-slate-400'}`}>
                {metrics.isLiveKaliConnected ? `● KALI AO VIVO (${metrics.sniffingInterface})` : '○ AGENTE KALI AGUARDANDO'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              {metrics.isLiveKaliConnected
                ? `Captura Scapy em modo promíscuo ativa no Kali (${metrics.totalPackets.toLocaleString()} pacotes). Última sincronização: ${metrics.lastKaliSync || 'Agora'}`
                : 'Conectando ao Agente na porta 8080 do Kali. Se estiver rodando no Kali, ele sincroniza automaticamente.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0 flex-wrap">
          {/* Audio Alert Status & Test Action */}
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs">
            <button
              onClick={() => {
                const next = soundAlertService.toggleMute();
                setSoundMuted(next);
                if (!next) {
                  soundAlertService.testSound('warning');
                }
              }}
              className={`flex items-center gap-1 font-mono transition-colors ${
                !soundMuted ? 'text-indigo-300 hover:text-indigo-200' : 'text-slate-500 hover:text-slate-300'
              }`}
              title={soundMuted ? 'Alerta sonoro mutado. Clique para ativar som.' : 'Alerta sonoro ativo'}
            >
              {!soundMuted ? <Volume2 className="w-3.5 h-3.5 text-indigo-400" /> : <VolumeX className="w-3.5 h-3.5 text-slate-500" />}
              <span className="hidden sm:inline">{!soundMuted ? 'Som: ATIVO' : 'Som: MUDO'}</span>
            </button>
            <button
              onClick={() => soundAlertService.testSound('critical')}
              className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 hover:text-white border border-slate-700 transition-colors ml-1 font-mono"
              title="Testar sirene crítica do SOC"
            >
              Testar
            </button>
          </div>

          <button
            onClick={onNavigateToDeploy}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 transition-colors"
          >
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            <span>Configuração Portainer</span>
          </button>
          <button
            onClick={() => onSimulateAttack('arp_poisoning')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 transition-colors shadow-sm"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Testar Detecção ARP</span>
          </button>
        </div>
      </div>

      {/* 3. Analytics & SOC Intelligence Hub (Recharts Telemetry + Heatmap Matrix) */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              Telemetria & Padrões Táticos de Rede
            </span>
            <span className="text-[10px] font-mono text-cyan-300 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/80">
              D3.js v7 + Recharts
            </span>
          </div>

          {/* Interactive Layout Controls: D3 vs Split vs Recharts vs Heatmap */}
          <div className="flex items-center gap-1 p-1 bg-slate-900 rounded-lg border border-slate-800 self-start sm:self-auto text-xs">
            <button
              onClick={() => setAnalyticsLayout('d3')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded font-medium transition-colors ${
                analyticsLayout === 'd3' 
                  ? 'bg-slate-800 text-cyan-300 font-semibold shadow-sm' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Vazão ao Vivo em bps com D3.js e Detecção de Picos de Tráfego"
            >
              <Zap className="w-3.5 h-3.5 text-cyan-400" />
              <span>D3 Live Throughput (bps)</span>
            </button>
            <button
              onClick={() => setAnalyticsLayout('split')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded font-medium transition-colors ${
                analyticsLayout === 'split' 
                  ? 'bg-slate-800 text-slate-100 font-semibold shadow-sm' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Exibir Gráfico D3.js de Throughput e Mapa de Calor lado a lado"
            >
              <Split className="w-3.5 h-3.5 text-cyan-400" />
              <span>Lado a Lado (SOC)</span>
            </button>
            <button
              onClick={() => setAnalyticsLayout('traffic')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded font-medium transition-colors ${
                analyticsLayout === 'traffic' 
                  ? 'bg-slate-800 text-slate-100 font-semibold shadow-sm' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Visualização Recharts por interface de rede"
            >
              <Activity className="w-3.5 h-3.5 text-emerald-400" />
              <span>Recharts Interface</span>
            </button>
            <button
              onClick={() => setAnalyticsLayout('heatmap')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded font-medium transition-colors ${
                analyticsLayout === 'heatmap' 
                  ? 'bg-slate-800 text-slate-100 font-semibold shadow-sm' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Expandir matriz de calor de incidentes por faixa horária"
            >
              <BarChart2 className="w-3.5 h-3.5 text-rose-400" />
              <span>Mapa de Calor</span>
            </button>
          </div>
        </div>

        {/* Viewport-Adaptive Container: D3 Live or Split Grid or Single Maximize */}
        {analyticsLayout === 'split' ? (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 items-start min-w-0">
            <div className="min-w-0 w-full overflow-hidden">
              <D3LiveThroughputChart 
                metrics={metrics} 
                alerts={alerts} 
                trafficFlows={trafficFlows} 
                onOpenKaliTerminal={onOpenKaliTerminal}
                onOpenAIForensic={onOpenAIForensic}
              />
            </div>
            <div className="min-w-0 w-full overflow-hidden">
              <IncidentHeatmapChart 
                alerts={alerts} 
                onSelectCategory={(cat) => onSimulateAttack(cat)}
              />
            </div>
          </div>
        ) : analyticsLayout === 'd3' ? (
          <div className="min-w-0 w-full overflow-hidden">
            <D3LiveThroughputChart 
              metrics={metrics} 
              alerts={alerts} 
              trafficFlows={trafficFlows} 
              onOpenKaliTerminal={onOpenKaliTerminal}
              onOpenAIForensic={onOpenAIForensic}
            />
          </div>
        ) : analyticsLayout === 'traffic' ? (
          <div className="min-w-0 w-full overflow-hidden">
            <NetworkTrafficChart 
              metrics={metrics} 
              alerts={alerts} 
              trafficFlows={trafficFlows} 
            />
          </div>
        ) : (
          <div className="min-w-0 w-full overflow-hidden">
            <IncidentHeatmapChart 
              alerts={alerts} 
              onSelectCategory={(cat) => onSimulateAttack(cat)}
            />
          </div>
        )}
      </div>

      {/* 4. Real-time Traffic Telemetry Sub-section (Recharts Engine) */}
      <RealtimeTrafficOverview 
        metrics={metrics} 
        trafficFlows={trafficFlows} 
        alerts={alerts} 
      />

      {/* 5. Threat Operations & Incident Center (Split 2-Column Balanced Viewport) */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start min-w-0">
        {/* Left Column (7 cols): Alerts Feed & Mitigation Playbooks */}
        <div className="xl:col-span-7 space-y-3 min-w-0">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <span>Alertas de Ameaças & Playbooks</span>
                <span className="text-xs text-slate-400 font-mono">({filteredAlerts.length})</span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Análise autônoma com execução de comandos de segurança no Kali Linux.
              </p>
            </div>

            <div className="flex items-center gap-2 self-start sm:self-auto flex-wrap">
              {onOpenAIForensic && (
                <button
                  onClick={() => onOpenAIForensic('posture')}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-cyan-300 bg-cyan-950/80 border border-cyan-800 hover:bg-cyan-900 rounded-lg transition-colors shadow-sm"
                  title="Auditoria Global de Postura da Rede com IA Gemini"
                >
                  <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Auditoria Postura IA</span>
                </button>
              )}

              {/* Segmented Filter Control */}
              <div className="flex items-center gap-1 p-1 bg-slate-900 rounded-lg border border-slate-800">
                <button
                  onClick={() => setFilterSeverity('all')}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                    filterSeverity === 'all'
                      ? 'bg-slate-800 text-slate-100'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Todos
                </button>
                <button
                  onClick={() => setFilterSeverity('active')}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                    filterSeverity === 'active'
                      ? 'bg-slate-800 text-slate-100'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Ativos ({activeAlerts.length})
                </button>
                <button
                  onClick={() => setFilterSeverity('critical')}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                    filterSeverity === 'critical'
                      ? 'bg-slate-800 text-rose-300'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Críticos ({criticalCount})
                </button>
              </div>
            </div>
          </div>

          {/* Scrollable Alerts Container with Max Height to keep Viewport Intact */}
          <div className="max-h-[620px] overflow-y-auto pr-1 space-y-3">
            {filteredAlerts.length === 0 ? (
              <div className="p-8 text-center bg-slate-900/50 rounded-xl border border-slate-800 space-y-2">
                <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" />
                <p className="text-sm font-medium text-slate-200">Nenhuma ameaça correspondente</p>
                <p className="text-xs text-slate-500">
                  O tráfego de rede está nominal e sem anomalias no filtro selecionado.
                </p>
              </div>
            ) : (
              filteredAlerts.map((alert) => {
                const pb = alert.playbook;
                const isMitigated = pb.applied;

                return (
                  <div
                    key={alert.id}
                    className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all space-y-3"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                      <div className="flex items-start gap-3">
                        <div className={`p-2 rounded-lg mt-0.5 shrink-0 ${
                          alert.severity === 'critical' ? 'bg-rose-950/70 text-rose-400 border border-rose-800/80' :
                          alert.severity === 'high' ? 'bg-amber-950/70 text-amber-400 border border-amber-800/80' :
                          'bg-cyan-950/70 text-cyan-400 border border-cyan-800/80'
                        }`}>
                          <ShieldAlert className="w-4 h-4" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <h3 className="text-sm font-semibold text-slate-100">{alert.title}</h3>
                            <span className="text-xs font-mono text-slate-400">· {alert.timestamp}</span>
                            <span className={`text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded ${
                              alert.severity === 'critical' ? 'bg-rose-950 text-rose-300' :
                              alert.severity === 'high' ? 'bg-amber-950 text-amber-300' :
                              'bg-cyan-950 text-cyan-300'
                            }`}>
                              {alert.severity}
                            </span>
                          </div>
                          <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                            {alert.details}
                          </p>
                          <div className="flex items-center gap-2.5 text-xs text-slate-400 mt-2 font-mono flex-wrap">
                            <span>Origem: <strong className="text-slate-200">{alert.sourceIp}</strong></span>
                            {alert.sourceMac && (
                              <>
                                <span aria-hidden="true">·</span>
                                <span>MAC: <strong className="text-slate-200">{alert.sourceMac}</strong></span>
                              </>
                            )}
                            <span aria-hidden="true">·</span>
                            <span>Alvo: <strong className="text-slate-200">{alert.targetIp}</strong></span>
                            <span aria-hidden="true">·</span>
                            <span>Confiança: <strong className="text-cyan-400">{alert.confidence}%</strong></span>
                            {alert.mitreAttack && (
                              <>
                                <span aria-hidden="true">·</span>
                                <span className="text-indigo-400">{alert.mitreAttack}</span>
                              </>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Mitigation execution buttons */}
                      <div className="flex items-center gap-2 self-end sm:self-start shrink-0">
                        {alert.sourceIp === '192.168.0.156' || alert.sourceIp === '127.0.0.1' ? (
                          <button
                            onClick={() => onUnblockHost?.(alert.sourceIp)}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold text-amber-950 bg-amber-400 hover:bg-amber-300 transition-colors shadow-sm cursor-pointer"
                            title="Remover regra DROP do iptables para liberar o Kali"
                          >
                            <Zap className="w-3.5 h-3.5 fill-amber-950" />
                            <span>Desbloquear Kali</span>
                          </button>
                        ) : isMitigated ? (
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1 bg-emerald-950/40 px-2.5 py-1 rounded border border-emerald-800/50">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              <span>Mitigado</span>
                            </span>
                            <button
                              onClick={() => onRollbackMitigation(alert.id)}
                              className="p-1.5 text-xs text-slate-400 hover:text-amber-400 rounded hover:bg-slate-800 transition-colors"
                              title="Desfazer mitigação (Rollback)"
                            >
                              <RotateCcw className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => onApplyMitigation(alert.id)}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 transition-colors shadow-sm"
                          >
                            <Zap className="w-3.5 h-3.5 fill-slate-950" />
                            <span>Mitigar</span>
                          </button>
                        )}

                        {onOpenAIForensic && (
                          <button
                            onClick={() => onOpenAIForensic('threat', alert)}
                            className="px-2.5 py-1.5 rounded-lg text-xs font-semibold text-cyan-300 bg-cyan-950/80 border border-cyan-800 hover:bg-cyan-900 transition-colors flex items-center gap-1 shadow-sm"
                            title="Diagnóstico Forense Aprofundado com IA Gemini"
                          >
                            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                            <span>Diagnóstico IA</span>
                          </button>
                        )}

                        <button
                          onClick={() => onOpenPlaybook(alert)}
                          className="px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 transition-colors flex items-center gap-1"
                        >
                          <span>Playbook</span>
                          <ExternalLink className="w-3 h-3 text-slate-400" />
                        </button>
                      </div>
                    </div>

                    {/* Suggested Action Preview with Direct Send to Terminal */}
                    <div className="p-2.5 bg-slate-950/70 rounded-lg border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                      <div className="flex items-center gap-2">
                        <Terminal className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                        <span className="text-slate-400">Sugestão:</span>
                        <strong className="text-slate-200">{pb.actionName}</strong>
                      </div>
                      <div className="flex items-center gap-2">
                        <code className="font-mono text-emerald-400 truncate max-w-xs md:max-w-sm bg-slate-900 px-2 py-0.5 rounded border border-slate-800 text-[11px]">
                          {pb.iptablesCommand}
                        </code>
                        {onOpenKaliTerminal && (
                          <button
                            onClick={() => onOpenKaliTerminal(pb.iptablesCommand)}
                            className="flex items-center gap-1 px-2.5 py-1 bg-cyan-950 text-cyan-300 border border-cyan-800/80 hover:bg-cyan-900/60 font-semibold rounded text-[11px] whitespace-nowrap transition-colors"
                            title="Enviar comando sugerido diretamente para o terminal do Kali"
                          >
                            <Play className="w-3 h-3 text-cyan-400 fill-cyan-400" />
                            <span>Terminal</span>
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column (5 cols): Quick Attack Simulator, High Risk Devices & Live Sniffer */}
        <div className="xl:col-span-5 space-y-4 min-w-0">
          {/* Quick Anomaly Simulator Row */}
          <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                <Radio className="w-3.5 h-3.5 text-cyan-400" />
                Simulador Rápido de Anomalias
              </span>
              <span className="text-[10px] text-slate-500 font-mono">Injeção no Sniffer</span>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => onSimulateAttack('arp_poisoning')}
                className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-amber-700 hover:bg-slate-800/80 transition-all text-left group"
              >
                <div className="text-xs font-semibold text-slate-200 group-hover:text-amber-400 flex items-center justify-between">
                  <span>ARP Poisoning</span>
                  <Play className="w-3 h-3 text-slate-500 group-hover:text-amber-400" />
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">MITM Gateway Spoof</div>
              </button>

              <button
                onClick={() => onSimulateAttack('port_scan')}
                className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-700 hover:bg-slate-800/80 transition-all text-left group"
              >
                <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-400 flex items-center justify-between">
                  <span>SYN Port Scan</span>
                  <Play className="w-3 h-3 text-slate-500 group-hover:text-cyan-400" />
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">Nmap Stealth Sweep</div>
              </button>

              <button
                onClick={() => onSimulateAttack('dns_tunneling')}
                className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-purple-700 hover:bg-slate-800/80 transition-all text-left group"
              >
                <div className="text-xs font-semibold text-slate-200 group-hover:text-purple-400 flex items-center justify-between">
                  <span>Tunelamento DNS</span>
                  <Play className="w-3 h-3 text-slate-500 group-hover:text-purple-400" />
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">Exfiltração Shannon C2</div>
              </button>

              <button
                onClick={() => onSimulateAttack('ddos_flood')}
                className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-rose-700 hover:bg-slate-800/80 transition-all text-left group"
              >
                <div className="text-xs font-semibold text-slate-200 group-hover:text-rose-400 flex items-center justify-between">
                  <span>Surto DDoS SYN</span>
                  <Play className="w-3 h-3 text-slate-500 group-hover:text-rose-400" />
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">1.400+ PPS Flood</div>
              </button>

              <button
                onClick={() => onSimulateAttack('rogue_device')}
                className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-emerald-700 hover:bg-slate-800/80 transition-all text-left group col-span-2"
              >
                <div className="text-xs font-semibold text-slate-200 group-hover:text-emerald-400 flex items-center justify-between">
                  <span>Dispositivo Rogue Não Autorizado</span>
                  <Play className="w-3 h-3 text-slate-500 group-hover:text-emerald-400" />
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">Novo MAC com Telnet na LAN</div>
              </button>
            </div>
          </div>

          {/* High Risk / Quarantined Devices */}
          <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5 uppercase tracking-wider">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                <span>Dispositivos de Alto Risco</span>
              </h3>
              <button
                onClick={onNavigateToDevices}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 font-medium"
              >
                Ver ({devices.length}) →
              </button>
            </div>

            <div className="space-y-2">
              {highRiskDevices.length > 0 ? (
                highRiskDevices.slice(0, 3).map((dev) => (
                  <div
                    key={dev.id}
                    className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs"
                  >
                    <div className="truncate pr-2">
                      <div className="flex items-center gap-1.5">
                        <span className="font-medium text-slate-200 truncate">{dev.hostname}</span>
                        <span className={`text-[9px] uppercase font-semibold px-1 py-0.2 rounded shrink-0 ${
                          dev.trustLevel === 'quarantined' ? 'bg-amber-950 text-amber-300' :
                          dev.trustLevel === 'blocked' ? 'bg-rose-950 text-rose-300' :
                          'bg-slate-800 text-slate-300'
                        }`}>
                          {dev.trustLevel}
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                        {dev.ip} · {dev.vendor}
                      </div>
                    </div>

                    <div className="text-right shrink-0">
                      <div className="font-mono font-bold text-xs text-rose-400">
                        {dev.threatScore}/100
                      </div>
                      <div className="text-[9px] text-slate-500">Score Risco</div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-3 text-center rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs text-slate-500">
                  Nenhum host em quarentena ou com risco elevado detectado.
                </div>
              )}
            </div>
          </div>

          {/* Live Sniffer Traffic Telemetry Sample */}
          <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5 uppercase tracking-wider">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                <span>Sniffer em Tempo Real (Scapy)</span>
              </h3>
              <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Promíscuo
              </span>
            </div>

            <div className="space-y-1.5 font-mono text-xs">
              {trafficFlows.length > 0 ? (
                trafficFlows.slice(0, 4).map((flow) => (
                  <div
                    key={flow.id}
                    className={`p-2 rounded bg-slate-950 border flex items-center justify-between text-[11px] ${
                      flow.isSuspicious ? 'border-rose-900/80 bg-rose-950/20 text-rose-300' : 'border-slate-800/80 text-slate-300'
                    }`}
                  >
                    <div className="flex items-center gap-1.5 truncate">
                      <span className={`px-1 py-0.2 text-[9px] font-bold rounded shrink-0 ${
                        flow.protocol === 'ARP' ? 'bg-amber-950 text-amber-300' :
                        flow.protocol === 'DNS' ? 'bg-purple-950 text-purple-300' :
                        flow.protocol === 'TCP' ? 'bg-cyan-950 text-cyan-300' :
                        'bg-slate-800 text-slate-300'
                      }`}>
                        {flow.protocol}
                      </span>
                      <span className="truncate">{flow.srcIp} → {flow.dstIp}</span>
                    </div>
                    <div className="text-[10px] text-slate-400 shrink-0 ml-1.5">
                      {flow.packetLength}B
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-3 text-center rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs text-slate-500 font-sans">
                  Aguardando pacotes capturados pelo sniffer Scapy no Kali...
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
