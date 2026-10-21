import React, { useState } from 'react';
import { TrafficFlow, AnomalyDetectionRule } from '../types';
import { 
  Activity, 
  Pause, 
  Play, 
  Download, 
  Filter, 
  Sliders, 
  ShieldAlert, 
  CheckCircle2, 
  SlidersHorizontal,
  FileText,
  Search
} from 'lucide-react';

interface TrafficLogsViewProps {
  flows: TrafficFlow[];
  rules: AnomalyDetectionRule[];
  isStreaming: boolean;
  onToggleStreaming: () => void;
  onToggleRule: (ruleId: string, enabled: boolean) => void;
}

export const TrafficLogsView: React.FC<TrafficLogsViewProps> = ({
  flows,
  rules,
  isStreaming,
  onToggleStreaming,
  onToggleRule
}) => {
  const [filterProto, setFilterProto] = useState<string>('all');
  const [onlySuspicious, setOnlySuspicious] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [showRulesDrawer, setShowRulesDrawer] = useState(false);

  const filteredFlows = flows.filter((f) => {
    const matchProto = filterProto === 'all' || f.protocol === filterProto;
    const matchSuspicious = !onlySuspicious || f.isSuspicious;
    const matchSearch = 
      f.srcIp.includes(searchTerm) ||
      f.dstIp.includes(searchTerm) ||
      f.info.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (f.anomalyReason && f.anomalyReason.toLowerCase().includes(searchTerm.toLowerCase()));

    return matchProto && matchSuspicious && matchSearch;
  });

  const exportCSV = () => {
    const headers = 'ID,Timestamp,Protocol,Source_IP,Source_Port,Dest_IP,Dest_Port,Length,Flags,Info,Suspicious\n';
    const rows = filteredFlows.map(f => 
      `"${f.id}","${f.timestamp}","${f.protocol}","${f.srcIp}","${f.srcPort || ''}","${f.dstIp}","${f.dstPort || ''}","${f.packetLength}","${f.flags || ''}","${f.info.replace(/"/g, '""')}","${f.isSuspicious}"`
    ).join('\n');
    
    const blob = new Blob([headers + rows], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `netsentry_traffic_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6">
      {/* 1. Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <span>Inspetor de Tráfego & Fluxos de Rede em Tempo Real</span>
            <span className="text-xs text-slate-400 font-mono">({filteredFlows.length} capturados)</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Sniffer em tempo real com identificação de anomalias por heurística e inspeção de cabeçalhos.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto">
          <button
            onClick={() => setShowRulesDrawer(!showRulesDrawer)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
              showRulesDrawer 
                ? 'bg-cyan-950 text-cyan-300 border-cyan-700' 
                : 'bg-slate-900 text-slate-300 border-slate-800 hover:bg-slate-800'
            }`}
          >
            <SlidersHorizontal className="w-3.5 h-3.5" />
            <span>Regras de Anomalia ({rules.filter(r => r.enabled).length}/{rules.length})</span>
          </button>

          <button
            onClick={onToggleStreaming}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
              isStreaming
                ? 'bg-amber-950/60 text-amber-300 border-amber-800 hover:bg-amber-950'
                : 'bg-emerald-950/60 text-emerald-300 border-emerald-800 hover:bg-emerald-950'
            }`}
          >
            {isStreaming ? (
              <>
                <Pause className="w-3.5 h-3.5" />
                <span>Pausar Captura</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Retomar Captura</span>
              </>
            )}
          </button>

          <button
            onClick={exportCSV}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 bg-slate-900 border border-slate-800 hover:bg-slate-800 transition-colors"
            title="Exportar registros filtrados para CSV"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Exportar CSV</span>
          </button>
        </div>
      </div>

      {/* 2. Anomaly Rules Configuration Panel (Collapsible) */}
      {showRulesDrawer && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 animate-fadeIn">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <span>Configuração dos Motores Heurísticos de Detecção</span>
            </h3>
            <span className="text-xs text-slate-400">
              Persistido na tabela <code className="text-cyan-400 font-mono">anomaly_rules</code> do PostgreSQL
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {rules.map((rule) => (
              <div
                key={rule.id}
                className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between space-y-2 text-xs"
              >
                <div>
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">{rule.name}</span>
                    <button
                      onClick={() => onToggleRule(rule.id, !rule.enabled)}
                      className={`text-[10px] font-semibold px-2 py-0.5 rounded transition-colors ${
                        rule.enabled ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {rule.enabled ? 'ATIVO' : 'PAUSADO'}
                    </button>
                  </div>
                  <p className="text-slate-400 text-[11px] mt-1 leading-relaxed">
                    {rule.description}
                  </p>
                </div>

                <div className="pt-2 border-t border-slate-900 flex items-center justify-between font-mono text-[11px] text-slate-400">
                  <span>Limiar: <strong className="text-cyan-400">{rule.threshold} {rule.metric}</strong></span>
                  <span>Disparos: <strong className="text-slate-200">{rule.triggersCount}</strong></span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 3. Filters Bar */}
      <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-2 text-slate-500" />
          <input
            type="text"
            placeholder="Filtrar por IP, porta ou payload..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-1 bg-slate-950 border border-slate-800 rounded-md text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Protocol Selector */}
        <div className="flex items-center gap-1.5 overflow-x-auto text-xs">
          <span className="text-slate-500 whitespace-nowrap">Protocolo:</span>
          {['all', 'TCP', 'UDP', 'DNS', 'ARP', 'TLS', 'HTTP', 'ICMP'].map((proto) => (
            <button
              key={proto}
              onClick={() => setFilterProto(proto)}
              className={`px-2.5 py-0.5 rounded transition-colors ${
                filterProto === proto ? 'bg-slate-800 text-slate-100 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {proto === 'all' ? 'Todos' : proto}
            </button>
          ))}
        </div>

        {/* Suspicious Toggle */}
        <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer self-start md:self-auto shrink-0 select-none">
          <input
            type="checkbox"
            checked={onlySuspicious}
            onChange={(e) => setOnlySuspicious(e.target.checked)}
            className="rounded border-slate-800 bg-slate-950 text-cyan-500 focus:ring-0"
          />
          <span>Apenas Anomalias / Suspeitos</span>
        </label>
      </div>

      {/* 4. Live Traffic Stream Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden font-mono text-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase text-[11px]">
              <tr>
                <th className="py-2.5 px-3">Hora</th>
                <th className="py-2.5 px-3">Proto</th>
                <th className="py-2.5 px-3">Origem</th>
                <th className="py-2.5 px-3">Destino</th>
                <th className="py-2.5 px-3">Tamanho</th>
                <th className="py-2.5 px-3">Flags</th>
                <th className="py-2.5 px-3">Informação / Análise</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredFlows.map((flow) => (
                <tr 
                  key={flow.id} 
                  className={`hover:bg-slate-800/40 transition-colors ${
                    flow.isSuspicious ? 'bg-rose-950/20 text-rose-200' : ''
                  }`}
                >
                  <td className="py-2 px-3 text-slate-400 whitespace-nowrap">
                    {flow.timestamp}
                  </td>

                  <td className="py-2 px-3">
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                      flow.protocol === 'ARP' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                      flow.protocol === 'DNS' ? 'bg-purple-950 text-purple-300 border border-purple-800' :
                      flow.protocol === 'TCP' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' :
                      flow.protocol === 'TLS' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                      'bg-slate-800 text-slate-300'
                    }`}>
                      {flow.protocol}
                    </span>
                  </td>

                  <td className="py-2 px-3 whitespace-nowrap">
                    <span className="font-semibold text-slate-200">{flow.srcIp}</span>
                    {flow.srcPort && <span className="text-slate-400">:{flow.srcPort}</span>}
                  </td>

                  <td className="py-2 px-3 whitespace-nowrap">
                    <span className="font-semibold text-slate-200">{flow.dstIp}</span>
                    {flow.dstPort && <span className="text-slate-400">:{flow.dstPort}</span>}
                  </td>

                  <td className="py-2 px-3 tabular-nums text-slate-400 whitespace-nowrap">
                    {flow.packetLength} B
                  </td>

                  <td className="py-2 px-3 text-slate-400 whitespace-nowrap">
                    {flow.flags || '-'}
                  </td>

                  <td className="py-2 px-3 font-sans">
                    <div className="flex items-center gap-2">
                      {flow.isSuspicious && (
                        <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                      )}
                      <span className="text-xs truncate max-w-md">{flow.info}</span>
                    </div>
                    {flow.anomalyReason && (
                      <div className="text-[11px] text-rose-400 font-mono mt-0.5">
                        motivo: {flow.anomalyReason}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
