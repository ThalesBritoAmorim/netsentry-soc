import React, { useState, useMemo } from 'react';
import { 
  ResponsiveContainer, 
  ScatterChart, 
  Scatter, 
  XAxis, 
  YAxis, 
  ZAxis, 
  Tooltip, 
  BarChart, 
  Bar, 
  CartesianGrid, 
  Legend 
} from 'recharts';
import { ThreatAlert, ThreatCategory } from '../types';
import { 
  Flame, 
  Clock, 
  ShieldAlert, 
  BarChart3, 
  Grid, 
  SlidersHorizontal,
  Info,
  Calendar,
  Zap,
  TrendingUp,
  AlertTriangle
} from 'lucide-react';

interface IncidentHeatmapChartProps {
  alerts: ThreatAlert[];
  onSelectCategory?: (category: ThreatCategory) => void;
}

// 6 blocos horários de 4 horas
const TIME_SLOTS_4H = [
  { id: '00-04', label: '00:00 - 04:00', shortLabel: '00-04h', name: 'Madrugada', start: 0, end: 4 },
  { id: '04-08', label: '04:00 - 08:00', shortLabel: '04-08h', name: 'Alvorecer', start: 4, end: 8 },
  { id: '08-12', label: '08:00 - 12:00', shortLabel: '08-12h', name: 'Manhã', start: 8, end: 12 },
  { id: '12-16', label: '12:00 - 16:00', shortLabel: '12-16h', name: 'Tarde', start: 12, end: 16 },
  { id: '16-20', label: '16:00 - 20:00', shortLabel: '16-20h', name: 'Entardecer', start: 16, end: 20 },
  { id: '20-24', label: '20:00 - 24:00', shortLabel: '20-24h', name: 'Noite', start: 20, end: 24 }
];

// 24 horas individuais
const TIME_SLOTS_24H = Array.from({ length: 24 }, (_, i) => {
  const hStr = i.toString().padStart(2, '0');
  return {
    id: `h-${i}`,
    label: `${hStr}:00 - ${hStr}:59`,
    shortLabel: `${hStr}h`,
    name: `${hStr}h`,
    start: i,
    end: i + 1
  };
});

// Metadados das categorias de ameaça
export const THREAT_CATEGORIES_META: {
  category: ThreatCategory;
  name: string;
  shortName: string;
  color: string;
  mitreCode: string;
  description: string;
}[] = [
  { 
    category: 'arp_poisoning', 
    name: 'ARP Poisoning / Spoofing', 
    shortName: 'ARP Spoof', 
    color: '#fbbf24', 
    mitreCode: 'T1557.002',
    description: 'Envenenamento de tabela ARP para sequestro de gateway e ataque MITM.'
  },
  { 
    category: 'port_scan', 
    name: 'Varredura de Portas (SYN Scan)', 
    shortName: 'SYN Scan', 
    color: '#38bdf8', 
    mitreCode: 'T1046',
    description: 'Reconnaissance furtivo com sondagem de portas em busca de vulnerabilidades.'
  },
  { 
    category: 'dns_tunneling', 
    name: 'Tunelamento DNS (Exfiltração)', 
    shortName: 'DNS Tunnel', 
    color: '#a855f7', 
    mitreCode: 'T1071.004',
    description: 'Canal encoberto de exfiltração de dados ou comando C2 sobre UDP 53.'
  },
  { 
    category: 'ddos_flood', 
    name: 'Surto de Tráfego / DDoS Flood', 
    shortName: 'DDoS Flood', 
    color: '#f43f5e', 
    mitreCode: 'T1498.001',
    description: 'Sobrecarga volumétrica de pacotes SYN/UDP para indisponibilizar serviços.'
  },
  { 
    category: 'rogue_device', 
    name: 'Dispositivo Rogue Desconhecido', 
    shortName: 'Rogue Device', 
    color: '#34d399', 
    mitreCode: 'T1200',
    description: 'MAC address não autorizado conectado na sub-rede sem credenciamento.'
  },
  { 
    category: 'brute_force', 
    name: 'Força Bruta de Credenciais', 
    shortName: 'Brute Force', 
    color: '#f97316', 
    mitreCode: 'T1110',
    description: 'Tentativas repetidas de autenticação em serviços SSH, SMB ou Telnet.'
  },
  { 
    category: 'c2_beaconing', 
    name: 'Beaconing C2 (Comando & Controle)', 
    shortName: 'C2 Beacon', 
    color: '#e879f9', 
    mitreCode: 'T1071',
    description: 'Comunicação periódica de malware com servidores de comando externos.'
  },
  { 
    category: 'anomalous_outbound', 
    name: 'Tráfego Outbound Anômalo', 
    shortName: 'Outbound Anômalo', 
    color: '#60a5fa', 
    mitreCode: 'T1048',
    description: 'Fluxo volumoso para portas não padronizadas ou IPs de alto risco.'
  }
];

// Extrai a hora (0-23) de timestamps em múltiplos formatos
function parseAlertHour(timestamp: string): number {
  const match = timestamp.match(/(\d{1,2}):(\d{2})/);
  if (match) {
    const hour = parseInt(match[1], 10);
    if (!isNaN(hour) && hour >= 0 && hour <= 23) return hour;
  }
  const dateObj = new Date(timestamp);
  if (!isNaN(dateObj.getTime())) {
    return dateObj.getHours();
  }
  return 12;
}

export const IncidentHeatmapChart: React.FC<IncidentHeatmapChartProps> = ({
  alerts,
  onSelectCategory
}) => {
  const [viewMode, setViewMode] = useState<'heatmap' | 'bars'>('heatmap');
  const [timeGranularity, setTimeGranularity] = useState<'4h' | '24h'>('4h');
  const [filterSeverity, setFilterSeverity] = useState<'all' | 'critical_high'>('all');

  // Filtragem de alertas
  const relevantAlerts = useMemo(() => {
    return alerts.filter(a => {
      if (filterSeverity === 'critical_high') {
        return a.severity === 'critical' || a.severity === 'high';
      }
      return true;
    });
  }, [alerts, filterSeverity]);

  const activeTimeSlots = timeGranularity === '4h' ? TIME_SLOTS_4H : TIME_SLOTS_24H;

  // Montagem da matriz de frequência [Categoria x Faixa Horária]
  const { matrixData, scatterData, barData, stats } = useMemo(() => {
    // Inicializar mapa de contagens: categoria -> slotId -> lista de alertas
    const countsMap = new Map<string, ThreatAlert[]>();
    THREAT_CATEGORIES_META.forEach(cat => {
      activeTimeSlots.forEach(slot => {
        countsMap.set(`${cat.category}:${slot.id}`, []);
      });
    });

    let totalCritical = 0;
    let totalHigh = 0;

    // Distribuir alertas nos slots
    relevantAlerts.forEach(alert => {
      const hour = parseAlertHour(alert.timestamp);
      const slot = activeTimeSlots.find(s => {
        if (s.start <= s.end) {
          return hour >= s.start && hour < s.end;
        }
        return hour >= s.start || hour < s.end;
      }) || activeTimeSlots[0];

      const key = `${alert.category}:${slot.id}`;
      if (countsMap.has(key)) {
        countsMap.get(key)!.push(alert);
      }

      if (alert.severity === 'critical') totalCritical++;
      if (alert.severity === 'high') totalHigh++;
    });

    // 100% REAL: Sem injeção de sementes fictícias ou incidentes sintéticos.
    // Todos os dados do mapa de calor são exclusivamente os incidentes reais da rede física.
    let maxVal = 1;
    const sData: any[] = [];
    const bData: any[] = activeTimeSlots.map(slot => ({
      slotId: slot.id,
      name: slot.shortLabel,
      fullName: slot.label,
      total: 0
    }));

    const categoryTotals: Record<string, number> = {};
    const slotTotals: Record<string, number> = {};

    THREAT_CATEGORIES_META.forEach((catMeta, catIdx) => {
      categoryTotals[catMeta.category] = 0;

      activeTimeSlots.forEach((slot, slotIdx) => {
        const key = `${catMeta.category}:${slot.id}`;
        const list = countsMap.get(key) || [];
        const count = list.length;

        if (count > maxVal) maxVal = count;

        categoryTotals[catMeta.category] += count;
        slotTotals[slot.id] = (slotTotals[slot.id] || 0) + count;

        // Atualiza barData
        const barSlot = bData.find(b => b.slotId === slot.id);
        if (barSlot) {
          barSlot[catMeta.category] = count;
          barSlot.total += count;
        }

        sData.push({
          x: slotIdx,
          y: catIdx,
          z: count,
          count,
          slotName: slot.label,
          slotShort: slot.shortLabel,
          category: catMeta.category,
          categoryName: catMeta.name,
          color: catMeta.color,
          mitre: catMeta.mitreCode,
          alertsCount: count,
          sampleAlert: list[0]
        });
      });
    });

    // Identificar padrões de ataque principais
    // Encontrar o slot com mais ataques
    let peakSlotId = activeTimeSlots[0].id;
    let peakSlotCount = -1;
    Object.entries(slotTotals).forEach(([sid, cnt]) => {
      if (cnt > peakSlotCount) {
        peakSlotCount = cnt;
        peakSlotId = sid;
      }
    });
    const peakSlotObj = activeTimeSlots.find(s => s.id === peakSlotId) || activeTimeSlots[0];

    // Encontrar categoria mais frequente
    let topCatKey: string = 'port_scan';
    let topCatCount = -1;
    Object.entries(categoryTotals).forEach(([cat, cnt]) => {
      if (cnt > topCatCount) {
        topCatCount = cnt;
        topCatKey = cat;
      }
    });
    const topCatObj = THREAT_CATEGORIES_META.find(c => c.category === topCatKey) || THREAT_CATEGORIES_META[0];

    const totalIncidents = Object.values(categoryTotals).reduce((a, b) => a + b, 0);

    // Diagnóstico Heurístico de Padrão
    let patternDiagnosis = 'Rede Nominal (Sem Incidentes)';
    let patternDescription = 'Nenhum incidente ou anomalia detectado na rede monitorada até o momento.';
    let recommendation = 'Manter o sensor de pacotes Scapy ativo no Kali Linux em modo promíscuo.';

    if (totalIncidents > 0) {
      if (peakSlotObj.start >= 0 && peakSlotObj.end <= 8) {
        patternDiagnosis = 'Campanha Noturna / Automação de Botnet';
        patternDescription = `Pico concentrado na ${peakSlotObj.name} (${peakSlotObj.label}) com ${peakSlotCount} incidentes. Típico de bots que atacam fora do horário comercial para evitar detecção imediata.`;
        recommendation = 'Habilitar rate-limit e drop de conexões SYN não autorizadas via iptables durante a madrugada.';
      } else if (topCatKey === 'ddos_flood' || topCatKey === 'port_scan') {
        patternDiagnosis = 'Varredura Agressiva & Tentativa de Evasão';
        patternDescription = `Alta incidência de ${topCatObj.name} detectada com padrão de rajada volumétrica.`;
        recommendation = 'Isolar o host de origem adicionando rota blackhole ou regra netfilter no kernel do Kali Linux.';
      } else {
        patternDiagnosis = 'Padrão Distribuído de Baixo Ruído';
        patternDescription = 'Incidentes espalhados ao longo do dia, típico de escaneamento externo intermitente.';
        recommendation = 'Mantenha o daemon autônomo monitorando o tráfego e execute varredura de sub-rede periódica.';
      }
    }

    return {
      matrixData: countsMap,
      scatterData: sData,
      barData: bData,
      stats: {
        totalIncidents: Object.values(categoryTotals).reduce((a, b) => a + b, 0),
        maxVal,
        peakSlot: peakSlotObj,
        peakCount: peakSlotCount,
        topCategory: topCatObj,
        topCategoryCount: topCatCount,
        patternDiagnosis,
        patternDescription,
        recommendation
      }
    };
  }, [relevantAlerts, activeTimeSlots]);

  // Função para gerar gradiente de cor térmica baseado no valor
  const getCellColor = (count: number, max: number, catColor: string) => {
    if (count === 0) return 'rgba(15, 23, 42, 0.6)'; // Vazio
    const ratio = Math.min(count / (max || 1), 1);
    if (ratio < 0.25) return 'rgba(56, 189, 248, 0.25)'; // Leve
    if (ratio < 0.5) return 'rgba(251, 191, 36, 0.45)';  // Moderado
    if (ratio < 0.75) return 'rgba(249, 115, 22, 0.7)';  // Intenso
    return 'rgba(244, 63, 94, 0.9)';                     // Crítico
  };

  return (
    <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
      {/* Top Header & Interactive Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-rose-950/80 border border-rose-800/80 text-rose-400">
              <Flame className="w-4 h-4" />
            </div>
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <span>Mapa de Calor de Incidentes & Padrões de Ataque</span>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                {stats.totalIncidents} Registros
              </span>
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Distribuição temporal de anomalias por faixa horária e vetor de ameaça para reconhecimento tático de padrões MITRE ATT&CK.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 flex-wrap self-start sm:self-auto">
          {/* 4h vs 24h Granularity */}
          <div className="flex items-center bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            <button
              onClick={() => setTimeGranularity('4h')}
              className={`px-2.5 py-1 rounded font-medium transition-colors ${
                timeGranularity === '4h' 
                  ? 'bg-cyan-500/20 text-cyan-300 font-semibold' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Agrupar em 6 faixas de 4 horas"
            >
              Blocos 4h
            </button>
            <button
              onClick={() => setTimeGranularity('24h')}
              className={`px-2.5 py-1 rounded font-medium transition-colors ${
                timeGranularity === '24h' 
                  ? 'bg-cyan-500/20 text-cyan-300 font-semibold' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Visualizar todas as 24 horas individuais"
            >
              24 Horas
            </button>
          </div>

          {/* Heatmap Matrix vs Stacked Bar Chart */}
          <div className="flex items-center bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            <button
              onClick={() => setViewMode('heatmap')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded font-medium transition-colors ${
                viewMode === 'heatmap' 
                  ? 'bg-slate-800 text-slate-100 font-semibold' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Grid className="w-3.5 h-3.5" />
              <span>Matriz</span>
            </button>
            <button
              onClick={() => setViewMode('bars')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded font-medium transition-colors ${
                viewMode === 'bars' 
                  ? 'bg-slate-800 text-slate-100 font-semibold' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <BarChart3 className="w-3.5 h-3.5" />
              <span>Barras</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Chart Canvas */}
      {viewMode === 'heatmap' ? (
        <div className="space-y-3">
          {/* Matriz Térmica Renderizada com Grade Interativa & Tooltips */}
          <div className="overflow-x-auto pb-2">
            <div className="min-w-[620px]">
              {/* Header com Faixas Horárias */}
              <div className="grid gap-1 mb-1.5" style={{
                gridTemplateColumns: `140px repeat(${activeTimeSlots.length}, minmax(0, 1fr))`
              }}>
                <div className="text-[11px] font-mono text-slate-500 font-semibold flex items-center gap-1">
                  <Clock className="w-3 h-3 text-cyan-400" />
                  <span>VETOR / HORA</span>
                </div>
                {activeTimeSlots.map((slot) => (
                  <div key={slot.id} className="text-center font-mono text-[10px] text-slate-400 px-1 truncate">
                    <span className="font-semibold block text-slate-300">{slot.shortLabel}</span>
                    <span className="text-[9px] text-slate-500 hidden sm:inline">{slot.name}</span>
                  </div>
                ))}
              </div>

              {/* Linhas da Matriz (Categorias) */}
              <div className="space-y-1.5">
                {THREAT_CATEGORIES_META.map((cat) => (
                  <div 
                    key={cat.category}
                    className="grid gap-1 items-center group hover:bg-slate-950/40 p-0.5 rounded transition-colors"
                    style={{
                      gridTemplateColumns: `140px repeat(${activeTimeSlots.length}, minmax(0, 1fr))`
                    }}
                  >
                    {/* Rótulo da Categoria */}
                    <div 
                      onClick={() => onSelectCategory && onSelectCategory(cat.category)}
                      className="cursor-pointer truncate pr-2 text-left"
                      title={`${cat.name} (${cat.mitreCode}) - Clique para filtrar`}
                    >
                      <div className="flex items-center gap-1.5">
                        <span 
                          className="w-2 h-2 rounded-full shrink-0" 
                          style={{ backgroundColor: cat.color }} 
                        />
                        <span className="text-xs font-medium text-slate-200 truncate group-hover:text-cyan-300 transition-colors">
                          {cat.shortName}
                        </span>
                      </div>
                      <span className="text-[9px] font-mono text-slate-500 block truncate">
                        {cat.mitreCode}
                      </span>
                    </div>

                    {/* Células de Calor */}
                    {activeTimeSlots.map((slot) => {
                      const count = matrixData.get(`${cat.category}:${slot.id}`)?.length || 0;
                      const intensityColor = getCellColor(count, stats.maxVal, cat.color);

                      return (
                        <div
                          key={`${cat.category}-${slot.id}`}
                          className="h-8 rounded flex items-center justify-center font-mono text-[11px] font-bold border transition-all duration-150 relative group/cell cursor-pointer"
                          style={{
                            backgroundColor: intensityColor,
                            borderColor: count > 0 ? 'rgba(255, 255, 255, 0.12)' : 'rgba(30, 41, 59, 0.6)',
                            color: count > 0 ? '#ffffff' : '#475569'
                          }}
                        >
                          <span>{count > 0 ? count : '·'}</span>

                          {/* Hover Tooltip flutuante detalhado */}
                          <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover/cell:flex flex-col z-50 w-52 p-2.5 rounded-lg bg-slate-950 border border-slate-700 shadow-xl pointer-events-none text-left">
                            <div className="flex items-center justify-between text-xs font-semibold text-slate-100">
                              <span className="truncate">{cat.name}</span>
                              <span className="font-mono text-cyan-400">{count} evento(s)</span>
                            </div>
                            <div className="text-[10px] text-slate-400 mt-1 font-mono">
                              Faixa: <strong className="text-slate-200">{slot.label}</strong>
                            </div>
                            <div className="text-[10px] text-slate-400 font-mono">
                              MITRE: <strong className="text-indigo-400">{cat.mitreCode}</strong>
                            </div>
                            <p className="text-[10px] text-slate-300 mt-1 leading-snug">
                              {count > 0 
                                ? `${count} incidentes flagrados pelo sniffer Scapy nesta janela horária.` 
                                : 'Nenhum incidente registrado nesta faixa horária.'}
                            </p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Escala Térmica de Referência */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-xs text-slate-400">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono">Intensidade:</span>
              <div className="flex items-center gap-1.5 text-[10px] font-mono">
                <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-500">0 Nulo</span>
                <span className="px-1.5 py-0.5 rounded bg-cyan-950/60 border border-cyan-800 text-cyan-300">1-3 Leve</span>
                <span className="px-1.5 py-0.5 rounded bg-amber-950/60 border border-amber-800 text-amber-300">4-6 Moderado</span>
                <span className="px-1.5 py-0.5 rounded bg-rose-950/80 border border-rose-800 text-rose-300">7+ Crítico</span>
              </div>
            </div>

            <span className="text-[11px] font-mono text-slate-500">
              Pico Máximo na Matriz: <strong className="text-rose-400">{stats.maxVal} ataques/janela</strong>
            </span>
          </div>
        </div>
      ) : (
        /* Visão Alternativa Recharts: Gráfico de Barras Empilhadas por Faixa Horária */
        <div className="h-[280px] w-full pt-2">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={barData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis 
                dataKey="name" 
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
                allowDecimals={false}
              />
              <Tooltip 
                content={({ active, payload, label }) => {
                  if (!active || !payload || !payload.length) return null;
                  const slotItem = barData.find(b => b.name === label);
                  return (
                    <div className="p-3 bg-slate-950/95 border border-slate-800 rounded-lg shadow-xl text-xs space-y-1.5 max-w-xs">
                      <div className="font-semibold text-slate-100 flex items-center justify-between">
                        <span>{slotItem?.fullName || label}</span>
                        <span className="font-mono text-cyan-400 font-bold">{slotItem?.total || 0} ataques</span>
                      </div>
                      <div className="space-y-1 pt-1 border-t border-slate-800">
                        {payload.map((entry: any) => {
                          if (!entry.value) return null;
                          const catMeta = THREAT_CATEGORIES_META.find(c => c.category === entry.dataKey);
                          return (
                            <div key={entry.dataKey} className="flex items-center justify-between text-[11px]">
                              <span className="flex items-center gap-1.5 text-slate-300">
                                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }} />
                                {catMeta?.shortName || entry.name}:
                              </span>
                              <span className="font-mono font-semibold text-slate-100">{entry.value}</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                }}
              />
              <Legend 
                wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }}
                iconType="circle"
              />
              {THREAT_CATEGORIES_META.map((cat) => (
                <Bar 
                  key={cat.category} 
                  dataKey={cat.category} 
                  name={cat.shortName} 
                  stackId="threats" 
                  fill={cat.color} 
                  radius={[0, 0, 0, 0]}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Threat Pattern Intelligence Card (Identificação de Padrões de Ataque) */}
      <div className="p-3 bg-slate-950 rounded-lg border border-slate-800/80 space-y-2">
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-slate-200 flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>Padrão Tático Identificado: <strong className="text-cyan-400">{stats.patternDiagnosis}</strong></span>
          </span>
          <span className="text-[11px] font-mono text-rose-400 font-semibold">
            Janela Crítica: {stats.peakSlot.label}
          </span>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          {stats.patternDescription} {stats.totalIncidents > 0 && (
            <>Vetor predominante: <strong className="text-slate-200">{stats.topCategory.name}</strong> ({stats.topCategoryCount} ocorrências).</>
          )}
        </p>

        <div className="p-2 rounded bg-slate-900 border border-slate-800 text-[11px] text-emerald-300 font-mono flex items-center gap-2">
          <ShieldAlert className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
          <span>Mitigação Recomendada: {stats.recommendation}</span>
        </div>
      </div>
    </div>
  );
};
