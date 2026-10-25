import React, { useState } from 'react';
import { AnalysisParameters } from '../types';
import { parametersService, DEFAULT_ANALYSIS_PARAMETERS } from '../services/parametersService';
import { soundAlertService } from '../services/soundAlertService';
import { 
  Sliders, 
  Shield, 
  Filter, 
  Cpu, 
  Zap, 
  Plus, 
  Trash2, 
  RotateCcw, 
  Save, 
  Download, 
  CheckCircle2, 
  AlertTriangle,
  Lock,
  Layers,
  Terminal,
  Volume2,
  Bell
} from 'lucide-react';

interface AnalysisParametersViewProps {
  onToast: (msg: string, type: 'success' | 'alert') => void;
  onOpenKaliTerminal?: (cmd: string) => void;
}

export const AnalysisParametersView: React.FC<AnalysisParametersViewProps> = ({
  onToast,
  onOpenKaliTerminal
}) => {
  const [params, setParams] = useState<AnalysisParameters>(parametersService.get());
  const [newIp, setNewIp] = useState('');
  const [newPort, setNewPort] = useState('');
  const [newSubnet, setNewSubnet] = useState('');
  const [isSaved, setIsSaved] = useState(false);

  const handleSave = () => {
    parametersService.save(params);
    setIsSaved(true);
    setTimeout(() => setIsSaved(false), 2500);
    onToast('Parâmetros de análise e filtros atualizados com sucesso no motor SOC!', 'success');
  };

  const handleReset = () => {
    const res = parametersService.reset();
    setParams(res);
    onToast('Parâmetros restaurados para os valores padrão de fábrica.', 'alert');
  };

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(params, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', 'netsentry-kali-parameters.json');
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    onToast('Arquivo netsentry-kali-parameters.json exportado com sucesso!', 'success');
  };

  const handleAddIp = () => {
    const trimmed = newIp.trim();
    if (!trimmed) return;
    if (params.whitelistedIps.includes(trimmed)) {
      onToast('Este IP já está na lista branca.', 'alert');
      return;
    }
    setParams({
      ...params,
      whitelistedIps: [...params.whitelistedIps, trimmed]
    });
    setNewIp('');
  };

  const handleRemoveIp = (ipToRemove: string) => {
    setParams({
      ...params,
      whitelistedIps: params.whitelistedIps.filter(ip => ip !== ipToRemove)
    });
  };

  const handleAddPort = () => {
    const p = parseInt(newPort.trim(), 10);
    if (isNaN(p) || p <= 0 || p > 65535) {
      onToast('Porta inválida (deve estar entre 1 e 65535).', 'alert');
      return;
    }
    if (params.protectedPorts.includes(p)) {
      onToast('Esta porta já está protegida.', 'alert');
      return;
    }
    setParams({
      ...params,
      protectedPorts: [...params.protectedPorts, p].sort((a, b) => a - b)
    });
    setNewPort('');
  };

  const handleRemovePort = (portToRemove: number) => {
    setParams({
      ...params,
      protectedPorts: params.protectedPorts.filter(p => p !== portToRemove)
    });
  };

  const handleAddSubnet = () => {
    const trimmed = newSubnet.trim();
    if (!trimmed) return;
    if (params.monitoredSubnets.includes(trimmed)) {
      onToast('Esta sub-rede já está monitorada.', 'alert');
      return;
    }
    setParams({
      ...params,
      monitoredSubnets: [...params.monitoredSubnets, trimmed]
    });
    setNewSubnet('');
  };

  const handleRemoveSubnet = (subnetToRemove: string) => {
    setParams({
      ...params,
      monitoredSubnets: params.monitoredSubnets.filter(s => s !== subnetToRemove)
    });
  };

  return (
    <div className="space-y-6">
      {/* 1. Header Banner */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xl">
        <div className="flex items-start sm:items-center gap-3.5">
          <div className="p-3 rounded-xl bg-cyan-950/80 border border-cyan-800 text-cyan-400 shrink-0">
            <Sliders className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h2 className="text-base sm:text-lg font-bold text-slate-100">
                Configuração de Parâmetros de Análise & Filtros SOC
              </h2>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-full border bg-cyan-950 text-cyan-300 border-cyan-800">
                Kernel Netfilter / Scapy / Gemini
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
              Ajuste fino dos limiares matemáticos de detecção de anomalias, whitelists de IPs/portas essenciais, diretrizes do motor forense de IA e políticas de auto-mitigação no Kali Linux.
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 shrink-0 flex-wrap">
          <button
            onClick={handleExportJson}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 hover:bg-slate-800 text-xs font-medium text-slate-300 transition-colors"
            title="Exportar configuração em JSON para o Kali Linux"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Exportar JSON</span>
          </button>
          <button
            onClick={handleReset}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 hover:bg-slate-800 text-xs font-medium text-slate-300 transition-colors"
            title="Restaurar valores de fábrica"
          >
            <RotateCcw className="w-3.5 h-3.5 text-amber-400" />
            <span>Padrões</span>
          </button>
          <button
            onClick={handleSave}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-400 hover:bg-cyan-300 text-slate-950 text-xs font-semibold shadow-md transition-all active:scale-95"
          >
            {isSaved ? <CheckCircle2 className="w-4 h-4 text-slate-950" /> : <Save className="w-4 h-4 fill-slate-950" />}
            <span>{isSaved ? 'Salvo no Motor!' : 'Salvar Alterações'}</span>
          </button>
        </div>
      </div>

      {/* 2. Grid of Parameters */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 items-start">
        {/* Section 1: Anomaly Detection Thresholds */}
        <div className="p-4 sm:p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4 shadow-lg">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <Zap className="w-4 h-4 text-cyan-400" />
              <span>Limiares de Detecção de Anomalias</span>
            </div>
            <span className="text-[11px] font-mono text-slate-500">Heurística & Shannon</span>
          </div>

          <div className="space-y-4 text-xs">
            {/* PPS Flood Threshold */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="font-medium text-slate-200">
                  Gatilho de Alerta de DDoS / SYN Flood (PPS):
                </label>
                <span className="font-mono text-cyan-400 font-bold text-xs bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                  {params.ppsFloodThreshold} PPS
                </span>
              </div>
              <input
                type="range"
                min="100"
                max="3000"
                step="50"
                value={params.ppsFloodThreshold}
                onChange={(e) => setParams({ ...params, ppsFloodThreshold: Number(e.target.value) })}
                className="w-full accent-cyan-400 bg-slate-950 h-1.5 rounded-lg appearance-none cursor-pointer"
              />
              <p className="text-[11px] text-slate-400">
                Dispara alarme no SOC quando o volume de pacotes por segundo na interface ultrapassar este limite.
              </p>
            </div>

            {/* Port Scan Rate */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="font-medium text-slate-200">
                  Taxa de Varredura de Portas (Port Scan):
                </label>
                <span className="font-mono text-cyan-400 font-bold text-xs bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                  {params.portScanThreshold} portas/seg
                </span>
              </div>
              <input
                type="range"
                min="5"
                max="50"
                step="1"
                value={params.portScanThreshold}
                onChange={(e) => setParams({ ...params, portScanThreshold: Number(e.target.value) })}
                className="w-full accent-cyan-400 bg-slate-950 h-1.5 rounded-lg appearance-none cursor-pointer"
              />
              <p className="text-[11px] text-slate-400">
                Quantidade de portas TCP distintas sondadas sem completar o handshake antes de classificar como varredura Nmap.
              </p>
            </div>

            {/* Shannon Entropy Threshold */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="font-medium text-slate-200">
                  Entropia de Shannon para Tunelamento DNS:
                </label>
                <span className="font-mono text-purple-400 font-bold text-xs bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                  {params.dnsEntropyThreshold.toFixed(2)} bits
                </span>
              </div>
              <input
                type="range"
                min="2.5"
                max="5.0"
                step="0.05"
                value={params.dnsEntropyThreshold}
                onChange={(e) => setParams({ ...params, dnsEntropyThreshold: Number(e.target.value) })}
                className="w-full accent-purple-400 bg-slate-950 h-1.5 rounded-lg appearance-none cursor-pointer"
              />
              <p className="text-[11px] text-slate-400">
                Subdomínios de consultas DNS com entropia superior a este índice indicam dados codificados em Base64/Hex (Exfiltração C2).
              </p>
            </div>

            {/* ARP Spoofing Sensitivity */}
            <div className="space-y-1.5">
              <label className="font-medium text-slate-200 block">
                Sensibilidade de Verificação ARP Spoofing:
              </label>
              <div className="grid grid-cols-3 gap-2">
                {[
                  { id: 'strict', label: 'Estrita (Zero Tolerância)' },
                  { id: 'moderate', label: 'Moderada (2-3 pacotes)' },
                  { id: 'permissive', label: 'Permissiva (Broadcast)' }
                ].map(opt => (
                  <button
                    key={opt.id}
                    onClick={() => setParams({ ...params, arpSpoofSensitivity: opt.id as any })}
                    className={`py-1.5 px-2 rounded-lg text-center font-medium transition-all ${
                      params.arpSpoofSensitivity === opt.id
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 font-semibold'
                        : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Section 2: Whitelist & Protected Assets */}
        <div className="p-4 sm:p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4 shadow-lg">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <Shield className="w-4 h-4 text-emerald-400" />
              <span>Lista Branca & Ativos Protegidos</span>
            </div>
            <span className="text-[11px] font-mono text-slate-500">Isenção de Bloqueio</span>
          </div>

          <div className="space-y-4 text-xs">
            {/* Whitelisted IPs */}
            <div className="space-y-2">
              <label className="font-medium text-slate-200 block">
                IPs Confiáveis / Whitelist (Nunca Serão Bloqueados no Firewall):
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={newIp}
                  onChange={(e) => setNewIp(e.target.value)}
                  placeholder="Ex: 192.168.1.50 ou 10.0.0.1"
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={handleAddIp}
                  className="px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs flex items-center gap-1 transition-colors shrink-0"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Adicionar</span>
                </button>
              </div>
              <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto p-1.5 bg-slate-950 rounded-lg border border-slate-800/80">
                {params.whitelistedIps.map(ip => (
                  <span
                    key={ip}
                    className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-emerald-300"
                  >
                    <span>{ip}</span>
                    <button
                      onClick={() => handleRemoveIp(ip)}
                      className="text-slate-500 hover:text-rose-400 transition-colors"
                      title="Remover da lista branca"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </span>
                ))}
              </div>
            </div>

            {/* Protected Ports */}
            <div className="space-y-2">
              <label className="font-medium text-slate-200 block">
                Portas de Serviço Críticas (Isentas de Bloqueio Automático):
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  value={newPort}
                  onChange={(e) => setNewPort(e.target.value)}
                  placeholder="Ex: 22 (SSH), 3000 (Web), 5432 (Postgres)"
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={handleAddPort}
                  className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs flex items-center gap-1 transition-colors shrink-0"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Adicionar</span>
                </button>
              </div>
              <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto p-1.5 bg-slate-950 rounded-lg border border-slate-800/80">
                {params.protectedPorts.map(port => (
                  <span
                    key={port}
                    className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-cyan-300"
                  >
                    <span>TCP/UDP {port}</span>
                    <button
                      onClick={() => handleRemovePort(port)}
                      className="text-slate-500 hover:text-rose-400 transition-colors"
                      title="Remover porta"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </span>
                ))}
              </div>
            </div>

            {/* Monitored Subnets */}
            <div className="space-y-2">
              <label className="font-medium text-slate-200 block">
                Sub-redes Locais CIDR Sob Vigilância:
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={newSubnet}
                  onChange={(e) => setNewSubnet(e.target.value)}
                  placeholder="Ex: 192.168.1.0/24 ou 10.0.0.0/24"
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={handleAddSubnet}
                  className="px-3 py-1.5 rounded-lg bg-indigo-500 hover:bg-indigo-400 text-slate-950 font-semibold text-xs flex items-center gap-1 transition-colors shrink-0"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Adicionar</span>
                </button>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {params.monitoredSubnets.map(sub => (
                  <span
                    key={sub}
                    className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-indigo-300"
                  >
                    <span>{sub}</span>
                    <button
                      onClick={() => handleRemoveSubnet(sub)}
                      className="text-slate-500 hover:text-rose-400 transition-colors"
                      title="Remover sub-rede"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Section 3: AI Forensic Engine Configuration */}
        <div className="p-4 sm:p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4 shadow-lg">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span>Diretrizes do Motor Forense de IA (Gemini / Ollama)</span>
            </div>
            <span className="text-[11px] font-mono text-slate-500">Engenharia de Prompt</span>
          </div>

          <div className="space-y-4 text-xs">
            {/* Forensic Detail Level */}
            <div className="space-y-1.5">
              <label className="font-medium text-slate-200 block">
                Profundidade do Relatório Forense:
              </label>
              <div className="grid grid-cols-3 gap-2">
                {[
                  { id: 'summary', label: 'Resumo Executivo', desc: 'Objetivo e direto' },
                  { id: 'standard', label: 'Analista Pleno', desc: 'Impacto e vetores' },
                  { id: 'deep_forensic', label: 'Forense Profundo', desc: 'Pacotes e Netfilter' }
                ].map(opt => (
                  <button
                    key={opt.id}
                    onClick={() => setParams({ ...params, forensicDetailLevel: opt.id as any })}
                    className={`p-2 rounded-lg text-left transition-all ${
                      params.forensicDetailLevel === opt.id
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 font-semibold'
                        : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    <span className="font-bold block text-xs">{opt.label}</span>
                    <span className="text-[10px] text-slate-500 block mt-0.5">{opt.desc}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Target Iptables Action Rule */}
            <div className="space-y-1.5">
              <label className="font-medium text-slate-200 block">
                Alvo de Descarte no Netfilter (Ação Iptables):
              </label>
              <div className="grid grid-cols-3 gap-2">
                {[
                  { id: 'drop', label: 'DROP (Silencioso)', desc: 'Descarte sem resposta ICMP' },
                  { id: 'reject', label: 'REJECT (Explícito)', desc: 'Envia ICMP port unreachable' },
                  { id: 'tarpit', label: 'TARPIT (Slowdown)', desc: 'Prende conexão do atacante' }
                ].map(opt => (
                  <button
                    key={opt.id}
                    onClick={() => setParams({ ...params, iptablesRuleType: opt.id as any })}
                    className={`p-2 rounded-lg text-left transition-all ${
                      params.iptablesRuleType === opt.id
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 font-semibold'
                        : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    <span className="font-bold block text-xs">{opt.label}</span>
                    <span className="text-[10px] text-slate-500 block mt-0.5">{opt.desc}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Prioritize MITRE & Auto Anonymize Toggles */}
            <div className="space-y-2 pt-1">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-3">
                <div>
                  <span className="font-semibold text-slate-200 block">Priorizar Classificação MITRE ATT&CK</span>
                  <span className="text-[11px] text-slate-400">
                    Obriga a IA a correlacionar a anomalia a uma tática/técnica da matriz corporativa (ex: T1557, T1046).
                  </span>
                </div>
                <button
                  onClick={() => setParams({ ...params, prioritizeMitre: !params.prioritizeMitre })}
                  className={`w-10 h-5 rounded-full transition-colors relative shrink-0 ${
                    params.prioritizeMitre ? 'bg-cyan-500' : 'bg-slate-800'
                  }`}
                >
                  <span className={`w-3.5 h-3.5 rounded-full bg-white absolute top-0.5 transition-transform ${
                    params.prioritizeMitre ? 'right-0.5' : 'left-0.5'
                  }`} />
                </button>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-3">
                <div>
                  <span className="font-semibold text-slate-200 block">Anonimização Automática da Topologia de Rede</span>
                  <span className="text-[11px] text-slate-400">
                    Mascaramento de IPs da sub-rede local e MACs de placas de rede antes de consultar a API Gemini.
                  </span>
                </div>
                <button
                  onClick={() => setParams({ ...params, autoAnonymizeTopology: !params.autoAnonymizeTopology })}
                  className={`w-10 h-5 rounded-full transition-colors relative shrink-0 ${
                    params.autoAnonymizeTopology ? 'bg-cyan-500' : 'bg-slate-800'
                  }`}
                >
                  <span className={`w-3.5 h-3.5 rounded-full bg-white absolute top-0.5 transition-transform ${
                    params.autoAnonymizeTopology ? 'right-0.5' : 'left-0.5'
                  }`} />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Section 4: Autonomous Response & Mitigation Policy */}
        <div className="p-4 sm:p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4 shadow-lg">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <Zap className="w-4 h-4 text-emerald-400" />
              <span>Políticas de Mitigação Autônoma & TTL do Kernel</span>
            </div>
            <span className="text-[11px] font-mono text-slate-500">Iptables & Netfilter</span>
          </div>

          <div className="space-y-4 text-xs">
            {/* Auto block high severity */}
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-3">
              <div>
                <span className="font-semibold text-slate-200 block">Auto-Bloqueio Imediato para Ameaças Críticas</span>
                <span className="text-[11px] text-slate-400">
                  Quando ativo, incidentes com confiança &gt;95% (ex: ARP Spoofing) são inseridos automaticamente no iptables do kernel.
                </span>
              </div>
              <button
                onClick={() => setParams({ ...params, autoBlockHighSeverity: !params.autoBlockHighSeverity })}
                className={`w-10 h-5 rounded-full transition-colors relative shrink-0 ${
                  params.autoBlockHighSeverity ? 'bg-emerald-500' : 'bg-slate-800'
                }`}
              >
                <span className={`w-3.5 h-3.5 rounded-full bg-white absolute top-0.5 transition-transform ${
                  params.autoBlockHighSeverity ? 'right-0.5' : 'left-0.5'
                }`} />
              </button>
            </div>

            {/* Block TTL Selection */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="font-medium text-slate-200">
                  Tempo de Expiração do Bloqueio (TTL no Netfilter):
                </label>
                <span className="font-mono text-emerald-400 font-bold text-xs bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                  {params.blockTtlMinutes === 0 ? 'Permanente (Sem TTL)' : `${params.blockTtlMinutes} minutos`}
                </span>
              </div>
              <div className="grid grid-cols-4 gap-2">
                {[
                  { val: 15, label: '15 min' },
                  { val: 60, label: '1 hora' },
                  { val: 240, label: '4 horas' },
                  { val: 0, label: 'Permanente' }
                ].map(opt => (
                  <button
                    key={opt.val}
                    onClick={() => setParams({ ...params, blockTtlMinutes: opt.val })}
                    className={`py-1.5 rounded-lg text-center font-medium transition-all ${
                      params.blockTtlMinutes === opt.val
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50 font-semibold'
                        : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
              <p className="text-[11px] text-slate-400">
                O daemon do NetSentry remove automaticamente as regras do iptables após este tempo para evitar acúmulo desnecessário.
              </p>
            </div>

            {/* Notification and alert modes */}
            <div className="space-y-2 pt-1">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Bell className="w-4 h-4 text-cyan-400 shrink-0" />
                  <div>
                    <span className="font-semibold text-slate-200 block">Banners & Toasts de Notificação</span>
                    <span className="text-[11px] text-slate-400">
                      Exibir avisos visuais no canto inferior da tela do SOC ao detectar anomalias.
                    </span>
                  </div>
                </div>
                <button
                  onClick={() => setParams({ ...params, enableDesktopBanners: !params.enableDesktopBanners })}
                  className={`w-10 h-5 rounded-full transition-colors relative shrink-0 ${
                    params.enableDesktopBanners ? 'bg-cyan-500' : 'bg-slate-800'
                  }`}
                >
                  <span className={`w-3.5 h-3.5 rounded-full bg-white absolute top-0.5 transition-transform ${
                    params.enableDesktopBanners ? 'right-0.5' : 'left-0.5'
                  }`} />
                </button>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <Volume2 className="w-4 h-4 text-indigo-400 shrink-0" />
                    <div>
                      <span className="font-semibold text-slate-200 block">Sinal Sonoro de Alerta Crítico (Web Audio SOC)</span>
                      <span className="text-[11px] text-slate-400">
                        Sintetiza sirene tática no navegador quando anomalias de severidade alta/crítica ou picos de tráfego ocorrem.
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      const next = !params.enableAudioAlerts;
                      setParams({ ...params, enableAudioAlerts: next });
                      soundAlertService.setMuted(!next);
                      if (next) {
                        soundAlertService.testSound('warning');
                        onToast('Alertas sonoros ativados no navegador!', 'success');
                      } else {
                        onToast('Alertas sonoros desativados.', 'alert');
                      }
                    }}
                    className={`w-10 h-5 rounded-full transition-colors relative shrink-0 ${
                      params.enableAudioAlerts ? 'bg-indigo-500' : 'bg-slate-800'
                    }`}
                  >
                    <span className={`w-3.5 h-3.5 rounded-full bg-white absolute top-0.5 transition-transform ${
                      params.enableAudioAlerts ? 'right-0.5' : 'left-0.5'
                    }`} />
                  </button>
                </div>

                {/* Tactical Audio Test Controls */}
                <div className="pt-2 border-t border-slate-900 flex items-center justify-between flex-wrap gap-2 text-xs">
                  <span className="text-slate-400 font-mono text-[11px]">Testar Efeitos Sonoros do SOC:</span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => {
                        soundAlertService.testSound('critical');
                        onToast('Reproduzindo sirene crítica...', 'alert');
                      }}
                      className="px-2.5 py-1 rounded bg-rose-950/70 text-rose-300 border border-rose-800/80 hover:bg-rose-900 transition-colors text-[11px] font-mono"
                    >
                      Sirene Crítica
                    </button>
                    <button
                      onClick={() => {
                        soundAlertService.testSound('warning');
                        onToast('Reproduzindo bip de alerta...', 'alert');
                      }}
                      className="px-2.5 py-1 rounded bg-amber-950/70 text-amber-300 border border-amber-800/80 hover:bg-amber-900 transition-colors text-[11px] font-mono"
                    >
                      Alerta Bip
                    </button>
                    <button
                      onClick={() => {
                        soundAlertService.testSound('success');
                        onToast('Reproduzindo confirmação de mitigação...', 'success');
                      }}
                      className="px-2.5 py-1 rounded bg-emerald-950/70 text-emerald-300 border border-emerald-800/80 hover:bg-emerald-900 transition-colors text-[11px] font-mono"
                    >
                      Chime Sucesso
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
