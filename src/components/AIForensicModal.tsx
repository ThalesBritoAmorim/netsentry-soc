import React, { useState, useEffect } from 'react';
import { 
  Sparkles, 
  ShieldAlert, 
  Terminal, 
  Play, 
  Copy, 
  Check, 
  X, 
  RefreshCw, 
  Activity, 
  ShieldCheck, 
  Cpu, 
  ExternalLink,
  Volume2,
  VolumeX,
  Layers,
  ArrowRight,
  AlertTriangle
} from 'lucide-react';
import { aiService } from '../services/aiService';
import { soundAlertService } from '../services/soundAlertService';
import { ThreatAlert, NetworkDevice, TrafficFlow, SystemMetrics } from '../types';

export type AIForensicTargetType = 'threat' | 'device' | 'flow' | 'spike' | 'posture';

interface AIForensicModalProps {
  isOpen: boolean;
  onClose: () => void;
  targetType: AIForensicTargetType;
  targetData?: ThreatAlert | NetworkDevice | TrafficFlow | any;
  metrics?: SystemMetrics;
  devices?: NetworkDevice[];
  onOpenKaliTerminal?: (cmd: string) => void;
  onApplyMitigation?: (alertId: string) => void;
  onToast?: (msg: string, type: 'success' | 'alert') => void;
}

export const AIForensicModal: React.FC<AIForensicModalProps> = ({
  isOpen,
  onClose,
  targetType,
  targetData,
  metrics,
  devices,
  onOpenKaliTerminal,
  onApplyMitigation,
  onToast
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [result, setResult] = useState<{
    analysis: string;
    riskLevel: string;
    mitreTechnique: string;
    validatedIptablesCommand: string;
    recommendedActions: string[];
    providerUsed: string;
    modelUsed: string;
    isAirGapped: boolean;
  } | null>(null);

  const [soundMuted, setSoundMuted] = useState(soundAlertService.isMuted());

  useEffect(() => {
    return soundAlertService.onMuteChange(setSoundMuted);
  }, []);

  const runAnalysis = async () => {
    setIsLoading(true);
    try {
      let res;
      if (targetType === 'threat' && targetData) {
        res = await aiService.analyzeThreat(targetData, metrics, devices);
      } else if (targetType === 'device' && targetData) {
        res = await aiService.analyzeDevice(targetData, devices);
      } else if (targetType === 'flow' && targetData) {
        res = await aiService.analyzeFlow(targetData, metrics);
      } else if (targetType === 'spike' && targetData) {
        res = await aiService.analyzeSpike(targetData, metrics);
      } else {
        res = await aiService.analyzeNetworkPosture(metrics, devices || []);
      }
      setResult(res);
    } catch (e: any) {
      console.error('Erro na análise forense IA:', e);
      onToast?.('Falha ao processar diagnóstico com IA', 'alert');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      runAnalysis();
    } else {
      setResult(null);
    }
  }, [isOpen, targetType, targetData?.id, targetData?.ip]);

  if (!isOpen) return null;

  const handleCopyCommand = () => {
    if (!result?.validatedIptablesCommand) return;
    navigator.clipboard.writeText(result.validatedIptablesCommand);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    onToast?.('Comando copiado para a área de transferência!', 'success');
  };

  const handleExecuteInTerminal = () => {
    if (!result?.validatedIptablesCommand) return;
    if (onOpenKaliTerminal) {
      onOpenKaliTerminal(result.validatedIptablesCommand);
      onToast?.('Comando enviado diretamente para o terminal do Kali Linux!', 'success');
      onClose();
    }
  };

  const getTargetTitle = () => {
    switch (targetType) {
      case 'threat':
        return `Diagnóstico de Ameaça: ${targetData?.title || 'Incidente Crítico'}`;
      case 'device':
        return `Auditoria Forense de Host: ${targetData?.hostname || targetData?.ip || 'Dispositivo'}`;
      case 'flow':
        return `Inspeção Forense de Pacote: ${targetData?.protocol || 'TCP/IP'} (${targetData?.srcIp || 'Origem'})`;
      case 'spike':
        return `Análise de Surto de Tráfego: ${targetData?.bps ? `${(targetData.bps / 1_000_000).toFixed(2)} Mbps` : 'Pico Detectado'}`;
      case 'posture':
        return 'Auditoria Global de Postura de Rede & Tráfego';
    }
  };

  const getRiskBadgeColor = (risk: string) => {
    const r = (risk || '').toUpperCase();
    if (r.includes('CRÍTICO') || r.includes('CRITICAL')) {
      return 'bg-rose-950/80 text-rose-300 border-rose-700';
    }
    if (r.includes('ALTO') || r.includes('HIGH')) {
      return 'bg-amber-950/80 text-amber-300 border-amber-700';
    }
    if (r.includes('MÉDIO') || r.includes('MEDIUM')) {
      return 'bg-yellow-950/80 text-yellow-300 border-yellow-700';
    }
    return 'bg-emerald-950/80 text-emerald-300 border-emerald-700';
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-5 overflow-y-auto">
      <div 
        className="w-full max-w-3xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col my-auto max-h-[90vh] animate-in fade-in zoom-in-95 duration-150"
        role="dialog"
        aria-modal="true"
      >
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 bg-slate-950/70 flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <div className="w-10 h-10 rounded-xl bg-cyan-950/90 border border-cyan-700 flex items-center justify-center text-cyan-400 shrink-0 shadow-lg shadow-cyan-950/50">
              <Sparkles className="w-5 h-5 animate-pulse" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400 font-bold">
                  Motor Forense NetSentry IA
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  {result?.modelUsed || 'gemini-3.8-flash'}
                </span>
              </div>
              <h3 className="text-base font-bold text-slate-100 truncate mt-0.5">
                {getTargetTitle()}
              </h3>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {/* Audio alert toggle */}
            <button
              onClick={() => {
                const next = soundAlertService.toggleMute();
                setSoundMuted(next);
                if (!next) {
                  soundAlertService.testSound('warning');
                }
              }}
              className={`p-2 rounded-lg border text-xs transition-colors ${
                !soundMuted 
                  ? 'bg-indigo-950/70 border-indigo-700 text-indigo-300' 
                  : 'bg-slate-800 border-slate-700 text-slate-500 hover:text-slate-300'
              }`}
              title={soundMuted ? 'Alerta sonoro mutado (Clique para ativar)' : 'Alerta sonoro ativo'}
            >
              {!soundMuted ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
            </button>

            {/* Refresh Analysis */}
            <button
              onClick={runAnalysis}
              disabled={isLoading}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 transition-colors disabled:opacity-50"
              title="Recalcular diagnóstico com IA"
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>

            {/* Close */}
            <button
              onClick={onClose}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-400 hover:text-slate-100 transition-colors"
              title="Fechar"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-4 sm:p-6 overflow-y-auto space-y-5 text-sm">
          {isLoading ? (
            <div className="py-16 text-center space-y-4">
              <div className="relative w-16 h-16 mx-auto">
                <div className="absolute inset-0 rounded-full border-2 border-cyan-500/30 animate-ping" />
                <div className="relative w-16 h-16 rounded-full bg-cyan-950/80 border border-cyan-500 flex items-center justify-center text-cyan-400 shadow-xl shadow-cyan-950">
                  <Cpu className="w-8 h-8 animate-pulse" />
                </div>
              </div>
              <div>
                <h4 className="text-sm font-semibold text-slate-200">
                  Correlacionando telemetria e gerando parecer forense...
                </h4>
                <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
                  Auditando pacotes brutos do Scapy, tabelas do Netfilter e vetores do framework MITRE ATT&CK.
                </p>
              </div>
            </div>
          ) : result ? (
            <>
              {/* Top Summary Banner: Risk + MITRE */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <div>
                    <span className="text-[11px] font-mono text-slate-500 uppercase tracking-wider block">
                      Classificação de Risco
                    </span>
                    <span className="text-sm font-bold text-slate-200 mt-0.5 block">
                      {result.riskLevel}
                    </span>
                  </div>
                  <span className={`px-2.5 py-1 rounded-lg text-xs font-mono font-bold border uppercase ${getRiskBadgeColor(result.riskLevel)}`}>
                    {result.riskLevel}
                  </span>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <div>
                    <span className="text-[11px] font-mono text-slate-500 uppercase tracking-wider block">
                      Mapeamento MITRE ATT&CK
                    </span>
                    <span className="text-xs font-semibold text-indigo-300 mt-0.5 block font-mono truncate max-w-[200px] sm:max-w-[240px]">
                      {result.mitreTechnique}
                    </span>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-950/80 text-indigo-300 border border-indigo-700 shrink-0">
                    MITRE TTP
                  </span>
                </div>
              </div>

              {/* Technical Forensic Diagnosis Prose */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 border-b border-slate-800/80 pb-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  <span>Parecer Técnico do Especialista (SOC Forensics)</span>
                </div>
                <div className="text-xs text-slate-300 leading-relaxed whitespace-pre-line font-sans pt-1">
                  {result.analysis}
                </div>
              </div>

              {/* Validated Linux Kernel Netfilter Rule */}
              {result.validatedIptablesCommand && (
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300 flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-emerald-400" />
                      <span>Regra de Mitigação Validada para o Kernel Kali Linux:</span>
                    </span>
                    <span className="text-[10px] text-emerald-400 font-mono bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-800">
                      Iptables Seguro
                    </span>
                  </div>

                  <div className="flex items-center justify-between gap-2 p-2.5 rounded-lg bg-slate-900 border border-slate-800 font-mono text-xs">
                    <code className="text-emerald-300 truncate select-all">
                      {result.validatedIptablesCommand}
                    </code>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <button
                        onClick={handleCopyCommand}
                        className="p-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                        title="Copiar comando"
                      >
                        {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                      {onOpenKaliTerminal && (
                        <button
                          onClick={handleExecuteInTerminal}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs font-sans transition-colors shadow-sm"
                          title="Enviar e executar no terminal do Kali Linux"
                        >
                          <Play className="w-3.5 h-3.5 fill-slate-950" />
                          <span>Executar no Kali</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Tactical Action Checklist */}
              {result.recommendedActions && result.recommendedActions.length > 0 && (
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
                    <ShieldCheck className="w-4 h-4 text-cyan-400" />
                    <span>Ações Táticas Imediatas Recomendadas:</span>
                  </div>
                  <ul className="space-y-1.5 text-xs text-slate-300 pt-1">
                    {result.recommendedActions.map((act, idx) => (
                      <li key={idx} className="flex items-start gap-2.5">
                        <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                        <span>{act}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          ) : (
            <div className="py-12 text-center text-slate-400 text-xs">
              Nenhuma telemetria disponível para análise no momento.
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Motor: {result?.providerUsed || 'Google Gemini (API Integrada)'}</span>
          </div>

          <div className="flex items-center gap-2">
            {targetType === 'threat' && targetData && !targetData.playbook?.applied && onApplyMitigation && (
              <button
                onClick={() => {
                  onApplyMitigation(targetData.id);
                  onClose();
                }}
                className="px-3.5 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs transition-colors flex items-center gap-1.5 shadow-sm"
              >
                <span>Aplicar Mitigação do Playbook</span>
              </button>
            )}
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
            >
              Fechar
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
